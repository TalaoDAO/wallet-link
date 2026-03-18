
from __future__ import annotations
import json
import logging
import random
import string
import uuid
from datetime import datetime
from typing import Any

import requests
from eth_account import Account
from eth_account.messages import encode_defunct
from flask import (
    Flask,
    Response,
    current_app,
    render_template,
    request,
    session,
)
from pytezos.crypto import key


PROOF_SESSION_TTL = 600  # 10 minutes

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------

logging.getLogger().setLevel(logging.INFO)

app_logger = logging.getLogger("issuer")
file_handler = logging.FileHandler("issuer.log")
app_logger.addHandler(file_handler)

logging.basicConfig(level=logging.INFO)

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------


def utc_now_z() -> str:
    """Return UTC timestamp like '2026-02-14T12:34:56Z' (no microseconds)."""
    return datetime.now().replace(microsecond=0).isoformat() + "Z"


def make_secret_code() -> str:
    """Return a 4-digit numeric secret code."""
    return "".join(random.choice(string.digits) for _ in range(4))


def make_session_expiration(ttl_seconds: int = PROOF_SESSION_TTL) -> int:
    return int(datetime.now().timestamp()) + ttl_seconds


def save_session(session_id: str, proof_session: dict[str, Any], ttl_seconds: int = PROOF_SESSION_TTL) -> None:
    current_app.config["REDIS"].setex(session_id, ttl_seconds, json.dumps(proof_session))


def read_session_or_403(session_id: str) -> tuple[dict[str, Any] | None, tuple[dict[str, str], int] | None]:
    red = current_app.config["REDIS"]
    raw_session = red.get(session_id)
    if not raw_session:
        app_logger.warning("proof session expired or missing")
        return None, ({"status": "error", "message": "Session expired"}, 403)

    proof_session = json.loads(raw_session.decode())
    if int(datetime.now().timestamp()) > proof_session.get("exp", 0):
        red.delete(session_id)
        return None, ({"status": "error", "message": "Session expired"}, 403)
    return proof_session, None



def verify_tezos_signature(pub_key: str, signature: str, payload: bytes, expected_address: str) -> str:
    """
    Verify Tezos signature and ensure address matches the public key hash.
    Returns the verified address (public_key_hash) if OK.
    """
    k = key.Key.from_encoded_key(pub_key)
    if not k.verify(signature, payload):
        raise ValueError("Invalid Tezos signature")

    pkh = k.public_key_hash()
    if pkh != expected_address:
        raise ValueError("Tezos address does not match pubKey hash")
    return pkh


def tezos_micheline_string_hex(message: str) -> str:
    """
    Convert a UTF-8 string into a Tezos Micheline packed string payload.
    Equivalent to the frontend:
    05 + 01 + <4-byte big-endian length> + <utf8-bytes-hex>
    """
    message_bytes = message.encode("utf-8")
    length_hex = len(message_bytes).to_bytes(4, byteorder="big").hex()
    return "05" + "01" + length_hex + message_bytes.hex()


def evm_challenge_message(domain: str, uri: str, chain_id: int, nonce: str, code: str) -> str:
    """
    Human-readable SIWE-style message for EVM wallets.
    This is intentionally simple and uses personal_sign / signMessage.
    """
    return (
        f"{domain} wants you to prove control of your wallet\n\n"
        f"URI: {uri}\n"
        f"Version: 1\n"
        f"Chain ID: {chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {utc_now_z()}\n"
        f"Statement: Sign this message to prove ownership of your wallet. "
        f"Your EUDI Wallet Binding Code is {code}."
    )


def verify_evm_signature(message: str, signature: str, expected_address: str) -> str:
    """
    Recover the signer from a standard EVM signed message.
    Supports signatures produced by personal_sign / signMessage.
    """
    encoded = encode_defunct(text=message)
    recovered = Account.recover_message(encoded, signature=signature)
    if recovered.lower() != expected_address.lower():
        raise ValueError("Recovered EVM address does not match expected address")
    return Account.from_key("0x" + "11" * 32).address if False else recovered  # keep type checkers happy


def build_template_context(
    *,
    session_id: str,
    wallet_type: str,
    chain_id: str,
    micheline_payload: str | None = None,
    evm_challenge: str | None = None,
    evm_chain_id: int | None = None,
) -> dict[str, Any]:
    
    config = current_app.config
    walletconnect_project_id = config.get("WALLETCONNECT_PROJECT_ID", "")
    mode = config["MODE"]
    server_url = getattr(mode, "server", "")
    
    if chain_id == "1":
        blockchain_network = "Ethereum"
        blockchain_logo = "ethereum.jpeg"
    elif chain_id == "42793":
        blockchain_network = "Etherlink"
        blockchain_logo = "etherlink.jpeg"
    elif chain_id == "137":
        blockchain_network = "Polygon"
        blockchain_logo = "polygon.jpeg"
    else:
        blockchain_network = "Tezos"
        blockchain_logo = "tezos.jpeg"

    return {
        "session_id": session_id,
        "wallet_type": wallet_type,
        "blockchain_network":blockchain_network,
        "chain_id": chain_id,
        "micheline_payload": micheline_payload,
        "evm_challenge": evm_challenge,
        "evm_chain_id": evm_chain_id,
        "walletconnect_project_id": walletconnect_project_id,
        "dapp_url": server_url.rstrip("/") or request.host_url.rstrip("/"),
        "blockchain_logo": blockchain_logo
    }


def build_credential_offer_request(
    *,
    session_id: str,
    code: str,
    address: str,
    caip2_chain_id: str,
    webhook_path_prefix: str,
) -> tuple[dict[str, Any], str]:
    
    mode = current_app.config["MODE"]
    webhook_url = mode.server + f"{webhook_path_prefix}/webhook"
    webhook_api_key = str(uuid.uuid4())
    
    if caip2_chain_id == "eip155:1":
        SCA = "SCA_Ethereum"
        vct = "urn:eudi:sca:crypto:ethereum:1"
        blockchain_network = "Ethereum"
    elif caip2_chain_id == "eip155:42793":
        SCA = "SCA_Etherlink"
        vct = "urn:eudi:sca:crypto:etherlink:1"
        blockchain_network = "Etherlink"
    elif caip2_chain_id == "eip155:137":
        SCA = "SCA_Polygon"
        vct = "urn:eudi:sca:crypto:polygon:1"
        blockchain_network = "Polygon"
    else: #  caip2_chain_id == "tezos:NetXdQprcVkpaWU":
        SCA = "SCA_Tezos"
        vct = "urn:eudi:sca:crypto:tezos:1"
        blockchain_network = "Tezos"

    data = {
        "tx_code": {
            "is_required": True,
            "description": "Binding Code",
            "length": 4,
            "input_mode": "numeric",
            "value": code,
        },
        "webhook_url": webhook_url,
        "webhook_X-API-KEY": webhook_api_key,
        "session_id": session_id,
        "credential_id": SCA,
        "vc": {
            SCA: {
                "vct": vct,
                "blockchain_network": blockchain_network,
                "account_address": address,
                "caip2_chain_id": caip2_chain_id,
                "disclosure": ["all"],
            }
        },
    }
    return data, webhook_api_key


def request_credential_offer(data: dict[str, Any]) -> tuple[dict[str, Any], int]:
    mode = current_app.config["MODE"]
    headers = {"Content-Type": "application/json"}
    resp = requests.post(
        mode.server + "get_credential_offer",
        json=data,
        headers=headers,
        timeout=10,
    )
    if resp.status_code != 200:
        logging.error("Credential offer API error: %s", resp.text)
        return {"error": "credential API offer error"}, 500

    payload = resp.json() or {}
    if payload.get("error") or not payload.get("url"):
        return {"error": "credential API offer error"}, 500
    return {"url": payload["url"]}, 200


# ------------------------------------------------------------------------------
# Routes registration
# ------------------------------------------------------------------------------


def init_app(app_: Flask) -> None:
    # Tezos
    app_.add_url_rule("/tezos", view_func=tezos_dapp, methods=["GET"])
    app_.add_url_rule("/tezos/validate_sign", view_func=tezos_validate_sign, methods=["POST"])
    app_.add_url_rule("/tezos/credential_offer", view_func=tezos_credential_offer, methods=["POST"])
    app_.add_url_rule("/tezos/stream", view_func=tezos_stream, methods=["GET", "POST"])
    app_.add_url_rule("/tezos/webhook", view_func=tezos_webhook, methods=["GET", "POST"])

    # EVM
    app_.add_url_rule("/evm", view_func=evm_dapp, methods=["GET"])
    app_.add_url_rule("/evm/validate_sign", view_func=evm_validate_sign, methods=["POST"])
    app_.add_url_rule("/evm/credential_offer", view_func=evm_credential_offer, methods=["POST"])
    app_.add_url_rule("/evm/stream", view_func=evm_stream, methods=["GET", "POST"])
    app_.add_url_rule("/evm/webhook", view_func=evm_webhook, methods=["GET", "POST"])


# ------------------------------------------------------------------------------
# Tezos flow
# ------------------------------------------------------------------------------


def tezos_dapp():
    red = current_app.config["REDIS"]
    session["is_connected"] = True

    code = make_secret_code()
    session_id = str(uuid.uuid4())

    readable_message = (
        f"Tezos Signed Message: altme.io {utc_now_z()} "
        f"Sign this message with your crypto wallet. "
        f"Your EUDI Wallet Binding Code is {code}"
    )
    micheline_payload = tezos_micheline_string_hex(readable_message)
    
    proof_session = {
        "wallet_type": "tezos",
        "code": code,
        "status": "pending",
        "pkh": None,
        "address": None,
        "micheline_payload": micheline_payload,
        "exp": make_session_expiration(PROOF_SESSION_TTL),
    }
    red.setex(session_id, PROOF_SESSION_TTL, json.dumps(proof_session))


    return render_template(
        "dapp.html",
        **build_template_context(
            session_id=session_id,
            wallet_type="tezos",
            chain_id=None,
            micheline_payload=micheline_payload,
        ),
    )


def tezos_validate_sign():
    red = current_app.config["REDIS"]
    body = request.get_json(silent=True) or {}

    pub_key = body.get("pubkey")
    signature = body.get("signature") or ""
    payload_hex = body.get("payload") or ""
    session_id = body.get("session_id")
    address = body.get("address")

    if not session_id:
        return {"status": "error", "message": "Missing session id"}, 400
    if not payload_hex:
        return {"status": "error", "message": "Missing payload"}, 400
    if not pub_key or not signature or not address:
        return {"status": "error", "message": "Missing signature parameters"}, 400

    proof_session, error = read_session_or_403(session_id)
    if error:
        return error
    assert proof_session is not None

    if proof_session.get("status") != "pending" or proof_session.get("wallet_type") != "tezos":
        red.delete(session_id)
        return {"status": "error", "message": "Invalid session status"}, 403

    expected_payload = proof_session.get("micheline_payload")
    if not expected_payload or payload_hex != expected_payload:
        red.delete(session_id)
        return {"status": "error", "message": "Payload mismatch"}, 403

    try:
        payload_bytes = bytes.fromhex(payload_hex)
        pkh = verify_tezos_signature(pub_key, signature, payload_bytes, address)
        proof_session["status"] = "account_address_validated"
        proof_session["address"] = address
        proof_session["pkh"] = pkh
        save_session(session_id, proof_session)
        return {"status": "valid"}, 200
    except Exception as exc:
        app_logger.exception("Tezos signature validation failed: %s", exc)
        red.delete(session_id)
        return {"status": "error", "message": "Invalid signature"}, 403


def tezos_credential_offer():
    payload = request.get_json(silent=True) or {}
    session_id = payload.get("session_id")
    if not session_id:
        return {"status": "error", "message": "Missing session id"}, 400

    proof_session, error = read_session_or_403(session_id)
    if error:
        return error
    assert proof_session is not None

    if proof_session.get("status") != "account_address_validated" or proof_session.get("wallet_type") != "tezos":
        current_app.config["REDIS"].delete(session_id)
        return {"status": "error", "message": "Invalid session status"}, 403

    code = proof_session.get("code", "")
    address = proof_session.get("address")
    data, webhook_api_key = build_credential_offer_request(
        session_id=session_id,
        code=code,
        address=address,
        caip2_chain_id="tezos:NetXdQprcVkpaWU",
        webhook_path_prefix="tezos",
    )
    proof_session["webhook_X-API-KEY"] = webhook_api_key
    save_session(session_id, proof_session)
    
    response, status = request_credential_offer(data)
    if status != 200:
        return response, status

    proof_session["status"] = "credential_offer_sent"
    save_session(session_id, proof_session)
    return response, 200


# ------------------------------------------------------------------------------
# EVM flow
# ------------------------------------------------------------------------------


def evm_dapp():
    red = current_app.config["REDIS"]
    session["is_connected"] = True

    code = make_secret_code()
    session_id = str(uuid.uuid4())
    chain_id = request.args.get("chain_id") or int(current_app.config.get("EVM_CHAIN_ID", 1))
    domain = request.host
    uri = request.url_root.rstrip("/") + "/evm"
    nonce = uuid.uuid4().hex[:8]
    challenge = evm_challenge_message(domain, uri, chain_id, nonce, code)

    proof_session = {
        "wallet_type": "evm",
        "code": code,
        "status": "pending",
        "address": None,
        "chain_id": chain_id,
        "nonce": nonce,
        "challenge": challenge,
        "exp": make_session_expiration(PROOF_SESSION_TTL),
    }
    red.setex(session_id, PROOF_SESSION_TTL, json.dumps(proof_session))
    
    return render_template(
        "dapp.html",
        **build_template_context(
            session_id=session_id,
            chain_id=str(chain_id),
            wallet_type="evm",
            evm_challenge=challenge,
            evm_chain_id=chain_id,
        ),
    )


def evm_validate_sign():
    red = current_app.config["REDIS"]
    body = request.get_json(silent=True) or {}

    session_id = body.get("session_id")
    address = body.get("address")
    signature = body.get("signature") or ""
    challenge = body.get("message") or ""
    chain_id = body.get("chain_id")

    if not session_id or not address or not signature or not challenge:
        return {"status": "error", "message": "Missing signature parameters"}, 400

    proof_session, error = read_session_or_403(session_id)
    if error:
        return error
    assert proof_session is not None

    if proof_session.get("status") != "pending" or proof_session.get("wallet_type") != "evm":
        red.delete(session_id)
        return {"status": "error", "message": "Invalid session status"}, 403

    expected_challenge = proof_session.get("challenge")
    expected_chain_id = int(proof_session.get("chain_id", 1))
    
    app_logger.info("expected_chain_id=%s submitted_chain_id=%s", expected_chain_id, chain_id)

    if challenge != expected_challenge:
        red.delete(session_id)
        return {"status": "error", "message": "Challenge mismatch"}, 403

    if chain_id is not None and int(chain_id) != expected_chain_id:
        red.delete(session_id)
        return {"status": "error", "message": "Chain mismatch"}, 403

    try:
        recovered = verify_evm_signature(challenge, signature, address)
        proof_session["status"] = "account_address_validated"
        proof_session["address"] = recovered
        save_session(session_id, proof_session)
        return {"status": "valid"}, 200
    except Exception as exc:
        app_logger.exception("EVM signature validation failed: %s", exc)
        red.delete(session_id)
        return {"status": "error", "message": "Invalid signature"}, 403


def evm_credential_offer():
    payload = request.get_json(silent=True) or {}
    session_id = payload.get("session_id")
    if not session_id:
        return {"status": "error", "message": "Missing session id"}, 400

    proof_session, error = read_session_or_403(session_id)
    if error:
        return error
    assert proof_session is not None

    if proof_session.get("status") != "account_address_validated" or proof_session.get("wallet_type") != "evm":
        current_app.config["REDIS"].delete(session_id)
        return {"status": "error", "message": "Invalid session status"}, 403

    chain_id = int(proof_session.get("chain_id", current_app.config.get("EVM_CHAIN_ID", 1)))
    code = proof_session.get("code", "")
    address = proof_session.get("address")
    data, webhook_api_key = build_credential_offer_request(
        session_id=session_id,
        code=code,
        address=address,
        caip2_chain_id=f"eip155:{chain_id}",
        webhook_path_prefix="evm",
    )
    
    proof_session["webhook_X-API-KEY"] = webhook_api_key
    save_session(session_id, proof_session)

    response, status = request_credential_offer(data)
    if status != 200:
        return response, status

    proof_session["status"] = "credential_offer_sent"
    save_session(session_id, proof_session)
    return response, 200


# ------------------------------------------------------------------------------
# Shared SSE / webhook helpers
# ------------------------------------------------------------------------------


def stream_for(channel: str):
    red = current_app.config["REDIS"]

    def event_stream():
        pubsub = red.pubsub()
        pubsub.subscribe(channel)
        for item in pubsub.listen():
            if item.get("type") == "message":
                yield f"data: {item['data'].decode()}\n\n"

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    }
    return Response(event_stream(), headers=headers)


def webhook_for(channel: str):
    red = current_app.config["REDIS"]

    body = request.get_json(silent=True) or {}
    api_key = request.headers.get("X-API-KEY")
    session_id = body.get("session_id")

    if not session_id:
        return {"error": "missing session_id"}, 400

    raw_session = red.get(session_id)
    if not raw_session:
        return {"error": "session expired"}, 403

    proof_session = json.loads(raw_session.decode())
    expected_key = proof_session.get("webhook_X-API-KEY")
    if not api_key or api_key != expected_key:
        logging.warning("Webhook authentication failed")
        return {"error": "unauthorized"}, 401

    red.publish(channel, json.dumps(body))
    return {"status": "ok"}, 200


def tezos_stream():
    return stream_for("tezos4eudiw")


def evm_stream():
    return stream_for("evm4eudiw")


def tezos_webhook():
    return webhook_for("tezos4eudiw")


def evm_webhook():
    return webhook_for("evm4eudiw")
