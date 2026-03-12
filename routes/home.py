

from __future__ import annotations
import logging
import random
import string
from datetime import datetime
import json
import uuid

from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    session,
    current_app
)
from pytezos.crypto import key
from routes import oidc4vci

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
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def make_secret_code() -> str:
    """Return a 6-digit numeric secret code."""
    return "".join(random.choice(string.digits) for _ in range(6))


def verify_tezos_signature(pub_key: str, signature: str, payload: str, expected_address: str) -> str:
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


# ------------------------------------------------------------------------------
# Routes registration
# ------------------------------------------------------------------------------


def init_app(app_: Flask) -> None:
    app_.add_url_rule("/tezos4eudiw", view_func=dapp, methods=["GET"])
    app_.add_url_rule("/tezos4eudiw/validate_sign", view_func=validate_sign, methods=["POST"])
    app_.add_url_rule("/tezos4eudiw/credential_offer", view_func=credential_offer, methods=["GET", "POST"])
    app_.add_url_rule("/tezos4eudiw/stream", view_func=wallet_link_stream, methods=["GET", "POST"])
    app_.add_url_rule("/tezos4eudiw/webhook", view_func=webhook, methods=["GET", "POST"])


# ------------------------------------------------------------------------------
# Main flow: dapp wallet sign-in (Tezos)
# ------------------------------------------------------------------------------


def dapp():
    """
    - Creates a nonce and Tezos signed-message payload
    - Renders the signing page

    """
    mode = current_app.config["MODE"]
    red = current_app.config["REDIS"]
    session["is_connected"] = True

    # Text that the wallet signs (human-readable)
    code = make_secret_code()
    session_id = str(uuid.uuid4())
    print("session_id = ", session_id)
    proof_session = {
        "code": code,
        "status": "pending",
        "pkh": None,
        "wallet_address": None,
        "exp": int(datetime.now().timestamp()) + 100,
    }
    red.setex(session_id, 100, json.dumps(proof_session))
    message = (
        f"Tezos Signed Message: altme.io {utc_now_z()} " 
        f"Sign this message with your crypto wallet. "
        "After signing, open your EUDI Wallet and scan the QR code to receive your attestation."
        f" Your EUDI Wallet binding code is {code}"
    )
    return render_template(
        "dapp.html",
        session_id=session_id,
        nonce=message,   # send readable message to frontend
        link=mode.server + "tezos4eudiw/validate_sign",
    )


def validate_sign():
    """
    Validate Tezos signature coming from front-end.
    On success sets session['addressVerified'].
    """
    red = current_app.config["REDIS"]
    body = request.get_json(silent=True) or {}
    pub_key = body.get("pubkey")
    signature = body.get("signature") or ""
    payload_hex = body.get("payload") or  ""
    session_id = body.get("sessionid")
    address = body.get("address")
    
    if not payload_hex:
        return {"status": "error", "message": "Missing session payload"}, 400
    
    proof_session = json.loads(red.get(session_id).decode())
    print("proof session = ",proof_session)
    if not proof_session:
        app_logger.exception("proof session expired or missing")
        return {"status": "error"}, 403
    if int(datetime.now().timestamp()) > proof_session.get("exp", 0):
        app_logger.exception("Tezos signature validation expired")
        return {"status": "error"}, 403
    if proof_session.get("status") != "pending":
        app_logger.exception("proof session status")
        return {"status": "error"}, 403
    
    try:   
        payload_bytes = bytes.fromhex(payload_hex)
        pkh = verify_tezos_signature(pub_key, signature, payload_bytes, address)
        logging.info("Signature is validated")
        
        # update proof_session
        proof_session["status"] = "account_address_validated"
        proof_session["wallet_address"] = pkh
        red.setex(session_id, 100, json.dumps(proof_session))
        
        return {"status": "valid"}, 200

    except Exception as e:
        #session["addressVerified"] = False
        app_logger.exception("Tezos signature validation failed: %s", e)
        return {"status": "error"}, 403


def credential_offer():
    """
    Docstring for credential_offer
    """
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    payload = request.get_json(silent=True) or {}
    session_id = payload.get("session_id")
    proof_session = json.loads(red.get(session_id).decode())
    if not proof_session:
        app_logger.exception("proof session expired or missing")
        return {"status": "error"}, 403
    code = proof_session.get('code', "None")
    wallet_address = proof_session.get("wallet_address")

    data = {
        "user_pin_required": True,
        "webhook": mode.server + "/tezos4eudiw/webhook",
        "stream_id": session_id,
        "user_pin": code,
        "vc": {
            "SCA": {
                "vct": "urn:eudi:sca:crypto:1",
                "blockchain_network": "Tezos",
                "account_address": wallet_address,
                "caip2_chain_id": "tezos:NetXdQprcVkpaWU",
                "blockchain_logo": "https://talao.co/image/server/TezosLogo_Icon_Blue.png",
                "disclosure": ["all"]
            }
        }
    }
    # Call the existing API helper (returns Flask Response from jsonify)
    resp = oidc4vci.get_credential_offer(data, red, mode)
    payload = resp.get_json() or {}
    logging.info("QRcode value = %s", payload["qrcode_value"])
    return jsonify({"url": payload["qrcode_value"]})


def wallet_link_stream():
    """Server-Sent Events endpoint so the browser can receive issuer updates."""
    red = current_app.config["REDIS"]
    def event_stream():
        pubsub = red.pubsub()
        pubsub.subscribe("tezos4eudiw")
        for item in pubsub.listen():
            if item.get("type") == "message":
                yield f"data: {item['data'].decode()}\n\n"

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    }
    return Response(event_stream(), headers=headers)

        
def webhook():
    red = current_app.config["REDIS"]
    body = request.get_json(silent=True) or {}
    print("webhook call = ", body)
    stream_id = body.get("stream_id")
    if stream_id:
        red.publish(
            "tezos4eudiw",
            json.dumps(body)
        )
    return {"status": "ok"}, 200