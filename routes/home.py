"""
Altme Identity Issuer / Wallet Link (Tezos-only) - Flask

What this service does (high level):
- Serves a dApp page where users sign a nonce with a Tezos wallet.
- Verifies Tezos signatures (pytezos).
- Stores a short-lived session payload in Redis (used for wallet linking).
- Exposes an endpoint that returns a credential offer and issues a signed VC (via didkit).
- Provides an SSE stream so the browser can receive issuer status updates.

Assumes presence of:
- keys.json
- ./credentials/TezosAssociatedAddress.jsonld
- ./credentials_manifests/TezosAssociatedAddress_credential_manifest.json
- environment.py, message.py
- local Redis
"""

from __future__ import annotations

import json
import logging
import random
import string
from datetime import datetime, timedelta
from typing import Any, Dict

from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    session,
    current_app
)
#from flask_mobility import Mobility
#from flask_qrcode import QRcode
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
# Constants / Configuration (Tezos only)
# ------------------------------------------------------------------------------

INACTIVE_TEZOS_LINK = """<p class="inactiveNav" id="tezos">Tezos</p>"""

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------


def load_keys(path: str = "keys.json") -> Dict[str, Any]:
    """Load secrets and keys from local JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def read_json(path: str) -> Dict[str, Any]:
    """Read and parse a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def utc_now_z() -> str:
    """Return UTC timestamp like '2026-02-14T12:34:56Z' (no microseconds)."""
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def make_secret_code() -> str:
    """Return a 6-digit numeric secret code."""
    return "".join(random.choice(string.digits) for _ in range(6))


def fill_common_credential_fields(credential: Dict[str, Any], issuer_did: str) -> None:
    """Mutate credential with issuer and issuance/expiration dates."""
    credential["issuer"] = issuer_did
    credential["issuanceDate"] = utc_now_z()
    credential["expirationDate"] = (datetime.now() + timedelta(days=365)).isoformat() + "Z"


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
    app_.add_url_rule("/altme-identity", view_func=dapp, methods=["GET"])
    app_.add_url_rule("/", view_func=dapp, methods=["GET"])
    app_.add_url_rule("/altme-identity/validate_sign", view_func=validate_sign, methods=["GET"])
    app_.add_url_rule("/altme-identity/credential_offer", view_func=credential_offer, methods=["GET", "POST"])
    app_.add_url_rule("/altme-identity/stream", view_func=wallet_link_stream, methods=["GET", "POST"])


# ------------------------------------------------------------------------------
# Main flow: dapp wallet sign-in (Tezos)
# ------------------------------------------------------------------------------


def dapp():
    """
    - Creates a nonce and Tezos signed-message payload
    - Renders the signing page

    """
    mode = current_app.config["MODE"]
    session["is_connected"] = True
    secret_code = make_secret_code()

    # Text that the wallet signs (human-readable)
    message = (
        f"Tezos Signed Message: altme.io {utc_now_z()} "
        f"Proof of Crypto Ownership. "
        #f"Secret code: {secret_code}. "
        f"Open your EUDI Wallet and scan the next QR code to complete attestation issuance."
    )
    message = (
        "Tezos Signed Message: altme.io " 
        "Proof of Crypto Ownership. "
        "You are about to sign a message to prove that you control this Tezos wallet. "
        "This signature is safe and will not trigger any blockchain transaction or cost any fees. "
        "After signing, open your EUDI Wallet and scan the QR code to receive your attestation."
    )


    session["secret_code"] = secret_code
    session["cryptoWalletMessage"] = message
    session["cryptoWalletPayloadHex"] = message.encode("utf-8").hex()
        
    is_mobile = getattr(request, "MOBILE", False)
    template = "dappMOBILE.html" if is_mobile else "dapp.html"

    return render_template(
        template,
        nonce=session["cryptoWalletMessage"],   # send readable message to frontend
        link=mode.server + "altme-identity/validate_sign",
    )


def validate_sign():
    """
    Validate Tezos signature coming from front-end.
    On success sets session['addressVerified'].
    """
    try:
        pub_key = request.headers.get("pubKey") or ""
        signature = request.headers.get("signature") or ""
        payload_hex = request.headers.get("payload", "")
        if not payload_hex:
            return {"status": "error", "message": "Missing session payload"}, 400
        
        payload_bytes = bytes.fromhex(payload_hex)
        expected_address = request.headers.get("address")
        pkh = verify_tezos_signature(pub_key, signature, payload_bytes, expected_address)
        session["addressVerified"] = pkh
        logging.info("Signature is validated")
        return {"status": "valid"}, 200

    except Exception as e:
        session["addressVerified"] = False
        app_logger.exception("Tezos signature validation failed: %s", e)
        return {"status": "error"}, 403


def credential_offer():
    """
    Docstring for credential_offer
    """
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    payload = request.get_json(silent=True) or {}
    wallet_address = payload.get("walletAddress")

    data = {
        "user_pin_required": False,
        "webhook": None,
        "stream_id": None,
        "user_pin": None,
        "issuer_state": "mvp_aptitude",
        "vc": {
            "SCA": {
                "vct": "talao:aptitude:sca:1",
                "blockchain_network": "tezos",
                "wallet_address": wallet_address,
            }
        }
    }
    # Call the existing API helper (returns Flask Response from jsonify)
    resp = oidc4vci.get_credential_offer(data, red, mode)
    payload = resp.get_json() or {}
    return jsonify({"url": payload["qrcode_value"], "id": payload["id"]})


def wallet_link_stream():
    """Server-Sent Events endpoint so the browser can receive issuer updates."""
    red = current_app.config["REDIS"]
    def event_stream():
        pubsub = red.pubsub()
        pubsub.subscribe("altme-identity")
        for item in pubsub.listen():
            if item.get("type") == "message":
                yield f"data: {item['data'].decode()}\n\n"

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    }
    return Response(event_stream(), headers=headers)
