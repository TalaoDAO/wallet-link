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
import os
from datetime import datetime
from typing import Any, Dict

import redis
from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    send_file,
)
from flask_mobility import Mobility
from flask_qrcode import QRcode
from routes import home, oidc4vci
import environment
from utils import message

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


def load_keys(path: str = "keys.json") -> Dict[str, Any]:
    """Load secrets and keys from local JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def utc_now_z() -> str:
    """Return UTC timestamp like '2026-02-14T12:34:56Z' (no microseconds)."""
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def char2bytes_hex(text: str) -> str:
    """Encode text to UTF-8 hex string (Tezos signed message payload building)."""
    return text.encode("utf-8").hex()

KEYS = load_keys()
APP_SECRET_KEY = KEYS["appSecretKey"]

# Environment / mode
myenv = os.getenv("MYENV") or "local"
mode = environment.currentMode(myenv)

# Redis (local)
red = redis.Redis(host="127.0.0.1", port=6379, db=0)

# Flask app
app = Flask(__name__)
app.config["MODE"] = mode
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_REDIS"] = red
app.config["REDIS"] = red
app.secret_key = json.dumps(APP_SECRET_KEY)

QRcode(app)
Mobility(app)
home.init_app(app)
oidc4vci.init_app(app)

@app.errorhandler(500)
def error_500(e: Exception):
    """Notify support and redirect to homepage on unhandled errors."""
    message.msg("Error 500 wallet-link", "support@talao.io", str(e))
    return redirect(mode.server)


# ------------------------------------------------------------------------------
# Static serving and error page
# ------------------------------------------------------------------------------

@app.route("/tezos4eudiw/error", methods=["GET"])
def error():
    return render_template("error.html")


@app.route("/tezos4eudiw/static/img/<filename>", methods=["GET"])
def serve_img(filename: str):
    try:
        return send_file(f"./static/img/{filename}", download_name=filename)
    except FileNotFoundError:
        app_logger.error("%s not found", filename)
        abort(404)


@app.route("/tezos4eudiw/static/<filename>", methods=["GET"])
def serve_static(filename: str):
    try:
        return send_file(f"./static/{filename}", download_name=filename)
    except FileNotFoundError:
        app_logger.error("%s not found", filename)
        abort(404)


# ------------------------------------------------------------------------------
# local bootstrap
# ------------------------------------------------------------------------------


if __name__ == "__main__":
    app_logger.info("app init (Tezos-only)")
    app.run(host=mode.IP, port=mode.port, debug=True)
