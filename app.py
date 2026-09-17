from datetime import datetime, timedelta, timezone

import jwt
from flask import Flask, jsonify, request

import keys


app = Flask(__name__)


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """
    Return all currently valid public keys in JWKS format.

    Expired keys are intentionally excluded.
    """
    return jsonify(keys.get_valid_jwks()), 200


@app.route("/auth", methods=["POST"])
def auth():
    """
    Mock authentication endpoint.

    No username/password or request body is required.

    Normal request:
        POST /auth

    Expired-token request:
        POST /auth?expired=true
    """

    expired_requested = "expired" in request.args

    now = datetime.now(timezone.utc)

    if expired_requested:
        selected_key = keys.expired_key

        # JWT itself must already be expired.
        expiration = now - timedelta(hours=1)

    else:
        selected_key = keys.active_key

        # Valid for one hour.
        expiration = now + timedelta(hours=1)

    payload = {
        "sub": "fake-user",
        "iat": now,
        "exp": expiration
    }

    headers = {
        "kid": selected_key["kid"],
        "typ": "JWT"
    }

    private_key = keys.get_private_key_pem(selected_key)

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers=headers
    )

    return token, 200, {
        "Content-Type": "text/plain"
    }


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Not Found"
    }), 404


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8080,
        debug=False
    )