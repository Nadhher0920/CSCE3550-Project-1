import jwt

import keys
from app import app


def test_jwks_returns_200():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200


def test_jwks_contains_keys_array():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")
    data = response.get_json()

    assert "keys" in data
    assert isinstance(data["keys"], list)


def test_jwks_contains_active_key():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")
    data = response.get_json()

    kids = [key["kid"] for key in data["keys"]]

    assert keys.active_key["kid"] in kids


def test_expired_key_not_in_jwks():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")
    data = response.get_json()

    kids = [key["kid"] for key in data["keys"]]

    assert keys.expired_key["kid"] not in kids


def test_jwk_has_required_fields():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")
    data = response.get_json()

    assert len(data["keys"]) >= 1

    jwk = data["keys"][0]

    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"

    assert "kid" in jwk
    assert "n" in jwk
    assert "e" in jwk


def test_auth_returns_token():
    client = app.test_client()

    response = client.post("/auth")

    assert response.status_code == 200

    token = response.data.decode("utf-8")

    assert token.count(".") == 2


def test_valid_jwt_header_uses_active_kid():
    client = app.test_client()

    response = client.post("/auth")

    token = response.data.decode("utf-8")

    header = jwt.get_unverified_header(token)

    assert header["kid"] == keys.active_key["kid"]
    assert header["alg"] == "RS256"


def test_valid_jwt_can_be_verified():
    client = app.test_client()

    response = client.post("/auth")

    token = response.data.decode("utf-8")

    public_key = keys.active_key["public_key"]

    decoded = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"]
    )

    assert decoded["sub"] == "fake-user"


def test_expired_auth_returns_token():
    client = app.test_client()

    response = client.post("/auth?expired=true")

    assert response.status_code == 200

    token = response.data.decode("utf-8")

    assert token.count(".") == 2


def test_expired_jwt_uses_expired_key():
    client = app.test_client()

    response = client.post("/auth?expired=true")

    token = response.data.decode("utf-8")

    header = jwt.get_unverified_header(token)

    assert header["kid"] == keys.expired_key["kid"]


def test_expired_jwt_is_expired():
    client = app.test_client()

    response = client.post("/auth?expired=true")

    token = response.data.decode("utf-8")

    public_key = keys.expired_key["public_key"]

    try:
        jwt.decode(
            token,
            public_key,
            algorithms=["RS256"]
        )

        assert False, "Token should have been expired"

    except jwt.ExpiredSignatureError:
        assert True


def test_get_auth_not_allowed():
    client = app.test_client()

    response = client.get("/auth")

    assert response.status_code == 405


def test_post_jwks_not_allowed():
    client = app.test_client()

    response = client.post("/.well-known/jwks.json")

    assert response.status_code == 405


def test_unknown_page_returns_404():
    client = app.test_client()

    response = client.get("/does-not-exist")

    assert response.status_code == 404