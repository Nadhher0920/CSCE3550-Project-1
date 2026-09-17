import base64
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# Store our two keys:
# one valid key and one expired key.
active_key = {}
expired_key = {}


def base64url_uint(value):
    """
    Convert an integer into Base64URL format without '=' padding.
    This is required for RSA JWK values such as n and e.
    """
    byte_length = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(byte_length, byteorder="big")

    return (
        base64.urlsafe_b64encode(value_bytes)
        .rstrip(b"=")
        .decode("utf-8")
    )


def create_rsa_key(expired=False):
    """
    Create a new RSA key pair.

    Each key contains:
    - unique kid
    - private key
    - public key
    - expiration timestamp
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    kid = str(uuid.uuid4())

    now = datetime.now(timezone.utc)

    if expired:
        expires_at = now - timedelta(hours=1)
    else:
        expires_at = now + timedelta(hours=1)

    return {
        "kid": kid,
        "private_key": private_key,
        "public_key": public_key,
        "expires_at": expires_at
    }


def initialize_keys():
    """
    Generate one active RSA key and one expired RSA key.
    """

    global active_key
    global expired_key

    active_key = create_rsa_key(expired=False)
    expired_key = create_rsa_key(expired=True)


def public_key_to_jwk(key_data):
    """
    Convert an RSA public key into JWK format.
    """

    public_numbers = key_data["public_key"].public_numbers()

    return {
        "kty": "RSA",
        "use": "sig",
        "kid": key_data["kid"],
        "alg": "RS256",
        "n": base64url_uint(public_numbers.n),
        "e": base64url_uint(public_numbers.e)
    }


def get_valid_jwks():
    """
    Return only keys whose key-expiration timestamp
    has not expired.
    """

    now = datetime.now(timezone.utc)

    keys = []

    if active_key["expires_at"] > now:
        keys.append(public_key_to_jwk(active_key))

    # Normally this will not be included because it is expired.
    if expired_key["expires_at"] > now:
        keys.append(public_key_to_jwk(expired_key))

    return {
        "keys": keys
    }


def get_private_key_pem(key_data):
    """
    Convert a private RSA key into PEM format for PyJWT.
    """

    return key_data["private_key"].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


# Generate keys when this module is first imported.
initialize_keys()