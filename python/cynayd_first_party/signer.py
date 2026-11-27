"""Confidential client assertions and DPoP as defined by SDK RC.8."""

from base64 import urlsafe_b64encode
from hashlib import sha256
import json
from time import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import httpx
import jwt


def _base64url(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _digest(value: str) -> str:
    return _base64url(sha256(value.encode()).digest())


def _endpoint(value: str) -> httpx.URL:
    url = httpx.URL(value)
    if (
        url.scheme != "https"
        or not url.host
        or url.userinfo
        or "#" in value
    ):
        raise ValueError("A trusted HTTPS URL is required")
    return url


class DelegationSigner:
    def __init__(
        self, client_id: str, credential_kid: str, client_pem: bytes, proof_pem: bytes
    ) -> None:
        client_key = load_pem_private_key(client_pem, password=None)
        proof_key = load_pem_private_key(proof_pem, password=None)
        if (
            not client_id
            or not credential_kid
            or not isinstance(client_key, rsa.RSAPrivateKey)
            or client_key.key_size < 2048
        ):
            raise ValueError("A registered client ID, KID and RSA key of at least 2048 bits are required")
        if not isinstance(proof_key, ec.EllipticCurvePrivateKey) or not isinstance(
            proof_key.curve, ec.SECP256R1
        ):
            raise ValueError("A P-256 private proof key is required")

        self.client_id = client_id
        self._credential_kid = credential_kid
        self._client_key = client_key
        self._proof_key = proof_key
        public = proof_key.public_key().public_numbers()
        self._proof_jwk = {
            "crv": "P-256",
            "kty": "EC",
            "x": _base64url(public.x.to_bytes(32, "big")),
            "y": _base64url(public.y.to_bytes(32, "big")),
        }
        self.thumbprint = _digest(json.dumps(self._proof_jwk, sort_keys=True, separators=(",", ":")))

    def assertion(self, endpoint: str) -> str:
        _endpoint(endpoint)
        if "?" in endpoint:
            raise ValueError("An assertion endpoint cannot contain a query")
        now = int(time())
        return jwt.encode(
            {
                "iss": self.client_id,
                "sub": self.client_id,
                "aud": endpoint,
                "iat": now,
                "exp": now + 30,
                "jti": str(uuid4()),
                "cnf": {"jkt": self.thumbprint},
            },
            self._client_key,
            algorithm="RS256",
            headers={"kid": self._credential_kid},
        )

    def proof(self, method: str, endpoint: str, token: str | None = None) -> str:
        url = _endpoint(endpoint)
        target = url.copy_with(query=None)
        if target.raw_path == b"/" and not str(target).endswith("/"):
            target = target.copy_with(raw_path=b"/")
        claims = {
            "htm": method.upper(),
            "htu": str(target),
            "iat": int(time()),
            "jti": str(uuid4()),
        }
        if token:
            claims["ath"] = _digest(token)
        return jwt.encode(
            claims,
            self._proof_key,
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": self._proof_jwk},
        )
