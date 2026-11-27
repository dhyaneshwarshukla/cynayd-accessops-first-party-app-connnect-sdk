"""Resolve a signing KID against One's configured HTTPS JWKS."""

from uuid import uuid4

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .client import AuthorityError
from .signer import _endpoint


def one_signing_keys(uri, issuer, http: httpx.AsyncClient):
    endpoint, authority = _endpoint(uri), _endpoint(issuer)
    if endpoint.netloc != authority.netloc or endpoint.query:
        raise ValueError("Configure the trusted One JWKS endpoint")

    async def resolve(kid):
        request_id = str(uuid4())
        try:
            response = await http.get(endpoint, follow_redirects=False, timeout=10)
            response.raise_for_status()
            keys = response.json()["keys"]
            if not isinstance(keys, list):
                raise ValueError()
            matches = [key for key in keys if isinstance(key, dict) and key.get("kid") == kid]
            if not matches:
                return None
            key = matches[0]
            if (len(matches) != 1 or key.get("kty") != "RSA" or key.get("alg", "RS256") != "RS256"
                    or key.get("use", "sig") != "sig" or set(key) & {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}):
                raise ValueError()
            public = jwt.algorithms.RSAAlgorithm.from_jwk(key)
            if not isinstance(public, RSAPublicKey) or public.key_size < 2048:
                raise ValueError()
            return public
        except (httpx.HTTPError, jwt.PyJWTError, ValueError, TypeError, KeyError):
            raise AuthorityError(503, "JWKS_UNAVAILABLE", request_id, "RETRY") from None

    return resolve
