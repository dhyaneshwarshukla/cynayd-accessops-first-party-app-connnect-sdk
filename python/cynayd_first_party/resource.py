"""Resource-side verification for the SDK's One DPoP delegation contract."""

from dataclasses import dataclass
from inspect import isawaitable
import json
import re
from time import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import jwt

from .client import AuthorityError
from .signer import _digest, _endpoint


@dataclass(frozen=True)
class ResourceIdentity:
    user_id: str
    organization_id: str
    installation_id: str


def _header(token):
    if not token or len(token) > 32768:
        raise ValueError()
    header = jwt.get_unverified_header(token)
    if header.keys() & {"crit", "jku", "x5u"}:
        raise ValueError()
    return header


def _proof(proof, public_url, method, token, now):
    header = _header(proof)
    jwk = header.get("jwk")
    if (header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256" or not isinstance(jwk, dict)
            or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256"
            or not all(isinstance(jwk.get(key), str) for key in ("x", "y"))
            or jwk.keys() & {"d", "p", "q", "k"}):
        raise ValueError()
    key = jwt.algorithms.ECAlgorithm.from_jwk(jwk)
    claims = jwt.decode(proof, key, algorithms=["ES256"], options={"verify_iat": False})
    target = public_url.copy_with(query=None)
    htu = str(target)
    if target.raw_path == b"/" and not htu.endswith("/"):
        htu += "/"
    iat, jti = claims.get("iat"), claims.get("jti")
    if (claims.get("htu") != htu or claims.get("htm") != method.upper() or claims.get("ath") != _digest(token)
            or type(iat) is not int or abs(now - iat) > 30
            or not isinstance(jti, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", jti)):
        raise ValueError()
    thumbprint = _digest(json.dumps({key: jwk[key] for key in ("crv", "kty", "x", "y")}, separators=(",", ":")))
    return thumbprint, jti


class DelegatedResource:
    def __init__(self, *, issuer, audience, public_origin, signing_key, delegation, replay, authorize):
        _endpoint(issuer)
        origin = _endpoint(public_origin)
        if not audience or origin.raw_path != b"/":
            raise ValueError("Configure the approved resource audience and HTTPS origin")
        self.issuer, self.audience, self.origin = issuer, audience, origin
        self.signing_key, self.delegation, self.replay, self.acl = signing_key, delegation, replay, authorize

    async def authorize(self, *, authorization, proof, method, path, required_scope, context):
        """Verify a credential, reserve its proof, introspect, then apply the product ACL."""
        request_id, now = str(uuid4()), int(time())
        if (not path.startswith("/") or path.startswith("//") or "\\" in path or "#" in path
                or not re.fullmatch(r"[a-z][a-z0-9_.:-]{1,127}", required_scope)):
            raise AuthorityError(400, "INVALID_RESOURCE_REQUEST", request_id)
        public_url = self.origin.join(path)
        if public_url.netloc != self.origin.netloc or public_url.scheme != self.origin.scheme:
            raise AuthorityError(400, "INVALID_RESOURCE_REQUEST", request_id)
        if not authorization.startswith("DPoP ") or any(char.isspace() for char in authorization[5:]):
            raise AuthorityError(401, "invalid_token", request_id)
        token = authorization[5:]
        try:
            header = _header(token)
            kid = header.get("kid")
            if header.get("typ") != "at+jwt" or header.get("alg") != "RS256" or not isinstance(kid, str) or not kid:
                raise ValueError()
            key = self.signing_key(kid)
            if isawaitable(key):
                key = await key
            if not isinstance(key, RSAPublicKey) or key.key_size < 2048:
                raise ValueError()
            claims = jwt.decode(token, key, algorithms=["RS256"], issuer=self.issuer, audience=self.audience,
                                options={"require": ["iss", "aud", "iat", "nbf", "exp"], "verify_iat": False})
            ids = ("sub", "organization_id", "client_id", "azp", "source_installation_id", "target_installation_id", "jti")
            numbers = ("source_epoch", "target_epoch", "grant_revision", "client_revision", "iat", "nbf", "exp")
            actor = claims.get("act")
            if (claims.get("aud") != self.audience or claims.get("iss") != self.issuer or
                    claims.get("type") != "one_delegated_access" or claims.get("mode") != "DELEGATED" or
                    not all(isinstance(claims.get(field), str) and claims[field] for field in ids) or
                    not all(type(claims.get(field)) is int for field in numbers) or
                    not isinstance(actor, dict) or actor.get("sub") != claims["client_id"] or
                    claims["nbf"] != claims["iat"] or claims["iat"] > now + 5 or
                    not 0 < claims["exp"] - claims["iat"] <= 300):
                raise ValueError()
        except (ValueError, TypeError, jwt.PyJWTError):
            raise AuthorityError(401, "invalid_token", request_id) from None
        scope = claims.get("scope")
        if not isinstance(scope, str) or required_scope not in scope.split(" "):
            raise AuthorityError(403, "insufficient_scope", request_id, "ACCESS_DENIED")
        try:
            thumbprint, proof_id = _proof(proof, public_url, method, token, now)
            confirmation = claims.get("cnf")
            if not isinstance(confirmation, dict) or confirmation.get("jkt") != thumbprint:
                raise ValueError()
        except (ValueError, TypeError, jwt.PyJWTError):
            raise AuthorityError(401, "invalid_dpop_proof", request_id) from None
        try:
            fresh = await self.replay.consume(thumbprint, proof_id, now + 65)
        except Exception:
            raise AuthorityError(503, "REPLAY_STORE_UNAVAILABLE", request_id, "RETRY") from None
        if fresh is not True:
            raise AuthorityError(401, "invalid_dpop_proof", request_id)
        verified = await self.delegation.introspect(token, self.audience, request_id)
        if verified.get("active") is not True or any(
            type(verified.get(field)) is not type(claims[field]) or verified[field] != claims[field] for field in (
            "jti", "sub", "organization_id", "client_id", "grant_revision", "scope",
            )
        ):
            raise AuthorityError(401, "invalid_token", request_id)
        identity = ResourceIdentity(claims["sub"], claims["organization_id"], claims["target_installation_id"])
        try:
            allowed = await self.acl(identity, context)
        except Exception:
            raise AuthorityError(503, "RESOURCE_AUTHORITY_UNAVAILABLE", request_id, "RETRY") from None
        if allowed is not True:
            raise AuthorityError(403, "RESOURCE_ACCESS_DENIED", request_id, "ACCESS_DENIED")
        return identity
