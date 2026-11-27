"""Verify the RC.8 One delegation subject against a trusted issuer key."""

from dataclasses import dataclass
from time import time

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt


@dataclass(frozen=True)
class SubjectIdentity:
    user_id: str
    tenant_id: str
    installation_id: str
    central_session_id: str
    access_epoch: int
    expires_at: int


def _identifier(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _positive_integer(value: object) -> bool:
    return type(value) is int and 0 < value <= 9007199254740991


def verify_subject(token: str, *, issuer: str, app_slug: str, signing_key) -> SubjectIdentity:
    """Resolve KIDs only through the host's configured One signing-key resolver."""
    try:
        if not token or len(token) > 32768:
            raise ValueError()
        header = jwt.get_unverified_header(token)
        if (
            header.get("alg") != "RS256"
            or not _identifier(header.get("kid"))
            or any(field in header for field in ("crit", "jku", "x5u"))
        ):
            raise ValueError()
        key = signing_key(header["kid"])
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
            raise ValueError()
        claims = jwt.decode(
            token, key, algorithms=["RS256"], issuer=issuer, audience=app_slug,
            options={"require": ["exp", "iat", "iss", "aud", "sub"], "verify_iat": False},
        )
        binding = claims.get("sessionBinding")
        if (
            claims["aud"] != app_slug
            or claims["iss"] != issuer
            or claims.get("type") != "one_delegation_subject"
            or claims.get("appSlug") != app_slug
            or not _identifier(claims["sub"])
            or claims.get("id") != claims["sub"]
            or not _identifier(claims.get("organizationId"))
            or not _identifier(claims.get("installedAppId"))
            or not _positive_integer(claims.get("launchAccessEpoch"))
            or not _positive_integer(claims["iat"])
            or claims["iat"] > int(time()) + 5
            or not _positive_integer(claims["exp"])
            or not isinstance(binding, dict)
            or not _identifier(binding.get("sessionId"))
            or not _identifier(binding.get("reference"))
            or claims.get("launchJti") != binding["reference"]
            or not _positive_integer(binding.get("originalIat"))
            or not _positive_integer(binding.get("expiresAt"))
            or binding["expiresAt"] <= time()
        ):
            raise ValueError()
        return SubjectIdentity(
            claims["sub"], claims["organizationId"], claims["installedAppId"],
            binding["sessionId"], claims["launchAccessEpoch"],
            min(claims["exp"], binding["expiresAt"]),
        )
    except (jwt.PyJWTError, ValueError, TypeError, KeyError):
        raise ValueError("Invalid One delegation subject") from None
