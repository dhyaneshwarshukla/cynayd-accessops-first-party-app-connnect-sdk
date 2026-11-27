"""Confidential RC.8 wire calls. Hosts own cookies, atomic storage and recovery."""

from dataclasses import dataclass, field
from datetime import datetime
from hmac import compare_digest
import re
from secrets import token_urlsafe
from time import time
from urllib.parse import urljoin
from uuid import uuid4

import httpx

from .signer import DelegationSigner, _digest, _endpoint
from .subject import SubjectIdentity

_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_SUBJECT_TYPE = "urn:ietf:params:oauth:token-type:access_token"
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{43}")
_EVENT = re.compile(r"[A-Za-z0-9_-]{16,128}")
_CODE = re.compile(r"[a-zA-Z][a-zA-Z0-9_]{1,95}")
_SCREEN = frozenset({"screen.interaction", "screen.view", "screen.view.end"})
_BUSINESS = frozenset({
    "message.send", "document.edit", "presentation.edit", "spreadsheet.edit",
    "mail.compose", "mail.send", "file.interact", "record.edit",
})


class AuthorityError(Exception):
    def __init__(self, status: int, code: str, request_id: str, action: str = "INVESTIGATE"):
        super().__init__(code)
        self.status, self.code, self.request_id, self.action = status, code, request_id, action


@dataclass(frozen=True)
class Launch:
    request: str
    state: str = field(repr=False)
    verifier: str = field(repr=False)
    expires_in: int


@dataclass(frozen=True)
class Capability:
    value: str = field(repr=False)
    generation: int
    expires_at: int


@dataclass(frozen=True)
class Redemption:
    subject: str = field(repr=False)
    capability: Capability | None


def _opaque(value):
    return isinstance(value, str) and bool(_OPAQUE.fullmatch(value))


def _action(status, code, value):
    if status in (429, 503) or value == "RETRY":
        return "RETRY"
    if code.lower() == "access_denied" or value == "ACCESS_DENIED":
        return "ACCESS_DENIED"
    if code in ("session_locked", "source_renewal_locked_unspent") or value == "UNLOCK":
        return "UNLOCK"
    if value in ("REAUTHENTICATE", "RECONNECT") or code in (
        "session_revoked", "session_expired", "step_up_required", "ACCESS_EPOCH_STALE",
        "access_epoch_stale", "TOKEN_EXPIRED", "AUTH_TOKEN_EPOCH", "SESSION_EXPIRED",
        "PIN_REQUIRED", "MFA_ENROLLMENT_REQUIRED", "VERIFIED_FEDERATION_EVIDENCE_REQUIRED",
    ):
        return "REAUTHENTICATE"
    return "INVESTIGATE"


def _timestamp(value):
    try:
        result = datetime.fromisoformat(value)
        return result.timestamp() if result.tzinfo is not None else None
    except (ValueError, TypeError, OverflowError):
        return None


class DelegationClient:
    def __init__(self, token_endpoint: str, signer: DelegationSigner, http: httpx.AsyncClient):
        _endpoint(token_endpoint)
        if "?" in token_endpoint or token_endpoint.endswith("/"):
            raise ValueError("Configure the exact One delegation token endpoint")
        self._endpoint = token_endpoint
        self._signer = signer
        self._http = http

    async def _post(self, operation, fields, request_id):
        endpoint = urljoin(self._endpoint, operation)
        try:
            response = await self._http.post(
                endpoint,
                data={
                    **fields,
                    "client_id": self._signer.client_id,
                    "client_assertion_type": _ASSERTION_TYPE,
                    "client_assertion": self._signer.assertion(endpoint),
                },
                headers={"DPoP": self._signer.proof("POST", endpoint), "X-Request-Id": request_id},
                follow_redirects=False, timeout=10.0,
            )
        except httpx.RequestError:
            raise AuthorityError(503, "UPSTREAM_UNAVAILABLE", request_id, "RETRY") from None
        try:
            result = response.json()
        except ValueError:
            result = {}
        if not isinstance(result, dict):
            result = {}
        if not response.is_success:
            code = next((value for value in (result.get("code"), result.get("error"))
                         if isinstance(value, str) and _CODE.fullmatch(value)), "UPSTREAM_AUTH_ERROR")
            raise AuthorityError(response.status_code, code, request_id,
                                 _action(response.status_code, code, result.get("nextAction")))
        if not result:
            raise self._mismatch(request_id)
        return result

    @staticmethod
    def _mismatch(request_id):
        return AuthorityError(503, "UPSTREAM_PROFILE_MISMATCH", request_id)

    async def initiate(self, callback: str) -> Launch:
        _endpoint(callback)
        verifier, state = token_urlsafe(32), token_urlsafe(32)
        request_id = str(uuid4())
        result = await self._post("bound-launch-initiate", {
            "callback": callback, "challenge": _digest(verifier), "state": state,
        }, request_id)
        expires = result.get("expires_in")
        if not _opaque(result.get("request")) or type(expires) is not int or not 0 < expires <= 120:
            raise self._mismatch(request_id)
        return Launch(result["request"], state, verifier, expires)

    async def redeem(self, launch: Launch, *, request: str, code: str, state: str) -> Redemption:
        """Call after atomically consuming the transaction owned by the browser."""
        request_id = str(uuid4())
        if not all(_opaque(value) for value in (request, code, state, launch.verifier)) or (
            not compare_digest(request, launch.request) or not compare_digest(state, launch.state)
        ):
            raise AuthorityError(401, "SOURCE_BINDING_INVALID", request_id, "REAUTHENTICATE")
        result = await self._post("bound-launch-redeem", {
            "request": request, "code": code, "verifier": launch.verifier, "renewal": "optional",
        }, request_id)
        status = result.get("renewal_status")
        if status == "eligible":
            return self._redemption(result, 1, request_id)
        if status != "ineligible" or any(key.startswith("renewal_") and key != "renewal_status" for key in result):
            raise self._mismatch(request_id)
        return self._redemption(result, None, request_id)

    def _redemption(self, result, generation, request_id):
        subject = result.get("subject_token")
        if not isinstance(subject, str) or not subject:
            raise self._mismatch(request_id)
        if generation is None:
            return Redemption(subject, None)
        value, received, expiry = (result.get(key) for key in (
            "renewal_capability", "renewal_generation", "renewal_expires_at",
        ))
        if not _opaque(value) or type(received) is not int or received != generation or (
            type(expiry) is not int or expiry <= time()
        ):
            raise self._mismatch(request_id)
        return Redemption(subject, Capability(value, generation, expiry))

    async def renew(self, capability: Capability) -> Redemption:
        """Dispatch once after a durable CAS claim. Ambiguous results require browser recovery."""
        request_id = str(uuid4())
        if not _opaque(capability.value) or type(capability.generation) is not int or (
            not 0 < capability.generation <= 2147483646 or capability.expires_at <= time()
        ):
            raise AuthorityError(401, "SOURCE_CAPABILITY_EXPIRED", request_id, "REAUTHENTICATE")
        result = await self._post("source-renewal", {
            "capability": capability.value, "generation": str(capability.generation),
        }, request_id)
        return self._redemption(result, capability.generation + 1, request_id)

    async def status(self, subject: str, identity: SubjectIdentity):
        request_id = str(uuid4())
        result = await self._post("session-status", {
            "subject_token": subject, "subject_token_type": _SUBJECT_TYPE,
        }, request_id)
        deadlines = [_timestamp(result.get(key)) for key in ("centralExpiresAt", "subjectExpiresAt")]
        revision = result.get("revision")
        if (
            result.get("state") != "ACTIVE" or result.get("reason") != "SESSION_VALID"
            or result.get("nextAction") != "NONE"
            or type(result.get("accessEpoch")) is not int or result["accessEpoch"] != identity.access_epoch
            or "revision" not in result or (revision is not None and (not isinstance(revision, str) or not revision))
            or any(value is None or value <= time() for value in deadlines)
            or any(key not in result or (result[key] is not None and _timestamp(result[key]) is None)
                   for key in ("lastActivityAt", "idleExpiresAt"))
        ):
            raise self._mismatch(request_id)
        return result

    async def report_screen(self, subject, identity, operation, event_id):
        if operation not in _SCREEN:
            raise ValueError("Unrecognized screen activity")
        return await self._activity(subject, identity, operation, event_id, screen=True)

    async def report_business(self, subject, identity, operation, event_id):
        if operation not in _BUSINESS:
            raise ValueError("Unrecognized business activity")
        return await self._activity(subject, identity, operation, event_id, screen=False)

    async def _activity(self, subject, identity, operation, event_id, *, screen):
        request_id = str(uuid4())
        if not subject or identity.expires_at <= time():
            raise AuthorityError(401, "SOURCE_SESSION_EXPIRED", request_id, "REAUTHENTICATE")
        if not isinstance(event_id, str) or not _EVENT.fullmatch(event_id):
            raise AuthorityError(400, "INVALID_ACTIVITY_EVENT", request_id)
        result = await self._post("activity", {
            "subject_token": subject, "subject_token_type": _SUBJECT_TYPE,
            "operation": operation, "event_id": event_id,
        }, request_id)
        idle = result.get("authenticationIdleUpdated", False)
        if (result.get("accepted") is not True or type(result.get("updated")) is not bool
                or type(idle) is not bool or (idle and (screen or not result["updated"]))):
            raise self._mismatch(request_id)
        return result
