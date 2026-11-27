"""Same-origin FastAPI host routes for an existing One registration."""

from dataclasses import asdict
from hashlib import sha256
import json
from base64 import urlsafe_b64encode
import re
from secrets import token_urlsafe
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from .client import AuthorityError, Launch, _opaque
from .subject import SubjectIdentity
from .session import HostStore

_HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}
_COOKIE = {"secure": True, "httponly": True, "samesite": "lax", "path": "/"}


class HostError(Exception):
    def __init__(self, status, code, action):
        self.status, self.code, self.action = status, code, action


def host_error_response(error):
    reconnect = error.code in {"invalid_grant", "SOURCE_RENEWAL_UNKNOWN", "SOURCE_SESSION_EXPIRED", "access_epoch_stale"}
    body = {"code": error.code, "nextAction": "RECONNECT" if reconnect else error.action}
    if isinstance(error, AuthorityError):
        body["requestId"] = error.request_id
    return JSONResponse(body, 401 if reconnect else error.status, headers=_HEADERS)


def _read_cookie(request, name):
    parts = [item.strip().partition("=")[2] for header in request.headers.getlist("cookie")
             for item in header.split(";") if item.strip().partition("=")[0] == name]
    if not parts:
        return None
    if len(parts) != 1 or not _opaque(parts[0]):
        raise HostError(401, "HOST_COOKIE_INVALID", "REAUTHENTICATE")
    return parts[0]


def _origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or
            value != "https://" + parsed.netloc):
        raise ValueError("Configure an exact HTTPS origin")
    return value


class FastAPIHost:
    def __init__(self, *, app_origin, portal_origin, base_path, callback, cookie_label, session, store: HostStore,
                 installation_for_tenant, allows_return, renewal=False):
        self.app_origin, self.portal_origin = _origin(app_origin), _origin(portal_origin)
        if (not re.fullmatch(r"/(?:[a-zA-Z0-9_-]+/)*[a-zA-Z0-9_-]+", base_path)
                or callback != app_origin + base_path + "/callback"
                or not re.fullmatch(r"[a-z0-9_-]{1,48}", cookie_label)):
            raise ValueError("Invalid host registration configuration")
        self.callback, self.session, self.store = callback, session, store
        self.installation_for_tenant, self.allows_return, self.renewal = installation_for_tenant, allows_return, renewal
        self.session_cookie = f"__Host-{cookie_label}-one"
        self.launch_cookie = self.session_cookie + "-launch"
        self.router = APIRouter(prefix=base_path)
        for method, endpoint in (
            ("POST", self.start), ("GET", self.complete), ("GET", self.status), ("POST", self.unlock_binding),
            ("POST", self.screen_activity), ("POST", self.logout),
        ):
            path = {"complete": "callback", "status": "session"}.get(endpoint.__name__, endpoint.__name__.replace("_", "-"))
            self.router.add_api_route("/" + path, endpoint, methods=[method])

    def assert_origin(self, request):
        if request.headers.getlist("origin") != [self.app_origin]:
            raise HostError(403, "HOST_ORIGIN_DENIED", "ACCESS_DENIED")

    def _return_path(self, value):
        if (not isinstance(value, str) or len(value) > 2048 or not value.startswith("/") or value.startswith("//")
                or re.search(r"[\\\x00-\x20\x7f]", value)):
            return "/"
        parsed = urlsplit(value)
        return parsed.path + ("?" + parsed.query if parsed.query else "") if self.allows_return(parsed) else "/"

    async def _stored(self, request):
        token = _read_cookie(request, self.session_cookie)
        record = await self.store.read(token) if token else None
        if not record:
            raise HostError(401, "HOST_SESSION_REQUIRED", "REAUTHENTICATE")
        return token, record

    async def authenticate(self, request):
        """Call before each protected operation, then enforce the existing product ACL."""
        token, _ = await self._stored(request)
        return await self.session.active(token, self.store)

    async def _json(self, request):
        try:
            body = bytearray()
            async for chunk in request.stream():
                if len(body) + len(chunk) > 4096:
                    raise HostError(413, "HOST_REQUEST_TOO_LARGE", "INVESTIGATE")
                body.extend(chunk)
            data = json.loads(body)
        except ValueError:
            data = None
        if not isinstance(data, dict):
            raise HostError(400, "HOST_REQUEST_INVALID", "INVESTIGATE")
        return data

    async def start(self, request: Request):
        try:
            self.assert_origin(request)
            body = await self._json(request)
            prior = _read_cookie(request, self.session_cookie)
            previous = await self.store.read(prior) if prior else None
            old_launch = _read_cookie(request, self.launch_cookie)
            launch = await self.session.client.initiate(self.callback)
            if old_launch and old_launch != prior:
                await self.store.remove([old_launch])
            token = token_urlsafe(32)
            await self.store.create_launch(token, {
                "request": launch.request, "state": launch.state, "launch": asdict(launch), "prior_id": prior,
                "previous": [prior, previous[0], asdict(previous[1].identity)] if previous else None,
                "return_to": self._return_path(body.get("returnTo")),
            }, launch.expires_in)
            url = self.portal_origin + "/apps/bound-launch?" + urlencode({"request": launch.request})
            response = JSONResponse({"authorizationUrl": url}, headers=_HEADERS)
            response.set_cookie(self.launch_cookie, token, max_age=launch.expires_in, **_COOKIE)
            return response
        except (AuthorityError, HostError) as error:
            return host_error_response(error)

    async def complete(self, request: Request):
        try:
            token = _read_cookie(request, self.launch_cookie)
            fields = {key: request.query_params.getlist(key) for key in ("request", "code", "state")}
            if not token or any(len(values) != 1 or not _opaque(values[0]) for values in fields.values()):
                raise HostError(401, "LAUNCH_STATE_INVALID", "REAUTHENTICATE")
            inputs = {key: values[0] for key, values in fields.items()}
            claim = await self.store.consume_launch(token, request=inputs["request"], state=inputs["state"],
                                                    prior_id=_read_cookie(request, self.session_cookie))
            if not claim:
                raise HostError(401, "LAUNCH_STATE_INVALID", "REAUTHENTICATE")
            revision, pending = claim
            previous = pending["previous"]
            credentials = await self.session.complete(
                Launch(**pending["launch"]), **inputs,
                expected=SubjectIdentity(**previous[2]) if previous else None,
                installation_for_tenant=self.installation_for_tenant, renewal=self.renewal,
            )
            if not await self.store.activate(token, revision, credentials, previous[:2] if previous else None):
                raise HostError(401, "SOURCE_SESSION_CHANGED", "RECONNECT")
            response = RedirectResponse(self.app_origin + self._return_path(pending["return_to"]), 303, headers=_HEADERS)
            response.delete_cookie(self.launch_cookie, **_COOKIE)
            response.set_cookie(self.session_cookie, token, **_COOKIE)
            return response
        except (AuthorityError, HostError) as error:
            return host_error_response(error)

    async def status(self, request: Request):
        try:
            credentials, _ = await self.authenticate(request)
            identity = credentials.identity
            return JSONResponse({"userId": identity.user_id, "tenantId": identity.tenant_id,
                                 "installedAppId": identity.installation_id, "email": None}, headers=_HEADERS)
        except (AuthorityError, HostError) as error:
            return host_error_response(error)

    async def unlock_binding(self, request: Request):
        try:
            self.assert_origin(request)
            _, (_, credentials) = await self._stored(request)
            digest = sha256(("one-embedded-unlock:" + credentials.identity.central_session_id).encode()).digest()
            return JSONResponse({"binding": urlsafe_b64encode(digest).decode().rstrip("=")}, headers=_HEADERS)
        except HostError as error:
            return host_error_response(error)

    async def screen_activity(self, request: Request):
        try:
            self.assert_origin(request)
            body = await self._json(request)
            _, (_, credentials) = await self._stored(request)
            result = await self.session.client.report_screen(
                credentials.subject, credentials.identity, body.get("operation"), body.get("eventId"),
            )
            return JSONResponse(result, headers=_HEADERS)
        except (AuthorityError, HostError) as error:
            return host_error_response(error)
        except (ValueError, TypeError):
            return host_error_response(HostError(400, "SCREEN_ACTIVITY_INVALID", "INVESTIGATE"))

    async def logout(self, request: Request):
        try:
            self.assert_origin(request)
            tokens = [_read_cookie(request, name) for name in (self.session_cookie, self.launch_cookie)]
            await self.store.remove([token for token in tokens if token])
            response = Response(status_code=204, headers=_HEADERS)
            response.delete_cookie(self.session_cookie, **_COOKIE)
            response.delete_cookie(self.launch_cookie, **_COOKIE)
            return response
        except HostError as error:
            return host_error_response(error)


def resource_error_response(error: AuthorityError):
    """Translate the central resource contract for an existing FastAPI product route."""
    response = host_error_response(error)
    if error.code in ("invalid_token", "invalid_dpop_proof"):
        response.headers["WWW-Authenticate"] = 'DPoP error="invalid_token"'
    elif error.code == "insufficient_scope":
        response.headers["WWW-Authenticate"] = 'DPoP error="insufficient_scope"'
    response.headers["X-Request-Id"] = error.request_id
    return response
