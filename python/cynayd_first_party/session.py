"""Framework-independent bound session verification and credential rotation."""

from dataclasses import dataclass, field
from time import time
from typing import Callable, Literal, Protocol
from uuid import uuid4

from .client import AuthorityError, Capability, DelegationClient, Launch, Redemption
from .subject import SubjectIdentity, verify_subject


@dataclass(frozen=True)
class Credentials:
    identity: SubjectIdentity
    subject: str = field(repr=False)
    capability: Capability | None = field(default=None, repr=False)


class RotationStore(Protocol):
    """Implement with a durable claim and credential CAS in the same store as host sessions."""

    async def read(self, session_id: str) -> tuple[str, Credentials] | None: ...
    async def claim(
        self, session_id: str, revision: str, generation: int,
    ) -> tuple[Literal["claimed", "in_progress", "recovery_required", "changed"], str | None]: ...
    async def replace(self, session_id: str, revision: str, credentials: Credentials) -> bool: ...


def _identity_tuple(identity: SubjectIdentity):
    return (identity.user_id, identity.tenant_id, identity.installation_id,
            identity.central_session_id, identity.access_epoch)


def _changed():
    return AuthorityError(401, "SOURCE_BINDING_INVALID", str(uuid4()), "REAUTHENTICATE")


class OneApplicationSession:
    def __init__(
        self, client: DelegationClient, *, issuer: str, app_slug: str, signing_key: Callable,
    ):
        self.client = client
        self._issuer = issuer
        self._app_slug = app_slug
        self._signing_key = signing_key

    def _verify(self, redemption: Redemption) -> Credentials:
        try:
            identity = verify_subject(
                redemption.subject, issuer=self._issuer, app_slug=self._app_slug,
                signing_key=self._signing_key,
            )
        except ValueError:
            raise _changed() from None
        return Credentials(identity, redemption.subject, redemption.capability)

    async def complete(
        self, launch: Launch, *, request: str, code: str, state: str,
        expected: SubjectIdentity | None = None,
        installation_for_tenant: Callable[[str], str | None],
    ) -> Credentials:
        """Call with a consumed transaction before atomically committing the host session."""
        credentials = self._verify(await self.client.redeem(launch, request=request, code=code, state=state))
        identity = credentials.identity
        if installation_for_tenant(identity.tenant_id) != identity.installation_id or (
            expected is not None and _identity_tuple(expected) != _identity_tuple(identity)
        ):
            raise _changed()
        await self.client.status(credentials.subject, identity)
        return credentials

    async def active(
        self, session_id: str, store: RotationStore, *, renew_within: int = 30,
    ) -> tuple[Credentials, dict]:
        """Validate current central access and optionally rotate with a durable one-shot claim."""
        current = await store.read(session_id)
        if current is None:
            raise _changed()
        revision, credentials = current
        capability = credentials.capability
        if capability and credentials.identity.expires_at - time() <= renew_within:
            claim, claimed_revision = await store.claim(session_id, revision, capability.generation)
            if claim == "recovery_required":
                raise AuthorityError(401, "SOURCE_RENEWAL_UNKNOWN", str(uuid4()), "REAUTHENTICATE")
            if claim != "claimed":
                # Another worker may have completed rotation. Never resubmit its capability.
                latest = await store.read(session_id)
                if latest is None or latest[0] == revision:
                    raise AuthorityError(503, "SOURCE_RENEWAL_PENDING", str(uuid4()), "RETRY")
                revision, credentials = latest
            else:
                if not claimed_revision or claimed_revision == revision:
                    raise _changed()
                try:
                    renewed = self._verify(await self.client.renew(capability))
                except AuthorityError as error:
                    if error.code == "source_renewal_locked_unspent":
                        if not await store.replace(session_id, claimed_revision, credentials):
                            raise _changed() from None
                        raise
                    if error.action in ("UNLOCK", "ACCESS_DENIED", "REAUTHENTICATE"):
                        raise
                    raise AuthorityError(
                        401, "SOURCE_RENEWAL_UNKNOWN", error.request_id, "REAUTHENTICATE",
                    ) from None
                if (
                    _identity_tuple(renewed.identity) != _identity_tuple(credentials.identity)
                    or renewed.identity.expires_at <= max(time(), credentials.identity.expires_at)
                    or renewed.capability is None
                    or renewed.identity.expires_at > renewed.capability.expires_at
                ):
                    raise _changed()
                if not await store.replace(session_id, claimed_revision, renewed):
                    raise _changed()
                latest = await store.read(session_id)
                if latest is None or latest[1] != renewed:
                    raise _changed()
                revision, credentials = latest
        if credentials.identity.expires_at <= time():
            raise AuthorityError(401, "SOURCE_SESSION_EXPIRED", str(uuid4()), "REAUTHENTICATE")
        status = await self.client.status(credentials.subject, credentials.identity)
        latest = await store.read(session_id)
        if latest != (revision, credentials):
            raise _changed()
        return credentials, status
