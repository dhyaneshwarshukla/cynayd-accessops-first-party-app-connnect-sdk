# Grid and Calendar host-session qualification

Use the canonical ownership manifest at
`sso/access-platform-cutover-backend/docs/authentication-architecture.md`
when working in the CYNAYD application workspace.

## Grid release state

Development Grid uses SDK RC.7 for confidential direct entry. The signed
One subject establishes the initial host identity after live AccessOps
authorization. Existing host recovery checks the original user, organization,
installation, central session and access epoch. See the
[Phase 4 rollout record](../../sso/access-platform-cutover-backend/docs/grid-phase-4-rollout.md)
for deployment and remaining qualification. Grid bearer compatibility stays
available while its consumers and retirement evidence are reviewed.

## Grid deployment and checks

- Serve Grid and its API on the same HTTPS origin. Route `/api` to the
  Grid backend and configure the web API base and trusted One portal
  origin. Validate the exact registered callback, issuer and JWKS origin.
  Redact callback queries from proxy logs, application logs and analytics.
- Use the existing backend assertion and proof keys and apply the
  `20261125193000_one_host_sessions` migration only in the approved
  target environment. Configure the same session seal key on all Grid
  replicas. Plan session invalidation for key rotation.
- Scope the host rollout to the authorized installation during
  qualification. Grid requests optional renewal when the existing
  Grid renewal switch is enabled. One checks the live central session,
  lock and AccessOps authorization. Go decides continuing assurance.
  Keep the separate activity operation and authentication-idle policy
  checks at One and Go, with Grid reporting only eligible committed
  foreground work.
- Verify direct workbook entry and My Apps entry with a disposable
  authorized account. Ensure no browser bearer or consent is used for
  approved first-party entry. Exercise exact callback and replay rejection,
  central lock and unlock, source expiry, renewal races, logout and pending
  edit reconciliation under the same identity.
- Retire Grid browser bearer consumers only after these checks pass in the
  deployed candidate. Keep shared SSO and SDK interfaces for their
  remaining consumers. Roll back with the pinned prior image.

## PHP and Python adapter boundary

HRMS Laravel and Groot Python should call a reviewed server-only adapter
running this SDK. A protected middleware call should provide an opaque
backend-held reference to an authenticated host session; the adapter must
resolve its bound credential record and use live One status on every protected
operation. Authenticate the calling backend and bind the reference to its
registered client, installation, person and tenant. A deny, lock, outage or
invalid reference must fail closed. Return only decision and structured
recovery information to the caller. Never forward source credentials or
capabilities to the browser. Leave product resource ACLs in the application.

The same adapter should use compare-and-set and a shared lease for any
approved recovery, and publish advisory session hints to a product relay.
MCP calls must continue to authorize the exact user and tenant before each
protected side effect. Laravel SAML sessions and Vault remain on their existing
verified federation recovery until One provides a reviewed live central session
binding for that mode. This describes the adapter contract. No PHP or Python
adapter was built or authenticated in this pass.

## Calendar and Tasks pilot

The backend pins the same rc.4 tarball. Its opt-in pilot is configured with
`CALENDAR_ONE_SESSION_ENABLED`, `CALENDAR_ONE_PILOT_TENANT_ID`,
`CALENDAR_ONE_PILOT_INSTALLATION_ID`, `CALENDAR_ONE_JWKS_URL`, and a
random 32-byte base64url `CALENDAR_ONE_SEAL_KEY`. Configure the approved
`ONE_DELEGATION_ISSUER`, token endpoint, client ID, key ID and backend
assertion and proof key files. Apply migration `027_calendar_one_sessions`
to the isolated Calendar database. Schedule expired-row cleanup before
sustained use. Enabling the pilot requires an exact canonical AccessOps
decision and a fresh verified One code. Existing sessions for that tenant
must recover through One. Other tenants retain existing SAML behavior.

Calendar stores the verified subject in the backend with its organization,
person, installation and epoch. The signed product session carries only the
host reference. Protected requests make a live SDK status call before the
existing Calendar permissions. Local logout can delete the host row while the
central session is locked. Expired evidence requires a new verified launch.
Silent renewal, event relaying and Calendar activity reporting remain unqualified.

## Host middleware examples

These examples show where to place the shared adapter and resource checks.
They assume injection of a reviewed SDK-backed service and an already
authenticated server-side host binding.

Laravel:

```php
$binding = $serverSession->requireVerifiedOneBinding($request->user());
$decision = $oneSessionAdapter->check($binding);
abort_unless($decision->allowed(), $decision->httpStatus());
return $next($request); // Existing resource authorization still runs.
```

Python:

```python
binding = await host_sessions.require_verified_one_binding(local_session)
decision = await one_session_adapter.check(binding)
decision.require_allowed()
await require_resource_permission(binding, operation, resource)
```

The adapter is responsible for returning structured lock and recovery actions.
These examples do not introduce a deployment endpoint or authorize a
caller-supplied identity. Wire the same check at Groot's protected MCP
side-effect boundary.

See [remote application migration guides](remote-application-migration-readiness.md)
and [restricted distribution](phase2/distribution.md).
