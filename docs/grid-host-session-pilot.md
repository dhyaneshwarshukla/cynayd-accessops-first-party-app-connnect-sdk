# Grid host-session pilot

Grid pins SDK 0.6.0-rc.4 from commit
`5df357cb191890c22701925e91d0957e1ff94343`. The Grid host-session commit is `adb368b3ad91c30f86b0c54da8145b78b0386b59`
and the activity and save-recovery commit is
`303e2d2d0d56b1160d06a02d9932f11e5450ad04`. Its migration is
`apps/api/prisma/migrations/20261125193000_one_host_sessions/migration.sql`.

## Isolated configuration

- Serve Grid and the Grid API on one HTTPS origin with `/api` routed to
  the Grid backend. Configure the web build's `NEXT_PUBLIC_API_BASE_URL`
  for that origin and `NEXT_PUBLIC_ONE_ORIGIN` for the trusted One portal.
  Existing split-origin deployments need a reviewed routing change before
  this pilot. Grid's `deployments/isolated-one-pilot.nginx.conf` is a tested
  loopback ingress fixture. Use the same exact callback and SSE routing in
  an approved staging ingress, with callback query redaction.
- Pin `SHEETS_ONE_GRID_ORIGIN`, `SHEETS_ONE_PORTAL_ORIGIN`,
  `ONE_DELEGATION_ISSUER`, `SHEETS_ONE_JWKS_URL`, and the registered
  `APP_SLUG`. Use the existing server-side assertion and proof key
  configuration. Register the exact HTTPS callback under
  `SHEETS_ONE_BOUND_CALLBACK`, ending in `/api/auth/one/callback`. Redact
  callback queries in every proxy, application log, and analytics layer.
- Apply the migration only to the isolated target database. Set a random
  32-byte base64url `SHEETS_ONE_SESSION_SEAL_KEY` consistently across Grid
  replicas. Rotating this key requires invalidating existing Grid host sessions.
  Have the database owner schedule expired-row deletion before sustained traffic.
- The local session entry points require
  `ONE_DELEGATION_ENABLED=true`, `SHEETS_ONE_SESSION_STATUS_ENABLED=true`
  and `SHEETS_ONE_HOST_SESSION_ENABLED=true`. Use the existing authenticated
  Grid session as the prerequisite for starting the confidential launch.
- Keep `SHEETS_ONE_SOURCE_RENEWAL_ENABLED` off outside the independently
  approved pilot. Renewal also requires the exact
  `SHEETS_ONE_RENEWAL_TENANT_ID` and `SHEETS_ONE_RENEWAL_INSTALLATION_ID`.
  One must independently approve the same registered client/installation and
  assurance policy. Unsupported authority modes retain their verified recovery
  path. Reauth flows must never establish a local session from the bound
  redemption response alone.

## Grid behavior and acceptance

The launch cookie is separate from the established host cookie. The database
stores a cookie digest, a revision, encrypted state and credentials, and a
bounded renewal lease. The store consumes launch state via compare-and-set.
The SDK checks the existing user, tenant, installation, One session and epoch
before storing replacement evidence. Guarded requests get a live One status
decision and retain existing workbook and downstream Drive authorization.
The relay emits advisory hints only. Each browser reconciliation checks
current status again. Lock state can be displayed without unmounting an
already open workbook, and the user unlocks in One.

Exercise start, consent, exact callback, replay rejection, lock/recovery,
logout with a concurrent renewal, an expired lease, Drive read and write, and
return to the intended workbook. The PostgreSQL fixture tests two store
instances, launch consumption, revision advancement, lease exclusion and
logout racing a credential replacement. A browser pilot must additionally
verify pending edits and ambiguous action reconciliation. The Grid checkout
did not expose a separate WebSocket gateway in the API source reviewed.
Qualify any independently deployed collaboration transport separately. The Grid activity adapter is independently switched with
`SHEETS_ONE_SPREADSHEET_ACTIVITY_ENABLED`,
`SHEETS_ONE_ACTIVITY_TENANT_ID`, and `SHEETS_ONE_ACTIVITY_INSTALLATION_ID`.
Keep it disabled until approval. Only a newly committed single-cell edit on
the protocol 2 route can report. A short-lived in-memory hint from the viewport
editor narrows eligible operations. One still checks the bound application
client, session, installation, operation policy, and idle-extension policy.
The hint alone does not establish user presence. Restored edits, receipt
replays, heartbeat and autosave do not report. Activity failure cannot
fail or repeat the accepted write. Recovery after central unlock looks up
stored receipts before scheduling any still-pending writes.

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
