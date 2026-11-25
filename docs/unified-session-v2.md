# Unified session contract v2

SDK candidate `@cynayd/accessops-first-party-app-connnect-sdk@0.5.0` builds on [silent status and explicit locking](unified-session-v1.md) and [verified browser resume](session-renewal-v1.md).

## Qualified activity and automatic lock

Enable a pilot with `ONE_CENTRAL_SESSION_LOCK=true` and `ONE_CENTRAL_SESSION_IDLE_LOCK_SECONDS` from 120 through 86400. Align this interval with the authority's existing idle and absolute policy. Automatic locking applies to PIN-enrolled sessions. The first lock anchor is session creation. Qualify freshly launched staging sessions before switching an existing cohort.

Configure exact `appSlug:operation` pairs in the comma-separated `ONE_FIRST_PARTY_ACTIVITY_POLICY`. An empty policy denies all activity. Do not reuse these examples as authorization or derive names from display names. The operation set is `message.send`, `document.edit`, `presentation.edit`, `spreadsheet.edit`, `mail.compose`, `mail.send`, `file.interact` and `record.edit`.

Send form-encoded `POST /api/v1/delegations/activity` using the standard registered client fields, signed assertion, DPoP, `subject_token`, and `subject_token_type`. Also send `operation` and `event_id`. The event ID is an opaque application-server command identifier matching `[A-Za-z0-9_-]{16,128}`. Set the assertion audience and proof target to this endpoint. Discover the route with `activity_endpoint`.

One rechecks source provenance, exact installation and tenant, current AccessOps assignment and access epoch, live session, device and policy. The existing client rate limit and proof replay checks apply. The session row serializes activity and lock writes. One uses database time, rotates no credentials, and consumes the application event ID for at least the replay retention window. The central row accepts at most one clock update per 30 seconds across registered sources. An accepted duplicate or coalesced report returns `{"accepted":true,"updated":false}`. Accepted activity can postpone only this inactivity lock. It does not extend the central idle or absolute deadline or confer new assurance. Already-due, expired, locked, revoked and unauthorized reports fail closed.

Application adapters must classify an authenticated, authorized, meaningful command from server semantics and report promptly after acceptance. Do not expose a general browser activity proxy. Client focus, visibility and trusted-event flags may narrow adoption, but they cannot establish user presence on their own. Do not call from polls, autosave, heartbeat, background AI, renewal, invisible tabs or automated jobs. A compromised registered backend can mislabel its own allowed commands, so review the adapter before allowlisting any pair.

The lock transition is computed at the next relevant One status, launch, or delegation access. No sweep is required for enforcement. Expiry and revocation still take precedence. A valid PIN updates the exact central session and starts a fresh overlay interval via compare-and-set. A stale or simultaneous PIN attempt cannot clear a newer lock.

For the portal pilot, enable `NEXT_PUBLIC_ONE_CENTRAL_INACTIVITY_LOCK=true` together with backend configuration. The portal uses passive PIN state checks and disables its periodic legacy activity writes. Hidden tabs do not run the reconciliation request. The old frontend timer is bypassed only when One confirms the central policy manages the PIN-enrolled session.

## Protected operations and synchronization

Authenticate the host application session and resolve its verified server-side credentials. Protect direct business operations with `withCentralSession(client, credentials, async state => ...)`. The callback must still apply the operation's existing ACL or AccessOps checks as appropriate. Reject when One cannot confirm current state. No shared positive authorization cache is used. For operations already enforced by delegation exchange and resource introspection, omit the extra status call.

Use one `SessionEventMonitor` per product backend process. The key is the verified host session identifier and must never be reassigned. Subscribe through an authenticated, same-origin SSE route. Do not expose source session references, assertions or browser tokens. Encode events with `encodeSessionEvent` and release subscriptions when the stream closes. Deliver any protected state only through independent live authorization. The browser `./browser` export attaches to the application's own endpoint with `observeSessionEventStream`.

The per-process monitor shares one passive check across subscribers for the same host session. It checks about once a minute by default, with jitter. Apps on separate origins use their own relay, backed by the same One row. Events are advisory invalidations. The browser discards ordering assumptions and reloads current state from its own backend. Active snapshots can carry the opaque authoritative lock revision. Lock, unlock, expiry, revocation, local logout and credential-renewal hints are supported. A logout elsewhere that One only records as revocation is reported as `SESSION_REVOKED`. A lock and unlock entirely between observations may be missed by the stream, while backend protection remains live. There is no central push bus or cross-replica subscription lease in this candidate. Prototype SSE integration must be qualified for delivery lag, reconnect fan-out and revocation behavior.

## Connect, Docs and Grid

```ts
// Inside an existing authenticated product handler. Derive the class on the server.
const result = await withCentralSession(client, credentials, async () => {
  await requireProductPermission();
  return performIdempotentCommand();
});
if (result.foregroundCommandAccepted) {
  await client.reportActivity(credentials, reviewedOperationClass, result.commandId);
}
```

- Connect reports reviewed message commands. Keep attachment selections and draft text outside authentication state. Chat uses Connect's authorized backend for delegated uploads. An ambiguous upload requires lookup or idempotent confirmation.
- Docs reports only an approved foreground edit command. Autosave never reports activity. Preserve presentation and document changes in the existing pending-edit queue, and reconcile permissions and versions on resume.
- Grid uses the same approach for spreadsheet commands. Keep edit versions and mutation IDs. Resolve permission and conflict state before resubmission.
- Mail, Drive, CRM and HRMS must approve exact application registrations and validate their server command adapters before enabling eligible classes.

Report failures separately from an already committed product command. Apply bounded retries with the same event ID, or drop the report if its originating interaction is stale. Keep One's browser code recovery and the v0.4.0 `SOURCE_RENEWAL_NOT_ADVANCED` suppression. Existing target exchange continues to create short-lived DPoP credentials. No backend-only source renewal is introduced.

## Compatibility

| SDK | One contract | Consumer expectations |
| --- | --- | --- |
| 0.2.0 | Verified launch and delegation | Existing routes and response fields retained |
| 0.3.0 | Verified browser resume | Requires One resume-code support |
| 0.4.0 | Passive status and explicit lock | Requires session-status support for direct checks |
| 0.5.0 | Qualified activity, inactivity lock and SSE adapters | Requires activity route, aligned pilot configuration, audited adapters and application relay |

Staging must verify each allowed cell of the policy, an inactive portal with active Connect, eight hours of presentations, product convergence during concurrent lock/unlock/logout, sleep/network recovery, installation isolation, timed revocation, and authenticated upload and autosave reconciliation. Controlled-clock SDK execution is not an authenticated soak test.

## Local performance measurements

Node fixture results after 10 warm-up calls and 100 timed sequential calls per path. The fixture signs client assertions and DPoP proofs and validates the mock resource request in-process. Times omit network, production database, Redis, and AccessOps latency.

| Fixture operation | p50 | p95 |
| --- | ---: | ---: |
| Silent status | 1.15 ms | 1.57 ms |
| Activity report | 1.18 ms | 1.81 ms |
| Drive exchange, resource proof and fixture introspection | 3.71 ms | 5.00 ms |

Sixteen concurrent Drive calls with the same credentials and operation shared one exchange. Sixteen event subscribers for the same backend session shared one status request. These figures do not establish replica-wide coalescing or staging latency. The [broader regression comparison](unified-session-regression.md) records the baseline and both candidate results.
