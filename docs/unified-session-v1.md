# Unified session contract v1

This is the local contract for SDK v0.4.0 and a compatible One service. One Identity owns portal authentication, refresh rotation and the canonical login row. Security Authority owns Go session eligibility, deadlines, policy and device checks. Legacy sessions retain One's existing idle rules. AccessOps owns current application assignments and installation resolution. Resource services own ACLs. The SDK preserves all three boundaries and stores no central session authority.

## Architecture assessment

| Existing component | Reuse and current boundary |
| --- | --- |
| Portal JWT and refresh | One browser holds portal access and rotating refresh credentials. Go refresh is authority-controlled. Existing legacy refresh policy remains in effect. |
| Session checks | The same passive central validation used by delegation checks Go eligibility, account status, device status, revocation and policy revision. Legacy validates its effective idle policy. |
| Screen lock | Existing PIN verification handles proof and attempt limits. Account-wide activity and portal lock cookies had no per-session backend enforcement on delegated tokens. An opt-in lock overlay on the existing session row now supplies explicit per-session enforcement to One's delegation paths. |
| AccessOps | Status checks source entitlement and access epoch. Exchange and introspection still check both source and target, the grant and resource revisions. |
| Delegation | Source evidence expiry and target expiry are separate. Resource introspection reruns the source session gate, including explicit lock when enabled. Resources must continue to validate DPoP and ACLs. |
| Revocation and logout | Existing One device or global logout revokes the canonical login session. The app must also invalidate its server session, queued renewal and credentials. |
| Step-up | Go transport validation rejects changed policy. Operation-specific freshness and step-up remain with their existing security gates; generic status does not authorize a sensitive action. |

## Silent status

Send form-encoded `POST /api/v1/delegations/session-status` to the configured One endpoint. Use the same `client_id`, `client_assertion_type`, `client_assertion`, `subject_token`, `subject_token_type` fields and DPoP header as launch evaluation, with the assertion and proof bound to this endpoint. Discovery exposes `session_status_endpoint`. Supply no identity fields. One derives identity and installation from signed subject and its stored launch provenance, then verifies central status and current canonical AccessOps approval. Each request has a fresh proof, assertion and replay check. The result never issues credentials or updates activity.

HTTP 200 returns `state=ACTIVE`, `reason=SESSION_VALID`, `nextAction=NONE`, source `accessEpoch`, opaque lock `revision` (nullable when disabled), `centralExpiresAt`, `subjectExpiresAt` and nullable `idleExpiresAt` and `lastActivityAt`. Dates are ISO 8601. A revision is a stale-state detector scoped to a central session. It is not proof of authorization or permission to skip validation.

| State | Transition and action |
| --- | --- |
| ACTIVE | Current central session and source AccessOps grant verified. Continue under the operation's own authorization. |
| RENEWAL_DUE / EVIDENCE_REQUIRED | SDK observes a local deadline or One can no longer verify evidence. Begin the existing browser resume when appropriate. Expired evidence alone cannot tell the app whether its central session expired. |
| RENEWAL_IN_PROGRESS | App server owns a bounded per-session renewal transaction. Share its outcome across nodes and tabs. It does not change central state. |
| INACTIVITY_WARNING | Client advisory based on the returned idle deadline. Only the central authority determines actual expiry. |
| LOCKED | HTTP 403 `session_locked`. Use One PIN verification. No protected operation should proceed. |
| STEP_UP_REQUIRED | HTTP 403 for changed Go transport policy. Return to One for required authentication. Other operation-specific challenges keep their existing paths. |
| EXPIRED / REVOKED | HTTP 401 when centrally identified from valid provenance. Stop protected operations and invalidate app credentials. Some Go eligibility failures have a generic evidence outcome. |
| ACCESS_CHANGED / ACCESS_DENIED | HTTP 403 when an access epoch is stale or canonical app approval is denied. An epoch change requires a verified launch. Product file or folder denial remains separate. |
| AUTHORITY_UNAVAILABLE | HTTP 503, bounded retry. Retain queued work. Authentication and proof errors are distinct, and HTTP 429 preserves `Retry-After`. |

Do not call status ahead of every exchange. Use exchange/introspection as the operation gate where already present. Use status for a direct protected application operation, user-driven foreground recovery, or one coalesced reconciliation after an invalid target credential. Avoid periodic per-tab polling and positive decision caching. A check reports state at the time of authorization. A lock cannot undo an operation already authorized and committed.

## Explicit lock and synchronization

`ONE_CENTRAL_SESSION_LOCK=true` enables the local candidate. A verified human portal session with PIN configured can send a protected `POST /api/auth/session/lock`; cookie callers use the existing XSRF mechanism. One writes an opaque revision and lock state into its existing `sso.sessions` metadata. A PIN success at `POST /api/auth/pin/verify` updates that exact session only if the revision read before verification is current. A newer lock, session expiry, rotation or revocation prevents the stale write. PIN verification and account lockout remain the existing implementation. PIN success with this feature no longer writes account-wide activity. Device and tenant session rows are isolated.

The One PIN status, verified launches, subject issuance, silent status, delegation exchange and introspection check the explicit lock. A previously issued token introspects inactive while its source session is locked. A product must enforce status on protected direct operations and suspend background writes during a lock. Direct product enforcement has not been integrated across repositories. Portal inactivity remains on its existing path. There is no centrally emitted cross-origin event transport in this candidate.

The browser-only `./browser` export sends opaque same-origin invalidation hints and observes network and visibility transitions. Coalesce these hints to one backend reconciliation per app session. A hint never unlocks a session. Cross-origin applications learn state from their next protected operation or bounded foreground reconciliation. To add push, use a One-owned, authenticated session event stream or existing approved delivery infrastructure. Route by central session and send only an invalidation identifier. A reconnect or missed event requires a fresh central check. Never forward source evidence, PIN, assertion or portal credentials in messages. One PIN verification updates the eligible session; tab UX remains an application adapter responsibility.

## Activity contract and acceptance policy

An activity write API is **proposed and disabled** pending an approved source-operation evidence and central enforcement contract. Product typing, keypress, focus, visibility and input timestamps are hints and cannot act as authenticated keepalives. Background polls, sockets, autosave, AI tasks, scheduled work, renewal and hidden tabs do not qualify.

Proposed ingress uses the same client assertion and DPoP envelope and verified session subject as status, plus an approved operation class and opaque backend event ID. Resolve person, tenant and installation from provenance. Require authoritative evidence of a committed foreground product command and an active, unlocked session. Examples for policy review include sending a message, explicitly saving an edit, composing mail through an approved user-present command, or an interactive file operation. Reject unapproved classes, stale or duplicate events, and substituted bindings. A 202 acknowledgement should reflect an authority-accepted update. Duplicate IDs must be idempotent. Use server time, authority-owned rate limits per central session across all apps, minimum reporting intervals, and atomic ordering with lock/revocation. Never change absolute expiry, unlock state, or step-up policy through activity. Go's existing activity update must participate in the same lock/revocation ordering before a write API can be exposed. Automatic inactivity lock and application-wide activity aggregation are blockers.

## Renewal and product migration

Retain the [v0.3.0 verified browser resume flow](session-renewal-v1.md). A registered backend and a previous launch by themselves do not establish a fresh browser/device/PIN/step-up state. No backend-only source renewal or portal refresh token handoff is enabled. Keep one browser recovery transaction per host credential revision. On `SOURCE_RENEWAL_NOT_ADVANCED`, retain the current evidence and suppress automatic re-entry for that deadline and revision. Let a user retry on an eligible foreground action after the portal refresh window. Mint target tokens through the existing exchange; suppress duplicate concurrent exchange and never reuse a DPoP proof.

- **Connect and Chat** use the approved return path and keep source and proof keys on Connect. Chat invokes operations over the authenticated backend. Persist draft text and attachment intent safely. Track upload operation IDs and verify an ambiguous outcome before retrying.
- **Docs** checks authoritative state for protected operations that do not already use a live resource gateway. Queue unsaved document and presentation changes by document and version. Reconcile permission and version before resubmission.
- **Grid** follows the same direct-operation checks and saves pending edits by spreadsheet, tab and mutation ID. Resume delegated Drive operations through the same SDK. Reconcile version conflicts and ambiguous writes.
- **Mail and other first-party products** use the same mechanism and approved source/installation registrations. Preserve user work under the host application's storage policy. Avoid independent keepalives and unlock authorities.

## Qualification

The controlled SDK clock sequence covers 1, 4, 8 and 12 simulated hours. Isolated One tests cover confidential status, the database-bound lock revision, unlock races and an already-issued delegated token during lock. These tests do not establish browser or staging timing. Qualify four timed runs with approved staging users and exact grants, multiple products and tabs, expired/locked/revoked sessions, outages, sleep and visible resume, autosave and upload lossless reconciliation, network partitions and concurrent recovery. Probe forged and duplicate activity once an authorized activity adapter exists. Record p50/p95 validation and renewal latency, authority calls per operation, reconciliation bursts on resume, and accepted activity events per central session. No authenticated staging performance figures are available.
