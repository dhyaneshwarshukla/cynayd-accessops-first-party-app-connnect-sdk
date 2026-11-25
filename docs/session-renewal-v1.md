# First-party session renewal v1

SDK candidate `@cynayd/accessops-first-party-app-connnect-sdk@0.3.0`. Deploy compatible One backend and portal builds before enabling this flow in a consumer. A browser launch, resume code, delegation subject, source API token and resource token have distinct lifetimes.

## Existing lifecycle

| Layer | Existing authority and behavior |
| --- | --- |
| Portal access and refresh | One owns the access cookie and rotating refresh family. Legacy refresh may slide the login row using existing policy. Go refresh uses the Security Authority receipt; applications must treat the issued deadline as authoritative. |
| Central session | One checks the login row, account and revocation. Legacy uses the effective web/mobile idle policy. Go validation checks central policy, device revocation and account state. Delegation validation does not record activity. |
| Portal screen lock | One’s resume page waits for the portal lock state, including synchronization among One tabs. The issue endpoint enforces the server-side PIN rule. Product tabs still need their own protected-operation gate while the portal or product is locked. |
| Launch evidence | The verified browser launch records user, tenant, canonical app, installation, access epoch and login session. The binding expires at the earlier of portal access JWT expiration and the authoritative session row's expiration at issuance. |
| Source | The app API token and separately signed delegation subject have different deadlines. Validating an existing source token can reissue a subject only within the original launch binding. The SDK v0.2.0 additionally included the consumed launch JWT deadline in its application session minimum. |
| Target | One exchanges the subject through a registered confidential client with proof of possession. AccessOps evaluates source and target. Target token TTL is capped at five minutes and the resource checks DPoP, live introspection and ACLs. |
| Logout | One exposes device logout and global logout. Revoked sessions are rejected by live delegation checks. The app must also invalidate its own server session revision and discard locally cached credentials. |

## Wire contract

From an authenticated application, a visible user action starts a short-lived, one-time server-side return transaction. Build the browser destination with `oneResumeUrl({ portalOrigin, appSlug, callbackUrl })`. The trusted portal uses `GET /apps/resume?mode=renew&appSlug=…&returnUrl=…` and validates the return URL against its app origin registry. Register a fixed application callback, with no query or fragment. Connect uses its approved origin and `/one-drive-return`.

After One's existing browser session and lock checks, the portal sends `POST /api/sso/resume-code` to configured One Identity.

- JSON request `{"appSlug":"cynayd-connect"}`. The server reads the authenticated One portal token and derives the user, tenant and login session. Cookie requests require One’s XSRF cookie and matching header. Bearer requests must supply a valid human portal access JWT.
- Success is HTTP 200 with `{"success":true,"code":"<opaque one-time code>","expiresIn":<seconds>}` and `Cache-Control: no-store`. No credential exchange or write grant is implied.
- Authentication failure returns `401 SESSION_EXPIRED / REAUTHENTICATE`. PIN and MFA requirements use 403 with unlock/enrollment guidance. Canonical source denial returns `403 ACCESS_DENIED`. The existing bounded rate limit returns 429 and `Retry-After`. Infrastructure or authority failures return 503 and retry guidance.
- The portal sends only the code to the approved application callback. The SDK redeems it once through `POST /api/sso/redeem-code` with `{code,appSlug}`, then calls `POST /api/sso/validate` with `{token:ssoToken,appSlug,includeDelegationSubject:true}`.
- Existing `sessionInfo` fields are retained. `delegationSubjectExpiresAt` is added for the signed subject expiry. SDK `sourceEvidence` exposes `launchTokenExpiresAt`, `portalBindingExpiresAt`, `subjectExpiresAt`, and `apiTokenExpiresAt` as Unix milliseconds. The portal binding deadline describes the issued evidence and is distinct from the authoritative central session lifetime.
- The endpoint validates the session without recording activity or rotating refresh tokens. The browser portal can use its existing portal refresh flow under One policy. A still-current portal token may yield a fresh code with the same effective deadline. The SDK then returns `409 SOURCE_RENEWAL_NOT_ADVANCED`; keep the existing credential until it expires and apply bounded retry or prompt the user on the next protected action.

The renewed subject must carry the same One login session, canonical user, tenant, source app, source installation and access epoch. A changed session or epoch requires a fresh verified app launch after authorization, with no reuse of the old transaction. The SDK asks One's confidential launch evaluation endpoint to recheck AccessOps before the app commits the credentials. Later delegated operations still exchange and introspect independently. The flow changes neither session deadlines nor the evidence signer's verification requirements.

## Backend integration

1. Upgrade the package and pin the approved release. Opt into `useEvidenceDeadlines` so a consumed launch JWT does not shorten one verified session. Bootstrap existing stored v0.2.0 sessions with a fresh verified launch whenever trusted central session binding is absent.
2. Use `sourceRecoveryStatus(session, leadMs)` to surface `ACTIVE`, `RENEWAL_DUE` or `EXPIRED` on foreground interactions and after visibility or network resume. Background work must not launch a browser resume.
3. Create a bounded, single-flight transaction per host session revision in shared storage. Store expected canonical IDs, credential revision and an unpredictable one-time state server-side. Bind it to the initiating host cookie and resolved callback. Use a Secure, HttpOnly cookie compatible with a top-level return, and recover the state server-side. The existing portal strips state parameters from return URLs.
4. On the callback, call `completeSourceRenewal(one, {code,state}, states, store)`. The atomic state consume and atomic revision advance must work across nodes and tabs. The browser may signal completion to same-origin tabs with just an operation identifier. Reload credentials from the backend and authenticate the browser session on every request. Redact callback query parameters in ingress, app logs, traces and browser referrers. Immediately redirect to a clean URL.
5. Resume protected operations with the renewed server-held subject through `DelegationClient.call`. Retain request correlation IDs and structured recovery actions. Use idempotency keys for queued mutations or verify the outcome before retrying; never replay an ambiguous upload automatically. Handle transient upstream errors with bounded backoff and keep drafts.
6. During local logout, invalidate the host session revision and pending renewal state atomically, then clear product session cookies. For central logout use One’s existing device or global operation. Stop protected work when central exchange or introspection rejects; app tabs must observe host logout. Preserve drafts encrypted or access-controlled under app policy.

## Activity and locking

The release adds no product heartbeat or user-facing central activity write API. Portal UI already has its own lock/activity handling. Start renewal on foreground, user-initiated interaction and keep the workspace open where possible; a hidden iframe, browser timer, polling loop, autosave request, service job or merely visible tab is insufficient. Treat client input reports as hints rather than evidence. A future common activity bridge would require One policy to explicitly allow it, origin-bound browser authentication, a fresh user-present interaction gate, monotonic deduplication/rate limiting, and an authority-owned update that can never change absolute expiry or unlock a session. Record separately from renewal. Existing Go device and security checks continue to govern issuance. Existing portal screen-lock enforcement on already-issued target tokens has not been qualified; verify protected actions during lock across applications before rollout.

## Consumers

| Consumer | Integration work |
| --- | --- |
| Connect and Chat | Connect owns the assertion and DPoP keys, callback and protected store. Chat calls Connect’s authorized backend operation for attachments. Keep draft metadata and an idempotency key across return. Register and verify the exact pilot installations. |
| Docs and Grid | Use the same lifecycle for One JWT launch and Drive exchange. Preserve unsynced document, presentation and cell edits in a local queue. Run each existing Drive authorization and persistence check. |
| Mail | Bind the same shared session flow before attachment delegation. Preserve compose state and enforce target permissions. |
| Drive | Integrate the shared lifecycle for Drive-as-source when ready. As resource, keep live introspection, atomic proof replay and ACL checks. |
| Calendar | Use canonical `cynayd-calendar-tasks` for verified browser resume after operator verification. Its delegation registration and resource rollout are independent of the Drive pilot. |
| HRMS and CRM | Confirm canonical app IDs, launch mode and registered HTTPS callback origins with their owners. One’s checked-in resume origin registry does not list these products. Any SAML-first deployment must preserve its verified federation flow. |
| Groot | The checked-in One portal registry has a local Groot fixture. Verify the actual production canonical entry and HTTPS origin before rollout. |

## Acceptance

Local tests exercise the SDK's deadline decisions, a virtual 1/4/8/12-hour sequence, repeated exchange, same-session renewal, concurrent state consumption, logout racing a callback, revoked/denied/unavailable authority, and existing exchange/introspection regressions. The virtual fixture is not an authenticated soak.

Run the real pilot for one, four, eight and twelve hours with approved Connect ↔ Drive installations and test users. Observe legacy and Go-policy cases where approved. Cover presentation autosave and Chat upload over renewal with empty, pending, and ambiguous-write queues; multiple tabs and products; sleep/resume; offline recovery; lock/unlock; admin revocation and global logout; incorrect tenant and installation; concurrent callbacks; expiry, Identity/AccessOps outage and retry behavior. Capture sanitized time, correlation ID, policy mode, operation, status, user prompts and draft recovery outcomes. For policy-enforced expiry, revocation, lock and step-up, verify that protected operations stop according to policy. Never put codes, tokens, proofs or drafts in the evidence.

Connect staging requires the approved tenant and exact active installations, confidential client `cynayd-connect-backend`, signed public assertion key, approved callback, callback query redaction, one expiring `cynayd-drive` read grant and a separately approved write grant. The registry proposal and existing operator controls remain the source of truth. See [registration](phase2/registration.md) and [Connect handoff](phase2/connect-agent.md). No staging approval or acceptance evidence was available for this candidate.
