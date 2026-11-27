# Common first-party host integration v1

The implementation candidate is SDK 0.6.0-rc.7. Use the SDK server export for confidential launch, verification, live status, renewal and activity. Use the browser export for same-origin host transport and revalidation signals. Framework, persistence and business authorization adapters belong to the host.

## Registration and entry

Register the application slug, confidential client, exact HTTPS callback, signing and proof keys, allowed audiences and scopes in the existing One and AccessOps systems. Map trusted entries in One using `ONE_BOUND_LAUNCH_TRUSTED_ENTRIES`, an object keyed by app slug with `clientId` and `callback` values. Every entry must also match `ONE_BOUND_LAUNCH_CALLBACKS`. Use the registered product origin for both launcher and direct entry. Existing Grid pilot behavior is retained when the trusted-entry map is absent.

The host serves `POST /start`, `GET /callback`, `GET /session`, `GET /events` and `POST /logout` under a single same-origin prefix. Start checks browser origin, sanitizes the product return path, calls `DelegationClient.initiateBoundLaunch` and stores the verifier and state behind a short-lived host-only transaction cookie. The browser follows the SDK-validated One URL. One checks the canonical browser session, lock and live AccessOps entitlement before binding and approval. The portal automatically approves exact trusted registrations. One presents required authentication and unlock in the central flow. An untrusted registration keeps its explicit confirmation flow.

The callback checks transaction ownership and matches request and state, then uses `OneApplicationSession.completeBoundLaunch` to redeem once with the confidential verifier and proof. Initial entry obtains user, tenant, central session and installation from signed One evidence. A single-installation host can additionally pin the expected tenant and installation. Recovery for an existing host verifies the same user, tenant, installation, central session and access epoch. Commit the host session using revision CAS and invalidate the replaced host in the same transaction. Return using a sanitized host path. Suppress caching and referrers on the callback.

## Protected requests and lifecycle

- Store tokens, renewal capabilities, signing keys and proof keys on the backend. Seal host credentials in shared storage. The browser receives an opaque Secure, HttpOnly, host-only cookie with SameSite=Lax and a root path. Check explicit origin on browser mutations.
- Bind product requests and pending work to the UI's verified tenant, user and installation. The host compares this context with its authenticated identity. Every protected operation uses live central status and existing resource authorization. A session response contains only the identity needed by the UI.
- Use `activeBoundSession` for live validation and current-credential checks. Pass the shared lease coordinator to enable eligible optional renewal near source expiry. The SDK coordinates with the host's shared lease and revision store. The durable claim precedes credential dispatch. An ambiguous attempt triggers verified browser recovery instead of reusing the capability. Check live status before releasing the protected operation and confirm the credential remains current. One and Go decide eligibility, lock and expiry.
- Send activity only after an accepted, authorized foreground command, using a stable operation ID. Background jobs, ordinary fetches, polling, refetches and autosave are passive.
- Translate the authority's result into reconnect, sign-in, lock, access denial or retry. The browser revalidates on push, visibility, connectivity or an advisory hint. The SDK deduplicates launch attempts and limits automatic redirect loops. Hosts keep held edits associated with the verified context and reconcile committed receipts before resubmission.
- Host logout clears local credentials and launch state. One logout, lock and entitlement revocation take effect at live checks. Relay notifications only prompt revalidation. Explicit local sign-out suppresses immediate automatic launch.
- Resource-specific assurance, roles and ACLs remain at their existing owners. Drive and other downstream exchanges continue to use server-held delegated evidence and their registered audiences.

## Host response shape

`POST /start` takes a local return path and returns `{ authorizationUrl }`. The callback carries opaque `request`, `code` and `state`. `GET /session` returns `{ userId, tenantId, installedAppId, email }` on success. A missing cookie returns HTTP 401 with `HOST_SESSION_REQUIRED`. Grid currently supplies its compatibility code via the browser SDK option. Central decisions use recognized machine codes and actions including `RECONNECT`, `REAUTHENTICATE`, `UNLOCK`, `ACCESS_DENIED` and `RETRY`. `GET /events` emits `session` SSE events. `POST /logout` returns 204 on completion.
