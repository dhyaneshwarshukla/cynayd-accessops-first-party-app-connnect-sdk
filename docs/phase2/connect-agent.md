# Connect backend implementation and staging gate

Use the SDK `@cynayd/accessops-first-party-app-connnect-sdk@0.2.0` from the [restricted release workflow](distribution.md) once published. The [registration packet](registration.md) names the canonical app IDs, audience and client proposal. Complete approval inputs separately for each environment.

## Runtime configuration

These are proposed Connect environment variable names. Wire them into the existing service configuration and secret store.

| Variable | Production reference or source |
| --- | --- |
| `ONE_SOURCE_APP_KEY` | `cynayd-connect` |
| `ONE_IDENTITY_ORIGIN` | `https://auth.one.cynayd.com` |
| `ONE_DELEGATION_ISSUER` | `https://auth.one.cynayd.com/` |
| `ONE_DELEGATION_TOKEN_ENDPOINT` | `https://auth.one.cynayd.com/api/v1/delegations/token` |
| `ONE_DELEGATION_INTROSPECTION_ENDPOINT` | `https://auth.one.cynayd.com/api/v1/delegations/introspect` |
| `ONE_DELEGATION_LAUNCH_EVALUATION_ENDPOINT` | `https://auth.one.cynayd.com/api/v1/delegations/launch-evaluate` |
| `ONE_DELEGATION_JWKS_URI` | `https://auth.one.cynayd.com/.well-known/jwks.json` |
| `ONE_DELEGATION_CLIENT_ID` | Approved environment-specific client. Production proposal is `cynayd-connect-backend`. |
| `ONE_DELEGATION_CLIENT_KID`, `ONE_DELEGATION_CLIENT_KEY_FILE`, `ONE_DELEGATION_PROOF_KEY_FILE` | Registered active KID and protected backend mounts. No default secret file values. |
| `CONNECT_ONE_CALLBACK_URL` | Exact existing approved callback from the Connect and One owners. Callback transport and state are staging acceptance items. |
| `CONNECT_DRIVE_ORIGIN`, `CONNECT_DRIVE_AUDIENCE` | Production `https://api.drive.cynayd.com` and `cynayd-drive`. Use isolated fixtures on staging. |
| `CONNECT_DRIVE_DELEGATION_ENABLED` | Off until the pilot and its operation allowlist are accepted. |

Load only One endpoints from trusted environment configuration. The launch entry is `GET /api/sso/launch/cynayd-connect` or an approved portal code-launch flow with `POST /api/sso/exchange-code` and backend redemption at `POST /api/sso/redeem-code`. Use the registered return with application-owned one-time callback state bound to the same browser transaction. One's code redemption takes `code` and `appSlug` and does not echo arbitrary app state. Verify the actual Connect callback flow in staging. If using an existing verified direct return, immediately validate the credential server-side, remove it from the browser URL, and prevent referrer and log capture. Match canonical user, organization and exact source installation with the trusted local session or verified launch transaction before the atomic session revision update. On reentry, do not attach a different person, tenant or installation.

Call `/api/sso/validate` for the Connect app with `includeDelegationSubject:true`. Keep verified evidence and token deadlines server-side. Exchange only while the fixed source binding is live. On expiry, present an explicit reconnect action that re-enters One. Resume with the same session only after matching the canonical binding. Active unlocked One sessions can often continue silently. Invalidate local evidence on logout and use live authorization for every target operation.

## Chat and Connect operation boundary

Keep a single registered operation table in the Connect backend. Each entry has exact origin, method, route/parameter predicate, audience and smallest approved scope. Proposed source contracts, to be mapped onto existing Connect API conventions:

| Operation | Authorized input | Result |
| --- | --- | --- |
| List Drive content | Authenticated Chat/Connect action, optional validated folder ID, cursor and limit | Sanitized file/folder items and pagination cursor |
| Read metadata or stream contents | Authenticated operation and Drive file ID | Sanitized metadata or bounded stream. Check operation-specific link and cache rules before exposing previews or downloads. |
| Create attachment folder | Authorized chat context, approved parent ID, validated name, operation ID | Drive folder ID and operation status |
| Upload attachment | Authorized chat context, same approved destination, multipart data and operation ID | Drive file ID and sanitized attachment metadata |
| Update attachment content | Approved Drive file ID, content, expected version or idempotency context | New version and sanitized status |

Validate existing Chat membership, the user's action and destination and the intended scope before calling `DelegationClient.call`. Drive must still check its own resources. Chat calls these operations through the proof-key-owning backend. It receives operation data and errors, never a delegated token or proof key. Keep sharing disabled until the Drive owner qualifies a central route and scope. Preserve existing worker and unrelated login paths.

Return status, safe code, next action and request ID. Preserve upstream `access_denied` and resource ACL denial distinctly. A missing client/grant and an absent user assignment have different causes. Preserve the supplied `429 Retry-After` and classify an unavailable authority as retryable `503`. Only documented source/session errors prompt reconnect. For ambiguous writes, reconcile by operation ID before retrying. Keep raw upstream payloads, headers and credentials out of logs and browser responses.

## Qualification matrix

Use an explicitly designated staging environment, approved registrations, one assigned allowed user, one unassigned user, revoked or expired fixture sessions, two distinct tenant contexts, shared and unshared files and folders, and a write-only test destination with disposable content. Use known fixture IDs rather than customer data.

| Evidence to capture | Expected |
| --- | --- |
| Same Connect launch, Drive read and write | Accepted reads, parent-authorized create/upload/update, contents committed and visible. Use separate read/write exchange scopes. |
| Missing delegation grant versus missing app assignment | One denies both. Distinguish grant rejection from the AccessOps assignment denial. |
| File and folder denied, wrong tenant or installation, narrow scope | No metadata leak, bytes, mutation or side effect. |
| Expired source, expired target, and reconnect | Source prompts reconnect, expired target denies and requires fresh exchange, same session resumes only with a valid binding. |
| Revoke after issuance, replay across two resource instances | Next protected call denies after revocation. At most one instance accepts a given proof. |
| Authority/introspection or replay storage failure | No successful read or write; structured retry or rate-limit response with request ID. |
| Existing Docs → Drive and Grid → Drive | Authenticated reads and saves still work, ACL denials remain effective, and existing worker paths continue. |

Record UTC time, environment, sanitized fixture label, operation, HTTP status/code, request ID and confirmed side effect or denial. Screenshots and traces must omit credentials. The [local fixture](../../examples/connect.cjs) demonstrates the transport and session flow. The One isolated tests cover the resource-client scope question and denied grants. Approved shared staging registrations and authenticated test accounts were not available in this workspace, so business endpoint results remain pending.
