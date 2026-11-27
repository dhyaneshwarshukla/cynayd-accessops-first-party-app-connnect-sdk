# Integrate a first-party application with CYNAYD One

Use the confidential bound-launch profile for new browser integrations. One owns authentication and browser credentials. Go Security Authority decides central session validity and renewal. AccessOps decides whether the current person may use the installed application. Your backend owns its host session and product ACLs. The SDK keeps those boundaries in one integration.

## 1. Install an exact SDK version

Pin the approved release and verify its integrity against the private release record. Commit the lockfile. Consult [release controls](phase2/distribution.md) for restricted registry access. The 0.6.0-rc.9 source is a candidate. Use a locally verified tarball for evaluation until an operator publishes an approved release.

```sh
npm install --save-exact /path/to/cynayd-accessops-first-party-app-connnect-sdk-0.6.0-rc.9.tgz
python -m pip install '/path/to/cynayd_first_party-0.6.0rc9-py3-none-any.whl[fastapi]'
```

## 2. Configure One and AccessOps registration

Send the application key, client ID, exact HTTPS landing and callback, RSA public assertion key and P-256 thumbprint to the One operator. Use an existing AccessOps installation and approved tenant policy. Use a launch-only profile when the application has no outbound delegation. Request resource scopes only for reviewed operations. Follow [One’s registration workflow and public templates](registration.md).

## 3. Mount the server adapter

Start from the [configuration template](../examples/host/.env.example). Match `APP_ORIGIN` and `ONE_EXACT_CALLBACK` to the actual edge routes and approved profile. `ONE_PORTAL_ORIGIN` is the browser-facing portal. The SDK sends confidential calls to `ONE_TOKEN_ENDPOINT`, using the registered assertion KID and proof key. Verify the identity issuer, delegation token endpoint and signing JWKS against the authorized One deployment’s `GET /api/v1/delegations/metadata`. Keep them in backend configuration. The portal origin alone is enough for browser configuration.

| Runtime | Integration |
| --- | --- |
| Node.js or Express | Install `pg` and `express` for the reference. Copy [config.cjs](../examples/host/config.cjs) and [express.cjs](../examples/host/express.cjs). Mount the Node handler before body parsing. Native HTTP can call the same handler for the configured route prefix. |
| NestJS | Use the shared [configuration](../examples/host/config.cjs) and [Express-based Nest bootstrap](../examples/host/nest.ts). Protected guards call `host.authenticate` and carry the verified identity into the operation. Register the SDK error mapping in the guard or existing exception filter. |
| Next.js | Use the [Node runtime route handler](../examples/host/next-route.ts) and the same configuration module. Adapt the import path to your project and use Node 22+ for separate Set-Cookie headers. Keep the config out of Client Components and middleware that runs on the Edge runtime. |
| FastAPI | Use the [FastAPI app](../examples/host/fastapi_app.py) with the installed Python SDK, `uvicorn`, and the included `fastapi` extra. Supply the exact operator-approved tenant-to-installation map in `ONE_APPROVED_INSTALLATIONS` and an application-owned pool. |

Host mutations require the browser’s exact `Origin`. Preserve it through your reverse proxy. The launch callback is a top-level GET with a one-use browser-bound transaction. Exclude callback query strings, cookies, raw headers and credential payloads from request logging and telemetry. All examples default to a root-only return path. Extend that allowlist for your real routes and keep auth and redirection endpoints out.

Protect HTTP, realtime handshakes and protected messages, and resumed user-initiated execution. Run live status before each protected operation, then apply your existing product ACL. Bind request context, unsaved work and retries to the verified person, tenant, and installation. A valid session in another account cannot inherit held work. Use immutable command IDs and reconcile receipts before replaying any ambiguous write. Server-rendered or statically generated routes must enforce the same rules before delivering protected content.

## 4. Configure the browser adapter

Import the browser entry point and use the [React session gate](../examples/host/session-gate.tsx) or the [standalone browser entry](../examples/host/reference-browser.mjs). Use the same path prefix as your server and the registered portal origin from public configuration. For React without Next.js, use your bundler’s public configuration in the portal origin callback. The browser transport validates that One returns the expected authorization destination. Enable automatic entry and same-account reconnect through the bound launch flow. Browser state and events only schedule live checks.

## 5. Establish host-session persistence

Apply [the PostgreSQL schema](../examples/host/schema.sql) to the application’s database. Each application and runtime needs its own schema or database and seal key. Use a separate random 32-byte key in the application’s approved secret store, encoded base64url. The database stores hashed opaque cookie handles, sealed payloads, expiry and revisions. PINs, JWTs, and renewal capabilities never go in browser state. Treat host row retention as a storage limit and use live One status for current access. Schedule owner-approved cleanup for rows whose `expires_at` has passed. Manage seal key rotation with a coordinated host session reset or a reviewed multi-key store.

Keep the durable claim and credential revision update atomic. Recovery commits a fresh handle and retires its predecessor at the captured revision. Configure renewal only when the bound client and organization have approved source renewal and the matched deployment has qualified it. Ambiguous renewal leaves a durable marker and uses a new verified browser launch. Never resubmit the capability. Node custom stores implement `HostSessionStore` and optional `SourceRenewalCoordinator`. Python custom stores implement `cynayd_first_party.session.HostStore`, which extends `RotationStore`.

## 6. Integrate Smart Lock and logout

The browser reads the same-origin session endpoint, mounts the One-hosted `/workspace-unlock` frame for `UNLOCK`, and treats its message as a request to fetch current host status. Use `mountCentralUnlock` and the One origin checked by `unlockFrameUrl`. One resolves organization and user appearance on the central frame. Permit the exact portal origin in your app’s frame-src policy and use One’s registry for the exact parent origin. Only One collects the PIN and resolves lock state. Keep held work under the same verified identity while the UI is blocked.

The React reference includes cross-tab invalidation, visibility and reconnect handling. Node serves a same-origin SSE relay. For FastAPI set `eventsEnabled={false}` in the React example and use its passive revalidation, which also runs on visibility and connectivity changes. Relay, cross-tab and frame events are advisory. One supports an explicit lock in its own authenticated browser surface. The audited first-party delegation profile has no application-side manual lock endpoint for a universal keyboard shortcut.

Call `host.logout()` from the browser for local app sign-out. The backend invalidates both host and pending launch state. Offer global sign-out at the existing One entry point. Central lock, logout, AccessOps revocation and session expiry take effect at the next live check.

## 7. Enable foreground activity

Use `observeScreenViewing` only in an active session and return true from its viewing predicate solely for approved viewing routes. It can request a bounded viewing lease after real input. Focus loss, page hide and teardown end the lease. The authority decides duration and eligibility. For authentication activity, send `reportActivity` in TypeScript or `report_business` in Python on the server after an accepted authorized business command, with a stable event ID. Silently extending deadlines through polling, autosave, retries, timers, rendering or background work breaks the central activity contract.

## 8. Configure delegated access

Configure the approved target route, method, HTTPS origin, audience and scope server-side. Call it with the live bound subject and scoped SDK transport. Enforce source commands locally. A target enforces live introspection, proof replay, exact scope and its existing resource ACL. See [operation examples and known availability](delegated-operations.md). A missing grant or target interface blocks that operation.

## 9. Retire legacy authentication after parity

Inventory every browser, backend, job, socket, provider and agent consumer of the older credential paths. Keep existing compatibility in service during qualification. Establish verified entry, direct and launcher callbacks, account and resource continuity, lock and recovery, and denial parity. Record deployment, consumer migration and rollback evidence before removing compatibility. Keep service identities and independent connector grants with their existing owners.

## 10. Deploy and verify

Use the existing deployment and an authorized test user. Exercise fresh direct entry and launcher entry, same-account recovery, account switching with held drafts, access removal, central logout, PIN lock/unlock, deadline and viewing behavior, separately approved renewal, and approved target ACL denials. Verify expected authorization failures with a second tenant and an unassigned user. Compare source, installed version, integrity, One registration revision and matching runtime. Record sanitized request IDs and deployment evidence. Run contract and standalone tests locally before authenticated acceptance.

## Troubleshooting

| Result | Action |
| --- | --- |
| `HOST_SESSION_REQUIRED` | Begin a verified launch. If persistent, confirm exact same-origin routing and secure cookies and test the callback against the approved URL. |
| `LAUNCH_STATE_INVALID` | Return to the app and start a new transaction. Check for missing transaction cookies, retry races, query rewriting or a mismatched return origin. |
| `UNLOCK` | Load the One frame and revalidate through the backend. Confirm exact frame origin, public frame registry and app CSP if the frame is blocked. |
| `RECONNECT` or `REAUTHENTICATE` | Recover through One. For a revoked or expired central session, establish a fresh session. Keep pending requests bound to the original identity and reconcile any uncertain writes. |
| `ACCESS_DENIED` | Check the live assignment, installation and access epoch. For a target request also check the exact grant, scope and target ACL. |
| `RETRY`, 429 or 503 | Respect `Retry-After` where present. Keep the operation gated. Diagnose with sanitized request IDs. A failed live check cannot authorize an operation. |
| Unexpected redirect or TLS failure | Check issuer and endpoint configuration. Fix routing and certificates before retrying. The confidential transport rejects redirects. |

## Run the standalone reference

Copy the files from the SDK’s host example into your application workspace. Install the npm candidate, Express, pg and esbuild in that workspace. Apply the schema, load the reference configuration from your application’s approved deployment settings, and build the example browser entry.

```sh
npx --no-install esbuild examples/host/reference-browser.mjs --bundle --format=esm \
  --outfile=examples/host/reference-browser.js
node examples/host/express.cjs
```

Serve the application through its existing HTTPS proxy on the registered origin. The root page exercises browser launch, live status, embedded unlock, and local logout. The protected example at `/api/me` returns the verified identity projection. For local contract qualification with a disposable database and fixture authority, run the commands in the [README](../README.md).

## Registration from a separate application server

Use the [cross-server registration workflow](registration-workflow.md) to generate
and publish a public Git request for One operator review. It includes registration
preflight, preservation of existing client permissions, and audited publication.
