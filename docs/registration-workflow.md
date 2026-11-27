# Cross-server registration

Use the existing private First-Party SDK Git repository for the CYNAYD One handoff. Grant the app team access to propose requests and the One operator access to review them. Use a protected review branch and the existing One approval and execution permissions. Keep environment requests in the top-level `registrations/` directory, which is excluded from the SDK package allowlist. Keep operator inventory and receipts outside the Git handoff.

```text
registrations/<environment>/<app>/<request-id>/
  request.json
  request.sha256
```

A request contains public client and app identifiers, HTTPS destinations, a public assertion JWK, proof thumbprints, installation identifiers and any explicitly requested grants. Keep runtime secrets, private keys, credentials, logs and operator inventory out of the handoff repository. Treat tenant metadata as organization-internal. Publish only the two generated files. Use the same reviewed SDK tooling revision on each server.

## Prepare on the application server

Ask the existing One operator for discovery evidence for the application key and expected client ID. Reuse a compatible active client. Preserve its allowlist by choosing `"mode": "reuse", "client": null`. Use an existing assertion KID only when the corresponding public key and active validity are confirmed and the app backend controls the private key. To add a key, use a distinct KID. For a confirmed new launch-only client, use `"mode": "create", "client": {"audiences":[],"scopes":[]}`.

Use the [metadata template](../examples/registration/manifest-template.json). The callback URL and landing URL determine the exact approved origin. The source installation is tenant-specific. Existing delegations need no request entry unless you want the preflight to verify them. To request a missing grant, include its `organizationId`, `audience`, `targetInstallationId`, `scopes` and `validUntil`. The central resource and both installations must exist before applying a grant. A new delegated client must declare its precise allowlist; a reused client must already allow that access. Resource creation and existing permission changes use the [audited One workflow](registration.md).

```sh
SDK=/path/to/trusted-sdk
HANDOFF=/path/to/existing-private-handoff-clone
REG=registrations/development/example-app/owner-change-123
node "$SDK/tooling/registration/register.cjs" generate metadata.json assertion-public.pem proof-public.pem \
  example-kid "$KEY_NOT_BEFORE" "$KEY_NOT_AFTER" /tmp/example-app-request.json
node "$SDK/tooling/registration/register.cjs" package /tmp/example-app-request.json "$HANDOFF/$REG"

git -C "$HANDOFF" switch -c registrations/example-app/owner-change-123
git -C "$HANDOFF" add -- "$REG/request.json" "$REG/request.sha256"
git -C "$HANDOFF" commit -m "Request example-app first-party registration"
git -C "$HANDOFF" push -u origin HEAD
```

Open the normal private review. Record the full commit SHA, repository-relative request path, request SHA-256 and existing One change reference in the review. The checksum next to the request is convenient for transport checks. The operator must take the expected digest from the reviewed change record and must use the pinned commit rather than take both values from an unreviewed branch.

## Discover and review on the One server

Fetch the reviewed commit in the existing private repository. The CLI reads the two servers' shared artifact by Git object ID and the exact path, independent of the checkout. Run trusted SDK code and the current One operator CLI from their own checkouts. The handoff supplies data only.

Prepare a fresh operator-local inventory based on authorized live One and AccessOps reads. One's registration CLI checks and applies documents; the version documented here has no discovery command. Use the environment owner's existing registry evidence process. The [inventory example](../examples/registration/inventory-template.json) describes the SDK's input format, which is an operator evidence projection. It is not a new central API or stored registry. An empty list must mean the operator verified absence. Set `contract: "one-registration-v1"` after confirming the selected One CLI understands the current client, key, first-party profile and requested grant documents. Refresh evidence within five minutes for each review, apply or preflight invocation.

| Member | Evidence |
| --- | --- |
| `clients` | Include all client records for the app plus any record with the requested client ID, including inactive records. Fields are `clientId, appSlug, active, audiences, scopes, keys, profile`. Each key has public `kid, publicJwk, notBefore, notAfter, active`. A missing profile is `null`. Map existing profiles to One's approved or disabled public profile shape. |
| `installations` | Exact active or inactive `organizationId, installationId, appSlug, active` records for the app and requested targets. |
| `resources` | Existing target records use `audience, appSlug, scopes, active`. |
| `grants` | Include existing grants for the requested client and requested audiences, including inactive grants. Fields are `clientId, organizationId, audience, sourceInstallationId, targetInstallationId, scopes, validUntil, active`. |
| `frameOrigins` | Registry-enabled One's live `/api/v1/delegations/frame-origins` list. |
| `observedAt` | Timestamp when observations were collected. |

```sh
git -C "$HANDOFF" fetch origin
TOOL="$SDK/tooling/registration/register.cjs"
REQUEST="$REG/request.json"
node "$TOOL" preflight "$HANDOFF" "$COMMIT" "$REQUEST" "$REVIEWED_REQUEST_SHA256" "$INVENTORY"
node "$TOOL" review "$HANDOFF" "$COMMIT" "$REQUEST" "$REVIEWED_REQUEST_SHA256" \
  "$INVENTORY" "$ONE_STANDALONE_BACKEND" "$CHANGE_ID"
```

Preflight exits nonzero for any readiness finding and reports a specific remedy. Review skips matching records and invokes One `--check` for every proposed write. It fails on conflicts, incompatible evidence, missing prerequisites and existing permission changes. Approve the exact emitted `planSha256` through the existing change. The plan digest binds the commit, request path, request digest, change reference and ordered operations.

## Apply and verify on the One server

Run as the authorized One operator after approval. Use the existing operator change window to serialize writes affecting the client, app and grants. Refresh inventory in that window immediately before applying. The tool recomputes the approved plan and reruns One schema checks. It sets the operator write flag on individual apply processes only. One retains responsibility for authenticating the operator execution environment, registry validation and audit events.

```sh
node "$TOOL" apply "$HANDOFF" "$COMMIT" "$REQUEST" "$REVIEWED_REQUEST_SHA256" \
  "$FRESH_INVENTORY" "$ONE_STANDALONE_BACKEND" "$CHANGE_ID" "$APPROVED_PLAN_SHA256" "$NEW_RECEIPT_JSONL"
node "$TOOL" preflight "$HANDOFF" "$COMMIT" "$REQUEST" "$REVIEWED_REQUEST_SHA256" "$POST_APPLY_INVENTORY"
node "$SDK/examples/registration/check-origin.cjs" "$ONE_ORIGIN" "$APP_ORIGIN"
```

Save the receipt with the existing approval and correlate it with One's audit events. Each CLI invocation is individually audited. An interrupted run may have partially applied. Refresh the registry evidence and review the remainder under the existing change process. A matching client, key, profile or grant results in no write. Existing grants with additional scopes or a later expiry stay as recorded. Conflicting records, disabled profiles and key or grant replacement require separate operator review. The workflow relies on the existing operator change window because review and individual CLI writes do not form a single transaction.

A successful preflight records registration readiness at the time of the observation. Complete authenticated direct and launched access, central status and each approved delegated operation before release.
