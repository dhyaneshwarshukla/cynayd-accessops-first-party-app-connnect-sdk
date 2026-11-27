# One and AccessOps registration

One owns the confidential client, trusted callback and landing, public keys, target audiences and delegated grants. AccessOps owns installed applications and launch authorization. The registration uses the same global application key on both sides. The source and target installation IDs for a grant come from AccessOps under the same exact tenant. Use the existing tenant administration process for application assignment, access policy and approved launch permissions. A valid registry record never assigns a user access.

## Public registration documents

One accepts one strict JSON operation per invocation. Identifiers have 1–160 characters from letters, numbers, underscore, period, colon and hyphen. Scope names start with a lowercase letter, are 2–128 characters long, and otherwise use lowercase letters, numbers and the punctuation allowed for identifiers. Use exact registered names. Lists allow at most 32 entries. Scope lists must have unique values.

| Operation | Fields following `kind` |
| --- | --- |
| `client` | `clientId`, `appSlug`, `audiences`, `scopes`. Both arrays are empty for launch-only or both populated for delegated use. |
| `key` | `clientId`, `kid`, `publicJwk` with exactly `kty: "RSA"`, `n`, and `e`, and `notBefore`, `notAfter` with timezone offsets. One validates RSA strength and the ordering and validity of the window during apply. |
| `first-party-client` | `clientId`, `profile`. For `state: "approved"`, include `callback`, `landing`, and 1–8 unique 43-character base64url `proofThumbprints`. For `state: "disabled"`, include only the state. |
| `resource` | `audience`, `appSlug`, nonempty `scopes`. The target owner supplies its existing API, verifier and scope mapping. |
| `grant` | `organizationId`, `clientId`, `audience`, `sourceInstallationId`, `targetInstallationId`, nonempty `scopes`, future `validUntil` with timezone offset. One verifies current registry scope membership and both installation bindings on apply. |
| `revoke-client` | `clientId`. |
| `revoke-key` | `clientId`, `kid`. |
| `revoke-grant` | `organizationId`, `clientId`, `audience`. |

Callback and landing must use exact canonical HTTPS URLs with no userinfo, query or fragment and the same browser origin. Include the trailing slash for a root landing. Use the callback served by your actual HTTP adapter and the browser-visible origin seen after proxying. An approved profile requires an active global CYNAYD product or platform system app. Coordinate a single approved active client per application. One derives the unlock frame origin from that profile. Whole-origin trust and a root-scoped cookie require that the browser origin is appropriate for every application sharing it.

Copy the [client template](../examples/registration/client.json) and [profile template](../examples/registration/profile.json) and fill in operator-approved public identifiers. Generate separate RSA 2048+ and P-256 keys in the application’s approved secret system. Use a new KID for the assertion key. Export only the public SPKI PEMs to registration tooling.

```sh
node examples/registration/public-key.cjs proof proof-public.pem
node examples/registration/public-key.cjs key assertion-public.pem \
  example-app-backend example-kid '<ISO-NOT-BEFORE>' '<ISO-NOT-AFTER>' > key.json
```

Load the private keys from secret mounts on the app backend. Place the emitted proof thumbprint in the profile. The SDK signer requires the corresponding private key at runtime. Keep the storage seal key separate from both signing keys.

## Validate and publish through One

Send the filled public operation documents and approved change ID to the One operator. The following commands run **in One’s standalone backend operator environment**, using its actual `scripts/delegation-register.ts` implementation. The application repository needs the SDK and approved registration details. Registry publication only needs to be performed by the operator.

```sh
./node_modules/.bin/ts-node --files scripts/delegation-register.ts PUBLIC_CONFIG.json CHANGE_ID --check
ONE_DELEGATION_ALLOW_OPERATOR_CHANGES=true \
  ./node_modules/.bin/ts-node --files scripts/delegation-register.ts PUBLIC_CONFIG.json CHANGE_ID --apply
```

Apply in dependency order. Register the client, append its key, attach the first-party profile, then apply any separately approved resource and tenant grant. The target resource must exist before its grant. The operator needs a change ID of at least eight characters and an authenticated, authorized execution context. Keep writes disabled in the normal One service. Apply validates the live records and commits the mutation with an audit event. A successful check reports `schemaValid: true, applied: false` and has no provisioned-state meaning.

Verify the recorded apply receipt and corresponding sanitized registration audit entries with the operator. The CLI supports check and apply. Obtain active registrations, public key validity windows, profile revision and grant state through operator evidence. `GET /api/v1/delegations/frame-origins` on the registry-enabled One deployment verifies the exact public framing origin. It does not attest to the callback, proof binding, installation or grant. Verify these using authorized direct and launcher entry, protected status, targeted denial and an authenticated call to each approved resource operation.

Rotate an assertion key by appending a new KID with a validity overlap, switching the host and verifying operation, then revoking the old KID. Rotate a proof key by publishing both thumbprints in the approved profile, switching and verifying the host, then removing the old thumbprint. Profile revisions can invalidate renewal capabilities. Plan verified recovery and preserve user, tenant and installation continuity. Disable a profile to withdraw first-party trust or use the appropriate revoke operation to withdraw the client, key or grant. Re-run live denial checks after the change. See the [disabled profile template](../examples/registration/disabled.json).

Use the [resource template](../examples/registration/resource.json) and [grant template](../examples/registration/grant.json) when outbound access is approved. Replace every sample value with operator-supplied identifiers and an explicit approved scope and expiry. To check just the public frame origin, run the following command.

```sh
node examples/registration/check-origin.cjs https://one.example.test https://app.example.test
```

For applications hosted separately from One, use the [Git handoff and operator
workflow](registration-workflow.md) to package, reconcile, review and apply
public requests.
