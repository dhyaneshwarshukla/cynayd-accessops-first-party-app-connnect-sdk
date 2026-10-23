# CYNAYD AccessOps First-Party App Connection SDK

Private, server-side TypeScript package for checking whole-application access against the AccessOps launch authority.

This package contains the current `checkApplicationAccess` helper and its focused helper tests. It does not register an application with AccessOps, enable a capability profile, implement SSO, create a session, protect routes automatically, grant access, or replace product identity validation. A host application still needs a reviewed capability registration and server-side enforcement at every authenticated HTTP, socket/realtime, and user-scoped job boundary.

## Compatibility and source provenance

- Requires Node.js 18.17 or later for built-in `fetch`, `AbortController`, and Node crypto APIs.
- Runtime dependencies: none beyond Node.js built-ins and global `fetch`.
- Development dependencies: TypeScript, Jest, ts-jest, and Node/Jest type definitions.
- The Calendar, Vault, and Forms helper files in the source workspace have the same SHA-256 digest. Release 0.1.0 preserved their implementation. Release 0.1.1 corrects it for the EdDSA product endpoint described below. Their source checkouts do not provide a tracked commit for the helper: Calendar and Vault have no Git metadata, and Forms' helper is untracked. See [SOURCE-MANIFEST.json](SOURCE-MANIFEST.json) for paths, hashes, and the Forms checkout HEAD. This snapshot does not claim an upstream commit that could not be verified.

## Install from a private GitHub repository

Once this local repository has been reviewed, committed, and pushed to the approved private organization, a consuming app can use a pinned tag:

```json
{
  "dependencies": {
    "@cynayd/accessops-first-party-app-connnect-sdk": "git+ssh://git@github.com/<CYNAYD_ORG>/cynayd-accessops-first-party-app-connnect-sdk.git#<RELEASE_TAG>"
  }
}
```

Use the approved GitHub organization and an immutable release tag. Do not commit GitHub tokens or embed them in dependency URLs. Private-repository access should use the consuming build system's SSH deploy key or approved GitHub App credentials.

## Integration

The host must first validate its SSO/session credential. Call the helper on the server only; never let a browser choose the trusted person, organization, app key, or installation ID.

At trusted session creation, run an initial check and put the result into a signed, server-validated session or token:

```ts
import {
  checkApplicationAccess,
  type ApplicationSession,
} from '@cynayd/accessops-first-party-app-connnect-sdk';

const access = await checkApplicationAccess(
  'cynayd-connect',
  {
    personId: validatedSso.personId,
    organizationId: validatedSso.organizationId,
    installedAppId: validatedSso.installedAppId,
  },
  { initial: true },
);

// Store these values only in a signed server session/token.
const authorizedSession: ApplicationSession = {
  personId: validatedSso.personId,
  organizationId: validatedSso.organizationId,
  installedAppId: access.installedAppId,
  launchAccessEpoch: access.launchAccessEpoch,
};
```

Before each authenticated operation, pass the identity and epoch from that already-validated signed session. Do not use `{ initial: true }` on ordinary requests:

```ts
await checkApplicationAccess('cynayd-connect', authorizedSession);
```

Map `ApplicationAccessError.status` to the host response: 403 is a denial; 503 means the authoritative check was unavailable and must not be treated as allow. The helper does not cache positive decisions. Apply equivalent enforcement to WebSocket/realtime handshakes and user-scoped background operations. Public/guest endpoints must remain separately scoped and must not become an alternate authenticated path.

The function `applicationAuthorizationEnabled()` exactly reflects `ACCESSOPS_APPLICATION_AUTHORIZATION_ENABLED === 'true'`. It is only a host integration flag, not an AccessOps grant. Production route guards must fail closed when authorization is not enabled; do not deploy an authenticated route with a local-role fallback.

### Identity requirements

Use the validated CYNAYD `personId` and `organizationId`, exact AccessOps `installedAppId`, and exact canonical `applicationKey`. The evaluator target is whole-app `ACCESS` with no resource ID. Never derive these identifiers from email, display name, slug, or an app-local account ID. If SSO omits the installation ID, use the explicit organization mapping below and reject any mismatch.

The helper calls `POST /api/v1/accessops/launch/product-evaluate` with a scoped service identity. It accepts only an exact matching `ALLOW` response with `availability: AVAILABLE`, `launchSource: ACCESSOPS`, effective access, launch readiness, and a valid epoch. `DENY` is 403; malformed, mismatched, unavailable, or transport results fail closed as 503. An epoch mismatch denies the session and requires reauthentication.

## Environment variables

Set values through the host's secret/configuration manager. This repository does not include secret values.

| Variable | Required | Purpose |
|---|---|---|
| `ACCESSOPS_BASE_URL` or `ACCESSOPS_URL` | Yes, one | Server-side AccessOps base URL. `ACCESSOPS_BASE_URL` takes precedence. |
| `ACCESSOPS_SERVICE_TOKEN` | Unsupported | Legacy static tokens are not used by 0.1.1. |
| `SERVICE_AUTH_PRIVATE_KEY_PEM` | Yes | PEM private key used to sign a short-lived EdDSA service token. |
| `SERVICE_AUTH_SECRET` | Unsupported | Legacy HMAC credentials are not used by 0.1.1. |
| `SERVICE_AUTH_KID` | Yes | Explicit registered key identifier. |
| `GATEWAY_ACTOR_TRUST_SECRET` | Unused | Product evaluation authenticates only the scoped EdDSA credential. |
| `ACCESSOPS_APPLICATION_INSTALLATIONS` | Yes | Exact organization-to-installation allowlist, including sessions that already claim an installation. |
| `ACCESSOPS_APPLICATION_AUTHORIZATION_ENABLED` | Host wiring | Enables the host's feature gate only when its value is exactly `true`; production guards must fail closed otherwise. |

The helper requires `SERVICE_AUTH_PRIVATE_KEY_PEM` and `SERVICE_AUTH_KID`. Never log token/key values or return them in errors. `ACCESSOPS_APPLICATION_INSTALLATIONS` is identity configuration, not a secret substitute or an app-key registry.

## Development and checks

```sh
npm install
npm run typecheck
npm test
npm run build
```

The focused suite is based on Vault's existing helper tests and exercises exact target binding, service scope, epoch validation, installation resolution, per-request rechecks, denial, malformed proofs, and transport failure. Calendar's application middleware tests remain in Calendar because they import its route middleware and cover host-specific behavior; those tests do not certify another product's route coverage.

## Security and release checklist

- Confirm the app's canonical key and installation IDs with the AccessOps owner; this SDK alone does not enable `cynayd-connect` or any other app.
- Confirm AccessOps capability registration and application authority are certified for the exact app. Do not add `APP_ACCESS` or alter a capability registration as an SDK installation step.
- Verify SSO claims before the first call and verify the signed session before every later call.
- Deny on 403; fail closed on 503, timeout, bad response, or missing credentials.
- Test every authenticated HTTP, realtime/socket, and user-scoped background path, plus separate guest behavior.
- Review dependency lockfile, pinned Git tag, secrets handling, and production rollout before release.

## Corrected product-evaluate release 0.1.1

Use `checkApplicationAccess(canonicalKey, verifiedScope, {initial: true})` only after server identity validation. Store the returned installation and epoch in the signed session; omit `initial` for every subsequent request, person job, socket handshake and protected message. Resource ACLs still apply. The exported enabled flag is only an application rollout switch; the check itself never bypasses authority.

Required server configuration: `ACCESSOPS_BASE_URL` is an HTTPS origin; `ACCESSOPS_APPLICATION_INSTALLATIONS` is an exact organization-to-installation JSON object; `SERVICE_AUTH_PRIVATE_KEY_PEM` is the protected Ed25519 key loaded by the host secret mechanism; `SERVICE_AUTH_KID` is its registered KID. Never expose these to browser code. `ACCESSOPS_APPLICATION_AUTHORIZATION_ENABLED=true` is set only after integration and registration on the approved test deployment. Keep SSO configuration separate.

The only credential is `Authorization: Bearer <EdDSA JWT>`. The existing verifier convention fixes `serviceId` to canonical application key, audience to `accessops-service`, scope to the single `accessops.launch.evaluate`, and binds organizationId/personId/installationId/applicationKey. Header is alg EdDSA, typ JWT, registered kid. Claims use `issuedAt`/`expiresAt` (seconds), plus alg/kid; the helper issues 30 seconds, the server accepts at most 60 seconds and at most 5 seconds future issuance. Do not replace these with standard JWT claim names without changing both sides. No HMAC/static-token fallback or privileged actor headers are sent. Redirects are rejected. The timeout is 3 seconds.

Every decision is fetched anew: no positive cache, no time-based decision reuse. `ALLOW` must have AVAILABLE, ACCESSOPS source, effectiveAccess and launchReady true, exact authorityTarget organization/person/installation/application/ACCESS, matching installedAppId and positive integer launchAccessEpoch. A session epoch mismatch requires reauthentication. DENY maps to 403, transport/non-2xx/malformed/incomplete responses to 503. There is no decision-issued-at claim in the current response contract: freshness is established by a new request and session epoch comparison, rather than an invented decision TTL. Revoke applies on the next protected evaluation. Persistent sockets must implement repeated checks and close/reject on failure; the helper does not schedule them. System ingestion without a person needs an explicit separate policy and is not authorized by an employee ALLOW.

Version plus the release tarball SHA-256 in `ACCESSOPS_THREE_APPS_HANDOFF.md` pins the corrected distribution. This package is prepared locally; it does not imply organizational release approval, registration or deployment.
