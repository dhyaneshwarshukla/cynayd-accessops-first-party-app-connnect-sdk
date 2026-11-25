# Application onboarding and integration

## Quick start

Use the private package artifact pinned to version 0.2.0. For a checkout, run `npm ci && npm run example`. The example executes code redemption, source validation, token exchange, DPoP, live mock introspection and an ACL check for Drive and Calendar. The fixture registration, keys and paths are local test inputs.

1. Inventory source and target operations, their canonical application keys and installed app IDs. Ask the registration owners to verify active client IDs, RSA public KIDs, resource audiences, scopes, target backends and tenant grants against the One registry. Record the source/target app ID and tenant installation ID separately. Continue once the needed access is approved and observable.
2. Configure One issuer, validation origin, token, introspection and launch evaluation endpoints and an allowlisted JWKS URI. Keep separate private keys for client assertions and P-256 proofs in the backend secret store. Register only the assertion public key with One. A target uses its own confidential client and proof key for introspection.
3. Wire the registered callback and protected session store on the source. Wire delegated middleware to the approved target operations, leaving existing local ACLs in place. Test as an existing authorized user and as a denied or revoked user before any traffic rollout.

## Source application guide

```ts
import {
  DelegationClient, DelegationSigner, OneApplicationSession, oneSigningKeys,
} from '@cynayd/accessops-first-party-app-connnect-sdk';

const delegation = new DelegationClient({
  signer: new DelegationSigner({
    clientId: config.clientId,
    credentialKid: config.clientKid,
    clientPrivateKey: keys.assertion,
    proofPrivateKey: keys.proof,
  }),
  tokenEndpoint: config.tokenEndpoint,
  introspectionEndpoint: config.introspectionEndpoint,
  launchEvaluationEndpoint: config.launchEvaluationEndpoint,
});
const login = new OneApplicationSession({
  appSlug: config.sourceAppKey,
  issuer: config.issuer,
  identityOrigin: config.identityOrigin,
  signingKey: oneSigningKeys(config.jwksUri),
  delegation,
});
```

Use `login.launchUrl` to re-enter One on user action, through your portal's configured entry and callback. Bind the return to a current authenticated local session or a trusted, server-verified launch transaction. Populate expected canonical person/tenant/installation from that session or transaction. Independently verify callback state and the callback's intended user and tenant. A raw browser-supplied identity is unsuitable. For code callbacks, `completeCodeLaunch(inputs, states, store, requestId)` consumes a one-time application state and conditionally stores verified evidence for the current session revision. A registered direct-token callback can call `validate` with the verified return and commit using the same revision check.

Call `delegation.call(binding, registeredOperation, publicUrl, init, requestId)` after loading the current authenticated session's binding and validating the local action. Register the operation in the backend with exact audience, scopes, HTTPS origin, HTTP method and a URL predicate that checks path and relevant query parameters. Construct the request body and allowlist any forwarded headers. Maintain operation capability checks and CSRF protection. Return only the operation's response data and sanitized errors. Dependent backends invoke Connect's authenticated business operation instead of fetching its delegation token.

Use `assertActive` for explicitly re-evaluating the source application through One when appropriate. The regular exchange already checks source and target authorization. The previous Ed25519 AccessOps API remains available for product-authorization callers.

### Host storage and transport

- `CredentialStore` reads protected state by the host session ID, replaces it only at the expected revision and removes it on logout or invalidation. The application owns encrypted storage, credential rotation, retention, and lookup by the current authenticated session. In multi-instance environments, coordinate changes through the same shared store and invalidate local state on logout.
- `LaunchStateStore.consume` atomically consumes expiring state bound to the current browser transaction. Verify the state before processing returned credentials. The SDK accepts an injected `fetch` and timeout for service integration and tests. An injected transport must enforce TLS, reject redirects and respect cancellation.
- `oneSigningKeys` resolves only from the pinned One HTTPS JWKS. High-traffic apps may supply an equivalent trusted resolver with bounded **key** caching and rotation support. Authorization and introspection results cannot be positively cached.
- Send protected service requests with the same request ID. Batched concurrent token requests may share a single upstream exchange ID. Use local operation IDs for separate target calls. Never log headers, tokens, proof contents or raw upstream responses.

## Target resource guide

Instantiate `DelegatedResource` with its exact registered audience, canonical public origin, One issuer and trusted key resolver. Pass a `DelegationClient` configured with the target's introspection client, and implement `ReplayStore.consume` as a shared atomic insert-if-absent with expiry in Unix seconds. Failed replay-store operations deny the request.

For every delegated route, pass the actual public method/path, credentials and the required operation scope from the server route table. The public URL must be derived from trusted routing configuration. Supply the local operation context to the ACL adapter. Resolve the verified tenant, canonical person and exact target installation into that context and enforce the current ACL. An authenticated user with an application permit still requires access to the specific folder, file, calendar, event, document or grid.

Run `authErrorResponse` on `FirstPartyAuthError` to preserve 401 challenges, 403 denials, 429 retry guidance, 503 availability signals and request IDs. Keep business validations and database write semantics in the target. Test introspection denial and unavailability on the same code path that performs the actual operation.
