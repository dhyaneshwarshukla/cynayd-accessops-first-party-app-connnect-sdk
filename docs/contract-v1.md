# CYNAYD first-party authentication contract v1

SDK compatibility starts at `@cynayd/accessops-first-party-app-connnect-sdk@0.2.0`. Configure the trusted issuer and endpoint URLs server-side. The One production discovery endpoint is [delegation metadata](https://auth.one.cynayd.com/api/v1/delegations/metadata). Deployments must pin the expected HTTPS origins rather than using metadata or key URLs from tokens or browser input. One honors `X-Request-Id` UUIDs on delegation endpoints.

## Establish the source session

| Endpoint | Request | Success |
| --- | --- | --- |
| `GET /api/sso/launch/:appSlug` | One-authenticated browser with portal access. The slug is the installed source application's registered key. | Registered app redirect carrying a One launch credential. |
| `POST /api/sso/exchange-code` | One-authenticated portal request with JSON `{ "appSlug": "<source>" }`. | `{success:true, code, expiresIn, ssoToken, launchUrl, app}`. Use the registered browser return and one-time code when available. |
| `POST /api/sso/redeem-code` | JSON `{ "code": "<single-use code>", "appSlug": "<source>" }`. | `{success:true, ssoToken, user, app}`. The app separately validates the credential and matches the intended local session. |
| `POST /api/sso/validate` | JSON `{ "token": "<source credential>", "appSlug": "<source>", "includeDelegationSubject": true }`. | `valid:true`, `apiToken`, `delegationSubjectToken`, `sessionInfo` and ordinary validation metadata. |

A code is short-lived and purpose-bound. Browser-return state binding belongs to the registered app/portal integration. One's redemption request carries only code and app slug. The SDK requires an application-owned, atomically consumed state for its code callback; it does not assume One currently echoes arbitrary state. Only accept a returned token via a verified registered return flow, and match the signed subject with the expected canonical person, tenant and installation. A browser session without a verified source binding must obtain a new One launch.

The validation endpoint returns the following relevant shape. Values represented as strings in angle brackets are placeholders.

```json
{
  "valid": true,
  "apiToken": "<server-held One API credential>",
  "delegationSubjectToken": "<signed source credential>",
  "sessionInfo": {
    "expiresAt": "<input credential's ISO-8601 expiry>",
    "tokenType": "Bearer",
    "apiTokenExpiresAt": "<returned credential expiry>",
    "delegationSourceSessionExpiresAt": "<fixed launch-binding deadline>",
    "delegationCredentialExpiresAt": "<subject and returned API credential deadline>",
    "delegationRenewalMode": "INTERACTIVE_RECONNECT"
  }
}
```

Subject verification requires RS256, `typ=at+jwt`, exact issuer and scalar source audience, `type=one_delegation_subject`, matching `sub` and `id`, `organizationId`, `appSlug`, `installedAppId`, `launchAccessEpoch`, `launchJti` and signed `sessionBinding`. The session binding contains the One reference, session ID, original issue time and absolute expiry. These values are derived from One-held evidence.

## Registered operations

| Endpoint | Strict form fields beyond confidential client authentication | Response |
| --- | --- | --- |
| `POST /api/v1/delegations/token` | `grant_type`, `subject_token_type`, `subject_token`, `audience`, `scope`, optional `requested_token_type`. | `{access_token, token_type:"DPoP", expires_in, issued_token_type, scope}`. `expires_in` is an integer from 1 to 300 seconds. |
| `POST /api/v1/delegations/introspect` | `token`, `audience`. Use the target's own registered confidential client. | `{active:false}` or `{active:true,...validatedClaims}`. |
| `POST /api/v1/delegations/launch-evaluate` | `subject_token`, `subject_token_type`. Use the source app's registered client. | `{decision:"ALLOW",availability:"AVAILABLE",applicationKey,organizationId,userId,installedAppId,launchAccessEpoch}`. |

Use `application/x-www-form-urlencoded` and `DPoP` for each registered operation. The common form fields are `client_id`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion`. Use `urn:ietf:params:oauth:grant-type:token-exchange` for `grant_type` and `urn:ietf:params:oauth:token-type:access_token` for the token type fields. Scope is a space-delimited set of registered identifiers. The request schema forbids extra fields, including alternate actor, tenant and refresh credentials.

- **Client assertion.** RS256 with `kid` for the active registered RSA public key, `iss=sub=client_id`, exact endpoint `aud`, NumericDate `iat` and `exp`, unique `jti` and `cnf.jkt` matching the proof-key thumbprint. The SDK uses 30 seconds within One's 60-second maximum assertion window.
- **DPoP proof.** ES256 with a P-256 public JWK and `typ=dpop+jwt`. Claims are `htm`, `htu` without query or fragment, `iat` within 30 seconds, and fresh `jti`. Resource requests add `ath`, the SHA-256 base64url access-token hash, and send `Authorization: DPoP <access_token>`. Token, launch evaluation and introspection proofs omit `ath`.
- **Target token.** Validate One RS256 signature, `typ=at+jwt`, `type=one_delegated_access`, `mode=DELEGATED`, exact `aud`, `sub`, `organization_id`, `client_id`, `azp`, `act.sub`, `scope`, source/target installation IDs and epochs, grant/client/resource revisions, `cnf.jkt`, `jti`, and time claims. The canonical verifier checks the credential and proof, then live introspection revalidates the current server-side authority. The resource applies its own tenant and object ACL after binding the verified identity.
- **IDs and registration.** One's application record ID, canonical application key, tenant installation ID, confidential client ID and resource audience serve different purposes. The current Connect and Drive values are documented in the [compatibility report](connect-handoff.md). Each operation scope must exist on the client, resource and live tenant grant. The SDK takes these from trusted server configuration and confines credentials to that operation’s approved route.

## Lifecycle and recovery

The target token expires after the minimum of five minutes, subject expiry, fixed launch-binding expiry and grant expiry. The SDK uses a conservative local deadline. It shares concurrent in-flight exchanges only within the same client/session/subject/audience/scope and generates a fresh target proof per request. It retains no completed target token cache. Logout invalidates the local session credential, and One revocation must be checked live on every target operation. The target must fail closed when introspection, shared replay protection or resource authorization is unavailable.

Repeat exchange while the source binding remains valid. Renew expired source evidence by re-entering the registered One browser launch. A live, unlocked One session can often complete this without another credential prompt. The SDK never receives portal refresh credentials and never slides the fixed launch deadline. Keep editor drafts and request intent across a reconnect. Recheck ambiguous write outcomes before retry.

## Error behavior

`FirstPartyAuthError` exposes `status`, `code`, `requestId`, `nextAction`, optional `upstreamError` and optional `retryAfter`. `authErrorResponse` supplies a sanitized response body and matching headers. `DelegationClient.call` throws SDK errors for exchange or transport failures and returns the target’s HTTP response for application-specific handling.

| Condition | Wire or app result | Handling |
| --- | --- | --- |
| Missing verified federation evidence | Identity `403 VERIFIED_FEDERATION_EVIDENCE_REQUIRED` | `REAUTHENTICATE`. Keep reported status and code. |
| Source expired, stale epoch or missing launch binding | One may return `401`, or the source validation wrapper returns `401 SOURCE_SESSION_EXPIRED` | `REAUTHENTICATE`. Inspect `invalid_grant` by stage. It can also indicate binding or grant state problems. |
| AccessOps application denial | Delegation `403 access_denied` or Identity `403 ACCESS_DENIED` | `ACCESS_DENIED`. Preserve distinction from registration rejection. |
| Missing client/resource authorization or incorrect requested scope | One may return `400 invalid_target`, `400 invalid_scope`, `401 invalid_client` or `403 unauthorized_client` | Inspect registration, scope and key configuration. Preserve the status. |
| Bad proof, audience, expiry or revoked token at target | `401 invalid_token` or `401 invalid_dpop_proof` | Include DPoP challenge. Investigate proof/configuration or restart authentication where applicable. |
| Missing scope or local resource ACL denial | `403 insufficient_scope` or `403 RESOURCE_ACCESS_DENIED` | Keep resource denial separate from AccessOps app assignment. |
| Rate limiting | `429`, code and `Retry-After` when supplied | `RETRY` after the server limit. |
| Authority, storage, replay or transport unavailable | `503` | `RETRY` with bounded backoff. Keep the source stage and request ID. |

Keep credentials and proofs out of application logs, URLs controlled by the application, browser responses and incident captures. If an existing registered launch redirect carries a One credential in the URL, immediately consume it, remove it from the browser URL, and prevent referrer and access log capture on that route.
