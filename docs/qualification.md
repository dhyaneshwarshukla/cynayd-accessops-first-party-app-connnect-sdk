# Qualification and release decision

## Completed locally

| Evidence | Result |
| --- | --- |
| SDK TypeScript build and typecheck | Passed. |
| SDK compatibility and delegation tests | 49 passed. Includes original product authorization tests, verified source session and callback state, same-session Drive and Calendar operations, 401/403/429/503, audience and scope failures, proof replay, cross-user and cross-tenant binding, installation mismatch, expired tokens, concurrent exchanges, resource ACL denial and revocation after token issuance. |
| Standalone fixture example | Drive HTTP 201 and Calendar HTTP 201 from the same verified session. |
| One isolated Postgres delegation regression | 94 passed across nine suites, including migrations, registry, HTTP, proof and authorization paths. |
| One authoritative SAML regression | Seven passed. Includes the attribute-only denial and verified application continuation. |
| Vault callback and denial regressions | Ten passed. |
| Production dependency audit | No known runtime dependency vulnerabilities reported by `npm audit --omit=dev` at qualification time. |

Representative commands from their respective repositories

```sh
npm run typecheck
npm test
npm run example
npm run test:delegation
./node_modules/.bin/jest --runInBand --runTestsByPath src/routes/__tests__/saml-from-attributes-auth.test.ts
npm test -- --runInBand --runTestsByPath src/__tests__/auth-controller-exchange-http.test.ts src/__tests__/auth-controller-denial.test.ts
```

SDK mock services use synthetic keys, registered operations, authority decisions and an in-memory replay store. These runs verify SDK behavior and existing One regressions. The mock results do not establish the state of application routes or the availability of keys and grants in the affected tenant.

## Required authenticated acceptance

- Run the same source session through Drive read, folder creation and upload, and Calendar read and event creation. Confirm Connect retains the key and sends the target request itself, including for the Chat caller.
- Verify wrong app assignment, inactive resources and absent grant outcomes separately from wrong object ACLs. Confirm exact canonical installation IDs for the user’s tenant at both the source and target.
- Exercise source and target expiry, One reconnect with a live session, logout and revocation after issuance, key rotation, and proof replay across resource instances. Verify AccessOps and resource stores fail closed and report 503 or 429 as applicable.
- Confirm that the target's actual business route requires live introspection and its existing ACL using negative cases. Keep sanitized request traces.
- Approve a limited rollout and monitor by operation and status. Reconcile ambiguous writes and verify the disable switch.

**Production decision: hold.** The package and handoff are ready for integration in development. Connect has no registered client or delegation grants in the observed registry. Calendar has no registered target and its verifier is unproven. Drive has an audience and introspection client record, but authenticated route, proof and ACL acceptance is pending. Production was checked read-only.
