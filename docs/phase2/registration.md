# Connect delegation registration approval packet

**Status: proposed, pending approval.** The production One registry shows the active Connect app `cynayd-connect` (One app ID `cmffr7in2000v10clilb52asx`) and Drive app `cynayd-drive` (One app ID `cmfcyq27n0000shwweuuq8cf6`). Four tenants have current Connect and Drive installations. No registered Connect delegation client or grant was observed. An app ID is not an installed app ID.

## Changes for review

| Record | Proposed value or approval input |
| --- | --- |
| Confidential client | [Schema-ready client config](connect-client.proposed.json). Proposed ID `cynayd-connect-backend`, app `cynayd-connect`, allowed target `cynayd-drive`, allowed scope ceiling `drive:read` and `drive:write`. Confirm ID uniqueness in the intended environment. |
| Public key | New environment-specific RSA 3072-bit key. Register only the public JWK and a unique immutable KID. Set a short, explicitly approved validity window. |
| DPoP proof key | Separate environment-specific P-256 private key held by the Connect backend. The matching public JWK travels in the proof. |
| Delegation grant | One expiring `DELEGATED` grant for the explicitly approved pilot tenant, using its exact active Connect and Drive installations. Start with only `drive:read` for read cases. Add `drive:write` only for an approved write pilot. Select a specific expiry and include the intended operations and rollback owner in the change ticket. |
| Existing access | Tenant application assignments and Drive file/folder ACLs continue to apply. No new Drive resource, duplicative Connect app, or changes to the Drive introspection client are required for the proposed pilot. |

An authorized registrar must resolve the organization and both installation IDs from the **same environment** through the existing application registry or a read-only query of `accessops.installed_apps`, matching exact canonical keys and excluding archived rows. A duplicate or ambiguous installation lookup blocks preparation. At runtime One verifies exact installations from the source launch and current authorization. Do not substitute product IDs or pick an installation by display name.

Prepare the remaining registration files after the environment owner supplies a test or pilot tenant and backend-generated public key. The objects below are templates with placeholders; they are deliberately unusable as-is.

```json
{"kind":"key","clientId":"cynayd-connect-backend","kid":"<unique-KID>","publicJwk":{"kty":"RSA","n":"<public modulus>","e":"<public exponent>"},"notBefore":"<UTC ISO-8601>","notAfter":"<UTC ISO-8601>"}
```

```json
{"kind":"grant","organizationId":"<approved organization ID>","clientId":"cynayd-connect-backend","audience":"cynayd-drive","sourceInstallationId":"<exact Connect installation ID>","targetInstallationId":"<exact Drive installation ID>","scopes":["drive:read"],"validUntil":"<UTC ISO-8601>"}
```

Use the existing One `scripts/delegation-register.ts <file> <change-reference> --check` on each file. `--check` validates schema only. It does not resolve an installation, validate a key's material or consult the live registry. The existing gated operator apply validates active app/client/resource records, public RSA material, scope intersection and both installations. It commits the change and sanitized audit record transactionally. An authorized operator applies client, key and the approved grant in that order in the target environment after review. Production requires a separately approved change with passing authenticated acceptance evidence.

Generate and retain private keys in the Connect secret store and mount them read-only to the backend. Limit read access to its service identity and maintain independent staging and production key sets. Rotate by appending a new KID and testing its assertions, switching the backend, then revoking the old KID through the existing registry. Revoking the old key can invalidate tokens issued under it, so plan for fresh exchange. Keep proof keys available only to backends that execute the requests; rotate by discarding old in-flight capabilities and exchanging fresh tokens. For containment, revoke the grant, key or client according to the affected boundary. Use the existing `revoke-grant`, `revoke-key` and `revoke-client` commands and verify the next target request denies stale tokens.

**Separate Calendar workstream.** The Day One packet permits only Drive. Calendar/Tasks registration, exact scopes, target middleware and ACL acceptance need independent approval. Calendar does not gate Drive qualification.

## Central management gap

The existing One/AccessOps registry manages tenant installations. The restricted One CLI covers delegation client upsert, public key registration, resource scopes, tenant grants, and client/key/grant revocation. Audit records include a change reference, operator reference and sanitized before/after data. No dedicated delegation management HTTP or UI surface was found in the checked One and AccessOps sources. The CLI has no standalone resource-revoke command; disabling the affected grants or source clients is an existing containment path.

Extend the existing registry UI in two steps. First add a read-only view for authorized scope, key metadata, tenant installation resolution and audit history. Then add approved operator changes that call One’s existing registration validation, transactions and audit. Separate platform ownership of client/key/resource definitions from tenant-scoped grant approval. Require explicit tenant and installation binding and an auditable change reference, plus a separate approver for grant expansion. Exclude key material beyond public metadata. Enforce revocation and rotation through One’s existing records and keep the current CLI as the recovery path. Add dedicated resource suspension through the same transaction/audit path if required. No additional authorization datastore is needed.
