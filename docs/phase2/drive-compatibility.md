# Drive deployment and operation compatibility

Checked on November 25, 2026 UTC. The running Identity registry has an active Drive resource `cynayd-drive` with `drive:read` and `drive:write`. Its active introspection client is `cynayd-drive-resource`, KID `cynayd-drive-rsa-20261027-82c4a06e1d`, RSA 3072, registered through 2027-01-25 04:42:39.306 UTC. Its client scope list is `drive:read`.

**The introspection client does not need `drive:write` to verify a write token.** One authenticates the resource caller and checks the requested audience belongs to its app. It then checks the token’s scopes against the original **source** client, resource and tenant grant. The regression runs One’s actual exchange and introspection logic for Connect, Docs and Grid fixtures, with a Drive introspection client restricted to `drive:read`. Both scopes introspect as active. This is separate from Drive’s per-operation scope check and ACL. No registry change is proposed for this client.

## Deployment evidence and limits

The October 27 Drive/Docs deployed handoff records a healthy Drive API/worker image, separate mounted RSA and P-256 keys, successful authenticated introspection of a deliberately invalid token (`active:false`), PostgreSQL atomic proof replay storage, exact canonical identity mapping, and AccessOps plus local ACL enforcement in the central inter-app path. The prior release tested 16 concurrent replay claims against PostgreSQL and observed one winner. That is historical deployment evidence. Current SSH access was rejected, so current image, key mounts, replay database and route code could not be inspected directly. The current valid registered public key does not establish private key availability today.

Current public checks sent one deliberately invalid DPoP credential per **read** path, using a synthetic object ID. Drive health was 200. The paths below returned `401 DRIVE_INVALID_TOKEN` and a DPoP challenge where indicated. A shared middleware can return 401 before endpoint resolution, so these results do not independently establish routing, introspection, or ACL success. No production write was attempted.

| Operation | Candidate direct Drive route and central scope | Current coverage and acceptance |
| --- | --- | --- |
| List accessible files | `GET /api/interapp/files`, `drive:read` | 401 challenge. Confirm listing returns only files visible to the user. |
| List accessible folders | `GET /api/interapp/folders`, `drive:read` | 401 challenge. Check pagination and filtering of unauthorized and foreign-tenant folders. |
| Read file metadata | `GET /api/interapp/files/:fileId`, `drive:read` | Grid client supplies route evidence; 401 challenge. Test allowed, denied and foreign-tenant object IDs. |
| Preview | `GET /api/interapp/files/:fileId/preview`, proposed `drive:read` | 401 challenge. Confirm actual preview route, inherited scope and ACL checks before returning thumbnails, previews or cached content. |
| Download | `GET /api/interapp/files/:fileId/download`, `drive:read` | Grid client supplies route evidence; 401 challenge. Verify bytes and denial, including any redirect or signed URL. |
| Create folder | `POST /api/interapp/folders`, `drive:write` | Grid client supplies route evidence. Verify permission on the parent folder, organization binding, read-only denial, and idempotency. |
| Upload attachment | `POST /api/interapp/files/upload`, `drive:write` | Grid uses multipart and a `folderId` query value. Verify exact deployed schema, immutable destination, folder create/write ACL, attachment bounds and final persistence. |
| Update file | `PUT /api/interapp/files/:fileId/content`, `drive:write` for content | Grid client supplies content-route evidence. Verify current object write ACL and version behavior. Confirm a separate route and mapping if metadata updates are required. |
| Share existing file | Central DPoP route and scope unverified | Keep disabled for this pilot. Gateway source has a legacy permission route with `drive.share` and upstream `/shares`. The One resource registers only `drive:read` and `drive:write`. Do not treat either as approval to share. The Drive owner must verify or implement a central operation with existing share capability checks and approve its explicit scope mapping. |

The missing target-side work is a current runtime and route review plus positive and negative authenticated acceptance. Preview and sharing are specifically unconfirmed for central delegation. The existing historical implementation includes DPoP, live introspection, PostgreSQL replay protection and an ACL gate. The current evidence does not justify rewriting that layer or changing worker-token paths.

Current correlation examples for Drive operators are file listing `bef08689-7cc7-4fda-94de-7c7662cf405d`, preview path `0ec11f4e-0c7d-4f44-a973-55ce4eb7fa77`, and download path `ead7f12d-d908-49b6-829b-965e0a27dfd9`. No credentials were collected.
