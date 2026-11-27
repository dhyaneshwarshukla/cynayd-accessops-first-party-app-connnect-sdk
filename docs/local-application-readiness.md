# Local first-party integration readiness

Production decision: NO-GO. The release gate is open for local discovery and
preparation. No application migration has begun.

## Foundation and review gates

The current SDK supports verified launch, browser resume, silent status,
delegation, live introspection, PIN synchronization adapters, and qualified
product activity. One can advance the Go authentication idle timestamp for an
explicit tenant/client/installation/operation policy. The fixed source evidence
deadline still requires verified browser recovery. Automatic delegated target
replacement remains available while source evidence is valid.

The dedicated Go application_source_renewal decision is a prerequisite.
It checks a published policy and expiring assurance and does not issue source
credentials. The worktree has no authenticated renewal launch initiation, no
renewal capability lifecycle and no /api/v1/delegations/source-renewal route.

The [renewal decision](source-renewal-security-decision.md) identifies three
release gates with distinct owners:

1. Identity and Security Authority must bind immutable credential versions to
   the original verified evidence and the issuance transaction. TOTP in
   sso.credentials uses a mutable secret behind the logical totp identifier.
   Passkeys in sso.webauthn_credentials and mobile approval records in
   public."MfaApprovalDevice" have separate write paths. Include enrollment,
   deletion, replacement, recovery and administrative revocation. A version
   check in the transaction must fail closed on a missing or superseded
   version. Confirm the adopted lock order with existing SSO writers.
2. Security governance must approve a purpose-specific durable session
   assurance policy. The existing session-check evidence age and common
   verifier receipt validity are each capped at 15 minutes. Preserve the
   original verification timestamp and provenance, authentication idle and
   absolute deadlines, lock, risk and step-up rules, and device and factor
   revocation. Do not extend verifier receipt expiry or use activity as proof
   of fresh assurance.
3. The reviewed launch contract must bind the registered client, callback,
   DPoP key and backend verifier before browser authorization. Existing Redis
   exchange codes are single-use and scoped to application and purpose.
   Their redemption carries no confidential-client proof or verifier. Keep
   the legacy route intact and require a separate protocol for capability
   issuance. Independent review must cover transaction ordering, rotation,
   loss recovery and the AccessOps consistency boundary.

The local Go check consumes factor facts collected by One before the authority
transaction. A concurrent change can invalidate the snapshot. AccessOps is a
separate consistency domain as well. Keep live AccessOps checks for direct
protected operations, delegation and resource introspection. No approved
durable assurance policy or independent sign-off was available in the reviewed
workspace. Protocol activation, the new SDK candidate, and application
migration remain gated.

## Checked sources and running images

Values come from local Git and read-only Docker container metadata. A tag,
image digest or Compose source label identifies the running build separately
from source. It establishes neither an active registration nor authenticated
feature acceptance. Registry IDs, installed applications, grants and deployed
SDK package versions require operator-backed evidence.

| App | Local source | Running build and deployment source |
| --- | --- | --- |
| Grid | /opt/cynayd/apps/cynayd-sheet at e05a6d80904a99adc2caec09305dbf054a131c98 | API cynayd/sheets-api:accessops-view-disabled-20261103-r5, revision cc43f9a6c9e48cc199ed1c45917315c70fae5ea58d85d3e4d31a574433f68549. Web cynayd-sheet-web, image 7b2938013641, revision label unknown. docker-compose.prod.yml plus the live API override recorded by Docker. |
| HRMS | /opt/cynayd/apps/hr, no local Git HEAD | cynayd/hr-app:phase1-base-20261031, image 3b5e457b681b, docker-compose.yml. |
| Vault | /opt/cynayd/apps/vault, no local Git HEAD | cynayd/vault:local-authorization-20261017, image a2b9033fa079, docker-compose.prod.yml. |
| Calendar and Tasks | /opt/cynayd/apps/calender, Git metadata without a resolvable HEAD | cynayd/calendar:fc032-20261102-r1, image 8c829c7aa5c7, base production Compose plus calendar-step34 and calendar-fc032 overrides. |
| Groot | /home/ubuntu/groot, with groot-service, groot-mcp and frontend/groot-web. /home/ubuntu/kaamkaj/groot is a separate checkout. Both report bb776cedbe13e0dd2ca08475a7461c93c56d8c12. | Main services groot-service:temporary-inference-budget-bypass-20261118 and groot-mcp:stabilization-local-20261118, images 16f4ad5487d1c and 93e7be658fff. Separate Workspace 2 live candidate uses /root/.codex/worktrees/9e3a/groot/ops/workspace2-live with the same checkout HEAD, images 80cbff5fd532 and c44d0feea57e. Verify serving route before qualifying either stack. |

## Integration entry points and coverage

| App | Observed entry points and existing controls | Qualification scope after SDK freeze |
| --- | --- | --- |
| Grid | Nest API and Next web. apps/api/src/auth/auth.service.ts uses One launch and defaults to cynayd-sheets. Existing Drive delegation code is in apps/api/src/integrations/drive. Workbooks, sheets, commands and Forms import have separate entry points. Web runtime has persistence and sync queues under apps/web/src/grid/runtime. | Verify exact canonical registration and local session storage. Apply live backend checks to workbook and sheet commands, persistence, sharing, views, imports, exports and Drive operations. Preserve pending operations and version IDs. Propose spreadsheet.edit only for accepted foreground commands. |
| HRMS | Laravel routes and service middleware. app/Http/Controllers/SamlController.php and app/Services/SsoClientService.php contain SAML and attribute-token dependencies. Laravel has a configurable session driver and a Redis sidecar is running. | Confirm canonical ID, actual session driver and whether deployed flows invoke the attribute endpoints. Replace applicable calls with verified federation. Qualify employee, attendance, leave, settings and scoped administration. Propose record.edit only after record and tenant authorization. |
| Vault | Express backend, src/config/saml.ts defaults to cynayd-vault. src/controllers/auth.controller.ts and src/middleware/auth.ts form the authentication boundary. Folder, item, permission, share and audit controllers are separate. Verified exchange coverage exists in source tests. | Retain verified SAML, Vault-specific unlock, MFA, reauthentication and item ACLs. Central unlock carries no Vault assurance. Confirm local session backend and sensitive operation coverage. Leave idle activity disabled until Vault policy qualifies it. |
| Calendar and Tasks | Express routes under src/routes. src/config/sso.ts defaults to cynayd-calendar-tasks. src/middleware/auth.ts and calendar-accessops-revalidate.ts bind the local JWT and recheck application access. Events, calendars, tasks, notifications and work items use separate routes. | Validate canonical installation, supported audiences and exact scopes with the registry. Preserve sharing and resource permissions for reads and commands. No idle activity for notifications, reminders, sync or scheduled jobs. Leave activity disabled pending reviewed classes. |
| Groot | Python service and MCP, with frontend/groot-web. app/auth/sso.py redeems One codes, app/auth/deps.py resolves the local SSO cookie, app/auth/entitlements.py and guarded_execution.py provide authorization entry points. Config defaults to cynayd-groot. Calendar, mail, docs, tasks, and MCP tools have separate boundaries. | Use the reviewed shared server contract for Python. Validate each user-authorized side effect and its tenant, installation, audience and operation. Preserve conversation context and enforce authorization on resume. Exclude agent jobs, scheduling, streaming heartbeats and background AI from activity. Qualify Drive and tool grants before enabling them. |

The application identifiers above are source defaults. No new SDK integration,
qualified activity adapters or protected-operation coverage are claimed.
Deployment rollback preparation requires capturing the applicable Compose
overrides, image digests, cookie/session compatibility and the operator-approved
previous build before rollout. Exercise rollback in staging before deployment.

## Authority-mode compatibility

| Mode | Supported recovery | Authentication idle extension | Silent backend source renewal |
| --- | --- | --- | --- |
| Ordinary Go AUTHORITATIVE | Verified browser resume where launch is supported and session is eligible | Locally qualified backend path, explicit policy and eligible app contract required | Pending |
| Legacy / Go SHADOW | Existing One browser path where supported | Existing lock clock only | Pending separate qualification |
| Orbit-linked | Existing verified Orbit channel and browser flow | Outside qualified Go writer | Pending separate qualification |
| Verified SAML | Existing verified federation recovery and application controls | No qualified extension asserted for SAML application sessions | Pending separate qualification |

## Evidence and staging gates

The current One regression comparison recorded 1,105 passed, 36 skipped and
62 failures. The failed test identities match the saved baseline, with zero
new and zero resolved failures. The isolated delegation run passed 104 tests.
Go Security Authority suites passed in the default local test environment.
SDK type-checking and all 65 SDK tests passed. The existing candidate checksum
matched and a clean offline install loaded the server and browser exports. Read the
[regression inventory](unified-session-regression.md) before prioritizing
production failures. Signed-challenge validation, token issuance on denied
challenges, tenant isolation, administrative password-reset step-up and
disable-MFA device invalidation are security release blockers until their
observed failures are reproduced against the appropriate authority and
classified as fixture defects or resolved behavior. Existing fixture
classifications are insufficient to clear those gates.
The prior Go PostgreSQL fixture coalesced eight copies of a report into one
write in about 64 ms. There is no realistic cross-service p50/p95/p99 or
authenticated cross-app acceptance evidence for the requested renewal flow.

After protocol review and source qualification, run controlled 1/4/8/12/24-hour
tests and separately authenticated soak tests. Exercise exact registrations,
factor replacement, idle and absolute expiry, lock/unlock races, revoked
sessions and grants, browser sleep, response loss, ambiguous writes, Vault
step-up and Groot background sessions. Measure authenticated session status,
renewal, exchange, introspection, activity and notification transport under
multi-instance load with PostgreSQL/Redis and authority timings. Authenticate
the tested build IDs and record newly failing, resolved, skipped and unverified
tests distinctly. No application-specific or cross-application staging suites
were run for this readiness inventory.

SDK 0.6.0-rc.0 remains the local candidate at
d32c5463fd57cf030d3fa2a7124573c70af6ea88. Use the existing restricted distribution
workflow after release approval. There is no new version, tag, push or
publication in this phase.
