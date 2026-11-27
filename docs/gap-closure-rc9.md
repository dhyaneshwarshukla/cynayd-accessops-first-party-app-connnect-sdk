# First-party SDK gap closure for 0.6.0-rc.9

## Review scope and findings

Reviewed SDK RC.8, Grid’s OneHostSessionService, OneHostSessionStore, controller and OneSessionPilot, and Groot’s one_host, one_host_store, browser integration and guarded execution handoff. Verified the source of One’s delegation-register.ts, registrationSchema, firstPartyProfile, delegation router, and the One embedded unlock route. Reviewed the Drive, Docs and Mail onboarding handoffs, including the whole-application AccessOps activation evidence, the October Drive and Docs application-server review, and the existing Grid Drive client and Calendar API evidence. The older Ed25519 product-evaluation client remains a supported compatibility path during migration.

| Classification | What was outside the common repository | RC.9 outcome |
| --- | --- | --- |
| Reusable SDK functionality | Shared TypeScript protocol calls existed. Host cookies, launch transaction ownership, callback commit and HTTP adaptation lived in Grid and Groot. | Shared host lifecycle with one-use callback, live status, sealed credential persistence, atomic replacement, optional renewal and same-origin logout. Node and Python adapters reuse the existing protocol primitives. |
| Reference adapter | Grid’s PostgreSQL and Nest wiring and Groot’s FastAPI persistence and routing were product-local. React’s embedded unlock and reconnect composition lived in consumers. | PostgreSQL host stores, shared replay adapter, Node HTTP and Express-based NestJS wiring, Next.js Fetch route, FastAPI and React references, and isolated standalone qualification fixtures. |
| Reusable SDK functionality | Shared browser primitives lacked a common embedded One modal. | Browser modal validates the frame origin and source before triggering a live recheck. One supplies PIN verification and resolves effective organization and personal appearance. |
| Documentation | Version drift and dispersed Grid, Groot and onboarding handoffs obscured the common path. | Canonical onboarding, registration and operation guides. Existing versioned contracts remain available. |
| Registration requirement | One’s operator command, key formats, profile revision and AccessOps grant conditions were outside the onboarding material. | Verified CLI and schema, public-key tooling, exact callback and origin templates, audited apply and verification steps, rotation and revocation. |
| Application-specific functionality | Grid edit receipts, Drive document/version mapping and ACLs, Groot provider execution approval and resumption, Mail draft/send deduplication, Calendar ownership and Connect recipient permissions. | Discussed where these checks plug in. Their owners still implement and qualify them. |
| External target requirement | Docs and Mail need Drive read/write and existing ACL support. Drive-to-Connect sharing and Connect-to-Calendar lack verified target contracts for One DPoP. Groot has a launch-only registration. | Added code against observed Drive routes and shared exchange for Python and Node. Documented missing target contracts and owner approval requirements without assuming scope names or inventing target routes. |
| Central platform requirement | A manual lock action exists in One’s authenticated browser surface. No first-party command binding for an app-wide universal keyboard shortcut was found. | Supported Smart Lock continues through the One-hosted surface and live status. |

## Qualification

Local contract verification covers TypeScript and Python protocol fixtures, Node, Express, NestJS and FastAPI host lifecycles on PostgreSQL, callback consumption, local logout, recovery, denial and shared proof replay. The local environment supplied Node 20 and Python 3.12. The Next example uses the same Fetch handler. Authenticated qualification against the deployed authorities remains pending.

The One development frame registry returned Grid and Groot as exact origins. Both deployed app session entry points returned HTTP 401 without a cookie. These establish availability of the public compatibility surfaces. Authenticated callback, PIN, policies, central logout, renewal and product operation parity against the deployed One and Grid were not established in this run. Keep existing compatibility paths during acceptance.

The repository contains enough common code and operator-facing material to wire an authorized launch-only host without another product checkout. Production qualification remains open. Node and Python provide delegated source and resource adapters. Production delegated operation coverage is limited by the verified target contracts and explicit grants.

Restricted registry publication requires the protected release workflow and independent operator approval. The artifacts prepared from this change are local candidates.

## Local release record

- Node contract tests and the two-target example passed. The standalone host contract passed with native Node, Express and NestJS against disposable PostgreSQL 16.
- Python wire, resource and FastAPI lifecycle tests passed on Python 3.12 with the same PostgreSQL version.
- The Next.js production build and HTTP smoke test passed for the route reference, including separate Set-Cookie headers.
- One’s actual registration CLI accepted the fixture launch-only client, generated RSA public-key record, approved public profile and disabled profile in check mode. No apply command was run.
- A Chromium fixture verified that the React lock screen hides held work, rejects unrelated frame messages and restores the same draft after authoritative revalidation.
