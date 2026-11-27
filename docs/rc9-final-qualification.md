# RC.9 qualification and publication status

## Existing deployment checks — 2026-11-27 UTC

The existing One API and Web use `first-party-registry-dev`. Grid API and Web and Go Security Authority use `grid-smartlock-rc8`. The installed RC.9 browser bundle, run in a fresh Chromium session on the existing Grid origin, classified Grid’s missing-cookie response as unbound and reached the existing One sign-in page through confidential launch. The TypeScript delegation wire modules are unchanged from the RC.8 source baseline.

Grid readiness returned 200. Grid rejected a status request without a cookie with 401 and a foreign-origin launch with 403. A valid same-origin start returned 201 with a secure, HttpOnly, host-only SameSite=Lax transaction cookie and an opaque One launch URL. A callback without an owned transaction redirected within Grid. The One frame registry included Grid and the embedded unlock route served the registry-derived frame policy. The login page retained self-only framing. These checks did not require authentication or modify the deployed applications.

| Qualification area | Evidence and remaining acceptance |
| --- | --- |
| Confidential bound launch | Live start and browser handoff passed. Signed-in callback redemption, automatic workspace entry and launcher entry remain open. |
| Host persistence and live session validation | RC.9 PostgreSQL and lifecycle fixtures passed. Authenticated Grid status and session continuity remain open. |
| Credential renewal and recovery | RC.9 contract tests cover recovery behavior. Verifying an eligible renewal with persisted advancement and a subsequent protected Grid request requires an authorized session under an eligible policy. |
| Smart Lock, foreground activity and bounded viewing | The deployed pre-authentication surfaces are reachable. Verify the locked API decision, accepted foreground activity, bounded viewing and passive behavior with an authorized Grid session. |
| Embedded unlock and cross-tab synchronization | Live registration and frame policy checks passed. RC.9 fixture browser lock and unlock passed. Authenticated One unlock and live cross-tab revalidation remain open. |
| Logout and revocation | Local contract and PostgreSQL checks passed. Verify application logout, central revocation and access removal against deployed Grid with authorized test sessions. |
| Organization lock-screen appearance | The deployed frame was reachable. Verify the effective configured appearance while locked using an authorized test organization and account. |

## Repository and release

The [onboarding guide](onboarding.md), [registration commands and templates](registration.md), standalone reference and framework adapters cover launch-only integration with the SDK, application source and approved registration. [Application delegation requirements](delegated-operations.md) remain separate from launch and Smart Lock acceptance.

The Node and Python candidate checksums and npm integrity were reverified. No authenticated qualification session was available in this run. The existing Node release packer accepts only stable versions, and the workstation has no npm registry authentication. The checked-in workflow uses a protected release tag and registry environment. The Python wheel and source distribution are available as candidate artifacts. An approved Python publication destination and workflow could not be verified from the supplied release materials. Registry publication remains conditional on authenticated acceptance and the approved version and distribution procedure. Keep the release labeled RC.9 candidate until those gates pass.
