# Changelog

## 0.6.0-rc.9

- Adds the shared confidential host lifecycle, same-origin Fetch and Node HTTP adapters, sealed PostgreSQL host persistence and an atomic resource proof replay store.
- Adds native FastAPI and Python PostgreSQL adapters, pinned One JWKS lookup and source and resource delegation.
- Adds the One-hosted unlock modal, framework references and a single onboarding guide with the audited One operator workflow.
- Documents verified Drive request shapes and the target contracts still needed for other delegated workflows.
- Candidate qualification uses local One fixtures and PostgreSQL. Authenticated deployment acceptance and restricted registry publication remain release gates.


## 0.6.0-rc.7

- Add the shared browser host-session client for status, launch, recovery and local logout.
- Add a server operation for live bound-host validation, optional source renewal and current-evidence checks.
- Reject non-string bound callback fields before consuming launch state.

## 0.6.0-rc.6

- Support confidential initial entry with the signed One subject as the identity source. Preserve existing host recovery binding checks.

## 0.6.0-rc.5

- Negotiate optional renewal during confidential bound launch. Explicitly
  ineligible sessions keep verified browser recovery. Mandatory renewal
  continues to require a valid capability.

## 0.6.0-rc.4

- Claim each renewal generation durably before sending it to One. Response loss,
  process exit and overlapping leases cannot trigger another send of that generation.

## 0.6.0-rc.3

- Add disabled-by-default confidential source renewal and protected host
  credential coordination.
- Rotate source capabilities once and use verified browser recovery after an
  ambiguous response. Existing bound launch without renewal remains compatible.


## 0.6.0-rc.2

- Validate the bound launch callback and write delegation evidence through the
  authenticated host session's revision compare-and-set.
- Document the One portal confirmation flow and continuing assurance pilot
  prerequisites. This candidate does not issue silent renewal credentials.


## 0.6.0-rc.1

- Add server-only confidential bound-launch initiation and redemption.
- Document the pilot flow, rollout gates and TOTP version prerequisite.
- Silent source renewal remains outside this candidate.


## 0.6.0-rc.0

- Surface One's optional qualified authentication-idle update result while
  retaining the v0.5 response shape for legacy servers.
- Document the Go-authoritative pilot, application adapters, and the pending
  security review for backend-only source renewal.


## 0.5.0

- Adds authenticated, allowlisted activity reports and direct-operation session enforcement.
- Adds application SSE relay support with coalesced, passive session monitoring.
- Keeps verified browser source renewal and existing delegation behavior.

## 0.4.0

- Adds private, passive One session status with deadlines and structured lock recovery.
- Adds a browser-only session invalidation observer for same-origin coordination.
- Preserves verified browser renewal and existing delegation APIs.

## 0.3.0

- Adds One browser resume helpers, verified same-session credential replacement and proactive expiry status.
- Exposes launch, portal binding, delegation subject and source API token deadlines separately.
- Keeps existing launch defaults and target exchange interfaces compatible.

## 0.2.0

- Adds verified One launch/session binding, delegation exchange, private key JWT, DPoP, live introspection and resource integration.
- Preserves the existing Ed25519 AccessOps product authorization API.
- Adds versioned contract documentation, Connect handoff, local fixtures and contract tests.
- Prepares exact-version distribution through restricted npm packages. Check the private release workflow for publication status and the release checksum.

## 0.1.1

- Enforces Ed25519 product evaluation, known installation, HTTPS and fail-closed denial handling.
