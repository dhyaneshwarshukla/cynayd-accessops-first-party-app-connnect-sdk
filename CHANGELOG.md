# Changelog

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
