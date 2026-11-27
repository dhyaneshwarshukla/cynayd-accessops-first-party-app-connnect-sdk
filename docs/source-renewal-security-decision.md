# Backend source renewal security decision

Status: architecture assessment and prerequisite implementation. Enablement is
blocked pending a completed protocol, independent review, and authenticated
acceptance. Verified browser resume remains supported.

## Decisions

- Go AUTHORITATIVE ordinary portal sessions are the first candidate. Legacy,
  Go SHADOW and Orbit-linked sessions retain their current recovery and activity
  support. Qualify each separately before introducing renewal.
- Use a dedicated `application_source_renewal` Go session-check scope, configured
  explicitly in the tenant's published policy. Reuse signed verifier receipts,
  current enrolled factor capabilities and the current device state. Enforce
  freshness, the baseline minimum assurance and any minimum MFA requirement.
  Return a bounded assurance deadline for future issuance logic. This decision
  is only an input into issuance. It confers no capability and does not record
  activity.
- Add a confidential-client-authenticated launch initiation that fixes the
  app/client/key thumbprint and registered callback before browser
  authorization. The browser authorizes a reference under verified One session
  and CSRF protection. The backend redeems the resulting single-use code with a
  fresh assertion, DPoP proof and backend-held verifier. Consume the grant and
  bind the capability only after checking the same client, proof key, browser
  transaction, canonical installation and access epoch. Do not upgrade the
  existing `/api/sso/redeem-code` bearer code to a renewal grant.
- Store a random opaque 256-bit capability's digest, generation, binding,
  registration revision, proof thumbprint and expiry in One provenance. Keep
  plaintext only in the host backend, encrypted at rest and excluded from
  logs, browser responses, and events.
- Require proof of the exact capability with the renewal request plus the
  existing confidential-client assertion and replay store. A successor is
  usable only by the same client and proof key. Rotate on every successful
  use. An ambiguous response or stale generation requires verified browser
  recovery. Never return a cached successor for a spent capability. Key
  rotation or deactivation invalidates affected capabilities. Rebind through
  verified launch.
- Use the existing Go attempt and SSO row lock ordering, and a conditional
  update against the capability generation and lock revision. The transaction
  must hold the authoritative policy, attempt, and session eligible until it
  commits. Recheck device lifecycle and current assurance, and cap issuance
  at the earliest of the new source TTL, absolute expiry, authentication idle
  expiry, assurance validity and capability expiry. A capability never proves
  current human presence. Preserve the original authentication timestamp.
- Allow One to release the response only after commit. The SDK uses a
  host-provided distributed lease and durable compare-and-set against the
  local credential revision. Host logout invalidates that revision. A lost
  lease or ambiguous write cannot reinstate a signed-out host session.

## Threat model and boundaries

| Threat | Required control |
| --- | --- |
| Stolen launch code or legacy app token | No capability issuance on existing redemption or validate routes. Backend-held verifier and key must match the authenticated launch initiation. |
| Stolen capability | Superseded, mismatched or expired digest/generation denied. Correct registered assertion and DPoP key required. No browser storage. |
| Replay and retries | Fresh proofs with shared replay reservation. Exactly one generation advance. Lost response requires verified browser recovery. |
| Wrong person, tenant, installation or scope | Resolve only One-owned bindings. Recheck AccessOps and exact epoch. Issue dedicated source evidence, usable only for the source app and supported delegation purposes. |
| Lock, PIN unlock or logout race | Compare authoritative revision and serialize against the same session row. Live checks continue for exchange, direct operations and resource introspection after issuance. |
| Device or factor change | Resolve current account, device, and factor usability. Reject obsolete assurance. Keep freshness and step-up requirements distinct from passive session validity. |
| Concurrent administrative revocation | AccessOps and Security Authority are separate consistency domains. A live AccessOps check before issuance is not atomic with an AccessOps grant mutation. Treat the source credential as transport evidence only. Retain fresh AccessOps checks before privileged use and resource introspection. |
| Authority outage | Reject issuance. Back off with bounded retry. Preserve application drafts and reconcile ambiguous business writes separately. |

Device state has persisted authority checks. One currently supplies factor
capability facts to Go before the authority transaction. A factor revocation
can race that snapshot. Some capability identifiers, including the current
TOTP identifier, identify the factor type across credential replacement.
A replacement must invalidate evidence from the superseded credential version.
Issuance needs a reviewed live factor revision or
transactional binding, and renewed evidence needs a defined invalidation
rule. The assurance prerequisite alone does not close this race.

## Proposed contract and rollout gates

The confidential redemption response and a future
`POST /api/v1/delegations/source-renewal` success response would carry a
source credential, independent subject and source deadlines, and a successor
capability and generation. The renewal form would carry the client assertion,
opaque capability and generation. Session, tenant, person, epoch and
installation never come from the caller. Treat this as a proposal until a
versioned implementation and contract tests exist.

Use structured 401 for spent/revoked/expired credentials, 403 for lock,
assurance or AccessOps denial, 429 with backoff, and 503 for unavailability.
No positive authorization cache. After an ambiguous renewal, verify browser
recovery once. Do not replay an upload, send, or autosave because renewal
or post-operation activity failed.

Expired source evidence cannot report activity through the current endpoint.
Renew proactively when possible. If the source has expired, obtain fresh
verified evidence before reporting a newly accepted operation. Authentication
idle or lock may already have won the race. Browser recovery never resurrects
an expired central session.

The current Go session-check policy caps configured evidence age at 15 minutes.
Common primary receipts also expire after 15 minutes. Source expiry and
assurance freshness are different clocks. Reusing session eligibility or
blindly extending verifier receipt expiry would weaken policy. If longer
silent reuse is required, security governance must approve an explicit
durable session-assurance policy with device/factor invalidation semantics.

Before activation, independently review the authenticated launch binding,
factor consistency, generation transaction, lost-response behavior and key
rotation. Exercise simultaneous lock/unlock/logout and AccessOps revocation
with multiple backend instances and actual PostgreSQL and Redis. Run
controlled 1/4/8/12/24-hour scenarios separately from authenticated staging
soaks. Connect, Docs, Grid and Mail retain server-held credentials and
verified browser recovery until those gates pass. The rest of the ecosystem
uses the same contract only after mode and registration qualification.
