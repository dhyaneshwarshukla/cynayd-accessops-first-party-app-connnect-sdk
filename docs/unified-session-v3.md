# Unified session v0.6 release candidate

Status: local candidate for qualified authentication activity in Go-authoritative
One sessions. Silent backend source renewal remains blocked. Keep the activity
policy disabled outside an approved authenticated pilot.

## Authority assessment

| Mode | Authentication lifecycle | Product activity in this candidate |
| --- | --- | --- |
| Go AUTHORITATIVE | The existing Go attempt and issued session hold the policy revision/hash, evidence, device, last authentication activity, and absolute expiry. The SSO row binds and revokes the session. Portal refresh rotates the portal refresh JTI under the authority transaction. | Exact operator opt-in for approved product operations. Go changes its existing activity timestamp and updates the screen-lock marker in the same database commit. |
| Legacy, including Go SHADOW | One reads the SSO row, legacy effective organization policy and platform-specific idle timeout. Go shadow output does not confer authority. | Existing v0.5 lock-only behavior. The candidate has no qualified legacy authentication-idle writer. |
| Orbit-linked browser session | Go additionally checks the native parent, browser channel and device. The browser credential and native lifecycle are distinct. | Go declines qualified authentication activity for these channels. Keep them out of the pilot. |

One's verified launch and code redemption establish app and installation
provenance. Delegation subjects are bounded by their One-held launch binding and
the original portal-access deadline. Target credentials may be exchanged again
while the subject is valid. Passive session status, delegation, and live
introspection never advance the idle clock. PIN unlock changes the lock revision
and lock activity marker. It leaves authentication assurance and absolute
expiry subject to authority policy.

## Activity API

Use the existing SDK server method
`client.reportActivity(binding, operation, eventId, requestId?)` against
`POST /api/v1/delegations/activity`. The request stays form-encoded with
`client_id`, `client_assertion_type`, `client_assertion`, `subject_token_type`,
`subject_token`, `operation`, and `event_id`, with a DPoP header. One validates
the confidential client, assertion/proof replay, current source subject and
session, canonical AccessOps app authorization, exact installation and access
epoch before calling the authority. The SDK creates fresh transport proofs.
Use one stable event ID per accepted operation, including retries.

The response retains `accepted: true` and `updated: boolean`. An optional
`authenticationIdleUpdated: boolean` appears when the request used the qualified
Go path. False means admission without a clock advance, including duplicates and
coalesced reports. Absence preserves the original v0.5 response. Obtain current
deadlines through session status when needed. Silent status caps its
authentication idle deadline at absolute expiry. Keep that deadline separate
from the PIN lock clock and the source, subject and target credential deadlines.

Set `ONE_AUTHENTICATION_ACTIVITY_POLICY` only for approved
`tenantId:clientId:installationId:operation` entries, comma separated. Empty or
absent disables Go authentication activity. Keep the corresponding existing
`ONE_FIRST_PARTY_ACTIVITY_POLICY` entry and central inactivity lock configured.
Use canonical identifiers from the registry. Configure and test the internal
One-to-Go service authentication and the migration giving the existing security
DB role replay insert access before enabling any pilot entry. Product
applications call only One's existing public delegation surface.

Go uses database time after taking the attempt, device and SSO row locks.
It rejects expired evidence, idle or absolute expiry, revocation, lock,
an already-due inactivity lock, stale lock revision and changed Go policy.
It reserves event hashes using the existing replay table and coalesces writes
across applications for 30 seconds. Active attempts use the existing Go idle
clock. Authorization and device outages fail closed. AccessOps is checked
online before the authority transaction. It is a separate authority call, so
there is no distributed transaction with concurrent AccessOps grant mutations.

Use structured 401/403/429/503 errors and existing SDK recovery actions.
Handle lock through One PIN, changed assurance or expiry through verified
browser resume or reauthentication, AccessOps denial as a permission error
and unavailability with backoff. Never use a successful business operation's
activity-report failure as a reason to automatically rerun the operation.

## Silent backend source renewal review

The current launch row stores app, installation, session, epoch and expiry.
It has no sender-constrained renewal capability. The passive Go validator
checks live transport eligibility and policy revision. The Go sensitive-action
check separately applies purpose-specific assurance, factor usability and
freshness. The portal refresh operation requires rotating portal credentials
and advances activity. None of those interfaces alone is a product-renewal
contract. Legacy sessions lack a common equivalent of the Go assurance
decision. Orbit's channel-specific context also requires separate review.

A candidate design for independent review is a launch-time, opaque, one-purpose
grant, bound on confidential-client-authenticated redemption to the exact
One session, canonical user and tenant, client, installation, access epoch and
DPoP thumbprint. Store only its hash and generation in existing One-owned
provenance storage. A renewal request would bind the presented capability to
the DPoP proof and client assertion, re-evaluate a dedicated Security Authority
assurance policy and canonical AccessOps, then serialize grant rotation and
issuance with the session's lock/revocation state. New evidence would remain
source-app-only and short-lived, capped by the strictest authoritative
deadline. Portal refresh credentials stay within One.

| Threat | Required design and acceptance |
| --- | --- |
| Capability disclosure | Reject wrong DPoP key and registered client. A stolen capability alone cannot renew. No capability, proof or token in logs or browser responses. |
| Replay and duplicate renewal | Shared proof replay protection, atomic generation compare-and-swap and host distributed single-flight. Define lost-response behavior without returning a successor to a replayed or different proof key. |
| Logout or PIN lock racing issuance | Linearize issuance with canonical revocation and lock changes. Newly issued evidence remains subject to live authorization and lock checks. Reject old lock revisions after PIN unlock. |
| Factor or device changes | Resolve live device, account and usable factors. Apply a reviewed purpose-specific assurance decision. Capability possession cannot satisfy PIN, presence, MFA or step-up. |
| App/client/installation changes | Require current registration, exact installation and epoch. Review client and DPoP key migration and revoke superseded capabilities. |
| Cross-tenant or escalation | Resolve identity solely from One-owned provenance. Issue only restricted source evidence. Resource tokens still need canonical AccessOps and live resource checks. |

No renewal endpoint or capability is issued by this candidate. A purpose-specific
assurance policy, launch-key binding, transaction and lost-response semantics,
and independent security signoff remain implementation gates. Preserve the
existing verified browser resume contract and stop automatic retry on
`SOURCE_RENEWAL_NOT_ADVANCED`.

## Common product integration

Protect direct operations with SDK `withCentralSession`, then apply local
application and resource authorization. Delegated operations use exchange and
live resource introspection. The backend holding the target DPoP key executes
the target call. Report activity only after an approved interactive command
is accepted. Attachments, autosave, activity reports and delegation retries
have separate lifecycles. Preserve drafts through recovery, coordinate one
browser reconnect per session and recheck protected operations following an
advisory SDK session event. Retain an idempotency key or reconcile ambiguous
writes before retry.

| Products | Candidate adapter operations for governance review |
| --- | --- |
| Connect and Chat | `message.send` after an accepted interactive send. Chat uses the backend holding the Drive proof key for attachments. |
| Docs | `document.edit` and `presentation.edit` after an accepted foreground edit command. Autosave is excluded. |
| Grid | `spreadsheet.edit` after an accepted foreground edit command. Autosave is excluded. |
| Drive | `file.interact` for reviewed foreground operations after file/folder ACL checks. |
| Mail | `mail.compose` or `mail.send` for accepted interactive commands. Preserve compose state through recovery. |
| HRMS and CRM | `record.edit` for reviewed operations with local record authorization. |
| Calendar, Forms, Tasks, Vault and Groot | Use the same session lifecycle. Keep authentication-idle reporting disabled until governance approves exact applicable operation classes and underlying adapters. Vault retains its verified federation path. |

## Compatibility and acceptance

SDK 0.5 continues to work with the extended response. SDK 0.6.0-rc.0 accepts
the existing v0.5 result and surfaces the optional Go outcome. Prior SDK
refresh and launch behavior remains as documented in the existing contracts.
Use the existing restricted package registry and pinned release workflow
in [distribution](phase2/distribution.md).

Local fixture coverage includes replay, concurrent duplicate writes, stale
lock revision, explicit lock, subject expiry, underlying idle and absolute
expiry, revocation, and unchanged portal refresh identity. It is not realistic
load or authenticated soak evidence. Before approval, qualify the exact
tenant, installations, identities, clients and reviewed command adapters in
staging. Run 1/4/8/12/24-hour scenarios, activity and renewal versus lock/logout
races, multiple devices and browser sleep, service and AccessOps faults, live
Docs/Grid-to-Drive, Vault/SAML/Orbit and worker integrations. Measure service
latency, database/Redis load and session event traffic across multiple replicas.
Audit existing portal activity writers for background traffic under the pilot
policy. Both foundational capabilities and authenticated acceptance are
required for production GO.
