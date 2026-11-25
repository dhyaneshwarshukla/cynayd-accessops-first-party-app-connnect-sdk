# Remote application migration handoffs

This handoff targets the local 0.6.0-rc.4 candidate. Install it in isolated
qualification from the reviewed tarball and verify SHA-256 against the
release record. After restricted publication is approved, run
`npm install --save-exact @cynayd/accessops-first-party-app-connnect-sdk@0.6.0-rc.4`
against the approved private registry and commit the lockfile. See
[restricted distribution](phase2/distribution.md). Use
[bound launch](bound-launch-v1.md) for the pilot. Keep activation disabled
until the independent review and authenticated environment gates pass.
Persist the in-flight renewal marker and advance the host revision with
each credential CAS. On uncertain renewal, route to verified browser
recovery and reconcile pending writes by operation ID.

## Shared integration and rollback

Configure the operator-issued source app key, client ID, assertion key ID,
server-side key provider, exact tenant installations, registered callback,
approved resource audiences and scopes, One endpoint URLs, host credential
store, and shared replay protection where the app is a resource. Confirm
exact configuration from the approved registry before rollout. Keep
credentials and capabilities in encrypted server-side storage. Browser
session event relays carry advisory state only. Recheck authoritative
session state for protected work using the SDK, and apply local resource
permissions before side effects.

Accept renewal, PIN, MFA and logout recovery actions from the common contract.
Treat 401 as a credential/session recovery case, 403 with lock or assurance
action as One-directed interaction, and 403 authorization denial as a
permission result. Back off on 429 and 503. Keep drafts in the application
and use verified browser resume while backend renewal is gated. Prevent
automatic replay of ambiguous writes. Test lock, expiry, revocation,
installation mismatch, proof replay and authority failure before promotion.
For rollback, restore the approved prior image and package lockfile, disable
the new activity adapter through operator policy, and invalidate incompatible
host credentials. Preserve security controls and grants through rollback.

## Mail

Bind verified One launch to the server-held compose session and guard message
send and attachment operations. Preserve drafts and attachment selections.
Qualify Drive attachments and Calendar commands against exact registry grants.
Run the delegated call from the backend that holds the proof key. Propose
mail.compose or mail.send only for an accepted foreground operation, excluding
draft autosave and synchronization. Test expired or locked sessions during
send, duplicate sends after response loss and attachment ACL denial.

## Drive

As a source, apply the same live backend validation and use only approved
tool/resource delegations. As a resource, preserve DPoP, replay reservation,
live introspection, audience/scope validation, file and folder ACLs and
versioned writes. Qualify read and write endpoints separately, including
metadata, preview, download, folder creation, upload, update and share.
Propose file.interact only for verified foreground actions. Test ACL
revocation between token issuance and use, cross-tenant folders and
reconciliation of ambiguous updates.

## Docs

Guard direct document and presentation operations. Preserve unsaved edits
and their revision identifiers through lock, reconnect and network recovery.
Apply existing resource checks to Drive opens and persistence. Use reviewed
document.edit or presentation.edit commands for activity. Autosave cannot
advance activity. Test long-running editing, conflicts, expired delegation
while saving, and reconciliation by operation or document version.

## Connect and Chat

Replace the interactive attribute-only mint path with verified One launch
where still present. Qualify exact Connect and Drive clients, installations,
callback and read/write grants. Keep Calendar's audience and scopes as a
separate approval. Protect direct sends and attachments, report message.send
only after acceptance, and retain drafts and pending uploads. Chat calls the
authorized backend operation and the DPoP-key holder performs the target call.
Test send deduplication, upload reconciliation, lock synchronization and
Drive/Calendar access denial separately.
