# Bound application launch candidate

SDK 0.6.0-rc.2 adds host callback completion to the server-only initiation and redemption helpers.
This candidate issues a delegation subject using the existing One launch
deadline. It includes no renewal capability or source-renewal endpoint.

Set the One pilot flag ONE_BOUND_LAUNCH_ENABLED only in a qualified
environment. Set ONE_BOUND_LAUNCH_CALLBACKS to a JSON object keyed by the
registered delegation client ID, with exact approved HTTPS callback URLs as
array values. The default is disabled. Use the existing registration,
assertion keys, DPoP, client rate limits and AccessOps authorization.

1. The host calls initiateBoundLaunch with the registered callback. It
   stores request, verifier, state, and expiry in a server-side, one-time
   transaction bound to the browser and host session revision. Only the
   opaque request goes to the One portal.
2. Send only the opaque request to the trusted One portal at
   /apps/bound-launch?request=.... The page previews the registered application
   and callback and asks the user to continue. The cookie-authenticated CSRF
   protected POST to /api/sso/bound-launch-authorize first accepts
   {request, intent: "preview"} and binds the request to that One session.
   Only explicit confirmation submits {request, intent: "approve"}.
   The portal sends request, code and state to the exact configured callback.
   Exclude callback query values from access logs and analytics.
3. The host adapter calls OneApplicationSession.completeBoundLaunch with
   a store that atomically consumes the initiating browser's state. The SDK
   verifies the subject signature and app, person, tenant, installation,
   original One session and epoch, then applies the host credential revision
   compare-and-set. Store only on the backend. This operation attaches
   delegation evidence to an existing authenticated host session.
4. A timeout or uncertain redemption starts a new verified launch. A
   consumed code cannot return a second subject.

The form-encoded initiation and redemption paths are
/api/v1/delegations/bound-launch-initiate and
/api/v1/delegations/bound-launch-redeem. Both take private_key_jwt and DPoP.
Initiation takes callback, challenge (SHA-256 of verifier, base64url), and
state, and returns request and expires_in (120 seconds).
Redemption takes request, code, and verifier and returns subject_token.
Code, state, request and verifier are 32 random bytes encoded as base64url.
One consumes the authorized Redis record atomically after checking the
registered client revision, assertion key, DPoP key and verifier. The
browser authorization operation can only advance the Redis record once.
One rechecks live launch session and source AccessOps epoch before returning
the subject. Existing bearer code endpoints have no access to these records.

## Factor-version prerequisite

Migration 0205 versions the existing TOTP credential row. It advances the
version on secret or enabled-state changes, including removal and replacement.
The Go TOTP verifier consumes the TOTP time step conditional on the version
read during verification. New Go receipts carry that version in the factor
identifier. Go locks and compares the current version in its source
assurance transaction. Legacy receipts cannot satisfy the TOTP renewal
check, and the legacy login paths retain their existing factor handling.

The TOTP SQL row lock closes this part of the race only inside the Go
transaction. Future generation advancement and issuance must occur in the
same transaction. Passkey, mobile approval, password, email and recovery
provenance still require comparable version and invalidation review before
any capability is issued. AccessOps evaluation remains a separate live check.

## Tenant policy decision required

Keep continuing assurance disabled. The proposed tenant policy is an
explicit application_source_renewal mode with an approved maximum
continuation age measured from original verified authentication, minimum
assurance, and exact eligible installation policy. It would be evaluated
against durable verified session assurance derived at initial login, with
current credential-generation checks, device eligibility, idle and
absolute deadlines, lock revision, revocation and current risk and
step-up rules. It would not mutate verifier expiry or prove presence.
Security governance must approve the duration, eligible factor kinds,
risk and step-up requirements, and invalidation semantics. Independently
review these decisions and the issuance transaction before activation.

The administrative reset routes also require the existing step-up
middleware with the admin.users.reset_password scope. Go-authoritative
tenants need that exact scope in their approved policy for the operation.

## Continuing assurance pilot controls

Migration 0206 versions the authoritative password hash and exposes a
restricted database function that locks both the password and TOTP generations.
The dedicated Go password routes sign the generation paired with the exact
verified hash. Go pins versioned password and TOTP receipts at initial grant
consumption and during the source-assurance transaction.

The Go test policy has an optional continuingSourceAssurance with
maximumAgeMinutes (1–480) and allowedSources (exact clientId and installationId
pairs). It requires an application_source_renewal session check and explicit
session lifetime policy. The process switch
ONE_CONTINUING_SOURCE_ASSURANCE_ENABLED defaults to disabled. The internal
decision also requires the current unlocked One revision and an eligible
ordinary Go session. The pilot reuses low-risk, verified password plus TOTP
assurance from original grant consumption. Its deadline is the earliest of age
from original verification, current authentication idle and absolute expiry.
It changes neither receipt expiry nor session activity.

Passkeys, mobile approval, email, and recovery evidence cannot contribute to
this pilot. They retain existing sign-in behavior. Legacy, Go SHADOW, Orbit
and SAML are outside the continuing pilot. No product endpoint invokes this
mode to issue credentials yet. Before issuance, independently review current
risk and required step-up handling, lazy idle lock and central logout
serialization, atomic capability rotation and credential-generation invalidation
of previously issued renewed subjects. AccessOps remains a separate live
authorization boundary.
