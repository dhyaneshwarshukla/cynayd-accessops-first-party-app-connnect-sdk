# Bound application launch candidate

SDK 0.6.0-rc.1 adds server-only initiation and redemption helpers.
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
2. The browser, on the trusted One portal, authorizes the request with
   POST /api/sso/bound-launch-authorize and JSON {request}. The browser
   uses a verified One access cookie and the One CSRF header. The portal
   must present the intended application and obtain explicit user intent.
   The response contains code, callback, and state. The portal sends only
   the request, code, and state to that exact callback. Do not log these
   values or put them in analytics. Portal UI wiring remains outstanding.
3. The host consumes the application transaction and compares request,
   returned state, original browser binding and current host revision
   before redeemBoundLaunch. Keep the result on the server. The host must
   verify the subject through One and check the expected person, tenant,
   installation and session before committing a host session. Never use
   this subject as application session authentication by itself.
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
