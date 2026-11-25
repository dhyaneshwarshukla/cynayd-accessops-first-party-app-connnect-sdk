# One broad regression comparison

Baseline used the workspace snapshot with session-related files restored to repository HEAD d4b43f5, while retaining unrelated worktree changes. The pre-change candidate reused the original v0.4.0 session files. The final candidate used the v0.5.0 implementation. All runs used the same dependency links, Jest options and test environment without copying workspace secrets. The first snapshot lacked monorepo dependency links and reproduced 102 failures on both sides; the comparison below uses the restored links.

| Snapshot | Result |
| --- | --- |
| Baseline | 62 failed tests across 30 suites |
| v0.4.0 candidate | 62 failed tests across 30 suites |
| v0.5.0 candidate | 62 failed tests across 30 suites |

All failed test identities match the baseline on both candidates: true. Suite initialization failure paths also match: true. Classifications describe the observed failure family. They are not claims that the underlying baseline defects have been fixed.

| Classification | Tests |
| --- | ---: |
| Authentication policy, response or expectation mismatch | 21 |
| Service mock API mismatch | 4 |
| Security Authority unavailable | 4 |
| Guardrail or baseline assertion mismatch | 3 |
| Tenant-scoping assertion mismatch | 4 |
| Prisma mock API mismatch | 24 |
| MFA service error | 1 |
| Crypto fixture configuration | 1 |

## All 62 failed assertions

Every assertion below failed in the baseline and both candidates.

| Test file | Test | Observed failure family |
| --- | --- | --- |
| `src/__tests__/integration/auth-magic-link-approval.integration.test.ts` | magic link approval integration blocks high-risk email OTP fallback when policy disallows it | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/auth-magic-link-approval.integration.test.ts` | magic link approval integration verifies magic link and returns approval challenge from orchestrator | Service mock API mismatch |
| `src/__tests__/integration/auth-token-issuance-bypass.integration.test.ts` | auth HTTP token issuance bypass rejected challenge poll returns rejected with no token and security event on reject | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/security.integration.test.ts` | security integration (unit-mocked) enforces concurrent session eviction | Security Authority unavailable |
| `src/__tests__/integration/signed-challenge-approval.integration.test.ts` | signed challenge approval HTTP integration 1. keyed device missing signature/payload → SIGNATURE_REQUIRED | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/signed-challenge-approval.integration.test.ts` | signed challenge approval HTTP integration 11. expired expiresAt in payload → SIGNATURE_EXPIRED | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/signed-challenge-approval.integration.test.ts` | signed challenge approval HTTP integration 12. expiresAt later than challenge.expiresAt → INVALID_SIGNATURE | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/signed-challenge-approval.integration.test.ts` | signed challenge approval HTTP integration 13. issuedAt too far in future → INVALID_SIGNATURE | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/signed-challenge-approval.integration.test.ts` | signed challenge approval HTTP integration 14. valid approve signature → approved | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/signed-challenge-approval.integration.test.ts` | signed challenge approval HTTP integration 2. invalid signature bytes → INVALID_SIGNATURE | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/signed-challenge-approval.integration.test.ts` | signed challenge approval HTTP integration 4. reject signature on approve endpoint → INVALID_SIGNATURE | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/signed-challenge-approval.integration.test.ts` | signed challenge approval HTTP integration 5. wrong challengeId → INVALID_SIGNATURE | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/signed-challenge-approval.integration.test.ts` | signed challenge approval HTTP integration 6. wrong nonce → INVALID_SIGNATURE | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/signed-challenge-approval.integration.test.ts` | signed challenge approval HTTP integration 7. wrong organizationId → INVALID_SIGNATURE | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/signed-challenge-approval.integration.test.ts` | signed challenge approval HTTP integration 8. wrong userId → INVALID_SIGNATURE | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/signed-challenge-approval.integration.test.ts` | signed challenge approval HTTP integration 9. wrong deviceId → INVALID_SIGNATURE | Authentication policy, response or expectation mismatch |
| `src/__tests__/integration/sso-security-audit.integration.test.ts` | CYNAYD One SSO Security Audit Phase 1 — Auth flow abuse returns Invalid credentials for wrong password (not password-specific leak) | Authentication policy, response or expectation mismatch |
| `src/accessops/__tests__/baseline/phase0-baseline.contract.test.ts` | Phase 0 baseline — Access Ops domain symbols (real code) baseline.tenant.isolation assertUserInOrg rejects cross-tenant | Guardrail or baseline assertion mismatch |
| `src/accessops/__tests__/baseline/phase0-baseline.contract.test.ts` | Phase 0 baseline — login / MFA / refresh / SAML / launch (real symbols) baseline.app-launch.user-app-access uses tenant-scoped app visibility | Guardrail or baseline assertion mismatch |
| `src/accessops/__tests__/tenant-scope.test.ts` | tenant-scope helpers assertConnectorInOrg returns connector for matching org | Tenant-scoping assertion mismatch |
| `src/accessops/__tests__/tenant-scope.test.ts` | tenant-scope helpers assertGrantInOrg throws when grant is outside tenant | Tenant-scoping assertion mismatch |
| `src/accessops/__tests__/tenant-scope.test.ts` | tenant-scope helpers assertUserInOrg returns user when scoped correctly | Tenant-scoping assertion mismatch |
| `src/accessops/__tests__/tenant-scope.test.ts` | tenant-scope helpers assertUserInOrg throws TenantScopeError when missing | Tenant-scoping assertion mismatch |
| `src/auth/providers/__tests__/password-auth.provider.test.ts` | PasswordAuthProvider allows password when passkeyOnlyWhenEnrolled but user has no passkeys | Security Authority unavailable |
| `src/auth/providers/__tests__/password-auth.provider.test.ts` | PasswordAuthProvider allows password when passkeyOnlyWhenEnrolled is false even if passkeys enrolled | Security Authority unavailable |
| `src/auth/providers/__tests__/password-auth.provider.test.ts` | PasswordAuthProvider rejects password when passkeyOnlyWhenEnrolled and user has passkeys | Authentication policy, response or expectation mismatch |
| `src/lib/__tests__/ssot-guardrails.test.ts` | Identity SSoT guardrails legacy UAA/LoginSession/AccessGrant tables are marked dropped in retirement notes | Guardrail or baseline assertion mismatch |
| `src/middleware/__tests__/continuous-verification.middleware.test.ts` | continuousVerification clearance allows cleared sessions without re-raising SECURITY_REVIEW_REQUIRED | Prisma mock API mismatch |
| `src/middleware/__tests__/continuous-verification.middleware.test.ts` | continuousVerification clearance returns SECURITY_REVIEW_REQUIRED when uncleared and critical | Prisma mock API mismatch |
| `src/middleware/__tests__/require-mfa-enrollment.middleware.test.ts` | requireMfaEnrollment middleware blocks /api/users when mustEnrollMfa is set and MFA not enabled | Security Authority unavailable |
| `src/routes/__tests__/mfa-email-send.test.ts` | POST /api/mfa/email/send returns 400 when email MFA is not enabled | Authentication policy, response or expectation mismatch |
| `src/routes/__tests__/mfa-email-send.test.ts` | POST /api/mfa/email/send returns challengeId when email MFA is enabled | Authentication policy, response or expectation mismatch |
| `src/routes/__tests__/user-admin-reset-password.test.ts` | POST /api/users/:id/reset-password returns 403 without step-up token | Authentication policy, response or expectation mismatch |
| `src/services/__tests__/auth-audit.service.test.ts` | AuthAuditService recordLoginFailed omits audit log when user unknown | Prisma mock API mismatch |
| `src/services/__tests__/auth-audit.service.test.ts` | AuthAuditService recordLoginFailed stores organizationId for unknown email without audit row | Prisma mock API mismatch |
| `src/services/__tests__/auth-audit.service.test.ts` | AuthAuditService recordLoginFailed uses userId when email resolves | Prisma mock API mismatch |
| `src/services/__tests__/complete-login-challenge-session.test.ts` | completeLoginFromChallengeSession MFA after security review returns enriched MFA_REQUIRED and transitions attempt | Prisma mock API mismatch |
| `src/services/__tests__/complete-login-challenge-session.test.ts` | completeLoginFromChallengeSession MFA after security review returns MFA_ENROLLMENT_REQUIRED when MFA not enrolled and no passkey | Prisma mock API mismatch |
| `src/services/__tests__/login-approval-bootstrap.test.ts` | login approval bootstrap returns APPROVAL_CHALLENGE_REQUIRED when approval required but challenge missing | Prisma mock API mismatch |
| `src/services/__tests__/login-approval-bootstrap.test.ts` | login approval bootstrap returns APPROVAL_EMAIL_OTP_REQUIRED for zero devices at medium risk | Prisma mock API mismatch |
| `src/services/__tests__/login-approval-bootstrap.test.ts` | login approval bootstrap returns APPROVAL_REQUIRED with pushDelivered false when device registered but no push token | Prisma mock API mismatch |
| `src/services/__tests__/login-pipeline-mfa.test.ts` | loginPipelineService MFA flags sets requireApproval for require_approval action | Service mock API mismatch |
| `src/services/__tests__/login-pipeline-mfa.test.ts` | loginPipelineService MFA flags sets requireMfa when policy returns require_mfa | Service mock API mismatch |
| `src/services/__tests__/login-pipeline-mfa.test.ts` | loginPipelineService MFA flags sets requireMfaEnrollmentBlock for require_mfa_enrollment action | Service mock API mismatch |
| `src/services/__tests__/mfa-device-enrollment.service.test.ts` | mfaDeviceEnrollmentService cancels pending enrollment | Prisma mock API mismatch |
| `src/services/__tests__/mfa-device-enrollment.service.test.ts` | mfaDeviceEnrollmentService completes enrollment and enables MFA | Prisma mock API mismatch |
| `src/services/__tests__/mfa-device-enrollment.service.test.ts` | mfaDeviceEnrollmentService enforces push retry limit | Prisma mock API mismatch |
| `src/services/__tests__/mfa-device-enrollment.service.test.ts` | mfaDeviceEnrollmentService rejects completion for mismatched user | Prisma mock API mismatch |
| `src/services/__tests__/mfa-device-enrollment.service.test.ts` | mfaDeviceEnrollmentService returns pending session via getPendingForUser | Prisma mock API mismatch |
| `src/services/__tests__/mfa-device-enrollment.service.test.ts` | mfaDeviceEnrollmentService starts and returns pending session for user with mfa secret | Prisma mock API mismatch |
| `src/services/__tests__/mfa-passkey-stepup.service.test.ts` | mfa-passkey-stepup.service starts MFA passkey step-up for MFA_REQUIRED attempt | Prisma mock API mismatch |
| `src/services/__tests__/mfa-passkey-stepup.service.test.ts` | mfa-passkey-stepup.service verifies passkey MFA and continues login without bypassing gatekeeper path | Prisma mock API mismatch |
| `src/services/__tests__/mfa.service.test.ts` | mfaService.disableMFA clears MFA state and untrusts all devices | MFA service error |
| `src/services/__tests__/passkey-approval-fallback.service.test.ts` | passkey-approval-fallback.service blocks passkey approval start at critical risk | Prisma mock API mismatch |
| `src/services/__tests__/passkey-approval-fallback.service.test.ts` | passkey-approval-fallback.service consumes backup code and completes login at low risk | Prisma mock API mismatch |
| `src/services/__tests__/passkey-approval-fallback.service.test.ts` | passkey-approval-fallback.service finishes passkey approval through gatekeeper completion path | Prisma mock API mismatch |
| `src/services/__tests__/passkey-approval-fallback.service.test.ts` | passkey-approval-fallback.service starts passkey approval when allowed | Prisma mock API mismatch |
| `src/services/__tests__/resolve-login.service.test.ts` | resolveLogin service defers IP allow-list MFA challenge until post_primary so login/start can issue password challenge | Authentication policy, response or expectation mismatch |
| `src/services/__tests__/risk-auth-mfa-enrollment.test.ts` | riskAuthService.getAuthRequirements (MFA enrollment grace) blocks critical risk regardless of MFA enrollment | Authentication policy, response or expectation mismatch |
| `src/utils/__tests__/mfa-secret-crypto.util.test.ts` | mfa-secret-crypto.util encrypts and decrypts envelope secrets | Crypto fixture configuration |
| `src/utils/__tests__/tenant-scope-security.test.ts` | userIdFilterForScope security events org admin filter includes organizationId OR user ids | Prisma mock API mismatch |
| `src/utils/__tests__/tenant-scope-security.test.ts` | userIdFilterForScope security events org admin filter matches org-scoped events without userId via organizationId | Prisma mock API mismatch |

## Suite initialization failures

- `src/accessops/__tests__/integration/tenant-isolation.integration.test.ts`
- `src/accessops/__tests__/pilot-certification-foundation.test.ts`
- `src/accessops/__tests__/security-certification.test.ts`
- `src/accessops/__tests__/worker-helpers.test.ts`
- `src/orbit/__tests__/handoff-prisma.test.ts`

Isolated delegation tests run separately with a temporary PostgreSQL database. The broad run alone does not qualify OAuth/Orbit database integration or an authenticated staging deployment.
