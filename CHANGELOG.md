# Changelog

## 0.1.1

- Validate the common authority envelope and exact tenant/person/installation/application/permission target before interpreting either decision.
- Return 503 for bare, mismatched, contradictory or resource-scoped DENY responses; reserve 403 for a validated authoritative denial.
- Preserve the existing initial-session/epoch behavior for ALLOW and add real EdDSA signature/scope tests.
- Document that the current product verifier is EdDSA-only and that all three platform registration gates remain mandatory.
