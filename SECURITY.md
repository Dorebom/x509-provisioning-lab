# Security considerations

This project creates **test credentials**. It is intentionally not a public trust service or production-grade CA.

## Supported uses

- Local cryptography and certificate-lifecycle development
- Reproducible integration-test fixtures and disposable certificate provisioning
- Negative tests for validity windows, trust mismatches, possession failures and local denial indexes

## Outside the security boundary

- Public trust, registration authority operations, HSM/TPM-backed key isolation
- Production-grade certificate policy and path validation, CRL/OCSP publication
- Key escrow, remote production enrollment, factory line separation, multi-operator approvals
- Concurrent issuance coordination, transactional database or crash-safe rotation
- Hardened security isolation against malicious users sharing the same host

The CA signing private key and subject private keys currently reside on the same host in different subdirectories. This reflects a **simulated** provisioning environment, not a real security boundary.

## Avoid publishing secrets

- `artifacts/` contains encrypted private keys and should never enter version control or a GitHub upload.
- The `.gitignore` excludes generated artifacts, but .gitignore alone does **not** protect against `git add -f`, manual ZIP creation or accidental file placement elsewhere.
- Use `python scripts/package_source.py`, which applies a source-file allowlist and scans for credential-like content.
- Treat passphrases and generated key files as sensitive even though they are intended for testing.
- Interactive hidden prompts are preferred. Environment-variable secrets are suitable only for isolated throwaway CI fixtures.

## Limits of validation

Validation checks a pinned, single-root test certificate chain, expected critical extensions, P-256 keys, ECDSA signatures, validity windows, local denylist and challenge-response key possession. It is **not** general RFC 5280 certificate path validation. It cannot establish whether a certificate is acceptable for a separate organization's certificate profile, and the generated test URI SAN is not a DNS hostname.

## Reporting a security concern

Do not attach live keys, passphrases or private user data to a public issue. Use the repository's private vulnerability reporting feature, when available, or contact the repository maintainer through an appropriate private channel. The maintainer should configure a real contact method before publishing.
