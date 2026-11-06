# Suggested GitHub repository metadata

**Repository name:** `x509-provisioning-lab`

**Description (English):** Local X.509 test CA toolkit for generating keys, signing CSRs, issuing certificates, simulated provisioning, verification, and revocation checks in Python.

**説明文（日本語）:** PythonでX.509試験用CA、CSR署名、証明書発行、模擬プロビジョニング、検証、失効試験を行う開発ツール。

**Topics:** `python`, `x509`, `pki`, `cryptography`, `certificates`, `csr`, `testing`, `provisioning`

**Suggested visibility:** Public, after manual review of all tracked files.

**Suggested release tag:** `v0.1.0`

## Pre-publication steps

1. Confirm that the repository name is available under your GitHub account. Availability is not guaranteed by this document.
2. Confirm that you own the contributed source or have appropriate publication rights. Adjust the copyright notice before publication if needed.
3. Review the `SECURITY.md` contact channel and enable private vulnerability reporting if appropriate.
4. Run tests and confirm that tracked files exclude `artifacts/` runtime credentials.
5. Upload the *contents* of the extracted repository root, not the outer generated-secret directory or the original internal delivery archive.
6. Run GitHub Actions and create a source release from a clean commit.
