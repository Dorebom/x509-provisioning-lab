# X.509 Provisioning Lab

**A Python toolkit for local, disposable X.509 certificate issuance and provisioning tests.**

Create an encrypted private root CA, generate per-subject P-256 keys and signed CSRs, issue X.509 v3 leaf certificates, install public credentials, validate them, and simulate revocation. Intended for development, integration tests, workshops, and certificate lifecycle experiments.

> **TEST ONLY.** This is not a production CA, a general RFC 5280 validation engine, or a substitute for a trusted certificate service. Do not use its root certificates or private keys for production or publicly exposed systems.

## Features

- Encrypted PKCS#8 P-256 private keys; ECDSA/SHA-256 signatures
- Local root CA (`BasicConstraints: CA=true`, path length 0)
- Signed CSRs and CA-issued X.509 v3 leaf certificates
- Test URI `subjectAltName` tied to a local subject/identity ID
- Test leaf extended key usages: `clientAuth` **and** `serverAuth`
- Basic certificate validity, issuer signature, extension and key-possession checks
- Local fingerprint denylist to **simulate** revocation (not CRL or OCSP)
- Non-overwriting file creation, fail-closed validation and structured JSON CLI results
- Outputs written only under the extracted source directory's `artifacts/`
- Python regression tests and a source-only ZIP packaging script

## Requirements

- Python **3.11 or newer** (tested locally on Python 3.13)
- `cryptography==46.0.4`
- Windows PowerShell or a POSIX shell

## Quick start — Windows PowerShell

Extract the source ZIP, open PowerShell in the extracted `x509-provisioning-lab` directory, then run:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run_tests.py

# Create a disposable local CA and three sample certificates.
.\.venv\Scripts\python.exe run_x509lab.py demo --root public-demo

# Enter the same SUBJECT passphrase used by the demo.
.\.venv\Scripts\python.exe run_x509lab.py verify-demo --root public-demo

# Inspect the generated files.
explorer.exe .\artifacts\public-demo
```

The `demo` command asks for two passphrases: one for the **CA** private key and one shared among the **sample subjects**. These are separate secrets. When generating new keys, both prompts require confirmation. Individual issuance lets each subject have its own passphrase.

## Quick start — Linux/macOS

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python run_tests.py
.venv/bin/python run_x509lab.py demo --root public-demo
.venv/bin/python run_x509lab.py verify-demo --root public-demo
```

## Manual issuance for an arbitrary subject

Replace `<python>` with `.\.venv\Scripts\python.exe` (Windows) or `.venv/bin/python` (POSIX).

```text
<python> run_x509lab.py init-ca --root demo-ca
<python> run_x509lab.py new-identity --root demo-ca --subject-id application-a
<python> run_x509lab.py issue --root demo-ca --subject-id application-a
<python> run_x509lab.py provision --root demo-ca --subject-id application-a
<python> run_x509lab.py check-key --root demo-ca --subject-id application-a
<python> run_x509lab.py verify --root demo-ca --subject-id application-a
```

CA passphrase is needed for `init-ca` and `issue`; subject passphrase is needed for `new-identity`, `provision`, `check-key`, and `verify`. All private keys stay encrypted on disk.

`--subject-id` names the logical owner of an identity; optionally supply `--identity-id` when you need more than one distinct certificate identity under that owner. This is a local file-management model, **not** a statement of requirements for any external certificate profile.

## Revocation simulation

```text
<python> run_x509lab.py revoke --root demo-ca --subject-id application-a --reason key-compromise
<python> run_x509lab.py verify --root demo-ca --subject-id application-a
```

The second command fails with exit status `2` and `CERT_REVOKED_LAB`. This is an expected secure rejection, not an error in the test itself. No CRL or OCSP response is generated.

## File layout

```text
x509-provisioning-lab/
├── run_x509lab.py
├── run_tests.py
├── src/x509_provisioning_lab/
├── tests/
├── scripts/
├── docs/
├── .github/workflows/
└── artifacts/
    ├── README.md                 # safe to publish
    └── public-demo/              # GENERATED; never publish
        ├── ca/private/root.key.pem
        ├── ca/public/root.cert.pem
        ├── ca/profile.json
        ├── ca/revocations.json   # appears after revocation
        ├── issued/
        └── subjects/<subject-id>/identities/<identity-id>/
            ├── private/identity.key.pem
            ├── request.csr.pem
            └── provisioned/
                ├── identity.cert.pem
                ├── lab-root.cert.pem
                └── receipt.json
```

Private keys are encrypted but **remain sensitive**. Do not commit or upload the generated `artifacts/` tree. The `.gitignore` excludes it. Use `python scripts/package_source.py` for a source-only release (not your file manager's ordinary ZIP action).

## Verification / limitations

- `python run_tests.py` runs the regression suite.
- Signing and validating use the real `cryptography` library, not a simulated cryptographic success response.
- The built-in verifier intentionally supports a narrow **single self-signed P-256 root → P-256 leaf** chain only. It does not implement arbitrary certificate-path building or all RFC 5280 policy requirements.
- The issued leaf has a **URI SAN**, not a DNS hostname SAN or IP SAN. It is not suitable for ordinary browser hostname validation without changing the profile.
- The local denial index is not a network revocation protocol; no hardware key storage, multi-user privilege separation, audit service, or secure factory boundary is provided.
- Test secrets may be supplied non-interactively through `X509LAB_CA_PASSPHRASE` and `X509LAB_SUBJECT_PASSPHRASE`, but environment variables can be exposed to local processes and debugging tools. Prefer interactive prompts and use CI variables only for disposable test material.
- The direct source launcher and editable installation are supported. A non-editable wheel install is **not** the recommended execution model because runtime output is deliberately anchored to the extracted source tree.

See [Security considerations](SECURITY.md), [design](docs/ARCHITECTURE.md), and [command reference](docs/COMMAND_REFERENCE.md).

## Release, contributions, license

See [RELEASE_NOTES.md](RELEASE_NOTES.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [MIT LICENSE](LICENSE). This code is supplied as a public-development candidate; review the license attribution and security assumptions before making it public.
