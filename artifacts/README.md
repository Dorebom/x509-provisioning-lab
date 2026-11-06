# Local runtime output — not for source control

All generated CA keys, subject keys, CSRs, certificates, provisioned copies, and metadata live under `artifacts/<root-name>/`.

**Never commit, share, or archive the full `artifacts/` tree.** Use `scripts/package_source.py` to build a source-only release. The CA and subject keys are encrypted, but remain sensitive. This project does not provide OS-user isolation, a hardware-backed key store, a publicly trusted CA, or network revocation services.
