# Release notes

## v0.1.0 — public-source candidate (2026-11-07)

- Extracted and generalized X.509 certificate workflows into a standalone Python package.
- Implemented an independent local root CA, subject-side P-256 key generation, signed CSR, CA issuance, simulated public credential installation, verification and local revocation simulation.
- Added a generic example with three independently issued identities.
- Added source-only packaging, GitHub CI, documentation, and automated positive/negative tests.
- Preserved fail-closed error handling and encrypted local private-key storage.

**Compatibility:** This public CLI uses new command names, namespaces, file paths and output metadata. It is not a drop-in replacement for other private prototypes. Pre-existing local credential directories should not be copied or reused without a deliberate compatibility review.
