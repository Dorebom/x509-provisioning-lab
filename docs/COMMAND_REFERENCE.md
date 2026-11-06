# Command reference

Command pattern (from extracted source root):

```text
python run_x509lab.py <command> --root <lab-name> [arguments]
```

| Command | Arguments | Result |
|---|---|---|
| `init-ca` | `--name`, `--days` | Encrypted CA P-256 key, pinned self-signed test root |
| `new-identity` | `--subject-id`, optional `--identity-id` | Encrypted subject key and signed CSR |
| `issue` | same, `--days` | Signed leaf and public issuance record |
| `provision` | same | Installed public leaf/root and receipt after key-possession check |
| `check-key` | same | Read-only private-key unlock and CSR key matching |
| `verify` | same, optional `--at`, `--time-untrusted` | Certificate validity and private-key-possession verification |
| `revoke` | same, `--reason` | Append certificate fingerprint to local test denylist |
| `demo` | none | Create example CA and three distinct subject identities |
| `verify-demo` | optional `--at`, `--time-untrusted` | Verify all three demo identities; fail closed |

The `--root` argument is interpreted as a subdirectory of `artifacts/`. An absolute path is allowed only when it resolves beneath this source checkout's `artifacts/`; external paths, path traversal and symlink/junction paths are rejected. The default is `artifacts/default/`.

Passphrase sources: hidden interactive prompt or environment variables `X509LAB_CA_PASSPHRASE` and `X509LAB_SUBJECT_PASSPHRASE`. Key-generation commands confirm the interactive passphrase; non-interactive environment values should only be disposable CI secrets. Values are never printed in the CLI JSON result.

Exit status:

- `0`: command completed as intended, result `PASS` in the JSON envelope.
- `2`: invalid input, failed issuance, failed verification or another fail-closed refusal, result `FAIL`.

The JSON output contains paths and certificate fingerprints. These are not key material, but may expose user-chosen local names and directory structures.
