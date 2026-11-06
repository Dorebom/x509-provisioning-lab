# Contributing

- Keep the tool **test-only** and do not add features that silently create a publicly trusted root.
- Run `python run_tests.py` and document new negative cases for any change to issuance, validation or file handling.
- Do not commit runtime credentials, certificate signing requests containing real identifiers, user passphrases, or artifacts generated in non-test environments.
- Keep the CLI's JSON result schema stable when possible. Changes to file layouts should include a migration note.
- Submit focused changes with an explanation of threat boundaries and affected tests.

This project uses an MIT license. Contributed code must be compatible with it.
