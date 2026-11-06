"""Safe-by-default command line interface for local X.509 test certificates."""
from __future__ import annotations

import argparse
import getpass
import hmac
import json
import os
import sys
from pathlib import Path

from . import __version__
from .core import (
    LabCAError, check_subject_key, demo, init_ca, issue_cert, new_subject,
    parse_at, provision, revoke_identity, verify_demo, verify_provisioned,
)


def secret(which: str, *, confirm: bool = False) -> bytes:
    """Prompt securely; environment variables are allowed for disposable CI only."""
    env_name = f"X509LAB_{which}_PASSPHRASE"
    if env_name in os.environ:
        value = os.environ[env_name]
    elif sys.stdin.isatty():
        value = getpass.getpass(f"Test {which.lower()} key passphrase: ")
        if confirm:
            check = getpass.getpass(f"Confirm test {which.lower()} key passphrase: ")
            if not hmac.compare_digest(value.encode(), check.encode()):
                raise LabCAError("PASSPHRASE_CONFIRMATION_MISMATCH", "Passphrases do not match")
    else:
        raise LabCAError("PASSPHRASE_REQUIRED", f"Provide {env_name} for non-interactive test runs")
    return value.encode("utf-8")


def package_root() -> Path:
    return Path(__file__).resolve().parents[2]


def artifacts_directory() -> Path:
    return package_root() / "artifacts"


def resolve_lab_root(requested: Path | None) -> Path:
    """Resolve test outputs beneath this checkout's artifacts directory."""
    artifacts = artifacts_directory()
    if not artifacts.is_dir() or artifacts.is_symlink() or getattr(artifacts, 'is_junction', lambda: False)():
        raise LabCAError("ARTIFACTS_DIRECTORY_UNAVAILABLE", "A real artifacts/ directory must exist beside the source")
    raw = requested or Path("default")
    if ".." in raw.parts:
        raise LabCAError("ROOT_PATH_TRAVERSAL", "Parent traversal is not permitted")
    if raw.is_absolute():
        candidate = raw
    elif raw.parts[0] == "artifacts":
        candidate = package_root() / raw
    else:
        candidate = artifacts / raw
    root = artifacts.resolve(strict=True)
    resolved = candidate.resolve(strict=False)
    if resolved == root or not resolved.is_relative_to(root):
        raise LabCAError("ROOT_OUTSIDE_ARTIFACTS", "The output root must be a subfolder of artifacts/")
    cursor = artifacts
    for part in candidate.absolute().relative_to(artifacts.absolute()).parts:
        cursor = cursor / part
        if cursor.is_symlink() or getattr(cursor, 'is_junction', lambda: False)():
            raise LabCAError("ROOT_LINK_REJECTED", "Symlinks and junctions under artifacts/ are not accepted")
    if resolved.exists() and not resolved.is_dir():
        raise LabCAError("ROOT_NOT_DIRECTORY", "Output root is not a directory")
    return resolved


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="x509-provisioning-lab",
        description="Generate, issue, provision and verify local X.509 test certificates (not a production CA)",
    )
    p.add_argument("--version", action="version", version=__version__)
    commands = p.add_subparsers(dest="command", required=True)

    def add(name: str, description: str) -> argparse.ArgumentParser:
        s = commands.add_parser(name, help=description)
        s.add_argument("--root", type=Path, help="Subdirectory of artifacts/; defaults to 'default'")
        return s

    ca = add("init-ca", "Create a local encrypted P-256 root CA")
    ca.add_argument("--name", default="Local X509 Test Root CA")
    ca.add_argument("--days", type=int, default=3650)

    def identity(s: argparse.ArgumentParser) -> None:
        s.add_argument("--subject-id", required=True, help="Unique local identifier: letters, digits, - and _")
        s.add_argument("--identity-id", help="Optional certificate identity identifier (defaults to subject-id)")

    identity(add("new-identity", "Generate an encrypted identity key and signed CSR"))
    issue = add("issue", "Issue an X.509 leaf certificate from a validated CSR")
    identity(issue)
    issue.add_argument("--days", type=int, default=365)
    identity(add("provision", "Install issued public certificate and trusted root in an identity directory"))
    identity(add("check-key", "Check encrypted key unlock and CSR binding (read-only)"))
    verify = add("verify", "Validate installed certificate and prove key possession")
    identity(verify)
    verify.add_argument("--at", help="Time for tests: ISO 8601 with UTC offset")
    verify.add_argument("--time-untrusted", action="store_true", help="Negative test: fail closed")
    revoke = add("revoke", "Add a certificate to the local test-only denial index")
    identity(revoke)
    revoke.add_argument("--reason", default="lab-simulated-revocation",
                        choices=["lab-simulated-revocation", "key-compromise", "superseded", "ca-compromise"])
    add("demo", "Create three example certificates and provision them")
    verify_all = add("verify-demo", "Verify all example certificates (fail-closed)")
    verify_all.add_argument("--at", help="Test time, ISO 8601 with UTC offset")
    verify_all.add_argument("--time-untrusted", action="store_true", help="Negative test: fail closed")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        root = resolve_lab_root(args.root)
        name = getattr(args, "subject_id", None)
        ident = getattr(args, "identity_id", None)
        if args.command == "init-ca":
            data = init_ca(root, secret("CA", confirm=True), name=args.name, days=args.days)
        elif args.command == "new-identity":
            data = new_subject(root, name, ident, secret("SUBJECT", confirm=True))
        elif args.command == "issue":
            data = issue_cert(root, name, ident, secret("CA"), days=args.days)
        elif args.command == "provision":
            data = provision(root, name, ident, secret("SUBJECT"))
        elif args.command == "check-key":
            data = check_subject_key(root, name, ident, secret("SUBJECT"))
        elif args.command == "verify":
            data = verify_provisioned(root, name, ident, secret("SUBJECT"),
                                      now=parse_at(args.at), time_trusted=not args.time_untrusted)
        elif args.command == "revoke":
            data = revoke_identity(root, name, ident, reason=args.reason)
        elif args.command == "demo":
            data = demo(root, secret("CA", confirm=True), secret("SUBJECT", confirm=True))
        elif args.command == "verify-demo":
            data = verify_demo(root, secret("SUBJECT"), now=parse_at(args.at),
                               time_trusted=not args.time_untrusted)
        else:
            raise LabCAError("UNKNOWN_COMMAND", "Unsupported command")
        result = {"schema": "x509lab.cli/v1", "test_only": True, "command": args.command,
                  "status": "FAIL" if data.get("status") == "FAIL" else "PASS",
                  "root": str(root), "result": data}
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["status"] == "PASS" else 2
    except LabCAError as exc:
        print(json.dumps({"schema": "x509lab.cli/v1", "test_only": True,
                          "command": args.command, "status": "FAIL",
                          "reason_code": exc.code, "detail": exc.detail}, ensure_ascii=False, sort_keys=True))
        return 2
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"schema": "x509lab.cli/v1", "test_only": True,
                          "command": args.command, "status": "FAIL",
                          "reason_code": "IO_OR_FORMAT_ERROR", "detail": type(exc).__name__},
                         ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
