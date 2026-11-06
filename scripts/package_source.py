"""Build a source-only archive, deliberately excluding all generated secrets.

Example:
  python scripts/package_source.py --out-dir /some/release/directory

A carefully allowlisted source release is safer than archiving a full working
checkout, but humans must still review newly added source for embedded secrets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
ROOT_NAME = "x509-provisioning-lab"
VERSION = "0.1.0"
TOP_LEVEL = {
    ".gitignore", "README.md", "README_ja.md", "LICENSE", "SECURITY.md",
    "CONTRIBUTING.md", "GITHUB_SETUP.md", "RELEASE_NOTES.md",
    "pyproject.toml", "requirements.txt", "run_tests.py", "run_x509lab.py",
}
SOURCE_DIRS = {"src", "tests", "scripts", "docs", ".github"}
ALLOWED_SUFFIX = {".py", ".md", ".toml", ".txt", ".ps1", ".yml", ".yaml", ".json"}
SKIP_PARTS = {".git", "__pycache__", ".venv", "dist", "build", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
SECRET_FILENAME = re.compile(r"(?:\.key(?:\.pem)?|\.p12|\.pfx|\.p8|\.jks|\.env(?:\..*)?)$", re.I)
SECRET_HEADER = re.compile(rb"(?m)^-----BEGIN (?:ENCRYPTED |RSA |EC |OPENSSH )?PRIVATE KEY-----\r?$")
PEM_CERT_HEADER = re.compile(rb"(?m)^-----BEGIN (?:CERTIFICATE|CERTIFICATE REQUEST|NEW CERTIFICATE REQUEST)-----\r?$")
PRIVATE_TOKENS = tuple(bytes.fromhex(h) for h in (
    "4543484f4e4554",   # legacy organization marker, coded to avoid reintroducing it in published text
    "53504b4757", "53504b2d4757", "53504b5f4757", "e6a99fe599a8e8aa8de8a8bc",
))


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collect() -> list[tuple[str, bytes]]:
    entries = []
    for f in sorted(BASE.rglob("*")):
        rel = f.relative_to(BASE)
        if any(part in SKIP_PARTS for part in rel.parts):
            continue
        if f.is_symlink() or getattr(f, "is_junction", lambda: False)():
            raise ValueError(f"SYMLINK_IN_SOURCE: {rel}")
        if not f.is_file():
            continue
        name = rel.as_posix()
        if name == "artifacts/README.md":
            pass
        elif len(rel.parts) == 1 and name in TOP_LEVEL:
            pass
        elif rel.parts[0] in SOURCE_DIRS and rel.suffix.lower() in ALLOWED_SUFFIX:
            pass
        else:
            # Reject unexpectedly placed files, except generated artifacts.
            if rel.parts[0] == "artifacts":
                continue
            raise ValueError(f"UNEXPECTED_FILE_IN_SOURCE: {name}")
        if SECRET_FILENAME.search(name):
            raise ValueError(f"KEY_FILE_IN_SOURCE: {name}")
        data = f.read_bytes()
        if SECRET_HEADER.search(data) or PEM_CERT_HEADER.search(data):
            raise ValueError(f"EMBEDDED_CREDENTIAL_IN_SOURCE: {name}")
        if any(token in data for token in PRIVATE_TOKENS):
            # Source from a larger internal workspace must be explicitly cleaned.
            raise ValueError(f"PROJECT_SPECIFIC_TOKEN_IN_SOURCE: {name}")
        entries.append((name, data))
    required = TOP_LEVEL | {"artifacts/README.md"}
    existing = {n for n, _ in entries}
    if not required <= existing:
        raise ValueError(f"REQUIRED_SOURCE_MISSING: {sorted(required - existing)}")
    if not any(n.startswith("src/x509_provisioning_lab/") for n, _ in entries):
        raise ValueError("PACKAGE_SOURCE_MISSING")
    return entries


def package(out_dir: Path) -> dict:
    out_dir = out_dir.resolve()
    if out_dir == BASE or out_dir.is_relative_to(BASE):
        raise ValueError("OUTPUT_MUST_BE_OUTSIDE_SOURCE_TREE")
    out_dir.mkdir(parents=True, exist_ok=True)
    entries = collect()
    manifest = "".join(f"{digest(data)}  {name}\n" for name, data in entries).encode()
    entries.append(("MANIFEST.sha256", manifest))
    output = out_dir / f"{ROOT_NAME}_v{VERSION}_PUBLIC.zip"
    tmp = output.with_suffix(".zip.tmp")
    try:
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in entries:
                info = zipfile.ZipInfo(f"{ROOT_NAME}/{name}", date_time=(2026, 11, 7, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        os.replace(tmp, output)
    finally:
        tmp.unlink(missing_ok=True)
    receipt = {
        "schema": "x509lab.public-release/v1",
        "product": ROOT_NAME,
        "version": VERSION,
        "archive": output.name,
        "archive_bytes": output.stat().st_size,
        "archive_sha256": digest(output.read_bytes()),
        "file_count": len(entries),
        "manifest_sha256": digest(manifest),
        "runtime_artifacts_included": False,
        "private_keys_included": False,
        "usage": "TEST_ONLY",
        "review_status": "PUBLIC_RELEASE_CANDIDATE",
    }
    receipt_path = out_dir / f"{ROOT_NAME}_v{VERSION}_PUBLIC_RECEIPT.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"archive": str(output), "receipt": str(receipt_path), **receipt}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out-dir", type=Path, default=BASE.parent)
    args = p.parse_args()
    try:
        print(json.dumps({"status": "PASS", **package(args.out_dir)}, ensure_ascii=False, sort_keys=True))
        return 0
    except (ValueError, OSError) as e:
        print(json.dumps({"status": "FAIL", "error": str(e)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    sys.exit(main())
