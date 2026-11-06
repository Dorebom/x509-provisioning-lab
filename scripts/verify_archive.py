"""Check a public source ZIP: safe members, manifest exact coverage and hashes."""
from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import sys
import zipfile
from pathlib import Path

PREFIX = "x509-provisioning-lab/"
SECRET_PEM = re.compile(rb"(?m)^-----BEGIN (?:ENCRYPTED |RSA |EC |OPENSSH )?PRIVATE KEY-----\r?$")
SECRET_SUFFIX = re.compile(r"(?:\.key(?:\.pem)?|\.p12|\.pfx|\.jks|\.env(?:\..*)?)$", re.I)
BANNED = tuple(bytes.fromhex(h) for h in (
    "4543484f4e4554",   # legacy organization marker, coded to avoid reintroducing it in published text
    "53504b4757", "53504b2d4757", "53504b5f4757", "e6a99fe599a8e8aa8de8a8bc",
))


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        info = archive.infolist()
        names = [x.filename for x in info]
        if len(names) != len(set(names)):
            raise ValueError("DUPLICATE_MEMBER")
        if any(not n.startswith(PREFIX) or n.endswith("/") or "\\" in n or posixpath.normpath(n) != n or ".." in n.split("/") for n in names):
            raise ValueError("UNSAFE_MEMBER_NAME")
        if any((x.external_attr >> 16) & 0o170000 == 0o120000 for x in info):
            raise ValueError("SYMLINK_MEMBER")
        bare = {n.removeprefix(PREFIX): archive.read(n) for n in names}
        manifest = bare.pop("MANIFEST.sha256", None)
        if manifest is None:
            raise ValueError("MANIFEST_MISSING")
        rows = [line.split("  ", 1) for line in manifest.decode("utf-8").splitlines()]
        expected = {n: h for h, n in rows}
        if len(rows) != len(expected) or set(expected) != set(bare):
            raise ValueError("MANIFEST_COVERAGE_MISMATCH")
        for name, body in bare.items():
            if digest(body) != expected[name]:
                raise ValueError(f"MANIFEST_HASH_MISMATCH:{name}")
            if name.startswith("artifacts/") and name != "artifacts/README.md":
                raise ValueError("RUNTIME_ARTIFACT_IN_ARCHIVE")
            if SECRET_SUFFIX.search(name) or SECRET_PEM.search(body) or any(t in body for t in BANNED):
                raise ValueError(f"PRIVATE_MATERIAL_OR_TOKEN:{name}")
        return {"schema": "x509lab.archive-validation/v1", "status": "PASS",
                "zip_sha256": digest(path.read_bytes()), "member_count": len(names),
                "manifest_entries": len(rows), "runtime_artifacts_included": False}


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("archive", type=Path)
    args = cli.parse_args()
    try:
        print(json.dumps(verify(args.archive), indent=2))
        sys.exit(0)
    except (OSError, ValueError, zipfile.BadZipFile, UnicodeError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}))
        sys.exit(2)
