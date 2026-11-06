"""Lab CA, CSR issuance, simulated provisioning and pinned-root verification.

All identities are TEST_ONLY. The chain validation deliberately handles only a
single test root issuing P-256 leaves; it is NOT an RFC 5280 general path builder
and is NOT an external certificate-profile implementation.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import secrets
import tempfile
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ExtensionOID

UTC = dt.timezone.utc
SCHEMA = "x509lab.core/v1"
LAB_ORG = "X509 Provisioning Lab - Test Certificates Only"
LAB_PROFILE = "X509LAB-P256-DEMO-v1"
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}\Z")
ALLOWED_CSR_EXTENSIONS = frozenset({ExtensionOID.SUBJECT_ALTERNATIVE_NAME})
# These extensions are known to this narrow lab-only verifier.
ALLOWED_LEAF_EXTENSIONS = frozenset({
    ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
    ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.SUBJECT_KEY_IDENTIFIER,
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
})


class LabCAError(Exception):
    def __init__(self, code: str, detail: str):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def safe_id(value: str, field: str) -> str:
    if not SAFE_ID.fullmatch(value):
        raise LabCAError("INVALID_ID", f"{field} must match {SAFE_ID.pattern!r}")
    return value


def current_time() -> dt.datetime:
    return dt.datetime.now(UTC)


def iso(value: dt.datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_at(value: str | None) -> dt.datetime:
    if not value:
        return current_time()
    try:
        candidate = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LabCAError("INVALID_TIME", "Expected ISO 8601 timestamp with offset") from exc
    if candidate.tzinfo is None:
        raise LabCAError("INVALID_TIME", "UTC offset is required")
    return candidate.astimezone(UTC)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cert_fp(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def lab_uri(subject_id: str, identity_id: str) -> str:
    return f"urn:x509lab:test:subject:{subject_id}:identity:{identity_id}"


def subject_for(identity_id: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, LAB_ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, identity_id),
    ])


def ca_paths(root: Path) -> tuple[Path, Path, Path]:
    return (root / "ca" / "private" / "root.key.pem",
            root / "ca" / "public" / "root.cert.pem",
            root / "ca" / "profile.json")


def subject_paths(root: Path, subject_id: str, identity_id: str) -> dict[str, Path]:
    safe_id(subject_id, "subject_id")
    safe_id(identity_id, "identity_id")
    base = root / "subjects" / subject_id / "identities" / identity_id
    pub = base / "provisioned"
    return {"base": base, "key": base / "private" / "identity.key.pem",
            "csr": base / "request.csr.pem", "cert": pub / "identity.cert.pem",
            "trust": pub / "lab-root.cert.pem", "receipt": pub / "receipt.json"}


def issued_paths(root: Path, identity_id: str) -> tuple[Path, Path]:
    safe_id(identity_id, "identity_id")
    return root / "issued" / f"{identity_id}.cert.pem", root / "issued" / f"{identity_id}.json"


def check_path_no_symlinks(root: Path, path: Path) -> None:
    """Refuse links in the lab-owned subtree. Not a hostile multi-user sandbox."""
    resolved_root = root.absolute()
    try:
        components = path.absolute().relative_to(resolved_root).parts
    except ValueError as exc:
        raise LabCAError("PATH_OUTSIDE_ROOT", "Refusing a path outside lab root") from exc
    cursor = resolved_root
    if cursor.is_symlink():
        raise LabCAError("SYMLINK_REJECTED", str(cursor))
    for part in components:
        cursor = cursor / part
        if cursor.is_symlink():
            raise LabCAError("SYMLINK_REJECTED", str(cursor))


def prepare(root: Path, path: Path) -> None:
    check_path_no_symlinks(root, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    check_path_no_symlinks(root, path)


def write_new(root: Path, path: Path, data: bytes, private: bool = False) -> None:
    prepare(root, path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(path, flags, 0o600 if private else 0o644)
    except FileExistsError as exc:
        raise LabCAError("ALREADY_EXISTS", f"Refusing to overwrite {path.name}") from exc
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if private and os.name != "nt":
            os.chmod(path, 0o600)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def replace_json(root: Path, path: Path, obj: dict[str, Any]) -> None:
    """Atomic replacement for non-secret simulator indexes (not generated keys)."""
    prepare(root, path)
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".writing-", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
            json.dump(obj, out, ensure_ascii=False, sort_keys=True, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        check_path_no_symlinks(root, path)
        os.replace(tmp, path)
    finally:
        if tmp is not None:
            Path(tmp).unlink(missing_ok=True)


def write_json_new(root: Path, path: Path, obj: dict[str, Any]) -> None:
    write_new(root, path, (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))


def read_bytes(root: Path, path: Path) -> bytes:
    check_path_no_symlinks(root, path)
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise LabCAError("NOT_FOUND", str(path)) from exc


def read_json(root: Path, path: Path) -> dict[str, Any]:
    try:
        data = json.loads(read_bytes(root, path))
        if not isinstance(data, dict):
            raise ValueError("object expected")
        return data
    except (ValueError, UnicodeError) as exc:
        raise LabCAError("INVALID_DATA", f"Invalid JSON in {path.name}") from exc


def private_serialization(key: ec.EllipticCurvePrivateKey, passphrase: bytes) -> bytes:
    if len(passphrase) < 12:
        raise LabCAError("WEAK_PASSPHRASE", "Use at least 12 bytes of UTF-8 passphrase")
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.BestAvailableEncryption(passphrase))


def load_private(root: Path, path: Path, passphrase: bytes) -> ec.EllipticCurvePrivateKey:
    """Fail-closed key unlock with actionable, non-secret-safe diagnostics.

    A failed PKCS#8 decrypt cannot reliably distinguish an incorrect passphrase
    from damaged encrypted bytes. Never report either hypothesis as proven.
    """
    try:
        data = read_bytes(root, path)
    except LabCAError as exc:
        if exc.code == "NOT_FOUND":
            raise LabCAError("PRIVATE_KEY_MISSING", "Expected encrypted private-key file is absent") from exc
        raise
    except OSError as exc:
        raise LabCAError("PRIVATE_KEY_READ_FAILED", "Unable to read encrypted private-key file") from exc
    if not data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") or b"-----END ENCRYPTED PRIVATE KEY-----" not in data:
        raise LabCAError("PRIVATE_KEY_FORMAT_INVALID", "Expected encrypted PKCS#8 PEM private key")
    try:
        key = serialization.load_pem_private_key(data, password=passphrase)
    except (TypeError, ValueError) as exc:
        raise LabCAError("PRIVATE_KEY_UNLOCK_FAILED",
                         "Passphrase mismatch or damaged encrypted private key; neither can be confirmed from this error") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise LabCAError("KEY_PROFILE_MISMATCH", "P-256 private key expected")
    return key


def check_subject_key(root: Path, subject_id: str, identity_id: str | None,
                     subject_passphrase: bytes) -> dict[str, Any]:
    """Read-only key unlock / CSR public-key binding check (not remote authentication)."""
    subject_id = safe_id(subject_id, "subject_id")
    identity_id = safe_id(identity_id or subject_id, "identity_id")
    root = Path(root).absolute()
    paths = subject_paths(root, subject_id, identity_id)
    key = load_private(root, paths["key"], subject_passphrase)
    try:
        csr = x509.load_pem_x509_csr(read_bytes(root, paths["csr"]))
    except ValueError as exc:
        raise LabCAError("CSR_FORMAT_INVALID", "Cannot read the subject CSR") from exc
    if not csr.is_signature_valid:
        raise LabCAError("CSR_INVALID_SIGNATURE", "Subject CSR signature is invalid")
    p256(csr.public_key())
    if key.public_key().public_numbers() != csr.public_key().public_numbers():
        raise LabCAError("KEY_CSR_MISMATCH", "Subject private key does not match its CSR")
    return {"schema": SCHEMA, "status": "KEY_ACCESS_CONFIRMED_LAB", "usage": "TEST_ONLY",
            "subject_id": subject_id, "identity_id": identity_id,
            "encrypted_key_unlocked": True, "csr_public_key_matches": True,
            "certificate_validation_performed": False, "standard_profile_conformant": False}


def p256(public_key: Any) -> None:
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise LabCAError("KEY_PROFILE_MISMATCH", "P-256 public key expected")


def verify_signature(public_key: Any, signature: bytes, payload: bytes, algo: hashes.HashAlgorithm | None) -> None:
    p256(public_key)
    if not isinstance(algo, hashes.SHA256):
        raise LabCAError("SIGNATURE_PROFILE_MISMATCH", "ECDSA/SHA-256 required")
    try:
        public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise LabCAError("CERT_INVALID_SIGNATURE", "ECDSA signature verification failed") from exc


def load_cert(root: Path, path: Path) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(read_bytes(root, path))
    except ValueError as exc:
        raise LabCAError("INVALID_CERTIFICATE", str(path.name)) from exc


def check_not_before_after(cert: x509.Certificate, at: dt.datetime) -> None:
    if at < cert.not_valid_before_utc:
        raise LabCAError("CERT_NOT_YET_VALID", "Validation time precedes notBefore")
    if at > cert.not_valid_after_utc:
        raise LabCAError("CERT_EXPIRED", "Validation time exceeds notAfter")


def init_ca(root: Path, passphrase: bytes, name: str = "Local X509 Test Root CA", days: int = 3650,
            now: dt.datetime | None = None) -> dict[str, Any]:
    if not 1 <= days <= 3650:
        raise LabCAError("INVALID_VALIDITY", "CA days must be 1..3650")
    if not name or len(name) > 100:
        raise LabCAError("INVALID_NAME", "CA name must be 1..100 characters")
    root = Path(root).absolute()
    key_file, cert_file, profile_file = ca_paths(root)
    # Require an entirely new CA; never silently regenerate trust anchor.
    if any(p.exists() or p.is_symlink() for p in (key_file, cert_file, profile_file)):
        raise LabCAError("ALREADY_EXISTS", "CA already initialized or partially initialized")
    now = now or current_time()
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, LAB_ORG),
                         x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    pem = private_serialization(key, passphrase)
    write_new(root, key_file, pem, private=True)
    write_new(root, cert_file, cert.public_bytes(serialization.Encoding.PEM))
    write_json_new(root, profile_file, {"schema": SCHEMA, "profile": LAB_PROFILE, "usage": "TEST_ONLY",
                                        "ca_fingerprint_sha256": cert_fp(cert),
                                        "generated_at": iso(now), "expires_at": iso(cert.not_valid_after_utc)})
    return {"ca_cert": str(cert_file), "ca_fingerprint_sha256": cert_fp(cert),
            "expires_at": iso(cert.not_valid_after_utc), "usage": "TEST_ONLY"}


def trusted_ca(root: Path, at: dt.datetime | None = None) -> x509.Certificate:
    _, cert_file, profile_file = ca_paths(root)
    cert = load_cert(root, cert_file)
    profile = read_json(root, profile_file)
    if profile.get("profile") != LAB_PROFILE or profile.get("usage") != "TEST_ONLY" or profile.get("ca_fingerprint_sha256") != cert_fp(cert):
        raise LabCAError("UNTRUSTED_ISSUER", "CA fingerprint does not match pinned lab profile")
    if cert.subject != cert.issuer:
        raise LabCAError("UNTRUSTED_ISSUER", "Root CA is not self-issued")
    try:
        bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        ku_ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
        bc, ku = bc_ext.value, ku_ext.value
        if not bc_ext.critical or not ku_ext.critical:
            raise LabCAError("CA_POLICY_MISMATCH", "CA constraint extensions must be critical")
        if not bc.ca or bc.path_length != 0 or not ku.key_cert_sign:
            raise LabCAError("CA_POLICY_MISMATCH", "CA constraints invalid")
    except x509.ExtensionNotFound as exc:
        raise LabCAError("CA_POLICY_MISMATCH", "CA extensions missing") from exc
    verify_signature(cert.public_key(), cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
    if at is not None:
        check_not_before_after(cert, at)
    return cert


def new_subject(root: Path, subject_id: str, identity_id: str | None, passphrase: bytes,
               now: dt.datetime | None = None) -> dict[str, Any]:
    subject_id = safe_id(subject_id, "subject_id")
    identity_id = safe_id(identity_id or subject_id, "identity_id")
    root = Path(root).absolute()
    paths = subject_paths(root, subject_id, identity_id)
    if paths["key"].exists() or paths["csr"].exists() or paths["key"].is_symlink():
        raise LabCAError("ALREADY_EXISTS", "Subject identity already created")
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(subject_for(identity_id))
           .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(lab_uri(subject_id, identity_id))]), critical=False)
           .sign(key, hashes.SHA256()))
    pem = private_serialization(key, passphrase)
    write_new(root, paths["key"], pem, private=True)
    write_new(root, paths["csr"], csr.public_bytes(serialization.Encoding.PEM))
    return {"subject_id": subject_id, "identity_id": identity_id, "csr_file": str(paths["csr"]),
            "key_file": str(paths["key"]), "key_exported_to_ca": False, "usage": "TEST_ONLY"}


def load_valid_csr(root: Path, csr_path: Path, subject_id: str, identity_id: str) -> x509.CertificateSigningRequest:
    try:
        csr = x509.load_pem_x509_csr(read_bytes(root, csr_path))
    except ValueError as exc:
        raise LabCAError("INVALID_CSR", "Cannot parse CSR") from exc
    if csr.subject != subject_for(identity_id):
        raise LabCAError("CSR_IDENTITY_MISMATCH", "CSR Subject is not the requested lab identity")
    p256(csr.public_key())
    if not isinstance(csr.signature_hash_algorithm, hashes.SHA256) or not csr.is_signature_valid:
        raise LabCAError("CSR_INVALID_SIGNATURE", "Invalid CSR proof of possession")
    if {ext.oid for ext in csr.extensions} != ALLOWED_CSR_EXTENSIONS:
        raise LabCAError("CSR_POLICY_MISMATCH", "Unexpected CSR extension")
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound as exc:
        raise LabCAError("CSR_POLICY_MISMATCH", "Missing subject identity SAN URI") from exc
    if names != [lab_uri(subject_id, identity_id)]:
        raise LabCAError("CSR_IDENTITY_MISMATCH", "CSR SAN does not match requested identity")
    return csr


def issue_cert(root: Path, subject_id: str, identity_id: str | None, ca_passphrase: bytes,
               days: int = 365, now: dt.datetime | None = None) -> dict[str, Any]:
    if not 1 <= days <= 365:
        raise LabCAError("INVALID_VALIDITY", "Subject days must be 1..365")
    subject_id = safe_id(subject_id, "subject_id")
    identity_id = safe_id(identity_id or subject_id, "identity_id")
    root = Path(root).absolute()
    issued_cert_path, issued_receipt_path = issued_paths(root, identity_id)
    if issued_cert_path.exists() or issued_receipt_path.exists():
        raise LabCAError("ALREADY_EXISTS", "Certificate already issued for identity; create new identity to rotate")
    now = now or current_time()
    ca_key_path, _, _ = ca_paths(root)
    ca = trusted_ca(root, now)
    ca_key = load_private(root, ca_key_path, ca_passphrase)
    if ca_key.public_key().public_numbers() != ca.public_key().public_numbers():
        raise LabCAError("CA_KEY_MISMATCH", "CA key does not match pinned certificate")
    paths = subject_paths(root, subject_id, identity_id)
    csr = load_valid_csr(root, paths["csr"], subject_id, identity_id)
    not_after = min(now + dt.timedelta(days=days), ca.not_valid_after_utc)
    if not_after <= now:
        raise LabCAError("CA_EXPIRED", "CA expires before subject certificate can be issued")
    cert = (x509.CertificateBuilder()
            .subject_name(csr.subject).issuer_name(ca.subject)
            .public_key(csr.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    write_new(root, issued_cert_path, cert.public_bytes(serialization.Encoding.PEM))
    receipt = {"schema": SCHEMA, "usage": "TEST_ONLY", "subject_id": subject_id,
               "identity_id": identity_id, "serial_hex": format(cert.serial_number, "x"),
               "certificate_fingerprint_sha256": cert_fp(cert), "ca_fingerprint_sha256": cert_fp(ca),
               "issued_at": iso(now), "expires_at": iso(cert.not_valid_after_utc)}
    write_json_new(root, issued_receipt_path, receipt)
    return {**receipt, "certificate_path": str(issued_cert_path)}


def validate_leaf(cert: x509.Certificate, ca: x509.Certificate, subject_id: str, identity_id: str,
                  at: dt.datetime) -> None:
    check_not_before_after(ca, at)
    check_not_before_after(cert, at)
    if cert.version != x509.Version.v3 or cert.issuer != ca.subject:
        raise LabCAError("UNTRUSTED_ISSUER", "Issuer or X.509 version is invalid")
    if cert.subject != subject_for(identity_id):
        raise LabCAError("CERT_POLICY_MISMATCH", "Leaf Subject is not the lab identity")
    if {ext.oid for ext in cert.extensions} != ALLOWED_LEAF_EXTENSIONS:
        raise LabCAError("CERT_POLICY_MISMATCH", "Unexpected/missing extensions in lab leaf")
    p256(cert.public_key())
    try:
        bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        ku_ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
        eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        aki_ext = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        ski_ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        bc, usage, eku, san, aki, ski = (bc_ext.value, ku_ext.value, eku_ext.value,
                                        san_ext.value, aki_ext.value, ski_ext.value)
        if not bc_ext.critical or not ku_ext.critical or any(
            x.critical for x in (eku_ext, san_ext, aki_ext, ski_ext)
        ):
            raise LabCAError("CERT_POLICY_MISMATCH", "Lab critical extension flags invalid")
    except x509.ExtensionNotFound as exc:
        raise LabCAError("CERT_POLICY_MISMATCH", "Required lab profile extension is missing") from exc
    if bc.ca or not usage.digital_signature or usage.key_cert_sign or usage.crl_sign or usage.key_agreement:
        raise LabCAError("CERT_POLICY_MISMATCH", "Leaf key usage/CA constraint invalid")
    if set(eku) != {ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH}:
        raise LabCAError("CERT_POLICY_MISMATCH", "Lab EKU mismatch")
    if san.get_values_for_type(x509.UniformResourceIdentifier) != [lab_uri(subject_id, identity_id)]:
        raise LabCAError("CERT_POLICY_MISMATCH", "Lab subject SAN mismatch")
    if aki.key_identifier != x509.SubjectKeyIdentifier.from_public_key(ca.public_key()).digest or ski.digest != x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest:
        raise LabCAError("CERT_POLICY_MISMATCH", "SKI/AKI mismatch")
    verify_signature(ca.public_key(), cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)


def prove_key_ownership(key: ec.EllipticCurvePrivateKey, cert: x509.Certificate) -> None:
    challenge = b"X509LAB_POSSESSION_V1:" + secrets.token_bytes(32)
    signature = key.sign(challenge, ec.ECDSA(hashes.SHA256()))
    try:
        cert.public_key().verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise LabCAError("KEY_CERT_MISMATCH", "Private key cannot sign for this certificate") from exc


def read_revocations(root: Path) -> dict[str, Any]:
    path = root / "ca" / "revocations.json"
    if not path.exists():
        return {"schema": SCHEMA, "usage": "TEST_ONLY", "revoked": {}}
    data = read_json(root, path)
    if data.get("schema") != SCHEMA or not isinstance(data.get("revoked"), dict):
        raise LabCAError("INVALID_REVOCATION_INDEX", "Bad local revocation index")
    return data


def check_not_revoked(root: Path, cert: x509.Certificate) -> None:
    if cert_fp(cert) in read_revocations(root)["revoked"]:
        raise LabCAError("CERT_REVOKED_LAB", "Certificate denied by local lab revocation index (not CRL/OCSP)")


def provision(root: Path, subject_id: str, identity_id: str | None, subject_passphrase: bytes,
              now: dt.datetime | None = None) -> dict[str, Any]:
    subject_id = safe_id(subject_id, "subject_id")
    identity_id = safe_id(identity_id or subject_id, "identity_id")
    root = Path(root).absolute()
    paths = subject_paths(root, subject_id, identity_id)
    if any(paths[name].exists() for name in ("cert", "trust", "receipt")):
        raise LabCAError("ALREADY_EXISTS", "Already provisioned or partial write; do not silently repair")
    now = now or current_time()
    ca = trusted_ca(root, now)
    cert_path, issuance_file = issued_paths(root, identity_id)
    cert = load_cert(root, cert_path)
    issued = read_json(root, issuance_file)
    if issued.get("subject_id") != subject_id or issued.get("identity_id") != identity_id or issued.get("certificate_fingerprint_sha256") != cert_fp(cert):
        raise LabCAError("ISSUANCE_MISMATCH", "Issued certificate/metadata mismatch")
    validate_leaf(cert, ca, subject_id, identity_id, now)
    check_not_revoked(root, cert)
    key = load_private(root, paths["key"], subject_passphrase)
    prove_key_ownership(key, cert)
    # Secret-bearing key never leaves the source subject's private directory.
    write_new(root, paths["cert"], read_bytes(root, cert_path))
    write_new(root, paths["trust"], ca.public_bytes(serialization.Encoding.PEM))
    receipt = {"schema": SCHEMA, "usage": "TEST_ONLY", "status": "PROVISIONED_LAB",
               "subject_id": subject_id, "identity_id": identity_id,
               "certificate_fingerprint_sha256": cert_fp(cert),
               "trust_anchor_fingerprint_sha256": cert_fp(ca),
               "provisioned_at": iso(now), "key_handle": f"lab-keystore://subject/{subject_id}/identity/{identity_id}",
               "secret_material_in_receipt": False}
    # Receipt last is the simulated commit marker.
    write_json_new(root, paths["receipt"], receipt)
    return receipt


def verify_provisioned(root: Path, subject_id: str, identity_id: str | None,
                       subject_passphrase: bytes | None, now: dt.datetime | None = None,
                       require_pop: bool = True, time_trusted: bool = True) -> dict[str, Any]:
    if not time_trusted:
        raise LabCAError("TIME_UNTRUSTED", "No trusted validation time; fail closed")
    subject_id = safe_id(subject_id, "subject_id")
    identity_id = safe_id(identity_id or subject_id, "identity_id")
    if require_pop and subject_passphrase is None:
        raise LabCAError("SUBJECT_PASSPHRASE_REQUIRED", "PoP verification requires subject passphrase")
    root = Path(root).absolute()
    paths = subject_paths(root, subject_id, identity_id)
    now = now or current_time()
    receipt = read_json(root, paths["receipt"])
    if any((receipt.get("status") != "PROVISIONED_LAB", receipt.get("usage") != "TEST_ONLY",
            receipt.get("subject_id") != subject_id, receipt.get("identity_id") != identity_id)):
        raise LabCAError("PROVISION_INCOMPLETE", "Missing or mismatched provisioning receipt")
    ca = trusted_ca(root, now)
    installed_ca = load_cert(root, paths["trust"])
    if cert_fp(installed_ca) != cert_fp(ca) or receipt.get("trust_anchor_fingerprint_sha256") != cert_fp(ca):
        raise LabCAError("UNTRUSTED_ISSUER", "Subject trust anchor differs from pinned factory CA")
    cert = load_cert(root, paths["cert"])
    if cert_fp(cert) != receipt.get("certificate_fingerprint_sha256"):
        raise LabCAError("PROVISION_INCOMPLETE", "Certificate differs from committed receipt")
    validate_leaf(cert, ca, subject_id, identity_id, now)
    check_not_revoked(root, cert)
    if require_pop:
        key = load_private(root, paths["key"], subject_passphrase or b"")
        prove_key_ownership(key, cert)
    return {"schema": SCHEMA, "status": "VALID_LAB", "usage": "TEST_ONLY", "subject_id": subject_id,
            "identity_id": identity_id, "certificate_fingerprint_sha256": cert_fp(cert),
            "ca_fingerprint_sha256": cert_fp(ca), "validated_at": iso(now),
            "proof_of_possession": require_pop, "standard_profile_conformant": False}


def revoke_identity(root: Path, subject_id: str, identity_id: str | None,
                    reason: str = "lab-simulated-revocation") -> dict[str, Any]:
    if reason not in {"lab-simulated-revocation", "key-compromise", "superseded", "ca-compromise"}:
        raise LabCAError("INVALID_REASON", "Unsupported lab revocation reason")
    subject_id = safe_id(subject_id, "subject_id")
    identity_id = safe_id(identity_id or subject_id, "identity_id")
    root = Path(root).absolute()
    cert = load_cert(root, issued_paths(root, identity_id)[0])
    issuance = read_json(root, issued_paths(root, identity_id)[1])
    if issuance.get("subject_id") != subject_id or issuance.get("certificate_fingerprint_sha256") != cert_fp(cert):
        raise LabCAError("ISSUANCE_MISMATCH", "Cannot revoke ambiguous identity")
    revocations = read_revocations(root)
    if cert_fp(cert) in revocations["revoked"]:
        raise LabCAError("ALREADY_REVOKED", "Certificate is already in local denylist")
    revocations["revoked"][cert_fp(cert)] = {"identity_id": identity_id, "subject_id": subject_id,
                                                 "reason": reason, "revoked_at": iso(current_time())}
    replace_json(root, root / "ca" / "revocations.json", revocations)
    return {"schema": SCHEMA, "status": "REVOKED_LAB", "identity_id": identity_id,
            "subject_id": subject_id, "certificate_fingerprint_sha256": cert_fp(cert), "usage": "TEST_ONLY"}




DEMO_IDENTITIES = ("client-alpha", "server-beta", "service-gamma")

def demo(root: Path, ca_passphrase: bytes, subject_passphrase: bytes) -> dict[str, Any]:
    """Create three example identities using genuine X.509 operations."""
    root = Path(root).absolute()
    if (root / "demo_manifest.json").exists():
        raise LabCAError("ALREADY_EXISTS", "A demo already exists at this root")
    result = init_ca(root, ca_passphrase)
    for subject in DEMO_IDENTITIES:
        new_subject(root, subject, None, subject_passphrase)
        issue_cert(root, subject, None, ca_passphrase)
        provision(root, subject, None, subject_passphrase)
    write_json_new(root, root / "demo_manifest.json",
                   {"schema": SCHEMA, "usage": "TEST_ONLY",
                    "subjects": list(DEMO_IDENTITIES),
                    "ca_fingerprint_sha256": result["ca_fingerprint_sha256"]})
    return {"schema": SCHEMA, "usage": "TEST_ONLY", "status": "PROVISIONED_LAB",
            "subject_count": len(DEMO_IDENTITIES), "issued_certificates": len(DEMO_IDENTITIES)}

def verify_demo(root: Path, subject_passphrase: bytes,
                now: dt.datetime | None = None, time_trusted: bool = True) -> dict[str, Any]:
    """Run a fail-closed check across every subject in the demo manifest."""
    root = Path(root).absolute()
    manifest = read_json(root, root / "demo_manifest.json")
    if manifest.get("schema") != SCHEMA or manifest.get("subjects") != list(DEMO_IDENTITIES):
        raise LabCAError("INVALID_DEMO_MANIFEST", "Unexpected demo manifest")
    checks = []
    for subject in DEMO_IDENTITIES:
        try:
            verify_provisioned(root, subject, None, subject_passphrase, now=now, time_trusted=time_trusted)
            checks.append({"subject_id": subject, "status": "VALID_LAB"})
        except LabCAError as exc:
            checks.append({"subject_id": subject, "status": "REJECTED_LAB", "reason_code": exc.code})
    return {"schema": SCHEMA, "usage": "TEST_ONLY",
            "status": "PASS" if all(x["status"] == "VALID_LAB" for x in checks) else "FAIL",
            "checks": checks}
