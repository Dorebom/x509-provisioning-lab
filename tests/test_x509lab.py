"""Regression and negative tests using temporary, local-only credentials."""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from x509_provisioning_lab.cli import artifacts_directory, resolve_lab_root, secret
from x509_provisioning_lab.core import (
    LabCAError, ca_paths, cert_fp, check_subject_key, current_time,
    demo, init_ca, issue_cert, issued_paths, load_cert, new_subject,
    parse_at, provision, read_json, revoke_identity, subject_paths,
    trusted_ca, validate_leaf, verify_demo, verify_provisioned,
)

CA_PASSWORD = b"temporary-testing-ca-passphrase-123"
SUBJECT_PASSWORD = b"temporary-testing-subject-passphrase-123"


class CertificateWorkflowTests(unittest.TestCase):
    def setUp(self):
        artifacts_directory().mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=artifacts_directory(), prefix="public-x509-tests-")
        self.root = Path(self.tmp.name)
        self.now = current_time()

    def tearDown(self):
        self.tmp.cleanup()

    def error(self, expected: str, fn, *a, **kw):
        with self.assertRaises(LabCAError) as cm:
            fn(*a, **kw)
        self.assertEqual(cm.exception.code, expected)

    def create(self, name="client-alpha"):
        init_ca(self.root, CA_PASSWORD)
        new_subject(self.root, name, None, SUBJECT_PASSWORD)
        issue_cert(self.root, name, None, CA_PASSWORD)
        provision(self.root, name, None, SUBJECT_PASSWORD)

    def test_01_ca_key_encrypted_and_constraints(self):
        init_ca(self.root, CA_PASSWORD)
        key, cert, profile = ca_paths(self.root)
        self.assertIn(b"BEGIN ENCRYPTED PRIVATE KEY", key.read_bytes())
        self.assertNotIn(CA_PASSWORD, key.read_bytes())
        ca = load_cert(self.root, cert)
        self.assertEqual(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length, 0)
        self.assertTrue(ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign)
        self.assertEqual(read_json(self.root, profile)["profile"], "X509LAB-P256-DEMO-v1")

    def test_02_subject_creates_encrypted_key_and_valid_csr(self):
        init_ca(self.root, CA_PASSWORD)
        new_subject(self.root, "client-alpha", None, SUBJECT_PASSWORD)
        paths = subject_paths(self.root, "client-alpha", "client-alpha")
        self.assertIn(b"BEGIN ENCRYPTED PRIVATE KEY", paths["key"].read_bytes())
        self.assertIn(b"BEGIN CERTIFICATE REQUEST", paths["csr"].read_bytes())
        self.assertTrue(x509.load_pem_x509_csr(paths["csr"].read_bytes()).is_signature_valid)
        self.assertNotIn(b"PRIVATE KEY", paths["csr"].read_bytes())

    def test_03_full_issue_provision_and_verify(self):
        self.create()
        report = verify_provisioned(self.root, "client-alpha", None, SUBJECT_PASSWORD)
        self.assertEqual(report["status"], "VALID_LAB")
        self.assertTrue(report["proof_of_possession"])
        self.assertFalse(report["standard_profile_conformant"])

    def test_04_check_key_matches_csr(self):
        self.create()
        r = check_subject_key(self.root, "client-alpha", None, SUBJECT_PASSWORD)
        self.assertTrue(r["encrypted_key_unlocked"])
        self.assertTrue(r["csr_public_key_matches"])

    def test_05_wrong_key_password_rejected(self):
        self.create()
        self.error("PRIVATE_KEY_UNLOCK_FAILED", check_subject_key, self.root, "client-alpha", None, b"wrong password")

    def test_06_wrong_issuer_password_rejected(self):
        init_ca(self.root, CA_PASSWORD)
        new_subject(self.root, "client-alpha", None, SUBJECT_PASSWORD)
        self.error("PRIVATE_KEY_UNLOCK_FAILED", issue_cert, self.root, "client-alpha", None, b"incorrect-password")

    def test_07_weak_password_rejected_before_file_created(self):
        init_ca(self.root, CA_PASSWORD)
        self.error("WEAK_PASSPHRASE", new_subject, self.root, "client-alpha", None, b"short")
        self.assertFalse(subject_paths(self.root, "client-alpha", "client-alpha")["key"].exists())

    def test_08_duplicate_ca_and_cert_no_overwrite(self):
        self.create()
        cert = issued_paths(self.root, "client-alpha")[0]
        original = cert.read_bytes()
        self.error("ALREADY_EXISTS", init_ca, self.root, CA_PASSWORD)
        self.error("ALREADY_EXISTS", issue_cert, self.root, "client-alpha", None, CA_PASSWORD)
        self.assertEqual(cert.read_bytes(), original)

    def test_09_invalid_subject_id_no_traversal(self):
        init_ca(self.root, CA_PASSWORD)
        self.error("INVALID_ID", new_subject, self.root, "../escape", None, SUBJECT_PASSWORD)
        self.assertFalse((self.root / "escape").exists())

    def test_10_expired_leaf_rejected(self):
        self.create()
        self.error("CERT_EXPIRED", verify_provisioned, self.root, "client-alpha", None, SUBJECT_PASSWORD,
                   now=self.now + dt.timedelta(days=370))

    def test_11_not_yet_valid_leaf_rejected(self):
        init_ca(self.root, CA_PASSWORD, now=self.now)
        new_subject(self.root, "client-alpha", None, SUBJECT_PASSWORD)
        future = self.now + dt.timedelta(days=5)
        issue_cert(self.root, "client-alpha", None, CA_PASSWORD, now=future)
        provision(self.root, "client-alpha", None, SUBJECT_PASSWORD, now=future)
        self.error("CERT_NOT_YET_VALID", verify_provisioned, self.root, "client-alpha", None, SUBJECT_PASSWORD,
                   now=self.now)

    def test_12_key_certificate_mismatch_rejected(self):
        self.create()
        new_subject(self.root, "service-beta", None, SUBJECT_PASSWORD)
        orig = subject_paths(self.root, "client-alpha", "client-alpha")["key"]
        orig.write_bytes(subject_paths(self.root, "service-beta", "service-beta")["key"].read_bytes())
        self.error("KEY_CERT_MISMATCH", verify_provisioned, self.root, "client-alpha", None, SUBJECT_PASSWORD)

    def test_13_corrupt_key_rejected(self):
        self.create()
        subject_paths(self.root, "client-alpha", "client-alpha")["key"].write_text("bad key")
        self.error("PRIVATE_KEY_FORMAT_INVALID", check_subject_key, self.root, "client-alpha", None, SUBJECT_PASSWORD)

    def test_14_missing_key_rejected(self):
        self.create()
        subject_paths(self.root, "client-alpha", "client-alpha")["key"].unlink()
        self.error("PRIVATE_KEY_MISSING", check_subject_key, self.root, "client-alpha", None, SUBJECT_PASSWORD)

    def test_15_wrong_root_installed_rejected(self):
        self.create()
        with tempfile.TemporaryDirectory(dir=artifacts_directory()) as other:
            other_root = Path(other)
            init_ca(other_root, CA_PASSWORD)
            subject_paths(self.root, "client-alpha", "client-alpha")["trust"].write_bytes(ca_paths(other_root)[1].read_bytes())
            self.error("UNTRUSTED_ISSUER", verify_provisioned, self.root, "client-alpha", None, SUBJECT_PASSWORD)

    def test_16_forged_leaf_signature_rejected(self):
        self.create()
        ca = trusted_ca(self.root)
        leaf = load_cert(self.root, subject_paths(self.root, "client-alpha", "client-alpha")["cert"])
        fake = ec.generate_private_key(ec.SECP256R1())
        cb = (x509.CertificateBuilder().subject_name(leaf.subject).issuer_name(ca.subject)
              .public_key(leaf.public_key()).serial_number(leaf.serial_number)
              .not_valid_before(leaf.not_valid_before_utc).not_valid_after(leaf.not_valid_after_utc))
        for ext in leaf.extensions:
            cb = cb.add_extension(ext.value, critical=ext.critical)
        forged = cb.sign(fake, hashes.SHA256())
        self.error("CERT_INVALID_SIGNATURE", validate_leaf, forged, ca, "client-alpha", "client-alpha", self.now)

    def test_17_csr_subject_switch_rejected(self):
        init_ca(self.root, CA_PASSWORD)
        new_subject(self.root, "client-alpha", None, SUBJECT_PASSWORD)
        new_subject(self.root, "server-beta", None, SUBJECT_PASSWORD)
        paths = subject_paths(self.root, "client-alpha", "client-alpha")
        paths["csr"].write_bytes(subject_paths(self.root, "server-beta", "server-beta")["csr"].read_bytes())
        self.error("CSR_IDENTITY_MISMATCH", issue_cert, self.root, "client-alpha", None, CA_PASSWORD)

    def test_18_revocation_denies_target_but_not_other(self):
        demo(self.root, CA_PASSWORD, SUBJECT_PASSWORD)
        revoke_identity(self.root, "client-alpha", None)
        self.error("CERT_REVOKED_LAB", verify_provisioned, self.root, "client-alpha", None, SUBJECT_PASSWORD)
        self.assertEqual(verify_provisioned(self.root, "server-beta", None, SUBJECT_PASSWORD)["status"], "VALID_LAB")
        self.assertEqual(verify_demo(self.root, SUBJECT_PASSWORD)["status"], "FAIL")

    def test_19_duplicate_revocation_denied(self):
        self.create()
        revoke_identity(self.root, "client-alpha", None)
        self.error("ALREADY_REVOKED", revoke_identity, self.root, "client-alpha", None)

    def test_20_partial_provisioning_rejected(self):
        init_ca(self.root, CA_PASSWORD)
        new_subject(self.root, "client-alpha", None, SUBJECT_PASSWORD)
        issue_cert(self.root, "client-alpha", None, CA_PASSWORD)
        self.error("NOT_FOUND", verify_provisioned, self.root, "client-alpha", None, SUBJECT_PASSWORD)

    def test_21_untrusted_clock_rejected(self):
        self.create()
        self.error("TIME_UNTRUSTED", verify_provisioned, self.root, "client-alpha", None, SUBJECT_PASSWORD, time_trusted=False)

    def test_22_parse_timestamp_requires_offset(self):
        self.error("INVALID_TIME", parse_at, "2026-11-07T12:30:00")
        self.assertIsNotNone(parse_at("2026-11-07T12:30:00+09:00").tzinfo)

    def test_23_demo_three_unique_public_keys(self):
        report = demo(self.root, CA_PASSWORD, SUBJECT_PASSWORD)
        self.assertEqual(report["issued_certificates"], 3)
        keys = []
        for name in ("client-alpha", "server-beta", "service-gamma"):
            cert = load_cert(self.root, issued_paths(self.root, name)[0])
            keys.append(cert.public_key().public_numbers())
        self.assertEqual(len(set(keys)), 3)
        self.assertEqual(verify_demo(self.root, SUBJECT_PASSWORD)["status"], "PASS")

    def test_24_public_receipts_no_private_material(self):
        self.create()
        paths = subject_paths(self.root, "client-alpha", "client-alpha")
        receipt = paths["receipt"].read_bytes()
        self.assertNotIn(b"BEGIN", receipt)
        self.assertNotIn(CA_PASSWORD, receipt)
        self.assertNotIn(SUBJECT_PASSWORD, receipt)
        self.assertFalse((self.root / "issued" / "private").exists())

    def test_25_symlink_key_rejected(self):
        self.create()
        dest = subject_paths(self.root, "client-alpha", "client-alpha")["key"]
        original = dest.read_bytes()
        dest.unlink()
        alternative = self.root / "key-alternative.bin"
        alternative.write_bytes(original)
        try:
            dest.symlink_to(alternative)
        except (NotImplementedError, OSError):
            self.skipTest("Symlink creation not permitted on this system")
        self.error("SYMLINK_REJECTED", check_subject_key, self.root, "client-alpha", None, SUBJECT_PASSWORD)

    def test_26_reject_outside_root_and_path_traversal(self):
        self.error("ROOT_OUTSIDE_ARTIFACTS", resolve_lab_root, artifacts_directory().parent / "unsafe")
        self.error("ROOT_PATH_TRAVERSAL", resolve_lab_root, Path("../unsafe"))

    def test_27_default_root_is_inside_artifacts(self):
        self.assertEqual(resolve_lab_root(None), artifacts_directory().resolve() / "default")

    def test_28_cli_demo_and_negative_verify_exit_codes(self):
        root_name = self.root.name
        env = os.environ.copy()
        env["X509LAB_CA_PASSPHRASE"] = CA_PASSWORD.decode()
        env["X509LAB_SUBJECT_PASSPHRASE"] = SUBJECT_PASSWORD.decode()
        def run(*a):
            return subprocess.run([sys.executable, "-m", "x509_provisioning_lab", *a, "--root", root_name],
                                  env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        r = run("demo")
        self.assertEqual(r.returncode, 0, r.stdout+r.stderr)
        ok = run("verify-demo")
        self.assertEqual(ok.returncode, 0, ok.stdout+ok.stderr)
        revoked = run("revoke", "--subject-id", "client-alpha")
        self.assertEqual(revoked.returncode, 0, revoked.stdout+revoked.stderr)
        bad = run("verify-demo")
        self.assertEqual(bad.returncode, 2, bad.stdout+bad.stderr)
        self.assertEqual(json.loads(bad.stdout)["status"], "FAIL")

    def test_29_cli_wrong_passphrase_fails_closed(self):
        self.create()
        env = os.environ.copy()
        env["X509LAB_SUBJECT_PASSPHRASE"] = "wrong-test-passphrase"
        p = subprocess.run([sys.executable, "-m", "x509_provisioning_lab", "verify", "--root", self.root.name,
                            "--subject-id", "client-alpha"], env=env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(json.loads(p.stdout)["reason_code"], "PRIVATE_KEY_UNLOCK_FAILED")
        self.assertNotIn("wrong-test-passphrase", p.stdout)

    def test_30_no_secret_bytes_in_cli_json(self):
        self.create()
        result = verify_provisioned(self.root, "client-alpha", None, SUBJECT_PASSWORD)
        data = json.dumps(result)
        self.assertNotIn(CA_PASSWORD.decode(), data)
        self.assertNotIn(SUBJECT_PASSWORD.decode(), data)

    def test_31_subject_identity_aliases_supported(self):
        init_ca(self.root, CA_PASSWORD)
        new_subject(self.root, "client-alpha", "client-rotated", SUBJECT_PASSWORD)
        issue_cert(self.root, "client-alpha", "client-rotated", CA_PASSWORD)
        provision(self.root, "client-alpha", "client-rotated", SUBJECT_PASSWORD)
        self.assertEqual(verify_provisioned(self.root, "client-alpha", "client-rotated", SUBJECT_PASSWORD)["status"], "VALID_LAB")

    def test_32_cli_outside_path_does_not_prompt(self):
        p = subprocess.run([sys.executable, "-m", "x509_provisioning_lab", "demo", "--root", str(self.root.parent.parent / "outside")],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(json.loads(p.stdout)["reason_code"], "ROOT_OUTSIDE_ARTIFACTS")


if __name__ == "__main__":
    unittest.main()
