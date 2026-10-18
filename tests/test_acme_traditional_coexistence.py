"""Tests for the traditional protocol and ACME independently managing the
same fqdns (previously mutually exclusive - see the "Status" note on
TECHNICAL_REFERENCE.md's "exactly one interface at a time" claim and
ACME_SERVER_DESIGN.md's coexistence section for the full rationale).

Two directions, each exercised against the real code path, nothing mocked
except the one acme.sh-invoking boundary (_attempt_issue_or_renew) in the
second test, to avoid an actual subprocess call:

1. An ACME order for an fqdns the traditional protocol already manages must
   succeed, and must never disturb the traditional protocol's own stored
   certificate/key (common/acme_server_utils.py's handle_new_order() no
   longer rejects this; crtrequest.py's
   update_database_with_certificate_from_csr() skips overwriting the shared
   Certificate row when it's already traditional-protocol-owned).

2. The traditional protocol's own issuance loop must no longer skip an
   fqdns just because a live ACME order also exists for it
   (crtrequest.py's two is_acme_managed()-gated call sites are now
   informational logging only, not a skip).

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import base64
import datetime
import http.client
import json
import os
import secrets
import shutil
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

import josepy as jose
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from sslcrtsrv import crtrequest
from sslcrtsrv.common import database
from sslcrtsrv.common.acme_server_utils import AcmeRequestHandler, build_routes


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _make_self_signed_cert_pem(common_name, days=90):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _write_cert_dir(cert_pem):
    cert_dir = tempfile.mkdtemp(prefix="acme-coexistence-test-")
    with open(os.path.join(cert_dir, "ssl.cer"), "w") as f:
        f.write(cert_pem)
    with open(os.path.join(cert_dir, "intermed.cer"), "w") as f:
        f.write("")
    return cert_dir


class AcmeCoexistenceTestCase(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="acme-coexistence-db-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()
        self._cert_dirs = []

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)
        for cert_dir in self._cert_dirs:
            shutil.rmtree(cert_dir, ignore_errors=True)

    def _cert_dir(self, cert_pem):
        cert_dir = _write_cert_dir(cert_pem)
        self._cert_dirs.append(cert_dir)
        return cert_dir


class TestAcmeIndependentOfTraditional(AcmeCoexistenceTestCase):
    def test_acme_issuance_does_not_disturb_the_traditional_certificate(self):
        fqdns = f"coexist-{secrets.token_hex(4)}.test"

        # Simulate an existing, traditional-protocol-managed certificate -
        # a real private key stored server-side, exactly as crtrequest.py's
        # own (non-CSR) issuance path would leave it.
        database.create_certificate_entry(fqdns)
        traditional_validity = _utcnow() + datetime.timedelta(days=60)
        database.update_certificate(
            fqdns=fqdns, public_key="TRADITIONAL-CERT-PEM", private_key="TRADITIONAL-KEY-PEM",
            intermediates="TRADITIONAL-CHAIN-PEM", validity_end_date=traditional_validity,
            key_fingerprint="traditional-fp")

        # An independent ACME account/order for the exact same fqdns.
        account = database.create_acme_account(jwk_json="{}", thumbprint=secrets.token_hex(16))
        order = database.create_acme_order(
            account_client_id=account.id, fqdns=fqdns, identifiers_json="[]",
            expires_at=_utcnow() + datetime.timedelta(days=7))
        self.assertTrue(database.acquire_acme_processing_lock(
            order.id, fqdns, csr_pem="dummy-csr", csr_key_fingerprint="acme-fp"))

        acme_cert_pem = _make_self_signed_cert_pem(fqdns)
        cert_dir = self._cert_dir(acme_cert_pem)
        result = crtrequest.update_database_with_certificate_from_csr(
            cert_dir, fqdns, order.id, csr_key_fingerprint="acme-fp")
        self.assertTrue(result)

        # The ACME order got its own, independently-issued certificate...
        acme_cert_row = database.get_acme_certificate_by_order_id(order.id)
        self.assertIsNotNone(acme_cert_row)
        self.assertEqual(acme_cert_row.certificate_pem, acme_cert_pem)

        # ...and the shared Certificate row - which the traditional
        # protocol's handle_retrieve_request() actually depends on - is
        # completely untouched.
        cert_row = database.get_certificate(fqdns)
        self.assertEqual(cert_row.private_key, "TRADITIONAL-KEY-PEM")
        self.assertEqual(cert_row.public_key, "TRADITIONAL-CERT-PEM")
        self.assertEqual(cert_row.key_fingerprint, "traditional-fp")

    def test_acme_only_fqdns_is_unaffected_by_this_change(self):
        # Regression guard: an fqdns with no traditional-protocol involvement
        # at all must still get its shared Certificate row populated by a
        # successful ACME issuance, exactly as before.
        fqdns = f"acme-only-{secrets.token_hex(4)}.test"
        database.create_certificate_entry(fqdns)
        account = database.create_acme_account(jwk_json="{}", thumbprint=secrets.token_hex(16))
        order = database.create_acme_order(
            account_client_id=account.id, fqdns=fqdns, identifiers_json="[]",
            expires_at=_utcnow() + datetime.timedelta(days=7))
        self.assertTrue(database.acquire_acme_processing_lock(
            order.id, fqdns, csr_pem="dummy-csr", csr_key_fingerprint="acme-fp"))

        cert_pem = _make_self_signed_cert_pem(fqdns)
        cert_dir = self._cert_dir(cert_pem)
        result = crtrequest.update_database_with_certificate_from_csr(
            cert_dir, fqdns, order.id, csr_key_fingerprint="acme-fp")
        self.assertTrue(result)

        cert_row = database.get_certificate(fqdns)
        self.assertEqual(cert_row.public_key, cert_pem)
        self.assertIsNone(cert_row.private_key or None, "ACME issuance must never populate a private key")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


class TestNewOrderOverTheWire(unittest.TestCase):
    """Real HTTP new-order request against a live AcmeRequestHandler - this
    is the actual rejected-vs-accepted boundary that changed
    (handle_new_order() no longer returns 403 for an fqdns the traditional
    protocol already manages)."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="acme-coexistence-wire-test-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()

        self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = jose.JWKRSA(key=self.priv.public_key())
        client = database.create_acme_account(jwk_json=self.jwk.json_dumps(), thumbprint=secrets.token_hex(16))
        database.update_client_status(client.client_id, 'confirmed')
        self.client_row_id = client.id

        self.config = {}
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), AcmeRequestHandler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.config["acme_external_url"] = f"http://127.0.0.1:{self.port}/acme"
        self.httpd.acme_config = self.config
        self.httpd.acme_routes = build_routes("/acme")
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}/acme"
        self.account_url = f"{self.base}/account/{self.client_row_id}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def _get_nonce(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("HEAD", "/acme/new-nonce")
        resp = conn.getresponse()
        resp.read()
        nonce = resp.getheader("Replay-Nonce")
        conn.close()
        return nonce

    def _new_order(self, fqdns):
        url = f"{self.base}/new-order"
        nonce = self._get_nonce()
        protected = {"alg": "RS256", "nonce": nonce, "url": url, "kid": self.account_url}
        payload = json.dumps({"identifiers": [{"type": "dns", "value": fqdns}]}).encode()
        protected_b64 = _b64url(json.dumps(protected).encode())
        payload_b64 = _b64url(payload)
        signing_input = f"{protected_b64}.{payload_b64}".encode()
        signature = self.priv.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        envelope = json.dumps({
            "protected": protected_b64, "payload": payload_b64, "signature": _b64url(signature),
        }).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("POST", "/acme/new-order", body=envelope, headers={"Content-Type": "application/jose+json"})
        resp = conn.getresponse()
        status = resp.status
        body = json.loads(resp.read())
        conn.close()
        return status, body

    def test_new_order_accepted_for_a_traditionally_managed_fqdns(self):
        fqdns = f"wire-coexist-{secrets.token_hex(4)}.test"
        database.create_certificate_entry(fqdns)
        database.update_certificate(
            fqdns=fqdns, public_key="TRADITIONAL-CERT-PEM", private_key="TRADITIONAL-KEY-PEM",
            intermediates="", validity_end_date=_utcnow() + datetime.timedelta(days=60))

        status, body = self._new_order(fqdns)
        self.assertEqual(status, 201, body)

        # The shared row is still untouched by merely creating the order.
        cert_row = database.get_certificate(fqdns)
        self.assertEqual(cert_row.private_key, "TRADITIONAL-KEY-PEM")


class TestTraditionalIndependentOfAcme(AcmeCoexistenceTestCase):
    def test_issuance_loop_no_longer_skips_an_acme_managed_fqdns(self):
        fqdns = f"trad-coexist-{secrets.token_hex(4)}.test"
        database.create_certificate_entry(fqdns)

        # A live (non-expired, non-invalid) ACME order for the same fqdns -
        # is_acme_managed() returns True for this.
        account = database.create_acme_account(jwk_json="{}", thumbprint=secrets.token_hex(16))
        database.create_acme_order(
            account_client_id=account.id, fqdns=fqdns, identifiers_json="[]",
            expires_at=_utcnow() + datetime.timedelta(days=7))
        self.assertTrue(database.is_acme_managed(fqdns))

        # The one acme.sh-invoking boundary is stubbed - this test is about
        # whether crtrequest.py's loop *attempts* issuance at all, not
        # whether a real acme.sh call succeeds.
        with mock.patch.object(crtrequest, "_attempt_issue_or_renew", return_value=True) as stub:
            result = crtrequest.process_certificates(cert_name=fqdns)

        self.assertTrue(result)
        stub.assert_called_once()
        self.assertEqual(stub.call_args[0][0], fqdns, "must still attempt issuance for the fqdns, not skip it")


if __name__ == "__main__":
    unittest.main()
