"""Tests for validate_dns_identifier_value() (ACME_SERVER_DESIGN.md §9/§11
risk 7) - both as a unit and through a real newOrder request against a live
AcmeRequestHandler, confirming a malformed identifier is actually rejected
over the wire with a 400/malformed problem+json response, not just that the
helper function itself returns the right tuple.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import base64
import datetime
import http.client
import json
import secrets
import shutil
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

import josepy as jose
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sslcrtsrv.common import acme_server_utils, database
from sslcrtsrv.common.acme_server_utils import AcmeRequestHandler, build_routes, validate_dns_identifier_value


class TestValidateDnsIdentifierValue(unittest.TestCase):
    """Direct unit tests for the validator function."""

    def test_valid_values(self):
        for value in ("example.com", "*.example.com", "mail.example.com",
                      "xn--80akhbyknj4f.example.com", "single-label",
                      "EXAMPLE.COM", "a" * 63 + ".com"):
            with self.subTest(value=value):
                ok, reason = validate_dns_identifier_value(value)
                self.assertTrue(ok, f"expected {value!r} to be valid, got: {reason}")

    def test_idna_encodes_unicode_labels(self):
        ok, reason = validate_dns_identifier_value("münchen.example.com")
        self.assertTrue(ok, reason)

    def test_rejects_ip_address_literals(self):
        for value in ("127.0.0.1", "10.0.0.1", "::1", "2001:db8::1"):
            with self.subTest(value=value):
                ok, reason = validate_dns_identifier_value(value)
                self.assertFalse(ok)
                self.assertIn("IP address", reason)

    def test_rejects_whitespace_and_control_characters(self):
        for value in (" example.com", "example.com ", "exam ple.com", "example.com\x00", "\texample.com"):
            with self.subTest(value=value):
                ok, reason = validate_dns_identifier_value(value)
                self.assertFalse(ok)

    def test_rejects_misplaced_or_duplicated_wildcard(self):
        for value in ("*.*.example.com", "a*.example.com", "example.*.com", "*"):
            with self.subTest(value=value):
                ok, reason = validate_dns_identifier_value(value)
                self.assertFalse(ok)

    def test_rejects_empty_labels(self):
        for value in ("example..com", ".example.com", "example.com."):
            with self.subTest(value=value):
                ok, reason = validate_dns_identifier_value(value)
                self.assertFalse(ok)

    def test_rejects_invalid_label_syntax(self):
        for value in ("-bad.example.com", "bad-.example.com", "a_b.example.com"):
            with self.subTest(value=value):
                ok, reason = validate_dns_identifier_value(value)
                self.assertFalse(ok)

    def test_rejects_overlong_values(self):
        ok, reason = validate_dns_identifier_value("a" * 64 + ".com")
        self.assertFalse(ok)
        ok, reason = validate_dns_identifier_value(("a" * 63 + ".") * 5 + "com")
        self.assertFalse(ok)

    def test_rejects_non_string_and_empty(self):
        for value in (None, 123, [], "", "   "):
            with self.subTest(value=value):
                ok, reason = validate_dns_identifier_value(value)
                self.assertFalse(ok)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


class TestNewOrderRejectsBadIdentifierOverTheWire(unittest.TestCase):
    """End-to-end: a real HTTP request through the real AcmeRequestHandler
    against a real (confirmed) account must be rejected with 400/malformed
    for a syntactically invalid identifier - not just at the unit level."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="acme-identifier-test-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()

        self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = jose.JWKRSA(key=self.priv.public_key())
        thumbprint = secrets.token_hex(16)
        client = database.create_acme_account(jwk_json=self.jwk.json_dumps(), thumbprint=thumbprint)
        database.update_client_status(client.client_id, 'confirmed')
        self.account_client_id = client.id

        self.config = {"acme_external_url": "http://127.0.0.1:0/acme"}
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), AcmeRequestHandler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.config["acme_external_url"] = f"http://127.0.0.1:{self.port}/acme"
        self.httpd.acme_config = self.config
        self.httpd.acme_routes = build_routes("/acme")
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

        self.base = f"http://127.0.0.1:{self.port}/acme"
        self.account_url = f"{self.base}/account/{self.account_client_id}"

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

    def _post(self, path, protected, payload_bytes):
        protected_b64 = _b64url(json.dumps(protected).encode())
        payload_b64 = _b64url(payload_bytes)
        signing_input = f"{protected_b64}.{payload_b64}".encode()
        signature = self.priv.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        envelope = json.dumps({
            "protected": protected_b64, "payload": payload_b64, "signature": _b64url(signature),
        }).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("POST", path, body=envelope, headers={"Content-Type": "application/jose+json"})
        resp = conn.getresponse()
        status = resp.status
        body = json.loads(resp.read())
        conn.close()
        return status, body

    def _new_order(self, identifiers):
        url = f"{self.base}/new-order"
        nonce = self._get_nonce()
        protected = {"alg": "RS256", "nonce": nonce, "url": url, "kid": self.account_url}
        payload = json.dumps({"identifiers": identifiers}).encode()
        return self._post("/acme/new-order", protected, payload)

    def test_valid_identifier_is_accepted(self):
        fqdns = f"validorder-{secrets.token_hex(4)}.test"
        status, body = self._new_order([{"type": "dns", "value": fqdns}])
        self.assertEqual(status, 201, body)

    def test_ip_address_identifier_is_rejected(self):
        status, body = self._new_order([{"type": "dns", "value": "127.0.0.1"}])
        self.assertEqual(status, 400, body)
        self.assertIn("malformed", body.get("type", ""))
        self.assertIn("IP address", body.get("detail", ""))

    def test_control_character_identifier_is_rejected(self):
        status, body = self._new_order([{"type": "dns", "value": "exam\x00ple.com"}])
        self.assertEqual(status, 400, body)
        self.assertIn("malformed", body.get("type", ""))

    def test_malformed_wildcard_identifier_is_rejected(self):
        status, body = self._new_order([{"type": "dns", "value": "*.*.example.com"}])
        self.assertEqual(status, 400, body)
        self.assertIn("malformed", body.get("type", ""))


if __name__ == "__main__":
    unittest.main()
