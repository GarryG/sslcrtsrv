"""Regression test for the 2026-09-17 fixed-issues.md entry: a renewal's
newOrder call must not silently reset an already-approved fqdns permission
back to pending. Real HTTP request through the real AcmeRequestHandler,
mirroring test_acme_identifier_validation.py's harness - the bug was never
caught by unit-level tests that construct AcmeOrder rows directly instead of
going through handle_new_order().

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import base64
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

from sslcrtsrv.common import database
from sslcrtsrv.common.acme_server_utils import AcmeRequestHandler, build_routes


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


class TestRenewalPreservesApprovedPermission(unittest.TestCase):
    """An admin-approved (cltmanager.py assign) ClientCertificateRelation
    must survive a later newOrder call for the same fqdns - a renewal - not
    get silently reset to pending, or every ACME renewal would require the
    admin to re-run `assign` before finalize would ever succeed again."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="acme-renewal-permission-test-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()

        self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = jose.JWKRSA(key=self.priv.public_key())
        thumbprint = secrets.token_hex(16)
        client = database.create_acme_account(jwk_json=self.jwk.json_dumps(), thumbprint=thumbprint)
        database.update_client_status(client.client_id, 'confirmed')
        self.client_id = client.id

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), AcmeRequestHandler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.config = {"acme_external_url": f"http://127.0.0.1:{self.port}/acme"}
        self.httpd.acme_config = self.config
        self.httpd.acme_routes = build_routes("/acme")
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

        self.base = f"http://127.0.0.1:{self.port}/acme"
        self.account_url = f"{self.base}/account/{self.client_id}"

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

    def _new_order(self, fqdns):
        url = f"{self.base}/new-order"
        nonce = self._get_nonce()
        protected = {"alg": "RS256", "nonce": nonce, "url": url, "kid": self.account_url}
        payload = json.dumps({"identifiers": [{"type": "dns", "value": fqdns}]}).encode()
        return self._post("/acme/new-order", protected, payload)

    def test_second_new_order_does_not_reset_an_already_approved_relation(self):
        fqdns = f"renewal-perm-{secrets.token_hex(4)}.test"

        status, body = self._new_order(fqdns)
        self.assertEqual(status, 201, body)
        self.assertEqual(body.get("status"), "pending")

        # The admin approves it (cltmanager.py assign's own DB-level effect).
        self.assertTrue(database.add_client_certificate_relation(self.client_id, fqdns, status=1))
        relation = database.get_client_certificate_relation(self.client_id, fqdns)
        self.assertEqual(relation.status, 1)

        # A later renewal: the same client orders the same fqdns again.
        status, body = self._new_order(fqdns)
        self.assertEqual(status, 201, body)
        self.assertEqual(body.get("status"), "ready",
                          "a renewal's newOrder must see the already-approved permission, not pending")

        relation = database.get_client_certificate_relation(self.client_id, fqdns)
        self.assertEqual(relation.status, 1,
                          "an admin-approved relation must not be reset to pending by a later newOrder call")

    def test_first_new_order_still_creates_a_pending_relation(self):
        fqdns = f"renewal-perm-fresh-{secrets.token_hex(4)}.test"
        status, body = self._new_order(fqdns)
        self.assertEqual(status, 201, body)
        self.assertEqual(body.get("status"), "pending")

        relation = database.get_client_certificate_relation(self.client_id, fqdns)
        self.assertIsNotNone(relation)
        self.assertEqual(relation.status, 0)


if __name__ == "__main__":
    unittest.main()
