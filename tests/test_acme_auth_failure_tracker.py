"""Tests for the ACME server's authentication-failure tracking
(SECURITY_FINDINGS.md finding #17) - common/acme_server_utils.py's
module-level _acme_auth_failure_tracker, incremented on JWS signature
failure and checked in _dispatch(). Real end-to-end HTTP requests against a
live AcmeRequestHandler, same harness as tests/test_acme_ip_pinning.py.

The tracker is a module-level singleton (AcmeRequestHandler is
instantiated fresh per request by http.server, so it must survive across
requests to count strikes) - each test resets it in setUp()/tearDown() to
avoid cross-test pollution, the same reason tests/test_logging_utils.py
resets the shared "sslcrtsrv" logger.

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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sslcrtsrv.common import database
from sslcrtsrv.common import acme_server_utils
from sslcrtsrv.common.acme_server_utils import AcmeRequestHandler, build_routes
from sslcrtsrv.common.auth_failure_tracker import new_auth_failure_tracker, AUTH_FAILURE_THRESHOLD


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


class TestAcmeAuthFailureTracker(unittest.TestCase):
    def setUp(self):
        acme_server_utils._acme_auth_failure_tracker = new_auth_failure_tracker()

        self.data_dir = tempfile.mkdtemp(prefix="acme-auth-failure-test-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()

        self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.wrong_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = jose.JWKRSA(key=self.priv.public_key())
        thumbprint = secrets.token_hex(16)
        client = database.create_acme_account(jwk_json=self.jwk.json_dumps(), thumbprint=thumbprint)
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
        acme_server_utils._acme_auth_failure_tracker = new_auth_failure_tracker()

    def _get_nonce(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("HEAD", "/acme/new-nonce")
        resp = conn.getresponse()
        resp.read()
        nonce = resp.getheader("Replay-Nonce")
        conn.close()
        return nonce

    def _new_order_signed_with(self, signing_key):
        url = f"{self.base}/new-order"
        nonce = self._get_nonce()
        protected = {"alg": "RS256", "nonce": nonce, "url": url, "kid": self.account_url}
        payload = json.dumps({"identifiers": [{"type": "dns", "value": f"authfail-{secrets.token_hex(4)}.test"}]}).encode()
        protected_b64 = _b64url(json.dumps(protected).encode())
        payload_b64 = _b64url(payload)
        signing_input = f"{protected_b64}.{payload_b64}".encode()
        signature = signing_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        envelope = json.dumps({
            "protected": protected_b64, "payload": payload_b64, "signature": _b64url(signature),
        }).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("POST", "/acme/new-order", body=envelope, headers={"Content-Type": "application/jose+json"})
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        return status

    def test_valid_signature_is_unaffected(self):
        self.assertEqual(self._new_order_signed_with(self.priv), 201)

    def test_bad_signature_is_rejected_but_not_yet_blocked(self):
        status = self._new_order_signed_with(self.wrong_priv)
        self.assertEqual(status, 401)

    def test_repeated_bad_signatures_trigger_a_block(self):
        for _ in range(AUTH_FAILURE_THRESHOLD - 1):
            status = self._new_order_signed_with(self.wrong_priv)
            self.assertEqual(status, 401)
        # One more bad signature reaches the threshold and blocks the subnet -
        # the *next* request, even a validly-signed one, gets refused outright.
        self._new_order_signed_with(self.wrong_priv)
        status = self._new_order_signed_with(self.priv)
        self.assertEqual(status, 403)

    def test_valid_requests_do_not_accumulate_toward_a_block(self):
        for _ in range(AUTH_FAILURE_THRESHOLD * 3):
            self.assertEqual(self._new_order_signed_with(self.priv), 201)


if __name__ == "__main__":
    unittest.main()
