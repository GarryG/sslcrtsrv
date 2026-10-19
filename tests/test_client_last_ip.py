"""Tests for clients.last_connection_ip - the source address of a client's
most recent successful connection/request, recorded for both protocols:
  - the traditional protocol, on a successful registration
    (common/server_utils.py's handle_registration()) and on every later
    verified signed message (common/network_utils.py's
    receive_secure_message()).
  - ACME, on every successful kid-authenticated JWS request
    (common/acme_server_utils.py's verify_acme_jws()) - never on the jwk
    (newAccount) branch, since that client row doesn't exist yet at that
    point.

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
import time
import unittest
from http.server import ThreadingHTTPServer

import josepy as jose
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sslcrtsrv.common import database
from sslcrtsrv.common.acme_server_utils import AcmeRequestHandler, build_routes
from sslcrtsrv.common.crypto_utils import compute_registration_proof
from sslcrtsrv.common.server_utils import Server


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


class TestUpdateClientLastIp(unittest.TestCase):
    """Direct unit tests for the shared database helper both protocols call."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="client-last-ip-db-test-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()
        database.save_client("test-client", "fake-public-key-pem", status="confirmed")

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def test_sets_last_connection_ip(self):
        self.assertTrue(database.update_client_last_ip("test-client", "203.0.113.5"))
        client = database.get_client("test-client")
        self.assertEqual(client.last_connection_ip, "203.0.113.5")

    def test_overwrites_a_previous_value(self):
        database.update_client_last_ip("test-client", "203.0.113.5")
        database.update_client_last_ip("test-client", "198.51.100.9")
        client = database.get_client("test-client")
        self.assertEqual(client.last_connection_ip, "198.51.100.9")

    def test_unknown_client_id_returns_false(self):
        self.assertFalse(database.update_client_last_ip("no-such-client", "203.0.113.5"))

    def test_does_not_touch_last_successful_connection(self):
        # Deliberately separate from update_client_connection_success() -
        # see that function's own docstring for why.
        database.update_client_last_ip("test-client", "203.0.113.5")
        client = database.get_client("test-client")
        self.assertIsNone(client.last_successful_connection)


class TestTraditionalProtocolRecordsLastIp(unittest.TestCase):
    """In-process, no real socket needed - handle_registration()'s address
    parameter is passed through explicitly, same style as
    test_registration_auth_failure_tracker.py."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="client-last-ip-traditional-test-")
        self.config_path = f"{self.data_dir}/server_config.json"
        with open(self.config_path, "w") as f:
            json.dump({"data_dir": self.data_dir, "registration_secret": "s3cr3t"}, f)
        self.server = Server(host="127.0.0.1", port=0, config_file_path=self.config_path)
        self.address = ("203.0.113.5", 54321)

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def test_successful_registration_records_the_source_ip(self):
        client_id, public_key_pem = "new-client", "not-a-real-key-but-present"
        nonce, timestamp = "nonce-1", int(time.time())
        proof = compute_registration_proof("s3cr3t", client_id, public_key_pem, nonce, timestamp)
        message = {"type": "register", "client_id": client_id, "public_key": public_key_pem,
                   "nonce": nonce, "timestamp": timestamp, "registration_proof": proof}

        response = self.server.process_message(message, self.address)
        self.assertTrue(response["success"], response)

        client = database.get_client(client_id)
        self.assertEqual(client.last_connection_ip, "203.0.113.5")

    def test_failed_registration_does_not_record_anything(self):
        message = {"type": "register", "client_id": "attacker", "public_key": "not-a-real-key-but-present"}
        response = self.server.process_message(message, self.address)
        self.assertFalse(response["success"])
        self.assertIsNone(database.get_client("attacker"))


class TestAcmeRecordsLastIp(unittest.TestCase):
    """Real HTTP request through the real AcmeRequestHandler - verify_acme_jws()
    only updates last_connection_ip on the kid (existing-account) branch."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="client-last-ip-acme-test-")
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
        import threading
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

    def test_kid_authenticated_request_records_the_source_ip(self):
        client = database.get_client_by_id_or_client_id(str(self.client_id))
        self.assertIsNone(client.last_connection_ip)

        status, body = self._new_order(f"last-ip-test-{secrets.token_hex(4)}.test")
        self.assertEqual(status, 201, body)

        client = database.get_client_by_id_or_client_id(str(self.client_id))
        self.assertEqual(client.last_connection_ip, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
