"""Tests for the main protocol server's authentication-failure tracking
(SECURITY_FINDINGS.md finding #17) - common/server_utils.py's
Server.auth_failure_tracker, incremented on a rejected registration
(process_message()'s "register" branch) and checked in
_accept_connections(). Exercises the real process_message()/
handle_registration() code path directly (in-process, no real socket
needed for the registration-message part - the message-framing/signature
side of this same feature is covered by handle_client()'s hook, exercised
indirectly via tests/test_network_acl.py's live-socket Server harness for
the accept-loop is_blocked() check this shares).
"""
import json
import shutil
import tempfile
import unittest

from sslcrtsrv.common.server_utils import Server


class TestRegistrationAuthFailureTracking(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="registration-auth-failure-test-")
        self.config_path = f"{self.data_dir}/server_config.json"
        with open(self.config_path, "w") as f:
            json.dump({"data_dir": self.data_dir, "registration_secret": "s3cr3t"}, f)
        self.server = Server(host="127.0.0.1", port=0, config_file_path=self.config_path)
        self.address = ("203.0.113.5", 54321)

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def _bad_registration_attempt(self, client_id="attacker-guessed-id"):
        # Missing nonce/timestamp/proof - the cheapest possible rejected
        # registration, exercising process_message()'s failure-tracking hook
        # without needing a real keypair/HMAC proof (handle_registration()
        # rejects on the missing proof long before any crypto is checked).
        message = {"type": "register", "client_id": client_id, "public_key": "not-a-real-key-but-present"}
        return self.server.process_message(message, self.address)

    def test_missing_fields_is_rejected(self):
        response = self._bad_registration_attempt()
        self.assertFalse(response["success"])

    def test_repeated_bad_registrations_block_the_source(self):
        for _ in range(3):
            self.assertFalse(self.server.auth_failure_tracker.is_blocked(self.address[0]))
            self._bad_registration_attempt()
        self.assertTrue(self.server.auth_failure_tracker.is_blocked(self.address[0]))

    def test_client_already_registered_is_not_tracked_as_an_attack(self):
        # A duplicate registration attempt for an already-registered
        # client_id is deliberately excluded from tracking (see
        # server_utils.py's process_message() comment) - it can legitimately
        # happen to an honest client (e.g. a restart racing a retry), unlike
        # a bad proof/nonce/timestamp, so it shouldn't cost a strike. Needs a
        # genuinely valid registration proof to reach that far - anything
        # short-circuits earlier at "Invalid registration credentials".
        import time
        from sslcrtsrv.common.database import save_client
        from sslcrtsrv.common.crypto_utils import compute_registration_proof

        save_client("already-registered-client", "some-public-key-pem", status="pending")
        client_id, public_key_pem = "already-registered-client", "not-a-real-key-but-present"
        for i in range(5):
            nonce, timestamp = f"nonce-{i}", int(time.time())
            proof = compute_registration_proof("s3cr3t", client_id, public_key_pem, nonce, timestamp)
            message = {"type": "register", "client_id": client_id, "public_key": public_key_pem,
                       "nonce": nonce, "timestamp": timestamp, "registration_proof": proof}
            response = self.server.process_message(message, self.address)
            self.assertEqual(response["data"]["message"], "Client already registered")
        self.assertFalse(self.server.auth_failure_tracker.is_blocked(self.address[0]))


if __name__ == "__main__":
    unittest.main()
