"""Tests for common/database.py's AcmeTrustGrant and the EAB/contact-token
trusted-client auto-approval paths in common/acme_server_utils.py's
handle_new_account()/handle_new_order(). Real HTTP requests through the
real AcmeRequestHandler, mirroring test_acme_identifier_validation.py's
harness - not just unit-level checks of the database.py helpers.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import base64
import hashlib
import hmac
import http.client
import json
import shutil
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

import josepy as jose
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sslcrtsrv.common import database
from sslcrtsrv.common.acme_server_utils import AcmeRequestHandler, build_routes
from sslcrtsrv.common.db_crypto import generate_db_keypair


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


class AcmeTrustGrantTestCase(unittest.TestCase):
    """Shared harness: a real AcmeRequestHandler server, one account keypair
    per test, and helpers to build newAccount (with or without an EAB)/
    newOrder JWS requests."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="acme-trust-grant-test-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()

        # A throwaway DB-encryption keypair, isolated to this test - EAB
        # grants' HMAC keys go through the same encrypt_for_storage()
        # envelope as Certificate.private_key, which needs a real keypair
        # to exist; never the real /etc/sslcrtsrv one, so this stays a
        # hermetic test with no dependency on real system state. Patched in
        # as common/database.py's own module globals (not passed as an
        # explicit argument) so it also takes effect inside
        # handle_new_account()'s own call to get_acme_eab_hmac_key_bytes(),
        # which has no override parameter of its own.
        db_encryption_private_key_path = f"{self.data_dir}/db_encryption_private.pem"
        db_encryption_public_key_path = f"{self.data_dir}/db_encryption_public.pem"
        generate_db_keypair(private_key_path=db_encryption_private_key_path,
                             public_key_path=db_encryption_public_key_path)
        self.enterContext(mock.patch.object(database, 'DB_ENCRYPTION_PRIVATE_KEY_FILE',
                                             db_encryption_private_key_path))
        self.enterContext(mock.patch.object(database, 'DB_ENCRYPTION_PUBLIC_KEY_FILE',
                                             db_encryption_public_key_path))

        self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = jose.JWKRSA(key=self.priv.public_key())

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), AcmeRequestHandler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.config = {"acme_external_url": f"http://127.0.0.1:{self.port}/acme"}
        self.httpd.acme_config = self.config
        self.httpd.acme_routes = build_routes("/acme")
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

        self.base = f"http://127.0.0.1:{self.port}/acme"

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
        location = resp.getheader("Location")
        conn.close()
        return status, body, location

    def _new_account(self, contact=None, eab=None):
        url = f"{self.base}/new-account"
        nonce = self._get_nonce()
        protected = {"alg": "RS256", "nonce": nonce, "url": url, "jwk": json.loads(self.jwk.json_dumps())}
        payload_obj = {}
        if contact is not None:
            payload_obj["contact"] = contact
        if eab is not None:
            payload_obj["externalAccountBinding"] = eab
        return self._post("/acme/new-account", protected, json.dumps(payload_obj).encode())

    def _build_eab(self, kid, hmac_key_bytes, url, payload_override=None):
        eab_protected_b64 = _b64url(json.dumps({"alg": "HS256", "kid": kid, "url": url}).encode())
        payload_bytes = payload_override if payload_override is not None else self.jwk.json_dumps().encode()
        payload_b64 = _b64url(payload_bytes)
        signing_input = f"{eab_protected_b64}.{payload_b64}".encode()
        sig = hmac.new(hmac_key_bytes, signing_input, hashlib.sha256).digest()
        return {"protected": eab_protected_b64, "payload": payload_b64, "signature": _b64url(sig)}

    def _new_order(self, account_url, fqdns):
        url = f"{self.base}/new-order"
        nonce = self._get_nonce()
        protected = {"alg": "RS256", "nonce": nonce, "url": url, "kid": account_url}
        payload = json.dumps({"identifiers": [{"type": "dns", "value": fqdns}]}).encode()
        status, body, _ = self._post("/acme/new-order", protected, payload)
        return status, body

    def _account_client(self):
        from sslcrtsrv.common import acme_jose
        return database.get_client_by_acme_thumbprint(acme_jose.compute_thumbprint(self.jwk))


class TestEabAutoApproval(AcmeTrustGrantTestCase):
    def test_valid_eab_auto_confirms_account(self):
        result = database.create_acme_trust_grant("test-eab", "*.eab.test", method="eab")
        grant = result["grant"]
        hmac_key_bytes = database.get_acme_eab_hmac_key_bytes(grant)

        eab = self._build_eab(grant.eab_kid, hmac_key_bytes, f"{self.base}/new-account")
        status, body, location = self._new_account(eab=eab)
        self.assertEqual(status, 201, body)

        client = self._account_client()
        self.assertIsNotNone(client)
        self.assertEqual(client.status, "confirmed")
        self.assertEqual(client.trust_grant_id, grant.id)

        grant_after = database.get_acme_trust_grant(grant.id)
        self.assertEqual(grant_after.use_count, 1)
        self.assertIsNotNone(grant_after.last_used_at)

    def test_wrong_hmac_key_is_rejected_not_downgraded(self):
        result = database.create_acme_trust_grant("test-eab-wrong", "*.eab.test", method="eab")
        grant = result["grant"]
        wrong_key = b"\x00" * 32  # deliberately not this grant's real key

        eab = self._build_eab(grant.eab_kid, wrong_key, f"{self.base}/new-account")
        status, body, _ = self._new_account(eab=eab)
        self.assertEqual(status, 400, body)

        # No account must have been created at all - a bad EAB attempt must
        # not silently fall through to a normal pending self-registration.
        self.assertIsNone(self._account_client())

    def test_unknown_kid_is_rejected(self):
        eab = self._build_eab("nonexistent-kid", b"\x00" * 32, f"{self.base}/new-account")
        status, body, _ = self._new_account(eab=eab)
        self.assertEqual(status, 400, body)
        self.assertIsNone(self._account_client())

    def test_revoked_grant_cannot_bootstrap_new_account(self):
        result = database.create_acme_trust_grant("test-eab-revoked", "*.eab.test", method="eab")
        grant = result["grant"]
        hmac_key_bytes = database.get_acme_eab_hmac_key_bytes(grant)
        self.assertTrue(database.revoke_acme_trust_grant(grant.id))

        eab = self._build_eab(grant.eab_kid, hmac_key_bytes, f"{self.base}/new-account")
        status, body, _ = self._new_account(eab=eab)
        self.assertEqual(status, 400, body)
        self.assertIsNone(self._account_client())


class TestContactTokenAutoApproval(AcmeTrustGrantTestCase):
    def test_valid_contact_token_auto_confirms_account(self):
        result = database.create_acme_trust_grant("test-contact", "*.contact.test", method="contact_token")
        grant = result["grant"]
        token = result["secret"]

        status, body, _ = self._new_account(contact=[f"mailto:provisioning+{token}@sslcrtsrv.local"])
        self.assertEqual(status, 201, body)

        client = self._account_client()
        self.assertIsNotNone(client)
        self.assertEqual(client.status, "confirmed")
        self.assertEqual(client.trust_grant_id, grant.id)

    def test_nonmatching_contact_falls_back_to_normal_pending_registration(self):
        database.create_acme_trust_grant("test-contact-2", "*.contact.test", method="contact_token")

        status, body, _ = self._new_account(contact=["mailto:someone+not-a-real-token-at-all-1234@example.test"])
        self.assertEqual(status, 201, body)

        client = self._account_client()
        self.assertIsNotNone(client)
        self.assertEqual(client.status, "registered")
        self.assertIsNone(client.trust_grant_id)

    def test_revoked_token_falls_back_to_normal_pending_registration(self):
        result = database.create_acme_trust_grant("test-contact-3", "*.contact.test", method="contact_token")
        token = result["secret"]
        database.revoke_acme_trust_grant(result["grant"].id)

        status, body, _ = self._new_account(contact=[f"mailto:provisioning+{token}@sslcrtsrv.local"])
        self.assertEqual(status, 201, body)

        client = self._account_client()
        self.assertEqual(client.status, "registered")
        self.assertIsNone(client.trust_grant_id)


class TestTrustGrantOrderAutoApproval(AcmeTrustGrantTestCase):
    def _bootstrap_trusted_account(self, pattern):
        result = database.create_acme_trust_grant("test-order-grant", pattern, method="contact_token")
        token = result["secret"]
        status, body, location = self._new_account(contact=[f"mailto:provisioning+{token}@sslcrtsrv.local"])
        self.assertEqual(status, 201, body)
        return result["grant"], location

    def test_matching_fqdns_is_auto_approved(self):
        grant, account_url = self._bootstrap_trusted_account("*.autoapprove.test")

        status, body = self._new_order(account_url, "device.autoapprove.test")
        self.assertEqual(status, 201, body)
        self.assertEqual(body.get("status"), "ready",
                          "a trust-granted account's matching fqdns must be auto-approved, not pending")

        client = self._account_client()
        relation = database.get_client_certificate_relation(client.id, "device.autoapprove.test")
        self.assertEqual(relation.status, 1)

    def test_nonmatching_fqdns_stays_pending(self):
        grant, account_url = self._bootstrap_trusted_account("*.autoapprove.test")

        status, body = self._new_order(account_url, "device.somewhere-else.test")
        self.assertEqual(status, 201, body)
        self.assertEqual(body.get("status"), "pending")

        client = self._account_client()
        relation = database.get_client_certificate_relation(client.id, "device.somewhere-else.test")
        self.assertEqual(relation.status, 0)

    def test_revoking_grant_stops_future_auto_approval_but_not_past_relations(self):
        grant, account_url = self._bootstrap_trusted_account("*.autoapprove.test")

        status, body = self._new_order(account_url, "first.autoapprove.test")
        self.assertEqual(body.get("status"), "ready")

        self.assertTrue(database.revoke_acme_trust_grant(grant.id))

        status, body = self._new_order(account_url, "second.autoapprove.test")
        self.assertEqual(status, 201, body)
        self.assertEqual(body.get("status"), "pending",
                          "a revoked grant must not auto-approve any *new* fqdns")

        client = self._account_client()
        first_relation = database.get_client_certificate_relation(client.id, "first.autoapprove.test")
        self.assertEqual(first_relation.status, 1,
                          "revoking a grant must not retroactively undo an already-approved relation")


if __name__ == "__main__":
    unittest.main()
