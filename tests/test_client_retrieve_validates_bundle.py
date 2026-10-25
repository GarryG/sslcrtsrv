"""Tests that Client.retrieve_certificate() (common/client_utils.py) refuses
to write any file when the downloaded key/cert/intermediate bundle fails
common/crypto_utils.py's validate_certificate_bundle() check - confirming the
validation gate is actually wired in and runs before any open()/write, not
just that validate_certificate_bundle() itself works in isolation (covered
separately in tests/test_validate_certificate_bundle.py).

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import os
import tempfile
import shutil
import unittest
from unittest import mock

from sslcrtsrv.common import client_utils


class TestRetrieveCertificateValidatesBeforeWriting(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="client-retrieve-validate-test-")
        self.client = client_utils.Client("test-client")
        # Bypass _require_secure_channel()/the real network - this test is only
        # about the validation gate between receiving a response and writing files.
        self.client.socket = object()
        self.client.private_key = object()
        self.client.server_public_key = object()
        self.key_path = os.path.join(self.tmp_dir, "key.pem")
        self.cert_path = os.path.join(self.tmp_dir, "cert.pem")
        self.intermediate_path = os.path.join(self.tmp_dir, "intermediate.pem")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _fake_response(self):
        return {
            "response_type": "retrieve",
            "success": True,
            "data": {"key": "fake-key-pem", "cert": "fake-cert-pem", "intermediate": "fake-intermediate-pem"},
        }

    @mock.patch("sslcrtsrv.common.client_utils.send_secure_message", return_value=True)
    def test_invalid_bundle_is_not_written_to_disk(self, _mock_send):
        with mock.patch("sslcrtsrv.common.client_utils.receive_secure_message", return_value=self._fake_response()), \
             mock.patch("sslcrtsrv.common.client_utils.validate_certificate_bundle",
                        return_value=(False, "fake validation failure")):
            result = self.client.retrieve_certificate(
                "host.example.com", key_path=self.key_path, cert_path=self.cert_path,
                intermediate_path=self.intermediate_path)

        self.assertIsNone(result)
        self.assertFalse(os.path.exists(self.key_path))
        self.assertFalse(os.path.exists(self.cert_path))
        self.assertFalse(os.path.exists(self.intermediate_path))

    @mock.patch("sslcrtsrv.common.client_utils.send_secure_message", return_value=True)
    def test_valid_bundle_is_written_to_disk(self, _mock_send):
        with mock.patch("sslcrtsrv.common.client_utils.receive_secure_message", return_value=self._fake_response()), \
             mock.patch("sslcrtsrv.common.client_utils.validate_certificate_bundle", return_value=(True, None)):
            result = self.client.retrieve_certificate(
                "host.example.com", key_path=self.key_path, cert_path=self.cert_path,
                intermediate_path=self.intermediate_path)

        self.assertIsNotNone(result)
        with open(self.key_path) as f:
            self.assertEqual(f.read(), "fake-key-pem")
        with open(self.cert_path) as f:
            self.assertEqual(f.read(), "fake-cert-pem")
        with open(self.intermediate_path) as f:
            self.assertEqual(f.read(), "fake-intermediate-pem")


if __name__ == "__main__":
    unittest.main()
