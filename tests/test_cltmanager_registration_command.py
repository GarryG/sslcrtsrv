"""Tests for cltmanager.py's generate_registration_command() - prints the
client.py init/register command lines for a new client, built from
server_config.json's own registration_secret/listen_address/port.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from sslcrtsrv.cltmanager import generate_registration_command


class TestGenerateRegistrationCommand(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="cltmanager-regcmd-test-")
        self.config_path = os.path.join(self.tmp_dir, "server_config.json")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _write_config(self, **fields):
        with open(self.config_path, "w") as f:
            json.dump(fields, f)

    def _run(self, client_id=None, server_host=None, server_port=None):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = generate_registration_command(
                client_id, server_host, server_port, config_file_path=self.config_path)
        return result, buf.getvalue()

    def test_missing_registration_secret_fails_with_clear_error(self):
        self._write_config(listen_address="10.20.0.5", port=5514)
        success, output = self._run()
        self.assertFalse(success)
        self.assertIn("no 'registration_secret' set", output)
        self.assertIn("scs-server init --registration-secret", output)

    def test_wildcard_listen_address_requires_explicit_server_host(self):
        self._write_config(listen_address="0.0.0.0", port=5514, registration_secret="s3cr3t")
        success, output = self._run()
        self.assertFalse(success)
        self.assertIn("listen_address", output)
        self.assertIn("--server-host", output)

    def test_ipv6_wildcard_also_requires_explicit_server_host(self):
        self._write_config(listen_address="::", port=5514, registration_secret="s3cr3t")
        success, output = self._run()
        self.assertFalse(success)
        self.assertIn("--server-host", output)

    def test_concrete_listen_address_is_used_as_default_host(self):
        self._write_config(listen_address="10.20.0.5", port=5514, registration_secret="s3cr3t")
        success, output = self._run()
        self.assertTrue(success)
        self.assertIn("--server-host 10.20.0.5", output)
        self.assertIn("--server-port 5514", output)

    def test_explicit_server_host_overrides_wildcard_listen_address(self):
        self._write_config(listen_address="0.0.0.0", port=5514, registration_secret="s3cr3t")
        success, output = self._run(server_host="srv.example.com")
        self.assertTrue(success)
        self.assertIn("--server-host srv.example.com", output)

    def test_explicit_server_port_overrides_config_port(self):
        self._write_config(listen_address="10.20.0.5", port=5514, registration_secret="s3cr3t")
        success, output = self._run(server_port=6000)
        self.assertTrue(success)
        self.assertIn("--server-port 6000", output)

    def test_registration_secret_is_embedded_in_the_init_command(self):
        self._write_config(listen_address="10.20.0.5", port=5514, registration_secret="s3cr3t-xyz")
        success, output = self._run()
        self.assertTrue(success)
        self.assertIn("--registration-secret 's3cr3t-xyz'", output)

    def test_client_id_is_embedded_when_given(self):
        self._write_config(listen_address="10.20.0.5", port=5514, registration_secret="s3cr3t")
        success, output = self._run(client_id="web01")
        self.assertTrue(success)
        self.assertIn("--client-id web01", output)
        self.assertIn("scs-cltmanager confirm web01", output)

    def test_client_id_omitted_leaves_a_placeholder_for_the_confirm_step(self):
        self._write_config(listen_address="10.20.0.5", port=5514, registration_secret="s3cr3t")
        success, output = self._run()
        self.assertTrue(success)
        self.assertNotIn("--client-id", output)
        self.assertIn("scs-cltmanager confirm <client-id register reports>", output)

    def test_both_commands_are_present(self):
        self._write_config(listen_address="10.20.0.5", port=5514, registration_secret="s3cr3t")
        success, output = self._run()
        self.assertTrue(success)
        self.assertIn("scs-client init", output)
        self.assertIn("scs-client register", output)

    def test_unreadable_config_fails_with_clear_error(self):
        success, output = self._run()
        self.assertFalse(success)
        self.assertIn("could not read", output)


if __name__ == "__main__":
    unittest.main()
