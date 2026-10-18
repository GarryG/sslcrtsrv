"""Tests for common/network_acl.py's is_ip_permitted() - the shared
netblock/subnet allow-list/deny-list matching used by both the main
protocol server (common/server_utils.py's _accept_connections()) and the
ACME server (common/acme_server_utils.py's _dispatch()) to gate which
source IPs may reach their listening ports at all, independent of either
server's own authentication.

Also includes a real end-to-end test of the main protocol server's
enforcement, using a live Server instance bound to 127.0.0.1 on an
ephemeral port - the ACME side's equivalent enforcement is covered in
tests/test_acme_ip_pinning.py's TestAccessControlListOverTheWire, which
already has a live-server harness to build on; this one is new since no
prior test exercised common/server_utils.py's Server class at all.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import json
import shutil
import socket
import tempfile
import threading
import unittest

from sslcrtsrv.common.network_acl import is_ip_permitted


class TestIsIpPermitted(unittest.TestCase):
    def test_no_lists_permits_everything(self):
        self.assertTrue(is_ip_permitted("203.0.113.5", [], []))
        self.assertTrue(is_ip_permitted("203.0.113.5", None, None))

    def test_denied_exact_ip_is_rejected(self):
        self.assertFalse(is_ip_permitted("203.0.113.5", [], ["203.0.113.5"]))

    def test_denied_cidr_is_rejected(self):
        self.assertFalse(is_ip_permitted("203.0.113.200", [], ["203.0.113.0/24"]))

    def test_ip_not_in_deny_list_is_permitted(self):
        self.assertTrue(is_ip_permitted("198.51.100.1", [], ["203.0.113.0/24"]))

    def test_non_empty_allow_list_rejects_a_non_matching_ip(self):
        self.assertFalse(is_ip_permitted("198.51.100.1", ["203.0.113.0/24"], []))

    def test_non_empty_allow_list_permits_a_matching_ip(self):
        self.assertTrue(is_ip_permitted("203.0.113.9", ["203.0.113.0/24"], []))

    def test_deny_takes_precedence_over_allow(self):
        self.assertFalse(is_ip_permitted("203.0.113.9", ["203.0.113.0/24"], ["203.0.113.9/32"]))

    def test_ipv6_cidr_match(self):
        self.assertTrue(is_ip_permitted("2001:db8::1", [], []))
        self.assertFalse(is_ip_permitted("2001:db8::1", [], ["2001:db8::/32"]))

    def test_malformed_deny_entry_is_skipped_not_raised(self):
        # An invalid entry elsewhere in the list must not break checking the
        # rest of it, or the whole feature, on a startup typo.
        self.assertTrue(is_ip_permitted("203.0.113.5", [], ["not-a-cidr", "198.51.100.0/24"]))
        self.assertFalse(is_ip_permitted("198.51.100.5", [], ["not-a-cidr", "198.51.100.0/24"]))

    def test_malformed_source_ip_fails_closed(self):
        self.assertFalse(is_ip_permitted("not-an-ip", [], []))
        self.assertFalse(is_ip_permitted("not-an-ip", ["0.0.0.0/0"], []))


class TestServerAcceptLoopAccessControl(unittest.TestCase):
    """Real TCP connections against a live common.server_utils.Server -
    the actual regression test for "does this block traffic", not just
    unit-level logic on is_ip_permitted() itself."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="server-acl-test-")
        self.config_path = f"{self.data_dir}/server_config.json"
        self.config = {"data_dir": self.data_dir, "registration_secret": "s"}
        with open(self.config_path, "w") as f:
            json.dump(self.config, f)

        from sslcrtsrv.common.server_utils import Server
        self.server = Server(host="127.0.0.1", port=0, config_file_path=self.config_path)
        self.assertTrue(self.server.setup_server())
        self.server.running = True
        self.port = self.server.socket.getsockname()[1]
        self.thread = threading.Thread(
            target=self.server._accept_connections,
            args=(self.server.socket, "127.0.0.1", self.port),
            daemon=True,
        )
        self.thread.start()

    def tearDown(self):
        self.server.running = False
        try:
            self.server.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.server.socket.close()
        self.thread.join(timeout=5)
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def _connection_is_accepted(self):
        """True if the server keeps the connection open long enough for a
        1-byte read to time out (rather than the peer seeing it closed
        immediately, which is how a denied connection is rejected)."""
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        try:
            sock.settimeout(0.5)
            try:
                data = sock.recv(1)
            except socket.timeout:
                return True
            return data != b""
        finally:
            sock.close()

    def test_no_lists_configured_connection_is_accepted(self):
        self.assertTrue(self._connection_is_accepted())

    def test_denied_network_rejects_the_connection(self):
        self.server.denied_networks = ["127.0.0.1/32"]
        self.assertFalse(self._connection_is_accepted())

    def test_removing_the_deny_entry_restores_access(self):
        self.server.denied_networks = ["127.0.0.1/32"]
        self.assertFalse(self._connection_is_accepted())
        self.server.denied_networks = []
        self.assertTrue(self._connection_is_accepted())

    def test_allow_list_rejects_a_non_matching_peer(self):
        self.server.allowed_networks = ["203.0.113.0/24"]
        self.assertFalse(self._connection_is_accepted())

    def test_allow_list_permits_a_matching_peer(self):
        self.server.allowed_networks = ["127.0.0.1/32"]
        self.assertTrue(self._connection_is_accepted())


if __name__ == "__main__":
    unittest.main()
