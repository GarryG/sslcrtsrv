"""Tests for the optional IP-pinning second factor (ACME_SERVER_DESIGN.md
§7.3): Client.allowed_source_ip, common/acme_server_utils.py's enforcement
in verify_acme_jws(), and cltmanager.py's set_allowed_ip command. Includes
real end-to-end HTTP requests against a live AcmeRequestHandler - the actual
TCP peer in these tests is always 127.0.0.1, which is what lets the
trusted-proxy/X-Forwarded-For tests exercise the real code path rather than
mocking it.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import base64
import http.client
import json
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

import josepy as jose
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sslcrtsrv.common import database
from sslcrtsrv.common.acme_server_utils import (
    AcmeRequestHandler, build_routes, _request_source_ip, _source_ip_allowed,
)


class _FakeHandler:
    """Minimal stand-in for AcmeRequestHandler, just enough for
    _request_source_ip()'s two attribute reads - used only for the
    pure-function unit tests below; the end-to-end tests further down use a
    real handler/live server instead."""

    def __init__(self, peer_ip, headers=None):
        self.client_address = (peer_ip, 12345)
        self.headers = headers or {}


class TestSourceIpAllowed(unittest.TestCase):

    def test_exact_ip_match(self):
        self.assertTrue(_source_ip_allowed("203.0.113.5", "203.0.113.5"))

    def test_exact_ip_mismatch(self):
        self.assertFalse(_source_ip_allowed("203.0.113.6", "203.0.113.5"))

    def test_cidr_match(self):
        self.assertTrue(_source_ip_allowed("203.0.113.200", "203.0.113.0/24"))

    def test_cidr_mismatch(self):
        self.assertFalse(_source_ip_allowed("10.0.0.1", "203.0.113.0/24"))

    def test_ipv6_match(self):
        self.assertTrue(_source_ip_allowed("2001:db8::1", "2001:db8::/32"))

    def test_malformed_request_ip_fails_closed(self):
        self.assertFalse(_source_ip_allowed("not-an-ip", "203.0.113.0/24"))

    def test_malformed_allowed_ip_fails_closed(self):
        self.assertFalse(_source_ip_allowed("203.0.113.5", "not-an-ip"))


class TestRequestSourceIp(unittest.TestCase):

    def test_uses_peer_ip_when_no_trusted_proxy_configured(self):
        handler = _FakeHandler("198.51.100.9", headers={"X-Forwarded-For": "203.0.113.1"})
        self.assertEqual(_request_source_ip(handler, {}), "198.51.100.9")

    def test_ignores_forwarded_header_from_untrusted_peer(self):
        handler = _FakeHandler("198.51.100.9", headers={"X-Forwarded-For": "203.0.113.1"})
        config = {"acme_trusted_proxy_ip": "127.0.0.1"}
        self.assertEqual(_request_source_ip(handler, config), "198.51.100.9")

    def test_trusts_forwarded_header_from_configured_proxy(self):
        handler = _FakeHandler("127.0.0.1", headers={"X-Forwarded-For": "203.0.113.1"})
        config = {"acme_trusted_proxy_ip": "127.0.0.1"}
        self.assertEqual(_request_source_ip(handler, config), "203.0.113.1")

    def test_trusted_proxy_with_no_forwarded_header_falls_back_to_peer(self):
        handler = _FakeHandler("127.0.0.1", headers={})
        config = {"acme_trusted_proxy_ip": "127.0.0.1"}
        self.assertEqual(_request_source_ip(handler, config), "127.0.0.1")

    def test_multi_hop_forwarded_header_is_untrusted_falls_back_to_peer(self):
        # internal/security/SECURITY_FINDINGS.md finding #18: a correctly-configured single-tier
        # proxy that strips inbound X-Forwarded-For only ever emits one hop -
        # more than one means the proxy isn't stripping client-supplied
        # values, so none of it is trusted (a prior version of this function
        # took the leftmost entry here, which this test used to assert).
        handler = _FakeHandler("127.0.0.1", headers={"X-Forwarded-For": "203.0.113.1, 10.0.0.5"})
        config = {"acme_trusted_proxy_ip": "127.0.0.1"}
        self.assertEqual(_request_source_ip(handler, config), "127.0.0.1")

    def test_single_hop_forwarded_header_is_still_trusted(self):
        handler = _FakeHandler("127.0.0.1", headers={"X-Forwarded-For": "203.0.113.1"})
        config = {"acme_trusted_proxy_ip": "127.0.0.1"}
        self.assertEqual(_request_source_ip(handler, config), "203.0.113.1")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


class TestIpPinEnforcementOverTheWire(unittest.TestCase):
    """Real HTTP requests, real signatures, real database, against a live
    AcmeRequestHandler - the actual TCP peer here is always 127.0.0.1."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="acme-ippin-test-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()

        self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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

    def _get_nonce(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("HEAD", "/acme/new-nonce")
        resp = conn.getresponse()
        resp.read()
        nonce = resp.getheader("Replay-Nonce")
        conn.close()
        return nonce

    def _post(self, path, protected, payload_bytes, extra_headers=None):
        protected_b64 = _b64url(json.dumps(protected).encode())
        payload_b64 = _b64url(payload_bytes)
        signing_input = f"{protected_b64}.{payload_b64}".encode()
        signature = self.priv.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        envelope = json.dumps({
            "protected": protected_b64, "payload": payload_b64, "signature": _b64url(signature),
        }).encode()
        headers = {"Content-Type": "application/jose+json"}
        if extra_headers:
            headers.update(extra_headers)
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("POST", path, body=envelope, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        body = json.loads(resp.read())
        conn.close()
        return status, body

    def _new_order(self, extra_headers=None):
        url = f"{self.base}/new-order"
        nonce = self._get_nonce()
        protected = {"alg": "RS256", "nonce": nonce, "url": url, "kid": self.account_url}
        payload = json.dumps({"identifiers": [{"type": "dns", "value": f"ippin-{secrets.token_hex(4)}.test"}]}).encode()
        return self._post("/acme/new-order", protected, payload, extra_headers=extra_headers)

    def test_unpinned_account_is_unaffected(self):
        status, body = self._new_order()
        self.assertEqual(status, 201, body)

    def test_pin_matching_real_peer_is_accepted(self):
        database.set_client_allowed_ip(self.client_row_id, "127.0.0.1")
        status, body = self._new_order()
        self.assertEqual(status, 201, body)

    def test_pin_to_a_different_ip_is_rejected(self):
        database.set_client_allowed_ip(self.client_row_id, "203.0.113.0/24")
        status, body = self._new_order()
        self.assertEqual(status, 403, body)
        self.assertIn("unauthorized", body.get("type", ""))
        # Deliberately the same message as "not confirmed" - §7.3's
        # anti-enumeration requirement.
        self.assertEqual(body.get("detail"), "Account is not yet confirmed")

    def test_clearing_the_pin_restores_access(self):
        database.set_client_allowed_ip(self.client_row_id, "203.0.113.0/24")
        status, _ = self._new_order()
        self.assertEqual(status, 403)
        database.set_client_allowed_ip(self.client_row_id, None)
        status, body = self._new_order()
        self.assertEqual(status, 201, body)

    def test_untrusted_forwarded_header_cannot_bypass_a_pin(self):
        # No acme_trusted_proxy_ip configured - a self-supplied
        # X-Forwarded-For claiming the pinned address must be ignored, and
        # the real peer (127.0.0.1) checked instead.
        database.set_client_allowed_ip(self.client_row_id, "203.0.113.9")
        status, body = self._new_order(extra_headers={"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual(status, 403, body)

    def test_forwarded_header_honored_once_proxy_is_trusted(self):
        self.config["acme_trusted_proxy_ip"] = "127.0.0.1"
        database.set_client_allowed_ip(self.client_row_id, "203.0.113.9")
        status, body = self._new_order(extra_headers={"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual(status, 201, body)

    def test_access_log_shows_direct_peer_without_a_trusted_proxy(self):
        # No acme_trusted_proxy_ip configured - the access log must show the
        # real TCP peer (127.0.0.1 here), never a self-supplied
        # X-Forwarded-For, exactly like the pin-enforcement side above.
        with self.assertLogs("sslcrtsrv", level="INFO") as captured:
            status, body = self._new_order(extra_headers={"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual(status, 201, body)
        self.assertTrue(any("127.0.0.1" in line for line in captured.output), captured.output)
        self.assertFalse(any("203.0.113.9" in line for line in captured.output), captured.output)

    def test_access_log_shows_forwarded_client_once_proxy_is_trusted(self):
        self.config["acme_trusted_proxy_ip"] = "127.0.0.1"
        with self.assertLogs("sslcrtsrv", level="INFO") as captured:
            status, body = self._new_order(extra_headers={"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual(status, 201, body)
        self.assertTrue(any("203.0.113.9" in line for line in captured.output), captured.output)


class TestAccessControlListOverTheWire(unittest.TestCase):
    """acme_allowed_networks/acme_denied_networks (common/network_acl.py),
    checked in _dispatch() before any route/auth logic runs - independent of
    the per-account IP pinning tested above. Same live-server harness as
    TestIpPinEnforcementOverTheWire; the real TCP peer here is always
    127.0.0.1."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="acme-acl-test-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()

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

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def _get_directory(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/acme/directory")
        resp = conn.getresponse()
        resp.read()
        status = resp.status
        conn.close()
        return status

    def test_no_lists_configured_is_unaffected(self):
        self.assertEqual(self._get_directory(), 200)

    def test_denied_network_is_rejected_even_on_an_unauthenticated_endpoint(self):
        # /directory never goes through verify_acme_jws() - proves the ACL
        # check in _dispatch() is a true universal chokepoint, not just one
        # wired into the authenticated endpoints.
        self.config["acme_denied_networks"] = ["127.0.0.1/32"]
        self.assertEqual(self._get_directory(), 403)

    def test_denied_network_not_matching_peer_is_unaffected(self):
        self.config["acme_denied_networks"] = ["203.0.113.0/24"]
        self.assertEqual(self._get_directory(), 200)

    def test_allow_list_permits_a_matching_peer(self):
        self.config["acme_allowed_networks"] = ["127.0.0.1/32"]
        self.assertEqual(self._get_directory(), 200)

    def test_allow_list_rejects_a_non_matching_peer(self):
        self.config["acme_allowed_networks"] = ["203.0.113.0/24"]
        self.assertEqual(self._get_directory(), 403)

    def test_denied_country_is_rejected_even_on_an_unauthenticated_endpoint(self):
        # No real GeoIP database needed - see test_network_acl.py's identical
        # reasoning for using a fake reader against the real accept/dispatch
        # wiring. self.httpd.geoip_reader isn't set by setUp() at all (no
        # GeoIP configured), proving _dispatch()'s getattr() default also
        # behaves correctly before this test overrides it.
        from tests.test_geoip_acl import _FakeReader
        self.httpd.geoip_reader = _FakeReader({"127.0.0.1": "RU"})
        self.config["acme_denied_countries"] = ["RU"]
        self.assertEqual(self._get_directory(), 403)

    def test_allowed_country_permits_a_matching_peer(self):
        from tests.test_geoip_acl import _FakeReader
        self.httpd.geoip_reader = _FakeReader({"127.0.0.1": "DE"})
        self.config["acme_allowed_countries"] = ["DE"]
        self.assertEqual(self._get_directory(), 200)

    def test_allowed_country_rejects_a_non_matching_peer(self):
        from tests.test_geoip_acl import _FakeReader
        self.httpd.geoip_reader = _FakeReader({"127.0.0.1": "FR"})
        self.config["acme_allowed_countries"] = ["DE"]
        self.assertEqual(self._get_directory(), 403)

    def test_explicit_network_allow_overrides_a_country_deny(self):
        from tests.test_geoip_acl import _FakeReader
        self.httpd.geoip_reader = _FakeReader({"127.0.0.1": "RU"})
        self.config["acme_denied_countries"] = ["RU"]
        self.config["acme_allowed_networks"] = ["127.0.0.1/32"]
        self.assertEqual(self._get_directory(), 200)

    def test_access_control_default_deny_rejects_when_nothing_else_configured(self):
        self.config["acme_access_control_default"] = "deny"
        self.assertEqual(self._get_directory(), 403)

    def test_deny_takes_precedence_over_allow(self):
        self.config["acme_allowed_networks"] = ["127.0.0.1/32"]
        self.config["acme_denied_networks"] = ["127.0.0.1/32"]
        self.assertEqual(self._get_directory(), 403)

    def test_removing_the_deny_entry_restores_access(self):
        self.config["acme_denied_networks"] = ["127.0.0.1/32"]
        self.assertEqual(self._get_directory(), 403)
        self.config["acme_denied_networks"] = []
        self.assertEqual(self._get_directory(), 200)

    def test_default_checks_native_peer_not_a_self_supplied_forwarded_header(self):
        # No acme_trusted_proxy_ip / acme_access_control_use_forwarded_ip -
        # a client-supplied X-Forwarded-For claiming an allowed address must
        # not bypass a deny list keyed on the real (denied) peer.
        self.config["acme_denied_networks"] = ["127.0.0.1/32"]
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/acme/directory", headers={"X-Forwarded-For": "203.0.113.9"})
        resp = conn.getresponse()
        resp.read()
        status = resp.status
        conn.close()
        self.assertEqual(status, 403)

    def test_forwarded_ip_used_once_opted_in_and_proxy_is_trusted(self):
        # With acme_access_control_use_forwarded_ip set and the peer trusted
        # as the proxy, the deny list should apply to the forwarded address,
        # not the (now-allowed) direct peer.
        self.config["acme_trusted_proxy_ip"] = "127.0.0.1"
        self.config["acme_access_control_use_forwarded_ip"] = True
        self.config["acme_denied_networks"] = ["203.0.113.0/24"]
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/acme/directory", headers={"X-Forwarded-For": "203.0.113.9"})
        resp = conn.getresponse()
        resp.read()
        status = resp.status
        conn.close()
        self.assertEqual(status, 403)


class TestSetAllowedIpCli(unittest.TestCase):
    """Real subprocess invocations of `cltmanager.py set_allowed_ip`."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="acme-ippin-cli-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()
        client = database.create_acme_account(jwk_json="{}", thumbprint=secrets.token_hex(16))
        self.client_id = client.id

        import json as _json
        self.config_path = f"{self.data_dir}/server_config.json"
        with open(self.config_path, "w") as f:
            _json.dump({"data_dir": self.data_dir, "listen_address": "127.0.0.1", "port": 5514,
                        "private_key": "x", "public_key": "y", "registration_secret": "s"}, f)

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def _run(self, *args):
        cmd = [sys.executable, "-m", "sslcrtsrv.cltmanager", "--config", self.config_path] + list(args)
        return subprocess.run(cmd, cwd="/workspaces/python/keysrv/src", capture_output=True, text=True)

    def test_set_and_clear_via_cli(self):
        result = self._run("set_allowed_ip", str(self.client_id), "203.0.113.0/24")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        client = database.get_client_by_id_or_client_id(self.client_id)
        self.assertEqual(client.allowed_source_ip, "203.0.113.0/24")

        result = self._run("set_allowed_ip", str(self.client_id), "none")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        client = database.get_client_by_id_or_client_id(self.client_id)
        self.assertIsNone(client.allowed_source_ip)

    def test_rejects_invalid_value(self):
        result = self._run("set_allowed_ip", str(self.client_id), "not-an-ip")
        self.assertEqual(result.returncode, 1)
        client = database.get_client_by_id_or_client_id(self.client_id)
        self.assertIsNone(client.allowed_source_ip)

    def test_unknown_client_fails(self):
        result = self._run("set_allowed_ip", "999999", "203.0.113.5")
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
