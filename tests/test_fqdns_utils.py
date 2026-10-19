"""Tests for common/fqdns_utils.py - split_fqdns()/normalize_fqdns(), the
shared canonicalization every exact-match fqdns lookup/storage key (and the
ACME trust-grant glob-pattern list) now goes through on both the client and
server side.

Regression coverage for the specific bug report: `scs-client request
"my.domain *.my.domain *.mydomain.net"` (quoted as one shell argument, space-
delimited instead of comma-delimited) was treated as a single bogus "domain"
containing literal spaces, so it never matched the existing SAN certificate's
properly comma-separated fqdns and was added as a new, duplicate request.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import json
import shutil
import tempfile
import unittest

from sslcrtsrv.common import database
from sslcrtsrv.common.fqdns_utils import normalize_fqdns, split_fqdns


class TestSplitFqdns(unittest.TestCase):
    def test_comma_delimited(self):
        self.assertEqual(split_fqdns("a.com,b.com,c.com"), ["a.com", "b.com", "c.com"])

    def test_space_delimited(self):
        self.assertEqual(split_fqdns("a.com b.com c.com"), ["a.com", "b.com", "c.com"])

    def test_mixed_commas_and_spaces(self):
        self.assertEqual(split_fqdns("a.com, b.com ,c.com   d.com"), ["a.com", "b.com", "c.com", "d.com"])

    def test_extra_whitespace_and_empty_entries_collapsed(self):
        self.assertEqual(split_fqdns("  a.com ,,,  b.com   "), ["a.com", "b.com"])

    def test_empty_string(self):
        self.assertEqual(split_fqdns(""), [])
        self.assertEqual(split_fqdns("   "), [])

    def test_order_preserved_not_sorted(self):
        self.assertEqual(split_fqdns("z.com a.com m.com"), ["z.com", "a.com", "m.com"])

    def test_wildcard_entries(self):
        self.assertEqual(split_fqdns("*.a.com *.b.com"), ["*.a.com", "*.b.com"])


class TestNormalizeFqdns(unittest.TestCase):
    def test_comma_and_space_delimited_produce_the_same_key(self):
        # The exact bug report: quoting FQDNs as one shell argument with
        # spaces instead of commas must canonicalize identically to the
        # comma-separated equivalent, so it matches the same existing
        # certificate/relation instead of being treated as a new one.
        comma_form = normalize_fqdns("my.domain,*.my.domain,*.mydomain.net")
        space_form = normalize_fqdns("my.domain *.my.domain *.mydomain.net")
        self.assertEqual(comma_form, space_form)
        self.assertEqual(space_form, "*.my.domain,*.mydomain.net,my.domain")

    def test_sorted_alphabetically(self):
        self.assertEqual(normalize_fqdns("c.com,a.com,b.com"), "a.com,b.com,c.com")

    def test_duplicates_removed(self):
        self.assertEqual(normalize_fqdns("a.com,b.com,a.com"), "a.com,b.com")

    def test_whitespace_and_blank_entries_ignored(self):
        self.assertEqual(normalize_fqdns("  a.com,  b.com   c.com ,,, d.com"), "a.com,b.com,c.com,d.com")

    def test_single_domain_unaffected(self):
        self.assertEqual(normalize_fqdns("example.com"), "example.com")

    def test_empty_string_returns_empty(self):
        self.assertEqual(normalize_fqdns(""), "")

    def test_idempotent(self):
        once = normalize_fqdns("b.com a.com, c.com")
        twice = normalize_fqdns(once)
        self.assertEqual(once, twice)


class TestHandleCertificatesRequestRecognizesSpaceDelimitedDuplicate(unittest.TestCase):
    """End-to-end regression test for the actual bug report: a second
    'certificates' request for the same FQDNs set, sent space-delimited
    instead of comma-delimited (as scs-client would produce from a quoted,
    space-separated command-line argument), must be recognized as the
    already-existing relation - not silently create a new, duplicate one."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="fqdns-dup-test-")
        self.config_path = f"{self.data_dir}/server_config.json"
        with open(self.config_path, "w") as f:
            json.dump({"data_dir": self.data_dir, "registration_secret": "s"}, f)

        from sslcrtsrv.common.server_utils import Server
        self.server = Server(host="127.0.0.1", port=0, config_file_path=self.config_path)

        database.save_client("test-client", "fake-public-key-pem", status="confirmed")
        self.client = database.get_client("test-client")

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def _request_certificates(self, domains_value):
        message = {"data": {"client_id": "test-client", "domains": domains_value}}
        return self.server.handle_certificates_request(message)

    def test_comma_then_space_delimited_is_recognized_as_already_registered(self):
        first = self._request_certificates("my.domain,*.my.domain,*.mydomain.net")
        self.assertTrue(first["success"])

        second = self._request_certificates("my.domain *.my.domain *.mydomain.net")
        self.assertTrue(second["success"])
        self.assertEqual(second["data"]["message"], "Certificate request already registered")
        self.assertEqual(first["data"]["domains"], second["data"]["domains"])

        # Exactly one relation exists for this client - not two.
        relations = database.get_client_certificate_relations(self.client.id)
        self.assertEqual(len(relations), 1)

    def test_space_delimited_request_matches_a_pre_existing_comma_delimited_relation(self):
        canonical = normalize_fqdns("my.domain,*.my.domain,*.mydomain.net")
        self.assertIsNotNone(database.create_certificate_entry(canonical))
        self.assertTrue(database.add_client_certificate_relation(self.client.id, canonical, status=1))

        response = self._request_certificates("my.domain *.my.domain *.mydomain.net")
        self.assertTrue(response["success"])
        self.assertEqual(response["data"]["message"], "Certificate request already registered")

        relations = database.get_client_certificate_relations(self.client.id)
        self.assertEqual(len(relations), 1)


if __name__ == "__main__":
    unittest.main()
