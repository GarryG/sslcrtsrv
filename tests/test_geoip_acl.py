"""Tests for common/geoip_acl.py - GeoIP country-level access control,
checked alongside common/network_acl.py's netblock lists by both the main
protocol server and the ACME server. No real .mmdb/.BIN database is used
anywhere here: a tiny fake reader stands in for either backend, since
is_country_permitted()/is_access_permitted() only ever call it as a plain
"resolve this IP to a country code" dependency - exactly how
test_network_acl.py's TestIsIpPermitted needs no real network hardware.

Live end-to-end coverage (does this actually block a real TCP/HTTP
connection) extends the existing live-server test classes rather than
duplicating their harnesses here - see
tests/test_network_acl.py's TestServerAcceptLoopAccessControl and
tests/test_acme_ip_pinning.py's TestAccessControlListOverTheWire.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import importlib.util
import os
import tempfile
import unittest

from sslcrtsrv.common.geoip_acl import is_access_permitted, is_country_permitted, load_geoip_database

_HAS_MAXMINDDB = importlib.util.find_spec("maxminddb") is not None
_HAS_IP2LOCATION = importlib.util.find_spec("IP2Location") is not None


class _FakeReader:
    """Stands in for either backend's real reader object - maps a bare IP
    string to a bare ISO 3166-1 alpha-2 code (or None, for "no country on
    file for this address", the same outcome a real anonymizing/satellite
    IP range or a lookup miss produces)."""

    def __init__(self, mapping):
        self.mapping = mapping

    def get(self, ip_str):
        code = self.mapping.get(ip_str)
        return {"country": {"iso_code": code}} if code else None

    def get_country_short(self, ip_str):
        return self.mapping.get(ip_str)


class TestIsCountryPermitted(unittest.TestCase):
    def test_no_reader_always_permits(self):
        # GeoIP not configured, or its database failed to load - this check
        # must never be the only thing standing in a connection's way.
        self.assertTrue(is_country_permitted("203.0.113.5", ["DE"], [], None))
        self.assertTrue(is_country_permitted("203.0.113.5", [], ["US"], None))

    def test_no_lists_permits_everything(self):
        reader = _FakeReader({"203.0.113.5": "DE"})
        self.assertTrue(is_country_permitted("203.0.113.5", [], [], reader))
        self.assertTrue(is_country_permitted("203.0.113.5", None, None, reader))

    def test_denied_country_is_rejected(self):
        reader = _FakeReader({"203.0.113.5": "RU"})
        self.assertFalse(is_country_permitted("203.0.113.5", [], ["RU"], reader))

    def test_country_not_in_deny_list_is_permitted(self):
        reader = _FakeReader({"203.0.113.5": "DE"})
        self.assertTrue(is_country_permitted("203.0.113.5", [], ["RU"], reader))

    def test_non_empty_allow_list_rejects_a_non_matching_country(self):
        reader = _FakeReader({"203.0.113.5": "FR"})
        self.assertFalse(is_country_permitted("203.0.113.5", ["DE"], [], reader))

    def test_non_empty_allow_list_permits_a_matching_country(self):
        reader = _FakeReader({"203.0.113.5": "DE"})
        self.assertTrue(is_country_permitted("203.0.113.5", ["DE"], [], reader))

    def test_deny_takes_precedence_over_allow(self):
        reader = _FakeReader({"203.0.113.5": "DE"})
        self.assertFalse(is_country_permitted("203.0.113.5", ["DE"], ["DE"], reader))

    def test_matching_is_case_insensitive(self):
        reader = _FakeReader({"203.0.113.5": "de"})
        self.assertTrue(is_country_permitted("203.0.113.5", ["DE"], [], reader))
        self.assertFalse(is_country_permitted("203.0.113.5", [], ["de"], reader))

    def test_unresolvable_ip_is_permitted_with_no_allow_list(self):
        reader = _FakeReader({})  # lookup miss
        self.assertTrue(is_country_permitted("203.0.113.5", [], ["RU"], reader))

    def test_unresolvable_ip_is_rejected_once_an_allow_list_exists(self):
        reader = _FakeReader({})
        self.assertFalse(is_country_permitted("203.0.113.5", ["DE"], [], reader))

    def test_lookup_exception_is_treated_as_unresolvable_not_raised(self):
        class _BrokenReader:
            def get(self, ip_str):
                raise RuntimeError("simulated backend failure")

        self.assertTrue(is_country_permitted("203.0.113.5", [], ["RU"], _BrokenReader()))
        self.assertFalse(is_country_permitted("203.0.113.5", ["DE"], [], _BrokenReader()))


class TestLoadGeoipDatabase(unittest.TestCase):
    def test_no_path_returns_none(self):
        self.assertIsNone(load_geoip_database(None))
        self.assertIsNone(load_geoip_database(""))

    def test_unknown_backend_returns_none(self):
        with tempfile.NamedTemporaryFile() as f:
            self.assertIsNone(load_geoip_database(f.name, backend="not-a-real-backend"))

    def test_nonexistent_file_returns_none(self):
        # Passes either way (both backends' lazy import also raises cleanly
        # if the package isn't installed at all), but is only actually
        # exercising "nonexistent file" handling, not "package missing",
        # when the relevant package is installed - see the two
        # library-specific corrupt-file tests below for what does require it.
        self.assertIsNone(load_geoip_database("/nonexistent/path/to.mmdb", backend="maxmind"))
        self.assertIsNone(load_geoip_database("/nonexistent/path/to.bin", backend="ip2location"))

    @unittest.skipUnless(_HAS_MAXMINDDB, "maxminddb not installed - install the 'maxmind' extra to run this")
    def test_corrupt_maxmind_file_returns_none_not_raised(self):
        # Verifies the real library actually rejects a non-mmdb file with a
        # catchable exception rather than silently mis-resolving - this is
        # the format-rejection check flagged as a security consideration
        # when this feature was planned, not just a sanity check.
        fd, path = tempfile.mkstemp(suffix=".mmdb")
        try:
            os.write(fd, b"this is not a valid mmdb file")
            os.close(fd)
            self.assertIsNone(load_geoip_database(path, backend="maxmind"))
        finally:
            os.unlink(path)

    @unittest.skipUnless(_HAS_IP2LOCATION, "IP2Location not installed - install the 'ip2location' extra to run this")
    def test_corrupt_ip2location_file_returns_none_not_raised(self):
        # Same reasoning as the maxmind test above, for the other backend -
        # confirmed against the real library that it raises ValueError
        # ("Incorrect IP2Location BIN file format...") on a garbage file,
        # which load_geoip_database()'s generic except Exception catches.
        fd, path = tempfile.mkstemp(suffix=".bin")
        try:
            os.write(fd, b"this is not a valid ip2location bin file" * 10)
            os.close(fd)
            self.assertIsNone(load_geoip_database(path, backend="ip2location"))
        finally:
            os.unlink(path)


class TestIsAccessPermitted(unittest.TestCase):
    """The combined netblock + country check: permitted only if both
    independent dimensions permit."""

    def test_neither_configured_permits_by_default(self):
        self.assertTrue(is_access_permitted("203.0.113.5", [], [], [], [], None))

    def test_neither_configured_denies_with_default_deny(self):
        self.assertFalse(is_access_permitted("203.0.113.5", [], [], [], [], None, default="deny"))

    def test_explicit_network_deny_overrides_country_allow(self):
        reader = _FakeReader({"203.0.113.5": "DE"})
        self.assertFalse(is_access_permitted(
            "203.0.113.5", [], ["203.0.113.0/24"], ["DE"], [], reader))

    def test_explicit_network_allow_overrides_country_deny(self):
        # The whole point of this feature: an admin-listed, specific
        # IP/CIDR is trusted over a coarse GeoIP lookup of the same address.
        reader = _FakeReader({"203.0.113.5": "RU"})
        self.assertTrue(is_access_permitted(
            "203.0.113.5", ["203.0.113.0/24"], [], [], ["RU"], reader))

    def test_non_matching_allowed_networks_falls_through_to_a_country_allow(self):
        # allowed_networks is non-empty but doesn't cover this address - not
        # an explicit denied_networks hit, so unlike a real netblock deny,
        # this doesn't override GeoIP: allowed_countries still gets a say.
        reader = _FakeReader({"203.0.113.5": "DE"})
        self.assertTrue(is_access_permitted(
            "203.0.113.5", ["198.51.100.0/24"], [], ["DE"], [], reader))

    def test_non_matching_allowed_networks_falls_through_to_a_country_deny(self):
        reader = _FakeReader({"203.0.113.5": "RU"})
        self.assertFalse(is_access_permitted(
            "203.0.113.5", ["198.51.100.0/24"], [], [], ["RU"], reader))

    def test_non_matching_allowed_networks_with_no_country_opinion_still_denies(self):
        # allowed_networks doesn't cover this address, and GeoIP has nothing
        # to say either (no allowed_countries/denied_countries configured,
        # even though a reader is present) - the non-matching allow-list
        # still wins here, regardless of `default`: an admin who configured
        # allowed_networks alone made a deliberate "only these" decision
        # that `default` (commonly "allow") must not silently override.
        reader = _FakeReader({"203.0.113.5": "DE"})
        self.assertFalse(is_access_permitted(
            "203.0.113.5", ["198.51.100.0/24"], [], [], [], reader, default="allow"))
        self.assertFalse(is_access_permitted(
            "203.0.113.5", ["198.51.100.0/24"], [], [], [], reader, default="deny"))

    def test_non_matching_allowed_networks_with_geoip_not_configured_at_all_still_denies(self):
        # Same as above, but with no GeoIP database at all (geoip_reader=None)
        # - the plain-netblock-only use case this feature always supported.
        self.assertFalse(is_access_permitted(
            "203.0.113.5", ["198.51.100.0/24"], [], [], [], None, default="allow"))

    def test_geoip_decides_only_when_network_acl_has_nothing_configured(self):
        # No allowed_networks/denied_networks at all - network_verdict() is
        # None, so the country check gets to make the actual decision.
        reader = _FakeReader({"203.0.113.5": "RU"})
        self.assertFalse(is_access_permitted("203.0.113.5", [], [], [], ["RU"], reader))
        self.assertTrue(is_access_permitted("203.0.113.5", [], [], ["RU"], [], reader))

    def test_default_only_applies_when_both_dimensions_are_silent(self):
        # denied_networks is configured but doesn't match this address, and
        # no GeoIP database is configured at all - both dimensions are
        # genuinely silent, so the configurable default decides.
        self.assertTrue(is_access_permitted(
            "203.0.113.5", [], ["198.51.100.0/24"], [], [], None, default="allow"))
        self.assertFalse(is_access_permitted(
            "203.0.113.5", [], ["198.51.100.0/24"], [], [], None, default="deny"))

    def test_unrecognized_default_value_falls_back_to_allow(self):
        self.assertTrue(is_access_permitted(
            "203.0.113.5", [], [], [], [], None, default="not-a-real-policy"))


if __name__ == "__main__":
    unittest.main()
