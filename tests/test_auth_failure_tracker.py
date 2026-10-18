"""Tests for common/auth_failure_tracker.py (SECURITY_FINDINGS.md finding
#17) and, since it's built directly on top of it, the generalization of
common/http_abuse_tracker.py's HttpAbuseTracker to accept configurable
thresholds (previously hardcoded module constants, with no prior test
coverage of the class at all).

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import unittest

from sslcrtsrv.common.http_abuse_tracker import HttpAbuseTracker
from sslcrtsrv.common.auth_failure_tracker import (
    new_auth_failure_tracker, AUTH_FAILURE_THRESHOLD,
)


class TestHttpAbuseTrackerConfigurable(unittest.TestCase):
    """The generalized constructor - default args must reproduce the
    original hardcoded-constant behavior exactly (no regression for the
    existing http_abuse_tracker.py call sites), and custom args must
    actually take effect (what auth_failure_tracker.py relies on)."""

    def test_defaults_match_original_module_constants(self):
        from sslcrtsrv.common import http_abuse_tracker as hat
        tracker = HttpAbuseTracker()
        for _ in range(hat.BAD_REQUEST_THRESHOLD - 1):
            tracker.record_bad_request("203.0.113.5")
        self.assertFalse(tracker.is_blocked("203.0.113.5"))
        tracker.record_bad_request("203.0.113.5")
        self.assertTrue(tracker.is_blocked("203.0.113.5"))

    def test_custom_threshold_triggers_earlier(self):
        tracker = HttpAbuseTracker(threshold=2, block_seconds=60)
        tracker.record_bad_request("203.0.113.5")
        self.assertFalse(tracker.is_blocked("203.0.113.5"))
        tracker.record_bad_request("203.0.113.5")
        self.assertTrue(tracker.is_blocked("203.0.113.5"))

    def test_custom_threshold_blocks_whole_subnet(self):
        tracker = HttpAbuseTracker(threshold=2, block_seconds=60)
        tracker.record_bad_request("203.0.113.5")
        tracker.record_bad_request("203.0.113.6")  # same /24, different IP
        self.assertTrue(tracker.is_blocked("203.0.113.7"))

    def test_good_request_clears_history(self):
        tracker = HttpAbuseTracker(threshold=2, block_seconds=60)
        tracker.record_bad_request("203.0.113.5")
        tracker.record_good_request("203.0.113.5")
        tracker.record_bad_request("203.0.113.5")
        self.assertFalse(tracker.is_blocked("203.0.113.5"),
                          "a good request should reset the strike count, not just decrement it")


class TestAuthFailureTracker(unittest.TestCase):
    def test_new_tracker_uses_the_tighter_threshold(self):
        tracker = new_auth_failure_tracker()
        ip = "198.51.100.9"
        for _ in range(AUTH_FAILURE_THRESHOLD - 1):
            tracker.record_bad_request(ip)
            self.assertFalse(tracker.is_blocked(ip))
        tracker.record_bad_request(ip)
        self.assertTrue(tracker.is_blocked(ip))

    def test_each_call_returns_an_independent_tracker(self):
        # server_utils.py/acme_server_utils.py each need their own instance -
        # a shared singleton would let an attack on one server lock out the
        # other's legitimate traffic from the same address.
        tracker_a = new_auth_failure_tracker()
        tracker_b = new_auth_failure_tracker()
        for _ in range(AUTH_FAILURE_THRESHOLD):
            tracker_a.record_bad_request("198.51.100.9")
        self.assertTrue(tracker_a.is_blocked("198.51.100.9"))
        self.assertFalse(tracker_b.is_blocked("198.51.100.9"))


if __name__ == "__main__":
    unittest.main()
