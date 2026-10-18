"""Tests for common/database.py's consume_nonce() (SECURITY_FINDINGS.md
finding #19) - it used to check-then-insert as two separate queries (a
TOCTOU race under concurrent requests carrying the same nonce), now fixed
to insert-first and rely on UsedNonce.nonce's existing primary-key
constraint, catching IntegrityError as "already consumed" instead.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import shutil
import tempfile
import unittest

from sslcrtsrv.common import database


class TestConsumeNonce(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="consume-nonce-test-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def test_first_use_succeeds(self):
        self.assertTrue(database.consume_nonce("nonce-a", 300))

    def test_replay_is_rejected(self):
        self.assertTrue(database.consume_nonce("nonce-b", 300))
        self.assertFalse(database.consume_nonce("nonce-b", 300))

    def test_replay_rejected_even_immediately_after_first_use(self):
        # The scenario the old check-then-insert pattern got wrong under
        # concurrency: two calls for the same nonce in immediate succession
        # must never both return True.
        nonce = "nonce-c"
        results = [database.consume_nonce(nonce, 300) for _ in range(5)]
        self.assertEqual(results, [True, False, False, False, False])

    def test_different_nonces_are_independent(self):
        self.assertTrue(database.consume_nonce("nonce-d", 300))
        self.assertTrue(database.consume_nonce("nonce-e", 300))

    def test_a_failed_consume_does_not_break_the_next_unrelated_call(self):
        # Regression guard: the prune-then-insert split now commits the
        # prune separately, so a rollback on the insert's IntegrityError
        # must not also undo the prune or corrupt the session for
        # subsequent calls.
        nonce = "nonce-f"
        self.assertTrue(database.consume_nonce(nonce, 300))
        self.assertFalse(database.consume_nonce(nonce, 300))
        self.assertTrue(database.consume_nonce("nonce-g", 300))


if __name__ == "__main__":
    unittest.main()
