"""Automated tests for ACME_SERVER_DESIGN.md's §10 concurrency scenarios.

These specifically target the expiry/issuance races the design's own §4.3.1/
§6.2/§6.3 were built to close - the kind of bug that (per §10's own words)
"would not have been caught by casual testing against a single well-behaved
client making one request at a time". Each test drives the real
common/database.py functions and crtrequest.py's real
update_database_with_certificate_from_csr() against a real scratch SQLite
database - nothing here is mocked.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).

Not wired into any packaging/build step - see debian/rules' override_dh_auto_test
for why (the build environment doesn't have the runtime deps - sqlalchemy,
josepy, cryptography - these tests need).
"""
import datetime
import os
import secrets
import shutil
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sslcrtsrv import crtrequest
from sslcrtsrv.common import database


def _utcnow():
    """Naive UTC now - matches common/database.py's own _utcnow() helper,
    since AcmeOrder.expires_at etc. are naive-UTC DateTime columns compared
    directly against this."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _make_self_signed_cert_pem(common_name, days=90):
    """A real, valid, parseable self-signed certificate - just enough for
    crtrequest.extract_validity_end_date()'s real `openssl x509 -enddate`
    subprocess call to succeed, and for two calls to produce two
    genuinely-different certificates (distinct keys/serials/validity)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _write_cert_dir(cert_pem):
    """A cert_dir shaped like crtrequest.read_certificate_files() expects
    (ssl.cer/intermed.cer) - no ssl.key, matching a real CSR-relay result
    where this server never sees a private key."""
    cert_dir = tempfile.mkdtemp(prefix="acme-concurrency-test-")
    with open(os.path.join(cert_dir, "ssl.cer"), "w") as f:
        f.write(cert_pem)
    with open(os.path.join(cert_dir, "intermed.cer"), "w") as f:
        f.write("")
    return cert_dir


class AcmeConcurrencyTestCase(unittest.TestCase):
    """Common scratch-database setup/teardown shared by every scenario
    below. Each test gets its own fresh SQLite file and its own randomly
    suffixed fqdns/thumbprints, so tests never interfere with each other."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="acme-concurrency-db-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()
        self._cert_dirs = []

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)
        for cert_dir in self._cert_dirs:
            shutil.rmtree(cert_dir, ignore_errors=True)

    def _cert_dir(self, cert_pem):
        cert_dir = _write_cert_dir(cert_pem)
        self._cert_dirs.append(cert_dir)
        return cert_dir

    def _make_account(self):
        thumbprint = secrets.token_hex(16)
        client = database.create_acme_account(jwk_json="{}", thumbprint=thumbprint)
        self.assertIsNotNone(client)
        return client

    def _make_order(self, account_client_id, fqdns, expires_delta):
        expires_at = _utcnow() + expires_delta
        order = database.create_acme_order(
            account_client_id=account_client_id, fqdns=fqdns,
            identifiers_json="[]", expires_at=expires_at)
        self.assertIsNotNone(order)
        return order

    def _force_expire(self, order_id):
        """Test-only direct manipulation (via the real ORM, not a mock) to
        put an order's expires_at in the past, standing in for "time has
        passed" without an actual multi-day sleep - exactly the kind of
        setup §10 describes as "short-circuit acme_order_ttl_days for the
        test"."""
        session = database.get_db_session()
        try:
            session.query(database.AcmeOrder).filter_by(id=order_id).update(
                {"expires_at": _utcnow() - datetime.timedelta(seconds=1)})
            session.commit()
        finally:
            session.close()

    def _lock_holder(self, fqdns):
        session = database.get_db_session()
        try:
            row = session.query(database.AcmeProcessingLock).filter_by(fqdns=fqdns).first()
            return row.order_id if row else None
        finally:
            session.close()


class TestExpiryRacingInFlightIssuance(AcmeConcurrencyTestCase):
    """§10 scenario 1: expiry racing a still-in-flight issuance."""

    def test_stale_success_after_expiry_is_discarded(self):
        fqdns = f"expiry-race-{secrets.token_hex(4)}.test"
        account = self._make_account()
        database.create_certificate_entry(fqdns)

        order = self._make_order(account.id, fqdns, datetime.timedelta(days=7))
        self.assertTrue(database.acquire_acme_processing_lock(
            order.id, fqdns, csr_pem="dummy-csr", csr_key_fingerprint="fp-a"))
        self.assertEqual(database.get_acme_order(order.id).status, "processing")

        # Force the order past its expiry, then run the real cleanup pass -
        # this is the "expiry cleanup pass runs while acme.sh is still
        # working" half of the race.
        self._force_expire(order.id)
        expired_count = database.expire_stale_acme_orders_and_locks()
        self.assertEqual(expired_count, 1)
        self.assertEqual(database.get_acme_order(order.id).status, "invalid")
        self.assertIsNone(self._lock_holder(fqdns))

        # The stale acme.sh call "succeeds" only now, after the order is
        # already gone - drive the real crtrequest.py integration point.
        cert_pem = _make_self_signed_cert_pem(fqdns)
        cert_dir = self._cert_dir(cert_pem)
        result = crtrequest.update_database_with_certificate_from_csr(
            cert_dir, fqdns, order.id, csr_key_fingerprint="fp-a")

        self.assertFalse(result, "a stale issuance for an already-invalidated order must be discarded")
        self.assertIsNone(database.get_acme_certificate_by_order_id(order.id))
        self.assertIsNone(self._lock_holder(fqdns), "a discarded issuance must not resurrect the lock")
        cert_row = database.get_certificate(fqdns)
        self.assertEqual(cert_row.public_key, "", "the shared Certificate row must be untouched by the discarded result")


class TestFreshOrderReacquiringLock(AcmeConcurrencyTestCase):
    """§10 scenario 2: a fresh order re-acquiring the fqdns while the stale
    one is still finishing."""

    def test_second_order_lock_survives_first_orders_late_success(self):
        fqdns = f"reacquire-{secrets.token_hex(4)}.test"
        account = self._make_account()
        database.create_certificate_entry(fqdns)

        order_a = self._make_order(account.id, fqdns, datetime.timedelta(days=7))
        self.assertTrue(database.acquire_acme_processing_lock(
            order_a.id, fqdns, csr_pem="csr-a", csr_key_fingerprint="fp-a"))
        self._force_expire(order_a.id)
        self.assertEqual(database.expire_stale_acme_orders_and_locks(), 1)
        self.assertIsNone(self._lock_holder(fqdns))

        # A second, fresh order legitimately re-acquires the now-free lock.
        order_b = self._make_order(account.id, fqdns, datetime.timedelta(days=7))
        self.assertTrue(database.acquire_acme_processing_lock(
            order_b.id, fqdns, csr_pem="csr-b", csr_key_fingerprint="fp-b"))
        self.assertEqual(self._lock_holder(fqdns), order_b.id)

        # Order A's stale acme.sh call now "succeeds" too late.
        cert_dir_a = self._cert_dir(_make_self_signed_cert_pem(fqdns))
        result_a = crtrequest.update_database_with_certificate_from_csr(
            cert_dir_a, fqdns, order_a.id, csr_key_fingerprint="fp-a")
        self.assertFalse(result_a)

        # Order B must be completely unaffected by A's late arrival.
        self.assertEqual(self._lock_holder(fqdns), order_b.id, "B's lock must survive A's late, discarded success")
        self.assertEqual(database.get_acme_order(order_b.id).status, "processing")
        self.assertIsNone(database.get_acme_certificate_by_order_id(order_b.id))

        # And B can still legitimately complete afterward.
        cert_pem_b = _make_self_signed_cert_pem(fqdns)
        cert_dir_b = self._cert_dir(cert_pem_b)
        result_b = crtrequest.update_database_with_certificate_from_csr(
            cert_dir_b, fqdns, order_b.id, csr_key_fingerprint="fp-b")
        self.assertTrue(result_b)
        self.assertEqual(database.get_certificate(fqdns).public_key, cert_pem_b)


class TestStaleFailureVsLiveLock(AcmeConcurrencyTestCase):
    """§10 scenario 3: the same stale-order scenario, but failing instead of
    succeeding - the failure/attempt-cap path must not touch a different,
    currently-live order's lock, and a third order must still be rejected
    while the live one holds it."""

    def test_stale_failure_does_not_release_a_newer_orders_lock(self):
        fqdns = f"stale-fail-{secrets.token_hex(4)}.test"
        account = self._make_account()
        database.create_certificate_entry(fqdns)

        order_a = self._make_order(account.id, fqdns, datetime.timedelta(days=7))
        self.assertTrue(database.acquire_acme_processing_lock(
            order_a.id, fqdns, csr_pem="csr-a", csr_key_fingerprint="fp-a"))
        self._force_expire(order_a.id)
        self.assertEqual(database.expire_stale_acme_orders_and_locks(), 1)

        order_b = self._make_order(account.id, fqdns, datetime.timedelta(days=7))
        self.assertTrue(database.acquire_acme_processing_lock(
            order_b.id, fqdns, csr_pem="csr-b", csr_key_fingerprint="fp-b"))
        self.assertEqual(self._lock_holder(fqdns), order_b.id)

        # Order A's stale call fails and immediately hits the attempt cap
        # (max_attempts=1) - its own lock-release, scoped by order_id, must
        # be a no-op against the lock row B now owns.
        database.record_acme_order_failure(
            order_a.id, "simulated failure", max_attempts=1,
            base_retry_seconds=1, max_retry_seconds=10)
        self.assertEqual(database.get_acme_order(order_a.id).status, "invalid")
        self.assertEqual(self._lock_holder(fqdns), order_b.id, "B's lock must survive A's attempt-cap cleanup")

        # A third order for the same fqdns must still be rejected while B
        # holds the lock - acquire_acme_processing_lock's own IntegrityError
        # handling is what enforces this (AcmeProcessingLock.fqdns is the
        # primary key).
        order_c = self._make_order(account.id, fqdns, datetime.timedelta(days=7))
        acquired_c = database.acquire_acme_processing_lock(
            order_c.id, fqdns, csr_pem="csr-c", csr_key_fingerprint="fp-c")
        self.assertFalse(acquired_c, "a third order must be rejected while B still holds the lock")
        self.assertEqual(self._lock_holder(fqdns), order_b.id, "the rejected third order must not disturb B's lock")


class TestRenewalCertificateImmutability(AcmeConcurrencyTestCase):
    """§10 scenario 4: a renewal alongside an old, still-referenced
    certificate - the direct proof that AcmeCertificate rows are genuinely
    immutable per-order records, not overwritten by a later renewal."""

    def test_each_orders_certificate_is_independently_retrievable(self):
        fqdns = f"renewal-{secrets.token_hex(4)}.test"
        account = self._make_account()
        database.create_certificate_entry(fqdns)

        order_a = self._make_order(account.id, fqdns, datetime.timedelta(days=7))
        self.assertTrue(database.acquire_acme_processing_lock(
            order_a.id, fqdns, csr_pem="csr-a", csr_key_fingerprint="fp-a"))
        cert_pem_a = _make_self_signed_cert_pem(fqdns, days=90)
        self.assertTrue(crtrequest.update_database_with_certificate_from_csr(
            self._cert_dir(cert_pem_a), fqdns, order_a.id, csr_key_fingerprint="fp-a"))

        # A later renewal for the identical fqdns, with a different key/CSR.
        order_b = self._make_order(account.id, fqdns, datetime.timedelta(days=7))
        self.assertTrue(database.acquire_acme_processing_lock(
            order_b.id, fqdns, csr_pem="csr-b", csr_key_fingerprint="fp-b"))
        cert_pem_b = _make_self_signed_cert_pem(fqdns, days=90)
        self.assertTrue(crtrequest.update_database_with_certificate_from_csr(
            self._cert_dir(cert_pem_b), fqdns, order_b.id, csr_key_fingerprint="fp-b"))

        self.assertNotEqual(cert_pem_a, cert_pem_b, "test setup sanity: the two certs must actually differ")

        # Each order's own AcmeCertificate row must still reflect exactly
        # what was issued for it - never the other order's certificate.
        self.assertEqual(database.get_acme_certificate_by_order_id(order_a.id).certificate_pem, cert_pem_a)
        self.assertEqual(database.get_acme_certificate_by_order_id(order_b.id).certificate_pem, cert_pem_b)

        # The shared Certificate row reflects only the latest (B's) result.
        self.assertEqual(database.get_certificate(fqdns).public_key, cert_pem_b)


if __name__ == "__main__":
    unittest.main()
