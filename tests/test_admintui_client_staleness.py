"""Tests for the data behind admintui's Clients tab staleness coloring
(yellow: no successful connection/order in 2 months; red: never connected,
or not confirmed):
  - common/database.py's get_latest_acme_order_created_at_by_account() - the
    "last seen" proxy for ACME accounts, which never populate
    Client.last_successful_connection at all (it's only ever set by the
    traditional protocol's signed-message verification).
  - admintui/screens/clients.py's _last_seen() - picks the right signal per
    client_kind.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import datetime
import secrets
import shutil
import tempfile
import unittest

import josepy as jose
from cryptography.hazmat.primitives.asymmetric import rsa

from sslcrtsrv.admintui.screens.clients import _last_seen
from sslcrtsrv.common import database


def _set_order_created_at(order_id, when):
    """Test-only: create_acme_order() always stamps created_at via the
    model default (now) - direct session access is the only way to
    simulate an order from the past."""
    session = database.get_db_session()
    try:
        order = session.query(database.AcmeOrder).filter_by(id=order_id).first()
        order.created_at = when
        session.commit()
    finally:
        session.close()


class TestGetLatestAcmeOrderCreatedAtByAccount(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="admintui-staleness-test-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def _create_acme_account(self):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = jose.JWKRSA(key=priv.public_key())
        client = database.create_acme_account(jwk_json=jwk.json_dumps(), thumbprint=secrets.token_hex(16))
        return client

    def test_no_orders_at_all_returns_empty_dict(self):
        self.assertEqual(database.get_latest_acme_order_created_at_by_account(), {})

    def test_single_order_is_returned_for_its_account(self):
        client = self._create_acme_account()
        order = database.create_acme_order(client.id, "a.example.com", "{}", datetime.datetime(2099, 1, 1))
        result = database.get_latest_acme_order_created_at_by_account()
        self.assertIn(client.id, result)
        self.assertIsNotNone(result[client.id])

    def test_most_recent_order_wins_for_the_same_account(self):
        client = self._create_acme_account()
        older = database.create_acme_order(client.id, "a.example.com", "{}", datetime.datetime(2099, 1, 1))
        newer = database.create_acme_order(client.id, "b.example.com", "{}", datetime.datetime(2099, 1, 1))
        _set_order_created_at(older.id, datetime.datetime(2026, 1, 1))
        _set_order_created_at(newer.id, datetime.datetime(2026, 6, 1))

        result = database.get_latest_acme_order_created_at_by_account()
        self.assertEqual(result[client.id], datetime.datetime(2026, 6, 1))

    def test_invalid_orders_still_count_as_activity(self):
        # Unlike get_acme_order_rows(), this must NOT exclude 'invalid'
        # orders - a failed/expired order is still evidence the account did
        # something recently.
        client = self._create_acme_account()
        order = database.create_acme_order(client.id, "a.example.com", "{}", datetime.datetime(2099, 1, 1))
        session = database.get_db_session()
        try:
            db_order = session.query(database.AcmeOrder).filter_by(id=order.id).first()
            db_order.status = 'invalid'
            session.commit()
        finally:
            session.close()

        result = database.get_latest_acme_order_created_at_by_account()
        self.assertIn(client.id, result)

    def test_separate_accounts_tracked_independently(self):
        client_a = self._create_acme_account()
        client_b = self._create_acme_account()
        order_a = database.create_acme_order(client_a.id, "a.example.com", "{}", datetime.datetime(2099, 1, 1))
        order_b = database.create_acme_order(client_b.id, "b.example.com", "{}", datetime.datetime(2099, 1, 1))
        _set_order_created_at(order_a.id, datetime.datetime(2026, 1, 1))
        _set_order_created_at(order_b.id, datetime.datetime(2026, 6, 1))

        result = database.get_latest_acme_order_created_at_by_account()
        self.assertEqual(result[client_a.id], datetime.datetime(2026, 1, 1))
        self.assertEqual(result[client_b.id], datetime.datetime(2026, 6, 1))


class TestLastSeen(unittest.TestCase):
    """_last_seen() itself needs no database - a plain object with the
    attributes it reads is enough."""

    class _FakeClient:
        def __init__(self, client_kind, id=1, last_successful_connection=None):
            self.client_kind = client_kind
            self.id = id
            self.last_successful_connection = last_successful_connection

    def test_traditional_client_uses_last_successful_connection(self):
        when = datetime.datetime(2026, 6, 1)
        client = self._FakeClient("custom", last_successful_connection=when)
        self.assertEqual(_last_seen(client, {}), when)

    def test_traditional_client_with_no_connection_returns_none(self):
        client = self._FakeClient("custom", last_successful_connection=None)
        self.assertIsNone(_last_seen(client, {1: datetime.datetime(2026, 6, 1)}))

    def test_acme_client_uses_latest_order_dict_not_last_successful_connection(self):
        when = datetime.datetime(2026, 6, 1)
        client = self._FakeClient("acme", id=42, last_successful_connection=None)
        self.assertEqual(_last_seen(client, {42: when}), when)

    def test_acme_client_with_no_orders_returns_none(self):
        client = self._FakeClient("acme", id=42)
        self.assertIsNone(_last_seen(client, {}))


if __name__ == "__main__":
    unittest.main()
