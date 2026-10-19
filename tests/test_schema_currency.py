"""Regression tests for the 2026-09-20 fixed-issues.md entry: a database
whose schema predates the current ORM model must be rejected by
common/database.py's check_schema_is_current()/init_database() *before*
Base.metadata.create_all() ever runs against it - otherwise create_all()
silently creates any brand-new tables a migration introduces while never
adding the new columns it also adds to already-existing tables, leaving a
straddled state scs-dbmigrate's own stamp-detection can't cleanly recover
from (this happened twice in a row: once for 0006_acme_support, then again
for 0008_acme_trust_grants, because the original fix only special-cased the
one migration it was written for instead of the general problem).

check_schema_is_current() now reuses the exact same _detect_stamp_revision()
logic scs-dbmigrate itself uses - a single shared, exhaustive list - rather
than a second, separately hand-maintained set of column checks that's easy
to forget to extend for a new migration.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import shutil
import tempfile
import unittest

from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, text

from sslcrtsrv.common import database


class TestSchemaCurrencyCheck(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="schema-currency-test-")
        database.configure_database({"data_dir": self.data_dir})
        database.init_database()  # create_all() -> current (head) schema
        self.engine = database.get_db_engine()

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def _strip_to_0007(self):
        """Undo just 0008's changes via raw batch/DDL (not create_all,
        which never removes anything) - leaves a genuine 0007-shaped
        database, the same state a real pre-existing installation would be
        in before ever running scs-dbmigrate upgrade-schema for 0008."""
        with self.engine.connect() as conn:
            mctx = MigrationContext.configure(conn)
            ops = Operations(mctx)
            with ops.batch_alter_table('clients') as batch_op:
                batch_op.drop_column('trust_grant_id')
            conn.execute(text('DROP TABLE acme_trust_grants'))
            conn.commit()

    def _strip_to_0006(self):
        """Further back: also undo 0007's allowed_source_ip column."""
        self._strip_to_0007()
        with self.engine.connect() as conn:
            mctx = MigrationContext.configure(conn)
            ops = Operations(mctx)
            with ops.batch_alter_table('clients') as batch_op:
                batch_op.drop_column('allowed_source_ip')
            conn.commit()

    def test_fresh_database_passes(self):
        database.check_schema_is_current()  # must not raise

    def test_stale_at_0007_is_rejected_with_revision_named(self):
        self._strip_to_0007()
        with self.assertRaises(database.SchemaOutOfDate) as ctx:
            database.check_schema_is_current()
        self.assertIn("0007_acme_ip_pinning", str(ctx.exception))

    def test_stale_at_0006_is_rejected_with_revision_named(self):
        self._strip_to_0006()
        with self.assertRaises(database.SchemaOutOfDate) as ctx:
            database.check_schema_is_current()
        self.assertIn("0006_acme_support", str(ctx.exception))

    def test_init_database_refuses_before_create_all_can_run(self):
        # The actual regression: init_database() must raise *before*
        # create_all() has a chance to silently create acme_trust_grants
        # while leaving clients.trust_grant_id missing.
        self._strip_to_0007()
        with self.assertRaises(database.SchemaOutOfDate):
            database.init_database()

        insp = inspect(self.engine)
        self.assertNotIn("acme_trust_grants", insp.get_table_names(),
                          "create_all() must never run against a stale schema")
        self.assertNotIn("trust_grant_id", [c['name'] for c in insp.get_columns('clients')])


if __name__ == "__main__":
    unittest.main()
