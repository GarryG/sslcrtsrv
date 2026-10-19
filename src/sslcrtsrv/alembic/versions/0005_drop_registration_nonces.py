"""Drop the old registration_nonces table, now superseded by used_nonces
(common/database.py's UsedNonce/consume_nonce()) - the nonce store is now
shared by registration and every general request's anti-replay check
(common/server_utils.py's handle_request()), not just registration.

registration_nonces was never itself Alembic-managed (only ever created by
init_database()'s Base.metadata.create_all(), like used_nonces now is) - this
migration exists purely to clean up the old table name left behind on an
existing installation after the ORM model rename; a brand-new database never
had registration_nonces in the first place, so this is a safe no-op there.

Revision ID: 0005_drop_registration_nonces
Revises: 0004_download_tracking
"""
import sqlalchemy as sa
from alembic import op

revision = '0005_drop_registration_nonces'
down_revision = '0004_download_tracking'
branch_labels = None
depends_on = None


def upgrade():
    op.execute('DROP TABLE IF EXISTS registration_nonces')


def downgrade():
    # Nothing meaningful to restore - registration_nonces only ever held
    # short-lived nonce hashes. Recreate the empty table so anything that
    # might still reference the old name by pure chance doesn't hit a
    # missing-table error.
    op.create_table(
        'registration_nonces',
        sa.Column('nonce', sa.String(255), primary_key=True),
        sa.Column('created_at', sa.DateTime()),
    )
