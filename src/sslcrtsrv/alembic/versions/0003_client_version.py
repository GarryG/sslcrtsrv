"""Add clients.client_version: the sslcrtsrv package version most recently
reported by that client, sent on every register/request message and
refreshed on every successfully-verified message (see
common/network_utils.py's receive_secure_message(),
common/server_utils.py's handle_registration()) - used by scs-client's
checkversion command's server-side counterpart.

Revision ID: 0003_client_version
Revises: 0002_certificate_id
"""
import sqlalchemy as sa
from alembic import op

revision = '0003_client_version'
down_revision = '0002_certificate_id'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('clients') as batch_op:
        batch_op.add_column(sa.Column('client_version', sa.String(length=64), nullable=True))


def downgrade():
    with op.batch_alter_table('clients') as batch_op:
        batch_op.drop_column('client_version')
