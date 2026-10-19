"""Add clients.last_connection_ip: the source address of a client's most
recent successful connection/request - the traditional protocol's direct TCP
peer, or an ACME account's resolved request address (same
acme_trusted_proxy_ip/X-Forwarded-For-aware resolution IP-pinning already
uses). NULL until a client's first successful connection/request. See
common/database.py's Client.last_connection_ip docstring for the full
rationale.

Revision ID: 0009_client_last_ip
Revises: 0008_acme_trust_grants
"""
import sqlalchemy as sa
from alembic import op

revision = '0009_client_last_ip'
down_revision = '0008_acme_trust_grants'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('clients') as batch_op:
        batch_op.add_column(sa.Column('last_connection_ip', sa.String(64), nullable=True))


def downgrade():
    with op.batch_alter_table('clients') as batch_op:
        batch_op.drop_column('last_connection_ip')
