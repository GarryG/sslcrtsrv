"""Add clients.allowed_source_ip: an optional IP-pinning second factor for
an ACME account (ACME_SERVER_DESIGN.md §7.3) - a bare IP or CIDR network
string, enforced in acme_server_utils.py's verify_acme_jws() immediately
after resolving the account via kid. NULL (the default) means unrestricted;
never consulted at all for the traditional protocol.

Revision ID: 0007_acme_ip_pinning
Revises: 0006_acme_support
"""
import sqlalchemy as sa
from alembic import op

revision = '0007_acme_ip_pinning'
down_revision = '0006_acme_support'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('clients') as batch_op:
        batch_op.add_column(sa.Column('allowed_source_ip', sa.String(64), nullable=True))


def downgrade():
    with op.batch_alter_table('clients') as batch_op:
        batch_op.drop_column('allowed_source_ip')
