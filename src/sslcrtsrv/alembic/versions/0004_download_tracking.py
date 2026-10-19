"""Add client_certificate_relations.last_download_at and
.last_download_validity_end_date: when a client last successfully retrieved
a given certificate, and what that certificate's validity_end_date was at
that moment - lets scs-crtmanager's warn-stale-downloads report compare the
downloaded snapshot against the certificate's *current* validity_end_date to
flag clients still running an old, since-renewed (or simply expiring) copy.
See common/server_utils.py's handle_retrieve_request() (where it's
recorded) and common/database.py's record_certificate_download()/
get_stale_certificate_downloads().

No backfill: there's no historical download data to reconstruct, so both
columns simply start NULL ("never downloaded") for every existing row.

Revision ID: 0004_download_tracking
Revises: 0003_client_version
"""
import sqlalchemy as sa
from alembic import op

revision = '0004_download_tracking'
down_revision = '0003_client_version'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('client_certificate_relations') as batch_op:
        batch_op.add_column(sa.Column('last_download_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('last_download_validity_end_date', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('client_certificate_relations') as batch_op:
        batch_op.drop_column('last_download_validity_end_date')
        batch_op.drop_column('last_download_at')
