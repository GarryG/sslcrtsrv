"""Add certificates.id: a real surrogate primary key, replacing the
implicit, SQLite-only rowid that crtrequest.py/crtmanager.py/cltmanager.py
used to identify a certificate by a short numeric ID (used to name each
certificate's acme.sh --home directory, cert_home_dir/cert-<id>).

On SQLite, id is backfilled from the table's own rowid so those existing
on-disk directories keep matching. MySQL/PostgreSQL never had a rowid
concept to preserve here (pluggable backends are new), so their rows are
backfilled in `last_update` order instead - no on-disk state depends on it.

Revision ID: 0002_certificate_id
Revises: 0001_baseline
"""
import sqlalchemy as sa
from alembic import op

revision = '0002_certificate_id'
down_revision = '0001_baseline'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()

    with op.batch_alter_table('certificates') as batch_op:
        batch_op.add_column(sa.Column('id', sa.Integer(), nullable=True))

    if bind.dialect.name == 'sqlite':
        bind.execute(sa.text('UPDATE certificates SET id = rowid'))
    else:
        rows = bind.execute(sa.text('SELECT fqdns FROM certificates ORDER BY last_update')).fetchall()
        for next_id, (fqdns,) in enumerate(rows, start=1):
            bind.execute(sa.text('UPDATE certificates SET id = :id WHERE fqdns = :fqdns'),
                         {'id': next_id, 'fqdns': fqdns})

    # Explicit target shape for the PK-handover recreate pass, instead of
    # letting batch mode reflect the live table and queue create_primary_key()
    # on top of it: the reflected 'fqdns' column still carries its own
    # primary_key=True flag from the live schema, which conflicts with the
    # queued PrimaryKeyConstraint(['id']) and makes SQLAlchemy emit a
    # SAWarning ("... not matching locally specified columns 'id' ...",
    # reported directly by a user - fixed-issues.md) - one that its own
    # message says may become a hard error in a future release. Passing the
    # fully-explicit final shape via copy_from sidesteps the conflict
    # entirely: there's nothing reflected to disagree with.
    target_table = sa.Table(
        'certificates', sa.MetaData(),
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('fqdns', sa.String(512), nullable=False, unique=True),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('private_key', sa.Text()),
        sa.Column('intermediates', sa.Text()),
        sa.Column('validity_end_date', sa.DateTime(), nullable=False),
        sa.Column('last_update', sa.DateTime()),
        sa.Column('acme_provider', sa.String(512)),
        sa.Column('is_staging', sa.Boolean()),
    )
    with op.batch_alter_table('certificates', copy_from=target_table, recreate='always') as batch_op:
        batch_op.alter_column('id', existing_type=sa.Integer(), nullable=False)


def downgrade():
    with op.batch_alter_table('certificates', recreate='always') as batch_op:
        batch_op.drop_constraint('uq_certificates_fqdns', type_='unique')
        batch_op.create_primary_key('pk_certificates', ['fqdns'])
        batch_op.drop_column('id')
