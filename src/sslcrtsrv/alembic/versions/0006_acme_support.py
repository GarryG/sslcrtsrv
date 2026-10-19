"""Add ACME (RFC 8555) server support: client_kind/acme_key_thumbprint/
acme_contact on clients, key_fingerprint on certificates, and four new
tables (acme_orders, acme_certificates, acme_processing_locks, acme_nonces)
holding all ACME-specific state. See ACME_SERVER_DESIGN.md for the full
rationale behind this schema.

acme_certificates.order_id references acme_orders.id, and nothing on
acme_orders references acme_certificates back - there is no circular
foreign key between the two tables, so acme_orders can be created in one
step and acme_certificates simply references it afterward.

Revision ID: 0006_acme_support
Revises: 0005_drop_registration_nonces
"""
import sqlalchemy as sa
from alembic import op

revision = '0006_acme_support'
down_revision = '0005_drop_registration_nonces'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('clients') as batch_op:
        batch_op.add_column(sa.Column('client_kind', sa.String(16), nullable=False, server_default='custom'))
        batch_op.add_column(sa.Column('acme_key_thumbprint', sa.String(128), nullable=True))
        batch_op.add_column(sa.Column('acme_contact', sa.Text(), nullable=True))
        batch_op.create_unique_constraint('uq_clients_acme_key_thumbprint', ['acme_key_thumbprint'])

    with op.batch_alter_table('certificates') as batch_op:
        batch_op.add_column(sa.Column('key_fingerprint', sa.String(128), nullable=True))
    op.create_index('ix_certificates_key_fingerprint', 'certificates', ['key_fingerprint'])

    op.create_table(
        'acme_orders',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('account_client_id', sa.Integer(), sa.ForeignKey('clients.id'), nullable=False),
        sa.Column('fqdns', sa.String(512), sa.ForeignKey('certificates.fqdns'), nullable=False),
        sa.Column('identifiers_json', sa.Text(), nullable=False),
        sa.Column('csr_pem', sa.Text(), nullable=True),
        sa.Column('csr_key_fingerprint', sa.String(128), nullable=True),
        sa.Column('status', sa.String(16), nullable=False, server_default='pending'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('finalized_at', sa.DateTime(), nullable=True),
        sa.Column('issuance_attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_issuance_attempt_at', sa.DateTime(), nullable=True),
        sa.Column('last_issuance_error', sa.Text(), nullable=True),
        sa.Column('next_issuance_attempt_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_acme_orders_account_client_id', 'acme_orders', ['account_client_id'])
    op.create_index('ix_acme_orders_fqdns', 'acme_orders', ['fqdns'])
    op.create_index('ix_acme_orders_csr_key_fingerprint', 'acme_orders', ['csr_key_fingerprint'])

    op.create_table(
        'acme_certificates',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        # unique=True declared inline, not via a separate
        # op.create_unique_constraint() call after the fact - SQLite's
        # Alembic dialect has no support for ALTER-ing a constraint onto an
        # existing table (only batch_alter_table's copy-and-move strategy
        # can do that), but a constraint declared as part of the CREATE
        # TABLE statement itself, as here, needs no ALTER at all and works
        # identically on every backend.
        sa.Column('order_id', sa.Integer(), sa.ForeignKey('acme_orders.id'), nullable=False, unique=True),
        sa.Column('certificate_pem', sa.Text(), nullable=False),
        sa.Column('intermediates', sa.Text(), nullable=True),
        sa.Column('key_fingerprint', sa.String(128), nullable=False),
        sa.Column('validity_end_date', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_acme_certificates_key_fingerprint', 'acme_certificates', ['key_fingerprint'])

    op.create_table(
        'acme_processing_locks',
        sa.Column('fqdns', sa.String(512), primary_key=True),
        sa.Column('order_id', sa.Integer(), sa.ForeignKey('acme_orders.id'), nullable=False),
        sa.Column('locked_at', sa.DateTime(), nullable=False),
    )

    op.create_table(
        'acme_nonces',
        sa.Column('nonce', sa.String(255), primary_key=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )


def downgrade():
    op.drop_table('acme_nonces')
    op.drop_table('acme_processing_locks')
    op.drop_table('acme_certificates')
    op.drop_table('acme_orders')
    # The index must be dropped explicitly, before batch_alter_table
    # reflects the table to rebuild it - it was created via a standalone
    # op.create_index() in upgrade(), outside any batch_alter_table block,
    # so SQLite's batch (copy-and-recreate) strategy would otherwise still
    # see it as part of the table's live structure and try to recreate it
    # on the new table *after* key_fingerprint has already been dropped
    # from that new table's own column set, failing with "no such column".
    op.drop_index('ix_certificates_key_fingerprint', table_name='certificates')
    with op.batch_alter_table('certificates') as batch_op:
        batch_op.drop_column('key_fingerprint')
    with op.batch_alter_table('clients') as batch_op:
        batch_op.drop_constraint('uq_clients_acme_key_thumbprint', type_='unique')
        batch_op.drop_column('acme_contact')
        batch_op.drop_column('acme_key_thumbprint')
        batch_op.drop_column('client_kind')
