"""Add ACME trusted-client auto-approval: a new acme_trust_grants table
(admin-issued, out-of-band pre-shared credentials - RFC 8555 External
Account Binding or a contact-field-token fallback for clients with no EAB
support) and clients.trust_grant_id (which grant, if any, auto-confirmed a
given account). See common/database.py's AcmeTrustGrant class docstring for
the full design rationale.

acme_trust_grants must be created before clients.trust_grant_id's foreign
key can reference it - the reverse order on downgrade, for the same reason.

Revision ID: 0008_acme_trust_grants
Revises: 0007_acme_ip_pinning
"""
import sqlalchemy as sa
from alembic import op

revision = '0008_acme_trust_grants'
down_revision = '0007_acme_ip_pinning'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'acme_trust_grants',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('label', sa.Text(), nullable=False),
        sa.Column('eab_kid', sa.String(255), nullable=True),
        sa.Column('eab_hmac_key_encrypted', sa.Text(), nullable=True),
        sa.Column('contact_token_hash', sa.String(64), nullable=True),
        sa.Column('allowed_fqdns_pattern', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('use_count', sa.Integer(), nullable=False, server_default='0'),
    )
    op.create_index('ix_acme_trust_grants_eab_kid', 'acme_trust_grants', ['eab_kid'], unique=True)
    op.create_index('ix_acme_trust_grants_contact_token_hash', 'acme_trust_grants',
                     ['contact_token_hash'], unique=True)

    # SQLite's batch (copy-and-recreate) mode needs an explicitly-named
    # constraint to add a foreign key - an inline sa.ForeignKey(...) on the
    # Column itself (like every other add_column() call in this project's
    # migrations) has no name for batch mode to reference when rebuilding
    # the table, and raises "Constraint must have a name". Splitting into a
    # plain add_column() plus a separately-named create_foreign_key() is
    # the standard fix.
    with op.batch_alter_table('clients') as batch_op:
        batch_op.add_column(sa.Column('trust_grant_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            'fk_clients_trust_grant_id', 'acme_trust_grants', ['trust_grant_id'], ['id'])


def downgrade():
    # No explicit drop_constraint() call for the FK, unlike 0006's downgrade
    # dropping its own named unique constraint before the column it's on -
    # SQLite's batch (copy-and-recreate) mode already drops a column's own
    # foreign key along with the column itself when reflecting the table to
    # rebuild it, and naming a *foreign* key constraint explicitly here
    # would only work if the live database's FK actually carries this exact
    # name (true for one created by this migration's own upgrade(), but not
    # for one SQLAlchemy's create_all() auto-named differently on a
    # brand-new database that was never migrated through this revision at
    # all - confirmed via direct testing both ways).
    with op.batch_alter_table('clients') as batch_op:
        batch_op.drop_column('trust_grant_id')

    op.drop_index('ix_acme_trust_grants_contact_token_hash', table_name='acme_trust_grants')
    op.drop_index('ix_acme_trust_grants_eab_kid', table_name='acme_trust_grants')
    op.drop_table('acme_trust_grants')
