"""Baseline: schema as it looked immediately before pluggable database
backends were introduced (certificates.fqdns as primary key, no separate
id column - identification relied on SQLite's implicit rowid instead).

scs-dbmigrate stamps an existing pre-Alembic database at this revision
without running it (its schema already matches this point) - see
dbmigrate.py's upgrade-schema command. A brand-new database never needs
this revision at all: init_database()'s Base.metadata.create_all() creates
the current (post-0002) schema directly.

Revision ID: 0001_baseline
Revises:
"""
revision = '0001_baseline'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
