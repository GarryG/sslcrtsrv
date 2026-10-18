"""Alembic environment, driven entirely programmatically by dbmigrate.py -
there is no alembic.ini on disk. dbmigrate.py builds a bare alembic.config.Config,
points script_location at this directory, and passes the already-open
connection to migrate via config.attributes['connection'] (the standard
pattern for invoking Alembic from application code rather than its CLI).

This module is never imported by server.py/crtmanager.py/cltmanager.py/
admintui - dbmigrate.py is the only place Alembic is used at all, so the
day-to-day tools stay free of migration logic (see Manual.MD's database
backend section and the plan behind this file).
"""
from alembic import context
from sqlalchemy import engine_from_config, pool

from sslcrtsrv.common.database import Base

config = context.config
target_metadata = Base.metadata


def run_migrations_offline():
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connection = config.attributes.get('connection')
    if connection is not None:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
        return

    # Fallback for the plain `alembic` CLI (not used by dbmigrate.py itself,
    # but keeps this env.py usable standalone for development/debugging).
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix='sqlalchemy.', poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
