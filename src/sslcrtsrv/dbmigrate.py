#!/usr/bin/env python3
"""Standalone database schema/backend migration tool (scs-dbmigrate).

This is the only place in the codebase that imports Alembic, and the only
place that performs schema DDL changes or cross-backend data copies -
server.py/crtmanager.py/cltmanager.py/admintui only ever create a fresh,
empty, up-to-date schema on first run (see common/database.py's
init_database()/check_schema_is_current()) and never alter an existing one.
See TECHNICAL_REFERENCE.md's database backend section for the full picture.

Two subcommands:
  upgrade-schema   In-place schema upgrade of the currently configured
                   backend to the latest ORM schema (e.g. adding
                   certificates.id to a pre-existing installation). Run
                   this once after upgrading onto a version of sslcrtsrv
                   that requires it - check_schema_is_current() will refuse
                   to start otherwise.
  migrate          Copy all data to a different backend, then repoint
                   server_config.json at it. Prompts interactively for any
                   connection detail not given as a flag.
"""
import argparse
import getpass
import json
import logging
import os
import sys

from . import __version__
from .common.constants import DEFAULT_SERVER_CONFIG_FILE, SHARED_FILE_MODE
from .common import database
from .common.database import _detect_stamp_revision
from .common.system_utils import write_secure_json

# A quiet audit trail for schema upgrades/backend migrations - both
# rare, high-impact, hard-to-undo actions well worth a permanent,
# timestamped record beyond whatever's in the terminal scrollback.
#
# Explicit name, not logging.getLogger(__name__): this module can be run
# directly via `python3 -m sslcrtsrv.dbmigrate`, under which __name__
# becomes "__main__" rather than "sslcrtsrv.dbmigrate" - a logger named
# "__main__" would not be a descendant of "sslcrtsrv" and would never reach
# the handlers common/logging_utils.py's setup_tool_logging() configures
# there (see server.py's identical note for its own logger).
logger = logging.getLogger("sslcrtsrv.dbmigrate")


def _load_config(config_file_path):
    try:
        with open(config_file_path) as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        print(f"Error reading {config_file_path}: {e}")
        sys.exit(1)


def _alembic_config(connection):
    from alembic.config import Config
    alembic_dir = os.path.join(os.path.dirname(__file__), 'alembic')
    cfg = Config()
    cfg.set_main_option('script_location', alembic_dir)
    cfg.attributes['connection'] = connection
    return cfg


def upgrade_schema(config_file_path=None):
    """In-place schema upgrade of the currently configured backend to the
    latest ORM schema. Safe to run repeatedly - a no-op once already
    current, and a no-op on a database with no `certificates` table yet
    (init_database() creates a fresh one at the current schema directly)."""
    from alembic import command
    from sqlalchemy import inspect

    config_file_path = config_file_path or DEFAULT_SERVER_CONFIG_FILE
    config = _load_config(config_file_path)
    database.configure_database(config)

    engine = database.get_db_engine()
    inspector = inspect(engine)
    if 'certificates' not in inspector.get_table_names():
        print("No existing database found - nothing to upgrade. A fresh one "
              "at the current schema will be created automatically on next startup.")
        return True

    with engine.connect() as connection:
        cfg = _alembic_config(connection)
        if 'alembic_version' not in inspector.get_table_names():
            # Never migrated before - anchor it at whichever revision its
            # actual current schema matches, so `upgrade head` only ever
            # applies migrations it genuinely still needs.
            command.stamp(cfg, _detect_stamp_revision(inspector))
        command.upgrade(cfg, 'head')

    print("Schema upgrade complete.")
    return True


def _prompt_backend_connection(backend, host, port, user, password, database_name):
    """Fill in any connection detail not already given as a CLI flag by
    prompting for it interactively."""
    default_port = '3306' if backend == 'mysql' else '5432'
    host = host or input(f"{backend} host: ").strip()
    if port is None:
        port = int(input(f"{backend} port [{default_port}]: ").strip() or default_port)
    user = user or input(f"{backend} user: ").strip()
    if password is None:
        password = getpass.getpass(f"{backend} password: ")
    database_name = database_name or input(f"{backend} database name: ").strip()
    return {'host': host, 'port': port, 'user': user, 'password': password, 'database': database_name}


def migrate_to_backend(to_backend, host=None, port=None, user=None, password=None,
                        database_name=None, config_file_path=None):
    """Copy every client/certificate/permission row from the currently
    configured backend to a freshly created target backend, then repoint
    server_config.json at it. The source backend/data is never modified -
    if anything goes wrong before the config is rewritten, the server keeps
    using the original backend untouched.

    used_nonces is deliberately not copied - it's short-lived anti-replay
    state (registration and every general request's nonce/timestamp check -
    common/database.py's consume_nonce()), and skipping it only costs a
    harmless one-time window where an old, already-processed message could
    in principle be replayed against the new backend, not worth the added
    complexity here.
    """
    from sqlalchemy.orm import sessionmaker

    config_file_path = config_file_path or DEFAULT_SERVER_CONFIG_FILE
    config = _load_config(config_file_path)

    database.configure_database(config)
    source_engine = database.get_db_engine()
    SourceSession = sessionmaker(bind=source_engine)
    source_session = SourceSession()

    if to_backend == 'sqlite':
        target_path = database_name or input("Target sqlite file path: ").strip()
        target_url = f'sqlite:///{target_path}'
        new_database_section = {'backend': 'sqlite'}
    else:
        from sqlalchemy.engine import URL
        backend_config = _prompt_backend_connection(to_backend, host, port, user, password, database_name)
        drivername = 'mysql+pymysql' if to_backend == 'mysql' else 'postgresql+psycopg2'
        target_url = URL.create(
            drivername=drivername,
            username=backend_config['user'],
            password=backend_config['password'],
            host=backend_config['host'],
            port=backend_config['port'],
            database=backend_config['database'])
        new_database_section = {'backend': to_backend, to_backend: backend_config}

    from sqlalchemy.exc import OperationalError

    target_engine = database.create_engine_for_url(target_url)
    try:
        database.Base.metadata.create_all(target_engine)
    except OperationalError as e:
        print(f"Error: could not connect to the {to_backend} target ({e.orig}). "
              "Check that the server is running and reachable at the given host/port, "
              "and that the user/password/database name are correct, then try again.")
        return False
    TargetSession = sessionmaker(bind=target_engine)
    target_session = TargetSession()

    counts = {}
    try:
        # Clients and certificates first - client_certificate_relations'
        # foreign keys (client_id, fqdns) depend on both already existing.
        # Track which ids/fqdns actually got copied: SQLite never enforces
        # its declared FOREIGN KEY constraints (this codebase never turns on
        # `PRAGMA foreign_keys`), so a source database can silently carry
        # client_certificate_relations rows left dangling by some earlier,
        # since-fixed deletion path (or manual editing) - referencing a
        # client_id/fqdns that no longer has a matching row. MySQL/PostgreSQL
        # both enforce the same FK for real, so copying such a row verbatim
        # fails outright instead of silently reproducing the inconsistency.
        valid_client_ids = set()
        valid_fqdns = set()
        for model in (database.Client, database.Certificate):
            rows = source_session.query(model).all()
            for row in rows:
                source_session.expunge(row)
                target_session.merge(row)
            counts[model.__tablename__] = len(rows)
            if model is database.Client:
                valid_client_ids = {row.id for row in rows}
            else:
                valid_fqdns = {row.fqdns for row in rows}

        relations = source_session.query(database.ClientCertificateRelation).all()
        skipped, kept = [], []
        for relation in relations:
            if relation.client_id not in valid_client_ids or relation.fqdns not in valid_fqdns:
                skipped.append(relation)
            else:
                kept.append(relation)
        for relation in kept:
            source_session.expunge(relation)
            target_session.merge(relation)
        counts['client_certificate_relations'] = len(kept)

        target_session.commit()

        if skipped:
            print(f"Warning: skipped {len(skipped)} client_certificate_relations row(s) that "
                  "referenced a client or certificate no longer present in the source database "
                  "(a pre-existing inconsistency, harmless to drop):")
            for relation in skipped:
                print(f"  client_id={relation.client_id} fqdns={relation.fqdns!r}")
    except Exception as e:
        target_session.rollback()
        print(f"Error during migration: {e}")
        return False
    finally:
        source_session.close()
        target_session.close()

    for table, count in counts.items():
        print(f"Copied {count} row(s) from '{table}'")

    if to_backend == 'sqlite':
        print(f"New sqlite database written to {target_path}.")
        print("Point server_config.json's data_dir at its directory (or move "
              "the file under the existing data_dir), then restart the server.")
    else:
        config['database'] = new_database_section
        write_secure_json(config_file_path, config, mode=SHARED_FILE_MODE)
        print(f"{config_file_path} now points at the {to_backend} backend. Restart the server.")

    return True


def main():
    parser = argparse.ArgumentParser(
        prog='scs-dbmigrate',
        description='Database schema upgrades and cross-backend data migration for sslcrtsrv')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('--config', default=DEFAULT_SERVER_CONFIG_FILE,
                         help=f'Server configuration file path (default: {DEFAULT_SERVER_CONFIG_FILE})')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    subparsers.add_parser('upgrade-schema',
        help='In-place schema upgrade of the currently configured backend to the latest ORM schema')

    migrate_parser = subparsers.add_parser('migrate',
        help='Copy all data to a different backend and repoint server_config.json at it')
    migrate_parser.add_argument('--to-backend', required=True, choices=['sqlite', 'mysql', 'postgresql'])
    migrate_parser.add_argument('--host')
    migrate_parser.add_argument('--port', type=int)
    migrate_parser.add_argument('--user')
    migrate_parser.add_argument('--password')
    migrate_parser.add_argument('--database', dest='database_name',
        help='Target database name (mysql/postgresql), or sqlite file path (sqlite)')

    args = parser.parse_args()

    from .common.logging_utils import setup_tool_logging_from_file
    setup_tool_logging_from_file(args.config, "dbmigrate")

    try:
        if args.command == 'upgrade-schema':
            logger.info("upgrade-schema starting (config=%s)", args.config)
            success = upgrade_schema(config_file_path=args.config)
            (logger.info if success else logger.warning)("upgrade-schema: %s",
                                                           "ok" if success else "failed")
        elif args.command == 'migrate':
            logger.info("migrate starting: --to-backend %s (config=%s)", args.to_backend, args.config)
            success = migrate_to_backend(
                args.to_backend, host=args.host, port=args.port, user=args.user,
                password=args.password, database_name=args.database_name, config_file_path=args.config)
            (logger.info if success else logger.warning)("migrate --to-backend %s: %s", args.to_backend,
                                                           "ok" if success else "failed")
        else:
            parser.print_help()
            sys.exit(1)
    except ModuleNotFoundError as e:
        logger.warning("%s: %s", args.command, e)
        print(f"Error: {e}")
        sys.exit(1)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
