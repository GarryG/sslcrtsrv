# This file has been updated to use SQLAlchemy instead of SQLite directly
# The implementation is complete and all functions are properly mapped to SQLAlchemy ORM

import base64
import fnmatch
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, CheckConstraint, ForeignKey, text, or_, case, inspect, func
from sqlalchemy.engine import URL
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from .system_utils import ensure_secure_dir
from .constants import (
    DEFAULT_ACME_PROVIDER, SHARED_DIR_MODE, SHARED_FILE_MODE,
    DB_ENCRYPTION_PUBLIC_KEY_FILE, DB_ENCRYPTION_PRIVATE_KEY_FILE,
)
from .db_crypto import encrypt_for_storage, decrypt_for_storage
from .fqdns_utils import split_fqdns

# Default database file path
DEFAULT_DB_FILE = "/opt/sslcrtsrv/keysrv.db"

# Set by configure_database() when server_config.json's "database.backend" is
# "mysql"/"postgresql" instead of the sqlite default - get_db_engine() then
# ignores DEFAULT_DB_FILE entirely and connects here instead. None means
# "use sqlite", the default for every existing install with no `database`
# config section at all.
_network_db_url = None
_network_pool_recycle = -1

# Engines are expensive to open per network round-trip (unlike sqlite, where
# it's cheap) - cache the one currently in use (sqlite path or network
# target) instead of building a new Engine on every get_db_session() call.
_engines = {}

def relocate_under_data_dir(data_dir: str) -> None:
    """Point every database function's default path at `data_dir`/keysrv.db
    instead of the hardcoded default, and update common.constants.DATA_DIR
    to match - the one place server_config.json's `data_dir` (--datadir)
    actually takes effect (it used to just sit in the config file, unused -
    see issue.md).

    Every database function below that isn't given an explicit db_file_path
    reads DEFAULT_DB_FILE fresh at call time (`if db_file_path is None:
    db_file_path = DEFAULT_DB_FILE`), so reassigning it here, once, at
    startup, is enough to redirect all of them - no need to thread a path
    through every individual call site.

    Called once, early, by every tool that touches the database - server.py,
    crtmanager.py, cltmanager.py, crtrequest.py, admintui - since they all
    read the same server_config.json and must agree on where it actually
    lives; calling this from only one of them would just make the others
    silently keep using the old, wrong path instead.
    """
    global DEFAULT_DB_FILE
    DEFAULT_DB_FILE = os.path.join(data_dir, "keysrv.db")
    from . import constants
    constants.DATA_DIR = data_dir

def apply_data_dir_from_config(config_file_path=None) -> None:
    """Read server_config.json and apply its `data_dir`/`database` settings
    via configure_database() - a thin file-loading wrapper around it for
    callers that don't already have the parsed config in hand. A silent
    no-op if the config file doesn't exist yet or isn't valid JSON - callers
    that already have the parsed config (server.py, crtrequest.py) should
    call configure_database() directly instead, to avoid reading the file
    twice.
    """
    import json
    from .constants import DEFAULT_SERVER_CONFIG_FILE
    config_file_path = config_file_path or DEFAULT_SERVER_CONFIG_FILE
    try:
        with open(config_file_path) as f:
            config = json.load(f)
    except (OSError, ValueError):
        return
    configure_database(config)

def configure_database(config: dict = None) -> None:
    """Point the database layer at whichever backend/location
    server_config.json selects - the one place every CLI tool
    (server.py/crtmanager.py/cltmanager.py/crtrequest.py/admintui) should
    apply the loaded config before touching the database, in place of
    calling relocate_under_data_dir() directly.

    Config shape (all optional - an absent `database` key, or
    backend == "sqlite" with no further settings, is exactly today's
    data_dir-based sqlite behavior with no config changes required):

        "data_dir": "/path/to/data",
        "database": {
            "backend": "sqlite" | "mysql" | "postgresql",
            "mysql":      {"host": ..., "port": 3306, "user": ..., "password": ..., "database": ...},
            "postgresql": {"host": ..., "port": 5432, "user": ..., "password": ..., "database": ...}
        }

    For "mysql"/"postgresql", builds the SQLAlchemy connection URL from the
    matching sub-section and drops any previously cached engine so the next
    get_db_session() call connects to the new target. Schema creation/
    upgrades are never performed here - see scs-dbmigrate.
    """
    global _network_db_url, _network_pool_recycle, _engines
    config = config or {}

    data_dir = config.get('data_dir')
    if data_dir:
        relocate_under_data_dir(data_dir)

    db_config = config.get('database') or {}
    backend = db_config.get('backend', 'sqlite')

    if backend == 'sqlite':
        _network_db_url = None
        _engines = {}
        return

    if backend not in ('mysql', 'postgresql'):
        raise ValueError(f"Unknown database backend '{backend}' - expected 'sqlite', 'mysql', or 'postgresql'")

    backend_config = db_config.get(backend) or {}
    drivername = 'mysql+pymysql' if backend == 'mysql' else 'postgresql+psycopg2'
    # internal/security/SECURITY_FINDINGS.md finding #21: opt-in alternative to keeping the DB
    # password in server_config.json at all - checked first, falling back
    # to the config value so nobody who isn't using this has to change
    # anything.
    db_password = os.environ.get('SSLCRTSRV_DB_PASSWORD') or backend_config.get('password')
    _network_db_url = URL.create(
        drivername=drivername,
        username=backend_config.get('user'),
        password=db_password,
        host=backend_config.get('host'),
        port=backend_config.get('port'),
        database=backend_config.get('database'),
    )
    # MySQL drops idle connections after `wait_timeout` (default 8h, often
    # lowered) - pool_recycle forces a reconnect just before that instead of
    # surfacing a "server has gone away" error on the next query. Postgres
    # has no equivalent idle-connection timeout by default.
    _network_pool_recycle = 280 if backend == 'mysql' else -1
    _engines = {}

def _utcnow():
    """Naive UTC now, matching the value datetime.utcnow() used to return -
    the rest of this codebase assumes naive UTC everywhere (comparisons
    elsewhere strip tzinfo) - without using that now-deprecated call."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

# Create (or reuse a cached) database engine
# PyMySQL/psycopg2 are optional extras (setup.cfg's mysql/postgresql
# extras, debian/control's Suggests, not a hard Depends) - a sqlite-only
# install has neither installed. create_engine() imports the driver
# eagerly (to pick the dialect's paramstyle etc.), so picking that backend
# without the driver installed fails there with a bare ModuleNotFoundError
# deep inside SQLAlchemy/dh_python's import machinery. Turn that into an
# actionable message naming the missing package instead.
_DRIVER_PACKAGES = {
    'pymysql': 'python3-pymysql (or `pip install PyMySQL`)',
    'psycopg2': 'python3-psycopg2 (or `pip install psycopg2-binary`)',
}


def create_engine_for_url(url, **kwargs):
    try:
        return create_engine(url, **kwargs)
    except ModuleNotFoundError as e:
        package = _DRIVER_PACKAGES.get(e.name, e.name)
        raise ModuleNotFoundError(
            f"Missing database driver for this backend: install {package} and try again."
        ) from e


def get_db_engine(db_file_path=None):
    """Return the currently configured database engine, cached across calls.

    If configure_database() has selected a network backend (mysql/
    postgresql), that target is used regardless of db_file_path. Otherwise
    returns/creates a cached sqlite engine for db_file_path (or
    DEFAULT_DB_FILE) - callers passing an explicit path (e.g. scratch test
    configs) each get their own cached engine, keyed by path.
    """
    if _network_db_url is not None:
        if 'network' not in _engines:
            _engines['network'] = create_engine_for_url(
                _network_db_url, pool_pre_ping=True, pool_recycle=_network_pool_recycle)
        return _engines['network']

    if db_file_path is None:
        db_file_path = DEFAULT_DB_FILE
    if db_file_path not in _engines:
        _engines[db_file_path] = create_engine(f'sqlite:///{db_file_path}', echo=False)
    return _engines[db_file_path]

# Create base class for declarative models
Base = declarative_base()

def _identifier_string(length):
    """String column type for an identifier used in a unique/PK constraint
    (client_id, fqdns, nonce). A bare, unlengthed String works for sqlite/
    postgresql but MySQL/MariaDB's InnoDB requires an explicit length on any
    indexed VARCHAR column. Also pins MySQL to a case-sensitive binary
    collation so uniqueness/lookups behave the same as sqlite's and
    postgresql's case-sensitive defaults, rather than MySQL's normally
    case-insensitive one - a client_id or certificate fqdns differing only
    in case must not collide.
    """
    return String(length).with_variant(String(length, collation='utf8mb4_bin'), 'mysql')

# Define the clients table
class Client(Base):
    __tablename__ = 'clients'

    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(_identifier_string(255), unique=True, nullable=False)
    public_key = Column(Text, nullable=False)
    registration_date = Column(DateTime, default=_utcnow)
    status = Column(String(32), default='registered')
    last_successful_connection = Column(DateTime)
    # Source address of the most recent successful connection/request -
    # the traditional protocol's direct TCP peer (set in
    # common/network_utils.py's receive_secure_message()), or an ACME
    # account's resolved request address (set in common/acme_server_utils.py's
    # verify_acme_jws(), via the same _request_source_ip() resolution
    # acme_trusted_proxy_ip/X-Forwarded-For-aware IP-pinning already uses -
    # not the raw TCP peer, which behind the mandatory reverse proxy would
    # otherwise always just be the proxy's own address). NULL until a
    # client's first successful connection/request.
    last_connection_ip = Column(String(64), nullable=True)
    first_unsuccessful_connection = Column(DateTime)
    unsuccessful_attempts = Column(Integer, default=0)
    # sslcrtsrv package version most recently reported by this client - sent
    # on every register/request message (see common/message_utils.py) and
    # refreshed on every successfully-verified message (see
    # common/network_utils.py's receive_secure_message()). Not set until the
    # client actually connects with a version that reports it.
    client_version = Column(String(64))

    # 'custom' (default - the existing hand-rolled protocol) or 'acme' - an
    # ACME account is a Client row with no separate accounts table (see
    # ACME_SERVER_DESIGN.md §4.1). For client_kind='acme' rows, public_key
    # holds the account's canonical JWK as JSON, not PEM, and client_id is
    # f"acme:{acme_key_thumbprint}".
    client_kind = Column(String(16), nullable=False, default='custom', server_default='custom')
    # RFC 7638 JWK thumbprint of an ACME account's key - the canonical
    # identity ACME tooling itself treats an account key by, used in place of
    # a re-derived PEM/SPKI fingerprint for the acme_confirm out-of-band
    # comparison. NULL for client_kind='custom' rows.
    acme_key_thumbprint = Column(String(128), unique=True, nullable=True, index=True)
    # Optional JSON-encoded contact list from an ACME account's newAccount/
    # account-update payload (§5.3/§5.4). NULL for client_kind='custom' rows.
    acme_contact = Column(Text, nullable=True)
    # Optional IP-pinning second factor for an ACME account (§7.3) - a bare
    # IP or CIDR network string (e.g. "203.0.113.5" or "203.0.113.0/24"),
    # enforced in acme_server_utils.py's verify_acme_jws() immediately after
    # resolving the account via kid. NULL (the default) means unrestricted -
    # this column is never consulted at all for the traditional protocol,
    # only for kid-authenticated ACME requests.
    allowed_source_ip = Column(String(64), nullable=True)
    # Which AcmeTrustGrant (if any) this account was auto-confirmed through -
    # an EAB or contact-token credential an admin pre-generated for a
    # trusted device (cltmanager.py's acme_create_eab_grant/
    # acme_create_contact_token_grant). NULL for every normal
    # self-registered account (the overwhelming majority) and for every
    # client_kind='custom' row. Recorded so a *later* newOrder call - which
    # doesn't re-present the credential - can still look up the grant's
    # fqdns pattern/expiry/revocation state to decide whether to
    # auto-approve a new domain (see handle_new_order()'s trust-grant
    # branch).
    trust_grant_id = Column(Integer, ForeignKey('acme_trust_grants.id'), nullable=True)

    # Relationship with client_certificate_relations
    relations = relationship("ClientCertificateRelation", back_populates="client")

# Define the certificates table
class Certificate(Base):
    __tablename__ = 'certificates'

    # Real surrogate primary key - crtrequest.py/crtmanager.py/cltmanager.py
    # use this to name each certificate's own acme.sh --home directory and
    # to address a certificate by a short numeric ID on the CLI. Previously
    # this table had no such column (fqdns alone was the primary key) and
    # callers instead relied on SQLite's implicit, backend-specific rowid -
    # see issue.md/fixed-issues.md and TECHNICAL_REFERENCE.md's database backend section.
    id = Column(Integer, primary_key=True, autoincrement=True)
    fqdns = Column(_identifier_string(512), unique=True, nullable=False, index=True)
    public_key = Column(Text, nullable=False)
    private_key = Column(Text)
    intermediates = Column(Text)
    validity_end_date = Column(DateTime, nullable=False)
    last_update = Column(DateTime, default=_utcnow)
    # Which ACME CA acme.sh should use (see common.constants.ACME_PROVIDERS),
    # or MANUAL_ACME_PROVIDER for certificates uploaded locally that
    # crtrequest.py's ACME automation must never touch.
    # Long enough to also hold a raw ACME directory URL, not just one of the
    # short predefined provider names (see set_certificate_acme_provider()).
    acme_provider = Column(String(512), default=DEFAULT_ACME_PROVIDER)
    # True if the currently stored certificate came from a CA's staging/test
    # environment rather than its live one - see crtrequest.py's overwrite
    # rules (staging never clobbers a valid production cert, production
    # always clobbers staging).
    is_staging = Column(Boolean, default=False)
    # SHA-256 hex digest of the *currently stored* certificate's public key
    # (SubjectPublicKeyInfo, DER-encoded) - populated by both the traditional
    # self-generated-key issuance path and the ACME CSR-relay path. Used only
    # as a defensive cross-check that an installed certificate matches a
    # given order's CSR key (see ACME_SERVER_DESIGN.md §4.2) - not the
    # primary ACME issuance-tracking mechanism (that's AcmeOrder/
    # AcmeCertificate).
    key_fingerprint = Column(String(128), nullable=True, index=True)

    # Relationship with client_certificate_relations
    relations = relationship("ClientCertificateRelation", back_populates="certificate")

# Tracks every nonce this server has ever consumed - originally just
# registration's (secret proof + nonce + timestamp), now every post-
# registration request too (common/server_utils.py's handle_request()), so
# a captured message of any kind can't simply be replayed later.
class UsedNonce(Base):
    __tablename__ = 'used_nonces'

    nonce = Column(String(255), primary_key=True)
    created_at = Column(DateTime, default=_utcnow)

# Define the client_certificate_relations table for n:m relationship
class ClientCertificateRelation(Base):
    __tablename__ = 'client_certificate_relations'

    client_id = Column(Integer, ForeignKey('clients.id'), primary_key=True)
    fqdns = Column(_identifier_string(512), ForeignKey('certificates.fqdns'), primary_key=True)
    status = Column(Integer, nullable=False)
    permission_valid_until = Column(DateTime)
    # When this client last successfully retrieved this certificate's private
    # key (common/server_utils.py's handle_retrieve_request()) - NULL means
    # never downloaded since this column was added.
    last_download_at = Column(DateTime)
    # Snapshot of Certificate.validity_end_date *at the time of that
    # download* - the live Certificate row gets overwritten in place on
    # renewal (update_certificate()), so without this snapshot there is no
    # way to tell "the certificate this client actually has on disk expires
    # soon" once the server's own copy has since been renewed. NULL iff
    # last_download_at is NULL. See get_stale_certificate_downloads().
    last_download_validity_end_date = Column(DateTime)

    # Add check constraint using the proper SQLAlchemy syntax
    __table_args__ = (
        CheckConstraint('status IN (0, 1)', name='client_cert_status_check'),
    )
    
    # Relationships
    client = relationship("Client", back_populates="relations")
    certificate = relationship("Certificate", back_populates="relations")

# The sole authoritative record of one ACME order's CSR/finalize/issuance
# state (ACME_SERVER_DESIGN.md §4.3) - deliberately not spread across a
# mutable shared field on Certificate, which would let concurrent orders for
# the same fqdns silently clobber each other's state.
class AcmeOrder(Base):
    __tablename__ = 'acme_orders'

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_client_id = Column(Integer, ForeignKey('clients.id'), nullable=False, index=True)
    # Canonical (sorted, comma-joined) fqdns - same form ClientCertificateRelation
    # already uses. NOT unique - multiple orders (even concurrent ones) may
    # legitimately target the same fqdns; see AcmeProcessingLock for the
    # "only one processing at a time" rule. Retains a wildcard's literal
    # "*." prefix, exactly like Certificate.fqdns/ClientCertificateRelation.fqdns
    # already do.
    fqdns = Column(_identifier_string(512), ForeignKey('certificates.fqdns'), nullable=False, index=True)
    # The original identifiers array from newOrder, in the client's own
    # order/casing form - used only to render the order object's own
    # `identifiers` field back to the client exactly as submitted.
    identifiers_json = Column(Text, nullable=False)
    # Populated only once finalize has been ACCEPTED (passed full CSR
    # validation) - immutable from that point on.
    csr_pem = Column(Text, nullable=True)
    csr_key_fingerprint = Column(String(128), nullable=True, index=True)
    # The explicit, stored part of the order state machine - one of
    # 'pending', 'processing', 'valid', 'invalid'. Deliberately does NOT
    # include 'ready' - that's derived fresh at request time from
    # permission_is_active() on the matching ClientCertificateRelation.
    status = Column(String(16), nullable=False, default='pending')
    created_at = Column(DateTime, default=_utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    # Set the moment finalize is ACCEPTED (not on a badCSR rejection) - the
    # one-way commitment point authorization_status()/challenge_status() key
    # off of, since it never reverts once set.
    finalized_at = Column(DateTime, nullable=True)
    # Retry/backoff bookkeeping for crtrequest.py's issuance pass.
    issuance_attempts = Column(Integer, nullable=False, default=0)
    last_issuance_attempt_at = Column(DateTime, nullable=True)
    last_issuance_error = Column(Text, nullable=True)
    next_issuance_attempt_at = Column(DateTime, nullable=True)  # NULL = eligible immediately

# Immutable, per-order certificate record (ACME_SERVER_DESIGN.md §4.3.1) -
# NOT the same as the shared, mutable Certificate row, which gets
# overwritten in place on every renewal. Fixes the bug where a later order's
# renewal would silently make an earlier order's certificate-download
# endpoint start returning the wrong certificate.
class AcmeCertificate(Base):
    __tablename__ = 'acme_certificates'

    id = Column(Integer, primary_key=True, autoincrement=True)
    order_id = Column(Integer, ForeignKey('acme_orders.id'), nullable=False, unique=True, index=True)
    # This order's own certificate PEM + chain, exactly as installed at the
    # moment this order completed - never touched again afterward, even if a
    # later order for the same fqdns supersedes it in Certificate.
    certificate_pem = Column(Text, nullable=False)
    intermediates = Column(Text, nullable=True)
    key_fingerprint = Column(String(128), nullable=False, index=True)
    validity_end_date = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=_utcnow, nullable=False)

# Makes the "one processing order per fqdns" rule atomic
# (ACME_SERVER_DESIGN.md §4.4.1) - a plain lock table rather than a partial
# unique index, since MySQL/MariaDB (one of this project's three supported
# backends) has no equivalent to a filtered/partial unique index. The
# database's own primary-key constraint on `fqdns` is what actually enforces
# atomicity: a second concurrent finalize for the same fqdns gets a real
# IntegrityError on its own INSERT attempt.
class AcmeProcessingLock(Base):
    __tablename__ = 'acme_processing_locks'

    fqdns = Column(_identifier_string(512), primary_key=True)
    order_id = Column(Integer, ForeignKey('acme_orders.id'), nullable=False)
    locked_at = Column(DateTime, default=_utcnow, nullable=False)

# Server-issued, single-use ACME replay-nonces (newNonce/every Replay-Nonce
# response header) - the reverse direction from UsedNonce, which consumes
# client-picked nonces for the traditional protocol.
class AcmeNonce(Base):
    __tablename__ = 'acme_nonces'

    nonce = Column(String(255), primary_key=True)
    created_at = Column(DateTime, default=_utcnow, nullable=False)

# An admin-issued, out-of-band pre-shared credential that lets a trusted
# ACME client skip both manual admin steps (cltmanager.py acme_confirm and
# assign) - explicitly a reduced-security convenience for devices the admin
# already trusts, never applied to the default self-registration flow. Two
# methods, mutually exclusive per row (enforced in create_acme_trust_grant(),
# not a DB constraint - simpler and portable across backends):
#   - EAB (RFC 8555 SS7.3.4): eab_kid/eab_hmac_key_encrypted set, verified via
#     common/acme_jose.py's verify_eab_jws(). Works with any spec-compliant
#     ACME client (e.g. FortiOS 7.6.3+).
#   - contact-token: contact_token_hash set, matched against a plus-address
#     token embedded in newAccount's plain `contact` field - the fallback for
#     clients with no EAB support at all (e.g. FortiOS < 7.6.3, whose ACME
#     config exposes only a free-text Email field).
# Reusable (not single-use) with an optional expiry, per explicit product
# decision 2026-09-20 - the same grant can bootstrap multiple devices/
# accounts, or the same account re-registering with a new key, until it's
# revoked or its expiry passes.
class AcmeTrustGrant(Base):
    __tablename__ = 'acme_trust_grants'

    id = Column(Integer, primary_key=True, autoincrement=True)
    label = Column(Text, nullable=False)
    # EAB method - hmac_key stored encrypted at rest (common/db_crypto.py's
    # encrypt_for_storage(), the same envelope Certificate.private_key
    # already uses) since, unlike a password/token, HMAC verification needs
    # the actual secret bytes at verify time, not just a one-way hash.
    eab_kid = Column(String(255), unique=True, nullable=True, index=True)
    eab_hmac_key_encrypted = Column(Text, nullable=True)
    # contact-token method - only ever a hash (SHA-256 hex of the raw
    # high-entropy token), since this one only needs equality comparison,
    # never a reversible secret.
    contact_token_hash = Column(String(64), unique=True, nullable=True, index=True)
    # Comma-separated glob patterns (fnmatch semantics - '*' matches across
    # dots too, more permissive than a TLS wildcard cert's single-label
    # rule; documented plainly in cltmanager.py's own --help/printed output)
    # checked against a requested fqdns in handle_new_order() to decide
    # whether to auto-approve it instead of leaving it pending.
    allowed_fqdns_pattern = Column(Text, nullable=False)
    created_at = Column(DateTime, default=_utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    # Soft-revoke (keeps audit history) rather than deleting the row -
    # matches this project's general preference for a "when did this
    # happen" timestamp over a bare boolean flag.
    revoked_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    use_count = Column(Integer, nullable=False, default=0)

# The revision representing the schema as it looked immediately before
# certificates.id existed - see alembic/versions/0001_baseline.py. Lives
# here (not dbmigrate.py) alongside _SCHEMA_REVISIONS/_detect_stamp_revision
# below - see check_schema_is_current()'s docstring for why: this module
# needs the exact same "what revision does this schema match" logic
# dbmigrate.py uses to stamp a pre-existing database, and dbmigrate.py
# already imports this module, so the shared logic has to live on this
# side of that import to avoid a cycle. dbmigrate.py imports these names
# from here instead of defining its own copy.
BASELINE_REVISION = '0001_baseline'

def _has_column(inspector, table, column):
    return column in {col['name'] for col in inspector.get_columns(table)}

def _has_last_download_at(inspector):
    return _has_column(inspector, 'client_certificate_relations', 'last_download_at')

# Newest-first: each entry is (revision_id, predicate). _detect_stamp_revision()
# walks this looking for the first (newest) one whose predicate is already
# true, telling us exactly how far an unstamped, pre-existing database's
# schema has already progressed - so `upgrade head` only ever applies
# migrations it genuinely still needs, and check_schema_is_current() below
# can tell a genuinely-current database from a stale one without a second,
# separately-maintained list that can silently fall out of sync with this
# one (see the 2026-09-20 fixed-issues.md entry - that's exactly what
# happened: a hand-maintained duplicate check in check_schema_is_current()
# was updated for one migration and then forgotten for the next two).
#
# A hardcoded 2-way version of this check (just certificates.id) previously
# mis-stamped straight to 'head' once a 3rd schema-changing revision
# existed, silently skipping it (see fixed-issues.md) - adding a future
# revision here is a one-line addition to this list, not a new branch, so
# that mistake can't repeat itself.
#
# '0005_drop_registration_nonces' is the one entry that isn't a plain column
# check: that migration only *drops* a table, leaving no new column to look
# for - checked here as "already at the 0004 column level, AND
# registration_nonces is already gone" (real fresh installs never had it in
# the first place; an existing one only loses it once 0005 actually runs) -
# column-only detection alone would otherwise be unable to tell "genuinely
# at 0005" apart from "at 0004, 0005 just hasn't run yet", exactly the class
# of bug this same list was already rewritten once to avoid (see
# fixed-issues.md). Every entry from '0006_acme_support' on is a plain
# column check, since none of those migrations need the drop-table special
# case 0005 needed.
_SCHEMA_REVISIONS = [
    ('head', lambda insp: _has_column(insp, 'clients', 'last_connection_ip')),
    ('0008_acme_trust_grants', lambda insp: _has_column(insp, 'clients', 'trust_grant_id')),
    ('0007_acme_ip_pinning', lambda insp: _has_column(insp, 'clients', 'allowed_source_ip')),
    ('0006_acme_support', lambda insp: _has_column(insp, 'clients', 'client_kind')),
    ('0005_drop_registration_nonces', lambda insp: _has_last_download_at(insp)
                                                    and 'registration_nonces' not in insp.get_table_names()),
    ('0004_download_tracking', _has_last_download_at),
    ('0003_client_version', lambda insp: _has_column(insp, 'clients', 'client_version')),
    ('0002_certificate_id', lambda insp: _has_column(insp, 'certificates', 'id')),
]

def _detect_stamp_revision(inspector):
    """Which revision an unstamped, pre-existing database's actual schema
    matches - see _SCHEMA_REVISIONS above."""
    for revision_id, predicate in _SCHEMA_REVISIONS:
        if predicate(inspector):
            return revision_id
    return BASELINE_REVISION

class SchemaOutOfDate(Exception):
    """Raised by check_schema_is_current() when an existing database predates
    the current ORM schema (e.g. a certificates table with no `id` column) -
    see scs-dbmigrate."""
    pass

def check_schema_is_current(db_file_path=None):
    """Read-only guard against starting up against a stale schema. Must be
    called *before* init_database() calls Base.metadata.create_all(), not
    after - see the 2026-09-17 fixed-issues.md entry this was extended for:
    create_all() only ever creates missing tables, so run against a
    pre-existing database that predates a migration adding both new tables
    *and* new columns on an existing table (e.g. 0006_acme_support), it
    silently creates the new tables while leaving the existing table's new
    columns missing - a partially-migrated state scs-dbmigrate's own
    stamp-detection can't cleanly recover from afterwards. Checking (and
    refusing to proceed) first means create_all() never runs against a
    database in that in-between state at all.

    Reuses _detect_stamp_revision() - the exact same logic scs-dbmigrate
    itself uses to figure out where a pre-existing database's schema
    actually stands - rather than a second, separately hand-maintained list
    of column checks here. That second list existed for a while (one check
    added for 0006_acme_support) and was never extended for 0007 or 0008,
    which is exactly what let a database land in this stale, half-upgraded
    state twice in a row before this fix (2026-09-20 fixed-issues.md) - a
    single shared source of truth means a future migration only ever needs
    its _SCHEMA_REVISIONS entry added once, not once per module.
    """
    engine = get_db_engine(db_file_path)
    inspector = inspect(engine)
    if 'certificates' not in inspector.get_table_names():
        return  # brand new database - init_database()'s create_all() handles this
    detected = _detect_stamp_revision(inspector)
    if detected != 'head':
        raise SchemaOutOfDate(
            f"This database's schema matches revision '{detected}', not the current schema. "
            "Run 'scs-dbmigrate upgrade-schema' once before starting this tool again.")

def init_database(db_file_path=None):
    """Initialize the database and create tables if they don't exist.

    Only ever creates missing tables (Base.metadata.create_all()) - never
    alters an existing table's columns. That used to also happen here via a
    hand-rolled, sqlite-only ALTER TABLE migration; it's been replaced by the
    standalone scs-dbmigrate tool (Alembic-based, portable across backends)
    so this function - and everything that calls it at routine startup -
    stays free of migration logic. See check_schema_is_current().

    Directory and file permissions are group-shared (not owner-only) - unlike
    client.py's own config, this DB is meant to be read/written by both
    server.py and web_admin's PHP process, which normally run as different OS
    users (see common/constants.py's SHARED_DIR_MODE/SHARED_FILE_MODE docstring
    for the deployment implications: a shared unix group is required for this
    to actually grant access, not just widen the mode bits). Only applicable
    to the sqlite backend - a network database's directory/file permissions
    are the DBMS's own concern.
    """
    if db_file_path is None:
        db_file_path = DEFAULT_DB_FILE
    if _network_db_url is None:
        db_dir = os.path.dirname(db_file_path)
        if db_dir:
            ensure_secure_dir(db_dir, mode=SHARED_DIR_MODE)
    check_schema_is_current(db_file_path)
    engine = get_db_engine(db_file_path)
    Base.metadata.create_all(engine)
    if _network_db_url is None and os.path.exists(db_file_path):
        os.chmod(db_file_path, SHARED_FILE_MODE)
    print("Database initialized successfully")

def get_db_session(db_file_path=None):
    """Get a database session"""
    engine = get_db_engine(db_file_path)
    Session = sessionmaker(bind=engine)
    return Session()

def get_client(client_id):
    """Get client information by client ID"""
    session = get_db_session()
    try:
        client = session.query(Client).filter_by(client_id=client_id).first()
        return client
    except Exception as e:
        print(f"Error getting client: {e}")
        return None
    finally:
        session.close()

def save_client(client_id, public_key, status='registered', client_version=None):
    """Save client information to database"""
    session = get_db_session()
    try:
        # Check if client already exists
        existing_client = session.query(Client).filter_by(client_id=client_id).first()

        if existing_client:
            # Client already exists - do not overwrite
            return False

        # Create new client with default values for all required fields
        client = Client(
            client_id=client_id,
            public_key=public_key,
            status=status,
            client_version=client_version
        )
        
        session.add(client)
        session.commit()
        return True
    except Exception as e:
        print(f"Error saving client: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def consume_nonce(nonce, max_age_seconds):
    """Atomically record a nonce, rejecting replays - used by both
    registration and every general request's anti-replay check (see
    common/server_utils.py's handle_registration()/handle_request()).

    Returns True the first time a given nonce is seen (and records it), False
    if that nonce has already been consumed. Also opportunistically prunes
    nonces older than max_age_seconds, since they've already fallen outside the
    timestamp window checked separately and can never be replayed successfully
    again anyway.

    internal/security/SECURITY_FINDINGS.md finding #19: this used to check-then-insert as two
    separate queries, a TOCTOU race under concurrent requests carrying the
    same nonce (unlike consume_acme_nonce()'s already-atomic delete-based
    consumption). Fixed the same way create_certificate_if_missing() above
    handles its own equivalent race: insert first and let UsedNonce.nonce's
    existing primary-key constraint be the actual source of atomicity,
    catching IntegrityError as "already consumed" rather than pre-checking.
    """
    session = get_db_session()
    try:
        cutoff = _utcnow() - timedelta(seconds=max_age_seconds)
        session.query(UsedNonce).filter(UsedNonce.created_at < cutoff).delete()
        session.commit()

        session.add(UsedNonce(nonce=nonce))
        session.commit()
        return True
    except IntegrityError:
        session.rollback()
        return False
    except Exception as e:
        print(f"Error consuming registration nonce: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def get_client_status(client_id):
    """Get client status by client ID"""
    session = get_db_session()
    try:
        client = session.query(Client).filter_by(client_id=client_id).first()
        return client.status if client else None
    except Exception as e:
        print(f"Error getting client status: {e}")
        return None
    finally:
        session.close()

def update_client_status(client_id, status):
    """Update client status"""
    session = get_db_session()
    try:
        client = session.query(Client).filter_by(client_id=client_id).first()
        if client:
            client.status = status
            session.commit()
            return True
        return False
    except Exception as e:
        print(f"Error updating client status: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def update_client_version(client_id, client_version):
    """Record the sslcrtsrv version most recently reported by this client -
    refreshed on every register/request message (see
    common/network_utils.py's receive_secure_message() and
    common/server_utils.py's handle_registration())."""
    session = get_db_session()
    try:
        client = session.query(Client).filter_by(client_id=client_id).first()
        if client:
            client.client_version = client_version
            session.commit()
            return True
        return False
    except Exception as e:
        print(f"Error updating client version: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def update_client_connection_success(client_id):
    """Update client's last successful connection"""
    session = get_db_session()
    try:
        client = session.query(Client).filter_by(client_id=client_id).first()
        if client:
            client.last_successful_connection = _utcnow()
            client.unsuccessful_attempts = 0
            client.first_unsuccessful_connection = None
            session.commit()
            return True
        return False
    except Exception as e:
        print(f"Error updating client connection success: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def update_client_last_ip(client_id, ip):
    """Record the source address of a client's most recent successful
    connection/request - called from both protocols' own success paths
    (common/network_utils.py's receive_secure_message() for the
    traditional protocol, common/acme_server_utils.py's verify_acme_jws()
    for ACME), deliberately kept separate from
    update_client_connection_success() above: that function also sets
    last_successful_connection, a field ACME accounts never populate at
    all (Client.last_connection_ip's own docstring explains why) - reusing
    it here would incorrectly start setting that field for ACME too."""
    session = get_db_session()
    try:
        client = session.query(Client).filter_by(client_id=client_id).first()
        if client:
            client.last_connection_ip = ip
            session.commit()
            return True
        return False
    except Exception as e:
        print(f"Error updating client last IP: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def update_client_connection_failure(client_id):
    """Update client's unsuccessful connection attempt"""
    session = get_db_session()
    try:
        client = session.query(Client).filter_by(client_id=client_id).first()
        if client:
            client.unsuccessful_attempts += 1
            if not client.first_unsuccessful_connection:
                client.first_unsuccessful_connection = _utcnow()
            session.commit()
            return True
        return False
    except Exception as e:
        print(f"Error updating client connection failure: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def get_all_clients():
    """Get all clients"""
    session = get_db_session()
    try:
        clients = session.query(Client).order_by(Client.registration_date.desc()).all()
        return clients
    except Exception as e:
        print(f"Error getting all clients: {e}")
        return []
    finally:
        session.close()

def get_unconfirmed_clients():
    """Get all unconfirmed clients"""
    session = get_db_session()
    try:
        clients = session.query(Client).filter(Client.status != 'confirmed').order_by(Client.registration_date.desc()).all()
        return clients
    except Exception as e:
        print(f"Error getting unconfirmed clients: {e}")
        return []
    finally:
        session.close()

def get_pending_clients_with_requests():
    """Every client needing admin attention: not yet confirmed, and/or has at
    least one pending (status=0) certificate permission request. Covers both
    brand-new registrations and already-confirmed clients requesting a new
    domain. Two queries total regardless of client count, so callers (like an
    admin dashboard) don't have to run one query per client to build this.

    Returns a list of dicts: {'client': Client, 'pending_fqdns': [str, ...]},
    newest registration first.
    """
    session = get_db_session()
    try:
        pending = session.query(ClientCertificateRelation).filter(
            ClientCertificateRelation.status == 0).all()
        pending_by_client = {}
        for relation in pending:
            pending_by_client.setdefault(relation.client_id, []).append(relation.fqdns)

        candidates = {c.id: c for c in
                      session.query(Client).filter(Client.status != 'confirmed').all()}
        missing_ids = set(pending_by_client) - set(candidates)
        if missing_ids:
            for c in session.query(Client).filter(Client.id.in_(missing_ids)).all():
                candidates[c.id] = c

        rows = [{'client': c, 'pending_fqdns': pending_by_client.get(c.id, [])}
                for c in candidates.values()]
        rows.sort(key=lambda r: r['client'].registration_date or datetime.min, reverse=True)
        return rows
    except Exception as e:
        print(f"Error getting pending clients with requests: {e}")
        return []
    finally:
        session.close()

def delete_client_by_id(client_id):
    """Delete a client by ID, along with any client_certificate_relations
    rows pointing at it. Those relations must be removed first - client_id is
    part of that table's composite primary key, and with no cascade
    configured on the relationship, SQLAlchemy would otherwise try to null it
    out to satisfy the FK and raise (visible here as a caught exception that
    made every delete of a client with any certificate permission silently
    fail, always returning False - see issue.md). Deleting a client is
    expected to take its permissions with it, unlike delete_certificate_placeholder()'s
    deliberate non-cascade in the other direction.

    For an ACME account (client_kind='acme'), also cascades through its
    AcmeOrder rows first (ACME_SERVER_DESIGN.md §7.2): AcmeProcessingLock and
    AcmeCertificate both reference acme_orders.id, so they must be deleted
    before the orders themselves, or MySQL/PostgreSQL's enforced FK
    constraints (unlike SQLite unless PRAGMA foreign_keys is set) would
    reject the deletion outright. A no-op for a client with no AcmeOrder
    rows (every 'custom' client, and any never-ordering ACME account)."""
    session = get_db_session()
    try:
        client = session.query(Client).filter_by(id=client_id).first()
        if client:
            order_ids = [row[0] for row in session.query(AcmeOrder.id)
                         .filter_by(account_client_id=client_id).all()]
            if order_ids:
                session.query(AcmeProcessingLock).filter(
                    AcmeProcessingLock.order_id.in_(order_ids)).delete(synchronize_session=False)
                session.query(AcmeCertificate).filter(
                    AcmeCertificate.order_id.in_(order_ids)).delete(synchronize_session=False)
                session.query(AcmeOrder).filter(
                    AcmeOrder.id.in_(order_ids)).delete(synchronize_session=False)
            session.query(ClientCertificateRelation).filter_by(client_id=client_id).delete()
            session.delete(client)
            session.commit()
            return True
        return False
    except Exception as e:
        print(f"Error deleting client: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def get_certificate(fqdns):
    """Get certificate information by FQDNs"""
    session = get_db_session()
    try:
        certificate = session.query(Certificate).filter_by(fqdns=fqdns).first()
        return certificate
    except Exception as e:
        print(f"Error getting certificate: {e}")
        return None
    finally:
        session.close()

def get_certificate_info(fqdns):
    """Get detailed certificate information including parts availability"""
    session = get_db_session()
    try:
        certificate = session.query(Certificate).filter_by(fqdns=fqdns).first()
        if not certificate:
            return None
        
        # Check which parts are present
        key_present = bool(certificate.private_key)
        cert_present = bool(certificate.public_key)
        intermediate_present = bool(certificate.intermediates)
        
        # Extract validity information 
        validity_end = certificate.validity_end_date
        validity_start = certificate.last_update
        
        # Return detailed information
        return {
            'fqdns': certificate.fqdns,
            'validity_end_date': validity_end,
            'format': 'PEM',  # Assuming PEM format as per the codebase
            'certifier': 'Unknown',  # Would need to parse certificate to get actual certifier
            'key_present': key_present,
            'cert_present': cert_present,
            'intermediate_present': intermediate_present,
            'parts_present': [part for part, present in [('key', key_present), ('certificate', cert_present), ('intermediate', intermediate_present)] if present],
            'id': certificate.fqdns  # Using fqdns as ID for consistency
        }
    except Exception as e:
        print(f"Error getting certificate info: {e}")
        return None
    finally:
        session.close()

def save_certificate(fqdns, public_key, private_key=None, intermediates=None, validity_end_date=None,
                      acme_provider="manual"):
    """Save certificate information to database. Used for locally-uploaded certificates
    (crtmanager.py addlocal), so acme_provider defaults to 'manual' and is_staging is
    always False - crtrequest.py's ACME automation must never touch these rows."""
    session = get_db_session()
    try:
        # Check if certificate already exists
        existing_cert = session.query(Certificate).filter_by(fqdns=fqdns).first()

        if existing_cert:
            # Update existing certificate
            existing_cert.public_key = public_key
            existing_cert.private_key = private_key
            existing_cert.intermediates = intermediates
            existing_cert.validity_end_date = validity_end_date
            existing_cert.last_update = _utcnow()
            existing_cert.acme_provider = acme_provider
            existing_cert.is_staging = False
        else:
            # Create new certificate
            certificate = Certificate(
                fqdns=fqdns,
                public_key=public_key,
                private_key=private_key,
                intermediates=intermediates,
                validity_end_date=validity_end_date,
                acme_provider=acme_provider,
                is_staging=False,
            )
            session.add(certificate)

        session.commit()
        return True
    except Exception as e:
        print(f"Error saving certificate: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def update_certificate(fqdns, public_key, private_key, intermediates, validity_end_date, is_staging=False,
                        key_fingerprint=None):
    """Update certificate information in the database after an ACME issuance/renewal.
    Does not touch acme_provider - that's set once at creation and only changed via
    crtmanager.py set-provider.

    key_fingerprint is optional and only written when explicitly given (not
    None) - existing call sites that don't pass it leave the column
    untouched, matching its NULL-until-first-write default."""
    session = get_db_session()
    try:
        certificate = session.query(Certificate).filter_by(fqdns=fqdns).first()
        if certificate:
            certificate.public_key = public_key
            certificate.private_key = private_key
            certificate.intermediates = intermediates
            certificate.validity_end_date = validity_end_date
            certificate.last_update = _utcnow()
            certificate.is_staging = is_staging
            if key_fingerprint is not None:
                certificate.key_fingerprint = key_fingerprint
            session.commit()
            return True
        return False
    except Exception as e:
        print(f"Error updating certificate: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def get_all_certificates():
    """Get all certificates, soonest-to-expire first"""
    session = get_db_session()
    try:
        certificates = session.query(Certificate).order_by(Certificate.validity_end_date.asc()).all()
        return certificates
    except Exception as e:
        print(f"Error getting all certificates: {e}")
        return []
    finally:
        session.close()

def add_client_certificate_relation(client_id, fqdns, status=0, valid_until=None):
    """Add a relationship between a client and a certificate with a status"""
    session = get_db_session()
    try:
        # Check if relationship already exists
        existing_relation = session.query(ClientCertificateRelation).filter_by(client_id=client_id, fqdns=fqdns).first()
        
        if existing_relation:
            # Update existing relation
            existing_relation.status = status
            existing_relation.permission_valid_until = valid_until
        else:
            # Create new relation
            relation = ClientCertificateRelation(
                client_id=client_id,
                fqdns=fqdns,
                status=status,
                permission_valid_until=valid_until
            )
            session.add(relation)
        
        session.commit()
        return True
    except Exception as e:
        print(f"Error adding client-certificate relation: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def permission_is_active(relation) -> bool:
    """True if a ClientCertificateRelation currently grants access: status
    must be 1 (active - not pending/inactive) and, if permission_valid_until
    is set, it must not yet have passed. Every access-gating check in
    common/server_utils.py should use this instead of a bare
    `relation.status == 1` comparison, so a client's permission actually
    stops working once it expires (see issue.md's entry on
    permission_valid_until previously being modeled but never enforced)."""
    if relation is None or relation.status != 1:
        return False
    if relation.permission_valid_until is not None and relation.permission_valid_until <= _utcnow():
        return False
    return True

def set_permission_valid_until(client_id, fqdns, valid_until):
    """Set (or clear, with valid_until=None) the expiry date on an existing
    client-certificate relation, without touching its status. Returns False
    if no such relation exists yet - use add_client_certificate_relation()/
    assign_certificate_permissions() to create one first."""
    session = get_db_session()
    try:
        relation = session.query(ClientCertificateRelation).filter_by(client_id=client_id, fqdns=fqdns).first()
        if not relation:
            return False
        relation.permission_valid_until = valid_until
        session.commit()
        return True
    except Exception as e:
        print(f"Error setting permission expiry: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def record_certificate_download(client_id, fqdns, validity_end_date):
    """Record that client_id just successfully retrieved fqdns's private
    key/certificate - called from common/server_utils.py's
    handle_retrieve_request() right after the private key is decrypted (a
    real, successful retrieval only). Stores both the download timestamp and
    a snapshot of the certificate's validity_end_date as of this download -
    see get_stale_certificate_downloads() for why the snapshot, not the live
    Certificate row, is what a staleness check must compare against.

    Returns False if no such client-certificate relation exists (shouldn't
    happen in practice - retrieval already required an active permission row
    to reach this point) rather than raising."""
    session = get_db_session()
    try:
        relation = session.query(ClientCertificateRelation).filter_by(client_id=client_id, fqdns=fqdns).first()
        if not relation:
            return False
        relation.last_download_at = _utcnow()
        relation.last_download_validity_end_date = validity_end_date
        session.commit()
        return True
    except Exception as e:
        print(f"Error recording certificate download: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def get_stale_certificate_downloads(days=21):
    """Every active (status==1, permission not expired - same condition as
    permission_is_active()) client-certificate relation whose last recorded
    downloaded copy is within `days` of expiring (or already expired), or
    that the client has never actually downloaded at all (last_download_at
    IS NULL - included unconditionally, since there's no date to compare and
    an admin still needs to see it). Compares the *downloaded snapshot's*
    expiry, not Certificate.validity_end_date directly, so a certificate
    that's since been renewed but whose client hasn't re-fetched yet still
    shows up here even though the live row's own expiry looks fine.

    Used by crtmanager.py's `warn-stale-downloads`. Returns a flat list of
    dicts (client_id, fqdns, last_download_at, downloaded_validity_end_date,
    current_validity_end_date, is_renewed_since_download, never_downloaded),
    ordered by client_id then by downloaded-expiry (soonest/never-downloaded
    first) within each client, for a grouped per-client report."""
    session = get_db_session()
    try:
        cutoff = _utcnow() + timedelta(days=days)
        permission_active_clause = or_(
            ClientCertificateRelation.permission_valid_until.is_(None),
            ClientCertificateRelation.permission_valid_until > _utcnow())
        results = (session.query(ClientCertificateRelation, Client, Certificate)
                   .join(Client, ClientCertificateRelation.client_id == Client.id)
                   .join(Certificate, ClientCertificateRelation.fqdns == Certificate.fqdns)
                   .filter(ClientCertificateRelation.status == 1, permission_active_clause)
                   .filter(or_(
                       ClientCertificateRelation.last_download_at.is_(None),
                       ClientCertificateRelation.last_download_validity_end_date <= cutoff))
                   # NULLS FIRST isn't valid syntax on MySQL/MariaDB (only
                   # PostgreSQL/Oracle support it natively, and SQLAlchemy's
                   # MySQL dialect doesn't emulate it) - a portable CASE
                   # expression (0 for "never downloaded", 1 otherwise) sorts
                   # those rows first on every backend without relying on
                   # dialect-specific SQL.
                   .order_by(Client.client_id,
                             case((ClientCertificateRelation.last_download_at.is_(None), 0), else_=1),
                             ClientCertificateRelation.last_download_validity_end_date.asc())
                   .all())
    except Exception as e:
        print(f"Error getting stale certificate downloads: {e}")
        return []
    finally:
        session.close()

    rows = []
    for relation, client, cert in results:
        rows.append({
            'client_id': client.client_id,
            'fqdns': relation.fqdns,
            'last_download_at': relation.last_download_at,
            'downloaded_validity_end_date': relation.last_download_validity_end_date,
            'current_validity_end_date': cert.validity_end_date,
            'is_renewed_since_download': (
                relation.last_download_validity_end_date is not None
                and cert.validity_end_date is not None
                and relation.last_download_validity_end_date < cert.validity_end_date),
            'never_downloaded': relation.last_download_at is None,
        })
    return rows

def get_client_certificate_relations(client_id):
    """Get all certificate relations for a specific client"""
    session = get_db_session()
    try:
        relations = session.query(ClientCertificateRelation).filter_by(client_id=client_id).all()
        return relations
    except Exception as e:
        print(f"Error getting client certificate relations: {e}")
        return []
    finally:
        session.close()

def get_client_certificate_relation(client_id, fqdns):
    """Get a specific client-certificate relation"""
    session = get_db_session()
    try:
        relation = session.query(ClientCertificateRelation).filter_by(client_id=client_id, fqdns=fqdns).first()
        return relation
    except Exception as e:
        print(f"Error getting client certificate relation: {e}")
        return None
    finally:
        session.close()

def delete_client_certificate_relation(client_id, fqdns):
    """Remove one client-certificate relation outright (as opposed to
    changing its status) - used by cltmanager.py's `revoke_permission` for a
    single fqdns (as distinct from its `all` case, which uses
    delete_all_client_certificate_relations()). Returns False if no such
    relation exists."""
    session = get_db_session()
    try:
        relation = session.query(ClientCertificateRelation).filter_by(client_id=client_id, fqdns=fqdns).first()
        if not relation:
            return False
        session.delete(relation)
        session.commit()
        return True
    except Exception as e:
        print(f"Error deleting client certificate relation: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def update_client_certificate_status(client_id, fqdns, status):
    """Update the status of a client-certificate relationship"""
    session = get_db_session()
    try:
        relation = session.query(ClientCertificateRelation).filter_by(client_id=client_id, fqdns=fqdns).first()
        if relation:
            relation.status = status
            session.commit()
            return True
        return False
    except Exception as e:
        print(f"Error updating client-certificate relation status: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def get_certificates_for_client(client_id):
    """Get all certificates for a specific client with their status"""
    session = get_db_session()
    try:
        # Join ClientCertificateRelation with Certificate to get certificate data
        result = session.query(ClientCertificateRelation, Certificate).filter_by(client_id=client_id).join(Certificate).all()
        return result
    except Exception as e:
        print(f"Error getting certificates for client: {e}")
        return []
    finally:
        session.close()

def get_clients_for_certificate(fqdns):
    """Get all clients that have access to a specific certificate"""
    session = get_db_session()
    try:
        # Join ClientCertificateRelation with Client to get client data
        result = session.query(ClientCertificateRelation, Client).filter_by(fqdns=fqdns).join(Client).all()
        return result
    except Exception as e:
        print(f"Error getting clients for certificate: {e}")
        return []
    finally:
        session.close()

def get_all_client_certificate_relations_with_certs():
    """Every ClientCertificateRelation paired with its Certificate row (or
    None if no certificate exists yet for that fqdns, e.g. a still-pending
    request) - one query covering every relation across all clients, so
    callers summarizing per-client certificate counts don't need an N+1
    lookup (one query per client) to get there."""
    session = get_db_session()
    try:
        return session.query(ClientCertificateRelation, Certificate).outerjoin(
            Certificate, ClientCertificateRelation.fqdns == Certificate.fqdns).all()
    except Exception as e:
        print(f"Error getting client certificate relations with certs: {e}")
        return []
    finally:
        session.close()

def get_certificate_id(fqdns):
    """This certificate's surrogate id, handed out by crtrequest.py's
    create_certificate_entry() as "cert_id" to name each certificate's own
    isolated acme.sh --home directory (cert_home_dir/cert-<id> - see
    crtrequest.certificate_directory_path()). Returns None if no row exists
    for this fqdns. Must be looked up *before* delete_certificate(), which
    removes the row this query depends on.

    Before the `id` column existed, this returned SQLite's own internal
    rowid via raw SQL - a SQLite-only concept with no equivalent on MySQL/
    PostgreSQL (see issue.md/fixed-issues.md).
    """
    session = get_db_session()
    try:
        return session.query(Certificate.id).filter_by(fqdns=fqdns).scalar()
    finally:
        session.close()

def get_certificate_fqdns_by_id(cert_id):
    """Reverse of get_certificate_id(): the fqdns for a given surrogate id,
    or None if no such certificate exists. Used to resolve a numeric
    certificate ID passed on the CLI (crtmanager.py/cltmanager.py) back to
    the fqdns every other database function keys on."""
    session = get_db_session()
    try:
        return session.query(Certificate.fqdns).filter_by(id=cert_id).scalar()
    finally:
        session.close()

def resolve_certificate_by_identifier(identifier):
    """Look up a certificate by numeric id (if identifier parses as one) or
    by FQDNs otherwise - shared by crtmanager.py's `delete`/`set-provider`
    commands and cltmanager.py's certificate-permission commands."""
    try:
        cert_id = int(identifier)
    except ValueError:
        return get_certificate(identifier)
    fqdns = get_certificate_fqdns_by_id(cert_id)
    return get_certificate(fqdns) if fqdns is not None else get_certificate(identifier)

def set_certificate_acme_provider(fqdns, provider):
    """Change which ACME service (or the manual-import marker) a certificate
    uses. Pure DB update, no validation/printing - see crtmanager.py's
    set_certificate_provider() and update_certificate() (the file-import
    one) for the CLI-facing callers."""
    session = get_db_session()
    try:
        session.query(Certificate).filter_by(fqdns=fqdns).update({'acme_provider': provider})
        session.commit()
        return True
    except Exception as e:
        print(f"Error setting ACME provider: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def get_active_certificate_assignments():
    """{fqdns: [client_id, ...]} for every currently-active (status=1)
    client-certificate relation, across all clients/certificates in one
    query - used by admin certificate listings that show which clients have
    access to each certificate, without an N+1 query per certificate."""
    session = get_db_session()
    try:
        rows = (session.query(ClientCertificateRelation.fqdns, Client.client_id)
                .join(Client, ClientCertificateRelation.client_id == Client.id)
                .filter(ClientCertificateRelation.status == 1)
                .order_by(ClientCertificateRelation.fqdns).all())
        result = {}
        for fqdns, client_id in rows:
            result.setdefault(fqdns, []).append(client_id)
        return result
    except Exception as e:
        print(f"Error getting active certificate assignments: {e}")
        return {}
    finally:
        session.close()

def get_requested_certificate_rows():
    """One row per pending (status=0) or not-yet-issued certificate request:
    a client-certificate relation that either hasn't been approved yet, or
    has been approved but no certificate has actually been issued for its
    fqdns yet. Used by crtmanager.py's `list --requested`/`list --clients`
    (the "Requested Certificates" section) and cltmanager.py."""
    session = get_db_session()
    try:
        issued_fqdns = session.query(Certificate.fqdns).filter(Certificate.last_update.isnot(None))
        results = (session.query(ClientCertificateRelation, Client)
                   .join(Client, ClientCertificateRelation.client_id == Client.id)
                   .filter(or_(ClientCertificateRelation.status == 0,
                               ~ClientCertificateRelation.fqdns.in_(issued_fqdns)))
                   .order_by(ClientCertificateRelation.permission_valid_until.desc()).all())
    except Exception as e:
        print(f"Error getting requested certificate rows: {e}")
        return []
    finally:
        session.close()

    rows = []
    for relation, client in results:
        status = str(relation.status)
        status_text = "unassigned" if status == "0" else ("requested" if status == "1" else status)
        rows.append({
            'client_id': client.client_id,
            'fqdns': relation.fqdns,
            'status': status,
            'status_text': status_text,
            'valid_until': relation.permission_valid_until if relation.permission_valid_until else "N/A",
        })
    return rows

def get_client_by_id_or_client_id(identifier):
    """Get a Client row by either its numeric database id or its string
    client_id - shared by cltmanager.py's client-identifying commands."""
    session = get_db_session()
    try:
        try:
            db_id = int(identifier)
            client = session.query(Client).filter_by(id=db_id).first()
            if client:
                return client
        except ValueError:
            pass
        return session.query(Client).filter_by(client_id=identifier).first()
    finally:
        session.close()

def get_pending_client_certificate_relations(client_id=None):
    """All pending (status=0) client-certificate relations, optionally
    scoped to one client's numeric database id. Used by cltmanager.py's
    `clean_requests` to preview what a matching delete_pending_client_certificate_relations()
    call would remove."""
    session = get_db_session()
    try:
        query = session.query(ClientCertificateRelation).filter(ClientCertificateRelation.status == 0)
        if client_id is not None:
            query = query.filter(ClientCertificateRelation.client_id == client_id)
        return query.all()
    except Exception as e:
        print(f"Error getting pending client certificate relations: {e}")
        return []
    finally:
        session.close()

def delete_pending_client_certificate_relations(client_id=None):
    """Delete all pending (status=0) client-certificate relations,
    optionally scoped to one client's numeric database id."""
    session = get_db_session()
    try:
        query = session.query(ClientCertificateRelation).filter(ClientCertificateRelation.status == 0)
        if client_id is not None:
            query = query.filter(ClientCertificateRelation.client_id == client_id)
        query.delete(synchronize_session=False)
        session.commit()
        return True
    except Exception as e:
        print(f"Error deleting pending client certificate relations: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def delete_all_client_certificate_relations(client_id):
    """Delete every client-certificate relation (any status) for one
    client's numeric database id - used by cltmanager.py's
    `revoke_permission ... all`."""
    session = get_db_session()
    try:
        session.query(ClientCertificateRelation).filter_by(client_id=client_id).delete(synchronize_session=False)
        session.commit()
        return True
    except Exception as e:
        print(f"Error deleting client certificate relations: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def delete_certificate(fqdns):
    """Delete a certificate from the database by FQDNs, along with any
    client_certificate_relations rows pointing at it. Those relations must be
    removed first - fqdns is part of that table's composite primary key, and
    with no cascade configured on the relationship, SQLAlchemy would
    otherwise try to null it out to satisfy the FK and raise (visible here as
    a caught exception that made every delete of an assigned/requested
    certificate silently fail, always returning False)."""
    session = get_db_session()
    try:
        certificate = session.query(Certificate).filter_by(fqdns=fqdns).first()
        if certificate:
            session.query(ClientCertificateRelation).filter_by(fqdns=fqdns).delete()
            session.delete(certificate)
            session.commit()
            return True
        return False
    except Exception as e:
        print(f"Error deleting certificate: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def delete_certificate_placeholder(fqdns):
    """Remove a Certificate row that never received real data - used only by
    crtrequest.py to clean up after a failed issuance attempt.

    Deliberately does NOT touch client_certificate_relations, unlike
    delete_certificate(): that function's whole point is to also revoke a
    client's request/permission when an admin explicitly deletes a real
    certificate, but here the certificate never existed in the first place -
    the client's request is still perfectly valid and must stay visible
    (see admintui's Requests tab / get_requested_certificate_rows()), not
    silently disappear along with the placeholder that failed to become a
    real certificate.

    Uses a raw DELETE rather than session.delete(Certificate) specifically
    to avoid the ORM's own unit-of-work touching the relationship at all -
    session.delete() on a Certificate with relations pointing at it tries to
    null out those rows' fqdns column first (which delete_certificate()
    works around by deleting the relations outright), and fqdns can't be
    nulled anyway since it's part of that table's composite primary key.
    """
    session = get_db_session()
    try:
        result = session.execute(text('DELETE FROM certificates WHERE fqdns = :fqdns'), {'fqdns': fqdns})
        session.commit()
        return result.rowcount > 0
    except Exception as e:
        print(f"Error deleting certificate placeholder: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def create_certificate_entry(fqdns, acme_provider=None):
    """Create a new certificate entry with only fqdns field and return its
    id. acme_provider is only applied when creating a brand-new row; an
    existing row's acme_provider is left untouched (change it via
    crtmanager.py set-provider).

    Tolerates two callers racing to create the same brand-new fqdns
    concurrently (e.g. two ACME orders for the same not-yet-existing fqdns
    arriving at nearly the same instant, see ACME_SERVER_DESIGN.md §5.7/
    §6.3): the loser's INSERT raises IntegrityError on fqdns's unique
    constraint, caught here by re-fetching and returning the winner's id
    instead of propagating a crash."""
    session = get_db_session()
    try:
        existing_cert = session.query(Certificate).filter_by(fqdns=fqdns).first()
        if existing_cert:
            return existing_cert.id

        # Create new certificate with minimal data
        certificate = Certificate(
            fqdns=fqdns,
            public_key="",
            private_key="",
            intermediates="",
            validity_end_date=datetime(2020, 1, 1, 0, 0, 0),  # Default date
            acme_provider=acme_provider or DEFAULT_ACME_PROVIDER,
        )
        session.add(certificate)
        session.commit()
        return certificate.id
    except IntegrityError:
        session.rollback()
        existing_cert = session.query(Certificate).filter_by(fqdns=fqdns).first()
        return existing_cert.id if existing_cert else None
    except Exception as e:
        print(f"Error creating certificate entry: {e}")
        session.rollback()
        return None
    finally:
        session.close()

# ---------------------------------------------------------------------------
# ACME (RFC 8555) server support - ACME_SERVER_DESIGN.md
# ---------------------------------------------------------------------------

def issue_acme_nonce(ttl_seconds):
    """Generate and record a new server-issued ACME nonce (AcmeNonce, §4.4),
    returned to the caller for use as a Replay-Nonce header value. Mirrors
    consume_nonce()'s prune-then-act shape: opportunistically deletes rows
    older than ttl_seconds before issuing the new one. Returns None on
    error - callers must turn that into a 500."""
    session = get_db_session()
    try:
        cutoff = _utcnow() - timedelta(seconds=ttl_seconds)
        session.query(AcmeNonce).filter(AcmeNonce.created_at < cutoff).delete()

        nonce = secrets.token_urlsafe(32)
        session.add(AcmeNonce(nonce=nonce))
        session.commit()
        return nonce
    except Exception as e:
        print(f"Error issuing ACME nonce: {e}")
        session.rollback()
        return None
    finally:
        session.close()

def consume_acme_nonce(nonce):
    """Atomically redeem a server-issued ACME nonce - a single-use
    delete-and-check-rowcount, not a plain existence check followed by a
    separate delete. Returns True the first (and only) time a given nonce is
    redeemed, False if it was never issued or has already been consumed."""
    session = get_db_session()
    try:
        result = session.query(AcmeNonce).filter_by(nonce=nonce).delete()
        session.commit()
        return result > 0
    except Exception as e:
        print(f"Error consuming ACME nonce: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def prune_expired_acme_nonces(max_age_seconds):
    """Delete AcmeNonce rows older than max_age_seconds - exposed separately
    from issue_acme_nonce()'s own opportunistic pruning so the periodic
    cleanup pass (§8.5) can prune even during idle periods with no new nonce
    issuance."""
    session = get_db_session()
    try:
        cutoff = _utcnow() - timedelta(seconds=max_age_seconds)
        session.query(AcmeNonce).filter(AcmeNonce.created_at < cutoff).delete()
        session.commit()
    except Exception as e:
        print(f"Error pruning ACME nonces: {e}")
        session.rollback()
    finally:
        session.close()

def create_acme_account(jwk_json, thumbprint, contact_json=None, status='registered', trust_grant_id=None):
    """Create a brand-new ACME account - a Client row with client_kind='acme'
    (§4.1/§5.3). Returns the created Client, fully loaded via
    session.refresh() before the session closes so the caller can safely
    read its attributes afterward (a plain post-commit return would leave
    the object's attributes expired and inaccessible once this function's
    session is closed). Returns None on error, including a thumbprint
    collision (IntegrityError on acme_key_thumbprint's uniqueness - two
    newAccount requests for the same not-yet-registered key racing each
    other); the caller should re-fetch via get_client_by_acme_thumbprint()
    in that case.

    status/trust_grant_id default to the normal self-registration outcome
    (pending, no grant) - handle_new_account() passes status='confirmed'
    and the matching grant's id when a valid EAB/contact-token credential
    was presented, so a trusted device is auto-confirmed atomically at
    creation rather than via a separate update_client_status() call
    afterward (avoiding a window where the row briefly exists unconfirmed)."""
    session = get_db_session()
    try:
        client = Client(
            client_id=f"acme:{thumbprint}",
            public_key=jwk_json,
            status=status,
            client_kind='acme',
            acme_key_thumbprint=thumbprint,
            acme_contact=contact_json,
            trust_grant_id=trust_grant_id,
        )
        session.add(client)
        session.commit()
        session.refresh(client)
        return client
    except IntegrityError:
        session.rollback()
        return None
    except Exception as e:
        print(f"Error creating ACME account: {e}")
        session.rollback()
        return None
    finally:
        session.close()

def create_acme_trust_grant(label, allowed_fqdns_pattern, method, expires_at=None,
                             db_encryption_public_key_path=None):
    """Create a new AcmeTrustGrant - a pre-shared credential letting a
    trusted ACME client skip both manual admin steps (see the class'
    docstring). `method` is 'eab' or 'contact_token'; the actual secret is
    generated server-side here and returned to the caller exactly once -
    the contact-token is never recoverable again afterward (only its hash
    is stored); the EAB HMAC key technically could be decrypted again
    later, but cltmanager.py's CLI only ever prints it at creation time,
    matching standard "show once" credential hygiene.

    db_encryption_public_key_path is only ever passed by tests (see
    db_crypto.py's own identically-purposed parameter) - defaults to this
    module's own DB_ENCRYPTION_PUBLIC_KEY_FILE global (looked up fresh on
    every call, not baked in as this function's own default value) so a
    test can patch that module attribute and have it also take effect
    inside get_acme_eab_hmac_key_bytes()'s call from handle_new_account(),
    which has no override parameter of its own to pass one through.

    Returns a dict {'grant': <AcmeTrustGrant>, 'secret': <str>} - 'secret'
    is the raw HMAC key (base64url, unpadded) for method='eab', or the raw
    token (urlsafe) for method='contact_token'. Returns None on error or an
    unrecognized method."""
    if method not in ('eab', 'contact_token'):
        print(f"Error creating ACME trust grant: invalid method {method!r}")
        return None
    session = get_db_session()
    try:
        grant = AcmeTrustGrant(label=label, allowed_fqdns_pattern=allowed_fqdns_pattern, expires_at=expires_at)
        if method == 'eab':
            grant.eab_kid = secrets.token_urlsafe(16)
            hmac_key_bytes = secrets.token_bytes(32)
            secret = base64.urlsafe_b64encode(hmac_key_bytes).decode('ascii').rstrip('=')
            public_key_path = db_encryption_public_key_path or DB_ENCRYPTION_PUBLIC_KEY_FILE
            grant.eab_hmac_key_encrypted = encrypt_for_storage(secret, public_key_path=public_key_path)
        else:
            secret = secrets.token_urlsafe(32)
            grant.contact_token_hash = hashlib.sha256(secret.encode('ascii')).hexdigest()
        session.add(grant)
        session.commit()
        session.refresh(grant)
        return {'grant': grant, 'secret': secret}
    except Exception as e:
        print(f"Error creating ACME trust grant: {e}")
        session.rollback()
        return None
    finally:
        session.close()

def find_active_eab_grant(kid):
    """Look up a still-active (not revoked, not expired) EAB grant by its
    eab_kid - used by handle_new_account() when a newAccount request
    includes an externalAccountBinding object. Returns None if no such
    grant exists, or if it exists but is revoked/expired (deliberately
    indistinguishable from "doesn't exist" to the caller - either way, this
    EAB attempt cannot succeed)."""
    session = get_db_session()
    try:
        grant = session.query(AcmeTrustGrant).filter_by(eab_kid=kid).first()
        if grant is None or grant.revoked_at is not None:
            return None
        if grant.expires_at is not None and grant.expires_at <= _utcnow():
            return None
        return grant
    except Exception as e:
        print(f"Error finding ACME EAB grant: {e}")
        return None
    finally:
        session.close()

def find_active_contact_token_grant(token):
    """Same as find_active_eab_grant(), for the contact-token method -
    hashes `token` before lookup (only the hash is ever stored)."""
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode('ascii')).hexdigest()
    session = get_db_session()
    try:
        grant = session.query(AcmeTrustGrant).filter_by(contact_token_hash=token_hash).first()
        if grant is None or grant.revoked_at is not None:
            return None
        if grant.expires_at is not None and grant.expires_at <= _utcnow():
            return None
        return grant
    except Exception as e:
        print(f"Error finding ACME contact-token grant: {e}")
        return None
    finally:
        session.close()

def get_acme_trust_grant(grant_id):
    """Look up an AcmeTrustGrant by id regardless of revoked/expired state -
    used by handle_new_order() to re-validate a Client's linked grant
    (fqdns_matches_trust_grant() below does the actual revoked/expired
    re-check, so this is deliberately not filtered the way the two
    find_active_*() lookups above are)."""
    session = get_db_session()
    try:
        return session.query(AcmeTrustGrant).filter_by(id=grant_id).first()
    except Exception as e:
        print(f"Error getting ACME trust grant: {e}")
        return None
    finally:
        session.close()

def get_acme_eab_hmac_key_bytes(grant, db_encryption_private_key_path=None):
    """Decrypt and base64url-decode an EAB grant's stored HMAC key back into
    raw bytes, ready for common/acme_jose.py's verify_eab_jws(). Returns
    None if `grant` has no EAB credential (e.g. it's a contact_token-method
    grant) - keeps db_crypto/base64 details out of acme_server_utils.py.

    db_encryption_private_key_path defaults to this module's own
    DB_ENCRYPTION_PRIVATE_KEY_FILE global, looked up fresh on every call -
    same rationale as create_acme_trust_grant()'s public-key-path
    parameter (lets a test patch that module attribute and have it apply
    here too, even though handle_new_account() calls this with no override
    of its own)."""
    if grant is None or not grant.eab_hmac_key_encrypted:
        return None
    private_key_path = db_encryption_private_key_path or DB_ENCRYPTION_PRIVATE_KEY_FILE
    encoded = decrypt_for_storage(grant.eab_hmac_key_encrypted, private_key_path=private_key_path)
    padded = encoded + '=' * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(padded)

def record_trust_grant_use(grant_id):
    """Bump use_count/last_used_at - called once a grant has actually been
    used to auto-confirm an account (not on every lookup attempt, only a
    successful one)."""
    session = get_db_session()
    try:
        grant = session.query(AcmeTrustGrant).filter_by(id=grant_id).first()
        if grant is None:
            return
        grant.use_count += 1
        grant.last_used_at = _utcnow()
        session.commit()
    except Exception as e:
        print(f"Error recording ACME trust grant use: {e}")
        session.rollback()
    finally:
        session.close()

def revoke_acme_trust_grant(grant_id):
    """Soft-revoke a grant (sets revoked_at) - stops it granting anything
    new immediately (find_active_*() and fqdns_matches_trust_grant() both
    check this), without touching any ClientCertificateRelation it already
    caused to be auto-approved. Returns False if the grant doesn't exist or
    is already revoked."""
    session = get_db_session()
    try:
        grant = session.query(AcmeTrustGrant).filter_by(id=grant_id).first()
        if grant is None or grant.revoked_at is not None:
            return False
        grant.revoked_at = _utcnow()
        session.commit()
        return True
    except Exception as e:
        print(f"Error revoking ACME trust grant: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def get_acme_trust_grants():
    """All grants, newest first, for cltmanager.py's acme_list_trust_grants
    - never includes the raw secret (eab_hmac_key_encrypted stays
    encrypted, contact_token_hash is already one-way)."""
    session = get_db_session()
    try:
        return session.query(AcmeTrustGrant).order_by(AcmeTrustGrant.created_at.desc()).all()
    except Exception as e:
        print(f"Error getting ACME trust grants: {e}")
        return []
    finally:
        session.close()

def fqdns_matches_trust_grant(grant, fqdns):
    """True iff `grant` is still active (not revoked, not expired) AND
    `fqdns` matches at least one of its comma-separated glob patterns
    (fnmatch semantics - '*' matches across dots too). Re-checks revoked/
    expired here too, not just trusting the caller already checked at
    lookup time - handle_new_order() calls this well after a Client's
    linked grant was first loaded (often long after the account itself was
    created), so a grant revoked/expired since must stop granting new
    domains immediately."""
    if grant is None or grant.revoked_at is not None:
        return False
    if grant.expires_at is not None and grant.expires_at <= _utcnow():
        return False
    patterns = split_fqdns(grant.allowed_fqdns_pattern)
    return any(fnmatch.fnmatch(fqdns, pattern) for pattern in patterns)

def get_client_by_acme_thumbprint(thumbprint):
    """Look up an ACME account's Client row by its RFC 7638 JWK thumbprint."""
    session = get_db_session()
    try:
        return session.query(Client).filter_by(acme_key_thumbprint=thumbprint).first()
    except Exception as e:
        print(f"Error getting client by ACME thumbprint: {e}")
        return None
    finally:
        session.close()

def update_acme_account_contact(client_id, contact_json):
    """Update an ACME account's contact field (§5.4's account-update
    endpoint) - the only account field this design allows a client to
    change."""
    session = get_db_session()
    try:
        client = session.query(Client).filter_by(id=client_id).first()
        if client:
            client.acme_contact = contact_json
            session.commit()
            return True
        return False
    except Exception as e:
        print(f"Error updating ACME account contact: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def any_client_has_ip_pin() -> bool:
    """Whether any client has an IP-pinning restriction set (§7.3) - used
    by acme_server.py at startup to warn if IP pinning is in use while
    acme_trusted_proxy_ip is unset, since in that configuration a pin is
    always checked against the direct TCP peer (the reverse proxy itself,
    if any) rather than the real client, making it either silently
    ineffective (proxied deployments) or a startup-worthy misconfiguration
    to flag (internal/security/SECURITY_FINDINGS.md finding #18)."""
    session = get_db_session()
    try:
        return session.query(Client).filter(
            Client.allowed_source_ip.isnot(None), Client.allowed_source_ip != ''
        ).first() is not None
    finally:
        session.close()


def set_client_allowed_ip(client_id, allowed_ip):
    """Set (or clear, if allowed_ip is None) a client's IP-pinning
    restriction (§7.3) - a bare IP or CIDR network string. Validity of
    `allowed_ip` as a real IP/network is the caller's responsibility
    (cltmanager.py's set_allowed_ip command validates before ever calling
    this) - this function only ever stores whatever string it's given."""
    session = get_db_session()
    try:
        client = session.query(Client).filter_by(id=client_id).first()
        if client:
            client.allowed_source_ip = allowed_ip
            session.commit()
            return True
        return False
    except Exception as e:
        print(f"Error updating client's allowed source IP: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def create_acme_order(account_client_id, fqdns, identifiers_json, expires_at):
    """Create a new AcmeOrder row (§5.7's newOrder), status='pending'.
    Returns the created order, fully loaded via session.refresh() before the
    session closes (see create_acme_account()'s docstring for why), or None
    on error."""
    session = get_db_session()
    try:
        order = AcmeOrder(
            account_client_id=account_client_id,
            fqdns=fqdns,
            identifiers_json=identifiers_json,
            status='pending',
            expires_at=expires_at,
        )
        session.add(order)
        session.commit()
        session.refresh(order)
        return order
    except Exception as e:
        print(f"Error creating ACME order: {e}")
        session.rollback()
        return None
    finally:
        session.close()

def get_acme_order(order_id):
    """Fetch a single AcmeOrder by id."""
    session = get_db_session()
    try:
        return session.query(AcmeOrder).filter_by(id=order_id).first()
    except Exception as e:
        print(f"Error getting ACME order: {e}")
        return None
    finally:
        session.close()

def get_acme_orders_for_account(account_client_id, limit=100):
    """This account's own AcmeOrder rows, filtered/capped/ordered exactly as
    §5.5 specifies: excludes 'invalid' orders (so an account with many old
    abandoned ones doesn't have its one current, useful order pushed off the
    end of the cap), newest-first, hard-capped at `limit` (no pagination in
    v1 - see §5.5's own discussion of this being a hard, silent truncation
    rather than a promise to eventually return everything)."""
    session = get_db_session()
    try:
        return (session.query(AcmeOrder)
                .filter(AcmeOrder.account_client_id == account_client_id,
                        AcmeOrder.status != 'invalid')
                .order_by(AcmeOrder.created_at.desc())
                .limit(limit)
                .all())
    except Exception as e:
        print(f"Error getting ACME orders for account: {e}")
        return []
    finally:
        session.close()

def acquire_acme_processing_lock(order_id, fqdns, csr_pem, csr_key_fingerprint):
    """Atomically acquire the per-fqdns processing lock and transition the
    order to 'processing' in one step, exactly as §4.4.1/§5.10 specify:
    finalize treats "acquire the lock" and "commit this order's CSR" as one
    atomic operation, since a lock acquired without also making the CSR
    immutable would leave a window where a second finalize on the same order
    could still replace it.

    The lock INSERT is wrapped in a nested transaction/savepoint
    specifically so the expected IntegrityError (another order for this
    fqdns is genuinely 'processing') can be recovered from without poisoning
    the rest of this session - session.begin_nested() as a context manager
    already performs the SAVEPOINT rollback itself when the exception
    propagates out of the `with` block, so no further session.rollback()
    call is needed (or correct - it would roll back further than intended,
    operating on the outermost transaction instead of just the failed
    nested one).

    Returns True iff the lock was acquired and the order updated; False if
    another order already holds this fqdns's lock, or the order doesn't
    exist / isn't in a state where finalize should be accepted (caller is
    responsible for the 'pending'+permission-active check before calling
    this - this function only guards the lock itself)."""
    session = get_db_session()
    try:
        order = session.query(AcmeOrder).filter_by(id=order_id).first()
        if not order:
            return False
        try:
            with session.begin_nested():
                session.add(AcmeProcessingLock(fqdns=fqdns, order_id=order_id))
                session.flush()
        except IntegrityError:
            return False
        order.csr_pem = csr_pem
        order.csr_key_fingerprint = csr_key_fingerprint
        order.finalized_at = _utcnow()
        order.status = 'processing'
        session.commit()
        return True
    except Exception as e:
        print(f"Error acquiring ACME processing lock: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def release_acme_processing_lock(fqdns, order_id):
    """Idempotent lock release, scoped by BOTH fqdns and order_id - never by
    fqdns alone. Since the lock table's primary key is fqdns alone, a delete
    scoped only by fqdns would delete whatever row currently occupies that
    fqdns, even one belonging to a completely different, newer order than
    the one requesting the release (a real race this design had to close -
    see §4.4.1). A no-op, not an error, whether the row is already gone or
    belongs to someone else."""
    session = get_db_session()
    try:
        session.query(AcmeProcessingLock).filter_by(fqdns=fqdns, order_id=order_id).delete()
        session.commit()
    except Exception as e:
        print(f"Error releasing ACME processing lock: {e}")
        session.rollback()
    finally:
        session.close()

def mark_acme_order_valid(order_id):
    """The atomic conditional success-transition from §4.3.1/§6.2: only
    flips an order to 'valid' if it's still 'processing' at this exact
    moment. Returns True iff the transition actually happened (exactly one
    row matched) - callers (update_database_with_certificate_from_csr())
    must only proceed with the AcmeCertificate insert / Certificate update /
    lock release when this returns True. A False return means the order was
    already moved out of 'processing' by something else (expiry cleanup, or
    the attempt-cap invalidation) while its own acme.sh call was still in
    flight - the caller should discard the freshly-issued certificate rather
    than attaching it to a dead order or overwriting a different, currently-
    live order's Certificate row."""
    session = get_db_session()
    try:
        matched = session.query(AcmeOrder).filter_by(
            id=order_id, status='processing').update({'status': 'valid'})
        session.commit()
        return matched > 0
    except Exception as e:
        print(f"Error marking ACME order valid: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def insert_acme_certificate(order_id, certificate_pem, intermediates, key_fingerprint, validity_end_date):
    """Insert this order's own immutable AcmeCertificate row (§4.3.1) - only
    ever called after mark_acme_order_valid() has returned True for the same
    order_id."""
    session = get_db_session()
    try:
        session.add(AcmeCertificate(
            order_id=order_id,
            certificate_pem=certificate_pem,
            intermediates=intermediates,
            key_fingerprint=key_fingerprint,
            validity_end_date=validity_end_date,
        ))
        session.commit()
        return True
    except Exception as e:
        print(f"Error inserting ACME certificate: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def get_acme_certificate_by_order_id(order_id):
    """This order's own immutable AcmeCertificate row, or None if the order
    hasn't reached 'valid' yet (or ever)."""
    session = get_db_session()
    try:
        return session.query(AcmeCertificate).filter_by(order_id=order_id).first()
    except Exception as e:
        print(f"Error getting ACME certificate: {e}")
        return None
    finally:
        session.close()

def record_acme_order_failure(order_id, error_message, max_attempts, base_retry_seconds, max_retry_seconds):
    """Record a failed issuance attempt and apply §6.3.1's capped
    exponential backoff. Once issuance_attempts reaches max_attempts, the
    order is invalidated and its processing lock released (scoped by both
    fqdns and order_id, per release-path invariant above) so a different,
    working order for the same fqdns is never permanently blocked by one
    that's already effectively dead. max_attempts/base_retry_seconds/
    max_retry_seconds are passed in by the caller (crtrequest.py, from
    config/constants) rather than imported here, keeping this module
    config-agnostic."""
    session = get_db_session()
    try:
        order = session.query(AcmeOrder).filter_by(id=order_id).first()
        if not order:
            return
        order.issuance_attempts += 1
        order.last_issuance_attempt_at = _utcnow()
        order.last_issuance_error = error_message
        if order.issuance_attempts >= max_attempts:
            order.status = 'invalid'
            session.query(AcmeProcessingLock).filter_by(
                fqdns=order.fqdns, order_id=order.id).delete()
            session.commit()
            return
        delay = min(base_retry_seconds * (2 ** (order.issuance_attempts - 1)), max_retry_seconds)
        order.next_issuance_attempt_at = order.last_issuance_attempt_at + timedelta(seconds=delay)
        session.commit()
    except Exception as e:
        print(f"Error recording ACME order failure: {e}")
        session.rollback()
    finally:
        session.close()

def get_stuck_pending_acme_orders(min_age_seconds=300):
    """Orders still `status == 'pending'` (i.e. the client has never
    successfully called finalize) that are older than min_age_seconds -
    diagnostic-only, used by crtrequest.py's ACME pass to log orders that
    get_pending_acme_orders_for_issuance() will never see (it only ever
    looks at 'processing' orders), so a client that's stuck polling
    order/authz/challenge without ever finalizing - whether because its fqdns
    permission isn't approved yet, or because it doesn't understand/follow
    this server's authorization flow - is visible from crtrequest.py's own
    log, not just admintui's Requests tab or the ACME server's access log.

    Returns a list of (order, age_seconds, permission_active) tuples rather
    than bare AcmeOrder rows, so callers don't need their own
    ClientCertificateRelation lookup just to log the one fact that actually
    distinguishes "waiting on admin approval" from "approved, but the client
    itself never finalizes"."""
    session = get_db_session()
    try:
        cutoff = _utcnow() - timedelta(seconds=min_age_seconds)
        orders = session.query(AcmeOrder).filter(
            AcmeOrder.status == 'pending',
            AcmeOrder.created_at <= cutoff,
        ).all()
        now = _utcnow()
        results = []
        for order in orders:
            relation = session.query(ClientCertificateRelation).filter_by(
                client_id=order.account_client_id, fqdns=order.fqdns).first()
            age_seconds = (now - order.created_at).total_seconds()
            results.append((order, age_seconds, permission_is_active(relation)))
        return results
    except Exception as e:
        print(f"Error getting stuck pending ACME orders: {e}")
        return []
    finally:
        session.close()

def get_pending_acme_orders_for_issuance():
    """§6.3's exact worker-selection query: orders ready for crtrequest.py's
    issuance pass to act on - 'processing', with a CSR attached, not
    expired, and either never attempted or due for a retry."""
    session = get_db_session()
    try:
        now = _utcnow()
        return session.query(AcmeOrder).filter(
            AcmeOrder.status == 'processing',
            AcmeOrder.csr_pem.isnot(None),
            AcmeOrder.expires_at > now,
            or_(AcmeOrder.next_issuance_attempt_at.is_(None),
                AcmeOrder.next_issuance_attempt_at <= now),
        ).all()
    except Exception as e:
        print(f"Error getting pending ACME orders for issuance: {e}")
        return []
    finally:
        session.close()

def expire_stale_acme_orders_and_locks():
    """The order/lock half of the periodic cleanup pass (§4.3.1/§8.5):
    flips any 'pending'/'processing' order whose expires_at has passed to
    'invalid', and deletes their AcmeProcessingLock rows (scoped by
    order_id) in the same operation - an expired order that isn't also
    unlocked would otherwise permanently block that fqdns from ever
    reaching 'processing' again. Returns the number of orders expired."""
    session = get_db_session()
    try:
        now = _utcnow()
        order_ids = [row[0] for row in session.query(AcmeOrder.id).filter(
            AcmeOrder.status.in_(('pending', 'processing')),
            AcmeOrder.expires_at <= now,
        ).all()]
        if not order_ids:
            return 0
        session.query(AcmeOrder).filter(AcmeOrder.id.in_(order_ids)).update(
            {'status': 'invalid'}, synchronize_session=False)
        session.query(AcmeProcessingLock).filter(
            AcmeProcessingLock.order_id.in_(order_ids)).delete(synchronize_session=False)
        session.commit()
        return len(order_ids)
    except Exception as e:
        print(f"Error expiring stale ACME orders: {e}")
        session.rollback()
        return 0
    finally:
        session.close()

def cancel_acme_order(order_id):
    """Admin-initiated single-order counterpart to
    expire_stale_acme_orders_and_locks() - lets an admin (cltmanager.py/
    admintui) unblock a specific stuck/dead order on demand, rather than
    waiting for its own expires_at. Deliberately one atomic action (flip to
    'invalid' AND release its lock together), not two separate ones: a bare
    lock release without invalidating the order would let
    get_pending_acme_orders_for_issuance() keep retrying the "abandoned"
    order (it only filters on status, never checks the lock) while also
    letting a new, competing order for the same fqdns acquire the
    now-free lock - reintroducing the exact race AcmeProcessingLock exists
    to prevent (ACME_SERVER_DESIGN.md §4.4.1).

    Returns True iff an order in 'pending' or 'processing' was found and
    cancelled; False if it doesn't exist or is already 'valid'/'invalid'
    (nothing to cancel)."""
    session = get_db_session()
    try:
        order = session.query(AcmeOrder).filter(
            AcmeOrder.id == order_id,
            AcmeOrder.status.in_(('pending', 'processing')),
        ).first()
        if order is None:
            return False
        order.status = 'invalid'
        session.query(AcmeProcessingLock).filter_by(order_id=order_id).delete()
        session.commit()
        return True
    except Exception as e:
        print(f"Error cancelling ACME order: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def get_acme_order_rows(account_client_id=None):
    """Display-ready rows for admintui/cltmanager.py, one per non-'invalid'
    AcmeOrder - either one account's own (account_client_id given, reusing
    get_acme_orders_for_account()'s own filter/order) or every account's
    (account_client_id=None, for a global outstanding-orders view).

    order['status'] is the same *externally-visible* status an ACME client
    itself would see, not AcmeOrder.status verbatim - mirrors
    common/acme_server_utils.py's _order_external_status()/
    authorization_status() derivation (a 'pending' order only really means
    "ready" once its ClientCertificateRelation is admin-approved), kept as a
    small, self-contained duplicate here rather than importing that HTTP
    handler module (which itself imports this one - a cycle)."""
    session = get_db_session()
    try:
        query = (session.query(AcmeOrder, Client)
                  .join(Client, AcmeOrder.account_client_id == Client.id)
                  .filter(AcmeOrder.status != 'invalid'))
        if account_client_id is not None:
            query = query.filter(AcmeOrder.account_client_id == account_client_id)
        results = query.order_by(AcmeOrder.created_at.desc()).all()

        rows = []
        for order, client in results:
            if order.status == 'pending':
                relation = session.query(ClientCertificateRelation).filter_by(
                    client_id=order.account_client_id, fqdns=order.fqdns).first()
                status = 'ready' if permission_is_active(relation) else 'pending'
            else:
                status = order.status
            rows.append({
                'order_id': order.id,
                'client_id': client.client_id,
                'account_client_id': order.account_client_id,
                'fqdns': order.fqdns,
                'status': status,
                'created_at': order.created_at,
                'expires_at': order.expires_at,
                'issuance_attempts': order.issuance_attempts,
                'last_issuance_error': order.last_issuance_error,
            })
        return rows
    except Exception as e:
        print(f"Error getting ACME order rows: {e}")
        return []
    finally:
        session.close()

def get_latest_acme_order_created_at_by_account():
    """{account_client_id: most recent AcmeOrder.created_at}, any order
    status, across every ACME account - one aggregate query, not one per
    client (same bulk-fetch-then-bucket style as
    get_all_client_certificate_relations_with_certs()'s callers).

    Used as a "last seen" proxy for ACME accounts in admintui's Clients tab:
    Client.last_successful_connection is only ever set by the traditional
    protocol's signed-message verification (common/network_utils.py's
    receive_secure_message()) - an ACME account authenticates via JWS
    instead, a completely separate path, so that column is permanently
    NULL for every ACME client regardless of how active it actually is. A
    new order is the clearest "this account did something" signal ACME
    exposes instead - roughly the renewal-cycle equivalent of a traditional
    client's periodic reconnection. Any status (not just non-'invalid', the
    way get_acme_order_rows() filters) - even a failed/expired order is
    still evidence the account was recently active."""
    session = get_db_session()
    try:
        results = (session.query(AcmeOrder.account_client_id, func.max(AcmeOrder.created_at))
                   .group_by(AcmeOrder.account_client_id).all())
        return {account_client_id: created_at for account_client_id, created_at in results}
    except Exception as e:
        print(f"Error getting latest ACME order timestamps: {e}")
        return {}
    finally:
        session.close()

def get_acme_issued_fqdns(fqdns_list):
    """Which of these fqdns's *current* Certificate.public_key exactly
    matches some AcmeCertificate.certificate_pem for that same fqdns -
    bulk form (one query for admintui's whole certificate listing rather
    than one query per row). An exact PEM match, not just "an AcmeOrder for
    this fqdns once reached valid", since a later traditional reissue could
    have overwritten the shared Certificate row since (update_certificate()
    updates it in place, unchanged pre-ACME behavior) - matching on the
    live PEM content is the only way to avoid mislabeling that as
    ACME-issued. Returns a set of fqdns for which this is true."""
    if not fqdns_list:
        return set()
    session = get_db_session()
    try:
        results = (session.query(Certificate.fqdns)
                   .join(AcmeOrder, AcmeOrder.fqdns == Certificate.fqdns)
                   .join(AcmeCertificate, AcmeCertificate.order_id == AcmeOrder.id)
                   .filter(Certificate.fqdns.in_(fqdns_list),
                           AcmeCertificate.certificate_pem == Certificate.public_key)
                   .distinct().all())
        return {row[0] for row in results}
    except Exception as e:
        print(f"Error getting ACME-issued fqdns: {e}")
        return set()
    finally:
        session.close()

def delete_unconfirmed_stale_acme_accounts(retention_days=30):
    """§8.5's second cleanup requirement: delete an ACME account that
    self-registered but was never confirmed by an admin, older than
    retention_days - otherwise an anonymous attacker can accumulate
    unlimited account rows (and unlimited admin registration-notification
    emails) for free. Reuses delete_client_by_id()'s own cascade rather than
    duplicating it, per client, rather than a single bulk statement -
    simplest way to guarantee the same AcmeOrder/AcmeCertificate/
    AcmeProcessingLock cleanup applies even in the unlikely case an
    unconfirmed account already has orders. Returns the number of accounts
    deleted."""
    session = get_db_session()
    try:
        cutoff = _utcnow() - timedelta(days=retention_days)
        client_ids = [row[0] for row in session.query(Client.id).filter(
            Client.client_kind == 'acme',
            Client.status == 'registered',
            Client.registration_date < cutoff,
        ).all()]
    except Exception as e:
        print(f"Error finding stale ACME accounts: {e}")
        return 0
    finally:
        session.close()

    deleted = 0
    for client_id in client_ids:
        if delete_client_by_id(client_id):
            deleted += 1
    return deleted

def is_acme_managed(fqdns):
    """§6.4's exact liveness check, used by the traditional issuance loop to
    avoid claiming an fqdns a live ACME order already owns: True if any
    non-'invalid', non-expired AcmeOrder exists for this fqdns (whether
    still pending/processing, or already 'valid' - a real, currently-in-use
    ACME certificate). False for an fqdns whose only AcmeOrder history is
    expired/invalid ones, which is free to fall back to the traditional
    protocol again."""
    session = get_db_session()
    try:
        now = _utcnow()
        return session.query(AcmeOrder).filter(
            AcmeOrder.fqdns == fqdns,
            AcmeOrder.status != 'invalid',
            AcmeOrder.expires_at > now,
        ).count() > 0
    except Exception as e:
        print(f"Error checking ACME-managed status: {e}")
        return False
    finally:
        session.close()
