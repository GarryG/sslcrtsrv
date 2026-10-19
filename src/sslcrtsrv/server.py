#!/usr/bin/env python3
"""
SSL Key Repository Server
Handles client registration, certificate management, and secure communication
"""

import logging
import sys
import os
import argparse
import json
import secrets
from pathlib import Path

from . import __version__
from .common import create_server, start_server
from .common.crypto_utils import generate_key_pair, save_keys
from .common.constants import (
    DATA_DIR, DEFAULT_ACME_PROVIDER, DEFAULT_SERVER_CONFIG_FILE, SHARED_DIR_MODE, SHARED_FILE_MODE,
    CLIENT_PACKAGE_DOWNLOAD_PATH_PREFIX, ACME_DEFAULT_LISTEN, ACME_DEFAULT_PORT
)
from .common.notify_utils import (
    NOTIFIER_TYPES, NOTIFICATION_EVENTS, DEFAULT_RATE_LIMIT_MAX_NOTIFICATIONS, DEFAULT_RATE_LIMIT_WINDOW_SECONDS
)
from .common.server_utils import parse_bind_entry
from .common import database
from .common.logging_utils import DEFAULT_SYSLOG_PORT, DEFAULT_SYSLOG_FACILITY
from .common.system_utils import ensure_secure_dir, write_secure_json
from cryptography.hazmat.primitives import serialization

# Explicit name, not logging.getLogger(__name__): this module is normally
# run via `python3 -m sslcrtsrv.server`, under which __name__ becomes
# "__main__" rather than "sslcrtsrv.server" - a logger named "__main__"
# would not be a descendant of "sslcrtsrv" and would never reach the
# handlers common/logging_utils.py's setup_server_logging() configures
# there (see that function's docstring). Only used after create_server()
# has already run (so Server.__init__() has already set logging up) - see
# the two call sites below.
logger = logging.getLogger("sslcrtsrv.server")


def _database_section_updates(db_backend, db_host, db_port, db_user, db_password, db_name):
    """Build the {"backend": ..., "mysql"/"postgresql": {...}} updates for
    the `database` config section from whichever --db-* flags were
    explicitly supplied, or None if none were. Shared by both init_config()
    branches below - see their matching `notifiers`/`client_packages`
    upsert-by-key comments for why this is update-in-place, not replace."""
    if db_backend is None:
        return None
    updates = {'backend': db_backend}
    if db_backend in ('mysql', 'postgresql'):
        backend_fields = {}
        if db_host is not None:
            backend_fields['host'] = db_host
        if db_port is not None:
            backend_fields['port'] = db_port
        if db_user is not None:
            backend_fields['user'] = db_user
        if db_password is not None:
            backend_fields['password'] = db_password
        if db_name is not None:
            backend_fields['database'] = db_name
        if backend_fields:
            updates[db_backend] = backend_fields
    return updates


def init_config(config_file_path, listen_address="0.0.0.0", port=5514, data_dir=None, cert_dir=None,
                 registration_secret=None, default_acme_provider=None,
                 client_packages=None, notifiers=None, notification_routing=None,
                 syslog_host=None, syslog_port=None, syslog_facility=None, bind_also=None,
                 notification_rate_limit_max=None, notification_rate_limit_window=None,
                 notification_rate_limits=None,
                 db_backend=None, db_host=None, db_port=None, db_user=None, db_password=None, db_name=None,
                 acme_enabled=None, acme_external_url=None, acme_listen=None, acme_port=None):
    """Initialize configuration file with keys and settings"""

    # Create directory for config file if it doesn't exist. Group-shared, not
    # owner-only - web_admin's PHP process (a different OS user) needs to
    # read/write this file too; see common/constants.py's SHARED_DIR_MODE.
    config_dir = os.path.dirname(config_file_path)
    if config_dir and not os.path.exists(config_dir):
        ensure_secure_dir(config_dir, mode=SHARED_DIR_MODE)
    
    # Check if config file already exists
    if os.path.exists(config_file_path):
        print(f"Configuration file {config_file_path} already exists.")
        while True:
            choice = input("Do you want to (c)ancel, (o)verwrite (creating new key), or (u)pdate (keep existing key, update the rest)? ").lower()
            if choice in ['c', 'cancel']:
                print("Operation cancelled.")
                return False
            elif choice in ['o', 'overwrite']:
                print("Overwriting configuration with new key...")
                break
            elif choice in ['u', 'update']:
                print("Updating config (key will remain unchanged)...")
                # Load existing config to preserve keys
                with open(config_file_path, 'r') as f:
                    existing_config = json.load(f)
                
                # Update only listen address and port
                existing_config['listen_address'] = listen_address
                existing_config['port'] = port

                # Additional listeners (Server.setup_server()'s 'bind_also')
                # - extends the existing list rather than replacing it, so
                # re-running init to add one more address never drops
                # previously configured ones; duplicates are skipped.
                if bind_also:
                    existing_list = existing_config.setdefault('bind_also', [])
                    for entry in bind_also:
                        if entry not in existing_list:
                            existing_list.append(entry)

                # Update data_dir if provided
                if data_dir is not None:
                    existing_config['data_dir'] = data_dir
                
                # Update cert_dir if provided
                if cert_dir is not None:
                    existing_config['cert_home_dir'] = cert_dir

                # Syslog settings (Section 5.1/10.6) - update only whichever
                # of these were explicitly supplied, same pattern as
                # data_dir/cert_dir above.
                if syslog_host is not None:
                    existing_config['syslog_host'] = syslog_host
                if syslog_port is not None:
                    existing_config['syslog_port'] = syslog_port
                if syslog_facility is not None:
                    existing_config['syslog_facility'] = syslog_facility

                # Only touch the registration secret if a new one was explicitly
                # supplied - rotating it invalidates it for any client that
                # hasn't been given the new value yet, so it's opt-in here.
                if registration_secret is not None:
                    existing_config['registration_secret'] = registration_secret
                    print(f"Registration secret updated. New value to share with client "
                          f"administrators out-of-band: {registration_secret}")

                # Update the default ACME provider only if explicitly supplied
                if default_acme_provider is not None:
                    existing_config['default_acme_provider'] = default_acme_provider

                # Client install packages served over HTTP on this same port
                # (see common/constants.py's CLIENT_PACKAGE_DOWNLOAD_PATH_PREFIX) -
                # each --client-package upserts one named entry rather than
                # replacing the whole map, so re-running init to add/update
                # one package (e.g. a new version) never drops the others.
                if client_packages:
                    existing_config.setdefault('client_packages', {}).update(client_packages)

                # Multi-notifier system (see common/notify_utils.py) - same
                # upsert-by-key pattern as client_packages above, so adding
                # one more notifier or re-routing one event never drops any
                # previously configured notifier/route.
                if notifiers:
                    existing_config.setdefault('notifiers', {}).update(notifiers)
                if notification_routing:
                    existing_config.setdefault('notification_routing', {}).update(notification_routing)

                # Notification rate limiting (see common/notify_utils.py) -
                # update only whichever of the global max/window were
                # explicitly supplied (same pattern as data_dir/cert_dir
                # above), and upsert per-notifier-name overrides the same
                # way notifiers/client_packages are upserted above.
                if notification_rate_limit_max is not None:
                    existing_config.setdefault('notification_rate_limit', {})['max_notifications'] = notification_rate_limit_max
                if notification_rate_limit_window is not None:
                    existing_config.setdefault('notification_rate_limit', {})['window_seconds'] = notification_rate_limit_window
                if notification_rate_limits:
                    existing_rate_limits = existing_config.setdefault('notification_rate_limits', {})
                    for name, override in notification_rate_limits.items():
                        existing_rate_limits.setdefault(name, {}).update(override)

                # Database backend (see common/database.py's configure_database())
                # - entirely optional; with none configured, the server keeps
                # using the sqlite/data_dir default exactly as before.
                database_updates = _database_section_updates(db_backend, db_host, db_port, db_user, db_password, db_name)
                if database_updates is not None:
                    db_section = existing_config.setdefault('database', {})
                    db_section['backend'] = database_updates['backend']
                    if database_updates['backend'] in database_updates:
                        db_section.setdefault(database_updates['backend'], {}).update(database_updates[database_updates['backend']])

                # ACME (RFC 8555) server settings (see acme_server.py /
                # ACME_SERVER_DESIGN.md) - update only whichever of these
                # were explicitly supplied, same pattern as data_dir/cert_dir
                # above. acme_listen/acme_port are left unset (falling back
                # to acme_server.py's own ACME_DEFAULT_LISTEN/ACME_DEFAULT_PORT)
                # unless explicitly given here, exactly like every other
                # optional setting in this function.
                if acme_enabled is not None:
                    existing_config['acme_enabled'] = acme_enabled
                if acme_external_url is not None:
                    existing_config['acme_external_url'] = acme_external_url
                if acme_listen is not None:
                    existing_config['acme_listen'] = acme_listen
                if acme_port is not None:
                    existing_config['acme_port'] = acme_port

                # Save updated config
                write_secure_json(config_file_path, existing_config, mode=SHARED_FILE_MODE)

                print(f"Configuration file {config_file_path} updated successfully.")
                return True
            else:
                print("Invalid choice. Please enter 'c' (cancel), 'o' (overwrite), or 'u' (update).")
    
    # Generate new key pair
    private_key, public_key = generate_key_pair()

    # Generate a registration secret if one wasn't supplied - this is what
    # clients must prove knowledge of to be allowed to register (finding #4)
    if registration_secret is None:
        registration_secret = secrets.token_urlsafe(24)
    print(f"Registration secret (share this with client administrators out-of-band, "
          f"it will not be shown again): {registration_secret}")

    # Create configuration
    config = {
        "listen_address": listen_address,
        "port": port,
        "private_key": None,  # Will be saved to file
        "public_key": None,   # Will be saved to file
        "registration_secret": registration_secret,
        "default_acme_provider": default_acme_provider or DEFAULT_ACME_PROVIDER
    }

    # Additional listeners, on top of the primary listen_address/port above
    # (Server.setup_server()'s 'bind_also') - entirely optional; with none
    # configured, the server listens only on the primary address as before.
    if bind_also:
        config["bind_also"] = list(dict.fromkeys(bind_also))

    # Add data directory if provided
    if data_dir is not None:
        config["data_dir"] = data_dir

    # Add certificate directory if provided
    if cert_dir is not None:
        config["cert_home_dir"] = cert_dir

    # Syslog settings (Section 5.1/10.6) - entirely optional; with none
    # configured, the server logs to the local syslog daemon (/dev/log)
    # with the "daemon" facility by default (common/logging_utils.py).
    if syslog_host is not None:
        config["syslog_host"] = syslog_host
    if syslog_port is not None:
        config["syslog_port"] = syslog_port
    if syslog_facility is not None:
        config["syslog_facility"] = syslog_facility

    # Client install packages served over HTTP on this same port (see
    # common/constants.py's CLIENT_PACKAGE_DOWNLOAD_PATH_PREFIX) -
    # entirely optional; with none configured, those endpoints just serve
    # the "nothing configured" overview/empty catalog
    if client_packages:
        config["client_packages"] = client_packages

    # Multi-notifier system (see common/notify_utils.py) - entirely optional.
    # Email is just one more notifier type here (--notifier NAME:email:...),
    # no longer a special case with its own flags/flat fields.
    if notifiers:
        config.setdefault("notifiers", {}).update(notifiers)
    if notification_routing:
        config.setdefault("notification_routing", {}).update(notification_routing)

    # Notification rate limiting (see common/notify_utils.py) - entirely
    # optional; with none configured, this module's own
    # DEFAULT_RATE_LIMIT_MAX_NOTIFICATIONS/DEFAULT_RATE_LIMIT_WINDOW_SECONDS
    # apply for every notifier.
    if notification_rate_limit_max is not None or notification_rate_limit_window is not None:
        rate_limit = {}
        if notification_rate_limit_max is not None:
            rate_limit["max_notifications"] = notification_rate_limit_max
        if notification_rate_limit_window is not None:
            rate_limit["window_seconds"] = notification_rate_limit_window
        config["notification_rate_limit"] = rate_limit
    if notification_rate_limits:
        config["notification_rate_limits"] = notification_rate_limits

    # Database backend (see common/database.py's configure_database()) -
    # entirely optional; with none configured, the server uses the
    # sqlite/data_dir default.
    database_updates = _database_section_updates(db_backend, db_host, db_port, db_user, db_password, db_name)
    if database_updates is not None:
        config["database"] = database_updates

    # ACME (RFC 8555) server settings (see acme_server.py /
    # ACME_SERVER_DESIGN.md) - entirely optional; with none configured,
    # acme_enabled defaults to unset/false and scs-acme-server refuses to
    # start, exactly as if this server were never meant to run it.
    if acme_enabled is not None:
        config["acme_enabled"] = acme_enabled
    if acme_external_url is not None:
        config["acme_external_url"] = acme_external_url
    if acme_listen is not None:
        config["acme_listen"] = acme_listen
    if acme_port is not None:
        config["acme_port"] = acme_port

    # Save keys to configuration file (no separate key files)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    config["private_key"] = private_pem
    config["public_key"] = public_pem

    # Save configuration file - group-shared, not owner-only, despite containing
    # the private key: see SHARED_FILE_MODE's docstring for why (web_admin needs
    # read/write access to this file) and its security tradeoff.
    write_secure_json(config_file_path, config, mode=SHARED_FILE_MODE)

    print(f"Configuration file {config_file_path} created successfully.")
    return True


def load_config(config_file_path=None):
    """Pure read of the server config file - returns the parsed dict, or
    None if it doesn't exist yet (server hasn't been through 'init'). Used
    by admintui's Config tab; unlike main()'s own loading code this never
    prints or exits."""
    if config_file_path is None:
        config_file_path = DEFAULT_SERVER_CONFIG_FILE
    if not os.path.exists(config_file_path):
        return None
    with open(config_file_path, 'r') as f:
        return json.load(f)


def update_config_fields(config_file_path, updates: dict, remove_keys=None) -> bool:
    """Pure update of an already-existing config file: merges `updates` into
    whatever's on disk - preserving every key not mentioned, notably
    private_key/public_key - and writes the result back. `remove_keys`, if
    given, deletes those top-level keys first - a plain dict.update() alone
    can only add/overwrite keys, never remove them, which matters for e.g.
    admintui's ConfigView._save() migrating the old flat email fields
    (Section 10.1) away once their replacement is included in `updates`.
    Returns False without writing anything if the config file doesn't exist
    yet; callers should tell the admin to run 'init' first rather than have
    this silently create a fresh, unkeyed config.
    """
    if config_file_path is None:
        config_file_path = DEFAULT_SERVER_CONFIG_FILE
    if not os.path.exists(config_file_path):
        return False
    with open(config_file_path, 'r') as f:
        config = json.load(f)
    for key in remove_keys or ():
        config.pop(key, None)
    config.update(updates)
    write_secure_json(config_file_path, config, mode=SHARED_FILE_MODE)
    return True


def parse_client_package_arg(raw: str):
    """Parse one --client-package NAME:PATH:VERSION[:DESCRIPTION] value into
    (name, {"path": ..., "version": ..., "description": ...}). DESCRIPTION
    is optional and may itself contain colons (split with maxsplit=3, so
    anything past the third colon is taken verbatim as the description).
    Raises ValueError with a message safe to print directly if malformed.
    """
    parts = raw.split(':', 3)
    if len(parts) < 3:
        raise ValueError("expected NAME:PATH:VERSION[:DESCRIPTION]")
    name, path, version = parts[0], parts[1], parts[2]
    description = parts[3] if len(parts) > 3 else ""
    if not name or not path or not version:
        raise ValueError("NAME, PATH, and VERSION must all be non-empty")
    return name, {"path": path, "version": version, "description": description}


def parse_notifier_arg(raw: str):
    """Parse one --notifier NAME:TYPE:key=value[,key=value...] value into
    (name, {"type": TYPE, **fields}). The key=value list is optional (a
    notifier with no fields at all isn't useful, but the parse doesn't care).
    A nested value (e.g. a webhook's arbitrary extra 'headers') isn't
    expressible via this flat shorthand - edit server_config.json directly
    for that; see the 'headers'/'auth_header' fields in Manual.MD.
    Raises ValueError with a message safe to print directly if malformed.
    """
    parts = raw.split(':', 2)
    if len(parts) < 2:
        raise ValueError("expected NAME:TYPE[:key=value,...]")
    name, notifier_type = parts[0], parts[1]
    if not name or not notifier_type:
        raise ValueError("NAME and TYPE must both be non-empty")
    if notifier_type not in NOTIFIER_TYPES:
        raise ValueError(f"unknown type '{notifier_type}' - must be one of: "
                          f"{', '.join(sorted(NOTIFIER_TYPES))}")
    fields = {}
    if len(parts) == 3 and parts[2]:
        for pair in parts[2].split(','):
            if '=' not in pair:
                raise ValueError(f"expected key=value in '{pair}'")
            key, value = pair.split('=', 1)
            if not key:
                raise ValueError(f"empty key in '{pair}'")
            fields[key] = value
    return name, {"type": notifier_type, **fields}


def parse_notification_rate_limit_for_arg(raw: str):
    """Parse one --notification-rate-limit-for NAME:MAX[:WINDOW] value into
    (name, {"max_notifications": MAX, [.."window_seconds": WINDOW]}). WINDOW
    is optional - a name given without it still inherits the global window
    (Section 10.6), only overriding max_notifications. MAX of 0 or less
    disables the cap entirely for that one notifier.
    Raises ValueError with a message safe to print directly if malformed.
    """
    parts = raw.split(':', 2)
    if len(parts) < 2:
        raise ValueError("expected NAME:MAX[:WINDOW]")
    name = parts[0]
    if not name:
        raise ValueError("NAME must be non-empty")
    try:
        max_notifications = int(parts[1])
    except ValueError:
        raise ValueError(f"MAX must be an integer, got '{parts[1]}'")
    override = {"max_notifications": max_notifications}
    if len(parts) == 3:
        try:
            override["window_seconds"] = int(parts[2])
        except ValueError:
            raise ValueError(f"WINDOW must be an integer, got '{parts[2]}'")
    return name, override


def parse_notify_on_arg(raw: str):
    """Parse one --notify-on EVENT:NAME[,NAME...] value into (event, [names]).
    Raises ValueError with a message safe to print directly if malformed."""
    if ':' not in raw:
        raise ValueError("expected EVENT:NAME[,NAME...]")
    event, names_str = raw.split(':', 1)
    if event not in NOTIFICATION_EVENTS:
        raise ValueError(f"unknown event '{event}' - must be one of: {', '.join(NOTIFICATION_EVENTS)}")
    names = [n.strip() for n in names_str.split(',') if n.strip()]
    if not names:
        raise ValueError("at least one notifier name is required")
    return event, names


def main():
    """Main server application"""
    parser = argparse.ArgumentParser(description='SSL Key Repository Server')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('command', nargs='?', choices=['init', 'test-notifier'], help='Command to execute')
    parser.add_argument('--listen', default="0.0.0.0", help='IP address to listen on (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5514, help='Port to listen on (default: 5514)')
    parser.add_argument('--bind-also', action='append', default=None, dest='bind_also', metavar='HOST:PORT',
                         help='Also listen on this additional address/port, on top of --listen/--port - '
                              'e.g. --bind-also 10.0.0.5:5514 or --bind-also [::1]:5514 for IPv6. Every '
                              'additional listener handles requests identically to the primary one (both '
                              'the regular signed/encrypted protocol and the plain-HTTP download path). '
                              'Repeat this flag once per extra address - each is added on top of any '
                              'already configured, none are replaced.')
    parser.add_argument('--config', default=DEFAULT_SERVER_CONFIG_FILE, help=f'Configuration file path (default: {DEFAULT_SERVER_CONFIG_FILE})')
    parser.add_argument('--datadir', default='/opt/sslcrtsrv',help='Data directory path, default: /opt/sslcrtsrv)')
    parser.add_argument('--certdir', default='/opt/sslcrtsrv/certs', help='Certificate directory path')
    parser.add_argument('--syslog-host', default=None,
                         help='Send the server process\'s log output to a remote syslog server at this '
                              'host, in addition to the console (Section 10.6). If omitted, logs to the '
                              'local syslog daemon via /dev/log instead - no flag needed for that, the '
                              'default with nothing configured.')
    parser.add_argument('--syslog-port', type=int, default=None,
                         help='Remote syslog server port - only used if --syslog-host is also set '
                              f'(default: {DEFAULT_SYSLOG_PORT}).')
    parser.add_argument('--syslog-facility', default=None,
                         help='Syslog facility to log under, local or remote (e.g. "daemon", "local0"-'
                              f'"local7", "user", ...) (default: "{DEFAULT_SYSLOG_FACILITY}").')
    parser.add_argument('--registration-secret', default=None,
                         help='Shared secret clients must prove knowledge of to register. '
                              'If omitted, a new one is generated and printed once.')
    parser.add_argument('--default-acme-provider', default=None,
                         help=f'Default ACME provider crtrequest.py uses for new certificates, unless '
                              f'overridden per-certificate via crtmanager.py set-provider '
                              f'(default: {DEFAULT_ACME_PROVIDER})')
    parser.add_argument('--client-package', action='append', default=None, metavar='NAME:PATH:VERSION[:DESCRIPTION]',
                         help=f'Add/update one client install package to serve for download over plain '
                              f'HTTP GET on this same port, at {CLIENT_PACKAGE_DOWNLOAD_PATH_PREFIX}NAME '
                              f'- e.g. `curl -f http://<this server>:<port>{CLIENT_PACKAGE_DOWNLOAD_PATH_PREFIX}'
                              f'debian-amd64 -O`. Repeat this flag once per package (e.g. one per OS/'
                              f'architecture: a .deb, an .rpm, a tarball, ...) - each upserts just that '
                              f'named entry, existing ones are left alone. DESCRIPTION is optional and '
                              f'may itself contain colons. Unauthenticated by design: a brand-new host '
                              f'needs this before it has any keys or registration secret. With none '
                              f'configured, these endpoints just report nothing is available.')
    parser.add_argument('--notifier', action='append', default=None, metavar='NAME:TYPE:key=value[,key=value...]',
                         help=f'Add/update one named admin notifier. TYPE is one of: '
                              f'{", ".join(sorted(NOTIFIER_TYPES))} (email is just another type here, e.g. '
                              f'--notifier admin-email:email:notification_recipient=admin@example.com,'
                              f'smtp_host=mail.example.com) - e.g. '
                              f'--notifier ops-pushover:pushover:api_token=abc,user_key=def. Repeat this '
                              f'flag once per notifier - each upserts just that named entry, existing ones '
                              f'are left alone. A notifier alone does nothing until routed to at least one '
                              f'event with --notify-on. See Manual.MD for each type\'s fields.')
    parser.add_argument('--notify-on', action='append', default=None, dest='notify_on', metavar='EVENT:NAME[,NAME...]',
                         help=f'Route one event to one or more notifier names (by name, not type) - e.g. '
                              f'--notify-on error:ops-pushover,admin-email. EVENT is one of: '
                              f'{", ".join(NOTIFICATION_EVENTS)}. Repeat this flag once per event - each '
                              f'replaces just that event\'s routing, other events\' routing is left alone. '
                              f'"error" is a new category with no prior default - it is never routed '
                              f'anywhere unless explicitly set here.')
    parser.add_argument('--notification-rate-limit', type=int, default=None, dest='notification_rate_limit',
                         metavar='MAX',
                         help=f'Global cap on how many notifications any one notifier may send within '
                              f'the rate-limit window (Section 10.6) - the last one allowed through gets '
                              f'a note appended that further notifications may be waiting. 0 or less '
                              f'disables the cap entirely (default: {DEFAULT_RATE_LIMIT_MAX_NOTIFICATIONS}).')
    parser.add_argument('--notification-rate-limit-window', type=int, default=None,
                         dest='notification_rate_limit_window', metavar='SECONDS',
                         help=f'Global rate-limit window length, in seconds (default: '
                              f'{DEFAULT_RATE_LIMIT_WINDOW_SECONDS}).')
    parser.add_argument('--notification-rate-limit-for', action='append', default=None,
                         dest='notification_rate_limit_for', metavar='NAME:MAX[:WINDOW]',
                         help='Override the rate limit for one specific notifier (by name, not type) - '
                              'e.g. --notification-rate-limit-for ops-pushover:3:600. WINDOW is optional '
                              '(inherits the global window if omitted). Repeat this flag once per '
                              'notifier - each upserts just that named override, others are left alone.')
    parser.add_argument('--notifier-name', default=None,
                         help="For 'test-notifier': name of the configured notifier to send a real test "
                              "message through (works for the plain email settings too, under the name "
                              "'email').")
    parser.add_argument('--db-backend', default=None, choices=['sqlite', 'mysql', 'postgresql'],
                         help="Database backend (see common/database.py's configure_database()). "
                              "Omit to keep using sqlite under --datadir, the default - no other "
                              "--db-* flag is needed in that case. For 'mysql'/'postgresql', at least "
                              "--db-host and --db-name are required for the server to actually connect.")
    parser.add_argument('--db-host', default=None, help="mysql/postgresql host")
    parser.add_argument('--db-port', type=int, default=None,
                         help="mysql/postgresql port (default: 3306/5432 respectively)")
    parser.add_argument('--db-user', default=None, help="mysql/postgresql user")
    parser.add_argument('--db-password', default=None, help="mysql/postgresql password")
    parser.add_argument('--db-name', default=None, help="mysql/postgresql database name")
    parser.add_argument('--acme-enabled', action=argparse.BooleanOptionalAction, default=None,
                         help="Enable/disable scs-acme-server(1), the optional RFC 8555 ACME protocol "
                              "listener - e.g. --acme-enabled or --no-acme-enabled. Omit to leave "
                              "whatever is already configured (or unset/disabled, for a new config) "
                              "untouched. --acme-external-url is also required before scs-acme-server "
                              "will actually start.")
    parser.add_argument('--acme-external-url', default=None,
                         help="Externally-visible base URL of the ACME endpoint, behind the mandatory "
                              "reverse proxy in front of scs-acme-server - e.g. "
                              "https://ca.example.com/acme. Required for --acme-enabled to take effect.")
    parser.add_argument('--acme-listen', default=None,
                         help=f"Local address scs-acme-server binds to, behind the reverse proxy "
                              f"(default: {ACME_DEFAULT_LISTEN}).")
    parser.add_argument('--acme-port', type=int, default=None,
                         help=f"Local port scs-acme-server binds to (default: {ACME_DEFAULT_PORT}).")

    args = parser.parse_args()

    client_packages = None
    if args.client_package:
        client_packages = {}
        for raw in args.client_package:
            try:
                name, entry = parse_client_package_arg(raw)
            except ValueError as e:
                print(f"Error: --client-package '{raw}': {e}")
                sys.exit(1)
            client_packages[name] = entry

    notifiers = None
    if args.notifier:
        notifiers = {}
        for raw in args.notifier:
            try:
                name, entry = parse_notifier_arg(raw)
            except ValueError as e:
                print(f"Error: --notifier '{raw}': {e}")
                sys.exit(1)
            notifiers[name] = entry

    bind_also = None
    if args.bind_also:
        bind_also = []
        for raw in args.bind_also:
            try:
                parse_bind_entry(raw)
            except ValueError as e:
                print(f"Error: --bind-also '{raw}': {e}")
                sys.exit(1)
            bind_also.append(raw)

    notification_rate_limits = None
    if args.notification_rate_limit_for:
        notification_rate_limits = {}
        for raw in args.notification_rate_limit_for:
            try:
                name, override = parse_notification_rate_limit_for_arg(raw)
            except ValueError as e:
                print(f"Error: --notification-rate-limit-for '{raw}': {e}")
                sys.exit(1)
            notification_rate_limits[name] = override

    notification_routing = None
    if args.notify_on:
        notification_routing = {}
        for raw in args.notify_on:
            try:
                event, names = parse_notify_on_arg(raw)
            except ValueError as e:
                print(f"Error: --notify-on '{raw}': {e}")
                sys.exit(1)
            notification_routing[event] = names

    if args.command == 'init':
        # Initialize configuration
        init_config(args.config, args.listen, args.port, args.datadir, args.certdir,
                    args.registration_secret, args.default_acme_provider,
                    client_packages, notifiers, notification_routing,
                    args.syslog_host, args.syslog_port, args.syslog_facility, bind_also,
                    args.notification_rate_limit, args.notification_rate_limit_window,
                    notification_rate_limits,
                    args.db_backend, args.db_host, args.db_port, args.db_user,
                    args.db_password, args.db_name,
                    args.acme_enabled, args.acme_external_url, args.acme_listen, args.acme_port)
        return

    if args.command == 'test-notifier':
        if not args.notifier_name:
            print("Error: --notifier-name is required for 'test-notifier'")
            sys.exit(1)
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"Configuration file {config_path} not found. Please run 'init' command first.")
            sys.exit(1)
        with open(config_path, 'r') as f:
            config = json.load(f)
        from .common.notify_utils import send_test_notification_for
        success = send_test_notification_for(config, args.notifier_name)
        sys.exit(0 if success else 1)

    print("Starting SSL Key Repository Server...")
    
    # Load configuration from file
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Configuration file {config_path} not found. Please run 'init' command first.")
        sys.exit(1)
        
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        # Update config with command line arguments if provided
        if args.certdir:
            config['cert_home_dir'] = args.certdir
            
        # Create a new server with configured settings. Pass the actual
        # --config path through (not just the DEFAULT_SERVER_CONFIG_FILE
        # Server() falls back to) so the config-change watcher restarts on
        # edits to the file this invocation was actually told to use.
        server = create_server(config['listen_address'], config['port'], config_file_path=str(config_path))
        
        # Start the server
        try:
            start_server(server)
        except KeyboardInterrupt:
            logger.info("Shutting down server...")
        except Exception as e:
            logger.error(f"Server error: {e}")
            from .common.notify_utils import notify_error
            notify_error(server.config, "server_crash",
                         "[sslcrtsrv] Server process crashed",
                         f"The server process exited due to an unhandled error: {e}\n\n"
                         f"It is no longer running and will not restart automatically "
                         f"unless managed by systemd or a similar supervisor.")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in configuration file {config_path}")
        sys.exit(1)
    except database.SchemaOutOfDate as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
