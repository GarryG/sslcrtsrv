#!/usr/bin/env python3
# SSL Key Repository Client Application

import sys
import os
import argparse
import contextlib
import io
import json
import getpass
from pathlib import Path

from .common import create_client, connect_client, register_client
from .common.client_utils import (
    Client, check_for_client_package_update, download_client_package,
    list_available_packages, detect_package_type
)
from .common.crypto_utils import generate_key_pair, save_keys, load_private_key, load_public_key
from .common.constants import DATA_DIR, BASE_CONFIG_DIR, DEFAULT_SERVER_HOST, DEFAULT_SERVER_PORT
from .common.system_utils import get_fqdn, ensure_secure_dir, write_secure_json
from . import __version__

# rich is optional for the client (unlike the server side, which requires
# it unconditionally for crtmanager.py/cltmanager.py/admintui) - it's only
# ever used here to prettify the listcerts/info tables below, so a client
# host that only has `cryptography` installed still works, just with a
# plain-text fallback instead of a styled table.
try:
    from rich.console import Console
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Exit code for `retrieve`: the destination certificate already exists, is
# valid, and is not older than the one just retrieved - nothing was written
# and --exec was not run. Distinct from 0 (replaced) and 1 (a real failure)
# so wrapper scripts/cron jobs can tell "no update needed" apart from both.
EXIT_CERTIFICATE_NOT_REPLACED = 10

# Event names _dispatch() may report via _Outcome.event, for
# _run_dispatch_and_notify() to route through client_config.json's own
# "notification_routing" (Manual.MD Section 10.3.1/5.2). Deliberately NOT
# merged into or validated against common/notify_utils.py's
# NOTIFICATION_EVENTS - that tuple only feeds server.py's `--notify-on`
# argparse choices and admintui's server-only Notifiers Tab checkbox list,
# neither of which ever touches client_config.json. client_config.json's
# notification_routing has no CLI/TUI writer at all - it's always
# hand-edited - so this tuple exists purely for documentation/consistency
# within this file, not for enforced validation.
CLIENT_NOTIFICATION_EVENTS = (
    "client_registered", "client_certificate_requested",
    "client_certificate_retrieved", "client_update_downloaded",
    "client_update_installed", "error",
)


def _version_tuple(version_str):
    """Parse a dotted version string ("0.8.2") into a tuple of ints for
    comparison - plain string comparison would misorder e.g. "0.8.10" before
    "0.8.9". Any non-numeric component becomes 0 rather than raising, since
    this only ever feeds a best-effort comparison, not validation."""
    parts = []
    for part in str(version_str).split('.'):
        digits = ''.join(ch for ch in part if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _version_is_newer(version_a, version_b):
    """True if version_a is strictly newer than version_b."""
    tuple_a, tuple_b = _version_tuple(version_a), _version_tuple(version_b)
    max_len = max(len(tuple_a), len(tuple_b))
    tuple_a += (0,) * (max_len - len(tuple_a))
    tuple_b += (0,) * (max_len - len(tuple_b))
    return tuple_a > tuple_b


def _print_table(title, columns, rows):
    """Print `rows` (each a tuple of strings, one per column) under `title`.
    Uses a styled rich Table when available; falls back to plain
    fixed-width text otherwise, since rich is optional here (see the import
    above)."""
    if HAS_RICH:
        console = Console()
        table = Table(title=title, show_header=True, header_style="bold blue")
        for name, style in columns:
            table.add_column(name, style=style)
        for row in rows:
            table.add_row(*row)
        console.print(table)
        return

    widths = [len(name) for name, _style in columns]
    for row in rows:
        for i, value in enumerate(row):
            widths[i] = max(widths[i], len(value))

    print(title)
    print("  ".join(name.ljust(widths[i]) for i, (name, _style) in enumerate(columns)))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(value.ljust(widths[i]) for i, value in enumerate(row)))


def init_config(config_file_path, server_host=None, server_port=None, data_dir=None, client_id=None,
                 registration_secret=None):
    """Initialize configuration file with keys and settings"""
    
    # Create directory if it doesn't exist, restricted to owner access
    config_dir = os.path.dirname(config_file_path)
    if config_dir and not os.path.exists(config_dir):
        try:
            ensure_secure_dir(config_dir)
            print(f"Created directory: {config_dir}")
        except OSError as e:
            print(f"Error creating directory {config_dir}: {e}")
            return False
    
    # Check if config file already exists
    if os.path.exists(config_file_path):
        print(f"Configuration file {config_file_path} already exists.")
        while True:
            choice = input("Do you want to (c)ancel, (o)verwrite (creating new keys), or (u)pdate (only address/port)? ").lower()
            if choice in ['c', 'cancel']:
                print("Operation cancelled.")
                return False
            elif choice in ['o', 'overwrite']:
                print("Overwriting configuration with new keys...")
                break
            elif choice in ['u', 'update']:
                print("Updating only address and port (keys will remain unchanged)...")
                # Load existing config to preserve keys
                with open(config_file_path, 'r') as f:
                    existing_config = json.load(f)
                
                # Update only server address and port
                existing_config['server_host'] = server_host if server_host else existing_config.get('server_host', 'localhost')
                existing_config['server_port'] = server_port if server_port else existing_config.get('server_port', 5514)
                existing_config['client_id'] = client_id if client_id else existing_config.get('client_id', get_fqdn())

                # Only touch the registration secret if a new one was explicitly
                # supplied (e.g. the admin rotated it) - otherwise leave whatever
                # was already there alone.
                if registration_secret:
                    existing_config['registration_secret'] = registration_secret

                # Save updated config
                write_secure_json(config_file_path, existing_config)

                print(f"Configuration file {config_file_path} updated successfully.")
                return True
            else:
                print("Invalid choice. Please enter 'c' (cancel), 'o' (overwrite), or 'u' (update).")
    
    # Generate new key pair
    private_key, public_key = generate_key_pair()
    
    # Determine client_id - use provided one or default to FQDN
    if client_id is None:
        client_id = get_fqdn()
    if server_host is None:
        server_host = "localhost"
    if server_port is None:
        server_port = 5514

    # The registration secret must be obtained out-of-band from the server
    # administrator; prompt for it (not echoed) rather than require it on the
    # command line, where it would leak into shell history/process listings.
    while not registration_secret:
        registration_secret = getpass.getpass(
            "Enter the registration secret provided by the server administrator: "
        ).strip()
        if not registration_secret:
            print("A registration secret is required to register with the server.")

    # Create configuration
    config = {
        "client_id": client_id,
        "server_host": server_host,
        "server_port": server_port,
        "private_key": None,  # Will be saved to file
        "public_key": None,   # Will be saved to file
        "registration_secret": registration_secret
    }

    # Add data directory if provided
    if data_dir is not None:
        config["data_dir"] = data_dir
    
    # Save keys directly to configuration (no separate key files)
    from cryptography.hazmat.primitives import serialization
    
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

    # Save configuration file, restricted to owner access (it contains the private key)
    write_secure_json(config_file_path, config)

    print(f"Configuration file {config_file_path} created successfully.")
    return True


def load_config(config_file_path):
    """Load client configuration from JSON file"""
    try:
        with open(config_file_path, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"Error loading configuration: {e}")
        return None


def create_client_from_config(client_id, private_key_str, public_key_str, server_public_key_str=None,
                               registration_secret=None):
    """Create a client instance using keys from the configuration"""
    # Create the actual client with no specific key paths (will use config values)
    client = Client(client_id, server_public_key_str=server_public_key_str,
                     registration_secret=registration_secret)

    # Set up keys using the strings from config
    if not client.setup_keys(private_key_str, public_key_str):
        raise Exception("Failed to setup keys for client from config")

    return client


def resolve_update_package_name(cli_value, config, package_type):
    """Resolve the package name for `update`, in priority order: an explicit
    --update-package always wins; then a literal client_config.json
    'update_package'; then 'update_package_base' combined with this
    install's own detected package type (see common/client_utils.py's
    detect_package_type()) - e.g. base "sslcrtsrv-client" + detected type
    "deb" -> "sslcrtsrv-client-deb", matching whatever naming convention the
    admin used when registering packages via `scs-server init
    --client-package` (TECHNICAL_REFERENCE.md Section 2.2.2). Returns None if nothing
    resolves - callers must then report a clear error, never guess further.
    """
    if cli_value:
        return cli_value
    if config.get('update_package'):
        return config['update_package']
    update_package_base = config.get('update_package_base')
    if update_package_base and package_type:
        return f"{update_package_base}-{package_type}"
    return None


def perform_client_update(server_host, server_port, package_name, update_command):
    """Check the server's client-package catalog for `package_name`, and if
    it's newer than this running client (see sslcrtsrv.__version__), download
    it (saved as `package_name` in the current directory) and, if
    update_command was given, run it to actually install the download.

    Uses the server's plain HTTP endpoints directly (see
    common/client_utils.py's check_for_client_package_update()/
    download_client_package()) - no registration or keys needed, since
    that's exactly what makes this usable to self-update in the first
    place. Returns (exit_code, event): exit_code is 0 on success/nothing
    to do, 1 on any real error; event is one of CLIENT_NOTIFICATION_EVENTS
    ("client_update_downloaded"/"client_update_installed") describing what
    actually happened, or None when nothing changed or the run failed.
    """
    result = check_for_client_package_update(server_host, server_port, package_name, __version__)
    if result['error']:
        print(f"Error checking for update: {result['error']}")
        return 1, None

    print(f"Installed version: {__version__}; server has '{package_name}' at version "
          f"{result['server_version']}")

    if not result['newer']:
        print("Already up to date - nothing to download.")
        return 0, None

    print(f"Newer version available ({result['server_version']} > {__version__}) - downloading...")
    error = download_client_package(server_host, server_port, package_name, package_name)
    if error:
        print(f"Error downloading update: {error}")
        return 1, None

    print(f"Downloaded new package to {package_name}")

    if not update_command:
        print("No --update-command given - package downloaded but not installed.")
        return 0, "client_update_downloaded"

    import subprocess
    try:
        proc_result = subprocess.run(update_command, shell=True, check=True, capture_output=True, text=True)
        print(f"Update command executed successfully: {proc_result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Update command failed: {e.stderr}")
        return 1, None
    except Exception as e:
        print(f"Error executing update command: {e}")
        return 1, None

    return 0, "client_update_installed"


def main():
    """Main client application"""
    parser = argparse.ArgumentParser(description='SSL Key Repository Client')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Init command
    init_parser = subparsers.add_parser('init', help='Initialize client configuration')
    init_parser.add_argument('--client-id', help='Client ID to use. If not provided, system FQDN will be used as default.')
    init_parser.add_argument('--server-host', default="localhost", help='Server host address (default: localhost)')
    init_parser.add_argument('--server-port', type=int, default=5514, help='Server port (default: 5514)')
    init_parser.add_argument('--config', default='/etc/sslcrtsrv/client_config.json', help='Configuration file path (default: /etc/sslcrtsrv/client_config.json)')
    init_parser.add_argument('--datadir', default='/opt/sslcrtsrv', help='Data directory path, default: /opt/sslcrtsrv')
    init_parser.add_argument('--registration-secret', default=None,
                              help='Registration secret provided by the server administrator. '
                                   'If omitted, you will be prompted (recommended, avoids shell history exposure).')
    
    # Admin notifications (Manual.MD Section 10.3/10.3.1) are not gated by a
    # CLI flag: every subcommand except 'init' (a one-time interactive setup
    # step, never run unattended, so there's nothing there worth notifying
    # about) is always wrapped by _run_dispatch_and_notify(), which sends a
    # notification purely based on what client_config.json's own
    # 'notifiers'/'notification_routing' actually route (CLIENT_NOTIFICATION_
    # EVENTS above) - a completely separate notifier configuration from the
    # server's own. With neither key configured, nothing is read or sent,
    # the same no-op behavior as an unconfigured server_config.json.

    # Register command
    register_parser = subparsers.add_parser('register', help='Register client with server')
    register_parser.add_argument('--config', default='/etc/sslcrtsrv/client_config.json', help='Configuration file path (default: /etc/sslcrtsrv/client_config.json)')

    # Request command
    request_parser = subparsers.add_parser('request', help='Request certificates from server')
    request_parser.add_argument('domains', nargs='+', help='One or more FQDNs to request certificates for')
    request_parser.add_argument('--config', default='/etc/sslcrtsrv/client_config.json', help='Configuration file path (default: /etc/sslcrtsrv/client_config.json)')

    # List certificates command
    listcerts_parser = subparsers.add_parser('listcerts', help='List certificates available on the server')
    listcerts_parser.add_argument('--config', default='/etc/sslcrtsrv/client_config.json', help='Configuration file path (default: /etc/sslcrtsrv/client_config.json)')

    # Info command
    info_parser = subparsers.add_parser('info', help='Get certificate information from server')
    info_parser.add_argument('fqdns', nargs='+', help='One or more FQDNs to get certificate information for')
    info_parser.add_argument('--config', default='/etc/sslcrtsrv/client_config.json', help='Configuration file path (default: /etc/sslcrtsrv/client_config.json)')

    # Retrieve command
    retrieve_parser = subparsers.add_parser('retrieve', help='Retrieve certificate from server')
    retrieve_parser.add_argument('fqdns', nargs='+', help='One or more FQDNs to retrieve certificates for')
    retrieve_parser.add_argument('--all', nargs='?', const='', help='File path prefix to save all certificate components (key, cert, intermediate)')
    retrieve_parser.add_argument('--key', nargs='?', const='', help='File path to save the private key')
    retrieve_parser.add_argument('--cert', nargs='?', const='', help='File path to save the certificate')
    retrieve_parser.add_argument('--intermediate', nargs='?', const='', help='File path to save the intermediate certificate')
    retrieve_parser.add_argument('--combined', nargs='?', const='', help='File path to save the certificate followed by the intermediate certificate in one file')
    retrieve_parser.add_argument('--exec', nargs='?', const='', help='Command to execute after retrieving certificates')
    retrieve_parser.add_argument('--config', default='/etc/sslcrtsrv/client_config.json', help='Configuration file path (default: /etc/sslcrtsrv/client_config.json)')

    # Check version command
    checkversion_parser = subparsers.add_parser(
        'checkversion',
        help="Compare this client's version against the server's, exiting 1 if the server is newer")
    checkversion_parser.add_argument('--config', default='/etc/sslcrtsrv/client_config.json', help='Configuration file path (default: /etc/sslcrtsrv/client_config.json)')

    # List packages command
    listpackages_parser = subparsers.add_parser(
        'listpackages', help="List every client package available on the server's catalog")
    listpackages_parser.add_argument('--config', default='/etc/sslcrtsrv/client_config.json', help='Configuration file path (default: /etc/sslcrtsrv/client_config.json)')

    # Update command
    update_parser = subparsers.add_parser('update', help='Check the server for a newer client package and install it')
    update_parser.add_argument('--update-package', default=None, metavar='NAME',
                                help='Name of the client package to check/download, matching a key in '
                                     'the server\'s /client-packages catalog (see server.py init '
                                     '--client-package, or client.py listpackages to see what\'s '
                                     'available) - typically named after the actual package file, e.g. '
                                     '"sslcrtsrv-client-deb". Also used as the local file name a newer '
                                     'package is saved to, in the current directory. If omitted, falls '
                                     'back to client_config.json\'s "update_package" key, or to '
                                     '"update_package_base" combined with this install\'s detected '
                                     'package type (see TECHNICAL_REFERENCE.md Section 2.2.2).')
    update_parser.add_argument('--update-command', default=None,
                                help='Shell command to run after a newer package has been downloaded, '
                                     'to actually install it (e.g. "sudo dpkg -i sslcrtsrv-client_*.deb"). '
                                     'Only run if a newer version was actually downloaded - never run '
                                     'just because --update-package was given. Falls back to '
                                     'client_config.json\'s "update_command" key if omitted.')
    update_parser.add_argument('--config', default='/etc/sslcrtsrv/client_config.json', help='Configuration file path (default: /etc/sslcrtsrv/client_config.json)')

    # For other commands, we don't add server arguments - they just use config
    args = parser.parse_args()

    if args.command in (None, 'init'):
        _dispatch(args, parser, outcome=None)
    else:
        _run_dispatch_and_notify(args, parser)


class _Outcome:
    """Mutable box _dispatch() uses to report which (if any) named success
    event just occurred (one of CLIENT_NOTIFICATION_EVENTS), alongside the
    exit code it also raises via SystemExit. A plain attribute, not a
    return value, because _dispatch() calls sys.exit() from deep inside
    nested branches - there is no single return point to hand a tuple back
    through."""
    def __init__(self):
        self.event = None


def _run_dispatch_and_notify(args, parser):
    """Wraps _dispatch(args, parser, outcome) to capture everything it
    prints - via a tee, so it's still shown live, not silenced - and
    afterwards sends at most one admin notification, purely based on what
    client_config.json's own 'notifiers'/'notification_routing' actually
    route (Manual.MD Section 10.3.1): a generic 'error' notification if the
    run genuinely failed, or a named success notification if _dispatch()
    reported one via `outcome.event` (e.g. retrieve actually replacing a
    certificate, update actually downloading/installing), or nothing at
    all otherwise (a read-only command's success, or retrieve's "nothing
    to do" exit 10). There is no --notify flag gating this any more: with
    nothing configured in client_config.json, notify_admin()/notify_error()
    are already unconditional no-ops, so an untouched config pays only the
    cost of one extra config-file read per invocation.

    Mirrors crtrequest.py's --notify (one summary per run, not per
    individual failure site) - the difference here is client.py has no
    existing logging-module handler to hook into (it uses plain print()
    throughout), so this captures stdout instead of log records.

    Called for every subcommand except 'init' (see main()) - a one-time
    interactive setup step, never run unattended, so there's nothing there
    worth notifying about.
    """
    class _Tee(io.TextIOBase):
        def __init__(self, real, buf):
            self._real = real
            self._buf = buf

        def write(self, s):
            self._real.write(s)
            self._buf.write(s)
            return len(s)

        def flush(self):
            self._real.flush()

    buf = io.StringIO()
    exit_code = 0
    outcome = _Outcome()
    try:
        with contextlib.redirect_stdout(_Tee(sys.stdout, buf)):
            _dispatch(args, parser, outcome)
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else (1 if e.code else 0)

    config = load_config(args.config) or {}

    # EXIT_CERTIFICATE_NOT_REPLACED (10) is a deliberate non-error outcome
    # (Section 3.4.4/Appendix B in Manual.MD) - only 0 and 10 mean "not a
    # failure", every other code is a real failure.
    if exit_code not in (0, EXIT_CERTIFICATE_NOT_REPLACED):
        from .common.notify_utils import notify_error
        notify_error(config, f"client_{args.command}_failed",
                     f"[sslcrtsrv] client.py {args.command} failed",
                     f"client.py {args.command} exited with code {exit_code}.\n\n"
                     f"Output from this run:\n{buf.getvalue()}")
    elif outcome.event:
        from .common.notify_utils import notify_admin
        notify_admin(config, outcome.event,
                     f"[sslcrtsrv] client.py {args.command}: {outcome.event}",
                     f"client.py {args.command} completed successfully.\n\n"
                     f"Output from this run:\n{buf.getvalue()}")

    sys.exit(exit_code)


def _dispatch(args, parser, outcome):
    """Everything main() does once a subcommand's own arguments are parsed.
    `outcome` is an _Outcome instance (see above) that success branches may
    set `.event` on to report a named notification event to
    _run_dispatch_and_notify(); it is None when called directly for 'init'
    or the no-command-given case, neither of which ever touch it.

    Every failure path calls sys.exit(1) explicitly (see the individual
    fixes below) instead of a bare `return`, which previously left the
    process exiting 0 despite reporting a failure - a real, independent bug
    (a failure that doesn't set a nonzero exit code would also be invisible
    to _run_dispatch_and_notify()), matching what Manual.MD's own exit-code
    table already (incorrectly, until fixed) claimed this always did.
    """
    if args.command == 'init':
        # Initialize configuration
        init_config(args.config, args.server_host, args.server_port, args.datadir, args.client_id,
                    args.registration_secret)
        return
    
    if args.command == 'register':
        # Register with server using configuration
        print("Starting registration process...")
        
        # Load configuration from file
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"Configuration file {config_path} not found. Please run 'init' command first.")
            sys.exit(1)
            
        try:
            config = load_config(args.config)
            if config is None:
                print("Failed to load configuration.")
                sys.exit(1)
                
            # Create a new client using the keys from config
            client = create_client_from_config(
                config.get('client_id', 'default_client'),
                config['private_key'],
                config['public_key'],
                config.get('server_public_key'),  # Pass server public key if available
                config.get('registration_secret')
            )
            
            # Connect to server using configuration
            if not connect_client(client, config['server_host'], config['server_port']):
                print("Failed to connect to server")
                sys.exit(1)

            # Register with server
            if not register_client(client, args.config):
                print("Failed to register with server")
                sys.exit(1)

            print("Client registered successfully!")
            outcome.event = "client_registered"

        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in configuration file {config_path}")
            sys.exit(1)
        except Exception as e:
            print(f"Error during registration: {e}")
            sys.exit(1)

        return

    if args.command == 'listpackages':
        # Same "no socket/keys needed" reasoning as 'update' below - plain
        # unauthenticated HTTP against the server's catalog endpoint.
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"Configuration file {config_path} not found. Please run 'init' command first.")
            sys.exit(1)

        config = load_config(args.config)
        if config is None:
            print("Failed to load configuration.")
            sys.exit(1)

        server_host = config.get('server_host', DEFAULT_SERVER_HOST)
        server_port = config.get('server_port', DEFAULT_SERVER_PORT)

        result = list_available_packages(server_host, server_port)
        if result['error']:
            print(f"Error fetching package catalog: {result['error']}")
            sys.exit(1)

        if not result['packages']:
            print("No packages available on the server.")
        else:
            rows = [(name, entry.get('version', 'N/A'), entry.get('description') or '')
                    for name, entry in sorted(result['packages'].items())]
            _print_table("Available Client Packages",
                         [("Name", "cyan"), ("Version", "magenta"), ("Description", "green")],
                         rows)
        sys.exit(0)

    if args.command == 'update':
        # Deliberately doesn't go through the shared config-load/connect_client()
        # block below: checking for and downloading a client package uses the
        # server's plain, unauthenticated HTTP endpoints (see
        # common/server_utils.py's handle_http_download()), not the signed/
        # encrypted socket protocol - there's no need to open that connection
        # at all for this command.
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"Configuration file {config_path} not found. Please run 'init' command first.")
            sys.exit(1)

        config = load_config(args.config)
        if config is None:
            print("Failed to load configuration.")
            sys.exit(1)

        server_host = config.get('server_host', DEFAULT_SERVER_HOST)
        server_port = config.get('server_port', DEFAULT_SERVER_PORT)

        package_name = resolve_update_package_name(args.update_package, config, detect_package_type())
        if not package_name:
            print("Error: no package name to update. Pass --update-package, set 'update_package' "
                  "(or 'update_package_base', combined with this install's detected package type) "
                  "in client_config.json, or run 'listpackages' to see what's available.")
            sys.exit(1)

        update_command = args.update_command or config.get('update_command')

        exit_code, event = perform_client_update(server_host, server_port, package_name, update_command)
        if event:
            outcome.event = event
        sys.exit(exit_code)

    # If no command is specified, show help
    if args.command is None:
        parser.print_help()
        return
    
    # int("Starting SSL Key Repository Client...")
    
    # Load configuration from file
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Configuration file {config_path} not found. Please run 'init' command first.")
        sys.exit(1)
        
    try:
        config = load_config(args.config)
        if config is None:
            print("Failed to load configuration.")
            sys.exit(1)
            
        # Create a new client using the keys from config
        client = create_client_from_config(
            config.get('client_id', 'default_client'),
            config['private_key'],
            config['public_key'],
            config.get('server_public_key')  # Pass server public key if available
        )
        
        # Display public key fingerprint for registration
        # print(f"Client public key fingerprint: {client.public_key_fingerprint}")
        
        # Connect to server using configuration
        if not connect_client(client, config['server_host'], config['server_port']):
            print("Failed to connect to server")
            sys.exit(1)

        # Handle the listcerts command
        if args.command == 'listcerts':
            # List certificates from server
            success = False
            response = client.list_certificates()
            if response:
                # Check if we have a successful response with certificates data
                if response.get("response_type") == "listcerts" and response.get("success"):
                    success = True
                    certificates = response.get("data", {}).get("certificates", [])
                    if not certificates:
                        print("No certificates found.")
                    else:
                        rows = []
                        for cert in certificates:
                            name = cert.get('name', 'N/A')
                            name = name.replace(',', ' ') if name else ""
                            valid_from = cert.get('valid_from', 'N/A')
                            valid_to = cert.get('valid_to', 'N/A')

                            # Extract just the date part (before the time) from valid_from and valid_to
                            if valid_from and ' ' in valid_from:
                                valid_from = valid_from.split(' ')[0]
                            if valid_to and ' ' in valid_to:
                                valid_to = valid_to.split(' ')[0]

                            rows.append((name, valid_from, valid_to))
                        _print_table("Server Certificates",
                                     [("Name", "cyan"), ("Valid From", "magenta"), ("Valid To", "green")],
                                     rows)
                else:
                    print("Error: Invalid response format from server")
                    print(response)
            else:
                print("Failed to retrieve certificate list")
            # Close connection before exiting
            client.close_connection()
            sys.exit(0 if success else 1)

        # Handle the checkversion command
        if args.command == 'checkversion':
            response = client.check_version()
            client.close_connection()
            if not response or not response.get("success"):
                print("Failed to check server version")
                sys.exit(1)

            server_version = response.get("server_version", "unknown")
            print(f"Client version: {__version__}")
            print(f"Server version: {server_version}")

            if _version_is_newer(server_version, __version__):
                print("The server is running a newer version than this client.")
                sys.exit(1)
            print("This client is up to date with the server.")
            sys.exit(0)

        # Handle the request command
        if args.command == 'request':
            # Process FQDNs and request certificates from server
            # Join the list of domains into a comma-delimited string
            domains_string = ','.join(args.domains)
            response = client.request_certificates(domains_string)
            success = False
            if response:
                # Display human-readable response instead of raw JSON
                if response.get("success"):
                    success = True
                    outcome.event = "client_certificate_requested"
                    # No separate "successful!" banner here - the server's own
                    # message already says exactly what happened ("...
                    # registered successfully" for a new request, "...already
                    # registered" for a duplicate), and both are reported with
                    # success=True since neither is an error condition; a
                    # generic banner in front was redundant for the former and
                    # read as contradictory for the latter.
                    message = response.get("data", {}).get("message", "Request registered successfully")
                    domains = response.get("data", {}).get("domains", domains_string)
                    print(f"{message}")
                    print(f"Domains: {domains}")
                else:
                    print("Certificate request failed!")
                    message = response.get("data", {}).get("message", "Unknown error")
                    print(f"Error: {message}")
            else:
                print("Failed to request certificates")
            # Close connection before exiting
            client.close_connection()
            sys.exit(0 if success else 1)
        
        # Handle the info command
        if args.command == 'info':
            # Get certificate information from server
            fqdns_string = ','.join(args.fqdns)
            response = client.get_certificate_info(fqdns_string)
            success = False
            if response:
                if response.get("response_type") == "info" and response.get("success"):
                    success = True
                    cert_info = response.get("data", {}).get("certificate", {})
                    rows = [
                        ("FQDNs", cert_info.get('fqdns', 'N/A')),
                        ("Valid From", cert_info.get('validity_start_date', 'N/A')),
                        ("Valid To", cert_info.get('validity_end_date', 'N/A')),
                        ("Format", cert_info.get('format', 'N/A')),
                        ("Certifier", cert_info.get('certifier', 'N/A')),
                        ("Key Present", str(cert_info.get('key_present', 'N/A'))),
                        ("Intermediate Present", str(cert_info.get('intermediate_present', 'N/A'))),
                        ("Certificate Present", str(cert_info.get('cert_present', 'N/A'))),
                        ("Parts Present", ', '.join(cert_info.get('parts_present', []))),
                    ]
                    _print_table("Certificate Information",
                                 [("Property", "cyan"), ("Value", "green")], rows)
                else:
                    print(f"Error getting certificate info: {response.get('data', {}).get('message', 'Unknown error')}")
            else:
                print("Failed to get certificate info")
            # Close connection before exiting
            client.close_connection()
            sys.exit(0 if success else 1)
        
        # Handle the retrieve command
        if args.command == 'retrieve':
            # Retrieve certificate from server
            fqdns_string = ','.join(args.fqdns)
            # Fix: command should be args.command (the value of the --command argument) 
            # but only if it's not None/empty (the nargs='?' with const='' creates an empty string when used)
            command_to_execute = args.exec if args.exec is not None and args.exec != '' else None
            key_path = cert_path = intermediate_path = combined_path = None

            # Handle --all parameter
            if args.all is not None:
                # When --all is used, create three files with the same prefix but different extensions
                key_path = args.all + ".key"
                cert_path = args.all + ".cer"
                intermediate_path = args.all + ".inter"

            # Overwrite individual file parameters if they are provided (they take precedence over --all)
            if args.key:
                key_path = args.key
            if args.cert:
                cert_path = args.cert
            if args.intermediate:
                intermediate_path = args.intermediate
            if args.combined:
                combined_path = args.combined

            response = client.retrieve_certificate(
                fqdns_string,
                key_path=key_path,
                cert_path=cert_path,
                intermediate_path=intermediate_path,
                combined_path=combined_path,
                exec=command_to_execute
            )

            success = False
            if response:
                if response.get("success"):
                    success = True
                    if response.get("data", {}).get("certificate_replaced") is False:
                        print("Certificate not replaced: the existing certificate is still valid "
                              "and not older than the one just retrieved.")
                        client.close_connection()
                        sys.exit(EXIT_CERTIFICATE_NOT_REPLACED)
                    outcome.event = "client_certificate_retrieved"
                    print("Certificate retrieval successful!")
                else:
                    print("Certificate retrieval failed!")
                    print(f"Error details: {response.get('data', {}).get('message', 'Unknown error')}")
            else:
                print("Failed to retrieve certificate")
            # Close connection before exiting
            client.close_connection()
            sys.exit(0 if success else 1)
        
        # Register with server (this is for the default case, but it's not really needed for the commands)
        # The registration is already handled by the specific command handlers
        # If we get here, it means we're not in a specific command that handled registration
        
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in configuration file {config_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error running client: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
