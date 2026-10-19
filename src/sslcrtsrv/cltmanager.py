#!/usr/bin/env python3

import os
import sys
import datetime
import hashlib
import ipaddress
import logging
import argparse
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.table import Table

from . import __version__
from .common.constants import DEFAULT_SERVER_CONFIG_FILE, DEFAULT_SERVER_PORT
from .common.fqdns_utils import normalize_fqdns

# A quiet audit trail for the state-changing actions below (confirm/revoke/
# assign/acme_* grant management, ...) - separate from this file's existing
# print()/rich.Console console output, which stays exactly as it was. These
# functions are shared verbatim by admintui (calling them in-process, e.g.
# screens/clients.py), so logging here covers both entry points from one
# place rather than needing separate audit logging in the TUI layer too.
# Reaches console/file/syslog only once something in this process has
# called common.logging_utils.setup_tool_logging() (main() below does, for
# the CLI; admintui's __main__.py does the same for the TUI) - before that,
# an INFO-level call here is simply dropped (never raises), so no caller is
# required to set logging up first for these functions to still work.
#
# Explicit name, not logging.getLogger(__name__): this module can be run
# directly via `python3 -m sslcrtsrv.cltmanager`, under which __name__
# becomes "__main__" rather than "sslcrtsrv.cltmanager" - a logger named
# "__main__" would not be a descendant of "sslcrtsrv" and would never reach
# the handlers common/logging_utils.py's setup_tool_logging() configures
# there (see server.py's identical note for its own logger). Importing this
# module normally (e.g. admintui's `from ... import cltmanager`) is
# unaffected either way - only matters for how *this* module is loaded.
logger = logging.getLogger("sslcrtsrv.cltmanager")
from .common.database import (
    init_database, get_all_clients, get_unconfirmed_clients, update_client_status,
    delete_client_by_id, apply_data_dir_from_config, get_client_by_id_or_client_id,
    get_certificate_fqdns_by_id, add_client_certificate_relation, create_certificate_entry,
    delete_all_client_certificate_relations, delete_client_certificate_relation,
    set_permission_valid_until, get_pending_client_certificate_relations,
    delete_pending_client_certificate_relations, set_client_allowed_ip,
    cancel_acme_order as _db_cancel_acme_order,
    create_acme_trust_grant, get_acme_trust_grants, revoke_acme_trust_grant,
)

def parse_valid_until(value):
    """Parse a --valid-until/set_expiry CLI value into a naive UTC datetime,
    or None for a permission that never expires. Accepts the literal 'never'
    and bare dates ('2026-12-31') as well as full ISO datetimes
    ('2026-12-31T23:59:59') - always interpreted as UTC, matching how
    permission_valid_until is compared against (see common/database.py's
    permission_is_active()/_utcnow()). Raises ValueError with a
    human-readable message on anything else."""
    if not value or value.strip().lower() == 'never':
        return None
    try:
        return datetime.datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f"Invalid date/time '{value}' - use e.g. '2026-12-31' or '2026-12-31T23:59:59' (or 'never')")

def utc_to_local(utc_dt):
    """Convert UTC datetime to local timezone"""
    # Ensure the datetime is timezone-aware (UTC)
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=datetime.timezone.utc)
    return utc_dt.astimezone(tz=None)

def list_unconfirmed_clients():
    """List all unconfirmed client registrations. Returns False if listing
    them failed (see issue.md - previously any of these functions returning
    nothing let cltmanager.py's main() exit 0 even after printing an error)."""
    # Initialize database
    init_database()

    console = Console()

    table = Table(title="Unconfirmed Client Registrations", show_header=True, header_style="bold blue")
    table.add_column("Client ID", style="cyan")
    table.add_column("Registration Date", style="magenta")
    table.add_column("Public Key Fingerprint", style="green")

    try:
        clients = get_unconfirmed_clients()
        if not clients:
            console.print("[bold yellow]No unconfirmed clients found.[/bold yellow]")
            return True

        for client in clients:
            # Convert registration_date to local time
            if client.registration_date:
                try:
                    # Handle registration_date which can be either a datetime object or string
                    if isinstance(client.registration_date, str):
                        # Parse the UTC date string and convert to local time
                        utc_dt = datetime.datetime.fromisoformat(client.registration_date.replace('Z', '+00:00'))
                    elif isinstance(client.registration_date, datetime.datetime):
                        # Already a datetime object, just use it
                        utc_dt = client.registration_date
                    else:
                        # If it's neither a string nor datetime, treat as invalid
                        raise ValueError("Invalid registration_date format")
                    
                    local_dt = utc_to_local(utc_dt)
                    reg_date = local_dt.strftime('%Y-%m-%d %H:%M:%S')
                    print(f"Converted registration date: {reg_date} (Local Time)")
                except Exception as e:
                    # If conversion fails, display the original date
                    print(f"Error converting registration date: {e}")
                    reg_date = str(client.registration_date)
            else:
                reg_date = "N/A"
            
            # Calculate and display public key fingerprint
            public_key_pem = client.public_key
            # Parse the public key to get its fingerprint
            try:
                public_key = serialization.load_pem_public_key(
                    public_key_pem.encode('utf-8'),
                    backend=default_backend()
                )
                public_key_der = public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                fingerprint = hashlib.sha256(public_key_der).hexdigest()
            except Exception as e:
                fingerprint = f"Error calculating fingerprint: {e}"
            
            table.add_row(client.client_id, reg_date, fingerprint)

    except Exception as e:
        console.print(f"[bold red]Error reading clients: {e}[/bold red]")
        return False

    console.print(table)
    return True

def list_all_clients():
    """List all client entries with a short overview. Returns False if
    listing them failed (see issue.md)."""
    # Initialize database
    init_database()

    console = Console()

    table = Table(title="All Client Entries", show_header=True, header_style="bold blue")
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("Client ID", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Version", style="blue")
    table.add_column("Last Successful Connection", style="yellow")
    table.add_column("Last IP", style="yellow")

    try:
        clients = get_all_clients()
        if not clients:
            console.print("[bold yellow]No clients found.[/bold yellow]")
            return True

        for client in clients:
            # Format client_id to max 30 characters
            client_id_display = client.client_id[:27] + "..." if len(client.client_id) > 30 else client.client_id
            
            # Convert last successful connection time to local time if available
            if client.last_successful_connection:
                try:
                    # Handle different formats of last_successful_connection
                    if isinstance(client.last_successful_connection, str):
                        # Parse the UTC date string and convert to local time
                        utc_dt = datetime.datetime.fromisoformat(client.last_successful_connection.replace('Z', '+00:00'))
                    elif isinstance(client.last_successful_connection, datetime.datetime):
                        utc_dt = client.last_successful_connection
                    else:
                        # If it's already a datetime object or other type, just use it as is
                        utc_dt = client.last_successful_connection
                    
                    local_dt = utc_to_local(utc_dt)
                    last_success = local_dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception as e:
                    # If conversion fails, display the original date
                    last_success = str(client.last_successful_connection)
            else:
                last_success = 'N/A'
            
            table.add_row(str(client.id), client_id_display, client.status,
                          client.client_version or 'N/A', last_success, client.last_connection_ip or 'N/A')
            
    except Exception as e:
        console.print(f"[bold red]Error reading clients: {e}[/bold red]")
        return False

    console.print(table)
    return True

def generate_registration_command(client_id=None, server_host=None, server_port=None, config_file_path=None):
    """CLI-facing: print the exact `client.py init`/`client.py register`
    command lines a new client host should run to register against this
    server, built from server_config.json's own registration_secret/port -
    same file/pattern get_client_action_preview() already reads `public_key`
    from - so an admin copies this output instead of typing Manual.MD's
    Section 4.3.2 walkthrough by hand each time.

    server_host must be given explicitly unless server_config.json's own
    listen_address is a concrete, non-wildcard address: "0.0.0.0"/"::" are
    bind addresses, not something a remote client could use to reach this
    server, and there is no separate "public hostname" field anywhere for
    the traditional protocol (unlike acme_external_url, which is ACME-only
    and unrelated).
    """
    config_file_path = config_file_path or DEFAULT_SERVER_CONFIG_FILE
    try:
        with open(config_file_path, 'r') as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"Error: could not read {config_file_path}: {e}")
        return False

    registration_secret = config.get('registration_secret')
    if not registration_secret:
        print(f"Error: no 'registration_secret' set in {config_file_path} - registration is "
              f"disabled until one is configured. Run 'scs-server init --registration-secret "
              f"<secret>' (or rotate it, Manual.MD Section 9.5) first.")
        return False

    if not server_host:
        listen_address = config.get('listen_address')
        if listen_address and listen_address not in ('0.0.0.0', '::'):
            server_host = listen_address
        else:
            print(f"Error: {config_file_path}'s listen_address is {listen_address!r} - a bind "
                  f"address, not something a remote client can connect to. Pass --server-host "
                  f"with this server's actual externally-reachable hostname or IP.")
            return False

    server_port = server_port or config.get('port', DEFAULT_SERVER_PORT)

    init_cmd = (f"scs-client init --server-host {server_host} --server-port {server_port} "
                f"--registration-secret '{registration_secret}'")
    if client_id:
        init_cmd += f" --client-id {client_id}"

    print("Run these on the new client host:")
    print()
    print(f"  {init_cmd}")
    print("  scs-client register")
    print()
    print("Then, on this server, once 'register' succeeds:")
    print()
    confirm_target = client_id if client_id else "<client-id register reports>"
    print(f"  sudo scs-cltmanager confirm {confirm_target}")
    print()
    print("'confirm' shows both public-key fingerprints for comparison before accepting - "
          "verify them against what 'register' printed on the client before answering yes "
          "(TECHNICAL_REFERENCE.md's Section 2.3.4).")
    print()
    print("Note: --registration-secret is embedded above for one-line convenience - it will "
          "appear in the new host's shell history and process listing. client.py init's own "
          "--registration-secret is optional and prompts interactively instead, specifically "
          "to avoid that; omit the flag above (client.py will then prompt for it) if this "
          "matters for a given deployment.")
    return True

def get_client_action_preview(client_id, action="confirm", config_file_path=None):
    """Pure preview for confirm_client(): resolves the client, checks whether
    confirm/revoke is blocked by current status, and computes both public-key
    fingerprints for the identity-verification step - all without printing or
    prompting, so callers (the CLI, or a future admin UI) can present it
    however they like.

    Fingerprint math is duplicated from crypto_utils.get_public_key_fingerprint()
    rather than calling it, since that helper prints its own error message and
    swallows the exception - which would both corrupt a full-screen UI's
    display and lose the distinct error text confirm_client() has always shown
    here.

    `config_file_path` is the server's own config file - only its `public_key`
    is read from it, to compute the server's fingerprint for comparison
    against `client_fingerprint`. Defaults to DEFAULT_SERVER_CONFIG_FILE (see
    issue.md - this used to be a second, independent hardcoded copy of that
    same path, with no way to point it at a server running with a non-default
    `--config`).

    Returns a dict:
      client, status_blocked_reason,
      client_fingerprint, client_fingerprint_error,
      server_fingerprint, server_fingerprint_error
    """
    config_file_path = config_file_path or DEFAULT_SERVER_CONFIG_FILE
    client = get_client_by_id_or_client_id(client_id)
    if not client:
        return {
            'client': None, 'status_blocked_reason': None,
            'client_fingerprint': None, 'client_fingerprint_error': None,
            'server_fingerprint': None, 'server_fingerprint_error': None,
        }

    status_blocked_reason = None
    if action == "confirm" and client.status == 'confirmed':
        status_blocked_reason = f"Client with ID {client.client_id} is already confirmed."
    elif action == "revoke" and client.status != 'confirmed':
        status_blocked_reason = f"Client with ID {client.client_id} is not confirmed, cannot revoke."
    elif action not in ("confirm", "revoke"):
        status_blocked_reason = f"Error: Unknown action '{action}'. Use 'confirm' or 'revoke'."

    client_fingerprint = client_fingerprint_error = None
    server_fingerprint = server_fingerprint_error = None

    if action != "revoke" and status_blocked_reason is None:
        try:
            public_key = serialization.load_pem_public_key(
                client.public_key.encode('utf-8'),
                backend=default_backend()
            )
            public_key_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_fingerprint = hashlib.sha256(public_key_der).hexdigest()
        except Exception as e:
            client_fingerprint_error = f"Error calculating client fingerprint: {e} - no valid public key found"

        if client_fingerprint_error is None:
            try:
                with open(config_file_path, 'r') as f:
                    config = json.load(f)

                server_public_key = serialization.load_pem_public_key(
                    config['public_key'].encode('utf-8'),
                    backend=default_backend()
                )
                server_public_key_der = server_public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                server_fingerprint = hashlib.sha256(server_public_key_der).hexdigest()
            except Exception as e:
                server_fingerprint_error = f"Error calculating server fingerprint: {e}"

    return {
        'client': client,
        'status_blocked_reason': status_blocked_reason,
        'client_fingerprint': client_fingerprint,
        'client_fingerprint_error': client_fingerprint_error,
        'server_fingerprint': server_fingerprint,
        'server_fingerprint_error': server_fingerprint_error,
    }

def apply_client_action(client_id, action="confirm"):
    """Pure tail of confirm_client(): flips the client's status, with no
    print()/input(). client_id here is the string client_id (not the numeric
    DB id) - matches what confirm_client() has always passed to
    update_client_status()."""
    if action == "revoke":
        success = update_client_status(client_id, 'registered')
    elif action == "confirm":
        success = update_client_status(client_id, 'confirmed')
    else:
        return False
    (logger.info if success else logger.warning)("%s client %s: %s", action, client_id,
                                                   "ok" if success else "failed")
    return success

def cancel_acme_order(order_id):
    """Pure wrapper around common.database.cancel_acme_order() - no print(),
    so admintui can call it directly (same convention as
    apply_client_action() above); the acme_cancel_order CLI subcommand
    wraps this with its own success/failure print for terminal use."""
    success = _db_cancel_acme_order(order_id)
    (logger.info if success else logger.warning)("cancel_acme_order %s: %s", order_id,
                                                   "ok" if success else "failed")
    return success

def create_acme_eab_grant(label, allowed_fqdns_pattern, expires_at=None):
    """CLI-facing: create a new RFC 8555 External Account Binding trust
    grant (common/database.py's AcmeTrustGrant) and print the generated
    kid/HMAC key, ready to paste into an ACME client's EAB configuration
    (e.g. FortiOS 7.6.3+'s `config vpn certificate local` EAB fields).
    Prints the HMAC key exactly once - it cannot be recovered again
    afterward, only the encrypted form is kept."""
    init_database()
    result = create_acme_trust_grant(label, allowed_fqdns_pattern, method='eab', expires_at=expires_at)
    if result is None:
        logger.warning("create_acme_eab_grant %r: failed", label)
        print("Error: could not create EAB trust grant.")
        return False
    grant = result['grant']
    # Never the secret itself (grant.eab_kid is a public-ish identifier,
    # fine to log; result['secret'] - the HMAC key - never is).
    logger.info("create_acme_eab_grant %r (id %s, kid %s): ok", label, grant.id, grant.eab_kid)
    print(f"EAB trust grant '{label}' created (id {grant.id}).")
    print(f"Allowed fqdns pattern: {allowed_fqdns_pattern} (fnmatch glob - '*' matches across dots too)")
    print(f"Expires: {expires_at if expires_at else 'never'}")
    print()
    print("Configure the ACME client's External Account Binding with:")
    print(f"  Key ID (kid): {grant.eab_kid}")
    print(f"  HMAC key:     {result['secret']}  (base64url, unpadded)")
    print()
    print("This is the only time the HMAC key is shown - it cannot be recovered again afterward.")
    return True

def create_acme_contact_token_grant(label, allowed_fqdns_pattern, expires_at=None, domain="sslcrtsrv.local"):
    """CLI-facing: create a new contact-token trust grant - the fallback
    for ACME clients with no EAB support at all (e.g. FortiOS < 7.6.3,
    whose ACME config exposes only a free-text Email field). Prints the
    exact plus-addressed contact string to paste into that field, and the
    raw token exactly once - only its hash is kept, so it cannot be
    recovered again afterward."""
    init_database()
    result = create_acme_trust_grant(label, allowed_fqdns_pattern, method='contact_token', expires_at=expires_at)
    if result is None:
        logger.warning("create_acme_contact_token_grant %r: failed", label)
        print("Error: could not create contact-token trust grant.")
        return False
    grant = result['grant']
    # Never the raw token itself (result['secret']) - only its id/label.
    logger.info("create_acme_contact_token_grant %r (id %s): ok", label, grant.id)
    print(f"Contact-token trust grant '{label}' created (id {grant.id}).")
    print(f"Allowed fqdns pattern: {allowed_fqdns_pattern} (fnmatch glob - '*' matches across dots too)")
    print(f"Expires: {expires_at if expires_at else 'never'}")
    print()
    print("Configure the ACME client's contact/email field with exactly:")
    print(f"  provisioning+{result['secret']}@{domain}")
    print()
    print("This is the only time the token is shown - it cannot be recovered again afterward.")
    return True

def list_acme_trust_grants():
    """Print every ACME trust grant (id/label/method/pattern/expiry/
    revoked/last-used/use-count) - never the raw secret, which isn't
    recoverable from what's stored anyway (see create_acme_eab_grant()/
    create_acme_contact_token_grant())."""
    init_database()
    grants = get_acme_trust_grants()
    if not grants:
        print("No ACME trust grants configured.")
        return True
    table = Table(title="ACME Trust Grants")
    table.add_column("ID")
    table.add_column("Label")
    table.add_column("Method")
    table.add_column("Allowed FQDNs pattern")
    table.add_column("Expires")
    table.add_column("Revoked")
    table.add_column("Last used")
    table.add_column("Uses")
    for grant in grants:
        method = "EAB" if grant.eab_kid else "Contact-token"
        table.add_row(
            str(grant.id), grant.label, method, grant.allowed_fqdns_pattern,
            str(grant.expires_at) if grant.expires_at else "Never",
            str(grant.revoked_at) if grant.revoked_at else "No",
            str(grant.last_used_at) if grant.last_used_at else "Never",
            str(grant.use_count),
        )
    Console().print(table)
    return True

def revoke_trust_grant(grant_id):
    """CLI-facing wrapper around common.database.revoke_acme_trust_grant()."""
    init_database()
    success = revoke_acme_trust_grant(grant_id)
    (logger.info if success else logger.warning)("revoke_trust_grant %s: %s", grant_id,
                                                   "ok" if success else "failed")
    if success:
        print(f"ACME trust grant {grant_id} revoked.")
    else:
        print(f"Error: ACME trust grant {grant_id} not found, or already revoked.")
    return success

def confirm_client(client_id, action="confirm", config_file_path=None):
    """Confirm or revoke a client entry by ID"""
    preview = get_client_action_preview(client_id, action, config_file_path=config_file_path)
    client = preview['client']

    if not client:
        print(f"Error: Client with ID {client_id} not found.")
        return False

    if preview['status_blocked_reason']:
        print(preview['status_blocked_reason'])
        return False

    # Display client information
    print(f"Client ID: {client.client_id}")
    print(f"Last IP: {client.last_connection_ip or 'N/A'}")

    # Convert registration_date to local time
    if client.registration_date:
        try:
            # Parse the UTC date string and convert to local time
            utc_dt = datetime.datetime.fromisoformat(client.registration_date.replace('Z', '+00:00'))
            local_dt = utc_to_local(utc_dt)
            print(f"Registered at: {local_dt.strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception:
            # If conversion fails, display the original date
            print(f"Registered at: {client.registration_date}")
    else:
        print("Registered at: N/A")

    if action != "revoke":
        from .common.fingerprint_words import format_fingerprint_words

        if preview['client_fingerprint_error']:
            print(preview['client_fingerprint_error'])
            return False
        print(f"Client's Public Key Fingerprint: {preview['client_fingerprint']}")
        print(format_fingerprint_words(preview['client_fingerprint']))

        if preview['server_fingerprint_error']:
            print(preview['server_fingerprint_error'])
            return False
        print(f"Server's Public Key Fingerprint: {preview['server_fingerprint']}")
        print(format_fingerprint_words(preview['server_fingerprint']))

    # Ask for user confirmation
    confirm = input(f"Do you want to {action} client {client.client_id}? (yes/no): ")

    if confirm.lower() in ['yes', 'y']:
        success = apply_client_action(client.client_id, action)
        if success:
            print(f"Client with ID {client.client_id} has been {action}ed successfully.")
            return True
        else:
            print(f"Error: Failed to {action} client with ID {client.client_id}.")
            return False
    else:
        print(f"{action} cancelled.")
        return False

def revoke_client(client_id):
    """Revoke a client's confirmation by ID"""
    # This function is just a wrapper around confirm_client for revoke action
    return confirm_client(client_id, action="revoke")

def get_acme_client_action_preview(client_id):
    """Pure preview for confirm_acme_client(): resolves the client, checks
    it's actually an ACME account and not already confirmed, and surfaces
    its RFC 7638 JWK thumbprint - the canonical account-key identity ACME
    tooling itself treats an account key by (ACME_SERVER_DESIGN.md §4.1/
    §7.1), used here instead of a re-derived PEM/SPKI fingerprint.

    A separate function from get_client_action_preview() rather than a
    branch inside it: that function's PEM-parsing/dual-fingerprint logic is
    tightly coupled to the custom protocol's mutual-auth key model, which
    doesn't apply here - ACME's own JWS authentication has no server-side
    key for the account to compare against, so there is no "server
    fingerprint" to compute or show.

    Returns a dict: client, status_blocked_reason, thumbprint, thumbprint_error
    """
    client = get_client_by_id_or_client_id(client_id)
    if not client:
        return {'client': None, 'status_blocked_reason': None,
                'thumbprint': None, 'thumbprint_error': None}

    status_blocked_reason = None
    if client.client_kind != 'acme':
        status_blocked_reason = (
            f"Client with ID {client.client_id} is not an ACME account "
            f"(use 'confirm' for a custom-protocol client)."
        )
    elif client.status == 'confirmed':
        status_blocked_reason = f"ACME account {client.client_id} is already confirmed."

    thumbprint = thumbprint_error = None
    if status_blocked_reason is None:
        # Already computed once at newAccount time and stored - reusing it
        # here (rather than recomputing from public_key) keeps this display
        # guaranteed consistent with client_id itself (which is literally
        # f"acme:{thumbprint}").
        thumbprint = client.acme_key_thumbprint
        if not thumbprint:
            thumbprint_error = f"Error: ACME account {client.client_id} has no stored thumbprint."

    return {
        'client': client,
        'status_blocked_reason': status_blocked_reason,
        'thumbprint': thumbprint,
        'thumbprint_error': thumbprint_error,
    }

def confirm_acme_client(client_id):
    """Confirm an ACME account by ID (ACME_SERVER_DESIGN.md §5.6/§7.1) - the
    ACME-specific counterpart to confirm_client(), comparing the RFC 7638
    JWK thumbprint instead of a PEM/SPKI fingerprint. There is no
    ACME-specific 'revoke': the existing `revoke`/`delete` commands are
    already generic over client_kind and need no ACME-specific variant."""
    preview = get_acme_client_action_preview(client_id)
    client = preview['client']

    if not client:
        print(f"Error: Client with ID {client_id} not found.")
        return False

    if preview['status_blocked_reason']:
        print(preview['status_blocked_reason'])
        return False

    print(f"Client ID: {client.client_id}")
    if client.registration_date:
        try:
            utc_dt = datetime.datetime.fromisoformat(client.registration_date.replace('Z', '+00:00'))
            local_dt = utc_to_local(utc_dt)
            print(f"Registered at: {local_dt.strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception:
            print(f"Registered at: {client.registration_date}")
    else:
        print("Registered at: N/A")

    if preview['thumbprint_error']:
        print(preview['thumbprint_error'])
        return False

    from .common import acme_jose
    from .common.fingerprint_words import format_fingerprint_words
    print(f"ACME Account JWK Thumbprint (RFC 7638, base64url): {preview['thumbprint']}")
    # format_fingerprint_words() expects hex (the custom protocol's own
    # SHA-256-hex fingerprint convention) - decode the stored base64url
    # thumbprint back to raw bytes and hex-encode it just for this display;
    # the base64url form above remains the canonical one (matches client_id
    # and everywhere else this thumbprint is used).
    print(format_fingerprint_words(acme_jose.decode_b64url(preview['thumbprint']).hex()))
    print(
        "Note: confirming based on timing/context alone (e.g. \"exactly one new "
        "account just appeared, right when I expected one\") is a real, deliberate "
        "operational trust decision, not a completed cryptographic verification - "
        "see Manual.MD for how to reproduce this thumbprint from a real client's "
        "own account key if you want full cryptographic confirmation."
    )

    confirm = input(f"Do you want to confirm ACME account {client.client_id}? (yes/no): ")
    if confirm.lower() in ['yes', 'y']:
        success = apply_client_action(client.client_id, 'confirm')
        if success:
            print(f"ACME account {client.client_id} has been confirmed successfully.")
            return True
        print(f"Error: Failed to confirm ACME account {client.client_id}.")
        return False
    print("confirm cancelled.")
    return False

def confirm_and_delete_client(client_id):
    """Confirm and delete a client entry by ID"""
    init_database()

    client = get_client_by_id_or_client_id(client_id)
    if not client:
        print(f"Error: Client with ID {client_id} not found.")
        return False

    # Display client information
    print(f"Client ID: {client.client_id}")
    print(f"Registered at: {client.registration_date}")
    print(f"Status: {client.status}")

    # Get last successful connection (or display N/A)
    last_success = client.last_successful_connection if client.last_successful_connection else 'N/A'
    print(f"Last successful connection: {last_success}")
    print(f"Last IP: {client.last_connection_ip or 'N/A'}")

    # Ask for confirmation
    confirm = input(f"Are you sure you want to delete client with ID {client_id}? (yes/no): ")

    if confirm.lower() in ['yes', 'y']:
        # Delete the client - must use the resolved numeric database ID
        # (client.id), not the original client_id argument: that can be
        # either the numeric ID or the string client identifier
        # (get_client_by_id_or_client_id() accepts both), but
        # delete_client_by_id() only ever looks up by the numeric ID.
        success = delete_client_by_id(client.id)
        (logger.info if success else logger.warning)("delete client %s: %s", client.client_id,
                                                       "ok" if success else "failed")
        if success:
            print(f"Client with ID {client_id} has been deleted successfully.")
            return True
        else:
            print(f"Error: Failed to delete client with ID {client_id}.")
            return False
    else:
        print("Deletion cancelled.")
        return False

def onboard_client(client_id, fqdns_list):
    """Confirm the client if not already confirmed, then grant active
    permission for each selected fqdns group. Composes existing operations
    with no new business logic - collapses what used to be one `confirm` call
    plus one `assign` call per domain into a single call. Like the functions
    it composes, this still prints its own progress; callers that can't
    tolerate stray stdout output (e.g. a full-screen UI) should wrap the call
    themselves (see admintui/util/capture.py's silence_stdout()).

    Returns (client_ok: bool, results: dict[fqdns, bool]).
    """
    client = get_client_by_id_or_client_id(client_id)
    if not client:
        return False, {}

    client_ok = True
    if client.status != 'confirmed':
        client_ok = update_client_status(client.client_id, 'confirmed')

    results = {fqdns: assign_certificate_permissions(client.client_id, fqdns) for fqdns in fqdns_list}
    return client_ok, results

def assign_certificate_permissions(client_id, fqdns_string, valid_until=None):
    """Assign certificate permissions to a client, optionally expiring
    automatically at `valid_until` (a datetime, or None for a permission
    that never expires on its own - the previous, only-ever behavior)."""
    init_database()

    client = get_client_by_id_or_client_id(client_id)
    if not client:
        print(f"Error: Client with ID {client_id} not found.")
        return False

    if client.status != 'confirmed':
        print(f"Error: Client {client_id} must be confirmed to assign certificate permissions.")
        return False

    if fqdns_string.isdigit():
        # Treat as certificate ID directly.
        cert_id = int(fqdns_string)
        fqdns = get_certificate_fqdns_by_id(cert_id)
        if fqdns is None:
            print(f"Error: Certificate with ID {cert_id} does not exist.")
            return False
    else:
        fqdns = normalize_fqdns(fqdns_string)

    # Add permission relation (status = 1 for active) - always set to 1 regardless of certificate existence.
    # client_certificate_relations.fqdns is a foreign key into certificates.fqdns, so
    # granting permission for a not-yet-existing certificate needs a placeholder row
    # first (same mechanism crtrequest.py uses) - harmless on SQLite (never enforces
    # its own FKs) but a hard failure on MySQL/PostgreSQL, which do.
    if create_certificate_entry(fqdns) is None:
        print(f"Error assigning permission to client {client_id} for {fqdns}")
        return False

    if not add_client_certificate_relation(client.id, fqdns, status=1, valid_until=valid_until):
        print(f"Error assigning permission to client {client_id} for {fqdns}")
        return False

    expiry_note = f" (expires {valid_until})" if valid_until else ""
    if fqdns_string.isdigit():
        print(f"Permission assigned to client {client_id} for certificate ID {cert_id}{expiry_note}")
    else:
        print(f"Permission assigned to client {client_id} for certificate FQDNs: {fqdns}{expiry_note}")

    logger.info("assign client %s -> %s%s: ok", client.client_id, fqdns, expiry_note)
    print(f"Successfully assigned certificate permissions to client {client_id}")
    return True

def revoke_certificate_permissions(client_id, fqdns_string):
    """Revoke certificate permissions for a client"""
    init_database()

    client = get_client_by_id_or_client_id(client_id)
    if not client:
        print(f"Error: Client with ID {client_id} not found.")
        return False

    if fqdns_string.lower() == "all":
        if delete_all_client_certificate_relations(client.id):
            logger.info("revoke_permission client %s -> all: ok", client.client_id)
            print(f"All permissions revoked for client {client_id}")
            return True
        logger.warning("revoke_permission client %s -> all: failed", client.client_id)
        print(f"Error revoking all permissions for client {client_id}")
        return False

    if fqdns_string.isdigit():
        cert_id = int(fqdns_string)
        fqdns = get_certificate_fqdns_by_id(cert_id)
        if fqdns is None:
            print(f"Error: Certificate with ID {cert_id} does not exist.")
            return False
    else:
        fqdns = normalize_fqdns(fqdns_string)

    if delete_client_certificate_relation(client.id, fqdns):
        logger.info("revoke_permission client %s -> %s: ok", client.client_id, fqdns)
        print(f"Permission revoked from client {client_id} for certificate FQDNs: {fqdns}")
        print(f"Successfully revoked certificate permissions for client {client_id}")
        return True
    else:
        # Nothing to revoke - a warning, not a crash, but also not a success:
        # nothing was actually changed (see issue.md's "cltmanager.py always
        # exits 0" entry - this specific "Warning: ..." message used to fall
        # through to a plain `return True` regardless).
        logger.warning("revoke_permission client %s -> %s: nothing to revoke", client.client_id, fqdns)
        print(f"Warning: No permission found for client {client_id} with FQDNs: {fqdns}")
        return False

def set_permission_expiry(client_id, fqdns_string, valid_until):
    """Change the expiry date on an existing certificate permission, without
    touching its status - use `assign` to grant a new permission (optionally
    with its own --valid-until), and `revoke_permission` to remove one
    outright. Pass valid_until=None to make the permission never expire."""
    init_database()

    client = get_client_by_id_or_client_id(client_id)
    if not client:
        print(f"Error: Client with ID {client_id} not found.")
        return False

    if fqdns_string.isdigit():
        cert_id = int(fqdns_string)
        fqdns = get_certificate_fqdns_by_id(cert_id)
        if fqdns is None:
            print(f"Error: Certificate with ID {cert_id} does not exist.")
            return False
    else:
        fqdns = normalize_fqdns(fqdns_string)

    if not set_permission_valid_until(client.id, fqdns, valid_until):
        logger.warning("set_expiry client %s -> %s: no existing permission", client.client_id, fqdns)
        print(f"Error: No existing permission found for client {client_id} on {fqdns} - use 'assign' to create one first.")
        return False

    logger.info("set_expiry client %s -> %s: %s", client.client_id, fqdns,
                f"expires {valid_until}" if valid_until else "no longer expires")
    if valid_until:
        print(f"Permission for client {client_id} on {fqdns} now expires {valid_until}")
    else:
        print(f"Permission for client {client_id} on {fqdns} no longer expires automatically")
    return True

def set_client_ip_pin(client_id, allowed_ip):
    """Set or clear (allowed_ip=None/'none') a client's IP-pinning
    restriction (ACME_SERVER_DESIGN.md §7.3) - a second authentication
    factor on top of the JWS cryptography that already authenticates every
    ACME request. Only ever enforced for ACME accounts (client_kind='acme')
    - acme_server_utils.py's verify_acme_jws() is the sole place that reads
    this field; the traditional protocol never consults it - but the
    column and this command work generically over any client_id, matching
    Client.allowed_source_ip's own table-level scope. Validates as a real
    IP address or CIDR network before ever reaching the database, so a
    typo can't silently produce a value that fails closed at request time
    for a reason the admin never intended (a value stored as-is that
    doesn't parse would make every future request for this account
    rejected, indistinguishably from "not confirmed" - see §7.3's
    deliberate error-message reuse)."""
    init_database()

    client = get_client_by_id_or_client_id(client_id)
    if not client:
        print(f"Error: Client with ID {client_id} not found.")
        return False

    if allowed_ip is not None:
        try:
            ipaddress.ip_network(allowed_ip, strict=False)
        except ValueError as e:
            print(f"Error: '{allowed_ip}' is not a valid IP address or CIDR network: {e}")
            return False

    if not set_client_allowed_ip(client.id, allowed_ip):
        logger.warning("set_allowed_ip client %s: failed", client.client_id)
        print(f"Error: Could not update client {client_id}.")
        return False

    logger.info("set_allowed_ip client %s -> %s", client.client_id, allowed_ip or "(cleared)")
    if allowed_ip:
        print(f"Client {client_id} is now pinned to {allowed_ip} - ACME requests for this account "
              f"will now only be accepted from that address/network.")
    else:
        print(f"Client {client_id}'s IP pin has been cleared - ACME requests are no longer address-restricted.")
    return True

def _permission_cert_is_valid(cert):
    """True only for a real, currently-valid production certificate - the
    same definition admintui's client-overview counts use: exists, has
    actually been issued (has a public key), isn't a staging-only cert, and
    isn't expired (crtmanager.check_certificate_validity also treats an
    unissued placeholder's dummy 2020-01-01 date as expired)."""
    if not cert or not cert.public_key or cert.is_staging:
        return False
    from . import crtmanager
    return crtmanager.check_certificate_validity(cert)


def get_client_permission_rows(client_id=None):
    """Pure data form of list_client_permissions(): if client_id is given,
    returns {'client': Client, 'permissions': [row, ...]} for just that
    client (or None if the client doesn't exist); otherwise returns a list of
    that same shape for every client. Each row dict has fqdns/status/
    status_text/valid_until/cert_id/is_valid/permission_expires/
    permission_active - 'valid_until'/'is_valid' describe the *certificate's*
    own expiry (unchanged meaning), 'permission_expires'/'permission_active'
    describe ccr.permission_valid_until, now that it's actually enforced
    (see issue.md)."""
    from .common.database import get_db_session, Client, Certificate, ClientCertificateRelation, permission_is_active
    session = get_db_session()
    try:
        if client_id:
            client = get_client_by_id_or_client_id(client_id)
            if not client:
                return None

            relations = session.query(ClientCertificateRelation).filter_by(
                client_id=client.id).order_by(ClientCertificateRelation.fqdns).all()

            rows = []
            for relation in relations:
                # Determine status text - for pending requests (status=0), show as "Requested"
                if relation.status == 0:
                    status_text = "Requested"
                else:
                    status_text = "Active" if relation.status == 1 else "Inactive"
                cert = session.query(Certificate).filter_by(fqdns=relation.fqdns).first()
                rows.append({
                    'fqdns': relation.fqdns,
                    'status': relation.status,
                    'status_text': status_text,
                    'valid_until': cert.validity_end_date if cert and cert.validity_end_date else "N/A",
                    'cert_id': cert.id if cert else "N/A",
                    'is_valid': _permission_cert_is_valid(cert),
                    'permission_expires': relation.permission_valid_until if relation.permission_valid_until else "Never",
                    'permission_active': permission_is_active(relation),
                })
            return {'client': client, 'permissions': rows}
        else:
            # List all clients and their permissions (both active and pending permissions)
            clients = session.query(Client).order_by(Client.client_id).all()
            client_dict = {}
            for client in clients:
                relations = session.query(ClientCertificateRelation).filter_by(
                    client_id=client.id).order_by(ClientCertificateRelation.fqdns).all()
                permissions = []
                for relation in relations:
                    cert = session.query(Certificate).filter_by(fqdns=relation.fqdns).first()
                    permissions.append({
                        'fqdns': relation.fqdns,
                        'status': relation.status,
                        'status_text': "Requested" if relation.status == 0 else (
                            "Active" if relation.status == 1 else "Inactive"),
                        # Only a real certificate ID for active permissions (status = 1) -
                        # for pending permissions (status = 0), there's nothing to point at yet
                        'cert_id': (cert.id or 'N/A') if relation.status == 1 and cert else 'N/A',
                        'valid_until': cert.validity_end_date if cert and cert.validity_end_date else "N/A",
                        'is_valid': _permission_cert_is_valid(cert),
                        'permission_expires': relation.permission_valid_until if relation.permission_valid_until else "Never",
                        'permission_active': permission_is_active(relation),
                    })
                client_dict[client.id] = {
                    'client_id': client.client_id,
                    'status': client.status,
                    'client_version': client.client_version,
                    'permissions': permissions,
                }
            return list(client_dict.values())
    finally:
        session.close()

def list_client_permissions(client_id=None):
    """List clients and their certificate permissions. Returns False if a
    specific client_id was given but not found (see issue.md); True
    otherwise."""
    # Initialize database
    init_database()

    console = Console()

    # If a specific client_id was provided, list only that client's permissions
    if client_id:
        data = get_client_permission_rows(client_id)
        if data is None:
            print(f"Error: Client with ID {client_id} not found.")
            return False

        client = data['client']
        console.print(f"Version: {client.client_version or 'N/A'}")
        table = Table(title=f"Client Permissions: {client.client_id}", show_header=True, header_style="bold blue")
        table.add_column("FQDNs", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Cert Valid Until", style="yellow")
        table.add_column("Certificate ID", style="blue")
        table.add_column("Permission Expires", style="yellow")

        if not data['permissions']:
            console.print("[bold yellow]No permissions found for this client.[/bold yellow]")
        else:
            for perm in data['permissions']:
                status_text = perm['status_text']
                if perm['status'] == 1 and not perm['permission_active']:
                    status_text += " (expired)"
                table.add_row(perm['fqdns'], status_text, str(perm['valid_until']), str(perm['cert_id']),
                              str(perm['permission_expires']))

        console.print(table)
        return True
    else:
        client_list = get_client_permission_rows()

        # Display table
        table = Table(title="All Clients and Certificate Permissions", show_header=True, header_style="bold blue")
        table.add_column("Client ID", style="cyan")
        table.add_column("Clt Status", style="magenta")
        table.add_column("Version", style="blue")
        table.add_column("FQDNs", style="green")
        table.add_column("Crt Status", style="yellow")
        table.add_column("Certificate ID", style="blue")
        table.add_column("Permission Expires", style="yellow")

        for client_data in client_list:
            client_id_display = client_data['client_id'][:30] + "..." if len(client_data['client_id']) > 30 else client_data['client_id']
            status = client_data['status']
            version = client_data['client_version'] or "N/A"

            # Add rows for each permission
            if not client_data['permissions']:
                table.add_row(client_id_display, status, version, "No permissions", "N/A", "N/A", "N/A")
            else:
                for i, perm in enumerate(client_data['permissions']):
                    cert_id = str(perm['cert_id']) if perm['cert_id'] else "N/A"
                    status_text = perm['status_text']
                    if perm['status'] == 1 and not perm['permission_active']:
                        status_text += " (expired)"
                    expires = str(perm['permission_expires'])
                    if i == 0:
                        table.add_row(client_id_display, status, version, perm['fqdns'], status_text, cert_id, expires)
                    else:
                        table.add_row("", "", "", perm['fqdns'], status_text, cert_id, expires)

        console.print(table)
        return True

def get_pending_relations(client_id=None):
    """Pending (status=0) client-certificate relations, optionally scoped to
    one client. Returns (client_or_None, relations) - relations are
    ClientCertificateRelation ORM objects. If client_id was given but
    doesn't resolve to a real client, returns (None, [])."""
    if client_id:
        client = get_client_by_id_or_client_id(client_id)
        if not client:
            return None, []
        return client, get_pending_client_certificate_relations(client.id)
    return None, get_pending_client_certificate_relations()

def clean_requests(client_id=None):
    """Clean up entries in client_certificate_relations with status = 0"""
    init_database()

    client, pending_requests = get_pending_relations(client_id)
    if client_id and client is None:
        print(f"Error: Client with ID {client_id} not found.")
        return False

    if not pending_requests:
        if client_id:
            print(f"No pending requests found for client {client_id}")
        else:
            print("No pending requests found")
        return True

    # Display the requests that will be deleted
    console = Console()
    table = Table(title="Pending Requests to be Deleted", show_header=True, header_style="bold blue")
    table.add_column("Client ID", style="cyan")
    table.add_column("FQDNs", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Valid Until", style="yellow")
    table.add_column("Certificate ID", style="blue")

    for relation in pending_requests:
        row_client = get_client_by_id_or_client_id(relation.client_id)
        client_id_display = row_client.client_id if row_client else str(relation.client_id)

        valid_until_col = relation.permission_valid_until
        if valid_until_col is None:
            valid_until = "N/A"
        elif isinstance(valid_until_col, datetime.datetime):
            valid_until = valid_until_col.strftime('%Y-%m-%d %H:%M:%S')
        else:
            valid_until = str(valid_until_col)

        # No direct cert_id on a still-pending request - nothing issued yet
        table.add_row(client_id_display, relation.fqdns, "Requested", valid_until, "N/A")

    console.print(table)

    # Ask for confirmation
    confirm = input(f"Do you want to delete {len(pending_requests)} pending request(s)? (yes/no): ")

    if confirm.lower() in ['yes', 'y']:
        success = delete_pending_client_certificate_relations(client.id if client else None)
        if success:
            print(f"Successfully deleted {len(pending_requests)} pending request(s)")
        return success
    else:
        print("Deletion cancelled.")
        return True

def main():
    """Main function"""
    # Create the parser
    parser = argparse.ArgumentParser(description='Client management utility for key server')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('--config', default=DEFAULT_SERVER_CONFIG_FILE,
                         help=f'Server configuration file path (default: {DEFAULT_SERVER_CONFIG_FILE}) - '
                              f'only relevant to a server running with a non-default --config; used to '
                              f'relocate the database (its data_dir, if set), to compute the server\'s '
                              f'own fingerprint for the confirm command\'s identity-verification step, and '
                              f'to read registration_secret/listen_address/port for registration_command')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Parser for listall command
    listall_parser = subparsers.add_parser('listall', help='List all client entries with a short overview')
    
    # Parser for list command
    list_parser = subparsers.add_parser('list', help='List clients and their certificate permissions')
    list_parser.add_argument('client_id', nargs='?', help='Optional client ID to list only that client and their permissions')

    # Parser for registration_command command
    registration_command_parser = subparsers.add_parser(
        'registration_command',
        help="Print the client.py init/register commands to run on a new client host")
    registration_command_parser.add_argument(
        'client_id', nargs='?',
        help='Client ID to embed via --client-id - if omitted, the new client defaults to its own hostname')
    registration_command_parser.add_argument(
        '--server-host',
        help="This server's externally-reachable hostname/IP for the new client to connect to - "
             "required unless server_config.json's listen_address is already a concrete, "
             "non-wildcard address")
    registration_command_parser.add_argument(
        '--server-port', type=int,
        help="Port for the new client to connect to (default: this server's own 'port' from "
             "server_config.json)")

    # Parser for confirm command
    confirm_parser = subparsers.add_parser('confirm', help='Confirm a client entry by ID')
    confirm_parser.add_argument('client_id', help='Client ID (database ID or client identifier) to confirm')
    
    # Parser for revoke command
    revoke_parser = subparsers.add_parser('revoke', help='Revoke confirmation of a client entry by ID')
    revoke_parser.add_argument('client_id', help='Client ID (database ID or client identifier) to revoke')

    # Parser for acme_confirm command
    acme_confirm_parser = subparsers.add_parser(
        'acme_confirm', help='Confirm an ACME account by ID (RFC 7638 JWK-thumbprint based)')
    acme_confirm_parser.add_argument('client_id', help='Client ID (database ID or client identifier) to confirm')

    # Parser for acme_cancel_order command
    acme_cancel_order_parser = subparsers.add_parser(
        'acme_cancel_order', help='Cancel (invalidate) a stuck/dead ACME order and release its processing lock')
    acme_cancel_order_parser.add_argument('order_id', type=int, help='ACME order ID to cancel')

    # Parser for acme_create_eab_grant command
    acme_create_eab_grant_parser = subparsers.add_parser(
        'acme_create_eab_grant',
        help='Create an RFC 8555 External Account Binding trust grant for a trusted ACME client')
    acme_create_eab_grant_parser.add_argument('--label', required=True, help='Admin-facing name for this grant')
    acme_create_eab_grant_parser.add_argument(
        '--allowed-fqdns', required=True, dest='allowed_fqdns',
        help='Comma-separated glob pattern(s) this grant may auto-approve, e.g. "*.my.domain,*.other.domain"')
    acme_create_eab_grant_parser.add_argument(
        '--expires', default=None, help="Expiry date/time (or 'never', the default) - same format as assign's --valid-until")

    # Parser for acme_create_contact_token_grant command
    acme_create_contact_token_grant_parser = subparsers.add_parser(
        'acme_create_contact_token_grant',
        help='Create a contact-field-token trust grant for a trusted ACME client with no EAB support')
    acme_create_contact_token_grant_parser.add_argument(
        '--label', required=True, help='Admin-facing name for this grant')
    acme_create_contact_token_grant_parser.add_argument(
        '--allowed-fqdns', required=True, dest='allowed_fqdns',
        help='Comma-separated glob pattern(s) this grant may auto-approve, e.g. "*.my.domain,*.other.domain"')
    acme_create_contact_token_grant_parser.add_argument(
        '--expires', default=None, help="Expiry date/time (or 'never', the default) - same format as assign's --valid-until")
    acme_create_contact_token_grant_parser.add_argument(
        '--domain', default='sslcrtsrv.local',
        help="Domain part of the generated plus-addressed contact string (default: sslcrtsrv.local) - "
             "doesn't need to be a real mailbox, it's never used to send mail")

    # Parser for acme_list_trust_grants command
    subparsers.add_parser('acme_list_trust_grants', help='List all ACME trust grants')

    # Parser for acme_revoke_trust_grant command
    acme_revoke_trust_grant_parser = subparsers.add_parser(
        'acme_revoke_trust_grant', help='Revoke an ACME trust grant by ID')
    acme_revoke_trust_grant_parser.add_argument('grant_id', type=int, help='Trust grant ID to revoke')

    # Parser for delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a client entry by ID')
    delete_parser.add_argument('client_id', help='Database ID or client identifier of the client to delete')
    
    # Parser for assign command
    assign_parser = subparsers.add_parser('assign', help='Assign certificate permissions to a client')
    assign_parser.add_argument('client_id', help='Client ID to assign permissions to')
    assign_parser.add_argument('fqdns', help='FQDNs of certificates to assign (comma-separated) or certificate ID')
    assign_parser.add_argument('--valid-until', metavar='DATETIME',
                                help="Automatically expire this permission at this UTC date/time "
                                     "(e.g. '2026-12-31' or '2026-12-31T23:59:59'). Omit for a "
                                     "permission that never expires on its own.")

    # Parser for revoke permission command
    revoke_permission_parser = subparsers.add_parser('revoke_permission', help='Revoke and remove certificate permissions for a client')
    revoke_permission_parser.add_argument('client_id', help='Client ID to revoke permissions from')
    revoke_permission_parser.add_argument('fqdns', help='FQDNs of certificates to revoke permissions for (comma-separated)')

    # Parser for set_expiry command
    set_expiry_parser = subparsers.add_parser('set_expiry', help="Change an existing certificate permission's expiry date")
    set_expiry_parser.add_argument('client_id', help='Client ID whose permission to change')
    set_expiry_parser.add_argument('fqdns', help='FQDNs of the certificate permission to change (comma-separated) or certificate ID')
    set_expiry_parser.add_argument('valid_until', metavar='DATETIME',
                                    help="New expiry, e.g. '2026-12-31' or '2026-12-31T23:59:59' (UTC), "
                                         "or 'never' to make the permission never expire.")

    # Parser for clean_requests command
    clean_requests_parser = subparsers.add_parser('clean_requests', help='Clean up pending certificate requests')
    clean_requests_parser.add_argument('client_id', nargs='?', help='Optional client ID to clean only for that client')

    # Parser for set_allowed_ip command
    set_allowed_ip_parser = subparsers.add_parser(
        'set_allowed_ip', help='Set or clear an IP-pinning restriction on a client (ACME accounts only take effect)')
    set_allowed_ip_parser.add_argument('client_id', help='Client ID to set the restriction on')
    set_allowed_ip_parser.add_argument('allowed_ip', metavar='IP-OR-CIDR|none',
                                        help="An IP address or CIDR network (e.g. '203.0.113.5' or "
                                             "'203.0.113.0/24'), or 'none' to clear an existing restriction.")

    # Parse arguments
    args = parser.parse_args()

    # Relocate the database under server_config.json's data_dir first, if
    # one is configured (see common/database.py's relocate_under_data_dir()) -
    # every command below eventually calls init_database() itself. Honors
    # --config so this agrees with whatever server_config.json a non-default
    # --config points at, rather than always the default path (see issue.md).
    apply_data_dir_from_config(args.config)

    from .common.logging_utils import setup_tool_logging_from_file
    setup_tool_logging_from_file(args.config, "cltmanager")

    # Check which command was used - every branch below now exits 0 on
    # success and 1 on failure (mirroring the sys.exit(0 if success else 1)
    # pattern crtmanager.py already uses throughout), instead of always
    # falling off the end of main() with an implicit exit 0 regardless of
    # whether the operation actually succeeded (see issue.md).
    if args.command == 'listall':
        sys.exit(0 if list_all_clients() else 1)
    elif args.command == 'list':
        if args.client_id:
            success = list_client_permissions(args.client_id)
        else:
            success = list_client_permissions()
        sys.exit(0 if success else 1)
    elif args.command == 'registration_command':
        sys.exit(0 if generate_registration_command(
            args.client_id, args.server_host, args.server_port, config_file_path=args.config) else 1)
    elif args.command == 'confirm':
        sys.exit(0 if confirm_client(args.client_id, 'confirm', config_file_path=args.config) else 1)
    elif args.command == 'revoke':
        sys.exit(0 if confirm_client(args.client_id, 'revoke', config_file_path=args.config) else 1)
    elif args.command == 'acme_confirm':
        sys.exit(0 if confirm_acme_client(args.client_id) else 1)
    elif args.command == 'acme_cancel_order':
        success = cancel_acme_order(args.order_id)
        if success:
            print(f"ACME order {args.order_id} cancelled.")
        else:
            print(f"Error: ACME order {args.order_id} not found, or not in a cancellable state "
                  f"(already 'valid' or 'invalid').")
        sys.exit(0 if success else 1)
    elif args.command == 'acme_create_eab_grant':
        try:
            expires_at = parse_valid_until(args.expires)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
        sys.exit(0 if create_acme_eab_grant(args.label, args.allowed_fqdns, expires_at=expires_at) else 1)
    elif args.command == 'acme_create_contact_token_grant':
        try:
            expires_at = parse_valid_until(args.expires)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
        sys.exit(0 if create_acme_contact_token_grant(
            args.label, args.allowed_fqdns, expires_at=expires_at, domain=args.domain) else 1)
    elif args.command == 'acme_list_trust_grants':
        sys.exit(0 if list_acme_trust_grants() else 1)
    elif args.command == 'acme_revoke_trust_grant':
        sys.exit(0 if revoke_trust_grant(args.grant_id) else 1)
    elif args.command == 'delete':
        sys.exit(0 if confirm_and_delete_client(args.client_id) else 1)
    elif args.command == 'assign':
        try:
            valid_until = parse_valid_until(args.valid_until)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
        sys.exit(0 if assign_certificate_permissions(args.client_id, args.fqdns, valid_until) else 1)
    elif args.command == 'revoke_permission':
        sys.exit(0 if revoke_certificate_permissions(args.client_id, args.fqdns) else 1)
    elif args.command == 'set_expiry':
        try:
            valid_until = parse_valid_until(args.valid_until)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
        sys.exit(0 if set_permission_expiry(args.client_id, args.fqdns, valid_until) else 1)
    elif args.command == 'clean_requests':
        sys.exit(0 if clean_requests(args.client_id) else 1)
    elif args.command == 'set_allowed_ip':
        allowed_ip = None if args.allowed_ip.strip().lower() == 'none' else args.allowed_ip.strip()
        sys.exit(0 if set_client_ip_pin(args.client_id, allowed_ip) else 1)
    else:
        # Default behavior - list unconfirmed clients
        sys.exit(0 if list_unconfirmed_clients() else 1)

if __name__ == "__main__":
    main()
