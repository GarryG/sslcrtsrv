#!/usr/bin/env python3
"""
Certificate Request and Renewal Script
This script handles initial certificate requests and renewals using acme.sh
"""

import collections
import os
import shutil
import sys
import subprocess
import json
import datetime
import logging
import argparse
import threading
from pathlib import Path
from typing import List, Dict, Optional

from . import __version__
# Import database functions
from .common.database import (
    init_database, get_db_session, get_certificate, create_certificate_entry, configure_database
)
from .common import database
from .common import acme_jose
from .common.constants import (
    BASE_CONFIG_DIR, ACME_PROVIDERS, MANUAL_ACME_PROVIDER, DEFAULT_ACME_PROVIDER,
    ACME_BASE_RETRY_SECONDS, ACME_MAX_RETRY_SECONDS, ACME_DEFAULT_MAX_ISSUANCE_ATTEMPTS,
    ACME_DEFAULT_UNCONFIRMED_ACCOUNT_RETENTION_DAYS, ACME_DEFAULT_NONCE_TTL_SECONDS,
)

# Logging is configured in main() via common/logging_utils.py's
# setup_tool_logging(), once server_config.json is loaded - not here at
# import time. This module's own logger starts unconfigured (no handlers)
# and picks up console/file/syslog handlers via propagation to the shared
# "sslcrtsrv" ancestor logger the moment setup_tool_logging() runs. This
# replaced a self-contained logging.basicConfig() that wrote a fixed,
# relative 'crtrequest.log' - resolved against whatever the process's
# current working directory happened to be, scattering log files across
# cron/admintui-subprocess/manual-shell invocations with no rotation at
# all (see the 2026-09-20 issue.md entry this was written to close).
#
# Explicit name, not logging.getLogger(__name__): this module can be run
# directly via `python3 -m sslcrtsrv.crtrequest`, under which __name__
# becomes "__main__" rather than "sslcrtsrv.crtrequest" - a logger named
# "__main__" would not be a descendant of "sslcrtsrv" and would never reach
# the handlers setup_tool_logging() configures there (see server.py's
# identical note for its own logger - discovered here the hard way, by
# testing this exact invocation and finding every logger.info()/.warning()
# call silently going nowhere despite setup_tool_logging() itself working
# correctly).
logger = logging.getLogger("sslcrtsrv.crtrequest")


class _ErrorCollectingHandler(logging.Handler):
    """Attached to `logger` only for the duration of a run started with
    --notify, so a summary of everything that went wrong can be included in
    one admin notification without threading notify_error(...) through the
    dozens of individual logger.error() call sites in this file - every one
    of them already goes through `logger`, so capturing at the handler level
    gets all of them for free."""

    def __init__(self):
        super().__init__(level=logging.ERROR)
        self.records: List[str] = []

    def emit(self, record):
        self.records.append(record.getMessage())


def resolve_acme_server(acme_provider: str, staging: bool) -> str:
    """Map a Certificate.acme_provider value to the acme.sh --server value to use.

    Raises ValueError if staging is requested for a provider with no known
    staging/test server (including unrecognized providers, which are passed
    through as raw acme.sh --server values, e.g. a custom ACME directory URL).
    """
    entry = ACME_PROVIDERS.get(acme_provider)
    if entry:
        if staging:
            if not entry['staging']:
                raise ValueError(f"ACME provider '{acme_provider}' has no known staging server")
            return entry['staging']
        return entry['live']
    if staging:
        raise ValueError(f"Cannot request a staging certificate for unrecognized ACME provider '{acme_provider}'")
    return acme_provider

def resolve_acme_sh_path(crtrequest_config: dict) -> str:
    """Return the acme.sh command/path to invoke, from ACME_SH_PATH in
    crtrequest_config.json. Defaults to the bare command 'acme.sh' (looked up
    on PATH) if unset, preserving prior behavior.

    Raises FileNotFoundError if ACME_SH_PATH is set to something that looks
    like a path (contains a '/') but isn't an executable file - a bare
    command name is left to PATH lookup at exec time instead, since checking
    it here would require duplicating PATH resolution.
    """
    acme_sh_path = crtrequest_config.get('ACME_SH_PATH') or 'acme.sh'
    acme_sh_path = os.path.expanduser(os.path.expandvars(acme_sh_path))
    if '/' in acme_sh_path and not os.access(acme_sh_path, os.X_OK):
        raise FileNotFoundError(
            f"ACME_SH_PATH is set to '{acme_sh_path}' in crtrequest_config.json, but that "
            f"file doesn't exist or isn't executable"
        )
    return acme_sh_path

def certificate_directory_path(cert_home_dir: str, cert_id: int) -> str:
    """Path of a certificate's own, isolated acme.sh --home directory (see
    request_new_certificate()/renew_certificate()'s --home flag) - nothing
    else ever reads or writes it, so once the certificate's DB row is gone
    it's unconditionally orphaned (see crtmanager.delete_certificate_and_directory).
    """
    return os.path.join(cert_home_dir, f"cert-{cert_id}")

def create_certificate_directory(cert_home_dir: str, cert_id: int) -> str:
    """Create certificate directory structure"""
    cert_dir = certificate_directory_path(cert_home_dir, cert_id)
    Path(cert_dir).mkdir(parents=True, exist_ok=True)
    return cert_dir

def get_domains_from_fqdns(fqdns: str) -> List[str]:
    """Split fqdns string into individual domain entries"""
    domains = fqdns.split(',')
    # Escape domains that start with "*" to prevent shell interpretation issues
    escaped_domains = []
    for domain in domains:
        domain = domain.strip()
        escaped_domains.append(domain)
    return escaped_domains

# acme.sh's own RENEW_SKIP exit code (see its `RENEW_SKIP=2` and every `return
# $RENEW_SKIP` in acme.sh's source) - it means "nothing to do", not a failure:
# the certificate in this --home directory is already valid and its domain
# list hasn't changed, so acme.sh deliberately declined to touch anything.
ACME_RENEW_SKIP_CODE = 2

# Wall-clock cap on one acme.sh invocation (ACME_SERVER_DESIGN.md §6.1) -
# opt-in via execute_acme_command()'s timeout_seconds parameter, used only
# by the ACME CSR-relay path for now. That path runs on a much tighter cron
# cadence than the traditional one (every 5-15 minutes, vs. once daily), so
# a single hung acme.sh invocation is far more consequential: it can delay
# every other pending ACME order's much tighter latency expectations, not
# just push a daily renewal to the next day.
ACME_SH_TIMEOUT_SECONDS = 600

def execute_acme_command(command: List[str], env_vars: Dict[str, str] = None,
                          timeout_seconds: Optional[float] = None, capture_tail_lines: int = 0):
    """Execute acme.sh command with proper environment.

    Returns True on success, False on a genuine failure, or None if acme.sh
    exited with its RENEW_SKIP code (2) - meaning it already has a valid,
    unchanged certificate for this --home directory and intentionally did
    nothing, which callers should treat as "read the existing files", not
    an error.

    timeout_seconds: if given, a watchdog thread kills the process (and this
    returns False) if it hasn't exited within this many seconds. Armed
    before the output-reading loop starts, not just around the final wait(),
    so it also catches a process that's gone silently unresponsive rather
    than only one still producing output right up until it hangs. None (the
    default) preserves this function's original, unbounded-wait behavior for
    existing callers - the traditional --issue path is unaffected unless it
    explicitly opts in.

    capture_tail_lines: if > 0, also collects the last N lines of acme.sh's
    own combined stdout/stderr and returns (status, tail_text) instead of a
    bare status - used by the ACME CSR-relay path to surface a real failure
    reason into an AcmeOrder's own last_issuance_error field, rather than
    nothing (0, the default, preserves the original bare-status return).
    """
    tail = collections.deque(maxlen=capture_tail_lines) if capture_tail_lines else None

    def _result(status, message=None):
        if tail is None:
            return status
        return status, (message if message is not None else '\n'.join(tail))

    try:
        # Set environment variables if provided
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        logger.info(f"Executing command: {' '.join(command)}")
        if env_vars:
            # Log which extra env vars are set and whether each has a non-empty
            # value, without ever logging the values themselves (some, like
            # PDNS_Token, are secrets) - useful for diagnosing "DNS hook can't
            # find its credentials" failures without a debug/log build of acme.sh
            env_summary = ', '.join(f"{k}={'set' if v else 'EMPTY'}" for k, v in env_vars.items())
            logger.info(f"Extra environment passed to acme.sh: {env_summary}")

        # Stream acme.sh's combined stdout/stderr line-by-line as it runs,
        # logging each line as it arrives, rather than buffering the whole
        # run (subprocess.run(capture_output=True)) and logging it as one
        # blob only once acme.sh exits. This is what lets a caller tailing
        # this process's own stdout - e.g. admintui's "Issue now" progress
        # window - show real-time progress instead of a long silence
        # followed by a wall of text.
        process = subprocess.Popen(
            command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

        timed_out = threading.Event()
        watchdog = None
        if timeout_seconds is not None:
            def _kill_on_timeout():
                timed_out.set()
                logger.error(f"Command exceeded {timeout_seconds}s timeout, killing it: {' '.join(command)}")
                process.kill()
            watchdog = threading.Timer(timeout_seconds, _kill_on_timeout)
            watchdog.daemon = True
            watchdog.start()

        try:
            for line in process.stdout:
                logger.info(f"[acme.sh] {line.rstrip()}")
                if tail is not None:
                    tail.append(line.rstrip())
            returncode = process.wait()
        finally:
            if watchdog is not None:
                watchdog.cancel()

        if timed_out.is_set():
            return _result(False, f"acme.sh exceeded its {timeout_seconds}s timeout and was killed")
        if returncode == 0:
            return _result(True)
        if returncode == ACME_RENEW_SKIP_CODE:
            # acme.sh's own diagnostic messages (e.g. "Domains not changed.
            # Skipping.") were already logged line-by-line above via _info(),
            # interleaved with its --debug trace via _debug() - both go
            # through the same merged stdout/stderr stream now.
            logger.info("acme.sh reported nothing to do (already valid/unchanged, RENEW_SKIP)")
            return _result(None)
        logger.error(f"Command failed with return code {returncode}")
        return _result(False)
    except Exception as e:
        logger.error(f"Unexpected error executing command: {e}")
        return _result(False, str(e))

def read_certificate_files(cert_dir: str) -> Dict[str, str]:
    """Read certificate files and return their contents"""
    try:
        # Read certificate file
        cert_file_path = os.path.join(cert_dir, 'ssl.cer')
        if os.path.exists(cert_file_path):
            with open(cert_file_path, 'r') as f:
                cert_content = f.read()
        else:
            cert_content = ""
            
        # Read private key file
        key_file_path = os.path.join(cert_dir, 'ssl.key')
        if os.path.exists(key_file_path):
            with open(key_file_path, 'r') as f:
                key_content = f.read()
        else:
            key_content = ""
            
        # Read intermediate certificate file
        intermediate_file_path = os.path.join(cert_dir, 'intermed.cer')
        if os.path.exists(intermediate_file_path):
            with open(intermediate_file_path, 'r') as f:
                intermediate_content = f.read()
        else:
            intermediate_content = ""
            
        return {
            'cert': cert_content,
            'key': key_content,
            'intermediate': intermediate_content
        }
    except Exception as e:
        logger.error(f"Error reading certificate files: {e}")
        return {
            'cert': "",
            'key': "",
            'intermediate': ""
        }


def request_new_certificate(client_id: int, fqdns: str, cert_id: int, acme_provider: str = DEFAULT_ACME_PROVIDER,
                             staging: bool = False, force_reissue: bool = False, debug: bool = False) -> Optional[bool]:
    """Request a new certificate using acme.sh.

    Returns True/False/None - see execute_acme_command()'s return value,
    which this passes straight through.

    acme_provider/staging select which acme.sh --server to use (see
    resolve_acme_server()). force_reissue adds --force, guaranteeing acme.sh
    actually runs the DNS-01 challenge (add/remove TXT record) instead of
    possibly skipping a domain it doesn't consider due for renewal yet. This
    is what lets a freshly rotated DNS provider token get pushed into
    acme.sh's saved per-certificate state on demand - see
    force_refresh_dns_token().
    """
    try:
        try:
            acme_server = resolve_acme_server(acme_provider, staging)
        except ValueError as e:
            logger.error(str(e))
            return False

        # Load configuration
        config = load_server_config()
        cert_home_dir = config.get('cert_home_dir')
        if not cert_home_dir:
            logger.error("cert_home_dir not found in server config")
            return False

        # Create certificate directory
        cert_dir = create_certificate_directory(cert_home_dir, cert_id)

        # Load DNS provider / ACME challenge configuration
        crtrequest_config = load_crtrequest_config()
        dns_provider_config = crtrequest_config.get('DNS_PROVIDER_CONFIG')
        challenge_alias = crtrequest_config.get('CHALLENGE_ALIAS')
        if not dns_provider_config or not challenge_alias:
            logger.error("DNS_PROVIDER_CONFIG/CHALLENGE_ALIAS not found in certificate request config")
            return False

        missing_fields = [
            field for field in ('PDNS_Url', 'PDNS_ServerId', 'PDNS_Token')
            if not dns_provider_config.get(field)
        ]
        if missing_fields:
            logger.error(
                f"DNS_PROVIDER_CONFIG is missing/empty for: {', '.join(missing_fields)} - "
                f"check crtrequest_config.json"
            )
            return False

        try:
            acme_sh_path = resolve_acme_sh_path(crtrequest_config)
        except FileNotFoundError as e:
            logger.error(str(e))
            return False

        # Prepare domains for acme.sh command
        domains = get_domains_from_fqdns(fqdns)
        domain_args = []
        for domain in domains:
            # Remove quotes around domains to prevent acme.sh from treating them as IDN
            domain_args.extend(['-d', domain.strip()])

        # Set environment variables for DNS provider
        env_vars = {
            'PDNS_Url': dns_provider_config['PDNS_Url'],
            'PDNS_ServerId': dns_provider_config['PDNS_ServerId'],
            'PDNS_Token': dns_provider_config['PDNS_Token']
        }

        # Build acme.sh command for new certificate request
        cmd = [
            acme_sh_path,
            '--issue',
            '--dns', 'dns_pdns'
        ] + domain_args + [
            '--challenge-alias', challenge_alias,
            '--cert-file', f'{cert_dir}/ssl.cer',
            '--key-file', f'{cert_dir}/ssl.key',
            '--ca-file', f'{cert_dir}/intermed.cer',
            '--home', cert_dir,
            '--server', acme_server,
        ]
        if force_reissue:
            cmd.append('--force')
        if debug:
            cmd.append('--debug')

        # Execute the command
        return execute_acme_command(cmd, env_vars)

    except Exception as e:
        logger.error(f"Error requesting new certificate: {e}")
        return False

def request_new_certificate_from_csr(order_id: int, fqdns: str, cert_id: int, csr_pem: str,
                                      acme_provider: str = DEFAULT_ACME_PROVIDER, staging: bool = False,
                                      force_reissue: bool = False, debug: bool = False):
    """CSR-relay counterpart to request_new_certificate() (ACME_SERVER_DESIGN.md
    §6.1): relays an ACME client's own CSR to the real upstream CA via
    `acme.sh --signcsr`, deliberately with **no `--key-file`** - `--signcsr`
    mode never generates or handles a private key, and this server never
    sees or stores the downstream ACME client's key.

    Returns (success, error_message): error_message is None on success, and
    on failure carries acme.sh's own captured output tail (via
    execute_acme_command()'s capture_tail_lines), which the caller passes
    into record_acme_order_failure()'s last_issuance_error field - the same
    information the traditional path already logs, just also surfaced to
    whoever's looking at the order's own DB row.
    """
    try:
        try:
            acme_server = resolve_acme_server(acme_provider, staging)
        except ValueError as e:
            logger.error(str(e))
            return False, str(e)

        config = load_server_config()
        cert_home_dir = config.get('cert_home_dir')
        if not cert_home_dir:
            message = "cert_home_dir not found in server config"
            logger.error(message)
            return False, message

        cert_dir = create_certificate_directory(cert_home_dir, cert_id)

        crtrequest_config = load_crtrequest_config()
        dns_provider_config = crtrequest_config.get('DNS_PROVIDER_CONFIG')
        challenge_alias = crtrequest_config.get('CHALLENGE_ALIAS')
        if not dns_provider_config or not challenge_alias:
            message = "DNS_PROVIDER_CONFIG/CHALLENGE_ALIAS not found in certificate request config"
            logger.error(message)
            return False, message

        missing_fields = [
            field for field in ('PDNS_Url', 'PDNS_ServerId', 'PDNS_Token')
            if not dns_provider_config.get(field)
        ]
        if missing_fields:
            message = (f"DNS_PROVIDER_CONFIG is missing/empty for: {', '.join(missing_fields)} - "
                       f"check crtrequest_config.json")
            logger.error(message)
            return False, message

        try:
            acme_sh_path = resolve_acme_sh_path(crtrequest_config)
        except FileNotFoundError as e:
            logger.error(str(e))
            return False, str(e)

        domains = get_domains_from_fqdns(fqdns)
        domain_args = []
        for domain in domains:
            domain_args.extend(['-d', domain.strip()])

        env_vars = {
            'PDNS_Url': dns_provider_config['PDNS_Url'],
            'PDNS_ServerId': dns_provider_config['PDNS_ServerId'],
            'PDNS_Token': dns_provider_config['PDNS_Token']
        }

        csr_path = os.path.join(cert_dir, 'request.csr')
        with open(csr_path, 'w') as f:
            f.write(csr_pem)

        # Deliberately no --key-file - --signcsr never generates/handles a key.
        cmd = [
            acme_sh_path,
            '--signcsr',
            '--csr', csr_path,
            '--dns', 'dns_pdns',
        ] + domain_args + [
            '--challenge-alias', challenge_alias,
            '--cert-file', f'{cert_dir}/ssl.cer',
            '--ca-file', f'{cert_dir}/intermed.cer',
            '--home', cert_dir,
            '--server', acme_server,
        ]
        if force_reissue:
            cmd.append('--force')
        if debug:
            cmd.append('--debug')

        return execute_acme_command(cmd, env_vars, timeout_seconds=ACME_SH_TIMEOUT_SECONDS, capture_tail_lines=20)

    except Exception as e:
        message = f"Error requesting new certificate from CSR for ACME order {order_id}: {e}"
        logger.error(message)
        return False, message

def renew_certificate(cert_id: int, cert_home_dir: str) -> bool:
    """Renew an existing certificate using acme.sh"""
    try:
        # Create certificate directory path
        cert_dir = create_certificate_directory(cert_home_dir, cert_id)
        
        # Build acme.sh command for renewal
        cmd = [
            'acme.sh',
            '--home', cert_dir,
            '--refresh',
            '--install-cert'
        ]
        
        # Execute the command
        return execute_acme_command(cmd)
        
    except Exception as e:
        logger.error(f"Error renewing certificate: {e}")
        return False

def _acme_challenge_dns_name(domain: str) -> str:
    """The DNS name that must carry a CNAME delegating this domain's ACME
    DNS-01 challenge to CHALLENGE_ALIAS - see README's "Requesting
    certificates via crtrequest.py and acme.sh" section for the full setup.

    A wildcard domain (*.example.com) uses a literal wildcard record,
    *._acme-challenge.example.com, NOT the RFC 8555 "strip the leading *."
    name (_acme-challenge.example.com) a non-delegated DNS-01 setup would
    use for it - the two would otherwise be indistinguishable from the
    bare/apex domain's own entry, which needs its own, separate CNAME.
    """
    if domain.startswith("*."):
        return f"*._acme-challenge.{domain[2:]}"
    return f"_acme-challenge.{domain}"

def _resolve_cname(name: str) -> Optional[str]:
    """The first CNAME hop for `name`, or None if it has no CNAME record at
    all (NXDOMAIN, a different record type, or the lookup simply timed
    out) - all of those mean "not delegated" as far as check_dns_delegation()
    is concerned.

    Shells out to `dig` rather than adding a DNS-library dependency for this
    one lookup - dig (Debian/Ubuntu package dnsutils/bind9-dnsutils) is a
    standard tool already expected on a host set up to manage DNS
    delegation like this, matching how this script already shells out to
    acme.sh itself rather than reimplementing it.

    Raises RuntimeError if `dig` isn't installed at all - that's a DNS-check
    configuration problem, not a "no CNAME configured" result, so it must
    not be silently swallowed the same way.
    """
    try:
        result = subprocess.run(
            ['dig', '+short', '+time=5', '+tries=1', 'CNAME', name],
            capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        raise RuntimeError(
            "'dig' command not found - install the dnsutils (Debian/Ubuntu: bind9-dnsutils) "
            "package to perform the DNS delegation check (runs by default; pass --no-check-dns "
            "to skip it, or use --check-dns-only)")
    except subprocess.TimeoutExpired:
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    # +short prints one name per line for a CNAME chain - only the first
    # line (this name's own immediate target) matters here: whether
    # delegation exists at all, not where it ultimately leads.
    return result.stdout.strip().splitlines()[0].rstrip(".")

def check_dns_delegation(fqdns: str) -> bool:
    """Verify every domain in `fqdns` (comma-separated) has the CNAME entry
    acme.sh's --challenge-alias needs to complete DNS-01 validation - see
    _acme_challenge_dns_name()/README for the exact naming scheme.

    Logs one line per domain either way (info on success, warning/error on
    failure) so a DNS check run is self-explanatory from its log output
    alone. Returns True only if every domain's expected CNAME is present
    and points at CHALLENGE_ALIAS; callers use a False return to skip
    calling acme.sh for this certificate entirely rather than let a
    half-configured domain fail there instead.
    """
    crtrequest_config = load_crtrequest_config()
    challenge_alias = crtrequest_config.get('CHALLENGE_ALIAS')
    if not challenge_alias:
        logger.error("CHALLENGE_ALIAS not found in certificate request config - cannot verify DNS delegation")
        return False
    expected_target = f"_acme-challenge.{challenge_alias}".rstrip(".")

    all_ok = True
    for domain in get_domains_from_fqdns(fqdns):
        challenge_name = _acme_challenge_dns_name(domain)
        try:
            target = _resolve_cname(challenge_name)
        except RuntimeError as e:
            logger.error(str(e))
            return False

        if target is None:
            logger.warning(f"DNS check failed for {domain}: no CNAME record found at {challenge_name} - "
                           f"add one pointing to {expected_target} before requesting this certificate.")
            all_ok = False
        elif target != expected_target:
            logger.warning(f"DNS check failed for {domain}: {challenge_name} is a CNAME, but points to "
                           f"'{target}' instead of the expected '{expected_target}' - DNS-01 validation "
                           f"would fail.")
            all_ok = False
        else:
            logger.info(f"DNS check OK for {domain}: {challenge_name} -> {target}")
    return all_ok

def check_dns_for_certificates(cert_name=None) -> bool:
    """Pure DNS diagnostic pass for --check-dns-only: verify check_dns_delegation()
    for --cert-name (or every FQDNs set this server currently tracks, if
    omitted) and report the results. Never touches the database and never
    calls acme.sh, regardless of what it finds - unlike the DNS check that
    now gates the normal issue/renew flow by default (--no-check-dns turns
    that one off), this is meant to be run on its own, e.g. to confirm DNS
    is ready before approving a brand new request or relying on the next
    scheduled renewal.

    Returns True only if every checked certificate's DNS delegation is fully
    in place; per-domain detail is already logged by check_dns_delegation().
    """
    if shutil.which('dig') is None:
        logger.error("'dig' command not found - install the dnsutils (Debian/Ubuntu: bind9-dnsutils) "
                      "package to use --check-dns-only")
        return False

    if cert_name:
        fqdns_list = [cert_name]
    else:
        from sqlalchemy import text
        init_database()
        session = get_db_session()
        try:
            rows = session.execute(
                text('SELECT DISTINCT fqdns FROM client_certificate_relations ORDER BY fqdns')).fetchall()
        finally:
            session.close()
        fqdns_list = [row[0] for row in rows]

    if not fqdns_list:
        logger.warning("No certificates found to check" + (f" for '{cert_name}'" if cert_name else "") + ".")
        return False

    all_ok = True
    for fqdns in fqdns_list:
        logger.info(f"Checking DNS delegation for {fqdns}...")
        if not check_dns_delegation(fqdns):
            all_ok = False

    if all_ok:
        logger.info(f"DNS check passed for all {len(fqdns_list)} certificate(s).")
    else:
        logger.warning("DNS check failed for one or more certificates - see warnings above.")
    return all_ok

def _attempt_issue_or_renew(fqdns, client_id, cert_home_dir, acme_provider, staging, force, debug=False,
                            check_dns=True) -> bool:
    """Create/reuse a certificate's DB row and attempt to (re)issue it via acme.sh,
    updating the DB on success or cleaning up a never-succeeded placeholder on failure.

    Returns True if the certificate ends up in a good state, False on a
    genuine failure - callers use this to decide whether the overall run
    succeeded, since a caught/logged failure here must never be silently
    reported as success by the process's exit code.

    acme.sh's own exit code isn't trusted in isolation for this: it exiting
    0 doesn't strictly guarantee a certificate file actually exists (an
    unusual acme.sh version/behavior, a path mismatch, etc.) -
    update_database_with_certificate() verifies a real certificate file is
    present in cert_dir before this counts as success.

    check_dns=True (the default - pass False, or --no-check-dns on the CLI,
    to skip it) verifies the DNS delegation check_dns_delegation() requires
    is in place *before* touching the database or calling acme.sh at all -
    a certificate missing it is skipped (logged, returns False) without
    creating even a placeholder DB row, so it costs nothing to retry once
    the missing DNS entry is added.
    """
    if check_dns and not check_dns_delegation(fqdns):
        logger.warning(f"Skipping {fqdns}: required DNS delegation is not (fully) in place - "
                        f"see the warning(s) above. Not calling acme.sh for this certificate.")
        return False

    logger.info(f"Creating/reusing certificate entry for {fqdns}")
    cert_id = create_certificate_entry(fqdns, acme_provider=acme_provider)
    if cert_id is None:
        logger.error(f"Failed to create certificate entry for {fqdns}")
        return False

    def _cleanup_placeholder():
        # Clean up if this was a fresh placeholder that never got any real data.
        # Uses delete_certificate_placeholder(), NOT delete_certificate() - the
        # latter also deletes client_certificate_relations rows for this fqdns,
        # which is correct when an admin explicitly deletes a real certificate,
        # but wrong here: a certificate that failed to issue must stay visible
        # as a pending request (admintui's Requests tab), not vanish along with
        # the client's actual request/permission just because this attempt
        # failed.
        existing = get_certificate(fqdns)
        if existing and not existing.public_key:
            from .common.database import delete_certificate_placeholder
            if delete_certificate_placeholder(fqdns):
                logger.info(f"Successfully deleted failed certificate entry for {fqdns}")
                # This placeholder's acme.sh --home directory (created just
                # above by create_certificate_directory) is now orphaned too -
                # nothing else uses cert-<cert_id>, so it would otherwise sit
                # there forever holding whatever partial acme.sh state a
                # failed issuance attempt left behind. cert_home_dir may be
                # unconfigured (checked below, same as the success path further
                # down) - nothing to clean up on disk in that case.
                if cert_home_dir:
                    cert_dir = certificate_directory_path(cert_home_dir, cert_id)
                    if os.path.isdir(cert_dir):
                        try:
                            shutil.rmtree(cert_dir)
                            logger.info(f"Removed acme.sh directory {cert_dir} for failed placeholder")
                        except OSError as e:
                            logger.warning(f"Could not remove acme.sh directory {cert_dir}: {e}")
            else:
                logger.warning(f"Failed to delete failed certificate entry for {fqdns}")

    # A request for a production certificate must always actually happen,
    # even if acme.sh's own saved state for this --home directory still has
    # an unexpired certificate on disk - which, if that certificate is our
    # currently-stored staging one, is exactly the case here. Without this,
    # acme.sh's RENEW_SKIP ("nothing changed, not due yet") silently keeps
    # the old staging certificate in place, and it looks - incorrectly -
    # like a production certificate was issued (see the is_staging
    # correction in update_database_with_certificate() below for the other
    # half of this fix).
    existing_cert = get_certificate(fqdns)
    switching_from_staging = not staging and existing_cert is not None and existing_cert.is_staging
    force_reissue = force or switching_from_staging
    if switching_from_staging and not force:
        logger.info(f"{fqdns} currently has a staging certificate - forcing acme.sh to actually "
                    f"reissue for this production request instead of possibly skipping it")

    logger.info(f"Requesting certificate for {fqdns} (provider={acme_provider}, staging={staging})")
    success = request_new_certificate(client_id, fqdns, cert_id, acme_provider=acme_provider, staging=staging,
                                       force_reissue=force_reissue, debug=debug)
    if success is False:
        logger.error(f"Failed to request certificate for {fqdns}")
        _cleanup_placeholder()
        return False

    if success is None:
        # acme.sh's RENEW_SKIP: it already has a valid, unchanged certificate on
        # disk for this --home directory and declined to touch anything - not a
        # failure. This happens when our DB placeholder lost track of a
        # certificate acme.sh actually issued successfully in an earlier run
        # (e.g. update_database_with_certificate() failed that time) - read the
        # files already on disk and sync them in now, instead of deleting the
        # placeholder and retrying forever.
        logger.info(f"acme.sh already has a valid certificate on disk for {fqdns} - syncing it into the database")
    else:
        logger.info(f"Successfully requested certificate for {fqdns}")

    if not cert_home_dir:
        logger.warning(f"cert_home_dir not configured in server config - cannot verify a certificate "
                        f"file actually exists for {fqdns}")
        return True

    cert_dir = create_certificate_directory(cert_home_dir, cert_id)
    if update_database_with_certificate(cert_dir, fqdns, is_staging=staging, force=force):
        return True

    logger.error(f"acme.sh reported success for {fqdns}, but no certificate file was found in "
                 f"{cert_dir} - treating this as a failure")
    _cleanup_placeholder()
    return False

def process_certificates(cert_name=None, staging=False, force=False, debug=False, check_dns=True) -> bool:
    """Main function to process certificates needing attention.

    Returns True if every certificate handled ended up in a good state
    (issued/renewed/already valid), False if any genuinely failed - main()
    uses this to set the script's exit code, so a real acme.sh failure is
    never silently reported as success just because process_certificates()
    itself didn't raise.
    """
    try:
        # Initialize database
        init_database()

        config = load_server_config()
        cert_home_dir = config.get('cert_home_dir')
        default_provider = config.get('default_acme_provider', DEFAULT_ACME_PROVIDER)

        if cert_name:
            # A specific certificate was requested (e.g. admintui's "Issue
            # now") - act on it directly rather than requiring it to already
            # have an approved (status=1) client relation. Requiring that
            # made this silently do nothing (0 rows matched, no error) for
            # any certificate an admin explicitly picked that didn't happen
            # to have one yet - which reported as "succeeded" even though no
            # certificate was ever requested. Also skip the "still valid, no
            # renewal needed" check below: an explicit "issue now" should
            # always actually attempt it, not silently no-op.
            existing_cert = get_certificate(cert_name)
            if existing_cert and existing_cert.acme_provider == MANUAL_ACME_PROVIDER:
                logger.info(f"Skipping {cert_name}: managed manually (acme_provider={MANUAL_ACME_PROVIDER})")
                return True
            if database.is_acme_managed(cert_name):
                # No longer a reason to skip issuance outright - the
                # traditional protocol and a live ACME order can now manage
                # the same fqdns independently (see
                # update_database_with_certificate_from_csr()'s matching
                # guard, which keeps this issuance from disturbing the ACME
                # order's own certificate). Logged for visibility only.
                logger.info(f"{cert_name} also has a live ACME order (ACME_SERVER_DESIGN.md §6.4) - "
                            f"proceeding with its own, independent traditional-protocol issuance")
            acme_provider = (existing_cert.acme_provider if existing_cert else None) or default_provider
            ok = _attempt_issue_or_renew(cert_name, None, cert_home_dir, acme_provider, staging, force, debug=debug,
                                          check_dns=check_dns)
            logger.info("Certificate processing completed")
            return ok

        # Batch mode (e.g. cron): every certificate a client currently has
        # approved access to.
        session = get_db_session()
        from sqlalchemy import text
        query = text('''
            SELECT ccr.client_id, ccr.fqdns, ccr.status, ccr.permission_valid_until
            FROM client_certificate_relations ccr
            WHERE ccr.status = 1
            ORDER BY ccr.fqdns
        ''')
        relations = session.execute(query).fetchall()
        session.close()

        # Convert results to a format that matches the old code
        # SQLAlchemy returns Row objects, we need to convert to dict-like structure
        formatted_relations = []
        for row in relations:
            formatted_relations.append({
                'client_id': row.client_id,
                'fqdns': row.fqdns,
                'status': row.status,
                'permission_valid_until': row.permission_valid_until
            })
        relations = formatted_relations

        logger.info(f"Found {len(relations)} active certificate relations to process")

        all_ok = True

        # Process each relation
        for relation in relations:
            client_id = relation['client_id']
            fqdns = relation['fqdns']

            logger.info(f"Processing certificate for client {client_id}, FQDNs: {fqdns}")

            # Check if certificate exists in certificates table
            existing_cert = get_certificate(fqdns)

            if existing_cert and existing_cert.acme_provider == MANUAL_ACME_PROVIDER:
                logger.info(f"Skipping {fqdns}: managed manually (acme_provider={MANUAL_ACME_PROVIDER})")
                continue

            if database.is_acme_managed(fqdns):
                # See the matching comment at the single-certificate path
                # above - this is now informational only, not a skip.
                logger.info(f"{fqdns} also has a live ACME order (ACME_SERVER_DESIGN.md §6.4) - "
                            f"proceeding with its own, independent traditional-protocol issuance")

            if not existing_cert:
                # Brand new domain - never seen before
                if not _attempt_issue_or_renew(fqdns, client_id, cert_home_dir, default_provider, staging, force,
                                                debug=debug, check_dns=check_dns):
                    all_ok = False
                continue

            acme_provider = existing_cert.acme_provider or default_provider
            has_certificate_data = bool(existing_cert.public_key)

            if not has_certificate_data:
                # Certificate row exists but has no actual certificate data (a
                # placeholder from a previous failed attempt) - treat as a new request
                logger.info(f"Certificate for {fqdns} has no actual certificate data, requesting it")
                if not _attempt_issue_or_renew(fqdns, client_id, cert_home_dir, acme_provider, staging, force,
                                                debug=debug, check_dns=check_dns):
                    all_ok = False
                continue

            # Certificate exists and has data - check if it's still valid
            try:
                validity_end = existing_cert.validity_end_date
                if validity_end and validity_end.tzinfo is None:
                    import pytz
                    validity_end = validity_end.replace(tzinfo=pytz.UTC)
            except Exception as e:
                logger.error(f"Error accessing validity_end_date for {fqdns}: {e}")
                all_ok = False
                continue

            if not validity_end:
                logger.info(f"Could not determine certificate validity for {fqdns}, proceeding with renewal")
                if not _attempt_issue_or_renew(fqdns, client_id, cert_home_dir, acme_provider, staging, force,
                                                debug=debug, check_dns=check_dns):
                    all_ok = False
                continue

            import pytz
            now = datetime.datetime.now(pytz.UTC)
            days_remaining = (validity_end - now).days
            if validity_end < now or days_remaining < 14:
                logger.info(f"Certificate for {fqdns} needs renewal. Days remaining: {days_remaining if days_remaining >= 0 else 'expired'}")
                if not _attempt_issue_or_renew(fqdns, client_id, cert_home_dir, acme_provider, staging, force,
                                                debug=debug, check_dns=check_dns):
                    all_ok = False
            else:
                logger.info(f"Certificate for {fqdns} is still valid until {validity_end}. No renewal needed.")

        # ACME (RFC 8555) support: a separate pass over AcmeOrder rows,
        # alongside (not instead of) the traditional ClientCertificateRelation
        # loop above - see ACME_SERVER_DESIGN.md §6.3. Batch-mode only (not
        # the single-cert_name path above, which addresses a Certificate by
        # fqdns, not an AcmeOrder by id) - guarded by acme_enabled so a
        # non-ACME deployment pays no extra queries per cron pass.
        if config.get('acme_enabled'):
            run_acme_cleanup_pass(config)

            max_attempts = config.get('acme_max_issuance_attempts', ACME_DEFAULT_MAX_ISSUANCE_ATTEMPTS)
            pending_acme_orders = database.get_pending_acme_orders_for_issuance()
            logger.info(f"Found {len(pending_acme_orders)} ACME order(s) ready for issuance")

            # Diagnostic only: orders stuck in 'pending' (the client has
            # never successfully called finalize) are invisible to the
            # query above - it only ever looks at 'processing' orders. Log
            # them here so "a certificate isn't renewing and I don't know
            # why" is answerable from this log alone - see the matching
            # per-request logging in acme_server_utils.py's handle_order()/
            # handle_authz()/handle_challenge()/handle_finalize() for what
            # the client has actually been doing (or not doing) with it.
            stuck_orders = database.get_stuck_pending_acme_orders()
            if stuck_orders:
                logger.warning(
                    f"{len(stuck_orders)} ACME order(s) still 'pending' (client has never called "
                    f"finalize) for more than 5 minutes - these will NOT be picked up for issuance "
                    f"until the client finalizes them:")
                for order, age_seconds, permission_active in stuck_orders:
                    reason = ("fqdns permission is active - the CLIENT has not called finalize "
                              "(check whether it even understands this server's authorization flow)"
                              if permission_active else
                              "fqdns permission is NOT YET approved - run cltmanager.py "
                              "assign_certificate_permissions, or this will never progress")
                    logger.warning(
                        f"  order {order.id}: client_id={order.account_client_id} fqdns={order.fqdns!r} "
                        f"age={int(age_seconds)}s - {reason}")
            for order in pending_acme_orders:
                cert = get_or_create_placeholder_certificate(order.fqdns)
                if cert is None:
                    logger.error(f"Could not create/reuse certificate placeholder for ACME order "
                                 f"{order.id} ({order.fqdns})")
                    continue

                result = request_new_certificate_from_csr(
                    order.id, order.fqdns, cert.id, order.csr_pem,
                    acme_provider=cert.acme_provider or default_provider, staging=staging,
                    force_reissue=True, debug=debug)
                success, error_message = result

                if success:
                    cert_dir = create_certificate_directory(cert_home_dir, cert.id)
                    if not update_database_with_certificate_from_csr(
                            cert_dir, order.fqdns, order.id, order.csr_key_fingerprint, is_staging=staging):
                        all_ok = False
                elif success is False:
                    logger.error(f"Failed to issue certificate for ACME order {order.id} ({order.fqdns}): "
                                 f"{error_message}")
                    database.record_acme_order_failure(order.id, error_message, max_attempts,
                                                        ACME_BASE_RETRY_SECONDS, ACME_MAX_RETRY_SECONDS)
                    all_ok = False
                else:
                    # acme.sh's own RENEW_SKIP is not expected here - a
                    # freshly-finalized CSR is never "already up to date"
                    # from acme.sh's perspective. Treat it as a failure.
                    message = "unexpected acme.sh RENEW_SKIP for a freshly-finalized CSR"
                    logger.error(f"ACME order {order.id} ({order.fqdns}): {message}")
                    database.record_acme_order_failure(order.id, message, max_attempts,
                                                        ACME_BASE_RETRY_SECONDS, ACME_MAX_RETRY_SECONDS)
                    all_ok = False

        logger.info("Certificate processing completed")
        return all_ok

    except Exception as e:
        logger.error(f"Error in process_certificates: {e}")
        raise

def force_refresh_dns_token(cert_name=None, debug=False) -> bool:
    """Force acme.sh to re-run its DNS-01 challenge for an already-issued
    certificate (or all of them, if cert_name is omitted), independent of
    whether it's actually due for renewal.

    This exists so a freshly rotated DNS provider token (PDNS_Token) gets
    pushed into that certificate's acme.sh state right away: acme.sh's DNS
    hooks re-save whatever token is currently in the environment every time
    they actually run, but they only run during a real challenge cycle. On
    the normal schedule that only happens close to expiry, so a rotated
    token would otherwise sit unused - and unsaved - in every other
    certificate's acme.sh directory until its own natural renewal, possibly
    weeks or months later.

    Note this consumes a real certificate issuance against the CA for every
    domain touched (that's what --force guarantees will happen), so this is
    meant to be run deliberately after a token rotation, not on a schedule.

    Returns True if every touched certificate was successfully refreshed,
    False if anything failed or nothing matched - main() uses this to set
    the script's exit code.
    """
    init_database()

    session = get_db_session()
    from sqlalchemy import text
    try:
        if cert_name:
            query = text("SELECT fqdns, acme_provider, is_staging FROM certificates WHERE fqdns = :fqdns")
            result = session.execute(query, {'fqdns': cert_name})
        else:
            query = text("SELECT fqdns, acme_provider, is_staging FROM certificates WHERE acme_provider != :manual")
            result = session.execute(query, {'manual': MANUAL_ACME_PROVIDER})
        certs = [(row.fqdns, row.acme_provider, bool(row.is_staging)) for row in result.fetchall()]
    finally:
        session.close()

    if cert_name:
        skipped_manual = [c for c in certs if c[1] == MANUAL_ACME_PROVIDER]
        certs = [c for c in certs if c[1] != MANUAL_ACME_PROVIDER]
        for fqdns, _, _ in skipped_manual:
            logger.info(f"Skipping {fqdns}: managed manually (acme_provider={MANUAL_ACME_PROVIDER})")

    if not certs:
        logger.warning(f"No matching certificate(s) found to refresh"
                        + (f" for {cert_name}" if cert_name else ""))
        return False

    config = load_server_config()
    cert_home_dir = config.get('cert_home_dir')
    if not cert_home_dir:
        logger.error("cert_home_dir not found in server config")
        return False

    logger.info(f"Forcing DNS token refresh for {len(certs)} certificate(s)")

    all_ok = True
    for fqdns, acme_provider, is_staging in certs:
        # create_certificate_entry() returns the existing row's ID without
        # modifying it when the fqdns is already present, which it is here
        cert_id = create_certificate_entry(fqdns)
        if cert_id is None:
            logger.error(f"Could not resolve certificate ID for {fqdns}, skipping")
            all_ok = False
            continue

        logger.info(f"Forcing DNS token refresh for {fqdns}")
        success = request_new_certificate(None, fqdns, cert_id, acme_provider=acme_provider,
                                           staging=is_staging, force_reissue=True, debug=debug)
        if success:
            cert_dir = create_certificate_directory(cert_home_dir, cert_id)
            if update_database_with_certificate(cert_dir, fqdns, is_staging=is_staging, force=True):
                logger.info(f"Successfully refreshed DNS token / reissued certificate for {fqdns}")
            else:
                logger.error(f"acme.sh reported success for {fqdns}, but no certificate file was found - "
                             f"treating as a failure")
                all_ok = False
        else:
            logger.error(f"Failed to force DNS token refresh for {fqdns}")
            all_ok = False

    return all_ok

def update_database_with_certificate(cert_dir: str, fqdns: str, is_staging: bool = False, force: bool = False) -> bool:
    """Update the database with certificate data after acme.sh execution.

    Returns True only if an actual certificate file was found in cert_dir
    and its data was saved to the database. acme.sh exiting 0 doesn't by
    itself guarantee a certificate file was actually written, so checking
    for the file on disk is the real confirmation that something was
    genuinely issued - not just that the acme.sh process claimed success.

    A staging certificate never overwrites a valid, non-expired production
    certificate already in the DB, unless force=True. A production
    certificate always overwrites an existing staging one - no guard needed
    for that direction.

    The is_staging value actually recorded is verified against the
    certificate's own issuer field where possible (see
    certificate_looks_like_staging()), rather than blindly trusting the
    is_staging argument - acme.sh can leave an old certificate's files
    untouched (RENEW_SKIP) even when a different staging/production request
    was made for that domain, which would otherwise silently mislabel a
    still-staging certificate as production (or vice versa).
    """
    try:
        # Convert validity_end_date string to datetime object for proper database storage
        # (imported early since the staging/production overwrite guard below needs it too)
        from datetime import datetime
        import pytz

        # Read certificate files
        cert_files = read_certificate_files(cert_dir)

        # Confirm a real certificate file actually exists before writing anything
        # to the database - without this check, an acme.sh run that exits 0 but
        # somehow didn't produce a certificate (wrong path, unusual version
        # behavior, etc.) would silently overwrite the DB row with empty data
        # while still logging "success".
        cert_content = cert_files['cert']
        if not cert_content:
            logger.error(
                f"No certificate file found in {cert_dir} for {fqdns} - acme.sh did not actually "
                f"produce one, even though it reported success"
            )
            return False

        detected_staging = certificate_looks_like_staging(cert_content)
        if detected_staging is not None and detected_staging != is_staging:
            logger.warning(
                f"Certificate content for {fqdns} looks like a "
                f"{'staging' if detected_staging else 'production'} certificate, but this update was "
                f"requested as {'staging' if is_staging else 'production'} - recording it as "
                f"{'staging' if detected_staging else 'production'} to match what's actually stored "
                f"(likely acme.sh declined to issue a new certificate for this request)"
            )
            is_staging = detected_staging

        if is_staging and not force:
            existing_cert = get_certificate(fqdns)
            if existing_cert and not existing_cert.is_staging and existing_cert.public_key:
                existing_end = existing_cert.validity_end_date
                if existing_end and existing_end.replace(tzinfo=None) > datetime.now(pytz.UTC).replace(tzinfo=None):
                    logger.warning(
                        f"Refusing to overwrite valid production certificate for {fqdns} with a "
                        f"staging certificate (use --force to override)"
                    )
                    return False

        validity_end_date = extract_validity_end_date(cert_content)

        if validity_end_date is None:
            # A real certificate was received (cert_content is non-empty, checked
            # above) but its validity end date couldn't be determined - treat this
            # the same as "no certificate file found" rather than silently
            # recording a fake placeholder date (see extract_validity_end_date()'s
            # docstring/fixed-issues.md: this previously left a genuinely-issued
            # certificate stuck showing a hardcoded 2020-01-01 "Valid to" forever).
            logger.error(f"Could not determine validity end date for {fqdns} - not saving this certificate data")
            return False

        # Import database functions for update
        from .common.database import update_certificate
        from .common.db_crypto import encrypt_for_storage

        # Parse the datetime string to create a proper datetime object
        # Remove timezone for parsing
        if '+' in validity_end_date:
            date_part = validity_end_date.split('+')[0]
        else:
            date_part = validity_end_date
        validity_end_date = datetime.strptime(date_part, '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.UTC)

        # Encrypt the private key before it ever touches the database. Any failure here
        # (e.g. missing DB encryption public key) propagates to the except block below,
        # so a plaintext key is never stored.
        encrypted_private_key = encrypt_for_storage(cert_files['key'])

        # Update the certificate in database
        success = update_certificate(
            fqdns=fqdns,
            public_key=cert_files['cert'],
            private_key=encrypted_private_key,
            intermediates=cert_files['intermediate'],
            validity_end_date=validity_end_date,
            is_staging=is_staging
        )

        if success:
            logger.info(f"Successfully updated database with certificate data for {fqdns}")
        else:
            logger.error(f"Failed to update database with certificate data for {fqdns}")
        return success

    except Exception as e:
        logger.error(f"Error updating database with certificate data: {e}")
        return False

def update_database_with_certificate_from_csr(cert_dir: str, fqdns: str, order_id: int,
                                               csr_key_fingerprint: str, is_staging: bool = False) -> bool:
    """CSR-relay counterpart to update_database_with_certificate()
    (ACME_SERVER_DESIGN.md §6.2). Never calls encrypt_for_storage()/never
    sets Certificate.private_key - a CSR-relay certificate legitimately has
    no private key on this server, the downstream ACME client's own key
    never left its own machine.

    Persists success via the atomic conditional database.mark_acme_order_valid()
    FIRST, and only proceeds with the AcmeCertificate insert/Certificate
    update/lock release if that returns True - a blind, unconditional write
    here would be a real race (see §4.3.1): between this order being
    selected for issuance and acme.sh actually finishing, the order could
    have already expired and been cleaned up (its lock released and
    re-acquired by a different, newer order for the same fqdns), in which
    case this freshly-issued certificate must be discarded, not attached to
    a dead order or used to overwrite a different, currently-live order's
    Certificate row.
    """
    try:
        cert_files = read_certificate_files(cert_dir)
        cert_content = cert_files['cert']
        if not cert_content:
            logger.error(
                f"No certificate file found in {cert_dir} for ACME order {order_id} ({fqdns}) - "
                f"acme.sh did not actually produce one, even though it reported success"
            )
            return False

        validity_end_date = extract_validity_end_date(cert_content)
        if validity_end_date is None:
            logger.error(
                f"Could not determine validity end date for ACME order {order_id} ({fqdns}) - "
                f"not saving this certificate data"
            )
            return False

        from datetime import datetime
        import pytz
        if '+' in validity_end_date:
            date_part = validity_end_date.split('+')[0]
        else:
            date_part = validity_end_date
        validity_end_date_dt = datetime.strptime(date_part, '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.UTC)

        key_fingerprint = acme_jose.certificate_public_key_fingerprint(cert_content)

        if not database.mark_acme_order_valid(order_id):
            logger.warning(
                f"ACME order {order_id} ({fqdns}) was no longer 'processing' by the time its certificate "
                f"arrived - discarding this issuance rather than attaching it to a dead order or "
                f"overwriting a different, currently-live order's certificate"
            )
            return False

        # An fqdns can now be managed independently by both the traditional
        # protocol and ACME at once (see ACME_SERVER_DESIGN.md's "coexistence"
        # note) - this ACME order's own delivery never depends on the shared
        # `certificates` row (handle_certificate_download() serves from this
        # order's own immutable AcmeCertificate row, inserted below
        # regardless). If that shared row's private_key is already populated,
        # it means the traditional protocol (or a manual crtmanager import)
        # actively depends on exactly what's there now for its own clients -
        # skip overwriting it, rather than silently clobbering someone else's
        # certificate/key with this ACME order's key-less result.
        existing_cert = database.get_certificate(fqdns)
        if existing_cert and existing_cert.private_key:
            logger.info(
                f"ACME order {order_id} ({fqdns}): leaving the shared certificate row untouched - "
                f"it's actively managed by the traditional protocol (or a manual import); this ACME "
                f"order's own certificate is unaffected and still served from its own record")
        else:
            from .common.database import update_certificate
            update_certificate(
                fqdns=fqdns,
                public_key=cert_content,
                private_key=None,
                intermediates=cert_files['intermediate'],
                validity_end_date=validity_end_date_dt,
                is_staging=is_staging,
                key_fingerprint=key_fingerprint,
            )
        database.insert_acme_certificate(
            order_id, cert_content, cert_files['intermediate'], key_fingerprint, validity_end_date_dt)
        database.release_acme_processing_lock(fqdns, order_id)

        logger.info(f"Successfully updated database with ACME-issued certificate for order {order_id} ({fqdns})")
        return True

    except Exception as e:
        logger.error(f"Error updating database with ACME certificate data for order {order_id}: {e}")
        return False

def get_or_create_placeholder_certificate(fqdns: str):
    """Wraps create_certificate_entry() (already IntegrityError-safe against
    two orders racing to create the same brand-new fqdns, see
    common/database.py) to return the full Certificate row rather than just
    its id - the ACME issuance pass needs .acme_provider too."""
    cert_id = create_certificate_entry(fqdns)
    if cert_id is None:
        return None
    return get_certificate(fqdns)

def run_acme_cleanup_pass(config: dict) -> None:
    """Periodic ACME cleanup (ACME_SERVER_DESIGN.md §8.5), piggybacked on
    crtrequest.py's existing cron invocation rather than needing a separate
    scheduled job: expire stale orders/locks, delete never-confirmed
    abandoned ACME accounts, and prune old nonces. Called once per
    process_certificates() batch run, guarded by acme_enabled so a
    non-ACME deployment pays nothing extra."""
    expired = database.expire_stale_acme_orders_and_locks()
    if expired:
        logger.info(f"ACME cleanup: expired {expired} stale order(s)")

    retention_days = config.get('acme_unconfirmed_account_retention_days',
                                 ACME_DEFAULT_UNCONFIRMED_ACCOUNT_RETENTION_DAYS)
    deleted = database.delete_unconfirmed_stale_acme_accounts(retention_days)
    if deleted:
        logger.info(f"ACME cleanup: deleted {deleted} stale unconfirmed ACME account(s)")

    nonce_ttl = config.get('acme_nonce_ttl_seconds', ACME_DEFAULT_NONCE_TTL_SECONDS)
    database.prune_expired_acme_nonces(nonce_ttl)

def extract_validity_end_date(cert_content: str) -> Optional[str]:
    """Extract validity end date from certificate content, or None if it
    couldn't be determined (openssl missing/failed, or its output wasn't in
    the expected format) - callers must treat None as a hard failure, not
    silently record a made-up date (see issue.md/fixed-issues.md: a
    genuinely-issued certificate was previously stuck showing a hardcoded
    placeholder "Valid to" date forever whenever this failed)."""
    try:
        import subprocess
        # Extract certificate validity end date using openssl
        cmd = ['openssl', 'x509', '-in', '/dev/stdin', '-noout', '-enddate']
        result = subprocess.run(cmd, input=cert_content, text=True, capture_output=True, check=True)
        # Parse the output - format is "notAfter=Jun 26 15:50:22 2026 GMT"
        end_date_line = result.stdout.strip()
        if end_date_line.startswith('notAfter='):
            end_date_str = end_date_line[9:].strip()  # Remove "notAfter=" prefix
            # Convert to standard format with timezone
            # We need to convert to UTC timezone format
            from datetime import datetime
            # Parse the date string
            parsed_date = datetime.strptime(end_date_str, '%b %d %H:%M:%S %Y %Z')
            # Convert to UTC timezone-aware datetime
            import pytz
            utc_tz = pytz.UTC
            parsed_date = parsed_date.replace(tzinfo=utc_tz)
            # Format to match what's expected in database (YYYY-MM-DD HH:MM:SS+0000)
            formatted_date = parsed_date.strftime('%Y-%m-%d %H:%M:%S%z')
            return formatted_date
        logger.error(f"Could not extract validity end date: unexpected openssl output: {end_date_line!r}")
        return None
    except Exception as e:
        logger.error(f"Error extracting validity end date: {e}")
        return None

# Substrings known to appear in the issuer field of a CA's staging/test
# certificates but never its production ones - e.g. Let's Encrypt's staging
# issuer is literally "(STAGING) Let's Encrypt" / "(STAGING) Artificial
# Apricot R3", vs. production's plain "Let's Encrypt" / "R3". Extend this if
# other providers in ACME_PROVIDERS turn out to need their own marker.
_STAGING_ISSUER_MARKERS = ('staging', 'fake', 'pebble')

def certificate_looks_like_staging(cert_content: str) -> Optional[bool]:
    """Best-effort check of whether a PEM certificate was actually issued by
    a known CA's staging/test environment, by inspecting its issuer field.

    This exists so the database's is_staging flag reflects what a
    certificate actually is, not just what was requested: acme.sh can leave
    an old certificate's files untouched (RENEW_SKIP) even when a different
    staging/production request was made for that domain, which would
    otherwise silently mislabel a still-staging certificate as production
    (or vice versa) just because that's what the caller asked for.

    Returns True if the issuer matches a known staging marker, False if the
    issuer was successfully read and matches no known marker (i.e. assumed
    production - real CAs don't hide their identity, unlike staging/test
    environments which conventionally announce themselves precisely so they
    can't be mistaken for a trusted production cert), or None only if the
    certificate's issuer couldn't be read at all - callers should fall back
    to trusting the requested staging flag in that case.
    """
    if not cert_content:
        return None
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-in', '/dev/stdin', '-noout', '-issuer'],
            input=cert_content, text=True, capture_output=True, check=True)
        issuer = result.stdout.strip().lower()
    except Exception as e:
        logger.warning(f"Could not inspect certificate issuer to verify staging status: {e}")
        return None

    if any(marker in issuer for marker in _STAGING_ISSUER_MARKERS):
        return True
    return False

def load_server_config(config_file_path=None):
    """Load server configuration from JSON file"""
    try:
        # If config_file_path is provided, use it, otherwise default to the old behavior
        if config_file_path:
            config_file = config_file_path
        else:
            config_file = '/etc/sslcrtsrv/server_config.json'
        with open(config_file, 'r') as f:
            import json
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading server configuration: {e}")
        return {}

def load_crtrequest_config(config_file_path=None):
    """Load DNS provider / ACME challenge configuration from JSON file"""
    config_file = config_file_path or os.path.join(BASE_CONFIG_DIR, 'crtrequest_config.json')
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(
            f"Error loading certificate request configuration from {config_file}: {e}. "
            f"Copy src/crtrequest_config.json.dist to {config_file} and fill in your DNS provider values."
        )
        return {}

def parse_arguments():
    """Parse command line arguments"""
    # allow_abbrev=False: argparse's default prefix-matching would otherwise
    # let the old, now-removed --check-dns flag silently resolve to
    # --check-dns-only (the only remaining option starting with that
    # prefix) - a pure diagnostic that never calls acme.sh at all. Anyone
    # with --check-dns baked into an existing script/cron job would
    # otherwise have every renewal silently stop happening, with no error.
    parser = argparse.ArgumentParser(description='Certificate Request and Renewal Script', allow_abbrev=False)
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('--config', default='/etc/sslcrtsrv/server_config.json',
                       help='Configuration file path (default: /etc/sslcrtsrv/server_config.json)')
    parser.add_argument('--cert-name', help='Specific certificate name to process')
    parser.add_argument('--force-dns-refresh', action='store_true',
                       help='Force acme.sh to re-run its DNS-01 challenge for --cert-name '
                            '(or every issued certificate, if --cert-name is omitted), so a '
                            'freshly rotated DNS provider token gets pushed into acme.sh\'s '
                            'saved state immediately instead of waiting for each certificate\'s '
                            'own next renewal. Consumes a real certificate issuance per domain touched.')
    parser.add_argument('--staging', action='store_true',
                       help="Request certificate(s) from the ACME provider's staging/test server "
                            "instead of its live one. A staging certificate never overwrites a "
                            "valid production certificate already stored, unless --force is given.")
    parser.add_argument('--force', action='store_true',
                       help='Allow a --staging certificate to overwrite an existing valid production '
                            'certificate. Not needed the other way around - a production certificate '
                            'always replaces a staging one.')
    parser.add_argument('--debug-acme', action='store_true',
                       help="Add acme.sh's own --debug flag to every acme.sh invocation, for "
                            "troubleshooting issuance/DNS-hook failures.")
    parser.add_argument('--no-check-dns', action='store_true',
                       help="Skip the DNS delegation check that runs by default before calling acme.sh "
                            "for a certificate. Normally, before calling acme.sh, each of a certificate's "
                            "domains is checked for the CNAME entry(ies) delegating its ACME DNS-01 "
                            "challenge to CHALLENGE_ALIAS (see README's 'Requesting certificates via "
                            "crtrequest.py and acme.sh' section); a certificate missing one is skipped "
                            "with a warning instead of calling acme.sh, and the script moves on to the "
                            "next certificate. This flag disables that check entirely (e.g. if 'dig' "
                            "isn't installed, or the extra DNS lookups per certificate aren't wanted).")
    parser.add_argument('--check-dns-only', action='store_true',
                       help="Only check DNS delegation (the same check that gates acme.sh calls by "
                            "default - see --no-check-dns) for --cert-name, or every certificate this "
                            "server currently tracks if --cert-name is omitted, and report the results. "
                            "Never calls acme.sh and never touches the database, regardless of what it "
                            "finds - unlike the default behavior, this doesn't also attempt issuance/"
                            "renewal. Useful to confirm DNS is ready before approving a new request or "
                            "relying on the next scheduled renewal run. Requires 'dig' (dnsutils/bind9-dnsutils).")
    parser.add_argument('--notify', action='store_true',
                       help="Also send an admin notification (see common/notify_utils.py, "
                            "Manual.MD Section 10) if this run finishes with one or more "
                            "failures - routed via server_config.json's 'error' event, same "
                            "as the server process's own operational-error notifications. Off "
                            "by default: a normal interactive/admintui-triggered run already "
                            "shows errors directly (console output or the live progress modal) "
                            "- this is meant for unattended runs (e.g. cron) where nobody's "
                            "watching the console.")
    return parser.parse_args()

def main():
    """Main entry point"""
    args = parse_arguments()

    # Loaded here (not just inside the try block below) so logging can be
    # set up from it before anything else runs - a failure still logs via
    # logger.error() inside load_server_config() itself and returns {}
    # rather than raising, in which case setup_tool_logging() just falls
    # back to every default (console + DEFAULT_LOG_DIR, no syslog); that
    # one error message itself is the sole edge case without a configured
    # handler to go through yet (Python's own built-in last-resort stderr
    # handler still surfaces it either way).
    # Note: We pass the config_file_path to load_server_config directly
    config = load_server_config(args.config)

    from .common.logging_utils import setup_tool_logging
    setup_tool_logging(config, "crtrequest")

    # Attached only for --notify runs, so a summary of everything that went
    # wrong can be sent in one admin notification at the end - see
    # _ErrorCollectingHandler's docstring. A normal interactive/admintui run
    # (--notify not given) behaves exactly as before: console/log output
    # only, no notification attempted at all.
    error_handler = _ErrorCollectingHandler() if args.notify else None
    if error_handler:
        logger.addHandler(error_handler)

    success = False
    unhandled_error = None
    try:
        # Apply data_dir/database backend config first (see
        # common/database.py's configure_database()) - every init_database()
        # call for the rest of this process picks this up, even the ones
        # below that reload server_config.json themselves. Without this,
        # this script silently operated against the default sqlite database
        # regardless of a configured mysql/postgresql backend - see
        # fixed-issues.md.
        configure_database(config)

        logger.info("Starting certificate request/renewal script")
        if args.check_dns_only:
            success = check_dns_for_certificates(args.cert_name)
        elif args.force_dns_refresh:
            success = force_refresh_dns_token(args.cert_name, debug=args.debug_acme)
        else:
            success = process_certificates(args.cert_name, staging=args.staging, force=args.force,
                                            debug=args.debug_acme, check_dns=not args.no_check_dns)

        if success:
            logger.info("Script completed successfully")
        else:
            # process_certificates()/force_refresh_dns_token() log the specific
            # failure themselves - this just makes sure that failure actually
            # surfaces as a nonzero exit code instead of being silently
            # reported as success just because no exception was raised.
            logger.error("Script completed with one or more failures")
    except Exception as e:
        unhandled_error = str(e)
        logger.error(f"Script failed with error: {e}")
        success = False
    finally:
        if error_handler:
            logger.removeHandler(error_handler)

    if args.notify and not success:
        from .common.notify_utils import notify_error
        body_lines = ["crtrequest.py finished with one or more failures.", ""]
        if unhandled_error:
            body_lines.append(f"Unhandled error: {unhandled_error}")
            body_lines.append("")
        error_lines = error_handler.records if error_handler else []
        if error_lines:
            body_lines.append("Errors logged during this run:")
            body_lines.extend(f"  - {line}" for line in error_lines)
        notify_error(config, "crtrequest_failures",
                     "[sslcrtsrv] Certificate request/renewal run failed",
                     "\n".join(body_lines) + "\n")

    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()