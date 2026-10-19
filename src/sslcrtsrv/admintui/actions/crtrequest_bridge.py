import asyncio
import sys


async def _stream_crtrequest_command(extra_args: list, on_line=None):
    """Shell out to crtrequest.py rather than importing its functions
    in-process: crtrequest.py attaches its own stdout log handler and makes
    real ACME/DNS network calls, either of which would corrupt the Textual
    display or block the UI if run in-process. Runs asynchronously so the
    app stays responsive while it does its thing.

    crtrequest.py streams its own output line-by-line as it runs (rather
    than buffering the whole run), so as long as on_line is given, callers
    get genuinely live progress - not just a wall of text once the whole
    run finishes.

    on_line, if given, is called with each line of combined stdout/stderr as
    it arrives. Returns (success: bool, full_output: str).

    Deliberately never passes --notify: an admin watching this live progress
    modal already sees every error as it happens, so also firing an admin
    notification would be redundant. --notify exists for crtrequest.py runs
    nobody is watching (cron) - see Manual.MD Section 10.
    """
    # Invoked via `-m` (not a raw file path) so crtrequest.py's own relative
    # imports (`from .common...`) resolve correctly - running it as a bare
    # script would have no package context and fail with "attempted
    # relative import with no known parent package".
    cmd = [sys.executable, "-m", "sslcrtsrv.crtrequest"] + extra_args

    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)

    lines = []
    while True:
        raw_line = await proc.stdout.readline()
        if not raw_line:
            break
        line = raw_line.decode("utf-8", errors="replace").rstrip("\n")
        lines.append(line)
        if on_line:
            on_line(line)

    returncode = await proc.wait()
    return returncode == 0, "\n".join(lines)


async def stream_crtrequest(cert_name: str, staging: bool = False, force: bool = False,
                             debug: bool = False, skip_dns_check: bool = False, on_line=None):
    """Request/renew one certificate via `crtrequest.py --cert-name`, live-
    streaming acme.sh's own output as it runs. See _stream_crtrequest_command().

    crtrequest.py checks DNS delegation by default now (skip_dns_check=False
    matches that default) - pass skip_dns_check=True for the equivalent of
    its --no-check-dns flag.
    """
    cmd = ["--cert-name", cert_name]
    if staging:
        cmd.append("--staging")
    if force:
        cmd.append("--force")
    if debug:
        cmd.append("--debug-acme")
    if skip_dns_check:
        cmd.append("--no-check-dns")
    return await _stream_crtrequest_command(cmd, on_line=on_line)


async def stream_check_dns(cert_name: str = None, on_line=None):
    """Check DNS delegation via `crtrequest.py --check-dns-only`, for one
    certificate (cert_name given) or every certificate this server currently
    tracks (cert_name omitted) - never calls acme.sh or touches the
    database, regardless of what it finds. See _stream_crtrequest_command()."""
    cmd = ["--check-dns-only"]
    if cert_name:
        cmd += ["--cert-name", cert_name]
    return await _stream_crtrequest_command(cmd, on_line=on_line)
