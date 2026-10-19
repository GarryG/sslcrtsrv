# Unified logging setup for every sslcrtsrv tool - the server process
# (server.py/server_utils.py), scs-acme-server, crtrequest.py, and the
# admin CLI/TUI tools (cltmanager.py/crtmanager.py/dbmigrate.py/admintui)
# all call setup_tool_logging() once at startup with their own tool name.
# Previously this only covered the server process (as setup_server_logging(),
# kept below as a thin backward-compatible alias) - see the 2026-09-20
# issue.md entry this generalization was written to close: every other tool
# either wrote its own ad hoc, inconsistent logging (crtrequest.py's
# relative, unrotated crtrequest.log) or had no persistent log at all.

import logging
import logging.handlers
import os
import socket
import sys

from .constants import DEFAULT_LOG_DIR, DEFAULT_LOG_MAX_BYTES, DEFAULT_LOG_BACKUP_COUNT, SHARED_DIR_MODE
from .system_utils import ensure_secure_dir

DEFAULT_SYSLOG_PORT = 514
DEFAULT_SYSLOG_FACILITY = "daemon"
LOCAL_SYSLOG_ADDRESS = "/dev/log"

# Common ancestor of every tool's own logging.getLogger(__name__) loggers
# (e.g. "sslcrtsrv.server", "sslcrtsrv.common.server_utils",
# "sslcrtsrv.acme_server", "sslcrtsrv.crtrequest", ...) - configuring
# handlers here once, rather than on each of those directly, is what lets
# every module just use the ordinary logging.getLogger(__name__) idiom and
# still end up going through the same console/file/syslog handlers via
# normal logger propagation.
PACKAGE_LOGGER_NAME = "sslcrtsrv"


def setup_tool_logging(config: dict, tool_name: str, console: bool = True) -> logging.Logger:
    """Configures and returns the calling tool's shared logger, sending
    output to up to three destinations: console (always), a local rotating
    log file (unless explicitly disabled), and syslog (only if configured).

    `tool_name` (e.g. "server", "acme_server", "crtrequest", "cltmanager")
    identifies the caller in the log file's name and the syslog message
    prefix, so multiple tools sharing one destination (a single log file
    directory, or one syslog stream) stay distinguishable - it does not
    affect the console/file line format, which stays a plain
    "<timestamp> - <level> - <message>" for every tool alike.

    `console=False` skips the stdout handler entirely - for admintui only,
    whose Textual UI owns the terminal; a stray write to stdout from a log
    record would corrupt the screen exactly like a stray print() already
    would (see util/capture.py's silence_stdout(), which exists for that
    same reason). Every other tool wants console output as its primary
    channel and should leave this at the default.

    File logging: a RotatingFileHandler under server_config.json's
    "log_dir" (default DEFAULT_LOG_DIR, common/constants.py - alongside
    DATA_DIR rather than /var/log, reusing that directory's existing
    group-shared ownership setup instead of needing a new one), one file
    per tool_name, capped at "log_max_bytes" (default 10 MiB) with
    "log_backup_count" (default 5) rotated-out backups kept. Set "log_dir"
    to "" or false to disable file logging entirely without touching
    console/syslog. A directory that can't be created/written (e.g.
    permission trouble) degrades to a warning and console/syslog-only
    logging, exactly like an unreachable syslog target already does below -
    never crashes the tool over a logging problem.

    Syslog: uses a remote syslog server if "syslog_host" is set
    ("syslog_port"/"syslog_facility" apply either way, defaulting to
    514/"daemon"); otherwise connects to the local syslog daemon via the
    standard /dev/log Unix domain socket. If neither is reachable (no local
    syslog daemon running, e.g. a minimal container - or a genuinely
    unreachable/misconfigured remote host), logging falls back to
    console/file-only rather than crashing the tool over a logging problem -
    the same "warn and continue" pattern the config-file watcher's own
    inotify setup already uses (config_watcher.py).

    Idempotent within one process: a second call (e.g. a test harness
    constructing more than one Server()) is a no-op, returning the same
    already-configured logger rather than duplicating handlers - actual
    config changes only ever take effect via a fresh process (the
    config-file watcher's full process re-exec for the two servers, or
    simply the next invocation for a short-lived CLI tool).
    """
    logger = logging.getLogger(PACKAGE_LOGGER_NAME)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False  # don't also hand records to the root logger

    line_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    if console:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(line_formatter)
        logger.addHandler(stream_handler)

    log_dir = config.get("log_dir", DEFAULT_LOG_DIR)
    if log_dir:
        try:
            ensure_secure_dir(log_dir, mode=SHARED_DIR_MODE)
            log_path = os.path.join(log_dir, f"{tool_name}.log")
            max_bytes = config.get("log_max_bytes") or DEFAULT_LOG_MAX_BYTES
            backup_count = config.get("log_backup_count")
            if backup_count is None:
                backup_count = DEFAULT_LOG_BACKUP_COUNT
            file_handler = logging.handlers.RotatingFileHandler(
                log_path, maxBytes=max_bytes, backupCount=backup_count)
            file_handler.setFormatter(line_formatter)
            logger.addHandler(file_handler)
        except OSError as e:
            logger.warning(f"Could not open log file under {log_dir}: {e} - "
                            f"continuing without file logging.")

    facility_name = (config.get("syslog_facility") or DEFAULT_SYSLOG_FACILITY).lower()
    facility = logging.handlers.SysLogHandler.facility_names.get(facility_name)
    if facility is None:
        logger.warning(f"Unknown syslog_facility '{facility_name}' - falling back to "
                        f"'{DEFAULT_SYSLOG_FACILITY}'.")
        facility = logging.handlers.SysLogHandler.facility_names[DEFAULT_SYSLOG_FACILITY]

    syslog_host = config.get("syslog_host")
    if syslog_host:
        syslog_port = config.get("syslog_port") or DEFAULT_SYSLOG_PORT
        address = (syslog_host, syslog_port)
        address_description = f"{syslog_host}:{syslog_port}"
        probe_family = socket.AF_INET
    else:
        address = LOCAL_SYSLOG_ADDRESS
        address_description = LOCAL_SYSLOG_ADDRESS
        probe_family = socket.AF_UNIX

    # SysLogHandler itself deliberately swallows a failed connection at
    # construction time (mirroring C's openlog(), which also ignores
    # connection errors - see its own createSocket()'s docstring/source),
    # deferring to emit() instead - which would mean a broken/absent local
    # syslog daemon doesn't fail once here, it fails *every single log
    # call* for the rest of the process, each one printing its own
    # exception traceback to stderr (logging's default handleError()
    # behavior). Probing the same address ourselves first, with a real
    # UDP socket whose errors we don't swallow, is what actually achieves
    # the "warn once and fall back to console/file-only" behavior this
    # function promises. This only reliably detects "the local socket
    # doesn't even exist" (AF_UNIX) or "the hostname doesn't resolve"
    # (AF_INET) - a UDP connect() never confirms a remote peer is actually
    # listening, so a remote host that resolves but has nothing listening
    # on that port will still pass this probe and only be discovered as
    # unreachable, silently, at actual send time (an inherent UDP
    # limitation, not something this project can detect any more reliably
    # than that).
    probe = socket.socket(probe_family, socket.SOCK_DGRAM)
    try:
        probe.connect(address)
    except OSError as e:
        logger.warning(f"Could not reach syslog at {address_description}: {e} - "
                        f"continuing without syslog logging.")
        return logger
    finally:
        probe.close()

    syslog_handler = logging.handlers.SysLogHandler(address=address, facility=facility)
    syslog_handler.setFormatter(logging.Formatter(f"sslcrtsrv-{tool_name}[%(process)d]: %(levelname)s %(message)s"))
    logger.addHandler(syslog_handler)

    return logger


def setup_tool_logging_from_file(config_file_path: str, tool_name: str, console: bool = True) -> logging.Logger:
    """Convenience wrapper for a CLI tool that doesn't already have the
    parsed server_config.json in hand (cltmanager.py/crtmanager.py/
    dbmigrate.py/admintui) - loads it tolerantly (silent {} fallback on a
    missing or invalid file, matching common/database.py's own
    apply_data_dir_from_config()) and calls setup_tool_logging(). A caller
    that already has the parsed config (server.py/acme_server.py/
    crtrequest.py) should call setup_tool_logging() directly instead, to
    avoid reading the file twice."""
    import json
    try:
        with open(config_file_path) as f:
            config = json.load(f)
    except (OSError, ValueError):
        config = {}
    return setup_tool_logging(config, tool_name, console=console)


def setup_server_logging(config: dict) -> logging.Logger:
    """Backward-compatible alias for setup_tool_logging(config, "server") -
    server_utils.py's Server.__init__() calls this by name; kept as a thin
    wrapper rather than updating that one call site, since "server" is
    exactly the right tool_name for it anyway."""
    return setup_tool_logging(config, "server")
