#!/usr/bin/env python3
"""
ACME (RFC 8555) server for sslcrtsrv - a new, parallel interface alongside
the existing custom client/server protocol. See ACME_SERVER_DESIGN.md for
the full protocol design; this module is only the process/HTTP-server
scaffolding (config loading, ThreadingHTTPServer setup, live config reload)
around common/acme_server_utils.py's actual endpoint logic.
"""

import argparse
import http.server
import json
import logging
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

from .common import database
from .common.acme_server_utils import AcmeRequestHandler, build_routes
from .common.config_watcher import ConfigFileWatcher
from .common.constants import DEFAULT_SERVER_CONFIG_FILE, ACME_DEFAULT_LISTEN, ACME_DEFAULT_PORT

# Explicit name, not logging.getLogger(__name__) - see server.py's own
# identical note: this module is normally run via
# `python3 -m sslcrtsrv.acme_server`, under which __name__ becomes
# "__main__" rather than "sslcrtsrv.acme_server".
logger = logging.getLogger("sslcrtsrv.acme_server")

# http.server.HTTPServer's stdlib default request_queue_size is 5 - fine for
# a lightly-loaded custom protocol, but far too small for an HTTP listener
# sitting behind a reverse proxy: a handful of concurrent client connections
# fills the accept backlog, and once it's full the kernel silently drops the
# final ACK of any new handshake instead of completing it, leaving the
# client's connection stuck retransmitting SYN-ACK forever (observed in
# production behind Nginx Proxy Manager, 2026-09-17). Raise it well above
# anything this server should plausibly see at once.
class _AcmeHTTPServer(http.server.ThreadingHTTPServer):
    request_queue_size = 128


class AcmeServer:
    """Owns the ThreadingHTTPServer instance and its own ConfigFileWatcher-
    based live-reload - mirrors common/server_utils.py's Server class, but
    for the ACME HTTP listener specifically. Deliberately a separate
    process/class rather than folded into that one's `bind_also` mechanism
    (ACME_SERVER_DESIGN.md §8.3) - `bind_also` is for multiple listeners of
    the *same* minimal binary protocol, and ACME's full HTTP surface (JSON
    bodies, custom headers, Retry-After) doesn't fit that minimal parser.

    Reads acme_* fields from the *same* server_config.json the traditional
    server uses - no separate config file, no `init` subcommand of its own.
    """

    def __init__(self, config_file_path=None):
        self.config_file_path = config_file_path or DEFAULT_SERVER_CONFIG_FILE
        self.httpd = None
        self.config_watcher = None
        self.running = False

        with open(self.config_file_path, 'r') as f:
            self.config = json.load(f)

        from .common.logging_utils import setup_tool_logging
        setup_tool_logging(self.config, "acme_server")

        if not self.config.get('acme_enabled'):
            raise RuntimeError(
                "acme_enabled is not set to true in server_config.json - the ACME "
                "server has nothing to do. Add \"acme_enabled\": true and "
                "\"acme_external_url\": \"https://your-host/acme\" to enable it."
            )
        if not self.config.get('acme_external_url'):
            raise RuntimeError(
                "acme_external_url is required when acme_enabled is true - it's the "
                "externally-visible base URL (behind the mandatory reverse proxy, see "
                "ACME_SERVER_DESIGN.md §8.1) every ACME resource URL is built from."
            )

        # Point the database layer at whatever data_dir/backend
        # server_config.json selects, exactly like common/server_utils.py's
        # Server.__init__() does - both processes must agree on where the
        # shared database actually lives.
        database.configure_database(self.config)
        from .common import constants as common_constants
        os.makedirs(common_constants.DATA_DIR, exist_ok=True)
        database.init_database()

        # SECURITY_FINDINGS.md finding #18: IP pinning is only ever checked
        # against the direct TCP peer unless acme_trusted_proxy_ip is also
        # set - behind a reverse proxy (the mandatory deployment shape,
        # ACME_SERVER_DESIGN.md §8.1) that peer is the proxy itself, not the
        # real client, silently making every pin ineffective. Surface this
        # loudly at startup instead of leaving it a silent misconfiguration.
        if not self.config.get('acme_trusted_proxy_ip') and database.any_client_has_ip_pin():
            logger.warning(
                "One or more clients have an IP pin (allowed_source_ip) set, but "
                "acme_trusted_proxy_ip is not configured - behind a reverse proxy, pins "
                "are checked against the proxy's own address, not the real client, making "
                "them ineffective. Set acme_trusted_proxy_ip to the proxy's address (Manual.MD "
                "Section 9.13) if this deployment sits behind one.")

        self.acme_listen = self.config.get('acme_listen', ACME_DEFAULT_LISTEN)
        self.acme_port = self.config.get('acme_port', ACME_DEFAULT_PORT)
        self.path_prefix = urlparse(self.config['acme_external_url']).path or '/'

    def start(self):
        self.httpd = _AcmeHTTPServer((self.acme_listen, self.acme_port), AcmeRequestHandler)
        # A hung handler thread must not block process shutdown - the main
        # binary-protocol server achieves the same end via its own explicit
        # shutdown()-before-close() sequencing (see Server.stop_server());
        # daemon_threads is ThreadingHTTPServer's equivalent for its
        # per-request worker threads.
        self.httpd.daemon_threads = True
        self.httpd.acme_config = self.config
        self.httpd.acme_routes = build_routes(self.path_prefix)

        self.running = True
        self.config_watcher = ConfigFileWatcher(self.config_file_path, self._on_config_file_changed,
                                                 on_error=self._on_config_watcher_error)
        self.config_watcher.start()

        logger.info(f"ACME server listening on {self.acme_listen}:{self.acme_port}, "
                    f"external URL {self.config['acme_external_url']}")
        try:
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("ACME server shutting down...")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        if self.config_watcher:
            self.config_watcher.stop()
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()

    def _on_config_file_changed(self):
        """Re-execs this same process rather than reloading fields in place -
        same reasoning as common/server_utils.py's Server._on_config_file_changed():
        config touches things (data_dir, database location, acme_listen/
        acme_port, acme_external_url) woven through already-initialized
        state, so a full restart is less error-prone than reconciling all of
        that live."""
        logger.info(f"Configuration file {self.config_file_path} changed - restarting to apply it...")
        self.stop()
        os.execv(sys.executable, [sys.executable, "-m", "sslcrtsrv.acme_server"] + sys.argv[1:])

    def _on_config_watcher_error(self, message: str):
        from .common.notify_utils import notify_error
        notify_error(self.config, "acme_config_watcher_init",
                     "[sslcrtsrv] ACME server config file watcher failed to start",
                     f"{message}\n\nChanges to {self.config_file_path} will require a "
                     f"manual restart of scs-acme-server to take effect until this is resolved.")


def main():
    parser = argparse.ArgumentParser(description="sslcrtsrv ACME (RFC 8555) server")
    parser.add_argument('--config', default=DEFAULT_SERVER_CONFIG_FILE,
                         help=f"Path to server_config.json (default: {DEFAULT_SERVER_CONFIG_FILE})")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Configuration file {config_path} not found. Run 'server.py init' first, "
              f"then add acme_enabled/acme_external_url to it.")
        sys.exit(1)

    try:
        acme_server = AcmeServer(config_file_path=str(config_path))
    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in configuration file {config_path}")
        sys.exit(1)
    except database.SchemaOutOfDate as e:
        print(f"Error: {e}")
        sys.exit(1)

    try:
        acme_server.start()
    except Exception as e:
        logger.error(f"ACME server error: {e}")
        from .common.notify_utils import notify_error
        notify_error(acme_server.config, "acme_server_crash",
                     "[sslcrtsrv] ACME server process crashed",
                     f"The ACME server process exited due to an unhandled error: {e}\n\n"
                     f"It is no longer running and will not restart automatically unless "
                     f"managed by systemd or a similar supervisor.")


if __name__ == "__main__":
    main()
