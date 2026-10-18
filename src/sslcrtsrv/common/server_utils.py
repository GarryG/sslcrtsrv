# Server utilities for the SSL Key Repository application

import logging
import os
import socket
import sys
import json
import threading
from datetime import datetime
from typing import Dict, Any, Optional
from .constants import (
    DEFAULT_SERVER_HOST, DEFAULT_SERVER_PORT, DEFAULT_SERVER_CONFIG_FILE,
    CLIENT_PACKAGE_DOWNLOAD_PATH_PREFIX, CLIENT_PACKAGES_CATALOG_PATH, CLIENT_PACKAGES_LIST_PATH,
    DEFAULT_TIMEOUT
)
from .config_watcher import ConfigFileWatcher
from .http_abuse_tracker import HttpAbuseTracker
from .auth_failure_tracker import new_auth_failure_tracker
from .network_acl import is_ip_permitted
from .crypto_utils import (
    generate_key_pair, save_keys, load_private_key, load_public_key,
    sign_message, verify_signature, get_public_key_fingerprint,
    encrypt_data, decrypt_data, load_private_key_from_string, load_public_key_from_string
)
from .network_utils import send_secure_message, receive_secure_message
from .message_utils import (
    create_register_message, create_status_message,
    create_response_message, create_congestion_message, is_valid_message
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Propagates up to and through the "sslcrtsrv" logger logging_utils.py's
# setup_server_logging() configures with console + syslog handlers - see
# that function's docstring. Only meaningful for the long-running server
# process (Server, below) - every other tool in this project still uses
# plain print().
logger = logging.getLogger(__name__)


def parse_bind_entry(raw: str):
    """Parse one 'HOST:PORT' entry from the config's optional 'bind_also'
    list (see Server.setup_server()) into a (host, port) tuple. A bracketed
    IPv6 host is also accepted ('[::1]:8443'); a bare host is split on the
    last colon so IPv4 addresses/hostnames with no brackets still work.
    Raises ValueError with a message safe to print directly if malformed.
    """
    raw = raw.strip()
    if raw.startswith('['):
        host, sep, rest = raw[1:].partition(']')
        if not sep or not rest.startswith(':'):
            raise ValueError(f"expected [HOST]:PORT in '{raw}'")
        port_str = rest[1:]
    else:
        if ':' not in raw:
            raise ValueError(f"expected HOST:PORT in '{raw}'")
        host, port_str = raw.rsplit(':', 1)
    if not host or not port_str.isdigit():
        raise ValueError(f"expected HOST:PORT in '{raw}'")
    return host, int(port_str)


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle datetime objects"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class Server:
    """Server class for the SSL Key Repository application"""
    
    def __init__(self, host: str = DEFAULT_SERVER_HOST, port: int = DEFAULT_SERVER_PORT,
                 config_file_path: Optional[str] = None):
        self.host = host
        self.port = port
        self.socket = None
        # (host, port, socket) for each extra 'bind_also' listener, populated
        # by setup_server() - see that method and _accept_connections().
        self.extra_sockets = []
        self.running = False
        self.config_watcher: Optional[ConfigFileWatcher] = None

        # Tracks unknown-URL HTTP requests and blocks abusive /24 subnets
        # from connecting to the port at all - both this HTTP path and the
        # regular signed/encrypted protocol (see start_server()'s accept
        # loop and handle_http_download()). See http_abuse_tracker.py.
        self.http_abuse_tracker = HttpAbuseTracker()

        # Tracks authentication-failure signals (a registration proof
        # mismatch, a rejected message signature) by source IP and blocks
        # the offending /24 subnet after a few strikes - SECURITY_FINDINGS.md
        # finding #17. Deliberately a separate tracker/threshold from
        # http_abuse_tracker above: these are higher-stakes events (someone
        # actively failing authentication, not just probing an unknown URL),
        # so fewer strikes trigger a longer block. See auth_failure_tracker.py.
        self.auth_failure_tracker = new_auth_failure_tracker()

        # Initialize server keys from configuration
        from .crypto_utils import generate_key_pair, save_keys, load_private_key, load_public_key
        from .system_utils import write_secure_json
        import json

        # Load or generate server keys from configuration file. Kept around
        # as self.config_file_path so start_server() can watch this exact
        # file for changes (not just DEFAULT_SERVER_CONFIG_FILE) - matters
        # when the server was started with a non-default --config.
        self.config_file_path = config_file_path or DEFAULT_SERVER_CONFIG_FILE
        config_path = self.config_file_path
        self.registration_secret = None
        self.config = {}
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)

                # Keep the full config around (notably the smtp_*/
                # notification_* keys) so handlers like handle_registration
                # can use it without re-reading the file from disk.
                self.config = config

                # Shared secret proving a client registration attempt was
                # authorized out-of-band; absent on unmigrated configs
                self.registration_secret = config.get("registration_secret")

                # Check if keys are already in the config
                if "private_key" in config and "public_key" in config:
                    # Load keys from configuration (they're stored as strings)
                    self.private_key = load_private_key_from_string(config["private_key"])
                    self.public_key = load_public_key_from_string(config["public_key"])
                else:
                    # Generate new keys and save to config
                    self.private_key, self.public_key = generate_key_pair()
                    # Save keys back to config as strings
                    private_pem = self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ).decode('utf-8')
                    
                    public_pem = self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8')
                    
                    config["private_key"] = private_pem
                    config["public_key"] = public_pem

                    from .constants import SHARED_FILE_MODE
                    write_secure_json(config_path, config, mode=SHARED_FILE_MODE)
            except Exception as e:
                # Deliberately still plain print(), not logger.error(): this
                # can be reached before setup_server_logging() below has
                # run (e.g. if the top-level json.load() itself is what
                # failed, self.config never got set to the real dict at
                # all) - there's no reliable syslog_host/syslog_facility to
                # read yet at this exact point.
                print(f"Error loading server keys from config: {e}")
                # Generate new keys if loading fails
                self.private_key, self.public_key = generate_key_pair()
                from .notify_utils import notify_error
                notify_error(self.config, "server_init_keys",
                             "[sslcrtsrv] Server failed to load its identity keys",
                             f"Loading the server's keypair from {config_path} failed: {e}\n\n"
                             f"The server generated a fresh keypair instead - every "
                             f"previously registered client will now fail signature "
                             f"verification until it is given the new public key.")
        else:
            # Generate new keys and save to config
            self.private_key, self.public_key = generate_key_pair()

        # Now that self.config has its final value for this call (populated
        # from file, or left {} if there was no file/it couldn't be parsed),
        # set up console+syslog logging (Section 5.1/10.6) - every log call
        # in this class from here on goes through it.
        from .logging_utils import setup_server_logging
        setup_server_logging(self.config)

        # Optional additional listeners, on top of the primary self.host/
        # self.port one - each entry is a raw 'HOST:PORT' string, parsed
        # lazily in setup_server() (after logging is available to report a
        # malformed entry through) rather than here.
        self.bind_also_raw = self.config.get('bind_also') or []

        # Optional netblock/subnet access control, checked in
        # _accept_connections() before anything else touches a freshly
        # accepted connection - independent of, and stricter than, both
        # http_abuse_tracker's dynamic blocking and the per-client
        # registration/signature authentication that happens later. Both
        # default to empty (no restriction) - see common/network_acl.py.
        self.allowed_networks = self.config.get('allowed_networks') or []
        self.denied_networks = self.config.get('denied_networks') or []

        if not self.registration_secret:
            logger.warning("No 'registration_secret' set in server_config.json - "
                            "client registration will be refused until one is configured "
                            "(see 'server.py init --registration-secret').")

        # Point the database layer at whatever data_dir/backend
        # server_config.json selects - must happen after self.config is
        # loaded above, and before DATA_DIR is read/used just below.
        from . import database as database_module
        database_module.configure_database(self.config)

        # Make sure the data directory exists
        from .constants import DATA_DIR
        os.makedirs(DATA_DIR, exist_ok=True)

        # Initialize database when server starts
        database_module.init_database()
        
    def setup_server(self) -> bool:
        """Setup the primary server socket, plus one additional listener per
        'HOST:PORT' entry in the config's optional 'bind_also' list (see
        Manual.MD) - e.g. to also listen on a VPN-only interface or an IPv6
        address alongside the primary self.host/self.port one. Every
        listener is handled identically once set up - same accept loop,
        abuse tracking, handle_client dispatch - see _accept_connections().
        A failure to bind an extra listener is logged/notified but does not
        prevent the primary listener (or any other extra one) from starting;
        only a failure on the primary listener makes this return False."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            # 5 (the historical default here) is too small once this port sits
            # behind a reverse proxy: a handful of concurrent connections fills
            # the accept backlog, and once full the kernel silently drops the
            # final ACK of any new handshake instead of completing it, leaving
            # the client stuck retransmitting SYN-ACK forever (see the
            # matching fix/comment in acme_server.py, found 2026-09-17).
            self.socket.listen(128)
        except Exception as e:
            logger.error(f"Error setting up server: {e}")
            from .notify_utils import notify_error
            notify_error(self.config, "server_setup_bind",
                         "[sslcrtsrv] Server failed to start listening",
                         f"The server could not bind to {self.host}:{self.port}: {e}\n\n"
                         f"The server process is not accepting any connections.")
            return False

        self.extra_sockets = []
        for raw in self.bind_also_raw:
            try:
                host, port = parse_bind_entry(raw)
            except ValueError as e:
                logger.error(f"Ignoring invalid 'bind_also' entry {raw!r}: {e}")
                continue
            try:
                # A host containing a colon is an unbracketed IPv6 address
                # (parse_bind_entry() already stripped any brackets) -
                # everything else (IPv4 dotted-quad or a hostname) uses
                # AF_INET, matching the primary socket above.
                family = socket.AF_INET6 if ':' in host else socket.AF_INET
                extra_socket = socket.socket(family, socket.SOCK_STREAM)
                extra_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                extra_socket.bind((host, port))
                extra_socket.listen(128)
                self.extra_sockets.append((host, port, extra_socket))
            except Exception as e:
                logger.error(f"Error setting up additional listener on {host}:{port}: {e}")
                from .notify_utils import notify_error
                notify_error(self.config, f"server_setup_bind_also:{host}:{port}",
                             "[sslcrtsrv] Server failed to start an additional listener",
                             f"The server could not bind to additional address {host}:{port} "
                             f"(from 'bind_also'): {e}\n\nThe primary listener is unaffected; "
                             f"this address alone will not accept connections.")

        return True

    def _accept_connections(self, sock: socket.socket, host: str, port: int):
        """Shared accept loop for one listening socket - runs on the main
        thread for the primary listener, and on its own daemon thread per
        additional 'bind_also' listener (see start_server()). Identical
        handling either way: abuse-tracker check, per-connection timeout,
        dispatch to handle_client() in its own thread."""
        logger.info(f"Server listening on {host}:{port}")
        error_key = f"server_accept_loop:{host}:{port}"

        while self.running:
            try:
                client_socket, address = sock.accept()

                # Static, admin-configured netblock allow/deny list, checked
                # before the dynamic abuse-tracker lookup below - a hard
                # rule should short-circuit before spending a lookup on a
                # source that's going to be rejected either way. There is no
                # reverse proxy in front of this protocol, so the direct TCP
                # peer (address[0]) is the only meaningful address to check.
                if not is_ip_permitted(address[0], self.allowed_networks, self.denied_networks):
                    logger.info(f"Refusing connection from {address}: not permitted by allowed_networks/denied_networks")
                    client_socket.close()
                    continue

                # Refuse a connection from a currently-blocked /24 subnet
                # (http_abuse_tracker.py) before doing anything else with
                # it - applies equally to the HTTP download path and the
                # regular signed/encrypted protocol, since neither has been
                # identified yet at this point, and equally across every
                # listener (the tracker is shared, not per-socket).
                if self.http_abuse_tracker.is_blocked(address[0]):
                    logger.info(f"Refusing connection from blocked subnet: {address}")
                    client_socket.close()
                    continue

                # Same idea, separate tracker/threshold: a subnet that's
                # been repeatedly failing authentication (see handle_client()
                # below) rather than just probing unknown URLs.
                if self.auth_failure_tracker.is_blocked(address[0]):
                    logger.info(f"Refusing connection from blocked subnet (auth failures): {address}")
                    client_socket.close()
                    continue

                logger.info(f"Connection from {address} on {host}:{port}")

                # Without this, a peer that connects and then sends nothing
                # (or sends only part of a message/request line and stalls)
                # blocks its handler thread in recv() forever - this same
                # timeout applies to both the regular signed/encrypted
                # protocol (handle_client()'s own recv()s and
                # network_utils.receive_secure_message()) and the plain-
                # HTTP download path (handle_http_download()/
                # _read_http_request_line()), since both run against this
                # same accepted socket. See issue.md's "no socket timeout
                # anywhere" entry.
                client_socket.settimeout(DEFAULT_TIMEOUT)

                # Handle each client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()

            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection on {host}:{port}: {e}")
                    from .notify_utils import notify_error
                    notify_error(self.config, error_key,
                                 f"[sslcrtsrv] Server is failing to accept new connections "
                                 f"on {host}:{port}",
                                 f"accept() on the listening socket for {host}:{port} is "
                                 f"failing repeatedly: {e}\n\nThis usually indicates resource "
                                 f"exhaustion (e.g. too many open files) - the server may be "
                                 f"unable to serve new clients on this address until this is "
                                 f"resolved. Further notifications for this condition are "
                                 f"suppressed for a few minutes.")

    def start_server(self) -> bool:
        """Start the server and begin accepting connections"""
        if not self.setup_server():
            return False

        self.running = True
        self.config_watcher = ConfigFileWatcher(self.config_file_path, self._on_config_file_changed,
                                                 on_error=self._on_config_watcher_error)
        self.config_watcher.start()

        # One dedicated daemon thread per additional 'bind_also' listener -
        # the primary listener runs its own accept loop on this (the main)
        # thread, below, so start_server() only returns once that one stops.
        for host, port, sock in self.extra_sockets:
            extra_thread = threading.Thread(target=self._accept_connections, args=(sock, host, port))
            extra_thread.daemon = True
            extra_thread.start()

        try:
            self._accept_connections(self.socket, self.host, self.port)
        except KeyboardInterrupt:
            logger.info("Server shutting down...")
        finally:
            self.stop_server()

        return True

    def stop_server(self):
        """Stop the server"""
        self.running = False
        if self.config_watcher:
            self.config_watcher.stop()
        # shutdown() before close(): a plain close() from a different thread
        # than the one blocked in accept() is not reliably observed by that
        # blocked call on Linux and can leave it hanging forever -
        # shutdown() does reliably unblock it. Matters now that stop_server()
        # can be called from the config-watcher thread while the accept
        # loop(s) are blocked in sock.accept(). Applies equally to the
        # primary socket and every extra 'bind_also' listener.
        all_sockets = ([self.socket] if self.socket else []) + \
                      [sock for _, _, sock in self.extra_sockets]
        for sock in all_sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        self.extra_sockets = []

    def _on_config_file_changed(self):
        """Called from the config-watcher thread once a burst of edits to
        self.config_file_path has settled. Re-execs this same process rather
        than reloading individual fields in place: config touches things
        (server keypair, data_dir, listen host/port, database location) that
        are woven through self and an already-initialized DB connection, so
        a full restart is far less error-prone than trying to reconcile all
        of that live. `os.execv` replaces this process image immediately -
        same PID, re-runs main() from scratch against the now-current config
        file, no dependency on systemd or any other supervisor to notice.
        """
        logger.info(f"Configuration file {self.config_file_path} changed - restarting to apply it...")
        self.stop_server()
        # Re-exec via `-m sslcrtsrv.server` regardless of how this process was
        # originally invoked (installed console script vs. `python3 -m ...`):
        # sys.argv[0] alone isn't reliable here (relies on it being a valid,
        # directly-runnable script - untrue for e.g. `python3 -m` invocations,
        # where argv[0] becomes server.py's absolute path, which fails on
        # relative imports if exec'd directly instead of via -m).
        os.execv(sys.executable, [sys.executable, "-m", "sslcrtsrv.server"] + sys.argv[1:])

    def _on_config_watcher_error(self, message: str):
        """Called from the config-watcher thread if it couldn't even start
        watching (see ConfigFileWatcher's on_error param) - a real degraded-
        operation condition (config changes will now require a manual
        restart to take effect) that would otherwise only ever be visible in
        the server's own console/log output."""
        from .notify_utils import notify_error
        notify_error(self.config, "config_watcher_init",
                     "[sslcrtsrv] Config file watcher failed to start",
                     f"{message}\n\nChanges to {self.config_file_path} will require a "
                     f"manual server restart to take effect until this is resolved.")


    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle communication with a connected client"""
        try:
            # Peek at the first byte (without consuming it) to tell which
            # protocol this connection is speaking: this application's own
            # framed protocol always starts with a single encryption-flag
            # byte, 0x00 or 0x01 (see network_utils.send_secure_message),
            # which can never collide with an HTTP request line's leading
            # verb (GET, HEAD, ...) - always an uppercase ASCII letter. This
            # lets a plain `curl` request for the client install package
            # share this same listening port with the real protocol, with
            # no separate port or process needed.
            first_byte = client_socket.recv(1, socket.MSG_PEEK)
            if first_byte and first_byte.isalpha():
                self.handle_http_download(client_socket, address)
                return

            # Receive and process messages from the client
            while True:
                # Receive message
                data = receive_secure_message(
                    client_socket,
                    private_key=self.private_key,   # handle verification when needed
                    public_key=None,
                    is_from_client=1                # load the client's key from DB based on client_id for verification
                )
                
                if not data:
                    # receive_secure_message() already covers signature
                    # failure, a missing signature, and an unresolvable
                    # client_id (network_utils.py) - every one of those is
                    # an authentication-failure signal worth counting
                    # toward this source IP's strikes (SECURITY_FINDINGS.md
                    # finding #17), not just a silent disconnect.
                    self.auth_failure_tracker.record_bad_request(address[0])
                    break

                self.auth_failure_tracker.record_good_request(address[0])

                client_public_key = data.get("client_public_key")

                # Process the message based on its type
                response = self.process_message(data, address)

                if response:
                    # A registration response is the one legitimate exception -
                    # the client has no confirmed server key yet and the server
                    # has no client key at all yet, so client_public_key is None
                    # by design here (see network_utils.receive_secure_message()'s
                    # "type != register" guard, which is the only thing that
                    # ever leaves it unset). Every other message type must
                    # already have resolved a real client public key, or
                    # receive_secure_message() would have rejected the message
                    # outright before it ever reached here - this check exists
                    # purely as defense in depth, so a bug elsewhere can never
                    # make the server silently send an authenticated response
                    # unencrypted (see issue.md).
                    if data.get("type") != "register" and client_public_key is None:
                        logger.error(f"Refusing to send response to {address}: no client public "
                                     f"key was resolved for a non-registration message - this "
                                     f"should be unreachable. Closing the connection.")
                        break

                    # print(f"Response data to send: {response}")
                    # Send response back to client
                    send_secure_message(
                        client_socket,
                        response,
                        private_key=self.private_key,               # Sign response with server's private key for authenticity
                        public_key=client_public_key                # Encrypt response using client's public key for confidentiality
                    )
                    
        except Exception as e:
            logger.error(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()

    def handle_http_download(self, client_socket: socket.socket, address: tuple):
        """Serve the configured client install packages over plain HTTP GET,
        e.g. `curl -f http://host:port/client-package/<name> -O`, sharing
        this same port/process with the main protocol (see handle_client()'s
        peek). The -f/--fail matters: without it, curl -O silently saves
        whatever comes back - including a 401's own body, on a typo'd/
        unknown name - as the output file with no error at all.

        Deliberately minimal and unauthenticated: GET only, no keep-alive, no
        Range support - this exists specifically so a brand-new host can
        fetch a client package before it has any keys or registration
        secret, which the normal signed/encrypted protocol would require
        (and which it can't have yet, since installing that package is the
        very thing being bootstrapped here). The packages themselves aren't
        sensitive - the real gate stays where it already was, at the
        registration-secret check in handle_registration().

        Routes - anything else at all is treated as abuse (tracked, and
        rejected with a 401) via self.http_abuse_tracker, which can also go
        on to block the offending /24 subnet from connecting to this port
        entirely (both this HTTP path and the regular signed/encrypted
        protocol - see start_server()'s accept loop):
          GET /client-package/<name>  - download that package's file
          GET /client-packages        - the catalog as JSON, so a client can
                                         compare versions without downloading
                                         anything
          GET /list                   - the same catalog as a human-readable
                                         help page
        """
        try:
            try:
                request_line = self._read_http_request_line(client_socket)
            except socket.timeout:
                # A connection that was routed here (the peeked first byte
                # looked like an HTTP verb) but then never finishes sending
                # its request line before the per-connection DEFAULT_TIMEOUT
                # elapses - a stalled/slow-loris-style connection - is exactly
                # the kind of behavior the abuse tracker exists to catch, not
                # just a quiet timeout to log and forget (see issue.md - this
                # case wasn't being counted at all before).
                logger.info(f"HTTP request from {address} timed out waiting for data - "
                            f"counting it as a bad request")
                self.http_abuse_tracker.record_bad_request(address[0])
                return
            if request_line is None:
                return

            parts = request_line.split()
            method = parts[0] if parts else ""
            path = parts[1].split("?", 1)[0] if len(parts) > 1 else ""

            client_packages = self.config.get("client_packages") or {}

            if path == CLIENT_PACKAGES_LIST_PATH:
                if method != "GET":
                    self._send_http_response(client_socket, 405, "Method Not Allowed",
                                              b"Only GET is supported on this endpoint.\n")
                    return
                self.http_abuse_tracker.record_good_request(address[0])
                self._send_http_response(client_socket, 200, "OK",
                                          self._render_client_packages_overview(client_packages))
                return

            if path == CLIENT_PACKAGES_CATALOG_PATH:
                if method != "GET":
                    self._send_http_response(client_socket, 405, "Method Not Allowed",
                                              b"Only GET is supported on this endpoint.\n")
                    return
                self.http_abuse_tracker.record_good_request(address[0])
                self._send_http_response(client_socket, 200, "OK",
                                          self._render_client_packages_json(client_packages),
                                          content_type="application/json")
                return

            if path.startswith(CLIENT_PACKAGE_DOWNLOAD_PATH_PREFIX):
                if method != "GET":
                    self._send_http_response(client_socket, 405, "Method Not Allowed",
                                              b"Only GET is supported on this endpoint.\n")
                    return

                name = path[len(CLIENT_PACKAGE_DOWNLOAD_PATH_PREFIX):]
                entry = client_packages.get(name) if name else None
                if entry is None:
                    # No name at all, or one that isn't configured - this is
                    # on the requester, not the server: an unknown path.
                    logger.warning(f"HTTP download request from {address} for unconfigured "
                                    f"package '{name}' - treating as an unknown path")
                    self._reject_unknown_path(client_socket, address)
                    return

                package_path = entry.get("path")
                if not (package_path and os.path.isfile(package_path)):
                    # A real, configured name, but the file itself is
                    # missing/misconfigured on the server - not the
                    # requester's fault, so not tracked as abuse.
                    logger.error(f"Configured client package '{name}' has no readable file "
                                 f"at {package_path!r}")
                    self._send_http_response(client_socket, 500, "Internal Server Error",
                                              b"Could not read this package on the server.\n")
                    return

                try:
                    with open(package_path, 'rb') as f:
                        package_data = f.read()
                except OSError as e:
                    logger.error(f"Error reading client package '{name}' at {package_path}: {e}")
                    self._send_http_response(client_socket, 500, "Internal Server Error",
                                              b"Could not read this package on the server.\n")
                    return

                filename = os.path.basename(package_path)
                self.http_abuse_tracker.record_good_request(address[0])
                self._send_http_response(
                    client_socket, 200, "OK", package_data,
                    content_type="application/octet-stream",
                    extra_headers={"Content-Disposition": f'attachment; filename="{filename}"'}
                )
                logger.info(f"Served client package '{name}' ({filename}, {len(package_data)} bytes) "
                            f"to {address} over HTTP")
                return

            # Any other path at all is unknown - tracked as possible abuse.
            self._reject_unknown_path(client_socket, address)

        except Exception as e:
            logger.error(f"Error handling HTTP download request from {address}: {e}")

    def _reject_unknown_path(self, client_socket: socket.socket, address: tuple):
        """The one response every unrecognized path on this port gets - no
        self-correcting overview here anymore (see issue.md's history on
        this endpoint), since that was itself minor information disclosure,
        and this endpoint is now also where repeated bad requests get
        tracked toward a /24 subnet block (http_abuse_tracker.py)."""
        self.http_abuse_tracker.record_bad_request(address[0])
        self._send_http_response(client_socket, 401, "Unauthorized", b"Authentication needed\n")

    def _render_client_packages_overview(self, client_packages: Dict[str, Any]) -> bytes:
        """Minimal plain-text help page for GET /list: what's available and
        how to fetch it - the one path an unauthenticated caller can reach
        by name at all, alongside the JSON catalog and an actual package
        download (handle_http_download()'s docstring) - everything else is
        treated as abuse, not shown a self-correcting page (issue.md has
        this endpoint's history)."""
        host_header = f"{self.host}:{self.port}" if self.host not in ("0.0.0.0", "") else f"<this server>:{self.port}"
        lines = []
        if not client_packages:
            lines.append("No client packages are currently configured on this server.")
        else:
            lines.append("Available client packages:")
            lines.append("")
            for name, entry in sorted(client_packages.items()):
                version = entry.get("version", "unknown")
                description = entry.get("description", "")
                line = f"  {name}  (version {version})"
                if description:
                    line += f"  - {description}"
                lines.append(line)
            lines.append("")
            lines.append(f"Download with: curl -f http://{host_header}{CLIENT_PACKAGE_DOWNLOAD_PATH_PREFIX}<name> -O")
            lines.append("(the -f/--fail is important - without it, curl saves this very page as the "
                          "output file on a typo'd/unknown name, with no error)")
        lines.append(f"Machine-readable catalog: curl http://{host_header}{CLIENT_PACKAGES_CATALOG_PATH}")
        return ("\n".join(lines) + "\n").encode("utf-8")

    @staticmethod
    def _render_client_packages_json(client_packages: Dict[str, Any]) -> bytes:
        """JSON catalog of name/version/description for every configured
        package - deliberately omits each entry's local filesystem `path`,
        which is a server-internal detail with no value to a remote caller.
        Intended for a client to compare against its own installed version
        before deciding whether to fetch a real download."""
        catalog = {
            name: {"version": entry.get("version"), "description": entry.get("description")}
            for name, entry in client_packages.items()
        }
        return json.dumps({"packages": catalog}, indent=2).encode("utf-8")

    @staticmethod
    def _read_http_request_line(client_socket: socket.socket, max_bytes: int = 8192) -> Optional[str]:
        """Read just enough of a minimal HTTP request to get its request
        line, draining up to max_bytes total so the socket can be closed
        cleanly afterwards. Returns None if the peer sent nothing at all."""
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < max_bytes:
            chunk = client_socket.recv(1024)
            if not chunk:
                break
            buf += chunk
        if not buf:
            return None
        request_line = buf.split(b"\r\n", 1)[0]
        return request_line.decode("ascii", errors="replace")

    @staticmethod
    def _send_http_response(client_socket: socket.socket, status_code: int, status_text: str, body: bytes,
                             content_type: str = "text/plain; charset=utf-8",
                             extra_headers: Optional[Dict[str, str]] = None):
        header_lines = [
            f"HTTP/1.1 {status_code} {status_text}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
        ]
        for key, value in (extra_headers or {}).items():
            header_lines.append(f"{key}: {value}")
        header_lines.append("Connection: close")
        headers = ("\r\n".join(header_lines) + "\r\n\r\n").encode("ascii")
        try:
            client_socket.sendall(headers + body)
        except OSError:
            pass

    def process_message(self, message: Dict[str, Any], address: tuple) -> Optional[Dict[str, Any]]:
        """Process an incoming message from a client"""
        try:
            # Validate the message structure
            if not is_valid_message(message):
                return create_response_message("error", False, {"message": "Invalid message format"})
            
            msg_type = message.get("type")
            
            if msg_type == "register":
                response = self.handle_registration(message)
                # A rejected registration (bad/missing proof, replayed
                # nonce, expired timestamp, ...) is an authentication-
                # failure signal worth counting toward this source IP's
                # strikes (SECURITY_FINDINGS.md finding #17) - "client
                # already registered" is deliberately excluded, since that
                # can legitimately happen to an honest client (e.g. a
                # restart racing a retry) and isn't itself a sign of
                # someone guessing credentials.
                if not response.get("success") and response.get("data", {}).get("message") != "Client already registered":
                    self.auth_failure_tracker.record_bad_request(address[0])
                return response
            elif msg_type == "request":
                return self.handle_request(message)
            else:
                return create_response_message("error", False, {"message": f"Unknown message type: {msg_type}"})
                
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            return create_response_message("error", False, {"message": "Internal server error"})
    
    def handle_registration(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle client registration"""
        try:
            import time
            from .database import get_client, save_client, consume_nonce
            from .crypto_utils import verify_registration_proof
            from .constants import REGISTRATION_TIMESTAMP_WINDOW_SECONDS

            client_id = message.get("client_id")
            public_key = message.get("public_key")  # Get the actual public key from client
            client_version = message.get("client_version")

            if not client_id or not public_key:
                return create_response_message("register", False, {"message": "Missing required fields"})

            # Require proof of the shared registration secret before anything
            # else - including before the "already registered" check below, so
            # an unauthenticated peer can't use this endpoint to enumerate
            # which client_ids are already taken (see finding #4).
            if not self.registration_secret:
                return create_response_message("register", False, {"message": "Registration is not enabled on this server"})

            nonce = message.get("nonce")
            timestamp = message.get("timestamp")
            proof = message.get("registration_proof")

            if not nonce or not timestamp or not proof:
                return create_response_message("register", False, {"message": "Invalid registration credentials"})

            try:
                timestamp_value = int(timestamp)
            except (TypeError, ValueError):
                return create_response_message("register", False, {"message": "Invalid registration credentials"})

            if abs(time.time() - timestamp_value) > REGISTRATION_TIMESTAMP_WINDOW_SECONDS:
                return create_response_message("register", False, {"message": "Invalid registration credentials"})

            if not verify_registration_proof(self.registration_secret, client_id, public_key, nonce, timestamp, proof):
                return create_response_message("register", False, {"message": "Invalid registration credentials"})

            # Reject replay of a previously-seen nonce (also prunes expired ones)
            if not consume_nonce(nonce, REGISTRATION_TIMESTAMP_WINDOW_SECONDS):
                return create_response_message("register", False, {"message": "Invalid registration credentials"})

            # Check if client is already registered
            existing_client = get_client(client_id)

            if existing_client:
                # Client already exists - return error
                return create_response_message("register", False, {"message": "Client already registered"})

            # Use the actual public key provided by the client for storage
            stored_public_key = public_key
            
            # Register new client - save to database with required fields
            success = save_client(client_id, stored_public_key, client_version=client_version)
            
            if not success:
                return create_response_message("register", False, {"message": "Failed to register client"})

            logger.info(f"Registered new client: {client_id}")

            # Notify the admin by email, if configured. Sent from a
            # background thread so a slow/unreachable SMTP server can never
            # delay the registration response back to the client - the
            # client is already safely persisted at this point regardless of
            # whether the email goes out.
            import threading
            from .notify_utils import send_registration_notification
            try:
                fingerprint = get_public_key_fingerprint(load_public_key_from_string(public_key))
            except Exception:
                fingerprint = None
            threading.Thread(
                target=send_registration_notification,
                args=(self.config, client_id, fingerprint or "unavailable"),
                daemon=True
            ).start()

            # Return confirmation with server's public key (for future secure communication)
            from .crypto_utils import load_public_key
            from cryptography.hazmat.primitives import serialization
            
            try:
                # For the registration response, we need to return the public key
                # Since we're using keys from config (not files), we can use self.public_key directly
                server_public_key_content = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                return create_response_message("register", True, {
                    "message": "Registration successful",
                    "server_public_key": server_public_key_content
                })
            except Exception as e:
                # If we can't load the public key, still return success but without it
                logger.warning(f"Could not load server public key for response: {e}")
                return create_response_message("register", True, {
                    "message": "Registration successful"
                })

        except Exception as e:
            logger.error(f"Error handling registration: {e}")
            return create_response_message("register", False, {"message": "Registration failed"})
    
    def handle_list_certificates(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle certificate listing request"""
        try:
            # Get client_id from message data
            data = message.get("data", {})
            client_id = data.get("client_id")
            
            if not client_id:
                return create_response_message("listcerts", False, {"message": "Client ID not provided"})
            
            # Get the client's database ID
            from .database import get_client
            client = get_client(client_id)
            if not client:
                return create_response_message("listcerts", False, {"message": "Client not found"})
            
            # Check if client is confirmed
            if client.status != "confirmed":
                return create_response_message("listcerts", False, {"message": "Client must be confirmed to list certificates"})
            
            # Query the database for certificates that this client has access to
            from .database import get_certificates_for_client, permission_is_active

            # Access client ID properly - we know it's a Row object that supports indexing
            client_id_from_db = client.id

            certificates = get_certificates_for_client(client_id_from_db)

            # Format the certificates for response - only ones the client
            # currently has an active (status=1, not expired) permission for;
            # a still-pending request or an expired/revoked permission should
            # not be listed as available (see issue.md's permission_valid_until
            # entry - this endpoint previously didn't check status at all).
            formatted_certs = []
            for cert in certificates:
                if not permission_is_active(cert[0]):  # cert is (relation, certificate)
                    continue
                formatted_certs.append({
                    "name": cert[1].fqdns,  # Use fqdns as certificate name (cert is tuple of relation and certificate)
                    "valid_from": cert[1].last_update.isoformat() if cert[1].last_update else None,  # Using last_update as valid_from
                    "valid_to": cert[1].validity_end_date.isoformat() if cert[1].validity_end_date else None  # Using validity_end_date as valid_to
                })
            
            return create_response_message("listcerts", True, {"certificates": formatted_certs})
            
        except Exception as e:
            logger.error(f"Error handling certificate listing: {e}", exc_info=True)
            return create_response_message("listcerts", False, {"message": "Failed to list certificates"})
    
    def handle_certificates_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle certificates request from client"""
        try:
            # Extract data from the message
            data = message.get("data", {})
            domains_str = data.get("domains", "")
            
            if not domains_str:
                return create_response_message("certificates", False, {"message": "No domains provided"})
            
            # Split and sort the domains
            domains = [d.strip() for d in domains_str.split(",") if d.strip()]
            domains.sort()
            
            # Rejoin without spaces
            sorted_domains = ",".join(domains)
            
            # Get client ID from message (this should be included in the data)
            client_id = data.get("client_id")
            if not client_id:
                return create_response_message("certificates", False, {"message": "Client ID not provided"})
            
            # Validate that client exists
            from .database import get_client
            client = get_client(client_id)
            if not client:
                return create_response_message("certificates", False, {"message": "Client not registered"})
            
            # Check if the client is confirmed - if not, reject the request
            if client.status != "confirmed":
                return create_response_message("certificates", False, {"message": "Client must be confirmed to request certificates"})
            
            # Check if client already has a certificate entry for these domains
            from .database import get_client_certificate_relation
            existing_relation = get_client_certificate_relation(client.id, sorted_domains)
            
            if existing_relation:
                # Relation already exists - return success but indicate it's already registered
                return create_response_message("certificates", True, {
                    "message": "Certificate request already registered",
                    "domains": sorted_domains
                })
            
            # Add new certificate entry for this client. A client_certificate_relations
            # row's fqdns is a foreign key into certificates.fqdns, but no certificate
            # exists yet at request time - crtrequest.py only creates one once the
            # admin actually issues it. Ensure a placeholder row exists first (the same
            # mechanism crtrequest.py itself uses), otherwise this insert violates that
            # FK - harmless on SQLite (never enforces its own FKs) but a hard failure on
            # MySQL/PostgreSQL, which do.
            from .database import add_client_certificate_relation, create_certificate_entry
            if create_certificate_entry(sorted_domains) is None:
                return create_response_message("certificates", False, {"message": "Failed to register certificate request"})
            success = add_client_certificate_relation(client.id, sorted_domains, status=0, valid_until=None)

            if success:
                # Notify the admin by email, if configured - same
                # background-thread pattern as the registration notification
                # in handle_registration, so a slow/unreachable SMTP server
                # can never delay the response back to the client.
                import threading
                from .notify_utils import send_certificate_request_notification
                threading.Thread(
                    target=send_certificate_request_notification,
                    args=(self.config, client_id, sorted_domains),
                    daemon=True
                ).start()

                return create_response_message("certificates", True, {
                    "message": "Certificate request registered successfully",
                    "domains": sorted_domains
                })
            else:
                return create_response_message("certificates", False, {"message": "Failed to register certificate request"})
                
        except Exception as e:
            logger.error(f"Error handling certificates request: {e}")
            return create_response_message("error", False, {"message": "Certificates request processing failed"})
    
    def handle_certificate_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle specific certificate request from client"""
        try:
            # Extract data from the message
            data = message.get("data", {})
            fqdns = data.get("fqdns")
            
            if not fqdns:
                return create_response_message("certificate", False, {"message": "No FQDNs provided"})
            
            # Get client ID from message (this should be included in the data)
            client_id = data.get("client_id")
            if not client_id:
                return create_response_message("certificate", False, {"message": "Client ID not provided"})
            
            # Validate that client exists
            from .database import get_client
            client = get_client(client_id)
            if not client:
                return create_response_message("certificate", False, {"message": "Client not registered"})
            
            # Check if the client is confirmed - if not, reject the request
            if client.status != "confirmed":
                return create_response_message("certificate", False, {"message": "Client must be confirmed to request certificates"})
            
            # Check if client has permission for this certificate
            from .database import get_client_certificate_relation, permission_is_active
            relation = get_client_certificate_relation(client.id, fqdns)
            
            if not permission_is_active(relation):
                return create_response_message("certificate", False, {"message": "Access denied: Client does not have permission for this certificate"})
            
            # Get certificate information from database
            from .database import get_certificate_info
            
            cert_info = get_certificate_info(fqdns)
            
            if not cert_info:
                return create_response_message("certificate", False, {"message": "Certificate not found"})
            
            # Return certificate information
            return create_response_message("certificate", True, {"certificate": cert_info})
            
        except Exception as e:
            logger.error(f"Error handling certificate request: {e}")
            return create_response_message("error", False, {"message": "Certificate request processing failed"})

    def handle_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle general request from client"""
        try:
            request_type = message.get("request_type")

            # Anti-replay: every request must carry a fresh, unused nonce and
            # a current timestamp - mirrors registration's own scheme
            # (handle_registration()/Section 3.3.4), required unconditionally
            # here (no legacy/transitional tolerance for a request missing
            # either field) since every client in this deployment is upgraded
            # together with the server. Without this, a captured request
            # could be replayed verbatim later and reprocessed as if fresh -
            # harmless for a purely read-only request_type, but a genuine
            # integrity problem for one with a real side effect (e.g.
            # retrieve's download-tracking update - see fixed-issues.md).
            # Checked here, once, before any request_type-specific handler
            # runs, rather than per-handler, so this can't silently stop
            # applying to some future request type the way it already did
            # for retrieve.
            import time
            from .database import consume_nonce
            from .constants import REQUEST_TIMESTAMP_WINDOW_SECONDS
            nonce = message.get("nonce")
            timestamp = message.get("timestamp")
            valid = False
            if nonce and timestamp:
                try:
                    if abs(time.time() - int(timestamp)) <= REQUEST_TIMESTAMP_WINDOW_SECONDS:
                        valid = consume_nonce(nonce, REQUEST_TIMESTAMP_WINDOW_SECONDS)
                except (TypeError, ValueError):
                    valid = False
            if not valid:
                return create_response_message(request_type or "error", False,
                                                {"message": "Invalid, expired, or replayed request"})

            # Extract data from the message
            data = message.get("data", {})

            if request_type == "certificate":
                # Handle certificate request specifically
                return self.handle_certificate_request(message)
            elif request_type == "certificates":
                # Handle certificates request (new implementation)
                return self.handle_certificates_request(message)
            elif request_type == "info":
                # Handle info request
                return self.handle_info_request(message)
            elif request_type == "retrieve":
                # Handle retrieve request
                return self.handle_retrieve_request(message)
            elif request_type == "listcerts":
                # Handle list certificates request
                return self.handle_list_certificates(message)
            elif request_type == "version":
                # Handle version check request
                return self.handle_version_request(message)
            else:
                return create_response_message("error", False, {"message": f"Unknown request type: {request_type}"})
                
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            return create_response_message("error", False, {"message": "Request processing failed"})

    def handle_version_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Return the server's own version - used by scs-client's
        checkversion command. No confirmed-client (or even client_id) check
        needed: reaching this point already required a signature verified
        against a registered client's on-file public key (see
        common/network_utils.py's receive_secure_message()), and the
        server's version itself is added automatically to every response by
        create_response_message() - nothing else to do here."""
        return create_response_message("version", True, {})

    def handle_info_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle certificate info request from client"""
        try:
            # Extract data from the message
            data = message.get("data", {})
            fqdns = data.get("fqdns")

            if not fqdns:
                return create_response_message("info", False, {"message": "No FQDNs provided"})

            # Get client ID from message (this should be included in the data)
            client_id = data.get("client_id")
            if not client_id:
                return create_response_message("info", False, {"message": "Client ID not provided"})

            # Validate that client exists
            from .database import get_client
            client = get_client(client_id)
            if not client:
                return create_response_message("info", False, {"message": "Client not registered"})

            # Check if the client is confirmed - if not, reject the request
            if client.status != "confirmed":
                return create_response_message("info", False, {"message": "Client must be confirmed to request certificates"})

            # Check if client has permission for this certificate - same
            # check as handle_certificate_request/handle_retrieve_request, so
            # a client can't learn anything about a certificate (even just
            # its validity dates/provider) that isn't assigned to it.
            from .database import get_client_certificate_relation, permission_is_active
            relation = get_client_certificate_relation(client.id, fqdns)

            if not permission_is_active(relation):
                return create_response_message("info", False, {"message": "Access denied: Client does not have permission for this certificate"})

            # Get certificate information from database
            from .database import get_certificate_info

            cert_info = get_certificate_info(fqdns)

            if not cert_info:
                return create_response_message("info", False, {"message": "Certificate not found"})

            # Return certificate information
            return create_response_message("info", True, {"certificate": cert_info})

        except Exception as e:
            logger.error(f"Error handling info request: {e}")
            return create_response_message("error", False, {"message": "Info request processing failed"})
            
    def handle_retrieve_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle certificate retrieval request from client"""
        try:
            # Extract data from the message
            data = message.get("data", {})
            fqdns = data.get("fqdns")
            
            if not fqdns:
                return create_response_message("retrieve", False, {"message": "No FQDNs provided"})
            
            # Get client ID from message (this should be included in the data)
            client_id = data.get("client_id")
            if not client_id:
                return create_response_message("retrieve", False, {"message": "Client ID not provided"})
            
            # Validate that client exists
            from .database import get_client
            client = get_client(client_id)
            if not client:
                return create_response_message("retrieve", False, {"message": "Client not registered"})
            
            # Check if the client is confirmed - if not, reject the request
            if client.status != "confirmed":
                return create_response_message("retrieve", False, {"message": "Client must be confirmed to retrieve certificates"})
            
            # Check if client has permission for this certificate by checking client_certificate_relations
            from .database import get_client_certificate_relation, permission_is_active
            relation = get_client_certificate_relation(client.id, fqdns)
            
            if not permission_is_active(relation):
                return create_response_message("retrieve", False, {"message": "Access denied: Client does not have permission for this certificate"})
            
            # Get certificate information from database
            from .database import get_certificate_info, get_certificate
            
            cert_info = get_certificate_info(fqdns)
            certificate = get_certificate(fqdns)
            
            if not cert_info or not certificate:
                return create_response_message("retrieve", False, {"message": "Certificate not found"})
            
            # Check that the key is present (as an additional safety check)
            if not certificate.private_key:
                return create_response_message("retrieve", False, {"message": "Certificate not yet available for retrieval"})

            # Decrypt the private key (stored encrypted at rest - see common/db_crypto.py)
            from .db_crypto import decrypt_for_storage
            try:
                decrypted_private_key = decrypt_for_storage(certificate.private_key)
            except Exception as e:
                logger.error(f"Error decrypting private key for {fqdns}: {e}")
                return create_response_message("retrieve", False,
                    {"message": "Server misconfiguration: cannot decrypt certificate key"})

            # Record this successful retrieval so a stale-download report
            # (scs-crtmanager warn-stale-downloads) can later tell this
            # client is still running whatever copy it fetched today, even
            # after the certificate itself gets renewed. Never fails the
            # response - the client has already been handed real decrypted
            # key material below regardless of whether this write succeeds.
            from .database import record_certificate_download
            if not record_certificate_download(client.id, fqdns, certificate.validity_end_date):
                logger.warning(f"Failed to record certificate download for client {client_id}/{fqdns}")

            # Return certificate data components
            response_data = {
                "fqdns": cert_info['fqdns'],
                "key_present": cert_info['key_present'],
                "cert_present": cert_info['cert_present'],
                "intermediate_present": cert_info['intermediate_present'],
                "key": decrypted_private_key,
                "cert": certificate.public_key,
                "intermediate": certificate.intermediates if certificate.intermediates else None
            }
            
            return create_response_message("retrieve", True, response_data)
            
        except Exception as e:
            logger.error(f"Error handling retrieve request: {e}")
            return create_response_message("error", False, {"message": "Retrieve request processing failed"})


# Utility functions for server operations
def create_server(host: str = DEFAULT_SERVER_HOST, port: int = DEFAULT_SERVER_PORT,
                   config_file_path: Optional[str] = None) -> Server:
    """Create a new server instance"""
    return Server(host, port, config_file_path=config_file_path)


def start_server(server: Server) -> bool:
    """Start a server instance"""
    return server.start_server()


def stop_server(server: Server):
    """Stop a server instance"""
    server.stop_server()