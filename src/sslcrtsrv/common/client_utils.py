# Client utilities for the SSL Key Repository application

import os
import json
import re
import socket
import secrets
import time
import urllib.request
import urllib.error
from typing import Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from .constants import (
    DEFAULT_SERVER_HOST, DEFAULT_SERVER_PORT, REGISTRATION_NONCE_BYTES,
    CLIENT_PACKAGE_DOWNLOAD_PATH_PREFIX, CLIENT_PACKAGES_CATALOG_PATH
)
from .crypto_utils import (
    generate_key_pair, save_keys, load_private_key, load_public_key,
    load_private_key_from_string, load_public_key_from_string,
    sign_message, verify_signature, get_public_key_fingerprint,
    compute_registration_proof
)
from .network_utils import send_secure_message, receive_secure_message
from .message_utils import (
    create_register_message, create_listcerts_message,
    create_request_message, create_response_message, is_valid_message
)
from .system_utils import write_secure_json
from .fqdns_utils import normalize_fqdns


def _existing_certificate_is_current(cert_path: str, new_cert_pem: str) -> bool:
    """True if `cert_path` already holds a valid certificate whose validity
    end date is the same as, or later than, the certificate in
    `new_cert_pem` - i.e. writing the newly retrieved certificate would not
    actually be an improvement, so retrieve_certificate() should leave the
    existing key/cert/intermediate files untouched.

    False (go ahead and write the new files) if `cert_path` doesn't exist,
    doesn't contain a valid certificate, or is genuinely older than the new
    one - an unreadable/corrupt existing file is always replaced rather than
    left in place, since there's nothing meaningful to preserve there.
    """
    if not cert_path or not os.path.exists(cert_path):
        return False
    try:
        with open(cert_path, 'rb') as f:
            existing_pem = f.read()
        existing_cert = x509.load_pem_x509_certificate(existing_pem, default_backend())
        new_cert = x509.load_pem_x509_certificate(new_cert_pem.encode('utf-8'), default_backend())
    except Exception:
        return False

    # Support both old (<42.0.0) and new (>=42.0.0) cryptography library APIs
    existing_end = existing_cert.not_valid_after_utc if hasattr(existing_cert, 'not_valid_after_utc') \
        else existing_cert.not_valid_after
    new_end = new_cert.not_valid_after_utc if hasattr(new_cert, 'not_valid_after_utc') \
        else new_cert.not_valid_after
    return existing_end >= new_end


def _version_tuple(version_str: str):
    """Best-effort version-string -> comparable tuple, without pulling in an
    extra dependency (e.g. `packaging`) just for this. Splits on '.'/'-'/'_';
    numeric segments compare numerically, everything else falls back to
    string comparison, tagged so numeric and non-numeric segments never get
    directly compared to each other (which would raise TypeError) - good
    enough for this project's plain X.Y.Z versions.
    """
    segments = re.split(r'[.\-_]', version_str.strip())
    return tuple((0, int(s)) if s.isdigit() else (1, s) for s in segments)


def _fetch_client_packages_catalog(server_host: str, server_port: int, timeout: float = 10):
    """Fetch and parse the server's unauthenticated HTTP client-package
    catalog (see common/server_utils.py's handle_http_download(),
    CLIENT_PACKAGES_CATALOG_PATH) - shared by check_for_client_package_update()
    and list_available_packages() so the fetch/parse logic exists in one
    place. Returns (catalog_dict, None) on success, or (None, error_message)
    on failure - never raises."""
    url = f"http://{server_host}:{server_port}{CLIENT_PACKAGES_CATALOG_PATH}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode('utf-8')), None
    except Exception as e:
        return None, f"Could not reach server catalog at {url}: {e}"


def list_available_packages(server_host: str, server_port: int, timeout: float = 10) -> Dict[str, Any]:
    """Every package currently in the server's catalog - see client.py's
    `listpackages` command. Returns {'packages': {name: {'version',
    'description'}, ...}, 'error': str|None} - 'packages' is always a dict
    (empty if the catalog itself is empty), 'error' is only set when the
    server couldn't be reached at all."""
    catalog, error = _fetch_client_packages_catalog(server_host, server_port, timeout)
    if error:
        return {'packages': {}, 'error': error}
    return {'packages': catalog.get('packages') or {}, 'error': None}


def detect_package_type() -> Optional[str]:
    """The package "type" (e.g. "deb", "tarball") this running copy of
    sslcrtsrv was actually built/installed as, read from a PACKAGE_TYPE
    marker file placed inside the sslcrtsrv package directory at build time
    (see build-tarballs.py, debian/rules) - never present in the git source
    tree itself, so a development checkout/editable install correctly has
    none. Used by client.py's `update` command to combine with
    client_config.json's `update_package_base` into the actual catalog name
    to request, instead of guessing at a CPU architecture this project's
    packages don't actually vary by (they're all `Architecture: all`).

    Returns None if the marker is absent/unreadable - callers must then
    require an explicit --update-package/`update_package`, never guess."""
    marker_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'PACKAGE_TYPE')
    try:
        with open(marker_path) as f:
            return f.read().strip() or None
    except OSError:
        return None


def check_for_client_package_update(server_host: str, server_port: int, package_name: str,
                                     current_version: str, timeout: float = 10) -> Dict[str, Any]:
    """Query the server's unauthenticated HTTP catalog (see
    common/server_utils.py's handle_http_download(), CLIENT_PACKAGES_CATALOG_PATH)
    for `package_name`, and compare its version against `current_version`.
    Deliberately doesn't need a registered client/keys - it's plain HTTP.

    Returns {'found': bool, 'newer': bool, 'server_version': str|None,
    'description': str|None, 'error': str|None} - 'error' is set (and every
    other field left at its default) only when the server couldn't be
    reached at all or doesn't know about `package_name`.
    """
    catalog, error = _fetch_client_packages_catalog(server_host, server_port, timeout)
    if error:
        return {'found': False, 'newer': False, 'server_version': None, 'description': None,
                'error': error}

    entry = (catalog.get('packages') or {}).get(package_name)
    if not entry:
        catalog_url = f"http://{server_host}:{server_port}{CLIENT_PACKAGES_CATALOG_PATH}"
        return {'found': False, 'newer': False, 'server_version': None, 'description': None,
                'error': f"No package named '{package_name}' is available on the server "
                         f"(see {catalog_url}, or run `client.py listpackages`, for what is)."}

    server_version = entry.get('version')
    try:
        is_newer = bool(server_version) and _version_tuple(server_version) > _version_tuple(current_version)
    except Exception:
        # Versions that don't fit the usual X.Y.Z shape - fall back to "any
        # difference counts as newer" rather than silently never updating.
        is_newer = server_version != current_version

    return {'found': True, 'newer': is_newer, 'server_version': server_version,
            'description': entry.get('description'), 'error': None}


def download_client_package(server_host: str, server_port: int, package_name: str,
                             destination_path: str, timeout: float = 60) -> Optional[str]:
    """Download `package_name` from the server's unauthenticated HTTP
    download endpoint (see check_for_client_package_update()) and save it to
    destination_path. Returns None on success, or an error message string
    (safe to print directly) on failure.
    """
    url = f"http://{server_host}:{server_port}{CLIENT_PACKAGE_DOWNLOAD_PATH_PREFIX}{package_name}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
    except urllib.error.HTTPError as e:
        return f"Server returned {e.code} {e.reason} for {url}"
    except Exception as e:
        return f"Could not download from {url}: {e}"

    try:
        with open(destination_path, 'wb') as f:
            f.write(data)
    except OSError as e:
        return f"Could not save downloaded package to {destination_path}: {e}"

    return None


class Client:
    """Client class for the SSL Key Repository application"""
    
    def __init__(self, client_id: str, private_key_path: str = None,
                 public_key_path: str = None, server_public_key_str: str = None,
                 registration_secret: str = None):
        self.client_id = client_id
        self.private_key_path = private_key_path or f"/etc/sslcrtsrv/client_{client_id}_private.pem"
        self.public_key_path = public_key_path or f"/etc/sslcrtsrv/client_{client_id}_public.pem"
        self.private_key = None
        self.public_key = None
        self.public_key_fingerprint = None
        self.registration_secret = registration_secret
        # `server_public_key_str` used to be accepted here and then silently
        # discarded - self.server_public_key was unconditionally left None,
        # which made every post-registration request go out unencrypted (see
        # send_secure_message()'s public_key=None fallback) and every
        # response come back with no signature check at all (same fallback
        # in receive_secure_message()). Actually load it now, exactly like
        # setup_keys() loads the client's own keys.
        self.server_public_key = None
        if server_public_key_str:
            try:
                self.server_public_key = load_public_key_from_string(server_public_key_str)
            except Exception as e:
                print(f"Error loading server public key: {e}")
        self.socket = None
        
    def setup_keys(self, private_key_str: str = None, public_key_str: str = None) -> bool:
        """Generate or load keys for the client"""
        # If we have key strings passed in, use those directly
        if private_key_str is not None and public_key_str is not None:
            try:
                self.private_key = load_private_key_from_string(private_key_str)
                self.public_key = load_public_key_from_string(public_key_str)
                self.public_key_fingerprint = get_public_key_fingerprint(self.public_key)
                return True
            except Exception as e:
                print(f"Error loading keys from strings: {e}")
                return False
        
        # For this implementation, we only use keys from configuration
        # The check for existing key files is no longer needed since all keys are in config files
        # If the keys were not passed in, we should raise an error as they must be provided through config
        print("Warning: Keys should be provided via configuration - this method was called without key strings")
        return False
    
    def connect_to_server(self, host: str = DEFAULT_SERVER_HOST, 
                         port: int = DEFAULT_SERVER_PORT) -> bool:
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((host, port))
            return True
        except Exception as e:
            print(f"Error connecting to server: {e}")
            return False
    
    def register_with_server(self, config_file_path: str = None) -> bool:
        """Register this client with the server"""
        if not self.socket or not self.public_key_fingerprint:
            return False

        if not self.registration_secret:
            print("Error: no registration secret configured. Re-run 'init' with the "
                  "registration secret provided by the server administrator.")
            return False

        try:
            # Create registration message with actual public key (not just fingerprint)
            # Convert public key to string format for transmission
            from cryptography.hazmat.primitives import serialization
            public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            # Prove knowledge of the shared registration secret without ever
            # sending the secret itself, bound to a fresh nonce + timestamp so
            # a captured registration message can't be replayed later (finding #4)
            nonce = secrets.token_hex(REGISTRATION_NONCE_BYTES)
            timestamp = str(int(time.time()))
            registration_proof = compute_registration_proof(
                self.registration_secret, self.client_id, public_key_pem, nonce, timestamp
            )

            register_msg = create_register_message(
                self.client_id,
                public_key_pem,  # Send the actual public key as PEM string
                nonce=nonce,
                timestamp=timestamp,
                registration_proof=registration_proof
            )

            # Send registration message
            success = send_secure_message(
                self.socket, 
                register_msg, 
                private_key=None,
                public_key=None
            )
            
            if not success:
                return False
                
            # Receive response
            response = receive_secure_message(
                self.socket,
                private_key=None,
                public_key=None
            )
            
            if not response:
                print("Failed to receive registration response")
                return False
            
            # Check if registration was successful
            if response.get("response_type") == "register" and response.get("success"):
                print("Registration successful!")
                
                # Store server's public key for future communications (if provided)
                server_public_key = response.get("data", {}).get("server_public_key")
                if server_public_key:
                    # Load the server's public key to get its fingerprint
                    from cryptography.hazmat.primitives import serialization
                    server_public_key_obj = serialization.load_pem_public_key(
                        server_public_key.encode('utf-8'),
                        backend=default_backend()
                    )
                    server_fingerprint = get_public_key_fingerprint(server_public_key_obj)

                    # Keep this in-memory object consistent immediately, in
                    # case anything in this same process tries to send an
                    # authenticated message right after registering, rather
                    # than relying solely on the next process re-reading it
                    # back from the config file (see _require_secure_channel()).
                    self.server_public_key = server_public_key_obj

                    # Print both the server's key fingerprint and the client's own, as words
                    # (easier to read aloud/compare out-of-band than 64 hex characters - see
                    # fingerprint_words.py) and as raw hex underneath for anyone who wants to
                    # compare byte-for-byte or paste it elsewhere.
                    from .fingerprint_words import format_fingerprint_words
                    print(f"Server public key fingerprint: {server_fingerprint}")
                    print(format_fingerprint_words(server_fingerprint))
                    print(f"Client public key fingerprint: {self.public_key_fingerprint}")
                    print(format_fingerprint_words(self.public_key_fingerprint))
                    
                    # Update the configuration file with the server's public key
                    if config_file_path:
                        self.update_config_with_server_key(server_public_key, config_file_path)
                    else:
                        print("Warning: No config file path provided to store server public key")
                    
                return True
            else:
                print(f"Registration failed: {response.get('data', {}).get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            print(f"Error registering with server: {e}")
            return False
    
    def update_config_with_server_key(self, server_public_key: str, config_file_path: str) -> bool:
        """Update the client configuration file with the server's public key"""
        try:
            # Load existing config
            with open(config_file_path, 'r') as f:
                config = json.load(f)
            
            # Add or update the server public key in the config
            config['server_public_key'] = server_public_key

            # Save updated config (re-asserts owner-only permissions, since this
            # file also contains the client's private key)
            write_secure_json(config_file_path, config)

            return True
        except Exception as e:
            print(f"Error updating config with server key: {e}")
            return False

    def _require_secure_channel(self) -> bool:
        """True only if this client can both sign (self.private_key) and
        encrypt (self.server_public_key) an authenticated request. Every
        method below checks this before calling send_secure_message() -
        a missing key refuses the operation outright rather than silently
        falling back to an unencrypted/unsigned message (see issue.md).
        The only exceptions to this requirement anywhere in the protocol
        are register_with_server() (the initial key exchange necessarily
        has no keys to use yet) and the plain-HTTP client-package download
        helpers, neither of which call this method."""
        if not self.private_key:
            print("Error: no client private key loaded - cannot sign this request. "
                  "Re-run 'init' (or fix client_config.json) before retrying.")
            return False
        if not self.server_public_key:
            print("Error: no server public key on file for this client - refusing to "
                  "send this request unencrypted. Re-run 'register' to obtain the "
                  "server's public key.")
            return False
        return True

    def check_version(self) -> Optional[Dict[str, Any]]:
        """Ask the server for its own version - see client.py's checkversion
        command. The client's own version is already sent automatically
        with this request (see common/message_utils.py's
        create_request_message()); the response carries the server's back
        as its top-level "server_version" field."""
        if not self.socket:
            return None
        if not self._require_secure_channel():
            return None

        try:
            version_msg = create_request_message("version", {
                "client_id": self.client_id
            })

            success = send_secure_message(
                self.socket,
                version_msg,
                private_key=self.private_key,
                public_key=self.server_public_key
            )

            if not success:
                return None

            return receive_secure_message(
                self.socket,
                private_key=self.private_key,
                public_key=self.server_public_key
            )

        except Exception as e:
            print(f"Error checking server version: {e}")
            return None

    def list_certificates(self) -> Optional[Dict[str, Any]]:
        """Request a list of certificates from the server"""
        if not self.socket:
            return None
        if not self._require_secure_channel():
            return None

        try:
            # Create list certificates message with client_id in data
            list_msg = create_request_message("listcerts", {
                "client_id": self.client_id
            })
            
            # Send message
            success = send_secure_message(
                self.socket,
                list_msg,
                private_key=self.private_key,
                public_key=self.server_public_key
            )
            
            if not success:
                return None
            
            # Receive response
            response = receive_secure_message(
                self.socket,
                private_key=self.private_key,
                public_key=self.server_public_key
            )
            
            return response
            
        except Exception as e:
            print(f"Error listing certificates: {e}")
            return None
    
    def request_certificates(self, fqdn_string: str) -> Optional[Dict[str, Any]]:
        """Request certificates for the specified FQDNs from the server"""
        if not self.socket:
            return None
        if not self._require_secure_channel():
            return None

        try:
            # Canonicalize the FQDNs so the server's own lookup key (Section
            # 9.1 of the Manual) matches regardless of how this string was
            # delimited on the command line.
            processed_fqdns = normalize_fqdns(fqdn_string)

            # Create request message with the processed FQDNs
            request_msg = create_request_message("certificates", {
                "client_id": self.client_id,
                "domains": processed_fqdns
            })
            
            # Send message
            success = send_secure_message(
                self.socket,
                request_msg,
                private_key=self.private_key,
                public_key=self.server_public_key
            )
            
            if not success:
                return None
                
            # Receive response
            response = receive_secure_message(
                self.socket,
                private_key=self.private_key,
                public_key=self.server_public_key
            )
            
            return response
            
        except Exception as e:
            print(f"Error requesting certificates: {e}")
            return None
    
    def request_certificate(self, fqdns: str) -> Optional[Dict[str, Any]]:
        """Request a specific certificate from the server"""
        if not self.socket:
            return None
        if not self._require_secure_channel():
            return None

        try:
            # Create request message for specific certificate
            request_msg = create_request_message("certificate", {
                "client_id": self.client_id,
                "fqdns": normalize_fqdns(fqdns)
            })
            
            # Send message
            success = send_secure_message(
                self.socket,
                request_msg,
                private_key=self.private_key,
                public_key=self.server_public_key
            )
            
            if not success:
                return None
                
            # Receive response
            response = receive_secure_message(
                self.socket,
                private_key=self.private_key,
                public_key=self.server_public_key
            )
            
            return response
            
        except Exception as e:
            print(f"Error requesting certificate: {e}")
            return None
    
    def get_certificate_info(self, fqdns: str) -> Optional[Dict[str, Any]]:
        """Request certificate information from the server"""
        if not self.socket:
            return None
        if not self._require_secure_channel():
            return None

        try:
            # Create request message for info
            request_msg = create_request_message("info", {
                "client_id": self.client_id,
                "fqdns": normalize_fqdns(fqdns)
            })
            
            # Send message
            success = send_secure_message(
                self.socket,
                request_msg,
                private_key=self.private_key,
                public_key=self.server_public_key
            )
            
            if not success:
                return None
                
            # Receive response
            response = receive_secure_message(
                self.socket,
                private_key=self.private_key,
                public_key=self.server_public_key
            )
            
            return response
            
        except Exception as e:
            print(f"Error requesting certificate info: {e}")
            return None
    
    def retrieve_certificate(self, fqdns: str, key_path: str = None,
                           cert_path: str = None, intermediate_path: str = None,
                           combined_path: str = None, exec: str = None) -> Optional[Dict[str, Any]]:
        """Retrieve certificate from the server"""
        if not self.socket:
            return None
        if not self._require_secure_channel():
            return None

        try:
            # Create request message for retrieve
            request_msg = create_request_message("retrieve", {
                "client_id": self.client_id,
                "fqdns": normalize_fqdns(fqdns)
            })
            
            # Send message
            success = send_secure_message(
                self.socket,
                request_msg,
                private_key=self.private_key,
                public_key=self.server_public_key
            )
            
            if not success:
                return None
                
            # Receive response
            response = receive_secure_message(
                self.socket,
                private_key=self.private_key,
                public_key=self.server_public_key
            )
            
            if response:
                if response.get("response_type") == "retrieve":
                    if response.get("success"):
                        # Handle saving files if paths are provided
                        cert_data = response.get("data", {})

                        # If a certificate destination was requested and it
                        # already holds a valid certificate that's as new or
                        # newer than what the server just sent, leave every
                        # destination file (key/cert/intermediate) untouched
                        # and skip --exec entirely, rather than overwrite a
                        # perfectly good certificate with a stale one. This
                        # is what lets a cron job call `retrieve` on a
                        # schedule without needlessly rewriting files or
                        # restarting services when nothing actually changed.
                        #
                        # cert_path is only set by --cert/--all; combined_path
                        # (--combined) is checked too since it also starts
                        # with the leaf certificate (cert first, intermediate
                        # appended after - see below) - x509.load_pem_x509_
                        # certificate() only ever parses the first PEM block,
                        # so it's just as valid a comparison target. Without
                        # this fallback, --combined used on its own (without
                        # --cert/--all) bypassed this check entirely and
                        # always overwrote unconditionally (see fixed-issues.md).
                        comparison_path = cert_path or combined_path
                        if comparison_path and cert_data.get("cert") and \
                                _existing_certificate_is_current(comparison_path, cert_data["cert"]):
                            print(f"Existing certificate at {comparison_path} is already valid and "
                                  f"not older than the retrieved one - not overwriting.")
                            cert_data['certificate_replaced'] = False
                            return response

                        # Save key if path provided
                        if key_path and cert_data.get("key"):
                            try:
                                with open(key_path, 'w') as f:
                                    f.write(cert_data["key"])
                            except Exception as e:
                                print(f"Error saving key to {key_path}: {e}")
                                return None
                        
                        # Save cert if path provided
                        if cert_path and cert_data.get("cert"):
                            try:
                                with open(cert_path, 'w') as f:
                                    f.write(cert_data["cert"])
                            except Exception as e:
                                print(f"Error saving cert to {cert_path}: {e}")
                                return None
                        
                        # Save intermediate if path provided
                        if intermediate_path and cert_data.get("intermediate"):
                            try:
                                with open(intermediate_path, 'w') as f:
                                    f.write(cert_data["intermediate"])
                            except Exception as e:
                                print(f"Error saving intermediate to {intermediate_path}: {e}")
                                return None

                        # Save combined cert+intermediate file if path provided. The
                        # intermediate is appended after the certificate (still written
                        # on its own even without an intermediate available) - this is
                        # the order most servers/tools expect for a "fullchain" file.
                        if combined_path and cert_data.get("cert"):
                            try:
                                combined_content = cert_data["cert"]
                                if cert_data.get("intermediate"):
                                    if not combined_content.endswith("\n"):
                                        combined_content += "\n"
                                    combined_content += cert_data["intermediate"]
                                with open(combined_path, 'w') as f:
                                    f.write(combined_content)
                            except Exception as e:
                                print(f"Error saving combined certificate to {combined_path}: {e}")
                                return None

                        # Execute command if provided
                        if exec:
                            import subprocess
                            try:
                                # Execute the command with the file paths as arguments
                                result = subprocess.run(exec, shell=True, check=True, capture_output=True, text=True)
                                print(f"Command executed successfully: {result.stdout}")
                            except subprocess.CalledProcessError as e:
                                print(f"Command failed with error: {e.stderr}")
                                return None
                            except Exception as e:
                                print(f"Error executing command: {e}")
                                return None

                        cert_data['certificate_replaced'] = True
                        return response
                    else:
                        print(f"Certificate retrieval failed: {response.get('data', {}).get('message', 'Unknown error')}")
                        return response
                else:
                    print(f"Unexpected response type: {response.get('response_type')}")
                    return response
            else:
                return None
                
        except Exception as e:
            print(f"Error retrieving certificate: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def close_connection(self):
        """Close the connection to the server"""
        if self.socket:
            self.socket.close()
            self.socket = None


# Utility functions for client operations
def create_client(client_id: str, private_key_path: str = None, 
                 public_key_path: str = None) -> Client:
    """Create a new client instance"""
    client = Client(client_id, private_key_path, public_key_path)
    
    if not client.setup_keys():
        raise Exception("Failed to setup keys for client")
        
    return client


def connect_client(client: Client, host: str = DEFAULT_SERVER_HOST, 
                  port: int = DEFAULT_SERVER_PORT) -> bool:
    """Connect a client to the server"""
    return client.connect_to_server(host, port)


def register_client(client: Client, config_file_path: str = None) -> bool:
    """Register a client with the server"""
    # Call the register_with_server method which returns True if successful
    success = client.register_with_server(config_file_path)
    
    return success
