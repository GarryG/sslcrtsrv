# System utilities for the SSL Key Repository application

import json
import socket
import os


def ensure_secure_dir(dir_path: str, mode: int = 0o700) -> None:
    """Create a directory (if missing) and restrict its permissions.

    Defaults to owner-only access. server.py/common/database.py/db_crypto.py
    pass mode=SHARED_DIR_MODE (see common/constants.py) for the handful of
    directories web_admin's PHP process - which runs as a different OS user -
    needs to read/write; every other caller (notably client.py's own config
    directory, which must never be group-readable) keeps this strict default.

    Called on every startup (this is where server.py's database directory
    gets (re-)secured), so this is deliberately cheap and non-destructive
    when there's nothing to do: skips the chmod entirely once the directory
    already has the requested mode, rather than reasserting it every time
    unconditionally. That mattered in practice - chmod(2) requires owning
    the target (or being root), and re-attempting it on every single
    invocation, even when the mode already matched, turned a one-time
    ownership mismatch (e.g. a directory pre-created by a package's postinst
    before this process's own user actually owned it) into a permanent
    crash loop instead of a one-time, correctable warning.
    """
    os.makedirs(dir_path, mode=mode, exist_ok=True)
    current_mode = os.stat(dir_path).st_mode & 0o777
    if current_mode == mode:
        return
    try:
        os.chmod(dir_path, mode)  # mode above is subject to umask, so re-assert it
    except PermissionError:
        print(f"Warning: could not set permissions {oct(mode)} on {dir_path} (currently "
              f"{oct(current_mode)}, and not owned by this process) - leaving it as-is.")


def write_secure_json(file_path: str, data: dict, indent: int = 2, mode: int = 0o600) -> None:
    """Write JSON data to a file and restrict its permissions.

    Defaults to owner-only read/write. See ensure_secure_dir()'s docstring -
    the same mode=SHARED_FILE_MODE opt-in applies here, for the same reason.
    """
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=indent)
    os.chmod(file_path, mode)


def get_fqdn() -> str:
    """Get the system's Fully Qualified Domain Name"""
    try:
        # Try to get FQDN using socket.getfqdn()
        fqdn = socket.getfqdn()
        
        # If we got a result and it contains a dot, assume it's FQDN
        if fqdn and '.' in fqdn:
            return fqdn
            
        # If not, try to get hostname and resolve it
        hostname = socket.gethostname()
        if hostname:
            # Try to resolve the hostname to get FQDN
            fqdn = socket.getfqdn(hostname)
            if fqdn and '.' in fqdn:
                return fqdn
                
    except Exception:
        pass
    
    # If all else fails, return the hostname
    try:
        return socket.gethostname()
    except Exception:
        # If we can't get hostname either, return a default
        return "unknown-client"


def get_system_info() -> dict:
    """Get comprehensive system information"""
    info = {
        "fqdn": get_fqdn(),
        "hostname": socket.gethostname(),
        "platform": os.name,
        "machine": os.uname().machine if hasattr(os, 'uname') else "unknown"
    }
    return info
