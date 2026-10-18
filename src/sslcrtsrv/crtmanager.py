#!/usr/bin/env python3
"""
Certificate Handler for SSL Key Repository
Handles certificate management in the database and client access permissions
"""

import argparse
import logging
import os
import shutil
import sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime

from . import __version__
from .common.constants import DEFAULT_SERVER_CONFIG_FILE
from .common.database import (
    init_database, save_certificate, get_all_certificates, apply_data_dir_from_config,
    resolve_certificate_by_identifier, set_certificate_acme_provider,
    get_active_certificate_assignments, get_requested_certificate_rows,
)
from rich.console import Console
from rich.table import Table

# A quiet audit trail for the state-changing actions below (addlocal/update/
# delete/delete-invalid/set-provider), separate from this file's existing
# print()/rich.Console output. See cltmanager.py's identically-purposed
# logger for the full rationale, including why this uses an explicit name
# rather than logging.getLogger(__name__) - this module can be run directly
# via `python3 -m sslcrtsrv.crtmanager`, under which __name__ becomes
# "__main__" instead.
logger = logging.getLogger("sslcrtsrv.crtmanager")

def validate_pem_file(filepath):
    """
    Validate that a file exists, is readable, and contains valid PEM data
    
    Args:
        filepath (str): Path to the PEM file
        
    Returns:
        bool: True if file is valid PEM format, False otherwise
    """
    try:
        # Check if file exists and is readable
        if not os.path.exists(filepath):
            print(f"Error: File '{filepath}' does not exist")
            return False
            
        if not os.access(filepath, os.R_OK):
            print(f"Error: File '{filepath}' is not readable")
            return False
            
        # Try to read and parse the PEM file
        with open(filepath, 'rb') as f:
            pem_data = f.read()
            
        # Try to load as PEM data
        try:
            # This will raise an exception if it's not valid PEM
            loaded = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
            return True
        except Exception:
            # If that fails, try to load as certificate
            try:
                cert = x509.load_pem_x509_certificate(pem_data, default_backend())
                return True
            except Exception:
                print(f"Error: File '{filepath}' does not contain valid PEM data")
                return False
                
    except Exception as e:
        print(f"Error reading file '{filepath}': {e}")
        return False

def extract_certificate_info(cert_file):
    """
    Extract certificate information from a certificate file
    
    Args:
        cert_file (str): Path to the certificate file
        
    Returns:
        dict: Dictionary containing certificate information
    """
    try:
        with open(cert_file, 'rb') as f:
            cert_data = f.read()
            
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Extract relevant information
        subject = cert.subject
        issuer = cert.issuer
        # Support both old (<42.0.0) and new (>=42.0.0) cryptography library APIs
        if hasattr(cert, 'not_valid_before_utc'):
            not_valid_before = cert.not_valid_before_utc
            not_valid_after = cert.not_valid_after_utc
        else:
            not_valid_before = cert.not_valid_before
            not_valid_after = cert.not_valid_after
        
        # Get the public key
        public_key = cert.public_key()
        
        # Extract FQDNs/domains from Subject Alternative Names or Common Name
        fqdns = []
        
        # Try to get Subject Alternative Names
        try:
            san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_extension.value:
                if isinstance(name, x509.DNSName):
                    fqdns.append(name.value)
        except x509.ExtensionNotFound:
            # If no Subject Alternative Name extension, fall back to Common Name
            try:
                cn = subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                if cn:
                    fqdns.append(cn[0].value)
            except Exception:
                pass
        
        # Convert validity end date to Unix timestamp
        unix_timestamp = int(not_valid_after.timestamp())
        
        # For now, we'll just return basic info - the actual certificate 
        # data will be stored as PEM in the database
        return {
            'subject': str(subject),
            'issuer': str(issuer),
            'not_valid_before': not_valid_before,
            'not_valid_after': not_valid_after,
            'public_key': public_key,
            'fqdns': fqdns,
            'unix_timestamp': unix_timestamp
        }
    except Exception as e:
        print(f"Error extracting certificate info from '{cert_file}': {e}")
        return None

def addlocalcert(key_file, cert_file, intermediate_file=None):
    """
    Add a local certificate to the database
    
    Args:
        key_file (str): Path to the private key file
        cert_file (str): Path to the certificate file  
        intermediate_file (str, optional): Path to the intermediate certificate file
        
    Returns:
        bool: True if successful, False otherwise
    """
    print(f"Adding certificate from files:")
    print(f"  Private Key: {key_file}")
    print(f"  Certificate: {cert_file}")
    if intermediate_file:
        print(f"  Intermediate: {intermediate_file}")
    
    # Validate all files exist and are readable with valid PEM format
    if not validate_pem_file(key_file):
        return False
        
    if not validate_pem_file(cert_file):
        return False
        
    if intermediate_file and not validate_pem_file(intermediate_file):
        return False
    
    # Read the contents of the files
    try:
        with open(key_file, 'rb') as f:
            private_key_pem = f.read()
            
        with open(cert_file, 'rb') as f:
            cert_pem = f.read()
            
        intermediates_pem = None
        if intermediate_file:
            with open(intermediate_file, 'rb') as f:
                intermediates_pem = f.read()
                
    except Exception as e:
        print(f"Error reading certificate files: {e}")
        return False
    
    # Verify that the private key and certificate match
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
        
        # Load private key
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        
        # Load certificate
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        
        # Get the public key from the certificate
        cert_public_key = cert.public_key()
        
        # Extract the public key from the private key for comparison
        if isinstance(private_key, rsa.RSAPrivateKey):
            private_public_key = private_key.public_key()
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            private_public_key = private_key.public_key()
        elif isinstance(private_key, dsa.DSAPrivateKey):
            private_public_key = private_key.public_key()
        else:
            print("Error: Unsupported private key type")
            return False
            
        # Compare public keys using a more robust method
        # For RSA and DSA keys, we can compare the numbers directly
        # For EC keys, we need to compare the points
        try:
            # Try direct comparison first (works for most cases)
            if private_public_key == cert_public_key:
                pass  # Keys match
            else:
                # If that fails, check by comparing parameters
                if hasattr(private_public_key, 'public_numbers') and hasattr(cert_public_key, 'public_numbers'):
                    if private_public_key.public_numbers() == cert_public_key.public_numbers():
                        pass  # Keys match
                    else:
                        print("Error: Private key and certificate do not match")
                        return False
                else:
                    print("Error: Private key and certificate do not match")
                    return False
        except Exception:
            print("Error: Private key and certificate do not match")
            return False
            
    except Exception as e:
        print(f"Error verifying key-certificate match: {e}")
        return False
    
    # Extract information from the certificate
    cert_info = extract_certificate_info(cert_file)
    if not cert_info:
        print("Could not extract certificate information")
        return False
        
    # Use the extracted FQDNs for the database key
    # Sort FQDNs in alphabetical order
    sorted_fqdns = sorted(cert_info['fqdns']) if cert_info['fqdns'] else []
    if not sorted_fqdns:
        print("Error: No FQDNs found in certificate. Certificate will not be added to database.")
        return False
    fqdns = ','.join(sorted_fqdns)
    
    # Check if a certificate with the same FQDNs and validity already exists
    from .common.database import get_certificate
    existing_cert = get_certificate(fqdns)
    if existing_cert:
        # Access validity_end_date as an attribute of the SQLAlchemy object
        existing_date = existing_cert.validity_end_date
        new_date = cert_info['not_valid_after']
        
        # Handle the case where date might be stored as datetime or string
        if isinstance(existing_date, str):
            # Parse the string to datetime for comparison
            import datetime
            try:
                existing_date = datetime.datetime.fromisoformat(existing_date.replace('Z', '+00:00'))
            except:
                existing_date = existing_date
        elif hasattr(existing_date, 'astimezone'):
            # Convert timezone-aware datetime to naive for comparison
            existing_date = existing_date.replace(tzinfo=None)
        
        if existing_date == new_date:
            print(f"Warning: A certificate with the same FQDNs ({fqdns}) and validity date already exists in the database.")
            print("No update was made to the database.")
            return True  # Return True as it's not an error, just a warning
        
        # If validity dates differ, check if existing cert has longer validity
        # Only skip the update if existing validity is longer than new validity
        if isinstance(existing_date, datetime.datetime):
            if existing_date > new_date:
                # Existing certificate has longer validity - don't replace it
                print(f"Warning: Existing certificate with FQDNs ({fqdns}) is valid until {existing_date} which is later than the new certificate's validity until {new_date}.")
                print("The existing certificate will be kept as it has longer validity period.")
                return True
        elif isinstance(existing_date, str) and isinstance(new_date, datetime.datetime):
            # If existing is a string and new is datetime, compare as strings
            # This is a fallback case - should not normally happen
            pass  # Fall through to allow the update
    
    # Encrypt the private key before it ever touches the database
    from .common.db_crypto import encrypt_for_storage, DbKeyMissing
    try:
        encrypted_private_key = encrypt_for_storage(private_key_pem.decode('utf-8'))
    except DbKeyMissing as e:
        print(f"Error: {e}")
        return False

    # Save to database (this is a simplified version)
    # The actual certificate data will be stored in PEM format in the database
    success = save_certificate(
        fqdns=fqdns,
        public_key=cert_pem.decode('utf-8'),  # Store as string since it's PEM
        private_key=encrypted_private_key,  # Encrypted at rest - see common/db_crypto.py
        intermediates=intermediates_pem.decode('utf-8') if intermediates_pem else None,
        validity_end_date=cert_info['not_valid_after']
    )
    
    if success:
        print("Certificate successfully added to database")
        print(f"Extracted FQDNs: {fqdns}")
        print(f"Validity until (Unix timestamp): {cert_info['unix_timestamp']}")
        return True
    else:
        print("Failed to add certificate to database")
        return False

def set_certificate_provider(identifier, provider):
    """Change which ACME service (or 'manual') a certificate uses"""
    from .common.constants import ACME_PROVIDERS, MANUAL_ACME_PROVIDER

    cert = resolve_certificate_by_identifier(identifier)
    if not cert:
        print(f"No certificate found with ID/FQDN: {identifier}")
        return False

    if provider != MANUAL_ACME_PROVIDER and provider not in ACME_PROVIDERS:
        print(f"Warning: '{provider}' is not a recognized ACME provider name "
              f"({', '.join(sorted(ACME_PROVIDERS))}, {MANUAL_ACME_PROVIDER}) - "
              f"treating it as a raw ACME directory URL for acme.sh's --server option.")

    if set_certificate_acme_provider(cert.fqdns, provider):
        print(f"Certificate {cert.fqdns} now uses ACME provider '{provider}'")
        return True
    return False

def _format_date(value):
    """Format a validity/last-update value as YYYY-MM-DD, tolerating either a
    datetime object or an ISO string (the DB has historically stored both)."""
    if not value:
        return "N/A"
    if hasattr(value, 'strftime'):
        return value.strftime('%Y-%m-%d')
    try:
        if isinstance(value, str):
            return datetime.datetime.fromisoformat(value.replace('Z', '+00:00')).strftime('%Y-%m-%d')
        return str(value)
    except Exception:
        return str(value)

def get_certificate_rows(show_clients=False):
    """Pure data form of the per-certificate rows list_certificates() renders:
    one dict per issued certificate, with display-ready strings plus the
    underlying flags (is_expired/is_near_expiry) so callers - the CLI's own
    table builder, or a future UI - can style rows without re-deriving the
    validity math.
    """
    certificates = get_all_certificates()

    fqdn_clients = get_active_certificate_assignments() if show_clients else {}

    rows = []
    for cert in certificates:
        fqdns = cert.fqdns
        validity_end_date = cert.validity_end_date
        last_update = cert.last_update
        is_expired = not check_certificate_validity(cert)

        is_near_expiry = False
        if not is_expired and hasattr(validity_end_date, 'tzinfo'):
            end_dt = validity_end_date
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=datetime.timezone.utc)
            days_remaining = (end_dt - datetime.datetime.now(datetime.timezone.utc)).days
            is_near_expiry = days_remaining < 21

        provider_str = cert.acme_provider or "N/A"
        if cert.is_staging:
            provider_str += " (staging)"

        rows.append({
            'id': cert.id,
            'fqdns': fqdns,
            'fqdns_display': fqdns.replace(',', ' ') if fqdns else "",
            'validity_end_date': validity_end_date,
            'validity_end_date_str': _format_date(validity_end_date),
            'last_update': last_update,
            'last_update_str': _format_date(last_update),
            'provider_str': provider_str,
            'is_expired': is_expired,
            'is_near_expiry': is_near_expiry,
            'clients': fqdn_clients.get(fqdns, []) if show_clients else None,
        })

    return rows

def list_certificates(show_clients=False):
    """List all certificates in the database with their FQDN, validity date, and last update"""
    rows = get_certificate_rows(show_clients=show_clients)

    if not rows:
        console = Console()
        console.print("No certificates found in the database.", style="yellow")
        return

    console = Console()

    if show_clients:
        table = Table(title="Certificate List with Client Access", show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim")
        table.add_column("FQDN", no_wrap=False)
        table.add_column("Valid until")
        table.add_column("Last Update")
        table.add_column("Provider")
        table.add_column("Clients")
    else:
        table = Table(title="Certificate List", show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim")
        table.add_column("FQDN", no_wrap=False)
        table.add_column("Valid until")
        table.add_column("Last Update")
        table.add_column("Provider")

    for row in rows:
        id_display = str(row['id']) if row['id'] is not None else ""
        validity_str = row['validity_end_date_str']
        # Highlight certificates expiring within 3 weeks (expired ones already
        # get the whole-row red styling below, so skip those here)
        if row['is_near_expiry']:
            validity_str = f"[yellow]{validity_str}[/yellow]"

        if show_clients:
            client_list = ", ".join(row['clients']) if row['clients'] else "None"
            if row['is_expired']:
                table.add_row(id_display, row['fqdns_display'], validity_str, row['last_update_str'], row['provider_str'], client_list, style="red")
            else:
                table.add_row(id_display, row['fqdns_display'], validity_str, row['last_update_str'], row['provider_str'], client_list)
        else:
            if row['is_expired']:
                table.add_row(id_display, row['fqdns_display'], validity_str, row['last_update_str'], row['provider_str'], style="red")
            else:
                table.add_row(id_display, row['fqdns_display'], validity_str, row['last_update_str'], row['provider_str'])

    # Also add requested certificates to the table if --clients is used
    requested_rows = get_requested_certificate_rows() if show_clients else []

    if requested_rows:
        # Group requested certificates by FQDN to collect all client IDs per FQDN
        requested_by_fqdn = {}
        for row in requested_rows:
            requested_by_fqdn.setdefault(row['fqdns'], []).append(row['client_id'])

        req_table = Table(title="Requested Certificates (Not Yet Issued)", show_header=True, header_style="bold blue")
        req_table.add_column("Client ID")
        req_table.add_column("FQDNs")
        req_table.add_column("Status")
        req_table.add_column("Valid Until")

        for row in requested_rows:
            fqdns_display = row['fqdns'].replace(',', ' ') if row['fqdns'] else ""
            client_ids = requested_by_fqdn.get(row['fqdns'], [])
            client_id_display = ", ".join(client_ids) if client_ids else ""
            req_table.add_row(client_id_display, fqdns_display, row['status_text'], str(row['valid_until']))

        console.print(req_table)

    console.print(table)
def check_certificate_validity(cert):
    """
    Check if a certificate is still valid (not expired)
    
    Args:
        cert (Certificate): Certificate SQLAlchemy object from database
        
    Returns:
        bool: True if certificate is still valid, False if expired
    """
    import datetime
    
    # Access the validity_end_date attribute directly from the Certificate object
    validity_end_date = cert.validity_end_date
    
    # Handle different date formats - could be datetime object or string
    if validity_end_date:
        # If it's a string, try to parse it
        if isinstance(validity_end_date, str):
            try:
                # Try common date formats
                date_obj = datetime.datetime.fromisoformat(validity_end_date.replace('Z', '+00:00'))
            except ValueError:
                # If parsing fails, return invalid
                return False
        else:
            # Assume it's already a datetime object
            date_obj = validity_end_date
            
        # Compare with current time
        now = datetime.datetime.now(datetime.timezone.utc)
        
        # Handle timezone-aware vs naive datetime comparison
        if hasattr(date_obj, 'tzinfo') and date_obj.tzinfo is not None:
            # Date is timezone-aware
            return date_obj > now
        else:
            # Date is naive, assume it's UTC
            # Convert to timezone-aware for comparison
            date_obj_aware = date_obj.replace(tzinfo=datetime.timezone.utc)
            return date_obj_aware > now
    
    # If no validity end date, consider it invalid
    return False

def get_invalid_certificates():
    """Pure filter: all Certificate rows whose validity has already expired."""
    certificates = get_all_certificates()
    return [cert for cert in certificates if not check_certificate_validity(cert)]

def list_invalid_certificates():
    """List all certificates that are not valid anymore (expired)"""
    certificates = get_all_certificates()

    if not certificates:
        console = Console()
        console.print("No certificates found in the database.", style="yellow")
        return []

    invalid_certs = get_invalid_certificates()

    if not invalid_certs:
        console = Console()
        console.print("All certificates are still valid.", style="green")
        return []

    console = Console()
    table = Table(title="Invalid Certificates (Expired)", show_header=True, header_style="bold red")
    table.add_column("ID", style="dim")
    table.add_column("FQDN")
    table.add_column("Valid until")
    table.add_column("Last Update")

    for cert in invalid_certs:
        table.add_row(str(cert.id), cert.fqdns, _format_date(cert.validity_end_date), _format_date(cert.last_update))

    console.print(table)
    return invalid_certs
def delete_certificate_and_directory(fqdns: str) -> bool:
    """Delete a certificate's DB row, then clean up its acme.sh working
    directory on disk if one exists.

    request_new_certificate()/renew_certificate() (crtrequest.py) give every
    certificate its own, isolated acme.sh --home directory -
    cert_home_dir/cert-<id>, nothing else reads or writes it - so once
    the DB row is gone that directory is unconditionally orphaned. Left
    behind, it silently accumulates one full acme.sh account state
    directory (private account key included) per deleted certificate
    forever; there's no other cleanup path for it.

    The id has to be captured *before* delete_certificate() removes the
    row it depends on. A manually-added certificate (crtmanager.py addlocal,
    MANUAL_ACME_PROVIDER) never had a directory created for it in the first
    place, and cert_home_dir may not be configured at all (server not fully
    set up yet) - both are treated as "nothing to clean up", not an error.
    """
    from .common.database import delete_certificate, get_certificate_id
    from .crtrequest import load_server_config, certificate_directory_path

    cert_id = get_certificate_id(fqdns)
    if not delete_certificate(fqdns):
        return False

    if cert_id is not None:
        cert_home_dir = load_server_config().get('cert_home_dir')
        if cert_home_dir:
            cert_dir = certificate_directory_path(cert_home_dir, cert_id)
            if os.path.isdir(cert_dir):
                try:
                    shutil.rmtree(cert_dir)
                    print(f"Removed acme.sh directory {cert_dir} for deleted certificate {fqdns}")
                except OSError as e:
                    print(f"Warning: deleted certificate {fqdns} from the database, but could not "
                          f"remove its acme.sh directory {cert_dir}: {e}")
    return True

def delete_invalid_certificates():
    """Delete all invalid (expired) certificates after user confirmation"""
    # List invalid certificates
    invalid_certs = list_invalid_certificates()
    
    if not invalid_certs:
        print("No invalid certificates to delete.")
        return False
    
    # Ask for confirmation
    confirm = input(f"\nDo you want to delete {len(invalid_certs)} invalid certificate(s)? (yes/no): ")
    
    if confirm.lower() in ['yes', 'y']:
        deleted_count = 0
        for cert in invalid_certs:
            success = delete_certificate_and_directory(cert.fqdns)
            if success:
                print(f"Deleted certificate with FQDNs: {cert.fqdns}")
                deleted_count += 1
            else:
                print(f"Failed to delete certificate with FQDNs: {cert.fqdns}")
        
        logger.info("delete-invalid: deleted %d of %d certificates", deleted_count, len(invalid_certs))
        print(f"\nSuccessfully deleted {deleted_count} out of {len(invalid_certs)} invalid certificates.")
        return True
    else:
        print("Deletion cancelled.")
        return False

def list_requested_certificates():
    """List all requested certificates that have not been issued yet"""
    rows = get_requested_certificate_rows()

    if not rows:
        console = Console()
        console.print("No requested certificates found.", style="yellow")
        return

    console = Console()
    table = Table(title="Requested Certificates (Not Yet Issued)", show_header=True, header_style="bold blue")
    table.add_column("Client ID")
    table.add_column("FQDNs")
    table.add_column("Status")
    table.add_column("Valid Until")

    for row in rows:
        table.add_row(row['client_id'], row['fqdns'], row['status_text'], row['valid_until'])

    console.print(table)

def report_stale_certificate_downloads(days=21):
    """Per-client report of active certificate assignments whose last
    downloaded copy is at or near expiry, already superseded by a renewal,
    or never downloaded at all - see common.database.get_stale_certificate_downloads()."""
    from .common.database import get_stale_certificate_downloads
    rows = get_stale_certificate_downloads(days=days)

    console = Console()
    if not rows:
        console.print(f"No stale or never-downloaded certificates found (within {days} day(s)).", style="green")
        return rows

    table = Table(title=f"Stale Certificate Downloads (within {days} days)",
                  show_header=True, header_style="bold red")
    table.add_column("Client ID", style="cyan")
    table.add_column("FQDNs", style="green")
    table.add_column("Downloaded On")
    table.add_column("Downloaded Cert Expires")
    table.add_column("Current Cert Expires")

    last_client = None
    for row in rows:
        client_display = row['client_id'] if row['client_id'] != last_client else ""
        downloaded_on = _format_date(row['last_download_at']) if row['last_download_at'] else "Never"
        downloaded_expiry = _format_date(row['downloaded_validity_end_date']) if row['downloaded_validity_end_date'] else "N/A"
        table.add_row(client_display, row['fqdns'], downloaded_on, downloaded_expiry,
                      _format_date(row['current_validity_end_date']))
        last_client = row['client_id']

    console.print(table)
    return rows

def update_certificate(key_file, cert_file, intermediate_file=None):
    """
    Update a certificate in the database
    
    Args:
        key_file (str): Path to the private key file
        cert_file (str): Path to the certificate file  
        intermediate_file (str, optional): Path to the intermediate certificate file
        
    Returns:
        bool: True if successful, False otherwise
    """
    print(f"Updating certificate from files:")
    print(f"  Private Key: {key_file}")
    print(f"  Certificate: {cert_file}")
    if intermediate_file:
        print(f"  Intermediate: {intermediate_file}")
    
    # Validate all files exist and are readable with valid PEM format
    if not validate_pem_file(key_file):
        return False
        
    if not validate_pem_file(cert_file):
        return False
        
    if intermediate_file and not validate_pem_file(intermediate_file):
        return False
    
    # Read the contents of the files
    try:
        with open(key_file, 'rb') as f:
            private_key_pem = f.read()
            
        with open(cert_file, 'rb') as f:
            cert_pem = f.read()
            
        intermediates_pem = None
        if intermediate_file:
            with open(intermediate_file, 'rb') as f:
                intermediates_pem = f.read()
                
    except Exception as e:
        print(f"Error reading certificate files: {e}")
        return False
    
    # Verify that the private key and certificate match
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
        
        # Load private key
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        
        # Load certificate
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        
        # Get the public key from the certificate
        cert_public_key = cert.public_key()
        
        # Extract the public key from the private key for comparison
        if isinstance(private_key, rsa.RSAPrivateKey):
            private_public_key = private_key.public_key()
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            private_public_key = private_key.public_key()
        elif isinstance(private_key, dsa.DSAPrivateKey):
            private_public_key = private_key.public_key()
        else:
            print("Error: Unsupported private key type")
            return False
            
        # Compare public keys using a more robust method
        try:
            # Try direct comparison first (works for most cases)
            if private_public_key == cert_public_key:
                pass  # Keys match
            else:
                # If that fails, check by comparing parameters
                if hasattr(private_public_key, 'public_numbers') and hasattr(cert_public_key, 'public_numbers'):
                    if private_public_key.public_numbers() == cert_public_key.public_numbers():
                        pass  # Keys match
                    else:
                        print("Error: Private key and certificate do not match")
                        return False
                else:
                    print("Error: Private key and certificate do not match")
                    return False
        except Exception:
            print("Error: Private key and certificate do not match")
            return False
            
    except Exception as e:
        print(f"Error verifying key-certificate match: {e}")
        return False
    
    # Extract information from the certificate
    cert_info = extract_certificate_info(cert_file)
    if not cert_info:
        print("Could not extract certificate information")
        return False
        
    # Use the extracted FQDNs for the database key
    # Sort FQDNs in alphabetical order
    sorted_fqdns = sorted(cert_info['fqdns']) if cert_info['fqdns'] else []
    if not sorted_fqdns:
        print("Error: No FQDNs found in certificate. Certificate will not be added to database.")
        return False
    fqdns = ','.join(sorted_fqdns)
    
    # Check if a certificate with the same FQDNs exists - this is what we're updating
    from .common.database import get_certificate
    existing_cert = get_certificate(fqdns)
    if not existing_cert:
        print(f"Warning: No existing certificate found with FQDNs ({fqdns}). This will be treated as an add operation.")
        # In this case, we'll still proceed to add it as a new certificate
        return addlocalcert(key_file, cert_file, intermediate_file)
    
    # Update the existing certificate in database
    from .common.database import update_certificate

    # Encrypt the private key before it ever touches the database
    from .common.db_crypto import encrypt_for_storage, DbKeyMissing
    try:
        encrypted_private_key = encrypt_for_storage(private_key_pem.decode('utf-8'))
    except DbKeyMissing as e:
        print(f"Error: {e}")
        return False

    success = update_certificate(
        fqdns=fqdns,
        public_key=cert_pem.decode('utf-8'),  # Store as string since it's PEM
        private_key=encrypted_private_key,  # Encrypted at rest - see common/db_crypto.py
        intermediates=intermediates_pem.decode('utf-8') if intermediates_pem else None,
        validity_end_date=cert_info['not_valid_after']
    )

    if success:
        # database.update_certificate() never touches acme_provider (it's also used by
        # crtrequest.py's ACME path, which must never change it) - force it to 'manual'
        # here since this is a manual file import, even if the row was previously
        # ACME-managed (e.g. an admin taking over a domain from crtrequest.py by hand).
        from .common.constants import MANUAL_ACME_PROVIDER
        set_certificate_acme_provider(fqdns, MANUAL_ACME_PROVIDER)
        print("Certificate successfully updated in database")
        print(f"Extracted FQDNs: {fqdns}")
        print(f"Validity until (Unix timestamp): {cert_info['unix_timestamp']}")
        return True
    else:
        print("Failed to update certificate in database")
        return False

def migrate_encrypt_existing_keys(dry_run=False):
    """One-time migration: encrypt any legacy plaintext Certificate.private_key rows.

    Safe to re-run - already-encrypted and empty/placeholder rows are skipped.
    """
    from .common.db_crypto import encrypt_for_storage, is_encrypted, DbKeyMissing
    from .common.database import get_db_session, Certificate

    session = get_db_session()
    try:
        certs = session.query(Certificate).all()
        to_migrate, already_done, empty = [], 0, 0

        for cert in certs:
            pk = cert.private_key
            if not pk:
                empty += 1
            elif is_encrypted(pk):
                already_done += 1
            else:
                to_migrate.append(cert)

        print(f"Found {len(certs)} certificate row(s): "
              f"{len(to_migrate)} plaintext, {already_done} already encrypted, {empty} empty/placeholder.")

        if not to_migrate:
            print("Nothing to migrate.")
            return True

        if dry_run:
            for cert in to_migrate:
                print(f"[dry-run] would encrypt private key for {cert.fqdns}")
            return True

        for cert in to_migrate:
            try:
                cert.private_key = encrypt_for_storage(cert.private_key)
                print(f"Encrypted private key for {cert.fqdns}")
            except DbKeyMissing as e:
                print(f"Error: {e}")
                session.rollback()
                return False

        session.commit()
        print(f"Migration complete: {len(to_migrate)} row(s) encrypted.")
        return True
    except Exception as e:
        print(f"Error during migration: {e}")
        session.rollback()
        return False
    finally:
        session.close()

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description='Add local certificate to the SSL Key Repository')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all certificates in the database')
    list_parser.add_argument('--requested', action='store_true', help='Show only requested certificates that have not been issued yet')
    list_parser.add_argument('--clients', action='store_true', help='Show clients that have access to each certificate')
    
    # Add local certificate command
    add_parser = subparsers.add_parser('addlocal', help='Add a local certificate to the database')
    add_parser.add_argument('key_file', help='Path to the private key file (PEM format)')
    add_parser.add_argument('cert_file', help='Path to the certificate file (PEM format)')
    add_parser.add_argument('intermediate_file', nargs='?', help='Path to the intermediate certificate file (PEM format, optional)')
    
    # Update local certificate command
    update_parser = subparsers.add_parser('update', help='Update a local certificate in the database')
    update_parser.add_argument('key_file', help='Path to the private key file (PEM format)')
    update_parser.add_argument('cert_file', help='Path to the certificate file (PEM format)')
    update_parser.add_argument('intermediate_file', nargs='?', help='Path to the intermediate certificate file (PEM format, optional)')

    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete certificate from the database')
    delete_parser.add_argument('identifier', help='FQDNs or ID of the certificate to delete')

    # Delete invalid command
    delete_invalid_parser = subparsers.add_parser('delete-invalid', help='List and delete invalid (expired) certificates')

    # Warn about stale client downloads command
    warn_stale_parser = subparsers.add_parser('warn-stale-downloads',
        help='Report clients still holding a downloaded certificate that is expiring soon, '
             'already renewed, or never downloaded at all')
    warn_stale_parser.add_argument('--days', type=int, default=21,
        help='Flag downloads whose snapshotted expiry is within this many days (default: 21)')

    # Set ACME provider command
    from .common.constants import ACME_PROVIDERS, MANUAL_ACME_PROVIDER
    set_provider_parser = subparsers.add_parser('set-provider',
        help='Change which ACME service a certificate uses')
    set_provider_parser.add_argument('identifier', help='FQDNs or ID of the certificate')
    set_provider_parser.add_argument('provider',
        help=f"ACME provider ({', '.join(sorted(ACME_PROVIDERS))}), '{MANUAL_ACME_PROVIDER}' to exclude "
             f"this certificate from crtrequest.py's automation entirely, or a raw ACME directory URL")

    # Init DB encryption key command
    init_key_parser = subparsers.add_parser('init-db-key',
        help='Generate the dedicated keypair used to encrypt certificate private keys at rest (one-time setup)')
    init_key_parser.add_argument('--overwrite', action='store_true',
        help='Overwrite an existing keypair (DANGEROUS: orphans already-encrypted rows unless re-encrypted first)')

    # Migrate existing plaintext keys command
    migrate_parser = subparsers.add_parser('migrate-encrypt-keys',
        help='One-time: encrypt any legacy plaintext private keys already stored in the database')
    migrate_parser.add_argument('--dry-run', action='store_true',
        help='Report what would be migrated without writing changes')

    args = parser.parse_args()

    # Relocate the database under server_config.json's data_dir first, if
    # one is configured (see common/database.py's relocate_under_data_dir())
    apply_data_dir_from_config()

    from .common.logging_utils import setup_tool_logging_from_file
    setup_tool_logging_from_file(DEFAULT_SERVER_CONFIG_FILE, "crtmanager")

    # Initialize database
    from .common.database import SchemaOutOfDate
    try:
        init_database()
    except SchemaOutOfDate as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Handle commands
    if args.command == 'list':
        if args.requested:
            list_requested_certificates()
        elif args.clients:
            list_certificates(show_clients=True)
        else:
            list_certificates()
        sys.exit(0)
    elif args.command == 'addlocal':
        success = addlocalcert(args.key_file, args.cert_file, args.intermediate_file)
        (logger.info if success else logger.warning)("addlocal %s: %s", args.cert_file,
                                                       "ok" if success else "failed")
        if success:
            print("Certificate added successfully")
            sys.exit(0)
        else:
            print("Failed to add certificate")
            sys.exit(1)
    elif args.command == 'update':
        success = update_certificate(args.key_file, args.cert_file, args.intermediate_file)
        (logger.info if success else logger.warning)("update %s: %s", args.cert_file,
                                                       "ok" if success else "failed")
        if success:
            print("Certificate updated successfully")
            sys.exit(0)
        else:
            print("Failed to update certificate")
            sys.exit(1)
    elif args.command == 'delete':
        # Get the certificate information before deletion for confirmation
        cert = resolve_certificate_by_identifier(args.identifier)

        if not cert:
            print(f"No certificate found with ID/FQDN: {args.identifier}")
            sys.exit(1)
        
        # Confirm deletion
        print(f"Certificate to delete:")
        print(f"  FQDNs: {cert.fqdns}")
        print(f"  Validity End Date: {cert.validity_end_date}")
        confirm = input("Are you sure you want to delete this certificate? (yes/no): ")
        
        if confirm.lower() in ['yes', 'y']:
            success = delete_certificate_and_directory(cert.fqdns)
            (logger.info if success else logger.warning)("delete %s: %s", cert.fqdns,
                                                           "ok" if success else "failed")
            if success:
                print("Certificate deleted successfully")
                sys.exit(0)
            else:
                print("Failed to delete certificate")
                sys.exit(1)
        else:
            print("Deletion cancelled.")
            sys.exit(0)
    elif args.command == 'delete-invalid':
        delete_invalid_certificates()
        sys.exit(0)
    elif args.command == 'warn-stale-downloads':
        report_stale_certificate_downloads(days=args.days)
        sys.exit(0)
    elif args.command == 'set-provider':
        success = set_certificate_provider(args.identifier, args.provider)
        (logger.info if success else logger.warning)("set-provider %s -> %s: %s", args.identifier,
                                                       args.provider, "ok" if success else "failed")
        sys.exit(0 if success else 1)
    elif args.command == 'init-db-key':
        from .common.db_crypto import generate_db_keypair
        from .common.constants import DB_ENCRYPTION_PRIVATE_KEY_FILE, DB_ENCRYPTION_PUBLIC_KEY_FILE
        try:
            generate_db_keypair(overwrite=args.overwrite)
            print("DB encryption keypair generated:")
            print(f"  Private key (keep only where server.py runs, mode 0600): {DB_ENCRYPTION_PRIVATE_KEY_FILE}")
            print(f"  Public key (safe to copy anywhere crtmanager.py/crtrequest.py run): {DB_ENCRYPTION_PUBLIC_KEY_FILE}")
            sys.exit(0)
        except FileExistsError as e:
            print(f"Error: {e}")
            sys.exit(1)
    elif args.command == 'migrate-encrypt-keys':
        success = migrate_encrypt_existing_keys(dry_run=args.dry_run)
        sys.exit(0 if success else 1)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
