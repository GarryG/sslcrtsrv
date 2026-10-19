"""JOSE (JWK/JWS/RFC 7638 thumbprint) helpers for the ACME server, plus CSR
parsing/validation. See ACME_SERVER_DESIGN.md for the full protocol design
this supports.

Every other ACME server module goes through this one rather than importing
`josepy` directly - a single choke point for that dependency (see the
design doc's §8.4/§11 note about a possible future swap if josepy's Debian
packaging turns out to be a problem), and the natural home for CSR handling
(josepy has no CSR support at all) since it's used alongside JOSE handling
throughout `finalize` (§5.10).

Deliberately does NOT use josepy's own `Header`/`Signature`/`JWS.sign()`
machinery for parsing an incoming request's protected header: josepy's
`Header` class supports only registered JOSE header parameters (RFC 7515
§4.1) and silently drops private ones - ACME's own `nonce`/`url` header
parameters (RFC 8555 §6.2/§6.4) included - rather than raising or exposing
them. Structural JWS parsing/signature verification still goes through
josepy's `JWS`/`JWK` classes (that part works correctly for any header
shape), but the protected header's own JSON is decoded directly here so
`nonce`/`url`/`alg`/`jwk`/`kid` are all available to the caller
(`verify_acme_jws()` in `acme_server_utils.py`) without going through
josepy's stricter, registered-fields-only Header model.
"""

try:
    import josepy as jose
except ImportError as e:
    raise ImportError(
        "The ACME server requires the 'josepy' package. Install the 'acme' "
        "extra (pip install sslcrtsrv[acme]) or the python3-josepy Debian "
        "package."
    ) from e

import hashlib
import json

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class InvalidCsr(Exception):
    """Raised by parse_and_validate_csr() on a malformed CSR or one whose
    own self-signature doesn't verify - callers (acme_server_utils.py's
    finalize handler) catch this to produce a 400 malformed response
    (ACME_SERVER_DESIGN.md §5.10)."""
    pass


# RFC 8555 doesn't mandate a specific alg set. This matches what real-world
# CAs (Let's Encrypt/Boulder) and mainstream ACME clients actually use.
# 'none' and any HMAC-based alg are never included - an explicit allowlist,
# checked before any JWS/JWK object is even constructed, is what actually
# prevents an algorithm-confusion attack (e.g. a client asserting alg:HS256
# and using some known public value as the "secret"), not merely trusting
# whatever josepy's own jwa.JWASignature.from_json() happens to recognize.
ALLOWED_JWS_ALGS = ('RS256', 'ES256', 'ES384')


# --- JWK / JWS -------------------------------------------------------------

def json_to_jwk(json_str):
    """Parse a JSON JWK string into a josepy JWK object - auto-dispatches to
    JWKRSA/JWKEC by the JWK's own 'kty' field. Raises (josepy's own
    josepy.errors.Error subclasses, or plain ValueError/KeyError/
    json.JSONDecodeError for malformed JSON/missing fields) on invalid
    input - callers should catch broadly and turn it into a 400 malformed
    response."""
    return jose.JWK.json_loads(json_str)


def jwk_to_json(jwk):
    """Canonical JSON serialization of a JWK - the exact form stored in
    Client.public_key for client_kind='acme' rows (§4.1)."""
    return jwk.json_dumps()


def compute_thumbprint(jwk):
    """RFC 7638 JWK thumbprint, base64url-encoded (no padding) - the
    canonical account-key identity used for client_id (f"acme:{thumbprint}")
    and Client.acme_key_thumbprint (§4.1), and for cltmanager.py
    acme_confirm's out-of-band comparison display (§7.1)."""
    return jose.b64.b64encode(jwk.thumbprint()).decode('ascii')


def compute_thumbprint_hex(jwk):
    """Same RFC 7638 thumbprint as compute_thumbprint(), hex-encoded instead
    of base64url - only needed for common/fingerprint_words.py's word-list
    rendering, which expects hex (matching the custom protocol's own
    SHA-256-hex fingerprint convention) rather than ACME's own base64url
    convention used everywhere else."""
    return jwk.thumbprint().hex()


def decode_b64url(b64url_str):
    """Base64url-decode one JWS component (protected header or payload) to
    raw bytes. A POST-as-GET payload decodes to b'' (RFC 8555 §6.3's
    empty-payload convention) - checking for that is the caller's job."""
    return jose.b64.b64decode(b64url_str)


def decode_protected_header(protected_b64url):
    """Base64url-decode and JSON-parse a JWS's protected header directly -
    see the module docstring for why this bypasses josepy's own Header
    class. Raises ValueError/json.JSONDecodeError on malformed input."""
    return json.loads(decode_b64url(protected_b64url))


def build_jws(protected_b64url, payload_b64url, signature_b64url):
    """Build a josepy JWS object from an ACME request's flattened JWS
    envelope ({"protected": ..., "payload": ..., "signature": ...}), for
    signature verification via verify_jws(). Raises on structurally invalid
    input (missing/malformed fields)."""
    return jose.JWS.from_json({
        'protected': protected_b64url,
        'payload': payload_b64url,
        'signature': signature_b64url,
    })


def verify_jws(jws, jwk):
    """Verify a parsed JWS's signature against the given JWK. Returns True/
    False - never raises on a bad signature (josepy's own JWS.verify()
    contract); a structurally malformed JWS would already have raised
    earlier, in build_jws()."""
    return jws.verify(jwk)


def verify_eab_jws(eab_jws_dict, expected_url, account_jwk, hmac_key_bytes):
    """Verify an RFC 8555 §7.3.4 External Account Binding object: a nested
    JWS, structurally separate from the outer newAccount envelope, whose
    payload must be the account's own JWK and whose signature is an HS256
    MAC keyed by a pre-shared secret an admin generated out-of-band
    (cltmanager.py's acme_create_eab_grant).

    Deliberately does NOT go through verify_acme_jws()'s ALLOWED_JWS_ALGS
    gate in acme_server_utils.py - that allowlist exists specifically to
    block an alg-confusion attack on the *outer* envelope and excludes every
    HMAC alg on purpose (see this module's own ALLOWED_JWS_ALGS comment).
    This is a separate, explicitly-HS256-only verification path for a
    structurally distinct object, never fed through that shared gate.

    Compares the EAB payload's own JWK to `account_jwk` by RFC 7638
    thumbprint rather than raw byte equality - robust to a client
    re-serializing the same key with different field order/whitespace
    (a real concern for trusted-but-not-conformance-tested devices) while
    still proving it's cryptographically the same key.

    Returns True/False; never raises - any malformed/mismatched EAB is
    just "verification failed", not a crash."""
    try:
        protected = decode_protected_header(eab_jws_dict['protected'])
    except (KeyError, ValueError, TypeError):
        return False
    if protected.get('alg') != 'HS256':
        return False
    if protected.get('url') != expected_url:
        return False

    try:
        eab_payload_jwk = json_to_jwk(decode_b64url(eab_jws_dict['payload']).decode('utf-8'))
    except Exception:
        return False
    if compute_thumbprint(eab_payload_jwk) != compute_thumbprint(account_jwk):
        return False

    try:
        jws = build_jws(eab_jws_dict['protected'], eab_jws_dict['payload'], eab_jws_dict['signature'])
        return bool(jws.verify(jose.jwk.JWKOct(key=hmac_key_bytes)))
    except Exception:
        return False


# --- CSR (josepy has no support for this at all) ----------------------------

def parse_and_validate_csr(csr_der: bytes):
    """Parse a DER-encoded CSR and verify its own self-signature. Raises
    InvalidCsr on any parse/signature failure."""
    try:
        csr = x509.load_der_x509_csr(csr_der)
    except Exception as e:
        raise InvalidCsr(f"could not parse CSR: {e}") from e
    if not csr.is_signature_valid:
        raise InvalidCsr("CSR self-signature is invalid")
    return csr


def extract_csr_san_dns_names(csr):
    """DNS SAN entries only, canonicalized (lowercased) - never falls back
    to commonName, matching real CA practice (§5.10: Boulder requires every
    requested domain in SAN and rejects a CN entry not also present there).
    Returns an empty list if the CSR has no SAN extension at all."""
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return [name.lower() for name in san_ext.value.get_values_for_type(x509.DNSName)]


def _public_key_der(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def csr_public_key_fingerprint(csr):
    """SHA-256 hex digest of the CSR's public key (SubjectPublicKeyInfo, DER-
    encoded) - the same fingerprint convention as Certificate.key_fingerprint/
    AcmeCertificate.key_fingerprint (§4.2/§4.3.1)."""
    return hashlib.sha256(_public_key_der(csr.public_key())).hexdigest()


def certificate_public_key_fingerprint(cert_pem: str):
    """Same fingerprint convention as csr_public_key_fingerprint(), for an
    issued certificate's PEM - used by crtrequest.py's CSR-relay path to
    populate Certificate.key_fingerprint/AcmeCertificate.key_fingerprint
    after a successful `acme.sh --signcsr` run."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
    return hashlib.sha256(_public_key_der(cert.public_key())).hexdigest()


def csr_public_key_matches_jwk(csr, jwk):
    """True if the CSR's public key is identical to the account JWK's own
    public key - the account-key-vs-CSR-key rejection hardening (§5.10): the
    account key and the certificate key are meant to be independent
    identities. Compares both as DER SubjectPublicKeyInfo bytes. `jwk` here
    is always a public-only JWK (parsed from an incoming request's `jwk`
    field, or from a stored account's Client.public_key), so its `.key`
    attribute is already a public key object - no `.public_key()` call
    needed."""
    return _public_key_der(csr.public_key()) == _public_key_der(jwk.key)
