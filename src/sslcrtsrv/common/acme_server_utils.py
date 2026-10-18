"""ACME (RFC 8555) HTTP server logic: routing, the centralized JWS
verification choke point, and every protocol endpoint handler. See
ACME_SERVER_DESIGN.md for the full protocol design this implements.

`acme_server.py` builds a `http.server.ThreadingHTTPServer` using
`AcmeRequestHandler` from this module, and is responsible for attaching two
attributes to the server instance before serving:
  - `server.acme_config`: the parsed server_config.json dict (must include
    `acme_external_url`; other `acme_*` fields are read via `.get(...)`
    with sensible defaults).
  - `server.acme_routes`: the list returned by `build_routes()`, built once
    from `acme_external_url`'s own path prefix.

Every request gets its own, fresh SQLAlchemy session (see `_dispatch()`) -
never shared across threads, matching the hardening requirement in
ACME_SERVER_DESIGN.md §8.3. Within one request, that session is used for
read-only lookups; mutations go through the existing `common/database.py`
helper functions (each managing their own short-lived session), except
where a handler needs to keep local, unpersisted object state in sync for
its own response rendering (see `handle_finalize()`).
"""

import http.server
import ipaddress
import json
import logging
import re
from datetime import timedelta
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization

from . import acme_jose
from . import database
from . import notify_utils
from .network_acl import is_ip_permitted
from .auth_failure_tracker import new_auth_failure_tracker
from .constants import (
    ACME_MAX_BODY_BYTES,
    ACME_DEFAULT_NONCE_TTL_SECONDS,
    ACME_DEFAULT_ORDER_TTL_DAYS,
    ACME_DEFAULT_FINALIZE_RETRY_AFTER_SECONDS,
    DEFAULT_TIMEOUT,
)

logger = logging.getLogger(__name__)

# Tracks JWS signature/EAB-credential failures by source IP and blocks the
# offending /24 subnet after a few strikes - SECURITY_FINDINGS.md finding
# #17. One instance per server process (module-level, since AcmeRequestHandler
# is instantiated fresh per request by http.server - this must survive
# across requests to actually count strikes).
_acme_auth_failure_tracker = new_auth_failure_tracker()

# RFC 8555 §6.7 registered error types this server actually uses - rendered
# as urn:ietf:params:acme:error:<suffix>. Anything NOT in this set (just
# this server's own 'orderConflict', §5.10) is rendered as a dereferenceable
# HTTPS URL under this server's own /errors/ namespace instead, per RFC
# 7807's extensibility model.
STANDARD_ERROR_TYPES = {
    'accountDoesNotExist', 'badCSR', 'badNonce', 'badPublicKey',
    'badSignatureAlgorithm', 'malformed', 'orderNotReady',
    'rejectedIdentifier', 'serverInternal', 'unauthorized',
    'unsupportedIdentifier',
}

_KID_PATTERN = re.compile(r'/account/(\d+)$')

# Trusted-client contact-token fallback (common/database.py's
# AcmeTrustGrant) - matches a plus-addressed token embedded in a newAccount
# contact entry, e.g. "mailto:provisioning+7K3f9...@yourdomain.example".
# Not anchored to a "mailto:" prefix specifically (contact entries are
# generic URIs per RFC 8555) - just looks for the "+<long-token>@" shape
# anywhere in the string. The length floor (20) is a cheap pre-filter, not
# the actual security boundary - that's find_active_contact_token_grant()'s
# hash lookup, which fails closed on anything that isn't an exact match for
# a still-active grant's real token.
_CONTACT_TOKEN_PATTERN = re.compile(r'\+([A-Za-z0-9_-]{20,})@')


# ---------------------------------------------------------------------------
# URL builders - always built from acme_external_url, never from request
# headers (ACME_SERVER_DESIGN.md §8.1's X-Forwarded-* distrust requirement).
# ---------------------------------------------------------------------------

def _base(config):
    return config['acme_external_url'].rstrip('/')

def _directory_url(config):
    return _base(config) + '/directory'

def _new_nonce_url(config):
    return _base(config) + '/new-nonce'

def _new_account_url(config):
    return _base(config) + '/new-account'

def _new_order_url(config):
    return _base(config) + '/new-order'

def _account_url(config, client_id):
    return _base(config) + f'/account/{client_id}'

def _account_orders_url(config, client_id):
    return _account_url(config, client_id) + '/orders'

def _order_url(config, order_id):
    return _base(config) + f'/order/{order_id}'

def _finalize_url(config, order_id):
    return _order_url(config, order_id) + '/finalize'

def _authz_url(config, order_id, n):
    return _base(config) + f'/authz/{order_id}/{n}'

def _challenge_url(config, order_id, n):
    return _base(config) + f'/challenge/{order_id}/{n}'

def _cert_url(config, order_id):
    return _base(config) + f'/cert/{order_id}'

def _intermediate_url(config):
    return _base(config) + '/intermediate'

def _resource_url(config, handler):
    """The absolute URL this request was actually addressed to - what an
    ACME client is required to sign into its JWS's `url` header. Built from
    acme_external_url's own scheme+host (never trusting request headers)
    plus the incoming request's own path, so it self-consistently matches
    whatever this server itself advertised in the directory/earlier
    responses, regardless of what path prefix acme_external_url uses."""
    parsed = urlparse(config['acme_external_url'])
    return f'{parsed.scheme}://{parsed.netloc}{handler.path}'

def _iso8601(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ') if dt else None


# ---------------------------------------------------------------------------
# Response building - every response, success or error, goes through
# _send_raw() so the cross-cutting requirements (fresh Replay-Nonce,
# Cache-Control: no-store, Link: rel="index") can never be forgotten by an
# individual handler (ACME_SERVER_DESIGN.md §5.1/§5.2/§4.4).
# ---------------------------------------------------------------------------

def _send_raw(handler, config, status, payload_bytes, headers):
    handler.send_response(status)
    for name, value in headers:
        handler.send_header(name, value)
    handler.send_header('Content-Length', str(len(payload_bytes)))
    handler.send_header('Cache-Control', 'no-store')
    nonce_ttl = config.get('acme_nonce_ttl_seconds', ACME_DEFAULT_NONCE_TTL_SECONDS)
    nonce = database.issue_acme_nonce(nonce_ttl)
    if nonce:
        handler.send_header('Replay-Nonce', nonce)
    handler.send_header('Link', f'<{_directory_url(config)}>; rel="index"')
    handler.end_headers()
    if handler.command != 'HEAD':
        handler.wfile.write(payload_bytes)

def _send_acme_json(handler, config, status, body_dict, extra_headers=None):
    payload = json.dumps(body_dict).encode('utf-8')
    headers = [('Content-Type', 'application/json')]
    if extra_headers:
        headers.extend(extra_headers)
    _send_raw(handler, config, status, payload, headers)

def _send_problem(handler, config, status, type_suffix, detail, extra_headers=None):
    body = {'type': _problem_type(config, type_suffix), 'detail': detail}
    payload = json.dumps(body).encode('utf-8')
    headers = [('Content-Type', 'application/problem+json')]
    if extra_headers:
        headers.extend(extra_headers)
    _send_raw(handler, config, status, payload, headers)

def _send_acme_pem(handler, config, status, pem_text, extra_headers=None):
    payload = pem_text.encode('ascii')
    headers = [('Content-Type', 'application/pem-certificate-chain')]
    if extra_headers:
        headers.extend(extra_headers)
    _send_raw(handler, config, status, payload, headers)

def _send_status_only(handler, config, status):
    _send_raw(handler, config, status, b'', [])

def _problem_type(config, type_suffix):
    if type_suffix in STANDARD_ERROR_TYPES:
        return f'urn:ietf:params:acme:error:{type_suffix}'
    return _base(config) + f'/errors/{type_suffix}'


# ---------------------------------------------------------------------------
# Centralized JWS verification (ACME_SERVER_DESIGN.md §5.12) - single choke
# point every authenticated endpoint routes through.
# ---------------------------------------------------------------------------

class JwsVerifyResult:
    """ok=False: status/error_type/error_detail are set, ready to pass
    straight into _send_problem(). ok=True: payload/client/jwk are set -
    `client` is None only when this was a jwk-authenticated request (i.e.
    newAccount) that resolved to a not-yet-existing account; `jwk` is
    always populated (either the request's own asserted jwk, or the stored
    JWK of the account resolved via kid) so callers needing to compare
    against the account's public key (e.g. finalize's CSR-key-vs-account-
    key check) never have to re-derive it themselves."""

    def __init__(self, ok, status=None, error_type=None, error_detail=None,
                 payload=None, client=None, jwk=None):
        self.ok = ok
        self.status = status
        self.error_type = error_type
        self.error_detail = error_detail
        self.payload = payload
        self.client = client
        self.jwk = jwk

def _jws_fail(status, error_type, detail):
    return JwsVerifyResult(False, status=status, error_type=error_type, error_detail=detail)

def _client_id_from_kid(kid_url):
    match = _KID_PATTERN.search(kid_url or '')
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None

def _request_source_ip(handler, config):
    """The IP address to check an account's `allowed_source_ip` pin against
    (§7.3). Defaults to the direct TCP peer (`handler.client_address`) -
    the only thing that can't be spoofed by an arbitrary connecting client.
    `X-Forwarded-For` is trusted ONLY when the direct TCP peer is itself the
    configured `acme_trusted_proxy_ip` - never from an arbitrary peer, which
    would otherwise let anyone spoof past the pin simply by setting that
    header themselves. With `acme_trusted_proxy_ip` unset (the default),
    `X-Forwarded-For` is never consulted at all.

    SECURITY_FINDINGS.md finding #18: a single-tier reverse proxy that
    correctly strips any inbound X-Forwarded-For before appending its own
    hop will only ever emit exactly one entry here. More than one is a sign
    the proxy isn't stripping client-supplied values - i.e. a client could
    be prepending an arbitrary spoofed address ahead of the proxy's own -
    so that case is treated as untrustworthy and falls back to the direct
    peer instead, rather than blindly taking the leftmost entry."""
    peer_ip = handler.client_address[0]
    trusted_proxy = config.get('acme_trusted_proxy_ip')
    if trusted_proxy and peer_ip == trusted_proxy:
        forwarded = handler.headers.get('X-Forwarded-For')
        if forwarded:
            hops = [hop.strip() for hop in forwarded.split(',')]
            if len(hops) > 1:
                logger.warning(
                    "Ignoring X-Forwarded-For with %d hops from trusted proxy %s (expected exactly "
                    "1 - the proxy may not be stripping client-supplied values): %r",
                    len(hops), trusted_proxy, forwarded)
                return peer_ip
            return hops[0]
    return peer_ip

def _acl_check_ip(handler, config):
    """The address checked against acme_allowed_networks/acme_denied_networks
    (common/network_acl.py) - independent of, and checked before, both
    per-account IP pinning (_source_ip_allowed(), above) and JWS/EAB
    authentication. Defaults to the direct TCP peer (handler.client_address)
    - the natural choice when this list is meant to restrict which hosts may
    reach the ACME port at all (e.g. only a reverse proxy's own address, or
    an internal management network). Set acme_access_control_use_forwarded_ip
    to true to instead check the real ACME client's address behind a trusted
    reverse proxy, reusing _request_source_ip()'s existing trusted-proxy/
    X-Forwarded-For resolution - only different from the direct peer once
    acme_trusted_proxy_ip is also configured."""
    if config.get('acme_access_control_use_forwarded_ip'):
        return _request_source_ip(handler, config)
    return handler.client_address[0]

def _source_ip_allowed(request_ip, allowed_ip):
    """Whether `request_ip` (a bare address) falls within `allowed_ip` (a
    bare IP or CIDR network string, as stored in Client.allowed_source_ip -
    §7.3). A malformed `request_ip` or `allowed_ip` - which should never
    happen for the former (it's either a real TCP peer address or an
    admin-configured trusted-proxy match) and is prevented at write time for
    the latter (cltmanager.py's set_allowed_ip validates before storing) -
    fails closed (returns False) rather than raising into the request
    handler."""
    try:
        return ipaddress.ip_address(request_ip) in ipaddress.ip_network(allowed_ip, strict=False)
    except ValueError:
        return False

def verify_acme_jws(session, handler, body_bytes, expected_url, account_required=True,
                     expect_empty_payload=False, allow_jwk=False):
    """Verify every aspect of an incoming ACME request's JWS envelope,
    exactly per ACME_SERVER_DESIGN.md §5.12. `account_required` is accepted
    for signature-shape fidelity with the design doc; in practice it's
    always satisfied by construction here - the kid branch below already
    fails closed (accountDoesNotExist) before returning if no matching
    account exists, and the jwk branch (only ever used by newAccount, which
    always passes account_required=False) never needs an existing account
    at all."""
    content_type = handler.headers.get('Content-Type', '')
    if content_type.split(';')[0].strip().lower() != 'application/jose+json':
        return _jws_fail(415, 'malformed', 'Content-Type must be application/jose+json')

    try:
        envelope = json.loads(body_bytes) if body_bytes else {}
    except ValueError:
        return _jws_fail(400, 'malformed', 'Request body is not valid JSON')

    if not isinstance(envelope, dict) or not all(k in envelope for k in ('protected', 'payload', 'signature')):
        return _jws_fail(400, 'malformed', 'JWS envelope missing protected/payload/signature')

    try:
        header = acme_jose.decode_protected_header(envelope['protected'])
    except Exception:
        return _jws_fail(400, 'malformed', 'Could not decode protected header')
    if not isinstance(header, dict):
        return _jws_fail(400, 'malformed', 'Protected header is not a JSON object')

    alg = header.get('alg')
    if alg not in acme_jose.ALLOWED_JWS_ALGS:
        return _jws_fail(400, 'badSignatureAlgorithm', f'Unsupported or missing alg: {alg!r}')

    has_jwk = 'jwk' in header
    has_kid = 'kid' in header
    if has_jwk == has_kid:
        return _jws_fail(400, 'malformed', 'Exactly one of jwk/kid must be present')
    if has_jwk and not allow_jwk:
        return _jws_fail(400, 'malformed', 'jwk is not allowed on this endpoint')
    if has_kid and allow_jwk:
        return _jws_fail(400, 'malformed', 'kid is not allowed on this endpoint')

    if header.get('url') != expected_url:
        return _jws_fail(400, 'malformed', 'url header does not match the request target')

    nonce = header.get('nonce')
    if not nonce or not database.consume_acme_nonce(nonce):
        return _jws_fail(400, 'badNonce', 'Invalid, missing, or already-used nonce')

    client = None
    if has_jwk:
        try:
            jwk = acme_jose.json_to_jwk(json.dumps(header['jwk']))
        except Exception:
            return _jws_fail(400, 'malformed', 'Invalid jwk in protected header')
    else:
        client_id = _client_id_from_kid(header.get('kid'))
        client = (session.query(database.Client)
                  .filter_by(id=client_id, client_kind='acme').first()) if client_id is not None else None
        if client is None:
            return _jws_fail(401, 'accountDoesNotExist', 'No such ACME account')
        if client.allowed_source_ip:
            request_ip = _request_source_ip(handler, handler.server.acme_config)
            if not _source_ip_allowed(request_ip, client.allowed_source_ip):
                # Same status/type/detail as the "not confirmed" rejection
                # (see handle_new_order()) - deliberately, so a probing
                # attacker can't distinguish an IP-pin mismatch from an
                # unconfirmed account (§7.3).
                return _jws_fail(403, 'unauthorized', 'Account is not yet confirmed')
        try:
            jwk = acme_jose.json_to_jwk(client.public_key)
        except Exception:
            return _jws_fail(500, 'serverInternal', 'Stored account key is corrupt')

    try:
        jws = acme_jose.build_jws(envelope['protected'], envelope['payload'], envelope['signature'])
    except Exception:
        return _jws_fail(400, 'malformed', 'Malformed JWS envelope')

    try:
        signature_ok = acme_jose.verify_jws(jws, jwk)
    except Exception:
        signature_ok = False
    if not signature_ok:
        # A rejected signature is an authentication-failure signal worth
        # counting toward this source IP's strikes (SECURITY_FINDINGS.md
        # finding #17) - unlike the malformed-envelope/nonce failures above,
        # this specifically indicates someone signed with the wrong key.
        _acme_auth_failure_tracker.record_bad_request(handler.client_address[0])
        return _jws_fail(401, 'unauthorized', 'JWS signature verification failed')

    payload = acme_jose.decode_b64url(envelope['payload'])
    if expect_empty_payload and payload != b'':
        return _jws_fail(400, 'malformed', 'Expected an empty POST-as-GET payload')

    _acme_auth_failure_tracker.record_good_request(handler.client_address[0])
    return JwsVerifyResult(True, payload=payload, client=client, jwk=jwk)


# ---------------------------------------------------------------------------
# Status derivation (ACME_SERVER_DESIGN.md §4.3.1/§5.9)
# ---------------------------------------------------------------------------

def _get_relation(session, client_id, fqdns):
    return session.query(database.ClientCertificateRelation).filter_by(
        client_id=client_id, fqdns=fqdns).first()

def _order_external_status(session, order):
    """The ACME `status` field an order/finalize/order-poll response
    actually shows - §4.3.1's table."""
    if order.status in ('invalid', 'processing', 'valid'):
        return order.status
    # order.status == 'pending' - the one place this design still derives
    # live, mirroring the pending/ready boundary.
    relation = _get_relation(session, order.account_client_id, order.fqdns)
    return 'ready' if database.permission_is_active(relation) else 'pending'

def authorization_status(session, order):
    """One of 'pending', 'valid', 'invalid', 'expired' - §5.9's exact
    derivation. Uses AcmeOrder.finalized_at (a true one-way commitment) as
    the point past which the authorization can only ever move forward to
    'expired', never back to 'pending' and never to 'invalid' - order.status
    itself is not fully one-way from the authorization's point of view
    (processing -> invalid via expiry/attempt-cap describes issuance
    failing, not authorization un-happening)."""
    now = database._utcnow()
    if order.finalized_at is not None:
        return 'valid' if order.expires_at > now else 'expired'
    if order.status == 'invalid':
        return 'invalid'
    relation = _get_relation(session, order.account_client_id, order.fqdns)
    return 'valid' if database.permission_is_active(relation) else 'pending'

def challenge_status(session, order):
    """RFC 8555 §8 challenge status has no 'expired' value, unlike
    authorization status - an already-expired authorization's embedded
    challenge still reports whatever it last legitimately was."""
    status = authorization_status(session, order)
    return 'valid' if status in ('valid', 'expired') else status


# ---------------------------------------------------------------------------
# Identifier / fqdns helpers
# ---------------------------------------------------------------------------

# A DNS label after IDNA encoding must be pure ASCII alphanumeric-and-hyphen,
# 1-63 characters, never starting or ending with a hyphen (RFC 1035 §2.3.1,
# as amended by RFC 1123 §2.1 to allow a leading digit).
_DNS_LABEL_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')


def validate_dns_identifier_value(value):
    """Syntactic validation for one `newOrder` identifier's `value` field
    (ACME_SERVER_DESIGN.md §9/§11 risk 7) - basic `type: "dns"` + syntactic
    checks, deliberately no deeper than RFC 1035/1123 label syntax plus IDNA
    encoding via the stdlib `idna` codec (no extra dependency). Before this,
    handle_new_order() only checked `type == 'dns'` and a non-empty value -
    a value containing whitespace, control characters, an IP address literal
    (which is syntactically a valid-looking set of numeric DNS labels, but
    not a domain name - RFC 8738 uses a distinct `ip` identifier type this
    server has no support for at all), or invalid Unicode/IDNA input would
    otherwise reach _canonicalize_fqdns(), the database, CSR SAN matching,
    and crtrequest.py's DNS delegation check completely unvalidated.

    Returns (True, None) if valid, or (False, <reason>) - the reason is
    meant to go straight into a `badCSR`-sibling `malformed` problem+json
    response, so keep it a plain, client-facing sentence.

    Deliberately NOT attempted here: full IDNA2008/UTS-46 normalization
    (the stdlib `idna` codec implements the older IDNA2003 algorithm) or
    Unicode confusable-character detection - see §11 risk 7's own framing
    that deeper IDNA validation is a "depends whether a real deployment
    needs it" question, not a v1 blocker. This closes the more basic gap
    of having no syntactic validation at all, not that specific one."""
    if not isinstance(value, str) or not value:
        return False, "identifier value must be a non-empty string"
    if value != value.strip():
        return False, "identifier value must not have leading or trailing whitespace"
    if len(value) > 253:
        return False, "identifier value exceeds 253 characters"
    if any(ord(c) < 0x21 or ord(c) == 0x7f for c in value):
        return False, "identifier value contains a control character or space"

    try:
        ipaddress.ip_address(value)
        return False, "identifier value is an IP address literal, not a DNS name"
    except ValueError:
        pass

    labels = value.split('.')
    if labels[0] == '*':
        if '*' in labels[1:]:
            return False, "'*' may only appear once, as the leftmost label"
        labels = labels[1:]
    elif '*' in labels:
        return False, "'*' may only appear once, as the leftmost label"
    if not labels or any(not label for label in labels):
        return False, "identifier value has an empty label (e.g. a double dot)"

    for label in labels:
        try:
            ascii_label = label.encode('idna').decode('ascii')
        except UnicodeError as e:
            return False, f"label {label!r} is not a valid DNS label: {e}"
        if len(ascii_label) > 63:
            return False, f"label {label!r} exceeds 63 characters"
        if not _DNS_LABEL_RE.match(ascii_label):
            return False, f"label {label!r} is not a valid DNS label"
    return True, None


def _canonicalize_fqdns(identifiers):
    """Sorted, comma-joined, lowercased fqdns form - the same convention
    Certificate.fqdns/ClientCertificateRelation.fqdns already use. Retains
    a wildcard's literal '*.' prefix (never stripped here - see §5.7)."""
    return ','.join(sorted(ident['value'].lower() for ident in identifiers))


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _render_account(config, client):
    body = {'status': 'valid', 'orders': _account_orders_url(config, client.id)}
    if client.acme_contact:
        try:
            body['contact'] = json.loads(client.acme_contact)
        except (ValueError, TypeError):
            pass
    return body

def _render_order(config, session, order):
    identifiers = json.loads(order.identifiers_json)
    body = {
        'status': _order_external_status(session, order),
        'expires': _iso8601(order.expires_at),
        'identifiers': identifiers,
        'authorizations': [_authz_url(config, order.id, n) for n in range(len(identifiers))],
        'finalize': _finalize_url(config, order.id),
    }
    if body['status'] == 'valid':
        body['certificate'] = _cert_url(config, order.id)
    return body

def _render_challenge(config, session, order, order_id, n):
    body = {
        'type': 'sslcrtsrv-admin-authorization',
        'url': _challenge_url(config, order_id, n),
        'status': challenge_status(session, order),
    }
    if order.finalized_at is not None:
        body['validated'] = _iso8601(order.finalized_at)
    return body

def _accept_allows_default(accept_header):
    for part in (accept_header or '*/*').split(','):
        media_type = part.split(';')[0].strip().lower()
        if media_type in ('', '*/*', 'application/*', 'application/pem-certificate-chain'):
            return True
    return False


# ---------------------------------------------------------------------------
# Endpoint handlers - each takes (handler, session, match, body) and sends
# its own response via the _send_* helpers above.
# ---------------------------------------------------------------------------

def handle_directory(handler, session, match, body):
    config = handler.server.acme_config
    body_out = {
        'newNonce': _new_nonce_url(config),
        'newAccount': _new_account_url(config),
        'newOrder': _new_order_url(config),
        'meta': {'externalAccountRequired': False},
    }
    _send_acme_json(handler, config, 200, body_out)

def handle_new_nonce(handler, session, match, body):
    config = handler.server.acme_config
    _send_raw(handler, config, 200, b'', [])

def handle_intermediate_download(handler, session, match, body):
    config = handler.server.acme_config
    cert = (session.query(database.AcmeCertificate)
            .order_by(database.AcmeCertificate.created_at.desc()).first())
    if cert is None or not cert.intermediates:
        return _send_problem(handler, config, 404, 'malformed', 'No intermediate certificate available yet')
    _send_acme_pem(handler, config, 200, cert.intermediates)

def handle_new_account(handler, session, match, body):
    config = handler.server.acme_config
    url = _resource_url(config, handler)
    result = verify_acme_jws(session, handler, body, url, account_required=False,
                              expect_empty_payload=False, allow_jwk=True)
    if not result.ok:
        return _send_problem(handler, config, result.status, result.error_type, result.error_detail)

    try:
        payload = json.loads(result.payload) if result.payload else {}
    except ValueError:
        return _send_problem(handler, config, 400, 'malformed', 'Invalid JSON payload')
    if payload.get('termsOfServiceAgreed') is False:
        return _send_problem(handler, config, 400, 'malformed', 'termsOfServiceAgreed must not be false')

    # Trusted-client auto-approval (common/database.py's AcmeTrustGrant) - a
    # pre-shared credential an admin generated out-of-band for a device
    # they already trust, letting it skip both acme_confirm and assign.
    # Checked in this order; the contact-token fallback only matters for
    # clients with no EAB support at all (e.g. FortiOS < 7.6.3 - see the
    # class' own docstring in database.py). A *claimed* EAB that fails
    # verification is rejected outright here, never silently downgraded to
    # a normal pending self-registration - that would let a wrong/stale
    # credential attempt still result in *some* account existing to keep
    # retrying against.
    trust_grant = None
    eab = payload.get('externalAccountBinding')
    if eab is not None:
        eab_kid = None
        try:
            eab_kid = acme_jose.decode_protected_header(eab['protected']).get('kid')
        except Exception:
            eab_kid = None
        candidate_grant = database.find_active_eab_grant(eab_kid) if eab_kid else None
        hmac_key_bytes = database.get_acme_eab_hmac_key_bytes(candidate_grant)
        if (candidate_grant is None or hmac_key_bytes is None
                or not acme_jose.verify_eab_jws(eab, url, result.jwk, hmac_key_bytes)):
            # Same reasoning as the JWS-signature failure above - a wrong/
            # guessed EAB credential is an authentication-failure signal
            # (SECURITY_FINDINGS.md finding #17).
            _acme_auth_failure_tracker.record_bad_request(handler.client_address[0])
            return _send_problem(handler, config, 400, 'malformed', 'Invalid externalAccountBinding')
        trust_grant = candidate_grant
    else:
        for entry in (payload.get('contact') or []):
            m = _CONTACT_TOKEN_PATTERN.search(entry or '')
            if m:
                candidate_grant = database.find_active_contact_token_grant(m.group(1))
                if candidate_grant is not None:
                    trust_grant = candidate_grant
                    break

    thumbprint = acme_jose.compute_thumbprint(result.jwk)
    client = session.query(database.Client).filter_by(acme_key_thumbprint=thumbprint).first()
    created = False

    if client is None:
        if payload.get('onlyReturnExisting'):
            return _send_problem(handler, config, 400, 'accountDoesNotExist', 'No account exists for this key')
        contact = payload.get('contact')
        contact_json = json.dumps(contact) if contact else None
        jwk_json = acme_jose.jwk_to_json(result.jwk)
        status = 'confirmed' if trust_grant else 'registered'
        client = database.create_acme_account(jwk_json, thumbprint, contact_json, status=status,
                                               trust_grant_id=trust_grant.id if trust_grant else None)
        if client is None:
            # Thumbprint collision race (two newAccount requests for the
            # same not-yet-registered key) - re-fetch the winner. Trust
            # grant use is deliberately *not* recorded in this branch: the
            # row that actually landed belongs to whichever request won the
            # race, which might not be this one.
            client = database.get_client_by_acme_thumbprint(thumbprint)
            if client is None:
                return _send_problem(handler, config, 500, 'serverInternal', 'Could not create account')
        else:
            created = True
            if trust_grant:
                database.record_trust_grant_use(trust_grant.id)
                notify_utils.send_acme_trust_grant_registration_notification(
                    config, client.client_id, thumbprint, trust_grant.label)
            else:
                notify_utils.send_acme_registration_notification(config, client.client_id, thumbprint)

    body_out = _render_account(config, client)
    extra_headers = [('Location', _account_url(config, client.id))]
    _send_acme_json(handler, config, 201 if created else 200, body_out, extra_headers=extra_headers)

def handle_account(handler, session, match, body):
    config = handler.server.acme_config
    client_id = int(match.group('client_id'))
    url = _resource_url(config, handler)
    result = verify_acme_jws(session, handler, body, url, account_required=True,
                              expect_empty_payload=False, allow_jwk=False)
    if not result.ok:
        return _send_problem(handler, config, result.status, result.error_type, result.error_detail)
    if result.client.id != client_id:
        return _send_problem(handler, config, 403, 'unauthorized', 'kid does not match this account URL')

    if result.payload:
        try:
            payload = json.loads(result.payload)
        except ValueError:
            return _send_problem(handler, config, 400, 'malformed', 'Invalid JSON payload')
        if 'contact' in payload:
            contact_json = json.dumps(payload['contact']) if payload['contact'] else None
            database.update_acme_account_contact(result.client.id, contact_json)
            result.client.acme_contact = contact_json  # keep in-memory object in sync for rendering below

    _send_acme_json(handler, config, 200, _render_account(config, result.client))

def handle_account_orders(handler, session, match, body):
    config = handler.server.acme_config
    client_id = int(match.group('client_id'))
    url = _resource_url(config, handler)
    result = verify_acme_jws(session, handler, body, url, account_required=True,
                              expect_empty_payload=True, allow_jwk=False)
    if not result.ok:
        return _send_problem(handler, config, result.status, result.error_type, result.error_detail)
    if result.client.id != client_id:
        return _send_problem(handler, config, 403, 'unauthorized', 'kid does not match this account URL')

    orders = database.get_acme_orders_for_account(client_id, limit=100)
    _send_acme_json(handler, config, 200, {'orders': [_order_url(config, o.id) for o in orders]})

def handle_new_order(handler, session, match, body):
    config = handler.server.acme_config
    url = _resource_url(config, handler)
    result = verify_acme_jws(session, handler, body, url, account_required=True,
                              expect_empty_payload=False, allow_jwk=False)
    if not result.ok:
        return _send_problem(handler, config, result.status, result.error_type, result.error_detail)
    client = result.client
    if client.status != 'confirmed':
        return _send_problem(handler, config, 403, 'unauthorized', 'Account is not yet confirmed')

    try:
        payload = json.loads(result.payload) if result.payload else {}
    except ValueError:
        return _send_problem(handler, config, 400, 'malformed', 'Invalid JSON payload')
    identifiers = payload.get('identifiers')
    if not isinstance(identifiers, list) or not identifiers:
        return _send_problem(handler, config, 400, 'malformed', 'identifiers must be a non-empty array')
    for ident in identifiers:
        if not isinstance(ident, dict) or not ident.get('value'):
            return _send_problem(handler, config, 400, 'malformed', 'Each identifier needs a value')
        if ident.get('type') != 'dns':
            return _send_problem(handler, config, 400, 'unsupportedIdentifier',
                                  'Only dns identifiers are supported')
        valid, reason = validate_dns_identifier_value(ident['value'])
        if not valid:
            return _send_problem(handler, config, 400, 'malformed', reason)

    fqdns = _canonicalize_fqdns(identifiers)
    existing_cert = session.query(database.Certificate).filter_by(fqdns=fqdns).first()
    if existing_cert and existing_cert.private_key:
        # No longer a hard rejection: the traditional protocol and ACME can
        # now manage the same fqdns independently, each with its own
        # certificate (see crtrequest.py's update_database_with_certificate_
        # from_csr(), which keeps this order's eventual issuance from ever
        # overwriting the traditional protocol's own stored key). Logged for
        # visibility, since it's still worth an admin knowing this fqdns now
        # has two independently-managed certificates.
        logger.info("new-order for %r: already has a traditional-protocol-managed certificate - "
                    "proceeding with an independent, separately-tracked ACME certificate for client %d",
                    fqdns, client.id)

    cert_id = database.create_certificate_entry(fqdns)
    if cert_id is None:
        return _send_problem(handler, config, 500, 'serverInternal', 'Could not create certificate placeholder')
    # Only initialize the relation the *first* time this client orders this
    # fqdns - an admin's approval (cltmanager.py assign, §5.8) must survive
    # every later renewal's new-order call untouched, exactly like it does
    # for the traditional protocol. Unconditionally resetting it to pending
    # here would silently revoke an already-approved fqdns on every single
    # renewal, since permission_is_active() gates both the authorization's
    # "ready" status and finalize itself - discovered 2026-09-17 debugging a
    # real device's renewal getting stuck without ever exercising this via
    # the handler in existing tests (they construct AcmeOrder rows directly).
    if _get_relation(session, client.id, fqdns) is None:
        # A trust-granted account (client.trust_grant_id set - see
        # common/database.py's AcmeTrustGrant) skips the pending state
        # entirely for any fqdns matching its admin-configured glob
        # pattern, exactly as if cltmanager.py assign had already been run.
        # Re-validated here (not just trusted from account-creation time) -
        # a grant revoked/expired since must stop granting new domains
        # immediately, without disturbing relations it already approved.
        auto_approved = False
        if client.trust_grant_id is not None:
            grant = database.get_acme_trust_grant(client.trust_grant_id)
            auto_approved = database.fqdns_matches_trust_grant(grant, fqdns)
        database.add_client_certificate_relation(client.id, fqdns, status=1 if auto_approved else 0)

    order_ttl_days = config.get('acme_order_ttl_days', ACME_DEFAULT_ORDER_TTL_DAYS)
    expires_at = database._utcnow() + timedelta(days=order_ttl_days)
    order = database.create_acme_order(client.id, fqdns, json.dumps(identifiers), expires_at)
    if order is None:
        return _send_problem(handler, config, 500, 'serverInternal', 'Could not create order')

    logger.info("new-order created: order=%d client_id=%d fqdns=%r", order.id, client.id, fqdns)

    body_out = _render_order(config, session, order)
    _send_acme_json(handler, config, 201, body_out, extra_headers=[('Location', _order_url(config, order.id))])

def _log_order_status_check(session, order, where):
    """Diagnostic logging for a client polling an order/authz/challenge
    without ever reaching finalize (the symptom that prompted adding this -
    a client stuck re-polling the same order indefinitely, with admintui
    showing nothing outstanding). Logs exactly what a client would see
    (external status) plus the server-side state that drives it
    (order.status, whether the fqdns permission is active) in one line, so
    this is diagnosable from the log alone without a DB query."""
    relation = _get_relation(session, order.account_client_id, order.fqdns)
    permission_active = database.permission_is_active(relation)
    external_status = _order_external_status(session, order)
    logger.info(
        "%s: order=%d client_id=%d fqdns=%r stored_status=%s external_status=%s "
        "permission_active=%s finalized_at=%s issuance_attempts=%s",
        where, order.id, order.account_client_id, order.fqdns, order.status, external_status,
        permission_active, order.finalized_at, getattr(order, 'issuance_attempts', None))

def handle_order(handler, session, match, body):
    config = handler.server.acme_config
    order_id = int(match.group('order_id'))
    url = _resource_url(config, handler)
    result = verify_acme_jws(session, handler, body, url, account_required=True,
                              expect_empty_payload=True, allow_jwk=False)
    if not result.ok:
        return _send_problem(handler, config, result.status, result.error_type, result.error_detail)
    order = session.query(database.AcmeOrder).filter_by(id=order_id).first()
    if order is None:
        return _send_problem(handler, config, 404, 'malformed', 'No such order')
    if order.account_client_id != result.client.id:
        return _send_problem(handler, config, 403, 'unauthorized', 'This order does not belong to your account')
    _log_order_status_check(session, order, "order poll")
    _send_acme_json(handler, config, 200, _render_order(config, session, order))

def handle_authz(handler, session, match, body):
    config = handler.server.acme_config
    order_id = int(match.group('order_id'))
    n = int(match.group('n'))
    url = _resource_url(config, handler)
    result = verify_acme_jws(session, handler, body, url, account_required=True,
                              expect_empty_payload=True, allow_jwk=False)
    if not result.ok:
        return _send_problem(handler, config, result.status, result.error_type, result.error_detail)
    order = session.query(database.AcmeOrder).filter_by(id=order_id).first()
    if order is None:
        return _send_problem(handler, config, 404, 'malformed', 'No such authorization')
    if order.account_client_id != result.client.id:
        return _send_problem(handler, config, 403, 'unauthorized',
                              'This authorization does not belong to your account')

    identifiers = json.loads(order.identifiers_json)
    if n < 0 or n >= len(identifiers):
        return _send_problem(handler, config, 404, 'malformed', 'No such authorization')
    value = identifiers[n]['value']
    wildcard = value.startswith('*.')
    base_domain = value[2:] if wildcard else value

    _log_order_status_check(session, order, "authz poll")
    body_out = {
        'identifier': {'type': 'dns', 'value': base_domain},
        'status': authorization_status(session, order),
        'expires': _iso8601(order.expires_at),
        'challenges': [_render_challenge(config, session, order, order_id, n)],
    }
    if wildcard:
        body_out['wildcard'] = True
    _send_acme_json(handler, config, 200, body_out)

def handle_challenge(handler, session, match, body):
    config = handler.server.acme_config
    order_id = int(match.group('order_id'))
    n = int(match.group('n'))
    url = _resource_url(config, handler)
    result = verify_acme_jws(session, handler, body, url, account_required=True,
                              expect_empty_payload=False, allow_jwk=False)
    if not result.ok:
        return _send_problem(handler, config, result.status, result.error_type, result.error_detail)
    order = session.query(database.AcmeOrder).filter_by(id=order_id).first()
    if order is None:
        return _send_problem(handler, config, 404, 'malformed', 'No such challenge')
    if order.account_client_id != result.client.id:
        return _send_problem(handler, config, 403, 'unauthorized',
                              'This challenge does not belong to your account')

    _log_order_status_check(session, order, "challenge poll")
    body_out = _render_challenge(config, session, order, order_id, n)
    extra_headers = [('Link', f'<{_authz_url(config, order_id, n)}>; rel="up"')]
    _send_acme_json(handler, config, 200, body_out, extra_headers=extra_headers)

def handle_finalize(handler, session, match, body):
    config = handler.server.acme_config
    order_id = int(match.group('order_id'))
    url = _resource_url(config, handler)
    result = verify_acme_jws(session, handler, body, url, account_required=True,
                              expect_empty_payload=False, allow_jwk=False)
    if not result.ok:
        return _send_problem(handler, config, result.status, result.error_type, result.error_detail)
    order = session.query(database.AcmeOrder).filter_by(id=order_id).first()
    if order is None:
        return _send_problem(handler, config, 404, 'malformed', 'No such order')
    if order.account_client_id != result.client.id:
        return _send_problem(handler, config, 403, 'unauthorized', 'This order does not belong to your account')

    relation = _get_relation(session, order.account_client_id, order.fqdns)
    if order.status != 'pending' or not database.permission_is_active(relation):
        # The key diagnostic signal for "client never progresses past
        # polling" - this is the one place that would show a client
        # actually *attempting* to finalize but being turned away, versus
        # never attempting it at all (only ever GETting order/authz/
        # challenge, as logged by _log_order_status_check above).
        logger.warning(
            "finalize rejected (orderNotReady): order=%d client_id=%d fqdns=%r order.status=%s "
            "permission_active=%s", order.id, order.account_client_id, order.fqdns, order.status,
            database.permission_is_active(relation))
        return _send_problem(handler, config, 403, 'orderNotReady', 'This order is not ready to be finalized')

    logger.info("finalize accepted: order=%d client_id=%d fqdns=%r", order.id, order.account_client_id, order.fqdns)
    try:
        payload = json.loads(result.payload) if result.payload else {}
    except ValueError:
        return _send_problem(handler, config, 400, 'malformed', 'Invalid JSON payload')
    csr_b64 = payload.get('csr')
    if not csr_b64:
        return _send_problem(handler, config, 400, 'malformed', 'Missing csr field')

    try:
        csr_der = acme_jose.decode_b64url(csr_b64)
        csr = acme_jose.parse_and_validate_csr(csr_der)
    except acme_jose.InvalidCsr as e:
        return _send_problem(handler, config, 400, 'malformed', str(e))
    except Exception:
        return _send_problem(handler, config, 400, 'malformed', 'Could not decode CSR')

    csr_names = set(acme_jose.extract_csr_san_dns_names(csr))
    identifiers = json.loads(order.identifiers_json)
    order_names_list = [ident['value'].lower() for ident in identifiers]
    order_names = set(order_names_list)
    if len(order_names_list) != len(order_names) or csr_names != order_names:
        return _send_problem(handler, config, 400, 'badCSR',
                              'CSR SAN entries must exactly match the order identifiers, with no duplicates')

    if acme_jose.csr_public_key_matches_jwk(csr, result.jwk):
        return _send_problem(handler, config, 400, 'badCSR', 'CSR public key must not match the account key')

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('ascii')
    csr_key_fingerprint = acme_jose.csr_public_key_fingerprint(csr)

    if not database.acquire_acme_processing_lock(order.id, order.fqdns, csr_pem, csr_key_fingerprint):
        return _send_problem(handler, config, 400, 'orderConflict',
                              'Another order for this fqdns is already processing')

    # Keep this request's own in-memory order object in sync with what was
    # just committed (via a different session, inside
    # acquire_acme_processing_lock()) so _render_order() below reflects the
    # new state without an extra round trip - never re-committed from here.
    order.status = 'processing'
    order.csr_pem = csr_pem
    order.finalized_at = database._utcnow()

    retry_after = config.get('acme_finalize_retry_after_seconds', ACME_DEFAULT_FINALIZE_RETRY_AFTER_SECONDS)
    _send_acme_json(handler, config, 200, _render_order(config, session, order),
                     extra_headers=[('Retry-After', str(retry_after))])

def handle_certificate_download(handler, session, match, body):
    config = handler.server.acme_config
    order_id = int(match.group('order_id'))
    url = _resource_url(config, handler)
    result = verify_acme_jws(session, handler, body, url, account_required=True,
                              expect_empty_payload=True, allow_jwk=False)
    if not result.ok:
        return _send_problem(handler, config, result.status, result.error_type, result.error_detail)
    order = session.query(database.AcmeOrder).filter_by(id=order_id).first()
    if order is None:
        return _send_problem(handler, config, 404, 'malformed', 'No such order')
    if order.account_client_id != result.client.id:
        return _send_problem(handler, config, 403, 'unauthorized',
                              'This certificate does not belong to your account')
    if order.status != 'valid':
        return _send_problem(handler, config, 403, 'orderNotReady', 'This order has no certificate yet')

    if not _accept_allows_default(handler.headers.get('Accept')):
        return _send_status_only(handler, config, 406)

    cert = database.get_acme_certificate_by_order_id(order_id)
    if cert is None:
        return _send_problem(handler, config, 500, 'serverInternal', 'Certificate record missing for a valid order')

    chain_pem = cert.certificate_pem + (cert.intermediates or '')
    extra_headers = [('Link', f'<{_intermediate_url(config)}>; rel="up"')]
    _send_acme_pem(handler, config, 200, chain_pem, extra_headers=extra_headers)


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def build_routes(path_prefix):
    """Build the fixed (method, compiled_regex, handler_fn) routing table
    for one running server, from acme_external_url's own path prefix
    (e.g. '/acme'). Built once at server startup, not per-request. Only
    directory/new-nonce/intermediate are registered under GET/HEAD - every
    other resource is reachable only via authenticated POST-as-GET,
    structurally enforcing §5.12's closing requirement rather than relying
    on verify_acme_jws() alone to reject a GET that should never have been
    routable in the first place."""
    p = re.escape(path_prefix.rstrip('/'))
    return [
        ('GET', re.compile(f'^{p}/directory$'), handle_directory),
        ('HEAD', re.compile(f'^{p}/directory$'), handle_directory),
        ('GET', re.compile(f'^{p}/new-nonce$'), handle_new_nonce),
        ('HEAD', re.compile(f'^{p}/new-nonce$'), handle_new_nonce),
        ('GET', re.compile(f'^{p}/intermediate$'), handle_intermediate_download),
        ('POST', re.compile(f'^{p}/new-account$'), handle_new_account),
        ('POST', re.compile(f'^{p}/new-order$'), handle_new_order),
        ('POST', re.compile(f'^{p}/account/(?P<client_id>\\d+)/orders$'), handle_account_orders),
        ('POST', re.compile(f'^{p}/account/(?P<client_id>\\d+)$'), handle_account),
        ('POST', re.compile(f'^{p}/order/(?P<order_id>\\d+)/finalize$'), handle_finalize),
        ('POST', re.compile(f'^{p}/order/(?P<order_id>\\d+)$'), handle_order),
        ('POST', re.compile(f'^{p}/authz/(?P<order_id>\\d+)/(?P<n>\\d+)$'), handle_authz),
        ('POST', re.compile(f'^{p}/challenge/(?P<order_id>\\d+)/(?P<n>\\d+)$'), handle_challenge),
        ('POST', re.compile(f'^{p}/cert/(?P<order_id>\\d+)$'), handle_certificate_download),
    ]


class AcmeRequestHandler(http.server.BaseHTTPRequestHandler):
    """Reads server.acme_config/server.acme_routes, set by acme_server.py
    before serve_forever() is called. protocol_version is HTTP/1.1 so
    responses can use keep-alive - every response path goes through
    _send_raw(), which always sends an accurate Content-Length."""

    server_version = "sslcrtsrv-acme-server/1.0"
    protocol_version = "HTTP/1.1"
    # Per-connection idle timeout, honored by socketserver.StreamRequestHandler's
    # own setup() (self.connection.settimeout(self.timeout)) - the same
    # protection common/server_utils.py's Server applies to its own accepted
    # sockets, so one slow/silent peer can't pin a handler thread forever
    # (ACME_SERVER_DESIGN.md §8.3).
    timeout = DEFAULT_TIMEOUT

    def log_message(self, fmt, *args):
        # Reuses _request_source_ip() - the exact same peer-vs-trusted-proxy
        # resolution the IP-pinning feature (SS7.3) already relies on - so
        # access logs show the real client behind a reverse proxy instead
        # of always logging the proxy's own (e.g. docker-internal) address.
        # Only takes effect once acme_trusted_proxy_ip is configured to the
        # proxy's own address (Manual.MD's Section 4.6/9.10); with it unset
        # (the default), this still logs the direct TCP peer exactly like
        # before - X-Forwarded-For is never trusted from an arbitrary peer.
        try:
            source_ip = _request_source_ip(self, self.server.acme_config)
        except Exception:
            source_ip = self.address_string()
        logger.info("%s - %s", source_ip, fmt % args)

    def do_GET(self):
        self._dispatch('GET')

    def do_HEAD(self):
        self._dispatch('HEAD')

    def do_POST(self):
        self._dispatch('POST')

    def _dispatch(self, method):
        config = self.server.acme_config

        # Static, admin-configured netblock allow/deny list - checked before
        # route matching, body reading, or opening a DB session, so a
        # disallowed source is turned away as cheaply as possible and never
        # reaches any per-endpoint logic (including the three unauthenticated
        # endpoints - directory/new-nonce/intermediate - that never go
        # through verify_acme_jws()). A minimal, bodyless response is used
        # instead of _send_raw()/_send_problem() deliberately: those always
        # issue a fresh Replay-Nonce via a DB call, which would defeat the
        # point of rejecting cheaply, and a bare 403 doesn't confirm to a
        # scanner that this is specifically an ACME endpoint.
        acl_ip = _acl_check_ip(self, config)
        if not is_ip_permitted(acl_ip, config.get('acme_allowed_networks'), config.get('acme_denied_networks'),
                                allowed_label="acme_allowed_networks", denied_label="acme_denied_networks"):
            logger.info("Refusing %s %s from %s: not permitted by acme_allowed_networks/acme_denied_networks",
                        method, self.path, acl_ip)
            try:
                self.send_response(403)
                self.send_header('Content-Length', '0')
                self.end_headers()
            except Exception:
                logger.exception("Failed to send 403 response")
            return

        # A subnet that's been repeatedly failing JWS/EAB authentication
        # (SECURITY_FINDINGS.md finding #17) - checked at the direct TCP
        # peer, same as the netblock ACL above, not the possibly-forwarded
        # acl_ip, since this is about the actual connecting source.
        if _acme_auth_failure_tracker.is_blocked(self.client_address[0]):
            logger.info("Refusing %s %s from %s: blocked subnet (auth failures)", method, self.path, self.client_address[0])
            try:
                self.send_response(403)
                self.send_header('Content-Length', '0')
                self.end_headers()
            except Exception:
                logger.exception("Failed to send 403 response")
            return

        path_only = self.path.split('?', 1)[0]

        route = None
        for route_method, pattern, handler_fn in self.server.acme_routes:
            if route_method != method:
                continue
            match = pattern.match(path_only)
            if match:
                route = (handler_fn, match)
                break
        if route is None:
            try:
                _send_problem(self, config, 404, 'malformed', 'Resource not found')
            except Exception:
                logger.exception("Failed to send 404 response")
            return

        body = self._read_body(config)
        if body is None:
            return  # error response already sent by _read_body()

        session = database.get_db_session()
        try:
            handler_fn, match = route
            handler_fn(self, session, match, body)
        except Exception:
            logger.exception("Unhandled error processing %s %s", method, self.path)
            try:
                _send_problem(self, config, 500, 'serverInternal', 'Internal server error')
            except Exception:
                logger.exception("Failed to send error response")
        finally:
            session.close()

    def _read_body(self, config):
        content_length_header = self.headers.get('Content-Length')
        if not content_length_header:
            return b''
        try:
            content_length = int(content_length_header)
        except ValueError:
            _send_problem(self, config, 400, 'malformed', 'Invalid Content-Length header')
            return None
        if content_length < 0 or content_length > ACME_MAX_BODY_BYTES:
            _send_problem(self, config, 413, 'malformed', 'Request body too large')
            return None
        return self.rfile.read(content_length)
