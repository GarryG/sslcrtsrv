"""Country-level access control, checked alongside common/network_acl.py's
netblock allow/deny lists by both common/server_utils.py (the main protocol
server) and common/acme_server_utils.py (the ACME server).

Purely additive defense-in-depth: a GeoIP database is user-provided (not
bundled), and this feature stays fully optional and fails soft - a missing
or unreadable database disables country checks (falling back to the
netblock ACL alone) rather than ever refusing to start or serve. GeoIP
country matching is inherently coarse and bypassable (any VPN/proxy exit
point in an allowed country defeats it) - it reduces exposure to bulk,
region-targeted traffic, and is not a security boundary against a
motivated attacker, exactly like network_acl.py's own netblock lists are
documented as "not a replacement for authentication" (see Manual.MD's
Netblock and GeoIP Access Control section).

Because of that difference in precision, the netblock ACL takes priority
over the GeoIP one whenever it has an explicit opinion about a given
address: an address matching denied_networks is rejected even if its
country is on allowed_countries, and - symmetrically - an address matching
a non-empty allowed_networks is accepted even if its country is on
denied_countries. GeoIP only gets to decide when network_verdict() returns
None, i.e. nothing in allowed_networks/denied_networks had anything to say
about this specific address (see is_access_permitted()). This is deliberate:
an admin who explicitly lists a specific IP/CIDR has made a precise,
intentional decision about it, which should stand regardless of what a
best-effort country lookup says about the same address.

Two backends are supported, both a thin adapter over a finished, official
vendor library - this project does not parse either binary database format
itself:
  - "maxmind" (default): MaxMind DB (.mmdb) via the `maxminddb` package.
    Covers MaxMind's own GeoLite2/GeoIP2 Country databases, and also
    DB-IP's/IPinfo's .mmdb exports, since they're the same file format.
  - "ip2location": IP2Location (.BIN) via the `IP2Location` package.

Adding a third backend later only means adding one more _load_*/
_country_code_* function pair and a _BACKENDS entry below - no change to
config field names, is_country_permitted()/is_access_permitted()'s
signatures, or either server's call sites.
"""
import logging
from typing import Optional

logger = logging.getLogger("sslcrtsrv")


def _load_maxmind(path):
    import maxminddb
    return maxminddb.open_database(path)


def _country_code_maxmind(reader, ip_str):
    record = reader.get(ip_str)
    if not record:
        return None
    return (record.get("country") or {}).get("iso_code")


def _load_ip2location(path):
    import IP2Location
    return IP2Location.IP2Location(path)


def _country_code_ip2location(reader, ip_str):
    return reader.get_country_short(ip_str)


_BACKENDS = {
    "maxmind": (_load_maxmind, _country_code_maxmind),
    "ip2location": (_load_ip2location, _country_code_ip2location),
}


def load_geoip_database(path, backend="maxmind"):
    """Returns an opened database reader, or None (never raises) if path is
    unset, backend is unrecognized, or opening/parsing it fails for any
    reason - every failure is logged here so it isn't silently swallowed by
    a caller that just sees None. A deployment using only one backend never
    needs the other backend's package installed, since each backend's
    import is deferred to its own _load_* function."""
    if not path:
        return None
    entry = _BACKENDS.get(backend)
    if entry is None:
        logger.error("Unknown geoip_backend %r - country-based access control is disabled "
                     "(valid values: %s)", backend, ", ".join(sorted(_BACKENDS)))
        return None
    load_fn, _ = entry
    try:
        return load_fn(path)
    except Exception as e:
        logger.error("Could not open GeoIP database %r (backend=%s): %s - country-based "
                     "access control is disabled until this is fixed", path, backend, e)
        return None


def _country_verdict(ip_str, allowed_countries, denied_countries, geoip_reader, backend="maxmind",
                      allowed_label="allowed_countries", denied_label="denied_countries",
                      detail: Optional[dict] = None):
    """True (explicitly allowed), False (explicitly denied), or None (GeoIP
    not active, or neither list configured/matched anything for this
    address - no opinion either way) - the three-valued counterpart to
    network_acl.network_verdict(), same structure: a non-empty allow list
    always yields an explicit True/False for any address evaluated against
    it, an empty one only ever yields False (via the deny list) or None.
    geoip_reader=None (GeoIP not configured, or its database failed to
    load) always returns None - this dimension never gets to decide on its
    own when it isn't actually active. A lookup miss/exception/unresolvable
    code is treated like a malformed address in network_verdict(): explicit
    False once an allow list is configured (fails closed), otherwise folded
    into "no opinion".

    When `detail` is given and this returns False, it's filled in with
    'label' (which config list decided this) and 'country' (the resolved
    ISO country code, or None if it couldn't be resolved at all) - so a
    caller logging the denial can report the country involved."""
    if geoip_reader is None:
        return None

    _, lookup_fn = _BACKENDS[backend]
    try:
        code = lookup_fn(geoip_reader, ip_str)
    except Exception as e:
        logger.warning("GeoIP lookup failed for %r (backend=%s): %s - treating as unresolvable",
                       ip_str, backend, e)
        code = None

    denied = {c.upper() for c in (denied_countries or [])}
    if code and code.upper() in denied:
        logger.debug("Rejecting %r: country %s matches %s", ip_str, code, denied_label)
        if detail is not None:
            detail['label'] = denied_label
            detail['country'] = code
        return False

    allowed = {c.upper() for c in (allowed_countries or [])}
    if allowed:
        permitted = bool(code) and code.upper() in allowed
        if not permitted:
            logger.debug("Rejecting %r: country %s does not match %s", ip_str, code, allowed_label)
            if detail is not None:
                detail['label'] = allowed_label
                detail['country'] = code
        return permitted

    return None


def is_country_permitted(ip_str, allowed_countries, denied_countries, geoip_reader, backend="maxmind",
                          allowed_label="allowed_countries", denied_label="denied_countries"):
    """Whether ip_str is permitted by the country ACL on its own -
    _country_verdict() with "no opinion" (None) treated as permitted. See
    _country_verdict() for the three-valued form is_access_permitted() uses
    to let an explicit netblock verdict override this one."""
    return _country_verdict(ip_str, allowed_countries, denied_countries, geoip_reader, backend,
                             allowed_label, denied_label) is not False


def is_access_permitted(ip_str, allowed_networks, denied_networks,
                         allowed_countries, denied_countries, geoip_reader, backend="maxmind", *,
                         prefix="", default="allow", detail: Optional[dict] = None):
    """Combined netblock + country ACL check, in this exact order:
      1. ip_str matches an entry in allowed_networks -> permitted, final
         (GeoIP never consulted).
      2. ip_str matches an entry in denied_networks -> denied, final.
      3. ip_str's resolved country matches allowed_countries -> permitted,
         final.
      4. ip_str's resolved country matches denied_countries -> denied, final.
      5. None of the above had an opinion -> `default` decides.

    Only an explicit *match* in either dimension is final - a non-empty
    allowed_networks that simply doesn't cover ip_str is not itself a
    denial, unlike network_verdict()'s own standalone three-valued
    contract (see its docstring): it falls through to let the country
    checks override it instead, so an address merely outside
    allowed_networks can still be permitted by an allowed_countries match.
    But if GeoIP has no opinion either (not configured, or the address's
    country matches neither allowed_countries nor denied_countries), that
    non-matching allowed_networks reverts to being the final answer (denied)
    rather than falling through to `default` - an admin who configured
    allowed_networks with no GeoIP involved at all made a deliberate "only
    these addresses" decision, and `default` (commonly "allow") must not
    silently let everything else through just because GeoIP was never
    actually asked to weigh in. A real denied_networks/denied_countries
    match (steps 2 and 4) is always final, never overridden by a later step.

    `default` is "allow" (the default, preserving this feature's original
    lenient-by-default behavior - no lists configured at all means no
    restriction) or "deny" (a default-deny posture - access requires an
    explicit allow somewhere, in either dimension). Any other value is
    treated as "allow" with a logged warning, the same fail-safe-for-
    availability handling this project gives other malformed policy
    settings, rather than an unrecognized typo silently locking everyone
    out.

    `prefix` selects which config field names appear in log messages
    ("acme_" for the ACME server's fields, "" for the traditional
    server's).

    When `detail` is given and this returns False, it's filled in with
    'dimension' ('netblock', 'geoip', or 'default') plus whatever
    network_verdict()/_country_verdict() themselves added ('label' and
    'network', or 'label' and 'country') - so a caller can log exactly what
    caused the denial (e.g. the matched subnet or resolved country) instead
    of just naming every config field that could have been involved."""
    from .network_acl import network_verdict
    net_detail = {}
    net = network_verdict(ip_str, allowed_networks, denied_networks,
                           allowed_label=f"{prefix}allowed_networks", denied_label=f"{prefix}denied_networks",
                           detail=net_detail)
    if net is True:
        return True
    # network_verdict() returns False both for an explicit denied_networks
    # match and for "allowed_networks is configured but doesn't cover this
    # address" - only the former is a final verdict here; net_detail['label']
    # (set by network_verdict() itself) tells the two apart.
    if net is False and net_detail.get('label') == f"{prefix}denied_networks":
        if detail is not None:
            detail.update(net_detail)
            detail['dimension'] = 'netblock'
        return False

    country = _country_verdict(ip_str, allowed_countries, denied_countries, geoip_reader, backend,
                                allowed_label=f"{prefix}allowed_countries", denied_label=f"{prefix}denied_countries",
                                detail=detail)
    if country is not None:
        if country is False and detail is not None:
            detail['dimension'] = 'geoip'
        return country

    if net is False:
        # Non-matching allowed_networks, and GeoIP had no opinion at all
        # (inactive, or no match in either country list) - the original
        # soft netblock deny stands; `default` never gets a chance to
        # override a configured-but-non-matching allow-list.
        if detail is not None:
            detail.update(net_detail)
            detail['dimension'] = 'netblock'
        return False

    if default == "deny":
        if detail is not None:
            detail['dimension'] = 'default'
        return False
    if default != "allow":
        logger.warning("Unrecognized %saccess_control_default %r - treating as \"allow\" "
                       "(valid values: \"allow\", \"deny\")", prefix, default)
    return True


def describe_denial(detail: dict) -> str:
    """Render the `detail` dict a False is_access_permitted() call filled in
    as a short, human-readable reason for a deny log line - e.g. "denied_networks
    (203.0.113.0/24)" or "denied_countries (country=RU)". Used by both
    server_utils.py and acme_server_utils.py so the two servers' deny log
    lines stay in the same format."""
    dimension = detail.get('dimension')
    if dimension == 'netblock':
        network = detail.get('network')
        return f"{detail['label']}" + (f" ({network})" if network else "")
    if dimension == 'geoip':
        country = detail.get('country')
        return f"{detail['label']} (country={country or 'unresolved'})"
    return "access_control_default=deny"
