"""Shared netblock/subnet allow-list and deny-list matching, used by both
common/server_utils.py (the main protocol server) and
common/acme_server_utils.py (the ACME server) to gate which source IPs may
reach their listening ports at all - independent of, and checked before,
either server's own authentication (registration proof / JWS verification)
or the per-account IP-pinning feature (Client.allowed_source_ip,
acme_server_utils.py's _source_ip_allowed()).

Deny-then-allow semantics, the standard firewall-ACL order:
  1. Denied (matches an entry in denied_networks) -> rejected, always.
  2. Not denied, and allowed_networks is non-empty -> permitted only if it
     matches an entry there.
  3. Not denied, and allowed_networks is empty/absent -> permitted (no
     restriction configured), matching this project's existing
     lenient-by-default config convention (bind_also, syslog_host, etc. are
     all "off" when absent).
"""
import ipaddress
import logging

logger = logging.getLogger("sslcrtsrv")


def _parse_networks(entries, list_label):
    """Parse a list of bare-IP/CIDR strings into ip_network objects,
    skipping (and warning about) individually malformed entries rather than
    aborting startup - the same lenient-per-entry handling
    server_utils.py's parse_bind_entry() already uses for bind_also."""
    networks = []
    for entry in entries or []:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as e:
            logger.warning("Ignoring invalid entry %r in %s: %s", entry, list_label, e)
    return networks


def is_ip_permitted(ip_str, allowed_networks, denied_networks,
                     allowed_label="allowed_networks", denied_label="denied_networks"):
    """Whether ip_str (a bare address string, e.g. a TCP peer or a resolved
    X-Forwarded-For value) is permitted, per the deny-then-allow order
    above. allowed_networks/denied_networks are the raw config lists (bare
    IP/CIDR strings) - parsed here on every call, matching the same
    not-pre-cached style _source_ip_allowed() already uses elsewhere in this
    codebase for the same kind of check. A malformed ip_str fails closed
    (rejected) rather than raising into the caller. allowed_label/denied_label
    are only used in log messages, so callers using differently-named config
    fields (e.g. acme_allowed_networks) get accurate warnings."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        logger.warning("Rejecting connection: could not parse source address %r", ip_str)
        return False

    for network in _parse_networks(denied_networks, denied_label):
        if ip in network:
            return False

    allowed = _parse_networks(allowed_networks, allowed_label)
    if allowed:
        return any(ip in network for network in allowed)

    return True
