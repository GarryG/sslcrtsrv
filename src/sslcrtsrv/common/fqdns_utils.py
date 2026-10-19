"""Parsing a user/admin-supplied FQDNs (or FQDNs-glob-pattern) string the
same way everywhere it's accepted as a delimited list - split on commas
AND/OR whitespace (any mix, any amount) rather than commas only, so a value
quoted as one shell argument with spaces instead of commas (e.g.
`scs-client request "a.example.com b.example.com"`, picked up by argparse's
`nargs='+'` as a single token since the shell already merged it before argv
ever reached Python) still parses into separate entries instead of being
treated as one bogus value containing literal spaces. No real hostname or
glob pattern ever contains whitespace, so treating it as an additional
separator is unambiguous and safe.

Used on both the client and server side for the exact-match fqdns case (see
issue.md's entry on this) so the two always agree on the canonical form
regardless of which single code path produced the string - a malformed
value from any one caller no longer silently becomes a wrong lookup/storage
key for every other caller.
"""
import re


def split_fqdns(fqdns_string: str) -> list:
    """The raw split: a list of non-empty, stripped entries, in their
    original order (not deduplicated or sorted) - what a glob-pattern list
    (ACME trust grants' allowed_fqdns_pattern) needs, since order/duplicates
    don't affect an any()-style match. normalize_fqdns() builds on this for
    the exact-match canonical-key case, which does need dedup+sort."""
    return [e for e in re.split(r'[,\s]+', fqdns_string.strip()) if e]


def normalize_fqdns(fqdns_string: str) -> str:
    """Canonicalize into the comma-joined, alphabetically-sorted,
    deduplicated form every Certificate/ClientCertificateRelation/AcmeOrder
    row uses as its `fqdns` key. Returns '' for an empty/all-separator
    input."""
    unique_entries = list(dict.fromkeys(split_fqdns(fqdns_string)))
    unique_entries.sort()
    return ','.join(unique_entries)
