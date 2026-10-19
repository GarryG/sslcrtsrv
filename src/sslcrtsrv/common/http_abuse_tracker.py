# Tracks requests for unknown/invalid URLs against the server's plain-HTTP
# client-package endpoints (common/server_utils.py's handle_http_download())
# and blocks abusive /24 subnets from connecting to the server's port at
# all - both the HTTP path and the regular signed/encrypted protocol, since
# the block is enforced by Server.start_server()'s accept loop, before
# either protocol is even identified.
#
# Per-source-IP state machine:
#
#   1. Accumulating: each bad (unknown-URL) request increments that IP's
#      counter and refreshes its last-seen time. The record is forgotten
#      entirely if INACTIVITY_CLEAR_SECONDS pass with no further bad
#      request from it, or immediately on any correct/known-URL request
#      (record_good_request()) - whichever comes first.
#
#   2. Triggered: the moment either that one IP's own count reaches
#      BAD_REQUEST_THRESHOLD, or the combined count across every IP
#      currently tracked in its /24 subnet reaches BAD_REQUEST_THRESHOLD,
#      the whole /24 is blocked from connecting to the port at all for
#      BLOCK_SECONDS - not just that one IP, since a distributed scan
#      rotating through addresses in the same /24 would otherwise dodge
#      this entirely by never repeating an IP.
#
#   3. Probation, for PROBATION_SECONDS after the block above expires:
#      every IP that was part of the triggering subnet stays tracked; a
#      single further bad request from any of them instantly re-triggers
#      another BLOCK_SECONDS-long subnet block and restarts this
#      probation window from that new request's timestamp (not the
#      original one) - so a subnet that keeps offending never actually
#      gets to the "forgotten" state, only one that goes quiet for the
#      full window does.

import ipaddress
import threading
import time
from typing import Dict

BAD_REQUEST_THRESHOLD = 5
BLOCK_SECONDS = 5 * 60
INACTIVITY_CLEAR_SECONDS = 5 * 60
PROBATION_SECONDS = 30 * 60


def _subnet_of(ip: str) -> str:
    """The /24 network an IPv4 address belongs to, as a string key (e.g.
    "192.168.1.0/24"). Only ever called with addresses accepted by
    Server.setup_server(), which only ever listens on socket.AF_INET
    (IPv4) - an unparseable address falls back to being its own subnet of
    one rather than raising and breaking connection handling over this."""
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return ip


class HttpAbuseTracker:
    """One instance per running Server - a plain in-memory ("temporary")
    tracker, deliberately not persisted anywhere, so a server restart
    always starts with a clean slate.

    Despite the name (kept for compatibility with existing call sites),
    the logic here is generic - a source-IP/subnet abuse tracker, not
    HTTP-specific. common/auth_failure_tracker.py reuses this exact class
    with tighter constants for authentication-failure tracking (SECURITY_
    FINDINGS.md finding #17) rather than duplicating this state machine."""

    def __init__(self, threshold: int = BAD_REQUEST_THRESHOLD, block_seconds: float = BLOCK_SECONDS,
                 inactivity_clear_seconds: float = INACTIVITY_CLEAR_SECONDS,
                 probation_seconds: float = PROBATION_SECONDS):
        self._lock = threading.Lock()
        self._records: Dict[str, dict] = {}  # ip -> {"last_bad": float, "count": int, "in_probation": bool}
        self._subnet_blocked_until: Dict[str, float] = {}
        self._threshold = threshold
        self._block_seconds = block_seconds
        self._inactivity_clear_seconds = inactivity_clear_seconds
        self._probation_seconds = probation_seconds

    def is_blocked(self, ip: str) -> bool:
        """True if `ip`'s /24 subnet is currently under an active block -
        checked by Server.start_server()'s accept loop for *every* new
        connection, before any protocol (HTTP or the regular signed/
        encrypted one) is identified."""
        now = time.monotonic()
        subnet = _subnet_of(ip)
        with self._lock:
            blocked_until = self._subnet_blocked_until.get(subnet)
            if blocked_until is None:
                return False
            if now >= blocked_until:
                del self._subnet_blocked_until[subnet]
                return False
            return True

    def record_good_request(self, ip: str) -> None:
        """A known/correct URL was requested - forget this IP's bad-request
        history entirely, regardless of what phase it was in."""
        with self._lock:
            self._records.pop(ip, None)

    def record_bad_request(self, ip: str) -> None:
        """An unknown/invalid URL was requested - update this IP's record
        and trigger a subnet block if warranted (see the module docstring's
        state machine)."""
        now = time.monotonic()
        subnet = _subnet_of(ip)
        with self._lock:
            self._prune_expired_locked(now)

            record = self._records.setdefault(ip, {"last_bad": now, "count": 0, "in_probation": False})
            record["last_bad"] = now
            record["count"] += 1

            if record["in_probation"]:
                # Any single bad request during probation re-triggers
                # instantly - no need to reach the threshold again.
                self._trigger_block_locked(subnet, now)
                return

            subnet_total = sum(
                other["count"] for other_ip, other in self._records.items()
                if _subnet_of(other_ip) == subnet
            )
            if record["count"] >= self._threshold or subnet_total >= self._threshold:
                self._trigger_block_locked(subnet, now)

    def _trigger_block_locked(self, subnet: str, now: float) -> None:
        self._subnet_blocked_until[subnet] = now + self._block_seconds
        # Every IP that contributed to (or was already implicated by) this
        # subnet's block moves into probation together, timed from this
        # same trigger - otherwise a different IP in the same subnet,
        # still only "accumulating", could keep probing at the original
        # 5-strikes pace instead of the stricter one-strike probation rule.
        for other_ip, other in self._records.items():
            if _subnet_of(other_ip) == subnet:
                other["in_probation"] = True
                other["last_bad"] = now

    def _prune_expired_locked(self, now: float) -> None:
        expired = [
            ip for ip, record in self._records.items()
            if now - record["last_bad"] > (
                (self._block_seconds + self._probation_seconds) if record["in_probation"]
                else self._inactivity_clear_seconds
            )
        ]
        for ip in expired:
            del self._records[ip]
