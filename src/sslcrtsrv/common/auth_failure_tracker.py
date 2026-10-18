# Authentication-failure tracking (SECURITY_FINDINGS.md finding #17): a
# source-IP-keyed lockout for actual auth-failure signals - a registration
# proof mismatch, a rejected message signature, an ACME JWS/EAB mismatch -
# reusing common/http_abuse_tracker.py's proven subnet-abuse state machine
# rather than duplicating it, with tighter constants (fewer strikes, a
# longer block) since these are higher-stakes events than an unknown-URL
# HTTP probe.
#
# Deliberately source-IP-keyed, not keyed on any claimed identity
# (client_id, ACME account, etc.): locking out by a claimed identity alone
# would let an attacker who merely knows/guesses that identifier, with no
# valid key at all, deliberately lock out the legitimate holder of it -
# exactly the DoS vector this design avoids.
from .http_abuse_tracker import HttpAbuseTracker

AUTH_FAILURE_THRESHOLD = 3
AUTH_FAILURE_BLOCK_SECONDS = 15 * 60
AUTH_FAILURE_INACTIVITY_CLEAR_SECONDS = 15 * 60
AUTH_FAILURE_PROBATION_SECONDS = 60 * 60


def new_auth_failure_tracker() -> HttpAbuseTracker:
    """One of these per running server process (the main protocol server
    and the ACME server each get their own) - see is_blocked()/
    record_bad_request()/record_good_request() on the returned tracker."""
    return HttpAbuseTracker(
        threshold=AUTH_FAILURE_THRESHOLD,
        block_seconds=AUTH_FAILURE_BLOCK_SECONDS,
        inactivity_clear_seconds=AUTH_FAILURE_INACTIVITY_CLEAR_SECONDS,
        probation_seconds=AUTH_FAILURE_PROBATION_SECONDS,
    )
