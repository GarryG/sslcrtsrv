# Admin notifications - a new client registered and is waiting to be
# confirmed, a confirmed client requested a new certificate that's waiting
# to be assigned, or the server itself hit a genuine operational problem.
#
# Delivery is pluggable: one or more independently-named "notifiers" (each
# of a "type" - email, webhook, or a specific push-notification API) can be
# configured in server_config.json, and each of the three events above can
# be routed to any subset of them. See resolve_notifiers_and_routing()'s
# docstring for the config schema.

import json
import smtplib
import threading
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage
from typing import Callable, Dict, Tuple

from .system_utils import get_fqdn

DEFAULT_SMTP_PORT = 587
DEFAULT_SMTP_SECURITY = "starttls"  # "none" | "starttls" | "ssl"
DEFAULT_SMTP_TIMEOUT = 10

# Timeout for the non-email notifier types' HTTP calls - a separate constant
# from DEFAULT_SMTP_TIMEOUT (same pattern: each delivery mechanism owns its
# own timeout rather than sharing one across unrelated protocols).
DEFAULT_NOTIFIER_HTTP_TIMEOUT = 10

# The three things a notifier can be routed to. "error" has no legacy
# equivalent - see resolve_notifiers_and_routing().
NOTIFICATION_EVENTS = ("registration", "certificate_request", "error")

# How long a repeating error condition (e.g. accept() failing in a tight
# loop under resource exhaustion) is suppressed after the first notification
# for the same error_key, so one ongoing problem doesn't turn into a
# notification per failed iteration. There is no other rate-limiting
# anywhere in this codebase to lean on, so this is intentionally the
# smallest mechanism that covers the one hook point that can actually repeat
# (see notify_error()'s callers in server_utils.py/server.py).
ERROR_NOTIFICATION_COOLDOWN_SECONDS = 300

_last_error_notification: Dict[str, float] = {}
_last_error_notification_lock = threading.Lock()

# Caps how many notifications may be sent to any one *notifier* (by name)
# within a rolling time window, so a burst of triggering events (many
# registrations/certificate requests in a short time, or an error condition
# not already covered by ERROR_NOTIFICATION_COOLDOWN_SECONDS above, since
# that one only suppresses repeats of the *same* error_key) can't flood
# whatever's actually on the other end of a notifier - an inbox, a phone, a
# paid push API with its own quota. Distinct from, and independent of, the
# per-error_key cooldown above; both can apply to the same notify_error()
# call.
#
# Configured via server_config.json's/client_config.json's optional
# "notification_rate_limit" (global default) and "notification_rate_limits"
# (per-notifier-name overrides, keyed by notifier name - not by type or
# event, since the actual rate-limited resource is one specific account/
# endpoint) - see _resolve_rate_limit()'s docstring for the exact schema.
# Both max_notifications and window_seconds can be overridden per notifier
# name independently, so one Pushover notifier can have a tighter window
# than another even though they share a type.
#
# Purely in-memory, per-process state (same limitation as
# _last_error_notification above) - meaningful for the long-running server
# process, but not across separate crtrequest.py/client.py --notify
# invocations, each a fresh process with its own empty counters; those
# callers already send at most one notification per run anyway (Section
# 10.3), so this doesn't need to survive a process restart to do its job.
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 300
DEFAULT_RATE_LIMIT_MAX_NOTIFICATIONS = 10

_rate_limit_state: Dict[str, Dict[str, float]] = {}
_rate_limit_lock = threading.Lock()


def _resolve_rate_limit(config: dict, notifier_name: str) -> Tuple[int, int]:
    """Returns (max_notifications, window_seconds) that apply to
    `notifier_name`, combining:
      - server_config.json's/client_config.json's optional
        "notification_rate_limit": {"max_notifications": N, "window_seconds": W} -
        the global default, applied when no more specific override exists.
      - "notification_rate_limits": {"<notifier name>": {"max_notifications": N,
        "window_seconds": W}} - a per-notifier-name override; either field
        may be given on its own, in which case the other still falls back
        to the global default above (not this module's hardcoded default),
        so a custom global window is respected by every override that
        doesn't set its own.
    With neither key present at all, falls back to this module's own
    DEFAULT_RATE_LIMIT_MAX_NOTIFICATIONS/DEFAULT_RATE_LIMIT_WINDOW_SECONDS.
    """
    global_limit = config.get("notification_rate_limit") or {}
    global_max = global_limit.get("max_notifications", DEFAULT_RATE_LIMIT_MAX_NOTIFICATIONS)
    global_window = global_limit.get("window_seconds", DEFAULT_RATE_LIMIT_WINDOW_SECONDS)

    override = (config.get("notification_rate_limits") or {}).get(notifier_name) or {}
    max_notifications = override.get("max_notifications", global_max)
    window_seconds = override.get("window_seconds", global_window)
    return max_notifications, window_seconds


def _check_rate_limit(config: dict, notifier_name: str) -> Tuple[bool, bool]:
    """Records one notification attempt for `notifier_name` and returns
    (allowed, is_last_before_cap).

    `allowed` is False if this notifier has already reached its cap for the
    current window - the caller must not actually send in that case.
    `is_last_before_cap` is True exactly once per window: on the
    notification that brings the count up to (not past) the configured max,
    since that's the last one the admin will actually see before this
    notifier goes quiet until the window rolls over - the caller should
    append a note to that one message saying so.

    A `max_notifications` of 0 or less disables the cap entirely for this
    notifier (always allowed, is_last_before_cap always False) - the escape
    hatch for a notifier that should never be rate-limited regardless of
    the configured global default.
    """
    max_notifications, window_seconds = _resolve_rate_limit(config, notifier_name)
    if max_notifications is None or max_notifications <= 0:
        return True, False

    now = time.monotonic()
    with _rate_limit_lock:
        state = _rate_limit_state.get(notifier_name)
        if state is None or now - state["window_start"] >= window_seconds:
            state = {"window_start": now, "count": 0}
            _rate_limit_state[notifier_name] = state

        if state["count"] >= max_notifications:
            return False, False

        state["count"] += 1
        return True, state["count"] == max_notifications


def _send_notification_email(config: dict, context: str, subject: str, body: str) -> bool:
    """Best-effort email to the admin. Never raises - a failure here (missing
    config, unreachable SMTP server, auth failure, ...) must never affect the
    operation that triggered it, which has already completed successfully by
    the time this is called. Returns True/False only so the caller can log
    the outcome. `context` is just used to make the "not fully configured"
    warning specific to whichever notification tried to send.
    """
    recipient = config.get("notification_recipient")
    if not recipient:
        return False  # notifications not configured - nothing to do

    smtp_host = config.get("smtp_host")
    if not smtp_host:
        print(f"Warning: 'notification_recipient' is configured but 'smtp_host' is not - "
              f"cannot send {context} notification email.")
        return False

    smtp_port = config.get("smtp_port") or DEFAULT_SMTP_PORT
    smtp_security = (config.get("smtp_security") or DEFAULT_SMTP_SECURITY).lower()
    smtp_user = config.get("smtp_user")
    smtp_password = config.get("smtp_password")
    smtp_timeout = config.get("smtp_timeout") or DEFAULT_SMTP_TIMEOUT
    sender = config.get("notification_sender") or f"sslcrtsrv@{get_fqdn()}"

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    message.set_content(body)

    try:
        smtp_class = smtplib.SMTP_SSL if smtp_security == "ssl" else smtplib.SMTP
        with smtp_class(smtp_host, smtp_port, timeout=smtp_timeout) as smtp:
            if smtp_security == "starttls":
                smtp.starttls()
            if smtp_user:
                smtp.login(smtp_user, smtp_password or "")
            smtp.send_message(message)
        return True
    except Exception as e:
        print(f"Warning: failed to send {context} notification email: {e}")
        return False


def _render_body_template(template, event: str, subject: str, message: str):
    """Recursively substitutes `{{event}}`/`{{subject}}`/`{{message}}`
    placeholders into string values anywhere inside `template` (a JSON-
    shaped dict/list/str, exactly as it appears in server_config.json's
    webhook `body_template` field), leaving every other value untouched.

    Plain string substitution rather than str.format(): a JSON body's own
    structural braces (`{"key": "value"}`) would otherwise need doubling to
    avoid being misread as format fields, which is an easy mistake to make
    by hand in a config file. The double-brace `{{...}}` placeholders can't
    collide with JSON's own single-brace syntax, so no escaping is ever
    needed in a template.

    Substituting into the *dict/list structure* first and only then calling
    json.dumps() on the result (see _send_notification_webhook()) - rather
    than substituting into an already-serialized JSON string - is what
    makes this safe against a subject/message containing quotes, backslashes,
    or newlines: json.dumps() escapes those correctly; naive text
    substitution into a JSON string would not, and could silently produce
    invalid JSON the receiving service rejects.
    """
    if isinstance(template, str):
        return (template.replace("{{event}}", event)
                         .replace("{{subject}}", subject)
                         .replace("{{message}}", message))
    if isinstance(template, dict):
        return {key: _render_body_template(value, event, subject, message) for key, value in template.items()}
    if isinstance(template, list):
        return [_render_body_template(item, event, subject, message) for item in template]
    return template


def _send_notification_webhook(notifier_config: dict, context: str, subject: str, body: str) -> bool:
    """Generic HTTP notifier for anything that isn't one of the specific
    services below - a JSON POST (by default) carrying the event/subject/
    message, or a custom JSON shape if `body_template` is given (see
    _render_body_template()'s docstring - this is what makes services with
    their own required JSON field names, e.g. Slack/Discord/Telegram/
    Pushbullet/Bark/Pushcut, usable here without a dedicated type: Manual.MD
    Section 10.2.2 has a worked example for each). `headers` (a dict) gives
    full control when hand-editing server_config.json; `auth_header` is a
    CLI-friendly single-string shortcut for the common "one auth header"
    case (e.g. "Authorization: Bearer xyz"), since a nested dict isn't
    expressible via the flat `--notifier NAME:TYPE:key=value,...` CLI
    shorthand.
    """
    url = notifier_config.get("url")
    if not url:
        print(f"Warning: webhook notifier is missing 'url' - cannot send {context} notification.")
        return False

    method = (notifier_config.get("method") or "POST").upper()
    body_template = notifier_config.get("body_template")
    if body_template is not None:
        rendered = _render_body_template(body_template, event=context, subject=subject, message=body)
    else:
        rendered = {"event": context, "subject": subject, "message": body}
    payload = json.dumps(rendered).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    headers.update(notifier_config.get("headers") or {})
    auth_header = notifier_config.get("auth_header")
    if auth_header and ":" in auth_header:
        header_name, header_value = auth_header.split(":", 1)
        headers[header_name.strip()] = header_value.strip()

    request = urllib.request.Request(url, data=payload, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_NOTIFIER_HTTP_TIMEOUT) as response:
            return 200 <= response.status < 300
    except Exception as e:
        print(f"Warning: failed to send {context} notification via webhook: {e}")
        return False


def _send_notification_pushover(notifier_config: dict, context: str, subject: str, body: str) -> bool:
    """https://pushover.net/api - form-encoded POST, not JSON."""
    api_token = notifier_config.get("api_token")
    user_key = notifier_config.get("user_key")
    if not api_token or not user_key:
        print(f"Warning: pushover notifier is missing 'api_token'/'user_key' - "
              f"cannot send {context} notification.")
        return False

    fields = {"token": api_token, "user": user_key, "title": subject, "message": body}
    if notifier_config.get("priority") is not None:
        fields["priority"] = notifier_config["priority"]
    if notifier_config.get("sound"):
        fields["sound"] = notifier_config["sound"]

    data = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request("https://api.pushover.net/1/messages.json", data=data, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_NOTIFIER_HTTP_TIMEOUT) as response:
            return 200 <= response.status < 300
    except Exception as e:
        print(f"Warning: failed to send {context} notification via Pushover: {e}")
        return False


def _send_notification_pushsafer(notifier_config: dict, context: str, subject: str, body: str) -> bool:
    """https://www.pushsafer.com/en/pushapi - form-encoded POST, not JSON
    (unlike most of the other services natively supported here, Pushsafer
    has no documented JSON option at all, so - unlike Pushbullet/Bark/
    Pushcut/Telegram/Discord/Slack, all of which are just a `webhook`
    notifier with a `body_template`, Manual.MD Section 10.2.2 - this
    genuinely needs its own sender)."""
    private_key = notifier_config.get("private_key")
    if not private_key:
        print(f"Warning: pushsafer notifier is missing 'private_key' - cannot send {context} notification.")
        return False

    fields = {"k": private_key, "t": subject, "m": body}
    if notifier_config.get("device"):
        fields["d"] = notifier_config["device"]
    if notifier_config.get("icon"):
        fields["i"] = notifier_config["icon"]
    if notifier_config.get("sound"):
        fields["s"] = notifier_config["sound"]
    if notifier_config.get("priority") is not None:
        fields["pr"] = notifier_config["priority"]

    data = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request("https://www.pushsafer.com/api", data=data, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_NOTIFIER_HTTP_TIMEOUT) as response:
            return 200 <= response.status < 300
    except Exception as e:
        print(f"Warning: failed to send {context} notification via Pushsafer: {e}")
        return False


def _send_notification_gotify(notifier_config: dict, context: str, subject: str, body: str) -> bool:
    """https://gotify.net/api-docs - JSON POST to a self-hosted server."""
    server_url = (notifier_config.get("server_url") or "").rstrip("/")
    app_token = notifier_config.get("app_token")
    if not server_url or not app_token:
        print(f"Warning: gotify notifier is missing 'server_url'/'app_token' - "
              f"cannot send {context} notification.")
        return False

    payload = json.dumps({
        "title": subject,
        "message": body,
        "priority": notifier_config.get("priority", 5),
    }).encode("utf-8")
    url = f"{server_url}/message?token={urllib.parse.quote(app_token)}"
    request = urllib.request.Request(url, data=payload, method="POST",
                                      headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_NOTIFIER_HTTP_TIMEOUT) as response:
            return 200 <= response.status < 300
    except Exception as e:
        print(f"Warning: failed to send {context} notification via Gotify: {e}")
        return False


def _send_notification_ntfy(notifier_config: dict, context: str, subject: str, body: str) -> bool:
    """https://docs.ntfy.sh/publish/ - plain-text POST, subject carried via
    the Title header. Defaults to the public ntfy.sh instance; set
    'server_url' for a self-hosted one."""
    server_url = (notifier_config.get("server_url") or "https://ntfy.sh").rstrip("/")
    topic = notifier_config.get("topic")
    if not topic:
        print(f"Warning: ntfy notifier is missing 'topic' - cannot send {context} notification.")
        return False

    headers = {"Title": subject, "Content-Type": "text/plain; charset=utf-8"}
    auth_token = notifier_config.get("auth_token")
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    if notifier_config.get("priority"):
        headers["Priority"] = str(notifier_config["priority"])

    request = urllib.request.Request(f"{server_url}/{topic}", data=body.encode("utf-8"),
                                      method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_NOTIFIER_HTTP_TIMEOUT) as response:
            return 200 <= response.status < 300
    except Exception as e:
        print(f"Warning: failed to send {context} notification via ntfy: {e}")
        return False


# Maps a notifier's "type" field to the function that delivers through it.
# Every entry has the same (notifier_config, context, subject, body) -> bool
# signature, including "email" (unchanged from before this dict existed).
NOTIFIER_TYPES: Dict[str, Callable[[dict, str, str, str], bool]] = {
    "email": _send_notification_email,
    "webhook": _send_notification_webhook,
    "pushover": _send_notification_pushover,
    "pushsafer": _send_notification_pushsafer,
    "gotify": _send_notification_gotify,
    "ntfy": _send_notification_ntfy,
}

def resolve_notifiers_and_routing(config: dict) -> Tuple[Dict[str, dict], Dict[str, list]]:
    """Returns (notifiers, routing) - notifiers is {name: {"type": ..., ...}},
    routing is {event: [notifier names]} for event in NOTIFICATION_EVENTS.

    Pure read of the "notifiers"/"notification_routing" schema - a missing
    key defaults to {}.
    """
    return config.get("notifiers") or {}, config.get("notification_routing") or {}


def notify_admin(config: dict, event: str, subject: str, body: str) -> bool:
    """Dispatch one admin notification to every notifier routed to `event`.
    Best-effort per notifier - one failing/misconfigured notifier never
    prevents the others from being tried, and this never raises. Returns
    True if at least one routed notifier reported success (False if none
    were routed, or all of them failed)."""
    notifiers, routing = resolve_notifiers_and_routing(config)
    any_succeeded = False
    for name in routing.get(event, []):
        notifier_config = notifiers.get(name)
        if not notifier_config:
            print(f"Warning: notification routing for '{event}' references unknown notifier "
                  f"'{name}' - skipping.")
            continue

        notifier_type = notifier_config.get("type")
        sender_fn = NOTIFIER_TYPES.get(notifier_type)
        if not sender_fn:
            print(f"Warning: notifier '{name}' has unknown type '{notifier_type}' - skipping.")
            continue

        allowed, is_last_before_cap = _check_rate_limit(config, name)
        if not allowed:
            print(f"Warning: notifier '{name}' has reached its notification rate limit - "
                  f"suppressing this {event} notification.")
            continue

        send_body = body
        if is_last_before_cap:
            send_body = (
                f"{body}\n\n"
                f"Note: notifier '{name}' has reached its notification rate limit for the "
                f"current window - additional notifications may be waiting and will be "
                f"suppressed until the window resets."
            )

        try:
            if sender_fn(notifier_config, event, subject, send_body):
                any_succeeded = True
        except Exception as e:
            print(f"Warning: notifier '{name}' ({notifier_type}) raised while sending "
                  f"{event} notification: {e}")
    return any_succeeded


def notify_error(config: dict, error_key: str, subject: str, body: str) -> bool:
    """Like notify_admin(config, "error", ...), but suppresses repeat
    notifications for the same error_key within
    ERROR_NOTIFICATION_COOLDOWN_SECONDS - see that constant's comment for
    why (an ongoing failure that repeats in a tight loop, e.g. the accept()
    loop under resource exhaustion, must not turn into one notification per
    iteration). Returns False (without even attempting delivery) if still
    within the cooldown for this error_key."""
    now = time.monotonic()
    with _last_error_notification_lock:
        last = _last_error_notification.get(error_key, 0.0)
        if now - last < ERROR_NOTIFICATION_COOLDOWN_SECONDS:
            return False
        _last_error_notification[error_key] = now
    return notify_admin(config, "error", subject, body)


def send_test_notification_for(config: dict, notifier_name: str) -> bool:
    """CLI equivalent of admintui's "Send test mail" button, generalized to
    any configured notifier (including the legacy-synthesized "email" one,
    so this works even on an untouched pre-existing config) - `server.py
    test-notifier --notifier-name <name>`. Without this, a broken
    Pushover/Gotify/etc. config would have no way to be verified before
    being depended on for real."""
    notifiers, _ = resolve_notifiers_and_routing(config)
    notifier_config = notifiers.get(notifier_name)
    if not notifier_config:
        print(f"Error: no notifier named '{notifier_name}' is configured.")
        return False

    notifier_type = notifier_config.get("type")
    sender_fn = NOTIFIER_TYPES.get(notifier_type)
    if not sender_fn:
        print(f"Error: notifier '{notifier_name}' has unknown type '{notifier_type}'.")
        return False

    subject = f"[sslcrtsrv] Test notification via '{notifier_name}' ({notifier_type})"
    body = (
        f"This is a test message from the SSL Certificate Server, confirming that "
        f"the '{notifier_name}' notifier ({notifier_type}) is correctly configured "
        f"and can deliver messages.\n"
    )
    return sender_fn(notifier_config, "test", subject, body)


def send_registration_notification(config: dict, client_id: str, public_key_fingerprint: str) -> bool:
    """Notify the admin that a new client registered and is waiting to be
    confirmed."""
    subject = f"[sslcrtsrv] New client registered: {client_id}"
    body = (
        "A new client has registered with the SSL Certificate Server and is "
        "waiting to be confirmed.\n\n"
        f"Client ID: {client_id}\n"
        f"Public key fingerprint: {public_key_fingerprint}\n\n"
        "Verify this fingerprint out-of-band with the client administrator "
        f"before confirming the registration, e.g.:\n"
        f"  cltmanager.py confirm {client_id}\n"
    )
    return notify_admin(config, "registration", subject, body)


def send_acme_registration_notification(config: dict, client_id: str, thumbprint: str) -> bool:
    """Notify the admin that a new ACME account self-registered and is
    waiting to be confirmed (ACME_SERVER_DESIGN.md §5.3/§5.6) - a dedicated
    sibling of send_registration_notification() rather than a branch inside
    it, since the message content genuinely differs: an ACME account's
    canonical identity is its RFC 7638 JWK thumbprint (not a PEM/SPKI
    fingerprint), and it's confirmed via `cltmanager.py acme_confirm`, not
    `confirm`."""
    subject = f"[sslcrtsrv] New ACME account registered: {client_id}"
    body = (
        "A new ACME account has self-registered and is waiting to be "
        "confirmed.\n\n"
        f"Client ID: {client_id}\n"
        f"JWK thumbprint (RFC 7638): {thumbprint}\n\n"
        "Verify this thumbprint out-of-band with the account's operator "
        f"before confirming the registration, e.g.:\n"
        f"  cltmanager.py acme_confirm {client_id}\n"
    )
    return notify_admin(config, "registration", subject, body)


def send_acme_trust_grant_registration_notification(config: dict, client_id: str, thumbprint: str,
                                                      grant_label: str) -> bool:
    """Notify the admin that a new ACME account self-registered and was
    *already auto-confirmed* via a pre-shared trust grant (EAB or
    contact-token, see common/database.py's AcmeTrustGrant) - a distinctly-
    worded sibling of send_acme_registration_notification() rather than a
    flag on it, since no action is needed here (unlike that one, which
    exists specifically to prompt an admin to go run acme_confirm): this is
    pure visibility, so an admin always knows every account that gets
    minted, trusted-path or not, and can revoke the grant immediately if an
    unexpected registration looks wrong."""
    subject = f"[sslcrtsrv] New ACME account auto-confirmed via trust grant: {client_id}"
    body = (
        f"A new ACME account self-registered and was automatically confirmed "
        f"via the pre-shared trust grant '{grant_label}' - no admin action is "
        f"needed.\n\n"
        f"Client ID: {client_id}\n"
        f"JWK thumbprint (RFC 7638): {thumbprint}\n\n"
        f"If this registration is unexpected, revoke the grant immediately:\n"
        f"  cltmanager.py acme_revoke_trust_grant <grant id>\n"
    )
    return notify_admin(config, "registration", subject, body)


def send_certificate_request_notification(config: dict, client_id: str, fqdns: str) -> bool:
    """Notify the admin that a confirmed client requested a new certificate
    that's waiting to be assigned."""
    subject = f"[sslcrtsrv] New certificate request from {client_id}: {fqdns}"
    body = (
        "A client has requested a new certificate and is waiting for it to "
        "be assigned.\n\n"
        f"Client ID: {client_id}\n"
        f"FQDNs: {fqdns}\n\n"
        "Assign it, e.g.:\n"
        f"  cltmanager.py assign {client_id} {fqdns}\n"
    )
    return notify_admin(config, "certificate_request", subject, body)
