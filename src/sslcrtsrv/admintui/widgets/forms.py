from textual import work
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Select

from ... import cltmanager
from ... import crtmanager
from ...common.constants import ACME_PROVIDERS, MANUAL_ACME_PROVIDER
from ...common.database import get_client, get_all_certificates, get_client_certificate_relations
from ...common.notify_utils import NOTIFIER_TYPES, NOTIFICATION_EVENTS, send_test_notification_for
from ..util.capture import silence_stdout
from ..util.notify import notify_safe


class AssignPermissionModal(ModalScreen):
    """Grant a client access to a certificate by FQDNs - the TUI form behind
    `cltmanager.py assign`. The dropdown is just a convenience that fills in
    the text field below it; typing an FQDNs list or a certificate ID
    directly still works exactly as before."""

    DEFAULT_CSS = """
    AssignPermissionModal {
        align: center middle;
    }
    AssignPermissionModal > Vertical {
        width: 60%;
        height: auto;
        border: thick $primary 80%;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, client_id: str):
        super().__init__()
        self.client_id = client_id

    def _unassigned_certificate_options(self):
        """(label, fqdns) pairs for every certificate this client doesn't
        already have a relation (active or pending) for."""
        client = get_client(self.client_id)
        assigned_fqdns = {rel.fqdns for rel in get_client_certificate_relations(client.id)} if client else set()

        options = []
        for cert in get_all_certificates():
            if cert.fqdns in assigned_fqdns:
                continue
            label = cert.fqdns
            if cert.is_staging:
                label += " (staging)"
            options.append((label, cert.fqdns))
        return options

    def compose(self):
        with Vertical():
            yield Label(f"Assign certificate permission to {self.client_id}", classes="section-title")

            options = self._unassigned_certificate_options()
            yield Label("Pick an existing certificate not yet assigned to this client:", classes="form-label")
            yield Select(options, id="cert-select",
                         prompt="Select a certificate..." if options else "No unassigned certificates available")

            yield Label("FQDNs (comma-separated) or certificate ID:", classes="form-label")
            yield Input(placeholder="example.com,www.example.com", id="fqdns-input")
            yield Label("Expires (optional, UTC - e.g. 2026-12-31):", classes="form-label")
            yield Input(placeholder="leave blank for a permission that never expires", id="valid-until-input")
            with Horizontal(classes="form-actions"):
                yield Button("Cancel", id="cancel")
                yield Button("Assign", id="assign", variant="success")

    def on_select_changed(self, event: Select.Changed) -> None:
        # Checking against the "blank"/no-selection sentinel by name
        # (Select.NULL / Select.BLANK) isn't reliable across Textual
        # versions - some don't have it under either name. Every real
        # option's value here is always one of our own fqdns strings, so
        # checking the type is a version-independent way to ignore the
        # blank state instead.
        if event.select.id == "cert-select" and isinstance(event.value, str):
            self.query_one("#fqdns-input", Input).value = event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        fqdns = self.query_one("#fqdns-input", Input).value.strip()
        if not fqdns:
            notify_safe(self.app, "Enter FQDNs or a certificate ID first.", severity="warning")
            return
        valid_until_text = self.query_one("#valid-until-input", Input).value.strip()
        try:
            valid_until = cltmanager.parse_valid_until(valid_until_text)
        except ValueError as e:
            notify_safe(self.app, str(e), severity="warning")
            return
        success, _captured = silence_stdout(cltmanager.assign_certificate_permissions, self.client_id, fqdns, valid_until)
        if success:
            self.dismiss(f"Assigned {fqdns} to {self.client_id}.")
        else:
            self.dismiss(f"Failed to assign {fqdns} to {self.client_id}.")


class SetPermissionExpiryModal(ModalScreen):
    """Change an existing certificate permission's expiry date - the TUI
    form behind `cltmanager.py set_expiry`."""

    DEFAULT_CSS = """
    SetPermissionExpiryModal {
        align: center middle;
    }
    SetPermissionExpiryModal > Vertical {
        width: 60%;
        height: auto;
        border: thick $primary 80%;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, client_id: str, fqdns: str, current_display: str = ""):
        super().__init__()
        self.client_id = client_id
        self.fqdns = fqdns
        # Pre-fill with the current expiry, unless it's one of the
        # placeholder strings meaning "no expiry set" - those should start
        # the field blank (which parse_valid_until() also treats as never).
        self.current_display = "" if current_display in ("Never", "N/A", "") else str(current_display)

    def compose(self):
        with Vertical():
            yield Label(f"Set permission expiry for {self.client_id}", classes="section-title")
            yield Label(f"FQDNs: {self.fqdns}")
            yield Label("Expires (UTC - e.g. 2026-12-31), or 'never':", classes="form-label")
            yield Input(value=self.current_display, placeholder="never", id="valid-until-input")
            with Horizontal(classes="form-actions"):
                yield Button("Cancel", id="cancel")
                yield Button("Set", id="set", variant="success")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        value = self.query_one("#valid-until-input", Input).value.strip()
        try:
            valid_until = cltmanager.parse_valid_until(value)
        except ValueError as e:
            notify_safe(self.app, str(e), severity="warning")
            return
        success, _captured = silence_stdout(cltmanager.set_permission_expiry, self.client_id, self.fqdns, valid_until)
        if success:
            self.dismiss(f"Expiry updated for {self.fqdns}.")
        else:
            self.dismiss(f"Failed to update expiry for {self.fqdns}.")


class AddUpdateCertModal(ModalScreen):
    """Add or update a locally-uploaded ('manual') certificate from key/cert/
    intermediate file paths on the server - the TUI form behind
    `crtmanager.py addlocal`/`update`. Paths are server-local, matching the
    existing CLI's constraint (no upload-from-laptop support)."""

    DEFAULT_CSS = """
    AddUpdateCertModal {
        align: center middle;
    }
    AddUpdateCertModal > Vertical {
        width: 70%;
        height: auto;
        border: thick $primary 80%;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, mode: str = "add"):
        super().__init__()
        self.mode = mode  # "add" or "update"

    def compose(self):
        title = "Add local certificate" if self.mode == "add" else "Update certificate"
        with Vertical():
            yield Label(title, classes="section-title")
            yield Label("Private key file path (PEM):", classes="form-label")
            yield Input(placeholder="/path/to/privkey.pem", id="key-file")
            yield Label("Certificate file path (PEM):", classes="form-label")
            yield Input(placeholder="/path/to/cert.pem", id="cert-file")
            yield Label("Intermediate file path (optional):", classes="form-label")
            yield Input(placeholder="/path/to/chain.pem", id="intermediate-file")
            with Horizontal(classes="form-actions"):
                yield Button("Cancel", id="cancel")
                yield Button("Save", id="save", variant="success")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return

        key_file = self.query_one("#key-file", Input).value.strip()
        cert_file = self.query_one("#cert-file", Input).value.strip()
        intermediate_file = self.query_one("#intermediate-file", Input).value.strip() or None

        if not key_file or not cert_file:
            notify_safe(self.app, "Key file and certificate file are both required.", severity="warning")
            return

        func = crtmanager.addlocalcert if self.mode == "add" else crtmanager.update_certificate
        success, captured = silence_stdout(func, key_file, cert_file, intermediate_file)
        if success:
            self.dismiss(captured.strip().splitlines()[-1] if captured.strip() else "Certificate saved.")
        else:
            self.dismiss(captured.strip().splitlines()[-1] if captured.strip() else "Failed to save certificate.")


class SetProviderModal(ModalScreen):
    """Change which ACME CA (or 'manual') a certificate uses - the TUI form
    behind `crtmanager.py set-provider`."""

    DEFAULT_CSS = """
    SetProviderModal {
        align: center middle;
    }
    SetProviderModal > Vertical {
        width: 60%;
        height: auto;
        border: thick $primary 80%;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, identifier: str):
        super().__init__()
        self.identifier = identifier

    def compose(self):
        options = ", ".join(sorted(ACME_PROVIDERS)) + f", {MANUAL_ACME_PROVIDER}"
        with Vertical():
            yield Label(f"Set ACME provider for {self.identifier}", classes="section-title")
            yield Label(f"Provider ({options}), or a raw ACME directory URL:", classes="form-label")
            yield Input(placeholder=MANUAL_ACME_PROVIDER, id="provider-input")
            with Horizontal(classes="form-actions"):
                yield Button("Cancel", id="cancel")
                yield Button("Set", id="set", variant="success")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        provider = self.query_one("#provider-input", Input).value.strip()
        if not provider:
            notify_safe(self.app, "Enter a provider name or URL.", severity="warning")
            return
        success, captured = silence_stdout(crtmanager.set_certificate_provider, self.identifier, provider)
        self.dismiss(captured.strip().splitlines()[-1] if captured.strip() else
                      ("Provider updated." if success else "Failed to update provider."))


# Per-type field specs for AddUpdateNotifierModal: (field name, label,
# password?, required?, integer?). Field names/requiredness match exactly
# what each common/notify_utils.py _send_notification_*() function reads -
# see their docstrings, or Manual.MD Section 10.2's field table. Deliberately
# excludes webhook's 'headers'/'body_template' (JSON-only, documented
# project-wide as hand-edit-server_config.json-only fields, Section 10.2.2) -
# 'auth_header' covers the common single-auth-header case via this form.
NOTIFIER_TYPE_FIELDS = {
    "email": [
        ("notification_recipient", "Recipient email address", False, True, False),
        ("notification_sender", "Sender (From) address (optional)", False, False, False),
        ("smtp_host", "SMTP host", False, True, False),
        ("smtp_port", "SMTP port (optional, default 587)", False, False, True),
        ("smtp_security", "SMTP security: none/starttls/ssl (optional, default starttls)", False, False, False),
        ("smtp_user", "SMTP username (optional)", False, False, False),
        ("smtp_password", "SMTP password (optional)", True, False, False),
    ],
    "webhook": [
        ("url", "URL", False, True, False),
        ("method", "HTTP method (optional, default POST)", False, False, False),
        ("auth_header", "Auth header, e.g. 'Authorization: Bearer xyz' (optional)", False, False, False),
    ],
    "pushover": [
        ("api_token", "API token", False, True, False),
        ("user_key", "User key", False, True, False),
        ("priority", "Priority (optional)", False, False, True),
        ("sound", "Sound (optional)", False, False, False),
    ],
    "pushsafer": [
        ("private_key", "Private key", False, True, False),
        ("device", "Device (optional)", False, False, False),
        ("icon", "Icon (optional)", False, False, False),
        ("sound", "Sound (optional)", False, False, False),
        ("priority", "Priority (optional)", False, False, True),
    ],
    "gotify": [
        ("server_url", "Server URL", False, True, False),
        ("app_token", "App token", False, True, False),
        ("priority", "Priority (optional, default 5)", False, False, True),
    ],
    "ntfy": [
        ("topic", "Topic", False, True, False),
        ("server_url", "Server URL (optional, default https://ntfy.sh)", False, False, False),
        ("auth_token", "Auth token (optional)", False, False, False),
        ("priority", "Priority (optional)", False, False, True),
    ],
}


class AddUpdateNotifierModal(ModalScreen):
    """Add a new named admin notifier, or edit an existing one's fields/
    routing/rate-limit override - the TUI form behind `scs-server init
    --notifier`/`--notify-on`/`--notification-rate-limit-for`. Renaming an
    existing notifier isn't supported here (the Name field is disabled in
    "update" mode) - delete and re-add under a new name instead, same as
    the CLI has no rename either.

    Dismisses with a result dict describing what to save, or None if
    cancelled - the calling view (NotifiersView) does the actual config
    load/merge/write, mirroring how AddUpdateCertModal only collects form
    data and leaves persistence to its caller.
    """

    DEFAULT_CSS = """
    AddUpdateNotifierModal {
        align: center middle;
    }
    AddUpdateNotifierModal > Vertical {
        width: 76%;
        height: auto;
        max-height: 90%;
        border: thick $primary 80%;
        background: $surface;
        padding: 1 2;
        overflow-y: auto;
    }
    """

    def __init__(self, mode: str = "add", name: str = "", notifier_config: dict = None,
                 routed_events: list = None, rate_limit_override: dict = None,
                 existing_names: set = None):
        super().__init__()
        self.mode = mode  # "add" or "update"
        self.initial_name = name
        self.notifier_config = notifier_config or {}
        self.routed_events = set(routed_events or [])
        self.rate_limit_override = rate_limit_override or {}
        self.existing_names = existing_names or set()

    def compose(self):
        title = "Add notifier" if self.mode == "add" else f"Edit notifier: {self.initial_name}"
        initial_type = self.notifier_config.get("type") or sorted(NOTIFIER_TYPES)[0]

        with Vertical():
            yield Label(title, classes="section-title")

            yield Label("Name:", classes="form-label")
            yield Input(value=self.initial_name, id="notifier-name", disabled=(self.mode == "update"))

            yield Label("Type:", classes="form-label")
            yield Select([(t, t) for t in sorted(NOTIFIER_TYPES)], id="notifier-type",
                         allow_blank=False, value=initial_type)

            for notifier_type, fields in NOTIFIER_TYPE_FIELDS.items():
                with Vertical(id=f"fields-{notifier_type}") as group:
                    group.display = (notifier_type == initial_type)
                    for field_name, label, is_password, required, _is_int in fields:
                        yield Label(label + (" *" if required else ""), classes="form-label")
                        value = self.notifier_config.get(field_name)
                        yield Input(value="" if value is None else str(value),
                                    password=is_password, id=f"field-{notifier_type}-{field_name}")

            yield Label("Route to events:", classes="section-title")
            with Horizontal(classes="form-actions"):
                for event in NOTIFICATION_EVENTS:
                    yield Checkbox(event, value=(event in self.routed_events), id=f"route-{event}")

            yield Label("Rate limit override (optional - blank uses the global default, Section 10.7):",
                        classes="section-title")
            yield Label("Max notifications per window:", classes="form-label")
            yield Input(value=self._override_str("max_notifications"), id="rate-limit-max")
            yield Label("Window (seconds):", classes="form-label")
            yield Input(value=self._override_str("window_seconds"), id="rate-limit-window")

            with Horizontal(classes="form-actions"):
                yield Button("Test", id="test")
                yield Button("Cancel", id="cancel")
                yield Button("Save", id="save", variant="success")

    def _override_str(self, field_name: str) -> str:
        value = self.rate_limit_override.get(field_name)
        return "" if value is None else str(value)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "notifier-type" and isinstance(event.value, str):
            for notifier_type in NOTIFIER_TYPE_FIELDS:
                self.query_one(f"#fields-{notifier_type}", Vertical).display = (notifier_type == event.value)

    def _selected_type(self) -> str:
        return self.query_one("#notifier-type", Select).value

    def _collect_fields(self, notifier_type: str) -> dict:
        """Reads every Input for `notifier_type`'s field group, skipping
        blanks (so an optional field left empty is simply absent from the
        saved notifier config, not stored as an empty string)."""
        fields = {}
        for field_name, _label, _is_password, _required, is_int in NOTIFIER_TYPE_FIELDS[notifier_type]:
            raw = self.query_one(f"#field-{notifier_type}-{field_name}", Input).value.strip()
            if not raw:
                continue
            if is_int:
                try:
                    fields[field_name] = int(raw)
                except ValueError:
                    raise ValueError(f"'{field_name}' must be a number, got '{raw}'")
            else:
                fields[field_name] = raw
        return fields

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        if event.button.id == "test":
            self._test()
            return
        if event.button.id == "save":
            self._save()

    def _validated_form(self):
        """Returns (name, notifier_type, fields) after validating required
        fields, or None (having already shown a notify_safe error) if
        invalid. Shared by Test and Save."""
        name = self.query_one("#notifier-name", Input).value.strip()
        if not name:
            notify_safe(self.app, "Name is required.", severity="warning")
            return None
        if self.mode == "add" and name in self.existing_names:
            notify_safe(self.app, f"A notifier named '{name}' already exists - edit it instead.",
                        severity="warning")
            return None

        notifier_type = self._selected_type()
        try:
            fields = self._collect_fields(notifier_type)
        except ValueError as e:
            notify_safe(self.app, str(e), severity="error")
            return None

        for field_name, _label, _is_password, required, _is_int in NOTIFIER_TYPE_FIELDS[notifier_type]:
            if required and field_name not in fields:
                notify_safe(self.app, f"'{field_name}' is required for type '{notifier_type}'.",
                            severity="warning")
                return None

        return name, notifier_type, fields

    def _test(self):
        validated = self._validated_form()
        if validated is None:
            return
        name, notifier_type, fields = validated
        tmp_config = {"notifiers": {name: {"type": notifier_type, **fields}}}
        notify_safe(self.app, f"Sending a test notification via '{name}'...", severity="information")
        self._test_worker(tmp_config, name)

    @work(thread=True)
    def _test_worker(self, tmp_config: dict, name: str):
        # thread=True: every notifier type's send is a blocking network call
        # (smtplib, or a blocking urllib.request.urlopen) - would otherwise
        # freeze the whole UI. notify_safe() touches app state, so it's
        # marshalled back onto the main thread, same pattern as the old
        # Config tab's removed _send_test_mail_worker.
        success = send_test_notification_for(tmp_config, name)
        message = (f"Test notification sent via '{name}'." if success else
                   f"Failed to send test notification via '{name}' - check the server "
                   f"process's console/log output for details.")
        self.app.call_from_thread(notify_safe, self.app, message,
                                   severity="information" if success else "error")

    def _save(self):
        validated = self._validated_form()
        if validated is None:
            return
        name, notifier_type, fields = validated

        routed_events = [event for event in NOTIFICATION_EVENTS
                          if self.query_one(f"#route-{event}", Checkbox).value]

        rate_limit_override = {}
        max_str = self.query_one("#rate-limit-max", Input).value.strip()
        window_str = self.query_one("#rate-limit-window", Input).value.strip()
        try:
            if max_str:
                rate_limit_override["max_notifications"] = int(max_str)
            if window_str:
                rate_limit_override["window_seconds"] = int(window_str)
        except ValueError:
            notify_safe(self.app, "Rate limit max/window must be numbers.", severity="error")
            return

        self.dismiss({
            "name": name,
            "type": notifier_type,
            "fields": fields,
            "routed_events": routed_events,
            "rate_limit_override": rate_limit_override,  # {} means "no override"
        })
