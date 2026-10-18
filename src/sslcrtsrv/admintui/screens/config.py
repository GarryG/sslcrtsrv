from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Checkbox, Input, Label, Select, Static

from ... import server
from ...common.constants import (
    ACME_PROVIDERS, MANUAL_ACME_PROVIDER, DEFAULT_SERVER_CONFIG_FILE, ACME_DEFAULT_LISTEN, ACME_DEFAULT_PORT
)
from ..util.notify import notify_safe

# Fields that must always have a real value for the server to function.
REQUIRED_FIELDS = ("listen-address", "port", "data-dir", "cert-dir", "registration-secret", "acme-provider")


def _acme_provider_options():
    return [(name, name) for name in sorted(ACME_PROVIDERS)] + [(MANUAL_ACME_PROVIDER, MANUAL_ACME_PROVIDER)]


# Per network-backend connection fields: (field_name, label, is_password, required, is_int) -
# same shape as forms.py's NOTIFIER_TYPE_FIELDS, toggled the same way (see
# on_select_changed() below). sqlite has no fields here - it uses the
# Storage section's data-dir Input above instead.
DB_BACKEND_FIELDS = {
    "mysql": [
        ("host", "Host:", False, True, False),
        ("port", "Port (default 3306):", False, False, True),
        ("user", "User:", False, True, False),
        ("password", "Password:", True, False, False),
        ("database", "Database name:", False, True, False),
    ],
    "postgresql": [
        ("host", "Host:", False, True, False),
        ("port", "Port (default 5432):", False, False, True),
        ("user", "User:", False, True, False),
        ("password", "Password:", True, False, False),
        ("database", "Database name:", False, True, False),
    ],
}


class ConfigView(VerticalScroll):
    """Editor for every server_config.json setting except the server's own
    TLS identity keypair (private_key/public_key) - regenerating that is a
    much bigger, disruptive operation (every already-registered client would
    need the new public key redistributed) and doesn't belong in a routine
    settings form, so it's deliberately left out here.

    Like every other server_config.json setting, changes here only take
    effect the next time the server process is (re)started - this doesn't
    talk to a running server at all, just the config file on disk.
    """

    DEFAULT_CSS = """
    ConfigView > #config-form {
        /* Vertical's own default (height: 1fr; overflow: hidden hidden)
        clamps it to the viewport and clips anything past that - height:
        auto instead sizes it to its actual content, so ConfigView (a
        VerticalScroll) sees the true content height and can scroll to it
        on a terminal too short to show every field at once. */
        height: auto;
    }
    """

    def compose(self):
        yield Static("", id="config-status", classes="empty-state")

        with Vertical(id="config-form"):
            yield Label("Network", classes="section-title")
            yield Label("Listen address:", classes="form-label")
            yield Input(id="listen-address")
            yield Label("Port:", classes="form-label")
            yield Input(id="port", type="integer")

            yield Label("Storage", classes="section-title")
            yield Label("Data directory (SQLite database, etc.):", classes="form-label")
            yield Input(id="data-dir")
            yield Label("Certificate directory (acme.sh working directories):", classes="form-label")
            yield Input(id="cert-dir")

            yield Label("Database backend:", classes="form-label")
            yield Select([("sqlite", "sqlite"), ("mysql/mariadb", "mysql"), ("postgresql", "postgresql")],
                         id="db-backend-select", allow_blank=False, value="sqlite")
            for backend, fields in DB_BACKEND_FIELDS.items():
                with Vertical(id=f"db-fields-{backend}") as group:
                    group.display = False
                    for field_name, label, is_password, _required, is_int in fields:
                        yield Label(label, classes="form-label")
                        yield Input(id=f"db-{backend}-{field_name}", password=is_password,
                                    type="integer" if is_int else "text")

            yield Label("Client registration", classes="section-title")
            yield Label("Registration secret (shared with client admins out-of-band):", classes="form-label")
            yield Input(id="registration-secret", password=True)
            with Horizontal(classes="form-actions"):
                yield Checkbox("Show", id="show-registration-secret")
                yield Button("Generate new", id="regen-secret")

            yield Label("Certificates", classes="section-title")
            yield Label("Default ACME provider (or pick a known one below):", classes="form-label")
            yield Select(_acme_provider_options(), id="acme-provider-select", prompt="Pick a known provider...")
            yield Input(id="acme-provider")

            yield Label("ACME server", classes="section-title")
            yield Checkbox("Enabled (scs-acme-server)", id="acme-enabled")
            yield Label("External URL (behind the mandatory reverse proxy):", classes="form-label")
            yield Input(id="acme-external-url", placeholder="https://ca.example.com/acme")
            yield Label("Listen address:", classes="form-label")
            yield Input(id="acme-listen", placeholder=ACME_DEFAULT_LISTEN)
            yield Label("Port:", classes="form-label")
            yield Input(id="acme-port", type="integer", placeholder=str(ACME_DEFAULT_PORT))

            yield Label("Admin notifications (email, webhook, Pushover, ...) are configured on the "
                        "Notifiers tab, not here.", classes="form-label")

            with Horizontal(classes="form-actions"):
                yield Button("Reload from disk", id="reload")
                yield Button("Save", id="save", variant="success")

    def on_mount(self):
        self.refresh_data()

    def refresh_data(self):
        config = server.load_config(DEFAULT_SERVER_CONFIG_FILE)
        status = self.query_one("#config-status", Static)
        form = self.query_one("#config-form", Vertical)

        if config is None:
            status.update(f"No config file found at {DEFAULT_SERVER_CONFIG_FILE} - "
                           f"run 'server.py init' on the server first.")
            form.display = False
            return

        status.update(f"Editing {DEFAULT_SERVER_CONFIG_FILE} - changes take effect on next server restart.")
        form.display = True

        def _set(field_id, value):
            self.query_one(f"#{field_id}", Input).value = "" if value is None else str(value)

        _set("listen-address", config.get("listen_address", "0.0.0.0"))
        _set("port", config.get("port", 5514))
        _set("data-dir", config.get("data_dir", ""))
        _set("cert-dir", config.get("cert_home_dir", ""))
        _set("registration-secret", config.get("registration_secret", ""))
        _set("acme-provider", config.get("default_acme_provider", ""))

        self.query_one("#acme-enabled", Checkbox).value = bool(config.get("acme_enabled"))
        _set("acme-external-url", config.get("acme_external_url", ""))
        _set("acme-listen", config.get("acme_listen", ""))
        _set("acme-port", config.get("acme_port", ""))

        db_config = config.get("database") or {}
        db_backend = db_config.get("backend", "sqlite")
        self.query_one("#db-backend-select", Select).value = db_backend
        for backend, fields in DB_BACKEND_FIELDS.items():
            backend_values = db_config.get(backend) or {}
            for field_name, _label, _is_password, _required, _is_int in fields:
                _set(f"db-{backend}-{field_name}", backend_values.get(field_name, ""))
            self.query_one(f"#db-fields-{backend}", Vertical).display = (backend == db_backend)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "show-registration-secret":
            self.query_one("#registration-secret", Input).password = not event.value

    def on_select_changed(self, event: Select.Changed) -> None:
        # Same version-independent pattern as forms.py's AssignPermissionModal:
        # checking against the blank sentinel by name (Select.NULL/BLANK)
        # isn't reliable across Textual versions, so just check the type -
        # every real option's value here is always one of our own strings.
        if event.select.id == "acme-provider-select" and isinstance(event.value, str):
            self.query_one("#acme-provider", Input).value = event.value
        elif event.select.id == "db-backend-select":
            for backend in DB_BACKEND_FIELDS:
                self.query_one(f"#db-fields-{backend}", Vertical).display = (backend == event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "reload":
            self.refresh_data()
            notify_safe(self.app, "Reloaded from disk.", severity="information")
            return

        if event.button.id == "regen-secret":
            import secrets
            self.query_one("#registration-secret", Input).value = secrets.token_urlsafe(24)
            return

        if event.button.id == "save":
            self._save()
            return

    def _value_of(self, field_id):
        return self.query_one(f"#{field_id}", Input).value.strip()

    def _save(self):
        for field_id in REQUIRED_FIELDS:
            if not self._value_of(field_id):
                notify_safe(self.app, f"'{field_id.replace('-', ' ')}' cannot be empty.", severity="error")
                return

        try:
            port = int(self._value_of("port"))
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            notify_safe(self.app, "Port must be a number between 1 and 65535.", severity="error")
            return

        acme_enabled = self.query_one("#acme-enabled", Checkbox).value
        acme_external_url = self._value_of("acme-external-url")
        if acme_enabled and not acme_external_url:
            notify_safe(self.app, "ACME server 'External URL' is required while it's enabled.",
                        severity="error")
            return

        acme_port_raw = self._value_of("acme-port")
        acme_port = None
        if acme_port_raw:
            try:
                acme_port = int(acme_port_raw)
                if not (1 <= acme_port <= 65535):
                    raise ValueError
            except ValueError:
                notify_safe(self.app, "ACME server port must be a number between 1 and 65535.",
                            severity="error")
                return

        db_backend = self.query_one("#db-backend-select", Select).value
        if db_backend in DB_BACKEND_FIELDS:
            for field_name, label, _is_password, required, _is_int in DB_BACKEND_FIELDS[db_backend]:
                if required and not self._value_of(f"db-{db_backend}-{field_name}"):
                    notify_safe(self.app, f"Database {label.rstrip(':').lower()} cannot be empty.", severity="error")
                    return
            port_raw = self._value_of(f"db-{db_backend}-port")
            if port_raw:
                try:
                    int(port_raw)
                except ValueError:
                    notify_safe(self.app, "Database port must be a number.", severity="error")
                    return

        updates = {
            "listen_address": self._value_of("listen-address"),
            "port": port,
            "data_dir": self._value_of("data-dir"),
            "cert_home_dir": self._value_of("cert-dir"),
            "registration_secret": self._value_of("registration-secret"),
            "default_acme_provider": self._value_of("acme-provider"),
            "acme_enabled": acme_enabled,
            "acme_external_url": acme_external_url,
        }
        # acme_listen/acme_port are genuinely optional at runtime
        # (acme_server.py falls back to ACME_DEFAULT_LISTEN/ACME_DEFAULT_PORT
        # when unset) - only write a key here if the field isn't blank, same
        # "leave it alone otherwise" spirit as server.py init's own
        # --acme-listen/--acme-port flags, rather than forcing an explicit
        # value into the file the way the always-required fields above do.
        acme_listen = self._value_of("acme-listen")
        if acme_listen:
            updates["acme_listen"] = acme_listen
        if acme_port is not None:
            updates["acme_port"] = acme_port

        # Merge onto whatever's already on disk (rather than replacing the
        # whole "database" key outright) so a backend's saved connection
        # details survive switching to a different backend and back -
        # update_config_fields() itself only ever replaces top-level keys,
        # it doesn't merge nested dicts.
        existing_config = server.load_config(DEFAULT_SERVER_CONFIG_FILE) or {}
        db_section = dict(existing_config.get("database") or {})
        db_section["backend"] = db_backend
        for backend, fields in DB_BACKEND_FIELDS.items():
            values = {}
            for field_name, _label, _is_password, _required, is_int in fields:
                raw = self._value_of(f"db-{backend}-{field_name}")
                if raw:
                    values[field_name] = int(raw) if is_int else raw
            if values:
                db_section[backend] = values
        updates["database"] = db_section

        # notifiers/notification_routing/notification_rate_limits are the
        # Notifiers tab's responsibility now (Section 7.8) - this view never
        # touches them, so update_config_fields()'s "preserve every key not
        # mentioned" behavior leaves them exactly as they are.
        if server.update_config_fields(DEFAULT_SERVER_CONFIG_FILE, updates):
            notify_safe(self.app, "Configuration saved. Restart the server process for changes to take effect.",
                        severity="information")
            self.refresh_data()
        else:
            notify_safe(self.app, f"No config file found at {DEFAULT_SERVER_CONFIG_FILE} - "
                                   f"run 'server.py init' on the server first.", severity="error")
