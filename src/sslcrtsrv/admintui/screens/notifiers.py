from textual import on, work
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from ... import server
from ...common.constants import DEFAULT_SERVER_CONFIG_FILE
from ..util.notify import notify_safe
from ..util.table import current_row_key, restore_row_cursor
from ..widgets.clickable_table import ClickableDataTable
from ..widgets.confirm_modal import ConfirmModal
from ..widgets.forms import AddUpdateNotifierModal


class NotifiersView(Vertical):
    """Every configured admin notifier (Section 10.2), with per-row add/
    edit/delete - the general-purpose replacement for the Config tab's old
    hardcoded single-email section. Covers every notifier type, event
    routing (Section 10.3), and per-notifier rate-limit overrides
    (Section 10.7) from one place."""

    BINDINGS = [
        Binding("a", "add_notifier", "Add"),
        Binding("enter", "edit_selected", "Edit"),
        Binding("u", "edit_selected", "Edit"),
        Binding("D", "delete_selected", "Delete"),
    ]

    def compose(self):
        table = ClickableDataTable(id="notifiers-table")
        table.cursor_type = "row"
        table.add_columns("Name", "Type", "Routed events", "Rate limit")
        yield table
        yield Static("", id="notifiers-empty", classes="empty-state")

    def on_mount(self):
        self.refresh_data()

    def refresh_data(self):
        table = self.query_one("#notifiers-table", DataTable)
        previous_key = current_row_key(table)
        table.clear()

        config = server.load_config(DEFAULT_SERVER_CONFIG_FILE) or {}
        notifiers = config.get("notifiers") or {}
        routing = config.get("notification_routing") or {}
        rate_limits = config.get("notification_rate_limits") or {}

        empty = self.query_one("#notifiers-empty", Static)
        empty.update("No notifiers configured yet - press 'a' to add one." if not notifiers else "")

        for name in sorted(notifiers):
            notifier_config = notifiers[name]
            events = sorted(event for event, names in routing.items() if name in names)
            override = rate_limits.get(name) or {}
            if override:
                rate_text = ", ".join(f"{k}={v}" for k, v in override.items())
            else:
                rate_text = "default"
            table.add_row(name, notifier_config.get("type", ""), ", ".join(events) or "-", rate_text, key=name)

        restore_row_cursor(table, previous_key)

    def _selected_name(self):
        return current_row_key(self.query_one("#notifiers-table", DataTable))

    def action_add_notifier(self):
        config = server.load_config(DEFAULT_SERVER_CONFIG_FILE) or {}
        existing_names = set((config.get("notifiers") or {}).keys())

        def _after_close(result):
            if result:
                self._save_notifier(result)

        self.app.push_screen(AddUpdateNotifierModal(mode="add", existing_names=existing_names), _after_close)

    @on(ClickableDataTable.RowDoubleClicked)
    def on_row_double_clicked(self, event: ClickableDataTable.RowDoubleClicked) -> None:
        self._edit_notifier(event.row_key.value)

    def action_edit_selected(self):
        name = self._selected_name()
        if not name:
            return
        self._edit_notifier(name)

    def _edit_notifier(self, name: str):
        config = server.load_config(DEFAULT_SERVER_CONFIG_FILE) or {}
        notifier_config = (config.get("notifiers") or {}).get(name, {})
        routing = config.get("notification_routing") or {}
        routed_events = [event for event, names in routing.items() if name in names]
        rate_limit_override = (config.get("notification_rate_limits") or {}).get(name, {})

        def _after_close(result):
            if result:
                self._save_notifier(result)

        self.app.push_screen(
            AddUpdateNotifierModal(mode="update", name=name, notifier_config=notifier_config,
                                   routed_events=routed_events, rate_limit_override=rate_limit_override),
            _after_close)

    def _save_notifier(self, result: dict):
        name = result["name"]
        config = server.load_config(DEFAULT_SERVER_CONFIG_FILE) or {}

        notifiers = config.setdefault("notifiers", {})
        notifiers[name] = {"type": result["type"], **result["fields"]}

        routing = config.setdefault("notification_routing", {})
        for event in ("registration", "certificate_request", "error"):
            names = routing.setdefault(event, [])
            routed = event in result["routed_events"]
            if routed and name not in names:
                names.append(name)
            elif not routed and name in names:
                names.remove(name)

        rate_limits = config.setdefault("notification_rate_limits", {})
        if result["rate_limit_override"]:
            rate_limits[name] = result["rate_limit_override"]
        else:
            rate_limits.pop(name, None)

        if server.update_config_fields(DEFAULT_SERVER_CONFIG_FILE, {
            "notifiers": notifiers,
            "notification_routing": routing,
            "notification_rate_limits": rate_limits,
        }):
            notify_safe(self.app, f"Notifier '{name}' saved. Restart the server process for changes "
                                   f"to take effect.", severity="information")
            self.refresh_data()
        else:
            notify_safe(self.app, f"No config file found at {DEFAULT_SERVER_CONFIG_FILE} - "
                                   f"run 'server.py init' on the server first.", severity="error")

    @work
    async def action_delete_selected(self):
        name = self._selected_name()
        if not name:
            return
        confirmed = await self.app.push_screen_wait(
            ConfirmModal("Delete this notifier?", detail=f"Name: {name}\nThis cannot be undone."))
        if not confirmed:
            return

        config = server.load_config(DEFAULT_SERVER_CONFIG_FILE) or {}
        notifiers = config.get("notifiers") or {}
        notifiers.pop(name, None)
        routing = config.get("notification_routing") or {}
        for names in routing.values():
            if name in names:
                names.remove(name)
        rate_limits = config.get("notification_rate_limits") or {}
        rate_limits.pop(name, None)

        if server.update_config_fields(DEFAULT_SERVER_CONFIG_FILE, {
            "notifiers": notifiers,
            "notification_routing": routing,
            "notification_rate_limits": rate_limits,
        }):
            notify_safe(self.app, f"Notifier '{name}' deleted.", severity="information")
            self.refresh_data()
        else:
            notify_safe(self.app, f"No config file found at {DEFAULT_SERVER_CONFIG_FILE} - "
                                   f"run 'server.py init' on the server first.", severity="error")
