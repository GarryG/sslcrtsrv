import json
from datetime import datetime, timedelta, timezone
from time import monotonic
from rich.text import Text
from textual import on, work
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Label, Static

from ...common.database import (
    get_all_clients, get_all_client_certificate_relations_with_certs, permission_is_active,
    get_client_by_id_or_client_id, get_acme_order_rows, get_latest_acme_order_created_at_by_account,
)

# Deliberately approximate (not calendar-exact) - a simple, easily-explained
# staleness threshold for an admin-facing indicator, not a precise SLA.
STALE_CONNECTION_THRESHOLD = timedelta(days=60)
from ... import cltmanager
from ... import crtmanager
from ..util.capture import silence_stdout
from ..util.notify import notify_safe
from ..util.table import (
    current_row_key, restore_row_cursor, should_debounce_header_click, sort_text_key, sort_version_key,
    toggle_sort_state,
)
from ..widgets.clickable_table import ClickableDataTable
from ..widgets.confirm_modal import ConfirmModal
from ..widgets.forms import AssignPermissionModal, SetPermissionExpiryModal
from .onboarding import _fmt_fingerprint


def _client_certificate_counts():
    """For every client (by numeric DB id): how many certificates they have
    assigned that are valid (issued, not expired, not staging, and the
    permission itself hasn't passed its own permission_valid_until - i.e. a
    real, currently-usable production certificate), assigned but invalid
    (not yet issued, expired, staging-only, or an expired permission), and
    requested but not yet assigned."""
    counts = {}
    for relation, cert in get_all_client_certificate_relations_with_certs():
        bucket = counts.setdefault(relation.client_id, {'valid': 0, 'invalid': 0, 'requested': 0})
        if relation.status == 0:
            bucket['requested'] += 1
        elif relation.status == 1:
            is_valid = bool(cert and cert.public_key and not cert.is_staging
                             and crtmanager.check_certificate_validity(cert)
                             and permission_is_active(relation))
            bucket['valid' if is_valid else 'invalid'] += 1
    return counts


def _last_seen(client, latest_acme_orders):
    """Best available "last seen" signal for this client, for the Clients
    tab's staleness coloring. Traditional-protocol clients use
    Client.last_successful_connection directly; ACME accounts never
    populate that field at all (see get_latest_acme_order_created_at_by_
    account()'s own docstring for why), so their most recent order's
    created_at is used instead. Returns None if there's no signal at all -
    a brand-new client of either kind that's done nothing yet."""
    if client.client_kind == 'acme':
        return latest_acme_orders.get(client.id)
    return client.last_successful_connection


class ClientsView(Vertical):
    """All clients, with a Pending/Confirmed filter and per-row confirm/
    revoke/delete/view-permissions actions."""

    BINDINGS = [
        Binding("c", "confirm_selected", "Confirm"),
        # Terminals send a capital "R" for Shift+R, not a separate "shift+r"
        # modifier combo - Textual's key name for it is just "R".
        Binding("R", "revoke_selected", "Revoke"),
        Binding("d", "delete_selected", "Delete"),
        Binding("enter", "view_selected", "Permissions", show=False),
        Binding("ctrl+f", "focus_search", "Find"),
    ]

    filter_mode = reactive("all")
    search_text = reactive("")

    # Click a header to sort by it (ascending), click again for descending -
    # the other columns (DB ID, Status, Last IP, Valid/Invalid/Requested)
    # aren't sortable. Keys match the column labels added in compose() below,
    # since add_columns() defaults a column's key to its label when none is
    # given explicitly.
    SORTABLE_COLUMNS = {
        "Client ID": sort_text_key,
        "Type": sort_text_key,
        "Version": sort_version_key,
        "Last connection": sort_text_key,
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._sort_column = None
        self._sort_reverse = False
        self._last_header_click_column = None
        self._last_header_click_time = None

    def compose(self):
        with Horizontal(classes="form-actions"):
            yield Input(placeholder="Filter by Client ID...", id="clients-search", classes="search-input")
            yield Button("All", id="filter-all", variant="primary")
            yield Button("Pending", id="filter-pending")
            yield Button("Confirmed", id="filter-confirmed")
        table = ClickableDataTable(id="clients-table")
        table.cursor_type = "row"
        labels = ("DB ID", "Client ID", "Type", "Status", "Version", "Last connection", "Last IP",
                  "Valid", "Invalid", "Requested")
        # add_columns() auto-generates an opaque ColumnKey per column, unrelated
        # to its label text - captured here (by label) so HeaderSelected/
        # _apply_sort() below can always look a column up by the actual key
        # DataTable itself uses, rather than assuming a column's key equals
        # its label (version-fragile: DataTable.columns is keyed by ColumnKey,
        # and relying on a plain str to compare equal to one isn't guaranteed
        # across Textual versions - confirmed to vary in practice).
        self._column_keys = dict(zip(labels, table.add_columns(*labels)))
        yield table
        yield Static("", id="clients-empty", classes="empty-state")

    def on_mount(self):
        self.refresh_data()

    def action_focus_search(self) -> None:
        self.query_one("#clients-search", Input).focus()

    @on(Input.Changed, "#clients-search")
    def _on_search_changed(self, event: Input.Changed) -> None:
        self.search_text = event.value
        self.refresh_data()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id and event.button.id.startswith("filter-"):
            self.filter_mode = event.button.id.removeprefix("filter-")
            for btn_id in ("filter-all", "filter-pending", "filter-confirmed"):
                self.query_one(f"#{btn_id}", Button).variant = (
                    "primary" if btn_id == event.button.id else "default")
            self.refresh_data()

    def refresh_data(self):
        table = self.query_one("#clients-table", DataTable)
        previous_key = current_row_key(table)
        table.clear()
        clients = get_all_clients()
        cert_counts = _client_certificate_counts()
        latest_acme_orders = get_latest_acme_order_created_at_by_account()

        if self.filter_mode == "pending":
            clients = [c for c in clients if c.status != "confirmed"]
        elif self.filter_mode == "confirmed":
            clients = [c for c in clients if c.status == "confirmed"]

        if self.search_text:
            clients = [c for c in clients if self.search_text.lower() in c.client_id.lower()]

        empty = self.query_one("#clients-empty", Static)
        empty.update("No clients match this filter." if not clients else "")

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        for client in clients:
            last_seen = _last_seen(client, latest_acme_orders)
            last_success = last_seen.strftime('%Y-%m-%d %H:%M') if last_seen else "N/A"
            counts = cert_counts.get(client.id, {'valid': 0, 'invalid': 0, 'requested': 0})
            client_type = "ACME" if client.client_kind == 'acme' else "Custom"
            cells = [str(client.id), client.client_id, client_type, client.status,
                     client.client_version or "N/A", last_success, client.last_connection_ip or "N/A",
                     str(counts['valid']), str(counts['invalid']), str(counts['requested'])]

            # Red: never seen at all (no successful connection/order ever),
            # or not confirmed - either way, not a trusted, active client.
            # Yellow: confirmed and has been seen, but not recently. Checked
            # in this order so an unconfirmed-and-stale client shows red
            # (the stronger signal), not yellow.
            if client.status != 'confirmed' or last_seen is None:
                cells = [Text(c, style="red") for c in cells]
            elif now - last_seen > STALE_CONNECTION_THRESHOLD:
                cells = [Text(c, style="yellow") for c in cells]

            table.add_row(*cells, key=client.client_id)

        restore_row_cursor(table, previous_key)
        self._apply_sort(table)

    @on(DataTable.HeaderSelected)
    def _on_header_selected(self, event: DataTable.HeaderSelected) -> None:
        label = next((lbl for lbl, key in self._column_keys.items() if key == event.column_key), None)
        if label not in self.SORTABLE_COLUMNS:
            return
        now = monotonic()
        if should_debounce_header_click(self._last_header_click_column, self._last_header_click_time,
                                         label, now):
            return
        self._last_header_click_column, self._last_header_click_time = label, now
        self._sort_column, self._sort_reverse = toggle_sort_state(
            self._sort_column, self._sort_reverse, label)
        self._apply_sort(event.data_table)

    def _apply_sort(self, table):
        """Re-applies the current sort (if any) - called both right after a
        header click and at the end of every refresh_data(), since
        table.clear() discards any prior ordering just like it discards the
        cursor position (see restore_row_cursor() above). Also redraws every
        sortable column's header with a ▲/▼ indicator on whichever one is
        currently active, clearing it from the rest. Always goes through
        self._column_keys (the actual ColumnKey objects add_columns()
        returned) rather than a column's label string - see compose()'s
        comment for why."""
        for label in self.SORTABLE_COLUMNS:
            if label == self._sort_column:
                arrow = " ▼" if self._sort_reverse else " ▲"
            else:
                arrow = ""
            table.columns[self._column_keys[label]].label = Text(label + arrow)
        if self._sort_column is None:
            return
        table.sort(self._column_keys[self._sort_column], key=self.SORTABLE_COLUMNS[self._sort_column],
                   reverse=self._sort_reverse)
        table.refresh()

    def _selected_client_id(self):
        return current_row_key(self.query_one("#clients-table", DataTable))

    @on(ClickableDataTable.RowDoubleClicked)
    def on_row_double_clicked(self, event: ClickableDataTable.RowDoubleClicked) -> None:
        self._open_permissions(event.row_key.value)

    def action_view_selected(self):
        client_id = self._selected_client_id()
        if client_id:
            self._open_permissions(client_id)

    def _open_permissions(self, client_id):
        def _after_close(result):
            self.refresh_data()
            if result:
                notify_safe(self.app, result, severity="information")
        self.app.push_screen(ClientPermissionsModal(client_id), _after_close)

    def action_confirm_selected(self):
        client_id = self._selected_client_id()
        if not client_id:
            return
        success, captured = silence_stdout(cltmanager.apply_client_action, client_id, "confirm")
        self.refresh_data()
        notify_safe(self.app, f"Client {client_id} confirmed." if success else f"Could not confirm {client_id}.",
                    severity="information" if success else "error")

    def action_revoke_selected(self):
        client_id = self._selected_client_id()
        if not client_id:
            return
        success, captured = silence_stdout(cltmanager.apply_client_action, client_id, "revoke")
        self.refresh_data()
        notify_safe(self.app, f"Client {client_id} revoked." if success else f"Could not revoke {client_id}.",
                    severity="information" if success else "error")

    @work
    async def action_delete_selected(self):
        client_id = self._selected_client_id()
        if not client_id:
            return
        confirmed = await self.app.push_screen_wait(
            ConfirmModal("Delete this client?", detail=f"Client ID: {client_id}\nThis cannot be undone."))
        if confirmed:
            from ...common.database import get_client, delete_client_by_id
            client = get_client(client_id)
            if client:
                delete_client_by_id(client.id)
                notify_safe(self.app, f"Client {client_id} deleted.", severity="information")
                self.refresh_data()


class ClientPermissionsModal(ModalScreen):
    """Client detail: identity fingerprint (re-checkable any time, not just
    at onboarding) and their certificate permissions, with assign/revoke
    actions."""

    DEFAULT_CSS = """
    ClientPermissionsModal {
        align: center middle;
    }
    ClientPermissionsModal > Vertical {
        width: 85%;
        height: auto;
        max-height: 90%;
        border: thick $primary 80%;
        background: $surface;
        padding: 1 2;
    }
    ClientPermissionsModal DataTable {
        height: auto;
        max-height: 12;
    }
    """

    BINDINGS = [("escape", "close", "Close")]

    def __init__(self, client_id: str):
        super().__init__()
        self.client_id = client_id

    def compose(self):
        client = get_client_by_id_or_client_id(self.client_id)
        with Vertical():
            if not client:
                yield Label(f"Client {self.client_id} not found.")
                yield Button("Close", id="close")
                return

            yield Label(f"Client: {client.client_id} ({client.status})", classes="section-title")
            yield Label(f"Version: {client.client_version or 'N/A'}")

            if client.client_kind == 'acme':
                # No fingerprint block here - unlike the custom protocol's
                # mutual-auth key (verified by a human comparing word-lists
                # with whoever runs the device), an ACME account key belongs
                # to an unattended, automated client with nobody to compare
                # it against, so there is no verification value in showing
                # one (explicit product decision, 2026-09-18).
                if client.acme_contact:
                    try:
                        contact_display = ", ".join(json.loads(client.acme_contact))
                    except (ValueError, TypeError):
                        contact_display = client.acme_contact
                    yield Label(f"Contact: {contact_display}")
            else:
                preview = cltmanager.get_client_action_preview(self.client_id, "confirm")
                if preview['client_fingerprint']:
                    yield Label("Fingerprint:")
                    yield Static(_fmt_fingerprint(preview['client_fingerprint']))
                elif preview['client_fingerprint_error']:
                    yield Label(Text(preview['client_fingerprint_error'], style="red"))

            yield Label("Certificate permissions:", classes="section-title")
            data = cltmanager.get_client_permission_rows(self.client_id)
            table = DataTable(id="perm-table")
            table.cursor_type = "row"
            table.add_columns("FQDNs", "Status", "Cert Valid Until", "Certificate ID", "Permission Expires")
            for perm in (data['permissions'] if data else []):
                status_text = perm['status_text']
                if perm['status'] == 1 and not perm['permission_active']:
                    status_text += " (expired)"
                cells = [perm['fqdns'], status_text, str(perm['valid_until']), str(perm['cert_id']),
                         str(perm['permission_expires'])]
                if not perm['is_valid'] or not perm['permission_active']:
                    # Whole-row red, matching CertificatesView's expired-row styling
                    cells = [Text(c, style="red") for c in cells]
                table.add_row(*cells, key=perm['fqdns'])
            yield table

            if client.client_kind == 'acme':
                yield Label("ACME orders:", classes="section-title")
                orders = get_acme_order_rows(account_client_id=client.id)
                if not orders:
                    yield Static("No ACME orders for this account.", classes="empty-state")
                else:
                    orders_table = DataTable(id="acme-orders-table")
                    orders_table.cursor_type = "row"
                    orders_table.add_columns("Order ID", "FQDNs", "Status", "Created", "Expires",
                                              "Attempts", "Last error")
                    for order in orders:
                        created = order['created_at'].strftime('%Y-%m-%d %H:%M') if order['created_at'] else 'N/A'
                        expires = order['expires_at'].strftime('%Y-%m-%d %H:%M') if order['expires_at'] else 'N/A'
                        orders_table.add_row(
                            str(order['order_id']), order['fqdns'], order['status'], created, expires,
                            str(order['issuance_attempts']), order['last_issuance_error'] or "",
                            key=str(order['order_id']))
                    yield orders_table

            with Horizontal(classes="form-actions"):
                yield Button("Close", id="close")
                yield Button("Revoke all", id="revoke-all", variant="error")
                yield Button("Revoke selected", id="revoke-selected")
                yield Button("Set expiry", id="set-expiry")
                yield Button("Assign new domain", id="assign", variant="success")

    @work
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id

        if button_id == "close":
            self.dismiss(None)
            return

        if button_id == "assign":
            def _after_assign(result):
                if result:
                    self.dismiss(result)
                    self.app.push_screen(ClientPermissionsModal(self.client_id))
            self.app.push_screen(AssignPermissionModal(self.client_id), _after_assign)
            return

        if button_id == "revoke-all":
            confirmed = await self.app.push_screen_wait(
                ConfirmModal("Revoke ALL certificate permissions for this client?",
                             detail=f"Client ID: {self.client_id}"))
            if confirmed:
                silence_stdout(cltmanager.revoke_certificate_permissions, self.client_id, "all")
                self.dismiss(f"All permissions revoked for {self.client_id}.")
            return

        if button_id == "revoke-selected":
            fqdns = current_row_key(self.query_one("#perm-table", DataTable))
            if fqdns is None:
                notify_safe(self.app, "No permission selected.", severity="warning")
                return
            confirmed = await self.app.push_screen_wait(
                ConfirmModal("Revoke this permission?", detail=f"FQDNs: {fqdns}"))
            if confirmed:
                silence_stdout(cltmanager.revoke_certificate_permissions, self.client_id, fqdns)
                self.dismiss(f"Permission for {fqdns} revoked.")
            return

        if button_id == "set-expiry":
            fqdns = current_row_key(self.query_one("#perm-table", DataTable))
            if fqdns is None:
                notify_safe(self.app, "No permission selected.", severity="warning")
                return
            data = cltmanager.get_client_permission_rows(self.client_id)
            current = next((str(p['permission_expires']) for p in (data['permissions'] if data else [])
                             if p['fqdns'] == fqdns), "")

            def _after_set_expiry(result):
                if result:
                    self.dismiss(result)
                    self.app.push_screen(ClientPermissionsModal(self.client_id))
            self.app.push_screen(SetPermissionExpiryModal(self.client_id, fqdns, current), _after_set_expiry)
            return

    def action_close(self):
        self.dismiss(None)
