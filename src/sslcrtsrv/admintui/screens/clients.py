import json
from rich.text import Text
from textual import on, work
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Label, Static

from ...common.database import (
    get_all_clients, get_all_client_certificate_relations_with_certs, permission_is_active,
    get_client_by_id_or_client_id, get_acme_order_rows,
)
from ... import cltmanager
from ... import crtmanager
from ..util.capture import silence_stdout
from ..util.notify import notify_safe
from ..util.table import current_row_key, restore_row_cursor
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
    ]

    filter_mode = reactive("all")

    def compose(self):
        with Horizontal(classes="form-actions"):
            yield Button("All", id="filter-all", variant="primary")
            yield Button("Pending", id="filter-pending")
            yield Button("Confirmed", id="filter-confirmed")
        table = ClickableDataTable(id="clients-table")
        table.cursor_type = "row"
        table.add_columns("DB ID", "Client ID", "Type", "Status", "Version", "Last successful connection",
                           "Valid Certs", "Invalid Certs", "Requested Certs")
        yield table
        yield Static("", id="clients-empty", classes="empty-state")

    def on_mount(self):
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

        if self.filter_mode == "pending":
            clients = [c for c in clients if c.status != "confirmed"]
        elif self.filter_mode == "confirmed":
            clients = [c for c in clients if c.status == "confirmed"]

        empty = self.query_one("#clients-empty", Static)
        empty.update("No clients match this filter." if not clients else "")

        for client in clients:
            last_success = client.last_successful_connection.strftime('%Y-%m-%d %H:%M') \
                if client.last_successful_connection else "N/A"
            counts = cert_counts.get(client.id, {'valid': 0, 'invalid': 0, 'requested': 0})
            client_type = "ACME" if client.client_kind == 'acme' else "Custom"
            table.add_row(str(client.id), client.client_id, client_type, client.status,
                          client.client_version or "N/A", last_success,
                          str(counts['valid']), str(counts['invalid']), str(counts['requested']),
                          key=client.client_id)

        restore_row_cursor(table, previous_key)

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
