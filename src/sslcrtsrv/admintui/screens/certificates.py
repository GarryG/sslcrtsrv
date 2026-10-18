from rich.text import Text
from textual import on, work
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.reactive import reactive
from textual.widgets import Button, DataTable, Label, Static

from ... import crtmanager
from ...common.database import get_clients_for_certificate, permission_is_active, get_acme_issued_fqdns
from ..util.capture import silence_stdout
from ..util.notify import notify_safe
from ..util.table import current_row_key, restore_row_cursor
from ..widgets.clickable_table import ClickableDataTable
from ..widgets.confirm_modal import ConfirmModal
from ..widgets.dns_check_modal import DnsCheckModal
from ..widgets.forms import AddUpdateCertModal, SetProviderModal
from ..widgets.issuance_modal import IssuanceOptionsModal, IssuanceProgressModal


class CertificatesView(Vertical):
    """All issued certificates, with an expiry/status filter and per-row
    provider-change/issue-now/delete/check-dns actions plus add/update-from-file."""

    BINDINGS = [
        Binding("a", "add_cert", "Add"),
        Binding("u", "update_cert", "Update"),
        Binding("p", "set_provider", "Set provider"),
        Binding("i", "issue_now", "Issue now"),
        Binding("D", "delete_selected", "Delete"),
        Binding("d", "check_dns", "Check DNS"),
        Binding("c", "toggle_clients", "Toggle clients"),
    ]

    filter_mode = reactive("all")
    show_clients = reactive(False)

    def compose(self):
        with Horizontal(classes="form-actions"):
            yield Button("All", id="filter-all", variant="primary")
            yield Button("Expiring soon", id="filter-expiring")
            yield Button("Expired", id="filter-expired")
        table = ClickableDataTable(id="certs-table")
        table.cursor_type = "row"
        table.add_columns("ID", "FQDN", "Valid until", "Last update", "Provider", "Origin")
        yield table
        yield Static("", id="certs-empty", classes="empty-state")

    def on_mount(self):
        self.refresh_data()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id and event.button.id.startswith("filter-"):
            self.filter_mode = event.button.id.removeprefix("filter-")
            for btn_id in ("filter-all", "filter-expiring", "filter-expired"):
                self.query_one(f"#{btn_id}", Button).variant = (
                    "primary" if btn_id == event.button.id else "default")
            self.refresh_data()

    def refresh_data(self):
        table = self.query_one("#certs-table", DataTable)
        previous_key = current_row_key(table)
        table.clear()
        rows = crtmanager.get_certificate_rows(show_clients=self.show_clients)

        if self.filter_mode == "expiring":
            rows = [r for r in rows if r['is_near_expiry']]
        elif self.filter_mode == "expired":
            rows = [r for r in rows if r['is_expired']]

        empty = self.query_one("#certs-empty", Static)
        empty.update("No certificates match this filter." if not rows else "")

        acme_issued = get_acme_issued_fqdns([r['fqdns'] for r in rows])

        for row in rows:
            id_display = str(row['id']) if row['id'] is not None else ""
            origin = "ACME" if row['fqdns'] in acme_issued else "Traditional"
            cells = [id_display, row['fqdns_display'], row['validity_end_date_str'],
                     row['last_update_str'], row['provider_str'], origin]

            if row['is_expired']:
                # Whole-row red, matching list_certificates()'s expired-row styling
                cells = [Text(str(c), style="red") for c in cells]
            elif row['is_near_expiry']:
                # Only the "Valid until" cell, matching list_certificates()'s [yellow]...[/yellow]
                cells[2] = Text(cells[2], style="yellow")

            table.add_row(*cells, key=row['fqdns'])

        restore_row_cursor(table, previous_key)

    def _selected_fqdns(self):
        return current_row_key(self.query_one("#certs-table", DataTable))

    @on(ClickableDataTable.RowDoubleClicked)
    def on_row_double_clicked(self, event: ClickableDataTable.RowDoubleClicked) -> None:
        self.app.push_screen(CertificateClientsModal(event.row_key.value))

    def action_toggle_clients(self):
        self.show_clients = not self.show_clients
        self.refresh_data()

    def action_add_cert(self):
        def _after_close(result):
            self.refresh_data()
            if result:
                notify_safe(self.app, result, severity="information")
        self.app.push_screen(AddUpdateCertModal(mode="add"), _after_close)

    def action_update_cert(self):
        def _after_close(result):
            self.refresh_data()
            if result:
                notify_safe(self.app, result, severity="information")
        self.app.push_screen(AddUpdateCertModal(mode="update"), _after_close)

    def action_set_provider(self):
        fqdns = self._selected_fqdns()
        if not fqdns:
            return

        def _after_close(result):
            self.refresh_data()
            if result:
                notify_safe(self.app, result, severity="information")
        self.app.push_screen(SetProviderModal(fqdns), _after_close)

    def action_issue_now(self):
        fqdns = self._selected_fqdns()
        if not fqdns:
            return

        def _after_options(options):
            if options is None:
                return

            def _after_progress(_success):
                self.refresh_data()

            self.app.push_screen(
                IssuanceProgressModal(fqdns, staging=options['staging'], force=options['force'],
                                      debug=options['debug'], skip_dns_check=options['skip_dns_check']),
                _after_progress)

        self.app.push_screen(IssuanceOptionsModal(fqdns), _after_options)

    @work
    async def action_delete_selected(self):
        fqdns = self._selected_fqdns()
        if not fqdns:
            return
        confirmed = await self.app.push_screen_wait(
            ConfirmModal("Delete this certificate?", detail=f"FQDNs: {fqdns}\nThis cannot be undone."))
        if confirmed:
            crtmanager.delete_certificate_and_directory(fqdns)
            notify_safe(self.app, f"Certificate {fqdns} deleted.", severity="information")
            self.refresh_data()

    def action_check_dns(self):
        fqdns = self._selected_fqdns()
        if not fqdns:
            return
        self.app.push_screen(DnsCheckModal(fqdns))


class CertificateClientsModal(ModalScreen):
    """Clients that have (or have requested) access to a certificate -
    opened by double-clicking a row in the Certificates tab."""

    DEFAULT_CSS = """
    CertificateClientsModal {
        align: center middle;
    }
    CertificateClientsModal > Vertical {
        width: 80%;
        height: auto;
        max-height: 80%;
        border: thick $primary 80%;
        background: $surface;
        padding: 1 2;
    }
    """

    BINDINGS = [("escape", "close", "Close")]

    def __init__(self, fqdns: str):
        super().__init__()
        self.fqdns = fqdns

    def compose(self):
        with Vertical():
            yield Label(f"Clients with access to {self.fqdns}", classes="section-title")
            table = DataTable(id="cert-clients-table")
            table.cursor_type = "row"
            table.add_columns("Client ID", "Status", "Permission Expires")
            yield table
            yield Static("", id="cert-clients-empty", classes="empty-state")
            with Horizontal(classes="form-actions"):
                yield Button("Close", id="close")

    def on_mount(self) -> None:
        table = self.query_one("#cert-clients-table", DataTable)
        relations = get_clients_for_certificate(self.fqdns)

        empty = self.query_one("#cert-clients-empty", Static)
        empty.update("No clients are assigned to this certificate." if not relations else "")

        for relation, client in relations:
            status_text = "Active" if relation.status == 1 else ("Requested" if relation.status == 0 else "Inactive")
            if relation.status == 1 and not permission_is_active(relation):
                status_text += " (expired)"
            valid_until = str(relation.permission_valid_until) if relation.permission_valid_until else "Never"
            table.add_row(client.client_id, status_text, valid_until, key=client.client_id)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close":
            self.dismiss()

    def action_close(self) -> None:
        self.dismiss()
