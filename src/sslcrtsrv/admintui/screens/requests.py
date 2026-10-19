from textual import work
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import DataTable, Label, Static

from ... import cltmanager
from ... import crtmanager
from ...common.database import get_acme_order_rows
from ..util.capture import silence_stdout
from ..util.notify import notify_safe
from ..util.table import current_row_key, restore_row_cursor
from ..widgets.confirm_modal import ConfirmModal
from ..widgets.dns_check_modal import DnsCheckModal
from ..widgets.issuance_modal import IssuanceOptionsModal, IssuanceProgressModal

# AcmeOrder.status values that mean "still outstanding" for this view's
# purposes - 'valid'/'invalid' orders are done (issued or dead) and belong
# in the Certificates tab / history, not here.
_OUTSTANDING_ACME_STATUSES = ('pending', 'ready', 'processing')


class RequestsView(Vertical):
    """Two independent outstanding-request views: the traditional protocol's
    not-yet-issued ClientCertificateRelation rows (crtmanager.py's
    `list --requested`), and outstanding ACME orders across every account -
    each with its own issue-now/check-dns or cancel action per row."""

    BINDINGS = [
        Binding("i", "issue_now", "Issue now"),
        Binding("d", "check_dns", "Check DNS"),
        Binding("x", "cancel_order", "Cancel ACME order"),
    ]

    def compose(self):
        yield Label("Certificate requests awaiting issuance", classes="section-title")
        table = DataTable(id="requests-table")
        table.cursor_type = "row"
        table.add_columns("Client ID", "FQDNs", "Status", "Valid Until")
        yield table
        yield Static("", id="requests-empty", classes="empty-state")

        yield Label("Outstanding ACME orders", classes="section-title")
        orders_table = DataTable(id="acme-orders-table")
        orders_table.cursor_type = "row"
        orders_table.add_columns("Client ID", "FQDNs", "Status", "Created", "Expires", "Attempts", "Last error")
        yield orders_table
        yield Static("", id="acme-orders-empty", classes="empty-state")

    def on_mount(self):
        self.refresh_data()

    def refresh_data(self):
        table = self.query_one("#requests-table", DataTable)
        previous_key = current_row_key(table)
        table.clear()
        rows = crtmanager.get_requested_certificate_rows()

        empty = self.query_one("#requests-empty", Static)
        empty.update("No requested certificates found." if not rows else "")

        for row in rows:
            table.add_row(row['client_id'], row['fqdns'], row['status_text'], row['valid_until'], key=row['fqdns'])

        restore_row_cursor(table, previous_key)

        orders_table = self.query_one("#acme-orders-table", DataTable)
        previous_order_key = current_row_key(orders_table)
        orders_table.clear()
        orders = [o for o in get_acme_order_rows() if o['status'] in _OUTSTANDING_ACME_STATUSES]

        orders_empty = self.query_one("#acme-orders-empty", Static)
        orders_empty.update("No outstanding ACME orders." if not orders else "")

        for order in orders:
            created = order['created_at'].strftime('%Y-%m-%d %H:%M') if order['created_at'] else 'N/A'
            expires = order['expires_at'].strftime('%Y-%m-%d %H:%M') if order['expires_at'] else 'N/A'
            orders_table.add_row(
                order['client_id'], order['fqdns'], order['status'], created, expires,
                str(order['issuance_attempts']), order['last_issuance_error'] or "",
                key=str(order['order_id']))

        restore_row_cursor(orders_table, previous_order_key)

    def _selected_fqdns(self):
        return current_row_key(self.query_one("#requests-table", DataTable))

    def _selected_order_id(self):
        key = current_row_key(self.query_one("#acme-orders-table", DataTable))
        return int(key) if key is not None else None

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

    def action_check_dns(self):
        fqdns = self._selected_fqdns()
        if not fqdns:
            return
        self.app.push_screen(DnsCheckModal(fqdns))

    @work
    async def action_cancel_order(self):
        order_id = self._selected_order_id()
        if order_id is None:
            return
        confirmed = await self.app.push_screen_wait(
            ConfirmModal("Cancel this ACME order?",
                         detail=f"Order ID: {order_id}\nThis invalidates the order and releases its "
                                f"fqdns processing lock. This cannot be undone."))
        if not confirmed:
            return
        success, captured = silence_stdout(cltmanager.cancel_acme_order, order_id)
        notify_safe(self.app, f"ACME order {order_id} cancelled." if success
                    else f"Could not cancel ACME order {order_id}.",
                    severity="information" if success else "error")
        self.refresh_data()
