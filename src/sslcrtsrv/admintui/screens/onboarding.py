from rich.text import Text
from textual import work
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Label, SelectionList, Static
from textual.widgets.selection_list import Selection

from ...common.database import get_pending_clients_with_requests, delete_client_by_id
from ...common.fingerprint_words import format_fingerprint_words
from ... import cltmanager
from ..util.capture import silence_stdout
from ..util.notify import notify_safe
from ..util.table import current_row_key, restore_row_cursor
from ..widgets.confirm_modal import ConfirmModal


def _fmt_fingerprint(fingerprint):
    """Render a SHA-256 hex digest as a numbered sequence of common words
    (common/fingerprint_words.py) for out-of-band comparison - much easier
    to read aloud or eyeball-compare than 64 hex characters - with the raw
    hex, chunked into 4-char groups like an SSH fingerprint, kept underneath
    for anyone who wants to compare byte-for-byte or paste it elsewhere."""
    if not fingerprint:
        return "(unavailable)"
    hex_grouped = " ".join(fingerprint[i:i + 4] for i in range(0, len(fingerprint), 4))
    try:
        return f"{format_fingerprint_words(fingerprint)}\n({hex_grouped})"
    except ValueError:
        # Not a well-formed 32-byte digest - fall back to just the hex.
        return hex_grouped


class OnboardingView(Vertical):
    """Default/home tab: every client needing admin attention - not yet
    confirmed, and/or holding at least one pending certificate request."""

    def compose(self):
        yield Label("Clients awaiting approval or holding pending certificate requests", classes="section-title")
        table = DataTable(id="onboarding-table")
        table.cursor_type = "row"
        table.add_columns("Client ID", "Status", "Registered", "Pending domains")
        yield table
        yield Static("", id="onboarding-empty", classes="empty-state")

    def on_mount(self):
        self.refresh_data()

    def refresh_data(self):
        table = self.query_one("#onboarding-table", DataTable)
        previous_key = current_row_key(table)
        table.clear()
        rows = get_pending_clients_with_requests()

        empty = self.query_one("#onboarding-empty", Static)
        if not rows:
            empty.update("Nothing needs attention - no pending clients or certificate requests.")
        else:
            empty.update("")

        for row in rows:
            client = row['client']
            reg_date = client.registration_date.strftime('%Y-%m-%d %H:%M') if client.registration_date else "N/A"
            table.add_row(
                client.client_id, client.status, reg_date, str(len(row['pending_fqdns'])),
                key=client.client_id,
            )

        restore_row_cursor(table, previous_key)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        client_id = event.row_key.value
        rows = {row['client'].client_id: row['pending_fqdns'] for row in get_pending_clients_with_requests()}
        pending_fqdns = rows.get(client_id, [])

        def _after_close(result):
            self.refresh_data()
            if result:
                notify_safe(self.app, result, severity="information")

        self.app.push_screen(OnboardingDetailModal(client_id, pending_fqdns), _after_close)


class OnboardingDetailModal(ModalScreen):
    """Combined confirm + assign workflow: identity verification (if the
    client isn't confirmed yet), then a checklist of their pending domain
    requests to approve or discard in one action."""

    DEFAULT_CSS = """
    OnboardingDetailModal {
        align: center middle;
    }
    OnboardingDetailModal > Vertical {
        width: 80%;
        height: auto;
        max-height: 90%;
        border: thick $primary 80%;
        background: $surface;
        padding: 1 2;
    }
    OnboardingDetailModal SelectionList {
        height: auto;
        max-height: 12;
        border: round $primary-lighten-1;
    }
    """

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, client_id: str, pending_fqdns: list):
        super().__init__()
        self.client_id = client_id
        self.pending_fqdns = pending_fqdns
        self.preview = cltmanager.get_client_action_preview(client_id, "confirm")
        self.needs_verification = self.preview['status_blocked_reason'] is None

    def compose(self):
        client = self.preview['client']
        with Vertical():
            if not client:
                yield Label(f"Client {self.client_id} not found.")
                yield Button("Close", id="cancel")
                return

            yield Label(f"Client: {client.client_id}", classes="section-title")

            if self.needs_verification:
                if self.preview['client_fingerprint_error']:
                    # Wrap in a Text object (not an f-string) - the exception text can
                    # itself contain brackets, which would otherwise be misparsed as markup.
                    yield Label(Text(self.preview['client_fingerprint_error'], style="red"))
                else:
                    yield Label("Their fingerprint - compare against the value the client operator "
                                 "sent out-of-band (email/chat) before approving:")
                    yield Static(_fmt_fingerprint(self.preview['client_fingerprint']))
                    if self.preview['server_fingerprint_error']:
                        yield Label(Text(self.preview['server_fingerprint_error'], style="red"))
                    else:
                        yield Label("This server's fingerprint - share it with them if they need to verify us:")
                        yield Static(_fmt_fingerprint(self.preview['server_fingerprint']))
                    yield Checkbox("I have compared this fingerprint out-of-band and it matches", id="fp-confirmed")
            else:
                yield Label(f"Client is already confirmed (status: {client.status}).")

            yield Label("Pending certificate requests:", classes="section-title")
            if self.pending_fqdns:
                selections = [Selection(fqdns, fqdns, True) for fqdns in self.pending_fqdns]
                yield SelectionList(*selections, id="domain-list")
            else:
                yield Static("No certificate requests yet from this client.", classes="empty-state")

            with Horizontal(classes="form-actions"):
                yield Button("Delete client", id="delete-client", variant="error")
                yield Button("Reject selected", id="reject-selected")
                yield Button("Cancel", id="cancel")
                yield Button("Approve selected", id="approve", variant="success", disabled=self.needs_verification)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "fp-confirmed":
            self.query_one("#approve", Button).disabled = not event.value

    def _selected_fqdns(self):
        if not self.pending_fqdns:
            return []
        return list(self.query_one("#domain-list", SelectionList).selected)

    @work
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id

        if button_id == "cancel":
            self.dismiss(None)
            return

        if button_id == "delete-client":
            confirmed = await self.app.push_screen_wait(
                ConfirmModal("Delete this client?", detail=f"Client ID: {self.client_id}\n"
                             "This permanently removes the client and cannot be undone."))
            if confirmed:
                delete_client_by_id(self.preview['client'].id)
                self.dismiss(f"Client {self.client_id} deleted.")
            return

        if button_id == "reject-selected":
            selected = self._selected_fqdns()
            if not selected:
                notify_safe(self.app, "No domains selected to reject.", severity="warning")
                return
            for fqdns in selected:
                silence_stdout(cltmanager.revoke_certificate_permissions, self.client_id, fqdns)
            self.dismiss(f"Discarded {len(selected)} pending request(s) for {self.client_id}.")
            return

        if button_id == "approve":
            selected = self._selected_fqdns()
            (client_ok, results), _captured = silence_stdout(
                cltmanager.onboard_client, self.client_id, selected)
            failed = [fqdns for fqdns, ok in results.items() if not ok]
            summary = f"Client {self.client_id} approved."
            if selected:
                summary += f" {len(selected) - len(failed)}/{len(selected)} domain(s) granted."
            if not client_ok:
                summary = f"Warning: could not confirm client {self.client_id}."
            if failed:
                summary += f" Failed: {', '.join(failed)}."
            self.dismiss(summary)
            return

    def action_cancel(self) -> None:
        self.dismiss(None)
