import os

from textual import work
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, RichLog, Static

from ...common.constants import DB_ENCRYPTION_PUBLIC_KEY_FILE
from ...common.database import get_all_certificates
from ...common.db_crypto import generate_db_keypair, is_encrypted
from ... import crtmanager
from ... import cltmanager
from ..util.capture import silence_stdout
from ..util.notify import notify_safe
from ..widgets.confirm_modal import ConfirmModal
from ..widgets.dns_check_modal import DnsCheckModal


class TypedConfirmModal(ModalScreen[bool]):
    """Stronger confirmation for the highest-blast-radius actions: requires
    typing an exact phrase rather than just clicking a button, so it can't be
    triggered by an absent-minded Enter/click."""

    DEFAULT_CSS = """
    TypedConfirmModal {
        align: center middle;
    }
    TypedConfirmModal > Vertical {
        width: 60%;
        height: auto;
        border: thick $error 80%;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, message: str, phrase: str):
        super().__init__()
        self.message = message
        self.phrase = phrase

    def compose(self):
        with Vertical():
            yield Label(self.message)
            yield Label(f"Type '{self.phrase}' to confirm:")
            yield Input(id="phrase-input")
            with Horizontal(classes="form-actions"):
                yield Button("Cancel", id="cancel")
                yield Button("Confirm", id="confirm", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm":
            typed = self.query_one("#phrase-input", Input).value.strip()
            self.dismiss(typed == self.phrase)
        else:
            self.dismiss(False)


class MaintenanceView(VerticalScroll):
    """One-time/rare admin operations, deliberately kept off the daily tabs:
    DB encryption key setup, legacy key migration, bulk expired-cert cleanup,
    and global stale-request cleanup.

    Unlike the other tabs (Onboarding/Clients/Certificates/Requests), whose
    content is a single DataTable that already scrolls its own rows
    internally, this tab is a stack of independent sections with no one
    flexible/scrollable widget - a plain Vertical here would just clip
    anything past the terminal's height on a short window. VerticalScroll
    (same fix as ConfigView's own #config-form) plus height: auto on the
    inner container is what actually makes that scrollable, rather than
    just clipped: Vertical's own default (height: 1fr; overflow: hidden
    hidden) clamps content to the viewport, so the outer VerticalScroll
    never sees a true content height taller than the viewport to scroll to.
    """

    DEFAULT_CSS = """
    MaintenanceView > #maintenance-content {
        height: auto;
    }
    MaintenanceView #migrate-log {
        /* RichLog has no default height of its own (falls back to the
        widget-base 1fr), which doesn't resolve sensibly as a child of the
        height: auto container above - fr shares out a parent's *definite*
        size, and an auto-sized parent doesn't have one yet to share. Giving
        it a fixed height sidesteps that, and is fine either way since the
        log already scrolls its own content independently (RichLog's
        overflow-y: scroll) regardless of how tall it is. */
        height: 10;
    }
    """

    def compose(self):
        with Vertical(id="maintenance-content"):
            yield Static("", id="health-block", classes="health-block")

            yield Label("DB encryption key", classes="section-title")
            with Horizontal(classes="form-actions"):
                yield Button("Generate keypair", id="init-key")
                yield Button("Overwrite existing keypair", id="overwrite-key", variant="error")

            yield Label("Legacy plaintext key migration", classes="section-title")
            with Horizontal(classes="form-actions"):
                yield Button("Preview", id="migrate-preview")
                yield Button("Run migration", id="migrate-run", variant="warning")
            yield RichLog(id="migrate-log", max_lines=200)

            yield Label("Bulk cleanup", classes="section-title")
            with Horizontal(classes="form-actions"):
                yield Button("Delete expired certificates", id="delete-invalid", variant="error")
                yield Button("Clean all stale requests", id="clean-requests", variant="error")

            yield Label("DNS delegation", classes="section-title")
            with Horizontal(classes="form-actions"):
                yield Button("Check DNS (all tracked certificates)", id="check-dns-all")

    def on_mount(self):
        self.refresh_data()

    def refresh_data(self):
        key_configured = os.path.exists(DB_ENCRYPTION_PUBLIC_KEY_FILE)
        certs = get_all_certificates()
        pending_migration = sum(1 for c in certs if c.private_key and not is_encrypted(c.private_key))

        health = self.query_one("#health-block", Static)
        health.update(
            f"DB encryption key: {'configured' if key_configured else '[red]not configured[/red]'}\n"
            f"Certificates pending key migration: {pending_migration}"
        )

    @work
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        # @work: push_screen_wait() (used below for several confirmations)
        # requires running inside a worker - a plain async message handler
        # raises NoActiveWorker as soon as it's awaited.
        button_id = event.button.id

        if button_id == "init-key":
            try:
                generate_db_keypair(overwrite=False)
                notify_safe(self.app, "DB encryption keypair generated.", severity="information")
            except FileExistsError as e:
                notify_safe(self.app, str(e), severity="error")
            self.refresh_data()
            return

        if button_id == "overwrite-key":
            confirmed = await self.app.push_screen_wait(TypedConfirmModal(
                "Overwriting the DB encryption keypair orphans every already-encrypted "
                "certificate private key permanently, unless re-encrypted under the new key first.",
                phrase="OVERWRITE"))
            if confirmed:
                generate_db_keypair(overwrite=True)
                notify_safe(self.app, "DB encryption keypair overwritten.", severity="warning")
                self.refresh_data()
            return

        if button_id == "migrate-preview":
            _success, captured = silence_stdout(crtmanager.migrate_encrypt_existing_keys, dry_run=True)
            self.query_one("#migrate-log", RichLog).write(captured)
            return

        if button_id == "migrate-run":
            confirmed = await self.app.push_screen_wait(
                ConfirmModal("Encrypt all legacy plaintext certificate private keys now?"))
            if confirmed:
                _success, captured = silence_stdout(crtmanager.migrate_encrypt_existing_keys, dry_run=False)
                self.query_one("#migrate-log", RichLog).write(captured)
                self.refresh_data()
            return

        if button_id == "delete-invalid":
            invalid_certs = crtmanager.get_invalid_certificates()
            if not invalid_certs:
                notify_safe(self.app, "No invalid certificates to delete.", severity="information")
                return
            detail = "\n".join(c.fqdns for c in invalid_certs)
            confirmed = await self.app.push_screen_wait(
                ConfirmModal(f"Delete {len(invalid_certs)} expired certificate(s)?", detail=detail))
            if confirmed:
                deleted = sum(1 for c in invalid_certs if crtmanager.delete_certificate_and_directory(c.fqdns))
                notify_safe(self.app, f"Deleted {deleted}/{len(invalid_certs)} expired certificate(s).",
                            severity="information")
            return

        if button_id == "check-dns-all":
            self.app.push_screen(DnsCheckModal())
            return

        if button_id == "clean-requests":
            _client, pending = cltmanager.get_pending_relations()
            if not pending:
                notify_safe(self.app, "No pending requests found.", severity="information")
                return
            confirmed = await self.app.push_screen_wait(
                ConfirmModal(f"Delete {len(pending)} pending certificate request(s) across all clients?"))
            if confirmed:
                success = cltmanager.delete_pending_relations()
                notify_safe(
                    self.app,
                    f"Deleted {len(pending)} pending request(s)." if success else "Failed to delete requests.",
                    severity="information" if success else "error")
            return
