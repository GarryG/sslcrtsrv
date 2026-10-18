from textual import work
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, RichLog

from ..actions.crtrequest_bridge import stream_check_dns


class DnsCheckModal(ModalScreen):
    """Live output of `crtrequest.py --check-dns-only`, for one certificate
    or every certificate this server tracks - never calls acme.sh or
    touches the database, regardless of what it finds (see crtrequest.py's
    --check-dns-only for the exact CNAME delegation this verifies)."""

    DEFAULT_CSS = """
    DnsCheckModal {
        align: center middle;
    }
    DnsCheckModal > Vertical {
        width: 90%;
        height: 80%;
        border: thick $primary 80%;
        background: $surface;
        padding: 1 2;
    }
    DnsCheckModal RichLog {
        height: 1fr;
        border: round $primary-lighten-1;
    }
    """

    BINDINGS = [("escape", "close", "Close")]

    def __init__(self, fqdns: str = None):
        super().__init__()
        self.fqdns = fqdns
        self.success = None  # None while still running

    def compose(self):
        title = f"Checking DNS delegation for {self.fqdns}..." if self.fqdns \
            else "Checking DNS delegation for every tracked certificate..."
        with Vertical():
            yield Label(title, id="dns-check-title", classes="section-title")
            yield RichLog(id="dns-check-log", max_lines=4000)
            with Horizontal(classes="form-actions"):
                yield Button("Close", id="close", disabled=True)

    def on_mount(self) -> None:
        self.run_check()

    @work
    async def run_check(self) -> None:
        log = self.query_one("#dns-check-log", RichLog)

        success, _output = await stream_check_dns(self.fqdns, on_line=log.write)
        self.success = success

        title = self.query_one("#dns-check-title", Label)
        subject = self.fqdns or "all tracked certificates"
        title.update(f"DNS check {'passed' if success else 'failed'} for {subject}")

        close_button = self.query_one("#close", Button)
        close_button.disabled = False
        close_button.focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close":
            self.dismiss(self.success)

    def action_close(self) -> None:
        # Only let escape close the window once the run has actually
        # finished, same reasoning as IssuanceProgressModal - a stray
        # keypress shouldn't abandon visibility into a still-running check.
        if self.success is not None:
            self.dismiss(self.success)
