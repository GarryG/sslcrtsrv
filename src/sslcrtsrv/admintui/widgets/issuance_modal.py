from textual import work
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Label, RichLog

from ..actions.crtrequest_bridge import stream_crtrequest


class IssuanceOptionsModal(ModalScreen):
    """Prompt shown before triggering acme.sh via crtrequest.py --cert-name:
    lets the admin opt into --staging/--force/--debug-acme, and opt *out* of
    the DNS delegation check crtrequest.py now runs by default (--no-check-dns),
    for this one run - mirroring crtrequest.py's own CLI flags. Dismisses
    with a dict of the chosen options, or None if cancelled."""

    DEFAULT_CSS = """
    IssuanceOptionsModal {
        align: center middle;
    }
    IssuanceOptionsModal > Vertical {
        width: 70%;
        height: auto;
        border: thick $primary 80%;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, fqdns: str):
        super().__init__()
        self.fqdns = fqdns

    def compose(self):
        with Vertical():
            yield Label(f"Request certificate for {self.fqdns}", classes="section-title")
            yield Checkbox(
                "Staging - request from the CA's test server instead of its live one",
                id="opt-staging")
            yield Checkbox(
                "Force - allow a staging certificate to overwrite an existing valid production one",
                id="opt-force")
            yield Checkbox(
                "Debug - add acme.sh's own --debug flag, for troubleshooting issuance failures",
                id="opt-debug")
            yield Checkbox(
                "Skip DNS check - don't verify CNAME delegation before calling acme.sh",
                id="opt-skip-dns-check")
            with Horizontal(classes="form-actions"):
                yield Button("Cancel", id="cancel")
                yield Button("Start", id="start", variant="success")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        self.dismiss({
            'staging': self.query_one("#opt-staging", Checkbox).value,
            'force': self.query_one("#opt-force", Checkbox).value,
            'debug': self.query_one("#opt-debug", Checkbox).value,
            'skip_dns_check': self.query_one("#opt-skip-dns-check", Checkbox).value,
        })


class IssuanceProgressModal(ModalScreen):
    """Live acme.sh issuance output, streamed line-by-line as crtrequest.py
    runs, so an admin can watch DNS challenge / validation progress instead
    of waiting blind for a single pass/fail toast."""

    DEFAULT_CSS = """
    IssuanceProgressModal {
        align: center middle;
    }
    IssuanceProgressModal > Vertical {
        width: 90%;
        height: 80%;
        border: thick $primary 80%;
        background: $surface;
        padding: 1 2;
    }
    IssuanceProgressModal RichLog {
        height: 1fr;
        border: round $primary-lighten-1;
    }
    """

    BINDINGS = [("escape", "close", "Close")]

    def __init__(self, fqdns: str, staging: bool = False, force: bool = False, debug: bool = False,
                 skip_dns_check: bool = False):
        super().__init__()
        self.fqdns = fqdns
        self.staging = staging
        self.force = force
        self.debug = debug
        self.skip_dns_check = skip_dns_check
        self.success = None  # None while still running

    def compose(self):
        with Vertical():
            yield Label(f"Requesting certificate for {self.fqdns} via acme.sh...",
                        id="issuance-title", classes="section-title")
            yield RichLog(id="issuance-log", max_lines=4000)
            with Horizontal(classes="form-actions"):
                yield Button("Close", id="close", disabled=True)

    def on_mount(self) -> None:
        self.run_issuance()

    @work
    async def run_issuance(self) -> None:
        log = self.query_one("#issuance-log", RichLog)

        success, _output = await stream_crtrequest(
            self.fqdns, staging=self.staging, force=self.force, debug=self.debug,
            skip_dns_check=self.skip_dns_check, on_line=log.write)
        self.success = success

        title = self.query_one("#issuance-title", Label)
        title.update(f"Issuance {'succeeded' if success else 'failed'} for {self.fqdns}")

        close_button = self.query_one("#close", Button)
        close_button.disabled = False
        close_button.focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close":
            self.dismiss(self.success)

    def action_close(self) -> None:
        # Only let escape close the window once the run has actually
        # finished, so a stray keypress can't abandon visibility into a
        # long-running acme.sh call (DNS propagation waits can take a while).
        if self.success is not None:
            self.dismiss(self.success)
