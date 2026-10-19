from textual.containers import Grid
from textual.screen import ModalScreen
from textual.widgets import Button, Label


class ConfirmModal(ModalScreen[bool]):
    """Generic yes/no confirmation dialog. Dismisses with True (confirmed) or
    False (cancelled). Default focus is on Cancel so a stray Enter never
    triggers a destructive action.

    `detail` lines are shown below the main message (e.g. exactly what will
    be affected), matching the "show the blast radius" behavior every
    destructive CLI command already has today.
    """

    DEFAULT_CSS = """
    ConfirmModal {
        align: center middle;
    }
    ConfirmModal > Grid {
        grid-size: 2;
        grid-gutter: 1 2;
        grid-rows: auto 3;
        padding: 1 2;
        width: 60%;
        height: auto;
        border: thick $error 80%;
        background: $surface;
    }
    ConfirmModal #message {
        column-span: 2;
        height: auto;
        content-align: center middle;
    }
    """

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, message: str, detail: str = "", yes_label: str = "Confirm", no_label: str = "Cancel"):
        super().__init__()
        self.message = message
        self.detail = detail
        self.yes_label = yes_label
        self.no_label = no_label

    def compose(self):
        text = self.message
        if self.detail:
            text = f"{self.message}\n\n{self.detail}"
        with Grid():
            yield Label(text, id="message")
            yield Button(self.no_label, id="no", variant="primary")
            yield Button(self.yes_label, id="yes", variant="error")

    def on_mount(self):
        self.query_one("#no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_cancel(self) -> None:
        self.dismiss(False)
