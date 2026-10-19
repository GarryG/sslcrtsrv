from textual.app import App
from textual.binding import Binding

from .screens.main_screen import MainScreen


class KeysrvAdminApp(App):
    """Full-screen admin console consolidating crtmanager.py and
    cltmanager.py's server-side certificate/client management tasks."""

    CSS_PATH = "app.tcss"
    TITLE = "keysrv admin"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("f5", "refresh_all", "Refresh"),
    ]

    def on_mount(self) -> None:
        self.push_screen(MainScreen())

    def action_refresh_all(self) -> None:
        if isinstance(self.screen, MainScreen):
            self.screen.refresh_active_tab()
