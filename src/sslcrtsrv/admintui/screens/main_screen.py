from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, TabbedContent, TabPane

from .onboarding import OnboardingView
from .clients import ClientsView
from .certificates import CertificatesView
from .requests import RequestsView
from .maintenance import MaintenanceView
from .notifiers import NotifiersView
from .config import ConfigView


class MainScreen(Screen):
    """Top-level shell: Header + a tabbed Onboarding/Clients/Certificates/
    Requests/Maintenance/Notifiers/Config layout + Footer. Onboarding is the
    default tab since it's where admin attention is most often needed."""

    # Fallback for Clients/CertificatesView's own "ctrl+f" binding: Textual
    # resolves bindings by walking up from the focused widget, and TabbedContent's
    # tab bar (Tabs) is a sibling of the active TabPane, not an ancestor of it -
    # so when focus is on the tab bar itself, the view's own binding is
    # unreachable. This screen-level binding is always in the focus chain and
    # delegates to whichever pane is currently active.
    BINDINGS = [Binding("ctrl+f", "focus_search", "Find", show=False)]

    def compose(self):
        yield Header()
        with TabbedContent(initial="tab-onboarding"):
            with TabPane("Onboarding", id="tab-onboarding"):
                yield OnboardingView()
            with TabPane("Clients", id="tab-clients"):
                yield ClientsView()
            with TabPane("Certificates", id="tab-certificates"):
                yield CertificatesView()
            with TabPane("Requests", id="tab-requests"):
                yield RequestsView()
            with TabPane("Maintenance", id="tab-maintenance"):
                yield MaintenanceView()
            with TabPane("Notifiers", id="tab-notifiers"):
                yield NotifiersView()
            with TabPane("Config", id="tab-config"):
                yield ConfigView()
        yield Footer()

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        """Data can go stale while a different tab was active (e.g. approving
        a client in Onboarding changes what Clients/Certificates would show),
        so refresh whichever tab just became visible rather than trying to
        push updates to every tab on every action."""
        self._refresh_pane(event.pane)

    def refresh_active_tab(self) -> None:
        """Manual refresh (f5) - refresh whatever tab is currently visible."""
        tabbed = self.query_one(TabbedContent)
        active_pane = tabbed.get_pane(tabbed.active) if tabbed.active else None
        self._refresh_pane(active_pane)

    def _refresh_pane(self, pane) -> None:
        if pane is None:
            return
        for child in pane.children:
            refresh = getattr(child, "refresh_data", None)
            if callable(refresh):
                refresh()

    def action_focus_search(self) -> None:
        tabbed = self.query_one(TabbedContent)
        active_pane = tabbed.get_pane(tabbed.active) if tabbed.active else None
        if active_pane is None:
            return
        for child in active_pane.children:
            focus_search = getattr(child, "action_focus_search", None)
            if callable(focus_search):
                focus_search()
