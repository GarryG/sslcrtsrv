from textual.message import Message
from textual.widgets import DataTable


class ClickableDataTable(DataTable):
    """A DataTable that also posts a RowDoubleClicked message when a row is
    double-clicked (Textual's Click event already tracks click chains; this
    just surfaces chain==2 as a distinct event, since DataTable's own click
    handling stops the raw Click event from bubbling to the parent)."""

    class RowDoubleClicked(Message):
        def __init__(self, data_table: "ClickableDataTable", row_key) -> None:
            self.data_table = data_table
            self.row_key = row_key
            super().__init__()

        @property
        def control(self) -> "ClickableDataTable":
            return self.data_table

    async def _on_click(self, event) -> None:
        await super()._on_click(event)
        if event.chain == 2 and self.cursor_row is not None:
            row_key, _ = self.coordinate_to_cell_key(self.cursor_coordinate)
            self.post_message(self.RowDoubleClicked(self, row_key))
