def current_row_key(table):
    """The key of the row under the cursor, or None if the table is empty.
    Call before table.clear() - clear() unconditionally resets the cursor to
    row 0, so without this a refresh silently moves the cursor onto whatever
    row now happens to be first, and the next keypress acts on the wrong row."""
    if table.cursor_row is None or table.row_count == 0:
        return None
    row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
    return row_key.value


def restore_row_cursor(table, key):
    """Put the cursor back on the row identified by `key` (as set via
    add_row(..., key=...)) after a refresh repopulated the table - a no-op if
    that row no longer exists (e.g. it was just deleted)."""
    if key is None:
        return
    try:
        row_index = table.get_row_index(key)
    except Exception:
        return
    from textual.coordinate import Coordinate
    table.cursor_coordinate = Coordinate(row_index, table.cursor_column)
