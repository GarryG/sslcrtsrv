def sort_text_key(value):
    """Normalizes a DataTable cell for case-insensitive string sorting -
    handles both a plain str and a rich.text.Text-wrapped cell (used for
    staleness/expiry row coloring elsewhere in admintui) uniformly, since
    Text.__str__() already returns its plain text."""
    return str(value).lower()


def sort_version_key(value):
    """Version-aware sort key for a "x.y.z"-style version string (or "N/A"),
    so e.g. "0.9.10" sorts after "0.9.8" instead of before it as a plain
    string would. Each dot-separated segment's leading digit run becomes one
    int in the returned tuple; a value with no parseable segments at all
    (e.g. "N/A") sorts after every real version in ascending order (and so
    before them once a sort is reversed) - a minor, accepted quirk rather
    than something specially engineered around, since the client/certificate
    "N/A" placeholders elsewhere in admintui behave the same way under plain
    text sort."""
    segments = []
    for part in str(value).split('.'):
        digits = ''
        for ch in part:
            if ch.isdigit():
                digits += ch
            else:
                break
        if digits:
            segments.append(int(digits))
    if not segments:
        return (float('inf'),)
    return tuple(segments)


def toggle_sort_state(current_column, current_reverse, clicked_column):
    """New (column, reverse) sort state after a header click: clicking the
    already-sorted column flips direction; clicking a different column
    switches to it, ascending."""
    if clicked_column == current_column:
        return clicked_column, not current_reverse
    return clicked_column, False


# DataTable's own header-click handling (_on_click's is_header_click branch,
# textual/widgets/_data_table.py) never calls event.stop() on the underlying
# Click the way its row-click branch does - on some terminals/mouse-reporting
# setups this lets a single physical click reach the DataTable twice,
# posting HeaderSelected twice for the one click. Since toggle_sort_state()
# flips direction on a repeat click, an undetected duplicate always nets out
# to "descending" no matter how many times the header is actually clicked -
# exactly the reported symptom. Not reproducible via Textual's own Pilot
# (its synthetic click() bypasses real terminal mouse-event parsing
# entirely), so this debounces defensively instead of chasing the exact
# platform-specific cause.
HEADER_CLICK_DEBOUNCE_SECONDS = 0.3


def should_debounce_header_click(last_column, last_time, clicked_column, now):
    """True if `clicked_column` arriving at `now` looks like a duplicate of
    the same header click already handled at `last_time`, not a genuine
    second click - i.e. the same column, within HEADER_CLICK_DEBOUNCE_SECONDS.
    `last_time`/`now` are plain floats (time.monotonic()); `last_time=None`
    (nothing handled yet) never debounces."""
    if last_column != clicked_column or last_time is None:
        return False
    return (now - last_time) < HEADER_CLICK_DEBOUNCE_SECONDS


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
