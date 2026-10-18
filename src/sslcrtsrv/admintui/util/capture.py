import contextlib
import io


def silence_stdout(func, *args, **kwargs):
    """Call func, capturing anything it prints to stdout instead of letting it
    reach the terminal - a stray print() while Textual owns the screen would
    corrupt the display until the next redraw.

    Returns (result, captured_text).
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = func(*args, **kwargs)
    return result, buf.getvalue()
