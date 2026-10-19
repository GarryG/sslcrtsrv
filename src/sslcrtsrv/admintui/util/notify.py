from rich.markup import escape


def notify_safe(app, message, severity="information"):
    """App.notify() that never interprets `message` as Rich markup.

    Achieves the same intent as passing markup=False, but by escaping the
    message instead of relying on that keyword - notify()'s `markup`
    parameter isn't present on older Textual releases (e.g. Debian/Ubuntu's
    packaged python3-textual), where passing it raises
    TypeError: App.notify() got an unexpected keyword argument 'markup'.
    """
    app.notify(escape(message), severity=severity)
