# Watches the server's config file for changes and reacts without polling.
#
# Uses Linux inotify directly via a small ctypes wrapper rather than pulling
# in a third-party dependency (e.g. watchdog/inotify_simple) just for this:
# the surface needed here - one watch, a handful of event flags, blocking
# reads - is small enough that wrapping the three libc calls directly is
# simpler than adding a dependency, and this project is Debian/Linux-only
# already (see debian/control).

import ctypes
import ctypes.util
import os
import select
import struct
import sys
import threading
import time
from typing import Callable, Optional

_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)

# linux/inotify.h event masks (stable ABI, safe to hardcode)
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080
IN_DELETE = 0x00000200
IN_NONBLOCK = 0o4000

_EVENT_HEADER = struct.Struct("iIII")  # struct inotify_event: wd, mask, cookie, len


class ConfigFileWatcher:
    """Notifies a callback when a specific file is written to, replaced, or
    deleted - without the watching thread ever having to wake up and check.

    The thread blocks in the kernel (inotify fd + select()) until the kernel
    itself has an event to report, so an untouched config costs nothing
    beyond one idle thread; this is the "get notified" alternative to a
    loop that periodically stats the file.

    Watches the *containing directory* rather than the file itself: config
    editors commonly replace a file by writing a temp file and renaming it
    over the original (vim, `sed -i`, etc.), which swaps out the underlying
    inode - a watch on the original file's inode would then be left
    watching an orphaned, deleted inode and silently stop reporting
    anything. Watching the directory and filtering events by filename
    survives both that and a plain in-place rewrite (this server's own
    write_secure_json() truncates-in-place, producing IN_ATTRIB/
    IN_CLOSE_WRITE rather than a rename).

    Multiple edits in quick succession (e.g. a write() followed by a
    chmod()) are coalesced into a single on_change() call via a short
    debounce, so one logical edit doesn't trigger repeated reloads.
    """

    def __init__(self, config_file_path: str, on_change: Callable[[], None], debounce_seconds: float = 1.0,
                 on_error: Optional[Callable[[str], None]] = None):
        self.config_file_path = os.path.abspath(config_file_path)
        self.watch_dir = os.path.dirname(self.config_file_path)
        self.watch_name = os.path.basename(self.config_file_path)
        self.on_change = on_change
        self.debounce_seconds = debounce_seconds
        self.on_error = on_error
        self._stop = False
        self._fd: Optional[int] = None

    def start(self) -> threading.Thread:
        thread = threading.Thread(target=self._run, name="config-watcher", daemon=True)
        thread.start()
        return thread

    def stop(self):
        self._stop = True
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass

    def _run(self):
        fd = _libc.inotify_init1(IN_NONBLOCK)
        if fd < 0:
            errno = ctypes.get_errno()
            message = (f"could not start config file watcher (inotify_init1 failed: "
                       f"{os.strerror(errno)}); changes to {self.config_file_path} will require "
                       f"a manual restart to take effect.")
            print(f"Warning: {message}", file=sys.stderr)
            if self.on_error:
                self.on_error(message)
            return
        self._fd = fd

        mask = IN_CLOSE_WRITE | IN_MOVED_TO | IN_ATTRIB | IN_DELETE
        watch_dir_bytes = self.watch_dir.encode(sys.getfilesystemencoding())
        wd = _libc.inotify_add_watch(fd, watch_dir_bytes, mask)
        if wd < 0:
            errno = ctypes.get_errno()
            message = (f"could not watch {self.watch_dir} for config changes "
                       f"({os.strerror(errno)}); changes to {self.config_file_path} will require "
                       f"a manual restart to take effect.")
            print(f"Warning: {message}", file=sys.stderr)
            if self.on_error:
                self.on_error(message)
            os.close(fd)
            self._fd = None
            return

        pending = False
        last_event_time = 0.0

        try:
            while not self._stop:
                timeout = None
                if pending:
                    remaining = self.debounce_seconds - (time.monotonic() - last_event_time)
                    if remaining <= 0:
                        pending = False
                        self.on_change()
                        continue
                    timeout = remaining

                try:
                    ready, _, _ = select.select([fd], [], [], timeout)
                except (OSError, ValueError):
                    break
                if self._stop:
                    break
                if not ready:
                    continue

                try:
                    data = os.read(fd, 4096)
                except OSError:
                    break
                if not data:
                    break

                if self._data_mentions_watched_file(data):
                    pending = True
                    last_event_time = time.monotonic()
        finally:
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None

    def _data_mentions_watched_file(self, data: bytes) -> bool:
        offset = 0
        while offset + _EVENT_HEADER.size <= len(data):
            _wd, _mask, _cookie, name_len = _EVENT_HEADER.unpack_from(data, offset)
            offset += _EVENT_HEADER.size
            raw_name = data[offset:offset + name_len]
            offset += name_len
            name = raw_name.split(b"\0", 1)[0].decode(sys.getfilesystemencoding(), errors="replace")
            if name == self.watch_name:
                return True
        return False
