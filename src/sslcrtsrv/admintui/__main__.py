#!/usr/bin/env python3
"""Entry point: installed as the `scs-admintui` console script, or
`python3 -m sslcrtsrv.admintui` from a checkout with sslcrtsrv installed."""

import argparse
import sys

from .. import __version__
from ..common.constants import DEFAULT_SERVER_CONFIG_FILE
from ..common.database import init_database, apply_data_dir_from_config, SchemaOutOfDate
from ..common.logging_utils import setup_tool_logging_from_file
from .app import KeysrvAdminApp


def main():
    parser = argparse.ArgumentParser(prog='scs-admintui',
                                      description='SSLCrtSrv full-screen terminal admin dashboard')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.parse_args()

    # Relocate the database under server_config.json's data_dir first, if
    # one is configured (see common/database.py's relocate_under_data_dir()) -
    # crtmanager.py/cltmanager.py functions called directly from the various
    # tabs below all rely on this having already happened.
    apply_data_dir_from_config()

    # console=False - Textual owns the terminal from the moment
    # KeysrvAdminApp().run() starts, and a stray write to stdout from a log
    # record would corrupt the screen exactly like a stray print() already
    # would (see util/capture.py's silence_stdout()). File/syslog logging
    # both still apply normally. This also gives every cltmanager.py/
    # crtmanager.py action function's own logger calls (e.g. assign/revoke/
    # confirm) a real destination when called in-process from the various
    # tabs below - previously their outcome had no persistent record at all
    # once called through admintui rather than the CLI (see the 2026-09-20
    # issue.md entry this was written to close).
    setup_tool_logging_from_file(DEFAULT_SERVER_CONFIG_FILE, "admintui", console=False)

    try:
        init_database()
    except SchemaOutOfDate as e:
        print(f"Error: {e}")
        sys.exit(1)
    KeysrvAdminApp().run()


if __name__ == "__main__":
    main()
