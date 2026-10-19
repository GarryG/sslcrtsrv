"""Smoke test: every console_scripts entry point module (setup.cfg) must
actually import cleanly and expose a callable `main`.

This exists because of a real bug that slipped through the full test suite:
removing common/client_utils.py's process_fqdns() (replaced by
common/fqdns_utils.py's normalize_fqdns()) left a dangling
`from .common.client_utils import (..., process_fqdns, ...)` in client.py -
a bare name in an import list, never actually called anywhere in that file,
so no existing test (none of which import sslcrtsrv.client at all) caught
it. The installed scs-client script failed with an ImportError on every
invocation until a user hit it in production.

Entry points are read from setup.cfg itself (not hand-copied here), so a
newly added one is automatically covered. A module that fails to import
because an *optional third-party* dependency isn't installed in this
environment (e.g. josepy for acme_server.py, textual for admintui) is
skipped, not failed - this test is only about catching a broken import
*within this project's own code*, not about requiring every optional extra
to be installed wherever the suite runs.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import configparser
import importlib
import os
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP_CFG_PATH = os.path.join(REPO_ROOT, "setup.cfg")


def get_entry_point_modules():
    """{command_name: module_path} from setup.cfg's console_scripts - same
    parsing build-tarballs.py's own get_entry_points() does."""
    config = configparser.ConfigParser()
    config.read(SETUP_CFG_PATH)
    entries = {}
    for line in config.get("options.entry_points", "console_scripts").splitlines():
        line = line.strip()
        if not line:
            continue
        name, target = (part.strip() for part in line.split("=", 1))
        module_path = target.split(":", 1)[0]
        entries[name] = module_path
    return entries


class TestEntryPointModulesImportCleanly(unittest.TestCase):
    def test_every_console_script_module_imports_and_has_main(self):
        entries = get_entry_point_modules()
        self.assertTrue(entries, "setup.cfg's console_scripts parsed to nothing - check SETUP_CFG_PATH/parsing")

        for command_name, module_path in entries.items():
            with self.subTest(command=command_name, module=module_path):
                try:
                    module = importlib.import_module(module_path)
                except ImportError as e:
                    # e.name is the dotted name of whatever failed to
                    # resolve - either this project's own module/symbol
                    # (the real bug class this test exists for), or a
                    # missing *third-party* optional dependency (acceptable
                    # if that extra just isn't installed here).
                    if e.name and e.name.startswith("sslcrtsrv"):
                        self.fail(f"{module_path} (for {command_name}) failed to import due to its own "
                                  f"code, not a missing third-party dependency: {e}")
                    self.skipTest(f"{module_path} (for {command_name}) needs an optional dependency "
                                  f"not installed here: {e}")
                else:
                    self.assertTrue(callable(getattr(module, "main", None)),
                                     f"{module_path} (for {command_name}) has no callable 'main'")


if __name__ == "__main__":
    unittest.main()
