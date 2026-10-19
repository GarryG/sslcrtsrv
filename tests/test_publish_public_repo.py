"""Regression test for internal/tools/publish_public_repo.py's public export.

This exists because of a real bug that slipped through an actual release:
WEB_ADMIN_TEXT_REMOVALS stripped the scs-web-admin-bridge references from
setup.cfg, debian/sslcrtsrv-server.install, and debian/control, but not from
debian/sslcrtsrv-server.manpages - which still listed the export-ignored
man/scs-web-admin-bridge.1, breaking `dh_installman` the first time a real
`dpkg-buildpackage` ran against the actual public export (the new GitHub
Actions release workflow, not anything that ran locally before). Nothing in
the existing test suite ever built a package from the exported tree, so this
went unnoticed until a real CI build hit it.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import importlib.util
import os
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_PATH = os.path.join(REPO_ROOT, "internal", "tools", "publish_public_repo.py")


def _load_publish_script():
    spec = importlib.util.spec_from_file_location("publish_public_repo", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(os.path.isfile(SCRIPT_PATH), "internal/ not present in this checkout (public export)")
class TestPublicExport(unittest.TestCase):
    """Builds a real export of the current HEAD (same export_tree() +
    strip_web_admin_references() the real publish does) and checks it for
    the specific class of bug that broke a real release: a packaging file
    listing a man page/install path that doesn't actually exist in the
    export."""

    @classmethod
    def setUpClass(cls):
        cls.publish = _load_publish_script()
        cls.tmp_dir = tempfile.mkdtemp(prefix="publish-public-repo-test-")
        commit_sha = cls.publish.resolve_commit("HEAD")
        cls.publish.export_tree(commit_sha, cls.tmp_dir)
        cls.publish.strip_web_admin_references(cls.tmp_dir)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_every_manpages_entry_exists_in_the_export(self):
        debian_dir = os.path.join(self.tmp_dir, "debian")
        manpages_files = [f for f in os.listdir(debian_dir) if f.endswith(".manpages")]
        self.assertTrue(manpages_files, "expected at least one debian/*.manpages file in the export")
        for manpages_file in manpages_files:
            with open(os.path.join(debian_dir, manpages_file)) as f:
                entries = [line.strip() for line in f if line.strip()]
            for entry in entries:
                self.assertTrue(
                    os.path.isfile(os.path.join(self.tmp_dir, entry)),
                    f"{manpages_file} lists {entry!r}, which doesn't exist in the public export - "
                    f"add it to WEB_ADMIN_TEXT_REMOVALS (or another such removal) if it's meant to be "
                    f"excluded, or stop excluding the file it points to")

    def test_no_web_admin_bridge_references_remain_in_packaging_files(self):
        for relative_path in ("setup.cfg", "debian/control",
                               "debian/sslcrtsrv-server.install", "debian/sslcrtsrv-server.manpages"):
            with open(os.path.join(self.tmp_dir, relative_path)) as f:
                content = f.read()
            self.assertNotIn("web_admin_bridge", content, f"{relative_path} still references web_admin_bridge")
            self.assertNotIn("scs-web-admin-bridge", content, f"{relative_path} still references scs-web-admin-bridge")


if __name__ == "__main__":
    unittest.main()
