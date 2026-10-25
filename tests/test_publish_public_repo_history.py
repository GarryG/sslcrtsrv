"""Tests for internal/tools/publish_public_repo.py's persistent-checkout
machinery (ensure_public_repo_checkout/clear_working_tree/
commit_and_push_export) - added after a real, user-reported bug: the
previous version of this script re-created a brand new repo and
force-pushed a single squashed commit over the public GitHub repo's main
branch on every run, discarding its entire prior commit history each time.
These functions replace that with a persistent local checkout that's synced
to origin/main and then given one ordinary incremental commit, so public
history survives across runs.

A local bare repo stands in for GITHUB_REMOTE throughout - no real network
or GitHub access is exercised.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_PATH = os.path.join(REPO_ROOT, "internal", "tools", "publish_public_repo.py")


def _load_publish_script():
    spec = importlib.util.spec_from_file_location("publish_public_repo", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(args, cwd):
    subprocess.run(["git"] + args, cwd=cwd, check=True, capture_output=True, text=True)


def _log_subjects(repo_dir):
    result = subprocess.run(["git", "log", "--format=%s"], cwd=repo_dir, check=True, capture_output=True, text=True)
    return [line for line in result.stdout.splitlines() if line]


@unittest.skipUnless(os.path.isfile(SCRIPT_PATH), "internal/ not present in this checkout (public export)")
class TestPersistentPublicCheckout(unittest.TestCase):
    def setUp(self):
        self.publish = _load_publish_script()
        self.work_dir = tempfile.mkdtemp(prefix="publish-public-repo-history-test-")
        self.remote_dir = os.path.join(self.work_dir, "remote.git")
        self.checkout_dir = os.path.join(self.work_dir, "checkout")
        os.makedirs(self.remote_dir)
        _git(["init", "-q", "--bare", "--initial-branch=main", self.remote_dir], cwd=self.work_dir)
        self.publish.GITHUB_REMOTE = self.remote_dir

    def tearDown(self):
        shutil.rmtree(self.work_dir, ignore_errors=True)

    def _remote_subjects(self):
        clone_dir = tempfile.mkdtemp(dir=self.work_dir)
        _git(["clone", "-q", self.remote_dir, clone_dir], cwd=self.work_dir)
        return _log_subjects(clone_dir)

    def test_first_publish_clones_and_creates_the_first_commit(self):
        self.publish.ensure_public_repo_checkout(self.checkout_dir)
        with open(os.path.join(self.checkout_dir, "a.txt"), "w") as f:
            f.write("v1\n")
        committed = self.publish.commit_and_push_export(self.checkout_dir, "first")
        self.assertTrue(committed)
        self.assertEqual(self._remote_subjects(), ["first"])

    def test_second_publish_adds_a_commit_without_discarding_the_first(self):
        self.publish.ensure_public_repo_checkout(self.checkout_dir)
        with open(os.path.join(self.checkout_dir, "a.txt"), "w") as f:
            f.write("v1\n")
        self.publish.commit_and_push_export(self.checkout_dir, "first")

        # Simulate a second, independent run of the script against the same
        # remote - a fresh local directory, same as a different machine/day.
        second_checkout = os.path.join(self.work_dir, "checkout2")
        self.publish.ensure_public_repo_checkout(second_checkout)
        self.publish.clear_working_tree(second_checkout)
        with open(os.path.join(second_checkout, "a.txt"), "w") as f:
            f.write("v2\n")
        committed = self.publish.commit_and_push_export(second_checkout, "second")

        self.assertTrue(committed)
        # Both commits must still be present - this is the actual bug fix:
        # the old force-push-a-squash-commit behavior would have left only "second".
        self.assertEqual(self._remote_subjects(), ["second", "first"])

    def test_identical_export_is_not_recommitted(self):
        self.publish.ensure_public_repo_checkout(self.checkout_dir)
        with open(os.path.join(self.checkout_dir, "a.txt"), "w") as f:
            f.write("same content\n")
        self.assertTrue(self.publish.commit_and_push_export(self.checkout_dir, "first"))

        # Re-sync and re-apply the exact same content - nothing to publish.
        self.publish.ensure_public_repo_checkout(self.checkout_dir)
        self.publish.clear_working_tree(self.checkout_dir)
        with open(os.path.join(self.checkout_dir, "a.txt"), "w") as f:
            f.write("same content\n")
        committed = self.publish.commit_and_push_export(self.checkout_dir, "would-be-second")

        self.assertFalse(committed)
        self.assertEqual(self._remote_subjects(), ["first"])

    def test_clear_working_tree_removes_old_files_but_keeps_git(self):
        self.publish.ensure_public_repo_checkout(self.checkout_dir)
        with open(os.path.join(self.checkout_dir, "stale.txt"), "w") as f:
            f.write("will be removed\n")
        self.publish.commit_and_push_export(self.checkout_dir, "first")

        self.publish.clear_working_tree(self.checkout_dir)

        self.assertFalse(os.path.exists(os.path.join(self.checkout_dir, "stale.txt")))
        self.assertTrue(os.path.isdir(os.path.join(self.checkout_dir, ".git")))

    def test_a_file_removed_from_the_export_is_committed_as_a_deletion(self):
        self.publish.ensure_public_repo_checkout(self.checkout_dir)
        with open(os.path.join(self.checkout_dir, "will_be_removed.txt"), "w") as f:
            f.write("v1\n")
        self.publish.commit_and_push_export(self.checkout_dir, "first")

        self.publish.ensure_public_repo_checkout(self.checkout_dir)
        self.publish.clear_working_tree(self.checkout_dir)
        with open(os.path.join(self.checkout_dir, "kept.txt"), "w") as f:
            f.write("v2\n")
        self.publish.commit_and_push_export(self.checkout_dir, "second")

        result = subprocess.run(["git", "show", "--stat", "HEAD"], cwd=self.checkout_dir,
                                 check=True, capture_output=True, text=True)
        self.assertIn("will_be_removed.txt", result.stdout)
        self.assertIn("kept.txt", result.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.checkout_dir, "will_be_removed.txt")))


if __name__ == "__main__":
    unittest.main()
