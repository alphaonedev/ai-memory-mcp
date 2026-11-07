"""cargo_skip round 5 (#8493): git environment scrub, unborn-HEAD reasons, gitlinks.

F1: a repository-locating git environment variable inherited from the caller
must never redirect the classifier's git calls to another repository.
F2: both unborn-HEAD shapes report the reason the module docstring states.
N2: a tracked gitlink (mode 160000) forces full CI like a tracked symlink.

Every case builds throwaway repositories under `.local-runs/` (impact_fixture).
"""
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Dict, Optional

from impact_fixture import IMPACT_DIR, RULES_JSON, git, make_scratch, write_files

sys.path.append(str(IMPACT_DIR.parent))
from impact import cargo_skip  # noqa: E402

CARGO_SKIP = IMPACT_DIR / "cargo_skip.py"
REASON_TRACKED = "tracked-symlink-full-ci"
REASON_GITLINK = "tracked-gitlink-full-ci"
REASON_ERROR = "classifier-error-fail-closed"
DOCS_CHANGE = "docs/ADMIN_GUIDE.md"
GITLINK_SHA = "1" * 40


def run_cli(repo: Path, env: Optional[Dict[str, str]] = None) -> str:
    """Run cargo_skip.py --stdin for a docs change against `repo`; return stdout."""
    res = subprocess.run(
        [sys.executable, "-I", str(CARGO_SKIP), "--stdin", "--rules", str(RULES_JSON),
         "--repo", str(repo)],
        input=DOCS_CHANGE + "\n", capture_output=True, text=True, check=True, env=env)
    return res.stdout


class Base(unittest.TestCase):
    """Scratch directory plus an assertion for a closed three-line verdict."""

    def setUp(self):
        self.scratch = make_scratch()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def make_repo(self, name: str) -> Path:
        """Create and return an empty repository `name` under the scratch root."""
        repo = self.root / name
        repo.mkdir()
        git(repo, "init", "-q", "-b", "main")
        return repo

    def assert_closed(self, out: str, reason: str) -> None:
        """Assert both verdicts false, `reason` named, and exactly three lines."""
        self.assertIn("cargo_skip=false", out, out)
        self.assertIn("docs_only=false", out, out)
        self.assertIn(reason, out, out)
        self.assertEqual(len(out.splitlines()), 3, out)


class EnvScrub(Base):
    """(F1) inherited git location variables are dropped from every git call."""

    def setUp(self):
        super().setUp()
        self.linked = self.make_repo("linked")
        write_files(self.linked, {"real.txt": "r\n", "docs/other.md": "o\n"})
        (self.linked / "notes").mkdir()
        (self.linked / "notes" / "link.txt").symlink_to("../real.txt")
        git(self.linked, "add", "--", "real.txt", "docs/other.md", "notes/link.txt")
        git(self.linked, "commit", "-q", "-m", "linked")
        self.clean = self.make_repo("clean")
        write_files(self.clean, {"docs/other.md": "o\n"})
        git(self.clean, "add", "--", "docs/other.md")
        git(self.clean, "commit", "-q", "-m", "clean")

    def test_constant_matches_the_git_on_this_host(self):
        listed = subprocess.run(["git", "rev-parse", "--local-env-vars"],
                                capture_output=True, text=True, check=True).stdout.split()
        self.assertEqual(sorted(cargo_skip.GIT_LOCAL_ENV_VARS), sorted(listed))

    def test_git_dir_alone_cannot_redirect_the_scan(self):
        env = dict(os.environ, GIT_DIR=str(self.clean / ".git"))
        self.assert_closed(run_cli(self.linked, env=env), REASON_TRACKED)

    def test_git_dir_with_work_tree_cannot_redirect_the_scan(self):
        env = dict(os.environ, GIT_DIR=str(self.clean / ".git"),
                   GIT_WORK_TREE=str(self.clean))
        self.assert_closed(run_cli(self.linked, env=env), REASON_TRACKED)

    def test_git_index_file_cannot_hide_a_staged_symlink(self):
        """The symlink is staged only; a clean index file must not replace the real one."""
        staged = self.make_repo("staged")
        write_files(staged, {"real.txt": "r\n", "docs/other.md": "o\n"})
        git(staged, "add", "--", "real.txt", "docs/other.md")
        git(staged, "commit", "-q", "-m", "plain")
        clean_index = self.root / "clean-index"
        shutil.copyfile(staged / ".git" / "index", clean_index)
        (staged / "link.txt").symlink_to("real.txt")
        git(staged, "add", "--", "link.txt")
        env = dict(os.environ, GIT_INDEX_FILE=str(clean_index))
        self.assert_closed(run_cli(staged, env=env), REASON_TRACKED)

    def test_scrub_keeps_path_and_drops_only_the_listed_names(self):
        env = cargo_skip.git_environment(
            {"PATH": "/x", "HOME": "/h", "GIT_DIR": "/d", "GIT_CONFIG_COUNT": "1"})
        self.assertEqual(env, {"PATH": "/x", "HOME": "/h"})


class UnbornHead(Base):
    """(F2) the docstring names the reason of each unborn-HEAD shape."""

    def test_unborn_head_with_a_staged_symlink_reports_the_symlink(self):
        repo = self.make_repo("unborn-staged")
        write_files(repo, {"real.txt": "r\n"})
        (repo / "link.txt").symlink_to("real.txt")
        git(repo, "add", "--", "real.txt", "link.txt")
        self.assert_closed(run_cli(repo), REASON_TRACKED)

    def test_unborn_head_with_nothing_staged_fails_closed(self):
        repo = self.make_repo("unborn-empty")
        self.assert_closed(run_cli(repo), REASON_ERROR)

    def test_docstring_states_the_index_is_scanned_before_head(self):
        self.assertIn("before the HEAD-tree listing runs", cargo_skip.__doc__)


class Gitlink(Base):
    """(N2) a mode 160000 entry forces full CI in both scans."""

    def add_gitlink(self, repo: Path, path: str) -> None:
        """Stage a gitlink entry without any submodule checkout."""
        git(repo, "update-index", "--add", "--cacheinfo",
            "160000,%s,%s" % (GITLINK_SHA, path))

    def test_staged_gitlink_under_a_docs_glob_forces_full_ci(self):
        repo = self.make_repo("staged-gitlink")
        write_files(repo, {"docs/other.md": "o\n"})
        git(repo, "add", "--", "docs/other.md")
        git(repo, "commit", "-q", "-m", "plain")
        self.add_gitlink(repo, "docs/compliance/sub")
        out = run_cli(repo)
        self.assert_closed(out, REASON_GITLINK)
        self.assertIn("docs/compliance/sub", out)

    def test_committed_gitlink_with_an_empty_index_forces_full_ci(self):
        repo = self.make_repo("head-gitlink")
        write_files(repo, {"docs/other.md": "o\n"})
        git(repo, "add", "--", "docs/other.md")
        self.add_gitlink(repo, "vendor/sub")
        git(repo, "commit", "-q", "-m", "gitlink")
        (repo / ".git" / "index").unlink()
        self.assert_closed(run_cli(repo), REASON_GITLINK)

    def test_symlink_listed_before_a_gitlink_keeps_the_symlink_reason(self):
        repo = self.make_repo("both")
        write_files(repo, {"real.txt": "r\n"})
        (repo / "a-link.txt").symlink_to("real.txt")
        git(repo, "add", "--", "real.txt", "a-link.txt")
        self.add_gitlink(repo, "z-sub")
        git(repo, "commit", "-q", "-m", "both")
        self.assert_closed(run_cli(repo), REASON_TRACKED)


if __name__ == "__main__":
    unittest.main()
