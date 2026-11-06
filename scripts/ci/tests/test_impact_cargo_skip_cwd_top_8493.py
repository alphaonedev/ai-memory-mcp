"""cargo_skip judges the whole resolved top whatever the process cwd is (#8493, round 7).

F1: the two listings inherited the classifier's process cwd, which git treats as a
pathspec prefix, so a tracked symlink outside the cwd subtree was missed.
F2: the lstat check on test_read_globs paths used the raw --repo path instead of the
top that --repo resolves to.

Every case builds throwaway repositories under the repository's `.local-runs/`.
"""
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Optional

from impact_fixture import git, make_scratch, write_files
from test_impact_cargo_skip_symlink_tracked_8493 import (
    CARGO_SKIP, DOCS_FALSE, DOCS_TRUE, REASON_TRACKED, RULES_JSON, SKIP_FALSE,
    SKIP_TRUE)

REASON_READ = "registered-read-path-is-symlink-full-ci"
DOCS_CHANGE = "docs/other.md"


def run_in(cwd: Path, repo: str, changed: str = DOCS_CHANGE) -> str:
    """Run the CLI as a subprocess with process cwd `cwd` and --repo `repo`."""
    res = subprocess.run(
        [sys.executable, "-I", str(CARGO_SKIP), "--stdin", "--rules", str(RULES_JSON),
         "--repo", repo],
        input=changed + "\n", capture_output=True, text=True, check=True, cwd=str(cwd))
    return res.stdout


class Base(unittest.TestCase):
    """Scratch directory and repository builder."""

    def setUp(self):
        self.scratch = make_scratch()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def make_repo(self, name: str, link: Optional[str] = None) -> Path:
        """Create repository `name`; commit the symlink `link` if given."""
        repo = self.root / name
        repo.mkdir()
        git(repo, "init", "-q", "-b", "main")
        write_files(repo, {"docs/other.md": "g\n", "real.txt": "r\n", "sub/x.txt": "x\n"})
        paths = ["docs/other.md", "real.txt", "sub/x.txt"]
        if link:
            (repo / link).parent.mkdir(parents=True, exist_ok=True)
            (repo / link).symlink_to("/nonexistent-target")
            paths.append(link)
        git(repo, "add", "--", *paths)
        git(repo, "commit", "-q", "-m", "seed")
        return repo

    def assert_has(self, out: str, reason: str) -> None:
        """Assert both verdicts false and `reason` present."""
        self.assertIn(SKIP_FALSE, out, out)
        self.assertIn(DOCS_FALSE, out, out)
        self.assertIn(reason, out, out)
        self.assertNotIn(SKIP_TRUE, out, out)
        self.assertNotIn(DOCS_TRUE, out, out)


class CwdSubdirectory(Base):
    """(r7 F1) the process cwd must not narrow the listings."""

    def test_top_repo_from_subdirectory(self):
        top = self.make_repo("t", link="notes/link.txt")
        self.assert_has(run_in(top / "sub", str(top)), REASON_TRACKED)

    def test_dot_repo_from_subdirectory(self):
        top = self.make_repo("t", link="notes/link.txt")
        self.assert_has(run_in(top / "sub", "."), REASON_TRACKED)

    def test_subdirectory_repo_from_subdirectory(self):
        top = self.make_repo("t", link="notes/link.txt")
        self.assert_has(run_in(top / "sub", str(top / "sub")), REASON_TRACKED)


class ResolvedTopReadPath(Base):
    """(r7 F2) the lstat check inspects the resolved top."""

    def test_repo_subdirectory_with_top_readme_symlink(self):
        top = self.make_repo("t")
        (top / "README.md").symlink_to("real.txt")
        out = run_in(self.root, str(top / "docs"))
        self.assert_has(out, REASON_READ)
        self.assertIn("README.md", out)

    def test_core_worktree_untracked_readme_symlink(self):
        repo_a = self.make_repo("a")
        work = self.root / "w"
        work.mkdir()
        (work / "README.md").symlink_to("/nonexistent-target")
        git(repo_a, "config", "core.worktree", str(work))
        out = run_in(self.root, str(repo_a))
        self.assert_has(out, REASON_READ)
        self.assertIn("README.md", out)


if __name__ == "__main__":
    unittest.main()
