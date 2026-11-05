"""cargo_skip forces cargo when the repo tracks any symlink (#8493, round 2).

Round 1 checked only the literal prefix of each test_read_globs entry, so a
symlink at a path a wildcard glob matches (docs/compliance/x.md,
crates/foo/README.md, a directory below docs/compliance) kept cargo_skip=true.
Round 2 lists the index (git ls-files -s -z under --repo) and treats every
mode 120000 entry as a reason for full CI; a git failure fails closed.

Every case builds a throwaway git repository under the repository's
`.local-runs/` (impact_fixture) and runs the CLI with `--repo <that repo>`.
"""
import os
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Dict, Optional

from impact_fixture import IMPACT_DIR, RULES_JSON, git, make_scratch, write_files

CARGO_SKIP = IMPACT_DIR / "cargo_skip.py"
SKIP_TRUE = "cargo_skip=true"
SKIP_FALSE = "cargo_skip=false"
DOCS_TRUE = "docs_only=true"
DOCS_FALSE = "docs_only=false"
REASON_TRACKED = "tracked-symlink-full-ci"
REASON_ERROR = "classifier-error-fail-closed"
DOCS_CHANGE = "docs/ADMIN_GUIDE.md"


def run_cli(repo: Path, changed: str, env: Optional[Dict[str, str]] = None) -> str:
    """Run cargo_skip.py --stdin for `changed` against `repo`; return stdout."""
    res = subprocess.run(
        [sys.executable, "-I", str(CARGO_SKIP), "--stdin", "--rules", str(RULES_JSON),
         "--repo", str(repo)],
        input=changed + "\n", capture_output=True, text=True, check=True, env=env)
    return res.stdout


class TrackedSymlink(unittest.TestCase):
    """(#8493 r2) any tracked symlink forces full CI."""

    def setUp(self):
        self.scratch = make_scratch()
        self.addCleanup(self.scratch.cleanup)
        self.repo = Path(self.scratch.name)
        git(self.repo, "init", "-q", "-b", "main")

    def commit_link(self, link: str, target: str, files: Dict[str, str]) -> None:
        """Write `files`, add the symlink `link` -> `target`, stage and commit."""
        write_files(self.repo, files)
        (self.repo / link).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / link).symlink_to(target)
        git(self.repo, "add", "--", link, *files)
        git(self.repo, "commit", "-q", "-m", "link")

    def assert_forced(self, out: str) -> None:
        """Assert both verdicts false and the tracked-symlink reason."""
        self.assertIn(SKIP_FALSE, out, out)
        self.assertIn(DOCS_FALSE, out, out)
        self.assertIn(REASON_TRACKED, out, out)

    def test_probe_c_symlink_file_under_wildcard_glob(self):
        self.commit_link("docs/compliance/x.md", "../real.md", {"docs/real.md": "r\n"})
        self.assert_forced(run_cli(self.repo, "docs/real.md"))

    def test_probe_c2_symlink_readme_matching_double_star_glob(self):
        self.commit_link("crates/foo/README.md", "../../docs/real.md",
                         {"docs/real.md": "r\n"})
        self.assert_forced(run_cli(self.repo, "docs/real.md"))

    def test_probe_c3_symlink_directory_below_wildcard_glob(self):
        self.commit_link("docs/compliance/sub", "../realdir", {"docs/realdir/a.md": "a\n"})
        self.assert_forced(run_cli(self.repo, "docs/realdir/a.md"))

    def test_tracked_symlink_outside_every_read_glob_still_forces(self):
        self.commit_link("notes/link.txt", "../real.txt", {"real.txt": "r\n"})
        self.assert_forced(run_cli(self.repo, DOCS_CHANGE))

    def test_dangling_tracked_symlink_forces(self):
        self.commit_link("docs/compliance/dead.md", "no-such-target", {"seed.txt": "s\n"})
        self.assert_forced(run_cli(self.repo, DOCS_CHANGE))

    def test_repo_without_symlink_keeps_the_docs_only_verdict(self):
        write_files(self.repo, {"docs/other.md": "o\n"})
        git(self.repo, "add", "--", "docs/other.md")
        git(self.repo, "commit", "-q", "-m", "plain")
        out = run_cli(self.repo, "docs/other.md")
        self.assertIn(SKIP_TRUE, out, out)
        self.assertIn(DOCS_TRUE, out, out)
        self.assertNotIn(REASON_TRACKED, out, out)

    def test_directory_that_is_not_a_git_repository_fails_closed(self):
        plain = self.repo / "plain"
        plain.mkdir()
        # The scratch repo above `plain` must not be discovered: stop git's upward search.
        env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(self.repo))
        out = run_cli(plain, "docs/other.md", env=env)
        self.assertIn(SKIP_FALSE, out, out)
        self.assertIn(DOCS_FALSE, out, out)
        self.assertIn(REASON_ERROR, out, out)
        self.assertEqual(len(out.splitlines()), 3, out)

    def assert_closed(self, out: str, reason: str) -> None:
        """Assert both verdicts false, `reason` named, and exactly three lines."""
        self.assertIn(SKIP_FALSE, out, out)
        self.assertIn(DOCS_FALSE, out, out)
        self.assertIn(reason, out, out)
        self.assertEqual(len(out.splitlines()), 3, out)

    def test_m1_bare_repository_fails_closed(self):
        """(r3 m1) a bare clone of a repo tracking a symlink has no work tree."""
        self.commit_link("notes/link.txt", "../real.txt", {"real.txt": "r\n"})
        bare = self.repo / "bare.git"
        subprocess.run(["git", "clone", "-q", "--bare", str(self.repo), str(bare)],
                       check=True, capture_output=True)
        env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(self.repo))
        self.assert_closed(run_cli(bare, DOCS_CHANGE, env=env), REASON_ERROR)

    def test_m2_repo_naming_a_subdirectory_still_sees_the_symlink_outside_it(self):
        """(r3 m2) --repo docs/ while the symlink sits outside docs/."""
        self.commit_link("notes/link.txt", "../real.txt",
                         {"real.txt": "r\n", "docs/other.md": "o\n"})
        self.assert_closed(run_cli(self.repo / "docs", "docs/other.md"), REASON_TRACKED)

    def test_m3_worktree_without_an_index_still_sees_the_head_symlink(self):
        """(r3 m3) the index file is gone; HEAD still tracks a symlink."""
        self.commit_link("notes/link.txt", "../real.txt",
                         {"real.txt": "r\n", "docs/other.md": "o\n"})
        (self.repo / ".git" / "index").unlink()
        self.assert_closed(run_cli(self.repo, "docs/other.md"), REASON_TRACKED)

    def test_git_that_cannot_start_fails_closed(self):
        """(r3 F2) PATH names an empty directory, so git is not found."""
        write_files(self.repo, {"docs/other.md": "o\n"})
        git(self.repo, "add", "--", "docs/other.md")
        git(self.repo, "commit", "-q", "-m", "plain")
        empty = self.repo / "empty-path"
        empty.mkdir()
        env = dict(os.environ, PATH=str(empty))
        self.assert_closed(run_cli(self.repo, "docs/other.md", env=env), REASON_ERROR)


if __name__ == "__main__":
    unittest.main()
