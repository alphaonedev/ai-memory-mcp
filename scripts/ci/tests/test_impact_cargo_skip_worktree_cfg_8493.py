"""cargo_skip scans the repository --repo resolves to, not what sits at its top (#8493, round 6).

Round 5 resolved the top with `rev-parse --show-toplevel` and ran both listings as
`git -C <top>`, which discovers whatever repository lives at that top. A repository
whose own .git/config sets core.worktree to a symlink-free repository (or to a plain
directory nested in one) was therefore scanned through the other repository and
answered docs_only=true. The listings now take --git-dir and --work-tree from one
`rev-parse --absolute-git-dir --show-toplevel` call.

Every case builds throwaway repositories under the repository's `.local-runs/`.
"""
import sys
import unittest
from pathlib import Path

from impact_fixture import IMPACT_DIR, git, make_scratch, write_files
from test_impact_cargo_skip_symlink_tracked_8493 import (
    DOCS_FALSE, DOCS_TRUE, REASON_TRACKED, SKIP_FALSE, SKIP_TRUE, run_cli)

sys.path.append(str(IMPACT_DIR.parent))
from impact import cargo_skip  # noqa: E402

DOCS_CHANGE = "docs/other.md"


class WorktreeConfig(unittest.TestCase):
    """(#8493 r6 F1) the scan trusts only the git dir --repo resolved to."""

    def setUp(self):
        self.scratch = make_scratch()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def make_repo(self, name: str, link: bool) -> Path:
        """Create repository `name`; commit notes/link.txt as a symlink if `link`."""
        repo = self.root / name
        repo.mkdir()
        git(repo, "init", "-q", "-b", "main")
        write_files(repo, {"docs/other.md": "g\n", "real.txt": "r\n"})
        paths = ["docs/other.md", "real.txt"]
        if link:
            (repo / "notes").mkdir()
            (repo / "notes" / "link.txt").symlink_to("../real.txt")
            paths.append("notes/link.txt")
        git(repo, "add", "--", *paths)
        git(repo, "commit", "-q", "-m", "seed")
        return repo

    def assert_forced(self, out: str) -> None:
        self.assertNotIn(SKIP_TRUE, out, out)
        self.assertNotIn(DOCS_TRUE, out, out)
        self.assertIn(SKIP_FALSE, out, out)
        self.assertIn(DOCS_FALSE, out, out)
        self.assertIn(REASON_TRACKED, out, out)

    def test_core_worktree_pointing_at_another_repository(self):
        linked = self.make_repo("linked", link=True)
        clean = self.make_repo("clean", link=False)
        git(linked, "config", "core.worktree", str(clean))
        self.assert_forced(run_cli(linked, DOCS_CHANGE))

    def test_core_worktree_pointing_at_a_plain_directory_in_a_clean_checkout(self):
        linked = self.make_repo("linked", link=True)
        clean = self.make_repo("clean", link=False)
        nested = clean / "plain"
        nested.mkdir()
        git(linked, "config", "core.worktree", str(nested))
        self.assert_forced(run_cli(linked, DOCS_CHANGE))

    def test_docstring_states_unborn_head_qualifier(self):
        doc = cargo_skip.tracked_symlink.__doc__
        self.assertIn("an unborn HEAD with nothing staged as a symlink or gitlink", doc)
        self.assertIn("--absolute-git-dir", doc)


if __name__ == "__main__":
    unittest.main()
