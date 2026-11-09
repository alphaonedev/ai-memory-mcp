"""cargo_skip keeps every byte of the work tree top git reports (#8493, round 4).

Round 3 resolved the top with `rev-parse --show-toplevel` and then called
.strip() on the output, which also removed whitespace that belongs to the path.
A work tree directory whose name ends in a space (w1: with a sibling repository
at the stripped path, the listings ran against the sibling and the classifier
answered docs_only=true cargo_skip=true; w2: no sibling, fail closed) or in a
tab or a carriage return must round-trip. Only the one trailing newline git
appends may be removed.

Every case builds throwaway repositories under the repository's `.local-runs/`
(impact_fixture) and runs the CLI with `--repo <that tree>`.
"""
import unittest
from pathlib import Path

from impact_fixture import git, make_scratch, write_files
from test_impact_cargo_skip_symlink_tracked_8493 import (
    DOCS_FALSE, DOCS_TRUE, REASON_ERROR, REASON_TRACKED, SKIP_FALSE,
    SKIP_TRUE, run_cli)

DOCS_CHANGE = "docs/other.md"
TRAILING_SPACE = "tree "
SIBLING = "tree"
TRAILING_TAB = "tab\t"
TRAILING_CR = "cr\r"


class ToplevelBytes(unittest.TestCase):
    """(#8493 r4) the top path is taken byte for byte from git."""

    def setUp(self):
        self.scratch = make_scratch()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def make_repo(self, name: str, link: bool) -> Path:
        """Create repository `name` under the scratch root; commit a symlink if `link`."""
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
        """Assert both verdicts false, the tracked-symlink reason and three lines."""
        self.assertIn(SKIP_FALSE, out, out)
        self.assertIn(DOCS_FALSE, out, out)
        self.assertIn(REASON_TRACKED, out, out)
        self.assertEqual(len(out.splitlines()), 3, out)

    def test_w1_trailing_space_tree_with_a_symlink_free_sibling(self):
        """(r4 w1) the sibling without the trailing space must not be scanned."""
        tree = self.make_repo(TRAILING_SPACE, link=True)
        self.make_repo(SIBLING, link=False)
        out = run_cli(tree, DOCS_CHANGE)
        self.assertNotIn(SKIP_TRUE, out, out)
        self.assertNotIn(DOCS_TRUE, out, out)
        self.assert_forced(out)

    def test_w2_trailing_space_tree_without_a_sibling(self):
        """(r4 w2) no sibling: both verdicts false and a reason that is not docs-only."""
        tree = self.make_repo(TRAILING_SPACE, link=True)
        out = run_cli(tree, DOCS_CHANGE)
        self.assertIn(SKIP_FALSE, out, out)
        self.assertIn(DOCS_FALSE, out, out)
        self.assertTrue(REASON_TRACKED in out or REASON_ERROR in out, out)
        self.assertNotIn(DOCS_TRUE, out, out)

    def test_top_ending_in_a_tab_round_trips(self):
        """(r4) a work tree directory ending in a tab byte keeps it."""
        self.assert_forced(run_cli(self.make_repo(TRAILING_TAB, link=True), DOCS_CHANGE))

    def test_top_ending_in_a_carriage_return_round_trips(self):
        """(r4) a work tree directory ending in a CR byte keeps it."""
        self.assert_forced(run_cli(self.make_repo(TRAILING_CR, link=True), DOCS_CHANGE))


if __name__ == "__main__":
    unittest.main()
