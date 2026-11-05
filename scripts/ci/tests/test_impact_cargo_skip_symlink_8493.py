"""cargo_skip refuses to skip when a registered read-glob path is a symlink (#8493).

rules.json lists documents a Rust test reads (test_read_globs). The globs match
file NAMES only, so when one of those documents is a symlink an edit to its
TARGET never shows up as a change to the registered path and cargo would be
skipped although a pin test reads the content: fail-open by omission. The
classifier must instead force cargo and name the symlink in the reason line.

Every case builds a throwaway repository under the repository's `.local-runs/`
(impact_fixture.make_scratch; git init plus one commit, because the classifier
judges the top --repo resolves to, round 7) and runs the CLI with `--repo <tree>`.
"""
import subprocess
import sys
import unittest
from pathlib import Path

from impact_fixture import IMPACT_DIR, git, make_scratch, write_files

CARGO_SKIP = IMPACT_DIR / "cargo_skip.py"
REGISTERED_DOC = "docs/ADMIN_GUIDE.md"
SYMLINK_TARGET = "docs/admin_guide_target.md"
REGISTERED_DIR_LITERAL = "docs/compliance"
DIR_TARGET = "docs/compliance_target"
SKIP_TRUE = "cargo_skip=true"
SKIP_FALSE = "cargo_skip=false"
REASON_FRAGMENT = "registered-read-path-is-symlink"


def run_cli(repo: Path, changed: str) -> str:
    """Run cargo_skip.py --stdin for `changed` against the tree `repo`; return stdout."""
    res = subprocess.run(
        [sys.executable, "-I", str(CARGO_SKIP), "--stdin", "--repo", str(repo)],
        input=changed + "\n", capture_output=True, text=True, check=True)
    return res.stdout


class SymlinkedRegisteredPath(unittest.TestCase):
    """(#8493) a symlinked test_read_globs path forces cargo."""

    def setUp(self):
        self.scratch = make_scratch()
        self.addCleanup(self.scratch.cleanup)
        self.repo = Path(self.scratch.name)
        git(self.repo, "init", "-q", "-b", "main")
        write_files(self.repo, {"seed.txt": "s\n"})
        git(self.repo, "add", "--", "seed.txt")
        git(self.repo, "commit", "-q", "-m", "seed")

    def test_symlinked_registered_document_forces_cargo(self):
        write_files(self.repo, {SYMLINK_TARGET: "target\n"})
        (self.repo / REGISTERED_DOC).symlink_to(Path(SYMLINK_TARGET).name)
        out = run_cli(self.repo, SYMLINK_TARGET)
        self.assertIn(SKIP_FALSE, out, out)
        self.assertIn(REASON_FRAGMENT, out, out)
        self.assertIn(REGISTERED_DOC, out, out)

    def test_symlinked_directory_under_a_registered_glob_forces_cargo(self):
        write_files(self.repo, {DIR_TARGET + "/a.md": "a\n"})
        (self.repo / REGISTERED_DIR_LITERAL).symlink_to(Path(DIR_TARGET).name)
        out = run_cli(self.repo, DIR_TARGET + "/a.md")
        self.assertIn(SKIP_FALSE, out, out)
        self.assertIn(REASON_FRAGMENT, out, out)
        self.assertIn(REGISTERED_DIR_LITERAL, out, out)

    def test_regular_registered_document_keeps_the_skip(self):
        write_files(self.repo, {REGISTERED_DOC: "doc\n", SYMLINK_TARGET: "t\n"})
        out = run_cli(self.repo, SYMLINK_TARGET)
        self.assertIn(SKIP_TRUE, out, out)
        self.assertNotIn(REASON_FRAGMENT, out, out)

    def test_missing_registered_document_is_not_a_symlink(self):
        write_files(self.repo, {SYMLINK_TARGET: "t\n"})
        out = run_cli(self.repo, SYMLINK_TARGET)
        self.assertIn(SKIP_TRUE, out, out)
        self.assertNotIn(REASON_FRAGMENT, out, out)


if __name__ == "__main__":
    unittest.main()
