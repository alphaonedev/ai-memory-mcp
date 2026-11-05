"""Exercise the docs home-path guard and byte-preserving repair (#8493)."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "scripts/ci/check_docs_private_paths.py"
SCRATCH = REPO / ".local-runs/redaction/tests"
DOC = "docs/nested/record.md"
PLACEHOLDER = b"<home>"


class DocsPrivatePaths(unittest.TestCase):
    """Run the real CLI against isolated documentation trees."""

    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "docs private-path gate must exist")
        SCRATCH.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.doc = self.root / DOC
        self.doc.parent.mkdir(parents=True)

    def run_gate(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), *args],
            capture_output=True, text=True, check=False,
        )

    def test_linux_path_reports_file_line_and_prefix(self):
        self.doc.write_bytes(b"header\n/home/private_account/project/file\n")
        result = self.run_gate()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(DOC + ":2: /home/private_account", result.stdout)

    def test_macos_path_is_rejected(self):
        self.doc.write_bytes(b"`/Users/private_account/project`\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_named_tilde_home_is_rejected(self):
        self.doc.write_bytes(b"`~private_account/project`\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_bare_named_home_in_inline_code_is_rejected(self):
        self.doc.write_bytes(b"home: `~private_account`\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_generic_placeholders_are_preserved(self):
        content = b"/home/user/project /Users/alice/project ~bob/project <home>/project $HOME/project ~/project\n"
        self.doc.write_bytes(content)
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.doc.read_bytes(), content)

    def test_fix_changes_only_prefix_bytes_and_is_idempotent(self):
        content = (b"# historical record\r\n\xff /home/private_account/a  \r\n"
                   b"/Users/private_account/b ~private_account/c\nlast byte")
        self.doc.write_bytes(content)
        expected = content.replace(b"/home/private_account", PLACEHOLDER)
        expected = expected.replace(b"/Users/private_account", PLACEHOLDER)
        expected = expected.replace(b"~private_account", PLACEHOLDER)
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.doc.read_bytes(), expected)
        self.assertEqual(self.run_gate().returncode, 0)
        self.assertEqual(self.run_gate("--fix").returncode, 0)
        self.assertEqual(self.doc.read_bytes(), expected)

    def test_allow_file_is_data_and_matches_whole_names(self):
        allow = self.root / "allow.json"
        allow.write_text(json.dumps({"allowed_names": ["fixture_account"]}))
        self.doc.write_bytes(b"/home/fixture_account/a\n/home/fixture_account_extra/b\n")
        result = self.run_gate("--allow-file", str(allow))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(DOC + ":1:", result.stdout)
        self.assertIn(DOC + ":2:", result.stdout)

    def test_bad_allow_file_refuses(self):
        allow = self.root / "allow.json"
        allow.write_text('{"allowed_names": "anything"}')
        self.doc.write_bytes(b"safe\n")
        result = self.run_gate("--allow-file", str(allow))
        self.assertEqual(result.returncode, 2)
        self.assertIn("allowed_names", result.stderr)

    def test_markdown_below_docs_only(self):
        self.doc.write_bytes(b"safe\n")
        (self.root / "outside.md").write_bytes(b"/home/private_account/a\n")
        (self.doc.parent / "data.txt").write_bytes(b"/home/private_account/b\n")
        self.assertEqual(self.run_gate().returncode, 0)

    def test_symlink_is_refused_without_writing_target(self):
        target = self.root / "outside.md"
        content = b"/home/private_account/a\n"
        target.write_bytes(content)
        self.doc.symlink_to(target)
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)
        self.assertEqual(target.read_bytes(), content)

    def test_directory_symlink_is_refused(self):
        self.doc.write_bytes(b"safe\n")
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "docs/linked").symlink_to(outside, target_is_directory=True)
        result = self.run_gate()
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)


if __name__ == "__main__":
    unittest.main()
