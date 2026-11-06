"""Exercise maintained debt-register anchors through the real gate command."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
REGISTER = Path("docs/internal/v070-accepted-debt.md")
GATE = ROOT / "scripts/ci/check_debt_doc_anchors.py"
LEGACY_GATE = ROOT / "scripts/check-doc-symbol-anchors.sh"
FIXTURE_SOURCE = Path("src/anchor_fixture.rs")
REFERENCE_NAMES = ("ARCHITECTURE_REFERENCE.md", "CODE_STYLE.md")


class DebtDocAnchors8599(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".local-runs"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="debt-anchors-8599-", dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.document = self.root / REGISTER
        self.document.parent.mkdir(parents=True)
        source = self.root / FIXTURE_SOURCE
        source.parent.mkdir()
        source.write_text("pub struct Anchor;\npub fn current_anchor() {}\n", encoding="utf-8")
        references = self.root / "docs/reference"
        references.mkdir()
        for name in REFERENCE_NAMES:
            (references / name).write_text("# Fixture\nReference body.\n", encoding="utf-8")
        allow = self.root / "scripts/qc-allowlists/doc-symbol-anchors-allow.txt"
        allow.parent.mkdir(parents=True)
        allow.write_text("", encoding="utf-8")
        self.document.write_text(f"See `{FIXTURE_SOURCE}::current_anchor`.\n", encoding="utf-8")

    def run_gate(self):
        environment = os.environ.copy()
        environment["AI_MEMORY_SYMBOL_GATE_ROOT"] = str(self.root)
        if environment.get("DEBT_ANCHOR_TEST_LEGACY") == "1":
            command = ["bash", str(LEGACY_GATE)]
        else:
            command = [sys.executable, str(GATE)]
        return subprocess.run(command, env=environment, capture_output=True, text=True, check=False)

    def assert_rejected(self, token):
        result = self.run_gate()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(str(REGISTER), result.stderr)
        self.assertIn(token, result.stderr)

    def test_current_path_and_qualified_symbol_pass_8599(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_path_is_rejected_8599(self):
        self.document.write_text("See `src/absent_anchor.rs`.\n", encoding="utf-8")
        self.assert_rejected("src/absent_anchor.rs")

    def test_renamed_symbol_is_rejected_8599(self):
        self.document.write_text(f"See `{FIXTURE_SOURCE}::old_anchor`.\n", encoding="utf-8")
        self.assert_rejected("old_anchor")

    def test_line_past_eof_is_rejected_8599(self):
        self.document.write_text(f"See `{FIXTURE_SOURCE}:9999`.\n", encoding="utf-8")
        self.assert_rejected(":9999")

    def test_markdown_symbol_link_is_rejected_8599(self):
        self.document.write_text(f"See [`old_anchor`](../../{FIXTURE_SOURCE}).\n", encoding="utf-8")
        self.assert_rejected("old_anchor")

    def test_missing_document_is_rejected_8599(self):
        self.document.unlink()
        self.assert_rejected("regular file")

    def test_empty_document_is_rejected_8599(self):
        self.document.write_text("", encoding="utf-8")
        self.assert_rejected("no source anchors")

    def test_symlinked_document_is_rejected_8599(self):
        other = self.root / "document-copy.md"
        self.document.rename(other)
        self.document.symlink_to(other)
        self.assert_rejected("symlink")

    def test_symlinked_source_is_rejected_8599(self):
        source = self.root / FIXTURE_SOURCE
        other = self.root / "source-copy.rs"
        source.rename(other)
        source.symlink_to(other)
        self.assert_rejected("symlink")

    def test_historical_sibling_remains_unscanned_8599(self):
        (self.document.parent / "frozen-review.md").write_text("See `src/retired.rs`.\n", encoding="utf-8")
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_valid_anchor_forms_pass_8599(self):
        self.document.write_text(
            f"See `{FIXTURE_SOURCE}` and `{FIXTURE_SOURCE}:1`.\n"
            f"See `{FIXTURE_SOURCE}::{{Anchor, current_anchor}}`.\n"
            f"See [`current_anchor`](../../{FIXTURE_SOURCE}).\n",
            encoding="utf-8",
        )
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
