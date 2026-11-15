"""Exercise maintained debt-register anchors through the real gate command."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
REGISTER = Path("docs/internal/v070-accepted-debt.md")
GATE = ROOT / "scripts/ci/check_debt_doc_anchors.py"
LEGACY_GATE = ROOT / "scripts/check-doc-symbol-anchors.sh"
FIXTURE_SOURCE = Path("src/anchor_fixture.rs")
REFERENCE_NAMES = ("ARCHITECTURE_REFERENCE.md", "CODE_STYLE.md")
PREFIX = "debt-doc-anchors"
VALID_LINE = f"See `{FIXTURE_SOURCE}::current_anchor`.\n"
UNCLASSIFIED = "unclassified anchor"
SOURCE_LINE_COUNT = 2
LARGE_REGISTER_LINES = 100_000
LARGE_SOURCE_OPENERS = 100_000
LARGE_RUN_CEILING_SECONDS = 20.0
# Spans that contain .rs or start with src/ but that no known anchor form fully consumes.
UNCLASSIFIED_TRAILING_JUNK = f"{FIXTURE_SOURCE} (x)"
UNCLASSIFIED_BARE_DIR = "src/utils/"
UNCLASSIFIED_FRAGMENT = f"{FIXTURE_SOURCE}#L10"
UNCLASSIFIED_COLON_SYMBOL = f"{FIXTURE_SOURCE}:current_anchor"
UNCLASSIFIED_UNKNOWN_SUFFIX = f"{FIXTURE_SOURCE}.bak"
UNCLASSIFIED_DASHED_NAME = "src/bin/foo-bar.rs"
UNCLASSIFIED_EMPTY_QUALIFIER = f"{FIXTURE_SOURCE}::"
UNCLASSIFIED_OPEN_BRACE = f"{FIXTURE_SOURCE}::{{Anchor"
UNCLASSIFIED_CALL_SYNTAX = f"{FIXTURE_SOURCE}::current_anchor()"
UNCLASSIFIED_OPEN_RANGE = f"{FIXTURE_SOURCE}:1-"
UNCLASSIFIED_LINE_LIST = f"{FIXTURE_SOURCE}:1,2"
UNCLASSIFIED_DOTDOT_SEGMENT = "src/../escape.rs"
UNCLASSIFIED_UPPER_SUFFIX = "src/anchor_fixture.RS"
UNCLASSIFIED_HUGE_LINE = f"{FIXTURE_SOURCE}:{'9' * 40}"
UNCLASSIFIED_BAD_BRACE_ITEM = f"{FIXTURE_SOURCE}::{{Anchor, bad-item}}"
UNCLASSIFIED_CORPUS = (
    UNCLASSIFIED_TRAILING_JUNK,
    UNCLASSIFIED_BARE_DIR,
    UNCLASSIFIED_FRAGMENT,
    UNCLASSIFIED_COLON_SYMBOL,
    UNCLASSIFIED_UNKNOWN_SUFFIX,
    UNCLASSIFIED_DASHED_NAME,
    UNCLASSIFIED_EMPTY_QUALIFIER,
    UNCLASSIFIED_OPEN_BRACE,
    UNCLASSIFIED_CALL_SYNTAX,
    UNCLASSIFIED_OPEN_RANGE,
    UNCLASSIFIED_LINE_LIST,
    UNCLASSIFIED_DOTDOT_SEGMENT,
    UNCLASSIFIED_UPPER_SUFFIX,
    UNCLASSIFIED_HUGE_LINE,
    UNCLASSIFIED_BAD_BRACE_ITEM,
)
COMMENTED_SOURCE = (
    "// fn line_ghost() {}\n"
    "/* fn block_ghost() {} */ pub fn real_anchor() {}\n"
    "/* outer /* fn nested_ghost() {} */ fn still_commented() {} */\n"
    "/*\nfn multi_ghost() {}\n*/\n"
)


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

    def assert_rejected(self, token, reason, line=1):
        """Require exactly one diagnostic naming the register line, token and reason."""
        result = self.run_gate()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stderr.splitlines(), [f"{PREFIX}: {REGISTER}:{line}: {token}: {reason}"])

    def assert_document_rejected(self, reason):
        result = self.run_gate()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stderr.splitlines(), [f"{PREFIX}: {REGISTER}: {reason}"])

    def reject_second_line(self, span_text, token, reason):
        self.document.write_text(VALID_LINE + span_text + "\n", encoding="utf-8")
        self.assert_rejected(token, reason, line=2)

    def test_current_path_and_qualified_symbol_pass_8599(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_path_is_rejected_8599(self):
        self.document.write_text("See `src/absent_anchor.rs`.\n", encoding="utf-8")
        self.assert_rejected("src/absent_anchor.rs", "expected a regular file")

    def test_renamed_symbol_is_rejected_8599(self):
        self.document.write_text(f"See `{FIXTURE_SOURCE}::old_anchor`.\n", encoding="utf-8")
        self.assert_rejected(f"{FIXTURE_SOURCE}::old_anchor", f"symbol old_anchor is not defined in {FIXTURE_SOURCE}")

    def test_line_past_eof_is_rejected_8599(self):
        self.document.write_text(f"See `{FIXTURE_SOURCE}:9999`.\n", encoding="utf-8")
        self.assert_rejected(f"{FIXTURE_SOURCE}:9999", f"line is outside 1..{SOURCE_LINE_COUNT}")

    def test_markdown_symbol_link_is_rejected_8599(self):
        self.document.write_text(f"See [`old_anchor`](../../{FIXTURE_SOURCE}).\n", encoding="utf-8")
        self.assert_rejected(f"{FIXTURE_SOURCE}::old_anchor", f"symbol old_anchor is not defined in {FIXTURE_SOURCE}")

    def test_missing_document_is_rejected_8599(self):
        self.document.unlink()
        self.assert_document_rejected("expected a regular file")

    def test_empty_document_is_rejected_8599(self):
        self.document.write_text("", encoding="utf-8")
        self.assert_document_rejected("no source anchors found; refusing an empty check")

    def test_symlinked_document_is_rejected_8599(self):
        other = self.root / "document-copy.md"
        self.document.rename(other)
        self.document.symlink_to(other)
        self.assert_document_rejected(f"symlink at {REGISTER}")

    def test_symlinked_source_is_rejected_8599(self):
        source = self.root / FIXTURE_SOURCE
        other = self.root / "source-copy.rs"
        source.rename(other)
        source.symlink_to(other)
        self.assert_rejected(f"{FIXTURE_SOURCE}::current_anchor", f"symlink at {FIXTURE_SOURCE}")

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

    def test_every_unclassifiable_anchor_form_is_a_finding_8599(self):
        for span in UNCLASSIFIED_CORPUS:
            with self.subTest(span=span):
                self.reject_second_line(f"See `{span}`.", span, UNCLASSIFIED)

    def test_unprefixed_module_path_resolves_under_src_8599(self):
        (self.root / "src/sub").mkdir()
        (self.root / "src/sub/mod_fixture.rs").write_text("pub fn f() {}\n", encoding="utf-8")
        self.document.write_text(VALID_LINE + "See `sub/mod_fixture.rs`.\n", encoding="utf-8")
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.document.write_text(VALID_LINE + "See `sub/absent_fixture.rs`.\n", encoding="utf-8")
        self.assert_rejected("src/sub/absent_fixture.rs", "expected a regular file", line=2)

    def test_symbol_only_in_comment_does_not_resolve_8599(self):
        (self.root / FIXTURE_SOURCE).write_text(COMMENTED_SOURCE, encoding="utf-8")
        self.document.write_text(f"See `{FIXTURE_SOURCE}::real_anchor`.\n", encoding="utf-8")
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for symbol in ("line_ghost", "block_ghost", "nested_ghost", "still_commented", "multi_ghost"):
            with self.subTest(symbol=symbol):
                self.document.write_text(f"See `{FIXTURE_SOURCE}::{symbol}`.\n", encoding="utf-8")
                self.assert_rejected(f"{FIXTURE_SOURCE}::{symbol}", f"symbol {symbol} is not defined in {FIXTURE_SOURCE}")

    def test_empty_brace_list_is_a_finding_8599(self):
        for raw in ("", " ", ", ,"):
            with self.subTest(raw=raw):
                self.document.write_text(f"See `{FIXTURE_SOURCE}::{{{raw}}}`.\n", encoding="utf-8")
                self.assert_rejected(f"{FIXTURE_SOURCE}::{{{raw}}}", "empty symbol list")

    def test_line_ranges_are_bounded_at_both_ends_8599(self):
        cases = (
            ("1-999", f"line is outside 1..{SOURCE_LINE_COUNT}"),
            ("0-1", f"line is outside 1..{SOURCE_LINE_COUNT}"),
            ("3-4", f"line is outside 1..{SOURCE_LINE_COUNT}"),
            ("2-1", "range start 2 is after end 1"),
        )
        for text, reason in cases:
            with self.subTest(range=text):
                self.document.write_text(f"See `{FIXTURE_SOURCE}:{text}`.\n", encoding="utf-8")
                self.assert_rejected(f"{FIXTURE_SOURCE}:{text}", reason)
        self.document.write_text(f"See `{FIXTURE_SOURCE}:1-2` and `{FIXTURE_SOURCE}:2-2`.\n", encoding="utf-8")
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_large_register_and_source_stay_linear_8599(self):
        line = f"See `{FIXTURE_SOURCE}:1-2` and `{FIXTURE_SOURCE}::{{Anchor, current_anchor}}`.\n"
        self.document.write_text(line * LARGE_REGISTER_LINES + "`" * LARGE_REGISTER_LINES + "\n", encoding="utf-8")
        (self.root / FIXTURE_SOURCE).write_text("pub struct Anchor;\npub fn current_anchor() {}\n" + "/* " * LARGE_SOURCE_OPENERS, encoding="utf-8")
        started = time.monotonic()
        result = self.run_gate()
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stdout[-300:] + result.stderr[-300:])
        self.assertEqual(result.stdout.splitlines(), [f"{PREFIX}: problems=0 anchors={2 * LARGE_REGISTER_LINES} document={REGISTER}"])
        self.assertLess(elapsed, LARGE_RUN_CEILING_SECONDS)


if __name__ == "__main__":
    unittest.main()
