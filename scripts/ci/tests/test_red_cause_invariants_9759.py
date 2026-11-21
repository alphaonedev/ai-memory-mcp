#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Class invariants of the red-cause summary (#9709, PR 9759 round 1), each one table or generative test.

A. Redact before cut: no output holds a fragment of a token a cut went through, and every cut prints a count.
B. Work before the cap: the cost is linear in the input and the redaction runs only for values that are shown.
C. Unanchored log text: a section opens only on cargo's exact line shapes, and names come only from the anchored
   lines of their own section, committed by that section's ``test result: FAILED`` line, each counted once.
D. Message from state: counts come from the full lists, the omission line and the notes are kept, and an unreadable
   step log is a problem line.

The rows h01-h19, x1-x8 and c4-c5 are the reviewers' row ids of round 1 (REVIEW-9759-code-r1.md).  The shared
helpers (``Scratch``, ``load_module`` and the fixture constants) come from test_ci_red_cause_summary.py, loaded by path.
"""

import ast
import builtins
import contextlib
import importlib.util
import io
import itertools
import os
import re
import sys
import time
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("red_cause_base_9709", str(HERE / "test_ci_red_cause_summary.py"))
base = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(base)

SCRIPT = base.SCRIPT
RESULT_FAILED_LINE = base.RESULT_FAILED_LINE
CRASH_DETAIL = base.CRASH_DETAIL
NOTICE = base.NOTICE
CAUSE_TITLE = base.CAUSE_TITLE

LINE_BYTES = 300
FILE_BYTES = 16 * 1024 * 1024
NAME_KEY_BYTES = 284
LISTED = 50
ANNOTATIONS = 10
SUMMARY_BYTES = 32768
REDACTION_CALLS = 256
ANNOTATION_DEFAULT_CHARS = 1000

RUNNING_B = "     Running tests/b.rs (target/debug/deps/b-0123456789abcdef)\n"
RUNNING_CRASHY = "     Running tests/crashy.rs (target/debug/deps/crashy-fedcba9876543210)\n"
RESULT_OK_LINE = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s"
BINARY_TITLE = "::error title=failing test binary::"
TEST_TITLE = "::error title=failing test::"
CAUSE_PREFIX = "last error line (a candidate cause): "
CRASH_AFTER_OK = "crashed after a passing test result line; "
NO_RESULT = "ended without a test result line (crash, timeout or signal)"
NO_FINDINGS = "cause not identified; no failing test or test binary found in 1 input file(s)"
WORD_JOINER = "⁠"  # a Cf character: three UTF-8 bytes, shown as ⁠

# The canary of invariant A: a GitHub token shape the redaction masks whole; no 7+ hex run (md_cell breaks those).
CANARY = "ghp_" + "Q7w9Zr4Kx2Lp8Vn3Ty6Hb1Mc5Jd0Fg2Ws4Ea7"
CANARY_WINDOW = 8
CANARY_OFFSETS = range(250, 301)


def canary_windows():
    """Every 8-character window of the canary after its ``ghp_`` prefix (the prefix alone is no secret)."""
    body = CANARY[4:]
    return [body[at:at + CANARY_WINDOW] for at in range(len(body) - CANARY_WINDOW + 1)]


def padded(prefix, offset, filler="x "):
    """``prefix`` padded with ``filler`` to exactly ``offset`` bytes (ASCII), so the next byte sits at ``offset``."""
    text = prefix
    while len(text) < offset:
        text += filler
    return text[:offset]


class Base(base.Scratch):
    """Subprocess and in-process runs of the script."""

    def run_log(self, text, steps=(), extra=()):
        log = self.write("in.log", text)
        args = [str(log)] + list(extra)
        for path, name in steps:
            args += ["--step", path, name]
        rc, out, err, summary = self.run_script(args)
        self.assertEqual(rc, 0, err)
        return out, summary or ""

    def run_inproc(self, args, module=None):
        """(stdout, summary) of ``main(args)`` in this process: fast enough for the generative tables."""
        module = module or load_script()
        summary = self.dir / "summary-inproc.md"
        if summary.exists():
            summary.unlink()
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}), contextlib.redirect_stdout(out):
            self.assertEqual(module.main(list(args)), 0)
        return out.getvalue(), summary.read_text(encoding="utf-8") if summary.exists() else ""


def load_script():
    return base.load_module(SCRIPT)


class RedactBeforeCut(Base):
    """Invariant A: a canary slid across offsets 250..300 of every cut site leaves no 8-character window."""

    def assert_no_canary(self, text, where):
        for window in canary_windows():
            self.assertNotIn(window, text, "%s holds a canary fragment %r" % (where, window))

    def test_a_canary_across_the_line_cut_leaves_no_fragment_at_any_site(self):
        module = load_script()
        for offset in CANARY_OFFSETS:
            result = padded("test result: FAILED. ", offset) + CANARY + " tail"
            name = padded("test n ", offset) + CANARY + " ... FAILED"
            crash = padded("  process didn't exit successfully: `/x/c` ", offset) + CANARY + " (signal: 11)"
            log = self.write("c%d.log" % offset, RUNNING_B + name + "\n" + result + "\n" + RUNNING_CRASHY + crash + "\n")
            out, summary = self.run_inproc([str(log)], module)
            self.assert_no_canary(out + summary, "offset %d findings" % offset)
            step = self.write("s%d.log" % offset, padded("error: ", offset) + CANARY + " tail\n")
            empty = self.write("e%d.log" % offset, "")
            out, summary = self.run_inproc([str(empty), "--step", str(step), "build"], module)
            self.assert_no_canary(out + summary, "offset %d error line" % offset)
            self.assertIn("build: error:", out + summary)

    def test_a_canary_across_the_value_cut_of_clean_leaves_no_fragment(self):
        module = load_script()
        module.load_redaction()
        for offset in CANARY_OFFSETS:
            text = padded("v ", offset) + CANARY + " tail" + " pad" * 40
            shown = module.clean(text).text
            self.assertLessEqual(len(shown.encode("utf-8")), LINE_BYTES)
            self.assert_no_canary(shown, "clean() at offset %d" % offset)

    def test_a_name_that_is_one_long_token_run_is_a_marked_row_in_both_forms(self):
        # the token-safe line cut drops a run whole; a name that is ONE run is then the fixed marker, never lost.
        run = "a" * (LINE_BYTES * 4)
        for form in ("test %s ... FAILED\n\nfailures:\n    %s\n\n", "failures:\n    %s\n\ntest %s ... FAILED\n"):
            with self.subTest(form=form[:8]):
                out, summary = self.run_log(RUNNING_B + form % (run, run) + RESULT_FAILED_LINE + "\n")
                self.assertIn("failing tests: 1\n", summary)
                self.assertIn("| b | &lt;redacted> |\n", summary)
                self.assertIn(TEST_TITLE + "b: <redacted>\n", out)
                self.assertNotIn("a" * 32, out + summary)

    def test_names_that_differ_stay_distinct_after_redaction(self):
        names = ["t::k_%s" % (CANARY[:-1] + tail) for tail in "AB"]
        log = RUNNING_B + "".join("test %s ... FAILED\n" % name for name in names) + RESULT_FAILED_LINE + "\n"
        out, summary = self.run_log(log)
        self.assertIn("failing tests: 2\n", summary)
        self.assert_no_canary(out + summary, "two token names")

    def test_x1_a_long_crash_detail_keeps_its_signal_and_counts_the_cut(self):
        # A dot in every component: the shared redaction masks a 32+ run of [A-Za-z0-9+/_-] whole, so a path without one
        # would show as <redacted> and the components the shrink keeps could not be seen.
        path = "/" + "abcd.fghi/" * 19 + "crashy"
        fixed = len("process didn't exit successfully: `") + len("` (signal: 11, SIGSEGV: invalid memory reference)")
        path += "z" * (298 - fixed - len(path))
        detail = "process didn't exit successfully: `%s` (signal: 11, SIGSEGV: invalid memory reference)" % path
        self.assertEqual(len(detail), 298)
        out, summary = self.run_log(RUNNING_CRASHY + "  " + detail + "\n")
        line = [row for row in out.splitlines() if row.startswith(BINARY_TITLE)]
        self.assertEqual(len(line), 1, out)
        message = line[0][len(BINARY_TITLE + "crashy: "):]
        self.assertTrue(message.startswith(NO_RESULT + "; process didn't exit successfully: `.../abcd.fghi/"), message)
        self.assertTrue(message.endswith("crashy" + "z" * (298 - fixed - 1 - 190 - 6)
                                         + "` (signal: 11, SIGSEGV: invalid memory reference)"), message)
        self.assertLessEqual(len(message.encode("utf-8")), LINE_BYTES)
        self.assertIn("shown values cut: 1 (limit 300 bytes)\n", summary)


class WorkBeforeTheCap(Base):
    """Invariant B: linear cost, the redaction only for shown values, a no-newline tail reported as not parsed."""

    def counting(self, module):
        calls = []
        real_load = module.load_redaction

        def load():
            real_load()
            real = module._redact_line

            def counted(text):
                calls.append(len(text))
                return real(text)
            module._redact_line = counted
        module.load_redaction = load
        return calls

    def test_100k_distinct_result_lines_redact_at_most_the_budget(self):
        module = load_script()
        calls = self.counting(module)
        # 20 words keep the file under MAX_FILE_BYTES (16 MiB), so its section line is read and every line counts.
        lines = ["test result: FAILED. %06d of the ones %s" % (index, "word " * 20) for index in range(100000)]
        log = self.write("many.log", RUNNING_B + "\n".join(lines) + "\n")
        started = time.monotonic()
        out, summary = self.run_inproc([str(log)], module)
        elapsed = time.monotonic() - started
        self.assertIn("failing test binaries: 100000\n", summary)
        self.assertIn("failing test binaries not listed: 99950 (limit 50)", summary)
        self.assertLessEqual(len(calls), REDACTION_CALLS)
        self.assertLess(elapsed, 20.0)

    def test_b_the_redaction_budget_stops_at_its_bound(self):
        """The budget is a backstop the row limits never reach in a log, so it is driven through clean() directly."""
        module = load_script()
        calls = self.counting(module)
        module.load_redaction()
        over = 5
        shown = [module.clean("value %d" % index).text for index in range(REDACTION_CALLS + over)]
        self.assertEqual(len(calls), REDACTION_CALLS)
        self.assertEqual(shown[:2], ["value 0", "value 1"])
        self.assertEqual(shown[REDACTION_CALLS:], ["<redaction budget spent>"] * over)
        self.assertEqual(module._budget_spent, over)

    def test_100k_failing_names_are_counted_in_linear_time(self):
        lines = ["test t::n%06d ... FAILED" % index for index in range(100000)]
        started = time.monotonic()
        out, summary = self.run_log(RUNNING_B + "\n".join(lines) + "\n" + RESULT_FAILED_LINE + "\n")
        self.assertLess(time.monotonic() - started, 20.0)
        self.assertIn("failing tests: 100000\n", summary)

    def test_c5_a_17_mib_line_without_a_newline_is_reported_as_not_parsed(self):
        self.write("big.log", b"x" * 17825813)
        rc, out, err, summary = self.run_script(["big.log"])
        self.assertEqual(rc, 0, err)
        self.assertIn("input file big.log: no complete line found in the last 16777216 bytes, not parsed", summary)


SECTION_ALLOW = (
    ("lib", "     Running unittests src/lib.rs (target/debug/deps/ai_memory-0123456789abcdef)"),
    ("test", "     Running tests/a.rs (target/debug/deps/a-0123456789abcdef)"),
    ("bin", "     Running unittests src/main.rs (target/debug/deps/ai_memory-0123456789abcdef)"),
    ("doc", "   Doc-tests ai_memory"),
    ("trailing-space", "     Running tests/a.rs (target/debug/deps/a-0123456789abcdef)   "),
)
SECTION_DENY = (
    ("h05", "     Running `rustc --crate-name x src/lib.rs`"),
    ("h06", "     Running `target/debug/tool --flag`"),
    ("six-spaces", "      Running tests/a.rs (target/debug/deps/a-0123456789abcdef)"),
    ("four-spaces", "    Running tests/a.rs (target/debug/deps/a-0123456789abcdef)"),
    ("no-parens", "     Running tests/a.rs"),
    ("empty-source", "     Running  (target/debug/deps/a-0123)"),
    ("backtick-path", "     Running tests/a.rs (`x`)"),
    ("doc-two-words", "   Doc-tests two words"),
    ("doc-backtick", "   Doc-tests `x`"),
    ("prefixed", "x     Running tests/a.rs (target/debug/deps/a-0123456789abcdef)"),
)


class UnanchoredLogText(Base):
    """Invariant C: the section openers and the name sources, as allow and deny tables with exact counts."""

    def test_only_cargo_section_lines_open_a_section(self):
        module = load_script()
        for row, line in SECTION_ALLOW:
            out, summary = self.run_inproc([str(self.write(row + ".log", line + "\n"))], module)
            self.assertIn("failing test binaries: 1\n", summary, row)
        for row, line in SECTION_DENY:
            out, summary = self.run_inproc([str(self.write(row + ".log", line + "\n"))], module)
            self.assertNotIn("failing test binaries", summary, row)
            self.assertIn(NO_FINDINGS, summary, row)

    NAME_ROWS = (
        # (row, log, failing tests, failing test binaries)
        ("bare-failed-line", "test a::x ... FAILED\n", 0, 0),
        ("no-result", RUNNING_B + "test a::x ... FAILED\n", 0, 1),
        ("ok-result", RUNNING_B + "test a::x ... FAILED\n" + RESULT_OK_LINE + "\n", 0, 0),
        ("indented-result", RUNNING_B + "test a::x ... FAILED\n  " + RESULT_FAILED_LINE + "\n", 0, 1),
        ("indented-failed", RUNNING_B + "  test a::x ... FAILED\n" + RESULT_FAILED_LINE + "\n", 0, 1),
        ("other-section", RUNNING_B + "test a::x ... FAILED\n" + RUNNING_CRASHY + RESULT_FAILED_LINE + "\n", 0, 2),
        ("once", RUNNING_B + "test a::x ... FAILED\n\nfailures:\n    a::x\n\n" + RESULT_FAILED_LINE + "\n", 1, 1),
        ("h03", RUNNING_B + "test a::x ... FAILED\n\nfailures:\n\n---- a::x stdout ----\ntest a::y ... FAILED\n"
         "    a::z\nfailures\n\nfailures:\n    a::x\n\n" + RESULT_FAILED_LINE + "\n", 1, 1),
        ("list-wins", RUNNING_B + "test a::x ... FAILED\ntest a::y ... FAILED\n\nfailures:\n    a::x\n\n"
         + RESULT_FAILED_LINE + "\n", 1, 1),
    )

    def test_names_come_only_from_their_own_section_and_its_failed_result(self):
        module = load_script()
        for row, log, tests, binaries in self.NAME_ROWS:
            out, summary = self.run_inproc([str(self.write(row + ".log", log))], module)
            self.assertEqual(summary.count("failing tests: %d\n" % tests), 1 if tests else 0, row + "\n" + summary)
            if not tests:
                self.assertNotIn("failing tests:", summary, row)
            if binaries:
                self.assertIn("failing test binaries: %d\n" % binaries, summary, row)
            else:
                self.assertNotIn("failing test binaries", summary, row)

    def test_h04_a_crash_after_a_passing_result_is_a_crash_row(self):
        out, summary = self.run_log(RUNNING_CRASHY + RESULT_OK_LINE + "\nerror: test failed\n\nCaused by:\n  "
                                    + CRASH_DETAIL + "\n")
        self.assertIn(BINARY_TITLE + "crashy: " + CRASH_AFTER_OK + CRASH_DETAIL + "\n", out)
        self.assertIn("failing test binaries: 1\n", summary)

    MODE_ROWS = (
        # (row, the name part of the FAILED line, the name in the failures list and as shown)
        ("h01", "a::b - should panic", "a::b"),
        ("h02", "src/lib.rs - x (line 3) - compile fail", "src/lib.rs - x (line 3)"),
        ("h09", "src/lib.rs - y (line 9) - compile", "src/lib.rs - y (line 9)"),
        ("h12", "a::padded      ", "a::padded"),
        ("x8", "a::c - should panic   ", "a::c"),
    )

    def test_f1_mode_suffixes_and_padding_are_stripped_with_and_without_the_list(self):
        module = load_script()
        for row, failed, name in self.MODE_ROWS:
            for with_list in (False, True):
                listed = "\nfailures:\n    %s\n\n" % name if with_list else ""
                log = RUNNING_B + "test %s ... FAILED\n" % failed + listed + RESULT_FAILED_LINE + "\n"
                out, summary = self.run_inproc([str(self.write(row + ".log", log))], module)
                label = "%s list=%s" % (row, with_list)
                self.assertIn("failing tests: 1\n", summary, label)
                shown = [line for line in out.splitlines() if line.startswith(TEST_TITLE)]
                self.assertEqual(shown, [TEST_TITLE + "b: " + name.replace("::", "\\x3a:")], label)


class MessageFromState(Base):
    """Invariant D: counts from the full lists, kept notes, problem lines for unreadable step logs."""

    def test_h17_the_annotation_total_counts_every_test(self):
        lines = "".join("test t::n%02d ... FAILED\n" % index for index in range(60))
        out, summary = self.run_log(RUNNING_B + lines + RESULT_FAILED_LINE + "\n")
        note = "annotations: 10 of 61 findings printed (limit 10), 51 omitted"
        self.assertIn(note, summary)
        self.assertIn(NOTICE + note + "\n", out)

    def test_c4_300000_names_count_in_full(self):
        lines = "".join("test t::n%06d ... FAILED\n" % index for index in range(300000))
        started = time.monotonic()
        out, summary = self.run_log(RUNNING_B + lines + RESULT_FAILED_LINE + "\n")
        self.assertLess(time.monotonic() - started, 40.0)
        self.assertIn("failing tests: 300000\n", summary)
        self.assertIn("annotations: 10 of 300001 findings printed (limit 10), 299991 omitted", summary)

    def test_x2_2000_sections_keep_the_notes_and_a_blank_line_before_the_omission(self):
        parts = []
        for index in range(2000):
            parts.append("     Running tests/b%04d.rs (target/debug/deps/b%04d-0123456789abcdef)\n" % (index, index))
            parts.append("test t%04d%s ... FAILED\n" % (index, WORD_JOINER * 90))
            parts.append("test result: FAILED. %s\n" % (WORD_JOINER * 90))
        out, summary = self.run_log("".join(parts))
        self.assertLessEqual(len(summary.encode("utf-8")), SUMMARY_BYTES)
        at = summary.find("\n\nsummary over the limit: ")
        self.assertGreater(at, 0, summary[-2000:])
        for note in ("failing test binaries not listed: 1950 (limit 50)", "failing tests not listed: 1950 (limit 50)",
                     "annotations: 10 of 4000 findings printed (limit 10), 3990 omitted"):
            self.assertGreater(summary.find(note), at, note)

    def test_x3_an_unreadable_step_log_is_a_problem_line(self):
        empty = self.write("empty.log", "")
        locked = self.write("locked.log", "error: hidden\n")
        os.chmod(str(locked), 0)
        self.addCleanup(os.chmod, str(locked), 0o600)
        if os.access(str(locked), os.R_OK):
            self.skipTest("running as a user that reads mode 000 files")
        rc, out, err, summary = self.run_script([str(empty.name), "--step", "locked.log", "test"])
        self.assertIn(NOTICE + "cannot read step log locked.log: Permission denied (PermissionError)\n", out)
        (self.dir / "dir.log").mkdir()
        rc, out, err, summary = self.run_script([str(empty.name), "--step", "dir.log", "test"])
        self.assertIn(NOTICE + "step log dir.log is not a regular file (NotRegular)\n", out)
        self.assertIn("cause not identified; failing step: test (the last step whose log exists)", summary)

    def test_l1_the_last_error_line_is_named_as_a_candidate(self):
        step = self.write("step.log", "error: first\nwarning: x\nerror[E0599]: second\n")
        out, summary = self.run_log("", steps=[(str(step), "build")])
        self.assertIn(CAUSE_PREFIX + "build: error&#91;E0599]: second", summary)
        self.assertIn(CAUSE_TITLE + "build: error[E0599]: second\n", out)


class LowFindings(Base):
    """L2-L5: the summary escaper, visible format characters, Markdown cells, a raising redaction."""

    def test_l2_the_summary_keeps_double_colons_and_escapes_control_characters(self):
        out, summary = self.run_log(RUNNING_B + "test a::bad ... FAILED\ntest result: FAILED. 50% \x07 #1\n")
        self.assertIn("| b | a::bad |", summary)
        self.assertIn("test result: FAILED. 50% \\x07 &#35;1", summary)
        self.assertIn(TEST_TITLE + "b: a\\x3a:bad\n", out)

    def test_l3_format_and_bidi_characters_are_shown_as_escapes(self):
        out, summary = self.run_log(RUNNING_B + "test a::b‮c ... FAILED\n" + RESULT_FAILED_LINE + "\n")
        for text in (out, summary):
            self.assertNotIn("‮", text)
        self.assertIn(TEST_TITLE + "b: a\\x3a:b\\\\u202ec\n", out)
        self.assertIn("| b | a::b\\\\u202ec |", summary)

    def test_l4_md_cell_escapes_and_breaks_autolinks(self):
        module = load_script()
        rows = (
            ("#*_~", "&#35;&#42;&#95;&#126;"),
            ("a&b#c", "a&amp;b&#35;c"),
            ("<|`[", "&lt;&#124;&#96;&#91;"),
            ("GH-123", "G​H-123"),
            ("gh-9", "g​h-9"),
            ("deadbee", "d​eadbee"),
            ("deadbe", "deadbe"),
            ("x" + "f" * 40 + " y", "x" + "f" * 40 + " y"),
            ("see 0123456789abcdef0123456789abcdef01234567 ok", "see 0​123456789abcdef0123456789abcdef01234567 ok"),
            ("a‮b", "a\\u202eb"),
        )
        for raw, expected in rows:
            self.assertEqual(module.md_cell(raw), expected, raw)

    def test_l5_a_raising_redaction_shows_the_fixed_marker_end_to_end(self):
        script = self.fixture_copy()
        (script.parent.parent / "cert_gate_evidence.py").write_text(
            "def redact_line(text):\n    raise ValueError('boom')\n", encoding="utf-8")
        self.write("in.log", RUNNING_B + RESULT_FAILED_LINE + "\n")
        rc, out, err, summary = self.run_script(["in.log"], script=str(script))
        self.assertEqual(rc, 0, err)
        self.assertIn("| b | &lt;redaction failed> |", summary)
        self.assertIn(BINARY_TITLE + "b: <redaction failed>\n", out)
        self.assertNotIn("1 passed; 2 failed", out + summary)


class Survivors(Base):
    """The round-1 mutants that no test killed (F11): each row pins the bound from both sides."""

    def test_m03_clean_cuts_to_the_line_bound_exactly(self):
        module = load_script()
        module.load_redaction()
        shown = module.clean(":" * 400).text
        self.assertEqual(len(shown.encode("utf-8")), LINE_BYTES)
        self.assertEqual(module.clean(":" * LINE_BYTES).text, ":" * LINE_BYTES)
        cuts = module._shown_cuts
        one_over = module.clean(":" * (LINE_BYTES + 1)).text  # the first length that is cut (both sides of the bound)
        self.assertEqual(len(one_over.encode("utf-8")), LINE_BYTES)
        self.assertNotEqual(one_over, ":" * (LINE_BYTES + 1))
        self.assertEqual(module._shown_cuts, cuts + 1, "the cut of a value one byte over the bound is counted")

    def test_m27_a_step_log_of_the_file_bound_and_one_above_names_its_last_error(self):
        tail = b"error: at the end\n"
        for size in (FILE_BYTES, FILE_BYTES + 1):
            step = self.write("step%d.log" % size, b"x" * (size - len(tail) - 1) + b"\n" + tail)
            self.assertEqual(step.stat().st_size, size)
            out, summary = self.run_log("", steps=[(str(step), "build")])
            self.assertIn(CAUSE_TITLE + "build: error: at the end\n", out, size)

    def test_m33_a_carriage_return_is_not_counted_as_a_line_byte(self):
        for length, cut in ((LINE_BYTES, False), (LINE_BYTES + 1, True)):
            line = padded("test result: FAILED. ", length, "w ")
            out, summary = self.run_log(RUNNING_B + line + "\r\n")
            self.assertEqual("input lines over 300 bytes cut: 1" in summary, cut, length)

    def test_m35_an_annotation_over_the_shared_default_is_shown_whole(self):
        label = "b" + WORD_JOINER * 75
        log = ("     Running tests/b.rs (target/debug/deps/%s-0123456789abcdef)\n" % label
               + "test result: FAILED. " + WORD_JOINER * 90 + "\n")
        out, summary = self.run_log(log)
        line = [row for row in out.splitlines() if row.startswith(BINARY_TITLE)][0]
        self.assertGreater(len(line), ANNOTATION_DEFAULT_CHARS)
        self.assertTrue(line.endswith("\\\\u2060"), line[-40:])

    def test_x5_names_equal_in_their_first_key_bytes_are_one_test(self):
        stem = "t::" + "n" * (NAME_KEY_BYTES - 3)
        log = (RUNNING_B + "\nfailures:\n    %sA\n    %sB\n\n" % (stem, stem) + RESULT_FAILED_LINE + "\n")
        out, summary = self.run_log(log)
        self.assertIn("failing tests: 1\n", summary)


# The F12 ratchet: an allowlist over the whole script, never a list of forbidden spellings.
ALLOWED_IMPORTS = {"argparse", "hashlib", "importlib.util", "os", "re", "stat", "sys", "unicodedata"}
ALLOWED_FROM = {("pathlib", "Path")}
MODULE_NAMES = {"argparse", "hashlib", "importlib", "os", "re", "stat", "sys", "unicodedata"}
ALLOWED_GETATTR = {("os", "'O_NOFOLLOW'"), ("os", "'O_NONBLOCK'"), ("loaded", "'__file__'"), ("module", "name")}
ALLOWED_OS = {"O_RDONLY", "SEEK_SET", "close", "environ", "fdopen", "fstat", "lseek", "lstat", "open", "path", "scandir",
              "sep"}
ALLOWED_SYS = {"argv", "exit", "modules", "stderr", "stdout"}
ALLOWED_BUILTINS = {"AttributeError", "BaseException", "Exception", "OSError", "SystemExit", "TypeError", "callable",
                    "enumerate", "getattr", "isinstance", "len", "list", "max", "min", "object", "open", "ord", "print",
                    "range", "set", "sorted", "str", "sum", "super", "type", "ValueError", "any", "chr", "hasattr",
                    "tuple", "dict", "bytes", "int", "reversed", "zip", "UnicodeError", "property", "staticmethod",
                    "bool", "iter", "next", "all", "frozenset", "map", "id", "repr", "divmod", "abs",
                    "__name__"}  # the main guard reads the module's own __name__, also an attribute of builtins
ENVIRON_SITES = 1


def ratchet_problems(source):
    """Every construct of ``source`` outside the allowlists, as readable lines (empty when the script conforms)."""
    tree = ast.parse(source)
    problems = []
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    environ = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            problems.extend("import %s" % alias.name for alias in node.names
                            if alias.name not in ALLOWED_IMPORTS or alias.asname is not None)
        elif isinstance(node, ast.ImportFrom):
            problems.extend("from %s import %s" % (node.module, alias.name) for alias in node.names
                            if (node.module, alias.name) not in ALLOWED_FROM or alias.asname is not None)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr":
            pair = tuple(ast.unparse(arg) for arg in node.args[:2])
            if pair not in ALLOWED_GETATTR:
                problems.append("getattr%r" % (pair,))
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            owner, attr = node.value.id, node.attr
            if owner == "os" and attr not in ALLOWED_OS:
                problems.append("os.%s" % attr)
            if owner == "sys" and attr not in ALLOWED_SYS:
                problems.append("sys.%s" % attr)
            if owner == "os" and attr == "environ":
                environ += 1
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in MODULE_NAMES:
                parent = parents.get(node)
                in_attr = isinstance(parent, ast.Attribute) and parent.value is node
                in_getattr = (isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name)
                              and parent.func.id == "getattr" and parent.args and parent.args[0] is node)
                if not (in_attr or in_getattr):
                    problems.append("module %s used as a value" % node.id)
            elif hasattr(builtins, node.id) and node.id not in ALLOWED_BUILTINS:
                problems.append("builtin %s" % node.id)
    if environ != ENVIRON_SITES:
        problems.append("os.environ sites: %d" % environ)
    return problems


RATCHET_MUTANTS = (
    ("S1 getattr concat", 'X = 1\n', 'X = 1\n_ENV2 = getattr(os, "env" + "iron")\n'),
    ("S2 __import__", 'X = 1\n', 'X = 1\n_SP = __import__("sub" + "process")\n'),
    ("S3 os.system", 'X = 1\n', 'X = 1\nos.system("true")\n'),
    ("S4 from os import", 'X = 1\n', 'X = 1\nfrom os import system\n'),
    ("S5 import alias", 'X = 1\n', 'X = 1\nimport subprocess as sp\n'),
    ("S6 module alias", 'X = 1\n', 'X = 1\nE = os\n'),
    ("S7 second environ", 'X = 1\n', 'X = 1\nY = os.environ.get("HOME")\n'),
    ("S8 eval", 'X = 1\n', 'X = 1\nY = eval("1")\n'),
    ("S9 sys attr", 'X = 1\n', 'X = 1\nY = sys.modules_x\n'),
)


class SourceRatchet(unittest.TestCase):
    """F12: imports, getattr, os and sys attributes, builtins and the one environment read, as allowlists."""

    def test_the_script_conforms(self):
        self.assertEqual(ratchet_problems(SCRIPT.read_text(encoding="utf-8")), [])
        self.assertIn('SUMMARY_ENV = "GITHUB_STEP_SUMMARY"', SCRIPT.read_text(encoding="utf-8"))

    def test_every_mutant_form_is_caught(self):
        source = SCRIPT.read_text(encoding="utf-8")
        anchor = "\nISSUE = \"#9709\"\n"
        self.assertIn(anchor, source)
        for row, _old, new in RATCHET_MUTANTS:
            mutated = source.replace(anchor, anchor + new, 1)
            self.assertNotEqual(ratchet_problems(mutated), [], row)


# ---------------------------------------------------------------------------------------------------------------------
# Round 2 (#9830 class A, #9831 class C): the class-fix designs of NOTICE-9759-r2.md.
# ---------------------------------------------------------------------------------------------------------------------
REDACTOR = SCRIPT.parent.parent / "cert_gate_evidence.py"
WORKFLOWS = SCRIPT.parent.parent.parent / ".github" / "workflows"
PRE_CAP_BYTES = 400
LINE_NOT_SHOWN = "<line not shown: %d bytes>"
NAMES_NOT_AVAILABLE = "failed, names not available"
FRAGMENT_CHARS = 3
SWEEP_OFFSETS = tuple(range(250, 301)) + tuple(range(350, 401))  # across the line cut (300) and the pre-cap (400)
CANARY_VALUE = "Q7W9ZR4KX2LP8VN3TY6HB1MC5JD0FG2WS4EA7"
CANARY_HEX = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c" * 2
CANARY_URL_VALUE = CANARY_VALUE[:12] + "!" + CANARY_VALUE[12:20]

# One row per compiled pattern of the shared redactor (scripts/cert_gate_evidence.py), written out by hand: the
# pattern name, the line shape it masks and the secret value placed in it.
CANARY_ROWS = {
    "PEM_BEGIN": ("-----BEGIN RSA PRIVATE KEY----- {v}", CANARY_VALUE),
    "PEM_END": ("{v} -----END RSA PRIVATE KEY-----", CANARY_VALUE),
    "SECRET_KEY_VALUE": ("api_key={v}", CANARY_VALUE),
    "WEAK_KEY_VALUE": ("session={v}", CANARY_VALUE),
    "WEAK_KEY_SPACE": ("pass {v}", CANARY_VALUE),
    "JSON_KEY_NAME": ('{{"pwd": "{v}"}}', CANARY_VALUE),
    "AUTHORIZATION": ("Authorization: Basic {v}", CANARY_VALUE),
    "COOKIE_HEADER": ("Cookie: a={v}", CANARY_VALUE),
    "BEARER": ("Bearer {v}", CANARY_VALUE),
    "TOKEN_SHAPES": ("ghp_{v}", CANARY_VALUE),
    "URL_CREDENTIALS": ("https://user:{v}@example.com/x", CANARY_URL_VALUE),
    "LONG_HEX": ("{v}", CANARY_HEX),
    "LONG_B64": ("{v}", CANARY_VALUE),
    "ABS_PATH": ("/home/{v}", CANARY_VALUE),
    "KEY_ESCAPE": ("\\u0074oken={v}", CANARY_VALUE),
    "PUBLIC_KEY_LINE": ("pub_b64=AAAA;signing_key={v}", CANARY_VALUE),
}
# Compiled patterns that mask nothing on their own: each one is a helper another pattern's rule calls.
HELPER_PATTERNS = {
    "GIT_SHA": "keeps a 40-hex commit id readable inside LONG_HEX",
    "SEG_LOWER": "path segment test used by ABS_PATH and PATH_LIKE",
    "PATH_LIKE": "keeps a plain relative path readable inside LONG_B64",
    "PUBLIC_VALUE": "keeps a public key value readable inside PUBLIC_KEY_LINE",
}


def canary_line(pattern):
    """(line, secret) of a canary row: the shape between a fixed head and tail."""
    template, value = CANARY_ROWS[pattern]
    return "x " + template.format(v=value) + " tail", value


def shown_form(text):
    """``text`` without format characters and backslashes, so an escape inserted into a run cannot hide a fragment."""
    return "".join(char for char in text if char != "\\" and unicodedata.category(char) != "Cf")


def load_redactor():
    spec = importlib.util.spec_from_file_location("cert_gate_evidence_9830", str(REDACTOR))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CanaryTable(unittest.TestCase):
    """#9830: the canary table has one row per redactor pattern and every row is masked whole."""

    def test_the_table_has_one_row_per_redactor_pattern(self):
        patterns = {name for name, value in vars(load_redactor()).items() if isinstance(value, re.Pattern)}
        self.assertEqual(set(CANARY_ROWS) | set(HELPER_PATTERNS), patterns)
        self.assertEqual(set(CANARY_ROWS) & set(HELPER_PATTERNS), set())

    def test_the_redactor_masks_every_row_whole(self):
        redactor = load_redactor()
        for pattern in CANARY_ROWS:
            line, value = canary_line(pattern)
            shown = shown_form(redactor.redact_line(line))
            leaked = [value[at:at + FRAGMENT_CHARS] for at in range(len(value) - FRAGMENT_CHARS + 1)
                      if value[at:at + FRAGMENT_CHARS] in shown]
            self.assertEqual(leaked, [], pattern)


class CanaryEverySite(Base):
    """#9830: every canary row at every offset across the line cut and the pre-cap, at every site that shows log
    text (a progress name, a result line, a crash detail, a section label, a step log's error line), leaves no
    fragment of 3 characters in any output."""

    def assert_no_fragment(self, text, value, where):
        shown = shown_form(text)
        leaked = [value[at:at + FRAGMENT_CHARS] for at in range(len(value) - FRAGMENT_CHARS + 1)
                  if value[at:at + FRAGMENT_CHARS] in shown]
        self.assertEqual(leaked, [], where)

    def test_every_row_at_every_offset_of_every_site(self):
        module = load_script()
        for pattern in sorted(CANARY_ROWS):
            line, value = canary_line(pattern)
            for offset in SWEEP_OFFSETS:
                where = "%s at offset %d" % (pattern, offset)
                log = (RUNNING_B + padded("test n ", offset) + line + " ... FAILED\n"
                       + padded("test result: FAILED. ", offset) + line + "\n"
                       + RUNNING_CRASHY + padded("  process didn't exit successfully: `/x/c` ", offset) + line + "\n"
                       + padded("     Running tests/", offset) + line + " (target/debug/deps/x-0123456789abcdef)\n"
                       + "test t ... FAILED\n" + RESULT_FAILED_LINE + "\n")
                out, summary = self.run_inproc([str(self.write("c.log", log))], module)
                self.assertIn("failing test binaries: 3\n", summary, where)
                self.assertIn("failing tests: 2\n", summary, where)
                self.assert_no_fragment(out + summary, value, where)
                step = self.write("s.log", padded("error: ", offset) + line + "\n")
                out, summary = self.run_inproc([str(self.write("e.log", "")), "--step", str(step), "build"], module)
                self.assertIn(CAUSE_PREFIX + "build: ", summary, where)
                self.assert_no_fragment(out + summary, value, where + " (step log)")


class OneFunnel(Base):
    """#9830: one function is the only way from raw text to shown text; the cut and the writers refuse a str."""

    def test_the_cut_and_every_writer_refuse_a_plain_str(self):
        module = load_script()
        module.load_redaction()
        shown = module.redact_shown("plain")
        self.assertIs(type(shown), module.Redacted)
        self.assertEqual(shown.text, "plain")
        for call in (lambda: module.Redacted("x"), lambda: module.cut_redacted("x"), lambda: module.md_cell("x"),
                     lambda: module.notice("x"), lambda: module.summary_text("x"),
                     lambda: module.compose(module.NAMES_NOT_AVAILABLE_REASON, "x")):
            with self.assertRaises(TypeError):
                call()

    def test_a_line_over_the_pre_cap_is_a_fixed_marker_with_its_byte_length(self):
        module = load_script()
        module.load_redaction()
        self.assertEqual(module.PRE_CAP_BYTES, PRE_CAP_BYTES)
        unit = "a b "
        rows = (
            # (raw line, shown text, cuts counted)
            (unit * 75, unit * 75, 0),
            (unit * 75 + "c", (unit * 75)[:LINE_BYTES - 3] + "...", 1),
            (unit * 100, (unit * 100)[:LINE_BYTES - 3] + "...", 1),
            (unit * 100 + "c", LINE_NOT_SHOWN % (PRE_CAP_BYTES + 1), 1),
            (unit * 99 + "a b" + "é", LINE_NOT_SHOWN % (PRE_CAP_BYTES + 1), 1),
        )
        for raw, expected, cuts in rows:
            before = module._shown_cuts
            self.assertEqual(module.redact_shown(raw).text, expected, len(raw))
            self.assertEqual(module._shown_cuts - before, cuts, len(raw))

    def test_a_mutant_that_passes_raw_text_to_the_cut_is_refused_by_the_type(self):
        script = self.fixture_copy()
        source = script.read_text(encoding="utf-8")
        target = "redact_shown(raw_line)"
        self.assertIn(target, source)
        script.write_text(source.replace(target, "cut_redacted(raw_line)"), encoding="utf-8")
        line, value = canary_line("TOKEN_SHAPES")
        self.write("in.log", RUNNING_B + "test " + line + " ... FAILED\n" + RESULT_FAILED_LINE + "\n")
        rc, out, err, summary = self.run_script(["in.log"], script=str(script))
        self.assertIn("TypeError", out + err + (summary or ""))
        self.assertNotIn(value[:8], out + err + (summary or ""))


class ShowLogTextSwitch(Base):
    """The pre-armed split: SHOW_LOG_TEXT = False shows counts and step names only, no text taken from a log."""

    def test_the_switch_off_shows_no_log_text(self):
        module = load_script()
        self.assertIs(module.SHOW_LOG_TEXT, True)
        module.SHOW_LOG_TEXT = False
        log = self.write("in.log", RUNNING_B + "test a::secretname ... FAILED\n" + RESULT_FAILED_LINE + "\n"
                         + RUNNING_CRASHY + "  " + CRASH_DETAIL + "\n")
        out, summary = self.run_inproc([str(log)], module)
        self.assertIn("failing test binaries: 2\n", summary)
        self.assertIn("failing tests: 1\n", summary)
        for text in ("secretname", "test result", "process didn't exit", "crashy.rs", "tests/b.rs"):
            self.assertNotIn(text, out + summary, text)
        step = self.write("s.log", "error: secretline\n")
        out, summary = self.run_inproc([str(self.write("e.log", "")), "--step", str(step), "build"], module)
        self.assertNotIn("secretline", out + summary)
        self.assertIn("failing step: build", summary)


# The forged lines of class C, each a line shape the runner itself prints.
FORGED = {
    "header": "failures:",
    "name": "test a::forged ... FAILED",
    "list": "    a::forged",
    "ok": RESULT_OK_LINE,
    "failed": "test result: FAILED. 0 passed; 9 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
    "section": "     Running tests/forged.rs (target/debug/deps/forged-0123456789abcdef)",
    "doc": "   Doc-tests forged",
}
CAPTURE_HEAD = "\nfailures:\n\n---- a::bad stdout ----\n"
# (row, the log before the captured output, the log after it, failing test binaries, failing tests)
CAPTURE_BASES = (
    ("failing-test", RUNNING_B + "test a::good ... ok\ntest a::bad ... FAILED\n" + CAPTURE_HEAD,
     "\nfailures:\n    a::bad\n\n" + RESULT_FAILED_LINE + "\n", 1, 1),
    ("passing-result", RUNNING_B + "test a::good ... ok\n" + CAPTURE_HEAD, "\n" + RESULT_OK_LINE + "\n", 1, 0),
)


def forged_captures():
    """Every ordered combination of {header, name, result ok or FAILED, section line} (each at most once)."""
    for results in ((), ("ok",), ("failed",)):
        for size in range(4):
            for chosen in itertools.combinations(("header", "name", "section"), size):
                for order in itertools.permutations(chosen + results):
                    yield order


def counts(summary):
    """(failing test binaries, failing tests) as printed (0 when the line is absent)."""
    found = []
    for label in ("failing test binaries: ", "failing tests: "):
        match = re.search("^" + label + r"(\d+)$", summary, re.M)
        found.append(int(match.group(1)) if match else 0)
    return tuple(found)


class CaptureCannotForge(Base):
    """#9831: one section yields at most one binary row and one result; no byte of captured output can add a
    binary, a name or a section, or change a count."""

    def test_p1_a_forged_header_name_and_failed_result_change_nothing(self):
        capture = "failures:\n    a::forged\n\ntest a::forged ... FAILED\n" + FORGED["failed"] + "\n"
        row, head, tail, binaries, tests = CAPTURE_BASES[0]
        out, summary = self.run_log(head + capture + tail)
        self.assertEqual(counts(summary), (binaries, tests))
        self.assertNotIn("forged", out + summary)
        self.assertNotIn("9 failed", out + summary)

    def test_p2_a_forged_running_line_after_a_header_opens_no_section(self):
        capture = FORGED["section"] + "\ntest a::x ... FAILED\n" + FORGED["failed"] + "\n" + FORGED["doc"] + "\n"
        row, head, tail, binaries, tests = CAPTURE_BASES[0]
        out, summary = self.run_log(head + capture + tail)
        self.assertEqual(counts(summary), (binaries, tests))
        self.assertNotIn("forged", out + summary)

    def test_p3_100000_result_lines_in_one_section_are_one_row(self):
        started = time.monotonic()
        out, summary = self.run_log(RUNNING_B + (RESULT_FAILED_LINE + "\n") * 100000)
        self.assertLess(time.monotonic() - started, 20.0)
        self.assertEqual(counts(summary), (1, 0))
        self.assertEqual(out.count(BINARY_TITLE), 1)

    def test_every_forged_combination_leaves_the_counts_unchanged(self):
        module = load_script()
        for row, head, tail, binaries, tests in CAPTURE_BASES:
            out, summary = self.run_inproc([str(self.write("base.log", head + tail))], module)
            self.assertEqual(counts(summary), (binaries, tests), row)
            for order in forged_captures():
                capture = "".join(FORGED[piece] + "\n" for piece in order)
                out, summary = self.run_inproc([str(self.write("f.log", head + capture + tail))], module)
                self.assertEqual(counts(summary), (binaries, tests), (row, order))
                self.assertNotIn("forged", out + summary, (row, order))

    def test_a_failed_result_with_no_progress_name_is_names_not_available(self):
        out, summary = self.run_log(RUNNING_B + RESULT_FAILED_LINE + "\n")
        self.assertIn(BINARY_TITLE + "b: " + NAMES_NOT_AVAILABLE + "; " + RESULT_FAILED_LINE + "\n", out)
        self.assertEqual(counts(summary), (1, 0))

    def test_the_100k_line_capture_stays_inside_the_time_bound(self):
        capture = "".join(FORGED[piece] + "\n" for piece in ("header", "name", "section", "failed")) * 25000
        row, head, tail, binaries, tests = CAPTURE_BASES[0]
        started = time.monotonic()
        out, summary = self.run_log(head + capture + tail)
        self.assertLess(time.monotonic() - started, 20.0)
        self.assertEqual(counts(summary), (binaries, tests))


class CaptureResidual(unittest.TestCase):
    """#9831 residual: text a test prints under --nocapture or --show-output lands in the progress region, so no
    workflow may pass either to the test steps (a contract pin next to the behaviour tests above)."""

    def test_no_workflow_passes_nocapture_or_show_output(self):
        files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
        self.assertGreater(len(files), 0)
        for path in files:
            text = path.read_text(encoding="utf-8")
            for flag in ("--nocapture", "RUST_TEST_NOCAPTURE", "--show-output"):
                self.assertNotIn(flag, text, path.name)


# #9830 source conformance: the sites that may slice or cut text, and every funnel call, as allowlists of
# (function, source text) pairs; a new site in any form is a problem line.
SLICE_SITES = {
    ("cut_bytes", "data[:limit]"): "the byte cut of redacted text, on a character boundary",
    ("read_input", "data[newline + 1:]"): "drops the partial first line of a file tail (input framing, not shown)",
    ("read_line", "raw[:-1]"): "drops the newline of a read line (input framing, not shown)",
}
CUT_SITES = {
    ("cut_redacted", "cut_bytes(value.text, MAX_LINE_BYTES - len(CUT_MARK))"): "the one cut, behind the type",
}
REDACT_SITES = {
    ("progress_name", "redact_shown(raw_line)"),
    ("section_label", "redact_shown(raw_line)"),
    ("close_section", "redact_shown(section.result_raw)"),
    ("close_section", "redact_shown(section.crash_raw)"),
    ("last_error_line", "redact_shown(raw_line)"),
    ("describe", "redact_shown(text)"),
    ("shown_arg", "redact_shown(text)"),
}
WA_ATTRS = {"annotation", "safe_text"}


def function_of(parents, node):
    while node is not None and not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        node = parents.get(node)
    return node.name if node is not None else "<module>"


def funnel_problems(source):
    """Every slice, cut, funnel call and shared-helper attribute of ``source`` outside the allowlists."""
    tree = ast.parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    problems = []
    redact = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
            site = (function_of(parents, node), ast.unparse(node))
            if site not in SLICE_SITES:
                problems.append("slice %r" % (site,))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            site = (function_of(parents, node), ast.unparse(node))
            if node.func.id == "cut_bytes" and site not in CUT_SITES:
                problems.append("cut %r" % (site,))
            if node.func.id == "redact_shown":
                redact.add(site)
            if node.func.id in ("compose", "fixed") and not (
                    node.args and isinstance(node.args[0], ast.Name) and node.args[0].id.isupper()):
                problems.append("template not a constant %r" % (site,))
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "wa":
            if node.attr not in WA_ATTRS:
                problems.append("wa.%s" % node.attr)
        elif isinstance(node, ast.keyword) and node.arg == "max_chars":
            site = (function_of(parents, node), ast.unparse(node))
            if site != ("run", "max_chars=ANNOTATION_MAX_CHARS"):
                problems.append("max_chars %r" % (site,))
    if redact != REDACT_SITES:
        problems.append("funnel calls %r" % (sorted(redact ^ REDACT_SITES),))
    return problems


FUNNEL_MUTANTS = (
    ("F1 slice in a new function", "def leak(text):\n    return text[:10]\n"),
    ("F2 slice through a constant", "LEAK_N = 10\n\n\ndef leak(text):\n    return text[:LEAK_N]\n"),
    ("F3 slice object", "def leak(text):\n    return text[slice(0, 10)]\n"),
    ("F4 textwrap.shorten", "import textwrap\n\n\ndef leak(text):\n    return textwrap.shorten(text, 10)\n"),
    ("F5 a helper in another file", "def leak(text):\n    return wa.shorten(text, 10)\n"),
    ("F6 a second cut", "def leak(text):\n    return cut_bytes(text, 10)\n"),
    ("F7 a funnel call on a part", "def leak(raw_line):\n    return redact_shown(raw_line.split()[0])\n"),
    ("F8 a template from text", "def leak(raw_line):\n    return compose(raw_line)\n"),
    ("F9 a max_chars cut", "def leak(text):\n    return wa.annotation('error', text, max_chars=9)\n"),
)


class FunnelConformance(unittest.TestCase):
    """#9830: the slice, cut and funnel sites of the script as allowlists, each mutant form caught."""

    def test_the_script_conforms(self):
        self.assertEqual(funnel_problems(SCRIPT.read_text(encoding="utf-8")), [])

    def test_every_mutant_form_is_caught(self):
        source = SCRIPT.read_text(encoding="utf-8")
        anchor = "\nISSUE = \"#9709\"\n"
        self.assertIn(anchor, source)
        for row, new in FUNNEL_MUTANTS:
            mutated = source.replace(anchor, anchor + "\n\n" + new + "\n\n", 1)
            self.assertNotEqual(funnel_problems(mutated) + ratchet_problems(mutated), [], row)

    def test_a_slice_added_inside_an_allowed_function_is_caught(self):
        source = SCRIPT.read_text(encoding="utf-8")
        target = "    return raw[:-1]"
        self.assertIn(target, source)
        mutated = source.replace(target, "    return raw[:-1][:200]", 1)
        self.assertNotEqual(funnel_problems(mutated), [])


if __name__ == "__main__":
    unittest.main()
