# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The stored-log mode (--bench-dir) of scripts/ci/measure_ci_time.py on hand-written logs (#9710).

Every expected value below is written out by hand from the fixture text, never computed by the script.

Invariant under test: bench_report prints a number, a count, a "yes" or a fail-set line only when the log it comes
from held a complete, self-consistent record of it. Every other log gives `not measured: <exact reason>` naming the
log, and every line derived from it is `not measured` too. A run with any not-measured log exits 7, never 0.
"""

import contextlib
import importlib.util
import io
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "measure_ci_time.py"
spec = importlib.util.spec_from_file_location("measure_ci_time", SCRIPT)
mct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mct)

WRITTEN_EPOCH = 1767225600  # 2026-01-01T00:00:00Z
READ_EPOCH = 1767312000  # 2026-01-02T00:00:00Z
WRITTEN = "2026-01-01T00:00:00Z"
READ = "2026-01-02T00:00:00Z"
ROW = "test result: ok. {p} passed; 0 failed; {i} ignored; 0 measured; {f} filtered out; finished in {s}s"

# A lib binary of 5 tests (3 pass, 2 ignored) whose output holds one child-process run of 1 test; then a binary of 2.
CARGO_LOG = """
running 5 tests
test a::one ... ok
running 1 test
test a::two ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.05s

test a::three ... ok
test a::four ... ignored
test a::five ... ignored, manual bench
test result: ok. 3 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 10.5s

running 2 tests
test b::one ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.5s
--- stderr ---
test result: ok. 99 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 99.0s
""".strip().splitlines()

CARGO_LIST = ["a::one: test", "a::two: test", "a::three: test", "a::four: test", "a::five: test", "b::one: test",
              "b::two: test", "     Running tests/b.rs (target/debug/deps/b-1)"]
NEXTEST_LIST = ["ai-memory a::one", "ai-memory a::two", "ai-memory::b b::one", "ai-memory::b b::two",
                "ai-memory a::three", "warning: `ai-memory` generated 1 warning"]
NEXTEST_1 = ["    Starting 5 tests across 2 binaries (2 tests skipped)",
             "        FAIL [   0.045s] (   1/5) ai-memory a::one",
             "        FAIL [   0.057s] (   2/5) ai-memory::b b::two",
             "        Summary [  10.500s] 5 tests run: 3 passed (1 slow), 2 failed, 2 skipped",
             "        FAIL [   0.045s] ( 1/5) ai-memory a::one",
             "        FAIL [   0.057s] ( 2/5) ai-memory::b b::two"]
NEXTEST_2 = ["        FAIL [   0.4s] (   1/5) ai-memory::b b::two",
             "        FAIL [   0.7s] (   2/5) ai-memory a::three",
             "        Summary [  12.000s] 5 tests run: 3 passed, 2 failed, 2 skipped"]
SOLO_1 = ["        Summary [   2.000s] 1 test run: 1 passed, 6 skipped"]
SOLO = ["        FAIL [   1.5s] (   1/3) ai-memory::b b::one",
        "        Summary [   1.500s] 3 tests run: 0 passed, 3 failed, 4 skipped"]
SOLO_J1 = ["        Summary [   3.500s] 3 tests run: 3 passed, 4 skipped"]
COMPILE = ["   Compiling x v1", "    Finished `test` profile [unoptimized] target(s) in 2m 15s"]

FIXTURE = {"compile.log": COMPILE, "cglist.log": CARGO_LIST, "nxlist.log": NEXTEST_LIST,
           "cargotest-1.log": CARGO_LOG, "cargotest-2.log": CARGO_LOG, "nextest-1.log": NEXTEST_1,
           "nextest-2.log": NEXTEST_2, "nextest-solo1.log": SOLO_1, "nextest-solo.log": SOLO,
           "nextest-solo-j1.log": SOLO_J1}


def lay_out(directory, files_override=None, **override):
    """Write the ten fixture logs into directory.

    files_override maps a file name to its lines, to raw bytes, or to None (file omitted); override does the same
    with the spelling `nextest_1_log` for `nextest-1.log`. The access time differs from the write time on purpose.
    """
    files = dict(FIXTURE)
    files.update({name.replace("_", "-").replace("-log", ".log"): lines for name, lines in override.items()})
    files.update(files_override or {})
    for name, lines in files.items():
        if lines is None:
            continue
        path = Path(directory) / name
        if isinstance(lines, bytes):
            path.write_bytes(lines)
        else:
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.utime(path, (READ_EPOCH, WRITTEN_EPOCH))


def run_main(directory):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = mct.main(["--repo", "o/r", "--branch", "b", "--bench-dir", str(directory)])
    return rc, out.getvalue(), err.getvalue()


_CARGO = (f" (written {WRITTEN}): 2 top-level result rows, header sum 7, 5 passed, 0 failed, 2 ignored, "
          "sum of finished-in 12.0 s; 1 nested result rows (1 passed) printed inside the lib test output; "
          "all rows 6 passed")
_RECONCILE = ("  reconcile: header sum == list yes; top-level passed + ignored == list yes; "
              "all rows passed - list = -1, explained by nested rows (1) minus ignored (2) = -1: yes")
_NESTED = "  nested result rows: 1; `filtered out` of those rows: 4"
_IGNORED = "  ignored tests: 2 named (a::five, a::four); top-level ignored count 2: yes"

# The full report of the fixture, line by line, written by hand. IDX names the lines the table below replaces.
FULL = [
    f"read at {READ} UTC from <dir>",
    f"build: compile.log (written {WRITTEN}) cargo Finished in 135 s",
    f"list: cglist.log (written {WRITTEN}) 7 `: test` lines; nxlist.log (written {WRITTEN}) 5 test lines",
    "cargotest-1.log" + _CARGO, _RECONCILE, _NESTED, _IGNORED,
    "cargotest-2.log" + _CARGO, _RECONCILE, _NESTED, _IGNORED,
    f"nextest-1.log (written {WRITTEN}): nextest Summary 10.5 s, 5 run, 3 passed, 2 failed, 2 skipped; "
    "2 distinct FAIL names (== failed: yes)",
    f"nextest-2.log (written {WRITTEN}): nextest Summary 12.0 s, 5 run, 3 passed, 2 failed, 2 skipped; "
    "2 distinct FAIL names (== failed: yes)",
    "nextest fail sets over runs 1 and 2: 1 in both, 3 in either",
    f"nextest-solo1.log (written {WRITTEN}): nextest Summary 2.0 s, 1 run, 1 passed, 0 failed",
    f"nextest-solo.log (written {WRITTEN}): nextest Summary 1.5 s, 3 run, 0 passed, 3 failed",
    f"nextest-solo-j1.log (written {WRITTEN}): nextest Summary 3.5 s, 3 run, 3 passed, 0 failed",
    "same test count: nextest run + skipped == cargo list yes; nextest list == nextest run yes",
]
I_BUILD, I_LIST, I_CARGO1, I_NX1, I_NX2, I_FAILSETS, I_SOLO1, I_SOLO, I_SOLOJ1, I_SAME = 1, 2, 3, 11, 12, 13, 14, 15, 16, 17
_LIST_OK = f"cglist.log (written {WRITTEN}) 7 `: test` lines"
_NXLIST_OK = f"nxlist.log (written {WRITTEN}) 5 test lines"


def _cargo_lines(name, first):
    return {first: f"{name} (written {WRITTEN}): not measured: <R>",
            first + 1: f"  reconcile: not measured: {name}",
            first + 2: f"  nested result rows: not measured: {name}",
            first + 3: f"  ignored tests: not measured: {name}"}


# What each log's not-measured reason changes in FULL ("<R>" is the reason), written by hand per log.
AFFECTED = {
    "compile.log": {I_BUILD: f"build: compile.log (written {WRITTEN}) cargo Finished in not measured: <R>"},
    "cglist.log": {
        I_LIST: f"list: cglist.log (written {WRITTEN}) not measured: <R>; {_NXLIST_OK}",
        4: "  reconcile: not measured: cglist.log", 8: "  reconcile: not measured: cglist.log",
        I_SAME: "same test count: nextest run + skipped == cargo list not measured: cglist.log; "
                "nextest list == nextest run yes"},
    "nxlist.log": {
        I_LIST: f"list: {_LIST_OK}; nxlist.log (written {WRITTEN}) not measured: <R>",
        I_SAME: "same test count: nextest run + skipped == cargo list yes; "
                "nextest list == nextest run not measured: nxlist.log"},
    "cargotest-1.log": _cargo_lines("cargotest-1.log", 3),
    "cargotest-2.log": _cargo_lines("cargotest-2.log", 7),
    "nextest-1.log": {
        I_NX1: f"nextest-1.log (written {WRITTEN}): not measured: <R>",
        I_FAILSETS: "nextest fail sets over runs 1 and 2: not measured: nextest-1.log",
        I_SAME: "same test count: nextest run + skipped == cargo list not measured: nextest-1.log; "
                "nextest list == nextest run not measured: nextest-1.log"},
    "nextest-2.log": {
        I_NX2: f"nextest-2.log (written {WRITTEN}): not measured: <R>",
        I_FAILSETS: "nextest fail sets over runs 1 and 2: not measured: nextest-2.log"},
    "nextest-solo1.log": {I_SOLO1: f"nextest-solo1.log (written {WRITTEN}): not measured: <R>"},
    "nextest-solo.log": {I_SOLO: f"nextest-solo.log (written {WRITTEN}): not measured: <R>"},
    "nextest-solo-j1.log": {I_SOLOJ1: f"nextest-solo-j1.log (written {WRITTEN}): not measured: <R>"},
}


def expected_lines(*cases):
    """FULL with the lines that each (log name, reason) pair changes, written from AFFECTED."""
    out = list(FULL)
    for name, reason in cases:
        for index, template in AFFECTED[name].items():
            out[index] = template.replace("<R>", reason)
    return out


BYTE_CASES = [
    (b"", "empty (0 bytes)"),
    (b" \n\t\n  \n", "whitespace only"),
    (b"\xff\xfe", "not valid UTF-8 (byte 0xff at offset 0: invalid start byte)"),
    (b"ok\n\xc3\x28\n", "not valid UTF-8 (byte 0xc3 at offset 3: invalid continuation byte)"),
]
# Valid text that holds none of the records the log kind is read for.
NO_RECORD = {
    "compile.log": ("no Finished line", ["   Compiling x v1"]),
    "cglist.log": ("no `: test` lines", ["Running tests/b.rs", "warning: unused"]),
    "nxlist.log": ("no test lines", ["warning: `ai-memory` generated 1 warning"]),
    "cargotest-1.log": ("no top-level `test result:` row", ["Compiling a", "test a::one ... ok"]),
    "cargotest-2.log": ("no top-level `test result:` row", ["Compiling a", "test a::one ... ok"]),
    "nextest-1.log": ("no Summary line", ["    Starting 5 tests across 2 binaries"]),
    "nextest-2.log": ("no Summary line", ["    Starting 5 tests across 2 binaries"]),
    "nextest-solo1.log": ("no Summary line", ["Starting 1 test"]),
    "nextest-solo.log": ("no Summary line", ["Starting 1 test"]),
    "nextest-solo-j1.log": ("no Summary line", ["Starting 1 test"]),
}


class CargoResultsTests(unittest.TestCase):
    def test_top_level_and_nested_rows_are_told_apart(self):
        top, nested, why = mct.parse_cargo_results(CARGO_LOG)
        self.assertEqual([(r["header"], r["passed"], r["failed"], r["ignored"], r["secs"]) for r in top],
                         [(5, 3, 0, 2, 10.5), (2, 2, 0, 0, 1.5)])
        self.assertEqual([(r["passed"], r["secs"], r["filtered"]) for r in nested], [(1, 0.05, 4)])
        self.assertIsNone(why)

    def test_a_row_after_the_stderr_marker_is_not_read(self):
        top, nested, _ = mct.parse_cargo_results(CARGO_LOG)
        self.assertEqual(sum(r["passed"] for r in top + nested), 6)  # not 105: the 99-passed row is stderr

    def test_a_row_with_no_open_header_is_nested_and_no_top_row_is_a_reason(self):
        top, nested, why = mct.parse_cargo_results([ROW.format(p=4, i=0, f=0, s="1.0")])
        self.assertEqual((top, [r["passed"] for r in nested], why), ([], [4], "no top-level `test result:` row"))

    def test_a_row_whose_count_differs_from_the_open_header_is_nested_and_the_header_stays_open(self):
        top, nested, why = mct.parse_cargo_results([
            "running 5 tests",
            ROW.format(p=4, i=0, f=0, s="1.0"),
            ROW.format(p=4, i=1, f=0, s="2.0"),
        ])
        self.assertEqual(([(r["header"], r["secs"]) for r in top], [r["secs"] for r in nested], why),
                         ([(5, 2.0)], [1.0], None))

    def test_a_nested_header_does_not_replace_the_open_one(self):
        top, _, _ = mct.parse_cargo_results(["running 3 tests", "running 1 test", ROW.format(p=3, i=0, f=0, s="1.0")])
        self.assertEqual([r["header"] for r in top], [3])

    def test_a_failed_and_a_measured_count_enter_the_sum(self):
        top, _, _ = mct.parse_cargo_results([
            "running 6 tests",
            "test result: FAILED. 1 passed; 2 failed; 1 ignored; 2 measured; 0 filtered out; finished in 1.0s"])
        self.assertEqual([(r["passed"], r["failed"], r["ignored"], r["measured"]) for r in top], [(1, 2, 1, 2)])

    def test_an_unclosed_header_is_a_reason_naming_the_header_and_its_line(self):
        lines = ["running 5 tests", "test a::one ... ok", "running 2 tests", "test b::one ... ok",
                 ROW.format(p=2, i=0, f=0, s="1.5")]
        top, nested, why = mct.parse_cargo_results(lines)
        self.assertEqual((top, len(nested)), ([], 1))
        self.assertEqual(why, "`running 5 tests` header (line 1) never closed before end of log")
        _, _, why = mct.parse_cargo_results(lines + ["--- stderr ---"])
        self.assertEqual(why, "`running 5 tests` header (line 1) never closed before the stderr marker")

    def test_an_unclosed_header_after_a_closed_binary_still_is_a_reason(self):
        _, _, why = mct.parse_cargo_results(
            ["running 2 tests", ROW.format(p=2, i=0, f=0, s="1.0"), "", "running 9 tests", "test x ... ok"])
        self.assertEqual(why, "`running 9 tests` header (line 4) never closed before end of log")

    def test_ignored_names_are_read_before_the_stderr_marker_only(self):
        self.assertEqual(mct.parse_cargo_ignored(CARGO_LOG + ["test z::late ... ignored"]), ["a::five", "a::four"])
        self.assertEqual(mct.parse_cargo_ignored(["--- stderr ---", "test z::late ... ignored"]), [])


class NextestTests(unittest.TestCase):
    def test_summary_and_distinct_failures(self):
        summary, fails, why = mct.parse_nextest(NEXTEST_1)
        self.assertEqual(summary, {"secs": 10.5, "run": 5, "passed": 3, "failed": 2, "skipped": 2, "timed_out": 0,
                                   "leaky": 0})
        self.assertEqual(fails, {"ai-memory a::one", "ai-memory::b b::two"})
        self.assertIsNone(why)

    def test_summary_without_a_failed_or_skipped_clause(self):
        summary, _, why = mct.parse_nextest(["Summary [   3.500s] 3 tests run: 3 passed"])
        self.assertEqual(summary, {"secs": 3.5, "run": 3, "passed": 3, "failed": 0, "skipped": 0, "timed_out": 0,
                                   "leaky": 0})
        self.assertIsNone(why)

    def test_no_summary_is_a_reason(self):
        self.assertEqual(mct.parse_nextest(["        FAIL [   0.4s] (   1/5) ai-memory::b b::two"]),
                         (None, {"ai-memory::b b::two"}, "no Summary line"))

    def test_every_clause_of_the_summary_is_read_into_a_named_field(self):
        summary, _, why = mct.parse_nextest(
            ["Summary [  10.500s] 5 tests run: 2 passed (1 slow, 1 flaky), 1 failed, 2 timed out, 2 skipped"])
        self.assertEqual(summary, {"secs": 10.5, "run": 5, "passed": 2, "failed": 1, "skipped": 2, "timed_out": 2,
                                   "leaky": 0})
        self.assertIsNone(why)

    def test_a_leaky_clause_enters_its_own_field(self):
        summary, _, why = mct.parse_nextest(["Summary [ 1.000s] 4 tests run: 2 passed (1 leaky), 1 failed, 1 leaky, 3 skipped"])
        self.assertEqual((summary["leaky"], summary["passed"], summary["failed"], why), (1, 2, 1, None))

    def test_an_unparsed_remainder_is_a_reason_quoting_the_clause(self):
        for rest, clause in [("5 passed, 1 mystery", "1 mystery"),
                             ("3 passed (1 slow, weird), 2 failed", "3 passed (1 slow, weird)"),
                             ("5 passed, two failed", "two failed"),
                             ("5 passed, 0 failed extra", "0 failed extra"),
                             ("5 passed,", "")]:
            with self.subTest(rest=rest):
                summary, _, why = mct.parse_nextest([f"Summary [ 1.000s] 5 tests run: {rest}"])
                self.assertEqual((summary, why), (None, f"unknown Summary clause {clause!r}"))

    def test_a_repeated_clause_is_a_reason(self):
        summary, _, why = mct.parse_nextest(["Summary [ 1.000s] 10 tests run: 5 passed, 5 passed"])
        self.assertEqual((summary, why), (None, "repeated Summary clause '5 passed'"))

    def test_a_summary_without_a_passed_clause_is_a_reason(self):
        summary, _, why = mct.parse_nextest(["Summary [ 1.000s] 5 tests run: 5 failed"])
        self.assertEqual((summary, why), (None, "Summary line has no passed clause: '5 failed'"))

    def test_an_unbalanced_parenthesis_is_a_reason(self):
        summary, _, why = mct.parse_nextest(["Summary [ 1.000s] 5 tests run: 5 passed (1 slow, 2 failed"])
        self.assertEqual((summary, why), (None, "unbalanced parenthesis in Summary clauses: '5 passed (1 slow, 2 failed'"))

    def test_a_close_before_its_open_is_unbalanced_even_when_the_depth_returns_to_zero(self):
        summary, _, why = mct.parse_nextest(["Summary [ 1.000s] 1 tests run: 1 passed ) 2 skipped ("])
        self.assertEqual((summary, why), (None, "unbalanced parenthesis in Summary clauses: '1 passed ) 2 skipped ('"))

    def test_a_summary_line_of_an_unknown_form_is_a_reason(self):
        summary, _, why = mct.parse_nextest(["  Summary [ 1.0s] five tests ran"])
        self.assertEqual((summary, why), (None, "Summary line not understood: 'Summary [ 1.0s] five tests ran'"))

    def test_counts_that_disagree_with_the_run_are_a_reason(self):
        summary, _, why = mct.parse_nextest(["Summary [ 1.000s] 5 tests run: 3 passed, 1 failed, 1 skipped"])
        self.assertEqual((summary, why),
                         (None, "Summary counts disagree: 5 run but passed + failed + timed out + leaky = 4"))
        summary, _, why = mct.parse_nextest(["Summary [ 1.000s] 5 tests run: 3 passed, 1 failed, 1 timed out"])
        self.assertEqual((summary["timed_out"], why), (1, None))

    def test_two_summary_lines_are_a_reason(self):
        summary, _, why = mct.parse_nextest(["Summary [ 1.0s] 1 test run: 1 passed", "Summary [ 2.0s] 1 test run: 1 passed"])
        self.assertEqual((summary, why), (None, "2 Summary lines"))

    def test_a_quoted_clause_is_cut_to_the_quote_bound(self):
        _, _, why = mct.parse_nextest(["Summary [ 1.000s] 5 tests run: 5 passed, 1 " + "x" * 300])
        self.assertEqual(why, "unknown Summary clause " + repr("1 " + "x" * 58) + "...")
        self.assertEqual(mct.CLAUSE_QUOTE_MAX, 60)

    def test_list_counts(self):
        self.assertEqual(mct.count_list(CARGO_LIST, mct.LIST_TEST_RE), 7)
        self.assertEqual(mct.count_list(NEXTEST_LIST, mct.NEXTEST_LIST_RE), 5)


class BenchReportTests(unittest.TestCase):
    def report(self, files_override=None, **override):
        with tempfile.TemporaryDirectory() as tmp:
            lay_out(tmp, files_override, **override)
            lines, missing, unmeasured = mct.bench_report(Path(tmp), READ_EPOCH)
        return [ln.replace(tmp, "<dir>") for ln in lines], [m.replace(tmp, "<dir>") for m in missing], unmeasured

    def test_full_report(self):
        lines, missing, unmeasured = self.report()
        self.assertEqual((missing, unmeasured), ([], []))
        self.assertEqual(lines, FULL)

    def test_the_write_time_is_the_modification_time_not_the_access_time(self):
        lines, _, _ = self.report()
        self.assertEqual(lines[I_BUILD], f"build: compile.log (written {WRITTEN}) cargo Finished in 135 s")
        self.assertNotIn(READ, "\n".join(lines[1:]))

    def test_a_list_that_disagrees_with_the_headers_says_no(self):
        lines, _, unmeasured = self.report(cglist_log=CARGO_LIST[:-2])
        self.assertIn("  reconcile: header sum == list NO; top-level passed + ignored == list NO; "
                      "all rows passed - list = 0, explained by nested rows (1) minus ignored (2) = -1: NO", lines)
        self.assertIn("same test count: nextest run + skipped == cargo list NO; nextest list == nextest run yes", lines)
        self.assertEqual(unmeasured, [])

    def test_ignored_names_that_do_not_match_the_ignored_count_say_no(self):
        lines, _, _ = self.report(cargotest_1_log=[ln for ln in CARGO_LOG if "a::five" not in ln])
        self.assertIn("  ignored tests: 1 named (a::four); top-level ignored count 2: NO", lines)

    def test_a_failed_name_count_that_differs_from_the_summary_says_no_below_and_above(self):
        below = self.report(nextest_2_log=NEXTEST_2[:1] + NEXTEST_2[2:])[0]
        self.assertIn(f"nextest-2.log (written {WRITTEN}): nextest Summary 12.0 s, 5 run, 3 passed, 2 failed, 2 skipped; "
                      "1 distinct FAIL names (== failed: NO)", below)
        above = self.report(nextest_2_log=NEXTEST_2[:2] + ["        FAIL [   0.9s] (   3/5) ai-memory a::two"] + NEXTEST_2[1:])[0]
        self.assertIn(f"nextest-2.log (written {WRITTEN}): nextest Summary 12.0 s, 5 run, 3 passed, 2 failed, 2 skipped; "
                      "3 distinct FAIL names (== failed: NO)", above)

    def test_a_summary_with_timed_out_and_slow_clauses_prints_what_the_log_holds(self):
        lines, _, unmeasured = self.report(nextest_1_log=[
            "Summary [  10.500s] 5 tests run: 2 passed (1 slow, 1 flaky), 1 failed, 2 timed out, 2 skipped"])
        self.assertEqual(lines[I_NX1], f"nextest-1.log (written {WRITTEN}): nextest Summary 10.5 s, 5 run, 2 passed, "
                                       "1 failed, 2 timed out, 2 skipped; 0 distinct FAIL names (== failed: NO)")
        self.assertEqual(unmeasured, [])

    def test_a_leaky_clause_is_printed_between_failed_and_skipped(self):
        lines, _, unmeasured = self.report(nextest_1_log=[
            "Summary [  10.500s] 5 tests run: 3 passed, 1 failed, 1 leaky, 2 skipped"])
        self.assertEqual(lines[I_NX1], f"nextest-1.log (written {WRITTEN}): nextest Summary 10.5 s, 5 run, 3 passed, "
                                       "1 failed, 1 leaky, 2 skipped; 0 distinct FAIL names (== failed: NO)")
        self.assertEqual(unmeasured, [])

    def test_a_build_log_without_a_finished_line_is_not_measured(self):
        lines, _, unmeasured = self.report(compile_log=["   Compiling x v1"])
        self.assertIn(f"build: compile.log (written {WRITTEN}) cargo Finished in not measured: no Finished line", lines)
        self.assertEqual(unmeasured, ["compile.log"])

    def test_empty_whitespace_and_bad_utf8_logs_of_every_kind_are_not_measured(self):
        for name in FIXTURE:
            for raw, reason in BYTE_CASES:
                with self.subTest(log=name, reason=reason):
                    lines, missing, unmeasured = self.report({name: raw})
                    self.assertEqual(lines, expected_lines((name, reason)))
                    self.assertEqual((missing, unmeasured), ([], [name]))

    def test_a_log_that_holds_none_of_its_records_is_not_measured_for_every_kind(self):
        for name, (reason, content) in NO_RECORD.items():
            with self.subTest(log=name):
                lines, missing, unmeasured = self.report({name: content})
                self.assertEqual(lines, expected_lines((name, reason)))
                self.assertEqual((missing, unmeasured), ([], [name]))

    def test_an_unclosed_header_in_a_cargo_log_is_not_measured_and_the_next_binary_is_not_nested(self):
        unclosed = ["running 5 tests", "test a::one ... ok", "running 2 tests", "test b::one ... ok",
                    ROW.format(p=2, i=0, f=0, s="1.5")]
        lines, _, unmeasured = self.report(cargotest_1_log=unclosed)
        self.assertEqual(lines, expected_lines(("cargotest-1.log", "`running 5 tests` header (line 1) never closed before end of log")))
        self.assertEqual(unmeasured, ["cargotest-1.log"])

    def test_empty_cargo_and_list_logs_print_no_number_and_no_yes(self):
        lines, _, unmeasured = self.report({"cargotest-1.log": b"", "cargotest-2.log": b"", "cglist.log": b""})
        text = "\n".join(lines[I_CARGO1:I_NX1])  # the two cargo logs with their reconcile lines
        self.assertNotIn("yes", text)
        self.assertNotIn("0.0 s", text)
        self.assertNotIn(" 0 passed", text)
        self.assertEqual(unmeasured, ["cglist.log", "cargotest-1.log", "cargotest-2.log"])

    def test_both_nextest_runs_without_a_summary_give_no_fail_set_line_numbers(self):
        lines, _, unmeasured = self.report(nextest_1_log=NEXTEST_1[:1], nextest_2_log=NEXTEST_2[:1])
        self.assertEqual(lines[I_FAILSETS], "nextest fail sets over runs 1 and 2: not measured: nextest-1.log, nextest-2.log")
        self.assertEqual(unmeasured, ["nextest-1.log", "nextest-2.log"])

    def test_a_nextest_log_without_a_summary_is_not_measured(self):
        lines, _, _ = self.report(nextest_1_log=NEXTEST_1[:1])
        self.assertIn(f"nextest-1.log (written {WRITTEN}): not measured: no Summary line", lines)
        self.assertIn("same test count: nextest run + skipped == cargo list not measured: nextest-1.log; "
                      "nextest list == nextest run not measured: nextest-1.log", lines)

    def test_a_probe_log_without_a_summary_is_not_measured(self):
        lines, _, _ = self.report(nextest_solo_log=SOLO[:1])
        self.assertIn(f"nextest-solo.log (written {WRITTEN}): not measured: no Summary line", lines)

    def test_two_not_measured_logs_both_change_their_lines(self):
        lines, _, unmeasured = self.report({"cglist.log": b"", "nextest-1.log": b""})
        expected = expected_lines(("cglist.log", "empty (0 bytes)"), ("nextest-1.log", "empty (0 bytes)"))
        expected[I_SAME] = ("same test count: nextest run + skipped == cargo list not measured: nextest-1.log, "
                            "cglist.log; nextest list == nextest run not measured: nextest-1.log")
        self.assertEqual(lines, expected)
        self.assertEqual(unmeasured, ["cglist.log", "nextest-1.log"])

    def test_a_cargo_log_with_a_bad_summary_clause_in_a_nextest_run_is_not_measured(self):
        lines, _, unmeasured = self.report(nextest_2_log=["Summary [ 1.000s] 5 tests run: 5 passed, 1 mystery"])
        self.assertEqual(lines, expected_lines(("nextest-2.log", "unknown Summary clause '1 mystery'")))
        self.assertEqual(unmeasured, ["nextest-2.log"])

    def test_a_log_of_exactly_the_cap_is_read_and_one_byte_more_is_not(self):
        size = len("\n".join(COMPILE) + "\n")
        with mock.patch.object(mct, "BENCH_LOG_MAX_BYTES", size):
            lines, _, unmeasured = self.report()
            self.assertEqual((lines[I_BUILD], unmeasured), (FULL[I_BUILD], [n for n in FIXTURE if len(
                "\n".join(FIXTURE[n]) + "\n") > size]))
        with mock.patch.object(mct, "BENCH_LOG_MAX_BYTES", size - 1):
            lines, _, unmeasured = self.report()
            self.assertEqual(lines[I_BUILD], f"build: compile.log (written {WRITTEN}) cargo Finished in not measured: "
                                             f"larger than the {size - 1} byte cap")
            self.assertIn("compile.log", unmeasured)

    def test_the_cap_is_a_named_constant_well_above_the_stored_logs(self):
        self.assertGreaterEqual(mct.BENCH_LOG_MAX_BYTES, 8 * 4_600_000)

    def test_a_missing_log_is_named_and_nothing_else_is_printed(self):
        with tempfile.TemporaryDirectory() as tmp:
            lay_out(tmp, nextest_solo_j1_log=None)
            lines, missing, unmeasured = mct.bench_report(Path(tmp), READ_EPOCH)
        self.assertEqual((lines, unmeasured), ([], []))
        self.assertEqual(len(missing), 1)
        self.assertTrue(missing[0].startswith("nextest-solo-j1.log: "), missing)

    def test_a_large_log_is_read_in_bounded_time(self):
        count = 300_000
        big = ([f"running {count} tests"] + [f"test t::n{i} ... ok" for i in range(count)]
               + [ROW.format(p=count, i=0, f=0, s="9.0")])
        big_nextest = ["        FAIL [   0.1s] (   1/9) ai-memory t::n" + str(i) for i in range(count)]
        with tempfile.TemporaryDirectory() as tmp:
            lay_out(tmp, {"cargotest-1.log": big, "nextest-1.log": big_nextest +
                          ["Summary [ 1.0s] 1 test run: 1 passed"]})
            started = time.monotonic()
            lines, _, _ = mct.bench_report(Path(tmp), READ_EPOCH)
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 20.0)
        self.assertIn(f"{count} passed", lines[I_CARGO1])


class ExitCodeTests(unittest.TestCase):
    def test_the_exit_rule_is_in_the_docstring(self):
        self.assertEqual(mct.EXIT_BENCH_PARTIAL, 7)
        self.assertIn("7 the report was printed and at least one stored bench log is not measured", mct.__doc__)

    def test_a_full_run_is_0_a_not_measured_run_is_7_a_missing_log_is_6(self):
        with tempfile.TemporaryDirectory() as tmp:
            lay_out(tmp)
            rc, out, err = run_main(tmp)
            self.assertEqual((rc, err), (0, ""))
            self.assertIn("nextest fail sets over runs 1 and 2: 1 in both, 3 in either", out)
            lay_out(tmp, {"nextest-1.log": b"", "cglist.log": b" \n"})
            rc, out, err = run_main(tmp)
            self.assertEqual(rc, 7)
            self.assertEqual(err, "not measured: 2 log(s): cglist.log, nextest-1.log\n")
            self.assertIn(f"nextest-1.log (written {WRITTEN}): not measured: empty (0 bytes)", out)
            (Path(tmp) / "nxlist.log").unlink()
            rc, out, err = run_main(tmp)
        self.assertEqual(rc, 6)
        self.assertEqual(out, "")
        self.assertTrue(err.startswith("not measured: nxlist.log: "), err)
        self.assertNotIn("log(s)", err)

    def test_every_not_measured_log_kind_exits_7_with_its_name_on_stderr(self):
        for name in FIXTURE:
            with self.subTest(log=name), tempfile.TemporaryDirectory() as tmp:
                lay_out(tmp, {name: b""})
                rc, out, err = run_main(tmp)
                self.assertEqual((rc, err), (7, f"not measured: 1 log(s): {name}\n"))
                self.assertTrue(out.startswith(f"read at "), out)


if __name__ == "__main__":
    unittest.main()
