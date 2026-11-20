# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The stored-log mode (--bench-dir) of scripts/ci/measure_ci_time.py on hand-written logs (#9710).

Every expected value below is written out by hand from the fixture text, never computed by the script.
"""

import contextlib
import importlib.util
import io
import os
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "measure_ci_time.py"
spec = importlib.util.spec_from_file_location("measure_ci_time", SCRIPT)
mct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mct)

WRITTEN_EPOCH = 1767225600  # 2026-01-01T00:00:00Z
READ_EPOCH = 1767312000  # 2026-01-02T00:00:00Z
WRITTEN = "2026-01-01T00:00:00Z"
READ = "2026-01-02T00:00:00Z"

# A lib binary of 5 tests (3 pass, 2 ignored) whose output holds one child-process run of 1 test; then a binary of 2.
CARGO_LOG = """
running 5 tests
test a::one ... ok
running 1 test
test a::two ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.05s

test a::three ... ok
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


def lay_out(directory, **override):
    """Write the eleven fixture logs into directory; override maps a file name to its lines (None omits the file)."""
    files = {"compile.log": COMPILE, "cglist.log": CARGO_LIST, "nxlist.log": NEXTEST_LIST,
             "cargotest-1.log": CARGO_LOG, "cargotest-2.log": CARGO_LOG, "nextest-1.log": NEXTEST_1,
             "nextest-2.log": NEXTEST_2, "nextest-solo1.log": SOLO_1, "nextest-solo.log": SOLO,
             "nextest-solo-j1.log": SOLO_J1}
    files.update({name.replace("_", "-").replace("-log", ".log"): lines for name, lines in override.items()})
    for name, lines in files.items():
        if lines is None:
            continue
        path = Path(directory) / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.utime(path, (WRITTEN_EPOCH, WRITTEN_EPOCH))


class CargoResultsTests(unittest.TestCase):
    def test_top_level_and_nested_rows_are_told_apart(self):
        top, nested = mct.parse_cargo_results(CARGO_LOG)
        self.assertEqual([(r["header"], r["passed"], r["failed"], r["ignored"], r["secs"]) for r in top],
                         [(5, 3, 0, 2, 10.5), (2, 2, 0, 0, 1.5)])
        self.assertEqual([(r["passed"], r["secs"]) for r in nested], [(1, 0.05)])

    def test_a_row_after_the_stderr_marker_is_not_read(self):
        top, nested = mct.parse_cargo_results(CARGO_LOG)
        self.assertEqual(sum(r["passed"] for r in top + nested), 6)  # not 105: the 99-passed row is stderr

    def test_a_row_with_no_open_header_is_nested(self):
        top, nested = mct.parse_cargo_results(
            ["test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.0s"])
        self.assertEqual((top, [r["passed"] for r in nested]), ([], [4]))

    def test_a_row_whose_count_differs_from_the_open_header_is_nested_and_the_header_stays_open(self):
        top, nested = mct.parse_cargo_results([
            "running 5 tests",
            "test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.0s",
            "test result: ok. 4 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 2.0s",
        ])
        self.assertEqual(([(r["header"], r["secs"]) for r in top], [r["secs"] for r in nested]), ([(5, 2.0)], [1.0]))

    def test_a_nested_header_does_not_replace_the_open_one(self):
        top, _ = mct.parse_cargo_results([
            "running 3 tests", "running 1 test",
            "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.0s"])
        self.assertEqual([r["header"] for r in top], [3])

    def test_a_failed_and_a_measured_count_enter_the_sum(self):
        top, _ = mct.parse_cargo_results([
            "running 6 tests",
            "test result: FAILED. 1 passed; 2 failed; 1 ignored; 2 measured; 0 filtered out; finished in 1.0s"])
        self.assertEqual([(r["passed"], r["failed"], r["ignored"], r["measured"]) for r in top], [(1, 2, 1, 2)])


class NextestTests(unittest.TestCase):
    def test_summary_and_distinct_failures(self):
        summary, fails = mct.parse_nextest(NEXTEST_1)
        self.assertEqual(summary, {"secs": 10.5, "run": 5, "passed": 3, "failed": 2, "skipped": 2})
        self.assertEqual(fails, {"ai-memory a::one", "ai-memory::b b::two"})

    def test_summary_without_a_failed_or_skipped_clause(self):
        summary, _ = mct.parse_nextest(["Summary [   3.500s] 3 tests run: 3 passed"])
        self.assertEqual(summary, {"secs": 3.5, "run": 3, "passed": 3, "failed": 0, "skipped": 0})

    def test_no_summary_is_none(self):
        self.assertEqual(mct.parse_nextest(["        FAIL [   0.4s] (   1/5) ai-memory::b b::two"]),
                         (None, {"ai-memory::b b::two"}))

    def test_list_counts(self):
        self.assertEqual(mct.count_list(CARGO_LIST, mct.LIST_TEST_RE), 7)
        self.assertEqual(mct.count_list(NEXTEST_LIST, mct.NEXTEST_LIST_RE), 5)


class BenchReportTests(unittest.TestCase):
    def report(self, **override):
        with tempfile.TemporaryDirectory() as tmp:
            lay_out(tmp, **override)
            lines, missing = mct.bench_report(Path(tmp), READ_EPOCH)
        return [ln.replace(tmp, "<dir>") for ln in lines], [m.replace(tmp, "<dir>") for m in missing]

    def test_full_report(self):
        lines, missing = self.report()
        self.assertEqual(missing, [])
        reconcile = ("  reconcile: header sum == list yes; top-level passed + ignored == list yes; "
                     "all rows passed - list = -1, explained by nested rows (1) minus ignored (2) = -1: yes")
        cargo = (f" (written {WRITTEN}): 2 top-level result rows, header sum 7, 5 passed, 0 failed, 2 ignored, "
                 "sum of finished-in 12.0 s; 1 nested result rows (1 passed) printed inside the lib test output; "
                 "all rows 6 passed")
        self.assertEqual(lines, [
            f"read at {READ} UTC from <dir>",
            f"build: compile.log (written {WRITTEN}) cargo Finished in 135 s",
            f"list: cglist.log (written {WRITTEN}) 7 `: test` lines; nxlist.log (written {WRITTEN}) 5 test lines",
            "cargotest-1.log" + cargo, reconcile,
            "cargotest-2.log" + cargo, reconcile,
            f"nextest-1.log (written {WRITTEN}): nextest Summary 10.5 s, 5 run, 3 passed, 2 failed, 2 skipped; "
            "2 distinct FAIL names (== failed: yes)",
            f"nextest-2.log (written {WRITTEN}): nextest Summary 12.0 s, 5 run, 3 passed, 2 failed, 2 skipped; "
            "2 distinct FAIL names (== failed: yes)",
            "nextest fail sets over runs 1 and 2: 1 in both, 3 in either",
            f"nextest-solo1.log (written {WRITTEN}): nextest Summary 2.0 s, 1 run, 1 passed, 0 failed",
            f"nextest-solo.log (written {WRITTEN}): nextest Summary 1.5 s, 3 run, 0 passed, 3 failed",
            f"nextest-solo-j1.log (written {WRITTEN}): nextest Summary 3.5 s, 3 run, 3 passed, 0 failed",
            "same test count: nextest run + skipped == cargo list yes; nextest list == nextest run yes",
        ])

    def test_a_list_that_disagrees_with_the_headers_says_no(self):
        lines, _ = self.report(cglist_log=CARGO_LIST[:-2])
        self.assertIn("  reconcile: header sum == list NO; top-level passed + ignored == list NO; "
                      "all rows passed - list = 0, explained by nested rows (1) minus ignored (2) = -1: NO", lines)
        self.assertIn("same test count: nextest run + skipped == cargo list NO; nextest list == nextest run yes", lines)

    def test_a_nextest_log_without_a_summary_is_not_measured(self):
        lines, _ = self.report(nextest_1_log=NEXTEST_1[:1])
        self.assertIn(f"nextest-1.log (written {WRITTEN}): not measured: no Summary line", lines)
        self.assertIn("same test count: nextest run + skipped == cargo list NO; nextest list == nextest run NO", lines)

    def test_a_build_log_without_a_finished_line_is_not_measured(self):
        lines, _ = self.report(compile_log=["   Compiling x v1"])
        self.assertIn(f"build: compile.log (written {WRITTEN}) cargo Finished in not measured", lines)

    def test_a_failed_name_count_that_differs_from_the_summary_says_no(self):
        lines, _ = self.report(nextest_2_log=NEXTEST_2[:1] + NEXTEST_2[2:])
        self.assertIn(f"nextest-2.log (written {WRITTEN}): nextest Summary 12.0 s, 5 run, 3 passed, 2 failed, 2 skipped; "
                      "1 distinct FAIL names (== failed: NO)", lines)

    def test_a_missing_log_is_named_and_nothing_else_is_printed(self):
        with tempfile.TemporaryDirectory() as tmp:
            lay_out(tmp, nextest_solo_j1_log=None)
            lines, missing = mct.bench_report(Path(tmp), READ_EPOCH)
        self.assertEqual(lines, [])
        self.assertEqual(len(missing), 1)
        self.assertTrue(missing[0].startswith("nextest-solo-j1.log: "), missing)

    def test_main_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            lay_out(tmp)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = mct.main(["--repo", "o/r", "--branch", "b", "--bench-dir", tmp])
            self.assertEqual((rc, err.getvalue()), (0, ""))
            self.assertIn("nextest fail sets over runs 1 and 2: 1 in both, 3 in either", out.getvalue())
            (Path(tmp) / "nxlist.log").unlink()
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = mct.main(["--repo", "o/r", "--branch", "b", "--bench-dir", tmp])
        self.assertEqual(rc, 6)
        self.assertEqual(out.getvalue(), "")
        self.assertTrue(err.getvalue().startswith("not measured: nxlist.log: "), err.getvalue())


if __name__ == "__main__":
    unittest.main()
