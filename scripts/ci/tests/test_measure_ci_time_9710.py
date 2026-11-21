# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Arithmetic of scripts/ci/measure_ci_time.py on a hand-written jobs-API fixture (#9710)."""

import contextlib
import importlib.util
import io
import os
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "measure_ci_time.py"
SCRATCH = Path(os.environ.get("TMPDIR") or ".local-runs")
spec = importlib.util.spec_from_file_location("measure_ci_time", SCRIPT)
mct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mct)

# Hand-written: queue 10 s, setup 10+20+30 = 60 s, combined step 600 s, post 5+15 = 20 s, total 700 s + 10 s tail.
JOB = {
    "created_at": "2026-01-01T00:00:00Z",
    "started_at": "2026-01-01T00:00:10Z",
    "completed_at": "2026-01-01T00:11:50Z",
    "steps": [
        {"name": "Set up job", "started_at": "2026-01-01T00:00:10Z", "completed_at": "2026-01-01T00:00:20Z", "conclusion": "success"},
        {"name": "Run actions/checkout@x", "started_at": "2026-01-01T00:00:20Z", "completed_at": "2026-01-01T00:00:40Z", "conclusion": "success"},
        {"name": "Run Swatinem/rust-cache@x", "started_at": "2026-01-01T00:00:40Z", "completed_at": "2026-01-01T00:01:10Z", "conclusion": "success"},
        {"name": "Run tests (impact-aware)", "started_at": "2026-01-01T00:01:10Z", "completed_at": "2026-01-01T00:11:10Z", "conclusion": "success"},
        {"name": "Upload test results", "started_at": "2026-01-01T00:11:10Z", "completed_at": "2026-01-01T00:11:15Z", "conclusion": "success"},
        {"name": "Post Run Swatinem/rust-cache@x", "started_at": "2026-01-01T00:11:15Z", "completed_at": "2026-01-01T00:11:30Z", "conclusion": "success"},
    ],
}
# cargo reported 4m 30s (270 s) of compile; the step runs 600 s, so 330 s remain for the test run.
LOG = [
    "2026-01-01T00:01:11.1000000Z \x1b[1m\x1b[92m   Compiling\x1b[0m serde v1",
    "2026-01-01T00:05:40.0000000Z     Finished `test` profile [unoptimized + debuginfo] target(s) in 4m 30s",
    "2026-01-01T00:05:41.0000000Z     Finished `test` profile [unoptimized + debuginfo] target(s) in 0.85s",
]


class SplitJobTests(unittest.TestCase):
    def test_stage_arithmetic_with_log_split(self):
        got = mct.split_job(JOB, LOG)
        self.assertEqual(got["queue"], 10.0)
        self.assertEqual(got["setup"], 60.0)
        self.assertEqual(got["compile"], 270.0)
        self.assertEqual(got["test"], 330.0)
        self.assertEqual(got["post"], 20.0)
        self.assertEqual(got["total"], 700.0)

    def test_without_log_compile_and_test_are_not_separable(self):
        got = mct.split_job(JOB, None)
        self.assertIsNone(got["compile"])
        self.assertIsNone(got["test"])
        self.assertEqual(got["combined_wall"], 600.0)

    def test_carried_over_job_has_no_queue_figure(self):
        job = dict(JOB, created_at="2026-01-01T01:00:00Z")
        self.assertIsNone(mct.split_job(job, LOG)["queue"])

    def test_separate_compile_step_adds_to_compile_not_post(self):
        job = dict(JOB, steps=JOB["steps"] + [
            {"name": "Build release (once leg)", "started_at": "2026-01-01T00:11:30Z", "completed_at": "2026-01-01T00:11:50Z", "conclusion": "success"}])
        got = mct.split_job(job, LOG)
        self.assertEqual(got["compile"], 290.0)
        self.assertEqual(got["post"], 20.0)

    def test_finished_line_outside_the_step_window_is_ignored(self):
        late = ["2026-01-01T09:00:00.0000000Z     Finished `test` profile [x] target(s) in 1m 0s"]
        self.assertIsNone(mct.split_job(JOB, late)["test"])


def step_index(name_prefix):
    return next(i for i, s in enumerate(JOB["steps"]) if s["name"].startswith(name_prefix))


def job_with_step(index, **changes):
    steps = [dict(s) for s in JOB["steps"]]
    steps[index].update(changes)
    return dict(JOB, steps=steps)


MAIN = step_index("Run tests")
SETUP = step_index("Run actions/checkout")
# One row per reason: (case name, job, log, stage that must be None, "stage:reason" that must be reported).
UNMEASURED_CASES = (
    ("setup step without timestamps", job_with_step(SETUP, started_at=None, completed_at=None), LOG, "setup", "setup:missing-timestamp"),
    ("setup step with a garbage timestamp", job_with_step(SETUP, completed_at="not-a-time"), LOG, "setup", "setup:missing-timestamp"),
    ("setup step that ends before it starts", job_with_step(SETUP, completed_at="2026-01-01T00:00:01Z"), LOG, "setup", "setup:negative"),
    ("main step without timestamps", job_with_step(MAIN, started_at=None, completed_at=None), LOG, "compile", "compile:missing-timestamp"),
    ("main step that ends before it starts", job_with_step(MAIN, completed_at="2026-01-01T00:00:01Z"), LOG, "test", "test:negative"),
    ("job without a completed_at", dict(JOB, completed_at=None), LOG, "total", "total:missing-timestamp"),
    ("job that ends before it starts", dict(JOB, completed_at="2026-01-01T00:00:00Z"), LOG, "total", "total:negative"),
    ("compile reported longer than the step", JOB, ["2026-01-01T00:05:40.0000000Z     Finished `test` profile [x] target(s) in 20m 0s"], "compile", "compile:compile-longer-than-step"),
    ("compile reported longer than the step (test side)", JOB, ["2026-01-01T00:05:40.0000000Z     Finished `test` profile [x] target(s) in 20m 0s"], "test", "test:compile-longer-than-step"),
)


class UnmeasuredTests(unittest.TestCase):
    def test_each_bad_input_is_unmeasured_with_a_named_reason(self):
        for case, job, log, stage, reason in UNMEASURED_CASES:
            with self.subTest(case):
                got = mct.split_job(job, log)
                self.assertIsNone(got[stage])
                self.assertIn(reason, got["unmeasured"])

    def test_no_stage_is_ever_reported_as_zero_for_bad_input(self):
        for case, job, log, _stage, _reason in UNMEASURED_CASES:
            with self.subTest(case):
                got = mct.split_job(job, log)
                flagged = {entry.split(":")[0] for entry in got["unmeasured"]}
                for stage in mct.STAGES:
                    if stage in flagged:
                        self.assertIsNone(got[stage])

    def test_good_input_has_no_unmeasured_entry(self):
        self.assertEqual(mct.split_job(JOB, LOG)["unmeasured"], [])

    def test_main_step_without_timestamps_does_not_accept_a_finished_line_from_another_day(self):
        other_day = ["2026-03-05T09:00:00.0000000Z     Finished `test` profile [x] target(s) in 1m 0s"]
        got = mct.split_job(job_with_step(MAIN, started_at=None, completed_at=None), other_day)
        self.assertIsNone(got["compile"])
        self.assertIsNone(got["test"])

    def test_unmeasured_rows_stay_out_of_median_and_sum(self):
        good = mct.split_job(JOB, LOG)
        bad = mct.split_job(job_with_step(SETUP, started_at=None, completed_at=None), LOG)
        stat = mct.summarize([good["setup"], bad["setup"]])
        self.assertEqual(stat, (60.0, 60.0, 60.0, 1))

    def test_footer_counts_every_reason(self):
        rows = []
        for _case, job, log, _stage, _reason in UNMEASURED_CASES:
            row = mct.split_job(job, log)
            row.update(workflow="ci.yml", job="Check (x)", kind="hosted")
            rows.append(row)
        line = mct.unmeasured_footer(rows)
        self.assertTrue(line.startswith("unmeasured: "))
        for reason in ("missing-timestamp", "negative", "compile-longer-than-step"):
            self.assertIn(f"{reason}=", line)
        self.assertEqual(mct.unmeasured_footer([mct.split_job(JOB, LOG)]), "unmeasured: 0 cells in 0 of 1 rows")


class NullStepNameTests(unittest.TestCase):
    def test_null_step_name_is_a_row_reason_not_a_traceback(self):
        job = job_with_step(SETUP, name=None)
        got = mct.split_job(job, LOG)
        self.assertIn("setup:missing-step-name", got["unmeasured"])
        self.assertIsNone(got["setup"])

    def test_missing_name_key_behaves_like_null(self):
        steps = [dict(s) for s in JOB["steps"]]
        del steps[SETUP]["name"]
        got = mct.split_job(dict(JOB, steps=steps), LOG)
        self.assertIn("setup:missing-step-name", got["unmeasured"])

    def test_malformed_payload_exits_with_the_documented_code_and_one_stderr_line(self):
        def boom(*_args, **_kwargs):
            raise TypeError("expected string or bytes-like object, got 'NoneType'")
        original = mct.collect
        mct.collect = boom
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                rc = mct.main(["--repo", "o/n", "--branch", "b", "--scratch", str(SCRATCH)])
        finally:
            mct.collect = original
        self.assertEqual(rc, mct.EXIT_BAD_INPUT)
        self.assertEqual(len(err.getvalue().strip().splitlines()), 1)
        self.assertIn("unexpected input", err.getvalue())


class TimezoneTests(unittest.TestCase):
    def _interval(self, tz_name):
        old = os.environ.get("TZ")
        os.environ["TZ"] = tz_name
        time.tzset()
        try:
            return mct.parse_ts("2026-11-01T02:30:00Z") - mct.parse_ts("2026-11-01T01:30:00Z")
        finally:
            if old is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old
            time.tzset()

    def test_interval_across_a_dst_change_is_the_same_in_every_zone(self):
        self.assertEqual(self._interval("UTC"), 3600.0)
        self.assertEqual(self._interval("America/New_York"), 3600.0)

    def test_fraction_is_kept(self):
        self.assertEqual(mct.parse_ts("2026-01-01T00:00:01.5000000Z") - mct.parse_ts("2026-01-01T00:00:00Z"), 1.5)

    def test_unusable_timestamps_are_none(self):
        for bad in (None, "", "garbage", 12345, "2026-13-45T99:00:00Z"):
            with self.subTest(bad=bad):
                self.assertIsNone(mct.parse_ts(bad))


class RunsArgumentTests(unittest.TestCase):
    def _run(self, value):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
            mct.main(["--repo", "o/n", "--branch", "b", "--runs", value, "--scratch", str(SCRATCH)])
        return raised.exception.code, err.getvalue()

    def test_out_of_range_or_non_numeric_runs_exit_2_with_the_reason(self):
        for value in ("0", "-3", "31", "1000", "abc", "2.5"):
            with self.subTest(value):
                code, text = self._run(value)
                self.assertEqual(code, 2)
                self.assertIn("--runs", text)
                self.assertIn(f"1..{mct.MAX_RUNS}", text)

    def test_bounds_are_accepted(self):
        for value, expected in (("1", 1), ("30", 30)):
            with self.subTest(value):
                self.assertEqual(mct.runs_arg(value), expected)


class RankTests(unittest.TestCase):
    def test_pairs_running_with_next_result_longest_first(self):
        lines = [
            "2026-01-01T00:00:01.0000000Z      Running tests/slow.rs (target/debug/deps/slow-1)",
            "2026-01-01T00:00:02.0000000Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 12.50s",
            "2026-01-01T00:00:03.0000000Z      Running unittests src/lib.rs (target/debug/deps/lib-2)",
            "2026-01-01T00:00:04.0000000Z test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s",
            "2026-01-01T00:00:05.0000000Z test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.00s",
        ]
        self.assertEqual(mct.rank_binaries(lines), [(12.5, 3, "tests/slow.rs"), (0.25, 7, "src/lib.rs")])


class SummaryTests(unittest.TestCase):
    def test_median_and_range_drop_none(self):
        self.assertEqual(mct.summarize([10.0, None, 30.0, 20.0, 100.0]), (25.0, 10.0, 100.0, 4))
        self.assertIsNone(mct.summarize([None, None]))
        self.assertEqual(mct.fmt(None), "not measured")
        self.assertEqual(mct.fmt((25.0, 10.0, 100.0, 4)), "25 (10-100) n=4")

    def test_runner_kind(self):
        self.assertEqual(mct.runner_kind(["self-hosted", "macos-fed"]), "macos-fed")
        self.assertEqual(mct.runner_kind(["self-hosted", "linux-fed"]), "self-hosted Linux")
        self.assertEqual(mct.runner_kind(["ubuntu-latest"]), "hosted")


if __name__ == "__main__":
    unittest.main()
