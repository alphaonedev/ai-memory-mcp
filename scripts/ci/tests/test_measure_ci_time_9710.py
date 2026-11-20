# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Arithmetic of scripts/ci/measure_ci_time.py on a hand-written jobs-API fixture (#9710)."""

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "measure_ci_time.py"
spec = importlib.util.spec_from_file_location("measure_ci_time", SCRIPT)
mct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mct)

# Hand-written: queue 10 s, setup 10+20+30 = 60 s, combined step 600 s, post 5+15 = 20 s, total 700 s + 10 s tail.
JOB = {
    "created_at": "2026-01-01T00:00:00Z",
    "started_at": "2026-01-01T00:00:10Z",
    "completed_at": "2026-01-01T00:11:50Z",
    "steps": [
        {"name": "Set up job", "started_at": "2026-01-01T00:00:10Z", "completed_at": "2026-01-01T00:00:20Z"},
        {"name": "Run actions/checkout@x", "started_at": "2026-01-01T00:00:20Z", "completed_at": "2026-01-01T00:00:40Z"},
        {"name": "Run Swatinem/rust-cache@x", "started_at": "2026-01-01T00:00:40Z", "completed_at": "2026-01-01T00:01:10Z"},
        {"name": "Run tests (impact-aware)", "started_at": "2026-01-01T00:01:10Z", "completed_at": "2026-01-01T00:11:10Z"},
        {"name": "Upload test results", "started_at": "2026-01-01T00:11:10Z", "completed_at": "2026-01-01T00:11:15Z"},
        {"name": "Post Run Swatinem/rust-cache@x", "started_at": "2026-01-01T00:11:15Z", "completed_at": "2026-01-01T00:11:30Z"},
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
            {"name": "Build release (once leg)", "started_at": "2026-01-01T00:11:30Z", "completed_at": "2026-01-01T00:11:50Z"}])
        got = mct.split_job(job, LOG)
        self.assertEqual(got["compile"], 290.0)
        self.assertEqual(got["post"], 20.0)

    def test_finished_line_outside_the_step_window_is_ignored(self):
        late = ["2026-01-01T09:00:00.0000000Z     Finished `test` profile [x] target(s) in 1m 0s"]
        self.assertIsNone(mct.split_job(JOB, late)["test"])


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
