# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Wait figures of scripts/ci/measure_ci_time.py (#9773): load-gate wait, semaphore wait, compile and test run.

Invariant: the four figures are each computed from the state they name and never overlap; a job with no such step or
line reports the wait as absent with its own exact reason, never as 0 and never by guessing.

The expected reason texts and numbers below are written out here, not read from the script. The semaphore marker and
the load-gate step name are the script's named constants, used by the script and by these tests alike.
"""

import contextlib
import importlib.util
import io
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "measure_ci_time.py"
spec = importlib.util.spec_from_file_location("measure_ci_time_9773", SCRIPT)
mct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mct)

DAY = "2026-11-20"
BIG_LINE_COUNT = 150_000  # over 100K lines
BIG_LOG_SECONDS_CEILING = 5.0
DIGITS_FLOOD = 5000  # more digits than int() accepts by default
# Expected reason texts, written out (not taken from the script).
R_NO_LINE = "no-semaphore-line"
R_NO_LOG = "no-log"
R_EMPTY_LOG = "empty-log"
R_MALFORMED = "malformed-semaphore-wait"
R_MULTIPLE = "multiple-semaphore-lines"
R_WAIT_LONGER = "semaphore-wait-longer-than-step"
R_OVERLAP = "compile-plus-wait-longer-than-step"
R_NO_GATE = "no-load-gate-step"
R_GATE_NO_TS = "load-gate-missing-timestamp"
R_GATE_NEGATIVE = "load-gate-negative"
R_GATE_MULTIPLE = "multiple-load-gate-steps"


def stamp(clock):
    return f"{DAY}T{clock}Z"


def log_line(clock, text):
    return f"{DAY}T{clock}.0000000Z {text}"


def sem_line(clock, wait_text="300s", prefix="##[notice]"):
    return log_line(clock, f"{prefix}{mct.SEMAPHORE_MARKER} 'T': slot 1 of 2 acquired after {wait_text} (load=26.90 cores=14)")


def finished_line(clock, took="34m 41s"):
    return log_line(clock, f"    Finished `test` profile [unoptimized] target(s) in {took}")


def issue_job(gate_steps=None, main_start="22:00:01", main_end="23:54:28"):
    """The shape of job 136556334572 (issue 9773): load gate 1200 s, test step 6867 s."""
    gate = gate_steps if gate_steps is not None else [
        {"name": mct.LOAD_GATE_STEP_NAME, "started_at": stamp("21:40:01"), "completed_at": stamp("22:00:01")}]
    return {
        "created_at": stamp("21:39:29"),
        "started_at": stamp("21:39:29"),
        "completed_at": stamp("23:54:46"),
        "steps": [
            {"name": "Set up job", "started_at": stamp("21:39:29"), "completed_at": stamp("21:39:40")},
            *gate,
            {"name": "Run tests (impact-aware)", "started_at": stamp(main_start), "completed_at": stamp(main_end)},
            {"name": "Post Run actions/checkout", "started_at": stamp(main_end), "completed_at": stamp("23:54:46")},
        ],
    }


def issue_log(*middle):
    return [log_line("22:00:02", "##[group]Run tests"), *middle,
            finished_line("22:39:43"), log_line("23:54:00", "test result: ok. 1 passed; finished in 1.00s")]


def default_log():
    return issue_log(sem_line("22:05:01"))


class IssueFiguresTests(unittest.TestCase):
    def test_issue_9773_job_reports_four_figures_apart(self):
        # step 22:00:01 to 23:54:28 = 6867 s; compile 34m 41s = 2081 s; wait 300 s; test run = 6867 - 2081 - 300 = 4486 s
        # (the issue's 4485 s is the difference of two log timestamps, one second off the reported compile figure).
        got = mct.split_job(issue_job(), default_log())
        self.assertEqual(got["combined_wall"], 6867.0)
        self.assertEqual(got["load_gate"], 1200.0)
        self.assertEqual(got["semaphore"], 300.0)
        self.assertEqual(got["compile"], 2081.0)
        self.assertEqual(got["test"], 4486.0)
        self.assertEqual(got["wait_absent"], {})
        self.assertEqual(got["unmeasured"], [])

    def test_semaphore_compile_and_test_run_do_not_overlap(self):
        got = mct.split_job(issue_job(), default_log())
        self.assertEqual(got["semaphore"] + got["compile"] + got["test"], got["combined_wall"])

    def test_ansi_colour_and_annotation_prefix_do_not_hide_the_line(self):
        coloured = issue_log(sem_line("22:05:01", prefix="\x1b[36m"))
        self.assertEqual(mct.split_job(issue_job(), coloured)["semaphore"], 300.0)

    def test_zero_second_wait_is_a_real_zero(self):
        got = mct.split_job(issue_job(), issue_log(sem_line("22:05:01", "0s")))
        self.assertEqual(got["semaphore"], 0.0)
        self.assertEqual(got["test"], 6867.0 - 2081.0)
        self.assertEqual(got["wait_absent"], {})


class SemaphoreAbsentTests(unittest.TestCase):
    def test_no_semaphore_line_is_absent_not_zero(self):
        got = mct.split_job(issue_job(), issue_log())
        self.assertIsNone(got["semaphore"])
        self.assertEqual(got["wait_absent"]["semaphore"], R_NO_LINE)
        self.assertEqual(got["test"], 6867.0 - 2081.0)  # a job without the semaphore keeps its figure

    def test_no_log_and_empty_log_have_their_own_reasons(self):
        none_log = mct.split_job(issue_job(), None)
        empty_log = mct.split_job(issue_job(), [])
        self.assertEqual(none_log["wait_absent"]["semaphore"], R_NO_LOG)
        self.assertEqual(empty_log["wait_absent"]["semaphore"], R_EMPTY_LOG)
        self.assertIsNone(none_log["semaphore"])
        self.assertIsNone(empty_log["semaphore"])

    def test_other_semaphore_marker_lines_are_not_acquisitions(self):
        other = issue_log(log_line("22:05:01", f"{mct.SEMAPHORE_MARKER} 'T': slot 1 of 2 released"),
                          log_line("22:05:02", f"##[error]{mct.SEMAPHORE_MARKER} 'T': no slot free after 3600s (all 2 slots busy on this host)"))
        got = mct.split_job(issue_job(), other)
        self.assertIsNone(got["semaphore"])
        self.assertEqual(got["wait_absent"]["semaphore"], R_NO_LINE)

    def test_line_after_the_compile_finished_line_is_test_output_not_the_job_line(self):
        # decision: read only lines up to the first cargo Finished line over taking every line of the step, because the
        # semaphore wraps the cargo command and prints before it; a test that prints the marker runs after Finished.
        forged = issue_log(sem_line("22:05:01"))
        forged.insert(-1, sem_line("22:50:00", "7s"))
        got = mct.split_job(issue_job(), forged)
        self.assertEqual(got["semaphore"], 300.0)
        only_forged = issue_log()
        only_forged.insert(-1, sem_line("22:50:00", "7s"))
        got = mct.split_job(issue_job(), only_forged)
        self.assertIsNone(got["semaphore"])
        self.assertEqual(got["wait_absent"]["semaphore"], R_NO_LINE)

    def test_line_before_the_step_window_is_another_steps_line(self):
        earlier = issue_log(sem_line("21:50:00", "7s"))
        got = mct.split_job(issue_job(), earlier)
        self.assertIsNone(got["semaphore"])
        self.assertEqual(got["wait_absent"]["semaphore"], R_NO_LINE)


class SemaphoreRefusedTests(unittest.TestCase):
    def test_two_semaphore_lines_are_refused_not_summed(self):
        # decision: refuse over sum because a second line is either a second command in the step or quoted text, and a
        # sum would count it as wait either way; the exact reason names the case.
        got = mct.split_job(issue_job(), issue_log(sem_line("22:05:01"), sem_line("22:06:00", "40s")))
        self.assertIsNone(got["semaphore"])
        self.assertEqual(got["wait_absent"]["semaphore"], R_MULTIPLE)
        self.assertIsNone(got["test"])
        self.assertIn(f"test:{R_MULTIPLE}", got["unmeasured"])

    def test_wait_larger_than_the_step_is_refused(self):
        got = mct.split_job(issue_job(), issue_log(sem_line("22:05:01", "9000s")))
        self.assertIsNone(got["semaphore"])
        self.assertEqual(got["wait_absent"]["semaphore"], R_WAIT_LONGER)
        self.assertIsNone(got["test"])
        self.assertIn(f"test:{R_WAIT_LONGER}", got["unmeasured"])

    def test_compile_plus_wait_larger_than_the_step_is_refused(self):
        # step 6867 s, compile 2081 s, wait 5000 s: each fits the step alone, together they do not.
        got = mct.split_job(issue_job(), issue_log(sem_line("22:05:01", "5000s")))
        self.assertIsNone(got["semaphore"])
        self.assertEqual(got["wait_absent"]["semaphore"], R_OVERLAP)
        self.assertIsNone(got["test"])
        self.assertIn(f"test:{R_OVERLAP}", got["unmeasured"])

    def test_malformed_numbers_are_refused_with_one_reason(self):
        cases = ("abcs", "-5s", "1.5s", "5", "s", "12xs", "1,000s", "0x10s", "١٢s", "9" * DIGITS_FLOOD + "s")
        for wait_text in cases:
            with self.subTest(wait_text[:20]):
                got = mct.split_job(issue_job(), issue_log(sem_line("22:05:01", wait_text)))
                self.assertIsNone(got["semaphore"])
                self.assertEqual(got["wait_absent"]["semaphore"], R_MALFORMED)
                self.assertIsNone(got["test"])
                self.assertIn(f"test:{R_MALFORMED}", got["unmeasured"])

    def test_no_absent_wait_is_ever_a_number(self):
        logs = (None, [], issue_log(), issue_log(sem_line("22:05:01"), sem_line("22:06:00")),
                issue_log(sem_line("22:05:01", "x")), issue_log(sem_line("22:05:01", "9000s")))
        for log in logs:
            got = mct.split_job(issue_job(), log)
            self.assertIn("semaphore", got["wait_absent"])
            self.assertIsNone(got["semaphore"])

    def test_parse_function_raises_with_the_reason(self):
        window = (mct.parse_ts(stamp("22:00:01")), mct.parse_ts(stamp("23:54:28")), mct.parse_ts(stamp("22:39:43")))
        with self.assertRaises(mct.WaitUnavailable) as ctx:
            mct.parse_semaphore_wait(issue_log(), *window)
        self.assertEqual(ctx.exception.reason, R_NO_LINE)
        self.assertEqual(mct.parse_semaphore_wait(default_log(), *window), 300)


class LoadGateTests(unittest.TestCase):
    def test_step_list_without_the_load_gate_step_is_absent(self):
        got = mct.split_job(issue_job(gate_steps=[]), default_log())
        self.assertIsNone(got["load_gate"])
        self.assertEqual(got["wait_absent"]["load_gate"], R_NO_GATE)
        self.assertEqual(got["semaphore"], 300.0)  # the other figures are unaffected

    def test_load_gate_step_without_timestamps_is_absent(self):
        for changes, reason in (({"started_at": None, "completed_at": None}, R_GATE_NO_TS),
                                ({"completed_at": "not-a-time"}, R_GATE_NO_TS),
                                ({"completed_at": stamp("21:40:00")}, R_GATE_NEGATIVE)):
            with self.subTest(str(changes)):
                step = {"name": mct.LOAD_GATE_STEP_NAME, "started_at": stamp("21:40:01"), "completed_at": stamp("22:00:01")}
                step.update(changes)
                got = mct.split_job(issue_job(gate_steps=[step]), default_log())
                self.assertIsNone(got["load_gate"])
                self.assertEqual(got["wait_absent"]["load_gate"], reason)

    def test_two_load_gate_steps_are_refused_not_summed(self):
        step = {"name": mct.LOAD_GATE_STEP_NAME, "started_at": stamp("21:40:01"), "completed_at": stamp("22:00:01")}
        got = mct.split_job(issue_job(gate_steps=[step, dict(step)]), default_log())
        self.assertIsNone(got["load_gate"])
        self.assertEqual(got["wait_absent"]["load_gate"], R_GATE_MULTIPLE)

    def test_similar_step_names_are_not_the_load_gate(self):
        step = {"name": mct.LOAD_GATE_STEP_NAME + " again", "started_at": stamp("21:40:01"), "completed_at": stamp("22:00:01")}
        got = mct.split_job(issue_job(gate_steps=[step]), default_log())
        self.assertEqual(got["wait_absent"]["load_gate"], R_NO_GATE)

    def test_null_step_name_beside_the_gate_does_not_raise(self):
        nameless = {"name": None, "started_at": stamp("21:39:40"), "completed_at": stamp("21:40:01")}
        step = {"name": mct.LOAD_GATE_STEP_NAME, "started_at": stamp("21:40:01"), "completed_at": stamp("22:00:01")}
        got = mct.split_job(issue_job(gate_steps=[nameless, step]), default_log())
        self.assertEqual(got["load_gate"], 1200.0)

    def test_step_without_a_name_leaves_the_semaphore_absent_with_that_reason(self):
        job = issue_job()
        job["steps"].append({"name": None, "started_at": stamp("23:54:46"), "completed_at": stamp("23:54:46")})
        got = mct.split_job(job, default_log())
        self.assertIsNone(got["semaphore"])
        self.assertEqual(got["wait_absent"]["semaphore"], "missing-step-name")
        self.assertEqual(got["load_gate"], 1200.0)

    def test_job_without_a_combined_step_still_reports_the_gate(self):
        job = issue_job()
        job["steps"] = [s for s in job["steps"] if not s["name"].startswith("Run tests")]
        got = mct.split_job(job, default_log())
        self.assertEqual(got["load_gate"], 1200.0)
        self.assertEqual(got["wait_absent"]["semaphore"], R_NO_LINE)


class BoundTests(unittest.TestCase):
    def test_100k_line_log_is_read_within_the_ceiling(self):
        filler = log_line("22:10:00", "    Compiling serde v1.0.0")
        big = [log_line("22:00:02", "##[group]Run tests"), sem_line("22:05:01")]
        big += [filler] * BIG_LINE_COUNT
        big += [finished_line("22:39:43")] + [log_line("23:00:00", "test a ... ok")] * BIG_LINE_COUNT
        began = time.monotonic()
        got = mct.split_job(issue_job(), big)
        elapsed = time.monotonic() - began
        self.assertEqual(got["semaphore"], 300.0)
        self.assertEqual(got["test"], 4486.0)
        self.assertLess(elapsed, BIG_LOG_SECONDS_CEILING)

    def test_100k_marker_lines_after_finished_are_not_counted(self):
        big = issue_log(sem_line("22:05:01"))
        big[-1:-1] = [sem_line("23:00:00", "1s")] * BIG_LINE_COUNT
        began = time.monotonic()
        got = mct.split_job(issue_job(), big)
        self.assertEqual(got["semaphore"], 300.0)
        self.assertLess(time.monotonic() - began, BIG_LOG_SECONDS_CEILING)


class TableTests(unittest.TestCase):
    def render(self, rows):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            mct.print_table(rows)
        return out.getvalue().splitlines()

    def row(self, log):
        got = mct.split_job(issue_job(), log)
        got.update(workflow="ci.yml", job="Check (linux-fed,enterprise-fed)", kind="self-hosted Linux")
        return got

    def test_existing_columns_keep_their_order_and_the_new_ones_follow(self):
        header = self.render([self.row(default_log())])[0]
        self.assertEqual(header, "workflow | job | runner kind | queue s | setup s | compile s | test s | post s | total s"
                                 " | load gate s | semaphore s")

    def test_present_figures_print_as_numbers(self):
        line = self.render([self.row(default_log())])[1]
        self.assertTrue(line.endswith("| 1200 (1200-1200) n=1 | 300 (300-300) n=1"), line)
        self.assertIn("| 4486 (4486-4486) n=1 |", line)

    def test_absent_figures_print_the_reason_never_zero(self):
        line = self.render([self.row(issue_log())])[1]
        self.assertTrue(line.endswith("| 1200 (1200-1200) n=1 | absent: no-semaphore-line"), line)
        gateless = mct.split_job(issue_job(gate_steps=[]), default_log())
        gateless.update(workflow="ci.yml", job="Check (x)", kind="hosted")
        self.assertIn("| absent: no-load-gate-step | 300 (300-300) n=1", self.render([gateless])[1])

    def test_mixed_rows_name_how_many_are_absent(self):
        line = self.render([self.row(default_log()), self.row(issue_log())])[1]
        self.assertTrue(line.endswith("| 300 (300-300) n=1 (absent in 1 of 2 rows: no-semaphore-line)"), line)

    def test_footer_counts_the_new_refusal_reasons(self):
        rows = [self.row(issue_log(sem_line("22:05:01"), sem_line("22:06:00"))), self.row(issue_log(sem_line("22:05:01", "x")))]
        footer = self.render(rows)[-1]
        self.assertIn(f"{R_MULTIPLE}=1", footer)
        self.assertIn(f"{R_MALFORMED}=1", footer)


if __name__ == "__main__":
    unittest.main()
