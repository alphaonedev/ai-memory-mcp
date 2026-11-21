# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Wait figures of scripts/ci/measure_ci_time.py (#9773): load-gate wait, semaphore wait, compile and test run.

Invariants (PR #9799, issue #9773):
- the four figures are each computed from the state they name and never overlap; a job with no such step or line
  reports the wait as absent with its own reason, never as 0 and never by guessing;
- a figure comes only from a step that ran (conclusion success); a value that was not measured is never a number;
- a semaphore wait is taken only from one physical line (split on the newline only, as the runner wrote it) that has a
  readable stamp and is exactly the form scripts/ci/host_semaphore.py prints, inside the test step and strictly before
  the first cargo `Finished` line;
- reading a log is linear in its size.

The expected reason texts and numbers below are written out here, not read from the script. The semaphore marker and
the load-gate step name are the script's named constants, used by the script and by these tests alike.
"""

import contextlib
import importlib.util
import io
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "measure_ci_time.py"
SCRATCH_ROOT = Path(__file__).resolve().parents[3] / ".local-runs" / "tests-9773"
spec = importlib.util.spec_from_file_location("measure_ci_time_9773", SCRIPT)
mct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mct)

DAY = "2026-11-20"
BIG_LINE_COUNT = 150_000  # over 100K lines
BIG_LOG_SECONDS_CEILING = 5.0
DIGITS_FLOOD = 5000  # more digits than int() accepts by default
LONG_LINE_CHARS = 200_000  # the size at which the head of the PR took 7.374 s (code verdict F3, security finding 2)
LONG_LINE_SECONDS_CEILING = 0.5  # a linear read of one 200K-character line takes milliseconds
LONG_LINE_RATIO_LIMIT = 3.0  # doubling the line may not more than triple the time
LONG_LINE_RATIO_FLOOR_SECONDS = 0.05  # below this a timing is noise and the ratio is not judged
LABEL_MAX = 256  # longest label host_semaphore.py prints in a semaphore line
SEMAPHORE_LINE_CAP = 8192  # a longer line is never read as the semaphore line (finding N1, mutant G02)
LINE_MATCH_CAP = 4096  # a longer line is not matched against the Finished and test result patterns
CAP_LINE_COUNT = 150_000  # lines of exactly LINE_MATCH_CAP characters (finding N4)
# Every character str.splitlines() ends a line on besides "\n", written out (not computed): CR, VT, FF, FS, GS, RS, NEL,
# LINE SEPARATOR, PARAGRAPH SEPARATOR.
LINE_TERMINATORS = ("\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " ")
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
R_GATE_SKIPPED = "load-gate-skipped"
R_GATE_NOT_SUCCESS = "load-gate-not-success"
R_GATE_NO_CONCLUSION = "load-gate-no-conclusion"
R_SEM_NO_TS = "semaphore-line-no-timestamp"
R_NO_TEST_STEP = "no-test-step"
R_STEP_SKIPPED = "step-skipped"
R_STEP_NOT_SUCCESS = "step-not-success"
R_STEP_NO_CONCLUSION = "step-no-conclusion"
R_MISSING_TS = "missing-timestamp"
R_COMPILE_LONGER = "compile-longer-than-step"
R_MISSING_NAME = "missing-step-name"
R_NEGATIVE = "negative"
# Every reason a wait column can print as `absent: <reason>`, written out (not taken from the script).
WAIT_ABSENT_EXPECTED = (R_NO_LINE, R_NO_LOG, R_EMPTY_LOG, R_MALFORMED, R_MULTIPLE, R_WAIT_LONGER, R_OVERLAP, R_NO_GATE,
                        R_GATE_NO_TS, R_GATE_NEGATIVE, R_GATE_MULTIPLE, R_GATE_SKIPPED, R_GATE_NOT_SUCCESS,
                        R_GATE_NO_CONCLUSION, R_SEM_NO_TS, R_NO_TEST_STEP, R_STEP_SKIPPED, R_STEP_NOT_SUCCESS,
                        R_STEP_NO_CONCLUSION, R_MISSING_TS, R_NEGATIVE, R_MISSING_NAME)
# Every reason the docstring must name: the absent ones and the one that only leaves compile and test unmeasured.
ALL_REASONS = (*WAIT_ABSENT_EXPECTED, R_COMPILE_LONGER)
# The documented limit of the strict parser (finding N2), written out.
LIMIT_TEXT = "prints the whole exact line itself"
NO_FINISHED_DECISION = "a step whose log holds no `Finished` line reads every exact-form line inside the step"


def stamp(clock):
    return f"{DAY}T{clock}Z"


def log_line(clock, text):
    return f"{DAY}T{clock}.0000000Z {text}"


def sem_body(wait_text="300s", prefix="##[notice]", label="T"):
    """The text host_semaphore.py prints after the runner's stamp, written out here."""
    return f"{prefix}{mct.SEMAPHORE_MARKER} '{label}': slot 1 of 2 acquired after {wait_text} (load=26.90 cores=14)"


def sem_line(clock, wait_text="300s", prefix="##[notice]", label="T"):
    return log_line(clock, sem_body(wait_text, prefix, label))


def finished_line(clock, took="34m 41s"):
    return log_line(clock, f"    Finished `test` profile [unoptimized] target(s) in {took}")


def stamped(clock_fraction, text):
    """A log line stamped with the given time of day, whole seconds or with a fraction of any length."""
    return f"{DAY}T{clock_fraction}Z {text}"


def at_line_length(prefix, total):
    """The prefix padded with blanks and one trailing x so that the line is exactly total characters long."""
    return prefix + " " * (total - len(prefix) - 1) + "x"


def step(name, start, end, conclusion="success"):
    row = {"name": name, "started_at": stamp(start), "completed_at": stamp(end)}
    if conclusion is not None:
        row["conclusion"] = conclusion
    return row


def issue_job(gate_steps=None, main_start="22:00:01", main_end="23:54:28", main_conclusion="success", before=(),
              after=()):
    """The shape of job 136556334572 (issue 9773): load gate 1200 s, test step 6867 s."""
    gate = gate_steps if gate_steps is not None else [step(mct.LOAD_GATE_STEP_NAME, "21:40:01", "22:00:01")]
    return {
        "created_at": stamp("21:39:29"),
        "started_at": stamp("21:39:29"),
        "completed_at": stamp("23:54:46"),
        "steps": [
            step("Set up job", "21:39:29", "21:39:40"),
            *before,
            *gate,
            step("Run tests (impact-aware)", main_start, main_end, main_conclusion),
            step("Post Run actions/checkout", main_end, "23:54:46"),
            *after,
        ],
    }


def issue_log(*middle):
    return [log_line("22:00:02", "##[group]Run tests"), *middle,
            finished_line("22:39:43"), log_line("23:54:00", "test result: ok. 1 passed; finished in 1.00s")]


def default_log():
    return issue_log(sem_line("22:05:01"))


def no_finished_log(*lines):
    return [log_line("22:00:02", "##[group]Run tests"), *lines, log_line("23:54:00", "test result: ok. 1 passed; finished in 1.00s")]


def figures(job, log):
    got = mct.split_job(job, log)
    return got["semaphore"], got["wait_absent"].get("semaphore")


def fetch_text(raw):
    """Lines that fetch_log_lines returns for a downloaded log of these bytes (the gh call is replaced)."""
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)

    def fake_run(argv, **kwargs):
        kwargs["stdout"].write(raw)
        return SimpleNamespace(returncode=0, stderr=b"")

    with mock.patch.object(mct.subprocess, "run", fake_run):
        lines, err = mct.fetch_log_lines("o/r", 1, SCRATCH_ROOT)
    assert err is None, err
    return lines


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
        self.assertEqual(got["setup"], 1211.0)
        self.assertEqual(got["post"], 18.0)
        self.assertEqual(got["wait_absent"], {})
        self.assertEqual(got["unmeasured"], [])

    def test_semaphore_compile_and_test_run_do_not_overlap(self):
        got = mct.split_job(issue_job(), default_log())
        self.assertEqual(got["semaphore"] + got["compile"] + got["test"], got["combined_wall"])

    def test_ansi_colour_in_every_place_does_not_hide_the_line(self):
        # the colour codes sit before the notice prefix, inside it, and after the line; each form is 300 s only when the
        # codes are removed before the line is read.
        forms = ("\x1b[36m##[notice]", "\x1b[36m", "##[notice]\x1b[0m")
        for prefix in forms:
            with self.subTest(prefix=prefix):
                got = mct.split_job(issue_job(), issue_log(sem_line("22:05:01", prefix=prefix)))
                self.assertEqual(got["semaphore"], 300.0)
        tail = issue_log(log_line("22:05:01", sem_body() + "\x1b[0m"))
        self.assertEqual(mct.split_job(issue_job(), tail)["semaphore"], 300.0)
        inside = issue_log(log_line("22:05:01", sem_body().replace("acquired after 300s", "acquired after \x1b[1m300s\x1b[0m")))
        self.assertEqual(mct.split_job(issue_job(), inside)["semaphore"], 300.0)

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
        cases = ("abcs", "-5s", "1.5s", "5", "s", "12xs", "1,000s", "0x10s", "١٢s", "9" * DIGITS_FLOOD + "s",
                 "300sec", "300 s", "300s.", "+300s", "1234567890s", "9" * 19 + "s", "300m", "5m 0s")
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


class StrictLineTests(unittest.TestCase):
    """Class A: the semaphore line is read strictly (one physical line, readable stamp, exact form, inside the step,
    strictly before the first Finished line). Each row is (name, middle lines, expected semaphore, expected reason)."""

    def run_rows(self, rows, **job):
        for name, middle, expected_wait, expected_reason in rows:
            with self.subTest(name):
                self.assertEqual(figures(issue_job(**job), issue_log(*middle)), (expected_wait, expected_reason))

    def test_form_table_before_finished(self):
        real = sem_line("22:05:01")
        forged_wait = sem_body("900s")
        rows = (
            ("real line alone", [real], 300.0, None),
            ("quoted source line with the marker", [log_line("22:10:00", "   | " + forged_wait)], None, R_NO_LINE),
            ("build-script warning with the marker", [log_line("22:10:00", "warning: pkg@1.0.0: " + forged_wait)], None, R_NO_LINE),
            ("marker after text on the same line", [log_line("22:10:00", "x " + forged_wait)], None, R_NO_LINE),
            ("quoted line beside the real line", [real, log_line("22:10:00", "   | " + forged_wait)], 300.0, None),
            ("warning beside the real line", [real, log_line("22:10:00", "warning: pkg@1.0.0: " + forged_wait)], 300.0, None),
            ("other annotation level is not the wrapper's notice", [log_line("22:05:01", sem_body(prefix="##[warning]"))], None, R_NO_LINE),
            ("no notice prefix at all", [log_line("22:05:01", sem_body(prefix=""))], 300.0, None),
            ("line stamped the same instant as Finished", [sem_line("22:39:43")], None, R_NO_LINE),
            ("line one tick before Finished", [f"{DAY}T22:39:42.9999999Z " + sem_body()], 300.0, None),
            ("line one tick after Finished", [f"{DAY}T22:39:43.0000001Z " + sem_body()], None, R_NO_LINE),
            ("label with a slash", [sem_line("22:05:01", label="linux-fed/enterprise-fed")], 300.0, None),
            ("empty label", [sem_line("22:05:01", label="")], 300.0, None),
            ("longest label", [sem_line("22:05:01", label="a" * LABEL_MAX)], 300.0, None),
            ("label one over the cap", [sem_line("22:05:01", label="a" * (LABEL_MAX + 1))], None, R_MALFORMED),
            ("label holding a quote", [sem_line("22:05:01", label="it's")], None, R_MALFORMED),
            ("acquired-after text with no space before it", [log_line("22:05:01", sem_body().replace(" acquired after ", "_acquired after "))], None, R_NO_LINE),
            ("two acquired-after in one line", [log_line("22:05:01", sem_body("7s") + " acquired after 9s (load=1.00 cores=2)")], None, R_MALFORMED),
            ("text after the closing parenthesis", [log_line("22:05:01", sem_body() + " extra")], None, R_MALFORMED),
            ("slot field not a number", [log_line("22:05:01", sem_body().replace("slot 1 of 2", "slot x of 2"))], None, R_MALFORMED),
            ("load field not a number", [log_line("22:05:01", sem_body().replace("load=26.90", "load=high"))], None, R_MALFORMED),
            ("slot total not a number", [log_line("22:05:01", sem_body().replace("slot 1 of 2", "slot 1 of many"))], None, R_MALFORMED),
            ("cores not a number", [log_line("22:05:01", sem_body().replace("cores=14", "cores=abc"))], None, R_MALFORMED),
            ("doubled notice prefix", [log_line("22:05:01", sem_body(prefix="##[notice]##[notice]"))], None, R_NO_LINE),
            ("a line of one word with no stamp", ["oneword"], None, R_NO_LINE),
            ("line of exactly the 8192 cap is read (and is malformed)",
             [at_line_length(log_line("22:05:01", sem_body()), SEMAPHORE_LINE_CAP)], None, R_MALFORMED),
            ("line one over the 8192 cap is never read",
             [at_line_length(log_line("22:05:01", sem_body()), SEMAPHORE_LINE_CAP + 1)], None, R_NO_LINE),
            # the documented limit (finding N2): the line is produced inside the job and no trusted side channel exists.
            ("whole exact line printed by a build-time program, no real line", [log_line("22:10:00", sem_body("7s"))], 7.0, None),
            ("whole exact line printed by a build-time program, beside the real line",
             [real, log_line("22:10:00", sem_body("7s"))], None, R_MULTIPLE),
        )
        self.run_rows(rows)

    def test_stamp_fraction_is_compared_exactly_with_the_finished_stamp(self):
        # (semaphore stamp, Finished stamp, expected wait, expected reason); both stamps are in the same second.
        rows = (
            ("22:39:43.1000000", "22:39:43.9000000", 300.0, None),
            ("22:39:43.9000000", "22:39:43.1000000", None, R_NO_LINE),
            ("22:39:43.4", "22:39:43.45", 300.0, None),
            ("22:39:43.5", "22:39:43.45", None, R_NO_LINE),
            ("22:39:43", "22:39:43.0000001", 300.0, None),
            ("22:39:43.0000001", "22:39:43", None, R_NO_LINE),
            ("22:39:43", "22:39:43", None, R_NO_LINE),
        )
        for sem_at, finished_at, expected_wait, expected_reason in rows:
            with self.subTest(f"{sem_at} before {finished_at}"):
                log = [log_line("22:00:02", "##[group]Run tests"), stamped(sem_at, sem_body()),
                       stamped(finished_at, "    Finished `test` profile [unoptimized] target(s) in 34m 41s"),
                       log_line("23:54:00", "test result: ok. 1 passed; finished in 1.00s")]
                self.assertEqual(figures(issue_job(), log), (expected_wait, expected_reason))

    def test_unreadable_stamp_is_its_own_reason(self):
        body = sem_body()
        rows = (
            ("no stamp at all", [body], None, R_SEM_NO_TS),
            ("stamp cut inside the time", [f"{DAY}T22:0 " + body], None, R_SEM_NO_TS),
            ("stamp without the zone letter", [f"{DAY}T22:05:01.0000000 " + body], None, R_SEM_NO_TS),
            ("byte order mark before the stamp", ["﻿" + log_line("22:05:01", body)], None, R_SEM_NO_TS),
            ("stamp shaped right but month 13", [f"2026-13-20T22:05:01.0000000Z " + body], None, R_SEM_NO_TS),
            ("unreadable stamp beside the real line", [log_line("22:05:01", body), body], None, R_SEM_NO_TS),
            ("non-ASCII digits in the stamp year", ["٢٠٢٦-11-20T22:05:01.0000000Z " + body], None, R_SEM_NO_TS),
        )
        self.run_rows(rows)
        got = mct.split_job(issue_job(), issue_log(body))
        self.assertIsNone(got["test"])  # the wait cannot be taken out of the test run
        self.assertEqual(got["unmeasured"], [f"test:{R_SEM_NO_TS}"])

    def test_step_window_boundaries_are_pinned(self):
        # the step starts 22:00:01 and ends 23:54:28; a log stamp may sit one second outside it (second granularity).
        rows = (
            ("one second before the step start", [sem_line("22:00:00")], 300.0, None),
            ("two seconds before the step start", [sem_line("21:59:59")], None, R_NO_LINE),
        )
        self.run_rows(rows)
        end_rows = (
            ("one second after the step end", [sem_line("23:54:29")], 300.0, None),
            ("two seconds after the step end", [sem_line("23:54:30")], None, R_NO_LINE),
        )
        for name, middle, expected_wait, expected_reason in end_rows:
            with self.subTest(name):
                got = figures(issue_job(), no_finished_log(*middle))
                self.assertEqual(got, (expected_wait, expected_reason))

    def test_wall_and_compile_boundaries_are_pinned(self):
        # step 6867 s, compile 2081 s.
        got = mct.split_job(issue_job(), issue_log(sem_line("22:05:01", "4786s")))
        self.assertEqual((got["semaphore"], got["test"]), (4786.0, 0.0))  # compile + wait == wall is measured
        got = mct.split_job(issue_job(), issue_log(sem_line("22:05:01", "4787s")))
        self.assertEqual((got["semaphore"], got["wait_absent"]["semaphore"]), (None, R_OVERLAP))
        got = mct.split_job(issue_job(), issue_log(sem_line("22:05:01", "6867s")))
        self.assertEqual(got["wait_absent"]["semaphore"], R_OVERLAP)  # wait == wall: it fits the step alone, not with compile
        got = mct.split_job(issue_job(), issue_log(sem_line("22:05:01", "6868s")))
        self.assertEqual(got["wait_absent"]["semaphore"], R_WAIT_LONGER)
        got = mct.split_job(issue_job(), no_finished_log(sem_line("22:05:01", "6867s")))
        self.assertEqual((got["semaphore"], got["compile"], got["test"]), (6867.0, None, None))  # wait == wall, no compile
        got = mct.split_job(issue_job(), no_finished_log(sem_line("22:05:01", "6868s")))
        self.assertEqual(got["wait_absent"]["semaphore"], R_WAIT_LONGER)

    def test_compile_longer_than_the_step_keeps_the_wait_and_flags_compile_and_test(self):
        long_compile = [log_line("22:00:02", "##[group]Run tests"), sem_line("22:05:01"),
                        finished_line("22:39:43", took="200m 0s")]
        got = mct.split_job(issue_job(), long_compile)
        self.assertEqual(got["semaphore"], 300.0)
        self.assertEqual(got["wait_absent"], {})
        self.assertEqual((got["compile"], got["test"]), (None, None))
        self.assertEqual(got["unmeasured"], [f"compile:{R_COMPILE_LONGER}", f"test:{R_COMPILE_LONGER}"])

    def test_step_without_finished_line_decision_is_pinned(self):
        # decision (base behaviour, issue 9809 is not changed here): a step whose log holds no `Finished` line reads every
        # exact-form line inside the step, because nothing separates the wrapper's line from a test's output there.
        got = mct.split_job(issue_job(), no_finished_log(sem_line("22:05:01")))
        self.assertEqual((got["semaphore"], got["compile"], got["test"]), (300.0, None, None))
        self.assertEqual((got["wait_absent"], got["unmeasured"]), ({}, []))
        # an exact-form copy printed by a test is read as the wait there (the documented residual of that decision) ...
        self.assertEqual(figures(issue_job(), no_finished_log(sem_line("22:50:00", "7s"))), (7.0, None))
        # ... while two exact lines are refused and leave test unmeasured, as with a Finished line.
        got = mct.split_job(issue_job(), no_finished_log(sem_line("22:05:01"), sem_line("22:50:00", "7s")))
        self.assertEqual(got["wait_absent"]["semaphore"], R_MULTIPLE)
        self.assertEqual(got["unmeasured"], [f"test:{R_MULTIPLE}"])
        # a form that is not exact is never read, with or without a Finished line.
        quoted = no_finished_log(log_line("22:50:00", "   | " + sem_body("7s")))
        self.assertEqual(figures(issue_job(), quoted), (None, R_NO_LINE))

    def test_wall_unmeasured_leaves_the_semaphore_absent_with_that_reason(self):
        job = issue_job()
        job["steps"][-2] = {"name": "Run tests (impact-aware)", "started_at": stamp("22:00:01"), "conclusion": "success"}
        got = mct.split_job(job, default_log())
        self.assertEqual((got["semaphore"], got["wait_absent"]["semaphore"]), (None, R_MISSING_TS))
        extra = issue_job(before=[{"name": "Build release (once leg)", "started_at": None, "completed_at": None, "conclusion": "success"}])
        got = mct.split_job(extra, default_log())
        self.assertEqual((got["semaphore"], got["wait_absent"]["semaphore"]), (None, R_MISSING_TS))


class ForgedTerminatorTests(unittest.TestCase):
    """Security finding 1: the log is split on the newline only, so a line splitter inside test output cannot start a
    second line. Every row goes through fetch_log_lines (the gh call is replaced), not a hand-built list."""

    def forged_log(self, terminator, real_line):
        lines = issue_log(*([sem_line("22:05:01")] if real_line else []))
        forged = log_line("22:40:00", "output" + terminator + log_line("22:10:00", sem_body("900s")))
        lines.insert(-1, forged)
        return lines

    def test_forged_line_behind_every_terminator_is_not_a_second_line(self):
        for terminator in LINE_TERMINATORS:
            for real_line, expected in ((True, (300.0, None)), (False, (None, R_NO_LINE))):
                with self.subTest(terminator=repr(terminator), real_line=real_line):
                    raw = "\n".join(self.forged_log(terminator, real_line)).encode("utf-8")
                    self.assertEqual(figures(issue_job(), fetch_text(raw)), expected)

    def test_forged_line_before_finished_behind_every_terminator_is_not_a_second_line(self):
        for terminator in LINE_TERMINATORS:
            with self.subTest(terminator=repr(terminator)):
                lines = issue_log(sem_line("22:05:01"), log_line("22:10:00", "output" + terminator + log_line("22:10:01", sem_body("900s"))))
                raw = "\n".join(lines).encode("utf-8")
                self.assertEqual(figures(issue_job(), fetch_text(raw)), (300.0, None))

    def test_carriage_return_line_endings_are_dropped_once(self):
        raw = "\r\n".join(default_log()).encode("utf-8") + b"\r\n"
        self.assertEqual(figures(issue_job(), fetch_text(raw)), (300.0, None))

    def test_line_splitting_rule_of_fetch_log_lines(self):
        self.assertEqual(fetch_text(b"a\nb\n"), ["a", "b"])
        self.assertEqual(fetch_text(b"a\r\nb"), ["a", "b"])
        self.assertEqual(fetch_text(b"a\r\r\nb\n"), ["a\r", "b"])
        self.assertEqual(fetch_text("a b\x85c\x0cd\ne\n".encode("utf-8")), ["a b\x85c\x0cd", "e"])
        self.assertEqual(fetch_text(b"x\n\ny\n"), ["x", "", "y"])
        self.assertEqual(fetch_text(b""), [])
        self.assertEqual(fetch_text(b"a\xff\xfeb\n"), ["a��b"])  # bad UTF-8 is replaced, not raised


class LongLineTests(unittest.TestCase):
    """Class B: reading one long line is linear (200K characters of repeated marker took 7.374 s at the head)."""

    def timed(self, call):
        began = time.monotonic()
        call()
        return time.monotonic() - began

    def assert_linear(self, name, make_call):
        short = self.timed(make_call(LONG_LINE_CHARS))
        self.assertLess(short, LONG_LINE_SECONDS_CEILING, f"{name}: {LONG_LINE_CHARS} chars took {short:.3f}s")
        double = self.timed(make_call(2 * LONG_LINE_CHARS))
        self.assertLess(double, LONG_LINE_SECONDS_CEILING * 2, f"{name}: {2 * LONG_LINE_CHARS} chars took {double:.3f}s")
        self.assertLess(double, LONG_LINE_RATIO_LIMIT * max(short, LONG_LINE_RATIO_FLOOR_SECONDS), f"{name}: {short:.3f}s then {double:.3f}s")

    def test_semaphore_line_scan_is_linear_on_repeated_markers(self):
        unit = mct.SEMAPHORE_MARKER + " "
        for label, text in (("marker", unit), ("marker and acquired", unit + "acquired after "), ("notice and marker", "##[notice]" + unit)):
            def make_call(chars, text=text):
                big = log_line("22:10:00", text * (chars // len(text)))
                return lambda: self.assertEqual(figures(issue_job(), issue_log(sem_line("22:05:01"), big)), (300.0, None))
            with self.subTest(label):
                self.assert_linear(label, make_call)

    def test_finished_line_scan_is_linear_on_repeated_finished_text(self):
        unit = "Finished `a` profile "

        def make_call(chars):
            line = log_line("22:10:00", unit * (chars // len(unit)))
            return lambda: self.assertIsNone(mct.first_finished([line]))
        self.assert_linear("finished", make_call)

    def test_bench_compile_log_scan_is_linear_on_repeated_finished_text(self):
        unit = "Finished `a` profile "
        SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)

        def make_call(chars):
            def call():
                with tempfile.TemporaryDirectory(dir=SCRATCH_ROOT) as tmp:
                    for name in mct.BENCH_FILES:
                        body = unit * (chars // len(unit)) if name == mct.BENCH_COMPILE else "x"
                        (Path(tmp) / name).write_text(body + "\n", encoding="utf-8")
                    mct.bench_report(Path(tmp), 0.0)
            return call
        self.assert_linear("bench compile log", make_call)

    def test_rank_binaries_scan_is_linear_on_repeated_result_text(self):
        unit = "test result: ok. 1 passed; "

        def make_call(chars):
            lines = [log_line("22:10:00", "Running x"), log_line("22:10:01", unit * (chars // len(unit)))]
            return lambda: self.assertEqual(mct.rank_binaries(lines), [])
        self.assert_linear("rank_binaries", make_call)


class CapLengthLineTests(unittest.TestCase):
    """Class B: a log of 100K+ lines, each as long as the match cap and full of the pattern's own text, is read in
    linear time (150K such lines took 76.88 s at the previous head: one pass from every start in the line)."""

    def capped(self, unit):
        return (unit * (LINE_MATCH_CAP // len(unit) + 1))[:LINE_MATCH_CAP]

    def timed_under_ceiling(self, name, call):
        began = time.monotonic()
        result = call()
        elapsed = time.monotonic() - began
        self.assertLess(elapsed, BIG_LOG_SECONDS_CEILING, f"{name}: {CAP_LINE_COUNT} lines took {elapsed:.2f}s")
        return result

    def test_150k_lines_at_the_cap_length_are_read_within_the_ceiling(self):
        finished = [self.capped("Finished `a` profile ")] * CAP_LINE_COUNT
        self.assertEqual(len(finished[0]), LINE_MATCH_CAP)
        self.assertIsNone(self.timed_under_ceiling("first_finished", lambda: mct.first_finished(finished)))
        results = [self.capped("test result: ok. 1 passed; ")] * CAP_LINE_COUNT
        self.assertEqual(self.timed_under_ceiling("rank_binaries", lambda: mct.rank_binaries(["Running x"] + results)), [])

    def test_real_finished_and_result_lines_are_still_read(self):
        # the linear form reads the same lines the search did: one Finished line, one result line, text in front of both.
        text = "    Finished `test` profile [unoptimized] target(s) in 34m 41s"
        self.assertEqual(mct.first_finished([log_line("22:39:43", text)])[1], 2081.0)
        rows = [log_line("22:10:00", "Running unittests src/lib.rs"),
                log_line("22:10:01", "test result: ok. 3 passed; 0 failed; finished in 4.50s")]
        self.assertEqual(mct.rank_binaries(rows), [(4.5, 3, "src/lib.rs")])

    def test_the_anchor_is_the_whole_literal_not_its_first_word(self):
        # a first "Finished" with no backtick, or a first "test result:" with no space, is not the anchor: the
        # literal is "Finished `" and "test result: " (finding N4), so the real text after it is still read.
        text = "Finished building; Finished `test` profile [unoptimized] target(s) in 5s"
        self.assertEqual(mct.first_finished([log_line("22:39:43", text)])[1], 5.0)
        rows = [log_line("22:10:00", "Running unittests src/lib.rs"),
                log_line("22:10:01", "test result:ok test result: ok. 3 passed; 0 failed; finished in 2.50s")]
        self.assertEqual(mct.rank_binaries(rows), [(2.5, 3, "src/lib.rs")])


class BranchPinTests(unittest.TestCase):
    """Class D (finding N1): one row per remaining branch of step_secs, sum_steps, parse_ts, duration and first_finished."""

    FINISHED_TEXT = "    Finished `test` profile [unoptimized] target(s) in 34m 41s"

    def test_sum_steps_names_the_first_unmeasured_step_whatever_the_order(self):
        ok = step("a", "10:00:00", "10:00:05")
        failed = step("b", "10:00:05", "10:00:06", "failure")
        no_conclusion = step("c", "10:00:06", "10:00:07", None)
        self.assertEqual(mct.sum_steps([ok, failed, no_conclusion]), (None, R_STEP_NOT_SUCCESS))
        self.assertEqual(mct.sum_steps([ok, no_conclusion, failed]), (None, R_STEP_NO_CONCLUSION))
        self.assertEqual(mct.sum_steps([ok, step("s", "10:00:06", "10:00:07", "skipped"), ok]), (10.0, None))

    def test_fractions_of_a_second_and_a_zero_length_step_are_measured(self):
        fractional = {"conclusion": "success", "started_at": f"{DAY}T10:00:00.250Z", "completed_at": f"{DAY}T10:00:01.750Z"}
        self.assertEqual(mct.step_secs(fractional), (1.5, None))
        self.assertEqual(mct.duration(stamp("10:00:00"), stamp("10:00:00")), (0.0, None))
        self.assertEqual(mct.duration(stamp("10:00:01"), stamp("10:00:00")), (None, R_NEGATIVE))
        gate = issue_job(gate_steps=[step(mct.LOAD_GATE_STEP_NAME, "21:40:01", "21:40:01")])
        self.assertEqual(mct.split_job(gate, default_log())["load_gate"], 0.0)

    def test_first_finished_reads_a_coloured_line_and_the_cap_boundary(self):
        coloured = log_line("22:39:43", "\x1b[32m    Finished\x1b[0m `test` profile [unoptimized] target(s) in 34m 41s")
        self.assertEqual(mct.first_finished([coloured])[1], 2081.0)  # colour codes are stripped before the match
        painted = log_line("22:39:43", "\x1b[1m" + self.FINISHED_TEXT + "\x1b[0m")
        self.assertEqual(mct.first_finished([painted])[1], 2081.0)
        base = log_line("22:39:43", self.FINISHED_TEXT)
        at_cap = base.replace("    Finished", " " * (LINE_MATCH_CAP - len(base)) + "    Finished", 1)
        self.assertEqual(len(at_cap), LINE_MATCH_CAP)
        self.assertEqual(mct.first_finished([at_cap])[1], 2081.0)
        over = at_cap.replace("    Finished", " " + "    Finished", 1)
        self.assertEqual(len(over), LINE_MATCH_CAP + 1)
        self.assertIsNone(mct.first_finished([over]))

    def test_first_finished_needs_a_stamp_and_a_time_inside_the_window(self):
        self.assertIsNone(mct.first_finished([self.FINISHED_TEXT]))  # no stamp
        inside = log_line("22:39:43", self.FINISHED_TEXT)
        start = mct.log_line_time(log_line("22:39:00", "x"))
        end = mct.log_line_time(log_line("22:40:00", "x"))
        self.assertEqual(mct.first_finished([inside], start, end)[1], 2081.0)
        before = log_line("22:30:00", self.FINISHED_TEXT)
        after = log_line("22:50:00", self.FINISHED_TEXT)
        self.assertEqual(mct.first_finished([before, after, inside], start, end)[0], mct.log_line_time(inside))


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
                gate = step(mct.LOAD_GATE_STEP_NAME, "21:40:01", "22:00:01")
                gate.update(changes)
                got = mct.split_job(issue_job(gate_steps=[gate]), default_log())
                self.assertIsNone(got["load_gate"])
                self.assertEqual(got["wait_absent"]["load_gate"], reason)

    def test_two_load_gate_steps_are_refused_not_summed(self):
        gate = step(mct.LOAD_GATE_STEP_NAME, "21:40:01", "22:00:01")
        got = mct.split_job(issue_job(gate_steps=[gate, dict(gate)]), default_log())
        self.assertIsNone(got["load_gate"])
        self.assertEqual(got["wait_absent"]["load_gate"], R_GATE_MULTIPLE)

    def test_similar_step_names_are_not_the_load_gate(self):
        gate = step(mct.LOAD_GATE_STEP_NAME + " again", "21:40:01", "22:00:01")
        got = mct.split_job(issue_job(gate_steps=[gate]), default_log())
        self.assertEqual(got["wait_absent"]["load_gate"], R_NO_GATE)

    def test_null_step_name_beside_the_gate_does_not_raise(self):
        nameless = {"name": None, "started_at": stamp("21:39:40"), "completed_at": stamp("21:40:01"), "conclusion": "success"}
        gate = step(mct.LOAD_GATE_STEP_NAME, "21:40:01", "22:00:01")
        got = mct.split_job(issue_job(gate_steps=[nameless, gate]), default_log())
        self.assertEqual(got["load_gate"], 1200.0)

    def test_step_without_a_name_leaves_the_semaphore_absent_with_that_reason(self):
        job = issue_job()
        job["steps"].append({"name": None, "started_at": stamp("23:54:46"), "completed_at": stamp("23:54:46"), "conclusion": "success"})
        got = mct.split_job(job, default_log())
        self.assertIsNone(got["semaphore"])
        self.assertEqual(got["wait_absent"]["semaphore"], R_MISSING_NAME)
        self.assertEqual(got["load_gate"], 1200.0)

    def test_job_without_a_test_step_has_its_own_reason_and_still_reports_the_gate(self):
        job = issue_job()
        job["steps"] = [s for s in job["steps"] if not s["name"].startswith("Run tests")]
        got = mct.split_job(job, default_log())
        self.assertEqual(got["load_gate"], 1200.0)
        self.assertIsNone(got["semaphore"])
        self.assertEqual(got["wait_absent"]["semaphore"], R_NO_TEST_STEP)
        self.assertEqual(mct.split_job(job, None)["wait_absent"]["semaphore"], R_NO_TEST_STEP)


class ConclusionTests(unittest.TestCase):
    """Class C: a figure comes only from a step that ran; the conclusion is read at every reader of a step duration."""

    def gate_with(self, conclusion, start="21:40:01", end="22:00:01"):
        return step(mct.LOAD_GATE_STEP_NAME, start, end, conclusion)

    def test_load_gate_conclusion_table(self):
        rows = (
            ("success", 1200.0, None),
            ("skipped", None, R_GATE_SKIPPED),
            ("cancelled", None, R_GATE_NOT_SUCCESS),
            ("failure", None, R_GATE_NOT_SUCCESS),
            ("neutral", None, R_GATE_NOT_SUCCESS),
            (None, None, R_GATE_NO_CONCLUSION),
            ("", None, R_GATE_NO_CONCLUSION),
            (0, None, R_GATE_NO_CONCLUSION),
            ([], None, R_GATE_NO_CONCLUSION),
            (True, None, R_GATE_NO_CONCLUSION),
        )
        for conclusion, expected, reason in rows:
            with self.subTest(str(conclusion)):
                got = mct.split_job(issue_job(gate_steps=[self.gate_with(conclusion)]), default_log())
                self.assertEqual(got["load_gate"], expected)
                self.assertEqual(got["wait_absent"].get("load_gate"), reason)
                self.assertEqual(got["semaphore"], 300.0)  # the other figures are unaffected

    def test_skipped_gate_with_zero_duration_is_not_a_zero(self):
        got = mct.split_job(issue_job(gate_steps=[self.gate_with("skipped", "22:00:01", "22:00:01")]), default_log())
        self.assertIsNone(got["load_gate"])
        self.assertEqual(got["wait_absent"]["load_gate"], R_GATE_SKIPPED)

    def test_cancelled_gate_after_300_seconds_is_not_a_figure(self):
        got = mct.split_job(issue_job(gate_steps=[self.gate_with("cancelled", "21:40:01", "21:45:01")]), default_log())
        self.assertIsNone(got["load_gate"])
        self.assertEqual(got["wait_absent"]["load_gate"], R_GATE_NOT_SUCCESS)

    def test_conclusion_is_read_before_the_timestamps(self):
        gate = self.gate_with("skipped")
        gate["completed_at"] = None
        got = mct.split_job(issue_job(gate_steps=[gate]), default_log())
        self.assertEqual(got["wait_absent"]["load_gate"], R_GATE_SKIPPED)

    def test_test_step_conclusion_table(self):
        rows = (("skipped", R_STEP_SKIPPED), ("cancelled", R_STEP_NOT_SUCCESS), ("failure", R_STEP_NOT_SUCCESS),
                (None, R_STEP_NO_CONCLUSION), ("", R_STEP_NO_CONCLUSION), (0, R_STEP_NO_CONCLUSION),
                ([], R_STEP_NO_CONCLUSION), (True, R_STEP_NO_CONCLUSION), ("SUCCESS", R_STEP_NOT_SUCCESS),
                ("success ", R_STEP_NOT_SUCCESS))
        for conclusion, reason in rows:
            with self.subTest(str(conclusion)):
                got = mct.split_job(issue_job(main_conclusion=conclusion), default_log())
                self.assertEqual((got["compile"], got["test"], got["combined_wall"]), (None, None, None))
                self.assertEqual(got["unmeasured"], [f"compile:{reason}", f"test:{reason}"])
                self.assertEqual((got["semaphore"], got["wait_absent"]["semaphore"]), (None, reason))
                self.assertEqual(got["load_gate"], 1200.0)

    def test_setup_and_post_sums_read_the_conclusion(self):
        # setup is Set up job (11 s) plus the load gate step (1200 s); post is the Post step (18 s).
        got = mct.split_job(issue_job(before=[step("Checkout", "21:39:40", "21:39:41", None)]), default_log())
        self.assertEqual((got["setup"], got["unmeasured"]), (None, [f"setup:{R_STEP_NO_CONCLUSION}"]))
        got = mct.split_job(issue_job(after=[step("Complete job", "23:54:46", "23:54:47", "cancelled")]), default_log())
        self.assertEqual((got["post"], got["unmeasured"]), (None, [f"post:{R_STEP_NOT_SUCCESS}"]))
        got = mct.split_job(issue_job(before=[step("Cache", "21:39:41", "21:39:51", "skipped")],
                                      after=[step("Upload", "23:54:46", "23:55:46", "skipped")]), default_log())
        self.assertEqual((got["setup"], got["post"], got["unmeasured"]), (1211.0, 18.0, []))  # a skipped step took no time

    def test_extra_compile_steps_read_the_conclusion(self):
        built = step("Build release (once leg)", "21:39:41", "21:49:41")  # 600 s
        got = mct.split_job(issue_job(before=[built]), default_log())
        self.assertEqual((got["compile"], got["test"]), (2081.0 + 600.0, 6867.0 - 2081.0 - 300.0))
        skipped = step("Build release (once leg)", "21:39:41", "21:49:41", "skipped")
        got = mct.split_job(issue_job(before=[skipped]), default_log())
        self.assertEqual((got["compile"], got["unmeasured"]), (2081.0, []))
        failed = step("Build release (once leg)", "21:39:41", "21:49:41", "failure")
        got = mct.split_job(issue_job(before=[failed]), default_log())
        self.assertEqual((got["compile"], got["test"]), (None, None))
        self.assertEqual(got["unmeasured"], [f"compile:{R_STEP_NOT_SUCCESS}", f"test:{R_STEP_NOT_SUCCESS}"])
        self.assertEqual(got["wait_absent"]["semaphore"], R_STEP_NOT_SUCCESS)

    def test_skipped_gates_are_left_out_of_the_median_and_of_n(self):
        table = TableTests()
        all_skipped = [table.row(default_log(), gate=self.gate_with("skipped")) for _ in range(3)]
        line = table.render(all_skipped)[1]
        self.assertIn("| absent: load-gate-skipped | 300 (300-300) n=3", line)
        self.assertNotIn("1200 (1200-1200)", line)  # the skipped gate's own timestamps are never a figure
        self.assertNotIn("| 0 (0-0) n=3 | absent", line)  # and never a zero (the queue cell before them is a real 0)
        mixed = [table.row(default_log()), table.row(default_log(), gate=self.gate_with("skipped"))]
        line = table.render(mixed)[1]
        self.assertIn("| 1200 (1200-1200) n=1 (absent in 1 of 2 rows: load-gate-skipped) | 300 (300-300) n=2", line)


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

    def test_100k_marker_lines_before_finished_are_refused_within_the_ceiling(self):
        big = issue_log(sem_line("22:05:01"))
        big[1:1] = [sem_line("22:10:00", "1s")] * BIG_LINE_COUNT
        began = time.monotonic()
        got = mct.split_job(issue_job(), big)
        self.assertEqual((got["semaphore"], got["wait_absent"]["semaphore"]), (None, R_MULTIPLE))
        self.assertLess(time.monotonic() - began, BIG_LOG_SECONDS_CEILING)


class TableTests(unittest.TestCase):
    def render(self, rows):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            mct.print_table(rows)
        return out.getvalue().splitlines()

    def row(self, log, gate=None, **job):
        gates = [gate] if gate is not None else None
        got = mct.split_job(issue_job(gate_steps=gates, **job), log)
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

    def test_footers_are_exact_lines_from_the_rows(self):
        rows = [self.row(default_log()), self.row(issue_log()), self.row(None),
                self.row(issue_log(sem_line("22:05:01"), sem_line("22:06:00")))]
        lines = self.render(rows)
        self.assertEqual(lines[-2], "waits absent: semaphore multiple-semaphore-lines=1, semaphore no-log=1, semaphore no-semaphore-line=1")
        self.assertEqual(lines[-1], "unmeasured: 1 cells in 1 of 4 rows (multiple-semaphore-lines=1)")
        self.assertEqual(len(lines), 4)  # header, one group line, two footers

    def test_waits_absent_counts_every_row_once_and_prints_only_when_a_wait_is_absent(self):
        rows = [self.row(None), self.row(None), self.row(issue_log())]
        self.assertEqual(self.render(rows)[-2], "waits absent: semaphore no-log=2, semaphore no-semaphore-line=1")
        clean = self.render([self.row(default_log())])
        self.assertEqual(clean[-1], "unmeasured: 0 cells in 0 of 1 rows")
        self.assertFalse(any(line.startswith("waits absent:") for line in clean))
        self.assertEqual(len(clean), 3)

    def test_unmeasured_footer_orders_reasons_as_the_script_lists_them(self):
        rows = [self.row(issue_log(sem_line("22:05:01", "5000s"))), self.row(issue_log(sem_line("22:05:01"), sem_line("22:06:00")))]
        self.assertEqual(self.render(rows)[-1],
                         "unmeasured: 2 cells in 2 of 2 rows (multiple-semaphore-lines=1, compile-plus-wait-longer-than-step=1)")

    def test_footer_counts_every_new_unmeasured_reason_exactly(self):
        rows = [self.row(default_log(), main_conclusion="skipped"), self.row(default_log(), main_conclusion=None),
                self.row(issue_log(sem_line("22:05:01", "x")))]
        self.assertEqual(self.render(rows)[-1],
                         "unmeasured: 5 cells in 3 of 3 rows (malformed-semaphore-wait=1, step-skipped=2, step-no-conclusion=2)")


class StoredLogSplitTests(unittest.TestCase):
    def test_stored_log_lines_end_on_newline_only(self):
        forged = "a\x0bb\x0cc d\u0085e\rf"
        self.assertEqual(mct.clean_lines(forged + "\nnext\n"), [forged, "next"])
        self.assertEqual(mct.clean_lines("one\r\ntwo\r\n"), ["one", "two"])


class DocstringTests(unittest.TestCase):
    def test_docstring_names_every_wait_reason_and_the_no_finished_decision(self):
        text = " ".join(mct.__doc__.split())
        for reason in ALL_REASONS:
            with self.subTest(reason):
                self.assertIn(reason, text)
        self.assertIn(NO_FINISHED_DECISION, text)

    def test_docstring_names_the_documented_limit_of_the_strict_parser(self):
        text = " ".join(mct.__doc__.split())
        self.assertIn(LIMIT_TEXT, text)
        self.assertIn("multiple-semaphore-lines", text.split(LIMIT_TEXT, 1)[1])  # and what that program causes beside the real line


class WaitReasonSetTests(unittest.TestCase):
    """Class E: the docstring's list of absent reasons equals the set of reasons the code can print."""

    def reached(self):
        """Run one row per absent reason through split_job; return the set of reasons the rows expect."""
        main_name = "Run tests (impact-aware)"

        def gate(**changes):
            return dict(step(mct.LOAD_GATE_STEP_NAME, "21:40:01", "22:00:01"), **changes)

        def with_main(**changes):
            job = issue_job()
            next(s for s in job["steps"] if s["name"] == main_name).update(changes)
            return job

        nameless = issue_job()
        nameless["steps"].append({"name": None, "started_at": stamp("23:54:46"), "completed_at": stamp("23:54:46"), "conclusion": "success"})
        no_test = issue_job()
        no_test["steps"] = [s for s in no_test["steps"] if s["name"] != main_name]
        rows = (
            (R_NO_GATE, "load_gate", issue_job(gate_steps=[]), default_log()),
            (R_GATE_MULTIPLE, "load_gate", issue_job(gate_steps=[gate(), gate()]), default_log()),
            (R_GATE_NO_TS, "load_gate", issue_job(gate_steps=[gate(completed_at=None)]), default_log()),
            (R_GATE_NEGATIVE, "load_gate", issue_job(gate_steps=[gate(completed_at=stamp("21:40:00"))]), default_log()),
            (R_GATE_SKIPPED, "load_gate", issue_job(gate_steps=[gate(conclusion="skipped")]), default_log()),
            (R_GATE_NOT_SUCCESS, "load_gate", issue_job(gate_steps=[gate(conclusion="failure")]), default_log()),
            (R_GATE_NO_CONCLUSION, "load_gate", issue_job(gate_steps=[gate(conclusion=None)]), default_log()),
            (R_NO_TEST_STEP, "semaphore", no_test, default_log()),
            (R_MISSING_NAME, "semaphore", nameless, default_log()),
            (R_STEP_SKIPPED, "semaphore", with_main(conclusion="skipped"), default_log()),
            (R_STEP_NOT_SUCCESS, "semaphore", with_main(conclusion="failure"), default_log()),
            (R_STEP_NO_CONCLUSION, "semaphore", with_main(conclusion=None), default_log()),
            (R_MISSING_TS, "semaphore", with_main(completed_at=None), default_log()),
            (R_NEGATIVE, "semaphore", with_main(completed_at=stamp("21:00:00")), default_log()),
            (R_NO_LOG, "semaphore", issue_job(), None),
            (R_EMPTY_LOG, "semaphore", issue_job(), []),
            (R_NO_LINE, "semaphore", issue_job(), issue_log()),
            (R_SEM_NO_TS, "semaphore", issue_job(), issue_log(sem_body())),
            (R_MULTIPLE, "semaphore", issue_job(), issue_log(sem_line("22:05:01"), sem_line("22:06:01"))),
            (R_MALFORMED, "semaphore", issue_job(), issue_log(sem_line("22:05:01", "5.0s"))),
            (R_WAIT_LONGER, "semaphore", issue_job(), issue_log(sem_line("22:05:01", "6868s"))),
            (R_OVERLAP, "semaphore", issue_job(), issue_log(sem_line("22:05:01", "4787s"))),
        )
        for reason, column, job, log in rows:
            with self.subTest(reason):
                self.assertEqual(mct.split_job(job, log)["wait_absent"].get(column), reason)
        return {reason for reason, _, _, _ in rows}

    def test_the_constant_is_the_set_the_code_prints_and_the_docstring_names_every_member(self):
        self.assertEqual(self.reached(), set(WAIT_ABSENT_EXPECTED))
        self.assertEqual(len(WAIT_ABSENT_EXPECTED), len(set(WAIT_ABSENT_EXPECTED)))
        self.assertEqual(sorted(mct.WAIT_ABSENT_REASONS), sorted(WAIT_ABSENT_EXPECTED))
        text = " ".join(mct.__doc__.split())
        for reason in mct.WAIT_ABSENT_REASONS:
            with self.subTest(reason):
                self.assertIn(reason, text)

    def test_every_reason_constant_is_listed_and_no_print_site_holds_a_bare_literal(self):
        constants = {name: value for name, value in vars(mct).items() if name.startswith("REASON_") and isinstance(value, str)}
        self.assertEqual(sorted(constants.values()), sorted(ALL_REASONS))
        source = SCRIPT.read_text(encoding="utf-8")
        for reason in ALL_REASONS:
            with self.subTest(reason):
                self.assertEqual(source.count(f'"{reason}"'), 1)  # the one definition; every print site uses the constant

    def test_an_unlisted_reason_is_refused_when_a_wait_is_marked_absent(self):
        with mock.patch.object(mct, "REASON_NO_LOG", "an-unlisted-reason"):
            with self.assertRaises(ValueError):
                mct.split_job(issue_job(), None)


if __name__ == "__main__":
    unittest.main()
