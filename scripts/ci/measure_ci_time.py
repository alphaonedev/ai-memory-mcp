# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Measure where the minutes of a CI test job go (#9710). Read-only.

For the newest green runs of ci.yml and coverage.yml on one branch it reads the
jobs API (`gh api` GET only) and prints, per test job and runner kind, the queue
wait, setup and cache restore, compile, test run, cache save and post steps, and
the total, as median and range over the runs.

Compile and test often share one step (`Run tests`, `Generate coverage JSON`).
The split comes from the job log: the first cargo `Finished ... target(s) in
<duration>` line gives the compile time cargo reported, and the rest of that step
is the test run. A step whose log holds no such line is reported as "not
separable". The log is fetched to a scratch file, parsed here and deleted; no log
text is printed.

Usage:
    python3 -I scripts/ci/measure_ci_time.py --repo OWNER/NAME --branch BRANCH \
        [--runs 10] [--scratch DIR] [--no-logs] [--json-out FILE]
    python3 -I scripts/ci/measure_ci_time.py --repo OWNER/NAME --branch BRANCH --rank-job JOB_ID

`--rank-job` prints the test binaries with the longest `finished in` time from one job log.

Wait figures (#9773, PR #9799). Two waits are reported apart from compile and test, each from the state it names:
`load gate` is the wall time of the step `Load gate (#6795)` from the step list of the jobs API, and `semaphore` is the
`<N>` of the line `[#7914 semaphore] ... acquired after <N>s` that scripts/ci/host_semaphore.py prints before it runs
the cargo command. The four figures load gate, semaphore, compile and test never overlap: for a test step,
test = step wall time - compile - semaphore.

The log is split on the newline only (a downloaded log is read as bytes, split on "\\n", one trailing "\\r" dropped per
line), so a carriage return, form feed, U+2028 or any other line terminator inside a test's output never starts a
second line. A semaphore line is read strictly, with no search: after the runner's stamp and one optional `##[notice]`
the line is exactly `[#7914 semaphore] '<label>': slot <n> of <m> acquired after <N>s (load=<F> cores=<C>)` (the form
host_semaphore.py prints; label at most 256 characters without a quote, numbers ASCII digits, N at most 9 digits).
Text in front of the marker (a quoted source line, a build-script `warning:`), text after the closing parenthesis, a
second `acquired after` and every other number form are not a wait. A line longer than 8192 characters is never
read. The line must carry a readable stamp, lie inside the step and be strictly before the first cargo `Finished`
line (a stamp equal to it is refused; a test that prints the marker runs after `Finished`). Decision: a step whose log
holds no `Finished` line reads every exact-form line inside the step (nothing can be told apart there, so a test that
prints an exact copy of the line is read as the wait; this is the base behaviour of issue 9809 and is unchanged).

Documented limit of the strict form (finding N2, tracked in #8216): the line is produced inside the job and this
script has no trusted side channel to tell the wrapper's line from a line with the same text that a build-time program
(a build script, a proc macro) prints before the first `Finished` line, since both carry the runner's stamp. A program
that prints the whole exact line itself, with no real line in the step, is read as the wait; next to the real line it
makes two lines, which are refused as multiple-semaphore-lines. A test's own output after `Finished` is never read.

A wait that cannot be read is `absent` with its own reason (a column cell `absent: <reason>`, never 0). The reasons
are the members of WAIT_ABSENT_REASONS, and the code prints no other text there. For the load gate: no-load-gate-step,
multiple-load-gate-steps, load-gate-missing-timestamp, load-gate-negative, load-gate-skipped, load-gate-not-success,
load-gate-no-conclusion. For the semaphore: no-test-step, missing-step-name (a step has no name), step-skipped,
step-not-success, step-no-conclusion, missing-timestamp, negative (the three of them are the test step's own conclusion
and timestamps), no-log, empty-log, no-semaphore-line, semaphore-line-no-timestamp (a semaphore line whose stamp cannot
be read), multiple-semaphore-lines (two lines are refused, not summed), malformed-semaphore-wait,
semaphore-wait-longer-than-step, compile-plus-wait-longer-than-step. The reasons multiple-semaphore-lines, malformed-semaphore-wait, semaphore-wait-longer-than-step,
compile-plus-wait-longer-than-step and semaphore-line-no-timestamp also leave `test` unmeasured with the same reason,
because the wait cannot then be taken out of it. No line at all leaves `test` as step minus compile.

A figure comes only from a step that ran: a step whose jobs-API `conclusion` is `skipped` is step-skipped, any other
conclusion except `success` is step-not-success, and a conclusion that is missing, empty or not a string is
step-no-conclusion (a skipped step is left
out of a sum of steps, since it took no time; the other two make the sum unmeasured). For the load gate these are
load-gate-skipped, load-gate-not-success and load-gate-no-conclusion.

Every duration is computed from two UTC timestamps that are both present and ordered, from a step that succeeded, or
the row is reported as `unmeasured` with a named reason (missing-timestamp, negative, compile-longer-than-step,
missing-step-name, step-skipped, step-not-success, step-no-conclusion) and left out of every median and range. The
table is followed by a footer line that counts them. A value that could not be measured is never printed as 0 s. Link
time is inside cargo's one `Finished` compile figure and is not split out. A log line over 4096 characters is not
matched against the `Finished` and `test result:` patterns, and a shorter line is matched once, anchored at the first
place it holds the text "Finished `" or "test result: " (find, then one anchored match, never a search from every
start), so reading a log is linear in its size.

`--bench-dir DIR` reads the stored logs of the nextest-against-cargo-test runs (compile.log, cglist.log, nxlist.log,
cargotest-1/2.log, nextest-1/2.log, nextest-solo1.log, nextest-solo.log, nextest-solo-j1.log) and prints, with the UTC
time it was read and each file's write time, the cargo build time, the test counts, the reconciliation of the
`test result:` rows with the list (rows printed by a child process inside a test are counted apart as nested, with
their `filtered out` counts), the names of the ignored tests, the nextest summaries and the failed-test sets.

Every stored log is read once, up to BENCH_LOG_MAX_BYTES, and is either measured or `not measured: <exact reason>`.
A number, a count, a `yes` or a fail-set line is printed only from a log that held a complete, self-consistent record
of it. These give `not measured` naming the log: a log that is empty, whitespace only, not UTF-8, over the byte cap,
without its record (no Finished line, no `: test` lines, no top-level `test result:` row, no nextest Summary line), with
a nextest Summary clause the parser does not know, with a `running N tests` header never closed, or whose Summary
counts disagree. Every line derived from such a log (a reconcile, a fail-set comparison, a same-count check) is
`not measured` too and names it. A missing log is `not measured` with its error and nothing else is printed.

Exit codes: 0 done, 2 usage error (argparse; `--runs` outside 1..30 is one), 3 a gh call failed, 4 no green run found,
5 the API payload had an unexpected shape (one line on stderr), 6 a stored bench log is missing,
7 the report was printed and at least one stored bench log is not measured (stderr names them). Only 0 is a full run.
"""
import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from fractions import Fraction
from pathlib import Path

EXIT_OK = 0
EXIT_GH_FAILED = 3
EXIT_NO_RUNS = 4
EXIT_BAD_INPUT = 5
MIN_RUNS = 1
WORKFLOWS = ("ci.yml", "coverage.yml")
MAX_RUNS = 30  # one API page is 100 rows; a request above this is refused, not cut
MAX_JOB_PAGES = 3
JOBS_PER_PAGE = 100
GH_TIMEOUT_SECS = 120
LOG_TIMEOUT_SECS = 300
TEST_JOB_RE = re.compile(r"^(Check \(|Per-Module Coverage)")
COMBINED_STEP_RE = re.compile(r"^(Run tests|Generate coverage JSON)")
COMPILE_STEP_RE = re.compile(r"^(Prebuild|Build release)")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
LOG_TS_RE = re.compile(r"^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z ")
LINE_MATCH_MAX = 4096  # a log line longer than this is not matched against FINISHED_RE or RESULT_RE
FINISHED_LITERAL = "Finished `"  # FINISHED_RE is matched only at the first place a line holds this text
RESULT_LITERAL = "test result: "  # RESULT_RE is matched only at the first place a line holds this text
FINISHED_RE = re.compile(r"Finished `[^`]+` profile .* target\(s\) in (?:(\d+)m )?([\d.]+)s")
RUNNING_RE = re.compile(r"Running (?:unittests )?(\S+)")
RESULT_RE = re.compile(r"test result: \w+\. (\d+) passed;.* finished in ([\d.]+)s")
STDERR_MARK = "--- stderr ---"
HEADER_RE = re.compile(r"^running (\d+) tests?$")
TEST_RESULT_RE = re.compile(
    r"^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; "
    r"finished in (\d+(?:\.\d+)?)s")
IGNORED_TEST_RE = re.compile(r"^test (\S+) \.\.\. ignored(?:, .*)?$")
NEXTEST_FAIL_RE = re.compile(r"^\s+FAIL \[\s*[\d.]+s\] \(\s*\d+/\d+\)\s+(.+?)\s*$")
SUMMARY_MARK = "Summary ["
SUMMARY_HEAD_RE = re.compile(r"^Summary \[\s*(\d+(?:\.\d+)?)s\] (\d+) tests? run: (.*)$")
SUMMARY_PASSED_RE = re.compile(r"^(\d+) passed(?: \(\d+ \w+(?:, \d+ \w+)*\))?$")
SUMMARY_COUNT_RE = re.compile(r"^(\d+) (failed|timed out|leaky|skipped)$")
SUMMARY_FIELDS = {"failed": "failed", "timed out": "timed_out", "leaky": "leaky", "skipped": "skipped"}
CLAUSE_QUOTE_MAX = 60  # longest slice of log text quoted in a reason
LIST_TEST_RE = re.compile(r"^\S.*: test$")
NEXTEST_LIST_RE = re.compile(r"^ai-memory(?:::\w+)? \S+$")
BENCH_COMPILE = "compile.log"
BENCH_CARGO_LIST = "cglist.log"
BENCH_NEXTEST_LIST = "nxlist.log"
BENCH_CARGO_RUNS = ("cargotest-1.log", "cargotest-2.log")
BENCH_NEXTEST_RUNS = ("nextest-1.log", "nextest-2.log")
BENCH_PROBES = ("nextest-solo1.log", "nextest-solo.log", "nextest-solo-j1.log")
BENCH_FILES = (BENCH_COMPILE, BENCH_CARGO_LIST, BENCH_NEXTEST_LIST, *BENCH_CARGO_RUNS, *BENCH_NEXTEST_RUNS, *BENCH_PROBES)
EXIT_BENCH_MISSING = 6
EXIT_BENCH_PARTIAL = 7
BENCH_LOG_MAX_BYTES = 64 * 1024 * 1024  # the stored logs are about 4.6 MB each; a log over the cap is not read
RANK_TOP = 16
STAGES = ("queue", "setup", "compile", "test", "post", "total")
WAIT_STAGES = ("load_gate", "semaphore")
WAIT_HEADERS = ("load gate s", "semaphore s")
LOAD_GATE_STEP_NAME = "Load gate (#6795)"
SEMAPHORE_MARKER = "[#7914 semaphore]"  # TAG of scripts/ci/host_semaphore.py
SEMAPHORE_NOTICE = "##[notice]"  # the runner's annotation prefix on a ::notice:: line
SEMAPHORE_ACQUIRED_TEXT = " acquired after "
SEMAPHORE_LINE_MAX = 8192  # a line longer than this is never read as the semaphore line
SEMAPHORE_LABEL_MAX = 256
# The one form scripts/ci/host_semaphore.py prints (after the stamp and the optional notice prefix), matched whole.
SEMAPHORE_LINE_RE = re.compile(
    re.escape(SEMAPHORE_MARKER) + r" '[^'\n]{0," + str(SEMAPHORE_LABEL_MAX) + r"}': slot [0-9]{1,4} of [0-9]{1,4}"
    r" acquired after ([0-9]{1,9})s \(load=[0-9]+\.[0-9]{2} cores=[0-9]{1,6}\)")
SLACK_SECS = 1  # a log stamp has whole-second precision; a window edge gets one second each side
NOT_MEASURED = "not measured"
REASON_MISSING_TS = "missing-timestamp"
REASON_NEGATIVE = "negative"
REASON_COMPILE_LONGER = "compile-longer-than-step"
REASON_MISSING_NAME = "missing-step-name"
REASON_NO_LOG = "no-log"
REASON_EMPTY_LOG = "empty-log"
REASON_NO_SEMAPHORE_LINE = "no-semaphore-line"
REASON_MULTIPLE_SEMAPHORE = "multiple-semaphore-lines"
REASON_MALFORMED_WAIT = "malformed-semaphore-wait"
REASON_WAIT_LONGER = "semaphore-wait-longer-than-step"
REASON_WAIT_COMPILE_OVERLAP = "compile-plus-wait-longer-than-step"
REASON_NO_LOAD_GATE = "no-load-gate-step"
REASON_MULTIPLE_LOAD_GATE = "multiple-load-gate-steps"
REASON_LOAD_GATE_NO_TS = "load-gate-missing-timestamp"
REASON_LOAD_GATE_NEGATIVE = "load-gate-negative"
REASON_LOAD_GATE_SKIPPED = "load-gate-skipped"
REASON_LOAD_GATE_NOT_SUCCESS = "load-gate-not-success"
REASON_LOAD_GATE_NO_CONCLUSION = "load-gate-no-conclusion"
REASON_NO_TEST_STEP = "no-test-step"
REASON_SEMAPHORE_NO_TS = "semaphore-line-no-timestamp"
REASON_STEP_SKIPPED = "step-skipped"
REASON_STEP_NOT_SUCCESS = "step-not-success"
REASON_STEP_NO_CONCLUSION = "step-no-conclusion"
CONCLUSION_SUCCESS = "success"
CONCLUSION_SKIPPED = "skipped"
# a jobs-API step reason to the reason of the load gate step
LOAD_GATE_STEP_REASONS = {REASON_STEP_SKIPPED: REASON_LOAD_GATE_SKIPPED,
                          REASON_STEP_NOT_SUCCESS: REASON_LOAD_GATE_NOT_SUCCESS,
                          REASON_STEP_NO_CONCLUSION: REASON_LOAD_GATE_NO_CONCLUSION}
# reasons that leave the test figure unmeasured, because the wait cannot be taken out of it
TEST_REFUSING_WAIT_REASONS = (REASON_MULTIPLE_SEMAPHORE, REASON_MALFORMED_WAIT, REASON_WAIT_LONGER,
                              REASON_WAIT_COMPILE_OVERLAP, REASON_SEMAPHORE_NO_TS)
# Every reason a wait figure can print as `absent: <reason>`; wait_absent() refuses any other text, and the module
# docstring names each member (a test pins both).
WAIT_ABSENT_REASONS = (
    REASON_NO_LOAD_GATE, REASON_MULTIPLE_LOAD_GATE, REASON_LOAD_GATE_NO_TS, REASON_LOAD_GATE_NEGATIVE,
    REASON_LOAD_GATE_SKIPPED, REASON_LOAD_GATE_NOT_SUCCESS, REASON_LOAD_GATE_NO_CONCLUSION,
    REASON_NO_TEST_STEP, REASON_MISSING_NAME, REASON_STEP_SKIPPED, REASON_STEP_NOT_SUCCESS, REASON_STEP_NO_CONCLUSION,
    REASON_MISSING_TS, REASON_NEGATIVE, REASON_NO_LOG, REASON_EMPTY_LOG, REASON_NO_SEMAPHORE_LINE,
    REASON_SEMAPHORE_NO_TS, REASON_MULTIPLE_SEMAPHORE, REASON_MALFORMED_WAIT, REASON_WAIT_LONGER,
    REASON_WAIT_COMPILE_OVERLAP)
REASONS = (REASON_MISSING_TS, REASON_NEGATIVE, REASON_COMPILE_LONGER, REASON_MISSING_NAME, *TEST_REFUSING_WAIT_REASONS,
           REASON_STEP_SKIPPED, REASON_STEP_NOT_SUCCESS, REASON_STEP_NO_CONCLUSION)
UNMEASURED_KEY = "unmeasured"
WAIT_ABSENT_KEY = "wait_absent"


class WaitUnavailable(Exception):
    """A wait figure that cannot be read; `reason` is its own exact reason text."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def parse_ts(text):
    """GitHub timestamp (`2026-11-16T01:54:55Z` or with a fraction) to UTC epoch seconds, None when unusable.

    The value is read as UTC whatever the TZ of the process is.
    """
    if not text or not isinstance(text, str):
        return None
    try:
        base = datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        return base + (float("0." + text[20:-1]) if len(text) > 20 and text[19] == "." else 0.0)
    except ValueError:
        return None


def duration(start_text, end_text):
    """(seconds, None) when both timestamps are usable and ordered, else (None, reason)."""
    start, end = parse_ts(start_text), parse_ts(end_text)
    if start is None or end is None:
        return None, REASON_MISSING_TS
    if end < start:
        return None, REASON_NEGATIVE
    return end - start, None


def runner_kind(labels):
    """hosted, macos-fed or self-hosted Linux, from the job labels."""
    if "macos-fed" in labels:
        return "macos-fed"
    if "linux-fed" in labels or "self-hosted" in labels:
        return "self-hosted Linux"
    return "hosted"


def step_secs(step):
    """(seconds, reason) of one jobs-API step; only a step whose conclusion is `success` has a duration.

    The conclusion is read first: `skipped` is step-skipped, a missing or non-string conclusion is step-no-conclusion
    and any other value (failure, cancelled, ...) is step-not-success. A step that did not run to success has
    timestamps that say nothing about the work, so no figure is taken from it.
    """
    conclusion = step.get("conclusion")
    if conclusion == CONCLUSION_SKIPPED:
        return None, REASON_STEP_SKIPPED
    if not isinstance(conclusion, str) or not conclusion:
        return None, REASON_STEP_NO_CONCLUSION
    if conclusion != CONCLUSION_SUCCESS:
        return None, REASON_STEP_NOT_SUCCESS
    return duration(step.get("started_at"), step.get("completed_at"))


def sum_steps(steps):
    """(sum of step seconds, None), or (None, reason) when any step in the range is unmeasured.

    A skipped step took no time and is left out of the sum; every other unmeasured step makes the sum unmeasured.
    """
    total, bad = 0.0, None
    for step in steps:
        secs, why = step_secs(step)
        if why == REASON_STEP_SKIPPED:
            continue
        if why:
            bad = bad or why
        else:
            total += secs
    return (None, bad) if bad else (total, None)


def log_line_time(line):
    """UTC epoch (an exact Fraction, so two stamps one tick apart never round to the same instant) of the stamp a
    job-log line starts with; None when it has none or it is not a date."""
    stamp = LOG_TS_RE.match(line)
    if not stamp:
        return None
    whole = parse_ts(stamp.group(1) + "Z")
    if whole is None:
        return None
    fraction = stamp.group(2)
    return Fraction(int(whole)) + (Fraction(int(fraction), 10 ** len(fraction)) if fraction else 0)


def in_window(when, win_start, win_end):
    """True when the time is inside the window (one second of slack each side); an open end accepts everything."""
    return not ((win_start is not None and when < win_start - SLACK_SECS)
                or (win_end is not None and when > win_end + SLACK_SECS))


def find_then_match(regex, literal, text):
    """regex.match anchored at the first place `literal` occurs in text, else None; one pass, never a search.

    A search retries the pattern from every start in the text, which is quadratic for a line made of the pattern's own
    first words. Only the first occurrence of the literal is read, so a line whose first occurrence does not match is
    not a match even when a later occurrence would have.
    """
    at = text.find(literal)
    return regex.match(text, at) if at >= 0 else None


def first_finished(lines, win_start=None, win_end=None):
    """(timestamp, reported compile seconds) of the first cargo Finished line inside the window, else None."""
    for raw in lines:
        line = ANSI_RE.sub("", raw)
        if len(line) > LINE_MATCH_MAX:
            continue
        hit = find_then_match(FINISHED_RE, FINISHED_LITERAL, line)
        if not hit:
            continue
        when = log_line_time(line)
        if when is None or not in_window(when, win_start, win_end):
            continue
        return when, int(hit.group(1) or 0) * 60 + float(hit.group(2))
    return None


def semaphore_candidate(raw):
    """(body, when) of a line that may be the semaphore line, else None; when is None for an unreadable stamp.

    The body is what follows the runner's stamp and one optional `##[notice]`, and it must start with the marker and
    hold ` acquired after `. A line whose stamp does not have the runner's shape is still a candidate when the marker
    starts the line or follows its first word (a stamp cut short, a byte order mark, a missing zone letter), and so is
    a line whose stamp has the shape but is not a date (month 13): both come back with when None and are refused
    with their own reason, never skipped.
    """
    line = ANSI_RE.sub("", raw)
    stamp = LOG_TS_RE.match(line)
    if stamp:
        bodies = [line[stamp.end():]]
    else:
        bodies = [line]
        first_word = line.split(" ", 1)
        if len(first_word) == 2:
            bodies.append(first_word[1])
    for body in bodies:
        if body.startswith(SEMAPHORE_NOTICE):
            body = body[len(SEMAPHORE_NOTICE):]
        if body.startswith(SEMAPHORE_MARKER) and SEMAPHORE_ACQUIRED_TEXT in body:
            return body, log_line_time(line)
    return None


def parse_semaphore_wait(lines, win_start, win_end, cutoff):
    """Seconds (int) of the one exact-form `acquired after <N>s` semaphore line inside the step window.

    A line is read only in the form host_semaphore.py prints (SEMAPHORE_LINE_RE, matched whole, no search) after the
    runner's stamp and one optional `##[notice]`; text in front of the marker is never a wait. The line must carry a
    readable stamp, lie inside the window (one second of slack each side) and be strictly before cutoff, the time of
    the first cargo `Finished` line (the semaphore wraps the cargo command and prints before it, so a later line is a
    test's own output). cutoff None (the step has no `Finished` line) reads every in-window exact-form line.
    Raises WaitUnavailable with the reason: semaphore-line-no-timestamp, no-semaphore-line, multiple-semaphore-lines
    (refused, not summed) or malformed-semaphore-wait (not the exact form). A line longer than SEMAPHORE_LINE_MAX is never read.
    """
    first, count, unstamped = None, 0, False
    for raw in lines:
        if len(raw) > SEMAPHORE_LINE_MAX:
            continue  # the wrapper's line is a few hundred characters; a longer one is never read
        candidate = semaphore_candidate(raw)
        if candidate is None:
            continue
        body, when = candidate
        if when is None:
            unstamped = True
            continue
        if not in_window(when, win_start, win_end) or (cutoff is not None and when >= cutoff):
            continue
        count += 1
        if first is None:
            first = body
    if unstamped:
        raise WaitUnavailable(REASON_SEMAPHORE_NO_TS)
    if count == 0:
        raise WaitUnavailable(REASON_NO_SEMAPHORE_LINE)
    if count > 1:
        raise WaitUnavailable(REASON_MULTIPLE_SEMAPHORE)
    hit = SEMAPHORE_LINE_RE.fullmatch(first)
    if not hit:
        raise WaitUnavailable(REASON_MALFORMED_WAIT)
    return int(hit.group(1))


def load_gate_wait(steps):
    """Wall seconds of the one step named LOAD_GATE_STEP_NAME; raises WaitUnavailable with the reason otherwise.

    The step's conclusion is read before its timestamps: skipped, not-success and no-conclusion are the load-gate-*
    reasons, so a gate that did not run is never printed as a number.
    """
    gates = [s for s in steps if (s.get("name") or "") == LOAD_GATE_STEP_NAME]
    if not gates:
        raise WaitUnavailable(REASON_NO_LOAD_GATE)
    if len(gates) > 1:
        raise WaitUnavailable(REASON_MULTIPLE_LOAD_GATE)
    secs, why = step_secs(gates[0])
    if why in LOAD_GATE_STEP_REASONS:
        raise WaitUnavailable(LOAD_GATE_STEP_REASONS[why])
    if why == REASON_MISSING_TS:
        raise WaitUnavailable(REASON_LOAD_GATE_NO_TS)
    if why:
        raise WaitUnavailable(REASON_LOAD_GATE_NEGATIVE)
    return secs


def split_job(job, log_lines=None):
    """Seconds per stage for one jobs-API job object; None for a stage that cannot be derived.

    queue: created to started, None when the job was carried over from an earlier attempt (started before created).
    setup: every step before the first compile/test step. compile/test: the combined step split by the log, or the
    separate compile steps. post: every step after the combined step except a compile step.
    Link time is inside the compile figure: cargo prints one `Finished` time for compile and link together.
    A stage that cannot be derived because a timestamp is missing, a duration is negative, the compile time cargo
    reported is longer than its step or a step has no name is None, and `unmeasured` lists `stage:reason` for it.
    """
    out = dict.fromkeys((*STAGES, *WAIT_STAGES))
    out[UNMEASURED_KEY] = []
    out[WAIT_ABSENT_KEY] = {}

    def flag(stage, reason):
        out[stage] = None
        out[UNMEASURED_KEY].append(f"{stage}:{reason}")

    def wait_absent(stage, reason):
        if reason not in WAIT_ABSENT_REASONS:
            raise ValueError(f"wait reason not in WAIT_ABSENT_REASONS: {reason!r}")
        out[stage] = None
        out[WAIT_ABSENT_KEY][stage] = reason

    total, why = duration(job.get("started_at"), job.get("completed_at"))
    out["total"] = total
    if why:
        flag("total", why)
    created, started = parse_ts(job.get("created_at")), parse_ts(job.get("started_at"))
    if created is None or started is None:
        flag("queue", REASON_MISSING_TS)
    elif started >= created:
        out["queue"] = started - created
    steps = job.get("steps") or []
    try:
        out["load_gate"] = load_gate_wait(steps)
    except WaitUnavailable as exc:
        wait_absent("load_gate", exc.reason)
    main = next((i for i, s in enumerate(steps) if COMBINED_STEP_RE.match(s.get("name") or "")), None)
    if main is None:
        wait_absent("semaphore", REASON_NO_TEST_STEP)
        return out
    if any(not s.get("name") for s in steps):
        for stage in ("setup", "compile", "test", "post"):
            flag(stage, REASON_MISSING_NAME)
        wait_absent("semaphore", REASON_MISSING_NAME)
        out["combined_wall"] = None
        return out

    def named(chunk, wanted):
        return [s for s in chunk if bool(COMPILE_STEP_RE.match(s["name"])) is wanted]

    setup, why = sum_steps(named(steps[:main], False))
    if why:
        flag("setup", why)
    else:
        out["setup"] = setup
    post, why = sum_steps(named(steps[main + 1:], False))
    if why:
        flag("post", why)
    else:
        out["post"] = post
    extra_compile, extra_why = sum_steps(named(steps, True))
    wall, wall_why = step_secs(steps[main])
    out["combined_wall"] = wall
    if wall_why or extra_why:
        for stage in ("compile", "test"):
            flag(stage, wall_why or extra_why)
        wait_absent("semaphore", wall_why or extra_why)
        return out
    win_start, win_end = parse_ts(steps[main].get("started_at")), parse_ts(steps[main].get("completed_at"))
    found = first_finished(log_lines, win_start, win_end) if log_lines else None
    wait, wait_why = None, None
    try:
        if log_lines is None:
            raise WaitUnavailable(REASON_NO_LOG)
        if not log_lines:
            raise WaitUnavailable(REASON_EMPTY_LOG)
        wait = parse_semaphore_wait(log_lines, win_start, win_end, found[0] if found else None)
        if wait > wall:
            wait, wait_why = None, REASON_WAIT_LONGER
        elif found and found[1] <= wall and found[1] + wait > wall:
            wait, wait_why = None, REASON_WAIT_COMPILE_OVERLAP
    except WaitUnavailable as exc:
        wait_why = exc.reason
    if wait_why:
        wait_absent("semaphore", wait_why)
    else:
        out["semaphore"] = float(wait)
    if found and found[1] > wall:
        for stage in ("compile", "test"):
            flag(stage, REASON_COMPILE_LONGER)
    elif found:
        out["compile"] = found[1] + extra_compile
        if wait_why in TEST_REFUSING_WAIT_REASONS:
            flag("test", wait_why)
        else:
            # wait is None here only for no-log, empty-log or no-semaphore-line: there is nothing to take out
            out["test"] = wall - found[1] if wait is None else wall - found[1] - wait
    else:
        out["compile"] = extra_compile or None
        if wait_why in TEST_REFUSING_WAIT_REASONS:
            flag("test", wait_why)
    return out


def rank_binaries(lines):
    """[(seconds, passed, target)] longest first, pairing each cargo `Running <target>` with the next `test result:`.

    Valid for one sequential shard; a log with interleaved shards can mispair, which the caller must name.
    """
    pending, rows = [], []
    for raw in lines:
        body = LOG_TS_RE.sub("", ANSI_RE.sub("", raw), count=1).strip()
        run = RUNNING_RE.match(body)
        if run:
            pending.append(run.group(1))
            continue
        res = find_then_match(RESULT_RE, RESULT_LITERAL, body) if len(body) <= LINE_MATCH_MAX else None
        if res and pending:
            rows.append((float(res.group(2)), int(res.group(1)), pending.pop(0)))
    return sorted(rows, reverse=True)


def clean_lines(text):
    """Lines of a stored log with ANSI colour removed and trailing blanks stripped."""
    return [ANSI_RE.sub("", ln).rstrip() for ln in split_log_text(text)]


def quote(text):
    """repr of at most CLAUSE_QUOTE_MAX characters of log text, with `...` when it was cut."""
    return repr(text[:CLAUSE_QUOTE_MAX]) + ("..." if len(text) > CLAUSE_QUOTE_MAX else "")


def parse_cargo_results(lines):
    """(top, nested, reason): the `test result:` rows of a stored `cargo test` log, split by who printed them.

    Only the stdout part (before the stderr marker) is read. A binary prints `running N tests` and later one result
    row whose passed + failed + ignored + measured equals N: that row is top-level. Any other row inside that
    window, and any header inside it, was printed by a child process of a test (nested) and is counted apart.
    reason is None when the log holds at least one top-level row and no header is left open; otherwise it says
    which of the two failed, and the caller reports the log as not measured.
    """
    top, nested, open_count, open_text, open_line, ended = [], [], None, "", 0, "end of log"
    for number, line in enumerate(lines, 1):
        if line == STDERR_MARK:
            ended = "the stderr marker"
            break
        head = HEADER_RE.match(line)
        if head:
            if open_count is None:
                open_count, open_text, open_line = int(head.group(1)), line, number
            continue
        res = TEST_RESULT_RE.match(line)
        if not res:
            continue
        row = {"passed": int(res.group(1)), "failed": int(res.group(2)), "ignored": int(res.group(3)),
               "measured": int(res.group(4)), "filtered": int(res.group(5)), "secs": float(res.group(6))}
        if open_count is not None and row["passed"] + row["failed"] + row["ignored"] + row["measured"] == open_count:
            row["header"] = open_count
            top.append(row)
            open_count = None
        else:
            nested.append(row)
    if open_count is not None:
        return top, nested, f"`{open_text}` header (line {open_line}) never closed before {ended}"
    return top, nested, (None if top else "no top-level `test result:` row")


def parse_cargo_ignored(lines):
    """Sorted names of the tests a stored `cargo test` log prints as `ignored`, stdout part only."""
    names = []
    for line in lines:
        if line == STDERR_MARK:
            break
        hit = IGNORED_TEST_RE.match(line)
        if hit:
            names.append(hit.group(1))
    return sorted(names)


def split_clauses(rest):
    """The comma separated clauses of a Summary line outside parentheses; None when the parentheses do not balance."""
    parts, depth, start = [], 0, 0
    for index, char in enumerate(rest):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif char == "," and depth == 0:
            parts.append(rest[start:index].strip())
            start = index + 1
    if depth:
        return None
    parts.append(rest[start:].strip())
    return parts


def parse_summary_line(text):
    """(summary, reason) for one nextest `Summary [..] N tests run: ...` line; every clause is read into a named field.

    A clause the parser does not know, a repeated clause, a missing passed clause and counts that do not add up
    (passed + failed + timed out + leaky must equal the tests run) give summary None and the reason, with the
    offending text quoted to CLAUSE_QUOTE_MAX characters.
    """
    head = SUMMARY_HEAD_RE.match(text)
    if not head:
        return None, f"Summary line not understood: {quote(text)}"
    clauses = split_clauses(head.group(3))
    if clauses is None:
        return None, f"unbalanced parenthesis in Summary clauses: {quote(head.group(3))}"
    summary = {"secs": float(head.group(1)), "run": int(head.group(2)), "passed": 0, "failed": 0, "skipped": 0,
               "timed_out": 0, "leaky": 0}
    seen = set()
    for clause in clauses:
        passed, counted = SUMMARY_PASSED_RE.match(clause), SUMMARY_COUNT_RE.match(clause)
        if passed:
            key, value = "passed", int(passed.group(1))
        elif counted:
            key, value = SUMMARY_FIELDS[counted.group(2)], int(counted.group(1))
        else:
            return None, f"unknown Summary clause {quote(clause)}"
        if key in seen:
            return None, f"repeated Summary clause {quote(clause)}"
        seen.add(key)
        summary[key] = value
    if "passed" not in seen:
        return None, f"Summary line has no passed clause: {quote(head.group(3))}"
    total = summary["passed"] + summary["failed"] + summary["timed_out"] + summary["leaky"]
    if total != summary["run"]:
        return None, f"Summary counts disagree: {summary['run']} run but passed + failed + timed out + leaky = {total}"
    return summary, None


def parse_nextest(lines):
    """(summary, fails, reason): the Summary and distinct failed test names of a stored `cargo nextest run` log.

    summary is None, with the reason, when the log holds no Summary line, more than one, or one that
    parse_summary_line refuses.
    """
    fails, found = set(), []
    for line in lines:
        fail = NEXTEST_FAIL_RE.match(line)
        if fail:
            fails.add(fail.group(1))
        if line.strip().startswith(SUMMARY_MARK):
            found.append(line.strip())
    if not found:
        return None, fails, "no Summary line"
    if len(found) > 1:
        return None, fails, f"{len(found)} Summary lines"
    summary, reason = parse_summary_line(found[0])
    return summary, fails, reason


def count_list(lines, pattern):
    """Number of lines of a stored `list` output that match the compiled pattern."""
    return sum(1 for ln in lines if pattern.match(ln))


def utc_text(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def yes_no(flag):
    return "yes" if flag else "NO"


def nextest_counts(summary, with_skipped):
    """`N run, P passed, F failed` of a parsed Summary, plus the timed out and leaky clauses when they are not 0."""
    parts = [f"{summary['run']} run", f"{summary['passed']} passed", f"{summary['failed']} failed"]
    if summary["timed_out"]:
        parts.append(f"{summary['timed_out']} timed out")
    if summary["leaky"]:
        parts.append(f"{summary['leaky']} leaky")
    if with_skipped:
        parts.append(f"{summary['skipped']} skipped")
    return ", ".join(parts)


def read_bench_log(path):
    """(lines, written epoch, reason): one read of at most BENCH_LOG_MAX_BYTES + 1 bytes of a stored log.

    lines is None, with the exact reason, when the log is over the cap, empty, not UTF-8 or whitespace only.
    An OSError (a missing or unreadable log) is not caught here.
    """
    with path.open("rb") as handle:
        written = os.fstat(handle.fileno()).st_mtime
        raw = handle.read(BENCH_LOG_MAX_BYTES + 1)
    if len(raw) > BENCH_LOG_MAX_BYTES:
        return None, written, f"larger than the {BENCH_LOG_MAX_BYTES} byte cap"
    if not raw:
        return None, written, "empty (0 bytes)"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return None, written, f"not valid UTF-8 (byte 0x{raw[exc.start]:02x} at offset {exc.start}: {exc.reason})"
    if not text.strip():
        return None, written, "whitespace only"
    return clean_lines(text), written, None


def _reason(reasons, name):
    """`not measured: <reason>` for one log of the reasons table."""
    return f"{NOT_MEASURED}: {reasons[name]}"


def bench_report(directory, now):
    """(report lines, missing file names, not-measured log names) for the stored logs in one directory.

    A missing log gives no report at all. Otherwise every log is measured or carries one reason (see the module
    docstring); a line that needs a not-measured log prints `not measured: <log names>` in place of its numbers.
    """
    missing, logs, written, reasons = [], {}, {}, {}
    for name in BENCH_FILES:
        try:
            lines, epoch, why = read_bench_log(directory / name)
        except OSError as exc:
            missing.append(f"{name}: {str(exc)[:120]}")
            continue
        logs[name], written[name] = lines, utc_text(epoch)
        if why:
            reasons[name] = why
    if missing:
        return [], missing, []

    def unmeasured(*names):
        return ", ".join(n for n in names if n in reasons)

    build_secs = None
    if BENCH_COMPILE not in reasons:
        hits = (find_then_match(FINISHED_RE, FINISHED_LITERAL, ln) for ln in logs[BENCH_COMPILE] if len(ln) <= LINE_MATCH_MAX)
        build = next((hit for hit in hits if hit), None)
        if build is None:
            reasons[BENCH_COMPILE] = "no Finished line"
        else:
            build_secs = int(build.group(1) or 0) * 60 + float(build.group(2))
    counts = {}
    for name, pattern, none_reason in ((BENCH_CARGO_LIST, LIST_TEST_RE, "no `: test` lines"),
                                       (BENCH_NEXTEST_LIST, NEXTEST_LIST_RE, "no test lines")):
        if name not in reasons:
            found = count_list(logs[name], pattern)
            if found:
                counts[name] = found
            else:
                reasons[name] = none_reason
    cargo = {}
    for name in BENCH_CARGO_RUNS:
        if name not in reasons:
            top, nested, why = parse_cargo_results(logs[name])
            if why:
                reasons[name] = why
            else:
                cargo[name] = (top, nested, parse_cargo_ignored(logs[name]))
    nextest = {}
    for name in (*BENCH_NEXTEST_RUNS, *BENCH_PROBES):
        if name not in reasons:
            summary, fails, why = parse_nextest(logs[name])
            if why:
                reasons[name] = why
            else:
                nextest[name] = (summary, fails)
    list_total, nextest_list = counts.get(BENCH_CARGO_LIST), counts.get(BENCH_NEXTEST_LIST)

    out = [f"read at {utc_text(now)} UTC from {directory}"]
    out.append(f"build: {BENCH_COMPILE} (written {written[BENCH_COMPILE]}) cargo Finished in "
               f"{_reason(reasons, BENCH_COMPILE) if build_secs is None else f'{build_secs:.0f} s'}")
    out.append("list: " + "; ".join(
        f"{name} (written {written[name]}) " + (_reason(reasons, name) if name in reasons else f"{counts[name]} {text}")
        for name, text in ((BENCH_CARGO_LIST, "`: test` lines"), (BENCH_NEXTEST_LIST, "test lines"))))
    for name in BENCH_CARGO_RUNS:
        if name not in cargo:
            out.append(f"{name} (written {written[name]}): {_reason(reasons, name)}")
            for label in ("reconcile", "nested result rows", "ignored tests"):
                out.append(f"  {label}: {NOT_MEASURED}: {name}")
            continue
        top, nested, ignored_names = cargo[name]
        head = sum(r["header"] for r in top)
        passed, ignored = sum(r["passed"] for r in top), sum(r["ignored"] for r in top)
        nest_passed = sum(r["passed"] for r in nested)
        out.append(f"{name} (written {written[name]}): {len(top)} top-level result rows, header sum {head}, "
                   f"{passed} passed, {sum(r['failed'] for r in top)} failed, {ignored} ignored, "
                   f"sum of finished-in {sum(r['secs'] for r in top):.1f} s; {len(nested)} nested result rows "
                   f"({nest_passed} passed) printed inside the lib test output; all rows {passed + nest_passed} passed")
        if list_total is None:
            out.append(f"  reconcile: {NOT_MEASURED}: {unmeasured(BENCH_CARGO_LIST)}")
        else:
            out.append(f"  reconcile: header sum == list {yes_no(head == list_total)}; "
                       f"top-level passed + ignored == list {yes_no(passed + ignored == list_total)}; "
                       f"all rows passed - list = {passed + nest_passed - list_total}, "
                       f"explained by nested rows ({nest_passed}) minus ignored ({ignored}) = {nest_passed - ignored}: "
                       f"{yes_no(passed + nest_passed - list_total == nest_passed - ignored)}")
        filtered = ", ".join(str(v) for v in sorted({r["filtered"] for r in nested})) or "none"
        out.append(f"  nested result rows: {len(nested)}; `filtered out` of those rows: {filtered}")
        out.append(f"  ignored tests: {len(ignored_names)} named ({', '.join(ignored_names)}); "
                   f"top-level ignored count {ignored}: {yes_no(len(ignored_names) == ignored)}")
    for name in BENCH_NEXTEST_RUNS:
        if name not in nextest:
            out.append(f"{name} (written {written[name]}): {_reason(reasons, name)}")
            continue
        summary, fails = nextest[name]
        out.append(f"{name} (written {written[name]}): nextest Summary {summary['secs']:.1f} s, "
                   f"{nextest_counts(summary, True)}; {len(fails)} distinct FAIL names "
                   f"(== failed: {yes_no(len(fails) == summary['failed'])})")
    if unmeasured(*BENCH_NEXTEST_RUNS):
        out.append(f"nextest fail sets over runs 1 and 2: {NOT_MEASURED}: {unmeasured(*BENCH_NEXTEST_RUNS)}")
    else:
        first_fails, second_fails = (nextest[n][1] for n in BENCH_NEXTEST_RUNS)
        out.append(f"nextest fail sets over runs 1 and 2: {len(first_fails & second_fails)} in both, "
                   f"{len(first_fails | second_fails)} in either")
    for name in BENCH_PROBES:
        if name not in nextest:
            out.append(f"{name} (written {written[name]}): {_reason(reasons, name)}")
            continue
        summary = nextest[name][0]
        out.append(f"{name} (written {written[name]}): nextest Summary {summary['secs']:.1f} s, "
                   f"{nextest_counts(summary, False)}")
    first_name = BENCH_NEXTEST_RUNS[0]
    first = nextest[first_name][0] if first_name in nextest else None
    count_bad = unmeasured(first_name, BENCH_CARGO_LIST)
    list_bad = unmeasured(first_name, BENCH_NEXTEST_LIST)
    count_text = f"{NOT_MEASURED}: {count_bad}" if count_bad else yes_no(first["run"] + first["skipped"] == list_total)
    list_text = f"{NOT_MEASURED}: {list_bad}" if list_bad else yes_no(first["run"] == nextest_list)
    out.append(f"same test count: nextest run + skipped == cargo list {count_text}; nextest list == nextest run "
               f"{list_text}")
    return out, [], [name for name in BENCH_FILES if name in reasons]


def summarize(values):
    """(median, min, max, n) over the numbers in values, None entries dropped; None when nothing is left."""
    nums = [v for v in values if v is not None]
    return (statistics.median(nums), min(nums), max(nums), len(nums)) if nums else None


def unmeasured_footer(rows):
    """One line counting the cells left out of the table, by reason."""
    counts = dict.fromkeys(REASONS, 0)
    cells = bad_rows = 0
    for row in rows:
        entries = row.get(UNMEASURED_KEY) or []
        bad_rows += bool(entries)
        for entry in entries:
            cells += 1
            reason = entry.split(":", 1)[1]
            counts[reason] = counts.get(reason, 0) + 1
    detail = f" ({', '.join(f'{r}={n}' for r, n in counts.items() if n)})" if cells else ""
    return f"unmeasured: {cells} cells in {bad_rows} of {len(rows)} rows{detail}"


def fmt(stat):
    if stat is None:
        return NOT_MEASURED
    return f"{stat[0]:.0f} ({stat[1]:.0f}-{stat[2]:.0f}) n={stat[3]}"


def gh_get(args):
    """Run `gh api <args>` (a GET); returns stdout text. Raises RuntimeError with the exact error."""
    proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True, timeout=GH_TIMEOUT_SECS, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"gh api {' '.join(args)} exit {proc.returncode}: {proc.stderr.strip()[:300]}")
    return proc.stdout


def list_runs(repo, workflow, branch, count):
    path = f"repos/{repo}/actions/workflows/{workflow}/runs?branch={branch}&status=success&per_page={count}"
    rows = json.loads(gh_get([path, "--jq", "[.workflow_runs[]|{id,head_sha,run_attempt,created_at}]"]))
    return rows[:count]


def list_jobs(repo, run_id):
    jobs = []
    for page in range(1, MAX_JOB_PAGES + 1):
        batch = json.loads(gh_get([f"repos/{repo}/actions/runs/{run_id}/jobs?per_page={JOBS_PER_PAGE}&page={page}",
                                   "--jq", "[.jobs[]|{id,name,labels,created_at,started_at,completed_at,steps:[.steps[]|{name,started_at,completed_at,conclusion}]}]"]))
        jobs += batch
        if len(batch) < JOBS_PER_PAGE:
            break
    return jobs


def split_log_text(text):
    """Lines of a downloaded job log: split on the newline only, one trailing carriage return dropped per line.

    str.splitlines() also ends a line on CR, VT, FF, FS, GS, RS, NEL, U+2028 and U+2029, and Path.read_text turns a
    lone CR into a newline, so a test that prints one of them could start a second physical line that looks like the
    wrapper's. The runner puts every real line on its own stamped line, so only the newline is a line end.
    """
    lines = [ln[:-1] if ln.endswith("\r") else ln for ln in text.split("\n")]
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def fetch_log_lines(repo, job_id, scratch):
    """Download one job log to scratch, return its lines, delete the file. None plus the error when it fails."""
    target = scratch / f"job-{job_id}.log"
    try:
        with target.open("wb") as handle:
            proc = subprocess.run(["gh", "api", "--allow-escape-sequences", f"repos/{repo}/actions/jobs/{job_id}/logs"],
                                  stdout=handle, stderr=subprocess.PIPE, timeout=LOG_TIMEOUT_SECS, check=False)
        if proc.returncode != 0:
            return None, f"gh exit {proc.returncode}: {proc.stderr.decode(errors='replace').strip()[:200]}"
        return split_log_text(target.read_bytes().decode("utf-8", errors="replace")), None
    except (subprocess.TimeoutExpired, OSError) as exc:
        return None, str(exc)[:200]
    finally:
        target.unlink(missing_ok=True)


def collect(repo, branch, count, scratch, want_logs):
    rows, errors = [], []
    for workflow in WORKFLOWS:
        for run in list_runs(repo, workflow, branch, count):
            for job in list_jobs(repo, run["id"]):
                if not TEST_JOB_RE.match(job.get("name") or ""):
                    continue
                lines = None
                if want_logs:
                    lines, err = fetch_log_lines(repo, job["id"], scratch)
                    if err:
                        errors.append(f"run {run['id']} job {job['id']} log: {err}")
                row = split_job(job, lines)
                row.update(workflow=workflow, run=run["id"], head=run["head_sha"][:10], job=job["name"],
                           kind=runner_kind(job.get("labels") or []), job_id=job["id"])
                rows.append(row)
    return rows, errors


def wait_cell(rows, stage):
    """One wait cell of a group: the median and range, `absent: <reasons>` when no row has the figure."""
    absent = [r[WAIT_ABSENT_KEY][stage] for r in rows if stage in r.get(WAIT_ABSENT_KEY, {})]
    reasons = ", ".join(sorted(set(absent)))
    stat = summarize([r.get(stage) for r in rows])
    if stat is None:
        return f"absent: {reasons}" if absent else NOT_MEASURED
    return fmt(stat) + (f" (absent in {len(absent)} of {len(rows)} rows: {reasons})" if absent else "")


def wait_footer(rows):
    """One line counting the absent wait figures by stage and reason, or None when every wait was read."""
    counts = defaultdict(int)
    for row in rows:
        for stage, reason in sorted(row.get(WAIT_ABSENT_KEY, {}).items()):
            counts[(stage, reason)] += 1
    if not counts:
        return None
    return "waits absent: " + ", ".join(f"{stage} {reason}={n}" for (stage, reason), n in sorted(counts.items()))


def print_table(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[(row["workflow"], row["job"], row["kind"])].append(row)
    print("workflow | job | runner kind | " + " | ".join(f"{s} s" for s in STAGES) + " | " + " | ".join(WAIT_HEADERS))
    for key in sorted(groups):
        cells = [fmt(summarize([r[s] for r in groups[key]])) for s in STAGES]
        cells += [wait_cell(groups[key], stage) for stage in WAIT_STAGES]
        print(" | ".join(key) + " | " + " | ".join(cells))
    footer = wait_footer(rows)
    if footer:
        print(footer)
    print(unmeasured_footer(rows))


def runs_arg(text):
    """argparse type for --runs: an integer in MIN_RUNS..MAX_RUNS, else a reason."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer; --runs takes {MIN_RUNS}..{MAX_RUNS}") from None
    if not MIN_RUNS <= value <= MAX_RUNS:
        raise argparse.ArgumentTypeError(f"{value} is outside {MIN_RUNS}..{MAX_RUNS}; --runs takes {MIN_RUNS}..{MAX_RUNS}")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--runs", type=runs_arg, default=10, metavar=f"{MIN_RUNS}..{MAX_RUNS}")
    parser.add_argument("--scratch", type=Path, default=Path(".local-runs"))
    parser.add_argument("--no-logs", action="store_true", help="skip the log split; compile/test stay unseparated")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--rank-job", type=int, help="print the longest test binaries of this job id's log and exit")
    parser.add_argument("--bench-dir", type=Path,
                        help="read the stored cargo test and nextest logs of one directory, print their counts and exit")
    args = parser.parse_args(argv)
    if args.bench_dir:
        report, missing, partial = bench_report(args.bench_dir, time.time())
        for reason in missing:
            print(f"{NOT_MEASURED}: {reason}", file=sys.stderr)
        for line in report:
            print(line)
        if partial:
            print(f"{NOT_MEASURED}: {len(partial)} log(s): {', '.join(partial)}", file=sys.stderr)
        return EXIT_BENCH_MISSING if missing else EXIT_BENCH_PARTIAL if partial else EXIT_OK
    args.scratch.mkdir(parents=True, exist_ok=True)
    if args.rank_job:
        lines, err = fetch_log_lines(args.repo, args.rank_job, args.scratch)
        if err:
            print(f"{NOT_MEASURED}: {err}", file=sys.stderr)
            return EXIT_GH_FAILED
        for secs, passed, target in rank_binaries(lines)[:RANK_TOP]:
            print(f"{secs:8.2f} s {passed:5d} tests {target}")
        return EXIT_OK
    try:
        rows, errors = collect(args.repo, args.branch, args.runs, args.scratch, not args.no_logs)
    except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"gh failed: {exc}", file=sys.stderr)
        return EXIT_GH_FAILED
    except (KeyError, TypeError, AttributeError, ValueError, IndexError) as exc:
        print(f"unexpected input from the API: {type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
        return EXIT_BAD_INPUT
    if not rows:
        print("no green test job found", file=sys.stderr)
        return EXIT_NO_RUNS
    if args.json_out:
        args.json_out.write_text(json.dumps({"rows": rows, "errors": errors}, indent=1), encoding="utf-8")
    print_table(rows)
    for err in errors:
        print(f"{NOT_MEASURED}: {err}", file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
