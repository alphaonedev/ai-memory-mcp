#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""CI failure classifier for annotation lines (issues #9235, #9231).

`jev_ci_class` maps a CI log to a class.  This module owns the mapping for two
annotation families.  Every rule matches one WHOLE log line, anchored at the line
start after the optional `job<TAB>step<TAB>` prefix of `gh run view --log` and the
optional runner timestamp, never a substring of a line:

    ::error::[coverage-pg] PG-ENV <reason>              ->   ci-env
    [#7914 semaphore] '<label>': infra-no-slot: ...     ->   infra-no-slot
    [#7914 semaphore] '<label>': infra-unknown-runner   ->   infra-unknown-runner

The semaphore lines are those of `scripts/ci/host_semaphore.py`.  A job log shows an
error annotation as `##[error]<message>` with no title, so the message carries the
outcome token; the raw `::error title=infra no-slot::<message>` form is matched too.

A log is split per job and each job is classified on its own.  A job gets a
semaphore class only when its log has the matching line, has NO slot-acquired marker
line (the wrapper prints one when it holds the slot, before the command starts) and
has no test or build failure evidence (`test result: FAILED`, `could not compile`,
a panic, a nextest FAIL line) and no ci-env line.  Pull-request code runs in the
same job and can print any text, so the text alone never decides.  ci-env wins over
the semaphore classes; any failure evidence wins over them.  For a whole run log,
`classify` returns ci-env if any job is ci-env, None if any job shows failure
evidence (a no-slot job never hides a red job), else the semaphore class.

The class is a hint for re-run routing and never makes a gate softer: the job and
`ci-gate` stay red whatever this module returns.  Consumers: only the CLI below, run
by hand by a human or conductor.  No workflow, no gate (`impact/gate.py`) and no
re-run helper reads it; `jev_ci_class.py` has its own classes and does not import it.

Anything else (a warning, a missing `::error::`, another label, a glued-on suffix such
as `PG-ENVX`, a quoted or indented copy of a line) yields `None`.

CLI: `ci_failure_class.py [LOGFILE]` (stdin when omitted) prints
`CI-CLASS: ci-env`, `CI-CLASS: infra-no-slot`, `CI-CLASS: infra-unknown-runner`
or `CI-CLASS: none`; exit code 0 always.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

CLASS_CI_ENV = "ci-env"
CLASS_INFRA_NO_SLOT = "infra-no-slot"
CLASS_INFRA_UNKNOWN_RUNNER = "infra-unknown-runner"
PG_ENV_LABEL = "coverage-pg"
SEMAPHORE_TAG = r"\[#7914 semaphore\]"

# `gh run view --log` line: <job>\t<step>\t<timestamp> <text>.  The third part must start
# with a timestamp, so a raw log line that contains tabs is not read as a job prefix.
_TIMESTAMP = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z"
_JOB_PREFIX = re.compile(r"^(?P<job>[^\t\n]+)\t[^\t\n]*\t(?=" + _TIMESTAMP + r"(?: |$))")
_TIMESTAMP_PREFIX = re.compile(r"^" + _TIMESTAMP + r" ?")

_ERROR_LEAD = r"(?:##\[error\]|::error::)"
PG_ENV_LINE = re.compile(r"^" + _ERROR_LEAD + r"\[" + re.escape(PG_ENV_LABEL) + r"\] PG-ENV [^\s]")
NO_SLOT_LINE = re.compile(
    r"^(?:##\[error\]|::error title=infra no-slot::)" + SEMAPHORE_TAG
    + r" '[^'\n]*': infra-no-slot: no slot free after \d+s "
    r"\(all \d+ slots busy on this host, (?:\d+|unknown) serving runners\)"
)
UNKNOWN_RUNNER_LINE = re.compile(
    r"^(?:##\[error\]|::error title=infra unknown-runner::)" + SEMAPHORE_TAG
    + r" '[^'\n]*': infra-unknown-runner: runner '[^'\n]*' is not a serving runner of gate"
)
SLOT_ACQUIRED_LINE = re.compile(r"^" + SEMAPHORE_TAG + r" '[^'\n]*': slot-acquired$")

# Failure evidence is searched anywhere in a line: a hit only ever blocks a soft class.
FAILURE_EVIDENCE = re.compile(
    r"test result: FAILED|error: test failed|could not compile|panicked at|(?:^|\s)FAIL \["
)

_NO_JOB = ""


def _split_jobs(log_text: str) -> dict[str, list[str]]:
    """Normalised lines (job prefix and timestamp removed) per job, in first-seen order."""
    jobs: dict[str, list[str]] = {}
    current = _NO_JOB
    for raw in log_text.lstrip("\ufeff").splitlines():
        match = _JOB_PREFIX.match(raw)
        if match:
            current = match.group("job")
            raw = raw[match.end():]
        jobs.setdefault(current, []).append(_TIMESTAMP_PREFIX.sub("", raw, count=1))
    return jobs


def _classify_lines(lines: list[str]) -> tuple[str | None, bool]:
    """(class, failed) of one job: failed is True when failure evidence is in the job."""
    ci_env = no_slot = unknown_runner = acquired = failed = False
    for line in lines:
        if PG_ENV_LINE.match(line):
            ci_env = True
        elif NO_SLOT_LINE.match(line):
            no_slot = True
        elif UNKNOWN_RUNNER_LINE.match(line):
            unknown_runner = True
        elif SLOT_ACQUIRED_LINE.match(line):
            acquired = True
        if FAILURE_EVIDENCE.search(line):
            failed = True
    if ci_env:
        return CLASS_CI_ENV, failed
    if failed or acquired:
        return None, failed
    if no_slot:
        return CLASS_INFRA_NO_SLOT, failed
    if unknown_runner:
        return CLASS_INFRA_UNKNOWN_RUNNER, failed
    return None, failed


def classify_jobs(log_text: str) -> dict[str, str | None]:
    """The class of every job of a run log, keyed by job name (the empty name for an unsplit log)."""
    return {job: _classify_lines(lines)[0] for job, lines in _split_jobs(log_text).items()}


def classify(log_text: str) -> str | None:
    """Return the CI class for the log text, or None when no rule matches (see the module docstring)."""
    results = [_classify_lines(lines) for lines in _split_jobs(log_text).values()]
    classes = [cls for cls, _ in results]
    if CLASS_CI_ENV in classes:
        return CLASS_CI_ENV
    if any(failed for _, failed in results):
        return None
    for cls in classes:
        if cls is not None:
            return cls
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument("logfile", nargs="?", help="log file (stdin when omitted)")
    args = parser.parse_args(argv)
    if args.logfile:
        text = Path(args.logfile).read_text(encoding="utf-8", errors="replace")
    else:
        text = sys.stdin.read()
    print(f"CI-CLASS: {classify(text) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
