#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Check that hosted-PostgreSQL workflows run the PG preflight first (#9235).

For each workflow given (default: every workflow in `DEFAULT_WORKFLOWS`),
fail unless:
  * a step calls `scripts/ci/pg_env_preflight.py`;
  * that step is placed BEFORE the first step that runs the coverage or
    test command (`cargo llvm-cov` / `cargo test` / `cargo nextest`);
  * that step carries no `continue-on-error` and no `if:` (it can never be
    skipped or waved through);
  * the enclosing job has no job-level `continue-on-error`.

The workflow YAML is scanned line by line (standard library only): a step
starts at a `- name:` / `- uses:` / `- run:` line at the steps indent.

Exit codes: 0 all clean, 1 at least one problem, 2 usage error.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


def _load_workflow_annotation():
    """The shared module at WA_RELATIVE_PATH from this file's real directory, by path only, never through
    sys.path; every name in WA_REQUIRED must be a callable of it (#9365, one shape in every script)."""
    import importlib.util
    import os
    path = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), WA_RELATIVE_PATH))
    loaded = sys.modules.get("workflow_annotation")
    if loaded is not None and os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
        module = loaded
    else:
        spec = importlib.util.spec_from_file_location("workflow_annotation", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # absent, unreadable or broken: it raises here, the try below catches it
    missing = [name for name in WA_REQUIRED if not callable(getattr(module, name, None))]
    if missing:
        raise AttributeError("workflow_annotation.py lacks " + ", ".join(missing))
    if loaded is None:
        sys.modules["workflow_annotation"] = module
    return module


# The one shared-module load shape of scripts/ (#9365, ruling bcd0a15c; LoaderShape pins it).
WA_PROG = "check_pg_preflight_workflows"
WA_RELATIVE_PATH = "workflow_annotation.py"
WA_REQUIRED = ("out",)
WA_EXIT_LOAD_REFUSED = 3  # a failed shared-module load; no other meaning in this script
WA_ERROR_TO_STDERR = False

try:
    wa = _load_workflow_annotation()
except (Exception, SystemExit) as exc:  # any failed load: one fixed line built without the module, then exit
    wa_cause = type(exc).__name__
    print("%s: refused: shared module workflow_annotation.py next to the script cannot be loaded (%s)"
          % (WA_PROG, wa_cause if wa_cause.isidentifier() else "BaseException"), file=sys.stderr, flush=True)
    print("::error title=check_pg_preflight_workflows refused::check_pg_preflight_workflows: refused: shared module workflow_annotation.py"
          " next to the script cannot be loaded",
          file=sys.stderr if WA_ERROR_TO_STDERR else sys.stdout, flush=True)
    sys.exit(WA_EXIT_LOAD_REFUSED)

PREFLIGHT_SCRIPT = "scripts/ci/pg_env_preflight.py"
TEST_COMMAND = re.compile(r"\bcargo\s+(?:llvm-cov|test|nextest)\b")
STEP_START = re.compile(r"^(\s*)- (?:name|uses|run|id|if|env|with):")
STEPS_KEY = re.compile(r"^(\s*)steps:\s*$")
JOB_KEY = re.compile(r"^  [A-Za-z0-9_-]+:\s*$")
KEY_LINE = re.compile(r"^\s*(?:- )?(continue-on-error|if):")
DEFAULT_WORKFLOWS = (".github/workflows/coverage.yml",)
EXIT_CLEAN = 0
EXIT_PROBLEMS = 1


@dataclass(frozen=True)
class Step:
    job: str
    index: int
    name: str
    lines: tuple[str, ...]

    def code_lines(self) -> list[str]:
        return [ln for ln in self.lines if not ln.lstrip().startswith("#")]


def _job_name(job_line: str) -> str:
    return job_line.strip().rstrip(":")


def parse_steps(text: str) -> tuple[list[Step], dict[str, list[str]]]:
    """Return every step plus the pre-`steps:` lines of each job."""
    steps: list[Step] = []
    job_head: dict[str, list[str]] = {}
    job = ""
    in_steps = False
    steps_indent = -1
    cur: list[str] = []
    cur_name = ""
    idx = 0

    def flush() -> None:
        nonlocal cur, idx
        if cur:
            steps.append(Step(job, idx, cur_name, tuple(cur)))
            idx += 1
        cur = []

    for line in text.splitlines():
        if JOB_KEY.match(line):
            flush()
            job = _job_name(line)
            job_head[job] = []
            in_steps = False
            idx = 0
            continue
        m = STEPS_KEY.match(line)
        if m and job:
            flush()
            in_steps = True
            steps_indent = len(m.group(1))
            continue
        if not in_steps:
            if job:
                job_head[job].append(line)
            continue
        m = STEP_START.match(line)
        if m and len(m.group(1)) == steps_indent + 2:
            flush()
            cur_name = line.split(":", 1)[1].strip() if "name:" in line else ""
        cur.append(line)
    flush()
    return steps, job_head


def check_text(text: str, label: str) -> list[str]:
    """Return the problems found in one workflow's text."""
    steps, job_head = parse_steps(text)
    problems: list[str] = []
    preflight = [s for s in steps if PREFLIGHT_SCRIPT in "\n".join(s.code_lines())]
    if not preflight:
        return [f"{label}: preflight step ({PREFLIGHT_SCRIPT}) is absent"]
    for pf in preflight:
        for ln in pf.code_lines():
            m = KEY_LINE.match(ln)
            if m:
                problems.append(
                    f"{label}: preflight step '{pf.name}' carries `{m.group(1)}`"
                )
        for ln in job_head.get(pf.job, []):
            if re.match(r"^    continue-on-error:", ln):
                problems.append(f"{label}: job '{pf.job}' carries job-level continue-on-error")
        tests = [
            s
            for s in steps
            if s.job == pf.job and s is not pf and TEST_COMMAND.search("\n".join(s.code_lines()))
        ]
        earliest = min((s.index for s in tests), default=None)
        if earliest is not None and pf.index > earliest:
            problems.append(
                f"{label}: preflight step '{pf.name}' (#{pf.index}) is placed after the"
                f" coverage/test step (#{earliest})"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument("workflows", nargs="*", help="workflow files to check")
    args = parser.parse_args(argv)
    problems: list[str] = []
    for wf in args.workflows or DEFAULT_WORKFLOWS:
        path = Path(wf)
        if not path.is_file():
            problems.append(f"{wf}: workflow file not found")
            continue
        problems.extend(check_text(path.read_text(encoding="utf-8"), wf))
    for p in problems:
        wa.out(f"PROBLEM {p}")
    wa.out(f"problems={len(problems)}")
    return EXIT_PROBLEMS if problems else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
