#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the self-hosted runner target-dir hygiene of every cargo-test job (#6118).

THE DEFECT (#6118).  On the f2 host each self-hosted runner's persistent
``_work/ai-memory-mcp/ai-memory-mcp/target`` reached 164 GB after ONE full
``cargo test`` build (1001 test executables of ~170 MB in ``debug/deps``) and no
step removed them, so two runners took the root filesystem from 224 GB to 78 GB
free in two hours; a parallel pair of fresh builds would have hit ENOSPC
mid-job.  The persistent ``target/`` IS the fleet's warm cache (#3128), but the
test executables are not cache: cargo relinks every one of them whenever the lib
crate changes, i.e. on every commit, so keeping them past the job buys nothing.

RULES ENFORCED, for every job that runs cargo on a self-hosted label (closed
world: a workflow file the reader cannot read is a FAILURE, never a skip):
  R-CENSUS the set of (workflow, job) pairs that run ``cargo`` on a
           ``self-hosted`` label is exactly EXPECTED_SELF_HOSTED_CARGO_JOBS, so
           a new self-hosted cargo job cannot appear without being pinned here.
  R-DEBUG  the effective env (workflow ``env:`` overlaid by job ``env:``) sets
           BOTH ``CARGO_PROFILE_DEV_DEBUG`` and ``CARGO_PROFILE_TEST_DEBUG`` to
           ``0`` (the pair rule of #3461: ``test`` only inherits ``dev`` while
           nothing overrides it; one value for every self-hosted job so the
           shared persistent ``target/`` holds ONE artifact tree, not one per
           debuginfo level).  ``0``, not ``line-tables-only``: the check job
           ALREADY ran at ``line-tables-only`` when it wrote the 164 GB, and a
           sandbox measurement (2026-10-09, lib unit-test binary + one
           integration test binary) put the integration test binary at 130 MB
           at ``line-tables-only`` and 11.6 MB at ``0`` (11x); the ~1000
           integration binaries are what fill the disk.  Nothing in CI reads
           line tables: no workflow, script or test sets RUST_BACKTRACE, panic
           locations are compile-time strings, and the hosted sqlite leg and
           both pg jobs have run the full suites at ``0`` since #3461 / #3274.
  R-PRUNE  the job's LAST step is named PRUNE_STEP_NAME, runs under
           ``if: always()`` (a red or cancelled test run leaves the same
           binaries behind), is skipped on GitHub-hosted runners when the job
           can land on one, carries the ``docs_only`` guard when its siblings do
           (rule (b3) of scripts/check-required-contexts.sh), and runs
           ``python3 scripts/ci/prune-runner-target.py --target-dir ...``.

The prune script itself is exercised below against a fake target tree built
under ``<repo>/.local-runs`` (never /tmp, project hard rule): it must refuse a
directory that is not a cargo target dir, delete only test/example executables
(+ their ``.d`` and ``.dSYM`` companions) and ``incremental/`` by default, keep
the rlib/rmeta/proc-macro outputs, ``build/`` and ``.fingerprint/`` that make
the next compile warm, never follow a symlink, report the bytes it freed, and
wipe the five artifact dirs under ``--scope all``.

The workflow reader is the Python standard library only (no PyYAML), the same
approach as scripts/test/test_workflow_pr_triggers_5447.py.  The mutation legs
at the bottom prove the rules are not vacuous: each mutant of the LIVE ci.yml
must be rejected, and the unmutated control must be accepted first.

Run:  python3 scripts/test/test_ci_runner_target_hygiene_6118.py
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
PRUNE_SCRIPT = ROOT / "scripts" / "ci" / "prune-runner-target.py"
LOCAL_RUNS = ROOT / ".local-runs"

PRUNE_STEP_NAME = "Prune runner target dir (#6118)"
PRUNE_INVOCATION = "python3 scripts/ci/prune-runner-target.py"
# The exact step body every self-hosted job runs (honours a runner-side
# CARGO_TARGET_DIR override, else the workspace default `target`).
PRUNE_RUN_LINE = '        run: python3 scripts/ci/prune-runner-target.py --target-dir "${CARGO_TARGET_DIR:-target}"'
DEBUG_LEVEL = "0"
DEBUG_KEYS = ("CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG")
HOSTED_GUARD = "runner.environment != 'github-hosted'"
DOCS_ONLY_GUARD = "docs_only"
# S-F4 (round 2): the prune step runs the CHECKED-OUT script, so it must not run
# when this job's checkout was skipped (fork-PR refusal) or failed: the
# persistent workspace would otherwise hand it the previous job's copy.
CHECKOUT_STEP_ID = "checkout"
CHECKOUT_GUARD = "steps.checkout.outcome == 'success'"
CARGO_RE = re.compile(r"(^|[\s;&|(])cargo\s+(test|build|llvm-cov|bench|nextest)\b")

# Every (workflow, job) that runs cargo on a self-hosted label, pinned.  A new
# self-hosted cargo job must be added here AND given the two rules above.
EXPECTED_SELF_HOSTED_CARGO_JOBS = frozenset({
    ("cert-postgres-age.yml", "cert-postgres-age"),
    ("ci.yml", "check"),
    ("postgres-ignored.yml", "postgres-ignored"),
    ("session-boot-lifetime.yml", "lifetime-tests"),
})


class Unparsed(Exception):
    """Raised when the reader cannot interpret a workflow (a FAILURE, never a skip)."""


class Step:
    def __init__(self) -> None:
        self.name = ""
        self.cond = ""
        self.uses = ""
        self.step_id = ""
        self.run: List[str] = []

    def run_text(self) -> str:
        return "\n".join(self.run)


class Job:
    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        self.runs_on = ""
        self.env: Dict[str, str] = {}
        self.matrix_runners: List[str] = []
        self.steps: List[Step] = []

    def self_hosted(self) -> bool:
        if "self-hosted" in self.runs_on:
            return True
        return any("self-hosted" in r for r in self.matrix_runners)

    def runs_cargo(self) -> bool:
        return any(CARGO_RE.search(line) for s in self.steps for line in s.run)

    def can_be_hosted(self) -> bool:
        """True when the job's runs-on is matrix-driven (some legs may be GitHub-hosted)."""
        return "fromJSON" in self.runs_on or "matrix." in self.runs_on


class Workflow:
    def __init__(self) -> None:
        self.env: Dict[str, str] = {}
        self.jobs: Dict[str, Job] = {}


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_comment(text: str) -> str:
    """Drop a trailing ``# comment`` outside quotes and trailing white space."""
    out: List[str] = []
    quote: Optional[str] = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip(" \t\r")


def _unquote(value: str) -> str:
    value = value.strip(" ")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


_KEY_ROW = re.compile(r"^(- )?([A-Za-z_][A-Za-z0-9_.-]*):(?: (.*))?$")


def _split_key(content: str) -> Tuple[bool, str, str]:
    """(is sequence entry, key, raw value) for a ``key: value`` row, or key ''."""
    m = _KEY_ROW.match(content)
    if not m:
        return content.startswith("- "), "", content
    return m.group(1) is not None, m.group(2), (m.group(3) or "")


def _env_block(lines: List[Tuple[int, str, str]], start: int, indent: int) -> Tuple[Dict[str, str], int]:
    """Read ``KEY: value`` rows deeper than ``indent`` from ``start``; return (env, next index)."""
    env: Dict[str, str] = {}
    i = start
    while i < len(lines) and lines[i][0] > indent:
        _dash, key, value = _split_key(lines[i][1])
        if not key or value.endswith("|") or value.endswith(">"):
            raise Unparsed("env row is not KEY: value at line %d: %r" % (lines[i][2], lines[i][1]))
        env[key] = _unquote(_strip_comment(value))
        i += 1
    return env, i


def read_workflow(text: str) -> Workflow:
    """Read the top-level env and every job's runs-on / env / matrix runners / steps.

    Structure rows are (indent, content, 1-based line number) with blank and
    comment lines dropped; block-scalar bodies of ``run:`` are collected from
    the RAW lines so the cargo invocations are seen verbatim.
    """
    raw = text.split("\n")
    rows: List[Tuple[int, str, int]] = []
    for n, line in enumerate(raw, 1):
        lead = line[: len(line) - len(line.lstrip(" \t"))]
        if "\t" in lead:
            raise Unparsed("tab indentation at line %d" % n)
        content = line.rstrip("\r")
        if not content.strip() or content.lstrip(" ").startswith("#"):
            continue
        rows.append((_indent(content), content[_indent(content):], n))
    wf = Workflow()
    i = 0
    while i < len(rows):
        ind, content, _n = rows[i]
        if ind != 0:
            i += 1
            continue
        _dash, key, value = _split_key(content)
        if key == "env" and not value.strip():
            wf.env, i = _env_block(rows, i + 1, 0)
            continue
        if key == "jobs":
            i = _read_jobs(wf, rows, raw, i + 1)
            continue
        i += 1
    if not wf.jobs:
        raise Unparsed("no jobs: block with at least one job")
    return wf


def _read_jobs(wf: Workflow, rows: List[Tuple[int, str, int]], raw: List[str], start: int) -> int:
    i = start
    job_indent = rows[i][0] if i < len(rows) else 0
    if job_indent == 0:
        raise Unparsed("jobs: block is empty")
    while i < len(rows) and rows[i][0] >= job_indent:
        ind, content, n = rows[i]
        if ind != job_indent:
            raise Unparsed("row at line %d is not at the job-id column" % n)
        dash, job_id, value = _split_key(content)
        if dash or not job_id or value.strip():
            raise Unparsed("job row at line %d is not `<id>:`: %r" % (n, content))
        job = Job(job_id)
        i += 1
        while i < len(rows) and rows[i][0] > job_indent:
            kind, kcontent, kn = rows[i]
            if kind != job_indent + 2:
                i += 1
                continue
            _d, key, val = _split_key(kcontent)
            if key == "runs-on":
                job.runs_on = _strip_comment(val)
                i += 1
            elif key == "env" and not val.strip():
                job.env, i = _env_block(rows, i + 1, kind)
            elif key == "strategy":
                i += 1
                while i < len(rows) and rows[i][0] > kind:
                    _sd, skey, sval = _split_key(rows[i][1])
                    if skey == "runner":
                        job.matrix_runners.append(_unquote(_strip_comment(sval)))
                    i += 1
            elif key == "steps":
                i = _read_steps(job, rows, raw, i + 1, kind)
            else:
                i += 1
        wf.jobs[job_id] = job
    return i


def _read_steps(job: Job, rows: List[Tuple[int, str, int]], raw: List[str], start: int, steps_indent: int) -> int:
    i = start
    step: Optional[Step] = None
    step_col: Optional[int] = None  # column of the `- ` that opens each step
    key_col = 0  # column of the current step's own keys
    while i < len(rows) and rows[i][0] > steps_indent:
        ind, content, n = rows[i]
        dash, key, value = _split_key(content)
        if dash and (step_col is None or ind == step_col):
            step_col = ind
            step = Step()
            job.steps.append(step)
            key_col = ind + 2
        elif dash or ind != key_col:
            # A deeper row (a `with:` mapping, a step `env:`, a run-body line that
            # happens to look like `key: value` or `- item`) is not a step key.
            i += 1
            continue
        if step is None:
            raise Unparsed("step key before the first `- ` at line %d" % n)
        if key == "name":
            step.name = _unquote(_strip_comment(value))
        elif key == "if":
            step.cond = _strip_comment(value)
        elif key == "uses":
            step.uses = _strip_comment(value)
        elif key == "id":
            step.step_id = _unquote(_strip_comment(value))
        elif key == "run":
            header = _strip_comment(value)
            if header in ("|", "|-", "|+", ">", ">-", ">+"):
                # Block scalar: raw lines after row n indented deeper than the key.
                j = n  # raw index of the line AFTER the header (raw is 0-based, n is 1-based)
                while j < len(raw):
                    line = raw[j].rstrip("\r")
                    if line.strip() == "":
                        step.run.append("")
                        j += 1
                        continue
                    if _indent(line) <= key_col:
                        break
                    step.run.append(line.strip())
                    j += 1
            else:
                step.run.append(_unquote(header))
        i += 1
    return i


def load_all() -> Dict[str, str]:
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    return {p.name: p.read_text(encoding="utf-8") for p in files}


def self_hosted_cargo_jobs(workflows: Dict[str, str]) -> Dict[Tuple[str, str], Tuple[Workflow, Job]]:
    found: Dict[Tuple[str, str], Tuple[Workflow, Job]] = {}
    for name, text in workflows.items():
        wf = read_workflow(text)
        for job_id, job in wf.jobs.items():
            if job.self_hosted() and job.runs_cargo():
                found[(name, job_id)] = (wf, job)
    return found


def violations(name: str, wf: Workflow, job: Job) -> List[str]:
    """Every R-DEBUG / R-PRUNE violation for one self-hosted cargo job."""
    found: List[str] = []
    where = "%s job %s" % (name, job.job_id)
    effective = dict(wf.env)
    effective.update(job.env)
    for key in DEBUG_KEYS:
        got = effective.get(key)
        if got != DEBUG_LEVEL:
            found.append("%s: R-DEBUG %s is %r, want %r" % (where, key, got, DEBUG_LEVEL))
    if not job.steps:
        found.append("%s: R-PRUNE job has no steps" % where)
        return found
    last = job.steps[-1]
    if last.name != PRUNE_STEP_NAME:
        found.append("%s: R-PRUNE last step is %r, want %r" % (where, last.name, PRUNE_STEP_NAME))
        return found
    if "always()" not in last.cond:
        found.append("%s: R-PRUNE prune step `if:` lacks always(): %r" % (where, last.cond))
    if job.can_be_hosted() and HOSTED_GUARD not in last.cond:
        found.append("%s: R-PRUNE prune step `if:` lacks %s on a matrix-placed job" % (where, HOSTED_GUARD))
    siblings_guarded = any(DOCS_ONLY_GUARD in s.cond for s in job.steps[:-1])
    if siblings_guarded and DOCS_ONLY_GUARD not in last.cond:
        found.append("%s: R-PRUNE prune step `if:` lacks the docs_only guard its siblings carry (rule (b3))" % where)
    if not any(s.uses.startswith("actions/checkout@") and s.step_id == CHECKOUT_STEP_ID for s in job.steps[:-1]):
        found.append("%s: R-PRUNE no `actions/checkout` step with `id: %s` before the prune step" % (where, CHECKOUT_STEP_ID))
    if CHECKOUT_GUARD not in last.cond:
        found.append("%s: R-PRUNE prune step `if:` lacks %s (S-F4)" % (where, CHECKOUT_GUARD))
    run = last.run_text()
    if PRUNE_INVOCATION not in run or "--target-dir" not in run:
        found.append("%s: R-PRUNE prune step does not run `%s --target-dir ...`: %r" % (where, PRUNE_INVOCATION, run))
    return found


def all_violations(workflows: Dict[str, str]) -> List[str]:
    found: List[str] = []
    try:
        jobs = self_hosted_cargo_jobs(workflows)
    except Unparsed as exc:
        return ["R-SHAPE cannot read a workflow (%s)" % exc]
    census = frozenset(jobs)
    for missing in sorted(EXPECTED_SELF_HOSTED_CARGO_JOBS - census):
        found.append("R-CENSUS expected self-hosted cargo job %s/%s not found" % missing)
    for extra in sorted(census - EXPECTED_SELF_HOSTED_CARGO_JOBS):
        found.append("R-CENSUS unpinned self-hosted cargo job %s/%s (add it to EXPECTED_SELF_HOSTED_CARGO_JOBS)" % extra)
    for (name, _job_id), (wf, job) in sorted(jobs.items()):
        found.extend(violations(name, wf, job))
    return found


def _replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) < 1:
        raise AssertionError("mutation anchor not found: " + old)
    return text.replace(old, new, 1)


class LiveWorkflows6118(unittest.TestCase):
    def test_6118_live_workflows_clean(self) -> None:
        found = all_violations(load_all())
        self.assertEqual([], found, "\n".join(found))

    def test_6118_census_matches_live_runs_on(self) -> None:
        # The census is derived from the live files, so a job moving on or off
        # the fleet shows up here before the rules are even applied.
        jobs = self_hosted_cargo_jobs(load_all())
        self.assertEqual(EXPECTED_SELF_HOSTED_CARGO_JOBS, frozenset(jobs))
        check = jobs[("ci.yml", "check")][1]
        self.assertTrue(check.can_be_hosted(), check.runs_on)
        self.assertIn('["self-hosted","linux-fed"]', check.matrix_runners)


class Mutants6118(unittest.TestCase):
    """Each mutant of the LIVE ci.yml must be rejected (the rules are not vacuous)."""

    def setUp(self) -> None:
        self.live = load_all()
        self.ci = self.live["ci.yml"]

    def _mutated(self, text: str) -> List[str]:
        files = dict(self.live)
        files["ci.yml"] = text
        return all_violations(files)

    def test_6118_control_unmutated_is_clean(self) -> None:
        self.assertEqual([], self._mutated(self.ci))

    def test_6118_m01_rename_prune_step(self) -> None:
        mutant = _replace_once(self.ci, "- name: " + PRUNE_STEP_NAME, "- name: Prune (renamed)")
        found = self._mutated(mutant)
        self.assertTrue(any("R-PRUNE last step is" in v for v in found), found)

    def test_6118_m02_debug_level_line_tables(self) -> None:
        # The check job's env rows are the quoted form `"0"`; the reader unquotes.
        anchor = 'CARGO_PROFILE_DEV_DEBUG: "0"'
        self.assertEqual(1, self.ci.count(anchor), anchor)
        mutant = _replace_once(self.ci, anchor, "CARGO_PROFILE_DEV_DEBUG: line-tables-only")
        found = self._mutated(mutant)
        self.assertTrue(any("R-DEBUG CARGO_PROFILE_DEV_DEBUG is 'line-tables-only'" in v for v in found), found)

    def test_6118_m02b_debug_pair_half_set(self) -> None:
        # Only DEV set: the `test` profile would still inherit it today, but the
        # #3461 pair rule says both are stated wherever either is, so the pair
        # can never drift apart.
        anchor = 'CARGO_PROFILE_TEST_DEBUG: "0"'
        self.assertEqual(1, self.ci.count(anchor), anchor)
        mutant = _replace_once(self.ci, anchor, "CARGO_PROFILE_TEST_DEBUG_UNSET: x")
        found = self._mutated(mutant)
        self.assertTrue(any("R-DEBUG CARGO_PROFILE_TEST_DEBUG is None" in v for v in found), found)

    def test_6118_m03_drop_always(self) -> None:
        anchor = "if: always() && needs.classify.outputs.docs_only != 'true' && " + HOSTED_GUARD
        self.assertIn(anchor, self.ci)
        mutant = _replace_once(self.ci, anchor, "if: needs.classify.outputs.docs_only != 'true' && " + HOSTED_GUARD)
        found = self._mutated(mutant)
        self.assertTrue(any("lacks always()" in v for v in found), found)

    def test_6118_m04_drop_hosted_guard(self) -> None:
        anchor = "if: always() && needs.classify.outputs.docs_only != 'true' && " + HOSTED_GUARD
        mutant = _replace_once(self.ci, anchor, "if: always() && needs.classify.outputs.docs_only != 'true'")
        found = self._mutated(mutant)
        self.assertTrue(any("lacks " + HOSTED_GUARD in v for v in found), found)

    def test_6118_m05_a_step_after_the_prune_step(self) -> None:
        # Any step after the prune step in the `check` job makes it no longer last.
        anchor = PRUNE_RUN_LINE
        self.assertEqual(1, self.ci.count(anchor), anchor)
        mutant = _replace_once(self.ci, anchor, anchor + "\n      - name: Something after the prune\n        run: echo later")
        found = self._mutated(mutant)
        self.assertTrue(any("R-PRUNE last step is 'Something after the prune'" in v for v in found), found)

    def test_6118_m06_new_self_hosted_cargo_job_is_unpinned(self) -> None:
        # `jobs:` is the last top-level block of ci.yml, so a job appended at the
        # end of the file is read as a job.
        mutant = self.ci.rstrip("\n") + (
            "\n  extra_fleet_job:\n    runs-on: [self-hosted, linux-fed]\n    steps:\n"
            "      - run: cargo test --lib\n"
        )
        found = self._mutated(mutant)
        self.assertTrue(any("R-CENSUS unpinned self-hosted cargo job ci.yml/extra_fleet_job" in v for v in found), found)

    def test_6118_m07_unreadable_file_is_a_failure(self) -> None:
        found = self._mutated("name: x\n\ton: push\n")
        self.assertTrue(found and found[0].startswith("R-SHAPE"), found)

    # ---- round 2 (C-F1): workflow shapes the round-1 reader let through ----

    def _appended(self, job_yaml: str) -> List[str]:
        return self._mutated(self.ci.rstrip("\n") + "\n" + job_yaml)

    def _before_prune(self, step_yaml: str) -> List[str]:
        anchor = "      - name: " + PRUNE_STEP_NAME + "\n"
        self.assertEqual(1, self.ci.count(anchor), anchor)
        return self._mutated(_replace_once(self.ci, anchor, step_yaml + anchor))

    def _assert_unpinned(self, found: List[str], job_id: str) -> None:
        self.assertTrue(any(v.startswith("R-CENSUS unpinned self-hosted") and ("ci.yml/" + job_id) in v
                            for v in found), found)

    def test_6118_m08_block_sequence_runs_on(self) -> None:
        found = self._appended(
            "  extra_block_seq_job:\n    runs-on:\n      - self-hosted\n      - linux-fed\n"
            "    steps:\n      - run: cargo test --all-targets\n")
        self._assert_unpinned(found, "extra_block_seq_job")

    def test_6118_m09_self_hosted_label_under_matrix_os_via_fromjson(self) -> None:
        found = self._appended(
            "  extra_matrix_os_job:\n    strategy:\n      matrix:\n        include:\n"
            "          - os: '[\"ubuntu-latest\"]'\n          - os: '[\"self-hosted\",\"linux-fed\"]'\n"
            "    runs-on: ${{ fromJSON(matrix.os) }}\n    steps:\n      - run: cargo test --lib\n")
        self._assert_unpinned(found, "extra_matrix_os_job")

    def test_6118_m09b_fleet_label_without_self_hosted_literal(self) -> None:
        # A fleet label alone routes to the fleet; it is not a GitHub-hosted image.
        found = self._appended(
            "  extra_matrix_label_job:\n    strategy:\n      matrix:\n        os: [ubuntu-latest, macos-fed]\n"
            "    runs-on: ${{ matrix.os }}\n    steps:\n      - run: cargo build\n")
        self._assert_unpinned(found, "extra_matrix_label_job")

    def test_6118_m10_cargo_through_a_script(self) -> None:
        found = self._appended(
            "  extra_script_job:\n    runs-on: [self-hosted, linux-fed]\n"
            "    steps:\n      - run: scripts/coverage.sh\n")
        self._assert_unpinned(found, "extra_script_job")

    def test_6118_m11_debug_override_written_to_github_env(self) -> None:
        found = self._before_prune(
            "      - name: Raise debuginfo\n"
            "        run: echo \"CARGO_PROFILE_DEV_DEBUG=line-tables-only\" >> \"$GITHUB_ENV\"\n")
        self.assertTrue(any("R-DEBUG" in v and "line-tables-only" in v for v in found), found)

    def test_6118_m11b_debug_override_in_a_block_run_group(self) -> None:
        found = self._before_prune(
            "      - name: Raise test debuginfo\n        run: |\n          {\n"
            "            echo \"CARGO_PROFILE_TEST_DEBUG=1\"\n          } >> \"$GITHUB_ENV\"\n")
        self.assertTrue(any("R-DEBUG" in v and "CARGO_PROFILE_TEST_DEBUG" in v and "'1'" in v for v in found), found)

    def test_6118_m12_runs_on_mapping_form_is_unparsed(self) -> None:
        found = self._appended(
            "  extra_group_job:\n    runs-on:\n      group: fleet\n    steps:\n      - run: echo hi\n")
        self.assertTrue(found and found[0].startswith("R-SHAPE"), found)

    def test_6118_m13_prune_without_checkout_guard(self) -> None:
        anchor = "&& " + HOSTED_GUARD + " && " + CHECKOUT_GUARD
        self.assertEqual(1, self.ci.count(anchor), anchor)
        found = self._mutated(_replace_once(self.ci, anchor, "&& " + HOSTED_GUARD))
        self.assertTrue(any("lacks " + CHECKOUT_GUARD in v for v in found), found)

    def test_6118_m14_step_level_env_debug_override(self) -> None:
        found = self._before_prune(
            "      - name: Step env override\n        env:\n          CARGO_PROFILE_TEST_DEBUG: line-tables-only\n"
            "        run: cargo test --no-run\n")
        self.assertTrue(any("R-DEBUG" in v and "line-tables-only" in v for v in found), found)

    def test_6118_m15_unknown_runs_on_expression_is_unparsed(self) -> None:
        found = self._appended(
            "  extra_expr_job:\n    runs-on: ${{ inputs.runner }}\n    steps:\n      - run: echo hi\n")
        self.assertTrue(found and found[0].startswith("R-SHAPE"), found)


def _write(path: Path, size: int, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _tree_size(root: Path) -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            total += os.lstat(os.path.join(dirpath, f)).st_size
    return total


class PruneScript6118(unittest.TestCase):
    """scripts/ci/prune-runner-target.py against a fake cargo target tree."""

    # (relative path, size, executable, deleted by default scope)
    LAYOUT = (
        ("CACHEDIR.TAG", 10, False, False),
        ("debug/.cargo-lock", 0, False, False),
        ("debug/ai-memory", 700, True, False),  # uplifted bin, kept
        ("debug/deps/libai_memory-0a1b.rlib", 5000, False, False),
        ("debug/deps/libai_memory-0a1b.rmeta", 400, False, False),
        ("debug/deps/libai_memory-0a1b.d", 30, False, False),
        ("debug/deps/libserde_derive-9f9f.so", 900, True, False),  # proc-macro dylib, kept
        ("debug/deps/ai_memory-0a1b", 170000, True, True),  # lib test executable
        ("debug/deps/ai_memory-0a1b.d", 50, False, True),
        ("debug/deps/mcp_input_schema-7c7c", 120000, True, True),  # integration test executable
        ("debug/deps/mcp_input_schema-7c7c.d", 40, False, True),
        ("debug/deps/mcp_input_schema-7c7c.dSYM/Contents/Resources/DWARF/mcp", 2000, False, True),
        ("debug/build/libsqlite3-sys-3d3d/out/sqlite3.o", 3000, False, False),
        ("debug/build/libsqlite3-sys-3d3d/output", 20, False, False),
        ("debug/.fingerprint/ai-memory-0a1b/lib-ai_memory", 8, False, False),
        ("debug/incremental/ai_memory-xyz/s-abc-def-working/dep-graph.bin", 6000, False, True),
        ("debug/examples/demo-1e1e", 50000, True, True),
        ("debug/examples/demo-1e1e.d", 10, False, True),
        ("release/deps/ai_memory-ffff", 900, True, False),  # other profile, untouched
    )
    FIVE_DIRS = ("deps", "build", "incremental", "examples", ".fingerprint")

    def setUp(self) -> None:
        LOCAL_RUNS.mkdir(exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(prefix="prune-6118-", dir=str(LOCAL_RUNS))
        self.addCleanup(self.scratch.cleanup)
        self.target = Path(self.scratch.name) / "target"
        for rel, size, exe, _deleted in self.LAYOUT:
            _write(self.target / rel, size, exe)
        # A symlink inside deps that points OUTSIDE the target dir; it looks
        # like an executable (the link target is executable) and must be
        # skipped, never followed.
        self.outside = Path(self.scratch.name) / "outside-exe"
        _write(self.outside, 777, True)
        (self.target / "debug" / "deps" / "evil-link").symlink_to(self.outside)

    def _run(self, *args: str, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
        base = {k: v for k, v in os.environ.items() if k not in ("GITHUB_WORKSPACE", "CARGO_TARGET_DIR")}
        base.update(env or {})
        return subprocess.run(
            [sys.executable, "-I", str(PRUNE_SCRIPT), *args],
            cwd=str(ROOT), capture_output=True, text=True, check=False, env=base,
        )

    def _expected_freed(self) -> int:
        return sum(size for _rel, size, _exe, deleted in self.LAYOUT if deleted)

    def _freed(self, out: str) -> int:
        m = re.search(r"^freed_bytes=(\d+)$", out, re.MULTILINE)
        self.assertIsNotNone(m, out)
        return int(m.group(1))

    def test_6118_script_exists_and_is_python3_stdlib(self) -> None:
        self.assertTrue(PRUNE_SCRIPT.is_file(), str(PRUNE_SCRIPT))
        text = PRUNE_SCRIPT.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/usr/bin/env python3"), text[:40])
        self.assertNotIn("shell=True", text)
        self.assertNotIn("\nmatch ", text)

    def test_6118_refuses_non_target_dir(self) -> None:
        plain = Path(self.scratch.name) / "not-a-target"
        (plain / "debug" / "deps").mkdir(parents=True)
        _write(plain / "debug" / "deps" / "x-1111", 10, True)
        proc = self._run("--target-dir", str(plain))
        self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("refusing", proc.stderr)
        self.assertTrue((plain / "debug" / "deps" / "x-1111").exists())

    def test_6118_missing_dir_is_nothing_to_prune(self) -> None:
        # C-F4: a job that fails before its first compile on a fresh runner has no
        # target dir; the always() prune must not add a second, misleading red step.
        proc = self._run("--target-dir", str(Path(self.scratch.name) / "absent"))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("nothing to prune", proc.stdout)
        self.assertEqual(0, self._freed(proc.stdout))

    def test_6118_refuses_a_file_as_target_dir(self) -> None:
        f = Path(self.scratch.name) / "a-file"
        _write(f, 10)
        proc = self._run("--target-dir", str(f))
        self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("refusing", proc.stderr)

    def test_6118_dry_run_deletes_nothing_and_reports_bytes(self) -> None:
        before = _tree_size(self.target)
        proc = self._run("--target-dir", str(self.target), "--dry-run")
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual(self._expected_freed(), self._freed(proc.stdout))
        self.assertEqual(before, _tree_size(self.target))
        self.assertIn("dry-run", proc.stdout)

    def test_6118_default_scope_prunes_test_bins_and_keeps_the_warm_cache(self) -> None:
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual(self._expected_freed(), self._freed(proc.stdout))
        for rel, _size, _exe, deleted in self.LAYOUT:
            path = self.target / rel
            if deleted:
                self.assertFalse(path.exists(), "should be gone: " + rel)
            else:
                self.assertTrue(path.exists(), "should be kept: " + rel)
        self.assertFalse((self.target / "debug" / "deps" / "mcp_input_schema-7c7c.dSYM").exists())
        self.assertTrue((self.target / "debug" / "incremental").is_dir())
        # The symlink is skipped and its target untouched.
        self.assertTrue((self.target / "debug" / "deps" / "evil-link").is_symlink())
        self.assertTrue(self.outside.exists())
        # Idempotent: a second run frees nothing.
        again = self._run("--target-dir", str(self.target))
        self.assertEqual(0, again.returncode, again.stdout + again.stderr)
        self.assertEqual(0, self._freed(again.stdout))

    def test_6118_scope_all_wipes_the_five_dirs_only(self) -> None:
        proc = self._run("--target-dir", str(self.target), "--scope", "all")
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        debug = self.target / "debug"
        for d in self.FIVE_DIRS:
            self.assertFalse((debug / d).exists(), d)
        self.assertTrue((debug / ".cargo-lock").exists())
        self.assertTrue((debug / "ai-memory").exists())
        self.assertTrue((self.target / "release" / "deps" / "ai_memory-ffff").exists())
        self.assertTrue(self.outside.exists())
        kept = sum(size for rel, size, _e, _d in self.LAYOUT
                   if not rel.startswith("debug/deps/") and not rel.startswith("debug/build/")
                   and not rel.startswith("debug/incremental/") and not rel.startswith("debug/examples/")
                   and not rel.startswith("debug/.fingerprint/"))
        self.assertEqual(sum(s for _r, s, _e, _d in self.LAYOUT) - kept, self._freed(proc.stdout))

    def test_6118_hardlinked_uplift_copy_is_kept_and_not_counted(self) -> None:
        # cargo "uplifts" a bin by hard-linking debug/deps/<bin>-<hash> to
        # debug/<bin>. Deleting the deps side frees nothing while the uplift
        # exists, so the script keeps it and does not count it as freed.
        src = self.target / "debug" / "deps" / "ai_memory-bin-1111"
        _write(src, 4096, True)
        os.link(src, self.target / "debug" / "ai-memory-bin")
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual(self._expected_freed(), self._freed(proc.stdout))
        self.assertTrue(src.exists())
        self.assertTrue((self.target / "debug" / "ai-memory-bin").exists())
        self.assertIn("hard-linked", proc.stdout)

    def test_6118_missing_profile_subdirs_are_not_an_error(self) -> None:
        import shutil
        shutil.rmtree(self.target / "debug" / "incremental")
        shutil.rmtree(self.target / "debug" / "examples")
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)

    def test_6118_relative_target_dir_resolves_against_cwd(self) -> None:
        rel = os.path.relpath(self.target, ROOT)
        proc = self._run("--target-dir", rel, "--dry-run")
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual(self._expected_freed(), self._freed(proc.stdout))

    # ---- round 2 (C-F5, S-F1..S-F3, S-F5) ----

    def test_6118_scope_all_counts_only_bytes_it_frees(self) -> None:
        # C-F5: a hard-linked file whose other link SURVIVES (the uplifted bin
        # outside the five dirs) frees nothing; a pair whose links are BOTH
        # inside the wiped dirs frees its bytes once.
        src = self.target / "debug" / "deps" / "ai_memory-bin-1111"
        _write(src, 4096, True)
        os.link(src, self.target / "debug" / "ai-memory-bin")
        pair = self.target / "debug" / "deps" / "pair-a"
        _write(pair, 3000)
        os.link(pair, self.target / "debug" / "deps" / "pair-b")
        proc = self._run("--target-dir", str(self.target), "--scope", "all")
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        in_five = sum(size for rel, size, _e, _d in self.LAYOUT
                      if any(rel.startswith("debug/" + d + "/") for d in self.FIVE_DIRS))
        self.assertEqual(in_five + 3000, self._freed(proc.stdout))
        self.assertTrue((self.target / "debug" / "ai-memory-bin").exists())

    def test_6118_refuses_symlinked_target_root(self) -> None:
        # S-F2: a committed `target` symlink must not redirect the prune.
        link = Path(self.scratch.name) / "link-target"
        link.symlink_to(self.target)
        proc = self._run("--target-dir", str(link))
        self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("symlink", proc.stderr)
        self.assertTrue((self.target / "debug" / "deps" / "ai_memory-0a1b").exists())

    def test_6118_refuses_root_outside_github_workspace(self) -> None:
        # S-F2: with GITHUB_WORKSPACE set, the root must lie inside it unless it IS
        # the runner's explicit CARGO_TARGET_DIR.
        ws = Path(self.scratch.name) / "workspace"
        ws.mkdir()
        proc = self._run("--target-dir", str(self.target), env={"GITHUB_WORKSPACE": str(ws)})
        self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("GITHUB_WORKSPACE", proc.stderr)
        self.assertTrue((self.target / "debug" / "deps" / "ai_memory-0a1b").exists())
        ok_ws = self._run("--target-dir", str(self.target), "--dry-run",
                          env={"GITHUB_WORKSPACE": str(Path(self.scratch.name))})
        self.assertEqual(0, ok_ws.returncode, ok_ws.stdout + ok_ws.stderr)
        ok_ctd = self._run("--target-dir", str(self.target), "--dry-run",
                           env={"GITHUB_WORKSPACE": str(ws), "CARGO_TARGET_DIR": str(self.target)})
        self.assertEqual(0, ok_ctd.returncode, ok_ctd.stdout + ok_ctd.stderr)

    def test_6118_cachedir_tag_signature_is_checked(self) -> None:
        # S-F2: a CACHEDIR.TAG without cargo's signature is not a marker.
        (self.target / "debug" / ".cargo-lock").unlink()
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
        self.assertTrue((self.target / "debug" / "deps" / "ai_memory-0a1b").exists())
        (self.target / "CACHEDIR.TAG").write_bytes(CARGO_CACHEDIR_TAG)
        ok = self._run("--target-dir", str(self.target), "--dry-run")
        self.assertEqual(0, ok.returncode, ok.stdout + ok.stderr)

    def test_6118_profile_is_validated_before_any_filesystem_work(self) -> None:
        # S-F5: the --profile check fires first, whatever the target dir is.
        for target in (str(Path(self.scratch.name) / "absent"), str(self.target)):
            for bad in ("..", "../x", "a/b", ""):
                proc = self._run("--target-dir", target, "--profile", bad)
                self.assertEqual(2, proc.returncode, (target, bad, proc.stdout + proc.stderr))
                self.assertIn("--profile must be one path component", proc.stderr, (target, bad))

    def test_6118_symlink_swap_of_deps_between_scan_and_delete_cannot_escape(self) -> None:
        # S-F1: deletion goes through directory fds opened O_NOFOLLOW at scan time,
        # so swapping `deps` for a symlink afterwards cannot redirect it.
        mod = _load_prune()
        plan = mod.plan_target(str(self.target), "debug", "test-bins", env={})
        victim = Path(self.scratch.name) / "victim-deps"
        for name in ("ai_memory-0a1b", "ai_memory-0a1b.d", "mcp_input_schema-7c7c", "mcp_input_schema-7c7c.d"):
            _write(victim / name, 11, True)
        deps = self.target / "debug" / "deps"
        deps.rename(self.target / "debug" / "deps-orig")
        deps.symlink_to(victim)
        try:
            tally = mod.execute(plan, dry_run=False)
        finally:
            plan.close()
        for name in ("ai_memory-0a1b", "ai_memory-0a1b.d", "mcp_input_schema-7c7c", "mcp_input_schema-7c7c.d"):
            self.assertTrue((victim / name).exists(), name)
            self.assertFalse((self.target / "debug" / "deps-orig" / name).exists(), name)
        self.assertEqual([], tally.errors)

    def test_6118_symlink_swap_of_profile_under_scope_all_cannot_escape(self) -> None:
        mod = _load_prune()
        plan = mod.plan_target(str(self.target), "debug", "all", env={})
        victim = Path(self.scratch.name) / "victim-profile"
        for d in self.FIVE_DIRS:
            _write(victim / d / "precious", 13)
        debug = self.target / "debug"
        debug.rename(self.target / "debug-orig")
        debug.symlink_to(victim)
        try:
            mod.execute(plan, dry_run=False)
        finally:
            plan.close()
        for d in self.FIVE_DIRS:
            self.assertTrue((victim / d / "precious").exists(), d)
            self.assertFalse((self.target / "debug-orig" / d).exists(), d)

    def test_6118_file_vanishing_mid_run_is_tolerated(self) -> None:
        # S-F3: a candidate removed by someone else between scan and delete is
        # already gone: no traceback, no error, and its bytes are not claimed.
        mod = _load_prune()
        plan = mod.plan_target(str(self.target), "debug", "test-bins", env={})
        (self.target / "debug" / "deps" / "mcp_input_schema-7c7c").unlink()
        try:
            tally = mod.execute(plan, dry_run=False)
        finally:
            plan.close()
        self.assertEqual([], tally.errors)
        self.assertEqual(self._expected_freed() - 120000, tally.freed)

    def test_6118_unremovable_entry_warns_continues_and_exits_1(self) -> None:
        # S-F3: any other OSError is a warning; the rest is still pruned, the
        # totals are still printed, and the exit code is 1 at the end.
        dwarf = self.target / "debug" / "deps" / "mcp_input_schema-7c7c.dSYM" / "Contents" / "Resources" / "DWARF"
        dwarf.chmod(0o500)
        self.addCleanup(dwarf.chmod, 0o700)
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("::warning::prune-runner-target:", proc.stdout)
        self.assertEqual(self._expected_freed() - 2000, self._freed(proc.stdout))
        self.assertFalse((self.target / "debug" / "deps" / "ai_memory-0a1b").exists())
        self.assertFalse((self.target / "debug" / "examples" / "demo-1e1e").exists())


# cargo's own CACHEDIR.TAG (https://bford.info/cachedir/): the signature line is
# what makes it a marker, not the file name.
CARGO_CACHEDIR_TAG = (b"Signature: 8a477f597d28d172789f06886806bc55\n"
                      b"# This file is a cache directory tag created by cargo.\n")


def _load_prune():
    """Import scripts/ci/prune-runner-target.py in-process (its name has dashes)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("prune_runner_target_6118", str(PRUNE_SCRIPT))
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load " + str(PRUNE_SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False, verbosity=1).result.wasSuccessful() else 1)
