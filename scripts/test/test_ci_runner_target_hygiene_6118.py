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

RULES ENFORCED, for EVERY job that can land on a self-hosted runner (closed
world: a workflow file, or a ``runs-on`` form, the reader cannot read is a
FAILURE, never a skip):
  R-CENSUS the set of (workflow, job) pairs whose ``runs-on`` can resolve to a
           self-hosted runner is exactly EXPECTED_SELF_HOSTED_JOBS, so a new
           self-hosted job cannot appear without being pinned here.  Every
           self-hosted job is censused, cargo or not: cargo can run through a
           script (``scripts/coverage.sh``), an action or a Makefile, and a
           guard that guesses which commands compile fails open.  ``runs-on``
           is read in every form Actions accepts that a job here could use: an
           inline label, a flow list ``[a, b]``, a block sequence, and
           ``${{ matrix.<key> }}`` / ``${{ fromJSON(matrix.<key>) }}`` resolved
           against EVERY value of that matrix key (dimension lists and
           ``include:`` rows).  Any other form (a ``group:``/``labels:``
           mapping, another expression, a matrix key with no literal values)
           raises Unparsed.  A leg is GitHub-hosted only when every label is a
           GitHub-hosted image label (HOSTED_LABEL_RE) and none is
           ``self-hosted``; a bare fleet label such as ``linux-fed`` counts as
           self-hosted.
  R-DEBUG  the effective env (workflow ``env:`` overlaid by job ``env:``) sets
           BOTH ``CARGO_PROFILE_DEV_DEBUG`` and ``CARGO_PROFILE_TEST_DEBUG`` to
           ``0`` (the pair rule of #3461: ``test`` only inherits ``dev`` while
           nothing overrides it; one value for every self-hosted job so the
           shared persistent ``target/`` holds ONE artifact tree, not one per
           debuginfo level).  ``0``, not ``line-tables-only``: the check job
           ALREADY ran at ``line-tables-only`` when it wrote the 164 GB, and a
           Linux x86_64 measurement (packed debuginfo, 2026-10-09, lib
           unit-test binary + one integration test binary) put the integration
           test binary at 130 MB at ``line-tables-only`` and 11.6 MB at ``0``
           (11x); the ~1000 integration binaries are what fill the disk.  On
           macOS (unpacked debuginfo) the binaries shrink only 1.11x, and
           ``debug/deps`` 3.7 GB -> 2.0 GB, from the loose ``.o`` files that
           ``0`` no longer writes.  Nothing in CI reads
           line tables: no workflow, script or test sets RUST_BACKTRACE, panic
           locations are compile-time strings, and the hosted sqlite leg and
           both pg jobs have run the full suites at ``0`` since #3461 / #3274.
           No step may set any ``CARGO_PROFILE_*_DEBUG`` (or a rustc
           ``debuginfo=`` / ``-g`` flag, or a ``cargo --config
           profile.<p>.debug=``) to anything but ``0``: a step-level ``env:``
           row, or an assignment in a ``run:`` body (``export``, or an
           ``echo ... >> "$GITHUB_ENV"`` that overrides the job env for every
           later step) is flagged.  Also flagged: an inline ``profile.<p>={debug=..}``
           table, a ``rustflags`` value (any case, env row, run body, a config
           file a step writes, a ``RUSTFLAGS<<EOF`` heredoc, YAML ``\\x1f``
           escapes decoded), ``cargo --config <file>`` (a file can set any
           level) and ``cargo --profile <p>`` for a ``p`` outside dev / test /
           release / bench.  ``0``, ``false`` and ``"none"`` are the level-0
           spellings of a flag; ``git log -g`` or prose that mentions ``-g`` is
           not a rustc flag.
  R-PRUNE  the job's LAST step is named PRUNE_STEP_NAME, runs under
           ``if: always()`` (a red or cancelled test run leaves the same
           binaries behind), is skipped on GitHub-hosted runners when the job
           can land on one, carries the ``docs_only`` guard when its siblings do
           (rule (b3) of scripts/check-required-contexts.sh), and runs
           ``python3 scripts/ci/prune-runner-target.py --target-dir ...``
           without ``--allow-outside-workspace``.

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

import json
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
ALLOW_OUTSIDE_FLAG = "--allow-outside-workspace"
PRUNE_RUN_LINE = '        run: python3 scripts/ci/prune-runner-target.py --target-dir "${CARGO_TARGET_DIR:-target}"'
DEBUG_LEVEL = "0"
DEBUG_KEYS = ("CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG")
# Every spelling of debuginfo level 0 that cargo / rustc accept in a flag or a
# `--config` value.  The pinned CARGO_PROFILE_*_DEBUG env rows stay the literal
# ``0`` (DEBUG_LEVEL): one value, one artifact tree.
LEVEL_OFF = frozenset({DEBUG_LEVEL, "false", "none"})
CARGO_PROFILES_OK = frozenset({"dev", "test", "release", "bench"})
HOSTED_GUARD = "runner.environment != 'github-hosted'"
DOCS_ONLY_GUARD = "docs_only"
# S-F4 (round 2): the prune step runs the CHECKED-OUT script, so it must not run
# when this job's checkout was skipped (fork-PR refusal) or failed: the
# persistent workspace would otherwise hand it the previous job's copy.
CHECKOUT_STEP_ID = "checkout"
CHECKOUT_GUARD = "steps.checkout.outcome == 'success'"
# GitHub-hosted image labels (ubuntu-latest, ubuntu-24.04-arm, ubuntu-slim,
# macos-15-intel, windows-2022, ...).  Anything else (``self-hosted``,
# ``linux-fed``, ``macos-fed``, a typo) is treated as a fleet label: fail closed.
HOSTED_LABEL_RE = re.compile(
    r"ubuntu-slim|(ubuntu|macos|windows)-(latest|[0-9]+(\.[0-9]+)?)(-(arm|arm64|intel|large|xlarge))?")
RUNS_ON_EXPR_RE = re.compile(
    r"\$\{\{\s*(?:fromJSON\(\s*matrix\.([A-Za-z0-9_-]+)\s*\)|matrix\.([A-Za-z0-9_-]+))\s*\}\}")
DEBUG_ENV_KEY_RE = re.compile(r"CARGO_PROFILE_[A-Z0-9_]+_DEBUG")
# `CARGO_PROFILE_X_DEBUG=value` anywhere in a run body (export, env prefix,
# `echo ... >> "$GITHUB_ENV"`), with the value bare or quoted.
RUN_DEBUG_ASSIGN_RE = re.compile(r"(CARGO_PROFILE_[A-Z0-9_]+_DEBUG)\s*=\s*[\"']?([^\s\"';|&)}]*)")
DEBUGINFO_FLAG_RE = re.compile(r"debuginfo\s*=\s*[\"']?([A-Za-z0-9_-]*)")
# `cargo --config profile.<p>.debug=<v>` (also `profile.<p>.package.<pkg>.debug`):
# command-line config takes precedence over the CARGO_PROFILE_* env.  Not
# `debug-assertions`.  The value may be TOML-quoted inside shell quotes.
CONFIG_DEBUG_RE = re.compile(r"(profile\.[A-Za-z0-9_.*\"'-]*?\.debug)\s*=\s*\\?[\"']?([A-Za-z0-9_-]*)")
# The same key in an inline table: `--config 'profile.dev={debug=1}'`.
INLINE_DEBUG_RE = re.compile(
    r"(profile\.[A-Za-z0-9_.*\"'-]+)\s*=\s*\{[^}]*?\bdebug\s*=\s*\\?[\"']?([A-Za-z0-9_-]*)")
# `cargo --config <value>`: a value without `=` is a config FILE, which can set
# anything (and beats the CARGO_PROFILE_* env).
CARGO_CONFIG_ARG_RE = re.compile(r"\bcargo\b[^|;&\n]*?--config(?:=|\s+)(?:\"([^\"]*)\"|'([^']*)'|(\S+))")
CARGO_PROFILE_ARG_RE = re.compile(r"\bcargo\b[^|;&\n]*?--profile(?:=|\s+)([A-Za-z0-9_.-]+)")
# rustc's `-g` is `-C debuginfo=2`.  Matched as a standalone token in a rustc
# flags env value, or in a run line that sets RUSTFLAGS / calls rustc (a bare
# `-g` elsewhere, e.g. `npm install -g`, is not a rustc flag).
RUSTC_FLAGS_KEY_RE = re.compile(r"(CARGO_ENCODED_)?RUST(DOC)?FLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_TARGET_[A-Z0-9_]+_RUSTFLAGS")
# In a run body only the VALUE of a flags assignment (`RUSTFLAGS=...`,
# `rustflags = [...]` in a config.toml written by a step; any case) or the
# simple command that calls `rustc` is searched for `-g`, so `git log -g` on the
# same line, or prose that mentions -g, is not a rustc flag.
RUSTFLAGS_ASSIGN_RE = re.compile(
    r"(?i)RUST(?:DOC)?FLAGS\s*=\s*(\"[^\"]*\"|'[^']*'|\[[^\]]*\]|[^\s;|&]*)")
RUSTFLAGS_HEREDOC_RE = re.compile(r"(?i)RUST(?:DOC)?FLAGS\s*<<-?\s*['\"]?(\w+)['\"]?")
RUSTC_SEGMENT_RE = re.compile(r"\brustc\b([^|;&]*)")
YAML_HEX_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})|\\u([0-9A-Fa-f]{4})")
DASH_G_RE = re.compile(r"(?:^|[\s\"'=\x1f\[,])-g(?=$|[\s\"'\x1f\],])")

# Every (workflow, job) that can land on a self-hosted runner, pinned.  A new
# self-hosted job must be added here AND given the rules above.
EXPECTED_SELF_HOSTED_JOBS = frozenset({
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
        self.env: Dict[str, str] = {}
        self.run: List[str] = []

    def run_text(self) -> str:
        return "\n".join(self.run)


def _leg_is_hosted(labels: List[str]) -> bool:
    return bool(labels) and "self-hosted" not in labels and all(HOSTED_LABEL_RE.fullmatch(x) for x in labels)


class Job:
    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        self.runs_on = ""  # the raw inline spec ("" for the block forms)
        self.env: Dict[str, str] = {}
        self.matrix: Dict[str, List[str]] = {}  # every literal value of every matrix key
        self.legs: List[List[str]] = []  # one label list per possible runner
        self.steps: List[Step] = []

    def self_hosted(self) -> bool:
        return any(not _leg_is_hosted(leg) for leg in self.legs)

    def can_be_hosted(self) -> bool:
        """True when at least one leg lands on a GitHub-hosted image."""
        return any(_leg_is_hosted(leg) for leg in self.legs)


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


def _flow_items(text: str, line: int) -> List[str]:
    """Items of a one-line flow sequence ``[a, 'b, c', "d"]`` (quote-aware)."""
    inner = text.strip()
    if not (inner.startswith("[") and inner.endswith("]")):
        raise Unparsed("not a flow sequence at line %d: %r" % (line, text))
    items: List[str] = []
    cur: List[str] = []
    quote: Optional[str] = None
    for ch in inner[1:-1]:
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch in "[]{}":
            raise Unparsed("nested flow collection at line %d: %r" % (line, text))
        elif ch == ",":
            items.append(_unquote("".join(cur)))
            cur = []
            continue
        cur.append(ch)
    if quote:
        raise Unparsed("unterminated quote at line %d: %r" % (line, text))
    tail = "".join(cur).strip()
    if tail or items:
        items.append(_unquote(tail))
    return [x for x in items if x != ""]


def _labels(value: str, via_json: bool, line: int) -> List[str]:
    """Runner labels of one resolved matrix value (or one inline label)."""
    if "${{" in value:
        raise Unparsed("runs-on value is itself an expression at line %d: %r" % (line, value))
    if not via_json:
        return [value]
    try:
        data = json.loads(value)
    except ValueError as exc:
        raise Unparsed("fromJSON value is not JSON at line %d: %r (%s)" % (line, value, exc))
    if isinstance(data, str):
        return [data]
    if isinstance(data, list) and data and all(isinstance(x, str) for x in data):
        return list(data)
    raise Unparsed("fromJSON value is not a label or label list at line %d: %r" % (line, value))


def _read_matrix(rows: List[Tuple[int, str, int]], start: int, indent: int, job: Job) -> int:
    """Collect every literal value of every key under ``strategy:`` (dims and include rows)."""
    i = start
    pending: Optional[Tuple[str, int]] = None  # a `key:` with an empty value, awaiting `- item` rows
    while i < len(rows) and rows[i][0] > indent:
        ind, content, n = rows[i]
        dash, key, value = _split_key(content)
        if not key:
            if dash and pending is not None and ind > pending[1]:
                job.matrix.setdefault(pending[0], []).append(_unquote(_strip_comment(content[2:])))
            i += 1
            continue
        value = _strip_comment(value).strip()
        key_col = ind + 2 if dash else ind
        if value == "":
            pending = (key, key_col)
        else:
            pending = None
            if value.startswith("["):
                job.matrix.setdefault(key, []).extend(_flow_items(value, n))
            else:
                job.matrix.setdefault(key, []).append(_unquote(value))
        i += 1
    return i


def _resolve_runs_on(job: Job, spec: str, block: List[Tuple[int, str, int]], line: int) -> None:
    """Fill ``job.legs`` from the runs-on spec (inline) or its block rows; Unparsed otherwise."""
    if block:
        labels: List[str] = []
        for _ind, content, n in block:
            dash, key, _v = _split_key(content)
            if not dash or key:
                raise Unparsed("runs-on mapping form (group:/labels:) is not read, line %d: %r" % (n, content))
            labels.append(_unquote(_strip_comment(content[2:])))
        job.legs = [labels]
        return
    spec = spec.strip()
    if spec == "":
        raise Unparsed("job %s has an empty runs-on at line %d" % (job.job_id, line))
    if spec.startswith("{"):
        raise Unparsed("runs-on mapping form is not read, line %d: %r" % (line, spec))
    if spec.startswith("["):
        labels = _flow_items(spec, line)
        for x in labels:
            _labels(x, False, line)
        job.legs = [labels]
        return
    if "${{" in spec:
        m = RUNS_ON_EXPR_RE.fullmatch(spec)
        if not m:
            raise Unparsed("runs-on expression is not matrix.<key> / fromJSON(matrix.<key>), line %d: %r" % (line, spec))
        via_json = m.group(1) is not None
        key = m.group(1) or m.group(2)
        values = job.matrix.get(key, [])
        if not values:
            raise Unparsed("runs-on uses matrix.%s but the matrix has no literal values for it, line %d" % (key, line))
        job.legs = [_labels(v, via_json, line) for v in values]
        return
    job.legs = [[_unquote(spec)]]


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
        job_line = n
        i += 1
        runs_on_line = 0
        runs_on_block: List[Tuple[int, str, int]] = []
        seen_runs_on = False
        calls_workflow = False
        while i < len(rows) and rows[i][0] > job_indent:
            kind, kcontent, kn = rows[i]
            if kind != job_indent + 2:
                i += 1
                continue
            _d, key, val = _split_key(kcontent)
            if key == "runs-on":
                seen_runs_on = True
                runs_on_line = kn
                job.runs_on = _strip_comment(val)
                i += 1
                if job.runs_on.strip() == "":
                    while i < len(rows) and rows[i][0] > kind:
                        runs_on_block.append(rows[i])
                        i += 1
            elif key == "uses":
                calls_workflow = True
                i += 1
            elif key == "env":
                if val.strip():
                    raise Unparsed("inline job env at line %d is not read: %r" % (kn, kcontent))
                job.env, i = _env_block(rows, i + 1, kind)
            elif key == "strategy":
                i = _read_matrix(rows, i + 1, kind, job)
            elif key == "steps":
                i = _read_steps(job, rows, raw, i + 1, kind)
            else:
                i += 1
        if seen_runs_on:
            _resolve_runs_on(job, job.runs_on, runs_on_block, runs_on_line)
        elif not calls_workflow:
            # A reusable-workflow call (`uses:`) runs where the CALLED file says,
            # and that file is read on its own; anything else must name a runner.
            raise Unparsed("job %s at line %d has no runs-on" % (job_id, job_line))
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
        if key == "env":
            if value.strip():
                raise Unparsed("inline step env at line %d is not read: %r" % (n, content))
            step.env, i = _env_block(rows, i + 1, key_col)
            continue
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


def self_hosted_jobs(workflows: Dict[str, str]) -> Dict[Tuple[str, str], Tuple[Workflow, Job]]:
    found: Dict[Tuple[str, str], Tuple[Workflow, Job]] = {}
    for name, text in workflows.items():
        try:
            wf = read_workflow(text)
        except Unparsed as exc:
            raise Unparsed("%s: %s" % (name, exc))
        for job_id, job in wf.jobs.items():
            if job.self_hosted():
                found[(name, job_id)] = (wf, job)
    return found


def _yaml_unescape(value: str) -> str:
    """Decode the ``\\xNN`` / ``\\uNNNN`` escapes of a YAML double-quoted scalar (``\\x1f`` is cargo's flag separator)."""
    return YAML_HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), value)


def _heredoc_ends(line: str, delimiter: str) -> bool:
    return re.search(r"(?:^|[\s'\"])" + re.escape(delimiter) + r"(?:$|[\s'\"])", line) is not None


def _level_spellings(text: str, flags_value: bool) -> List[str]:
    """Every debuginfo level other than off spelled in ``text`` as a rustc flag or cargo --config.

    ``flags_value``: ``text`` IS a rustc flags value (an env row of a RUSTFLAGS
    key), so a standalone ``-g`` anywhere in it counts; otherwise ``text`` is a
    run line and ``-g`` counts only in a flags assignment's value or after ``rustc``.
    """
    found: List[str] = []
    for m in DEBUGINFO_FLAG_RE.finditer(text):
        if m.group(1) not in LEVEL_OFF:
            found.append("debuginfo=%r" % m.group(1))
    for m in CONFIG_DEBUG_RE.finditer(text):
        if m.group(2) not in LEVEL_OFF:
            found.append("%s=%r (cargo --config beats CARGO_PROFILE_* env)" % (m.group(1).strip("\"'"), m.group(2)))
    for m in INLINE_DEBUG_RE.finditer(text):
        if m.group(2) not in LEVEL_OFF:
            found.append("%s={debug=%r} (cargo --config beats CARGO_PROFILE_* env)" % (m.group(1).strip("\"'"), m.group(2)))
    if flags_value:
        scanned = [text]
    else:
        scanned = [m.group(1) for m in RUSTFLAGS_ASSIGN_RE.finditer(text)]
        scanned.extend(m.group(1) for m in RUSTC_SEGMENT_RE.finditer(text))
    if any(DASH_G_RE.search(piece) for piece in scanned):
        found.append("rustc -g (= -C debuginfo=2)")
    if not flags_value:
        for m in CARGO_CONFIG_ARG_RE.finditer(text):
            value = next(g for g in m.groups() if g is not None)
            if "=" not in value:
                found.append("cargo --config %s (a config file can set any debuginfo level)" % value)
        for m in CARGO_PROFILE_ARG_RE.finditer(text):
            if m.group(1) not in CARGO_PROFILES_OK:
                found.append("cargo --profile %s (a custom profile has its own debuginfo and a target/%s the prune "
                             "never touches)" % (m.group(1), m.group(1)))
    return found


def _debug_overrides(where: str, effective: Dict[str, str], job: Job) -> List[str]:
    """Every place a self-hosted job sets a debuginfo level other than ``0``."""
    found: List[str] = []
    for key, value in sorted(effective.items()):
        if DEBUG_ENV_KEY_RE.fullmatch(key) and key not in DEBUG_KEYS and value != DEBUG_LEVEL:
            found.append("%s: R-DEBUG env %s is %r, want %r" % (where, key, value, DEBUG_LEVEL))
        for spelled in _level_spellings(_yaml_unescape(value), bool(RUSTC_FLAGS_KEY_RE.fullmatch(key))):
            found.append("%s: R-DEBUG env %s carries %s, want %r" % (where, key, spelled, DEBUG_LEVEL))
    for step in job.steps:
        label = step.name or step.uses or "<unnamed step>"
        for key, value in sorted(step.env.items()):
            if DEBUG_ENV_KEY_RE.fullmatch(key) and value != DEBUG_LEVEL:
                found.append("%s: R-DEBUG step %r env %s is %r, want %r" % (where, label, key, value, DEBUG_LEVEL))
            for spelled in _level_spellings(_yaml_unescape(value), bool(RUSTC_FLAGS_KEY_RE.fullmatch(key))):
                found.append("%s: R-DEBUG step %r env %s carries %s, want %r" % (where, label, key, spelled, DEBUG_LEVEL))
        heredoc = ""  # delimiter of an open `RUSTFLAGS<<DELIM` ($GITHUB_ENV multi-line value)
        for line in step.run:
            if heredoc:
                if _heredoc_ends(line, heredoc):
                    heredoc = ""
                elif DASH_G_RE.search(line):
                    found.append("%s: R-DEBUG step %r run sets rustc -g in a RUSTFLAGS heredoc, want %r"
                                 % (where, label, DEBUG_LEVEL))
            else:
                opened = RUSTFLAGS_HEREDOC_RE.search(line)
                if opened:
                    heredoc = opened.group(1)
            for m in RUN_DEBUG_ASSIGN_RE.finditer(line):
                if m.group(2) != DEBUG_LEVEL:
                    found.append("%s: R-DEBUG step %r run sets %s to %r (a $GITHUB_ENV write overrides every later "
                                 "step), want %r" % (where, label, m.group(1), m.group(2), DEBUG_LEVEL))
            for spelled in _level_spellings(line, False):
                found.append("%s: R-DEBUG step %r run sets %s, want %r" % (where, label, spelled, DEBUG_LEVEL))
    return found


def violations(name: str, wf: Workflow, job: Job) -> List[str]:
    """Every R-DEBUG / R-PRUNE violation for one self-hosted job."""
    found: List[str] = []
    where = "%s job %s" % (name, job.job_id)
    effective = dict(wf.env)
    effective.update(job.env)
    for key in DEBUG_KEYS:
        got = effective.get(key)
        if got != DEBUG_LEVEL:
            found.append("%s: R-DEBUG %s is %r, want %r" % (where, key, got, DEBUG_LEVEL))
    found.extend(_debug_overrides(where, effective, job))
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
    if ALLOW_OUTSIDE_FLAG in run:
        found.append("%s: R-PRUNE prune step passes %s; a workflow never prunes a target dir outside "
                     "its workspace (CF4)" % (where, ALLOW_OUTSIDE_FLAG))
    return found


def all_violations(workflows: Dict[str, str]) -> List[str]:
    found: List[str] = []
    try:
        jobs = self_hosted_jobs(workflows)
    except Unparsed as exc:
        return ["R-SHAPE cannot read a workflow (%s)" % exc]
    census = frozenset(jobs)
    for missing in sorted(EXPECTED_SELF_HOSTED_JOBS - census):
        found.append("R-CENSUS expected self-hosted job %s/%s not found" % missing)
    for extra in sorted(census - EXPECTED_SELF_HOSTED_JOBS):
        found.append("R-CENSUS unpinned self-hosted job %s/%s (add it to EXPECTED_SELF_HOSTED_JOBS)" % extra)
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
        jobs = self_hosted_jobs(load_all())
        self.assertEqual(EXPECTED_SELF_HOSTED_JOBS, frozenset(jobs))
        check = jobs[("ci.yml", "check")][1]
        self.assertTrue(check.can_be_hosted(), check.legs)
        self.assertIn(["self-hosted", "linux-fed"], check.legs)
        self.assertIn(["ubuntu-latest"], check.legs)
        self.assertFalse(jobs[("cert-postgres-age.yml", "cert-postgres-age")][1].can_be_hosted())


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
        self.assertTrue(any("R-CENSUS unpinned self-hosted job ci.yml/extra_fleet_job" in v for v in found), found)

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

    # ---- round 3 (F1, F3): two more debuginfo spellings, one hosted label ----

    def test_6118_m16_cargo_config_profile_debug_override(self) -> None:
        # F1: cargo's --config on the command line beats CARGO_PROFILE_* env.
        found = self._before_prune(
            "      - name: Config debug override\n"
            "        run: cargo test --no-run --config 'profile.dev.debug=\"line-tables-only\"'\n")
        self.assertTrue(any("R-DEBUG" in v and "profile.dev.debug" in v and "line-tables-only" in v
                            for v in found), found)

    def test_6118_m17_rustflags_dash_g(self) -> None:
        # F1: `-g` is rustc's spelling of `-C debuginfo=2`.
        found = self._before_prune(
            "      - name: RUSTFLAGS -g\n        env:\n          RUSTFLAGS: \"-g\"\n"
            "        run: cargo test --no-run\n")
        self.assertTrue(any("R-DEBUG" in v and "RUSTFLAGS" in v and "-g" in v for v in found), found)

    def test_6118_m17b_rustflags_dash_g_in_a_run_body(self) -> None:
        found = self._before_prune(
            "      - name: RUSTFLAGS -g inline\n"
            "        run: RUSTFLAGS=\"-C opt-level=0 -g\" cargo test --no-run\n")
        self.assertTrue(any("R-DEBUG" in v and "-g" in v for v in found), found)

    def test_6118_m18_level_0_spellings_and_unrelated_dash_g_are_clean(self) -> None:
        # The F1 detectors must not flag a level-0 spelling or a `-g` that is not
        # a rustc flag (npm's global install), nor `profile.*.debug-assertions`.
        found = self._before_prune(
            "      - name: Level 0 spellings\n        env:\n          RUSTFLAGS: \"-C debuginfo=0\"\n"
            "        run: |\n"
            "          cargo test --no-run --config profile.dev.debug=0 --config 'profile.test.debug=\"0\"'\n"
            "          cargo test --no-run --config profile.dev.debug-assertions=true\n"
            "          npm install -g some-tool\n")
        self.assertEqual([], found)

    def test_6118_m19_ubuntu_slim_is_github_hosted(self) -> None:
        # F3: `ubuntu-slim` is a GitHub-hosted label; a job on it is not censused.
        self.assertTrue(_leg_is_hosted(["ubuntu-slim"]))
        found = self._appended(
            "  extra_slim_job:\n    runs-on: ubuntu-slim\n    steps:\n      - run: cargo test --lib\n")
        self.assertEqual([], found)
        self.assertFalse(_leg_is_hosted(["ubuntu-slim", "self-hosted"]))

    # ---- round 3, cloud review CF1: the six census shapes, each pinned ----
    # (shape 2 `group:` block = m12, shape 3 non-`runner` matrix key = m09/m09b,
    # shape 5 cargo through a script = m10; the rest are pinned here)

    def test_6118_m20_bare_fleet_label_inline(self) -> None:
        for spec in ("macos-fed", "[linux-fed]"):
            found = self._appended("  extra_bare_job:\n    runs-on: %s\n    steps:\n      - run: cargo test\n" % spec)
            self._assert_unpinned(found, "extra_bare_job")

    def test_6118_m21_runs_on_flow_mapping_is_unparsed(self) -> None:
        found = self._appended(
            "  extra_flow_map_job:\n    runs-on: {labels: [self-hosted, linux-fed]}\n"
            "    steps:\n      - run: cargo test\n")
        self.assertTrue(found and found[0].startswith("R-SHAPE"), found)

    def test_6118_m22_cargo_spellings_are_censused(self) -> None:
        for run in ("cargo +nightly test", "\"\\\"$CARGO\\\" test\"", "cargo run --bin ai-memory",
                    "bash scripts/x.sh"):
            found = self._appended(
                "  extra_cargo_job:\n    runs-on: [self-hosted, linux-fed]\n    steps:\n      - run: %s\n" % run)
            self._assert_unpinned(found, "extra_cargo_job")

    def test_6118_m23_composite_action_is_censused(self) -> None:
        found = self._appended(
            "  extra_action_job:\n    runs-on: [self-hosted, linux-fed]\n    steps:\n"
            "      - uses: ./.github/actions/cargo\n        with:\n          args: test\n")
        self._assert_unpinned(found, "extra_action_job")

    def test_6118_m24_prune_step_must_not_allow_outside_workspace(self) -> None:
        # CF4: the workflows never opt in to an out-of-workspace target dir.
        anchor = PRUNE_RUN_LINE
        self.assertEqual(1, self.ci.count(anchor), anchor)
        found = self._mutated(_replace_once(self.ci, anchor, anchor + " --allow-outside-workspace"))
        self.assertTrue(any("R-PRUNE" in v and "--allow-outside-workspace" in v for v in found), found)

    # ---- round 4 (R3-F2, SR3-3): more debuginfo spellings, fewer false alarms ----

    def _debug_flagged(self, found: List[str]) -> bool:
        return any("R-DEBUG" in v for v in found)

    def test_6118_m25_inline_table_profile_debug(self) -> None:
        found = self._before_prune(
            "      - name: Inline table\n"
            "        run: cargo test --no-run --config 'profile.dev={debug=1}'\n")
        self.assertTrue(self._debug_flagged(found), found)
        found = self._before_prune(
            "      - name: Inline table spaced\n"
            "        run: cargo test --no-run --config 'profile.test = { debug = \"line-tables-only\" }'\n")
        self.assertTrue(self._debug_flagged(found), found)

    def test_6118_m26_lowercase_build_rustflags_dash_g(self) -> None:
        found = self._before_prune(
            "      - name: Lowercase key\n"
            "        run: cargo test --no-run --config 'build.rustflags=[\"-g\"]'\n")
        self.assertTrue(self._debug_flagged(found), found)

    def test_6118_m27_yaml_escaped_separator_in_encoded_rustflags(self) -> None:
        # The YAML double-quoted escape \x1f is the unit separator cargo splits on.
        for value in ('"-Copt-level=0\\x1f-g"', '"-g\\x1f-Copt-level=0"', '"-Copt-level=0\\u001f-g"'):
            found = self._before_prune(
                "      - name: Encoded flags\n        env:\n          CARGO_ENCODED_RUSTFLAGS: " + value + "\n"
                "        run: cargo test --no-run\n")
            self.assertTrue(self._debug_flagged(found), (value, found))

    def test_6118_m28_benign_lines_are_clean(self) -> None:
        # R3-F2 false positives: `git log -g` on a RUSTFLAGS line, prose that
        # mentions -g, and the valid level-0 spellings false / "none".
        found = self._before_prune(
            "      - name: Benign\n        run: |\n"
            "          RUSTFLAGS=\"-D warnings\" cargo clippy && git log -g\n"
            "          echo \"RUSTFLAGS: never pass -g here\"\n"
            "          cargo test --no-run --config profile.dev.debug=false\n"
            "          cargo test --no-run --config 'profile.test.debug=\"none\"'\n"
            "          cargo test --no-run --config 'profile.dev={debug=0}'\n"
            "          cargo test --no-run --config 'build.rustflags=[\"-D\", \"warnings\"]'\n")
        self.assertEqual([], found)

    def test_6118_m29_step_appends_build_rustflags_to_cargo_config(self) -> None:
        found = self._before_prune(
            "      - name: Write config\n        run: |\n"
            "          mkdir -p .cargo\n"
            "          printf '[build]\\nrustflags = [\"-g\"]\\n' >> .cargo/config.toml\n")
        self.assertTrue(self._debug_flagged(found), found)
        found = self._before_prune(
            "      - name: Write config heredoc\n        run: |\n"
            "          cat >> .cargo/config.toml <<'EOF'\n"
            "          [build]\n"
            "          rustflags = [\"-g\"]\n"
            "          EOF\n")
        self.assertTrue(self._debug_flagged(found), found)

    def test_6118_m30_cargo_config_file_can_set_anything(self) -> None:
        found = self._before_prune(
            "      - name: Config file\n        run: cargo test --no-run --config ci/debug.toml\n")
        self.assertTrue(self._debug_flagged(found), found)

    def test_6118_m31_github_env_heredoc_rustflags(self) -> None:
        found = self._before_prune(
            "      - name: Env heredoc\n        run: |\n"
            "          {\n"
            "            echo 'RUSTFLAGS<<EOF'\n"
            "            echo '-g'\n"
            "            echo 'EOF'\n"
            "          } >> \"$GITHUB_ENV\"\n")
        self.assertTrue(self._debug_flagged(found), found)
        found = self._before_prune(
            "      - name: Env heredoc plain\n        run: |\n"
            "          cat >> \"$GITHUB_ENV\" <<EOF\n"
            "          RUSTFLAGS<<FLAGS\n"
            "          -Copt-level=0 -g\n"
            "          FLAGS\n"
            "          EOF\n")
        self.assertTrue(self._debug_flagged(found), found)

    def test_6118_m32_custom_cargo_profile_on_a_self_hosted_job(self) -> None:
        # The prune only ever touches target/<profile> for the default profile.
        found = self._before_prune(
            "      - name: Custom profile\n        run: cargo test --no-run --profile ci\n")
        self.assertTrue(self._debug_flagged(found), found)
        found = self._before_prune(
            "      - name: Known profiles\n        run: |\n"
            "          cargo test --no-run --profile dev\n"
            "          cargo build --profile=release\n")
        self.assertEqual([], found)


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
        # cargo builds examples/<name>-<hash> and uplifts it by hard-linking
        # examples/<name> (setUp adds the link): a real tree never holds an
        # example with nlink 1 (CF2).
        ("debug/examples/demo-0123456789abcdef", 50000, True, True),
        ("debug/examples/demo-0123456789abcdef.d", 10, False, True),
        ("debug/examples/demo.d", 10, False, True),
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
        os.link(self.target / EXAMPLE_HASHED, self.target / EXAMPLE_UPLIFT)
        # A symlink inside deps that points OUTSIDE the target dir; it looks
        # like an executable (the link target is executable) and must be
        # skipped, never followed.
        self.outside = Path(self.scratch.name) / "outside-exe"
        _write(self.outside, 777, True)
        (self.target / "debug" / "deps" / "evil-link").symlink_to(self.outside)

    def _run(self, *args: str, env: Optional[Dict[str, str]] = None,
             cwd: Optional[Path] = None, timeout: Optional[float] = None) -> subprocess.CompletedProcess:
        base = {k: v for k, v in os.environ.items() if k not in ("GITHUB_WORKSPACE", "CARGO_TARGET_DIR")}
        base.update(env or {})
        return subprocess.run(
            [sys.executable, "-I", str(PRUNE_SCRIPT), *args],
            cwd=str(cwd or ROOT), capture_output=True, text=True, check=False, env=base, timeout=timeout,
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
        # CF4: an exported CARGO_TARGET_DIR outside the workspace is honoured only
        # with the explicit --allow-outside-workspace (the workflows never pass it).
        no_flag = self._run("--target-dir", str(self.target), "--dry-run",
                            env={"GITHUB_WORKSPACE": str(ws), "CARGO_TARGET_DIR": str(self.target)})
        self.assertEqual(2, no_flag.returncode, no_flag.stdout + no_flag.stderr)
        self.assertIn("--allow-outside-workspace", no_flag.stderr)
        ok_ctd = self._run("--target-dir", str(self.target), "--dry-run", "--allow-outside-workspace",
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
        self.assertFalse((self.target / EXAMPLE_HASHED).exists())

    # ---- round 3, cloud review (CF2, CF4, CF6) ----

    def test_6118_example_uplift_pair_is_pruned_together(self) -> None:
        # CF2: examples/<name> and examples/<name>-<hash> are one inode (nlink 2,
        # both in examples/); cargo re-uplifts, so the pair goes together and its
        # bytes count once.  A pair that does not match <name> + <name>-<hash>,
        # and an example linked from outside examples/, stay.
        ex = self.target / "debug" / "examples"
        _write(ex / "tool-fedcba9876543210", 700, True)
        os.link(ex / "tool-fedcba9876543210", ex / "unrelated")
        _write(ex / "keep-1111222233334444", 800, True)
        os.link(ex / "keep-1111222233334444", self.target / "debug" / "keep")
        # macOS: cargo uplifts the dSYM bundle as a symlink <name>.dSYM; it is
        # unlinked as a link and never followed (here it points outside).
        _write(self.target / (EXAMPLE_HASHED + ".dSYM") / "Contents" / "dwarf", 300, False)
        outside = Path(self.scratch.name) / "outside-dsym"
        _write(outside / "keep-me", 5, False)
        os.symlink(str(outside), str(self.target / (EXAMPLE_UPLIFT + ".dSYM")))
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual(self._expected_freed() + 300, self._freed(proc.stdout))
        self.assertTrue((outside / "keep-me").exists())
        self.assertFalse(os.path.lexists(str(self.target / (EXAMPLE_UPLIFT + ".dSYM"))))
        self.assertFalse((self.target / (EXAMPLE_HASHED + ".dSYM")).exists())
        for rel in (EXAMPLE_HASHED, EXAMPLE_UPLIFT, EXAMPLE_HASHED + ".d", "debug/examples/demo.d"):
            self.assertFalse((self.target / rel).exists(), rel)
        for name in ("tool-fedcba9876543210", "unrelated", "keep-1111222233334444"):
            self.assertTrue((ex / name).exists(), name)
        self.assertTrue((self.target / "debug" / "keep").exists())
        # The deps <-> <profile>/<bin> uplift rule is unchanged.
        self.assertTrue((self.target / "debug" / "ai-memory").exists())

    def test_6118_notice_line_carries_the_totals(self) -> None:
        # CF6: the totals are also a ::notice:: annotation, so the first fleet
        # run's evidence is on the job summary, not deep in the step log.
        dry = self._run("--target-dir", str(self.target), "--dry-run")
        self.assertRegex(dry.stdout, r"(?m)^::notice::prune-runner-target freed_bytes=%d deleted=10 mode=dry-run$"
                         % self._expected_freed())
        real = self._run("--target-dir", str(self.target))
        self.assertEqual(0, real.returncode, real.stdout + real.stderr)
        self.assertRegex(real.stdout, r"(?m)^::notice::prune-runner-target freed_bytes=%d deleted=10 mode=pruned$"
                         % self._expected_freed())

    def test_6118_outside_workspace_real_run_needs_the_flag(self) -> None:
        # CF4: two runners sharing one out-of-workspace CARGO_TARGET_DIR would let
        # runner A's prune delete runner B's in-flight test binaries.
        ws = Path(self.scratch.name) / "workspace"
        ws.mkdir()
        env = {"GITHUB_WORKSPACE": str(ws), "CARGO_TARGET_DIR": str(self.target)}
        proc = self._run("--target-dir", str(self.target), env=env)
        self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
        self.assertTrue((self.target / "debug" / "deps" / "ai_memory-0a1b").exists())
        ok = self._run("--target-dir", str(self.target), "--allow-outside-workspace", env=env)
        self.assertEqual(0, ok.returncode, ok.stdout + ok.stderr)
        self.assertFalse((self.target / "debug" / "deps" / "ai_memory-0a1b").exists())

    # ---- round 3 (F2 = SR2-1, SR2-2, SR2-3, SR2-4) ----

    def _main_in_process(self, mod, *args: str) -> Tuple[int, str]:
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = mod.main(list(args))
        return rc, buf.getvalue()

    def test_6118_scan_unreadable_subdir_warns_and_prunes_the_rest(self) -> None:
        # F2 / SR2-1: EACCES on deps/ during the SCAN is a warning, not a
        # traceback; examples/ and incremental/ are still pruned, the totals are
        # printed, and the exit code is 1.
        deps = self.target / "debug" / "deps"
        deps.chmod(0)
        self.addCleanup(deps.chmod, 0o755)
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("::warning::prune-runner-target: debug/deps:", proc.stdout)
        self.assertEqual(EXAMPLES_AND_INCREMENTAL, self._freed(proc.stdout))
        self.assertFalse((self.target / EXAMPLE_HASHED).exists())
        self.assertEqual([], os.listdir(str(self.target / "debug" / "incremental")))
        self.assertIn("1 entry could not be read or removed (warnings above); exit 1", proc.stdout)

    def test_6118_scan_entry_vanishing_or_failing_lstat_is_handled(self) -> None:
        # F2 / SR2-1: an entry that vanishes between scandir and lstat is skipped
        # silently; any other lstat error is a warning and the scan continues.
        mod = _load_prune()
        real = mod._lstat

        def flaky(name, dir_fd):
            if name == "ai_memory-0a1b":
                raise FileNotFoundError(2, "No such file or directory", name)
            if name == "mcp_input_schema-7c7c":
                raise OSError(5, "Input/output error", name)
            return real(name, dir_fd)

        mod._lstat = flaky
        rc, out = self._main_in_process(mod, "--target-dir", str(self.target), "--dry-run")
        self.assertEqual(1, rc, out)
        self.assertIn("::warning::prune-runner-target: debug/deps/mcp_input_schema-7c7c: Input/output error", out)
        self.assertNotIn("ai_memory-0a1b", out.split("freed_bytes=")[0].replace("libai_memory-0a1b", ""))
        self.assertEqual(EXAMPLES_AND_INCREMENTAL, self._freed(out))

    def test_6118_newline_in_entry_name_cannot_inject_a_workflow_command(self) -> None:
        # SR2-2: a name printed on a `::warning::` (or any) line is escaped the way
        # GitHub decodes command values (% -> %25, CR -> %0D, LF -> %0A), so the
        # rest of a hostile name never starts its own log line.
        name = "pwn\n::error::forged-6118"
        deps = self.target / "debug" / "deps"
        _write(deps / name, 5, True)
        inner = deps / (name + ".dSYM") / "inner"
        _write(inner / "f", 3)
        inner.chmod(0o500)
        self.addCleanup(inner.chmod, 0o700)
        for args in (("--dry-run",), ()):
            proc = self._run("--target-dir", str(self.target), *args)
            lines = (proc.stdout + proc.stderr).splitlines()
            self.assertFalse([x for x in lines if x.lstrip().startswith("::error::")], proc.stdout + proc.stderr)
            self.assertIn("pwn%0A::error::forged-6118", proc.stdout, args)
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("::warning::prune-runner-target: debug/deps/pwn%0A::error::forged-6118.dSYM/inner/f:",
                      proc.stdout)
        mod = _load_prune()
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            mod.Tally().warn("a%b\rc\nd", OSError(13, "Permission denied"))
        self.assertEqual("::warning::prune-runner-target: a%25b%0Dc%0Ad: Permission denied\n", buf.getvalue())

    def test_6118_refuses_empty_target_dir(self) -> None:
        # SR2-3: `--target-dir ""` must not silently mean the current directory.
        before = _tree_size(self.target)
        for bad in ("", "  "):
            proc = self._run("--target-dir", bad, cwd=self.target)
            self.assertEqual(2, proc.returncode, (bad, proc.stdout + proc.stderr))
            self.assertIn("refusing", proc.stderr)
            self.assertIn("--target-dir", proc.stderr)
        self.assertEqual(before, _tree_size(self.target))

    def test_6118_cachedir_tag_fifo_cannot_stall_the_marker_check(self) -> None:
        # SR2-4: a CACHEDIR.TAG that is (or is swapped, after any lstat, for) a
        # FIFO must not block the open until a writer appears.
        driver = (
            "import importlib.util, os, stat, sys\n"
            "spec = importlib.util.spec_from_file_location('p', sys.argv[1])\n"
            "mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
            "root = sys.argv[2]; tag = os.path.join(root, 'CACHEDIR.TAG')\n"
            "real = mod._lstat\n"
            "def swapping(name, dir_fd):\n"
            "    st = real(name, dir_fd)\n"
            "    if name == 'CACHEDIR.TAG' and stat.S_ISREG(st.st_mode):\n"
            "        os.unlink(tag); os.mkfifo(tag)\n"
            "    return st\n"
            "mod._lstat = swapping\n"
            "fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)\n"
            "first = mod._has_cachedir_tag(fd)\n"
            "if not stat.S_ISFIFO(os.lstat(tag).st_mode):\n"
            "    os.unlink(tag); os.mkfifo(tag)\n"
            "second = mod._has_cachedir_tag(fd)\n"
            "print('RESULT', first, second)\n"
        )
        (self.target / "CACHEDIR.TAG").write_bytes(CARGO_CACHEDIR_TAG)
        try:
            proc = subprocess.run([sys.executable, "-I", "-c", driver, str(PRUNE_SCRIPT), str(self.target)],
                                  capture_output=True, text=True, check=False, timeout=20)
        except subprocess.TimeoutExpired:
            self.fail("opening a FIFO CACHEDIR.TAG blocked (SR2-4)")
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        # The first call reads the real tag unless an lstat-before-open let the
        # swap in; the second always meets a FIFO.  Neither may block.
        self.assertRegex(proc.stdout, r"RESULT (True|False) False")
        # End to end: a FIFO tag and no .cargo-lock is "not a cargo target dir".
        (self.target / "debug" / ".cargo-lock").unlink()
        try:
            cli = self._run("--target-dir", str(self.target), timeout=20)
        except subprocess.TimeoutExpired:
            self.fail("the prune CLI blocked on a FIFO CACHEDIR.TAG (SR2-4)")
        self.assertEqual(2, cli.returncode, cli.stdout + cli.stderr)
        self.assertTrue((self.target / "debug" / "deps" / "ai_memory-0a1b").exists())

    # ---- round 4 (SR3-1, SR3-2, R3-F1, R3-F3, R3-F4, R3-F5) ----

    def _hash_name_lines(self, out: str) -> List[str]:
        return [x for x in out.splitlines() if "##[" in x]

    def test_6118_r4_sr3_1_legacy_v1_command_prefix_cannot_forge_a_command(self) -> None:
        # SR3-1: the runner also parses the legacy `##[cmd]` form ANYWHERE in a
        # line, so a printed file name must not carry `##[` either: the kept
        # (nlink 2) line and the dry-run `would delete` line both echo names.
        deps = self.target / "debug" / "deps"
        kept = deps / "kv1##[error]forged-v1"
        _write(kept, 9, True)
        os.link(kept, Path(self.scratch.name) / "kv1-outside")
        _write(deps / "dr##[add-mask]x-0123456789abcdef", 7, True)
        for args in (("--dry-run",), ()):
            proc = self._run("--target-dir", str(self.target), *args)
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual([], self._hash_name_lines(proc.stdout + proc.stderr), (args, proc.stdout))
            self.assertIn("kv1%23%23[error]forged-v1", proc.stdout, args)
        mod = _load_prune()
        self.assertEqual("a%2523%0Ab%23%23[x]", mod._escape("a%23\nb##[x]"))

    def test_6118_r4_sr3_2a_scandir_failure_inside_remove_warns_and_continues(self) -> None:
        # SR3-2(a): os.scandir dups the fd, so EMFILE (EIO, ENOMEM) escapes
        # _remove; it must warn, leave the directory and report False.
        import errno
        from unittest import mock
        mod = _load_prune()
        sub = self.target / "debug" / "incremental" / "s1"
        _write(sub / "f", 3)
        parent_fd = os.open(str(sub.parent), os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, parent_fd)
        tally = mod.Tally()
        with mock.patch.object(mod.os, "scandir", side_effect=OSError(errno.EMFILE, "Too many open files")):
            ok = mod._remove(parent_fd, "s1", "debug/incremental/s1", tally, False)
        self.assertFalse(ok)
        self.assertEqual(1, len(tally.errors), tally.errors)
        self.assertIn("Too many open files", tally.errors[0])
        self.assertTrue((sub / "f").exists())

    def test_6118_r4_sr3_2b_a_very_deep_tree_warns_instead_of_crashing(self) -> None:
        # SR3-2(b): _remove recursed without a bound (RecursionError, or EMFILE
        # on the fd it holds per level).  A tree deeper than any cargo output
        # is warned about and left in place; the other candidates still go and
        # the totals still print.  Built with chdir (a path this long exceeds
        # PATH_MAX), removed the same way.
        inc = self.target / "debug" / "incremental" / "deep"
        inc.mkdir(parents=True)
        here = os.getcwd()

        def _drop_deep() -> None:
            os.chdir(str(inc))
            level = 0
            while os.path.isdir("d"):
                os.chdir("d")
                level += 1
            for _ in range(level):
                os.chdir("..")
                os.rmdir("d")
            os.chdir(here)
        self.addCleanup(_drop_deep)
        os.chdir(str(inc))
        try:
            for _ in range(1100):
                os.mkdir("d")
                os.chdir("d")
        finally:
            os.chdir(here)
        proc = self._run("--target-dir", str(self.target))
        self.assertNotIn("Traceback", proc.stderr, proc.stdout + proc.stderr)
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertRegex(proc.stdout, r"::warning::prune-runner-target: debug/incremental/deep/d/d")
        self.assertIn("::notice::prune-runner-target freed_bytes=", proc.stdout)
        self.assertFalse((self.target / "debug" / "deps" / "ai_memory-0a1b").exists())

    def test_6118_r4_r3_f3_non_utf8_name_is_escaped_not_a_traceback(self) -> None:
        # R3-F3: a file name that is not UTF-8 decodes with surrogateescape; a
        # strict UTF-8 stdout (the f2 runners run LANG=en_US.UTF-8) raised
        # UnicodeEncodeError before the totals.  _escape now backslash-escapes
        # the undecodable bytes, and main() makes stdout/stderr lossless.
        mod = _load_prune()
        raw = os.fsdecode(b"deps/tst\xfe-0123456789abcdef")
        self.assertEqual("deps/tst\\xfe-0123456789abcdef", mod._escape(raw))
        mod._escape(raw).encode("utf-8")  # must not raise
        import contextlib
        import io
        deps = os.fsencode(str(self.target / "debug" / "deps"))
        try:
            with open(os.path.join(deps, b"tst\xfe-0123456789abcdef"), "wb") as fh:
                fh.write(b"x" * 11)
            os.chmod(os.path.join(deps, b"tst\xfe-0123456789abcdef"), 0o755)
        except OSError:
            self.skipTest("this filesystem rejects non-UTF-8 names (APFS)")
        out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict")
        err = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict")
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mod.main(["--target-dir", str(self.target), "--dry-run"])
        out.flush()
        self.assertEqual(0, rc)
        text = out.buffer.getvalue().decode("utf-8")  # type: ignore[attr-defined]
        self.assertIn("deps/tst\\xfe-0123456789abcdef", text)
        self.assertIn("::notice::prune-runner-target freed_bytes=", text)

    def test_6118_r4_r3_f3_main_survives_a_stdout_that_cannot_encode_a_name(self) -> None:
        # R3-F3/SR3-2(c): the same crash for a VALID name the stream cannot
        # encode (a strict ASCII stdout); portable to APFS.  main() reconfigures
        # stdout/stderr to backslashreplace, so the run reaches its totals.
        import contextlib
        import io
        _write(self.target / "debug" / "deps" / "caf\u00e9-0123456789abcdef", 11, True)
        mod = _load_prune()
        out = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict")
        err = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict")
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mod.main(["--target-dir", str(self.target), "--dry-run"])
        out.flush()
        self.assertEqual(0, rc)
        text = out.buffer.getvalue().decode("ascii")  # type: ignore[attr-defined]
        self.assertIn("caf\\xe9-0123456789abcdef", text)
        self.assertIn("::notice::prune-runner-target freed_bytes=", text)

    def test_6118_r4_r3_f1_clone_shaped_bin_source_is_kept_by_name_and_size(self) -> None:
        # R3-F1: on macOS cargo copies (APFS clonefile) instead of hard-linking,
        # so deps/<bin>-<hash> and <profile>/<bin> are two inodes with nlink 1.
        # Pruning the deps side forces a relink of the bin ("Dirty ... couldn't
        # read metadata").  The partner is found by name and size.
        deps = self.target / "debug" / "deps"
        _write(deps / "probe_bin-cff58677ac0f78dc", 4096, True)
        _write(self.target / "debug" / "probe-bin", 4096, True)
        _write(deps / "probe_bin-1111222233334444", 5000, True)  # same crate, other size: a test exe
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertTrue((deps / "probe_bin-cff58677ac0f78dc").exists())
        self.assertTrue((self.target / "debug" / "probe-bin").exists())
        self.assertFalse((deps / "probe_bin-1111222233334444").exists())
        self.assertEqual(self._expected_freed() + 5000, self._freed(proc.stdout))
        self.assertIn("kept deps/probe_bin-cff58677ac0f78dc", proc.stdout)
        self.assertIn("debug/probe-bin", proc.stdout)

    def test_6118_r4_r3_f1_clone_shaped_example_pair_is_pruned_together(self) -> None:
        # R3-F1 (macOS): the example uplift is a clone too (two inodes, nlink 1,
        # equal size and name): the pair goes together.  freed_bytes counts each
        # clone at full size, an upper bound on APFS (clones share blocks).
        ex = self.target / "debug" / "examples"
        _write(ex / "clone-0123456789abcdef", 900, True)
        _write(ex / "clone", 900, True)
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertFalse((ex / "clone").exists())
        self.assertFalse((ex / "clone-0123456789abcdef").exists())
        self.assertEqual(self._expected_freed() + 1800, self._freed(proc.stdout))

    def test_6118_r4_r3_f4_dashed_example_pair_is_pruned_together(self) -> None:
        # R3-F4: cargo names the hashed artifact with the crate-style stem
        # (my_demo-<hash>) and uplifts it under the declared name (my-demo):
        # one inode, nlink 2.  The dash and underscore spellings are one name.
        ex = self.target / "debug" / "examples"
        _write(ex / "my_demo-228f4a433534936b", 4000, True)
        os.link(ex / "my_demo-228f4a433534936b", ex / "my-demo")
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertFalse((ex / "my-demo").exists())
        self.assertFalse((ex / "my_demo-228f4a433534936b").exists())
        self.assertEqual(self._expected_freed() + 4000, self._freed(proc.stdout))

    def test_6118_r4_r3_f5_kept_line_names_the_real_reason(self) -> None:
        # R3-F5: the kept line used to say "<profile>/<bin>" for every kept file,
        # even a hard-linked example.  It now names what was actually found.
        ex = self.target / "debug" / "examples"
        _write(ex / "keep3-0123456789abcdef", 800, True)
        os.link(ex / "keep3-0123456789abcdef", ex / "keep3")
        os.link(ex / "keep3-0123456789abcdef", ex / "keep3-third")
        deps = self.target / "debug" / "deps"
        _write(deps / "probe_bin-cff58677ac0f78dc", 4096, True)
        _write(self.target / "debug" / "probe-bin", 4096, True)
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        kept = [x for x in proc.stdout.splitlines() if x.lstrip().startswith("kept ")]
        ex_lines = [x for x in kept if "examples/keep3" in x]
        self.assertTrue(ex_lines, proc.stdout)
        for line in ex_lines:
            self.assertNotIn("<profile>/<bin>", line)
            self.assertIn("examples", line)
        bin_lines = [x for x in kept if "deps/probe_bin-" in x]
        self.assertEqual(1, len(bin_lines), kept)
        self.assertIn("debug/probe-bin", bin_lines[0])


EXAMPLE_HASHED = "debug/examples/demo-0123456789abcdef"
EXAMPLE_UPLIFT = "debug/examples/demo"
# Bytes the default scope frees from examples/ (the uplift pair once, two .d)
# plus incremental/.
EXAMPLES_AND_INCREMENTAL = 50000 + 10 + 10 + 6000


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
