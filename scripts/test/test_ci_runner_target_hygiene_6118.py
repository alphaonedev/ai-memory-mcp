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
           not a rustc flag.  A bash ``$'..'`` string is decoded first
           (``\\x1f``, ``\\037``, ``\\n``).  The guard also reads cargo TOML by
           section (``Cargo.toml``, ``.cargo/config.toml``, and any config a
           step writes): ``[profile.dev|test.package.<spec>]`` or
           ``build-override`` ``debug`` above 0 (it beats the env pin; a plain
           ``[profile.dev] debug`` does not) and a ``rustflags`` array joined
           across lines are flagged.
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

import contextlib
import inspect
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
PRUNE_SCRIPT = ROOT / "scripts" / "ci" / "prune-runner-target.py"
LOCAL_RUNS = ROOT / ".local-runs"
# chmod-based EACCES tests cannot fail for root (and APFS refuses some modes): skip them (#6303).
UID0 = hasattr(os, "geteuid") and os.geteuid() == 0


def restore_mode(path: Path, mode: int) -> None:
    """addCleanup helper: put a mode back, tolerating a path the test (or a prune) already removed (#6303)."""
    try:
        os.chmod(str(path), mode)
    except FileNotFoundError:
        pass

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
RUSTC_FLAGS_KEY_RE = re.compile(r"(CARGO_ENCODED_)?RUST(DOC)?FLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_TARGET_[A-Z0-9_]+_RUSTFLAGS"
                                r"|CARGO_PROFILE_[A-Z0-9_]+_RUSTFLAGS")
# cargo nightly switches (#6473): RUSTC_BOOTSTRAP / the channel override make the pinned stable
# toolchain accept `-Z`, `cargo-features` and `[unstable]`, e.g. profile-rustflags.
UNSTABLE_ENV_KEY_RE = re.compile(r"CARGO_UNSTABLE_[A-Z0-9_]+")
CARGO_UNSTABLE_ARG_RE = re.compile(r"\bcargo\b[^|;&\n]*?\s-Z")
# A run body is read as shell: words (quotes, escapes, ``$'..'`` decoded), operators and
# here-document bodies.  A ``KEY=value`` / ``KEY+=value`` / ``KEY<<DELIM`` inside a word or a
# here-document line is an assignment of KEY.  Kinds of KEY that matter:
#   debug      CARGO_PROFILE_<P>_DEBUG: the value must stay ``0``
#   flags      a rustc / rustdoc flags variable or config key: no ``-g`` / debuginfo>0
#   forbidden  CARGO_HOME / RUSTC / RUSTC_WRAPPER ...: each can inject a debuginfo level the
#              CARGO_PROFILE_* pins do not cover, so setting them at all is a violation
RUN_ASSIGN_RE = re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z_][A-Za-z0-9_-]*)(\+?=|<<-?)")
TOOL_OVERRIDE_KEYS = frozenset({
    "CARGO_HOME", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "rustc", "rustc-wrapper", "rustc-workspace-wrapper",
    "RUSTC_BOOTSTRAP", "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS"})
FLAGS_CONFIG_KEYS = frozenset({"rustflags", "rustdocflags"})
# Actions whose behaviour is pinned and known not to raise a debuginfo level.  A `with:` input of
# ANY step is still read; a step that `uses:` anything else (a local composite action, a reusable
# workflow reference, a docker image, a third-party action) can run cargo with any setting.
USES_ALLOWLIST = ("actions/checkout@", "dtolnay/rust-toolchain@", "Swatinem/rust-cache@",
                  "actions/setup-python@", "actions/setup-node@", "actions/upload-artifact@")
SHELL_CMD_WORDS = frozenset({"echo", "printf", "cat", "-n", "-e", "-E", "-ne", "-en", "--"})
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
        self.with_: Dict[str, str] = {}
        self.workdir = ""
        self.shell = ""
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
        self.workdir = ""  # `defaults.run.working-directory`
        self.shell = ""  # `defaults.run.shell`
        self.container = False  # a `container:` job runs its steps in an image with its own env
        self.steps: List[Step] = []

    def self_hosted(self) -> bool:
        return any(not _leg_is_hosted(leg) for leg in self.legs)

    def can_be_hosted(self) -> bool:
        """True when at least one leg lands on a GitHub-hosted image."""
        return any(_leg_is_hosted(leg) for leg in self.legs)


class Workflow:
    def __init__(self) -> None:
        self.workdir = ""  # top-level `defaults.run.working-directory`
        self.shell = ""  # top-level `defaults.run.shell`
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


_KEY_ROW = re.compile(r"^(- +)?([A-Za-z_][A-Za-z0-9_.-]*):(?: (.*))?$")
# Round 7 (3-agent vote (6def5ab6), option C): the reader accepts a strict subset of YAML and
# raises Unparsed (R-SHAPE) for everything outside it, instead of skipping what it cannot read.
WORKFLOW_KEYS = frozenset({"name", "on", "run-name", "permissions", "concurrency", "env", "defaults", "jobs"})
JOB_KEYS = frozenset({"name", "runs-on", "steps", "needs", "if", "timeout-minutes", "permissions", "outputs",
                      "env", "strategy", "environment", "continue-on-error", "defaults", "uses", "with",
                      "secrets", "concurrency", "container", "services"})
STEP_KEYS = frozenset({"id", "if", "name", "uses", "run", "shell", "with", "env", "continue-on-error",
                       "timeout-minutes", "working-directory"})
DEFAULTS_RUN_KEYS = frozenset({"shell", "working-directory"})
BLOCK_HEADER_RE = re.compile(r"[|>][+-]?")
# Shells whose run body the guard reads as shell text with nothing run before it (#6487).  A
# custom shell string runs its own words first (`env KEY=V bash {0}`, a wrapper script), and
# pwsh / python / cmd bodies are not shell, so anything else is a finding.
SHELL_ALLOWLIST = frozenset({"bash", "sh", "bash -e {0}", "bash --noprofile --norc -eo pipefail {0}", "sh -e {0}"})


def _split_key(content: str) -> Tuple[bool, str, str]:
    """(is sequence entry, key, raw value) for a ``key: value`` row, or key ''."""
    m = _KEY_ROW.match(content)
    if not m:
        return content.startswith("- "), "", content
    return m.group(1) is not None, m.group(2), (m.group(3) or "")


def _dash_width(content: str) -> int:
    """Width of the ``-`` plus spaces that open a sequence entry (0 for a plain key row)."""
    m = re.match(r"- +", content)
    return len(m.group()) if m else 0


def _children_end(rows: List[Tuple[int, str, int]], start: int, indent: int) -> int:
    i = start
    while i < len(rows) and rows[i][0] > indent:
        i += 1
    return i


def _strict_key(content: str, n: int, where: str, allowed: "frozenset[str]", seen: set) -> Tuple[str, str]:
    """(key, value) of a row the strict grammar reads; Unparsed for anything else."""
    _dash, key, value = _split_key(content)
    if not key:
        raise Unparsed("%s row at line %d is not a bare `key: value` row: %r" % (where, n, content))
    if key not in allowed:
        raise Unparsed("%s key %r at line %d is not read by this guard" % (where, key, n))
    if key in seen:
        raise Unparsed("duplicate %s key %r at line %d" % (where, key, n))
    seen.add(key)
    head = _strip_comment(value).strip()
    if head[:1] in ("&", "*", "!") or head.startswith("<<"):
        raise Unparsed("anchor, alias or tag at line %d is not read: %r" % (n, content))
    return key, value


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


def _quote_end(v: str) -> int:
    """Index of the quote that closes the scalar opened at ``v[0]``, or -1."""
    q = v[0]
    i = 1
    while i < len(v):
        ch = v[i]
        if q == '"' and ch == "\\":
            i += 2
            continue
        if ch == q:
            if q == "'" and i + 1 < len(v) and v[i + 1] == "'":
                i += 2
                continue
            return i
        i += 1
    return -1


def _scalar(value: str, n: int) -> str:
    """One inline scalar: plain, or quoted and closed on its own row; Unparsed otherwise."""
    v = _strip_comment(value).strip()
    if v[:1] in ("|", ">", "[", "{", "&", "*", "!", "%", "@", "`"):
        raise Unparsed("value at line %d is not an inline scalar: %r" % (n, value))
    if v[:1] in ("'", '"') and _quote_end(v) != len(v) - 1:
        raise Unparsed("quoted value at line %d is not closed on its row: %r" % (n, value))
    return _unquote(v)


def _no_children(rows: List[Tuple[int, str, int]], start: int, indent: int, what: str) -> None:
    if start < len(rows) and rows[start][0] > indent:
        raise Unparsed("%s continues on line %d; a multi-line value is not read: %r"
                       % (what, rows[start][2], rows[start][1]))


def _env_block(lines: List[Tuple[int, str, int]], start: int, indent: int) -> Tuple[Dict[str, str], int]:
    """Read ``KEY: value`` rows (one column, inline scalars) deeper than ``indent``; return (env, next index)."""
    env: Dict[str, str] = {}
    i = start
    col = lines[i][0] if i < len(lines) and lines[i][0] > indent else -1
    while i < len(lines) and lines[i][0] > indent:
        ind, content, n = lines[i]
        _dash, key, value = _split_key(content)
        if ind != col or not key or content.startswith("-") or key in env:
            raise Unparsed("env row is not KEY: value at line %d: %r" % (n, content))
        env[key] = _scalar(value, n)
        i += 1
        _no_children(lines, i, col, "env value %s" % key)
    return env, i


def _with_block(lines: List[Tuple[int, str, int]], start: int, indent: int) -> Tuple[Dict[str, str], int]:
    """Read a step's ``with:`` inputs; block-scalar bodies and continuations join the preceding input."""
    inputs: Dict[str, str] = {}
    i = start
    own: Optional[int] = None
    last = ""
    while i < len(lines) and lines[i][0] > indent:
        ind, content, n = lines[i]
        if own is None:
            own = ind
        if ind == own:
            _dash, key, value = _split_key(content)
            header = _strip_comment(value).strip()
            if not key or content.startswith("-") or key in inputs:
                raise Unparsed("with: row is not KEY: value at line %d: %r" % (n, content))
            if header[:1] in ("&", "*", "!"):
                raise Unparsed("anchor, alias or tag at line %d is not read: %r" % (n, content))
            if header[:1] in ("|", ">") and not BLOCK_HEADER_RE.fullmatch(header):
                raise Unparsed("block header %r at line %d is not read" % (header, n))
            inputs[key] = "" if BLOCK_HEADER_RE.fullmatch(header) else _unquote(header)
            last = key
        elif ind < own:
            raise Unparsed("with: row at line %d is left of the input column" % n)
        else:
            inputs[last] += "\n" + content
        i += 1
    return inputs, i


def _read_defaults(rows: List[Tuple[int, str, int]], start: int, indent: int) -> Tuple[str, str, int]:
    """``defaults: run: {shell, working-directory}`` -> (working directory, shell, next index)."""
    end = _children_end(rows, start, indent)
    if start == end:
        raise Unparsed("empty defaults: block at line %d" % rows[start - 1][2])
    run_ind, content, n = rows[start]
    key, value = _strict_key(content, n, "defaults", frozenset({"run"}), set())
    if value.strip() or content.startswith("-"):
        raise Unparsed("defaults.run at line %d is not a block mapping" % n)
    i = start + 1
    seen: set = set()
    got: Dict[str, str] = {}
    col = rows[i][0] if i < end else -1
    if col <= run_ind:
        raise Unparsed("empty defaults.run block at line %d" % n)
    while i < end:
        ind, content, n = rows[i]
        if ind != col or content.startswith("-"):
            raise Unparsed("defaults.run row at line %d is not at the key column: %r" % (n, content))
        key, value = _strict_key(content, n, "defaults.run", DEFAULTS_RUN_KEYS, seen)
        got[key] = _scalar(value, n)
        i += 1
        _no_children(rows, i, col, "defaults.run.%s" % key)
    return got.get("working-directory", ""), got.get("shell", ""), end


def read_workflow(text: str) -> Workflow:
    """Read the top-level env / defaults and every job's runs-on / env / matrix / defaults / steps.

    Structure rows are (indent, content, 1-based line number) with blank and
    comment lines dropped; block-scalar bodies of ``run:`` are collected from
    the RAW lines so the cargo invocations are seen verbatim.  Anything outside
    the strict subset the guard reads raises Unparsed (R-SHAPE).
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
    seen: set = set()
    i = 0
    while i < len(rows):
        ind, content, n = rows[i]
        if ind != 0:
            raise Unparsed("row at line %d is not under a top-level key" % n)
        key, value = _strict_key(content, n, "workflow", WORKFLOW_KEYS, seen)
        i += 1
        if key in ("env", "defaults", "jobs") and value.strip():
            raise Unparsed("top-level %s at line %d is not a block mapping: %r" % (key, n, content))
        if key == "env":
            wf.env, i = _env_block(rows, i, 0)
        elif key == "defaults":
            wf.workdir, wf.shell, i = _read_defaults(rows, i, 0)
        elif key == "jobs":
            i = _read_jobs(wf, rows, raw, i)
        else:
            i = _children_end(rows, i, 0)  # name / on / run-name / permissions / concurrency: inert
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
        if dash or not job_id or value.strip() or job_id in wf.jobs:
            raise Unparsed("job row at line %d is not `<id>:`: %r" % (n, content))
        job = Job(job_id)
        job_line = n
        i += 1
        runs_on_line = 0
        runs_on_block: List[Tuple[int, str, int]] = []
        seen_runs_on = False
        calls_workflow = False
        seen: set = set()
        key_col = rows[i][0] if i < len(rows) and rows[i][0] > job_indent else -1
        while i < len(rows) and rows[i][0] > job_indent:
            kind, kcontent, kn = rows[i]
            if kind != key_col or kcontent.startswith("-"):
                raise Unparsed("job %s row at line %d is not at its key column: %r" % (job_id, kn, kcontent))
            key, val = _strict_key(kcontent, kn, "job", JOB_KEYS, seen)
            i += 1
            end = _children_end(rows, i, kind)
            if key in ("env", "strategy", "defaults", "steps") and val.strip():
                raise Unparsed("job %s %s at line %d is not a block mapping: %r" % (job_id, key, kn, kcontent))
            if key == "runs-on":
                seen_runs_on = True
                runs_on_line = kn
                job.runs_on = _strip_comment(val)
                if job.runs_on.strip() == "":
                    runs_on_block.extend(rows[i:end])
                else:
                    _no_children(rows, i, kind, "runs-on")
                i = end
            elif key == "uses":
                calls_workflow = True
                i = end
            elif key == "env":
                job.env, i = _env_block(rows, i, kind)
            elif key == "strategy":
                i = _read_matrix(rows, i, kind, job)
            elif key == "defaults":
                job.workdir, job.shell, i = _read_defaults(rows, i, kind)
            elif key == "steps":
                i = _read_steps(job, rows, raw, i, kind)
            else:
                job.container = job.container or key == "container"
                i = end  # name / needs / if / permissions / outputs / ...: no cargo setting
            if i != end:
                raise Unparsed("job %s key %s at line %d was not read to its end" % (job_id, key, kn))
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
    step_col: Optional[int] = None  # column of the `-` that opens each step
    key_col = 0  # column of the current step's own keys
    seen: set = set()
    while i < len(rows) and rows[i][0] > steps_indent:
        ind, content, n = rows[i]
        width = _dash_width(content)
        if width:
            if step_col is None:
                step_col = ind
            if ind != step_col:
                raise Unparsed("step entry at line %d is not at the step column" % n)
            step = Step()
            job.steps.append(step)
            key_col = ind + width
            seen = set()
        elif step is None or ind != key_col:
            raise Unparsed("row at line %d is not a step key: %r" % (n, content))
        key, value = _strict_key(content, n, "step", STEP_KEYS, seen)
        i += 1
        end = _children_end(rows, i, key_col)
        if key in ("env", "with") and value.strip() and not value.strip().startswith("{"):
            raise Unparsed("inline step %s at line %d is not read: %r" % (key, n, content))
        if key == "env":
            if value.strip():
                raise Unparsed("inline step env at line %d is not read: %r" % (n, content))
            step.env, i = _env_block(rows, i, key_col)
        elif key == "with":
            flow = _strip_comment(value).strip()
            if flow:
                if not flow.endswith("}"):
                    raise Unparsed("inline step with at line %d is not read: %r" % (n, content))
                # `with: { a: 1, b: x }`: every entry is read like a block input.
                for part in flow[1:-1].split(","):
                    k, _sep, v = part.partition(":")
                    if k.strip():
                        step.with_[_unquote(k.strip())] = _unquote(v.strip())
                _no_children(rows, i, key_col, "with")
            else:
                step.with_, i = _with_block(rows, i, key_col)
        elif key == "run":
            header = _strip_comment(value).strip()
            if BLOCK_HEADER_RE.fullmatch(header):
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
                i = end
            else:
                step.run.append(_scalar(value, n))
                _no_children(rows, i, key_col, "run")
        else:
            text = _scalar(value, n)
            _no_children(rows, i, key_col, key)
            if key == "name":
                step.name = text
            elif key == "working-directory":
                step.workdir = text
            elif key == "if":
                step.cond = _strip_comment(value).strip()
            elif key == "uses":
                step.uses = text
            elif key == "id":
                step.step_id = text
            elif key == "shell":
                step.shell = text
        if i != end:
            raise Unparsed("step key %s at line %d was not read to its end" % (key, n))
    return i


def load_all() -> Dict[str, str]:
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    return {p.name: p.read_text(encoding="utf-8") for p in files}


REPO_CONFIG_FILES = ("Cargo.toml", ".cargo/config.toml", ".cargo/config")


def load_repo_files(root: Path = ROOT) -> Dict[str, str]:
    """The cargo manifest and every ``.cargo/config[.toml]`` a self-hosted build can read (#6255 #6297).

    Files are read as ``utf-8-sig``: cargo strips a leading byte-order mark (#6474).

    A step that changes directory (or sets ``working-directory``) makes cargo read the nearest
    ``.cargo/config.toml`` above that directory, so every one below ``root`` is checked, build
    output trees (``target``) and VCS / scratch directories excluded.
    """
    found = {name: (root / name).read_text(encoding="utf-8-sig") for name in REPO_CONFIG_FILES if (root / name).is_file()}
    for dirpath, dirnames, _files in os.walk(str(root)):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for cfg in CONFIG_NAMES:
            path = Path(dirpath) / cfg
            if path.is_file():
                found.setdefault(path.relative_to(root).as_posix(), path.read_text(encoding="utf-8-sig"))
    return found


# Cargo profile tables whose `package.<spec>` / `build-override` sub-tables beat the
# CARGO_PROFILE_<P>_DEBUG env pin (cargo 1.98.0), unlike a plain `[profile.dev] debug`.
OVERRIDE_PROFILES = frozenset({"dev", "test"})
OVERRIDE_TABLES = frozenset({"package", "build-override"})
DEV_TEST_RE = re.compile(r"\b(?:dev|test)\b")
# TOML basic-string escapes in a quoted key: \uXXXX, \UXXXXXXXX and TOML 1.1 \xHH (cargo 1.98.0, #6296)
TOML_UNICODE_RE = re.compile(r"\\u([0-9A-Fa-f]{4})|\\U([0-9A-Fa-f]{8})|\\x([0-9A-Fa-f]{2})")
BOM = "\ufeff"
TOML_ML_RE = re.compile(r"=\s*(\"\"\"|\'\'\')")
CONFIG_NAMES = (".cargo/config.toml", ".cargo/config")
SKIP_DIRS = frozenset({"target", ".git", ".local-runs", "node_modules", ".codegraph"})
SHELL_ECHO_PREFIX_RE = re.compile(r"^(?:printf|echo)\s+(?:-[A-Za-z]+\s+)*[\"']")
TOML_DEBUG_RE = re.compile(r"\bdebug\s*=\s*[\"']?([A-Za-z0-9_-]*)")


def _toml_char(code: int) -> str:
    return chr(code) if code < 0x110000 else ""


def _toml_split(text: str, sep: str) -> List[str]:
    """Split ``text`` on ``sep`` outside quotes; backslashes (shell-escaped quotes) are dropped."""
    parts: List[str] = []
    cur: List[str] = []
    quote: Optional[str] = None
    decoded = TOML_UNICODE_RE.sub(lambda m: _toml_char(int(m.group(1) or m.group(2) or m.group(3), 16)), text)
    for ch in decoded.replace("\\", ""):
        if quote:
            if ch == quote:
                quote = None
            cur.append(ch)
        elif ch in ("'", '"'):
            quote = ch
            cur.append(ch)
        elif ch == sep:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def _toml_depth(text: str) -> int:
    depth = 0
    quote: Optional[str] = None
    for ch in text:
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
    return depth


def _toml_path(key: str) -> Tuple[str, ...]:
    return tuple(p.strip().strip("\"'") for p in _toml_split(key.strip(), "."))


def _toml_entries(text: str) -> List[Tuple[Tuple[str, ...], str]]:
    """``(full key path, value text)`` of every ``key = value`` in ``text``, tables tracked.

    ``text`` may be a TOML file or a shell body that writes one (``printf '..\\n'``,
    a heredoc): the literal ``\\n`` splits a line and a leading ``printf '`` is dropped.
    A value opened with ``[`` or ``{`` runs to its closing bracket, across lines.
    """
    rows: List[str] = []
    raw_lines = text.replace("\\n", "\n").split("\n")
    k = 0
    while k < len(raw_lines):
        # cargo strips a leading byte-order mark (#6474); one written by a step sits after `printf '`
        line = SHELL_ECHO_PREFIX_RE.sub("", raw_lines[k].strip().lstrip(BOM), count=1).lstrip(BOM)
        line = _strip_comment(line).strip()
        k += 1
        opener = TOML_ML_RE.search(line)
        if opener and line.count(opener.group(1)) % 2 == 1:
            # A multi-line string (#6296): its body, up to the closing triple quote, is one value.
            while k < len(raw_lines):
                piece = raw_lines[k].strip()
                k += 1
                line += " " + piece
                if opener.group(1) in piece:
                    break
        if line:
            rows.append(line)
    out: List[Tuple[Tuple[str, ...], str]] = []
    table: Tuple[str, ...] = ()
    i = 0
    while i < len(rows):
        line = rows[i]
        i += 1
        head = re.match(r"\[\[?(.*?)\]\]?(?:[\s\"'#>]|$)", line)
        if head and "=" not in _toml_split(line, "]")[0]:
            table = _toml_path(head.group(1))
            continue
        pair = _toml_split(line, "=")
        if len(pair) < 2:
            continue
        value = "=".join(pair[1:]).strip()
        while _toml_depth(value) > 0 and i < len(rows):
            value += " " + rows[i]
            i += 1
        out.append((table + _toml_path(pair[0]), value))
    return out


def _toml_alias_command(value: str) -> str:
    """The command line of a cargo ``[alias]`` value: a string, or an array of words joined by blanks."""
    text = value.strip()
    if text.startswith("["):
        inner = text[1:-1] if text.endswith("]") else text[1:]
        return " ".join(w.strip().strip("\"'") for w in _toml_split(inner, ",") if w.strip())
    return text.strip("\"'")


def toml_debug_findings(text: str) -> List[str]:
    """Debuginfo overrides cargo would honour over the ``CARGO_PROFILE_*_DEBUG=0`` pin (#6255)."""
    found: List[str] = []
    for path, value in _toml_entries(text):
        if not path:
            continue
        dotted = ".".join(path)
        if (path[0] == "profile" and (len(path) == 1 or path[1] in OVERRIDE_PROFILES)
                and (len(path) > 1 or DEV_TEST_RE.search(value))
                and (OVERRIDE_TABLES & set(path[2:]) or any(t in value for t in OVERRIDE_TABLES))):
            levels = [value.strip("\"' ")] if path[-1] == "debug" else []
            levels.extend(m.group(1) for m in TOML_DEBUG_RE.finditer(value))
            for level in levels:
                if level and level not in LEVEL_OFF:
                    found.append("%s = %r (a profile package / build-override table beats the CARGO_PROFILE_* env)"
                                 % (dotted, level))
        # cargo keys are case-sensitive and `[env]` values never reach rustc's flags (#6316); a
        # `[profile.*]` rustflags is the profile-rustflags feature (#6473)
        if path[-1] in FLAGS_CONFIG_KEYS and (path[0] in ("build", "target", "profile") or len(path) == 1):
            for spelled in _level_spellings(value, True):
                found.append("%s carries %s" % (dotted, spelled))
        if path == ("cargo-features",) or path[0] == "unstable":
            found.append("%s (a cargo nightly feature switch; with RUSTC_BOOTSTRAP it enables profile rustflags)"
                         % dotted)
        if path[0] == "include":
            # cargo's config include (#6488) loads more config files; fail closed rather than resolve them
            found.append("%s = %s (an included config is not read)" % (dotted, value.strip()))
        if path in (("build", "target-dir"), ("build", "target")):
            found.append("%s = %s %s" % (dotted, value.strip(), PRUNE_MARK))
        if path[0] == "alias" and len(path) == 2:
            # an alias value is a cargo command line (#6475 #6489): judge it as a run line would be judged
            command = "cargo " + _toml_alias_command(value)
            for spelled in _level_spellings(command, False) + _run_findings(command):
                found.append("%s (alias) carries %s" % (dotted, spelled))
        if path[0] == "build" and len(path) == 2 and path[1] in ("rustc", "rustc-wrapper", "rustc-workspace-wrapper"):
            found.append("%s = %s (a compiler wrapper can add any debuginfo flag)" % (dotted, value.strip()))
    return found


def repo_file_violations(repo_files: Dict[str, str]) -> List[str]:
    """R-DEBUG findings in Cargo.toml and .cargo/config.toml."""
    return [_relabel("%s: R-DEBUG %s, want %r" % (name, spelled, DEBUG_LEVEL))
            for name, text in sorted(repo_files.items()) for spelled in toml_debug_findings(text)]


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


ANSI_C_ESCAPE_RE = re.compile(r"\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|c.|.)", re.S)
ANSI_C_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t",
                 "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}
SHELL_OPS = ";&|()"
EXPANSION_START_RE = re.compile(r"[A-Za-z_0-9@*#?!$-]")


def _ansi_c_one(m: "re.Match[str]") -> str:
    body = m.group(1)
    if body[0] in "xuU":
        return chr(int(body[1:], 16)) if int(body[1:], 16) < 0x110000 else ""
    if body[0] in "01234567":
        return chr(int(body, 8) & 0xFF)
    if body[0] == "c" and len(body) == 2:
        return chr(ord(body[1]) & 0x1F)
    return ANSI_C_SIMPLE.get(body, "\\" + body)


def _escapes(text: str) -> str:
    """Decode ``\\xHH`` / ``\\NNN`` / ``\\n`` ... the way ``printf`` and ``$'..'`` do (#6295)."""
    return ANSI_C_ESCAPE_RE.sub(_ansi_c_one, text) if "\\" in text else text


class Unit(NamedTuple):
    kind: str  # "word" | "line" (here-document body) | "op"
    text: str
    dynamic: bool  # the text depends on a variable / command substitution the guard cannot evaluate
    file_data: bool = False  # a here-document body that is written to a file (read by the TOML rules)
    name_dynamic: bool = False  # an expansion sits in the variable-name part of the word (#6490)


def _skip_balanced(text: str, i: int, open_ch: str, close_ch: str) -> int:
    """``text[i]`` follows an opener; return the index after its matching closer (quotes honoured)."""
    depth = 1
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = text.find("'", i + 1)
            i = n if j < 0 else j + 1
            continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _read_word(text: str, i: int) -> Tuple[str, bool, bool, int, bool]:
    """One shell word from ``text[i]``: (value, dynamic, quoted, next index, name_dynamic).

    ``name_dynamic`` (#6490) is True when an expansion sits in the NAME part of the word: before any
    ``=`` and with only name characters ahead of it (``"$K=2"``, ``CARGO_${P}_DEBUG=2``, ``"$K"``).
    """
    n = len(text)
    out: List[str] = []
    seg: List[str] = []
    dynamic = False
    quoted = False
    name_dynamic = False

    def note_name() -> None:
        nonlocal name_dynamic
        if NAME_CHARS_RE.fullmatch("".join(out) + "".join(seg)):
            name_dynamic = True

    def flush() -> None:
        if seg:
            out.append(_escapes("".join(seg)))
            del seg[:]

    def expansion(j: int) -> int:
        """``text[j] == '$'``: skip a substitution / parameter expansion; note it was dynamic."""
        nonlocal dynamic
        nxt = text[j + 1:j + 2]
        if nxt in ("(", "{") or (nxt and EXPANSION_START_RE.match(nxt)):
            note_name()
        if nxt == "(":
            dynamic = True
            return _skip_balanced(text, j + 2, "(", ")")
        if nxt == "{":
            dynamic = True
            return _skip_balanced(text, j + 2, "{", "}")
        if nxt and EXPANSION_START_RE.match(nxt):
            dynamic = True
            j += 1
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            return j + 1 if j == i + 1 else j
        seg.append("$")
        return j + 1

    while i < n:
        c = text[i]
        if c in " \t\n" or c in SHELL_OPS or c in "<>":
            break
        if c == "\\":
            nxt = text[i + 1:i + 2]
            if nxt == "\n":
                i += 2
            elif nxt and nxt in " \t\"'$;&|<>()#`":
                seg.append(nxt)
                i += 2
            else:
                seg.append(c + nxt)
                i += 2
            continue
        if c == "'":
            quoted = True
            j = text.find("'", i + 1)
            end = n if j < 0 else j
            seg.append(text[i + 1:end])
            i = end + 1
            continue
        if c == "$" and text[i + 1:i + 2] == "'":
            quoted = True
            j = i + 2
            while j < n and text[j] != "'":
                j += 2 if text[j] == "\\" else 1
            flush()
            inner = ANSI_C_ESCAPE_RE.sub(_ansi_c_one, text[i + 2:j])
            # A decoded blank, newline or \x1f stays inside the one word bash assigned; every flag
            # matcher splits on whitespace and \x1f alike, so nothing is rewritten here.
            out.append(inner)
            i = j + 1
            continue
        if c == '"' or (c == "$" and text[i + 1:i + 2] == '"'):
            quoted = True
            i += 2 if c == "$" else 1
            while i < n and text[i] != '"':
                d = text[i]
                if d == "\\":
                    nxt = text[i + 1:i + 2]
                    if nxt == "\n":
                        pass
                    elif nxt and nxt in '$"\\`':
                        seg.append(nxt)
                    else:
                        seg.append(d + nxt)
                    i += 2
                elif d == "$":
                    i = expansion(i)
                elif d == "`":
                    note_name()
                    dynamic = True
                    j = text.find("`", i + 1)
                    i = n if j < 0 else j + 1
                else:
                    seg.append(d)
                    i += 1
            i += 1
            continue
        if c == "$":
            i = expansion(i)
            continue
        if c == "`":
            note_name()
            dynamic = True
            j = text.find("`", i + 1)
            i = n if j < 0 else j + 1
            continue
        seg.append(c)
        i += 1
    flush()
    return "".join(out), dynamic, quoted, i, name_dynamic


def _redirects_to_file(units: List[Unit], raw: str) -> bool:
    """True when a command line writes to a file other than ``$GITHUB_ENV`` (stdout of ``tee`` included).

    ``raw`` is the source text of the line: ``$GITHUB_ENV`` is a variable, so the tokenised word is empty.
    """
    if "GITHUB_ENV" in raw:
        return False
    words = [u.text for u in units if u.kind == "word"]
    if "tee" in words:
        return True
    for idx, u in enumerate(units[:-1]):
        if u.kind == "op" and u.text in (">", ">>") and units[idx + 1].kind == "word":
            return True
    return False


def _shell_units(text: str) -> List[Unit]:
    """Tokenise a run body into words, operators and here-document body lines (#6312)."""
    units: List[Unit] = []
    pending: List[Tuple[str, bool, bool]] = []
    line_start = 0
    line_char = 0
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\n":
            units.append(Unit("op", "\n", False))
            file_data = _redirects_to_file(units[line_start:], text[line_char:i])
            i += 1
            for delim, strip, quoted in pending:
                while i < n:
                    j = text.find("\n", i)
                    body = text[i:n if j < 0 else j]
                    i = n if j < 0 else j + 1
                    if (body.lstrip("\t") if strip else body).strip() == delim:
                        break
                    expands = not quoted and ("$" in body or "`" in body)
                    units.append(Unit("line", body, expands, file_data))
                    units.append(Unit("op", "\n", False))
            pending = []
            line_start = len(units)
            line_char = i
            continue
        if c in " \t":
            i += 1
            continue
        if c == "\\" and text[i + 1:i + 2] == "\n":
            i += 2
            continue
        if c == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c in SHELL_OPS:
            units.append(Unit("op", c, False))
            i += 1
            continue
        if c in "{}" and (i + 1 >= n or text[i + 1] in " \t\n;&|)"):
            units.append(Unit("op", c, False))
            i += 1
            continue
        if c == "<":
            if text.startswith("<<<", i):
                units.append(Unit("op", "<<<", False))
                i += 3
            elif text.startswith("<<", i):
                j = i + 2
                strip = text[j:j + 1] == "-"
                j += 1 if strip else 0
                while j < n and text[j] in " \t":
                    j += 1
                delim, _dyn, quoted, j, _name_dyn = _read_word(text, j)
                pending.append((delim, strip, quoted))
                units.append(Unit("op", "<<", False))
                i = j
            else:
                units.append(Unit("op", "<", False))
                i += 1
            continue
        if c == ">":
            op = ">>" if text.startswith(">>", i) else ">"
            units.append(Unit("op", op, False))
            i += len(op)
            continue
        word, dynamic, _quoted, i, name_dynamic = _read_word(text, i)
        units.append(Unit("word", word, dynamic, False, name_dynamic))
    return units


# R-PRUNE (#6478): the prune step reads only ${CARGO_TARGET_DIR:-target}/<profile>, so a build that moves its
# output (another target dir, a --target triple's target/<triple>/<profile>) grows a tree it never prunes.
PRUNE_MARK = "(cargo then writes a tree the prune step never reads)"
PRUNE_ENV_KEYS = frozenset({"CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_TARGET"})
TARGET_ARG_RE = re.compile(r"\bcargo\b[^|;&\n]*?\s--target(-dir)?(?:=|\s+)(\S+)")
TARGET_CONFIG_RE = re.compile(r"\bcargo\b[^|;&\n]*?\s--config(?:=|\s+)[\"']?build\.(target(?:-dir)?)\s*=")
# Exact spellings of the live self-hosted target dirs. Each lies inside the checked-out workspace and is
# git-ignored (`/target`, `/.local-runs/*`), so actions/checkout (clean: true, the default on every
# self-hosted job) removes it with `git clean -ffdx` at the start of the next run. The shell reader drops
# the unresolved `$REPO_ROOT` prefix, so scripts/check-bootstrap-cert-gate.sh's
# "$REPO_ROOT/target/cert-gate-pg" is read as "/target/cert-gate-pg".
TARGET_DIR_ALLOWLIST = frozenset({
    ".local-runs/ci-prebuilt-t0",
    "/target/cert-gate-pg",
    "/target/cert-gate-driverless",
})


def _relabel(finding: str) -> str:
    return finding.replace("R-DEBUG", "R-PRUNE", 1) if PRUNE_MARK in finding else finding


def _key_kind(key: str) -> str:
    if DEBUG_ENV_KEY_RE.fullmatch(key):
        return "debug"
    if RUSTC_FLAGS_KEY_RE.fullmatch(key) or key in FLAGS_CONFIG_KEYS:
        return "flags"
    if key in TOOL_OVERRIDE_KEYS or UNSTABLE_ENV_KEY_RE.fullmatch(key):
        return "forbidden"
    if key in PRUNE_ENV_KEYS:
        return "prune"
    return ""


def _judge(key: str, kind: str, value: str, dynamic: bool) -> List[str]:
    if kind == "prune":
        return ["%s is set %s" % (key, PRUNE_MARK)]
    if kind == "forbidden":
        return ["%s is set (it changes which cargo config or compiler is used, so the debuginfo pins no longer "
                "decide the level)" % key]
    if dynamic:
        return ["%s is assigned a value computed at run time (variable, command substitution or here-string); "
                "the guard cannot read it" % key]
    if kind == "debug":
        level = value.strip().strip("\"'")
        return [] if level == DEBUG_LEVEL else ["%s is %r (a $GITHUB_ENV write overrides every later step)" % (key, level)]
    return _level_spellings(value, True)


def _command_strings(units: List[Unit]) -> List[str]:
    """Each simple command (and each here-document line) as one blank-separated string."""
    cmds: List[str] = []
    cur: List[str] = []
    for u in units:
        if u.kind == "word":
            cur.append(u.text)
            continue
        if u.kind == "line":
            cmds.append(u.text)
            continue
        if u.text in (";", "&", "|", "(", ")", "{", "}", "\n"):
            if cur:
                cmds.append(" ".join(cur))
            cur = []
    if cur:
        cmds.append(" ".join(cur))
    return cmds


# #6490: a variable whose NAME is computed at run time cannot be judged, so writing one is a finding.
NAME_CHARS_RE = re.compile(r"[A-Za-z0-9_]*")
DYNAMIC_NAME_SETTERS = frozenset({"export", "declare", "typeset", "readonly", "local", "echo", "printf"})
READ_NAME_COMMANDS = frozenset({"read", "mapfile", "readarray"})
READ_VALUE_OPTIONS = frozenset({"-d", "-i", "-n", "-N", "-p", "-t", "-u", "-C", "-c", "-O", "-s"})
# a printf conversion in the name position of a line of the format: `printf '%s=\n' "$name"`
PRINTF_NAME_FORMAT_RE = re.compile(r"(?:^|\n)[A-Za-z0-9_]*%[-#0 +]*[0-9*]*(?:\.[0-9*]+)?[a-zA-Z][A-Za-z0-9_]*(?:=|<<)")
DYNAMIC_NAME_LINE_RE = re.compile(r"\s*[A-Za-z0-9_]*(?:\$|`)[^\s=]*?(?:=|<<)")


def _dynamic_name_findings(words: List[str], u: "Unit", before: str) -> List[str]:
    """One word of a simple command that names a variable through an expansion (#6490)."""
    head = words[0]
    if len(words) < 2:
        return []
    if head in DYNAMIC_NAME_SETTERS and u.name_dynamic and re.match(r"[A-Za-z0-9_]*(?:=|<<)", u.text):
        return ["%s %r computes the variable name at run time; the guard cannot read it" % (head, u.text)]
    if head == "printf" and not u.dynamic and PRINTF_NAME_FORMAT_RE.search(u.text):
        return ["printf format %r computes the variable name at run time; the guard cannot read it" % u.text]
    names_var = (head == "printf" and before == "-v") or (
        head in READ_NAME_COMMANDS and before not in READ_VALUE_OPTIONS and before != "<<<")
    if names_var and u.name_dynamic and NAME_CHARS_RE.fullmatch(u.text):
        return ["%s fills a variable name computed at run time (variable name at run time); the guard cannot "
                "read it" % head]
    return []


def _run_findings(run_text: str) -> List[str]:
    """Every way a run body raises a debuginfo level, or hides that it might (#6295 #6296 #6297 #6298 #6312)."""
    units = _shell_units(run_text)
    found: List[str] = []
    for cmd in _command_strings(units):
        found.extend(_level_spellings(cmd, False))
    multi: Optional[List[object]] = None  # [key, kind, delimiter, pieces, dynamic] of an open NAME<<DELIM
    words: List[str] = []  # the words of the current simple command
    skip_target = False
    prev = ""  # the unit before this one (an operator text or a word)
    for u in units:
        before, prev = prev, u.text
        if u.kind == "op":
            if u.text in (">", ">>", "<"):
                skip_target = True
            elif u.text in (";", "&", "|", "(", ")", "{", "}", "\n"):
                words = []
            continue
        if skip_target:
            skip_target = False
            continue
        if multi is not None:
            if u.text.strip() == multi[2]:
                pieces = [p for p in multi[3] if p not in SHELL_CMD_WORDS]  # type: ignore[union-attr]
                value = "\x1f".join(pieces)
                kind = str(multi[1])
                if kind == "debug" and not pieces:
                    value = ""
                found.extend(_judge(str(multi[0]), kind, value, bool(multi[4])))
                multi = None
            else:
                multi[3].append(u.text)  # type: ignore[union-attr]
                multi[4] = bool(multi[4]) or u.dynamic
            continue
        if u.kind == "word":
            words.append(u.text)
            if words[0] in ("cd", "pushd") and len(words) == 1:
                found.append("%s changes the directory cargo reads .cargo/config from" % words[0])
            if len(words) >= 3 and words[0] == "printf" and words[-2] == "-v" and _key_kind(words[-1]):
                found.append("printf -v %s computes the value at run time; the guard cannot read it" % words[-1])
            if words[0] in ("read", "mapfile", "readarray") and len(words) > 1 and _key_kind(u.text):
                found.append("%s %s fills the variable from input; the guard cannot read it" % (words[0], u.text))
            found.extend(_dynamic_name_findings(words, u, before))
        if u.kind == "line" and u.file_data:
            continue
        if u.kind == "line" and u.dynamic and DYNAMIC_NAME_LINE_RE.match(u.text):
            found.append("a here-document line %r computes the variable name at run time; the guard cannot "
                         "read it" % u.text.strip())
        for m in RUN_ASSIGN_RE.finditer(u.text):
            kind = _key_kind(m.group(1))
            if not kind:
                continue
            rest = u.text[m.end():]
            if m.group(2).startswith("<<"):
                multi = [m.group(1), kind, rest.strip("'\" \t"), [], False]
                break
            found.extend(_judge(m.group(1), kind, rest, u.dynamic))
    return found


# Committed files a self-hosted run step may execute without the guard reading them (#6477):
# the prune script is pinned by its own tests (PruneScript6118) and never sets a cargo variable.
SCRIPT_ALLOWLIST = frozenset({"scripts/ci/prune-runner-target.py"})
SCRIPT_DEPTH = 3  # shell scripts are followed this many levels deep; a deeper chain is a finding
SHELL_RUNNERS = frozenset({"bash", "sh", "dash", "zsh", "ksh", "source", "."})
OTHER_RUNNERS = frozenset({"python", "python3", "node", "perl", "ruby", "pwsh", "make", "gmake", "just", "cmake",
                           "npx", "ninja"})
# npm runs a committed package.json script for these subcommands; `npm install -g x` stays clean (#6312 pin)
NPM_SCRIPT_SUBCOMMANDS = frozenset({"run", "run-script", "exec", "test", "t", "start", "restart", "stop"})
PREFIX_WORDS = frozenset({"exec", "time", "nohup", "env", "command", "builtin", "nice", "sudo"})
SHELL_SHEBANG_RE = re.compile(r"#!\s*\S*/(?:env\s+)?(?:ba|da|z|k)?sh\b")
ASSIGN_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def _simple_command_units(units: List[Unit]) -> List[List[Unit]]:
    """The words of each simple command, redirect targets and here-document lines left out."""
    cmds: List[List[Unit]] = []
    cur: List[Unit] = []
    skip_target = False
    for u in units:
        if u.kind == "op":
            if u.text in (">", ">>", "<"):
                skip_target = True
            elif u.text in (";", "&", "|", "(", ")", "{", "}", "\n"):
                if cur:
                    cmds.append(cur)
                cur = []
            continue
        if u.kind != "word":
            continue
        if skip_target:
            skip_target = False
            continue
        cur.append(u)
    if cur:
        cmds.append(cur)
    return cmds


def _script_ref(words: List[Unit]) -> Optional[Tuple[str, Unit]]:
    """``(kind, word)`` when a simple command runs a file: kind ``shell`` (read it), ``other`` or ``exec``."""
    i = 0
    while i < len(words):
        text = words[i].text
        if ASSIGN_WORD_RE.match(text):
            i += 1
        elif text in PREFIX_WORDS:
            if text == "command" and i + 1 < len(words) and words[i + 1].text.startswith("-v"):
                return None
            if text == "command" and i + 1 < len(words) and words[i + 1].text.startswith("-V"):
                return None
            i += 1
            while i < len(words) and words[i].text.startswith("-") and words[0].text != "exec":
                i += 1
        else:
            break
    if i >= len(words):
        return None
    head = words[i]
    rest = words[i + 1:]
    if head.dynamic:
        # a program named by a variable or substitution ("$PSQL", "$(...)") is not followed: the live
        # workflows use such heads for psql / docker, and the run-body rules still read its arguments
        return None
    if head.text in SHELL_RUNNERS:
        for w in rest:
            if w.text in ("-c", "-s") or w.text.startswith("-") and "c" in w.text.lstrip("-") and head.text != ".":
                return None  # inline code is part of the step text, read by _run_findings
            if not w.text.startswith("-") or w.dynamic:
                return ("shell", w)
        return None  # the shell reads stdin (a here-document the step text already holds)
    if head.text == "npm":
        sub = [w for w in rest if not w.text.startswith("-")]
        return ("other", head) if sub and (sub[0].dynamic or sub[0].text in NPM_SCRIPT_SUBCOMMANDS) else None
    if head.text in OTHER_RUNNERS or os.path.basename(head.text) in OTHER_RUNNERS:
        for w in rest:
            if w.text in ("-c", "-e", "-") and head.text.startswith(("python", "node", "perl", "ruby")):
                return None  # inline code / stdin: its text is part of the body the run-body rules read
            if not w.text.startswith("-") or w.dynamic:
                return ("other", w)
        return ("other", head)
    if "/" in head.text:
        return ("exec", head)
    return None


_SCRIPT_CACHE: Dict[Tuple[str, str, int], List[str]] = {}  # findings of an on-disk script, by (path, text, depth)


def _script_text(path: str, scripts: Optional[Dict[str, str]]) -> Optional[str]:
    if scripts is not None and path in scripts:
        return scripts[path]
    full = ROOT / path
    try:
        return full.read_text(encoding="utf-8-sig") if full.is_file() else None
    except (OSError, UnicodeDecodeError):
        return None


def _script_findings(text: str, scripts: Optional[Dict[str, str]] = None, depth: int = 0) -> List[str]:
    """Findings for the committed files a run body executes (#6477).

    A shell script (run with a shell, sourced, or executed with a shell shebang) is read with the run-body
    rules, following the scripts it runs up to ``SCRIPT_DEPTH`` levels. Any other program file (python,
    make, just, ...) can set any cargo variable, so it is a finding unless it is on ``SCRIPT_ALLOWLIST``.
    ``scripts`` overlays file contents by repository path (tests and mutation drivers); a path that is
    neither in it nor a file below the repository root is a finding.
    """
    found: List[str] = []
    for words in _simple_command_units(_shell_units(text)):
        ref = _script_ref(words)
        if ref is None:
            continue
        kind, word = ref
        if word.dynamic:
            found.append("a script whose path is computed at run time (%s); the guard cannot read it" % word.text)
            continue
        path = os.path.normpath(word.text).replace(os.sep, "/") if word.text else word.text
        if kind == "other" and word.text == words[-1].text and word.text in OTHER_RUNNERS:
            path = word.text
        if path in SCRIPT_ALLOWLIST:
            continue
        if path.startswith("/") or path.startswith("../") or path == "..":
            found.append("%s, a file outside the repository the guard cannot read" % word.text)
            continue
        if kind == "other":
            found.append("%s, a program the guard cannot read (it can set any cargo variable); add a reviewed "
                         "file to SCRIPT_ALLOWLIST or run a shell script" % path)
            continue
        body = _script_text(path, scripts)
        if body is None:
            found.append("%s, which is not a readable file in the repository" % path)
            continue
        if kind == "exec" and not (path.endswith((".sh", ".bash")) or SHELL_SHEBANG_RE.match(body)):
            found.append("%s, an executable that is not a shell script the guard can read" % path)
            continue
        if depth >= SCRIPT_DEPTH:
            found.append("%s, nested more than %d scripts deep" % (path, SCRIPT_DEPTH))
            continue
        cache_key = (path, body, depth)
        if scripts is None and cache_key in _SCRIPT_CACHE:
            found.extend(_SCRIPT_CACHE[cache_key])
            continue
        start = len(found)
        for spelled in _run_findings(body) + toml_debug_findings(body):
            # a `cd` inside a script is not one: every .cargo/config below the repository root is judged
            # wherever it sits (#6297), and a config the script writes is read by toml_debug_findings
            if not spelled.startswith(("cd changes", "pushd changes")):
                found.append("%s, which sets %s" % (path, spelled))
        for spelled in _script_findings(body, scripts, depth + 1):
            found.append("%s, which runs %s" % (path, spelled))
        if scripts is None:
            _SCRIPT_CACHE[cache_key] = found[start:]
    return found


def _level_spellings(text: str, flags_value: bool) -> List[str]:
    """Every debuginfo level other than off spelled in ``text`` as a rustc flag or cargo --config.

    ``flags_value``: ``text`` IS a rustc flags value (an env row of a RUSTFLAGS
    key, a flags assignment found by ``_run_findings``), so a standalone ``-g``
    anywhere in it counts; otherwise ``text`` is a command and ``-g`` counts only
    after ``rustc`` (a bare ``-g``, e.g. ``npm install -g``, is not a rustc flag).
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
        scanned = [m.group(1) for m in RUSTC_SEGMENT_RE.finditer(text)]
    if any(DASH_G_RE.search(piece) for piece in scanned):
        found.append("rustc -g (= -C debuginfo=2)")
    if not flags_value:
        for m in TARGET_ARG_RE.finditer(text):
            if not (m.group(1) and m.group(2).strip("\"'") in TARGET_DIR_ALLOWLIST):
                found.append("cargo --target%s %s %s" % (m.group(1) or "", m.group(2), PRUNE_MARK))
        for m in TARGET_CONFIG_RE.finditer(text):
            found.append("cargo --config build.%s %s" % (m.group(1), PRUNE_MARK))
        if CARGO_UNSTABLE_ARG_RE.search(text):
            found.append("cargo -Z (an unstable flag can enable profile rustflags or any other nightly setting)")
        for m in CARGO_CONFIG_ARG_RE.finditer(text):
            value = next(g for g in m.groups() if g is not None)
            if "=" not in value:
                found.append("cargo --config %s (a config file can set any debuginfo level)" % value)
        for m in CARGO_PROFILE_ARG_RE.finditer(text):
            if m.group(1) not in CARGO_PROFILES_OK:
                found.append("cargo --profile %s (a custom profile has its own debuginfo and a target/%s the prune "
                             "never touches)" % (m.group(1), m.group(1)))
    return found


def _value_findings(key: str, value: str) -> List[str]:
    """Findings for one env row or ``with:`` input named ``key``."""
    text = _yaml_unescape(value)
    found: List[str] = []
    if _key_kind(key) in ("forbidden", "prune"):
        found.extend(_judge(key, _key_kind(key), text, False))
    flags = bool(RUSTC_FLAGS_KEY_RE.fullmatch(key)) or key.lower().replace("-", "") in FLAGS_CONFIG_KEYS
    kind = _key_kind(key) or ("flags" if flags else "")
    if kind in ("debug", "flags") and "${{" in text:
        # the value is decided outside the workflow text (a variable, matrix or event data), as a
        # run-line value computed at run time is (#6476)
        found.extend(_judge(key, kind, text, True))
    found.extend(_level_spellings(text, flags))
    found.extend(_run_findings(text))
    return found


def _debug_overrides(where: str, effective: Dict[str, str], job: Job,
                     scripts: Optional[Dict[str, str]] = None) -> List[str]:
    """Every place a self-hosted job sets a debuginfo level other than ``0``."""
    found: List[str] = []
    for key, value in sorted(effective.items()):
        if key == "CARGO_TARGET_DIR":
            continue  # job- or workflow-wide, so the prune step reads ${CARGO_TARGET_DIR:-target} too
        if DEBUG_ENV_KEY_RE.fullmatch(key) and key not in DEBUG_KEYS and value != DEBUG_LEVEL:
            found.append("%s: R-DEBUG env %s is %r, want %r" % (where, key, value, DEBUG_LEVEL))
        for spelled in _value_findings(key, value):
            found.append("%s: R-DEBUG env %s carries %s, want %r" % (where, key, spelled, DEBUG_LEVEL))
    if job.workdir:
        found.append("%s: R-DEBUG defaults.run.working-directory moves cargo to another .cargo/config, want %r"
                     % (where, DEBUG_LEVEL))
    if job.shell and job.shell not in SHELL_ALLOWLIST:
        found.append("%s: R-DEBUG defaults.run.shell %r is not on the shell allowlist (a custom shell runs its own "
                     "words before every run body), want one of %s" % (where, job.shell, sorted(SHELL_ALLOWLIST)))
    if job.container:
        found.append("%s: R-DEBUG job runs its steps in a container, whose image sets its own environment and "
                     "cargo config" % where)
    for step in job.steps:
        label = step.name or step.uses or "<unnamed step>"
        if step.uses and not step.uses.startswith(USES_ALLOWLIST):
            found.append("%s: R-DEBUG step %r uses %r, which is not on the allowlist of actions known not to raise a "
                         "debuginfo level (%s)" % (where, label, step.uses, ", ".join(USES_ALLOWLIST)))
        if step.shell and step.shell not in SHELL_ALLOWLIST:
            found.append("%s: R-DEBUG step %r shell %r is not on the shell allowlist (a custom shell runs its own "
                         "words before the run body), want one of %s" % (where, label, step.shell, sorted(SHELL_ALLOWLIST)))
        if step.workdir:
            found.append("%s: R-DEBUG step %r sets working-directory %r, which moves cargo to another .cargo/config"
                         % (where, label, step.workdir))
        for key, value in sorted(step.env.items()):
            if DEBUG_ENV_KEY_RE.fullmatch(key) and value != DEBUG_LEVEL:
                found.append("%s: R-DEBUG step %r env %s is %r, want %r" % (where, label, key, value, DEBUG_LEVEL))
            for spelled in _value_findings(key, value):
                found.append("%s: R-DEBUG step %r env %s carries %s, want %r" % (where, label, key, spelled, DEBUG_LEVEL))
        for key, value in sorted(step.with_.items()):
            for spelled in _value_findings(key, value):
                found.append("%s: R-DEBUG step %r input %s carries %s, want %r" % (where, label, key, spelled, DEBUG_LEVEL))
        for spelled in _run_findings(step.run_text()):
            found.append("%s: R-DEBUG step %r run sets %s, want %r" % (where, label, spelled, DEBUG_LEVEL))
        for spelled in toml_debug_findings(step.run_text()):
            found.append("%s: R-DEBUG step %r writes a cargo config with %s, want %r" % (where, label, spelled, DEBUG_LEVEL))
        for spelled in _script_findings(step.run_text(), scripts):
            found.append("%s: R-DEBUG step %r runs %s, want %r" % (where, label, spelled, DEBUG_LEVEL))
    return [_relabel(v) for v in found]


def violations(name: str, wf: Workflow, job: Job, scripts: Optional[Dict[str, str]] = None) -> List[str]:
    """Every R-DEBUG / R-PRUNE violation for one self-hosted job."""
    found: List[str] = []
    where = "%s job %s" % (name, job.job_id)
    effective = dict(wf.env)
    effective.update(job.env)
    for key in DEBUG_KEYS:
        got = effective.get(key)
        if got != DEBUG_LEVEL:
            found.append("%s: R-DEBUG %s is %r, want %r" % (where, key, got, DEBUG_LEVEL))
    found.extend(_debug_overrides(where, effective, job, scripts))
    if wf.workdir:
        found.append("%s: R-DEBUG workflow defaults.run.working-directory moves cargo to another .cargo/config" % where)
    if wf.shell and wf.shell not in SHELL_ALLOWLIST:
        found.append("%s: R-DEBUG workflow defaults.run.shell %r is not on the shell allowlist, want one of %s"
                     % (where, wf.shell, sorted(SHELL_ALLOWLIST)))
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


def all_violations(workflows: Dict[str, str], repo_files: Optional[Dict[str, str]] = None,
                   scripts: Optional[Dict[str, str]] = None) -> List[str]:
    """Every violation; ``scripts`` overlays committed script contents by repository path (#6477)."""
    found: List[str] = []
    found.extend(repo_file_violations(load_repo_files() if repo_files is None else repo_files))
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
        found.extend(violations(name, wf, job, scripts))
    return found


def _replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) < 1:
        raise AssertionError("mutation anchor not found: " + old)
    return text.replace(old, new, 1)


class LiveWorkflows6118(unittest.TestCase):
    def test_6118_live_workflows_clean(self) -> None:
        found = all_violations(load_all(), load_repo_files())
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


class _GuardHelpers6118:
    """Workflow / repo-file mutation helpers shared by the guard test classes."""

    def setUp(self) -> None:
        self.live = load_all()
        self.ci = self.live["ci.yml"]

    def _mutated(self, text: str) -> List[str]:
        files = dict(self.live)
        files["ci.yml"] = text
        return all_violations(files)

    def _before_prune(self, step_yaml: str) -> List[str]:
        anchor = "      - name: " + PRUNE_STEP_NAME + "\n"
        self.assertEqual(1, self.ci.count(anchor), anchor)
        return self._mutated(_replace_once(self.ci, anchor, step_yaml + anchor))

    def _debug_flagged(self, found: List[str]) -> bool:
        return any("R-DEBUG" in v for v in found)

    def _repo_mutated(self, name: str, text: str) -> List[str]:
        repo = load_repo_files()
        repo[name] = text
        return all_violations(self.live, repo)


class Mutants6118(_GuardHelpers6118, unittest.TestCase):
    """Each mutant of the LIVE ci.yml must be rejected (the rules are not vacuous)."""

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

    def test_6118_m33_bash_ansi_c_quoting_hides_the_separator(self) -> None:
        # #6256: bash $'..' decodes \x1f, \037 and \n before cargo sees the value.
        for spelling in (
                "CARGO_ENCODED_RUSTFLAGS=$'-Copt-level=0\\x1f-g' cargo test --no-run",
                "CARGO_ENCODED_RUSTFLAGS=$'-g\\x1f-Copt-level=0' cargo test --no-run",
                "export CARGO_ENCODED_RUSTFLAGS=$'-Copt-level=0\\037-g'",
                "RUSTFLAGS=$'-Copt-level=0\\n-g' cargo test --no-run",
                "RUSTFLAGS=$'-Copt-level=0\\x20-g' cargo test --no-run"):
            found = self._before_prune("      - name: Ansi-C\n        run: " + spelling + "\n")
            self.assertTrue(self._debug_flagged(found), (spelling, found))
        found = self._before_prune(
            "      - name: Ansi-C benign\n        run: |\n"
            "          CARGO_ENCODED_RUSTFLAGS=$'-Copt-level=0\\x1f-Dwarnings' cargo test --no-run\n"
            "          echo $'tab\\there'\n")
        self.assertEqual([], found)

    # ---- round 5 (#6255): section-aware cargo TOML, multi-line arrays ----

    PKG_OVERRIDES = (
        '[profile.dev.package."*"]\ndebug = 2\n',
        '[profile.test.package."*"]\ndebug = "line-tables-only"\n',
        '[profile.dev]\npackage."*".debug = 2\n',
        '[profile.dev]\npackage = { "*" = { debug = 2 } }\n',
        '[profile.dev.package]\n"*" = { debug = 1 }\n',
        '[profile]\ndev.package."*".debug = 2\n',
        '[profile.dev.build-override]\ndebug = 2\n',
        '[profile.dev.package.\'*\']\ndebug = true\n',
    )
    MULTILINE_FLAGS = (
        '[build]\nrustflags = [\n  "-C",\n  "opt-level=0",\n  "-g",\n]\n',
        '[build]\nrustflags = [\n  "-Copt-level=0",\n  "-g"\n]\n',
        '[target.x86_64-unknown-linux-gnu]\nrustflags = [ # why\n  "-g",\n]\n',
    )
    BENIGN_TOML = (
        '[profile.dev]\ndebug = 2\nopt-level = 1\n',
        '[profile.dev.package."*"]\ndebug = 0\nopt-level = 3\n',
        '[profile.dev.package.foo]\ndebug = false\ndebug-assertions = true\n',
        '[profile.coverage]\ninherits = "dev"\ndebug = 1\n',
        '[profile.release.package."*"]\ndebug = 2\n',
        '[build]\nrustflags = [\n  "-D",\n  "warnings",\n]\n',
    )

    def test_6118_r5_6255_step_written_config_package_override(self) -> None:
        for body in self.PKG_OVERRIDES:
            lines = "".join("          " + ln + "\n" for ln in body.splitlines())
            found = self._before_prune(
                "      - name: Write config\n        run: |\n          cat >> .cargo/config.toml <<'EOF'\n"
                + lines + "          EOF\n")
            self.assertTrue(self._debug_flagged(found), (body, found))
        found = self._before_prune(
            "      - name: Printf config\n        run: |\n"
            "          printf '[profile.dev.package.\"*\"]\\ndebug = 2\\n' >> .cargo/config.toml\n")
        self.assertTrue(self._debug_flagged(found), found)

    def test_6118_r5_6255_cargo_manifest_package_override(self) -> None:
        live = load_repo_files()["Cargo.toml"]
        for body in self.PKG_OVERRIDES:
            found = self._repo_mutated("Cargo.toml", live.rstrip("\n") + "\n\n" + body)
            self.assertTrue(self._debug_flagged(found), (body, found))

    def test_6118_r5_6255_cargo_config_file_package_override(self) -> None:
        for body in self.PKG_OVERRIDES + self.MULTILINE_FLAGS:
            found = self._repo_mutated(".cargo/config.toml", body)
            self.assertTrue(self._debug_flagged(found), (body, found))

    def test_6118_r5_6255_multiline_rustflags_array(self) -> None:
        for body in self.MULTILINE_FLAGS:
            lines = "".join("          " + ln + "\n" for ln in body.splitlines())
            found = self._before_prune(
                "      - name: Write flags\n        run: |\n          cat > .cargo/config.toml <<'EOF'\n"
                + lines + "          EOF\n")
            self.assertTrue(self._debug_flagged(found), (body, found))
            found = self._repo_mutated("Cargo.toml", load_repo_files()["Cargo.toml"].rstrip("\n") + "\n\n" + body)
            self.assertTrue(self._debug_flagged(found), (body, found))

    def test_6118_r5_6255_benign_toml_is_clean(self) -> None:
        for body in self.BENIGN_TOML:
            self.assertEqual([], self._repo_mutated(".cargo/config.toml", body), body)
            lines = "".join("          " + ln + "\n" for ln in body.splitlines())
            found = self._before_prune(
                "      - name: Write config\n        run: |\n          cat >> .cargo/config.toml <<'EOF'\n"
                + lines + "          EOF\n")
            self.assertEqual([], found, body)


class Evasions6118(_GuardHelpers6118, unittest.TestCase):
    """R-DEBUG evasions confirmed effective under cargo 1.98 with both pins at 0 (#6295 #6296 #6297 #6298).

    Every form below sets a debuginfo level on a self-hosted runner while the
    CARGO_PROFILE_{DEV,TEST}_DEBUG=0 pins stay in place.  Each has its own test.
    """

    @staticmethod
    def _step(name: str, run: Optional[str] = None, env: Optional[List[Tuple[str, str]]] = None,
              uses: Optional[str] = None, with_: Optional[List[Tuple[str, str]]] = None,
              workdir: Optional[str] = None) -> str:
        y = "      - name: %s\n" % name
        if uses:
            y += "        uses: %s\n" % uses
        if workdir:
            y += "        working-directory: %s\n" % workdir
        if with_:
            y += "        with:\n" + "".join("          %s: %s\n" % kv for kv in with_)
        if env:
            y += "        env:\n" + "".join("          %s: %s\n" % kv for kv in env)
        if run is not None:
            y += "        run: |\n" + "".join("          %s\n" % ln for ln in run.split("\n"))
        return y

    def _caught(self, step_yaml: str) -> None:
        found = self._before_prune(step_yaml)
        self.assertTrue(self._debug_flagged(found), (step_yaml, found))

    def _clean(self, step_yaml: str) -> None:
        self.assertEqual([], self._before_prune(step_yaml), step_yaml)

    # ---- #6295: $GITHUB_ENV multi-line form and printf escapes ----

    def test_6118_r6_6295_printf_octal_escape_in_command_substitution(self) -> None:
        self._caught(self._step(
            "a", "export CARGO_ENCODED_RUSTFLAGS=\"$(printf -- '-Copt-level=0\\037-g')\"\ncargo test --no-run"))

    def test_6118_r6_6295_printf_escape_written_to_github_env(self) -> None:
        self._caught(self._step(
            "a", "printf 'CARGO_ENCODED_RUSTFLAGS=-Copt-level=0\\037-g\\n' >> \"$GITHUB_ENV\""))

    def test_6118_r6_6295_printf_hex_escape_written_to_github_env(self) -> None:
        self._caught(self._step(
            "a", "printf 'CARGO_ENCODED_RUSTFLAGS=-Copt-level=0\\x1f-g\\n' >> \"$GITHUB_ENV\""))

    def test_6118_r6_6295_github_env_multiline_debug_one_line_echo(self) -> None:
        self._caught(self._step(
            "a", "{ echo 'CARGO_PROFILE_TEST_DEBUG<<EOF'; echo 2; echo EOF; } >> \"$GITHUB_ENV\""))

    def test_6118_r6_6295_github_env_multiline_debug_separate_lines(self) -> None:
        self._caught(self._step(
            "a", "echo 'CARGO_PROFILE_DEV_DEBUG<<EOF' >> \"$GITHUB_ENV\"\necho full >> \"$GITHUB_ENV\"\n"
                 "echo EOF >> \"$GITHUB_ENV\""))

    def test_6118_r6_6295_github_env_multiline_debug_heredoc(self) -> None:
        self._caught(self._step(
            "a", "cat >> \"$GITHUB_ENV\" <<'X'\nCARGO_PROFILE_TEST_DEBUG<<EOF\nlimited\nEOF\nX"))

    def test_6118_r6_6295_github_env_multiline_rustflags_one_line_echo(self) -> None:
        self._caught(self._step(
            "a", "{ echo 'RUSTFLAGS<<EOF'; echo '-g'; echo EOF; } >> \"$GITHUB_ENV\""))

    def test_6118_r6_6295_github_env_multiline_rustflags_heredoc_debuginfo(self) -> None:
        self._caught(self._step(
            "a", "cat >> \"$GITHUB_ENV\" <<'X'\nRUSTFLAGS<<EOF\n-C debuginfo=2\nEOF\nX"))

    def test_6118_r6_6295_github_env_multiline_off_value_is_clean(self) -> None:
        self._clean(self._step(
            "a", "{ echo 'CARGO_PROFILE_TEST_DEBUG<<EOF'; echo 0; echo EOF; } >> \"$GITHUB_ENV\"\n"
                 "{ echo 'RUSTFLAGS<<EOF'; echo '-Dwarnings'; echo EOF; } >> \"$GITHUB_ENV\""))

    # ---- #6296: TOML multi-line strings and escaped quoted keys ----

    ML_BASIC = '[build]\nrustflags = """\n-g\n"""\n'
    ML_LITERAL = "[build]\nrustflags = '''\n-C\ndebuginfo=2\n'''\n"
    ESCAPED_KEY = '[build]\n"rust\\u0066lags" = ["-g"]\n'
    ESCAPED_KEY_UPPER = '[build]\n"rustfl\\U00000061gs" = ["-g"]\n'
    ENV_FLAGS = '[env]\nRUSTFLAGS = { value = "-g", force = true }\n'
    ENV_ENCODED = '[env]\nCARGO_ENCODED_RUSTFLAGS = { value = "-g", force = true }\n'

    def _config_in_file(self, body: str) -> None:
        found = self._repo_mutated(".cargo/config.toml", body)
        self.assertTrue(self._debug_flagged(found), (body, found))

    def _config_in_step(self, body: str) -> None:
        self._caught(self._step("Write config", "cat >> .cargo/config.toml <<'EOF'\n" + body + "EOF"))

    def test_6118_r6_6296_multiline_basic_string_rustflags_in_config_file(self) -> None:
        self._config_in_file(self.ML_BASIC)

    def test_6118_r6_6296_multiline_basic_string_rustflags_in_step(self) -> None:
        self._config_in_step(self.ML_BASIC)

    def test_6118_r6_6296_multiline_literal_string_rustflags_in_config_file(self) -> None:
        self._config_in_file(self.ML_LITERAL)

    def test_6118_r6_6296_multiline_literal_string_rustflags_in_step(self) -> None:
        self._config_in_step(self.ML_LITERAL)

    def test_6118_r6_6296_escaped_quoted_key_in_config_file(self) -> None:
        self._config_in_file(self.ESCAPED_KEY)
        self._config_in_file(self.ESCAPED_KEY_UPPER)

    def test_6118_r6_6296_escaped_quoted_key_in_step(self) -> None:
        self._config_in_step(self.ESCAPED_KEY)

    def test_6118_r6_6316_env_table_rustflags_is_inert_in_config_file(self) -> None:
        # cargo 1.98 ignores [env] RUSTFLAGS / CARGO_ENCODED_RUSTFLAGS for rustc.
        for body in (self.ENV_FLAGS, self.ENV_ENCODED, '[env]\nRUSTFLAGS = "-g"\n'):
            self.assertEqual([], self._repo_mutated(".cargo/config.toml", body), body)
            self.assertEqual([], self._repo_mutated("Cargo.toml", body), body)

    def test_6118_r6_6316_env_table_rustflags_is_inert_in_step(self) -> None:
        for body in (self.ENV_FLAGS, '[env]\nRUSTFLAGS = "-g"\n'):
            self._clean(self._step("Write config", "cat >> .cargo/config.toml <<'EOF'\n" + body + "EOF"))

    def test_6118_r6_6316_commented_out_rustflags_in_step_is_clean(self) -> None:
        body = '[build]\n# rustflags = ["-g"]\nrustflags = ["-Dwarnings"]\n'
        self._clean(self._step("Write config", "cat >> .cargo/config.toml <<'EOF'\n" + body + "EOF"))
        self._clean(self._step("Write config", "printf '[build]\\n# rustflags = [\"-g\"]\\n' >> .cargo/config.toml"))

    def test_6118_r6_6316_commented_out_profile_override_in_step_is_clean(self) -> None:
        body = '# [profile.dev.package."*"]\n# debug = 2\n[term]\nquiet = false\n'
        self._clean(self._step("Write config", "cat >> .cargo/config.toml <<'EOF'\n" + body + "EOF"))

    def test_6118_r6_6316_env_assignment_text_in_a_file_heredoc_is_clean(self) -> None:
        # Data written to a FILE (not $GITHUB_ENV, not an interpreter) is read by the TOML rules only.
        self._clean(self._step("a", "cat > notes.txt <<'EOF'\nRUSTFLAGS=-g\nEOF"))

    def test_6118_r6_6296_benign_multiline_string_is_clean(self) -> None:
        body = '[build]\nrustflags = """\n-Dwarnings\n"""\n[term]\nquiet = false\n'
        self.assertEqual([], self._repo_mutated(".cargo/config.toml", body))
        self._clean(self._step("Write config", "cat >> .cargo/config.toml <<'EOF'\n" + body + "EOF"))

    # ---- #6297: CARGO_HOME and nested .cargo/config.toml ----

    def test_6118_r6_6297_cargo_home_in_run_line(self) -> None:
        self._caught(self._step("a", "CARGO_HOME=$PWD/ci/cargo-home cargo test --no-run"))

    def test_6118_r6_6297_cargo_home_exported(self) -> None:
        self._caught(self._step("a", "export CARGO_HOME=\"$GITHUB_WORKSPACE/ci/home\"\ncargo test --no-run"))

    def test_6118_r6_6297_cargo_home_in_step_env(self) -> None:
        self._caught(self._step("a", "cargo test --no-run", env=[("CARGO_HOME", "ci/cargo-home")]))

    def test_6118_r6_6297_cargo_home_written_to_github_env(self) -> None:
        self._caught(self._step("a", "echo \"CARGO_HOME=$PWD/ci/cargo-home\" >> \"$GITHUB_ENV\""))

    def test_6118_r6_6297_cargo_home_in_job_env(self) -> None:
        anchor = '      CARGO_PROFILE_TEST_DEBUG: "0"\n'
        found = self._mutated(_replace_once(self.ci, anchor, anchor + "      CARGO_HOME: ci/cargo-home\n"))
        self.assertTrue(self._debug_flagged(found), found)

    def test_6118_r6_6297_cd_into_subdirectory_before_cargo(self) -> None:
        self._caught(self._step("a", "cd crates/sub && cargo test --no-run"))

    def test_6118_r6_6297_pushd_before_cargo(self) -> None:
        self._caught(self._step("a", "pushd crates/sub\ncargo test --no-run\npopd"))

    def test_6118_r6_6297_working_directory_before_cargo(self) -> None:
        self._caught(self._step("a", "cargo test --no-run", workdir="crates/sub"))

    def test_6118_r6_6297_nested_config_file_is_loaded_and_checked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nested-6297-", dir=str(LOCAL_RUNS)) as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text("[package]\nname = \"x\"\n", encoding="utf-8")
            (root / ".cargo").mkdir()
            (root / ".cargo" / "config.toml").write_text("[term]\nquiet = false\n", encoding="utf-8")
            (root / "crates" / "sub" / ".cargo").mkdir(parents=True)
            (root / "crates" / "sub" / ".cargo" / "config.toml").write_text(self.ML_BASIC, encoding="utf-8")
            (root / "target" / ".cargo").mkdir(parents=True)  # a build output tree is not source
            (root / "target" / ".cargo" / "config.toml").write_text(self.ML_BASIC, encoding="utf-8")
            repo = load_repo_files(root)
            self.assertIn("crates/sub/.cargo/config.toml", repo, sorted(repo))
            self.assertNotIn("target/.cargo/config.toml", repo, sorted(repo))
            found = all_violations(self.live, repo)
            self.assertTrue(any("crates/sub/.cargo/config.toml" in v and "R-DEBUG" in v for v in found), found)

    # ---- #6298: uses: steps, composite actions, RUSTC_WRAPPER ----

    def test_6118_r6_6298_uses_with_input_cargo_config_override(self) -> None:
        self._caught(self._step("a", uses="actions-rs/cargo@v1",
                                with_=[("command", "test"), ("args", "--config profile.dev.debug=2")]))

    def test_6118_r6_6298_uses_allowlisted_action_with_rustflags_input(self) -> None:
        self._caught(self._step("a", uses="dtolnay/rust-toolchain@stable",
                                with_=[("toolchain", "stable"), ("rustflags", "$'-Copt-level=0\\x1f-g'")]))

    def test_6118_r6_6298_uses_allowlisted_action_with_debuginfo_input(self) -> None:
        self._caught(self._step("a", uses="Swatinem/rust-cache@v2",
                                with_=[("env-vars", "RUSTFLAGS=-C debuginfo=2")]))

    def test_6118_r6_6298_uses_local_composite_action(self) -> None:
        self._caught(self._step("a", uses="./.github/actions/build-debug"))

    def test_6118_r6_6298_uses_reusable_workflow_reference_in_a_step(self) -> None:
        self._caught(self._step("a", uses="alphaonedev/ai-memory-mcp/.github/workflows/build.yml@main"))

    def test_6118_r6_6298_uses_docker_image(self) -> None:
        self._caught(self._step("a", uses="docker://rust:1.98"))

    def test_6118_r6_6298_uses_unlisted_third_party_action(self) -> None:
        self._caught(self._step("a", uses="someone/build-action@v1", with_=[("command", "test")]))

    def test_6118_r6_6298_allowlisted_uses_with_benign_inputs_is_clean(self) -> None:
        self._clean(self._step("a", uses="actions/checkout@v4", with_=[("fetch-depth", "0")]))
        self._clean(self._step("b", uses="dtolnay/rust-toolchain@stable",
                               with_=[("toolchain", "1.98.0"), ("components", "clippy, rustfmt")]))

    def test_6118_r6_6298_rustc_wrapper_in_run_line(self) -> None:
        self._caught(self._step("a", "RUSTC_WRAPPER=scripts/ci/wrap-g.sh cargo test --no-run"))

    def test_6118_r6_6298_rustc_workspace_wrapper_exported(self) -> None:
        self._caught(self._step("a", "export RUSTC_WORKSPACE_WRAPPER=scripts/ci/wrap-g.sh\ncargo test --no-run"))

    def test_6118_r6_6298_rustc_wrapper_in_step_env(self) -> None:
        self._caught(self._step("a", "cargo test --no-run", env=[("RUSTC_WRAPPER", "scripts/ci/wrap-g.sh")]))

    def test_6118_r6_6298_rustc_override_in_step_env(self) -> None:
        self._caught(self._step("a", "cargo test --no-run", env=[("RUSTC", "scripts/ci/fake-rustc.sh")]))

    def test_6118_r6_6298_rustc_wrapper_written_to_github_env(self) -> None:
        self._caught(self._step("a", "echo \"RUSTC_WRAPPER=$PWD/wrap-g.sh\" >> \"$GITHUB_ENV\""))

    def test_6118_r6_6298_rustc_wrapper_in_config_file(self) -> None:
        for body in ('[build]\nrustc-wrapper = "scripts/ci/wrap-g.sh"\n',
                     '[build]\nrustc-workspace-wrapper = "scripts/ci/wrap-g.sh"\n',
                     '[build]\nrustc = "scripts/ci/fake-rustc.sh"\n'):
            self._config_in_file(body)
            self._config_in_step(body)


    # ---- #6311: profile overrides as inline tables one level above the package table ----

    INLINE_PKG = '[profile]\ndev = { package = { "*" = { debug = 2 } } }\n'
    INLINE_TOP = 'profile = { dev = { package = { "*" = { debug = 2 } } } }\n'
    INLINE_BO = '[profile]\ndev = { build-override = { debug = 2 } }\n'
    INLINE_TEST = '[profile]\ntest = { package = { serde = { debug = "limited" } } }\n'

    def test_6118_r6_6311_inline_package_table_under_profile_in_config_file(self) -> None:
        for body in (self.INLINE_PKG, self.INLINE_TOP, self.INLINE_BO, self.INLINE_TEST):
            self._config_in_file(body)

    def test_6118_r6_6311_inline_package_table_under_profile_in_cargo_toml(self) -> None:
        for body in (self.INLINE_PKG, self.INLINE_TOP, self.INLINE_BO, self.INLINE_TEST):
            found = self._repo_mutated("Cargo.toml", body)
            self.assertTrue(self._debug_flagged(found), (body, found))

    def test_6118_r6_6311_inline_package_table_under_profile_in_step(self) -> None:
        for body in (self.INLINE_PKG, self.INLINE_TOP, self.INLINE_BO, self.INLINE_TEST):
            self._config_in_step(body)

    def test_6118_r6_6311_inline_overrides_that_do_not_raise_debuginfo_are_clean(self) -> None:
        for body in ('[profile]\ndev = { opt-level = 1 }\n',
                     '[profile]\ndev = { package = { "*" = { debug = 0 } } }\n',
                     '[profile]\nrelease = { package = { "*" = { debug = 2 } } }\n',
                     'profile = { release = { debug = 2 } }\n'):
            self.assertEqual([], self._repo_mutated(".cargo/config.toml", body), body)

    # ---- #6312: shell spellings of a rustc flags assignment (value semantics of bash) ----

    SHELL_BAD = (
        ("append", 'export RUSTFLAGS+=" -g"\ncargo test --no-run'),
        ("append, no space", "RUSTFLAGS+=-g cargo test --no-run"),
        ("locale string", 'RUSTFLAGS=$"-Copt-level=0 -g" cargo test --no-run'),
        ("dq then bare concat", 'RUSTFLAGS="-Copt-level=0 "-g cargo test --no-run'),
        ("bare then sq concat", "RUSTFLAGS=-Copt-level=0' -g' cargo test --no-run"),
        ("dq continuation", 'RUSTFLAGS="-Copt-level=0 \\\n  -g" cargo test --no-run'),
        ("dq multi-line value", 'export RUSTFLAGS="-Copt-level=0\n-g"\ncargo test --no-run'),
        ("variable indirection", 'F=-g\nRUSTFLAGS="$F" cargo test --no-run'),
        ("braced indirection", 'DBG="-C debuginfo=2"\nexport RUSTFLAGS="${DBG}"'),
        ("command substitution", 'RUSTFLAGS="$(printf %s -g)" cargo test --no-run'),
        ("backtick substitution", "RUSTFLAGS=`printf %s -g` cargo test --no-run"),
        ("printf -v", "printf -v RUSTFLAGS '%s' -g\nexport RUSTFLAGS\ncargo test --no-run"),
        ("read here-string", "read -r RUSTFLAGS <<< '-g'\nexport RUSTFLAGS\ncargo test --no-run"),
        ("encoded separator in substitution", 'CARGO_ENCODED_RUSTFLAGS="$(printf \'-Copt-level=0\\x1f-g\')" cargo t'),
        ("GITHUB_ENV echo heredoc", '{ echo "RUSTFLAGS<<EOF"; echo "-g"; echo "EOF"; } >> "$GITHUB_ENV"'),
        ("GITHUB_ENV echo", 'echo "RUSTFLAGS=-g" >> "$GITHUB_ENV"'),
        ("bash -c", "bash -c 'RUSTFLAGS=-g cargo test --no-run'"),
        ("env prefix", "env RUSTFLAGS=-g cargo test --no-run"),
        ("encoded dash escape", "RUSTFLAGS=$'\\x2dg' cargo test --no-run"),
        ("debug env computed", 'L=2\nexport CARGO_PROFILE_DEV_DEBUG="$L"'),
    )
    SHELL_GOOD = (
        ("npm -g", "npm install -g foo"),
        ("RUSTFLAGS -D", 'RUSTFLAGS="-D warnings" cargo test --no-run'),
        ("git log -g", "git log -g -1"),
        ("debuginfo 0", 'echo "RUSTFLAGS=-C debuginfo=0" >> "$GITHUB_ENV"'),
        ("prose mentions the flag", "echo 'build with RUSTFLAGS -g is slow' >&2"),
        ("comment", "# RUSTFLAGS=-g would be slow\ncargo test --no-run"),
    )

    def test_6118_r6_6312_every_bad_shell_spelling_is_caught(self) -> None:
        for label, run in self.SHELL_BAD:
            with self.subTest(label):
                self._caught(self._step("a", run))

    def test_6118_r6_6312_benign_shell_lines_stay_clean(self) -> None:
        for label, run in self.SHELL_GOOD:
            with self.subTest(label):
                self._clean(self._step("a", run))

    # ---- #6514: compiler-wrapper keys on a run line and as a with: input ----

    def test_6118_r7_6514_rustc_wrapper_keys_on_a_run_line_are_flagged(self) -> None:
        for key in ("rustc-workspace-wrapper", "rustc-wrapper", "rustc"):
            with self.subTest(key=key):
                self._caught(self._step("a", "cargo test --config build.%s='\"w\"'" % key))
        self._clean(self._step("a", "cargo test --no-run"))

    def test_6118_r7_6514_rustc_wrapper_keys_as_a_with_input_are_flagged(self) -> None:
        for key in ("rustc-workspace-wrapper", "rustc-wrapper", "rustc"):
            with self.subTest(key=key):
                self._caught(self._step("a", uses="dtolnay/rust-toolchain@stable",
                                        with_=[("toolchain", "stable"), (key, "w")]))
        self._clean(self._step("a", uses="dtolnay/rust-toolchain@stable", with_=[("toolchain", "stable")]))

    # ---- #6515: rustdocflags in a cargo config, on a run line and in step env ----

    def test_6118_r7_6515_rustdocflags_in_a_cargo_config_is_flagged(self) -> None:
        for body in ('[build]\nrustdocflags = ["-g"]\n', '[target.x86_64-unknown-linux-gnu]\nrustdocflags = ["-g"]\n'):
            with self.subTest(body=body):
                found = self._repo_mutated(".cargo/config.toml", body)
                self.assertTrue(self._debug_flagged(found), (body, found))
        self.assertEqual([], self._repo_mutated(".cargo/config.toml", '[build]\nrustdocflags = ["-Dwarnings"]\n'))

    def test_6118_r7_6515_rustdocflags_on_a_run_line_input_and_step_env_are_flagged(self) -> None:
        self._caught(self._step("a", "cargo test --config 'build.rustdocflags=[\"-g\"]'"))
        self._caught(self._step("a", "cargo test --doc", env=[("RUSTDOCFLAGS", "-g")]))
        self._caught(self._step("a", uses="dtolnay/rust-toolchain@stable",
                                with_=[("toolchain", "stable"), ("rustdocflags", "-g")]))
        self._clean(self._step("a", "cargo test --doc", env=[("RUSTDOCFLAGS", "-Dwarnings")]))



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


R7_CFG = "profile.dev.debug=2"
R7_PRE = "      - name: Probe\n"
CHECK_RUNS_ON = "    runs-on: ${{ fromJSON(matrix.runner) }}\n"


class StrictReader6118(_GuardHelpers6118, unittest.TestCase):
    """Round 7 (3-agent vote (6def5ab6), option C): the reader refuses every row it cannot read.

    Each case is valid YAML that GitHub Actions runs with debuginfo above 0 (or
    with a hidden key); each must give R-DEBUG or R-SHAPE, never silence.
    """

    def _flagged(self, found: List[str]) -> bool:
        return any("R-DEBUG" in v or "R-SHAPE" in v for v in found)

    def _step_cases(self, cases: List[Tuple[str, str]]) -> None:
        for label, step_yaml in cases:
            with self.subTest(label):
                found = self._before_prune(step_yaml)
                self.assertTrue(self._flagged(found), (label, found))

    def _job_cases(self, cases: List[Tuple[str, str]]) -> None:
        for label, job_yaml in cases:
            with self.subTest(label):
                found = self._mutated(_replace_once(self.ci, CHECK_RUNS_ON, CHECK_RUNS_ON + job_yaml))
                self.assertTrue(self._flagged(found), (label, found))

    def _top_cases(self, cases: List[Tuple[str, str]]) -> None:
        for label, top_yaml in cases:
            with self.subTest(label):
                found = self._mutated(_replace_once(self.ci, "\njobs:\n", "\n" + top_yaml + "jobs:\n"))
                self.assertTrue(self._flagged(found), (label, found))

    def test_6118_r7_6484_unreadable_step_keys_are_refused(self) -> None:
        self._step_cases([
            ("quoted run key", R7_PRE + '        "run": cargo test --no-run --config ' + R7_CFG + "\n"),
            ("single-quoted run key", R7_PRE + "        'run': cargo test --no-run --config " + R7_CFG + "\n"),
            ("space before colon", R7_PRE + "        run : cargo test --no-run --config " + R7_CFG + "\n"),
            ("quoted uses key", R7_PRE + "        'uses': evil/action@v1\n"),
            ("quoted working-directory key", R7_PRE + '        "working-directory": sub\n        run: cargo test\n'),
            ("dash and three spaces", "      -   name: Probe\n          run: cargo test --no-run --config " + R7_CFG + "\n"),
            ("bare dash then keys", "      -\n        name: Probe\n        run: cargo test --no-run --config " + R7_CFG + "\n"),
            ("anchor on run", R7_PRE + "        run: &x cargo test --no-run --config " + R7_CFG + "\n"),
            ("duplicate run key", R7_PRE + "        run: cargo test\n        run: cargo test --config " + R7_CFG + "\n"),
        ])

    def test_6118_r7_6484_unreadable_defaults_keys_are_refused(self) -> None:
        self._job_cases([
            ("job quoted working-directory", '    defaults:\n      run:\n        "working-directory": sub\n'),
            ("job working-directory space colon", "    defaults:\n      run:\n        working-directory : sub\n"),
            ("job quoted defaults key", "    'defaults':\n      run:\n        working-directory: sub\n"),
        ])
        self._top_cases([
            ("workflow quoted working-directory", 'defaults:\n  run:\n    "working-directory": sub\n'),
            ("workflow unknown top key", "x-anchors: &a\n  CARGO_PROFILE_DEV_DEBUG: '2'\n"),
        ])

    def test_6118_r7_6485_block_header_indentation_indicator_is_read_or_refused(self) -> None:
        body = "          cargo test --no-run --config " + R7_CFG + "\n"
        self._step_cases([
            ("|2", R7_PRE + "        run: |2\n" + body),
            (">2", R7_PRE + "        run: >2\n" + body),
            ("|-2", R7_PRE + "        run: |-2\n" + body),
            ("|2-", R7_PRE + "        run: |2-\n" + body),
            ("with input |2", R7_PRE + "        uses: actions/cache@v4\n        with:\n          path: |2\n"
             "            x\n          key: |2\n            --config " + R7_CFG + "\n"),
        ])

    def test_6118_r7_6486_multi_line_flow_run_is_read_or_refused(self) -> None:
        self._step_cases([
            ("plain continuation", R7_PRE + "        run: cargo test --no-run\n          --config " + R7_CFG + "\n"),
            ("double-quoted continuation", R7_PRE + '        run: "cargo test --no-run\n          --config ' + R7_CFG + '"\n'),
            ("single-quoted continuation", R7_PRE + "        run: 'cargo test --no-run\n          --config " + R7_CFG + "'\n"),
            ("unterminated quote", R7_PRE + '        run: "cargo test --no-run --config ' + R7_CFG + "\n"),
        ])


    def test_6118_r7_6487_custom_shell_and_container_are_flagged(self) -> None:
        self._step_cases([
            ("step shell env prefix", R7_PRE + "        shell: env CARGO_PROFILE_DEV_DEBUG=2 bash -e {0}\n"
             "        run: cargo test --no-run\n"),
            ("step shell RUSTFLAGS prefix", R7_PRE + "        shell: env RUSTFLAGS=-g bash -e {0}\n"
             "        run: cargo test --no-run\n"),
            ("step shell wrapper script", R7_PRE + "        shell: ./wrap.sh {0}\n        run: cargo test --no-run\n"),
            ("step shell python", R7_PRE + "        shell: python\n        run: import os\n"),
        ])
        self._job_cases([
            ("job defaults shell", "    defaults:\n      run:\n        shell: env RUSTFLAGS=-g bash -e {0}\n"),
            ("job container", "    container: rust:1.98\n"),
        ])
        self._top_cases([
            ("workflow defaults shell", "defaults:\n  run:\n    shell: env CARGO_PROFILE_TEST_DEBUG=2 bash {0}\n"),
        ])

    def test_6118_r7_6487_plain_bash_shell_is_clean(self) -> None:
        for shell in ("bash", "sh", "bash -e {0}", "bash --noprofile --norc -eo pipefail {0}"):
            with self.subTest(shell):
                found = self._before_prune(R7_PRE + "        shell: %s\n        run: cargo test --no-run\n" % shell)
                self.assertEqual([], found)


    def _repo_cases(self, cases: List[Tuple[str, str, str]]) -> None:
        for label, name, text in cases:
            with self.subTest(label):
                found = self._repo_mutated(name, text)
                self.assertTrue(any("R-DEBUG" in v for v in found), (label, found))

    def test_6118_r7_6473_profile_rustflags_and_unstable_switches_are_flagged(self) -> None:
        cfg = ".cargo/config.toml"
        self._repo_cases([
            ("manifest profile rustflags", "Cargo.toml",
             'cargo-features = ["profile-rustflags"]\n[package]\nname = "x"\n[profile.dev]\nrustflags = ["-g"]\n'),
            ("manifest package override rustflags", "Cargo.toml",
             '[profile.dev.package."*"]\nrustflags = ["-C", "debuginfo=2"]\n'),
            ("config [profile.dev] rustflags", cfg, '[profile.dev]\nrustflags = ["-g"]\n'),
            ("config [unstable] table", cfg, "[unstable]\nprofile-rustflags = true\n"),
            ("config dotted unstable key", cfg, "unstable.profile-rustflags = true\n"),
            ("manifest cargo-features alone", "Cargo.toml", 'cargo-features = ["profile-rustflags"]\n'),
        ])
        self._step_cases([
            ("env RUSTC_BOOTSTRAP", R7_PRE + "        env:\n          RUSTC_BOOTSTRAP: 1\n        run: cargo test\n"),
            ("env channel override", R7_PRE + "        env:\n          __CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS: nightly\n"
             "        run: cargo test\n"),
            ("env CARGO_UNSTABLE_*", R7_PRE + "        env:\n          CARGO_UNSTABLE_PROFILE_RUSTFLAGS: true\n"
             "        run: cargo test\n"),
            ("env CARGO_PROFILE_DEV_RUSTFLAGS", R7_PRE + "        env:\n          CARGO_PROFILE_DEV_RUSTFLAGS: -g\n"
             "        run: cargo test\n"),
            ("run RUSTC_BOOTSTRAP", R7_PRE + "        run: RUSTC_BOOTSTRAP=1 cargo test\n"),
            ("run cargo -Z", R7_PRE + "        run: cargo -Zprofile-rustflags test\n"),
            ("run cargo -Z spaced", R7_PRE + "        run: cargo test -Z unstable-options\n"),
        ])

    def test_6118_r7_6473_env_table_rustflags_stays_clean(self) -> None:
        found = self._repo_mutated(".cargo/config.toml", '[env]\nrustflags = "-g"\n')
        self.assertEqual([], found)


    BOM_PKG = '\ufeff[profile.dev.package."*"]\ndebug = 2\n'

    def test_6118_r7_6474_bom_prefixed_config_first_table_is_read(self) -> None:
        self._repo_cases([
            ("root config BOM", ".cargo/config.toml", self.BOM_PKG),
            ("nested config BOM", "crates/sub/.cargo/config.toml", self.BOM_PKG),
            ("manifest BOM", "Cargo.toml", self.BOM_PKG),
        ])
        self._step_cases([
            ("step writes BOM config", R7_PRE + "        run: |\n          printf '\ufeff[profile.dev.package.\"*\"]\\ndebug = 2\\n'"
             " > .cargo/config.toml\n          cargo test --no-run\n"),
        ])

    def test_6118_r7_6474_bom_prefixed_config_on_disk_is_read(self) -> None:
        LOCAL_RUNS.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="bom-6474-", dir=str(LOCAL_RUNS)) as tmp:
            root = Path(tmp)
            (root / ".cargo").mkdir()
            (root / ".cargo" / "config.toml").write_bytes(b'\xef\xbb\xbf[profile.dev.package."*"]\ndebug = 2\n')
            found = repo_file_violations(load_repo_files(root))
            self.assertTrue(any(".cargo/config.toml" in v and "R-DEBUG" in v for v in found), found)


    def test_6118_r7_6475_6489_cargo_alias_values_are_judged(self) -> None:
        cfg, nested = ".cargo/config.toml", "crates/sub/.cargo/config.toml"
        pkg = 'profile.dev.package.\\"*\\".debug=2'
        self._repo_cases([
            ("string alias, root config", cfg, '[alias]\nxt = "test --config %s"\n' % pkg),
            ("array alias, root config", cfg, '[alias]\nxt = ["test", "--config", "profile.dev.debug=2"]\n'),
            ("string alias, nested config", nested, '[alias]\nxt = "test --config profile.test.debug=2"\n'),
            ("array alias, nested config", nested, "[alias]\nxt = [\n  'test',\n  '--config',\n  'build.rustflags=[\"-g\"]',\n]\n"),
            ("dotted alias key", cfg, 'alias.xt = "test --config profile.dev.debug=2"\n'),
            ("alias with -Z", cfg, '[alias]\nxt = "test -Zunstable-options"\n'),
            ("alias with custom profile", cfg, '[alias]\nxt = "test --profile dbg"\n'),
            ("alias with config file", cfg, '[alias]\nxt = "test --config dbg.toml"\n'),
            ("alias rustc -g", cfg, '[alias]\nxr = "rustc -- -g"\n'),
        ])

    def test_6118_r7_6475_plain_alias_stays_clean(self) -> None:
        found = self._repo_mutated(".cargo/config.toml", '[alias]\nxt = "test --no-run --locked"\nb = ["build", "--release"]\n')
        self.assertEqual([], found)


    JOB_ENV = "    timeout-minutes: ${{ matrix.timeout }}\n    env:\n"
    WF_ENV = '  CARGO_INCREMENTAL: "0"\n\njobs:\n'

    def _env_rows(self, rows: List[Tuple[str, str]]) -> List[Tuple[str, List[str]]]:
        out: List[Tuple[str, List[str]]] = []
        for label, row in rows:
            out.append(("step " + label, self._before_prune(
                R7_PRE + "        env:\n          %s\n        run: cargo test --no-run\n" % row)))
            out.append(("job " + label, self._mutated(_replace_once(self.ci, self.JOB_ENV, self.JOB_ENV + "      %s\n" % row))))
            out.append(("workflow " + label, self._mutated(
                _replace_once(self.ci, self.WF_ENV, '  CARGO_INCREMENTAL: "0"\n  %s\n\njobs:\n' % row))))
        return out

    def test_6118_r7_6476_expression_valued_env_and_with_rows_are_flagged(self) -> None:
        cases = self._env_rows([
            ("RUSTFLAGS vars", "RUSTFLAGS: ${{ vars.EXTRA_RUSTFLAGS }}"),
            ("RUSTFLAGS event data", "RUSTFLAGS: ${{ github.event.pull_request.title }}"),
            ("CARGO_ENCODED_RUSTFLAGS matrix", "CARGO_ENCODED_RUSTFLAGS: ${{ matrix.flags }}"),
            ("RUSTDOCFLAGS quoted", "RUSTDOCFLAGS: \"-C opt-level=0 ${{ vars.X }}\""),
            ("profile rustflags", "CARGO_PROFILE_DEV_RUSTFLAGS: ${{ vars.X }}"),
            ("target rustflags", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS: ${{ vars.X }}"),
            ("debug key", "CARGO_PROFILE_DEV_BUILD_OVERRIDE_DEBUG: ${{ vars.DBG }}"),
        ])
        cases.append(("with rustflags input", self._before_prune(
            R7_PRE + "        uses: dtolnay/rust-toolchain@stable\n        with:\n"
            "          rustflags: ${{ vars.EXTRA_RUSTFLAGS }}\n")))
        for label, found in cases:
            with self.subTest(label):
                self.assertTrue(any("R-DEBUG" in v for v in found), (label, found))

    def test_6118_r7_6476_expression_valued_unrelated_env_stays_clean(self) -> None:
        for label, found in self._env_rows([("unrelated key", "SCCACHE_GHA_ENABLED: ${{ vars.X }}")]):
            with self.subTest(label):
                self.assertEqual([], found)


    def test_6118_r7_6296_toml_hex_escape_in_quoted_key_is_decoded(self) -> None:
        self._repo_cases([
            ("config rustflags key", ".cargo/config.toml", '[build]\n"rust\\x66lags" = ["-g"]\n'),
            ("manifest package debug key", "Cargo.toml", '[profile.dev.package."*"]\n"deb\\x75g" = 2\n'),
            ("nested config dotted key", "crates/sub/.cargo/config.toml", 'build."rust\\x66lags" = "-g"\n'),
        ])


    def _script_cases(self, files: Dict[str, str], cases: List[Tuple[str, str]], want: bool) -> None:
        """Write ``files`` under a scratch dir below the repo root, then run each ``run:`` line ({d} = that dir)."""
        LOCAL_RUNS.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="scripts-6477-", dir=str(LOCAL_RUNS)) as tmp:
            rel = Path(tmp).relative_to(ROOT).as_posix()
            for name, text in files.items():
                (Path(tmp) / name).parent.mkdir(parents=True, exist_ok=True)
                (Path(tmp) / name).write_text(text.replace("{d}", rel), encoding="utf-8")
            for label, run in cases:
                with self.subTest(label):
                    step = R7_PRE + "        run: |\n" + "".join(
                        "          %s\n" % line for line in run.replace("{d}", rel).split("\n"))
                    found = self._before_prune(step)
                    if want:
                        self.assertTrue(any("R-DEBUG" in v for v in found), (label, found))
                    else:
                        self.assertEqual([], found, label)

    SCRIPTS_6477 = {
        "build.sh": "#!/usr/bin/env bash\nexport RUSTFLAGS=-g\ncargo build\n",
        "env.sh": "export CARGO_PROFILE_DEV_DEBUG=2\n",
        "outer.sh": "#!/bin/sh\nbash {d}/build.sh\n",
        "d1.sh": "bash {d}/d2.sh\n", "d2.sh": "bash {d}/d3.sh\n", "d3.sh": "bash {d}/d4.sh\n",
        "d4.sh": "bash {d}/build.sh\n",
        "build.py": "import os\nos.environ['RUSTFLAGS'] = '-g'\n",
        "clean.sh": "#!/usr/bin/env bash\nset -euo pipefail\necho hi\ncargo test --no-run\n",
    }

    def test_6118_r7_6477_committed_scripts_run_from_a_step_are_read(self) -> None:
        self._script_cases(self.SCRIPTS_6477, [
            ("bash script exports RUSTFLAGS", "bash {d}/build.sh"),
            ("sh script", "sh {d}/build.sh"),
            ("direct path", "./{d}/build.sh"),
            ("env prefix then bash", "X=1 bash {d}/build.sh"),
            ("source sets debug level", "source {d}/env.sh\ncargo test --no-run"),
            ("dot sets debug level", ". {d}/env.sh\ncargo test --no-run"),
            ("nested script", "bash {d}/outer.sh"),
            ("nesting deeper than three", "bash {d}/d1.sh"),
            ("python script", "python3 {d}/build.py"),
            ("make", "make build"),
            ("just", "just build"),
            ("missing script", "bash {d}/no-such-script.sh"),
            ("script path computed at run time", 'bash "$SCRIPT_6477"'),
        ], True)

    def test_6118_r7_6477_clean_script_and_allowlisted_tool_stay_clean(self) -> None:
        self._script_cases(self.SCRIPTS_6477, [
            ("clean script", "bash {d}/clean.sh"),
            ("command -v probe", "command -v python3 >/dev/null"),
            ("script named in an echo", "echo see {d}/build.sh"),
        ], False)


    def test_6118_r7_6477_script_overlay_and_npm_scripts(self) -> None:
        anchor = "      - name: " + PRUNE_STEP_NAME + "\n"
        for label, run, overlay, want in (
            ("overlay script sets RUSTFLAGS", "bash scripts/ci/x-6477.sh", {"scripts/ci/x-6477.sh": "export RUSTFLAGS=-g\n"}, True),
            ("overlay script is clean", "bash scripts/ci/x-6477.sh", {"scripts/ci/x-6477.sh": "cargo test --no-run\n"}, False),
            ("no overlay, no file", "bash scripts/ci/x-6477.sh", None, True),
            ("npm run", "npm run build", None, True),
            ("npx", "npx some-tool", None, True),
            ("npm ci", "npm ci", None, False),
        ):
            with self.subTest(label):
                files = dict(self.live)
                files["ci.yml"] = _replace_once(self.ci, anchor, R7_PRE + "        run: %s\n" % run + anchor)
                found = all_violations(files, None, overlay)
                self.assertEqual(want, any("R-DEBUG" in v for v in found), (label, found))


    def _prune_flagged(self, cases: List[Tuple[str, List[str]]], want: bool) -> None:
        for label, found in cases:
            with self.subTest(label):
                if want:
                    self.assertTrue(any("R-PRUNE" in v for v in found), (label, found))
                else:
                    self.assertEqual([], found, label)

    def test_6118_r7_6478_builds_outside_the_pruned_tree_are_flagged(self) -> None:
        def run(line: str) -> List[str]:
            return self._before_prune(R7_PRE + "        run: %s\n" % line)

        def step_env(row: str) -> List[str]:
            return self._before_prune(R7_PRE + "        env:\n          %s\n        run: cargo test --no-run\n" % row)

        cfg = ".cargo/config.toml"
        self._prune_flagged([
            ("run --target-dir", run("cargo test --no-run --target-dir elsewhere")),
            ("run --target-dir=", run("cargo build --target-dir=/srv/elsewhere")),
            ("run --target triple", run("cargo test --no-run --target x86_64-unknown-linux-gnu")),
            ("run --target=triple", run("cargo test --no-run --target=x86_64-unknown-linux-gnu")),
            ("run --config build.target-dir", run("cargo test --no-run --config build.target-dir=\\\"elsewhere\\\"")),
            ("run --config build.target", run("cargo test --no-run --config 'build.target=\"x86_64-unknown-linux-gnu\"'")),
            ("run CARGO_TARGET_DIR prefix", run("CARGO_TARGET_DIR=elsewhere cargo test --no-run")),
            ("run export CARGO_BUILD_TARGET", run("export CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu")),
            ("run GITHUB_ENV CARGO_BUILD_TARGET_DIR", run("echo \"CARGO_BUILD_TARGET_DIR=elsewhere\" >> \"$GITHUB_ENV\"")),
            ("step env CARGO_TARGET_DIR", step_env("CARGO_TARGET_DIR: elsewhere")),
            ("step env CARGO_BUILD_TARGET", step_env("CARGO_BUILD_TARGET: x86_64-unknown-linux-gnu")),
            ("job env CARGO_BUILD_TARGET_DIR", self._mutated(_replace_once(
                self.ci, self.JOB_ENV, self.JOB_ENV + "      CARGO_BUILD_TARGET_DIR: elsewhere\n"))),
            ("config [build] target-dir", self._repo_mutated(cfg, '[build]\ntarget-dir = "elsewhere"\n')),
            ("config [build] target", self._repo_mutated(cfg, '[build]\ntarget = "x86_64-unknown-linux-gnu"\n')),
            ("nested config dotted build.target-dir", self._repo_mutated("crates/sub/.cargo/config.toml",
                                                                         'build.target-dir = "elsewhere"\n')),
            ("step writes build.target-dir", run("printf '[build]\\ntarget-dir = \"elsewhere\"\\n' > .cargo/config.toml")),
        ], True)

    def test_6118_r7_6478_job_level_cargo_target_dir_stays_clean(self) -> None:
        # the prune step reads ${CARGO_TARGET_DIR:-target}, so a job-wide CARGO_TARGET_DIR is pruned
        self._prune_flagged([("job env CARGO_TARGET_DIR", self._mutated(_replace_once(
            self.ci, self.JOB_ENV, self.JOB_ENV + "      CARGO_TARGET_DIR: /srv/target\n")))], False)


    # ---- #6488: cargo config `include` loads a file the guard never reads ----

    def test_6118_r7_6488_cargo_config_include_is_flagged(self) -> None:
        cfg = ".cargo/config.toml"
        want = "an included config is not read"
        cases = [
            ("include array", self._repo_mutated(cfg, 'include = ["extra.toml"]\n')),
            ("include string", self._repo_mutated(cfg, 'include = "extra.toml"\n')),
            ("include array of tables", self._repo_mutated(cfg, '[[include]]\npath = "extra.toml"\n')),
            ("include inline tables", self._repo_mutated(cfg, 'include = [{ path = "extra.toml", optional = true }]\n')),
            ("nested config include", self._repo_mutated("crates/sub/.cargo/config.toml", 'include = ["x.toml"]\n')),
            ("step writes include", self._before_prune(
                R7_PRE + "        run: printf 'include = [\"extra.toml\"]\\n' >> .cargo/config.toml\n")),
        ]
        for label, found in cases:
            with self.subTest(label):
                self.assertTrue(any(want in v and "R-DEBUG" in v for v in found), (label, found))

    def test_6118_r7_6488_include_named_key_inside_a_table_stays_clean(self) -> None:
        # only the top-level `include` key is cargo's config include; [env] include is an env var
        self.assertEqual([], self._repo_mutated(".cargo/config.toml", '[env]\ninclude = "x"\n'))

    # ---- #6490: a variable NAME computed at run time ----

    def test_6118_r7_6490_dynamic_variable_names_are_flagged(self) -> None:
        want = "variable name at run time"
        k = "K=CARGO_PROFILE_DEV_DEBUG\n          "
        cases = [
            ("export quoted", k + 'export "$K=2"'),
            ("export braced", k + "export ${K}=2"),
            ("declare -x", k + 'declare -x "$K=2"'),
            ("typeset -x", k + 'typeset -x "${K}=2"'),
            ("GITHUB_ENV echo", k + 'echo "${K}=2" >> "$GITHUB_ENV"'),
            ("GITHUB_ENV echo partial name", 'P=DEV\n          echo "CARGO_PROFILE_${P}_DEBUG=2" >> "$GITHUB_ENV"'),
            ("GITHUB_ENV echo command substitution", 'echo "$(echo CARGO_PROFILE_DEV_DEBUG)=2" >> "$GITHUB_ENV"'),
            ("GITHUB_ENV printf format", k + "printf '%s=2\\n' \"$K\" >> \"$GITHUB_ENV\""),
            ("GITHUB_ENV multi-line form", k + '{ echo "${K}<<EOF"; echo 2; echo EOF; } >> "$GITHUB_ENV"'),
            ("GITHUB_ENV here-document", k + 'cat >> "$GITHUB_ENV" <<EOF\n          ${K}=2\n          EOF'),
            ("printf -v", k + "printf -v \"$K\" '%s' 2\n          export \"$K\""),
            ("read", k + 'read -r "$K" <<< 2\n          export "$K"'),
        ]
        for label, body in cases:
            with self.subTest(label):
                found = self._before_prune(R7_PRE + "        run: |\n          %s\n          cargo test --no-run\n" % body)
                self.assertTrue(any(want in v and "R-DEBUG" in v for v in found), (label, found))

    def test_6118_r7_6490_literal_names_with_dynamic_values_stay_clean(self) -> None:
        for label, body in [
            ("value expansion", 'echo "EXTRA_PATH=${X}" >> "$GITHUB_ENV"'),
            ("export value", 'export FOO="$BAR"'),
            ("printf without a name", "printf '%s\\n' \"$x\""),
            ("read a plain name", "read -r line <<< x"),
            ("notice", 'echo "::notice::$name kept"'),
            ("literal scrub", '{ echo "AI_MEMORY_DB_PASSPHRASE="; echo "AI_MEMORY_DB_PASSPHRASE_FILE="; } >> "$GITHUB_ENV"'),
        ]:
            with self.subTest(label):
                self.assertEqual([], self._before_prune(
                    R7_PRE + "        run: |\n          %s\n          cargo test --no-run\n" % body), label)

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

    def test_6118_unremovable_entry_warns_continues_and_exits_0(self) -> None:
        # S-F3: any other OSError is a warning; the rest is still pruned, the
        # totals are still printed, and the exit code is 1 at the end.
        dwarf = self.target / "debug" / "deps" / "mcp_input_schema-7c7c.dSYM" / "Contents" / "Resources" / "DWARF"
        if UID0:
            self.skipTest("root ignores directory permission bits")
        dwarf.chmod(0o500)
        self.addCleanup(restore_mode, dwarf, 0o700)
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
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
        self.assertRegex(dry.stdout, r"(?m)^::notice::prune-runner-target freed_bytes=%d deleted=10 mode=dry-run warnings=0$"
                         % self._expected_freed())
        real = self._run("--target-dir", str(self.target))
        self.assertEqual(0, real.returncode, real.stdout + real.stderr)
        self.assertRegex(real.stdout, r"(?m)^::notice::prune-runner-target freed_bytes=%d deleted=10 mode=pruned warnings=0$"
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
        if UID0:
            self.skipTest("root ignores directory permission bits")
        deps.chmod(0)
        self.addCleanup(restore_mode, deps, 0o755)
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("::warning::prune-runner-target: debug/deps:", proc.stdout)
        self.assertEqual(EXAMPLES_AND_INCREMENTAL, self._freed(proc.stdout))
        self.assertFalse((self.target / EXAMPLE_HASHED).exists())
        self.assertEqual([], os.listdir(str(self.target / "debug" / "incremental")))
        self.assertIn("1 entry could not be read or removed (warnings above); exit 0", proc.stdout)

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
        self.assertEqual(0, rc, out)
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
        if UID0:
            self.skipTest("root ignores directory permission bits")
        inner.chmod(0o500)
        self.addCleanup(restore_mode, inner, 0o700)
        for args in (("--dry-run",), ()):
            proc = self._run("--target-dir", str(self.target), *args)
            lines = (proc.stdout + proc.stderr).splitlines()
            self.assertFalse([x for x in lines if x.lstrip().startswith("::error::")], proc.stdout + proc.stderr)
            self.assertIn("pwn%0A::error::forged-6118", proc.stdout, args)
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
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
        mock = unittest.mock
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
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
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

    # ---- round 5 (#6254..#6258) ----

    def _control_bytes(self, out: str) -> List[str]:
        """Every character of ``out`` that a terminal or a log viewer would act on (LF ends a line, so it stays)."""
        return sorted({repr(c) for c in out if (ord(c) < 0x20 and c != "\n") or 0x7F <= ord(c) <= 0x9F})

    def test_6118_r5_6254_control_characters_in_names_never_reach_the_log_raw(self) -> None:
        # #6254 (SR4-1): a file name with ESC, BEL, BS, VT, FF, DEL or a C1
        # character reaches a LATER job's log through the kept, `would delete`
        # and warning lines; the web viewer recolours or hides text on an ANSI
        # SGR sequence.  Every C0 control other than CR/LF, DEL and C1 is
        # written as \xNN.
        mod = _load_prune()
        self.assertEqual("a\\x1b[31mb\\x07c\\x7fd\\u{85}e\\x09f", mod._escape("a\x1b[31mb\x07c\x7fd\u0085e\tf"))
        self.assertEqual("a%0Db%0Ac%25", mod._escape("a\rb\nc%"))  # the existing escapes still win for CR / LF / %
        deps = self.target / "debug" / "deps"
        for name in ("esc\x1b[31m-0123456789abcdef", "bel\x07x-0123456789abcdef", "del\x7fx-0123456789abcdef",
                     "ctl\x08\x0b\x0c-0123456789abcdef", "c1\u0085x-0123456789abcdef"):
            _write(deps / name, 9, True)
        kept = deps / "kept\x1b]0;title\x07name"
        _write(kept, 9, True)
        os.link(kept, Path(self.scratch.name) / "kept-outside")
        for args in (("--dry-run",), ()):
            proc = self._run("--target-dir", str(self.target), *args)
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual([], self._control_bytes(proc.stdout + proc.stderr), (args, proc.stdout))
            self.assertIn("kept\\x1b]0;title\\x07name", proc.stdout, args)
            if args:  # only the dry run lists the names it would delete
                self.assertIn("esc\\x1b[31m-0123456789abcdef", proc.stdout, args)

    def test_6118_r5_6258_category_rows_count_only_successful_deletions(self) -> None:
        # #6258: execute() counted every candidate in its category row, whether
        # `_remove` succeeded or not, so a row read "incremental 3" beside
        # `deleted=2`.  An injected EACCES on one executable: the row counts the
        # removals only, the failure is reported on its own, and the row counts
        # sum to the `deleted` figure.
        mod = _load_prune()
        real_unlink = os.unlink

        def flaky(path, *args, **kwargs):  # type: ignore[no-untyped-def]
            if path == "mcp_input_schema-7c7c":
                raise PermissionError(13, "Permission denied")
            return real_unlink(path, *args, **kwargs)

        plan = mod.plan_target(str(self.target), "debug", "test-bins", env={})
        try:
            with unittest.mock.patch.object(mod.os, "unlink", flaky):
                tally = mod.execute(plan, dry_run=False)
        finally:
            plan.close()
        self.assertEqual(1, len(tally.errors), tally.errors)
        counted = sum(count for count, _size in tally.per_category.values())
        self.assertEqual(tally.deleted, counted, tally.per_category)
        self.assertEqual(1, tally.per_category["deps executable"][0], tally.per_category)
        self.assertEqual({"deps executable": 1}, tally.failed)
        out = io.StringIO()
        dir_fd_ok = set(os.supports_dir_fd) | {flaky}  # main() refuses an os.unlink without dir_fd support
        with unittest.mock.patch.object(mod.os, "unlink", flaky), \
                unittest.mock.patch.object(mod.os, "supports_dir_fd", dir_fd_ok), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = mod.main(["--target-dir", str(self.target)])
        self.assertEqual(0, rc, out.getvalue())
        self.assertRegex(out.getvalue(), r"(?m)^  failed\s+deps executable\s+1$")
        self.assertNotRegex(out.getvalue(), r"(?m)^  deps executable\s+2\b")

    def test_6118_r5_6257_example_dsym_uplift_symlink_does_not_dangle(self) -> None:
        # #6257: with packed split debuginfo on macOS cargo writes
        # examples/<name>.dSYM -> <name>-<hash>.dSYM next to the nlink-1 clone
        # pair.  The pair and the hashed dSYM go; the link into it must go too
        # (as a link, never followed) instead of dangling.  A link that points
        # anywhere else is none of the prune's business and stays.
        ex = self.target / "debug" / "examples"
        _write(ex / "clonex-0123456789abcdef", 900, True)
        _write(ex / "clonex", 900, True)
        _write(ex / "clonex-0123456789abcdef.dSYM" / "Contents" / "Info.plist", 40)
        (ex / "clonex.dSYM").symlink_to("clonex-0123456789abcdef.dSYM")
        _write(ex / "stray", 300, True)
        outside_dsym = Path(self.scratch.name) / "outside-dsym"
        _write(outside_dsym / "keep", 5)
        (ex / "stray.dSYM").symlink_to(outside_dsym)
        for args in (("--dry-run",), ()):
            proc = self._run("--target-dir", str(self.target), *args)
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            if args:
                self.assertTrue(os.path.lexists(ex / "clonex.dSYM"))
                self.assertIn("debug/examples/clonex.dSYM", proc.stdout)
        self.assertFalse(os.path.lexists(ex / "clonex.dSYM"), os.listdir(ex))
        self.assertFalse((ex / "clonex-0123456789abcdef.dSYM").exists())
        self.assertTrue(os.path.islink(ex / "stray.dSYM"))
        self.assertEqual(5, (outside_dsym / "keep").stat().st_size)
        self.assertFalse((ex / "clonex").exists())

    def test_6118_r5_info_same_size_impostor_is_not_named_as_the_bin_source(self) -> None:
        # Round-4 code review, INFO: name and size alone matched an unrelated
        # deps/<bin>-<hash> of the same size and then kept it as the bin's
        # "uplift source".  The bytes decide: only a file with the content of
        # <profile>/<bin> (a hard link or a clone of it) is the source.
        deps = self.target / "debug" / "deps"
        _write(self.target / "debug" / "imp-bin", 4096, True)
        _write(deps / "imp_bin-aaaaaaaaaaaaaaaa", 4096, True)  # the real source: same bytes
        impostor = deps / "imp_bin-bbbbbbbbbbbbbbbb"  # a test executable that happens to be as large
        impostor.write_bytes(b"y" * 4096)
        impostor.chmod(0o755)
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertTrue((deps / "imp_bin-aaaaaaaaaaaaaaaa").exists())
        self.assertFalse(impostor.exists(), proc.stdout)
        self.assertNotIn("imp_bin-bbbbbbbbbbbbbbbb", proc.stdout)
        self.assertIn("kept deps/imp_bin-aaaaaaaaaaaaaaaa", proc.stdout)
        self.assertEqual(self._expected_freed() + 4096, self._freed(proc.stdout))

    # ---- round 6 (#6300, #6299, #6301, #6303) ----

    def test_6118_r6_6300_partial_failure_exits_0_on_every_consecutive_run(self) -> None:
        # #6300: the step is `if: always()`; a nonzero exit after a partial
        # failure turned every later job red.  Warnings are annotations, the
        # run completed: rc 0, each time (the unremovable entry persists).
        if UID0:
            self.skipTest("root ignores directory permission bits")
        dwarf = self.target / "debug" / "deps" / "mcp_input_schema-7c7c.dSYM" / "Contents" / "Resources" / "DWARF"
        dwarf.chmod(0o500)
        self.addCleanup(restore_mode, dwarf, 0o700)
        for attempt in range(3):
            _write(self.target / "debug" / "deps" / "mcp_input_schema-7c7c", 120000, True)
            proc = self._run("--target-dir", str(self.target))
            self.assertEqual(0, proc.returncode, (attempt, proc.stdout, proc.stderr))
            self.assertRegex(proc.stdout, r"(?m)^::notice::prune-runner-target freed_bytes=\d+ deleted=\d+ "
                                          r"mode=pruned warnings=1$")
            self.assertIn("::warning::prune-runner-target:", proc.stdout)

    def test_6118_r6_6300_refusals_still_exit_2(self) -> None:
        # rc 2 stays for refusals: nothing was touched and the step is misconfigured.
        bad_profile = self._run("--target-dir", str(self.target), "--profile", "..")
        self.assertEqual(2, bad_profile.returncode, bad_profile.stdout + bad_profile.stderr)
        (self.target / "CACHEDIR.TAG").unlink()
        (self.target / "debug" / ".cargo-lock").unlink()
        no_marker = self._run("--target-dir", str(self.target))
        self.assertEqual(2, no_marker.returncode, no_marker.stdout + no_marker.stderr)
        self.assertTrue((self.target / "debug" / "deps" / "ai_memory-0a1b").exists())

    def test_6118_r6_6300_completed_without_warnings_reports_warnings_0(self) -> None:
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertRegex(proc.stdout, r"(?m)^::notice::prune-runner-target freed_bytes=\d+ deleted=10 "
                                      r"mode=pruned warnings=0$")

    # Characters that render invisibly or reorder / split a log line (#6299): Zl, Zp,
    # bidi controls, zero-width and format characters, a private-use and a noncharacter.
    INVISIBLE = (0x2028, 0x2029, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D,
                 0x202E, 0x2060, 0x2061, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF, 0x00AD, 0x061C, 0x180E,
                 0xE000, 0xFFFF, 0xE0001, 0xE007F)

    def test_6118_r6_6299_line_and_paragraph_separators_are_escaped(self) -> None:
        mod = _load_prune()
        self.assertEqual("a\\u{2028}b", mod._escape("a\u2028b"))
        self.assertEqual("a\\u{2029}b", mod._escape("a\u2029b"))

    def test_6118_r6_6299_every_invisible_code_point_is_escaped(self) -> None:
        mod = _load_prune()
        for cp in self.INVISIBLE:
            with self.subTest(code_point="U+%04X" % cp):
                self.assertEqual("x\\u{%x}y" % cp, mod._escape("x%sy" % chr(cp)))

    def test_6118_r6_6299_visible_non_ascii_names_are_untouched(self) -> None:
        mod = _load_prune()
        for text in ("caf\u00e9", "\u65e5\u672c\u8a9e", "\U0001f980-rust", "tab-free name.rlib"):
            self.assertEqual(text, mod._escape(text))

    def test_6118_r6_6299_bidi_name_never_reaches_the_log_raw(self) -> None:
        name = "tst\u202e\u2028-0123456789abcdef"
        _write(self.target / "debug" / "deps" / name, 5, True)
        for args in (("--dry-run",), ()):
            proc = self._run("--target-dir", str(self.target), *args)
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            for ch in ("\u202e", "\u2028"):
                self.assertNotIn(ch, proc.stdout + proc.stderr, args)
            if args:
                self.assertIn("tst\\u{202e}\\u{2028}-0123456789abcdef", proc.stdout)

    def test_6118_r6_6301_unreadable_uplift_candidate_is_kept_and_named_unverified(self) -> None:
        # #6301 (vote 5-agent 4d3ea1c5, r6): a same-name same-size candidate whose bytes
        # cannot be read stays (fail closed) and says so, instead of claiming "same content".
        if UID0:
            self.skipTest("root reads any file")
        deps = self.target / "debug" / "deps"
        _write(self.target / "debug" / "unrd-bin", 4096, True)
        cand = deps / "unrd_bin-aaaaaaaaaaaaaaaa"
        _write(cand, 4096, True)
        cand.chmod(0o111)
        self.addCleanup(restore_mode, cand, 0o755)
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertTrue(cand.exists(), proc.stdout)
        kept = [ln for ln in proc.stdout.splitlines() if "kept deps/unrd_bin-aaaaaaaaaaaaaaaa" in ln]
        self.assertEqual(1, len(kept), proc.stdout)
        self.assertIn("unreadable, not verified", kept[0])
        self.assertNotIn("same name, size and content", kept[0])

    def test_6118_r6_6313_escape_is_injective_on_backslash(self) -> None:
        # #6313: a literal backslash used to pass through, so the text "\\x0a" (backslash,
        # x, 0, a) read exactly like an escaped newline.  Every output must decode one way.
        mod = _load_prune()
        self.assertEqual("\\\\", mod._escape("\\"))
        self.assertNotEqual(mod._escape("a\nb"), mod._escape("a\\x0ab"))
        self.assertNotEqual(mod._escape("a\u2028b"), mod._escape("a\\u{2028}b"))
        samples = ["", "\\", "\\\\", "\n", "\\n", "\\x0a", "\x0a", "a\\", "\u2028", "\\u{2028}",
                   "\u202e", "\\u{202e}", "plain", "é", "\\\n", "\x1b[31m", "\\x1b[31m"]
        outs = [mod._escape(x) for x in samples]
        self.assertEqual(len(set(samples)), len(set(outs)), list(zip(samples, outs)))

    def test_6118_r6_6313_backslash_name_is_logged_escaped(self) -> None:
        deps = self.target / "debug" / "deps"
        _write(deps / "back\\x0aslash-0123456789abcdef", 130000, True)
        proc = self._run("--target-dir", str(self.target), "--dry-run")
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("back\\\\x0aslash-0123456789abcdef", proc.stdout)

    def test_6118_r6_6314_unreadable_profile_side_partner_is_kept_and_not_called_a_match(self) -> None:
        # #6314: the kept line must not claim "same content" when the bytes were never compared;
        # the unreadable file here is the uplifted copy in the profile dir.
        if UID0:
            self.skipTest("root reads any file")
        deps = self.target / "debug" / "deps"
        up = self.target / "debug" / "unrp-bin"
        _write(up, 4096, True)
        cand = deps / "unrp_bin-bbbbbbbbbbbbbbbb"
        _write(cand, 4096, True)
        up.chmod(0o111)
        self.addCleanup(restore_mode, up, 0o755)
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertTrue(cand.exists(), proc.stdout)
        kept = [ln for ln in proc.stdout.splitlines() if "kept deps/unrp_bin-bbbbbbbbbbbbbbbb" in ln]
        self.assertEqual(1, len(kept), proc.stdout)
        self.assertIn("content unreadable, not verified", kept[0])
        self.assertNotIn("same name, size and content", kept[0])

    def test_6118_r6_6314_readable_identical_partner_still_says_same_content(self) -> None:
        deps = self.target / "debug" / "deps"
        _write(self.target / "debug" / "okrd-bin", 4096, True)
        _write(deps / "okrd_bin-cccccccccccccccc", 4096, True)
        proc = self._run("--target-dir", str(self.target))
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        kept = [ln for ln in proc.stdout.splitlines() if "kept deps/okrd_bin-cccccccccccccccc" in ln]
        self.assertEqual(1, len(kept), proc.stdout)
        self.assertIn("same name, size and content", kept[0])

    def test_6118_r6_6315_missing_dir_fd_support_is_refused_for_every_function(self) -> None:
        # #6315: each of os.open / os.stat / os.unlink / os.rmdir / os.readlink is a separate
        # fail-closed refusal; dropping any one from the check must fail a test.
        mod = _load_prune()
        for fn in (os.open, os.stat, os.unlink, os.rmdir, os.readlink):
            with self.subTest(fn.__name__):
                out = io.StringIO()
                supported = set(os.supports_dir_fd) - {fn}
                with unittest.mock.patch.object(mod.os, "supports_dir_fd", supported), \
                        contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                    rc = mod.main(["--target-dir", str(self.target)])
                self.assertEqual(2, rc, out.getvalue())
                self.assertIn("dir_fd support for %s" % fn.__name__, out.getvalue())
                self.assertTrue((self.target / "debug" / "deps" / "ai_memory-0a1b").exists())

    def test_6118_r7_6480_mock_tests_pass_when_run_alone(self) -> None:
        # #6480: the #6315 test used `unittest.mock` while only `import unittest` was at
        # module level; it passed only when another test had imported the submodule first.
        # Run it alone in a fresh isolated interpreter.
        code = ("import importlib.util, sys, unittest\n"
                "spec = importlib.util.spec_from_file_location('alone_6480', sys.argv[1])\n"
                "mod = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(mod)\n"
                "suite = unittest.TestSuite([mod.PruneScript6118(sys.argv[2])])\n"
                "ok = unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful()\n"
                "sys.exit(0 if ok else 1)\n")
        proc = subprocess.run([sys.executable, "-I", "-c", code, str(Path(__file__).resolve()),
                               "test_6118_r6_6315_missing_dir_fd_support_is_refused_for_every_function"],
                              capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("Ran 1 test", proc.stderr)

    def test_6118_r6_6303_restore_mode_tolerates_a_removed_path(self) -> None:
        gone = Path(self.scratch.name) / "removed-by-the-prune"
        restore_mode(gone, 0o700)  # must not raise FileNotFoundError

    def test_6118_r6_6303_chmod_tests_skip_under_root(self) -> None:
        for name in ("test_6118_unremovable_entry_warns_continues_and_exits_0",
                     "test_6118_scan_unreadable_subdir_warns_and_prunes_the_rest",
                     "test_6118_newline_in_entry_name_cannot_inject_a_workflow_command"):
            src = inspect.getsource(getattr(PruneScript6118, name))
            self.assertIn("if UID0:", src, name)
            self.assertIn("self.skipTest(", src, name)
            self.assertIn("restore_mode", src, name)


    # ---- #6479: a different file system mounted inside the target tree ----

    def _other_device(self, mod: object, mounts: List[Path]):  # type: ignore[no-untyped-def]
        """Patch ``mod.os.stat`` / ``mod.os.fstat`` so each directory in ``mounts`` and everything below it
        reports another st_dev, the way a volume mounted there does."""
        inos = set()
        for top in mounts:
            for path in [top, *top.rglob("*")]:
                inos.add(os.lstat(str(path)).st_ino)
        real_stat, real_fstat = os.stat, os.fstat

        def moved(st: os.stat_result) -> os.stat_result:
            if st.st_ino not in inos:
                return st
            fields = list(st[:10])
            fields[2] = st.st_dev + 1
            return os.stat_result(fields)

        def fake_stat(*args, **kwargs):  # type: ignore[no-untyped-def]
            return moved(real_stat(*args, **kwargs))

        def fake_fstat(fd: int) -> os.stat_result:
            return moved(real_fstat(fd))

        dir_fd_ok = set(os.supports_dir_fd) | {fake_stat}
        return contextlib.ExitStack(), [
            unittest.mock.patch.object(mod.os, "stat", fake_stat),  # type: ignore[attr-defined]
            unittest.mock.patch.object(mod.os, "fstat", fake_fstat),  # type: ignore[attr-defined]
            unittest.mock.patch.object(mod.os, "supports_dir_fd", dir_fd_ok),  # type: ignore[attr-defined]
        ]

    def test_6118_r7_6479_prune_never_descends_into_another_file_system(self) -> None:
        cases = [
            ("mount below a candidate", "debug/incremental/ai_memory-xyz/mnt", "test-bins"),
            ("mount below a candidate, scope all", "debug/incremental/ai_memory-xyz/mnt", "all"),
            ("artifact dir is the mount", "debug/incremental", "test-bins"),
            ("deps is the mount, scope all", "debug/deps", "all"),
        ]
        for label, rel, scope in cases:
            for dry_run in (True, False):
                with self.subTest(label, dry_run=dry_run):
                    self.setUp()  # a fresh tree per subcase
                    mount = self.target / rel
                    victim = mount / "victim-on-other-volume"
                    _write(victim, 64)
                    mod = _load_prune()
                    stack, patches = self._other_device(mod, [mount])
                    out = io.StringIO()
                    args = ["--target-dir", str(self.target), "--scope", scope] + (["--dry-run"] if dry_run else [])
                    with stack:
                        for patch in patches:
                            stack.enter_context(patch)
                        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                            rc = mod.main(args)
                    self.assertEqual(0, rc, out.getvalue())
                    self.assertTrue(victim.is_file(), (label, out.getvalue()))
                    self.assertIn("other file system", out.getvalue(), label)
                    if not dry_run and mount.name == "mnt":
                        # the same-device artifacts around the mount still go
                        self.assertFalse((self.target / "debug" / "deps" / "ai_memory-0a1b").exists(), label)

    # ---- #6313 residual: a raw byte 0x80-0x9F and the C1 code point U+0080-U+009F ----

    def test_6118_r7_6313_raw_byte_and_c1_code_point_print_differently(self) -> None:
        mod = _load_prune()
        for b in range(0x80, 0xA0):
            with self.subTest(byte="0x%02X" % b):
                raw = mod._escape(os.fsdecode(b"a" + bytes([b]) + b"b"))  # an undecodable byte (surrogateescape)
                c1 = mod._escape("a%sb" % chr(b))  # the C1 control code point
                self.assertEqual("a\\x%02xb" % b, raw)
                self.assertEqual("a\\u{%x}b" % b, c1)
                self.assertNotEqual(raw, c1)

    def test_6118_r7_6313_escape_is_injective_on_a_byte_and_code_point_corpus(self) -> None:
        mod = _load_prune()
        samples = set()
        for b in list(range(0x00, 0x20)) + list(range(0x7F, 0x100)):
            samples.add(os.fsdecode(b"n" + bytes([b])))
            samples.add("n" + chr(b))
            samples.add("n\\x%02x" % b)
            samples.add("n\\u{%x}" % b)
        outs = {}
        for x in sorted(samples):
            outs.setdefault(mod._escape(x), []).append(x)
        self.assertEqual([], [v for v in outs.values() if len(v) > 1])

    # ---- #6299 residual: blank, combining and filler code points ----

    def test_6118_r7_6299_blank_combining_and_filler_code_points_are_escaped(self) -> None:
        mod = _load_prune()
        cases = (
            0x00A0, 0x1680, 0x2000, 0x2007, 0x200A, 0x202F, 0x205F, 0x3000,  # Zs other than space
            0x0301, 0x0333, 0x20E3,  # Mn (combining marks)
            0x20DD, 0x0488,  # Me (enclosing marks)
            0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800,  # fillers and the blank braille pattern
        )
        for cp in cases:
            with self.subTest(cp="U+%04X" % cp):
                self.assertEqual("x\\u{%x}y" % cp, mod._escape("x%sy" % chr(cp)))

    def test_6118_r7_6299_space_and_visible_letters_stay_raw(self) -> None:
        mod = _load_prune()
        for text in ("a b", "caf\xe9", "\u65e5\u672c", "na\xefve-\xdf"):
            with self.subTest(text=text):
                self.assertEqual(text, mod._escape(text))

    # ---- #6532: _escape is total over str, every surrogate included ----

    def test_6118_r7_6532_escape_is_total_over_every_surrogate(self) -> None:
        mod = _load_prune()
        bad = []
        for cp in range(0xD800, 0xE000):
            try:
                out = mod._escape("a%sb" % chr(cp))
            except UnicodeError as exc:  # the defect: os.fsencode raises outside U+DC80-U+DCFF
                bad.append("U+%04X raised %s" % (cp, type(exc).__name__))
                continue
            want = "a\\x%02xb" % (cp - 0xDC00) if 0xDC80 <= cp <= 0xDCFF else "a\\u{%x}b" % cp
            if out != want or not (out.isascii() and out.isprintable()):
                bad.append("U+%04X -> %r" % (cp, out))
        self.assertEqual([], bad)

    def test_6118_r7_6532_surrogate_halves_never_print_as_the_paired_character(self) -> None:
        mod = _load_prune()
        cases = {
            chr(0xD83D) + chr(0xDE00): "\\u{d83d}\\u{de00}",  # two halves, not U+1F600
            "%\ud800#\udc80\\": "%25\\u{d800}%23\\x80\\\\",  # mixed with every other escape
            "\udfff\u0085": "\\u{dfff}\\u{85}",
        }
        for text, want in cases.items():
            with self.subTest(text=ascii(text)):
                self.assertEqual(want, mod._escape(text))
        self.assertNotEqual(mod._escape(chr(0xD83D) + chr(0xDE00)), mod._escape("\U0001f600"))

    # ---- #6512: an artifact dir that is ALREADY a symlink when the plan is made ----

    def _victim_tree(self, name: str) -> Path:
        """An out-of-tree directory holding names the prune would delete in a real tree."""
        victim = Path(self.scratch.name) / name
        _write(victim / "ai_memory-0a1b", 170000, True)
        _write(victim / "ai_memory-0a1b.d", 50, False)
        _write(victim / "demo-0123456789abcdef", 50000, True)
        _write(victim / "ai_memory-xyz" / "s-abc-def-working" / "dep-graph.bin", 6000, False)
        _write(victim / "sub" / "keep.bin", 64, False)
        return victim

    @staticmethod
    def _snapshot(root: Path) -> List[Tuple[str, int]]:
        return sorted((str(p.relative_to(root)), p.lstat().st_size) for p in root.rglob("*"))

    def _link_in(self, rel: str, victim: Path) -> None:
        here = self.target / rel
        if here.is_dir() and not here.is_symlink():
            shutil.rmtree(str(here))
        else:
            here.unlink()
        here.symlink_to(victim, target_is_directory=True)

    def test_6118_r7_6512_symlinked_artifact_dir_is_never_followed(self) -> None:
        reached = {"test-bins": ("deps", "incremental", "examples"), "all": self.FIVE_DIRS}
        for sub in self.FIVE_DIRS:
            for scope in ("test-bins", "all"):
                for dry in (False, True):
                    with self.subTest(sub=sub, scope=scope, dry_run=dry):
                        self.setUp()
                        victim = self._victim_tree("victim-%s" % sub.strip("."))
                        before = self._snapshot(victim)
                        self._link_in("debug/" + sub, victim)
                        args = ["--target-dir", str(self.target), "--scope", scope] + (["--dry-run"] if dry else [])
                        proc = self._run(*args)
                        out = proc.stdout + proc.stderr
                        self.assertEqual(0, proc.returncode, out)
                        self.assertNotIn("Traceback", out)
                        self.assertEqual(before, self._snapshot(victim), out)
                        self.assertTrue((self.target / "debug" / sub).is_symlink(), out)
                        if sub in reached[scope]:
                            self.assertIn("skipped debug/%s: a symlink or not a directory (never followed)" % sub, out)

    def test_6118_r7_6512_symlinked_nested_dir_inside_a_candidate_is_never_followed(self) -> None:
        nested = (
            "debug/deps/mcp_input_schema-7c7c.dSYM/Contents",
            "debug/incremental/ai_memory-xyz/s-abc-def-working",
        )
        for rel in nested:
            for scope in ("test-bins", "all"):
                for dry in (False, True):
                    with self.subTest(rel=rel, scope=scope, dry_run=dry):
                        self.setUp()
                        victim = self._victim_tree("victim-nested")
                        before = self._snapshot(victim)
                        self._link_in(rel, victim)
                        args = ["--target-dir", str(self.target), "--scope", scope] + (["--dry-run"] if dry else [])
                        proc = self._run(*args)
                        out = proc.stdout + proc.stderr
                        self.assertEqual(0, proc.returncode, out)
                        self.assertNotIn("Traceback", out)
                        self.assertEqual(before, self._snapshot(victim), out)

    # ---- #6513: the target root is swapped between the lstat and the open ----

    def test_6118_r7_6513_root_swapped_between_lstat_and_open_is_refused(self) -> None:
        for scope in ("test-bins", "all"):
            for dry in (False, True):
                with self.subTest(scope=scope, dry_run=dry):
                    self.setUp()
                    other = Path(self.scratch.name) / "other-dir"
                    other.mkdir()
                    before = self._snapshot(self.target)
                    mod = _load_prune()
                    real_lstat = os.lstat
                    calls = []

                    def swapped_lstat(path, *a, **kw):  # type: ignore[no-untyped-def]
                        calls.append(str(path))
                        if len(calls) == 1 and str(path) == str(self.target):
                            return real_lstat(str(other))  # the root a racer had in place at check time
                        return real_lstat(path, *a, **kw)

                    out = io.StringIO()
                    args = ["--target-dir", str(self.target), "--scope", scope] + (["--dry-run"] if dry else [])
                    with unittest.mock.patch.object(mod.os, "lstat", swapped_lstat):
                        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                            rc = mod.main(args)
                    self.assertEqual([str(self.target)], calls[:1], out.getvalue())
                    self.assertEqual(2, rc, out.getvalue())
                    self.assertIn("refusing: %s changed while it was being checked" % self.target, out.getvalue())
                    self.assertEqual(before, self._snapshot(self.target), out.getvalue())

    # ---- #6528: the NothingToPrune notice carries warnings=0 ----

    def test_6118_r7_6528_nothing_to_prune_notice_ends_with_warnings_0(self) -> None:
        no_profile = Path(self.scratch.name) / "fresh-target"  # cargo wrote the tag, no build ran yet
        no_profile.mkdir()
        (no_profile / "CACHEDIR.TAG").write_bytes(_load_prune().CACHEDIR_SIGNATURE + b"\n")
        for label, target in (("absent target", Path(self.scratch.name) / "absent"), ("no profile dir", no_profile)):
            for dry in (False, True):
                with self.subTest(label, dry_run=dry):
                    proc = self._run("--target-dir", str(target), *(["--dry-run"] if dry else []))
                    self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
                    self.assertIn("nothing to prune", proc.stdout)
                    notices = [line for line in proc.stdout.splitlines() if line.startswith("::notice::")]
                    self.assertEqual(1, len(notices), proc.stdout)
                    self.assertTrue(notices[0].endswith(" warnings=0"), notices[0])
                    self.assertIn("mode=%s " % ("dry-run" if dry else "pruned"), notices[0])

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
