#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Allow-list stream ratchet for the CI workflow-command escape class (#9365 lane b, Refs #8219).

Class: a script or workflow under ``scripts/`` or ``.github/`` writes a workflow command (``::name ...::``,
``##[...]``) or a value-bearing line to fd 1 or 2 without going through ``scripts/ci/workflow_annotation.py``.

Invariant (allow list by construction, not a deny list of known forms):

* Every ``.py`` under ``scripts/`` is covered; the tree is walked, so a new file is covered without being
  listed. A file may stay un-routed only with an ``UNROUTED_FILES`` row whose site count EQUALS the count
  found (lower, higher, a missing or clean file are all red; an unlisted file is red at once). The list is
  exact and shrink-only until PR-4 of #9365, where it is EMPTY (spec deviation, ruling b29 8f7ba133).
* In a covered file the only way to reach fd 1 or 2 is a call of a shared emitter
  (``wa.out`` / ``wa.err`` / ``wa.emit_to``). Every other form that can write there is a finding:
  any use of the name ``print`` (call, alias, ``map(print, ...)``), any use of ``sys.stdout`` /
  ``sys.stderr`` / ``sys.__stdout__`` / ``sys.__stderr__`` (so ``.write``, ``.buffer.write``,
  ``.writelines``, ``out = sys.stdout``, ``json.dump(x, sys.stdout)`` and ``print(file=alias)`` all fall),
  ``getattr``/``vars`` on ``sys``, ``from sys import stdout``, ``os.write``, ``os.fdopen`` / ``open`` /
  ``io.open`` of a file descriptor number, ``logging``, ``warnings.warn``, ``traceback.print_*``,
  ``pprint``, ``input(prompt)``, ``os.system``, a subprocess ``echo`` / ``printf`` whose output is not
  captured, and ``sys.exit`` / ``SystemExit`` with a text argument (the interpreter prints it).
* A covered file never puts ``##`` or ``::`` right before a format placeholder, a ``%`` template, a
  ``.format`` field or a ``+`` operand (constant ``+`` chains are folded first, so ``'#' + '#' + v`` falls).
* The only exempt sites are the rows of ``EXEMPT_SITES`` (each with its reason) and the canonical load ``try``
  that ``test_ci_annotation_escape_9365.loader_shape_violations`` already proves byte-shaped.
* The emitters neutralise every line they write (``log_line`` rules, also across calls that end mid-line);
  only a ``CommandLine`` from ``annotation`` / ``end_group_line`` is written as a command. No value up to
  ``HUGE_VALUE_CHARS`` reaches a workflow command un-neutralised.
* Workflow YAML: no ``echo`` / ``printf`` line in a ``run:`` block prints a workflow command with a shell
  value (``$x``, ``${{ }}``, a backtick); a command with a value goes through the module's CLI
  (``python3 scripts/ci/workflow_annotation.py <command> ...``). Constant lines are exempt by rule.

Run: python3 -m unittest scripts/ci/tests/test_ci_stream_allowlist_9365.py
"""

import ast
import contextlib
import importlib.util
import io
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPTS_ROOT = REPO / "scripts"
WORKFLOWS_ROOT = REPO / ".github" / "workflows"
SHARED_MODULE_PATH = REPO / "scripts" / "ci" / "workflow_annotation.py"
SHARED_MODULE_REL = "scripts/ci/workflow_annotation.py"
LOADER_TEST_PATH = REPO / "scripts" / "ci" / "tests" / "test_ci_annotation_escape_9365.py"
FIXTURE_DIR_REL = "scripts/test/fixtures"
FIXTURE_RUNNER_REL = "scripts/check-foreign-text-to-caller.py"

EMITTERS = frozenset({"out", "err", "emit_to"})
SHARED_MODULE_ALIAS = "wa"
COMMAND_LINE_CLASS = "CommandLine"  # only annotation()/end_group_line() build one; a script may not forge it
# file -> the EXACT number of un-routed fd 1/2 sites in it (#9365 PR-1, ruling b29 8f7ba133). Equality, not <=:
# a new site in a listed file is red, a routed site is red until the row is lowered in the same commit, a
# row for a missing or clean file is red, and a file not listed here is red at once. The list shrinks to
# EMPTY in PR-4 of #9365: PR-2 routes the scripts/ top level, PR-3 bench/, evidence/, release/, test/, tests/.
# The one scripts/ci subtree that may hold UNROUTED_FILES rows in PR-1a: its scripts run from the base tree in the
# ci.yml/coverage.yml trust steps, so they are routed in PR-1b with the steps that materialise the base module.
UNROUTED_CI_PREFIX = "scripts/ci/impact/"
UNROUTED_FILES = {
    'scripts/bench/mesh_probe.py': 12,
    'scripts/bench/ops_producer.py': 14,
    'scripts/bench/wake_latency.py': 27,
    'scripts/cert_gate_evidence.py': 5,
    'scripts/check-build-script-vetting.py': 17,
    'scripts/check-claude-md-size.py': 88,
    'scripts/check-docs-no-argv-secrets.py': 22,
    'scripts/check-foreign-text-to-caller.py': 26,
    'scripts/check-mcp-transport-isolation.py': 23,
    'scripts/check-sqlite-write-txn-immediate.py': 8,
    'scripts/check-test-keydir-mode.py': 11,
    'scripts/check_cert_expiry.py': 22,
    'scripts/check_promotion_geometry.py': 10,
    'scripts/check_release_features.py': 41,
    'scripts/ci-sweep-target.py': 20,
    # PR-1b of #9365 routes scripts/ci/impact together with the base-tree trust steps and removes these rows
    'scripts/ci/impact/base_sha.py': 1,
    'scripts/ci/impact/build_index.py': 1,
    'scripts/ci/impact/cargo_skip.py': 1,
    'scripts/ci/impact/common.py': 2,
    'scripts/ci/impact/gate.py': 3,
    'scripts/ci/impact/read_set.py': 1,
    'scripts/ci/impact/select.py': 1,
    'scripts/claude-md-rule-compare.py': 65,
    'scripts/evidence/build_bundle.py': 13,
    'scripts/evidence/continuity-cycle.py': 13,
    'scripts/evidence/mcp-tools-state.py': 4,
    'scripts/evidence/predicates.py': 11,
    'scripts/evidence/prep.py': 12,
    'scripts/evidence/run_cert.py': 13,
    'scripts/recapture-cert-3607-posture.py': 43,
    'scripts/release/check-release-workflow.py': 4,
    'scripts/release/qualify-sha.py': 13,
    'scripts/test/pg_isolated_binary.py': 7,
    'scripts/tests/for-admin-checked-literal-3943.py': 1,
    'scripts/tests/gate-production-3623.py': 5,
}
# (file, enclosing function or "<module>") -> why the site may write to fd 1/2 without the emitters
EXEMPT_SITES = {
    (SHARED_MODULE_REL, "_stream"): "the emitter resolves sys.stdout / sys.stderr at call time (redirects work)",
    (SHARED_MODULE_REL, "annotation"): "builds the one command head '::' + a command name checked against ANNOTATION_COMMANDS",
    ("scripts/ci/tests/test_ci_annotation_escape_9365.py", "assert_commands"): (
        "compares an emitted line with '::' + kind (startswith); writes nothing"),
    ("scripts/ci/prune_runner_tmp.py", "<module>"): (
        "the Python floor refusal runs before any import but sys (ruling 598d069e): fixed text plus "
        "version_text(), byte-equal to annotation(), pinned by test_ci_annotation_escape_9365"),
    ("scripts/ci/prune_runner_tmp.py", "default_streams"): (
        "resolves the caller's out/err (else the process streams) once per run; each write to them is a "
        "wa.emit_to call the walk sees"),
    ("scripts/test/test_ci_sweep_target.py", "make_deep_chain_with_files"): (
        "fixture: os.write to a regular file the opened_fd() context manager opened under dir_fd (never fd 1/2)"),
    ("scripts/ci/check_pr_body_ids.py", "report_error"): (
        "checked raw write (#8275 output-boundary contract: blocking fd, complete write, failed stream closed); "
        "the text is wa.neutral_lines(...) first"),
    ("scripts/ci/check_pr_body_ids.py", "error"): (
        "checked raw write (#8275 output-boundary contract: blocking fd, complete write, failed stream closed); "
        "the text is wa.neutral_lines(...) first"),
    ("scripts/ci/check_pr_body_ids.py", "_print_message"): (
        "checked raw write (#8275 output-boundary contract: blocking fd, complete write, failed stream closed); "
        "the text is wa.neutral_lines(...) first"),
    ("scripts/ci/check_pr_body_ids.py", "write_report"): (
        "checked raw write (#8275 output-boundary contract: blocking fd, complete write, failed stream closed); "
        "the text is wa.neutral_lines(...) first"),
    ("scripts/ci/tests/test_ci_stream_allowlist_9365.py", "test_benign_text_is_byte_equal_to_print_9365"): (
        "the oracle: print(..., file=io.StringIO()) is what print wrote before routing; it writes to the buffer only"),
    ("scripts/ci/tests/test_ci_annotation_escape_9365.py", "cells"): (
        "passes sys.stdout to emit_to, the function under test, inside emitted_lines' redirect_stdout(StringIO)"),
    ("scripts/ci/tests/test_check_cert_expiry_corpus.py", "main"): (
        "hands sys.stderr to unittest.TextTestRunner outside --machine, the stream unittest.main itself uses; "
        "the --machine lines are wa.out calls"),
    ("scripts/ci/prune_runner_tmp.py", "load_refused"): (
        "the shared module failed to load: one fixed ::warning literal and one stderr line whose only variable "
        "is a fixed LOAD_* cause constant (ruling bcd0a15c)"),
}
# A file under scripts/test/fixtures/ is a FROZEN VERBATIM prefix of an old gate, kept as data; its only runner
# executes it with captured output (proved by test_fixture_output_never_reaches_the_runner_9365), so its writes
# never reach the runner log. It is exempt by that proved rule, not by a file list.
FIXTURE_EXEMPT_REASON = "frozen fixture; run only by %s with capture_output=True" % FIXTURE_RUNNER_REL

STD_STREAM_ATTRS = frozenset({"stdout", "stderr", "__stdout__", "__stderr__"})
FD_NUMBERS = frozenset({1, 2})
SUBPROCESS_CALLS = frozenset({"run", "call", "check_call", "Popen"})
ECHO_PROGRAMS = frozenset({"echo", "printf"})
CAPTURE_KEYWORDS = frozenset({"capture_output", "stdout"})
COMMAND_PREFIXES = ("##", "::")
V1_PREFIX = "##"
V2_PREFIX = "::"
LINE_BREAKS = "\n\r"


def command_prefix_hit(text, at_line_start):
    """Which command prefix a literal ends with, where a value follows it: ``##`` anywhere (the v1 ``##[``
    form matches mid-line), ``::`` only when nothing but blanks sits before it on its line (the v2 form must
    open the line). ``at_line_start`` says whether the literal itself opens the rendered text."""
    if text.endswith(V1_PREFIX):
        return V1_PREFIX
    if not text.endswith(V2_PREFIX):
        return ""
    head = text[:-len(V2_PREFIX)]
    cut = max(head.rfind(ch) for ch in LINE_BREAKS)
    if cut < 0 and not at_line_start:
        return ""
    return V2_PREFIX if not head[cut + 1:].strip() else ""


def template_prefix_hit(template, opener):
    """The prefix hit for a ``%`` or ``.format`` template: the first placeholder opened by ``opener``
    that a command prefix sits before."""
    start = 0
    while True:
        index = template.find(opener, start)
        if index < 0:
            return ""
        hit = command_prefix_hit(template[:index], True)
        if hit:
            return hit
        start = index + 1

# workflow YAML
# YAML and the runner end a line only at \r\n, \r or \n; str.splitlines() also splits at \x0c, \x1c and \u2028.
YAML_LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")
YAML_ECHO_RE = re.compile(r"^\s*(?:[^#\s][^#]*?(?:&&|\|\||;|then|else|do)\s+)?(echo|printf)\b")
YAML_COMMAND_RE = re.compile(r"::(error|warning|notice|group|endgroup|add-mask|set-output|debug|stop-commands)|##\[")
YAML_VALUE_RE = re.compile(r"\$\{\{|\$[A-Za-z_{(0-9#@*?!-]|`")
YAML_EXPRESSION = "${{"
YAML_PR4_REASON = "routed in PR-4 (#9365 lane c)"
# (workflow file, stripped line) -> (the EXACT number of such lines in that file, why the value may stay
# raw). Equality: a row whose line is gone (stale) or whose line appears more often (duplicated) is red.
YAML_EXEMPT_LINES = {
    ('release-shape.yml', 'echo "::add-mask::$pw"'): (1, 'add-mask must carry the generated password raw: an escaped copy would mask a different string'),
    ('batman-mode-acceptance.yml', 'echo "::error::$missing load-bearing symbol(s) missing — Batman Mode CI gate will fail downstream"'): (1, YAML_PR4_REASON),
    ('batman-mode-acceptance.yml', 'echo "::error::missing symbol: $desc (regex: $pat)"'): (1, YAML_PR4_REASON),
    ('cert-postgres-age.yml', 'echo "::error::$RUNNER_NAME failed to CREATE DATABASE $CI_FED_DB on the native cert tier"'): (1, YAML_PR4_REASON),
    ('cert-postgres-age.yml', 'echo "::error::$RUNNER_NAME failed to create age/vector extensions in $CI_FED_DB"'): (1, YAML_PR4_REASON),
    ('cert-postgres-age.yml', 'echo "::error::$RUNNER_NAME is missing $url_file — the native cert tier URL is not provisioned on this node"'): (1, YAML_PR4_REASON),
    ('cert-postgres-age.yml', 'echo "::error::native enterprise-fed tier did not answer within 60s on $RUNNER_NAME"'): (1, YAML_PR4_REASON),
    ('cert-postgres-age.yml', 'echo "::error::rustup is not provisioned at \\$HOME/.cargo/bin/rustup on $RUNNER_NAME — repair the node."'): (1, YAML_PR4_REASON),
    ('cert-postgres-age.yml', 'echo "::notice::cert cells pointed at ephemeral db $CI_FED_DB on the native enterprise-fed tier ($RUNNER_NAME)"'): (1, YAML_PR4_REASON),
    ('cert-postgres-age.yml', 'echo "::notice::certified pins resolved from deploy/docker-1461/provision/lib.sh — PG server ${EXPECTED_PG_VERSION}, AGE server ${EXPECTED_AGE_VERSION}, pgvector ${PGVECTOR_APT_VERSION%%-*}"'): (1, YAML_PR4_REASON),
    ('cert-postgres-age.yml', 'echo "::notice::certified stack — PostgreSQL=$pg_ver  Apache AGE=$age_ver  pgvector=$vec_ver"'): (1, YAML_PR4_REASON),
    ('cert-postgres-age.yml', 'echo "::notice::dropped ephemeral db $CI_FED_DB on $RUNNER_NAME"'): (1, YAML_PR4_REASON),
    ('cert-postgres-age.yml', 'echo "::warning::cannot drop $CI_FED_DB — $url_file missing on $RUNNER_NAME (leaked ephemeral db)"'): (1, YAML_PR4_REASON),
    ('cert-postgres-age.yml', 'echo "::warning::failed to drop ephemeral db $CI_FED_DB on $RUNNER_NAME (leaked)"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::NDK clang for android24 not found at $TC"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::Refusing to run fork PR code on a self-hosted runner (leg ${{ matrix.leg }})."'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::[#1492 watchdog] \'${label}\' exceeded the ${WATCHDOG_SECS}s per-invocation timeout (tier=${TIER:-sqlite}) and was terminated (previously a silent ~34min hang until the job cap). Reproduce with the impact set logged above; then file a follow-up for the specific flaky test."'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::[#1492 watchdog] \'${label}\' exceeded the ${WATCHDOG_SECS}s per-invocation timeout (tier=${TIER:-sqlite}) and was terminated."'): (2, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::[#6344 shard] ${name}: ${SHARD_BUDGET}s shard budget exhausted before the binaries run"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::[#6344 shard] ${name}: ${SHARD_BUDGET}s shard budget exhausted before the doc tests"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::[#6344 shard] ${name}: ${SHARD_BUDGET}s shard budget exhausted before the lib run"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::[#6344 shard] ${name}: lib Postgres filter list is empty (refusing to run the lib unfiltered)"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::[#6344] sharded \'${label}\' FAILED (serial=${rc_s} parallel_1=${rc_1} parallel_2=${rc_2}); see the shard output groups above"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::[#6383 shard] ${name}: ${SHARD_BUDGET}s shard budget exhausted before the isolated binaries"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::[#6383] \'${label}\': the isolated target list is empty"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::cargo-audit ${CARGO_AUDIT_VERSION} is not the installed version"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::enterprise-fed leg on $RUNNER_NAME failed to CREATE DATABASE $CI_FED_DB on the native tier"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::enterprise-fed leg on $RUNNER_NAME failed to create age/vector extensions in $CI_FED_DB"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::enterprise-fed leg on $RUNNER_NAME is missing $url_file — the native pg tier URL is not provisioned on this node"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::enterprise-fed leg on $RUNNER_NAME: AGE self-heal failed (#6161), see the ensure-age-extension line above"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::error::rustup is not provisioned at \\$HOME/.cargo/bin/rustup on $RUNNER_NAME — repair the node."'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::group::[#6344] ${n} shard output"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[#1492] \'${label}\' ran ${elapsed}s of the ${WATCHDOG_SECS}s per-invocation watchdog budget ($((elapsed * 100 / WATCHDOG_SECS))% used, $((WATCHDOG_SECS - elapsed))s margin; tier=${TIER:-sqlite} node=${CI_NODE:-unknown} watchdog=${TIMEOUT_BIN:-disabled})"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[#1492] \'${label}\' ran ${elapsed}s of the ${WATCHDOG_SECS}s per-invocation watchdog budget (tier=${TIER:-sqlite} node=${CI_NODE:-unknown})"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[#1492] hung-test watchdog active via \'$TIMEOUT_BIN\' (${WATCHDOG_SECS}s per invocation, tier=${TIER:-sqlite})"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[#1492] watchdog disabled on ${RUNNER_OS:-unknown} — no coreutils gtimeout/timeout found (job-level timeout-minutes still applies)"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[#1853] e1 orchestrator prebuilt at $BIN"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[#6202] \'${label}\' passed: suite wall ${elapsed}s of the ${WATCHDOG_SECS}s watchdog budget ($((elapsed * 100 / WATCHDOG_SECS))% used, $(( (WATCHDOG_SECS - elapsed) / 60 )) min margin; tier=${TIER:-sqlite} node=${CI_NODE:-unknown})"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[#6344] \'${label}\': compile once, partition, then run serial + 2 parallel shards"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[#6344] progress | serial: $(tail -n 1 "$sd/serial.log" 2>/dev/null | cut -c1-90) | parallel_1: $(tail -n 1 "$sd/parallel_1.log" 2>/dev/null | cut -c1-90) | parallel_2: $(tail -n 1 "$sd/parallel_2.log" 2>/dev/null | cut -c1-90)"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[#6344] shard exit codes: serial=${rc_s} parallel_1=${rc_1} parallel_2=${rc_2}"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[#6383] \'${label}\' ran ${elapsed}s of the ${WATCHDOG_SECS}s per-invocation watchdog budget (tier=${TIER:-sqlite} node=${CI_NODE:-unknown})"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[#6383] per-binary Postgres isolation ON: template ${CI_FED_DB}_tpl"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[#6795] serial shard budget ${SERIAL_BUDGET_SECS}s (job cap ${JOB_TIMEOUT_MIN} min - ${job_elapsed}s elapsed since job start - 300s safety); parallel shards min(${WATCHDOG_SECS}s, job time left)"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[enterprise-fed] cargo test $FEAT ... $TAIL (watchdog ${WATCHDOG_SECS}s)"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[enterprise-fed] created ephemeral db $CI_FED_DB on the native tier ($RUNNER_NAME) and pointed AI_MEMORY_TEST_POSTGRES_URL at it"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::[sqlite] cargo test (default features) (watchdog ${WATCHDOG_SECS}s, node=${CI_NODE:-unknown})"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::cannot fetch classification base tree ($cls_base) after retry — running full pipeline"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::cannot fetch impact base tree ($impact_base) — widening impact selection to the classification base"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::cannot resolve classification base commit ($cls_base) — running full pipeline"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::cargo_skip=false ($cargo_skip_reason) - running full pipeline"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::cargo_skip=true ($cargo_skip_reason) - cargo legs no-op"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::dropped ephemeral db $CI_FED_DB on $RUNNER_NAME"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::impact selection returned __SKIP__ from the incremental base ($IMPACT_BASE) but the PR is NOT docs-only - overriding to __ALL__ (fail closed)"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::impact selector exited $selector_rc - full selection (fail closed)"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::impact-selection-rejected-at-consumer (${impact_rejected} of ${#impact_words[@]} words rejected, charset ${impact_charset}) - running the full suite (fail closed)"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::impact-skip-overridden-at-consumer (docs_only=${DOCS_ONLY:-unset}) - running the full suite (fail closed)"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::running FULL test suite (tier=${TIER:-sqlite})"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::notice::running cargo test --lib + impact-selected integration binaries (tier=${TIER:-sqlite})"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::warning::[#3539] $name was present in this self-hosted runner\'s environment; neutralising it for this job (value never printed)"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::warning::cannot drop $CI_FED_DB — $url_file missing on $RUNNER_NAME (leaked ephemeral db)"'): (1, YAML_PR4_REASON),
    ('ci.yml', 'echo "::warning::failed to drop ephemeral db $CI_FED_DB on $RUNNER_NAME (leaked)"'): (1, YAML_PR4_REASON),
    ('coverage.yml', 'echo "::notice::$repo resolvable at $snap (all 3 artifacts present)"'): (1, YAML_PR4_REASON),
    ('coverage.yml', 'echo "::notice::cannot fetch base tree ($base) after retry — running full pipeline"'): (1, YAML_PR4_REASON),
    ('coverage.yml', 'echo "::notice::cannot resolve base commit ($base) — running full pipeline"'): (1, YAML_PR4_REASON),
    ('coverage.yml', 'echo "::notice::staged $m (attempt $attempt)"; ok=1; break'): (1, YAML_PR4_REASON),
    ('coverage.yml', 'echo "::warning::hf fetch $m attempt $attempt failed; retry in $((attempt*10))s"'): (1, YAML_PR4_REASON),
    ('mobile-runtime.yml', 'echo "::notice::booting iOS Simulator: $DEVICE_NAME ($UDID)"'): (1, YAML_PR4_REASON),
    ('mobile-runtime.yml', 'echo "::notice::built $BIN ($(du -h "$BIN" | cut -f1))"'): (2, YAML_PR4_REASON),
    ('postgres-ignored.yml', 'echo "::error::$RUNNER_NAME failed to CREATE DATABASE $CI_FED_DB on the native cert tier"'): (1, YAML_PR4_REASON),
    ('postgres-ignored.yml', 'echo "::error::$RUNNER_NAME failed to create age/vector extensions in $CI_FED_DB"'): (1, YAML_PR4_REASON),
    ('postgres-ignored.yml', 'echo "::error::$RUNNER_NAME is missing $url_file — the native cert tier URL is not provisioned on this node"'): (1, YAML_PR4_REASON),
    ('postgres-ignored.yml', 'echo "::error::rustup is not provisioned at \\$HOME/.cargo/bin/rustup on $RUNNER_NAME — repair the node."'): (1, YAML_PR4_REASON),
    ('postgres-ignored.yml', 'echo "::notice::[#3274] ignored pg tests pointed at ephemeral db $CI_FED_DB on $RUNNER_NAME"'): (1, YAML_PR4_REASON),
    ('postgres-ignored.yml', 'echo "::notice::dropped ephemeral db $CI_FED_DB on $RUNNER_NAME"'): (1, YAML_PR4_REASON),
    ('postgres-ignored.yml', 'echo "::warning::cannot drop $CI_FED_DB — $url_file missing on $RUNNER_NAME (leaked ephemeral db)"'): (1, YAML_PR4_REASON),
    ('postgres-ignored.yml', 'echo "::warning::failed to drop ephemeral db $CI_FED_DB on $RUNNER_NAME (leaked)"'): (1, YAML_PR4_REASON),
    ('publish-ci-image.yml', 'echo "::notice::CI image tag resolved from SSOT: ${IMAGE_REPO}:${img_tag}"'): (1, YAML_PR4_REASON),
    ('publish-ci-image.yml', 'echo "::notice::built CI image — PostgreSQL=$pg_ver Apache AGE=$age_ver pgvector=$vec_ver"'): (1, YAML_PR4_REASON),
    ('publish-ci-image.yml', 'echo "::notice::postgres up after $((i*2))s"; break'): (1, YAML_PR4_REASON),
    ('publish-ci-image.yml', 'if [ "$i" = 60 ]; then echo "::error::postgres did not become ready"; docker logs ci-image-verify || true; exit 1; fi'): (1, YAML_PR4_REASON),
    ('release.yml', 'echo "::error::${ASSET}.sha256 does not contain a valid SHA-256 digest"'): (2, YAML_PR4_REASON),
    ('release.yml', 'echo "::error::checksum mismatch for ${ASSET} (published ${EXPECTED}, downloaded ${ACTUAL}) - refusing to build an SRPM"'): (1, YAML_PR4_REASON),
    ('release.yml', 'echo "::error::checksum mismatch for ${ASSET} (published ${EXPECTED}, downloaded ${ACTUAL}) - refusing to mint a Homebrew formula"'): (1, YAML_PR4_REASON),
    ('release.yml', 'echo "::error::libai_memory.a not produced for $TARGET"'): (1, YAML_PR4_REASON),
    ('release.yml', 'echo "::error::release.yml must be dispatched from a release branch (gh workflow run release.yml --ref release/vX.Y.Z -f tag=vX.Y.Z); got \'$DISPATCH_REF\'"'): (1, YAML_PR4_REASON),
    ('release.yml', 'echo "::error::tag \'$TAG\' does not match SemVer v<MAJ>.<MIN>.<PATCH>(-pre)?"'): (1, YAML_PR4_REASON),
    ('release.yml', 'echo "::error::tagged commit $SHA is not on the dispatch branch (tip $DISPATCH_SHA); a release ships a commit the protected branch already contains"'): (1, YAML_PR4_REASON),
    ('release.yml', 'echo "::group::cargo build --target $TARGET ($ABI)"'): (1, YAML_PR4_REASON),
    ('release.yml', 'echo "::group::cargo build --target $TARGET"'): (1, YAML_PR4_REASON),
    ('release.yml', 'echo "::notice::crates.io publish succeeded on attempt $attempt"'): (1, YAML_PR4_REASON),
    ('release.yml', 'echo "::notice::no release-body file at $path — falling back to auto-generated notes"'): (1, YAML_PR4_REASON),
    ('release.yml', 'echo "::notice::release body sourced from $path"'): (1, YAML_PR4_REASON),
    ('release.yml', 'echo "::warning::crates.io publish failed on attempt $attempt — retrying after 30s"'): (1, YAML_PR4_REASON),
    ('token-budget.yml', 'echo "::error::v0.7 C5 CI gate FAILED: trimmed full-profile tools/list payload is $TOTAL cl100k_base tokens (ceiling: 8110, post-D1.6 + #1067 + #1709 + #2037 + #2059 + #2204 + #3171 + #3266/#3322)."'): (1, YAML_PR4_REASON),
    ('tool-count-drift.yml', 'echo "::error::README MCP badge missing \'7_default • ${EXPECTED_FULL_COUNT}_full\' (derived from registry)"'): (1, YAML_PR4_REASON),
    ('tool-count-drift.yml', 'echo "::error::docs/v0.7.0/release-notes.md missing frozen \'60 → ${FROZEN_V070_FULL_COUNT}\' v0.7.0 tool count delta"'): (1, YAML_PR4_REASON),
    ('tool-count-drift.yml', 'echo "::error::registry RegisteredTool::of count $count is outside plausibility window [60, 130]"'): (1, YAML_PR4_REASON),
    ('tool-count-drift.yml', 'echo "::error::v0.7.0 ceiling is Profile::full().expected_tool_count() == $EXPECTED_FULL_COUNT"'): (1, YAML_PR4_REASON),
    ('tool-count-drift.yml', 'echo "::warning::src/daemon_runtime.rs has \'profile full\' tool-count narrative lines; verify they match $EXPECTED_FULL_COUNT / $EXPECTED_CALLABLE_COUNT"'): (1, YAML_PR4_REASON),
}

HUGE_VALUE_CHARS = 100_001
HUGE_WALL_CLOCK_SECS = 5.0
SUBPROCESS_TIMEOUT_SECS = 60
GENERATED_CASES = 400
GENERATED_SEED = 9365
GENERATED_ALPHABET = ":#[]%0ADd\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029 \tax\\,="

HOSTILE_VALUES = {
    "command": "::error::x",
    "leading_space_command": "   ::error::x",
    "raw_newline": "a\n::error::injected",
    "raw_cr": "a\r::error::injected",
    "percent_lf": "%0A::set-output name=pwn::1",
    "percent_cr": "a%0D::error::b",
    "v1_form": "x ##[error]pwn",
    "v1_split_hash": "#",
    "separators": "a\u2028::error::b\x85::error::c\x0b::warning::d",
    "colons": "a::b",
    "non_utf8": os.fsdecode(b"bad\xff\xfe::x"),
}
BENIGN_TEXTS = {
    "plain": "removed /home/runner/work/x",
    "colon_inside": "label: value",
    "issue_hash": "see issue #9365",
    "csharp": "C#",
    "brackets": "[Errno 13] Permission denied",
    "ansi": "\x1b[31mred\x1b[0m",
    "multi_line": "first\nsecond\n  third",
    "empty": "",
}

# One red cell per bypass form named on the tracker (c9365-lane-b): source -> the form the ratchet must name.
BYPASS_FORMS = {
    "print alias": ("p = print\np(value)\n", "print"),
    "print end=value": ("print('x', end=value)\n", "print"),
    "print sep=value": ("print('x', 'y', sep=value)\n", "print"),
    "stdout.buffer.write": ("import sys\nsys.stdout.buffer.write(value)\n", "sys.stdout"),
    "stderr.buffer.write": ("import sys\nsys.stderr.buffer.write(value)\n", "sys.stderr"),
    "os.write fd 1": ("import os\nos.write(1, value)\n", "os.write"),
    "os.write fd 2": ("import os\nos.write(2, value)\n", "os.write"),
    "logging call": ("import logging\nlogging.error(value)\n", "logging"),
    "stdout alias": ("import sys\nout = sys.stdout\nout.write(value)\n", "sys.stdout"),
    "subprocess echo": ("import subprocess\nsubprocess.run(['echo', value])\n", "subprocess echo"),
    "percent template": ("text = '##%s' % value\n", "## before a placeholder"),
    "format template": ("text = '##{}'.format(value)\n", "## before a placeholder"),
    "plus chain": ("text = '#' + '#' + value\n", "## before a + operand"),
}
SIBLING_FORMS = {
    "f-string ##{": ("text = f'##{value}'\n", "## before a placeholder"),
    "f-string ::{": ("text = f'::{value}'\n", ":: before a placeholder"),
    "print file=alias": ("import sys\nprint(value, file=err)\n", "print"),
    "sys.__stdout__": ("import sys\nsys.__stdout__.write(value)\n", "sys.__stdout__"),
    "open fd 1": ("open(1, 'w').write(value)\n", "open of fd 1"),
    "io.open fd 2": ("import io\nio.open(2, 'w').write(value)\n", "open of fd 2"),
    "os.fdopen": ("import os\nos.fdopen(1, 'w').write(value)\n", "os.fdopen"),
    "fd bound to 1": ("import os\ndef f(value):\n    fd = 1\n    os.write(fd, value)\n", "os.write"),
    "opened fd rebound to 2": ("import os\ndef f(path, value):\n    fd = os.open(path, os.O_RDONLY)\n"
                               "    fd = 2\n    os.write(fd, value)\n", "os.write"),
    "fd duplicated from 1": ("import os\ndef f(value):\n    fd = os.dup(1)\n    os.write(fd, value)\n",
                             "os.write"),
    "fd parameter": ("import os\ndef f(fd, value):\n    os.fdopen(fd, 'w').write(value)\n", "os.fdopen"),
    "fd opened only in a nested function": ("import os\nfd = 1\ndef f(path, value):\n    def g():\n"
                                            "        fd = os.open(path, os.O_RDONLY)\n        return fd\n"
                                            "    os.write(fd, value)\n", "os.write"),
    "helper returning 1": ("import os\ndef fd_of():\n    fd = 1\n    return fd\ndef f(value):\n"
                           "    os.fdopen(fd_of(), 'w').write(value)\n", "os.fdopen"),
    "helper with a parameter return": ("import os\ndef fd_of(fd):\n    return fd\ndef f(value):\n"
                                       "    os.write(fd_of(1), value)\n", "os.write"),
    "module-level opened fd": ("import os\nfd = os.open(path, os.O_RDONLY)\nos.write(fd, value)\n", "os.write"),
    "stdout.writelines": ("import sys\nsys.stdout.writelines([value])\n", "sys.stdout"),
    "warnings.warn": ("import warnings\nwarnings.warn(value)\n", "warnings.warn"),
    "traceback.print_exc": ("import traceback\ntraceback.print_exc()\n", "traceback.print_exc"),
    "traceback.print_exception": ("import traceback\ntraceback.print_exception(exc)\n", "traceback.print_exception"),
    "getattr sys stdout": ("import sys\ngetattr(sys, 'stdout').write(value)\n", "getattr on sys"),
    "vars sys": ("import sys\nvars(sys)['stdout'].write(value)\n", "vars on sys"),
    "from sys import stdout": ("from sys import stdout\nstdout.write(value)\n", "from sys import stdout"),
    "builtins.print": ("import builtins\nbuiltins.print(value)\n", "builtins.print"),
    "pprint": ("import pprint\npprint.pprint(value)\n", "pprint"),
    "input prompt": ("input(value)\n", "input"),
    "os.system": ("import os\nos.system('echo ' + value)\n", "os.system"),
    "subprocess printf": ("import subprocess\nsubprocess.call(['printf', value])\n", "subprocess echo"),
    "subprocess shell echo": ("import subprocess\nsubprocess.run('echo ' + value, shell=True)\n", "subprocess echo"),
    "sys.exit text": ("import sys\nsys.exit(f'failed: {value}')\n", "sys.exit with text"),
    "SystemExit text": ("raise SystemExit('failed: ' + value)\n", "SystemExit with text"),
    "logging import": ("from logging import error\nerror(value)\n", "logging"),
    "forged CommandLine": ("wa.out(wa.CommandLine(value))\n", "CommandLine outside the shared module"),
    "emitter internals": ("wa._neutralise(value, state)\n", "private emitter name"),
}
# forms that stay allowed: a routed emitter call, a captured echo, an int exit, a file write
ALLOWED_FORMS = {
    "routed out": "wa.out('x', value)\n",
    "routed err": "wa.err(value, end='')\n",
    "routed stream": "wa.emit_to(stream, value)\n",
    "captured echo": "import subprocess\nsubprocess.run(['echo', value], capture_output=True)\n",
    "piped echo": "import subprocess\nsubprocess.run(['echo', value], stdout=subprocess.PIPE)\n",
    "int exit": "import sys\nsys.exit(main())\n",
    "file write": "with open(path, 'w') as fh:\n    fh.write(value)\n",
    "fd opened here": "import os\ndef f(path, value):\n    fd = os.open(path, os.O_WRONLY)\n    os.write(fd, value)\n",
    "temp file fd": ("import os, tempfile\ndef f(value):\n    fd, tmp = tempfile.mkstemp()\n"
                     "    with os.fdopen(fd, 'wb') as fh:\n        fh.write(value)\n"),
    "helper opening a path": ("import os\ndef open_new(path):\n    fd = os.open(path, os.O_WRONLY)\n    return fd\n"
                              "def f(path, value):\n    os.fdopen(open_new(path), 'wb').write(value)\n"),
    "closed pipe forgotten": ("import os\ndef f(value):\n    r, w = os.pipe()\n    os.write(w, value)\n"
                              "    os.close(w)\n    w = None\n"),
    "pipe fds": "import os\ndef f(value):\n    r, w = os.pipe()\n    os.write(w, value)\n    os.fdopen(r).read()\n",
    "rust path": "text = a + '::' \n",
    "hash then text": "text = '##' + ' note'\n",
}


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def covered_files(root):
    """Every .py under ``root``, found by walking the tree (no list): ``scripts/`` relative posix paths."""
    found = []
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = sorted(d for d in subdirs if d != "__pycache__")
        for name in sorted(files):
            if name.endswith(".py"):
                found.append((Path(directory) / name).relative_to(REPO).as_posix())
    return found


def _dotted(node):
    """``a.b.c`` for a Name/Attribute chain, else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _is_text(node):
    """True for an expression that is text the interpreter would print (literal, f-string, % / + / .format)."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return _is_text(node.left) or _is_text(node.right)
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
            and _is_text(node.func.value))


def _plus_operands(node):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _plus_operands(node.left) + _plus_operands(node.right)
    return [node]


def _placeholder_findings(node):
    """The ``##`` / ``::`` before-a-placeholder rule for one node: [(form)]."""
    found = []
    if isinstance(node, ast.JoinedStr):
        for index, (left, right) in enumerate(zip(node.values, node.values[1:])):
            if isinstance(left, ast.Constant) and isinstance(right, ast.FormattedValue):
                hit = command_prefix_hit(str(left.value), index == 0)
                if hit:
                    found.append("%s before a placeholder" % hit)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant) \
            and isinstance(node.left.value, str):
        hit = template_prefix_hit(node.left.value.replace("%%", ""), "%")
        if hit:
            found.append("%s before a placeholder" % hit)
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
          and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str)):
        hit = template_prefix_hit(node.func.value.value.replace("{{", ""), "{")
        if hit:
            found.append("%s before a placeholder" % hit)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        folded, at_start = "", True
        for operand in _plus_operands(node):
            if isinstance(operand, ast.Constant) and isinstance(operand.value, str):
                folded += operand.value
                continue
            hit = command_prefix_hit(folded, at_start)
            if hit:
                found.append("%s before a + operand" % hit)
            folded, at_start = "", False
    return found


def _scopes(tree):
    """node id -> name of the innermost enclosing function ("<module>" at top level)."""
    owner = {}

    def visit(node, name):
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else name
            owner[id(child)] = inner
            visit(child, inner)

    visit(tree, "<module>")
    return owner


def _load_try_nodes(rel, tree, source):
    """Ids of the nodes inside the canonical load ``try`` when the file passes the one-shape check."""
    loader = _loader_test()
    if not loader.shared_module_references(tree) or loader.loader_shape_violations(rel, source):
        return set()
    inside = set()
    containers = [tree] + [node for node in tree.body if isinstance(node, ast.FunctionDef)
                           and node.name == loader.REQUIRE_NAME]
    for container in containers:
        for node in container.body:
            if loader._is_load_try(node):
                for handler in node.handlers:
                    inside.update(id(inner) for inner in ast.walk(handler))
    return inside


_LOADER_TEST = []


def _loader_test():
    if not _LOADER_TEST:
        _LOADER_TEST.append(load_module(LOADER_TEST_PATH, "loader_shape_9365_for_stream_allowlist"))
    return _LOADER_TEST[0]


def _captured(call):
    return any(keyword.arg in CAPTURE_KEYWORDS for keyword in call.keywords)


def _echo_argv(call):
    """True when a subprocess call runs echo/printf (argv list or a shell string) without capturing stdout."""
    if not call.args or _captured(call):
        return False
    first = call.args[0]
    if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
        head = first.elts[0]
        return isinstance(head, ast.Constant) and isinstance(head.value, str) and \
            os.path.basename(head.value) in ECHO_PROGRAMS
    folded = _plus_operands(first)[0]
    if isinstance(folded, ast.JoinedStr) and folded.values and isinstance(folded.values[0], ast.Constant):
        folded = folded.values[0]
    return (isinstance(folded, ast.Constant) and isinstance(folded.value, str)
            and folded.value.split(" ", 1)[0] in ECHO_PROGRAMS)


# A raw fd write is allowed only on a name its own function bound, at every binding, from one of these calls: a
# path, a pipe or a fresh temp file is never the runner's fd 1 or 2 (those stay open, so no opener returns them).
FD_OPENERS = {("os", "open"): "value", ("os", "pipe"): "both", ("os", "openpty"): "both",
              ("tempfile", "mkstemp"): "first"}
FD_WRITERS = frozenset({"write", "fdopen"})


def _function_of(tree):
    """id(node) -> the innermost enclosing FunctionDef node (absent at module level)."""
    owner = {}

    def visit(node, func):
        for child in ast.iter_child_nodes(node):
            owner[id(child)] = func
            visit(child, child if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else func)

    visit(tree, None)
    return owner


def _own_nodes(func):
    """Every node of ``func``'s own scope: nested functions, lambdas and classes are not entered."""
    stack = list(ast.iter_child_nodes(func))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(node))


def _bindings(func):
    """(target, value) for every name binding of ``func``'s own scope; value is None unless it is ``x = <expr>``."""
    for node in _own_nodes(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                yield target, node.value
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            yield node.target, node.value
        elif isinstance(node, (ast.AugAssign, ast.For, ast.AsyncFor, ast.comprehension)):
            yield node.target, None
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    yield item.optional_vars, None
        elif isinstance(node, ast.ExceptHandler) and node.name:
            yield ast.Name(id=node.name), None
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                yield ast.Name(id=name), None


def _opener_kind(value, module_of, helpers):
    """How an assigned call yields fds: an FD_OPENERS kind, "value" for a same-file helper in ``helpers``."""
    if not isinstance(value, ast.Call):
        return None
    if isinstance(value.func, ast.Name) and value.func.id in helpers:
        return "value"
    parts = (_dotted(value.func) or "").split(".")
    return FD_OPENERS.get((module_of(parts[0]), parts[1])) if len(parts) == 2 else None


def _opened_fd_names(func, module_of, helpers=frozenset()):
    """Names ``func`` binds only from an FD_OPENERS call (or a ``helpers`` call), at every binding; ``x = None``
    (a closed fd forgotten) binds nothing, a parameter never counts."""
    args = func.args
    good, bad = set(), {arg.arg for arg in args.posonlyargs + args.args + args.kwonlyargs}
    for target, value in _bindings(func):
        if isinstance(value, ast.Constant) and value.value is None:
            continue
        kind = _opener_kind(value, module_of, helpers)
        if isinstance(target, ast.Name):
            (good if kind == "value" else bad).add(target.id)
            continue
        elts = target.elts if isinstance(target, (ast.Tuple, ast.List)) else []
        for index, name in enumerate(elts):
            if isinstance(name, ast.Name):
                proven = kind == "both" or (kind == "first" and index == 0)
                (good if proven else bad).add(name.id)
    return good - bad


def _fd_helpers(tree, module_of):
    """Module-level functions whose every return (at least one) is a name they opened: ``open_new(path)``."""
    helpers = set()
    for func in tree.body:
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            returns = [node for node in _own_nodes(func) if isinstance(node, ast.Return)]
            opened = _opened_fd_names(func, module_of)
            if returns and all(isinstance(node.value, ast.Name) and node.value.id in opened for node in returns):
                helpers.add(func.name)
    return frozenset(helpers)


def sink_findings(rel, source):
    """Every way ``source`` (repo-relative ``rel``) can reach fd 1 or 2 outside the emitters: ["rel:line: form"]."""
    tree = ast.parse(source)
    owner = _scopes(tree)
    load_try = _load_try_nodes(rel, tree, source)
    aliases = {}  # local name -> module it imports (import x as y)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
    found = []
    func_of = _function_of(tree)
    opened = {}
    helpers = []

    def opened_fd(call):
        """True when the fd argument of an os.write / os.fdopen call is a name its own function opened, or a
        direct call of a same-file fd helper (``_fd_helpers``)."""
        if not helpers:
            helpers.append(_fd_helpers(tree, module_of))
        first = call.args[0] if call.args else None
        if isinstance(first, ast.Call) and isinstance(first.func, ast.Name):
            return first.func.id in helpers[0]
        func = func_of.get(id(call))
        if func is None or not isinstance(first, ast.Name):
            return False
        if id(func) not in opened:
            opened[id(func)] = _opened_fd_names(func, module_of, helpers[0])
        return first.id in opened[id(func)]

    def add(node, form):
        if id(node) in load_try:
            return
        if (rel, owner.get(id(node), "<module>")) in EXEMPT_SITES:
            return
        found.append("%s:%d: %s" % (rel, node.lineno, form))

    def module_of(name):
        return aliases.get(name, name)

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "print" and isinstance(node.ctx, ast.Load):
            add(node, "print")
        elif isinstance(node, ast.Attribute):
            dotted = _dotted(node)
            head = dotted.split(".")[0] if dotted else None
            if head and module_of(head) == "sys" and node.attr in STD_STREAM_ATTRS \
                    and isinstance(node.value, ast.Name):
                add(node, "sys." + node.attr)
            elif head and module_of(head) == "builtins" and node.attr == "print":
                add(node, "builtins.print")
            elif head and module_of(head) == "traceback" and node.attr.startswith("print"):
                add(node, "traceback." + node.attr)
            elif head and module_of(head) == "logging" and isinstance(node.value, ast.Name):
                add(node, "logging")
            elif rel != SHARED_MODULE_REL and node.attr == COMMAND_LINE_CLASS:
                add(node, "CommandLine outside the shared module")
            elif rel != SHARED_MODULE_REL and head == SHARED_MODULE_ALIAS and node.attr.startswith("_") \
                    and isinstance(node.value, ast.Name):
                add(node, "private emitter name")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            module = node.module if isinstance(node, ast.ImportFrom) else None
            names = [alias.name for alias in node.names]
            if module == "sys" and STD_STREAM_ATTRS & set(names):
                add(node, "from sys import " + sorted(STD_STREAM_ATTRS & set(names))[0])
            elif module == "logging" or (module is None and "logging" in names):
                if module == "logging":
                    add(node, "logging")
            elif module == "pprint" or (module is None and "pprint" in names):
                add(node, "pprint")
            elif module == "builtins" and "print" in names:
                add(node, "builtins.print")
        if isinstance(node, ast.Call):
            func = _dotted(node.func) or ""
            parts = func.split(".")
            mod = module_of(parts[0]) if len(parts) > 1 else None
            leaf = parts[-1]
            if mod == "os" and leaf in FD_WRITERS and opened_fd(node):
                pass  # an fd this function opened from a path, a pipe or a temp file (FD_OPENERS)
            elif mod == "os" and leaf == "write":
                add(node, "os.write")
            elif mod == "os" and leaf == "fdopen":
                add(node, "os.fdopen")
            elif mod == "os" and leaf == "system":
                add(node, "os.system")
            elif (func in ("open", "io.open") or (mod == "io" and leaf == "open")) and node.args \
                    and isinstance(node.args[0], ast.Constant) and node.args[0].value in FD_NUMBERS:
                add(node, "open of fd %d" % node.args[0].value)
            elif mod == "warnings" and leaf in ("warn", "warn_explicit", "showwarning"):
                add(node, "warnings." + leaf)
            elif func in ("getattr", "vars", "setattr") and node.args and isinstance(node.args[0], ast.Name) \
                    and module_of(node.args[0].id) == "sys":
                add(node, "%s on sys" % func)
            elif func == "input" and (node.args or node.keywords):
                add(node, "input")
            elif mod == "subprocess" and leaf in SUBPROCESS_CALLS and _echo_argv(node):
                add(node, "subprocess echo")
            elif ((mod == "sys" and leaf == "exit") or func == "SystemExit") and node.args \
                    and _is_text(node.args[0]):
                add(node, "%s with text" % ("sys.exit" if leaf == "exit" else "SystemExit"))
        for form in _placeholder_findings(node):
            add(node, form)
    return sorted(set(found), key=lambda line: (int(line.split(":")[1]), line))


def fixture_runner_captures(source):
    """[] when every subprocess call in the fixture runner that names a fixture prefix captures its output."""
    problems = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and (_dotted(node.func) or "").startswith("subprocess.") \
                and not _captured(node):
            problems.append("%s:%d: subprocess call without captured output" % (FIXTURE_RUNNER_REL, node.lineno))
    return problems


def is_fixture(rel):
    return rel.startswith(FIXTURE_DIR_REL + "/")


def tree_findings(root=SCRIPTS_ROOT, rows=UNROUTED_FILES):
    """Every finding over the walked tree, fixtures excluded by their proved rule; a file with a row in
    ``rows`` is skipped here (its count is checked by ``unrouted_row_problems``)."""
    found = []
    for rel, path in walked_files(root):
        if is_fixture(rel) or rel in rows:
            continue
        found.extend(sink_findings(rel, path.read_text(encoding="utf-8")))
    return found


def walked_files(root):
    """(key, path) for every covered file under ``root``; the key is relative to ``root.parent``, so a copy of
    the tree elsewhere (a break-it cell) has the same ``scripts/...`` keys as the real one."""
    base = Path(root).parent
    return [(path.relative_to(base).as_posix(), path)
            for path in (REPO / rel for rel in covered_files(root))]


def unrouted_row_problems(root=SCRIPTS_ROOT, rows=UNROUTED_FILES):
    """Rows of ``rows`` whose recorded site count differs from the count found (equality, never <=)."""
    walked = dict(walked_files(root))
    problems = []
    for rel in sorted(rows):
        path = walked.get(rel)
        if path is None:
            problems.append("%s: row for a missing file" % rel)
            continue
        found = len(sink_findings(rel, path.read_text(encoding="utf-8")))
        if found == 0:
            problems.append("%s: row for a file with no un-routed site" % rel)
        elif found > rows[rel]:
            problems.append("%s: %d un-routed sites, the row says %d (a new un-routed site)" % (rel, found, rows[rel]))
        elif found < rows[rel]:
            problems.append("%s: %d un-routed sites, the row says %d (lower the row in the same commit)"
                            % (rel, found, rows[rel]))
    return problems


def yaml_line_finding(line):
    """The finding text for one workflow line, or ``""``."""
    if not YAML_ECHO_RE.search(line):
        return ""
    if YAML_EXPRESSION in line and YAML_COMMAND_RE.search(line):
        return "${{ }} in a workflow-command echo"
    if YAML_COMMAND_RE.search(line) and YAML_VALUE_RE.search(line):
        return "workflow-command echo with a shell value"
    return ""


def yaml_echo_findings(root=WORKFLOWS_ROOT, rows=YAML_EXEMPT_LINES):
    """Every echo/printf line in a workflow that prints a workflow command with a shell value (or any ${{ }}),
    except the lines ``rows`` names (their counts are checked by ``yaml_exempt_problems``)."""
    found = []
    for path in sorted(root.glob("*.y*ml")):
        for number, line in enumerate(YAML_LINE_BREAK_RE.split(path.read_text(encoding="utf-8")), 1):
            finding = yaml_line_finding(line)
            if finding and (path.name, line.strip()) not in rows:
                found.append("%s:%d: %s" % (path.name, number, finding))
    return found


def yaml_exempt_problems(root=WORKFLOWS_ROOT, rows=YAML_EXEMPT_LINES):
    """Rows of ``rows`` whose line is gone (stale) or whose line count differs from the row (equality)."""
    problems = []
    for (name, line), (count, _reason) in sorted(rows.items()):
        path = root / name
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        found = [row.strip() for row in YAML_LINE_BREAK_RE.split(text)].count(line)
        if found == 0:
            problems.append("%s: %r: row for a line that is gone (stale)" % (name, line))
        elif found != count:
            problems.append("%s: %r: %d such lines, the row says %d" % (name, line, found, count))
    return problems


def wa_module():
    return load_module(SHARED_MODULE_PATH, "workflow_annotation_stream_9365")


def command_lines(text):
    """Lines the runner would read as a workflow command: v2 (``::`` after TrimStart) or v1 (``##[`` anywhere)."""
    return [line for line in re.split(r"\r\n|\n|\r", text) if line.lstrip().startswith("::") or "##[" in line]


class TreeRatchet(unittest.TestCase):
    """Structural cells over the whole scripts/ tree."""

    def test_the_tree_walk_covers_every_python_file_9365(self):
        walked = set(covered_files(SCRIPTS_ROOT))
        listed = set(subprocess.run(["git", "-C", str(REPO), "ls-files", "scripts/*.py", "scripts/**/*.py"],
                                    capture_output=True, text=True, check=True,
                                    timeout=SUBPROCESS_TIMEOUT_SECS).stdout.split())
        self.assertEqual(listed - walked, set())
        self.assertIn("scripts/check-claude-md-size.py", walked)
        self.assertIn("scripts/ci/tests/test_ci_annotation_escape_9365.py", walked)

    def test_every_unrouted_row_equals_its_site_count_9365(self):
        self.assertEqual(unrouted_row_problems(), [])

    def test_no_unrouted_row_names_a_file_under_scripts_ci_9365(self):
        """PR-1a routes scripts/ci completely except UNROUTED_CI_PREFIX (PR-1b); no other file there gets a row."""
        self.assertEqual([rel for rel in UNROUTED_FILES
                          if rel.startswith("scripts/ci/") and not rel.startswith(UNROUTED_CI_PREFIX)], [])
        self.assertEqual([rel for rel, count in UNROUTED_FILES.items() if count < 1], [])

    def test_every_exempt_site_has_a_reason_and_exists_9365(self):
        for (rel, scope), reason in EXEMPT_SITES.items():
            with self.subTest(site=(rel, scope)):
                self.assertGreater(len(reason), 20)
                source = (REPO / rel).read_text(encoding="utf-8")
                if scope != "<module>":
                    self.assertIn("def %s(" % scope, source)

    def test_no_script_writes_to_fd_1_or_2_outside_the_emitters_9365(self):
        self.assertEqual(tree_findings(), [])

    def test_fixture_output_never_reaches_the_runner_9365(self):
        fixtures = [rel for rel in covered_files(SCRIPTS_ROOT) if is_fixture(rel)]
        self.assertTrue(fixtures)
        runner = (REPO / FIXTURE_RUNNER_REL).read_text(encoding="utf-8")
        for rel in fixtures:
            with self.subTest(fixture=rel):
                self.assertIn("'%s'" % Path(rel).name, runner)  # its one runner names it
        users = [rel for rel in covered_files(SCRIPTS_ROOT) if not is_fixture(rel)
                 and "foreign-text-prefix-" in (REPO / rel).read_text(encoding="utf-8")
                 and rel != FIXTURE_RUNNER_REL and "/tests/" not in rel]
        self.assertEqual(users, [])
        self.assertEqual(fixture_runner_captures((REPO / FIXTURE_RUNNER_REL).read_text(encoding="utf-8")), [])
        self.assertTrue(FIXTURE_EXEMPT_REASON)

    def test_no_workflow_echo_prints_a_command_with_a_value_9365(self):
        self.assertEqual(yaml_echo_findings(), [])

    def test_every_yaml_exempt_row_equals_its_line_count_9365(self):
        self.assertEqual(yaml_exempt_problems(), [])
        for (name, line), (count, reason) in YAML_EXEMPT_LINES.items():
            with self.subTest(line=line):
                self.assertGreater(len(reason), 20)
                self.assertGreaterEqual(count, 1)
        others = {key: value for key, value in YAML_EXEMPT_LINES.items() if key[0] != "release-shape.yml"
                  or "::add-mask::" not in key[1]}
        self.assertEqual({value[1] for value in others.values()}, {YAML_PR4_REASON})


class ExactListCells(unittest.TestCase):
    """Break-it cells for the exact lists (#9365 PR-1, ruling b29 8f7ba133): each mutation is red."""

    LISTED = "scripts/bench/listed_9365.py"
    LISTED_SOURCE = "import sys\n\n\ndef f(a, b):\n    print(a)\n    sys.stderr.write(b)\n"
    WF_LINE = 'echo "::warning::$name"'

    def tree(self, cell, files):
        base = REPO / ".local-runs" / "stream-allowlist-9365" / "exact" / cell
        if base.exists():
            shutil.rmtree(base)
        for rel, source in files.items():
            path = base / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
        return base

    def test_the_unmutated_listed_copy_is_clean_9365(self):
        base = self.tree("clean", {self.LISTED: self.LISTED_SOURCE})
        rows = {self.LISTED: 2}
        self.assertEqual(unrouted_row_problems(base / "scripts", rows), [])
        self.assertEqual(tree_findings(base / "scripts", rows), [])

    def test_an_added_site_in_a_listed_file_is_red_9365(self):
        base = self.tree("added", {self.LISTED: self.LISTED_SOURCE + "    print(b)\n"})
        self.assertEqual(unrouted_row_problems(base / "scripts", {self.LISTED: 2}),
                         ["%s: 3 un-routed sites, the row says 2 (a new un-routed site)" % self.LISTED])

    def test_a_removed_site_without_lowering_the_row_is_red_9365(self):
        base = self.tree("removed", {self.LISTED: self.LISTED_SOURCE.replace("    print(a)\n", "")})
        self.assertEqual(unrouted_row_problems(base / "scripts", {self.LISTED: 2}),
                         ["%s: 1 un-routed sites, the row says 2 (lower the row in the same commit)" % self.LISTED])

    def test_a_row_for_a_clean_or_missing_file_is_red_9365(self):
        base = self.tree("zero", {self.LISTED: "x = 1\n"})
        rows = {self.LISTED: 2, "scripts/bench/gone_9365.py": 1}
        self.assertEqual(unrouted_row_problems(base / "scripts", rows),
                         ["scripts/bench/gone_9365.py: row for a missing file",
                          "%s: row for a file with no un-routed site" % self.LISTED])

    def test_a_new_unlisted_file_is_red_at_once_9365(self):
        base = self.tree("unlisted", {self.LISTED: self.LISTED_SOURCE,
                                      "scripts/bench/new_9365.py": "print(value)\n"})
        rows = {self.LISTED: 2}
        self.assertEqual(tree_findings(base / "scripts", rows), ["scripts/bench/new_9365.py:1: print"])
        self.assertEqual(unrouted_row_problems(base / "scripts", rows), [])

    def test_a_stale_yaml_row_is_red_9365(self):
        base = self.tree("stale", {"x.yml": "    run: |\n      %s\n" % self.WF_LINE})
        rows = {("x.yml", self.WF_LINE): (1, YAML_PR4_REASON),
                ("x.yml", 'echo "::error::$gone"'): (1, YAML_PR4_REASON)}
        self.assertEqual(yaml_echo_findings(base, rows), [])
        self.assertEqual(yaml_exempt_problems(base, rows),
                         ["x.yml: 'echo \"::error::$gone\"': row for a line that is gone (stale)"])

    def test_a_duplicated_yaml_line_is_red_9365(self):
        base = self.tree("dup", {"x.yml": "    run: |\n      %s\n      %s\n" % (self.WF_LINE, self.WF_LINE)})
        rows = {("x.yml", self.WF_LINE): (1, YAML_PR4_REASON)}
        self.assertEqual(yaml_exempt_problems(base, rows),
                         ["x.yml: 'echo \"::warning::$name\"': 2 such lines, the row says 1"])
        self.assertEqual(yaml_exempt_problems(base, {("x.yml", self.WF_LINE): (2, YAML_PR4_REASON)}), [])

    def test_a_line_separator_does_not_split_a_workflow_line_9365(self):
        # YAML and the runner end a line only at \r\n, \r or \n. str.splitlines() also splits at \u2028, so one
        # physical line holding a listed line twice would pass as two copies of the listed line.
        base = self.tree("u2028", {"x.yml": "    run: |\n      %s\u2028%s\n" % (self.WF_LINE, self.WF_LINE)})
        rows = {("x.yml", self.WF_LINE): (2, YAML_PR4_REASON)}
        self.assertEqual(yaml_echo_findings(base, rows), ["x.yml:2: workflow-command echo with a shell value"])
        self.assertEqual(yaml_exempt_problems(base, rows),
                         ["x.yml: 'echo \"::warning::$name\"': row for a line that is gone (stale)"])


class BypassCells(unittest.TestCase):
    """Table: each bypass form (tracker list) and each sibling form is named, with the exact form text."""

    def assert_form(self, source, form):
        rel = "scripts/ci/new_tool_9365.py"
        found = sink_findings(rel, source)
        self.assertTrue(found, source)
        self.assertIn(form, [line.split(": ", 1)[1] for line in found], found)

    def test_each_bypass_form_is_refused_9365(self):
        for label, (source, form) in BYPASS_FORMS.items():
            with self.subTest(form=label):
                self.assert_form(source, form)

    def test_each_sibling_form_is_refused_9365(self):
        for label, (source, form) in SIBLING_FORMS.items():
            with self.subTest(form=label):
                self.assert_form(source, form)

    def test_routed_and_harmless_forms_stay_allowed_9365(self):
        for label, source in ALLOWED_FORMS.items():
            with self.subTest(form=label):
                self.assertEqual(sink_findings("scripts/ci/new_tool_9365.py", source), [])

    def test_exact_finding_line_9365(self):
        self.assertEqual(sink_findings("scripts/x/new_9365.py", "import sys\n\nsys.stderr.write(v)\n"),
                         ["scripts/x/new_9365.py:3: sys.stderr"])

    def test_a_new_file_anywhere_under_scripts_is_covered_9365(self):
        base = REPO / ".local-runs" / "stream-allowlist-9365"
        base.mkdir(parents=True, exist_ok=True)
        tree = base / "scripts" / "deep" / "er"
        tree.mkdir(parents=True, exist_ok=True)
        planted = tree / "planted_9365.py"
        planted.write_text("print('::error::' + value)\n", encoding="utf-8")
        try:
            rels = covered_files(base / "scripts")
        finally:
            planted.unlink()
        self.assertIn(".local-runs/stream-allowlist-9365/scripts/deep/er/planted_9365.py", rels)

    def test_a_100k_source_is_scanned_within_the_bound_9365(self):
        source = "value = 'x'\n" + "wa.out('line', value)\n" * (HUGE_VALUE_CHARS // 20)
        start = time.monotonic()
        self.assertEqual(sink_findings("scripts/ci/huge_9365.py", source), [])
        self.assertLess(time.monotonic() - start, HUGE_WALL_CLOCK_SECS * 4)

    def test_yaml_echo_rule_flags_a_reintroduced_expression_9365(self):
        base = REPO / ".local-runs" / "stream-allowlist-9365" / "wf"
        base.mkdir(parents=True, exist_ok=True)
        (base / "x.yml").write_text('    run: |\n      echo "::error::bad ref ${{ github.head_ref }}"\n'
                                    '      echo "::notice::constant text"\n'
                                    '      if x; then echo "::warning::$name"; fi\n', encoding="utf-8")
        self.assertEqual(yaml_echo_findings(base), ["x.yml:2: ${{ }} in a workflow-command echo",
                                                    "x.yml:4: workflow-command echo with a shell value"])


class Emitters(unittest.TestCase):
    """The shared emitters: byte-equal for benign text, neutralised for every hostile value, bounded."""

    @classmethod
    def setUpClass(cls):
        cls.wa = wa_module()

    def emit(self, *parts, **kwargs):
        stream = io.StringIO()
        self.wa.emit_to(stream, *parts, **kwargs)
        return stream.getvalue()

    def test_benign_text_is_byte_equal_to_print_9365(self):
        for label, text in BENIGN_TEXTS.items():
            for kwargs in ({}, {"end": ""}, {"sep": ", "}, {"end": "\n\n"}):
                with self.subTest(text=label, kwargs=kwargs):
                    want = io.StringIO()
                    print(text, 7, **kwargs, file=want)  # the oracle: what print wrote before routing
                    self.assertEqual(self.emit(text, 7, **kwargs), want.getvalue())

    def test_out_and_err_write_the_real_streams_at_call_time_9365(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.wa.out("a", 1)
            self.wa.err("b", end="")
        self.assertEqual((out.getvalue(), err.getvalue()), ("a 1\n", "b"))

    def test_no_hostile_value_reaches_a_command_9365(self):
        for label, value in HOSTILE_VALUES.items():
            for prefix in ("", "x ", "#", "##", ":", "  "):
                for kwargs in ({}, {"end": ""}, {"sep": value}, {"end": value}):
                    with self.subTest(value=label, prefix=prefix, kwargs=kwargs):
                        self.assertEqual(command_lines(self.emit(prefix + value, "tail", **kwargs)), [])

    def test_a_command_split_across_calls_is_neutralised_9365(self):
        pieces = [(":", ":error::x"), ("#", "#[error]x"), ("##", "[error]x"), ("  :", ":error::x"),
                  ("", "::error::x"), ("a\n", "::error::x"), (" ", " ::warning::y")]
        for first, second in pieces:
            with self.subTest(pieces=(first, second)):
                stream = io.StringIO()
                self.wa.emit_to(stream, first, end="")
                self.wa.emit_to(stream, second)
                self.assertEqual(command_lines(stream.getvalue()), [])

    def test_a_command_line_from_annotation_is_written_as_a_command_9365(self):
        line = self.wa.annotation("error", "bad\n::error::x", title="t")
        self.assertEqual(self.emit(line), line + "\n")
        self.assertEqual(command_lines(self.emit(line)), [line])
        self.assertEqual(self.emit(self.wa.end_group_line()), "::endgroup::\n")
        self.assertEqual(command_lines(self.emit(str(line) + "")), [])  # a plain copy is not trusted
        self.assertEqual(command_lines(self.emit(line, "x")), [])
        self.assertEqual(command_lines(self.emit("::error::forged")), [])

    def test_exact_neutralised_bytes_9365(self):
        self.assertEqual(self.emit("::error::x"), "\\x3a:error::x\n")
        self.assertEqual(self.emit("a\n::error::x"), "a\n\\x3a:error::x\n")
        self.assertEqual(self.emit("a\r::error::x"), "a\\x0d::error::x\n")
        self.assertEqual(self.emit("x ##[error]y"), "x ##\\x5berror]y\n")

    def test_generated_values_never_reach_a_command_9365(self):
        rng = random.Random(GENERATED_SEED)
        for case in range(GENERATED_CASES):
            value = "".join(rng.choice(GENERATED_ALPHABET) for _ in range(rng.randint(0, 24)))
            end = rng.choice(("", "\n", value))
            with self.subTest(case=case, value=value):
                stream = io.StringIO()
                self.wa.emit_to(stream, value, end=end)
                self.wa.emit_to(stream, value[::-1], sep=value)
                self.assertEqual(command_lines(stream.getvalue()), [])

    def test_a_100k_value_is_neutralised_within_the_bound_9365(self):
        value = ("::error::x\n##[y\r%0A" * (HUGE_VALUE_CHARS // 18 + 1))[:HUGE_VALUE_CHARS]
        start = time.monotonic()
        text = self.emit(value)
        self.assertLess(time.monotonic() - start, HUGE_WALL_CLOCK_SECS)
        self.assertEqual(command_lines(text), [])

    def test_bad_stream_arguments_raise_9365(self):
        with self.assertRaises(TypeError):
            self.wa.emit_to(io.StringIO(), "x", end=3)
        with self.assertRaises(TypeError):
            self.wa.emit_to(io.StringIO(), "x", sep=None.__class__)


class Cli(unittest.TestCase):
    """``python3 scripts/ci/workflow_annotation.py <command> ...``: the YAML entry point."""

    def run_cli(self, *argv):
        proc = subprocess.run([sys.executable, "-I", str(SHARED_MODULE_PATH), *argv], capture_output=True,
                              text=True, timeout=SUBPROCESS_TIMEOUT_SECS, check=False)
        return proc.returncode, proc.stdout, proc.stderr

    def test_each_command_prints_one_escaped_line_9365(self):
        cases = {
            ("error", "--message", "bad $x"): "::error::bad $x\n",
            ("warning", "--title", "t:1", "--message", "m"): "::warning title=t\\x3a1::m\n",
            ("notice", "--message", "a\n::error::b"): "::notice::a\\x0a\\x3a:error\\x3a:b\n",
            ("group", "--message", "g ##[x"): "::group::g \\x23\\x23\\x5bx\n",
            ("endgroup",): "::endgroup::\n",
            ("log", "--message", "::error::x"): "\\x3a:error::x\n",
            ("error", "--file", "a,b", "--line", "3", "--message", "m"): "::error file=a\\x2cb,line=3::m\n",
        }
        for argv, want in cases.items():
            with self.subTest(argv=argv):
                self.assertEqual(self.run_cli(*argv), (0, want, ""))

    def test_bad_arguments_exit_2_9365(self):
        rc, out, err = self.run_cli("bogus", "--message", "x")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("invalid choice: 'bogus'", err)
        rc, out, _ = self.run_cli("error")
        self.assertEqual((rc, out), (2, ""))



AGE_HELPER_REL = "scripts/ci/ensure-age-extension.py"
AGE_HELPER_LOAD_REFUSED = 3
AGE_HELPER_REFUSAL = ("ensure-age-extension: refused: shared module workflow_annotation.py next to the script cannot be "
                      "loaded (FileNotFoundError)\n")
AGE_HELPER_ANNOTATION = ("::error title=ensure-age-extension refused::ensure-age-extension: refused: shared module "
                         "workflow_annotation.py next to the script cannot be loaded\n")
SCRATCH_ENV = "TMPDIR"


class DeferredHyphenLoad(unittest.TestCase):
    """ensure-age-extension.py is exec'd as a module by tier_cred_preflight (its name has a hyphen), so its load is
    deferred: importing prints nothing whatever the shared module's state; main refuses before any work (#9365)."""

    def fixture(self, with_shared):
        base = Path(tempfile.mkdtemp(prefix="age9365-", dir=os.environ.get(SCRATCH_ENV)))
        self.addCleanup(shutil.rmtree, base, True)
        (base / "scripts" / "ci").mkdir(parents=True)
        (base / AGE_HELPER_REL).write_bytes((REPO / AGE_HELPER_REL).read_bytes())
        if with_shared:
            (base / SHARED_MODULE_REL).write_bytes(SHARED_MODULE_PATH.read_bytes())
        return base

    def test_exec_as_a_module_prints_nothing_with_or_without_the_shared_module_9365(self):
        for with_shared in (True, False):
            with self.subTest(with_shared=with_shared):
                base = self.fixture(with_shared)
                with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                    module = load_module(base / AGE_HELPER_REL, "ensure_age_extension_9365_%d" % with_shared)
                self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))
                self.assertTrue(callable(module.read_url))
                with self.assertRaises(module.SharedModuleNotLoadedError) as raised:
                    module.wa.err("x")
                self.assertIn("(wanted err)", str(raised.exception))

    def test_running_without_the_shared_module_refuses_before_any_work_9365(self):
        base = self.fixture(False)
        proc = subprocess.run([sys.executable, "-I", str(base / AGE_HELPER_REL), "--url-file", str(base / "absent")],
                              capture_output=True, text=True, cwd=str(base), timeout=SUBPROCESS_TIMEOUT_SECS,
                              check=False)
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr),
                         (AGE_HELPER_LOAD_REFUSED, AGE_HELPER_ANNOTATION, AGE_HELPER_REFUSAL))

if __name__ == "__main__":
    unittest.main()
