# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Invariant for #9680: the release smoke build and the cargo-audit gate leave the
serial path of `Check (ubuntu-latest,sqlite)` without weakening any required context.

The invariant holds for EVERY job of `.github/workflows/ci.yml`:
  1. the job ids, job names, `needs` edges and matrix legs, and so the required
     context names they expand to, are the hand-written sets below;
  2. every gate step (a step that can fail its job) sits in the hand-written job,
     and the moved steps sit in a required job, under the same guards;
  3. no gate step is dropped or gains a condition;
  4. a consumer of a downloaded artifact verifies the commit sha and fails closed;
     the ci-gate aggregator treats a skipped, failed or cancelled need as red.
cargo-audit comes only from `cargo install --locked` at the #3138 pin (the base
bbede4b2 form), once, in the job that runs it; no step downloads, extracts or
checksums a prebuilt cargo-audit (ruling 7fd3cd38).

Every expected set is written by hand (rule d54c4b0e); nothing is derived from
the workflow under test. CI_9680_WORKFLOW and CI_9680_GATE point the test at a
copy of ci.yml and of scripts/ci/impact/gate.py (the mutant runs use them).

Run: python3 -I -m unittest discover -s scripts/ci/tests -p test_ci_release_split_9680.py
"""
import importlib.util
import os
import re
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import workflow_text  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
WORKFLOW_ENV = "CI_9680_WORKFLOW"
GATE_ENV = "CI_9680_GATE"
CI_YML = Path(os.environ.get(WORKFLOW_ENV) or REPO / ".github" / "workflows" / "ci.yml")
GATE_PY = Path(os.environ.get(GATE_ENV) or REPO / "scripts" / "ci" / "impact" / "gate.py")
LIVE_PIN = REPO / "scripts" / "qc-allowlists" / "required-contexts-live-pin.txt"

CARGO_SKIP_GUARD = "needs.classify.outputs.cargo_skip != 'true'"
ONCE_GUARD = CARGO_SKIP_GUARD + " && matrix.once"

# 1. Job ids and their `name:` values.
EXPECTED_JOB_NAMES = {
    "select": "Impact selection",
    "classify": "Classify changes",
    "lint": "Lint (fmt + clippy)",
    "build-script-vetting": "Build-script custom-build ledger gate (#2635)",
    "actionlint": "actionlint (workflow-injection guard)",
    "msrv": "MSRV (Rust 1.98)",
    "check": "Check (${{ matrix.leg }})",
    "postgres-feature": "Postgres feature gate",
    "mobile-cross-compile": "Cross-compile (${{ matrix.target }})",
    "sal-feature": "SAL-only feature gate",
    "vectorlite-feature": "vectorlite feature gate",
    "dockerfile-validate": "Dockerfile build (no push)",
    "ci-gate": "ci-gate",
}

CLASSIFY_SELECT = ("classify", "select")
EXPECTED_NEEDS = {
    "select": (),
    "classify": (),
    "lint": CLASSIFY_SELECT,
    "build-script-vetting": (),
    "actionlint": CLASSIFY_SELECT,
    "msrv": CLASSIFY_SELECT,
    "check": ("classify",),
    "postgres-feature": CLASSIFY_SELECT,
    "mobile-cross-compile": ("classify",),
    "sal-feature": CLASSIFY_SELECT,
    "vectorlite-feature": CLASSIFY_SELECT,
    "dockerfile-validate": CLASSIFY_SELECT,
    "ci-gate": ("select", "classify", "build-script-vetting", "check", "mobile-cross-compile"),
}

# Jobs whose check-runs are required contexts, and the jobs that are not.
REQUIRED_JOBS = frozenset(EXPECTED_JOB_NAMES) - {"select", "ci-gate"}
# Matrix jobs: a job-level `if:` is evaluated before expansion and would hide
# the expanded required names (#2494), so these two never carry one.
MATRIX_JOBS = {"check": "leg", "mobile-cross-compile": "target"}

EXPECTED_CHECK_LEGS = (
    {"leg": "ubuntu-latest,sqlite", "runner": '["ubuntu-latest"]'},
    {"leg": "linux-fed,enterprise-fed", "runner": '["self-hosted","linux-fed"]'},
    {"leg": "macos-fed,sqlite"},
    {"leg": "macos-fed,enterprise-fed"},
)
EXPECTED_MOBILE_TARGETS = (
    {"target": "aarch64-apple-ios", "os": "macos-latest"},
    {"target": "aarch64-linux-android", "os": "ubuntu-latest", "once": "true"},
)
# The one matrix entry that carries the once-per-run extras.
ONCE_HOLDER = ("mobile-cross-compile", "aarch64-linux-android")

EXPECTED_CI_CONTEXTS = frozenset({
    "Impact selection",
    "Classify changes",
    "Lint (fmt + clippy)",
    "Build-script custom-build ledger gate (#2635)",
    "actionlint (workflow-injection guard)",
    "MSRV (Rust 1.98)",
    "Check (ubuntu-latest,sqlite)",
    "Check (linux-fed,enterprise-fed)",
    "Check (macos-fed,sqlite)",
    "Check (macos-fed,enterprise-fed)",
    "Postgres feature gate",
    "Cross-compile (aarch64-apple-ios)",
    "Cross-compile (aarch64-linux-android)",
    "SAL-only feature gate",
    "vectorlite feature gate",
    "Dockerfile build (no push)",
    "ci-gate",
})
# Contexts of this workflow that branch protection requires (live pin).
EXPECTED_REQUIRED_CI_CONTEXTS = EXPECTED_CI_CONTEXTS - {"Impact selection", "ci-gate"}

# 2./3. Gate steps: name -> the job that must hold it.
SECURITY_AUDIT = "Security audit"
RELEASE_SMOKE = "Build release (once leg — release-profile smoke)"
RUN_TESTS = "Run tests (impact-aware)"
EXPECTED_GATE_STEPS = {
    "Select jobs": "select",
    "Test impact selector security fallbacks": "classify",
    "Workflow concurrency invariants (#6340)": "classify",
    "Shard partition and wiring unit tests (#6344)": "classify",
    "AGE self-heal helper unit test (#6161)": "classify",
    "Target sweep unit tests (#7160)": "classify",
    "Check formatting": "lint",
    "Clippy": "lint",
    "Clippy (all targets, sal — cfg-stripped doc-lint class)": "lint",
    "Verify every custom-build package is ledgered": "build-script-vetting",
    "Self-test (prove the gate is load-bearing)": "build-script-vetting",
    "actionlint": "actionlint",
    "cargo check on MSRV": "msrv",
    "Fork-PR refusal (self-hosted legs never run fork code)": "check",
    "Load gate (#6795)": "check",
    RUN_TESTS: "check",
    "Run the pg_isolated_binary live cells (enterprise-fed legs only)": "check",
    "Clippy (sal-postgres feature, lib + tests)": "postgres-feature",
    "cargo check (--lib --features sqlite-bundled)": "mobile-cross-compile",
    SECURITY_AUDIT: "mobile-cross-compile",
    RELEASE_SMOKE: "mobile-cross-compile",
    "Clippy (sal feature)": "sal-feature",
    "Build release (sal feature)": "sal-feature",
    "Run lib tests (sal feature)": "sal-feature",
    "Clippy (vectorlite feature, all targets)": "vectorlite-feature",
    "Run vectorlite no-native-lib seam tests (#1860)": "vectorlite-feature",
    "Run config-precedence under vectorlite (#2256 feature-gated pin)": "vectorlite-feature",
    "Build Docker image (validation only)": "dockerfile-validate",
    "Smoke-test the built image": "dockerfile-validate",
    "Fold job results (base gate)": "ci-gate",
    "Fold job results (bootstrap, PR-tree gate)": "ci-gate",
    "Fold job results (branch tip gate)": "ci-gate",
    "Fail the gate (base gate unreadable)": "ci-gate",
}
# Exact guards of the steps this change moves or depends on.
EXPECTED_STEP_IFS = {
    ("check", RUN_TESTS): CARGO_SKIP_GUARD,
    ("mobile-cross-compile", "cargo check (--lib --features sqlite-bundled)"): CARGO_SKIP_GUARD,
    ("mobile-cross-compile", SECURITY_AUDIT): ONCE_GUARD,
    ("mobile-cross-compile", RELEASE_SMOKE): ONCE_GUARD,
}
RELEASE_SMOKE_RUN = "cargo build --release"
SETUP_PYTHON_USES = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5"

# The audit gate lines the Security audit step runs after the install (base form).
AUDIT_GATE_LINES = (
    "python3 -m unittest discover -s scripts/ci/tests -p test_check_cargo_audit_8615.py",
    "python3 scripts/ci/check_cargo_audit.py",
)

DOWNLOAD_ARTIFACT_RE = re.compile(r"actions/download-artifact@")
SHA_COMPARE_RE = re.compile(r"\$\{\{\s*github\.sha\s*\}\}|\$GITHUB_SHA|\$\{GITHUB_SHA\}")

JOB_KEY_RE = re.compile(r"^    ([A-Za-z0-9_-]+):\s*(.*)$")
NEEDS_ITEM_RE = re.compile(r"^      - ([A-Za-z0-9_-]+)\s*$")
INCLUDE_START_RE = re.compile(r"^          - ([A-Za-z0-9_-]+):\s*(.*)$")
INCLUDE_KEY_RE = re.compile(r"^            ([A-Za-z0-9_-]+):\s*(.*)$")
INCLUDE_LINE = "        include:"


def unquote(value):
    value = (value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def job_blocks(text):
    """Return {job id: [lines]} for the top-level `jobs:` mapping."""
    blocks = {}
    current = None
    in_jobs = False
    for line in text.split("\n"):
        if line == "jobs:":
            in_jobs = True
            continue
        if in_jobs and line and not line.startswith(" ") and not line.startswith("#"):
            in_jobs = False
        if not in_jobs:
            continue
        match = workflow_text.JOB_ID_RE.match(line)
        if match:
            current = match.group(1)
            blocks[current] = []
            continue
        if current is not None:
            blocks[current].append(line)
    return blocks


def job_meta(lines):
    """Return {"name", "if", "needs", "timeout-minutes", "continue-on-error"} of one job block."""
    meta = {"name": None, "if": None, "needs": (), "timeout-minutes": None,
            "continue-on-error": None}
    collecting_needs = False
    needs = []
    for line in lines:
        if collecting_needs:
            item = NEEDS_ITEM_RE.match(line)
            if item:
                needs.append(item.group(1))
                continue
            collecting_needs = False
        key = JOB_KEY_RE.match(line)
        if not key:
            continue
        name, value = key.group(1), key.group(2).strip()
        if name == "name":
            meta["name"] = unquote(value)
        elif name in ("if", "timeout-minutes", "continue-on-error"):
            meta[name] = value
        elif name == "needs":
            if not value:
                collecting_needs = True
            elif value.startswith("["):
                needs = [v.strip() for v in value.strip("[]").split(",") if v.strip()]
            else:
                needs = [value]
    meta["needs"] = tuple(needs)
    return meta


def matrix_include(lines):
    """Return the `strategy.matrix.include` entries of one job block as dicts."""
    entries = []
    inside = False
    for line in lines:
        if line == INCLUDE_LINE:
            inside = True
            continue
        if not inside:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        start = INCLUDE_START_RE.match(line)
        if start:
            entries.append({start.group(1): unquote(start.group(2))})
            continue
        key = INCLUDE_KEY_RE.match(line)
        if key and entries:
            entries[-1][key.group(1)] = unquote(key.group(2))
            continue
        break
    return entries


STRATEGY_LINE = "    strategy:"
STRATEGY_KEY_RE = re.compile(r"^      ([A-Za-z0-9_-]+):\s*(.*)$")
MATRIX_KEY_RE = re.compile(r"^        ([A-Za-z0-9_-]+):\s*(.*)$")
# An `exclude` key at any indent, block or `- exclude:` form, outside a comment.
EXCLUDE_RE = re.compile(r"^\s*(?:-\s+)?exclude\s*:")


def strategy_shape(lines):
    """Return ({strategy key: raw value}, [matrix keys]) of one job block (#9698).

    A flow-style `matrix: {...}` shows up as a non-empty raw `matrix` value.
    """
    strategy, matrix_keys = {}, []
    inside = in_matrix = False
    for line in lines:
        if line == STRATEGY_LINE:
            inside = True
            continue
        if not inside:
            continue
        if JOB_KEY_RE.match(line):
            break
        key = STRATEGY_KEY_RE.match(line)
        if key:
            strategy[key.group(1)] = key.group(2).strip()
            in_matrix = key.group(1) == "matrix"
            continue
        matrix_key = MATRIX_KEY_RE.match(line)
        if in_matrix and matrix_key:
            matrix_keys.append(matrix_key.group(1))
    return strategy, matrix_keys


def scalar_int(raw):
    """The integer of a one-line YAML scalar (a trailing comment dropped), else None."""
    text = (raw or "").split("#", 1)[0].strip()
    return int(text) if text.isdigit() else None


def expand_names(name, axis, entries):
    token = "${{ matrix.%s }}" % axis
    return {name.replace(token, entry[axis]) for entry in entries}


def load_gate(path):
    spec = importlib.util.spec_from_file_location("gate_9680_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unverified_artifact_consumers(text, path=CI_YML):
    """Jobs that download an artifact without a later step that compares the sha and fails."""
    bad = []
    blocks = job_blocks(text)
    for job, lines in blocks.items():
        if not any(DOWNLOAD_ARTIFACT_RE.search(l) for l in lines):
            continue
        steps = read_steps_text("\n".join(["jobs:", "  %s:" % job] + lines), job)
        seen_download = False
        verified = False
        for step in steps:
            if step["uses"] and DOWNLOAD_ARTIFACT_RE.search(step["uses"]):
                seen_download = True
                verified = False
                continue
            run = step["run"] or ""
            if seen_download and SHA_COMPARE_RE.search(run) and "exit 1" in run:
                verified = True
        if not verified:
            bad.append(job)
    return bad


def read_steps_text(text, job):
    """workflow_text.read_steps on in-memory text (it reads a path)."""
    scratch = Path(os.environ.get("TMPDIR_9680") or REPO / ".local-runs")
    scratch.mkdir(parents=True, exist_ok=True)
    probe = scratch / ("steps-%d-%s.yml" % (os.getpid(), job))
    try:
        probe.write_text(text, encoding="utf-8")
        return workflow_text.read_steps(probe, job)
    finally:
        probe.unlink(missing_ok=True)


class Workflow:
    def __init__(self, path):
        self.path = path
        self.text = path.read_text(encoding="utf-8")
        self.blocks = job_blocks(self.text)
        self.meta = {job: job_meta(lines) for job, lines in self.blocks.items()}
        self.steps = {job: workflow_text.read_steps(path, job) for job in self.blocks}

    def step(self, job, name):
        found = [s for s in self.steps.get(job, []) if s["name"] == name]
        return found[0] if len(found) == 1 else None

    def index(self, job, name):
        names = [s["name"] for s in self.steps.get(job, [])]
        return names.index(name) if name in names else -1


class Jobs9680(unittest.TestCase):
    """Rule 1: the job set, names, needs, legs and required names are unchanged."""

    @classmethod
    def setUpClass(cls):
        cls.wf = Workflow(CI_YML)

    def test_job_ids_and_names(self):
        names = {job: meta["name"] for job, meta in self.wf.meta.items()}
        self.assertEqual(names, EXPECTED_JOB_NAMES)

    def test_needs_edges(self):
        needs = {job: meta["needs"] for job, meta in self.wf.meta.items()}
        self.assertEqual(needs, EXPECTED_NEEDS)

    def test_matrix_jobs_have_no_job_level_if(self):
        for job in MATRIX_JOBS:
            self.assertIsNone(self.wf.meta[job]["if"], job)
        self.assertEqual(self.wf.meta["ci-gate"]["if"], "always()")

    def test_matrix_legs(self):
        check = matrix_include(self.wf.blocks["check"])
        self.assertEqual([e["leg"] for e in check], [e["leg"] for e in EXPECTED_CHECK_LEGS])
        for got, want in zip(check, EXPECTED_CHECK_LEGS):
            for key, value in want.items():
                self.assertEqual(got.get(key), value, (got["leg"], key))
            self.assertNotIn("once", got, got["leg"])
        mobile = matrix_include(self.wf.blocks["mobile-cross-compile"])
        self.assertEqual(mobile, [dict(e) for e in EXPECTED_MOBILE_TARGETS])

    def test_required_context_names(self):
        names = set()
        for job, meta in self.wf.meta.items():
            axis = MATRIX_JOBS.get(job)
            if axis:
                names |= expand_names(meta["name"], axis, matrix_include(self.wf.blocks[job]))
            else:
                names.add(meta["name"])
        self.assertEqual(names, EXPECTED_CI_CONTEXTS)
        pinned = {l.strip() for l in LIVE_PIN.read_text(encoding="utf-8").splitlines()
                  if l.strip() and not l.startswith("#")}
        self.assertEqual(names & pinned, EXPECTED_REQUIRED_CI_CONTEXTS)
        required_names = set()
        for job in REQUIRED_JOBS:
            axis = MATRIX_JOBS.get(job)
            meta = self.wf.meta[job]
            if axis:
                required_names |= expand_names(meta["name"], axis, matrix_include(self.wf.blocks[job]))
            else:
                required_names.add(meta["name"])
        self.assertEqual(required_names, EXPECTED_REQUIRED_CI_CONTEXTS)


class Steps9680(unittest.TestCase):
    """Rules 2 and 3: every gate step is where it must be, under the same guard."""

    @classmethod
    def setUpClass(cls):
        cls.wf = Workflow(CI_YML)

    def test_every_gate_step_in_its_job(self):
        where = {}
        for job, steps in self.wf.steps.items():
            for step in steps:
                if step["name"] in EXPECTED_GATE_STEPS:
                    where.setdefault(step["name"], []).append(job)
        self.assertEqual(where, {name: [job] for name, job in EXPECTED_GATE_STEPS.items()})

    def test_moved_steps_live_in_a_required_job(self):
        for name in (SECURITY_AUDIT, RELEASE_SMOKE):
            self.assertIn(EXPECTED_GATE_STEPS[name], REQUIRED_JOBS, name)

    def test_step_guards(self):
        for (job, name), want in EXPECTED_STEP_IFS.items():
            step = self.wf.step(job, name)
            self.assertIsNotNone(step, (job, name))
            self.assertEqual(step["if"], want, (job, name))

    def test_once_flag_only_on_the_android_leg(self):
        holders = []
        for job, axis in MATRIX_JOBS.items():
            for entry in matrix_include(self.wf.blocks[job]):
                if entry.get("once") == "true":
                    holders.append((job, entry[axis]))
        self.assertEqual(holders, [ONCE_HOLDER])
        android = [e for e in EXPECTED_MOBILE_TARGETS if e["target"] == ONCE_HOLDER[1]][0]
        self.assertEqual(android["os"], "ubuntu-latest")

    def test_release_smoke_runs_once_after_the_audit(self):
        job = "mobile-cross-compile"
        smoke = self.wf.step(job, RELEASE_SMOKE)
        self.assertIsNotNone(smoke)
        self.assertEqual((smoke["run"] or "").strip(), RELEASE_SMOKE_RUN)
        self.assertGreaterEqual(self.wf.index(job, SECURITY_AUDIT), 0)
        self.assertLess(self.wf.index(job, SECURITY_AUDIT), self.wf.index(job, RELEASE_SMOKE))
        # One binary, the same fat-LTO link the ubuntu-latest Bench / Batman /
        # token-budget jobs run without swap: no swap step (and no new
        # tainted-job-boundary row) in this job.
        for step in self.wf.steps[job]:
            self.assertNotIn("swapon", step["run"] or "", step["name"])
        exact = [(j, s["name"]) for j, steps in self.wf.steps.items() for s in steps
                 if (s["run"] or "").strip() == RELEASE_SMOKE_RUN]
        self.assertEqual(exact, [(job, RELEASE_SMOKE)])

    def test_check_leg_no_longer_runs_audit_or_release(self):
        for step in self.wf.steps["check"]:
            run = step["run"] or ""
            self.assertNotIn("cargo audit", run, step["name"])
            self.assertNotIn("check_cargo_audit.py", run, step["name"])
            self.assertNotEqual(run.strip(), RELEASE_SMOKE_RUN, step["name"])
            self.assertNotIn("matrix.once", step["if"] or "", step["name"])

    def test_audit_has_python_before_it(self):
        job = "mobile-cross-compile"
        setup = [i for i, s in enumerate(self.wf.steps[job]) if s["uses"] == SETUP_PYTHON_USES]
        self.assertEqual(len(setup), 1)
        self.assertEqual(self.wf.steps[job][setup[0]]["if"], ONCE_GUARD)
        self.assertLess(setup[0], self.wf.index(job, SECURITY_AUDIT))


# ---------------------------------------------------------------------------
# The properties of the old home of the moved work move with it (#9698, #9699,
# #9700): the moved steps and their job (a) cannot report green after a failure,
# (b) are bounded by a job timeout, (c) are cached the way the PR body says, and
# pull_request runs cannot save that cache.
# ---------------------------------------------------------------------------
MOVED_JOB = "mobile-cross-compile"
MOVED_STEPS = (SECURITY_AUDIT, RELEASE_SMOKE)
RUST_CACHE_USES_PREFIX = "Swatinem/rust-cache@"
# (c) #9700: the key is rotated once, so the entry saved before the move (no
# cargo-audit, no target/release) is not an exact match that never re-saves;
# the save-if is the #3089 form of the check and postgres-feature cache steps.
MOBILE_CACHE_KEY = "mobile-${{ matrix.target }}-audit-release"
PUSH_ONLY_SAVE_IF = "${{ github.event_name == 'push' }}"
EXPECTED_MOBILE_CACHE_WITH = {"key": MOBILE_CACHE_KEY, "save-if": PUSH_ONLY_SAVE_IF}
# (b) #9699: the longest measured time of each piece of work the job now holds
# (push runs of ci.yml on release/v1.0.0, 2026-11-20). The job timeout must leave
# the 20 % margin the check-leg cap rule asks for (ci.yml `timeout: 95` comment)
# and stay below twice the sum, so a hang still ends near the honest worst case.
MOVED_WORK_MEASURED_MAX_S = {
    "android leg before the move (run 43809244411)": 177,
    "Security audit, cold cargo-audit install (run 43715405044)": 459,
    "release smoke, cold (run 43715405044)": 1319,
}
TIMEOUT_FLOOR_FACTOR = 1.2
TIMEOUT_CEILING_FACTOR = 2.0
SECS_PER_MINUTE = 60
# (a) #9698: the only steps of the workflow that may carry continue-on-error.
# The select job widens the run when the selector is unusable (ci.yml, the
# comment above `select:`); nothing else may turn a failed step green.
CONTINUE_ON_ERROR_BY_DESIGN = {
    ("select", "Build impact index"): "true",
    ("select", "Select jobs"): "true",
}
FAIL_OPEN_RUN_RE = re.compile(r"\|\|\s*(?:true|:)(?:\s|;|$)|\bset\s+\+e\b")
# #9687: the classify unit-test steps run on every event, unconditionally.
CLASSIFY_JOB = "classify"


class MovedWorkBounds9680(unittest.TestCase):
    """The moved steps and their job fail closed, are time-bounded and push-cached."""

    @classmethod
    def setUpClass(cls):
        cls.wf = Workflow(CI_YML)

    def test_mobile_cache_saves_only_on_push_under_the_rotated_key(self):
        caches = [s for s in self.wf.steps[MOVED_JOB]
                  if (s["uses"] or "").startswith(RUST_CACHE_USES_PREFIX)]
        self.assertEqual(len(caches), 1, "%s: expected one rust-cache step" % MOVED_JOB)
        cache = caches[0]
        self.assertEqual(cache["if"], CARGO_SKIP_GUARD, "%s rust-cache guard" % MOVED_JOB)
        self.assertEqual(cache["with"], EXPECTED_MOBILE_CACHE_WITH,
                         "%s rust-cache must use the rotated key and save only on push "
                         "(#9700)" % MOVED_JOB)

    def test_job_timeout_bounds_the_moved_work(self):
        raw = self.wf.meta[MOVED_JOB]["timeout-minutes"]
        minutes = scalar_int(raw)
        self.assertIsNotNone(minutes, "%s: no integer job timeout-minutes (got %r, #9699)"
                             % (MOVED_JOB, raw))
        work_s = sum(MOVED_WORK_MEASURED_MAX_S.values())
        self.assertGreaterEqual(minutes * SECS_PER_MINUTE, work_s * TIMEOUT_FLOOR_FACTOR,
                                "%s timeout %d min leaves under 20 %% over the %d s of "
                                "measured work" % (MOVED_JOB, minutes, work_s))
        self.assertLessEqual(minutes * SECS_PER_MINUTE, work_s * TIMEOUT_CEILING_FACTOR,
                             "%s timeout %d min is over twice the %d s of measured work"
                             % (MOVED_JOB, minutes, work_s))

    def test_moved_job_steps_have_no_step_timeout(self):
        timed = [(s["name"], s["timeout-minutes"]) for s in self.wf.steps[MOVED_JOB]
                 if s["timeout-minutes"] is not None]
        self.assertEqual(timed, [], "%s: the job timeout is the bound; a step timeout "
                         "can cut the moved work short" % MOVED_JOB)

    def test_no_continue_on_error_outside_the_select_job(self):
        found = {(job, s["name"]): s["continue-on-error"]
                 for job, steps in self.wf.steps.items() for s in steps
                 if s["continue-on-error"] is not None}
        self.assertEqual(found, CONTINUE_ON_ERROR_BY_DESIGN,
                         "step-level continue-on-error outside the select job (#9698)")

    def test_no_job_level_continue_on_error(self):
        found = {job: meta["continue-on-error"] for job, meta in self.wf.meta.items()
                 if meta["continue-on-error"] is not None}
        self.assertEqual(found, {}, "job-level continue-on-error (#9698; %s, check and "
                         "ci-gate above all)" % MOVED_JOB)

    def test_moved_steps_cannot_swallow_a_failure(self):
        for name in MOVED_STEPS:
            step = self.wf.step(MOVED_JOB, name)
            self.assertIsNotNone(step, name)
            self.assertIsNone(FAIL_OPEN_RUN_RE.search(step["run"] or ""),
                              "%s: run swallows a failure" % name)

    def test_matrix_has_no_exclude(self):
        for job in MATRIX_JOBS:
            lines = self.wf.blocks[job]
            strategy, matrix_keys = strategy_shape(lines)
            self.assertEqual(strategy.get("fail-fast"), "false", "%s fail-fast" % job)
            self.assertEqual(strategy.get("matrix"), "", "%s: flow-style matrix" % job)
            self.assertEqual(matrix_keys, ["include"], "%s: matrix keys other than "
                             "include (an exclude can drop the leg that holds the "
                             "work, #9698)" % job)
            excludes = [line for line in lines if EXCLUDE_RE.match(line)]
            self.assertEqual(excludes, [], "%s: exclude key" % job)

    def test_the_once_leg_is_present(self):
        mobile = matrix_include(self.wf.blocks[MOVED_JOB])
        once = [e.get("target") for e in mobile if e.get("once") == "true"]
        self.assertEqual(once, [ONCE_HOLDER[1]], "%s: the android leg with once: true "
                         "holds the moved work" % MOVED_JOB)

    def test_classify_unit_test_steps_are_unconditional(self):
        gated = {name: self.wf.step(CLASSIFY_JOB, name) for name, job in
                 EXPECTED_GATE_STEPS.items() if job == CLASSIFY_JOB}
        missing = sorted(name for name, step in gated.items() if step is None)
        self.assertEqual(missing, [], "classify gate steps missing")
        conditional = {name: step["if"] for name, step in gated.items() if step["if"]}
        self.assertEqual(conditional, {}, "classify unit-test steps with a step-level if "
                         "(#9687)")
        self.assertIsNone(self.wf.meta[CLASSIFY_JOB]["if"], "classify job-level if (#9687)")


# ---------------------------------------------------------------------------
# cargo-audit source invariant (#9680 r0 send-back, ruling 7fd3cd38): in every
# job of the workflow cargo-audit comes only from `cargo install --locked` at
# the one named pin (the base bbede4b2 form, #3138), and no step downloads,
# extracts or checksums a prebuilt cargo-audit. The scanner reads the whole
# workflow on its own (it does not reuse workflow_text.read_steps): every job,
# every `run:` value at any indent (literal, folded and plain multi-line
# scalars, one-line values), shell continuation lines, and every env entry.
# ---------------------------------------------------------------------------
AUDIT_JOB = "mobile-cross-compile"
CARGO_AUDIT_PIN_VAR = "CARGO_AUDIT_VERSION"
CARGO_AUDIT_PIN = "0.22.2"
CARGO_AUDIT_VERSION_ARG = '"${CARGO_AUDIT_VERSION}"'
CARGO_AUDIT_INSTALL = 'cargo install cargo-audit --locked --force --version "${CARGO_AUDIT_VERSION}"'
EXPECTED_AUDIT_INSTALL_JOBS = frozenset({AUDIT_JOB})

# Text that names the audit tool or its upstream (CARGO_AUDIT_* variables too).
AUDIT_SUBJECT_RE = re.compile(r"(?i)cargo[-_]audit|rustsec")
RUSTSEC_RELEASE_RE = re.compile(r"(?i)rustsec/rustsec/releases")
SHA256_DIGEST_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
# The download, extract and checksum forms a prebuilt install takes.
PREBUILT_FORMS = (
    ("curl download", re.compile(r"\bcurl\b")),
    ("wget download", re.compile(r"\bwget\b")),
    ("gh release download", re.compile(r"\bgh\s+release\s+download\b")),
    ("tar extract", re.compile(r"\btar\b")),
    ("unzip extract", re.compile(r"\bunzip\b")),
    ("checksum", re.compile(r"\b(?:sha256sum|sha512sum|shasum|b2sum)\b|\bopenssl\s+dgst\b")),
    ("cargo binstall", re.compile(r"\bcargo[- ]binstall\b")),
)
INSTALLER_INPUT_RE = re.compile(
    r"^\s*(?:-\s+)?(?:tool|tools|crate|crates|bin|bins|package|packages):\s*.*\bcargo-audit\b")
INSTALL_RE = re.compile(r"\bcargo\s+install\b")
AUDIT_CRATE_RE = re.compile(r"(?<![\w-])cargo-audit(?![\w-])")
RUNS_AUDIT_RE = re.compile(r"\bcargo\s+audit\b|check_cargo_audit\.py")

SCAN_JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$")
SCAN_KEY_RE = re.compile(r"^(?P<indent> *)(?P<dash>- +)?(?P<key>[A-Za-z0-9_.-]+):(?:[ \t]+(?P<value>.*?))?\s*$")
SCAN_DASH_RE = re.compile(r"^(?P<indent> *)- ")
BLOCK_HEADER_RE = re.compile(r"^(?P<style>[|>])(?:[1-9][+-]?|[+-][1-9]?)?\s*(?:#.*)?$")
SHELL_ASSIGN_RE = re.compile(r"^\s*(?:export\s+|local\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)=(\S*)")
SHELL_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}|\$([A-Za-z_][A-Za-z0-9_]*)")
EXPAND_PASSES = 3


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def scalar_value(raw):
    """A one-line YAML value without quotes or a trailing comment."""
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        inner = value[1:-1]
        return inner.replace('\\"', '"') if value[0] == '"' else inner.replace("''", "'")
    return re.sub(r"\s+#.*$", "", value)


def block_text(lines, style):
    """Body of a literal (|) or folded (>) block scalar, its indent removed."""
    body = [l for l in lines]
    while body and not body[-1].strip():
        body.pop()
    width = min((indent_of(l) for l in body if l.strip()), default=0)
    body = [l[width:] for l in body]
    if style == "|":
        return "\n".join(body)
    folded, para = [], []
    for line in body:
        if not line.strip():
            folded.append(" ".join(para))
            para = []
        elif line.startswith((" ", "\t")):
            if para:
                folded.append(" ".join(para))
                para = []
            folded.append(line)
        else:
            para.append(line)
    if para:
        folded.append(" ".join(para))
    return "\n".join(folded)


def shell_lines(script):
    """Logical shell lines: backslash continuations joined, comment lines dropped."""
    logical, pending = [], ""
    for line in script.split("\n"):
        stripped = line.rstrip()
        trailing = len(stripped) - len(stripped.rstrip("\\"))
        if trailing % 2 == 1:
            pending += stripped[:-1] + " "
            continue
        logical.append(pending + line)
        pending = ""
    if pending:
        logical.append(pending)
    return [l for l in logical if l.strip() and not l.strip().startswith("#")]


def scan_workflow(text):
    """Read the whole workflow: every run script, every env entry, every line's place.

    Returns (scripts, envs, places, run_lines): scripts is
    [{"job","step","script"}] with the script as shell text, envs is
    [{"job","step","key","value"}], places maps each line index to its
    (job, step) label, run_lines holds the indexes of every run key and body.
    """
    lines = text.split("\n")
    scripts, envs, places = [], [], {}
    in_jobs = False
    job = step = None
    steps_indent = item_indent = None
    step_index = 0
    run_lines = set()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line == "jobs:" or line.startswith("jobs:"):
            in_jobs = True
            job = step = None
            i += 1
            continue
        if line and not line.startswith((" ", "#")):
            in_jobs = False
            job = step = None
        job_match = SCAN_JOB_RE.match(line) if in_jobs else None
        if job_match:
            job, step = job_match.group(1), None
            steps_indent = item_indent = None
            step_index = 0
            places[i] = (job, None)
            i += 1
            continue
        dash = SCAN_DASH_RE.match(line)
        if job and steps_indent is not None and dash:
            if item_indent is None and indent_of(line) > steps_indent:
                item_indent = indent_of(line)
            if indent_of(line) == item_indent:
                step_index += 1
                step = "step %d" % step_index
        if job and steps_indent is not None and line.strip() and indent_of(line) <= steps_indent \
                and not SCAN_DASH_RE.match(line):
            steps_indent = item_indent = None
            step = None
        places[i] = (job, step)
        key = SCAN_KEY_RE.match(line)
        if not key or line.strip().startswith("#"):
            i += 1
            continue
        name, value = key.group("key"), key.group("value") or ""
        key_col = len(key.group("indent")) + len(key.group("dash") or "")
        if job and name == "steps" and not value:
            steps_indent = key_col
            step = None
        elif job and name in ("name", "uses") and step and item_indent is not None \
                and key_col == item_indent + 2 and step.startswith("step "):
            step = scalar_value(value)
            places[i] = (job, step)
        if name in ("run", "env"):
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or indent_of(lines[j]) > key_col):
                j += 1
            child = lines[i + 1:j]
            for k in range(i + 1, j):
                places[k] = (job, step)
            if name == "run":
                header = BLOCK_HEADER_RE.match(value)
                if header:
                    script = block_text(child, header.group("style"))
                else:
                    parts = [value.strip()] + [c.strip() for c in child if c.strip()]
                    script = scalar_value(" ".join(parts))
                scripts.append({"job": job, "step": step, "script": script})
                run_lines.update(range(i, j))
            elif not value:
                width = min((indent_of(c) for c in child if c.strip()), default=0)
                for c in child:
                    entry = SCAN_KEY_RE.match(c)
                    if entry and indent_of(c) == width and not entry.group("dash"):
                        envs.append({"job": job, "step": step, "key": entry.group("key"),
                                     "value": scalar_value(entry.group("value") or "")})
            i = j
            continue
        i += 1
    return scripts, envs, places, run_lines


def expand(line, variables):
    for _ in range(EXPAND_PASSES):
        new = SHELL_VAR_RE.sub(lambda m: variables.get(m.group(1) or m.group(2), m.group(0)), line)
        if new == line:
            break
        line = new
    return line


def label(job, step):
    return "%s: %s" % (job or "workflow", step or "job")


def install_problem(tokens):
    """Why an install line is not the base form, or None."""
    if " ".join(tokens) == CARGO_AUDIT_INSTALL:
        return None
    if "--locked" not in tokens:
        return "cargo-audit install without --locked"
    version = None
    for n, tok in enumerate(tokens):
        if tok in ("--version", "--vers") and n + 1 < len(tokens):
            version = tokens[n + 1]
        elif tok.startswith(("--version=", "--vers=")):
            version = tok.split("=", 1)[1]
    if version is None:
        return "cargo-audit install without --version"
    if version != CARGO_AUDIT_VERSION_ARG:
        return "cargo-audit install version is not ${CARGO_AUDIT_VERSION}"
    return "cargo-audit install is not the base form"


def cargo_audit_source_problems(text):
    """Every way the workflow gets cargo-audit other than the pinned source install."""
    scripts, envs, places, run_lines = scan_workflow(text)
    problems = []

    def add(message):
        if message not in problems:
            problems.append(message)

    global_vars = {e["key"]: e["value"] for e in envs}
    installs = {}
    runs = set()
    for entry in scripts:
        job, step = entry["job"], entry["step"]
        variables = dict(global_vars)
        logical = shell_lines(entry["script"])
        for line in logical:
            assign = SHELL_ASSIGN_RE.match(line)
            if assign:
                variables[assign.group(1)] = scalar_value(assign.group(2))
        for line in logical:
            seen = line + " " + expand(line, variables)
            if AUDIT_SUBJECT_RE.search(seen):
                for form, pattern in PREBUILT_FORMS:
                    if pattern.search(line):
                        add("%s: %s of a prebuilt cargo-audit" % (label(job, step), form))
            if INSTALL_RE.search(line) and AUDIT_CRATE_RE.search(line):
                installs.setdefault(job, []).append((step, line.split()))
            elif RUNS_AUDIT_RE.search(line):
                runs.add(job)
    for idx, line in enumerate(text.split("\n")):
        if line.strip().startswith("#"):
            continue
        job, step = places.get(idx, (None, None))
        if RUSTSEC_RELEASE_RE.search(line):
            add("%s: rustsec release URL of a prebuilt cargo-audit" % label(job, step))
        if SHA256_DIGEST_RE.search(line) and AUDIT_SUBJECT_RE.search(line):
            add("%s: sha256 pin of a prebuilt cargo-audit" % label(job, step))
        if idx not in run_lines and INSTALLER_INPUT_RE.match(line):
            add("%s: installer action of a prebuilt cargo-audit" % label(job, step))
    for job in sorted(runs - set(installs)):
        add("%s: runs cargo-audit with no cargo install of it" % job)
    for job, found in installs.items():
        if len(found) > 1:
            add("%s: installs cargo-audit %d times, not once" % (job, len(found)))
        if job not in runs:
            add("%s: installs cargo-audit and never runs it" % job)
        for step, tokens in found:
            why = install_problem(tokens)
            if why:
                add("%s: %s" % (label(job, step), why))
            pins = [e["value"] for e in envs
                    if e["job"] == job and e["step"] == step and e["key"] == CARGO_AUDIT_PIN_VAR]
            if not pins:
                add("%s: no %s pin on the install step" % (label(job, step), CARGO_AUDIT_PIN_VAR))
    for e in envs:
        if e["key"] == CARGO_AUDIT_PIN_VAR and e["value"] != CARGO_AUDIT_PIN:
            add("%s: %s is %r, not %r" % (label(e["job"], e["step"]), CARGO_AUDIT_PIN_VAR,
                                          e["value"], CARGO_AUDIT_PIN))
    return problems


def cargo_audit_install_jobs(text):
    scripts = scan_workflow(text)[0]
    return {s["job"] for s in scripts
            for line in shell_lines(s["script"])
            if INSTALL_RE.search(line) and AUDIT_CRATE_RE.search(line)}


AUDIT_FIXTURE = """name: CI
on: [push]
env:
  TOP_LEVEL: "x"
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v4
      - name: Lint
        run: cargo fmt --all --check
  mobile-cross-compile:
    runs-on: ubuntu-latest
    steps:
      - name: Security audit
        if: matrix.once
        env:
          CARGO_AUDIT_VERSION: "0.22.2"
        run: |
          if ! command -v cargo-audit >/dev/null 2>&1 \\
             || ! cargo audit --version 2>/dev/null | grep -Fqw -- "${CARGO_AUDIT_VERSION}"; then
            cargo install cargo-audit --locked --force --version "${CARGO_AUDIT_VERSION}"
          fi
          #INJECT
          python3 scripts/ci/check_cargo_audit.py
"""
FIXTURE_INSTALL = '            cargo install cargo-audit --locked --force --version "${CARGO_AUDIT_VERSION}"\n'
FIXTURE_PIN = '          CARGO_AUDIT_VERSION: "0.22.2"\n'
FIXTURE_LINT_STEP = "      - name: Lint\n        run: cargo fmt --all --check\n"
INJECT = "          #INJECT\n"
DIGEST = "7f" * 32
AUDIT_STEP = AUDIT_JOB + ": Security audit"


def inject(body):
    return AUDIT_FIXTURE.replace(INJECT, "".join("          %s\n" % l for l in body.split("\n")))


def lint_step(step):
    return AUDIT_FIXTURE.replace(FIXTURE_LINT_STEP, FIXTURE_LINT_STEP + step)


# (row, workflow text, exact problems). Every download form, in every scalar shape.
AUDIT_SOURCE_ROWS = (
    ("base form", AUDIT_FIXTURE, []),
    ("curl", inject('curl -fsSL -o ca.tgz "https://example.invalid/cargo-audit.tgz"'),
     [AUDIT_STEP + ": curl download of a prebuilt cargo-audit"]),
    ("wget", inject("wget -q https://example.invalid/cargo-audit-v0.22.2.tgz"),
     [AUDIT_STEP + ": wget download of a prebuilt cargo-audit"]),
    ("gh release download", inject("gh release download cargo-audit/v0.22.2 --repo rustsec/rustsec"),
     [AUDIT_STEP + ": gh release download of a prebuilt cargo-audit"]),
    ("tar through a shell variable",
     inject('asset="cargo-audit-x86_64-unknown-linux-musl"\ntar -xzf "${asset}.tgz" -C bin'),
     [AUDIT_STEP + ": tar extract of a prebuilt cargo-audit"]),
    ("tar through an env value",
     AUDIT_FIXTURE.replace(FIXTURE_PIN, FIXTURE_PIN + '          ARCHIVE: "ca-musl.tgz"\n'
                           '          MEMBER: "cargo-audit"\n').replace(
         INJECT, '          tar -xzf "${ARCHIVE}" "${MEMBER}"\n'),
     [AUDIT_STEP + ": tar extract of a prebuilt cargo-audit"]),
    ("unzip", inject("unzip -o cargo-audit.zip"),
     [AUDIT_STEP + ": unzip extract of a prebuilt cargo-audit"]),
    ("sha256sum", inject('echo "${SUM}  cargo-audit" | sha256sum -c -'),
     [AUDIT_STEP + ": checksum of a prebuilt cargo-audit"]),
    ("shasum", inject("shasum -a 256 -c cargo-audit.sha256"),
     [AUDIT_STEP + ": checksum of a prebuilt cargo-audit"]),
    ("cargo binstall", inject("cargo binstall --no-confirm cargo-audit"),
     [AUDIT_STEP + ": cargo binstall of a prebuilt cargo-audit"]),
    ("rustsec release URL in env",
     AUDIT_FIXTURE.replace(FIXTURE_PIN, FIXTURE_PIN +
                           '          CA_URL: "https://github.com/rustsec/rustsec/releases/download/x"\n'),
     [AUDIT_STEP + ": rustsec release URL of a prebuilt cargo-audit"]),
    ("sha256 pin in env",
     AUDIT_FIXTURE.replace(FIXTURE_PIN, FIXTURE_PIN + '          CARGO_AUDIT_TGZ_SHA256: "%s"\n' % DIGEST),
     [AUDIT_STEP + ": sha256 pin of a prebuilt cargo-audit"]),
    ("installer action",
     lint_step("      - uses: taiki-e/install-action@0000000000000000000000000000000000000000\n"
               "        with:\n          tool: cargo-audit\n"),
     ["lint: taiki-e/install-action@0000000000000000000000000000000000000000: "
      "installer action of a prebuilt cargo-audit"]),
    ("folded scalar in another job",
     lint_step("      - name: Fetch\n        run: >\n          curl -fsSL -o ca.tgz\n"
               "          https://example.invalid/cargo-audit.tgz\n"),
     ["lint: Fetch: curl download of a prebuilt cargo-audit"]),
    ("folded strip scalar",
     lint_step("      - name: Fetch\n        run: >-\n          wget\n          cargo-audit.tgz\n"),
     ["lint: Fetch: wget download of a prebuilt cargo-audit"]),
    ("continuation lines",
     inject("curl -fsSL \\\n  -o ca.tgz \\\n  https://example.invalid/cargo-audit.tgz"),
     [AUDIT_STEP + ": curl download of a prebuilt cargo-audit"]),
    ("one-line run",
     lint_step("      - name: Fetch\n        run: wget https://example.invalid/cargo-audit.tgz\n"),
     ["lint: Fetch: wget download of a prebuilt cargo-audit"]),
    ("plain multi-line run",
     lint_step("      - name: Fetch\n        run: curl -fsSL -o ca.tgz\n"
               "          https://example.invalid/cargo-audit.tgz\n"),
     ["lint: Fetch: curl download of a prebuilt cargo-audit"]),
    ("dash run step",
     lint_step("      - run: curl -fsSL https://example.invalid/cargo-audit.tgz\n"),
     ["lint: step 3: curl download of a prebuilt cargo-audit"]),
    ("install without --locked",
     AUDIT_FIXTURE.replace(" --locked --force", " --force"),
     [AUDIT_STEP + ": cargo-audit install without --locked"]),
    ("install at another version",
     AUDIT_FIXTURE.replace('--version "${CARGO_AUDIT_VERSION}"\n', "--version 0.22.3\n"),
     [AUDIT_STEP + ": cargo-audit install version is not ${CARGO_AUDIT_VERSION}"]),
    ("install with no version",
     AUDIT_FIXTURE.replace(' --version "${CARGO_AUDIT_VERSION}"\n', "\n"),
     [AUDIT_STEP + ": cargo-audit install without --version"]),
    ("install from git",
     AUDIT_FIXTURE.replace("cargo install cargo-audit --locked",
                           "cargo install --git https://example.invalid/rustsec cargo-audit --locked"),
     [AUDIT_STEP + ": cargo-audit install is not the base form"]),
    ("install removed", AUDIT_FIXTURE.replace(FIXTURE_INSTALL, ""),
     [AUDIT_JOB + ": runs cargo-audit with no cargo install of it"]),
    ("install doubled", AUDIT_FIXTURE.replace(FIXTURE_INSTALL, FIXTURE_INSTALL * 2),
     [AUDIT_JOB + ": installs cargo-audit 2 times, not once"]),
    ("install in a job that never runs it",
     lint_step('      - name: Tools\n        run: cargo install cargo-audit --locked --force'
               ' --version "${CARGO_AUDIT_VERSION}"\n'),
     ["lint: installs cargo-audit and never runs it",
      "lint: Tools: no CARGO_AUDIT_VERSION pin on the install step"]),
    ("pin changed", AUDIT_FIXTURE.replace(FIXTURE_PIN, '          CARGO_AUDIT_VERSION: "0.22.3"\n'),
     [AUDIT_STEP + ": CARGO_AUDIT_VERSION is '0.22.3', not '0.22.2'"]),
    ("pin removed", AUDIT_FIXTURE.replace(FIXTURE_PIN, '          OTHER: "1"\n'),
     [AUDIT_STEP + ": no CARGO_AUDIT_VERSION pin on the install step"]),
)
# Input-size bound for the scanner: a 100K+ line run body scans in linear time.
SCAN_BOUND_LINES = 120_000
SCAN_BOUND_SECONDS = 10.0


class CargoAuditSource9680(unittest.TestCase):
    """cargo-audit comes only from the pinned `cargo install --locked`; no prebuilt."""

    def test_workflow_gets_cargo_audit_only_from_the_pinned_source_install(self):
        self.assertEqual(cargo_audit_source_problems(CI_YML.read_text(encoding="utf-8")), [])

    def test_only_the_audit_job_installs_cargo_audit(self):
        self.assertEqual(cargo_audit_install_jobs(CI_YML.read_text(encoding="utf-8")),
                         EXPECTED_AUDIT_INSTALL_JOBS)

    def test_the_audit_step_installs_the_base_form(self):
        wf = Workflow(CI_YML)
        step = wf.step(AUDIT_JOB, SECURITY_AUDIT)
        self.assertIsNotNone(step)
        self.assertEqual(unquote(step["env"].get(CARGO_AUDIT_PIN_VAR)), CARGO_AUDIT_PIN)
        installs = [" ".join(l.split()) for l in shell_lines(step["run"] or "")
                    if INSTALL_RE.search(l)]
        self.assertEqual(installs, [CARGO_AUDIT_INSTALL])

    def test_the_audit_step_checks_the_version_then_runs_the_gate(self):
        step = Workflow(CI_YML).step(AUDIT_JOB, SECURITY_AUDIT)
        self.assertIsNotNone(step)
        code = [" ".join(l.split()) for l in shell_lines(step["run"] or "")]
        self.assertEqual(code.count(CARGO_AUDIT_INSTALL), 1, "the base install line, once")
        install = code.index(CARGO_AUDIT_INSTALL)
        self.assertEqual(code[install + 1:install + 5], [
            "fi",
            'if ! cargo audit --version 2>/dev/null | grep -Fqw -- "${CARGO_AUDIT_VERSION}"; then',
            'echo "::error::cargo-audit ${CARGO_AUDIT_VERSION} is not the installed version"',
            "exit 1",
        ])
        self.assertEqual(code[-len(AUDIT_GATE_LINES):], list(AUDIT_GATE_LINES))

    def test_rows(self):
        for row, text, want in AUDIT_SOURCE_ROWS:
            with self.subTest(row=row):
                self.assertEqual(sorted(cargo_audit_source_problems(text)), sorted(want))

    def test_scan_is_linear_in_input_size(self):
        filler = "".join("          echo line %d\n" % n for n in range(SCAN_BOUND_LINES))
        text = AUDIT_FIXTURE.replace(INJECT, filler + "          curl https://example.invalid/cargo-audit\n")
        started = time.monotonic()
        problems = cargo_audit_source_problems(text)
        elapsed = time.monotonic() - started
        self.assertEqual(problems, [AUDIT_STEP + ": curl download of a prebuilt cargo-audit"])
        self.assertLess(elapsed, SCAN_BOUND_SECONDS)


class Aggregator9680(unittest.TestCase):
    """Rule 4: ci-gate is red on a skipped, failed or cancelled required need."""

    @classmethod
    def setUpClass(cls):
        cls.gate = load_gate(GATE_PY)
        cls.job_map = cls.gate.common.load_rules(None)["job_map"]

    def needs(self, **overrides):
        doc = {job: {"result": "success", "outputs": {}} for job in EXPECTED_NEEDS["ci-gate"]}
        doc["classify"]["outputs"] = {"docs_only": "false"}
        doc["select"]["outputs"] = {"rust": "true", "cells": "true"}
        for job, result in overrides.items():
            doc[job.replace("_", "-")]["result"] = result
        return doc

    def evaluate(self, doc):
        ok, _ = self.gate.evaluate(doc, self.job_map, "", (), self.gate.REQUIRED_NEEDS)
        return ok

    def test_gate_needs_match_the_workflow(self):
        self.assertEqual(tuple(self.gate.REQUIRED_NEEDS), EXPECTED_NEEDS["ci-gate"])

    def test_all_success_passes(self):
        self.assertTrue(self.evaluate(self.needs()))

    def test_selected_need_not_success_is_red(self):
        for job in ("check", "mobile_cross_compile", "build_script_vetting"):
            for result in ("skipped", "failure", "cancelled"):
                self.assertFalse(self.evaluate(self.needs(**{job: result})), (job, result))

    def test_missing_need_is_red(self):
        doc = self.needs()
        del doc["mobile-cross-compile"]
        self.assertFalse(self.evaluate(doc))


class ArtifactConsumers9680(unittest.TestCase):
    """Rule 4: an artifact consumer verifies the commit sha and fails closed."""

    def test_no_unverified_consumer(self):
        wf = Workflow(CI_YML)
        self.assertEqual(unverified_artifact_consumers(wf.text), [])

    def test_checker_bites(self):
        head = "jobs:\n  c:\n    runs-on: x\n    steps:\n"
        download = "      - uses: actions/download-artifact@abc # v4\n"
        bad = head + download + "      - run: ./ai-memory --version\n"
        good = head + download + (
            "      - name: Verify sha\n        run: |\n"
            "          test \"$(cat sha)\" = \"${{ github.sha }}\" || exit 1\n")
        self.assertEqual(unverified_artifact_consumers(bad), ["c"])
        self.assertEqual(unverified_artifact_consumers(good), [])


if __name__ == "__main__":
    unittest.main()
