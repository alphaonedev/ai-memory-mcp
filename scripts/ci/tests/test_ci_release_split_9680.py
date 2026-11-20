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
The cargo-audit binary is a pinned prebuilt verified by sha256 before it runs.

Every expected set is written by hand (rule d54c4b0e); nothing is derived from
the workflow under test. CI_9680_WORKFLOW and CI_9680_GATE point the test at a
copy of ci.yml and of scripts/ci/impact/gate.py (the mutant runs use them).

Run: python3 -I -m unittest discover -s scripts/ci/tests -p test_ci_release_split_9680.py
"""
import importlib.util
import os
import re
import sys
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

# cargo-audit prebuilt pin (rustsec/rustsec release cargo-audit/v0.22.2).
CARGO_AUDIT_VERSION = "0.22.2"
CARGO_AUDIT_TGZ_SHA256 = "7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428"
CARGO_AUDIT_BIN_SHA256 = "66f9c8f530950d106c1869ce27ef5a4008bcea53c7716c3ed8117586337ee7d8"
CARGO_AUDIT_URL_PREFIX = "https://github.com/rustsec/rustsec/releases/download/cargo-audit%2Fv"
SHA_CHECK = "sha256sum -c"
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
    """Return {"name", "if", "needs"} of one job block."""
    meta = {"name": None, "if": None, "needs": ()}
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
        elif name == "if":
            meta["if"] = value
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


def audit_problems(step):
    """Every way the Security audit step can fail open or run an unverified binary."""
    if step is None:
        return ["no Security audit step"]
    problems = []
    env = {k: unquote(v) for k, v in (step["env"] or {}).items()}
    if env.get("CARGO_AUDIT_VERSION") != CARGO_AUDIT_VERSION:
        problems.append("version pin")
    if env.get("CARGO_AUDIT_TGZ_SHA256") != CARGO_AUDIT_TGZ_SHA256:
        problems.append("archive sha256 pin")
    if env.get("CARGO_AUDIT_BIN_SHA256") != CARGO_AUDIT_BIN_SHA256:
        problems.append("binary sha256 pin")
    run = step["run"] or ""
    code = "\n".join(l for l in run.splitlines() if not l.strip().startswith("#"))
    if not code.startswith("set -euo pipefail"):
        problems.append("set -euo pipefail first")
    if "cargo install" in code:
        problems.append("source build")
    if CARGO_AUDIT_URL_PREFIX not in code:
        problems.append("download URL")
    for line in code.splitlines():
        if "curl " in line and ("|" in line or " -f" not in line):
            problems.append("curl must be -f and never piped")
    checks = [m.start() for m in re.finditer(re.escape(SHA_CHECK), code)]
    tar = code.find("tar ")
    audit = code.find("cargo audit")
    if len(checks) < 2:
        problems.append("two sha256 checks")
    elif tar < 0 or checks[0] > tar or audit < 0 or checks[1] > audit:
        problems.append("sha256 check before extract and before run")
    for var in ("${CARGO_AUDIT_TGZ_SHA256}", "${CARGO_AUDIT_BIN_SHA256}"):
        if var not in code:
            problems.append("checks use " + var)
    if code.count("::error::") < 3 or code.count("exit 1") < 3:
        problems.append("checksum, path and version mismatch are red")
    if 'grep -Fqw -- "${CARGO_AUDIT_VERSION}"' not in code:
        problems.append("version check")
    for line in AUDIT_GATE_LINES:
        if line not in code:
            problems.append("gate line " + line)
    return problems


class CargoAudit9680(unittest.TestCase):
    """The audit runs a sha256-verified pinned prebuilt; a mismatch is red."""

    def test_audit_step_is_verified(self):
        wf = Workflow(CI_YML)
        self.assertEqual(audit_problems(wf.step("mobile-cross-compile", SECURITY_AUDIT)), [])

    def test_checker_bites(self):
        wf = Workflow(CI_YML)
        step = wf.step("mobile-cross-compile", SECURITY_AUDIT)
        self.assertIsNotNone(step)
        no_check = dict(step, run=(step["run"] or "").replace(SHA_CHECK, "true"))
        self.assertIn("two sha256 checks", audit_problems(no_check))
        source = dict(step, run=(step["run"] or "") + "cargo install cargo-audit --locked\n")
        self.assertIn("source build", audit_problems(source))
        wrong = dict(step, env=dict(step["env"], CARGO_AUDIT_TGZ_SHA256='"00"'))
        self.assertIn("archive sha256 pin", audit_problems(wrong))


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
