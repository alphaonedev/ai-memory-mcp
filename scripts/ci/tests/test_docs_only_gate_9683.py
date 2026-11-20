"""Docs-only short-circuit for the heavy PR jobs (#9683).

cert-postgres-age, postgres-ignored and token-budget ran in full on a PR that
changes only documentation. They now carry one step-level gate
(.github/actions/docs-only-gate -> scripts/ci/impact/docs_only_gate.py) that
judges the whole-PR diff (pull_request.base.sha to the checked-out merge ref)
with the single allowlist coverage already uses (rules.json cargo_skip
docs_globs, minus every never-skip and test-read glob).

This module holds the invariant three ways:

* Workflow shape, for EVERY job of the touched workflows, against sets written
  by hand here (rule d54c4b0e): the job ids and `name:` lines (the required
  contexts), the job-level `if:` unchanged, no `paths` filter on the trigger,
  the exact ordered step list, the gate's position and inputs, and the guard
  on every step after it, with the step's old condition kept as the prefix.
  Housekeeping steps (`always()`, `failure()`) keep their condition as is.
* The decider's table: docs-only sets, one non-docs path first, last and in the
  middle, renames both ways, an empty list, unreadable input (bad status, a
  newline, a leading dash, a `..` segment, non-UTF-8, an unterminated list,
  more paths than the bound), a docs-looking path under .github/ and a 100K
  path list within a stated time bound.
* The step mode end to end on a scratch git repository: whole-PR diff (a
  code commit followed by a docs commit is a full run), a missing base, a
  decider absent from the base tree, a push event and a protected base are
  all full runs; only the decider's docs-only exit writes docs_only=true.
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION = ROOT / ".github" / "actions" / "docs-only-gate" / "action.yml"
IMPACT = ROOT / "scripts" / "ci" / "impact"
GATE_PATH = IMPACT / "docs_only_gate.py"
RULES_PATH = IMPACT / "rules.json"
SCRATCH = ROOT / ".local-runs"

GATE_LABEL = "Docs-only short-circuit (#9683)"
GATE_ID = "docs"
GATE_USES = "./.github/actions/docs-only-gate"
GATE_WITH = {
    "base-sha": "${{ github.event.pull_request.base.sha }}",
    "event-name": "${{ github.event_name }}",
    "base-ref": "${{ github.base_ref }}",
}
GUARD = "steps.docs.outputs.docs_only != 'true'"
SAME_REPO_IF = ("github.event_name != 'pull_request' || "
                "github.event.pull_request.head.repo.full_name == github.repository")
SELF_HOSTED = "runner.environment == 'self-hosted'"
NOT_HOSTED = "runner.environment != 'github-hosted'"
HOSTED = "runner.environment == 'github-hosted'"
ALWAYS = "always()"
FAILURE = "failure()"
SWEEP_IF = "always() && runner.environment == 'self-hosted'"


# A plain YAML scalar ends at " #" (a comment), so a step written as
# "... fail-closed #3128)" is named "... fail-closed" for GitHub and for
# taint_boundary.py; the labels below are the names GitHub reports.
ASSERT_RUSTUP = "Assert rustup is provisioned (self-hosted; fail-closed"
CERT_RUN = "Run"
CERT_ARM = "Cluster-A cert-posture armability gate (#3061"


def guarded(old=None):
    """The expected `if:` of a step after the gate: the old condition, then the guard."""
    return GUARD if old is None else "%s && %s" % (old, GUARD)


# Hand-written expectations (rule d54c4b0e): every job of every touched workflow.
EXPECTED = {
    "postgres-ignored.yml": {
        "jobs": {"postgres-ignored": "Postgres ignored tests (sal-postgres --ignored)"},
        "job_if": {"postgres-ignored": SAME_REPO_IF},
        "steps": {"postgres-ignored": [
            ("actions/checkout", None),
            ("Prune stale runner TMPDIR (#8634)", SELF_HOSTED),
            (GATE_LABEL, None),
            (ASSERT_RUSTUP, guarded(NOT_HOSTED)),
            ("Install Rust 1.99.1 (matches rust-toolchain.toml pin)", guarded()),
            ("Point at the native enterprise-fed tier (per-job ephemeral db)", guarded()),
            ("cargo test --features sal-postgres -- --ignored", guarded()),
            ("Cleanup enterprise-fed ephemeral db", ALWAYS),
            ("Sweep target/debug to the size cap (self-hosted)", SWEEP_IF),
        ]},
        "tests": {"cargo test --features sal-postgres -- --ignored":
                  ["cargo test --features sal-postgres"]},
    },
    "cert-postgres-age.yml": {
        "jobs": {"cert-postgres-age":
                 "Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6)"},
        "job_if": {"cert-postgres-age": SAME_REPO_IF},
        "steps": {"cert-postgres-age": [
            ("actions/checkout", None),
            ("Prune stale runner TMPDIR (#8634)", SELF_HOSTED),
            (GATE_LABEL, None),
            (ASSERT_RUSTUP, guarded(NOT_HOSTED)),
            ("Install Rust 1.99.1 (matches rust-toolchain.toml pin)", guarded()),
            ("Point at the native enterprise-fed tier (per-job ephemeral db)", guarded()),
            ("Swatinem/rust-cache", guarded(HOSTED)),
            ("Resolve certified stack pins from deploy SSOT", guarded()),
            ("Wait for native tier readiness", guarded()),
            ("Ensure AGE + vector extensions present (best-effort — tier is pre-provisioned)",
             guarded()),
            ("Assert certified stack versions (cert evidence, hard-fail on drift)", guarded()),
            (CERT_RUN, guarded()),
            (CERT_ARM, guarded()),
            ("Redact cert-bootstrap evidence on failure", FAILURE),
            ("Upload cert-bootstrap evidence on failure", FAILURE),
            ("Cleanup enterprise-fed ephemeral db", ALWAYS),
            ("Sweep target/debug to the size cap (self-hosted)", SWEEP_IF),
        ]},
        "tests": {
            CERT_RUN:
                ["cargo test --features sal-postgres", "check-cert-leg-nonvacuity.sh"],
            CERT_ARM:
                ["cargo build --features sal-postgres --bin ai-memory",
                 "check-bootstrap-cert-gate.sh"],
        },
    },
    "token-budget.yml": {
        "jobs": {"budget": "token-budget gates"},
        "job_if": {"budget": None},
        "steps": {"budget": [
            ("actions/checkout", None),
            (GATE_LABEL, None),
            ("dtolnay/rust-toolchain", guarded()),
            ("Swatinem/rust-cache", guarded()),
            ("per-tool ceiling (1500 tokens cl100k_base)", guarded()),
            ("full-profile honest range (5K–8K cl100k_base)", guarded()),
            ("doctor --tokens default-profile-is-core", guarded()),
            ("full-profile <= 8110 tokens (v0.7 C5 hard ceiling, post-D1.6 +", guarded()),
            ("doctor --tokens --json reports trimmed total <= 8110 (v0.7 C5 post-D1.6 +",
             guarded()),
        ]},
        "tests": {
            "per-tool ceiling (1500 tokens cl100k_base)":
                ["cargo test --lib sizes::tests::no_tool_exceeds_1500_tokens -- --exact"],
            "full-profile honest range (5K–8K cl100k_base)":
                ["cargo test --lib sizes::tests::full_profile_total_in_honest_measured_range"],
            "doctor --tokens default-profile-is-core":
                ["cargo test --lib cli::doctor::tests::run_tokens_human_default_profile_is_core"],
        },
    },
}
HOUSEKEEPING_PREFIXES = (ALWAYS, FAILURE)

# The allowlist coverage uses, by hand (invariant 7: never wider).
EXPECTED_DOCS_GLOBS = ["docs/**", "**/*.md"]
EXPECTED_EXIT = {"EXIT_FULL_RUN": 0, "EXIT_USAGE": 2, "EXIT_DOCS_ONLY": 3, "EXIT_UNREADABLE": 4}
EXPECTED_MAX_PATHS = 100_000
BIG_LIST_SECONDS = 20.0
EVENT_BASE_EXPR = "${{ github.event.pull_request.base.sha }}"
EXPECTED_ACTION_ENV = {
    # The sha the base copy is read at comes from the event itself (the taint scanner's base binding);
    # the caller's input must equal it or the run is full.
    "DOCS_GATE_BASE_SHA": EVENT_BASE_EXPR,
    "DOCS_GATE_INPUT_BASE_SHA": "${{ inputs.base-sha }}",
    "DOCS_GATE_EVENT_NAME": "${{ inputs.event-name }}",
    "DOCS_GATE_BASE_REF": "${{ inputs.base-ref }}",
}
GATE_FILES = ("__init__.py", "common.py", "cargo_skip.py", "docs_only_gate.py", "rules.json")
CHAIN_BASE = "chain/promo6-ssh-r2"
# The action (H1 of REVIEW-9696-code-r1): ONE step copies the BASE commit's gate files into RUNNER_TEMP
# with fixed `git show <base>:<path>` commands and then runs that base copy, so the code that maps the
# decider's exit to docs_only is the base copy. Every doubt before the run prints a full-run notice and
# exits 0 with docs_only empty; the run itself has errexit and no continue-on-error. Hand-written.
BASE_GATE_DIR = "$RUNNER_TEMP/docs-gate-base/impact"


def full_run_guard(why):
    return ('|| { echo "::notice::docs-only gate (#9683): %s; docs_only stays empty and the job runs in'
            ' full"; exit 0; }\n' % why)


EXPECTED_GATE_RUN = "".join(
    ['[[ "$DOCS_GATE_BASE_SHA" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ && "$DOCS_GATE_INPUT_BASE_SHA" =='
     ' "$DOCS_GATE_BASE_SHA" ]] ' + full_run_guard("the base sha is missing, malformed or not the event's"),
     '[[ -d "$RUNNER_TEMP" ]] ' + full_run_guard("RUNNER_TEMP is unset or not a directory"),
     'git cat-file -e "${DOCS_GATE_BASE_SHA}^{commit}" || git fetch --no-tags --no-recurse-submodules'
     ' --depth=1 origin "$DOCS_GATE_BASE_SHA" ' + full_run_guard("the base commit could not be fetched"),
     'rm -rf "$RUNNER_TEMP/docs-gate-base" && mkdir -p "%s" ' % BASE_GATE_DIR
     + full_run_guard("the base copy directory could not be made")]
    + ['git show "${DOCS_GATE_BASE_SHA:?}:scripts/ci/impact/%s" > "%s/%s" ' % (name, BASE_GATE_DIR, name)
       + full_run_guard("the base commit has no gate files") for name in GATE_FILES]
    + ['python3 -I "%s/docs_only_gate.py" step\n' % BASE_GATE_DIR])
EXPECTED_ACTION_STEPS = [
    # (id, if, continue-on-error, env)
    ("gate", "inputs.event-name == 'pull_request'", None, EXPECTED_ACTION_ENV),
]
EXPECTED_ACTION_OUTPUT = "${{ steps.gate.outputs.docs_only }}"
HEAD_GATE_PATH = "GITHUB_ACTION_PATH"

GATE = None


def setUpModule():
    global GATE
    if GATE_PATH.is_file():
        spec = importlib.util.spec_from_file_location("docs_only_gate_9683", GATE_PATH)
        GATE = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(GATE)


def need_gate(case):
    if GATE is None:
        case.fail("scripts/ci/impact/docs_only_gate.py is missing (#9683)")


# ---------------------------------------------------------------- workflow parse
def strip_value(raw):
    value = raw.strip()
    if " #" in value and not value.startswith(("'", '"')):
        value = value.split(" #", 1)[0].rstrip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return value


def parse_workflow(text):
    """Return (on_lines, {job_id: {"name", "if", "steps"}}) from a workflow's text.

    The workflows are block YAML with two-space indents: jobs at 2, job keys at 4,
    step items at 6 ('      - '), step keys at 8. Each step is a dict of its
    scalar keys plus 'with' and 'env' mappings and the raw lines.
    """
    lines = text.splitlines()
    on_lines, jobs, section = [], {}, None
    job = step = sub = None
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            section = line.split(":", 1)[0]
            job = step = sub = None
            continue
        if section == "on":
            on_lines.append(line)
            continue
        if section != "jobs":
            continue
        if indent == 2:
            job_id = line.strip().rstrip(":")
            job = jobs.setdefault(job_id, {"name": None, "if": None, "steps": [], "keys": []})
            step = sub = None
            continue
        if job is None:
            continue
        if indent == 4:
            key, _, value = line.strip().partition(":")
            job["keys"].append(key)
            if key in ("name", "if"):
                job[key] = strip_value(value)
            step = sub = None
            continue
        if indent == 6 and line.lstrip().startswith("- "):
            step = {"lines": [line], "with": {}, "env": {}}
            job["steps"].append(step)
            sub = None
            line = " " * 8 + line.lstrip()[2:]
            indent = 8
        if step is None:
            continue
        step["lines"].append(line)
        if indent == 8:
            key, _, value = line.strip().partition(":")
            sub = key if key in ("with", "env") and not value.strip() else None
            if sub is None and key not in step:
                step[key] = strip_value(value)
        elif indent == 10 and sub is not None:
            key, _, value = line.strip().partition(":")
            step[sub][key] = strip_value(value)
    return on_lines, jobs


def parse_action(text):
    """Return (inputs {name: default}, outputs {name: value}, steps) from the composite action's text.

    Block YAML with two-space indents: top-level keys at 0, input/output names at 2 and their keys at 4,
    step items at 4 ('    - '), step keys at 6, env entries at 8, and a `run: |` block at 8 or deeper.
    A step is a dict of its scalar keys, its 'env' mapping and its 'run' text (a literal block keeps one
    trailing newline, as YAML's clip chomping does).
    """
    inputs, outputs, steps = {}, {}, []
    section = name = step = None
    block = None
    for line in text.splitlines():
        indent = len(line) - len(line.lstrip(" "))
        if block is not None:
            if not line.strip() or indent >= 8:
                block.append(line[8:])
                continue
            step["run"] = "\n".join(block).rstrip("\n") + "\n"
            block = None
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if indent == 0:
            section = line.split(":", 1)[0]
            name = step = None
            continue
        if section in ("inputs", "outputs"):
            key, _, value = line.strip().partition(":")
            if indent == 2:
                name = key
                (inputs if section == "inputs" else outputs)[name] = None
            elif indent == 4 and section == "inputs" and key == "default":
                inputs[name] = strip_value(value)
            elif indent == 4 and section == "outputs" and key == "value":
                outputs[name] = strip_value(value)
            continue
        if section != "runs":
            continue
        if indent == 4 and line.lstrip().startswith("- "):
            step = {"env": {}}
            steps.append(step)
            line = " " * 6 + line.lstrip()[2:]
            indent = 6
        if step is None:
            continue
        key, _, value = line.strip().partition(":")
        if indent == 6:
            if key == "run" and value.strip() == "|":
                block = []
            elif key != "env":
                step[key] = strip_value(value)
        elif indent == 8:
            step["env"][key] = strip_value(value)
    if block is not None:
        step["run"] = "\n".join(block).rstrip("\n") + "\n"
    return inputs, outputs, steps


# The `if:` expressions the action may use, each with its meaning written by hand. An expression not in
# this table fails the test that runs the action, so a new condition is never evaluated by guesswork.
ACTION_CONDITIONS = {
    "inputs.event-name == 'pull_request'":
        lambda inputs, outcomes: inputs["event-name"] == "pull_request",
}
INPUT_EXPR = re.compile(r"^\$\{\{ inputs\.([a-z-]+) \}\}$")
STEP_OUTPUT_EXPR = re.compile(r"^\$\{\{ steps\.([a-z_]+)\.outputs\.([a-z_]+) \}\}$")


def label(step):
    if step.get("name"):
        return step["name"]
    return step.get("uses", "").split("@", 1)[0]


def read_workflow(name):
    return parse_workflow((WORKFLOWS / name).read_text(encoding="utf-8"))


class WorkflowShape(unittest.TestCase):
    """Every job of every touched workflow, against the hand-written sets."""

    def test_required_job_ids_and_names_are_unchanged_9683(self):
        for name, spec in EXPECTED.items():
            _, jobs = read_workflow(name)
            self.assertEqual({j: v["name"] for j, v in jobs.items()}, spec["jobs"], name)

    def test_job_level_if_is_unchanged_9683(self):
        for name, spec in EXPECTED.items():
            _, jobs = read_workflow(name)
            self.assertEqual({j: v["if"] for j, v in jobs.items()}, spec["job_if"], name)
            for job_id, job in jobs.items():
                # A second job-level key (a duplicate `if:` above the first)
                # would hide behind the last-value read above.
                self.assertEqual(len(job["keys"]), len(set(job["keys"])),
                                 "%s %s: duplicate job key" % (name, job_id))

    def test_no_paths_filter_on_any_trigger_9683(self):
        for name in EXPECTED:
            on_lines, _ = read_workflow(name)
            keys = [line.strip().split(":", 1)[0] for line in on_lines]
            self.assertNotIn("paths", keys, name)
            self.assertNotIn("paths-ignore", keys, name)

    def test_step_list_and_conditions_are_exact_9683(self):
        for name, spec in EXPECTED.items():
            _, jobs = read_workflow(name)
            for job_id, expected in spec["steps"].items():
                got = [(label(s), s.get("if")) for s in jobs[job_id]["steps"]]
                self.assertEqual(got, expected, "%s:%s" % (name, job_id))

    def test_gate_step_inputs_come_from_the_pr_base_9683(self):
        for name in EXPECTED:
            _, jobs = read_workflow(name)
            for job_id, job in jobs.items():
                gates = [s for s in job["steps"] if label(s) == GATE_LABEL]
                self.assertEqual(len(gates), 1, "%s:%s" % (name, job_id))
                gate = gates[0]
                self.assertEqual(gate.get("id"), GATE_ID)
                self.assertEqual(gate.get("uses"), GATE_USES)
                self.assertEqual(gate["with"], GATE_WITH, "%s:%s" % (name, job_id))
                self.assertNotIn("continue-on-error", gate)

    def test_every_step_after_the_gate_is_guarded_or_housekeeping_9683(self):
        for name in EXPECTED:
            _, jobs = read_workflow(name)
            for job_id, job in jobs.items():
                steps = job["steps"]
                labels = [label(s) for s in steps]
                self.assertIn(GATE_LABEL, labels, "%s:%s" % (name, job_id))
                at = labels.index(GATE_LABEL)
                for step in steps[:at + 1]:
                    self.assertNotIn(GUARD, step.get("if") or "", label(step))
                for step in steps[at + 1:]:
                    cond = step.get("if") or ""
                    if cond.startswith(HOUSEKEEPING_PREFIXES):
                        self.assertNotIn(GUARD, cond, label(step))
                    else:
                        self.assertTrue(cond == GUARD or cond.endswith(" && " + GUARD),
                                        "%s:%s %s" % (name, label(step), cond))
                        self.assertNotIn("||", cond, "an || would let the guard be bypassed")

    def test_the_same_tests_still_run_9683(self):
        for name, spec in EXPECTED.items():
            _, jobs = read_workflow(name)
            by_label = {label(s): s for job in jobs.values() for s in job["steps"]}
            for step_label, needles in spec["tests"].items():
                self.assertIn(step_label, sorted(by_label), name)
                body = "\n".join(by_label[step_label]["lines"])
                for needle in needles:
                    self.assertIn(needle, body, "%s: %s" % (name, step_label))


# The step-level `if:` terms the touched workflows may use, each evaluated by hand. A condition is
# terms joined by " && "; a term outside this table fails the test, so a new form is never guessed.
DOCS_TERM = re.compile(r"^steps\.docs\.outputs\.docs_only (==|!=) '([^']*)'$")
RUNNER_TERM = re.compile(r"^runner\.environment (==|!=) '([^']*)'$")
RUNNER_ENVIRONMENTS = ("github-hosted", "self-hosted")
# What the gate step can leave in docs_only: true skips work; empty (a doubt before the base copy, or
# an event other than pull_request) and false run in full.
DOCS_ONLY_VALUES = ("true", "", "false")
# The guarded steps that also carry a runner term (by hand); every other guarded step runs on both.
RUNNER_ONLY = {
    ("postgres-ignored.yml", ASSERT_RUSTUP): NOT_HOSTED,
    ("cert-postgres-age.yml", ASSERT_RUSTUP): NOT_HOSTED,
    ("cert-postgres-age.yml", "Swatinem/rust-cache"): HOSTED,
}


def step_runs(cond, docs_only, runner_env, failed=False):
    """Whether a step with `if: cond` runs in a job that has not failed, as GitHub evaluates it."""
    if cond is None:
        return not failed
    status = None
    result = True
    for term in cond.split(" && "):
        if term in (ALWAYS, FAILURE):
            status = term
            continue
        for pattern, actual in ((DOCS_TERM, docs_only), (RUNNER_TERM, runner_env)):
            match = pattern.match(term)
            if match:
                equal = actual == match.group(2)
                result = result and (equal if match.group(1) == "==" else not equal)
                break
        else:
            raise AssertionError("an `if:` term this harness cannot evaluate: %r" % term)
    if status == ALWAYS:
        return result
    if status == FAILURE:
        return failed and result
    return (not failed) and result


class WorkflowRun(unittest.TestCase):
    """Every step of every touched job, run through its `if:` for each docs_only value and runner."""

    def runs(self, name, job_id, docs_only, runner_env):
        _, jobs = read_workflow(name)
        return [label(s) for s in jobs[job_id]["steps"]
                if step_runs(s.get("if"), docs_only, runner_env)]

    def test_test_steps_run_unless_docs_only_is_true_9683(self):
        for name, spec in EXPECTED.items():
            for job_id in spec["jobs"]:
                for runner_env in RUNNER_ENVIRONMENTS:
                    for docs_only in DOCS_ONLY_VALUES:
                        with self.subTest(workflow=name, runner=runner_env, docs_only=docs_only):
                            ran = self.runs(name, job_id, docs_only, runner_env)
                            for step_label in spec["tests"]:
                                self.assertEqual(step_label in ran, docs_only != "true", step_label)

    def test_docs_only_true_runs_only_the_steps_before_the_gate_and_housekeeping_9683(self):
        for name, spec in EXPECTED.items():
            for job_id in spec["jobs"]:
                _, jobs = read_workflow(name)
                labels = [label(s) for s in jobs[job_id]["steps"]]
                before = labels[:labels.index(GATE_LABEL) + 1]
                for runner_env in RUNNER_ENVIRONMENTS:
                    with self.subTest(workflow=name, runner=runner_env):
                        ran = self.runs(name, job_id, "true", runner_env)
                        full = self.runs(name, job_id, "false", runner_env)
                        for step in jobs[job_id]["steps"]:
                            step_label = label(step)
                            if step_label in before or (step.get("if") or "").startswith(HOUSEKEEPING_PREFIXES):
                                self.assertEqual(step_label in ran, step_label in full, step_label)
                            else:
                                # Skipped on docs-only; on a full run only its runner term decides.
                                self.assertNotIn(step_label, ran)
                                runner_only = RUNNER_ONLY.get((name, step_label))
                                self.assertEqual(step_label in full,
                                                 step_runs(runner_only, "false", runner_env), step_label)

    def test_the_evaluator_reads_each_term_9683(self):
        """Controls for step_runs itself, written by hand."""
        self.assertTrue(step_runs(GUARD, "", "self-hosted"))
        self.assertFalse(step_runs(GUARD, "true", "self-hosted"))
        self.assertFalse(step_runs(guarded(NOT_HOSTED), "", "github-hosted"))
        self.assertTrue(step_runs(guarded(NOT_HOSTED), "false", "self-hosted"))
        self.assertTrue(step_runs(ALWAYS, "true", "github-hosted", failed=True))
        self.assertFalse(step_runs(FAILURE, "", "self-hosted"))
        self.assertTrue(step_runs(FAILURE, "", "self-hosted", failed=True))
        self.assertFalse(step_runs(SWEEP_IF, "", "github-hosted"))
        self.assertFalse(step_runs(None, "", "self-hosted", failed=True))
        with self.assertRaises(AssertionError):
            step_runs("steps.docs.outputs.docs_only != 'true' || always()", "", "self-hosted")


class GateAction(unittest.TestCase):
    """The composite action: inputs only through env, fixed git commands, the BASE copy's step."""

    def test_action_shape_9683(self):
        self.assertTrue(ACTION.is_file(), "missing %s" % ACTION)
        text = ACTION.read_text(encoding="utf-8")
        self.assertIn("using: composite", text)
        _, outputs, steps = parse_action(text)
        self.assertEqual(outputs, {"docs_only": EXPECTED_ACTION_OUTPUT})
        got = [(s.get("id"), s.get("if"), s.get("continue-on-error"), s["env"]) for s in steps]
        self.assertEqual(got, EXPECTED_ACTION_STEPS)
        self.assertEqual(steps[0]["run"], EXPECTED_GATE_RUN)
        for step in steps:
            self.assertEqual(step.get("shell"), "bash")
            self.assertNotIn("${{", step["run"])
            # The PR head's copy of the gate is never what runs.
            self.assertNotIn(HEAD_GATE_PATH, step["run"])

    def test_gate_step_has_no_continue_on_error_9683(self):
        _, _, steps = parse_action(ACTION.read_text(encoding="utf-8"))
        gates = [s for s in steps if s.get("id") == "gate"]
        self.assertEqual(len(gates), 1)
        self.assertNotIn("continue-on-error", gates[0])


class Allowlist(unittest.TestCase):
    def test_docs_globs_are_coverages_and_no_wider_9683(self):
        need_gate(self)
        section = GATE.load_section(RULES_PATH)
        self.assertEqual(section["docs_globs"], EXPECTED_DOCS_GLOBS)
        self.assertIs(GATE.DOCS_SECTION, GATE.cargo_skip.SECTION)

    def test_exit_codes_are_named_and_distinct_9683(self):
        need_gate(self)
        got = {k: getattr(GATE, k) for k in EXPECTED_EXIT}
        self.assertEqual(got, EXPECTED_EXIT)
        self.assertEqual(GATE.MAX_PATHS, EXPECTED_MAX_PATHS)


# ---------------------------------------------------------------- the table
def ns(*entries):
    """NUL-separated `git diff --name-status -z` bytes from (status, path...) tuples."""
    out = b""
    for entry in entries:
        for part in entry:
            out += (part if isinstance(part, bytes) else part.encode("utf-8")) + b"\0"
    return out


DOC_A = ("M", "docs/guide/intro.md")
DOC_B = ("A", "docs/notes/new-page.md")
DOC_C = ("M", "changelog.d/9683.md")
CODE = ("M", "src/lib.rs")

DOCS_ONLY_ROWS = {
    "one doc": ns(DOC_A),
    "three docs": ns(DOC_A, DOC_B, DOC_C),
    "a deleted doc": ns(("D", "docs/old.md")),
    "doc to doc rename": ns(("R100", "docs/a.md", "docs/b.md")),
    "doc to doc copy": ns(("C075", "docs/a.md", "docs/c.md")),
    "a type change on a doc": ns(("T", "docs/guide/intro.md")),
    "a txt under docs (coverage's docs/** glob)": ns(("A", "docs/notes.txt")),
}
FULL_ROWS = {
    "code first": ns(CODE, DOC_A, DOC_B),
    "code middle": ns(DOC_A, CODE, DOC_B),
    "code last": ns(DOC_A, DOC_B, CODE),
    "rename docs to code": ns(("R100", "docs/x.md", "src/x.rs")),
    "rename code to docs": ns(("R100", "src/x.rs", "docs/x.md")),
    "copy code to docs": ns(("C090", "src/x.rs", "docs/x.md")),
    "md under .github": ns(("M", ".github/PULL_REQUEST_TEMPLATE.md")),
    "md under .github/workflows": ns(("A", ".github/workflows/notes.md")),
    "md under scripts/ci": ns(("A", "scripts/ci/README-gate.md")),
    "a doc a test reads": ns(("M", "docs/API_REFERENCE.md")),
    "root README a test reads": ns(("M", "README.md")),
    "a toml config": ns(("M", "deploy/config.toml")),
    "a Cargo manifest": ns(("M", "Cargo.toml")),
    "a shell script": ns(("M", "docs/tools/build.sh")),
    "a migration": ns(("A", "migrations/0001_x.sql")),
}
UNREADABLE_ROWS = {
    "newline in path": ns(("M", "docs/a\nsrc/lib.rs.md")),
    "carriage return in path": ns(("M", "docs/a\r.md")),
    "leading dash": ns(("M", "-docs.md")),
    "leading dash segment": ns(("M", "docs/--output=x.md")),
    "dotdot segment": ns(("M", "docs/../src/lib.md")),
    "dot segment": ns(("M", "docs/./a.md")),
    "empty segment": ns(("M", "docs//a.md")),
    "absolute path": ns(("M", "/docs/a.md")),
    "trailing slash": ns(("M", "docs/a.md/")),
    "control char": ns(("M", "docs/a\x1b.md")),
    "non utf-8": ns(("M", b"docs/\xff.md")),
    "unknown status": ns(("X", "docs/a.md")),
    "unmerged status": ns(("U", "docs/a.md")),
    "rename without score": ns(("R", "docs/a.md", "docs/b.md")),
    "status with no path": b"M\0",
    "rename with one path": b"R100\0docs/a.md\0",
    "no trailing nul": b"M\0docs/a.md",
    "empty path": ns(("M", "")),
    "lowercase status": ns(("m", "docs/a.md")),
}


class Table(unittest.TestCase):
    def setUp(self):
        need_gate(self)
        self.section = GATE.load_section(RULES_PATH)

    def judge(self, raw, event="pull_request", base_ref=CHAIN_BASE):
        return GATE.decide(self.section, raw, event, base_ref)

    def test_docs_only_sets_9683(self):
        for row, raw in DOCS_ONLY_ROWS.items():
            code, _ = self.judge(raw)
            self.assertEqual(code, GATE.EXIT_DOCS_ONLY, row)

    def test_any_non_docs_path_is_a_full_run_9683(self):
        for row, raw in FULL_ROWS.items():
            code, reason = self.judge(raw)
            self.assertEqual(code, GATE.EXIT_FULL_RUN, "%s: %s" % (row, reason))

    def test_unreadable_input_is_unreadable_9683(self):
        for row, raw in UNREADABLE_ROWS.items():
            code, reason = self.judge(raw)
            self.assertEqual(code, GATE.EXIT_UNREADABLE, "%s: %s" % (row, reason))

    def test_empty_list_is_a_full_run_9683(self):
        code, reason = self.judge(b"")
        self.assertEqual(code, GATE.EXIT_FULL_RUN)
        self.assertIn("empty", reason)

    def test_push_merge_group_and_protected_bases_are_full_runs_9683(self):
        raw = DOCS_ONLY_ROWS["one doc"]
        for event, base_ref in (("push", ""), ("merge_group", ""), ("pull_request", "main"),
                                ("pull_request", "develop"), ("pull_request", "release/v1.0.0")):
            code, _ = self.judge(raw, event, base_ref)
            self.assertEqual(code, GATE.EXIT_FULL_RUN, "%s %s" % (event, base_ref))

    def test_more_paths_than_the_bound_is_unreadable_9683(self):
        raw = b"".join(b"M\0docs/p%d.md\0" % i for i in range(GATE.MAX_PATHS + 1))
        code, reason = self.judge(raw)
        self.assertEqual(code, GATE.EXIT_UNREADABLE)
        self.assertIn("bound", reason)

    def test_bytes_over_the_bound_are_unreadable_9683(self):
        raw = b"M\0docs/" + b"a" * GATE.MAX_INPUT_BYTES + b".md\0"
        code, _ = self.judge(raw)
        self.assertEqual(code, GATE.EXIT_UNREADABLE)

    def test_100k_docs_paths_within_the_time_bound_9683(self):
        raw = b"".join(b"M\0docs/area%d/page%d.md\0" % (i % 97, i)
                       for i in range(EXPECTED_MAX_PATHS))
        start = time.monotonic()
        code, _ = self.judge(raw)
        elapsed = time.monotonic() - start
        self.assertEqual(code, GATE.EXIT_DOCS_ONLY)
        self.assertLess(elapsed, BIG_LIST_SECONDS, "100K paths took %.2fs" % elapsed)

    def test_100k_paths_with_one_code_path_last_is_full_9683(self):
        raw = b"".join(b"M\0docs/p%d.md\0" % i for i in range(EXPECTED_MAX_PATHS - 1))
        raw += b"M\0src/lib.rs\0"
        start = time.monotonic()
        code, _ = self.judge(raw)
        self.assertLess(time.monotonic() - start, BIG_LIST_SECONDS)
        self.assertEqual(code, GATE.EXIT_FULL_RUN)

    def test_cli_stdin_exit_codes_9683(self):
        for raw, expected in ((DOCS_ONLY_ROWS["three docs"], GATE.EXIT_DOCS_ONLY),
                              (FULL_ROWS["code middle"], GATE.EXIT_FULL_RUN),
                              (UNREADABLE_ROWS["newline in path"], GATE.EXIT_UNREADABLE)):
            res = subprocess.run(
                [sys.executable, "-I", str(GATE_PATH), "decide", "--stdin",
                 "--rules", str(RULES_PATH), "--event-name", "pull_request",
                 "--base-ref", CHAIN_BASE],
                input=raw, capture_output=True, timeout=120, check=False)
            self.assertEqual(res.returncode, expected, res.stderr.decode("utf-8", "replace"))


# ---------------------------------------------------------------- step mode
def git_bytes(repo, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    # Same email-free identity as impact_fixture.GIT_IDENT.
    env.update({"GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture-ident",
                "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture-ident",
                "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(repo)})
    res = subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false"] + list(args),
                         capture_output=True, env=env, timeout=120, check=True)
    return res.stdout


def git(repo, *args):
    return git_bytes(repo, *args).decode("utf-8").strip()


GATE_REL = "scripts/ci/impact/docs_only_gate.py"
RULES_REL = "scripts/ci/impact/rules.json"
ACTION_REL = ".github/actions/docs-only-gate/action.yml"
# Where a base-commit copy of the gate gets a stand-in decider: right after the gate's own imports, so
# the `step` mode stays the real code and only `decide` is replaced.
DECIDE_SHIM_ANCHOR = "from impact import common  # noqa: E402\n"
DECIDE_SHIM = "\nif sys.argv[1:2] == ['decide']:\n%s\n"
UNKNOWN_EXITS = (1, 2, 4, 5, 7, 125, 255)
OWNER_READ_EXEC_ONLY = 0o500  # a directory the owner cannot write into
OWNER_FULL_ONLY = 0o700  # the restored mode: owner only
EXIT_FULL_RUN_CODE = 0  # the decider's full-run code, written by hand (not read from the gate)
# A rules file that calls every path documentation and no path CI code: what a PR could put in its
# own copy of rules.json to skip the heavy jobs if the head's rules were ever read.
ALL_DOCS_SECTION = {
    "walk_guards": [], "skip_globs": ["**"], "docs_globs": ["**"], "never_skip_globs": [],
    "test_read_globs": [], "ci_tree_globs": [], "ci_tree_exempt_globs": [], "full_ci_events": [],
    "full_ci_base_names": [], "full_ci_base_prefixes": []}
FULL_RUN_LITERAL = "docs_only stays empty and the job runs in full"
# Standard-library modules the gate's helpers import after the gate extends sys.path; a file of the
# same name beside impact/ must never be the one imported.
PLANTED_STDLIB_NAMES = ("json.py", "sqlite3.py")
# A sitecustomize a job could reach through PYTHONPATH: it claims docs-only and exits before the
# gate runs. The interpreter that runs the base copy is isolated, so it is never loaded.
STEERING_SITECUSTOMIZE = (
    "import os\n"
    "with open(os.environ['GITHUB_OUTPUT'], 'a') as out:\n"
    "    out.write('docs_only=true\\n')\n"
    "os._exit(0)\n")


def all_docs_rules():
    """This tree's rules.json with the cargo_skip lists replaced by ALL_DOCS_SECTION."""
    rules = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    rules["cargo_skip"].update(ALL_DOCS_SECTION)
    return json.dumps(rules, indent=2) + "\n"


class GateRepo(unittest.TestCase):
    """A scratch repository whose base commit carries this tree's gate files (no tests here)."""

    def setUp(self):
        need_gate(self)
        SCRATCH.mkdir(exist_ok=True)
        self.top = Path(tempfile.mkdtemp(prefix="gate9683-", dir=str(SCRATCH)))
        self.repo = self.top / "repo"
        self.repo.mkdir()
        self.runner_temp = self.top / "runner-temp"
        self.runner_temp.mkdir()
        git(self.repo, "init", "-q", "-b", "trunk")
        (self.repo / "docs").mkdir()
        (self.repo / "src").mkdir()
        (self.repo / "docs" / "a.md").write_text("a\n")
        (self.repo / "src" / "lib.rs").write_text("// x\n")
        self.add_gate_files()
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")

    def tearDown(self):
        shutil.rmtree(str(self.top), ignore_errors=True)

    def add_gate_files(self):
        target = self.repo / "scripts" / "ci" / "impact"
        target.mkdir(parents=True, exist_ok=True)
        for name in GATE_FILES:
            shutil.copyfile(str(IMPACT / name), str(target / name))
        action = self.repo / ACTION_REL
        action.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(ACTION), str(action))

    def commit(self, rel, text):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        git(self.repo, "add", rel)
        git(self.repo, "commit", "-q", "-m", rel)

    def edit(self, rel, change):
        """Commit `change(old text)` as the new text of `rel`."""
        self.commit(rel, change((self.repo / rel).read_text()))

    def new_base(self, rel, change):
        """Commit an edit of `rel` and make that commit the PR base."""
        self.edit(rel, change)
        self.base = git(self.repo, "rev-parse", "HEAD")

    def base_decider_exits(self, body):
        """Make the base commit's gate replace only its `decide` mode with `body` (indented code)."""
        def change(_old):
            text = GATE_PATH.read_text(encoding="utf-8")
            self.assertEqual(text.count(DECIDE_SHIM_ANCHOR), 1)
            return text.replace(DECIDE_SHIM_ANCHOR, DECIDE_SHIM_ANCHOR + DECIDE_SHIM % body)
        self.new_base(GATE_REL, change)

    def step_env(self, out, event, base, base_ref, runner_temp):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("GIT_", "GITHUB_", "RUNNER_", "DOCS_GATE_"))}
        env.update({"DOCS_GATE_EVENT_NAME": event,
                    "DOCS_GATE_BASE_SHA": self.base if base is None else base,
                    "DOCS_GATE_BASE_REF": base_ref, "GITHUB_OUTPUT": str(out),
                    "GITHUB_WORKSPACE": str(self.repo)})
        if runner_temp is not None:
            env["RUNNER_TEMP"] = str(runner_temp)
        return env

    def run_step(self, event="pull_request", base=None, base_ref=CHAIN_BASE, runner_temp=True):
        """Run this tree's gate step directly; return (the one output line, stdout)."""
        out = self.top / "github_output"
        out.write_text("")
        temp = self.runner_temp if runner_temp is True else runner_temp
        env = self.step_env(out, event, base, base_ref, temp)
        res = subprocess.run([sys.executable, "-I", str(GATE_PATH), "step"],
                             cwd=str(self.repo), env=env, capture_output=True,
                             timeout=300, check=False)
        self.assertEqual(res.returncode, 0, res.stderr.decode("utf-8", "replace"))
        lines = out.read_text().splitlines()
        self.assertEqual(len(lines), 1, lines)
        return lines[0], res.stdout.decode("utf-8", "replace")

    def run_action(self, event="pull_request", base=None, base_ref=CHAIN_BASE, runner_temp=True,
                   event_base=None, extra_env=None):
        """Run this tree's composite action the way the runner does; return a result dict.

        Each step runs as `bash --noprofile --norc -eo pipefail` (the runner's `shell: bash`) in the
        workspace, with the step's env (inputs and the event's base sha substituted), GITHUB_ACTION_PATH
        at the PR head's copy of the action, and its own GITHUB_OUTPUT. `event_base` is
        github.event.pull_request.base.sha (default: the base-sha input, as every caller passes it).
        `if:` comes from ACTION_CONDITIONS only; a failed step without continue-on-error fails the
        action. `extra_env` is added to every step's environment (a runner variable the job set).
        Keys: failed, docs_only, outcomes, stdout.
        """
        inputs_default, outputs, steps = parse_action(ACTION.read_text(encoding="utf-8"))
        inputs = dict(inputs_default)
        inputs.update({"base-sha": self.base if base is None else base, "event-name": event,
                       "base-ref": base_ref})
        expressions = {EVENT_BASE_EXPR: inputs["base-sha"] if event_base is None else event_base}
        bindir = self.top / "bin"
        bindir.mkdir(exist_ok=True)
        python3 = bindir / "python3"
        if not python3.exists():
            python3.symlink_to(sys.executable)
        action_path = self.repo / Path(ACTION_REL).parent
        action_path.mkdir(parents=True, exist_ok=True)
        temp = self.runner_temp if runner_temp is True else runner_temp
        outcomes, step_outputs, stdout = {}, {}, []
        for index, step in enumerate(steps):
            sid = step.get("id")
            condition = step.get("if")
            if condition is not None:
                self.assertIn(condition, ACTION_CONDITIONS, "an `if:` this harness cannot evaluate")
                if not ACTION_CONDITIONS[condition](inputs, outcomes):
                    if sid:
                        outcomes[sid] = "skipped"
                    continue
            out = self.top / ("step-output-%d" % index)
            out.write_text("")
            env = self.step_env(out, event, base, base_ref, temp)
            for key in ("DOCS_GATE_EVENT_NAME", "DOCS_GATE_BASE_SHA", "DOCS_GATE_BASE_REF"):
                env.pop(key)
            for key, value in step["env"].items():
                if value in expressions:
                    env[key] = expressions[value]
                    continue
                match = INPUT_EXPR.match(value)
                self.assertIsNotNone(match, value)
                env[key] = inputs[match.group(1)]
            env.update({"GITHUB_ACTION_PATH": str(action_path), "HOME": str(self.top),
                        "GIT_CONFIG_NOSYSTEM": "1",
                        "PATH": str(bindir) + os.pathsep + env.get("PATH", "/usr/bin:/bin")})
            env.update(extra_env or {})
            self.assertEqual(step.get("shell"), "bash")
            res = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
                                 cwd=str(self.repo), env=env, capture_output=True, timeout=300,
                                 check=False)
            stdout.append(res.stdout.decode("utf-8", "replace"))
            outcome = "success" if res.returncode == 0 else "failure"
            if sid:
                outcomes[sid] = outcome
                step_outputs[sid] = dict(line.split("=", 1) for line in out.read_text().splitlines()
                                         if "=" in line)
            if outcome == "failure" and step.get("continue-on-error") != "true":
                return {"failed": True, "docs_only": None, "outcomes": outcomes,
                        "stdout": "".join(stdout)}
        match = STEP_OUTPUT_EXPR.match(outputs["docs_only"])
        self.assertIsNotNone(match, outputs["docs_only"])
        value = step_outputs.get(match.group(1), {}).get(match.group(2), "")
        return {"failed": False, "docs_only": value, "outcomes": outcomes, "stdout": "".join(stdout)}


class StepMode(GateRepo):
    def test_docs_only_pr_writes_true_9683(self):
        self.commit("docs/b.md", "b\n")
        line, _ = self.run_step()
        self.assertEqual(line, "docs_only=true")

    def test_whole_pr_diff_not_the_last_commit_9683(self):
        self.commit("src/lib.rs", "// changed\n")
        self.commit("docs/b.md", "b\n")
        line, _ = self.run_step()
        self.assertEqual(line, "docs_only=false")

    def test_rename_code_to_docs_is_full_9683(self):
        git(self.repo, "mv", "src/lib.rs", "docs/lib.md")
        git(self.repo, "commit", "-q", "-m", "mv")
        line, _ = self.run_step()
        self.assertEqual(line, "docs_only=false")

    def test_rename_docs_to_code_is_full_9683(self):
        git(self.repo, "mv", "docs/a.md", "src/a.rs")
        git(self.repo, "commit", "-q", "-m", "mv")
        line, _ = self.run_step()
        self.assertEqual(line, "docs_only=false")

    def test_no_change_is_full_9683(self):
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "empty")
        line, _ = self.run_step()
        self.assertEqual(line, "docs_only=false")

    def test_missing_base_is_full_9683(self):
        self.commit("docs/b.md", "b\n")
        line, _ = self.run_step(base="ab" * 20)
        self.assertEqual(line, "docs_only=false")

    def test_malformed_base_is_full_9683(self):
        self.commit("docs/b.md", "b\n")
        for base in ("", "HEAD~1", "--output=x", "ab" * 19, "g" * 40):
            line, _ = self.run_step(base=base)
            self.assertEqual(line, "docs_only=false", base)

    def test_push_event_is_full_9683(self):
        self.commit("docs/b.md", "b\n")
        for event in ("push", "merge_group", "workflow_dispatch", ""):
            line, _ = self.run_step(event=event)
            self.assertEqual(line, "docs_only=false", event)

    def test_protected_base_is_full_9683(self):
        self.commit("docs/b.md", "b\n")
        line, _ = self.run_step(base_ref="main")
        self.assertEqual(line, "docs_only=false")

    def test_decider_absent_from_base_is_full_9683(self):
        shutil.rmtree(str(self.repo / "scripts"))
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "no gate")
        self.base = git(self.repo, "rev-parse", "HEAD")
        self.add_gate_files()
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "gate in the PR only")
        line, out = self.run_step()
        self.assertEqual(line, "docs_only=false")
        self.assertIn("base", out)

    def test_pr_edit_of_the_decider_does_not_judge_itself_9683(self):
        gate = self.repo / "scripts" / "ci" / "impact" / "docs_only_gate.py"
        gate.write_text(gate.read_text() + "\n# PR edit\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "edit gate")
        line, _ = self.run_step()
        self.assertEqual(line, "docs_only=false")


class StepDoubt(GateRepo):
    """Every doubt of the step is a full run (REVIEW-9696 M1, L1): one cell per doubt path."""

    def judge(self, base=None):
        return GATE.judge_step(self.repo, self.runner_temp, "pull_request",
                               self.base if base is None else base, CHAIN_BASE)

    def test_runner_temp_unset_is_a_full_run_9683(self):
        self.commit("docs/b.md", "b\n")
        line, out = self.run_step(runner_temp=None)
        self.assertEqual(line, "docs_only=false")
        self.assertIn("RUNNER_TEMP", out)
        self.assertEqual(sorted(p.name for p in self.repo.iterdir()), [".git", ".github", "docs", "scripts", "src"])

    def test_runner_temp_not_a_directory_is_a_full_run_9683(self):
        self.commit("docs/b.md", "b\n")
        afile = self.top / "a-file"
        afile.write_text("x")
        for temp in (self.top / "missing", afile, ""):
            with self.subTest(runner_temp=str(temp)):
                line, out = self.run_step(runner_temp=temp)
                self.assertEqual(line, "docs_only=false")
                self.assertIn("RUNNER_TEMP", out)

    def test_base_decider_unknown_exit_is_a_full_run_9683(self):
        for code in UNKNOWN_EXITS + (EXIT_FULL_RUN_CODE,):
            with self.subTest(exit=code):
                self.base_decider_exits("    sys.exit(%d)" % code)
                self.commit("docs/b%d.md" % code, "b\n")
                line, out = self.run_step()
                self.assertEqual(line, "docs_only=false")
                self.assertIn("rc=%d" % code, out)

    def test_base_decider_killed_by_a_signal_is_a_full_run_9683(self):
        self.base_decider_exits("    import os, signal\n    os.kill(os.getpid(), signal.SIGKILL)")
        self.commit("docs/b.md", "b\n")
        line, _ = self.run_step()
        self.assertEqual(line, "docs_only=false")

    def test_base_decider_docs_only_exit_is_the_only_true_9683(self):
        """Positive control for the cells above: the same shim with the docs-only code writes true."""
        self.base_decider_exits("    sys.exit(%d)" % GATE.EXIT_DOCS_ONLY)
        self.commit("src/lib.rs", "// changed\n")
        line, _ = self.run_step()
        self.assertEqual(line, "docs_only=true")

    def test_base_decider_is_not_asked_off_pull_request_9683(self):
        """Off pull_request the step writes false before it runs any decider: a base decider that
        always answers docs-only is not consulted (the decider's own event check is a second line)."""
        self.base_decider_exits("    sys.exit(%d)" % GATE.EXIT_DOCS_ONLY)
        self.commit("docs/b.md", "b\n")
        for event in ("push", "merge_group", "workflow_dispatch", ""):
            with self.subTest(event=event):
                line, out = self.run_step(event=event)
                self.assertEqual(line, "docs_only=false")
                self.assertIn("is not a pull request", out)

    def test_planted_stdlib_name_beside_impact_is_not_imported_9683(self):
        """The gate appends its parent to sys.path, so a json.py or sqlite3.py planted beside impact/
        never shadows the standard library (REVIEW-9696 L2); the copy still decides a full run."""
        tree = self.top / "planted" / "ci"
        (tree / "impact").mkdir(parents=True)
        for name in GATE_FILES:
            shutil.copyfile(str(IMPACT / name), str(tree / "impact" / name))
        for name in PLANTED_STDLIB_NAMES:
            (tree / name).write_text("raise SystemExit(%d)\n" % GATE.EXIT_DOCS_ONLY)
        for raw, expected in ((FULL_ROWS["code middle"], EXIT_FULL_RUN_CODE),
                              (DOCS_ONLY_ROWS["three docs"], GATE.EXIT_DOCS_ONLY)):
            res = subprocess.run([sys.executable, "-I", str(tree / "impact" / "docs_only_gate.py"),
                                  "decide", "--stdin", "--rules", str(tree / "impact" / "rules.json"),
                                  "--event-name", "pull_request", "--base-ref", CHAIN_BASE],
                                 input=raw, capture_output=True, timeout=120, check=False)
            self.assertEqual(res.returncode, expected, res.stderr.decode("utf-8", "replace"))

    def test_base_decider_timeout_is_a_full_run_9683(self):
        self.base_decider_exits("    import time\n    time.sleep(60)\n    sys.exit(%d)" % GATE.EXIT_DOCS_ONLY)
        self.commit("docs/b.md", "b\n")
        with unittest.mock.patch.object(GATE, "DECIDER_TIMEOUT_S", 2):
            started = time.monotonic()
            value, notice = self.judge()
        self.assertLess(time.monotonic() - started, 30)
        self.assertEqual(value, GATE.FALSE)
        self.assertIn("base decider did not run", notice)

    def test_base_decider_that_cannot_start_is_a_full_run_9683(self):
        self.commit("docs/b.md", "b\n")
        with unittest.mock.patch.object(GATE.sys, "executable", str(self.top / "no-such-python")):
            value, notice = self.judge()
        self.assertEqual(value, GATE.FALSE)
        self.assertIn("base decider did not run", notice)

    def test_unreadable_whole_pr_diff_is_a_full_run_9683(self):
        self.commit("docs/b.md", "b\n")
        # HEAD names a branch with no commit: the base and its blobs are readable, the diff is not.
        git(self.repo, "symbolic-ref", "HEAD", "refs/heads/unborn-9683")
        value, notice = self.judge()
        self.assertEqual(value, GATE.FALSE)
        self.assertIn("whole-PR diff unreadable", notice)
        line, _ = self.run_step()
        self.assertEqual(line, "docs_only=false")

    def test_exception_in_the_step_is_a_full_run_9683(self):
        self.commit("docs/b.md", "b\n")
        out = self.top / "github_output"
        for exc in (RuntimeError("boom"), KeyError("k"), ValueError("v"), OSError(5, "io"), Exception("e")):
            with self.subTest(exc=type(exc).__name__):
                out.write_text("")
                env = self.step_env(out, "pull_request", None, CHAIN_BASE, self.runner_temp)
                printed = io.StringIO()
                with unittest.mock.patch.dict(os.environ, env, clear=True), \
                        unittest.mock.patch.object(GATE, "judge_step", side_effect=exc), \
                        contextlib.redirect_stdout(printed):
                    code = GATE.cmd_step(None)
                self.assertEqual(code, GATE.EXIT_FULL_RUN)
                self.assertEqual(out.read_text(), "docs_only=false\n")
                self.assertIn("error", printed.getvalue())

    def test_decide_with_unreadable_rules_is_a_full_run_9683(self):
        bad = self.top / "rules.json"
        docs = b"M\0docs/a.md\0"
        for text in ("{", "[]", "{}", json.dumps({"known_jobs": [], "rules": []}), ""):
            with self.subTest(rules=text):
                bad.write_text(text)
                res = subprocess.run([sys.executable, "-I", str(GATE_PATH), "decide", "--stdin",
                                      "--rules", str(bad), "--event-name", "pull_request",
                                      "--base-ref", CHAIN_BASE],
                                     input=docs, capture_output=True, timeout=60, check=False)
                self.assertEqual(res.returncode, GATE.EXIT_FULL_RUN, res.stderr)
        res = subprocess.run([sys.executable, "-I", str(GATE_PATH), "decide", "--stdin",
                              "--rules", str(self.top / "missing.json"), "--event-name", "pull_request"],
                             input=docs, capture_output=True, timeout=60, check=False)
        self.assertEqual(res.returncode, GATE.EXIT_FULL_RUN, res.stderr)

    def test_base_rules_unreadable_is_a_full_run_9683(self):
        self.new_base(RULES_REL, lambda _text: "{\n")
        self.commit("docs/b.md", "b\n")
        line, _ = self.run_step()
        self.assertEqual(line, "docs_only=false")

    def test_notice_carries_no_workflow_command_9683(self):
        """Text from the environment reaches the notice through the shared escape (the #9365 class)."""
        hostile = ("push::error::x", "a\n::warning::y", "z##[error]w", "p%0A::notice::q", "r\u2028::debug::s")
        for event in hostile:
            with self.subTest(event=event):
                line, out = self.run_step(event=event)
                self.assertEqual(line, "docs_only=false")
                lines = out.splitlines()
                self.assertEqual(len(lines), 1, lines)
                self.assertTrue(lines[0].startswith("::notice::"), lines[0])
                rest = lines[0][len("::notice::"):]
                self.assertNotIn("::", rest)
                self.assertNotIn("##[", rest)
                self.assertNotIn("%", rest)


class ActionRun(GateRepo):
    """The composite action end to end: what runs on pull_request is the BASE copy (REVIEW-9696 H1)."""

    def test_head_gate_that_maps_full_run_to_docs_only_is_not_run_9683(self):
        """H1: a head whose step maps the decider's full-run exit to true, with a code change."""
        self.edit(GATE_REL, lambda t: t.replace("EXIT_DOCS_ONLY = 3\n", "EXIT_DOCS_ONLY = 0\n"))
        self.commit("src/lib.rs", "// changed\n")
        result = self.run_action()
        self.assertFalse(result["failed"], result)
        self.assertEqual(result["docs_only"], "false", result)

    def test_head_gate_replaced_by_a_stub_is_not_run_9683(self):
        """A head whose gate always says docs-only (step and decide alike) changes nothing."""
        self.commit(GATE_REL, "import sys\nsys.exit(%d)\n" % GATE.EXIT_DOCS_ONLY)
        self.commit("src/lib.rs", "// changed\n")
        result = self.run_action()
        self.assertFalse(result["failed"], result)
        self.assertEqual(result["docs_only"], "false", result)

    def test_head_rules_that_call_everything_docs_are_not_read_9683(self):
        self.commit(RULES_REL, all_docs_rules())
        self.commit("src/lib.rs", "// changed\n")
        result = self.run_action()
        self.assertFalse(result["failed"], result)
        self.assertEqual(result["docs_only"], "false", result)

    def test_head_helpers_are_not_imported_9683(self):
        """A head cargo_skip.py / common.py that would call everything docs is never imported."""
        self.edit("scripts/ci/impact/cargo_skip.py",
                  lambda t: t + "\n\ndef is_doc(section, path):\n    return True\n\n\n"
                                "def matches_any(globs, path):\n    return False\n")
        self.commit("src/lib.rs", "// changed\n")
        result = self.run_action()
        self.assertEqual(result["docs_only"], "false", result)

    def test_docs_only_pr_is_true_through_the_action_9683(self):
        self.commit("docs/b.md", "b\n")
        result = self.run_action()
        self.assertFalse(result["failed"], result)
        self.assertEqual(result["docs_only"], "true", result)
        self.assertEqual(result["outcomes"].get("gate"), "success")
        self.assertNotIn(FULL_RUN_LITERAL, result["stdout"])

    def test_pythonpath_sitecustomize_does_not_steer_the_base_copy_9683(self):
        """A job-level PYTHONPATH is not read by the isolated interpreter that runs the base copy, so a
        sitecustomize there cannot write docs_only=true for a code PR."""
        site = self.top / "site"
        site.mkdir()
        (site / "sitecustomize.py").write_text(STEERING_SITECUSTOMIZE)
        self.commit("src/lib.rs", "// changed\n")
        result = self.run_action(extra_env={"PYTHONPATH": str(site)})
        self.assertFalse(result["failed"], result)
        self.assertEqual(result["docs_only"], "false", result)

    def test_base_decider_unknown_exit_through_the_action_is_a_full_run_9683(self):
        for code in (1, 2, 4):
            with self.subTest(exit=code):
                self.base_decider_exits("    sys.exit(%d)" % code)
                self.commit("docs/b%d.md" % code, "b\n")
                result = self.run_action()
                self.assertEqual(result["docs_only"], "false", result)

    def test_pr_editing_the_action_is_a_full_run_by_the_base_rules_9683(self):
        """Bootstrap honesty: action.yml comes from the head, so a PR editing it never skips."""
        self.edit(ACTION_REL, lambda t: t + "# edited by the PR\n")
        result = self.run_action()
        self.assertEqual(result["docs_only"], "false", result)
        self.assertIn("ci-tree-edited-full-ci", result["stdout"])

    def test_pr_editing_a_workflow_is_a_full_run_by_the_base_rules_9683(self):
        for name in ("token-budget.yml", "postgres-ignored.yml", "cert-postgres-age.yml", "ci.yml"):
            with self.subTest(workflow=name):
                self.commit(".github/workflows/" + name, "# %s edited by the PR\n" % name)
                result = self.run_action()
                self.assertEqual(result["docs_only"], "false", result)
                self.assertIn("ci-tree-edited-full-ci", result["stdout"])

    def test_base_without_the_gate_is_a_full_run_through_the_action_9683(self):
        """decision: a base commit without a gate file (this PR's own bootstrap) leaves docs_only empty."""
        for name in GATE_FILES:
            with self.subTest(missing=name):
                git(self.repo, "rm", "-q", "%s/%s" % ("scripts/ci/impact", name))
                git(self.repo, "commit", "-q", "-m", "base without " + name)
                self.base = git(self.repo, "rev-parse", "HEAD")
                self.add_gate_files()
                git(self.repo, "add", "-A")
                git(self.repo, "commit", "-q", "-m", "gate in the PR only")
                self.commit("docs/b-%s.md" % name, "b\n")
                result = self.run_action()
                self.assertFalse(result["failed"], result)
                self.assertEqual(result["docs_only"], "", result)
                self.assertIn("the base commit has no gate files; " + FULL_RUN_LITERAL, result["stdout"])

    def test_missing_or_malformed_base_through_the_action_is_a_full_run_9683(self):
        self.commit("docs/b.md", "b\n")
        for base in ("ab" * 20, "", "HEAD~1", "--output=x", "g" * 40, self.base + "\n"):
            with self.subTest(base=base):
                result = self.run_action(base=base)
                self.assertFalse(result["failed"], result)
                self.assertEqual(result["docs_only"], "", result)
                self.assertIn(FULL_RUN_LITERAL, result["stdout"])

    def test_input_base_that_is_not_the_events_is_a_full_run_9683(self):
        """The copy is read at the event's base sha; a caller input naming another commit is a full run."""
        other = self.base
        self.commit("docs/b.md", "b\n")
        later = git(self.repo, "rev-parse", "HEAD")
        for input_base, event_base in ((later, other), (other, later), (other, "")):
            with self.subTest(input=input_base, event=event_base):
                result = self.run_action(base=input_base, event_base=event_base)
                self.assertFalse(result["failed"], result)
                self.assertEqual(result["docs_only"], "", result)
                self.assertIn("not the event's; " + FULL_RUN_LITERAL, result["stdout"])

    def test_runner_temp_unset_through_the_action_is_a_full_run_9683(self):
        self.commit("docs/b.md", "b\n")
        afile = self.top / "a-file"
        afile.write_text("x")
        for temp in (None, self.top / "missing", afile, ""):
            with self.subTest(runner_temp=str(temp)):
                result = self.run_action(runner_temp=temp)
                self.assertFalse(result["failed"], result)
                self.assertEqual(result["docs_only"], "", result)
                self.assertIn("RUNNER_TEMP is unset or not a directory; " + FULL_RUN_LITERAL, result["stdout"])

    def test_unfetchable_base_through_the_action_is_a_full_run_9683(self):
        """A well-formed base sha the clone lacks and no origin can serve is a full run, not a red job."""
        self.commit("docs/b.md", "b\n")
        result = self.run_action(base="ab" * 20)
        self.assertFalse(result["failed"], result)
        self.assertEqual(result["docs_only"], "", result)
        self.assertIn("the base commit could not be fetched; " + FULL_RUN_LITERAL, result["stdout"])

    def test_base_copy_dir_that_cannot_be_made_is_a_full_run_9683(self):
        self.commit("docs/b.md", "b\n")
        (self.runner_temp / "docs-gate-base").write_text("a file where the directory goes\n")
        # owner read+execute only: the owner is the sole user that must be refused, so no group or other bit is set
        os.chmod(str(self.runner_temp), OWNER_READ_EXEC_ONLY)
        try:
            result = self.run_action()
        finally:
            os.chmod(str(self.runner_temp), OWNER_FULL_ONLY)
        self.assertFalse(result["failed"], result)
        self.assertEqual(result["docs_only"], "", result)
        self.assertIn("the base copy directory could not be made; " + FULL_RUN_LITERAL, result["stdout"])

    def test_head_gitattributes_textconv_does_not_alter_the_base_copy_9683(self):
        """decision: `git show <sha>:<path>` over `git cat-file blob`; a blob is shown as its plain bytes,
        even with a head .gitattributes naming a textconv driver that would map docs-only onto full run."""
        git(self.repo, "config", "diff.evil9683.textconv",
            "sed 's/EXIT_DOCS_ONLY = 3/EXIT_DOCS_ONLY = 0/'")
        self.commit(".gitattributes", "*.py diff=evil9683\n")
        self.commit("src/lib.rs", "// changed\n")
        result = self.run_action()
        self.assertFalse(result["failed"], result)
        self.assertEqual(result["docs_only"], "false", result)
        copied = (self.runner_temp / "docs-gate-base" / "impact" / "docs_only_gate.py").read_bytes()
        self.assertEqual(copied, git_bytes(self.repo, "cat-file", "blob", "%s:%s" % (self.base, GATE_REL)))

    def test_stale_base_copy_is_replaced_9683(self):
        """A leftover RUNNER_TEMP copy that says docs-only is removed before the base copy is written."""
        stale = self.runner_temp / "docs-gate-base" / "impact"
        stale.mkdir(parents=True)
        (stale / "docs_only_gate.py").write_text("import sys\nsys.exit(3)\n")
        (stale / "extra.py").write_text("x = 1\n")
        (stale / "__pycache__").mkdir()
        self.commit("src/lib.rs", "// changed\n")
        result = self.run_action()
        self.assertEqual(result["docs_only"], "false", result)
        # __pycache__ is the base copy's own import cache from this run (rm -rf clears it every run).
        self.assertEqual(sorted(p.name for p in stale.iterdir() if p.name != "__pycache__"), sorted(GATE_FILES))
        self.assertNotIn("extra.py", [p.name for p in stale.iterdir()])

    def test_not_a_pull_request_through_the_action_is_a_full_run_9683(self):
        """Off pull_request the gate step never runs, even with a valid base sha in the event."""
        self.commit("docs/b.md", "b\n")
        for event in ("push", "merge_group", "workflow_dispatch", "pull_request_target", ""):
            with self.subTest(event=event):
                result = self.run_action(event=event, event_base=self.base)
                self.assertFalse(result["failed"], result)
                self.assertEqual(result["docs_only"], "", result)
                self.assertEqual(result["outcomes"].get("gate"), "skipped", result)

    def test_a_failing_gate_step_fails_the_job_9683(self):
        """No continue-on-error on the gate step: a base step that writes true and then fails is a red job."""
        def change(text):
            anchor = "def cmd_step(_args: argparse.Namespace) -> int:\n"
            self.assertEqual(text.count(anchor), 1)
            return text.replace(anchor, anchor + "    with open(os.environ['GITHUB_OUTPUT'], 'a') as h:\n"
                                        "        h.write('docs_only=true\\n')\n    sys.exit(1)\n")
        self.new_base(GATE_REL, change)
        self.commit("src/lib.rs", "// changed\n")
        result = self.run_action()
        self.assertTrue(result["failed"], result)
        self.assertIsNone(result["docs_only"])


class SharedEscape(unittest.TestCase):
    """common.safe_text is the gate's copy of the shared module's safe_text (the #9365 ratchet's name)."""

    def setUp(self):
        need_gate(self)
        spec = importlib.util.spec_from_file_location(
            "shared_annotation_9683", ROOT / "scripts" / "ci" / "workflow_annotation.py")
        self.shared = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.shared)

    def test_safe_text_matches_the_shared_module_for_every_code_point_9683(self):
        local = GATE.common.safe_text
        chunk = 4096
        for start in range(0, 0x110000, chunk):
            text = "".join(chr(code) for code in range(start, min(start + chunk, 0x110000)))
            self.assertEqual(local(text), self.shared.safe_text(text), hex(start))

    def test_safe_text_matches_the_shared_module_in_context_9683(self):
        local = GATE.common.safe_text
        pieces = (":", "#", "[", "%", "\\", "\n", "a", "\u2028", "\ud800", "]", ",")
        for a in pieces:
            for b in pieces:
                for c in pieces:
                    text = a + b + c
                    self.assertEqual(local(text), self.shared.safe_text(text), repr(text))
        for value in (None, 7, b"x", "::error::x", "##[warning]y", "C#", "#", ""):
            self.assertEqual(local(value), self.shared.safe_text(value), repr(value))


if __name__ == "__main__":
    unittest.main()
