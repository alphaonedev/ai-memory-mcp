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
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
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
EXPECTED_ACTION_RUN = 'python3 -I "${GITHUB_ACTION_PATH}/../../../scripts/ci/impact/docs_only_gate.py" step'
EXPECTED_ACTION_ENV = {
    "DOCS_GATE_BASE_SHA": "${{ inputs.base-sha }}",
    "DOCS_GATE_EVENT_NAME": "${{ inputs.event-name }}",
    "DOCS_GATE_BASE_REF": "${{ inputs.base-ref }}",
}
GATE_FILES = ("__init__.py", "common.py", "cargo_skip.py", "docs_only_gate.py", "rules.json")
CHAIN_BASE = "chain/promo6-ssh-r2"

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


class GateAction(unittest.TestCase):
    """The composite action: inputs only through env, one closed-form run line."""

    def test_action_shape_9683(self):
        self.assertTrue(ACTION.is_file(), "missing %s" % ACTION)
        text = ACTION.read_text(encoding="utf-8")
        runs = [line.strip()[len("run:"):].strip() for line in text.splitlines()
                if line.strip().startswith("run:")]
        self.assertEqual(runs, [EXPECTED_ACTION_RUN])
        env = dict(re.findall(r"^\s+(DOCS_GATE_[A-Z_]+):\s*(.+?)\s*$", text, re.M))
        self.assertEqual(env, EXPECTED_ACTION_ENV)
        self.assertIn("using: composite", text)
        self.assertRegex(text, r"(?m)^\s+docs_only:\s*$")
        self.assertIn("${{ steps.gate.outputs.docs_only }}", text)
        for line in text.splitlines():
            if line.strip().startswith("run:"):
                self.assertNotIn("${{", line)


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
def git(repo, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
                "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(repo)})
    res = subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false"] + list(args),
                         capture_output=True, env=env, timeout=120, check=True)
    return res.stdout.decode("utf-8").strip()


class StepMode(unittest.TestCase):
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
        target.mkdir(parents=True)
        for name in GATE_FILES:
            shutil.copyfile(str(IMPACT / name), str(target / name))

    def commit(self, rel, text):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        git(self.repo, "add", rel)
        git(self.repo, "commit", "-q", "-m", rel)

    def run_step(self, event="pull_request", base=None, base_ref=CHAIN_BASE):
        out = self.top / "github_output"
        out.write_text("")
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update({"DOCS_GATE_EVENT_NAME": event,
                    "DOCS_GATE_BASE_SHA": self.base if base is None else base,
                    "DOCS_GATE_BASE_REF": base_ref, "GITHUB_OUTPUT": str(out),
                    "GITHUB_WORKSPACE": str(self.repo), "RUNNER_TEMP": str(self.runner_temp)})
        res = subprocess.run([sys.executable, "-I", str(GATE_PATH), "step"],
                             cwd=str(self.repo), env=env, capture_output=True,
                             timeout=300, check=False)
        self.assertEqual(res.returncode, 0, res.stderr.decode("utf-8", "replace"))
        lines = out.read_text().splitlines()
        self.assertEqual(len(lines), 1, lines)
        return lines[0], res.stdout.decode("utf-8", "replace")

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


if __name__ == "__main__":
    unittest.main()
