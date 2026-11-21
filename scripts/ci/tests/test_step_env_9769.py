#!/usr/bin/env python3
"""#9769: every harness that executes the `Run tests (impact-aware)` step body uses the step env of ci.yml.

Class: a harness ran the step body with an environment the workflow never produces (it lacked
CI_PG_ISOLATE_OFF, which ci.yml always supplies, so the fail-closed kill-switch read raised in the
harness only). Invariant: each harness builds its env through workflow_text.step_exec_env, so every key
of the step's `env:` block is present with the value Actions gives it when nothing is set (the empty
string for an expression), and a runner-level value of a step key never leaks in.

The harnesses are called with subprocess.run replaced by a recorder, so this module runs no step body.

Run: python3 -m unittest discover -s scripts/ci/tests -p test_step_env_9769.py
"""
import importlib.util
import os
import re
import subprocess
import sys
import unittest
import unittest.mock as mock
from pathlib import Path

# `python3 -I FILE` leaves the script's own folder off sys.path; append it (never insert at 0) (#9592).
sys.path.append(str(Path(__file__).resolve().parent))
import workflow_text  # noqa: E402

HERE = Path(__file__).resolve().parent
KILL_SWITCH = "CI_PG_ISOLATE_OFF"
# Written out by hand from ci.yml (job check, step Run tests (impact-aware), env block): the run-time
# value of each key when no repository variable, matrix value or job output is set.
EXPECTED_STEP_ENV = {
    "AI_MEMORY_NO_CONFIG": "1",
    "TIER": "",
    "CI_NODE": "",
    "TEST_IMPACT": "",
    "DOCS_ONLY": "",
    "TEST_IMPACT_REASON": "",
    "TEST_IMPACT_COUNT": "",
    "TEST_IMPACT_TOTAL": "",
    "JOB_TIMEOUT_MIN": "",
    KILL_SWITCH: "",
    "HOST_SEMAPHORE_SLOTS": "",
    "HOST_SEMAPHORE_MAX_WAIT_SECS": "3600",
}
# A runner-level value of each step key (and of the kill switch) that must not reach a harness.
LEAKED = "leaked-from-runner"
# Harness modules: file name -> loader name (loaded by path, so their test classes are not collected twice).
HARNESS_FILES = {
    "6795": "test_ci_test_step_exec_6795.py",
    "9229": "test_suite_budget_9229.py",
    "9229_integrity": "test_suite_budget_9229_integrity.py",
    "8328": "test_impact_cargo_skip_8328.py",
}
# The keys each harness sets itself for its fixture; every other step key keeps the step value.
FIXTURE_KEYS = {
    "6795": {"AI_MEMORY_NO_CONFIG", "TIER", "CI_NODE", "TEST_IMPACT", "JOB_TIMEOUT_MIN"},
    "9229": {"AI_MEMORY_NO_CONFIG", "TIER", "CI_NODE", "TEST_IMPACT", "JOB_TIMEOUT_MIN"},
    "9229_integrity_step": {"AI_MEMORY_NO_CONFIG", "TIER", "CI_NODE", "TEST_IMPACT", "JOB_TIMEOUT_MIN"},
    "9229_integrity_real_time": set(),
    "8328_whole": {"AI_MEMORY_NO_CONFIG", "TIER", "CI_NODE", "TEST_IMPACT", "DOCS_ONLY", "JOB_TIMEOUT_MIN",
                   "HOST_SEMAPHORE_SLOTS"},
    "8328_boundary": {"TEST_IMPACT", "DOCS_ONLY"},
}


# Allowlist ratchet over every tracked file under scripts/ (the whole tree where workflow tests live): a
# file that names the Run tests step (plain or regex-escaped) and starts bash is a step-exec harness and
# must be in HARNESS_FILES; each other file that names the step is listed here with its reason.
REPO = HERE.parents[2]
SCAN_ROOT = "scripts"
NAMES_STEP_RE = re.compile(r"Run tests \\?\(impact-aware|RUN_TESTS_STEP|step_exec_env\(")
STARTS_BASH_RE = re.compile(r"""['"](?:/bin/|/usr/bin/env )?bash['"]|RUNNER_BASH|^\s*bash\s""", re.M)
NOT_STEP_EXEC = {
    "scripts/ci/tests/workflow_text.py": "the helper itself; reads the workflow text, runs nothing",
    "scripts/ci/tests/test_step_env_9769.py": "this module; subprocess.run is a recorder here",
    "scripts/ci/check_pg_isolate_invariants.py": "the gate; parses ci.yml, runs no step body",
    "scripts/ci/taint_boundary.py": "a static parser of run steps ('bash' is a table key); executes nothing",
    "scripts/ci/tests/test_check_pg_isolate_invariants.py": "runs the gate script, not a step body",
    "scripts/ci/tests/test_ci_check_matrix_max_parallel_9682.py": "text pins on the job matrix",
    "scripts/ci/tests/test_ci_load_gate_wiring_6795.py": "text pins on the step wiring",
    "scripts/ci/tests/test_ci_semaphore_wiring_7914.py": "text pins on the semaphore wiring",
    "scripts/ci/tests/test_ci_tainted_job_boundary.py": "text pins on the job boundary",
    "scripts/ci/tests/test_ci_tainted_job_boundary_open_rows.py": "text pins on the job boundary rows",
    "scripts/test/test-ci-workflow-invariants.sh": "grep pins on ci.yml text, runs no step body",
}


def step_exec_files():
    """Tracked files under SCAN_ROOT that name the step and start bash, and those that only name it."""
    listed = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z", "--", SCAN_ROOT], capture_output=True,
                            check=True).stdout.decode("utf-8", "surrogateescape").split("\0")
    execs, names = set(), set()
    for rel in filter(None, listed):
        try:
            text = (REPO / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if NAMES_STEP_RE.search(text):
            (execs if STARTS_BASH_RE.search(text) else names).add(rel)
    return execs, names


def load(key):
    """The harness module `key`, loaded by path under a private name."""
    spec = importlib.util.spec_from_file_location("step_env_9769_" + key, str(HERE / HARNESS_FILES[key]))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Recorder:
    """Stands in for subprocess.run: records the env of each call and returns a passing result."""

    def __init__(self, stdout=""):
        self.envs = []
        self.stdout = stdout

    def __call__(self, args, **kwargs):
        self.envs.append(dict(kwargs.get("env") or {}))
        return subprocess.CompletedProcess(args, 0, stdout=self.stdout, stderr="")


def leaky_environ():
    """os.environ with every step key set to LEAKED (the runner-level values a harness must not inherit)."""
    return mock.patch.dict(os.environ, {key: LEAKED for key in EXPECTED_STEP_ENV})


class StepEnvHelper(unittest.TestCase):
    def test_step_env_is_the_env_block_with_unset_expressions_empty(self):
        self.assertEqual(workflow_text.step_env(), EXPECTED_STEP_ENV)

    def test_env_value_table(self):
        rows = (
            ("${{ vars.CI_PG_ISOLATE_OFF }}", ""),
            ('"1"', "1"),
            ("'3600'", "3600"),
            ("${{ a }}-${{ b }}", "-"),
            ("plain", "plain"),
            ("  spaced  ", "spaced"),
            ("'", "'"),
            ("'1\"", "'1\""),
        )
        for raw, expected in rows:
            self.assertEqual(workflow_text.env_value(raw), expected, raw)

    def test_runner_value_of_a_step_key_never_leaks(self):
        env = workflow_text.step_exec_env({"TIER": "sqlite"}, base={KILL_SWITCH: "1", "PATH": "/bin"})
        self.assertEqual(env[KILL_SWITCH], "")
        self.assertEqual(env["TIER"], "sqlite")
        self.assertEqual(env["PATH"], "/bin")

    def test_absent_or_duplicate_step_is_refused(self):
        with self.assertRaises(LookupError) as ctx:
            workflow_text.step_env(step="no such step")
        self.assertEqual(str(ctx.exception), "0 steps named 'no such step' in job 'check' of %s"
                         % workflow_text.CI_YML)


class HarnessAllowlist(unittest.TestCase):
    def test_every_step_exec_harness_is_listed(self):
        execs, names = step_exec_files()
        harness = {"scripts/ci/tests/" + name for name in HARNESS_FILES.values()}
        self.assertEqual(sorted(execs - harness - set(NOT_STEP_EXEC)), [],
                         "a file names the Run tests step and starts bash but is not in HARNESS_FILES")
        self.assertEqual(sorted(harness - execs), [], "a listed harness no longer starts bash")
        self.assertEqual(sorted(set(NOT_STEP_EXEC) - execs - names), [], "a stale NOT_STEP_EXEC entry")

    def test_every_harness_builds_its_env_through_the_helper(self):
        for key, name in HARNESS_FILES.items():
            text = (HERE / name).read_text(encoding="utf-8")
            self.assertIn("workflow_text.step_exec_env(", text, key)


class HarnessEnv(unittest.TestCase):
    """Each harness's step env holds every step key at the step value (fixture keys excepted)."""

    def assert_step_env(self, name, env):
        missing = sorted(set(EXPECTED_STEP_ENV) - set(env))
        self.assertEqual(missing, [], "%s: step keys missing from the harness env" % name)
        for key, value in EXPECTED_STEP_ENV.items():
            if key in FIXTURE_KEYS[name]:
                self.assertNotEqual(env[key], LEAKED, "%s: %s" % (name, key))
            else:
                self.assertEqual(env[key], value, "%s: %s" % (name, key))

    def test_6795_run_step(self):
        module = load("6795")
        rec = Recorder()
        with leaky_environ(), mock.patch.object(module.subprocess, "run", rec):
            module.StepExec("run_step").run_step("1")
        self.assertEqual(len(rec.envs), 1)
        self.assert_step_env("6795", rec.envs[0])

    def test_9229_run_step(self):
        module = load("9229")
        rec = Recorder()
        with leaky_environ(), mock.patch.object(module.subprocess, "run", rec):
            module.StepExec("run_step").run_step()
        self.assertEqual(len(rec.envs), 1)
        self.assert_step_env("9229", rec.envs[0])

    def test_9229_integrity_run_step(self):
        module = load("9229_integrity")
        rec = Recorder()
        with leaky_environ(), mock.patch.object(module.subprocess, "run", rec):
            module.run_step(module.base.step_script())
        self.assertEqual(len(rec.envs), 1)
        self.assert_step_env("9229_integrity_step", rec.envs[0])

    def test_9229_integrity_run_real_time(self):
        module = load("9229_integrity")
        rec = Recorder()
        with leaky_environ(), mock.patch.object(module.subprocess, "run", rec):
            module.run_real_time(0)
        self.assertEqual(len(rec.envs), 1)
        self.assert_step_env("9229_integrity_real_time", rec.envs[0])

    def test_8328_run_whole_step(self):
        module = load("8328")
        rec = Recorder()
        with leaky_environ(), mock.patch.object(module.subprocess, "run", rec):
            module.run_whole_step("__ALL__")
        self.assertEqual(len(rec.envs), 1)
        self.assert_step_env("8328_whole", rec.envs[0])

    def test_8328_consumer_boundary(self):
        module = load("8328")
        rec = Recorder(stdout="RESULT=__ALL__\n")
        with leaky_environ(), mock.patch.object(module.subprocess, "run", rec):
            module.ConsumerBoundary("boundary_block").resolve("__ALL__", "false")
        self.assertEqual(len(rec.envs), 1)
        self.assert_step_env("8328_boundary", rec.envs[0])


if __name__ == "__main__":
    unittest.main()
