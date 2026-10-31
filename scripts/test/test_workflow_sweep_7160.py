#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the #7160 target-cap sweep wiring in the CI workflows.

Read from the workflow text (stdlib only, Python 3.9+; PyYAML is not
guaranteed on every node). Properties:

  (a) every self-hosted leg of the ``check`` matrix runs exactly one sweep
      step, and a hosted leg runs none (the steps are guarded by
      ``runner.environment == 'self-hosted'``);
  (b) the shared_target leg (#7188, per-runner CARGO_TARGET_DIR outside the
      workspace) sweeps ``"$CARGO_TARGET_DIR"`` with ``--allow-root --within
      "$AI_MEMORY_CI_TARGET_ROOT"`` (#7297 S11: the script resolves both and
      requires the target strictly inside the root, so a symlinked cache
      parent such as f2's is accepted only by containment); every
      other self-hosted leg sweeps the workspace ``target`` without
      ``--allow-root``;
  (c) the cap literal is the one ``SELF_HOSTED_TARGET_CAP_BYTES`` value, the
      step runs ``always()``, docs-only skips it, and no sweep step may fail
      silently (no ``continue-on-error``);
  (d) the sweep never TARGETS the whole cache root: ``AI_MEMORY_CI_TARGET_ROOT``
      appears only as the ``--within`` containment root.

Run: python3 -m unittest scripts/test/test_workflow_sweep_7160.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"
CI_YML = WORKFLOWS / "ci.yml"
OTHER_WORKFLOWS = ("cert-postgres-age.yml", "postgres-ignored.yml")
SWEEP_SCRIPT = "scripts/ci-sweep-target.py"
CAP_ENV = "SELF_HOSTED_TARGET_CAP_BYTES"
CAP_VALUE = "42949672960"
CAP_ARG = "--max-bytes ${{ env.%s }}" % CAP_ENV
WORKSPACE_TARGET_ARG = "--target target "
SHARED_TARGET_ARG = '--target "${CARGO_TARGET_DIR:?'
ALLOW_ROOT = "--allow-root"
WITHIN_ARG = '--within "${AI_MEMORY_CI_TARGET_ROOT:?per-runner cache root not set}"'
LOCK_ARG = '--lock "${AI_MEMORY_CI_TARGET_ROOT:?per-runner cache root not set}/.evict.lock"'
SHARED_FLAG = "matrix.shared_target"
NOT_SHARED_FLAG = "!matrix.shared_target"
SELF_HOSTED_GUARD = "runner.environment == 'self-hosted'"
DOCS_ONLY_GUARD = "needs.classify.outputs.cargo_skip != 'true'"  # #8322
ROOT_ENV = "AI_MEMORY_CI_TARGET_ROOT"


def read(path):
    return path.read_text(encoding="utf-8")


def job_lines(text, job):
    """Lines of the top-level ``job:`` from its header to the next job."""
    lines = text.splitlines()
    start = lines.index("  %s:" % job)
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[i]):
            end = i
            break
    return lines[start:end]


def matrix_legs(job):
    """Map leg name -> its matrix include lines."""
    legs = {}
    current = None
    for ln in job:
        m = re.match(r"^          - leg: (\S+)\s*$", ln)
        if m:
            current = m.group(1)
            legs[current] = []
        elif current is not None:
            if re.match(r"^    steps:\s*$", ln):
                break
            legs[current].append(ln)
    return legs


def steps(job):
    """Split the job's ``steps:`` list into one line list per step."""
    out = []
    in_steps = False
    for ln in job:
        if re.match(r"^    steps:\s*$", ln):
            in_steps = True
            continue
        if not in_steps:
            continue
        if re.match(r"^      - ", ln):
            out.append([ln])
        elif out:
            out[-1].append(ln)
    return out


def sweep_steps(all_steps):
    return [s for s in all_steps if any(SWEEP_SCRIPT in ln for ln in s if not ln.lstrip().startswith("#"))]


def field(step, key):
    for ln in step:
        m = re.match(r"^\s+(?:- )?%s:\s*(.*)$" % re.escape(key), ln)
        if m:
            return m.group(1).strip()
    return ""


def runs_on_leg(step, shared):
    """Whether the step's ``if:`` can fire on a self-hosted leg of this shape."""
    cond = field(step, "if")
    if SELF_HOSTED_GUARD not in cond:
        return False
    if NOT_SHARED_FLAG in cond:
        return not shared
    if SHARED_FLAG in cond:
        return shared
    return True


class CheckJobSweep(unittest.TestCase):
    def setUp(self):
        self.job = job_lines(read(CI_YML), "check")
        self.legs = matrix_legs(self.job)
        self.sweeps = sweep_steps(steps(self.job))

    def self_hosted_legs(self):
        return {
            leg: lines
            for leg, lines in self.legs.items()
            if any("self-hosted" in ln and "runner:" in ln for ln in lines)
        }

    def test_check_matrix_has_self_hosted_and_shared_legs(self):
        hosted = [leg for leg in self.legs if leg not in self.self_hosted_legs()]
        self.assertTrue(self.self_hosted_legs(), "no self-hosted leg parsed")
        self.assertTrue(hosted, "no hosted leg parsed")
        shared = [
            leg for leg, lines in self.legs.items() if any("shared_target: true" in ln for ln in lines)
        ]
        self.assertEqual(shared, ["linux-fed,enterprise-fed"])

    def test_every_self_hosted_leg_runs_exactly_one_sweep_7160_s10(self):
        for leg, lines in self.self_hosted_legs().items():
            shared = any("shared_target: true" in ln for ln in lines)
            firing = [s for s in self.sweeps if runs_on_leg(s, shared)]
            self.assertEqual(len(firing), 1, "leg %s runs %d sweep steps" % (leg, len(firing)))

    def test_shared_leg_sweeps_its_own_cargo_target_dir_7160_s10(self):
        step = [s for s in self.sweeps if runs_on_leg(s, True)][0]
        run = field(step, "run")
        self.assertIn(SHARED_TARGET_ARG, run)
        self.assertIn(ALLOW_ROOT + " " + WITHIN_ARG + " " + LOCK_ARG, run)
        self.assertNotIn(WORKSPACE_TARGET_ARG, run)
        self.assertEqual(run.count(ROOT_ENV), 2, "the cache root is only the --within root and the lock dir")
        self.assertNotIn("--target " + ROOT_ENV, run)
        self.assertNotIn('--target "$' + ROOT_ENV, run)

    def test_shared_step_executes_on_symlinked_cache_root_7297_s11(self):
        """Run the exact step line on the f2 layout (``~/.cache/ai-memory-ci`` is a
        symlink to another disk) with the env the #7188 helper exports: rc 0 and
        the per-runner directory is capped (the workflow text pins above cannot
        see a symlinked ancestor)."""
        scratch = REPO / ".local-runs"
        scratch.mkdir(exist_ok=True)
        base = Path(tempfile.mkdtemp(prefix="wf7297-", dir=str(scratch)))
        try:
            disk = base / "mnt-t9" / "ai-memory-ci"
            disk.mkdir(parents=True)
            home = base / "hm"
            (home / ".cache").mkdir(parents=True)
            os.symlink(str(disk), str(home / ".cache" / "ai-memory-ci"))
            github_env = base / "github_env"
            github_env.write_text("")
            helper = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "ci" / "shared_cargo_target.py"),
                 "--home", str(home), "--runner-name", "f2-linux-fed",
                 "--github-env", str(github_env)],
                capture_output=True, text=True, check=False)
            self.assertEqual(helper.returncode, 0, helper.stderr)
            env = dict(os.environ)
            for line in github_env.read_text().splitlines():
                key, value = line.split("=", 1)
                env[key] = value
            deps = Path(env["CARGO_TARGET_DIR"]) / "debug" / "deps"
            deps.mkdir(parents=True)
            for idx in range(4):
                (deps / ("lib%d.rlib" % idx)).write_bytes(b"x" * 600)
            step = [s for s in self.sweeps if runs_on_leg(s, True)][0]
            run = field(step, "run").replace("${{ env.%s }}" % CAP_ENV, "1000")
            result = subprocess.run(["bash", "-e", "-c", run], cwd=str(REPO), env=env,
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("freed=1800", result.stdout)
            self.assertEqual(len(list(deps.iterdir())), 1)
        finally:
            shutil.rmtree(str(base), ignore_errors=True)

    def test_workspace_legs_sweep_workspace_target_without_allow_root_7160_s10(self):
        step = [s for s in self.sweeps if runs_on_leg(s, False)][0]
        run = field(step, "run")
        self.assertIn(WORKSPACE_TARGET_ARG, run)
        self.assertNotIn(ALLOW_ROOT, run)
        self.assertNotIn("CARGO_TARGET_DIR", run)

    def test_sweep_steps_keep_reviewed_properties_7160_s10(self):
        self.assertEqual(len(self.sweeps), 2)
        for step in self.sweeps:
            cond = field(step, "if")
            self.assertTrue(cond.startswith("always() && "), cond)
            self.assertIn(DOCS_ONLY_GUARD, cond)
            self.assertIn(SELF_HOSTED_GUARD, cond)
            self.assertEqual(field(step, "continue-on-error"), "")
            self.assertIn(CAP_ARG, field(step, "run"))

    def test_sweep_steps_come_after_the_prune_step_7160_s10(self):
        all_steps = steps(self.job)
        prune = [i for i, s in enumerate(all_steps) if any("prune_runner_artifacts.py" in ln for ln in s)]
        sweep = [i for i, s in enumerate(all_steps) if s in self.sweeps]
        self.assertEqual(len(prune), 1)
        self.assertEqual(len(sweep), 2)
        self.assertGreater(min(sweep), prune[0])
        self.assertEqual(max(sweep), len(all_steps) - 1, "the sweep steps are the last steps")


class CapLiteral(unittest.TestCase):
    def test_cap_literal_is_unchanged_in_every_workflow_7160(self):
        for name in ("ci.yml",) + OTHER_WORKFLOWS:
            text = read(WORKFLOWS / name)
            self.assertIn("  %s: %s\n" % (CAP_ENV, CAP_VALUE), text, name)

    def test_other_workflows_sweep_the_workspace_target_7160(self):
        for name in OTHER_WORKFLOWS:
            text = read(WORKFLOWS / name)
            found = sweep_steps(
                [s for jb in re.findall(r"(?ms)^      - .*?(?=^      - |\Z)", text) for s in [jb.splitlines()]]
            )
            self.assertEqual(len(found), 1, name)
            run = field(found[0], "run")
            self.assertIn(WORKSPACE_TARGET_ARG, run)
            self.assertNotIn(ALLOW_ROOT, run)
            self.assertIn(CAP_ARG, run)
            self.assertTrue(field(found[0], "if").startswith("always() && "))
            self.assertEqual(field(found[0], "continue-on-error"), "")


class SweepTestsRunInCi(unittest.TestCase):
    """#7160 F3: a CI step runs the sweep unit tests, so the Linux-only S7 test executes there."""

    SWEEP_TEST_FILE = "scripts/test/test_ci_sweep_target.py"
    PIN_TEST_FILE = "scripts/test/test_workflow_sweep_7160.py"
    DISCOVERY = "python3 -m unittest discover -s scripts/ci/tests"

    def setUp(self):
        self.classify = steps(job_lines(read(CI_YML), "classify"))

    def runs(self, test_file):
        return [
            s for s in self.classify
            if "unittest" in field(s, "run") and test_file in field(s, "run")
        ]

    def test_classify_job_runs_the_sweep_unit_tests_7160_f3(self):
        found = self.runs(self.SWEEP_TEST_FILE)
        self.assertEqual(len(found), 1, "no classify step runs %s" % self.SWEEP_TEST_FILE)
        self.assertEqual(field(found[0], "if"), "", "the sweep tests must run on every event")
        self.assertEqual(field(found[0], "continue-on-error"), "")

    def test_classify_job_runs_the_sweep_workflow_pin_7160_f3(self):
        self.assertEqual(len(self.runs(self.PIN_TEST_FILE)), 1)

    def test_existing_discovery_step_is_intact_7160_f3(self):
        found = [s for s in self.classify if field(s, "run") == self.DISCOVERY]
        self.assertEqual(len(found), 1)

    def test_classify_job_runs_on_linux_so_o_path_exists_7160_f3(self):
        self.assertIn("    runs-on: ubuntu-latest", job_lines(read(CI_YML), "classify"))


if __name__ == "__main__":
    unittest.main()
