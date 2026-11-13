# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin scripts/ci/check_pg_preflight_workflows.py and the coverage.yml wiring (#9235).

Invariant: every workflow that starts a hosted-runner PostgreSQL runs the
preflight step BEFORE the coverage/test step, with no `continue-on-error`
and no `if:`.  Deliberately broken copies of the real workflow must be red
with the exact problem text.
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = Path(__file__).resolve().parents[1] / "check_pg_preflight_workflows.py"
SPEC = importlib.util.spec_from_file_location("check_pg_preflight_workflows", SCRIPT)
CHK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHK
SPEC.loader.exec_module(CHK)

WORKFLOW = ROOT / ".github/workflows/coverage.yml"
LABEL = "coverage.yml"
PREFLIGHT_NAME = "PostgreSQL package repair + preflight (#9235)"
GENERATE_NAME = "Generate coverage JSON"


class WorkflowCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def preflight_block(self):
        start = self.text.index(f"      - name: {PREFLIGHT_NAME}")
        end = self.text.index(f"      - name: {GENERATE_NAME}")
        return start, end

    def test_real_coverage_workflow_is_clean(self):
        self.assertEqual(CHK.check_text(self.text, LABEL), [])

    def test_default_workflows_cover_coverage_yml(self):
        self.assertEqual(CHK.DEFAULT_WORKFLOWS, (".github/workflows/coverage.yml",))

    def test_absent_preflight_is_red(self):
        start, end = self.preflight_block()
        broken = self.text[:start] + self.text[end:]
        self.assertEqual(
            CHK.check_text(broken, LABEL),
            [f"{LABEL}: preflight step (scripts/ci/pg_env_preflight.py) is absent"],
        )

    def test_preflight_after_coverage_step_is_red(self):
        start, end = self.preflight_block()
        block = self.text[start:end]
        without = self.text[:start] + self.text[end:]
        anchor = "      - name: Enforce per-module thresholds"
        broken = without.replace(anchor, block + anchor, 1)
        problems = CHK.check_text(broken, LABEL)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn(f"preflight step '{PREFLIGHT_NAME}'", problems[0])
        self.assertIn("is placed after the coverage/test step", problems[0])

    def test_continue_on_error_is_red(self):
        broken = self.text.replace(
            f"      - name: {PREFLIGHT_NAME}\n",
            f"      - name: {PREFLIGHT_NAME}\n        continue-on-error: true\n",
            1,
        )
        self.assertEqual(
            CHK.check_text(broken, LABEL),
            [f"{LABEL}: preflight step '{PREFLIGHT_NAME}' carries `continue-on-error`"],
        )

    def test_if_condition_is_red(self):
        broken = self.text.replace(
            f"      - name: {PREFLIGHT_NAME}\n",
            f"      - name: {PREFLIGHT_NAME}\n        if: always()\n",
            1,
        )
        self.assertEqual(
            CHK.check_text(broken, LABEL),
            [f"{LABEL}: preflight step '{PREFLIGHT_NAME}' carries `if`"],
        )

    def test_job_level_continue_on_error_is_red(self):
        broken = self.text.replace(
            "    timeout-minutes: 110\n",
            "    timeout-minutes: 110\n    continue-on-error: true\n",
            1,
        )
        problems = CHK.check_text(broken, LABEL)
        self.assertEqual(
            problems,
            [f"{LABEL}: job 'per-module-thresholds' carries job-level continue-on-error"],
        )

    def test_comment_mention_does_not_count_as_the_step(self):
        start, end = self.preflight_block()
        broken = self.text[:start] + "      # scripts/ci/pg_env_preflight.py is mentioned\n" + self.text[end:]
        self.assertEqual(
            CHK.check_text(broken, LABEL),
            [f"{LABEL}: preflight step (scripts/ci/pg_env_preflight.py) is absent"],
        )

    def test_step_runs_the_script_with_restart(self):
        start, end = self.preflight_block()
        block = self.text[start:end]
        self.assertIn(
            "run: python3 scripts/ci/pg_env_preflight.py --container pg-age --restart --label coverage-pg",
            block,
        )
        self.assertNotIn("continue-on-error", block.replace("`continue-on-error`", ""))


if __name__ == "__main__":
    unittest.main()
