#!/usr/bin/env python3
"""Tests for scripts/test/check_ci_floor_gate_step_8473.py (#8473 round 3).

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.12+, standard library only.
"""
import importlib.util
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    "floor_step", REPO / "scripts" / "test" / "check_ci_floor_gate_step_8473.py")
floor_step = importlib.util.module_from_spec(spec)
spec.loader.exec_module(floor_step)

GOOD_JOB_IF = "${{ !cancelled() && needs.classify.result != 'skipped' }}"
GOOD_AUDIT_IF = "${{ !cancelled() && needs.classify.outputs.cargo_skip != 'true' && matrix.once }}"


def workflow(job_if=GOOD_JOB_IF, audit_if=GOOD_AUDIT_IF, needs="classify", runs_on="ubuntu-24.04",
             timeout="15", py=("'3.12'", "'3.x'"), suite=True, gate_in_check=False, gate=True,
             gate_first=False, cancel_3x=True):
    lines = ["name: ci", "jobs:", "  dependency-floors:"]
    if needs is not None:
        lines.append("    needs: " + needs)
    if job_if is not None:
        lines.append("    if: " + job_if)
    lines.append("    runs-on: " + runs_on)
    if timeout is not None:
        lines.append("    timeout-minutes: " + timeout)
    lines.append("    steps:")
    gate_lines = ["      - name: Dependency floor gate (OSV)",
                  "        run: python3 -I scripts/check-dependency-floors.py --lock Cargo.lock"]
    if gate and gate_first:
        lines += gate_lines
    for ver in py or ():
        guard = ["      - if: ${{ !cancelled() }}", "        uses: actions/setup-python@abc # v5"] \
            if ver == "'3.x'" and cancel_3x else ["      - uses: actions/setup-python@abc # v5"]
        lines += guard + ["        with:", "          python-version: " + ver]
        if gate and not gate_first and ver == py[0]:
            lines += gate_lines
        if suite:
            lines += ["      - name: Suite " + ver]
            if ver == "'3.x'" and cancel_3x:
                lines.append("        if: ${{ !cancelled() }}")
            lines += ["        run: |",
                      "          python3 -I -m unittest discover -s scripts/ci/tests -p 'test_*.py'"]
    if suite and not py:
        lines += ["      - name: Suite", "        run: |",
                  "          python3 -I -m unittest discover -s scripts/ci/tests -p 'test_*.py'"]
    lines += ["  check:", "    needs: classify", "    steps:"]
    if gate_in_check:
        lines += ["      - name: Dependency floor gate (OSV)", "        run: echo gate"]
    lines += ["      - name: Security audit"]
    if audit_if is not None:
        lines.append("        if: " + audit_if)
    lines += ["        run: cargo audit", "  other:", "    steps:", "      - run: echo"]
    return "\n".join(lines) + "\n"


class FloorGateJob(unittest.TestCase):
    def problems(self, text):
        return floor_step.check(text)[1]

    def flagged(self, text, needle):
        got = self.problems(text)
        self.assertTrue(any(needle in p for p in got), got)

    def test_good_job_passes(self):
        self.assertEqual(self.problems(workflow()), [])

    def test_missing_job_is_rc_2(self):
        self.assertIsNone(floor_step.check("jobs:\n  a:\n    steps:\n      - name: other\n")[0])
        self.assertEqual(floor_step.main(["--ci-yml", __file__]), 2)

    def test_job_without_cancelled_is_flagged(self):
        self.flagged(workflow(job_if="${{ needs.classify.result != 'skipped' }}"), "!cancelled()")

    def test_job_without_classify_term_is_flagged(self):
        self.flagged(workflow(job_if="${{ !cancelled() }}"), "needs.classify.result != 'skipped'")

    def test_job_without_if_is_flagged(self):
        self.flagged(workflow(job_if=None), "no if: condition")

    def test_disjunction_is_flagged(self):
        self.flagged(workflow(job_if="${{ !cancelled() && needs.classify.result != 'skipped' || true }}"),
                     "contains ||")

    def test_job_needs_runner_timeout_are_pinned(self):
        self.flagged(workflow(needs="select"), "needs: classify")
        self.flagged(workflow(runs_on="self-hosted"), "ubuntu-24.04")

    def test_gate_before_the_3_12_setup_is_flagged(self):
        self.flagged(workflow(gate_first=True), "before the 3.12 setup-python")

    def test_3_x_leg_without_cancelled_guard_is_flagged(self):
        self.flagged(workflow(cancel_3x=False), "need if: ${{ !cancelled() }}")
        self.flagged(workflow(runs_on="ubuntu-latest"), "ubuntu-24.04")
        self.flagged(workflow(timeout="60"), "timeout-minutes: 15")
        self.flagged(workflow(timeout=None), "timeout-minutes: 15")

    def test_python_312_and_current_stable_legs_are_required(self):
        self.flagged(workflow(py=None), "python-version 3.12")
        self.flagged(workflow(py=("'3.12'",)), "python-version 3.x")
        self.flagged(workflow(py=("'3.x'",)), "python-version 3.12")
        self.flagged(workflow(suite=False), "scripts/ci/tests suite")

    def test_python_39_leg_is_flagged(self):
        self.flagged(workflow(py=("'3.12'", "'3.x'", "'3.9'")), "end of life")

    def test_suite_before_setup_python_is_flagged(self):
        text = workflow()
        setup = ("      - uses: actions/setup-python@abc # v5\n        with:\n"
                 "          python-version: '3.12'\n")
        start = text.index(setup)
        stop = text.index("      - if: ${{ !cancelled() }}\n        uses: actions/setup-python@abc # v5")
        swapped = text[:start] + text[start + len(setup):stop] + setup + text[stop:]
        self.assertNotEqual(swapped, text)
        self.flagged(swapped, "after the 3.12 setup-python")

    def test_gate_left_in_check_is_flagged(self):
        self.flagged(workflow(gate_in_check=True), "still carries")

    def test_gate_script_missing_is_flagged(self):
        self.flagged(workflow(gate=False), "check-dependency-floors.py")

    def test_audit_without_cancelled_is_flagged(self):
        self.flagged(workflow(audit_if="needs.classify.outputs.cargo_skip != 'true' && matrix.once"),
                     "!cancelled()")

    def test_audit_without_if_is_flagged(self):
        self.flagged(workflow(audit_if=None), "no if: condition")

    def test_negated_matrix_once_is_not_matrix_once(self):
        got = self.problems(workflow(
            audit_if="${{ !cancelled() && needs.classify.outputs.cargo_skip != 'true' && !matrix.once }}"))
        self.assertTrue(any("matrix.once" in p for p in got), got)

    def test_terms_are_whole_tokens(self):
        self.assertEqual(floor_step.terms("${{ a && !b }}"), (["a", "!b"], False))
        self.assertEqual(floor_step.terms("a || b && c"), (["a || b", "c"], True))
        # a substring of a longer term never satisfies the requirement
        got = self.problems(workflow(
            audit_if="${{ !cancelled() && needs.classify.outputs.cargo_skip != 'true' && matrix.once_not }}"))
        self.assertTrue(any("matrix.once" in p for p in got), got)

    def test_cargo_skip_condition_is_required_on_audit(self):
        self.flagged(workflow(audit_if="${{ !cancelled() && matrix.once }}"), "cargo_skip")

    def test_the_real_ci_yml_passes(self):
        text = (REPO / ".github" / "workflows" / "ci.yml").read_text()
        self.assertEqual(self.problems(text), [])


if __name__ == "__main__":
    unittest.main()
