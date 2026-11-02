#!/usr/bin/env python3
"""Tests for scripts/test/check_ci_floor_gate_step_8473.py (#8473 round 2).

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only.
"""
import importlib.util
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    "floor_step", REPO / "scripts" / "test" / "check_ci_floor_gate_step_8473.py")
floor_step = importlib.util.module_from_spec(spec)
spec.loader.exec_module(floor_step)

GOOD_IF = "${{ !cancelled() && needs.classify.outputs.cargo_skip != 'true' && matrix.once }}"


def workflow(gate_if, order=("gate", "audit")):
    gate = ["      - name: Dependency floor gate (OSV)"]
    if gate_if is not None:
        gate.append("        if: " + gate_if)
    gate.append("        run: python3 -I scripts/check-dependency-floors.py")
    audit = ["      - name: Security audit",
             "        if: needs.classify.outputs.cargo_skip != 'true' && matrix.once",
             "        run: cargo audit"]
    parts = {"gate": gate, "audit": audit}
    lines = ["jobs:", "  check:", "    steps:"]
    for key in order:
        lines.extend(parts[key])
    return "\n".join(lines) + "\n"


class FloorGateStep(unittest.TestCase):
    def problems(self, text):
        return floor_step.check(text)[1]

    def test_good_step_passes(self):
        self.assertEqual(self.problems(workflow(GOOD_IF)), [])

    def test_missing_cancelled_is_flagged(self):
        got = self.problems(workflow("needs.classify.outputs.cargo_skip != 'true' && matrix.once"))
        self.assertTrue(any("!cancelled()" in p for p in got), got)

    def test_missing_if_is_flagged(self):
        self.assertTrue(self.problems(workflow(None)))

    def test_lost_cargo_skip_or_once_is_flagged(self):
        self.assertTrue(self.problems(workflow("${{ !cancelled() && matrix.once }}")))
        self.assertTrue(self.problems(
            workflow("${{ !cancelled() && needs.classify.outputs.cargo_skip != 'true' }}")))

    def test_gate_after_audit_is_flagged(self):
        got = self.problems(workflow(GOOD_IF, order=("audit", "gate")))
        self.assertTrue(any("after the Security audit" in p for p in got), got)

    def test_missing_gate_is_rc_2(self):
        self.assertIsNone(floor_step.check("jobs:\n  a:\n    steps:\n      - name: other\n")[0])

    def test_the_real_ci_yml_passes(self):
        text = (REPO / ".github" / "workflows" / "ci.yml").read_text()
        self.assertEqual(self.problems(text), [])


if __name__ == "__main__":
    unittest.main()
