#!/usr/bin/env python3
"""Workflow wiring invariants for the #6795 load gate and serial-shard budget.

Pins: the gate step sits immediately before `Run tests (impact-aware)`, runs
only on self-hosted legs, and never uses shell logic beyond the helper call;
the serial shard budget is derived from the job cap, not the flat 7800 s; the
parallel shards keep 7800 s.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only (the workflow is read as text).
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CI = (REPO / '.github' / 'workflows' / 'ci.yml').read_text()
DOC = (REPO / 'docs' / 'ci' / 'CARRIER-BRANCH-GATES.md').read_text()


def function_body(text, name):
    m = re.search(r'^(\s*)%s\(\) \{\n' % re.escape(name), text, re.M)
    if not m:
        raise AssertionError('function %s() not found' % name)
    end = text.index('\n%s}\n' % m.group(1), m.end())
    return text[m.end():end]


class LoadGateStep(unittest.TestCase):
    def test_step_precedes_run_tests_and_is_self_hosted_only(self):
        m = re.search(r'      - name: Load gate \(#6795\)\n(.*?)\n      - name: Run tests \(impact-aware\)\n', CI, re.S)
        self.assertIsNotNone(m, 'Load gate step must be immediately before Run tests')
        body = m.group(1)
        self.assertIn("contains(matrix.runner, 'self-hosted')", body)
        self.assertIn("needs.classify.outputs.docs_only != 'true'", body)
        self.assertIn('python3 scripts/ci/load_gate.py --label "${{ matrix.node }}/${{ matrix.tier }}"', body)

    def test_exactly_one_gate_step(self):
        self.assertEqual(CI.count('- name: Load gate (#6795)'), 1)


class SerialBudget(unittest.TestCase):
    def test_parallel_shards_keep_7800(self):
        self.assertEqual(len(re.findall(r'^\s*WATCHDOG_SECS=7800\s*$', CI, re.M)), 1)

    def test_serial_budget_derived_from_job_cap(self):
        body = function_body(CI, 'run_sharded')
        self.assertIn('JOB_TIMEOUT_MIN', CI)
        self.assertIn('SERIAL_BUDGET_SECS=$(( JOB_TIMEOUT_MIN * 60', body)
        self.assertIn('[#6795] serial shard budget', body)

    def test_run_shard_uses_serial_budget_only_for_serial(self):
        body = function_body(CI, 'run_shard')
        self.assertIn('SHARD_BUDGET="$SERIAL_BUDGET_SECS"', body)
        self.assertIn('SHARD_BUDGET="$WATCHDOG_SECS"', body)
        self.assertIn('"$name" = serial', body)

    def test_shard_left_uses_per_shard_budget(self):
        self.assertIn('echo $(( SHARD_BUDGET - ($(date +%s) - $1) ))', function_body(CI, 'shard_left'))


class Docs(unittest.TestCase):
    def test_docs_record_gate_budget_and_cargo_cap(self):
        for needle in ('#6795', 'load_gate.py', '1.5', 'SERIAL_BUDGET_SECS', '2 concurrent cargo'):
            self.assertIn(needle, DOC)


if __name__ == '__main__':
    unittest.main()
