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
    def test_parallel_shards_keep_7800_base(self):
        self.assertEqual(len(re.findall(r'^\s*WATCHDOG_SECS=7800\s*$', CI, re.M)), 1)

    def test_job_t0_step_exists_before_the_test_step(self):
        m = re.search(r'      - name: Record job start \(#6795\)\n(.*?)\n      - ', CI, re.S)
        self.assertIsNotNone(m, 'JOB_T0 step missing')
        self.assertIn('echo "JOB_T0=$(date +%s)" >> "$GITHUB_ENV"', m.group(1))
        self.assertLess(CI.index('- name: Record job start (#6795)'), CI.index('- name: Run tests (impact-aware)'))
        self.assertLess(CI.index('- name: Record job start (#6795)'), CI.index('- uses: actions/checkout@', CI.index('- name: Fork-PR refusal')))

    def test_serial_formula_anchored_on_job_start_without_allowance(self):
        body = function_body(CI, 'run_sharded')
        m = re.search(r'SERIAL_BUDGET_SECS=\$\(\( (.*?) \)\)\n', body)
        self.assertIsNotNone(m)
        formula = m.group(1)
        self.assertIn('JOB_T0', formula)
        self.assertNotIn('STEP_T0', formula)
        self.assertIsNone(re.search(r'\b600\b', formula), formula)
        self.assertNotIn('STEP_T0', CI)

    def test_every_shard_budget_is_capped_by_job_time_left(self):
        body = function_body(CI, 'run_shard')
        self.assertIn('SHARD_BUDGET="$(cap_to_job_left "$WATCHDOG_SECS")"', body)
        self.assertIn('SHARD_BUDGET="$(cap_to_job_left "$SERIAL_BUDGET_SECS")"', body)
        left = function_body(CI, 'job_left')
        self.assertIn('JOB_T0', left)
        self.assertIn('JOB_TIMEOUT_MIN * 60', left)

    def test_non_sharded_watchdog_is_capped_too(self):
        self.assertIn('local WATCHDOG_SECS="$(cap_to_job_left "$WATCHDOG_SECS")"',
                      function_body(CI, 'run_tests'))

    def test_shard_left_uses_per_shard_budget(self):
        self.assertIn('echo $(( SHARD_BUDGET - ($(date +%s) - $1) ))', function_body(CI, 'shard_left'))

    def test_timeout_comment_table_matches_matrix(self):
        for row in ('ubuntu-latest,sqlite      95', 'linux-fed,enterprise-fed 160',
                    'macos-fed,sqlite          80', 'macos-fed,enterprise-fed 160'):
            self.assertIn(row, CI)


class Docs(unittest.TestCase):
    def test_docs_record_gate_budget_and_cargo_cap(self):
        for needle in ('#6795', 'load_gate.py', '1.5', 'SERIAL_BUDGET_SECS', 'JOB_T0', '2 concurrent cargo'):
            self.assertIn(needle, DOC)


if __name__ == '__main__':
    unittest.main()
