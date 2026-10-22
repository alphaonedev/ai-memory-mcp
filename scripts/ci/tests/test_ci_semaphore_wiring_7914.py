#!/usr/bin/env python3
"""Workflow wiring invariants for the #7914 host-local semaphore.

Pins: the `Run tests (impact-aware)` step re-runs itself under
scripts/ci/host_semaphore.py only when HOST_SEMAPHORE_SLOTS is above 0; that
variable is 2 for the linux-fed enterprise-fed leg and 0 elsewhere; the slots
value equals the helper's default; only the linux-fed enterprise-fed leg has
the 240 min cap while the macos-fed and hosted caps are unchanged.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only (the workflow is read as text).
"""
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CI = (REPO / '.github' / 'workflows' / 'ci.yml').read_text()
sys.path.insert(0, str(REPO / 'scripts' / 'ci'))
import host_semaphore  # noqa: E402


def step_text(name):
    start = CI.index('      - name: %s\n' % name)
    nxt = CI.find('\n      - name: ', start + 1)
    return CI[start:nxt]


class SemaphoreWiring(unittest.TestCase):
    def test_slots_expression_names_linux_fed_enterprise_fed_only(self):
        step = step_text('Run tests (impact-aware)')
        m = re.search(r"HOST_SEMAPHORE_SLOTS: \$\{\{ (.+?) \}\}", step)
        self.assertIsNotNone(m, step[:400])
        expr = m.group(1)
        self.assertIn("matrix.node == 'linux-fed'", expr)
        self.assertIn("matrix.tier == 'enterprise-fed'", expr)
        self.assertIn("'%d'" % host_semaphore.SEMAPHORE_SLOTS_DEFAULT, expr)
        self.assertTrue(expr.endswith("|| '0'"), expr)

    def test_step_reruns_itself_under_the_helper(self):
        step = step_text('Run tests (impact-aware)')
        self.assertIn('[ "${HOST_SEMAPHORE_SLOTS:-0}" -gt 0 ]', step)
        self.assertIn('[ -z "${HOST_SEMAPHORE_HELD:-}" ]', step)
        self.assertIn('export HOST_SEMAPHORE_HELD=1', step)
        self.assertIn('exec python3 -I scripts/ci/host_semaphore.py --name linux-fed-tests '
                      '--slots "$HOST_SEMAPHORE_SLOTS"', step)
        self.assertIn('-- bash --noprofile --norc -eo pipefail "$0"', step)
        # the guard runs before JOB_T0 handling and before any cargo call
        guard = step.index('exec python3 -I scripts/ci/host_semaphore.py')
        self.assertLess(guard, step.index('JOB_T0_VALID=0'))
        self.assertLess(guard, step.index('cargo test'))

    def test_load_gate_stays_the_pre_check(self):
        self.assertLess(CI.index('- name: Load gate (#6795)'),
                        CI.index('- name: Run tests (impact-aware)'))

    def test_no_concurrency_group_was_added_for_it(self):
        self.assertNotIn('linux-fed-tests', re.sub(r'--name linux-fed-tests', '', CI))

    def test_only_the_linux_fed_enterprise_leg_has_240(self):
        rows = re.findall(r'- leg: (\S+)\n(?:(?!\n          - leg:).)*?timeout: (\d+)\n', CI, re.S)
        caps = dict(rows)
        self.assertEqual(caps['linux-fed,enterprise-fed'], '240')
        self.assertEqual(caps['macos-fed,enterprise-fed'], '160')
        self.assertEqual(caps['macos-fed,sqlite'], '80')
        self.assertEqual(caps['ubuntu-latest,sqlite'], '95')

    def test_job_left_still_derives_from_job_t0(self):
        body = step_text('Run tests (impact-aware)')
        self.assertIn('JOB_TIMEOUT_MIN * 60 - ($(date +%s) - JOB_T0)', body)


if __name__ == '__main__':
    unittest.main()
