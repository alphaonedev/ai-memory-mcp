#!/usr/bin/env python3
"""Workflow wiring invariants for the #7914 host-local semaphore.

Pins: the `Run tests (impact-aware)` step re-runs itself under
scripts/ci/host_semaphore.py only when HOST_SEMAPHORE_SLOTS is above 0; that
variable is 2 for the linux-fed enterprise-fed leg and 0 elsewhere; the slots
value equals the helper's default; only the linux-fed enterprise-fed leg has
the 300 min cap while the macos-fed and hosted caps are unchanged.

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


# Measured on the 4-runner linux-fed host (#7914 attempt-2 evidence comment, run
# 39686450440 attempt 2): a cold compile took ~4100 s and the serial shard alone ~7800 s.
COLD_COMPILE_SECS = 4100
SERIAL_SHARD_SECS = 7800


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

    def test_job_cap_covers_every_wait_plus_the_serial_shard_7928(self):
        """The cap, the gate wait, the semaphore wait and the safety are read from the YAML text."""
        caps = dict(re.findall(r'- leg: (\S+)\n(?:(?!\n          - leg:).)*?timeout: (\d+)\n', CI, re.S))
        cap_secs = int(caps['linux-fed,enterprise-fed']) * 60
        gate = re.search(r'load_gate\.py[^\n]*--max-wait-secs (\d+)', CI)
        if gate is None:  # no flag in the workflow: the helper default applies
            gate = re.search(r"'--max-wait-secs', type=_non_negative_int, default=(\d+)",
                             (REPO / 'scripts' / 'ci' / 'load_gate.py').read_text())
        gate_wait = int(gate.group(1))
        sem = re.search(r"HOST_SEMAPHORE_MAX_WAIT_SECS: '(\d+)'", CI)
        self.assertIsNotNone(sem, 'the semaphore wait must be one named env constant')
        semaphore_wait = int(sem.group(1))
        self.assertIn('--max-wait-secs "$HOST_SEMAPHORE_MAX_WAIT_SECS"', CI)
        safety = re.search(r'JOB_T0\) - (\d+) \)\)', CI)
        self.assertIsNotNone(safety)
        safety_secs = int(safety.group(1))
        slack = cap_secs - gate_wait - semaphore_wait - COLD_COMPILE_SECS - safety_secs
        self.assertGreaterEqual(
            slack, SERIAL_SHARD_SECS,
            'cap %d - gate %d - semaphore %d - compile %d - safety %d = %d < serial shard %d'
            % (cap_secs, gate_wait, semaphore_wait, COLD_COMPILE_SECS, safety_secs, slack, SERIAL_SHARD_SECS))
        self.assertIn('cap 18000 s >= load-gate wait 1200 + semaphore wait 3600 + cold compile 4100 '
                      '+ safety 300 + serial shard 7800 (= 17000 s)', CI)

    def test_only_the_linux_fed_enterprise_leg_has_300(self):
        rows = re.findall(r'- leg: (\S+)\n(?:(?!\n          - leg:).)*?timeout: (\d+)\n', CI, re.S)
        caps = dict(rows)
        self.assertEqual(caps['linux-fed,enterprise-fed'], '300')
        self.assertEqual(caps['macos-fed,enterprise-fed'], '160')
        self.assertEqual(caps['macos-fed,sqlite'], '80')
        self.assertEqual(caps['ubuntu-latest,sqlite'], '95')

    def test_job_left_still_derives_from_job_t0(self):
        body = step_text('Run tests (impact-aware)')
        self.assertIn('JOB_TIMEOUT_MIN * 60 - ($(date +%s) - JOB_T0)', body)


if __name__ == '__main__':
    unittest.main()
