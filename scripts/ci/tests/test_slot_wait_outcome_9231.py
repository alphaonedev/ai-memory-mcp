#!/usr/bin/env python3
"""Class invariant for #9231: a host-slot wait never ends as a red TEST failure.

Invariants, each a table over runner counts and slot counts:
  1. A slot wait ends in a slot, or in the named outcome `infra: no slot`: the
     wrapper records it in the step output and the step summary, and ci-gate
     folds it as its own bucket (exit EXIT_INFRA), never as a plain `failure`.
     The outcome never turns into a pass (fail closed).
  2. The number of runners that serve a slot-gated leg is tied to the slot
     count by the slot configuration (scripts/ci/host_slots.json), read here
     together with the workflow files: no gated name may have more serving
     runners than slots, and every call site and slot count in a workflow is
     in the configuration.
  3. The wait bound is a named constant, far below the old 3600 s, and the
     workflow and the helper default agree on it.

The expected values below are written out here; none is computed from the
code under test.

Run: python3 -m unittest discover -s scripts/ci/tests
"""
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CI_DIR = REPO / 'scripts' / 'ci'
sys.path.insert(0, str(CI_DIR))
sys.path.insert(0, str(CI_DIR / 'impact'))
import host_semaphore as hs  # noqa: E402
import gate  # noqa: E402
import host_slots_check as hsc  # noqa: E402

WORKFLOWS = sorted((REPO / '.github' / 'workflows').glob('*.yml'))
CONFIG = CI_DIR / 'host_slots.json'
SCRATCH_ROOT = REPO / '.local-runs'

# Written out, not read from the code under test.
EXPECTED_NO_SLOT_TEXT = 'infra: no slot'
EXPECTED_OUTPUT_LINE = 'no_slot=true'
EXPECTED_OUTPUT_PREFIX = 'slot_starved'
EXPECTED_EXIT_NO_SLOT = 3
EXPECTED_EXIT_INFRA = 4
EXPECTED_WAIT_SECS = 600
OLD_WAIT_SECS = 3600
IDLE_SEAT_CEILING_SECS = 900  # nothing may hold a runner seat idle longer than this
RUNNER_SLOT_TABLE = [(r, s) for s in (1, 2, 3, 4) for r in (1, 2, 3, 4, 5, 8)]


def scratch():
    SCRATCH_ROOT.mkdir(exist_ok=True)
    return tempfile.TemporaryDirectory(dir=str(SCRATCH_ROOT))


class WrapperOutcome(unittest.TestCase):
    """Invariant 1, wrapper side: every slot count, all slots busy."""

    def run_wrapper(self, slots, busy):
        with scratch() as td:
            root = Path(td) / 'locks'
            held = []
            slot_dir = root / 'n'
            slot_dir.mkdir(parents=True)
            for _ in range(busy):
                got = hs.try_acquire(slot_dir, slots)
                self.assertIsNotNone(got)
                held.append(got[1])
            out_file = Path(td) / 'out.txt'
            summary = Path(td) / 'summary.md'
            env = {'GITHUB_OUTPUT': str(out_file), 'GITHUB_STEP_SUMMARY': str(summary)}
            buf = io.StringIO()
            try:
                with unittest.mock.patch.dict(os.environ, env), contextlib.redirect_stdout(buf):
                    rc = hs.main(['--name', 'n', '--slots', str(slots), '--max-wait-secs', '0',
                                  '--root', str(root), '--label', 'T', '--',
                                  sys.executable, '-c', 'pass'])
            finally:
                for fd in held:
                    os.close(fd)
            return (rc, buf.getvalue(),
                    out_file.read_text() if out_file.exists() else '',
                    summary.read_text() if summary.exists() else '')

    def test_all_slots_busy_is_the_named_infra_outcome_for_every_slot_count(self):
        for slots in (1, 2, 3, 4):
            with self.subTest(slots=slots):
                rc, out, outputs, summary = self.run_wrapper(slots, slots)
                self.assertEqual(rc, EXPECTED_EXIT_NO_SLOT, out)
                self.assertIn(EXPECTED_OUTPUT_LINE, outputs.splitlines())
                self.assertIn(EXPECTED_NO_SLOT_TEXT, summary)
                self.assertIn('no slot free after 0s', out)

    def test_a_free_slot_writes_no_infra_record(self):
        for slots in (1, 2, 3, 4):
            with self.subTest(slots=slots):
                rc, out, outputs, summary = self.run_wrapper(slots, slots - 1)
                self.assertEqual(rc, 0, out)
                self.assertNotIn(EXPECTED_OUTPUT_LINE, outputs)
                self.assertNotIn(EXPECTED_NO_SLOT_TEXT, summary)


def needs_with_check(check):
    ok = {'result': 'success', 'outputs': {}}
    return {'select': ok, 'classify': ok, 'build-script-vetting': ok,
            'mobile-cross-compile': ok, 'check': check}


class GateFold(unittest.TestCase):
    """Invariant 1, gate side."""

    def fold(self, check):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = gate.main(['--needs', json.dumps(needs_with_check(check))])
        return rc, buf.getvalue()

    def test_starved_check_is_an_infra_row_and_never_a_pass_or_a_plain_failure(self):
        for index in (0, 1, 5, 11):
            with self.subTest(index=index):
                check = {'result': 'failure',
                         'outputs': {'%s_%d' % (EXPECTED_OUTPUT_PREFIX, index): 'true'}}
                rc, out = self.fold(check)
                self.assertEqual(rc, EXPECTED_EXIT_INFRA, out)
                self.assertIn(EXPECTED_NO_SLOT_TEXT, out)
                self.assertNotIn('ci-gate: pass', out)
                self.assertIn('not a test failure', out)

    def test_plain_failure_and_empty_or_false_markers_stay_test_failures(self):
        table = [
            {'result': 'failure', 'outputs': {}},
            {'result': 'failure', 'outputs': {'%s_0' % EXPECTED_OUTPUT_PREFIX: ''}},
            {'result': 'failure', 'outputs': {'%s_0' % EXPECTED_OUTPUT_PREFIX: 'false'}},
            {'result': 'failure', 'outputs': {'other_0': 'true'}},
            {'result': 'cancelled', 'outputs': {'%s_0' % EXPECTED_OUTPUT_PREFIX: 'true'}},
        ]
        for check in table:
            with self.subTest(check=check):
                rc, out = self.fold(check)
                self.assertEqual(rc, 1, out)
                self.assertNotIn(EXPECTED_NO_SLOT_TEXT, out)

    def test_marker_on_a_non_check_job_does_not_excuse_it(self):
        needs = needs_with_check({'result': 'success', 'outputs': {}})
        needs['classify'] = {'result': 'failure',
                             'outputs': {'%s_0' % EXPECTED_OUTPUT_PREFIX: 'true'}}
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = gate.main(['--needs', json.dumps(needs)])
        self.assertEqual(rc, 1, buf.getvalue())

    def test_infra_plus_a_real_failure_is_a_real_failure(self):
        needs = needs_with_check({'result': 'failure',
                                  'outputs': {'%s_0' % EXPECTED_OUTPUT_PREFIX: 'true'}})
        needs['mobile-cross-compile'] = {'result': 'failure', 'outputs': {}}
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = gate.main(['--needs', json.dumps(needs)])
        self.assertEqual(rc, 1, buf.getvalue())


def load_config():
    return json.loads(CONFIG.read_text())


def workflow_calls():
    """Every host_semaphore.py call site: (workflow name, --name value)."""
    found = []
    for wf in WORKFLOWS:
        for name in re.findall(r'host_semaphore\.py\s+--name\s+(\S+)', wf.read_text()):
            found.append((wf.name, name))
    return found


class RunnerSlotTie(unittest.TestCase):
    """Invariant 2: runners and slots are tied by the configuration, not by hand."""

    def test_config_exists_and_has_the_linux_fed_gate(self):
        cfg = load_config()
        self.assertIn('linux-fed-tests', cfg['gates'])

    def test_serving_runners_never_exceed_slots(self):
        for name, gate_cfg in load_config()['gates'].items():
            with self.subTest(gate=name):
                self.assertLessEqual(len(gate_cfg['serving_runners']), gate_cfg['slots'])
                self.assertEqual(len(set(gate_cfg['serving_runners'])), len(gate_cfg['serving_runners']))

    def test_every_call_site_name_is_configured_and_every_gate_is_called(self):
        cfg = load_config()['gates']
        calls = workflow_calls()
        self.assertTrue(calls)
        for wf, name in calls:
            self.assertIn(name, cfg, '%s calls an unconfigured gate %s' % (wf, name))
        self.assertEqual({n for _, n in calls}, set(cfg))

    def test_workflow_slot_count_equals_the_configuration(self):
        ci = (REPO / '.github' / 'workflows' / 'ci.yml').read_text()
        m = re.search(r"HOST_SEMAPHORE_SLOTS: \$\{\{ .*? && '(\d+)' \|\| '0' \}\}", ci)
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(1)), load_config()['gates']['linux-fed-tests']['slots'])
        self.assertEqual(hs.SEMAPHORE_SLOTS_DEFAULT, load_config()['gates']['linux-fed-tests']['slots'])

    def test_real_configuration_has_no_violation(self):
        self.assertEqual(hsc.config_violations(load_config()), [])

    def test_tie_rule_over_the_runner_and_slot_table(self):
        """The rule the configuration is judged by, over every (runners, slots) pair."""
        for runners, slots in RUNNER_SLOT_TABLE:
            with self.subTest(runners=runners, slots=slots):
                cfg = {'gates': {'g': {'slots': slots,
                                       'serving_runners': ['r%d' % i for i in range(runners)]}}}
                violations = hsc.config_violations(cfg)
                self.assertEqual(bool(violations), runners > slots, violations)


class WaitBound(unittest.TestCase):
    """Invariant 3: the bound is one named constant, short, and the same everywhere."""

    def test_named_constant_and_helper_default(self):
        self.assertEqual(hs.SEMAPHORE_MAX_WAIT_SECS_DEFAULT, EXPECTED_WAIT_SECS)
        self.assertLessEqual(hs.SEMAPHORE_MAX_WAIT_SECS_DEFAULT, IDLE_SEAT_CEILING_SECS)
        self.assertLess(hs.SEMAPHORE_MAX_WAIT_SECS_DEFAULT, OLD_WAIT_SECS)

    def test_workflow_bound_equals_the_constant(self):
        ci = (REPO / '.github' / 'workflows' / 'ci.yml').read_text()
        m = re.search(r"HOST_SEMAPHORE_MAX_WAIT_SECS: '(\d+)'", ci)
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(1)), hs.SEMAPHORE_MAX_WAIT_SECS_DEFAULT)

    def test_workflow_records_the_outcome_for_the_gate(self):
        ci = (REPO / '.github' / 'workflows' / 'ci.yml').read_text()
        start = ci.index('      - name: Run tests (impact-aware)\n')
        step = ci[start:ci.find('\n      - name: ', start + 1)]
        self.assertRegex(step, r'\n        id: tests\n')
        self.assertIn('slot_starved_${{ strategy.job-index }}: ${{ steps.tests.outputs.no_slot }}', ci)


if __name__ == '__main__':
    unittest.main()
