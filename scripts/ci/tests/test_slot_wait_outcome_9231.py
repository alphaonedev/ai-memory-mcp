#!/usr/bin/env python3
"""Class invariant for #9231: a host-slot wait never ends as a red TEST failure.

Invariants, each a table over runner counts and slot counts:
  1. A slot wait ends in a slot, or in the named outcome `infra: no slot`: one
     `::error title=infra\x3a no slot::` annotation with the wait seconds, the
     slot count and the serving-runner count, and one exit code (75) that no
     test failure produces. The job and the gate stay red (fail closed); the
     outcome sets no job output. ci_failure_class.py classifies the annotation.
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
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CI_DIR = REPO / 'scripts' / 'ci'
sys.path.insert(0, str(CI_DIR))
import ci_failure_class as cfc  # noqa: E402
import host_semaphore as hs  # noqa: E402
import host_slots_check as hsc  # noqa: E402

WORKFLOWS = sorted((REPO / '.github' / 'workflows').glob('*.yml'))
CONFIG = CI_DIR / 'host_slots.json'
SCRATCH_ROOT = REPO / '.local-runs'

# Written out, not read from the code under test.
EXPECTED_TITLE_ESCAPED = '::error title=infra\\x3a no slot::'
EXPECTED_EXIT_NO_SLOT = 75
EXPECTED_CLASS = 'infra-no-slot'
EXPECTED_WAIT_SECS = 600
OLD_WAIT_SECS = 3600
IDLE_SEAT_CEILING_SECS = 900  # nothing may hold a runner seat idle longer than this
RUNNER_SLOT_TABLE = [(r, s) for s in (1, 2, 3, 4) for r in (1, 2, 3, 4, 5, 8)]
# Exit codes that a wrapper, a shell, cargo, timeout or a signal produce; the no-slot code is none of them.
OTHER_EXIT_CODES = {
    0: 'success', 1: 'general failure', 2: 'bad arguments / shell misuse', 3: 'load_gate refusal',
    4: 'workflow_annotation module not loadable', 101: 'cargo test failure or panic', 124: 'timeout',
    125: 'docker/timeout internal', 126: 'not executable', 127: 'not found', 130: 'SIGINT',
    137: 'SIGKILL', 143: 'SIGTERM',
}


def scratch():
    SCRATCH_ROOT.mkdir(exist_ok=True)
    return tempfile.TemporaryDirectory(dir=str(SCRATCH_ROOT))


class WrapperOutcome(unittest.TestCase):
    """Invariant 1, wrapper side: every slot count, all slots busy."""

    def run_wrapper(self, slots, busy, name='linux-fed-tests'):
        with scratch() as td:
            root = Path(td) / 'locks'
            slot_dir = root / name
            slot_dir.mkdir(parents=True)
            held = []
            for _ in range(busy):
                got = hs.try_acquire(slot_dir, slots)
                self.assertIsNotNone(got)
                held.append(got[1])
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    rc = hs.main(['--name', name, '--slots', str(slots), '--max-wait-secs', '0',
                                  '--root', str(root), '--label', 'T', '--',
                                  sys.executable, '-c', 'pass'])
            finally:
                for fd in held:
                    hs.os.close(fd)
            return rc, buf.getvalue()

    def test_all_slots_busy_is_the_named_outcome_for_every_slot_count(self):
        for slots in (1, 2, 3, 4):
            with self.subTest(slots=slots):
                rc, out = self.run_wrapper(slots, slots)
                self.assertEqual(rc, EXPECTED_EXIT_NO_SLOT, out)
                lines = [ln for ln in out.splitlines() if ln.startswith('::error')]
                self.assertEqual(len(lines), 1, out)
                self.assertTrue(lines[0].startswith(EXPECTED_TITLE_ESCAPED), lines[0])
                self.assertIn('no slot free after 0s', lines[0])
                self.assertIn('all %d slots busy' % slots, lines[0])
                self.assertIn('2 serving runners', lines[0])  # host_slots.json: linux-fed-tests
                self.assertIn('not a test failure', lines[0])

    def test_unconfigured_gate_names_unknown_runner_count(self):
        rc, out = self.run_wrapper(1, 1, name='not-in-the-config')
        self.assertEqual(rc, EXPECTED_EXIT_NO_SLOT, out)
        self.assertIn('unknown serving runners', out)

    def test_a_free_slot_runs_the_command_and_prints_no_infra_annotation(self):
        for slots in (1, 2, 3, 4):
            with self.subTest(slots=slots):
                rc, out = self.run_wrapper(slots, slots - 1)
                self.assertEqual(rc, 0, out)
                self.assertNotIn(EXPECTED_TITLE_ESCAPED, out)

    def test_no_slot_exit_code_is_none_of_the_codes_a_test_or_shell_produces(self):
        self.assertEqual(hs.EXIT_NO_SLOT, EXPECTED_EXIT_NO_SLOT)
        for code, who in OTHER_EXIT_CODES.items():
            with self.subTest(code=code, who=who):
                self.assertNotEqual(hs.EXIT_NO_SLOT, code)
        self.assertLess(hs.EXIT_NO_SLOT, 128)  # not a 128+signal code

    def test_the_outcome_sets_no_job_output(self):
        """The class (iii) taint boundary: no job output is read by the gate for this outcome."""
        ci = (REPO / '.github' / 'workflows' / 'ci.yml').read_text()
        self.assertNotIn('slot_starved', ci)
        self.assertNotIn('steps.tests.outputs', ci)
        self.assertNotIn('GITHUB_OUTPUT', (CI_DIR / 'host_semaphore.py').read_text())


class Classifier(unittest.TestCase):
    """The annotation the wrapper prints is the class the failure classifier names."""

    REAL = ('::error title=infra\\x3a no slot::[#7914 semaphore] \'T\': no slot free after 600s '
            '(all 2 slots busy on this host, 2 serving runners); exit 75')
    TABLE = [
        (REAL, EXPECTED_CLASS),
        ('2026-11-21T10:00:00.1234567Z ' + REAL + '\n', EXPECTED_CLASS),
        ('::error title=infra: no slot::x', EXPECTED_CLASS),
        ('::error title=infra%3A no slot::x', EXPECTED_CLASS),
        ('::warning title=infra%3A no slot::x', None),
        ('::error title=infra%3A no slots::x', None),
        ('::error title=infra%3A no slot::', None),
        ('::error title=infra%3A no slot', None),
        ('prefix::error title=infra%3A no slot::x', None),
        ('::error::[coverage-pg] PG-ENV x', 'ci-env'),
        ('test result: FAILED. 1 passed; 1 failed', None),
        ('', None),
    ]

    def test_table(self):
        for text, expected in self.TABLE:
            with self.subTest(text=text[:60]):
                self.assertEqual(cfc.classify(text), expected)

    def test_class_constant(self):
        self.assertEqual(cfc.CLASS_INFRA_NO_SLOT, EXPECTED_CLASS)

    def test_the_wrapper_output_is_classified(self):
        with scratch() as td:
            root = Path(td) / 'locks'
            slot_dir = root / 'linux-fed-tests'
            slot_dir.mkdir(parents=True)
            got = hs.try_acquire(slot_dir, 1)
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    hs.main(['--name', 'linux-fed-tests', '--slots', '1', '--max-wait-secs', '0',
                             '--root', str(root), '--label', 'T', '--', sys.executable, '-c', 'pass'])
            finally:
                hs.os.close(got[1])
        self.assertEqual(cfc.classify(buf.getvalue()), EXPECTED_CLASS)

    def test_large_log_is_linear(self):
        log = 'ok line\n' * 200_000 + self.REAL + '\n'
        self.assertEqual(cfc.classify(log), EXPECTED_CLASS)


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
        self.assertIn('linux-fed-tests', load_config()['gates'])

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


if __name__ == '__main__':
    unittest.main()
