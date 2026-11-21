#!/usr/bin/env python3
"""Class invariant for #9231: a host-slot wait never ends as a red TEST failure, and nothing but the wrapper names it.

Defect class pinned here: an outcome label decided from text or an exit code that something
else can also produce, and a rule held by a test that does not go red when the rule breaks.

Invariants, each a table with expected values written out by hand (none computed from the code under test):
  1. No slot ends as the named outcome infra-no-slot: one error annotation whose MESSAGE carries the token
     (a job log shows `##[error]<message>` with no title), exit code 82, a title without colon or comma.
     A runner outside host_slots.json ends as infra-unknown-runner (83). A command that itself exits with
     82, 83 or 84 is reported as 84; every other code, 75 of the product binary included, passes through.
  2. The classifier gives a job a semaphore class only for the whole line form, without a slot-acquired
     marker and without test or build failure evidence; a run log is split per job.
  3. The wait bound, the slot counts and the serving runners are read from the PARSED workflow and
     configuration: a decoy comment, another quoting or a second definition cannot widen them.
  4. host_slots_check.py: one error line and exit 2 on a malformed file; .yaml files, composite actions and
     `--name` in any position are covered.

Run: python3 -m unittest discover -s scripts/ci/tests
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CI_DIR = REPO / 'scripts' / 'ci'
sys.path.insert(0, str(CI_DIR))
import host_semaphore as hs  # noqa: E402
try:
    import host_slots_check as hsc  # noqa: E402
except ImportError:  # a tree without the checker: its tests error by name, the wrapper tests still fail by assertion
    hsc = None

SCRATCH_ROOT = REPO / '.local-runs'
CI_YML = REPO / '.github' / 'workflows' / 'ci.yml'
CONFIG = CI_DIR / 'host_slots.json'

# Written out, not read from the code under test.
EXIT_NO_SLOT = 82
EXIT_UNKNOWN_RUNNER = 83
EXIT_CHILD_RESERVED = 84
EXPECTED_WAIT_SECS = 600
IDLE_SEAT_CEILING_SECS = 900
# Every producer of an exit code this wrapper's callers can see. None may use 82, 83 or 84.
EXIT_CODE_PRODUCERS = {
    0: 'success', 1: 'general failure, this wrapper bad config', 2: 'bad arguments, shell misuse, host_slots_check malformed',
    3: 'load_gate refusal', 4: 'EXIT_LOAD_REFUSED of the wrappers',
    64: 'sysexits EX_USAGE', 65: 'EX_DATAERR', 66: 'EX_NOINPUT', 69: 'EX_UNAVAILABLE', 70: 'EX_SOFTWARE',
    71: 'EX_OSERR', 73: 'EX_CANTCREAT', 74: 'EX_IOERR',
    75: 'product binary src/main.rs EX_TEMPFAIL and scripts/evidence/run_cert.py',
    78: 'product binary EX_CONFIG', 86: 'test stub exit', 87: 'test stub exit',
    100: 'nextest test failure', 101: 'cargo test failure or panic', 102: 'nextest no tests',
    124: 'timeout', 125: 'docker or timeout internal', 126: 'not executable', 127: 'not found',
    130: 'SIGINT', 134: 'SIGABRT', 137: 'SIGKILL', 139: 'SIGSEGV', 143: 'SIGTERM',
}


def load_classifier():
    spec = importlib.util.spec_from_file_location('ci_failure_class_under_test', CI_DIR / 'ci_failure_class.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cfc = load_classifier()


def scratch():
    SCRATCH_ROOT.mkdir(exist_ok=True)
    return tempfile.TemporaryDirectory(dir=str(SCRATCH_ROOT))


HOLDER = (
    'import fcntl, os, sys, time\n'
    'fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n'
    'fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n'
    'print("held", flush=True)\n'
    'time.sleep(120)\n'
)


class Wrapper:
    """Runs scripts/ci/host_semaphore.py as a subprocess; independent processes hold the slot flocks."""

    def __init__(self, test, runners, slots_in_file=2, gate='linux-fed-tests', registered=None):
        self.test = test
        self.td = scratch()
        self.root = Path(self.td.name) / 'locks'
        self.gate = gate
        self.holders = []
        self.config = Path(self.td.name) / 'host_slots.json'
        cfg = {'registered_runners': registered or list(runners),
               'gates': {gate: {'slots': slots_in_file, 'label': 'x', 'serving_runners': list(runners)}}}
        self.config.write_text(json.dumps(cfg))

    def hold(self, count):
        slot_dir = self.root / self.gate
        slot_dir.mkdir(parents=True, exist_ok=True)
        for i in range(count):
            p = subprocess.Popen([sys.executable, '-I', '-c', HOLDER, str(slot_dir / ('slot-%d.lock' % i))],
                                 stdout=subprocess.PIPE, text=True)
            self.holders.append(p)
            self.test.assertEqual(p.stdout.readline().strip(), 'held')

    def run(self, slots, child, runner=None, gate=None, use_config=True):
        env = {k: v for k, v in os.environ.items() if k != 'RUNNER_NAME'}
        if runner is not None:
            env['RUNNER_NAME'] = runner
        cmd = [sys.executable, '-I', str(CI_DIR / 'host_semaphore.py'), '--name', gate or self.gate,
               '--slots', str(slots), '--max-wait-secs', '0', '--root', str(self.root), '--label', 'T']
        if use_config:
            cmd += ['--config', str(self.config)]
        done = subprocess.run(cmd + ['--'] + child, capture_output=True, text=True, env=env, timeout=60)
        return done.returncode, done.stdout

    def close(self):
        for p in self.holders:
            p.kill()
            p.wait()
            p.stdout.close()
        self.td.cleanup()


def wrapper(test, *args, **kwargs):
    w = Wrapper(test, *args, **kwargs)
    test.addCleanup(w.close)
    return w


CHILD_OK = [sys.executable, '-c', 'print("CHILD-RAN")']


def child_exit(code):
    return [sys.executable, '-c', 'print("CHILD-RAN"); raise SystemExit(%d)' % code]


def error_lines(out):
    return [ln for ln in out.splitlines() if ln.startswith('::error')]


class WrapperOutcome(unittest.TestCase):
    # (slots held and asked for, serving runners listed, expected "N serving runners" text)
    NO_SLOT_TABLE = [(1, ['a'], 1), (2, ['a', 'b'], 2), (3, ['a', 'b'], 2), (4, ['a', 'b'], 2), (2, ['a', 'b', 'c', 'd'], 4)]

    def test_no_slot_table_pins_the_whole_line_and_the_runner_count(self):
        for slots, runners, expected_runners in self.NO_SLOT_TABLE:
            with self.subTest(slots=slots, runners=len(runners)):
                w = wrapper(self, runners, slots_in_file=slots)
                w.hold(slots)
                rc, out = w.run(slots, CHILD_OK)
                self.assertEqual(rc, 82, out)
                self.assertNotIn('CHILD-RAN', out)
                self.assertEqual(error_lines(out), [
                    "::error title=infra no-slot::[#7914 semaphore] 'T': infra-no-slot: no slot free after 0s "
                    "(all %d slots busy on this host, %d serving runners); no test ran, this is an "
                    "infrastructure outcome, not a test failure; exit 82" % (slots, expected_runners)])

    def test_title_has_no_colon_or_comma_so_no_property_escape_reaches_the_ui(self):
        w = wrapper(self, ['a'], slots_in_file=1)
        w.hold(1)
        _, out = w.run(1, CHILD_OK)
        title = re.match(r'::error title=([^:]*)::', error_lines(out)[0])
        self.assertIsNotNone(title, out)
        self.assertEqual(title.group(1), 'infra no-slot')
        self.assertNotIn('\\x3a', out.split('::', 2)[1])
        self.assertNotIn('%3A', out)

    def test_unconfigured_gate_says_unknown_serving_runners(self):
        w = wrapper(self, ['a'], slots_in_file=1)
        w.gate = 'not-in-the-config'
        w.hold(1)
        rc, out = w.run(1, CHILD_OK)
        self.assertEqual(rc, 82, out)
        self.assertIn('all 1 slots busy on this host, unknown serving runners)', out)

    def test_a_free_slot_runs_the_command_after_one_marker_line(self):
        for slots, held in ((1, 0), (2, 1), (3, 2), (4, 3)):
            with self.subTest(slots=slots):
                w = wrapper(self, ['a'], slots_in_file=slots)
                w.hold(held)
                rc, out = w.run(slots, CHILD_OK)
                self.assertEqual(rc, 0, out)
                self.assertEqual(error_lines(out), [])
                marker = "[#7914 semaphore] 'T': slot-acquired"
                lines = out.splitlines()
                self.assertEqual(lines.count(marker), 1, out)
                self.assertLess(lines.index(marker), lines.index('CHILD-RAN'))

    def test_marker_line_is_what_the_classifier_reads_as_slot_acquired(self):
        w = wrapper(self, ['a'], slots_in_file=1)
        rc, out = w.run(1, CHILD_OK)
        self.assertEqual(rc, 0, out)
        self.assertTrue(any(cfc.SLOT_ACQUIRED_LINE.match(ln) for ln in out.splitlines()), out)

    def test_child_code_75_of_the_product_binary_passes_through_unchanged(self):
        w = wrapper(self, ['a'], slots_in_file=1)
        rc, out = w.run(1, child_exit(75))
        self.assertEqual(rc, 75, out)
        self.assertEqual(error_lines(out), [])

    def test_child_codes_that_are_not_reserved_pass_through(self):
        for code in (1, 3, 7, 81, 85, 101, 130):
            with self.subTest(code=code):
                w = wrapper(self, ['a'], slots_in_file=1)
                rc, out = w.run(1, child_exit(code))
                self.assertEqual(rc, code, out)

    def test_child_exiting_with_a_reserved_code_is_reported_as_84_with_an_annotation(self):
        for code in (82, 83, 84):
            with self.subTest(code=code):
                w = wrapper(self, ['a'], slots_in_file=1)
                rc, out = w.run(1, child_exit(code))
                self.assertEqual(rc, 84, out)
                self.assertEqual(error_lines(out), [
                    "::error title=infra reserved-code::[#7914 semaphore] 'T': infra-reserved-code: the command "
                    "exited with %d, a code reserved for wrapper outcomes; reported as 84" % code])

    def test_unlisted_runner_ends_as_unknown_runner_and_never_runs_the_command(self):
        w = wrapper(self, ['f2-linux-fed', 'f2-linux-fed-2'], slots_in_file=2)
        rc, out = w.run(2, CHILD_OK, runner='rogue-runner')
        self.assertEqual(rc, 83, out)
        self.assertNotIn('CHILD-RAN', out)
        self.assertEqual(error_lines(out), [
            "::error title=infra unknown-runner::[#7914 semaphore] 'T': infra-unknown-runner: runner "
            "'rogue-runner' is not a serving runner of gate 'linux-fed-tests' in host_slots.json; "
            "no test ran; exit 83"])

    def test_registered_but_not_serving_runner_is_refused_too(self):
        w = wrapper(self, ['f2-linux-fed'], slots_in_file=1, registered=['f2-linux-fed', 'f2-linux-fed-3'])
        rc, out = w.run(1, CHILD_OK, runner='f2-linux-fed-3')
        self.assertEqual(rc, 83, out)

    def test_listed_runner_and_unset_runner_name_run_the_command(self):
        for runner in ('f2-linux-fed-2', None):
            with self.subTest(runner=runner):
                w = wrapper(self, ['f2-linux-fed', 'f2-linux-fed-2'], slots_in_file=2)
                rc, out = w.run(2, CHILD_OK, runner=runner)
                self.assertEqual(rc, 0, out)
                self.assertIn('CHILD-RAN', out)

    def test_runner_check_is_skipped_for_an_unconfigured_gate(self):
        w = wrapper(self, ['a'], slots_in_file=1)
        w.gate = 'not-in-the-config'
        rc, out = w.run(1, CHILD_OK, runner='anything')
        self.assertEqual(rc, 0, out)

    def test_the_shipped_config_lists_the_runner_seen_in_the_real_no_slot_job(self):
        cfg = json.loads(CONFIG.read_text())
        self.assertIn('f2-linux-fed-4', cfg['registered_runners'])  # run 44292743356 job 134771214198
        self.assertEqual(hs.serving_runners('linux-fed-tests'), ['f2-linux-fed', 'f2-linux-fed-2'])


class ExitCodeCollisionTable(unittest.TestCase):
    def test_reserved_codes_are_the_written_values(self):
        self.assertEqual((hs.EXIT_NO_SLOT, hs.EXIT_UNKNOWN_RUNNER, hs.EXIT_CHILD_RESERVED), (82, 83, 84))
        self.assertEqual(hs.RESERVED_EXIT_CODES, frozenset((82, 83, 84)))

    def test_no_producer_in_the_table_uses_a_reserved_code(self):
        for code, who in EXIT_CODE_PRODUCERS.items():
            with self.subTest(code=code, who=who):
                self.assertNotIn(code, hs.RESERVED_EXIT_CODES)

    def test_reserved_codes_are_not_a_signal_code(self):
        self.assertTrue(all(0 < c < 128 for c in hs.RESERVED_EXIT_CODES))


# A real job-log line (run 44292743356, job 134771214198) has the shape
#   2026-11-18T13:03:36.8238475Z ##[error][#7914 semaphore] 'linux-fed/enterprise-fed': no slot free after 3600s (all 2 slots busy on this host)
# The wrapper now writes the token and the counts into the same message.
TS = '2026-11-18T13:03:36.8238475Z '
NO_SLOT_MSG = ("[#7914 semaphore] 'linux-fed/enterprise-fed': infra-no-slot: no slot free after 600s "
               "(all 2 slots busy on this host, 2 serving runners); no test ran, this is an infrastructure "
               "outcome, not a test failure; exit 82")
NO_SLOT_JOB_LINE = TS + '##[error]' + NO_SLOT_MSG
NO_SLOT_RAW = '::error title=infra no-slot::' + NO_SLOT_MSG
OLD_REAL_LINE = (TS + "##[error][#7914 semaphore] 'linux-fed/enterprise-fed': no slot free after 3600s "
                 "(all 2 slots busy on this host)")
UNKNOWN_MSG = ("[#7914 semaphore] 'linux-fed/enterprise-fed': infra-unknown-runner: runner 'rogue' is not a "
               "serving runner of gate 'linux-fed-tests' in host_slots.json; no test ran; exit 83")
ACQUIRED = TS + "[#7914 semaphore] 'linux-fed/enterprise-fed': slot-acquired"
TEST_FAILED = TS + 'test result: FAILED. 10 passed; 1 failed; 0 ignored'
PG_ENV = TS + '##[error][coverage-pg] PG-ENV plpgsql.so cannot load'


def gh(job, text, step='Run tests'):
    return '%s\t%s\t%s' % (job, step, text if text.startswith('20') else TS + text)


class Classifier(unittest.TestCase):
    ROWS = [
        # (name, log lines, expected class)
        ('real no-slot job line', [NO_SLOT_JOB_LINE], 'infra-no-slot'),
        ('real no-slot job line, no timestamp', ['##[error]' + NO_SLOT_MSG], 'infra-no-slot'),
        ('raw annotation line', [TS + NO_SLOT_RAW], 'infra-no-slot'),
        ('old real line without the token', [OLD_REAL_LINE], None),
        ('unknown runner line', [TS + '##[error]' + UNKNOWN_MSG], 'infra-unknown-runner'),
        # P1: PR code printed the line after a failing test
        ('failing test then the no-slot line', [TEST_FAILED, NO_SLOT_JOB_LINE], None),
        ('no-slot line then failing test', [NO_SLOT_JOB_LINE, TEST_FAILED], None),
        ('compile error then the no-slot line', [TS + 'error: could not compile `x`', NO_SLOT_JOB_LINE], None),
        ('panic then the no-slot line', [TS + "thread 'a' panicked at src/a.rs:1:1:", NO_SLOT_JOB_LINE], None),
        ('nextest FAIL then the no-slot line', [TS + '        FAIL [   0.1s] x::y', NO_SLOT_JOB_LINE], None),
        # P2: the wrapper marker says a slot was held, so no wait ended the job
        ('slot acquired then the no-slot line', [ACQUIRED, NO_SLOT_JOB_LINE], None),
        ('no-slot line then slot acquired', [NO_SLOT_JOB_LINE, ACQUIRED], None),
        ('unknown runner but slot acquired', [ACQUIRED, TS + '##[error]' + UNKNOWN_MSG], None),
        # quoted, indented and mid-line copies
        ('indented copy', ['   ' + NO_SLOT_JOB_LINE], None),
        ('indented after timestamp', [TS + '   ##[error]' + NO_SLOT_MSG], None),
        ('quoted with >', [TS + '> ##[error]' + NO_SLOT_MSG], None),
        ('inside double quotes', [TS + '"##[error]' + NO_SLOT_MSG + '"'], None),
        ('mid-line after echo', [TS + 'echo ##[error]' + NO_SLOT_MSG], None),
        ('mid-line after text', [TS + 'got: ' + NO_SLOT_RAW], None),
        ('glued prefix', [TS + 'x' + NO_SLOT_RAW], None),
        ('wrong token', [TS + '##[error]' + NO_SLOT_MSG.replace('infra-no-slot: ', 'infra-no-slots: ')], None),
        ('missing counts', [TS + "##[error][#7914 semaphore] 'a': infra-no-slot: no slot free"], None),
        ('warning level', [TS + '##[warning]' + NO_SLOT_MSG], None),
        # sibling PG-ENV rule: line start only
        ('PG-ENV job line', [PG_ENV], 'ci-env'),
        ('PG-ENV mid-line', [TS + 'echo ##[error][coverage-pg] PG-ENV x'], None),
        ('PG-ENV mid-line raw', [TS + 'see ::error::[coverage-pg] PG-ENV x'], None),
        ('PG-ENV beats no-slot', [PG_ENV, NO_SLOT_JOB_LINE], 'ci-env'),
        ('PG-ENV with a failing test', [TEST_FAILED, PG_ENV], 'ci-env'),
    ]

    def test_table(self):
        for name, lines, expected in self.ROWS:
            with self.subTest(name):
                self.assertEqual(cfc.classify('\n'.join(lines)), expected)

    def test_tabs_inside_a_raw_line_are_not_read_as_a_second_job(self):
        log = '\n'.join([TS + 'a\tb\tc', NO_SLOT_JOB_LINE])
        self.assertEqual(cfc.classify_jobs(log), {'': 'infra-no-slot'})

    def test_run_log_is_split_per_job(self):
        log = '\n'.join([
            gh('Check (linux-fed,enterprise-fed)', NO_SLOT_JOB_LINE),
            gh('Check (macos-fed,enterprise-fed)', TEST_FAILED),
        ])
        self.assertEqual(cfc.classify_jobs(log), {
            'Check (linux-fed,enterprise-fed)': 'infra-no-slot', 'Check (macos-fed,enterprise-fed)': None})
        self.assertIsNone(cfc.classify(log))  # a no-slot job never hides a red job

    def test_run_log_failing_job_printing_the_line_stays_unclassified(self):
        log = '\n'.join([
            gh('A', TEST_FAILED), gh('A', NO_SLOT_JOB_LINE), gh('B', NO_SLOT_JOB_LINE)])
        self.assertEqual(cfc.classify_jobs(log), {'A': None, 'B': 'infra-no-slot'})
        self.assertIsNone(cfc.classify(log))

    def test_run_log_of_only_no_slot_jobs_is_no_slot(self):
        log = '\n'.join([gh('A', NO_SLOT_JOB_LINE), gh('B', NO_SLOT_JOB_LINE)])
        self.assertEqual(cfc.classify(log), 'infra-no-slot')

    def test_run_log_ci_env_job_beats_a_no_slot_job(self):
        log = '\n'.join([gh('A', NO_SLOT_JOB_LINE), gh('B', PG_ENV)])
        self.assertEqual(cfc.classify(log), 'ci-env')

    def test_run_log_with_a_clean_job_and_a_no_slot_job(self):
        log = '\n'.join([gh('A', TS + 'all good'), gh('B', NO_SLOT_JOB_LINE)])
        self.assertEqual(cfc.classify_jobs(log), {'A': None, 'B': 'infra-no-slot'})
        self.assertEqual(cfc.classify(log), 'infra-no-slot')

    def test_100k_line_log_is_classified_inside_a_time_bound(self):
        filler = [TS + 'compiling crate %d' % i for i in range(100000)]
        for name, lines, expected in (
                ('line at the end', filler + [NO_SLOT_JOB_LINE], 'infra-no-slot'),
                ('failure evidence at the end', filler + [NO_SLOT_JOB_LINE, TEST_FAILED], None),
                ('near-misses only', [TS + '##[error]' + NO_SLOT_MSG[:60]] * 100000, None)):
            with self.subTest(name):
                text = '\n'.join(lines)
                start = time.monotonic()
                got = cfc.classify(text)
                elapsed = time.monotonic() - start
                self.assertEqual(got, expected)
                self.assertLess(elapsed, 5.0)

    def test_cli_prints_the_class_and_exits_zero(self):
        with scratch() as td:
            log = Path(td) / 'log.txt'
            log.write_text(NO_SLOT_JOB_LINE + '\n')
            done = subprocess.run([sys.executable, '-I', str(CI_DIR / 'ci_failure_class.py'), str(log)],
                                  capture_output=True, text=True)
            self.assertEqual((done.returncode, done.stdout), (0, 'CI-CLASS: infra-no-slot\n'))

    def test_docstring_states_the_hint_only_rule_and_names_the_consumers(self):
        doc = cfc.__doc__
        self.assertIn('hint for re-run routing and never makes a gate softer', doc)
        for consumer in ('only the CLI', 'impact/gate.py', 'jev_ci_class.py'):
            self.assertIn(consumer, doc)
        for printed in ('CI-CLASS: infra-no-slot', 'CI-CLASS: infra-unknown-runner', 'CI-CLASS: none'):
            self.assertIn(printed, doc)


class RunnerSlotTie(unittest.TestCase):
    # (registered, serving, slots, expected violation lines): written by hand
    CONFIG_TABLE = [
        (['a', 'b'], ['a', 'b'], 2, []),
        (['a', 'b'], ['a'], 2, []),
        (['a', 'b'], ['a', 'b'], 1, ['g: 2 serving runners for 1 slots']),
        (['a', 'b', 'c'], ['a', 'b', 'c'], 2, ['g: 3 serving runners for 2 slots']),
        (['a', 'b'], ['a', 'a'], 2, ['g: a serving runner is listed twice']),  # M9
        (['a', 'b'], ['a', 'z'], 2, ['g: serving runner z is not a registered runner']),
        (['a', 'a'], ['a'], 1, ['registered_runners: a runner is listed twice']),
    ]

    def cfg(self, registered, serving, slots):
        return {'registered_runners': registered,
                'gates': {'g': {'slots': slots, 'label': 'x', 'serving_runners': serving}}}

    def test_config_table(self):
        for registered, serving, slots, expected in self.CONFIG_TABLE:
            with self.subTest(registered=registered, serving=serving, slots=slots):
                self.assertEqual(hsc.config_violations(self.cfg(registered, serving, slots)), expected)

    def test_duplicate_serving_runner_is_reported_even_within_the_slot_count(self):  # M9 killer
        got = hsc.config_violations(self.cfg(['a', 'b', 'c'], ['a', 'a'], 3))
        self.assertEqual(got, ['g: a serving runner is listed twice'])

    CALL = '          exec python3 -I scripts/ci/host_semaphore.py %s -- bash\n'

    def test_call_site_table(self):
        cfg = self.cfg(['a'], ['a'], 1)
        gated = {'workflows/w.yml': self.CALL % '--name g --slots 1'}
        rows = [
            ('configured gate called', gated, []),
            ('--name after another flag', {'workflows/w.yml': self.CALL % '--slots 1 --name g'}, []),
            ('--name=value form', {'workflows/w.yml': self.CALL % '--slots 1 --name=g'}, []),
            ('unconfigured gate called (M11)', {'workflows/w.yml': self.CALL % '--name other'},
             ['workflows/w.yml: calls the unconfigured gate other', 'g: configured but no workflow calls it']),
            ('configured gate never called (M12)', {'workflows/w.yml': 'run: echo hi\n'},
             ['g: configured but no workflow calls it']),
            ('a second unconfigured call beside the configured one',
             {'workflows/w.yml': (self.CALL % '--name g') + (self.CALL % '--slots 2 --name other')},
             ['workflows/w.yml: calls the unconfigured gate other']),
            ('.yaml workflow', {'workflows/w.yaml': self.CALL % '--name other', 'workflows/x.yml': self.CALL % '--name g'},
             ['workflows/w.yaml: calls the unconfigured gate other']),
            ('composite action', {'actions/c/action.yml': self.CALL % '--name other',
                                  'workflows/x.yml': self.CALL % '--name g'},
             ['actions/c/action.yml: calls the unconfigured gate other']),
            ('no --name', {'workflows/w.yml': self.CALL % '--slots 1', 'workflows/x.yml': self.CALL % '--name g'},
             ['workflows/w.yml: a host_semaphore.py call without exactly one literal --name']),
            ('variable --name', {'workflows/w.yml': self.CALL % '--name "$GATE"', 'workflows/x.yml': self.CALL % '--name g'},
             ['workflows/w.yml: a host_semaphore.py call without exactly one literal --name']),
            ('--name of the wrapped command is not the gate',
             {'workflows/w.yml': 'exec python3 scripts/ci/host_semaphore.py --name g -- tool --name zz\n'}, []),
            ('commented call is not a call', {'workflows/w.yml': '# python3 scripts/ci/host_semaphore.py --name other\n'
                                              + (self.CALL % '--name g')}, []),
            ('reference that is not a python call', {'workflows/w.yml': 'run: cat scripts/ci/host_semaphore.py\n'
                                                     + (self.CALL % '--name g')},
             ['workflows/w.yml: a host_semaphore.py reference that is not a python3 call']),
            ('continued line', {'workflows/w.yml': 'exec python3 -I scripts/ci/host_semaphore.py \\\n  --slots 1 \\\n  --name g -- x\n'}, []),
        ]
        for name, texts, expected in rows:
            with self.subTest(name):
                self.assertEqual(hsc.call_site_violations(cfg, texts), expected)
        self.assertEqual(hsc.call_site_violations(cfg, gated), [])

    def test_github_texts_reads_yml_yaml_and_composite_actions(self):
        with scratch() as td:
            gh_dir = Path(td) / '.github'
            for rel in ('workflows/a.yml', 'workflows/b.yaml', 'actions/c/action.yml', 'actions/d/action.yaml'):
                (gh_dir / rel).parent.mkdir(parents=True, exist_ok=True)
                (gh_dir / rel).write_text('x: 1\n')
            (gh_dir / 'workflows' / 'note.md').write_text('no\n')
            self.assertEqual(sorted(hsc.github_texts(gh_dir)), [
                'actions/c/action.yml', 'actions/d/action.yaml', 'workflows/a.yml', 'workflows/b.yaml'])

    def test_shipped_config_and_workflows_hold(self):
        cfg = hsc.load_config()
        texts = hsc.github_texts()
        workflows = {k: v for k, v in texts.items() if k.startswith('workflows/')}
        self.assertEqual(hsc.config_violations(cfg), [])
        self.assertEqual(hsc.call_site_violations(cfg, texts), [])
        self.assertEqual(hsc.bound_violations(cfg, workflows), [])

    def test_shipped_runner_to_slot_values_are_the_written_ones(self):
        cfg = json.loads(CONFIG.read_text())
        self.assertEqual(sorted(cfg['registered_runners']), [
            'f1-macos-fed', 'f1-macos-fed-2', 'f1-macos-fed-3', 'f1-macos-fed-4', 'f1-macos-fed-5',
            'f2-linux-fed', 'f2-linux-fed-2', 'f2-linux-fed-3', 'f2-linux-fed-4'])
        self.assertEqual(cfg['gates'], {'linux-fed-tests': {
            'slots': 2, 'label': 'linux-fed', 'serving_runners': ['f2-linux-fed', 'f2-linux-fed-2']}})

    def test_script_exits_zero_on_the_repository(self):
        done = subprocess.run([sys.executable, '-I', str(CI_DIR / 'host_slots_check.py')],
                              capture_output=True, text=True)
        self.assertEqual((done.returncode, done.stdout), (0, ''))


class MalformedConfig(unittest.TestCase):
    BAD = [
        ('not json', '{nope', 'is unreadable or not JSON'),
        ('top level list', '[]', 'top level must be an object'),
        ('no registered', '{"gates": {"g": {}}}', 'registered_runners must be a list of non-empty strings'),
        ('registered not strings', '{"registered_runners": [1], "gates": {}}',
         'registered_runners must be a list of non-empty strings'),
        ('no gates', '{"registered_runners": ["a"], "gates": {}}', 'gates must be a non-empty object'),
        ('gate not object', '{"registered_runners": ["a"], "gates": {"g": 3}}', 'gate g must be an object'),
        ('slots string', '{"registered_runners": ["a"], "gates": {"g": {"slots": "2"}}}',
         'gate g: slots must be an integer from 1 to 64'),
        ('slots bool', '{"registered_runners": ["a"], "gates": {"g": {"slots": true}}}',
         'gate g: slots must be an integer from 1 to 64'),
        ('slots zero', '{"registered_runners": ["a"], "gates": {"g": {"slots": 0}}}',
         'gate g: slots must be an integer from 1 to 64'),
        ('slots huge', '{"registered_runners": ["a"], "gates": {"g": {"slots": 65}}}',
         'gate g: slots must be an integer from 1 to 64'),
        ('label missing', '{"registered_runners": ["a"], "gates": {"g": {"slots": 1}}}',
         'gate g: label must be a non-empty string'),
        ('serving not list', '{"registered_runners": ["a"], "gates": {"g": {"slots": 1, "label": "x", "serving_runners": "a"}}}',
         'gate g: serving_runners must be a list of non-empty strings'),
        ('bad gate name', '{"registered_runners": ["a"], "gates": {"g h": {}}}', "gate name 'g h' is not a plain name"),
    ]

    def test_each_malformed_file_is_one_named_violation_never_a_traceback(self):
        for name, text, message in self.BAD:
            with self.subTest(name), scratch() as td:
                path = Path(td) / 'host_slots.json'
                path.write_text(text)
                with self.assertRaises(hsc.ConfigError) as ctx:
                    hsc.load_config(path)
                self.assertIn(message, str(ctx.exception))

    def test_script_prints_one_line_and_exits_2_on_a_malformed_file(self):
        with scratch() as td:
            repo = Path(td) / 'repo'
            (repo / 'scripts' / 'ci').mkdir(parents=True)
            for name in ('host_slots_check.py', 'taint_boundary.py', 'workflow_annotation.py'):
                if (CI_DIR / name).exists():
                    (repo / 'scripts' / 'ci' / name).write_text((CI_DIR / name).read_text())
            (repo / 'scripts' / 'ci' / 'host_slots.json').write_text('{"registered_runners": "x", "gates": 3}')
            (repo / '.github' / 'workflows').mkdir(parents=True)
            done = subprocess.run([sys.executable, '-I', str(repo / 'scripts' / 'ci' / 'host_slots_check.py')],
                                  capture_output=True, text=True)
            self.assertEqual(done.returncode, 2, done.stderr)
            self.assertEqual(done.stdout.splitlines(),
                             ['host_slots_check: malformed: registered_runners must be a list of non-empty strings'])
            self.assertEqual(done.stderr, '')


class WaitBound(unittest.TestCase):
    """Invariant 3: read from the parsed workflow, so a decoy comment or other quoting cannot widen it."""

    CI = CI_YML.read_text()
    LINE = "          HOST_SEMAPHORE_MAX_WAIT_SECS: '600'\n"

    def violations(self, text, extra=None):
        texts = {'workflows/ci.yml': text}
        texts.update(extra or {})
        return hsc.bound_violations(hsc.load_config(), texts)

    def test_the_shipped_bound_is_one_definition_of_600(self):
        defs = hsc.parsed_env_values({'ci.yml': self.CI}, 'HOST_SEMAPHORE_MAX_WAIT_SECS')
        self.assertEqual(defs, [('ci.yml', '600')])
        self.assertEqual(hs.SEMAPHORE_MAX_WAIT_SECS_DEFAULT, EXPECTED_WAIT_SECS)
        self.assertLessEqual(EXPECTED_WAIT_SECS, IDLE_SEAT_CEILING_SECS)
        self.assertEqual(hsc.IDLE_SEAT_CEILING_SECS, IDLE_SEAT_CEILING_SECS)

    def test_reviewer_mutant_decoy_comment_double_quotes_3600_goes_red(self):
        self.assertIn(self.LINE, self.CI)
        mutant = self.CI.replace(
            self.LINE, "          # HOST_SEMAPHORE_MAX_WAIT_SECS: '600'\n          HOST_SEMAPHORE_MAX_WAIT_SECS: \"3600\"\n")
        self.assertEqual(self.violations(mutant), [
            'workflows/ci.yml: HOST_SEMAPHORE_MAX_WAIT_SECS 3600 is above the 900 s idle seat ceiling'])

    def test_every_quoting_form_is_read_as_its_value(self):
        for quoted, expected in (("'3600'", 3600), ('"3600"', 3600), ('3600', 3600)):
            with self.subTest(form=quoted):
                mutant = self.CI.replace(self.LINE, "          HOST_SEMAPHORE_MAX_WAIT_SECS: %s\n" % quoted)
                got = hsc.parsed_env_values({'ci.yml': mutant}, 'HOST_SEMAPHORE_MAX_WAIT_SECS')
                self.assertEqual([(f, str(v)) for f, v in got], [('ci.yml', str(expected))])
                self.assertEqual(len(self.violations(mutant)), 1)

    def test_a_second_definition_in_any_workflow_file_goes_red(self):
        other = 'name: x\njobs:\n  j:\n    runs-on: x\n    env:\n      HOST_SEMAPHORE_MAX_WAIT_SECS: "60"\n    steps: []\n'
        for fname in ('workflows/other.yml', 'workflows/other.yaml'):
            with self.subTest(file=fname):
                self.assertEqual(self.violations(self.CI, {fname: other}),
                                 ['HOST_SEMAPHORE_MAX_WAIT_SECS must be defined exactly once, found 2'])

    def test_a_missing_definition_and_a_non_integer_go_red(self):
        removed = self.CI.replace(self.LINE, '')
        self.assertEqual(self.violations(removed), ['HOST_SEMAPHORE_MAX_WAIT_SECS must be defined exactly once, found 0'])
        text = self.CI.replace(self.LINE, "          HOST_SEMAPHORE_MAX_WAIT_SECS: ${{ vars.WAIT }}\n")
        self.assertEqual(self.violations(text), [
            "workflows/ci.yml: HOST_SEMAPHORE_MAX_WAIT_SECS is not a plain integer ('${{ vars.WAIT }}')"])

    def test_slot_count_in_the_workflow_must_match_the_config(self):
        mutant = self.CI.replace("&& '2' || '0'", "&& '4' || '0'")
        self.assertNotEqual(mutant, self.CI)
        got = self.violations(mutant)
        self.assertEqual(len(got), 1, got)
        self.assertIn('matches no configured slot count [2]', got[0])

    def test_workflow_slots_value_is_two(self):
        defs = hsc.parsed_env_values({'ci.yml': self.CI}, 'HOST_SEMAPHORE_SLOTS')
        self.assertEqual(len(defs), 1)
        self.assertEqual(re.findall(r"&& '(\d+)' \|\| '0'", defs[0][1]), ['2'])


class ChangelogAndDocs(unittest.TestCase):
    def test_changelog_fragment_exists(self):
        text = (REPO / 'changelog.d' / '9231.fixed.md').read_text()
        self.assertIn('infra-no-slot', text)


if __name__ == '__main__':
    unittest.main()
