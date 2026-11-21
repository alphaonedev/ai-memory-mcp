#!/usr/bin/env python3
"""Class invariant for #9231: a host-slot wait never ends as a red TEST failure, and the wrapper names its outcome.

The CI failure-classifier class for that outcome is tracked in #9833; this file does not test it.

Defect class pinned here: an outcome label decided from text or an exit code that something
else can also produce, and a rule held by a test that does not go red when the rule breaks.

Invariants, each a table with expected values written out by hand (none computed from the code under test):
  1. No slot ends as the named outcome infra-no-slot: one error annotation whose MESSAGE carries the token
     (a job log shows `##[error]<message>` with no title), exit code 82, a title without colon or comma.
     A runner outside host_slots.json ends as infra-unknown-runner (83). A command that itself exits with
     82, 83, 84 or 85 is reported as 84; every other code, 75 of the product binary included, passes through.
  2. The wait bound, the slot counts and the serving runners are read from the PARSED workflow and
     configuration: a decoy comment, another quoting or a second definition cannot widen them.
  3. host_slots_check.py: one error line and exit 2 on a malformed file; .yaml files, composite actions and
     `--name` in any position are covered; every call has exactly one --max-wait-secs and run text never
     writes HOST_SEMAPHORE_MAX_WAIT_SECS.
  4. R2-C, by construction: whatever the source of the wait (the flag, a repeated flag, the env key), the
     wrapper refuses a value above IDLE_SEAT_CEILING_SECS (900 s, one literal in host_slot_limits.py, read
     by both scripts), 0, negative, empty or not a plain decimal integer with exit 85, before any slot or
     command; 85 is reserved, so a refusal is never a child's exit code.

Run: python3 -m unittest discover -s scripts/ci/tests
"""
import ast
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
import host_slots_check as hsc  # noqa: E402

SCRATCH_ROOT = REPO / '.local-runs'
CI_YML = REPO / '.github' / 'workflows' / 'ci.yml'
CONFIG = CI_DIR / 'host_slots.json'

# Written out, not read from the code under test.
EXIT_NO_SLOT = 82
EXIT_UNKNOWN_RUNNER = 83
EXIT_CHILD_RESERVED = 84
EXIT_WAIT_REFUSED = 85
EXIT_BAD_ARGUMENTS = 2
EXPECTED_WAIT_SECS = 600
IDLE_SEAT_CEILING_SECS = 900
WAIT_ENV_KEY = 'HOST_SEMAPHORE_MAX_WAIT_SECS'
LIMITS_MODULE = CI_DIR / 'host_slot_limits.py'
# Every producer of an exit code this wrapper's callers can see. None may use 82, 83, 84 or 85.
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


def scratch():
    SCRATCH_ROOT.mkdir(exist_ok=True)
    return tempfile.TemporaryDirectory(dir=str(SCRATCH_ROOT))


def need(test, module, name):
    """MODULE.NAME, or an assertion failure naming it (a missing name is a red assertion, never an error)."""
    value = getattr(module, name, None)
    test.assertIsNotNone(value, '%s has no %s' % (module.__name__, name))
    return value


# The files a copy of scripts/ci needs to run host_semaphore.py and host_slots_check.py on its own.
COPIED_CI_FILES = ('host_semaphore.py', 'host_slots_check.py', 'host_slot_limits.py', 'taint_boundary.py',
                   'workflow_annotation.py', 'host_slots.json')


def copy_repo(td, replace=None, extra=None):
    """A minimal repository under TD: COPIED_CI_FILES, ci.yml and EXTRA {repo path: text}; REPLACE {file: text}."""
    repo = Path(td) / 'repo'
    (repo / 'scripts' / 'ci').mkdir(parents=True)
    (repo / '.github' / 'workflows').mkdir(parents=True)
    for name in COPIED_CI_FILES:
        if (CI_DIR / name).exists():
            (repo / 'scripts' / 'ci' / name).write_text((CI_DIR / name).read_text())
    (repo / '.github' / 'workflows' / 'ci.yml').write_text(CI_YML.read_text())
    for name, text in (replace or {}).items():
        target = repo / 'scripts' / 'ci' / name
        if text is None:
            target.unlink(missing_ok=True)
        else:
            target.write_text(text)
    for rel, text in (extra or {}).items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    return repo


HOLDER = (
    'import fcntl, os, sys, time\n'
    'fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n'
    'fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n'
    'print("held", flush=True)\n'
    'time.sleep(120)\n'
)
# The shortest wait the wrapper accepts (0 is refused since R2-C): one poll of one second.
WAIT_ONE_SEC = ('--max-wait-secs', '1', '--poll-secs', '1')


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

    def run(self, slots, child, runner=None, gate=None, use_config=True, wait=WAIT_ONE_SEC, env_wait=None):
        env = {k: v for k, v in os.environ.items() if k not in ('RUNNER_NAME', WAIT_ENV_KEY)}
        if runner is not None:
            env['RUNNER_NAME'] = runner
        if env_wait is not None:
            env[WAIT_ENV_KEY] = env_wait
        cmd = [sys.executable, '-I', str(CI_DIR / 'host_semaphore.py'), '--name', gate or self.gate,
               '--slots', str(slots), *wait, '--root', str(self.root), '--label', 'T']
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
                    "::error title=infra no-slot::[#7914 semaphore] 'T': infra-no-slot: no slot free after 1s "
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

    def test_child_code_75_of_the_product_binary_passes_through_unchanged(self):
        w = wrapper(self, ['a'], slots_in_file=1)
        rc, out = w.run(1, child_exit(75))
        self.assertEqual(rc, 75, out)
        self.assertEqual(error_lines(out), [])

    def test_child_codes_that_are_not_reserved_pass_through(self):
        for code in (1, 2, 3, 7, 81, 86, 88, 101, 130):
            with self.subTest(code=code):
                w = wrapper(self, ['a'], slots_in_file=1)
                rc, out = w.run(1, child_exit(code))
                self.assertEqual(rc, code, out)

    def test_child_exiting_with_a_reserved_code_is_reported_as_84_with_an_annotation(self):
        for code in (82, 83, 84, 85):
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
        self.assertEqual((getattr(hs, 'EXIT_NO_SLOT', None), getattr(hs, 'EXIT_UNKNOWN_RUNNER', None),
                          getattr(hs, 'EXIT_CHILD_RESERVED', None), getattr(hs, 'EXIT_WAIT_REFUSED', None)),
                         (82, 83, 84, 85))
        self.assertEqual(hs.RESERVED_EXIT_CODES, frozenset((82, 83, 84, 85)))

    def test_no_producer_in_the_table_uses_a_reserved_code(self):
        for code, who in EXIT_CODE_PRODUCERS.items():
            with self.subTest(code=code, who=who):
                self.assertNotIn(code, hs.RESERVED_EXIT_CODES)

    def test_reserved_codes_are_not_a_signal_code(self):
        self.assertTrue(all(0 < c < 128 for c in hs.RESERVED_EXIT_CODES))


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

    CALL = '          exec python3 -I scripts/ci/host_semaphore.py %s --max-wait-secs 600 -- bash\n'
    NO_FLAG = 'workflows/w.yml: a host_semaphore.py call without exactly one --max-wait-secs'

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
             {'workflows/w.yml': 'exec python3 scripts/ci/host_semaphore.py --name g --max-wait-secs 600 -- tool --name zz\n'},
             []),
            ('commented call is not a call', {'workflows/w.yml': '# python3 scripts/ci/host_semaphore.py --name other\n'
                                              + (self.CALL % '--name g')}, []),
            ('reference that is not a python call', {'workflows/w.yml': 'run: cat scripts/ci/host_semaphore.py\n'
                                                     + (self.CALL % '--name g')},
             ['workflows/w.yml: a host_semaphore.py reference that is not a python3 call']),
            ('continued line', {'workflows/w.yml': 'exec python3 -I scripts/ci/host_semaphore.py \\\n  --slots 1 \\\n'
                                                   '  --name g \\\n  --max-wait-secs 600 -- x\n'}, []),
            # R2-C: exactly one --max-wait-secs per call segment (the wrapper refuses a repeat at run time too)
            ('W6 a second --max-wait-secs 3600 at the call site', {'workflows/w.yml': self.CALL % '--name g --max-wait-secs 3600'},
             [self.NO_FLAG]),
            ('W6 the second one in = form', {'workflows/w.yml': self.CALL % '--name g --max-wait-secs=3600'}, [self.NO_FLAG]),
            ('W6 the second one on a continued line',
             {'workflows/w.yml': 'exec python3 scripts/ci/host_semaphore.py --name g --max-wait-secs 600 \\\n'
                                 '  --max-wait-secs 3600 -- x\n'}, [self.NO_FLAG]),
            ('no --max-wait-secs at all', {'workflows/w.yml': 'exec python3 scripts/ci/host_semaphore.py --name g -- bash\n'},
             [self.NO_FLAG]),
            ('--max-wait-secs of the wrapped command is not counted',
             {'workflows/w.yml': 'exec python3 scripts/ci/host_semaphore.py --name g --max-wait-secs 600 -- t --max-wait-secs 5\n'},
             []),
            ('the only --max-wait-secs is after -- (the wrapped command)',
             {'workflows/w.yml': 'exec python3 scripts/ci/host_semaphore.py --name g -- t --max-wait-secs 5\n'}, [self.NO_FLAG]),
        ]
        for name, texts, expected in rows:
            with self.subTest(name):
                self.assertEqual(hsc.call_site_violations(cfg, texts), expected)
        self.assertEqual(hsc.call_site_violations(cfg, gated), [])

    KEY_USE = ('%s: HOST_SEMAPHORE_MAX_WAIT_SECS is used other than as its env mapping key or a plain $ read; '
               'set it only in the one env mapping')
    EXEC = '          exec python3 -I scripts/ci/host_semaphore.py --name g --max-wait-secs "$HOST_SEMAPHORE_MAX_WAIT_SECS" -- b\n'

    def test_wait_key_in_run_text_table(self):
        """R2-C (c): the key is written only as its env mapping key or read as $KEY / ${KEY}; any other use refused."""
        w_use = self.KEY_USE % 'workflows/w.yml'
        rows = [
            ('the env mapping and a plain read', "        env:\n          HOST_SEMAPHORE_MAX_WAIT_SECS: '600'\n" + self.EXEC,
             []),
            ('the braced read', '          exec x --max-wait-secs "${HOST_SEMAPHORE_MAX_WAIT_SECS}" -- b\n', []),
            ('a comment line is not run text', '          # HOST_SEMAPHORE_MAX_WAIT_SECS=3600\n' + self.EXEC, []),
            ('a longer name is another variable', '          HOST_SEMAPHORE_MAX_WAIT_SECS_NOTE=1\n', []),
            ('W7 assignment before the exec', '          HOST_SEMAPHORE_MAX_WAIT_SECS=3600\n' + self.EXEC, [w_use]),
            ('export', '          export HOST_SEMAPHORE_MAX_WAIT_SECS=3600\n', [w_use]),
            ('export of the bare name', '          export HOST_SEMAPHORE_MAX_WAIT_SECS\n', [w_use]),
            ('declare -x', '          declare -x HOST_SEMAPHORE_MAX_WAIT_SECS=3600\n', [w_use]),
            ('readonly', '          readonly HOST_SEMAPHORE_MAX_WAIT_SECS=3600\n', [w_use]),
            ('local', '          local HOST_SEMAPHORE_MAX_WAIT_SECS=3600\n', [w_use]),
            ('after a semicolon', '          true; HOST_SEMAPHORE_MAX_WAIT_SECS=3600; exec x\n', [w_use]),
            ('after &&', '          true&&HOST_SEMAPHORE_MAX_WAIT_SECS=3600 exec x\n', [w_use]),
            ('append', '          HOST_SEMAPHORE_MAX_WAIT_SECS+=0\n', [w_use]),
            ('env prefix of a command', '          env HOST_SEMAPHORE_MAX_WAIT_SECS=3600 python3 x\n', [w_use]),
            ('run: one-liner', '      - run: HOST_SEMAPHORE_MAX_WAIT_SECS=3600 bash x\n', [w_use]),
            ('default-assigning expansion', '          exec x --max-wait-secs "${HOST_SEMAPHORE_MAX_WAIT_SECS:=3600}" -- b\n',
             [w_use]),
            ('read builtin', '          read HOST_SEMAPHORE_MAX_WAIT_SECS < f\n', [w_use]),
            ('printf -v', '          printf -v HOST_SEMAPHORE_MAX_WAIT_SECS 3600\n', [w_use]),
            ('unset', '          unset HOST_SEMAPHORE_MAX_WAIT_SECS\n', [w_use]),
            ('eval text', "          eval 'HOST_SEMAPHORE_MAX_WAIT_SECS=3600'\n", [w_use]),
            ('expression read', '          x: ${{ env.HOST_SEMAPHORE_MAX_WAIT_SECS }}\n', [w_use]),
            ('inline comment after code', '          true  # HOST_SEMAPHORE_MAX_WAIT_SECS=3600\n', [w_use]),
            ('continued line', '          true \\\n            HOST_SEMAPHORE_MAX_WAIT_SECS=3600\n', [w_use]),
            ('two uses on two lines', '          HOST_SEMAPHORE_MAX_WAIT_SECS=1\n          export HOST_SEMAPHORE_MAX_WAIT_SECS\n',
             [w_use, w_use]),
        ]
        for name, text, expected in rows:
            with self.subTest(name):
                self.assertEqual(need(self, hsc, 'wait_key_violations')({'workflows/w.yml': text}), expected)
        for rel in ('workflows/w.yaml', 'actions/c/action.yml', 'actions/c/action.yaml'):
            with self.subTest(file=rel):
                self.assertEqual(need(self, hsc, 'wait_key_violations')({rel:'          HOST_SEMAPHORE_MAX_WAIT_SECS=3600\n' + self.EXEC}),
                                 [self.KEY_USE % rel])

    def test_wait_key_scan_is_linear_on_a_large_text(self):
        text = ('          echo "$HOST_SEMAPHORE_MAX_WAIT_SECS" ' + 'x' * 200 + '\n') * 1000
        text += '          HOST_SEMAPHORE_MAX_WAIT_SECS=3600\n'
        self.assertGreater(len(text), 100000)
        start = time.monotonic()
        got = need(self, hsc, 'wait_key_violations')({'workflows/w.yml': text})
        self.assertLess(time.monotonic() - start, 2.0)
        self.assertEqual(got, [self.KEY_USE % 'workflows/w.yml'])

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
        self.assertEqual(hsc.bound_violations(cfg, texts), [])
        self.assertEqual(need(self, hsc, 'wait_key_violations')(texts), [])

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
            for name in ('host_slots_check.py', 'host_slot_limits.py', 'taint_boundary.py', 'workflow_annotation.py'):
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
    """Invariant 2: read from the parsed workflow, so a decoy comment or other quoting cannot widen it."""

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


def refused(reason):
    """The one stdout line of a refused wait, written out by hand."""
    return ("::error title=infra wait-refused::[#7914 semaphore] 'T': infra-wait-refused: %s; "
            "no slot taken, no command ran; exit 85" % reason)


F_ABOVE = refused('--max-wait-secs is above the 900 s idle seat ceiling')
F_ZERO = refused('--max-wait-secs is 0; the wait is at least 1 s')
F_NEGATIVE = refused('--max-wait-secs is negative')
F_NOT_INT = refused('--max-wait-secs is not a plain decimal integer')
F_EMPTY = refused('--max-wait-secs is empty')
E_ABOVE = refused('HOST_SEMAPHORE_MAX_WAIT_SECS is above the 900 s idle seat ceiling')
E_ZERO = refused('HOST_SEMAPHORE_MAX_WAIT_SECS is 0; the wait is at least 1 s')
E_NEGATIVE = refused('HOST_SEMAPHORE_MAX_WAIT_SECS is negative')
E_NOT_INT = refused('HOST_SEMAPHORE_MAX_WAIT_SECS is not a plain decimal integer')
E_EMPTY = refused('HOST_SEMAPHORE_MAX_WAIT_SECS is empty')
MARKER_CHILD = 'import sys; open(sys.argv[1], "w").close(); print("CHILD-RAN")'


class RunTimeCeiling(unittest.TestCase):
    """R2-C (b): the wrapper refuses every effective wait above the ceiling, whatever its source, before any slot or
    child; the refusal has its own code 85, so it is never mistaken for a child that exits 2."""

    # (--max-wait-secs values, HOST_SEMAPHORE_MAX_WAIT_SECS or None for unset, exit code, error lines): by hand
    TABLE = [
        (['901'], None, 85, [F_ABOVE]),
        (['3600'], None, 85, [F_ABOVE]),
        (['0'], None, 85, [F_ZERO]),
        (['-1'], None, 85, [F_NEGATIVE]),
        (['abc'], None, 85, [F_NOT_INT]),
        ([''], None, 85, [F_EMPTY]),
        (['900 '], None, 85, [F_NOT_INT]),
        ([' 900'], None, 85, [F_NOT_INT]),
        (['0900'], None, 85, [F_NOT_INT]),
        (['+5'], None, 85, [F_NOT_INT]),
        (['1e3'], None, 85, [F_NOT_INT]),
        (['6.5'], None, 85, [F_NOT_INT]),
        (['०९'], None, 85, [F_NOT_INT]),  # Devanagari digits: int() takes them, the wrapper does not
        (['9' * 100000], None, 85, [F_ABOVE]),  # above the ceiling by length, never converted
        (['900'], None, 0, []),
        (['600'], None, 0, []),
        (['1'], None, 0, []),
        (['600', '3600'], None, 85, [refused('--max-wait-secs is given 2 times; give it once')]),
        (['600', '600'], None, 85, [refused('--max-wait-secs is given 2 times; give it once')]),
        (['1', '2', '3'], None, 85, [refused('--max-wait-secs is given 3 times; give it once')]),
        ([], '3600', 85, [E_ABOVE]),
        ([], '901', 85, [E_ABOVE]),
        ([], '', 85, [E_EMPTY]),
        ([], '0', 85, [E_ZERO]),
        ([], '-5', 85, [E_NEGATIVE]),
        ([], 'x', 85, [E_NOT_INT]),
        ([], '600 ', 85, [E_NOT_INT]),
        ([], '600', 0, []),
        ([], '900', 0, []),
        ([], None, 0, []),  # neither: the 600 s default
        (['600'], '600', 0, []),
        (['600'], '300', 85, [refused('--max-wait-secs 600 differs from HOST_SEMAPHORE_MAX_WAIT_SECS 300')]),
        (['600'], '3600', 85, [E_ABOVE]),
        (['3600'], '600', 85, [F_ABOVE]),
        (['abc'], '3600', 85, [F_NOT_INT]),
        (['600', '700'], '3600', 85, [refused('--max-wait-secs is given 2 times; give it once')]),
    ]

    def run_row(self, values, env_value, runner=None):
        w = wrapper(self, ['a'], slots_in_file=1)
        marker = Path(w.td.name) / 'child-started'
        wait = [arg for value in values for arg in ('--max-wait-secs', value)] + ['--poll-secs', '1']
        rc, out = w.run(1, [sys.executable, '-c', MARKER_CHILD, str(marker)], wait=wait, env_wait=env_value, runner=runner)
        return w, marker, rc, out

    def test_refusal_table(self):
        for values, env_value, code, expected in self.TABLE:
            with self.subTest(flags=[v[:12] for v in values], env=env_value):
                w, marker, rc, out = self.run_row(values, env_value)
                self.assertEqual(rc, code, out[:500])
                self.assertEqual(error_lines(out), expected)
                if code == EXIT_WAIT_REFUSED:
                    # the child is NOT started, no slot directory is made and the refusal is the only output line
                    self.assertFalse(marker.exists())
                    self.assertFalse(w.root.exists())
                    self.assertEqual(out.splitlines(), expected)
                else:
                    self.assertTrue(marker.exists(), out)

    def test_refusal_comes_before_the_runner_check(self):
        w, marker, rc, out = self.run_row(['3600'], None, runner='rogue-runner')
        self.assertEqual((rc, out.splitlines()), (85, [F_ABOVE]))
        self.assertFalse(marker.exists())

    def test_an_abbreviated_flag_is_a_bad_argument_not_a_second_spelling(self):
        w = wrapper(self, ['a'], slots_in_file=1)
        marker = Path(w.td.name) / 'child-started'
        rc, out = w.run(1, [sys.executable, '-c', MARKER_CHILD, str(marker)], wait=['--max-wait', '3600'])
        self.assertEqual(rc, EXIT_BAD_ARGUMENTS, out)
        self.assertFalse(marker.exists())

    def test_main_called_in_process_refuses_too(self):
        import contextlib
        import io
        with scratch() as td:
            buf = io.StringIO()
            saved = os.environ.pop(WAIT_ENV_KEY, None)
            try:
                with contextlib.redirect_stdout(buf):
                    rc = hs.main(['--name', 'g', '--max-wait-secs', '3600', '--root', str(Path(td) / 'locks'),
                                  '--label', 'T', '--', 'true'])
            finally:
                if saved is not None:
                    os.environ[WAIT_ENV_KEY] = saved
            self.assertEqual((rc, buf.getvalue().splitlines()), (85, [F_ABOVE]))
            self.assertFalse((Path(td) / 'locks').exists())


class OneConstant(unittest.TestCase):
    """R2-C (a): IDLE_SEAT_CEILING_SECS is one literal in host_slot_limits.py, read by both scripts."""

    def test_limits_module_holds_the_one_literal_900(self):
        self.assertTrue(LIMITS_MODULE.is_file(), LIMITS_MODULE)
        tree = ast.parse(LIMITS_MODULE.read_text())
        values = [node.value.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
                  and [getattr(t, 'id', None) for t in node.targets] == ['IDLE_SEAT_CEILING_SECS']
                  and isinstance(node.value, ast.Constant)]
        self.assertEqual(values, [900])

    def test_both_scripts_carry_the_written_value(self):
        self.assertEqual(need(self, hs, 'IDLE_SEAT_CEILING_SECS'), IDLE_SEAT_CEILING_SECS)
        self.assertEqual(need(self, hsc, 'IDLE_SEAT_CEILING_SECS'), IDLE_SEAT_CEILING_SECS)

    def test_no_other_script_holds_the_value_or_binds_the_name(self):
        """Allowlist over every .py under scripts/ outside a tests directory: only host_slot_limits.py."""
        offenders = []
        for path in sorted((REPO / 'scripts').rglob('*.py')):
            rel = path.relative_to(REPO).as_posix()
            if 'tests' in path.relative_to(REPO).parts or path == LIMITS_MODULE:
                continue
            try:
                tree = ast.parse(path.read_text(encoding='utf-8'))
            except (SyntaxError, UnicodeDecodeError, ValueError) as exc:
                offenders.append('%s: unparsable (%s)' % (rel, type(exc).__name__))
                continue
            for node in ast.walk(tree):
                if (isinstance(node, ast.Constant) and type(node.value) in (int, float)
                        and node.value == IDLE_SEAT_CEILING_SECS):
                    offenders.append('%s:%d: the value %r' % (rel, node.lineno, node.value))
                targets = []
                if isinstance(node, ast.Assign):
                    targets = node.targets
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                    targets = [node.target]
                for target in targets:
                    if getattr(target, 'id', None) == 'IDLE_SEAT_CEILING_SECS' and not (
                            isinstance(node, ast.Assign) and isinstance(node.value, ast.Attribute)
                            and node.value.attr == 'IDLE_SEAT_CEILING_SECS'):
                        offenders.append('%s:%d: binds IDLE_SEAT_CEILING_SECS to its own value' % (rel, node.lineno))
                if isinstance(node, ast.ImportFrom) and node.module != 'host_slot_limits' and any(
                        alias.name == 'IDLE_SEAT_CEILING_SECS' for alias in node.names):
                    offenders.append('%s:%d: imports IDLE_SEAT_CEILING_SECS from %s' % (rel, node.lineno, node.module))
        self.assertEqual(offenders, [])

    def test_a_changed_limits_module_moves_both_checks(self):
        self.assertTrue(LIMITS_MODULE.is_file(), LIMITS_MODULE)
        text = LIMITS_MODULE.read_text()
        lowered = text.replace('IDLE_SEAT_CEILING_SECS = 900', 'IDLE_SEAT_CEILING_SECS = 300')
        self.assertNotEqual(lowered, text)
        with scratch() as td:
            repo = copy_repo(td, replace={'host_slot_limits.py': lowered})
            env = {k: v for k, v in os.environ.items() if k not in ('RUNNER_NAME', WAIT_ENV_KEY)}
            done = subprocess.run([sys.executable, '-I', str(repo / 'scripts' / 'ci' / 'host_semaphore.py'), '--name', 'g',
                                   '--max-wait-secs', '400', '--root', str(repo / 'locks'), '--label', 'T', '--', 'true'],
                                  capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual((done.returncode, done.stdout.splitlines()),
                             (85, [refused('--max-wait-secs is above the 300 s idle seat ceiling')]))
            done = subprocess.run([sys.executable, '-I', str(repo / 'scripts' / 'ci' / 'host_slots_check.py')],
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual((done.returncode, done.stdout.splitlines()), (1, [
                'host_slots_check: workflows/ci.yml: HOST_SEMAPHORE_MAX_WAIT_SECS 600 is above the 300 s idle seat ceiling']))

    # (host_slot_limits.py text or None for absent, the cause named on stderr): by hand
    BAD_LIMITS = [
        (None, 'FileNotFoundError'),
        ('IDLE_SEAT_CEILING_SECS = "900"\n', 'TypeError'),
        ('IDLE_SEAT_CEILING_SECS = True\n', 'TypeError'),
        ('IDLE_SEAT_CEILING_SECS = 900.0\n', 'TypeError'),
        ('IDLE_SEAT_CEILING_SECS = 0\n', 'ValueError'),
        ('IDLE_SEAT_CEILING_SECS = -900\n', 'ValueError'),
        ('OTHER = 900\n', 'AttributeError'),
        ('raise RuntimeError("boom")\n', 'RuntimeError'),
        ('IDLE_SEAT_CEILING_SECS = (\n', 'SyntaxError'),
        ('class OddLoadError(Exception):\n    pass\nraise OddLoadError()\n', 'Exception'),  # an unlisted class
    ]

    def test_an_unloadable_limits_module_refuses_with_exit_4_before_any_command(self):
        for text, cause in self.BAD_LIMITS:
            with self.subTest(cause=cause, text=text), scratch() as td:
                repo = copy_repo(td, replace={'host_slot_limits.py': text})
                marker = Path(td) / 'child-started'
                env = {k: v for k, v in os.environ.items() if k not in ('RUNNER_NAME', WAIT_ENV_KEY)}
                done = subprocess.run([sys.executable, '-I', str(repo / 'scripts' / 'ci' / 'host_semaphore.py'),
                                       '--name', 'g', '--max-wait-secs', '1', '--root', str(repo / 'locks'), '--label', 'T',
                                       '--', sys.executable, '-c', MARKER_CHILD, str(marker)],
                                      capture_output=True, text=True, env=env, timeout=60)
                self.assertEqual(done.returncode, 4, done.stdout + done.stderr)
                self.assertEqual(done.stdout.splitlines(), [
                    '::error title=host_semaphore refused::host_semaphore: refused: host_slot_limits.py next to the script '
                    'cannot be loaded'])
                self.assertEqual(done.stderr.splitlines(), [
                    'host_semaphore: refused: host_slot_limits.py next to the script cannot be loaded (%s)' % cause])
                self.assertFalse(marker.exists())


class MainReadsEveryGithubText(unittest.TestCase):
    """R2-C (c), sibling: the bound and the key check read composite actions too, not only workflows."""

    ACTION = ('name: c\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      env:\n'
              "        HOST_SEMAPHORE_MAX_WAIT_SECS: '3600'\n      run: echo hi\n")

    def run_check(self, extra):
        with scratch() as td:
            repo = copy_repo(td, extra=extra)
            done = subprocess.run([sys.executable, '-I', str(repo / 'scripts' / 'ci' / 'host_slots_check.py')],
                                  capture_output=True, text=True, timeout=60)
            return done.returncode, done.stdout.splitlines()

    def test_a_composite_action_definition_counts(self):
        self.assertEqual(self.run_check({'.github/actions/c/action.yml': self.ACTION}), (1, [
            'host_slots_check: HOST_SEMAPHORE_MAX_WAIT_SECS must be defined exactly once, found 2',
            'host_slots_check: actions/c/action.yml: HOST_SEMAPHORE_MAX_WAIT_SECS 3600 is above the 900 s idle seat ceiling']))

    def test_w7_in_a_workflow_run_script_is_reported_by_the_script(self):
        text = CI_YML.read_text()
        anchor = '            exec python3 -I scripts/ci/host_semaphore.py --name linux-fed-tests'
        self.assertIn(anchor, text)
        mutant = text.replace(anchor, '            HOST_SEMAPHORE_MAX_WAIT_SECS=3600\n' + anchor, 1)
        self.assertEqual(self.run_check({'.github/workflows/ci.yml': mutant}), (1, [
            'host_slots_check: workflows/ci.yml: HOST_SEMAPHORE_MAX_WAIT_SECS is used other than as its env mapping key '
            'or a plain $ read; set it only in the one env mapping']))

    def test_w6_in_the_workflow_call_is_reported_by_the_script(self):
        text = CI_YML.read_text()
        anchor = '--max-wait-secs "$HOST_SEMAPHORE_MAX_WAIT_SECS"'
        self.assertEqual(text.count(anchor), 1)
        mutant = text.replace(anchor, anchor + ' --max-wait-secs 3600')
        self.assertEqual(self.run_check({'.github/workflows/ci.yml': mutant}), (1, [
            'host_slots_check: workflows/ci.yml: a host_semaphore.py call without exactly one --max-wait-secs']))


class StaleExitCodeText(unittest.TestCase):
    """R2-D: the docstring and comments name the codes the wrapper uses (82-85), never the old 75 outcome."""

    SOURCE = (CI_DIR / 'host_semaphore.py').read_text()

    def test_docstring_names_every_wrapper_code(self):
        doc = ' '.join(hs.__doc__.split())
        for fragment in ('82 infra-no-slot', '``::error title=infra no-slot::``', '83 infra-unknown-runner',
                         '84 the child itself ended with 82, 83, 84 or 85', '85 infra-wait-refused', 'Python 3.12+'):
            with self.subTest(fragment):
                self.assertIn(fragment, doc)

    def test_no_stale_75_outcome_text(self):
        flat = ' '.join(self.SOURCE.split())
        for stale in ('75 no slot', '75 = no slot', 'title=infra: no slot', 'Python 3.9'):
            with self.subTest(stale):
                self.assertNotIn(stale, flat)
        for number, line in enumerate(self.SOURCE.splitlines(), 1):
            if re.search(r'\b75\b', line):
                with self.subTest(line=number):
                    self.assertIn('product binary', line)

    def test_load_refused_comment_lists_the_wrapper_codes(self):
        lines = [ln for ln in self.SOURCE.splitlines() if ln.startswith('EXIT_LOAD_REFUSED = ')]
        self.assertEqual(lines, ["EXIT_LOAD_REFUSED = 4  # a shared module cannot be loaded "
                                 "(2 = bad arguments, 82-85 = wrapper outcomes, else the child's)"])


class ChangelogAndDocs(unittest.TestCase):
    def test_changelog_fragment_exists(self):
        text = (REPO / 'changelog.d' / '9231.fixed.md').read_text()
        self.assertIn('infra-no-slot', text)

    def test_changelog_and_gate_doc_name_the_refusal_and_the_tracking_issue(self):
        changelog = ' '.join((REPO / 'changelog.d' / '9231.fixed.md').read_text().split())
        gates = ' '.join((REPO / 'docs' / 'ci' / 'CARRIER-BRANCH-GATES.md').read_text().split())
        for text, fragments in ((changelog, ('infra-wait-refused', 'exit code 85', '900 s', 'tracked in #9833')),
                                (gates, ('infra-wait-refused', '85', '900 s'))):
            for fragment in fragments:
                with self.subTest(fragment):
                    self.assertIn(fragment, text)


if __name__ == '__main__':
    unittest.main()
