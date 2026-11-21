#!/usr/bin/env python3
"""Unit tests for scripts/ci/pg_isolate_parity.py (#9592, vote 71472661 I-4 / I-5).

Run: python3 -m unittest scripts/ci/tests/test_pg_isolate_parity_9592.py

The checker compares the per-test outcomes (ok / FAILED / ignored) of the
per-binary isolated logs with the serial log of the same binaries. Every
failure has an exact reason; a 500 x 200 corpus runs under a named ceiling.
"""
import importlib.util
import subprocess
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / 'scripts' / 'ci' / 'pg_isolate_parity.py'
SCRATCH = REPO / '.local-runs' / 'test-pg-isolate-parity-9592'

LARGE_BINARIES = 500
LARGE_TESTS_PER_BINARY = 200


def load():
    spec = importlib.util.spec_from_file_location('pg_isolate_parity', SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules['pg_isolate_parity'] = mod
    spec.loader.exec_module(mod)
    return mod


def binary_log(name, outcomes, header=True, result=True, totals=None):
    """A cargo test log of one binary; ``outcomes`` maps test -> ok|FAILED|ignored."""
    lines = []
    if header:
        lines.append('# [pg_isolated_binary] current_database=ai_memory_t_r1_1_abcdef01 mode=isolated')
    lines.append('     Running tests/%s.rs (target/debug/deps/%s-0123456789abcdef)' % (name, name))
    lines.append('')
    lines.append('running %d tests' % len(outcomes))
    for test, outcome in outcomes.items():
        suffix = ', reason' if outcome == 'ignored' else ''
        lines.append('test %s ... %s%s' % (test, outcome, suffix))
    counts = totals or (sum(1 for o in outcomes.values() if o == 'ok'),
                        sum(1 for o in outcomes.values() if o == 'FAILED'),
                        sum(1 for o in outcomes.values() if o == 'ignored'))
    if result:
        word = 'FAILED' if counts[1] else 'ok'
        lines.append('')
        lines.append('test result: %s. %d passed; %d failed; %d ignored; 0 measured; 0 filtered out; '
                     'finished in 0.01s' % (word, counts[0], counts[1], counts[2]))
    return '\n'.join(lines) + '\n'


def serial_log(per_binary):
    return ''.join(binary_log(name, outcomes, header=False) for name, outcomes in per_binary.items())


BASE = {
    'alpha_9592': {'a::one': 'ok', 'a::two': 'ignored', 'a::three': 'FAILED'},
    'beta_9592': {'b::one': 'ok'},
}


class Compare(unittest.TestCase):
    def setUp(self):
        self.p = load()

    def iso(self, per_binary=None, **over):
        per_binary = per_binary or BASE
        return {name + '.log': over.get(name, binary_log(name, outcomes)) for name, outcomes in per_binary.items()}

    def check(self, iso_logs, serial_text, expected=('alpha_9592', 'beta_9592')):
        return self.p.compare_logs(iso_logs, serial_text, list(expected))

    def test_identical_outcomes_pass_with_totals(self):
        reasons, summary = self.check(self.iso(), serial_log(BASE))
        self.assertEqual(reasons, [])
        self.assertEqual(summary, {'binaries': 2, 'tests': 4, 'ok': 2, 'failed': 1, 'ignored': 1})

    def test_a_different_outcome_fails(self):
        serial = dict(BASE, alpha_9592={'a::one': 'FAILED', 'a::two': 'ignored', 'a::three': 'FAILED'})
        reasons, _ = self.check(self.iso(), serial_log(serial))
        self.assertEqual(reasons, ['outcome differs: alpha_9592::a::one isolated=ok serial=FAILED'])

    def test_ignored_is_compared_like_any_outcome(self):
        serial = dict(BASE, alpha_9592={'a::one': 'ok', 'a::two': 'ok', 'a::three': 'FAILED'})
        reasons, _ = self.check(self.iso(), serial_log(serial))
        self.assertEqual(reasons, ['outcome differs: alpha_9592::a::two isolated=ignored serial=ok'])

    def test_a_test_missing_on_one_side_fails(self):
        serial = dict(BASE, beta_9592={'b::one': 'ok', 'b::two': 'ok'})
        reasons, _ = self.check(self.iso(), serial_log(serial))
        self.assertEqual(reasons, ['outcome differs: beta_9592::b::two isolated=absent serial=ok'])

    def test_a_missing_isolated_log_fails(self):
        iso = self.iso()
        del iso['beta_9592.log']
        reasons, _ = self.check(iso, serial_log(BASE))
        self.assertEqual(reasons, ['missing log: beta_9592 (isolated)'])

    def test_a_missing_serial_segment_fails(self):
        reasons, _ = self.check(self.iso(), serial_log({'alpha_9592': BASE['alpha_9592']}))
        self.assertEqual(reasons, ['missing log: beta_9592 (serial)'])

    def test_a_zero_test_binary_fails(self):
        iso = self.iso(beta_9592=binary_log('beta_9592', {}))
        reasons, _ = self.check(iso, serial_log(BASE))
        self.assertEqual(reasons, ['zero tests: beta_9592 (isolated)'])

    def test_a_duplicate_binary_log_fails(self):
        iso = self.iso()
        iso['beta_copy.log'] = binary_log('beta_9592', BASE['beta_9592'])
        reasons, _ = self.check(iso, serial_log(BASE))
        self.assertEqual(reasons, ['duplicate binary log: beta_9592 (isolated: beta_9592.log, beta_copy.log)'])

    def test_a_duplicate_serial_segment_fails(self):
        serial = serial_log(BASE) + binary_log('beta_9592', BASE['beta_9592'], header=False)
        reasons, _ = self.check(self.iso(), serial)
        self.assertEqual(reasons, ['duplicate binary log: beta_9592 (serial)'])

    def test_a_log_without_a_result_line_fails(self):
        iso = self.iso(beta_9592=binary_log('beta_9592', BASE['beta_9592'], result=False))
        reasons, _ = self.check(iso, serial_log(BASE))
        self.assertEqual(reasons, ['no test result line: beta_9592 (isolated)'])

    def test_totals_that_disagree_with_the_outcomes_fail(self):
        iso = self.iso(beta_9592=binary_log('beta_9592', BASE['beta_9592'], totals=(2, 0, 0)))
        reasons, _ = self.check(iso, serial_log(BASE))
        self.assertEqual(reasons, ['result totals differ from the test lines: beta_9592 (isolated)'])

    def test_an_outcome_after_child_stderr_is_read_9592(self):
        # A test that spawns a child process: the child's stderr lands between
        # "test X ... " and the outcome, which then arrives alone on a later
        # line (seen in the local proof on envelope_column_type_fail_closed_4133).
        interleaved = binary_log('beta_9592', BASE['beta_9592']).replace(
            'test b::one ... ok\n',
            'test b::one ... ai-memory: generated a key at <path>\nai-memory MCP server started\nok\n')
        seg = [s for s in self.p.segments(interleaved) if s.name == 'beta_9592'][0]
        self.assertEqual(seg.tests, {'b::one': 'ok'})
        reasons, summary = self.check(self.iso(beta_9592=interleaved), serial_log(BASE))
        self.assertEqual(reasons, [])
        self.assertEqual(summary['tests'], 4)

    def test_every_interleaved_outcome_form_is_read_9592(self):
        for outcome, line in (('ok', 'ok'), ('FAILED', 'FAILED'), ('ignored', 'ignored, needs pg')):
            with self.subTest(outcome=outcome):
                text = ('     Running tests/x.rs (target/debug/deps/x_9592-0123456789abcdef)\n'
                        'test x::t ... child line\n%s\n' % line)
                self.assertEqual(self.p.segments(text)[0].tests, {'x::t': outcome})

    def test_a_stray_outcome_word_without_an_open_test_is_ignored_9592(self):
        text = ('     Running tests/x.rs (target/debug/deps/x_9592-0123456789abcdef)\n'
                'test x::t ... ok\nok\nFAILED\n')
        self.assertEqual(self.p.segments(text)[0].tests, {'x::t': 'ok'})

    def test_a_wrong_stray_outcome_is_caught_by_the_totals_9592(self):
        # A child that prints "ok" alone while the test later FAILS: the read
        # outcome is wrong, and the totals cross-check fails closed on it.
        text = ('     Running tests/x.rs (target/debug/deps/x_9592-0123456789abcdef)\n'
                'test x::t ... child\nok\nFAILED\n\n'
                'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n')
        seg = self.p.segments(text)[0]
        self.assertEqual(self.p.structural(seg, 'isolated'),
                         'result totals differ from the test lines: x_9592 (isolated)')

    def test_a_log_running_no_binary_fails(self):
        iso = self.iso(beta_9592='# [pg_isolated_binary] current_database=x mode=isolated\nerror: could not compile\n')
        reasons, _ = self.check(iso, serial_log(BASE))
        self.assertEqual(reasons, ['no test binary ran: beta_9592.log (isolated)', 'missing log: beta_9592 (isolated)'])

    def test_a_binary_nobody_expected_fails(self):
        iso = self.iso()
        iso['gamma_9592.log'] = binary_log('gamma_9592', {'g::one': 'ok'})
        reasons, _ = self.check(iso, serial_log(BASE))
        self.assertEqual(reasons, ['unexpected binary: gamma_9592 (isolated)'])

    def test_large_corpus_is_linear(self):
        per_binary = {'bin_%03d' % b: {'t::case_%03d' % t: 'ok' for t in range(LARGE_TESTS_PER_BINARY)}
                      for b in range(LARGE_BINARIES)}
        iso = {name + '.log': binary_log(name, outcomes) for name, outcomes in per_binary.items()}
        serial = serial_log(per_binary)
        started = time.monotonic()
        reasons, summary = self.p.compare_logs(iso, serial, sorted(per_binary))
        elapsed = time.monotonic() - started
        self.assertEqual(reasons, [])
        self.assertEqual(summary['tests'], LARGE_BINARIES * LARGE_TESTS_PER_BINARY)
        self.assertLess(elapsed, self.p.PARITY_CEILING_SECS)


class Cli(unittest.TestCase):
    def setUp(self):
        load()
        self.root = SCRATCH / self.id().rsplit('.', 1)[-1]
        self.root.mkdir(parents=True, exist_ok=True)
        self.iso = self.root / 'iso-logs'
        self.iso.mkdir(exist_ok=True)
        for name, outcomes in BASE.items():
            (self.iso / (name + '.log')).write_text(binary_log(name, outcomes))
        self.targets = self.root / 'iso_targets.txt'
        self.targets.write_text('--test alpha_9592\n--test beta_9592\n')
        self.serial = self.root / 'serial.log'
        self.serial.write_text(serial_log(BASE))

    def run_cli(self, *extra):
        return subprocess.run([sys.executable, str(SCRIPT), '--iso-log-dir', str(self.iso),
                               '--targets-file', str(self.targets), '--serial-log', str(self.serial), *extra],
                              capture_output=True, text=True)

    def test_parity_ok_line(self):
        done = self.run_cli()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(done.stdout.strip(), '[#9592] parity ok: binaries=2 tests=4 ok=2 failed=1 ignored=1')

    def test_parity_fail_exit_one(self):
        (self.iso / 'beta_9592.log').unlink()
        done = self.run_cli()
        self.assertEqual(done.returncode, 1)
        self.assertEqual(done.stdout.strip(), '[#9592] parity FAIL: missing log: beta_9592 (isolated)')

    def test_missing_serial_log_exit_two(self):
        self.serial.unlink()
        done = self.run_cli()
        self.assertEqual(done.returncode, 2)
        self.assertIn('[#9592] parity FAIL: cannot read', done.stdout)


if __name__ == '__main__':
    unittest.main()
