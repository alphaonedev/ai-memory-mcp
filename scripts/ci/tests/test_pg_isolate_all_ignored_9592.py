#!/usr/bin/env python3
"""#9592 B(iii) follow-on: a binary whose every test is ``#[ignore]`` is accounted, not "zero tests".

Run: python3 -m unittest discover -s scripts/ci/tests -p test_pg_isolate_all_ignored_9592.py

Class: once the colour-coded ``Running`` line parses (CARGO_TERM_COLOR=always), the serial step
reaches its "zero tests" rule for every deferred binary. That rule counted only passed + failed,
so a binary whose tests are all ``#[ignore]`` (for example tests/apply_remote_memory_26col_1029.rs:98
and :133, which run only with ``--ignored``) was red although every test it holds is named in the
log and cross-checked against the binary's own ``--list --ignored``. The parity checker already
defines zero tests as "no test line at all" (scripts/ci/pg_isolate_parity.py ``structural``).

Invariant: a binary is "zero tests" exactly when its log has no test line (passed + failed +
ignored == 0), in the log check and in the completion ledger alike; an all-ignored binary is green
only when its ignored total equals ``--list --ignored`` (that check is unchanged), and a binary with
no test at all stays red with the exact reason. Expected reasons and counts are written by hand.
"""
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_pg_isolate_serial_step_9592 as base  # noqa: E402  (sibling fixtures, by path)

FAIL = 'serial shard step FAIL: '
RUN_ID = 'rabc'
CLONE = 'ai_memory_t_%s_1700000000_000000cc'
# The real shape of an all-ignored binary's log (tests/apply_remote_memory_26col_1029.rs on this host).
IGNORED_REASON = 'requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79'
BIG_IGNORED = 100_000
BOUND_SECS = 5.0


def all_ignored_log(name, db, ignored, listed_reason=IGNORED_REASON):
    lines = ['# [pg_isolated_binary] current_database=%s mode=isolated' % db,
             '     Running tests/%s.rs (target/debug/deps/%s-0123456789abcdef)' % (name, name),
             'running %d tests' % ignored]
    lines += ['test t%d ... ignored, %s' % (i, listed_reason) for i in range(ignored)]
    lines.append('test result: ok. 0 passed; 0 failed; %d ignored; 0 measured; 0 filtered out; '
                 'finished in 0.00s' % ignored)
    return '\n'.join(lines) + '\n'


def empty_log(name, db):
    return ('# [pg_isolated_binary] current_database=%s mode=isolated\n'
            '     Running tests/%s.rs (target/debug/deps/%s-0123456789abcdef)\n'
            'running 0 tests\n'
            'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n'
            % (db, name, name))


def listing(count):
    return 0, ''.join('t%d: test\n' % i for i in range(count))


class AllIgnoredBinary(base.Base):
    def run_beta(self, text_of, list_out):
        def logs(log_dir, run_id):
            base.all_good(log_dir, run_id)
            (log_dir / 'beta_9592.log').write_text(text_of(CLONE % run_id))
        host = base.FakeHost(self.e, write_logs=logs, list_out={'beta_9592': list_out})
        return host, *self.step(host)

    def test_all_ignored_binary_with_matching_list_is_green(self):
        # (ignored tests, exact accounting line), written out by hand.
        for ignored in (1, 2, 7):
            with self.subTest(ignored=ignored):
                self.setUp()  # a fresh RUNNER_TEMP: the step refuses a second run in one leg
                _host, rc, out = self.run_beta(lambda db, n=ignored: all_ignored_log('beta_9592', db, n),
                                               listing(ignored))
                self.assertEqual(rc, 0, out)
                self.assertIn('[#9592] serial shard isolated binaries ok: binaries=3 isolated=2 residual=1', out)
                self.assertNotIn('zero tests', out)

    def test_all_ignored_binary_writes_an_accepted_ledger_row(self):
        _host, rc, out = self.run_beta(lambda db: all_ignored_log('beta_9592', db, 2), listing(2))
        self.assertEqual(rc, 0, out)
        text = (self.root / 'ci-iso-ledger.txt').read_text()
        rows = [ln for ln in text.splitlines() if ln.startswith('binary beta_9592 ')]
        self.assertEqual(len(rows), 1, text)
        self.assertTrue(rows[0].startswith('binary beta_9592 tests=0 ignored=2 mode=isolated db=ai_memory_t_'),
                        rows[0])

    def test_all_ignored_binary_with_a_short_list_is_red(self):
        _host, rc, out = self.run_beta(lambda db: all_ignored_log('beta_9592', db, 2), listing(1))
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'ignored count differs from --list --ignored: beta_9592 (log=2 list=1)', out)

    def test_binary_with_no_test_at_all_stays_red(self):
        _host, rc, out = self.run_beta(lambda db: empty_log('beta_9592', db), listing(0))
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'zero tests: beta_9592', out)

    def test_100k_ignored_lines_are_linear(self):
        started = time.monotonic()
        _host, rc, out = self.run_beta(lambda db: all_ignored_log('beta_9592', db, BIG_IGNORED),
                                       listing(BIG_IGNORED))
        self.assertLess(time.monotonic() - started, BOUND_SECS * 4)
        self.assertEqual(rc, 0, out[-2000:])


def ledger(rows):
    return '\n'.join(rows + ['complete binaries=%d run_id=%s' % (len(rows), RUN_ID)]) + '\n'


def row(name, tests, ignored, mode='isolated', db='ai_memory_t_rabc_1_00000001'):
    return 'binary %s tests=%d ignored=%d mode=%s db=%s' % (name, tests, ignored, mode, db)


OTHER_ROWS = [row('beta_9592', 2, 0, db='ai_memory_t_rabc_1_00000002'),
              row('resid_9592', 2, 0, mode='residual', db=base.SHARED_DB)]
# (label, alpha row, exact reasons), written out by hand.
LEDGER_CASES = (
    ('all ignored', row('alpha_9592', 0, 2), []),
    ('one ignored', row('alpha_9592', 0, 1), []),
    ('ran and ignored', row('alpha_9592', 1, 1), []),
    ('nothing at all', row('alpha_9592', 0, 0), ['ledger row for alpha_9592 has zero tests']),
)


class LedgerZeroMeansNoTestLine(base.Base):
    def test_ledger_table(self):
        for label, alpha, want in LEDGER_CASES:
            with self.subTest(label):
                got = self.e.ledger_reasons(ledger([alpha] + OTHER_ROWS), list(base.TARGETS), RUN_ID,
                                            set(base.RESIDUAL), base.SHARED_DB)
                self.assertEqual(got, want)


if __name__ == '__main__':
    unittest.main()
