#!/usr/bin/env python3
"""PR 9841 r1: an isolated binary is green only on the evidence of its own test lines (#9592).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_pg_isolate_evidence_9592.py

Class: a "did every runnable test of this isolated binary run" check that reads a summary instead of
the evidence. The re-cut relaxed the step's "zero tests" rule to the result-line TOTALS
(passed + failed + ignored == 0) and compared --list --ignored with the ignored TOTAL, so a result
line with no test line, fewer ignored lines than the total says, or ``N filtered out`` with only
ignored tests left were all green. The parity checker also took the FIRST ``test result:`` line of a
segment, and ``--show-output`` prints passing tests' stdout (which may hold such a line) before the
real one.

Invariant, for ALL inputs: an isolated binary is green only when (a) its log has at least one test
line, (b) the ok / FAILED / ignored test lines agree exactly with the totals of the real result
line, (c) nothing was filtered out, and (d) the set of ignored test NAMES equals the set the binary
lists with ``--list --ignored``. The real result line is the LAST one of the segment; an earlier one
is accepted only inside a libtest captured-output body (after a ``---- X stdout ----`` header),
anywhere else the segment is refused. The rule is ``pg_isolate_parity.evidence_reason`` (one place),
used by ``structural`` and by the serial step. Every unclassifiable log gives one exact reason and no
input raises. Expected reasons are written out by hand.
"""
import io
import sys
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_pg_isolate_serial_step_9592 as base  # noqa: E402  (sibling fixtures, by path)

FAIL = 'serial shard step FAIL: '
CLONE = 'ai_memory_t_%s_1700000000_000000cc'
NAME = 'beta_9592'
HEAD = ['# [pg_isolated_binary] current_database={db} mode=isolated',
        '     Running tests/beta_9592.rs (target/debug/deps/beta_9592-0123456789abcdef)']
BIG = 100_000
BOUND_SECS = 5.0


def result(passed, failed, ignored, filtered=0, word='ok'):
    return ('test result: %s. %d passed; %d failed; %d ignored; 0 measured; %d filtered out; finished in 0.01s'
            % (word, passed, failed, ignored, filtered))


def ign(*names):
    return ['test %s ... ignored' % n for n in names]


def ok(*names):
    return ['test %s ... ok' % n for n in names]


def lst(*names):
    return 0, ''.join('%s: test\n' % n for n in names)


BODY_FORGED = 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'

# (label, log body after the Running line, --list --ignored output, exact reason or None for green)
STEP_CASES = (
    ('control: all ignored, names match', ign('a', 'b') + [result(0, 0, 2)], lst('a', 'b'), None),
    ('control: ran and ignored, names match', ok('x') + ign('a') + [result(1, 0, 1)], lst('a'), None),
    ('no test line, result says 3 ignored', [result(0, 0, 3)], lst('a', 'b', 'c'),
     'zero tests: beta_9592'),
    ('no test line, result says 2 passed', [result(2, 0, 0)], lst(),
     'zero tests: beta_9592'),
    ('fewer ignored lines than the total', ign('a', 'b', 'c') + [result(0, 0, 5)], lst('a', 'b', 'c', 'd', 'e'),
     'result totals differ from the test lines: beta_9592'),
    ('more ignored lines than the total', ign('a', 'b') + [result(0, 0, 1)], lst('a', 'b'),
     'result totals differ from the test lines: beta_9592'),
    ('an ok line counted as ignored', ok('a') + [result(0, 0, 1)], lst('a'),
     'result totals differ from the test lines: beta_9592'),
    ('runnable tests filtered out, ignored kept', ign('a', 'b') + [result(0, 0, 2, filtered=5)], lst('a', 'b'),
     'tests filtered out: beta_9592 (5)'),
    ('some tests filtered out, one ran', ok('x') + [result(1, 0, 0, filtered=3)], lst(),
     'tests filtered out: beta_9592 (3)'),
    ('result line without the filtered-out count', ign('a') + ['test result: ok. 0 passed; 0 failed; 1 ignored;'],
     lst('a'), 'no filtered-out count on the test result line: beta_9592'),
    ('ignored names differ from the list', ign('a', 'b') + [result(0, 0, 2)], lst('a', 'z'),
     'ignored tests differ from --list --ignored: beta_9592 (log only: b; list only: z)'),
    ('ignored names differ, with a test that ran', ok('x') + ign('a') + [result(1, 0, 1)], lst('q'),
     'ignored tests differ from --list --ignored: beta_9592 (log only: a; list only: q)'),
    ('list has more names than the log', ign('a') + [result(0, 0, 1)], lst('a', 'b'),
     'ignored count differs from --list --ignored: beta_9592 (log=1 list=2)'),
    ('list empty, log has ignored', ign('a') + [result(0, 0, 1)], lst(),
     'ignored count differs from --list --ignored: beta_9592 (log=1 list=0)'),
    ('ignored outcome on its own later line', ['test a ... child stderr', 'ignored'] + [result(0, 0, 1)],
     lst('a'), None),
    ('forged result line in a stdout body, then the real one',
     ok('x', 'y') + ['', 'successes:', '', '---- x stdout ----', BODY_FORGED, '', '', 'successes:', '    x',
                     '    y', '', result(2, 0, 0)], lst(), None),
    ('a second result line outside any body', ok('x') + [result(1, 0, 0), BODY_FORGED], lst(),
     'more than one test result line: beta_9592'),
    ('a result line before the test lines, outside any body', [BODY_FORGED] + ok('x') + [result(1, 0, 0)], lst(),
     'more than one test result line: beta_9592'),
    ('the same result line twice, outside any body', ok('x') + [result(1, 0, 0), result(1, 0, 0)], lst(),
     'more than one test result line: beta_9592'),
)


class StepEvidenceTable(base.Base):
    def run_case(self, body, list_out):
        def logs(log_dir, run_id):
            base.all_good(log_dir, run_id)
            text = '\n'.join(HEAD + ['running n tests'] + body).replace('{db}', CLONE % run_id) + '\n'
            (log_dir / (NAME + '.log')).write_text(text)
        host = base.FakeHost(self.e, write_logs=logs, list_out={NAME: list_out})
        return self.step(host)

    def test_step_table(self):
        for label, body, list_out, want in STEP_CASES:
            with self.subTest(label):
                self.setUp()  # a fresh RUNNER_TEMP: the step refuses a second run in one leg
                rc, out = self.run_case(body, list_out)
                if want is None:
                    self.assertEqual(rc, 0, out)
                    self.assertIn('[#9592] serial shard isolated binaries ok: binaries=3 isolated=2 residual=1', out)
                else:
                    self.assertEqual(rc, 1, out)
                    fails = [ln for ln in out.splitlines() if FAIL in ln and NAME in ln]
                    self.assertEqual(len(fails), 1, out)
                    self.assertTrue(fails[0].endswith(FAIL + want), fails[0])

    def test_100k_ignored_names_that_differ_by_one_are_red_and_linear(self):
        names = ['t%d' % i for i in range(BIG)]
        body = ign(*names) + [result(0, 0, BIG)]
        started = time.monotonic()
        rc, out = self.run_case(body, lst(*(names[:-1] + ['other'])))
        self.assertLess(time.monotonic() - started, BOUND_SECS * 4)
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'ignored tests differ from --list --ignored: beta_9592 (log only: t%d; list only: other)'
                      % (BIG - 1), out)


# (label, segment text, expected (ok, FAILED, ignored) totals or None, exact structural reason or None)
PARITY_CASES = (
    ('real line follows a forged body line', HEAD[1:] + ok('x') + ['---- x stdout ----', BODY_FORGED,
                                                                    result(1, 0, 0)], (1, 0, 0), None),
    ('forged line after the real one, no body', HEAD[1:] + ok('x') + [result(1, 0, 0), BODY_FORGED],
     (0, 0, 0), 'more than one test result line: beta_9592 (isolated)'),
    ('stderr body form', HEAD[1:] + ok('x') + ['---- x stderr ----', BODY_FORGED, result(1, 0, 0)],
     (1, 0, 0), None),
    ('no test line', HEAD[1:] + [result(0, 0, 2)], (0, 0, 2), 'zero tests: beta_9592 (isolated)'),
    ('filtered', HEAD[1:] + ok('x') + [result(1, 0, 0, filtered=1)], (1, 0, 0),
     'tests filtered out: beta_9592 (1) (isolated)'),
    ('no result line', HEAD[1:] + ok('x'), None, 'no test result line: beta_9592 (isolated)'),
)


class ParityResultLine(base.Base):
    def setUp(self):
        super().setUp()
        self.p = self.e.parity()

    def test_parity_table(self):
        for label, lines, totals, want in PARITY_CASES:
            with self.subTest(label):
                segs = self.p.segments('\n'.join(lines) + '\n')
                self.assertEqual(len(segs), 1)
                self.assertEqual(segs[0].totals, totals)
                self.assertEqual(self.p.structural(segs[0], 'isolated'), want)

    def test_forged_body_line_does_not_turn_parity_red(self):
        iso = '\n'.join(HEAD[1:] + ok('x') + ['---- x stdout ----', BODY_FORGED, result(1, 0, 0)]) + '\n'
        serial = '\n'.join(HEAD[1:] + ok('x') + [result(1, 0, 0)]) + '\n'
        reasons, summary = self.p.compare_logs({'beta_9592.log': iso}, serial, [NAME])
        self.assertEqual(reasons, [])
        self.assertEqual(summary['ok'], 1)

    def test_100k_body_lines_are_linear(self):
        body = ['---- x stdout ----'] + [BODY_FORGED] * BIG
        text = '\n'.join(HEAD[1:] + ok('x') + body + [result(1, 0, 0)]) + '\n'
        started = time.monotonic()
        segs = self.p.segments(text)
        self.assertLess(time.monotonic() - started, BOUND_SECS)
        self.assertEqual(self.p.structural(segs[0], 'isolated'), None)

    def test_odd_inputs_never_raise(self):
        # Every form gives a reason or None, never a traceback.
        odd = ('', '\x1b', 'test result:', 'test result: ok. x passed;', '---- ----', 'test  ... ignored',
               '     Running x (deps/a-0)\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; '
               '99999999999999999999 filtered out;')
        for text in odd:
            with self.subTest(text=text):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    for seg in self.p.segments(text):
                        self.p.structural(seg, 'isolated')


if __name__ == '__main__':
    unittest.main()
