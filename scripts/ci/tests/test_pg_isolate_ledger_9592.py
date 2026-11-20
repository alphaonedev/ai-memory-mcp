#!/usr/bin/env python3
"""Completion-ledger, kill-switch, run-id and redaction tests for pg_isolate_serial_step.py (#9592 r1 fix notice).

Run: python3 -m unittest scripts/ci/tests/test_pg_isolate_ledger_9592.py

Invariant (fix notice 9592 r1): a leg is green only if every deferred binary
ran with at least one test, as ONE completion ledger records, and no clone is
left; every unset, empty or misspelled input (run id, GITHUB_ENV, mode, kill
switch) is a red step. Every case asserts the exact reason and exit code.
"""
import io
import os
import subprocess
import sys
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_pg_isolate_serial_step_9592 as base  # noqa: E402  (sibling fixtures, by path)

SCRIPT = base.SCRIPT
SECRET_URL = base.SECRET_URL
SECRET_TOKEN = 'canarypw9592'
TARGETS = base.TARGETS
RUN_ID = 'rabc'
BIG_ROWS = 100_000
BIG_LINE = 100_000
BOUND_SECS = 5.0
KILL_ON_VALUES = ('1', 'true', 'TRUE', 'On', 'on', ' on ')
KILL_OFF_VALUES = ('', '0', 'false', 'OFF', 'off')
KILL_BAD_VALUES = ('yes', '2', 'onn', 'disabled', 'canaryvalue9592')
KILL_BAD_REASON = 'CI_PG_ISOLATE_OFF has an unrecognised value'
FAIL = 'serial shard step FAIL: '


def ledger(rows, done):
    return '\n'.join(list(rows) + ([done] if done else [])) + '\n'


def row(name, tests=2, ignored=0, mode='isolated', db='ai_memory_t_rabc_1_00000001'):
    return 'binary %s tests=%d ignored=%d mode=%s db=%s' % (name, tests, ignored, mode, db)


GOOD_ROWS = [row('alpha_9592'), row('beta_9592', db='ai_memory_t_rabc_1_00000002'),
             row('resid_9592', mode='residual', db=base.SHARED_DB)]
DONE = 'complete binaries=3 run_id=%s' % RUN_ID

# (label, ledger text, exact reasons)
LEDGER_CASES = (
    ('good', ledger(GOOD_ROWS, DONE), []),
    ('empty', '', ['ledger has no complete row']),
    ('no complete row', ledger(GOOD_ROWS, None), ['ledger has no complete row']),
    ('complete row not last', ledger([DONE] + GOOD_ROWS, None), ['ledger complete row is not the last row']),
    ('short', ledger(GOOD_ROWS[:2], 'complete binaries=2 run_id=rabc'),
     ['ledger misses deferred binaries: resid_9592', 'ledger complete row counts 2 binaries, 3 deferred']),
    ('duplicate', ledger(GOOD_ROWS + [GOOD_ROWS[0]], DONE), ['ledger names a binary twice: alpha_9592']),
    ('not deferred', ledger(GOOD_ROWS + [row('gamma_9592')], DONE),
     ['ledger names a binary that was not deferred: gamma_9592']),
    ('zero tests', ledger([row('alpha_9592', tests=0)] + GOOD_ROWS[1:], DONE),
     ['ledger row for alpha_9592 has zero tests']),
    ('malformed row', ledger(GOOD_ROWS[:1] + ['binary beta_9592 tests=x'] + GOOD_ROWS[2:], DONE),
     ['ledger row 2 is malformed', 'ledger misses deferred binaries: beta_9592']),
    ('malformed complete row', ledger(GOOD_ROWS, 'complete binaries=3 run_id=RABC'), ['ledger row 4 is malformed']),
    ('other run', ledger(GOOD_ROWS, 'complete binaries=3 run_id=rzzz'), ['ledger run id is not this run']),
)


class Ledger(base.Base):
    def test_ledger_reasons_table(self):
        for label, text, want in LEDGER_CASES:
            with self.subTest(label):
                self.assertEqual(self.e.ledger_reasons(text, list(TARGETS), RUN_ID), want)

    def test_ledger_over_the_byte_ceiling_fails(self):
        text = 'x' * (self.e.LEDGER_MAX_BYTES + 1)
        self.assertEqual(self.e.ledger_reasons(text, list(TARGETS), RUN_ID),
                         ['ledger over %d bytes' % self.e.LEDGER_MAX_BYTES])

    def test_ledger_with_100k_rows_is_bounded(self):
        rows = [row('bin_%06d' % i) for i in range(BIG_ROWS)]
        text = ledger(rows, 'complete binaries=%d run_id=%s' % (BIG_ROWS, RUN_ID))
        self.assertLessEqual(len(text.encode()), self.e.LEDGER_MAX_BYTES * 8)
        started = time.monotonic()
        reasons = self.e.ledger_reasons(text[:self.e.LEDGER_MAX_BYTES], list(TARGETS), RUN_ID)
        self.assertLess(time.monotonic() - started, BOUND_SECS)
        self.assertLessEqual(len(reasons), self.e.REASONS_MAX)
        reasons = self.e.ledger_reasons(text, ['bin_%06d' % i for i in range(BIG_ROWS)], RUN_ID)
        self.assertEqual(reasons, ['ledger over %d bytes' % self.e.LEDGER_MAX_BYTES])

    def test_green_run_writes_the_ledger_with_the_complete_row_last(self):
        host = base.FakeHost(self.e, write_logs=base.all_good)
        rc, out = self.step(host)
        self.assertEqual(rc, 0, out)
        run_id = host.env_lines[0].split('=', 1)[1]
        lines = (self.root / 'ci-iso-ledger.txt').read_text().splitlines()
        self.assertEqual(lines[-1], 'complete binaries=3 run_id=%s' % run_id)
        self.assertEqual([ln.split()[1] for ln in lines[:-1]], list(TARGETS))
        self.assertIn('[#9592] serial shard isolated binaries ok: binaries=3 isolated=2 residual=1', out)

    def test_red_run_writes_no_ledger(self):
        host = base.FakeHost(self.e, run_rc={'--targets-file': 2}, write_logs=base.all_good)
        rc, out = self.step(host)
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'wrapper error (exit 2)', out)
        self.assertFalse((self.root / 'ci-iso-ledger.txt').exists())

    def test_a_ledger_already_present_fails_before_any_call(self):
        (self.root / 'ci-iso-ledger.txt').write_text(ledger(GOOD_ROWS, DONE))
        host = base.FakeHost(self.e, write_logs=base.all_good)
        rc, out = self.step(host)
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'ci-iso-ledger.txt already exists: this leg ran the step before', out)
        self.assertEqual(host.calls, [])


class CleanupLedger(base.Base):
    """Cleanup is red unless the ledger matches the deferred list and no clone is left."""

    def setUp(self):
        super().setUp()
        (self.root / 'ci-iso-run.txt').write_text('AI_MEMORY_TEST_PG_RUN_ID=%s\n' % RUN_ID)

    def cleanup(self, host, **env_over):
        env = {k: v for k, v in dict(self.env, **env_over).items() if v is not None}
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.e.cmd_cleanup(host, env)
        self.assertNotIn(SECRET_URL, buf.getvalue())
        return rc, buf.getvalue()

    def test_cleanup_with_a_complete_ledger_is_green(self):
        (self.root / 'ci-iso-ledger.txt').write_text(ledger(GOOD_ROWS, DONE))
        rc, out = self.cleanup(base.FakeHost(self.e))
        self.assertEqual(rc, 0, out)
        self.assertIn('[#9592] isolation ledger complete and no clone left: binaries=3', out)

    def test_cleanup_without_a_ledger_fails_and_still_tears_down(self):
        host = base.FakeHost(self.e)
        rc, out = self.cleanup(host)
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'cannot read ci-iso-ledger.txt: the isolated step did not complete', out)
        self.assertEqual(host.leftover_checks, 1)

    def test_cleanup_with_a_short_ledger_fails(self):
        (self.root / 'ci-iso-ledger.txt').write_text(ledger(GOOD_ROWS[:2], 'complete binaries=2 run_id=rabc'))
        rc, out = self.cleanup(base.FakeHost(self.e))
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'ledger misses deferred binaries: resid_9592', out)

    def test_cleanup_with_a_ledger_of_another_run_fails(self):
        (self.root / 'ci-iso-ledger.txt').write_text(ledger(GOOD_ROWS, 'complete binaries=3 run_id=rzzz'))
        rc, out = self.cleanup(base.FakeHost(self.e))
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'ledger run id is not this run', out)

    def test_cleanup_env_run_id_that_differs_from_the_run_file_fails(self):
        rc, out = self.cleanup(base.FakeHost(self.e), AI_MEMORY_TEST_PG_RUN_ID='rother')
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'AI_MEMORY_TEST_PG_RUN_ID is not the run id in ci-iso-run.txt', out)

    def test_cleanup_with_a_malformed_run_file_fails(self):
        (self.root / 'ci-iso-run.txt').write_text('AI_MEMORY_TEST_PG_RUN_ID=../x\n')
        host = base.FakeHost(self.e)
        rc, out = self.cleanup(host)
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'ci-iso-run.txt is malformed', out)
        self.assertEqual(host.calls, [])


# (kill switch value, mode file text or None, iso_targets.txt present) -> (rc, exact line)
MODE_CASES = (
    ('1', 'killswitch', False, 0, '[#9592] per-binary Postgres isolation disabled by CI_PG_ISOLATE_OFF: '
                                  'Run tests ran the serial-shard binaries itself'),
    ('1', 'deferred', True, 1, FAIL + 'the kill switch is on but the mode file says deferred'),
    ('1', 'none', False, 1, FAIL + 'the kill switch is on but the mode file says none'),
    ('1', 'killswitch', True, 1, FAIL + 'mode killswitch but iso_targets.txt lists binaries'),
    ('', 'killswitch', False, 1, FAIL + 'the mode file says killswitch but the kill switch is off'),
    ('', 'none', True, 1, FAIL + 'mode none but iso_targets.txt lists binaries'),
    ('', 'none', False, 0, '[#9592] no serial-shard binaries were deferred to this step'),
    ('', 'maybe', True, 1, FAIL + "unknown isolation mode 'maybe'"),
    ('', '', True, 1, FAIL + "unknown isolation mode ''"),
    ('', None, True, 1, FAIL + 'cannot read the isolation mode file'),
    ('yes', 'deferred', True, 1, FAIL + KILL_BAD_REASON),
    (None, 'deferred', True, 1, FAIL + 'CI_PG_ISOLATE_OFF is not in the step env'),
)

# (mode, targets present, run file present) -> (rc, exact line)
CLEANUP_MODE_CASES = (
    ('none', False, False, 0, '[#9592] mode none: this leg created no clones'),
    ('killswitch', False, False, 0, '[#9592] mode killswitch: this leg created no clones'),
    ('none', True, False, 1, FAIL + 'mode none but iso_targets.txt lists binaries'),
    ('killswitch', False, True, 1, FAIL + 'mode killswitch but ci-iso-run.txt or ci-iso-ledger.txt exists'),
    (None, False, False, 1, FAIL + 'cannot read the isolation mode file'),
    ('bogus', False, False, 1, FAIL + "unknown isolation mode 'bogus'"),
)


class ModeMatrix(base.Base):
    def arrange(self, mode, targets):
        mode_file = self.root / 'ci-iso-mode.txt'
        if mode is None:
            mode_file.unlink()
        else:
            mode_file.write_text(mode + '\n')
        if not targets:
            (self.shard / 'iso_targets.txt').unlink()

    def test_step_mode_matrix(self):
        for kill, mode, targets, want_rc, want in MODE_CASES:
            with self.subTest(kill=kill, mode=mode, targets=targets):
                self.setUp()
                self.arrange(mode, targets)
                host = base.FakeHost(self.e, write_logs=base.all_good)
                rc, out = self.step(host, CI_PG_ISOLATE_OFF=kill)
                self.assertEqual(rc, want_rc, out)
                self.assertIn(want, out)
                if want_rc == 0:
                    self.assertEqual(host.calls, [])

    def test_cleanup_mode_matrix(self):
        for mode, targets, run_file, want_rc, want in CLEANUP_MODE_CASES:
            with self.subTest(mode=mode, targets=targets, run_file=run_file):
                self.setUp()
                self.arrange(mode, targets)
                if run_file:
                    (self.root / 'ci-iso-run.txt').write_text('AI_MEMORY_TEST_PG_RUN_ID=rabc\n')
                host = base.FakeHost(self.e)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = self.e.cmd_cleanup(host, self.env)
                self.assertEqual(rc, want_rc, buf.getvalue())
                self.assertIn(want, buf.getvalue())
                self.assertEqual(host.calls, [])


class KillSwitchValues(base.Base):
    def test_accepted_values(self):
        for value in KILL_ON_VALUES:
            with self.subTest(value=value):
                self.assertIs(self.e.killswitch({'CI_PG_ISOLATE_OFF': value}), True)
        for value in KILL_OFF_VALUES:
            with self.subTest(value=value):
                self.assertIs(self.e.killswitch({'CI_PG_ISOLATE_OFF': value}), False)

    def test_other_values_are_red_and_never_echoed(self):
        for value in KILL_BAD_VALUES:
            with self.subTest(value=value):
                with self.assertRaises(self.e.StepFail) as ctx:
                    self.e.killswitch({'CI_PG_ISOLATE_OFF': value})
                self.assertTrue(str(ctx.exception).startswith(KILL_BAD_REASON))
                self.assertNotIn(value, str(ctx.exception).replace(KILL_BAD_REASON, ''))

    def test_absent_is_red(self):
        with self.assertRaises(self.e.StepFail) as ctx:
            self.e.killswitch({})
        self.assertEqual(str(ctx.exception), 'CI_PG_ISOLATE_OFF is not in the step env')

    def verb(self, value):
        env = {k: v for k, v in os.environ.items() if k != 'CI_PG_ISOLATE_OFF'}
        if value is not None:
            env['CI_PG_ISOLATE_OFF'] = value
        return subprocess.run([sys.executable, str(SCRIPT), 'killswitch'], env=env, capture_output=True,
                              text=True, timeout=60)

    def test_killswitch_verb(self):
        for value, rc, out in (('TRUE', 0, 'on\n'), ('', 0, 'off\n'), ('0', 0, 'off\n'), ('yes', 1, ''),
                               (None, 1, '')):
            with self.subTest(value=value):
                done = self.verb(value)
                self.assertEqual((done.returncode, done.stdout), (rc, out), done.stderr)
                if rc:
                    self.assertIn('[#9592] FAIL: ', done.stderr)


class RunIdAndGithubEnv(base.Base):
    def test_run_file_is_written_before_setup(self):
        root = self.root

        class Probe(base.FakeHost):
            def capture(self, argv, env):
                if 'setup' in argv:
                    self.seen = (root / 'ci-iso-run.txt').read_text()
                return super().capture(argv, env)
        host = Probe(self.e, write_logs=base.all_good)
        rc, out = self.step(host)
        self.assertEqual(rc, 0, out)
        self.assertEqual(host.seen, host.env_lines[0] + '\n')

    def test_a_run_file_already_present_fails_before_any_call(self):
        (self.root / 'ci-iso-run.txt').write_text('AI_MEMORY_TEST_PG_RUN_ID=rold\n')
        host = base.FakeHost(self.e, write_logs=base.all_good)
        rc, out = self.step(host)
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'ci-iso-run.txt already exists: this leg ran the step before', out)
        self.assertEqual(host.calls, [])

    def test_github_env_unset_is_red_and_still_tears_down(self):
        e = self.e

        class NoEnv(base.FakeHost):
            def append_env(self, line):
                raise e.StepFail('GITHUB_ENV is not set: the run id cannot reach the Cleanup step')
        host = NoEnv(e, write_logs=base.all_good)
        rc, out = self.step(host)
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'GITHUB_ENV is not set: the run id cannot reach the Cleanup step', out)
        self.assertEqual(self.wrapper_runs(host), [])
        self.assertEqual(host.leftover_checks, 1)

    def test_host_append_env_without_github_env_raises(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('GITHUB_ENV', None)
            with self.assertRaises(self.e.StepFail) as ctx:
                self.e.Host().append_env('AI_MEMORY_TEST_PG_RUN_ID=rabc')
        self.assertEqual(str(ctx.exception), 'GITHUB_ENV is not set: the run id cannot reach the Cleanup step')

    def test_host_append_env_shape_check(self):
        # S5: only the two expected names with an identifier value ever reach GITHUB_ENV.
        target = self.root / 'github_env'
        target.write_text('')
        with mock.patch.dict(os.environ, {'GITHUB_ENV': str(target)}):
            self.e.Host().append_env('AI_MEMORY_TEST_PG_RUN_ID=rabc')
            for bad in ('AI_MEMORY_TEST_PG_RUN_ID=rabc\nEVIL=1', 'AI_MEMORY_TEST_PG_RUN_ID=' + 'a' * 64,
                        'AI_MEMORY_TEST_PG_TEMPLATE=x y', 'AI_MEMORY_TEST_POSTGRES_URL=' + SECRET_URL,
                        'AI_MEMORY_TEST_PG_RUN_ID=RABC', 'AI_MEMORY_TEST_PG_RUN_ID=r-1'):
                with self.subTest(bad=bad[:40]):
                    with self.assertRaises(self.e.StepFail) as ctx:
                        self.e.Host().append_env(bad)
                    self.assertEqual(str(ctx.exception), 'refusing an env line of unexpected shape')
        self.assertEqual(target.read_text(), 'AI_MEMORY_TEST_PG_RUN_ID=rabc\n')


class Guards(base.Base):
    """SC: one behaviour test per guard that had no killing test (S4, S11, S12)."""

    def test_say_and_fail_redact_urls(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.e.say('connect to %s now' % SECRET_URL)
            self.e.fail('bad %s' % SECRET_URL)
        self.assertNotIn(SECRET_TOKEN, buf.getvalue())
        self.assertEqual(buf.getvalue(), '[#9592] connect to <redacted-url> now\n'
                                         '[#9592] serial shard step FAIL: bad <redacted-url>\n')

    def test_clone_of_another_run_is_rejected(self):
        def foreign(log_dir, run_id):
            base.all_good(log_dir, run_id)
            (log_dir / 'beta_9592.log').write_text(
                base.good_log('beta_9592', 'ai_memory_t_rother_1700000000_00000001', 'isolated'))
        host = base.FakeHost(self.e, write_logs=foreign)
        rc, out = self.step(host)
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'not on a clone of this run: beta_9592 '
                             '(current_database=ai_memory_t_rother_1700000000_00000001)', out)

    def test_residual_on_another_database_is_rejected(self):
        def elsewhere(log_dir, run_id):
            base.all_good(log_dir, run_id)
            (log_dir / 'resid_9592.log').write_text(base.good_log('resid_9592', 'ai_memory_other_9592', 'residual'))
        rc, out = self.step(base.FakeHost(self.e, write_logs=elsewhere))
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'residual not on the shared database: resid_9592', out)

    def test_session_bound_exit_is_named(self):
        rc, out = self.step(base.FakeHost(self.e, run_rc={'--targets-file': 5}, write_logs=base.all_good))
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'session bound exceeded (exit 5)', out)


class Redaction(base.Base):
    """SD: the pg-iso-logs artifact and streamed child output never carry a URL."""

    def lines(self, data):
        out = []
        self.e.redact_lines(io.BytesIO(data).readline, out.append)
        return out

    def test_redact_lines_forms(self):
        self.assertEqual(self.lines(('a %s b\nplain\n' % SECRET_URL).encode()), ['a <redacted-url> b', 'plain'])
        self.assertEqual(self.lines(b'\xff\xfe broken utf8\n'), ['�� broken utf8'])

    def test_url_across_the_chunk_boundary_does_not_leak(self):
        for cut in range(0, len(SECRET_URL) + 1, 3):
            with self.subTest(cut=cut):
                data = ('a' * (self.e.STREAM_LINE_MAX - cut) + SECRET_URL + ' tail\nnext\n').encode()
                out = self.lines(data)
                self.assertNotIn(SECRET_TOKEN, '\n'.join(out))
                self.assertEqual(out[-1], 'next')

    def test_100k_line_is_bounded(self):
        data = (SECRET_URL + ' ' + 'x' * BIG_LINE * 10 + '\n') * 3
        started = time.monotonic()
        out = self.lines(data.encode())
        self.assertLess(time.monotonic() - started, BOUND_SECS)
        self.assertEqual(len(out), 3)
        self.assertTrue(all(len(line) <= self.e.STREAM_LINE_MAX + 64 for line in out))
        self.assertNotIn(SECRET_TOKEN, '\n'.join(out))

    def test_green_step_leaves_redacted_logs(self):
        def leaky(log_dir, run_id):
            base.all_good(log_dir, run_id)
            path = log_dir / 'alpha_9592.log'
            path.write_text(path.read_text() + 'debug: url %s\n' % SECRET_URL)
        rc, out = self.step(base.FakeHost(self.e, write_logs=leaky))
        self.assertEqual(rc, 0, out)
        text = (self.shard / 'iso-logs' / 'alpha_9592.log').read_text()
        self.assertNotIn(SECRET_TOKEN, text)
        self.assertIn('debug: url <redacted-url>', text)

    def test_red_step_leaves_redacted_logs(self):
        def leaky(log_dir, run_id):
            base.all_good(log_dir, run_id)
            (log_dir / 'beta_9592.log').write_text('url %s\n' % SECRET_URL)
        rc, _out = self.step(base.FakeHost(self.e, write_logs=leaky))
        self.assertEqual(rc, 1)
        self.assertNotIn(SECRET_TOKEN, (self.shard / 'iso-logs' / 'beta_9592.log').read_text())

    def test_redact_logs_verb(self):
        log_dir = self.shard / 'iso-logs'
        log_dir.mkdir()
        (log_dir / 'x.log').write_text('u=%s\n' % SECRET_URL)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.e.cmd_redact_logs(self.env)
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertEqual((log_dir / 'x.log').read_text(), 'u=<redacted-url>\n')
        with redirect_stdout(io.StringIO()):
            self.assertEqual(self.e.cmd_redact_logs({}), 1)

    def test_host_run_streams_redacted_child_output(self):
        buf = io.StringIO()
        code = 'import os; print("child " + os.environ["AI_MEMORY_TEST_POSTGRES_URL"]); raise SystemExit(7)'
        with redirect_stdout(buf):
            rc = self.e.Host().run([sys.executable, '-c', code], dict(os.environ, AI_MEMORY_TEST_POSTGRES_URL=SECRET_URL))
        self.assertEqual(rc, 7)
        self.assertEqual(buf.getvalue(), 'child <redacted-url>\n')


# (line, is a hit)
SKIP_CASES = (
    ('skip: AI_MEMORY_TEST_POSTGRES_URL not set', True),
    ('Skipped: no AGE extension', True),
    ('postgres test skips: no url', True),
    ('skip AGE half: kg_backend resolved to CTE', True),
    ('AI_MEMORY_TEST_POSTGRES_URL unset — postgres half skipped', True),
    ('SKIPPING pg cell (no url)', True),
    ('test t ... skipping postgres', True),
    ('test it_skips_empty ... ok', False),
    ('test skip::case ... ok', False),
    ('test t ... ignored, skip on ci', False),
    ('---- skip_case stdout ----', False),
    ('# [pg_isolated_binary] skip', False),
    ('test result: ok. 2 passed; 0 failed; 0 ignored', False),
)


class SkipDetector(base.Base):
    def test_skip_table(self):
        for line, hit in SKIP_CASES:
            with self.subTest(line=line):
                self.assertEqual(bool(self.e.self_skip_lines(line)), hit)

    def test_100k_skip_lines_are_bounded(self):
        text = '\n'.join('skip: case %d' % i for i in range(BIG_ROWS))
        started = time.monotonic()
        hits = self.e.self_skip_lines(text)
        self.assertLess(time.monotonic() - started, BOUND_SECS)
        self.assertEqual(len(hits), self.e.SKIP_HITS_MAX)


def ignored_log(name, db, ignored):
    text = base.good_log(name, db, 'isolated')
    return text.replace('0 ignored', '%d ignored' % ignored)


class IgnoredParity(base.Base):
    """C-L3: each binary's ignored total equals what ``--list --ignored`` reports."""

    def run_with(self, list_out, beta_ignored=0, drop_running=False):
        def logs(log_dir, run_id):
            base.all_good(log_dir, run_id)
            text = ignored_log('beta_9592', 'ai_memory_t_%s_1700000000_000000cc' % run_id, beta_ignored)
            if drop_running:
                text = '\n'.join(ln for ln in text.splitlines() if 'Running' not in ln) + '\n'
            (log_dir / 'beta_9592.log').write_text(text)
        host = base.FakeHost(self.e, write_logs=logs, list_out=list_out)
        rc, out = self.step(host)
        return host, rc, out

    def test_matching_counts_are_green_and_the_list_call_has_no_url(self):
        host, rc, out = self.run_with({'beta_9592': (0, 'a: test\nb: test\n')}, beta_ignored=2)
        self.assertEqual(rc, 0, out)
        lists = [(argv, env) for kind, argv, env in host.calls if kind == 'capture' and '--list' in argv]
        self.assertEqual(len(lists), 3)
        for argv, env in lists:
            self.assertEqual(argv[1:], ['--list', '--ignored'])
            self.assertNotIn('AI_MEMORY_TEST_POSTGRES_URL', env)
            self.assertNotIn('AI_MEMORY_TEST_PG_ISOLATE', env)

    def test_a_test_ignored_only_under_isolation_is_red(self):
        _host, rc, out = self.run_with({'beta_9592': (0, 'a: test\n')}, beta_ignored=2)
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'ignored count differs from --list --ignored: beta_9592 (log=2 list=1)', out)

    def test_list_failure_is_red(self):
        _host, rc, out = self.run_with({'beta_9592': (1, '')})
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'cannot list ignored tests of beta_9592 (exit 1)', out)

    def test_log_without_the_binary_path_is_red(self):
        _host, rc, out = self.run_with({}, drop_running=True)
        self.assertEqual(rc, 1)
        self.assertIn(FAIL + 'no test binary path in the log: beta_9592', out)


if __name__ == '__main__':
    unittest.main()
