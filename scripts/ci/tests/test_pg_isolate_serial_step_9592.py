#!/usr/bin/env python3
"""Unit tests for scripts/ci/pg_isolate_serial_step.py (#9592, vote 71472661 I-2 / I-5 / I-6 / I-9 / I-11).

Run: python3 -m unittest scripts/ci/tests/test_pg_isolate_serial_step_9592.py

The entry is the only logic of the "serial shard isolated binaries" step of the
linux-fed enterprise-fed leg. Every side effect goes through a fake host, so
each fail-closed exit is proven with its exact reason and no database.
"""
import importlib.util
import io
import shutil
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / 'scripts' / 'ci' / 'pg_isolate_serial_step.py'
SCRATCH = REPO / '.local-runs' / 'test-pg-isolate-serial-step-9592'

SECRET_URL = 'postgresql://ci_user:s3cr3t-9592@pg.invalid:5445/ai_memory_ci_fed_9592'
SHARED_DB = 'ai_memory_ci_fed_9592'
TEMPLATE = SHARED_DB + '_tpl'
TARGETS = ('alpha_9592', 'beta_9592', 'resid_9592')
RESIDUAL = ('resid_9592',)
JOB_T0 = 1_000_000
NOW = JOB_T0 + 600


def load():
    spec = importlib.util.spec_from_file_location('pg_isolate_serial_step', SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules['pg_isolate_serial_step'] = mod
    spec.loader.exec_module(mod)
    return mod


def good_log(name, db, mode, tests=2, extra=''):
    lines = ['# [pg_isolated_binary] current_database=%s mode=%s' % (db, mode),
             '     Running tests/%s.rs (target/debug/deps/%s-0123456789abcdef)' % (name, name),
             'running %d tests' % tests]
    lines += ['test t%d ... ok' % i for i in range(tests)]
    if extra:
        lines.append(extra)
    lines.append('test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; '
                 'finished in 0.01s' % tests)
    return '\n'.join(lines) + '\n'


class FakeHost:
    """Records every call; ``run_rc`` scripts the exit of argv containing a key."""

    def __init__(self, entry, run_rc=None, setup_out=None, leftovers=(0, 0), write_logs=None):
        self.entry = entry
        self.calls = []
        self.env_lines = []
        self.run_rc = run_rc or {}
        self.setup_out = setup_out
        self.left = leftovers
        self.write_logs = write_logs
        self.leftover_checks = 0

    def now(self):
        return NOW

    def which(self, name):
        return '/usr/bin/' + name if name == 'timeout' else None

    def append_env(self, line):
        self.env_lines.append(line)

    def capture(self, argv, env):
        self.calls.append(('capture', list(argv), dict(env)))
        if self.setup_out is not None:
            return self.setup_out
        run_id = argv[argv.index('--run-id') + 1]
        return 0, 'AI_MEMORY_TEST_PG_TEMPLATE=%s\nAI_MEMORY_TEST_PG_RUN_ID=%s\n' % (TEMPLATE, run_id)

    def run(self, argv, env):
        self.calls.append(('run', list(argv), dict(env)))
        if 'pg_isolated_binary.py' in ' '.join(argv) and 'run' in argv and self.write_logs:
            log_dir = Path(argv[argv.index('--log-dir') + 1])
            run_id = argv[argv.index('--run-id') + 1]
            self.write_logs(log_dir, run_id)
        for key, rc in self.run_rc.items():
            if key in argv:
                return rc
        return 0

    def leftovers(self, env, db, run_id):
        self.leftover_checks += 1
        return self.left


def all_good(log_dir, run_id):
    log_dir.mkdir(parents=True, exist_ok=True)
    for i, name in enumerate(TARGETS):
        if name in RESIDUAL:
            text = good_log(name, SHARED_DB, 'residual')
        else:
            text = good_log(name, 'ai_memory_t_%s_1700000000_%08x' % (run_id, i), 'isolated')
        (log_dir / (name + '.log')).write_text(text)


class Base(unittest.TestCase):
    def setUp(self):
        self.e = load()
        self.root = SCRATCH / self.id().rsplit('.', 1)[-1]
        if self.root.exists():
            shutil.rmtree(self.root)
        self.shard = self.root / 'ci-shard'
        self.shard.mkdir(parents=True)
        (self.shard / 'iso_targets.txt').write_text(''.join('--test %s\n' % t for t in TARGETS))
        (self.shard / 'iso_residual.txt').write_text(''.join('%s\n' % t for t in RESIDUAL))
        (self.root / 'ci-iso-mode.txt').write_text('deferred\n')
        self.env = {'RUNNER_TEMP': str(self.root), 'AI_MEMORY_TEST_POSTGRES_URL': SECRET_URL,
                    'AI_MEMORY_TEST_PG_ISOLATE': '1', 'CI_FED_DB': SHARED_DB, 'JOB_TIMEOUT_MIN': '150',
                    'JOB_T0': str(JOB_T0), 'PATH': '/usr/bin'}

    def step(self, host, **env_over):
        env = dict(self.env, **env_over)
        env = {k: v for k, v in env.items() if v is not None}
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.e.run_step(host, env)
        out = buf.getvalue()
        self.assertNotIn(SECRET_URL, out)
        for _kind, argv, _env in host.calls:
            self.assertNotIn(SECRET_URL, ' '.join(argv))
        return rc, out

    def wrapper_runs(self, host):
        return [argv for kind, argv, _ in host.calls
                if kind == 'run' and 'pg_isolated_binary.py' in ' '.join(argv) and 'run' in argv]


class IsolatedPath(Base):
    def test_all_good_exits_zero_and_tears_down(self):
        host = FakeHost(self.e, write_logs=all_good)
        rc, out = self.step(host)
        self.assertEqual(rc, 0, out)
        self.assertIn('[#9592] serial shard isolated binaries ok: binaries=3 isolated=2 residual=1', out)
        self.assertEqual(host.leftover_checks, 1)
        teardown = [argv for kind, argv, _ in host.calls if 'teardown' in argv]
        self.assertEqual(len(teardown), 1)

    def test_run_id_reaches_github_env_before_setup(self):
        host = FakeHost(self.e, write_logs=all_good)
        self.step(host)
        self.assertTrue(host.env_lines[0].startswith('AI_MEMORY_TEST_PG_RUN_ID='))
        self.assertTrue(host.env_lines[1].startswith('AI_MEMORY_TEST_PG_TEMPLATE='))

    def test_wrapper_run_argv_shape(self):
        host = FakeHost(self.e, write_logs=all_good)
        self.step(host)
        (argv,) = self.wrapper_runs(host)
        self.assertEqual(argv[:5], ['/usr/bin/timeout', '--signal=TERM', '--kill-after=60', str(150 * 60 - 600 - 300)
                                    if 150 * 60 - 600 - 300 < 7800 else '7800', sys.executable])
        tail = argv[argv.index('--'):]
        self.assertEqual(tail, ['--', 'cargo', 'test', '--no-fail-fast', '--features', 'sal-postgres'])
        self.assertIn('--test-arg=--test-threads=1', argv)
        self.assertIn('--test-arg=--show-output', argv)
        self.assertNotIn('--url', argv)

    def test_teardown_passes_template_run_id_and_the_url_database(self):
        # PR 9686 dependency: teardown refuses without an explicit template and
        # checks --db against the URL database; the entry never parses refusal text.
        host = FakeHost(self.e, write_logs=all_good)
        self.step(host)
        ((argv, env),) = [(a, e) for kind, a, e in host.calls if 'teardown' in a]
        run_id = host.env_lines[0].split('=', 1)[1]
        self.assertEqual(argv[argv.index('--db') + 1], SHARED_DB)
        self.assertEqual(argv[argv.index('--run-id') + 1], run_id)
        self.assertEqual(env['AI_MEMORY_TEST_PG_TEMPLATE'], TEMPLATE)
        self.assertEqual(env['AI_MEMORY_TEST_PG_RUN_ID'], run_id)
        self.assertEqual(env['AI_MEMORY_TEST_POSTGRES_URL'], SECRET_URL)

    def test_teardown_after_a_failed_setup_still_names_the_template(self):
        host = FakeHost(self.e, setup_out=(3, ''), write_logs=all_good)
        self.step(host)
        ((_argv, env),) = [(a, e) for kind, a, e in host.calls if 'teardown' in a]
        self.assertEqual(env['AI_MEMORY_TEST_PG_TEMPLATE'], TEMPLATE)

    def test_db_that_is_not_the_url_database_fails_before_setup(self):
        host = FakeHost(self.e, write_logs=all_good)
        rc, out = self.step(host, CI_FED_DB='ai_memory_other_9592')
        self.assertEqual(rc, 1)
        self.assertIn('CI_FED_DB does not name the database of AI_MEMORY_TEST_POSTGRES_URL', out)
        self.assertEqual(host.calls, [])

    def test_setup_naming_another_template_fails_closed(self):
        host = FakeHost(self.e, setup_out=(0, 'AI_MEMORY_TEST_PG_TEMPLATE=other_tpl\n'), write_logs=all_good)
        self.assert_red(host, 'setup template is not %s' % TEMPLATE)

    def test_prebuild_builds_only_the_selection(self):
        host = FakeHost(self.e, write_logs=all_good)
        self.step(host)
        prebuild = [argv for kind, argv, _ in host.calls if '--no-run' in argv]
        self.assertEqual(prebuild, [['cargo', 'test', '--no-run', '--features', 'sal-postgres',
                                     '--test', 'alpha_9592', '--test', 'beta_9592', '--test', 'resid_9592']])

    def assert_red(self, host, reason):
        rc, out = self.step(host)
        self.assertEqual(rc, 1, out)
        self.assertIn(reason, out)
        self.assertEqual(host.leftover_checks, 1, 'teardown and the leftover check always run')
        return out

    def test_wrapper_exit_two_fails_closed(self):
        self.assert_red(FakeHost(self.e, run_rc={'--targets-file': 2}, write_logs=all_good),
                        'wrapper error (exit 2)')

    def test_wrapper_exit_three_fails_closed(self):
        self.assert_red(FakeHost(self.e, run_rc={'--targets-file': 3}, write_logs=all_good),
                        'clone mint/hold failure (exit 3)')

    def test_watchdog_exit_fails_closed(self):
        self.assert_red(FakeHost(self.e, run_rc={'--targets-file': 124}, write_logs=all_good),
                        'watchdog expired (exit 124)')

    def test_terminated_still_tears_down(self):
        self.assert_red(FakeHost(self.e, run_rc={'--targets-file': 143}, write_logs=all_good),
                        'terminated (exit 143)')

    def test_test_failures_fail(self):
        self.assert_red(FakeHost(self.e, run_rc={'--targets-file': 101}, write_logs=all_good),
                        'test failures (exit 101)')

    def test_missing_log_fails_closed(self):
        def missing(log_dir, run_id):
            all_good(log_dir, run_id)
            (log_dir / 'beta_9592.log').unlink()
        self.assert_red(FakeHost(self.e, write_logs=missing), 'missing log: beta_9592')

    def test_zero_test_binary_fails_closed(self):
        def zero(log_dir, run_id):
            all_good(log_dir, run_id)
            (log_dir / 'beta_9592.log').write_text(
                good_log('beta_9592', 'ai_memory_t_%s_1700000000_000000ff' % run_id, 'isolated', tests=0))
        self.assert_red(FakeHost(self.e, write_logs=zero), 'zero tests: beta_9592')

    def test_log_without_result_line_fails_closed(self):
        def no_result(log_dir, run_id):
            all_good(log_dir, run_id)
            (log_dir / 'beta_9592.log').write_text(
                '# [pg_isolated_binary] current_database=ai_memory_t_%s_1700000000_000000ff mode=isolated\n'
                'error: linking failed\n' % run_id)
        self.assert_red(FakeHost(self.e, write_logs=no_result), 'no test result line: beta_9592')

    def test_leftover_clone_after_teardown_fails_closed(self):
        self.assert_red(FakeHost(self.e, leftovers=(1, 0), write_logs=all_good),
                        'leftover clones after teardown: clones=1 template=0')

    def test_leftover_template_after_teardown_fails_closed(self):
        self.assert_red(FakeHost(self.e, leftovers=(0, 1), write_logs=all_good),
                        'leftover clones after teardown: clones=0 template=1')

    def test_teardown_failure_fails_closed(self):
        self.assert_red(FakeHost(self.e, run_rc={'teardown': 1}, write_logs=all_good),
                        'wrapper teardown failed (exit 1)')

    def test_setup_without_template_fails_closed(self):
        host = FakeHost(self.e, setup_out=(0, 'AI_MEMORY_TEST_PG_RUN_ID=r0\n'), write_logs=all_good)
        self.assert_red(host, 'setup emitted no AI_MEMORY_TEST_PG_TEMPLATE')
        self.assertEqual(self.wrapper_runs(host)[:1], [])

    def test_setup_failure_fails_closed(self):
        host = FakeHost(self.e, setup_out=(3, ''), write_logs=all_good)
        self.assert_red(host, 'wrapper setup failed (exit 3)')

    def test_binary_not_on_a_clone_of_this_run_fails(self):
        def foreign(log_dir, run_id):
            all_good(log_dir, run_id)
            (log_dir / 'beta_9592.log').write_text(good_log('beta_9592', SHARED_DB, 'isolated'))
        self.assert_red(FakeHost(self.e, write_logs=foreign),
                        'not on a clone of this run: beta_9592 (current_database=%s)' % SHARED_DB)

    def test_two_binaries_on_one_clone_fail(self):
        def shared(log_dir, run_id):
            all_good(log_dir, run_id)
            text = (log_dir / 'alpha_9592.log').read_text().replace('alpha_9592', 'beta_9592')
            (log_dir / 'beta_9592.log').write_text(text)
        self.assert_red(FakeHost(self.e, write_logs=shared), 'duplicate database: alpha_9592 and beta_9592 share')

    def test_residual_off_the_shared_database_fails(self):
        def moved(log_dir, run_id):
            all_good(log_dir, run_id)
            (log_dir / 'resid_9592.log').write_text(
                good_log('resid_9592', 'ai_memory_t_%s_1700000000_000000aa' % run_id, 'isolated'))
        self.assert_red(FakeHost(self.e, write_logs=moved),
                        'residual not on the shared database: resid_9592')

    def test_missing_evidence_line_fails(self):
        def bare(log_dir, run_id):
            all_good(log_dir, run_id)
            text = (log_dir / 'beta_9592.log').read_text().split('\n', 1)[1]
            (log_dir / 'beta_9592.log').write_text(text)
        self.assert_red(FakeHost(self.e, write_logs=bare), 'no current_database evidence line: beta_9592')

    def test_self_skipped_pg_test_fails(self):
        def skipped(log_dir, run_id):
            all_good(log_dir, run_id)
            (log_dir / 'beta_9592.log').write_text(
                good_log('beta_9592', 'ai_memory_t_%s_1700000000_000000bb' % run_id, 'isolated',
                         extra='skip: AI_MEMORY_TEST_POSTGRES_URL not set'))
        self.assert_red(FakeHost(self.e, write_logs=skipped),
                        'self-skipped PG test in beta_9592: skip: AI_MEMORY_TEST_POSTGRES_URL not set')


class Inputs(Base):
    def test_mode_none_is_a_notice_and_zero(self):
        (self.root / 'ci-iso-mode.txt').write_text('none\n')
        host = FakeHost(self.e)
        rc, out = self.step(host)
        self.assertEqual(rc, 0)
        self.assertIn('[#9592] no serial-shard binaries were deferred to this step', out)
        self.assertEqual(host.calls, [])

    def test_missing_mode_file_fails_closed(self):
        (self.root / 'ci-iso-mode.txt').unlink()
        rc, out = self.step(FakeHost(self.e))
        self.assertEqual(rc, 1)
        self.assertIn('cannot read the isolation mode file', out)

    def test_unknown_mode_fails_closed(self):
        (self.root / 'ci-iso-mode.txt').write_text('maybe\n')
        rc, out = self.step(FakeHost(self.e))
        self.assertEqual(rc, 1)
        self.assertIn("unknown isolation mode 'maybe'", out)

    def test_deferred_with_no_targets_fails_closed(self):
        (self.shard / 'iso_targets.txt').write_text('')
        rc, out = self.step(FakeHost(self.e))
        self.assertEqual(rc, 1)
        self.assertIn('deferred mode but iso_targets.txt lists no binary', out)

    def test_flag_not_set_fails_closed(self):
        rc, out = self.step(FakeHost(self.e), AI_MEMORY_TEST_PG_ISOLATE=None)
        self.assertEqual(rc, 1)
        self.assertIn('the step env does not set AI_MEMORY_TEST_PG_ISOLATE=1', out)

    def test_no_job_time_left_fails_closed(self):
        rc, out = self.step(FakeHost(self.e), JOB_TIMEOUT_MIN='15')
        self.assertEqual(rc, 1)
        self.assertIn('no job time left for the serial shard step', out)

    def test_watchdog_is_capped(self):
        self.assertEqual(self.e.watchdog_secs({'JOB_TIMEOUT_MIN': '600', 'JOB_T0': str(JOB_T0)}, NOW),
                         self.e.WATCHDOG_CAP_SECS)
        self.assertEqual(self.e.watchdog_secs({'JOB_TIMEOUT_MIN': '60', 'JOB_T0': str(JOB_T0)}, NOW),
                         60 * 60 - 600 - self.e.WATCHDOG_MARGIN_SECS)
        self.assertEqual(self.e.watchdog_secs({'JOB_T0': '0123'}, NOW), self.e.WATCHDOG_CAP_SECS)


class KillSwitch(Base):
    def test_kill_switch_prints_notice_and_runs_the_exact_serial_argv(self):
        host = FakeHost(self.e)
        rc, out = self.step(host, CI_PG_ISOLATE_OFF='1')
        self.assertEqual(rc, 0, out)
        self.assertIn('[#9592] per-binary Postgres isolation disabled by CI_PG_ISOLATE_OFF=1: running the serial path',
                      out)
        self.assertEqual(self.wrapper_runs(host), [])
        runs = [(argv, env) for kind, argv, env in host.calls if kind == 'run']
        sel = ['--test', 'alpha_9592', '--test', 'beta_9592', '--test', 'resid_9592']
        self.assertEqual(runs[0][0], ['cargo', 'test', '--no-run', '--features', 'sal-postgres'] + sel)
        self.assertEqual(runs[1][0][4:], ['cargo', 'test', '--no-fail-fast', '--features', 'sal-postgres'] + sel
                         + ['--', '--test-threads=1'])
        self.assertEqual(runs[1][1]['AI_MEMORY_TEST_PG_ISOLATE'], '0')
        self.assertEqual(self.e.serial_argv(sel), ['cargo', 'test', '--no-fail-fast', '--features', 'sal-postgres']
                         + sel + ['--', '--test-threads=1'])

    def test_kill_switch_red_tests_stay_red(self):
        rc, out = self.step(FakeHost(self.e, run_rc={'--no-fail-fast': 101}), CI_PG_ISOLATE_OFF='1')
        self.assertEqual(rc, 1)
        self.assertIn('serial path test failures (exit 101)', out)


class SelfSkip(Base):
    def test_detector_forms(self):
        hits = self.e.self_skip_lines('\n'.join([
            'skip: AI_MEMORY_TEST_POSTGRES_URL not set',
            'skipping: AI_MEMORY_TEST_POSTGRES_URL unset',
            'test skipped: PostgresStore::connect failed: refused',
            'skip: cannot reach AI_MEMORY_TEST_POSTGRES_URL: ' + SECRET_URL,
            'skip: no AI_MEMORY_TEST_POSTGRES_URL',
            'skip: AI_MEMORY_TEST_AGE_URL not set',
            'skipping: openssl not available on PATH',
            'test t0 ... ok',
            '# [pg_isolated_binary] skip connect failed',
        ]))
        self.assertEqual(hits, ['skip: AI_MEMORY_TEST_POSTGRES_URL not set',
                                'skipping: AI_MEMORY_TEST_POSTGRES_URL unset',
                                'test skipped: PostgresStore::connect failed: refused',
                                'skip: cannot reach AI_MEMORY_TEST_POSTGRES_URL: <redacted-url>',
                                'skip: no AI_MEMORY_TEST_POSTGRES_URL'])

    def test_detector_bounds_long_lines(self):
        hits = self.e.self_skip_lines('skip: connect failed ' + 'x' * 100_000)
        self.assertEqual(len(hits), 1)
        self.assertLessEqual(len(hits[0]), self.e.SKIP_LINE_MAX)


class Leftovers(Base):
    def test_leftovers_command(self):
        host = FakeHost(self.e, leftovers=(2, 1))
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.e.cmd_leftovers(host, dict(self.env, AI_MEMORY_TEST_PG_RUN_ID='rabc'))
        self.assertEqual(rc, 1)
        self.assertIn('[#9592] isolation leftovers after teardown: clones=2 template=1', buf.getvalue())

    def test_leftovers_clean(self):
        host = FakeHost(self.e)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.e.cmd_leftovers(host, dict(self.env, AI_MEMORY_TEST_PG_RUN_ID='rabc'))
        self.assertEqual(rc, 0)
        self.assertIn('[#9592] isolation leftovers after teardown: clones=0 template=0', buf.getvalue())

    def test_leftovers_without_a_run_id_is_zero(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.e.cmd_leftovers(FakeHost(self.e), self.env)
        self.assertEqual(rc, 0)
        self.assertIn('no isolation run id', buf.getvalue())


class Cleanup(Base):
    """I-11: the always() Cleanup step tears this run down again, then proves nothing is left."""

    def cleanup(self, host, **env_over):
        env = dict(self.env, AI_MEMORY_TEST_PG_RUN_ID='rabc')
        env.update(env_over)
        env = {k: v for k, v in env.items() if v is not None}
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.e.cmd_cleanup(host, env)
        out = buf.getvalue()
        self.assertNotIn(SECRET_URL, out)
        return rc, out

    def test_cleanup_tears_down_with_explicit_template_and_url_database(self):
        host = FakeHost(self.e)
        rc, out = self.cleanup(host)
        self.assertEqual(rc, 0, out)
        ((argv, env),) = [(a, e) for kind, a, e in host.calls if 'teardown' in a]
        self.assertEqual(argv[argv.index('--db') + 1], SHARED_DB)
        self.assertEqual(argv[argv.index('--run-id') + 1], 'rabc')
        self.assertNotIn('--url', argv)
        self.assertEqual(env['AI_MEMORY_TEST_PG_TEMPLATE'], TEMPLATE)
        self.assertEqual(host.leftover_checks, 1)
        self.assertIn('[#9592] isolation leftovers after teardown: clones=0 template=0', out)

    def test_cleanup_reports_leftovers(self):
        rc, out = self.cleanup(FakeHost(self.e, leftovers=(1, 1)))
        self.assertEqual(rc, 1)
        self.assertIn('[#9592] isolation leftovers after teardown: clones=1 template=1', out)

    def test_cleanup_teardown_failure_fails(self):
        host = FakeHost(self.e, run_rc={'teardown': 2})
        rc, out = self.cleanup(host)
        self.assertEqual(rc, 1)
        self.assertIn('wrapper teardown failed (exit 2)', out)
        self.assertEqual(host.leftover_checks, 1)

    def test_cleanup_without_a_run_id_does_nothing(self):
        host = FakeHost(self.e)
        rc, out = self.cleanup(host, AI_MEMORY_TEST_PG_RUN_ID=None)
        self.assertEqual(rc, 0)
        self.assertIn('no isolation run id', out)
        self.assertEqual(host.calls, [])

    def test_cleanup_refuses_a_db_that_is_not_the_url_database(self):
        host = FakeHost(self.e)
        rc, out = self.cleanup(host, CI_FED_DB='ai_memory_other_9592')
        self.assertEqual(rc, 1)
        self.assertIn('CI_FED_DB does not name the database of AI_MEMORY_TEST_POSTGRES_URL', out)
        self.assertEqual(host.calls, [])


class Termination(Base):
    """I-11: a TERM while the wrapper runs still tears down and checks for leftovers."""

    def test_sigterm_during_the_run_still_tears_down(self):
        e = self.e

        class Cancelled(FakeHost):
            def run(self, argv, env):
                if 'pg_isolated_binary.py' in ' '.join(argv) and 'run' in argv:
                    self.calls.append(('run', list(argv), dict(env)))
                    raise e.StepCancelled(15)
                return super().run(argv, env)
        host = Cancelled(e, write_logs=all_good)
        rc, out = self.step(host)
        self.assertEqual(rc, 1)
        self.assertIn('cancelled by signal 15', out)
        self.assertEqual(len([a for kind, a, _ in host.calls if 'teardown' in a]), 1)
        self.assertEqual(host.leftover_checks, 1)


if __name__ == '__main__':
    unittest.main()
