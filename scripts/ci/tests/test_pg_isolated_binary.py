#!/usr/bin/env python3
"""Unit tests for scripts/test/pg_isolated_binary.py (#6383 / #6386, review r2).

Run: python3 -m unittest scripts/ci/tests/test_pg_isolated_binary.py

Offline by default: ``subprocess.run`` / ``subprocess.Popen`` / ``os.killpg``
are replaced by recorders, so the assertions are about exact argument lists,
SQL order, child environments and exit codes. ``LiveEndToEnd`` additionally
runs the real script against the Postgres named by
``AI_MEMORY_TEST_POSTGRES_URL`` and skips when that is unset.
"""
import importlib.util
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / 'scripts' / 'test' / 'pg_isolated_binary.py'
SPEC = importlib.util.spec_from_file_location('pg_isolated_binary', SCRIPT)
pib = importlib.util.module_from_spec(SPEC)
sys.modules['pg_isolated_binary'] = pib
SPEC.loader.exec_module(pib)

BASE = 'postgres://u:pw@127.0.0.1:5445/ai_memory_test_ci_9_1_x?sslmode=verify-full&sslrootcert=/c/ca.crt'
TPL = 'ai_memory_test_ci_9_1_x_tpl'
RUN = 'r6386'
OTHER = 'zother'
SCRATCH = REPO / '.local-runs' / 'pg-isolate-unittest'


def scratch_dir():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    return tempfile.mkdtemp(dir=str(SCRATCH))


class Result:
    def __init__(self, rc=0, out='', err=''):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


def default_answer(argv, kw):
    """Plausible psql answers: a roomy budget and one live session per clone."""
    sql = argv[argv.index('-c') + 1] if '-c' in argv else ''
    if 'max_connections' in sql:
        return Result(0, '1000|3|0|10\n')
    if 'count(*)' in sql and 'pg_stat_activity' in sql:
        return Result(0, '1\n')
    return Result()


class Recorder:
    """subprocess.run stand-in: records calls, answers from a script."""

    def __init__(self, answer=None):
        self.calls = []
        self.answer = answer or default_answer
        self.lock = threading.Lock()

    def __call__(self, argv, **kw):
        assert isinstance(argv, list), 'argument list, never a shell string'
        assert not kw.get('shell'), 'shell=True is forbidden'
        with self.lock:
            self.calls.append((list(argv), kw))
        return self.answer(list(argv), kw)

    def sql(self):
        return [a[a.index('-c') + 1] for a, _ in self.calls if '-c' in a]


class FakePopen:
    """subprocess.Popen stand-in for holds (psql) and cargo children."""

    instances = []
    lock = threading.Lock()
    cargo_rc = 0
    cargo_output = 'test result: ok. 1 passed; 0 failed\n'
    block = None  # threading.Event the cargo child waits on, when set

    def __init__(self, argv, **kw):
        assert isinstance(argv, list), 'argument list, never a shell string'
        assert not kw.get('shell'), 'shell=True is forbidden'
        self.argv, self.kw = list(argv), kw
        self.pid = 40000 + len(FakePopen.instances)
        self.returncode = None
        self.stdin = mock.Mock()
        self.is_hold = argv[0] == 'psql'
        with FakePopen.lock:
            FakePopen.instances.append(self)
        out = kw.get('stdout')
        if not self.is_hold and hasattr(out, 'write'):
            out.write(FakePopen.cargo_output)
            out.flush()

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.is_hold:
            self.returncode = 0
            return 0
        if FakePopen.block is not None:
            FakePopen.block.wait(10)
            if self.returncode is not None:
                return self.returncode
        self.returncode = FakePopen.cargo_rc
        return self.returncode

    def kill(self):
        self.returncode = -9

    @classmethod
    def reset(cls):
        cls.instances = []
        cls.cargo_rc = 0
        cls.cargo_output = 'test result: ok. 1 passed; 0 failed\n'
        cls.block = None

    @classmethod
    def cargo(cls):
        return [p for p in cls.instances if not p.is_hold]


def patched(rec=None):
    """Context: fake run, fake Popen, fake killpg, no sleeping."""
    FakePopen.reset()
    rec = rec or Recorder()
    stack = [mock.patch.object(pib.subprocess, 'run', rec),
             mock.patch.object(pib.subprocess, 'Popen', FakePopen),
             mock.patch.object(pib.os, 'killpg'),
             mock.patch.object(pib.time, 'sleep')]
    return rec, stack


class Patched:
    def __init__(self, rec=None):
        self.rec, self.stack = patched(rec)

    def __enter__(self):
        self.mocks = [p.__enter__() for p in self.stack]
        return self.rec

    def __exit__(self, *exc):
        for p in reversed(self.stack):
            p.__exit__(*exc)
        return False


def runner(env=None, log_dir=None, width=2):
    env = dict(env or {pib.URL_VAR: BASE, pib.FLAG_VAR: '1', pib.TEMPLATE_VAR: TPL})
    return pib.Runner(cargo=['cargo', 'test', '--no-fail-fast'], test_args=['--test-threads=1'],
                      env=env, tpl=TPL, run_id=RUN, admin=BASE,
                      log_dir=log_dir or scratch_dir(), width=width)


class NameAndUrl(unittest.TestCase):
    def test_database_name_ignores_query(self):
        self.assertEqual(pib.database_name(BASE), 'ai_memory_test_ci_9_1_x')

    def test_with_database_preserves_tls_query(self):
        out = pib.with_database(BASE, 'ai_memory_t_r6386_1700000000_0123abcd')
        self.assertEqual(
            out,
            'postgres://u:pw@127.0.0.1:5445/ai_memory_t_r6386_1700000000_0123abcd'
            '?sslmode=verify-full&sslrootcert=/c/ca.crt')

    def test_quote_ident_doubles_quotes(self):
        self.assertEqual(pib.quote_ident('a"b'), '"a""b"')

    def test_safe_target_selector_rejects_shell_metacharacters(self):
        self.assertEqual(pib.parse_target_line('--test foo_bar-1'), ['--test', 'foo_bar-1'])
        self.assertEqual(pib.parse_target_line('--bin ai-memory'), ['--bin', 'ai-memory'])
        for bad in ('--test a;b', '--test $(x)', '--test', '--weird x', '--test a b', ''):
            with self.assertRaises(pib.WrapperError, msg=bad):
                pib.parse_target_line(bad)


class RunIdScoping(unittest.TestCase):
    """Review r1 H2: every clone carries the run id; nothing cross-run."""

    def test_run_id_validation(self):
        self.assertTrue(pib.valid_run_id(RUN))
        self.assertTrue(pib.valid_run_id('a' * pib.RUN_ID_MAX_LEN))
        for bad in ('', 'UP', 'a-b', 'a_b', 'x;y', 'a' * (pib.RUN_ID_MAX_LEN + 1)):
            self.assertFalse(pib.valid_run_id(bad), bad)
        fresh = pib.new_run_id()
        self.assertTrue(pib.valid_run_id(fresh), fresh)
        self.assertNotEqual(fresh, pib.new_run_id())

    def test_minted_name_shape_carries_run_id(self):
        name = pib.isolated_db_name(RUN, 1700000000)
        self.assertRegex(name, r'^ai_memory_t_r6386_[0-9]{10}_[0-9a-f]{8}$')
        self.assertLessEqual(len(pib.isolated_db_name('a' * pib.RUN_ID_MAX_LEN, 1700000000)), 63)
        self.assertEqual(pib.parse_isolated_name(name, RUN), 1700000000)
        self.assertEqual(pib.parse_isolated_name(name), 1700000000, 'any-run parse for the admin sweep')
        self.assertIsNone(pib.parse_isolated_name(name, OTHER), 'another run never matches')
        self.assertIsNone(pib.parse_isolated_name(name, 'r638'), 'prefix of a run id never matches')
        for bad in ('ai_memory_t_1700000000_0123abcd', 'ai_memory_t_r6386_1700000000_0123ABCD',
                    'ai_memory_t_r6386_17_0123abcd', 'ai_memory_test_ci_9_1_x', 'ai_memory_t_',
                    'x_ai_memory_t_r6386_1700000000_0123abcd'):
            self.assertIsNone(pib.parse_isolated_name(bad), bad)
            self.assertIsNone(pib.parse_isolated_name(bad, RUN), bad)

    def test_isolated_db_name_refuses_bad_run_id(self):
        with self.assertRaises(pib.WrapperError):
            pib.isolated_db_name('Bad-Run', 1700000000)


class LibpqEnv(unittest.TestCase):
    """Review r1 L3: the URL and password never reach argv."""

    def test_url_maps_to_libpq_variables(self):
        env = pib.libpq_env(BASE)
        self.assertEqual(env['PGHOST'], '127.0.0.1')
        self.assertEqual(env['PGPORT'], '5445')
        self.assertEqual(env['PGUSER'], 'u')
        self.assertEqual(env['PGPASSWORD'], 'pw')
        self.assertEqual(env['PGDATABASE'], 'ai_memory_test_ci_9_1_x')
        self.assertEqual(env['PGSSLMODE'], 'verify-full')
        self.assertEqual(env['PGSSLROOTCERT'], '/c/ca.crt')
        self.assertIn('PGCONNECT_TIMEOUT', env)

    def test_percent_encoded_credentials_are_decoded(self):
        env = pib.libpq_env('postgresql://a%40b:p%2Fw@h:1/d')
        self.assertEqual((env['PGUSER'], env['PGPASSWORD'], env['PGPORT']), ('a@b', 'p/w', '1'))

    def test_unknown_query_key_or_bad_scheme_fails_closed(self):
        for bad in ('postgres://u:p@h:1/d?weird=1', 'mysql://u:p@h:1/d', 'postgres://u:p@h1,h2:1/d',
                    'postgres://u:p@h:1/'):
            with self.assertRaises(pib.WrapperError, msg=bad):
                pib.libpq_env(bad)

    def test_psql_argv_has_no_url_or_password_and_strips_inherited_pg_vars(self):
        rec = Recorder()
        with mock.patch.object(pib.subprocess, 'run', rec), \
                mock.patch.dict(os.environ, {'PGSERVICE': 'evil', 'PGPASSFILE': '/x'}):
            pib.psql(BASE, 'SELECT 1', tuples=True)
        argv, kw = rec.calls[0]
        joined = ' '.join(argv)
        self.assertEqual(argv[0], 'psql')
        self.assertNotIn('postgres://', joined)
        self.assertNotIn('pw', argv)
        self.assertNotIn('127.0.0.1', joined)
        self.assertEqual(kw['env']['PGPASSWORD'], 'pw')
        self.assertNotIn('PGSERVICE', kw['env'])
        self.assertNotIn('PGPASSFILE', kw['env'])
        self.assertIn('ON_ERROR_STOP=1', argv)


class MintAndDrop(unittest.TestCase):
    def test_mint_issues_create_database_template_with_run_id(self):
        rec = Recorder()
        with mock.patch.object(pib.subprocess, 'run', rec):
            url, name = pib.mint(BASE, TPL, RUN, now=1700000000)
        self.assertEqual(pib.database_name(url), name)
        self.assertEqual(pib.parse_isolated_name(name, RUN), 1700000000)
        self.assertIn('sslmode=verify-full', url)
        self.assertEqual(rec.sql(), ['CREATE DATABASE "%s" TEMPLATE "%s"' % (name, TPL)])

    def test_mint_retries_on_template_in_use_then_succeeds(self):
        state = {'n': 0}

        def answer(argv, kw):
            state['n'] += 1
            if state['n'] < 3:
                return Result(1, '', 'ERROR:  source database "t" is being accessed by other users')
            return Result()
        with mock.patch.object(pib.subprocess, 'run', Recorder(answer)), mock.patch.object(pib.time, 'sleep'):
            pib.mint(BASE, TPL, RUN, now=1700000000)
        self.assertEqual(state['n'], 3)

    def test_mint_does_not_retry_other_errors(self):
        rec = Recorder(lambda a, k: Result(1, '', 'ERROR: permission denied to create database'))
        with mock.patch.object(pib.subprocess, 'run', rec):
            with self.assertRaises(pib.WrapperError):
                pib.mint(BASE, TPL, RUN, now=1700000000)
        self.assertEqual(len(rec.calls), 1)

    def test_drop_never_forces(self):
        rec = Recorder()
        with mock.patch.object(pib.subprocess, 'run', rec):
            pib.drop(BASE, 'ai_memory_t_r6386_1700000000_0123abcd', RUN)
        self.assertEqual(rec.sql(), ['DROP DATABASE IF EXISTS "ai_memory_t_r6386_1700000000_0123abcd"'])

    def test_drop_refuses_another_runs_clone_and_non_clone_names(self):
        rec = Recorder()
        with mock.patch.object(pib.subprocess, 'run', rec):
            for name in ('ai_memory_t_zother_1700000000_0123abcd', 'ai_memory_test_ci_9_1_x'):
                with self.assertRaises(pib.WrapperError, msg=name):
                    pib.drop(BASE, name, RUN)
        self.assertEqual(rec.calls, [])

    def test_drop_retries_while_in_use_then_fails_closed(self):
        rec = Recorder(lambda a, k: Result(1, '', 'ERROR: database "x" is being accessed by other users'))
        with mock.patch.object(pib.subprocess, 'run', rec), mock.patch.object(pib.time, 'sleep'):
            with self.assertRaises(pib.WrapperError):
                pib.drop(BASE, 'ai_memory_t_r6386_1700000000_0123abcd', RUN)
        self.assertEqual(len(rec.calls), pib.DROP_ATTEMPTS)
        self.assertFalse([s for s in rec.sql() if 'FORCE' in s])

    def test_source_has_no_force_drop(self):
        self.assertFalse('WITH (FORCE)' in SCRIPT.read_text(), 'no FORCE drop in the wrapper')


class Budget(unittest.TestCase):
    """Review r1 M5: the budget is what the server has free right now."""

    def test_budget_subtracts_reserved_and_live_sessions(self):
        rec = Recorder(lambda a, k: Result(0, '200|3|2|150\n'))
        with mock.patch.object(pib.subprocess, 'run', rec):
            got = pib.connection_budget(BASE)
        self.assertEqual(got, (200, 5, 150, 45))
        self.assertIn('pg_stat_activity', rec.sql()[0])

    def test_width_degrades_to_what_fits_and_fails_closed_at_zero(self):
        per = pib.PER_BINARY_CONNECTIONS + pib.HOLD_CONNECTIONS
        self.assertEqual(pib.width_for(10_000, 8), 8)
        self.assertEqual(pib.width_for(pib.CONNECTION_HEADROOM + 2 * per, 8), 2)
        with self.assertRaises(pib.WrapperError):
            pib.width_for(pib.CONNECTION_HEADROOM + per - 1, 8)

    def test_setup_fails_closed_when_live_budget_is_short(self):
        rec = Recorder(lambda a, k: Result(0, '1000|3|0|950\n') if 'max_connections' in ' '.join(a)
                       else Result())
        with mock.patch.object(pib.subprocess, 'run', rec):
            with self.assertRaises(pib.WrapperError) as ctx:
                pib.setup(BASE, 'ai_memory_test_ci_9_1_x', 8)
        self.assertIn('connection', str(ctx.exception))
        self.assertFalse([s for s in rec.sql() if s.startswith('CREATE DATABASE')])

    def test_required_connections_formula(self):
        self.assertEqual(pib.required_connections(8),
                         8 * (pib.PER_BINARY_CONNECTIONS + pib.HOLD_CONNECTIONS) + pib.CONNECTION_HEADROOM)


class TierSteps(unittest.TestCase):
    def test_setup_creates_template_installs_extensions_then_locks_it(self):
        rec = Recorder()
        with mock.patch.object(pib.subprocess, 'run', rec):
            tpl = pib.setup(BASE, 'ai_memory_test_ci_9_1_x', 8)
        self.assertEqual(tpl, TPL)
        sql = rec.sql()
        self.assertIn('CREATE DATABASE "%s"' % TPL, sql)
        ext = [i for i, s in enumerate(sql) if 'CREATE EXTENSION IF NOT EXISTS age' in s]
        lock = [i for i, s in enumerate(sql) if 'IS_TEMPLATE true ALLOW_CONNECTIONS false' in s]
        self.assertTrue(ext and lock and ext[0] < lock[0], 'extensions before the template is locked')
        ext_env = [k['env'] for a, k in rec.calls if any('CREATE EXTENSION' in x for x in a)][0]
        self.assertEqual(ext_env['PGDATABASE'], TPL, 'extensions install inside the template')
        self.assertFalse([s for s in sql if 'FORCE' in s])

    def test_setup_emit_env_prints_template_and_run_id_lines(self):
        rec = Recorder()
        out = []
        with mock.patch.object(pib.subprocess, 'run', rec), \
                mock.patch.dict(os.environ, {pib.URL_VAR: BASE}, clear=False), \
                mock.patch.object(pib, '_emit', out.append):
            rc = pib.main(['setup', '--db', 'ai_memory_test_ci_9_1_x', '--jobs', '8', '--run-id', RUN,
                           '--emit-env'])
        self.assertEqual(rc, 0)
        self.assertEqual(out, ['%s=%s' % (pib.TEMPLATE_VAR, TPL), '%s=%s' % (pib.RUN_ID_VAR, RUN)])

    def test_teardown_drops_only_this_runs_clones_without_force(self):
        def answer(argv, kw):
            if '-At' in argv:
                return Result(0, 'ai_memory_t_r6386_1700000000_0123abcd\n'
                                 'ai_memory_t_zother_1700000000_0123abcd\n'
                                 'ai_memory_test_ci_9_1_x\n')
            return Result()
        rec = Recorder(answer)
        with mock.patch.object(pib.subprocess, 'run', rec):
            pib.teardown(BASE, 'ai_memory_test_ci_9_1_x', RUN)
        sql = rec.sql()
        listing = [s for s in sql if s.startswith('SELECT')][0]
        self.assertIn('ai_memory_t_r6386_', listing, 'the listing is scoped to this run')
        drops = [s for s in sql if s.startswith('DROP DATABASE')]
        self.assertIn('DROP DATABASE IF EXISTS "ai_memory_t_r6386_1700000000_0123abcd"', drops)
        self.assertIn('DROP DATABASE IF EXISTS "%s"' % TPL, drops)
        self.assertFalse([s for s in drops if 'zother' in s or s.endswith('"ai_memory_test_ci_9_1_x"')])
        self.assertFalse([s for s in sql if 'FORCE' in s])
        unmark = [i for i, s in enumerate(sql) if 'IS_TEMPLATE false' in s]
        drop_tpl = [i for i, s in enumerate(sql) if s == 'DROP DATABASE IF EXISTS "%s"' % TPL]
        self.assertTrue(unmark and drop_tpl and unmark[0] < drop_tpl[0])

    def test_teardown_requires_a_valid_run_id(self):
        with mock.patch.object(pib.subprocess, 'run', Recorder()):
            with self.assertRaises(pib.WrapperError):
                pib.teardown(BASE, 'ai_memory_test_ci_9_1_x', 'Bad-Run')

    def test_admin_sweep_needs_an_explicit_age_floor(self):
        with mock.patch.object(pib.subprocess, 'run', Recorder()):
            with self.assertRaises(pib.WrapperError):
                pib.sweep(BASE, pib.MIN_SWEEP_AGE_SECS - 1)
        self.assertNotEqual(pib.main(['sweep']), 0, '--older-than is required')

    def test_admin_sweep_is_idle_only_aged_and_never_forces(self):
        def answer(argv, kw):
            sql = argv[argv.index('-c') + 1]
            if 'extract(epoch' in sql:
                return Result(0, '1700005000\n')
            if sql.startswith('SELECT'):
                return Result(0, 'ai_memory_t_zother_1700000000_0123abcd\n'
                                 'ai_memory_t_r6386_1700004900_0123abcd\n'
                                 'ai_memory_test_ci_9_1_x\n')
            return Result()
        rec = Recorder(answer)
        with mock.patch.object(pib.subprocess, 'run', rec):
            dropped = pib.sweep(BASE, 3600)
        self.assertEqual(dropped, ['ai_memory_t_zother_1700000000_0123abcd'])
        listing = [s for s in rec.sql() if 'pg_database' in s][0]
        self.assertIn('pg_stat_activity', listing, 'a database with a live session is never swept')
        self.assertFalse([s for s in rec.sql() if 'FORCE' in s])


class RunOne(unittest.TestCase):
    def test_cargo_runs_against_held_clone_then_clone_is_dropped(self):
        r = runner()
        with Patched() as rec:
            rc = r.run_one(['--test', 'foo_6383'], isolate=True)
        self.assertEqual(rc, 0)
        cargo = FakePopen.cargo()
        self.assertEqual(len(cargo), 1)
        self.assertEqual(cargo[0].argv, ['cargo', 'test', '--no-fail-fast', '--test', 'foo_6383', '--',
                                         '--test-threads=1'])
        self.assertTrue(cargo[0].kw.get('start_new_session'), 'children get their own process group')
        minted = pib.database_name(cargo[0].kw['env'][pib.URL_VAR])
        self.assertEqual(pib.parse_isolated_name(minted, RUN) is not None, True, minted)
        holds = [p for p in FakePopen.instances if p.is_hold]
        self.assertEqual(len(holds), 1, 'one keepalive session per clone')
        self.assertEqual(holds[0].kw['env']['PGDATABASE'], minted)
        self.assertNotIn('postgres://', ' '.join(holds[0].argv))
        sql = rec.sql()
        self.assertTrue(sql[0].startswith('CREATE DATABASE'))
        self.assertEqual(sql[-1], 'DROP DATABASE IF EXISTS "%s"' % minted)

    def test_hold_that_never_appears_fails_closed_without_running_cargo(self):
        def answer(argv, kw):
            sql = argv[argv.index('-c') + 1]
            if 'count(*)' in sql:
                return Result(0, '0\n')
            return Result()
        r = runner()
        with Patched(Recorder(answer)), mock.patch.object(pib.time, 'monotonic',
                                                           side_effect=[0.0] + [1e6] * 50):
            rc = r.run_one(['--test', 'foo'], isolate=True)
        self.assertEqual(rc, pib.EXIT_MINT)
        self.assertEqual(FakePopen.cargo(), [])

    def test_mint_failure_fails_closed_without_running_cargo(self):
        r = runner()
        with Patched(Recorder(lambda a, k: Result(1, '', 'ERROR: boom'))):
            rc = r.run_one(['--test', 'foo'], isolate=True)
        self.assertEqual(rc, pib.EXIT_MINT)
        self.assertEqual(FakePopen.cargo(), [])

    def test_residual_runs_on_shared_database_with_flag_stripped(self):
        # Review r1 M1: the Rust helper must not mint for a residual binary.
        r = runner()
        with Patched() as rec:
            rc = r.run_one(['--test', 'a2a_campaign_round1'], isolate=False)
        self.assertEqual(rc, 0)
        self.assertEqual(rec.sql(), [], 'nothing minted for a residual binary')
        env = FakePopen.cargo()[0].kw['env']
        self.assertEqual(env[pib.URL_VAR], BASE)
        self.assertNotIn(pib.FLAG_VAR, env)

    def test_isolated_child_keeps_template_variable(self):
        r = runner()
        with Patched():
            r.run_one(['--test', 'foo'], isolate=True)
        self.assertEqual(FakePopen.cargo()[0].kw['env'][pib.TEMPLATE_VAR], TPL)


class PerBinaryLogs(unittest.TestCase):
    """Review r1 M3: output goes to a per-binary file, tailed on failure."""

    def test_output_is_written_to_a_file_in_the_log_dir(self):
        d = scratch_dir()
        r = runner(log_dir=d)
        with Patched():
            r.run_one(['--test', 'foo_6383'], isolate=True)
        out = FakePopen.cargo()[0].kw['stdout']
        self.assertEqual(Path(out.name).parent, Path(d))
        self.assertEqual(Path(out.name).name, 'foo_6383.log')
        self.assertIn('test result: ok', (Path(d) / 'foo_6383.log').read_text())
        self.assertEqual(FakePopen.cargo()[0].kw.get('stderr'), subprocess.STDOUT)

    def test_failure_prints_a_group_with_the_log_tail(self):
        d = scratch_dir()
        r = runner(log_dir=d)
        printed = []
        with Patched(), mock.patch.object(pib, '_out', printed.append):
            FakePopen.cargo_rc = 101
            FakePopen.cargo_output = ''.join('line %d\n' % i for i in range(500)) + 'test result: FAILED.\n'
            rc = r.run_one(['--test', 'bad'], isolate=True)
        text = '\n'.join(printed)
        self.assertEqual(rc, 101)
        self.assertIn('::group::', text)
        self.assertIn('test result: FAILED.', text)
        self.assertIn('line 499', text)
        self.assertNotIn('line 100\n', text + '\n', 'only the tail is echoed')

    def test_success_prints_only_the_result_lines(self):
        r = runner()
        printed = []
        with Patched(), mock.patch.object(pib, '_out', printed.append):
            FakePopen.cargo_output = 'noise\ntest result: ok. 3 passed; 0 failed\n'
            r.run_one(['--test', 'good'], isolate=True)
        text = '\n'.join(printed)
        self.assertNotIn('::group::', text)
        self.assertNotIn('noise', text)
        self.assertIn('test result: ok. 3 passed', text)


class Pool(unittest.TestCase):
    def test_width_is_capped_at_eight(self):
        self.assertEqual(pib.clamp_jobs(100), 8)
        self.assertEqual(pib.clamp_jobs(3), 3)
        with self.assertRaises(pib.WrapperError):
            pib.clamp_jobs(0)

    def test_run_all_returns_worst_exit_code_and_runs_residual_after_pool(self):
        order = []
        r = runner()

        def fake_run_one(target, isolate=True):
            order.append((target[1], isolate))
            return 101 if target[1] == 'bad' else 0
        targets = [['--test', 'a'], ['--test', 'bad'], ['--test', 'res'], ['--test', 'b']]
        with mock.patch.object(r, 'run_one', fake_run_one):
            rc = r.run_all(targets, {'res'})
        self.assertEqual(rc, 101)
        self.assertEqual(sorted(n for n, _ in order), ['a', 'b', 'bad', 'res'])
        self.assertEqual(order[-1], ('res', False), 'residual runs last, on the shared database')

    def test_run_all_with_no_targets_fails_closed(self):
        with self.assertRaises(pib.WrapperError):
            runner().run_all([], set())


class Termination(unittest.TestCase):
    """Review r1 M2: SIGTERM stops dispatch, kills children, drops clones."""

    def test_terminate_stops_pool_kills_children_and_drops_clone(self):
        r = runner(width=1)
        targets = [['--test', 'b%d' % i] for i in range(4)]
        result = {}
        with Patched() as rec:
            FakePopen.block = threading.Event()
            started = threading.Event()
            real_init = FakePopen.__init__

            def init(self, argv, **kw):
                real_init(self, argv, **kw)
                if not self.is_hold:
                    started.set()
            killed = []

            def killpg(pgid, sig):
                killed.append((pgid, sig))
                for p in FakePopen.cargo():
                    p.returncode = -sig
                FakePopen.block.set()
            with mock.patch.object(FakePopen, '__init__', init), \
                    mock.patch.object(pib.os, 'killpg', killpg):
                t = threading.Thread(target=lambda: result.setdefault('rc', r.run_all(targets, {'b3'})))
                t.start()
                self.assertTrue(started.wait(10), 'the first child started')
                r.terminate()
                t.join(15)
        self.assertFalse(t.is_alive())
        self.assertEqual(result['rc'], pib.EXIT_TERM)
        self.assertEqual(len(FakePopen.cargo()), 1, 'no binary is dispatched after the stop')
        self.assertIn(signal.SIGTERM, [s for _, s in killed])
        creates = [s for s in rec.sql() if s.startswith('CREATE DATABASE')]
        drops = [s for s in rec.sql() if s.startswith('DROP DATABASE')]
        self.assertEqual(len(creates), 1)
        self.assertEqual(len(drops), 1, 'the running clone is dropped before exit')

    def test_main_installs_term_and_int_handlers_for_run(self):
        src = SCRIPT.read_text()
        self.assertTrue('signal.SIGTERM' in src, 'SIGTERM handler')
        self.assertTrue('signal.SIGINT' in src, 'SIGINT handler')
        self.assertFalse('sys.exit(143)' in src, 'a bare exit leaks children and clones')


class MainRun(unittest.TestCase):
    """Review r1 C1/L2: ``run`` parses --url and works end to end."""

    def write_targets(self, *names):
        d = scratch_dir()
        p = Path(d) / 'targets.txt'
        p.write_text(''.join('--test %s\n' % n for n in names))
        return d, p

    def test_run_help_lists_its_flags(self):
        done = subprocess.run([sys.executable, str(SCRIPT), 'run', '--help'], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        for flag in ('--url', '--run-id', '--template', '--log-dir', '--targets-file', '--jobs'):
            self.assertIn(flag, done.stdout)

    def test_main_run_with_url_flag_runs_and_returns_zero(self):
        d, targets = self.write_targets('one', 'two')
        env = {pib.FLAG_VAR: '1'}
        with Patched() as rec, mock.patch.dict(os.environ, env), \
                mock.patch.object(pib.signal, 'signal'):
            rc = pib.main(['run', '--url', BASE, '--run-id', RUN, '--template', TPL,
                           '--targets-file', str(targets), '--log-dir', d, '--jobs', '2',
                           '--', 'cargo', 'test', '--no-fail-fast'])
        self.assertEqual(rc, 0)
        self.assertEqual(len(FakePopen.cargo()), 2)
        self.assertEqual(len([s for s in rec.sql() if s.startswith('CREATE DATABASE')]), 2)
        self.assertEqual(len([s for s in rec.sql() if s.startswith('DROP DATABASE')]), 2)

    def test_run_is_refused_unless_opted_in(self):
        d, targets = self.write_targets('one')
        argv = ['run', '--url', BASE, '--run-id', RUN, '--template', TPL, '--targets-file', str(targets),
                '--log-dir', d, '--', 'cargo', 'test']
        for env in ({}, {pib.FLAG_VAR: '0'}, {pib.FLAG_VAR: '1', pib.KILL_VAR: '1'}):
            clean = {k: v for k, v in os.environ.items() if k not in (pib.FLAG_VAR, pib.KILL_VAR)}
            clean.update(env)
            with Patched(), mock.patch.dict(os.environ, clean, clear=True):
                self.assertEqual(pib.main(list(argv)), pib.EXIT_USAGE, env)
            self.assertEqual(FakePopen.cargo(), [], env)

    def test_run_requires_template_and_run_id(self):
        d, targets = self.write_targets('one')
        for missing in ('--template', '--run-id'):
            argv = ['run', '--url', BASE, '--run-id', RUN, '--template', TPL, '--targets-file',
                    str(targets), '--log-dir', d, '--', 'cargo', 'test']
            i = argv.index(missing)
            del argv[i:i + 2]
            clean = {k: v for k, v in os.environ.items() if k not in (pib.TEMPLATE_VAR, pib.RUN_ID_VAR)}
            clean[pib.FLAG_VAR] = '1'
            with Patched(), mock.patch.dict(os.environ, clean, clear=True):
                self.assertEqual(pib.main(argv), pib.EXIT_USAGE, missing)


class NoShell(unittest.TestCase):
    def test_source_never_uses_shell_true_or_tmp(self):
        src = SCRIPT.read_text()
        self.assertIsNone(re.search(r'shell\s*=\s*True', src))
        self.assertFalse('/tmp' in src, 'no /tmp paths')
        self.assertTrue(src.startswith('#!/usr/bin/env python3'))


def _live_url():
    return os.environ.get(pib.URL_VAR, '')


@unittest.skipUnless(_live_url() and shutil.which('psql'), 'AI_MEMORY_TEST_POSTGRES_URL unset (live e2e)')
class LiveEndToEnd(unittest.TestCase):
    """C1 end to end: the real script, a real server, a probe, /bin/true."""

    def test_setup_run_teardown_creates_and_drops_a_clone(self):
        url = _live_url()
        d = Path(scratch_dir())
        db = 'ai_memory_e2e_%s' % uuid.uuid4().hex[:8]
        run_id = 'e' + uuid.uuid4().hex[:10]
        probe = d / 'probe.py'
        probe.write_text(
            'import importlib.util, os, sys\n'
            'spec = importlib.util.spec_from_file_location("pib", %r)\n'
            'm = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n'
            'print("PROBE_DB=" + m.psql(os.environ[%r], "SELECT current_database()", tuples=True).strip())\n'
            'print("test result: ok. 1 passed; 0 failed")\n' % (str(SCRIPT), pib.URL_VAR))
        (d / 'targets.txt').write_text('--test e2e_probe\n--test e2e_true\n')
        env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
        env.update({pib.URL_VAR: url, pib.FLAG_VAR: '1'})
        env.pop(pib.KILL_VAR, None)
        setup = subprocess.run([sys.executable, str(SCRIPT), 'setup', '--db', db, '--jobs', '1',
                                '--run-id', run_id, '--emit-env'], env=env, capture_output=True, text=True)
        self.assertEqual(setup.returncode, 0, setup.stderr)
        emitted = dict(ln.split('=', 1) for ln in setup.stdout.split())
        self.assertEqual(emitted[pib.RUN_ID_VAR], run_id)
        env.update(emitted)
        try:
            probe_run = subprocess.run(
                [sys.executable, str(SCRIPT), 'run', '--targets-file', str(d / 'targets.txt'),
                 '--log-dir', str(d / 'logs'), '--jobs', '1', '--', sys.executable, str(probe)],
                env=env, capture_output=True, text=True, timeout=300)
            self.assertEqual(probe_run.returncode, 0, probe_run.stderr + probe_run.stdout)
            log = (d / 'logs' / 'e2e_probe.log').read_text()
            found = re.search(r'PROBE_DB=(\S+)', log)
            self.assertIsNotNone(found, log)
            clone = found.group(1)
            self.assertIsNotNone(pib.parse_isolated_name(clone, run_id), clone)
            true_run = subprocess.run(
                [sys.executable, str(SCRIPT), 'run', '--targets-file', str(d / 'targets.txt'),
                 '--log-dir', str(d / 'logs2'), '--jobs', '1', '--', '/bin/true'],
                env=env, capture_output=True, text=True, timeout=300)
            self.assertEqual(true_run.returncode, 0, true_run.stderr)
            self.assertIn('-> ai_memory_t_%s_' % run_id, true_run.stderr)
            left = pib.psql(url, "SELECT count(*) FROM pg_database WHERE starts_with(datname, '%s')"
                            % ('ai_memory_t_%s_' % run_id), tuples=True).strip()
            self.assertEqual(left, '0', 'every clone of the run was dropped')
        finally:
            down = subprocess.run([sys.executable, str(SCRIPT), 'teardown', '--db', db, '--run-id', run_id],
                                  env=env, capture_output=True, text=True)
            self.assertEqual(down.returncode, 0, down.stderr)
        tpl_left = pib.psql(url, "SELECT count(*) FROM pg_database WHERE datname = '%s_tpl'" % db,
                            tuples=True).strip()
        self.assertEqual(tpl_left, '0', 'teardown dropped the template')


if __name__ == '__main__':
    unittest.main()
