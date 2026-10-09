#!/usr/bin/env python3
"""Unit tests for scripts/test/pg_isolated_binary.py (#6383 / #6386).

Run: python3 -m unittest scripts/ci/tests/test_pg_isolated_binary.py

No live Postgres and no real cargo: ``subprocess.run`` is replaced by a
recorder, so every assertion is about the exact argument lists, the order of
the SQL and the exit codes.
"""
import importlib.util
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    'pg_isolated_binary', REPO / 'scripts' / 'test' / 'pg_isolated_binary.py')
pib = importlib.util.module_from_spec(SPEC)
sys.modules['pg_isolated_binary'] = pib
SPEC.loader.exec_module(pib)

BASE = 'postgres://u:pw@127.0.0.1:5445/ai_memory_test_ci_9_1_x?sslmode=verify-full&sslrootcert=/c/ca.crt'
TPL = 'ai_memory_test_ci_9_1_x_tpl'


class Result:
    def __init__(self, rc=0, out='', err=''):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


class Recorder:
    """subprocess.run stand-in: records calls, answers from a script."""

    def __init__(self, answer=None):
        self.calls = []
        self.answer = answer or (lambda argv, kw: Result())

    def __call__(self, argv, **kw):
        assert isinstance(argv, list), 'argument list, never a shell string'
        assert not kw.get('shell'), 'shell=True is forbidden'
        self.calls.append((list(argv), kw))
        return self.answer(list(argv), kw)

    def sql(self):
        return [a[a.index('-c') + 1] for a, _ in self.calls if '-c' in a]


class NameAndUrl(unittest.TestCase):
    def test_database_name_ignores_query(self):
        self.assertEqual(pib.database_name(BASE), 'ai_memory_test_ci_9_1_x')

    def test_with_database_preserves_tls_query(self):
        out = pib.with_database(BASE, 'ai_memory_t_1700000000_0123abcd')
        self.assertEqual(
            out,
            'postgres://u:pw@127.0.0.1:5445/ai_memory_t_1700000000_0123abcd'
            '?sslmode=verify-full&sslrootcert=/c/ca.crt')

    def test_with_database_without_query(self):
        self.assertEqual(pib.with_database('postgres://u:p@h:1/db', 'x'), 'postgres://u:p@h:1/x')

    def test_minted_name_shape_and_sweep_recognition(self):
        name = pib.isolated_db_name(1700000000)
        self.assertRegex(name, r'^ai_memory_t_[0-9]{10}_[0-9a-f]{8}$')
        self.assertLessEqual(len(name), 63)
        self.assertEqual(pib.parse_isolated_name(name), 1700000000)
        for bad in ('ai_memory_t_1700000000_0123ABCD', 'ai_memory_t_17_0123abcd',
                    'ai_memory_test_ci_9_1_x', 'ai_memory_t_', 'x_ai_memory_t_1700000000_0123abcd'):
            self.assertIsNone(pib.parse_isolated_name(bad), bad)

    def test_quote_ident_doubles_quotes(self):
        self.assertEqual(pib.quote_ident('a"b'), '"a""b"')

    def test_safe_target_selector_rejects_shell_metacharacters(self):
        self.assertEqual(pib.parse_target_line('--test foo_bar-1'), ['--test', 'foo_bar-1'])
        self.assertEqual(pib.parse_target_line('--bin ai-memory'), ['--bin', 'ai-memory'])
        for bad in ('--test a;b', '--test $(x)', '--test', '--weird x', '--test a b', ''):
            with self.assertRaises(pib.WrapperError, msg=bad):
                pib.parse_target_line(bad)


class MintAndDrop(unittest.TestCase):
    def test_mint_issues_create_database_template(self):
        rec = Recorder()
        with mock.patch.object(pib.subprocess, 'run', rec):
            url, name = pib.mint(BASE, TPL, now=1700000000)
        self.assertEqual(pib.database_name(url), name)
        self.assertIn('sslmode=verify-full', url)
        sql = rec.sql()
        self.assertEqual(len(sql), 1)
        self.assertEqual(sql[0], 'CREATE DATABASE "%s" TEMPLATE "%s"' % (name, TPL))
        self.assertEqual(rec.calls[0][0][0], 'psql')
        self.assertIn('ON_ERROR_STOP=1', rec.calls[0][0])

    def test_mint_retries_on_template_in_use_then_succeeds(self):
        state = {'n': 0}

        def answer(argv, kw):
            state['n'] += 1
            if state['n'] < 3:
                return Result(1, '', 'ERROR:  source database "t" is being accessed by other users')
            return Result()
        rec = Recorder(answer)
        with mock.patch.object(pib.subprocess, 'run', rec), mock.patch.object(pib.time, 'sleep'):
            pib.mint(BASE, TPL, now=1700000000)
        self.assertEqual(state['n'], 3)

    def test_mint_gives_up_after_three_attempts(self):
        rec = Recorder(lambda a, k: Result(1, '', 'source database is being accessed by other users'))
        with mock.patch.object(pib.subprocess, 'run', rec), mock.patch.object(pib.time, 'sleep'):
            with self.assertRaises(pib.WrapperError):
                pib.mint(BASE, TPL, now=1700000000)
        self.assertEqual(len(rec.calls), 3)

    def test_mint_does_not_retry_other_errors(self):
        rec = Recorder(lambda a, k: Result(1, '', 'ERROR: permission denied to create database'))
        with mock.patch.object(pib.subprocess, 'run', rec):
            with self.assertRaises(pib.WrapperError):
                pib.mint(BASE, TPL, now=1700000000)
        self.assertEqual(len(rec.calls), 1)

    def test_drop_uses_force_and_quotes(self):
        rec = Recorder()
        with mock.patch.object(pib.subprocess, 'run', rec):
            pib.drop(BASE, 'ai_memory_t_1700000000_0123abcd')
        self.assertEqual(rec.sql(), ['DROP DATABASE IF EXISTS "ai_memory_t_1700000000_0123abcd" WITH (FORCE)'])

    def test_drop_refuses_a_non_isolated_name(self):
        rec = Recorder()
        with mock.patch.object(pib.subprocess, 'run', rec):
            with self.assertRaises(pib.WrapperError):
                pib.drop(BASE, 'ai_memory_test_ci_9_1_x')
        self.assertEqual(rec.calls, [])


class RunOne(unittest.TestCase):
    def test_runs_cargo_per_binary_with_minted_env_and_drops(self):
        seen = {}

        def answer(argv, kw):
            if argv[0] == 'cargo':
                seen['argv'] = argv
                seen['env'] = kw['env']
            return Result()
        rec = Recorder(answer)
        env = {'AI_MEMORY_TEST_POSTGRES_URL': BASE, 'AI_MEMORY_TEST_AGE_URL': BASE, 'KEEP': '1'}
        with mock.patch.object(pib.subprocess, 'run', rec):
            rc = pib.run_one(['--test', 'foo_6383'], ['cargo', 'test', '--no-fail-fast', '--features', 'sal-postgres'],
                             ['--test-threads=1'], env, TPL)
        self.assertEqual(rc, 0)
        self.assertEqual(seen['argv'], ['cargo', 'test', '--no-fail-fast', '--features', 'sal-postgres',
                                        '--test', 'foo_6383', '--', '--test-threads=1'])
        minted = pib.database_name(seen['env']['AI_MEMORY_TEST_POSTGRES_URL'])
        self.assertRegex(minted, r'^ai_memory_t_[0-9]{10}_[0-9a-f]{8}$')
        self.assertEqual(pib.database_name(seen['env']['AI_MEMORY_TEST_AGE_URL']), minted)
        self.assertEqual(seen['env']['KEEP'], '1')
        # parent env untouched; the DB was dropped last.
        self.assertEqual(env['AI_MEMORY_TEST_POSTGRES_URL'], BASE)
        self.assertTrue(rec.sql()[0].startswith('CREATE DATABASE'))
        self.assertTrue(rec.sql()[-1].startswith('DROP DATABASE IF EXISTS'))

    def test_failing_binary_exit_code_is_propagated_and_db_still_dropped(self):
        rec = Recorder(lambda a, k: Result(101) if a[0] == 'cargo' else Result())
        env = {'AI_MEMORY_TEST_POSTGRES_URL': BASE}
        with mock.patch.object(pib.subprocess, 'run', rec):
            rc = pib.run_one(['--test', 'foo'], ['cargo', 'test', '--no-fail-fast'], [], env, TPL)
        self.assertEqual(rc, 101)
        self.assertTrue(rec.sql()[-1].startswith('DROP DATABASE'))

    def test_mint_failure_fails_closed_without_running_cargo(self):
        rec = Recorder(lambda a, k: Result(1, '', 'ERROR: boom'))
        env = {'AI_MEMORY_TEST_POSTGRES_URL': BASE}
        with mock.patch.object(pib.subprocess, 'run', rec):
            rc = pib.run_one(['--test', 'foo'], ['cargo', 'test', '--no-fail-fast'], [], env, TPL)
        self.assertNotEqual(rc, 0)
        self.assertFalse([c for c, _ in rec.calls if c[0] == 'cargo'])

    def test_residual_target_runs_on_the_shared_database_without_minting(self):
        rec = Recorder()
        env = {'AI_MEMORY_TEST_POSTGRES_URL': BASE}
        with mock.patch.object(pib.subprocess, 'run', rec):
            rc = pib.run_one(['--test', 'a2a_campaign_round1'], ['cargo', 'test', '--no-fail-fast'],
                             ['--test-threads=1'], env, TPL, isolate=False)
        self.assertEqual(rc, 0)
        self.assertEqual([c[0] for c, _ in rec.calls], ['cargo'])
        self.assertEqual(rec.calls[0][1]['env']['AI_MEMORY_TEST_POSTGRES_URL'], BASE)


class Pool(unittest.TestCase):
    def test_width_is_capped_at_eight(self):
        self.assertEqual(pib.clamp_jobs(100), 8)
        self.assertEqual(pib.clamp_jobs(3), 3)
        with self.assertRaises(pib.WrapperError):
            pib.clamp_jobs(0)

    def test_run_all_returns_worst_exit_code_and_runs_residual_after_pool(self):
        order = []

        def fake_run_one(target, cargo, test_args, env, tpl, isolate=True):
            order.append((target[1], isolate))
            return 101 if target[1] == 'bad' else 0
        targets = [['--test', 'a'], ['--test', 'bad'], ['--test', 'res'], ['--test', 'b']]
        with mock.patch.object(pib, 'run_one', fake_run_one):
            rc = pib.run_all(targets, {'res'}, ['cargo', 'test'], [], {}, TPL, jobs=2)
        self.assertEqual(rc, 101)
        self.assertEqual(sorted(n for n, _ in order), ['a', 'b', 'bad', 'res'])
        self.assertEqual(order[-1], ('res', False), 'residual runs last, on the shared database')
        self.assertTrue(all(iso for n, iso in order if n != 'res'))

    def test_run_all_with_no_targets_fails_closed(self):
        with self.assertRaises(pib.WrapperError):
            pib.run_all([], set(), ['cargo', 'test'], [], {}, TPL, jobs=2)


class TierSteps(unittest.TestCase):
    def test_setup_creates_template_installs_extensions_then_locks_it(self):
        rec = Recorder(lambda a, k: Result(0, '1000\n' if 'max_connections' in ' '.join(a) else ''))
        with mock.patch.object(pib.subprocess, 'run', rec):
            pib.setup(BASE, 'ai_memory_test_ci_9_1_x')
        sql = rec.sql()
        joined = '\n'.join(sql)
        self.assertIn('CREATE DATABASE "ai_memory_test_ci_9_1_x_tpl"', joined)
        ext = [i for i, s in enumerate(sql) if 'CREATE EXTENSION IF NOT EXISTS age' in s]
        lock = [i for i, s in enumerate(sql) if 'IS_TEMPLATE true ALLOW_CONNECTIONS false' in s]
        self.assertTrue(ext and lock and ext[0] < lock[0], 'extensions before the template is locked')
        # the extension install connects to the template DB itself
        ext_call = [a for a, _ in rec.calls if any('CREATE EXTENSION' in x for x in a)][0]
        self.assertTrue(any('ai_memory_test_ci_9_1_x_tpl' in x for x in ext_call))

    def test_setup_fails_closed_when_max_connections_too_low(self):
        rec = Recorder(lambda a, k: Result(0, '100\n') if any('max_connections' in x for x in a) else Result())
        with mock.patch.object(pib.subprocess, 'run', rec):
            with self.assertRaises(pib.WrapperError) as ctx:
                pib.setup(BASE, 'ai_memory_test_ci_9_1_x')
        self.assertIn('max_connections', str(ctx.exception))
        self.assertFalse([s for s in rec.sql() if s.startswith('CREATE DATABASE')],
                         'nothing is created when the budget check fails')

    def test_required_connections_formula(self):
        self.assertEqual(pib.required_connections(8), 8 * 18 + 20)

    def test_sweep_only_touches_idle_stale_isolated_and_old_ci_databases(self):
        rec = Recorder(lambda a, k: Result(0, ''))
        with mock.patch.object(pib.subprocess, 'run', rec):
            pib.sweep(BASE, 'ai_memory_test_ci_9_1_x')
        text = '\n'.join(rec.sql())
        self.assertIn('ai_memory_t_', text)
        self.assertIn('600', text)
        self.assertIn('pg_stat_activity', text, 'a database with live sessions is never swept')
        self.assertIn('ai_memory_test_ci_', text)
        self.assertIn("interval '1 day'", text)
        self.assertIn('ai_memory_test_ci_9_1_x', text, 'the running job database is excluded by name')

    def test_teardown_unmarks_template_before_drop_and_drops_clones(self):
        def answer(argv, kw):
            if '-At' in argv:
                return Result(0, 'ai_memory_t_1700000000_0123abcd\n')
            return Result()
        rec = Recorder(answer)
        with mock.patch.object(pib.subprocess, 'run', rec):
            pib.teardown(BASE, 'ai_memory_test_ci_9_1_x')
        sql = rec.sql()
        unmark = [i for i, s in enumerate(sql) if 'IS_TEMPLATE false' in s]
        drop_tpl = [i for i, s in enumerate(sql) if 'DROP DATABASE IF EXISTS "ai_memory_test_ci_9_1_x_tpl"' in s]
        self.assertTrue(unmark and drop_tpl and unmark[0] < drop_tpl[0])
        self.assertTrue(any('DROP DATABASE IF EXISTS "ai_memory_t_1700000000_0123abcd"' in s for s in sql))


class NoShell(unittest.TestCase):
    def test_source_never_uses_shell_true_or_tmp(self):
        src = (REPO / 'scripts' / 'test' / 'pg_isolated_binary.py').read_text()
        self.assertIsNone(re.search(r'shell\s*=\s*True', src))
        self.assertNotIn('/tmp', src)
        self.assertTrue(src.startswith('#!/usr/bin/env python3'))


if __name__ == '__main__':
    unittest.main()
