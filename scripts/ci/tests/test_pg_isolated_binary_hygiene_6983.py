#!/usr/bin/env python3
"""Base hygiene and ownership invariants of scripts/test/pg_isolated_binary.py (#6983, #7031 campaign H).

Run: python3 -m unittest scripts/ci/tests/test_pg_isolated_binary_hygiene_6983.py

I1 (H1)  ``setup`` builds a template only beside an ephemeral CI base (``ai_memory_test_ci_<run>_<attempt>_<leg>``)
         unless the caller passes ``--allow-shared-base "<reason>"``; every unclassifiable name is refused (exit 2,
         exact message). No base is ever minted (b29 ruling bc49233a): ``ci_base_<pid>_<ts>`` is refused too.
I2 (H2)  ``setup`` refuses a base whose ``lineage_integrity_watermark.high_water`` is above ``count(agent_lineage)``
         with the #6983 diagnostic; a row it cannot parse is a refusal, never a pass.
I3       only names this run created (a successful CREATE) are dropped; never ``WITH (FORCE)``.
I4       an exit that leaves an owned name behind is non-zero, names it and differs from the usage exit; every
         signal and every exception type keeps I3 and I4.

Offline cells replace ``subprocess.run`` with a small stateful server (``HygienePg``) and drive ``main`` with exact
argv, so every assertion is an exact exit code plus the exact ``pg_isolated_binary:`` stderr lines. ``LiveHygiene``
runs the real script against the Postgres named by ``AI_MEMORY_TEST_POSTGRES_URL`` and skips when it is unset.
"""
import ast
import contextlib
import importlib.util
import io
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest.mock
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / 'scripts' / 'test' / 'pg_isolated_binary.py'
SPEC = importlib.util.spec_from_file_location('pg_isolated_binary_hygiene', SCRIPT)
pib = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pib)

SCRATCH = REPO / '.local-runs' / 'pg-isolate-hygiene'
PREFIX = 'pg_isolated_binary: '
QUERY = '?sslmode=verify-full&sslrootcert=/c/ca.crt'
ADMIN_DB = 'ai_memory_test'                       # the URL default of the CI admin URL, and the poisoned base
ADMIN_URL = 'postgres://u:pw@127.0.0.1:5445/%s%s' % (ADMIN_DB, QUERY)
EPHEMERAL = 'ai_memory_test_ci_9_1_x'
EPHEMERAL_TPL = EPHEMERAL + '_tpl'
RUN = 'r7031'

# --- the contract this file pins (exit codes and exact messages) ------------------------------------------------
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_MINT = 3
EXIT_LOAD_REFUSED = 4
EXIT_UNRELEASED = 5
SIGNAL_EXIT_BASE = 128
ALLOW_SHARED_FLAG = '--allow-shared-base'
SHARED_REASON_MAX = 200
WATERMARK_MAX_ROWS = 64
HIGH_WATER_MAX_DIGITS = 19
EMITTED_VARS = ['RUN_ID_VAR', 'TEMPLATE_VAR']       # the only names --emit-env writes (#7153)

REFUSE_BASE = ('refusing base database %r: only an ephemeral CI base (ai_memory_test_ci_<run>_<attempt>_<leg>) may '
               'back a template; pass --allow-shared-base "<reason>" to use a shared base on purpose')
UNSAFE_NAME = 'unsafe database name %r'
REASON_REFUSED = ('refusing --allow-shared-base: the reason must be 1 to %d printable characters that say why a '
                  'shared base is safe here' % SHARED_REASON_MAX)
REGRESSED = ('refusing base database %r: the append-only relation `%s.agent_lineage` REGRESSED from a '
             'previously-recorded high-water mark of %d row(s) to %d; a template built beside it would run the '
             'suite on a poisoned base (#6983)')
UNREADABLE_ROW = ('refusing base database %r: lineage_integrity_watermark in schema %s has a row the precheck '
                  'cannot read (%s): %r')
ROW_FIELDS = 'not two fields'
ROW_RELATION = 'relation is not agent_lineage'
ROW_HIGH_WATER = 'high_water is not a non-negative integer of at most %d digits' % HIGH_WATER_MAX_DIGITS
TOO_MANY_ROWS = 'refusing base database %r: lineage_integrity_watermark in schema %s has more than %d rows'
COUNT_UNREADABLE = 'refusing base database %r: count(*) of %s.agent_lineage is not an integer (%r)'
PRECHECK_FAILED = 'refusing base database %r: the lineage precheck could not read it: %s'
BAD_SCHEMA = 'refusing base database %r: lineage_integrity_watermark sits in a schema with an unsafe name %r'
TEARDOWN_MISMATCH = "refusing teardown --db %r: its template %r is not %s=%r, the template this job's setup emitted"
UNRELEASED = ('unreleased: database %s of this run is still on the server: %s; drop it with a plain DROP DATABASE '
              'once no session holds it')
MAYBE = ("unreleased: database %s may exist with no owner record (the CREATE ended without a clean answer); check "
         "with `SELECT 1 FROM pg_database WHERE datname = '%s'` and drop it with a plain DROP DATABASE if this run "
         "made it")
INTERRUPTED = 'interrupted by signal %d (%s)'


def unexpected(exc):
    text = str(exc)
    return 'unexpected %s%s' % (type(exc).__name__, (': %s' % text) if text else '')


def line(msg):
    return pib.wa.log_line(PREFIX + msg)


# --- corpora -----------------------------------------------------------------------------------------------------
BASES_ALLOWED = (
    EPHEMERAL,
    'ai_memory_test_ci_12345678901_2_enterprise_fed_shard_1',
    'ai_memory_test_ci_1_99999_leg__x__',
    'ai_memory_test_ci_9_1_0',
)
BASES_REFUSED = (                                    # classifiable as an identifier, not as an ephemeral base
    ADMIN_DB,
    'ci_base_4242_1700000000',                       # the minted default of the H1 text: no mint (b29 bc49233a)
    'ai_memory_test_ci',
    'ai_memory_test_ci_9',
    'ai_memory_test_ci_9_1',
    'ai_memory_test_ci_9_1_',
    'ai_memory_test_ci__1_x',
    'ai_memory_test_ci_9__x',
    'ai_memory_test_ci_x_1_leg',
    'ai_memory_test_ci_9_x_leg',
    'ai_memory_test_ci_9_1_X',
    'AI_MEMORY_TEST_CI_9_1_X',
    'xai_memory_test_ci_9_1_x',
    'ai_memory_test_ci_' + '1' * 21 + '_1_x',
    'ai_memory_test_ci_9_123456_x',
    'ai_memory_test_ci_9_1_' + 'a' * 37,             # leg over the 36-byte room a 59-byte base leaves
    'ai_memory_t_r1_1700000000_0123abcd',            # a clone name
    'template1',
    'postgres',
)
BASES_HOSTILE = (                                    # not even a safe identifier
    EPHEMERAL + ';drop',
    EPHEMERAL + '"',
    EPHEMERAL + '\n',
    ' ' + EPHEMERAL,
    'ai_memory_test_ci_٩_1_x',
    'a' * 64,
)
EXCEPTIONS = (KeyboardInterrupt(), ValueError('v7114'), RuntimeError('r7114'), OSError(5, 'io7114'),
              MemoryError(), SystemExit(3), pib.WrapperError('w7114'))
SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


# --- a small stateful server behind psql -------------------------------------------------------------------------
class Result:
    def __init__(self, rc=0, out='', err=''):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


class HygienePg:
    """Databases, sessions, the watermark precheck, the teardown and sweep listings. ``hooks`` maps a SQL prefix to
    a callable run before the statement (raise, send a signal); ``fail`` maps a SQL prefix to an rc-1 error text;
    ``lost`` maps a prefix to a status the statement returns after it committed."""

    def __init__(self, dbs=None, watermark=None, fail=None, hooks=None, lost=None, clock=None):
        self.dbs = {k: dict(v) for k, v in (dbs or {}).items()}
        self.watermark = dict(watermark or {})      # schema -> (rows text, count text)
        self.fail = dict(fail or {})
        self.hooks = dict(hooks or {})
        self.lost = dict(lost or {})
        self.clock = clock
        self.log = []
        self.envs = []

    def __call__(self, argv, **kw):
        assert isinstance(argv, list) and not kw.get('shell')
        sql = argv[-1] if '-c' in argv else ''
        if 'max_connections' in sql:
            return Result(0, '1000|3|0|10\n')
        self.log.append(sql)
        self.envs.append((sql, dict(kw.get('env') or {})))
        for prefix, hook in self.hooks.items():
            if sql.startswith(prefix):
                hook(sql)
        for prefix, text in self.fail.items():
            if sql.startswith(prefix):
                return Result(1, '', text)
        answer = self._answer(sql)
        for prefix, status in self.lost.items():
            if sql.startswith(prefix):
                return Result(status, '', 'psql: error: connection to server was lost')
        return answer

    def _answer(self, sql):
        if 'pg_catalog.pg_class' in sql and 'lineage_integrity_watermark' in sql:
            return Result(0, ''.join(s + '\n' for s in sorted(self.watermark)))
        rows = re.search(r'FROM "([^"]+)"\.lineage_integrity_watermark', sql)
        if rows:
            return Result(0, self.watermark[rows.group(1)][0])
        count = re.search(r'FROM "([^"]+)"\."agent_lineage"', sql)
        if count and 'count(*)' in sql:
            return Result(0, self.watermark[count.group(1)][1] + '\n')
        if 'extract(epoch' in sql:
            return Result(0, '%d\n' % self.clock)
        if 'NOT EXISTS (SELECT 1 FROM pg_stat_activity' in sql:
            return Result(0, ''.join(n + '\n' for n in sorted(self.dbs) if not self.dbs[n].get('listed_busy')
                                     and n.startswith('ai_memory_t_')))
        listing = re.search(r"starts_with\(datname, '([^']+)'\)", sql)
        if listing:
            return Result(0, ''.join(n + '\n' for n in sorted(self.dbs) if n.startswith(listing.group(1))))
        probe = re.match(r"SELECT 1 FROM pg_database WHERE datname = '([^']+)'$", sql)
        if probe:
            return Result(0, '1\n' if probe.group(1) in self.dbs else '')
        found = re.search(r'DATABASE (?:IF EXISTS )?"([^"]+)"', sql)
        name = found.group(1) if found else None
        if sql.startswith('CREATE DATABASE'):
            if name in self.dbs:
                return Result(1, '', 'ERROR:  database "%s" already exists' % name)
            self.dbs[name] = {'sessions': 0}
        elif sql.startswith('ALTER DATABASE') and name not in self.dbs:
            return Result(1, '', 'ERROR:  database "%s" does not exist' % name)
        elif sql.startswith('DROP DATABASE'):
            db = self.dbs.get(name)
            if db and db.get('sessions'):
                return Result(1, '', 'ERROR:  database "%s" is being accessed by other users' % name)
            if db and db.get('drop_fail'):
                return Result(1, '', db['drop_fail'])
            self.dbs.pop(name, None)
        return Result()

    def drops(self, name):
        return [s for s in self.log if s.startswith('DROP DATABASE') and '"%s"' % name in s]


class Outcome:
    def __init__(self, rc, emitted, stderr, escaped):
        self.rc = rc
        self.emitted = emitted
        self.stderr = stderr
        self.escaped = escaped

    @property
    def lines(self):
        return [ln for ln in self.stderr.splitlines() if ln.startswith(PREFIX)]


def run_main(argv, pg, env=None):
    """``main(argv)`` against ``pg``; the env vars the wrapper reads are cleared unless ``env`` names them."""
    emitted, err, escaped, rc = [], io.StringIO(), None, None
    with unittest.mock.patch.object(pib.subprocess, 'run', pg), \
            unittest.mock.patch.object(pib.time, 'sleep'), \
            unittest.mock.patch.object(pib, '_emit', emitted.append), \
            unittest.mock.patch.dict(os.environ, env or {}), \
            contextlib.redirect_stderr(err):
        for var in (pib.URL_VAR, pib.TEMPLATE_VAR, pib.RUN_ID_VAR):
            if var not in (env or {}):
                os.environ.pop(var, None)
        try:
            rc = pib.main(argv)
        except BaseException as exc:                 # an escape is itself the defect under test
            escaped = exc
    return Outcome(rc, emitted, err.getvalue(), escaped)


def setup_argv(db=None, *extra, url=ADMIN_URL):
    argv = ['setup', '--url', url, '--jobs', '1', '--run-id', RUN]
    if db is not None:
        argv += ['--db', db]
    return argv + list(extra)


class Base(unittest.TestCase):
    def assertOutcome(self, got, rc, lines):
        self.assertIsNone(got.escaped, 'an exception escaped main: %r' % (got.escaped,))
        self.assertEqual(got.rc, rc, got.stderr[-2000:])
        self.assertEqual(got.lines, [line(m) for m in lines])
        self.assertNotIn('Traceback', got.stderr)
        self.assertNotIn(':pw@', got.stderr)

    def assertNoForce(self, pg):
        self.assertFalse([s for s in pg.log if 'FORCE' in s.upper()])


# --- I1: the base classification --------------------------------------------------------------------------------
class BaseClassI1(Base):
    def test_base_name_corpus_is_classified_7031(self):
        for db in BASES_ALLOWED:
            with self.subTest(allowed=db):
                pg = HygienePg()
                got = run_main(setup_argv(db), pg)
                self.assertOutcome(got, EXIT_OK, [])
                self.assertIn(db + '_tpl', pg.dbs)
        for db in BASES_REFUSED:
            with self.subTest(refused=db):
                pg = HygienePg()
                got = run_main(setup_argv(db), pg)
                self.assertOutcome(got, EXIT_USAGE, [REFUSE_BASE % db])
                self.assertEqual(pg.log, [], 'a refused base is refused before any SQL')
        for db in BASES_HOSTILE:
            with self.subTest(hostile=db):
                pg = HygienePg()
                got = run_main(setup_argv(db), pg)
                self.assertOutcome(got, EXIT_USAGE, [UNSAFE_NAME % db])
                self.assertEqual(pg.log, [])

    def test_url_default_base_is_refused_7031(self):
        pg = HygienePg()
        got = run_main(setup_argv(None), pg)
        self.assertOutcome(got, EXIT_USAGE, [REFUSE_BASE % ADMIN_DB])
        self.assertEqual(pg.log, [])

    def test_no_mint_ci_base_is_never_created_7031(self):
        pg = HygienePg()
        got = run_main(setup_argv('ci_base_%d_%d' % (os.getpid(), 1700000000)), pg)
        self.assertEqual(got.rc, EXIT_USAGE)
        self.assertFalse([s for s in pg.log if 'ci_base_' in s])

    def test_setup_function_refuses_a_shared_base_itself_7031(self):
        pg = HygienePg()
        with unittest.mock.patch.object(pib.subprocess, 'run', pg):
            with self.assertRaises(pib.WrapperError) as ctx:
                pib.setup(ADMIN_URL, ADMIN_DB, 1)
        self.assertEqual(str(ctx.exception), REFUSE_BASE % ADMIN_DB)
        self.assertEqual(pg.log, [])

    def test_allow_shared_base_with_a_reason_is_used_and_logged_7031(self):
        pg = HygienePg()
        got = run_main(setup_argv(ADMIN_DB, ALLOW_SHARED_FLAG, 'ops rebuild of the shared base'), pg)
        self.assertOutcome(got, EXIT_OK, [])
        self.assertIn(ADMIN_DB + '_tpl', pg.dbs)
        self.assertIn('shared base %r allowed: ops rebuild of the shared base' % ADMIN_DB, got.stderr)

    def test_allow_shared_base_refuses_an_empty_or_bad_reason_7031(self):
        for reason in ('', '   ', 'x' * (SHARED_REASON_MAX + 1), 'bell\x07', 'two\nlines'):
            with self.subTest(reason=reason[:20]):
                pg = HygienePg()
                got = run_main(setup_argv(ADMIN_DB, ALLOW_SHARED_FLAG, reason), pg)
                self.assertOutcome(got, EXIT_USAGE, [REASON_REFUSED])
                self.assertEqual(pg.log, [])

    def test_teardown_without_db_is_refused_7180(self):
        pg = HygienePg(dbs={ADMIN_DB + '_tpl': {}})
        got = run_main(['teardown', '--url', ADMIN_URL, '--run-id', RUN], pg)
        self.assertOutcome(got, EXIT_USAGE, [REFUSE_BASE % ADMIN_DB])
        self.assertEqual(pg.log, [])
        self.assertIn(ADMIN_DB + '_tpl', pg.dbs)

    def test_teardown_db_disagreeing_with_the_emitted_template_is_refused_7180(self):
        pg = HygienePg(dbs={EPHEMERAL_TPL: {}})
        other = 'ai_memory_test_ci_9_1_y_tpl'
        got = run_main(['teardown', '--url', ADMIN_URL, '--db', EPHEMERAL, '--run-id', RUN], pg,
                       env={pib.TEMPLATE_VAR: other})
        self.assertOutcome(got, EXIT_USAGE, [TEARDOWN_MISMATCH % (EPHEMERAL, EPHEMERAL_TPL, pib.TEMPLATE_VAR, other)])
        self.assertEqual(pg.log, [])
        agreed = run_main(['teardown', '--url', ADMIN_URL, '--db', EPHEMERAL, '--run-id', RUN], pg,
                          env={pib.TEMPLATE_VAR: EPHEMERAL_TPL})
        self.assertOutcome(agreed, EXIT_OK, [])
        self.assertNotIn(EPHEMERAL_TPL, pg.dbs)

    def test_classification_is_linear_on_a_100k_name_7031(self):
        started = time.monotonic()
        for name in ('ai_memory_test_ci_' + '1' * 100_000, 'ai_memory_test_ci_9_1_' + '_' * 100_000):
            pg = HygienePg()
            got = run_main(setup_argv(name), pg)
            self.assertEqual(got.rc, EXIT_USAGE)
            self.assertEqual(pg.log, [])
        self.assertLess(time.monotonic() - started, 2.0)


# --- I2: the lineage watermark precheck -------------------------------------------------------------------------
class LineagePrecheckI2(Base):
    def run_precheck(self, watermark, fail=None):
        pg = HygienePg(watermark=watermark, fail=fail)
        return pg, run_main(setup_argv(EPHEMERAL), pg)

    def test_watermark_rows_table_6983_7157(self):
        rows = (                                                        # (watermark, expected refusal or None)
            ({}, None),
            ({'public': ('agent_lineage|3\n', '3')}, None),
            ({'public': ('agent_lineage|2\n', '5')}, None),            # a mark below the count advances: intact
            ({'public': ('', '0')}, None),
            ({'public': ('agent_lineage|5\n', '2')}, REGRESSED % (EPHEMERAL, 'public', 5, 2)),
            ({'public': ('agent_lineage|1\n', '0')}, REGRESSED % (EPHEMERAL, 'public', 1, 0)),
            ({'public': ('agent_lineage|NULL\n', '0')},
             UNREADABLE_ROW % (EPHEMERAL, 'public', ROW_HIGH_WATER, 'agent_lineage|NULL')),
            ({'public': ('agent_lineage|-1\n', '0')},
             UNREADABLE_ROW % (EPHEMERAL, 'public', ROW_HIGH_WATER, 'agent_lineage|-1')),
            ({'public': ('agent_lineage|1.5\n', '9')},
             UNREADABLE_ROW % (EPHEMERAL, 'public', ROW_HIGH_WATER, 'agent_lineage|1.5')),
            ({'public': ('agent_lineage|\n', '9')},
             UNREADABLE_ROW % (EPHEMERAL, 'public', ROW_HIGH_WATER, 'agent_lineage|')),
            ({'public': ('agent_lineage|1e3\n', '9')},
             UNREADABLE_ROW % (EPHEMERAL, 'public', ROW_HIGH_WATER, 'agent_lineage|1e3')),
            ({'public': ('agent_lineage|٣\n', '9')},
             UNREADABLE_ROW % (EPHEMERAL, 'public', ROW_HIGH_WATER, 'agent_lineage|٣')),
            ({'public': ('agent_lineage|' + '9' * 20 + '\n', '9')},
             UNREADABLE_ROW % (EPHEMERAL, 'public', ROW_HIGH_WATER, 'agent_lineage|' + '9' * 20)),
            ({'public': ('agent_lineage\n', '9')},
             UNREADABLE_ROW % (EPHEMERAL, 'public', ROW_FIELDS, 'agent_lineage')),
            ({'public': ('agent_lineage|3|x\n', '9')},
             UNREADABLE_ROW % (EPHEMERAL, 'public', ROW_FIELDS, 'agent_lineage|3|x')),
            ({'public': ('agent lineage|3\n', '9')},
             UNREADABLE_ROW % (EPHEMERAL, 'public', ROW_RELATION, 'agent lineage|3')),
            ({'public': ('|3\n', '9')}, UNREADABLE_ROW % (EPHEMERAL, 'public', ROW_RELATION, '|3')),
            ({'public': ('Agent_Lineage|3\n', '9')},
             UNREADABLE_ROW % (EPHEMERAL, 'public', ROW_RELATION, 'Agent_Lineage|3')),
            ({'public': ('memories|3\n', '9')}, UNREADABLE_ROW % (EPHEMERAL, 'public', ROW_RELATION, 'memories|3')),
            ({'public': ('agent_lineage|3\n', 'x')}, COUNT_UNREADABLE % (EPHEMERAL, 'public', 'x')),
            ({'public': ('agent_lineage|3\n', '')}, COUNT_UNREADABLE % (EPHEMERAL, 'public', '')),
            ({'public': ('agent_lineage|3\n', '3'), 's2': ('agent_lineage|9\n', '4')},
             REGRESSED % (EPHEMERAL, 's2', 9, 4)),
            ({'bad;schema': ('agent_lineage|3\n', '3')}, BAD_SCHEMA % (EPHEMERAL, 'bad;schema')),
            ({'public': ('agent_lineage|1\n' * (WATERMARK_MAX_ROWS + 1), '9')},
             TOO_MANY_ROWS % (EPHEMERAL, 'public', WATERMARK_MAX_ROWS)),
        )
        for watermark, refusal in rows:
            with self.subTest(watermark=repr(watermark)[:80]):
                pg, got = self.run_precheck(watermark)
                if refusal is None:
                    self.assertOutcome(got, EXIT_OK, [])
                    self.assertIn(EPHEMERAL_TPL, pg.dbs)
                else:
                    self.assertOutcome(got, EXIT_USAGE, [refusal])
                    self.assertEqual(pg.dbs, {}, 'a refused base gets no template')
                    self.assertFalse([s for s in pg.log if s.startswith('CREATE DATABASE')])
                reads = [env for sql, env in pg.envs if 'lineage_integrity_watermark' in sql]
                self.assertTrue(reads, 'the precheck reads the watermark')
                self.assertEqual({env.get('PGDATABASE') for env in reads}, {EPHEMERAL}, 'it reads the base itself')

    def test_precheck_failure_is_a_refusal_6983(self):
        error = 'ERROR:  database "%s" does not exist' % EPHEMERAL
        pg, got = self.run_precheck({}, fail={'SELECT n.nspname': error})
        self.assertOutcome(got, EXIT_USAGE, [PRECHECK_FAILED % (EPHEMERAL, 'psql failed (1): %s' % error)])
        self.assertEqual(pg.dbs, {})

    def test_precheck_is_bounded_on_100k_inputs_7157(self):
        started = time.monotonic()
        for watermark in ({'public': ('agent_lineage|1\n' * 100_000, '1')},
                          {'public': ('a' * 200_000 + '|1\n', '1')},
                          {'public': ('agent_lineage|' + '7' * 200_000 + '\n', '1')}):
            pg, got = self.run_precheck(watermark)
            self.assertEqual(got.rc, EXIT_USAGE)
            self.assertIsNone(got.escaped)
            self.assertEqual(pg.dbs, {})
        self.assertLess(time.monotonic() - started, 3.0)


# --- I3 / I4: one ownership guard, every exception and signal ----------------------------------------------------
class OwnershipI3I4(Base):
    def test_every_exception_type_after_create_releases_the_template_7114(self):
        for exc in EXCEPTIONS:
            with self.subTest(exc=type(exc).__name__):
                def boom(_sql, exc=exc):
                    raise exc
                pg = HygienePg(hooks={'CREATE EXTENSION IF NOT EXISTS age': boom})
                got = run_main(setup_argv(EPHEMERAL, '--emit-env'), pg)
                msg = str(exc) if isinstance(exc, pib.WrapperError) else unexpected(exc)
                self.assertOutcome(got, EXIT_USAGE, [msg])
                self.assertEqual(pg.dbs, {})
                self.assertEqual(pg.drops(EPHEMERAL_TPL), ['DROP DATABASE IF EXISTS "%s"' % EPHEMERAL_TPL])
                self.assertEqual(got.emitted, [])
                self.assertNoForce(pg)

    def test_exception_with_a_failed_cleanup_is_unreleased_7114_7200(self):
        for exc in EXCEPTIONS:
            with self.subTest(exc=type(exc).__name__):
                def boom(_sql, exc=exc):
                    raise exc
                cause = 'ERROR:  permission denied to drop database'
                pg = HygienePg(hooks={'CREATE EXTENSION IF NOT EXISTS vector': boom},
                               fail={'DROP DATABASE': cause})
                got = run_main(setup_argv(EPHEMERAL), pg)
                msg = str(exc) if isinstance(exc, pib.WrapperError) else unexpected(exc)
                self.assertOutcome(got, EXIT_UNRELEASED,
                                   [msg, UNRELEASED % (EPHEMERAL_TPL, 'psql failed (1): %s' % cause)])
                self.assertIn(EPHEMERAL_TPL, pg.dbs)

    def _signal_hook(self, sig, missing):
        def send(_sql):
            current = signal.getsignal(sig)
            if not callable(current) or current is signal.default_int_handler:
                missing.append(sig)                      # sending it would kill (or KeyboardInterrupt) the suite
                return
            os.kill(os.getpid(), sig)
        return send

    def test_signal_windows_release_and_exit_128_plus_signum_7152_7179(self):
        windows = (                                      # (window, hook prefix, extra fail map, template left?)
            ('precheck', 'SELECT n.nspname', {}),
            ('create', 'CREATE DATABASE', {}),
            ('extension', 'CREATE EXTENSION IF NOT EXISTS age', {}),
            ('lock', 'ALTER DATABASE', {}),
            ('cleanup', 'DROP DATABASE', {'CREATE EXTENSION IF NOT EXISTS vector': 'ERROR:  boom7179'}),
        )
        for sig in SIGNALS:
            for window, prefix, fail in windows:
                with self.subTest(signal=sig.name, window=window):
                    before = signal.getsignal(sig)
                    missing = []
                    pg = HygienePg(hooks={prefix: self._signal_hook(sig, missing)}, fail=fail)
                    got = run_main(setup_argv(EPHEMERAL, '--emit-env'), pg)
                    self.assertEqual(missing, [], 'setup has no %s handler in the %s window' % (sig.name, window))
                    expected = (['psql failed (1): ERROR:  boom7179'] if fail else []) + \
                        [INTERRUPTED % (sig, sig.name)]
                    self.assertOutcome(got, SIGNAL_EXIT_BASE + sig, expected)
                    self.assertEqual(pg.dbs, {}, 'nothing this run created is left')
                    self.assertEqual(got.emitted, [])
                    self.assertNoForce(pg)
                    self.assertEqual(signal.getsignal(sig), before, 'the handler is restored')

    def test_signal_during_a_failing_cleanup_is_unreleased_7179(self):
        missing = []
        cause = 'ERROR:  permission denied to drop database'
        pg = HygienePg(hooks={'DROP DATABASE': self._signal_hook(signal.SIGTERM, missing)},
                       fail={'CREATE EXTENSION IF NOT EXISTS age': 'ERROR:  boom', 'DROP DATABASE': cause})
        got = run_main(setup_argv(EPHEMERAL), pg)
        self.assertEqual(missing, [])
        self.assertOutcome(got, EXIT_UNRELEASED, ['psql failed (1): ERROR:  boom', INTERRUPTED % (15, 'SIGTERM'),
                                                  UNRELEASED % (EPHEMERAL_TPL, 'psql failed (1): %s' % cause)])

    def test_unknown_create_outcome_is_unreleased_not_dropped_7200(self):
        pg = HygienePg(lost={'CREATE DATABASE': 2})
        got = run_main(setup_argv(EPHEMERAL), pg)
        self.assertIsNone(got.escaped)
        self.assertEqual(got.rc, EXIT_UNRELEASED)
        self.assertEqual(got.lines[-1], line(MAYBE % (EPHEMERAL_TPL, EPHEMERAL_TPL)))
        self.assertEqual(pg.drops(EPHEMERAL_TPL), [], 'a name of unknown outcome is never dropped')
        self.assertIn(EPHEMERAL_TPL, pg.dbs)

    def test_unreleased_exit_is_distinct_7200(self):
        codes = {EXIT_OK, EXIT_USAGE, EXIT_MINT, EXIT_LOAD_REFUSED, EXIT_UNRELEASED, pib.EXIT_TERM}
        codes |= {SIGNAL_EXIT_BASE + s for s in SIGNALS}
        self.assertEqual(len(codes), 6 + len(SIGNALS) - 1, 'SIGTERM is the run exit 143 too, every other differs')
        self.assertEqual(pib.EXIT_USAGE, EXIT_USAGE)
        self.assertEqual(pib.WA_EXIT_LOAD_REFUSED, EXIT_LOAD_REFUSED)
        self.assertEqual(getattr(pib, 'EXIT_UNRELEASED', None), EXIT_UNRELEASED)

    def test_settle_timeout_keeps_the_name_owned_7212(self):
        busy = 'ERROR:  database "%s" is being accessed by other users' % EPHEMERAL_TPL
        pg = HygienePg(fail={'CREATE EXTENSION IF NOT EXISTS age': 'ERROR:  boom', 'DROP DATABASE': busy})
        got = run_main(setup_argv(EPHEMERAL), pg)
        self.assertOutcome(got, EXIT_UNRELEASED, ['psql failed (1): ERROR:  boom',
                                                  UNRELEASED % (EPHEMERAL_TPL, 'psql failed (1): %s' % busy)])
        self.assertEqual(len(pg.drops(EPHEMERAL_TPL)), pib.DROP_ATTEMPTS, 'the drop waits out the settle window')
        self.assertNoForce(pg)

    def test_teardown_settle_timeout_is_unreleased_7212(self):
        pg = HygienePg(dbs={EPHEMERAL_TPL: {'sessions': 1}})
        got = run_main(['teardown', '--url', ADMIN_URL, '--db', EPHEMERAL, '--run-id', RUN], pg)
        busy = 'ERROR:  database "%s" is being accessed by other users' % EPHEMERAL_TPL
        self.assertOutcome(got, EXIT_UNRELEASED, [UNRELEASED % (EPHEMERAL_TPL, 'psql failed (1): %s' % busy)])
        self.assertEqual(len(pg.drops(EPHEMERAL_TPL)), pib.DROP_ATTEMPTS)
        self.assertIn(EPHEMERAL_TPL, pg.dbs)

    def test_failed_teardown_asserts_cause_and_state_7159(self):
        clone = 'ai_memory_t_%s_1700000000_0123abcd' % RUN
        foreign = 'ai_memory_t_zother_1700000000_0123abcd'
        cause = 'ERROR:  must be owner of database %s' % clone
        pg = HygienePg(dbs={clone: {'drop_fail': cause}, foreign: {}, EPHEMERAL_TPL: {}})
        got = run_main(['teardown', '--url', ADMIN_URL, '--db', EPHEMERAL, '--run-id', RUN], pg)
        self.assertOutcome(got, EXIT_UNRELEASED, [UNRELEASED % (clone, 'psql failed (1): %s' % cause)])
        self.assertEqual(sorted(pg.dbs), sorted([clone, foreign]), 'the template went, the foreign clone stayed')
        self.assertEqual(pg.drops(foreign), [])
        self.assertNoForce(pg)

    def test_teardown_signal_still_drops_everything_7152(self):
        clones = ['ai_memory_t_%s_170000000%d_0123abcd' % (RUN, i) for i in range(3)]
        missing = []
        pg = HygienePg(dbs=dict({c: {} for c in clones}, **{EPHEMERAL_TPL: {}}),
                       hooks={'DROP DATABASE IF EXISTS "%s"' % clones[0]: self._signal_hook(signal.SIGTERM, missing)})
        got = run_main(['teardown', '--url', ADMIN_URL, '--db', EPHEMERAL, '--run-id', RUN], pg)
        self.assertEqual(missing, [], 'teardown has no SIGTERM handler')
        self.assertOutcome(got, SIGNAL_EXIT_BASE + signal.SIGTERM, [INTERRUPTED % (15, 'SIGTERM')])
        self.assertEqual(pg.dbs, {})

    def test_emit_env_emits_only_the_template_and_run_id_7153(self):
        pg = HygienePg()
        got = run_main(setup_argv(EPHEMERAL, '--emit-env'), pg)
        self.assertOutcome(got, EXIT_OK, [])
        self.assertEqual(got.emitted, ['%s=%s' % (pib.TEMPLATE_VAR, EPHEMERAL_TPL), '%s=%s' % (pib.RUN_ID_VAR, RUN)])
        for emitted in got.emitted:
            self.assertNotIn(pib.URL_VAR, emitted)
            self.assertNotIn('postgres', emitted)
        tree = ast.parse(SCRIPT.read_text(encoding='utf-8'))
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, 'id', '') == '_emit']
        named = sorted(n.args[0].right.elts[0].id for n in calls)
        self.assertEqual(named, EMITTED_VARS, 'every _emit call names one of the two variables, never URL_VAR')

    def test_sweep_two_runs_one_run_id_7156(self):
        aged = 'ai_memory_t_r7156_1700000000_aaaaaaaa'            # the finished run, idle and old
        fresh = 'ai_memory_t_r7156_1700009990_bbbbbbbb'           # the active run, idle between mint and hold
        held = 'ai_memory_t_r7156_1700000100_cccccccc'            # the active run, its hold attached after listing
        pg = HygienePg(dbs={aged: {}, fresh: {}, held: {'sessions': 1}}, clock=1700010000)
        with unittest.mock.patch.object(pib.subprocess, 'run', pg), unittest.mock.patch.object(pib.time, 'sleep'), \
                contextlib.redirect_stderr(io.StringIO()):
            dropped = pib.sweep(ADMIN_URL, 3600)
        self.assertEqual(dropped, [aged])
        self.assertEqual(sorted(pg.dbs), sorted([fresh, held]))
        self.assertEqual(len(pg.drops(held)), 1, 'the sweep tries an aged name once, without force')
        self.assertEqual(pg.drops(fresh), [])
        self.assertNoForce(pg)


# --- the absence table: every [M]/[F] finding of PR 7088 --------------------------------------------------------
ABSENCE = (
    # (issue, kind, the test that proves the window is closed in this design)
    (7114, 'M', 'test_every_exception_type_after_create_releases_the_template_7114'),
    (7152, 'M', 'test_signal_windows_release_and_exit_128_plus_signum_7152_7179'),
    (7179, 'M', 'test_signal_during_a_failing_cleanup_is_unreleased_7179'),
    (7180, 'M', 'test_teardown_without_db_is_refused_7180'),
    (7200, 'M', 'test_unreleased_exit_is_distinct_7200'),
    (7212, 'M', 'test_settle_timeout_keeps_the_name_owned_7212'),
    (7156, 'F', 'test_sweep_two_runs_one_run_id_7156'),
    (7159, 'F', 'test_failed_teardown_asserts_cause_and_state_7159'),
)
CREATE_SITES = sorted(('CREATE DATABASE %s', 'CREATE DATABASE %s TEMPLATE %s'))   # the template, the clone
CREATE_SQL_RE = re.compile(r'CREATE DATABASE [^;]*%s', re.IGNORECASE)                # a SQL format, not prose


class AbsenceTable(unittest.TestCase):
    def test_minted_base_and_family_marker_classes_cannot_exist_7031(self):
        source = SCRIPT.read_text(encoding='utf-8')
        tree = ast.parse(source)
        creates = sorted(n.left.value for n in ast.walk(tree) if isinstance(n, ast.BinOp)
                         and isinstance(n.left, ast.Constant) and isinstance(n.left.value, str)
                         and CREATE_SQL_RE.fullmatch(n.left.value))
        names = {getattr(c, '__name__', '') for c in (OwnershipI3I4, BaseClassI1)}
        for issue, kind, test in ABSENCE:
            with self.subTest(issue=issue, kind=kind):
                owner = [c for c in (OwnershipI3I4, BaseClassI1) if hasattr(c, test)]
                self.assertTrue(owner, '#%d names %s, which %s does not define' % (issue, test, names))
                if kind == 'M':   # only a minted base opens the window: the wrapper creates the template and clones
                    self.assertEqual(creates, CREATE_SITES)
                    self.assertNotIn('ci_base_', source)
                else:             # only a family marker opens the window: the wrapper writes no marker at all
                    self.assertNotIn('COMMENT ON', source.upper())
                    self.assertNotIn('SHOBJ_DESCRIPTION', source.upper())


# --- live cells ---------------------------------------------------------------------------------------------------
LIVE_URL = os.environ.get(pib.URL_VAR, '')
LIVE_ADMIN_DB = 'postgres'                      # never the poisoned ai_memory_test, even as the admin hop
LIVE_ADMIN = pib.with_database(LIVE_URL, LIVE_ADMIN_DB) if LIVE_URL else ''
LIVE_READY = bool(LIVE_URL and shutil.which('psql'))
SHIM_SOURCE = '''#!/usr/bin/env python3
"""Test shim for psql: slows or fails one statement, then runs the real psql (LiveHygiene, #7179)."""
import os, subprocess, sys, time
from pathlib import Path
sql = sys.argv[-1] if len(sys.argv) > 1 else ''
if os.environ.get('PIB_SHIM_FAIL') and sql.startswith(os.environ['PIB_SHIM_FAIL']):
    sys.stderr.write('ERROR:  shim refused %s\\n' % os.environ['PIB_SHIM_FAIL'])
    sys.exit(1)
slow = os.environ.get('PIB_SHIM_SLOW') and sql.startswith(os.environ['PIB_SHIM_SLOW'])
if slow:
    Path(os.environ['PIB_SHIM_MARK']).write_text('started')
    time.sleep(float(os.environ.get('PIB_SHIM_SECS', '3')))
done = subprocess.run([os.environ['PIB_SHIM_REAL']] + sys.argv[1:], capture_output=True, text=True)
sys.stdout.write(done.stdout)
sys.stderr.write(done.stderr)
if slow:
    Path(os.environ['PIB_SHIM_MARK'] + '.done').write_text(str(done.returncode))
sys.exit(done.returncode)
'''


@unittest.skipUnless(LIVE_READY, 'AI_MEMORY_TEST_POSTGRES_URL unset (live hygiene)')
class LiveHygiene(unittest.TestCase):
    """The real script against a real server: a poisoned base, a foreign template, SIGTERM in CREATE and cleanup."""

    def setUp(self):
        self.base = 'ai_memory_test_ci_7031_1_h%s' % uuid.uuid4().hex[:8]
        self.tpl = self.base + '_tpl'
        self.admin('CREATE DATABASE %s' % self.base)
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.scratch = Path(tempfile.mkdtemp(dir=str(SCRATCH)))

    def tearDown(self):
        for name in (self.tpl, self.base):
            if self.exists(name):
                with contextlib.suppress(AssertionError):
                    self.admin('ALTER DATABASE %s WITH IS_TEMPLATE false' % name)
                self.admin('DROP DATABASE IF EXISTS %s' % name)
        if str(self.scratch).startswith(str(SCRATCH)):
            shutil.rmtree(self.scratch, ignore_errors=True)

    @staticmethod
    def admin(sql, db=None):
        url = pib.with_database(LIVE_URL, db) if db else LIVE_ADMIN
        done = subprocess.run(['psql', '-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1', '-c', sql], capture_output=True,
                              text=True, env=pib._pg_env(url), timeout=120)
        if done.returncode != 0:
            raise AssertionError('%s -> %s' % (sql[:60], done.stderr.strip()[:300]))
        return done.stdout

    def exists(self, name):
        return self.admin("SELECT 1 FROM pg_database WHERE datname = '%s'" % name).strip() == '1'

    def script(self, *argv, env=None, popen=False):
        cmd = [sys.executable, str(SCRIPT)] + list(argv)
        child_env = dict(os.environ, **{pib.URL_VAR: LIVE_ADMIN}, **(env or {}))
        if popen:
            return subprocess.Popen(cmd, env=child_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return subprocess.run(cmd, env=child_env, capture_output=True, text=True, timeout=300)

    @staticmethod
    def lines(stderr):
        return [ln for ln in stderr.splitlines() if ln.startswith(PREFIX)]

    def test_live_poisoned_base_is_refused_6983(self):
        self.admin('CREATE TABLE lineage_integrity_watermark (relation text PRIMARY KEY, high_water bigint)',
                   self.base)
        self.admin("INSERT INTO lineage_integrity_watermark VALUES ('agent_lineage', 5)", self.base)
        self.admin('CREATE TABLE agent_lineage (id int)', self.base)
        self.admin('INSERT INTO agent_lineage VALUES (1), (2)', self.base)
        done = self.script('setup', '--db', self.base, '--jobs', '1', '--run-id', 'r7031p')
        self.assertEqual(done.returncode, EXIT_USAGE, done.stderr[-1500:])
        self.assertEqual(self.lines(done.stderr), [line(REGRESSED % (self.base, 'public', 5, 2))])
        self.assertFalse(self.exists(self.tpl), 'no template beside a poisoned base')

    def test_live_intact_base_with_a_watermark_is_used_6983(self):
        self.admin('CREATE TABLE lineage_integrity_watermark (relation text PRIMARY KEY, high_water bigint)',
                   self.base)
        self.admin("INSERT INTO lineage_integrity_watermark VALUES ('agent_lineage', 2)", self.base)
        self.admin('CREATE TABLE agent_lineage (id int)', self.base)
        self.admin('INSERT INTO agent_lineage VALUES (1), (2)', self.base)
        done = self.script('setup', '--db', self.base, '--jobs', '1', '--run-id', 'r7031i')
        self.assertEqual(done.returncode, EXIT_OK, done.stderr[-1500:])
        self.assertTrue(self.exists(self.tpl))
        down = self.script('teardown', '--db', self.base, '--run-id', 'r7031i')
        self.assertEqual(down.returncode, EXIT_OK, down.stderr[-1500:])
        self.assertFalse(self.exists(self.tpl))

    def test_live_foreign_template_survives_i3(self):
        self.admin('CREATE DATABASE %s' % self.tpl)
        done = self.script('setup', '--db', self.base, '--jobs', '1', '--run-id', 'r7031f')
        self.assertEqual(done.returncode, EXIT_USAGE, done.stderr[-1500:])
        self.assertTrue(self.exists(self.tpl), 'a template this run did not create is never dropped')

    def _shimmed(self, slow, fail=''):
        shim_dir = self.scratch / 'bin'
        shim_dir.mkdir()
        shim = shim_dir / 'psql'
        shim.write_text(SHIM_SOURCE, encoding='utf-8')
        shim.chmod(0o755)
        mark = self.scratch / 'mark'
        env = {'PATH': '%s%s%s' % (shim_dir, os.pathsep, os.environ.get('PATH', '')),
               'PIB_SHIM_REAL': shutil.which('psql'), 'PIB_SHIM_SLOW': slow, 'PIB_SHIM_FAIL': fail,
               'PIB_SHIM_MARK': str(mark), 'PIB_SHIM_SECS': '3'}
        return env, mark

    def _term_in_window(self, slow, fail=''):
        env, mark = self._shimmed(slow, fail)
        child = self.script('setup', '--db', self.base, '--jobs', '1', '--run-id', 'r7031s', env=env, popen=True)
        deadline = time.monotonic() + 120
        while not mark.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(mark.exists(), 'the shimmed statement started')
        child.send_signal(signal.SIGTERM)
        _out, err = child.communicate(timeout=300)
        done_mark = Path(str(mark) + '.done')
        deadline = time.monotonic() + 60
        while not done_mark.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        return child.returncode, err

    def test_live_sigterm_during_create_drops_the_template_7179(self):
        rc, err = self._term_in_window('CREATE DATABASE')
        self.assertEqual(rc, SIGNAL_EXIT_BASE + signal.SIGTERM, err[-1500:])
        self.assertEqual(self.lines(err), [line(INTERRUPTED % (15, 'SIGTERM'))])
        self.assertFalse(self.exists(self.tpl), 'the template created under SIGTERM is dropped')

    def test_live_sigterm_during_cleanup_still_drops_7179(self):
        rc, err = self._term_in_window('DROP DATABASE', fail='CREATE EXTENSION IF NOT EXISTS age')
        self.assertEqual(rc, SIGNAL_EXIT_BASE + signal.SIGTERM, err[-1500:])
        self.assertEqual(self.lines(err), [line('psql failed (1): ERROR:  shim refused CREATE EXTENSION IF NOT '
                                                'EXISTS age'), line(INTERRUPTED % (15, 'SIGTERM'))])
        self.assertFalse(self.exists(self.tpl))


if __name__ == '__main__':
    unittest.main()
