#!/usr/bin/env python3
"""Unit tests for scripts/ci/test_binary_cache.py (#6384).

Run: python3 -m unittest scripts/ci/tests/test_test_binary_cache.py
Fixtures live under the repository's .local-runs/ (never the system temp dir).
No test runs cargo or rustc.
"""
import argparse
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import test_binary_cache as tbc  # noqa: E402

REPO = HERE.parents[2]
SCRATCH = REPO / '.local-runs' / 'cache-unittests'
NOW = 1_800_000_000.0
ENV_ON = {'CI_TEST_BINARY_CACHE': '1', 'CI_TEST_BINARY_CACHE_LOOKUP': '1', 'AI_MEMORY_NO_CONFIG': '1'}


def art(kind, name, exe, test, pid='path+file:///repo#ai-memory@1.0.0', filenames=None):
    return json.dumps({'reason': 'compiler-artifact', 'package_id': pid,
                       'target': {'kind': [kind], 'name': name, 'src_path': '/repo/x.rs'},
                       'profile': {'test': test}, 'executable': exe, 'filenames': filenames or []})


class World(unittest.TestCase):
    """A fake repo + target dir with dep-info files and a build.jsonl."""

    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        self.root = SCRATCH / 'repo'
        self.deps = self.root / 'target' / 'debug' / 'deps'
        self.sd = SCRATCH / 'shard'
        self.mdir = SCRATCH / 'manifests'
        for d in (self.root / 'src', self.root / 'tests', self.deps, self.sd, self.mdir):
            d.mkdir(parents=True)
        (self.root / 'Cargo.lock').write_text('lock-v1\n')
        (self.root / 'src' / 'lib.rs').write_text('pub fn a() {}\n')
        (self.root / 'tests' / 'a.rs').write_text('fn a() {}\n')
        (self.root / 'tests' / 'b.rs').write_text('fn b() {}\n')
        self.rustc = SCRATCH / 'rustc-vv.txt'
        self.rustc.write_text('rustc 1.98.0\nhost: x86_64\n')
        self.cargo_v = SCRATCH / 'cargo-v.txt'
        self.cargo_v.write_text('cargo 1.98.0 (fixture)\n')
        self.write_deps()
        self.build()
        self.lists()

    def tearDown(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def write_deps(self):
        d = self.deps
        (d / 'ai_memory-h1.d').write_text('target/debug/deps/ai_memory-h1: src/lib.rs\n\nsrc/lib.rs:\n')
        (d / 'libai_memory-h2.rlib').write_text('')
        (d / 'ai_memory-h2.d').write_text('target/debug/deps/libai_memory-h2.rlib: src/lib.rs\n\nsrc/lib.rs:\n')
        (d / 'a-h3.d').write_text('target/debug/deps/a-h3: tests/a.rs\n\ntests/a.rs:\n')
        (d / 'b-h4.d').write_text('target/debug/deps/b-h4: tests/b.rs\n\ntests/b.rs:\n')

    def build(self):
        d = str(self.deps)
        lines = [
            art('lib', 'ai_memory', d + '/ai_memory-h1', True),
            art('lib', 'ai_memory', None, False, filenames=[d + '/libai_memory-h2.rlib']),
            art('test', 'a', d + '/a-h3', True),
            art('test', 'b', d + '/b-h4', True),
            art('lib', 'serde', None, False, pid='registry+https://x#serde@1', filenames=['/nowhere/libserde.rlib']),
        ]
        self.bj = SCRATCH / 'build.jsonl'
        self.bj.write_text('\n'.join(lines) + '\n')

    def lists(self):
        (self.sd / 'serial.txt').write_text('--lib\n--test a\n')
        (self.sd / 'parallel_1.txt').write_text('--lib\n')
        (self.sd / 'parallel_2.txt').write_text('--test b\n')

    def args(self, **kw):
        base = dict(shard_dir=str(self.sd), manifest_dir=str(self.mdir), run_id='100', sha='abc', build_json=str(self.bj),
                    repo_root=str(self.root), rustc_vv=str(self.rustc), profile='test sal-postgres', tier='enterprise-fed',
                    node='linux-fed', base_ref='release/v1.0.0', event='pull_request', ref='refs/pull/1/merge',
                    no_runtime_tree=False, psql='psql', timeout_seconds=120,
                    cargo_v=str(self.cargo_v), cargo=str(SCRATCH / 'no-such-cargo'))
        base.update(kw)
        return argparse.Namespace(**base)

    def plan(self, now=NOW, env=None, **kw):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = tbc.run_plan(self.args(**kw), env=env if env is not None else ENV_ON, now=now)
        self.assertEqual(rc, 0)
        return out.getvalue()

    def record(self, rc=0, now=NOW, run_id='100'):
        out = io.StringIO()
        with redirect_stdout(out):
            tbc.run_record(argparse.Namespace(shard_dir=str(self.sd), manifest_dir=str(self.mdir), rc=rc,
                                              run_id=run_id, sha='abc'), now=now)
        return out.getvalue()

    def manifest(self):
        return json.loads(tbc.manifest_path(self.mdir, 'linux-fed', 'enterprise-fed', 'release/v1.0.0').read_text())

    def list_text(self, name):
        return (self.sd / (name + '.txt')).read_text()

    def green_run(self, run_id='100', now=NOW):
        """A green release/** push: the only run that records (r1 M2)."""
        self.plan(now=now, run_id=run_id, event='push', ref='refs/heads/release/v1.0.0')
        self.record(0, now=now, run_id=run_id)
        # restore the full lists for the next simulated run
        for n in tbc.SHARD_LISTS:
            full = self.sd / (n + '.txt.full')
            if full.exists():
                (self.sd / (n + '.txt')).write_text(full.read_text())


class DepInfoParsing(unittest.TestCase):
    def test_basic_rule_and_empty_prereq_lines(self):
        deps, env = tbc.parse_depinfo('t: src/a.rs src/b.rs\n\nsrc/a.rs:\n\nsrc/b.rs:\n')
        self.assertEqual(deps, ['src/a.rs', 'src/b.rs'])
        self.assertEqual(env, [])

    def test_escaped_space_continuation_and_env_dep(self):
        text = '# env-dep:CARGO_PKG_VERSION=1.0\nt: src/my\\ file.rs \\\n  src/b.rs\n\nsrc/b.rs:\n'
        deps, env = tbc.parse_depinfo(text)
        self.assertEqual(deps, ['src/b.rs', 'src/my file.rs'])
        self.assertEqual(env, ['# env-dep:CARGO_PKG_VERSION=1.0'])

    def test_empty_or_garbage_raises(self):
        for bad in ('', '\n\n', '# only a comment\n', 'no separator here\n'):
            with self.assertRaises(tbc.CacheError, msg=repr(bad)):
                tbc.parse_depinfo(bad)


class KeyStability(World):
    def keys(self, env=None, profile='test sal-postgres', rustc=None):
        exes = tbc.ptb.parse_build_json(self.bj.read_text().splitlines())
        rv = rustc if rustc is not None else self.rustc.read_text()
        return tbc.compute_keys(exes, self.bj.read_text().splitlines(), self.root, rv, profile, env or ENV_ON)

    def test_stable_across_calls_and_distinct_per_binary(self):
        k1, _ = self.keys()
        k2, _ = self.keys()
        self.assertEqual(k1, k2)
        self.assertEqual(set(k1), {'lib:ai_memory', 'test:a', 'test:b'})
        self.assertEqual(len(set(k1.values())), 3)
        self.assertTrue(all(k for k in k1.values()))

    def test_own_source_change_only_moves_that_key(self):
        k1, _ = self.keys()
        (self.root / 'tests' / 'a.rs').write_text('fn a() { 1 }\n')
        k2, _ = self.keys()
        self.assertNotEqual(k1['test:a'], k2['test:a'])
        self.assertEqual(k1['test:b'], k2['test:b'])
        self.assertEqual(k1['lib:ai_memory'], k2['lib:ai_memory'])

    def test_lib_source_change_moves_every_key(self):
        k1, _ = self.keys()
        (self.root / 'src' / 'lib.rs').write_text('pub fn a() { 2 }\n')
        k2, _ = self.keys()
        for n in k1:
            self.assertNotEqual(k1[n], k2[n], n)

    def test_lock_rustc_profile_env_move_every_key(self):
        base, _ = self.keys()
        for label, kw in (('rustc', {'rustc': 'rustc 1.99\n'}), ('profile', {'profile': 'test'}),
                          ('env', {'env': dict(ENV_ON, RUSTFLAGS='-C debuginfo=0')}),
                          ('nocfg', {'env': {'CI_TEST_BINARY_CACHE': '1', 'CI_TEST_BINARY_CACHE_LOOKUP': '1'}})):
            other, _ = self.keys(**kw)
            for n in base:
                self.assertNotEqual(base[n], other[n], '%s/%s' % (label, n))
        (self.root / 'Cargo.lock').write_text('lock-v2\n')
        other, _ = self.keys()
        for n in base:
            self.assertNotEqual(base[n], other[n], 'lock/' + n)

    def test_postgres_url_value_ignored_presence_counts(self):
        a, _ = self.keys(env=dict(ENV_ON, AI_MEMORY_TEST_POSTGRES_URL='postgres://x/db1'))
        b, _ = self.keys(env=dict(ENV_ON, AI_MEMORY_TEST_POSTGRES_URL='postgres://x/db2'))
        c, _ = self.keys(env=ENV_ON)
        self.assertEqual(a, b)
        self.assertNotEqual(a['test:a'], c['test:a'])

    def test_checkout_location_does_not_matter(self):
        k1, _ = self.keys()
        moved = SCRATCH / 'repo2'
        shutil.copytree(self.root, moved)
        exes = tbc.ptb.parse_build_json(self.bj.read_text().splitlines())
        k2, _ = tbc.compute_keys(exes, self.bj.read_text().splitlines(), moved, self.rustc.read_text(), 'test sal-postgres', ENV_ON)
        self.assertEqual(k1, k2)

    def test_env_dep_checkout_path_is_normalised(self):
        (self.deps / 'a-h3.d').write_text(
            '# env-dep:CARGO_MANIFEST_DIR=%s\nt: tests/a.rs\n\ntests/a.rs:\n' % self.root.resolve())
        k1, _ = self.keys()
        moved = SCRATCH / 'repo3'
        shutil.copytree(self.root, moved)
        (moved / 'target' / 'debug' / 'deps' / 'a-h3.d').write_text(
            '# env-dep:CARGO_MANIFEST_DIR=%s\nt: tests/a.rs\n\ntests/a.rs:\n' % moved.resolve())
        lines = self.bj.read_text().replace(str(self.root), str(moved)).splitlines()
        exes = tbc.ptb.parse_build_json(lines)
        k2, _ = tbc.compute_keys(exes, lines, moved, self.rustc.read_text(), 'test sal-postgres', ENV_ON)
        self.assertEqual(k1['test:a'], k2['test:a'])

    def test_missing_dep_file_degrades_only_that_binary(self):
        (self.deps / 'a-h3.d').unlink()
        keys, why = self.keys()
        self.assertIsNone(keys['test:a'])
        self.assertIn('test:a', why)
        self.assertIsNotNone(keys['test:b'])

    def test_unparsable_or_dangling_dep_file_yields_no_key(self):
        (self.deps / 'a-h3.d').write_text('garbage with no rule separator\n')
        (self.deps / 'b-h4.d').write_text('t: tests/gone.rs\n')
        keys, _ = self.keys()
        self.assertIsNone(keys['test:a'])
        self.assertIsNone(keys['test:b'])

    def test_no_shared_closure_means_no_keys_at_all(self):
        (self.deps / 'ai_memory-h1.d').unlink()
        (self.deps / 'ai_memory-h2.d').unlink()
        keys, why = self.keys()
        self.assertEqual(set(keys.values()), {None})
        self.assertTrue(all('shared inputs' in w for w in why.values()))

    def test_runtime_tree_moves_all_keys_but_compiled_rs_only_moves_scanners(self):
        (self.root / 'scripts').mkdir()
        (self.root / 'scripts' / 'x.txt').write_text('1')
        (self.deps / 'a-h3.d').write_text('t: tests/a.rs\n\ntests/a.rs:\n')
        (self.root / 'tests' / 'a.rs').write_text('fn a() { read_dir("tests"); }\n')  # scanner
        base, _ = self.keys()
        (self.root / 'scripts' / 'x.txt').write_text('2')
        data, _ = self.keys()
        for n in base:
            self.assertNotEqual(base[n], data[n], n)
        (self.root / 'tests' / 'b.rs').write_text('fn b() { /* edit */ }\n')
        rs, _ = self.keys()
        self.assertNotEqual(data['test:a'], rs['test:a'])   # scanner sees other tests/*.rs
        self.assertEqual(data['lib:ai_memory'], rs['lib:ai_memory'])  # lib/bin never use the scanner path
        self.assertNotEqual(data['test:b'], rs['test:b'])   # b's own source changed

    def test_non_scanner_ignores_other_binaries_rs_edits(self):
        base, _ = self.keys()
        (self.root / 'tests' / 'a.rs').write_text('fn a() { 1 }\n')
        after, _ = self.keys()
        self.assertEqual(base['test:b'], after['test:b'])


class OrphanSources6384H1(World):
    """r1 H1: a .rs file no dep-info names (cfg-off module, orphan) is a run-time input."""

    def keys(self):
        exes = tbc.ptb.parse_build_json(self.bj.read_text().splitlines())
        return tbc.compute_keys(exes, self.bj.read_text().splitlines(), self.root, self.rustc.read_text(),
                                'test sal-postgres', ENV_ON)

    def test_uncompiled_src_file_edit_moves_the_lib_key(self):
        (self.root / 'src' / 'vectorlite.rs').write_text('// cfg(feature = "vectorlite") only\n')
        k1, _ = self.keys()
        (self.root / 'src' / 'vectorlite.rs').write_text('// cfg(feature = "vectorlite") only\nfn m() {}\n')
        k2, _ = self.keys()
        self.assertNotEqual(k1['lib:ai_memory'], k2['lib:ai_memory'])
        self.assertNotEqual(k1['test:a'], k2['test:a'])

    def test_orphan_tests_file_edit_moves_every_key(self):
        (self.root / 'tests' / 'common').mkdir()
        (self.root / 'tests' / 'common' / 'orphan.rs').write_text('fn o() {}\n')
        k1, _ = self.keys()
        (self.root / 'tests' / 'common' / 'orphan.rs').write_text('fn o() { 1 }\n')
        k2, _ = self.keys()
        for n in k1:
            self.assertNotEqual(k1[n], k2[n], n)

    def test_compiled_file_of_another_binary_still_leaves_non_scanner_alone(self):
        base, _ = self.keys()
        (self.root / 'tests' / 'a.rs').write_text('fn a() { 2 }\n')
        after, _ = self.keys()
        self.assertEqual(base['test:b'], after['test:b'])
        self.assertEqual(base['lib:ai_memory'], after['lib:ai_memory'])


class EnvFingerprint6384H2(unittest.TestCase):
    """r1 H2: runner-inherited env that changes test behaviour is part of the key."""

    BASE = {'AI_MEMORY_NO_CONFIG': '1', 'AI_MEMORY_TEST_POSTGRES_URL': 'postgres://u@h/db1'}

    def fp(self, **extra):
        return tbc.env_fingerprint(dict(self.BASE, **extra))

    def test_age_url_presence_and_bless_value_move_the_fingerprint(self):
        base = self.fp()
        self.assertNotEqual(base, self.fp(AI_MEMORY_TEST_AGE_URL='postgres://age'))
        self.assertNotEqual(base, self.fp(AI_MEMORY_BLESS_SNAPSHOTS='1'))
        self.assertNotEqual(self.fp(AI_MEMORY_BLESS_SNAPSHOTS='1'), self.fp(AI_MEMORY_BLESS_SNAPSHOTS='0'))

    def test_every_ai_memory_and_runner_family_counts(self):
        base = self.fp()
        for name, val in (('AI_MEMORY_TEST_TIMING_BUDGET_MULT', '3'), ('AI_MEMORY_EMBED_OFFLINE', '1'),
                          ('AI_MEMORY_TEST_ALLOW_DROP_EXTENSION', '1'), ('AI_MEMORY_TEST_PG_ISOLATE', '1'),
                          ('CI', 'true'), ('RUST_TEST_THREADS', '1'), ('RUST_MIN_STACK', '8388608'),
                          ('PROPTEST_CASES', '10'), ('CARGO_PROFILE_TEST_DEBUG', '0'),
                          ('CARGO_BUILD_JOBS', '1'), ('RUSTFLAGS', '-C debuginfo=0')):
            self.assertNotEqual(base, self.fp(**{name: val}), name)

    def test_secret_like_names_count_by_presence_only_and_never_leak(self):
        a = self.fp(AI_MEMORY_TEST_PG_URL='postgres://one', AI_MEMORY_API_KEY='k-sentinel-1',
                    AI_MEMORY_DB_PASSPHRASE='pp-sentinel', AI_MEMORY_HUB_TOKEN='t1', AI_MEMORY_X_SECRET='s1',
                    AI_MEMORY_PG_PASSWORD='pw1')
        b = self.fp(AI_MEMORY_TEST_PG_URL='postgres://two', AI_MEMORY_API_KEY='k-sentinel-2',
                    AI_MEMORY_DB_PASSPHRASE='other', AI_MEMORY_HUB_TOKEN='t2', AI_MEMORY_X_SECRET='s2',
                    AI_MEMORY_PG_PASSWORD='pw2')
        self.assertEqual(a, b)
        self.assertNotEqual(a, self.fp())
        for raw in ('postgres://', 'sentinel', 'pw1', 'postgres://u@h/db1'):
            self.assertNotIn(raw, a)

    def test_empty_secret_differs_from_unset_and_from_set(self):
        unset, empty = self.fp(), self.fp(AI_MEMORY_DB_PASSPHRASE='')
        setv = self.fp(AI_MEMORY_DB_PASSPHRASE='x')
        self.assertEqual(len({unset, empty, setv}), 3)

    def test_plain_values_are_hashed_not_written(self):
        fp = self.fp(AI_MEMORY_BLESS_SNAPSHOTS='bless-sentinel-value')
        self.assertNotIn('bless-sentinel-value', fp)

    def test_unrelated_runner_env_is_ignored(self):
        self.assertEqual(self.fp(), self.fp(PATH='/x', HOME='/h', GITHUB_RUN_ID='9', RUNNER_TEMP='/r'))


FAKE_PSQL = """#!/usr/bin/env python3
import os, sys
sys.stdout.write(os.environ.get('FAKE_PSQL_OUT', ''))
sys.exit(int(os.environ.get('FAKE_PSQL_RC', '0')))
"""
PG_OUT_1 = 'PostgreSQL 18.6 on x86_64-pc-linux-gnu\nage 1.8.0 1.8.0\nvector 0.8.1 0.8.1\n'
PG_OUT_2 = 'PostgreSQL 18.6 on x86_64-pc-linux-gnu\nage 1.9.0 1.9.0\nvector 0.8.1 0.8.1\n'


class PostgresServerFingerprint6384M1(World):
    """r1 M1: the Postgres server and its age / vector versions are in the key."""

    def setUp(self):
        super().setUp()
        self.psql = SCRATCH / 'fake-psql'
        self.psql.write_text(FAKE_PSQL)
        self.psql.chmod(0o755)

    def pg_env(self, out=PG_OUT_1, rc='0'):
        return dict(ENV_ON, AI_MEMORY_TEST_POSTGRES_URL='postgres://u@h:5445/db', FAKE_PSQL_OUT=out, FAKE_PSQL_RC=rc)

    def test_no_url_is_none(self):
        self.assertEqual(tbc.pg_fingerprint(ENV_ON, psql=str(self.psql)), 'none')

    def test_version_or_extension_change_moves_the_fingerprint(self):
        a = tbc.pg_fingerprint(self.pg_env(PG_OUT_1), psql=str(self.psql))
        b = tbc.pg_fingerprint(self.pg_env(PG_OUT_2), psql=str(self.psql))
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, 'none')
        self.assertNotIn('postgres://', a)

    def test_failure_empty_or_missing_psql_raises(self):
        for env, psql in ((self.pg_env(rc='2'), str(self.psql)), (self.pg_env(out=''), str(self.psql)),
                          (self.pg_env(), str(SCRATCH / 'no-such-psql'))):
            with self.assertRaises(tbc.CacheError):
                tbc.pg_fingerprint(env, psql=psql)

    def test_server_fingerprint_moves_every_key(self):
        exes = tbc.ptb.parse_build_json(self.bj.read_text().splitlines())
        lines = self.bj.read_text().splitlines()
        k1, _ = tbc.compute_keys(exes, lines, self.root, self.rustc.read_text(), 'p', ENV_ON, server_fp='A')
        k2, _ = tbc.compute_keys(exes, lines, self.root, self.rustc.read_text(), 'p', ENV_ON, server_fp='B')
        for n in k1:
            self.assertNotEqual(k1[n], k2[n], n)

    def test_server_upgrade_between_runs_means_no_hits(self):
        seed = self.pg_env(PG_OUT_1)
        self.plan(env=seed, event='push', ref='refs/heads/release/v1.0.0', psql=str(self.psql))
        self.record(0)
        for n in tbc.SHARD_LISTS:
            (self.sd / (n + '.txt')).write_text((self.sd / (n + '.txt.full')).read_text())
        self.assertIn('skipped 0 of 3', self.plan(env=self.pg_env(PG_OUT_2), run_id='2', psql=str(self.psql)))

    def test_unreadable_server_fingerprint_means_no_skips(self):
        self.plan(env=self.pg_env(), event='push', ref='refs/heads/release/v1.0.0', psql=str(self.psql))
        self.record(0)
        for n in tbc.SHARD_LISTS:
            (self.sd / (n + '.txt')).write_text((self.sd / (n + '.txt.full')).read_text())
        out = self.plan(env=self.pg_env(rc='2'), run_id='2', psql=str(self.psql))
        self.assertIn('::warning::', out)
        self.assertEqual(self.list_text('serial'), '--lib\n--test a\n')


ENV_LOOKUP = dict(ENV_ON, CI_TEST_BINARY_CACHE_LOOKUP='1')


class PullRequestNeverRecords6384M2(World):
    """r1 M2 decision: pull_request looks up only; only a release/** push records."""

    def test_policy_matrix(self):
        pol = tbc.cache_policy
        self.assertEqual(pol(ENV_LOOKUP, 'pull_request', 'refs/pull/9/merge')[:2], (True, False))
        self.assertEqual(pol(ENV_LOOKUP, 'push', 'refs/heads/release/v1.0.0')[:2], (False, True))
        self.assertEqual(pol(ENV_LOOKUP, 'push', 'refs/heads/chain/promo6')[:2], (False, False))
        for ev in ('merge_group', 'workflow_dispatch', 'schedule', 'pull_request_target'):
            self.assertEqual(pol(ENV_LOOKUP, ev, 'refs/heads/release/v1.0.0')[:2], (False, False), ev)

    def test_no_event_both_looks_up_and_records(self):
        for ev, ref in (('pull_request', 'refs/pull/1/merge'), ('push', 'refs/heads/release/v1.0.0'),
                        ('push', 'refs/heads/chain/x'), ('push', 'release/v1.0.0')):
            lookup, record, _ = tbc.cache_policy(ENV_LOOKUP, ev, ref)
            self.assertFalse(lookup and record, (ev, ref))

    def test_pr_plan_then_green_record_never_writes_the_manifest(self):
        self.plan(env=ENV_LOOKUP)
        out = self.record(0)
        self.assertIn('not recorded', out)
        self.assertEqual([p.name for p in self.mdir.iterdir() if p.name.endswith('.json')], [])

    def test_pr_cannot_overwrite_the_release_seed(self):
        self.plan(env=ENV_LOOKUP, event='push', ref='refs/heads/release/v1.0.0')
        self.record(0)
        seed = self.manifest()
        for n in tbc.SHARD_LISTS:
            (self.sd / (n + '.txt')).write_text((self.sd / (n + '.txt.full')).read_text())
        (self.root / 'tests' / 'a.rs').write_text('fn a() { pr }\n')
        self.plan(env=ENV_LOOKUP, run_id='200', now=NOW + 60)
        self.record(0, now=NOW + 60, run_id='200')
        self.assertEqual(self.manifest(), seed)

    def test_tampered_plan_claiming_record_with_skips_is_refused(self):
        self.plan(env=ENV_LOOKUP, event='push', ref='refs/heads/release/v1.0.0')
        plan = json.loads((self.sd / 'cache_plan.json').read_text())
        plan['skipped'] = {'test:a': {'key': 'x', 'result': 'pass', 'base': 'release/v1.0.0', 'recorded_at': NOW}}
        (self.sd / 'cache_plan.json').write_text(json.dumps(plan))
        self.assertIn('not recorded', self.record(0))
        self.assertEqual([p.name for p in self.mdir.iterdir() if p.name.endswith('.json')], [])

    def test_docstring_states_the_decision(self):
        doc = tbc.__doc__
        self.assertIn('pull_request', doc)
        self.assertIn('never writes the manifest', doc)


class SpecialFilesAndTimeout6384M3(World):
    """r1 M3: the tree walk never opens a FIFO, socket or device, and the plan
    has a hard deadline; on timeout nothing is skipped and the lists stay full."""

    def _digest_in_child(self):
        code = ('import sys; sys.path.insert(0, %r); import test_binary_cache as t; '
                'd = t.digest_runtime_tree(%r, False); print(len(d))' % (str(HERE.parent), str(self.root)))
        try:
            out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            self.fail('digest_runtime_tree blocked on a special file')
        self.assertEqual(out.returncode, 0, out.stderr)
        return out

    def test_fifo_in_tree_is_not_opened(self):
        os.mkfifo(str(self.root / 'stale.fifo'))
        self._digest_in_child()
        labels = dict(tbc.digest_runtime_tree(self.root, False))
        self.assertTrue(labels['rt:stale.fifo'].startswith('special:'), labels.get('rt:stale.fifo'))

    def test_socket_in_tree_is_not_opened(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.bind(str(self.root / 'x.sock'))
            self._digest_in_child()
            labels = dict(tbc.digest_runtime_tree(self.root, False))
            self.assertTrue(labels['rt:x.sock'].startswith('special:'))
        finally:
            s.close()

    def test_symlink_to_fifo_is_not_followed_into_a_read(self):
        os.mkfifo(str(self.root / 'pipe'))
        os.symlink('pipe', str(self.root / 'link-to-pipe'))
        self._digest_in_child()

    def test_symlink_to_regular_file_hashes_the_target_content(self):
        (self.root / 'data.txt').write_text('v1\n')
        os.symlink('data.txt', str(self.root / 'alias.txt'))
        d0 = dict(tbc.digest_runtime_tree(self.root, False))
        (self.root / 'data.txt').write_text('v2\n')
        d1 = dict(tbc.digest_runtime_tree(self.root, False))
        self.assertNotEqual(d0['rt:alias.txt'], d1['rt:alias.txt'])

    def test_plan_timeout_runs_every_binary(self):
        self.green_run('100')
        real = tbc.compute_keys

        def slow(*a, **kw):
            time.sleep(3)
            return real(*a, **kw)
        tbc.compute_keys = slow
        try:
            t0 = time.monotonic()
            out = self.plan(run_id='200', now=NOW + 60, timeout_seconds=0.5)
            elapsed = time.monotonic() - t0
        finally:
            tbc.compute_keys = real
        self.assertLess(elapsed, 2.5)
        self.assertIn('timed out', out)
        self.assertIn('::warning::', out)
        self.assertEqual(self.list_text('serial'), '--lib\n--test a\n')
        self.assertEqual(self.list_text('parallel_2'), '--test b\n')
        self.assertFalse(json.loads((self.sd / 'cache_plan.json').read_text())['enabled'])
        self.assertIn('not recorded', self.record(rc=0, run_id='200'))

    def test_cli_default_timeout_is_120_seconds(self):
        a = tbc.build_parser().parse_args(['plan', '--shard-dir', 's', '--manifest-dir', 'm', '--build-json', 'b',
                                           '--rustc-vv', 'r', '--tier', 't', '--node', 'n', '--base-ref', 'x',
                                           '--event', 'pull_request'])
        self.assertEqual(a.timeout_seconds, 120)

    def test_restore_puts_full_lists_back_and_disables_the_plan(self):
        self.green_run('100')
        self.plan(run_id='200', now=NOW + 60)
        self.assertEqual(self.list_text('parallel_2'), '')
        out = io.StringIO()
        with redirect_stdout(out):
            rc = tbc.main(['restore', '--shard-dir', str(self.sd)])
        self.assertEqual(rc, 0)
        self.assertEqual(self.list_text('serial'), '--lib\n--test a\n')
        self.assertEqual(self.list_text('parallel_1'), '--lib\n')
        self.assertEqual(self.list_text('parallel_2'), '--test b\n')
        self.assertFalse(json.loads((self.sd / 'cache_plan.json').read_text())['enabled'])
        self.assertEqual((self.sd / 'skip.txt').read_text() if (self.sd / 'skip.txt').exists() else '', '')
        self.assertIn('not recorded', self.record(rc=0, run_id='200'))


class DocsNotInRuntimeKey6384M4(World):
    """r1 M4: changelog.d/**, docs/** and *.md leave the run-time key of a
    binary whose sources never name them, so a docs-only change is a hit."""

    def add_docs(self, tag):
        (self.root / 'changelog.d').mkdir(exist_ok=True)
        (self.root / 'docs' / 'ci').mkdir(parents=True, exist_ok=True)
        (self.root / 'changelog.d' / '9999.changed.md').write_text(tag)
        (self.root / 'docs' / 'ci' / 'notes.txt').write_text(tag)
        (self.root / 'README.md').write_text(tag)

    def test_base_digest_ignores_docs_changelog_and_markdown(self):
        d0 = tbc.digest_runtime_tree(self.root, False)
        self.add_docs('x')
        self.assertEqual(d0, tbc.digest_runtime_tree(self.root, False))

    def test_full_digest_still_sees_docs(self):
        d0 = tbc.digest_runtime_tree(self.root, True)
        self.add_docs('x')
        self.assertNotEqual(d0, tbc.digest_runtime_tree(self.root, True))

    def test_non_doc_file_still_changes_the_base_digest(self):
        d0 = tbc.digest_runtime_tree(self.root, False)
        (self.root / 'config.toml').write_text('x = 1\n')
        self.assertNotEqual(d0, tbc.digest_runtime_tree(self.root, False))

    def test_docs_only_change_is_a_hit_for_binaries_that_never_read_docs(self):
        self.add_docs('v1')
        self.green_run('100')
        self.add_docs('v2')
        out = self.plan(run_id='200', now=NOW + 60)
        self.assertIn('skipped 3 of 3', out)

    def test_binary_naming_changelog_reruns_on_a_changelog_change(self):
        (self.root / 'tests' / 'b.rs').write_text('fn b() { let _ = std::fs::read_dir("changelog.d"); }\n')
        self.add_docs('v1')
        self.green_run('100')
        self.add_docs('v2')
        self.plan(run_id='200', now=NOW + 60)
        self.assertEqual(self.list_text('parallel_2'), '--test b\n')
        self.assertEqual(self.list_text('serial'), '')

    def test_binary_naming_docs_in_a_string_reruns(self):
        (self.root / 'tests' / 'b.rs').write_text('fn b() { let _ = std::path::Path::new("docs").join("x"); }\n')
        self.add_docs('v1')
        self.green_run('100')
        self.add_docs('v2')
        self.plan(run_id='200', now=NOW + 60)
        self.assertEqual(self.list_text('parallel_2'), '--test b\n')

    def test_mention_only_in_a_line_comment_does_not_count(self):
        (self.root / 'tests' / 'b.rs').write_text('// see docs/ci/CARRIER-BRANCH-GATES.md\nfn b() {}\n')
        self.add_docs('v1')
        self.green_run('100')
        self.add_docs('v2')
        self.plan(run_id='200', now=NOW + 60)
        self.assertEqual(self.list_text('parallel_2'), '')


class DocsMatchHitCases6384M4(unittest.TestCase):
    """r1 M4: the docs and the changelog describe the real hit cases."""

    def test_changelog_names_pull_requests_into_release_only(self):
        text = (REPO / 'changelog.d' / '6384.changed.md').read_text()
        self.assertNotIn('chain push', text)
        self.assertIn('pull request', text)
        self.assertIn('release/**', text)
        self.assertIn('never skips', text)
        self.assertIn('pull requests never write', text)

    def test_carrier_doc_has_no_chain_lookup_claim(self):
        text = (REPO / 'docs' / 'ci' / 'CARRIER-BRANCH-GATES.md').read_text()
        i = text.index('## Per-test-binary result cache (#6384)')
        sec = text[i:]
        nxt = sec.find('\n## ', 5)
        sec = sec[:nxt] if nxt > 0 else sec
        self.assertNotIn('`push` to `chain/**`', sec)
        self.assertNotIn('green chain tip', sec)
        self.assertNotIn('carried forward', sec)
        self.assertIn('CI_TEST_BINARY_CACHE_LOOKUP', sec)
        self.assertIn('never writes the manifest', ' '.join(sec.split()))


class BuildScriptInputs6384L1(World):
    """r1 L1: the build-script dep-info is found and the build-script run
    output (cfgs, env, the ``output`` file) is part of the shared key."""

    def add_build_script(self):
        b = self.root / 'target' / 'debug' / 'build' / 'ai-memory-abc123'
        b.mkdir(parents=True)
        (self.root / 'build.rs').write_text('fn main() {}\n')
        (b / 'build_script_build-abc123.d').write_text('%s: build.rs\n\nbuild.rs:\n' % (b / 'build_script_build-abc123'))
        (b / 'build-script-build').write_text('x')
        run = self.root / 'target' / 'debug' / 'build' / 'ai-memory-def456'
        (run / 'out').mkdir(parents=True)
        (run / 'output').write_text('cargo:rustc-cfg=has_x\\n')
        self.run_dir = run
        msg = {'reason': 'compiler-artifact', 'package_id': 'path+file:///repo#ai-memory@1.0.0',
               'target': {'kind': ['custom-build'], 'name': 'build-script-build', 'src_path': '/repo/build.rs'},
               'profile': {'test': False}, 'executable': None,
               'filenames': [str(b / 'build-script-build'), str(b / 'build_script_build-abc123')]}
        self.bs_msg = msg
        self.exec_msg = {'reason': 'build-script-executed', 'package_id': 'path+file:///repo#ai-memory@1.0.0',
                         'linked_libs': [], 'linked_paths': [], 'cfgs': ['has_x'], 'env': [['K', 'v']],
                         'out_dir': str(run / 'out')}
        self.bj.write_text(self.bj.read_text() + json.dumps(msg) + '\n' + json.dumps(self.exec_msg) + '\n')
        return b

    def test_build_script_depinfo_is_found(self):
        b = self.add_build_script()
        # The review probe's shape: only the build-script-build hard link.
        msg = dict(self.bs_msg, filenames=[str(b / 'build-script-build')])
        found = tbc.shared_depinfo_files([json.dumps(msg)])
        self.assertEqual(found, [b / 'build_script_build-abc123.d'])

    def test_build_script_cfg_change_changes_every_key(self):
        self.add_build_script()
        self.green_run('100')
        lines = self.bj.read_text().splitlines()
        self.exec_msg['cfgs'] = ['has_y']
        lines[-1] = json.dumps(self.exec_msg)
        self.bj.write_text('\n'.join(lines) + '\n')
        out = self.plan(run_id='200', now=NOW + 60)
        self.assertIn('skipped 0 of 3', out)

    def test_build_script_output_file_change_changes_every_key(self):
        self.add_build_script()
        self.green_run('100')
        (self.run_dir / 'output').write_text('cargo:rustc-cfg=has_z\\n')
        out = self.plan(run_id='200', now=NOW + 60)
        self.assertIn('skipped 0 of 3', out)

    def test_unchanged_build_script_still_hits(self):
        self.add_build_script()
        self.green_run('100')
        out = self.plan(run_id='200', now=NOW + 60)
        self.assertIn('skipped 3 of 3', out)


class StaleDepInfo6384L2(World):
    """r1 L2: only the dep-info this build wrote counts; old deps/<name>-*.d
    files left in a persistent target dir are ignored."""

    def test_uplifted_bin_does_not_glob_historical_depinfo(self):
        top = self.root / 'target' / 'debug'
        for h in ('old1', 'old2'):
            (self.deps / ('ai_memory-%s.d' % h)).write_text('x: gone-%s.rs\n' % h)
        (top / 'ai-memory.d').write_text('%s: src/lib.rs\n' % (top / 'ai-memory'))
        msg = art('bin', 'ai-memory', str(top / 'ai-memory'), False, filenames=[str(top / 'ai-memory')])
        self.assertEqual(tbc.shared_depinfo_files([msg]), [top / 'ai-memory.d'])

    def test_stale_depinfo_naming_a_deleted_file_does_not_disable_the_cache(self):
        top = self.root / 'target' / 'debug'
        (self.deps / 'ai_memory-old1.d').write_text('x: src/deleted.rs\n\nsrc/deleted.rs:\n')
        (top / 'ai-memory.d').write_text('%s: src/lib.rs\n' % (top / 'ai-memory'))
        self.bj.write_text(self.bj.read_text() + art('bin', 'ai-memory', str(top / 'ai-memory'), False,
                                                     filenames=[str(top / 'ai-memory')]) + '\n')
        self.green_run('100')
        out = self.plan(run_id='200', now=NOW + 60)
        self.assertIn('skipped 3 of 3', out)


class AuditBeforeRewrite6384L3(World):
    """r1 L3: the audit trail and cache_plan.json exist before any shard list
    is shortened, and a failure while replacing the lists restores them."""

    def test_audit_and_plan_precede_every_list_replacement(self):
        self.green_run('100')
        out = io.StringIO()
        events = []
        real_replace = os.replace

        def spy(src, dst):
            name = Path(dst).name
            if name in ('serial.txt', 'parallel_1.txt', 'parallel_2.txt'):
                events.append(('list', name, '::group::' in out.getvalue() and 'hit test:a' in out.getvalue(),
                               (self.sd / 'cache_plan.json').exists()
                               and json.loads((self.sd / 'cache_plan.json').read_text()).get('enabled')))
            return real_replace(src, dst)
        tbc.os.replace = spy
        try:
            with redirect_stdout(out):
                tbc.run_plan(self.args(run_id='200'), env=ENV_ON, now=NOW + 60)
        finally:
            tbc.os.replace = real_replace
        self.assertTrue(events)
        for ev in events:
            self.assertTrue(ev[2], 'audit not printed before %s was replaced' % ev[1])
            self.assertTrue(ev[3], 'enabled plan not written before %s was replaced' % ev[1])

    def test_failure_while_replacing_lists_restores_the_full_lists(self):
        self.green_run('100')
        real_replace = os.replace

        failed = []

        def boom(src, dst):
            if Path(dst).name == 'parallel_2.txt' and not failed:
                failed.append(dst)
                raise OSError(28, 'No space left on device')
            return real_replace(src, dst)
        tbc.os.replace = boom
        out = io.StringIO()
        try:
            with redirect_stdout(out):
                rc = tbc.run_plan(self.args(run_id='200'), env=ENV_ON, now=NOW + 60)
        finally:
            tbc.os.replace = real_replace
        self.assertEqual(rc, 0)
        self.assertIn('::warning::', out.getvalue())
        self.assertEqual(self.list_text('serial'), '--lib\n--test a\n')
        self.assertEqual(self.list_text('parallel_1'), '--lib\n')
        self.assertEqual(self.list_text('parallel_2'), '--test b\n')
        self.assertFalse(json.loads((self.sd / 'cache_plan.json').read_text())['enabled'])
        self.assertEqual([p.name for p in self.sd.iterdir() if p.name.endswith('.tmp')], [])


    def test_persistent_write_failure_exits_non_zero_so_the_workflow_restores_or_fails(self):
        self.green_run('100')
        real_replace = os.replace

        def boom(src, dst):
            if Path(dst).name == 'parallel_2.txt':
                raise OSError(28, 'No space left on device')
            return real_replace(src, dst)
        tbc.os.replace = boom
        try:
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(OSError):
                    tbc.run_plan(self.args(run_id='200'), env=ENV_ON, now=NOW + 60)
        finally:
            tbc.os.replace = real_replace
        self.assertFalse(json.loads((self.sd / 'cache_plan.json').read_text())['enabled'])


class LockAndSweep6384L4(World):
    """r1 L4: no lock means no record (lookup unaffected), and manifests,
    locks and temp files older than 7 days are swept."""

    OLD = 8 * 24 * 3600

    def _flock_fails(self):
        import fcntl
        real = fcntl.flock

        def fail(*_a, **_k):
            raise OSError(37, 'No locks available')
        fcntl.flock = fail
        self.addCleanup(setattr, fcntl, 'flock', real)

    def _age(self, path, seconds):
        old = time.time() - seconds
        os.utime(str(path), (old, old))

    def test_lock_failure_records_nothing(self):
        self.plan(event='push', ref='refs/heads/release/v1.0.0')
        self._flock_fails()
        out = self.record(0)
        self.assertIn('not recorded', out)
        self.assertFalse(tbc.manifest_path(self.mdir, 'linux-fed', 'enterprise-fed', 'release/v1.0.0').exists())

    def test_lock_failure_still_allows_lookup(self):
        self.green_run('100')
        self._flock_fails()
        self.assertIn('skipped 3 of 3', self.plan(run_id='200', now=NOW + 60))

    def test_record_sweeps_old_manifests_locks_and_tmp_files(self):
        old_m = self.mdir / 'test-manifest-stale.json'
        old_l = self.mdir / 'test-manifest-stale.json.lock'
        old_t = self.mdir / '.test-manifest-stale.json.123.tmp'
        fresh_t = self.mdir / '.test-manifest-other.json.456.tmp'
        for f in (old_m, old_l, old_t, fresh_t):
            f.write_text('{}')
        for f in (old_m, old_l, old_t):
            self._age(f, self.OLD)
        self.green_run('100')
        self.assertFalse(old_m.exists())
        self.assertFalse(old_l.exists())
        self.assertFalse(old_t.exists())
        self.assertTrue(fresh_t.exists())
        self.assertTrue(tbc.manifest_path(self.mdir, 'linux-fed', 'enterprise-fed', 'release/v1.0.0').exists())

    def test_sweep_keeps_the_lock_of_a_live_manifest(self):
        live = self.mdir / 'test-manifest-live.json'
        lock = self.mdir / 'test-manifest-live.json.lock'
        live.write_text('{}')
        lock.write_text('')
        self._age(lock, self.OLD)
        self.green_run('100')
        self.assertTrue(live.exists())
        self.assertTrue(lock.exists())

    def test_sweep_leaves_unrelated_files_alone(self):
        other = self.mdir / 'notes.txt'
        other.write_text('x')
        self._age(other, self.OLD)
        self.green_run('100')
        self.assertTrue(other.exists())


class ManifestNameAndDir6384L5(World):
    """r1 L5: the manifest file name is a hash of node, tier and base ref, and
    the manifest directory never lands inside the checkout."""

    def test_distinct_bases_never_share_a_file(self):
        a = tbc.manifest_path('/m', 'n', 't', 'release/v1')
        b = tbc.manifest_path('/m', 'n', 't', 'release_v1')
        self.assertNotEqual(a, b)
        self.assertNotEqual(tbc.manifest_path('/m', 'a-b', 'c', 'x'), tbc.manifest_path('/m', 'a', 'b-c', 'x'))
        self.assertRegex(a.name, r'^test-manifest-[0-9a-f]{32}\.json$')
        self.assertEqual(a, tbc.manifest_path('/m', 'n', 't', 'release/v1'))

    def test_dir_resolution_order(self):
        r = Path('/repo')
        self.assertEqual(tbc.resolve_manifest_dir('/x', {'HOME': '/h'}, r), Path('/x'))
        self.assertEqual(tbc.resolve_manifest_dir('', {'CI_TEST_MANIFEST_DIR': '/e', 'HOME': '/h'}, r), Path('/e'))
        self.assertEqual(tbc.resolve_manifest_dir('', {'HOME': '/h'}, r), Path('/h/.cache/ai-memory-ci/test-manifest'))
        self.assertEqual(tbc.resolve_manifest_dir('', {'HOME': '', 'RUNNER_TEMP': '/rt'}, r),
                         Path('/rt/ai-memory-ci/test-manifest'))
        self.assertEqual(tbc.resolve_manifest_dir('', {}, r), r / '.local-runs' / 'ai-memory-ci' / 'test-manifest')

    def test_plan_refuses_a_manifest_dir_inside_the_checkout(self):
        self.green_run('100')
        out = self.plan(run_id='200', now=NOW + 60, manifest_dir=str(self.root / '.cache' / 'm'))
        self.assertIn('::warning::', out)
        self.assertIn('inside the checkout', out)
        self.assertEqual(self.list_text('parallel_2'), '--test b\n')
        self.assertFalse((self.root / '.cache').exists())

    def test_record_refuses_a_manifest_dir_inside_the_checkout(self):
        self.plan(event='push', ref='refs/heads/release/v1.0.0')
        out = io.StringIO()
        with redirect_stdout(out):
            tbc.run_record(argparse.Namespace(shard_dir=str(self.sd), manifest_dir=str(self.root / '.cache' / 'm'),
                                              rc=0, run_id='100', sha='abc', repo_root=str(self.root)), now=NOW)
        self.assertIn('not recorded', out.getvalue())
        self.assertFalse((self.root / '.cache').exists())

    def test_local_runs_inside_the_checkout_is_allowed(self):
        mdir = self.root / '.local-runs' / 'm'
        self.plan(event='push', ref='refs/heads/release/v1.0.0', manifest_dir=str(mdir))
        out = io.StringIO()
        with redirect_stdout(out):
            tbc.run_record(argparse.Namespace(shard_dir=str(self.sd), manifest_dir=str(mdir), rc=0, run_id='100',
                                              sha='abc', repo_root=str(self.root)), now=NOW)
        self.assertIn('recorded', out.getvalue())
        self.assertTrue(tbc.manifest_path(mdir, 'linux-fed', 'enterprise-fed', 'release/v1.0.0').exists())


class Policy(unittest.TestCase):
    def test_allowed_matrix(self):
        on = {'CI_TEST_BINARY_CACHE': '1', 'CI_TEST_BINARY_CACHE_LOOKUP': '1'}
        self.assertTrue(tbc.cache_allowed(on, 'pull_request', 'refs/pull/9/merge')[0])
        self.assertFalse(tbc.cache_allowed(on, 'push', 'refs/heads/chain/x')[0])
        self.assertFalse(tbc.cache_allowed(on, 'push', 'refs/heads/release/v1.0.0')[0])
        self.assertEqual(tbc.cache_policy(on, 'push', 'refs/heads/release/v1.0.0')[:2], (False, True))
        self.assertEqual(tbc.cache_policy(on, 'pull_request', 'x')[:2], (True, False))
        self.assertEqual(tbc.cache_policy(on, 'push', 'refs/heads/main')[:2], (False, False))
        self.assertFalse(tbc.cache_allowed(on, 'push', 'refs/heads/main')[0])
        self.assertFalse(tbc.cache_allowed(on, 'merge_group', 'refs/heads/gh-readonly-queue/x')[0])
        self.assertFalse(tbc.cache_allowed(on, 'workflow_dispatch', '')[0])
        for off in ({}, {'CI_TEST_BINARY_CACHE': '0'}, {'CI_TEST_BINARY_CACHE': 'true'}):
            self.assertFalse(tbc.cache_allowed(off, 'pull_request', 'x')[0])
            self.assertEqual(tbc.cache_policy(off, 'push', 'refs/heads/release/v1.0.0')[:2], (False, False))


class PlanAndRecord(World):
    def test_release_push_never_skips_but_records(self):
        # Seed: a release push records every binary, skipping none.
        self.plan(event='push', ref='refs/heads/release/v1.0.0')
        self.assertEqual(self.list_text('serial'), '--lib\n--test a\n')
        self.assertEqual(self.list_text('parallel_2'), '--test b\n')
        self.assertFalse((self.sd / 'skip.txt').read_text())
        self.record(0)
        self.assertEqual(set(self.manifest()['entries']), {'lib:ai_memory', 'test:a', 'test:b'})
        # A second release push on the identical tree still runs everything.
        for n in tbc.SHARD_LISTS:
            (self.sd / (n + '.txt')).write_text((self.sd / (n + '.txt.full')).read_text())
        self.plan(event='push', ref='refs/heads/release/v1.0.0', run_id='101')
        self.assertEqual(self.list_text('parallel_2'), '--test b\n')
        self.assertFalse((self.sd / 'skip.txt').read_text())
        # A PR into that base then hits the seed.
        for n in tbc.SHARD_LISTS:
            (self.sd / (n + '.txt')).write_text((self.sd / (n + '.txt.full')).read_text())
        out = self.plan(run_id='102')
        self.assertIn('skipped 3 of 3', out)

    def test_first_run_skips_nothing_and_records_all(self):
        out = self.plan(event='push', ref='refs/heads/release/v1.0.0')
        self.assertIn('skipped 0 of 3 binaries (cache hits), running 3', out)
        self.assertEqual(self.list_text('serial'), '--lib\n--test a\n')
        self.record(0)
        m = self.manifest()
        self.assertEqual(set(m['entries']), {'lib:ai_memory', 'test:a', 'test:b'})
        for e in m['entries'].values():
            self.assertEqual((e['result'], e['run_id'], e['base'], e['recorded_at']), ('pass', '100', 'release/v1.0.0', NOW))

    def test_second_identical_run_skips_everything_and_prints_provenance(self):
        self.green_run('100')
        out = self.plan(run_id='200', now=NOW + 60)
        self.assertIn('skipped 3 of 3 binaries (cache hits), running 0', out)
        self.assertIn('prior_run_id=100 prior_sha=abc', out)
        for n in tbc.SHARD_LISTS:
            self.assertEqual(self.list_text(n), '')
            self.assertTrue((self.sd / (n + '.txt.full')).exists())
        self.assertEqual(sorted((self.sd / 'skip.txt').read_text().split()), ['lib:ai_memory', 'test:a', 'test:b'])

    def test_changed_binary_runs_others_skip_and_lib_leaves_both_lists(self):
        self.green_run('100')
        (self.root / 'tests' / 'b.rs').write_text('fn b() { 1 }\n')
        out = self.plan(run_id='200', now=NOW + 60)
        self.assertIn('skipped 2 of 3 binaries (cache hits), running 1', out)
        self.assertEqual(self.list_text('serial'), '')
        self.assertEqual(self.list_text('parallel_1'), '')
        self.assertEqual(self.list_text('parallel_2'), '--test b\n')

    def test_removed_lines_plus_kept_lines_equal_the_full_lists(self):
        self.green_run('100')
        (self.root / 'tests' / 'a.rs').write_text('fn a() { 1 }\n')
        self.plan(run_id='200', now=NOW + 60)
        for n in tbc.SHARD_LISTS:
            full = set((self.sd / (n + '.txt.full')).read_text().split('\n')) - {''}
            kept = set(self.list_text(n).split('\n')) - {''}
            self.assertTrue(kept <= full)
        self.assertEqual(self.list_text('serial'), '--test a\n')

    def test_reseed_records_fresh_provenance_because_it_ran_everything(self):
        self.green_run('100', now=NOW)
        self.green_run('200', now=NOW + 3600)
        for e in self.manifest()['entries'].values():
            self.assertEqual((e['run_id'], e['recorded_at']), ('200', NOW + 3600))

    def test_stale_entry_is_ignored_after_seven_days(self):
        self.green_run('100', now=NOW)
        out = self.plan(run_id='300', now=NOW + 7 * 24 * 3600 + 1)
        self.assertIn('skipped 0 of 3', out)
        out = self.plan(run_id='301', now=NOW + 7 * 24 * 3600 - 10)
        self.assertIn('skipped 3 of 3', out)

    def test_future_timestamp_is_ignored(self):
        self.green_run('100', now=NOW + 10_000)
        out = self.plan(run_id='300', now=NOW)
        self.assertIn('skipped 0 of 3', out)

    def test_other_base_tier_or_corrupt_manifest_ignored(self):
        self.green_run('100')
        out = self.plan(base_ref='release/v2.0.0', run_id='300', now=NOW + 5)
        self.assertIn('skipped 0 of 3', out)
        # tamper: a manifest whose top-level base lies about the entries' base
        mp = tbc.manifest_path(self.mdir, 'linux-fed', 'enterprise-fed', 'release/v1.0.0')
        data = json.loads(mp.read_text())
        for e in data['entries'].values():
            e['base'] = 'somewhere/else'
        mp.write_text(json.dumps(data))
        self.assertIn('skipped 0 of 3', self.plan(run_id='301', now=NOW + 5))
        mp.write_text('{not json')
        self.assertIn('skipped 0 of 3', self.plan(run_id='302', now=NOW + 5))

    def test_non_pass_result_is_never_a_hit(self):
        self.green_run('100')
        mp = tbc.manifest_path(self.mdir, 'linux-fed', 'enterprise-fed', 'release/v1.0.0')
        data = json.loads(mp.read_text())
        data['entries']['test:a']['result'] = 'fail'
        mp.write_text(json.dumps(data))
        self.plan(run_id='300', now=NOW + 5)
        self.assertEqual(self.list_text('serial'), '--test a\n')

    def test_release_push_and_flag_off_leave_lists_untouched(self):
        self.green_run('100')
        before = {n: self.list_text(n) for n in tbc.SHARD_LISTS}
        out = self.plan(event='push', ref='refs/heads/release/v1.0.0', run_id='400', now=NOW + 5)
        self.assertIn('skipped 0 of 3', out)
        out = self.plan(env={}, run_id='401', now=NOW + 5)
        self.assertIn('cache off', out)
        self.assertEqual(before, {n: self.list_text(n) for n in tbc.SHARD_LISTS})
        self.assertFalse(json.loads((self.sd / 'cache_plan.json').read_text())['enabled'])

    def test_record_refuses_on_nonzero_exit_and_when_cache_was_off(self):
        self.plan()
        self.assertIn('not recorded', self.record(rc=1))
        self.assertIn('not recorded', self.record(rc=124))
        self.assertFalse(tbc.manifest_path(self.mdir, 'linux-fed', 'enterprise-fed', 'release/v1.0.0').exists())
        self.plan(env={})
        self.assertIn('cache was off', self.record(rc=0))
        self.assertFalse(tbc.manifest_path(self.mdir, 'linux-fed', 'enterprise-fed', 'release/v1.0.0').exists())

    def test_failed_run_does_not_poison_or_erase_prior_green(self):
        self.green_run('100')
        (self.root / 'tests' / 'a.rs').write_text('fn a() { broken }\n')
        self.plan(run_id='200', now=NOW + 60)
        self.record(rc=101, now=NOW + 60, run_id='200')
        m = self.manifest()
        self.assertEqual({e['run_id'] for e in m['entries'].values()}, {'100'})

    def test_binary_without_key_always_runs_and_loses_its_old_entry(self):
        self.green_run('100')
        (self.deps / 'b-h4.d').unlink()
        self.plan(run_id='200', now=NOW + 60)
        self.assertEqual(self.list_text('parallel_2'), '--test b\n')
        self.green_run('201', now=NOW + 60)
        self.assertNotIn('test:b', self.manifest()['entries'])

    def test_internal_error_runs_everything(self):
        self.rustc.write_text('')
        out = self.plan()
        self.assertIn('::warning::', out)
        self.assertEqual(self.list_text('serial'), '--lib\n--test a\n')
        self.assertFalse(json.loads((self.sd / 'cache_plan.json').read_text())['enabled'])

    def test_partial_impact_run_keeps_untouched_prior_entries(self):
        self.green_run('100')
        # impact run that only built b: rebuild fixtures with b only
        lines = [l for l in self.bj.read_text().splitlines() if '"name": "a"' not in l]
        self.bj.write_text('\n'.join(lines) + '\n')
        self.lists()
        (self.sd / 'serial.txt').write_text('--lib\n')
        self.green_run('200', now=NOW + 60)
        self.assertIn('test:a', self.manifest()['entries'])


class ImpactSubsetBuild6384R2M1(World):
    """r2 M1(a): a key never depends on which targets this build compiled. An
    impact-mode PR (``--lib --test <impacted>``) on the seed's tree hits."""

    def full_build(self):
        top = self.root / 'target' / 'debug'
        (self.root / 'src' / 'main.rs').write_text('fn main() {}\n')
        (self.root / 'tests' / 'c.rs').write_text('fn c() {}\n')
        (self.deps / 'c-h5.d').write_text('target/debug/deps/c-h5: tests/c.rs\n\ntests/c.rs:\n')
        (top / 'ai-memory').write_text('bin')
        (top / 'ai-memory.d').write_text('%s: src/main.rs\n\nsrc/main.rs:\n' % (top / 'ai-memory'))
        (self.deps / 'ai_memory-h6').write_text('bin-test')
        (self.deps / 'ai_memory-h6.d').write_text('target/debug/deps/ai_memory-h6: src/main.rs\n\nsrc/main.rs:\n')
        d = str(self.deps)
        self.extra = [art('bin', 'ai-memory', d + '/ai_memory-h6', True), art('test', 'c', d + '/c-h5', True)]
        bin_line = art('bin', 'ai-memory', str(top / 'ai-memory'), False, filenames=[str(top / 'ai-memory')])
        self.bj.write_text(self.bj.read_text() + '\n'.join([bin_line] + self.extra) + '\n')
        (self.sd / 'serial.txt').write_text('--lib\n--test a\n--bin ai-memory\n')
        (self.sd / 'parallel_2.txt').write_text('--test b\n--test c\n')

    def impact_build(self):
        """What ``cargo test --lib --test a --test b`` reports: no bin unittest, no c."""
        lines = [l for l in self.bj.read_text().splitlines() if l and l not in self.extra]
        self.bj.write_text('\n'.join(lines) + '\n')
        self.lists()

    def test_subset_build_on_identical_tree_hits_lib_and_plain_tests(self):
        self.full_build()
        self.green_run('100')
        self.impact_build()
        out = self.plan(run_id='200', now=NOW + 60)
        self.assertIn('skipped 3 of 3', out)

    def test_subset_build_reruns_only_the_edited_test(self):
        self.full_build()
        self.green_run('100')
        (self.root / 'tests' / 'a.rs').write_text('fn a() { let _ = 2; }\n')
        self.impact_build()
        self.plan(run_id='200', now=NOW + 60)
        self.assertEqual(self.list_text('serial'), '--test a\n')
        self.assertEqual(self.list_text('parallel_2'), '')

    def test_subset_build_still_keys_an_orphan_under_tests(self):
        self.full_build()
        self.green_run('100')
        (self.root / 'tests' / 'common').mkdir()
        (self.root / 'tests' / 'common' / 'orphan.rs').write_text('fn o() {}\n')
        self.impact_build()
        out = self.plan(run_id='200', now=NOW + 60)
        self.assertIn('skipped 0 of 3', out)

    def test_test_profile_units_are_not_in_the_shared_closure(self):
        self.full_build()
        found = {p.name for p in tbc.shared_depinfo_files(self.bj.read_text().splitlines())}
        self.assertEqual(found, {'ai_memory-h2.d', 'ai-memory.d'})


class ChangelogKeyedOnlyForReaders6384R2M1(World):
    """r2 M1(b): changelog.d/ is in a binary's key only when the binary can
    read it (names ``changelog``, runs a tool or repo script, or walks the
    repo root); docs/ and *.md keep the r1 M4 rule."""

    def changelog(self, text):
        (self.root / 'changelog.d').mkdir(exist_ok=True)
        (self.root / 'changelog.d' / '1.changed.md').write_text(text)

    def seed_then_changelog_edit(self):
        self.changelog('v1')
        self.green_run('100')
        self.changelog('v2')
        return self.plan(run_id='200', now=NOW + 60)

    def test_docs_reader_that_never_names_changelog_hits(self):
        (self.root / 'src' / 'lib.rs').write_text('pub fn a() -> &\'static str { "docs/x.md" }\n')
        (self.root / 'tests' / 'b.rs').write_text('fn b() { let _ = std::path::Path::new("docs"); }\n')
        self.assertIn('skipped 3 of 3', self.seed_then_changelog_edit())

    def test_docs_reader_still_reruns_on_a_docs_edit(self):
        (self.root / 'tests' / 'b.rs').write_text('fn b() { let _ = std::path::Path::new("docs"); }\n')
        (self.root / 'docs').mkdir()
        (self.root / 'docs' / 'x.md').write_text('v1')
        self.green_run('100')
        (self.root / 'docs' / 'x.md').write_text('v2')
        self.plan(run_id='200', now=NOW + 60)
        self.assertEqual(self.list_text('parallel_2'), '--test b\n')

    def test_scanner_of_one_subtree_hits_on_a_changelog_edit(self):
        (self.root / 'tests' / 'b.rs').write_text(
            'fn b() { let _ = std::fs::read_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")); }\n')
        self.assertIn('skipped 3 of 3', self.seed_then_changelog_edit())

    def test_scanner_of_one_subtree_still_reruns_on_any_rs_edit(self):
        (self.root / 'tests' / 'b.rs').write_text(
            'fn b() { let _ = std::fs::read_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")); }\n')
        self.green_run('100')
        (self.root / 'tests' / 'a.rs').write_text('fn a() { let _ = 3; }\n')
        self.plan(run_id='200', now=NOW + 60)
        self.assertEqual(self.list_text('parallel_2'), '--test b\n')

    def test_scanner_of_the_repo_root_reruns_on_a_changelog_edit(self):
        for body in ('let _ = std::fs::read_dir(env!("CARGO_MANIFEST_DIR"));',
                     'let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")); let _ = std::fs::read_dir(&root);',
                     'let _ = std::fs::read_dir(".");'):
            with self.subTest(body=body):
                self.setUp()
                (self.root / 'tests' / 'b.rs').write_text('fn b() { %s }\n' % body)
                self.seed_then_changelog_edit()
                self.assertEqual(self.list_text('parallel_2'), '--test b\n')
                self.assertEqual(self.list_text('serial'), '')

    def test_binary_running_a_tool_or_repo_script_reruns_on_a_changelog_edit(self):
        (self.root / 'scripts').mkdir()
        (self.root / 'scripts' / 'x.sh').write_text('true\n')
        for body in ('let _ = std::process::Command::new("git");',
                     'let _ = std::path::Path::new("scripts/x.sh");'):
            with self.subTest(body=body):
                self.setUp()
                (self.root / 'scripts').mkdir(exist_ok=True)
                (self.root / 'scripts' / 'x.sh').write_text('true\n')
                (self.root / 'tests' / 'b.rs').write_text('fn b() { %s }\n' % body)
                self.seed_then_changelog_edit()
                self.assertEqual(self.list_text('parallel_2'), '--test b\n')

    def test_lib_naming_a_missing_script_path_is_not_a_reader(self):
        # A skill resource path such as "scripts/run.sh" is data, not a spawn.
        (self.root / 'src' / 'lib.rs').write_text('pub fn a() -> &\'static str { "scripts/run.sh" }\n')
        self.assertIn('skipped 3 of 3', self.seed_then_changelog_edit())


class RealTreeCensus6384R2M1(unittest.TestCase):
    """r2 M1(b) on the real tree: the tree-scanning integration tests do not
    all key on changelog.d/, and the lib does not."""

    def census(self):
        scanners = readers = 0
        for root in tbc.test_target_roots(REPO):
            texts = [p.read_text(errors='replace') for p in tbc.static_mod_closure(REPO, root)]
            traits = tbc.source_traits(texts, 'test', REPO)
            if traits['tree']:
                scanners += 1
                readers += traits['changelog']
        return scanners, readers

    def test_most_tree_scanners_do_not_key_on_changelog(self):
        scanners, readers = self.census()
        self.assertGreater(scanners, 100)
        self.assertLess(readers * 2, scanners, 'scanners=%d changelog readers=%d' % (scanners, readers))

    def test_lib_does_not_key_on_changelog(self):
        texts = [p.read_text(errors='replace') for p in sorted((REPO / 'src').rglob('*.rs'))]
        self.assertFalse(tbc.source_traits(texts, 'lib', REPO)['changelog'])


class HitCaseDocs6384R2M1(unittest.TestCase):
    """r2 M1(c)(d): the docs and the changelog state only hit cases CI can reach."""

    def section(self):
        text = (REPO / 'docs' / 'ci' / 'CARRIER-BRANCH-GATES.md').read_text()
        sec = text[text.index('## Per-test-binary result cache (#6384)'):]
        nxt = sec.find('\n## ', 5)
        return ' '.join((sec[:nxt] if nxt > 0 else sec).split())

    def test_carrier_doc_names_the_skip_path_and_drops_the_overclaims(self):
        sec = self.section()
        self.assertIn('__SKIP__', sec)
        self.assertNotIn('skips every binary whose code does not name them', sec)
        self.assertIn('changelog.d', sec)
        self.assertIn('impact', sec)

    def test_changelog_fragment_drops_the_documentation_only_claim(self):
        text = ' '.join((REPO / 'changelog.d' / '6384.changed.md').read_text().split())
        self.assertNotIn('are hits for every binary that does not read them', text)
        self.assertIn('__SKIP__', text)


FAKE_CARGO = """#!/usr/bin/env python3
import os, sys
sys.stdout.write(os.environ.get('FAKE_CARGO_OUT', ''))
sys.exit(int(os.environ.get('FAKE_CARGO_RC', '0')))
"""


class CargoAndPgSettingsInKey6384R2L1(World):
    """r2 L1: the cargo version and the Postgres settings that change test
    behaviour are key inputs; an unknown cargo version never yields a hit."""

    def reseed(self):
        for n in tbc.SHARD_LISTS:
            (self.sd / (n + '.txt')).write_text((self.sd / (n + '.txt.full')).read_text())

    def test_cargo_version_moves_every_key(self):
        exes = tbc.ptb.parse_build_json(self.bj.read_text().splitlines())
        lines = self.bj.read_text().splitlines()
        rv = self.rustc.read_text()
        k1, _ = tbc.compute_keys(exes, lines, self.root, rv, 'p', ENV_ON, cargo_v='cargo 1.98.0')
        k2, _ = tbc.compute_keys(exes, lines, self.root, rv, 'p', ENV_ON, cargo_v='cargo 1.99.0')
        self.assertTrue(k1)
        for n in k1:
            self.assertIsNotNone(k1[n], n)
            self.assertNotEqual(k1[n], k2[n], n)

    def test_cargo_upgrade_between_runs_means_no_hits(self):
        self.plan(event='push', ref='refs/heads/release/v1.0.0')
        self.record(0)
        self.reseed()
        self.assertIn('skipped 3 of 3', self.plan(run_id='2'))
        self.reseed()
        self.cargo_v.write_text('cargo 1.99.0 (fixture)\n')
        self.assertIn('skipped 0 of 3', self.plan(run_id='3'))

    def test_empty_cargo_v_file_means_no_skips(self):
        self.plan(event='push', ref='refs/heads/release/v1.0.0')
        self.record(0)
        self.reseed()
        self.cargo_v.write_text('')
        out = self.plan(run_id='2')
        self.assertIn('::warning::', out)
        self.assertEqual(self.list_text('serial'), '--lib\n--test a\n')

    def test_without_the_file_cargo_is_asked_and_a_failure_fails_closed(self):
        fake = SCRATCH / 'fake-cargo'
        fake.write_text(FAKE_CARGO)
        fake.chmod(0o755)
        env = dict(ENV_ON, FAKE_CARGO_OUT='cargo 1.98.0 (fixture)\n')
        self.assertEqual(tbc.cargo_version('', env, cargo=str(fake)), 'cargo 1.98.0 (fixture)\n')
        for e, c in ((dict(env, FAKE_CARGO_RC='3'), str(fake)), (dict(env, FAKE_CARGO_OUT=''), str(fake)),
                     (env, str(SCRATCH / 'no-such-cargo'))):
            with self.assertRaises(tbc.CacheError):
                tbc.cargo_version('', e, cargo=c)
        with self.assertRaises(tbc.CacheError):
            tbc.cargo_version(str(SCRATCH / 'missing-cargo-v.txt'), env, cargo=str(fake))

    def test_cli_takes_cargo_v(self):
        a = tbc.build_parser().parse_args(['plan', '--shard-dir', 's', '--build-json', 'b', '--rustc-vv', 'r',
                                           '--cargo-v', 'c', '--tier', 't', '--node', 'n', '--base-ref', 'x',
                                           '--event', 'pull_request'])
        self.assertEqual(a.cargo_v, 'c')

    def test_pg_fingerprint_reads_the_behaviour_settings(self):
        sql = ' '.join(tbc.PG_FINGERPRINT_SQL)
        for name in ('max_connections', 'shared_preload_libraries', 'server_version_num'):
            self.assertIn(name, sql)
        self.assertIn('installed_version', sql)
        self.assertIn("'age'", sql)
        self.assertIn("'vector'", sql)


class RedRecordingRunInvalidates6384R2L3(World):
    """r2 L3: a red release/** push (the recording run) removes every manifest
    entry whose key equals a key of its own plan, because one of those
    binaries may be the one that failed; entries with other keys stay."""

    def red_push(self, run_id='200', now=NOW + 60):
        self.plan(now=now, run_id=run_id, event='push', ref='refs/heads/release/v1.0.0')
        return self.record(rc=101, now=now, run_id=run_id)

    def test_same_keys_are_removed(self):
        self.green_run('100')
        self.assertEqual(set(self.manifest()['entries']), {'lib:ai_memory', 'test:a', 'test:b'})
        out = self.red_push()
        self.assertIn('invalidated', out)
        self.assertEqual(self.manifest()['entries'], {})
        for n in tbc.SHARD_LISTS:
            (self.sd / (n + '.txt')).write_text((self.sd / (n + '.txt.full')).read_text())
        self.assertIn('skipped 0 of 3', self.plan(run_id='300', now=NOW + 120))

    def test_entries_with_other_keys_stay(self):
        self.green_run('100')
        old_a = self.manifest()['entries']['test:a']['key']
        (self.root / 'tests' / 'a.rs').write_text('fn a() { changed }\n')
        self.red_push()
        entries = self.manifest()['entries']
        self.assertEqual(set(entries), {'test:a'})
        self.assertEqual(entries['test:a']['key'], old_a)

    def test_red_pull_request_changes_nothing(self):
        self.green_run('100')
        before = self.manifest()
        self.plan(run_id='200', now=NOW + 60)
        self.record(rc=101, now=NOW + 60, run_id='200')
        self.assertEqual(self.manifest(), before)


if __name__ == '__main__':
    unittest.main()
