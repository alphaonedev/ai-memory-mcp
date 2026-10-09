#!/usr/bin/env python3
"""Unit tests for scripts/ci/test_binary_cache.py (#6384).

Run: python3 -m unittest scripts/ci/tests/test_test_binary_cache.py
Fixtures live under the repository's .local-runs/ (never the system temp dir).
No test runs cargo or rustc.
"""
import argparse
import io
import json
import shutil
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import test_binary_cache as tbc  # noqa: E402

REPO = HERE.parents[2]
SCRATCH = REPO / '.local-runs' / 'cache-unittests'
NOW = 1_800_000_000.0
ENV_ON = {'CI_TEST_BINARY_CACHE': '1', 'AI_MEMORY_NO_CONFIG': '1'}


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
                    no_runtime_tree=False)
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
        self.plan(now=now, run_id=run_id)
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
                          ('nocfg', {'env': {'CI_TEST_BINARY_CACHE': '1'}})):
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


class Policy(unittest.TestCase):
    def test_allowed_matrix(self):
        on = {'CI_TEST_BINARY_CACHE': '1'}
        self.assertTrue(tbc.cache_allowed(on, 'pull_request', 'refs/pull/9/merge')[0])
        self.assertTrue(tbc.cache_allowed(on, 'push', 'refs/heads/chain/x')[0])
        self.assertFalse(tbc.cache_allowed(on, 'push', 'refs/heads/release/v1.0.0')[0])
        self.assertEqual(tbc.cache_policy(on, 'push', 'refs/heads/release/v1.0.0')[:2], (False, True))
        self.assertEqual(tbc.cache_policy(on, 'pull_request', 'x')[:2], (True, True))
        self.assertEqual(tbc.cache_policy(on, 'push', 'refs/heads/main')[:2], (False, False))
        self.assertFalse(tbc.cache_allowed(on, 'push', 'refs/heads/main')[0])
        self.assertFalse(tbc.cache_allowed(on, 'merge_group', 'refs/heads/gh-readonly-queue/x')[0])
        self.assertFalse(tbc.cache_allowed(on, 'workflow_dispatch', '')[0])
        for off in ({}, {'CI_TEST_BINARY_CACHE': '0'}, {'CI_TEST_BINARY_CACHE': 'true'}):
            self.assertFalse(tbc.cache_allowed(off, 'pull_request', 'x')[0])


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
        out = self.plan()
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

    def test_carry_forward_keeps_original_provenance_and_age(self):
        self.green_run('100', now=NOW)
        self.green_run('200', now=NOW + 3600)
        for e in self.manifest()['entries'].values():
            self.assertEqual((e['run_id'], e['recorded_at']), ('100', NOW))

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
        self.record(0, now=NOW + 60, run_id='200')
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
        self.plan(run_id='200', now=NOW + 60)
        self.record(0, now=NOW + 60, run_id='200')
        self.assertIn('test:a', self.manifest()['entries'])


if __name__ == '__main__':
    unittest.main()
