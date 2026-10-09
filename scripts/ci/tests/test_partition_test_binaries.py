#!/usr/bin/env python3
"""Unit tests for scripts/ci/partition_test_binaries.py (#6344).

Run: python3 scripts/ci/tests/test_partition_test_binaries.py   (or python3 -m unittest scripts/ci/tests/test_partition_test_binaries.py)
Fixtures live in a scratch directory under the repository's .local-runs/ (never
the system temp directory).
"""
import json
import shutil
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import partition_test_binaries as pt  # noqa: E402

REPO = HERE.parents[2]
SCRATCH = REPO / '.local-runs' / 'partition-unittests'


def artifact(kind, name, src, executable=None, test=True):
    return json.dumps({
        'reason': 'compiler-artifact',
        'target': {'kind': kind, 'name': name, 'src_path': str(src)},
        'profile': {'test': test},
        'executable': executable or '/x/' + name,
    })


class Base(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        (SCRATCH / 'tests').mkdir(parents=True)
        (SCRATCH / 'src').mkdir()
        (SCRATCH / 'out').mkdir()

    def tearDown(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def write_src(self, name, text):
        p = SCRATCH / 'tests' / (name + '.rs')
        p.write_text(text)
        return p


class ParseTests(Base):
    def test_only_test_profile_executables_and_dedup(self):
        p = self.write_src('foo', '')
        lines = [
            artifact(['test'], 'foo', p, '/x/foo'),
            artifact(['test'], 'foo', p, '/x/foo'),
            artifact(['lib'], 'dep', p, None, test=False),
            artifact(['test'], 'bar', p, '/x/bar', test=False),
            '{"reason":"build-finished","success":true}',
            'not json',
        ]
        exes = pt.parse_build_json(lines)
        self.assertEqual([e.key for e in exes], ['test:foo'])

    def test_lib_bin_example_selectors(self):
        p = self.write_src('foo', '')
        exes = pt.parse_build_json([
            artifact(['lib', 'staticlib', 'cdylib'], 'ai_memory', p, '/x/l'),
            artifact(['bin'], 'ai-memory', p, '/x/b'),
            artifact(['example'], 'fed_issue', p, '/x/e'),
        ])
        self.assertEqual(sorted(e.selector for e in exes),
                         ['--bin ai-memory', '--example fed_issue', '--lib'])

    def test_empty_build_is_an_error(self):
        with self.assertRaises(pt.PartitionError):
            pt.parse_build_json(['{"reason":"build-finished"}'])

    def test_unsafe_name_is_an_error(self):
        p = self.write_src('foo', '')
        with self.assertRaises(pt.PartitionError):
            pt.parse_build_json([artifact(['test'], 'a b;rm', p)])


class ClassifyTests(Base):
    def cls(self, name, text):
        p = self.write_src(name, text)
        e = pt.Exe('test', name, str(p), '/x/' + name)
        pt.classify(e)
        return e

    def test_plain_is_b(self):
        e = self.cls('plain', 'fn main() { let _ = 1; }')
        self.assertEqual((e.cls, e.shared), ('b', []))

    def test_postgres_tokens_are_a(self):
        for i, tok in enumerate(['AI_MEMORY_TEST_POSTGRES_URL', 'sqlx::query', 'PgPool',
                                 '#[cfg(feature = "sal-postgres")]', 'PostgresStore',
                                 'common::lane_db::x']):
            self.assertEqual(self.cls('pg%d' % i, 'use %s;' % tok if 'cfg' not in tok else tok).cls, 'a', tok)

    def test_serial_is_a(self):
        self.assertEqual(self.cls('ser', '#[serial]\nfn t() {}').cls, 'a')
        self.assertEqual(self.cls('ser2', 'use serial_test::serial;').cls, 'a')

    def test_federat_name_is_a(self):
        e = self.cls('federation_scale', 'fn x() {}')
        self.assertEqual(e.cls, 'a')
        self.assertIn('name:federat', e.reasons)

    def test_unknown_source_is_a(self):
        e = pt.Exe('test', 'ghost', str(SCRATCH / 'tests' / 'ghost.rs'), '/x/ghost')
        pt.classify(e)
        self.assertEqual((e.cls, e.reasons), ('a', ['unknown-source']))
        e2 = pt.Exe('test', 'nopath', '', '/x/nopath')
        pt.classify(e2)
        self.assertEqual(e2.cls, 'a')

    def test_module_directory_is_scanned(self):
        p = self.write_src('modded', 'mod helpers;')
        d = SCRATCH / 'tests' / 'modded'
        d.mkdir()
        (d / 'helpers.rs').write_text('use sqlx::PgPool;')
        e = pt.Exe('test', 'modded', str(p), '/x/m')
        pt.classify(e)
        self.assertEqual(e.cls, 'a')

    def test_main_rs_target_scans_its_directory(self):
        d = SCRATCH / 'tests' / 'dirtest'
        d.mkdir()
        (d / 'main.rs').write_text('mod a;')
        (d / 'a.rs').write_text('#[serial]')
        e = pt.Exe('test', 'dirtest', str(d / 'main.rs'), '/x/d')
        pt.classify(e)
        self.assertEqual(e.cls, 'a')

    def test_ports_and_shared_paths_mark_shared(self):
        self.assertEqual(self.cls('portly', 'let u = "http://127.0.0.1:11434/x";').shared, ['port'])
        self.assertEqual(self.cls('pathy', 'let p = "/tmp/shared.db";').shared, ['shared-path'])
        self.assertEqual(self.cls('ephemeral', 'bind("127.0.0.1:0")').shared, [])


class PartitionTests(Base):
    def build(self, specs, lib=True):
        lines = []
        if lib:
            lines.append(artifact(['lib'], 'ai_memory', SCRATCH / 'src' / 'lib.rs', '/x/lib'))
        for name, text in specs.items():
            lines.append(artifact(['test'], name, self.write_src(name, text), '/x/' + name))
        return pt.parse_build_json(lines)

    def weights(self, **kw):
        w = {'lib:pg': 5.0, 'lib:nonpg': 100.0}
        w.update({'test:' + k: v for k, v in kw.items()})
        return w

    def test_disjoint_and_complete(self):
        exes = self.build({'a1': 'PgPool', 'b1': '', 'b2': '', 'b3': '', 'federation_x': ''})
        serial, h1, h2, has_lib, totals, _ = pt.partition(
            exes, self.weights(a1=1, b1=40, b2=30, b3=20, federation_x=2), ['store::postgres'])
        pt.write_lists(SCRATCH / 'out', serial, h1, h2, has_lib)
        pt.verify_written(SCRATCH / 'out', exes)
        self.assertEqual({e.name for e in serial}, {'a1', 'federation_x'})
        self.assertEqual({e.name for e in h1} | {e.name for e in h2}, {'b1', 'b2', 'b3'})
        self.assertTrue((SCRATCH / 'out' / 'serial.txt').read_text().startswith('--lib\n'))
        self.assertTrue((SCRATCH / 'out' / 'parallel_1.txt').read_text().startswith('--lib\n'))
        self.assertNotIn('--lib', (SCRATCH / 'out' / 'parallel_2.txt').read_text())

    def test_balance_prefers_the_lighter_half(self):
        exes = self.build({'b1': '', 'b2': '', 'b3': ''})
        _, h1, h2, _, totals, _ = pt.partition(exes, self.weights(b1=90, b2=60, b3=50), [])
        # half 1 starts with the lib (100): 90 and 60 go to half 2 (0, then 90 < 100), 50 to half 1.
        self.assertEqual(sorted(e.name for e in h2), ['b1', 'b2'])
        self.assertEqual([e.name for e in h1], ['b3'])
        self.assertAlmostEqual(totals['parallel_1'], 150.0)
        self.assertAlmostEqual(totals['parallel_2'], 150.0)

    def test_shared_binaries_share_one_half(self):
        exes = self.build({'p1': 'x = "127.0.0.1:9077"', 'p2': 'f = "/tmp/x"', 'p3': '"localhost:5555"',
                           'f1': '', 'f2': '', 'f3': ''})
        _, h1, h2, _, _, _ = pt.partition(
            exes, self.weights(p1=50, p2=50, p3=50, f1=40, f2=40, f3=40), [])
        halves = [{e.name for e in h1}, {e.name for e in h2}]
        homes = [i for i, h in enumerate(halves) if {'p1', 'p2', 'p3'} & h]
        self.assertEqual(len(homes), 1)
        self.assertTrue({'p1', 'p2', 'p3'} <= halves[homes[0]])

    def test_unmeasured_uses_class_mean(self):
        exes = self.build({'b1': '', 'new_b': '', 'a1': 'PgPool', 'new_a': '#[serial]'})
        _, _, _, _, totals, means = pt.partition(exes, self.weights(b1=10, a1=30), [])
        self.assertEqual(means, {'a': 30.0, 'b': 10.0})
        self.assertAlmostEqual(totals['serial'], 5.0 + 30.0 + 30.0)

    def test_verify_catches_overlap_and_missing(self):
        exes = self.build({'b1': '', 'b2': ''})
        serial, h1, h2, has_lib, _, _ = pt.partition(exes, self.weights(b1=1, b2=1), [])
        pt.write_lists(SCRATCH / 'out', serial, h1, h2, has_lib)
        p1 = SCRATCH / 'out' / 'parallel_1.txt'
        p2 = SCRATCH / 'out' / 'parallel_2.txt'
        both = (p1.read_text() + p2.read_text()).replace('--lib\n', '')
        # overlap: duplicate a line into the other half
        line = [l for l in both.splitlines() if l][0]
        p2.write_text(p2.read_text() + line + '\n')
        p1.write_text(p1.read_text() + line + '\n')
        with self.assertRaises(pt.PartitionError):
            pt.verify_written(SCRATCH / 'out', exes)
        # missing: drop everything but --lib from both halves
        p1.write_text('--lib\n')
        p2.write_text('')
        with self.assertRaises(pt.PartitionError):
            pt.verify_written(SCRATCH / 'out', exes)

    def test_lib_misplacement_is_caught(self):
        exes = self.build({'b1': ''})
        serial, h1, h2, has_lib, _, _ = pt.partition(exes, self.weights(b1=1), [])
        pt.write_lists(SCRATCH / 'out', serial, h1, h2, has_lib)
        (SCRATCH / 'out' / 'parallel_2.txt').write_text('--lib\n')
        with self.assertRaises(pt.PartitionError):
            pt.verify_written(SCRATCH / 'out', exes)

    def test_deterministic(self):
        specs = {'b%d' % i: '' for i in range(12)}
        w = self.weights(**{'b%d' % i: float(i % 5 + 1) for i in range(12)})
        runs = []
        for _ in range(2):
            exes = self.build(specs)
            _, h1, h2, _, _, _ = pt.partition(exes, w, [])
            runs.append(([e.name for e in h1], [e.name for e in h2]))
        self.assertEqual(runs[0], runs[1])


class LibPrefixTests(Base):
    def test_covered_and_uncovered_modules(self):
        src = SCRATCH / 'src'
        (src / 'store').mkdir()
        (src / 'store' / 'postgres.rs').write_text('std::env::var("AI_MEMORY_TEST_POSTGRES_URL")')
        (src / 'store' / 'postgres').mkdir()
        (src / 'store' / 'postgres' / 'tx_retry.rs').write_text('env::var("AI_MEMORY_TEST_POSTGRES_URL")')
        (src / 'newmod.rs').write_text('std::env::var( "AI_MEMORY_TEST_POSTGRES_URL" )')
        (src / 'commentonly.rs').write_text('// reads `AI_MEMORY_TEST_POSTGRES_URL` in docs')
        self.assertEqual(pt.uncovered_lib_pg_modules(src, ['store::postgres']), ['newmod'])
        self.assertEqual(pt.uncovered_lib_pg_modules(src, ['store::postgres', 'newmod::t']), [])

    def test_module_path(self):
        root = Path('/r/src')
        self.assertEqual(pt.module_path_of(Path('/r/src/store/postgres.rs'), root), 'store::postgres')
        self.assertEqual(pt.module_path_of(Path('/r/src/cli/mod.rs'), root), 'cli')

    def test_real_tree_has_no_uncovered_lib_pg_module(self):
        prefixes = pt.load_prefixes(HERE.parent / 'lib_pg_prefixes.txt')
        self.assertTrue(prefixes)
        self.assertEqual(pt.uncovered_lib_pg_modules(REPO / 'src', prefixes), [])

    def test_run_fails_closed_without_prefixes(self):
        lines = [artifact(['lib'], 'ai_memory', SCRATCH / 'src' / 'lib.rs', '/x/lib')]
        (SCRATCH / 'b.jsonl').write_text('\n'.join(lines))
        (SCRATCH / 'empty.txt').write_text('# none\n')
        rc = pt.main(['--build-json', str(SCRATCH / 'b.jsonl'), '--out-dir', str(SCRATCH / 'out'),
                      '--repo-root', str(SCRATCH), '--lib-pg-prefixes', str(SCRATCH / 'empty.txt')])
        self.assertEqual(rc, 2)


class WeightTableTests(unittest.TestCase):
    def test_vendored_table_is_well_formed(self):
        w = pt.load_weights(HERE.parent / 'test_binary_weights.json')
        self.assertIn('lib:pg', w)
        self.assertIn('lib:nonpg', w)
        self.assertTrue(all(v >= 0 for v in w.values()))


if __name__ == '__main__':
    unittest.main()
