#!/usr/bin/env python3
"""Serial-to-parallel rebalance rules and the machine-checked move list (#7343).

The enterprise-fed serial shard held 579 of 1010 executables and its own
estimate (6274 s) was above the watchdog budget. Two rules put binaries in the
serial shard without any host-global state behind them:

* ``pg-mention-only``  the source names Postgres (a type, a ``postgres://``
  literal, a cfg gate, a comment) but never the per-job database URL variable
  or a helper that reads it, so it cannot reach the shared database;
* ``name-federat-only``  nothing but the ``federat`` word in the target name.

A binary that moves keeps every other guard: fixed ports and shared paths put
it in the same-half group, ``#[serial]`` and real database use keep it serial.
``scripts/ci/serial_to_parallel_moves.txt`` records each move with its reason;
this test recomputes the set from the repository sources and fails on any
difference, so a new move (or a stale entry) is a conscious edit.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only. Fixtures live under .local-runs/.
"""
import re
import shutil
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import partition_test_binaries as pt  # noqa: E402

REPO = HERE.parents[2]
MOVES = REPO / 'scripts' / 'ci' / 'serial_to_parallel_moves.txt'
SCRATCH = REPO / '.local-runs' / 'serial-moves-7343'
ALLOWED_REASONS = ('name-federat-only', 'pg-mention-only', 'name-federat-only+pg-mention-only')


class Fixture(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        (SCRATCH / 'tests').mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def cls(self, name, text):
        p = SCRATCH / 'tests' / (name + '.rs')
        p.write_text(text)
        e = pt.Exe('test', name, str(p), '/x/' + name)
        pt.classify(e)
        return e


class MentionRule(Fixture):
    def test_mention_only_tokens_move(self):
        for i, src in enumerate([
                'use sqlx::PgPool;',
                'fn f(_: &PostgresStore) {}',
                '#![cfg(feature = "sal-postgres")]',
                'const U: &str = "postgres://u:p@127.0.0.1:1/db";',
                '// PostgresStore::store is covered elsewhere',
        ]):
            e = self.cls('mention%d' % i, src)
            self.assertEqual((e.cls, e.moved), ('b', ['pg-mention-only']), src)

    def test_database_use_stays_serial(self):
        for i, src in enumerate([
                'let u = std::env::var("AI_MEMORY_TEST_POSTGRES_URL");',
                'let u = std::env::var("AI_MEMORY_TEST_AGE_URL");',
                'let u = common::postgres_env::url();',
                'let u = postgres_url();',
                'use common::lane_db::LaneDb;',
                'use common::pg_isolate::isolated_url;',
                'use common::pg_barrier::with_database;',
        ]):
            e = self.cls('use%d' % i, 'use sqlx::PgPool;\n' + src)
            self.assertEqual((e.cls, e.moved), ('a', []), src)
            self.assertTrue(any(r.startswith('pg:') for r in e.reasons), e.reasons)

    def test_serial_attribute_still_serial(self):
        e = self.cls('ser', 'use sqlx::PgPool;\n#[serial]\nfn t() {}')
        self.assertEqual((e.cls, e.moved), ('a', []))


class FederatNameRule(Fixture):
    def test_name_only_moves(self):
        e = self.cls('federation_scale', 'fn x() {}')
        self.assertEqual((e.cls, e.moved, e.reasons), ('b', ['name-federat-only'], []))

    def test_name_with_database_use_stays_serial(self):
        e = self.cls('federation_pg', 'let u = std::env::var("AI_MEMORY_TEST_POSTGRES_URL");')
        self.assertEqual((e.cls, e.moved), ('a', []))
        self.assertNotIn('name:federat', e.reasons)

    def test_name_with_fixed_port_joins_the_same_half_group(self):
        e = self.cls('federation_port', 'let a = "127.0.0.1:19090";')
        self.assertEqual((e.cls, e.shared, e.moved), ('b', ['port'], ['name-federat-only']))

    def test_name_with_shared_path_joins_the_same_half_group(self):
        e = self.cls('federation_path', 'let a = "/tmp/fed.sock";')
        self.assertEqual((e.cls, e.shared), ('b', ['shared-path']))

    def test_both_reasons_are_recorded_sorted(self):
        e = self.cls('federation_mention', 'use sqlx::PgPool;')
        self.assertEqual((e.cls, e.moved), ('b', ['name-federat-only', 'pg-mention-only']))

    def test_unknown_source_never_moves(self):
        e = pt.Exe('test', 'federation_ghost', str(SCRATCH / 'tests' / 'ghost.rs'), '/x/g')
        pt.classify(e)
        self.assertEqual((e.cls, e.reasons, e.moved), ('a', ['unknown-source'], []))


def repo_test_exes():
    """The repository's integration-test targets: tests/*.rs, tests/*/main.rs and [[test]] paths."""
    found = {}
    for f in sorted((REPO / 'tests').glob('*.rs')):
        found[f.stem] = f
    for f in sorted((REPO / 'tests').glob('*/main.rs')):
        found[f.parent.name] = f
    cargo = (REPO / 'Cargo.toml').read_text()
    for m in re.finditer(r'\[\[test\]\]\s*\nname\s*=\s*"([^"]+)"\s*\npath\s*=\s*"([^"]+)"', cargo):
        found[m.group(1)] = REPO / m.group(2)
    return [pt.Exe('test', n, str(p), '/x/' + n) for n, p in sorted(found.items())]


def computed_moves():
    exes = repo_test_exes()
    index = pt.SourceIndex(exes)
    out = {}
    for e in exes:
        pt.classify(e, index)
        if e.cls == 'b' and e.moved:
            out[e.key] = '+'.join(e.moved)
    return out


def listed_moves():
    out = {}
    for ln in MOVES.read_text().splitlines():
        if not ln.strip() or ln.startswith('#'):
            continue
        key, _, reason = ln.partition('\t')
        out[key] = reason
    return out


class MoveList(unittest.TestCase):
    def test_list_exists_sorted_with_a_reason_per_entry(self):
        lines = [ln for ln in MOVES.read_text().splitlines() if ln.strip() and not ln.startswith('#')]
        self.assertTrue(lines, 'the move list is empty')
        keys = [ln.split('\t')[0] for ln in lines]
        self.assertEqual(keys, sorted(keys), 'the move list must be sorted by target key')
        self.assertEqual(len(keys), len(set(keys)), 'duplicate entry')
        for ln in lines:
            parts = ln.split('\t')
            self.assertEqual(len(parts), 2, 'entry %r needs "<kind:name><TAB><reason>"' % ln)
            self.assertIn(parts[1], ALLOWED_REASONS, ln)

    def test_list_matches_the_partitioner(self):
        want, got = computed_moves(), listed_moves()
        missing = sorted(set(want) - set(got))
        stale = sorted(set(got) - set(want))
        wrong = sorted(k for k in set(want) & set(got) if want[k] != got[k])
        self.assertEqual((missing, stale, wrong), ([], [], []),
                         'regenerate with: python3 scripts/ci/partition_test_binaries.py --print-moves --repo-root <repo> '
                         '(missing=%s stale=%s wrong-reason=%s)' % (missing, stale, wrong))

    def test_every_listed_binary_is_a_real_target(self):
        names = {e.key for e in repo_test_exes()}
        for key in listed_moves():
            self.assertIn(key, names)

    def test_moves_are_a_material_share_of_the_serial_shard(self):
        self.assertGreaterEqual(len(listed_moves()), 40)


if __name__ == '__main__':
    unittest.main()
