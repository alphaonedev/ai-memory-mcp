#!/usr/bin/env python3
"""The by-design residual rows of scripts/ci/pg_isolate_serial_residual.txt (#9592 B(i)/(ii)).

Run: python3 -m unittest scripts/ci/tests/test_pg_isolate_residual_by_design_9592.py

A per-binary clone is CREATE DATABASE ... TEMPLATE <db>_tpl, and the template
holds the age and vector extensions only (scripts/test/pg_isolated_binary.py,
setup), so every isolated binary starts on an empty, un-migrated database.
Two binaries cannot hold under that by design, and CI job 136822077211 failed
both in the isolated serial step:

* pg_health_probe_constant_cost_2617 never writes a row: cell B counts the
  rows other binaries left in ``memories`` and needs at least two of them.
* pg_record_stop_write_gate_ttl_3276 asserts that the first write lands inside
  the 1000 ms re-check window, and that window is seeded in
  PostgresStore::connect BEFORE the migration ladder runs, so on a fresh
  database the ladder itself can use up the window (it did, under CI load).

Each row is pinned to the source line that makes it by design. When that line
goes away (the test seeds its own corpus, or connect seeds the clock after the
ladder), the test here goes red so the row is removed: residual rows only fall.
The expected rows are written out by hand, never read from the residual file.
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
RESIDUAL = REPO / 'scripts' / 'ci' / 'pg_isolate_serial_residual.txt'
POSTGRES_RS = REPO / 'src' / 'store' / 'postgres.rs'

# name -> (test file, the source text that makes isolation impossible by design)
BY_DESIGN = {
    'pg_health_probe_constant_cost_2617': (
        'tests/pg_health_probe_constant_cost_2617.rs',
        ('"SELECT COUNT(*)::BIGINT FROM memories"',
         'point AI_MEMORY_TEST_POSTGRES_URL at a populated database'),
    ),
    'pg_record_stop_write_gate_ttl_3276': (
        'tests/pg_record_stop_write_gate_ttl_3276.rs',
        ('within the TTL window the write gate must ride the local cache',
         'PostgresStore::connect(&url).await.expect("connect store_a")'),
    ),
}
CLOCK_SEED = 'std::sync::atomic::AtomicU64::new(record_stop_refresh_now_ms())'
LADDER = 'store.migrate_locked_with_contention_retry().await?;'
CONNECT = 'pub async fn connect(url: &str) -> StoreResult<Self> {'


def residual_names(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith('#')]


class ResidualByDesign(unittest.TestCase):

    def setUp(self):
        self.text = RESIDUAL.read_text(encoding='utf-8')
        self.names = residual_names(self.text)

    def test_each_by_design_binary_is_a_residual_row_once(self):
        for name in BY_DESIGN:
            with self.subTest(name=name):
                self.assertEqual(self.names.count(name), 1,
                                 '%s must be exactly one residual row (#9592 B(i)/(ii))' % name)

    def test_each_row_carries_its_reason_comment(self):
        for name, (path, _) in BY_DESIGN.items():
            with self.subTest(name=name):
                self.assertRegex(self.text, r'#[^\n]*%s' % re.escape(path),
                                 'the residual file must cite %s for %s' % (path, name))

    def test_the_by_design_source_lines_still_exist(self):
        for name, (path, anchors) in BY_DESIGN.items():
            src = (REPO / path).read_text(encoding='utf-8')
            for anchor in anchors:
                with self.subTest(name=name, anchor=anchor):
                    self.assertIn(anchor, src, '%s no longer has %r: re-check whether %s still needs its '
                                  'residual row and remove it if not' % (path, anchor, name))

    def test_connect_seeds_the_record_stop_clock_before_the_ladder(self):
        src = POSTGRES_RS.read_text(encoding='utf-8')
        start = src.index(CONNECT)
        seed, ladder = src.find(CLOCK_SEED, start), src.find(LADDER, start)
        self.assertNotEqual(seed, -1, 'connect no longer seeds the #3276 clock as pinned')
        self.assertNotEqual(ladder, -1, 'connect no longer runs the migration ladder as pinned')
        self.assertLess(seed, ladder, 'connect seeds the #3276 clock after the ladder now: '
                        'pg_record_stop_write_gate_ttl_3276 may leave the residual list')


if __name__ == '__main__':
    unittest.main()
