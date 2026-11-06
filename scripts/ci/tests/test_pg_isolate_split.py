#!/usr/bin/env python3
"""Unit tests for scripts/ci/pg_isolate_split.py (#6383 / #6386).

Run: python3 -m unittest scripts/ci/tests/test_pg_isolate_split.py
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('pg_isolate_split', REPO / 'scripts' / 'ci' / 'pg_isolate_split.py')
split_mod = importlib.util.module_from_spec(SPEC)
sys.modules['pg_isolate_split'] = split_mod
SPEC.loader.exec_module(split_mod)


def artifact(name, src, kind='test'):
    return json.dumps({'reason': 'compiler-artifact', 'executable': '/x/' + name,
                       'profile': {'test': True},
                       'target': {'kind': [kind], 'name': name, 'src_path': str(src)}})


class Split(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(dir=str(REPO / 'scripts' / 'ci' / 'tests'))
        self.root = Path(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def write(self, name, body):
        p = self.root / (name + '.rs')
        p.write_text(body)
        return p

    def test_pooled_residual_and_other(self):
        plain = self.write('plain_pg', 'fn f(){ std::env::var("AI_MEMORY_TEST_POSTGRES_URL"); }')
        port = self.write('port_pg', 'const A: &str = "127.0.0.1:18080";')
        listed = self.write('a2a_campaign_round1', 'fn f(){}')
        exes = split_mod.ptb.parse_build_json([
            artifact('plain_pg', plain), artifact('port_pg', port),
            artifact('a2a_campaign_round1', listed), artifact('demo', plain, 'example'),
        ])
        targets, residual, other = split_mod.split(
            ['--lib', '--test plain_pg', '--test port_pg', '--test a2a_campaign_round1', '--example demo'],
            exes, {'a2a_campaign_round1'})
        self.assertEqual(targets, ['--test plain_pg', '--test port_pg', '--test a2a_campaign_round1'])
        self.assertEqual(sorted(residual), ['a2a_campaign_round1', 'port_pg'])
        self.assertEqual(other, ['--example demo'])

    def test_unknown_source_is_residual(self):
        exes = split_mod.ptb.parse_build_json([artifact('ghost', self.root / 'missing.rs')])
        _, residual, _ = split_mod.split(['--test ghost'], exes, set())
        self.assertEqual(residual, ['ghost'])

    def test_selector_not_built_fails_closed(self):
        exes = split_mod.ptb.parse_build_json([artifact('a', self.write('a', 'fn f(){}'))])
        with self.assertRaises(split_mod.SplitError):
            split_mod.split(['--test nope'], exes, set())

    def test_static_residual_names_are_validated(self):
        bad = self.root / 'r.txt'
        bad.write_text('ok_name\nbad name;rm\n')
        with self.assertRaises(split_mod.SplitError):
            split_mod.load_static_residual(bad)

    def test_shipped_residual_file_loads(self):
        names = split_mod.load_static_residual(REPO / 'scripts' / 'ci' / 'pg_isolate_serial_residual.txt')
        self.assertIn('a2a_campaign_round1', names)


if __name__ == '__main__':
    unittest.main()
