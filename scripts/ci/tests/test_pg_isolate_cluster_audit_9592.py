#!/usr/bin/env python3
"""Unit tests for scripts/ci/pg_isolate_cluster_audit.py (#9592, vote 71472661 I-7).

Run: python3 -m unittest scripts/ci/tests/test_pg_isolate_cluster_audit_9592.py

Per-binary clones isolate one database, not the cluster. A test that runs a
cluster-global operation (roles, tablespaces, ALTER SYSTEM, a backend signal
or a pg_stat_activity read that is not scoped to its own database or pid), or
that asserts on wall time (the load-sensitive class of 8230 defect 2, issue
6796), must be on the residual list, where it runs alone on the shared
database after the pool has drained.
"""
import importlib.util
import subprocess
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / 'scripts' / 'ci' / 'pg_isolate_cluster_audit.py'
RESIDUAL = REPO / 'scripts' / 'ci' / 'pg_isolate_serial_residual.txt'
SCRATCH = REPO / '.local-runs' / 'test-pg-isolate-cluster-audit-9592'
LARGE_LINES = 120_000
LARGE_CEILING_SECS = 5.0


def load():
    spec = importlib.util.spec_from_file_location('pg_isolate_cluster_audit', SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules['pg_isolate_cluster_audit'] = mod
    spec.loader.exec_module(mod)
    return mod


class AuditText(unittest.TestCase):
    def setUp(self):
        self.a = load()

    def hits(self, text):
        return [(line, kind, token) for line, kind, token in self.a.audit_text(text)]

    def test_every_cluster_global_form_is_a_hit(self):
        forms = ['CREATE ROLE r', 'alter role r', 'DROP ROLE r', 'CREATE USER u', 'ALTER USER u',
                 'DROP USER u', 'CREATE TABLESPACE t', 'ALTER SYSTEM SET x = 1', 'SELECT pg_reload_conf()',
                 'SELECT pg_terminate_backend(pid) FROM pg_stat_activity',
                 'SELECT count(*) FROM pg_stat_activity']
        for form in forms:
            with self.subTest(form=form):
                found = self.hits('let q = "%s";\n' % form)
                self.assertTrue(found and all(k == 'cluster' for _, k, _ in found), found)

    def test_scoped_forms_are_not_hits(self):
        for form in ['SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))',
                     'SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()',
                     'SELECT pg_cancel_backend($1)',
                     'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1']:
            with self.subTest(form=form):
                self.assertEqual(self.hits('let q = "%s";\n' % form), [])

    def test_comment_lines_are_not_hits(self):
        self.assertEqual(self.hits('// the pg_stat_activity capture caught it\n/// CREATE ROLE r\n'), [])

    def test_a_wall_time_assert_is_a_load_hit(self):
        text = 'fn t() {\n    assert!(\n        started.elapsed() < Duration::from_secs(2),\n    );\n}\n'
        self.assertEqual(self.hits(text), [(3, 'load', 'elapsed()')])

    def test_elapsed_outside_an_assert_is_not_a_hit(self):
        self.assertEqual(self.hits('let took = started.elapsed();\nprintln!("{took:?}");\n'), [])

    def test_large_input_is_linear(self):
        text = 'let q = "SELECT 1";\n' * LARGE_LINES + 'let q = "CREATE ROLE r";\n'
        started = time.monotonic()
        found = self.hits(text)
        self.assertLess(time.monotonic() - started, LARGE_CEILING_SECS)
        self.assertEqual(found, [(LARGE_LINES + 1, 'cluster', 'create role')])


class Repo(unittest.TestCase):
    def setUp(self):
        self.a = load()
        self.root = SCRATCH / self.id().rsplit('.', 1)[-1]
        (self.root / 'tests' / 'role_9592').mkdir(parents=True, exist_ok=True)
        (self.root / 'tests' / 'role_9592.rs').write_text('mod inner;\n')
        (self.root / 'tests' / 'role_9592' / 'inner.rs').write_text('const Q: &str = "CREATE ROLE r";\n')
        (self.root / 'tests' / 'plain_9592.rs').write_text('const Q: &str = "SELECT 1";\n')
        self.residual = self.root / 'residual.txt'

    def run_cli(self, *names):
        self.residual.write_text(''.join(n + '\n' for n in names))
        return subprocess.run([sys.executable, str(SCRIPT), '--root', str(self.root),
                               '--residual-file', str(self.residual)], capture_output=True, text=True)

    def test_a_hit_in_a_sub_module_is_attributed_to_its_binary(self):
        found = self.a.audit_repo(self.root)
        self.assertEqual(sorted(found), ['role_9592'])
        self.assertEqual(found['role_9592'][0][1:], ('tests/role_9592/inner.rs', 1, 'cluster', 'create role'))

    def test_a_hit_outside_the_residual_list_fails(self):
        done = self.run_cli('other_9592')
        self.assertEqual(done.returncode, 1)
        self.assertIn('[#9592] cluster audit FAIL: role_9592 has a cluster hit at tests/role_9592/inner.rs:1 '
                      '(create role) but is not on the residual list', done.stdout)

    def test_a_hit_on_the_residual_list_passes(self):
        done = self.run_cli('role_9592')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('[#9592] cluster audit ok: hits=1 binaries=1', done.stdout)

    def test_the_real_tree_routes_every_hit_to_the_residual_list(self):
        done = subprocess.run([sys.executable, str(SCRIPT), '--root', str(REPO), '--residual-file', str(RESIDUAL)],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


if __name__ == '__main__':
    unittest.main()
