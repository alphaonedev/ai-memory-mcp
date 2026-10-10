#!/usr/bin/env python3
"""Unit tests for scripts/ci/check_shared_test_db_refs.py (#7031 H4)."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / 'scripts' / 'ci' / 'check_shared_test_db_refs.py'
NAME = 'ai_memory' + '_test'  # built so this file never matches its own gate
SCRATCH = ROOT / '.local-runs'


def gate(root: Path, *extra: str) -> 'subprocess.CompletedProcess[str]':
    return subprocess.run([sys.executable, str(GATE), '--root', str(root)] + list(extra),
                          capture_output=True, text=True, check=False)


class SharedTestDbRefs7031(unittest.TestCase):
    def setUp(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        self._tmp = tempfile.TemporaryDirectory(dir=str(SCRATCH))
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        (self.dir / 'allow.txt').write_text('', encoding='utf-8')

    def mutant(self, text: str, name: str = 'm.txt') -> 'subprocess.CompletedProcess[str]':
        (self.dir / name).write_text(text + '\n', encoding='utf-8')
        return gate(self.dir, '--paths', name, '--allowlist', str(self.dir / 'allow.txt'))

    def test_real_tree_passes_with_allowlist(self) -> None:
        done = gate(ROOT)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_r1_url_literal(self) -> None:
        done = self.mutant('url = "postgres://u:p@h:5445/%s"' % NAME)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn('::error file=m.txt,line=1::R1', done.stdout)

    def test_r2_postgres_db(self) -> None:
        done = self.mutant('  POSTGRES_DB: %s' % NAME)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn('R2', done.stdout)

    def test_r3_db_flag(self) -> None:
        done = self.mutant('psql -U u -d %s -c x' % NAME)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn('R3', done.stdout)

    def test_r4_pg_isready(self) -> None:
        done = self.mutant('pg_isready -U u -d %s' % NAME)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn('R4', done.stdout)

    def test_prefixed_ephemeral_names_never_match(self) -> None:
        done = self.mutant('psql -d %s_ci_1_1_cov\nurl = "postgres://h/%s_p2_9"' % (NAME, NAME))
        self.assertEqual(done.returncode, 0, done.stdout)

    def test_comment_only_lines_never_match(self) -> None:
        text = '\n'.join(['# psql -d %s' % NAME, '// "postgres://h/%s"' % NAME,
                          '-- POSTGRES_DB=%s' % NAME, '  //! pg_isready -d %s' % NAME])
        done = self.mutant(text)
        self.assertEqual(done.returncode, 0, done.stdout)

    def test_allowlist_whole_file_and_line(self) -> None:
        (self.dir / 'allow.txt').write_text('m.txt:1  # cited\n', encoding='utf-8')
        done = self.mutant('url = "postgres://h/%s"' % NAME)
        self.assertEqual(done.returncode, 0, done.stdout)

    def test_stale_allowlist_entry_exits_2(self) -> None:
        (self.dir / 'allow.txt').write_text('m.txt  # nothing matches\n', encoding='utf-8')
        done = self.mutant('clean line')
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn('stale allowlist entry', done.stderr)

    def test_list_mode_exits_0(self) -> None:
        (self.dir / 'm.txt').write_text('POSTGRES_DB=%s\n' % NAME, encoding='utf-8')
        done = gate(self.dir, '--paths', 'm.txt', '--allowlist', str(self.dir / 'allow.txt'), '--list')
        self.assertEqual(done.returncode, 0)
        self.assertIn('m.txt:1 R2', done.stdout)


if __name__ == '__main__':
    unittest.main()
