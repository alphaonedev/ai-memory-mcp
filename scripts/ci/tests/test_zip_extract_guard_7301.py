#!/usr/bin/env python3
"""Issue #7301: tests for scripts/check-zip-extract-unreachable.py.

The guard backs the cargo-audit ignores for RUSTSEC-2026-0367/0368/0369 (zip
7.2.0 via candle-core). It must fail the moment zip's `extract()` path, a
candle npy/npz/pth loader or a non-candle zip parent becomes reachable.

Fixture trees live under the worktree's `.local-runs/` (never a tmpfs).

Run: python3 -m unittest scripts/ci/tests/test_zip_extract_guard_7301.py
"""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GUARD = REPO / 'scripts' / 'check-zip-extract-unreachable.py'
SCRATCH = REPO / '.local-runs'

GOOD_TREE = 'zip v7.2.0\n'
GOOD_TREE_DEPTH = '0zip v7.2.0\n1candle-core v0.10.2\n'
BAD_TREE_DEPTH = '0zip v7.2.0\n1candle-core v0.10.2\n1some-other v1.0.0\n'
MINIMAL_MANIFEST = '[package]\nname = "fixture"\nversion = "0.0.0"\n\n[dependencies]\nserde = "1"\n'


class GuardCase(unittest.TestCase):
    """Builds a fixture tree under .local-runs and runs the guard on it."""

    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='zip-guard-7301-', dir=str(SCRATCH)))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        (self.root / 'src').mkdir()
        (self.root / 'Cargo.toml').write_text(MINIMAL_MANIFEST, encoding='utf-8')
        (self.root / 'src' / 'lib.rs').write_text('pub fn ok() {}\n', encoding='utf-8')

    def run_guard(self, tree=GOOD_TREE_DEPTH, root=None):
        tree_file = self.root.parent / (self.root.name + '.tree')
        tree_file.write_text(tree, encoding='utf-8')
        self.addCleanup(lambda: tree_file.unlink() if tree_file.exists() else None)
        return subprocess.run(
            [sys.executable, str(GUARD), '--root', str(root or self.root),
             '--cargo-tree-file', str(tree_file)],
            capture_output=True, text=True, check=False)

    def test_clean_fixture_passes(self):
        res = self.run_guard()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_real_repo_tree_passes(self):
        res = self.run_guard(root=REPO)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_zip_path_use_fails(self):
        (self.root / 'src' / 'bad.rs').write_text(
            'fn f() {\n    let _ = zip::ZipArchive::new;\n}\n', encoding='utf-8')
        res = self.run_guard()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('src/bad.rs:2', res.stdout)

    def test_stream_reader_and_zip_extract_fail(self):
        (self.root / 'src' / 'bad.rs').write_text(
            'fn f(r: ZipStreamReader) {}\n', encoding='utf-8')
        (self.root / 'src' / 'bad2.rs').write_text(
            'use some::Zip;\nfn f(a: Zip) { a.extract("out"); }\n', encoding='utf-8')
        res = self.run_guard()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('src/bad.rs:1', res.stdout)
        self.assertIn('src/bad2.rs:2', res.stdout)

    def test_unrelated_extract_does_not_fail(self):
        (self.root / 'src' / 'ok.rs').write_text(
            'fn f(re: Regex) { re.extract("x"); }\n', encoding='utf-8')
        res = self.run_guard()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_loader_calls_fail(self):
        for i, call in enumerate((
                'Tensor::read_npz(p)', 'Tensor::read_npy(p)', 'VarBuilder::from_pth(p, d, v)',
                'VarBuilder::from_npz(p, d, v)', 'candle_core::pickle::read_all(p)',
                'read_pth_tensor_info(p, false, None)', 'Tensor::write_npz(&v, p)')):
            with self.subTest(call=call):
                (self.root / 'tests').mkdir(exist_ok=True)
                target = self.root / 'tests' / ('t%d.rs' % i)
                target.write_text('fn f() {\n    %s;\n}\n' % call, encoding='utf-8')
                res = self.run_guard()
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('tests/t%d.rs:2' % i, res.stdout)
                target.unlink()

    def test_build_rs_and_benches_scanned(self):
        (self.root / 'build.rs').write_text('fn main() { zip::read(); }\n', encoding='utf-8')
        (self.root / 'benches').mkdir()
        (self.root / 'benches' / 'b.rs').write_text('fn b() { Tensor::read_npy(p); }\n', encoding='utf-8')
        res = self.run_guard()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('build.rs:1', res.stdout)
        self.assertIn('benches/b.rs:1', res.stdout)

    def test_non_candle_parent_fails(self):
        res = self.run_guard(tree=BAD_TREE_DEPTH)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('some-other', res.stdout)

    def test_non_candle_parent_in_tree_format_fails(self):
        tree = 'zip v7.2.0\n+-- candle-core v0.10.2\n`-- evil-zip-user v1.0.0\n'
        res = self.run_guard(tree=tree)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('evil-zip-user', res.stdout)

    def test_direct_zip_dependency_fails(self):
        for body in ('zip = "9"\n', 'zip = { version = "9" }\n', 'zip.workspace = true\n',
                     'z = { package = "zip", version = "9" }\n'):
            with self.subTest(body=body):
                (self.root / 'Cargo.toml').write_text(
                    MINIMAL_MANIFEST + body, encoding='utf-8')
                res = self.run_guard()
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('Cargo.toml', res.stdout)

    def test_direct_zip_table_dependency_fails(self):
        (self.root / 'Cargo.toml').write_text(
            MINIMAL_MANIFEST + '\n[dev-dependencies.zip]\nversion = "9"\n', encoding='utf-8')
        res = self.run_guard()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)

    def test_crlf_in_path_is_escaped(self):
        name = 'evil\n::error::injected.rs'
        (self.root / 'src' / name).write_text('fn f() { zip::x(); }\n', encoding='utf-8')
        res = self.run_guard()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertNotIn('\r', res.stdout)
        for line in res.stdout.splitlines():
            self.assertFalse(line.startswith('::'), line)
        self.assertIn('\\n::error::injected.rs:1', res.stdout)

    def test_usage_error_exit_code(self):
        res = subprocess.run([sys.executable, str(GUARD), '--root', str(self.root / 'missing')],
                             capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)


if __name__ == '__main__':
    unittest.main()
