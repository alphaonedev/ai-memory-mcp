#!/usr/bin/env python3
"""Issue #7301: tests for scripts/check-zip-extract-unreachable.py.

The guard backs the cargo-audit ignores for RUSTSEC-2026-0367/0368/0369 (zip
7.2.0 via candle-core). It must fail the moment zip's `extract()` path, a
candle npy/npz/pth loader or a non-candle zip parent becomes reachable.

Fixture trees live under the worktree's `.local-runs/` (never a tmpfs).

Run: python3 -m unittest scripts/ci/tests/test_zip_extract_guard_7301.py
"""
import os
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


class GuardBase(unittest.TestCase):
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



class GuardCase(GuardBase):
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


STUB_TEMPLATE = """#!{python}
import json, sys
with open({log!r}, 'a') as fh:
    fh.write(json.dumps(sys.argv[1:]) + '\\n')
sys.stdout.write({out!r})
sys.stderr.write({err!r})
sys.exit({rc})
"""

LOCK_WITH_ZIP = '[[package]]\nname = "zip"\nversion = "7.2.0"\n'
LOCK_WITHOUT_ZIP = '[[package]]\nname = "serde"\nversion = "1.0.0"\n'
NO_MATCH_ERR = 'error: package ID specification `zip` did not match any packages\n'


class StubCargoCase(GuardBase):
    """Runs the guard against a stub `cargo` placed first on PATH."""

    def run_stub(self, out='', err='', rc=0, lock=None):
        stub_dir = self.root.parent / (self.root.name + '.bin')
        stub_dir.mkdir()
        self.addCleanup(shutil.rmtree, str(stub_dir), True)
        self.argv_log = stub_dir / 'argv.log'
        stub = stub_dir / 'cargo'
        stub.write_text(STUB_TEMPLATE.format(
            python=sys.executable, log=str(self.argv_log), out=out, err=err, rc=rc),
            encoding='utf-8')
        stub.chmod(0o755)
        if lock is not None:
            (self.root / 'Cargo.lock').write_text(lock, encoding='utf-8')
        env = dict(os.environ)
        env['PATH'] = str(stub_dir) + os.pathsep + env.get('PATH', '')
        return subprocess.run(
            [sys.executable, str(GUARD), '--root', str(self.root)],
            capture_output=True, text=True, check=False, env=env)


class TreeFailClosed7301(StubCargoCase):
    """Round 2: dev edges, fail closed, exact parent allowlist."""

    def test_cargo_tree_requests_dev_edges(self):
        res = self.run_stub(out=GOOD_TREE_DEPTH, lock=LOCK_WITH_ZIP)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('normal,build,dev', self.argv_log.read_text(encoding='utf-8'))

    def test_empty_stdout_rc0_exits_2(self):
        res = self.run_stub(out='', err='warning: nothing to print.\n', lock=LOCK_WITH_ZIP)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_unparseable_output_exits_2(self):
        res = self.run_stub(out='warning: something odd\n', lock=LOCK_WITH_ZIP)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_missing_zip_root_line_exits_2(self):
        res = self.run_stub(out='0candle-core v0.10.2\n1ai-memory v1.0.0\n', lock=LOCK_WITH_ZIP)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_empty_tree_file_exits_2(self):
        res = self.run_guard(tree='')
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_cargo_failure_exits_2(self):
        res = self.run_stub(err='error: no registry\n', rc=101, lock=LOCK_WITH_ZIP)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_zip_absent_from_lock_passes_with_message(self):
        res = self.run_stub(err=NO_MATCH_ERR, rc=101, lock=LOCK_WITHOUT_ZIP)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('zip not in graph', res.stdout)

    def test_did_not_match_but_lock_has_zip_exits_2(self):
        res = self.run_stub(err=NO_MATCH_ERR, rc=101, lock=LOCK_WITH_ZIP)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_did_not_match_without_lock_exits_2(self):
        res = self.run_stub(err=NO_MATCH_ERR, rc=101)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_candle_look_alike_parents_fail(self):
        for name in ('candle-zipx', 'candle-evil', 'candle-nn', 'candle-core-ext'):
            with self.subTest(name=name):
                tree = '0zip v7.2.0\n1candle-core v0.10.2\n1%s v0.1.0\n' % name
                res = self.run_guard(tree=tree)
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn(name, res.stdout)


try:
    import tomllib  # noqa: F401  (Python 3.11+)
    HAVE_TOMLLIB = True
except ImportError:
    HAVE_TOMLLIB = False

PY39 = Path.home() / '.local' / 'bin' / 'python3.9'

# Every manifest form that declares a direct zip dependency.
ZIP_MANIFEST_FORMS = {
    'target-normal': "[target.'cfg(unix)'.dependencies]\nzip = \"7\"\n",
    'target-dev': "[target.'cfg(unix)'.dev-dependencies]\nzip = { version = \"7\" }\n",
    'target-build': "[target.'cfg(windows)'.build-dependencies]\nzip = \"7\"\n",
    'target-complex-cfg': (
        "[target.'cfg(all(unix, target_pointer_width = \"64\"))'.dev-dependencies]\n"
        "zip = { version = \"7\", default-features = false }\n"),
    'target-dq-cfg': (
        "[target.\"cfg(target_os = \\\"linux\\\")\".dependencies]\nzip = \"7\"\n"),
    'target-triple': "[target.x86_64-unknown-linux-gnu.dependencies]\nzip = \"7\"\n",
    'target-table-zip': "[target.'cfg(unix)'.dependencies.zip]\nversion = \"7\"\n",
    'dependencies-table-zip': "[dependencies.zip]\nversion = \"7\"\n",
    'dev-table-zip': "[dev-dependencies.zip]\nversion = \"7\"\n",
    'build-table-zip': "[build-dependencies.zip]\nversion = \"7\"\n",
    'renamed-table': "[dependencies.z]\npackage = \"zip\"\nversion = \"7\"\n",
    'renamed-dotted': "[dependencies]\nz.package = \"zip\"\nz.version = \"7\"\n",
    'renamed-inline': "[dependencies]\nz = { package = \"zip\", version = \"7\" }\n",
    'quoted-key': "[dependencies]\n\"zip\" = \"7\"\n",
    'dotted-in-dependencies': "[dependencies]\nzip.version = \"7\"\n",
    'workspace-dependencies': "[workspace.dependencies]\nzip = \"7\"\n",
    'target-dotted-in-target-table': "[target.'cfg(unix)']\ndependencies.zip = \"7\"\n",
}
# Forms whose dotted key sits before any table header (top of the file).
ZIP_TOPLEVEL_FORMS = {
    'toplevel-dotted': 'dependencies.zip = "7"\n',
    'toplevel-dotted-dev': 'dev-dependencies.zip = "7"\n',
    'toplevel-dotted-build': 'build-dependencies.zip = "7"\n',
    'toplevel-dotted-target': "target.'cfg(unix)'.dependencies.zip = \"7\"\n",
}
CLEAN_MANIFEST_FORMS = {
    'zipper-lookalike': "[dependencies]\nzipper = \"1\"\nzip-extra = \"1\"\n",
    'feature-named-zip': "[features]\nzip = []\n",
    'zip-in-description': "[package.metadata]\ndescription = \"zip\"\n[target.'cfg(unix)'.dependencies]\nserde = \"1\"\n",
    'metadata-table': "[package.metadata.zip]\nlevel = 1\n",
    'multiline-string': "[package.metadata]\nnote = '''\n[dependencies]\nzip = \"7\"\n'''\n",
}


class ManifestForms7301(GuardBase):
    """Round 2: the manifest check recognises every dependency-table form."""

    def run_manifest(self, body, parser, top=''):
        (self.root / 'Cargo.toml').write_text(
            top + MINIMAL_MANIFEST + body, encoding='utf-8')
        tree_file = self.root.parent / (self.root.name + '.tree')
        tree_file.write_text(GOOD_TREE_DEPTH, encoding='utf-8')
        self.addCleanup(lambda: tree_file.unlink() if tree_file.exists() else None)
        return subprocess.run(
            [sys.executable, str(GUARD), '--root', str(self.root), '--cargo-tree-file', str(tree_file),
             '--manifest-parser', parser], capture_output=True, text=True, check=False)

    def parsers(self):
        out = ['fallback']
        if HAVE_TOMLLIB:
            out.append('tomllib')
        return out

    def test_every_zip_form_fails(self):
        for parser in self.parsers():
            for name, body in ZIP_MANIFEST_FORMS.items():
                with self.subTest(parser=parser, form=name):
                    res = self.run_manifest(body, parser)
                    self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                    self.assertIn('Cargo.toml', res.stdout)

    def test_toplevel_dotted_forms_fail(self):
        for parser in self.parsers():
            for name, top in ZIP_TOPLEVEL_FORMS.items():
                with self.subTest(parser=parser, form=name):
                    res = self.run_manifest('', parser, top=top)
                    self.assertEqual(res.returncode, 1, res.stdout + res.stderr)

    def test_clean_forms_pass(self):
        for parser in self.parsers():
            for name, body in CLEAN_MANIFEST_FORMS.items():
                with self.subTest(parser=parser, form=name):
                    res = self.run_manifest(body, parser)
                    self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_real_manifest_passes_with_each_parser(self):
        for parser in self.parsers():
            with self.subTest(parser=parser):
                tree_file = self.root.parent / (self.root.name + '.tree')
                tree_file.write_text(GOOD_TREE_DEPTH, encoding='utf-8')
                self.addCleanup(lambda: tree_file.unlink() if tree_file.exists() else None)
                res = subprocess.run(
                    [sys.executable, str(GUARD), '--root', str(REPO), '--cargo-tree-file', str(tree_file),
                     '--manifest-parser', parser], capture_output=True, text=True, check=False)
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_invalid_toml_exits_2_with_tomllib(self):
        if not HAVE_TOMLLIB:
            self.skipTest('tomllib needs Python 3.11+')
        res = self.run_manifest('[dependencies\n', 'tomllib')
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_tomllib_requested_but_missing_exits_2(self):
        if HAVE_TOMLLIB:
            self.skipTest('tomllib is available here')
        res = self.run_manifest('', 'tomllib')
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_python39_default_parser_catches_every_form(self):
        if not PY39.is_file():
            self.skipTest('python3.9 not installed')
        for name, body in ZIP_MANIFEST_FORMS.items():
            with self.subTest(form=name):
                (self.root / 'Cargo.toml').write_text(MINIMAL_MANIFEST + body, encoding='utf-8')
                tree_file = self.root.parent / (self.root.name + '.tree')
                tree_file.write_text(GOOD_TREE_DEPTH, encoding='utf-8')
                self.addCleanup(lambda: tree_file.unlink() if tree_file.exists() else None)
                res = subprocess.run(
                    [str(PY39), str(GUARD), '--root', str(self.root), '--cargo-tree-file', str(tree_file)],
                    capture_output=True, text=True, check=False)
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)


if __name__ == '__main__':
    unittest.main()
