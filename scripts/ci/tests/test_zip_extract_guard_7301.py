#!/usr/bin/env python3
"""Issue #7301: tests for scripts/check-zip-extract-unreachable.py.

The guard backs the cargo-audit ignores for RUSTSEC-2026-0367/0368/0369 (zip
7.2.0 via candle-core). It must fail the moment zip's `extract()` path, a
candle npy/npz/pth loader or a non-candle zip parent becomes reachable.

Fixture trees live under the worktree's `.local-runs/` (never a tmpfs).

Run: python3 -m unittest scripts/ci/tests/test_zip_extract_guard_7301.py
"""
import importlib.util
import json
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
PACKAGE_ONLY = '[package]\nname = "fixture"\nversion = "0.0.0"\n\n'
CANDLE_LOCK = ('[[package]]\nname = "candle-core"\nversion = "0.10.2"\n'
               'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
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
        (self.root / 'Cargo.lock').write_text(CANDLE_LOCK, encoding='utf-8')

    def run_guard(self, tree=GOOD_TREE_DEPTH, root=None, extra=()):
        tree_file = self.root.parent / (self.root.name + '.tree')
        tree_file.write_text(tree, encoding='utf-8')
        self.addCleanup(lambda: tree_file.unlink() if tree_file.exists() else None)
        return subprocess.run(
            [sys.executable, str(GUARD), '--root', str(root or self.root),
             '--cargo-tree-file', str(tree_file)] + list(extra),
            capture_output=True, text=True, check=False)



class GuardCase(GuardBase):
    def test_clean_fixture_passes(self):
        res = self.run_guard()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_real_repo_sources_pass_with_fixture_tree(self):
        """Fixture test: real repo sources and manifest, canned cargo tree text."""
        res = self.run_guard(root=REPO)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_real_repo_passes_with_real_cargo_tree(self):
        """Runs the real `cargo tree` (locked) against this checkout."""
        if shutil.which('cargo') is None:
            self.skipTest('cargo is not installed')
        res = subprocess.run([sys.executable, str(GUARD), '--root', str(REPO)],
                             capture_output=True, text=True, check=False)
        if res.returncode == 2 and 'cargo tree failed' in res.stderr:
            self.skipTest('cargo tree cannot run offline here: ' + res.stderr.strip()[-200:])
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('check-zip-extract-unreachable: ok', res.stdout)

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
        # The guard must exist: a missing script also exits 2 from the
        # interpreter, which would make this test green on a base without it.
        self.assertTrue(GUARD.is_file(), 'guard script missing: %s' % GUARD)
        res = subprocess.run([sys.executable, str(GUARD), '--root', str(self.root / 'missing')],
                             capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn('no Cargo.toml', res.stderr)

    def test_unknown_argument_exit_code(self):
        self.assertTrue(GUARD.is_file(), 'guard script missing: %s' % GUARD)
        res = subprocess.run([sys.executable, str(GUARD), '--no-such-flag'],
                             capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn('usage:', res.stderr)

    def test_audit_toml_record_names_both_loaders_and_the_yank(self):
        text = (REPO / '.cargo' / 'audit.toml').read_text(encoding='utf-8')
        for needle in ('npy.rs', 'pickle.rs', 'yanked', 'RUSTSEC-2026-0367', 'RUSTSEC-2026-0368',
                       'RUSTSEC-2026-0369', 'check-zip-extract-unreachable.py'):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)


STUB_TEMPLATE = """#!{python}
import json, sys
with open({log!r}, 'a') as fh:
    fh.write(json.dumps(sys.argv[1:]) + '\\n')
sys.stdout.write({out!r})
sys.stderr.write({err!r})
sys.exit({rc})
"""

OFFLINE_REFUSING_STUB = """#!{python}
import sys
if '--offline' in sys.argv:
    sys.stderr.write('error: failed to download `anstyle-wincon v3.0.11`\\n'
                     'Caused by: attempting to make an HTTP request, but --offline was specified\\n')
    sys.exit(101)
sys.stdout.write({out!r})
"""

LOCK_WITH_ZIP = CANDLE_LOCK + '[[package]]\nname = "zip"\nversion = "7.2.0"\n'
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


class CleanCargoHome7301(StubCargoCase):
    """Round 4 (CI): the guard must work on a runner that has not fetched every target."""

    def argv_of_run(self):
        res = self.run_stub(out=GOOD_TREE_DEPTH, lock=LOCK_WITH_ZIP)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        lines = self.argv_log.read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(lines), 1, lines)
        return json.loads(lines[0])

    def test_cargo_tree_argv_has_no_offline_flag(self):
        self.assertNotIn('--offline', self.argv_of_run())

    def test_cargo_tree_argv_keeps_locked_and_all_targets(self):
        argv = self.argv_of_run()
        self.assertIn('--locked', argv)
        self.assertIn('all', argv)

    def test_download_needed_is_not_refused_by_guard_flags(self):
        """A cargo that refuses to download under --offline: the guard must not pass that flag."""
        stub_dir = self.root.parent / (self.root.name + '.bin')
        stub_dir.mkdir()
        self.addCleanup(shutil.rmtree, str(stub_dir), True)
        stub = stub_dir / 'cargo'
        stub.write_text(OFFLINE_REFUSING_STUB.format(
            python=sys.executable, out=GOOD_TREE_DEPTH), encoding='utf-8')
        stub.chmod(0o755)
        (self.root / 'Cargo.lock').write_text(LOCK_WITH_ZIP, encoding='utf-8')
        env = dict(os.environ)
        env['PATH'] = str(stub_dir) + os.pathsep + env.get('PATH', '')
        res = subprocess.run([sys.executable, str(GUARD), '--root', str(self.root)],
                             capture_output=True, text=True, check=False, env=env)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_download_failure_still_fails_closed(self):
        res = self.run_stub(err='error: failed to download `x v1.0.0`\n', rc=101, lock=LOCK_WITH_ZIP)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)


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
        (self.root / 'Cargo.lock').unlink()
        res = self.run_stub(err=NO_MATCH_ERR, rc=101)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_candle_look_alike_parents_fail(self):
        for name in ('candle-zipx', 'candle-evil', 'candle-nn', 'candle-core-ext'):
            with self.subTest(name=name):
                tree = '0zip v7.2.0\n1candle-core v0.10.2\n1%s v0.1.0\n' % name
                res = self.run_guard(tree=tree)
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn(name, res.stdout)


class SourceScope7301(GuardBase):
    """Round 2: scan scope (examples, custom build script, #[path], include!) and patterns."""

    def write(self, rel, text):
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
        return target

    def test_examples_dir_is_scanned(self):
        self.write('examples/e.rs', 'fn main() { Tensor::read_npz(p); }\n')
        res = self.run_guard()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('examples/e.rs:1', res.stdout)

    def test_custom_build_script_is_scanned(self):
        (self.root / 'Cargo.toml').write_text(
            MINIMAL_MANIFEST.replace('name = "fixture"', 'name = "fixture"\nbuild = "tools/b.rs"'),
            encoding='utf-8')
        self.write('tools/b.rs', 'fn main() { zip::ZipArchive::new(r); }\n')
        res = self.run_guard()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('tools/b.rs:1', res.stdout)

    def test_declared_target_paths_are_scanned(self):
        (self.root / 'Cargo.toml').write_text(
            MINIMAL_MANIFEST + '\n[[bin]]\nname = "tool"\npath = "gen/tool.rs"\n', encoding='utf-8')
        self.write('gen/tool.rs', 'fn main() { Tensor::read_npy(p); }\n')
        res = self.run_guard()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('gen/tool.rs:1', res.stdout)

    def test_use_leading_colons_fails(self):
        for i, line in enumerate(('use ::zip as z;', 'use ::zip::ZipArchive;', 'extern crate zip as z;',
                                  'use {zip, serde};')):
            with self.subTest(line=line):
                self.write('src/u%d.rs' % i, line + '\n')
                res = self.run_guard()
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('src/u%d.rs:1' % i, res.stdout)
                (self.root / 'src' / ('u%d.rs' % i)).unlink()

    def test_extract_unwrapped_root_dir_fails_without_zip_context(self):
        self.write('src/x.rs', 'fn f(a: A) { a.extract_unwrapped_root_dir(p, v); }\n')
        res = self.run_guard()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('src/x.rs:1', res.stdout)

    def test_zip_named_in_macro_input_fails(self):
        cases = ('my_macro!(zip);', 'my_macro!(a, zip, b);', 'my_macro![zip];',
                 'my_macro! { zip }', 'my_macro!(\n    a,\n    zip\n);')
        for i, body in enumerate(cases):
            with self.subTest(body=body):
                self.write('src/m%d.rs' % i, 'fn f() {\n%s\n}\n' % body)
                res = self.run_guard()
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('src/m%d.rs:' % i, res.stdout)
                (self.root / 'src' / ('m%d.rs' % i)).unlink()

    def test_iterator_zip_in_macro_does_not_fail(self):
        self.write('src/ok.rs', (
            'fn f(a: &[u8], b: &[u8]) {\n'
            '    let v = vec![a.iter().zip(b)];\n'
            '    assert_eq!(a.len(), std::iter::zip(a, b).count());\n'
            '    println!("zip file {}", 1);\n'
            '}\n'))
        res = self.run_guard()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_path_attribute_outside_scanned_roots_is_followed(self):
        self.write('gen/evil.rs', 'pub fn e() { Tensor::read_npz(p); }\n')
        self.write('src/lib.rs', '#[path = "../gen/evil.rs"]\nmod evil;\n')
        res = self.run_guard()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('gen/evil.rs:1', res.stdout)

    def test_include_macro_outside_scanned_roots_is_followed(self):
        self.write('gen/evil.rs', 'fn e() { zip::x(); }\n')
        self.write('src/lib.rs', 'include!("../gen/evil.rs");\n')
        res = self.run_guard()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('gen/evil.rs:1', res.stdout)

    def test_unresolvable_path_and_include_fail(self):
        for i, body in enumerate(('#[path = "../gen/missing.rs"]\nmod m;\n',
                                  'include!("../gen/missing.rs");\n',
                                  'include!(concat!(env!("OUT_DIR"), "/g.rs"));\n',
                                  '#[path = "../../outside.rs"]\nmod m;\n')):
            with self.subTest(body=body):
                self.write('src/lib.rs', body)
                res = self.run_guard()
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('src/lib.rs:', res.stdout)

    def test_path_attribute_inside_scanned_roots_passes(self):
        self.write('src/sub/inner.rs', 'pub fn i() {}\n')
        self.write('src/lib.rs', '#[path = "sub/inner.rs"]\nmod inner;\ninclude_str!("a.txt");\n')
        res = self.run_guard()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_non_utf8_source_exits_2(self):
        (self.root / 'src' / 'bin.rs').write_bytes(b'fn f() {}\n\xff\xfe\n')
        res = self.run_guard()
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn('src/bin.rs', res.stderr)
        self.assertNotIn('Traceback', res.stderr)

    def test_non_utf8_manifest_exits_2(self):
        (self.root / 'Cargo.toml').write_bytes(b'[package]\nname = "\xff"\n')
        res = self.run_guard()
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertNotIn('Traceback', res.stderr)

    def test_unreadable_source_exits_2(self):
        target = self.write('src/locked.rs', 'fn f() {}\n')
        target.chmod(0)
        self.addCleanup(target.chmod, 0o644)
        if os.access(str(target), os.R_OK):
            self.skipTest('running as a user that ignores file modes')
        res = self.run_guard()
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn('src/locked.rs', res.stderr)
        self.assertNotIn('Traceback', res.stderr)


HAVE_TOMLLIB = importlib.util.find_spec('tomllib') is not None  # Python 3.11+

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
            top + PACKAGE_ONLY + body, encoding='utf-8')
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
        # An argparse usage error also exits 2: pin the reason so a guard that
        # merely rejects the flag cannot satisfy this test.
        self.assertIn('not valid TOML', res.stderr)
        self.assertNotIn('unrecognized arguments', res.stderr)

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
                (self.root / 'Cargo.toml').write_text(PACKAGE_ONLY + body, encoding='utf-8')
                tree_file = self.root.parent / (self.root.name + '.tree')
                tree_file.write_text(GOOD_TREE_DEPTH, encoding='utf-8')
                self.addCleanup(lambda: tree_file.unlink() if tree_file.exists() else None)
                res = subprocess.run(
                    [str(PY39), str(GUARD), '--root', str(self.root), '--cargo-tree-file', str(tree_file)],
                    capture_output=True, text=True, check=False)
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)


BR_EVIL = 'pub fn e() { Tensor::read_npz(p); }\n'
BOTH_PARSERS = ['fallback'] + (['tomllib'] if HAVE_TOMLLIB else [])


class Workspace7301(StubCargoCase):
    """Round 3 (N1): a workspace member that depends on zip must not pass."""

    def test_cargo_tree_requests_workspace(self):
        res = self.run_stub(out=GOOD_TREE_DEPTH, lock=LOCK_WITH_ZIP)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('--workspace', self.argv_log.read_text(encoding='utf-8'))

    def test_workspace_member_zip_parent_fails(self):
        tree = '0zip v7.2.0\n1candle-core v0.10.2\n1zipper v0.1.0 (/w/crates/zipper)\n'
        res = self.run_guard(tree=tree)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('zipper', res.stdout)

    def test_workspace_members_declared_fail_on_both_parsers(self):
        manifest = MINIMAL_MANIFEST + '\n[workspace]\nmembers = ["crates/zipper"]\n'
        for parser in BOTH_PARSERS:
            with self.subTest(parser=parser):
                (self.root / 'Cargo.toml').write_text(manifest, encoding='utf-8')
                res = self.run_guard(extra=('--manifest-parser', parser))
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('workspace', res.stdout)


class ParentPin7301(GuardBase):
    """Round 3 (N2, code L1): the zip parent is registry candle-core 0.10.x only."""

    def test_bad_parent_lines_fail(self):
        lines = (
            '1candle-core v0.10.2 (/w/vendor/candle-core)',
            '1candle-core v0.10.2 (https://github.com/x/candle?rev=1#abc)',
            '1candle-core v0.11.0',
            '1candle-core v0.9.9',
            '1candle-core v0.100.0',
        )
        for line in lines:
            with self.subTest(line=line):
                res = self.run_guard(tree='0zip v7.2.0\n%s\n' % line)
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('candle-core', res.stdout)

    def test_bad_parent_in_drawn_form_fails(self):
        res = self.run_guard(tree='zip v7.2.0\n`-- candle-core v0.10.2 (/w/x)\n')
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)

    def test_registry_candle_core_0_10_x_passes(self):
        for line in ('1candle-core v0.10.2', '1candle-core v0.10.9', '1candle-core v0.10.2 (*)'):
            with self.subTest(line=line):
                res = self.run_guard(tree='0zip v7.2.0\n%s\n' % line)
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_lock_entry_must_be_registry_0_10(self):
        registry = 'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        head = '[[package]]\nname = "candle-core"\n'
        locks = {
            'no-source': head + 'version = "0.10.2"\n',
            'git': head + 'version = "0.10.2"\nsource = "git+https://github.com/x/candle#abc"\n',
            'other-registry': head + 'version = "0.10.2"\nsource = "registry+https://example.com/index"\n',
            'version-0.11': head + 'version = "0.11.0"\n' + registry,
            'second-entry': CANDLE_LOCK + head + 'version = "0.11.0"\n' + registry,
            'absent': LOCK_WITHOUT_ZIP,
        }
        for name, lock in locks.items():
            with self.subTest(lock=name):
                (self.root / 'Cargo.lock').write_text(lock, encoding='utf-8')
                res = self.run_guard()
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('Cargo.lock', res.stdout)

    def test_missing_lock_exits_2(self):
        (self.root / 'Cargo.lock').unlink()
        res = self.run_guard()
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_patch_and_replace_of_candle_or_zip_fail(self):
        forms = {
            'patch-inline': '[patch.crates-io]\ncandle-core = { path = "../c" }\n',
            'patch-dotted': '[patch.crates-io]\ncandle-core.path = "../c"\n',
            'patch-table': '[patch.crates-io.candle-core]\npath = "../c"\n',
            'patch-git-source': "[patch.'https://github.com/x/candle']\ncandle-core = { git = 'https://github.com/y/c' }\n",
            'patch-zip': '[patch.crates-io]\nzip = { path = "../z" }\n',
            'replace': '[replace]\n"candle-core:0.10.2" = { path = "../c" }\n',
        }
        for parser in BOTH_PARSERS:
            for name, body in forms.items():
                with self.subTest(parser=parser, form=name):
                    (self.root / 'Cargo.toml').write_text(MINIMAL_MANIFEST + '\n' + body, encoding='utf-8')
                    res = self.run_guard(extra=('--manifest-parser', parser))
                    self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                    self.assertIn('Cargo.toml', res.stdout)

    def test_unrelated_patch_passes(self):
        for parser in BOTH_PARSERS:
            with self.subTest(parser=parser):
                (self.root / 'Cargo.toml').write_text(
                    MINIMAL_MANIFEST + '\n[patch.crates-io]\nserde = { path = "../s" }\n', encoding='utf-8')
                res = self.run_guard(extra=('--manifest-parser', parser))
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


class FallbackQuotes7301(GuardBase):
    """Round 3 (N3, code L2): triple quotes inside one-line strings do not desync the fallback."""

    DEP = '[dependencies]\nzip = "7"\n'

    def test_triple_quote_in_single_line_string_does_not_hide_zip(self):
        notes = (
            'note = "\'\'\'"',
            "note = '\"\"\"'",
            'description = "x\'\'\'y"',
            "description = 'x\"\"\"y'",
            'note = """abc"""',
            "note = '''abc'''",
            'note = "a" # \'\'\'',
        )
        for note in notes:
            with self.subTest(note=note):
                (self.root / 'Cargo.toml').write_text(
                    PACKAGE_ONLY + '[package.metadata.n]\n' + note + '\n' + self.DEP, encoding='utf-8')
                res = self.run_guard(extra=('--manifest-parser', 'fallback'))
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('Cargo.toml', res.stdout)

    def test_real_multiline_strings_still_hide_their_bodies(self):
        body = ('[package.metadata]\nnote = \'\'\'\n[dependencies]\nzip = "7"\n\'\'\'\n'
                'other = """\nzip = "8"\n"""\n')
        (self.root / 'Cargo.toml').write_text(PACKAGE_ONLY + body, encoding='utf-8')
        res = self.run_guard(extra=('--manifest-parser', 'fallback'))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


class MaskAndFalsePositives7301(GuardBase):
    """Round 3 (code L3, N5, code L4): raw-string prefixes and benign forms."""

    def write(self, rel, text):
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')

    def test_prefixed_raw_strings_do_not_hide_path_attribute(self):
        for prefix in ('br', 'cr', 'r'):
            with self.subTest(prefix=prefix):
                self.write('gen/evil.rs', BR_EVIL)
                self.write('src/lib.rs', (
                    'const A: &[u8] = %s"\\"; #[path = "../gen/evil.rs"] mod evil; // ";\n' % prefix))
                res = self.run_guard()
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('gen/evil.rs:1', res.stdout)

    def test_prefixed_raw_string_body_is_not_scanned(self):
        self.write('src/lib.rs', 'const A: &[u8] = br"zip::ZipArchive";\nconst B: &str = cr#"read_npz"#;\n')
        res = self.run_guard()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_benign_forms_pass(self):
        cases = {
            'doc-comment': '/// unlike zip::ZipArchive this is fine\nfn f() {}\n',
            'inner-doc': '//! Reads ZipArchive-free data.\nfn f() {}\n',
            'block-comment': '/* zip::x and read_npz in a comment */\nfn f() {}\n',
            'zip-param-in-macro': 'pub fn f(zip: u8) { println!("{}", zip); }\n',
            'zip-let-in-macro': 'fn f() {\n    let zip = 1;\n    assert_eq!(zip, 1);\n}\n',
            'if-not-zip': 'pub fn f(zip: bool) { if !(zip) { return; } }\n',
            'while-not-zip': 'pub fn f(zip: bool) { while !(zip) { break; } }\n',
            'regex-extract-with-iter-zip': (
                'fn f(c: Captures, a: &[u8], b: &[u8]) {\n'
                '    let _ = c.extract();\n    let _ = a.iter().zip(b);\n}\n'),
            'string-literal': 'const A: &str = "zip::ZipArchive read_npz";\n',
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                self.write('src/lib.rs', body)
                res = self.run_guard()
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_real_uses_still_fail_next_to_benign_forms(self):
        cases = {
            'crate-path-with-local-zip': 'fn f() {\n    let zip = 1;\n    let _ = zip::ZipArchive::new;\n}\n',
            'macro-input-in-other-fn': (
                'fn f(zip: u8) { println!("{}", zip); }\nfn g() { my_macro!(zip); }\n'),
            'archive-extract-with-iter-zip': (
                'fn f(ar: Archive, a: &[u8], b: &[u8]) {\n    ar.extract(p);\n    let _ = a.iter().zip(b);\n}\n'),
            'type-after-doc-comment': '/// docs\nfn f(a: ZipArchive) {}\n',
            'use-after-comment': '// zip\nuse zip::read;\n',
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                self.write('src/lib.rs', body)
                res = self.run_guard()
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('src/lib.rs:', res.stdout)


if __name__ == '__main__':
    unittest.main()
