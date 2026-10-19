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


def load_guard_module():
    """The guard imported as a module (its functions under test)."""
    spec = importlib.util.spec_from_file_location('zip_guard_under_test', str(GUARD))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def default_meta(root):
    """cargo metadata JSON naming only the fixture root package."""
    return {'packages': [{'name': 'fixture', 'source': None, 'manifest_path': str(Path(root) / 'Cargo.toml'),
                          'targets': [{'kind': ['lib'], 'name': 'fixture',
                                       'src_path': str(Path(root) / 'src' / 'lib.rs')}]}]}


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

    def meta_args(self, root=None, meta=None):
        """`--cargo-metadata-file <file>`: --cargo-tree-file requires it (#7305)."""
        meta_file = self.root.parent / (self.root.name + '.meta')
        meta_file.write_text(json.dumps(meta if meta is not None else default_meta(root or self.root)),
                             encoding='utf-8')
        self.addCleanup(lambda: meta_file.unlink() if meta_file.exists() else None)
        return ['--cargo-metadata-file', str(meta_file)]

    def run_guard(self, tree=GOOD_TREE_DEPTH, root=None, extra=(), meta=None):
        tree_file = self.root.parent / (self.root.name + '.tree')
        tree_file.write_text(tree, encoding='utf-8')
        self.addCleanup(lambda: tree_file.unlink() if tree_file.exists() else None)
        extra = list(extra) + self.meta_args(root, meta)
        return subprocess.run(
            [sys.executable, str(GUARD), '--root', str(root or self.root),
             '--cargo-tree-file', str(tree_file)] + extra,
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
        """Runs the real guard (cargo tree, metadata and check) against this checkout.

        The compiler step builds the whole workspace (a cold build takes more than 10 minutes), so
        this runs only with ZIP_GUARD_REAL_CARGO=1; CI exercises it in the Security audit step.
        """
        if os.environ.get('ZIP_GUARD_REAL_CARGO') != '1':
            self.skipTest('set ZIP_GUARD_REAL_CARGO=1 to run the real cargo check (CI runs the guard itself)')
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


STUB_SCRIPT = '''#!PYTHON
"""PATH cargo shim for the guard tests. Config: JSON file named by ZIP_STUB_CONFIG.

keys: log (argv log), out/err/rc (tree answer), refuse_offline, metadata_fail, spec (JSON file or null).
spec: {"check_rc": 0, "check_err": "", "packages": [{"name", "dir", "member", "targets": [{"kind", "name", "src",
"deps": [raw dep-info tokens], "artifact": true, "dfile": true, "dtext": null}]}]}; `{cwd}` and `{tgt}` in a
dep token are replaced. Default spec: the fixture lib listing src/lib.rs.
"""
import json
import os
import sys

config = json.load(open(os.environ['ZIP_STUB_CONFIG']))
with open(config['log'], 'a') as fh:
    fh.write(json.dumps(sys.argv[1:]) + '\\n')
cwd = os.getcwd()
tgt = cwd + '/.stub-target'
spec = json.load(open(config['spec'])) if config.get('spec') else {}
packages = spec.get('packages') or [{'name': 'fixture', 'dir': cwd, 'member': True, 'targets': [
    {'kind': ['lib'], 'name': 'fixture', 'src': 'src/lib.rs', 'deps': ['src/lib.rs']}]}]


def pkg_dir(package):
    return package['dir'] if os.path.isabs(package['dir']) else os.path.join(cwd, package['dir'])


def pkg_id(package):
    return 'path+file://' + pkg_dir(package) + '#' + package['name'] + '@0.0.0'


args = sys.argv[1:]
if args and args[0] == 'metadata':
    if config.get('metadata_fail'):
        sys.stderr.write('error: failed to load manifest\\n')
        sys.exit(101)
    docs = []
    for package in packages:
        docs.append({'name': package['name'], 'id': pkg_id(package), 'source': None,
                     'manifest_path': pkg_dir(package) + '/Cargo.toml',
                     'targets': [{'kind': t['kind'], 'name': t['name'],
                                  'src_path': os.path.join(pkg_dir(package), t['src'])} for t in package['targets']]})
    members = [pkg_id(p) for p in packages if p.get('member', True)]
    sys.stdout.write(json.dumps({'packages': docs, 'workspace_members': members, 'target_directory': tgt}))
    sys.exit(0)
if args and args[0] == 'check':
    if spec.get('check_rc'):
        sys.stderr.write(spec.get('check_err', 'error: could not compile\\n'))
        sys.exit(spec['check_rc'])
    count = 0
    for package in packages:
        for target in package['targets']:
            if not target.get('artifact', True):
                continue
            count += 1
            if 'custom-build' in target['kind']:
                out_dir = '%s/debug/build/%s-h%d' % (tgt, package['name'], count)
                out, dfile = out_dir + '/build-script-build', out_dir + '/build_script_build-h%d.d' % count
            else:
                out_dir = tgt + '/debug/deps'
                out = '%s/lib%s_%d-h.rmeta' % (out_dir, target['name'], count)
                dfile = '%s/%s_%d-h.d' % (out_dir, target['name'], count)
            os.makedirs(out_dir, exist_ok=True)
            deps = [d.replace('{cwd}', cwd).replace('{tgt}', tgt) for d in target.get('deps', [])]
            if target.get('dfile', True):
                text = target.get('dtext')
                if text is None:
                    text = dfile + ': ' + ' '.join(deps) + '\\n' + ''.join(d + ':\\n' for d in deps)
                else:
                    text = text.replace('{cwd}', cwd).replace('{tgt}', tgt)
                with open(dfile, 'w') as handle:
                    handle.write(text)
            sys.stdout.write(json.dumps({
                'reason': 'compiler-artifact', 'package_id': pkg_id(package),
                'target': {'kind': target['kind'], 'name': target['name'],
                           'src_path': os.path.join(pkg_dir(package), target['src'])},
                'filenames': [out], 'fresh': False}) + '\\n')
    sys.stdout.write('{"reason":"build-finished","success":true}\\n')
    sys.exit(0)
if config.get('refuse_offline') and '--offline' in args:
    sys.stderr.write('error: failed to download `anstyle-wincon v3.0.11`\\n'
                     'Caused by: attempting to make an HTTP request, but --offline was specified\\n')
    sys.exit(101)
sys.stdout.write(config.get('out', ''))
sys.stderr.write(config.get('err', ''))
sys.exit(config.get('rc', 0))
'''

LOCK_WITH_ZIP = CANDLE_LOCK + ('[[package]]\nname = "zip"\nversion = "7.2.0"\n'
                               'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
LOCK_WITHOUT_ZIP = '[[package]]\nname = "serde"\nversion = "1.0.0"\n'
NO_MATCH_ERR = 'error: package ID specification `zip` did not match any packages\n'


class StubCargoCase(GuardBase):
    """Runs the guard against a stub `cargo` placed first on PATH."""

    def stub_env(self, spec=None, **config):
        """Install the stub as `cargo` on a PATH dir and return the environment that selects it."""
        stub_dir = self.root.parent / (self.root.name + '.bin')
        stub_dir.mkdir(exist_ok=True)
        self.addCleanup(shutil.rmtree, str(stub_dir), True)
        self.argv_log = stub_dir / 'argv.log'
        spec_file = None
        if spec is not None:
            spec_file = stub_dir / 'spec.json'
            spec_file.write_text(json.dumps(spec), encoding='utf-8')
        config.update(log=str(self.argv_log), spec=str(spec_file) if spec_file else None)
        config_file = stub_dir / 'config.json'
        config_file.write_text(json.dumps(config), encoding='utf-8')
        stub = stub_dir / 'cargo'
        stub.write_text(STUB_SCRIPT.replace('#!PYTHON', '#!' + sys.executable, 1), encoding='utf-8')
        stub.chmod(0o755)
        env = dict(os.environ)
        env['PATH'] = str(stub_dir) + os.pathsep + env.get('PATH', '')
        env['ZIP_STUB_CONFIG'] = str(config_file)
        return env

    def run_stub(self, out='', err='', rc=0, lock=None, spec=None, **config):
        if lock is not None:
            (self.root / 'Cargo.lock').write_text(lock, encoding='utf-8')
        env = self.stub_env(spec=spec, out=out, err=err, rc=rc, **config)
        return subprocess.run(
            [sys.executable, str(GUARD), '--root', str(self.root)],
            capture_output=True, text=True, check=False, env=env)


class CleanCargoHome7301(StubCargoCase):
    """Round 4 (CI): the guard must work on a runner that has not fetched every target."""

    def argv_of_run(self):
        res = self.run_stub(out=GOOD_TREE_DEPTH, lock=LOCK_WITH_ZIP)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        lines = self.argv_log.read_text(encoding='utf-8').splitlines()
        trees = [json.loads(line) for line in lines if json.loads(line)[0] == 'tree']
        self.assertEqual(len(trees), 1, lines)
        return trees[0]

    def test_cargo_tree_argv_has_no_offline_flag(self):
        self.assertNotIn('--offline', self.argv_of_run())

    def test_cargo_tree_argv_keeps_locked_and_all_targets(self):
        argv = self.argv_of_run()
        self.assertIn('--locked', argv)
        self.assertEqual(target_value(argv), 'all')

    def test_download_needed_is_not_refused_by_guard_flags(self):
        """A cargo that refuses to download under --offline: the guard must not pass that flag."""
        res = self.run_stub(out=GOOD_TREE_DEPTH, lock=LOCK_WITH_ZIP, refuse_offline=True)
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
            top + PACKAGE_ONLY + body, encoding='utf-8')
        tree_file = self.root.parent / (self.root.name + '.tree')
        tree_file.write_text(GOOD_TREE_DEPTH, encoding='utf-8')
        self.addCleanup(lambda: tree_file.unlink() if tree_file.exists() else None)
        return subprocess.run(
            [sys.executable, str(GUARD), '--root', str(self.root), '--cargo-tree-file', str(tree_file),
             '--manifest-parser', parser] + self.meta_args(), capture_output=True, text=True, check=False)

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
                     '--manifest-parser', parser] + self.meta_args(REPO), capture_output=True, text=True, check=False)
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
                    [str(PY39), str(GUARD), '--root', str(self.root), '--cargo-tree-file', str(tree_file)]
                    + self.meta_args(),
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
        for line in ('1candle-core v0.10.2', '1candle-core v0.10.2 (*)'):
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


class RuleFixtures7305To7312(GuardBase):
    """Eight LOW findings off PR #7303 (#7305-#7312): a fail and a pass fixture per rule."""

    def write(self, rel, text):
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
        return target

    def meta(self, *dirs):
        """cargo metadata JSON: the fixture root, local packages at `dirs`, and a registry package."""
        packages = [{'name': 'fixture', 'source': None, 'manifest_path': str(self.root / 'Cargo.toml'),
                     'targets': [{'kind': ['lib'], 'name': 'fixture', 'src_path': str(self.root / 'src' / 'lib.rs')}]}]
        for rel in dirs:
            base = Path(rel) if os.path.isabs(rel) else self.root / rel
            packages.append({'name': base.name, 'source': None, 'manifest_path': str(base / 'Cargo.toml'),
                             'targets': [{'kind': ['lib'], 'name': base.name,
                                          'src_path': str(base / 'src' / 'lib.rs')}]})
        packages.append({'name': 'serde', 'source': 'registry+https://github.com/rust-lang/crates.io-index',
                         'manifest_path': '/registry/serde/Cargo.toml'})
        return {'packages': packages}

    def member(self, rel, lib):
        self.write(rel + '/Cargo.toml', '[package]\nname = "m"\nversion = "0.0.0"\n')
        self.write(rel + '/src/lib.rs', lib)

    def manifest_rc(self, body, parser, top=''):
        self.write('Cargo.toml', top + PACKAGE_ONLY + body)
        return self.run_guard(extra=('--manifest-parser', parser))

    # --- #7305: local path-dependency crates and implicit workspace members ---------
    def test_path_dependency_crate_is_scanned_7305(self):
        self.member('crates/loader', 'pub fn f() { candle_core::Tensor::read_npz("m.npz"); }\n')
        res = self.run_guard(meta=self.meta('crates/loader'))
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('crates/loader/src/lib.rs:1', res.stdout)
        self.assertIn('candle-loader', res.stdout)

    def test_implicit_workspace_member_is_scanned_7305(self):
        self.member('crates/loader', 'pub fn f() { VarBuilder::from_pth(p, d, v); }\n')
        for parser in BOTH_PARSERS:
            with self.subTest(parser=parser):
                self.write('Cargo.toml', MINIMAL_MANIFEST + '\n[workspace]\n')
                res = self.run_guard(meta=self.meta('crates/loader'), extra=('--manifest-parser', parser))
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('crates/loader/src/lib.rs:1', res.stdout)

    def test_path_dependency_outside_the_root_is_scanned_7305(self):
        outside = self.root.parent / (self.root.name + '.dep')
        self.addCleanup(shutil.rmtree, str(outside), True)
        outside.mkdir()
        self.member(os.path.relpath(str(outside), str(self.root)), 'pub fn f() { zip::ZipArchive::new; }\n')
        res = self.run_guard(meta=self.meta(str(outside)))
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('src/lib.rs:1', res.stdout)

    def test_clean_path_dependency_passes_7305(self):
        self.member('crates/clean', 'pub fn f() -> u8 { 1 }\n')
        res = self.run_guard(meta=self.meta('crates/clean'))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    # --- #7306: inline-table workspace and patch forms in the fallback reader --------
    def test_inline_table_workspace_members_fail_7306(self):
        for parser in BOTH_PARSERS:
            with self.subTest(parser=parser):
                res = self.manifest_rc('', parser, top='workspace = { members = ["crates/x"] }\n')
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('workspace', res.stdout)

    def test_inline_table_patch_forms_fail_7306(self):
        forms = {
            'patch-crates-io-zip': '[patch]\ncrates-io = { zip = { path = ".." } }\n',
            'patch-crates-io-candle': '[patch]\ncrates-io = { candle-core = { path = ".." } }\n',
            'patch-renamed': '[patch]\ncrates-io = { x = { package = "zip", path = ".." } }\n',
            'patch-dotted-zip': '[patch]\ncrates-io = { zip.path = ".." }\n',
            'patch-dotted-candle': '[patch]\ncrates-io = { candle-core.path = ".." }\n',
        }
        for parser in BOTH_PARSERS:
            for name, body in forms.items():
                with self.subTest(parser=parser, form=name):
                    res = self.manifest_rc(body, parser)
                    self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                    self.assertIn('Cargo.toml', res.stdout)

    def test_toplevel_inline_patch_fails_7306(self):
        for parser in BOTH_PARSERS:
            with self.subTest(parser=parser):
                res = self.manifest_rc('', parser, top='patch = { crates-io = { zip = { path = ".." } } }\n')
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('Cargo.toml', res.stdout)

    def test_inline_table_benign_forms_pass_7306(self):
        for parser in BOTH_PARSERS:
            with self.subTest(parser=parser, form='empty-members'):
                res = self.manifest_rc('', parser, top='workspace = { members = [] }\n')
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            with self.subTest(parser=parser, form='unrelated-patch'):
                res = self.manifest_rc('[patch]\ncrates-io = { serde = { path = ".." } }\n', parser)
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    # --- #7307: paste! identifier pieces ---------------------------------------------
    def test_paste_pieces_carry_loader_call_7307(self):
        calls = {
            'split-piece': 'paste::paste! { candle_core::Tensor::[<read_ npz>]("m.npz") }\n',
            'bare-paste': 'paste! { Tensor::[<read_ npy>](p) }\n',
            'prefixed': 'paste! { Tensor::[<try_ read_npz>](p) }\n',
            'from-pth': 'paste::paste! { VarBuilder::[<from_ pth>](p) }\n',
            'upper-with-lower-modifier': 'paste::paste! { Tensor::[<READ_NPZ:lower>](p) }\n',
            'camel-with-snake-modifier': 'paste::paste! { Tensor::[<ReadNpz:snake>](p) }\n',
            'aliased-macro': 'use paste::paste as p; p!{ Tensor::[<read_ npz>](p) }\n',
        }
        for name, body in calls.items():
            with self.subTest(case=name):
                self.write('src/lib.rs', body)
                res = self.run_guard()
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('src/lib.rs:1', res.stdout)

    def test_benign_paste_passes_7307(self):
        self.write('src/lib.rs', (
            'paste::paste! {\n    pub fn [<get_ name>]() {}\n    pub fn [<set_ $x>]() {}\n}\n'
            'pub fn g(a: [u8; 2]) -> u8 { a[0] }\n'))
        res = self.run_guard()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    # --- #7308: the zip-binding exemption ends with its fn body ----------------------
    def test_zip_binding_exemption_ends_at_fn_body_7308(self):
        cases = {
            'after-fn': 'pub fn a(zip: u8) -> u8 { zip }\nm!(zip);\n',
            'after-nested-braces': 'pub fn a(zip: u8) { if zip > 0 { drop(1); } }\nm!(zip);\n',
            'bodyless-decl': 'trait T { fn g(zip: u8); }\nm!(zip);\n',
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                self.write('src/lib.rs', body)
                res = self.run_guard()
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('macro input', res.stdout)

    def test_zip_binding_inside_its_fn_body_passes_7308(self):
        cases = {
            'nested-block': 'pub fn f(zip: bool) { if zip { println!("{}", zip); } }\n',
            'generic-where': 'pub fn f<T>(zip: T) -> T where T: Copy { assert_eq!(1, 1); zip }\n',
            'let-then-macro': 'fn f() {\n    let zip = 1;\n    { assert_eq!(zip, 1); }\n}\n',
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                self.write('src/lib.rs', body)
                res = self.run_guard()
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    # --- #7309: the candle-core parent pin is exactly 0.10.2 -------------------------
    def test_candle_core_0_10_3_tree_line_fails_7309(self):
        for line in ('1candle-core v0.10.3', '1candle-core v0.10.9 (*)', '1candle-core v0.10.20'):
            with self.subTest(line=line):
                res = self.run_guard(tree='0zip v7.2.0\n%s\n' % line)
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('candle-core', res.stdout)

    def test_candle_core_0_10_3_lock_entry_fails_7309(self):
        self.write('Cargo.lock', CANDLE_LOCK.replace('0.10.2', '0.10.3'))
        res = self.run_guard()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('Cargo.lock', res.stdout)

    def test_candle_core_0_10_2_still_passes_7309(self):
        res = self.run_guard(tree='0zip v7.2.0\n1candle-core v0.10.2\n')
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    # --- #7310: build-time generated modules -----------------------------------------
    def test_build_script_string_with_loader_call_fails_7310(self):
        self.write('build.rs', (
            'fn main() {\n    std::fs::write("src/gen.rs", "fn g() { Tensor::read_npz(p); }").unwrap();\n}\n'))
        self.write('src/gen.rs', 'pub fn g() {}\n')
        self.write('src/lib.rs', 'mod gen;\n')
        res = self.run_guard()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('build.rs:2', res.stdout)

    # --- #7311: [replace] package-ID keys and the registry origin --------------------
    def test_replace_package_id_keys_fail_7311(self):
        keys = ('zip@7.2.0', 'candle-core@0.10.2',
                'registry+https://github.com/rust-lang/crates.io-index#zip@7.2.0',
                'registry+https://github.com/rust-lang/crates.io-index#candle-core@0.10.2')
        for parser in BOTH_PARSERS:
            for key in keys:
                with self.subTest(parser=parser, key=key):
                    res = self.manifest_rc('[replace]\n"%s" = { path = "../c" }\n' % key, parser)
                    self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                    self.assertIn('[replace]', res.stdout)

    def test_unrelated_replace_keys_pass_7311(self):
        keys = ('serde@1.0.0', 'zipper@1.0.0', 'registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0')
        for parser in BOTH_PARSERS:
            for key in keys:
                with self.subTest(parser=parser, key=key):
                    res = self.manifest_rc('[replace]\n"%s" = { path = "../c" }\n' % key, parser)
                    self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_zip_lock_entry_must_be_registry_7_2_0_7311(self):
        head = '[[package]]\nname = "zip"\n'
        registry = 'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        locks = {
            'no-source': CANDLE_LOCK + head + 'version = "7.2.0"\n',
            'git': CANDLE_LOCK + head + 'version = "7.2.0"\nsource = "git+https://github.com/x/zip#abc"\n',
            'other-registry': CANDLE_LOCK + head + 'version = "7.2.0"\nsource = "registry+https://example.com/index"\n',
            'other-version': CANDLE_LOCK + head + 'version = "7.2.1"\n' + registry,
            'second-entry': LOCK_WITH_ZIP + head + 'version = "9.0.0"\n' + registry,
        }
        for name, lock in locks.items():
            with self.subTest(lock=name):
                self.write('Cargo.lock', lock)
                res = self.run_guard()
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('Cargo.lock', res.stdout)

    def test_zip_registry_lock_entry_passes_7311(self):
        self.write('Cargo.lock', LOCK_WITH_ZIP)
        res = self.run_guard()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_zip_tree_root_with_source_suffix_fails_7311(self):
        for root_line in ('0zip v7.2.0 (/w/v/zip)', '0zip v7.2.0 (https://github.com/x/zip#abc)'):
            with self.subTest(root=root_line):
                res = self.run_guard(tree='%s\n1candle-core v0.10.2\n' % root_line)
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('zip', res.stdout)

    def test_zip_tree_root_plain_and_repeat_pass_7311(self):
        for root_line in ('0zip v7.2.0', '0zip v7.2.0 (*)'):
            with self.subTest(root=root_line):
                res = self.run_guard(tree='%s\n1candle-core v0.10.2\n' % root_line)
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    # --- round 2 (r1 review of PR #7777): F1-F6 ----------------------------------------
    def test_tree_file_without_metadata_file_is_usage_error_7305(self):
        """F1: no metadata means no local package would be scanned, so the guard refuses to run."""
        self.member('crates/loader', 'pub fn f() { Tensor::read_npz(p); }\n')
        tree_file = self.root.parent / (self.root.name + '.tree')
        tree_file.write_text(GOOD_TREE_DEPTH, encoding='utf-8')
        self.addCleanup(lambda: tree_file.unlink() if tree_file.exists() else None)
        res = subprocess.run(
            [sys.executable, str(GUARD), '--root', str(self.root), '--cargo-tree-file', str(tree_file)],
            capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn('--cargo-tree-file requires --cargo-metadata-file', res.stderr)
        self.assertNotIn('check-zip-extract-unreachable: ok', res.stdout)

    def test_tree_file_with_metadata_file_scans_the_path_dependency_7305(self):
        self.member('crates/loader', 'pub fn f() { Tensor::read_npz(p); }\n')
        res = self.run_guard(meta=self.meta('crates/loader'))
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)

    def test_each_scanned_file_keeps_its_own_location_prefix_7305(self):
        """F4: the rule name never leaks into the location of the next file."""
        self.member('crates/loader', 'pub fn f() { Tensor::read_npz(p); }\n')
        self.write('crates/loader/src/b.rs', 'pub fn g() { Tensor::read_npy(p); }\n')
        self.write('crates/loader/src/c.rs', 'pub fn h() { Tensor::write_npz(p); }\n')
        res = self.run_guard(meta=self.meta('crates/loader'))
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        lines = res.stdout.splitlines()
        for name in ('lib', 'b', 'c'):
            self.assertIn('violation: crates/loader/src/%s.rs:1: candle-loader' % name, lines, res.stdout)

    def test_declared_target_without_a_file_fails_7310(self):
        """F2: a manifest-declared path with no file on disk could be written by a build step."""
        forms = {
            'lib-path': '[lib]\npath = "gen/lib.rs"\n',
            'bin-path': '[[bin]]\nname = "t"\npath = "gen/t.rs"\n',
        }
        for name in ('lib-path', 'bin-path'):
            with self.subTest(case=name):
                res = self.manifest_rc(forms[name], 'fallback')
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('declared target has no file on disk; a build step could generate it', res.stdout)
                self.assertIn('gen/', res.stdout)
        with self.subTest(case='build'):
            self.write('Cargo.toml', MINIMAL_MANIFEST.replace('[dependencies]', 'build = "gen/build.rs"\n\n[dependencies]'))
            res = self.run_guard()
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            self.assertIn('declared target has no file on disk', res.stdout)

    def test_declared_target_with_a_file_passes_7310(self):
        self.write('gen/lib.rs', 'pub fn g() {}\n')
        self.write('gen/t.rs', 'fn main() {}\n')
        body = '[lib]\npath = "gen/lib.rs"\n[[bin]]\nname = "t"\npath = "gen/t.rs"\n'
        for parser in BOTH_PARSERS:
            with self.subTest(parser=parser):
                res = self.manifest_rc(body, parser)
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    # --- round 3 (r2 review of PR #7777): N1-N4 ----------------------------------------
    def meta_targets(self, root_paths=(), build_paths=(), members=()):
        """cargo metadata JSON whose root package carries `targets`; `members` is (dir, [src paths])."""
        def targets(paths, builds=()):
            found = [{'kind': ['lib'], 'name': 't', 'src_path': str(self.root / rel)} for rel in paths]
            found += [{'kind': ['custom-build'], 'name': 'build-script-build', 'src_path': str(self.root / rel)}
                      for rel in builds]
            return found
        packages = [{'name': 'fixture', 'source': None, 'manifest_path': str(self.root / 'Cargo.toml'),
                     'targets': targets(root_paths or ['src/lib.rs'], build_paths)}]
        for rel, paths in members:
            packages.append({'name': Path(rel).name, 'source': None,
                             'manifest_path': str(self.root / rel / 'Cargo.toml'),
                             'targets': [{'kind': ['lib'], 'name': 'm', 'src_path': str(self.root / p)}
                                         for p in paths or ['%s/src/lib.rs' % rel]]})
        return {'packages': packages}

    def test_inline_table_and_array_targets_come_from_metadata_7310(self):
        """N3: `lib = { path = .. }` and `bin = [{ .. }]` are read from cargo metadata src_path."""
        cases = {
            'c1-missing-inline-lib': ('lib = { path = "gen/lib.rs" }\n', None, 'declared target has no file on disk'),
            'c2-loader-inline-lib': ('lib = { path = "other/lib.rs" }\n',
                                     'pub fn f() { Tensor::read_npz(p); }\n', 'candle-loader'),
            'c3-loader-bin-array': ('bin = [{ name = "x", path = "other/x.rs" }]\n',
                                    'fn main() { Tensor::read_npz(p); }\n', 'candle-loader'),
        }
        paths = {'c1-missing-inline-lib': 'gen/lib.rs', 'c2-loader-inline-lib': 'other/lib.rs',
                 'c3-loader-bin-array': 'other/x.rs'}
        for name, (decl, body, message) in cases.items():
            with self.subTest(case=name):
                self.write('Cargo.toml', PACKAGE_ONLY + decl)
                if body is not None:
                    self.write(paths[name], body)
                res = self.run_guard(meta=self.meta_targets([paths[name]]))
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn(message, res.stdout)
                self.assertIn(paths[name].split('/')[0] + '/', res.stdout)
                if body is not None:
                    (self.root / paths[name]).unlink()

    def test_inline_table_target_with_a_clean_file_passes_7310(self):
        self.write('Cargo.toml', PACKAGE_ONLY + 'lib = { path = "other/lib.rs" }\n')
        self.write('other/lib.rs', 'pub fn g() {}\n')
        res = self.run_guard(meta=self.meta_targets(['other/lib.rs']))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_local_package_target_outside_src_is_scanned_7310(self):
        self.member('crates/m', 'pub fn ok() {}\n')
        self.write('crates/m/other/x.rs', 'fn f() { Tensor::read_npz(p); }\n')
        res = self.run_guard(meta=self.meta_targets((), (), [('crates/m', ['crates/m/other/x.rs'])]))
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('crates/m/other/x.rs:1', res.stdout)

    def test_build_script_target_from_metadata_scans_its_strings_7310(self):
        self.write('tools/b.rs', 'fn main() { std::fs::write("g.rs", "fn g() { Tensor::read_npz(p); }").unwrap(); }\n')
        res = self.run_guard(meta=self.meta_targets((), ['tools/b.rs']))
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('tools/b.rs:1', res.stdout)

    def test_metadata_without_the_root_package_is_usage_error_7305(self):
        """N4: a metadata document that omits the root manifest scans no local package: refuse it."""
        for name, meta in (('empty', {'packages': []}),
                           ('other-root', {'packages': [{'name': 'x', 'source': None,
                                                         'manifest_path': '/elsewhere/Cargo.toml',
                                                         'targets': [{'kind': ['lib'], 'name': 'x',
                                                                      'src_path': '/elsewhere/src/lib.rs'}]}]})):
            with self.subTest(case=name):
                res = self.run_guard(meta=meta)
                self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
                self.assertIn('no package with manifest_path', res.stderr)
                self.assertNotIn('check-zip-extract-unreachable: ok', res.stdout)

    # --- round 4 (r3 review of PR #7777): E, F, G1, L3 ---------------------------------
    LOADER = 'pub fn f() { Tensor::read_npz(p); }\n'

    def test_cargo_timeout_is_a_tool_error_7310(self):
        """L-c: a hung cargo ends as ToolError (rc 2) naming the command, and both calls carry a timeout."""
        module = load_guard_module()
        seen = []

        def hang(argv, **kwargs):
            seen.append(kwargs.get('timeout'))
            raise subprocess.TimeoutExpired(argv, kwargs.get('timeout'))

        real = module.subprocess.run
        module.subprocess.run = hang
        try:
            for call, name in ((module.cargo_tree_output, 'cargo tree'), (module.cargo_metadata_output, 'cargo metadata')):
                with self.subTest(call=name):
                    with self.assertRaises(module.ToolError) as caught:
                        call(self.root)
                    self.assertIn(name, str(caught.exception))
                    self.assertIn('timed out', str(caught.exception))
        finally:
            module.subprocess.run = real
        self.assertEqual(seen, [600, 600])

    def test_package_without_targets_is_usage_error_7305(self):
        """G1: a local package whose metadata lacks `targets` (or lists none) is a tool error."""
        base = default_meta(self.root)
        absent = {'packages': [{key: value for key, value in base['packages'][0].items() if key != 'targets'}]}
        for name, meta in (('absent', absent),
                           ('empty', {'packages': [dict(base['packages'][0], targets=[])]}),
                           ('not-a-list', {'packages': [dict(base['packages'][0], targets='lib')]})):
            with self.subTest(case=name):
                res = self.run_guard(meta=meta)
                self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
                self.assertIn('has no targets', res.stderr)
                self.assertNotIn('check-zip-extract-unreachable: ok', res.stdout)

    def test_paste_loader_pattern_is_pinned_7307(self):
        """L3: both loader patterns come from LOADER_NAMES; the paste form is pinned to its literal."""
        spec = importlib.util.spec_from_file_location('zip_guard_under_test', str(GUARD))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(
            module.PASTE_LOADER_NORMAL.pattern,
            r'(?:readnpz\w*|readnpy|writenpz|writenpy|readpth\w*|frompth\w*|fromnpz|npztensors|pthtensors'
            r'|readallwithkey)\b')
        self.assertEqual(
            dict(module.FORBIDDEN)['candle-loader'].pattern,
            r'\b(?:read_npz\w*|read_npy|write_npz|write_npy|read_pth\w*|from_pth\w*|from_npz|NpzTensors'
            r'|PthTensors|read_all_with_key)\b')


class CompilerDepInfo7777R7(StubCargoCase):
    """Review round 7 (3-agent vote 6def5ab6): rule (c) reachability comes from rustc dep-info.

    The PATH cargo stub answers `cargo check --message-format=json` with one compiler-artifact
    per declared target and writes the dep-info (.d) file each fixture lists. Every module-
    resolution bypass of rounds 2 to 6 is now a file the compiler lists.
    """

    HIDDEN_ZIP = 'fn f() {\n    let _ = zip::ZipArchive::new;\n}\n'
    HIDDEN_LOADER = 'fn f() {\n    Tensor::read_npz(p);\n}\n'

    def write(self, rel, text):
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
        return target

    def lib_spec(self, deps, **target):
        entry = {'kind': ['lib'], 'name': 'fixture', 'src': 'src/lib.rs', 'deps': deps}
        entry.update(target)
        return {'packages': [{'name': 'fixture', 'dir': str(self.root), 'member': True, 'targets': [entry]}]}

    def run_dep(self, spec, **config):
        return self.run_stub(out=GOOD_TREE_DEPTH, lock=LOCK_WITH_ZIP, spec=spec, **config)

    def test_clean_tree_passes_and_runs_the_exact_check_command(self):
        res = self.run_dep(self.lib_spec(['src/lib.rs']))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('check-zip-extract-unreachable: ok', res.stdout)
        calls = [json.loads(line) for line in self.argv_log.read_text(encoding='utf-8').splitlines()]
        checks = [argv for argv in calls if argv and argv[0] == 'check']
        self.assertEqual(checks, [['check', '--workspace', '--all-targets', '--all-features', '--locked',
                                   '--message-format=json']])

    def test_file_listed_by_depinfo_outside_the_scan_dirs_is_scanned(self):
        """Former resolver bypasses (cfg_attr path, #[path] on a mod-rs root, inner #![path], long attribute
        look-back, mod inside macro input): the hidden file is whatever the compiler read. The path is
        built with concat! so the literal rule cannot find it; only the dep-info list can."""
        forms = (
            ('cfg-attr-path', '#[cfg_attr(unix, path = concat!("../gen/", "h.rs"))]\nmod h;\n'),
            ('path-on-mod-rs-root', '#[path = concat!("../gen/", "h.rs")]\nmod h;\n'),
            ('inner-path-attribute', '#![path = concat!("../gen/", "h.rs")]\n'),
            ('long-attribute-look-back',
             '#[cfg_attr(unix, doc = "' + 'x' * 400 + '", path = concat!("../gen/", "h.rs"))]\nmod h;\n'),
            ('mod-inside-macro-input', 'macro_rules! m { ($n:ident) => { mod $n; }; }\nm!(h);\n'),
            ('no-hint-in-the-source', 'pub fn ok() {}\n'),
        )
        for name, lib in forms:
            with self.subTest(form=name):
                self.write('src/lib.rs', lib)
                self.write('gen/h.rs', self.HIDDEN_ZIP)
                res = self.run_dep(self.lib_spec(['src/lib.rs', 'gen/h.rs']))
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('violation: gen/h.rs:2', res.stdout)

    def test_inline_table_target_file_listed_by_depinfo_is_scanned(self):
        self.write('custom/lib.rs', 'mod sub;\n')
        self.write('custom/sub.rs', self.HIDDEN_LOADER)
        res = self.run_dep(self.lib_spec(['custom/lib.rs', 'custom/sub.rs'], src='custom/lib.rs'))
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('custom/sub.rs:2', res.stdout)

    def test_symlink_alias_listed_by_depinfo_is_scanned(self):
        self.write('elsewhere/real.rs', self.HIDDEN_ZIP)
        (self.root / 'gen').mkdir()
        os.symlink('../elsewhere/real.rs', str(self.root / 'gen' / 'alias.rs'))
        res = self.run_dep(self.lib_spec(['src/lib.rs', 'gen/alias.rs']))
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('gen/alias.rs:2', res.stdout)

    def test_missing_module_makes_cargo_check_fail_and_the_guard_exit_2(self):
        """Former 'mod without a file' violation: now the compiler fails, so the guard cannot decide."""
        self.write('src/lib.rs', 'mod gen;\n')
        spec = self.lib_spec(['src/lib.rs'])
        spec['check_rc'] = 1
        spec['check_err'] = 'error[E0583]: file not found for module `gen`\n'
        res = self.run_dep(spec)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn('cargo check failed rc=1', res.stderr)
        self.assertNotIn('violation:', res.stdout)

    def test_target_without_a_compiler_artifact_exits_2(self):
        res = self.run_dep(self.lib_spec(['src/lib.rs'], artifact=False))
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn('built no target', res.stderr)
        self.assertNotIn('violation:', res.stdout)

    def test_missing_depinfo_file_exits_2(self):
        res = self.run_dep(self.lib_spec(['src/lib.rs'], dfile=False))
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn('no dep-info file', res.stderr)

    def test_malformed_or_empty_depinfo_exits_2(self):
        for name, text in (('no-colon', 'src/lib.rs src/other.rs\n'), ('empty-rule', 'out.d:\n'), ('blank', '\n')):
            with self.subTest(case=name):
                res = self.run_dep(self.lib_spec([], dtext=text))
                self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
                self.assertIn('dep-info', res.stderr)

    def test_listed_rs_file_that_does_not_exist_exits_2(self):
        res = self.run_dep(self.lib_spec(['src/lib.rs', 'gen/gone.rs']))
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn('does not exist', res.stderr)

    def test_unreadable_listed_file_exits_2(self):
        (self.root / 'gen').mkdir()
        (self.root / 'gen' / 'bin.rs').write_bytes(b'\xff\xfe not utf8\n')
        res = self.run_dep(self.lib_spec(['src/lib.rs', 'gen/bin.rs']))
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn('cannot read gen/bin.rs', res.stderr)

    def test_makefile_escapes_in_listed_paths_are_read(self):
        cases = (
            ('space', 'gen/my\\ dir/a.rs', 'gen/my dir/a.rs'),
            ('colon', 'gen/a\\:b.rs', 'gen/a:b.rs'),
            ('backslash', 'gen/c\\\\d.rs', 'gen/c\\d.rs'),
            ('dollar', 'gen/e$$f.rs', 'gen/e$f.rs'),
            ('hash', 'gen/g\\#h.rs', 'gen/g#h.rs'),
            ('space-and-colon', 'gen/i\\ j\\:k.rs', 'gen/i j:k.rs'),
        )
        for name, token, real in cases:
            with self.subTest(escape=name):
                self.write(real, self.HIDDEN_ZIP)
                res = self.run_dep(self.lib_spec(['src/lib.rs', token]))
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn(real + ':2', res.stdout)

    def test_depinfo_tokenizer_cases(self):
        module = load_guard_module()
        cases = (
            ('out.d: a.rs b.rs', (['out.d', 'a.rs', 'b.rs'], 1)),
            ('o\\ ut.d: a\\ b.rs', (['o ut.d', 'a b.rs'], 1)),
            ('a\\:b.d: c\\:d.rs', (['a:b.d', 'c:d.rs'], 1)),
            ('x.d: p\\\\q.rs $$z.rs', (['x.d', 'p\\q.rs', '$z.rs'], 1)),
            ('src/a.rs:', (['src/a.rs'], 1)),
            ('C:\\dir\\a.rs: b.rs', (['C:\\dir\\a.rs', 'b.rs'], 1)),
            ('no colon here', (['no', 'colon', 'here'], None)),
        )
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertEqual(module.depinfo_tokens(line), expected)

    def test_registry_or_git_checkout_path_in_a_local_target_is_a_violation(self):
        for token in ('/nonexistent/.cargo/registry/src/index.crates.io-abc/foo-1.0.0/src/lib.rs',
                      '/nonexistent/.cargo/git/checkouts/foo-abc/123456/src/lib.rs'):
            with self.subTest(token=token):
                res = self.run_dep(self.lib_spec(['src/lib.rs', token]))
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('local target reads a cargo registry or git checkout source', res.stdout)

    def test_non_rs_module_and_include_files_outside_the_target_dir_are_scanned(self):
        """Review r7 M1: a `#[path = "x.txt"] mod m;` body and an `include!(.../x.inc)` body are compiled,
        listed in the dep-info and outside the cargo target dir; every listed text file is scanned."""
        forms = (
            ('path-module-txt', 'gen/ptxt.txt', '#[path = "../gen/ptxt.txt"]\nmod ptxt;\n'),
            ('include-inc', 'gen/inc_txt.inc',
             'include!(concat!(env!("CARGO_MANIFEST_DIR"), "/gen/inc_txt.inc"));\n'),
        )
        for name, rel, lib in forms:
            with self.subTest(form=name):
                self.write('src/lib.rs', lib)
                self.write(rel, self.HIDDEN_LOADER)
                res = self.run_dep(self.lib_spec(['src/lib.rs', rel]))
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('violation: ' + rel + ':2', res.stdout)

    def test_binary_non_rs_listed_file_is_skipped_without_error(self):
        (self.root / 'gen').mkdir()
        (self.root / 'gen' / 'blob.bin').write_bytes(b'\xff\xfe\x00 not utf8 Tensor::read_npz(p)\n')
        res = self.run_dep(self.lib_spec(['src/lib.rs', 'gen/blob.bin']))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('check-zip-extract-unreachable: ok', res.stdout)

    def test_clean_non_rs_listed_file_passes(self):
        self.write('gen/data.json', '{"a": 1}\n')
        res = self.run_dep(self.lib_spec(['src/lib.rs', 'gen/data.json']))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_generated_out_dir_file_is_scanned_as_rust(self):
        out_dir = self.root / '.stub-target' / 'debug' / 'build' / 'fixture-h' / 'out'
        out_dir.mkdir(parents=True)
        (out_dir / 'gen.rs').write_text(self.HIDDEN_LOADER, encoding='utf-8')
        (out_dir / 'gen.inc').write_text('fn f() { zip::read(); }\n', encoding='utf-8')
        (out_dir / 'blob.bin').write_bytes(b'\xff\xfe\x00\x01')
        for token, hit in (('{tgt}/debug/build/fixture-h/out/gen.rs', 'gen.rs:2'),
                           ('{tgt}/debug/build/fixture-h/out/gen.inc', 'gen.inc:1')):
            with self.subTest(token=token):
                res = self.run_dep(self.lib_spec(['src/lib.rs', token]))
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn(hit, res.stdout)
        res = self.run_dep(self.lib_spec(['src/lib.rs', '{tgt}/debug/build/fixture-h/out/blob.bin']))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_build_script_dep_info_is_found_beside_the_build_script_output(self):
        self.write('build.rs', 'fn main() {}\n')
        self.write('gen/b.rs', self.HIDDEN_LOADER)
        spec = self.lib_spec(['src/lib.rs'])
        spec['packages'][0]['targets'].append(
            {'kind': ['custom-build'], 'name': 'build-script-build', 'src': 'build.rs',
             'deps': ['build.rs', 'gen/b.rs']})
        res = self.run_dep(spec)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('gen/b.rs:2', res.stdout)

    def test_non_member_package_needs_artifacts_for_buildable_targets_only(self):
        self.write('vendor/dep/src/lib.rs', 'pub fn d() {}\n')
        self.write('vendor/dep/tests/t.rs', 'fn t() {}\n')
        self.write('vendor/dep/Cargo.toml', PACKAGE_ONLY)
        dep_targets = [
            {'kind': ['lib'], 'name': 'dep', 'src': 'src/lib.rs', 'deps': ['vendor/dep/src/lib.rs']},
            {'kind': ['test'], 'name': 't', 'src': 'tests/t.rs', 'artifact': False, 'deps': []}]
        spec = self.lib_spec(['src/lib.rs'])
        spec['packages'].append({'name': 'dep', 'dir': str(self.root / 'vendor' / 'dep'), 'member': False,
                                 'targets': dep_targets})
        res = self.run_dep(spec)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        dep_targets[0]['artifact'] = False
        spec['packages'][1]['targets'] = dep_targets
        res = self.run_dep(spec)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn('built no target', res.stderr)

    def test_member_test_target_without_an_artifact_exits_2(self):
        self.write('tests/t.rs', 'fn t() {}\n')
        spec = self.lib_spec(['src/lib.rs'])
        spec['packages'][0]['targets'].append(
            {'kind': ['test'], 'name': 't', 'src': 'tests/t.rs', 'artifact': False, 'deps': []})
        res = self.run_dep(spec)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_text_scan_still_covers_files_the_compiler_did_not_list(self):
        """A cfg'd-out file inside src/ is not in dep-info; the directory-wide scan still reads it."""
        self.write('src/cfgd.rs', self.HIDDEN_LOADER)
        res = self.run_dep(self.lib_spec(['src/lib.rs']))
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn('src/cfgd.rs:2', res.stdout)

    def test_literal_rule_follows_rs_literals_in_attributes_and_includes(self):
        self.write('gen/via.rs', self.HIDDEN_ZIP)
        forms = (
            '#[path = "../gen/via.rs"]\nmod m;\n',
            '#![cfg_attr(unix, path = "../gen/via.rs")]\n',
            'include!("../gen/via.rs");\n',
            'const S: &str = include_str!("../gen/via.rs");\n',
            'const S: &[u8] = include_bytes!("../gen/via.rs");\n',
        )
        for lib in forms:
            with self.subTest(lib=lib):
                self.write('src/lib.rs', lib)
                res = self.run_dep(self.lib_spec(['src/lib.rs']))
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn('gen/via.rs:2', res.stdout)

    def test_literal_rule_resolves_against_the_package_root_too(self):
        self.write('gen/via.rs', self.HIDDEN_ZIP)
        self.write('src/lib.rs', '#[path = "gen/via.rs"]\nmod m;\n')
        res = self.run_dep(self.lib_spec(['src/lib.rs']))
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)

    def test_unresolved_or_non_rs_literals_are_not_violations(self):
        forms = (
            '#[path = "nope.rs"]\nmod m;\n',
            'include!("nope.rs");\n',
            'include!(concat!(env!("OUT_DIR"), "/g.rs"));\n',
            'const S: &str = include_str!("../data/readme.txt");\n',
            '#[doc = "see other.rs"]\npub fn f() {}\n',
        )
        for lib in forms:
            with self.subTest(lib=lib):
                self.write('src/lib.rs', lib)
                res = self.run_dep(self.lib_spec(['src/lib.rs']))
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_literal_in_a_string_or_comment_outside_an_attribute_is_ignored(self):
        self.write('gen/via.rs', self.HIDDEN_ZIP)
        self.write('src/lib.rs', 'fn f() { let _ = "../gen/via.rs"; } // include!("../gen/via.rs")\n')
        res = self.run_dep(self.lib_spec(['src/lib.rs']))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_file_mode_skips_the_compiler_step(self):
        """The test-input flags never call cargo check (CI never passes them)."""
        res = self.run_guard()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_check_timeout_is_its_own_tool_error(self):
        module = load_guard_module()
        seen = []

        def hang(argv, **kwargs):
            seen.append((argv[1], kwargs.get('timeout')))
            raise subprocess.TimeoutExpired(argv, kwargs.get('timeout'))

        real = module.subprocess.run
        module.subprocess.run = hang
        try:
            with self.assertRaises(module.ToolError) as caught:
                module.cargo_check_output(self.root)
        finally:
            module.subprocess.run = real
        self.assertIn('timed out', str(caught.exception))
        self.assertEqual(seen, [('check', 1500)])
        self.assertGreater(module.CHECK_TIMEOUT_SECS, module.CARGO_TIMEOUT_SECS)

    def test_non_json_check_output_line_exits_2(self):
        module = load_guard_module()
        with self.assertRaises(module.ToolError):
            module.artifact_messages('{"reason": "compiler-artifact"\n')
        self.assertEqual(module.artifact_messages('Compiling x\n{"reason":"build-finished"}\n'), [])


class CargoMetadata7305(StubCargoCase):
    """#7305: the guard asks cargo for the local packages, locked, with dependencies."""

    def metadata_argv(self):
        res = self.run_stub(out=GOOD_TREE_DEPTH, lock=LOCK_WITH_ZIP)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        lines = [json.loads(line) for line in self.argv_log.read_text(encoding='utf-8').splitlines()]
        metas = [argv for argv in lines if argv and argv[0] == 'metadata']
        self.assertEqual(len(metas), 1, lines)
        return metas[0]

    def test_cargo_metadata_argv_is_locked_with_deps_7305(self):
        argv = self.metadata_argv()
        self.assertIn('--locked', argv)
        self.assertEqual(argv[argv.index('--format-version') + 1], '1')
        self.assertNotIn('--no-deps', argv)
        self.assertNotIn('--offline', argv)

    def test_cargo_metadata_failure_exits_2_7305(self):
        res = self.run_stub(out=GOOD_TREE_DEPTH, lock=LOCK_WITH_ZIP, metadata_fail=True)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)


def target_value(argv):
    """The value after `--target` in a cargo tree argv, or None when the flag or its value is missing."""
    if '--target' not in argv:
        return None
    index = argv.index('--target') + 1
    return argv[index] if index < len(argv) else None


class TargetFlagPosition7312(unittest.TestCase):
    """#7312: `all` must be the VALUE of --target, not just any token of the argv."""

    def test_all_token_elsewhere_is_not_target_all_7312(self):
        loose = (['tree', '--all-features', 'all'], ['tree', '--target'],
                 ['tree', '--target', 'x86_64-unknown-linux-gnu', 'all'], ['tree', 'all', '--target', 'host'])
        for argv in loose:
            with self.subTest(argv=argv):
                self.assertNotEqual(target_value(argv), 'all')

    def test_target_all_value_is_recognised_7312(self):
        self.assertEqual(target_value(['tree', '--target', 'all', '--locked']), 'all')


if __name__ == '__main__':
    unittest.main()
