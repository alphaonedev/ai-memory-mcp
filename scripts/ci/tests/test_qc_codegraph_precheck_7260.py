#!/usr/bin/env python3
"""Unit tests for scripts/qc-codegraph-precheck.py, the Python port of the C8 gate (#7260).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_qc_codegraph_precheck_7260.py

Pins: the gate keeps its exit codes (0 clean, 1 violation, 2 setup error), its
scan root is pinned through pathpin (a missing or empty ``src/`` is exit 2, not
a pass), the awk and Python production-line filters agree on the real tree,
and the GOVERNANCE_INTERNAL exemption is anchored on content, so a line shift
above it changes nothing.
"""
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GATE_REL = Path('scripts') / 'qc-codegraph-precheck.py'
SPEC = importlib.util.spec_from_file_location('qc_codegraph_precheck', REPO / GATE_REL)
gate = importlib.util.module_from_spec(SPEC)
sys.modules['qc_codegraph_precheck'] = gate
SPEC.loader.exec_module(gate)

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_SETUP = 2
PROBE_FN = 'pub fn p() { CallerContext::for_agent("probe-7260"); }\n'
CLEAN_FN = 'pub fn p() {}\n'


class ProductionLines(unittest.TestCase):
    def test_test_module_is_blanked_and_line_numbers_are_kept(self):
        text = 'fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nfn b() {}\n'
        got = gate.production_lines('src/x.rs', text)
        self.assertEqual(len(got), 6)
        self.assertEqual(got[0], 'fn a() {}')
        self.assertEqual(got[3], '')
        self.assertEqual(got[5], 'fn b() {}')

    def test_test_named_file_is_wholly_blank(self):
        self.assertEqual(set(gate.production_lines('src/peer_tests.rs', 'fn a() {}\nfn b() {}\n')), {''})

    def test_inner_cfg_test_blanks_the_whole_file(self):
        self.assertEqual(set(gate.production_lines('src/peer.rs', '#![cfg(test)]\nfn a() {}\n')), {''})

    def test_cfg_any_test_stays_visible(self):
        text = '#[cfg(any(test, feature = "x"))]\nmod m {\n    fn a() {}\n}\n'
        self.assertEqual(gate.production_lines('src/x.rs', text)[2], '    fn a() {}')

    def test_awk_and_python_filters_agree_on_every_real_source_file(self):
        awk = REPO / 'scripts' / 'lib' / 'production-lines.awk'
        checked = 0
        for path in sorted((REPO / 'src').rglob('*.rs')):
            stem = path.stem
            if gate.is_test_stem(stem):
                continue
            run = subprocess.run(['awk', '-f', str(awk), str(path)], capture_output=True,
                                 text=True, check=True)
            expected = run.stdout.split('\n')[:-1]
            got = gate.production_lines(str(path), path.read_text(encoding='utf-8'))
            self.assertEqual(got, expected, path.as_posix())
            checked += 1
        self.assertGreater(checked, 50)


class Fixture(unittest.TestCase):
    """A copy of scripts/ plus a synthetic src/ (the harness shape of #3623)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='precheck-7260-')
        self.addCleanup(self._tmp.cleanup)
        self.tree = Path(self._tmp.name)
        shutil.copytree(REPO / 'scripts', self.tree / 'scripts',
                        ignore=shutil.ignore_patterns('__pycache__'))
        (self.tree / 'tools').mkdir()

    def write_src(self, rel, text):
        path = self.tree / 'src' / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def run_gate(self, *args):
        return subprocess.run([sys.executable, str(self.tree / GATE_REL), *args],
                              capture_output=True, text=True, check=False)


class ScanRootPin(Fixture):
    def test_missing_src_root_is_exit_two_not_a_pass(self):
        run = self.run_gate()
        self.assertEqual(run.returncode, EXIT_SETUP, run.stdout + run.stderr)
        self.assertIn('pathpin', run.stderr)

    def test_src_root_with_no_rust_files_is_exit_two(self):
        (self.tree / 'src').mkdir()
        run = self.run_gate()
        self.assertEqual(run.returncode, EXIT_SETUP, run.stdout + run.stderr)

    def test_moved_src_root_is_exit_two(self):
        self.write_src('a.rs', CLEAN_FN)
        (self.tree / 'src').rename(self.tree / 'lib_moved')
        self.assertEqual(self.run_gate().returncode, EXIT_SETUP)

    def test_missing_allowlist_dir_is_exit_two(self):
        self.write_src('a.rs', CLEAN_FN)
        shutil.rmtree(self.tree / 'scripts' / 'qc-codegraph-allowlists')
        self.assertEqual(self.run_gate().returncode, EXIT_SETUP)


class Verdicts(Fixture):
    def test_clean_tree_is_exit_zero_and_prints_the_ok_line(self):
        self.write_src('a.rs', CLEAN_FN)
        allow = self.tree / 'scripts' / 'qc-codegraph-allowlists'
        for name in ('caller-context-literals.txt', 'for-admin-bypass.txt'):
            (allow / name).write_text('# header\n\n')
        run = self.run_gate()
        self.assertEqual(run.returncode, EXIT_OK, run.stdout + run.stderr)
        self.assertIn('C8 precheck OK (for_agent: 0 sites, for_admin: 0 sites)', run.stdout)

    def test_new_for_agent_literal_is_exit_one(self):
        self.write_src('a.rs', PROBE_FN)
        run = self.run_gate()
        self.assertEqual(run.returncode, EXIT_VIOLATION, run.stdout + run.stderr)
        self.assertIn('C8 HARD-BLOCK: new CallerContext::for_agent site(s) not in allowlist', run.stderr)

    def test_update_regenerates_both_allowlists(self):
        self.write_src('a.rs', PROBE_FN)
        run = self.run_gate('--update')
        self.assertEqual(run.returncode, EXIT_OK, run.stderr)
        body = (self.tree / 'scripts' / 'qc-codegraph-allowlists' / 'caller-context-literals.txt').read_text()
        self.assertIn('src/a.rs:probe-7260', body)
        self.assertEqual(self.run_gate().returncode, EXIT_OK)


class Exemption(Fixture):
    SITE = '            let ctx = CallerContext::for_admin(crate::identity::sentinels::GOVERNANCE_INTERNAL);'

    def real_tree_marker(self):
        """A Cargo.toml marks a real checkout: the pinned exempt file is then mandatory."""
        (self.tree / 'Cargo.toml').write_text('[package]\nname = "x"\n')
        self.write_src('storage/connection.rs', CLEAN_FN)

    def test_real_checkout_without_the_exempt_file_is_exit_two(self):
        self.real_tree_marker()
        run = self.run_gate()
        self.assertEqual(run.returncode, EXIT_SETUP, run.stdout + run.stderr)
        self.assertIn('src/store/postgres.rs', run.stderr)

    def test_shifting_the_exempt_site_by_inserted_lines_changes_nothing(self):
        text = ('impl Store {\n    async fn resolve_governance_policy(&self) {\n'
                + self.SITE + '\n    }\n}\n')
        verdicts = []
        for pad in (0, 1, 40, 31500):
            self.write_src('store/postgres.rs', '\n' * pad + text)
            allow = self.tree / 'scripts' / 'qc-codegraph-allowlists' / 'for-admin-bypass.txt'
            allow.write_text(''.join(line for line in allow.read_text().splitlines(True)
                                     if line.strip() != 'src/store/postgres.rs:GOVERNANCE_INTERNAL'))
            verdicts.append(self.run_gate().returncode)
        self.assertEqual(verdicts, [EXIT_OK] * 4)

    def test_the_site_in_another_function_is_a_hard_block(self):
        text = 'impl Store {\n    async fn other_fn(&self) {\n' + self.SITE + '\n    }\n}\n'
        self.write_src('store/postgres.rs', text)
        allow = self.tree / 'scripts' / 'qc-codegraph-allowlists' / 'for-admin-bypass.txt'
        allow.write_text(''.join(line for line in allow.read_text().splitlines(True)
                                 if line.strip() != 'src/store/postgres.rs:GOVERNANCE_INTERNAL'))
        run = self.run_gate()
        self.assertEqual(run.returncode, EXIT_VIOLATION, run.stdout + run.stderr)


class RealTree(unittest.TestCase):
    def test_real_tree_is_green(self):
        run = subprocess.run([sys.executable, str(REPO / GATE_REL)], capture_output=True,
                             text=True, check=False)
        self.assertEqual(run.returncode, EXIT_OK, run.stdout + run.stderr)
        self.assertIn('C8 precheck OK', run.stdout)


if __name__ == '__main__':
    unittest.main()
