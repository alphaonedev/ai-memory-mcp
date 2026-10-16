#!/usr/bin/env python3
"""Unit tests for scripts/ci/compare_test_sets.py (#7259).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_compare_test_sets.py

The comparator proves a runner swap (`cargo test` -> `cargo nextest run`)
executed the same tests with the same outcomes. It fails closed: empty or
unparseable input is an error, never a pass.
"""
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / 'scripts' / 'ci' / 'compare_test_sets.py'
SPEC = importlib.util.spec_from_file_location('compare_test_sets', SCRIPT)
cts = importlib.util.module_from_spec(SPEC)
sys.modules['compare_test_sets'] = cts
SPEC.loader.exec_module(cts)

CARGO_LOG = """\
   Compiling ai-memory v1.0.0 (/w)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1m 02s
     Running unittests src/lib.rs (target/debug/deps/ai_memory-0123456789abcdef)

running 3 tests
test store::sqlite::tests::alpha ... ok
test store::sqlite::tests::beta ... FAILED
test store::sqlite::tests::gamma ... ignored

failures:

---- store::sqlite::tests::beta stdout ----
thread panicked

test result: FAILED. 1 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running unittests src/main.rs (target/debug/deps/ai_memory-fedcba9876543210)

running 1 test
test cli::tests::parse ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/recall_basic.rs (target/debug/deps/recall_basic-aaaaaaaaaaaaaaaa)

running 2 tests
test recall_one ... ok
test recall_two ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s

   Doc-tests ai_memory

running 1 test
test src/lib.rs - doc (line 3) ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s
"""

NEXTEST_LOG = """\
    Starting 5 tests across 3 binaries (1 test skipped)
        PASS [   0.011s] ai-memory store::sqlite::tests::alpha
        FAIL [   0.012s] ai-memory store::sqlite::tests::beta
        PASS [   0.004s] ai-memory::bin/ai-memory cli::tests::parse
        PASS [   0.020s] ai-memory::recall_basic recall_one
        PASS [   0.021s] ai-memory::recall_basic recall_two
------------
     Summary [   0.100s] 4 tests run: 3 passed, 1 failed, 1 skipped
"""

JUNIT = """\
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="4" failures="1">
  <testsuite name="ai-memory" tests="2" failures="1">
    <testcase name="store::sqlite::tests::alpha" classname="ai-memory" time="0.011"/>
    <testcase name="store::sqlite::tests::beta" classname="ai-memory" time="0.012">
      <failure message="boom"/>
    </testcase>
    <testcase name="store::sqlite::tests::gamma" classname="ai-memory" time="0"><skipped/></testcase>
  </testsuite>
  <testsuite name="ai-memory::bin/ai-memory" tests="1" failures="0">
    <testcase name="cli::tests::parse" classname="ai-memory::bin/ai-memory" time="0.004"/>
  </testsuite>
  <testsuite name="ai-memory::recall_basic" tests="2" failures="0">
    <testcase name="recall_one" classname="ai-memory::recall_basic" time="0.02"/>
    <testcase name="recall_two" classname="ai-memory::recall_basic" time="0.02"/>
  </testsuite>
</testsuites>
"""

EXPECTED = {
    ('lib', 'store::sqlite::tests::alpha'): 'pass',
    ('lib', 'store::sqlite::tests::beta'): 'fail',
    ('bin/ai_memory', 'cli::tests::parse'): 'pass',
    ('recall_basic', 'recall_one'): 'pass',
    ('recall_basic', 'recall_two'): 'pass',
}


class ParseCargo(unittest.TestCase):
    def test_binaries_names_and_outcomes(self):
        self.assertEqual(cts.parse_cargo_log(CARGO_LOG), EXPECTED)

    def test_ignored_and_doc_tests_are_not_executed_tests(self):
        got = cts.parse_cargo_log(CARGO_LOG)
        self.assertNotIn(('lib', 'store::sqlite::tests::gamma'), got)
        self.assertFalse([k for k in got if 'doc' in k[1]])

    def test_ci_timestamps_and_ansi_prefixes_are_stripped(self):
        stamped = ''.join('2026-10-09T11:22:33.4445556Z \x1b[0m%s\n' % ln for ln in CARGO_LOG.splitlines())
        self.assertEqual(cts.parse_cargo_log(stamped), EXPECTED)

    def test_test_line_before_any_binary_header_is_an_error(self):
        with self.assertRaises(cts.ParseError):
            cts.parse_cargo_log('test orphan ... ok\n')

    def test_no_tests_is_an_error(self):
        with self.assertRaises(cts.ParseError):
            cts.parse_cargo_log('   Compiling x\n    Finished\n')
        with self.assertRaises(cts.ParseError):
            cts.parse_cargo_log('')


class ParseNextest(unittest.TestCase):
    def test_binary_ids_are_normalised_to_the_cargo_keys(self):
        self.assertEqual(cts.parse_nextest_log(NEXTEST_LOG), EXPECTED)

    def test_progress_counter_and_timestamp_prefixes_are_accepted(self):
        lines = []
        for i, ln in enumerate(NEXTEST_LOG.splitlines()):
            if ln.strip().startswith(('PASS', 'FAIL')):
                ln = ln.replace('s] ', 's] (%d/5) ' % (i + 1))
            lines.append('2026-10-09T11:22:33.4445556Z ' + ln)
        self.assertEqual(cts.parse_nextest_log('\n'.join(lines) + '\n'), EXPECTED)

    def test_timeout_and_signal_statuses_are_failures(self):
        text = ('        PASS [   0.011s] ai-memory::a ok_one\n'
                '     TIMEOUT [ 360.000s] ai-memory::a slow_one\n'
                '     SIGABRT [   0.100s] ai-memory::a abort_one\n'
                '        LEAK [   0.010s] ai-memory::a leak_one\n')
        got = cts.parse_nextest_log(text)
        self.assertEqual(got[('a', 'ok_one')], 'pass')
        self.assertEqual(got[('a', 'slow_one')], 'fail')
        self.assertEqual(got[('a', 'abort_one')], 'fail')
        self.assertEqual(got[('a', 'leak_one')], 'pass')

    def test_retry_attempt_lines_do_not_add_tests_and_a_final_failure_wins(self):
        text = ('  TRY 1 FAIL [   0.010s] ai-memory::a flaky_one\n'
                '        FAIL [   0.010s] ai-memory::a flaky_one\n')
        self.assertEqual(cts.parse_nextest_log(text), {('a', 'flaky_one'): 'fail'})

    def test_no_results_is_an_error(self):
        with self.assertRaises(cts.ParseError):
            cts.parse_nextest_log('    Starting 0 tests across 0 binaries\n')
        with self.assertRaises(cts.ParseError):
            cts.parse_nextest_log('')


class ParseJunit(unittest.TestCase):
    def test_junit_matches_the_same_keys_and_skips_skipped_cases(self):
        self.assertEqual(cts.parse_junit(JUNIT), EXPECTED)

    def test_malformed_or_empty_junit_is_an_error(self):
        for text in ('', '<testsuites', '<testsuites name="x"></testsuites>'):
            with self.assertRaises(cts.ParseError, msg=text):
                cts.parse_junit(text)


class Compare(unittest.TestCase):
    def test_identical_sets_and_outcomes(self):
        rep = cts.compare(EXPECTED, dict(EXPECTED))
        self.assertTrue(rep.identical)
        self.assertEqual((rep.only_baseline, rep.only_candidate, rep.outcome_diffs), ([], [], []))

    def test_missing_extra_and_changed_are_reported_sorted(self):
        cand = dict(EXPECTED)
        del cand[('recall_basic', 'recall_two')]
        cand[('recall_basic', 'extra_new')] = 'pass'
        cand[('lib', 'store::sqlite::tests::alpha')] = 'fail'
        rep = cts.compare(EXPECTED, cand)
        self.assertFalse(rep.identical)
        self.assertEqual(rep.only_baseline, [('recall_basic', 'recall_two')])
        self.assertEqual(rep.only_candidate, [('recall_basic', 'extra_new')])
        self.assertEqual(rep.outcome_diffs, [(('lib', 'store::sqlite::tests::alpha'), 'pass', 'fail')])

    def test_empty_side_is_refused(self):
        with self.assertRaises(cts.ParseError):
            cts.compare({}, EXPECTED)
        with self.assertRaises(cts.ParseError):
            cts.compare(EXPECTED, {})

    def test_render_names_every_difference(self):
        cand = dict(EXPECTED)
        del cand[('recall_basic', 'recall_two')]
        text = cts.render(cts.compare(EXPECTED, cand), max_list=10)
        self.assertIn('recall_basic recall_two', text)
        self.assertIn('DIFFERENT', text)
        self.assertNotIn('IDENTICAL', text)

    def test_render_caps_long_lists_but_keeps_the_count(self):
        base = {('b', 't%d' % i): 'pass' for i in range(50)}
        cand = {('b', 'keep'): 'pass'}
        text = cts.render(cts.compare(base, cand), max_list=5)
        self.assertIn('50', text)
        self.assertIn('more', text)


class Cli(unittest.TestCase):
    def setUp(self):
        scratch = REPO / '.local-runs' / 'compare-test-sets-unittest'
        scratch.mkdir(parents=True, exist_ok=True)
        self.dir = Path(tempfile.mkdtemp(dir=str(scratch)))
        self.cargo = self.dir / 'cargo.log'
        self.cargo.write_text(CARGO_LOG)
        self.nextest = self.dir / 'nextest.log'
        self.nextest.write_text(NEXTEST_LOG)
        self.junit = self.dir / 'junit.xml'
        self.junit.write_text(JUNIT)

    def tearDown(self):
        for p in self.dir.iterdir():
            p.unlink()
        self.dir.rmdir()

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT)] + list(args), capture_output=True, text=True)

    def test_identical_log_exits_zero(self):
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(self.nextest))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('IDENTICAL', done.stdout)
        self.assertIn('executed tests: baseline=5 candidate=5', done.stdout)

    def test_junit_candidate_exits_zero(self):
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-junit', str(self.junit))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_difference_exits_one_with_a_readable_diff(self):
        self.nextest.write_text(NEXTEST_LOG.replace('PASS [   0.021s] ai-memory::recall_basic recall_two',
                                                   'FAIL [   0.021s] ai-memory::recall_basic recall_two'))
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(self.nextest))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('recall_two', done.stdout)
        self.assertIn('pass -> fail', done.stdout)

    def test_empty_input_fails_closed_with_exit_two(self):
        self.nextest.write_text('')
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(self.nextest))
        self.assertEqual(done.returncode, 2)
        self.assertNotIn('IDENTICAL', done.stdout)

    def test_missing_file_and_missing_candidate_are_exit_two(self):
        self.assertEqual(self.run_cli('--cargo-log', str(self.cargo), '--nextest-log',
                                      str(self.dir / 'absent.log')).returncode, 2)
        self.assertEqual(self.run_cli('--cargo-log', str(self.cargo)).returncode, 2)

    def test_several_logs_per_side_are_merged(self):
        half_a = self.dir / 'a.log'
        half_b = self.dir / 'b.log'
        lines = NEXTEST_LOG.splitlines()
        half_a.write_text('\n'.join(lines[:3]) + '\n')
        half_b.write_text('\n'.join(lines[3:]) + '\n')
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(half_a), str(half_b))
        half_a.unlink()
        half_b.unlink()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


class NoShell(unittest.TestCase):
    def test_script_is_python_without_shell_true(self):
        text = SCRIPT.read_text(encoding='utf-8')
        self.assertTrue(text.startswith('#!/usr/bin/env python3'))
        self.assertNotIn('shell=True', text)


if __name__ == '__main__':
    unittest.main()
