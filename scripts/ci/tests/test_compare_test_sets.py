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

RETRIES_LOG = REPO / 'scripts' / 'ci' / 'tests' / 'fixtures' / 'nextest-0.9.146-retries2.log'

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
     Summary [   0.100s] 5 tests run: 4 passed, 1 failed, 1 skipped
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

    def test_should_panic_suffix_is_not_part_of_the_name(self):
        log = ('     Running unittests src/lib.rs (target/debug/deps/ai_memory-0123456789abcdef)\n'
               'test a::b - should panic ... ok\n')
        self.assertEqual(cts.parse_cargo_log(log), {('lib', 'a::b'): cts.PASS})

    def test_verdict_glued_to_log_noise_or_on_a_later_line_is_still_read(self):
        log = ('     Running unittests src/lib.rs (target/debug/deps/ai_memory-0123456789abcdef)\n'
               'test glued ... ok2026-10-16T13:59:34.9Z  INFO noise\n'
               'test split ... 2026-10-16T13:57:55.6Z  WARN noise\n'
               'ok\n'
               'test split_fail ... noise\n'
               'FAILED\n')
        self.assertEqual(cts.parse_cargo_log(log), {
            ('lib', 'glued'): cts.PASS, ('lib', 'split'): cts.PASS, ('lib', 'split_fail'): cts.FAIL})

    def test_no_tests_is_an_error(self):
        with self.assertRaises(cts.ParseError):
            cts.parse_cargo_log('   Compiling x\n    Finished\n')
        with self.assertRaises(cts.ParseError):
            cts.parse_cargo_log('')

    def test_byte_order_mark_inside_a_log_line_does_not_drop_the_test(self):
        # GitHub inserts U+FEFF at log-chunk boundaries, before or between the stamp and the text.
        log = ('2026-10-16T09:00:00.1Z     Running unittests src/lib.rs (target/debug/deps/ai_memory-0123456789abcdef)\n'
               '﻿2026-10-16T09:00:00.2Z test bom_first ... ok\n'
               '2026-10-16T09:00:00.3Z ﻿test bom_second ... ok\n'
               '﻿test bom_bare ... FAILED\n')
        self.assertEqual(cts.parse_cargo_log(log), {
            ('lib', 'bom_first'): cts.PASS, ('lib', 'bom_second'): cts.PASS, ('lib', 'bom_bare'): cts.FAIL})

    def test_example_binary_is_keyed_like_nextest_example_id(self):
        log = ('     Running unittests examples/fed_issue.rs (target/debug/examples/fed_issue-211019ec7132104f)\n'
               'test tests::gen_node ... ok\n')
        self.assertEqual(cts.parse_cargo_log(log), {('example/fed_issue', 'tests::gen_node'): cts.PASS})
        nextest = '        PASS [   0.1s] ai-memory::example/fed_issue tests::gen_node\n'
        self.assertEqual(cts.parse_nextest_log(nextest), {('example/fed_issue', 'tests::gen_node'): cts.PASS})

    def test_nested_child_libtest_output_keeps_the_parent_verdict(self):
        log = ('     Running tests/audit_signature_pin_l4.rs (target/debug/deps/audit_signature_pin_l4-b7778225d1b4dc84)\n'
               'running 3 tests\n'
               'test recorder_unenrolled_child_l4 ... ok\n'
               'test recorder_unenrolled_row_under_pin_dirties_l4 ... \n'
               'running 1 test\n'
               'test recorder_unenrolled_child_l4 ... ok\n'
               '\n'
               'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.07s\n'
               '\n'
               'ok\n'
               'test sibling_after ... ok\n'
               '\n'
               'test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s\n')
        self.assertEqual(cts.parse_cargo_log(log), {
            ('audit_signature_pin_l4', 'recorder_unenrolled_child_l4'): cts.PASS,
            ('audit_signature_pin_l4', 'recorder_unenrolled_row_under_pin_dirties_l4'): cts.PASS,
            ('audit_signature_pin_l4', 'sibling_after'): cts.PASS})

    def test_nested_child_failure_is_the_parents_failure_only(self):
        log = ('     Running tests/x.rs (target/debug/deps/x-b7778225d1b4dc84)\n'
               'test parent ... running 1 test\n'
               'test child ... FAILED\n'
               '\n'
               'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
               '\n'
               'ok\n')
        self.assertEqual(cts.parse_cargo_log(log), {('x', 'parent'): cts.PASS})

    def test_literal_caret_bracket_escapes_are_stripped(self):
        # `gh run view --log` prints ESC as the two characters ^[ .
        log = ('2026-10-16T09:00:00.1Z ^[[1m^[[92m     Running^[[0m tests/a.rs (target/debug/deps/a-0123456789abcdef)\n'
               '2026-10-16T09:00:00.2Z test one ... ok\n')
        self.assertEqual(cts.parse_cargo_log(log), {('a', 'one'): cts.PASS})
        nextest = '2026-10-16T09:00:00.3Z ^[[32;1m        PASS^[[0m [   0.1s] ^[[35;1mai-memory::a^[[0m one\n'
        self.assertEqual(cts.parse_nextest_log(nextest), {('a', 'one'): cts.PASS})


# Verbatim lines of `gh run view <run> --log --job <job>` (run 38964028218 / baseline run 38876017305):
# `<job>\t<step>\t<timestamp>Z ` in front of the line, then the runner's own text with ^[ escapes.
GH_NEXTEST_LINE = ('Check (macos-fed,sqlite)\tUNKNOWN STEP\t2026-10-16T15:38:45.1478690Z '
                   '^[[32;1m        PASS^[[0m [   3.937s] (14239/14239) ^[[35;1mai-memory::write_receipts_cli_mcp_3555^[[0m '
                   '^[[34;1mmcp_store_update_capture_receipts_3555^[[0m')
GH_CARGO_RUNNING = ('Check (macos-fed,sqlite)\tUNKNOWN STEP\t2026-10-16T08:56:31.3000000Z      '
                    'Running unittests src/lib.rs (target/debug/deps/ai_memory-0123456789abcdef)')
GH_CARGO_LINE = ('Check (macos-fed,sqlite)\tUNKNOWN STEP\t2026-10-16T08:56:31.4140500Z '
                 'test actions::tests::authorize_claimed_by_binds_live_holder_3009 ... ok')
GH_CARGO_RESULT = ('Check (macos-fed,sqlite)\tUNKNOWN STEP\t2026-10-16T08:59:24.0988110Z '
                   'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8983 filtered out; finished in 0.01s')
GH_NEXTEST_SUMMARY = ('Check (macos-fed,sqlite)\tUNKNOWN STEP\t2026-10-16T15:38:45.1481420Z '
                      '^[[32;1m     Summary^[[0m [ 359.524s] ^[[1m1^[[0m tests run: ^[[1m1^[[0m ^[[32;1mpassed^[[0m, '
                      '^[[1m9^[[0m ^[[33;1mskipped^[[0m')


class GhRunViewLogForm(unittest.TestCase):
    """#7298 F1: `gh run view --log` prefixes every line with `<job>\\t<step>\\t<timestamp>`."""

    def test_nextest_line_with_job_step_prefix_parses(self):
        out = cts.parse_nextest_log(GH_NEXTEST_LINE + '\n')
        self.assertEqual(out, {('write_receipts_cli_mcp_3555', 'mcp_store_update_capture_receipts_3555'): 'pass'})

    def test_cargo_lines_with_job_step_prefix_parse(self):
        out = cts.parse_cargo_log('\n'.join([GH_CARGO_RUNNING, GH_CARGO_LINE, GH_CARGO_RESULT]) + '\n')
        self.assertEqual(out, {('lib', 'actions::tests::authorize_claimed_by_binds_live_holder_3009'): 'pass'})

    def test_a_log_with_genuinely_no_tests_is_still_refused(self):
        prefixed = 'Check (macos-fed,sqlite)\tUNKNOWN STEP\t2026-10-16T08:56:31.4140500Z Compiling x v1\n'
        with self.assertRaises(cts.ParseError):
            cts.parse_cargo_log(prefixed)
        with self.assertRaises(cts.ParseError):
            cts.parse_nextest_log(prefixed)

    def test_a_tab_inside_ordinary_text_is_not_a_job_prefix(self):
        line = 'a\tb\tno timestamp here PASS [ 0.1s] ai-memory::x y'
        self.assertEqual(cts._clean(line), line)


class SplicedPrefix(unittest.TestCase):
    """#7299: a stderr fragment glued in front of a result line must not drop the result."""

    def cargo(self, *body):
        return '     Running tests/t.rs (target/debug/deps/t-aaaaaaaaaaaaaaaa)\n' + '\n'.join(body) + '\n'

    def test_prefixed_ok_line_is_kept(self):
        out = cts.parse_cargo_log(self.cargo('the file log sink failed to deliver a record: no space lefttest mod::a ... ok'))
        self.assertEqual(out, {('t', 'mod::a'): 'pass'})

    def test_prefixed_failed_line_is_a_failure(self):
        out = cts.parse_cargo_log(self.cargo('warn: noise test mod::a ... FAILED'))
        self.assertEqual(out, {('t', 'mod::a'): 'fail'})

    def test_prefixed_nextest_fail_line_is_kept(self):
        out = cts.parse_nextest_log('stderr noise        FAIL [   0.012s] ai-memory::t mod::a\n')
        self.assertEqual(out, {('t', 'mod::a'): 'fail'})

    def test_watchdog_progress_notice_mirroring_in_flight_tests_is_not_a_result(self):
        # verbatim shape of the sharded legs' progress notice (baseline run 38876017305, enterprise-fed)
        notice = ("##[notice][#6344] progress | serial: test config1_full_surface_attested_nhi_e2e ...  | parallel_1: "
                  "test hnsw::d1_968_tests::rebuild_failure_leaves_active_unchanged_968 ... ok | parallel_2: "
                  "test http_check_duplicate_no_embedder_400 ... ok")
        scan = cts.scan_cargo_log(self.cargo(notice, 'test mod::a ... ok'))
        self.assertEqual(scan.outcomes, {('t', 'mod::a'): 'pass'})
        self.assertEqual(scan.spliced, 0)
        before_any_header = '2026-10-16T09:04:32.8167340Z ' + notice + '\n' + self.cargo('test mod::a ... ok')
        self.assertEqual(cts.parse_cargo_log(before_any_header), {('t', 'mod::a'): 'pass'})
        nextest = ('##[notice][#6344] progress | parallel_1: PASS [   0.012s] ai-memory::t mod::z\n'
                   '        PASS [   0.012s] ai-memory::t mod::a\n')
        self.assertEqual(cts.parse_nextest_log(nextest), {('t', 'mod::a'): 'pass'})

    def test_spliced_lines_are_counted(self):
        scan = cts.scan_cargo_log(self.cargo('noise test mod::a ... ok', 'test mod::b ... ok'))
        self.assertEqual(scan.spliced, 1)
        scan = cts.scan_nextest_log('noise        PASS [   0.012s] ai-memory::t mod::a\n')
        self.assertEqual(scan.spliced, 1)

    def test_same_prefixed_failure_on_both_sides_is_kept_as_a_failure(self):
        base = self.cargo('noise test mod::a ... FAILED')
        cand = 'noise        FAIL [   0.012s] ai-memory::t mod::a\n'
        report = cts.compare(cts.parse_cargo_log(base), cts.parse_nextest_log(cand))
        self.assertEqual(report.baseline[('t', 'mod::a')], 'fail')
        self.assertEqual(report.candidate[('t', 'mod::a')], 'fail')


class TotalsReconciliation(unittest.TestCase):
    """#7298 F2: parsed per-test lines must agree with the runners' own totals."""

    def test_cargo_totals_sum_across_binaries_and_skip_doc_tests(self):
        scan = cts.scan_cargo_log(CARGO_LOG)
        self.assertEqual((scan.total, scan.total_lines), (5, 3))  # 2 + 1 + 2 executed; the doc-test binary is excluded

    def test_child_libtest_results_before_the_parents_closing_line_are_not_its_total(self):
        # a test that re-executes its own test binary prints `running 1 test` / `test result:` first
        log = ('     Running tests/t.rs (target/debug/deps/t-aaaaaaaaaaaaaaaa)\n\nrunning 3 tests\n'
               'test mod::a ... ok\n\nrunning 1 test\ntest mod::b ... ok\n\n'
               'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s\n\n'
               'test mod::b ... ok\ntest mod::c ... ok\n\n'
               'test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s\n')
        scan = cts.scan_cargo_log(log)
        self.assertEqual((scan.parsed, scan.total, scan.total_lines), (3, 3, 1))
        cts.check_totals('cargo', scan)

    def test_nextest_total_is_the_tests_run_figure(self):
        scan = cts.scan_nextest_log(NEXTEST_LOG)
        self.assertEqual((scan.total, scan.total_lines), (5, 1))

    def test_gh_form_totals_parse(self):
        scan = cts.scan_nextest_log(GH_NEXTEST_LINE + '\n' + GH_NEXTEST_SUMMARY + '\n')
        self.assertEqual((scan.total, len(scan.outcomes)), (1, 1))

    def test_consistent_logs_pass_the_check(self):
        cts.check_totals('cargo', cts.scan_cargo_log(CARGO_LOG))
        cts.check_totals('nextest', cts.scan_nextest_log(NEXTEST_LOG))

    def test_a_line_missing_from_the_log_disagrees_with_the_total(self):
        broken = CARGO_LOG.replace('test recall_two ... ok\n', '')
        with self.assertRaises(cts.ParseError) as ctx:
            cts.check_totals('cargo', cts.scan_cargo_log(broken))
        self.assertIn('cargo', str(ctx.exception))
        self.assertIn('4', str(ctx.exception))
        self.assertIn('5', str(ctx.exception))

    def test_a_log_without_any_total_is_refused_naming_the_missing_total(self):
        no_total = '\n'.join(l for l in NEXTEST_LOG.splitlines() if 'Summary' not in l) + '\n'
        with self.assertRaises(cts.ParseError) as ctx:
            cts.check_totals('nextest', cts.scan_nextest_log(no_total))
        self.assertIn('Summary', str(ctx.exception))
        no_total = '\n'.join(l for l in CARGO_LOG.splitlines() if not l.startswith('test result:')) + '\n'
        with self.assertRaises(cts.ParseError) as ctx:
            cts.check_totals('cargo', cts.scan_cargo_log(no_total))
        self.assertIn('test result:', str(ctx.exception))


class TotalsCli(unittest.TestCase):
    def setUp(self):
        scratch = REPO / '.local-runs' / 'compare-test-sets-unittest'
        scratch.mkdir(parents=True, exist_ok=True)
        self.dir = Path(tempfile.mkdtemp(dir=str(scratch)))
        self.cargo = self.dir / 'cargo.log'
        self.cargo.write_text(CARGO_LOG)
        self.nextest = self.dir / 'nextest.log'
        self.nextest.write_text(NEXTEST_LOG)

    def tearDown(self):
        for p in self.dir.iterdir():
            p.unlink()
        self.dir.rmdir()

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT)] + list(args), capture_output=True, text=True)

    def test_same_line_removed_on_both_sides_exits_two_not_identical(self):
        self.cargo.write_text(CARGO_LOG.replace('test recall_two ... ok\n', ''))
        self.nextest.write_text(NEXTEST_LOG.replace('        PASS [   0.021s] ai-memory::recall_basic recall_two\n', ''))
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(self.nextest))
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertNotIn('IDENTICAL', done.stdout)

    def test_a_line_missing_on_one_side_only_still_reports_different(self):
        # the line AND the matching total are removed on one side: a real one-sided difference
        self.nextest.write_text(NEXTEST_LOG.replace('        PASS [   0.021s] ai-memory::recall_basic recall_two\n', '')
                                .replace('5 tests run: 4 passed', '4 tests run: 3 passed'))
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(self.nextest))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('DIFFERENT', done.stdout)

    def test_log_without_totals_exits_two_with_a_message(self):
        self.nextest.write_text('\n'.join(l for l in NEXTEST_LOG.splitlines() if 'Summary' not in l) + '\n')
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(self.nextest))
        self.assertEqual(done.returncode, 2)
        self.assertIn('Summary', done.stderr)

    def test_flaky_retry_compares_identical_against_a_plain_pass_baseline_7298(self):
        # nextest `Summary` counts a retried test once ("1 test run: 1 passed (1 flaky)"), not once per attempt
        cargo = ('     Running unittests src/lib.rs (target/debug/deps/ai_memory-0123456789abcdef)\n'
                 'running 1 test\n'
                 'test a::flaky_one ... ok\n\n'
                 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n')
        nextest = ('  TRY 1 FAIL [   0.010s] ai-memory a::flaky_one\n'
                   '  TRY 2 PASS [   0.011s] ai-memory a::flaky_one\n'
                   '  FLAKY 2/2 [   0.021s] ai-memory a::flaky_one\n'
                   '     Summary [   0.030s] 1 test run: 1 passed (1 flaky), 0 skipped\n')
        self.cargo.write_text(cargo)
        self.nextest.write_text(nextest)
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(self.nextest))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('IDENTICAL', done.stdout)
        self.assertIn('nextest 1 of 1', done.stdout)

    def pass_baseline(self):
        return ('     Running unittests src/lib.rs (target/debug/deps/ai_memory-0123456789abcdef)\n'
                'running 1 test\n'
                'test a::t ... ok\n\n'
                'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n')

    def test_fail_plus_leak_against_a_passing_baseline_is_different_not_identical_7298(self):
        # nextest prints a test that failed AND leaked as `FAIL + LEAK`; it must not read as a pass
        self.cargo.write_text(self.pass_baseline())
        self.nextest.write_text(' FAIL + LEAK [   0.010s] ai-memory a::t\n'
                                '     Summary [   0.030s] 1 test run: 0 passed, 1 failed, 0 skipped\n')
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(self.nextest))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('DIFFERENT', done.stdout)
        self.assertIn('a::t: pass -> fail', done.stdout)

    def test_unknown_nextest_status_exits_two_naming_the_line_7298(self):
        self.cargo.write_text(self.pass_baseline())
        self.nextest.write_text('  QUARANTINE [   0.010s] ai-memory a::t\n'
                                '     Summary [   0.030s] 1 test run: 1 passed, 0 skipped\n')
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(self.nextest))
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn('QUARANTINE', done.stderr)

    def retries_baseline(self, always_fails):
        return ('     Running unittests src/lib.rs (target/debug/deps/nxt-0123456789abcdef)\n'
                'running 3 tests\n'
                'test a::plain_pass ... ok\n'
                'test a::flaky_one ... ok\n'
                'test a::always_fails ... %s\n\n'
                'test result: %s. %d passed; %d failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
                % (('FAILED', 'FAILED', 2, 1) if always_fails else ('ok', 'ok', 3, 0)))

    def test_real_retries_log_compares_identical_to_cargo_test_of_the_same_crate_7298(self):
        self.cargo.write_text(self.retries_baseline(True))
        self.nextest.write_text(RETRIES_LOG.read_text())
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(self.nextest))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('IDENTICAL', done.stdout)
        self.assertIn('nextest 3 of 3', done.stdout)

    def test_real_retries_log_against_an_all_passing_baseline_is_different_7298(self):
        self.cargo.write_text(self.retries_baseline(False))
        self.nextest.write_text(RETRIES_LOG.read_text())
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(self.nextest))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('a::always_fails: pass -> fail', done.stdout)

    def test_totals_line_is_printed_when_they_agree(self):
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(self.nextest))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('totals: cargo 5 of 5', done.stdout)
        self.assertIn('nextest 5 of 5', done.stdout)

    def test_gh_run_view_form_compares_identical(self):
        cargo = '\n'.join([GH_CARGO_RUNNING, GH_CARGO_LINE, GH_CARGO_RESULT]) + '\n'
        nextest = GH_NEXTEST_LINE.replace('ai-memory::write_receipts_cli_mcp_3555', 'ai-memory')
        nextest = nextest.replace('mcp_store_update_capture_receipts_3555',
                                  'actions::tests::authorize_claimed_by_binds_live_holder_3009') + '\n' + GH_NEXTEST_SUMMARY + '\n'
        self.cargo.write_text(cargo)
        self.nextest.write_text(nextest)
        done = self.run_cli('--cargo-log', str(self.cargo), '--nextest-log', str(self.nextest))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


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

    def test_a_retried_flaky_test_is_a_pass_counted_once_7298(self):
        text = ('  TRY 1 FAIL [   0.010s] (───) ai-memory::a flaky_one\n'
                '  TRY 2 PASS [   0.011s] (1/1) ai-memory::a flaky_one\n'
                '  FLAKY 2/2 [   0.021s] (1/1) ai-memory::a flaky_one\n')
        scan = cts.scan_nextest_log(text)
        self.assertEqual(scan.outcomes, {('a', 'flaky_one'): 'pass'})
        self.assertEqual((scan.parsed, scan.spliced), (1, 0))

    def test_a_test_that_fails_every_retry_attempt_is_a_failure_from_its_try_lines_7298(self):
        # nextest 0.9.146 prints the FINAL line of a retried failure as `TRY n FAIL` (displayer/imp.rs:1811-1827)
        # and never a plain `FAIL` line for it; the last attempt's status is the result.
        text = ('  TRY 1 FAIL [   0.010s] (───) ai-memory::a always\n'
                '  TRY 2 FAIL [   0.010s] (───) ai-memory::a always\n'
                '  TRY 3 FAIL [   0.010s] (1/1) ai-memory::a always\n'
                '     Summary [   0.030s] 1 test run: 0 passed, 1 failed, 0 skipped\n'
                '  TRY 3 FAIL [   0.010s] (1/1) ai-memory::a always\n')
        scan = cts.scan_nextest_log(text)
        self.assertEqual(scan.outcomes, {('a', 'always'): 'fail'})
        self.assertEqual((scan.parsed, scan.total, scan.spliced), (1, 1, 0))
        cts.check_totals('nextest', scan)

    def test_a_non_try_final_line_decides_and_a_failure_stays_a_failure_7298(self):
        text = ('  TRY 1 FAIL [   0.010s] ai-memory::a flaky_one\n'
                '        FAIL [   0.010s] ai-memory::a flaky_one\n')
        self.assertEqual(cts.parse_nextest_log(text), {('a', 'flaky_one'): 'fail'})
        flaky_last = ('  TRY 2 FAIL [   0.010s] ai-memory::a t\n'
                      '  TRY 3 PASS [   0.010s] ai-memory::a t\n')
        self.assertEqual(cts.parse_nextest_log(flaky_last), {('a', 't'): 'pass'})  # last attempt wins

    def test_leaky_fail_attempt_forms_are_the_result_of_a_retry_only_chain_7298(self):
        for short in ('FL+LK', 'LKFAIL', 'TMT', 'XFAIL', 'ABORT', 'SIG 31', 'SEGV'):
            text = '  TRY 3 %s [   0.010s] ai-memory::a t\n' % short
            self.assertEqual(cts.parse_nextest_log(text), {('a', 't'): 'fail'}, short)
        for short in ('PASS', 'LEAK', 'TMPASS'):
            text = '  TRY 3 %s [   0.010s] ai-memory::a t\n' % short
            self.assertEqual(cts.parse_nextest_log(text), {('a', 't'): 'pass'}, short)

    def test_a_try_attempt_glued_with_no_space_behind_a_stderr_fragment_is_still_an_attempt_7298(self):
        text = ('stderr-fragmentTRY 1 FAIL [   0.010s] ai-memory::a flaky_one\n'
                '  TRY 2 PASS [   0.011s] ai-memory::a flaky_one\n'
                '  FLAKY 2/2 [   0.021s] ai-memory::a flaky_one\n')
        scan = cts.scan_nextest_log(text)
        self.assertEqual(scan.outcomes, {('a', 'flaky_one'): 'pass'})
        self.assertEqual(scan.spliced, 0)

    def test_the_real_nextest_0_9_146_retries_log_parses_to_three_reconciled_results_7298(self):
        # verbatim `cargo nextest run --retries 2 --status-level pass --final-status-level flaky` output
        # (3 tests: plain pass, fails once, always fails), saved without the two cargo build lines.
        scan = cts.scan_nextest_log(RETRIES_LOG.read_text())
        self.assertEqual(scan.outcomes, {('lib', 'a::plain_pass'): 'pass', ('lib', 'a::flaky_one'): 'pass',
                                         ('lib', 'a::always_fails'): 'fail'})
        self.assertEqual((scan.parsed, scan.total, scan.spliced), (3, 3, 0))
        cts.check_totals('nextest', scan)

    def test_flaky_test_fail_then_pass_on_retry_is_a_pass_with_no_spliced_lines_7298(self):
        text = ('  TRY 1 FAIL [   0.010s] ai-memory::a flaky_one\n'
                '  TRY 2 PASS [   0.011s] ai-memory::a flaky_one\n'
                '  FLAKY 2/2 [   0.021s] ai-memory::a flaky_one\n')
        scan = cts.scan_nextest_log(text)
        self.assertEqual(scan.outcomes, {('a', 'flaky_one'): 'pass'})
        self.assertEqual(scan.spliced, 0)
        self.assertEqual(scan.parsed, 1)

    def test_no_results_is_an_error(self):
        with self.assertRaises(cts.ParseError):
            cts.parse_nextest_log('    Starting 0 tests across 0 binaries\n')
        with self.assertRaises(cts.ParseError):
            cts.parse_nextest_log('')


class NextestStatusTable(unittest.TestCase):
    """#7298 S1: every nextest 0.9.146 status word is mapped by its WHOLE name; an unknown word exits 2."""

    @staticmethod
    def one(status, name='t'):
        return '%12s [   0.010s] ai-memory a::%s\n' % (status, name)

    def outcome(self, status):
        return cts.parse_nextest_log(self.one(status))[('lib', 'a::t')]

    def test_the_full_status_table_maps_pass_and_fail_by_whole_word_7298(self):
        passes = ['PASS', 'LEAK', 'TIMEOUT-PASS', 'SLOW + LEAK', 'SLOW+TMPASS', 'FLAKY 2/3']
        fails = ['FAIL', 'FAIL + LEAK', 'LEAK-FAIL', 'TIMEOUT', 'XFAIL', 'ABORT', 'ABORT SIG 31', 'SIGSEGV',
                 'SIGABRT', 'SIGKILL', 'FLKY-FL 2/2']
        for status in passes:
            self.assertEqual(self.outcome(status), cts.PASS, status)
        for status in fails:
            self.assertEqual(self.outcome(status), cts.FAIL, status)

    def test_a_whole_word_status_is_never_read_out_of_a_longer_one_7298(self):
        scan = cts.scan_nextest_log(self.one('FAIL + LEAK', 't') + self.one('TIMEOUT-PASS', 'u')
                                    + self.one('XFAIL', 'v'))
        self.assertEqual(scan.outcomes, {('lib', 'a::t'): cts.FAIL, ('lib', 'a::u'): cts.PASS,
                                         ('lib', 'a::v'): cts.FAIL})
        self.assertEqual(scan.spliced, 0)

    def test_marker_and_skip_lines_are_not_results_7298(self):
        text = (self.one('SLOW', 'a') + self.one('SKIP', 'b') + self.one('START', 'c') + self.one('TERMINATING', 'd')
                + self.one('DELAY 2/3', 'e') + self.one('PASS', 'f'))
        scan = cts.scan_nextest_log(text)
        self.assertEqual(scan.outcomes, {('lib', 'a::f'): cts.PASS})
        self.assertEqual(scan.spliced, 0)

    def test_retry_attempt_words_are_read_from_the_short_table_7298(self):
        for short in ['FAIL', 'FL+LK', 'LKFAIL', 'TMT', 'XFAIL', 'ABORT', 'SIG 31', 'SEGV', 'PASS', 'LEAK', 'TMPASS',
                      'SLOW']:
            text = '  TRY 1 %s [   0.010s] ai-memory a::flaky\n  FLAKY 2/2 [   0.011s] ai-memory a::flaky\n' % short
            scan = cts.scan_nextest_log(text)
            self.assertEqual(scan.outcomes, {('lib', 'a::flaky'): cts.PASS}, short)
            self.assertEqual(scan.spliced, 0, short)

    def test_a_failed_leaky_retry_attempt_does_not_make_a_flaky_pass_a_failure_7298(self):
        text = ('  TRY 1 FAIL [   0.010s] ai-memory a::flaky\n'
                ' TRY 2 LKFAIL [   0.010s] ai-memory a::flaky\n'
                '  TRY 3 PASS [   0.011s] ai-memory a::flaky\n'
                '  FLAKY 3/3 [   0.031s] ai-memory a::flaky\n')
        scan = cts.scan_nextest_log(text)
        self.assertEqual(scan.outcomes, {('lib', 'a::flaky'): cts.PASS})
        self.assertEqual(scan.spliced, 0)

    def test_an_unknown_status_word_exits_two_naming_the_line_7298(self):
        for bogus in ['QUARANTINE', 'FAIL + OOM', 'PASS-ISH', 'EXECFAIL']:
            with self.assertRaises(cts.ParseError) as ctx:
                cts.scan_nextest_log(self.one('PASS', 'ok') + self.one(bogus, 'weird'))
            self.assertIn(bogus, str(ctx.exception))
            self.assertIn('a::weird', str(ctx.exception))
        with self.assertRaises(cts.ParseError):
            cts.scan_nextest_log('  TRY 2 FAIL + LEAK [   0.010s] ai-memory a::x\n')
        with self.assertRaises(cts.ParseError):
            cts.scan_nextest_log('  TRY 2 NEWWORD [   0.010s] ai-memory a::x\n')


class NextestRetryAndSetupWords(unittest.TestCase):
    """#7298 R6: every other word nextest 0.9.146 prints (retry TRMNTG/START, SETUP script lines, the flaky-fail marker)."""

    HANG = ('  TRY 1 FAIL [   1.000s] (───) nx5 a::hangs\n'
            ' TRY 1 TRMNTG [>  2.000s] (───) nx5 a::hangs\n'
            '  TRY 2 FAIL [   1.000s] (───) nx5 a::hangs\n')

    def test_try_terminating_line_is_a_marker_not_an_unknown_status_7298(self):
        # displayer/imp.rs:866-875 (TestSlow while terminating, retries configured)
        scan = cts.scan_nextest_log(self.HANG)
        self.assertEqual(scan.outcomes, {('lib', 'a::hangs'): cts.FAIL})
        self.assertEqual((scan.parsed, scan.spliced), (1, 0))

    def test_try_start_line_is_a_marker_not_an_unknown_status_7298(self):
        # displayer/imp.rs:978-990 (TestRetryStarted with --no-capture or verbose)
        text = (' TRY 2 START [         ] (───) nx5 a::aborts\n'
                '  TRY 2 FAIL [   0.010s] (───) nx5 a::aborts\n'
                ' TRY 3 START [         ] (───) nx5 a::flaky_one\n'
                '  TRY 3 PASS [   0.010s] (1/7) nx5 a::flaky_one\n')
        scan = cts.scan_nextest_log(text)
        self.assertEqual(scan.outcomes, {('lib', 'a::aborts'): cts.FAIL, ('lib', 'a::flaky_one'): cts.PASS})

    def test_setup_script_lines_are_not_tests_7298(self):
        # displayer/imp.rs:743 (SETUP SLOW) and :1578-1593 (SETUP PASS / LEAK / LKFAIL / <short status>)
        text = ('  SETUP SLOW [> 60.000s] my-script: my-program --arg1\n'
                '  SETUP PASS [   0.100s] my-script: my-program --arg1\n'
                ' SETUP LEAK [   0.100s] my-script: my-program\n'
                ' SETUP LKFAIL [   0.100s] my-script: my-program\n'
                ' SETUP FAIL [   0.100s] my-script: my-program\n'
                ' SETUP SIG 31 [   0.100s] my-script: my-program\n'
                '        PASS [   0.010s] ai-memory a::real\n')
        scan = cts.scan_nextest_log(text)
        self.assertEqual(scan.outcomes, {('lib', 'a::real'): cts.PASS})
        self.assertEqual(scan.spliced, 0)


    def test_a_try_n_pass_followed_by_the_flaky_fail_marker_is_a_failure_7298(self):
        # flaky-result = "fail": displayer prints `TRY n PASS` then `- test configured to fail if flaky`
        # (snapshot status_line_all_variants, "flaky fail"); events.rs fail_message counts the test as failed.
        text = ('  TRY 1 FAIL [   0.010s] (───) ai-memory a::flaky\n'
                '  TRY 2 PASS [   1.000s] (  8/100) ai-memory a::flaky\n'
                '           - test configured to fail if flaky\n')
        scan = cts.scan_nextest_log(text)
        self.assertEqual(scan.outcomes, {('lib', 'a::flaky'): cts.FAIL})

    def test_the_flaky_fail_marker_beats_a_later_final_pass_line_7298(self):
        text = ('  TRY 2 PASS [   1.000s] (  8/100) ai-memory a::flaky\n'
                '           - test configured to fail if flaky\n'
                '  FLAKY 2/2 [   1.000s] ai-memory a::flaky\n'
                '        PASS [   0.010s] ai-memory a::other\n')
        scan = cts.scan_nextest_log(text)
        self.assertEqual(scan.outcomes, {('lib', 'a::flaky'): cts.FAIL, ('lib', 'a::other'): cts.PASS})

    def test_a_plain_flaky_pass_without_the_marker_stays_a_pass_7298(self):
        scan = cts.scan_nextest_log('  TRY 2 PASS [   1.000s] ai-memory a::flaky\n')
        self.assertEqual(scan.outcomes, {('lib', 'a::flaky'): cts.PASS})

    def test_a_marker_after_an_interleaved_status_line_is_a_parse_error_7298(self):
        # R7-1 (N2): the marker binds only to the immediately preceding `TRY n PASS`; another test's PASS line in
        # between clears it, so the marker has no predecessor and the log is refused (exit 2) instead of guessed.
        text = ('  TRY 2 PASS [   1.000s] (  1/2) nx5 a::f\n'
                '        PASS [   0.010s] (  2/2) nx5 a::p\n'
                '           - test configured to fail if flaky\n')
        with self.assertRaises(cts.ParseError) as ctx:
            cts.scan_nextest_log(text)
        self.assertIn('test configured to fail if flaky', str(ctx.exception))

    def test_a_marker_glued_behind_a_stderr_fragment_still_fails_the_test_7298(self):
        text = ('  TRY 2 PASS [   1.000s] (  1/2) nx5 a::f\n'
                'partial stderr frag- test configured to fail if flaky\n'
                '        PASS [   0.010s] (  2/2) nx5 a::p\n')
        scan = cts.scan_nextest_log(text)
        self.assertEqual(scan.outcomes, {('lib', 'a::f'): cts.FAIL, ('lib', 'a::p'): cts.PASS})

    def test_a_marker_without_a_try_n_pass_predecessor_is_a_parse_error_7298(self):
        text = ('           - test configured to fail if flaky\n'
                '  TRY 2 PASS [   1.000s] (  1/2) nx5 a::f\n'
                '        PASS [   0.010s] (  2/2) nx5 a::p\n')
        with self.assertRaises(cts.ParseError) as ctx:
            cts.scan_nextest_log(text)
        self.assertIn('line 1', str(ctx.exception))

    def test_help_text_states_the_flaky_marker_and_status_table_rules_7298(self):
        self.assertIn('configured to fail if flaky', cts.__doc__)
        self.assertIn('SETUP', cts.__doc__)
        self.assertIn('configured to fail if flaky', ' '.join(cts.build_parser().format_help().split()))
        self.assertIn('immediately preceding', cts.__doc__)
        self.assertIn('immediately preceding', ' '.join(cts.build_parser().format_help().split()))


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
