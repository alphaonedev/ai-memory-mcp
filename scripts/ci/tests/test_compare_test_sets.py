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
