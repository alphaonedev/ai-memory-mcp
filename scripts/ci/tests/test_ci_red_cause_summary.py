"""#9709: a red CI test job names its failing tests in the step summary and as annotations.

Invariant, for every test job of ci.yml and coverage.yml (the hand-written EXPECTED_JOBS below): a failing job runs one
deterministic step directly after its test step. The step is ``if: failure()`` + ``continue-on-error: true``, has no
secret, no ``env:``, no network and no ``uses:``, and calls ``scripts/ci/red_cause_summary.py``. The script parses cargo
test output, bounds every input and output, passes every value through the shared escape and the redaction, and exits 0
on every internal error after one notice line with the exact reason.

Expected values are hand-written; a bound is checked at the bound and one above with the number written out here, never
read from the module under test. Scratch lives under ``.local-runs``; every child process gets an environment built from
scratch (no inherited ``GIT_*`` or secret variables).
"""

import ast
import errno
import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT_REL = "scripts/ci/red_cause_summary.py"
SCRIPT = REPO / SCRIPT_REL
SHARED_REL = "scripts/ci/workflow_annotation.py"
REDACTION_REL = "scripts/cert_gate_evidence.py"
CI_YML = REPO / ".github" / "workflows" / "ci.yml"
COVERAGE_YML = REPO / ".github" / "workflows" / "coverage.yml"
SCRATCH_ROOT = REPO / ".local-runs"
CHILD_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
WALL_CLOCK_CEILING_SECONDS = 20.0

# The hand-written set of test jobs (every job with a step that runs ``cargo test`` or ``cargo llvm-cov``): file ->
# job -> (names of its test steps in order, the one command line of the red-cause step).
LOG_DIR_ARG = '"${RUNNER_TEMP}/red-cause"'
EXPECTED_JOBS = {
    "ci.yml": {
        "check": (("Run tests (impact-aware)",), 'python3 -I scripts/ci/red_cause_summary.py "${TEST_RESULT_LOG:-}" "${RUNNER_TEMP}/ci-shard"'),
        "sal-feature": (("Run lib tests (sal feature)",), "python3 -I scripts/ci/red_cause_summary.py " + LOG_DIR_ARG),
        "vectorlite-feature": (
            ("Run vectorlite no-native-lib seam tests (#1860)", "Run config-precedence under vectorlite (#2256 feature-gated pin)"),
            "python3 -I scripts/ci/red_cause_summary.py " + LOG_DIR_ARG,
        ),
    },
    "coverage.yml": {
        "per-module-thresholds": (("Generate coverage JSON",), "python3 -I scripts/ci/red_cause_summary.py " + LOG_DIR_ARG),
    },
}
RED_STEP_NAME = "Red cause summary (#9709)"
TEST_COMMAND = re.compile(r"\bcargo\s+(?:llvm-cov|test|nextest)\b")

# The bounds, written out (a mutant that moves one by one is caught by these numbers).
BOUND_FAILING_TESTS = 50
BOUND_LINE_BYTES = 300
BOUND_SUMMARY_BYTES = 32768
BOUND_ANNOTATIONS = 10
BOUND_FILE_BYTES = 16 * 1024 * 1024
BOUND_INPUT_FILES = 64

TITLE_LINE = "**Red cause (#9709)**"
NOTICE = "::notice title=red cause summary::"
LOAD_REFUSAL_LINE = ("::error title=red_cause_summary refused::red_cause_summary: refused: shared module "
                     "workflow_annotation.py next to the script cannot be loaded")
RESULT_FAILED_LINE = "test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s"
CRASH_DETAIL = ("process didn't exit successfully: `/x/crashy-fedcba9876543210` "
                "(signal: 11, SIGSEGV: invalid memory reference)")

FIXTURE_A = (
    "     Running unittests src/lib.rs (target/debug/deps/ai_memory-0123456789abcdef)\n"
    "\n"
    "running 3 tests\n"
    "test a::ok ... ok\n"
    "test a::bad ... FAILED\n"
    "test a::worse ... FAILED\n"
    "\n"
    "failures:\n"
    "\n"
    "---- a::bad stdout ----\n"
    "thread panicked\n"
    "\n"
    "failures:\n"
    "    a::bad\n"
    "    a::worse\n"
    "\n"
    "" + RESULT_FAILED_LINE + "\n"
    "\n"
    "error: test failed, to rerun pass `--lib`\n"
    "     Running tests/crashy.rs (target/debug/deps/crashy-fedcba9876543210)\n"
    "\n"
    "running 1 test\n"
    "error: test failed, to rerun pass `--test crashy`\n"
    "\n"
    "Caused by:\n"
    "  " + CRASH_DETAIL + "\n"
    "   Doc-tests ai_memory\n"
    "\n"
    "running 0 tests\n"
    "\n"
    "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
)
FIXTURE_A_SUMMARY = (
    TITLE_LINE + "\n"
    "\n"
    "failing test binaries: 2\n"
    "\n"
    "| Binary | Reason |\n"
    "| --- | --- |\n"
    "| ai_memory | " + RESULT_FAILED_LINE + " |\n"
    "| crashy | ended without a test result line (crash, timeout or signal); process didn't exit successfully: "
    "&#96;/x/crashy-fedcba9876543210&#96; (signal: 11, SIGSEGV: invalid memory reference) |\n"
    "\n"
    "failing tests: 2\n"
    "\n"
    "| Binary | Test |\n"
    "| --- | --- |\n"
    "| ai_memory | a\\x3a:bad |\n"
    "| ai_memory | a\\x3a:worse |\n"
)
FIXTURE_A_STDOUT = (
    "::error title=failing test binary::ai_memory: " + RESULT_FAILED_LINE + "\n"
    "::error title=failing test binary::crashy: ended without a test result line (crash, timeout or signal); "
    + CRASH_DETAIL + "\n"
    "::error title=failing test::ai_memory: a\\x3a:bad\n"
    "::error title=failing test::ai_memory: a\\x3a:worse\n"
)


def load_module(path=SCRIPT):
    spec = importlib.util.spec_from_file_location("red_cause_summary_under_test", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Scratch(unittest.TestCase):
    """A scratch directory under .local-runs per test, removed afterwards."""

    def setUp(self):
        SCRATCH_ROOT.mkdir(exist_ok=True)
        self.dir = Path(tempfile.mkdtemp(prefix="red-cause-9709-", dir=str(SCRATCH_ROOT)))
        self.addCleanup(self.remove_dir)

    def remove_dir(self):
        for root, dirs, files in os.walk(str(self.dir)):
            for name in dirs + files:
                try:
                    os.chmod(os.path.join(root, name), 0o700)
                except OSError:
                    pass
        resolved = self.dir.resolve()
        if str(resolved).startswith(str(SCRATCH_ROOT.resolve()) + os.sep):
            shutil.rmtree(str(resolved), ignore_errors=True)

    def write(self, name, content):
        path = self.dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode("utf-8") if isinstance(content, str) else content
        path.write_bytes(data)
        return path

    def run_script(self, args, summary="summary.md", script=None, extra_env=None):
        """(rc, stdout, stderr, summary text or None) of the script run in the scratch directory."""
        env = {"PATH": CHILD_PATH, "TMPDIR": str(self.dir), "LC_ALL": "C.UTF-8"}
        if summary is not None:
            env["GITHUB_STEP_SUMMARY"] = summary
        env.update(extra_env or {})
        proc = subprocess.run([sys.executable, "-I", str(script or SCRIPT)] + list(args), cwd=str(self.dir), env=env,
                              capture_output=True, timeout=120)
        written = None
        if summary is not None and (self.dir / summary).is_file():
            written = (self.dir / summary).read_text(encoding="utf-8")
        return proc.returncode, proc.stdout.decode("utf-8"), proc.stderr.decode("utf-8"), written

    def fixture_copy(self, with_shared=True, with_redaction=True):
        """A copy of the script with its siblings under the scratch directory; returns the script path."""
        script_dir = self.dir / "fx" / "scripts" / "ci"
        script_dir.mkdir(parents=True)
        shutil.copy(str(SCRIPT), str(script_dir / "red_cause_summary.py"))
        if with_shared:
            shutil.copy(str(REPO / SHARED_REL), str(script_dir / "workflow_annotation.py"))
        if with_redaction:
            shutil.copy(str(REPO / REDACTION_REL), str(script_dir.parent / "cert_gate_evidence.py"))
        return script_dir / "red_cause_summary.py"


class ParseAndRender(Scratch):
    """Cargo test output in, exact summary and annotations out."""

    def test_fixture_a_exact_output(self):
        self.write("a.log", FIXTURE_A)
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual((rc, out, err), (0, FIXTURE_A_STDOUT, ""))
        self.assertEqual(summary, FIXTURE_A_SUMMARY)

    def test_the_summary_is_appended_not_replaced(self):
        self.write("a.log", FIXTURE_A)
        self.write("summary.md", "earlier step\n")
        self.run_script(["a.log"])
        self.assertEqual((self.dir / "summary.md").read_text(), "earlier step\n" + FIXTURE_A_SUMMARY)

    def test_same_output_in_two_files_counts_once(self):
        self.write("a.log", FIXTURE_A)
        self.write("b.log", FIXTURE_A)
        rc, out, err, summary = self.run_script(["a.log", "b.log"])
        self.assertEqual((rc, out, summary), (0, FIXTURE_A_STDOUT, FIXTURE_A_SUMMARY))

    def test_directory_input_reads_log_files_below_it_and_ignores_the_rest(self):
        self.write("logs/a.log", FIXTURE_A)
        self.write("logs/sub/b.log", "test sub::only ... FAILED\n")
        self.write("logs/c.txt", "test ignored::txt ... FAILED\n")
        rc, out, err, summary = self.run_script(["logs"])
        self.assertEqual(rc, 0)
        self.assertIn("| ai_memory | a\\x3a:bad |\n", summary)
        self.assertIn("| (unknown binary) | sub\\x3a:only |\n", summary)
        self.assertNotIn("ignored::txt", summary)
        self.assertNotIn("ignored\\x3a:txt", summary)
        self.assertIn("failing tests: 3\n", summary)

    def test_a_binary_without_a_result_line_is_its_own_row_with_the_exact_reason(self):
        self.write("a.log", "     Running tests/hung.rs (target/debug/deps/hung-0123456789abcdef)\n\nrunning 1 test\n"
                            "     Running tests/next.rs (target/debug/deps/next-0123456789abcdef)\n\nrunning 0 tests\n\n"
                            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n")
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "::error title=failing test binary::hung: ended without a test result line (crash, timeout or signal)\n")
        self.assertEqual(summary, TITLE_LINE + "\n\nfailing test binaries: 1\n\n| Binary | Reason |\n| --- | --- |\n"
                                  "| hung | ended without a test result line (crash, timeout or signal) |\n")

    def test_a_binary_with_a_passing_result_has_no_row(self):
        self.write("a.log", "     Running tests/fine.rs (target/debug/deps/fine-0123456789abcdef)\n\nrunning 1 test\n"
                            "test t ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n")
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual((rc, out), (0, NOTICE + "no failing test or test binary found in 1 input file(s)\n"))
        self.assertEqual(summary, TITLE_LINE + "\nno failing test or test binary found in 1 input file(s)\n")

    def test_failures_list_without_failed_lines_names_the_tests(self):
        self.write("a.log", "     Running tests/x.rs (target/debug/deps/x-0123456789abcdef)\n\nfailures:\n    m::one\n    m::two\n\n"
                            "test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out\n")
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(rc, 0)
        self.assertIn("| x | m\\x3a:one |\n| x | m\\x3a:two |\n", summary)
        self.assertIn("failing tests: 2\n", summary)

    def test_doc_test_failure_and_ansi_colour(self):
        self.write("a.log", "   Doc-tests ai_memory\n\x1b[31mtest src/lib.rs - foo (line 3) ... FAILED\x1b[0m\n"
                            "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n")
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(rc, 0)
        self.assertIn("| doc-tests ai_memory | src/lib.rs - foo (line 3) |\n", summary)

    def test_crlf_line_endings_and_invalid_utf8(self):
        self.write("a.log", b"     Running tests/x.rs (target/debug/deps/x-0123456789abcdef)\r\n"
                            b"test bad\xff\xfe ... FAILED\r\n")
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(rc, 0)
        self.assertIn("| x | bad\ufffd\ufffd |\n", summary)
        self.assertEqual(out.splitlines()[0],
                         "::error title=failing test binary::x: ended without a test result line (crash, timeout or signal)")

    def test_no_failure_prints_one_notice_and_a_summary_line(self):
        self.write("a.log", "test a ... ok\n")
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual((rc, out), (0, NOTICE + "no failing test or test binary found in 1 input file(s)\n"))


HOSTILE_CASES = (
    # (case, raw test name, summary cell, annotation text)
    ("double colon", "x::y", "x\\x3a:y", "x\\x3a:y"),
    ("percent-encoded newline", "a%0Ab", "a\\x250Ab", "a\\x250Ab"),
    ("carriage return inside", "a\rb", "a\\x0db", "a\\x0db"),
    ("ansi colour", "\x1b[31mred\x1b[0m", "red", "red"),
    ("backtick", "a`b", "a&#96;b", "a`b"),
    ("angle bracket", "<b>x", "&lt;b>x", "<b>x"),
    ("pipe", "a|b", "a&#124;b", "a|b"),
    ("ampersand entity", "&amp;", "&amp;amp;", "&amp;"),
    ("markdown link", "[x](http://e)", "&#91;x](http://e)", "[x](http://e)"),
    ("workflow command", "::error::boom", "\\x3a:error\\x3a:boom", "\\x3a:error\\x3a:boom"),
    ("v1 command", "##[error]x", "\\x23#&#91;error]x", "\\x23\\x23\\x5berror]x"),
    ("line separator", "a\u2028b", "a\\u2028b", "a\\u2028b"),
    ("token", "ghp_abcdefghijklmnop", "&lt;redacted>", "<redacted>"),
    ("backslash", "a\\b", "a\\\\b", "a\\\\b"),
)
ALLOWED_STDOUT_LINE = re.compile(r"^::(?:error|notice) title=[a-z ]+::")


class Hostile(Scratch):
    """A value that can start a command, break a table or inject HTML is escaped; exact expected output."""

    def test_hostile_test_names_table(self):
        for case, raw, cell, text in HOSTILE_CASES:
            with self.subTest(case=case):
                self.write("a.log", "     Running tests/h.rs (target/debug/deps/h-0123456789abcdef)\n"
                                    "test " + raw + " ... FAILED\n"
                                    "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n")
                (self.dir / "summary.md").unlink(missing_ok=True)
                rc, out, err, summary = self.run_script(["a.log"])
                self.assertEqual(rc, 0)
                self.assertEqual(summary.splitlines()[-1], "| h | " + cell + " |")
                self.assertEqual(out.splitlines()[-1], "::error title=failing test::h: " + text)
                self.assertEqual(len(out.splitlines()), 2)

    def test_hostile_binary_label_result_line_and_crash_detail(self):
        self.write("a.log", "     Running x (target/debug/deps/b::c-0123456789abcdef)\n"
                            "test result: FAILED. 0 passed; ::error::pwn | <i>\n"
                            "     Running y (target/debug/deps/d-0123456789abcdef)\n"
                            "  process didn't exit successfully: ::notice::`x` %0A\n")
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "::error title=failing test binary::b\\x3a:c: test result: FAILED. 0 passed; \\x3a:error\\x3a:pwn | <i>\n"
                              "::error title=failing test binary::d: ended without a test result line (crash, timeout or signal); "
                              "process didn't exit successfully: \\x3a:notice\\x3a:`x` \\x250A\n")
        self.assertEqual(summary, TITLE_LINE + "\n\nfailing test binaries: 2\n\n| Binary | Reason |\n| --- | --- |\n"
                                  "| b\\x3a:c | test result: FAILED. 0 passed; \\x3a:error\\x3a:pwn &#124; &lt;i> |\n"
                                  "| d | ended without a test result line (crash, timeout or signal); process didn't exit successfully: "
                                  "\\x3a:notice\\x3a:&#96;x&#96; \\x250A |\n")

    def test_no_stdout_line_can_start_a_second_command(self):
        lines = ["     Running tests/h.rs (target/debug/deps/h-0123456789abcdef)\n"]
        lines += ["test " + raw + " ... FAILED\n" for _case, raw, _cell, _text in HOSTILE_CASES]
        self.write("a.log", "".join(lines))
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(rc, 0)
        for line in out.splitlines():
            self.assertRegex(line, ALLOWED_STDOUT_LINE)
            body = line.split("::", 2)[2]
            self.assertNotIn("::", body)
            self.assertNotIn("##[", line)
            self.assertNotIn("%", line)
        for line in summary.splitlines():
            self.assertNotIn("##[", line)
            self.assertNotIn("<", line.replace("&lt;", ""))
            self.assertNotIn("`", line)


class Bounds(Scratch):
    """Each bound held from both sides: at the bound nothing is cut, one above says so with an exact count."""

    def test_the_bounds_are_the_documented_numbers(self):
        module = load_module()
        self.assertEqual((module.MAX_FAILING_TESTS, module.MAX_LINE_BYTES, module.MAX_SUMMARY_BYTES, module.MAX_ANNOTATIONS,
                          module.MAX_FILE_BYTES, module.MAX_INPUT_FILES),
                         (BOUND_FAILING_TESTS, BOUND_LINE_BYTES, BOUND_SUMMARY_BYTES, BOUND_ANNOTATIONS, BOUND_FILE_BYTES,
                          BOUND_INPUT_FILES))

    def failing_tests(self, count):
        return "".join("test t::n%03d ... FAILED\n" % index for index in range(count))

    def test_failing_tests_at_the_bound_all_listed(self):
        self.write("a.log", self.failing_tests(50))
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(rc, 0)
        self.assertEqual(summary.count("| (unknown binary) | t\\x3a:n"), 50)
        self.assertIn("failing tests: 50\n", summary)
        self.assertNotIn("not listed", summary)

    def test_failing_tests_one_above_the_bound_prints_an_exact_count_line(self):
        self.write("a.log", self.failing_tests(51))
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(rc, 0)
        self.assertEqual(summary.count("| (unknown binary) | t\\x3a:n"), 50)
        self.assertIn("failing tests: 51\n", summary)
        self.assertNotIn("n050", summary)
        self.assertIn("\nfailing tests not listed: 1 (limit 50)\n", summary)

    def test_annotations_at_the_bound(self):
        self.write("a.log", self.failing_tests(10))
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(out.count("::error "), 10)
        self.assertNotIn("annotations:", out + summary)

    def test_annotations_one_above_the_bound(self):
        self.write("a.log", self.failing_tests(11))
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(out.count("::error "), 10)
        self.assertEqual(out.splitlines()[-1], NOTICE + "annotations: 10 of 11 findings printed (limit 10), 1 omitted")
        self.assertTrue(summary.endswith("\nannotations: 10 of 11 findings printed (limit 10), 1 omitted\n"))

    def long_line(self, total):
        unit = "ab::"
        name = unit * 71 + "a" * (total - 5 - 11 - len(unit) * 71)
        return "test " + name + " ... FAILED\n"

    def test_line_of_300_bytes_is_not_cut(self):
        self.write("a.log", self.long_line(300))
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(rc, 0)
        self.assertEqual(summary.splitlines()[-1], "| (unknown binary) | " + "ab\\x3a:" * 71 + " |")
        self.assertNotIn("bytes cut", summary)

    def test_line_of_301_bytes_is_cut_and_counted(self):
        self.write("a.log", self.long_line(301))
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(rc, 0)
        self.assertIn("| (unknown binary) | " + "ab\\x3a:" * 71 + " |\n", summary)
        self.assertTrue(summary.endswith("\ninput lines over 300 bytes cut: 1\n"))

    def test_summary_bound_at_the_bound_and_one_above(self):
        module = load_module()
        at_bound = ["x" * 99] * 327 + ["y" * 67]
        self.assertEqual(sum(len(line) + 1 for line in at_bound), 32768)
        self.assertEqual(module.fit_lines(at_bound, 32768), at_bound)
        above = ["x" * 99] * 327 + ["y" * 68]
        fitted = module.fit_lines(above, 32768)
        self.assertEqual(fitted[:-1], above[:326])
        self.assertEqual(fitted[-1], "summary over the limit: 2 lines omitted (limit 32768 bytes)")
        self.assertLessEqual(sum(len(line) + 1 for line in fitted), 32768)

    def test_a_huge_report_stays_under_the_summary_bound_and_says_how_much_was_omitted(self):
        rows = "".join("     Running tests/b%04d.rs (target/debug/deps/b%04d-0123456789abcdef)\n"
                       "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n" % (i, i)
                       for i in range(2000))
        self.write("a.log", rows)
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(rc, 0)
        self.assertLessEqual(len(summary.encode("utf-8")), 32768)
        self.assertRegex(summary.splitlines()[-1], r"^summary over the limit: [1-9][0-9]* lines omitted \(limit 32768 bytes\)$")
        self.assertEqual(out.count("::error "), 10)

    def filler_file(self, size, head):
        remaining = size - len(head)
        body = (b"x" * 199 + b"\n") * (remaining // 200) + b"x" * (remaining % 200)
        return head + body

    def test_file_of_exactly_the_byte_bound_is_read_whole(self):
        self.write("a.log", self.filler_file(16777216, b"test early ... FAILED\n"))
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(rc, 0)
        self.assertIn("| (unknown binary) | early |\n", summary)
        self.assertNotIn("input file over the limit", summary)

    def test_file_one_byte_over_the_bound_says_so_with_exact_numbers(self):
        self.write("a.log", self.filler_file(16777217, b"test early ... FAILED\n"))
        rc, out, err, summary = self.run_script(["a.log"])
        self.assertEqual(rc, 0)
        self.assertIn("| (unknown binary) | early |\n", summary)
        self.assertTrue(summary.endswith("\ninput file over the limit: a.log has 16777217 bytes, first 16777216 read\n"))

    def numbered_files(self, count):
        for index in range(count):
            body = "test late ... FAILED\n" if index == count - 1 else "test result: ok. 0 passed\n"
            self.write("logs/f%02d.log" % index, body)

    def test_input_files_at_the_bound_are_all_read(self):
        self.numbered_files(64)
        rc, out, err, summary = self.run_script(["logs"])
        self.assertEqual(rc, 0)
        self.assertIn("| (unknown binary) | late |\n", summary)
        self.assertNotIn("input files over the limit", summary)

    def test_input_files_one_above_the_bound_skip_the_last_and_say_so(self):
        self.numbered_files(65)
        rc, out, err, summary = self.run_script(["logs"])
        self.assertEqual(rc, 0)
        self.assertNotIn("late", summary)
        self.assertTrue(summary.endswith("input files over the limit: 65 found, first 64 read, 1 skipped\n"))


class LinearTime(Scratch):
    """No input shape takes more than linear time: stated ceiling 20 s on any host (the measured time is far below)."""

    def timed(self, name):
        started = time.monotonic()
        result = self.run_script([name])
        return time.monotonic() - started, result

    def test_100k_lines(self):
        lines = []
        for index in range(100000):
            if index % 1000 == 0:
                lines.append("     Running tests/t%d.rs (target/debug/deps/t%d-0123456789abcdef)" % (index, index))
            lines.append("test m::t%d ... %s" % (index, "FAILED" if index % 5000 == 0 else "ok"))
        self.write("a.log", "\n".join(lines) + "\n")
        elapsed, (rc, out, err, summary) = self.timed("a.log")
        self.assertEqual(rc, 0)
        self.assertLess(elapsed, WALL_CLOCK_CEILING_SECONDS)
        self.assertIn("failing tests: 20\n", summary)

    def test_100k_distinct_failures(self):
        self.write("a.log", "".join("test m::t%d ... FAILED\n" % index for index in range(100000)))
        elapsed, (rc, out, err, summary) = self.timed("a.log")
        self.assertEqual(rc, 0)
        self.assertLess(elapsed, WALL_CLOCK_CEILING_SECONDS)
        self.assertIn("failing tests: 100000\n", summary)
        self.assertIn("\nfailing tests not listed: 99950 (limit 50)\n", summary)

    def test_a_single_10mb_line(self):
        self.write("a.log", b"test " + b"a" * (10 * 1024 * 1024) + b" ... FAILED\n")
        elapsed, (rc, out, err, summary) = self.timed("a.log")
        self.assertEqual(rc, 0)
        self.assertLess(elapsed, WALL_CLOCK_CEILING_SECONDS)
        self.assertIn("| (unknown binary) | &lt;redacted> |\n", summary)
        self.assertTrue(summary.endswith("\ninput lines over 300 bytes cut: 1\n"))

    def test_a_10mb_line_of_colons_and_escapes(self):
        self.write("a.log", b"test " + b":" * (10 * 1024 * 1024) + b" ... FAILED\n")
        elapsed, (rc, out, err, summary) = self.timed("a.log")
        self.assertEqual(rc, 0)
        self.assertLess(elapsed, WALL_CLOCK_CEILING_SECONDS)


class FailsOpen(Scratch):
    """Every internal error exits 0 after one notice with the exact reason (a load refusal is the one exit 4)."""

    def check(self, args, notice, summary="summary.md", expect_out_prefix="", **kwargs):
        rc, out, err, written = self.run_script(args, summary=summary, **kwargs)
        self.assertEqual(rc, 0, (out, err))
        self.assertEqual(out, expect_out_prefix + NOTICE + notice + "\n")
        return written

    def test_no_arguments(self):
        written = self.check([], "no input paths given")
        self.assertEqual(written, TITLE_LINE + "\nno failing test or test binary found in 0 input file(s)\n")

    def test_missing_file(self):
        self.check(["missing.log"], "cannot read input missing.log: No such file or directory")

    def test_empty_path_argument(self):
        self.check([""], "input path is empty")

    def test_two_problems_name_the_first_and_count_the_rest(self):
        self.check(["missing.log", "missing2.log"], "cannot read input missing.log: No such file or directory (and 1 more problems)")

    @unittest.skipIf(os.geteuid() == 0, "root reads a mode 000 file")
    def test_unreadable_file(self):
        path = self.write("locked.log", "test x ... FAILED\n")
        os.chmod(str(path), 0)
        self.check(["locked.log"], "cannot read input locked.log: Permission denied")

    def test_fifo_is_not_read(self):
        os.mkfifo(str(self.dir / "pipe.log"))
        self.check(["pipe.log"], "input pipe.log is not a regular file")

    def test_symlink_is_not_followed(self):
        self.write("real.log", "test x ... FAILED\n")
        os.symlink("real.log", str(self.dir / "link.log"))
        self.check(["link.log"], "cannot read input link.log: " + os.strerror(errno.ELOOP))

    def test_summary_variable_missing_still_prints_the_annotations(self):
        self.write("a.log", "test one ... FAILED\n")
        self.check(["a.log"], "GITHUB_STEP_SUMMARY is not set, summary not written", summary=None,
                   expect_out_prefix="::error title=failing test::(unknown binary): one\n")

    def test_summary_file_not_writable(self):
        self.write("a.log", "test one ... FAILED\n")
        self.check(["a.log"], "cannot write summary nodir/x.md: No such file or directory", summary="nodir/x.md",
                   expect_out_prefix="::error title=failing test::(unknown binary): one\n")

    def test_bad_option(self):
        self.check(["--bogus"], "usage error: unrecognized arguments: --bogus")

    def test_help_exits_zero(self):
        rc, out, err, _ = self.run_script(["--help"])
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("usage: red_cause_summary"))

    def test_any_exception_is_one_notice_and_rc_0(self):
        module = load_module()

        def boom(paths, problems):
            raise RuntimeError("boom")

        module.scan = boom
        import io
        import contextlib
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            rc = module.main(["x.log"])
        self.assertEqual(rc, 0)
        self.assertEqual(stream.getvalue(), NOTICE + "internal error: RuntimeError: boom\n")

    def test_redaction_module_missing(self):
        script = self.fixture_copy(with_redaction=False)
        self.write("a.log", "test one ... FAILED\n")
        rc, out, err, _ = self.run_script(["a.log"], script=script)
        self.assertEqual((rc, out), (0, NOTICE + "cannot load redaction module: FileNotFoundError\n"))

    def test_shared_module_missing_is_the_one_fixed_refusal(self):
        script = self.fixture_copy(with_shared=False)
        rc, out, err, _ = self.run_script(["a.log"], script=script)
        self.assertEqual((rc, out), (4, LOAD_REFUSAL_LINE + "\n"))
        self.assertEqual(err, "red_cause_summary: refused: shared module workflow_annotation.py next to the script cannot be loaded "
                              "(FileNotFoundError)\n")


class ScriptShape(unittest.TestCase):
    """No secret, no network, no subprocess, one environment variable, standard library only."""

    def test_imports_are_standard_library_and_not_network(self):
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                modules.add(node.module)
        self.assertEqual(modules, {"argparse", "hashlib", "importlib.util", "os", "re", "stat", "sys", "pathlib"})

    def test_the_only_environment_variable_is_the_summary_file(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(len(re.findall(r"os\.environ|os\.getenv", text)), 1)
        self.assertIn('SUMMARY_ENV = "GITHUB_STEP_SUMMARY"', text)

    def test_no_shell_no_subprocess(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for word in ("subprocess", "shell=True", "os.system", "socket", "urllib"):
            self.assertNotIn(word, text)


def parse_jobs(text):
    """{job: [step dict]} of a workflow file by indentation (no YAML library): steps are the ``      - `` items."""
    jobs = {}
    in_jobs = False
    job = None
    step = None
    for line in text.splitlines():
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if in_jobs and re.match(r"^[A-Za-z]", line):
            in_jobs = False
        if not in_jobs:
            continue
        header = re.match(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$", line)
        if header:
            job = header.group(1)
            jobs[job] = []
            step = None
            continue
        if job is None:
            continue
        if re.match(r"^      - ", line):
            step = {"lines": [line]}
            jobs[job].append(step)
            continue
        if step is not None and not re.match(r"^ {0,5}\S", line.replace("\t", " ")) or (step is not None and line.strip() == ""):
            step["lines"].append(line)
        elif step is not None and line.startswith("      #"):
            step["lines"].append(line)
        elif re.match(r"^ {0,5}\S", line) and not line.lstrip().startswith("#"):
            step = None
    for steps in jobs.values():
        for item in steps:
            item["active"] = [ln for ln in item["lines"] if not ln.lstrip().startswith("#")]
            item["text"] = "\n".join(item["active"])
            first = item["active"][0]
            named = re.match(r"^      - name:\s*(.+?)\s*$", first)
            if not named:
                named = next((m for m in (re.match(r"^        name:\s*(.+?)\s*$", ln) for ln in item["active"]) if m), None)
            item["name"] = named.group(1).strip("\"'") if named else None
            item["if"] = next((m.group(1) for m in (re.match(r"^        if:\s*(.+?)\s*$", ln) for ln in item["active"]) if m), None)
            item["coe"] = next((m.group(1) for m in (re.match(r"^        continue-on-error:\s*(.+?)\s*$", ln) for ln in item["active"]) if m), None)
            item["run"] = run_command_lines(item["active"])
    return jobs


def run_command_lines(active):
    """The non-comment command lines of the step's ``run:`` value."""
    for index, line in enumerate(active):
        match = re.match(r"^        run:\s*(.*?)\s*$", line)
        if not match:
            continue
        value = match.group(1)
        if value and value[0] not in "|>":
            return [value]
        out = []
        for later in active[index + 1:]:
            if later.strip() and not later.startswith("          "):
                break
            if later.strip() and not later.strip().startswith("#"):
                out.append(later.strip())
        return out
    return []


class WorkflowInvariant(unittest.TestCase):
    """For ALL test jobs: the red-cause step exists, comes right after the test step, never changes the job result."""

    @classmethod
    def setUpClass(cls):
        cls.workflows = {"ci.yml": parse_jobs(CI_YML.read_text(encoding="utf-8")),
                         "coverage.yml": parse_jobs(COVERAGE_YML.read_text(encoding="utf-8"))}

    def red_steps(self, steps):
        return [(index, item) for index, item in enumerate(steps) if any(SCRIPT_REL in line for line in item["active"])]

    def test_every_test_job_is_in_the_expected_set(self):
        for workflow, jobs in self.workflows.items():
            derived = {job for job, steps in jobs.items()
                       if any(TEST_COMMAND.search(line) for item in steps for line in item["run"])}
            self.assertEqual(derived, set(EXPECTED_JOBS[workflow]), workflow)

    def test_the_red_cause_step_exists_once_in_each_test_job_and_nowhere_else(self):
        for workflow, jobs in self.workflows.items():
            holders = {job: len(self.red_steps(steps)) for job, steps in jobs.items() if self.red_steps(steps)}
            self.assertEqual(holders, {job: 1 for job in EXPECTED_JOBS[workflow]}, workflow)

    def test_the_step_comes_directly_after_the_last_test_step(self):
        for workflow, expected in EXPECTED_JOBS.items():
            for job, (test_names, _command) in expected.items():
                steps = self.workflows[workflow][job]
                names = [item["name"] for item in steps]
                last_test = max(names.index(name) for name in test_names)
                for name in test_names:
                    self.assertIn(name, names, (workflow, job, name))
                (index, item), = self.red_steps(steps)
                self.assertEqual(index, last_test + 1, (workflow, job))
                self.assertEqual(item["name"], RED_STEP_NAME)

    def test_the_step_never_changes_the_job_result(self):
        for workflow, expected in EXPECTED_JOBS.items():
            for job in expected:
                (_, item), = self.red_steps(self.workflows[workflow][job])
                # check has no job-level if: rule (b3) of check-required-contexts.sh wants a classify guard on every step.
                want = "failure() && needs.classify.outputs.cargo_skip != 'true'" if (workflow, job) == ("ci.yml", "check") else "failure()"
                self.assertEqual(item["if"], want, (workflow, job))
                self.assertEqual(item["coe"], "true", (workflow, job))

    def test_the_step_command_is_exactly_the_expected_one(self):
        for workflow, expected in EXPECTED_JOBS.items():
            for job, (_names, command) in expected.items():
                (_, item), = self.red_steps(self.workflows[workflow][job])
                self.assertEqual(item["run"], [command], (workflow, job))

    def test_the_step_has_no_secret_env_network_or_uses(self):
        banned = ("uses:", "env:", "with:", "secrets", "${{", "curl", "wget", "http://", "https://", "ssh ", " gh ", "token", "password")
        for workflow, expected in EXPECTED_JOBS.items():
            for job in expected:
                (_, item), = self.red_steps(self.workflows[workflow][job])
                for word in banned:
                    self.assertNotIn(word, item["text"], (workflow, job, word))
                self.assertIsNone(TEST_COMMAND.search(item["text"]), (workflow, job))

    def test_the_test_steps_keep_their_cargo_command_lines(self):
        pinned = {
            ("ci.yml", "sal-feature"): ("cargo test --features sal --lib 2>&1 | tee ",),
            ("ci.yml", "vectorlite-feature"): ("cargo test --features vectorlite --test vectorlite_1860 2>&1 | tee ",
                                               "cargo test --features vectorlite --test config_precedence 2>&1 | tee "),
        }
        for (workflow, job), prefixes in pinned.items():
            commands = [line for item in self.workflows[workflow][job] for line in item["run"]]
            for prefix in prefixes:
                self.assertEqual(sum(line.startswith(prefix) for line in commands), 1, (job, prefix))
            for item in self.workflows[workflow][job]:
                if any(line.startswith(prefixes[0].split(" 2>&1")[0]) for line in item["run"]):
                    self.assertIn("        shell: bash", item["active"], (job, item["name"]))

    def test_the_coverage_preflight_step_stays_before_the_test_step_unconditional(self):
        steps = self.workflows["coverage.yml"]["per-module-thresholds"]
        names = [item["name"] for item in steps]
        pre = steps[names.index("PostgreSQL package repair + preflight (#9235)")]
        self.assertLess(names.index("PostgreSQL package repair + preflight (#9235)"), names.index("Generate coverage JSON"))
        self.assertIsNone(pre["if"])
        self.assertIsNone(pre["coe"])


if __name__ == "__main__":
    unittest.main()
