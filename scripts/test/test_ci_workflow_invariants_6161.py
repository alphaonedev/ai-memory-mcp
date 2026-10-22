"""#6161 / #6181 / #6339: ci.yml invariants for the enterprise-fed tier helpers, in Python.

Seed of the port of scripts/test/test-ci-workflow-invariants.sh (that shell file is not edited here; the
operator rule is Python, not shell).  It carries the two sections the shell file would otherwise have gained:

* G (#6339): ci.yml runs the AGE self-heal helper as ``python3 -I`` (no sys.path[0], no PYTHON* env), because the
  helper reads the tier URL file and builds PGPASSWORD.  Pinned by test_ci_age_helper_isolated_6339.py.
* H (#6181): the tier password check runs before the URL is used.  Pinned by test_ci_tier_password_check_6181.py
  and test_check_tier_password_6181.py.

On top of those child suites it scans ci.yml as text (no YAML parser, stdlib only, Python 3.9+) for the wiring
lines themselves, so a rename of a child suite cannot leave the workflow silently unpinned.

Run: python3 -I scripts/test/test_ci_workflow_invariants_6161.py
"""
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
TEST_DIR = ROOT / "scripts" / "test"
CHILD_TIMEOUT_SECS = 300

AGE_SUITE = "test_ensure_age_extension_6161.py"
SECTION_G_SUITES = ("test_ci_age_helper_isolated_6339.py",)
SECTION_H_SUITES = ("test_ci_tier_password_check_6181.py", "test_check_tier_password_6181.py")

AGE_HELPER_CALL = "python3 -I scripts/ci/ensure-age-extension.py --url-file"
TIER_CHECK_CALL = "python3 -I scripts/ci/check-tier-password.py --url-file"
AGE_GUARD = 'if [ "${CI_NODE:-}" = "macos-fed" ]; then'
URL_READ = 'base_url="$(cat "$url_file")"'
CREATE_EXTENSION = "CREATE EXTENSION IF NOT EXISTS age"


def run_suite(name):
    """Run one sibling test file the way CI does (isolated interpreter); return the completed process."""
    return subprocess.run(
        [sys.executable, "-I", str(TEST_DIR / name)],
        cwd=str(ROOT), capture_output=True, text=True, timeout=CHILD_TIMEOUT_SECS, check=False)


def ci_lines():
    return CI_YML.read_text(encoding="utf-8").splitlines()


def first_index(lines, needle, start=0):
    for idx in range(start, len(lines)):
        if needle in lines[idx]:
            return idx
    return -1


class CiWorkflowInvariants6161(unittest.TestCase):

    def test_section_g_helper_runs_isolated_6339(self):
        for name in SECTION_G_SUITES:
            with self.subTest(suite=name):
                done = run_suite(name)
                self.assertEqual(done.returncode, 0, done.stderr[-1500:])

    def test_section_h_tier_password_check_pinned_6181(self):
        for name in SECTION_H_SUITES:
            with self.subTest(suite=name):
                done = run_suite(name)
                self.assertEqual(done.returncode, 0, done.stderr[-1500:])

    def test_age_helper_is_called_once_isolated_and_macos_fed_only(self):
        lines = ci_lines()
        calls = [i for i, ln in enumerate(lines) if "ensure-age-extension.py" in ln and not ln.lstrip().startswith("#")]
        self.assertEqual(len(calls), 1, "ci.yml must call the AGE helper exactly once")
        self.assertIn(AGE_HELPER_CALL, lines[calls[0]])
        guard = first_index(lines, AGE_GUARD)
        self.assertNotEqual(guard, -1, "the macos-fed guard is missing")
        self.assertLess(guard, calls[0], "the helper call must sit under the macos-fed guard")
        self.assertLess(calls[0] - guard, 3, "the guard must wrap the helper call directly")

    def test_age_helper_runs_before_create_extension(self):
        lines = ci_lines()
        call = first_index(lines, AGE_HELPER_CALL)
        create = first_index(lines, CREATE_EXTENSION, call)
        self.assertNotEqual(call, -1)
        self.assertNotEqual(create, -1, "CREATE EXTENSION age must follow the self-heal")

    def test_tier_password_check_runs_before_the_url_is_read(self):
        lines = ci_lines()
        check = first_index(lines, TIER_CHECK_CALL)
        read = first_index(lines, URL_READ, check)
        self.assertNotEqual(check, -1, "the tier password check is not wired")
        self.assertNotEqual(read, -1)
        self.assertLess(check, read)

    def test_age_unit_test_step_is_wired(self):
        text = CI_YML.read_text(encoding="utf-8")
        self.assertEqual(text.count("python3 scripts/test/" + AGE_SUITE), 1)


if __name__ == "__main__":
    unittest.main()
