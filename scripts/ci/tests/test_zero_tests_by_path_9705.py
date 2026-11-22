#!/usr/bin/env python3
"""A by-path run of a scripts/ci/tests module that executes 0 tests is a failure (#9705).

Defect class: a test module run by path (`python3 scripts/ci/tests/<module>.py`) can run 0 tests and exit 0, because
the module has no `if __name__ == "__main__": unittest.main()` guard or because its test classes are gone, so a broken
or emptied module is green.

Invariant: for every `test_*.py` module in this folder (the tree walk below, never a hand list; a module that is left
out is a row of LEFT_OUT with its reason, and the row count is pinned), a by-path run starts unittest and the module
holds at least one test. Otherwise the module is reported with the one message ZERO_TESTS_MESSAGE.

The check does not run the tests (the full by-path run of the folder takes about 20 minutes). It does the two things
that decide whether a by-path run executes anything: the module carries the `__main__` guard that calls
unittest.main (read from the syntax tree), and the loader finds at least one test in the module as a by-path run
imports it (a child interpreter with the module's own directory first on sys.path, the by-path form).
"""
import ast
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
MODULE_GLOB = "test_*.py"
ZERO_TESTS_MESSAGE = "by-path run executes 0 tests"
LOAD_FAILED_MESSAGE = "by-path load failed"
NO_GUARD_REASON = "no __main__ guard that calls unittest.main"
COUNT_PREFIX = "COUNT="
LOAD_TIMEOUT_S = 120
LOAD_WORKERS = 8
LEFT_OUT_ROWS = 1
LEFT_OUT = {
    "test_check_cert_expiry_corpus.py": "a self-test script (SelfTest, no unittest cases); its own __main__ runs the corpus",
}
DRIVER = (
    "import importlib.util, sys, unittest\n"
    "path = sys.argv[1]\n"
    "sys.path.insert(0, sys.argv[2])\n"
    "spec = importlib.util.spec_from_file_location('by_path_module', path)\n"
    "module = importlib.util.module_from_spec(spec)\n"
    "sys.modules['by_path_module'] = module\n"
    "spec.loader.exec_module(module)\n"
    f"print('{COUNT_PREFIX}' + str(unittest.defaultTestLoader.loadTestsFromModule(module).countTestCases()))\n"
)


def wired_modules(tests_dir=TESTS_DIR):
    """Every test module of the folder, from the tree, minus the LEFT_OUT rows."""
    return sorted(p for p in tests_dir.glob(MODULE_GLOB) if p.is_file() and p.name not in LEFT_OUT)


def has_main_guard(source):
    """True when the module has an `if __name__ == "__main__":` block that calls unittest.main."""
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)):
            continue
        test = node.test
        if not (isinstance(test.left, ast.Name) and test.left.id == "__name__" and len(test.comparators) == 1):
            continue
        comp = test.comparators[0]
        if not (isinstance(comp, ast.Constant) and comp.value == "__main__"):
            continue
        for inner in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "main" and isinstance(inner.func.value, ast.Name)
                    and inner.func.value.id == "unittest"):
                return True
    return False


def count_tests(path):
    """The number of tests a by-path run of `path` finds, or None when the module does not load."""
    run = subprocess.run([sys.executable, "-c", DRIVER, str(path), str(Path(path).resolve().parent)],
                         capture_output=True, text=True, timeout=LOAD_TIMEOUT_S, cwd=str(Path(path).resolve().parent))
    if run.returncode != 0:
        return None
    for line in run.stdout.splitlines():
        if line.startswith(COUNT_PREFIX):
            return int(line[len(COUNT_PREFIX):])
    return None


def zero_test_problem(path):
    """None when a by-path run of the module executes at least one test, else one problem line."""
    path = Path(path)
    if not has_main_guard(path.read_text(encoding="utf-8")):
        return f"{path.name}: {ZERO_TESTS_MESSAGE} ({NO_GUARD_REASON})"
    found = count_tests(path)
    if found is None:
        return f"{path.name}: {LOAD_FAILED_MESSAGE}"
    if found < 1:
        return f"{path.name}: {ZERO_TESTS_MESSAGE}"
    return None


def folder_problems(tests_dir=TESTS_DIR):
    modules = wired_modules(tests_dir)
    with ThreadPoolExecutor(max_workers=LOAD_WORKERS) as pool:
        found = list(pool.map(zero_test_problem, modules))
    return [problem for problem in found if problem]


GOOD_SOURCE = (
    "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_one(self):\n        self.assertTrue(True)\n\n\n"
    'if __name__ == "__main__":\n    unittest.main()\n'
)
EMPTIED_SOURCE = 'import unittest\n\n\nif __name__ == "__main__":\n    unittest.main()\n'
NO_GUARD_SOURCE = GOOD_SOURCE.split('if __name__')[0]
GUARD_NOT_UNITTEST_SOURCE = GOOD_SOURCE.replace("unittest.main()", "print('x')")
MODULE_COUNT_FLOOR = 100


class ZeroTestsByPath9705(unittest.TestCase):
    def write(self, name, source):
        scratch = TESTS_DIR.parents[2] / ".local-runs" / "zero-tests-9705"
        scratch.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: (scratch / name).unlink(missing_ok=True))
        path = scratch / name
        path.write_text(source, encoding="utf-8")
        return path

    def test_every_wired_module_runs_a_test_by_path(self):
        self.assertEqual(folder_problems(), [])

    def test_left_out_table_is_pinned_and_each_row_is_a_real_module(self):
        self.assertEqual(len(LEFT_OUT), LEFT_OUT_ROWS)
        for name, reason in LEFT_OUT.items():
            self.assertTrue((TESTS_DIR / name).is_file(), name)
            self.assertTrue(reason.strip(), name)

    def test_the_walk_comes_from_the_tree(self):
        walked = wired_modules()
        self.assertGreaterEqual(len(walked) + len(LEFT_OUT), MODULE_COUNT_FLOOR)
        self.assertIn(Path(__file__).resolve(), walked)
        self.assertEqual(len(walked) + len(LEFT_OUT), len(list(TESTS_DIR.glob(MODULE_GLOB))))

    def test_a_good_module_has_no_problem(self):
        self.assertIsNone(zero_test_problem(self.write("test_good_9705.py", GOOD_SOURCE)))

    def test_an_emptied_module_fails_with_the_named_message(self):
        problem = zero_test_problem(self.write("test_emptied_9705.py", EMPTIED_SOURCE))
        self.assertEqual(problem, f"test_emptied_9705.py: {ZERO_TESTS_MESSAGE}")

    def test_a_module_without_the_guard_fails_with_the_named_message(self):
        problem = zero_test_problem(self.write("test_noguard_9705.py", NO_GUARD_SOURCE))
        self.assertEqual(problem, f"test_noguard_9705.py: {ZERO_TESTS_MESSAGE} ({NO_GUARD_REASON})")

    def test_a_guard_that_does_not_call_unittest_main_fails(self):
        problem = zero_test_problem(self.write("test_otherguard_9705.py", GUARD_NOT_UNITTEST_SOURCE))
        self.assertEqual(problem, f"test_otherguard_9705.py: {ZERO_TESTS_MESSAGE} ({NO_GUARD_REASON})")

    def test_a_module_that_does_not_load_is_not_counted_as_green(self):
        problem = zero_test_problem(self.write("test_broken_9705.py", GOOD_SOURCE + "\nraise RuntimeError('x')\n"))
        self.assertEqual(problem, f"test_broken_9705.py: {LOAD_FAILED_MESSAGE}")

    def test_folder_walk_reports_an_emptied_module(self):
        scratch = TESTS_DIR.parents[2] / ".local-runs" / "zero-tests-9705-folder"
        scratch.mkdir(parents=True, exist_ok=True)
        emptied = scratch / "test_emptied_folder_9705.py"
        self.addCleanup(lambda: emptied.unlink(missing_ok=True))
        emptied.write_text(EMPTIED_SOURCE, encoding="utf-8")
        self.assertEqual(folder_problems(scratch), [f"test_emptied_folder_9705.py: {ZERO_TESTS_MESSAGE}"])


if __name__ == "__main__":
    unittest.main()
