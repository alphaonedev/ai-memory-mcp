"""Round-six isolation regressions; shell fixture text is never executed."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT / "scripts/ci/check_workflow_python_isolation.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("isolation_round_six", CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class InterpreterNamesS2(unittest.TestCase):
    def test_free_threaded_pypy_and_executable_suffix_s2(self):
        checker = load_checker()
        for name in ("python3.13t", "Python3.13t.exe", "pypy", "pypy3", "PYPY3.exe",
                     "python.exe", "python3.exe", "C:/Python312/python.exe",
                     "python3.12d", "python3-dbg"):
            with self.subTest(name=name):
                found = checker.scan_shell(f"{name} x.py")
                self.assertEqual(len(found), 1, "interpreter variant escaped")
                self.assertFalse(found[0].malformed)
                self.assertEqual(checker.scan_shell(f"{name} -I x.py"), [])


if __name__ == "__main__":
    unittest.main()
