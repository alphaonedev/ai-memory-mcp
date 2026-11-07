#!/usr/bin/env python3
"""Isolation policy regressions for #8202; fixtures never execute shell text."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT / "scripts/ci/check_python_isolation.py"


def load_checker():
    """Load by file location so isolated unittest discovery works."""
    if not CHECKER.is_file():
        raise AssertionError("workflow Python isolation checker is missing")
    spec = importlib.util.spec_from_file_location("check_python_isolation", CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ScriptArguments6389(unittest.TestCase):
    def test_quoted_paths_and_interleaved_flags_6389(self):
        checker = load_checker()
        for args in (
            "scripts/x.py", "-u scripts/x.py", '-B "scripts/x.py"',
            '"scripts/x.py"', "-O -u 'scripts/x.py'", "-W ignore scripts/x.py",
            "-X dev scripts/x.py",
        ):
            with self.subTest(args=args):
                self.assertEqual(len(checker.scan_shell("python3 " + args)), 1)
                self.assertEqual(checker.scan_shell("python3 -I " + args), [])

    def test_isolation_must_precede_program_6389(self):
        checker = load_checker()
        for text in (
            "python3 scripts/x.py -I",
            'python3 -W "-I" scripts/x.py',
            "python3 -X -I scripts/x.py",
        ):
            with self.subTest(text=text):
                self.assertEqual(len(checker.scan_shell(text)), 1)
        self.assertEqual(checker.scan_shell("python3 -u -I scripts/x.py"), [])


if __name__ == "__main__":
    unittest.main()
