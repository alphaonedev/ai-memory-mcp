#!/usr/bin/env python3
"""Round-five isolation grammar regressions; shell fixtures are never executed."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT / "scripts/ci/check_workflow_python_isolation.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("isolation_round_five", CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PrefixDynamicN1(unittest.TestCase):
    def test_dynamic_interpreters_after_prefix_arguments(self):
        checker = load_checker()
        for prefix in ("timeout 60", "sudo -u u", "nice -n 10", "xargs", "env -u X",
                       "env FOO=1", "sudo --user=u nice --adjustment=10 timeout -s TERM 60",
                       "xargs -I {}", "env --unset=X", "/usr/bin/timeout 60"):
            for interpreter in ("$PYTHON", "${PYTHON:-python3}", "py -3",
                                "${{ steps.x.outputs.python-path }}"):
                with self.subTest(prefix=prefix, interpreter=interpreter):
                    findings = checker.scan_shell(f"{prefix} {interpreter} x.py")
                    self.assertEqual(len(findings), 1, "prefixed dynamic interpreter escaped")
                    self.assertIn("dynamic interpreter", findings[0].reason)
                    unsafe, exempt = checker.scan_source(
                        f"{prefix} {interpreter} x.py # isolation: exempt #8202")
                    self.assertEqual(unsafe, [])
                    self.assertEqual(exempt, [(1, "8202")])

    def test_prefix_arguments_and_non_python_variables_are_not_interpreters(self):
        checker = load_checker()
        for command in ("sudo -u python3 echo ready", "env -u PYTHON python3 -I x.py",
                        "timeout 60 $BIN x.py", "nice -n 10 $PSQL -c query",
                        "timeout 60 python3 -I x.py", "$TIMEOUT_BIN 60 python3 -I x.py"):
            with self.subTest(command=command):
                self.assertEqual(checker.scan_shell(command), [])


if __name__ == "__main__":
    unittest.main()
