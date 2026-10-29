# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Guard: helper parser construction survives closed standard streams (#8275).

Python 3.14 argparse probes stdout (isatty) while building the parser, which
raises ValueError on a closed stream. The helper must still exit 2 with a diagnostic
path that does not raise, on every interpreter that runs this suite.
"""

import subprocess
import sys
import unittest
from pathlib import Path

HELPER = Path(__file__).resolve().parents[1] / "check_pr_body_ids.py"
TIMEOUT_SECONDS = 10
EXIT_ERROR = 2
CLOSE_AND_RUN = (
    "import runpy,sys; helper=runpy.run_path(sys.argv[1]); "
    "sys.stdout.close(); sys.stderr.close(); "
    "sys.exit(helper['main'](sys.argv[2:]))"
)
CLOSE_STDERR_ONLY = (
    "import runpy,sys; helper=runpy.run_path(sys.argv[1]); "
    "sys.stderr.close(); sys.exit(helper['main'](sys.argv[2:]))"
)
CLOSE_STDOUT_ONLY = (
    "import runpy,sys; helper=runpy.run_path(sys.argv[1]); "
    "sys.stdout.close(); sys.exit(helper['main'](sys.argv[2:]))"
)


class StreamGuard8275Tests(unittest.TestCase):
    def run_helper(self, code, args):
        return subprocess.run(
            [sys.executable, "-c", code, str(HELPER), *args], input=b"",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT_SECONDS,
        )

    def test_8275_parser_construction_with_closed_stdout_and_stderr(self):
        for args in ((), ("--help",)):
            with self.subTest(args=args):
                result = self.run_helper(CLOSE_AND_RUN, args)
                self.assertEqual(result.returncode, EXIT_ERROR, result.stderr)
                self.assertNotIn(b"Traceback", result.stderr)

    def test_8275_closed_stdout_reports_output_error_diagnostic(self):
        for args in ((), ("--help",)):
            with self.subTest(args=args):
                result = self.run_helper(CLOSE_STDOUT_ONLY, args)
                self.assertEqual(result.returncode, EXIT_ERROR, result.stderr)
                self.assertIn(b"output error", result.stderr)
                self.assertNotIn(b"Traceback", result.stderr)

    def test_8275_closed_stderr_usage_error_exits_2(self):
        """Pins the closed-stderr usage path (exit 2); passes on 3.12 and 3.14 with or without the construction guard."""
        result = self.run_helper(CLOSE_STDERR_ONLY, ("--unknown",))
        self.assertEqual(result.returncode, EXIT_ERROR)
        self.assertNotIn(b"Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
