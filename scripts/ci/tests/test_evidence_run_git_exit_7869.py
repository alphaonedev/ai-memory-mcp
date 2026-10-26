#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""LOW7869: prep.run_git has one return type; its terminal error path raises SystemExit(3)."""
import ast
import io
import unittest
from contextlib import redirect_stderr
import unittest.mock as mock

from test_evidence_generator_5040_5042 import EVIDENCE, load

EXIT_STATUS = 3
PREP = EVIDENCE / "prep.py"


def function_node(name):
    tree = ast.parse(PREP.read_text(encoding="utf-8"))
    return next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)


class RunGitExit7869(unittest.TestCase):
    def test_terminal_branch_raises_system_exit_not_sys_exit_call_7869(self):
        node = function_node("run_git")
        calls = [c for c in ast.walk(node) if isinstance(c, ast.Call)
                 and isinstance(c.func, ast.Attribute) and c.func.attr == "exit"]
        self.assertEqual(calls, [], "run_git must not end a return-valued function with a sys.exit() call")
        raises = [r for r in ast.walk(node) if isinstance(r, ast.Raise)]
        self.assertEqual(len(raises), 1)
        self.assertEqual(ast.unparse(raises[0].exc),
                         f"SystemExit({EXIT_STATUS})")

    def test_unrunnable_git_still_exits_three_with_diagnostic_7869(self):
        prep = load("prep")
        stderr = io.StringIO()
        with mock.patch.object(prep.subprocess, "run", side_effect=FileNotFoundError(2, "No such file")):
            with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                prep.run_git("/nonexistent-repo", "status")
        self.assertEqual(caught.exception.code, EXIT_STATUS)
        self.assertIn("cannot run in /nonexistent-repo", stderr.getvalue())

    def test_success_returns_the_completed_process_7869(self):
        prep = load("prep")
        sentinel = object()
        with mock.patch.object(prep.subprocess, "run", return_value=sentinel):
            self.assertIs(prep.run_git("/some/repo", "status"), sentinel)


if __name__ == "__main__":
    unittest.main()
