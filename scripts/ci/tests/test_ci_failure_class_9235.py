# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin scripts/ci/ci_failure_class.py (#9235): the PG-ENV annotation maps to ci-env."""

import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "ci_failure_class.py"
SPEC = importlib.util.spec_from_file_location("ci_failure_class", SCRIPT)
CLS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CLS
SPEC.loader.exec_module(CLS)

REAL = "::error::[coverage-pg] PG-ENV plpgsql.so cannot load (server binary and library packages do not match)"
NEAR_MISSES = (
    "::warning::[coverage-pg] PG-ENV plpgsql.so cannot load",
    "[coverage-pg] PG-ENV plpgsql.so cannot load",
    "::error::[coverage-pg] PG-ENVX plpgsql.so cannot load",
    "::error::[coverage-pg] PG-ENV",
    "::error::[coverage-pg] PG-ENV ",
    "::error::[coverage-pg]PG-ENV x",
    "::error::[other-pg] PG-ENV x",
    "::error::[coverage-pg] PG-ENVIRONMENT x",
    "error: [coverage-pg] PG-ENV x",
    "prefix::error::[coverage-pg] PG-ENV x",
    "",
)


class ClassifierTests(unittest.TestCase):
    def test_real_line_maps_to_ci_env(self):
        self.assertEqual(CLS.classify(REAL), "ci-env")

    def test_runner_timestamp_prefix_still_maps(self):
        self.assertEqual(CLS.classify("2026-11-12T18:15:17.5834172Z " + REAL + "\n"), "ci-env")

    def test_line_inside_a_large_log(self):
        log = "ok line\n" * 100_000 + REAL + "\n" + "more\n" * 10
        self.assertEqual(CLS.classify(log), "ci-env")

    def test_near_misses_do_not_map(self):
        for line in NEAR_MISSES:
            with self.subTest(line=line):
                self.assertIsNone(CLS.classify(line))

    def test_cli_prints_exact_class_lines(self):
        for text, expect in ((REAL, "CI-CLASS: ci-env\n"), (NEAR_MISSES[0], "CI-CLASS: none\n")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                import sys

                old = sys.stdin
                sys.stdin = io.StringIO(text)
                try:
                    rc = CLS.main([])
                finally:
                    sys.stdin = old
            self.assertEqual(rc, 0)
            self.assertEqual(out.getvalue(), expect)


if __name__ == "__main__":
    unittest.main()
