#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin coverage.yml to an ephemeral per-run Postgres base (#7031 H2).

The throwaway container must not be created with, probed on, or pointed at the
shared ``ai_memory_test`` database; the tests get ``ai_memory_test_ci_<run>_<attempt>_cov``.
The literal ``ai_memory_test`` is still legal as the container PASSWORD.

Stdlib only. Run: ``python3 -I scripts/test/test_workflow_coverage_ephemeral_db_7031.py``
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "coverage.yml"
# The bare shared name; `ai_memory_test_ci_...` never matches (word char `_`).
SHARED = re.compile(r"\bai_memory_test\b")
# A credential, not a database name: PGPASSWORD=/PGPASSWORD:/POSTGRES_PASSWORD=
# or the `user:password@` slot of a URL.
PASSWORD_CONTEXT = re.compile(r"(PASSWORD\s*[=:]\s*|ai_memory:)$")


def _code_lines(text: str):
    for number, line in enumerate(text.splitlines(), 1):
        if not line.lstrip().startswith("#"):
            yield number, line


class CoverageEphemeralDb7031(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_no_shared_db_name_outside_password_slot(self):
        offenders = []
        for number, line in _code_lines(self.text):
            for found in SHARED.finditer(line):
                if not PASSWORD_CONTEXT.search(line[: found.start()]):
                    offenders.append("%d: %s" % (number, line.strip()))
        self.assertEqual(offenders, [], "shared ai_memory_test used as a database name")

    def test_container_maintenance_db_is_postgres(self):
        self.assertIn("POSTGRES_DB=postgres", self.text)

    def test_ephemeral_base_is_minted_per_run_and_attempt(self):
        self.assertRegex(
            self.text,
            r"ai_memory_test_ci_\$\{GITHUB_RUN_ID\}_\$\{GITHUB_RUN_ATTEMPT\}_cov",
        )
        self.assertIn('CREATE DATABASE \\"$CI_COV_DB\\"', self.text)

    def test_both_test_urls_point_at_the_minted_base(self):
        for var in ("AI_MEMORY_TEST_POSTGRES_URL", "AI_MEMORY_TEST_AGE_URL"):
            self.assertRegex(self.text, var + r"=postgres://[^\"]*/\$\{CI_COV_DB\}\?")

    def test_both_extensions_are_created_on_the_minted_db_and_not_swallowed(self):
        # The image creates `age` only in POSTGRES_DB; the minted db needs both.
        lines = [l for _, l in _code_lines(self.text) if "CREATE EXTENSION" in l or "create_graph" in l]
        ext = [l for l in lines if "CREATE EXTENSION IF NOT EXISTS age" in l]
        self.assertTrue(ext, "no `CREATE EXTENSION IF NOT EXISTS age` in coverage.yml")
        for line in ext:
            self.assertIn('-d "$CI_COV_DB"', line)
            self.assertIn("CREATE EXTENSION IF NOT EXISTS vector", line)
            self.assertIn("ON_ERROR_STOP=1", line)
        for line in lines:
            self.assertNotRegex(line, r"\|\|\s*(echo|true)", "extension/graph failure must fail the step")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
