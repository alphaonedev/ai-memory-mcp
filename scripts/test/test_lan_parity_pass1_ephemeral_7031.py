#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin lan-parity Pass 1 to a throwaway database (#7031 H3).

PG_MAINT_DB stays the shared name but only as the CREATE/DROP connection; the
URL cargo reads must point at the minted ``ai_memory_test_p1_*`` base.

Stdlib only. Run: ``python3 -I scripts/test/test_lan_parity_pass1_ephemeral_7031.py``
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "infra" / "lan-parity-test" / "run-parity-tests.sh"


class LanParityPass1Ephemeral7031(unittest.TestCase):
    def setUp(self):
        self.text = SCRIPT.read_text(encoding="utf-8")

    def test_pass1_url_targets_the_minted_p1_db(self):
        self.assertRegex(self.text, r'PG_P1_DB="ai_memory_test_p1_')
        url = re.search(r'^PG_URL="([^"]*)"', self.text, re.M)
        self.assertIsNotNone(url)
        self.assertIn("${PG_P1_DB}", url.group(1))
        self.assertNotIn("PG_MAINT_DB", url.group(1))

    def test_p1_db_is_created_and_dropped(self):
        self.assertIn('CREATE DATABASE \\"$PG_P1_DB\\"', self.text)
        self.assertIn('DROP DATABASE IF EXISTS \\"$PG_P1_DB\\"', self.text)

    def test_maint_db_only_feeds_psql_connections(self):
        for number, line in enumerate(self.text.splitlines(), 1):
            if line.lstrip().startswith("#") or "PG_MAINT_DB" not in line:
                continue
            ok = line.startswith("PG_MAINT_DB=") or "-d \"$PG_MAINT_DB\"" in line
            self.assertTrue(ok, "line %d: PG_MAINT_DB outside a psql -d" % number)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
