#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin that ci.yml runs the tier password check before it uses the tier URL (#6181).

The "Configure enterprise-fed tier" step must run ``scripts/ci/check-tier-password.py`` as
``python3 -I`` on the URL file, before the first psql call, and a non-zero exit must stop the step
(``exit 1``) with no other branch.  The check is exercised against mutants.  Stdlib only.
"""

from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github/workflows/ci.yml"
CHECK = "scripts/ci/check-tier-password.py"
CALL = 'if ! python3 -I ' + CHECK + ' --url-file "$url_file"; then'
READ = 'base_url="$(cat "$url_file")"'
FIRST_PSQL = re.compile(r'\bpsql\s+"\$')


def step_lines(text):
    lines = text.splitlines()
    at = next((i for i, ln in enumerate(lines) if CHECK in ln), None)
    if at is None:
        return None, []
    start = at
    while start > 0 and not re.match(r"^\s*- name:", lines[start]):
        start -= 1
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = at + 1
    while end < len(lines) and not (lines[end].strip() and len(lines[end]) - len(lines[end].lstrip()) <= indent
                                    and lines[end].lstrip().startswith("- ")):
        end += 1
    return at - start, lines[start:end]


def wiring_problems(text):
    at, step = step_lines(text)
    found = []
    if at is None:
        return ["ci.yml does not run the tier password check"]
    calls = [i for i, ln in enumerate(step) if CHECK in ln]
    if len(calls) != 1 or step[calls[0]].strip() != CALL:
        return ['the check must run as `' + CALL + '` and nothing else']
    i = calls[0]
    if step[i + 1].strip() != "exit 1" or step[i + 2].strip() != "fi":
        found.append("a failing check must `exit 1` with no other branch")
    body = "\n".join(step)
    if "continue-on-error" in body:
        found.append("the step sets continue-on-error")
    if "Configure enterprise-fed tier" not in step[0]:
        found.append("the check is not in the Configure enterprise-fed tier step")
    psql_at = next((j for j, ln in enumerate(step) if FIRST_PSQL.search(ln)), None)
    read_at = next((j for j, ln in enumerate(step) if READ in ln), None)
    if psql_at is None or read_at is None or not (i < read_at < psql_at):
        found.append("the check must run before the URL is read and before the first psql call")
    return found


class TestTierPasswordWiring6181(unittest.TestCase):
    def test_the_wiring_is_pinned(self):
        self.assertEqual(wiring_problems(CI_YML.read_text(encoding="utf-8")), [])

    def test_the_wiring_check_rejects_each_mutant(self):
        text = CI_YML.read_text(encoding="utf-8")
        mutants = {
            "dropped": (CALL, "true"),
            "no -I": (CALL, CALL.replace("python3 -I", "python3")),
            "|| true": (CALL, CALL[:-6] + " || true; then"),
            "exit 0": (CALL + "\n            exit 1", CALL + "\n            exit 0"),
            "continue-on-error": ("        shell: bash\n        env:\n          # matrix.leg via env",
                                  "        shell: bash\n        continue-on-error: true\n        env:\n          # matrix.leg via env"),
        }
        block = CALL + "\n            exit 1\n          fi\n"
        self.assertEqual(text.count(block.replace("            exit 1", "            exit 1")), 1)
        moved = text.replace(block, "", 1).replace(READ + "\n", READ + "\n          " + block, 1)
        self.assertTrue(wiring_problems(moved), "mutant not caught: check moved after the URL read")
        for name, (old, new) in mutants.items():
            with self.subTest(mutant=name):
                self.assertIn(old, text, f"ci.yml no longer holds the text mutated by {name!r}")
                self.assertTrue(wiring_problems(text.replace(old, new, 1)), f"mutant not caught: {name}")


if __name__ == "__main__":
    sys.exit(unittest.main())
