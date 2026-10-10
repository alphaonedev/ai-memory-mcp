#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin that ci.yml runs the AGE self-heal helper in Python isolated mode (#6339).

``scripts/ci/ensure-age-extension.py`` reads the tier URL file and builds
``PGPASSWORD``.  Without ``python3 -I`` Python puts ``scripts/ci/`` first on
``sys.path`` and honours ``PYTHONPATH`` from the persistent self-hosted runner, so a
``scripts/ci/<stdlib-name>.py`` file or a ``PYTHONPATH`` entry could replace a standard
library module inside that process.  The repository runs its other security gate
scripts with ``python3 -I`` (#5163, #5280).

Rule: every ci.yml line that runs ``ensure-age-extension.py`` through python3 passes ``-I``
before the script path, and at least one such invocation exists (a rename must not make
the pin vacuous).  The check is exercised against a mutant that drops ``-I``.
Stdlib only.
"""

from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github/workflows/ci.yml"
HELPER = "scripts/ci/ensure-age-extension.py"
ISOLATED = re.compile(r"\bpython3\s+(?:-\S+\s+)*-I(?:\s+-\S+)*\s+" + re.escape(HELPER) + r"(?:\s|$)")


def helper_invocations(text):
    """Lines that run the helper through python3."""
    return [ln for ln in text.splitlines() if HELPER in ln and re.search(r"\bpython3\b", ln)]


def non_isolated(text):
    return [ln.strip() for ln in helper_invocations(text) if not ISOLATED.search(ln)]


class TestAgeHelperIsolated6339(unittest.TestCase):
    def test_ci_runs_the_helper_with_python_isolated_mode(self):
        text = CI_YML.read_text(encoding="utf-8")
        self.assertTrue(helper_invocations(text), "ci.yml no longer runs the AGE helper; update this pin")
        self.assertEqual(non_isolated(text), [], "the helper must run as `python3 -I`")

    def test_the_check_rejects_a_mutant_without_dash_i(self):
        text = CI_YML.read_text(encoding="utf-8")
        mutant = text.replace("python3 -I " + HELPER, "python3 " + HELPER)
        self.assertTrue(mutant != text, "ci.yml has no `python3 -I` helper invocation to mutate")
        self.assertTrue(non_isolated(mutant))
        self.assertTrue(non_isolated("run: python3 -S " + HELPER + " --url-file x"))
        self.assertEqual(non_isolated("run: python3 -I " + HELPER + " --url-file x"), [])


if __name__ == "__main__":
    sys.exit(unittest.main())
