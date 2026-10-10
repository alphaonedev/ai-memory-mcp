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

#6508 pins the rest of the step that runs the helper, so an edit that echoes the tier URL into the job
log (``set -x``, a URL in an ``::error::`` line, a URL on the helper argv), widens the ``macos-fed``
guard, or lets a failed self-heal pass (``|| true``, ``exit 0``, ``continue-on-error``) fails here.

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


STEP_START = re.compile(r"^(\s*)- (?:name|uses|run):")
XTRACE = re.compile(r"(?:\bset\s+(?:-\S*x\S*|[-+]o\s+xtrace)|\bxtrace\b|\bBASH_XTRACEFD\b|\bPS4=)")
GUARD = 'if [ "${CI_NODE:-}" = "macos-fed" ]; then'
CALL = re.compile(r'^\s*if ! python3 -I ' + re.escape(HELPER) + r' --url-file "\$url_file"; then$')
URL_VARS = re.compile(r"\$\{?(?:base_url|new_url)\b|\$\(cat\b")


def helper_step(text):
    """The workflow step (its lines) that holds the helper call."""
    lines = text.splitlines()
    at = next(i for i, ln in enumerate(lines) if HELPER in ln and re.search(r"\bpython3\b", ln))
    start = at
    while start > 0 and not re.match(r"^\s*- name:", lines[start]):
        start -= 1
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = at + 1
    while end < len(lines) and not (lines[end].strip() and len(lines[end]) - len(lines[end].lstrip()) <= indent
                                    and lines[end].lstrip().startswith("- ")):
        end += 1
    return lines[start:end]


def wiring_problems(text):
    """Every way the helper step could leak the tier URL, run on another runner, or let a failure pass."""
    step = helper_step(text)
    body = "\n".join(step)
    found = []
    if XTRACE.search(body):
        found.append("the step enables xtrace; it would print the tier URL")
    if "continue-on-error" in body:
        found.append("the step sets continue-on-error")
    calls = [i for i, ln in enumerate(step) if HELPER in ln and re.search(r"\bpython3\b", ln)]
    if len(calls) != 1 or not CALL.match(step[calls[0]]):
        found.append('the helper must run as `if ! python3 -I <helper> --url-file "$url_file"; then` and nothing else')
        return found
    i = calls[0]
    if step[i - 1].strip() != GUARD:
        found.append("the helper call is not guarded by exactly the macos-fed CI_NODE test")
    err, leave = step[i + 1].strip(), step[i + 2].strip()
    if not err.startswith('echo "::error::') or re.findall(r"\$\{?(\w+)", err) != ["RUNNER_NAME"]:
        found.append("the failure line must be an ::error:: echo that references only $RUNNER_NAME")
    if leave != "exit 1" or step[i + 3].strip() != "fi" or step[i + 4].strip() != "fi":
        found.append("the failure branch must end in `exit 1` with no other branch")
    for ln in step:
        s = ln.strip()
        if s.startswith("echo") and ">>" not in s and URL_VARS.search(s):
            found.append(f"an echo line prints the tier URL: {s[:60]}")
    return found


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

    def test_the_step_wiring_is_pinned_6508(self):
        self.assertEqual(wiring_problems(CI_YML.read_text(encoding="utf-8")), [])

    def test_the_wiring_check_rejects_each_mutant_6508(self):
        text = CI_YML.read_text(encoding="utf-8")
        call = 'if ! python3 -I ' + HELPER + ' --url-file "$url_file"; then'
        mutants = {
            "set-x on the step": ("set -euo pipefail\n          # psql lives", "set -euxo pipefail\n          # psql lives"),
            "set -x before the call": (call, "set -x\n            " + call),
            "URL in the ::error:: line": ("AGE self-heal failed (#6161), see", "AGE self-heal failed (#6161) $base_url, see"),
            "widened guard": (GUARD + "\n            " + call, 'if [ "${CI_NODE:-}" != "linux-fed" ]; then\n            ' + call),
            "|| true": (call, call[:-6] + " || true; then"),
            "exit 0 on failure": ('see the ensure-age-extension line above"\n              exit 1',
                                  'see the ensure-age-extension line above"\n              exit 0'),
            "URL on argv": ('--url-file "$url_file"; then', '--url-file "$url_file" "$base_url"; then'),
            "continue-on-error": ("        run: |\n          set -euo pipefail\n          # psql lives",
                                  "        continue-on-error: true\n        run: |\n          set -euo pipefail\n          # psql lives"),
            "echoed URL": (call, 'echo "url=$(cat "$url_file")"\n            ' + call),
        }
        for name, (old, new) in mutants.items():
            with self.subTest(mutant=name):
                self.assertEqual(text.count(old) >= 1, True, f"ci.yml no longer holds the text mutated by {name!r}")
                self.assertTrue(wiring_problems(text.replace(old, new, 1)), f"mutant not caught: {name}")


if __name__ == "__main__":
    sys.exit(unittest.main())
