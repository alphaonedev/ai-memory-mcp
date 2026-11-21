#!/usr/bin/env python3
"""#9592 (REVIEW-9592-delta-r3 D3-M1): a test file a gate runs as a script passes in the gate's exact call form.

Class: a module that passes under ``unittest discover`` (which puts the start directory on sys.path) fails
when a gate runs it as ``python3 -I FILE ...``, because isolated mode drops the script's own folder from
sys.path; a sibling import (``import workflow_text``) then raises ModuleNotFoundError and the gate is red.

Invariant: every file scripts/test/test-ci-workflow-invariants.sh runs with ``python3 -I`` loads in isolated
mode, and the s19 consumer check passes in the gate's exact argument list; every scripts/ci/tests module
that imports the sibling ``workflow_text`` also loads in isolated mode (each has a ``__main__`` entry).

The expected sets below are written out by hand from the gate script and a grep of the importers; they are
never computed from the code under test. Standard library only, so this file itself passes under ``-I``.

Run: python3 -m unittest discover -s scripts/ci/tests -p test_script_callform_9592.py
"""
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
THIS_FILE = "scripts/ci/tests/test_script_callform_9592.py"
GATE = REPO / "scripts" / "test" / "test-ci-workflow-invariants.sh"
PYTHON = "python3"
TIMEOUT_S = 600
CONSUMER_FILE = "scripts/ci/tests/test_impact_cargo_skip_8328.py"
CONSUMER_ARGS = ("consumer-check",)
CONSUMER_LINE = "consumer-check rows=17 problems=0"
# Every `python3 -I "$ROOT/<file>"` call form in the gate script, written out by hand.
GATE_ISOLATED_TARGETS = (
    CONSUMER_FILE,
    "scripts/ci/tests/test_coverage_classify_9263.py",
    "scripts/test/test_workflow_edited_cancel_8332.py",
    "scripts/test/test_pr_retarget_check_8332.py",
)
# The scripts/ci/tests modules that import the sibling module workflow_text and load in isolated mode,
# written out by hand: the gate target plus every other importer this PR edits.
WORKFLOW_TEXT_IMPORTERS = (
    "scripts/ci/tests/test_ci_release_split_9680.py",
    "scripts/ci/tests/test_ci_test_step_exec_6795.py",
    CONSUMER_FILE,
    "scripts/ci/tests/test_step_env_9769.py",
    "scripts/ci/tests/test_suite_budget_9229.py",
    "scripts/ci/tests/test_suite_budget_9229_integrity.py",
)
# The other workflow_text importers, each with the reason it is not held to the isolated load: no gate
# runs it as a script (unittest discover is its only call form) and it also imports other sibling
# modules first. A new importer must be added to one of the two tables.
DISCOVER_ONLY_IMPORTERS = {
    "scripts/ci/tests/test_ci_base_selector_8240.py": "discover only; imports gha_expr, impact_fixture first",
    "scripts/ci/tests/test_ci_full_nightly_8240.py": "discover only; imports impact_fixture first",
    "scripts/ci/tests/test_ci_select_gating_8240.py": "discover only; imports impact_fixture first",
    "scripts/ci/tests/test_impact_gate.py": "discover only; imports impact_fixture first",
}
GATE_CALL_RE = re.compile(r'python3 -I "\$ROOT/([A-Za-z0-9_./-]+\.py)"')
# Any isolated or no-site call form (-I, -S, or a flag cluster holding either) on one line.
SCRIPT_MODE_RE = re.compile(r"python3?(?:\s+-[A-Za-z]*[IS][A-Za-z]*)+\s")
LOAD_OK = "callform-load ok"
# Loads the module body in isolated mode under a non-main name, so no CLI action runs.
LOAD_PROBE = (
    "import runpy, sys\n"
    "runpy.run_path(sys.argv[1], run_name='callform_probe_9592')\n"
    "print(%r)\n" % LOAD_OK
)


def run(args):
    return subprocess.run(list(args), cwd=str(REPO), capture_output=True, text=True, timeout=TIMEOUT_S,
                          check=False)


def isolated_load(rel):
    return run([PYTHON, "-I", "-c", LOAD_PROBE, str(REPO / rel)])


def importer_list_problem(found, expected):
    """One line that names each file missing from, or stale in, the importer lists; "" when they agree."""
    missing = sorted(set(found) - set(expected))
    stale = sorted(set(expected) - set(found))
    parts = []
    if missing:
        parts.append("add " + ", ".join(missing) + " to WORKFLOW_TEXT_IMPORTERS (loads in isolated mode) "
                     "or DISCOVER_ONLY_IMPORTERS (discover only, with the reason) in " + THIS_FILE)
    if stale:
        parts.append("remove " + ", ".join(stale) + " from WORKFLOW_TEXT_IMPORTERS or DISCOVER_ONLY_IMPORTERS in "
                     + THIS_FILE + ": it no longer imports workflow_text")
    return "; ".join(parts)


class GateCallForm(unittest.TestCase):
    def test_gate_names_exactly_these_isolated_targets(self):
        found = sorted(set(GATE_CALL_RE.findall(GATE.read_text(encoding="utf-8"))))
        self.assertEqual(found, sorted(GATE_ISOLATED_TARGETS))

    def test_consumer_check_in_the_gate_call_form(self):
        done = run([PYTHON, "-I", str(REPO / CONSUMER_FILE), *CONSUMER_ARGS])
        self.assertEqual(done.returncode, 0, done.stdout[-2000:] + done.stderr[-2000:])
        self.assertIn(CONSUMER_LINE, done.stdout.splitlines())

    def test_every_gate_target_loads_in_isolated_mode(self):
        for rel in GATE_ISOLATED_TARGETS:
            with self.subTest(file=rel):
                done = isolated_load(rel)
                self.assertEqual((done.returncode, done.stdout.splitlines()[-1:]), (0, [LOAD_OK]),
                                 done.stderr[-2000:])


class SiblingImportersLoadIsolated(unittest.TestCase):
    def test_workflow_text_importers_load_in_isolated_mode(self):
        for rel in WORKFLOW_TEXT_IMPORTERS:
            with self.subTest(file=rel):
                done = isolated_load(rel)
                self.assertEqual((done.returncode, done.stdout.splitlines()[-1:]), (0, [LOAD_OK]),
                                 done.stderr[-2000:])

    def test_the_importer_list_is_complete(self):
        tests_dir = REPO / "scripts" / "ci" / "tests"
        importer_re = re.compile(r"^\s*(?:import workflow_text\b|from workflow_text import\b)", re.M)
        found = sorted("scripts/ci/tests/" + p.name for p in tests_dir.glob("*.py")
                       if importer_re.search(p.read_text(encoding="utf-8")))
        expected = sorted(WORKFLOW_TEXT_IMPORTERS + tuple(DISCOVER_ONLY_IMPORTERS))
        self.assertEqual(importer_list_problem(found, expected), "")
        self.assertEqual(found, expected)

    def test_the_importer_list_failure_message_is_one_line_naming_file_and_list(self):
        new = "scripts/ci/tests/test_new_importer_9592.py"
        self.assertEqual(
            importer_list_problem([new, "a.py"], ["a.py"]),
            "add " + new + " to WORKFLOW_TEXT_IMPORTERS (loads in isolated mode) or DISCOVER_ONLY_IMPORTERS "
            "(discover only, with the reason) in scripts/ci/tests/test_script_callform_9592.py")
        self.assertEqual(
            importer_list_problem(["a.py"], ["a.py", "gone.py"]),
            "remove gone.py from WORKFLOW_TEXT_IMPORTERS or DISCOVER_ONLY_IMPORTERS in "
            "scripts/ci/tests/test_script_callform_9592.py: it no longer imports workflow_text")
        self.assertEqual(importer_list_problem(["a.py"], ["a.py"]), "")
        self.assertNotIn("\n", importer_list_problem(["x.py", "y.py"], ["z.py"]))

    def test_no_discover_only_importer_has_a_script_caller(self):
        caller_files = [GATE, *sorted((REPO / ".github" / "workflows").glob("*.yml"))]
        lines = [line for path in caller_files for line in path.read_text(encoding="utf-8").splitlines()
                 if SCRIPT_MODE_RE.search(line)]
        for rel in DISCOVER_ONLY_IMPORTERS:
            with self.subTest(file=rel):
                self.assertEqual([line for line in lines if Path(rel).name in line], [])


if __name__ == "__main__":
    unittest.main()
