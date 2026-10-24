"""Tests for scripts/ci/impact/gate.py, the ci-gate aggregate (umbrella #8240).

The gate reads the `toJSON(needs)` of the aggregate job. Exit 0 only when
every selected job succeeded; a job skipped by selection passes; a selected
job that was skipped, failed, cancelled or timed out fails the gate.
"""
import json
import subprocess
import sys
import unittest

import impact_fixture as fx
from impact import gate

GATE_SCRIPT = fx.IMPACT_DIR / "gate.py"
JOB_MAP = {"lint": "rust", "check": "rust", "postgres-feature": "cells",
           "actionlint": "actionlint"}
EXIT_FAIL = 1


def needs(**results):
    """Build a needs document: job id -> {"result": ...}."""
    return {job: {"result": res, "outputs": {}} for job, res in results.items()}


class Evaluate(unittest.TestCase):
    def run_eval(self, doc, selected, all_flag=False):
        return gate.evaluate(doc, set(selected), all_flag, JOB_MAP)

    def test_all_success_passes(self):
        ok, _ = self.run_eval(needs(lint="success", check="success"), ["rust"])
        self.assertTrue(ok)

    def test_unselected_skipped_passes(self):
        ok, _ = self.run_eval(
            needs(lint="success", **{"postgres-feature": "skipped"}), ["rust"])
        self.assertTrue(ok)

    def test_selected_skipped_fails(self):
        ok, rows = self.run_eval(needs(lint="skipped"), ["rust"])
        self.assertFalse(ok)
        self.assertEqual(rows[0]["selected"], True)

    def test_failure_fails(self):
        ok, _ = self.run_eval(needs(lint="failure"), ["rust"])
        self.assertFalse(ok)

    def test_cancelled_fails_even_if_unselected(self):
        ok, _ = self.run_eval(needs(lint="cancelled"), [])
        self.assertFalse(ok)

    def test_timed_out_fails(self):
        ok, _ = self.run_eval(needs(lint="timed_out"), ["rust"])
        self.assertFalse(ok)

    def test_all_flag_selects_every_job(self):
        ok, _ = self.run_eval(needs(lint="skipped"), [], all_flag=True)
        self.assertFalse(ok)

    def test_all_flag_all_success(self):
        ok, _ = self.run_eval(needs(lint="success", actionlint="success"),
                              [], all_flag=True)
        self.assertTrue(ok)

    def test_unmapped_job_must_succeed(self):
        ok, _ = self.run_eval(needs(select="success", classify="success"), [])
        self.assertTrue(ok)
        ok, _ = self.run_eval(needs(select="failure"), [])
        self.assertFalse(ok)
        ok, _ = self.run_eval(needs(classify="skipped"), [])
        self.assertFalse(ok)

    def test_unknown_result_fails_closed(self):
        ok, _ = self.run_eval(needs(lint="weird"), ["rust"])
        self.assertFalse(ok)

    def test_missing_result_fails_closed(self):
        ok, _ = self.run_eval({"lint": {"outputs": {}}}, ["rust"])
        self.assertFalse(ok)

    def test_table_rows(self):
        _, rows = self.run_eval(needs(lint="success", check="failure"), ["rust"])
        self.assertEqual([r["job"] for r in rows], ["check", "lint"])
        self.assertEqual({r["job"]: r["result"] for r in rows},
                         {"lint": "success", "check": "failure"})


class CommandLine(unittest.TestCase):
    def run_gate(self, doc, jobs, all_flag="false"):
        return subprocess.run(
            [sys.executable, "-I", str(GATE_SCRIPT), "--needs", json.dumps(doc),
             "--jobs", jobs, "--all", all_flag, "--rules", str(fx.RULES_JSON)],
            capture_output=True, text=True)

    def test_exit_zero_on_pass(self):
        res = self.run_gate(needs(lint="success", select="success"), "rust")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_exit_one_on_selected_skipped(self):
        res = self.run_gate(needs(lint="skipped", select="success"), "rust")
        self.assertEqual(res.returncode, EXIT_FAIL)
        self.assertIn("lint", res.stdout)
        self.assertIn("skipped", res.stdout)

    def test_bad_json_fails(self):
        res = subprocess.run(
            [sys.executable, "-I", str(GATE_SCRIPT), "--needs", "{not json",
             "--jobs", "", "--all", "false"], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)

    def test_needs_from_file(self):
        path = fx.make_scratch()
        self.addCleanup(path.cleanup)
        doc = fx.Path(path.name) / "needs.json"
        doc.write_text(json.dumps(needs(select="success")))
        res = subprocess.run(
            [sys.executable, "-I", str(GATE_SCRIPT), "--needs", "@" + str(doc),
             "--jobs", "", "--all", "false"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
