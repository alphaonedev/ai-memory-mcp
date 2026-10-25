"""Tests for scripts/ci/impact/gate.py, the ci-gate aggregate (umbrella #8240).

The gate reads the `toJSON(needs)` of the aggregate job, including the
`select` and `classify` outputs. A job that succeeded passes. A job that was
skipped passes ONLY when `classify` succeeded and said docs_only, or when
`select` succeeded and recorded the literal 'false' for that job's domain
(S5, fail closed). Every other outcome fails the gate.
"""
import json
import subprocess
import sys
import unittest

import impact_fixture as fx
from impact import gate

GATE_SCRIPT = fx.IMPACT_DIR / "gate.py"
JOB_MAP = {"lint": "rust", "check": "rust", "postgres-feature": "cells",
           "actionlint": "actionlint", "dockerfile-validate": "rust"}
EXIT_FAIL = 1
DOMAINS_FALSE = {"rust": "false", "cells": "false", "actionlint": "false"}


def needs(select="success", outputs=None, docs_only="false", **results):
    """Build a needs document with select/classify and the given job results."""
    doc = {
        "select": {"result": select,
                   "outputs": DOMAINS_FALSE if outputs is None else outputs},
        "classify": {"result": "success", "outputs": {"docs_only": docs_only}},
    }
    for job, res in results.items():
        doc[job.replace("_", "-")] = {"result": res, "outputs": {}}
    return doc


class Evaluate(unittest.TestCase):
    def run_eval(self, doc, ref="refs/pull/1/merge"):
        return gate.evaluate(doc, JOB_MAP, ref, ("dockerfile-validate",))

    def test_all_success_passes(self):
        ok, _ = self.run_eval(needs(lint="success", check="success"))
        self.assertTrue(ok)

    def test_skipped_with_explicit_false_passes(self):
        ok, _ = self.run_eval(needs(postgres_feature="skipped"))
        self.assertTrue(ok)

    def test_skipped_with_true_output_fails(self):
        ok, rows = self.run_eval(needs(outputs={"rust": "true"}, lint="skipped"))
        self.assertFalse(ok)
        self.assertTrue(rows[[r["job"] for r in rows].index("lint")]["selected"])

    def test_skipped_with_empty_or_missing_output_fails(self):
        for outputs in ({}, {"rust": ""}, {"rust": "weird"}):
            with self.subTest(outputs=outputs):
                ok, _ = self.run_eval(needs(outputs=outputs, lint="skipped"))
                self.assertFalse(ok)

    def test_select_failed_and_job_skipped_fails_naming_the_job(self):
        ok, rows = self.run_eval(needs(select="failure", lint="skipped"))
        self.assertFalse(ok)
        failed = [r["job"] for r in rows if not r["ok"]]
        self.assertIn("lint", failed)
        self.assertIn("select", failed)

    def test_select_not_success_never_lets_a_skip_pass(self):
        for result in ("failure", "cancelled", "skipped", "timed_out", None):
            with self.subTest(select=result):
                ok, rows = self.run_eval(needs(select=result, lint="skipped"))
                self.assertFalse(ok)
                lint = [r for r in rows if r["job"] == "lint"][0]
                self.assertFalse(lint["ok"])

    def test_docs_only_skip_passes(self):
        ok, _ = self.run_eval(needs(outputs={}, docs_only="true", lint="skipped"))
        self.assertTrue(ok)

    def test_docs_only_with_failed_classify_does_not_excuse_a_skip(self):
        doc = needs(outputs={}, docs_only="true", lint="skipped")
        doc["classify"]["result"] = "failure"
        ok, _ = self.run_eval(doc)
        self.assertFalse(ok)

    def test_tag_ref_excuses_dockerfile_validate_only(self):
        doc = needs(outputs={}, dockerfile_validate="skipped")
        ok, _ = self.run_eval(doc, ref="refs/tags/v1.0.0")
        self.assertTrue(ok)
        ok, _ = self.run_eval(doc)
        self.assertFalse(ok)
        ok, _ = self.run_eval(needs(outputs={}, lint="skipped"), ref="refs/tags/v1.0.0")
        self.assertFalse(ok)

    def test_failure_fails(self):
        ok, _ = self.run_eval(needs(lint="failure"))
        self.assertFalse(ok)

    def test_cancelled_fails(self):
        ok, _ = self.run_eval(needs(lint="cancelled"))
        self.assertFalse(ok)

    def test_timed_out_fails(self):
        ok, _ = self.run_eval(needs(lint="timed_out"))
        self.assertFalse(ok)

    def test_unmapped_job_must_succeed(self):
        ok, _ = self.run_eval(needs(build_script_vetting="success"))
        self.assertTrue(ok)
        ok, _ = self.run_eval(needs(build_script_vetting="skipped"))
        self.assertFalse(ok)

    def test_select_and_classify_must_succeed(self):
        ok, _ = self.run_eval(needs(select="failure"))
        self.assertFalse(ok)
        doc = needs()
        doc["classify"]["result"] = "skipped"
        ok, _ = self.run_eval(doc)
        self.assertFalse(ok)

    def test_unknown_result_fails_closed(self):
        ok, _ = self.run_eval(needs(lint="weird"))
        self.assertFalse(ok)

    def test_missing_result_fails_closed(self):
        doc = needs()
        doc["lint"] = {"outputs": {}}
        ok, _ = self.run_eval(doc)
        self.assertFalse(ok)

    def test_table_rows(self):
        _, rows = self.run_eval(needs(lint="success", check="failure"))
        self.assertEqual([r["job"] for r in rows],
                         ["check", "classify", "lint", "select"])
        self.assertEqual({r["job"]: r["result"] for r in rows if r["job"] in JOB_MAP},
                         {"lint": "success", "check": "failure"})


def complete(doc):
    """Add a success entry for every required job the document lacks."""
    full = dict(doc)
    for job in gate.REQUIRED_NEEDS:
        full.setdefault(job, {"result": "success", "outputs": {}})
    return full


class MissingNeededJob(unittest.TestCase):
    """S13: an absent needed job fails the gate (an absent result looks like a skipped gate).

    decision: the gate requires the full expected job set over tolerating an
    absent job because an absent result is indistinguishable from a skipped
    gate
    """

    def run_gate(self, doc):
        cmd = [sys.executable, "-I", str(GATE_SCRIPT), "--needs", json.dumps(doc),
               "--rules", str(fx.RULES_JSON)]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_the_full_set_passes(self):
        res = self.run_gate(complete(needs()))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_each_removed_job_fails_with_the_fixed_reason_naming_it(self):
        for job in gate.REQUIRED_NEEDS:
            doc = complete(needs())
            del doc[job]
            with self.subTest(job=job):
                res = self.run_gate(doc)
                self.assertEqual(res.returncode, EXIT_FAIL, res.stdout)
                self.assertIn("ci-gate: missing-needed-job: %s" % job, res.stdout)
                self.assertIn("ci-gate: FAIL", res.stdout)

    def test_an_empty_payload_fails(self):
        res = self.run_gate({})
        self.assertEqual(res.returncode, EXIT_FAIL, res.stdout)
        for job in gate.REQUIRED_NEEDS:
            self.assertIn("missing-needed-job: %s" % job, res.stdout)

    def test_evaluate_reports_the_missing_job_row(self):
        doc = needs(lint="success")
        ok, rows = gate.evaluate(doc, JOB_MAP, "", (), ("lint", "check"))
        self.assertFalse(ok)
        self.assertIn({"job": "check", "result": "missing-needed-job",
                       "selected": True, "ok": False}, rows)

    def test_the_required_set_equals_the_ci_gate_needs_list(self):
        import workflow_text
        jobs = workflow_text.read_jobs(fx.REPO_ROOT / ".github" / "workflows" / "ci.yml")
        job = jobs["ci-gate"]
        self.assertEqual(sorted(job["needs"]), sorted(gate.REQUIRED_NEEDS))


class CommandLine(unittest.TestCase):
    def run_gate(self, doc, ref=""):
        doc = complete(doc)
        cmd = [sys.executable, "-I", str(GATE_SCRIPT), "--needs", json.dumps(doc),
               "--rules", str(fx.RULES_JSON)]
        if ref:
            cmd += ["--github-ref", ref]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_exit_zero_on_pass(self):
        res = self.run_gate(needs(lint="success"))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_exit_one_when_select_failed_and_job_skipped(self):
        res = self.run_gate(needs(select="failure", lint="skipped"))
        self.assertEqual(res.returncode, EXIT_FAIL)
        self.assertIn("lint", res.stdout)
        self.assertIn("skipped", res.stdout)

    def test_exit_zero_on_recorded_false(self):
        res = self.run_gate(needs(lint="skipped"))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_bad_json_fails(self):
        res = subprocess.run(
            [sys.executable, "-I", str(GATE_SCRIPT), "--needs", "{not json"],
            capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)

    def test_needs_from_file(self):
        path = fx.make_scratch()
        self.addCleanup(path.cleanup)
        doc = fx.Path(path.name) / "needs.json"
        doc.write_text(json.dumps(complete(needs())))
        res = subprocess.run(
            [sys.executable, "-I", str(GATE_SCRIPT), "--needs", "@" + str(doc)],
            capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
