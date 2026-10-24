"""ci.yml select gating invariants (umbrella #8240, PR #8241 round 2).

A skipped required job counts as green on the ruleset, so a job may be skipped
ONLY when the `select` job succeeded AND produced an explicit 'false' for the
job's domain. Every other `select` outcome (failure, cancelled, skipped,
missing, empty or malformed output) means the gated job RUNS.

These tests evaluate the real job-level `if:` text of ci.yml with a minimal
GitHub expression evaluator, including the implicit `success()` GitHub
prepends to an `if:` without a status function.
"""
import itertools
import json
import re
import unittest

import impact_fixture as fx
import gha_expr
import workflow_text

CI_YML = fx.REPO_ROOT / ".github" / "workflows" / "ci.yml"
SELECT_JOB = "select"
CLASSIFY_JOB = "classify"
GATE_JOB = "ci-gate"
SELECT_RESULTS = ("success", "failure", "cancelled", "skipped")
OUTPUT_VALUES = ("true", "false", "", None)
PATTERN = re.compile(
    r"^\$\{\{ !cancelled\(\) && (?:.+ && )?"
    r"\(needs\.select\.result != 'success' \|\| "
    r"needs\.select\.outputs\.(?P<domain>[a-z-]+) != 'false'\) \}\}$")
EXPECTED_GATED = {"lint", "actionlint", "msrv", "postgres-feature",
                  "sal-feature", "vectorlite-feature", "dockerfile-validate"}


def gated_jobs():
    """Return {job id: job} for every job whose `if:` mentions needs.select."""
    jobs = workflow_text.read_jobs(CI_YML)
    return {name: job for name, job in jobs.items()
            if job["if"] and "needs.select" in job["if"]}


def context(select_result, value, domain, docs_only="false"):
    """Build the needs/github context for one probe."""
    outputs = {} if value is None else {domain: value}
    return {
        "needs": {
            "classify": {"result": "success", "outputs": {"docs_only": docs_only}},
            "select": {"result": select_result, "outputs": outputs},
        },
        "github": {"ref": "refs/pull/1/merge"},
    }


class GatedIfShape(unittest.TestCase):
    def test_the_seven_gated_jobs_are_found(self):
        self.assertEqual(set(gated_jobs()), EXPECTED_GATED)

    def test_every_gated_if_uses_the_fail_closed_pattern(self):
        for name, job in gated_jobs().items():
            with self.subTest(job=name):
                self.assertRegex(job["if"], PATTERN)

    def test_every_gated_job_needs_select(self):
        for name, job in gated_jobs().items():
            with self.subTest(job=name):
                self.assertIn(SELECT_JOB, job["needs"])

    def test_domain_matches_the_gate_job_map(self):
        job_map = json.loads(fx.RULES_JSON.read_text())["job_map"]
        for name, job in gated_jobs().items():
            with self.subTest(job=name):
                domain = PATTERN.match(job["if"]).group("domain")
                self.assertEqual(domain, job_map[name])

    def test_select_job_declares_every_domain_output(self):
        outputs = workflow_text.read_jobs(CI_YML)[SELECT_JOB]["outputs"]
        domains = set(json.loads(fx.RULES_JSON.read_text())["job_map"].values())
        for domain in domains:
            with self.subTest(domain=domain):
                self.assertIn(domain, outputs)


class GatedIfEvaluation(unittest.TestCase):
    def test_every_combination_runs_except_success_false(self):
        for name, job in gated_jobs().items():
            domain_match = PATTERN.match(job["if"])
            domain = domain_match.group("domain") if domain_match else "rust"
            for result, value in itertools.product(SELECT_RESULTS, OUTPUT_VALUES):
                with self.subTest(job=name, select=result, value=value):
                    runs = gha_expr.evaluate_job_if(
                        job["if"], context(result, value, domain))
                    skip_allowed = (result, value) == ("success", "false")
                    self.assertEqual(runs, not skip_allowed)

    def test_docs_only_still_skips_when_select_succeeded(self):
        for name, job in gated_jobs().items():
            domain_match = PATTERN.match(job["if"])
            domain = domain_match.group("domain") if domain_match else "rust"
            with self.subTest(job=name):
                self.assertFalse(gha_expr.evaluate_job_if(
                    job["if"], context("success", "true", domain, docs_only="true")))

    def test_workflow_cancellation_skips(self):
        for name, job in gated_jobs().items():
            domain_match = PATTERN.match(job["if"])
            domain = domain_match.group("domain") if domain_match else "rust"
            with self.subTest(job=name):
                self.assertFalse(gha_expr.evaluate_job_if(
                    job["if"], context("success", "true", domain), cancelled=True))


class EvaluatorSelfCheck(unittest.TestCase):
    """The evaluator reproduces the defect in the pre-round-2 expression."""

    OLD = ("needs.classify.outputs.docs_only != 'true' && (needs.select.outputs.enforce"
           " != 'true' || needs.select.outputs.all != 'false')")

    def test_implicit_success_skips_after_a_failed_select(self):
        self.assertFalse(gha_expr.evaluate_job_if(self.OLD, context("failure", None, "rust")))
        self.assertTrue(gha_expr.evaluate_job_if(self.OLD, context("success", None, "rust")))

    def test_status_function_disables_the_implicit_success(self):
        self.assertTrue(gha_expr.evaluate_job_if(
            "${{ !cancelled() && needs.select.result != 'success' }}",
            context("failure", None, "rust")))


class CiGateNeeds(unittest.TestCase):
    def test_gate_needs_every_other_job_except_the_b4_set(self):
        # Rule (b4) of scripts/check-required-contexts.sh hard-fails a job that
        # needs a required job carrying a job-level `if:`, so those seven stay
        # out of ci-gate until (b4) exempts an `if: always()` aggregate.
        jobs = workflow_text.read_jobs(CI_YML)
        expected = set(jobs) - {GATE_JOB} - EXPECTED_GATED
        self.assertEqual(set(jobs[GATE_JOB]["needs"]), expected)

    def test_the_b4_set_is_exactly_the_jobs_with_a_job_level_if(self):
        jobs = workflow_text.read_jobs(CI_YML)
        with_if = {n for n, j in jobs.items() if j["if"] and n != GATE_JOB}
        self.assertEqual(with_if, EXPECTED_GATED)

    def test_build_script_vetting_is_in_the_gate(self):
        self.assertIn("build-script-vetting",
                      workflow_text.read_jobs(CI_YML)[GATE_JOB]["needs"])

    def test_gate_runs_always(self):
        self.assertEqual(workflow_text.read_jobs(CI_YML)[GATE_JOB]["if"], "always()")


if __name__ == "__main__":
    unittest.main()
