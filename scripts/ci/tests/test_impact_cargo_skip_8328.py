"""Round-2 guards for the cargo_skip classifier (#8328, issue #8322).

Findings covered (REVIEW-8328-code-r1 F1/F2, REVIEW-8328-security-r1 F1/F2):

1. Trust root: the classify step is the first step after checkout, loads the
   decider and rules from the merge-base tree, and runs it with -I from outside
   the workspace; a change under scripts/ci/ or .github/ forces a full run; the
   impact modules never put the workspace first on sys.path.
2. Never-skip set: the pg isolation test is never skippable; every path a
   workflow step reads (ci.yml, coverage.yml, composite actions) is in the read
   set and outside the skip set.
3. Read set: every top-level directory a Rust scanner walks is classified
   cargo-relevant, except the roots a Python mirror guard covers on every PR.
4. Forced full runs: a push event and a protected base ref force false.
5. Rules shape: a null or wrong-shaped rules.json exits 1 with a message.
6. Rule b3 no longer accepts cargo_skip_reason as a guard.

Round 3 (REVIEW-8328-code-r2 F1/F2/F3, REVIEW-8328-security-r2 F1/F2, #8338):

7. The cls step runs no workspace command and appends no PR-produced file to
   its output file; the PR-tree selector runs in the separate `impact` step with
   its own output file, copies only allow-listed lines, and degrades to the
   full selection on anything else (a multi-line value opener included).
8. The trust block never reads a workspace copy of the classifier, not even as
   a fallback.
9. Every walk guard is unskippable; the mirror roots equal the Rust roots.

Round 4 (REVIEW-8328-code-r3 F1/F2/INFO-2, REVIEW-8328-security-r3 F1/F2/INFO-a):

10. The test consumer is the boundary for the skip sentinel: `__SKIP__` never
    selects a no-op there, whatever the docs_only verdict says.
11. The impact step's stdout defuse and its log truncation are exercised with
    selector stdout (not only selector output-file lines), under the runner's
    `-eo pipefail` flags.

Round 5 (REVIEW-8328-code-r4 F1/F2/F3, REVIEW-8328-security-r4 F1/F2/INFO):

12. The consumer accepts a selection only when every word, split with
    globbing off, matches ^[A-Za-z0-9_]+$ and names an existing tests/<word>.rs;
    anything else runs the full suite and the words are counted, never echoed.
    The impact allow-list carries no dash in the test_impact value class.
13. The consumer is tested as the WHOLE step with a fake cargo on PATH (also
    the `consumer-check` mode the invariants harness runs), with its exact if:,
    a single reader in any spacing or index form, nothing reading the selection
    before the boundary, and exactly two dispatch arms.
14. The cls verdict-shape guard forces false/false on a malformed verdict.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.append(str(REPO / "scripts" / "ci"))

from impact import cargo_skip, read_set  # noqa: E402

CI_YML = REPO / ".github" / "workflows" / "ci.yml"
COVERAGE_YML = REPO / ".github" / "workflows" / "coverage.yml"
WORKFLOW_DIR = REPO / ".github" / "workflows"
ACTIONS_DIR = REPO / ".github" / "actions"
GATE = REPO / "scripts" / "check-required-contexts.sh"
RULES = REPO / "scripts" / "ci" / "impact" / "rules.json"
SCRATCH = REPO / ".local-runs"
SCRIPT = REPO / "scripts" / "ci" / "impact" / "cargo_skip.py"
PG_TEST = "scripts/ci/tests/test_pg_isolated_binary.py"
STEP_SCRIPT = re.compile(r"scripts/[A-Za-z0-9_./-]+\.(?:py|sh)")
JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
STEP_HEADER = re.compile(r"^      - ")
RUN_HEADER = re.compile(r"^        run: \|\s*$")
TIMEOUT_S = 120
RUN_INDENT = 10
# The flags the hosted runner gives a `shell: bash` step (errexit + pipefail).
RUNNER_BASH = ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c"]
TEST_STEP_NAME = "- name: Run tests (impact-aware)"
BOUNDARY_BEGIN = "# consumer-boundary-begin"
BOUNDARY_END = "# consumer-boundary-end"
DISPATCH_CASE = 'case "${TEST_IMPACT:-__ALL__}" in'
DISPATCH_ARM = re.compile(r"^ {12}([^ #][^)\n]*\))", re.M)
DISPATCH_ARMS = ('__ALL__|"")', "*)")
STEP_IF = re.compile(r"^        if:\s*(.*)$")
CONSUMER_IF = "needs.classify.outputs.cargo_skip != 'true'"
EXPECTED_READER = ("ci.yml", "TEST_IMPACT: ${{ needs.classify.outputs.test_impact }}")
REJECTED = "impact-selection-rejected-at-consumer"
WHOLE_STEP_NAMES = ("alpha_test", "beta_test")
# Any spacing or index form of a property access: `.name` or `['name']`.
_PROP = r"""\s*(?:\.\s*{0}|\[\s*['"]{0}['"]\s*\])"""
READER_RE = re.compile("needs" + _PROP.format("classify") + _PROP.format("outputs")
                       + _PROP.format("test_impact") + r"(?![A-Za-z0-9_-])")
# The whole outputs object (toJSON, fromJSON) is a read of every key.
WHOLE_OUTPUTS_RE = re.compile("needs" + _PROP.format("classify") + _PROP.format("outputs")
                              + r"(?!\s*[.\[])")


def job_lines(path: Path, job: str):
    """Return the lines of `job` in a workflow file."""
    lines = path.read_text().splitlines()
    out = []
    inside = False
    for line in lines:
        header = JOB_HEADER.match(line)
        if header:
            inside = header.group(1) == job
            continue
        if inside:
            out.append(line)
    return out


def step_starts(lines):
    """Return [(index, first line)] of each step of a job."""
    return [(i, line.strip()) for i, line in enumerate(lines) if STEP_HEADER.match(line)]


def step_run_body(lines, start):
    """Return the run body of the step that starts at `start`."""
    body = []
    in_run = False
    for line in lines[start + 1:]:
        if STEP_HEADER.match(line):
            break
        if RUN_HEADER.match(line):
            in_run = True
            continue
        if in_run:
            if line.strip() and not line.startswith(" " * RUN_INDENT):
                break  # a step-level comment or key ends the block scalar
            body.append(line)
    return "\n".join(body)


def step_by_id(path: Path, step_id: str):
    """Return (steps, index of the step, its run body) for a classify-job step."""
    lines = job_lines(path, "classify")
    steps = step_starts(lines)
    for pos, (index, first) in enumerate(steps):
        if first == "- id: %s" % step_id:
            return steps, pos, step_run_body(lines, index)
    raise AssertionError("no %s step in the classify job of %s" % (step_id, path.name))


def cls_step(path: Path):
    """Return (steps, index of the cls step, its run body) for the classify job."""
    return step_by_id(path, "cls")


def code_lines(body: str):
    """Return the non-comment, non-blank lines of a run body."""
    return [line for line in body.splitlines()
            if line.strip() and not line.strip().startswith("#")]


def trust_block(body: str) -> str:
    """Return the cls lines from the trust directory setup to the verdict case."""
    start = body.index("trust_dir=")
    end = body.index('case "$docs_only$cargo_skip" in')
    return body[start:end]


# Forms of the scripts/ci/impact path the trust block may contain: the
# merge-base tree read, and the scratch directory the extract lands in.
TRUST_PATH_FORMS = ('"${trust_ref}:scripts/ci/impact/${trust_file}"',
                    'trust_impact="$trust_dir/scripts/ci/impact"',
                    '"$trust_dir/scripts/ci/impact"')


def scratch_dir() -> Path:
    """Return a fresh scratch directory under the gitignored .local-runs."""
    SCRATCH.mkdir(exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="cs8328-", dir=str(SCRATCH)))


def run_cli(rules_text: str, args, stdin_text: str = "x.md\n"):
    """Run cargo_skip.py -I against a rules text; return (rc, stdout, stderr)."""
    work = scratch_dir()
    try:
        rules = work / "rules.json"
        rules.write_text(rules_text)
        res = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--stdin", "--rules", str(rules)] + list(args),
            input=stdin_text, capture_output=True, text=True, timeout=TIMEOUT_S)
        return res.returncode, res.stdout, res.stderr
    finally:
        shutil.rmtree(str(work), ignore_errors=True)


class TrustRootWorkflow(unittest.TestCase):
    """Security F1: the decider is not read from the PR tree."""

    def test_classify_is_the_first_step_after_checkout(self):
        for path in (CI_YML,):
            steps, pos, _ = cls_step(path)
            self.assertEqual(pos, 1, "cls must be step 2 (right after checkout) in %s, got index %d" % (path.name, pos))
            self.assertIn("actions/checkout", steps[0][1])

    def test_no_pr_code_step_precedes_classify(self):
        lines = job_lines(CI_YML, "classify")
        steps = step_starts(lines)
        cls_index = [i for i, first in steps if first == "- id: cls"][0]
        before = [first for i, first in steps if i < cls_index]
        self.assertEqual(len(before), 1, "only the checkout may precede cls: %s" % before)

    def test_decider_comes_from_the_merge_base_tree(self):
        _, _, body = cls_step(CI_YML)
        self.assertIn("git merge-base", body)
        self.assertIn('git show "${trust_ref}:scripts/ci/impact/', body)
        self.assertIn("python3 -I \"$trust_impact/cargo_skip.py\"", body)
        self.assertIn('--rules "$trust_impact/rules.json"', body)

    def test_decider_is_never_run_from_the_workspace(self):
        _, _, body = cls_step(CI_YML)
        self.assertNotRegex(body, r"python3?\s+(-I\s+)?scripts/ci/impact/cargo_skip\.py")
        self.assertNotIn("--rules scripts/ci/impact/rules.json", body)
        self.assertNotRegex(body, r"python3?\s+(-I\s+)?scripts/ci/impact/")

    def test_trust_block_has_no_workspace_impact_path_at_all(self):
        """REVIEW-8328-code-r2 F2: not even a silent fallback to the workspace copy."""
        block = trust_block(cls_step(CI_YML)[2])
        residue = "\n".join(code_lines(block))
        for form in TRUST_PATH_FORMS:
            residue = residue.replace(form, "")
        self.assertNotIn("scripts/ci/impact", residue,
                         "the trust block names a workspace classifier path")
        for token in ("$GITHUB_WORKSPACE", "./scripts", "cp ", "ln ", "source ", "mv "):
            self.assertNotIn(token, residue, "trust block uses %r" % token)

    def test_base_tree_extract_failure_only_marks_untrusted(self):
        block = trust_block(cls_step(CI_YML)[2])
        shows = [line for line in block.splitlines() if "git show" in line]
        self.assertEqual(len(shows), 1, shows)
        self.assertTrue(shows[0].rstrip().endswith("|| trusted=false"),
                        "a failed extract must only mark the classifier untrusted: %s" % shows[0])
        self.assertIn('if [ "$trusted" != "true" ]; then', block)
        self.assertIn("trusted-classifier-missing-in-base-fail-closed", block)

    def test_verdict_lines_are_written_once_by_the_cls_step(self):
        _, _, body = cls_step(CI_YML)
        for key in ("docs_only", "cargo_skip", "cargo_skip_reason"):
            marker = 'echo "%s=$%s" >> "$GITHUB_OUTPUT"' % (key, key)
            self.assertEqual(body.count(marker), 1, key)

    def test_ci_tree_edit_is_checked_in_the_workflow(self):
        _, _, body = cls_step(CI_YML)
        self.assertIn("classifier-or-workflow-edited-fail-closed", body)
        self.assertIn("trusted-classifier-missing-in-base-fail-closed", body)

    def test_coverage_classify_uses_the_trusted_decider(self):
        _, _, body = cls_step(COVERAGE_YML)
        self.assertIn('git show "${trust_ref}:scripts/ci/impact/', body)
        self.assertIn("python3 -I \"$trust_impact/cargo_skip.py\"", body)
        self.assertNotIn("grep -qvE '^(docs/|.*\\.md$)'", body)
        self.assertNotRegex(body, r"python3?\s+(-I\s+)?scripts/ci/impact/")


class ClsStepRunsNoWorkspaceCommand(unittest.TestCase):
    """Round 3 F1 (#8338 class): nothing PR-produced reaches the verdict file."""

    ALLOWED_PATH_TEXT = ("'^(\\.github/|scripts/ci/)'", "'^scripts/ci/tests/'")

    def test_cls_body_names_no_workspace_path(self):
        _, _, body = cls_step(CI_YML)
        residue = "\n".join(code_lines(body))
        for form in TRUST_PATH_FORMS + self.ALLOWED_PATH_TEXT:
            residue = residue.replace(form, "")
        self.assertNotIn("scripts/", residue, "cls names a workspace path outside the trust block")
        for token in ("ci-test-impact", "chmod", "$GITHUB_WORKSPACE", "./scripts"):
            self.assertNotIn(token, body, "cls must not run or touch %s" % token)

    def test_cls_appends_no_produced_file_to_the_output(self):
        _, _, body = cls_step(CI_YML)
        writers = [line for line in code_lines(body) if "GITHUB_OUTPUT" in line]
        self.assertTrue(writers)
        plain = re.compile(r'^\s*echo "[a-z_]+=[^"]*" >> "\$GITHUB_OUTPUT"$')
        for line in writers:
            self.assertRegex(line, plain, "cls writes the output file only with a plain echo")
        self.assertNotRegex(body, r"\b(cat|tee|cp|sed|awk)\b[^\n]*GITHUB_OUTPUT")
        self.assertNotIn("GITHUB_OUTPUT=", body)

    def test_cls_emits_no_test_impact_key(self):
        _, _, body = cls_step(CI_YML)
        self.assertNotIn("test_impact=", body)
        self.assertNotRegex(body, r"echo \"test_impact")

    DEFANG = r"sed -e 's/::/: :/g' -e 's/##\[/# #[/g'"
    IMPACT_DEFANG = r'''sed -n '1,200{s/::/: :/g;s/##\[/# #[/g;p}' "$impact_log"'''
    # The only consumers of the changed-file list that never reach the log.
    SILENT_SINKS = ("grep ", "python3 -I ", "wc -l")

    def changed_var(self, body):
        found = re.findall(r"^\s*(\w+)=\$\(git diff [^\n]*--name-only", body, re.M)
        self.assertEqual(len(found), 1, "cls assigns the changed-file list exactly once")
        return found[0]

    def test_cls_logs_the_changed_file_list_only_through_the_defang_8343(self):
        _, _, body = cls_step(CI_YML)
        var = re.escape(self.changed_var(body))
        ref = re.compile(r'\$\{?%s\}?' % var)
        echo_ref = re.compile(r'echo "\$\{?%s\}?"(?P<rest>[^\n)]*)' % var)
        seen = 0
        for line in code_lines(body):
            if not ref.search(line) or "GITHUB_OUTPUT" in line or "[ -z" in line:
                continue
            for form in ("printf", "<<<", "<<", "cat ", "tee "):
                self.assertNotIn(form, line, "cls prints the changed list in a form this guard does not model: %r" % line)
            hits = list(echo_ref.finditer(line))
            self.assertEqual(len(hits), 1, "cls uses the changed list in a form this guard does not model: %r" % line)
            rest = hits[0].group("rest").strip()
            self.assertTrue(rest.startswith("|"), "bare echo of the changed-file list reaches the log undefanged: %r" % line)
            sink = rest[1:].strip()
            if not sink.startswith(self.SILENT_SINKS):
                self.assertTrue(sink.startswith(self.DEFANG) and not re.search(r"[>;&]", sink[len(self.DEFANG):]),
                                "changed-file list leaves the step through an unmodeled sink: %r" % line)
            seen += 1
        self.assertGreaterEqual(seen, 4)
        self.assertIn(self.DEFANG, body)

    def test_impact_log_print_carries_both_defang_expressions_8343(self):
        _, _, body = step_by_id(CI_YML, "impact")
        self.assertIn(self.IMPACT_DEFANG, body)
        self.assertEqual(len(re.findall(r"s/::/: :/g", body)), 1)

    def test_cls_defang_executed_neutralises_a_workflow_command_in_a_file_name_8343(self):
        _, _, body = cls_step(CI_YML)
        var = re.escape(self.changed_var(body))
        printers = [line.strip() for line in code_lines(body)
                    if re.match(r'\s*echo "\$%s"\s*($|\|\s*sed\b)' % var, line)]
        self.assertTrue(printers, "no log-print line for the changed-file list")
        names = "docs/::stop-commands::x\ndocs/h##[stop-commands]x"
        script = "%s='%s'\n%s\n" % (self.changed_var(body), names, "\n".join(printers))
        res = subprocess.run(RUNNER_BASH + [script], capture_output=True, text=True, timeout=TIMEOUT_S)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("docs/: :stop-commands: :x", res.stdout)
        self.assertIn("docs/h# #[stop-commands]x", res.stdout)
        self.assertNotIn("::", res.stdout)
        self.assertNotIn("##[", res.stdout)

    def test_impact_defang_executed_neutralises_both_command_forms_8343(self):
        _, _, body = step_by_id(CI_YML, "impact")
        lines = [l.strip() for l in code_lines(body)
                 if '"$impact_log"' in l and l.strip().startswith("sed -n")]
        self.assertEqual(len(lines), 1, "impact prints the selector log through exactly one sed")
        script = "impact_log=/dev/stdin\n%s\n" % lines[0]
        text = "x ::stop-commands::tok\ny ##[add-mask]z\n"
        res = subprocess.run(RUNNER_BASH + [script], input=text, capture_output=True, text=True,
                             timeout=TIMEOUT_S)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("::", res.stdout)
        self.assertNotIn("##[", res.stdout)
        self.assertIn("y # #[add-mask]z", res.stdout)

    def test_impact_step_follows_cls_and_owns_the_test_impact_outputs(self):
        steps, cls_pos, _ = cls_step(CI_YML)
        _, impact_pos, body = step_by_id(CI_YML, "impact")
        self.assertEqual(impact_pos, cls_pos + 1)
        self.assertIn("scripts/ci-test-impact.sh", body)
        text = CI_YML.read_text()
        for key in ("test_impact", "test_impact_count", "test_impact_total", "test_impact_reason"):
            self.assertIn("      %s: ${{ steps.impact.outputs.%s }}" % (key, key), text)
            self.assertNotIn("steps.cls.outputs.%s }}" % key, text)

    def test_impact_step_copies_only_allow_listed_lines(self):
        _, _, body = step_by_id(CI_YML, "impact")
        self.assertIn("allow_re=", body)
        self.assertIn("^test_impact=[A-Za-z0-9_ ]*$|", body)
        self.assertIn("(test_impact_count|test_impact_total)=", body)
        self.assertIn("impact-output-rejected-fail-closed", body)
        self.assertEqual(body.count('cat "$impact_out" >> "$GITHUB_OUTPUT"'), 1)


class ImpactStepOutputAllowList(unittest.TestCase):
    """Run the real `impact` step body against hostile selector output (#8338 class)."""

    OPENER = "<" + "<"
    SELECTED = ["test_impact=alpha_test beta_test", "test_impact_count=2",
                "test_impact_total=40", "test_impact_reason=impact-selected:2/40 (95%-skip)"]

    def run_step(self, selector_lines, docs_only="false", forced="", rc=0,
                 stdout_lines=(), stdout_repeat=0):
        """Run the step in a scratch repo; return (outputs, selector ran, stdout).

        `selector_lines` go to the selector's output file; `stdout_lines` and
        `stdout_repeat` numbered noise lines go to its stdout instead.
        """
        work = scratch_dir()
        try:
            (work / "scripts").mkdir()
            script = work / "scripts" / "ci-test-impact.sh"
            ran = work / "selector-ran"
            body = ['#!/usr/bin/env bash', 'touch "%s"' % ran]
            body += ["printf '%%s\\n' '%s' >> \"$GITHUB_OUTPUT\"" % line for line in selector_lines]
            body += ["printf '%%s\\n' '%s'" % line for line in stdout_lines]
            if stdout_repeat:
                body += ['for i in $(seq 1 %d); do echo "selector noise line $i"; done' % stdout_repeat]
            body += ['exit %d' % rc]
            script.write_text("\n".join(body) + "\n")
            out = work / "step-output"
            out.write_text("")
            env = dict(os.environ, GITHUB_OUTPUT=str(out), RUNNER_TEMP=str(work),
                       CLS_BASE="base", IMPACT_BASE="base", DOCS_ONLY=docs_only,
                       IMPACT_FORCED_REASON=forced)
            res = subprocess.run(RUNNER_BASH + [step_by_id(CI_YML, "impact")[2]],
                                 cwd=str(work), env=env, capture_output=True, text=True,
                                 timeout=TIMEOUT_S)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            values = {}
            for line in out.read_text().splitlines():
                key, _, value = line.partition("=")
                values[key] = value
            return values, ran.exists(), res.stdout
        finally:
            shutil.rmtree(str(work), ignore_errors=True)

    def assert_degraded(self, values, reason):
        self.assertEqual(values["test_impact"], "__ALL__")
        self.assertEqual(values["test_impact_count"], "ALL")
        self.assertEqual(values["test_impact_total"], "ALL")
        self.assertEqual(values["test_impact_reason"], reason)

    def test_well_formed_selection_passes_through(self):
        values, ran, _ = self.run_step(self.SELECTED)
        self.assertTrue(ran)
        self.assertEqual(values["test_impact"], "alpha_test beta_test")
        self.assertEqual(values["test_impact_reason"], "impact-selected:2/40 (95%-skip)")

    def test_multiline_value_opener_degrades_to_all(self):
        for opener in ("test_impact" + self.OPENER + "EOF", "x" + self.OPENER + "docs_only=true",
                       "test_impact_reason" + self.OPENER + "cargo_skip=true"):
            values, ran, _ = self.run_step(self.SELECTED + [opener])
            self.assertTrue(ran)
            self.assert_degraded(values, "impact-output-rejected-fail-closed")
            self.assertNotIn("docs_only", values)
            self.assertNotIn("cargo_skip", values)

    def test_foreign_key_and_blank_line_degrade_to_all(self):
        for extra in ("docs_only=true", "cargo_skip=true", "PATH=/x", ""):
            values, _, _ = self.run_step(self.SELECTED + [extra])
            self.assert_degraded(values, "impact-output-rejected-fail-closed")
            self.assertNotIn("docs_only", values)

    def test_disallowed_value_character_degrades_to_all(self):
        values, _, _ = self.run_step(["test_impact=a;b"] + self.SELECTED[1:])
        self.assert_degraded(values, "impact-output-rejected-fail-closed")

    def test_test_impact_value_class_has_no_dash_or_glob(self):
        """Round 5 F1: test_impact admits only letters, digits, underscore and space."""
        for value in ("alpha_test --no-default-features", "alpha_test *", "alpha.test", "a/b", "a,b"):
            values, _, _ = self.run_step(["test_impact=%s" % value] + self.SELECTED[1:])
            self.assert_degraded(values, "impact-output-rejected-fail-closed")
        values, _, _ = self.run_step(["test_impact=__ALL__", "test_impact_count=ALL",
                                      "test_impact_total=ALL", "test_impact_reason=x"])
        self.assertEqual(values["test_impact_reason"], "x")

    def test_missing_or_duplicate_key_degrades_to_all(self):
        values, _, _ = self.run_step(self.SELECTED[:3])
        self.assert_degraded(values, "impact-output-rejected-fail-closed")
        values, _, _ = self.run_step(self.SELECTED + ["test_impact=__SKIP__"])
        self.assert_degraded(values, "impact-output-rejected-fail-closed")

    def test_skip_is_honoured_only_when_docs_only(self):
        skip = ["test_impact=__SKIP__", "test_impact_count=0", "test_impact_total=0",
                "test_impact_reason=docs-only"]
        values, _, _ = self.run_step(skip, docs_only="false")
        self.assert_degraded(values, "impact-skip-overridden-not-docs-only")
        values, _, _ = self.run_step(skip, docs_only="true")
        self.assertEqual(values["test_impact"], "__SKIP__")

    def test_selector_failure_degrades_to_all(self):
        values, _, _ = self.run_step(self.SELECTED, rc=3)
        self.assert_degraded(values, "impact-selector-failed-fail-closed")

    def test_early_exit_reason_runs_no_selector(self):
        values, ran, _ = self.run_step(self.SELECTED, forced="empty-diff-fail-closed")
        self.assertFalse(ran, "a forced full selection must not run the PR-tree selector")
        self.assert_degraded(values, "empty-diff-fail-closed")

    def test_selector_stdout_cannot_inject_a_workflow_command(self):
        values, _, stdout = self.run_step(self.SELECTED, stdout_lines=[
            "::set-output name=x::y", "::add-mask::z", "plain ok line"])
        for line in stdout.splitlines():
            self.assertFalse(line.startswith("::"), "undefused workflow command: %r" % line)
        self.assertIn(": :set-output name=x: :y", stdout)
        self.assertIn(": :add-mask: :z", stdout)
        self.assertIn("plain ok line", stdout)
        self.assertEqual(values["test_impact"], "alpha_test beta_test")
        self.assertEqual(values["test_impact_reason"], "impact-selected:2/40 (95%-skip)")

    def test_long_selector_log_does_not_fail_the_step(self):
        for count in (300, 20000):
            values, _, stdout = self.run_step(self.SELECTED, stdout_repeat=count)
            self.assertEqual(values["test_impact"], "alpha_test beta_test", count)
            self.assertIn("selector noise line 200", stdout)
            self.assertNotIn("selector noise line 201", stdout)


def test_step_lines():
    """Return (check-job lines, index of the Run tests (impact-aware) step)."""
    lines = job_lines(CI_YML, "check")
    for index, first in step_starts(lines):
        if first == TEST_STEP_NAME:
            return lines, index
    raise AssertionError("no Run tests (impact-aware) step in the check job")


def consumer_step_body():
    """Return the run body of the Run tests (impact-aware) step."""
    lines, index = test_step_lines()
    return step_run_body(lines, index)


def consumer_step_ifs():
    """Return every step-level `if:` value of the Run tests step."""
    lines, index = test_step_lines()
    found = []
    for line in lines[index + 1:]:
        if STEP_HEADER.match(line):
            break
        match = STEP_IF.match(line)
        if match:
            found.append(match.group(1).strip())
    return found


def consumer_readers():
    """Return (file, stripped line) for every read of the test_impact output."""
    readers = []
    for path in sorted(WORKFLOW_DIR.glob("*.y*ml")):
        for line in path.read_text().splitlines():
            if READER_RE.search(line) or WHOLE_OUTPUTS_RE.search(line):
                readers.append((path.name, line.strip()))
    return readers


def dispatch_region(body: str):
    """Return (code before the boundary, boundary through the case line, case arms)."""
    begin = body.index(BOUNDARY_BEGIN)
    case = body.index(DISPATCH_CASE)
    end = body.index("\n          esac", case)
    arms = [m.group(1) for m in DISPATCH_ARM.finditer(body[case:end])]
    return body[:begin], body[begin:case], arms


def consumer_shape_problems():
    """Return the static problems of the test consumer (empty when sound)."""
    problems = []
    ifs = consumer_step_ifs()
    if ifs != [CONSUMER_IF]:
        problems.append("Run tests if: is %r, want exactly [%r]" % (ifs, CONSUMER_IF))
    readers = consumer_readers()
    if readers != [EXPECTED_READER]:
        problems.append("test_impact readers are %r, want only %r" % (readers, EXPECTED_READER))
    body = consumer_step_body()
    before, boundary, arms = dispatch_region(body)
    for line in code_lines(before):
        if "TEST_IMPACT" in line or "__SKIP__" in line:
            problems.append("selection read before the boundary: %s" % line.strip())
    for line in code_lines(boundary):
        if re.search(r"\b(exit|return)\b", line):
            problems.append("exit or return between the boundary and the dispatch: %s" % line.strip())
    if arms != list(DISPATCH_ARMS):
        problems.append("dispatch arms are %r, want %r" % (arms, list(DISPATCH_ARMS)))
    for path in sorted(WORKFLOW_DIR.glob("*.y*ml")):
        if re.search(r"__SKIP__\)", path.read_text()):
            problems.append("a __SKIP__ case arm in %s" % path.name)
    return problems


FAKE_CARGO = "#!%s -I\nimport json, sys\nwith open(%r, 'a') as log:\n    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
STEP_ENV_DROP = ("TEST_IMPACT", "TEST_IMPACT_REASON", "TEST_IMPACT_COUNT", "TEST_IMPACT_TOTAL",
                 "DOCS_ONLY", "TIER", "CI_NODE", "JOB_T0", "HOST_SEMAPHORE_HELD",
                 "CI_PG_ISOLATE_OFF", "AI_MEMORY_TEST_PG_ISOLATE", "TEST_RESULT_LOG")


def run_whole_step(impact, docs_only="false", tier="sqlite"):
    """Run the WHOLE Run tests step with a fake cargo; return (rc, argv list, output).

    The scratch working directory holds tests/alpha_test.rs and
    tests/beta_test.rs, so those are the only existing test names.
    """
    work = scratch_dir()
    try:
        (work / "tests").mkdir()
        for name in WHOLE_STEP_NAMES:
            (work / "tests" / ("%s.rs" % name)).write_text("")
        (work / "bin").mkdir()
        argv_log = work / "cargo-argv.jsonl"
        fake = work / "bin" / "cargo"
        fake.write_text(FAKE_CARGO % (sys.executable, str(argv_log)))
        fake.chmod(0o755)
        env = {k: v for k, v in os.environ.items() if k not in STEP_ENV_DROP}
        env.update(PATH="%s%s%s" % (work / "bin", os.pathsep, os.environ.get("PATH", "")),
                   TEST_IMPACT=impact, DOCS_ONLY=docs_only, TIER=tier, CI_NODE="probe",
                   HOST_SEMAPHORE_SLOTS="0", JOB_TIMEOUT_MIN="60", AI_MEMORY_NO_CONFIG="1",
                   RUNNER_TEMP=str(work), GITHUB_ENV=str(work / "github-env"))
        res = subprocess.run(RUNNER_BASH + [consumer_step_body()], cwd=str(work), env=env,
                             capture_output=True, text=True, timeout=TIMEOUT_S)
        argv = []
        if argv_log.exists():
            argv = [json.loads(line) for line in argv_log.read_text().splitlines()]
        return res.returncode, argv, res.stdout + res.stderr
    finally:
        shutil.rmtree(str(work), ignore_errors=True)


# (label, TEST_IMPACT, DOCS_ONLY, tier, expected selection, expected notice)
WHOLE_STEP_ROWS = (
    ("skip-docs-false", "__SKIP__", "false", "sqlite", "full", "impact-skip-overridden-at-consumer"),
    ("skip-docs-true", "__SKIP__", "true", "sqlite", "full", "impact-skip-overridden-at-consumer"),
    ("skip-docs-unset", "__SKIP__", "", "sqlite", "full", "impact-skip-overridden-at-consumer"),
    ("skip-enterprise", "__SKIP__", "false", "enterprise-fed", "full", "impact-skip-overridden-at-consumer"),
    ("all", "__ALL__", "false", "sqlite", "full", None),
    ("blank", "", "false", "sqlite", "full", None),
    ("names", "alpha_test beta_test", "false", "sqlite", "names", None),
    ("names-enterprise", "alpha_test beta_test", "false", "enterprise-fed", "names", None),
    ("dash-word", "alpha_test --no-default-features", "false", "sqlite", "full", REJECTED),
    ("dash-only", "--release", "false", "sqlite", "full", REJECTED),
    ("dash-enterprise", "alpha_test --no-default-features", "false", "enterprise-fed", "full", REJECTED),
    ("glob-word", "alpha_test *", "false", "sqlite", "full", REJECTED),
    ("newline", "alpha_test\nbeta_test", "false", "sqlite", "full", REJECTED),
    ("tab", "alpha_test\tbeta_test", "false", "sqlite", "full", REJECTED),
    ("no-such-test", "alpha_test missing_test", "false", "sqlite", "full", REJECTED),
    ("unknown-sentinel", "__NONE__", "false", "sqlite", "full", REJECTED),
    ("spaces-only", "   ", "false", "sqlite", "full", REJECTED),
)
NAME_ARGS = ["--test", "alpha_test", "--test", "beta_test"]
SHARD_BUILD = ["test", "--no-run", "--message-format=json-render-diagnostics", "--features", "sal-postgres"]
EXPECTED_ARGV = {
    ("sqlite", "full"): [["test", "--no-run"], ["test", "--no-fail-fast"]],
    ("sqlite", "names"): [["test", "--no-run", "--lib"], ["test", "--no-fail-fast", "--lib"],
                          ["test", "--no-run"] + NAME_ARGS, ["test", "--no-fail-fast"] + NAME_ARGS],
    # enterprise-fed shards after one build; the scratch tree has no
    # partition script, so only the build argv (the selection) is compared.
    ("enterprise-fed", "full"): [SHARD_BUILD],
    ("enterprise-fed", "names"): [SHARD_BUILD + ["--lib"] + NAME_ARGS],
}


def whole_step_problem(row):
    """Run one WHOLE_STEP_ROWS row; return a problem string, or None."""
    label, impact, docs_only, tier, selection, notice = row
    rc, argv, output = run_whole_step(impact, docs_only, tier)
    want = EXPECTED_ARGV[(tier, selection)]
    got = argv[:1] if tier == "enterprise-fed" else argv
    if got != want:
        return "%s: cargo argv %r, want %r (rc %d)" % (label, argv, want, rc)
    if tier == "sqlite" and rc != 0:
        return "%s: step rc %d" % (label, rc)
    if notice and notice not in output:
        return "%s: no %s notice" % (label, notice)
    if notice is None and "-at-consumer" in output:
        return "%s: unexpected consumer notice" % label
    if notice == REJECTED and ("--no-default-features" in output or "--release" in output):
        return "%s: a rejected word was echoed" % label
    return None


def consumer_check_main():
    """CLI for the s19 invariant: run every whole-step row and the shape checks."""
    problems = consumer_shape_problems()
    for row in WHOLE_STEP_ROWS:
        problem = whole_step_problem(row)
        print("row %s: %s" % (row[0], problem or "ok"))
        if problem:
            problems.append(problem)
    for problem in problems:
        print("problem: %s" % problem)
    print("consumer-check rows=%d problems=%d" % (len(WHOLE_STEP_ROWS), len(problems)))
    return 1 if problems else 0


class ConsumerBoundary(unittest.TestCase):
    """The test consumer never honours `__SKIP__` (REVIEW-8328-*-r3 F1)."""

    def boundary_block(self):
        body = consumer_step_body()
        self.assertIn(BOUNDARY_BEGIN, body)
        return body[body.index(BOUNDARY_BEGIN):body.index(BOUNDARY_END)]

    def resolve(self, impact, docs_only):
        """Run the boundary block in a tree with two tests; return (TEST_IMPACT, stdout)."""
        work = scratch_dir()
        try:
            (work / "tests").mkdir()
            for name in WHOLE_STEP_NAMES:
                (work / "tests" / ("%s.rs" % name)).write_text("")
            script = "set -u\n%s\necho \"RESULT=$TEST_IMPACT\"\n" % self.boundary_block()
            env = dict(os.environ, TEST_IMPACT=impact, DOCS_ONLY=docs_only)
            res = subprocess.run(RUNNER_BASH + [script], cwd=str(work), env=env,
                                 capture_output=True, text=True, timeout=TIMEOUT_S)
        finally:
            shutil.rmtree(str(work), ignore_errors=True)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        result = [l for l in res.stdout.splitlines() if l.startswith("RESULT=")][0]
        return result[len("RESULT="):], res.stdout

    def test_skip_reaches_the_full_suite_branch_whatever_docs_only_says(self):
        for docs_only in ("false", "true", "", "True"):
            final, out = self.resolve("__SKIP__", docs_only)
            self.assertEqual(final, "__ALL__", docs_only)
            self.assertIn("impact-skip-overridden-at-consumer", out)
            self.assertIn("decision:", out)

    def test_other_selections_pass_through_untouched(self):
        for impact in ("__ALL__", "alpha_test beta_test"):
            final, out = self.resolve(impact, "false")
            self.assertEqual(final, impact)
            self.assertNotIn("-at-consumer", out)

    def test_only_existing_test_names_pass_the_boundary(self):
        """Round 5 F1: a dash word, a glob, a newline or an unknown name gives __ALL__."""
        for impact in ("alpha_test --no-default-features", "alpha_test *", "alpha_test\nbeta_test",
                       "alpha_test missing_test", "__NONE__", "   "):
            final, out = self.resolve(impact, "false")
            self.assertEqual(final, "__ALL__", repr(impact))
            self.assertIn(REJECTED, out, repr(impact))
            self.assertNotIn("--no-default-features", out)

    def test_step_has_no_skip_arm_and_receives_docs_only(self):
        body = consumer_step_body()
        self.assertNotRegex(body, r"__SKIP__\)")
        text = CI_YML.read_text()
        self.assertIn("DOCS_ONLY: ${{ needs.classify.outputs.docs_only }}", text)
        self.assertLess(body.index(BOUNDARY_END), body.index(DISPATCH_CASE))

    def test_every_test_impact_consumer_is_the_guarded_step(self):
        """s19 twin: one reader in any spacing or index form, if:, env: or with:."""
        self.assertEqual(consumer_readers(), [EXPECTED_READER])
        for form in ("if: ${{ needs.classify.outputs['test_impact'] == 'x' }}",
                     "X: ${{ needs . classify . outputs . test_impact }}",
                     "with: { a: \"${{ needs['classify']['outputs'][\"test_impact\"] }}\" }",
                     "Y: ${{ toJSON(needs.classify.outputs) }}"):
            self.assertTrue(READER_RE.search(form) or WHOLE_OUTPUTS_RE.search(form), form)
        self.assertIsNone(READER_RE.search("${{ needs.classify.outputs.test_impact_reason }}"))

    def test_consumer_step_shape(self):
        """Round 5 F2: exact if:, no read before the boundary, no early exit, two arms."""
        self.assertEqual(consumer_shape_problems(), [])


class ConsumerWholeStep(unittest.TestCase):
    """Round 5 F1/F2: execute the WHOLE Run tests step with a fake cargo on PATH."""

    def test_every_selection_shape_reaches_the_expected_cargo_argv(self):
        for row in WHOLE_STEP_ROWS:
            with self.subTest(row=row[0]):
                self.assertIsNone(whole_step_problem(row))


def run_cls_with_stub(stub_lines):
    """Run the real cls body in a scratch repo whose base-tree classifier prints `stub_lines`."""
    work = scratch_dir()
    try:
        repo = work / "repo"
        impact = repo / "scripts" / "ci" / "impact"
        impact.mkdir(parents=True)
        for name in ("__init__.py", "common.py"):
            (impact / name).write_text("")
        (impact / "rules.json").write_text("{}\n")
        (impact / "cargo_skip.py").write_text(
            "import sys\nsys.stdin.read()\nsys.stdout.write(%r)\n" % "".join(l + "\n" for l in stub_lines))
        (repo / "docs").mkdir()
        (repo / "docs" / "a.md").write_text("a\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        git = ["git", "-c", "user.name=ci", "-c", "user.email=ci@example.invalid",
               "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"]
        for args in (["init", "-q", "."], ["add", "-A"], ["commit", "-qm", "base"]):
            subprocess.run(git + args, cwd=str(repo), env=env, check=True, timeout=TIMEOUT_S)
        base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo), env=env, check=True,
                              capture_output=True, text=True, timeout=TIMEOUT_S).stdout.strip()
        (repo / "docs" / "a.md").write_text("a\nb\n")
        subprocess.run(git + ["commit", "-qam", "pr"], cwd=str(repo), env=env, check=True, timeout=TIMEOUT_S)
        out = work / "out"
        out.write_text("")
        (work / "rt").mkdir()
        env.update(GITHUB_OUTPUT=str(out), RUNNER_TEMP=str(work / "rt"), EVENT_NAME="pull_request",
                   PR_BEFORE="", PR_BASE_SHA=base, PR_ACTION="opened", PR_BASE_REF="chain/probe")
        res = subprocess.run(RUNNER_BASH + [cls_step(CI_YML)[2]], cwd=str(repo), env=env,
                             capture_output=True, text=True, timeout=TIMEOUT_S)
        values = {}
        for line in out.read_text().splitlines():
            key, _, value = line.partition("=")
            values[key] = value
        return res.returncode, values
    finally:
        shutil.rmtree(str(work), ignore_errors=True)


class ClsVerdictShapeGuard(unittest.TestCase):
    """Round 5 F3: a malformed trusted-classifier verdict fails closed (false/false)."""

    FAIL_CLOSED = "classifier-error-fail-closed cargo_skip-rules"

    def test_well_formed_verdict_is_consumed(self):
        rc, values = run_cls_with_stub(["docs_only=false", "cargo_skip=true", "cargo_skip_reason=stub-ok"])
        self.assertEqual(rc, 0)
        self.assertEqual((values["docs_only"], values["cargo_skip"], values["cargo_skip_reason"]),
                         ("false", "true", "stub-ok"))

    def test_malformed_verdict_forces_false_false(self):
        for lines in (["docs_only=true", "cargo_skip=false", "cargo_skip_reason=stub"],
                      ["docs_only=", "cargo_skip=true", "cargo_skip_reason=stub"],
                      ["docs_only=yes", "cargo_skip=true", "cargo_skip_reason=stub"],
                      ["docs_only=true", "docs_only=true", "cargo_skip=true", "cargo_skip_reason=stub"]):
            with self.subTest(lines=lines):
                rc, values = run_cls_with_stub(lines)
                self.assertEqual(rc, 0)
                self.assertEqual((values["docs_only"], values["cargo_skip"], values["cargo_skip_reason"]),
                                 ("false", "false", self.FAIL_CLOSED))


class NoWorkspaceFirstOnSysPath(unittest.TestCase):
    """Security F1(d): a scripts/ci module must not shadow the stdlib."""

    def test_no_sys_path_insert_zero(self):
        for name in ("cargo_skip.py", "read_set.py", "common.py"):
            text = (REPO / "scripts" / "ci" / "impact" / name).read_text()
            self.assertNotIn("sys.path.insert(0", text, name)

    def test_planted_stdlib_shadow_does_not_change_the_verdict(self):
        work = scratch_dir()
        try:
            tree = work / "scripts" / "ci"
            shutil.copytree(str(REPO / "scripts" / "ci" / "impact"), str(tree / "impact"),
                            ignore=shutil.ignore_patterns("__pycache__"))
            (tree / "json.py").write_text("raise SystemExit(0)\n")
            (tree / "sqlite3.py").write_text("raise SystemExit(0)\n")
            res = subprocess.run(
                [sys.executable, "-I", str(tree / "impact" / "cargo_skip.py"), "--stdin",
                 "--rules", str(tree / "impact" / "rules.json")],
                input="src/lib.rs\n", capture_output=True, text=True, timeout=TIMEOUT_S)
        finally:
            shutil.rmtree(str(work), ignore_errors=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("cargo_skip=false", res.stdout)


class CiTreeForcesFullRun(unittest.TestCase):
    """Security F1(c): editing the classifier or a workflow is a full run."""

    @classmethod
    def setUpClass(cls):
        cls.section = cargo_skip.load_section()

    def test_non_test_scripts_ci_path_forces_false(self):
        for path in ("scripts/ci/impact/cargo_skip.py", "scripts/ci/impact/rules.json",
                     "scripts/ci/new_gate.py", "scripts/ci/nested/deep/tool.py",
                     ".github/workflows/ci.yml", ".github/actions/x/action.yml"):
            got = cargo_skip.classify(self.section, [path])
            self.assertEqual(got["cargo_skip"], "false", path)
            self.assertEqual(got["docs_only"], "false", path)

    def test_ci_tree_edit_wins_over_a_skippable_companion(self):
        got = cargo_skip.classify(self.section, ["docs/ADMIN_GUIDE.md", "scripts/ci/gate.py"])
        self.assertEqual(got["cargo_skip"], "false")
        self.assertIn(cargo_skip.REASON_CI_TREE, got["cargo_skip_reason"])

    def test_scripts_ci_tests_stays_skippable(self):
        got = cargo_skip.classify(self.section, ["scripts/ci/tests/test_new_thing.py"])
        self.assertEqual(got["cargo_skip"], "true")


class NeverSkipSet(unittest.TestCase):
    """Security F2: pg isolation test and every workflow-read path."""

    @classmethod
    def setUpClass(cls):
        cls.section = cargo_skip.load_section()
        cls.tracked = read_set.tracked_files(REPO)
        cls.refs = read_set.referenced_paths(
            REPO, cls.tracked, read_set.guarded_map(cls.section))

    def test_pg_isolated_binary_test_is_never_skippable(self):
        self.assertIn(PG_TEST, self.tracked)
        self.assertIn(PG_TEST, self.section["never_skip_globs"])
        self.assertFalse(cargo_skip.is_skippable(self.section, PG_TEST))
        got = cargo_skip.classify(self.section, [PG_TEST])
        self.assertEqual(got["cargo_skip"], "false")
        self.assertEqual(got["docs_only"], "false")

    def workflow_step_paths(self):
        """Return {path: workflow file} for every script a workflow step names."""
        files = sorted(WORKFLOW_DIR.glob("*.y*ml"))
        if ACTIONS_DIR.is_dir():
            files += sorted(ACTIONS_DIR.rglob("*.y*ml"))
        tracked = set(self.tracked)
        found = {}
        for path in files:
            text = path.read_text()
            for match in STEP_SCRIPT.findall(text):
                if match in tracked:
                    found.setdefault(match, path.name)
            for module in read_set.UNITTEST_MODULE.findall(text):
                rel = "scripts/ci/tests/%s.py" % module
                if rel in tracked:
                    found.setdefault(rel, path.name)
        return found

    def test_workflow_step_paths_are_in_the_read_set(self):
        found = self.workflow_step_paths()
        self.assertGreater(len(found), 20, "extraction found too few step scripts")
        self.assertIn(PG_TEST, found, "the unittest module token must resolve to its file")
        missing = sorted(p for p in found if p not in self.refs)
        self.assertEqual(missing, [], "step scripts missing from the read set: %s" % missing)

    def test_workflow_step_paths_are_not_skippable(self):
        found = self.workflow_step_paths()
        leaked = sorted(p for p in found if cargo_skip.is_skippable(self.section, p))
        self.assertEqual(leaked, [], "step scripts inside the skip set: %s" % leaked)

    def test_workflow_unittest_modules_resolve(self):
        cands = read_set.candidates_of("python3 -m unittest -v test_pg_isolated_binary", False)
        self.assertIn("test_pg_isolated_binary.py", cands)


class RustScannerWalks(unittest.TestCase):
    """Code F1: the read set follows the real inputs of the scanner tests."""

    @classmethod
    def setUpClass(cls):
        cls.section = cargo_skip.load_section()
        cls.tracked = read_set.tracked_files(REPO)
        cls.guarded = read_set.guarded_map(cls.section)

    def test_walk_root_literal_is_a_directory_read(self):
        text = 'const ROOTS: [&str; 2] = ["docs", "scripts"];\nfn f(r: &str) { p.join(r); }\n'
        cands = read_set.candidates_of(text, True, {"docs", "scripts"})
        self.assertIn(read_set.DIR_MARK + "docs", cands)
        self.assertIn(read_set.DIR_MARK + "scripts", cands)

    def test_chain_component_is_not_a_root_walk(self):
        text = 'let p = root.join("docs").join("integrations");\n'
        cands = read_set.candidates_of(text, True, {"docs"})
        self.assertNotIn(read_set.DIR_MARK + "docs", cands)

    def test_3627_walk_hits_are_covered_by_the_mirror_guard(self):
        rust = "tests/issue_3627_retired_llm_alias.rs"
        self.assertIn(rust, self.guarded)
        unguarded = read_set.referenced_paths(REPO, self.tracked)
        for path in ("docs/ADMIN_GUIDE.md", "scripts/ci/tests/test_impact_cargo_skip_8328.py"):
            self.assertIn(path, unguarded, "the 3627 walk must reach %s" % path)
            self.assertTrue(
                read_set.under_any(path, self.guarded[rust]),
                "%s is skippable but not under a mirrored root" % path)

    def test_guard_files_exist_and_roots_are_walked_by_the_rust_source(self):
        for entry in self.section["walk_guards"]:
            self.assertIn(entry["rust"], self.tracked)
            self.assertIn(entry["guard"], self.tracked)
            source = (REPO / entry["rust"]).read_text()
            for root in entry["roots"]:
                self.assertIn(root.split("/")[0], source, "%s not walked by %s" % (root, entry["rust"]))

    def test_every_walked_file_is_cargo_relevant_or_mirrored(self):
        refs = read_set.referenced_paths(REPO, self.tracked, self.guarded)
        leaked = sorted(p for p in refs if cargo_skip.is_skippable(self.section, p))
        self.assertEqual(leaked, [], "skippable paths a Rust file or step reads: %s" % leaked[:20])

    def test_every_walk_guard_is_unskippable(self):
        """REVIEW-8328-code-r2 F3: the stand-in for a skipped Rust test is never skipped."""
        guards = cargo_skip.guard_paths(self.section)
        self.assertTrue(guards)
        for guard in guards:
            self.assertIn(guard, self.section["never_skip_globs"], guard)
            self.assertFalse(cargo_skip.is_skippable(self.section, guard), guard)
            got = cargo_skip.classify(self.section, [guard])
            self.assertEqual((got["docs_only"], got["cargo_skip"]), ("false", "false"), guard)
            got = cargo_skip.classify(self.section, [guard, "docs/ADMIN_GUIDE.md"])
            self.assertEqual((got["docs_only"], got["cargo_skip"]), ("false", "false"), guard)

    def test_a_derived_guard_is_unskippable_even_when_unlisted(self):
        section = json.loads(json.dumps(self.section))
        section["never_skip_globs"] = [g for g in section["never_skip_globs"]
                                       if "retired_alias" not in g]
        guard = section["walk_guards"][0]["guard"]
        self.assertTrue(cargo_skip.blocked(section, guard))
        self.assertFalse(cargo_skip.is_skippable(section, guard))

    def test_mirror_roots_cover_every_rust_root_for_skippable_notes(self):
        rust = (REPO / "tests" / "issue_3627_retired_llm_alias.rs").read_text()
        match = re.search(r"const SCANNED_ROOTS:[^=]*=\s*(.*?);\n", rust, re.S)
        rust_roots = re.findall(r'"([^"]+)"', match.group(1))
        mirrored = self.section["walk_guards"][0]["roots"]
        self.assertEqual(sorted(mirrored), sorted(rust_roots))
        for note in ("tools/x.md", "scripts/x.md"):
            self.assertTrue(read_set.under_any(note, mirrored), note)

    def test_conformance_tree_is_not_skippable(self):
        self.assertFalse(cargo_skip.is_skippable(self.section, "conformance/ROSETTA.md"))


class ForcedFullRuns(unittest.TestCase):
    """Code F2: push events and protected bases never skip."""

    @classmethod
    def setUpClass(cls):
        cls.section = cargo_skip.load_section()
        cls.tests_only = ["scripts/ci/tests/test_x.py"]

    def test_push_event_forces_false(self):
        labels = {"push": cargo_skip.REASON_EVENT, "merge_group": cargo_skip.REASON_MERGE_GROUP}
        for event, label in labels.items():
            got = cargo_skip.classify(self.section, ["docs/ADMIN_GUIDE.md"], event, "")
            self.assertEqual((got["docs_only"], got["cargo_skip"]), ("false", "false"), event)
            self.assertIn(label, got["cargo_skip_reason"])
        self.assertNotEqual(cargo_skip.REASON_EVENT, cargo_skip.REASON_MERGE_GROUP)

    def test_protected_base_ref_forces_false(self):
        for base in ("release/v1.0.0", "release/v2", "main", "develop"):
            got = cargo_skip.classify(self.section, self.tests_only, "pull_request", base)
            self.assertEqual(got["cargo_skip"], "false", base)
            self.assertIn(cargo_skip.REASON_BASE, got["cargo_skip_reason"])

    def test_chain_base_keeps_the_skip(self):
        got = cargo_skip.classify(self.section, self.tests_only, "pull_request", "chain/promo6-ssh-r2")
        self.assertEqual(got["cargo_skip"], "true")

    def test_cli_event_and_base_flags(self):
        rules = RULES.read_text()
        rc, out, _ = run_cli(rules, ["--event-name", "push"], "docs/ADMIN_GUIDE.md\n")
        self.assertEqual(rc, 0)
        self.assertIn("cargo_skip=false", out)
        self.assertIn("docs_only=false", out)
        rc, out, _ = run_cli(rules, ["--event-name", "pull_request", "--base-ref", "release/v1.0.0"],
                             "scripts/ci/tests/test_x.py\n")
        self.assertEqual(rc, 0)
        self.assertIn("cargo_skip=false", out)
        rc, out, _ = run_cli(rules, ["--event-name", "pull_request", "--base-ref", "chain/promo6-ssh-r2"],
                             "scripts/ci/tests/test_x.py\n")
        self.assertIn("cargo_skip=true", out)

    def test_full_ci_keys_match_the_selector_force_all_keys(self):
        data = json.loads(RULES.read_text())
        self.assertEqual(self.section["full_ci_base_names"], data["force_all_base_names"])
        self.assertEqual(self.section["full_ci_base_prefixes"], data["force_all_base_prefixes"])


class RulesShape(unittest.TestCase):
    """A structurally wrong rules.json is an error, not a silent verdict."""

    def assert_invalid(self, text):
        rc, out, err = run_cli(text, [])
        self.assertEqual(rc, 1, "stdout=%r stderr=%r" % (out, err))
        self.assertIn("invalid rules shape", err)
        self.assertNotIn("cargo_skip=", out)

    def test_null_rules_file(self):
        self.assert_invalid("null")

    def test_list_rules_file(self):
        self.assert_invalid("[]")

    def test_null_glob_list(self):
        data = json.loads(RULES.read_text())
        data["cargo_skip"]["never_skip_globs"] = None
        self.assert_invalid(json.dumps(data))

    def test_non_string_glob(self):
        data = json.loads(RULES.read_text())
        data["cargo_skip"]["skip_globs"] = ["docs/**", 7]
        self.assert_invalid(json.dumps(data))

    def test_malformed_walk_guards(self):
        data = json.loads(RULES.read_text())
        data["cargo_skip"]["walk_guards"] = [{"rust": "x.rs"}]
        self.assert_invalid(json.dumps(data))

    def test_missing_key_still_fails_closed_with_exit_zero(self):
        data = json.loads(RULES.read_text())
        del data["cargo_skip"]["never_skip_globs"]
        rc, out, _ = run_cli(json.dumps(data), [])
        self.assertEqual(rc, 0)
        self.assertIn("cargo_skip=false", out)


class RequiredContextsRuleB3(unittest.TestCase):
    """Rule b3 accepts only a real guard, not any mention of cargo_skip."""

    def test_reason_output_is_not_a_guard(self):
        work = scratch_dir()
        try:
            planted = work / "workflows"
            shutil.copytree(str(WORKFLOW_DIR), str(planted))
            ci = planted / "ci.yml"
            text = ci.read_text()
            self.assertIn("needs.classify.outputs.cargo_skip ", text)
            ci.write_text(text.replace("needs.classify.outputs.cargo_skip ",
                                       "needs.classify.outputs.cargo_skip_reason "))
            env = dict(os.environ, RQC_WORKFLOW_DIR=str(planted))
            res = subprocess.run(["bash", str(GATE)], cwd=str(REPO), env=env,
                                 capture_output=True, text=True, timeout=TIMEOUT_S)
        finally:
            shutil.rmtree(str(work), ignore_errors=True)
        self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("(b3)", res.stdout + res.stderr)

    def test_clean_tree_passes(self):
        res = subprocess.run(["bash", str(GATE)], cwd=str(REPO),
                             capture_output=True, text=True, timeout=TIMEOUT_S)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


if __name__ == "__main__":
    if sys.argv[1:] == ["consumer-check"]:
        sys.exit(consumer_check_main())
    unittest.main()
