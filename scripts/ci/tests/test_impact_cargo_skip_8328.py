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
        self.assertIn("test_impact|test_impact_count|test_impact_total", body)
        self.assertIn("impact-output-rejected-fail-closed", body)
        self.assertEqual(body.count('cat "$impact_out" >> "$GITHUB_OUTPUT"'), 1)


class ImpactStepOutputAllowList(unittest.TestCase):
    """Run the real `impact` step body against hostile selector output (#8338 class)."""

    OPENER = "<" + "<"
    SELECTED = ["test_impact=alpha_test beta_test", "test_impact_count=2",
                "test_impact_total=40", "test_impact_reason=impact-selected:2/40 (95%-skip)"]

    def run_step(self, selector_lines, docs_only="false", forced="", rc=0):
        """Run the step in a scratch repo; return (outputs dict, selector ran)."""
        work = scratch_dir()
        try:
            (work / "scripts").mkdir()
            script = work / "scripts" / "ci-test-impact.sh"
            ran = work / "selector-ran"
            body = ['#!/usr/bin/env bash', 'touch "%s"' % ran]
            body += ["printf '%%s\\n' '%s' >> \"$GITHUB_OUTPUT\"" % line for line in selector_lines]
            body += ['exit %d' % rc]
            script.write_text("\n".join(body) + "\n")
            out = work / "step-output"
            out.write_text("")
            env = dict(os.environ, GITHUB_OUTPUT=str(out), RUNNER_TEMP=str(work),
                       CLS_BASE="base", IMPACT_BASE="base", DOCS_ONLY=docs_only,
                       IMPACT_FORCED_REASON=forced)
            res = subprocess.run(["bash", "-e", "-c", step_by_id(CI_YML, "impact")[2]],
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
        _, _, stdout = self.run_step(self.SELECTED + ["::set-output name=x::y"])
        self.assertNotIn("\n::set-output", "\n" + stdout)


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
    unittest.main()
