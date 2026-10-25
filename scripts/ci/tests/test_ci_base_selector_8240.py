"""The `select` job judges a PR with the selector of its BASE sha (#8240, S2(b)).

decision: base-sha selector over PR-tree selector because a PR must not judge
itself; bootstrap and read failure select ALL (fail closed)

A pull request can edit scripts/ci/impact/select.py or rules.json. If the
select job ran the PR checkout's copy, such a PR could make the
`scripts/ci/**` -> ALL rule a no-op. The workflow therefore materialises the
selector files from the base sha into $RUNNER_TEMP/impact-base/ with an inline
step (the step text lives in ci.yml, so the PR cannot swap the helper) and runs
build_index.py and select.py from that copy against the PR tree's diff.

These tests pull the inline python out of ci.yml, run it against fixture
repositories, then run the materialised selector. No network, no cargo.
"""
import contextlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import unittest
import unittest.mock
from pathlib import Path

import gha_expr
import impact_fixture as fx
import workflow_text

CI_YML = fx.REPO_ROOT / ".github" / "workflows" / "ci.yml"
SELECT_JOB = "select"
GATE_JOB = "ci-gate"
MATERIALISE_STEP = "Materialise the base selector (#8240)"
FALLBACK_STEP = "Select the full matrix (base selector unavailable)"
GATE_MATERIALISE_STEP = "Materialise the base gate (#8240)"
BASE_DIR = "impact-base"
IMPACT_REL = "scripts/ci/impact"
SELECTOR_FILES = ("__init__.py", "common.py", "select.py", "build_index.py",
                  "gate.py", "rules.json")
HEREDOC_RE = re.compile(r"^python3 -I - <<'PY'\n(?P<body>.*)^PY\n\Z", re.S | re.M)
DECLARED_NON_DOMAIN_OUTPUTS = {"jobs", "all", "crates", "enforce"}
ENFORCE = "true"
WORKFLOW_DIR = fx.REPO_ROOT / ".github" / "workflows"
PR_WORKFLOWS = ("ci.yml", "ci-full.yml", "c8-precheck.yml")
BASE_SHA_MENTION_RE = re.compile(r"base\.sha|BASE_SHA", re.I)
ENV_LINE_RE = re.compile(r"^(?P<indent>\s+)(?P<key>[A-Z][A-Z0-9_]*):\s+(?P<value>\S.*?)\s*$")
EXPRESSION_RE = re.compile(r"^\$\{\{ .+ \}\}$")
SINGLE_BRACE_RE = re.compile(
    r"\$\{(?!\{)\s*(github|env|vars|secrets|inputs|needs|steps|matrix|runner)\.")
LEGACY_SINGLE_BRACE_RE = re.compile(r"\$\{\s")
BASE_EVENT_RE = re.compile(
    r"^\$\{\{ github\.event\.pull_request\.base\.sha( \|\| .+)? \}\}$")
LIVE_BASE_STEP = "Resolve the live base (#8240)"
LIVE_SUMMARY_STEP = "Name the live base in the summary"
RESOLVER_RE = re.compile(r"base_sha\.py")
CONTEXT_SHA_EXPR = "${{ github.sha }}"
HELPER = IMPACT_REL + "/base_sha.py"
BOOTSTRAP_STEP = "Fold job results (bootstrap, PR-tree gate)"
BASE_GATE_STEP = "Fold job results (base gate)"
BRANCH_TIP_STEP = "Fold job results (branch tip gate)"
FAIL_STEP = "Fail the gate (base gate unreadable)"
GATE_SCRIPT = IMPACT_REL + "/gate.py"
FAKE_SHA = "0123456789abcdef0123456789abcdef01234567"


def derived_env(base, head):
    """Event env under which the materialise step derives exactly `base` (merge_group form).

    `head` is the value of the `github.sha` context: the checked-out commit.
    """
    return {"EVENT_NAME": "merge_group", "HEAD_SHA": "", "MERGE_GROUP_BASE_SHA": base,
            "CONTEXT_SHA": head}


def step_named(job, name):
    """Return the step of `job` called `name`, or fail the test."""
    for step in workflow_text.read_steps(CI_YML, job):
        if step["name"] == name:
            return step
    raise AssertionError("step %r missing in job %s" % (name, job))


def snippet_of(step):
    """Return the inline python source of a `python3 -I - <<'PY'` step."""
    match = HEREDOC_RE.match(step["run"] or "")
    if match is None:
        raise AssertionError("step %r is not an inline python3 -I heredoc" % step["name"])
    return match.group("body")


def run_snippet(source, cwd, env_extra):
    """Run `source` with python -I in `cwd`; return (rc, output lines, summary)."""
    out = cwd.parent / "github_output.txt"
    summary = cwd.parent / "step_summary.md"
    for path in (out, summary):
        path.write_text("")
    env = {"PATH": os.environ["PATH"], "HOME": str(cwd.parent),
           "GITHUB_OUTPUT": str(out), "GITHUB_STEP_SUMMARY": str(summary),
           "RUNNER_TEMP": str(cwd.parent / "runner-temp")}
    env.update(env_extra)
    Path(env["RUNNER_TEMP"]).mkdir(exist_ok=True)
    res = subprocess.run([sys.executable, "-I", "-c", source], cwd=str(cwd), env=env,
                         capture_output=True, text=True, timeout=120)
    lines = dict(item.split("=", 1) for item in out.read_text().split("\n") if "=" in item)
    return res.returncode, lines, summary.read_text(), res


class BaseCase(unittest.TestCase):
    """A fixture repo whose base commit carries the real selector files."""

    def setUp(self):
        scratch = fx.make_scratch()
        self.addCleanup(scratch.cleanup)
        self.tmp = Path(scratch.name)
        self.repo = self.tmp / "repo"
        self.base = fx.init_repo(self.repo)
        self.dest = self.tmp / "runner-temp" / BASE_DIR

    def commit_selector(self, skip=()):
        """Commit the real selector files onto the fixture and return the sha."""
        files = {}
        for name in SELECTOR_FILES:
            if name not in skip:
                files["%s/%s" % (IMPACT_REL, name)] = (fx.IMPACT_DIR / name).read_text()
        return fx.commit_change(self.repo, files)

    def materialise(self, base, files=" ".join(SELECTOR_FILES), source=None):
        step = step_named(SELECT_JOB, MATERIALISE_STEP)
        head = fx.git(self.repo, "rev-parse", "HEAD")
        return run_snippet(source or snippet_of(step), self.repo,
                           dict(derived_env(base, head), IMPACT_FILES=files))


class WorkflowShape(unittest.TestCase):
    def test_select_job_materialises_before_it_builds_and_selects(self):
        names = [s["name"] for s in workflow_text.read_steps(CI_YML, SELECT_JOB)]
        self.assertIn(MATERIALISE_STEP, names)
        self.assertLess(names.index(MATERIALISE_STEP), names.index("Build impact index"))
        self.assertLess(names.index("Build impact index"), names.index("Select jobs"))

    def test_no_select_job_step_runs_the_pr_tree_selector(self):
        for step in workflow_text.read_steps(CI_YML, SELECT_JOB):
            run = step["run"] or ""
            with self.subTest(step=step["name"]):
                self.assertNotRegex(run, r"scripts/ci/impact/(select|build_index)\.py")

    def test_build_and_select_run_from_the_base_copy(self):
        for name, script in (("Build impact index", "build_index.py"),
                             ("Select jobs", "select.py")):
            step = step_named(SELECT_JOB, name)
            with self.subTest(step=name):
                self.assertIn('"$RUNNER_TEMP/%s/impact/%s"' % (BASE_DIR, script), step["run"])
                self.assertIn("steps.base.outputs.ok == 'true'", step["if"])

    def test_materialise_step_lists_the_selector_files(self):
        step = step_named(SELECT_JOB, MATERIALISE_STEP)
        listed = step["env"]["IMPACT_FILES"].split()
        self.assertEqual(sorted(listed), sorted(SELECTOR_FILES))
        self.assertEqual(step["id"], "base")

    def test_fallback_step_runs_when_the_base_copy_is_not_ok(self):
        step = step_named(SELECT_JOB, FALLBACK_STEP)
        self.assertEqual(step["if"],
                         "${{ !cancelled() && steps.base.outputs.ok != 'true' }}")

    def test_select_outputs_fall_back_to_the_full_matrix_step(self):
        outputs = workflow_text.read_jobs(CI_YML)[SELECT_JOB]["outputs"]
        for key, value in outputs.items():
            if key == "enforce":
                continue
            with self.subTest(output=key):
                self.assertIn("steps.select.outputs.%s" % key, value)
                self.assertIn("steps.fallback.outputs.%s" % key, value)

    def test_gate_job_runs_the_base_gate_when_available(self):
        materialise = step_named(GATE_JOB, GATE_MATERIALISE_STEP)
        self.assertEqual(materialise["id"], "base")
        runs = [s for s in workflow_text.read_steps(CI_YML, GATE_JOB)
                if s["run"] and "gate.py" in s["run"] and "<<'PY'" not in s["run"]
                and s["name"] != BRANCH_TIP_STEP]
        self.assertEqual(len(runs), 2)
        base_run = [s for s in runs if BASE_DIR in s["run"]]
        pr_run = [s for s in runs if BASE_DIR not in s["run"]]
        self.assertEqual(len(base_run), 1)
        self.assertEqual(len(pr_run), 1)
        self.assertIn("steps.base.outputs.ok == 'true'", base_run[0]["if"])
        self.assertEqual(pr_run[0]["if"],
                         "${{ !cancelled() && (github.event_name == 'pull_request' || "
                         "github.event_name == 'merge_group') && "
                         "steps.base.outputs.ok != 'true' "
                         "&& steps.base.outputs.bootstrap == 'true' }}")
        self.assertTrue(base_run[0]["if"].startswith("${{ !cancelled() &&"))

    def test_the_two_materialise_steps_share_one_source(self):
        select_src = snippet_of(step_named(SELECT_JOB, MATERIALISE_STEP))
        gate_src = snippet_of(step_named(GATE_JOB, GATE_MATERIALISE_STEP))
        self.assertEqual(select_src, gate_src)


class WorkflowExpressions(unittest.TestCase):
    """S7: a one-brace `${ ... }` is literal text, so the selector never saw its base sha."""

    def test_every_base_sha_env_value_is_a_well_formed_expression(self):
        for name in PR_WORKFLOWS:
            path = WORKFLOW_DIR / name
            for number, line in enumerate(path.read_text().split("\n"), 1):
                if line.lstrip().startswith("#"):
                    continue
                match = ENV_LINE_RE.match(line)
                if match is None or not BASE_SHA_MENTION_RE.search(match.group("value")):
                    continue
                with self.subTest(file=name, line=number):
                    self.assertRegex(
                        match.group("value"), EXPRESSION_RE,
                        "%s:%d %s is not a well-formed ${{ ... }} expression"
                        % (name, number, match.group("key")))

    def test_no_single_brace_expression_in_the_workflow_files_the_pr_touches(self):
        for name in PR_WORKFLOWS:
            path = WORKFLOW_DIR / name
            for number, line in enumerate(path.read_text().split("\n"), 1):
                with self.subTest(file=name, line=number):
                    self.assertIsNone(SINGLE_BRACE_RE.search(line),
                                      "%s:%d has a single-brace ${ expression" % (name, number))
                    self.assertIsNone(LEGACY_SINGLE_BRACE_RE.search(line),
                                      "%s:%d has a single-brace ${ expression" % (name, number))

    def test_both_materialise_steps_take_the_checked_out_sha_from_the_context(self):
        for job, step_name in ((SELECT_JOB, MATERIALISE_STEP),
                               (GATE_JOB, GATE_MATERIALISE_STEP)):
            with self.subTest(job=job):
                env = step_named(job, step_name)["env"]
                self.assertEqual(env["CONTEXT_SHA"], CONTEXT_SHA_EXPR)
                self.assertNotIn("BASE_SHA", env)

    def test_the_no_space_single_brace_form_is_flagged(self):
        for text in ("X: ${github.event.pull_request.head.sha || github.sha}",
                     "X: ${ github.event.before }", "X: ${env.FOO}",
                     "X: ${secrets.TOKEN}", "X: ${steps.base.outputs.ok}"):
            with self.subTest(text=text):
                self.assertTrue(SINGLE_BRACE_RE.search(text) or
                                LEGACY_SINGLE_BRACE_RE.search(text))
        for text in ("echo ${HOME}", 'echo "${GITHUB_ENV}"', "x=${y:-1}",
                     "X: ${{ github.sha }}"):
            with self.subTest(text=text):
                self.assertIsNone(SINGLE_BRACE_RE.search(text))
                self.assertIsNone(LEGACY_SINGLE_BRACE_RE.search(text))


class GateBaseRead(BaseCase):
    """S8: the PR-tree gate runs only when the base has no gate.py; any other read failure fails.

    decision: fail the gate on a non-bootstrap base read failure over falling
    back to the PR tree because a fallback the PR can trigger is self-judging;
    the select job already fails safe to the full matrix, the gate must fail
    closed
    """

    def gate_materialise(self, base, path=None):
        step = step_named(GATE_JOB, GATE_MATERIALISE_STEP)
        head = fx.git(self.repo, "rev-parse", "HEAD")
        env = dict(derived_env(base, head), IMPACT_FILES=step["env"]["IMPACT_FILES"])
        if path is not None:
            env["PATH"] = path
        return run_snippet(snippet_of(step), self.repo, env)

    def plan(self, lines):
        """Return the names of the gate steps whose `if:` holds after the materialise step."""
        context = {"github": {"event_name": "pull_request"},
                   "steps": {"base": {"outputs": lines}}}
        ran = []
        for step in workflow_text.read_steps(CI_YML, GATE_JOB):
            if step["uses"] or step["name"] == GATE_MATERIALISE_STEP:
                continue
            if step["if"] is None or gha_expr.evaluate_job_if(step["if"], context):
                ran.append(step["name"])
        return ran

    def failing_git(self, subcommand):
        """Return a PATH whose `git <subcommand>` exits 128 and whose other calls pass through."""
        real = shutil.which("git")
        wrapper_dir = self.tmp / "wrapbin"
        wrapper_dir.mkdir()
        wrapper = wrapper_dir / "git"
        wrapper.write_text("#!%s\nimport os\nimport sys\nif %r in sys.argv[1:3]:\n"
                           "    sys.exit(128)\nos.execv(%r, [%r] + sys.argv[1:])\n"
                           % (sys.executable, subcommand, real, real))
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        return str(wrapper_dir) + os.pathsep + os.environ["PATH"]

    def run_fail_step(self, reason):
        step = step_named(GATE_JOB, FAIL_STEP)
        summary = self.tmp / "fail_summary.md"
        summary.write_text("")
        env = {"PATH": os.environ["PATH"], "IMPACT_REASON": reason,
               "GITHUB_STEP_SUMMARY": str(summary)}
        res = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=str(self.repo), env=env,
                             capture_output=True, text=True, timeout=60)
        return res.returncode, summary.read_text()

    def assert_fails_closed(self, lines, summary):
        self.assertEqual(lines.get("ok"), "false", summary)
        self.assertNotEqual(lines.get("bootstrap"), "true", summary)
        ran = self.plan(lines)
        self.assertEqual(ran, [FAIL_STEP])
        self.assertNotIn(BOOTSTRAP_STEP, ran)
        code, text = self.run_fail_step(lines.get("reason", ""))
        self.assertNotEqual(code, 0)
        self.assertIn(lines["reason"], text)
        self.assertNotIn("full matrix", text)

    def test_a_base_without_gate_py_is_the_bootstrap_and_runs_the_pr_tree_gate(self):
        rc, lines, summary, res = self.gate_materialise(self.base)
        self.assertEqual(lines.get("ok"), "false", summary)
        self.assertEqual(lines.get("bootstrap"), "true", summary)
        self.assertEqual(self.plan(lines), [BOOTSTRAP_STEP])
        self.assertIn("bootstrap", summary)
        self.assertNotIn("full matrix", summary)
        run = step_named(GATE_JOB, BOOTSTRAP_STEP)["run"]
        self.assertIn(GATE_SCRIPT, run)
        self.assertNotIn(BASE_DIR, run)

    def test_a_base_with_other_files_but_no_gate_py_is_still_the_bootstrap(self):
        base = self.commit_selector(skip=("gate.py",))
        rc, lines, summary, res = self.gate_materialise(base)
        self.assertEqual(lines.get("bootstrap"), "true", summary)
        self.assertEqual(self.plan(lines), [BOOTSTRAP_STEP])

    def test_a_readable_base_runs_only_the_base_gate(self):
        base = self.commit_selector()
        rc, lines, summary, res = self.gate_materialise(base)
        self.assertEqual(lines.get("ok"), "true", summary)
        self.assertEqual(self.plan(lines), [BASE_GATE_STEP])

    def test_a_failing_git_show_of_a_present_gate_py_fails_the_gate(self):
        base = self.commit_selector()
        rc, lines, summary, res = self.gate_materialise(base, self.failing_git("show"))
        self.assert_fails_closed(lines, summary)

    def test_a_failing_ls_tree_fails_the_gate(self):
        base = self.commit_selector()
        rc, lines, summary, res = self.gate_materialise(base, self.failing_git("ls-tree"))
        self.assert_fails_closed(lines, summary)

    def test_a_missing_non_gate_file_with_gate_py_present_fails_the_gate(self):
        base = self.commit_selector(skip=("rules.json",))
        rc, lines, summary, res = self.gate_materialise(base)
        self.assert_fails_closed(lines, summary)

    def test_an_unfetchable_base_sha_fails_the_gate(self):
        self.commit_selector()
        rc, lines, summary, res = self.gate_materialise(FAKE_SHA)
        self.assert_fails_closed(lines, summary)

    def test_an_invalid_base_sha_fails_the_gate(self):
        self.commit_selector()
        for bad in ("", "--upload-pack=x", "main", FAKE_SHA.upper()):
            with self.subTest(sha=bad):
                rc, lines, summary, res = self.gate_materialise(bad)
                self.assert_fails_closed(lines, summary)
                self.assertEqual(lines["reason"], "base-sha-invalid")

    def test_the_pr_tree_gate_step_runs_only_on_the_bootstrap_output(self):
        step = step_named(GATE_JOB, BOOTSTRAP_STEP)
        self.assertIn("steps.base.outputs.bootstrap == 'true'", step["if"])
        self.assertTrue(step["if"].startswith("${{ !cancelled() &&"))


class BaseSelectorIgnoresPrHelpers(BaseCase):
    """S9: a base selector must not import helpers from the PR tree it is judging."""

    MARKER = "PR_TREE_HELPER_IMPORTED"

    def argv_of(self, step_name, env):
        """Return the step's command exactly as ci.yml writes it, variables expanded."""
        run = step_named(SELECT_JOB, step_name)["run"].replace("\\\n", " ")
        words = shlex.split(re.sub(r"\$(\w+)", lambda m: env[m.group(1)], run))
        self.assertEqual(words[0], "python3")
        words[0] = sys.executable
        self.assertIn("-I", words[1:3], "%s must run with python3 -I" % step_name)
        return words

    def env_of(self, step_name, base_env, step_env):
        """Return the process env the runner builds: the step's REAL `env:` block applied.

        Literal values are used as written; `${{ ... }}` values come from `step_env`
        (the test's stand-in for the expression context, keyed by variable name).
        """
        env = dict(base_env)
        for key, value in step_named(SELECT_JOB, step_name)["env"].items():
            self.assertFalse(key.upper().startswith("PYTHON"),
                             "step %r sets %s, which redirects imports" % (step_name, key))
            env[key] = step_env[key] if value.startswith("${{") else value
        return env

    def test_the_base_selector_never_imports_a_pr_tree_helper(self):
        base = self.commit_selector()
        sentinel = ((fx.IMPACT_DIR / "common.py").read_text()
                    + "\nopen(%r, 'w').write('imported')\n" % self.MARKER)
        head = fx.commit_change(self.repo, {"%s/common.py" % IMPACT_REL: sentinel,
                                            "crates/core/src/lib.rs": "// changed\n"})
        rc, lines, summary, res = self.materialise(base)
        self.assertEqual(lines.get("ok"), "true", summary)
        marker = self.repo / self.MARKER
        env = {"PATH": os.environ["PATH"], "HOME": str(self.tmp)}
        pr_run = subprocess.run(
            [sys.executable, "-I", str(self.repo / IMPACT_REL / "select.py"),
             "--db", str(self.tmp / "none.db"), "--repo", ".", "--base", base, "--head", head],
            cwd=str(self.repo), env=env, capture_output=True, text=True, timeout=120)
        self.assertTrue(marker.exists(), "control: the PR-tree helper was not imported\n"
                        + pr_run.stderr)
        marker.unlink()
        out = self.tmp / "selected.txt"
        out.write_text("")
        metadata = self.tmp / "metadata.json"
        metadata.write_text(json.dumps(fx.make_metadata(self.repo)))
        step_env = {"RUNNER_TEMP": str(self.tmp / "runner-temp"), "BASE_SHA": base,
                    "HEAD_SHA": head, "EVENT": "pull_request", "BASE_REF": "main",
                    "ENFORCE": ENFORCE, "GITHUB_OUTPUT": str(out)}
        build = self.argv_of("Build impact index", step_env) + ["--metadata-file", str(metadata)]
        select = self.argv_of("Select jobs", step_env)
        for name, argv in (("Build impact index", build), ("Select jobs", select)):
            done = subprocess.run(argv, cwd=str(self.repo), capture_output=True,
                                  env=self.env_of(name, env, step_env),
                                  text=True, timeout=120)
            self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse(marker.exists(), "the base selector imported a PR-tree helper")
        selected = dict(item.split("=", 1) for item in out.read_text().split("\n") if "=" in item)
        self.assertEqual(selected["all"], "true")


class BaseSelectorBeatsPrSelector(BaseCase):
    """The self-judging PR: its select.py selects nothing, the base copy does not."""

    STUB = ("import sys\n"
            "out = sys.argv[sys.argv.index('--github-output') + 1]\n"
            "open(out, 'a').write('all=false\\njobs=\\ncrates=\\nrust=false\\n"
            "cells=false\\nactionlint=false\\n')\n")

    def run_selector(self, script, head):
        metadata = self.tmp / "metadata.json"
        metadata.write_text(json.dumps(fx.make_metadata(self.repo)))
        db = self.tmp / ("impact-%s.db" % script.parent.name)
        env = {"PATH": os.environ["PATH"], "HOME": str(self.tmp)}
        out = self.tmp / ("out-%s.txt" % script.parent.name)
        out.write_text("")
        if (script.parent / "build_index.py").exists():
            subprocess.run([sys.executable, "-I", str(script.parent / "build_index.py"),
                            "--repo", str(self.repo), "--db", str(db),
                            "--metadata-file", str(metadata)],
                           cwd=str(self.repo), env=env, check=True,
                           capture_output=True, text=True, timeout=120)
        subprocess.run([sys.executable, "-I", str(script), "--db", str(db),
                        "--repo", str(self.repo), "--base", self.base, "--head", head,
                        "--event", "pull_request", "--enforce", ENFORCE,
                        "--github-output", str(out)],
                       cwd=str(self.repo), env=env, check=True,
                       capture_output=True, text=True, timeout=120)
        return dict(item.split("=", 1) for item in out.read_text().split("\n") if "=" in item)

    def test_pr_rewriting_select_py_cannot_narrow_the_selection(self):
        base = self.commit_selector()
        self.base = base
        head = fx.commit_change(self.repo, {
            "%s/select.py" % IMPACT_REL: self.STUB,
            "crates/core/src/lib.rs": "// changed\n"})
        rc, lines, summary, res = self.materialise(base)
        self.assertEqual(rc, 0, res.stderr)
        self.assertEqual(lines.get("ok"), "true", summary)
        pr_tree = self.run_selector(self.repo / IMPACT_REL / "select.py", head)
        self.assertEqual(pr_tree["all"], "false")
        self.assertEqual(pr_tree["rust"], "false")
        from_base = self.run_selector(self.dest / "impact" / "select.py", head)
        self.assertEqual(from_base["all"], "true")
        for domain in ("rust", "cells", "actionlint"):
            with self.subTest(domain=domain):
                self.assertEqual(from_base[domain], "true")

    def test_materialised_files_equal_the_base_blobs_not_the_pr_files(self):
        base = self.commit_selector()
        fx.commit_change(self.repo, {"%s/select.py" % IMPACT_REL: self.STUB})
        rc, lines, summary, res = self.materialise(base)
        self.assertEqual(lines.get("ok"), "true", summary)
        self.assertEqual((self.dest / "impact" / "select.py").read_text(),
                         (fx.IMPACT_DIR / "select.py").read_text())
        for name in SELECTOR_FILES:
            with self.subTest(file=name):
                self.assertTrue((self.dest / "impact" / name).is_file())


class FailClosed(BaseCase):
    def assert_closed(self, base, files=" ".join(SELECTOR_FILES), source=None):
        rc, lines, summary, res = self.materialise(base, files, source)
        self.assertEqual(rc, 0, res.stderr)
        self.assertEqual(lines.get("ok"), "false", summary)
        self.assertIn("impact: base files unavailable", summary)
        self.assertNotIn("full matrix", summary)
        self.assertFalse(self.dest.exists(), "partial base copy left behind")
        return summary

    def test_bootstrap_base_without_the_files_selects_all(self):
        summary = self.assert_closed(self.base)
        self.assertIn("base-file-missing:__init__.py", summary)

    def test_one_missing_file_selects_all_and_leaves_no_copy(self):
        base = self.commit_selector(skip=("gate.py",))
        summary = self.assert_closed(base)
        self.assertIn("base-file-missing:gate.py", summary)

    def test_empty_file_list_selects_all(self):
        base = self.commit_selector()
        rc, lines, summary, res = self.materialise(base, files="")
        self.assertEqual(lines.get("ok"), "false", summary)
        self.assertIn("no-files-listed", summary)

    def test_unknown_sha_selects_all(self):
        self.assert_closed(FAKE_SHA)

    def test_malformed_sha_selects_all(self):
        for bad in ("", "--upload-pack=x", "main", FAKE_SHA.upper(), FAKE_SHA + "0"):
            with self.subTest(sha=bad):
                summary = self.assert_closed(bad)
                self.assertIn("base-sha-invalid", summary)

    def test_symlinked_base_file_is_refused(self):
        self.commit_selector()
        target = self.repo / IMPACT_REL / "select.py"
        target.unlink()
        target.symlink_to("common.py")
        fx.git(self.repo, "add", "-A")
        fx.git(self.repo, "commit", "-q", "-m", "link")
        base = fx.git(self.repo, "rev-parse", "HEAD")
        summary = self.assert_closed(base)
        self.assertIn("base-file-not-regular:select.py", summary)

    def test_symlink_at_the_destination_is_refused(self):
        base = self.commit_selector()
        self.dest.parent.mkdir(parents=True, exist_ok=True)
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        self.dest.symlink_to(elsewhere)
        rc, lines, summary, res = self.materialise(base)
        self.assertEqual(lines.get("ok"), "false", summary)
        self.assertIn("dest-unsafe", summary)
        self.assertEqual(list(elsewhere.iterdir()), [], "wrote through the symlink")

    def test_dangling_symlink_at_the_destination_is_refused(self):
        base = self.commit_selector()
        self.dest.parent.mkdir(parents=True, exist_ok=True)
        self.dest.symlink_to(self.tmp / "does-not-exist")
        rc, lines, summary, res = self.materialise(base)
        self.assertEqual(lines.get("ok"), "false", summary)
        self.assertIn("dest-unsafe", summary)

    def test_write_failure_midway_removes_the_partial_copy(self):
        base = self.commit_selector()
        source = snippet_of(step_named(SELECT_JOB, MATERIALISE_STEP))
        namespace = {"__name__": "snippet"}
        exec(compile(source, "materialise", "exec"), namespace)
        calls = {"n": 0}
        real = Path.write_bytes

        def flaky(path, data):
            calls["n"] += 1
            if calls["n"] == 3:
                raise OSError(28, "No space left on device")
            return real(path, data)

        env = dict(derived_env(base, fx.git(self.repo, "rev-parse", "HEAD")),
                   IMPACT_FILES=" ".join(SELECTOR_FILES),
                   RUNNER_TEMP=str(self.tmp / "runner-temp"),
                   GITHUB_OUTPUT=str(self.tmp / "go.txt"),
                   GITHUB_STEP_SUMMARY=str(self.tmp / "gs.md"))
        (self.tmp / "runner-temp").mkdir()
        cwd = os.getcwd()
        os.chdir(str(self.repo))
        try:
            with unittest.mock.patch.dict(os.environ, env), \
                    unittest.mock.patch.object(Path, "write_bytes", flaky), \
                    contextlib.redirect_stdout(io.StringIO()):
                namespace["main"]()
        finally:
            os.chdir(cwd)
        self.assertFalse(self.dest.exists(), "partial copy survived ENOSPC")
        self.assertIn("ok=false", (self.tmp / "go.txt").read_text())
        self.assertIn("write-failed", (self.tmp / "gs.md").read_text())

    def test_summary_names_no_environment_value(self):
        summary = self.assert_closed("--upload-pack=secret-value-xyz")
        self.assertNotIn("secret-value-xyz", summary)


class FallbackStep(unittest.TestCase):
    """The `fallback` step is what the select job reports when the copy is unusable."""

    def test_fallback_selects_every_declared_domain(self):
        scratch = fx.make_scratch()
        self.addCleanup(scratch.cleanup)
        cwd = Path(scratch.name) / "work"
        cwd.mkdir()
        step = step_named(SELECT_JOB, FALLBACK_STEP)
        rc, lines, summary, res = run_snippet(snippet_of(step), cwd, {})
        self.assertEqual(rc, 0, res.stderr)
        self.assertEqual(step["id"], "fallback")
        self.assertEqual(lines["all"], "true")
        self.assertIn("selecting the full matrix", summary)
        outputs =workflow_text.read_jobs(CI_YML)[SELECT_JOB]["outputs"]
        domains = set(outputs) - DECLARED_NON_DOMAIN_OUTPUTS
        self.assertEqual(domains, {"rust", "cells", "actionlint"})
        for domain in domains:
            with self.subTest(domain=domain):
                self.assertEqual(lines[domain], "true")
        self.assertNotIn("false", lines.values())


class LiveBase(BaseCase):
    """R3-F10: the base is the live one, never the frozen pull_request.base.sha.

    decision: the live base is the first parent of the pull_request merge ref
    and merge_group.base_sha over pull_request.base.sha because base.sha is
    frozen at PR-open time and github.sha on merge_group contains the PR
    """

    def build(self):
        """main: c0 -> c1 (later base); pr: c0 -> p1; merge M = c1 + p1 on HEAD."""
        c0 = self.base
        git = lambda *a: fx.git(self.repo, *a)
        git("checkout", "-q", "-b", "pr")
        p1 = fx.commit_change(self.repo, {"pr.txt": "pr\n"})
        git("checkout", "-q", "main")
        c1 = fx.commit_change(self.repo, {"later.txt": "later\n"})
        git("checkout", "-q", "-b", "merge-ref")
        git("merge", "-q", "--no-ff", "-m", "merge", "pr")
        merge = git("rev-parse", "HEAD")
        git("update-ref", "refs/remotes/origin/main", c1)
        return c0, c1, p1, merge

    def run_helper(self, env_extra):
        out_path = self.tmp / "gh_out.txt"
        out_path.write_text("")
        env = {"PATH": os.environ["PATH"], "HOME": str(self.tmp)}
        env.update(env_extra)
        res = subprocess.run([sys.executable, "-I", str(fx.IMPACT_DIR / "base_sha.py"),
                              "--repo", str(self.repo), "--github-output", str(out_path)],
                             env=env, capture_output=True, text=True, timeout=120)
        out = dict(i.split("=", 1) for i in out_path.read_text().split("\n") if "=" in i)
        return res.returncode, out, res

    def test_pull_request_uses_the_first_parent_not_the_frozen_base_sha(self):
        c0, c1, p1, merge = self.build()
        rc, out, res = self.run_helper({
            "EVENT_NAME": "pull_request", "HEAD_SHA": p1, "BASE_REF": "main",
            "PR_BASE_SHA": c0, "GITHUB_SHA": merge})
        self.assertEqual(rc, 0, res.stderr)
        self.assertEqual(out["sha"], c1)
        self.assertNotEqual(out["sha"], c0)
        self.assertEqual(out["reason"], "live-base-first-parent")
        self.assertEqual(res.stdout.split()[0], "sha=" + c1)

    def test_merge_group_uses_the_event_base_sha_never_github_sha(self):
        c0, c1, p1, merge = self.build()
        rc, out, res = self.run_helper({
            "EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": c1,
            "HEAD_SHA": merge, "BASE_REF": "refs/heads/main", "GITHUB_SHA": merge})
        self.assertEqual(rc, 0, res.stderr)
        self.assertEqual(out["sha"], c1)
        self.assertNotEqual(out["sha"], merge)
        self.assertEqual(out["reason"], "live-base-merge-group")

    def test_a_base_that_contains_the_head_is_refused(self):
        c0, c1, p1, merge = self.build()
        rc, out, res = self.run_helper({
            "EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": merge,
            "HEAD_SHA": p1, "BASE_REF": "main"})
        self.assertNotEqual(rc, 0)
        self.assertEqual(out["reason"], "base-contains-head")
        self.assertEqual(out["sha"], "")

    def test_a_base_not_on_the_base_ref_is_refused(self):
        c0, c1, p1, merge = self.build()
        rc, out, res = self.run_helper({
            "EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": p1,
            "HEAD_SHA": merge, "BASE_REF": "main"})
        self.assertNotEqual(rc, 0)
        self.assertEqual(out["reason"], "base-not-on-base-ref")
        self.assertEqual(out["sha"], "")

    def test_an_unsupported_event_fails_closed(self):
        c0, c1, p1, merge = self.build()
        for event in ("push", "workflow_dispatch", "schedule", ""):
            with self.subTest(event=event):
                rc, out, res = self.run_helper({
                    "EVENT_NAME": event, "HEAD_SHA": merge, "BASE_REF": "main",
                    "MERGE_GROUP_BASE_SHA": c1, "GITHUB_SHA": merge})
                self.assertNotEqual(rc, 0)
                self.assertEqual(out["reason"], "base-event-unsupported")
                self.assertEqual(out["sha"], "")

    def test_malformed_inputs_fail_closed(self):
        c0, c1, p1, merge = self.build()
        cases = (
            ({"EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": "--oops",
              "HEAD_SHA": merge, "BASE_REF": "main"}, "base-sha-invalid"),
            ({"EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": c1,
              "HEAD_SHA": "zz", "BASE_REF": "main"}, "head-sha-invalid"),
            ({"EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": c1,
              "HEAD_SHA": merge, "BASE_REF": "../x"}, "base-ref-invalid"),
            ({"EVENT_NAME": "pull_request", "HEAD_SHA": c0, "BASE_REF": "main"},
             "merge-ref-unexpected"),
        )
        for env, reason in cases:
            with self.subTest(reason=reason):
                rc, out, res = self.run_helper(env)
                self.assertNotEqual(rc, 0)
                self.assertEqual(out["reason"], reason)
                self.assertEqual(out["sha"], "")


class TrustDecisionFirst(unittest.TestCase):
    """S15: the trust decision runs before any checkout file executes.

    decision: the trust decision runs before any checkout file executes and the
    resolver is demoted to a post-derivation report over keeping the resolver
    step first because any PR-tree step that runs earlier in the job can rewrite
    the git state and PATH the derivation reads

    The base_sha.py resolver is wired into no step of either job: the inline
    derivation is the sole authority. The bootstrap fold and the branch-tip fold
    are the only steps that run a scripts/ci/ path from the checkout, and both
    run after the derivation (the branch-tip fold only on events with no live
    base).
    """

    JOBS = ((SELECT_JOB, MATERIALISE_STEP), (GATE_JOB, GATE_MATERIALISE_STEP))
    CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
    NAMED_EXCEPTIONS = (BOOTSTRAP_STEP, BRANCH_TIP_STEP)

    # F4 / S16: an ALLOW-LIST of the steps that may run before the first step
    # that executes checkout content after the fold. Anything not listed here
    # (a `run:`, another `uses:`, a `shell:` or `working-directory:` override,
    # an `env:` key that alters shell start-up) is red until it is allow-listed.
    # decision: an allow-list of pre-trust steps and an explicit grafts,
    # replace, shallow and alternates refusal over a forbid-list and a comment
    # because every git state the runner can carry into the derivation is
    # refused by name and any new pre-trust step is red until it is allow-listed
    CHECKOUT_USES = CHECKOUT + " # v4"
    ECHO_RUN = 'echo "enforce=${ENFORCE}" >> "$GITHUB_OUTPUT"'
    INDEX_RUN = ('python3 -I "$RUNNER_TEMP/impact-base/impact/build_index.py"'
                 ' --repo . --db "$RUNNER_TEMP/impact.db"')
    BASE_FOLD_RUN = ('python3 -I "$RUNNER_TEMP/impact-base/impact/gate.py"'
                     ' --needs "$NEEDS_JSON" \\\n  --github-ref "$GITHUB_REF_NAME_FULL"\n')
    FORBIDDEN_ENV_RE = re.compile(
        r"^(BASH_ENV|ENV|SHELLOPTS|BASHOPTS|PATH|LD_PRELOAD|LD_LIBRARY_PATH|GIT_.*|PYTHON.*"
        r"|NODE_OPTIONS|RUNNER_TEMP|GITHUB_(PATH|ENV|OUTPUT))$")
    HEREDOC = object()
    # (name, exact top-level keys, exact env keys, exact `with:` mapping, exact run text)
    SELECT_ALLOW = (
        (None, {"uses", "with"}, set(), {"fetch-depth": "0"}, None),
        ("Selection mode", {"name", "id", "env", "run"}, {"ENFORCE"}, None, ECHO_RUN),
        (MATERIALISE_STEP, {"name", "id", "env", "run"},
         {"CONTEXT_SHA", "EVENT_NAME", "HEAD_SHA", "MERGE_GROUP_BASE_SHA", "IMPACT_FILES"},
         None, HEREDOC),
        ("Build impact index", {"name", "if", "continue-on-error", "run"}, set(), None,
         INDEX_RUN),
    )
    GATE_ALLOW = (
        (None, {"uses", "with"}, set(), {"fetch-depth": "0"}, None),
        (GATE_MATERIALISE_STEP, {"name", "id", "if", "env", "run"},
         {"CONTEXT_SHA", "EVENT_NAME", "HEAD_SHA", "MERGE_GROUP_BASE_SHA", "IMPACT_FILES"},
         None, HEREDOC),
        (BASE_GATE_STEP, {"name", "if", "env", "run"}, {"NEEDS_JSON", "GITHUB_REF_NAME_FULL"},
         None, BASE_FOLD_RUN),
    )
    # job -> (allow-list, first step that may execute checkout content)
    WINDOWS = {SELECT_JOB: (SELECT_ALLOW, "Select jobs"),
               GATE_JOB: (GATE_ALLOW, BOOTSTRAP_STEP)}

    RAW_KEY_RE = re.compile(r"^(?: {6}- | {8})([A-Za-z0-9_-]+):[ \t]*(.*)$")
    RAW_SUB_RE = re.compile(r"^ {10}([A-Za-z0-9_.-]+):[ \t]*(.*)$")

    def raw_steps(self, job):
        """Every step of `job` with ALL its top-level keys and its env/with mappings."""
        steps = []
        in_job = in_steps = False
        current = None
        for line in CI_YML.read_text().split("\n"):
            job_match = workflow_text.JOB_ID_RE.match(line)
            if job_match:
                in_job, in_steps = job_match.group(1) == job, False
                continue
            if not in_job:
                continue
            if line == "    steps:":
                in_steps = True
                continue
            if not in_steps:
                continue
            if line.startswith("      - "):
                steps.append({"keys": {}, "env": {}, "with": {}})
                current = None
            elif not steps:
                continue
            key = self.RAW_KEY_RE.match(line)
            if key:
                current = key.group(1)
                steps[-1]["keys"][current] = key.group(2).strip()
                continue
            sub = self.RAW_SUB_RE.match(line)
            if sub and current in ("env", "with"):
                steps[-1][current][sub.group(1)] = sub.group(2).strip()
        parsed = workflow_text.read_steps(CI_YML, job)
        self.assertEqual(len(parsed), len(steps), job)
        for raw, step in zip(steps, parsed):
            raw["name"], raw["run"] = step["name"], step["run"]
        return steps

    def window(self, job):
        steps = self.raw_steps(job)
        names = [s["name"] for s in steps]
        return steps[:names.index(self.WINDOWS[job][1])]

    def assert_step_allowed(self, step, entry):
        name, keys, env_keys, with_map, run = entry
        self.assertEqual(step["name"], name)
        self.assertEqual(set(step["keys"]), keys, "step %r keys" % name)
        self.assertEqual(set(step["env"]), env_keys, "step %r env" % name)
        for env_key in step["env"]:
            self.assertIsNone(self.FORBIDDEN_ENV_RE.match(env_key),
                              "step %r sets %s" % (name, env_key))
        for banned in ("shell", "working-directory", "submodules", "path", "ref",
                       "repository", "persist-credentials"):
            self.assertNotIn(banned, step["keys"])
            self.assertNotIn(banned, step["with"])
        if name is None:
            self.assertEqual(step["keys"]["uses"], self.CHECKOUT_USES)
            self.assertEqual(step["with"], with_map)
            self.assertIsNone(step["run"])
            return
        self.assertNotIn("uses", step["keys"])
        if run is self.HEREDOC:
            self.assertIsNotNone(HEREDOC_RE.match(step["run"] or ""), name)
        else:
            self.assertEqual(step["run"], run, name)

    def test_the_pre_trust_window_is_an_exact_allow_list_of_steps(self):
        for job in (SELECT_JOB, GATE_JOB):
            allow = self.WINDOWS[job][0]
            steps = self.window(job)
            with self.subTest(job=job):
                self.assertEqual([s["name"] for s in steps], [a[0] for a in allow])
            for step, entry in zip(steps, allow):
                with self.subTest(job=job, step=entry[0]):
                    self.assert_step_allowed(step, entry)

    def test_the_only_action_before_the_trust_decision_is_the_pinned_checkout(self):
        for job in (SELECT_JOB, GATE_JOB):
            uses = [s["keys"]["uses"] for s in self.window(job) if "uses" in s["keys"]]
            with self.subTest(job=job):
                self.assertEqual(uses, [self.CHECKOUT_USES])

    def test_no_job_level_override_can_alter_the_shell_or_the_start_up_env(self):
        """S16: shell, working-directory, defaults and poisoned env anywhere in either job."""
        for job in (SELECT_JOB, GATE_JOB):
            for step in self.raw_steps(job):
                with self.subTest(job=job, step=step["name"]):
                    self.assertNotIn("shell", step["keys"])
                    self.assertNotIn("working-directory", step["keys"])
                    for env_key in step["env"]:
                        self.assertIsNone(self.FORBIDDEN_ENV_RE.match(env_key), env_key)
            block = []
            in_job = False
            for line in CI_YML.read_text().split("\n"):
                job_match = workflow_text.JOB_ID_RE.match(line)
                if job_match:
                    in_job = job_match.group(1) == job
                    continue
                if in_job:
                    block.append(line)
            with self.subTest(job=job, scope="job"):
                text = "\n".join(block)
                self.assertIsNone(re.search(r"^\s*(shell|working-directory|defaults):", text, re.M))
                for line in text.split("\n"):
                    if re.match(r"^ {6}[A-Z_]+:", line):
                        self.assertIsNone(self.FORBIDDEN_ENV_RE.match(line.strip().split(":")[0]))

    def test_no_step_runs_before_the_fold_on_a_live_event_except_the_decision(self):
        """Every step that runs on pull_request or merge_group ahead of the first fold."""
        for event in LIVE_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                names = [s["name"] for s in ran]
                first_fold = min(i for i, n in enumerate(names)
                                 if (n or "").startswith(("Fold job results", "Fail the gate")))
                for step in ran[:first_fold]:
                    with self.subTest(event=event, outputs=outputs, step=step["name"]):
                        allowed = [entry[0] for entry in self.GATE_ALLOW]
                        self.assertIn(step["name"], allowed)

    def test_the_resolver_is_wired_into_no_step_of_either_job(self):
        for job in (SELECT_JOB, GATE_JOB):
            for step in workflow_text.read_steps(CI_YML, job):
                with self.subTest(job=job, step=step["name"]):
                    self.assertNotEqual(step["name"], LIVE_BASE_STEP)
                    self.assertNotEqual(step["id"], "live")
                    self.assertIsNone(RESOLVER_RE.search(step["run"] or ""))
                    self.assertNotIn("steps.live", " ".join(step["env"].values()))
                    self.assertNotIn("steps.live", step["if"] or "")

    def test_a_scripts_ci_path_runs_only_in_the_named_exception_steps(self):
        select_steps = workflow_text.read_steps(CI_YML, SELECT_JOB)
        for step in select_steps:
            with self.subTest(job=SELECT_JOB, step=step["name"]):
                if step["name"] == MATERIALISE_STEP:
                    continue
                self.assertNotIn("scripts/ci/", step["run"] or "")
        for step in workflow_text.read_steps(CI_YML, GATE_JOB):
            with self.subTest(job=GATE_JOB, step=step["name"]):
                if step["name"] == GATE_MATERIALISE_STEP:
                    continue
                if "scripts/ci/" in (step["run"] or ""):
                    self.assertIn(step["name"], self.NAMED_EXCEPTIONS)

    def test_the_named_exception_folds_cannot_run_before_the_derivation(self):
        names = [s["name"] for s in workflow_text.read_steps(CI_YML, GATE_JOB)]
        self.assertLess(names.index(GATE_MATERIALISE_STEP), names.index(BOOTSTRAP_STEP))
        self.assertLess(names.index(GATE_MATERIALISE_STEP), names.index(BRANCH_TIP_STEP))

    def test_the_materialise_steps_execute_only_git(self):
        for job, name in self.JOBS:
            source = snippet_of(step_named(job, name))
            with self.subTest(job=job):
                self.assertEqual(source.count("subprocess.run("), 1)
                self.assertIn('["git", "--no-replace-objects"]', source)
                self.assertNotIn("os.system", source)
                self.assertNotIn("shell=True", source)
                self.assertNotIn("import_module", source)

    def test_the_derivation_reads_the_github_sha_context_never_head(self):
        for job, name in self.JOBS:
            step = step_named(job, name)
            source = snippet_of(step)
            with self.subTest(job=job):
                self.assertEqual(step["env"]["CONTEXT_SHA"], CONTEXT_SHA_EXPR)
                self.assertNotIn("HEAD^1", source)
                self.assertNotIn("HEAD^2", source)
                self.assertIn('env.get("CONTEXT_SHA"', source)
                self.assertNotIn("HEAD", step["env"]["CONTEXT_SHA"])

    def test_no_run_line_of_either_job_interpolates_an_expression(self):
        for job in (SELECT_JOB, GATE_JOB):
            for step in workflow_text.read_steps(CI_YML, job):
                with self.subTest(job=job, step=step["name"]):
                    self.assertNotIn("${{", step["run"] or "")

    LIBRARY_NOTE = ("base_sha.py is a library kept for the unit tests that pin its behaviour;"
                    " no workflow step runs it.")
    SELECT_ORDER_NOTE = ("Only the pinned checkout action and the echo-only Selection mode"
                         " step run before this step;")
    GATE_ORDER_NOTE = "Only the pinned checkout action runs before this step;"

    def test_no_run_line_of_any_workflow_invokes_base_sha_py(self):
        """F5: the resolver is a library; a `run:` line (or any non-comment line) naming it is red."""
        for name in PR_WORKFLOWS:
            for number, line in enumerate((WORKFLOW_DIR / name).read_text().split("\n"), 1):
                with self.subTest(workflow=name, line=number):
                    if not line.lstrip().startswith("#"):
                        self.assertNotIn("base_sha.py", line)

    def test_the_comments_and_the_docstring_state_the_step_order_as_it_is(self):
        text = CI_YML.read_text()
        self.assertEqual(text.count(self.LIBRARY_NOTE), 2)
        self.assertEqual(text.count(self.SELECT_ORDER_NOTE), 1)
        self.assertEqual(text.count(self.GATE_ORDER_NOTE), 1)
        doc = (fx.IMPACT_DIR / "base_sha.py").read_text().split('"""')[1]
        self.assertNotIn("run this one script", doc)
        self.assertIn("library", doc)
        self.assertIn("no workflow step runs it", " ".join(doc.split()))

    def test_the_stale_chain_push_wording_is_gone_from_the_workflow(self):
        text = CI_YML.read_text()
        self.assertEqual(text.count("every chain push"), 0)
        self.assertEqual(text.count("nightly full run can"), 0)
        self.assertIn("red on every release/** push and workflow_dispatch full run", text)


class GitHardening(BaseCase):
    """S15: every git call of the materialise steps ignores replace objects."""

    def recording_path(self):
        log = self.tmp / "git-calls.jsonl"
        log.write_text("")
        wrapper_dir = self.tmp / "recbin"
        shutil.rmtree(str(wrapper_dir), ignore_errors=True)
        wrapper_dir.mkdir()
        wrapper = wrapper_dir / "git"
        real = shutil.which("git")
        wrapper.write_text(
            "#!%s\nimport json\nimport os\nimport sys\n"
            "with open(%r, 'a') as handle:\n"
            "    handle.write(json.dumps([os.environ.get('GIT_NO_REPLACE_OBJECTS'),"
            " sys.argv[1:]]) + '\\n')\n"
            "os.execv(%r, [%r] + sys.argv[1:])\n" % (sys.executable, str(log), real, real))
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        return log, str(wrapper_dir) + os.pathsep + os.environ["PATH"]

    def test_every_git_call_of_both_steps_sets_the_no_replace_guards(self):
        base = self.commit_selector()
        for job, name in ((SELECT_JOB, MATERIALISE_STEP), (GATE_JOB, GATE_MATERIALISE_STEP)):
            log, path = self.recording_path()
            step = step_named(job, name)
            head = fx.git(self.repo, "rev-parse", "HEAD")
            env = dict(derived_env(base, head), PATH=path,
                       IMPACT_FILES=step["env"]["IMPACT_FILES"])
            shutil.rmtree(str(self.dest), ignore_errors=True)
            _, lines, summary, _ = run_snippet(snippet_of(step), self.repo, env)
            self.assertEqual(lines.get("ok"), "true", summary)
            calls = [json.loads(item) for item in log.read_text().split("\n") if item]
            self.assertGreater(len(calls), 3)
            for flag, argv in calls:
                with self.subTest(job=job, argv=argv):
                    self.assertEqual(flag, "1")
                    self.assertEqual(argv[0], "--no-replace-objects")


LIVE_EVENTS = ("pull_request", "merge_group")
BRANCH_EVENTS = ("push", "schedule", "workflow_dispatch")
OTHER_EVENTS = BRANCH_EVENTS + ("release", "workflow_run", "")
OUTPUT_VALUES = (None, "true", "false")


def gate_steps_that_run(event):
    """Yield (steps, outputs) for every output combination of the ci-gate job.

    `steps` are the ci-gate steps whose `if:` holds for `event`. The base step
    is skipped on a branch-tip event, so its outputs are empty there; every
    output combination is still tried so a guard that only works for one
    combination is caught.
    """
    steps = workflow_text.read_steps(CI_YML, GATE_JOB)
    for ok in OUTPUT_VALUES:
        for bootstrap in OUTPUT_VALUES:
            outputs = {k: v for k, v in (("ok", ok), ("bootstrap", bootstrap)) if v}
            context = {"github": {"event_name": event},
                       "steps": {"base": {"outputs": outputs}, "live": {"outputs": {}}}}
            ran = [s for s in steps
                   if s["if"] is None or gha_expr.evaluate_job_if(s["if"], context)]
            yield ran, outputs


class BranchTipGate(unittest.TestCase):
    """R5-RISK: push, schedule and workflow_dispatch run the gate on the branch tip.

    decision: on push, schedule and workflow_dispatch the gate runs from the
    checked-out tree over failing closed because there is no second party to
    judge itself: the tree under test is already the branch tip, and a gate
    that is red on every release/** push and workflow_dispatch full run can
    never be made required
    """

    def test_a_branch_tip_event_runs_exactly_the_branch_tip_fold(self):
        for event in OTHER_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                folds = [s["name"] for s in ran if (s["name"] or "").startswith("Fold job results")]
                with self.subTest(event=event, outputs=outputs):
                    self.assertEqual(folds, [BRANCH_TIP_STEP])

    def test_a_branch_tip_event_skips_the_live_base_and_the_materialise_steps(self):
        for event in OTHER_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                names = [s["name"] for s in ran]
                with self.subTest(event=event, outputs=outputs):
                    self.assertNotIn(LIVE_BASE_STEP, names)
                    self.assertNotIn(GATE_MATERIALISE_STEP, names)

    def test_a_live_base_event_never_runs_the_branch_tip_fold(self):
        for event in LIVE_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                names = [s["name"] for s in ran]
                with self.subTest(event=event, outputs=outputs):
                    self.assertNotIn(BRANCH_TIP_STEP, names)
                    self.assertIn(GATE_MATERIALISE_STEP, names)

    def test_the_fail_step_can_only_run_on_a_live_base_event(self):
        for event in OTHER_EVENTS + LIVE_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                with self.subTest(event=event, outputs=outputs):
                    if FAIL_STEP in [s["name"] for s in ran]:
                        self.assertIn(event, LIVE_EVENTS)

    def test_exactly_one_fold_or_fail_step_runs_on_every_event(self):
        """S14: no event ends with zero verdict steps (a silent pass) or with two."""
        verdict = (BASE_GATE_STEP, BOOTSTRAP_STEP, BRANCH_TIP_STEP, FAIL_STEP)
        consistent = (("true", None), ("true", "false"), ("false", "true"),
                      ("false", "false"), ("false", None))
        for event in OTHER_EVENTS + LIVE_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                live = event in LIVE_EVENTS
                if live and (outputs.get("ok"), outputs.get("bootstrap")) not in consistent:
                    continue
                names = [s["name"] for s in ran if s["name"] in verdict]
                with self.subTest(event=event, outputs=outputs):
                    self.assertEqual(len(names), 1, names)

    def test_the_fail_step_still_runs_when_a_live_base_event_has_no_base_gate(self):
        hit = [outputs for ran, outputs in gate_steps_that_run("pull_request")
               if FAIL_STEP in [s["name"] for s in ran]]
        self.assertTrue(hit)

    def test_the_branch_tip_fold_runs_the_checked_out_gate_and_names_the_event(self):
        step = step_named(GATE_JOB, BRANCH_TIP_STEP)
        self.assertIn("python3 -I " + GATE_SCRIPT + " --needs", step["run"])
        self.assertIn("--github-ref", step["run"])
        self.assertIn("ci-gate: no live base needed (", step["run"])
        self.assertIn("the checked-out tree is the branch tip", step["run"])
        self.assertIn("github.event_name", " ".join(step["env"].values()))
        self.assertIn("!cancelled()", step["if"])

    def test_no_step_that_runs_on_a_branch_tip_event_reads_the_base_copy(self):
        for event in OTHER_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                for step in ran:
                    text = (step["run"] or "") + " ".join(step["env"].values())
                    with self.subTest(event=event, step=step["name"]):
                        self.assertNotIn(BASE_DIR, text)



PERMISSIVE_GATE = (
    "import sys\n"
    "print('PERMISSIVE-GATE-RAN')\n"
    "sys.exit(0)\n"
)


class DerivedBase(BaseCase):
    """S15 (R4-F12): both materialise steps derive the base before any PR code can run.

    decision: the trust decision runs before any checkout file executes and the
    resolver is demoted to a post-derivation report over keeping the resolver
    step first because any PR-tree step that runs earlier in the job can rewrite
    the git state and PATH the derivation reads

    The hostile cases below model the reviewer probes P2, P3, P4 and P8: a
    PR-tree step that had run first rewrites the checkout's git state (moves
    HEAD, adds a replace ref). The workflow no longer has such a step (see
    TrustDecisionFirst); the materialise step still refuses the rewritten state.
    """

    def build(self):
        """main: c0 (no gate.py) -> c1 (selector); PR p0 (permissive gate) -> p1; merge M on HEAD."""
        c0 = self.base
        git = lambda *a: fx.git(self.repo, *a)
        self.commit_selector()
        c1 = git("rev-parse", "HEAD")
        git("checkout", "-q", "-b", "pr")
        p0 = fx.commit_change(self.repo, {IMPACT_REL + "/gate.py": PERMISSIVE_GATE})
        p1 = fx.commit_change(self.repo, {"pr.txt": "pr\n"})
        git("checkout", "-q", "main")
        later = fx.commit_change(self.repo, {"later.txt": "later\n"})
        git("checkout", "-q", "-b", "merge-ref")
        git("merge", "-q", "--no-ff", "-m", "merge", "pr")
        merge = git("rev-parse", "HEAD")
        return {"c0": c0, "c1": c1, "p0": p0, "p1": p1, "base": later, "merge": merge}

    def forged_merge(self, shas):
        """A forged merge commit: first parent the permissive PR commit, second the real head."""
        tree = fx.git(self.repo, "rev-parse", shas["p1"] + "^{tree}")
        return fx.git(self.repo, "commit-tree", tree, "-p", shas["p0"], "-p", shas["p1"],
                      "-m", "forged")

    def hostile_move_head(self, commit):
        fx.git(self.repo, "checkout", "-q", "--detach", commit)

    def hostile_replace(self, real, forged):
        fx.git(self.repo, "replace", "-f", real, forged)

    def run_both(self, event, head, context_sha, merge_group_base="", extra_env=None):
        """Run both materialise steps; return {job: (lines, summary)}."""
        results = {}
        for job, name in ((SELECT_JOB, MATERIALISE_STEP), (GATE_JOB, GATE_MATERIALISE_STEP)):
            step = step_named(job, name)
            env = {"IMPACT_FILES": step["env"]["IMPACT_FILES"], "EVENT_NAME": event,
                   "HEAD_SHA": head, "MERGE_GROUP_BASE_SHA": merge_group_base,
                   "CONTEXT_SHA": context_sha}
            env.update(extra_env or {})
            shutil.rmtree(str(self.dest), ignore_errors=True)
            _, lines, summary, _ = run_snippet(snippet_of(step), self.repo, env)
            results[job] = (lines, summary)
        return results

    def assert_gate_fails_on_mismatch(self, results):
        for job, (lines, summary) in results.items():
            with self.subTest(job=job):
                self.assertEqual(lines.get("ok"), "false", summary)
                self.assertEqual(lines.get("reason"), "base-sha-mismatch", summary)
                self.assertNotEqual(lines.get("bootstrap"), "true", summary)
        gate_lines = results[GATE_JOB][0]
        self.assertEqual(GateBaseRead.plan(self, gate_lines), [FAIL_STEP])
        code, text = GateBaseRead.run_fail_step(self, gate_lines["reason"])
        self.assertNotEqual(code, 0)
        self.assertIn("base-sha-mismatch", text)
        self.assertFalse((self.dest / "impact" / "gate.py").exists())

    def test_the_honest_checkout_derives_the_merge_ref_first_parent_on_both_events(self):
        shas = self.build()
        for event, mg_base in (("pull_request", ""), ("merge_group", shas["base"])):
            results = self.run_both(event, shas["p1"], shas["merge"], mg_base)
            for job, (lines, summary) in results.items():
                with self.subTest(event=event, job=job):
                    self.assertEqual(lines.get("ok"), "true", summary)
            self.assertEqual(GateBaseRead.plan(self, results[GATE_JOB][0]), [BASE_GATE_STEP])
            copy = (self.dest / "impact" / "gate.py").read_text()
            self.assertEqual(copy, (fx.IMPACT_DIR / "gate.py").read_text())

    def test_P2_a_forged_merge_with_head_moved_cannot_reach_the_permissive_gate(self):
        for event, mg_base_key in (("pull_request", None), ("merge_group", "base")):
            with self.subTest(event=event):
                shas = self.build()
                self.hostile_move_head(self.forged_merge(shas))
                mg_base = shas[mg_base_key] if mg_base_key else ""
                self.assert_gate_fails_on_mismatch(
                    self.run_both(event, shas["p1"], shas["merge"], mg_base))
                self.fresh_repo()

    def test_P3_a_replace_ref_for_the_merge_commit_fails_closed(self):
        shas = self.build()
        self.hostile_replace(shas["merge"], self.forged_merge(shas))
        self.assert_gate_fails_on_mismatch(
            self.run_both("pull_request", shas["p1"], shas["merge"]))

    def test_P4_head_moved_onto_a_gateless_parent_never_bootstraps(self):
        shas = self.build()
        fx.git(self.repo, "checkout", "-q", "--detach", shas["c0"])
        forged = fx.commit_change(self.repo, {"forged.txt": "forged\n"})
        self.hostile_move_head(forged)
        self.assert_gate_fails_on_mismatch(
            self.run_both("pull_request", shas["p1"], shas["merge"]))

    def test_P8_a_replace_ref_on_the_merge_group_base_fails_closed(self):
        shas = self.build()
        self.hostile_replace(shas["base"], self.forged_merge(shas))
        self.assert_gate_fails_on_mismatch(
            self.run_both("merge_group", shas["p1"], shas["merge"], shas["base"]))

    def git_state_file(self, rel):
        """Absolute path of a file under the fixture's git dir (`rev-parse --git-path`)."""
        path = Path(fx.git(self.repo, "rev-parse", "--git-path", rel))
        path = path if path.is_absolute() else self.repo / path
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def run_each_event(self, shas, extra_env=None):
        """Run both steps on both live events; assert every one fails closed."""
        for event, mg_base in (("pull_request", ""), ("merge_group", shas["base"])):
            with self.subTest(event=event):
                self.assert_gate_fails_on_mismatch(
                    self.run_both(event, shas["p1"], shas["merge"], mg_base, extra_env))

    def test_F3_a_grafts_file_that_reparents_the_merge_commit_fails_closed(self):
        """F3 / S15 grafts: with .git/info/grafts present both jobs used the PR's permissive gate."""
        shas = self.build()
        self.git_state_file("info/grafts").write_text(
            "%s %s %s\n" % (shas["merge"], shas["p0"], shas["p1"]))
        self.run_each_event(shas)

    def test_F3_a_replace_ref_is_refused_on_both_events(self):
        shas = self.build()
        self.hostile_replace(shas["c1"], self.forged_merge(shas))
        self.run_each_event(shas)

    def test_F3_an_alternates_file_is_refused_on_both_events(self):
        shas = self.build()
        self.git_state_file("objects/info/alternates").write_text(
            str(self.tmp / "other-objects") + "\n")
        self.run_each_event(shas)

    def test_F3_alternate_object_directories_in_the_environment_are_refused(self):
        shas = self.build()
        self.run_each_event(shas, {"GIT_ALTERNATE_OBJECT_DIRECTORIES": str(self.tmp / "other")})

    def test_F3_a_graft_file_in_the_environment_is_refused(self):
        shas = self.build()
        self.run_each_event(shas, {"GIT_GRAFT_FILE": str(self.tmp / "grafts")})

    def test_F3_a_shallow_checkout_is_refused_on_both_events(self):
        """fetch-depth 0 leaves no shallow file; one that exists is never accepted."""
        shas = self.build()
        self.git_state_file("shallow").write_text(shas["c0"] + "\n")
        self.run_each_event(shas)

    def test_F3_the_refusal_names_a_token_and_no_author_text(self):
        shas = self.build()
        self.git_state_file("info/grafts").write_text("%s %s\n" % (shas["merge"], shas["p0"]))
        results = self.run_both("pull_request", shas["p1"], shas["merge"])
        for job, (lines, summary) in results.items():
            with self.subTest(job=job):
                self.assertEqual(lines.get("reason"), "base-sha-mismatch")
                self.assertNotIn("forged", summary)

    def test_the_derivation_uses_the_github_sha_context_not_head(self):
        shas = self.build()
        for context in (shas["c1"], shas["p1"], "", "zz"):
            with self.subTest(context=context):
                self.assert_gate_fails_on_mismatch(
                    self.run_both("pull_request", shas["p1"], context))
        self.hostile_move_head(shas["p1"])
        self.assert_gate_fails_on_mismatch(
            self.run_both("pull_request", shas["p1"], shas["merge"]))

    def test_a_checkout_that_is_not_the_merge_ref_fails_closed(self):
        shas = self.build()
        fx.git(self.repo, "checkout", "-q", "main")
        self.assert_gate_fails_on_mismatch(
            self.run_both("pull_request", shas["p1"], shas["merge"]))

    def test_a_force_pushed_head_is_a_mismatch_not_a_bootstrap(self):
        shas = self.build()
        self.assert_gate_fails_on_mismatch(
            self.run_both("pull_request", shas["c1"], shas["merge"]))

    def test_a_malformed_merge_group_base_fails_closed_without_bootstrap(self):
        shas = self.build()
        for raw in ("", "--oops", "zz"):
            with self.subTest(raw=raw):
                results = self.run_both("merge_group", "", shas["merge"], raw)
                for job, (lines, summary) in results.items():
                    self.assertEqual(lines.get("reason"), "base-sha-invalid", summary)
                    self.assertNotEqual(lines.get("bootstrap"), "true", summary)

    def fresh_repo(self):
        shutil.rmtree(str(self.repo))
        shutil.rmtree(str(self.dest), ignore_errors=True)
        self.base = fx.init_repo(self.repo)

    def test_bootstrap_still_runs_when_the_derived_base_lacks_gate_py(self):
        shas = self.build()
        results = self.run_both("merge_group", shas["p1"], shas["merge"], shas["c0"])
        lines = results[GATE_JOB][0]
        self.assertEqual(lines.get("ok"), "false", results[GATE_JOB][1])
        self.assertEqual(lines.get("bootstrap"), "true", results[GATE_JOB][1])
        self.assertEqual(GateBaseRead.plan(self, lines), [BOOTSTRAP_STEP])

    def test_both_materialise_steps_carry_the_event_payload_for_the_derivation(self):
        for job, name in ((SELECT_JOB, MATERIALISE_STEP), (GATE_JOB, GATE_MATERIALISE_STEP)):
            env = step_named(job, name)["env"]
            with self.subTest(job=job):
                self.assertEqual(env["EVENT_NAME"], "${{ github.event_name }}")
                self.assertEqual(env["HEAD_SHA"], "${{ github.event.pull_request.head.sha"
                                 " || github.event.merge_group.head_sha }}")
                self.assertEqual(env["MERGE_GROUP_BASE_SHA"],
                                 "${{ github.event.merge_group.base_sha }}")
                self.assertEqual(env["CONTEXT_SHA"], CONTEXT_SHA_EXPR)
                self.assertIn("base-sha-mismatch", snippet_of(step_named(job, name)))


if __name__ == "__main__":
    unittest.main()
