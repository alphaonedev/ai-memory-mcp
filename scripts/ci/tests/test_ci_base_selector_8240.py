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
LIVE_BASE_EXPR ="${{ steps.live.outputs.sha }}"
HELPER = IMPACT_REL + "/base_sha.py"
BOOTSTRAP_STEP = "Fold job results (bootstrap, PR-tree gate)"
BASE_GATE_STEP = "Fold job results (base gate)"
FAIL_STEP = "Fail the gate (base gate unreadable)"
GATE_SCRIPT = IMPACT_REL + "/gate.py"
FAKE_SHA = "0123456789abcdef0123456789abcdef01234567"


def derived_env(base):
    """Event env under which the materialise step derives exactly `base` (merge_group form)."""
    return {"BASE_SHA": base, "EVENT_NAME": "merge_group", "HEAD_SHA": "",
            "MERGE_GROUP_BASE_SHA": base}


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
        return run_snippet(source or snippet_of(step), self.repo,
                           dict(derived_env(base), IMPACT_FILES=files))


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

    def test_both_materialise_steps_take_the_base_sha_from_the_live_base_step(self):
        for job, step_name in ((SELECT_JOB, MATERIALISE_STEP),
                               (GATE_JOB, GATE_MATERIALISE_STEP)):
            with self.subTest(job=job):
                value = step_named(job, step_name)["env"]["BASE_SHA"]
                self.assertEqual(value, LIVE_BASE_EXPR)

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
        env = dict(derived_env(base), IMPACT_FILES=step["env"]["IMPACT_FILES"])
        if path is not None:
            env["PATH"] = path
        return run_snippet(snippet_of(step), self.repo, env)

    def plan(self, lines):
        """Return the names of the gate steps whose `if:` holds after the materialise step."""
        context = {"github": {"event_name": "pull_request"},
                   "steps": {"base": {"outputs": lines}}}
        ran = []
        for step in workflow_text.read_steps(CI_YML, GATE_JOB):
            if step["uses"] or step["name"] in (GATE_MATERIALISE_STEP, LIVE_BASE_STEP,
                                                 LIVE_SUMMARY_STEP):
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
        wrapper.write_text("#!%s\nimport os\nimport sys\nif %r in sys.argv[1:2]:\n"
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

        env = {"BASE_SHA": base, "EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": base,
               "IMPACT_FILES": " ".join(SELECTOR_FILES),
               "RUNNER_TEMP": str(self.tmp / "runner-temp"),
               "GITHUB_OUTPUT": str(self.tmp / "go.txt"),
               "GITHUB_STEP_SUMMARY": str(self.tmp / "gs.md")}
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


class LiveBaseWorkflow(unittest.TestCase):
    """R3-F10 (f): select and ci-gate resolve the base through one helper."""

    def test_both_jobs_run_the_same_helper_step(self):
        steps = {}
        for job in (SELECT_JOB, GATE_JOB):
            step = step_named(job, LIVE_BASE_STEP)
            self.assertEqual(step["id"], "live")
            self.assertIn(HELPER, step["run"])
            steps[job] = step
        self.assertEqual(steps[SELECT_JOB]["run"], steps[GATE_JOB]["run"])
        self.assertEqual(steps[SELECT_JOB]["env"], steps[GATE_JOB]["env"])

    def test_the_helper_step_precedes_materialise_in_both_jobs(self):
        for job, name in ((SELECT_JOB, MATERIALISE_STEP), (GATE_JOB, GATE_MATERIALISE_STEP)):
            names = [s["name"] for s in workflow_text.read_steps(CI_YML, job)]
            self.assertLess(names.index(LIVE_BASE_STEP), names.index(name))

    def test_no_base_step_reads_the_frozen_base_sha(self):
        for job, name in ((SELECT_JOB, MATERIALISE_STEP), (GATE_JOB, GATE_MATERIALISE_STEP),
                          (SELECT_JOB, LIVE_BASE_STEP), (GATE_JOB, LIVE_BASE_STEP)):
            step = step_named(job, name)
            with self.subTest(job=job, step=name):
                for value in step["env"].values():
                    self.assertNotIn("pull_request.base.sha", value)
                    self.assertNotIn("github.sha", value)

    def test_the_helper_receives_only_the_event_name_and_raw_candidates(self):
        env = step_named(SELECT_JOB, LIVE_BASE_STEP)["env"]
        self.assertEqual(sorted(env), ["BASE_REF", "EVENT_NAME", "HEAD_SHA",
                                       "MERGE_GROUP_BASE_SHA"])

    def test_the_gate_failure_step_names_the_live_base_reason(self):
        step = step_named(GATE_JOB, FAIL_STEP)
        self.assertIn("steps.live.outputs.reason", " ".join(step["env"].values()))


BRANCH_TIP_STEP = "Fold job results (branch tip gate)"
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
    that is red on every chain push and nightly full run can never be made
    required
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
                    self.assertNotIn(LIVE_SUMMARY_STEP, names)

    def test_a_live_base_event_never_runs_the_branch_tip_fold(self):
        for event in LIVE_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                names = [s["name"] for s in ran]
                with self.subTest(event=event, outputs=outputs):
                    self.assertNotIn(BRANCH_TIP_STEP, names)
                    self.assertIn(LIVE_BASE_STEP, names)
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


def printer_source(sha):
    """A hostile scripts/ci/impact/base_sha.py: prints a chosen sha as the live base."""
    return (
        "import sys\n"
        "out = sys.argv[sys.argv.index('--github-output') + 1]\n"
        "lines = 'sha=%s\\nreason=live-base-first-parent\\n'\n"
        "open(out, 'a').write(lines)\n"
        "sys.stdout.write(lines)\n"
    ).replace("%s", sha)


class DerivedBase(BaseCase):
    """R4-F12: both materialise steps re-derive the base; the resolver is a cross-check only.

    decision: materialise steps re-derive the base inline from git and the
    event payload and fail closed on mismatch over running the resolver from a
    non-PR-tree copy because the copy itself would need a trusted base to be
    fetched from, while HEAD^1 of the merge ref and merge_group.base_sha are
    not author-controllable
    """

    def build(self, helper_sha=None):
        """main: c0 (no gate.py) -> c1 (selector + helper); PR p1 edits the helper; merge M on HEAD.

        helper_sha: None keeps the real helper; "c0" / "p1" / "merge" make the PR commit
        replace scripts/ci/impact/base_sha.py with a printer of that sha (and gate.py with
        a permissive gate), exactly the change a PR limited to scripts/ci/impact can make.
        """
        c0 = self.base
        git = lambda *a: fx.git(self.repo, *a)
        self.commit_selector()
        real_helper = (fx.IMPACT_DIR / "base_sha.py").read_text()
        c1 = fx.commit_change(self.repo, {IMPACT_REL + "/base_sha.py": real_helper})
        git("checkout", "-q", "-b", "pr")
        change = {"pr.txt": "pr\n"}
        if helper_sha is not None:
            change[IMPACT_REL + "/gate.py"] = PERMISSIVE_GATE
        p0 = fx.commit_change(self.repo, change)
        p1 = p0
        if helper_sha is not None:
            printed = c0 if helper_sha == "c0" else p0
            p1 = fx.commit_change(self.repo, {
                IMPACT_REL + "/base_sha.py": printer_source(printed)})
        git("checkout", "-q", "main")
        later = fx.commit_change(self.repo, {"later.txt": "later\n"})
        git("checkout", "-q", "-b", "merge-ref")
        git("merge", "-q", "--no-ff", "-m", "merge", "pr")
        git("update-ref", "refs/remotes/origin/main", later)
        return {"c0": c0, "c1": c1, "p0": p0, "p1": p1, "base": later}

    def live_step(self, event, head, merge_group_base=""):
        """Run the checked-out (PR-tree) resolver exactly as the workflow does."""
        out_path = self.tmp / "live_out.txt"
        out_path.write_text("")
        env = {"PATH": os.environ["PATH"], "HOME": str(self.tmp), "EVENT_NAME": event,
               "HEAD_SHA": head, "MERGE_GROUP_BASE_SHA": merge_group_base,
               "BASE_REF": "main"}
        subprocess.run([sys.executable, "-I", IMPACT_REL + "/base_sha.py",
                        "--github-output", str(out_path)], cwd=str(self.repo), env=env,
                       capture_output=True, text=True, timeout=120)
        return dict(i.split("=", 1) for i in out_path.read_text().split("\n") if "=" in i)

    def run_both(self, event, head, resolver_sha, merge_group_base=""):
        """Run both materialise steps; return {job: (lines, summary)}."""
        results = {}
        for job, name in ((SELECT_JOB, MATERIALISE_STEP), (GATE_JOB, GATE_MATERIALISE_STEP)):
            step = step_named(job, name)
            env = {"BASE_SHA": resolver_sha, "IMPACT_FILES": step["env"]["IMPACT_FILES"],
                   "EVENT_NAME": event, "HEAD_SHA": head,
                   "MERGE_GROUP_BASE_SHA": merge_group_base}
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

    def test_a_pr_replacing_the_helper_with_a_stale_sha_printer_fails_ci_gate(self):
        shas = self.build("c0")
        live = self.live_step("pull_request", shas["p1"])
        self.assertEqual(live["sha"], shas["c0"])
        self.assert_gate_fails_on_mismatch(self.run_both("pull_request", shas["p1"], live["sha"]))

    def test_a_pr_replacing_the_helper_with_a_self_containing_printer_fails_ci_gate(self):
        shas = self.build("p0")
        live = self.live_step("pull_request", shas["p1"])
        self.assertEqual(live["sha"], shas["p0"])
        self.assert_gate_fails_on_mismatch(self.run_both("pull_request", shas["p1"], live["sha"]))

    def test_the_hostile_printers_cannot_reach_the_permissive_pr_tree_gate(self):
        for helper in ("c0", "p0"):
            with self.subTest(helper=helper):
                shas = self.build(helper)
                live = self.live_step("pull_request", shas["p1"])
                lines = self.run_both("pull_request", shas["p1"], live["sha"])[GATE_JOB][0]
                plan = GateBaseRead.plan(self, lines)
                self.assertNotIn(BOOTSTRAP_STEP, plan)
                self.assertNotIn(BASE_GATE_STEP, plan)
                self.assertFalse((self.dest / "impact" / "gate.py").exists())
                self.fresh_repo()

    def fresh_repo(self):
        shutil.rmtree(str(self.repo))
        shutil.rmtree(str(self.dest), ignore_errors=True)
        self.base = fx.init_repo(self.repo)

    def test_the_honest_helper_agrees_with_the_derived_base_and_the_base_gate_runs(self):
        shas = self.build(None)
        live = self.live_step("pull_request", shas["p1"])
        self.assertEqual(live["sha"], shas["base"])
        results = self.run_both("pull_request", shas["p1"], live["sha"])
        for job, (lines, summary) in results.items():
            with self.subTest(job=job):
                self.assertEqual(lines.get("ok"), "true", summary)
        self.assertEqual(GateBaseRead.plan(self, results[GATE_JOB][0]), [BASE_GATE_STEP])
        copy = (self.dest / "impact" / "gate.py").read_text()
        self.assertEqual(copy, (fx.IMPACT_DIR / "gate.py").read_text())

    def test_the_derived_base_is_the_merge_ref_first_parent_not_the_resolver_value(self):
        shas = self.build(None)
        results = self.run_both("pull_request", shas["p1"], shas["c1"])
        self.assert_gate_fails_on_mismatch(results)

    def test_an_empty_resolver_output_is_a_mismatch_not_a_bootstrap(self):
        shas = self.build(None)
        self.assert_gate_fails_on_mismatch(self.run_both("pull_request", shas["p1"], ""))

    def test_a_checkout_that_is_not_the_merge_ref_fails_closed(self):
        shas = self.build(None)
        fx.git(self.repo, "checkout", "-q", "main")
        self.assert_gate_fails_on_mismatch(
            self.run_both("pull_request", shas["p1"], shas["base"]))

    def test_merge_group_takes_the_event_base_sha_and_rejects_a_different_resolver_sha(self):
        shas = self.build(None)
        ok = self.run_both("merge_group", shas["p1"], shas["base"],
                           merge_group_base=shas["base"])
        for job, (lines, summary) in ok.items():
            with self.subTest(job=job):
                self.assertEqual(lines.get("ok"), "true", summary)
        self.assert_gate_fails_on_mismatch(self.run_both(
            "merge_group", shas["p1"], shas["p1"], merge_group_base=shas["base"]))

    def test_bootstrap_still_runs_when_the_derived_base_lacks_gate_py(self):
        shas = self.build(None)
        step = step_named(GATE_JOB, GATE_MATERIALISE_STEP)
        env = {"BASE_SHA": shas["c0"], "IMPACT_FILES": step["env"]["IMPACT_FILES"],
               "EVENT_NAME": "merge_group", "HEAD_SHA": shas["p1"],
               "MERGE_GROUP_BASE_SHA": shas["c0"]}
        _, lines, summary, _ = run_snippet(snippet_of(step), self.repo, env)
        self.assertEqual(lines.get("ok"), "false", summary)
        self.assertEqual(lines.get("bootstrap"), "true", summary)
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
                self.assertIn("base-sha-mismatch", snippet_of(step_named(job, name)))


if __name__ == "__main__":
    unittest.main()
