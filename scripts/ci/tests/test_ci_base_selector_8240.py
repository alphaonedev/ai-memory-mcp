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
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

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
FAKE_SHA = "0123456789abcdef0123456789abcdef01234567"


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
                           {"BASE_SHA": base, "IMPACT_FILES": files})


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
                if s["run"] and "gate.py" in s["run"] and "<<'PY'" not in s["run"]]
        self.assertEqual(len(runs), 2)
        base_run = [s for s in runs if BASE_DIR in s["run"]]
        pr_run = [s for s in runs if BASE_DIR not in s["run"]]
        self.assertEqual(len(base_run), 1)
        self.assertEqual(len(pr_run), 1)
        self.assertIn("steps.base.outputs.ok == 'true'", base_run[0]["if"])
        self.assertEqual(pr_run[0]["if"],
                         "${{ !cancelled() && steps.base.outputs.ok != 'true' }}")
        self.assertTrue(base_run[0]["if"].startswith("${{ !cancelled() &&"))

    def test_the_two_materialise_steps_share_one_source(self):
        select_src = snippet_of(step_named(SELECT_JOB, MATERIALISE_STEP))
        gate_src = snippet_of(step_named(GATE_JOB, GATE_MATERIALISE_STEP))
        self.assertEqual(select_src, gate_src)


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
        self.assertIn("impact: base selector unavailable", summary)
        self.assertIn("selecting the full matrix", summary)
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
        base = self.commit_selector()
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

        env = {"BASE_SHA": base, "IMPACT_FILES": " ".join(SELECTOR_FILES),
               "RUNNER_TEMP": str(self.tmp / "runner-temp"),
               "GITHUB_OUTPUT": str(self.tmp / "go.txt"),
               "GITHUB_STEP_SUMMARY": str(self.tmp / "gs.md")}
        (self.tmp / "runner-temp").mkdir()
        cwd = os.getcwd()
        os.chdir(str(self.repo))
        try:
            with mock.patch.dict(os.environ, env), \
                    mock.patch.object(Path, "write_bytes", flaky), \
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
        outputs = workflow_text.read_jobs(CI_YML)[SELECT_JOB]["outputs"]
        domains = set(outputs) - DECLARED_NON_DOMAIN_OUTPUTS
        self.assertEqual(domains, {"rust", "cells", "actionlint"})
        for domain in domains:
            with self.subTest(domain=domain):
                self.assertEqual(lines[domain], "true")
        self.assertNotIn("false", lines.values())


if __name__ == "__main__":
    unittest.main()
