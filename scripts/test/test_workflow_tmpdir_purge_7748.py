#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the #7748 runner-TMPDIR purge wiring in the self-hosted CI jobs.

Read from the workflow text (stdlib only, Python 3.9+; PyYAML is not
guaranteed on every node), mirroring test_workflow_sweep_7160.py. For each
job that can run on a self-hosted runner (ci.yml ``check``, cert-postgres-age,
postgres-ignored, session-boot-lifetime ``lifetime-tests``):

  (a) exactly one pre-job purge step exists and it is the step right after
      ``actions/checkout``; its ``if:`` is the self-hosted + same-repo guard;
  (b) exactly one post-job purge step exists, it is the LAST step of the job,
      and its ``if:`` is ``always() &&`` plus the same guard (plus the
      docs-only clause where the job carries the classify gate);
  (c) both run ``python3 scripts/ci/clean_job_tmpdir.py --apply`` and neither
      may fail silently (no ``continue-on-error``);
  (d) no other workflow carries a self-hosted job without the pair.

Run: python3 scripts/test/test_workflow_tmpdir_purge_7748.py
"""
import os
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
# TMPDIR_PURGE_WORKFLOWS points the pins at another copy of the workflows (reviewer RED runs).
WORKFLOWS = Path(os.environ.get("TMPDIR_PURGE_WORKFLOWS") or str(REPO / ".github" / "workflows"))
PRE_NAME = "Purge runner TMPDIR leftovers (#7748)"
POST_NAME = PRE_NAME + " (post-job)"
RUN = "python3 scripts/ci/clean_job_tmpdir.py --apply"
GUARD = (
    "runner.environment == 'self-hosted' && (github.event_name != 'pull_request' || "
    "github.event.pull_request.head.repo.full_name == github.repository)"
)
DOCS_ONLY = "needs.classify.outputs.docs_only != 'true' && "
# (workflow file, job id, docs-only clause on BOTH steps: ci.yml `check` needs classify and
# required-contexts rule (b3) demands the guard on every non-checkout step)
JOBS = (
    ("ci.yml", "check", DOCS_ONLY),
    ("cert-postgres-age.yml", "cert-postgres-age", ""),
    ("postgres-ignored.yml", "postgres-ignored", ""),
    ("session-boot-lifetime.yml", "lifetime-tests", ""),
)
SELF_HOSTED_RE = re.compile(r"^\s*(?:runs-on:.*|runner:.*)(self-hosted|linux-fed|macos-fed)")


def read(path):
    return path.read_text(encoding="utf-8")


def job_lines(text, job):
    """Lines of the top-level ``job:`` from its header to the next job."""
    lines = text.splitlines()
    start = lines.index("  %s:" % job)
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[i]):
            end = i
            break
    return lines[start:end]


def steps(job):
    """Split the job's ``steps:`` list into one line list per step."""
    out = []
    in_steps = False
    for ln in job:
        if re.match(r"^    steps:\s*$", ln):
            in_steps = True
            continue
        if not in_steps:
            continue
        if re.match(r"^      - ", ln):
            out.append([ln])
        elif out:
            out[-1].append(ln)
    return out


def field(step, key):
    for ln in step:
        m = re.match(r"^\s+(?:- )?%s:\s*(.*)$" % re.escape(key), ln)
        if m:
            return m.group(1).strip()
    return ""


def named(all_steps, name):
    return [s for s in all_steps if field(s, "name") == name]


class PurgeSteps(unittest.TestCase):
    def each_job(self):
        for wf, job, docs in JOBS:
            all_steps = steps(job_lines(read(WORKFLOWS / wf), job))
            self.assertTrue(all_steps, "%s %s: no steps parsed" % (wf, job))
            yield wf, job, docs, all_steps

    def test_pre_and_post_steps_exist_once_7748(self):
        for wf, job, _, all_steps in self.each_job():
            self.assertEqual(len(named(all_steps, PRE_NAME)), 1, "%s %s pre" % (wf, job))
            self.assertEqual(len(named(all_steps, POST_NAME)), 1, "%s %s post" % (wf, job))

    def test_pre_step_is_first_after_checkout_with_exact_guard_7748(self):
        for wf, job, docs, all_steps in self.each_job():
            checkout = [i for i, s in enumerate(all_steps) if "uses: actions/checkout@" in s[0]]
            self.assertEqual(len(checkout), 1, "%s %s checkout" % (wf, job))
            pre = named(all_steps, PRE_NAME)[0]
            self.assertIs(all_steps[checkout[0] + 1], pre, "%s %s pre not right after checkout" % (wf, job))
            self.assertEqual(field(pre, "if"), docs + GUARD, "%s %s" % (wf, job))

    def test_post_step_is_last_with_always_guard_7748(self):
        for wf, job, docs, all_steps in self.each_job():
            post = named(all_steps, POST_NAME)[0]
            self.assertIs(all_steps[-1], post, "%s %s post is not the last step" % (wf, job))
            self.assertEqual(field(post, "if"), "always() && " + docs + GUARD, "%s %s" % (wf, job))

    def test_steps_run_the_script_and_cannot_fail_silently_7748(self):
        for wf, job, _, all_steps in self.each_job():
            for name in (PRE_NAME, POST_NAME):
                step = named(all_steps, name)[0]
                self.assertEqual(field(step, "run"), RUN, "%s %s %s" % (wf, job, name))
                self.assertEqual(field(step, "continue-on-error"), "")

    def test_no_other_workflow_has_an_unpaired_self_hosted_job_7748(self):
        covered = set(wf for wf, _, _ in JOBS)
        for path in sorted(WORKFLOWS.glob("*.yml")):
            if path.name in covered:
                continue
            for ln in read(path).splitlines():
                if ln.lstrip().startswith("#"):
                    continue
                self.assertIsNone(SELF_HOSTED_RE.match(ln), "%s: self-hosted job without the purge pair: %s" % (path.name, ln))


if __name__ == "__main__":
    unittest.main()
