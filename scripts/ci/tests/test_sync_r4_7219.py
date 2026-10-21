#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Chain sync of #7219 (sccache + idle-target eviction) with #7191 (#7188 prune contract).

Each test guards one combination reconciled in the r4 merge:

  * the #7191 contract (fail closed on deletion, soft on the exit code, EXIT_USAGE
    only from validate_arguments, nothing inside the protected root deleted by the
    prune pass) holds for the #7199 eviction path too;
  * runner.name reaches every touched ``run:`` through env only.

Trees are built under <repo>/.local-runs/. Python 3.9+, standard library only.
"""
import io
import os
import re
import shutil
import sys
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[3]
SCRATCH = REPO / ".local-runs" / "sync-r4-7219"
sys.path.insert(0, str(REPO / "scripts" / "ci"))
import prune_runner_artifacts as prune  # noqa: E402

DAY = 86400
ME = "f2-linux-fed"
IDLE_AGE_DAYS = 30
BUSY_AGE_DAYS = 1
FORK_GUARD = ("(github.event_name != 'pull_request' || "
              "github.event.pull_request.head.repo.full_name == github.repository)")
STEP_NAMES = (
    "Per-runner cargo target (#7188)",
    "sccache stop CI server (#7199)",
    "Prune stale runner artifacts (#7188)",
)


def make_target(root, name, age_days):
    path = root / name
    (path / "debug").mkdir(parents=True)
    leaf = path / "debug" / "x.rlib"
    leaf.write_text("x", encoding="utf-8")
    stamp = time.time() - age_days * DAY
    for item in (leaf, leaf.parent, path):
        os.utime(item, (stamp, stamp))
    return path


class Fixture(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        self.home = SCRATCH / "home"
        self.root = self.home / ".cache" / "ai-memory-ci" / "cargo-target"
        self.root.mkdir(parents=True)
        self.me = make_target(self.root, ME, IDLE_AGE_DAYS)
        self.idle = make_target(self.root, "f2-linux-fed-3", IDLE_AGE_DAYS)
        self.busy = make_target(self.root, "f2-linux-fed-2", BUSY_AGE_DAYS)
        self.work = SCRATCH / "runner" / "_work"
        self.workspace = self.work / "repo" / "repo"
        self.workspace.mkdir(parents=True)
        stale = self.work / "_temp" / ".tmpstale"
        stale.mkdir(parents=True)
        old = time.time() - 30 * DAY
        os.utime(stale, (old, old))
        self.stale = stale

    def tearDown(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def main(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        argv = ["--work-root", str(self.work), "--workspace", str(self.workspace),
                "--protected-root", str(self.root), "--evict-root", str(self.root),
                "--runner-name", ME, "--home", str(self.home)] + list(extra)
        with redirect_stdout(out), redirect_stderr(err):
            rc = prune.main(argv)
        return rc, out.getvalue(), err.getvalue()


class PruneAndEvictTogether(Fixture):
    def test_prune_pass_spares_the_protected_root_and_eviction_takes_only_idle_siblings(self):
        rc, _, _ = self.main("--free-floor-gib", "0")
        self.assertEqual(rc, prune.EXIT_OK)
        self.assertFalse(self.stale.exists())
        self.assertTrue(self.me.exists(), "the current runner target is never evicted")
        self.assertTrue(self.busy.exists(), "a sibling younger than the idle threshold is kept above the floor")
        self.assertFalse(self.idle.exists(), "a sibling idle past the threshold is evicted")

    def test_eviction_arguments_are_refused_by_validate_arguments_only(self):
        other = self.home / ".cache" / "pip"
        other.mkdir(parents=True)
        problem = prune.validate_arguments(
            self.work, self.workspace, self.root, other, ME, self.home)
        self.assertIn("runner target root", problem)
        bad = prune.main(["--work-root", str(self.work), "--workspace", str(self.workspace),
                          "--protected-root", str(self.root), "--evict-root", str(other),
                          "--runner-name", ME, "--home", str(self.home)])
        self.assertEqual(bad, prune.EXIT_USAGE)
        self.assertTrue(self.idle.exists())

    def test_evict_idle_targets_never_returns_usage(self):
        with redirect_stderr(io.StringIO()):
            rc = prune.evict_idle_targets(
                self.home, ME, self.home, prune.IDLE_TARGET_DAYS, 0, time.time())
        self.assertEqual(rc, prune.EXIT_OK)
        self.assertTrue(self.idle.exists())


class EvictionFailsSoftAndClosed(Fixture):
    def test_listing_error_in_eviction_exits_zero_with_a_message(self):
        with mock.patch.object(prune, "other_targets", side_effect=OSError("boom")):
            rc, _, err = self.main("--free-floor-gib", "0")
        self.assertEqual(rc, prune.EXIT_OK)
        self.assertIn("eviction aborted", err)
        self.assertTrue(self.idle.exists())

    def test_unreadable_target_counts_as_busy_and_is_not_evicted(self):
        real = prune.newest_mtime

        def flaky(path, *args, **kwargs):
            if Path(path).name == self.idle.name and kwargs.get("max_entries"):
                raise OSError("unreadable")
            return real(path, *args, **kwargs)

        with mock.patch.object(prune, "newest_mtime", side_effect=flaky):
            rc, out, _ = self.main("--free-floor-gib", "0")
        self.assertEqual(rc, prune.EXIT_OK)
        self.assertTrue(self.idle.exists())
        self.assertIn("skipped busy", out)

    def test_unreadable_target_in_idle_scan_is_skipped_not_fatal(self):
        real = prune.newest_mtime

        def flaky(path, *args, **kwargs):
            if Path(path).name == self.idle.name and kwargs.get("newer_than") is not None \
                    and not kwargs.get("max_entries"):
                raise OSError("unreadable")
            return real(path, *args, **kwargs)

        with mock.patch.object(prune, "newest_mtime", side_effect=flaky):
            rc, _, err = self.main("--free-floor-gib", "0")
        self.assertEqual(rc, prune.EXIT_OK)
        self.assertTrue(self.idle.exists())
        self.assertIn("skipped unreadable", err)

    def test_prune_abort_does_not_stop_eviction(self):
        with mock.patch.object(prune, "prune_all", side_effect=OSError("scan failed")):
            rc, _, err = self.main("--free-floor-gib", "0")
        self.assertEqual(rc, prune.EXIT_OK)
        self.assertIn("aborted", err)
        self.assertFalse(self.idle.exists())
        self.assertTrue(self.me.exists())

    def test_newest_mtime_never_follows_a_symlink_out_of_the_target(self):
        outside = SCRATCH / "outside"
        outside.mkdir()
        fresh = outside / "fresh"
        fresh.write_text("x", encoding="utf-8")
        link = self.idle / "debug" / "link"
        link.symlink_to(outside)
        old = time.time() - IDLE_AGE_DAYS * DAY
        os.utime(link, (old, old), follow_symlinks=False)
        os.utime(self.idle / "debug", (old, old))
        os.utime(self.idle, (old, old))
        newest = prune.newest_mtime(self.idle)
        self.assertLess(newest, time.time() - DAY)


class RunnerNameThroughEnvOnly(unittest.TestCase):
    def step_text(self, ci, name):
        after = ci.split("- name: " + name, 1)[1]
        return re.split(r"\n      - name: |\n  [a-z0-9_-]+:\n", after, 1)[0]

    def test_no_expression_splice_inside_run_of_touched_steps(self):
        ci = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        for name in STEP_NAMES:
            step = self.step_text(ci, name)
            run = step.split("run:", 1)[1]
            self.assertNotIn("${{", run, name)
            self.assertIn("RUNNER_NAME_ARG: ${{ runner.name }}", step, name)
            self.assertIn('"$RUNNER_NAME_ARG"', run, name)

    def test_sccache_stats_and_stop_steps_carry_the_fork_pr_guard(self):
        # #7290: a refused fork-PR leg must not run the always() sccache steps.
        ci = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        for name in ("sccache hit-rate summary (#7199)", "sccache stop CI server (#7199)"):
            step = self.step_text(ci, name)
            condition = [ln for ln in step.splitlines() if ln.strip().startswith("if:")]
            self.assertEqual(len(condition), 1, name)
            self.assertIn(FORK_GUARD, condition[0], name)

    def test_prune_step_keeps_the_fork_pr_guard_and_the_eviction_arguments(self):
        ci = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        step = self.step_text(ci, "Prune stale runner artifacts (#7188)")
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", step)
        self.assertIn('--evict-root "$AI_MEMORY_CI_TARGET_ROOT"', step)
        self.assertIn('--protected-root "$AI_MEMORY_CI_TARGET_ROOT"', step)


if __name__ == "__main__":
    unittest.main()
