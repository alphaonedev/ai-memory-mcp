#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for scripts/ci/prune_runner_artifacts.py (#7188).

The helper prunes stale per-job artifacts after a self-hosted job and must
NEVER list, let alone delete, the shared per-host cargo target. Every tree is
built under <repo>/.local-runs/, never a tmp path.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only.
"""
import io
import os
import shutil
import sys
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRATCH = REPO / ".local-runs" / "prune-7188"
sys.path.insert(0, str(REPO / "scripts" / "ci"))
import prune_runner_artifacts as prune  # noqa: E402

DAY = 86400
OLD = 30 * DAY
MAX_AGE_DAYS = 7


def touch_dir(path, age_secs=0):
    path.mkdir(parents=True, exist_ok=True)
    (path / "f").write_text("x", encoding="utf-8")
    stamp = time.time() - age_secs
    os.utime(path, (stamp, stamp))
    return path


class Fixture(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        self.work = SCRATCH / "work"
        self.workspace = self.work / "repo" / "repo"
        self.shared = SCRATCH / "home" / "ci-cargo-target"
        self.workspace.mkdir(parents=True)
        touch_dir(self.shared / "debug" / "deps")
        touch_dir(self.shared / "debug" / "incremental")
        self.old_tmp = touch_dir(self.work / "_temp" / "old", OLD)
        self.new_tmp = touch_dir(self.work / "_temp" / "new", 0)
        self.ws_incr = touch_dir(self.workspace / "target" / "debug" / "incremental")
        self.ws_tmp = touch_dir(self.workspace / ".tmpabc123", 0)
        self.keep = touch_dir(self.workspace / "src")

    def tearDown(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def candidates(self):
        return prune.find_candidates(
            self.work, self.workspace, self.shared, MAX_AGE_DAYS, time.time()
        )


class Candidates(Fixture):
    def test_lists_stale_artifacts_only(self):
        got = set(self.candidates())
        self.assertEqual(got, {self.old_tmp, self.ws_incr, self.ws_tmp})

    def test_never_lists_the_shared_target_or_anything_in_it(self):
        for cand in self.candidates():
            self.assertTrue(prune.is_protected(self.shared, self.shared))
            self.assertFalse(
                cand == self.shared or self.shared in cand.parents or cand in self.shared.parents
            )

    def test_shared_target_inside_the_workspace_is_still_protected(self):
        inside = self.workspace / "target"
        got = prune.find_candidates(self.work, self.workspace, inside, MAX_AGE_DAYS, time.time())
        for cand in got:
            self.assertFalse(cand == inside or inside in cand.parents)

    def test_recent_temp_and_sources_survive(self):
        got = set(self.candidates())
        self.assertNotIn(self.new_tmp, got)
        self.assertNotIn(self.keep, got)


class Cli(Fixture):
    def run_main(self, *extra):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = prune.main(
                ["--work-root", str(self.work), "--workspace", str(self.workspace),
                 "--shared-target", str(self.shared), "--max-age-days", str(MAX_AGE_DAYS)]
                + list(extra)
            )
        return rc, out.getvalue()

    def test_dry_run_deletes_nothing_and_never_prints_the_shared_target(self):
        rc, out = self.run_main("--dry-run")
        self.assertEqual(rc, 0)
        self.assertTrue(self.old_tmp.exists() and self.ws_incr.exists())
        self.assertNotIn(str(self.shared), out)
        self.assertIn("would remove", out)

    def test_real_run_removes_stale_and_leaves_the_shared_target(self):
        rc, _ = self.run_main()
        self.assertEqual(rc, 0)
        self.assertFalse(self.old_tmp.exists())
        self.assertFalse(self.ws_incr.exists())
        self.assertFalse(self.ws_tmp.exists())
        self.assertTrue((self.shared / "debug" / "deps" / "f").exists())
        self.assertTrue((self.shared / "debug" / "incremental" / "f").exists())
        self.assertTrue(self.keep.exists() and self.new_tmp.exists())

    def test_bad_arguments_exit_2(self):
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(io.StringIO()):
                prune.main(["--max-age-days", "0"])
        self.assertEqual(ctx.exception.code, 2)


class Symlinks(Fixture):
    """r1 HIGH-2: the helper must never follow a symlink out of its root."""

    run_main = Cli.run_main

    def setUp(self):
        super().setUp()
        shutil.rmtree(self.workspace / "target")  # replace the real tree by a link
        self.outside = SCRATCH / "outside"
        self.outside_incr = touch_dir(self.outside / "debug" / "incremental", OLD)
        (self.workspace / "target").symlink_to(self.outside, target_is_directory=True)

    def test_symlinked_target_is_never_a_candidate(self):
        self.assertNotIn(self.workspace / "target" / "debug" / "incremental", self.candidates())

    def test_outside_directory_survives_a_real_run_and_the_skip_is_reported(self):
        rc, out = self.run_main()
        self.assertEqual(rc, 0)
        self.assertTrue((self.outside_incr / "f").exists())
        self.assertTrue((self.outside / "debug").is_dir())
        self.assertIn("skipped", out)
        self.assertFalse(self.old_tmp.exists())  # ordinary candidates still pruned

    def test_symlink_to_another_runners_tree_survives(self):
        other = touch_dir(SCRATCH / "work2" / "repo" / "repo" / "target" / "debug" / "incremental")
        (self.workspace / ".tmplink").symlink_to(other, target_is_directory=True)
        link = self.work / "_temp" / "oldlink"
        link.symlink_to(other, target_is_directory=True)
        os.utime(link, (time.time() - OLD, time.time() - OLD), follow_symlinks=False)
        rc, out = self.run_main()
        self.assertEqual(rc, 0)
        self.assertTrue((other / "f").exists())
        self.assertIn("skipped", out)

    def test_symlinked_debug_component_is_skipped(self):
        (self.workspace / "target").unlink()
        (self.workspace / "target").mkdir()
        (self.workspace / "target" / "debug").symlink_to(
            self.outside / "debug", target_is_directory=True
        )
        rc, _ = self.run_main()
        self.assertEqual(rc, 0)
        self.assertTrue((self.outside_incr / "f").exists())

    def test_shared_target_reached_through_a_link_stays_protected(self):
        link = self.workspace / ".tmpshared"
        link.symlink_to(self.shared, target_is_directory=True)
        rc, _ = self.run_main()
        self.assertEqual(rc, 0)
        self.assertTrue((self.shared / "debug" / "incremental" / "f").exists())


if __name__ == "__main__":
    unittest.main()
