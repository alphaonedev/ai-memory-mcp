#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for scripts/ci/prune_runner_artifacts.py (#7188).

The helper prunes stale per-job artifacts after a self-hosted job and must
NEVER list, let alone delete, the per-runner cargo target ROOT
(every runner's target) passed as --protected-root. Every tree is
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
import unittest.mock as mock
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRATCH = REPO / ".local-runs" / "prune-7188"
# A real directory that resolves to one path component on Linux and macOS.
SINGLE_COMPONENT_ROOT = "/usr"
MIN_COMPONENT_ROOT = "/usr/bin"
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
                 "--protected-root", str(self.shared), "--max-age-days", str(MAX_AGE_DAYS)]
                + list(extra)
            )
        return rc, out.getvalue()

    def test_dry_run_deletes_nothing_and_never_prints_the_shared_target(self):
        rc, out = self.run_main("--dry-run")
        self.assertEqual(rc, 0)
        self.assertTrue(self.old_tmp.exists() and self.ws_incr.exists())
        for line in out.splitlines():
            if line.startswith(("would remove", "removed")):
                self.assertNotIn(str(self.shared), line)
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


class Arguments(Fixture):
    """r1 MEDIUM-3: refuse unsafe arguments with EXIT_USAGE and delete nothing."""

    def run_with(self, work=None, workspace=None, shared=None):
        argv = [
            "--work-root", str(self.work if work is None else work),
            "--workspace", str(self.workspace if workspace is None else workspace),
            "--protected-root", str(self.shared if shared is None else shared),
        ]
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            rc = prune.main(argv)
        return rc, err.getvalue()

    def assert_refused(self, rc):
        self.assertEqual(rc, prune.EXIT_USAGE)
        self.assertEqual(prune.EXIT_USAGE, 2)
        self.assertTrue(self.old_tmp.exists())
        self.assertTrue(self.ws_incr.exists())
        self.assertTrue(self.ws_tmp.exists())

    def test_filesystem_root_is_refused(self):
        rc, _ = self.run_with(work="/")
        self.assert_refused(rc)

    def test_missing_root_is_refused(self):
        rc, _ = self.run_with(work=SCRATCH / "no-such-root")
        self.assert_refused(rc)

    def test_root_that_is_a_file_is_refused(self):
        plain = SCRATCH / "plain-file"
        plain.write_text("x", encoding="utf-8")
        rc, _ = self.run_with(work=plain)
        self.assert_refused(rc)

    def test_empty_shared_target_is_refused(self):
        rc, _ = self.run_with(shared="")
        self.assert_refused(rc)

    def test_missing_shared_target_option_is_refused(self):
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                prune.main(["--work-root", str(self.work), "--workspace", str(self.workspace)])
        self.assertEqual(ctx.exception.code, 2)
        self.assertTrue(self.old_tmp.exists())

    def test_protected_root_equal_to_work_root_is_refused(self):
        rc, _ = self.run_with(shared=self.work)
        self.assert_refused(rc)

    def test_protected_root_ancestor_of_work_root_is_refused(self):
        rc, _ = self.run_with(shared=SCRATCH)
        self.assert_refused(rc)
        rc, _ = self.run_with(shared="/")
        self.assert_refused(rc)

    def test_work_root_with_fewer_than_two_components_is_refused(self):
        rc, err = self.run_with(work=SINGLE_COMPONENT_ROOT, workspace=SINGLE_COMPONENT_ROOT + "/x", shared="/opt/ci-cargo-target")
        self.assertEqual(rc, prune.EXIT_USAGE)
        self.assertIn("fewer than %d path components" % prune.MIN_WORK_ROOT_COMPONENTS, err)
        self.assertTrue(self.old_tmp.exists())

    def test_work_root_with_exactly_the_minimum_components_is_accepted(self):
        """#8213: the floor is inclusive; `<` turned into `<=` would refuse a root of exactly two components."""
        self.assertEqual(len(Path(MIN_COMPONENT_ROOT).parts) - 1, prune.MIN_WORK_ROOT_COMPONENTS)
        reason = prune.validate_arguments(MIN_COMPONENT_ROOT, MIN_COMPONENT_ROOT + "/x", "/opt/ci-cargo-target")
        self.assertIsNone(reason)
        reason = prune.validate_arguments(SINGLE_COMPONENT_ROOT, SINGLE_COMPONENT_ROOT + "/x", "/opt/ci-cargo-target")
        self.assertIn("fewer than", reason)

    def test_relative_shared_target_is_refused(self):
        rc, _ = self.run_with(shared="cargo-target")
        self.assert_refused(rc)

    def test_workspace_outside_the_root_is_refused(self):
        outside = touch_dir(SCRATCH / "elsewhere" / "ws")
        touch_dir(outside / "target" / "debug" / "incremental")
        rc, _ = self.run_with(workspace=outside)
        self.assert_refused(rc)
        self.assertTrue((outside / "target" / "debug" / "incremental" / "f").exists())

    def test_shared_target_inside_the_root_is_accepted(self):
        rc, _ = self.run_with(shared=self.work / "shared-target")
        self.assertEqual(rc, 0)
        self.assertFalse(self.old_tmp.exists())

    def test_dry_run_still_previews_with_valid_arguments(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = prune.main(
                ["--work-root", str(self.work), "--workspace", str(self.workspace),
                 "--protected-root", str(self.shared), "--dry-run"]
            )
        self.assertEqual(rc, 0)
        self.assertIn("would remove", out.getvalue())
        self.assertTrue(self.old_tmp.exists())


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


class OutOfTreeProtectedRoot(Fixture):
    """#7188 fed runners: the protected root is a symlink whose target is outside the work root."""

    run_main = Cli.run_main
    FAKE = Path("/zz-7188-outside/cargo-target")

    def setUp(self):
        super().setUp()
        self.link = SCRATCH / "home" / "cache-link"
        self.link.symlink_to(self.shared, target_is_directory=True)
        real_resolve = prune.resolve
        link = self.link

        def fake_resolve(path):
            # Emulate fed hosts: after resolving, only the filesystem root is shared.
            if Path(path) == link:
                return OutOfTreeProtectedRoot.FAKE
            return real_resolve(path)

        patcher = mock.patch.object(prune, "resolve", fake_resolve)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_link(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = prune.main(
                ["--work-root", str(self.work), "--workspace", str(self.workspace),
                 "--protected-root", str(self.link), "--max-age-days", str(MAX_AGE_DAYS)]
            )
        return rc, out.getvalue(), err.getvalue()

    def test_out_of_tree_protected_root_is_not_refused_and_logs_once(self):
        rc, out, err = self.run_link()
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.count("is outside the work root; nothing to protect"), 1)
        self.assertIn("protected root %s is outside the work root" % self.link, out)

    def test_out_of_tree_protected_root_prunes_work_root_and_deletes_nothing_outside(self):
        rc, _, err = self.run_link()
        self.assertEqual(rc, 0, err)
        self.assertFalse(self.old_tmp.exists())
        self.assertFalse(self.ws_incr.exists())
        self.assertTrue(self.new_tmp.exists())
        self.assertTrue((self.shared / "debug" / "incremental" / "f").exists())
        self.assertTrue((self.shared / "debug" / "deps" / "f").exists())

    def test_link_inside_work_root_to_protected_target_is_not_followed(self):
        inner = self.workspace / ".tmpinner"
        inner.mkdir()
        (inner / "f").write_text("x", encoding="utf-8")
        (inner / "to-shared").symlink_to(self.shared, target_is_directory=True)
        top = self.workspace / ".tmptop"
        top.symlink_to(self.shared, target_is_directory=True)
        rc, _, err = self.run_link()
        self.assertEqual(rc, 0, err)
        self.assertFalse(inner.exists())  # real candidate removed; inner link unlinked only
        self.assertTrue(top.is_symlink())  # top-level link skipped, never followed
        self.assertTrue((self.shared / "debug" / "incremental" / "f").exists())
        self.assertTrue((self.shared / "debug" / "deps" / "f").exists())

    def test_prune_never_uses_a_following_walk(self):
        src = Path(prune.__file__).read_text(encoding="utf-8")
        self.assertNotIn("os.walk(", src)
        self.assertNotIn("followlinks=True", src)


class Hardening7188R2(Fixture):
    def test_f1_child_link_into_work_root_is_protected(self):
        child = self.shared / "r2"
        target = touch_dir(self.work / "_temp" / "runnerB", OLD)
        child.symlink_to(target, target_is_directory=True)
        self.assertNotIn(target, self.candidates())
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            prune.main(["--work-root", str(self.work), "--workspace", str(self.workspace),
                        "--protected-root", str(self.shared)])
        self.assertTrue(target.exists())

    def test_f2_swapped_component_is_not_followed(self):
        outside = touch_dir(SCRATCH / "outside" / "debug" / "incremental")
        victim = self.ws_incr
        self.assertIn(victim, self.candidates())
        shutil.rmtree(self.workspace / "target")
        (self.workspace / "target").symlink_to(SCRATCH / "outside", target_is_directory=True)
        status, _ = prune.remove_candidate(victim, self.work, self.shared)
        self.assertEqual(status, "skipped")
        self.assertTrue((outside / "f").exists())

    def test_f2_plain_candidate_is_removed(self):
        status, _ = prune.remove_candidate(self.ws_incr, self.work, self.shared)
        self.assertEqual(status, "removed")
        self.assertFalse(self.ws_incr.exists())

    def test_f3_f4_workflow_step(self):
        ci = (Path(prune.__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        step = ci.split("Prune stale runner artifacts (#7188)")[1].split("run:")[0]
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", step)
        self.assertIn("github.event_name != 'pull_request'", step)
        self.assertNotIn("never fails the job", ci)


class FailSoft(Fixture):
    """r3 F1: fail CLOSED on deletion, SOFT on the exit code."""

    def run_main(self, protected=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = prune.main(
                ["--work-root", str(self.work), "--workspace", str(self.workspace),
                 "--protected-root", str(protected or self.shared),
                 "--max-age-days", str(MAX_AGE_DAYS)]
            )
        return rc

    def test_b_symlink_loop_in_protected_root_does_not_crash(self):
        loop = self.shared / "loop"
        loop.symlink_to(loop)
        self.assertEqual(self.run_main(), 0)
        self.assertTrue((self.shared / "debug" / "deps").exists())
        self.assertTrue(self.new_tmp.exists())
        self.assertTrue(self.keep.exists())

    def test_c_temp_entry_vanishing_mid_scan_does_not_crash(self):
        real_is_old = prune.is_old

        def vanish(path, max_age_days, now):
            if path.name == "old":
                shutil.rmtree(path)
            return real_is_old(path, max_age_days, now)

        with mock.patch.object(prune, "is_old", vanish):
            self.assertEqual(self.run_main(), 0)
        self.assertTrue(self.new_tmp.exists())
        self.assertTrue(self.keep.exists())
        self.assertTrue((self.shared / "debug" / "deps").exists())

    def test_d_unreadable_temp_root_does_not_crash(self):
        temp = self.work / "_temp"
        real_iterdir = Path.iterdir

        def deny(self_path):
            if self_path == temp:
                raise PermissionError(13, "Permission denied", str(self_path))
            return real_iterdir(self_path)

        with mock.patch.object(Path, "iterdir", deny):
            self.assertEqual(self.run_main(), 0)
        self.assertTrue(self.old_tmp.exists())
        self.assertTrue(self.new_tmp.exists())
        self.assertTrue((self.shared / "debug" / "deps").exists())

    def test_unknown_resolve_state_is_protected(self):
        with mock.patch.object(prune, "resolve", side_effect=RuntimeError("loop")):
            self.assertTrue(prune.is_protected(self.old_tmp, self.shared))


class PerRunnerRoot(Fixture):
    """r3: the whole per-runner target root is protected, siblings included."""

    def setUp(self):
        super().setUp()
        self.root = self.workspace / (prune.TMP_PREFIX + "-targets")
        self.runner_1 = touch_dir(self.root / "runner-1" / "debug" / "incremental")
        self.runner_2 = touch_dir(self.root / "runner-2" / "debug" / "deps", OLD)

    def test_sibling_runner_target_is_protected_from_this_runners_prune(self):
        self.assertTrue(prune.is_protected(self.runner_2, self.root))
        self.assertTrue(prune.is_protected(self.runner_1.parent.parent, self.root))
        self.assertTrue(prune.is_protected(self.root, self.root))

    def test_sibling_runner_target_survives_a_real_run(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = prune.main(
                ["--work-root", str(self.work), "--workspace", str(self.workspace),
                 "--protected-root", str(self.root), "--max-age-days", str(MAX_AGE_DAYS)]
            )
        self.assertEqual(rc, 0)
        self.assertTrue(self.runner_1.exists())
        self.assertTrue(self.runner_2.exists())
        self.assertTrue(self.root.exists())
        self.assertFalse(self.old_tmp.exists())
        self.assertNotIn("runner-", out.getvalue())

    def test_old_flag_name_is_gone(self):
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stderr(io.StringIO()):
                prune.main(["--work-root", str(self.work), "--workspace", str(self.workspace),
                            "--shared-target", str(self.root)])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
