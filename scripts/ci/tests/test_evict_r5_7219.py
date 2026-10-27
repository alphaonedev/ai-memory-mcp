#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""r5 fixes of #7219 (idle-target eviction): fail-closed busy checks, eviction lock, #7284.

  * #7289: ``is_busy`` treats an unreadable subtree, a walk that hits WALK_ENTRY_CAP
    and an unreadable marker as BUSY (never evict on an unknown state);
  * #7292: eviction is serialised against a job start by ``<root>/.evict.lock``;
    the target is renamed to ``.evicting-<name>-<pid>`` under the lock and only then
    deleted, so a job that starts mid-eviction never loses its target or marker;
  * #7284 (and S4 of the r4 review): an unresolvable path is EXIT_USAGE, one
    unresolvable protected-root child no longer disables pruning, drop sites log.

Trees are built under <repo>/.local-runs/. Python 3.9+, standard library only.
"""
import io
import os
import shutil
import sys
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import unittest.mock as mock

REPO = Path(__file__).resolve().parents[3]
SCRATCH = REPO / ".local-runs" / "evict-r5-7219"
sys.path.insert(0, str(REPO / "scripts" / "ci"))
import prune_runner_artifacts as prune  # noqa: E402
import shared_cargo_target as shared  # noqa: E402

DAY = 86400
GIB = 1024 ** 3
ME = "f2-linux-fed"
OTHER = "f2-linux-fed-3"
STARVED_GIB = 1
IDLE_AGE_DAYS = 30
LOCK_TEST_TIMEOUT_SECS = 0.2
RECENT_AGE_DAYS = 2


def make_target(root, name, age_days, files=1):
    path = root / name
    (path / "debug" / "deps").mkdir(parents=True)
    leaves = []
    for number in range(files):
        leaf = path / "debug" / "deps" / ("x%d.rlib" % number)
        leaf.write_text("x", encoding="utf-8")
        leaves.append(leaf)
    stamp = time.time() - age_days * DAY
    for item in leaves + [path / "debug" / "deps", path / "debug", path]:
        os.utime(item, (stamp, stamp))
    return path


def starved(_path):
    return STARVED_GIB * GIB


class Fixture(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        self.home = SCRATCH / "home"
        self.root = self.home / ".cache" / "ai-memory-ci" / "cargo-target"
        self.root.mkdir(parents=True)
        self.me = make_target(self.root, ME, IDLE_AGE_DAYS)
        self.idle = make_target(self.root, OTHER, IDLE_AGE_DAYS)

    def tearDown(self):
        for path in SCRATCH.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o700)
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def evict(self, free_bytes=starved, **kwargs):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = prune.evict_idle_targets(
                self.root, ME, self.home, prune.IDLE_TARGET_DAYS,
                prune.FREE_FLOOR_GIB, time.time(), free_bytes=free_bytes, **kwargs)
        return rc, out.getvalue(), err.getvalue()


@unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root ignores directory modes")
class FailClosedBusyChecks7289(Fixture):
    def test_unreadable_subtree_with_a_fresh_write_is_busy_not_evicted(self):
        locked = self.idle / "debug" / "locked"
        locked.mkdir()
        (locked / "fresh.o").write_text("x", encoding="utf-8")
        old = time.time() - IDLE_AGE_DAYS * DAY
        for item in (locked, locked.parent, self.idle):
            os.utime(item, (old, old))
        locked.chmod(0o300)
        _, out, _ = self.evict()
        self.assertTrue(self.idle.exists())
        self.assertIn("skipped busy %s" % self.idle, out)
        self.assertNotIn("could not evict", out)

    def test_strict_newest_mtime_raises_on_an_unreadable_directory(self):
        locked = self.idle / "debug" / "locked"
        locked.mkdir()
        locked.chmod(0o300)
        with self.assertRaises(OSError):
            prune.newest_mtime(self.idle, strict=True)
        self.assertIsNotNone(prune.newest_mtime(self.idle))

    def test_unreadable_marker_counts_as_fresh(self):
        self.idle.chmod(0o600)
        self.assertTrue(shared.marker_is_fresh(self.idle, time.time()))


class FailClosedBusyChecksPortable7289(Fixture):
    def test_walk_that_hits_the_entry_cap_is_busy_not_evicted(self):
        with mock.patch.object(prune, "WALK_ENTRY_CAP", 1):
            _, out, _ = self.evict()
        self.assertTrue(self.idle.exists())
        self.assertIn("skipped busy %s" % self.idle, out)

    def test_strict_newest_mtime_raises_when_the_cap_is_hit(self):
        with self.assertRaises(RuntimeError):
            prune.newest_mtime(self.idle, max_entries=1, strict=True)
        self.assertIsNotNone(prune.newest_mtime(self.idle, max_entries=1))

    def test_marker_check_is_false_only_for_missing_or_non_directory(self):
        now = time.time()
        self.assertFalse(shared.marker_is_fresh(self.idle, now))
        plain = self.root / "plain-file"
        plain.write_text("x", encoding="utf-8")
        self.assertFalse(shared.marker_is_fresh(plain, now))
        with mock.patch.object(Path, "lstat", side_effect=PermissionError("denied")):
            self.assertTrue(shared.marker_is_fresh(self.idle, now))
        with mock.patch.object(Path, "lstat", side_effect=OSError("io")):
            self.assertTrue(shared.marker_is_fresh(self.idle, now))


class JobStartHelper(Fixture):
    def job_start(self, name=OTHER, *extra):
        """The linux-fed job-start step for runner ``name`` (shared_cargo_target.main)."""
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = shared.main(["--home", str(self.home), "--runner-name", name] + list(extra))
        return rc, err.getvalue()

    def marker_of(self, name=OTHER):
        return self.root / name / shared.IN_USE_MARKER_NAME


class EvictionIsSerialisedAgainstJobStart7292(JobStartHelper):
    def hook_rmtree(self, action):
        """Run ``action`` at the moment eviction calls shutil.rmtree, then delete for real."""
        seen = []
        real = shutil.rmtree

        def hooked(path, *args, **kwargs):
            seen.append(Path(path))
            action(Path(path))
            return real(path, *args, **kwargs)

        return mock.patch.object(prune.shutil, "rmtree", side_effect=hooked), seen

    def test_r1_job_start_between_the_check_and_the_delete_survives(self):
        patch, _ = self.hook_rmtree(lambda _p: self.job_start())
        with patch:
            self.evict()
        self.assertTrue(self.marker_of().exists(), "the started job's marker was deleted")

    def test_r1b_files_written_by_a_job_that_starts_mid_eviction_survive(self):
        big = make_target(self.root, "f2-linux-fed-9", IDLE_AGE_DAYS, files=3000)
        shutil.rmtree(self.idle)
        lost = []
        written = 200

        def job():
            shared.main(["--home", str(self.home), "--runner-name", "f2-linux-fed-9"])
            deps = big / "debug" / "deps"
            for number in range(written):
                try:
                    deps.mkdir(parents=True, exist_ok=True)
                    (deps / ("live%d.o" % number)).write_text("x", encoding="utf-8")
                except OSError:
                    lost.append(number)
                time.sleep(0.0005)

        holder = {}

        def start_job(_path):
            holder["thread"] = threading.Thread(target=job)
            holder["thread"].start()

        patch, _ = self.hook_rmtree(start_job)
        with patch:
            self.evict()
        holder["thread"].join()
        survivors = sorted(p.name for p in (big / "debug" / "deps").glob("live*.o"))
        self.assertEqual(lost, [])
        self.assertEqual(len(survivors), written, "files of the live job were deleted")
        self.assertTrue(self.marker_of("f2-linux-fed-9").exists())

    def test_the_target_is_renamed_under_the_lock_before_the_delete(self):
        calls = []

        def look(path):
            calls.append((path.name, path.parent, self.idle.exists()))

        patch, _ = self.hook_rmtree(look)
        with patch:
            self.evict()
        self.assertEqual(len(calls), 1)
        name, parent, original_exists = calls[0]
        self.assertTrue(name.startswith(".evicting-%s-" % OTHER), name)
        self.assertEqual(parent, self.root.resolve())
        self.assertFalse(original_exists, "the delete must run on the renamed path")

    def test_busy_is_rechecked_under_the_lock(self):
        real = shared.evict_lock
        started = []

        def start_then_lock(*args, **kwargs):
            if not started:
                started.append(True)
                self.job_start()
            return real(*args, **kwargs)

        with mock.patch.object(shared, "evict_lock", side_effect=start_then_lock):
            _, out, _ = self.evict()
        self.assertTrue(self.idle.exists())
        self.assertIn("skipped busy %s" % self.idle, out)

    def test_eviction_skips_when_the_lock_cannot_be_taken_in_time(self):
        # #7295: a recent sibling is left for the floor pass to rank, and the
        # floor is starved, so the old code walked it and blamed the floor.
        make_target(self.root, "f2-linux-fed-4", 0)
        real_walk = prune.newest_mtime
        with shared.evict_lock(self.root, 1.0) as held:
            self.assertTrue(held)
            started = time.monotonic()
            with mock.patch.object(prune, "newest_mtime", side_effect=real_walk) as walk:
                rc, out, err = self.evict(lock_timeout=LOCK_TEST_TIMEOUT_SECS)
            elapsed = time.monotonic() - started
        self.assertEqual(rc, prune.EXIT_OK)
        self.assertTrue(self.idle.exists())
        self.assertIn("skipping eviction:", err)
        self.assertLess(elapsed, 5)
        self.assertNotIn("::warning::", out, "the floor warning blamed the wrong cause")
        self.assertIn("eviction skipped: lock not taken", out)
        ranking = [c for c in walk.call_args_list if c.kwargs.get("max_entries")]
        self.assertEqual(ranking, [], "siblings were ranked after the lock timeout")

    def test_floor_pass_lock_timeout_takes_the_skip_path_7295(self):
        # #7295 floor-pass path: only a recent sibling (the idle pass never takes
        # the lock), a starved floor and a lock held by another holder.
        shutil.rmtree(self.idle)
        recent = make_target(self.root, "f2-linux-fed-4", RECENT_AGE_DAYS)
        with shared.evict_lock(self.root, 1.0) as held:
            self.assertTrue(held)
            rc, out, err = self.evict(lock_timeout=LOCK_TEST_TIMEOUT_SECS)
        self.assertEqual(rc, prune.EXIT_OK)
        self.assertTrue(recent.exists())
        self.assertIn("skipping eviction:", err)
        self.assertNotIn("::warning::", out, "the floor warning blamed the wrong cause")
        self.assertIn("eviction skipped: lock not taken", out)

    def test_job_start_never_fails_or_deadlocks_on_the_lock(self):
        with shared.evict_lock(self.root, 1.0) as held:
            self.assertTrue(held)
            started = time.monotonic()
            rc, err = self.job_start(OTHER, "--lock-timeout", str(LOCK_TEST_TIMEOUT_SECS))
            elapsed = time.monotonic() - started
        self.assertEqual(rc, shared.EXIT_OK)
        self.assertTrue(self.marker_of().exists())
        self.assertIn("warning", err.lower())
        self.assertLess(elapsed, 5)

    def test_job_start_creates_the_lock_file_under_the_root(self):
        self.job_start(OTHER)
        self.assertTrue((self.root / shared.EVICT_LOCK_NAME).is_file())

    def test_the_lock_file_is_never_pruned_or_evicted(self):
        lock = self.root / shared.EVICT_LOCK_NAME
        lock.write_text("", encoding="utf-8")
        old = time.time() - IDLE_AGE_DAYS * DAY
        os.utime(lock, (old, old))
        work = SCRATCH / "runner" / "_work"
        workspace = work / "repo" / "repo"
        workspace.mkdir(parents=True)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            prune.main(["--work-root", str(work), "--workspace", str(workspace),
                        "--protected-root", str(self.root), "--evict-root", str(self.root),
                        "--runner-name", ME, "--home", str(self.home), "--free-floor-gib", "0"])
        self.assertTrue(lock.is_file())
        self.assertFalse(self.idle.exists())

    def test_dot_names_are_not_siblings(self):
        hidden = make_target(self.root, ".hidden", IDLE_AGE_DAYS)
        evicting = make_target(self.root, ".evicting-x-1", 0)
        names = [p.name for p in prune.other_targets(self.root, ME)]
        self.assertNotIn(hidden.name, names)
        self.assertNotIn(evicting.name, names)
        self.assertIn(OTHER, names)

    def test_only_stale_evicting_leftovers_are_swept(self):
        stale = make_target(self.root, ".evicting-dead-11", IDLE_AGE_DAYS)
        fresh = make_target(self.root, ".evicting-live-12", 0)
        link = self.root / ".evicting-link-13"
        outside = SCRATCH / "outside"
        (outside / "keep").mkdir(parents=True)
        link.symlink_to(outside, target_is_directory=True)
        os.utime(link, (1, 1), follow_symlinks=False)
        _, out, _ = self.evict(lambda _p: 10_000 * GIB)
        self.assertFalse(stale.exists())
        self.assertIn("swept stale %s" % stale, out)
        self.assertTrue(fresh.exists(), "a recent leftover may belong to a running eviction")
        self.assertTrue(link.is_symlink())
        self.assertTrue((outside / "keep").exists())


class LeadingDotRunnerNames7293(Fixture):
    """#7293 (N1): the leading-dot namespace under the root is reserved."""

    def test_a_leading_dot_name_is_not_a_valid_runner_name(self):
        for name in (".evicting-x", ".evict.lock", ".hidden", ".", ".."):
            self.assertFalse(shared.valid_runner_name(name), name)
        self.assertTrue(shared.valid_runner_name("f2-linux-fed-1.x_y"))

    def test_job_start_refuses_a_leading_dot_runner_name(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = shared.main(["--home", str(self.home), "--runner-name", ".evicting-x"])
        self.assertEqual(rc, shared.EXIT_USAGE)
        self.assertFalse((self.root / ".evicting-x").exists())

    def test_a_fresh_marker_keeps_an_evicting_directory_from_being_swept(self):
        live = make_target(self.root, ".evicting-live-7", IDLE_AGE_DAYS)
        shared.write_in_use_marker(live, "live")
        old = time.time() - IDLE_AGE_DAYS * DAY
        os.utime(live, (old, old))  # a running build writes below the top level, not in it
        gone = make_target(self.root, ".evicting-dead-8", IDLE_AGE_DAYS)
        with redirect_stdout(io.StringIO()):
            prune.sweep_stale_evicting(self.root, time.time())
        self.assertTrue(live.exists(), "a directory with a fresh in-use marker was swept")
        self.assertFalse(gone.exists())


class BoundedLockHold7294(Fixture):
    """#7294 (C1): the under-lock busy walk is bounded below the job-start timeout."""

    def test_the_walk_deadline_is_below_the_job_start_lock_timeout(self):
        self.assertGreater(prune.EVICT_BUSY_WALK_DEADLINE_SECS, 0)
        self.assertLess(prune.EVICT_BUSY_WALK_DEADLINE_SECS, shared.JOB_START_LOCK_TIMEOUT_SECS)

    def test_a_walk_past_its_deadline_raises_walk_incomplete(self):
        with self.assertRaises(prune.WalkIncomplete):
            prune.newest_mtime(self.idle, strict=True, deadline=time.monotonic() - 1)

    def test_a_walk_that_exceeds_the_deadline_leaves_the_target_as_busy(self):
        with mock.patch.object(prune, "EVICT_BUSY_WALK_DEADLINE_SECS", 0, create=True):
            _, out, _ = self.evict()
        self.assertTrue(self.idle.exists(), "a slow busy walk must count as busy")
        self.assertIn("skipped busy %s" % self.idle, out)

    def test_the_marker_is_checked_again_right_before_the_rename(self):
        # A marker appears only once the strict busy walk has returned. A check
        # placed before the walk (a redundant repeat of is_busy's own look)
        # cannot see it, so only the check right before the rename keeps the
        # target alive.
        sequence = []
        real_walk = prune.newest_mtime

        def recording_walk(*args, **kwargs):
            result = real_walk(*args, **kwargs)
            if kwargs.get("strict"):
                sequence.append("walk")
            return result

        def marker_after_the_walk(_path, _now, *args, **kwargs):
            sequence.append("marker")
            return "walk" in sequence

        with mock.patch.object(prune, "newest_mtime", side_effect=recording_walk), \
                mock.patch.object(shared, "marker_is_fresh", side_effect=marker_after_the_walk):
            _, out, _ = self.evict()
        self.assertEqual(sequence[-2:], ["walk", "marker"], "the re-check must follow the walk")
        self.assertTrue(self.idle.exists(), "a marker written after the walk was ignored")
        self.assertIn("skipped busy %s" % self.idle, out)


class UnresolvablePaths7284(Fixture):
    def loop(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(path)
        return path

    def run_main(self, protected, evict=None):
        work = SCRATCH / "runner" / "_work"
        workspace = work / "repo" / "repo"
        workspace.mkdir(parents=True, exist_ok=True)
        argv = ["--work-root", str(work), "--workspace", str(workspace),
                "--protected-root", str(protected), "--home", str(self.home)]
        if evict is not None:
            argv += ["--evict-root", str(evict), "--runner-name", ME]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = prune.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_s1_loop_as_protected_and_evict_root_is_usage_not_a_traceback(self):
        looped = self.loop(self.home / "loop-root")
        rc, _, err = self.run_main(looped, looped)
        self.assertEqual(rc, prune.EXIT_USAGE)
        self.assertIn("refusing: unresolvable path:", err)

    def test_s1_loop_only_as_evict_root_is_usage(self):
        looped = self.loop(self.home / "loop-root")
        rc, _, err = self.run_main(self.root, looped)
        self.assertEqual(rc, prune.EXIT_USAGE)
        self.assertIn("refusing: unresolvable path:", err)
        self.assertTrue(self.idle.exists())

    def test_s1_loop_only_as_protected_root_is_usage(self):
        looped = self.loop(self.home / "loop-root")
        rc, _, err = self.run_main(looped)
        self.assertEqual(rc, prune.EXIT_USAGE)
        self.assertIn("refusing: unresolvable path:", err)

    def stale_temp(self, name="old-job"):
        stale = SCRATCH / "runner" / "_work" / "_temp" / name
        stale.mkdir(parents=True)
        old = time.time() - IDLE_AGE_DAYS * DAY
        os.utime(stale, (old, old))
        return stale

    def test_s2_one_unresolvable_child_does_not_disable_every_prune(self):
        self.loop(self.root / "loop-child")
        stale = self.stale_temp()
        rc, _, err = self.run_main(self.root)
        self.assertEqual(rc, prune.EXIT_OK)
        self.assertFalse(stale.exists(), "the loop child disabled the prune")
        self.assertIn("protected root child unresolvable: %s" % (self.root / "loop-child"), err)

    def test_s2_an_unresolvable_child_is_protected_by_its_lexical_path(self):
        # #7296: the protected root is reached through a symlinked ancestor, so
        # the loop child's lexical path (<alias>/root/loop-child) differs from the
        # resolved root. The candidate resolves cleanly and is an ancestor of the
        # lexical path only, so just the lexical fallback can protect it. (The
        # loop child itself would be protected by the outer except, which proves
        # nothing about the fallback.)
        lexical_parent = SCRATCH / "lexical"
        real_root = lexical_parent / "real-side" / "real" / "root"
        real_root.mkdir(parents=True)
        alias_side = lexical_parent / "alias-side"
        alias_side.mkdir()
        (alias_side / "alias").symlink_to(real_root.parent, target_is_directory=True)
        protected = alias_side / "alias" / "root"
        self.loop(protected / "loop-child")
        real_resolve = prune.resolve

        def loop_aware_resolve(path):
            # Python 3.13+ resolves a loop without raising (#7326); raise as 3.9-3.12
            # do so the fallback is reached on every interpreter.
            if "loop-child" in Path(path).parts:
                raise RuntimeError("Symlink loop from %s" % path)
            return real_resolve(path)

        unrelated = SCRATCH / "unrelated"
        with mock.patch.object(prune, "resolve", side_effect=loop_aware_resolve), \
                redirect_stderr(io.StringIO()):
            self.assertTrue(prune.is_protected(alias_side, protected))
            self.assertFalse(prune.is_protected(SCRATCH / "runner" / "_work" / "_temp" / "x", protected))
            with mock.patch.object(prune, "_protect_unresolvable_child", return_value=unrelated):
                self.assertFalse(
                    prune.is_protected(alias_side, protected),
                    "dropping the lexical protection must be caught")

    def test_s2_dropped_protected_candidates_are_logged(self):
        protected = self.stale_temp("keep-me")
        rc, out, _ = self.run_main(protected)
        self.assertEqual(rc, prune.EXIT_OK)
        self.assertTrue(protected.exists())
        self.assertIn("skipped protected %s" % protected, out)


if __name__ == "__main__":
    unittest.main()
