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
from unittest import mock

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


if __name__ == "__main__":
    unittest.main()
