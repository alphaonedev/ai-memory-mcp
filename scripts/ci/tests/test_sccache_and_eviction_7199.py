#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""sccache wiring and idle-target eviction for the linux-fed runners (#7199).

Two groups:

  * scripts/ci/sccache_env.py resolves ``sccache`` from PATH, FAILS CLOSED
    (non-zero exit, one-line reason, nothing written) when it is missing, and
    exports RUSTC_WRAPPER, SCCACHE_DIR, SCCACHE_CACHE_SIZE and SCCACHE_ERROR_LOG
    through $GITHUB_ENV (never a tmp path);
  * scripts/ci/prune_runner_artifacts.py --evict-root removes IDLE per-runner
    cargo targets (never this runner's, never outside the root, never through a
    symlink) and, below the free-space floor, the oldest other targets.

Every tree is built under <repo>/.local-runs/. Run:
python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only.
"""
import io
import os
import shutil
import stat
import sys
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRATCH = REPO / ".local-runs" / "sccache-evict-7199"
sys.path.insert(0, str(REPO / "scripts" / "ci"))
import prune_runner_artifacts as prune  # noqa: E402
import sccache_env  # noqa: E402

DAY = 86400
GIB = 1024 ** 3
ME = "f2-linux-fed"


def make_target(root, name, age_days):
    path = root / name
    (path / "debug" / "deps").mkdir(parents=True)
    f = path / "debug" / "deps" / "x.rlib"
    f.write_text("x", encoding="utf-8")
    stamp = time.time() - age_days * DAY
    for item in (f, f.parent, path / "debug", path):
        os.utime(item, (stamp, stamp))
    return path


def parse_env(path):
    pairs = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", 1)
        pairs[key] = value
    return pairs


class SccacheEnv(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        self.home = SCRATCH / "home"
        self.bin = SCRATCH / "bin"
        self.home.mkdir(parents=True)
        self.bin.mkdir(parents=True)
        self.env_file = SCRATCH / "github.env"
        self.fake = self.bin / "sccache"
        self.fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.fake.chmod(self.fake.stat().st_mode | stat.S_IXUSR)

    def tearDown(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def run_main(self, path_value, extra=None):
        old = os.environ.get("PATH")
        os.environ["PATH"] = path_value
        out, err = io.StringIO(), io.StringIO()
        argv = extra if extra is not None else [
            "--home", str(self.home), "--github-env", str(self.env_file)]
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rc = sccache_env.main(argv)
        finally:
            os.environ["PATH"] = old
        return rc, out.getvalue(), err.getvalue()

    def test_missing_sccache_fails_closed_with_one_line_and_writes_nothing(self):
        rc, _, err = self.run_main(str(SCRATCH / "empty"))
        self.assertEqual(rc, sccache_env.EXIT_MISSING)
        self.assertNotEqual(rc, 0)
        self.assertEqual(len(err.strip().splitlines()), 1)
        self.assertFalse(self.env_file.exists())

    def test_present_sccache_exports_the_four_variables(self):
        rc, _, _ = self.run_main(str(self.bin))
        self.assertEqual(rc, 0)
        pairs = parse_env(self.env_file)
        ci_root = self.home / ".cache" / "ai-memory-ci"
        self.assertEqual(pairs["RUSTC_WRAPPER"], str(self.fake))
        self.assertEqual(pairs["SCCACHE_DIR"], str(ci_root / "sccache"))
        self.assertEqual(pairs["SCCACHE_CACHE_SIZE"], sccache_env.SCCACHE_CACHE_SIZE)
        self.assertEqual(sccache_env.SCCACHE_CACHE_SIZE, "50G")
        self.assertTrue(pairs["SCCACHE_ERROR_LOG"].startswith(str(ci_root)))
        self.assertTrue((ci_root / "sccache").is_dir())
        for value in pairs.values():
            self.assertFalse(value.startswith(("/tmp", "/var/tmp", "/dev/shm")))

    def test_relative_home_is_refused(self):
        rc, _, _ = self.run_main(str(self.bin), ["--home", "rel", "--github-env", str(self.env_file)])
        self.assertEqual(rc, sccache_env.EXIT_USAGE)

    def test_stats_summary_is_capped_at_twelve_lines(self):
        text = "\n".join("line %d" % n for n in range(40))
        self.assertEqual(len(sccache_env.summarise_stats(text)), sccache_env.STATS_MAX_LINES)
        self.assertEqual(sccache_env.STATS_MAX_LINES, 12)

    def test_stats_mode_never_fails_when_sccache_is_missing(self):
        rc, _, _ = self.run_main(str(SCRATCH / "empty"), ["--stats"])
        self.assertEqual(rc, 0)


class Eviction(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        self.home = SCRATCH / "home"
        self.root = self.home / ".cache" / "ai-memory-ci" / "cargo-target"
        self.root.mkdir(parents=True)
        self.me = make_target(self.root, ME, 30)
        self.idle = make_target(self.root, "f2-linux-fed-3", 30)
        self.busy = make_target(self.root, "f2-linux-fed-2", 1)

    def tearDown(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def evict(self, free_bytes, root=None, dry_run=False):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = prune.evict_idle_targets(
                root or self.root, ME, self.home, prune.IDLE_TARGET_DAYS,
                prune.FREE_FLOOR_GIB, time.time(), dry_run=dry_run, free_bytes=free_bytes,
            )
        return rc, out.getvalue()

    @staticmethod
    def plenty(_path):
        return 10_000 * GIB

    @staticmethod
    def starved(_path):
        return 1 * GIB

    def test_constants_are_named(self):
        self.assertEqual(prune.IDLE_TARGET_DAYS, 7)
        self.assertEqual(prune.FREE_FLOOR_GIB, 200)

    def test_idle_other_target_evicted_own_and_busy_kept(self):
        rc, out = self.evict(self.plenty)
        self.assertEqual(rc, 0)
        self.assertFalse(self.idle.exists())
        self.assertTrue(self.me.exists())
        self.assertTrue(self.busy.exists())
        self.assertIn("idle over 7 days", out)
        self.assertIn("eviction summary", out)

    def test_own_target_never_evicted_below_floor(self):
        self.evict(self.starved)
        self.assertTrue(self.me.exists())
        self.assertFalse(self.busy.exists())

    def test_below_floor_evicts_oldest_first_and_stops_at_floor(self):
        middle = make_target(self.root, "f2-linux-fed-4", 3)
        shutil.rmtree(self.idle)

        def free(_path):
            return (500 if not middle.exists() else 1) * GIB

        rc, out = self.evict(free)
        self.assertEqual(rc, 0)
        # middle (3d) is older than busy (1d): evicted first; the floor is then met.
        self.assertFalse(middle.exists())
        self.assertTrue(self.busy.exists())
        self.assertTrue(self.me.exists())
        self.assertIn("free-space floor", out)

    def test_above_floor_keeps_recent_targets(self):
        self.evict(lambda _p: (prune.FREE_FLOOR_GIB + 1) * GIB)
        self.assertTrue(self.busy.exists())

    def test_symlink_entries_are_never_followed_or_deleted(self):
        outside = SCRATCH / "outside"
        (outside / "keep").mkdir(parents=True)
        os.utime(outside, (1, 1))
        link = self.root / "evil"
        link.symlink_to(outside, target_is_directory=True)
        self.evict(self.starved)
        self.assertTrue((outside / "keep").exists())
        self.assertTrue(link.is_symlink())

    def test_symlink_inside_a_target_is_not_followed(self):
        outside = SCRATCH / "outside2"
        (outside / "keep").mkdir(parents=True)
        link = self.idle / "debug" / "ln"
        link.symlink_to(outside, target_is_directory=True)
        old = time.time() - 30 * DAY
        os.utime(link, (old, old), follow_symlinks=False)
        os.utime(link.parent, (old, old))
        self.evict(self.plenty)
        self.assertFalse(self.idle.exists())
        self.assertTrue((outside / "keep").exists())

    def test_non_runner_names_and_plain_files_are_ignored(self):
        odd = self.root / "not a runner!"
        odd.mkdir()
        os.utime(odd, (1, 1))
        stray = self.root / "stray.txt"
        stray.write_text("x", encoding="utf-8")
        self.evict(self.starved)
        self.assertTrue(odd.exists() and stray.exists())

    def test_root_outside_home_or_relative_is_refused(self):
        outside = SCRATCH / "elsewhere"
        make_target(outside, "r1", 30)
        with redirect_stderr(io.StringIO()):
            rc, _ = self.evict(self.starved, root=outside)
            self.assertEqual(rc, prune.EXIT_USAGE)
            self.assertTrue((outside / "r1").exists())
            rc, _ = self.evict(self.starved, root=Path("rel/root"))
            self.assertEqual(rc, prune.EXIT_USAGE)

    def test_home_itself_or_filesystem_root_is_refused(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(self.evict(self.starved, root=self.home)[0], prune.EXIT_USAGE)
            self.assertEqual(self.evict(self.starved, root=Path("/"))[0], prune.EXIT_USAGE)

    def test_cli_requires_runner_name_with_evict_root(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            prune.main(["--work-root", str(SCRATCH), "--workspace", str(SCRATCH),
                        "--protected-root", str(self.root), "--evict-root", str(self.root)])

    def test_cli_runs_prune_then_evicts(self):
        work = SCRATCH / "work"
        ws = work / "repo" / "repo"
        ws.mkdir(parents=True)
        with redirect_stdout(io.StringIO()):
            rc = prune.main(["--work-root", str(work), "--workspace", str(ws),
                             "--protected-root", str(self.root), "--evict-root", str(self.root),
                             "--runner-name", ME, "--home", str(self.home)])
        self.assertEqual(rc, 0)
        self.assertFalse(self.idle.exists())
        self.assertTrue(self.me.exists())

    def test_dry_run_deletes_nothing(self):
        rc, out = self.evict(self.starved, dry_run=True)
        self.assertEqual(rc, 0)
        self.assertTrue(self.idle.exists() and self.busy.exists())
        self.assertIn("would evict", out)


if __name__ == "__main__":
    unittest.main()
