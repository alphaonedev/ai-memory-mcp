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
import json
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
import shared_cargo_target as shared  # noqa: E402

# A fake sccache client: logs its arguments plus the server variables it saw
# and, for --show-stats, reports FAKE_SCCACHE_LOCATION (default: SCCACHE_DIR).
FAKE_SCCACHE = """#!%s
import json, os, sys
with open(os.environ["FAKE_SCCACHE_LOG"], "a") as log:
    log.write(json.dumps({
        "args": sys.argv[1:],
        "port": os.environ.get("SCCACHE_SERVER_PORT"),
        "dir": os.environ.get("SCCACHE_DIR"),
        "size": os.environ.get("SCCACHE_CACHE_SIZE"),
        "error_log": os.environ.get("SCCACHE_ERROR_LOG", ""),
        "tracking": "RUNNER_TRACKING_ID" in os.environ,
    }) + "\\n")
if sys.argv[1:] == ["--show-stats"]:
    where = os.environ.get("FAKE_SCCACHE_LOCATION", os.environ.get("SCCACHE_DIR", ""))
    print("Compile requests                      0")
    if where:
        print('Cache location                  Local disk: "%%s"' %% where)
"""

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
        self.calls = SCRATCH / "calls.log"
        self.fake.write_text(FAKE_SCCACHE % sys.executable, encoding="utf-8")
        self.fake.chmod(self.fake.stat().st_mode | stat.S_IXUSR)
        self.saved_env = dict(os.environ)
        os.environ["FAKE_SCCACHE_LOG"] = str(self.calls)
        os.environ.pop("FAKE_SCCACHE_LOCATION", None)
        os.environ["RUNNER_TRACKING_ID"] = "github_runner_tracking_7199"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved_env)
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def logged_calls(self):
        text = self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""
        return [json.loads(line) for line in text.splitlines()]

    def test_foreign_cache_location_is_refused_and_writes_nothing(self):
        # HIGH 1: the dev lanes' sccache server (default port) reports its own store.
        os.environ["FAKE_SCCACHE_LOCATION"] = "/srv/foreign-sccache-store"
        rc, _, err = self.run_main(str(self.bin))
        self.assertNotEqual(rc, 0)
        self.assertEqual(rc, sccache_env.EXIT_WRONG_CACHE)
        self.assertIn("/srv/foreign-sccache-store", err)
        self.assertFalse(self.env_file.exists())

    def test_unreadable_stats_are_refused_and_write_nothing(self):
        os.environ["FAKE_SCCACHE_LOCATION"] = ""
        rc, _, _ = self.run_main(str(self.bin))
        self.assertEqual(rc, sccache_env.EXIT_WRONG_CACHE)
        self.assertFalse(self.env_file.exists())

    def test_dedicated_server_is_started_with_the_ci_environment(self):
        rc, _, _ = self.run_main(str(self.bin))
        self.assertEqual(rc, 0)
        ci_root = self.home / ".cache" / "ai-memory-ci"
        calls = self.logged_calls()
        self.assertEqual(calls[0]["args"], ["--start-server"])
        self.assertEqual(calls[-1]["args"], ["--show-stats"])
        for call in calls:
            self.assertEqual(call["port"], str(sccache_env.SCCACHE_SERVER_PORT))
            self.assertEqual(call["dir"], str(ci_root / "sccache"))
            self.assertEqual(call["size"], sccache_env.SCCACHE_CACHE_SIZE)
            self.assertTrue(call["error_log"].startswith(str(ci_root)))
            self.assertFalse(call["tracking"], "RUNNER_TRACKING_ID must not reach the server")
        self.assertEqual(parse_env(self.env_file)["SCCACHE_SERVER_PORT"],
                         str(sccache_env.SCCACHE_SERVER_PORT))

    def test_server_port_is_not_the_dev_lane_default(self):
        self.assertNotEqual(sccache_env.SCCACHE_SERVER_PORT, sccache_env.SCCACHE_DEFAULT_PORT)
        self.assertEqual(sccache_env.SCCACHE_DEFAULT_PORT, 4226)

    def test_cache_root_derives_from_the_shared_target_root(self):
        self.assertEqual(sccache_env.CACHE_ROOT_RELATIVE, shared.TARGET_ROOT_RELATIVE.parent)

    def test_stop_server_uses_the_same_port_and_never_fails(self):
        rc, _, _ = self.run_main(str(self.bin), ["--stop", "--home", str(self.home),
                                                 "--runner-name", ME])
        self.assertEqual(rc, 0)
        call = self.logged_calls()[-1]
        self.assertEqual(call["args"], ["--stop-server"])
        self.assertEqual(call["port"], str(sccache_env.SCCACHE_SERVER_PORT))

    def test_stop_server_is_skipped_while_a_sibling_job_is_running(self):
        root = self.home / ".cache" / "ai-memory-ci" / "cargo-target"
        (root / "f2-linux-fed-2").mkdir(parents=True)
        shared.write_in_use_marker(root / "f2-linux-fed-2", "f2-linux-fed-2")
        rc, out, _ = self.run_main(str(self.bin), ["--stop", "--home", str(self.home),
                                                   "--runner-name", ME])
        self.assertEqual(rc, 0)
        self.assertEqual(self.logged_calls(), [])
        self.assertIn("sibling", out)

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
            self.assertEqual(rc, prune.EXIT_OK)
            self.assertTrue((outside / "r1").exists())
            rc, _ = self.evict(self.starved, root=Path("rel/root"))
            self.assertEqual(rc, prune.EXIT_OK)

    def test_home_itself_or_filesystem_root_is_refused(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(self.evict(self.starved, root=self.home)[0], prune.EXIT_OK)
            self.assertEqual(self.evict(self.starved, root=Path("/"))[0], prune.EXIT_OK)

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

    def set_marker(self, target, age_secs):
        shared.write_in_use_marker(target, target.name)
        stamp = time.time() - age_secs
        os.utime(target / shared.IN_USE_MARKER_NAME, (stamp, stamp))
        os.utime(target, (time.time() - 30 * DAY,) * 2)

    def test_fresh_marker_target_is_never_evicted_below_the_floor(self):
        # HIGH 2: an old-mtime target with a fresh marker is a running job.
        self.set_marker(self.idle, 60)
        _, out = self.evict(self.starved)
        self.assertTrue(self.idle.exists())
        self.assertIn("skipped busy %s" % self.idle, out)

    def test_fresh_marker_target_survives_the_idle_pass(self):
        self.set_marker(self.idle, 60)
        self.evict(self.plenty)
        self.assertTrue(self.idle.exists())

    def test_expired_marker_with_old_mtime_is_evicted(self):
        self.set_marker(self.idle, shared.IN_USE_MARKER_MAX_AGE_SECS + 60)
        self.evict(self.starved)
        self.assertFalse(self.idle.exists())

    def test_recent_write_without_marker_is_never_evicted(self):
        fresh = self.busy / "debug" / "deps" / "fresh.o"
        fresh.write_text("x", encoding="utf-8")
        _, out = self.evict(self.starved)
        self.assertTrue(self.busy.exists())
        self.assertIn("skipped busy", out)

    def test_unmet_floor_prints_a_warning(self):
        self.set_marker(self.idle, 60)
        self.set_marker(self.busy, 60)
        _, out = self.evict(self.starved)
        self.assertIn("::warning::", out)

    def test_walk_is_capped(self):
        count = prune.WALK_ENTRY_CAP
        self.assertGreater(count, 0)
        self.assertEqual(prune.BUSY_MTIME_MINUTES, 30)
        self.assertEqual(shared.IN_USE_MARKER_MAX_AGE_SECS, 6 * 3600)
        self.assertEqual(shared.IN_USE_MARKER_NAME, ".in-use")
        old = time.time() - 30 * DAY
        self.assertLess(prune.newest_mtime(self.idle, max_entries=0), old + DAY)

    def test_target_step_writes_and_post_job_prune_clears_the_marker(self):
        env_file = SCRATCH / "gh.env"
        with redirect_stdout(io.StringIO()):
            rc = shared.main(["--home", str(self.home), "--runner-name", ME,
                              "--github-env", str(env_file)])
        self.assertEqual(rc, 0)
        marker = self.me / shared.IN_USE_MARKER_NAME
        self.assertIn(ME, marker.read_text(encoding="utf-8"))
        work = SCRATCH / "work"
        ws = work / "repo" / "repo"
        ws.mkdir(parents=True)
        with redirect_stdout(io.StringIO()):
            prune.main(["--work-root", str(work), "--workspace", str(ws),
                        "--protected-root", str(self.root), "--evict-root", str(self.root),
                        "--runner-name", ME, "--home", str(self.home)])
        self.assertFalse(marker.exists())

    def test_root_under_home_that_is_not_the_cache_root_is_refused(self):
        # LOW 5: ~/.cache is under the home but is not the runner target root.
        cache = self.home / ".cache"
        pip = make_target(cache, "pip", 30)
        with redirect_stderr(io.StringIO()) as err:
            rc, _ = self.evict(self.starved, root=cache)
        self.assertEqual(rc, prune.EXIT_OK)
        self.assertTrue(pip.exists())
        self.assertIn("runner target root", err.getvalue())

    def test_shared_literals_are_imported_not_duplicated(self):
        # LOW 6: one definition of the runner-name rules.
        self.assertIs(prune.shared, shared)
        self.assertFalse(hasattr(prune, "RUNNER_NAME_PATTERN"))
        self.assertFalse(hasattr(prune, "DOT_NAMES"))

    def test_dry_run_deletes_nothing(self):
        rc, out = self.evict(self.starved, dry_run=True)
        self.assertEqual(rc, 0)
        self.assertTrue(self.idle.exists() and self.busy.exists())
        self.assertIn("would evict", out)


if __name__ == "__main__":
    unittest.main()
