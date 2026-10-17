"""Unit tests for scripts/ci-sweep-target.py (#7160).

Every tree is synthetic and lives under the worktree's own ``.local-runs/``
directory, never under a tmpfs path.
"""

import contextlib
import fcntl
import importlib.util
import io
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "ci-sweep-target.py"
SCRATCH_ROOT = REPO_ROOT / ".local-runs"
SWEPT_SUBDIRS = ("deps", "incremental", "build", ".fingerprint")
EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_BAD_CAP = 3
EXIT_UNREADABLE = 4
EXIT_USAGE = 5
ENTRY_BYTES = 1000
BASE_MTIME = 1_700_000_000
MTIME_STEP = 100
PRECIOUS_BYTES = 50_000


def write_blob(path, size=ENTRY_BYTES):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)


def set_age(path, rank):
    """Higher rank means a newer mtime."""
    stamp = BASE_MTIME + rank * MTIME_STEP
    os.utime(str(path), (stamp, stamp), follow_symlinks=False)


class SweepTestCase(unittest.TestCase):
    def setUp(self):
        SCRATCH_ROOT.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="sweep7160-", dir=str(SCRATCH_ROOT)))
        self.workspace = self.root / "ws"
        self.target = self.workspace / "target"
        self.debug = self.target / "debug"
        self.debug.mkdir(parents=True)
        self.locked = []

    def tearDown(self):
        for locked in self.locked:
            locked.chmod(0o755)
        resolved = self.root.resolve()
        if str(resolved).startswith(str(SCRATCH_ROOT.resolve())):
            shutil.rmtree(str(resolved), ignore_errors=True)

    def run_sweep(self, *extra, workspace=None, target=None):
        env = dict(os.environ)
        env.pop("GITHUB_WORKSPACE", None)
        if workspace is not False:
            env["GITHUB_WORKSPACE"] = str(workspace or self.workspace)
        cmd = [sys.executable, str(SCRIPT), "--target", str(target or self.target)]
        cmd.extend(extra)
        return subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)

    def make_entries(self, count):
        """Create count files in deps, oldest first, and return their paths."""
        paths = []
        for idx in range(count):
            entry = self.debug / "deps" / "lib{}.rlib".format(idx)
            write_blob(entry)
            set_age(entry, idx)
            paths.append(entry)
        return paths


class SweepTests(SweepTestCase):
    def test_cap_respected_and_oldest_removed_first(self):
        paths = self.make_entries(5)
        res = self.run_sweep("--max-bytes", str(2 * ENTRY_BYTES + 10))
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        survivors = [p for p in paths if p.exists()]
        self.assertEqual(survivors, paths[-2:])
        self.assertIn("removed=3", res.stdout)
        self.assertIn("before=5000", res.stdout)
        self.assertIn("after=2000", res.stdout)

    def test_under_cap_removes_nothing(self):
        paths = self.make_entries(3)
        res = self.run_sweep("--max-bytes", str(10 * ENTRY_BYTES))
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertTrue(all(p.exists() for p in paths))
        self.assertIn("removed=0", res.stdout)

    def test_refuses_target_outside_workspace(self):
        outside = self.root / "elsewhere" / "target"
        victim = outside / "debug" / "deps" / "a.rlib"
        write_blob(victim)
        res = self.run_sweep("--max-bytes", "1", target=outside)
        self.assertEqual(res.returncode, EXIT_REFUSED)
        self.assertIn(str(outside), res.stderr)
        self.assertTrue(victim.exists())

    def test_refuses_without_workspace_env(self):
        victim = self.make_entries(1)[0]
        res = self.run_sweep("--max-bytes", "1", workspace=False)
        self.assertEqual(res.returncode, EXIT_REFUSED)
        self.assertTrue(victim.exists())

    def test_allow_root_overrides_refusal(self):
        outside = self.root / "elsewhere" / "target"
        victim = outside / "debug" / "deps" / "a.rlib"
        write_blob(victim)
        res = self.run_sweep("--max-bytes", "1", "--allow-root", "--within",
                             str(self.root / "elsewhere"), target=outside)
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertFalse(victim.exists())

    def test_dry_run_removes_nothing(self):
        paths = self.make_entries(4)
        res = self.run_sweep("--max-bytes", "1", "--dry-run")
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertTrue(all(p.exists() for p in paths))
        self.assertIn("removed=4", res.stdout)
        self.assertIn("dry-run", res.stdout)

    def test_symlink_not_followed(self):
        outside = self.root / "outside"
        keep = outside / "precious.bin"
        write_blob(keep, PRECIOUS_BYTES)
        link = self.debug / "deps" / "link-to-outside"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(outside, target_is_directory=True)
        set_age(link, 0)
        res = self.run_sweep("--max-bytes", "1")
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertFalse(link.is_symlink())
        self.assertTrue(keep.exists())
        self.assertNotIn("before=50", res.stdout)

    def test_symlinked_subdir_is_refused(self):
        outside = self.root / "outside2"
        keep = outside / "precious.bin"
        write_blob(keep)
        (self.debug / "deps").symlink_to(outside, target_is_directory=True)
        res = self.run_sweep("--max-bytes", "1")
        self.assertEqual(res.returncode, EXIT_REFUSED, res.stderr)
        self.assertIn("deps", res.stderr)
        self.assertTrue(keep.exists())

    def test_symlinked_debug_dir_is_refused(self):
        outside = self.root / "outside3"
        victim = outside / "deps" / "victim.rlib"
        write_blob(victim)
        shutil.rmtree(str(self.debug))
        self.debug.symlink_to(outside, target_is_directory=True)
        res = self.run_sweep("--max-bytes", "1")
        self.assertEqual(res.returncode, EXIT_REFUSED, res.stderr)
        self.assertIn(str(self.debug), res.stderr)
        self.assertTrue(victim.exists())

    def test_nonpositive_max_bytes_is_rejected(self):
        entry = self.make_entries(1)[0]
        for bad in ("0", "-1"):
            res = self.run_sweep("--max-bytes", bad)
            self.assertEqual(res.returncode, EXIT_BAD_CAP, res.stderr)
            self.assertIn("--max-bytes", res.stderr)
            self.assertTrue(entry.exists())

    @unittest.skipIf(os.geteuid() == 0, "root can read a mode-000 directory")
    def test_unreadable_dir_warns_without_traceback(self):
        deps = self.debug / "deps"
        write_blob(deps / "a.rlib")
        deps.chmod(0)
        self.locked.append(deps)
        res = self.run_sweep("--max-bytes", "10")
        self.assertEqual(res.returncode, EXIT_UNREADABLE, res.stderr)
        self.assertNotIn("Traceback", res.stderr)
        self.assertIn(str(deps), res.stderr)

    @unittest.skipIf(os.geteuid() == 0, "root can read a mode-000 directory")
    def test_unreadable_dir_does_not_stop_other_dirs(self):
        deps = self.debug / "deps"
        write_blob(deps / "a.rlib")
        deps.chmod(0)
        self.locked.append(deps)
        other = self.debug / "build" / "pkg"
        write_blob(other)
        res = self.run_sweep("--max-bytes", "10")
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertNotIn("Traceback", res.stderr)
        self.assertIn(str(deps), res.stderr)
        self.assertFalse(other.exists())

    def test_unparsable_max_bytes_has_its_own_exit_code_7167(self):
        entry = self.make_entries(1)[0]
        for bad in ("abc", "", "1.5"):
            res = self.run_sweep("--max-bytes", bad)
            self.assertEqual(res.returncode, EXIT_USAGE, (bad, res.stderr))
            self.assertNotEqual(res.returncode, EXIT_REFUSED)
            self.assertIn("--max-bytes", res.stderr)
            self.assertTrue(entry.exists())

    def test_other_argument_errors_use_usage_exit_code_7167(self):
        entry = self.make_entries(1)[0]
        for extra in (("--bogus-flag",), ("--max-bytes",), ()):
            res = self.run_sweep(*extra)
            self.assertEqual(res.returncode, EXIT_USAGE, (extra, res.stderr))
            self.assertTrue(entry.exists())

    def test_help_exits_zero(self):
        res = self.run_sweep("--help")
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)

    @unittest.skipIf(os.geteuid() == 0, "root can read a mode-000 directory")
    def test_unreadable_nested_dir_warns_7160_s3(self):
        nested = self.debug / "deps" / "pkg" / "sub"
        write_blob(nested / "inner.o")
        write_blob(self.debug / "deps" / "pkg" / "top.o")
        nested.chmod(0)
        self.locked.append(nested)
        res = self.run_sweep("--max-bytes", str(100 * ENTRY_BYTES), "--dry-run")
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertNotIn("Traceback", res.stderr)
        self.assertIn("cannot read {}".format(nested), res.stderr)

    def test_nothing_outside_four_dirs_touched(self):
        swept = []
        for rank, sub in enumerate(SWEPT_SUBDIRS):
            entry = self.debug / sub / "entry-{}".format(sub.strip("."))
            write_blob(entry)
            set_age(entry, rank)
            swept.append(entry)
        bystanders = [
            self.debug / "ai-memory",
            self.debug / "examples" / "demo",
            self.target / "release" / "ai-memory",
            self.target / "CACHEDIR.TAG",
            self.workspace / "src" / "main.rs",
        ]
        for path in bystanders:
            write_blob(path)
        res = self.run_sweep("--max-bytes", "1")
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertFalse(any(p.exists() for p in swept))
        self.assertTrue(all(p.exists() for p in bystanders))
        self.assertIn("removed=4", res.stdout)

    def test_oldest_across_all_four_dirs(self):
        newest = self.debug / "deps" / "new.rlib"
        oldest = self.debug / "build" / "old-pkg" / "out.o"
        write_blob(newest)
        write_blob(oldest)
        set_age(newest, 10)
        set_age(oldest.parent, 1)
        res = self.run_sweep("--max-bytes", str(ENTRY_BYTES + 10))
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertTrue(newest.exists())
        self.assertFalse(oldest.parent.exists())


def load_script_module():
    spec = importlib.util.spec_from_file_location("ci_sweep_target_under_test", str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ScanDeleteRaceTests(SweepTestCase):
    """#7160 S1: a swap between the scan and the delete must never be followed."""

    def run_main_with_swap(self, swap):
        module = load_script_module()
        real_collect = module.collect_entries

        def collect_then_swap(*args, **kwargs):
            entries = real_collect(*args, **kwargs)
            swap()
            return entries

        module.collect_entries = collect_then_swap
        err = io.StringIO()
        out = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            rc = module.main(["--target", str(self.target), "--max-bytes", "1",
                              "--allow-root", "--within", str(self.workspace)])
        return rc, err.getvalue(), out.getvalue()

    def test_swept_dir_swapped_for_symlink_is_refused(self):
        self.make_entries(2)
        outside = self.root / "outside"
        outside_files = [outside / "lib0.rlib", outside / "lib1.rlib"]
        for path in outside_files:
            write_blob(path, PRECIOUS_BYTES)
        deps = self.debug / "deps"

        def swap():
            deps.rename(self.debug / "deps.moved")
            deps.symlink_to(outside, target_is_directory=True)

        rc, err, _out = self.run_main_with_swap(swap)
        self.assertEqual(rc, EXIT_REFUSED, err)
        self.assertIn("deps", err)
        self.assertIn("refused", err)
        self.assertTrue(all(path.exists() for path in outside_files))
        self.assertTrue(deps.is_symlink())

    def test_entry_dir_swapped_for_symlink_is_unlinked_not_followed(self):
        pkg = self.debug / "deps" / "pkg"
        write_blob(pkg / "inner.o")
        outside = self.root / "outside"
        keep = outside / "inner.o"
        write_blob(keep, PRECIOUS_BYTES)

        def swap():
            shutil.rmtree(str(pkg))
            pkg.symlink_to(outside, target_is_directory=True)

        rc, err, _out = self.run_main_with_swap(swap)
        self.assertEqual(rc, EXIT_OK, err)
        self.assertTrue(keep.exists())
        self.assertFalse(pkg.is_symlink())


class TargetWalkTests(SweepTestCase):
    """#7160 R2-F1 / S4: the target and every ancestor are opened without following links."""

    def make_outside(self):
        outside = self.root / "outside"
        files = []
        for idx in range(3):
            path = outside / "debug" / "deps" / "lib{}.rlib".format(idx)
            write_blob(path, PRECIOUS_BYTES)
            files.append(path)
        return outside, files

    def test_target_swapped_for_symlink_before_first_open_is_refused(self):
        self.make_entries(2)
        outside, outside_files = self.make_outside()
        module = load_script_module()
        real_is_under = module.is_under
        target = self.target

        def is_under_then_swap(path, root):
            verdict = real_is_under(path, root)
            moved = target.parent / "target.moved"
            if not moved.exists():
                target.rename(moved)
                target.symlink_to(outside, target_is_directory=True)
            return verdict

        module.is_under = is_under_then_swap
        err = io.StringIO()
        out = io.StringIO()
        env = {module.WORKSPACE_ENV: str(self.workspace)}
        with unittest.mock.patch.dict(os.environ, env), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            rc = module.main(["--target", str(self.target), "--max-bytes", "1"])
        self.assertEqual(rc, EXIT_REFUSED, err.getvalue())
        self.assertIn("refused", err.getvalue())
        self.assertIn("target", err.getvalue())
        self.assertTrue(all(path.exists() for path in outside_files))

    def test_allow_root_refuses_symlink_escaping_the_root_7160_s4(self):
        """#7297 S11: a symlinked target is no longer refused as such (a symlinked
        PARENT is the f2 layout); it is refused only when it resolves outside the
        ``--within`` root. What stays refused: the escape, and (unchanged, no
        ``--allow-root``) any ``--target`` outside ``$GITHUB_WORKSPACE``."""
        self.make_entries(2)
        outside, outside_files = self.make_outside()
        link = self.root / "linked-target"
        link.symlink_to(outside, target_is_directory=True)
        result = self.run_sweep("--max-bytes", "1", "--allow-root", "--within",
                                str(self.workspace), target=link)
        self.assertEqual(result.returncode, EXIT_REFUSED, result.stderr)
        self.assertIn("is not strictly inside", result.stderr)
        self.assertTrue(all(path.exists() for path in outside_files))

    def make_symlinked_root(self):
        """The f2 layout: root R is a symlink to a real directory on 'another disk'."""
        disk = self.root / "mnt-t9" / "ai-memory-ci"
        disk.mkdir(parents=True)
        root = self.root / "home" / ".cache" / "ai-memory-ci"
        root.parent.mkdir(parents=True)
        root.symlink_to(disk, target_is_directory=True)
        return root, disk

    def test_allow_root_within_sweeps_target_under_symlinked_parent_7297_s11(self):
        root, disk = self.make_symlinked_root()
        target = root / "cargo-target" / "x"
        deps = disk / "cargo-target" / "x" / "debug" / "deps"
        for idx in range(4):
            write_blob(deps / "lib{}.rlib".format(idx))
            set_age(deps / "lib{}.rlib".format(idx), idx)
        sibling = disk / "cargo-target" / "y" / "debug" / "deps" / "keep.rlib"
        write_blob(sibling)
        result = self.run_sweep("--max-bytes", "1500", "--allow-root", "--within",
                                str(root), target=target)
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertIn("removed=3", result.stdout)
        self.assertIn("freed=3000", result.stdout)
        self.assertEqual(len(list(deps.iterdir())), 1)
        self.assertTrue(sibling.exists())

    def test_allow_root_refuses_target_resolving_outside_root_7297_s11(self):
        root, disk = self.make_symlinked_root()
        sibling_dir = self.root / "sibling"
        victim = sibling_dir / "debug" / "deps" / "a.rlib"
        write_blob(victim)
        (disk / "cargo-target").mkdir()
        (disk / "cargo-target" / "x").symlink_to(sibling_dir, target_is_directory=True)
        result = self.run_sweep("--max-bytes", "1", "--allow-root", "--within",
                                str(root), target=root / "cargo-target" / "x")
        self.assertEqual(result.returncode, EXIT_REFUSED, result.stderr)
        self.assertIn(str(sibling_dir.resolve()), result.stderr)
        self.assertIn(str(disk.resolve()), result.stderr)
        self.assertTrue(victim.exists())

    def test_allow_root_refuses_target_equal_to_root_7297_s11(self):
        root, disk = self.make_symlinked_root()
        victim = disk / "debug" / "deps" / "a.rlib"
        write_blob(victim)
        result = self.run_sweep("--max-bytes", "1", "--allow-root", "--within",
                                str(root), target=root)
        self.assertEqual(result.returncode, EXIT_REFUSED, result.stderr)
        self.assertTrue(victim.exists())

    def test_allow_root_without_within_is_a_usage_error_7297_s11(self):
        self.make_entries(2)
        result = self.run_sweep("--max-bytes", "1", "--allow-root")
        self.assertEqual(result.returncode, EXIT_USAGE, result.stderr)
        self.assertIn("--within", result.stderr)
        self.assertEqual(len(list((self.debug / "deps").iterdir())), 2)

    def test_within_without_allow_root_is_a_usage_error_7297_s11(self):
        self.make_entries(2)
        result = self.run_sweep("--max-bytes", "1", "--within", str(self.workspace))
        self.assertEqual(result.returncode, EXIT_USAGE, result.stderr)
        self.assertEqual(len(list((self.debug / "deps").iterdir())), 2)

    def test_within_filesystem_root_is_refused_7297_s11(self):
        self.make_entries(2)
        result = self.run_sweep("--max-bytes", "1", "--allow-root", "--within", os.sep)
        self.assertEqual(result.returncode, EXIT_REFUSED, result.stderr)
        self.assertEqual(len(list((self.debug / "deps").iterdir())), 2)

    def test_workspace_target_without_allow_root_unchanged_7297_s11(self):
        self.make_entries(3)
        result = self.run_sweep("--max-bytes", "1")
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertIn("removed=3", result.stdout)

    def test_target_that_is_a_regular_file_says_not_a_directory_7160_s8(self):
        not_dir = self.root / "target-is-a-file"
        not_dir.write_bytes(b"x")
        for extra in ((), ("--allow-root", "--within", str(self.root))):
            workspace = self.root if not extra else None
            result = self.run_sweep("--max-bytes", "1", *extra, target=not_dir,
                                    workspace=workspace)
            self.assertEqual(result.returncode, EXIT_REFUSED, result.stderr)
            self.assertIn("refused: {} is not a directory".format(not_dir.resolve()),
                          result.stderr)
            self.assertNotIn("replaced", result.stderr)
        self.assertTrue(not_dir.exists())

    def test_parent_opens_use_o_path_flags_7160_s7(self):
        """Only the listed directories are opened readable; every parent uses PARENT_OPEN_FLAGS."""
        self.make_entries(2)
        module = load_script_module()
        want_parent = getattr(os, "O_PATH", 0) | os.O_NOFOLLOW | os.O_DIRECTORY
        self.assertEqual(module.PARENT_OPEN_FLAGS, want_parent)
        real_open = os.open
        opened = []

        def recording_open(path, flags, *args, **kwargs):
            opened.append((str(path), flags))
            return real_open(path, flags, *args, **kwargs)

        out = io.StringIO()
        with unittest.mock.patch.object(module.os, "open", recording_open), \
                contextlib.redirect_stdout(out):
            rc = module.main(["--target", str(self.target), "--max-bytes", "1",
                              "--allow-root", "--within", str(self.workspace)])
        self.assertEqual(rc, EXIT_OK)
        by_name = dict(opened)
        for parent in (os.sep, "debug") + tuple(
                part for part in os.path.realpath(str(self.target)).split(os.sep) if part):
            self.assertEqual(by_name[parent], want_parent, parent)
        self.assertEqual(by_name["deps"], module.OPEN_DIR_FLAGS)

    def test_search_only_parent_is_swept_7160_s7(self):
        if not hasattr(os, "O_PATH"):
            self.skipTest("os.O_PATH is unavailable on this platform (macOS): every "
                          "parent of the target must be readable, as documented")
        self.make_entries(3)
        self.workspace.chmod(0o311)
        self.locked.append(self.workspace)
        canonical = Path(os.path.realpath(str(self.target)))
        result = self.run_sweep("--max-bytes", "1", "--allow-root", "--within",
                                str(self.workspace), target=canonical)
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertIn("removed=3", result.stdout)

    def test_allow_root_accepts_canonical_target(self):
        self.make_entries(3)
        canonical = Path(os.path.realpath(str(self.target)))
        result = self.run_sweep("--max-bytes", "1500", "--allow-root", "--within",
                                str(self.workspace), target=canonical)
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)


class EvictLockTests(SweepTestCase):
    """#7297 / #7219: the shared_target sweep coexists with idle-target eviction.

    #7219 keeps ``<root>/.evict.lock`` (flock), ``<root>/.evicting-<name>-<pid>``
    directories and the in-use marker ``<target>/.in-use`` (beside ``debug``,
    not inside it). The sweep reads and deletes only the top-level entries of
    ``<target>/debug/{deps,incremental,build,.fingerprint}``.
    """

    LOCK_NAME = ".evict.lock"

    def setUp(self):
        super().setUp()
        self.cache_root = self.root / "cache" / "cargo-target"
        self.runner = self.cache_root / "f2-linux-fed"
        self.deps = self.runner / "debug" / "deps"
        for idx in range(4):
            entry = self.deps / "lib{}.rlib".format(idx)
            write_blob(entry)
            set_age(entry, idx)
        self.lock_path = self.cache_root / self.LOCK_NAME

    def sweep(self, *extra):
        return self.run_sweep("--max-bytes", "1500", "--allow-root", "--within",
                              str(self.cache_root), *extra, target=self.runner)

    def test_free_lock_sweeps_and_releases_7297_lock(self):
        result = self.sweep("--lock", str(self.lock_path))
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertIn("removed=3", result.stdout)
        self.assertEqual(len(list(self.deps.iterdir())), 1)
        fd = os.open(str(self.lock_path), os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def test_held_lock_skips_with_one_warning_and_rc0_7297_lock(self):
        self.lock_path.write_bytes(b"")
        fd = os.open(str(self.lock_path), os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            started = time.monotonic()
            result = self.sweep("--lock", str(self.lock_path), "--lock-timeout", "1")
            elapsed = time.monotonic() - started
        finally:
            os.close(fd)
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertEqual(len(list(self.deps.iterdir())), 4)
        warnings = [ln for ln in result.stdout.splitlines() if "not taken within" in ln
                    and ln.startswith("::warning::")]
        self.assertEqual(len(warnings), 1, result.stdout)
        self.assertIn("sweep skipped", warnings[0])
        self.assertNotIn("ci-sweep-target: target=", result.stdout)
        self.assertLess(elapsed, 15, "the wait must be bounded by --lock-timeout")

    def test_lock_released_while_waiting_lets_the_sweep_run_7297_lock(self):
        self.lock_path.write_bytes(b"")
        with open(str(self.lock_path), "r+b") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            # close() is idempotent: the timer releases the lock, the with block backs it up.
            timer = threading.Timer(0.5, lock_fh.close)
            timer.start()
            try:
                result = self.sweep("--lock", str(self.lock_path), "--lock-timeout", "20")
            finally:
                timer.join()
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertIn("removed=3", result.stdout)

    def test_lock_outside_the_within_root_is_refused_7297_lock(self):
        stray = self.root / "stray.lock"
        result = self.sweep("--lock", str(stray))
        self.assertEqual(result.returncode, EXIT_REFUSED, result.stderr)
        self.assertEqual(len(list(self.deps.iterdir())), 4)
        self.assertFalse(stray.exists())

    def test_symlinked_lock_file_is_not_followed_7297_lock(self):
        victim = self.root / "victim"
        victim.write_bytes(b"keep")
        self.lock_path.symlink_to(victim)
        result = self.sweep("--lock", str(self.lock_path), "--lock-timeout", "1")
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertIn("::warning::", result.stdout)
        self.assertIn("sweep skipped", result.stdout)
        self.assertEqual(victim.read_bytes(), b"keep")
        self.assertEqual(len(list(self.deps.iterdir())), 4)

    def test_lock_without_allow_root_is_a_usage_error_7297_lock(self):
        self.make_entries(2)
        result = self.run_sweep("--max-bytes", "1", "--lock", str(self.lock_path))
        self.assertEqual(result.returncode, EXIT_USAGE, result.stderr)
        self.assertEqual(len(list((self.debug / "deps").iterdir())), 2)

    def test_marker_lock_file_and_evicting_dirs_are_never_swept_7297_lock(self):
        marker = self.runner / ".in-use"
        marker.write_text("f2-linux-fed 2026-10-16T00:00:00Z\n")
        self.lock_path.write_bytes(b"")
        evicting = self.cache_root / ".evicting-f2-linux-fed-2-4242"
        write_blob(evicting / "debug" / "deps" / "old.rlib")
        sibling = self.cache_root / "f2-linux-fed-2" / "debug" / "deps" / "keep.rlib"
        write_blob(sibling)
        result = self.run_sweep("--max-bytes", "1", "--allow-root", "--within",
                                str(self.cache_root), "--lock", str(self.lock_path),
                                target=self.runner)
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertIn("removed=4", result.stdout)
        self.assertTrue(marker.exists())
        self.assertTrue(self.lock_path.exists())
        self.assertTrue((evicting / "debug" / "deps" / "old.rlib").exists())
        self.assertTrue(sibling.exists())

    def test_evicting_dir_next_to_a_swept_dir_is_not_an_entry_7297_lock(self):
        """An eviction-leftover-named directory beside ``debug`` in the target is
        outside every swept directory, so it is never read or deleted."""
        evicting = self.runner / ".evicting-x-1"
        write_blob(evicting / "a")
        result = self.sweep()
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertTrue(evicting.exists())


class LockHardeningTests(SweepTestCase):
    """#7297 round 6: --lock-timeout validation, true skip causes, annotations,
    non-UTF-8 paths and the lock wait/hold report."""

    def setUp(self):
        super().setUp()
        self.cache_root = self.root / "cache" / "cargo-target"
        self.runner = self.cache_root / "f2-linux-fed"
        self.deps = self.runner / "debug" / "deps"
        for idx in range(4):
            entry = self.deps / "lib{}.rlib".format(idx)
            write_blob(entry)
            set_age(entry, idx)
        self.lock_path = self.cache_root / ".evict.lock"

    def sweep(self, *extra, target=None):
        return self.run_sweep("--max-bytes", "1500", "--allow-root", "--within",
                              str(self.cache_root), *extra, target=target or self.runner)

    def assert_untouched(self):
        self.assertEqual(len(list(self.deps.iterdir())), 4)

    def annotations(self, result):
        return [ln for ln in result.stdout.splitlines() if ln.startswith("::warning::")]

    def test_non_finite_or_negative_lock_timeout_is_usage_7297_r6(self):
        for bad in ("nan", "inf", "-inf", "-1", "abc", ""):
            with self.subTest(timeout=bad):
                result = self.sweep("--lock", str(self.lock_path), "--lock-timeout", bad)
                self.assertEqual(result.returncode, EXIT_USAGE, result.stderr)
                self.assertIn("--lock-timeout", result.stderr)
                self.assert_untouched()

    def test_zero_lock_timeout_is_a_single_attempt_7297_r6(self):
        result = self.sweep("--lock", str(self.lock_path), "--lock-timeout", "0")
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertIn("removed=3", result.stdout)

    def assert_skipped(self, result, cause_word):
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assert_untouched()
        annotations = self.annotations(result)
        self.assertEqual(len(annotations), 1, result.stdout)
        self.assertIn(cause_word, annotations[0])
        self.assertNotIn("not taken within", annotations[0])
        self.assertRegex(annotations[0], r"Errno|errno")
        summary = [ln for ln in result.stdout.splitlines()
                   if "sweep skipped (" in ln and not ln.startswith("::")]
        self.assertEqual(len(summary), 1, result.stdout)
        self.assertNotIn("removed=0", result.stdout)

    def test_symlink_lock_path_reports_symlink_7297_r6(self):
        victim = self.root / "victim"
        victim.write_bytes(b"keep")
        self.lock_path.symlink_to(victim)
        self.assert_skipped(self.sweep("--lock", str(self.lock_path)), "symlink")
        self.assertEqual(victim.read_bytes(), b"keep")

    def test_directory_lock_path_reports_directory_7297_r6(self):
        self.lock_path.mkdir()
        self.assert_skipped(self.sweep("--lock", str(self.lock_path)), "directory")

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root ignores mode bits")
    def test_unwritable_root_reports_not_writable_7297_r6(self):
        self.cache_root.chmod(0o555)
        self.addCleanup(self.cache_root.chmod, 0o755)
        self.assert_skipped(self.sweep("--lock", str(self.lock_path)), "not writable")

    def test_missing_root_reports_missing_7297_r6(self):
        gone = self.root / "gone-root"
        result = self.run_sweep("--max-bytes", "1500", "--allow-root", "--within", str(gone),
                                "--lock", str(gone / ".evict.lock"),
                                target=gone / "f2-linux-fed")
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        annotations = self.annotations(result)
        self.assertEqual(len(annotations), 1, result.stdout)
        self.assertIn("missing", annotations[0])
        self.assertNotIn("not taken within", annotations[0])
        self.assertIn("sweep skipped (", result.stdout)

    def test_contention_timeout_is_annotated_and_skipped_7297_r6(self):
        self.lock_path.write_bytes(b"")
        fd = os.open(str(self.lock_path), os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            result = self.sweep("--lock", str(self.lock_path), "--lock-timeout", "1")
        finally:
            os.close(fd)
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assert_untouched()
        annotations = self.annotations(result)
        self.assertEqual(len(annotations), 1, result.stdout)
        self.assertIn("not taken within", annotations[0])
        self.assertIn("sweep skipped (", result.stdout)
        self.assertNotIn("removed=0", result.stdout)

    def test_summary_reports_lock_wait_and_hold_7297_r6(self):
        result = self.sweep("--lock", str(self.lock_path))
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertRegex(result.stdout,
                         r"freed=\d+ lock_wait=\d+\.\d\d lock_held=\d+\.\d\d")

    def test_summary_without_lock_reports_zero_7297_r6(self):
        result = self.sweep()
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertIn("lock_wait=0.00 lock_held=0.00", result.stdout)

    def test_wait_is_measured_when_the_lock_is_released_late_7297_r6(self):
        self.lock_path.write_bytes(b"")
        with open(str(self.lock_path), "r+b") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            # close() is idempotent: the timer releases the lock, the with block backs it up.
            timer = threading.Timer(0.6, lock_fh.close)
            timer.start()
            try:
                result = self.sweep("--lock", str(self.lock_path), "--lock-timeout", "20")
            finally:
                timer.join()
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        match = re.search(r"lock_wait=(\d+\.\d\d)", result.stdout)
        self.assertIsNotNone(match, result.stdout)
        self.assertGreaterEqual(float(match.group(1)), 0.4)

    def non_utf8_path(self, parent):
        """A path with a non-UTF-8 component. It is not created: macOS (APFS)
        refuses to create such a name, and a missing target is still summarised."""
        return Path(os.fsdecode(os.path.join(os.fsencode(str(parent)), b"bad-\xff-name")))

    def test_non_utf8_target_summary_has_no_traceback_7297_r6(self):
        base = self.non_utf8_path(self.root)
        result = self.run_sweep("--max-bytes", "1500", "--allow-root", "--within",
                                str(self.root), target=base)
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertRegex(result.stdout, r"bad-\\(xff|udcff)-name")
        self.assertIn("removed=0", result.stdout)

    def test_non_utf8_target_refusal_has_documented_rc_7297_r6(self):
        base = self.non_utf8_path(self.root)
        result = self.run_sweep("--max-bytes", "1500", target=base)
        self.assertEqual(result.returncode, EXIT_REFUSED, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertRegex(result.stderr, r"bad-\\(xff|udcff)-name")


class LineBreakInjectionTests(SweepTestCase):
    """#7297 round 7 (F4/S15): a CR or LF in a root or target name must not split
    a printed line, so it can never start a second workflow command."""

    NAME = "evil\n::error::injected"

    def setUp(self):
        super().setUp()
        self.cache_root = self.root / "cache" / self.NAME
        self.runner = self.cache_root / "runner"
        self.deps = self.runner / "debug" / "deps"
        for idx in range(4):
            entry = self.deps / "lib{}.rlib".format(idx)
            write_blob(entry)
            set_age(entry, idx)

    def sweep(self, *extra):
        return self.run_sweep("--max-bytes", "1500", "--allow-root", "--within",
                              str(self.cache_root), *extra, target=self.runner)

    def command_lines(self, text):
        return [ln for ln in text.splitlines() if ln.startswith("::")]

    def test_swept_summary_is_one_line_7297_r7(self):
        result = self.sweep()
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertIn("removed=3", result.stdout)
        self.assertEqual(self.command_lines(result.stdout), [], result.stdout)
        self.assertEqual(self.command_lines(result.stderr), [], result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 1, result.stdout)

    def test_skip_lines_are_single_lines_7297_r7(self):
        lock_path = self.cache_root / ".evict.lock"
        lock_path.mkdir()
        result = self.sweep("--lock", str(lock_path))
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        commands = self.command_lines(result.stdout)
        self.assertEqual(len(commands), 1, result.stdout)
        self.assertTrue(commands[0].startswith("::warning::"), commands)
        self.assertEqual(self.command_lines(result.stderr), [], result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 2, result.stdout)

    def test_refusal_lines_are_single_lines_7297_r7(self):
        outside = self.root / self.NAME / "target"
        outside.mkdir(parents=True)
        result = self.run_sweep("--max-bytes", "1500", target=outside)
        self.assertEqual(result.returncode, EXIT_REFUSED, result.stderr)
        self.assertEqual(self.command_lines(result.stderr), [], result.stderr)
        self.assertEqual(len(result.stderr.splitlines()), 1, result.stderr)

    def test_usage_error_is_one_escaped_line_7297_r8(self):
        result = self.run_sweep("--max-bytes", "1500", "extra\n::error::injected")
        self.assertEqual(result.returncode, EXIT_USAGE, result.stderr)
        self.assertEqual(self.command_lines(result.stderr), [], result.stderr)
        self.assertIn("extra%0A::error::injected", result.stderr)

    def test_escape_line_rule_7297_r7(self):
        module = load_script_module()
        self.assertEqual(module.escape_line("a%b\rc\nd"), "a%25b%0Dc%0Ad")
        self.assertEqual(module.escape_line("plain/path"), "plain/path")

    def test_helper_covers_a_monkeypatched_path_7297_r7(self):
        module = load_script_module()
        err = io.StringIO()
        # CI sets GITHUB_WORKSPACE; an empty value makes the workspace check refuse.
        with unittest.mock.patch("os.path.realpath", return_value="/x\n::error::y"), \
                unittest.mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": ""}):
            with contextlib.redirect_stderr(err):
                code = module.main(["--target", "t", "--max-bytes", "5"])
        self.assertEqual(code, EXIT_REFUSED)
        self.assertEqual(self.command_lines(err.getvalue()), [])


def raise_fd_limit(wanted):
    """Raise the soft descriptor limit to ``wanted``; return the old limits or None."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft >= wanted:
        return (soft, hard)
    ceiling = wanted if hard == resource.RLIM_INFINITY else min(wanted, hard)
    if ceiling < wanted:
        return None
    resource.setrlimit(resource.RLIMIT_NOFILE, (ceiling, hard))
    return (soft, hard)


DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
# Fixture files are only ever read back by the same user, so owner-only is the minimum the test needs.
FIXTURE_FILE_MODE = 0o600


@contextlib.contextmanager
def opened_fd(path, flags, dir_fd=None):
    """Open ``path`` with os.open and always close the descriptor on exit."""
    fd = os.open(path, flags, FIXTURE_FILE_MODE, dir_fd=dir_fd)
    try:
        yield fd
    finally:
        os.close(fd)


def make_deep_chain(parent, name, depth):
    """Create ``parent/name/d/d/...`` ``depth`` levels deep using dir_fd-relative calls."""
    os.makedirs(str(parent / name))
    with contextlib.ExitStack() as stack:
        fd = stack.enter_context(opened_fd(str(parent / name), DIR_FLAGS))
        for _ in range(depth):
            os.mkdir("d", dir_fd=fd)
            fd = stack.enter_context(opened_fd("d", DIR_FLAGS, dir_fd=fd))


def remove_deep_chain(parent, name, depth):
    """Remove whatever is left of the chain made by make_deep_chain, without recursion."""
    with contextlib.ExitStack() as stack:
        try:
            fds = [stack.enter_context(opened_fd(str(parent / name), DIR_FLAGS))]
        except FileNotFoundError:
            return
        while len(fds) <= depth:
            try:
                fds.append(stack.enter_context(opened_fd("d", DIR_FLAGS, dir_fd=fds[-1])))
            except FileNotFoundError:
                break
        for idx in range(len(fds) - 1, -1, -1):
            try:
                os.unlink("f", dir_fd=fds[idx])
            except FileNotFoundError:
                # No file at this level: chains made by make_deep_chain hold none, so nothing to remove.
                pass
            if idx:
                os.rmdir("d", dir_fd=fds[idx - 1])
    os.rmdir(str(parent / name))


class DeepTreeTests(SweepTestCase):
    """#7160 R2-F2 / S5: a very deep tree is a warning, not a traceback."""

    DEPTH = 1200

    def test_deep_tree_warns_and_keeps_documented_exit_code(self):
        old = raise_fd_limit(self.DEPTH + 200)
        if old is None:
            self.skipTest("cannot raise the descriptor limit for a deep tree")
        pkg_parent = self.debug / "build"
        pkg_parent.mkdir()
        make_deep_chain(pkg_parent, "pkg", self.DEPTH)
        try:
            module = load_script_module()
            err = io.StringIO()
            out = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
                rc = module.main(["--target", str(self.target), "--max-bytes", "1",
                                  "--allow-root", "--within", str(self.workspace)])
            self.assertEqual(rc, EXIT_OK, err.getvalue())
            self.assertIn("warning: cannot", err.getvalue())
            self.assertIn("ci-sweep-target:", out.getvalue())
        finally:
            remove_deep_chain(pkg_parent, "pkg", self.DEPTH)
            resource.setrlimit(resource.RLIMIT_NOFILE, old)


def make_deep_chain_with_files(parent, name, depth):
    """Like make_deep_chain, with one small file at every level; returns the file count."""
    os.makedirs(str(parent / name))
    count = 0
    with contextlib.ExitStack() as stack:
        fd = stack.enter_context(opened_fd(str(parent / name), DIR_FLAGS))
        for _ in range(depth):
            with opened_fd("f", os.O_WRONLY | os.O_CREAT, dir_fd=fd) as file_fd:
                os.write(file_fd, b"0123456789")
            count += 1
            os.mkdir("d", dir_fd=fd)
            fd = stack.enter_context(opened_fd("d", DIR_FLAGS, dir_fd=fd))
    return count


def count_files(root):
    """Count regular files under ``root`` iteratively, by descriptor (no path limit)."""
    total = 0
    with contextlib.ExitStack() as holder:
        stack = [holder.enter_context(opened_fd(str(root), DIR_FLAGS))]
        while stack:
            fd = stack.pop()
            with os.scandir(fd) as it:
                children = list(it)
            for child in children:
                if child.is_dir(follow_symlinks=False):
                    stack.append(holder.enter_context(opened_fd(child.name, DIR_FLAGS, dir_fd=fd)))
                else:
                    total += 1
    return total


class DeepEntrySkippedTests(SweepTestCase):
    """#7160 S6: an entry too deep to walk is skipped whole, never partly deleted."""

    DEPTH = 1100

    def test_deep_entry_is_not_partly_deleted_7160_s6(self):
        old = raise_fd_limit(self.DEPTH + 200)
        if old is None:
            self.skipTest("cannot raise the descriptor limit for a deep tree")
        build = self.debug / "build"
        build.mkdir()
        files = make_deep_chain_with_files(build, "pkg", self.DEPTH)
        os.utime(str(build / "pkg"), (1, 1))
        plain = self.make_entries(2)
        try:
            res = self.run_sweep("--max-bytes", "1")
            self.assertEqual(res.returncode, EXIT_OK, res.stderr)
            self.assertEqual(count_files(build / "pkg"), files)
            self.assertIn("pkg", res.stderr)
            self.assertEqual(res.stderr.count("pkg"), 1, res.stderr)
            self.assertIn("skipped", res.stderr)
            self.assertNotIn("Traceback", res.stderr)
            self.assertFalse(any(path.exists() for path in plain))
        finally:
            remove_deep_chain(build, "pkg", self.DEPTH)
            resource.setrlimit(resource.RLIMIT_NOFILE, old)


def tree_bytes(path):
    """Bytes the sweep counts under ``path``: lstat size of every file and directory."""
    total = os.lstat(str(path)).st_size
    for dirpath, dirnames, filenames in os.walk(str(path)):
        for name in dirnames + filenames:
            total += os.lstat(os.path.join(dirpath, name)).st_size
    return total


def summary_field(stdout, key):
    for token in stdout.split():
        if token.startswith(key + "="):
            return int(token.split("=", 1)[1])
    raise AssertionError("no {} in {!r}".format(key, stdout))


class PartialDeleteTests(SweepTestCase):
    """#7160 S9 / code F2: an entry that cannot be emptied is kept whole, and the summary is true."""

    FILES = 40
    FILE_BYTES = 100

    def make_pkg(self, locked_names, mode):
        pkg = self.debug / "build" / "pkg"
        pkg.mkdir(parents=True)
        for idx in range(self.FILES):
            (pkg / "f{:02d}".format(idx)).write_bytes(b"x" * self.FILE_BYTES)
        for name in locked_names:
            sub = pkg / name
            sub.mkdir()
            (sub / "inner").write_bytes(b"z" * 10)
            sub.chmod(mode)
            self.locked.append(sub)
        return pkg

    def count_files(self, pkg):
        return len([n for n in os.listdir(str(pkg)) if n.startswith("f")])

    @unittest.skipIf(os.geteuid() == 0, "root can unlink inside a read-only directory")
    def test_entry_with_read_only_nested_dir_is_kept_whole_7160_s9(self):
        pkg = self.make_pkg(["a-ro", "m-ro", "zz-ro"], 0o555)
        expected = tree_bytes(pkg)
        res = self.run_sweep("--max-bytes", "1")
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertEqual(self.count_files(pkg), self.FILES)
        self.assertTrue((pkg / "m-ro" / "inner").exists())
        self.assertIn("cannot remove {}".format(pkg), res.stderr)
        self.assertEqual(res.stderr.count("cannot remove"), 1, res.stderr)
        self.assertNotIn("Traceback", res.stderr)
        self.assertEqual(summary_field(res.stdout, "before"), expected)
        self.assertEqual(summary_field(res.stdout, "after"), expected)
        self.assertEqual(summary_field(res.stdout, "removed"), 0)
        self.assertEqual(summary_field(res.stdout, "freed"), 0)

    @unittest.skipIf(os.geteuid() == 0, "root can read a mode-000 directory")
    def test_entry_with_unreadable_nested_dir_is_kept_whole_7160_s9(self):
        for position, name in enumerate(["a-locked", "m-locked", "zz-locked"]):
            with self.subTest(name=name):
                for locked in self.locked:
                    locked.chmod(0o755)
                self.locked = []
                shutil.rmtree(str(self.debug / "build"), ignore_errors=True)
                pkg = self.make_pkg([name], 0)
                res = self.run_sweep("--max-bytes", "1")
                self.assertEqual(res.returncode, EXIT_OK, res.stderr)
                self.assertEqual(self.count_files(pkg), self.FILES)
                self.assertIn("cannot remove {}".format(pkg), res.stderr)
                self.assertNotIn("Traceback", res.stderr)
                self.assertEqual(summary_field(res.stdout, "removed"), 0)
                self.assertEqual(summary_field(res.stdout, "freed"), 0)
                self.assertEqual(summary_field(res.stdout, "before"),
                                 summary_field(res.stdout, "after"))

    @unittest.skipIf(os.geteuid() == 0, "root can unlink inside a read-only directory")
    def test_kept_entry_does_not_stop_other_entries_7160_s9(self):
        pkg = self.make_pkg(["m-ro"], 0o555)
        os.utime(str(pkg), (1, 1))
        plain = self.make_entries(2)
        res = self.run_sweep("--max-bytes", "1")
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertEqual(self.count_files(pkg), self.FILES)
        self.assertFalse(any(path.exists() for path in plain))
        self.assertEqual(summary_field(res.stdout, "removed"), 2)
        self.assertEqual(summary_field(res.stdout, "freed"), 2 * ENTRY_BYTES)

    def test_summary_reports_bytes_really_deleted_after_a_failed_removal_7160_f2(self):
        module = load_script_module()
        pkg = self.debug / "build" / "pkg"
        for idx in range(20):
            write_blob(pkg / "f{:02d}".format(idx))
        real_unlink = os.unlink
        calls = []

        def flaky_unlink(name, *args, **kwargs):
            if len(calls) == 9:
                raise PermissionError(13, "Permission denied", name)
            calls.append(name)
            return real_unlink(name, *args, **kwargs)

        out = io.StringIO()
        err = io.StringIO()
        with unittest.mock.patch.object(os, "unlink", flaky_unlink), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            rc = module.main(["--target", str(self.target), "--max-bytes", "1",
                              "--allow-root", "--within", str(self.workspace)])
        self.assertEqual(rc, EXIT_OK, err.getvalue())
        self.assertEqual(self.count_files_in(pkg), 11)
        self.assertEqual(summary_field(out.getvalue(), "removed"), 0)
        self.assertEqual(summary_field(out.getvalue(), "freed"), 9 * ENTRY_BYTES)
        self.assertEqual(summary_field(out.getvalue(), "after"),
                         summary_field(out.getvalue(), "before") - 9 * ENTRY_BYTES)
        self.assertIn("cannot remove {}".format(pkg), err.getvalue())

    @staticmethod
    def count_files_in(path):
        return len(os.listdir(str(path)))


if __name__ == "__main__":
    unittest.main()
