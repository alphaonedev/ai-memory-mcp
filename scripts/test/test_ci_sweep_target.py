"""Unit tests for scripts/ci-sweep-target.py (#7160).

Every tree is synthetic and lives under the worktree's own ``.local-runs/``
directory, never under a tmpfs path.
"""

import contextlib
import importlib.util
import io
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
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
        res = self.run_sweep("--max-bytes", "1", "--allow-root", target=outside)
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

    def test_unreadable_dir_warns_without_traceback(self):
        deps = self.debug / "deps"
        write_blob(deps / "a.rlib")
        deps.chmod(0)
        self.locked.append(deps)
        res = self.run_sweep("--max-bytes", "10")
        self.assertEqual(res.returncode, EXIT_UNREADABLE, res.stderr)
        self.assertNotIn("Traceback", res.stderr)
        self.assertIn(str(deps), res.stderr)

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
                              "--allow-root"])
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
        with mock.patch.dict(os.environ, env), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            rc = module.main(["--target", str(self.target), "--max-bytes", "1"])
        self.assertEqual(rc, EXIT_REFUSED, err.getvalue())
        self.assertIn("refused", err.getvalue())
        self.assertIn("target", err.getvalue())
        self.assertTrue(all(path.exists() for path in outside_files))

    def test_allow_root_refuses_symlinked_target_7160_s4(self):
        self.make_entries(2)
        outside, outside_files = self.make_outside()
        link = self.root / "linked-target"
        link.symlink_to(outside, target_is_directory=True)
        result = self.run_sweep("--max-bytes", "1", "--allow-root", target=link)
        self.assertEqual(result.returncode, EXIT_REFUSED, result.stderr)
        self.assertIn("is not a canonical path", result.stderr)
        self.assertTrue(all(path.exists() for path in outside_files))

    def test_target_that_is_a_regular_file_says_not_a_directory_7160_s8(self):
        not_dir = self.root / "target-is-a-file"
        not_dir.write_bytes(b"x")
        for extra in ((), ("--allow-root",)):
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
        with mock.patch.object(module.os, "open", recording_open), \
                contextlib.redirect_stdout(out):
            rc = module.main(["--target", str(self.target), "--max-bytes", "1",
                              "--allow-root"])
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
        result = self.run_sweep("--max-bytes", "1", "--allow-root", target=canonical)
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)
        self.assertIn("removed=3", result.stdout)

    def test_allow_root_accepts_canonical_target(self):
        self.make_entries(3)
        canonical = Path(os.path.realpath(str(self.target)))
        result = self.run_sweep("--max-bytes", "1500", "--allow-root", target=canonical)
        self.assertEqual(result.returncode, EXIT_OK, result.stderr)


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


def make_deep_chain(parent, name, depth):
    """Create ``parent/name/d/d/...`` ``depth`` levels deep using dir_fd-relative calls."""
    os.makedirs(str(parent / name))
    fd = os.open(str(parent / name), DIR_FLAGS)
    for _ in range(depth):
        os.mkdir("d", dir_fd=fd)
        child = os.open("d", DIR_FLAGS, dir_fd=fd)
        os.close(fd)
        fd = child
    os.close(fd)


def remove_deep_chain(parent, name, depth):
    """Remove whatever is left of the chain made by make_deep_chain, without recursion."""
    try:
        fds = [os.open(str(parent / name), DIR_FLAGS)]
    except FileNotFoundError:
        return
    try:
        while len(fds) <= depth:
            try:
                fds.append(os.open("d", DIR_FLAGS, dir_fd=fds[-1]))
            except FileNotFoundError:
                break
        for idx in range(len(fds) - 1, -1, -1):
            try:
                os.unlink("f", dir_fd=fds[idx])
            except FileNotFoundError:
                pass
            if idx:
                os.rmdir("d", dir_fd=fds[idx - 1])
    finally:
        for fd in fds:
            os.close(fd)
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
                                  "--allow-root"])
            self.assertEqual(rc, EXIT_OK, err.getvalue())
            self.assertIn("warning: cannot", err.getvalue())
            self.assertIn("ci-sweep-target:", out.getvalue())
        finally:
            remove_deep_chain(pkg_parent, "pkg", self.DEPTH)
            resource.setrlimit(resource.RLIMIT_NOFILE, old)


def make_deep_chain_with_files(parent, name, depth):
    """Like make_deep_chain, with one small file at every level; returns the file count."""
    os.makedirs(str(parent / name))
    fd = os.open(str(parent / name), DIR_FLAGS)
    count = 0
    for _ in range(depth):
        file_fd = os.open("f", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd)
        os.write(file_fd, b"0123456789")
        os.close(file_fd)
        count += 1
        os.mkdir("d", dir_fd=fd)
        child = os.open("d", DIR_FLAGS, dir_fd=fd)
        os.close(fd)
        fd = child
    os.close(fd)
    return count


def count_files(root):
    """Count regular files under ``root`` iteratively, by descriptor (no path limit)."""
    total = 0
    stack = [os.open(str(root), DIR_FLAGS)]
    while stack:
        fd = stack.pop()
        try:
            with os.scandir(fd) as it:
                children = list(it)
            for child in children:
                if child.is_dir(follow_symlinks=False):
                    stack.append(os.open(child.name, DIR_FLAGS, dir_fd=fd))
                else:
                    total += 1
        finally:
            os.close(fd)
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


if __name__ == "__main__":
    unittest.main()
