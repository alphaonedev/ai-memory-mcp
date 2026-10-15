"""Unit tests for scripts/ci-sweep-target.py (#7160).

Every tree is synthetic and lives under the worktree's own ``.local-runs/``
directory, never under a tmpfs path.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "ci-sweep-target.py"
SCRATCH_ROOT = REPO_ROOT / ".local-runs"
SWEPT_SUBDIRS = ("deps", "incremental", "build", ".fingerprint")
EXIT_OK = 0
EXIT_REFUSED = 2
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

    def tearDown(self):
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
        res = self.run_sweep("--max-bytes", "0", target=outside)
        self.assertEqual(res.returncode, EXIT_REFUSED)
        self.assertIn(str(outside), res.stderr)
        self.assertTrue(victim.exists())

    def test_refuses_without_workspace_env(self):
        victim = self.make_entries(1)[0]
        res = self.run_sweep("--max-bytes", "0", workspace=False)
        self.assertEqual(res.returncode, EXIT_REFUSED)
        self.assertTrue(victim.exists())

    def test_allow_root_overrides_refusal(self):
        outside = self.root / "elsewhere" / "target"
        victim = outside / "debug" / "deps" / "a.rlib"
        write_blob(victim)
        res = self.run_sweep("--max-bytes", "0", "--allow-root", target=outside)
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertFalse(victim.exists())

    def test_dry_run_removes_nothing(self):
        paths = self.make_entries(4)
        res = self.run_sweep("--max-bytes", "0", "--dry-run")
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
        res = self.run_sweep("--max-bytes", "0")
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertFalse(link.is_symlink())
        self.assertTrue(keep.exists())
        self.assertNotIn("before=50", res.stdout)

    def test_symlinked_subdir_is_skipped(self):
        outside = self.root / "outside2"
        keep = outside / "precious.bin"
        write_blob(keep)
        (self.debug).mkdir(parents=True, exist_ok=True)
        (self.debug / "deps").symlink_to(outside, target_is_directory=True)
        res = self.run_sweep("--max-bytes", "0")
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertTrue(keep.exists())

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
        res = self.run_sweep("--max-bytes", "0")
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


if __name__ == "__main__":
    unittest.main()
