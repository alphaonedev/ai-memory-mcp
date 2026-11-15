# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin scripts/ci/prune_runner_tmp.py and its workflow wiring (#8634).

Invariant, for every input directory state: the prune removes ONLY direct
entries of the resolved TMPDIR whose own lstat mtime is older than MAX_AGE_SECS;
it never follows or deletes through a symlink; it never touches a sibling runner
directory; it refuses (exit 3, nothing deleted, exact reason) on a bad TMPDIR;
one failing entry never stops the rest (exit 0, failed=<n>). Every self-hosted
job calls the prune action right after its checkout.

Decision (pinned by test_old_directory_with_young_child_is_removed): the
top-level entry's own mtime rules; a young child does not keep an old directory.

Run: python3 -m unittest scripts/ci/tests/test_prune_runner_tmp_8634.py
Python 3.12+, standard library only.
"""

import importlib.util
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = Path(os.environ.get("PRUNE_SCRIPT_UNDER_TEST") or ROOT / "scripts/ci/prune_runner_tmp.py")
CHECKER = ROOT / "scripts/ci/check_pg_preflight_workflows.py"
SCRATCH_BASE = Path(os.environ.get("TMPDIR") or ROOT / ".local-runs")

SECS_PER_DAY = 86400
OLD_AGE_SECS = 2 * SECS_PER_DAY
YOUNG_AGE_SECS = 60
EXIT_OK = 0
EXIT_REFUSED = 3
MANY_ENTRIES = 50_000
MANY_ENTRIES_CEILING_SECS = 60.0
ACTION_PATH = ".github/actions/prune-runner-tmp/action.yml"
ACTION_USES = "uses: ./.github/actions/prune-runner-tmp"
SELF_HOSTED_JOBS = {
    ("ci.yml", "check"),
    ("cert-postgres-age.yml", "cert-postgres-age"),
    ("postgres-ignored.yml", "postgres-ignored"),
    ("session-boot-lifetime.yml", "lifetime-tests"),
}

PRUNE = None
CHK = None


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def setUpModule():
    global PRUNE, CHK
    CHK = _load("check_pg_preflight_workflows", CHECKER)
    if SCRIPT.exists():
        PRUNE = _load("prune_runner_tmp", SCRIPT)


def age(path, secs):
    stamp = time.time() - secs
    os.utime(path, (stamp, stamp), follow_symlinks=False)


def snapshot(top):
    """Relative path -> (kind, content or link target, mtime_ns); no symlink followed."""
    seen = {}
    for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            info = os.lstat(full)
            rel = os.path.relpath(full, top)
            if stat.S_ISLNK(info.st_mode):
                seen[rel] = ("link", os.readlink(full), info.st_mtime_ns)
            elif stat.S_ISDIR(info.st_mode):
                seen[rel] = ("dir", None, info.st_mtime_ns)
            else:
                seen[rel] = ("file", Path(full).read_bytes(), info.st_mtime_ns)
    return seen


class Base(unittest.TestCase):
    def setUp(self):
        if PRUNE is None:
            self.fail(f"script under test not found: {SCRIPT}")
        SCRATCH_BASE.mkdir(parents=True, exist_ok=True)
        holder = tempfile.TemporaryDirectory(dir=SCRATCH_BASE, prefix="prune8634-")
        self.addCleanup(holder.cleanup)
        self.base = Path(holder.name).resolve()
        self.runner = self.base / "runner-1"
        self.runner.mkdir()
        self.home = self.base / "home"
        self.home.mkdir()
        patch = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)

    def run_prune(self, tmpdir, *extra, env_extra=None):
        environ = {} if tmpdir is None else {"TMPDIR": str(tmpdir)}
        environ.update(env_extra or {})
        out, err = io.StringIO(), io.StringIO()
        rc = PRUNE.main(["--root", str(self.base), *extra], environ=environ, out=out, err=err)
        return rc, out.getvalue(), err.getvalue()

    def names(self, top=None):
        return sorted(p.name for p in (top or self.runner).iterdir())

    def make_file(self, name, secs, parent=None, data=b"x" * 10):
        path = (parent or self.runner) / name
        path.write_bytes(data)
        age(path, secs)
        return path

    def make_tree(self, name, secs):
        path = self.runner / name
        (path / "sub").mkdir(parents=True)
        (path / "sub" / "f.db").write_bytes(b"d" * 100)
        age(path / "sub" / "f.db", secs)
        age(path / "sub", secs)
        age(path, secs)
        return path


class PruneRules(Base):
    def test_young_file_and_young_directory_kept(self):
        self.make_file("young.db", YOUNG_AGE_SECS)
        self.make_tree("young-dir", YOUNG_AGE_SECS)
        rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertEqual(out.strip(), "pruned=0 kept=2 failed=0 freed_bytes=0")
        self.assertEqual(self.names(), ["young-dir", "young.db"])

    def test_old_file_old_tree_and_dangling_symlink_removed(self):
        self.make_file("old.db", OLD_AGE_SECS)
        self.make_tree("old-dir", OLD_AGE_SECS)
        self.make_file("keep.db", YOUNG_AGE_SECS)
        dangling = self.runner / "dangling"
        os.symlink(self.base / "does-not-exist", dangling)
        age(dangling, OLD_AGE_SECS)
        rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertRegex(out.strip(), r"^pruned=3 kept=1 failed=0 freed_bytes=\d+$")
        self.assertEqual(self.names(), ["keep.db"])

    def test_old_symlink_to_outside_directory_removed_target_intact(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "precious.db").write_bytes(b"precious")
        age(outside / "precious.db", OLD_AGE_SECS)
        age(outside, OLD_AGE_SECS)
        link = self.runner / "link-to-outside"
        os.symlink(outside, link)
        age(link, OLD_AGE_SECS)
        before = snapshot(outside)
        rc, out, _err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("pruned=1 kept=0 failed=0", out)
        self.assertEqual(self.names(), [])
        self.assertEqual(snapshot(outside), before)

    def test_symlink_age_is_the_links_own_mtime(self):
        outside = self.base / "outside-old"
        outside.mkdir()
        age(outside, OLD_AGE_SECS)
        link = self.runner / "young-link-old-target"
        os.symlink(outside, link)
        age(link, YOUNG_AGE_SECS)
        rc, out, _err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("pruned=0 kept=1 failed=0", out)
        self.assertEqual(self.names(), ["young-link-old-target"])

    def test_symlink_inside_old_tree_is_not_followed(self):
        outside = self.base / "outside-inner"
        outside.mkdir()
        (outside / "precious.db").write_bytes(b"precious")
        tree = self.make_tree("old-dir", OLD_AGE_SECS)
        os.symlink(outside, tree / "sub" / "escape")
        before = snapshot(outside)
        rc, _out, _err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(self.names(), [])
        self.assertEqual(snapshot(outside), before)

    def test_sibling_runner_directory_untouched_byte_for_byte(self):
        sibling = self.base / "runner-2"
        sibling.mkdir()
        (sibling / "old.db").write_bytes(b"sibling data")
        age(sibling / "old.db", OLD_AGE_SECS)
        (sibling / "tree" / "deep").mkdir(parents=True)
        age(sibling / "tree", OLD_AGE_SECS)
        age(sibling, OLD_AGE_SECS)
        before = snapshot(sibling)
        self.make_file("mine.db", OLD_AGE_SECS)
        rc, out, _err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("pruned=1 kept=0 failed=0", out)
        self.assertEqual(snapshot(sibling), before)
        self.assertEqual(snapshot(self.base / "runner-2"), before)

    def test_old_directory_with_young_child_is_removed(self):
        tree = self.make_tree("old-dir-young-child", OLD_AGE_SECS)
        young = tree / "young.db"
        young.write_bytes(b"y")
        age(young, YOUNG_AGE_SECS)
        age(tree, OLD_AGE_SECS)
        rc, out, _err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("pruned=1 kept=0 failed=0", out)
        self.assertEqual(self.names(), [])

    def test_dry_run_deletes_nothing(self):
        self.make_file("old.db", OLD_AGE_SECS)
        self.make_tree("old-dir", OLD_AGE_SECS)
        self.make_file("young.db", YOUNG_AGE_SECS)
        before = snapshot(self.runner)
        rc, out, err = self.run_prune(self.runner, "--dry-run")
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertIn("would-remove old.db", out)
        self.assertIn("would-remove old-dir", out)
        self.assertNotIn("young.db", out)
        self.assertIn("pruned=2 kept=1 failed=0 freed_bytes=0", out)
        self.assertEqual(snapshot(self.runner), before)

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_unremovable_entry_counts_failed_and_job_continues(self):
        locked = self.make_tree("locked-dir", OLD_AGE_SECS)
        self.make_file("old-after.db", OLD_AGE_SECS)
        inner = locked / "sub"
        inner.chmod(0o500)
        age(locked, OLD_AGE_SECS)
        self.addCleanup(lambda: inner.chmod(0o700))
        rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("pruned=1 kept=0 failed=1", out)
        self.assertIn("failed to remove locked-dir", err)
        self.assertEqual(self.names(), ["locked-dir"])

    def test_vanished_entry_is_counted_not_fatal(self):
        self.make_file("old-a.db", OLD_AGE_SECS)
        self.make_file("old-b.db", OLD_AGE_SECS)
        real_unlink = os.unlink
        state = {"hit": False}

        def flaky(name, *args, **kwargs):
            if not state["hit"]:
                state["hit"] = True
                real_unlink(name, *args, **kwargs)
                raise FileNotFoundError(2, "vanished", name)
            return real_unlink(name, *args, **kwargs)

        with mock.patch.object(os, "unlink", flaky):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("pruned=1 kept=0 failed=1", out)
        self.assertIn("failed to remove", err)
        self.assertEqual(self.names(), [])


class Refusals(Base):
    def refused(self, tmpdir, reason, env_extra=None, root=None):
        victim = self.make_file("old.db", OLD_AGE_SECS) if self.runner.exists() else None
        out, err = io.StringIO(), io.StringIO()
        environ = {} if tmpdir is None else {"TMPDIR": str(tmpdir)}
        environ.update(env_extra or {})
        rc = PRUNE.main(["--root", root or str(self.base)], environ=environ, out=out, err=err)
        self.assertEqual(rc, EXIT_REFUSED, err.getvalue())
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue().strip(), f"prune_runner_tmp: refused: {reason}")
        if victim is not None:
            self.assertTrue(victim.exists(), "a refusal must delete nothing")

    def test_unset(self):
        self.refused(None, "TMPDIR is unset")

    def test_empty(self):
        self.refused("", "TMPDIR is empty")

    def test_relative(self):
        self.refused("runner-1", "TMPDIR is not an absolute path: runner-1")

    def test_missing(self):
        gone = self.base / "gone"
        self.refused(gone, f"TMPDIR does not exist: {gone} (No such file or directory)")

    def test_file_not_directory(self):
        plain = self.base / "plain-file"
        plain.write_bytes(b"x")
        self.refused(plain, f"TMPDIR is not a directory: {plain}")

    def test_tmpdir_is_a_symlink(self):
        link = self.base / "runner-link"
        os.symlink(self.runner, link)
        self.refused(link, f"TMPDIR is a symlink: {link}")

    def test_outside_allowed_root(self):
        other = Path(tempfile.mkdtemp(dir=SCRATCH_BASE, prefix="prune8634-other-")).resolve()
        self.addCleanup(shutil.rmtree, other, True)
        self.refused(other, f"TMPDIR is outside the allowed roots {[*PRUNE.ALLOWED_ROOTS, str(self.base)]}: {other}")

    def test_equals_the_allowed_root_itself(self):
        self.refused(self.base, f"TMPDIR is outside the allowed roots {[*PRUNE.ALLOWED_ROOTS, str(self.base)]}: {self.base}")

    def test_equals_slash_and_tmp(self):
        self.runner = self.base / "unused"
        self.refused("/", "TMPDIR is a forbidden path: /", root="/usr")
        self.refused("/tmp", "TMPDIR is a forbidden path: /tmp", root="/usr")

    def test_equals_home_directory(self):
        self.runner = self.base / "unused"
        self.refused(self.home, f"TMPDIR is a forbidden path: {self.home}")

    def test_equals_workspace(self):
        workspace = self.base / "ws"
        workspace.mkdir()
        self.runner = self.base / "unused"
        self.refused(workspace, f"TMPDIR is a forbidden path: {workspace}", env_extra={"GITHUB_WORKSPACE": str(workspace)})

    def test_contains_the_workspace(self):
        workspace = self.runner / "ws"
        workspace.mkdir()
        self.refused(
            self.runner,
            f"TMPDIR contains the home directory or the workspace: {self.runner}",
            env_extra={"GITHUB_WORKSPACE": str(workspace)},
        )

    def test_root_slash_is_refused(self):
        self.refused(self.runner, "allowed root is '/'", root="/")

    def test_not_owned_by_current_user(self):
        with mock.patch.object(PRUNE.os, "geteuid", return_value=os.geteuid() + 1):
            self.refused(self.runner, f"TMPDIR is not owned by the current user: {self.runner}")

    def test_rmtree_without_symlink_protection_is_refused(self):
        with mock.patch.object(PRUNE.shutil.rmtree, "avoids_symlink_attacks", False, create=True):
            self.refused(self.runner, "shutil.rmtree cannot avoid symlink attacks on this platform")


class Scale(Base):
    def test_50k_entries_one_scandir_pass_under_ceiling(self):
        for i in range(MANY_ENTRIES):
            path = self.runner / f"wt1d-auto-atomise-{i:06d}.db"
            path.write_bytes(b"")
            age(path, OLD_AGE_SECS if i % 2 else YOUNG_AGE_SECS)
        real_scandir = os.scandir
        with mock.patch.object(os, "scandir", wraps=real_scandir) as spy:
            started = time.monotonic()
            rc, out, err = self.run_prune(self.runner)
            elapsed = time.monotonic() - started
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertEqual(out.strip(), f"pruned={MANY_ENTRIES // 2} kept={MANY_ENTRIES // 2} failed=0 freed_bytes=0")
        self.assertEqual(spy.call_count, 1, "one scandir pass over TMPDIR")
        self.assertLess(elapsed, MANY_ENTRIES_CEILING_SECS)
        self.assertEqual(len(os.listdir(self.runner)), MANY_ENTRIES // 2)


class CommandLine(Base):
    def test_cli_exit_codes_and_summary_line(self):
        self.make_file("old.db", OLD_AGE_SECS)
        env = {k: v for k, v in os.environ.items() if k != "TMPDIR"}
        done = subprocess.run([sys.executable, "-I", str(SCRIPT)], env=env, capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, EXIT_REFUSED)
        self.assertEqual(done.stderr.strip(), "prune_runner_tmp: refused: TMPDIR is unset")
        env["TMPDIR"] = str(self.runner)
        done = subprocess.run([sys.executable, "-I", str(SCRIPT), "--root", str(self.base)], env=env, capture_output=True, text=True, check=False)
        self.assertEqual((done.returncode, done.stderr), (EXIT_OK, ""))
        self.assertRegex(done.stdout.strip(), r"^pruned=1 kept=0 failed=0 freed_bytes=\d+$")
        self.assertEqual(self.names(), [])


class WorkflowWiring(unittest.TestCase):
    """Every self-hosted job calls the prune action first (right after its checkout)."""

    def self_hosted_jobs(self):
        found = {}
        for wf in sorted((ROOT / ".github/workflows").glob("*.yml")):
            steps, heads = CHK.parse_steps(wf.read_text())
            for job, head in heads.items():
                code = [ln for ln in head if not ln.lstrip().startswith("#")]
                if any("self-hosted" in ln for ln in code):
                    found[(wf.name, job)] = [s for s in steps if s.job == job]
        return found

    def test_the_self_hosted_job_set_is_the_pinned_one(self):
        self.assertEqual(set(self.self_hosted_jobs()), SELF_HOSTED_JOBS)

    def test_every_self_hosted_job_prunes_right_after_checkout(self):
        for key, steps in self.self_hosted_jobs().items():
            with self.subTest(job=key):
                checkout = [i for i, s in enumerate(steps) if "uses: actions/checkout@" in "\n".join(s.code_lines())]
                self.assertEqual(len(checkout), 1, key)
                prune_idx = [i for i, s in enumerate(steps) if ACTION_USES in "\n".join(s.code_lines())]
                self.assertEqual(prune_idx, [checkout[0] + 1], f"{key}: prune must be the step right after checkout")
                before = "\n".join("\n".join(s.code_lines()) for s in steps[: checkout[0]])
                self.assertNotRegex(before, r"\bcargo\b|\brustup\b|uses: [a-z]", f"{key}: nothing builds before the prune")
                text = "\n".join(steps[prune_idx[0]].code_lines())
                self.assertIn("runner.environment == 'self-hosted'", text)
                self.assertNotIn("continue-on-error", text)

    def test_action_describes_both_failure_modes_and_runs_the_script(self):
        text = (ROOT / ACTION_PATH).read_text()
        self.assertIn("using: composite", text)
        self.assertIn("scripts/ci/prune_runner_tmp.py", text)
        self.assertRegex(text, r"(?is)refus\w+ .*fails? the job")
        self.assertRegex(text, r"(?is)per-entry .*does not fail")
        self.assertIsNone(re.search(r"continue-on-error", text))


if __name__ == "__main__":
    unittest.main()
