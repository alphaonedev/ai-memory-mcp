# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin scripts/ci/prune_runner_tmp.py and its workflow wiring (#8634).

Invariant, for every input: the prune deletes only stale top-level entries of a
directory PROVEN, by file identity, to be this runner's own
``<confirmed runner root>/runner-<digits>``; any input it cannot prove ends in a
named refusal (exact reason, nothing deleted); a per-entry failure or a
refusal never fails or skips the rest of the job (a ``::warning`` annotation, exit 0); an
unexpected internal error stays red (exit 1); a per-entry failure is counted (exit 0); no output
line can carry a workflow command; removal never recurses in Python frames and
never enters another device or another mount; the platform check is a functional
probe and gives the same answer under every interpreter a runner uses.

Class cells, each over a named corpus: PATH_FORMS (every way TMPDIR can be
given), ROOT_FORMS (every way an allowed root can be given), HOSTILE_NAMES
(entry names that try to inject log lines), ENTRY_KINDS (file, dir, symlink,
FIFO, socket, other device).

Decision (pinned by test_old_directory_with_young_child_is_removed): the
top-level entry's own mtime rules; a young child does not keep an old directory.
The allowed roots are patched per test (no --root flag exists).

Run: python3 -m unittest scripts/ci/tests/test_prune_runner_tmp_8634.py
(under ``python3 -I`` the start directory is not on sys.path, so use
``python3 -I -m unittest discover -s scripts/ci/tests -p test_prune_runner_tmp_8634.py``).
Python 3.12+, standard library only.
"""

import ast
import contextlib
import errno
import importlib.util
import io
import json
import os
import re
import resource
import shutil
import socket
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
DOCS = ROOT / "docs/DEV-CI-ENVIRONMENT.md"
SCRATCH_BASE = Path(os.environ.get("TMPDIR") or ROOT / ".local-runs")

SECS_PER_DAY = 86400
OLD_AGE_SECS = 2 * SECS_PER_DAY
YOUNG_AGE_SECS = 60
EXIT_OK = 0
EXIT_REFUSED = EXIT_OK  # ruling f23a9ae4: a refusal ends the step green, with a ::warning annotation
EXIT_ERROR = 1
ANNOTATION_PREFIX = "::warning title=prune_runner_tmp refused::prune_runner_tmp: refused: "
MANY_ENTRIES = 50_000
MANY_ENTRIES_CEILING_SECS = 60.0
DEEP_LEVELS = 1200
WIDE_SUBDIRS = 300
WIDE_FILE_BYTES = 8192
SPARE_FDS = 24
FAILURE_FLOOD = 1000
ACTION_PATH = ".github/actions/prune-runner-tmp/action.yml"
ACTION_USES = "uses: ./.github/actions/prune-runner-tmp"
SELF_HOSTED_JOBS = {
    ("ci.yml", "check"),
    ("cert-postgres-age.yml", "cert-postgres-age"),
    ("postgres-ignored.yml", "postgres-ignored"),
    ("session-boot-lifetime.yml", "lifetime-tests"),
}
DROPPED_ROOT = "/mnt/t9/tmp"
CONFIRMED_ROOT_CONSTANTS = ("F2_RUNNER_ROOT",)
HOSTILE_NAMES = (
    "old\n::warning::injected",
    "x\r::error::boom",
    "%0A::set-output name=x::y",
    "::stop-commands::tok",
    "tab\there",
    "back\\slash",
    "\x1b[31mred",
    "line sep",
    "bad\udcff\nname",
)
FAILED_TITLE = "::warning title=prune_runner_tmp failed::prune_runner_tmp: "
ANNOTATION_NAMES_SHOWN = 5
ANNOTATION_MAX_CHARS = 1000
ANNOTATION_NAME_MAX_CHARS = 120
ANNOTATION_CUT_MARK = "..."
# raw entry name -> the exact text the annotation carries for it
ANNOTATION_ESCAPES = {
    "::error::x": "\\x3a\\x3aerror\\x3a\\x3ax",
    "%0A::set-output": "\\x250A\\x3a\\x3aset-output",
    "%0D": "\\x250D",
    "a\nb": "a\\x0ab",
    "a\rb": "a\\x0db",
    "::": "\\x3a\\x3a",
    ":::": "\\x3a\\x3a\\x3a",
    ":::0001": "\\x3a\\x3a\\x3a0001",
    "bad\udcffx": "bad\\udcffx",
}
COLON_ESCAPE = "\\x3a"
COLON_CORPUS_ALPHABET =(":", "a", "%", "\\", "\n", "x3a")
COLON_CORPUS_MAX_LEN = 4
ALLOWED_LINE_PREFIXES = ("would-remove ", "pruned=", "prune_runner_tmp: ", "prune-facts: ", ANNOTATION_PREFIX)
# D-H1 (ruling b29 9abefdf7): the platform check is a functional probe of each of these calls.
PROBED_CALLS = ("os.mkdir", "os.open", "os.lstat", "os.scandir", "os.unlink", "os.rmdir")
PROBE_NAME_RE = r"\.prune-probe-[0-9]+-[0-9a-f]+"
SYSTEM_PYTHON = Path("/usr/bin/python3")
PROBE_ERROR = "dir_fd unavailable on this platform"
PLATFORM_REASON = "this platform lacks a working descriptor-relative call: {call} raised NotImplementedError (" + PROBE_ERROR + ")"
MOUNT_UNREADABLE_REASON = "the mount id of TMPDIR cannot be read: {why}"
RESOLVES_ELSEWHERE_REASON = "TMPDIR resolves elsewhere than its normalized path: {path}"
SUMMARY_UNWRITABLE_LINE = "prune_runner_tmp: job summary not written: {why}"
BIND_HELPER_TIMEOUT_SECS = 120
LEFTOVER_LINE_RE = r"^prune_runner_tmp: probe directory left in place: " + PROBE_NAME_RE + "$"
# D-M1: skip reasons and the counted failure text of a directory the walk does not enter.
SKIP_MOUNT_POINT = "a mount point, not entered"
SKIP_MOUNT_UNREADABLE = "mount id unreadable, not entered"
SUMMARY_ENV = "GITHUB_STEP_SUMMARY"

PRUNE = None
CHK = None


def failed_line(count, shown, cut=False):
    """The one annotation line the counted-failure outcome prints, spelled out independently of the script."""
    text = f"{FAILED_TITLE}failed={count} not removed: " + ", ".join(shown)
    if cut:
        text += f" (list cut at {ANNOTATION_NAMES_SHOWN} of {count})"
    return text


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
            elif stat.S_ISREG(info.st_mode):
                seen[rel] = ("file", Path(full).read_bytes(), info.st_mtime_ns)
            else:
                seen[rel] = ("special", stat.S_IFMT(info.st_mode), info.st_mtime_ns)
    return seen


def tree_blocks_bytes(top):
    """Allocated bytes of ``top`` and everything below it (lstat, no symlink followed)."""
    total = os.lstat(top).st_blocks * PRUNE.DISK_BLOCK_BYTES
    for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
        for name in dirnames + filenames:
            total += os.lstat(os.path.join(dirpath, name)).st_blocks * PRUNE.DISK_BLOCK_BYTES
    return total


class Base(unittest.TestCase):
    def setUp(self):
        if PRUNE is None:
            self.fail(f"script under test not found: {SCRIPT}")
        SCRATCH_BASE.mkdir(parents=True, exist_ok=True)
        holder = tempfile.TemporaryDirectory(dir=SCRATCH_BASE, prefix="prune8634-")
        self.addCleanup(holder.cleanup)
        self.base = Path(holder.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()
        self.runner = self.root / "runner-1"
        self.runner.mkdir()
        self.home = self.base / "home"
        self.home.mkdir()
        for patch in (
            mock.patch.dict(os.environ, {"HOME": str(self.home)}),
            mock.patch.object(PRUNE, "ALLOWED_ROOTS", (str(self.root),)),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def run_prune(self, tmpdir, *extra, env_extra=None):
        environ = {} if tmpdir is None else {"TMPDIR": str(tmpdir)}
        environ.update(env_extra or {})
        out, err = io.StringIO(), io.StringIO()
        rc = PRUNE.main(list(extra), environ=environ, out=out, err=err)
        lines = out.getvalue().splitlines(keepends=True)
        self.annotations = [ln.rstrip("\n") for ln in lines if ln.startswith("::")]
        kept = [ln for ln in lines if not ln.startswith(("prune-facts:", "::"))]
        return rc, "".join(kept), err.getvalue()

    def deny_unlink(self):
        """Every unlink of an entry fails with EACCES; the platform probe's own file (D-H1) is not an entry."""
        real_unlink = os.unlink

        def denied(name, *args, **kwargs):
            if str(name) == PRUNE.PROBE_FILE:
                return real_unlink(name, *args, **kwargs)
            raise PermissionError(13, "denied")

        return mock.patch.object(PRUNE.os, "unlink", denied)

    def run_cli(self, tmpdir, *extra, interpreter=None, summary=None):
        """Run the script as a process; allowed roots patched by a tiny wrapper, never by a flag."""
        wrapper = self.base / "wrapper.py"
        wrapper.write_text(
            "import importlib.util, sys\n"
            "spec = importlib.util.spec_from_file_location('p', sys.argv[1])\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            "mod.ALLOWED_ROOTS = (sys.argv[2],)\n"
            "sys.exit(mod.main(sys.argv[3:]))\n"
        )
        env = {k: v for k, v in os.environ.items() if k not in ("TMPDIR", SUMMARY_ENV)}
        if tmpdir is not None:
            env["TMPDIR"] = str(tmpdir)
        if summary is not None:
            env[SUMMARY_ENV] = str(summary)
        done = subprocess.run(
            [interpreter or sys.executable, "-I", str(wrapper), str(SCRIPT), str(self.root), *extra],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        return done.returncode, done.stdout, done.stderr

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

    def open_runner(self):
        fd = os.open(self.runner, PRUNE.DIR_FLAGS)
        self.addCleanup(lambda: os.close(fd))
        return fd, os.fstat(fd)


class PruneRules(Base):
    def test_young_file_and_young_directory_kept(self):
        self.make_file("young.db", YOUNG_AGE_SECS)
        self.make_tree("young-dir", YOUNG_AGE_SECS)
        rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertEqual(out.strip(), "pruned=0 kept=2 failed=0 freed_bytes=0 skipped=0")
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
        self.assertRegex(out.strip(), r"^pruned=3 kept=1 failed=0 freed_bytes=\d+ skipped=0$")
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
        sibling = self.root / "runner-2"
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
        self.assertIn("pruned=2 kept=1 failed=0 freed_bytes=0 skipped=0", out)
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
            if not state["hit"] and str(name) != PRUNE.PROBE_FILE:  # the probe's own file is no entry
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


class EntryKinds(Base):
    """ENTRY_KINDS: file, dir, symlink, FIFO, socket are all removed as themselves; other-device is skipped."""

    def make_kinds(self, parent):
        made = {}
        made["file"] = self.make_file("k-file", OLD_AGE_SECS, parent)
        (parent / "k-dir" / "inner").mkdir(parents=True)
        (parent / "k-dir" / "inner" / "f").write_bytes(b"d")
        made["dir"] = parent / "k-dir"
        os.symlink(self.base, parent / "k-link")
        made["symlink"] = parent / "k-link"
        os.mkfifo(parent / "k-fifo")
        made["fifo"] = parent / "k-fifo"
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(parent / "k-sock"))
        sock.close()
        made["socket"] = parent / "k-sock"
        for path in (parent / "k-dir" / "inner" / "f", parent / "k-dir" / "inner", *made.values()):
            age(path, OLD_AGE_SECS)
        return made

    def test_every_kind_at_top_level_is_removed_and_counted(self):
        self.make_kinds(self.runner)
        outside_before = snapshot(self.base / "root")
        self.assertEqual(len(outside_before), 8)
        rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertIn("pruned=5 kept=0 failed=0", out)
        self.assertEqual(self.names(), [])
        self.assertTrue(self.root.is_dir() and self.home.is_dir())

    def test_every_kind_nested_in_an_old_directory_is_removed(self):
        holder = self.runner / "holder"
        holder.mkdir()
        self.make_kinds(holder)
        age(holder, OLD_AGE_SECS)
        rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertIn("pruned=1 kept=0 failed=0", out)
        self.assertEqual(self.names(), [])

    def test_hard_link_removes_only_the_name(self):
        canary = self.base / "canary"
        canary.write_bytes(b"keep")
        hard = self.runner / "hard"
        os.link(canary, hard)
        age(hard, OLD_AGE_SECS)
        rc, out, _err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("pruned=1", out)
        self.assertEqual(canary.read_bytes(), b"keep")

    def test_other_device_top_level_entries_are_skipped_and_reported_never_entered(self):
        made = self.make_kinds(self.runner)
        before = snapshot(self.runner)
        fd, info = self.open_runner()
        out, err = io.StringIO(), io.StringIO()
        tally = PRUNE.Tally(err)
        PRUNE.prune(fd, info.st_dev + 1, False, time.time(), out, tally)
        self.assertEqual((tally.pruned, tally.failed, tally.skipped), (0, 0, len(made)))
        self.assertEqual(snapshot(self.runner), before)
        lines = err.getvalue().splitlines()
        self.assertEqual(len(lines), len(made))
        for line in lines:
            self.assertRegex(line, r"^prune_runner_tmp: skipped k-\w+: on another device, not entered$")

    def test_other_device_entry_nested_in_an_old_directory_is_skipped_never_entered(self):
        holder = self.runner / "holder"
        (holder / "mount" / "precious").mkdir(parents=True)
        (holder / "mount" / "precious" / "data").write_bytes(b"precious")
        (holder / "plain.db").write_bytes(b"p")
        age(holder, OLD_AGE_SECS)
        fd, info = self.open_runner()
        scanned = os.lstat("holder", dir_fd=fd)
        err = io.StringIO()
        tally = PRUNE.Tally(err)
        real_list = PRUNE.list_level
        calls = {"n": 0}

        def mark_children_foreign(dir_fd, *rest, **kwargs):
            calls["n"] += 1
            return real_list(dir_fd, *rest, **kwargs)

        with mock.patch.object(PRUNE, "list_level", mark_children_foreign):
            with self.assertRaises(OSError):
                PRUNE.remove_tree(fd, "holder", scanned, info.st_dev + 1, tally)
        self.assertEqual(tally.skipped, 2)
        self.assertTrue((holder / "mount" / "precious" / "data").exists())
        self.assertTrue(holder.exists())
        self.assertEqual(err.getvalue().count("on another device, not entered"), 2)


class PathForms(Base):
    """PATH_FORMS: every way TMPDIR can be given; each is accepted or refused with the exact reason."""

    def refused(self, raw, reason, env_extra=None, victim_dir=None):
        victim = self.make_file("old.db", OLD_AGE_SECS, victim_dir or self.runner)
        rc, out, err = self.run_prune(raw, env_extra=env_extra)
        self.assertEqual(rc, EXIT_REFUSED, err)
        self.assertEqual(out, "")
        self.assertEqual(err.rstrip("\n"), f"prune_runner_tmp: refused: {reason}")
        self.assertEqual(self.annotations, [ANNOTATION_PREFIX + reason])
        self.assertTrue(victim.exists(), "a refusal must delete nothing")
        victim.unlink()

    def test_unset_empty_relative_missing_not_directory(self):
        self.refused(None, "TMPDIR is unset")
        self.refused("", "TMPDIR is empty")
        self.refused("runner-1", "TMPDIR is not an absolute path: runner-1")
        self.refused(".", "TMPDIR is not an absolute path: .")
        gone = self.root / "runner-9"
        self.refused(gone, f"TMPDIR does not exist: {gone} (No such file or directory)")
        plain = self.root / "runner-8"
        plain.write_bytes(b"x")
        self.refused(plain, f"TMPDIR is not a directory: {plain}")

    def test_symlink_forms(self):
        link = self.root / "runner-7"
        os.symlink(self.runner, link)
        self.refused(link, f"TMPDIR is a symlink: {link}")
        self.refused(f"{link}/.", f"TMPDIR is a symlink: {link}")
        out_link = self.root / "runner-6"
        os.symlink(self.base, out_link)
        self.refused(out_link, f"TMPDIR is a symlink: {out_link}")

    def test_not_a_runner_directory_below_a_root(self):
        for name in ("skills", "god-zsg", "runner-", "runner-1x", "Runner-1", "runner-1 ", "xrunner-1", "runner--1", "runner-١"):
            with self.subTest(name=name):
                lane = self.root / name
                lane.mkdir()
                self.refused(lane, f"TMPDIR is not named runner-<digits>: {name}", victim_dir=lane)
        nested = self.runner / "nested" / "x"
        nested.mkdir(parents=True)
        self.refused(nested, "TMPDIR is not named runner-<digits>: x")
        self.refused(self.root, "TMPDIR is not named runner-<digits>: root")
        self.refused(f"{self.root}/", "TMPDIR is not named runner-<digits>: root")

    def test_runner_named_directory_not_directly_below_a_root(self):
        inner = self.runner / "runner-2"
        inner.mkdir()
        self.refused(inner, f"TMPDIR is outside the allowed roots {[str(self.root)]}: {inner}", victim_dir=inner)
        twin = self.base / "rootX" / "runner-1"
        twin.mkdir(parents=True)
        self.refused(twin, f"TMPDIR is outside the allowed roots {[str(self.root)]}: {twin}", victim_dir=twin)
        dropped = self.base / "t9tmp" / "runner-5"
        dropped.mkdir(parents=True)
        self.refused(dropped, f"TMPDIR is outside the allowed roots {[str(self.root)]}: {dropped}", victim_dir=dropped)
        dropped_x = self.base / "t9tmp" / "x"
        dropped_x.mkdir()
        self.refused(dropped_x, f"TMPDIR is not named runner-<digits>: x", victim_dir=dropped_x)
        elsewhere = self.base / "runner-5"
        elsewhere.mkdir()
        self.refused(elsewhere, f"TMPDIR is outside the allowed roots {[str(self.root)]}: {elsewhere}", victim_dir=elsewhere)

    def test_accepted_forms_all_prove_the_same_directory(self):
        alias = self.base / "alias"
        os.symlink(self.root, alias)
        forms = [
            str(self.runner),
            f"{self.runner}/",
            f"{self.runner}/.",
            f"{self.runner}/../runner-1",
            f"{self.root}//runner-1",
            f"{alias}/runner-1",
        ]
        for raw in forms:
            with self.subTest(raw=raw):
                self.make_file("goes.db", OLD_AGE_SECS)
                rc, out, err = self.run_prune(raw)
                self.assertEqual((rc, err), (EXIT_OK, ""))
                self.assertIn("pruned=1 kept=0 failed=0", out)
                self.assertEqual(self.names(), [])

    def test_forbidden_by_file_identity_not_by_spelling(self):
        self.refused("/", "TMPDIR is a forbidden path: /")
        self.refused("/tmp", "TMPDIR is a forbidden path: /tmp")
        self.refused(self.home, f"TMPDIR is a forbidden path: {self.home}", victim_dir=self.home)
        via_alias = self.base / "alias"
        os.symlink(self.base, via_alias)
        aliased_home = f"{via_alias}/home"
        self.refused(aliased_home, f"TMPDIR is a forbidden path: {aliased_home}", victim_dir=self.home)
        workspace = self.root / "runner-3"
        workspace.mkdir()
        self.refused(workspace, f"TMPDIR is a forbidden path: {workspace}", env_extra={"GITHUB_WORKSPACE": str(workspace)}, victim_dir=workspace)
        ws_alias = self.base / "ws-alias"
        os.symlink(workspace, ws_alias)
        self.refused(workspace, f"TMPDIR is a forbidden path: {workspace}", env_extra={"GITHUB_WORKSPACE": str(ws_alias)}, victim_dir=workspace)

    def test_contains_the_workspace_or_the_working_directory(self):
        workspace = self.runner / "ws"
        workspace.mkdir()
        reason = f"TMPDIR contains the home directory or the workspace: {self.runner}"
        self.refused(self.runner, reason, env_extra={"GITHUB_WORKSPACE": str(workspace)})
        previous = os.getcwd()
        os.chdir(workspace)
        try:
            self.refused(self.runner, reason)
        finally:
            os.chdir(previous)

    def test_not_owned_by_current_user(self):
        with mock.patch.object(PRUNE.os, "geteuid", return_value=os.geteuid() + 1):
            self.refused(self.runner, f"TMPDIR is not owned by the current user: {self.runner}")

    @unittest.skipIf(os.geteuid() == 0, "root can open any directory")
    def test_unopenable_directory(self):
        self.runner.chmod(0)
        self.addCleanup(lambda: self.runner.chmod(0o700))
        rc, _out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_REFUSED)
        self.assertEqual(err.strip(), f"prune_runner_tmp: refused: TMPDIR cannot be opened: {self.runner} (Permission denied)")

    def test_directory_swapped_between_lstat_and_open_is_refused(self):
        victim = self.make_file("old.db", OLD_AGE_SECS)
        real_open = os.open
        state = {"swapped": False}

        def swapping(path, flags, *args, **kwargs):
            if not state["swapped"] and str(path) == str(self.runner):
                state["swapped"] = True
                os.rename(self.runner, self.base / "moved-away")
                self.runner.mkdir()
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(PRUNE.os, "open", swapping):
            rc, _out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_REFUSED)
        self.assertEqual(err.strip(), f"prune_runner_tmp: refused: TMPDIR changed while it was opened: {self.runner}")
        self.assertTrue((self.base / "moved-away" / victim.name).exists())

    def test_directory_swapped_after_the_proof_is_not_the_one_pruned(self):
        victim = self.base / "elsewhere"
        victim.mkdir()
        keep = self.make_file("lost.db", OLD_AGE_SECS, victim)
        self.make_file("mine.db", OLD_AGE_SECS)
        real_prune = PRUNE.prune

        def swapping(dir_fd, *args, **kwargs):
            os.rename(self.runner, self.root / "runner-1.orig")
            os.rename(victim, self.runner)
            return real_prune(dir_fd, *args, **kwargs)

        with mock.patch.object(PRUNE, "prune", swapping):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertIn("pruned=1 kept=0 failed=0", out)
        self.assertTrue((self.runner / keep.name).exists(), "the swapped-in directory was not pruned")
        self.assertFalse((self.root / "runner-1.orig" / "mine.db").exists(), "the proven directory was pruned")

    def test_python_below_the_floor_is_refused_before_anything_is_deleted(self):
        victim = self.make_file("old.db", OLD_AGE_SECS)
        with mock.patch.object(sys, "version_info", (3, 11, 9, "final", 0)):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, out), (EXIT_REFUSED, ""))
        self.assertEqual(err.strip(), "prune_runner_tmp: refused: python 3.11.9 is older than 3.12")
        self.assertTrue(victim.exists())

    def test_tmpdir_resolving_elsewhere_than_its_normalized_path_is_refused(self):
        """LATE (:240): ``<root>/lnk/../runner-2`` normalizes to a sibling runner dir the kernel never opens."""
        sibling = self.root / "runner-2"
        sibling.mkdir()
        sibling_victim = self.make_file("old.db", OLD_AGE_SECS, sibling)
        elsewhere = self.base / "other" / "runner-2"
        (self.base / "other" / "deep").mkdir(parents=True)
        elsewhere.mkdir()
        elsewhere_victim = self.make_file("old.db", OLD_AGE_SECS, elsewhere)
        (self.root / "lnk").symlink_to(self.base / "other" / "deep")
        raw = f"{self.root}/lnk/../runner-2"
        self.assertEqual(os.path.realpath(raw), str(elsewhere))
        reason = RESOLVES_ELSEWHERE_REASON.format(path=raw)
        for case in ("the kernel path exists", "the kernel path is missing"):
            with self.subTest(case=case):
                rc, out, err = self.run_prune(raw)
                self.assertEqual((rc, out), (EXIT_REFUSED, ""))
                self.assertEqual(err.rstrip("\n"), f"prune_runner_tmp: refused: {reason}")
                self.assertEqual(self.annotations, [ANNOTATION_PREFIX + reason])
                self.assertTrue(sibling_victim.exists(), "the sibling the lexical path names is untouched")
                if elsewhere_victim.exists():
                    elsewhere_victim.unlink()
                    elsewhere.rmdir()


class PlatformProbe(Base):
    """D-H1: the platform check is one real dir_fd call of each needed function on a directory it makes and removes."""

    def break_call(self, call):
        """Patch ``call`` so its descriptor-relative form raises NotImplementedError; the path form still works."""
        attr = call.split(".", 1)[1]
        real = getattr(os, attr)

        def broken(*args, **kwargs):
            relative = kwargs.get("dir_fd") is not None or (attr == "scandir" and args and isinstance(args[0], int))
            if relative:
                raise NotImplementedError(PROBE_ERROR)
            return real(*args, **kwargs)

        return mock.patch.object(PRUNE.os, attr, broken)

    def probe_dirs(self):
        return sorted(p.name for p in self.runner.iterdir() if re.fullmatch(PROBE_NAME_RE, p.name))

    def test_every_probed_call_made_to_fail_is_the_exact_refusal_and_deletes_nothing(self):
        leaves_probe = {"os.unlink", "os.rmdir"}
        for call in PROBED_CALLS:
            with self.subTest(call=call):
                victim = self.make_file("old.db", OLD_AGE_SECS)
                with self.break_call(call):
                    rc, out, err = self.run_prune(self.runner)
                reason = PLATFORM_REASON.format(call=call)
                self.assertEqual((rc, out), (EXIT_REFUSED, ""))
                lines = err.splitlines()
                self.assertEqual(lines[-1], f"prune_runner_tmp: refused: {reason}")
                self.assertEqual(self.annotations, [ANNOTATION_PREFIX + reason])
                self.assertTrue(victim.exists(), "a refusal must delete nothing")
                left = self.probe_dirs()
                if call in leaves_probe:
                    self.assertEqual(len(left), 1, left)
                    self.assertEqual(len(lines), 2, err)
                    self.assertRegex(lines[0], LEFTOVER_LINE_RE)
                    self.assertIn(left[0], lines[0])
                    for leftover in left:
                        for child in (self.runner / leftover).iterdir():
                            child.unlink()
                        (self.runner / leftover).rmdir()
                else:
                    self.assertEqual(left, [], "the probe removed its own directory")
                    self.assertEqual(len(lines), 1, err)
                victim.unlink()

    def test_a_working_platform_leaves_no_probe_behind_in_both_modes(self):
        young = self.make_file("young.db", YOUNG_AGE_SECS)
        for extra in ((), ("--dry-run",)):
            with self.subTest(extra=extra):
                rc, out, err = self.run_prune(self.runner, *extra)
                self.assertEqual((rc, err), (EXIT_OK, ""))
                self.assertIn("pruned=0 kept=1 failed=0", out)
                self.assertEqual(self.names(), ["young.db"])
        self.assertTrue(young.exists())

    def test_platform_check_gives_the_same_answer_under_every_runner_interpreter(self):
        """Ruling b29 9abefdf7: run under /usr/bin/python3 when present and under sys.executable."""
        interpreters = [sys.executable]
        if SYSTEM_PYTHON.exists():
            interpreters.append(str(SYSTEM_PYTHON))
        breaker = self.base / "breaker.py"
        breaker.write_text(
            "import importlib.util, os, sys\n"
            "spec = importlib.util.spec_from_file_location('p', sys.argv[1])\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            "mod.ALLOWED_ROOTS = (sys.argv[2],)\n"
            "real = os.lstat\n"
            "def broken(*args, **kwargs):\n"
            "    if kwargs.get('dir_fd') is not None:\n"
            f"        raise NotImplementedError({PROBE_ERROR!r})\n"
            "    return real(*args, **kwargs)\n"
            "os.lstat = broken\n"
            "sys.exit(mod.main([]))\n"
        )
        env = {k: v for k, v in os.environ.items() if k not in ("TMPDIR", SUMMARY_ENV)}
        env["TMPDIR"] = str(self.runner)
        for interpreter in interpreters:
            with self.subTest(interpreter=interpreter):
                self.make_file("old.db", OLD_AGE_SECS)
                rc, out, err = self.run_cli(self.runner, interpreter=interpreter)
                self.assertEqual((rc, err), (EXIT_OK, ""))
                self.assertNotIn("refused", out)
                self.assertRegex(out, r"(?m)^pruned=1 kept=0 failed=0 freed_bytes=\d+ skipped=0$")
                self.assertEqual(self.names(), [])
                victim = self.make_file("old.db", OLD_AGE_SECS)
                done = subprocess.run(
                    [interpreter, "-I", str(breaker), str(SCRIPT), str(self.root)],
                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
                )
                reason = PLATFORM_REASON.format(call="os.lstat")
                self.assertEqual(done.returncode, EXIT_REFUSED)
                self.assertEqual(done.stderr, f"prune_runner_tmp: refused: {reason}\n")
                self.assertIn(ANNOTATION_PREFIX + reason, done.stdout.splitlines())
                self.assertTrue(victim.exists())
                self.assertEqual(self.probe_dirs(), [])
                victim.unlink()


class MountCrossing(Base):
    """D-M1: the walk never enters a directory that is a mount point, whatever its st_dev, and never deletes through one."""

    def mount_id_override(self, target, value=None, unreadable=False):
        """Patch mount_id so the directory with identity ``target`` reads as another mount (or as unreadable)."""
        real = PRUNE.mount_id

        def fake(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == target:
                if unreadable:
                    raise PRUNE.MountIdUnreadable("fdinfo has no mnt_id line")
                return value
            return real(fd)

        return mock.patch.object(PRUNE, "mount_id", fake)

    def ident(self, path):
        info = os.lstat(path)
        return (info.st_dev, info.st_ino)

    def stale_holder(self):
        holder = self.runner / "holder"
        (holder / "inner" / "precious").mkdir(parents=True)
        (holder / "inner" / "precious" / "data").write_bytes(b"precious")
        (holder / "plain.db").write_bytes(b"p")
        age(holder, OLD_AGE_SECS)
        return holder

    def test_root_mount_id_is_read_on_linux(self):
        if not sys.platform.startswith("linux"):
            self.skipTest(f"mount ids come from /proc/self/fdinfo on Linux only (platform {sys.platform})")
        fd, _info = self.open_runner()
        self.assertIsInstance(PRUNE.mount_id(fd), int)

    def test_top_level_mount_point_is_skipped_never_entered(self):
        holder = self.stale_holder()
        with self.mount_id_override(self.ident(holder), value=-1):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(err.splitlines(), [f"prune_runner_tmp: skipped holder: {SKIP_MOUNT_POINT}"])
        self.assertIn("pruned=0 kept=0 failed=0 freed_bytes=0 skipped=1", out)
        self.assertEqual((holder / "inner" / "precious" / "data").read_bytes(), b"precious")
        self.assertTrue((holder / "plain.db").exists(), "nothing below a mount point is deleted")

    def test_nested_mount_point_is_skipped_and_its_parent_counted(self):
        holder = self.stale_holder()
        with self.mount_id_override(self.ident(holder / "inner"), value=-1):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(
            err.splitlines(),
            [
                f"prune_runner_tmp: skipped inner: {SKIP_MOUNT_POINT}",
                f"prune_runner_tmp: failed to remove holder: inner: {SKIP_MOUNT_POINT}",
            ],
        )
        self.assertRegex(out, r"pruned=0 kept=0 failed=1 freed_bytes=\d+ skipped=1")
        self.assertEqual((holder / "inner" / "precious" / "data").read_bytes(), b"precious")

    def test_unreadable_mount_id_is_a_skip_and_a_counted_failure_never_an_entry(self):
        for where in ("top", "nested"):
            with self.subTest(where=where):
                holder = self.stale_holder()
                target = holder if where == "top" else holder / "inner"
                with self.mount_id_override(self.ident(target), unreadable=True):
                    rc, out, err = self.run_prune(self.runner)
                self.assertEqual(rc, EXIT_OK)
                name = target.name
                failed_text = f"{name}: {SKIP_MOUNT_UNREADABLE}"
                self.assertEqual(
                    err.splitlines(),
                    [
                        f"prune_runner_tmp: skipped {name}: {SKIP_MOUNT_UNREADABLE}",
                        f"prune_runner_tmp: failed to remove holder: {failed_text}",
                    ],
                )
                self.assertRegex(out, r"pruned=0 kept=0 failed=1 freed_bytes=\d+ skipped=1")
                self.assertEqual((holder / "inner" / "precious" / "data").read_bytes(), b"precious")
                if where == "top":
                    self.assertTrue((holder / "plain.db").exists())
                subprocess.run(["rm", "-rf", str(holder)], check=True)

    def test_unreadable_root_mount_id_is_a_refusal(self):
        victim = self.make_file("old.db", OLD_AGE_SECS)

        def unreadable(fd):
            raise PRUNE.MountIdUnreadable("fdinfo has no mnt_id line")

        with mock.patch.object(PRUNE, "mount_id", unreadable):
            rc, out, err = self.run_prune(self.runner)
        reason = MOUNT_UNREADABLE_REASON.format(why="fdinfo has no mnt_id line")
        self.assertEqual((rc, out), (EXIT_REFUSED, ""))
        self.assertEqual(err.rstrip("\n"), f"prune_runner_tmp: refused: {reason}")
        self.assertTrue(victim.exists())

    def test_same_device_bind_mount_inside_a_stale_entry_is_never_entered(self):
        """unshare-gated: a real bind mount of a directory outside the root, same st_dev, inside a stale entry."""
        unshare, mount = shutil.which("unshare"), shutil.which("mount")
        if not sys.platform.startswith("linux") or unshare is None or mount is None:
            self.skipTest(f"bind-mount cell needs Linux unshare and mount (platform {sys.platform}, "
                          f"unshare {unshare}, mount {mount})")
        probe = subprocess.run([unshare, "-r", "-m", mount, "--bind", str(self.base), str(self.home)],
                               capture_output=True, text=True, check=False, timeout=BIND_HELPER_TIMEOUT_SECS)
        if probe.returncode != 0:
            self.skipTest(f"unshare -r -m bind mount unavailable here: rc={probe.returncode} {probe.stderr.strip()}")
        source = self.base / "bind-source"
        source.mkdir()
        canary = source / "canary"
        canary.write_bytes(b"canary")
        stale = self.runner / "stale"
        (stale / "m").mkdir(parents=True)
        (stale / "f.db").write_bytes(b"f")
        self.assertEqual(os.lstat(source).st_dev, os.lstat(stale).st_dev, "the bind source is on the same device")
        age(stale, OLD_AGE_SECS)
        helper = self.base / "bind-helper.py"
        helper.write_text(
            "import importlib.util, subprocess, sys\n"
            "mount, source, target, script, root = sys.argv[1:6]\n"
            "subprocess.run([mount, '--bind', source, target], check=True)\n"
            "spec = importlib.util.spec_from_file_location('p', script)\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            "mod.ALLOWED_ROOTS = (root,)\n"
            "sys.exit(mod.main([]))\n"
        )
        env = {k: v for k, v in os.environ.items() if k not in ("TMPDIR", SUMMARY_ENV)}
        env["TMPDIR"] = str(self.runner)
        done = subprocess.run(
            [unshare, "-r", "-m", sys.executable, "-I", str(helper), mount, str(source), str(stale / "m"),
             str(SCRIPT), str(self.root)],
            env=env, capture_output=True, text=True, check=False, timeout=BIND_HELPER_TIMEOUT_SECS,
        )
        self.assertEqual(done.returncode, EXIT_OK, done.stderr)
        self.assertEqual(canary.read_bytes(), b"canary", "the bind source outside the root survives")
        self.assertEqual(
            done.stderr.splitlines(),
            [
                f"prune_runner_tmp: skipped m: {SKIP_MOUNT_POINT}",
                f"prune_runner_tmp: failed to remove stale: m: {SKIP_MOUNT_POINT}",
            ],
        )
        self.assertRegex(done.stdout, r"(?m)^pruned=0 kept=0 failed=1 freed_bytes=\d+ skipped=1$")
        self.assertTrue((stale / "m").is_dir())


class RootForms(Base):
    """ROOT_FORMS: every way an allowed root can be spelled; a root that is or aliases '/' is refused."""

    def check(self, root, reason):
        victim = self.make_file("old.db", OLD_AGE_SECS)
        with mock.patch.object(PRUNE, "ALLOWED_ROOTS", (root,)):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, out), (EXIT_REFUSED, ""), root)
        self.assertEqual(err.rstrip("\n"), f"prune_runner_tmp: refused: {reason}")
        self.assertEqual(self.annotations, [ANNOTATION_PREFIX + reason])
        self.assertTrue(victim.exists())
        victim.unlink()

    def test_slash_in_every_spelling_is_refused(self):
        deep = self.base
        up = "/".join([".."] * len(deep.parts))
        for root in ("/", "/.", "//", "//.", "///", f"{deep}/{up}", f"{deep}/../../../../../../../../../../.."):
            with self.subTest(root=root):
                self.check(root, "allowed root is '/'")

    def test_relative_and_empty_roots_are_refused(self):
        for root in ("", ".", "root", "../root", "runner-tmp/"):
            with self.subTest(root=root):
                self.check(root, f"allowed root is not an absolute path: {root}")

    def test_slash_alias_by_symlink_is_refused(self):
        alias = self.base / "slash-alias"
        os.symlink("/", alias)
        self.check(str(alias), "allowed root is '/'")

    def test_a_missing_root_is_skipped_and_the_others_still_work(self):
        self.make_file("old.db", OLD_AGE_SECS)
        with mock.patch.object(PRUNE, "ALLOWED_ROOTS", (str(self.base / "no-such-root"), str(self.root))):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertIn("pruned=1 kept=0 failed=0", out)

    def test_a_directory_equal_to_a_root_alias_of_another_root_is_not_accepted_twice(self):
        other = self.base / "other-root"
        (other / "runner-1").mkdir(parents=True)
        victim = self.make_file("old.db", OLD_AGE_SECS, other / "runner-1")
        with mock.patch.object(PRUNE, "ALLOWED_ROOTS", (str(self.root),)):
            rc, _out, err = self.run_prune(other / "runner-1")
        self.assertEqual(rc, EXIT_REFUSED, err)
        self.assertTrue(victim.exists())


class HostileNames(Base):
    """HOSTILE_NAMES: no entry name can add a line or a workflow command to the log."""

    def lines_ok(self, text):
        for line in text.splitlines():
            self.assertTrue(line.startswith(ALLOWED_LINE_PREFIXES), repr(line))
            self.assertFalse(line.startswith("::"), repr(line))
        self.assertNotIn("\r", text)

    def make_named(self, name, as_dir):
        raw = os.path.join(os.fsencode(self.runner), os.fsencode(name))
        if as_dir:
            os.mkdir(raw)
            os.mkdir(os.path.join(raw, b"sub"))
            Path(os.fsdecode(os.path.join(raw, b"sub", b"f"))).write_bytes(b"x")
            os.utime(raw, (time.time() - OLD_AGE_SECS,) * 2)
        else:
            Path(os.fsdecode(raw)).write_bytes(b"x")
            os.utime(raw, (time.time() - OLD_AGE_SECS,) * 2)
        return raw

    def test_dry_run_lines_carry_no_injection(self):
        for index, name in enumerate(HOSTILE_NAMES):
            self.make_named(f"{index}-{name}", as_dir=False)
        rc, out, err = self.run_prune(self.runner, "--dry-run")
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.lines_ok(out)
        self.assertEqual(len(out.splitlines()), len(HOSTILE_NAMES) + 1)
        self.assertIn(f"pruned={len(HOSTILE_NAMES)} ", out)

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_failure_lines_carry_no_injection(self):
        locked = []
        for index, name in enumerate(HOSTILE_NAMES):
            raw = self.make_named(f"{index}-{name}", as_dir=True)
            os.chmod(os.path.join(raw, b"sub"), 0o500)
            locked.append(raw)
        self.addCleanup(lambda: [os.chmod(os.path.join(raw, b"sub"), 0o700) for raw in locked])
        rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn(f"failed={len(HOSTILE_NAMES)} ", out)
        self.lines_ok(err)
        self.assertEqual(len(err.splitlines()), len(HOSTILE_NAMES))

    def test_safe_text_forms(self):
        cases = {
            "plain-name.db": "plain-name.db",
            "a\nb": "a\\x0ab",
            "a\rb": "a\\x0db",
            "::error::boom": "\\x3a\\x3aerror\\x3a\\x3aboom",
            "%0A": "\\x250A",
            "a\\b": "a\\\\b",
            "bad\udcff": "bad\\udcff",
            ":": "\\x3a",
            ":::": "\\x3a\\x3a\\x3a",
            ":::0001": "\\x3a\\x3a\\x3a0001",
        }
        for raw, want in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(PRUNE.safe_text(raw), want)
        # exact bytes of the two pinned forms (D-L1)
        self.assertEqual(PRUNE.safe_text(":::").encode(), b"\\x3a\\x3a\\x3a")
        self.assertEqual(PRUNE.safe_text(":::0001").encode(), b"\\x3a\\x3a\\x3a0001")

    def test_safe_text_leaves_no_colon_and_is_injective_over_the_corpus(self):
        """D-L1 class invariant: every ':' is escaped (no '::' can survive any input) and no two inputs collide."""
        seen = {}
        frontier = [""]
        for _ in range(COLON_CORPUS_MAX_LEN):
            frontier = [prefix + piece for prefix in frontier for piece in COLON_CORPUS_ALPHABET]
            for raw in frontier:
                text = PRUNE.safe_text(raw)
                self.assertNotIn(":", text, repr(raw))
                self.assertNotIn("%", text, repr(raw))
                self.assertNotIn("\n", text, repr(raw))
                self.assertEqual(seen.setdefault(text, raw), raw, f"{raw!r} and {seen[text]!r} collide")
        big = ":" * 200_000
        started = time.monotonic()
        self.assertEqual(PRUNE.safe_text(big), "\\x3a" * 200_000)
        self.assertLess(time.monotonic() - started, MANY_ENTRIES_CEILING_SECS)

    def test_refusal_reason_and_facts_escape_the_tmpdir_text(self):
        rc, out, err = self.run_prune("/no/such\n::error::x")
        self.assertEqual(rc, EXIT_REFUSED)
        self.assertEqual(len(err.splitlines()), 1)
        self.lines_ok(err)
        self.assertEqual(len(self.annotations), 1)
        self.assertTrue(self.annotations[0].startswith(ANNOTATION_PREFIX))
        self.assertNotIn("::error::", self.annotations[0].replace(ANNOTATION_PREFIX, ""))
        merged = io.StringIO()
        PRUNE.print_runner_facts("/no/such\n::error::x", (), merged)
        self.assertEqual(len(merged.getvalue().splitlines()), 1)


class Robustness(Base):
    def test_deep_tree_is_removed_without_recursion(self):
        top = self.runner / "deep"
        top.mkdir()
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(top)], check=False))
        fd = os.open(top, os.O_RDONLY | os.O_DIRECTORY)
        for _ in range(DEEP_LEVELS):
            os.mkdir("d", dir_fd=fd)
            nxt = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = nxt
        os.close(fd)
        age(top, OLD_AGE_SECS)
        self.make_file("zz-after.db", OLD_AGE_SECS)
        rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertIn("pruned=2 kept=0 failed=0", out)
        self.assertEqual(self.names(), [])

    def test_tree_deeper_than_the_depth_bound_is_one_counted_failure_left_in_place(self):
        top = self.runner / "deep"
        top.mkdir()
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(top)], check=False))
        fd = os.open(top, os.O_RDONLY | os.O_DIRECTORY)
        for _ in range(12):
            os.mkdir("d", dir_fd=fd)
            nxt = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = nxt
        os.close(fd)
        age(top, OLD_AGE_SECS)
        self.make_file("zz-after.db", OLD_AGE_SECS)
        with mock.patch.object(PRUNE, "MAX_TREE_DEPTH", 5):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("pruned=1 kept=0 failed=1", out)
        self.assertIn("failed to remove deep: deeper than 5 levels", err)
        self.assertEqual(self.names(), ["deep"])
        self.assertNotIn("Traceback", err + out)

    def test_tree_with_more_entries_than_the_entry_bound_is_one_counted_failure(self):
        holder = self.runner / "wide-bound"
        holder.mkdir()
        for index in range(10):
            (holder / f"f{index}").write_bytes(b"x")
        age(holder, OLD_AGE_SECS)
        with mock.patch.object(PRUNE, "MAX_TREE_ENTRIES", 4):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("pruned=0 kept=0 failed=1", out)
        self.assertIn("failed to remove wide-bound: more than 4 entries under one top-level entry", err)
        self.assertTrue(holder.exists())

    def chain(self, name, levels):
        """``<runner>/<name>/d/d/...`` with ``levels`` directories below the top and a file at the bottom."""
        top = self.runner / name
        bottom = top.joinpath(*(["d"] * levels))
        bottom.mkdir(parents=True)
        (bottom / "leaf.db").write_bytes(b"leaf")
        age(top, OLD_AGE_SECS)
        return top

    def test_depth_bound_is_exact_at_max_and_max_plus_one(self):
        """D-L2: a tree exactly MAX_TREE_DEPTH levels deep goes; MAX+1 is one counted failure, untouched."""
        bound = 5
        at_max = self.chain("at-max", bound)
        over = self.chain("over-max", bound + 1)
        before = snapshot(over)
        with mock.patch.object(PRUNE, "MAX_TREE_DEPTH", bound):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(err.splitlines(), [f"prune_runner_tmp: failed to remove over-max: deeper than {bound} levels"])
        self.assertIn("pruned=1 kept=0 failed=1", out)
        self.assertFalse(at_max.exists())
        self.assertEqual(snapshot(over), before, "a tree over the depth bound is untouched")

    def test_entry_bound_is_counted_before_anything_is_removed(self):
        """D-L3: a tree of exactly MAX_TREE_ENTRIES entries goes; MAX+1 is one counted failure, untouched."""
        bound = 6
        for name, count in (("at-max", bound), ("over-max", bound + 1)):
            holder = self.runner / name
            (holder / "sub").mkdir(parents=True)
            for index in range(count - 1):
                (holder / "sub" / f"f{index}").write_bytes(b"x")
            age(holder, OLD_AGE_SECS)
        before = snapshot(self.runner / "over-max")
        with mock.patch.object(PRUNE, "MAX_TREE_ENTRIES", bound):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(
            err.splitlines(),
            [f"prune_runner_tmp: failed to remove over-max: more than {bound} entries under one top-level entry"],
        )
        self.assertIn("pruned=1 kept=0 failed=1", out)
        self.assertEqual(self.names(), ["over-max"])
        self.assertEqual(snapshot(self.runner / "over-max"), before, "a tree over the entry bound is untouched")

    def test_tree_grown_past_the_bound_during_removal_is_a_counted_partial_failure(self):
        """D-L3 race backstop: entries added after the count are still bounded; the partial state is pinned."""
        bound = 4
        holder = self.runner / "growing"
        (holder / "a").mkdir(parents=True)
        (holder / "b").mkdir()
        (holder / "a" / "f").write_bytes(b"x")
        age(holder, OLD_AGE_SECS)
        real_list = PRUNE.list_level
        state = {"grown": False}

        def grow(dir_fd, *rest, **kwargs):
            if kwargs.get("remove") and not state["grown"]:
                state["grown"] = True
                for index in range(bound):
                    (holder / "b" / f"late{index}").write_bytes(b"y")
            return real_list(dir_fd, *rest, **kwargs)

        with mock.patch.object(PRUNE, "MAX_TREE_ENTRIES", bound), mock.patch.object(PRUNE, "list_level", grow):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(
            err.splitlines(),
            [f"prune_runner_tmp: failed to remove growing: more than {bound} entries under one top-level entry"],
        )
        self.assertIn("pruned=0 kept=0 failed=1", out)
        self.assertTrue(holder.exists(), "the top-level entry stays when the bound is hit during removal")

    def test_directory_moved_during_removal_stops_the_entry_with_the_exact_reason(self):
        """D-L4: the up-walk re-checks the parent identity; a directory moved mid-walk is never deleted elsewhere."""
        top = self.runner / "top"
        (top / "a" / "b").mkdir(parents=True)
        (top / "a" / "b" / "f").write_bytes(b"x")
        age(top, OLD_AGE_SECS)
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep").write_bytes(b"keep")
        b_ident = os.lstat(top / "a" / "b")
        real_list = PRUNE.list_level
        state = {"moved": False}

        def move_b(dir_fd, *rest, **kwargs):
            pending = real_list(dir_fd, *rest, **kwargs)
            info = os.fstat(dir_fd)
            if kwargs.get("remove") and not state["moved"] and (info.st_dev, info.st_ino) == (b_ident.st_dev, b_ident.st_ino):
                state["moved"] = True
                os.rename(top / "a" / "b", outside / "b")
            return pending

        with mock.patch.object(PRUNE, "list_level", move_b):
            rc, out, err = self.run_prune(self.runner)
        self.assertTrue(state["moved"])
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(err.splitlines(), ["prune_runner_tmp: failed to remove top: directory moved during removal"])
        self.assertIn("pruned=0 kept=0 failed=1", out)
        self.assertTrue((outside / "b").is_dir(), "the moved directory is not removed from its new parent")
        self.assertEqual((outside / "keep").read_bytes(), b"keep")
        self.assertTrue((top / "a").is_dir())

    def test_internal_error_is_named_prints_the_summary_and_exits_red(self):
        self.make_file("old.db", OLD_AGE_SECS)
        with mock.patch.object(PRUNE, "remove_entry", side_effect=ValueError("boom")):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_ERROR)
        self.assertEqual(err.strip(), "prune_runner_tmp: internal error, pruning stopped: ValueError: boom")
        self.assertEqual(out.strip(), "pruned=0 kept=0 failed=0 freed_bytes=0 skipped=0 internal_error=1")

    def test_wide_tree_freed_bytes_is_exact_under_a_low_fd_limit(self):
        holder = self.runner / "wide"
        holder.mkdir()
        for index in range(WIDE_SUBDIRS):
            sub = holder / f"s{index:04d}"
            sub.mkdir()
            (sub / "f.db").write_bytes(b"w" * WIDE_FILE_BYTES)
        age(holder, OLD_AGE_SECS)
        expected = tree_blocks_bytes(holder)
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        in_use = len(os.listdir("/dev/fd"))
        resource.setrlimit(resource.RLIMIT_NOFILE, (in_use + SPARE_FDS, hard))
        try:
            rc, out, err = self.run_prune(self.runner)
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertEqual(out.strip(), f"pruned=1 kept=0 failed=0 freed_bytes={expected} skipped=0")
        self.assertEqual(self.names(), [])

    def test_inode_reuse_between_scan_and_recheck_is_refused(self):
        victim = self.runner / "victim"
        victim.mkdir()
        age(victim, OLD_AGE_SECS)
        real_remove = PRUNE.remove_entry

        def swapping(dir_fd, name, *args):
            if name == "victim":
                os.rmdir(victim)
                victim.mkdir()
                (victim / "live").write_bytes(b"live")
            return real_remove(dir_fd, name, *args)

        with mock.patch.object(PRUNE, "remove_entry", swapping):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("pruned=0 kept=0 failed=1", out)
        self.assertIn("failed to remove victim: entry changed since scan", err)
        self.assertEqual((victim / "live").read_bytes(), b"live")

    def test_directory_swapped_for_a_symlink_before_recheck_is_refused(self):
        outside = self.base / "outside"
        outside.mkdir()
        canary = self.make_file("canary", OLD_AGE_SECS, outside)
        victim = self.runner / "victim"
        victim.mkdir()
        age(victim, OLD_AGE_SECS)
        real_remove = PRUNE.remove_entry

        def swapping(dir_fd, name, *args):
            os.rmdir(victim)
            os.symlink(outside, victim)
            return real_remove(dir_fd, name, *args)

        with mock.patch.object(PRUNE, "remove_entry", swapping):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn("failed=1", out)
        self.assertIn("entry changed since scan", err)
        self.assertTrue(canary.exists())

    def test_failure_lines_are_capped(self):
        for index in range(FAILURE_FLOOD):
            self.make_file(f"f{index}", OLD_AGE_SECS)
        with self.deny_unlink():
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(err.count("failed to remove"), PRUNE.MAX_FAILURE_LINES)
        self.assertIn(f"failed={FAILURE_FLOOD}", out)

    def test_facts_line_prints_no_other_env(self):
        rc, out, err = self.run_prune(self.runner, env_extra={"GITHUB_TOKEN": "ghs_SENTINEL_8634"})
        self.assertEqual(rc, EXIT_OK)
        self.assertNotIn("SENTINEL", out + err)


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
        self.assertEqual(out.strip(), f"pruned={MANY_ENTRIES // 2} kept={MANY_ENTRIES // 2} failed=0 freed_bytes=0 skipped=0")
        self.assertEqual(spy.call_count, 2, "one scandir pass over TMPDIR plus the probe's one over its own directory")
        self.assertLess(elapsed, MANY_ENTRIES_CEILING_SECS)
        self.assertEqual(len(os.listdir(self.runner)), MANY_ENTRIES // 2)


class RunnerFacts(Base):
    """The prune prints its facts line before it judges anything (#8634, b29 ca55daab)."""

    def facts_line(self, text):
        found = [ln for ln in text.splitlines() if ln.startswith("prune-facts:")]
        self.assertEqual(len(found), 1, text)
        return found[0]

    def run_merged(self, tmpdir, *extra):
        rc, out, err = self.run_cli(tmpdir, *extra)
        return rc, out + err

    def expected(self, tmpdir, resolved, symlink, allowed):
        return (
            f"prune-facts: tmpdir={tmpdir} resolved={resolved} symlink={symlink} "
            f"allowed_root={allowed} python={sys.version.splitlines()[0].replace(':', COLON_ESCAPE)} "
            f"executable={sys.executable.replace(':', COLON_ESCAPE)}"
        )

    def test_facts_line_goes_to_the_job_summary_when_it_is_set(self):
        summary = self.base / "step-summary.md"
        summary.write_text("earlier step\n")
        out_rc, stdout, stderr = self.run_cli_summary(self.runner, summary)
        self.assertEqual((out_rc, stderr), (EXIT_OK, ""))
        facts = self.facts_line(stdout)
        self.assertEqual(summary.read_text(), "earlier step\n" + facts + "\n")

    def test_no_job_summary_when_it_is_unset(self):
        rc, stdout, stderr = self.run_cli(self.runner)
        self.assertEqual((rc, stderr), (EXIT_OK, ""))
        self.facts_line(stdout)
        self.assertEqual(sorted(p.name for p in self.base.iterdir() if p.name.startswith("step-summary")), [])

    def test_unwritable_job_summary_is_named_and_changes_no_exit_code(self):
        self.make_file("old.db", OLD_AGE_SECS)
        for kind, summary, why in (
            ("directory", self.base, "Is a directory"),
            ("missing", self.base / "no-such" / "summary.md", "No such file or directory"),
        ):
            with self.subTest(kind=kind):
                rc, stdout, stderr = self.run_cli_summary(self.runner, summary)
                self.assertEqual(rc, EXIT_OK)
                self.assertEqual(stderr.splitlines(), [SUMMARY_UNWRITABLE_LINE.format(why=why)])
                self.facts_line(stdout)
                self.assertRegex(stdout, r"pruned=\d+ kept=0 failed=0 ")
        self.assertEqual(self.names(), [])

    def test_job_summary_line_is_sanitised(self):
        summary = self.base / "step-summary.md"
        summary.write_text("")
        rc, out, err = self.run_prune("/no/such\n::error::x", env_extra={SUMMARY_ENV: str(summary)})
        self.assertEqual(rc, EXIT_REFUSED)
        written = summary.read_text()
        self.assertEqual(written.count("\n"), 1)
        self.assertTrue(written.startswith("prune-facts: tmpdir=/no/such\\x0a\\x3a\\x3aerror\\x3a\\x3ax "), written)
        self.assertNotIn("::", written)

    def run_cli_summary(self, tmpdir, summary):
        return self.run_cli(tmpdir, summary=summary)

    def test_facts_line_inside_allowed_root(self):
        rc, text = self.run_merged(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(text.splitlines()[0], self.expected(self.runner, self.runner, "no", self.root))

    def test_facts_line_precedes_the_refusal_outside_every_root(self):
        other = self.base / "runner-4"
        other.mkdir()
        rc, text = self.run_merged(other)
        self.assertEqual(rc, EXIT_REFUSED)
        lines = text.splitlines()
        self.assertEqual(lines[0], self.expected(other, other, "no", "none"))
        self.assertTrue(lines[1].startswith(ANNOTATION_PREFIX + "TMPDIR is outside the allowed roots"), lines)
        self.assertTrue(lines[2].startswith("prune_runner_tmp: refused: TMPDIR is outside the allowed roots"), lines)

    def test_facts_line_reports_a_symlinked_component(self):
        link = self.base / "link"
        link.symlink_to(self.runner)
        rc, text = self.run_merged(link)
        self.assertEqual(rc, EXIT_REFUSED)
        self.assertIn(f"tmpdir={link} resolved={self.runner} symlink=yes ", self.facts_line(text))

    def test_facts_line_precedes_the_refusal_when_tmpdir_is_unset(self):
        rc, text = self.run_merged(None)
        self.assertEqual(rc, EXIT_REFUSED)
        lines = text.splitlines()
        self.assertEqual(lines[0], self.expected(None, "unknown", "unknown", "unknown"))
        self.assertEqual(lines[1], ANNOTATION_PREFIX + "TMPDIR is unset")
        self.assertEqual(lines[2], "prune_runner_tmp: refused: TMPDIR is unset")

    def test_facts_line_precedes_the_refusal_when_tmpdir_is_empty(self):
        rc, text = self.run_merged("")
        self.assertEqual(rc, EXIT_REFUSED)
        lines = text.splitlines()
        self.assertEqual(lines[0], self.expected("", "unknown", "unknown", "unknown"))
        self.assertEqual(lines[1], ANNOTATION_PREFIX + "TMPDIR is empty")
        self.assertEqual(lines[2], "prune_runner_tmp: refused: TMPDIR is empty")

    def test_an_exception_in_the_facts_function_is_named_and_changes_no_exit_code(self):
        self.make_file("old.db", OLD_AGE_SECS)
        with mock.patch.object(PRUNE.os.path, "realpath", side_effect=OSError("boom")):
            out = io.StringIO()
            PRUNE.print_runner_facts(str(self.runner), (str(self.root),), out)
        self.assertEqual(out.getvalue(), "prune-facts: error=OSError\n")
        rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, err), (EXIT_OK, ""))

    def test_cli_exit_codes_and_summary_line(self):
        self.make_file("old.db", OLD_AGE_SECS)
        rc, out, err = self.run_cli(None)
        self.assertEqual((rc, err.strip()), (EXIT_OK, "prune_runner_tmp: refused: TMPDIR is unset"))
        self.assertIn(ANNOTATION_PREFIX + "TMPDIR is unset\n", out)
        rc, out, err = self.run_cli(self.runner)
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertRegex(out.strip().splitlines()[-1], r"^pruned=1 kept=0 failed=0 freed_bytes=\d+ skipped=0$")
        self.assertEqual(self.names(), [])


class ExitCodes(Base):
    """One cell per outcome: the exit code, the annotation and the summary the step shows (ruling f23a9ae4)."""

    def test_pruned_exits_zero_with_the_summary_and_no_annotation(self):
        self.make_file("old.db", OLD_AGE_SECS)
        rc, out, err = self.run_cli(self.runner)
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertNotIn("::", out)
        self.assertRegex(out.strip().splitlines()[-1], r"^pruned=1 kept=0 failed=0 freed_bytes=\d+ skipped=0$")

    def test_refusal_exits_zero_with_a_warning_annotation_and_deletes_nothing(self):
        victim = self.make_file("old.db", OLD_AGE_SECS, self.base)
        for raw, reason in ((None, "TMPDIR is unset"), (self.base, "TMPDIR is not named runner-<digits>: " + self.base.name)):
            with self.subTest(reason=reason):
                rc, out, err = self.run_cli(raw)
                self.assertEqual(rc, EXIT_OK)
                self.assertEqual(err.rstrip("\n"), f"prune_runner_tmp: refused: {reason}")
                self.assertEqual([ln for ln in out.splitlines() if ln.startswith("::")], [ANNOTATION_PREFIX + reason])
                self.assertNotIn("pruned=", out)
                self.assertTrue(victim.exists())

    def test_counted_failures_exit_zero_with_one_warning_annotation(self):
        self.make_file("old.db", OLD_AGE_SECS)
        with self.deny_unlink():
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(self.annotations, [failed_line(1, ["old.db"])])
        self.assertIn("pruned=0 kept=0 failed=1", out)
        self.assertIn("failed to remove old.db: [Errno 13] denied", err)

    def test_unexpected_error_exits_red_with_a_named_line_and_the_summary(self):
        self.make_file("old.db", OLD_AGE_SECS)
        with mock.patch.object(PRUNE, "remove_entry", side_effect=ValueError("boom")):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_ERROR)
        self.assertEqual(self.annotations, [])
        self.assertEqual(err.strip(), "prune_runner_tmp: internal error, pruning stopped: ValueError: boom")
        self.assertIn("internal_error=1", out)

    def test_python_floor_refusal_is_a_warning_and_exit_zero_in_the_process_guard(self):
        guard = (
            "import sys, runpy\n"
            "sys.version_info = (3, 11, 9, 'final', 0)\n"
            "try:\n"
            "    runpy.run_path(sys.argv[1], run_name='__main__')\n"
            "except SystemExit as exc:\n"
            "    print('exit', exc.code)\n"
        )
        done = subprocess.run([sys.executable, "-I", "-c", guard, str(SCRIPT)], capture_output=True, text=True, check=False)
        self.assertIn(ANNOTATION_PREFIX + "python 3.11.9 is older than 3.12\n", done.stdout)
        self.assertIn("exit 0", done.stdout)


class FailureAnnotation(Base):
    """Counted failures: one ``::warning`` line, the count and the first names, escaped and bounded (ruling 7af294fb)."""

    def run_failing(self, names):
        for name in names:
            self.make_file(name, OLD_AGE_SECS)
        with self.deny_unlink():
            return self.run_prune(self.runner)

    def only_annotation(self, out, err):
        self.assertEqual(len(self.annotations), 1, self.annotations)
        for line in (out + err).splitlines():
            if line.startswith("::"):
                self.assertEqual(line, self.annotations[0])
        return self.annotations[0]

    def test_constants_are_the_named_bounds(self):
        self.assertEqual(PRUNE.MAX_ANNOTATION_NAMES, ANNOTATION_NAMES_SHOWN)
        self.assertEqual(PRUNE.MAX_ANNOTATION_CHARS, ANNOTATION_MAX_CHARS)
        self.assertEqual(PRUNE.MAX_ANNOTATION_NAME_CHARS, ANNOTATION_NAME_MAX_CHARS)

    def test_one_and_five_failures_list_every_name_in_sorted_order(self):
        for count in (1, ANNOTATION_NAMES_SHOWN):
            with self.subTest(count=count):
                names = [f"f{index}.db" for index in reversed(range(count))]
                rc, out, err = self.run_failing(names)
                self.assertEqual(rc, EXIT_OK)
                self.assertEqual(self.only_annotation(out, err), failed_line(count, sorted(names)))
                for name in names:
                    (self.runner / name).unlink()

    def test_six_and_many_failures_state_the_count_and_that_the_list_is_cut(self):
        for count in (ANNOTATION_NAMES_SHOWN + 1, 40):
            with self.subTest(count=count):
                names = [f"f{index:03d}.db" for index in reversed(range(count))]
                rc, out, err = self.run_failing(names)
                self.assertEqual(rc, EXIT_OK)
                shown = sorted(names)[:ANNOTATION_NAMES_SHOWN]
                self.assertEqual(self.only_annotation(out, err), failed_line(count, shown, cut=True))
                self.assertIn(f"failed={count} ", out)
                for name in names:
                    (self.runner / name).unlink()

    def test_failure_flood_still_prints_one_bounded_annotation(self):
        names = [f"f{index:05d}" for index in range(FAILURE_FLOOD)]
        rc, out, err = self.run_failing(names)
        self.assertEqual(rc, EXIT_OK)
        line = self.only_annotation(out, err)
        self.assertEqual(line, failed_line(FAILURE_FLOOD, sorted(names)[:ANNOTATION_NAMES_SHOWN], cut=True))

    def test_hostile_names_reach_the_runner_as_exact_escaped_text(self):
        for raw, escaped in ANNOTATION_ESCAPES.items():
            with self.subTest(raw=raw):
                path = os.path.join(os.fsencode(self.runner), os.fsencode(raw))
                Path(os.fsdecode(path)).write_bytes(b"x")
                os.utime(path, (time.time() - OLD_AGE_SECS,) * 2)
                with self.deny_unlink():
                    rc, out, err = self.run_prune(self.runner)
                self.assertEqual(rc, EXIT_OK)
                self.assertEqual(self.only_annotation(out, err), failed_line(1, [escaped]))
                for line in (out + err).splitlines():
                    self.assertEqual(line.startswith("::"), line == self.annotations[0], repr(line))
                os.unlink(path)

    def test_builder_bounds_a_4096_byte_name_and_the_whole_line(self):
        long_name = "a" * 4096
        line = PRUNE.failed_annotation(1, [long_name])
        want = failed_line(1, ["a" * ANNOTATION_NAME_MAX_CHARS + ANNOTATION_CUT_MARK])
        self.assertEqual(line, want)
        control_heavy = ["\n" * 4096] * ANNOTATION_NAMES_SHOWN
        line = PRUNE.failed_annotation(9, control_heavy)
        self.assertEqual(len(line), ANNOTATION_MAX_CHARS)
        self.assertTrue(line.endswith(ANNOTATION_CUT_MARK))
        self.assertNotIn("\n", line)
        self.assertEqual([ln for ln in line.splitlines() if ln.startswith("::")], [line])

    def test_builder_escapes_every_hostile_name_and_non_utf8_bytes(self):
        names = list(ANNOTATION_ESCAPES) + [os.fsdecode(b"raw\xffbyte")]
        line = PRUNE.failed_annotation(len(names), names[:ANNOTATION_NAMES_SHOWN])
        self.assertEqual(len(line.splitlines()), 1)
        body = line[len(FAILED_TITLE):]
        self.assertNotIn("::", body)
        self.assertNotIn("%0", body.replace("\\x250", ""))
        self.assertTrue(line.isascii() or "\udcff" not in line)

    def test_no_failures_means_no_annotation(self):
        self.assertIsNone(PRUNE.failed_annotation(0, []))


class RootsAndFloor(unittest.TestCase):
    """The roots are named constants with evidence, the floor check runs before newer code, docs match the code."""

    def setUp(self):
        if PRUNE is None:
            self.fail(f"script under test not found: {SCRIPT}")
        self.source = SCRIPT.read_text()
        self.doc_section = DOCS.read_text().split("### 3.3", 1)[1].split("\n### ", 1)[0].split("\n## ", 1)[0]

    def test_allowed_roots_are_exactly_the_confirmed_constants(self):
        self.assertEqual(PRUNE.ALLOWED_ROOTS, tuple(getattr(PRUNE, name) for name in CONFIRMED_ROOT_CONSTANTS))
        self.assertNotIn(DROPPED_ROOT, PRUNE.ALLOWED_ROOTS)
        self.assertNotIn(DROPPED_ROOT, self.source.replace(f"not {DROPPED_ROOT}", ""))
        for name in CONFIRMED_ROOT_CONSTANTS:
            line = next(ln for ln in self.source.splitlines() if ln.startswith(f"{name} = "))
            self.assertIn("#", line, f"{name} carries its evidence comment")

    def test_no_root_override_flag_exists(self):
        self.assertNotIn('"--root"', self.source)

    def test_python_floor_corpus(self):
        corpus = {
            (3, 8, 0): "python 3.8.0 is older than 3.12",
            (3, 11, 9): "python 3.11.9 is older than 3.12",
            (3, 12, 0): None,
            (3, 12, 3): None,
            (3, 14, 1): None,
            (4, 0, 0): None,
        }
        for version, want in corpus.items():
            with self.subTest(version=version):
                self.assertEqual(PRUNE.python_refusal(version), want)

    def test_floor_check_precedes_every_non_sys_import_and_the_file_parses_on_old_python(self):
        tree = ast.parse(self.source, feature_version=(3, 8))
        body = [node for node in tree.body if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))]
        guard = next(i for i, node in enumerate(body) if isinstance(node, ast.If) and "python_refusal" in ast.unparse(node))
        for node in body[:guard]:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.assertEqual([alias.name for alias in node.names], ["sys"])
        later = [node for node in body[guard + 1:] if isinstance(node, ast.Import)]
        self.assertTrue(later, "the other imports come after the floor check")
        self.assertNotIn("shutil.rmtree", self.source.replace("no ``shutil.rmtree``", ""))

    def test_docs_list_every_refusal_reason_of_the_code(self):
        listed = set(re.findall(r"^- refusal: `([^`]+)`$", self.doc_section, flags=re.M))
        expected = {re.sub(r"\{(\w+)\}", r"<\1>", template) for template in PRUNE.REFUSAL_REASONS.values()}
        self.assertEqual(listed, expected)

    def test_every_reason_key_is_raised_somewhere_and_no_unlisted_reason_exists(self):
        used = set(re.findall(r'refuse\("(\w+)"', self.source))
        indirect = {"python"}
        self.assertEqual(used | indirect, set(PRUNE.REFUSAL_REASONS))
        self.assertNotIn("Refusal(f", self.source)
        self.assertNotIn("supports_dir_fd", self.source, "D-H1: the platform check is functional, never a table")

    def test_bounds_text_says_counted_before_anything_is_removed_everywhere(self):
        """D-L3: the docstring, the exception, the docs and the action all state the count-first bound."""
        action = (ROOT / ACTION_PATH).read_text()
        for where, text in (
            ("module docstring", PRUNE.__doc__),
            ("TreeTooLarge", PRUNE.TreeTooLarge.__doc__),
            ("docs 3.3", self.doc_section),
            ("action.yml", action),
        ):
            with self.subTest(where=where):
                flat = " ".join(text.split())
                self.assertIn("counted before anything under it is removed", flat)
                self.assertNotIn("left in place", flat.replace("probe directory left in place", ""))

    def test_docs_name_the_roots_constant_not_the_dropped_root(self):
        self.assertIn("ALLOWED_ROOTS", self.doc_section)
        self.assertNotIn(DROPPED_ROOT, self.doc_section)
        self.assertNotIn("--root", self.doc_section)
        for token in ("runner-<digits>", "another device", "internal error"):
            self.assertIn(token, self.doc_section)


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
        self.assertRegex(text, r"(?is)refus\w+ .*::warning.*does not fail")
        self.assertRegex(text, r"(?is)per-entry .*does not fail")
        self.assertRegex(text, r"(?is)unexpected error .*fails? the job")
        self.assertIsNone(re.search(r"continue-on-error", text))


if __name__ == "__main__":
    unittest.main()
