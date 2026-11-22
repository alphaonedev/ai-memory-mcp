# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin scripts/ci/prune_runner_tmp.py and its workflow wiring (#8634).

Invariant, for every input: the prune deletes only stale top-level entries of a
directory PROVEN, by file identity, to be this runner's own
``<confirmed runner root>/runner-<digits>``; any input it cannot prove ends in a
named refusal (exact reason, nothing deleted); in mode job-start a per-entry
failure or a refusal never fails or skips the rest of the job (a ``::warning``
annotation, exit 0), in mode job-end (#9820) a TMPDIR that is not cleared says
why with one ``::error`` annotation and exit 3; an unexpected internal error
stays red (exit 1); a per-entry failure is counted; no output
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
import functools
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
YOUNG_AGE_SECS = 5  # inside JOB_START_GRACE_SECS (30), so a job-start run keeps it as a live writer's entry
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
SOCKET_PATH_LIMIT = 104  # sun_path is 108 bytes on Linux and 104 on macOS (unix(7), sys/un.h); the smaller bounds both
LONG_TMPDIR_SEGMENT = "t" * 40
LONG_TMPDIR_SEGMENTS = 5  # 5 * 41 bytes below the scratch directory: a TMPDIR of at least 200 bytes (#9460)
LONG_TMPDIR_BYTES = 200
LONG_CHECKOUT_SEGMENT = "d" * 60
LONG_CHECKOUT_SEGMENTS = 3  # 3 * 61 bytes of path, past SOCKET_PATH_LIMIT before the file name
SOCKET_CELL_TIMEOUT_SECS = 300
SOCKET_CELL_CLASS = "EntryKinds"
SOCKET_CELL_MODULE = "test_prune_runner_tmp_8634"
SOCKET_CELL_SIBLINGS = ("scripts/ci/prune_runner_tmp.py", "scripts/ci/workflow_annotation.py",
                        "scripts/ci/check_pg_preflight_workflows.py")
LEFTOVER_LINE_RE = r"^prune_runner_tmp: probe directory left in place: " + PROBE_NAME_RE + "$"
# D-M1: skip reasons and the counted failure text of a directory the walk does not enter.
SKIP_MOUNT_POINT = "a mount point, not entered"
SKIP_MOUNT_UNREADABLE = "mount id unreadable, not entered"
SUMMARY_ENV = "GITHUB_STEP_SUMMARY"
# Round 1 of PR 9383 (b29 8734d28b): every place the walk declines to go is a counted failure with one annotation.
SKIP_OTHER_DEVICE = "on another device, not entered"
MOUNT_DIFFERS_REASON = "TMPDIR is not on its runner root's mount: {path}"
PLATFORM_UNVERIFIABLE_REASON = "this platform cannot verify mount identity: {platform}"
COUNTED_REFUSAL_SUMMARY = "pruned=0 kept=0 failed=1 freed_bytes=0 skipped=0"
VERIFIABLE_PLATFORMS = ("linux", "darwin")
UNVERIFIABLE_PLATFORMS = ("freebsd14", "sunos5", "cygwin", "aix7", "win32", "linux-gnu", "darwin2")
# errno -> strerror of a probe that cannot write (decision 3): the prune goes on after a read-only probe.
# The strerror text is libc's (glibc "Disk quota exceeded", macOS "Disc quota exceeded"): read from the host, never a literal.
CANNOT_WRITE_ERRNOS = {code: os.strerror(code) for code in (errno.ENOSPC, errno.EDQUOT, errno.EROFS)}
CREATING_CALLS = ("mkdir", "file-create")
NON_CREATING_PROBE_CALLS = ("open", "lstat")  # probe calls that make nothing: a full-disk errno there is a broken call
READ_ONLY_PROBE_LINE = "prune_runner_tmp: probe cannot write ({why}); the read-only probe passed, pruning goes on"
READ_ONLY_MISSING_WHY = "not in os.supports_dir_fd"
DIR_MOVED_DURING_COUNT = "directory moved during count"
DIR_MOVED_DURING_REMOVAL = "directory moved during removal"
ENTRY_CHANGED = "entry changed since scan"
SUMMARY_SYMLINK_WHY = "Too many levels of symbolic links"
CUTOFF_NOW = 2_000_000_000  # an integer clock, so an mtime exactly at the cutoff is exact

PRUNE = None
CHK = None


def failed_line(count, shown, cut=False):
    """The one annotation line the counted-failure outcome prints, spelled out independently of the script."""
    text = f"{FAILED_TITLE}failed={count} not removed: " + ", ".join(shown)
    if cut:
        text += f" (list cut at {ANNOTATION_NAMES_SHOWN} of {count})"
    return text


# #9876 N1: every refusal and failed annotation names the layout row, the owner and the entry. The older exact rows
# compare the reason alone, so these patterns take the context off; the N1 table compares the whole line.
REFUSAL_CONTEXT_RE = re.compile(
    r"^(.*) \(layout=(?:none|linux:\S*|macos:\S* runner=\S+) "
    r"owner=(?:[0-9]+|E[A-Z0-9]+|unset|invalid|relative) entry=.*\)$")
FAILED_LAYOUT_RE = re.compile(r" layout=(?:none|linux:\S*|macos:\S* runner=\S+) not removed: ")
FAILED_ENTRY_FIELDS_RE = re.compile(r" \(owner=(?:[0-9]+|E[A-Z0-9]+) errno=(?:E[A-Z0-9]+|none)\)")


def plain(line):
    """``line`` without the #9876 context fields; a line without them is returned unchanged."""
    match = REFUSAL_CONTEXT_RE.match(line)
    if match:
        return match.group(1)
    if FAILED_LAYOUT_RE.search(line):
        return FAILED_ENTRY_FIELDS_RE.sub("", FAILED_LAYOUT_RE.sub(" not removed: ", line, count=1))
    return line


def plain_lines(text):
    return [plain(line) for line in text.splitlines()]


def failed_entries(names, owner="501", errno_name="EACCES"):
    """Failed entries for the annotation builder: the name and the two context fields (#9876 N1)."""
    return [PRUNE.FailedEntry(name, owner, errno_name) for name in names]


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


def _fresh_probe_dir():
    SCRATCH_BASE.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(dir=SCRATCH_BASE, prefix="prune8634-probe-")).resolve()


def probe_byte_ff_refusal(create):
    """None when ``create`` makes a file named with byte 0xff, "EILSEQ" when the file system refuses that name.

    The one errno that names the missing facility is EILSEQ (APFS). Every other error (ENOSPC, EIO, EACCES, ...)
    says nothing about the name, so it propagates and the cell fails instead of silently dropping a security cell.
    """
    top = _fresh_probe_dir()
    try:
        fd = create(os.path.join(os.fsencode(top), b"probe\xff"), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError as exc:
        if exc.errno != errno.EILSEQ:
            raise
        return errno.errorcode[errno.EILSEQ]
    else:
        os.close(fd)
        return None
    finally:
        remove_scratch(top, SCRATCH_BASE)


@functools.cache
def host_refuses_byte_ff_names():
    """None when the scratch file system accepts a file name holding byte 0xff (Linux), else "EILSEQ" (APFS)."""
    return probe_byte_ff_refusal(os.open)


@functools.cache
def host_folds_case():
    """True when the scratch file system treats ``Probe-case`` and ``probe-case`` as one name (APFS default)."""
    top = _fresh_probe_dir()
    try:
        (top / "Probe-case").write_bytes(b"x")
        return (top / "probe-case").exists()
    finally:
        remove_scratch(top, SCRATCH_BASE)


def byte_ff_reason(errno_name):
    """The exact skip reason for a row that needs a 0xff file name, or None when the host runs it."""
    if errno_name is None:
        return None
    return f"this file system refuses a file name holding byte 0xff ({errno_name}, platform {sys.platform})"


def byte_ff_skip_reason():
    """The skip reason of this host for a 0xff-name row, or None when the host runs it."""
    return byte_ff_reason(host_refuses_byte_ff_names())


def split_hostile_names(names, refusal):
    """(kept, dropped): drop only the names holding a lone surrogate (byte 0xff) on a host that refuses them."""
    if refusal is None:
        return list(names), []
    kept = [name for name in names if "\udcff" not in name]
    return kept, [name for name in names if "\udcff" in name]


def remove_scratch(top, base):
    """Remove a fixture tree below ``base`` without recursion (os.walk is iterative on 3.12) and without PATH."""
    top = Path(top)
    if not top.resolve().is_relative_to(Path(base).resolve()) or not top.exists():
        return
    for dirpath, dirnames, filenames in os.walk(top, topdown=False, followlinks=False):
        for name in filenames:
            os.unlink(os.path.join(dirpath, name))
        for name in dirnames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                os.unlink(full)
            else:
                os.rmdir(full)
    os.rmdir(top)


def age(path, secs):
    stamp = time.time() - secs
    os.utime(path, (stamp, stamp), follow_symlinks=False)


def bind_unix_socket(parent, name):
    """Bind an AF_UNIX socket called ``name`` inside ``parent`` whatever the length of ``parent`` (#9460).

    The kernel limits the bound path to SOCKET_PATH_LIMIT bytes, so the bind uses the bare name from a working
    directory of ``parent``; the previous directory is restored also when the bind fails. decision: relative name
    over a short directory plus rename because the socket must be a child of ``parent`` (the prune cell scans it)
    and a rename cannot cross filesystems, so a short directory elsewhere could not hold it.
    """
    if len(name.encode()) >= SOCKET_PATH_LIMIT:
        raise ValueError(f"socket name is {len(name.encode())} bytes, limit {SOCKET_PATH_LIMIT}: {name}")
    previous = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.chdir(parent)
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(name)
    finally:
        os.fchdir(previous)
        os.close(previous)


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

    def as_other_user(self):
        """Make the MEDIUM-5 owner rwx retry fail as it does on a directory of another user (EPERM).

        A 0500 directory the job owns is now opened up and cleared (MEDIUM-5); a read-only directory the
        job cannot chmod is the case that stays unremovable and counted, which these tests are about. The
        TMPDIR owner proof still sees the real uid.
        """
        def refuse_fchmod(_fd, _mode):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))

        patch = mock.patch.object(PRUNE.os, "fchmod", refuse_fchmod)
        patch.start()
        self.addCleanup(patch.stop)

    def run_prune(self, tmpdir, *extra, env_extra=None):
        environ = {} if tmpdir is None else {"TMPDIR": str(tmpdir)}
        environ.update(env_extra or {})
        out, err = io.StringIO(), io.StringIO()
        rc = PRUNE.main(list(extra), environ=environ, out=out, err=err)
        lines = out.getvalue().splitlines(keepends=True)
        self.raw_annotations = [ln.rstrip("\n") for ln in lines if ln.startswith("::")]
        self.annotations = [plain(ln) for ln in self.raw_annotations]
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
        self.as_other_user()
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
        bind_unix_socket(parent, "k-sock")
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
        self.assertEqual((tally.pruned, tally.failed, tally.skipped), (0, len(made), len(made)))
        self.assertEqual(snapshot(self.runner), before)
        lines = err.getvalue().splitlines()
        self.assertEqual(len(lines), 2 * len(made))
        names = sorted(path.name for path in made.values())
        self.assertEqual(sorted(lines), sorted(
            [f"prune_runner_tmp: skipped {name}: {SKIP_OTHER_DEVICE}" for name in names]
            + [f"prune_runner_tmp: failed to remove {name}: {SKIP_OTHER_DEVICE}" for name in names]))
        self.assertEqual([entry.name for entry in tally.first_failed], names[:ANNOTATION_NAMES_SHOWN])

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
            with self.assertRaises(PRUNE.NotEntered) as caught:
                PRUNE.remove_tree(fd, "holder", scanned, info.st_dev + 1, tally)
        self.assertEqual((caught.exception.reason, caught.exception.nested), (SKIP_OTHER_DEVICE, True))
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
                root = self.root
                if host_folds_case() and name.casefold() == self.runner.name:
                    # `Runner-1` is `runner-1` here: put the row in a sibling allowed root that holds no `runner-1`.
                    root = self.base / "root-case-fold"
                    root.mkdir(exist_ok=True)
                lane = root / name
                lane.mkdir()
                with mock.patch.object(PRUNE, "ALLOWED_ROOTS", (str(self.root), str(root))):
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
        # macOS: /tmp is a symlink to private/tmp, and the tool names a symlink before it tests the forbidden list.
        tmp_reason = "TMPDIR is a symlink: /tmp" if os.path.islink("/tmp") else "TMPDIR is a forbidden path: /tmp"
        self.refused("/tmp", tmp_reason)
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
                version = subprocess.run(
                    [interpreter, "-I", "-c", "import sys; print(*sys.version_info[:3])"],
                    capture_output=True, text=True, check=True,
                ).stdout.split()
                refusal = PRUNE.python_refusal(tuple(int(part) for part in version))
                if refusal is not None:
                    # An interpreter below the floor (macOS /usr/bin/python3 is 3.9.6) refuses by design, deleting nothing.
                    victim = self.make_file("old.db", OLD_AGE_SECS)
                    rc, out, err = self.run_cli(self.runner, interpreter=interpreter)
                    self.assertEqual((rc, err), (EXIT_OK, f"prune_runner_tmp: refused: {refusal}\n"))
                    self.assertIn(ANNOTATION_PREFIX + refusal, plain_lines(out))
                    self.assertTrue(victim.exists())
                    self.assertEqual(self.probe_dirs(), [])
                    victim.unlink()
                    continue
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
                self.assertIn(ANNOTATION_PREFIX + reason, plain_lines(done.stdout))
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
        if holder.exists():
            remove_scratch(holder, self.base)
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
        self.assertEqual(err.splitlines(), [f"prune_runner_tmp: skipped holder: {SKIP_MOUNT_POINT}",
                                            f"prune_runner_tmp: failed to remove holder: {SKIP_MOUNT_POINT}"])
        self.assertIn("pruned=0 kept=0 failed=1 freed_bytes=0 skipped=1", out)
        self.assertEqual(self.annotations, [failed_line(1, ["holder"])])
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
                # F6: a top-level entry's failure line never repeats its own name
                failed_text = SKIP_MOUNT_UNREADABLE if where == "top" else f"{name}: {SKIP_MOUNT_UNREADABLE}"
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
                self.assertEqual(self.annotations, [failed_line(1, ["holder"])])
                remove_scratch(holder, self.base)

    def test_unreadable_root_mount_id_is_a_refusal(self):
        victim = self.make_file("old.db", OLD_AGE_SECS)

        def unreadable(fd):
            raise PRUNE.MountIdUnreadable("fdinfo has no mnt_id line")

        with mock.patch.object(PRUNE, "mount_id", unreadable):
            rc, out, err = self.run_prune(self.runner)
        reason = MOUNT_UNREADABLE_REASON.format(why="fdinfo has no mnt_id line")
        self.assertEqual((rc, out), (EXIT_REFUSED, COUNTED_REFUSAL_SUMMARY + "\n"))
        self.assertEqual(self.annotations, [ANNOTATION_PREFIX + reason])
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

    def host_names(self):
        """The hostile names this host can create; each dropped 0xff name is a skipped subTest with the exact reason."""
        kept, dropped = split_hostile_names(HOSTILE_NAMES, host_refuses_byte_ff_names())
        for name in dropped:
            with self.subTest(name=name):
                self.skipTest(byte_ff_skip_reason())
        return kept

    def test_dry_run_lines_carry_no_injection(self):
        names = self.host_names()
        for index, name in enumerate(names):
            self.make_named(f"{index}-{name}", as_dir=False)
        rc, out, err = self.run_prune(self.runner, "--dry-run")
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.lines_ok(out)
        self.assertEqual(len(out.splitlines()), len(names) + 1)
        self.assertIn(f"pruned={len(names)} ", out)

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_failure_lines_carry_no_injection(self):
        names = self.host_names()
        locked = []
        for index, name in enumerate(names):
            raw = self.make_named(f"{index}-{name}", as_dir=True)
            os.chmod(os.path.join(raw, b"sub"), 0o500)
            locked.append(raw)
        self.addCleanup(lambda: [os.chmod(os.path.join(raw, b"sub"), 0o700) for raw in locked])
        self.as_other_user()
        rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertIn(f"failed={len(names)} ", out)
        self.lines_ok(err)
        self.assertEqual(len(err.splitlines()), len(names))

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
        self.addCleanup(remove_scratch, top, self.base)
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
        self.addCleanup(remove_scratch, top, self.base)
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
        lines = plain_lines(text)
        self.assertEqual(lines[0], self.expected(None, "unknown", "unknown", "unknown"))
        self.assertEqual(lines[1], ANNOTATION_PREFIX + "TMPDIR is unset")
        self.assertEqual(lines[2], "prune_runner_tmp: refused: TMPDIR is unset")

    def test_facts_line_precedes_the_refusal_when_tmpdir_is_empty(self):
        rc, text = self.run_merged("")
        self.assertEqual(rc, EXIT_REFUSED)
        lines = plain_lines(text)
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
        self.assertIn(ANNOTATION_PREFIX + "TMPDIR is unset", plain_lines(out))
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
                self.assertEqual([ln for ln in plain_lines(out) if ln.startswith("::")], [ANNOTATION_PREFIX + reason])
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
                self.assertEqual(line, self.raw_annotations[0])
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
                if "\udcff" in raw and (reason := byte_ff_skip_reason()) is not None:
                    self.skipTest(reason)
                path = os.path.join(os.fsencode(self.runner), os.fsencode(raw))
                Path(os.fsdecode(path)).write_bytes(b"x")
                os.utime(path, (time.time() - OLD_AGE_SECS,) * 2)
                with self.deny_unlink():
                    rc, out, err = self.run_prune(self.runner)
                self.assertEqual(rc, EXIT_OK)
                self.assertEqual(self.only_annotation(out, err), failed_line(1, [escaped]))
                for line in (out + err).splitlines():
                    self.assertEqual(line.startswith("::"), line == self.raw_annotations[0], repr(line))
                os.unlink(path)

    def test_builder_bounds_a_4096_byte_name_and_the_whole_line(self):
        long_name = "a" * 4096
        line = PRUNE.failed_annotation(1, failed_entries([long_name]))
        want = failed_line(1, ["a" * ANNOTATION_NAME_MAX_CHARS + ANNOTATION_CUT_MARK])
        self.assertEqual(plain(line), want)
        control_heavy = ["\n" * 4096] * ANNOTATION_NAMES_SHOWN
        line = PRUNE.failed_annotation(9, failed_entries(control_heavy))
        self.assertEqual(len(line), ANNOTATION_MAX_CHARS)
        self.assertTrue(line.endswith(ANNOTATION_CUT_MARK))
        self.assertNotIn("\n", line)
        self.assertEqual([ln for ln in line.splitlines() if ln.startswith("::")], [line])

    def test_builder_escapes_every_hostile_name_and_non_utf8_bytes(self):
        names = list(ANNOTATION_ESCAPES) + [os.fsdecode(b"raw\xffbyte")]
        line = PRUNE.failed_annotation(len(names), failed_entries(names[:ANNOTATION_NAMES_SHOWN]))
        self.assertEqual(len(line.splitlines()), 1)
        body = line[len(FAILED_TITLE):]
        self.assertNotIn("::", body)
        self.assertNotIn("%0", body.replace("\\x250", ""))
        self.assertTrue(line.isascii() or "\udcff" not in line)

    def test_no_failures_means_no_annotation(self):
        self.assertIsNone(PRUNE.failed_annotation(0, []))


class RoundOneFixes(Base):
    """PR 9383 round 1 (b29 8734d28b): every decision is taken on the validated object; one cell per finding."""

    def mount_override(self, target, value=None, unreadable=False):
        return MountCrossing.mount_id_override(self, target, value=value, unreadable=unreadable)

    def ident(self, path):
        info = os.lstat(path)
        return (info.st_dev, info.st_ino)

    def clear_runner(self):
        """Each table row starts from an empty runner dir, whatever the row before it left."""
        for child in self.runner.iterdir():
            if child.is_dir() and not child.is_symlink():
                remove_scratch(child, self.base)
            else:
                child.unlink()

    # decision 1 (SEC M1): the TMPDIR fd and its runner root fd are on one mount, checked before anything is opened
    def test_tmpdir_on_another_mount_than_its_root_is_a_counted_refusal(self):
        if not sys.platform.startswith("linux"):
            self.skipTest(f"mount ids come from /proc/self/fdinfo on Linux only (platform {sys.platform})")
        cases = (
            ("mnt_id differs", {"value": -7}, MOUNT_DIFFERS_REASON.format(path=self.runner)),
            ("root mnt_id unreadable", {"unreadable": True},
             MOUNT_UNREADABLE_REASON.format(why="fdinfo has no mnt_id line")),
        )
        for label, override, reason in cases:
            with self.subTest(case=label):
                self.clear_runner()
                victim = self.make_file("old.db", OLD_AGE_SECS)
                opened_under = []
                real_mkdir = os.mkdir

                def spy_mkdir(name, *args, **kwargs):
                    opened_under.append(name)
                    return real_mkdir(name, *args, **kwargs)

                with self.mount_override(self.ident(self.root), **override), \
                        mock.patch.object(PRUNE.os, "mkdir", spy_mkdir):
                    rc, out, err = self.run_prune(self.runner)
                self.assertEqual((rc, out), (EXIT_REFUSED, COUNTED_REFUSAL_SUMMARY + "\n"))
                self.assertEqual(err, f"prune_runner_tmp: refused: {reason}\n")
                self.assertEqual(self.annotations, [ANNOTATION_PREFIX + reason])
                self.assertEqual(opened_under, [], "nothing is made or opened under TMPDIR before the mount check")
                self.assertTrue(victim.exists())
                victim.unlink()

    def test_tmpdir_on_another_device_than_its_root_is_a_counted_refusal(self):
        """decision 1, Darwin form: the TMPDIR fd's st_dev against the root fd's (fstat of '..').

        A volume mounted over runner-<n> has its own st_dev while '..' still is the root, so the TMPDIR
        identity is shifted to another device (fstat and lstat agree, as they do on a real mount).
        """
        victim = self.make_file("old.db", OLD_AGE_SECS)
        runner_ident = self.ident(self.runner)
        real_fstat, real_lstat = os.fstat, os.lstat

        def shifted(info):
            if (info.st_dev, info.st_ino) != runner_ident:
                return info
            values = list(info)
            values[stat.ST_DEV] = info.st_dev + 1
            return os.stat_result(values)

        with mock.patch.object(PRUNE.os, "fstat", lambda fd: shifted(real_fstat(fd))), \
                mock.patch.object(PRUNE.os, "lstat", lambda path, **kw: shifted(real_lstat(path, **kw))):
            rc, out, err = self.run_prune(self.runner)
        reason = MOUNT_DIFFERS_REASON.format(path=self.runner)
        self.assertEqual((rc, out), (EXIT_REFUSED, COUNTED_REFUSAL_SUMMARY + "\n"))
        self.assertEqual(err, f"prune_runner_tmp: refused: {reason}\n")
        self.assertEqual(self.annotations, [ANNOTATION_PREFIX + reason])
        self.assertTrue(victim.exists())

    def test_bind_mount_over_the_runner_dir_is_refused_and_its_source_survives(self):
        """unshare-gated (real mount, no root): a directory outside the root bind-mounted over runner-1."""
        unshare, mount = shutil.which("unshare"), shutil.which("mount")
        if not sys.platform.startswith("linux") or unshare is None or mount is None:
            self.skipTest(f"bind-mount cell needs Linux unshare and mount (platform {sys.platform}, "
                          f"unshare {unshare}, mount {mount})")
        probe = subprocess.run([unshare, "-r", "-m", mount, "--bind", str(self.base), str(self.home)],
                               capture_output=True, text=True, check=False, timeout=BIND_HELPER_TIMEOUT_SECS)
        if probe.returncode != 0:
            self.skipTest(f"unshare -r -m bind mount unavailable here: rc={probe.returncode} {probe.stderr.strip()}")
        source = self.base / "bindsrc"
        source.mkdir()
        canary = self.make_file("canary", OLD_AGE_SECS, source, data=b"canary")
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
            [unshare, "-r", "-m", sys.executable, "-I", str(helper), mount, str(source), str(self.runner),
             str(SCRIPT), str(self.root)],
            env=env, capture_output=True, text=True, check=False, timeout=BIND_HELPER_TIMEOUT_SECS,
        )
        reason = MOUNT_DIFFERS_REASON.format(path=self.runner)
        self.assertEqual(done.returncode, EXIT_REFUSED, done.stderr)
        self.assertEqual(done.stderr, f"prune_runner_tmp: refused: {reason}\n")
        self.assertIn(COUNTED_REFUSAL_SUMMARY, done.stdout.splitlines())
        self.assertIn(ANNOTATION_PREFIX + reason, plain_lines(done.stdout))
        self.assertEqual(canary.read_bytes(), b"canary", "the bind source outside the root survives")

    # decision 2 (SEC L1, CODE F4): every not-entered place is a counted failure with one annotation
    def test_every_not_entered_reason_is_a_counted_failure_with_one_annotation(self):
        if not sys.platform.startswith("linux"):
            self.skipTest(f"mount ids come from /proc/self/fdinfo on Linux only (platform {sys.platform})")
        cases = (
            ("top mount point", "", {"value": -1}, SKIP_MOUNT_POINT, "holder", SKIP_MOUNT_POINT),
            ("top unreadable", "", {"unreadable": True}, SKIP_MOUNT_UNREADABLE, "holder", SKIP_MOUNT_UNREADABLE),
            ("nested mount point", "inner", {"value": -1}, SKIP_MOUNT_POINT, "inner", f"inner: {SKIP_MOUNT_POINT}"),
            ("nested unreadable", "inner", {"unreadable": True}, SKIP_MOUNT_UNREADABLE, "inner",
             f"inner: {SKIP_MOUNT_UNREADABLE}"),
        )
        for label, below, override, skip_reason, skipped_name, failed_text in cases:
            with self.subTest(case=label):
                self.clear_runner()
                holder = MountCrossing.stale_holder(self)
                target = holder / below if below else holder
                with self.mount_override(self.ident(target), **override):
                    rc, out, err = self.run_prune(self.runner)
                self.assertEqual(rc, EXIT_OK)
                self.assertEqual(err.splitlines(), [f"prune_runner_tmp: skipped {skipped_name}: {skip_reason}",
                                                    f"prune_runner_tmp: failed to remove holder: {failed_text}"])
                self.assertRegex(out, r"^pruned=0 kept=0 failed=1 freed_bytes=\d+ skipped=1\n$")
                self.assertEqual(self.annotations, [failed_line(1, ["holder"])])
                self.assertEqual((holder / "inner" / "precious" / "data").read_bytes(), b"precious")
                remove_scratch(holder, self.base)

    def test_nested_other_device_entry_fails_its_top_level_entry_with_the_exact_line(self):
        holder = self.runner / "holder"
        (holder / "dev").mkdir(parents=True)
        (holder / "dev" / "data").write_bytes(b"precious")
        age(holder, OLD_AGE_SECS)
        fd, info = self.open_runner()
        dev_ident = self.ident(holder / "dev")
        real_list = PRUNE.list_level

        def foreign_dev(dir_fd, root_dev, *rest, **kwargs):
            here = os.fstat(dir_fd)
            if (here.st_dev, here.st_ino) == self.ident(holder):
                with mock.patch.object(PRUNE.os, "scandir", foreign_scandir):
                    return real_list(dir_fd, root_dev, *rest, **kwargs)
            return real_list(dir_fd, root_dev, *rest, **kwargs)

        real_scandir = os.scandir

        class Entry:
            def __init__(self, entry):
                self.entry, self.name = entry, entry.name

            def stat(self, follow_symlinks=False):
                found = self.entry.stat(follow_symlinks=follow_symlinks)
                if (found.st_dev, found.st_ino) != dev_ident:
                    return found
                values = list(found)
                values[stat.ST_DEV] = found.st_dev + 1
                return os.stat_result(values)

        @contextlib.contextmanager
        def foreign_scandir(target):
            with real_scandir(target) as scan:
                yield [Entry(entry) for entry in scan]

        out, err = io.StringIO(), io.StringIO()
        tally = PRUNE.Tally(err)
        with mock.patch.object(PRUNE, "list_level", foreign_dev):
            PRUNE.prune(fd, info.st_dev, False, time.time(), out, tally)
        self.assertEqual(err.getvalue().splitlines(), [f"prune_runner_tmp: skipped dev: {SKIP_OTHER_DEVICE}",
                                                       f"prune_runner_tmp: failed to remove holder: dev: {SKIP_OTHER_DEVICE}"])
        self.assertEqual((tally.pruned, tally.failed, tally.skipped), (0, 1, 1))
        self.assertEqual((holder / "dev" / "data").read_bytes(), b"precious")

    # decision 3 (CODE F1): a probe that cannot write probes read-only and the prune goes on
    def cannot_write(self, which, code):
        """Make the probe's creating call ``which`` raise OSError(``code``); the replacement stays in supports_dir_fd."""
        attr = "mkdir" if which == "mkdir" else "open"
        real = getattr(os, attr)

        def failing(name, *args, **kwargs):
            creating = attr == "mkdir" or (len(args) > 0 and args[0] & os.O_CREAT)
            if kwargs.get("dir_fd") is not None and creating and str(name).startswith(PRUNE.PROBE_PREFIX[:6]):
                raise OSError(code, os.strerror(code))
            return real(name, *args, **kwargs)

        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(PRUNE.os, attr, failing))
        if real in os.supports_dir_fd:
            stack.enter_context(mock.patch.object(os, "supports_dir_fd", os.supports_dir_fd | {failing}))
        return stack

    def test_probe_that_cannot_write_runs_read_only_and_prunes(self):
        for which in CREATING_CALLS:
            for code, why in CANNOT_WRITE_ERRNOS.items():
                with self.subTest(call=which, errno=errno.errorcode[code]):
                    self.clear_runner()
                    victim = self.make_file("old.db", OLD_AGE_SECS)
                    young = self.make_file("young.db", YOUNG_AGE_SECS)
                    with self.cannot_write(which, code):
                        rc, out, err = self.run_prune(self.runner)
                    self.assertEqual(rc, EXIT_OK)
                    self.assertEqual(err, READ_ONLY_PROBE_LINE.format(why=why) + "\n")
                    self.assertRegex(out, r"^pruned=1 kept=1 failed=0 freed_bytes=\d+ skipped=0\n$")
                    self.assertEqual(self.annotations, [])
                    self.assertFalse(victim.exists(), "a full disk is the case the tool exists for")
                    self.assertEqual(self.names(), ["young.db"], "no probe directory is left")
                    young.unlink()

    def test_read_only_probe_accepts_erofs_from_an_absent_name_only_when_the_cause_was_erofs(self):
        real_unlink = os.unlink

        def erofs_unlink(name, *args, **kwargs):
            if str(name).endswith("-absent"):
                raise OSError(errno.EROFS, os.strerror(errno.EROFS))
            return real_unlink(name, *args, **kwargs)

        for code, outcome in ((errno.EROFS, "prunes"), (errno.ENOSPC, "refuses")):
            with self.subTest(cause=errno.errorcode[code]):
                self.clear_runner()
                victim = self.make_file("old.db", OLD_AGE_SECS)
                with self.cannot_write("mkdir", code), mock.patch.object(PRUNE.os, "unlink", erofs_unlink), \
                        mock.patch.object(os, "supports_dir_fd", os.supports_dir_fd | {erofs_unlink}):
                    rc, out, err = self.run_prune(self.runner)
                self.assertEqual(rc, EXIT_OK)
                if outcome == "prunes":
                    self.assertEqual(err, READ_ONLY_PROBE_LINE.format(why=CANNOT_WRITE_ERRNOS[code]) + "\n")
                    self.assertFalse(victim.exists())
                else:
                    reason = ("this platform lacks a working descriptor-relative call: os.unlink raised OSError "
                              f"({os.strerror(errno.EROFS)})")
                    self.assertEqual(err, f"prune_runner_tmp: refused: {reason}\n")
                    self.assertEqual(self.annotations, [ANNOTATION_PREFIX + reason])
                    self.assertTrue(victim.exists())
                    victim.unlink()

    def test_read_only_probe_refuses_when_a_needed_call_lacks_dir_fd(self):
        for missing in ("open", "stat", "unlink", "rmdir"):
            with self.subTest(missing=missing):
                self.clear_runner()
                victim = self.make_file("old.db", OLD_AGE_SECS)
                without = {fn for fn in os.supports_dir_fd if fn is not getattr(os, missing)}
                with self.cannot_write("mkdir", errno.ENOSPC), mock.patch.object(os, "supports_dir_fd", without):
                    rc, out, err = self.run_prune(self.runner)
                reason = (f"this platform lacks a working descriptor-relative call: os.{missing} raised ProbeMismatch "
                          f"(os.{missing} {READ_ONLY_MISSING_WHY})")
                self.assertEqual((rc, out), (EXIT_REFUSED, ""))
                self.assertEqual(err, f"prune_runner_tmp: refused: {reason}\n")
                self.assertEqual(self.annotations, [ANNOTATION_PREFIX + reason])
                self.assertTrue(victim.exists())
                victim.unlink()

    def test_read_only_probe_refuses_when_a_call_returns_for_an_absent_name(self):
        """Round 2 L1: lstat, unlink and rmdir of the absent name must FAIL with ENOENT; a call that returns
        has not done the call (a platform that ignores dir_fd), so the probe refuses with the exact reason."""
        absent = PRUNE.PROBE_ABSENT_SUFFIX
        for attr in ("lstat", "unlink", "rmdir"):
            with self.subTest(call=attr):
                self.clear_runner()
                victim = self.make_file("old.db", OLD_AGE_SECS)
                canary = self.make_file("young.db", YOUNG_AGE_SECS)
                real = getattr(os, attr)

                def returning(name, *args, _real=real, **kwargs):
                    if str(name).endswith(absent):
                        return None
                    return _real(name, *args, **kwargs)

                with self.cannot_write("mkdir", errno.ENOSPC), mock.patch.object(PRUNE.os, attr, returning), \
                        mock.patch.object(os, "supports_dir_fd", os.supports_dir_fd | {returning}):
                    rc, out, err = self.run_prune(self.runner)
                reason = (f"this platform lacks a working descriptor-relative call: os.{attr} raised ProbeMismatch "
                          f"(os.{attr} of a name that does not exist returned)")
                self.assertEqual((rc, out), (EXIT_REFUSED, ""))
                self.assertEqual(err, f"prune_runner_tmp: refused: {reason}\n")
                self.assertEqual(self.annotations, [ANNOTATION_PREFIX + reason])
                self.assertTrue(victim.exists(), "nothing is deleted after the refusal")
                self.assertTrue(canary.exists())
                victim.unlink()
                canary.unlink()

    def refused_read_only_probe(self, reason, patches):
        """Run the prune with the probe unable to write (ENOSPC on mkdir) under ``patches``; assert the refusal."""
        victim = self.make_file("old.db", OLD_AGE_SECS)
        with patches, self.cannot_write("mkdir", errno.ENOSPC):  # patches outermost: they restore last
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, out), (EXIT_REFUSED, ""))
        self.assertEqual(err, f"prune_runner_tmp: refused: {reason}\n")
        self.assertEqual(self.annotations, [ANNOTATION_PREFIX + reason])
        self.assertTrue(victim.exists(), "nothing is deleted after the refusal")
        victim.unlink()

    def test_read_only_probe_refuses_a_call_that_is_not_implemented_with_the_exact_reason(self):
        """Round 2 siblings of L1: NotImplementedError and TypeError from lstat, unlink or rmdir are refusals."""
        for attr in ("lstat", "unlink", "rmdir"):
            for exc in (NotImplementedError("no dir_fd"), TypeError("no dir_fd")):
                with self.subTest(call=attr, exc=type(exc).__name__):
                    self.clear_runner()
                    real = getattr(os, attr)

                    def raising(name, *args, _real=real, _exc=exc, **kwargs):
                        if str(name).endswith(PRUNE.PROBE_ABSENT_SUFFIX):
                            raise _exc
                        return _real(name, *args, **kwargs)

                    patches = contextlib.ExitStack()
                    patches.enter_context(mock.patch.object(PRUNE.os, attr, raising))
                    patches.enter_context(mock.patch.object(os, "supports_dir_fd", os.supports_dir_fd | {raising}))
                    self.refused_read_only_probe(
                        f"this platform lacks a working descriptor-relative call: os.{attr} raised "
                        f"{type(exc).__name__} (no dir_fd)", patches)

    def test_read_only_probe_refuses_a_scandir_of_the_directory_that_fails(self):
        """Round 2 siblings of L1: the probe's last step, a scandir of the held directory, must list."""
        real = os.scandir
        for exc in (OSError(errno.EIO, os.strerror(errno.EIO)), NotImplementedError("no scandir"), TypeError("no scandir")):
            with self.subTest(exc=type(exc).__name__):
                self.clear_runner()
                state = {"calls": 0}

                def failing_once(target, _exc=exc, _state=state):
                    if isinstance(target, int) and _state["calls"] == 0:
                        _state["calls"] += 1
                        raise _exc
                    return real(target)

                patches = contextlib.ExitStack()
                patches.enter_context(mock.patch.object(PRUNE.os, "scandir", failing_once))
                patches.enter_context(mock.patch.object(os, "supports_fd", os.supports_fd | {failing_once}))
                shown = os.strerror(errno.EIO) if isinstance(exc, OSError) else "no scandir"
                self.refused_read_only_probe(
                    f"this platform lacks a working descriptor-relative call: os.scandir raised {type(exc).__name__} "
                    f"({shown})", patches)

    def test_read_only_probe_names_the_follow_symlinks_miss_and_the_first_miss_in_table_order(self):
        """Round 2 siblings of L1: the os.stat follow_symlinks row refuses, and with two calls missing the
        first one of the probe's table is the one named."""
        miss = "this platform lacks a working descriptor-relative call: os.{name} raised ProbeMismatch (os.{name} {why})"
        no_follow = {fn for fn in os.supports_follow_symlinks if fn is not os.stat}
        no_unlink = {fn for fn in os.supports_dir_fd if fn is not os.unlink}
        no_scandir = {fn for fn in os.supports_fd if fn is not os.scandir}
        cases = (
            ("follow_symlinks row", miss.format(name="stat", why="not in os.supports_follow_symlinks"),
             (("supports_follow_symlinks", no_follow),)),
            ("unlink before scandir", miss.format(name="unlink", why=READ_ONLY_MISSING_WHY),
             (("supports_dir_fd", no_unlink), ("supports_fd", no_scandir))),
        )
        for label, reason, tables in cases:
            with self.subTest(case=label):
                self.clear_runner()
                patches = contextlib.ExitStack()
                for table, value in tables:
                    patches.enter_context(mock.patch.object(os, table, value))
                self.refused_read_only_probe(reason, patches)

    def test_tree_deepened_past_the_bound_during_removal_is_a_counted_failure(self):
        """Round 2 siblings of L2: the depth bound is re-checked by the removal pass (a tree that deepens
        after the count), in the dry run as in the real run."""
        bound = 2
        results = {}
        for mode, extra in (("dry", ("--dry-run",)), ("real", ())):
            with self.subTest(mode=mode):
                self.clear_runner()
                top = self.runner / "deepening"
                (top / "a" / "b").mkdir(parents=True)
                (top / "a" / "b" / "f").write_bytes(b"x")
                age(top, OLD_AGE_SECS)
                b_ident = self.ident(top / "a" / "b")
                real_list = PRUNE.list_level
                state = {"grown": False}

                def deepen(dir_fd, *rest, _top=top, _state=state, _b=b_ident, **kwargs):
                    info = os.fstat(dir_fd)
                    if kwargs.get("remove") and not _state["grown"] and (info.st_dev, info.st_ino) == _b:
                        _state["grown"] = True
                        (_top / "a" / "b" / "c").mkdir()
                    return real_list(dir_fd, *rest, **kwargs)

                with mock.patch.object(PRUNE, "MAX_TREE_DEPTH", bound), mock.patch.object(PRUNE, "list_level", deepen):
                    rc, out, err = self.run_prune(self.runner, *extra)
                self.assertTrue(state["grown"])
                self.assertEqual(rc, EXIT_OK)
                self.assertEqual(err.splitlines(),
                                 [f"prune_runner_tmp: failed to remove deepening: deeper than {bound} levels"])
                self.assertRegex(out.splitlines()[-1], r"^pruned=0 kept=0 failed=1 freed_bytes=\d+ skipped=0$")
                self.assertTrue((top / "a" / "b" / "c").is_dir(), "the level over the bound is never entered")
                results[mode] = (rc, re.sub(r"freed_bytes=\d+", "freed_bytes=N", out.splitlines()[-1]), err)
        self.assertEqual(results.get("dry"), results.get("real"))

    def test_probe_error_that_is_not_cannot_write_stays_a_refusal(self):
        victim = self.make_file("old.db", OLD_AGE_SECS)
        with self.cannot_write("mkdir", errno.EACCES):
            rc, out, err = self.run_prune(self.runner)
        reason = ("this platform lacks a working descriptor-relative call: os.mkdir raised PermissionError "
                  f"({os.strerror(errno.EACCES)})")
        self.assertEqual((rc, out), (EXIT_REFUSED, ""))
        self.assertEqual(err, f"prune_runner_tmp: refused: {reason}\n")
        self.assertTrue(victim.exists())

    def test_full_disk_errno_from_a_call_that_creates_nothing_stays_a_refusal(self):
        """Only mkdir and the file create can fail for want of space: ENOSPC from the open of the probe
        directory or its lstat is a broken call, never the read-only path."""
        for attr in NON_CREATING_PROBE_CALLS:
            with self.subTest(call=attr):
                self.clear_runner()
                victim = self.make_file("old.db", OLD_AGE_SECS)
                real = getattr(os, attr)

                def failing(name, *args, _real=real, **kwargs):
                    creating = bool(args) and isinstance(args[0], int) and args[0] & os.O_CREAT
                    if kwargs.get("dir_fd") is not None and not creating and str(name).startswith(PRUNE.PROBE_PREFIX):
                        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
                    return _real(name, *args, **kwargs)

                with mock.patch.object(PRUNE.os, attr, failing), \
                        mock.patch.object(os, "supports_dir_fd", os.supports_dir_fd | {failing}):
                    rc, out, err = self.run_prune(self.runner)
                reason = (f"this platform lacks a working descriptor-relative call: os.{attr} raised OSError "
                          f"({os.strerror(errno.ENOSPC)})")
                self.assertEqual((rc, out), (EXIT_REFUSED, ""))
                self.assertEqual(err, f"prune_runner_tmp: refused: {reason}\n")
                self.assertEqual(self.annotations, [ANNOTATION_PREFIX + reason])
                self.assertTrue(victim.exists())
                victim.unlink()

    # decision 4 (CODE F3): only Linux and Darwin can verify mount identity; any other platform refuses loudly
    def test_platform_other_than_linux_and_darwin_is_a_counted_refusal(self):
        for platform in UNVERIFIABLE_PLATFORMS:
            with self.subTest(platform=platform):
                self.clear_runner()
                victim = self.make_file("old.db", OLD_AGE_SECS)
                with mock.patch.object(PRUNE.sys, "platform", platform):
                    rc, out, err = self.run_prune(self.runner)
                reason = PLATFORM_UNVERIFIABLE_REASON.format(platform=platform)
                self.assertEqual((rc, out), (EXIT_REFUSED, COUNTED_REFUSAL_SUMMARY + "\n"))
                self.assertEqual(err, f"prune_runner_tmp: refused: {reason}\n")
                self.assertEqual(self.annotations, [ANNOTATION_PREFIX + reason])
                self.assertTrue(victim.exists())
                victim.unlink()

    def test_mount_id_on_an_unverifiable_platform_is_unreadable_never_none(self):
        fd, _info = self.open_runner()
        for platform in UNVERIFIABLE_PLATFORMS:
            with self.subTest(platform=platform), mock.patch.object(PRUNE.sys, "platform", platform):
                with self.assertRaises(PRUNE.MountIdUnreadable):
                    PRUNE.mount_id(fd)

    def test_linux_and_darwin_are_not_refused(self):
        for platform in VERIFIABLE_PLATFORMS:
            if platform == "linux" and not sys.platform.startswith("linux"):
                continue
            with self.subTest(platform=platform):
                self.clear_runner()
                victim = self.make_file("old.db", OLD_AGE_SECS)
                with mock.patch.object(PRUNE.sys, "platform", platform):
                    rc, out, err = self.run_prune(self.runner)
                self.assertEqual((rc, err, self.annotations), (EXIT_OK, "", []))
                self.assertRegex(out, r"^pruned=1 kept=0 failed=0 freed_bytes=\d+ skipped=0\n$")
                self.assertFalse(victim.exists())

    # decision 5 (CODE F2): the dry run takes the real run's decision path up to the unlink
    def test_dry_run_decides_exactly_like_the_real_run(self):
        linux = sys.platform.startswith("linux")

        def bound_case():
            holder = self.runner / "holder"
            holder.mkdir()
            for index in range(3):
                (holder / f"f{index}").write_bytes(b"x")
            age(holder, OLD_AGE_SECS)
            return contextlib.ExitStack(), mock.patch.object(PRUNE, "MAX_TREE_ENTRIES", 2)

        def mount_case(unreadable):
            def build():
                holder = MountCrossing.stale_holder(self)
                kwargs = {"unreadable": True} if unreadable else {"value": -1}
                return contextlib.ExitStack(), self.mount_override(self.ident(holder / "inner"), **kwargs)
            return build

        def plain_case():
            self.make_file("old.db", OLD_AGE_SECS)
            self.make_tree("old-dir", OLD_AGE_SECS)
            self.make_file("young.db", YOUNG_AGE_SECS)
            return contextlib.ExitStack(), contextlib.nullcontext()

        cases = [("entry bound", bound_case), ("plain", plain_case)]
        if linux:
            cases += [("nested mount point", mount_case(False)), ("nested mnt_id unreadable", mount_case(True))]
        for label, build in cases:
            with self.subTest(case=label):
                self.clear_runner()
                _stack, patch = build()
                before = snapshot(self.runner)
                top_before = set(self.names())
                with patch:
                    dry_rc, dry_out, dry_err = self.run_prune(self.runner, "--dry-run")
                    self.assertEqual(snapshot(self.runner), before, "the dry run deletes nothing")
                    real_rc, real_out, real_err = self.run_prune(self.runner)
                facts = lambda text: re.sub(r"freed_bytes=\d+", "freed_bytes=N", text.splitlines()[-1])
                self.assertEqual((dry_rc, dry_err, facts(dry_out)), (real_rc, real_err, facts(real_out)))
                would = sorted(ln[len("would-remove "):] for ln in dry_out.splitlines() if ln.startswith("would-remove "))
                self.assertEqual(would, sorted(top_before - set(self.names())),
                                 "would-remove names exactly what the real run removes")

    def test_dry_run_reports_the_same_counts_and_reason_when_a_directory_moves_mid_walk(self):
        """Round 2 L2: the removal pass's up-walk identity check runs in the dry run too; a dry run that
        skipped it would say pruned=1 where the real run says failed=1."""
        for label, during_count, reason in (("during removal", False, DIR_MOVED_DURING_REMOVAL),
                                            ("during count", True, DIR_MOVED_DURING_COUNT)):
            results = {}
            for mode, extra in (("dry", ("--dry-run",)), ("real", ())):
                with self.subTest(case=label, mode=mode):
                    self.clear_runner()
                    top = self.runner / "top"
                    (top / "a" / "b").mkdir(parents=True)
                    (top / "a" / "b" / "f").write_bytes(b"x")
                    age(top, OLD_AGE_SECS)
                    outside = self.base / f"outside-{mode}-{int(during_count)}"
                    outside.mkdir()
                    (outside / "keep").write_bytes(b"keep")
                    b_ident = self.ident(top / "a" / "b")
                    real_list = PRUNE.list_level
                    state = {"moved": False}

                    def move_b(dir_fd, *rest, _during_count=during_count, _top=top, _outside=outside,
                               _state=state, _b=b_ident, **kwargs):
                        pending = real_list(dir_fd, *rest, **kwargs)
                        counting = not kwargs.get("remove", True)
                        info = os.fstat(dir_fd)
                        if counting == _during_count and not _state["moved"] and (info.st_dev, info.st_ino) == _b:
                            _state["moved"] = True
                            os.rename(_top / "a" / "b", _outside / "b")
                        return pending

                    with mock.patch.object(PRUNE, "list_level", move_b):
                        rc, out, err = self.run_prune(self.runner, *extra)
                    self.assertTrue(state["moved"])
                    self.assertEqual(rc, EXIT_OK)
                    self.assertEqual(err.splitlines(), [f"prune_runner_tmp: failed to remove top: {reason}"])
                    self.assertRegex(out.splitlines()[-1], r"^pruned=0 kept=0 failed=1 freed_bytes=\d+ skipped=0$")
                    self.assertEqual((outside / "keep").read_bytes(), b"keep")
                    self.assertEqual(len(self.annotations), 1)
                    results[mode] = (rc, re.sub(r"freed_bytes=\d+", "freed_bytes=N", out.splitlines()[-1]), err)
            self.assertEqual(results.get("dry"), results.get("real"), label)

    # decision 6 (SEC L2): the counting walk verifies the identity of the directory it returns to
    def test_directory_moved_during_count_stops_the_entry_with_the_exact_reason(self):
        top = self.runner / "top"
        (top / "a" / "b").mkdir(parents=True)
        (top / "a" / "b" / "f").write_bytes(b"x")
        (top / "a" / "keep.db").write_bytes(b"k")
        age(top, OLD_AGE_SECS)
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep").write_bytes(b"keep")
        b_ident = self.ident(top / "a" / "b")
        outside_ident = self.ident(outside)
        real_list = PRUNE.list_level
        state = {"moved": False, "listed": []}

        def move_b(dir_fd, *rest, **kwargs):
            info = os.fstat(dir_fd)
            state["listed"].append((info.st_dev, info.st_ino))
            pending = real_list(dir_fd, *rest, **kwargs)
            if not kwargs.get("remove", True) and not state["moved"] and (info.st_dev, info.st_ino) == b_ident:
                state["moved"] = True
                os.rename(top / "a" / "b", outside / "b")
            return pending

        with mock.patch.object(PRUNE, "list_level", move_b):
            rc, out, err = self.run_prune(self.runner)
        self.assertTrue(state["moved"])
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(err.splitlines(), [f"prune_runner_tmp: failed to remove top: {DIR_MOVED_DURING_COUNT}"])
        self.assertRegex(out, r"^pruned=0 kept=0 failed=1 freed_bytes=0 skipped=0\n$")
        self.assertNotIn(outside_ident, state["listed"])
        self.assertEqual((outside / "keep").read_bytes(), b"keep")
        self.assertEqual((outside / "b" / "f").read_bytes(), b"x")
        self.assertEqual((top / "a" / "keep.db").read_bytes(), b"k", "nothing is removed after a move in the count")

    # decision 7 (CODE F5): one cell per surviving mutant
    def test_inner_directory_swapped_between_listing_and_open_is_refused(self):
        """F5 :567: the open_checked re-check, not the top-level one, catches an inner swap in the removal pass."""
        top = self.runner / "top"
        (top / "sub").mkdir(parents=True)
        (top / "sub" / "f.db").write_bytes(b"f")
        age(top, OLD_AGE_SECS)
        elsewhere = self.base / "elsewhere"
        top_ident = self.ident(top)
        real_list = PRUNE.list_level
        state = {"swapped": False}

        def swap_sub(dir_fd, *rest, **kwargs):
            pending = real_list(dir_fd, *rest, **kwargs)
            info = os.fstat(dir_fd)
            if kwargs.get("remove") and not state["swapped"] and (info.st_dev, info.st_ino) == top_ident:
                state["swapped"] = True
                os.rename(top / "sub", elsewhere)
                (top / "sub").mkdir()
                (top / "sub" / "impostor-live").write_bytes(b"live")
            return pending

        with mock.patch.object(PRUNE, "list_level", swap_sub):
            rc, out, err = self.run_prune(self.runner)
        self.assertTrue(state["swapped"])
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(err.splitlines(), [f"prune_runner_tmp: failed to remove top: {ENTRY_CHANGED}"])
        self.assertRegex(out, r"^pruned=0 kept=0 failed=1 freed_bytes=\d+ skipped=0\n$")
        self.assertEqual((top / "sub" / "impostor-live").read_bytes(), b"live")

    def test_job_summary_that_is_a_symlink_is_not_written_through(self):
        """F5 :115: O_NOFOLLOW on GITHUB_STEP_SUMMARY; the link target keeps its bytes."""
        target = self.base / "summary-target"
        target.write_bytes(b"original")
        link = self.base / "summary-link"
        link.symlink_to(target)
        rc, out, err = self.run_prune(self.runner, env_extra={SUMMARY_ENV: str(link)})
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(err, SUMMARY_UNWRITABLE_LINE.format(why=SUMMARY_SYMLINK_WHY) + "\n")
        self.assertEqual(target.read_bytes(), b"original")

    def test_tree_one_level_over_the_depth_bound_loses_nothing(self):
        """F5 :632: the count pass stops at MAX+1 before the removal pass unlinks the files on its way down."""
        bound = 3
        top = self.runner / "over"
        level = top
        for depth in range(bound + 2):
            level.mkdir()
            (level / f"f{depth}.db").write_bytes(b"x")
            level = level / "d"
        age(top, OLD_AGE_SECS)
        before = snapshot(top)
        with mock.patch.object(PRUNE, "MAX_TREE_DEPTH", bound):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(err.splitlines(), [f"prune_runner_tmp: failed to remove over: deeper than {bound} levels"])
        self.assertRegex(out, r"^pruned=0 kept=0 failed=1 freed_bytes=0 skipped=0\n$")
        self.assertEqual(snapshot(top), before, "no file on the way down is removed")

    def test_entry_exactly_at_the_cutoff_is_kept(self):
        """F5 :724: mtime == now - JOB_START_GRACE_SECS is kept; one second older goes."""
        cutoff = CUTOFF_NOW - PRUNE.JOB_START_GRACE_SECS
        at = self.runner / "at-cutoff.db"
        older = self.runner / "older.db"
        for path, mtime in ((at, cutoff), (older, cutoff - 1)):
            path.write_bytes(b"x")
            os.utime(path, (mtime, mtime))
        with mock.patch.object(PRUNE.time, "time", return_value=float(CUTOFF_NOW)):
            rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertRegex(out, r"^pruned=1 kept=1 failed=0 freed_bytes=\d+ skipped=0\n$")
        self.assertEqual(self.names(), ["at-cutoff.db"])


SUN_PATH_OVERFLOW_BYTES = 200  # above both AF_UNIX limits (104 macOS, 108 Linux), so no TMPDIR length matters
BYTE_FF_REFUSED_NAME = "EILSEQ"
UNRELATED_PROBE_ERRNOS = (errno.ENOSPC, errno.EDQUOT, errno.EIO, errno.EROFS, errno.EACCES)


class HostProbes(unittest.TestCase):
    """Fix round 1 of #9674: a host probe skips only on the one errno that names the missing facility."""

    @staticmethod
    def failing_create(code):
        def create(path, flags, mode=0o777):
            raise OSError(code, os.strerror(code))
        return create

    def test_byte_ff_probe_skips_only_on_eilseq(self):
        got = probe_byte_ff_refusal(self.failing_create(errno.EILSEQ))
        self.assertEqual(got, BYTE_FF_REFUSED_NAME)
        self.assertEqual(
            byte_ff_reason(got),
            f"this file system refuses a file name holding byte 0xff (EILSEQ, platform {sys.platform})",
        )

    def test_byte_ff_probe_propagates_every_other_errno(self):
        for code in UNRELATED_PROBE_ERRNOS:
            with self.subTest(errno=errno.errorcode[code]):
                with self.assertRaises(OSError) as caught:
                    probe_byte_ff_refusal(self.failing_create(code))
                self.assertEqual(caught.exception.errno, code)

    def test_byte_ff_probe_propagates_a_non_oserror(self):
        def create(path, flags, mode=0o777):
            raise RuntimeError("boom")
        with self.assertRaises(RuntimeError):
            probe_byte_ff_refusal(create)

    def test_byte_ff_probe_accepting_host_returns_none(self):
        def accepting_create(path, flags, mode=0o777):
            return os.open(os.devnull, os.O_RDONLY)
        self.assertIsNone(probe_byte_ff_refusal(accepting_create))

    def test_hostile_names_drop_only_the_0xff_row_on_a_refusing_host(self):
        kept, dropped = split_hostile_names(HOSTILE_NAMES, BYTE_FF_REFUSED_NAME)
        self.assertEqual(dropped, ["bad\udcff\nname"])
        self.assertEqual(kept, [name for name in HOSTILE_NAMES if "\udcff" not in name])
        self.assertEqual(len(kept), len(HOSTILE_NAMES) - 1)

    def test_hostile_names_keep_every_row_on_an_accepting_host(self):
        kept, dropped = split_hostile_names(HOSTILE_NAMES, None)
        self.assertEqual((kept, dropped), (list(HOSTILE_NAMES), []))


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
        tree = ast.parse(self.source)
        users = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                 and "supports_dir_fd" in ast.unparse(node)}
        self.assertEqual(users, {"probe_read_only"},
                         "D-H1: the platform check is functional; the table is only the cannot-write fallback (decision 3)")

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


class SocketPathLimit9460(unittest.TestCase):
    """The socket cell binds whatever the length of TMPDIR or of the checkout path (#9460).

    Each cell runs the real ``EntryKinds`` class (the one that binds an AF_UNIX socket) in a child interpreter whose
    TMPDIR or checkout path is longer than SOCKET_PATH_LIMIT, and asserts it ends ``OK`` with no OSError.
    """

    def setUp(self):
        SCRATCH_BASE.mkdir(parents=True, exist_ok=True)
        holder = tempfile.TemporaryDirectory(dir=SCRATCH_BASE, prefix="sock9460-")
        self.addCleanup(holder.cleanup)
        self.scratch = Path(holder.name).resolve()

    def run_socket_cell(self, tests_dir, tmpdir):
        env = {key: value for key, value in os.environ.items() if key not in ("TMPDIR", "PRUNE_SCRIPT_UNDER_TEST")}
        if tmpdir is not None:
            env["TMPDIR"] = str(tmpdir)
        return subprocess.run(
            [sys.executable, "-m", "unittest", f"{SOCKET_CELL_MODULE}.{SOCKET_CELL_CLASS}"],
            cwd=tests_dir, env=env, capture_output=True, text=True, check=False, timeout=SOCKET_CELL_TIMEOUT_SECS)

    def assert_cell_green(self, done):
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn("OSError", done.stderr)
        self.assertNotIn("AF_UNIX path too long", done.stderr)
        self.assertRegex(done.stderr, r"(?m)^Ran [1-9][0-9]* tests? in ")
        self.assertRegex(done.stderr, r"(?m)^OK$")

    def test_socket_is_made_in_a_directory_deeper_than_sun_path_whatever_tmpdir_is(self):
        """Folded from #9674 round 1: the directory depth alone (not TMPDIR) is past both AF_UNIX limits."""
        deep = self.scratch.joinpath("d" * 60, "e" * 60, "f" * 60)
        deep.mkdir(parents=True)
        self.assertGreater(len(str(deep)), SUN_PATH_OVERFLOW_BYTES - 20)
        bind_unix_socket(deep, "k-sock")
        self.assertTrue(stat.S_ISSOCK(os.lstat(deep / "k-sock").st_mode))

    def test_socket_cell_with_a_200_byte_tmpdir(self):
        long_tmp = self.scratch
        for _ in range(LONG_TMPDIR_SEGMENTS):
            long_tmp = long_tmp / LONG_TMPDIR_SEGMENT
        long_tmp.mkdir(parents=True)
        self.assertGreaterEqual(len(str(long_tmp)), LONG_TMPDIR_BYTES)
        self.assert_cell_green(self.run_socket_cell(ROOT / "scripts/ci/tests", long_tmp))

    def test_bind_helper_restores_the_working_directory_on_success_and_on_failure(self):
        parent = self.scratch / "bind-parent"
        parent.mkdir()
        before = os.getcwd()
        bind_unix_socket(parent, "ok-sock")
        self.assertEqual(os.getcwd(), before)
        self.assertTrue(stat.S_ISSOCK(os.lstat(parent / "ok-sock").st_mode))
        with self.assertRaises(OSError) as raised:  # the name is taken: bind raises after the chdir
            bind_unix_socket(parent, "ok-sock")
        self.assertEqual(raised.exception.errno, errno.EADDRINUSE)
        self.assertEqual(os.getcwd(), before)
        too_long = "n" * SOCKET_PATH_LIMIT
        with self.assertRaises(ValueError):
            bind_unix_socket(parent, too_long)
        self.assertEqual(os.getcwd(), before)

    def test_socket_cell_from_a_checkout_path_past_the_socket_limit(self):
        checkout = self.scratch
        for _ in range(LONG_CHECKOUT_SEGMENTS):
            checkout = checkout / LONG_CHECKOUT_SEGMENT
        tests_dir = checkout / "scripts/ci/tests"
        tests_dir.mkdir(parents=True)
        shutil.copy2(Path(__file__), tests_dir / f"{SOCKET_CELL_MODULE}.py")
        for rel in SOCKET_CELL_SIBLINGS:
            shutil.copy2(ROOT / rel, checkout / rel)
        self.assertGreater(len(str(tests_dir / "k-sock")), SOCKET_PATH_LIMIT)
        self.assert_cell_green(self.run_socket_cell(tests_dir, None))


LIVE_WRITER_AGE_SECS = 3  # an entry touched seconds ago: owned by a job that is still running
FUTURE_SKEW_SECS = -1000  # an mtime 1000 s ahead of the clock (age() subtracts)
F1_LAYOUT_REFUSAL = "TMPDIR is not <root>/<runner folder>/_tmp of an allowed layout: {path}"
FLAG_PLATFORMS = ("linux", "darwin")
# PR 9822 r1: job end that is not cleared says why with a non-zero exit and one ::error annotation.
EXIT_NOT_CLEARED = 3
EXIT_USAGE = 2  # argparse exits 2 on a usage error
EPERM_ENDPOINT_PID = 4194301  # any pid above MIN_ENDPOINT_PID; os.kill is mocked to answer EPERM for it
LONG_COMPONENT_CHARS = 900  # one path component past NAME_MAX (255): lstat answers ENAMETOOLONG; the reason fills the line
ERROR_REFUSED = "::error title=prune_runner_tmp refused::prune_runner_tmp: refused: "
WARNING_REFUSED = "::warning title=prune_runner_tmp refused::prune_runner_tmp: refused: "
ERROR_FAILED = "::error title=prune_runner_tmp failed::prune_runner_tmp: "
# Written out from the TMPDIR= line of each live runner .env on f1 (2026-11-22) and the runner's agentName;
# never computed from the script (code HIGH-3, security M1/M3).
LIVE_RUNNER_TABLE = (
    ("f1-macos-fed", "/Volumes/f1dev/rt/fed/_tmp"),
    ("f1-macos-fed-2", "/Volumes/f1dev/rt/fed2/_tmp"),
    ("f1-macos-fed-3", "/Volumes/f1dev/rt/fed3/_tmp"),
)
NOT_A_RUNNER_FOLDER = ("evil", "fedx", "fed-2", "fed2x", "Fed2", "actions-runner", "actions-runner-2",
                       "f1-macos-fed-3", "tmp", "fed٢")
RUNNER_UNSET_REFUSAL = "RUNNER_NAME is unset or empty; the runner folder cannot be bound: {path}"
RUNNER_UNBOUND_REFUSAL = "TMPDIR folder {folder} is not the folder of runner {runner}: {path}"
TMPDIR_FLAGGED_REFUSAL = "TMPDIR carries an immutable or append-only flag: {path}"
CONTAINS_REFUSAL = "TMPDIR contains the home directory or the workspace: {path}"
JOB_START_GRACE_SECS_PINNED = 30
FS_IOC_PINNED = (0x80086601, 0x40086602)  # _IOR('f', 1, long) and _IOW('f', 2, long) on a 64-bit kernel
# Every module call the script may make (code MEDIUM-6): an allowlist, never a list of forbidden spellings.
PERMITTED_CALLS = frozenset({
    "argparse.ArgumentParser", "fcntl.ioctl", "os.chflags", "os.close", "os.fchdir", "os.fchmod", "os.fstat",
    "os.getcwd", "os.geteuid", "os.getpid", "os.kill", "os.lstat", "os.mkdir", "os.open", "os.path.basename",
    "os.path.dirname", "os.path.expanduser", "os.path.isabs", "os.path.normpath", "os.path.realpath", "os.read",
    "os.rmdir", "os.scandir", "os.stat", "os.unlink", "os.urandom", "os.urandom(PROBE_RANDOM_BYTES).hex",
    "os.write", "re.compile", "stat.S_IMODE", "stat.S_ISDIR", "stat.S_ISFIFO", "stat.S_ISLNK", "stat.S_ISREG",
    "stat.S_ISSOCK", "struct.pack", "struct.unpack", "sys.exit", "sys.modules.get", "sys.stderr.write",
    "sys.stdout.write", "sys.version.splitlines", "time.time",
})
REFLECTIVE_NAMES = ("__import__", "exec", "eval", "compile", "getattr", "globals", "vars", "setattr")
PERMITTED_REFLECTIVE_CALLS = frozenset({
    "__import__('os')", "compile(source, path, 'exec', dont_inherit=True)",
    "exec(compile(source, path, 'exec', dont_inherit=True), module.__dict__)", "getattr(exc, 'escaped', None)",
    "getattr(module, name, None)", "getattr(os, 'O_CLOEXEC', 0)", "getattr(os, 'O_NONBLOCK', 0)",
    "getattr(os.lstat(target), 'st_flags', 0)", "getattr(os.fstat(fd), 'st_flags', 0)",
    "getattr(reason, 'counted', False)", "getattr(reason, 'raw', reason)", "getattr(stat, 'UF_APPEND', 4)",
    "getattr(stat, 'UF_IMMUTABLE', 2)", "getattr(wa, 'safe_value', None)", "globals()",
})
# A module name used other than as ``module.attr``: the only permitted uses (an alias would hide a call).
PERMITTED_BARE_MODULE_USES = frozenset({
    "getattr(os, 'O_CLOEXEC', 0)", "getattr(os, 'O_NONBLOCK', 0)", "getattr(stat, 'UF_APPEND', 4)",
    "getattr(stat, 'UF_IMMUTABLE', 2)", "type(sys)",
})
PERMITTED_IMPORTS = frozenset({"argparse", "errno", "fcntl", "os", "re", "stat", "struct", "sys", "time"})
CALL_ROOTS = ("os", "time", "fcntl", "struct", "sys", "stat", "errno", "re", "argparse", "subprocess", "sp",
              "signal", "shutil", "socket", "threading", "psutil")


def module_calls(tree):
    """Every call whose callee is rooted at a module name, as source text."""
    return {ast.unparse(node.func) for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and ast.unparse(node.func).split(".")[0] in CALL_ROOTS}


def attribute_root(node):
    """The Name at the base of an ``a.b.c`` chain, or None when the chain starts at anything else."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node if isinstance(node, ast.Name) else None


def resolve_reference(text):
    """The object ``text`` (``module.attr...``) names, or None when it does not resolve here (fail closed)."""
    root, *parts = text.split(".")
    try:
        value = importlib.import_module(root)
        for part in parts:
            value = getattr(value, part)
    except (ImportError, AttributeError):
        return None
    return value


def callable_references(tree, parents):
    """Every module attribute named other than as a call's callee that is (or may be) a function.

    ``run = os.system`` or ``TABLE = (os.system,)`` hides a call from module_calls; such a reference counts as
    the call itself. A reference that does not resolve here, or that is written to, is reported as well.
    """
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or isinstance(parents.get(node), ast.Attribute):
            continue
        root = attribute_root(node)
        if root is None or root.id not in CALL_ROOTS:
            continue
        parent = parents.get(node)
        if isinstance(parent, ast.Call) and parent.func is node:
            continue
        text = ast.unparse(node)
        if not isinstance(node.ctx, ast.Load):
            found.add(f"write {text}")
            continue
        value = resolve_reference(text)
        if value is None or callable(value):
            found.add(text)
    return found


class FlagWorld:
    """A fake protect-flag store keyed by file identity, plus an unlink, rmdir and mkdir that honour it.

    A flagged entry cannot be removed, and nothing inside a flagged directory can be removed or made: the
    EPERM a real append-only or immutable flag gives. Clearing needs CAP_LINUX_IMMUTABLE (linux) or ownership
    (darwin), neither of which a test may assume, so the platform primitives (the ioctl pair and the
    chflags pair) are replaced by dict accessors and every other line of the clear path runs for real.
    Keys come from lstat (never a symlink target), as the real flag calls use O_NOFOLLOW / follow_symlinks=False.
    """

    def __init__(self, error=errno.EPERM):
        self.flags = {}
        self.error = error

    @staticmethod
    def key(info):
        return (info.st_dev, info.st_ino)

    def set(self, path, value):
        self.flags[self.key(os.lstat(path))] = value

    def get(self, path):
        return self.flags.get(self.key(os.lstat(path)), 0)

    def guarded(self, real):
        def remover(name, *args, dir_fd=None, **kwargs):
            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)  # ENOENT passes through, as for the real call
            parent = os.fstat(dir_fd) if dir_fd is not None else os.stat(os.path.dirname(os.fspath(name)) or ".")
            if self.flags.get(self.key(info)) or self.flags.get(self.key(parent)):
                raise PermissionError(self.error, os.strerror(self.error))
            return real(name, *args, dir_fd=dir_fd, **kwargs)

        return remover

    def guarded_mkdir(self, real):
        def maker(name, *args, dir_fd=None, **kwargs):
            parent = os.fstat(dir_fd) if dir_fd is not None else os.stat(os.path.dirname(os.fspath(name)) or ".")
            if self.flags.get(self.key(parent)):
                raise PermissionError(errno.EPERM, "Operation not permitted")
            return real(name, *args, dir_fd=dir_fd, **kwargs)

        return maker


class JobBoundaryClear9820(Base):
    """#9820: the runner's TMPDIR holds nothing a job made once the job ends; a live job's entry survives."""

    def make_scratch(self):
        """A left-behind file, a tree and a folder that carries the protect flag; returns the flagged folder."""
        self.make_file("left.db", 0)
        self.make_tree("left-dir", 0)
        flagged = self.runner / "append-only-dir"
        (flagged / "inner").mkdir(parents=True)
        (flagged / "inner" / "events.log").write_bytes(b"e" * 50)
        (flagged / "top.log").write_bytes(b"t" * 50)
        return flagged

    def flag_world(self, platform, flagged=None, protect=None, error=errno.EPERM):
        """Patch the platform's flag primitives onto a FlagWorld and make ``flagged`` and its file protected."""
        world = FlagWorld(error)
        if protect is None:
            protect = PRUNE.LINUX_PROTECT_FLAGS if platform == "linux" else PRUNE.DARWIN_PROTECT_FLAGS
        self.protect = protect
        if flagged is not None:
            world.set(flagged, protect)
            world.set(flagged / "top.log", protect)
        patches = [
            mock.patch.object(PRUNE.os, "unlink", world.guarded(os.unlink)),
            mock.patch.object(PRUNE.os, "rmdir", world.guarded(os.rmdir)),
            mock.patch.object(PRUNE.os, "mkdir", world.guarded_mkdir(os.mkdir)),
            mock.patch.object(PRUNE, "fd_flags", lambda fd: world.flags.get(world.key(os.fstat(fd)), 0)),
        ]
        if platform == "linux":
            clearer = PRUNE.linux_clear_flags
            patches += [
                mock.patch.object(PRUNE, "linux_flags", lambda fd: world.flags.get(world.key(os.fstat(fd)), 0)),
                mock.patch.object(PRUNE, "linux_set_flags",
                                  lambda fd, value: world.flags.__setitem__(world.key(os.fstat(fd)), value)),
            ]
        else:
            clearer = PRUNE.darwin_clear_flags
            patches += [
                mock.patch.object(PRUNE, "darwin_flags", lambda target: world.get(target)),
                mock.patch.object(PRUNE, "darwin_set_flags",
                                  lambda target, value: world.flags.__setitem__(world.key(os.lstat(target)), value)),
            ]
        patches.append(mock.patch.object(PRUNE, "FLAG_CLEARERS", {sys.platform: clearer}))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return world

    def errors(self):
        return [line for line in self.annotations if line.startswith("::error")]

    def assert_not_cleared(self, rc, err, reason):
        """Job end refused: exit 3, the reason on stderr and exactly one ::error annotation with it."""
        self.assertEqual(rc, EXIT_NOT_CLEARED, err)
        self.assertEqual(err, f"prune_runner_tmp: refused: {reason}\n")
        self.assertEqual(self.errors(), [ERROR_REFUSED + reason])

    def check_left_scratch_is_cleared(self, platform, protect=None, error=errno.EPERM):
        flagged = self.make_scratch()
        world = self.flag_world(platform, flagged, protect, error)
        rc, out, err = self.run_prune(self.runner, "--mode", "job-end")
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertRegex(out, r"^pruned=3 kept=0 failed=0 freed_bytes=\d+ skipped=0\n$")
        self.assertEqual(self.names(), [], "nothing the job made is left")
        self.assertTrue(world.flags, "the fake flag store was in play")

    def test_job_end_removes_a_left_file_and_an_append_only_folder_on_the_linux_path(self):
        self.check_left_scratch_is_cleared("linux")

    def test_job_end_removes_a_left_file_and_an_append_only_folder_on_the_darwin_path(self):
        self.check_left_scratch_is_cleared("darwin")

    def test_medium3_eacces_from_a_protect_flag_is_cleared_too(self):
        for platform in FLAG_PLATFORMS:
            with self.subTest(platform=platform):
                self.check_left_scratch_is_cleared(platform, error=errno.EACCES)

    def test_medium3_an_immutable_only_flag_is_cleared_on_both_paths(self):
        cases = (("linux", 0x10), ("darwin", 0x2))  # FS_IMMUTABLE_FL, UF_IMMUTABLE
        for platform, protect in cases:
            with self.subTest(platform=platform):
                self.check_left_scratch_is_cleared(platform, protect=protect)
        self.assertEqual(PRUNE.FS_IMMUTABLE_FL & PRUNE.LINUX_PROTECT_FLAGS, 0x10)
        self.assertEqual(PRUNE.DARWIN_PROTECT_FLAGS & 0x2, 0x2)

    def test_medium3_the_flag_ioctl_numbers_are_the_kernel_ones(self):
        self.assertEqual((PRUNE.FS_IOC_GETFLAGS, PRUNE.FS_IOC_SETFLAGS), FS_IOC_PINNED)

    def test_high1_without_the_flag_clearing_job_end_is_not_cleared_and_exits_non_zero(self):
        """The guard of the fake store is real: with no clearer the same scratch cannot be removed."""
        flagged = self.make_scratch()
        self.flag_world("linux", flagged)
        with mock.patch.object(PRUNE, "FLAG_CLEARERS", {}):
            rc, out, err = self.run_prune(self.runner, "--mode", "job-end")
        self.assertEqual(rc, EXIT_NOT_CLEARED)
        self.assertEqual(err, "prune_runner_tmp: failed to remove append-only-dir: [Errno 1] Operation not permitted\n")
        self.assertRegex(out, r"^pruned=2 kept=0 failed=1 freed_bytes=\d+ skipped=0\n$")
        self.assertEqual(self.errors(), [ERROR_FAILED + "failed=1 not removed: append-only-dir"])
        self.assertEqual(self.names(), ["append-only-dir"])

    def test_high1_the_same_failure_at_job_start_is_a_warning_with_exit_0(self):
        flagged = self.make_scratch()
        age(flagged, OLD_AGE_SECS)  # past the job-start grace, so it is tried (the young left.db, left-dir are kept)
        self.flag_world("linux", flagged)
        with mock.patch.object(PRUNE, "FLAG_CLEARERS", {}):
            rc, out, err = self.run_prune(self.runner, "--mode", "job-start")
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(self.errors(), [])
        self.assertEqual(self.annotations, [FAILED_TITLE + "failed=1 not removed: append-only-dir"])

    def test_medium2_a_symlink_to_a_flagged_outside_target_is_unlinked_and_the_target_keeps_its_flag(self):
        """The link sits in a flagged folder, so its unlink fails first and the flag clearing runs on the link."""
        outside = self.base / "outside.db"
        outside.write_bytes(b"o")
        for platform in FLAG_PLATFORMS:
            with self.subTest(platform=platform):
                box = self.runner / "box"
                box.mkdir()
                (box / "link").symlink_to(outside)
                world = self.flag_world(platform)
                world.set(outside, self.protect)
                world.set(box, self.protect)
                rc, out, err = self.run_prune(self.runner, "--mode", "job-end")
                self.assertEqual((rc, err), (EXIT_OK, ""))
                self.assertEqual(self.names(), [])
                self.assertEqual(world.get(outside), self.protect, "the outside target's flag is untouched")
                self.assertTrue(outside.exists())

    def test_low1_a_hard_link_to_a_flagged_outside_file_is_a_failure_and_its_flag_is_untouched(self):
        outside = self.base / "outside-hard.db"
        outside.write_bytes(b"o")
        os.link(outside, self.runner / "hard.db")
        for platform in FLAG_PLATFORMS:
            with self.subTest(platform=platform):
                world = self.flag_world(platform)
                world.set(outside, self.protect)
                rc, out, err = self.run_prune(self.runner, "--mode", "job-end")
                self.assertEqual(rc, EXIT_NOT_CLEARED)
                self.assertEqual(err, "prune_runner_tmp: failed to remove hard.db: [Errno 1] Operation not permitted\n")
                self.assertEqual(self.errors(), [ERROR_FAILED + "failed=1 not removed: hard.db"])
                self.assertEqual(world.get(outside), self.protect, "a shared inode never has its flag cleared")

    def test_medium5_an_owned_read_only_directory_is_made_writable_once_and_removed(self):
        locked = self.runner / "locked"
        (locked / "deep").mkdir(parents=True)
        (locked / "deep" / "f.db").write_bytes(b"x")
        (locked / "g.db").write_bytes(b"y")
        os.chmod(locked / "deep", 0o500)
        os.chmod(locked, 0o500)
        self.addCleanup(lambda: [os.chmod(p, 0o700) for p in (locked, locked / "deep") if p.exists()])
        rc, out, err = self.run_prune(self.runner, "--mode", "job-end")
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertRegex(out, r"^pruned=1 kept=0 failed=0 freed_bytes=\d+ skipped=0\n$")
        self.assertEqual(self.names(), [])

    def test_l4_a_flagged_tmpdir_is_a_named_refusal(self):
        world = self.flag_world(PRUNE.PLATFORM_LINUX if sys.platform == PRUNE.PLATFORM_LINUX else PRUNE.PLATFORM_DARWIN)
        world.set(self.runner, self.protect)
        victim = self.make_file("old.db", 0)
        rc, out, err = self.run_prune(self.runner, "--mode", "job-end")
        self.assert_not_cleared(rc, err, TMPDIR_FLAGGED_REFUSAL.format(path=self.runner))
        self.assertTrue(victim.exists())

    def test_low2_a_live_runner_diagnostic_pipe_is_kept_and_a_dead_ones_removed(self):
        dead = subprocess.Popen([sys.executable, "-c", ""])
        dead.wait()
        live_name = f"clr-debug-pipe-{os.getpid()}-1-in"
        os.mkfifo(self.runner / live_name)
        os.mkfifo(self.runner / f"dotnet-diagnostic-{dead.pid}-2-socket")
        self.make_file(f"dotnet-diagnostic-{os.getpid()}-3-socket", 0)  # a regular file is never kept
        # pid 0 (kill reaches the process group) and pid 1 (init answers EPERM) are below MIN_ENDPOINT_PID
        for floor_pid in (0, 1):
            os.mkfifo(self.runner / f"clr-debug-pipe-{floor_pid}-4-in")
        rc, out, err = self.run_prune(self.runner, "--mode", "job-end")
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertRegex(out, r"^pruned=4 kept=1 failed=0 freed_bytes=\d+ skipped=0\n$")
        self.assertEqual(self.names(), [live_name])

    def test_n4_an_endpoint_whose_pid_answers_eperm_is_live_and_kept(self):
        """#9876 N4: kill(pid, 0) raising PermissionError means the process exists (another user's): kept."""
        live_name = f"clr-debug-pipe-{EPERM_ENDPOINT_PID}-1-in"
        os.mkfifo(self.runner / live_name)
        with mock.patch.object(PRUNE.os, "kill", side_effect=PermissionError(errno.EPERM, os.strerror(errno.EPERM))):
            rc, out, err = self.run_prune(self.runner, "--mode", "job-end")
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertRegex(out, r"^pruned=0 kept=1 failed=0 freed_bytes=\d+ skipped=0\n$")
        self.assertEqual(self.names(), [live_name])

    def test_n5_eacces_in_a_flagged_read_only_owned_directory_clears_the_flag_and_opens_the_directory(self):
        """#9876 N5: the flag clear changes something AND the EACCES needs owner rwx: both happen, the entry goes."""
        world = self.flag_world(PRUNE.PLATFORM_LINUX if sys.platform == PRUNE.PLATFORM_LINUX else PRUNE.PLATFORM_DARWIN,
                                error=errno.EACCES)
        box = self.runner / "box"
        box.mkdir()
        (box / "f.db").write_bytes(b"x")
        world.set(box, self.protect)
        os.chmod(box, 0o500)
        self.addCleanup(lambda: box.exists() and os.chmod(box, 0o700))
        rc, out, err = self.run_prune(self.runner, "--mode", "job-end")
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertRegex(out, r"^pruned=1 kept=0 failed=0 freed_bytes=\d+ skipped=0\n$")
        self.assertEqual(self.names(), [])

    def test_n6_a_mode_option_after_the_end_of_options_marker_is_not_the_mode(self):
        self.assertEqual(PRUNE.requested_mode(["--", "--mode", "job-end"]), "job-start")
        self.assertEqual(PRUNE.requested_mode(["--", "--mode=job-end"]), "job-start")

    def test_n2_requested_mode_and_the_parser_agree_on_every_spelling(self):
        """#9876 N2: the mode the load refusal reads is the mode argparse parses; an abbreviation is a usage error."""
        usage_error = "usage error"
        table = (  # (argv, requested_mode, what main does with TMPDIR unset), written by hand
            ((), "job-start", EXIT_OK),
            (("--mode", "job-end"), "job-end", EXIT_NOT_CLEARED),
            (("--mode=job-end",), "job-end", EXIT_NOT_CLEARED),
            (("--mode", "job-start"), "job-start", EXIT_OK),
            (("--mode=job-start",), "job-start", EXIT_OK),
            (("--dry-run", "--mode=job-end"), "job-end", EXIT_NOT_CLEARED),
            (("--mode", "job-start", "--mode", "job-end"), "job-end", EXIT_NOT_CLEARED),
            (("--mo", "job-end"), "job-start", usage_error),
            (("--mo=job-end",), "job-start", usage_error),
            (("--mod", "job-end"), "job-start", usage_error),
            (("--", "--mode", "job-end"), "job-start", usage_error),
            (("--", "--mode=job-end"), "job-start", usage_error),
        )
        for argv, mode, outcome in table:
            with self.subTest(argv=argv):
                self.assertEqual(PRUNE.requested_mode(list(argv)), mode)
                with mock.patch.object(sys, "stderr", io.StringIO()):
                    try:
                        rc, _out, _err = self.run_prune(None, *argv)
                    except SystemExit as exc:
                        rc = usage_error if exc.code == EXIT_USAGE else exc.code
                self.assertEqual(rc, outcome)

    def context_row_world(self, state):
        """Build the state of one N1 row; returns (TMPDIR, extra environment)."""
        if state == "unset":
            return None, {}
        if state == "empty":
            return "", {}
        if state == "relative":
            return "runner-1", {}
        if state == "outside":
            outside = self.base / "runner-4"
            outside.mkdir(exist_ok=True)
            return outside, {}
        if state == "linux_missing":
            return self.root / "runner-2", {}
        if state in ("macos_runner_unset", "macos_runner_unbound"):
            self.layouts_here()
            leaf = self.leaf("fed3")
            return leaf, ({} if state == "macos_runner_unset" else {"RUNNER_NAME": "f1-macos-fed-2"})
        if state in ("failed", "clean"):
            self.make_file("old.db", OLD_AGE_SECS)
            return self.runner, {}
        raise AssertionError(state)

    def test_n1_every_state_names_layout_owner_and_entry_with_its_exit(self):
        """#9876 N1: each state maps to one exact annotation and exit code (the expected column is written out)."""
        uid = os.getuid()
        root, base, runner = str(self.root), str(self.base), str(self.runner)
        leaf = f"{root}/fed3/_tmp"

        def cut(text):
            return text if len(text) <= ANNOTATION_NAME_MAX_CHARS else text[:ANNOTATION_NAME_MAX_CHARS] + "..."

        refusals = {
            "unset": "TMPDIR is unset (layout=none owner=unset entry=unset)",
            "empty": "TMPDIR is empty (layout=none owner=unset entry=empty)",
            "relative": "TMPDIR is not an absolute path: runner-1 (layout=none owner=relative entry=runner-1)",
            "outside": (f"TMPDIR is outside the allowed roots ['{root}']: {base}/runner-4"
                        f" (layout=none owner={uid} entry={cut(base + '/runner-4')})"),
            "linux_missing": (f"TMPDIR does not exist: {root}/runner-2 (No such file or directory)"
                              f" (layout=linux:{cut(root + '/runner-2')} owner=ENOENT entry={cut(root + '/runner-2')})"),
            "macos_runner_unset": (RUNNER_UNSET_REFUSAL.format(path=leaf)
                                   + f" (layout=macos:{cut(leaf)} runner=unset owner={uid} entry={cut(leaf)})"),
            "macos_runner_unbound": (RUNNER_UNBOUND_REFUSAL.format(folder="fed3", runner="f1-macos-fed-2", path=leaf)
                                     + f" (layout=macos:{cut(leaf)} runner=f1-macos-fed-2 owner={uid}"
                                     f" entry={cut(leaf)})"),
        }
        failed = f"failed=1 layout=linux:{cut(runner)} not removed: old.db (owner={uid} errno=EACCES)"
        table = []
        for state, text in refusals.items():
            table.append((state, "job-start", EXIT_OK, [WARNING_REFUSED + text]))
            table.append((state, "job-end", EXIT_NOT_CLEARED, [ERROR_REFUSED + text]))
        table += [
            ("failed", "job-start", EXIT_OK, [FAILED_TITLE + failed]),
            ("failed", "job-end", EXIT_NOT_CLEARED, [ERROR_FAILED + failed]),
            ("clean", "job-start", EXIT_OK, []),
            ("clean", "job-end", EXIT_OK, []),
        ]
        self.assertEqual(len(table), 2 * (len(refusals) + 2))
        for state, mode, want_rc, want in table:
            with self.subTest(state=state, mode=mode):
                with mock.patch.dict(os.environ, {}, clear=False):
                    raw, env_extra = self.context_row_world(state)
                    if state == "failed":
                        with self.deny_unlink():
                            rc, _out, _err = self.run_prune(raw, "--mode", mode, env_extra=env_extra)
                    else:
                        rc, _out, _err = self.run_prune(raw, "--mode", mode, env_extra=env_extra)
                self.assertEqual((rc, self.raw_annotations), (want_rc, want))
                self.reset_row_world()

    def test_n1_a_reason_past_the_line_cap_is_cut_and_the_context_is_kept(self):
        """#9876 N1: a TMPDIR long enough to fill the line cuts the reason, never the layout, owner and entry."""
        raw = f"{self.base}/" + "a" * LONG_COMPONENT_CHARS + "/runner-1"
        want_context = f" (layout=none owner=ENAMETOOLONG entry={raw[:ANNOTATION_NAME_MAX_CHARS]}...)"
        for mode in ("job-start", "job-end"):
            with self.subTest(mode=mode):
                rc, _out, _err = self.run_prune(raw, "--mode", mode)
                self.assertEqual(rc, EXIT_OK if mode == "job-start" else EXIT_NOT_CLEARED)
                [line] = self.raw_annotations
                self.assertLessEqual(len(line), ANNOTATION_MAX_CHARS)
                self.assertTrue(line.endswith("..." + want_context), line[-200:])

    def reset_row_world(self):
        for path in (self.base / "runner-4", self.runner / "old.db"):
            if path.is_dir():
                path.rmdir()
            elif path.exists():
                path.unlink()

    def test_job_end_removes_an_entry_touched_a_moment_ago_and_one_dated_in_the_future(self):
        self.make_file("fresh.db", LIVE_WRITER_AGE_SECS)
        self.make_file("skewed.db", FUTURE_SKEW_SECS)
        self.make_tree("fresh-dir", 0)
        rc, out, err = self.run_prune(self.runner, "--mode", "job-end")
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertRegex(out, r"^pruned=3 kept=0 failed=0 freed_bytes=\d+ skipped=0\n$")
        self.assertEqual(self.names(), [])

    def test_job_start_keeps_the_entry_of_a_live_job_and_removes_what_an_ended_job_left(self):
        live_file = self.make_file("live.db", LIVE_WRITER_AGE_SECS)
        live_tree = self.make_tree("live-dir", LIVE_WRITER_AGE_SECS)
        self.make_file("left.db", PRUNE.JOB_START_GRACE_SECS + OLD_AGE_SECS)
        self.make_tree("left-dir", PRUNE.JOB_START_GRACE_SECS + OLD_AGE_SECS)
        rc, out, err = self.run_prune(self.runner, "--mode", "job-start")
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertRegex(out, r"^pruned=2 kept=2 failed=0 freed_bytes=\d+ skipped=0\n$")
        self.assertEqual(self.names(), ["live-dir", "live.db"])
        self.assertTrue(live_file.exists() and (live_tree / "sub" / "f.db").exists())

    def test_medium1_the_grace_is_30_s_an_entry_of_29_s_is_kept_and_one_of_31_s_removed(self):
        self.assertEqual(PRUNE.JOB_START_GRACE_SECS, JOB_START_GRACE_SECS_PINNED)
        self.make_file("young.db", JOB_START_GRACE_SECS_PINNED - 1)
        self.make_file("old.db", JOB_START_GRACE_SECS_PINNED + 1)
        rc, out, err = self.run_prune(self.runner, "--mode", "job-start")
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertRegex(out, r"^pruned=1 kept=1 failed=0 freed_bytes=\d+ skipped=0\n$")
        self.assertEqual(self.names(), ["young.db"])

    def test_the_default_mode_is_job_start_and_an_unknown_mode_is_a_usage_error(self):
        live = self.make_file("live.db", LIVE_WRITER_AGE_SECS)
        rc, out, err = self.run_prune(self.runner)
        self.assertEqual((rc, err), (EXIT_OK, ""))
        self.assertIn("pruned=0 kept=1 failed=0", out)
        self.assertTrue(live.exists())
        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stderr(io.StringIO()):
                self.run_prune(self.runner, "--mode", "idle")
        self.assertEqual(raised.exception.code, 2)
        self.assertTrue(live.exists())

    def test_the_grace_belongs_to_job_start_only(self):
        self.assertEqual(PRUNE.GRACE_SECS_BY_MODE, {"job-start": JOB_START_GRACE_SECS_PINNED, "job-end": 0})
        self.assertEqual(PRUNE.MODES, ("job-start", "job-end"))

    def test_medium6_the_script_makes_only_permitted_calls_and_imports(self):
        """f1 runners go from one job to the next in 2 s: nothing may wait for idleness, sleep or look at processes."""
        source = (ROOT / "scripts/ci/prune_runner_tmp.py").read_text()
        self.check_ratchet(source)
        for text in (source, (ROOT / ACTION_PATH).read_text()):
            self.assertNotRegex(text, r"(?i)\bsleep\b|pgrep|Runner\.Worker|\bidle poll")

    def check_ratchet(self, source):
        tree = ast.parse(source)
        self.assertLessEqual(module_calls(tree), PERMITTED_CALLS)
        imported = {alias.asname or alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                    for alias in node.names}
        self.assertEqual(imported, PERMITTED_IMPORTS)
        self.assertEqual([node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)], [])
        reflective = {ast.unparse(node) for node in ast.walk(tree) if isinstance(node, ast.Call)
                      and isinstance(node.func, ast.Name) and node.func.id in REFLECTIVE_NAMES}
        self.assertLessEqual(reflective, PERMITTED_REFLECTIVE_CALLS)
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        bare = {ast.unparse(parents[node]) for node in ast.walk(tree)
                if isinstance(node, ast.Name) and node.id in CALL_ROOTS
                and not (isinstance(parents.get(node), ast.Attribute) and parents[node].value is node)}
        self.assertLessEqual(bare, PERMITTED_BARE_MODULE_USES)
        self.assertLessEqual(callable_references(tree, parents), PERMITTED_CALLS)

    def test_medium6_each_ratchet_form_is_red(self):
        source = (ROOT / "scripts/ci/prune_runner_tmp.py").read_text()
        for mutant in ("import subprocess as sp\n", "from time import sleep\n", "os.system('true')\n",
                       "sp.run(['x'])\n", "__import__('subprocess')\n", "import signal\n", "run = os.system\n",
                       "getattr(os, 'system')('true')\n", "time.sleep(1)\n", "os.execv('/bin/true', ['true'])\n",
                       "eval('1')\n", "TABLE = {'x': os}\n"):
            with self.subTest(mutant=mutant):
                with self.assertRaises(AssertionError):
                    self.check_ratchet(source + mutant)

    def leaf(self, folder):
        leaf = self.root / folder / PRUNE.RUNNER_FOLDER_LEAF
        leaf.mkdir(parents=True, exist_ok=True)
        return leaf

    def layouts_here(self):
        patch = mock.patch.object(PRUNE, "RUNNER_FOLDER_LAYOUTS", ((str(self.root), PRUNE.RUNNER_FOLDER_LAYOUTS[0][1]),))
        patch.start()
        self.addCleanup(patch.stop)

    def test_high3_every_live_runner_tmpdir_is_cleared_at_job_end(self):
        self.layouts_here()
        for runner, tmpdir in LIVE_RUNNER_TABLE:
            with self.subTest(runner=runner):
                leaf = self.leaf(Path(tmpdir).parent.name)
                self.make_file("old.db", 0, leaf)
                rc, out, err = self.run_prune(leaf, "--mode", "job-end", env_extra={"RUNNER_NAME": runner})
                self.assertEqual((rc, err), (EXIT_OK, ""))
                self.assertIn("pruned=1 kept=0 failed=0", out)
                self.assertEqual(self.names(leaf), [])

    def test_high3_the_layout_table_is_the_live_one(self):
        self.assertEqual([root for root, _ in PRUNE.RUNNER_FOLDER_LAYOUTS],
                         sorted({str(Path(tmpdir).parent.parent) for _, tmpdir in LIVE_RUNNER_TABLE}))
        self.assertEqual(PRUNE.F1_VOLUME_RUNNER_ROOT, str(Path(LIVE_RUNNER_TABLE[0][1]).parent.parent))
        self.assertEqual(PRUNE.RUNNER_FOLDER_BY_NAME,
                         {runner: Path(tmpdir).parent.name for runner, tmpdir in LIVE_RUNNER_TABLE})
        self.assertEqual(PRUNE.RUNNER_NAME_ENV, "RUNNER_NAME")

    def test_high3_a_folder_that_matches_no_layout_is_not_cleared_and_exits_non_zero(self):
        self.layouts_here()
        for folder in NOT_A_RUNNER_FOLDER:
            with self.subTest(folder=folder):
                leaf = self.leaf(folder)
                victim = self.make_file("old.db", 0, leaf)
                rc, out, err = self.run_prune(leaf, "--mode", "job-end", env_extra={"RUNNER_NAME": "f1-macos-fed"})
                self.assert_not_cleared(rc, err, F1_LAYOUT_REFUSAL.format(path=leaf))
                self.assertEqual(out, "")
                self.assertTrue(victim.exists(), "a refusal deletes nothing")

    def test_m3_the_runner_name_binds_the_folder(self):
        self.layouts_here()
        leaf = self.leaf("fed3")
        victim = self.make_file("old.db", 0, leaf)
        rows = (({}, RUNNER_UNSET_REFUSAL.format(path=leaf)),
                ({"RUNNER_NAME": ""}, RUNNER_UNSET_REFUSAL.format(path=leaf)),
                ({"RUNNER_NAME": "f1-macos-fed-2"},
                 RUNNER_UNBOUND_REFUSAL.format(folder="fed3", runner="f1-macos-fed-2", path=leaf)),
                ({"RUNNER_NAME": "runner-x"}, RUNNER_UNBOUND_REFUSAL.format(folder="fed3", runner="runner-x", path=leaf)))
        for env, reason in rows:
            with self.subTest(env=env):
                rc, out, err = self.run_prune(leaf, "--mode", "job-end", env_extra=env)
                self.assert_not_cleared(rc, err, reason)
                self.assertTrue(victim.exists())

    def test_high3_a_refusal_at_job_start_stays_a_warning_with_exit_0(self):
        self.layouts_here()
        leaf = self.leaf("evil")
        rc, out, err = self.run_prune(leaf, "--mode", "job-start", env_extra={"RUNNER_NAME": "f1-macos-fed"})
        reason = F1_LAYOUT_REFUSAL.format(path=leaf)
        self.assertEqual((rc, err), (EXIT_OK, f"prune_runner_tmp: refused: {reason}\n"))
        self.assertEqual(self.annotations, [WARNING_REFUSED + reason])

    def test_high1_a_missing_shared_module_at_job_end_exits_non_zero(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(PRUNE, "wa", None):
            rc = PRUNE.main(["--mode", "job-end"], environ={}, out=out, err=err)
            rc_start = PRUNE.main([], environ={}, out=io.StringIO(), err=io.StringIO())
        self.assertEqual((rc, rc_start), (EXIT_NOT_CLEARED, EXIT_OK))
        self.assertTrue(out.getvalue().startswith("::error title=prune_runner_tmp refused::"), out.getvalue())

    def test_low1_a_folder_renamed_between_resolve_and_open_is_refused(self):
        self.layouts_here()
        leaf = self.leaf("fed")
        victim = self.make_file("old.db", 0, leaf)
        self.leaf("other")
        real_open, swapped = os.open, []

        def swapping_open(name, *args, **kwargs):
            if name == ".." and not swapped:
                swapped.append(True)
                os.rename(self.root / "fed", self.root / "moved")
                os.rename(self.root / "other", self.root / "fed")
            return real_open(name, *args, **kwargs)

        with mock.patch.object(PRUNE.os, "open", swapping_open):
            rc, out, err = self.run_prune(leaf, "--mode", "job-end", env_extra={"RUNNER_NAME": "f1-macos-fed"})
        self.assert_not_cleared(rc, err, F1_LAYOUT_REFUSAL.format(path=leaf))
        self.assertTrue((self.root / "moved" / "_tmp" / victim.name).exists())

    def test_medium4_a_runner_folder_tmp_that_holds_the_workspace_is_refused(self):
        self.layouts_here()
        leaf = self.leaf("fed")
        workspace = leaf / "ws"
        workspace.mkdir()
        rc, out, err = self.run_prune(leaf, "--mode", "job-end",
                                      env_extra={"RUNNER_NAME": "f1-macos-fed", "GITHUB_WORKSPACE": str(workspace)})
        self.assert_not_cleared(rc, err, CONTAINS_REFUSAL.format(path=leaf))
        self.assertTrue(workspace.exists())

    def test_medium4_a_runner_folder_tmp_on_another_device_than_its_root_is_refused(self):
        self.layouts_here()
        leaf = self.leaf("fed")
        victim = self.make_file("old.db", 0, leaf)
        leaf_info = os.lstat(leaf)
        leaf_ident = (leaf_info.st_dev, leaf_info.st_ino)
        real_fstat, real_lstat = os.fstat, os.lstat

        def shifted(info):
            if (info.st_dev, info.st_ino) != leaf_ident:
                return info
            values = list(info)
            values[stat.ST_DEV] = info.st_dev + 1
            return os.stat_result(values)

        with mock.patch.object(PRUNE.os, "fstat", lambda fd: shifted(real_fstat(fd))), \
                mock.patch.object(PRUNE.os, "lstat", lambda path, **kw: shifted(real_lstat(path, **kw))):
            rc, out, err = self.run_prune(leaf, "--mode", "job-end", env_extra={"RUNNER_NAME": "f1-macos-fed"})
        self.assert_not_cleared(rc, err, MOUNT_DIFFERS_REASON.format(path=leaf))
        self.assertTrue(victim.exists())

    def test_a_tmp_folder_under_a_root_that_is_not_a_layout_root_is_refused(self):
        elsewhere = self.base / "elsewhere" / "fed" / PRUNE.RUNNER_FOLDER_LEAF
        elsewhere.mkdir(parents=True)
        victim = self.make_file("old.db", 0, elsewhere)
        self.layouts_here()
        rc, out, err = self.run_prune(elsewhere, "--mode", "job-end", env_extra={"RUNNER_NAME": "f1-macos-fed"})
        self.assert_not_cleared(rc, err, F1_LAYOUT_REFUSAL.format(path=elsewhere))
        self.assertTrue(victim.exists())

    def test_n3_docs_name_the_one_runner_folder_root_the_code_allows(self):
        """#9876 N3: the docs name F1_VOLUME_RUNNER_ROOT as the one runner-folder layout root, as the code holds."""
        self.assertEqual([root for root, _folder in PRUNE.RUNNER_FOLDER_LAYOUTS], [PRUNE.F1_VOLUME_RUNNER_ROOT])
        text = " ".join((ROOT / "docs/DEV-CI-ENVIRONMENT.md").read_text().split())
        self.assertIn("`<runner folder>/_tmp` under the volume runner root named by `F1_VOLUME_RUNNER_ROOT`", text)
        self.assertIn("the one runner-folder layout in `RUNNER_FOLDER_LAYOUTS`", text)
        self.assertNotIn("shared home runner root", text)

    def test_l2_the_facts_line_names_the_layout_root_of_a_runner_folder_tmp(self):
        self.layouts_here()
        leaf = self.leaf("fed2")
        line = PRUNE.print_runner_facts(str(leaf), (), io.StringIO())
        self.assertIn(f" allowed_root={self.root} ", line)

    def test_high2_docs_state_the_job_boundary_clear_without_a_home_prefix(self):
        text = (ROOT / "docs/DEV-CI-ENVIRONMENT.md").read_text()
        for needle in ("--mode job-end", "JOB_START_GRACE_SECS", "never to polling for an idle runner", "append-only",
                       "F1_VOLUME_RUNNER_ROOT", "RUNNER_FOLDER_BY_NAME", "exits 3",
                       "No workflow invokes `--mode job-end` yet", "#9876", "#9875"):
            self.assertIn(needle, text)
        self.assertNotIn("/Users/", text)


def action_run_line():
    match = re.search(r"(?m)^\s+run: (.+)$", (ROOT / ACTION_PATH).read_text())
    return match.group(1)


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

    def test_the_wired_step_runs_job_start_and_a_refusal_does_not_fail_the_job(self):
        """PR 9822 lands the job-end mode unwired (#9876, #9875): the one wired step passes no --mode.

        Its own run: line runs under bash, as the runner does, on a TMPDIR that must be refused: the default
        mode is job-start, so the refusal is a ::warning with exit 0 and nothing is deleted.
        """
        self.assertNotIn("--mode", action_run_line())
        base = Path(tempfile.mkdtemp(dir=SCRATCH_BASE))
        self.addCleanup(shutil.rmtree, base)
        bindir = base / "bin"
        bindir.mkdir()
        (bindir / "python3").symlink_to(sys.executable)
        scratch = base / "not-a-runner"
        scratch.mkdir()
        (scratch / "keep.db").write_bytes(b"k")
        env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(base), "TMPDIR": str(scratch),
               "GITHUB_ACTION_PATH": str(ROOT / ".github/actions/prune-runner-tmp")}
        done = subprocess.run(["bash", "-c", action_run_line()], env=env, capture_output=True, text=True,
                              timeout=60, check=False)
        self.assertEqual(done.returncode, EXIT_OK, done.stderr)
        self.assertIn("::warning title=prune_runner_tmp refused::", done.stdout)
        self.assertNotIn("::error", done.stdout)
        self.assertTrue((scratch / "keep.db").exists())


if __name__ == "__main__":
    unittest.main()
