#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#5657 - a leftover append-only audit.log must not poison the next CI job.

Run: python3 scripts/test/test_clear_append_only_scratch_5657.py

The janitor's contract has two halves that pull against each other, and this
file pins BOTH at once (#5747 round 2):

* a permission problem on an UNFLAGGED leftover must not red a leg that
  `actions/checkout` would have cleaned by itself - the janitor chmods its way
  in and puts the mode back; and
* a flag that is still set when the janitor finishes must be reported and must
  exit non-zero - "0 cleared, 0 failed" while a flag survives is the worst
  possible outcome, because it hands a poisoned runner to the next job with a
  green tick.

The script runs as the UNPRIVILEGED runner user in CI. These tests run it
unprivileged too, with one exception: on Linux, clearing `chattr +a` needs
CAP_LINUX_IMMUTABLE, so the tests that need a flag actually CLEARED run it under
`sudo -n` there (`run_clear(..., privileged=True)`); on macOS/BSD the owner may
clear `uappnd` and those tests run it unprivileged like every other. Setting,
reading and clearing an inode flag are the only other things that escalate
(`chattr`/`lsattr` on Linux); no fixture is created, widened or removed with
privilege (#6003). When a mechanism is unavailable the test that needs it SKIPS
with a message; the workflow pin tests always run.

The workflow pins parse the YAML and evaluate the step `if:` expressions with a
small GitHub-expression evaluator, so a guard that is rewritten to skip the step
is caught by meaning rather than by string match. `PyYAML` is required for those
(it ships on the GitHub `ubuntu-latest` image and on both fleet nodes); its
absence FAILS those tests rather than skipping them.
"""
import ast
import atexit
import contextlib
import errno
import fcntl
import importlib.util
import io
import itertools
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "clear-append-only-scratch.py"
WF_DIR = ROOT / ".github" / "workflows"
WORKFLOWS = [WF_DIR / "ci.yml", WF_DIR / "session-boot-lifetime.yml"]
CLEAR_STEP = "Clear stale append-only scratch (#5657)"
SELFTEST_REL = "scripts/test/test_clear_append_only_scratch_5657.py"
CHECKOUT_PREFIX = "actions/checkout@"
CLASSIFY_JOB = "classify"
IS_BSD = hasattr(os, "lchflags")


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------
def _priv():
    return [] if os.geteuid() == 0 else ["sudo", "-n"]


def _sudo_available():
    if os.geteuid() == 0:
        return True
    return subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0


def set_flag(path, immutable=False):
    """Set append-only (or immutable) on path; SkipTest when impossible."""
    if IS_BSD:
        bit = stat.UF_IMMUTABLE if immutable else stat.UF_APPEND
        os.lchflags(str(path), os.lstat(str(path)).st_flags | bit)
        return
    r = subprocess.run(_priv() + ["chattr", "+i" if immutable else "+a", str(path)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise unittest.SkipTest("cannot set an inode flag on this host: %s" % r.stderr.strip())


def drop_flags(path):
    """Test-teardown only: always clear the flags so the scratch dir can go."""
    if IS_BSD:
        os.lchflags(str(path), 0)
    else:
        subprocess.run(_priv() + ["chattr", "-a", "-i", str(path)], capture_output=True)


def is_flagged(path):
    """True when an append-only / immutable flag is still set on path."""
    if IS_BSD:
        return bool(os.lstat(str(path)).st_flags & (stat.UF_APPEND | stat.UF_IMMUTABLE))
    r = subprocess.run(_priv() + ["lsattr", "-d", str(path)], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        raise unittest.SkipTest("cannot read inode flags on this host: %s" % r.stderr.strip())
    return any(c in r.stdout.split()[0] for c in "ai")


# --------------------------------------------------------------------------
# fixture containment (#5814): nothing this file creates may outlive it
# --------------------------------------------------------------------------
# A cancelled CI run does not unwind `addCleanup`. A fixture that is left at
# mode 0o444 or 0o000 with anything inside it survives `git clean -ffdx` (git
# cannot read the directory to empty it, and exits 1), so ONE cancellation
# wedges the very runner this suite exists to unblock. Every mode this file
# changes is therefore held by a context manager AND registered here, and the
# registry is drained on the way out however the process leaves - normal exit,
# SIGINT, SIGTERM, SIGHUP.
_LEAKED_MODES = []
_LEAKED_FLAGS = []


def _drain_leaked_fixtures():
    while _LEAKED_FLAGS:
        path = _LEAKED_FLAGS.pop()
        try:
            drop_flags(path)
        except Exception:  # a reaper never raises: it is the last thing to run
            pass
    while _LEAKED_MODES:
        path, mode = _LEAKED_MODES.pop()
        try:
            if not os.path.islink(path):
                os.chmod(path, mode)
        except OSError:
            _UNRESTORED.append(path)


def _install_fixture_reaper():
    # `atexit` runs last-registered first: drain, THEN forget the journal.
    atexit.register(lambda: _forget_fixture_modes())
    atexit.register(_drain_leaked_fixtures)
    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        number = getattr(signal, name, None)
        if number is None:
            continue
        previous = signal.getsignal(number)

        def handler(signum, frame, _previous=previous):
            _drain_leaked_fixtures()
            if callable(_previous):
                return _previous(signum, frame)
            raise SystemExit(128 + signum)

        try:
            signal.signal(number, handler)
        except (ValueError, OSError):  # not the main thread: atexit still holds
            pass


_install_fixture_reaper()


# A `SIGKILL` runs no handler and no `atexit`, so the reaper above cannot see
# it: a fixture held narrowed at that instant stays narrowed, and a narrowed
# directory is one `git clean -ffdx` cannot empty (#6024). Every mode
# `restrictive()` narrows is therefore also written down first - appended and
# fsynced before the chmod, the shape of the janitor's own #6006 journal - in a
# per-process file this process holds an exclusive `flock` on for its whole
# life. The kernel drops that lock with the process however it ends, so a
# journal nobody holds belongs to a process that is gone, and the next suite
# start (`setUpModule`) puts its modes back, newest first, and removes the
# `.ws5657-*` workspaces it names. Only paths inside one of this suite's own
# workspaces are ever touched, and never through a symlink.
_MODE_JOURNAL_PREFIX = ".fixture5657-modes-"
_HEALABLE_PREFIXES = (".ws5657-", ".cancel5657-")
_MODE_JOURNAL = []  # [fd, path] once this process has narrowed anything
_UNRESTORED = []


def _record_fixture_mode(path, before):
    """Append `path`'s mode before it is narrowed, durably, to this process's
    fixture journal (#6024)."""
    if not _MODE_JOURNAL:
        base = ROOT / ".local-runs"
        base.mkdir(exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=_MODE_JOURNAL_PREFIX, dir=str(base))
        fcntl.flock(fd, fcntl.LOCK_EX)
        _MODE_JOURNAL.extend([fd, name])
    os.write(_MODE_JOURNAL[0], ("%o %s\n" % (before, os.fsencode(path).hex())).encode("ascii"))
    os.fsync(_MODE_JOURNAL[0])


def _forget_fixture_modes():
    """On a clean exit, after the reaper has drained: every mode is back, so
    the journal says nothing the next suite start needs."""
    if not _MODE_JOURNAL or _UNRESTORED or _LEAKED_MODES:
        return
    fd, name = _MODE_JOURNAL
    with contextlib.suppress(OSError):
        os.unlink(name)
    with contextlib.suppress(OSError):
        os.close(fd)
    del _MODE_JOURNAL[:]


def _healable_workspace(real_base, path):
    """The suite workspace `path` lies in, resolved without trusting any
    symlink on the way, or None when it is not inside one."""
    full = os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))
    rel = os.path.relpath(full, real_base)
    first = rel.split(os.sep)[0]
    if rel.startswith("..") or os.path.isabs(rel) or not first.startswith(_HEALABLE_PREFIXES):
        return None
    return os.path.join(real_base, first)


def _heal_stranded_fixtures(base=None):
    """Put back every fixture mode a killed suite process left narrowed, and
    remove the `.ws5657-*` workspaces it held (#6024). Returns `(healed
    workspaces, problems)`. A journal some live process still holds is not
    touched, and one with anything it could not heal is kept."""
    base = Path(base) if base is not None else ROOT / ".local-runs"
    real_base = os.path.realpath(str(base))
    healed, problems = [], []
    for journal in sorted(base.glob(_MODE_JOURNAL_PREFIX + "*")):
        try:
            fd = os.open(str(journal), os.O_RDWR | os.O_NOFOLLOW)
        except OSError as err:
            problems.append("%s: %s" % (journal, err))
            continue
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                continue  # a live suite process holds it
            raw = b""
            while True:
                chunk = os.read(fd, 1 << 16)
                if not chunk:
                    break
                raw += chunk
            # A line that never became whole was cut by the kill before the
            # chmod it describes, which therefore never happened.
            lines = raw.split(b"\n")[:-1]
            kept, workspaces = False, []
            for line in reversed(lines):
                try:
                    text, hexpath = line.decode("ascii").split(" ")
                    mode, path = int(text, 8), os.fsdecode(bytes.fromhex(hexpath))
                except ValueError:
                    problems.append("%s: unreadable line %r" % (journal, line))
                    kept = True
                    continue
                ws = _healable_workspace(real_base, path)
                if ws is None:
                    problems.append("%s: %s is not inside a suite workspace; left as it is" % (journal, path))
                    kept = True
                    continue
                if os.path.basename(ws).startswith(".ws5657-") and ws not in workspaces:
                    workspaces.append(ws)
                if os.path.islink(path) or not os.path.lexists(path):
                    continue
                try:
                    os.chmod(path, mode)
                except OSError as err:
                    problems.append("%s: %s" % (path, err))
                    kept = True
            for ws in workspaces:
                if not os.path.lexists(ws):
                    continue
                subprocess.run(["chmod", "-R", "u+rwX", ws], capture_output=True)
                shutil.rmtree(ws, ignore_errors=True)
                if os.path.lexists(ws):
                    problems.append("%s: could not be removed" % ws)
                    kept = True
                else:
                    healed.append(ws)
            if not kept:
                os.unlink(str(journal))
        finally:
            os.close(fd)
    return healed, problems


def setUpModule():
    _healed, problems = _heal_stranded_fixtures()
    for problem in problems:
        print("::warning::selftest5657: a fixture an earlier killed run stranded is not healed: %s"
              % problem, file=sys.stderr)


@contextlib.contextmanager
def restrictive(path, mode):
    """Hold `path` at `mode` for the body only, and put the old mode back
    however the body ends - including a signal (#5814). The restore skips a
    symlink, because a test that swaps an entry mid-race must not have its
    cleanup chmod the swap target."""
    path = str(path)
    before = stat.S_IMODE(os.lstat(path).st_mode)
    entry = (path, before)
    _LEAKED_MODES.append(entry)
    _record_fixture_mode(path, before)
    os.chmod(path, mode)
    try:
        yield path
    finally:
        try:
            if not os.path.islink(path):
                os.chmod(path, before)
        except OSError:
            _UNRESTORED.append(path)
        with contextlib.suppress(ValueError):
            _LEAKED_MODES.remove(entry)


@contextlib.contextmanager
def flagged(path, immutable=False):
    """Set an inode flag for the body only. A leftover flag is the #5657
    defect itself, so the fixture that models it is never left behind."""
    path = str(path)
    set_flag(path, immutable=immutable)
    _LEAKED_FLAGS.append(path)
    try:
        yield path
    finally:
        try:
            drop_flags(path)
        except Exception:
            pass
        with contextlib.suppress(ValueError):
            _LEAKED_FLAGS.remove(path)


def load_script_module():
    """Import the janitor as a module so a single platform seam can be made to
    fail. A subprocess cannot be given an unreadable flag state on demand."""
    spec = importlib.util.spec_from_file_location("clear_append_only_scratch_5657", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_clear(root, privileged=False):
    """Run the janitor. Unprivileged by default: that is how CI runs it."""
    cmd = ([] if (IS_BSD or not privileged) else _priv()) + [sys.executable, str(SCRIPT), "--root", str(root)]
    return subprocess.run(cmd, capture_output=True, text=True)


def run_clear_in_process(mod, root):
    """Run the janitor inside this process, so a seam can be held open across
    it. Returns `(rc, stdout, stderr)`."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = mod.main(["--root", str(root)])
    return rc, out.getvalue(), err.getvalue()


# Run the janitor and have it killed the instant a mode it widened is on disk.
# The seam is `os.fchmod`, which is where BOTH the pre-#6006 descent-wide widen
# and the per-lookup `Search` widen land, so the same child reaches the same
# window on either revision - the difference is what the NEXT run does about it.
# `SIGKILL` is sent from inside the process because no handler, no `finally` and
# no `atexit` may run: that is the whole of what this reproduces.
_KILLED_MID_WIDEN = (
    "import importlib.util as u, os, signal, stat, sys\n"
    "spec = u.spec_from_file_location('selftest5657', sys.argv[1])\n"
    "mod = u.module_from_spec(spec)\n"
    "spec.loader.exec_module(mod)\n"
    "script = mod.load_script_module()\n"
    "real, fired = script.os.fchmod, []\n"
    "def fchmod(fd, mode):\n"
    "    real(fd, mode)\n"
    "    if not fired:\n"
    "        fired.append(mode)\n"
    "        print('WIDENED 0o%03o' % stat.S_IMODE(os.lstat(sys.argv[3]).st_mode), flush=True)\n"
    "        os.kill(os.getpid(), signal.SIGKILL)\n"
    "script.os.fchmod = fchmod\n"
    "sys.exit(script.main(['--root', sys.argv[2]]))\n"
)


@contextlib.contextmanager
def foreign_euid(mod):
    """Make every inode in the tree look like somebody else's WITHOUT creating
    one (#5814). `Cleaner._ownable` compares `st_uid` against `os.geteuid()`;
    moving the EUID it compares against is indistinguishable from moving the
    owner, the kernel's real EACCES still drives the branch, and no root-owned
    fixture is left inside the runner workspace for a cancelled run to strand."""
    if os.geteuid() == 0:
        raise unittest.SkipTest("running as root: every inode is ownable")
    with mock.patch.object(mod.os, "geteuid", return_value=os.geteuid() + 1):
        yield


@contextlib.contextmanager
def swap_when_inspected(mod, inode, swap):
    """Replace an entry at the instant the janitor decides it may widen it.

    `Cleaner._ownable` is the last call before BOTH widen sites, so a swap
    performed from here lands inside the window the janitor has to be immune
    to. Yields a list that stays empty if the window was never reached, so a
    test cannot pass by never racing anything."""
    original = mod.Cleaner._ownable
    fired = []

    def ownable(st):
        answer = original(st)
        if st.st_ino == inode and not fired:
            fired.append(True)
            swap()
        return answer

    mod.Cleaner._ownable = staticmethod(ownable)
    try:
        yield fired
    finally:
        mod.Cleaner._ownable = staticmethod(original)


@contextlib.contextmanager
def swap_after_the_widen(mod, swap):
    """Replace an entry the instant a widening chmod has landed and before the
    janitor reopens the name. A widen by name and a widen through a pinned
    descriptor both go through `os.chmod`, so this seam reaches the same
    window either way - and what the two do afterwards is the whole of #5812."""
    real = mod.os.chmod
    fired = []

    def chmod(*args, **kwargs):
        real(*args, **kwargs)
        if not fired:
            fired.append(True)
            swap()

    mod.os.chmod = chmod
    try:
        yield fired
    finally:
        mod.os.chmod = real


@contextlib.contextmanager
def swap_before_the_open(mod, name, swap):
    """Replace an entry between the `lstat` that classified it and the `open`
    that acts on it (#5995).

    `_walk` takes ONE `lstat` per entry and hands that struct down through
    `_visit` to `_open_at`; file-or-directory, widen-or-not and which-mode-to-
    put-back are all decided from it. Swapping from inside the `open` call
    itself is that window exactly, with no timing assumption anywhere. Yields a
    list that stays empty if the window was never reached, so a test cannot
    pass by never racing anything."""
    real = mod.os.open
    fired = []

    def opener(path, *args, **kwargs):
        if path == name and not fired:
            fired.append(True)
            swap()
        return real(path, *args, **kwargs)

    mod.os.open = opener
    try:
        yield fired
    finally:
        mod.os.open = real


@contextlib.contextmanager
def restore_that_fails(mod, nth=2):
    """Break the Nth `os.fchmod` of a run with EPERM (#6002).

    On the path this seam is used with - a directory readable but not searchable
    - `os.fchmod` is called exactly twice: once to widen, once to put the mode
    back after the descent. Breaking the second one is the restore failing, with
    no timing assumption and no patched filesystem. Yields the modes it saw, so
    a test cannot pass by never reaching the restore at all."""
    real = mod.os.fchmod
    calls = []

    def fchmod(fd, mode):
        calls.append(mode)
        if len(calls) == nth:
            raise OSError(errno.EPERM, "the restore was refused")
        return real(fd, mode)

    mod.os.fchmod = fchmod
    try:
        yield calls
    finally:
        mod.os.fchmod = real


class ScratchTree(unittest.TestCase):
    """Every case gets `<repo>/.local-runs/.ws5657-*/` as a fake workspace whose
    own `.local-runs/.tmpAbC123/audit/audit.log` is the poisoned leftover."""

    def setUp(self):
        base = ROOT / ".local-runs"
        base.mkdir(exist_ok=True)
        self.ws = Path(tempfile.mkdtemp(prefix=".ws5657-", dir=base))
        self.scratch = self.ws / ".local-runs"
        self.audit = self.scratch / ".tmpAbC123" / "audit"
        self.audit.mkdir(parents=True)
        self.log = self.audit / "audit.log"
        self.log.write_text("{}\n")
        self.addCleanup(self._teardown)

    def tearDown(self):
        """The property #5814 is actually about: when a test RETURNS, its
        workspace must already be removable by an ordinary `git clean -ffdx`.

        `tearDown` runs BEFORE the `addCleanup` repair, so a test that only
        survives because of that repair fails here - which is the same test a
        cancelled run would have failed by wedging the runner, except that
        this way somebody finds out. A directory that is not readable,
        writable and searchable by its owner cannot be emptied, and `git clean`
        exits 1 and leaves the whole tree behind; an unreadable FILE is
        harmless, because unlinking it only needs the parent's bits."""
        stranded = []

        def note(err):
            stranded.append("%s: %s" % (err.filename, err.strerror))

        need = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
        for root, dirnames, _files in os.walk(str(self.ws), onerror=note):
            for name in [""] + list(dirnames):
                full = os.path.join(root, name) if name else root
                if os.path.islink(full):
                    continue
                try:
                    mode = stat.S_IMODE(os.lstat(full).st_mode)
                except OSError as err:
                    stranded.append("%s: %s" % (full, err.strerror))
                    continue
                if mode & need != need:
                    stranded.append("%s is a directory at mode 0o%03o" % (full, mode))
        self.assertFalse(stranded,
                         "the test left behind a fixture a cancelled run could not clean up "
                         "(#5814): " + "; ".join(sorted(set(stranded))))
        self.assertFalse(_LEAKED_MODES, "a mode change outlived the test that made it: %r" % (_LEAKED_MODES,))
        self.assertFalse(_LEAKED_FLAGS, "an inode flag outlived the test that set it: %r" % (_LEAKED_FLAGS,))

    def _teardown(self):
        # Unprivileged, and `u+rwX` only (#6003): no fixture here is owned by
        # anyone but this process (#5814), so widening for group and other buys
        # nothing and, if the removal below never happens, leaves a world-
        # writable tree in a shared runner workspace. The flags come off first
        # - the one step that needs privilege, and only on Linux. On BSD a
        # symlink carries flags of its own and `drop_flags` uses `lchflags`,
        # which never follows it; Linux has no flags on a symlink.
        subprocess.run(["chmod", "-R", "u+rwX", str(self.ws)], capture_output=True)
        try:
            for path in self.ws.rglob("*"):
                if IS_BSD or not path.is_symlink():
                    drop_flags(path)
        except OSError:
            pass
        subprocess.run(["chmod", "-R", "u+rwX", str(self.ws)], capture_output=True)
        shutil.rmtree(self.ws, ignore_errors=True)

    # -- the defect itself -------------------------------------------------


class ScratchTreeCase(ScratchTree):
    """The walk: what it clears, what it refuses, and what it reports."""

    def test_flagged_leftover_blocks_removal_then_clear_makes_it_removable_5657(self):
        set_flag(self.log)
        with self.assertRaises(PermissionError):  # the macOS leg's EPERM on unlink
            shutil.rmtree(self.scratch)
        self.assertTrue(self.log.exists(), "flagged file must survive a failed clean")
        r = run_clear(self.ws, privileged=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("cleared append-only", r.stdout)
        self.assertIn("1 cleared, 0 failed", r.stdout)
        shutil.rmtree(self.scratch)
        self.assertFalse(self.scratch.exists())

    def test_clear_is_idempotent_5657(self):
        set_flag(self.log)
        for _ in range(2):
            r = run_clear(self.ws, privileged=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 cleared, 0 failed", run_clear(self.ws).stdout)

    def test_unflagged_and_missing_tree_are_noops_5657(self):
        r = run_clear(self.ws)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 cleared, 0 failed", r.stdout)
        shutil.rmtree(self.scratch)
        r = run_clear(self.ws)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("nothing to do", r.stdout)

    # -- CODE-F1: a permission problem is not a verdict --------------------
    def test_unflagged_unreadable_leftover_is_not_a_failure_5657(self):
        """mode-000 / mode-0200 / unreadable-dir leftovers carry NO flag, so
        `actions/checkout` would delete them unaided. The janitor must widen,
        look, put the mode back, and exit 0."""
        zero = self.audit / "unreadable.key"
        zero.write_text("k")
        wo = self.audit / "writeonly.log"
        wo.write_text("w")
        shut = self.scratch / ".tmpShut"
        shut.mkdir()
        (shut / "inner.log").write_text("{}\n")
        with restrictive(zero, 0o000), restrictive(wo, 0o200), restrictive(shut, 0o000):
            r = run_clear(self.ws)
            self.assertEqual(r.returncode, 0,
                             "an unflagged leftover must not red the leg:\n" + r.stdout + r.stderr)
            self.assertIn("0 cleared, 0 failed", r.stdout)
            self.assertEqual(stat.S_IMODE(os.lstat(zero).st_mode), 0o000, "original mode must be restored")
            self.assertEqual(stat.S_IMODE(os.lstat(wo).st_mode), 0o200, "original mode must be restored")
            self.assertEqual(stat.S_IMODE(os.lstat(shut).st_mode), 0o000, "original mode must be restored")

    def test_unsearchable_directory_is_widened_not_reported_5657(self):
        """mode-0400 opens but cannot be stat'ed through: the janitor owns it,
        so it widens on the descriptor instead of calling it a failure."""
        d = self.scratch / ".tmpR"
        d.mkdir()
        (d / "inner.log").write_text("{}\n")
        with restrictive(d, 0o400):
            r = run_clear(self.ws)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("0 cleared, 0 failed", r.stdout)
            self.assertEqual(stat.S_IMODE(os.lstat(d).st_mode), 0o400, "original mode must be restored")

    # -- SEC-F1: a surviving flag is never reported as success -------------
    def test_flagged_file_under_unreadable_directory_is_not_silently_skipped_5657(self):
        """The round-1 script walked with `os.walk` and no `onerror`, so this
        tree printed `0 cleared, 0 failed`, exited 0, and left the flag set."""
        with flagged(self.log):
            with restrictive(self.audit, 0o000):
                r = run_clear(self.ws)
            still = is_flagged(self.log)
        self.assertFalse(r.returncode == 0 and still,
                         "reported success while the flag survived:\n" + r.stdout + r.stderr)
        self.assertFalse("0 cleared, 0 failed" in r.stdout and still,
                         "counted a surviving flag as nothing to do:\n" + r.stdout + r.stderr)
        if still:
            self.assertIn("::error::", r.stderr)
            self.assertIn(str(self.log), r.stderr)

    def test_immutable_leftover_fails_closed_5657(self):
        """`uchg` / `chattr +i` is not a flag ai-memory sets, so the janitor
        never removes it - but it DOES block unlink, so it must exit 1 and name
        the path. Run WITH privilege so the refusal is policy, not permission."""
        imm = self.audit / "locked.log"
        imm.write_text("{}\n")
        set_flag(imm, immutable=True)
        r = run_clear(self.ws, privileged=True)
        self.assertNotEqual(r.returncode, 0, "an immutable leftover must red the leg:\n" + r.stdout + r.stderr)
        self.assertIn("::error::", r.stderr)
        self.assertIn(str(imm), r.stderr)
        self.assertIn("0 cleared, 1 failed", r.stdout)
        self.assertIn("still un-unlinkable after the clear", r.stderr,
                      "the verdict must come from a POST-clear re-read of the descriptor")
        self.assertTrue(is_flagged(imm), "the janitor must not strip an immutable flag")

    def test_append_plus_immutable_reports_the_surviving_flag_5657(self):
        """The append bit comes off, the immutable bit does not: the post-clear
        re-read is what turns a half-success into an honest failure."""
        both = self.audit / "both.log"
        both.write_text("{}\n")
        set_flag(both)
        set_flag(both, immutable=True)
        r = run_clear(self.ws, privileged=True)
        self.assertNotEqual(r.returncode, 0, "a surviving immutable bit must red the leg:\n" + r.stdout + r.stderr)
        self.assertIn("::error::", r.stderr)
        self.assertIn(str(both), r.stderr)
        self.assertTrue(is_flagged(both))
        if IS_BSD:
            # Linux refuses FS_IOC_SETFLAGS outright on an immutable inode, so
            # there the failure is the EPERM; on BSD the append bit does come
            # off and only the POST-clear re-read notices the leftover.
            self.assertIn("still un-unlinkable after the clear", r.stderr)

    def test_hardlinked_flagged_file_is_refused_5657(self):
        """A second link outside the scratch tree means clearing the flag here
        also unprotects an inode the janitor was never pointed at."""
        outside = self.ws / "second-link.log"
        os.link(str(self.log), str(outside))
        set_flag(self.log)
        r = run_clear(self.ws, privileged=True)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("links", r.stderr)
        self.assertIn(str(self.log), r.stderr)
        self.assertTrue(is_flagged(outside), "the out-of-tree link must stay protected")

    # -- SEC-F2 / SEC-F4: containment --------------------------------------
    def test_flag_outside_scratch_tree_is_never_touched_5657(self):
        live = self.ws / "audit.log"  # a LIVE log: not under .local-runs
        live.write_text("{}\n")
        set_flag(live)
        r = run_clear(self.ws, privileged=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(is_flagged(live), "the forensic control on a live log must be intact")

    def test_symlinked_scratch_root_is_refused_5657(self):
        """`.local-runs` itself a symlink = somebody redirected the scratch.
        The janitor refuses the tree outright instead of operating through it."""
        elsewhere = self.ws / "elsewhere"
        elsewhere.mkdir()
        victim = elsewhere / "audit.log"
        victim.write_text("{}\n")
        set_flag(victim)
        shutil.rmtree(self.scratch)
        self.scratch.symlink_to(elsewhere, target_is_directory=True)
        r = run_clear(self.ws, privileged=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("nothing to do", r.stdout)
        self.assertTrue(is_flagged(victim), "nothing beyond the symlink may be touched")

    def test_symlinked_subdirectory_is_not_descended_5657(self):
        elsewhere = self.ws / "elsewhere"
        elsewhere.mkdir()
        victim = elsewhere / "audit.log"
        victim.write_text("{}\n")
        set_flag(victim)
        (self.scratch / "link").symlink_to(elsewhere, target_is_directory=True)
        r = run_clear(self.ws, privileged=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 cleared, 0 failed", r.stdout)
        self.assertTrue(is_flagged(victim), "a symlinked subdirectory must not be descended")

    @unittest.skipUnless(IS_BSD, "only BSD/macOS can flag the symlink itself")
    def test_flagged_symlink_is_reported_not_cleared_5657(self):
        """A flagged symlink blocks unlink too, and a clear would have to go
        back through a path - so it is reported, never cleared."""
        link = self.scratch / "link.log"
        link.symlink_to(self.log)
        os.lchflags(str(link), os.lstat(str(link)).st_flags | stat.UF_APPEND)
        r = run_clear(self.ws)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("never", r.stderr)
        self.assertIn(str(link), r.stderr)
        self.assertTrue(bool(os.lstat(str(link)).st_flags & stat.UF_APPEND))

    # -- ownership: "I could not tell" is a failure, not a pass ------------
    def test_an_unreadable_flag_state_is_a_failure_not_an_absence_5657(self):
        """A GET that fails for a reason OTHER than "this filesystem has no
        flags" must not be read as "no flag here": that is the #5747 SEC-F1
        silent skip, and it exits 0 with the flag still set."""
        mod = load_script_module()

        def unreadable(fd):
            # Directories read normally, so the walk reaches the leftover and
            # the verdict is about the LEAF, not an abort at the scratch root.
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                return 0
            raise OSError(errno.EIO, "injected: the flag state cannot be read")

        mod._raw_flags = unreadable
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mod.main(["--root", str(self.ws)])
        self.assertNotEqual(rc, 0, "an unreadable flag state is not a pass:\n" + out.getvalue() + err.getvalue())
        self.assertIn("::error::", err.getvalue())
        self.assertIn(str(self.log), err.getvalue())
        self.assertNotIn("0 cleared, 0 failed", out.getvalue())

    def test_a_flagless_filesystem_is_still_a_noop_5657(self):
        """The other half of the same seam: the NAMED no-flag-support errnos
        stay tolerated, so this janitor does not red a tmpfs/overlay leg."""
        mod = load_script_module()
        tolerated = sorted(mod.NO_FLAG_SUPPORT)
        self.assertTrue(tolerated, "no errno is tolerated at all")

        def flagless(fd):
            raise OSError(tolerated[0], "injected: no inode-flag concept here")

        mod._raw_flags = flagless
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mod.main(["--root", str(self.ws)])
        self.assertEqual(rc, 0, out.getvalue() + err.getvalue())
        self.assertIn("0 cleared, 0 failed", out.getvalue())

    def test_foreign_owned_unreadable_directory_is_reported_5657(self):
        """An inode the janitor does not own cannot be widened, so an EACCES
        on it is reported rather than guessed at. The fixture moves the EUID
        instead of creating a root-owned directory: a root-owned mode-000
        directory inside the workspace is exactly what a cancelled run cannot
        clean up and `git clean -ffdx` cannot remove (#5814)."""
        mod = load_script_module()
        d = self.scratch / ".tmpForeign"
        d.mkdir()
        with restrictive(d, 0o000), foreign_euid(mod):
            rc, out, err = run_clear_in_process(mod, self.ws)
        self.assertNotEqual(rc, 0, "an inode we cannot inspect is not a pass:\n" + out + err)
        self.assertIn("not the owner", err)
        self.assertIn(str(d), err)

    def test_foreign_owned_unsearchable_directory_is_reported_5657(self):
        """Readable enough to list, not searchable enough to stat - and not
        ours to widen. The entry that cannot be stat'ed is named, because a
        flag on it cannot be ruled out."""
        mod = load_script_module()
        d = self.scratch / ".tmpForeignRO"
        d.mkdir()
        (d / "inner.log").write_text("{}\n")
        with restrictive(d, 0o444), foreign_euid(mod):
            rc, out, err = run_clear_in_process(mod, self.ws)
        self.assertNotEqual(rc, 0, "an entry we cannot stat is not a pass:\n" + out + err)
        self.assertIn("cannot be ruled out", err)
        self.assertIn(str(d / "inner.log"), err)

    # -- #5812 / #5813: the widen is the one mutation on an unproven entry --
    def test_a_widen_is_never_redirected_onto_another_inode_5657(self):
        """#5813. The entry is swapped for a symlink in the window between the
        EACCES and the widen. A widen that goes by NAME re-resolves it and
        lands on the symlink's target - an inode outside the scratch tree
        entirely - so the assertion is on THAT inode's mode. The exit code is
        1 either way, which is why it proves nothing here."""
        mod = load_script_module()
        victim = self.ws / "OUTSIDE-the-scratch-tree.key"
        victim.write_text("v")
        entry = self.audit / "unreadable.key"
        entry.write_text("k")
        with restrictive(victim, 0o000), restrictive(entry, 0o000):
            inode = os.lstat(entry).st_ino
            untouched = os.lstat(victim).st_ctime_ns

            def swap():
                os.unlink(entry)
                os.symlink(victim, entry)

            with swap_when_inspected(mod, inode, swap) as fired:
                run_clear_in_process(mod, self.ws)
            self.assertTrue(fired, "the seam never fired: the race window was never reached")
            self.assertEqual(stat.S_IMODE(os.lstat(victim).st_mode), 0o000,
                             "a widen was redirected onto an inode outside the scratch tree")
            # The end-state mode alone is not enough: a widen that is redirected
            # here and then RESTORED on the way out leaves the mode looking
            # untouched while an inode outside the tree was still mutated twice.
            # chmod bumps ctime, and a restore bumps it again, so ctime is what
            # actually says "nothing out here was touched".
            self.assertEqual(os.lstat(victim).st_ctime_ns, untouched,
                             "an inode outside the scratch tree was chmod'ed and then put back")

    def test_a_replaced_entry_is_refused_with_nothing_widened_5852(self):
        """#5852, the pre-chmod half of the bracket, and #5997. The entry is
        replaced by a different inode before the widen; the janitor must notice
        and refuse, and the inode that is left standing in the tree must not
        have been widened on the way out.

        The decoy's mode DIFFERS from the scanned entry's (#5997): a widen that
        lands on the decoy and is then "put back" leaves it at the SCANNED mode,
        which a decoy at the same mode would hide. Its ctime is read after the
        swap, so a widen that is put back to the very same mode is still seen."""
        mod = load_script_module()
        entry = self.audit / "unreadable.key"
        entry.write_text("k")
        # OUTSIDE the scratch tree, so the walk never visits the decoy itself
        # and the only entry that races is the one the test is about.
        decoy = self.ws / "decoy.key"
        decoy.write_text("d")
        seen = {}

        def swap():
            os.replace(str(decoy), str(entry))
            seen["ctime"] = os.lstat(entry).st_ctime_ns

        with restrictive(entry, 0o000), restrictive(decoy, 0o200):
            inode = os.lstat(entry).st_ino
            with swap_when_inspected(mod, inode, swap) as fired:
                rc, out, err = run_clear_in_process(mod, self.ws)
            self.assertTrue(fired, "the seam never fired: the race window was never reached")
            self.assertEqual(stat.S_IMODE(os.lstat(entry).st_mode), 0o200,
                             "the replacement inode was given the scanned entry's mode:\n" + out + err)
            self.assertEqual(os.lstat(entry).st_ctime_ns, seen["ctime"],
                             "the replacement inode was chmod'ed by a refusal:\n" + out + err)
            self.assertNotEqual(rc, 0, "a replaced entry is not a pass:\n" + out + err)

    def test_a_widened_mode_is_restored_or_reported_when_the_reopen_fails_5812(self):
        """#5812, the post-chmod half. The widen lands on the right inode,
        and only THEN is the name replaced, so the reopen fails.

        What happens next is not the same on both legs, and this test used to
        assert only the stronger half - which is why it was green where the
        inode can be pinned and red on the leg the issue exists to protect
        (#5812, #5852). Where the inode is pinned, the restore addresses the
        INODE and the mode comes back off it. Where it is not, the mode was
        reached by a name that now belongs to something else, and this platform
        offers no way to address an inode without a name: the mode is left
        applied, and the one thing the janitor can still do is SAY so. Both
        halves are pinned here, each on the leg it describes, because a widened
        mode left behind in silence is the #5657 defect itself and one reported
        with its path and its mode is recoverable by hand."""
        mod = load_script_module()
        entry = self.audit / "unreadable.key"
        entry.write_text("k")
        decoy = self.ws / "decoy.key"   # outside the scratch tree: never walked
        decoy.write_text("d")
        kept = self.ws / "kept-original.key"
        with restrictive(entry, 0o000), restrictive(decoy, 0o000):
            def swap():
                os.rename(entry, kept)
                os.replace(decoy, entry)

            with swap_after_the_widen(mod, swap) as fired:
                rc, out, err = run_clear_in_process(mod, self.ws)
            self.assertTrue(fired, "the seam never fired: nothing was ever widened")
        left = stat.S_IMODE(os.lstat(kept).st_mode)
        self.assertNotEqual(rc, 0, "a failed reopen is not a pass:\n" + out + err)
        if mod.HAS_O_PATH:
            self.assertEqual(left, 0o000,
                             "the widened mode was abandoned on the failure path")
        else:
            # The widened inode is unreachable: its only address was a name it
            # no longer has. Pinning the mode exactly is what makes a future
            # narrowing of this leg visible as a CHANGE rather than as drift.
            self.assertEqual(left, stat.S_IRUSR,
                             "the mode this leg leaves on the inode it widened is not the one "
                             "it was widened to, so neither half of this test describes it")
            self.assertIn("left applied", err,
                          "a widen this leg cannot undo must be reported, never abandoned "
                          "quietly:\n" + out + err)
            self.assertIn("0o%03o" % stat.S_IRUSR, err,
                          "the report must name the mode that was left applied:\n" + out + err)
            self.assertIn("unreadable.key", err,
                          "the report must name the entry it was left on:\n" + out + err)

    def test_an_unsearchable_directory_is_widened_through_its_own_descriptor_5657(self):
        """The mutant the first three reviews let through: widen by path
        instead of by fd. The directory is swapped for a symlink in the window
        between `_ownable` and the widen, so a by-name widen lands on the
        symlink's target outside the scratch tree, while a widen on the
        descriptor already held cannot move at all."""
        mod = load_script_module()
        victim = self.ws / "OUTSIDE-the-scratch-tree.key"
        victim.write_text("v")
        d = self.scratch / ".tmpR"
        d.mkdir()
        (d / "inner.log").write_text("{}\n")
        with restrictive(victim, 0o000), restrictive(d, 0o400):
            inode = os.lstat(d).st_ino

            def swap():
                os.chmod(d, 0o700)
                shutil.rmtree(d)
                os.symlink(victim, d)

            with swap_when_inspected(mod, inode, swap) as fired:
                run_clear_in_process(mod, self.ws)
            self.assertTrue(fired, "the seam never fired: the race window was never reached")
            self.assertEqual(stat.S_IMODE(os.lstat(victim).st_mode), 0o000,
                             "the widen was applied to a re-resolved name, not to the open descriptor")

    def test_a_swapped_entry_is_never_given_another_inodes_mode_5995(self):
        """#5995. The widen-and-reopen path proves its inode; the ORDINARY
        open - the common case, the one that needed no widen at all - did not.

        An entry replaced between the `lstat` that classified it and the `open`
        that acts on it is a different inode with a mode of its own, and every
        decision the walk then takes comes from a struct it no longer holds: it
        reads and clears that stranger's flags, descends into it, widens it to
        the SCANNED entry's mode and finally leaves it at the scanned entry's
        mode for good - and reports none of it. `rename` is the only swap a
        directory entry admits (`O_NOFOLLOW` already refuses a symlink and a
        directory cannot be hardlinked), so this is the whole of the reachable
        race for one."""
        mod = load_script_module()
        stranger = self.ws / "never-scanned.d"   # outside the scratch tree
        stranger.mkdir(mode=0o750)
        (stranger / "inner.log").write_text("{}\n")
        entry = self.scratch / ".tmpS"
        entry.mkdir()
        (entry / "inner.log").write_text("{}\n")
        moved = self.ws / "moved-away.d"
        seen = {}

        def swap():
            # A directory at 0o400 cannot be renamed at all (`rename(2)` needs
            # write on the source directory to update its `..`), and a
            # directory left at 0o400 is what wedges the next checkout
            # (#5814) - so the mode comes off before the move, which the walk
            # cannot see either way: it took its `lstat` before this ran.
            os.chmod(entry, 0o700)
            os.rename(entry, moved)
            os.rename(stranger, entry)
            # `rename` bumps the ctime itself, so the only honest baseline is
            # the one taken after the swap and before the janitor can act.
            seen["mode"] = stat.S_IMODE(os.lstat(entry).st_mode)
            seen["ctime"] = os.lstat(entry).st_ctime_ns

        with restrictive(entry, 0o400):
            with swap_before_the_open(mod, ".tmpS", swap) as fired:
                rc, out, err = run_clear_in_process(mod, self.ws)
            self.assertTrue(fired, "the seam never fired: the race window was never reached")
            self.assertEqual(seen.get("mode"), 0o750, "the swap itself did not land: %r" % (seen,))
            self.assertEqual(stat.S_IMODE(os.lstat(entry).st_mode), 0o750,
                             "an inode the walk never scanned was left at the scanned entry's mode")
            self.assertEqual(os.lstat(entry).st_ctime_ns, seen.get("ctime"),
                             "an inode the walk never scanned was chmod'ed and then put back")
            self.assertNotEqual(rc, 0, "a replaced entry is not a pass:\n" + out + err)
            self.assertIn(".tmpS", err)

    @unittest.skipUnless(hasattr(os, "O_PATH"), "only the O_PATH leg widens through /proc/self/fd")
    def test_an_unusable_fd_dir_is_reported_not_skipped_5996(self):
        """#5996. On the `O_PATH` leg every widen is addressed through
        `/proc/self/fd/N`, so that path is a DEPENDENCY of the only way this
        leg can look inside an unreadable directory. When it is unavailable -
        no procfs, a container that hides it, a hardened mount - the chmod
        raises `ENOENT`, which leaves `Widener.chmod` as `FileNotFoundError`;
        `_visit` catches `FileNotFoundError` and returns, because an entry that
        genuinely went away is not a failure. So the flagged file underneath
        was never reached, nothing was reported, and the run printed
        `0 cleared, 0 failed` with the append-only flag still set - which is
        the #5657 defect itself, handed back by a dependency failure.

        The flag survives either way: without that path there is no way in.
        What must not survive is the SILENCE."""
        mod = load_script_module()
        shut = self.scratch / ".tmpNoProc"
        shut.mkdir()
        inner = shut / "inner.log"
        inner.write_text("{}\n")
        with flagged(inner):
            with restrictive(shut, 0o000):
                with mock.patch.object(mod, "FD_DIR", str(self.ws / "no-such-fd-dir")):
                    rc, out, err = run_clear_in_process(mod, self.ws)
            self.assertNotEqual(rc, 0,
                                "a widen that could not happen over a flag that is still set is "
                                "not a pass:\n" + out + err)
            self.assertIn(str(shut), err, "the entry that could not be inspected is not named")
            self.assertNotIn("0 cleared, 0 failed", out,
                             "the run reported a clean sweep over an unreadable flagged leftover")
            self.assertTrue(is_flagged(inner), "the fixture itself did not survive the run")

    def test_an_unusable_fd_dir_is_refused_before_anything_is_opened_5996(self):
        """#5996, the half the exit code cannot show. Deleting the refusal
        outright leaves the suite green: the chmod through the missing route
        fails a moment later and the leg reds either way. What the refusal
        buys is that an entry whose mode could NOT be put back is never
        pinned open and never mutated at all - the refusal is taken before
        the `O_PATH` open, not after it."""
        mod = load_script_module()
        if not mod.HAS_O_PATH:
            self.skipTest("the FD_DIR route is the O_PATH leg's; this host has no O_PATH")
        shut = self.scratch / ".tmpNoRoute"
        shut.mkdir()
        inner = shut / "inner.log"
        inner.write_text("{}\n")
        pinned = []
        real_open = os.open

        def counting_open(path, flags, *rest, **kwargs):
            if flags & os.O_PATH:
                pinned.append((path, flags))
            return real_open(path, flags, *rest, **kwargs)

        with flagged(inner):
            with restrictive(shut, 0o000):
                with mock.patch.object(os, "open", counting_open):
                    with mock.patch.object(mod, "FD_DIR", str(self.ws / "no-such-fd-dir")):
                        rc, out, err = run_clear_in_process(mod, self.ws)
            self.assertEqual(pinned, [],
                             "an entry was pinned open on a leg with no way to set a mode on the "
                             "pin, so a widen was attempted that could not have been undone:\n"
                             + "\n".join(repr(entry) for entry in pinned))
            self.assertNotEqual(rc, 0, "a flag that is still set is not a pass:\n" + out + err)
            self.assertIn(str(shut), err, "the entry that could not be inspected is not named")
            self.assertTrue(is_flagged(inner), "the fixture itself did not survive the run")

    def test_a_restore_that_fails_is_reported_and_reds_the_leg_6002(self):
        """#6002. The walk widens a directory it cannot search, descends, and
        puts the mode back on the way out. That restore used to be allowed to
        fail in silence: the inode kept the owner bits this run added, and the
        run still printed "0 failed" and exited 0.

        That is the #5657 failure shape with a mode in place of a flag - a
        janitor reporting a clean sweep over something it left behind - and the
        reason it is not merely cosmetic is that the mode is the only evidence
        that the widen happened at all. A leftover that is named can be fixed by
        hand; one that is swallowed is found by the next job that trips over
        it."""
        mod = load_script_module()
        shut = self.scratch / ".tmpQ"
        shut.mkdir()
        (shut / "inner.log").write_text("{}\n")
        widened = 0o400 | stat.S_IXUSR
        with restrictive(shut, 0o400):
            with restore_that_fails(mod) as calls:
                rc, out, err = run_clear_in_process(mod, self.ws)
            self.assertEqual(calls, [widened, 0o400],
                             "this path is the widen and its restore, in that order: %r" % (calls,))
            self.assertEqual(stat.S_IMODE(os.lstat(shut).st_mode), widened,
                             "the fixture did not actually keep the widened mode, so the "
                             "reporting this test pins is not the reporting of a leftover")
            self.assertNotEqual(rc, 0,
                                "a mode this run added and could not remove is not a pass:\n"
                                + out + err)
            self.assertIn(str(shut), err, "the entry left widened is not named")
            self.assertIn("0o%03o" % widened, err,
                          "the report does not name the mode that is left applied:\n" + out + err)
            self.assertIn("0o400", err,
                          "the report does not name the mode the walk found:\n" + out + err)
            self.assertNotIn(" 0 failed", out,
                             "the run reported no failures while leaving a mode it added:\n" + out)

    def test_a_run_killed_with_a_widened_directory_is_repaired_by_the_next_run_6006(self):
        """#6006. The widen used to be held for the whole subtree descent and
        put back afterwards, which covers every exit that runs code and none of
        the exits that do not. A job timeout, an OOM kill and any other
        `SIGKILL` run no handler and no `finally`, so one of them inside that
        window left the directory more permissive than the walk found it, with
        nothing reported and nothing written down to find it by.

        `SIGKILL` cannot be caught, so the remedy is not a handler: it is a
        window one syscall wide plus a record on disk that the next run reads.
        This test is the only thing that can tell the two apart, because the
        leftover it is about is invisible by construction - the run that made it
        is gone."""
        d = self.scratch / ".tmpK"
        d.mkdir()
        (d / "inner.log").write_text("{}\n")
        widened = 0o400 | stat.S_IXUSR
        with restrictive(d, 0o400):
            killed = subprocess.run(
                [sys.executable, "-c", _KILLED_MID_WIDEN, str(Path(__file__).resolve()),
                 str(self.ws), str(d)],
                capture_output=True, text=True)
            # Without these two the test is vacuous (#2444): a child that dies
            # before it widens anything leaves a mode that was never changed,
            # and a child that EXITS has run the code the defect is about.
            self.assertIn("WIDENED 0o%03o" % widened, killed.stdout,
                          "the child never reached the widened state:\n" + killed.stdout + killed.stderr)
            self.assertEqual(killed.returncode, -signal.SIGKILL,
                             "the janitor exited instead of being killed, so this is not the "
                             "uncatchable window:\n" + killed.stdout + killed.stderr)
            self.assertEqual(stat.S_IMODE(os.lstat(d).st_mode), widened,
                             "a kill that runs no code cannot have put the mode back, so the "
                             "fixture is not in the state this test is about")
            r = run_clear(self.ws)
            self.assertEqual(stat.S_IMODE(os.lstat(d).st_mode), 0o400,
                             "the next run left the mode a killed run added:\n" + r.stdout + r.stderr)
            self.assertIn("put mode 0o400 back on %s" % d, r.stdout,
                          "the repair is unreported, so nothing distinguishes it from a mode "
                          "nobody ever changed:\n" + r.stdout + r.stderr)
            self.assertIn("0o%03o" % widened, r.stdout,
                          "the repair does not name the mode it found:\n" + r.stdout + r.stderr)
            self.assertEqual(r.returncode, 0,
                             "a leftover this run repaired is not a failure:\n" + r.stdout + r.stderr)

# --------------------------------------------------------------------------
# the pending-restore journal: one line per outstanding widen (#6006, #6013,
# #6015, #6020) and the input it must refuse (#6016, #6018, #6019)
# --------------------------------------------------------------------------
# Run the janitor and SIGKILL it right after the Nth call of one `os` seam has
# changed a mode. The kill is sent from inside the process, so no handler, no
# `finally` and no `atexit` runs: that is the whole of what this reproduces.
# argv: <this file> <workspace> <seam> <n> <inode or 0> <path to report>...
# With an inode, only an `fchmod` on that inode that ADDS `S_IXUSR` counts, so
# the Nth widen of one directory is reached with no timing assumption.
_KILLED_AT_NTH = (
    "import importlib.util as u, os, signal, stat, sys\n"
    "spec = u.spec_from_file_location('selftest5657', sys.argv[1])\n"
    "mod = u.module_from_spec(spec)\n"
    "spec.loader.exec_module(mod)\n"
    "script = mod.load_script_module()\n"
    "seam, nth, ino, watch = sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), sys.argv[6:]\n"
    "real, calls = getattr(script.os, seam), []\n"
    "def wrapped(*args, **kwargs):\n"
    "    real(*args, **kwargs)\n"
    "    if ino and not (os.fstat(args[0]).st_ino == ino and args[1] & stat.S_IXUSR):\n"
    "        return\n"
    "    calls.append(args)\n"
    "    if len(calls) == nth:\n"
    "        print('KILLED ' + ' '.join('%s=0o%03o' % (os.path.basename(p), stat.S_IMODE(os.lstat(p).st_mode))\n"
    "                                   for p in watch), flush=True)\n"
    "        os.kill(os.getpid(), signal.SIGKILL)\n"
    "setattr(script.os, seam, wrapped)\n"
    "sys.exit(script.main(['--root', sys.argv[2]]))\n"
)


class JournalCase(ScratchTree):
    """A widen that a `SIGKILL` interrupts is put back by the NEXT run, every
    one of them, and nothing else is ever changed on the journal's say-so."""

    def journal(self):
        return self.scratch / load_script_module().PENDING_RESTORE_FILE

    def kill_at(self, seam, nth, ino, *watch):
        killed = subprocess.run(
            [sys.executable, "-c", _KILLED_AT_NTH, str(Path(__file__).resolve()), str(self.ws),
             seam, str(nth), str(ino)] + [str(p) for p in watch],
            capture_output=True, text=True)
        # Without these two the test is vacuous (#2444): a child that dies
        # before the Nth widen leaves nothing widened, and a child that EXITS
        # has run the code a kill skips.
        self.assertIn("KILLED", killed.stdout,
                      "the child never reached the widen it is killed at:\n" + killed.stdout + killed.stderr)
        self.assertEqual(killed.returncode, -signal.SIGKILL,
                         "the janitor exited instead of being killed:\n" + killed.stdout + killed.stderr)
        return killed.stdout

    def test_a_kill_with_two_widens_outstanding_is_put_back_on_both_6020(self):
        """#6020 and #6006 mechanism 2. A `0o000` directory holding a `0o000`
        directory: when the inner one is widened, the outer one is widened
        too - its search window is open around the lookup - so a kill there
        leaves TWO modes applied. A record with one slot cannot describe that,
        and the `Widener` widen was not recorded at all."""
        d = self.scratch / ".tmpD"
        e = d / "E"
        e.mkdir(parents=True)
        (e / "inner.log").write_text("{}\n")
        with restrictive(e, 0o000), restrictive(d, 0o000):
            out = self.kill_at("chmod", 2, 0, d, e)
            self.assertIn("E=0o500", out, "the inner directory was not widened when the kill landed")
            self.assertIn("D=0o100", out, "the outer directory's search window was not open")
            r = run_clear(self.ws)
            self.assertEqual(stat.S_IMODE(os.lstat(d).st_mode), 0o000,
                             "the outer widen was left applied:\n" + r.stdout + r.stderr)
            with restrictive(d, 0o700):
                self.assertEqual(stat.S_IMODE(os.lstat(e).st_mode), 0o000,
                                 "the inner widen was left applied:\n" + r.stdout + r.stderr)
            for path, left in ((d, "0o100"), (e, "0o500")):
                self.assertIn("put mode 0o000 back on %s, which a previous run left at %s" % (path, left),
                              r.stdout, "a repair is unreported:\n" + r.stdout + r.stderr)
            self.assertEqual(r.returncode, 0, "a leftover this run repaired is not a failure:\n"
                             + r.stdout + r.stderr)
            again = run_clear(self.ws)
            self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
            self.assertNotIn("put mode", again.stdout, "a repair was made twice:\n" + again.stdout)

    def test_a_widen_after_an_inner_search_released_is_still_recorded_6013(self):
        """#6013. The outer directory's search window opens once per lookup.
        After the inner directory's descent is over and ITS line is released,
        the outer directory widens again for the next name - and a release
        that emptied the whole record, or a hold made on the first widen
        only, leaves that widen with nothing written down."""
        d = self.scratch / ".tmpP"
        (d / "A").mkdir(parents=True)
        (d / "A" / "a.log").write_text("{}\n")
        (d / "B").mkdir()
        with restrictive(d / "A", 0o400), restrictive(d, 0o400):
            # 1: the lookup of A; 2: the open of A; 3: the lookup of B.
            out = self.kill_at("fchmod", 3, os.lstat(d).st_ino, d)
            self.assertIn("P=0o500", out, "the outer directory was not widened when the kill landed")
            r = run_clear(self.ws)
            self.assertEqual(stat.S_IMODE(os.lstat(d).st_mode), 0o400,
                             "a widen made after an inner release was left applied:\n" + r.stdout + r.stderr)
            self.assertIn("put mode 0o400 back on %s, which a previous run left at 0o500" % d, r.stdout,
                          "the repair is unreported:\n" + r.stdout + r.stderr)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_clean_run_leaves_no_journal_line_behind_6013(self):
        """Every line a run holds is released by that run, so a run that
        finished leaves the journal empty: a line per widen and a release per
        line, not a line per lookup with only the last one released."""
        d = self.scratch / ".tmpC"
        for name in ("A", "B", "C"):
            (d / name).mkdir(parents=True)
            (d / name / "x.log").write_text("{}\n")
        with restrictive(d / "A", 0o400), restrictive(d / "B", 0o000), restrictive(d, 0o400):
            r = run_clear(self.ws)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            journal = self.journal()
            self.assertTrue(journal.exists(), "the widens this run made were never written down")
            self.assertEqual(journal.read_bytes(), b"",
                             "a run that finished left lines in the journal:\n%r" % journal.read_bytes())

    def test_a_mode_changed_since_the_kill_is_left_alone_and_reported_6014(self):
        """#6014. The journal says what was widened and from what. A mode that
        is neither of those now was set by somebody after the kill, and putting
        the recorded mode on it would undo THEIR change: it is reported, the
        line is kept, and nothing is changed."""
        d = self.scratch / ".tmpM"
        d.mkdir()
        (d / "x.log").write_text("{}\n")
        with restrictive(d, 0o400):
            self.kill_at("fchmod", 1, os.lstat(d).st_ino, d)
            os.chmod(str(d), 0o700)
            for attempt in (1, 2):
                r = run_clear(self.ws)
                self.assertEqual(stat.S_IMODE(os.lstat(d).st_mode), 0o700,
                                 "run %d put the recorded mode over a later change:\n%s%s"
                                 % (attempt, r.stdout, r.stderr))
                self.assertNotEqual(r.returncode, 0, "run %d: a widen it could not settle is not a "
                                    "pass:\n%s%s" % (attempt, r.stdout, r.stderr))
                for text in ("0o400", "0o500", "0o700", str(d)):
                    self.assertIn(text, r.stderr, "run %d's report does not name %s:\n%s"
                                  % (attempt, text, r.stderr))
                self.assertNotIn("put mode", r.stdout, r.stdout)

    def test_a_widened_directory_replaced_since_the_kill_is_reported_by_every_run_6015(self):
        """#6015 and the inode half of #6014. The recorded name now holds a
        different directory: the recorded mode is not that directory's to
        receive, and the widen it describes is still on an inode this run
        cannot reach. Every run says so - the walk's own widens append lines of
        their own and never overwrite this one."""
        d = self.scratch / ".tmpR"
        d.mkdir()
        (d / "x.log").write_text("{}\n")
        moved = self.ws / "moved-out.d"
        with restrictive(d, 0o400):
            self.kill_at("fchmod", 1, os.lstat(d).st_ino, d)
            os.chmod(str(d), 0o700)
            os.rename(str(d), str(moved))
            os.chmod(str(moved), 0o500)
            try:
                d.mkdir()
                (d / "y.log").write_text("{}\n")
                with restrictive(d, 0o400):
                    for attempt in (1, 2, 3):
                        r = run_clear(self.ws)
                        self.assertNotEqual(r.returncode, 0, "run %d forgot a widen it never settled:\n%s%s"
                                            % (attempt, r.stdout, r.stderr))
                        self.assertIn("different inode", r.stderr, "run %d:\n%s" % (attempt, r.stderr))
                        self.assertEqual(stat.S_IMODE(os.lstat(d).st_mode), 0o400,
                                         "the replacement was given the recorded mode")
                    self.assertEqual(stat.S_IMODE(os.lstat(moved).st_mode), 0o500,
                                     "the moved-out directory was reached and changed")
            finally:
                os.chmod(str(moved), 0o700)

    def test_a_record_in_the_old_format_is_never_acted_on_6018(self):
        """#6018. A record naming an inode outside the scratch tree, with its
        true device and inode numbers and a mode no widen produces, used to be
        applied and reported as a repair. A line is accepted only in the form
        this script writes, naming a path inside the tree, describing a widen
        this script makes; anything else is reported and changes nothing."""
        outside = self.ws / "outside.d"
        outside.mkdir(mode=0o700)
        os.chmod(str(outside), 0o700)
        st = os.lstat(outside)
        self.journal().write_text("%d %d %o %s\n" % (st.st_dev, st.st_ino, 0o777, outside))
        os.chmod(str(self.journal()), 0o600)
        r = run_clear(self.ws)
        self.assertEqual(stat.S_IMODE(os.lstat(outside).st_mode), 0o700,
                         "an inode outside the scratch tree was chmod'ed on a record's say-so:\n"
                         + r.stdout + r.stderr)
        self.assertEqual(os.lstat(outside).st_ctime_ns, st.st_ctime_ns,
                         "an inode outside the scratch tree was touched")
        self.assertNotIn("put mode", r.stdout, r.stdout)
        self.assertNotEqual(r.returncode, 0, "a record that cannot be used is not a pass:\n"
                            + r.stdout + r.stderr)

    def test_a_journal_line_outside_the_tree_or_beyond_a_widen_is_refused_6018(self):
        """The line format this script writes, forged: a relative path that
        climbs out of the tree, and a 'widen' that would add bits no widen in
        this file ever adds. Neither is applied; both are reported."""
        outside = self.ws / "outside.d"
        outside.mkdir()
        inside = self.scratch / ".tmpF"
        inside.mkdir()
        with restrictive(outside, 0o300), restrictive(inside, 0o777):
            so, si = os.lstat(outside), os.lstat(inside)
            self.journal().write_text(
                # 0o300 -> 0o700 is a widen this script makes, at a path it is not given.
                "+ 00.1 %d %d %o %o %s\n" % (so.st_dev, so.st_ino, 0o300, 0o700,
                                             os.fsencode("../outside.d").hex())
                # inside the tree, and a 'widen' that adds bits no widen here adds.
                + "+ 00.2 %d %d %o %o %s\n" % (si.st_dev, si.st_ino, 0o000, 0o777,
                                               os.fsencode(".tmpF").hex()))
            os.chmod(str(self.journal()), 0o600)
            r = run_clear(self.ws)
            self.assertEqual(stat.S_IMODE(os.lstat(outside).st_mode), 0o300, r.stdout + r.stderr)
            self.assertEqual(os.lstat(outside).st_ctime_ns, so.st_ctime_ns, r.stdout + r.stderr)
            self.assertEqual(stat.S_IMODE(os.lstat(inside).st_mode), 0o777, r.stdout + r.stderr)
            self.assertNotIn("put mode", r.stdout, r.stdout)
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("not inside the scratch tree", r.stderr, r.stderr)
            self.assertIn("not a widen this script makes", r.stderr, r.stderr)

    def test_a_hardlinked_journal_is_refused_not_written_through_6019(self):
        """#6019. `O_NOFOLLOW` refuses a symlink at the journal's name and not
        a hardlink, and a hardlink is the same inode as a file outside the
        tree. The journal is trusted only as a single-link regular file owned
        by this process; anything else is refused before a byte is written."""
        victim = self.ws / "precious.txt"
        victim.write_text("precious\n")
        os.link(str(victim), str(self.journal()))
        d = self.scratch / ".tmpH"
        d.mkdir()
        (d / "x.log").write_text("{}\n")
        with restrictive(d, 0o400):
            r = run_clear(self.ws)
            self.assertEqual(victim.read_text(), "precious\n",
                             "a file outside the scratch tree was written through the journal")
            self.assertEqual(stat.S_IMODE(os.lstat(d).st_mode), 0o400, r.stdout + r.stderr)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("links", r.stderr, r.stderr)

    def test_a_name_that_is_not_utf8_is_journalled_and_put_back_6016(self):
        """#6016. A directory name is bytes, and the journal stores the bytes:
        a name that is not UTF-8 is held, released and repaired like any other
        instead of crashing the walk. Linux only - APFS refuses such a name."""
        raw = os.path.join(os.fsencode(str(self.scratch)), b"\xff\xfe-dir")
        try:
            os.mkdir(raw)
        except OSError as err:
            if err.errno in (errno.EILSEQ, errno.EINVAL):
                self.skipTest("this filesystem refuses a name that is not UTF-8: %s" % err)
            raise
        name = os.fsdecode(raw)
        with open(os.path.join(raw, b"x.log"), "w") as handle:
            handle.write("{}\n")
        with restrictive(name, 0o400):
            r = run_clear(self.ws)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(stat.S_IMODE(os.lstat(raw).st_mode), 0o400, r.stdout + r.stderr)
            self.assertEqual(self.journal().read_bytes(), b"")
            out = self.kill_at("fchmod", 1, os.lstat(raw).st_ino)
            self.assertIn("KILLED", out)
            self.assertEqual(stat.S_IMODE(os.lstat(raw).st_mode), 0o500)
            r = run_clear(self.ws)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(stat.S_IMODE(os.lstat(raw).st_mode), 0o400,
                             "a widen on a non-UTF-8 name was not put back:\n" + r.stdout + r.stderr)

    def outstanding(self):
        """The `+` lines of the journal that no `-` line releases, as
        `(inode, found, widened)` - what the next run reads as outstanding."""
        held = {}
        for line in self.journal().read_bytes().decode("ascii").splitlines():
            fields = line.split(" ")
            if fields[0] == "+":
                held[fields[1]] = (int(fields[3]), int(fields[4], 8), int(fields[5], 8))
            elif fields[0] == "-":
                held.pop(fields[1], None)
        return list(held.values())

    def test_a_journalled_inode_that_gained_a_link_is_refused_not_repaired_6025(self):
        """#6025. A run is killed the instant its widen of a mode-0o000 file has
        landed, so the journal truly holds that widen. Before the next run a
        second name for the inode appears OUTSIDE the scratch tree. Putting the
        recorded mode back is a mode change on an inode this janitor was never
        pointed at - the one #5936 refuses on the walk's own widen - so the
        replay refuses it too: the outside name keeps its mode and its ctime,
        the run says why, and the line is kept until a run meets the inode with
        one link again, which then puts the mode back."""
        f = self.audit / "held.log"
        f.write_text("{}\n")
        outside = self.ws / "outside-6025.log"
        with restrictive(f, 0o000):
            out = self.kill_at("chmod", 1, 0, f)
            self.assertIn("held.log=0o400", out, "the widen had not landed when the kill did")
            self.assertEqual(self.outstanding(), [(os.lstat(f).st_ino, 0o000, 0o400)],
                             "the killed run did not leave its widen in the journal")
            os.link(str(f), str(outside))
            try:
                before = os.lstat(outside)
                r = run_clear(self.ws)
                after = os.lstat(outside)
                self.assertEqual(after.st_ctime_ns, before.st_ctime_ns,
                                 "an inode reachable from outside the scratch tree was chmod'ed by the "
                                 "replay:\n" + r.stdout + r.stderr)
                self.assertEqual(stat.S_IMODE(after.st_mode), 0o400, r.stdout + r.stderr)
                self.assertNotIn("put mode", r.stdout, r.stdout + r.stderr)
                self.assertNotEqual(r.returncode, 0, "a refused replay is not a pass:\n" + r.stdout + r.stderr)
                self.assertIn("2 links", r.stderr, r.stdout + r.stderr)
                self.assertIn(str(f), r.stderr, r.stdout + r.stderr)
                self.assertEqual(self.outstanding(), [(os.lstat(f).st_ino, 0o000, 0o400)],
                                 "the record of a widen that is still applied was dropped:\n"
                                 + r.stdout + r.stderr)
            finally:
                os.unlink(str(outside))
            # The record survived, so a run that meets the inode with one link
            # finishes it.
            r = run_clear(self.ws)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(stat.S_IMODE(os.lstat(f).st_mode), 0o000, r.stdout + r.stderr)
            self.assertIn("put mode 0o000 back on %s, which a previous run left at 0o400" % f, r.stdout,
                          r.stdout + r.stderr)
            self.assertEqual(self.outstanding(), [], r.stdout + r.stderr)


class WidenFailureCase(ScratchTree):
    """What every exit from the widen in `_open_at` leaves behind, and what it
    says about it - each pinned by a behaviour, not by the text of the code."""

    def test_an_entry_renamed_out_before_the_reopen_is_restored_or_reported_6017(self):
        """#6017 and #5812. The widen lands, the identity read after it passes,
        and only then does the name leave the tree, so the reopen fails. Where
        the inode is pinned the mode comes back off it; where it is not, the
        restore cannot reach it and must SAY so with both modes - it used to
        replace the error with its own `ENOENT`, which the walk treats as an
        entry that went away, and exit 0."""
        mod = load_script_module()
        entry = self.audit / "unreadable.key"
        entry.write_text("k")
        kept = self.ws / "kept-original.key"
        real = os.open
        opens = []

        def opener(path, flags, *args, **kwargs):
            if path == "unreadable.key" and not flags & getattr(os, "O_PATH", 0):
                opens.append(flags)
                if len(opens) == 2:
                    os.rename(str(entry), str(kept))
            return real(path, flags, *args, **kwargs)

        with restrictive(entry, 0o000):
            with mock.patch.object(mod.os, "open", opener):
                rc, out, err = run_clear_in_process(mod, self.ws)
        self.assertEqual(len(opens), 2, "the reopen after the widen was never reached: %r" % opens)
        left = stat.S_IMODE(os.lstat(kept).st_mode)
        if mod.HAS_O_PATH:
            self.assertEqual(left, 0o000, "the pinned inode kept the widened mode")
        else:
            self.assertEqual(left, stat.S_IRUSR)
            self.assertNotEqual(rc, 0, "a widen left applied is not a pass:\n" + out + err)
            self.assertIn("left applied", err, out + err)
            self.assertIn("0o400", err, out + err)
            self.assertIn("0o000", err, out + err)
            self.assertIn("unreadable.key", err, out + err)

    def test_a_shared_inode_is_never_widened_5936(self):
        """#5936. A regular file with a second link outside the scratch tree is
        an inode this janitor was never pointed at. Widening it to read its
        flags changes that other file too - its ctime says so even when the
        mode is put back - so it is refused before anything changes."""
        shared = self.audit / "shared.log"
        shared.write_text("{}\n")
        outside = self.ws / "outside-link.log"
        os.link(str(shared), str(outside))
        with restrictive(outside, 0o000):
            before = os.lstat(outside).st_ctime_ns
            r = run_clear(self.ws)
            self.assertEqual(os.lstat(outside).st_ctime_ns, before,
                             "an inode reachable from outside the scratch tree was chmod'ed:\n"
                             + r.stdout + r.stderr)
            self.assertEqual(stat.S_IMODE(os.lstat(outside).st_mode), 0o000)
            if not IS_BSD:
                # Linux's `lstat` carries no flags, so nothing short of the
                # widen can say whether this inode is flagged: it is reported.
                self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("links", r.stderr, r.stderr)

    def test_a_link_made_after_the_scan_is_refused_before_the_widen_5936(self):
        """#5936 on both legs, for the link the scan never saw. The entry has
        one link when it is classified, and a second name outside the scratch
        tree appears the instant the janitor decides it may widen it. The
        widen step re-reads the inode it is about to change - the pin's
        `fstat` with `O_PATH` (Linux), the bracket's `lstat` without it
        (macOS/BSD) - and refuses the shared inode there, so the outside name
        keeps its mode and its ctime. On macOS the `lstat` flags already skip
        a shared, unflagged file that the scan sees, so this race is the one
        path where only the widen step's own check stands in the way."""
        mod = load_script_module()
        entry = self.audit / "single.log"
        entry.write_text("{}\n")
        outside = self.ws / "late-outside-link.log"
        seen = {}

        def link():
            os.link(str(entry), str(outside))
            seen["ctime"] = os.lstat(outside).st_ctime_ns

        with restrictive(entry, 0o000):
            with swap_when_inspected(mod, os.lstat(entry).st_ino, link) as fired:
                rc, out, err = run_clear_in_process(mod, self.ws)
            self.assertTrue(fired, "the seam never fired: the entry was never a widen candidate")
            self.assertEqual(os.lstat(outside).st_ctime_ns, seen["ctime"],
                             "an inode reachable from outside the scratch tree was chmod'ed:\n" + out + err)
            self.assertEqual(stat.S_IMODE(os.lstat(outside).st_mode), 0o000)
            os.unlink(str(outside))
        self.assertNotEqual(rc, 0, "a shared inode left uninspected is not a pass:\n" + out + err)
        self.assertIn("links", err, out + err)

    @unittest.skipUnless(IS_BSD, "macOS/BSD: the lstat carries the inode flags (Linux: #6022 notes)")
    def test_an_append_only_file_behind_mode_0o000_names_the_remedy_6022(self):
        """#6022. macOS refuses a mode change on an append-only inode, so a
        flag hidden behind mode 0o000 cannot be reached by widening. The
        janitor cannot clear it; it must say what blocks it and how."""
        f = self.audit / "single.log"
        f.write_text("{}\n")
        with restrictive(f, 0o000):
            with flagged(f):
                r = run_clear(self.ws)
                self.assertTrue(is_flagged(f))
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("chflags nouappnd", r.stderr, r.stderr)
            self.assertIn("0o000", r.stderr, r.stderr)
            self.assertIn(str(f), r.stderr, r.stderr)

    @unittest.skipUnless(hasattr(os, "O_PATH"), "Linux only: the O_PATH pin")
    def test_a_failed_pin_never_leaks_its_descriptor_6004(self):
        """#6004. The `O_PATH` pin is closed on every failure after it is
        opened, including an `fstat` that raises."""
        mod = load_script_module()
        entry = self.audit / "unreadable.key"
        entry.write_text("k")
        pins, real_open, real_fstat = set(), os.open, os.fstat
        failed = []

        def opener(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if flags & os.O_PATH:
                pins.add(fd)
            return fd

        def fstat(fd):
            if fd in pins and not failed:
                failed.append(fd)
                raise OSError(errno.EIO, "fstat refused")
            return real_fstat(fd)

        def open_fds():
            return len(os.listdir("/proc/self/fd"))

        with restrictive(entry, 0o000):
            before = open_fds()
            with mock.patch.object(mod.os, "open", opener), mock.patch.object(mod.os, "fstat", fstat):
                rc, out, err = run_clear_in_process(mod, self.ws)
            after = open_fds()
        self.assertTrue(failed, "the pin's fstat was never reached")
        self.assertEqual(after, before, "the pinning descriptor leaked: %d -> %d" % (before, after))
        self.assertNotEqual(rc, 0, out + err)

    def test_a_swap_inside_the_bracket_is_refused_before_the_replacement_is_opened_5812(self):
        """#5812 on the leg with no `O_PATH` (macOS/BSD): the widen is by name,
        and the name is replaced the instant the chmod lands. The identity read
        that closes the bracket must refuse right there - the replacement is a
        readable inode the walk never classified, and it is never opened, never
        chmod'ed, and the mode left on the scanned inode is reported. Where the
        inode is pinned (Linux) there is no bracket - the reopen compare refuses
        a replacement instead, pinned by `..._5998` - so this leg-specific pin
        skips there."""
        mod = load_script_module()
        if mod.HAS_O_PATH:
            self.skipTest("the widen is inode-bound here; the bracket exists only without O_PATH")
        entry = self.audit / "unreadable.key"
        entry.write_text("k")
        stranger = self.ws / "stranger.key"   # outside the scratch tree: never walked
        stranger.write_text("s")
        kept = self.ws / "kept-original.key"
        seen = {}
        opened = []
        real_open = mod.os.open

        def opener(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            with contextlib.suppress(OSError):
                opened.append(os.fstat(fd).st_ino)
            return fd

        def swap():
            os.rename(str(entry), str(kept))
            os.replace(str(stranger), str(entry))
            st = os.lstat(entry)
            seen["ino"], seen["ctime"] = st.st_ino, st.st_ctime_ns

        with restrictive(entry, 0o000), restrictive(stranger, 0o644):
            mod.os.open = opener
            try:
                with swap_after_the_widen(mod, swap) as fired:
                    rc, out, err = run_clear_in_process(mod, self.ws)
            finally:
                mod.os.open = real_open
            self.assertTrue(fired, "the seam never fired: nothing was ever widened")
            self.assertNotIn(seen["ino"], opened,
                             "the replacement was opened after a swap inside the bracket:\n" + out + err)
            self.assertEqual(os.lstat(entry).st_ctime_ns, seen["ctime"],
                             "the replacement was chmod'ed:\n" + out + err)
            self.assertEqual(stat.S_IMODE(os.lstat(entry).st_mode), 0o644)
        self.assertNotEqual(rc, 0, "a swap inside the bracket is not a pass:\n" + out + err)
        self.assertIn("left applied", err, out + err)
        self.assertIn("0o%03o" % stat.S_IRUSR, err, out + err)
        self.assertEqual(stat.S_IMODE(os.lstat(kept).st_mode), stat.S_IRUSR,
                         "the mode left on the scanned inode is not the one reported")

    def test_a_readable_replacement_at_the_reopen_is_refused_untouched_5998(self):
        """#5998. The reopen after the widen is compared against the scanned
        inode. A replacement that is READABLE gets past the open, so only that
        compare stands between it and having the scanned entry's mode put on
        it. The swap lands inside the reopen itself - after the widen and
        after the macOS bracket's second identity read - so both legs reach
        the compare and nothing else can refuse first."""
        mod = load_script_module()
        entry = self.audit / "unreadable.key"
        entry.write_text("k")
        stranger = self.ws / "stranger.key"
        stranger.write_text("s")
        kept = self.ws / "kept-original.key"
        real, opens, seen = os.open, [], {}

        def opener(path, flags, *args, **kwargs):
            if path == "unreadable.key" and not flags & getattr(os, "O_PATH", 0):
                opens.append(flags)
                if len(opens) == 2:
                    os.rename(str(entry), str(kept))
                    os.rename(str(stranger), str(entry))
                    seen["ctime"] = os.lstat(entry).st_ctime_ns
            return real(path, flags, *args, **kwargs)

        with restrictive(stranger, 0o644), restrictive(entry, 0o000):
            with mock.patch.object(mod.os, "open", opener):
                rc, out, err = run_clear_in_process(mod, self.ws)
            self.assertEqual(len(opens), 2, "the reopen after the widen was never reached: %r" % opens)
            self.assertEqual(stat.S_IMODE(os.lstat(entry).st_mode), 0o644,
                             "the replacement was given the scanned entry's mode:\n" + out + err)
            self.assertEqual(os.lstat(entry).st_ctime_ns, seen["ctime"],
                             "the replacement was chmod'ed:\n" + out + err)
            self.assertNotEqual(rc, 0, out + err)
            self.assertIn("replaced", err, out + err)
            if mod.HAS_O_PATH:
                self.assertEqual(stat.S_IMODE(os.lstat(kept).st_mode), 0o000,
                                 "the scanned inode was not put back through its pin")

    def test_an_interrupt_at_the_reopen_puts_the_mode_back_and_propagates_5999(self):
        """#5999 M3. A `KeyboardInterrupt` between the widen and the return is
        not an `OSError`; the restore still runs, and the interrupt still
        stops the run."""
        mod = load_script_module()
        entry = self.audit / "unreadable.key"
        entry.write_text("k")
        real, opens = os.open, []

        def opener(path, flags, *args, **kwargs):
            if path == "unreadable.key" and not flags & getattr(os, "O_PATH", 0):
                opens.append(flags)
                if len(opens) == 2:
                    raise KeyboardInterrupt()
            return real(path, flags, *args, **kwargs)

        with restrictive(entry, 0o000):
            with mock.patch.object(mod.os, "open", opener):
                with self.assertRaises(KeyboardInterrupt):
                    run_clear_in_process(mod, self.ws)
            self.assertEqual(len(opens), 2)
            self.assertEqual(stat.S_IMODE(os.lstat(entry).st_mode), 0o000,
                             "an interrupt at the reopen left the widened mode applied")

    def test_a_refused_restore_at_the_reopen_is_reported_with_its_modes_5999(self):
        """#5999 M4. The reopen fails and the restore is refused: the run must
        say that the widened mode is left applied, with the entry's path."""
        mod = load_script_module()
        entry = self.audit / "unreadable.key"
        entry.write_text("k")
        real_open, real_chmod, opens, chmods = os.open, os.chmod, [], []

        def opener(path, flags, *args, **kwargs):
            if path == "unreadable.key" and not flags & getattr(os, "O_PATH", 0):
                opens.append(flags)
                if len(opens) == 2:
                    raise OSError(errno.EIO, "reopen refused")
            return real_open(path, flags, *args, **kwargs)

        def chmod(*args, **kwargs):
            chmods.append(args)
            if len(chmods) == 2:
                raise OSError(errno.EPERM, "restore refused")
            return real_chmod(*args, **kwargs)

        with restrictive(entry, 0o000):
            with mock.patch.object(mod.os, "open", opener), mock.patch.object(mod.os, "chmod", chmod):
                rc, out, err = run_clear_in_process(mod, self.ws)
            self.assertEqual(len(chmods), 2, "the widen and its restore: %r" % chmods)
        self.assertNotEqual(rc, 0, out + err)
        self.assertIn("left applied", err, out + err)
        self.assertIn("0o400", err, out + err)
        self.assertIn("unreadable.key", err, out + err)

    def test_no_safe_chmod_route_is_a_refusal_with_nothing_changed_6005(self):
        """#6005 M9. With neither an `O_PATH` pin nor a no-follow chmod there
        is no widen that cannot be redirected, so the entry is refused and
        nothing about it changes - its ctime included."""
        mod = load_script_module()
        entry = self.audit / "unreadable.key"
        entry.write_text("k")
        with restrictive(entry, 0o000):
            before = os.lstat(entry).st_ctime_ns
            with mock.patch.object(mod, "HAS_O_PATH", False), \
                    mock.patch.object(mod, "CAN_CHMOD_NOFOLLOW", False):
                rc, out, err = run_clear_in_process(mod, self.ws)
            self.assertEqual(os.lstat(entry).st_ctime_ns, before,
                             "an entry was chmod'ed with no safe route:\n" + out + err)
        self.assertNotEqual(rc, 0, out + err)
        self.assertIn("unreadable.key", err, out + err)
        self.assertIn("re-resolving", err, out + err)

    @unittest.skipUnless(hasattr(os, "O_PATH"), "Linux only: the /proc/self/fd route")
    def test_a_chmod_through_fd_dir_that_raises_enoent_is_reported_6021(self):
        """#6021. `FD_DIR` exists, so the up-front refusal does not fire, and
        the chmod through it raises `ENOENT` anyway. That must be reported as
        an entry that could not be inspected, never read as one that went
        away."""
        mod = load_script_module()
        shut = self.scratch / ".tmpEnoent"
        shut.mkdir()
        inner = shut / "inner.log"
        inner.write_text("{}\n")
        real, seen = os.chmod, []

        def chmod(path, *args, **kwargs):
            if isinstance(path, str) and path.startswith(mod.FD_DIR + "/"):
                seen.append(path)
                raise FileNotFoundError(errno.ENOENT, "no such entry", path)
            return real(path, *args, **kwargs)

        with restrictive(shut, 0o000):
            with mock.patch.object(mod.os, "chmod", chmod):
                rc, out, err = run_clear_in_process(mod, self.ws)
        self.assertTrue(seen, "no chmod went through FD_DIR")
        self.assertNotEqual(rc, 0, out + err)
        self.assertIn("could not inspect", err, out + err)
        self.assertIn(str(shut), err, out + err)
        self.assertNotIn("0 cleared, 0 failed", out, out)


# --------------------------------------------------------------------------
# structural pins: the containment primitives the behaviour tests cannot race
# --------------------------------------------------------------------------
_BANNED_CALLS = frozenset({
    "os.walk", "os.fwalk", "os.chflags", "os.lchflags", "os.stat", "os.readlink",
    "os.path.realpath", "os.path.abspath", "os.unlink", "os.remove", "os.rmdir",
    "shutil.rmtree",
})
# `os.chmod` is deliberately NOT in this set, and must never be put back into
# it. `dir_fd` makes a lookup RELATIVE; it does not make it non-following, and
# chmod's final component is still dereferenced. Asserting "it carries a
# dir_fd" where the property is "it cannot be redirected onto another inode"
# is what let a by-name widen survive three reviews (#5813). `os.open` is
# non-following because `_OPEN_FLAGS` carries `O_NOFOLLOW` (pinned separately)
# and `os.lstat` never follows; the walk may not call `os.chmod` at all.
_DIR_FD_FUNCS = frozenset({"os.open", "os.lstat"})
# Functions that walk the tree: a mode change from any of them must go through
# a descriptor that is already held, never through a name.
_WALK_FUNCS = ("_open_at", "_walk", "_visit", "_clear_fd")


def _named_def(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError("%s defines no %s()" % (SCRIPT.name, name))


def _named_class(tree, name):
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise AssertionError("%s defines no class %s" % (SCRIPT.name, name))


def _named_method(tree, class_name, name):
    for node in _named_class(tree, class_name).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError("%s defines no %s.%s()" % (SCRIPT.name, class_name, name))


def _carries_open_flags(tree, call):
    """True when `call`'s flags argument is _OPEN_FLAGS, directly or through a
    local binding every assignment of which derives from _OPEN_FLAGS."""
    arg = ast.unparse(call.args[1])
    if "_OPEN_FLAGS" in arg:
        return True
    if not isinstance(call.args[1], ast.Name):
        return False
    local = call.args[1].id
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef):
            continue
        if not any(node is call for node in ast.walk(func)):
            continue
        bindings = [
            ast.unparse(node.value)
            for node in ast.walk(func)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == local for target in node.targets)
        ]
        return bool(bindings) and all("_OPEN_FLAGS" in b for b in bindings)
    return False


def _module_assign(tree, name):
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return ast.unparse(node.value)
    raise AssertionError("%s has no module-level %s" % (SCRIPT.name, name))


class StructuralPinCase(unittest.TestCase):
    """A dir-swap race is not reproducible on demand, so the primitives that
    make it unwinnable are pinned by shape instead of by behaviour."""

    def setUp(self):
        self.tree = ast.parse(SCRIPT.read_text())

    def test_the_macos_step_comment_says_the_janitor_puts_widened_modes_back_6001(self):
        """The comment on the macOS self-test step is read by whoever debugs
        that leg, so it must not deny what the janitor does: every mode it
        widens is put back (`_open_at`, `Search`, and the journal's repair
        after a kill)."""
        lines = (WF_DIR / "ci.yml").read_text().splitlines()
        step = [i for i, line in enumerate(lines)
                if "Append-only scratch janitor self-test (#5657, macOS fleet leg)" in line]
        self.assertEqual(len(step), 1, "the macOS self-test step is not where this pin looks")
        start = step[0]
        while start > 0 and lines[start - 1].strip().startswith("#"):
            start -= 1
        comment = " ".join(line.strip().lstrip("#").strip() for line in lines[start:step[0]])
        self.assertNotIn("never restores a mode", comment)
        self.assertIn("puts back every mode it widens", comment)

    def test_script_never_follows_a_symlink_or_reresolves_a_path_5657(self):
        self.assertIn("O_NOFOLLOW", _module_assign(self.tree, "_OPEN_FLAGS"))
        opens = 0
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            name = ast.unparse(node.func)
            self.assertNotIn(name, _BANNED_CALLS,
                             "%s() re-resolves or follows a path; the walk descends by fd" % name)
            if name == "os.open":
                opens += 1
                self.assertGreaterEqual(len(node.args), 2, "os.open needs explicit flags")
                self.assertTrue(_carries_open_flags(self.tree, node),
                                "os.open(%s) may not carry O_NOFOLLOW" % ast.unparse(node.args[1]))
        self.assertGreater(opens, 0, "the walk must open something")
        # A symlink must be dispatched out of the walk before anything opens
        # it, and the dispatch must be the FIRST thing _visit does.
        first = _named_def(self.tree, "_visit").body[0]
        self.assertIsInstance(first, ast.If, "_visit must test for a symlink first")
        self.assertEqual(ast.unparse(first.test), "stat.S_ISLNK(st.st_mode)",
                         "_visit's first test is not the symlink test")
        body = [ast.unparse(n) for n in first.body]
        self.assertIn("self._symlink(path, st)", body, "a symlink is not reported")
        self.assertIsInstance(first.body[-1], ast.Return, "a symlink must not fall through the walk")
        for fname in ("_open_at", "_walk"):
            for node in ast.walk(_named_def(self.tree, fname)):
                if not isinstance(node, ast.Call):
                    continue
                name = ast.unparse(node.func)
                if name in _DIR_FD_FUNCS:
                    self.assertIn("dir_fd", [kw.arg for kw in node.keywords],
                                  "%s in %s() resolves a path instead of a (dirfd, name) pair" % (name, fname))

    def test_a_mode_is_only_ever_changed_through_a_held_descriptor_5657(self):
        """#5813. The widen is the only mutation the walk performs on an entry
        it has not proven anything about yet, so it must address an INODE. A
        chmod by name - even one relative to a `dir_fd` - re-resolves the final
        component and follows a symlink planted in the race window, which put
        a mode on an inode outside the scratch tree entirely."""
        for fname in _WALK_FUNCS:
            for node in ast.walk(_named_def(self.tree, fname)):
                if isinstance(node, ast.Call) and ast.unparse(node.func) == "os.chmod":
                    self.fail("os.chmod in %s(): a mode change in the walk must go through a "
                              "descriptor the walk already holds, never through a name" % fname)
        self.assertIn("Widener(", ast.unparse(_named_def(self.tree, "_open_at")),
                      "the EACCES widen must be bound to an inode by Widener")
        capability = _module_assign(self.tree, "CAN_CHMOD_NOFOLLOW")
        self.assertIn("os.supports_follow_symlinks", capability,
                      "the no-follow chmod must be capability-tested, not guessed from a platform name")
        for platform_name in ("darwin", "sys.platform", "uname", "IS_BSD"):
            self.assertNotIn(platform_name, capability,
                             "a platform name is not a capability test")

    def test_structural_the_widener_source_takes_a_pin_or_a_nofollow_route_5852(self):
        """STRUCTURAL ONLY: this reads the source, it runs nothing. It checks
        that `Widener` takes an `O_PATH` pin where one exists and a no-follow
        chmod where it does not; whether a swap is actually refused is pinned
        by behaviour, per leg, in `..._5852` and `..._5812` (#5852, #5813)."""
        init = _named_method(self.tree, "Widener", "__init__")
        source = ast.unparse(init)
        self.assertIn("os.O_PATH", source, "the entry must be pinned open before anything changes")
        self.assertIn("_OPEN_FLAGS", source, "the pin must carry O_NOFOLLOW")
        self.assertIn("st_dev", source)
        self.assertIn("st_ino", source)
        for node in ast.walk(init):
            if not isinstance(node, ast.Call):
                continue
            name = ast.unparse(node.func)
            self.assertNotEqual(name, "os.chmod", "the pin must land BEFORE any mutation")
            if name == "os.open":
                self.assertIn("dir_fd", [kw.arg for kw in node.keywords],
                              "the pin must be taken relative to the open parent descriptor")
        chmods = 0
        for node in ast.walk(_named_method(self.tree, "Widener", "chmod")):
            if not isinstance(node, ast.Call) or ast.unparse(node.func) != "os.chmod":
                continue
            chmods += 1
            if "FD_DIR" in ast.unparse(node.args[0]):
                continue  # addresses the pinned descriptor, not a name
            keywords = {kw.arg: ast.unparse(kw.value) for kw in node.keywords}
            self.assertEqual(keywords.get("follow_symlinks"), "False",
                             "Widener.chmod(%s) may be redirected by a symlink"
                             % ast.unparse(node.args[0]))
        self.assertGreater(chmods, 0, "Widener.chmod changes no mode at all")
        # Fail closed where neither route exists. On CPython the by-name leg
        # also raises NotImplementedError when `fchmodat(AT_SYMLINK_NOFOLLOW)`
        # is unsupported, so this guard is defence in depth - which is exactly
        # why it needs a pin: deleting it is invisible to a behavioural test on
        # any platform that has one of the two safe routes.
        self.assertIn("CAN_CHMOD_NOFOLLOW", source,
                      "the widener must refuse a platform with no non-following route")
        raises = [n for n in ast.walk(init) if isinstance(n, ast.Raise)]
        self.assertTrue(any("EPERM" in ast.unparse(n) for n in raises),
                        "no safe route must be a refusal, never a widen by name")

    def test_every_failure_exit_from_the_open_attempts_the_restore_and_still_raises_5657(self):
        """#5812. The widened mode escaped the old `_open_at` only on the
        success return: a reopen that raised and the deliberate "the entry was
        replaced" refusal both left the inode permanently more permissive.

        This is a STRUCTURAL test and its name now says only what it proves:
        that every failure exit from the frame attempts the restore and still
        raises the failure it came from. Whether the attempt REACHES the inode
        that was widened is a runtime property of the platform, and only the
        leg that can pin an inode delivers it - that half is pinned behaviourally
        by `test_a_widened_mode_is_restored_or_reported_when_the_reopen_fails_5812`,
        which is split by platform for exactly this reason (#5852)."""
        node = _named_def(self.tree, "_open_at")
        handlers = [
            h for h in ast.walk(node)
            if isinstance(h, ast.ExceptHandler) and "widener.chmod(mode)" in ast.unparse(h)
        ]
        self.assertTrue(handlers, "_open_at has no exit that puts the widened mode back")
        for handler in handlers:
            self.assertTrue(any(isinstance(n, ast.Raise) for n in ast.walk(handler)),
                            "a restored widen must still report the failure it came from")
        self.assertTrue(
            any(isinstance(n, ast.Try) and n.finalbody and "widener.close()" in ast.unparse(n.finalbody)
                for n in ast.walk(node)),
            "the pinning descriptor must be closed on every exit")

    def test_reopen_after_widening_is_checked_against_the_scanned_inode_5657(self):
        body = ast.unparse(_named_def(self.tree, "_open_at"))
        self.assertIn("os.fstat", body)
        self.assertIn("st_dev", body)
        self.assertIn("st_ino", body)

    def test_flags_are_reread_from_the_descriptor_after_the_clear_5657(self):
        body = ast.unparse(_named_def(self.tree, "_clear_fd"))
        self.assertGreaterEqual(body.count("get_flags("), 2,
                                "the clear must be PROVEN, not assumed")
        self.assertIn("st_nlink", body, "a multiply-linked inode must be refused")

    def test_the_janitor_only_ever_removes_the_append_bit_5657(self):
        clearable = _module_assign(self.tree, "CLEARABLE")
        blocking = _module_assign(self.tree, "BLOCKING")
        for immutable in ("UF_IMMUTABLE", "FS_IMMUTABLE_FL", "UF_NOUNLINK", "SF_IMMUTABLE"):
            self.assertNotIn(immutable, clearable, "CLEARABLE must not strip %s" % immutable)
        for blocker in ("UF_IMMUTABLE", "FS_IMMUTABLE_FL", "UF_APPEND", "FS_APPEND_FL"):
            self.assertIn(blocker, blocking, "BLOCKING must notice %s" % blocker)

    def test_no_claim_site_asserts_containment_the_code_does_not_deliver_6007(self):
        """#6007 - the docstring claims are checked against the AST, not read.

        A widen the module docstring does not account for is how the
        "one mutation ... see `Widener`" claim came to be false while three
        byte-identical copies of it shipped."""
        doc = ast.get_docstring(self.tree)
        self.assertTrue(doc, "the module docstring is itself a claim site")
        classes = [node.name for node in self.tree.body if isinstance(node, ast.ClassDef)]
        parent = {}
        for node in ast.walk(self.tree):
            for child in ast.iter_child_nodes(node):
                parent[child] = node
        performers = {}
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name not in ("chmod", "fchmod"):
                continue
            if not any(isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.BitOr)
                       for arg in node.args):
                continue
            performer = None
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                    and func.value.id != "os":
                for known in classes:
                    if known.lower() == func.value.id.lower():
                        performer = known
            if performer is None:
                walker = node
                while walker in parent:
                    walker = parent[walker]
                    if isinstance(walker, ast.ClassDef):
                        performer = walker.name
                        break
            performers.setdefault(performer, []).append(ast.unparse(node))
        self.assertGreaterEqual(len(performers), 2,
                                "a detector that finds no widen pins nothing: %r" % performers)
        self.assertIn("Widener", performers, "the mode-blocked widen must go through `Widener`")
        for performer, calls in sorted(performers.items()):
            self.assertIsNotNone(performer, "a widen outside any class: %r" % calls)
            self.assertIn("`%s`" % performer, doc,
                          "`%s` widens a mode (%s) and the module docstring does not name it, so "
                          "the docstring accounts for fewer widens than the code performs"
                          % (performer, "; ".join(calls)))
        claims = [para for para in doc.split("\n\n") if "nothing this walk widened" in para]
        self.assertTrue(claims, "the restore claim is load-bearing and must stay stated")
        for claim in claims:
            self.assertIn("REFUSED", claim,
                          "a restore the kernel refuses leaves the mode applied on BOTH "
                          "platforms, so an unqualified claim here is false (#6002): %r" % claim)
            self.assertIn("#6002", claim, "the refused-restore case has an issue to point at")

    def test_every_widen_is_journalled_before_it_lands_and_the_kill_claim_names_each_6007(self):
        """#6007 and #5852: the kill-safety claim is checked against the set of
        widens that are actually RECORDED, resolved from the AST, not against
        how often a class is mentioned.

        Every call that widens a mode (a `chmod`/`fchmod` whose mode is OR-ed
        with something) must be preceded, in its own function, by a `.hold(`
        that appends its journal line; the docstring paragraph that claims an
        exit running no code is covered must name every class that performs
        such a widen; and the two phrasings that claimed coverage for widens
        nothing recorded must not come back."""
        source = SCRIPT.read_text()
        doc = ast.get_docstring(self.tree)
        functions = [n for n in ast.walk(self.tree) if isinstance(n, ast.FunctionDef)]
        owner = {}
        for fn in functions:
            for node in ast.walk(fn):
                owner.setdefault(node, fn)
        widens, unrecorded, performers = 0, [], set()
        for fn in functions:
            for node in ast.walk(fn):
                if not isinstance(node, ast.Call) or owner.get(node) is not fn:
                    continue
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name not in ("chmod", "fchmod"):
                    continue
                if not any(isinstance(a, ast.BinOp) and isinstance(a.op, ast.BitOr) for a in node.args):
                    continue
                widens += 1
                held = [c for c in ast.walk(fn) if isinstance(c, ast.Call)
                        and isinstance(c.func, ast.Attribute) and c.func.attr == "hold"
                        and c.lineno < node.lineno]
                if not held:
                    unrecorded.append("%s:%d %s" % (fn.name, node.lineno, ast.unparse(node)))
                if isinstance(func.value, ast.Name) and func.value.id == "widener":
                    performers.add("Widener")
                    continue
                for cls in (n for n in self.tree.body if isinstance(n, ast.ClassDef)):
                    if cls.lineno <= node.lineno <= cls.end_lineno:
                        performers.add(cls.name)
        self.assertGreaterEqual(widens, 2, "a detector that finds no widen pins nothing")
        self.assertFalse(unrecorded, "a widen is made with no journal line held before it, so a "
                                     "kill inside it is unaccounted for: %r" % unrecorded)
        claims = [p for p in doc.split("\n\n") if "SIGKILL" in p]
        self.assertTrue(claims, "the kill-safety claim is load-bearing and must stay stated")
        for claim in claims:
            self.assertIn("journal", claim, "the claim must say what covers a kill: %r" % claim)
            for performer in sorted(performers):
                self.assertIn("`%s`" % performer, claim,
                              "`%s` widens a mode and the kill-safety claim does not name it" % performer)
        for phrase in ("cannot leave it unaccounted", "single durable record"):
            self.assertNotIn(phrase, source, "a claim that covered only the first widen is back: %r" % phrase)

    def test_platform_errnos_are_named_not_numbered_5657(self):
        """95 is ENOTSUP on Linux and EMULTIHOP on macOS (#5747 SEC-F5)."""
        src = SCRIPT.read_text()
        self.assertNotRegex(src, r"errno\s*(==|!=|in)\s*\(?\s*\d", "compare errno to a NAMED constant")
        tolerated = _module_assign(self.tree, "NO_FLAG_SUPPORT")
        for name in ("ENOTTY", "EOPNOTSUPP", "ENOTSUP"):
            self.assertIn(name, tolerated)
        self.assertNotRegex(tolerated, r"\b\d{2,}\b", "tolerate errnos by NAME, not by number")


class FixtureSafetyCase(unittest.TestCase):
    """#5814 - this suite runs ON the self-hosted runner it exists to unblock.
    A fixture it cannot remove is the same outage it is testing for."""

    def test_no_test_body_builds_a_fixture_it_cannot_remove_5657(self):
        """A fixture built with `sudo` is owned by root. `addCleanup` does not
        run when a workflow is cancelled, so one cancellation leaves a
        root-owned directory in the runner workspace that `git clean -ffdx`
        cannot remove and this janitor cannot heal. Privilege is for SETTING
        AN INODE FLAG - which the owner can clear again - never for creating
        an inode.

        Every function in this file is scanned - helpers, `setUp`, `_teardown`
        and the reaper included, not only `test_*` bodies (#6003) - and the
        only escalations allowed are the flag helpers' `chattr`/`lsattr`, the
        janitor's own privileged run, and the `sudo -n true` probe."""
        tree = ast.parse(Path(__file__).resolve().read_text())
        allowed = {"set_flag": ("chattr",), "drop_flags": ("chattr",), "is_flagged": ("lsattr",),
                   "run_clear": ("SCRIPT",), "_sudo_available": ("'true'",), "_priv": ("'sudo'",)}
        offenders, scanned = [], 0
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            scanned += 1
            if node.name == "test_no_test_body_builds_a_fixture_it_cannot_remove_5657":
                continue  # this scan names the words it looks for
            for call in ast.walk(node):
                # Simple statements only: each escalation is judged with the
                # whole command it builds in view.
                if not isinstance(call, (ast.Assign, ast.AugAssign, ast.Expr, ast.Return)):
                    continue
                text = ast.unparse(call)
                if not ("_priv()" in text or "'sudo'" in text or '"sudo"' in text):
                    continue
                if any(word in text for word in allowed.get(node.name, ())):
                    continue
                offenders.append("%s: %s" % (node.name, text.splitlines()[0]))
        self.assertGreater(scanned, 50, "the scan reached too few functions to pin anything")
        self.assertIn("_teardown", [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)])
        self.assertFalse(offenders, "a function in this file escalates privilege for something "
                                    "other than an inode flag: " + "; ".join(sorted(set(offenders))))

    def test_no_chmod_command_in_this_file_widens_for_group_or_other_6003(self):
        """Every fixture here is owned by this process (#5814), so a cleanup
        that widens for group or other buys nothing - and if the removal after
        it never happens, it leaves a world-writable tree in a shared runner
        workspace. Every symbolic mode handed to a `chmod` command in this
        file names the owner only."""
        tree = ast.parse(Path(__file__).resolve().read_text())
        symbolic = re.compile(r"^([ugoa]*)[-+=][rwxXst]+(,[ugoa]*[-+=][rwxXst]+)*$")
        offenders, seen = [], 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.List):
                continue
            words = [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if "chmod" not in words:
                continue
            for word in words:
                if not symbolic.match(word):
                    continue
                seen += 1
                for clause in word.split(","):
                    who = re.match(r"^([ugoa]*)", clause).group(1)
                    if clause[len(who)] == "+" and who != "u":
                        offenders.append("%s (line %d)" % (word, node.lineno))
        self.assertGreater(seen, 0, "no chmod command was found, so this scan pins nothing")
        self.assertFalse(offenders, "a chmod command in this file widens beyond the owner: "
                                    + "; ".join(offenders))

    def test_a_cancelled_run_restores_every_mode_it_changed_5657(self):
        """The reaper is the difference between "this suite was interrupted"
        and "this runner is wedged", so it is tested by actually interrupting
        a run that is holding a restrictive mode."""
        base = ROOT / ".local-runs"
        base.mkdir(exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix=".cancel5657-", dir=base))
        self.addCleanup(shutil.rmtree, str(work), True)
        victim = work / "fixture"
        (victim / "inner").mkdir(parents=True)
        (victim / "inner" / "x.log").write_text("{}\n")
        before = stat.S_IMODE(os.lstat(victim).st_mode)
        # The child's OWN handler is installed before the suite is imported, so
        # the reaper chains to it and it runs LAST - and it leaves through
        # `os._exit`, which runs no generator finaliser, no `finally` and no
        # `atexit`. Whatever mode it prints is what the registry and the
        # handler's drain restored, and nothing else (#6000): a `restrictive()`
        # that stops registering, or a handler that stops draining, both leave
        # 0o444 here.
        child = (
            "import importlib.util as u, os, signal, stat, sys, time\n"
            "def last(signum, frame):\n"
            "    print('LEFT 0o%03o' % stat.S_IMODE(os.lstat(sys.argv[2]).st_mode), flush=True)\n"
            "    os._exit(0)\n"
            "signal.signal(signal.SIGTERM, last)\n"
            "spec = u.spec_from_file_location('selftest5657', sys.argv[1])\n"
            "mod = u.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            "held = mod.restrictive(sys.argv[2], 0o444)\n"
            "held.__enter__()\n"
            "print('HELD 0o%03o' % stat.S_IMODE(os.lstat(sys.argv[2]).st_mode), flush=True)\n"
            "os.kill(os.getpid(), signal.SIGTERM)\n"
            "time.sleep(10)\n"
            "os._exit(3)\n"
        )
        try:
            r = subprocess.run([sys.executable, "-c", child, str(Path(__file__).resolve()), str(victim)],
                               capture_output=True, text=True)
            # Without this the test is vacuous (#2444): a child that dies before it
            # changes anything leaves the mode untouched and "restored" trivially.
            self.assertIn("HELD 0o444", r.stdout,
                          "the child never reached the held state, so nothing was restored:\n%s%s"
                          % (r.stdout, r.stderr))
            self.assertEqual(r.returncode, 0, "the child did not leave through its own handler, so "
                             "something other than the reaper ran:\n%s%s" % (r.stdout, r.stderr))
            self.assertIn("LEFT 0o%03o" % before, r.stdout,
                          "the reaper's registry and drain did not restore the mode before the "
                          "process left:\n%s%s" % (r.stdout, r.stderr))
            after = stat.S_IMODE(os.lstat(victim).st_mode)
            self.assertEqual(after, before,
                             "a cancelled run left %s at mode 0o%03o:\n%s%s" % (victim, after, r.stdout, r.stderr))
        finally:
            os.chmod(str(victim), before)
        shutil.rmtree(victim)  # must not raise: this is what git clean does

    def test_a_fixture_stranded_by_a_kill_is_healed_at_the_next_suite_start_6024(self):
        """#6024, the suite's own share. A `SIGKILL` runs no handler and no
        `atexit`, so a child killed inside `restrictive()` leaves its fixture
        narrowed. The next suite start finds the journal no live process
        holds, puts the mode back and removes the workspace, so `git clean`
        never meets it."""
        base = ROOT / ".local-runs"
        base.mkdir(exist_ok=True)
        ws = Path(tempfile.mkdtemp(prefix=".ws5657-", dir=str(base)))
        self.addCleanup(shutil.rmtree, str(ws), True)
        self.addCleanup(subprocess.run, ["chmod", "-R", "u+rwX", str(ws)], capture_output=True)
        fixture = ws / ".local-runs" / ".tmpK" / "audit"
        fixture.mkdir(parents=True)
        (fixture / "audit.log").write_text("{}\n")
        child = (
            "import importlib.util as u, os, signal, stat, sys\n"
            "spec = u.spec_from_file_location('selftest5657', sys.argv[1])\n"
            "mod = u.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            "held = mod.restrictive(sys.argv[2], 0o000)\n"
            "held.__enter__()\n"
            "print('HELD 0o%03o' % stat.S_IMODE(os.lstat(sys.argv[2]).st_mode), flush=True)\n"
            "os.kill(os.getpid(), signal.SIGKILL)\n"
        )
        r = subprocess.run([sys.executable, "-c", child, str(Path(__file__).resolve()), str(fixture)],
                           capture_output=True, text=True)
        # Without these the test is vacuous (#2444): a child that never held
        # the fixture, or that exited and ran its reaper, strands nothing.
        self.assertIn("HELD 0o000", r.stdout, r.stdout + r.stderr)
        self.assertEqual(r.returncode, -signal.SIGKILL, r.stdout + r.stderr)
        self.assertEqual(stat.S_IMODE(os.lstat(fixture).st_mode), 0o000,
                         "the kill did not strand the fixture, so this heals nothing")
        _healed, problems = _heal_stranded_fixtures()
        self.assertEqual([p for p in problems if os.path.basename(str(ws)) in p], [], "\n".join(problems))
        self.assertFalse(os.path.lexists(str(ws)),
                         "a workspace a killed run stranded survived the next suite start")


# --------------------------------------------------------------------------
# GitHub Actions expression evaluator (the `if:` guards, by meaning)
# --------------------------------------------------------------------------
_TOKEN = re.compile(
    r"""\s*(?:(?P<op>&&|\|\||==|!=|!|\(|\)|,)
           |(?P<str>'(?:[^']|'')*')
           |(?P<num>-?\d+(?:\.\d+)?)
           |(?P<name>[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_*][A-Za-z0-9_-]*)*))""",
    re.X,
)


def _tokenize(text):
    out, pos = [], 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        m = _TOKEN.match(text, pos)
        if not m:
            raise AssertionError("cannot tokenize GitHub expression at %r" % text[pos:])
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
        pos = m.end()
    return out


def gh_truthy(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        return value != ""
    if isinstance(value, (int, float)):
        return value != 0
    return True


def _gh_eq(left, right):
    if isinstance(left, bool) or isinstance(right, bool):
        return gh_truthy(left) == gh_truthy(right)
    if isinstance(left, str) or isinstance(right, str):
        return str(left).lower() == str(right).lower()
    return left == right


class GhExpr:
    """Evaluator for the GitHub-expression subset this repo's `if:` guards use.

    An identifier or function it does not know raises, so a guard that drifts
    into unparsed syntax FAILS the pin instead of quietly evaluating true."""

    def __init__(self, text, context):
        self.toks = _tokenize(text)
        self.pos = 0
        self.ctx = context
        self.text = text

    def evaluate(self):
        value = self._or()
        if self.pos != len(self.toks):
            raise AssertionError("trailing tokens in %r" % self.text)
        return value

    def _peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def _accept(self, kind, text):
        if self._peek() == (kind, text):
            self.pos += 1
            return True
        return False

    def _expect(self, kind, text):
        if not self._accept(kind, text):
            raise AssertionError("expected %r in %r" % (text, self.text))

    def _or(self):
        value = self._and()
        while self._accept("op", "||"):
            right = self._and()
            value = value if gh_truthy(value) else right
        return value

    def _and(self):
        value = self._cmp()
        while self._accept("op", "&&"):
            right = self._cmp()
            value = right if gh_truthy(value) else value
        return value

    def _cmp(self):
        value = self._unary()
        tok = self._peek()
        if tok is not None and tok[0] == "op" and tok[1] in ("==", "!="):
            self.pos += 1
            right = self._unary()
            equal = _gh_eq(value, right)
            return equal if tok[1] == "==" else not equal
        return value

    def _unary(self):
        if self._accept("op", "!"):
            return not gh_truthy(self._unary())
        return self._primary()

    def _primary(self):
        tok = self._peek()
        if tok is None:
            raise AssertionError("expression ended early: %r" % self.text)
        if tok == ("op", "("):
            self.pos += 1
            value = self._or()
            self._expect("op", ")")
            return value
        kind, raw = tok
        self.pos += 1
        if kind == "str":
            return raw[1:-1].replace("''", "'")
        if kind == "num":
            return float(raw) if "." in raw else int(raw)
        if kind != "name":
            raise AssertionError("unexpected token %r in %r" % (raw, self.text))
        if self._accept("op", "("):
            args = []
            if not self._accept("op", ")"):
                args.append(self._or())
                while self._accept("op", ","):
                    args.append(self._or())
                self._expect("op", ")")
            return self._call(raw, args)
        return self._lookup(raw)

    def _call(self, name, args):
        if name == "contains" and len(args) == 2:
            haystack, needle = args
            if isinstance(haystack, (list, tuple)):
                return any(_gh_eq(item, needle) for item in haystack)
            return str(needle).lower() in str(haystack).lower()
        if name == "startsWith" and len(args) == 2:
            return str(args[0]).lower().startswith(str(args[1]).lower())
        if name == "endsWith" and len(args) == 2:
            return str(args[0]).lower().endswith(str(args[1]).lower())
        if name == "fromJSON" and len(args) == 1:
            return json.loads(args[0])
        if name == "always" and not args:
            return True
        raise AssertionError("unsupported GitHub function %s/%d in %r" % (name, len(args), self.text))

    def _lookup(self, name):
        low = name.lower()
        if low in ("true", "false"):
            return low == "true"
        if low == "null":
            return None
        if name in self.ctx:
            return self.ctx[name]
        raise AssertionError("unknown context value %r in %r" % (name, self.text))


# --------------------------------------------------------------------------
# workflow pins
# --------------------------------------------------------------------------
def _yaml():
    try:
        import yaml
    except ImportError as err:  # fail, never skip: these pins are the gate
        raise AssertionError(
            "PyYAML is required for the #5657 workflow pins (pip install pyyaml): %s" % err
        )
    return yaml


def load_workflow(path):
    return _yaml().safe_load(path.read_text())


def _as_labels(value):
    """Runner labels from a `runs-on` / matrix `runner` value."""
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("["):
            try:
                return [str(x) for x in json.loads(text)]
            except ValueError:
                return []
        return [text]
    if isinstance(value, (list, tuple)):
        labels = []
        for item in value:
            labels.extend(_as_labels(item))
        return labels
    return []


def matrix_legs(job):
    """Every concrete matrix leg of `job`, as dicts of matrix key -> value."""
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    if not isinstance(matrix, dict) or not matrix:
        return [{}]
    include = matrix.get("include") or []
    dims = {k: v for k, v in matrix.items() if k not in ("include", "exclude") and isinstance(v, list)}
    legs = []
    if dims:
        keys = sorted(dims)
        for combo in itertools.product(*[dims[k] for k in keys]):
            legs.append(dict(zip(keys, combo)))
    if not legs:
        legs = [dict(entry) for entry in include] or [{}]
    elif include:
        merged = []
        for leg in legs:
            row = dict(leg)
            for entry in include:
                if all(row.get(k) == v for k, v in entry.items() if k in row):
                    row.update(entry)
            merged.append(row)
        legs = merged
    return legs


def job_runner_labels(job):
    """Every runner label `job` can run on, resolving a matrix-driven runs-on."""
    runs_on = job.get("runs-on")
    text = runs_on if isinstance(runs_on, str) else ""
    if "${{" not in text:
        return set(_as_labels(runs_on))
    labels = set()
    keys = set(re.findall(r"matrix\.([A-Za-z0-9_-]+)", text))
    for leg in matrix_legs(job):
        for key in keys:
            labels.update(_as_labels(leg.get(key)))
    return labels


def _all_steps():
    """Every `(path, job_id, step)` in every workflow in the repository."""
    for path in sorted(WF_DIR.glob("*.yml")) + sorted(WF_DIR.glob("*.yaml")):
        doc = load_workflow(path)
        if not isinstance(doc, dict):
            continue
        for job_id, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps") or []:
                if isinstance(step, dict):
                    yield path, job_id, step


def step_index(steps, predicate):
    for i, step in enumerate(steps):
        if isinstance(step, dict) and predicate(step):
            return i
    return None


def is_checkout(step):
    return str(step.get("uses") or "").startswith(CHECKOUT_PREFIX)


def is_clear_step(step):
    return step.get("name") == CLEAR_STEP


def leg_context(leg, docs_only):
    ctx = {"matrix.%s" % k: v for k, v in leg.items()}
    ctx["needs.%s.outputs.docs_only" % CLASSIFY_JOB] = docs_only
    ctx["github.event_name"] = "pull_request"
    return ctx


class WorkflowPinCase(unittest.TestCase):
    def test_inline_copy_is_byte_identical_to_the_script_5657(self):
        want = SCRIPT.read_text().rstrip("\n")
        for path in WORKFLOWS:
            doc = load_workflow(path)
            found = 0
            for job_id, job in (doc.get("jobs") or {}).items():
                for step in job.get("steps") or []:
                    if not is_clear_step(step):
                        continue
                    found += 1
                    self.assertEqual(step.get("shell"), "python3 {0}",
                                     "%s/%s must run the copy as a python3 script" % (path.name, job_id))
                    self.assertEqual(str(step.get("run", "")).rstrip("\n"), want,
                                     "%s/%s inline copy drifted from %s" % (path.name, job_id, SCRIPT.name))
            self.assertEqual(found, 1, "%s needs exactly one #5657 clear step" % path.name)

    def test_clear_step_condition_runs_on_every_self_hosted_leg_5657(self):
        """Evaluated, not grepped: a guard rewritten to `== 'true'`, to
        `false && ...`, or to anything else that skips a self-hosted leg is a
        poisoned runner on the next job.

        The `continue` below is the #2444 vacuity shape: with no clear step
        anywhere, every job is skipped and the test passes having asserted
        nothing. `evaluated` is what makes the pass mean something."""
        evaluated = 0
        covered = set()
        for path in WORKFLOWS:
            doc = load_workflow(path)
            for job_id, job in (doc.get("jobs") or {}).items():
                steps = job.get("steps") or []
                idx = step_index(steps, is_clear_step)
                if idx is None:
                    continue
                evaluated += 1
                covered.add(path.name)
                condition = steps[idx].get("if")
                self.assertIsNotNone(condition, "%s/%s clear step needs an `if:`" % (path.name, job_id))
                legs = matrix_legs(job)
                self.assertTrue(legs, "%s/%s has no resolvable legs" % (path.name, job_id))
                self_hosted = 0
                for leg in legs:
                    labels = set()
                    for value in leg.values():
                        labels.update(_as_labels(value))
                    want = "self-hosted" in labels
                    self_hosted += 1 if want else 0
                    for docs_only in ("true", "false", ""):
                        got = gh_truthy(GhExpr(str(condition), leg_context(leg, docs_only)).evaluate())
                        if want and docs_only != "":
                            self.assertTrue(got, "%s/%s: leg %r with docs_only=%r SKIPS the clear step"
                                            % (path.name, job_id, leg, docs_only))
                        if not want:
                            self.assertFalse(got, "%s/%s: hosted leg %r runs the clear step"
                                             % (path.name, job_id, leg))
                self.assertGreater(self_hosted, 0, "%s/%s has no self-hosted leg" % (path.name, job_id))
        self.assertEqual(covered, set(p.name for p in WORKFLOWS),
                         "a workflow carries no clear step at all, so this test asserted nothing "
                         "about it: %d guard(s) evaluated across %r"
                         % (evaluated, sorted(covered)))

    def test_a_step_that_is_not_the_clear_step_is_not_named_like_it_5657(self):
        """Every pin in this file finds the clear step by EXACT name. A
        neighbouring step one word away from that name makes the next edit of
        either silently unpin the other, and a step that runs the SELF-TEST
        while being named like the CLEAR step is the trap that was there."""
        core = "append-only scratch clear"
        checked = 0
        for path, job_id, step in _all_steps():
            name = str(step.get("name") or "")
            if not name or is_clear_step(step):
                continue
            checked += 1
            self.assertNotIn(core, name.lower(),
                             "%s/%s step %r is one word from the clear step's exact name"
                             % (path.name, job_id, name))
            if SELFTEST_REL in str(step.get("run") or ""):
                self.assertIn("self-test", name.lower(),
                              "%s/%s runs the #5657 self-test but is not named as one"
                              % (path.name, job_id))
        self.assertGreater(checked, 0, "no named step was examined")

    def test_every_self_hosted_macos_job_clears_before_checkout_5657(self):
        """Repo-wide: ANY job that can land on the self-hosted macOS node and
        checks out the repo must clear the dead scratch first."""
        checked = 0
        for path in sorted(WF_DIR.glob("*.yml")) + sorted(WF_DIR.glob("*.yaml")):
            doc = load_workflow(path)
            if not isinstance(doc, dict):
                continue
            for job_id, job in (doc.get("jobs") or {}).items():
                if not isinstance(job, dict):
                    continue
                labels = job_runner_labels(job)
                if "self-hosted" not in labels or not any(l.startswith("macos") for l in labels):
                    continue
                steps = job.get("steps") or []
                checkout_at = step_index(steps, is_checkout)
                if checkout_at is None:
                    continue
                checked += 1
                clear_at = step_index(steps, is_clear_step)
                self.assertIsNotNone(
                    clear_at,
                    "%s/%s runs on self-hosted macOS and checks out, with no #5657 clear step"
                    % (path.name, job_id))
                self.assertLess(clear_at, checkout_at,
                                "%s/%s clears the scratch AFTER actions/checkout, which is where it dies"
                                % (path.name, job_id))
        self.assertGreaterEqual(checked, 2, "expected at least the ci.yml and session-boot macOS jobs")

    def test_classify_job_runs_these_tests_5657(self):
        doc = load_workflow(WF_DIR / "ci.yml")
        job = (doc.get("jobs") or {}).get(CLASSIFY_JOB)
        self.assertIsNotNone(job, "ci.yml has no %s job" % CLASSIFY_JOB)
        runs = [str(s.get("run") or "") for s in job.get("steps") or [] if not is_clear_step(s)]
        self.assertTrue(any(SELFTEST_REL in r for r in runs),
                        "ci.yml/%s no longer runs %s" % (CLASSIFY_JOB, SELFTEST_REL))

    def test_macos_ci_leg_runs_these_tests_5657(self):
        """SEC-F3: the BSD branch of the janitor is the one that matters on the
        poisoned node, and `ubuntu-latest` never executes it."""
        doc = load_workflow(WF_DIR / "ci.yml")
        found = []
        for job_id, job in (doc.get("jobs") or {}).items():
            steps = job.get("steps") or []
            # the inline janitor copy NAMES this file in its docstring, so the
            # match has to exclude it or every clear step looks like a self-test
            idx = step_index(steps, lambda s: not is_clear_step(s) and SELFTEST_REL in str(s.get("run") or ""))
            if idx is None:
                continue
            checkout_at = step_index(steps, is_checkout)
            for leg in matrix_legs(job):
                labels = set()
                for value in leg.values():
                    labels.update(_as_labels(value))
                if "self-hosted" not in labels or not any(l.startswith("macos") for l in labels):
                    continue
                condition = steps[idx].get("if")
                runs = condition is None or gh_truthy(
                    GhExpr(str(condition), leg_context(leg, "false")).evaluate())
                if not runs:
                    continue
                self.assertIsNotNone(checkout_at, "%s needs a checkout before running the suite" % job_id)
                self.assertGreater(idx, checkout_at,
                                   "ci.yml/%s runs the suite before checkout" % job_id)
                found.append((job_id, leg.get("leg")))
        self.assertTrue(found, "no self-hosted macOS leg in ci.yml runs %s" % SELFTEST_REL)

    def test_live_audit_flag_is_still_set_5657(self):
        src = (ROOT / "src" / "audit.rs").read_text()
        self.assertIn("libc::UF_APPEND", src)
        self.assertIn("FS_APPEND_FL", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
