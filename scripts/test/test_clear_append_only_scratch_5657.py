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

The script runs as the UNPRIVILEGED runner user in CI, so these tests run it
unprivileged too. Only the FIXTURES escalate: `chflags uappnd` (macOS/BSD, owner
may set and clear) needs nothing, `chattr +a` (Linux) needs CAP_LINUX_IMMUTABLE
and therefore `sudo -n`. When a mechanism is unavailable the test that needs it
SKIPS with a message; the workflow pin tests always run.

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
            pass


def _install_fixture_reaper():
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
    os.chmod(path, mode)
    try:
        yield path
    finally:
        try:
            if not os.path.islink(path):
                os.chmod(path, before)
        except OSError:
            pass
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


class ScratchTreeCase(unittest.TestCase):
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
        # `a+rwX`, not `u+rwX`: a root-owned fixture is not ours to widen for
        # the OWNER, and the flags must come off before anything can be removed.
        subprocess.run(_priv() + ["chmod", "-R", "a+rwX", str(self.ws)], capture_output=True)
        try:
            for path in self.ws.rglob("*"):
                if not path.is_symlink():
                    drop_flags(path)
        except OSError:
            pass
        subprocess.run(_priv() + ["rm", "-rf", str(self.ws)], capture_output=True)
        shutil.rmtree(self.ws, ignore_errors=True)

    # -- the defect itself -------------------------------------------------
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

    def test_a_replaced_entry_is_refused_with_nothing_widened_5657(self):
        """#5812, the deliberate refusal path. The entry is replaced by a
        different inode before the widen; the janitor must notice and refuse,
        and the inode that is left standing in the tree must not have been
        widened on the way out."""
        mod = load_script_module()
        entry = self.audit / "unreadable.key"
        entry.write_text("k")
        # OUTSIDE the scratch tree, so the walk never visits the decoy itself
        # and the only entry that races is the one the test is about.
        decoy = self.ws / "decoy.key"
        decoy.write_text("d")
        with restrictive(entry, 0o000), restrictive(decoy, 0o000):
            inode = os.lstat(entry).st_ino
            with swap_when_inspected(mod, inode, lambda: os.replace(decoy, entry)) as fired:
                rc, out, err = run_clear_in_process(mod, self.ws)
            self.assertTrue(fired, "the seam never fired: the race window was never reached")
            self.assertEqual(stat.S_IMODE(os.lstat(entry).st_mode), 0o000,
                             "the replacement inode was left widened by a refusal")
            self.assertNotEqual(rc, 0, "a replaced entry is not a pass:\n" + out + err)

    def test_a_widened_mode_is_restored_when_the_reopen_fails_5657(self):
        """#5812, the other exit. The widen lands on the right inode, and only
        THEN is the name replaced, so the reopen fails.

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

    def test_the_widener_pins_the_inode_before_it_changes_anything_5657(self):
        """Every widen goes through this class, so the class itself has to be
        incapable of addressing a name that can be re-resolved (#5813)."""
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
        by `test_a_widened_mode_is_restored_when_the_reopen_fails_5657`, which
        is split by platform for exactly this reason (#5852)."""
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
        an inode."""
        tree = ast.parse(Path(__file__).resolve().read_text())
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
                continue
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                text = ast.unparse(call)
                if "_priv()" in text or "'sudo'" in text or '"sudo"' in text:
                    offenders.append("%s: %s" % (node.name, text.splitlines()[0]))
        self.assertFalse(offenders, "a test body escalates privilege to build a fixture: "
                                    + "; ".join(sorted(set(offenders))))

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
        child = (
            "import importlib.util as u, os, signal, stat, sys\n"
            "spec = u.spec_from_file_location('selftest5657', sys.argv[1])\n"
            "mod = u.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            "held = mod.restrictive(sys.argv[2], 0o444)\n"
            "held.__enter__()\n"
            "print('HELD 0o%03o' % stat.S_IMODE(os.lstat(sys.argv[2]).st_mode), flush=True)\n"
            "os.kill(os.getpid(), signal.SIGTERM)\n"
        )
        r = subprocess.run([sys.executable, "-c", child, str(Path(__file__).resolve()), str(victim)],
                           capture_output=True, text=True)
        # Without this the test is vacuous (#2444): a child that dies before it
        # changes anything leaves the mode untouched and "restored" trivially.
        self.assertIn("HELD 0o444", r.stdout,
                      "the child never reached the held state, so nothing was restored:\n%s%s"
                      % (r.stdout, r.stderr))
        after = stat.S_IMODE(os.lstat(victim).st_mode)
        self.assertEqual(after, before,
                         "a cancelled run left %s at mode 0o%03o:\n%s%s" % (victim, after, r.stdout, r.stderr))
        shutil.rmtree(victim)  # must not raise: this is what git clean does


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
