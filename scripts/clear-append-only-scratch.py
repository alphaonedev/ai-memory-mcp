#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Clear the append-only flag on a DEAD CI scratch tree so it can be deleted (#5657).

ai-memory marks its audit log append-only (`UF_APPEND` on macOS/BSD,
`FS_APPEND_FL` on Linux; see `mark_append_only` in `src/audit.rs`). That flag is
a forensic control on a LIVE log and is never weakened by this script. A test
process that is killed, or one that never clears the flag, leaves a flagged
`audit.log` inside the self-hosted runner workspace (`.local-runs/.tmp*/audit/`).
A flagged file cannot be unlinked even by its owner, so the NEXT job's
`actions/checkout` workspace clean dies with EPERM and the runner is poisoned.

This script walks `<root>/.local-runs` (a scratch tree that is already dead when
the next job starts) and clears ONLY the append-only bit. It makes the cleanup
idempotent: a clean tree is a no-op.

The decision rule is about FLAGS, not about openability (#5747 round 2):

* A permission error is NOT a verdict. The runner owns its own scratch, and an
  owner can always chmod its way back in, so a mode that hides the inode flags
  is answered by widening it just enough to read them and restoring it
  afterwards. An unflagged mode-000 leftover must never red a leg that
  `actions/checkout` would have cleaned by itself. The one exception is a
  regular file with more than one link: its inode may also live outside the
  scratch tree, so its mode is never widened, and where the platform cannot
  read its flags without opening it (Linux) it is reported instead (#5936).
* Reporting "0 failed" while a flag survives is worse than failing. Every
  candidate is re-read from the same descriptor AFTER the clear, and a name that
  is still un-unlinkable is reported by path and exits 1 - including a flag this
  script deliberately does not clear (`uchg`/`FS_IMMUTABLE_FL`: ai-memory never
  sets it, so removing it is not this janitor's business) and a name owned by
  somebody else, where the honest answer is "I could not tell".

Containment. The walk descends by directory descriptor: every entry is reached
as a bare name relative to an already-open parent fd, with `O_NOFOLLOW`, and
every flag clear happens on that descriptor.

Widening a mode is the one mutation the walk performs on an entry it has not
proven anything about yet (see `Widener`, #5813), so it is made as narrow as the
platform allows. There are two widens in this file and no others, and only the
first is on an entry nothing is known about yet:

* `Widener`'s, reached when a mode hides the inode flags. It is bracketed by an
  identity check, and what that is worth is the platform difference below.
* `Search`'s, on a directory this walk already holds open and has already proven
  to be the inode that was scanned. It adds `S_IXUSR` alone, through the held
  descriptor, for ONE lookup by name (#5995, #6006).

Each of the two appends its own line to the pending-restore journal before the
chmod that makes it (`Journal`, and the paragraph on uncatchable exits below);
what that journal does and does not cover is stated there, not here.

What `Widener`'s widen buys differs by platform, and the difference matters:

* Linux (`O_PATH`). The entry is pinned with `O_PATH|O_NOFOLLOW` - which
  succeeds whatever the mode is - and the pinned inode is compared with the
  scanned one BEFORE anything changes, so an entry swapped underneath the walk
  is refused with nothing mutated at all. The chmod then addresses that
  descriptor through `/proc/self/fd`: it is bound to the INODE that was scanned,
  and can neither follow a symlink nor land on a name that has since been
  replaced.
* macOS/BSD (no `O_PATH`). The chmod is `fchmodat` with `AT_SYMLINK_NOFOLLOW`
  relative to the already-open parent descriptor, bracketed by an `lstat` of the
  same name immediately before it and immediately after it. This is narrower
  than the Linux leg and is NOT equivalent to it. What the bracket buys: the
  lookup cannot be redirected by an ancestor component, a symlink at the final
  component is chmod'ed as the symlink rather than as its target, a swap that
  has already landed when the widen is reached is refused with nothing mutated,
  and a swap that lands inside the bracket is reported rather than silent. What
  it does not buy: the NAME is still resolved again at chmod time, so a swap
  inside the bracket still puts the mode on whatever holds that name at that
  instant, and a hardlink planted there shares an inode that may also live
  outside the scratch tree - staying inside this directory is a property of the
  namespace, not of the inode. The window is narrowed to one syscall, not
  closed. The exposure is bounded - only owner bits are added, only where
  `_ownable` says this process may chmod the inode back (its own euid owns it,
  or the euid is 0, which does not bound by ownership at all). Closing the
  window would need a way to address an inode with no name, and this platform
  offers none: `O_EVTONLY` was measured on the macOS leg as an `O_PATH`
  analogue and refused a mode-0o000 file and directory with EACCES (#5852).
* Neither mechanism. `Widener` refuses with EPERM rather than widen through a
  name it would have to re-resolve unprotected.

Every exit from the widen ATTEMPTS to put the widened mode back - a reopen that
raised, an inode that turns out to have been swapped, and the ordinary success -
and what the attempt is worth differs by platform AND by whether the kernel
takes it. Where the inode is pinned, the attempt addresses the INODE that was
scanned, so a restore that is accepted leaves nothing this walk widened still
widened (#5812); a restore that is REFUSED leaves the mode applied on either
platform, and is reported with the path, the mode that is applied and the mode
the walk found, which reds the leg - never swallowed (#6002).

Where the inode is NOT pinned, the restore after a SUCCESSFUL reopen goes
through the descriptor that was proven to be the scanned inode - so the common
path is inode-bound on both platforms - but on the failure exits the name is all
there is, and if the name was taken away inside the bracket around the widening
chmod, the inode that was widened can no longer be addressed at all. That mode
is then left applied, and the run SAYS so: the path and the mode go to stderr as
a workflow `::error::` and the exit code is non-zero, because an abandoned widen
that is named is recoverable and one that is silent is not (#5812, #5852). A
reopen after a widening chmod is still checked against the inode that was
scanned.

An exit that runs no code at all - `SIGKILL`, a job timeout, an OOM kill - is
covered by neither a handler nor a `finally`, so it is covered two other ways
(#6006). No mode is held across a descent: a directory is widened for ONE
lookup and narrowed again immediately, by `Search`, through the descriptor the
walk already holds. And every widen of either kind appends ONE line of its own to
a journal in the scratch root (`Journal`), fsynced BEFORE the chmod it
describes, naming the inode, the mode the walk found and the mode the widen
applies; the restore that undoes it appends a release naming that entry and no
other. Widens that nest - a `Widener` widen made inside a parent's `Search`
lookup, two directories deep - therefore each keep their own line, and a
release cannot discharge a widen it did not make (#6013, #6020). A widen whose
line cannot be written is refused.

The next run reads the lines no release matched and finishes them while its own
walk holds the inode open: only an inode the walk reached inside the scratch
tree, only where this process may chmod it, and only when the mode it reads is
exactly the widened one (put back) or exactly the found one (already back,
nothing changed). Every other outcome - a different inode at the recorded name,
a mode that is neither, a line that does not parse, a journal that is not this
process's own regular file - changes nothing, is reported, and keeps the line,
so it is reported again on every later run until someone resolves it (#6014,
#6015, #6018). A line whose inode the walk never met, in a run that met every
entry it looked for, is spent: the entry went away with its mode. What this
does not buy: an inode NUMBER recycled inside the scratch tree, owned by this
process and sitting at exactly the widened mode is indistinguishable from the
inode that was widened, and loses at most the owner bits the widen added.

Symlinks are never
followed and their flags are never cleared (a clear would have to go back
through a path); a flagged symlink is reported instead. A
regular file with more than one link is never widened and never cleared,
because its inode may also live outside the scratch tree: a flagged one is
refused, and so is one whose mode hides its flags where they cannot be read
without opening it (Linux); on macOS/BSD the `lstat` carries the flags, so an
unflagged one is left alone without being touched (#5936).

The workflow runs this BEFORE `actions/checkout`, when the repository may not be
on disk yet, so the workflow step carries a byte-identical inline copy of this
file; `scripts/test/test_clear_append_only_scratch_5657.py` pins the two equal.

Exit codes: 0 = nothing flagged or every flag cleared; 1 = a flag remains that
could not be cleared, or a name that could not be inspected (named on stderr, as
a workflow `::error::`); 2 = bad usage.
Python 3.9+, standard library only.
"""
import argparse
import errno
import os
import stat
import struct
import sys

SCRATCH_DIR = ".local-runs"
IS_BSD = hasattr(os, "lchflags")

# Every widen a walk may be holding, one line each, written down before it
# happens so a kill that runs no code leaves something the next run can finish
# (`Journal`; #6006, #6013, #6020). It lives INSIDE the scratch root on purpose:
# the journal and the modes it describes are removed by the same `rm -rf`, so it
# can never outlive the tree it refers to, and every path in it is stored
# RELATIVE to that root. Widens nest - a parent's search widen is applied while
# a child is widened to be opened - so the journal is a set of lines, never one
# slot, and it is emptied only at the end of a run that leaves nothing in it
# outstanding, because this file never unlinks anything.
PENDING_RESTORE_FILE = ".clear-append-only-pending"
_PENDING_LIMIT = 1 << 20
# The only bits a widen in this file ever adds; a journal line claiming any
# other change is not one this script wrote (#6018).
_WIDEN_BITS = stat.S_IRUSR | stat.S_IXUSR

# Linux inode flags (uapi/linux/fs.h).
FS_APPEND_FL = 0x0000_0020
FS_IMMUTABLE_FL = 0x0000_0010


def _bsd_mask(*names):
    """OR of the named `stat` flags that exist on this platform."""
    mask = 0
    for name in names:
        mask |= getattr(stat, name, 0)
    return mask


# Flags that make a name un-unlinkable, i.e. the ones that poison the next
# `actions/checkout`. Reported when they survive, whether or not we cleared them.
BLOCKING = (
    _bsd_mask("UF_APPEND", "UF_IMMUTABLE", "UF_NOUNLINK", "SF_APPEND", "SF_IMMUTABLE", "SF_NOUNLINK")
    if IS_BSD
    else FS_APPEND_FL | FS_IMMUTABLE_FL
)
# The ONLY flag this janitor removes: the one `mark_append_only` sets.
CLEARABLE = _bsd_mask("UF_APPEND") if IS_BSD else FS_APPEND_FL
# Flags under which macOS/BSD refuses any mode change, so a mode that hides
# them cannot be widened away (#6022). The `lstat` carries them on that leg.
_CHMOD_REFUSING = _bsd_mask("UF_APPEND", "UF_IMMUTABLE", "SF_APPEND", "SF_IMMUTABLE")

# Named errnos meaning "this filesystem has no inode-flag concept", tolerated on
# the GET side only. A hard-coded 95 would have been wrong: it is ENOTSUP on
# Linux but EMULTIHOP on macOS (#5747 SEC-F5).
NO_FLAG_SUPPORT = frozenset(
    v for v in (getattr(errno, n, None) for n in ("ENOTTY", "EOPNOTSUPP", "ENOTSUP")) if v is not None
)

_OPEN_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
_LIBC_FCHFLAGS = None

# Widening a mode is the only mutation the walk performs on an entry it has not
# proven anything about yet, so it addresses an inode wherever the platform lets
# it. `O_PATH` opens an entry whatever its mode and `/proc/self/fd/N` then
# addresses THAT inode (Linux). macOS has no `O_PATH`, only
# `fchmodat(AT_SYMLINK_NOFOLLOW)`, which `os.chmod(..., follow_symlinks=False)`
# reaches; that one is non-following but still by NAME, which is weaker - see
# the `Widener` docstring and #5852. `os.supports_follow_symlinks` is the
# capability test, because the same call raises `NotImplementedError` on
# Linux (#5813).
HAS_O_PATH = hasattr(os, "O_PATH")
FD_DIR = "/proc/self/fd"
CAN_CHMOD_NOFOLLOW = os.chmod in os.supports_follow_symlinks and os.chmod in os.supports_dir_fd


def _linux_ioctl_numbers():
    """FS_IOC_GETFLAGS / FS_IOC_SETFLAGS = _IOR/_IOW('f', 1|2, long)."""
    size = struct.calcsize("l")

    def ioc(direction, nr):
        return (direction << 30) | (size << 16) | (ord("f") << 8) | nr

    return ioc(2, 1), ioc(1, 2)  # _IOC_READ=2, _IOC_WRITE=1


def _fchflags(fd, flags):
    """macOS/BSD `fchflags(2)`: clears by descriptor, so no path is resolved.

    `os.chflags` has no `dir_fd`/fd form (`os.chflags not in os.supports_fd` on
    macOS) and Python 3.9 has no `os.O_SYMLINK`, so the descriptor-only clear
    this script needs is bound from libc directly."""
    global _LIBC_FCHFLAGS
    if _LIBC_FCHFLAGS is None:
        import ctypes
        import ctypes.util

        lib = ctypes.CDLL(ctypes.util.find_library("c") or "libc.dylib", use_errno=True)
        fn = lib.fchflags
        fn.argtypes = [ctypes.c_int, ctypes.c_uint]
        fn.restype = ctypes.c_int
        _LIBC_FCHFLAGS = (ctypes, fn)
    ctypes, fn = _LIBC_FCHFLAGS
    if fn(fd, flags) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _raw_flags(fd):
    """The platform's inode-flag read on `fd`. Raises on every failure; the
    single seam a test can make fail, so the fail-closed path below is proven
    rather than asserted."""
    if IS_BSD:
        return os.fstat(fd).st_flags
    import fcntl

    get_req, _ = _linux_ioctl_numbers()
    buf = bytearray(struct.pack("l", 0))
    fcntl.ioctl(fd, get_req, buf, True)
    (flags,) = struct.unpack("l", bytes(buf))
    return flags


def get_flags(fd):
    """Inode flags on `fd`, or None ONLY when the filesystem has no flag
    concept. Every other error propagates: a flag state we could not read is
    never reported as "no flag here" (#5747 SEC-F1)."""
    try:
        return _raw_flags(fd)
    except OSError as err:
        if err.errno in NO_FLAG_SUPPORT:
            return None
        raise


def set_flags(fd, flags):
    """Write inode flags on `fd`. Never swallows an error: a failed SET is a
    failure, where a failed GET on a flagless filesystem is not."""
    if IS_BSD:
        _fchflags(fd, flags)
        return
    import fcntl

    _, set_req = _linux_ioctl_numbers()
    fcntl.ioctl(fd, set_req, struct.pack("l", flags))


def _refuse_a_shared_file(st, change="widened to read its flags"):
    """Refuse a regular file with more than one link before its mode changes.

    Another name for the same inode may sit outside the scratch tree, and a
    mode put on the inode is put on every one of its names (#5936). That holds
    for a widen and for putting a recorded mode back alike (#6025); `change`
    names which one is refused."""
    if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
        raise PermissionError(errno.EACCES, "has %d links, so its inode may live outside the scratch "
                                            "tree; its mode is not %s" % (st.st_nlink, change))


# Every C0 and C1 control character, DEL and the two Unicode line separators,
# each as a visible escape. A name may hold any of them, and a report line is
# read by the runner: a newline would start a line of its own - a workflow
# command, a forged tally - and an escape sequence would rewrite what the log
# shows (#6027).
_UNPRINTABLE = dict((code, "\\x%02x" % code) for code in list(range(0x20)) + list(range(0x7f, 0xa0)))
_UNPRINTABLE.update({0x2028: "\\u2028", 0x2029: "\\u2029"})


def _shown(text, stream):
    """`text` as `stream` can print it, on one line. A path is bytes, not text:
    a name that is not UTF-8 arrives with surrogate escapes, and printing one
    to a strict stream would crash the report it belongs in (#6016); a name
    with a control character in it is shown with that character escaped
    (#6027)."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    return text.translate(_UNPRINTABLE).encode(encoding, "backslashreplace").decode(encoding)


class Widener:
    """A mode change that cannot be redirected onto a different inode (#5813).

    Built BEFORE anything is mutated, from the `(dirfd, name)` pair the walk is
    standing on and the `lstat` that was already taken of it.

    `os.chmod(name, ..., dir_fd=dirfd)` is NOT a descriptor operation: `dir_fd`
    makes the lookup relative, it does not make it non-following, and the final
    component is still dereferenced. So on Linux the entry is pinned open with
    `O_PATH|O_NOFOLLOW` - which succeeds whatever the mode is, and which yields
    the symlink itself rather than its target - and the pinned inode is compared
    with the scanned one straight away: an entry swapped underneath the walk is
    refused here, with nothing changed at all. Every later chmod goes through
    `/proc/self/fd/N`, which addresses the pinned inode.

    That route is also a dependency, and a dependency that is missing is a
    REFUSAL here, never an absence: `FD_DIR` is checked before the entry is
    opened, and a chmod through it that fails is reported as `EPERM` rather
    than as the `ENOENT` of an entry that went away - which the caller treats
    as "nothing to do here" and does not report at all (#5996). The mode is
    then read back off the pinned descriptor, so a widen this class says it
    performed is one the inode actually carries.

    Where there is no `O_PATH` (macOS/BSD), `fchmodat(AT_SYMLINK_NOFOLLOW)`
    relative to the already-open parent descriptor cannot traverse a symlink
    either, and every chmod is bracketed by an `lstat` of the same name taken
    immediately before it and immediately after it (`_identity`): an entry
    swapped before the bracket is refused with nothing changed, and one swapped
    inside it is reported. Nothing is pinned, though - the chmod itself still
    addresses a NAME, so a swap that lands inside the bracket, or a hardlink
    planted at that name, is mutated instead of the scanned inode. Not leaving
    this directory is a property of the namespace, not of the inode, so this
    leg is strictly weaker than the Linux one (#5852). A platform with neither
    mechanism gets no widen: the entry is reported, never mutated through a
    resolvable path.

    On both legs a regular file found with more than one link is refused
    before its mode changes, because its inode may also live outside the
    scratch tree (#5936)."""

    def __init__(self, dirfd, name, st, want_dir):
        self._dirfd = dirfd
        self._name = name
        self._st = st
        self._want_dir = want_dir
        self._fd = None
        # True from the instant a chmod is issued until it is known to have
        # failed. A chmod that raised did not happen, so a widen that fails
        # with this False left the mode exactly as the walk found it (#6023).
        self.may_have_landed = False
        if HAS_O_PATH:
            if not os.path.isdir(FD_DIR):
                # Every mode this leg sets is addressed THROUGH this directory.
                # Without it there is no inode-bound chmod here at all, so the
                # entry gets the same refusal a platform with no safe route
                # gets below - taken now, before anything is opened or changed.
                raise OSError(errno.EPERM,
                              "%s is unavailable, so no mode can be set on a pinned inode" % FD_DIR)
            flags = _OPEN_FLAGS | os.O_PATH | (os.O_DIRECTORY if want_dir else 0)
            fd = os.open(name, flags, dir_fd=dirfd)
            try:
                # Closed on EVERY failure from here, including an `fstat` that
                # raises, so a refusal never leaks the pinning descriptor (#6004).
                pinned = os.fstat(fd)
                if (pinned.st_dev, pinned.st_ino) != (st.st_dev, st.st_ino):
                    raise OSError(errno.EIO, "the entry was replaced while it was being inspected")
                _refuse_a_shared_file(pinned)
            except BaseException:
                os.close(fd)
                raise
            self._fd = fd
        elif not CAN_CHMOD_NOFOLLOW:
            raise OSError(errno.EPERM, "no way to widen a mode here without re-resolving the name")
        else:
            # The stand-in for the pin's check: the entry is read again and a
            # replaced or shared inode is refused HERE, before the caller
            # journals a widen - so a refusal leaves no line claiming one
            # (#6028). `chmod` repeats it, because the name can change again.
            self._identity()

    def _identity(self):
        """Read the entry's identity off the NAME and refuse a mismatch.

        This is the no-`O_PATH` leg's stand-in for a pin, and it is strictly
        weaker than one: it brackets a single chmod rather than binding it to an
        inode, so it narrows the window to one syscall and can only REPORT a
        swap that lands inside it (#5852). A failure of the lookup itself is
        left to propagate as what it is - an entry that went away is not an
        entry that was replaced."""
        now = os.lstat(self._name, dir_fd=self._dirfd)
        if (now.st_dev, now.st_ino) != (self._st.st_dev, self._st.st_ino):
            raise OSError(errno.EIO, "the entry no longer resolves to the inode that was scanned")
        _refuse_a_shared_file(now)

    def chmod(self, mode):
        """Set `mode` on the pinned inode, or - with no `O_PATH` - on the entry
        itself without following a symlink, bracketed by two identity reads."""
        if self._fd is None:
            # Before: nothing has been mutated yet, so a mismatch is a clean
            # refusal and the error is allowed to say exactly that.
            self._identity()
            self.may_have_landed = True
            try:
                os.chmod(self._name, mode, dir_fd=self._dirfd, follow_symlinks=False)
            except NotImplementedError:
                # The interpreter refuses this combination here. Widening by a
                # name that would be re-resolved is not an acceptable fallback,
                # so the entry is reported instead of being mutated.
                self.may_have_landed = False
                raise OSError(errno.EPERM, "no way to widen a mode here without re-resolving the name")
            except OSError:
                self.may_have_landed = False
                raise
            try:
                self._identity()
            except OSError as err:
                # After: the mode landed on the inode that was scanned, and the
                # name it was reached by now belongs to something else. This
                # platform cannot address an inode except by a name, so that
                # mode cannot be put back - it is named instead of abandoned.
                raise OSError(errno.EIO, "the entry was replaced while its mode was being set to "
                                         "0o%03o, so that mode landed on the inode that was scanned "
                                         "and is left applied: it can only be reached by the name it "
                                         "no longer has (%s)" % (mode, err))
        else:
            self.may_have_landed = True
            try:
                os.chmod("%s/%d" % (FD_DIR, self._fd), mode)
            except OSError as err:
                self.may_have_landed = False
                # Never `FileNotFoundError` out of here. The caller reads that
                # as "the entry went away" and returns WITHOUT reporting
                # anything, so a procfs that is missing or refusing would print
                # `0 cleared, 0 failed` over a flag that is still set (#5996).
                # Linux refuses a mode change on an inode that carries the
                # append-only or immutable attribute with `EPERM`, and behind a
                # mode that hides the flags this is where that shows, so the
                # report names the attribute and its remedy (#6023).
                remedy = ""
                if err.errno == errno.EPERM:
                    remedy = ("; Linux refuses a mode change on an inode with the append-only or "
                              "immutable attribute: as a holder of CAP_LINUX_IMMUTABLE run "
                              "`chattr -a` (and `chattr -i` for the immutable attribute) on it, then "
                              "run this again")
                raise OSError(errno.EPERM, "could not set mode 0o%03o on the pinned inode "
                                           "through %s: %s%s" % (mode, FD_DIR, err, remedy))
            landed = stat.S_IMODE(os.fstat(self._fd).st_mode)
            if landed != mode:
                raise OSError(errno.EPERM, "mode 0o%03o did not take on the pinned inode, "
                                           "which reads 0o%03o" % (mode, landed))

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


class Search:
    """Owner search permission on a directory this walk already holds open, for
    ONE lookup at a time (#6006).

    A directory that is readable but not searchable can be listed from a
    descriptor with no mode change at all, but a lookup BY NAME under it -
    `os.lstat(name, dir_fd=)`, `os.open(name, dir_fd=)` - needs the search bit
    at the instant of the call. Widening for the whole descent, as this walk
    used to, makes that window as long as a subtree; widening around the lookup
    makes it one syscall. Only `S_IXUSR` is added, and only through the
    descriptor the walk already holds, so neither the name nor any other bit is
    involved.

    The one syscall that remains cannot be covered by a handler, because
    `SIGKILL` runs none, so the first widen appends this directory's own line to
    the journal (`Cleaner.hold`), and the line is released only when the descent
    is over. Between those two the mode is always either the one the walk found
    or that plus `S_IXUSR`, and the next run's repair accepts exactly those two
    (`Cleaner._repair`). A `Widener` widen made inside one of these lookups has
    a line of its own, so neither release can discharge the other (#6013). A
    narrow that FAILS poisons this object: the mode is left applied, it is
    reported with its path, the line is deliberately left unreleased, and no
    further lookup is made under a directory whose mode this walk can no longer
    control (#6002)."""

    def __init__(self, cleaner, fd, path, st, mode):
        self._cleaner = cleaner
        self._fd = fd
        self._path = path
        self._st = st
        self._mode = mode
        self._held = None
        self._broken = False

    def __enter__(self):
        if self._broken:
            raise OSError(errno.EPERM, "the mode of this directory could not be narrowed again, so "
                                       "nothing further under it is looked up")
        if self._held is None:
            # Appended BEFORE the first widen and kept until the descent is
            # over. A line that cannot be written refuses the widen: this
            # janitor exists because silent leftovers are the failure, and an
            # unrecorded one is the silent kind.
            self._held = self._cleaner.hold(self._path, self._st, self._mode, self._mode | stat.S_IXUSR)
        os.fchmod(self._fd, self._mode | stat.S_IXUSR)
        return self

    def __exit__(self, kind, value, trace):
        try:
            os.fchmod(self._fd, self._mode)
        except OSError as err:
            self._broken = True
            try:
                applied = "0o%03o" % stat.S_IMODE(os.fstat(self._fd).st_mode)
            except OSError:
                applied = "a mode that could no longer be read back"
            self._cleaner.fail(self._path, "the mode this walk widened is left applied (%s, not the "
                                           "0o%03o the walk found): %s" % (applied, self._mode, err))
        return False

    def release(self):
        """Release this directory's own journal line once the descent is over.

        A broken window keeps its line on purpose. The mode really is still
        widened there, and the next run's repair is the only thing left that
        can put it back."""
        if self._held is not None and not self._broken:
            self._cleaner.release(self._held, self._path)


class _NoSearch:
    """A directory that is already searchable, or one this process may not
    chmod at all. Nothing is widened and nothing is recorded, so the walk has
    one shape for both cases instead of a flag it has to remember to test."""

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace):
        return False

    def release(self):
        pass


_NO_SEARCH = _NoSearch()


class _Entry:
    """One `+` line of the journal that no `-` line has released."""

    __slots__ = ("ident", "inode", "want", "widened", "rel", "path", "settled", "resolved")

    def __init__(self, ident, inode, want, widened, rel):
        self.ident = ident
        self.inode = inode
        self.want = want
        self.widened = widened
        self.rel = rel
        self.path = None
        self.settled = False  # this run has repaired it or reported it
        self.resolved = False  # this run has released it


class Journal:
    """The pending-restore journal: one line per widen that may be outstanding.

    `+ <id> <dev> <ino> <found> <widened> <hex path>` is appended and fsynced
    BEFORE the chmod it describes, and `- <id>` once that mode is back. A
    release names one entry and nothing else, so widens that nest each keep
    their own line and a release cannot discharge a widen it did not make
    (#6006, #6013, #6020). The file is opened `O_APPEND` and never `O_TRUNC`; it
    is emptied only at the end of a run that left nothing in it outstanding.
    The path is stored relative to the scratch root and hex-encoded from its
    bytes, so a name that is not UTF-8, or that carries a newline, is still one
    line and round-trips exactly (#6016).

    It is trusted only as far as its own inode can be: a regular file with ONE
    link, owned by this process's euid and writable by nobody else. Anything
    else is refused before a byte of it is read or written (#6018, #6019), and
    a widen whose line cannot be written is refused with it."""

    def __init__(self, top):
        self.top = top
        self.path = os.path.join(top, PENDING_RESTORE_FILE)
        self.refused = None
        self.recovered = None
        self._fd = None
        self._run = os.urandom(8).hex()
        self._seq = 0
        self._open = set()

    def _attach(self, create):
        if self._fd is not None:
            return
        flags = _OPEN_FLAGS | os.O_RDWR | os.O_APPEND | (os.O_CREAT if create else 0)
        fd = os.open(self.path, flags, stat.S_IRUSR | stat.S_IWUSR)
        try:
            st = os.fstat(fd)
            why = None
            if not stat.S_ISREG(st.st_mode):
                why = "is not a regular file"
            elif st.st_nlink != 1:
                why = "has %d links, so its inode may also live outside the scratch tree" % st.st_nlink
            elif st.st_uid != os.geteuid():
                why = "is owned by uid %d, not by this process (euid %d)" % (st.st_uid, os.geteuid())
            elif st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                why = "is writable by group or other (0o%03o)" % stat.S_IMODE(st.st_mode)
            if why is not None:
                raise OSError(errno.EPERM, "the pending-restore journal %s, so it is neither read "
                                           "nor written" % why)
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd

    def load(self):
        """The entries no release matched, in the order they were held, and a
        description of every line that could not be used. Raises when the
        journal itself cannot be trusted or read."""
        try:
            self._attach(create=False)
        except FileNotFoundError:
            return [], []  # no run has widened anything here
        raw = b""
        while True:
            chunk = os.pread(self._fd, 1 << 16, len(raw))
            if not chunk:
                break
            raw += chunk
            if len(raw) > _PENDING_LIMIT:
                raise OSError(errno.EFBIG, "the pending-restore journal is larger than %d bytes, so "
                                           "it is not read: once every `+ <id>` line in it has a "
                                           "matching `- <id>` line, or the inode each unmatched `+` "
                                           "line names has been checked by hand, delete it and run "
                                           "this again (#6026)" % _PENDING_LIMIT)
        lines = raw.split(b"\n")
        tail = lines.pop()
        held = {}
        problems = []
        for number, line in enumerate(lines, 1):
            why = self._take(line, held)
            if why is not None:
                problems.append("line %d (%r) %s" % (number, line[:160], why))
        if tail:
            # Every line is fsynced BEFORE the chmod it describes, so a line
            # that never became whole describes a chmod that was never made:
            # cutting it off loses nothing, and keeping it refused every widen
            # of every later run (#6026). Nothing may be appended after it
            # meanwhile - it would be glued to it - so if it cannot be cut off
            # the journal is refused, as before.
            try:
                os.ftruncate(self._fd, len(raw) - len(tail))
                os.fsync(self._fd)
            except OSError as err:
                self.refused = "its last line is incomplete"
                problems.append("ends in an incomplete line (%r) that could not be cut off (%s), so "
                                "a widen it began to describe cannot be ruled out" % (tail[:160], err))
            else:
                self.recovered = ("ended in an incomplete line (%r), which is cut off: every line is "
                                  "fsynced before the chmod it describes, so that line describes a "
                                  "chmod that was never made" % tail[:160])
        return list(held.values()), problems

    def _take(self, line, held):
        """Apply one journal line to `held`; a reason it cannot be used, or None."""
        try:
            fields = line.decode("ascii").split(" ")
        except UnicodeDecodeError:
            return "is not a line this script writes"
        if fields[0] == "-" and len(fields) == 2:
            if held.pop(fields[1], None) is None:
                return "releases an entry no earlier line holds"
            return None
        if fields[0] != "+" or len(fields) != 7:
            return "is not a line this script writes"
        ident, dev, ino, want, widened, hexpath = fields[1:]
        if not ident or ident.strip("0123456789abcdef.") or ident in held:
            return "does not carry an entry id of its own"
        if not (dev.isdigit() and ino.isdigit()):
            return "does not name an inode"
        if not want or not widened or want.strip("01234567") or widened.strip("01234567"):
            return "does not carry two octal modes"
        want, widened = int(want, 8), int(widened, 8)
        added = widened & ~want
        if (want > 0o7777 or widened > 0o7777 or widened & want != want or not added
                or added & ~_WIDEN_BITS):
            return ("describes 0o%o -> 0o%o, which is not a widen this script makes; nothing is "
                    "changed for it" % (want, widened))
        try:
            rel = os.fsdecode(bytes.fromhex(hexpath))
        except ValueError:
            return "does not carry a hex-encoded path"
        if not self._inside(rel):
            return "names a path that is not inside the scratch tree; nothing is changed for it"
        held[ident] = _Entry(ident, (int(dev), int(ino)), want, widened, rel)
        return None

    @staticmethod
    def _inside(rel):
        """True for "." or a relative path of plain components: no root, no
        `.`/`..`, nothing empty. Containment is checked on the stored text,
        before the path is ever joined to anything (#6018)."""
        if rel == ".":
            return True
        parts = rel.split(os.sep)
        return "\0" not in rel and all(part not in ("", ".", "..") for part in parts)

    def absolute(self, rel):
        return self.top if rel == "." else os.path.join(self.top, rel)

    def hold(self, path, st, want, widened):
        """Append the widen `path` is about to get and return its entry id."""
        if self.refused is not None:
            raise OSError(errno.EPERM, "the pending-restore journal cannot be appended to (%s), so "
                                       "the widen it would record is refused" % self.refused)
        if path == self.top:
            rel = "."
        elif path.startswith(self.top + os.sep):
            rel = path[len(self.top) + len(os.sep):]
        else:
            raise OSError(errno.EPERM, "is not under the scratch root, so its widen is refused")
        self._attach(create=True)
        self._seq += 1
        ident = "%s.%d" % (self._run, self._seq)
        self._append("+ %s %d %d %o %o %s\n" % (ident, st.st_dev, st.st_ino, want, widened,
                                                 os.fsencode(rel).hex()))
        self._open.add(ident)
        return ident

    def release(self, ident):
        """Append the release of ONE entry: that widen is no longer outstanding."""
        self._attach(create=True)
        self._append("- %s\n" % ident)
        self._open.discard(ident)

    def _append(self, text):
        data = text.encode("ascii")
        end, written = None, 0
        try:
            end = os.fstat(self._fd).st_size
            written = os.write(self._fd, data)
            if written != len(data):
                raise OSError(errno.EIO, "only %d of %d bytes reached it" % (written, len(data)))
            os.fsync(self._fd)
        except OSError as err:
            self.refused = "an append to it failed: %s" % err
            if written:
                self._take_back(end, written)
            raise

    def _take_back(self, end, written):
        """Cut off what a failed append wrote (#6026). The append raised, so the
        widen its line describes is refused and never made; left in the file,
        those bytes would be read by every later run as a torn line. Only bytes
        this append wrote are cut: a file that has grown by anything else is
        left as it is, and the journal stays refused."""
        try:
            if os.fstat(self._fd).st_size == end + written:
                os.ftruncate(self._fd, end)
                os.fsync(self._fd)
                return
            why = "the file changed size meanwhile"
        except OSError as err:
            why = str(err)
        self.refused += "; the %d bytes it wrote could not be taken back (%s)" % (written, why)

    def finish(self, settled):
        """Empty the journal if nothing in it is outstanding, then let it go.

        `settled` is the caller's half: no entry an earlier run left is still
        unresolved. This run's half is that every line it held was released."""
        if self._fd is None:
            return
        try:
            if settled and not self._open and self.refused is None:
                os.ftruncate(self._fd, 0)
                os.fsync(self._fd)
        finally:
            os.close(self._fd)
            self._fd = None


class Cleaner:
    """Depth-first clear over one scratch tree. Collects cleared paths, mode
    repairs, notes and failures; never raises out of `run`."""

    def __init__(self):
        self.cleared = []
        self.repaired = []
        self.notes = []
        self.failures = []
        self._journal = None
        self._journal_kept = False
        self._recorded = {}
        self._recorded_at = {}
        self._met = {}

    def fail(self, path, why):
        self.failures.append((path, str(why)))

    def run(self, top):
        self._journal = Journal(top)
        self.sweep()
        try:
            try:
                st = os.lstat(top)
            except OSError as err:
                self.fail(top, "could not stat the scratch root: %s" % err)
                return
            self._meet(top, st)
            self._visit(None, top, top, st, _NO_SEARCH)
        finally:
            self._settle()

    def hold(self, path, st, want, widened):
        """Append the widen `path` is about to get, BEFORE the chmod; its id.

        The reader is the NEXT process, after this one was killed, so the line
        is fsynced before the chmod it covers is allowed to happen. It names
        the inode as well as the path, because a path alone would let a later
        run put a mode on whatever has taken that name since (#6006)."""
        return self._journal.hold(path, st, want, widened)

    def release(self, ident, path):
        """Release ONE journal entry: the widen it describes is not outstanding."""
        try:
            self._journal.release(ident)
        except OSError as err:
            self.fail(path, "the mode was put back but its pending-restore journal line could not be "
                            "released, so the next run will read a widen that is no longer "
                            "outstanding: %s" % err)

    def sweep(self):
        """Read what a killed run left outstanding (#6006, #6015, #6018).

        `SIGKILL`, a job timeout and an OOM kill run no handler and no
        `finally`, so the only thing that can put back a mode one of them
        interrupted is the next run reading what the killed one wrote down.
        Nothing is changed here: an entry is finished by the walk, on the inode
        the walk holds (`_repair`), and an entry the walk never reaches is
        settled at the end (`_settle`). A journal that cannot be trusted or read
        is reported and refuses this run's widens; a line that cannot be used
        is reported and kept."""
        try:
            entries, problems = self._journal.load()
        except OSError as err:
            if self._journal.refused is None:
                self._journal.refused = str(err)
            self.fail(self._journal.path, "a pending-restore journal that cannot be trusted or read "
                                          "cannot be ruled out, so neither can a mode a previous run "
                                          "left widened: %s" % err)
            return
        if self._journal.recovered is not None:
            self.fail(self._journal.path, "the pending-restore journal %s" % self._journal.recovered)
        for why in problems:
            self.fail(self._journal.path, "the pending-restore journal's %s; it is kept for "
                                          "whoever resolves it" % why)
        self._journal_kept = bool(problems)
        for entry in entries:
            entry.path = self._journal.absolute(entry.rel)
            self._recorded.setdefault(entry.inode, []).append(entry)
            self._recorded_at.setdefault(entry.path, []).append(entry)

    def _meet(self, path, st):
        """Remember which inode the walk found at a name an entry was held for."""
        if path in self._recorded_at:
            self._met[path] = (st.st_dev, st.st_ino)

    def _repair(self, fd, path, mode):
        """Finish what an earlier run's journal says it left widened on the
        inode `fd` holds; the mode the inode carries afterwards (#6006).

        The inode is the one the walk reached inside the scratch tree, so the
        journal never names what gets changed - it can only ask for a change to
        an inode the walk already holds. Entries are unwound newest first, and
        each must find exactly the mode it widened to (put its found mode back)
        or exactly its found mode (already back). Anything else - the owner
        changed it, or the inode number was reused by something else - changes
        NOTHING on this inode and is reported, with every entry kept (#6014)."""
        now = os.fstat(fd)
        entries = [e for e in self._recorded.get((now.st_dev, now.st_ino), ()) if not e.settled]
        if not entries:
            return mode
        current = stat.S_IMODE(now.st_mode)
        for entry in entries:
            entry.settled = True
        try:
            # Putting a recorded mode back is a mode change on this inode, and
            # an inode with a second name may live outside the scratch tree:
            # the change would land on that name too. The widen it undoes was
            # refused on the same grounds (#5936), so this is refused the same
            # way, and the line is kept for a run that meets the inode with one
            # link again (#6025).
            _refuse_a_shared_file(now, "put back from the journal")
        except PermissionError as err:
            self.fail(path, "a previous run recorded widening this inode, and it %s, so nothing is "
                            "changed and the journal line is kept" % err.strerror)
            return current
        if not self._ownable(now):
            self.fail(path, "a previous run recorded widening this inode and this process may not "
                            "chmod it, so nothing is changed and the journal line is kept")
            return current
        target = current
        for entry in reversed(entries):
            if target == entry.widened:
                target = entry.want
            elif target != entry.want:
                self.fail(path, "a previous run recorded widening this inode from 0o%03o to 0o%03o and "
                                "it reads 0o%03o now, which is neither, so its mode is left as it is and "
                                "the journal line is kept" % (entry.want, entry.widened, current))
                return current
        if target != current:
            os.fchmod(fd, target)
            self.repaired.append((path, current, target))
        for entry in entries:
            entry.resolved = True
            self.release(entry.ident, path)
        return target

    def _settle(self):
        """Dispose of every entry the walk did not finish, then let the journal go.

        An entry whose name now holds a different inode is reported and kept.
        One the walk never met is spent - nothing is at that name any more, so
        there is nothing in the tree to put back - but only in a run that met
        everything it looked for: after any
        failure it is kept, because a walk that stopped short proves nothing
        about what it did not reach (#6015)."""
        kept = self._journal_kept
        for entries in self._recorded.values():
            for entry in entries:
                if entry.resolved:
                    continue
                met = self._met.get(entry.path)
                if entry.settled:
                    kept = True
                elif met is not None and met != entry.inode:
                    kept = True
                    self.fail(entry.path, "a previous run recorded widening inode %d:%d here and the "
                                          "name holds a different inode now, so the recorded mode is not "
                                          "this run's to put back; the journal line is kept" % entry.inode)
                elif met is not None or self.failures:
                    kept = True
                    self.fail(entry.path, "a previous run recorded widening this entry from 0o%03o to "
                                          "0o%03o and this walk did not put it back; the journal line is "
                                          "kept" % (entry.want, entry.widened))
                else:
                    entry.resolved = True
                    self.release(entry.ident, entry.path)
                    self.notes.append((entry.path, "a previous run recorded widening it from 0o%03o to "
                                                   "0o%03o, and nothing is at that name in the scratch "
                                                   "tree any more, so there is nothing here to put back; "
                                                   "the journal line is spent" % (entry.want, entry.widened)))
        try:
            self._journal.finish(not kept)
        except OSError as err:
            self.fail(self._journal.path, "could not empty the pending-restore journal after a run "
                                          "that left nothing in it outstanding: %s" % err)

    @staticmethod
    def _ownable(st):
        """True when this process may chmod the inode back into view."""
        euid = os.geteuid()
        return euid == 0 or st.st_uid == euid

    def _open_at(self, dirfd, name, path, st, want_dir, parent):
        """Open `name` under `dirfd` without following symlinks, inside the
        parent directory's search window.

        Returns the descriptor, and nothing this frame widened is still widened
        when it does. A mode that hides the inode flags is answered by widening
        it - the scanning process can chmod its way back in, see `_ownable` -
        and the widen comes off through the descriptor that has just been proven
        to be the scanned inode, before this frame returns. A descriptor keeps
        the access it was opened with, so the caller loses nothing by being
        handed an entry whose mode is exactly what the walk found, and a kill
        during the caller's descent finds no widened mode to leave behind
        (#6006). The widen is appended to the journal before it happens and
        released only once the mode is back, so a kill INSIDE this frame is
        finished by the next run (#6020).

        Every widen in this frame goes through `Widener` and is undone before
        EVERY exit from this frame, by the same route it took. The only other
        widen in the file is `Search`'s, which this frame never performs: it is
        taken on a directory already proven and already held, by the caller.

        What `Widener`'s widen is worth depends on the platform (module
        docstring, #5852). Where the inode can be pinned (Linux), the widen and
        its undo both address the INODE that was scanned, and an entry swapped
        underneath the walk is refused by `Widener` with nothing mutated at all.
        Where it cannot (macOS/BSD), both address the NAME inside an identity
        bracket: a swap that lands before the bracket is refused with nothing
        changed, a swap that lands inside it means some other inode may carry
        the widened mode, and the undo - bracketed the same way - then refuses
        to touch it and reports the mode as left applied (#5812, #5813, #6017).
        EVERY descriptor this frame returns is compared against the inode that
        was scanned - the reopen after a widen and the ordinary open that needed
        none alike - so an entry replaced between the `lstat` that classified it
        and the `open` that acts on it is reported instead of being cleared,
        descended into, or given the scanned entry's mode (#5995)."""
        flags = _OPEN_FLAGS | (os.O_DIRECTORY if want_dir else 0)
        mode = stat.S_IMODE(st.st_mode)
        needed = (stat.S_IRUSR | stat.S_IXUSR) if want_dir else stat.S_IRUSR
        with parent:
            try:
                fd = os.open(name, flags, dir_fd=dirfd)
            except OSError as err:
                if err.errno != errno.EACCES:
                    raise
                if not self._ownable(st):
                    raise PermissionError(errno.EACCES, "not the owner, so the flag state cannot be read")
                _refuse_a_shared_file(st)
                if IS_BSD and st.st_flags & _CHMOD_REFUSING:
                    # This platform refuses a mode change on an append-only or
                    # immutable inode, and the `lstat` already says this one is
                    # flagged, so a flag hidden behind this mode cannot be
                    # reached by widening. Nothing is changed and nothing is
                    # recorded; the report says what blocks it and how to clear
                    # it by hand (#6022).
                    raise OSError(errno.EPERM, "carries flags 0x%x at mode 0o%03o, and this platform "
                                               "refuses a mode change on an append-only or immutable "
                                               "inode, so its flags can be neither read nor cleared "
                                               "through a widen: as its owner run `chflags nouappnd` "
                                               "(and `chflags nouchg` for an immutable flag) on it, "
                                               "then run this again" % (st.st_flags, mode))
                widener = Widener(dirfd, name, st, want_dir)
                try:
                    held = self.hold(path, st, mode, mode | needed)
                    widened = False
                    try:
                        widener.chmod(mode | needed)
                        widened = True
                        fd = os.open(name, flags, dir_fd=dirfd)
                        try:
                            opened = os.fstat(fd)
                            if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                                raise OSError(errno.EIO, "the entry was replaced while it was being inspected")
                        except BaseException:
                            os.close(fd)
                            raise
                    except BaseException:
                        if not widened and not widener.may_have_landed:
                            # The widen was refused before its chmod, or by the
                            # chmod itself: the inode carries exactly the mode
                            # the walk found, so there is nothing to put back,
                            # nothing to report twice and no widen for the line
                            # to describe (#6023, #6028).
                            self.release(held, path)
                            raise
                        # The widen is never abandoned. A widen that raised, a
                        # reopen that raised and an inode that turns out to have
                        # been swapped all put the original mode back before the
                        # failure leaves this frame. A restore that is itself
                        # refused is reported with both modes and keeps its
                        # journal line, and the failure that got here still
                        # propagates - a `KeyboardInterrupt` stays one (#5812,
                        # #5999, #6017).
                        try:
                            widener.chmod(mode)
                        except OSError as undo:
                            if widened:
                                self.fail(path, "the mode this frame widened to 0o%03o is left applied, "
                                                "not the 0o%03o the walk found: putting it back was "
                                                "refused (%s)" % (mode | needed, mode, undo))
                            else:
                                self.fail(path, "the widen to 0o%03o may have landed and putting the "
                                                "0o%03o the walk found back was refused, so the mode it "
                                                "carries is not known; its journal line is kept (%s)"
                                                % (mode | needed, mode, undo))
                        else:
                            self.release(held, path)
                        raise
                finally:
                    widener.close()
                try:
                    # The inode is proven and this frame holds a descriptor on
                    # it, so the widen comes off NOW rather than being held for
                    # the caller's whole descent, where a kill that runs no code
                    # would leave it applied with nothing reported (#6006).
                    os.fchmod(fd, mode)
                except OSError as err:
                    os.close(fd)
                    raise OSError(errno.EPERM, "the mode this frame widened to 0o%03o is left applied: "
                                               "it could not be put back to the 0o%03o the walk found "
                                               "(%s)" % (mode | needed, mode, err))
                self.release(held, path)
                return fd
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                # The name resolved to an inode the caller never classified. It
                # is closed and reported, never cleared and never descended
                # into: its flags, its mode and its contents are all somebody
                # else's (#5995).
                os.close(fd)
                raise OSError(errno.EIO, "the entry was replaced while it was being inspected")
            return fd

    def _clear_fd(self, fd, path):
        """Clear the append-only bit on `fd`, then PROVE the name is unlinkable."""
        flags = get_flags(fd)
        if flags is None or not flags & BLOCKING:
            return
        st = os.fstat(fd)
        if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
            self.fail(path, "flagged file has %d links, so its inode may live outside the "
                            "scratch tree; refusing to clear" % st.st_nlink)
            return
        if flags & CLEARABLE:
            set_flags(fd, flags & ~CLEARABLE)
            self.cleared.append(path)
        remaining = get_flags(fd)
        if remaining is None:
            self.fail(path, "flags became unreadable after the clear (were 0x%x)" % flags)
        elif remaining & BLOCKING:
            self.fail(path, "still un-unlinkable after the clear (flags 0x%x)" % remaining)

    def _symlink(self, path, st):
        """Symlinks are never followed and their own flags are never cleared: a
        clear would have to re-resolve the path. A flagged symlink still blocks
        unlink, so it is reported rather than ignored."""
        if IS_BSD and st.st_flags & BLOCKING:
            self.fail(path, "symlink carries an append/immutable flag (0x%x); a flag is never "
                            "cleared through a symlink" % st.st_flags)

    def _visit(self, dirfd, name, path, st, parent):
        if stat.S_ISLNK(st.st_mode):
            self._symlink(path, st)
            return
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
            return  # fifo / socket / device: no inode flag can block its unlink
        if (IS_BSD and stat.S_ISREG(st.st_mode) and st.st_nlink > 1 and not st.st_flags & BLOCKING
                and (st.st_dev, st.st_ino) not in self._recorded):
            # The `lstat` already carries the flags here and none of them
            # blocks an unlink, so a file whose inode may also live outside the
            # scratch tree is left exactly as it is - opened, widened or
            # otherwise (#5936).
            return
        want_dir = stat.S_ISDIR(st.st_mode)
        try:
            fd = self._open_at(dirfd, name, path, st, want_dir, parent)
        except FileNotFoundError:
            return
        except OSError as err:
            self.fail(path, "could not inspect: %s" % err)
            return
        try:
            mode = self._repair(fd, path, stat.S_IMODE(st.st_mode))
            self._clear_fd(fd, path)
            if want_dir:
                search = _NO_SEARCH
                if not mode & stat.S_IXUSR and self._ownable(st):
                    # A directory this process cannot search has to be widened
                    # to look an entry up BY NAME - and only for that lookup.
                    # Held across the descent, as it used to be, a kill that
                    # runs no code left the mode added with nothing reported;
                    # `Search` widens around one lookup at a time and journals
                    # the outstanding widen first (#6006).
                    search = Search(self, fd, path, st, mode)
                try:
                    self._walk(fd, path, search)
                finally:
                    search.release()
        except OSError as err:
            self.fail(path, "could not clear or descend: %s" % err)
        finally:
            os.close(fd)

    def _walk(self, dirfd, path, search):
        # `os.listdir` reads the descriptor this walk already holds, so it needs
        # no mode on the directory at all. Only the per-name lookup does, and
        # that - plus the open in `_open_at` - is the whole of what `search`
        # widens for (#6006).
        for name in sorted(os.listdir(dirfd)):
            child = os.path.join(path, name)
            with search:
                try:
                    st = os.lstat(name, dir_fd=dirfd)
                except FileNotFoundError:
                    continue
                except OSError as err:
                    self.fail(child, "could not stat, so a flag on it cannot be ruled out: %s" % err)
                    continue
            self._meet(child, st)
            self._visit(dirfd, name, child, st, search)

def clear_tree(top):
    """Clear append-only under `top`. Returns (cleared, repaired, failures)."""
    cleaner = Cleaner()
    cleaner.run(top)
    return cleaner.cleared, cleaner.repaired, cleaner.failures, cleaner.notes


def _say(text, stream=None):
    stream = sys.stdout if stream is None else stream
    print(_shown(text, stream), file=stream)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--root", default=os.environ.get("GITHUB_WORKSPACE", os.getcwd()))
    args = parser.parse_args(argv)
    top = os.path.join(args.root, SCRATCH_DIR)
    if not os.path.isdir(top) or os.path.islink(top):
        # A symlinked scratch root is refused, not absent: say which it was so
        # the log cannot be read as "the janitor found nothing here" (#5657).
        why = "is a symlink and is never followed" if os.path.islink(top) else "is not there"
        _say("clear-append-only-scratch: %s under %s %s; nothing to do" % (SCRATCH_DIR, args.root, why))
        return 0
    cleared, repaired, failures, notes = clear_tree(top)
    for path in cleared:
        _say("clear-append-only-scratch: cleared append-only on %s" % path)
    for path, applied, want in repaired:
        # A repair is this run finishing what a killed one started, so it is
        # named even though nothing is wrong by the time anyone reads it (#6006).
        _say("clear-append-only-scratch: put mode 0o%03o back on %s, which a previous run left "
             "at 0o%03o" % (want, path, applied))
    for path, why in notes:
        _say("clear-append-only-scratch: %s: %s" % (path, why))
    for path, why in failures:
        _say("::error::clear-append-only-scratch: could not clear %s: %s" % (path, why), sys.stderr)
    _say("clear-append-only-scratch: %d cleared, %d failed" % (len(cleared), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
