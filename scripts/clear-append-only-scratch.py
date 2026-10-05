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
  `actions/checkout` would have cleaned by itself.
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
platform allows. What that buys differs by platform, and the difference matters:

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

Every exit from the widen puts the widened mode back - a reopen that raised, an
inode that turns out to have been swapped, and the ordinary success. What that
is worth, again, differs by platform. Where the inode is pinned, the restore
addresses the INODE that was scanned, so nothing this walk widened is left
widened (#5812). Where it is not, the restore after a SUCCESSFUL reopen goes
through the descriptor that was proven to be the scanned inode - so the common
path is inode-bound on both platforms - but on the failure exits the name is all
there is, and if the name was taken away inside the bracket around the widening
chmod, the inode that was widened can no longer be addressed at all. That mode
is then left applied, and the run SAYS so: the path and the mode go to stderr as
a workflow `::error::` and the exit code is non-zero, because an abandoned widen
that is named is recoverable and one that is silent is not (#5812, #5852). A
reopen after a widening chmod is still checked against the inode that was
scanned. Symlinks are never
followed and their flags are never cleared (a clear would have to go back
through a path); a flagged symlink is reported instead. A
flagged regular file with more than one link is refused, because its inode may
also live outside the scratch tree.

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

    Where there is no `O_PATH`, `fchmodat(AT_SYMLINK_NOFOLLOW)` relative to the
    already-open parent descriptor cannot traverse a symlink either, but it
    addresses a NAME and not the scanned inode: nothing is pinned, no identity
    check is taken, and an entry swapped between the scan and the widen - or a
    hardlink planted at that name - is mutated instead. Not leaving this
    directory is a property of the namespace, not of the inode, so this leg is
    strictly weaker than the Linux one (#5852). A platform with neither
    mechanism gets no widen: the entry is reported, never mutated through a
    resolvable path."""

    def __init__(self, dirfd, name, st, want_dir):
        self._dirfd = dirfd
        self._name = name
        self._st = st
        self._fd = None
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
            pinned = os.fstat(fd)
            if (pinned.st_dev, pinned.st_ino) != (st.st_dev, st.st_ino):
                os.close(fd)
                raise OSError(errno.EIO, "the entry was replaced while it was being inspected")
            self._fd = fd
        elif not CAN_CHMOD_NOFOLLOW:
            raise OSError(errno.EPERM, "no way to widen a mode here without re-resolving the name")

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

    def chmod(self, mode):
        """Set `mode` on the pinned inode, or - with no `O_PATH` - on the entry
        itself without following a symlink, bracketed by two identity reads."""
        if self._fd is None:
            # Before: nothing has been mutated yet, so a mismatch is a clean
            # refusal and the error is allowed to say exactly that.
            self._identity()
            try:
                os.chmod(self._name, mode, dir_fd=self._dirfd, follow_symlinks=False)
            except NotImplementedError:
                # The interpreter refuses this combination here. Widening by a
                # name that would be re-resolved is not an acceptable fallback,
                # so the entry is reported instead of being mutated.
                raise OSError(errno.EPERM, "no way to widen a mode here without re-resolving the name")
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
            try:
                os.chmod("%s/%d" % (FD_DIR, self._fd), mode)
            except OSError as err:
                # Never `FileNotFoundError` out of here. The caller reads that
                # as "the entry went away" and returns WITHOUT reporting
                # anything, so a procfs that is missing or refusing would print
                # `0 cleared, 0 failed` over a flag that is still set (#5996).
                raise OSError(errno.EPERM, "could not set mode 0o%03o on the pinned inode "
                                           "through %s: %s" % (mode, FD_DIR, err))
            landed = stat.S_IMODE(os.fstat(self._fd).st_mode)
            if landed != mode:
                raise OSError(errno.EPERM, "mode 0o%03o did not take on the pinned inode, "
                                           "which reads 0o%03o" % (mode, landed))

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


class Cleaner:
    """Depth-first clear over one scratch tree. Collects cleared paths and
    failures; never raises out of `run`."""

    def __init__(self):
        self.cleared = []
        self.failures = []

    def fail(self, path, why):
        self.failures.append((path, str(why)))

    def run(self, top):
        try:
            st = os.lstat(top)
        except OSError as err:
            self.fail(top, "could not stat the scratch root: %s" % err)
            return
        self._visit(None, top, top, st)

    @staticmethod
    def _ownable(st):
        """True when this process may chmod the inode back into view."""
        euid = os.geteuid()
        return euid == 0 or st.st_uid == euid

    def _open_at(self, dirfd, name, path, st, want_dir):
        """Open `name` under `dirfd` without following symlinks.

        Returns `(fd, mode_to_restore)`. A mode that hides the inode flags is
        answered by widening it - the scanning process can chmod its way back
        in, see `_ownable` - and the caller restores the original mode through
        the descriptor. Every widen here goes through `Widener` and is undone
        before EVERY failure exit from this frame, by the same route it took.
        What that is worth depends on the platform (module docstring, #5852):
        where the inode can be pinned, the widen and its undo both address the
        INODE that was scanned, and an entry swapped underneath the walk is
        refused by `Widener` with nothing mutated at all; where it cannot, both
        address the NAME, so a swap between the scan and the widen means some
        other inode is widened and is then set to the SCANNED entry's mode
        rather than to its own (#5812, #5813). EVERY descriptor this frame
        returns is compared against the inode that was scanned - the reopen
        after a widen and the ordinary open that needed none alike - so an
        entry replaced between the `lstat` that classified it and the `open`
        that acts on it is reported instead of being cleared, descended into,
        or given the scanned entry's mode (#5995)."""
        flags = _OPEN_FLAGS | (os.O_DIRECTORY if want_dir else 0)
        mode = stat.S_IMODE(st.st_mode)
        needed = (stat.S_IRUSR | stat.S_IXUSR) if want_dir else stat.S_IRUSR
        try:
            fd = os.open(name, flags, dir_fd=dirfd)
        except OSError as err:
            if err.errno != errno.EACCES:
                raise
            if not self._ownable(st):
                raise PermissionError(errno.EACCES, "not the owner, so the flag state cannot be read")
            widener = Widener(dirfd, name, st, want_dir)
            try:
                widener.chmod(mode | needed)
                try:
                    fd = os.open(name, flags, dir_fd=dirfd)
                    opened = os.fstat(fd)
                    if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                        os.close(fd)
                        raise OSError(errno.EIO, "the entry was replaced while it was being inspected")
                except BaseException:
                    # The widen is never abandoned. A reopen that raised and an
                    # inode that turns out to have been swapped both put the
                    # original mode back before the failure leaves this frame;
                    # a restore that itself fails replaces the error, so a
                    # widen abandoned HERE is never silent. The caller's own
                    # restore is quieter on purpose - see `_visit`.
                    widener.chmod(mode)
                    raise
            finally:
                widener.close()
            return fd, mode
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
            # The name resolved to an inode the caller never classified. It is
            # closed and reported, never cleared and never descended into: its
            # flags, its mode and its contents are all somebody else's (#5995).
            os.close(fd)
            raise OSError(errno.EIO, "the entry was replaced while it was being inspected")
        if want_dir and (mode & needed) != needed and self._ownable(st):
            # Readable enough to open, not searchable enough to stat its
            # entries (mode 0o400): widen on the descriptor, never by path.
            try:
                os.fchmod(fd, mode | needed)
                return fd, mode
            except OSError:
                pass
        return fd, None

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

    def _visit(self, dirfd, name, path, st):
        if stat.S_ISLNK(st.st_mode):
            self._symlink(path, st)
            return
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
            return  # fifo / socket / device: no inode flag can block its unlink
        want_dir = stat.S_ISDIR(st.st_mode)
        try:
            fd, restore = self._open_at(dirfd, name, path, st, want_dir)
        except FileNotFoundError:
            return
        except OSError as err:
            self.fail(path, "could not inspect: %s" % err)
            return
        try:
            self._clear_fd(fd, path)
            if want_dir:
                self._walk(fd, path)
        except OSError as err:
            self.fail(path, "could not clear or descend: %s" % err)
        finally:
            if restore is not None:
                # Reported, like the restore inside `_open_at`, and for the
                # same reason: a mode this walk added and could not take off is
                # something it changed and cannot account for. `fail` only
                # appends, so it cannot replace the verdict `_clear_fd` already
                # reached from this same descriptor - which was the whole
                # objection to reporting from a `finally` - and it makes `main`
                # exit non-zero. Silence here was "0 failed" over an inode left
                # more permissive than the walk found it, which is the #5657
                # shape with a mode in place of a flag (#6002).
                try:
                    os.fchmod(fd, restore)
                except OSError as err:
                    try:
                        applied = "0o%03o" % stat.S_IMODE(os.fstat(fd).st_mode)
                    except OSError:
                        applied = "a mode that could no longer be read back"
                    self.fail(path, "the mode this walk widened is left applied (%s, not the "
                                    "0o%03o the walk found): %s" % (applied, restore, err))
            os.close(fd)

    def _walk(self, dirfd, path):
        for name in sorted(os.listdir(dirfd)):
            child = os.path.join(path, name)
            try:
                st = os.lstat(name, dir_fd=dirfd)
            except FileNotFoundError:
                continue
            except OSError as err:
                self.fail(child, "could not stat, so a flag on it cannot be ruled out: %s" % err)
                continue
            self._visit(dirfd, name, child, st)


def clear_tree(top):
    """Clear append-only under `top`. Returns (cleared, failures)."""
    cleaner = Cleaner()
    cleaner.run(top)
    return cleaner.cleared, cleaner.failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--root", default=os.environ.get("GITHUB_WORKSPACE", os.getcwd()))
    args = parser.parse_args(argv)
    top = os.path.join(args.root, SCRATCH_DIR)
    if not os.path.isdir(top) or os.path.islink(top):
        # A symlinked scratch root is refused, not absent: say which it was so
        # the log cannot be read as "the janitor found nothing here" (#5657).
        why = "is a symlink and is never followed" if os.path.islink(top) else "is not there"
        print("clear-append-only-scratch: %s under %s %s; nothing to do" % (SCRATCH_DIR, args.root, why))
        return 0
    cleared, failures = clear_tree(top)
    for path in cleared:
        print("clear-append-only-scratch: cleared append-only on %s" % path)
    for path, why in failures:
        print("::error::clear-append-only-scratch: could not clear %s: %s" % (path, why), file=sys.stderr)
    print("clear-append-only-scratch: %d cleared, %d failed" % (len(cleared), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
