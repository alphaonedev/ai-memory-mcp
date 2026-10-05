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
the next job starts) and clears ONLY the append-only bit, in place, without
following symlinks. It makes the cleanup idempotent: a clean tree is a no-op.

The workflow runs this BEFORE `actions/checkout`, when the repository may not be
on disk yet, so the workflow step carries a byte-identical inline copy of this
file; `scripts/test/test_clear_append_only_scratch_5657.py` pins the two equal.

Exit codes: 0 = nothing flagged or every flag cleared; 1 = a flag remains that
could not be cleared (named on stderr, as a workflow `::error::`); 2 = bad usage.
Python 3.9+, standard library only.
"""
import argparse
import os
import stat
import struct
import sys

SCRATCH_DIR = ".local-runs"
# Linux ext*/xfs/btrfs inode flag; `chflags uappnd` is the macOS/BSD equivalent.
FS_APPEND_FL = 0x0000_0020


def _linux_ioctl_numbers():
    """FS_IOC_GETFLAGS / FS_IOC_SETFLAGS = _IOR/_IOW('f', 1|2, long)."""
    size = struct.calcsize("l")

    def ioc(direction, nr):
        return (direction << 30) | (size << 16) | (ord("f") << 8) | nr

    return ioc(2, 1), ioc(1, 2)  # _IOC_READ=2, _IOC_WRITE=1


def _clear_bsd(path, st):
    """macOS/BSD: drop UF_APPEND with lchflags (never follows a symlink)."""
    flag = getattr(stat, "UF_APPEND", 0)
    if not flag or not st.st_flags & flag:
        return False
    os.lchflags(path, st.st_flags & ~flag)
    return True


def _clear_linux(path, st):
    """Linux: FS_IOC_GETFLAGS then FS_IOC_SETFLAGS without FS_APPEND_FL."""
    import fcntl

    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        return False
    get_req, set_req = _linux_ioctl_numbers()
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        buf = bytearray(struct.pack("l", 0))
        fcntl.ioctl(fd, get_req, buf, True)
        (flags,) = struct.unpack("l", bytes(buf))
        if not flags & FS_APPEND_FL:
            return False
        fcntl.ioctl(fd, set_req, struct.pack("l", flags & ~FS_APPEND_FL))
        return True
    finally:
        os.close(fd)


def clear_tree(top):
    """Clear append-only under `top`. Returns (cleared, failures)."""
    cleared = []
    failures = []
    clear = _clear_bsd if hasattr(os, "lchflags") else _clear_linux
    candidates = [top]
    for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
        candidates.extend(os.path.join(dirpath, name) for name in dirnames + filenames)
    for path in candidates:
        try:
            st = os.lstat(path)
            if clear(path, st):
                cleared.append(path)
        except FileNotFoundError:
            continue
        except OSError as err:  # EPERM without CAP_LINUX_IMMUTABLE, ENOTTY, ...
            if getattr(err, "errno", None) in (25, 95):  # ENOTTY / EOPNOTSUPP: fs has no flag
                continue
            failures.append((path, str(err)))
    return cleared, failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--root", default=os.environ.get("GITHUB_WORKSPACE", os.getcwd()))
    args = parser.parse_args(argv)
    top = os.path.join(args.root, SCRATCH_DIR)
    if not os.path.isdir(top) or os.path.islink(top):
        print("clear-append-only-scratch: no %s under %s; nothing to do" % (SCRATCH_DIR, args.root))
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
