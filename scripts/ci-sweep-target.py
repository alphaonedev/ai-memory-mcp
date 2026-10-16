#!/usr/bin/env python3
"""Cap the size of a self-hosted runner's ``target/debug`` build state (#7160).

Self-hosted jobs reuse the checkout's ``target/`` between runs, so
``target/debug/deps`` and friends grow without bound. This sweep sizes the
top-level entries of exactly four directories under ``<target>/debug``
(``deps``, ``incremental``, ``build``, ``.fingerprint``) and deletes the
oldest-mtime entries until the total is at or under ``--max-bytes``.

Safety:
  * ``--target`` must resolve (realpath) under ``$GITHUB_WORKSPACE`` unless
    ``--allow-root`` is given (node cron); otherwise exit 2 naming the path.
  * ``<target>/debug`` and the four swept directories must not be symlinks:
    otherwise exit 2 naming the path and nothing is deleted.
  * Each swept directory is opened once (``O_NOFOLLOW | O_DIRECTORY``) and
    every scan and every delete is relative to that handle (``dir_fd``), so a
    directory swapped for a symlink after the scan is never followed. A swept
    directory that is no longer the directory that was scanned is refused
    (exit 2) before anything is deleted from it.
  * Symlink entries inside a swept directory are unlinked, never descended.
  * Nothing outside the four directories is read for sizing or deleted.
  * An unreadable directory or entry, or a tree too deep to walk (a
    RecursionError), at any depth, is reported as
    ``warning: cannot read <path>`` (or ``cannot size`` / ``cannot remove``)
    naming the path and skipped; no traceback.

Exit codes: 0 success, 2 refused path, 3 ``--max-bytes`` is zero or negative,
4 nothing could be sized because every swept directory or entry was
unreadable, 5 usage error (a missing, unknown or unparsable argument such as
``--max-bytes abc`` or an empty ``--max-bytes``; ``--help`` exits 0).
"""

import argparse
import errno
import os
import stat
import sys

DEBUG_DIR_NAME = "debug"
SWEPT_SUBDIRS = ("deps", "incremental", "build", ".fingerprint")
WORKSPACE_ENV = "GITHUB_WORKSPACE"
EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_BAD_CAP = 3
EXIT_UNREADABLE = 4
EXIT_USAGE = 5
# errno values open() reports for a symlink (or non-directory) met under
# O_NOFOLLOW | O_DIRECTORY; Linux reports ENOTDIR, macOS reports ELOOP.
SWAPPED_ERRNOS = (errno.ELOOP, errno.ENOTDIR)
OPEN_DIR_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY


class UsageParser(argparse.ArgumentParser):
    """ArgumentParser whose parse errors exit EXIT_USAGE, not the refused-path code."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, "{}: error: {}\n".format(self.prog, message))


class Refused(Exception):
    """A swept path is a symlink or was swapped after the scan."""


class SweptDir(object):
    """An open swept directory: its path, handle and the identity it had at open."""

    def __init__(self, path, fd, dev, ino):
        self.path = path
        self.fd = fd
        self.dev = dev
        self.ino = ino


def open_dir(name, dir_fd=None):
    """Open a directory without following a symlink in its final component."""
    return os.open(name, OPEN_DIR_FLAGS, dir_fd=dir_fd)


def entry_size(dir_fd, name, path, warnings):
    """Bytes under ``name`` (relative to ``dir_fd``) without following symlinks.

    A symlink counts as itself. A nested directory that cannot be listed is
    appended to ``warnings`` (same wording as the top-level unreadable-directory
    warning) and counts as its own size only.
    """
    st = os.lstat(name, dir_fd=dir_fd)
    if not stat.S_ISDIR(st.st_mode):
        return st.st_size
    total = st.st_size
    try:
        child_fd = open_dir(name, dir_fd)
    except OSError as exc:
        warnings.append("cannot read {}: {}".format(path, exc))
        return total
    try:
        try:
            with os.scandir(child_fd) as it:
                children = list(it)
        except OSError as exc:
            warnings.append("cannot read {}: {}".format(path, exc))
            return total
        for child in children:
            try:
                child_path = os.path.join(path, child.name)
                total += entry_size(child_fd, child.name, child_path, warnings)
            except (OSError, RecursionError) as exc:
                warnings.append("cannot size {}/{}: {}".format(path, child.name, exc))
    finally:
        os.close(child_fd)
    return total


def is_under(path, root):
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def open_swept_dirs(target, warnings, handles):
    """Open the existing swept directories; raise Refused on any symlink.

    Every opened descriptor is appended to ``handles`` for the caller to close.
    """
    debug_path = os.path.join(target, DEBUG_DIR_NAME)
    try:
        debug_st = os.lstat(debug_path)
    except FileNotFoundError:
        return []
    except OSError as exc:
        warnings.append("cannot read {}: {}".format(debug_path, exc))
        return []
    if stat.S_ISLNK(debug_st.st_mode):
        raise Refused("{} is a symlink".format(debug_path))
    if not stat.S_ISDIR(debug_st.st_mode):
        return []
    try:
        debug_fd = open_dir(debug_path)
    except OSError as exc:
        if exc.errno in SWAPPED_ERRNOS:
            raise Refused("{} is a symlink".format(debug_path))
        warnings.append("cannot read {}: {}".format(debug_path, exc))
        return []
    handles.append(debug_fd)
    found = []
    for sub in SWEPT_SUBDIRS:
        path = os.path.join(debug_path, sub)
        try:
            st = os.lstat(sub, dir_fd=debug_fd)
        except FileNotFoundError:
            continue
        except OSError as exc:
            warnings.append("cannot read {}: {}".format(path, exc))
            continue
        if stat.S_ISLNK(st.st_mode):
            raise Refused("{} is a symlink".format(path))
        if not stat.S_ISDIR(st.st_mode):
            continue
        try:
            fd = open_dir(sub, debug_fd)
        except OSError as exc:
            if exc.errno in SWAPPED_ERRNOS:
                raise Refused("{} is a symlink".format(path))
            warnings.append("cannot read {}: {}".format(path, exc))
            continue
        handles.append(fd)
        opened = os.fstat(fd)
        found.append(SweptDir(path, fd, opened.st_dev, opened.st_ino))
    return found


def collect_entries(target, warnings, handles):
    """Return (mtime, path, swept_dir, name, size) for each top-level entry.

    Unreadable directories and entries are appended to ``warnings`` and skipped.
    Descriptors stay open in ``handles`` so the delete phase reuses them.
    """
    entries = []
    for sdir in open_swept_dirs(target, warnings, handles):
        try:
            with os.scandir(sdir.fd) as it:
                children = list(it)
        except OSError as exc:
            warnings.append("cannot read {}: {}".format(sdir.path, exc))
            continue
        for child in children:
            child_path = os.path.join(sdir.path, child.name)
            try:
                mtime = child.stat(follow_symlinks=False).st_mtime
                size = entry_size(sdir.fd, child.name, child_path, warnings)
            except (OSError, RecursionError) as exc:
                warnings.append("cannot size {}: {}".format(child_path, exc))
                continue
            entries.append((mtime, child_path, sdir, child.name, size))
    entries.sort(key=lambda item: (item[0], item[1]))
    return entries


def verify_unchanged(sdir):
    """Refuse when the swept path no longer names the directory that was scanned."""
    try:
        now = os.lstat(sdir.path)
    except OSError as exc:
        raise Refused("{} cannot be re-checked before delete: {}".format(sdir.path, exc))
    if stat.S_ISLNK(now.st_mode) or not stat.S_ISDIR(now.st_mode) \
            or (now.st_dev, now.st_ino) != (sdir.dev, sdir.ino):
        raise Refused("{} was replaced after the scan".format(sdir.path))


def remove_tree(parent_fd, name):
    """Remove directory ``name`` under ``parent_fd`` using only descriptor-relative calls."""
    fd = open_dir(name, parent_fd)
    try:
        with os.scandir(fd) as it:
            names = [child.name for child in it]
        for child in names:
            if stat.S_ISDIR(os.lstat(child, dir_fd=fd).st_mode):
                remove_tree(fd, child)
            else:
                os.unlink(child, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent_fd)


def remove_entry(sdir, name):
    if stat.S_ISDIR(os.lstat(name, dir_fd=sdir.fd).st_mode):
        remove_tree(sdir.fd, name)
    else:
        os.unlink(name, dir_fd=sdir.fd)


def sweep(real_target, args, warnings, handles):
    """Scan, then delete oldest first; return (exit_code_or_None, before, remaining, removed)."""
    entries = collect_entries(real_target, warnings, handles)
    for line in warnings:
        print("warning: {}".format(line), file=sys.stderr)
    before = sum(item[4] for item in entries)
    remaining = before
    removed = 0
    verified = set()
    for _mtime, path, sdir, name, size in entries:
        if remaining <= args.max_bytes:
            break
        if not args.dry_run:
            if id(sdir) not in verified:
                verify_unchanged(sdir)
                verified.add(id(sdir))
            try:
                remove_entry(sdir, name)
            except (OSError, RecursionError) as exc:
                print("warning: cannot remove {}: {}".format(path, exc), file=sys.stderr)
                continue
        remaining -= size
        removed += 1
    code = EXIT_UNREADABLE if warnings and not entries else EXIT_OK
    return code, before, remaining, removed


def main(argv=None):
    parser = UsageParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", required=True, help="cargo target directory")
    parser.add_argument("--max-bytes", required=True, type=int, help="size cap in bytes")
    parser.add_argument("--allow-root", action="store_true",
                        help="permit a target outside $GITHUB_WORKSPACE (node cron)")
    parser.add_argument("--dry-run", action="store_true", help="report only; delete nothing")
    args = parser.parse_args(argv)
    if args.max_bytes <= 0:
        print("usage: --max-bytes must be a positive integer, got {}".format(
            args.max_bytes), file=sys.stderr)
        return EXIT_BAD_CAP

    real_target = os.path.realpath(args.target)
    if not args.allow_root:
        workspace = os.environ.get(WORKSPACE_ENV)
        real_ws = os.path.realpath(workspace) if workspace else None
        if real_ws is None or not is_under(real_target, real_ws):
            print("refused: {} is not under {} (use --allow-root)".format(
                real_target, WORKSPACE_ENV), file=sys.stderr)
            return EXIT_REFUSED

    warnings = []
    handles = []
    try:
        code, before, remaining, removed = sweep(real_target, args, warnings, handles)
    except Refused as exc:
        print("refused: {}".format(exc), file=sys.stderr)
        return EXIT_REFUSED
    finally:
        for fd in handles:
            try:
                os.close(fd)
            except OSError:
                pass
    print("ci-sweep-target: target={} cap={} before={} after={} removed={}{}".format(
        real_target, args.max_bytes, before, remaining, removed,
        " (dry-run)" if args.dry_run else ""))
    return code


if __name__ == "__main__":
    sys.exit(main())
