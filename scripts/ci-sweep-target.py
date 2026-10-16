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
    Under ``--allow-root`` the target must already be canonical (it equals its
    own realpath, no symlink in any component) or exit 2 ``is not a canonical
    path``.
  * ``<target>/debug`` and the four swept directories must not be symlinks:
    otherwise exit 2 naming the path and nothing is deleted. A target path
    component that is not a directory (``--target`` names a regular file) exits
    2 with ``refused: <path> is not a directory``.
  * The target is opened once by a descriptor walk from ``/``: every path
    component (target, ``debug``, each swept directory) is opened relative to
    its parent with ``O_NOFOLLOW | O_DIRECTORY``, and every scan and every
    delete is relative to those handles (``dir_fd``). No path is looked up
    twice, so a component swapped for a symlink before the open, after the scan
    or during removal is never followed. A component that is no longer the
    directory that was opened is refused (exit 2) before anything is deleted.
  * Symlink entries inside a swept directory are unlinked, never descended.
  * Nothing outside the four directories is read for sizing or deleted.
  * An unreadable directory or entry at any depth is reported as
    ``warning: cannot read <path>`` (or ``cannot size`` / ``cannot remove``)
    naming the path and skipped; no traceback.
  * A top-level entry whose tree is deeper than ``MAX_TREE_DEPTH`` levels (or
    that hits a RecursionError) is skipped as a whole: one
    ``warning: cannot size <entry>: ... skipped`` names the entry, it is never
    counted and never on the delete list, so none of it is deleted (a partly
    deleted cargo output is worse than an oversized one).

Exit codes: 0 success, 2 refused path (target outside the workspace, a
symlinked or swapped component, a target path component that is not a
directory, or a non-canonical ``--allow-root`` target), 3 ``--max-bytes`` is zero or negative,
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
# Deeper than this an entry is skipped whole. Sizing and removal both recurse
# one frame per level, so a tree sized within this depth is also removable
# within it and removal can never stop half way on the interpreter limit.
MAX_TREE_DEPTH = 300
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
    """An open directory: its path, handle and the identity it had at open.

    ``parent_fd`` and ``name`` say how it was reached (``None`` for ``/``);
    ``chain`` lists every held directory from ``/`` down to this one, so the
    whole walk can be re-checked through descriptors, never through a path.
    """

    def __init__(self, path, fd, parent_fd, name, chain):
        opened = os.fstat(fd)
        self.path = path
        self.fd = fd
        self.parent_fd = parent_fd
        self.name = name
        self.dev = opened.st_dev
        self.ino = opened.st_ino
        self.chain = chain + [self]


def open_dir(name, dir_fd=None):
    """Open a directory without following a symlink in its final component."""
    return os.open(name, OPEN_DIR_FLAGS, dir_fd=dir_fd)


class TooDeep(Exception):
    """An entry's tree is deeper than MAX_TREE_DEPTH."""


class SkippedWarning(str):
    """A warning for an entry skipped whole as too deep; it is not an unreadable-directory failure."""


def entry_size(dir_fd, name, path, warnings, depth=0):
    """Bytes under ``name`` (relative to ``dir_fd``) without following symlinks.

    A symlink counts as itself. A nested directory that cannot be listed is
    appended to ``warnings`` (same wording as the top-level unreadable-directory
    warning) and counts as its own size only. TooDeep (or RecursionError) is
    never caught here: it propagates so the caller drops the whole entry.
    """
    st = os.lstat(name, dir_fd=dir_fd)
    if not stat.S_ISDIR(st.st_mode):
        return st.st_size
    if depth >= MAX_TREE_DEPTH:
        raise TooDeep("deeper than {} levels".format(MAX_TREE_DEPTH))
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
                total += entry_size(child_fd, child.name, child_path, warnings,
                                    depth + 1)
            except OSError as exc:
                warnings.append("cannot size {}/{}: {}".format(path, child.name, exc))
    finally:
        os.close(child_fd)
    return total


def is_under(path, root):
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def not_openable_message(parent, component, path):
    """Say why ``component`` under the held ``parent`` could not be opened as a directory.

    The target is a realpath, so a symlink here was swapped in after the check;
    anything else that is not a directory (a regular file) was never one.
    """
    try:
        kind = os.lstat(component, dir_fd=parent.fd).st_mode
    except OSError:
        kind = None
    if kind is not None and not stat.S_ISLNK(kind):
        return "{} is not a directory".format(path)
    return "{} was replaced by a symlink before it could be opened".format(path)


def open_target(real_target, warnings, handles):
    """Open ``real_target`` by walking it from ``/`` one component at a time.

    Each component is opened relative to its parent with ``O_NOFOLLOW |
    O_DIRECTORY``, so a component swapped for a symlink (or any non-directory)
    after the realpath check is refused, never followed. Returns the held
    ``SweptDir`` for the target, or ``None`` when the target does not exist or
    cannot be read (the latter is also appended to ``warnings``).
    """
    root_fd = open_dir(os.sep)
    handles.append(root_fd)
    held = SweptDir(os.sep, root_fd, None, None, [])
    path = os.sep
    for component in [part for part in real_target.split(os.sep) if part]:
        path = os.path.join(path, component)
        try:
            fd = open_dir(component, held.fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            if exc.errno in SWAPPED_ERRNOS:
                raise Refused(not_openable_message(held, component, path))
            warnings.append("cannot read {}: {}".format(path, exc))
            return None
        handles.append(fd)
        held = SweptDir(path, fd, held.fd, component, held.chain)
    return held


def open_child(parent, name, warnings, handles):
    """Open directory ``name`` under the held ``parent``; None when absent or not a directory.

    Raises Refused when ``name`` is a symlink or is swapped for one while opening.
    """
    path = os.path.join(parent.path, name)
    try:
        st = os.lstat(name, dir_fd=parent.fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        warnings.append("cannot read {}: {}".format(path, exc))
        return None
    if stat.S_ISLNK(st.st_mode):
        raise Refused("{} is a symlink".format(path))
    if not stat.S_ISDIR(st.st_mode):
        return None
    try:
        fd = open_dir(name, parent.fd)
    except OSError as exc:
        if exc.errno in SWAPPED_ERRNOS:
            raise Refused("{} is a symlink".format(path))
        warnings.append("cannot read {}: {}".format(path, exc))
        return None
    handles.append(fd)
    return SweptDir(path, fd, parent.fd, name, parent.chain)


def open_swept_dirs(real_target, warnings, handles):
    """Open the existing swept directories; raise Refused on any symlink.

    The target, ``debug`` and each swept directory are reached through one
    descriptor walk (no path is looked up twice). Every opened descriptor is
    appended to ``handles`` for the caller to close.
    """
    target = open_target(real_target, warnings, handles)
    if target is None:
        return []
    debug = open_child(target, DEBUG_DIR_NAME, warnings, handles)
    if debug is None:
        return []
    found = []
    for sub in SWEPT_SUBDIRS:
        swept = open_child(debug, sub, warnings, handles)
        if swept is not None:
            found.append(swept)
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
            except (TooDeep, RecursionError) as exc:
                warnings.append(SkippedWarning(
                    "cannot size {}: too deep to walk ({}); entry skipped, nothing "
                    "of it deleted".format(child_path, exc)))
                continue
            except OSError as exc:
                warnings.append("cannot size {}: {}".format(child_path, exc))
                continue
            entries.append((mtime, child_path, sdir, child.name, size))
    entries.sort(key=lambda item: (item[0], item[1]))
    return entries


def verify_unchanged(sdir):
    """Refuse when any held directory on the walk was replaced after the scan.

    Every link of the chain (``/`` to the swept directory) is looked up by name
    relative to the descriptor of its parent and compared with ``os.fstat`` of
    the handle that was opened; no full path is resolved.
    """
    for held in sdir.chain:
        if held.parent_fd is None:
            continue
        try:
            now = os.lstat(held.name, dir_fd=held.parent_fd)
            opened = os.fstat(held.fd)
        except OSError as exc:
            raise Refused("{} cannot be re-checked before delete: {}".format(held.path, exc))
        if stat.S_ISLNK(now.st_mode) or not stat.S_ISDIR(now.st_mode) \
                or (now.st_dev, now.st_ino) != (opened.st_dev, opened.st_ino):
            raise Refused("{} was replaced after the scan".format(held.path))


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
    unreadable = [line for line in warnings if not isinstance(line, SkippedWarning)]
    code = EXIT_UNREADABLE if unreadable and not entries else EXIT_OK
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
    elif real_target != os.path.normpath(os.path.abspath(args.target)):
        print("refused: {} is not a canonical path (it resolves to {}); pass the "
              "resolved path with --allow-root".format(args.target, real_target),
              file=sys.stderr)
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
