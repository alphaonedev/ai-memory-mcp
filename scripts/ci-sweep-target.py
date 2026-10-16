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
  * ``<target>/debug`` and the four swept directories must not be symlinks and
    must resolve under the real target: otherwise exit 2 naming the path and
    nothing is deleted.
  * Symlink entries inside a swept directory are unlinked, never descended.
  * Nothing outside the four directories is read for sizing or deleted.
  * An unreadable directory or entry is reported as a warning naming the path
    and skipped; no traceback.

Exit codes: 0 success, 2 refused path (argparse usage errors also use 2),
3 ``--max-bytes`` is zero or negative, 4 nothing could be sized because every
swept directory or entry was unreadable.
"""

import argparse
import os
import shutil
import sys
from pathlib import Path

DEBUG_DIR_NAME = "debug"
SWEPT_SUBDIRS = ("deps", "incremental", "build", ".fingerprint")
WORKSPACE_ENV = "GITHUB_WORKSPACE"
EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_BAD_CAP = 3
EXIT_UNREADABLE = 4


def entry_size(path, warnings=None):
    """Bytes under path without following symlinks (a symlink counts as itself).

    A nested directory that cannot be listed is appended to ``warnings`` (same
    wording as the top-level unreadable-directory warning) and counts as its
    own size only.
    """
    st = os.lstat(path)
    if not os.path.isdir(path) or os.path.islink(path):
        return st.st_size
    total = st.st_size

    def on_error(exc):
        if warnings is not None:
            warnings.append("cannot read {}: {}".format(exc.filename, exc))

    for dirpath, dirnames, filenames in os.walk(path, followlinks=False, onerror=on_error):
        for name in dirnames + filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                continue
    return total


class Refused(Exception):
    """A swept path is a symlink or escapes the real target."""


def is_under(path, root):
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def checked_dirs(target):
    """Return the existing swept directories, or raise Refused on any symlink/escape."""
    debug = Path(target) / DEBUG_DIR_NAME
    if debug.is_symlink():
        raise Refused("{} is a symlink".format(debug))
    found = []
    for sub in SWEPT_SUBDIRS:
        base = debug / sub
        if base.is_symlink():
            raise Refused("{} is a symlink".format(base))
        if not base.is_dir():
            continue
        if not is_under(os.path.realpath(str(base)), target):
            raise Refused("{} resolves outside {}".format(base, target))
        found.append(base)
    return found


def collect_entries(target, warnings):
    """Return (mtime, name, path, size) for each top-level entry of the swept dirs.

    Unreadable directories and entries are appended to ``warnings`` and skipped.
    """
    entries = []
    for base in checked_dirs(target):
        try:
            with os.scandir(str(base)) as it:
                children = list(it)
        except OSError as exc:
            warnings.append("cannot read {}: {}".format(base, exc))
            continue
        for child in children:
            try:
                mtime = child.stat(follow_symlinks=False).st_mtime
                size = entry_size(child.path, warnings)
            except OSError as exc:
                warnings.append("cannot size {}: {}".format(child.path, exc))
                continue
            entries.append((mtime, child.path, child.path, size))
    entries.sort(key=lambda item: (item[0], item[1]))
    return entries


def remove_entry(path):
    if os.path.islink(path) or not os.path.isdir(path):
        os.unlink(path)
    else:
        shutil.rmtree(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
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
    try:
        entries = collect_entries(real_target, warnings)
    except Refused as exc:
        print("refused: {}".format(exc), file=sys.stderr)
        return EXIT_REFUSED
    for line in warnings:
        print("warning: {}".format(line), file=sys.stderr)
    before = sum(item[3] for item in entries)
    remaining = before
    removed = 0
    for _mtime, _name, path, size in entries:
        if remaining <= args.max_bytes:
            break
        if not args.dry_run:
            try:
                remove_entry(path)
            except OSError as exc:
                print("warning: cannot remove {}: {}".format(path, exc), file=sys.stderr)
                continue
        remaining -= size
        removed += 1
    print("ci-sweep-target: target={} cap={} before={} after={} removed={}{}".format(
        real_target, args.max_bytes, before, remaining, removed,
        " (dry-run)" if args.dry_run else ""))
    if warnings and not entries:
        return EXIT_UNREADABLE
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
