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
  * Symlinks are never followed: a symlink entry is unlinked, never descended,
    and a symlinked swept directory is skipped.
  * Nothing outside the four directories is read for sizing or deleted.

Exit codes: 0 success, 2 refused path.
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


def entry_size(path):
    """Bytes under path without following symlinks (a symlink counts as itself)."""
    st = os.lstat(path)
    if not os.path.isdir(path) or os.path.islink(path):
        return st.st_size
    total = st.st_size
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        for name in dirnames + filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                continue
    return total


def collect_entries(target):
    """Return (mtime, name, path, size) for each top-level entry of the swept dirs."""
    entries = []
    debug = Path(target) / DEBUG_DIR_NAME
    for sub in SWEPT_SUBDIRS:
        base = debug / sub
        if base.is_symlink() or not base.is_dir():
            continue
        for child in os.scandir(str(base)):
            try:
                mtime = child.stat(follow_symlinks=False).st_mtime
                size = entry_size(child.path)
            except OSError:
                continue
            entries.append((mtime, child.path, child.path, size))
    entries.sort(key=lambda item: (item[0], item[1]))
    return entries


def remove_entry(path):
    if os.path.islink(path) or not os.path.isdir(path):
        os.unlink(path)
    else:
        shutil.rmtree(path)


def is_under(path, root):
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", required=True, help="cargo target directory")
    parser.add_argument("--max-bytes", required=True, type=int, help="size cap in bytes")
    parser.add_argument("--allow-root", action="store_true",
                        help="permit a target outside $GITHUB_WORKSPACE (node cron)")
    parser.add_argument("--dry-run", action="store_true", help="report only; delete nothing")
    args = parser.parse_args(argv)

    real_target = os.path.realpath(args.target)
    if not args.allow_root:
        workspace = os.environ.get(WORKSPACE_ENV)
        real_ws = os.path.realpath(workspace) if workspace else None
        if real_ws is None or not is_under(real_target, real_ws):
            print("refused: {} is not under {} (use --allow-root)".format(
                real_target, WORKSPACE_ENV), file=sys.stderr)
            return EXIT_REFUSED

    entries = collect_entries(real_target)
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
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
