#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Prune stale entries of a self-hosted runner's own TMPDIR at job start (#8634).

Removes ONLY direct entries of the resolved ``$TMPDIR`` whose own mtime (lstat,
never a symlink target) is older than MAX_AGE_SECS. An old directory goes whole,
whatever its children's mtimes. Symlinks are unlinked, never followed. Nothing
outside TMPDIR is touched, so a sibling ``runner-N`` directory is safe.

Refuses (exit 3, nothing deleted, reason on stderr) when TMPDIR is unset, empty,
relative, missing, not a directory, a symlink, not owned by the current user,
equal to or above a forbidden path (``/``, ``/tmp``, the home directory, the
workspace) or not strictly below an allowed root (ALLOWED_ROOTS plus ``--root``).
A per-entry failure is reported and counted, never fatal: exit 0 with
``pruned=<n> kept=<n> failed=<n> freed_bytes=<n>``. ``--dry-run`` deletes nothing.

The scan is one streaming ``os.scandir`` pass over a directory fd (no list, no
sort), so a directory of 600,000 entries costs constant memory. Removal is
dir-fd based with an lstat re-check right before it (TOCTOU); the script
refuses to run where ``shutil.rmtree`` cannot avoid symlink attacks.
Python 3.12+, standard library only.
"""
import argparse
import os
import shutil
import stat
import sys
import time
from pathlib import Path

SECS_PER_DAY = 86400
MAX_AGE_SECS = SECS_PER_DAY
ALLOWED_ROOTS = ("/mnt/t9/tmp", "/Users/Shared")
FORBIDDEN_PATHS = ("/", "/tmp", "/var/tmp", "/private/tmp")
DISK_BLOCK_BYTES = 512
MAX_FAILURE_LINES = 20
EXIT_OK = 0
EXIT_REFUSED = 3
PROG = "prune_runner_tmp"


class Refusal(Exception):
    """TMPDIR cannot be pruned; the message is the exact reason."""


def resolve_tmpdir(raw, roots, environ):
    """Return the TMPDIR Path to prune, or raise Refusal with the reason."""
    if raw is None:
        raise Refusal("TMPDIR is unset")
    if raw == "":
        raise Refusal("TMPDIR is empty")
    if not os.path.isabs(raw):
        raise Refusal(f"TMPDIR is not an absolute path: {raw}")
    path = Path(os.path.normpath(raw))
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise Refusal(f"TMPDIR does not exist: {path} ({exc.strerror})") from exc
    if stat.S_ISLNK(info.st_mode):
        raise Refusal(f"TMPDIR is a symlink: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise Refusal(f"TMPDIR is not a directory: {path}")
    real = Path(os.path.realpath(path))
    guarded = [Path(p) for p in FORBIDDEN_PATHS]
    guarded += [Path(os.path.realpath(p)) for p in FORBIDDEN_PATHS]
    for name in (str(Path.home()), environ.get("GITHUB_WORKSPACE"), os.getcwd()):
        if name:
            guarded.append(Path(os.path.realpath(name)))
    if path in guarded or real in guarded:
        raise Refusal(f"TMPDIR is a forbidden path: {path}")
    if info.st_uid != os.geteuid():
        raise Refusal(f"TMPDIR is not owned by the current user: {path}")
    for root in roots:
        if root.rstrip("/") == "":
            raise Refusal("allowed root is '/'")
    if not any(Path(os.path.realpath(r)) in real.parents for r in roots):
        raise Refusal(f"TMPDIR is outside the allowed roots {list(roots)}: {real}")
    for forbidden in guarded[len(FORBIDDEN_PATHS) * 2:]:
        if real in forbidden.parents:
            raise Refusal(f"TMPDIR contains the home directory or the workspace: {path}")
    return real


def print_runner_facts(raw, roots, out):
    """Print one ``prune-facts:`` line (print only; no decision depends on it)."""
    resolved = symlink = allowed = "unknown"
    if raw:
        norm = os.path.normpath(raw)
        real = os.path.realpath(raw)
        resolved = real
        symlink = "yes" if norm != real else "no"
        allowed = "none"
        for root in roots:
            if Path(os.path.realpath(root)) in Path(real).parents:
                allowed = root
                break
    version = sys.version.splitlines()[0]
    print(
        f"prune-facts: tmpdir={raw} resolved={resolved} symlink={symlink} "
        f"allowed_root={allowed} python={version} executable={sys.executable}",
        file=out,
    )
    out.flush()


def tree_bytes(dir_fd, name):
    """Allocated bytes under ``name`` (fd based, no symlink followed)."""
    total = 0
    stack = [os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)]
    while stack:
        fd = stack.pop()
        try:
            with os.scandir(fd) as it:
                for entry in it:
                    info = entry.stat(follow_symlinks=False)
                    total += info.st_blocks * DISK_BLOCK_BYTES
                    if stat.S_ISDIR(info.st_mode):
                        try:
                            stack.append(os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd))
                        except OSError:
                            pass
        except OSError:
            pass
        finally:
            os.close(fd)
    return total


def remove_entry(dir_fd, name, scanned):
    """Remove one entry; re-check lstat first. Return (ok, freed_bytes)."""
    now_info = os.lstat(name, dir_fd=dir_fd)
    if (now_info.st_ino, now_info.st_dev, now_info.st_mode) != (scanned.st_ino, scanned.st_dev, scanned.st_mode):
        raise OSError("entry changed since scan")
    if stat.S_ISDIR(now_info.st_mode):
        freed = tree_bytes(dir_fd, name)
        errors = []
        shutil.rmtree(name, dir_fd=dir_fd, onexc=lambda _f, _p, exc: errors.append(exc))
        if errors:
            raise errors[0]
        return freed
    os.unlink(name, dir_fd=dir_fd)
    return now_info.st_blocks * DISK_BLOCK_BYTES


def prune(tmpdir, dry_run, now, out, err):
    """Prune old direct entries; return (pruned, kept, failed, freed_bytes)."""
    pruned = kept = failed = freed = 0
    cutoff = now - MAX_AGE_SECS
    dir_fd = os.open(tmpdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with os.scandir(dir_fd) as it:
            for entry in it:
                try:
                    info = entry.stat(follow_symlinks=False)
                    if info.st_mtime >= cutoff:
                        kept += 1
                        continue
                    if dry_run:
                        print(f"would-remove {entry.name}", file=out)
                    else:
                        freed += remove_entry(dir_fd, entry.name, info)
                    pruned += 1
                except OSError as exc:
                    failed += 1
                    if failed <= MAX_FAILURE_LINES:
                        print(f"{PROG}: failed to remove {entry.name}: {exc}", file=err)
    finally:
        os.close(dir_fd)
    return pruned, kept, failed, freed


def main(argv=None, environ=None, out=None, err=None):
    environ = os.environ if environ is None else environ
    out, err = out or sys.stdout, err or sys.stderr
    parser = argparse.ArgumentParser(prog=PROG, description=__doc__.split("\n")[0])
    parser.add_argument("--root", action="append", default=[], help="extra allowed root (repeatable)")
    parser.add_argument("--dry-run", action="store_true", help="print what would go, delete nothing")
    args = parser.parse_args(argv)
    print_runner_facts(environ.get("TMPDIR"), (*ALLOWED_ROOTS, *args.root), out)
    try:
        if not shutil.rmtree.avoids_symlink_attacks:
            raise Refusal("shutil.rmtree cannot avoid symlink attacks on this platform")
        tmpdir = resolve_tmpdir(environ.get("TMPDIR"), (*ALLOWED_ROOTS, *args.root), environ)
    except Refusal as exc:
        print(f"{PROG}: refused: {exc}", file=err)
        return EXIT_REFUSED
    pruned, kept, failed, freed = prune(tmpdir, args.dry_run, time.time(), out, err)
    print(f"pruned={pruned} kept={kept} failed={failed} freed_bytes={freed}", file=out)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
