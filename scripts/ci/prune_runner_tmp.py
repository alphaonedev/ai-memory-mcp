#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Prune stale entries of a self-hosted runner's own TMPDIR at job start (#8634).

Removes ONLY direct entries of one directory whose own mtime (lstat, never a
symlink target) is older than MAX_AGE_SECS. An old directory goes whole,
whatever its children's mtimes. Symlinks are unlinked, never followed. Nothing
outside that directory is touched, so a sibling ``runner-N`` directory is safe.

The directory is PROVEN, by file identity and not by path text, to be this
runner's own ``<runner root>/runner-<digits>``: TMPDIR is opened once
(O_NOFOLLOW), the opened directory's own ``..`` must be the same file
(st_dev, st_ino) as one of the confirmed runner roots (ALLOWED_ROOTS, each a
named constant with the run that confirmed it), the last component must match
RUNNER_DIR_PATTERN, and every later check and every deletion goes through that
one descriptor. Anything it cannot prove ends in a named refusal (nothing
deleted; the reason goes to stderr and to a ``::warning`` annotation on stdout,
and the step still exits 0 so the rest of the job runs): TMPDIR unset, empty, relative, missing, a
symlink, not a directory, changed while opened, a forbidden path (``/``,
``/tmp``, the home directory, the workspace, the working directory), not owned
by the current user, not named runner-<digits>, outside the allowed roots,
containing the home directory or the workspace; an allowed root that is
relative or ``/``; an interpreter older than MIN_PYTHON; a platform without
descriptor-relative file calls.

A per-entry failure is reported and counted, never fatal: exit 0 with
``pruned=<n> kept=<n> failed=<n> freed_bytes=<n> skipped=<n>``. An entry on
another device (a mount point) is skipped and reported, never entered. A tree
deeper than MAX_TREE_DEPTH or larger than MAX_TREE_ENTRIES is one counted
failure, left in place. An unexpected internal error stops the pruning, prints
a named line and exits 1 (the job goes red: that is a defect, not a
misconfiguration). ``--dry-run`` deletes nothing.

The top-level scan is one streaming ``os.scandir`` pass over a directory fd (no
list, no sort), so a directory of 600,000 entries costs constant memory.
Removal is an iterative, descriptor-relative walk (one open directory at a
time, no recursion, no ``shutil.rmtree``) with an identity re-check
(st_dev, st_ino, mode, st_ctime_ns) right before each entry is entered.
Python 3.12+, standard library only; the file itself parses on older
interpreters so the version refusal can run.
"""
import sys

MIN_PYTHON = (3, 12)
EXIT_OK = 0
EXIT_ERROR = 1
PROG = "prune_runner_tmp"


def python_refusal(version_info):
    """Return the refusal text when the interpreter is older than MIN_PYTHON, else None."""
    if tuple(version_info[:2]) < MIN_PYTHON:
        found = ".".join(str(part) for part in version_info[:3])
        wanted = ".".join(str(part) for part in MIN_PYTHON)
        return f"python {found} is older than {wanted}"
    return None


def refusal_annotation(reason):
    """The workflow annotation for a refusal; ``reason`` is already escaped."""
    return f"::warning title={PROG} refused::{PROG}: refused: {reason}"


if __name__ == "__main__" and python_refusal(sys.version_info) is not None:
    sys.stderr.write(f"{PROG}: refused: {python_refusal(sys.version_info)}\n")
    sys.stdout.write(refusal_annotation(python_refusal(sys.version_info)) + "\n")
    sys.exit(EXIT_OK)

import argparse  # noqa: E402  (the floor check above must run before anything newer is needed)
import os  # noqa: E402
import re  # noqa: E402
import stat  # noqa: E402
import time  # noqa: E402

SECS_PER_DAY = 86400
MAX_AGE_SECS = SECS_PER_DAY

# Confirmed runner roots (ruling f23a9ae4). A root is added only with the run
# whose prune-facts line shows a real runner TMPDIR under it; a guessed root was
# wrong on first contact (a lane-scratch directory on f2, run 43768137071). There is no f1
# root until its prune-facts line (run 43768136967) is quoted: the f1 step
# refuses visibly and the job continues.
F2_RUNNER_ROOT = "/ai-scratch/runner-tmp"  # confirmed: runs 43768137071, 43768136935, 43768136967 (runner-1, -3, -4)
ALLOWED_ROOTS = (F2_RUNNER_ROOT,)
MAX_TREE_DEPTH = 10000  # directory levels below a top-level entry; deeper = one counted failure
MAX_TREE_ENTRIES = 5_000_000  # entries removed under one top-level entry; more = one counted failure
RUNNER_DIR_PATTERN = re.compile(r"runner-[0-9]+")
FORBIDDEN_PATHS = ("/", "/tmp", "/var/tmp", "/private/tmp")
DISK_BLOCK_BYTES = 512
MAX_FAILURE_LINES = 20
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
FACTS_PREFIX = "prune-facts:"

# Every refusal reason, one named template each. docs/DEV-CI-ENVIRONMENT.md
# section 3.3 lists each template's fixed text; a test pins the two together.
REFUSAL_REASONS = {
    "python": "python {found} is older than {wanted}",
    "platform": "this platform lacks descriptor-relative file calls",
    "root_relative": "allowed root is not an absolute path: {root}",
    "root_slash": "allowed root is '/'",
    "unset": "TMPDIR is unset",
    "empty": "TMPDIR is empty",
    "relative": "TMPDIR is not an absolute path: {path}",
    "missing": "TMPDIR does not exist: {path} ({why})",
    "symlink": "TMPDIR is a symlink: {path}",
    "not_dir": "TMPDIR is not a directory: {path}",
    "unopenable": "TMPDIR cannot be opened: {path} ({why})",
    "changed": "TMPDIR changed while it was opened: {path}",
    "forbidden": "TMPDIR is a forbidden path: {path}",
    "not_owner": "TMPDIR is not owned by the current user: {path}",
    "not_runner_dir": "TMPDIR is not named runner-<digits>: {name}",
    "outside_roots": "TMPDIR is outside the allowed roots {roots}: {path}",
    "contains": "TMPDIR contains the home directory or the workspace: {path}",
}


class Refusal(Exception):
    """TMPDIR cannot be pruned; the message is the exact reason."""


class EntryChanged(OSError):
    """An entry no longer is the one the scan saw."""


class TreeTooLarge(OSError):
    """A tree deeper than MAX_TREE_DEPTH or larger than MAX_TREE_ENTRIES: left in place."""


def refuse(key, **fields):
    """Build the Refusal for reason ``key`` with ``fields`` escaped for the log."""
    return Refusal(REFUSAL_REASONS[key].format(**{k: safe_text(v) for k, v in fields.items()}))


def safe_text(text):
    """Escape control characters, backslashes, ``%`` and ``::`` so a name cannot inject a log line or workflow command."""
    pieces = []
    for char in str(text):
        code = ord(char)
        if char == "\\":
            pieces.append("\\\\")
        elif char == "%":
            pieces.append("\\x25")
        elif code < 0x20 or 0x7F <= code <= 0x9F:
            pieces.append(f"\\x{code:02x}")
        elif 0xD800 <= code <= 0xDFFF or code in (0x2028, 0x2029):
            pieces.append(f"\\u{code:04x}")
        else:
            pieces.append(char)
    return "".join(pieces).replace("::", "\\x3a:")


def file_id(info):
    """Identity of a file: device and inode."""
    return (info.st_dev, info.st_ino)


def entry_id(info):
    """Identity of an entry for the re-check: device, inode, type bits and change time."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_ctime_ns)


def stat_or_none(path):
    """stat (following links) or None when the path cannot be stat-ed."""
    try:
        return os.stat(path)
    except OSError:
        return None


def ancestor_ids(path):
    """File identities of ``path`` (resolved) and every ancestor of it."""
    seen = set()
    current = os.path.realpath(path)
    while True:
        info = stat_or_none(current)
        if info is not None:
            seen.add(file_id(info))
        parent = os.path.dirname(current)
        if parent == current:
            return seen
        current = parent


def root_ids(roots):
    """Validate every root, return {(st_dev, st_ino): root} for the roots that exist."""
    found = {}
    slash = stat_or_none("/")
    for root in roots:
        if not os.path.isabs(root):
            raise refuse("root_relative", root=root)
        info = stat_or_none(root)
        if info is None:
            continue
        if slash is not None and file_id(info) == file_id(slash):
            raise refuse("root_slash")
        found[file_id(info)] = root
    return found


def guarded_paths(environ):
    """The home directory, the workspace and the working directory that must never be pruned or contained."""
    names = [os.path.expanduser("~"), environ.get("GITHUB_WORKSPACE"), os.getcwd()]
    return [name for name in names if name]


def open_runner_dir(raw, roots, environ):
    """Open TMPDIR once, prove it is ``<root>/runner-<digits>`` by identity; return (fd, info) or raise Refusal."""
    known_roots = root_ids(roots)
    if raw is None:
        raise refuse("unset")
    if raw == "":
        raise refuse("empty")
    if not os.path.isabs(raw):
        raise refuse("relative", path=raw)
    path = os.path.normpath(raw)
    try:
        first = os.lstat(path)
    except OSError as exc:
        raise refuse("missing", path=path, why=exc.strerror) from exc
    if stat.S_ISLNK(first.st_mode):
        raise refuse("symlink", path=path)
    if not stat.S_ISDIR(first.st_mode):
        raise refuse("not_dir", path=path)
    try:
        dir_fd = os.open(path, DIR_FLAGS)
    except OSError as exc:
        raise refuse("unopenable", path=path, why=exc.strerror) from exc
    try:
        info = os.fstat(dir_fd)
        if file_id(info) != file_id(first):
            raise refuse("changed", path=path)
        prove_runner_dir(dir_fd, info, path, known_roots, roots, environ)
    except BaseException:
        os.close(dir_fd)
        raise
    return dir_fd, info


def prove_runner_dir(dir_fd, info, path, known_roots, roots, environ):
    """Run the identity checks on the opened directory; raise Refusal on the first failure."""
    forbidden = [stat_or_none(p) for p in FORBIDDEN_PATHS]
    guarded = [stat_or_none(p) for p in guarded_paths(environ)]
    if any(item is not None and file_id(item) == file_id(info) for item in forbidden + guarded):
        raise refuse("forbidden", path=path)
    if info.st_uid != os.geteuid():
        raise refuse("not_owner", path=path)
    name = os.path.basename(path)
    if RUNNER_DIR_PATTERN.fullmatch(name) is None:
        raise refuse("not_runner_dir", name=name)
    parent_fd = os.open("..", DIR_FLAGS, dir_fd=dir_fd)
    try:
        parent_id = file_id(os.fstat(parent_fd))
    finally:
        os.close(parent_fd)
    if parent_id not in known_roots:
        raise refuse("outside_roots", roots=list(roots), path=os.path.realpath(path))
    for name_ in guarded_paths(environ):
        if file_id(info) in ancestor_ids(name_):
            raise refuse("contains", path=path)


DIR_FD_CALLS = (os.open, os.unlink, os.rmdir, os.lstat, os.stat)  # captured at import, before any patch
FD_SCAN_CALL = os.scandir


def platform_refusal():
    """Return the refusal text when descriptor-relative calls are missing, else None."""
    if not all(call in os.supports_dir_fd for call in DIR_FD_CALLS) or FD_SCAN_CALL not in os.supports_fd:
        return REFUSAL_REASONS["platform"]
    return None


def print_runner_facts(raw, roots, out):
    """Print one ``prune-facts:`` line (print only; no decision depends on it, an error is named, never raised)."""
    try:
        resolved = symlink = allowed = "unknown"
        if raw:
            norm = os.path.normpath(raw)
            real = os.path.realpath(raw)
            resolved = real
            symlink = "yes" if norm != real else "no"
            allowed = "none"
            parent = stat_or_none(os.path.dirname(real))
            for root in roots:
                info = stat_or_none(root)
                if parent is not None and info is not None and file_id(info) == file_id(parent):
                    allowed = root
                    break
        version = sys.version.splitlines()[0]
        line = (
            f"{FACTS_PREFIX} tmpdir={safe_text(raw)} resolved={safe_text(resolved)} symlink={symlink} "
            f"allowed_root={safe_text(allowed)} python={version} executable={sys.executable}"
        )
    except Exception as exc:  # print-only helper: never change the exit code
        line = f"{FACTS_PREFIX} error={type(exc).__name__}"
    print(line, file=out)
    out.flush()


class Tally:
    """Counters and the failure and skip lines (capped) of one run."""

    def __init__(self, err):
        self.pruned = self.kept = self.failed = self.skipped = self.freed = 0
        self.tree_entries = 0
        self.internal_error = False
        self.err = err

    def fail(self, name, exc):
        self.failed += 1
        if self.failed <= MAX_FAILURE_LINES:
            print(safe_text(f"{PROG}: failed to remove {name}: {exc}"), file=self.err)

    def skip(self, name):
        self.skipped += 1
        if self.skipped <= MAX_FAILURE_LINES:
            print(safe_text(f"{PROG}: skipped {name}: on another device, not entered"), file=self.err)

    def summary(self):
        text = f"pruned={self.pruned} kept={self.kept} failed={self.failed} freed_bytes={self.freed} skipped={self.skipped}"
        return text + (" internal_error=1" if self.internal_error else "")


class Level:
    """One directory of the iterative walk: its identity, size and the subdirectories still to enter."""

    __slots__ = ("name", "file_id", "blocks", "pending")

    def __init__(self, name, info, pending):
        self.name = name
        self.file_id = file_id(info)
        self.blocks = info.st_blocks
        self.pending = pending


def open_checked(parent_fd, name, expected):
    """Open directory ``name`` below ``parent_fd`` without following a symlink and prove it is the scanned entry."""
    dir_fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    try:
        if entry_id(os.fstat(dir_fd)) != expected:
            raise EntryChanged("entry changed since scan")
    except BaseException:
        os.close(dir_fd)
        raise
    return dir_fd


def list_level(dir_fd, root_dev, tally, errors):
    """Unlink the non-directories of an open directory; return its subdirectories as (name, lstat) pairs."""
    pending = []
    try:
        with os.scandir(dir_fd) as scan:
            entries = list(scan)
    except OSError as exc:
        errors.append(exc)
        return pending
    for entry in entries:
        try:
            tally.tree_entries += 1
            if tally.tree_entries > MAX_TREE_ENTRIES:
                raise TreeTooLarge(f"more than {MAX_TREE_ENTRIES} entries under one top-level entry")
            info = entry.stat(follow_symlinks=False)
            if info.st_dev != root_dev:
                tally.skip(entry.name)
                errors.append(OSError(f"{entry.name} is on another device"))
            elif stat.S_ISDIR(info.st_mode):
                pending.append((entry.name, info))
            else:
                os.unlink(entry.name, dir_fd=dir_fd)
                tally.freed += info.st_blocks * DISK_BLOCK_BYTES
        except OSError as exc:
            errors.append(exc)
    return pending


def remove_tree(parent_fd, name, scanned, root_dev, tally):
    """Remove directory ``name`` below ``parent_fd``: iterative, one open directory at a time, stays on ``root_dev``."""
    errors = []
    tally.tree_entries = 0
    dir_fd = open_checked(parent_fd, name, entry_id(scanned))
    try:
        stack = [Level(name, scanned, list_level(dir_fd, root_dev, tally, errors))]
        while True:
            level = stack[-1]
            if level.pending:
                child_name, child_info = level.pending.pop()
                if len(stack) >= MAX_TREE_DEPTH:
                    errors.append(TreeTooLarge(f"deeper than {MAX_TREE_DEPTH} levels"))
                    continue
                try:
                    child_fd = open_checked(dir_fd, child_name, entry_id(child_info))
                except OSError as exc:
                    errors.append(exc)
                    continue
                os.close(dir_fd)
                dir_fd = child_fd
                stack.append(Level(child_name, child_info, list_level(dir_fd, root_dev, tally, errors)))
                continue
            stack.pop()
            if not stack:
                break
            up_fd = os.open("..", DIR_FLAGS, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = up_fd
            if file_id(os.fstat(dir_fd)) != stack[-1].file_id:
                raise EntryChanged("directory moved during removal")
            try:
                os.rmdir(level.name, dir_fd=dir_fd)
                tally.freed += level.blocks * DISK_BLOCK_BYTES
            except OSError as exc:
                errors.append(exc)
        os.close(dir_fd)
        dir_fd = None
        try:
            os.rmdir(name, dir_fd=parent_fd)
            tally.freed += level.blocks * DISK_BLOCK_BYTES
        except OSError as exc:
            errors.append(exc)
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    if errors:
        raise errors[0]


def remove_entry(dir_fd, name, scanned, root_dev, tally):
    """Remove one top-level entry after an identity re-check; raise OSError on any failure."""
    now_info = os.lstat(name, dir_fd=dir_fd)
    if entry_id(now_info) != entry_id(scanned):
        raise EntryChanged("entry changed since scan")
    if stat.S_ISDIR(now_info.st_mode):
        remove_tree(dir_fd, name, now_info, root_dev, tally)
        return
    os.unlink(name, dir_fd=dir_fd)
    tally.freed += now_info.st_blocks * DISK_BLOCK_BYTES


def prune(dir_fd, root_dev, dry_run, now, out, tally):
    """Prune old direct entries of the proven directory ``dir_fd`` into ``tally``."""
    cutoff = now - MAX_AGE_SECS
    with os.scandir(dir_fd) as scan:
        for entry in scan:
            try:
                info = entry.stat(follow_symlinks=False)
                if info.st_mtime >= cutoff:
                    tally.kept += 1
                    continue
                if info.st_dev != root_dev:
                    tally.skip(entry.name)
                    continue
                if dry_run:
                    print(safe_text(f"would-remove {entry.name}"), file=out)
                else:
                    remove_entry(dir_fd, entry.name, info, root_dev, tally)
                tally.pruned += 1
            except OSError as exc:  # one failed entry, left in place
                tally.fail(entry.name, exc)


def main(argv=None, environ=None, out=None, err=None):
    environ = os.environ if environ is None else environ
    out, err = out or sys.stdout, err or sys.stderr
    parser = argparse.ArgumentParser(prog=PROG, description=__doc__.split("\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="print what would go, delete nothing")
    args = parser.parse_args(argv)
    raw = environ.get("TMPDIR")
    print_runner_facts(raw, ALLOWED_ROOTS, out)
    tally = Tally(err)
    dir_fd = None
    try:
        try:
            reason = python_refusal(sys.version_info) or platform_refusal()
            if reason:
                raise Refusal(reason)
            dir_fd, info = open_runner_dir(raw, ALLOWED_ROOTS, environ)
        except Refusal as exc:
            print(f"{PROG}: refused: {exc}", file=err)
            print(refusal_annotation(exc), file=out)
            out.flush()
            return EXIT_OK
        prune(dir_fd, info.st_dev, args.dry_run, time.time(), out, tally)
    except Exception as exc:  # internal error: named, no traceback, the job goes red (exit 1)
        tally.internal_error = True
        print(safe_text(f"{PROG}: internal error, pruning stopped: {type(exc).__name__}: {exc}"), file=err)
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    print(tally.summary(), file=out)
    return EXIT_ERROR if tally.internal_error else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
