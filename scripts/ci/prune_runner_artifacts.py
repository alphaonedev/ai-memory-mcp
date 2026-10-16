#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Prune stale per-job artifacts on a self-hosted runner after a job (#7188).

Removes ONLY: the workspace ``target/debug/incremental`` tree (CI builds with
CARGO_INCREMENTAL=0, so anything there is a leftover), workspace ``.tmp*``
directories, and entries of ``<work-root>/_temp`` older than ``--max-age-days``.

It NEVER removes the per-runner cargo target ROOT (``--protected-root``,
``~/.cache/ai-memory-ci/cargo-target``) nor any path inside it (every runner's
target, so one runner's prune can never delete a sibling's) or above it; ``is_protected`` is checked on every candidate and
again immediately before each removal. Symlinks are never followed or deleted
(each one met is reported as skipped) and every removal must resolve inside the
work root. Use ``--dry-run`` to list only.

Idle-target eviction (#7199, ``--evict-root`` + ``--runner-name``) runs AFTER the
prune. Under the per-runner target root it deletes every OTHER runner's target
directory whose newest mtime is older than IDLE_TARGET_DAYS and, while the
root's filesystem has less than FREE_FLOOR_GIB free, the oldest remaining other
targets. It never touches this runner's target, anything that is not a real
directory with a runner-safe name directly under the root (symlinks are never
followed or deleted), or any root that is not an absolute path under the home.
One line is printed per eviction plus a summary line.

Exit codes: 0 ok, 2 bad arguments. A failed removal is reported and counted but
does not fail the post-job step (exit stays 0): cleanup must never red a job.
Python 3.9+, standard library only.
"""
import argparse
import os
import re
import shutil
import sys
import time
from pathlib import Path

SECS_PER_DAY = 86400
TEMP_DIR_NAME = "_temp"
INCREMENTAL_RELATIVE = Path("target") / "debug" / "incremental"
TMP_PREFIX = ".tmp"
DEFAULT_MAX_AGE_DAYS = 7
IDLE_TARGET_DAYS = 7
FREE_FLOOR_GIB = 200
BYTES_PER_GIB = 1024 ** 3
RUNNER_NAME_PATTERN = re.compile(r"\A[A-Za-z0-9._-]+\Z")
DOT_NAMES = (".", "..")
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_BAD_ARGS = EXIT_USAGE


def resolve(path):
    return Path(path).resolve()


def is_protected(candidate, protected_root):
    """True if ``candidate`` is, is inside, or contains the protected root."""
    cand = resolve(candidate)
    protected = resolve(protected_root)
    return cand == protected or protected in cand.parents or cand in protected.parents


def is_within(path, root):
    """True if ``path`` resolves to ``root`` or somewhere below it (3.9-safe)."""
    try:
        resolve(path).relative_to(resolve(root))
    except ValueError:
        return False
    return True


def is_old(path, max_age_days, now):
    return now - path.stat().st_mtime > max_age_days * SECS_PER_DAY


def scan(work_root, workspace, protected_root, max_age_days, now):
    """Return ``(candidates, skipped)``; a symlink is never a candidate.

    ``skipped`` lists every symlink met on the way (never followed, never
    deleted) so the run can report it.
    """
    found = []
    skipped = []
    workspace = Path(workspace)
    if workspace.is_symlink():
        skipped.append(workspace)
    elif workspace.is_dir():
        current = workspace
        for part in INCREMENTAL_RELATIVE.parts:
            current = current / part
            if current.is_symlink():
                skipped.append(current)
                break
            if not current.is_dir():
                break
        else:
            found.append(current)
        for entry in sorted(workspace.iterdir()):
            if not entry.name.startswith(TMP_PREFIX):
                continue
            if entry.is_symlink():
                skipped.append(entry)
            elif entry.is_dir():
                found.append(entry)
    temp_root = Path(work_root) / TEMP_DIR_NAME
    if temp_root.is_symlink():
        skipped.append(temp_root)
    elif temp_root.is_dir():
        for entry in sorted(temp_root.iterdir()):
            if entry.is_symlink():
                skipped.append(entry)
            elif entry.is_dir() and is_old(entry, max_age_days, now):
                found.append(entry)
    keep = [path for path in found if not is_protected(path, protected_root)]
    return keep, skipped


def find_candidates(work_root, workspace, protected_root, max_age_days, now):
    """Return the stale paths to prune, never including protected ones."""
    return scan(work_root, workspace, protected_root, max_age_days, now)[0]


def is_filesystem_root(path):
    return path == path.parent


def validate_arguments(work_root, workspace, protected_root):
    """Return a refusal reason, or None when the arguments are safe to act on.

    Refused: a work root that is a filesystem root, missing or not a directory;
    an empty or relative protected root; a protected root neither inside nor
    beside the work root (no common ancestor below the filesystem root); a
    workspace that does not resolve inside the work root.
    """
    if not str(work_root).strip():
        return "empty work root"
    root = resolve(work_root)
    if is_filesystem_root(root):
        return "work root is a filesystem root"
    if not root.is_dir():
        return "work root is not an existing directory"
    if not str(protected_root).strip():
        return "empty protected root"
    if not Path(protected_root).is_absolute():
        return "protected root must be an absolute path"
    protected = resolve(protected_root)
    if is_filesystem_root(protected):
        return "protected root is a filesystem root"
    common = [p for p in root.parents if p in protected.parents or p == protected]
    if not is_within(protected, root) and not any(not is_filesystem_root(p) for p in common):
        return "protected root is neither inside nor beside the work root"
    if not is_within(workspace, root):
        return "workspace is not inside the work root"
    return None


def eviction_problem(evict_root, runner_name, home):
    """Return a refusal reason for the eviction arguments, or None when safe.

    The root must be an absolute, ``..``-free path strictly under the absolute
    home (checked lexically: the cache directory may itself be a symlink to an
    external disk) and the runner name must be a safe single path component.
    """
    root = Path(evict_root)
    home = Path(home)
    if not str(evict_root).strip() or not root.is_absolute():
        return "evict root must be an absolute path"
    if not home.is_absolute() or is_filesystem_root(home):
        return "home must be an absolute non-root path"
    if ".." in root.parts:
        return "evict root must not contain .."
    try:
        relative = root.relative_to(home)
    except ValueError:
        return "evict root is not under the home"
    if not relative.parts:
        return "evict root is the home itself"
    if not runner_name or runner_name in DOT_NAMES or not RUNNER_NAME_PATTERN.match(runner_name):
        return "invalid runner name"
    return None


def newest_mtime(path, newer_than=None):
    """Newest mtime under ``path`` (symlinks never followed, only lstat'd).

    With ``newer_than`` the walk stops early and returns as soon as one entry
    is newer than it (the target is not idle).
    """
    newest = os.lstat(path).st_mtime
    if newer_than is not None and newest > newer_than:
        return newest
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        for name in dirnames + filenames:
            try:
                stamp = os.lstat(os.path.join(dirpath, name)).st_mtime
            except OSError:
                continue
            newest = max(newest, stamp)
            if newer_than is not None and newest > newer_than:
                return newest
    return newest


def other_targets(base, runner_name):
    """Real runner-named directories directly under ``base``, except this runner's."""
    found = []
    for entry in sorted(base.iterdir()):
        if entry.name == runner_name or entry.is_symlink() or not entry.is_dir():
            continue
        if entry.name in DOT_NAMES or not RUNNER_NAME_PATTERN.match(entry.name):
            continue
        found.append(entry)
    return found


def free_bytes_of(path):
    return shutil.disk_usage(path).free


def evict_idle_targets(evict_root, runner_name, home, idle_days, floor_gib, now,
                       dry_run=False, free_bytes=free_bytes_of):
    """Evict idle (then, below the free floor, oldest) other-runner targets."""
    problem = eviction_problem(evict_root, runner_name, home)
    if problem:
        print("prune_runner_artifacts: refusing eviction: %s" % problem, file=sys.stderr)
        return EXIT_USAGE
    base = resolve(evict_root)
    if not base.is_dir():
        print("eviction summary: 0 evicted, root %s does not exist" % evict_root)
        return EXIT_OK
    cutoff = now - idle_days * SECS_PER_DAY
    floor_bytes = floor_gib * BYTES_PER_GIB
    state = {"evicted": 0, "failed": 0}

    def remove(path, reason):
        if path.is_symlink() or path.parent != base:
            print("skipped unsafe %s" % path)
            return
        if dry_run:
            print("would evict %s (%s)" % (path, reason))
            state["evicted"] += 1
            return
        try:
            shutil.rmtree(path)
        except OSError as err:
            state["failed"] += 1
            print("could not evict %s: %s" % (path, err), file=sys.stderr)
            return
        state["evicted"] += 1
        print("evicted %s (%s)" % (path, reason))

    remaining = []
    for entry in other_targets(base, runner_name):
        if newest_mtime(entry, newer_than=cutoff) <= cutoff:
            remove(entry, "idle over %d days" % idle_days)
        else:
            remaining.append(entry)
    if free_bytes(base) < floor_bytes:
        ranked = sorted((newest_mtime(entry), entry) for entry in remaining)
        for _, entry in ranked:
            if not dry_run and free_bytes(base) >= floor_bytes:
                break
            remove(entry, "below the %d GiB free-space floor" % floor_gib)
    print("eviction summary: %d evicted, %d failed, %d GiB free (floor %d GiB)" % (
        state["evicted"], state["failed"], free_bytes(base) // BYTES_PER_GIB, floor_gib))
    return EXIT_OK


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--work-root", required=True, help="runner _work directory")
    parser.add_argument("--workspace", required=True, help="checkout of this job")
    parser.add_argument("--protected-root", required=True, help="per-runner cargo target root (never pruned)")
    parser.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS)
    parser.add_argument("--evict-root", help="per-runner cargo target root to evict idle targets from (#7199)")
    parser.add_argument("--runner-name", help="this runner's name (its target is never evicted)")
    parser.add_argument("--home", default=str(Path.home()), help="runner user home (eviction root must be under it)")
    parser.add_argument("--idle-target-days", type=int, default=IDLE_TARGET_DAYS)
    parser.add_argument("--free-floor-gib", type=int, default=FREE_FLOOR_GIB)
    parser.add_argument("--dry-run", action="store_true", help="list, delete nothing")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_age_days < 1:
        parser.error("--max-age-days must be >= 1")
    if args.evict_root and not args.runner_name:
        parser.error("--evict-root requires --runner-name")
    if args.idle_target_days < 1 or args.free_floor_gib < 0:
        parser.error("--idle-target-days must be >= 1 and --free-floor-gib >= 0")
    problem = validate_arguments(args.work_root, args.workspace, args.protected_root)
    if not problem and args.evict_root:
        problem = eviction_problem(args.evict_root, args.runner_name, args.home)
    if problem:
        print("prune_runner_artifacts: refusing: %s" % problem, file=sys.stderr)
        return EXIT_USAGE
    failures = 0
    candidates, skipped = scan(
        args.work_root, args.workspace, args.protected_root, args.max_age_days, time.time()
    )
    for link in skipped:
        print("skipped symlink %s" % link)
    for path in candidates:
        if path.is_symlink() or is_protected(path, args.protected_root):
            continue
        if not is_within(path, args.work_root):
            print("skipped outside root %s" % path)
            continue
        if args.dry_run:
            print("would remove %s" % path)
            continue
        try:
            shutil.rmtree(path)
            print("removed %s" % path)
        except OSError as err:
            failures += 1
            print("could not remove %s: %s" % (path, err), file=sys.stderr)
    if failures:
        print("prune_runner_artifacts: %d removal(s) failed" % failures, file=sys.stderr)
    if args.evict_root:
        return evict_idle_targets(
            args.evict_root, args.runner_name, args.home, args.idle_target_days,
            args.free_floor_gib, time.time(), dry_run=args.dry_run,
        )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
