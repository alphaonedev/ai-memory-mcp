#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Prune stale per-job artifacts on a self-hosted runner after a job (#7188).

Removes ONLY: the workspace ``target/debug/incremental`` tree (CI builds with
CARGO_INCREMENTAL=0, so anything there is a leftover), workspace ``.tmp*``
directories, and entries of ``<work-root>/_temp`` older than ``--max-age-days``.

It NEVER removes the shared per-host cargo target (``--shared-target``) nor any
path inside it or above it; ``is_protected`` is checked on every candidate and
again immediately before each removal. Symlinks are never followed or deleted
(each one met is reported as skipped) and every removal must resolve inside the
work root. Use ``--dry-run`` to list only.

Exit codes: 0 ok, 2 bad arguments. A failed removal is reported and counted but
does not fail the post-job step (exit stays 0): cleanup must never red a job.
Python 3.9+, standard library only.
"""
import argparse
import shutil
import sys
import time
from pathlib import Path

SECS_PER_DAY = 86400
TEMP_DIR_NAME = "_temp"
INCREMENTAL_RELATIVE = Path("target") / "debug" / "incremental"
TMP_PREFIX = ".tmp"
DEFAULT_MAX_AGE_DAYS = 7
EXIT_OK = 0
EXIT_BAD_ARGS = 2


def resolve(path):
    return Path(path).resolve()


def is_protected(candidate, shared_target):
    """True if ``candidate`` is, is inside, or contains the shared target."""
    cand = resolve(candidate)
    shared = resolve(shared_target)
    return cand == shared or shared in cand.parents or cand in shared.parents


def is_within(path, root):
    """True if ``path`` resolves to ``root`` or somewhere below it (3.9-safe)."""
    try:
        resolve(path).relative_to(resolve(root))
    except ValueError:
        return False
    return True


def is_old(path, max_age_days, now):
    return now - path.stat().st_mtime > max_age_days * SECS_PER_DAY


def scan(work_root, workspace, shared_target, max_age_days, now):
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
    keep = [path for path in found if not is_protected(path, shared_target)]
    return keep, skipped


def find_candidates(work_root, workspace, shared_target, max_age_days, now):
    """Return the stale paths to prune, never including protected ones."""
    return scan(work_root, workspace, shared_target, max_age_days, now)[0]


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--work-root", required=True, help="runner _work directory")
    parser.add_argument("--workspace", required=True, help="checkout of this job")
    parser.add_argument("--shared-target", required=True, help="shared cargo target (never pruned)")
    parser.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS)
    parser.add_argument("--dry-run", action="store_true", help="list, delete nothing")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_age_days < 1:
        parser.error("--max-age-days must be >= 1")
    failures = 0
    candidates, skipped = scan(
        args.work_root, args.workspace, args.shared_target, args.max_age_days, time.time()
    )
    for link in skipped:
        print("skipped symlink %s" % link)
    for path in candidates:
        if path.is_symlink() or is_protected(path, args.shared_target):
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
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
