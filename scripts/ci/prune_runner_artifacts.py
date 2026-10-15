#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Prune stale per-job artifacts on a self-hosted runner after a job (#7188).

Removes ONLY: the workspace ``target/debug/incremental`` tree (CI builds with
CARGO_INCREMENTAL=0, so anything there is a leftover), workspace ``.tmp*``
directories, and entries of ``<work-root>/_temp`` older than ``--max-age-days``.

It NEVER removes the shared per-host cargo target (``--shared-target``) nor any
path inside it or above it; ``is_protected`` is checked on every candidate and
again immediately before each removal. Use ``--dry-run`` to list only.

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


def is_old(path, max_age_days, now):
    return now - path.stat().st_mtime > max_age_days * SECS_PER_DAY


def find_candidates(work_root, workspace, shared_target, max_age_days, now):
    """Return the stale paths to prune, never including protected ones."""
    found = []
    incremental = Path(workspace) / INCREMENTAL_RELATIVE
    if incremental.is_dir():
        found.append(incremental)
    if Path(workspace).is_dir():
        for entry in sorted(Path(workspace).iterdir()):
            if entry.name.startswith(TMP_PREFIX) and entry.is_dir() and not entry.is_symlink():
                found.append(entry)
    temp_root = Path(work_root) / TEMP_DIR_NAME
    if temp_root.is_dir():
        for entry in sorted(temp_root.iterdir()):
            if entry.is_dir() and not entry.is_symlink() and is_old(entry, max_age_days, now):
                found.append(entry)
    return [path for path in found if not is_protected(path, shared_target)]


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
    for path in find_candidates(
        args.work_root, args.workspace, args.shared_target, args.max_age_days, time.time()
    ):
        if is_protected(path, args.shared_target):
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
