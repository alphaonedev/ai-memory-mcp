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
(each one met is reported as skipped; there is no os.walk, only is_symlink checks
and shutil.rmtree, which unlinks a symlink met inside a tree without entering it
and refuses a symlink given as the root) and every removal must resolve inside the
work root. A protected root whose realpath is outside the work root (a symlinked
cargo-target on fed runners) is unreachable by a prune confined to the work root,
so it is logged and ignored, not refused. Use ``--dry-run`` to list only.

Exit codes: 0 ok, 2 bad arguments. A failed removal is reported and counted but
does not fail the post-job step (exit stays 0): cleanup must never red a job.
Python 3.9+, standard library only.
"""
import argparse
import os
import shutil
import sys
import time
from pathlib import Path

SECS_PER_DAY = 86400
TEMP_DIR_NAME = "_temp"
INCREMENTAL_RELATIVE = Path("target") / "debug" / "incremental"
TMP_PREFIX = ".tmp"
DEFAULT_MAX_AGE_DAYS = 7
MIN_WORK_ROOT_COMPONENTS = 2
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_BAD_ARGS = EXIT_USAGE


def resolve(path):
    return Path(path).resolve()


def is_protected(candidate, protected_root):
    """True if ``candidate`` is, is inside, or contains the protected root."""
    cand = resolve(candidate)
    protected = resolve(protected_root)
    if _covers(cand, protected):
        return True
    # F1: a direct child of the root may be a link that resolves elsewhere
    # (including back into the work root); its target is protected too.
    try:
        children = list(Path(protected_root).iterdir())
    except OSError:
        return False
    return any(_covers(cand, resolve(child)) for child in children)


def _covers(cand, protected):
    return cand == protected or protected in cand.parents or cand in protected.parents


def is_within(path, root):
    """True if ``path`` resolves to ``root`` or somewhere below it (3.9-safe)."""
    try:
        resolve(path).relative_to(resolve(root))
    except ValueError:
        return False
    return True


def has_symlink_below(path, root):
    """True if ``path`` is not lexically below ``root`` or any component below it is a symlink."""
    base = Path(os.path.abspath(root))
    try:
        rel = Path(os.path.abspath(path)).relative_to(base)
    except ValueError:
        return True
    current = base
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def remove_candidate(path, work_root, protected_root):
    """Delete one candidate; return ``(status, reason)``, status removed or skipped.

    F2: re-check right before deleting, then delete the RESOLVED path, never a
    path that could be (or traverse) a symlink.
    """
    if has_symlink_below(path, work_root):
        return "skipped", "symlink in path chain"
    real = resolve(path)
    if real.is_symlink() or not real.is_dir():
        return "skipped", "not a plain directory"
    if is_protected(real, protected_root) or not is_within(real, work_root):
        return "skipped", "protected or outside root"
    shutil.rmtree(real)
    return "removed", None


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

    Refused: a work root that is a filesystem root, has fewer than two path
    components, is missing or not a directory; an empty or relative protected
    root; a protected root that is the work root or one of its ancestors; a
    workspace that does not resolve inside the work root. A protected root whose
    realpath is outside the work root is NOT refused (see ``is_out_of_tree``).
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
    if len(root.parts) - 1 < MIN_WORK_ROOT_COMPONENTS:
        return "work root has fewer than %d path components" % MIN_WORK_ROOT_COMPONENTS
    protected = resolve(protected_root)
    if protected == root or protected in root.parents:
        return "protected root is the work root or one of its ancestors"
    if not is_within(workspace, root):
        return "workspace is not inside the work root"
    return None


def is_out_of_tree(work_root, protected_root):
    """True if the protected root resolves outside the work root (and is not above it)."""
    return not is_within(protected_root, work_root)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--work-root", required=True, help="runner _work directory")
    parser.add_argument("--workspace", required=True, help="checkout of this job")
    parser.add_argument("--protected-root", required=True, help="per-runner cargo target root (never pruned)")
    parser.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS)
    parser.add_argument("--dry-run", action="store_true", help="list, delete nothing")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_age_days < 1:
        parser.error("--max-age-days must be >= 1")
    problem = validate_arguments(args.work_root, args.workspace, args.protected_root)
    if problem:
        print("prune_runner_artifacts: refusing: %s" % problem, file=sys.stderr)
        return EXIT_USAGE
    if is_out_of_tree(args.work_root, args.protected_root):
        print("protected root %s is outside the work root; nothing to protect" % args.protected_root)
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
            status, why = remove_candidate(path, args.work_root, args.protected_root)
            if status == "removed":
                print("removed %s" % path)
            else:
                print("skipped %s: %s" % (path, why))
        except OSError as err:
            failures += 1
            print("could not remove %s: %s" % (path, err), file=sys.stderr)
    if failures:
        print("prune_runner_artifacts: %d removal(s) failed" % failures, file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
