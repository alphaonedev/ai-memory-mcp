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

Idle-target eviction (#7199, ``--evict-root`` + ``--runner-name``) runs AFTER the
prune. Under the per-runner target root it deletes every OTHER runner's target
directory whose newest mtime is older than IDLE_TARGET_DAYS and, while the
root's filesystem has less than FREE_FLOOR_GIB free, the oldest remaining other
targets. A sibling target is evicted only when idle: in both passes it is
skipped (``skipped busy``) while its in-use marker (written by
shared_cargo_target.py at job start, cleared by this script's post-job run) is
younger than IN_USE_MARKER_MAX_AGE_SECS or while its newest mtime is younger
than BUSY_MTIME_MINUTES. It never touches this runner's target, anything that
is not a real directory with a runner-safe name directly under the root
(symlinks are never followed or deleted), or any root other than the one
shared_cargo_target.py computes for the home. This runner's own in-use marker
is cleared first. One line is printed per eviction plus a summary line; a
floor that cannot be met prints a ``::warning::`` line.

Eviction is serialised against a job start (#7292): shared_cargo_target.py takes
an exclusive flock on ``<root>/.evict.lock`` around its mkdir and marker write;
eviction takes the same lock (bounded wait, a timeout skips the eviction), re-runs
the busy check, renames the target to ``<root>/.evicting-<name>-<pid>`` and only
then, lock released, deletes it. Names starting with ``.`` are never siblings;
stale ``.evicting-*`` leftovers are swept first. The lock file lives in the
protected root and is never deleted. An unreadable subtree, a walk cut short by
WALK_ENTRY_CAP or an unreadable marker counts as busy (#7289).

Exit codes: 0 ok, 2 bad arguments (validate_arguments, which also checks the
eviction arguments, and any argument path that does not resolve: ``refusing:
unresolvable path``). A failed removal is reported and counted but
does not fail the post-job step (exit stays 0): cleanup must never red a job.
Python 3.9+, standard library only.
"""
import argparse
import os
import shutil
import sys
import time
from pathlib import Path

import shared_cargo_target as shared

SECS_PER_DAY = 86400
TEMP_DIR_NAME = "_temp"
INCREMENTAL_RELATIVE = Path("target") / "debug" / "incremental"
TMP_PREFIX = ".tmp"
DEFAULT_MAX_AGE_DAYS = 7
IDLE_TARGET_DAYS = 7
FREE_FLOOR_GIB = 200
BYTES_PER_GIB = 1024 ** 3
BUSY_MTIME_MINUTES = 30
# #7294: the strict busy walk runs under the eviction lock, which a job start
# waits for at most shared.JOB_START_LOCK_TIMEOUT_SECS before proceeding without
# it. The walk is cut off sooner, so the lock hold is below that timeout by
# construction; a cut-off walk counts as busy.
EVICT_BUSY_WALK_DEADLINE_SECS = 30
# #7292: under the eviction lock a target is renamed to
# <root>/.evicting-<name>-<pid> and deleted there; a leftover of a killed
# eviction is swept once its mtime is older than BUSY_MTIME_MINUTES.
EVICTING_PREFIX = ".evicting-"
SECS_PER_MINUTE = 60
# Cap on entries visited when looking for a recent write or ranking a target.
WALK_ENTRY_CAP = 200_000
MIN_WORK_ROOT_COMPONENTS = 2
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_BAD_ARGS = EXIT_USAGE


def resolve(path):
    return Path(path).resolve()


UNRESOLVABLE_WARNED = set()


def _protect_unresolvable_child(child):
    """Lexical protection for a protected-root child that does not resolve (#7284 S2)."""
    if child not in UNRESOLVABLE_WARNED:
        UNRESOLVABLE_WARNED.add(child)
        print("protected root child unresolvable: %s" % child, file=sys.stderr)
    return Path(os.path.abspath(child))


def is_protected(candidate, protected_root):
    """True if ``candidate`` is, is inside, or contains the protected root."""
    # r3 F1: an unknown state (loop, vanished or unreadable path) is protected.
    try:
        cand = resolve(candidate)
        protected = resolve(protected_root)
        if _covers(cand, protected):
            return True
        # A direct child of the root may be a link that resolves elsewhere
        # (including back into the work root); its target is protected too.
        try:
            children = list(Path(protected_root).iterdir())
        except (FileNotFoundError, NotADirectoryError):
            return False  # no such root yet: it has no children to protect
        for child in children:
            # #7284 S2: each child resolves in its own try, so one loop link
            # protects only its own lexical path, not every candidate.
            try:
                real = resolve(child)
            except (OSError, RuntimeError):
                real = _protect_unresolvable_child(child)
            if _covers(cand, real):
                return True
        return False
    except (OSError, RuntimeError):
        return True


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
        try:
            entries = sorted(workspace.iterdir())
        except OSError as err:
            print("could not list %s: %s" % (workspace, err), file=sys.stderr)
            entries = []
        for entry in entries:
            if not entry.name.startswith(TMP_PREFIX):
                continue
            try:
                if entry.is_symlink():
                    skipped.append(entry)
                elif entry.is_dir():
                    found.append(entry)
            except OSError as err:
                print("skipped unreadable %s: %s" % (entry, err), file=sys.stderr)
    temp_root = Path(work_root) / TEMP_DIR_NAME
    if temp_root.is_symlink():
        skipped.append(temp_root)
    elif temp_root.is_dir():
        try:
            entries = sorted(temp_root.iterdir())
        except OSError as err:
            print("could not list %s: %s" % (temp_root, err), file=sys.stderr)
            entries = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    skipped.append(entry)
                elif entry.is_dir() and is_old(entry, max_age_days, now):
                    found.append(entry)
            except OSError as err:
                print("skipped unreadable %s: %s" % (entry, err), file=sys.stderr)
    keep = []
    for path in found:
        if is_protected(path, protected_root):
            print("skipped protected %s" % path)
        else:
            keep.append(path)
    return keep, skipped


def find_candidates(work_root, workspace, protected_root, max_age_days, now):
    """Return the stale paths to prune, never including protected ones."""
    return scan(work_root, workspace, protected_root, max_age_days, now)[0]


def is_filesystem_root(path):
    return path == path.parent


def validate_arguments(work_root, workspace, protected_root, evict_root=None,
                       runner_name=None, home=None):
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
    if evict_root:
        # #7199: the eviction arguments are validated here, with the prune
        # arguments, so EXIT_USAGE has one source.
        return eviction_problem(evict_root, runner_name, home)
    return None


def eviction_problem(evict_root, runner_name, home):
    """Return a refusal reason for the eviction arguments, or None when safe.

    The root must be an absolute, ``..``-free path strictly under the absolute
    home and must be the very directory shared_cargo_target.py computes for
    that home (the cache directory may itself be a symlink to an external disk,
    so the comparison is on resolved paths). The runner name must be a safe
    single path component.
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
    expected = shared.target_root_dir(home)
    if resolve(root) != resolve(expected):
        return "evict root is not the runner target root %s" % expected
    if not shared.valid_runner_name(runner_name):
        return "invalid runner name"
    return None


class WalkIncomplete(RuntimeError):
    """A strict walk stopped at WALK_ENTRY_CAP before it saw every entry."""


def newest_mtime(path, newer_than=None, max_entries=None, strict=False, deadline=None):
    """Newest mtime under ``path`` (symlinks never followed, only lstat'd).

    With ``newer_than`` the walk stops early and returns as soon as one entry
    is newer than it (the target is not idle). With ``max_entries`` the walk
    stops after that many entries and returns the newest seen so far.

    ``strict`` (#7289) is for the busy check: an unreadable directory or entry
    re-raises the OSError, and a walk that reaches ``max_entries`` raises
    WalkIncomplete, so the caller can treat an unknown state as busy.

    ``deadline`` (#7294) is an absolute ``time.monotonic()`` value; a walk that
    reaches it raises WalkIncomplete.
    """
    newest = os.lstat(path).st_mtime
    if newer_than is not None and newest > newer_than:
        return newest
    seen = 0
    pending = [str(path)]
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as scan_it:
                entries = list(scan_it)
        except OSError:
            if strict:
                raise
            continue  # unreadable directory: skip it, the caller treats the rest as is
        for entry in entries:
            seen += 1
            if deadline is not None and time.monotonic() >= deadline:
                raise WalkIncomplete("walk of %s passed its deadline" % path)
            if max_entries is not None and seen > max_entries:
                if strict:
                    raise WalkIncomplete("more than %d entries under %s" % (max_entries, path))
                return newest
            try:
                stamp = entry.stat(follow_symlinks=False).st_mtime
                is_real_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                if strict:
                    raise
                continue
            newest = max(newest, stamp)
            if newer_than is not None and newest > newer_than:
                return newest
            if is_real_dir:
                pending.append(entry.path)
    return newest


def other_targets(base, runner_name):
    """Real runner-named directories directly under ``base``, except this runner's.

    A name starting with ``.`` (the lock file, ``.evicting-*`` leftovers) is
    never a sibling target.
    """
    found = []
    for entry in sorted(base.iterdir()):
        if entry.name.startswith(".") or entry.name == runner_name:
            continue
        if entry.is_symlink() or not entry.is_dir():
            continue
        if not shared.valid_runner_name(entry.name):
            continue
        found.append(entry)
    return found


def sweep_stale_evicting(base, now, dry_run=False):
    """Delete leftover ``.evicting-*`` directories older than BUSY_MTIME_MINUTES.

    These are targets renamed by an eviction that was killed before its rmtree
    finished; no job can reach them. A symlink or a recent entry (possibly a
    running eviction) is left alone.
    """
    cutoff = now - BUSY_MTIME_MINUTES * SECS_PER_MINUTE
    swept = 0
    for entry in sorted(base.iterdir()):
        if not entry.name.startswith(EVICTING_PREFIX):
            continue
        try:
            if entry.is_symlink() or not entry.is_dir() or entry.lstat().st_mtime > cutoff:
                continue
            if shared.marker_is_fresh(entry, now):
                continue  # #7293: a live target must never be swept
            if dry_run:
                print("would sweep stale %s" % entry)
                continue
            shutil.rmtree(entry)
        except OSError as err:
            print("could not sweep %s: %s" % (entry, err), file=sys.stderr)
            continue
        swept += 1
        print("swept stale %s" % entry)
    return swept


def free_bytes_of(path):
    return shutil.disk_usage(path).free


def evict_idle_targets(evict_root, runner_name, home, idle_days, floor_gib, now,
                       dry_run=False, free_bytes=free_bytes_of,
                       lock_timeout=shared.EVICT_LOCK_TIMEOUT_SECS):
    """Evict idle (then, below the free floor, oldest) other-runner targets.

    Each delete (#7292) runs as: take ``<root>/.evict.lock`` (bounded wait; on a
    timeout the whole eviction is skipped, fail closed), re-run the busy check,
    ``os.rename`` the target to ``<root>/.evicting-<name>-<pid>``, release the
    lock, then ``rmtree`` the renamed path. A job that starts afterwards creates
    a fresh target and never shares a tree with the delete.
    """
    problem = eviction_problem(evict_root, runner_name, home)
    if problem:
        print("prune_runner_artifacts: skipping eviction: %s" % problem, file=sys.stderr)
        return EXIT_OK
    base = resolve(evict_root)
    if not base.is_dir():
        print("eviction summary: 0 evicted, root %s does not exist" % evict_root)
        return EXIT_OK
    cutoff = now - idle_days * SECS_PER_DAY
    busy_cutoff = now - BUSY_MTIME_MINUTES * SECS_PER_MINUTE
    floor_bytes = floor_gib * BYTES_PER_GIB
    state = {"evicted": 0, "failed": 0, "busy": 0, "lock_timeout": False}

    def is_busy(path):
        """True while a fresh in-use marker or a recent write says a job uses it."""
        # r3 F1 + #7289: an unreadable subtree, a walk cut short by WALK_ENTRY_CAP
        # or an unreadable marker counts as busy, never evicted.
        try:
            if shared.marker_is_fresh(path, now):
                return True
            return newest_mtime(
                path, newer_than=busy_cutoff, max_entries=WALK_ENTRY_CAP, strict=True,
                deadline=time.monotonic() + EVICT_BUSY_WALK_DEADLINE_SECS) > busy_cutoff
        except (OSError, RuntimeError):
            return True

    def remove(path, reason):
        if state["lock_timeout"]:
            return
        if path.is_symlink() or path.parent != base:
            print("skipped unsafe %s" % path)
            return
        if dry_run:
            if is_busy(path):
                state["busy"] += 1
                print("skipped busy %s" % path)
                return
            print("would evict %s (%s)" % (path, reason))
            state["evicted"] += 1
            return
        renamed = base / ("%s%s-%d" % (EVICTING_PREFIX, path.name, os.getpid()))
        with shared.evict_lock(base, lock_timeout) as held:
            if not held:
                state["lock_timeout"] = True
                print("prune_runner_artifacts: skipping eviction: lock %s not taken within %s s"
                      % (base / shared.EVICT_LOCK_NAME, lock_timeout), file=sys.stderr)
                return
            # The decision is made again under the lock: a job start holds the
            # same lock around its marker write, so after this check no marker
            # can appear in a target we are about to move.
            if path.is_symlink() or is_busy(path):
                state["busy"] += 1
                print("skipped busy %s" % path)
                return
            # #7294: a marker written since the walk began (a job start that gave
            # up on the lock) is seen here, immediately before the rename.
            if shared.marker_is_fresh(path, now):
                state["busy"] += 1
                print("skipped busy %s" % path)
                return
            try:
                os.rename(path, renamed)
                os.utime(renamed)
            except OSError as err:
                state["failed"] += 1
                print("could not evict %s: %s" % (path, err), file=sys.stderr)
                return
        try:
            shutil.rmtree(renamed)
        except OSError as err:
            state["failed"] += 1
            print("could not evict %s: %s" % (path, err), file=sys.stderr)
            return
        state["evicted"] += 1
        print("evicted %s (%s)" % (path, reason))

    sweep_stale_evicting(base, now, dry_run=dry_run)
    remaining = []
    for entry in other_targets(base, runner_name):
        try:
            idle = newest_mtime(entry, newer_than=cutoff) <= cutoff
        except OSError as err:
            print("skipped unreadable %s: %s" % (entry, err), file=sys.stderr)
            continue
        if idle:
            remove(entry, "idle over %d days" % idle_days)
        else:
            remaining.append(entry)
        if state["lock_timeout"]:
            break
    if state["lock_timeout"]:
        # #7295: eviction was skipped; rank no sibling and do not blame the floor.
        print("eviction summary: %d evicted, %d failed, %d busy skipped, "
              "eviction skipped: lock not taken" % (
                  state["evicted"], state["failed"], state["busy"]))
        return EXIT_OK
    if free_bytes(base) < floor_bytes:
        ranked = []
        for entry in remaining:
            try:
                ranked.append((newest_mtime(entry, max_entries=WALK_ENTRY_CAP), entry))
            except OSError as err:
                print("skipped unreadable %s: %s" % (entry, err), file=sys.stderr)
        ranked.sort()
        for _, entry in ranked:
            if state["lock_timeout"]:
                break
            if not dry_run and free_bytes(base) >= floor_bytes:
                break
            remove(entry, "below the %d GiB free-space floor" % floor_gib)
        if not dry_run and free_bytes(base) < floor_bytes:
            print("::warning::free space under %s is below the %d GiB floor and no idle "
                  "sibling target is left to evict" % (base, floor_gib))
    print("eviction summary: %d evicted, %d failed, %d busy skipped, %d GiB free (floor %d GiB)" % (
        state["evicted"], state["failed"], state["busy"],
        free_bytes(base) // BYTES_PER_GIB, floor_gib))
    return EXIT_OK


def is_out_of_tree(work_root, protected_root):
    """True if the protected root resolves outside the work root (and is not above it)."""
    return not is_within(protected_root, work_root)


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


def prune_all(args):
    """Scan and remove; return the number of failed removals."""
    failures = 0
    candidates, skipped = scan(
        args.work_root, args.workspace, args.protected_root, args.max_age_days, time.time()
    )
    for link in skipped:
        print("skipped symlink %s" % link)
    for path in candidates:
        if path.is_symlink():
            continue
        if is_protected(path, args.protected_root):
            print("skipped protected %s" % path)
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
        except (OSError, RuntimeError) as err:
            failures += 1
            print("could not remove %s: %s" % (path, err), file=sys.stderr)
    return failures


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_age_days < 1:
        parser.error("--max-age-days must be >= 1")
    if args.evict_root and not args.runner_name:
        parser.error("--evict-root requires --runner-name")
    if args.idle_target_days < 1 or args.free_floor_gib < 0:
        parser.error("--idle-target-days must be >= 1 and --free-floor-gib >= 0")
    UNRESOLVABLE_WARNED.clear()
    try:
        # #7284 S1: every resolve() of the prune AND the eviction arguments is
        # covered; a loop or unreadable path is a usage error, never a traceback.
        problem = validate_arguments(
            args.work_root, args.workspace, args.protected_root,
            args.evict_root, args.runner_name, args.home,
        )
        out_of_tree = not problem and is_out_of_tree(args.work_root, args.protected_root)
    except (OSError, RuntimeError) as err:
        print("prune_runner_artifacts: refusing: unresolvable path: %s" % err, file=sys.stderr)
        return EXIT_USAGE
    if problem:
        print("prune_runner_artifacts: refusing: %s" % problem, file=sys.stderr)
        return EXIT_USAGE
    if out_of_tree:
        print("protected root %s is outside the work root; nothing to protect" % args.protected_root)
    failures = 0
    try:
        failures = prune_all(args)
    except (OSError, RuntimeError) as err:
        # r3 F1: fail closed on deletion, soft on the exit code.
        failures += 1
        print("prune_runner_artifacts: aborted: %s" % err, file=sys.stderr)
    if failures:
        print("prune_runner_artifacts: %d removal(s) failed" % failures, file=sys.stderr)
    if args.evict_root:
        # #7199 + r3 F1: eviction never reds the job; an error is reported.
        try:
            shared.clear_in_use_marker(Path(args.evict_root) / args.runner_name)
            evict_idle_targets(
                args.evict_root, args.runner_name, args.home, args.idle_target_days,
                args.free_floor_gib, time.time(), dry_run=args.dry_run,
            )
        except (OSError, RuntimeError) as err:
            print("prune_runner_artifacts: eviction aborted: %s" % err, file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
