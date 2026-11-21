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
import errno
import os
import shutil
import sys
import time
from pathlib import Path


def _load_workflow_annotation():
    """The shared module at WA_RELATIVE_PATH from this file's real directory, by path only, never through
    sys.path; every name in WA_REQUIRED must be a callable of it (#9365, one shape in every script)."""
    import importlib.util
    import os
    path = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), WA_RELATIVE_PATH))
    loaded = sys.modules.get("workflow_annotation")
    if loaded is not None and os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
        module = loaded
    else:
        spec = importlib.util.spec_from_file_location("workflow_annotation", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # absent, unreadable or broken: it raises here, the try below catches it
    missing = [name for name in WA_REQUIRED if not callable(getattr(module, name, None))]
    if missing:
        raise AttributeError("workflow_annotation.py lacks " + ", ".join(missing))
    if loaded is None:
        sys.modules["workflow_annotation"] = module
    return module


# The one shared-module load shape of scripts/ (#9365, ruling bcd0a15c; LoaderShape pins it).
WA_PROG = "prune_runner_artifacts"
WA_RELATIVE_PATH = "workflow_annotation.py"
WA_REQUIRED = ("annotation", "env_file_value", "log_line")
WA_EXIT_LOAD_REFUSED = 3  # a failed shared-module load; no other meaning in this script
WA_ERROR_TO_STDERR = False

try:
    wa = _load_workflow_annotation()
except (Exception, SystemExit) as exc:  # any failed load: one fixed line built without the module, then exit
    wa_cause = type(exc).__name__
    print("%s: refused: shared module workflow_annotation.py next to the script cannot be loaded (%s)"
          % (WA_PROG, wa_cause if wa_cause.isidentifier() else "BaseException"), file=sys.stderr, flush=True)
    print("::error title=prune_runner_artifacts refused::prune_runner_artifacts: refused: shared module workflow_annotation.py"
          " next to the script cannot be loaded",
          file=sys.stderr if WA_ERROR_TO_STDERR else sys.stdout, flush=True)
    sys.exit(WA_EXIT_LOAD_REFUSED)

# >>> sibling-load 9399 (canonical text; scripts/ci/sibling_load.py; test_sibling_load_9399 pins every copy)
class SiblingLoadError(ImportError):
    """A refused sibling load; ``reason`` is one of the fixed words the refusal line prints."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _sibling_path(filename):
    import os
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), filename)


def _load_sibling(filename, module_name):
    import os
    import stat
    import sys
    import types
    here = os.path.dirname(os.path.realpath(__file__))
    path = os.path.realpath(os.path.join(here, filename))
    if os.path.commonpath([here, path]) != here:
        raise SiblingLoadError("symlink leaves the script folder")
    loaded = sys.modules.get(module_name)
    if loaded is not None:
        if os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
            return loaded
        raise SiblingLoadError("module name taken")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise SiblingLoadError("absent") from None
    except OSError:
        raise SiblingLoadError("unreadable") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SiblingLoadError("not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            source = handle.read()
    except OSError:
        raise SiblingLoadError("unreadable") from None
    finally:
        os.close(fd)
    module = types.ModuleType(module_name)
    module.__file__ = path
    saved_path = list(sys.path)
    sys.modules[module_name] = module
    try:
        exec(compile(source, path, "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    finally:
        sys.path[:] = saved_path
    return module


def _sibling_refusal(prog, filename, exc):
    import sys
    why = exc.reason if isinstance(exc, SiblingLoadError) else type(exc).__name__
    if not why.replace(" ", "_").isidentifier():
        why = "BaseException"
    # The path comes from the checkout, so a control character in a folder name must not start a second output line
    # (a runner reads workflow commands at a line start): every non-printable character is written as its escape.
    shown = "".join(ch if ch.isprintable() else ascii(ch)[1:-1] for ch in _sibling_path(filename))
    print("%s: refused: sibling module %s at %s cannot be loaded (%s)" % (prog, filename, shown, why),
          file=sys.stderr, flush=True)
# <<< sibling-load 9399


SIBLING_PROG = "prune_runner_artifacts"
SIBLING_EXIT_LOAD_REFUSED = 3

try:
    shared = _load_sibling("shared_cargo_target.py", "shared_cargo_target")
except (Exception, SystemExit) as exc:  # any failed load ends here with one fixed line (#9399)
    _sibling_refusal(SIBLING_PROG, "shared_cargo_target.py", exc)
    sys.exit(SIBLING_EXIT_LOAD_REFUSED)


def log(text, file=None):
    """One plain log line; an untrusted path in it can never start a workflow command or add a line (#9365)."""
    print(wa.log_line(text), file=file)


SECS_PER_DAY = 86400
TEMP_DIR_NAME = "_temp"
INCREMENTAL_RELATIVE = Path("target") / "debug" / "incremental"
TMP_PREFIX = ".tmp"
DEFAULT_MAX_AGE_DAYS = 7
IDLE_TARGET_DAYS = 7
FREE_FLOOR_GIB = 200
BYTES_PER_GIB = 1024 ** 3
BUSY_MTIME_MINUTES = 30
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
    """Resolve ``path``; a symlink loop raises ``RuntimeError`` on every Python.

    Python 3.13+ no longer raises for a loop in non-strict ``Path.resolve()``, so
    the loop is detected explicitly: following the original path yields ELOOP.
    A merely missing path stays resolvable (#8275).
    """
    resolved = Path(path).resolve()
    try:
        os.stat(path)
    except OSError as err:
        if err.errno == errno.ELOOP:
            raise RuntimeError("Symlink loop from %r" % str(path)) from err
    return resolved


UNRESOLVABLE_WARNED = set()


def _protect_unresolvable_child(child):
    """Lexical protection for a protected-root child that does not resolve (#7284 S2)."""
    if child not in UNRESOLVABLE_WARNED:
        UNRESOLVABLE_WARNED.add(child)
        log("protected root child unresolvable: %s" % child, file=sys.stderr)
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
            log("could not list %s: %s" % (workspace, err), file=sys.stderr)
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
                log("skipped unreadable %s: %s" % (entry, err), file=sys.stderr)
    temp_root = Path(work_root) / TEMP_DIR_NAME
    if temp_root.is_symlink():
        skipped.append(temp_root)
    elif temp_root.is_dir():
        try:
            entries = sorted(temp_root.iterdir())
        except OSError as err:
            log("could not list %s: %s" % (temp_root, err), file=sys.stderr)
            entries = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    skipped.append(entry)
                elif entry.is_dir() and is_old(entry, max_age_days, now):
                    found.append(entry)
            except OSError as err:
                log("skipped unreadable %s: %s" % (entry, err), file=sys.stderr)
    keep = []
    for path in found:
        if is_protected(path, protected_root):
            log("skipped protected %s" % path)
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


def newest_mtime(path, newer_than=None, max_entries=None, strict=False):
    """Newest mtime under ``path`` (symlinks never followed, only lstat'd).

    With ``newer_than`` the walk stops early and returns as soon as one entry
    is newer than it (the target is not idle). With ``max_entries`` the walk
    stops after that many entries and returns the newest seen so far.

    ``strict`` (#7289) is for the busy check: an unreadable directory or entry
    re-raises the OSError, and a walk that reaches ``max_entries`` raises
    WalkIncomplete, so the caller can treat an unknown state as busy.
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
            if dry_run:
                log("would sweep stale %s" % entry)
                continue
            shutil.rmtree(entry)
        except OSError as err:
            log("could not sweep %s: %s" % (entry, err), file=sys.stderr)
            continue
        swept += 1
        log("swept stale %s" % entry)
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
        log("prune_runner_artifacts: skipping eviction: %s" % problem, file=sys.stderr)
        return EXIT_OK
    base = resolve(evict_root)
    if not base.is_dir():
        log("eviction summary: 0 evicted, root %s does not exist" % evict_root)
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
                path, newer_than=busy_cutoff, max_entries=WALK_ENTRY_CAP, strict=True) > busy_cutoff
        except (OSError, RuntimeError):
            return True

    def remove(path, reason):
        if state["lock_timeout"]:
            return
        if path.is_symlink() or path.parent != base:
            log("skipped unsafe %s" % path)
            return
        if dry_run:
            if is_busy(path):
                state["busy"] += 1
                log("skipped busy %s" % path)
                return
            log("would evict %s (%s)" % (path, reason))
            state["evicted"] += 1
            return
        renamed = base / ("%s%s-%d" % (EVICTING_PREFIX, path.name, os.getpid()))
        with shared.evict_lock(base, lock_timeout) as held:
            if not held:
                state["lock_timeout"] = True
                log("prune_runner_artifacts: skipping eviction: lock %s not taken within %s s"
                      % (base / shared.EVICT_LOCK_NAME, lock_timeout), file=sys.stderr)
                return
            # The decision is made again under the lock: a job start holds the
            # same lock around its marker write, so after this check no marker
            # can appear in a target we are about to move.
            if path.is_symlink() or is_busy(path):
                state["busy"] += 1
                log("skipped busy %s" % path)
                return
            try:
                os.rename(path, renamed)
                os.utime(renamed)
            except OSError as err:
                state["failed"] += 1
                log("could not evict %s: %s" % (path, err), file=sys.stderr)
                return
        try:
            shutil.rmtree(renamed)
        except OSError as err:
            state["failed"] += 1
            log("could not evict %s: %s" % (path, err), file=sys.stderr)
            return
        state["evicted"] += 1
        log("evicted %s (%s)" % (path, reason))

    sweep_stale_evicting(base, now, dry_run=dry_run)
    remaining = []
    for entry in other_targets(base, runner_name):
        try:
            idle = newest_mtime(entry, newer_than=cutoff) <= cutoff
        except OSError as err:
            log("skipped unreadable %s: %s" % (entry, err), file=sys.stderr)
            continue
        if idle:
            remove(entry, "idle over %d days" % idle_days)
        else:
            remaining.append(entry)
    if free_bytes(base) < floor_bytes:
        ranked = []
        for entry in remaining:
            try:
                ranked.append((newest_mtime(entry, max_entries=WALK_ENTRY_CAP), entry))
            except OSError as err:
                log("skipped unreadable %s: %s" % (entry, err), file=sys.stderr)
        ranked.sort()
        for _, entry in ranked:
            if state["lock_timeout"]:
                break
            if not dry_run and free_bytes(base) >= floor_bytes:
                break
            remove(entry, "below the %d GiB free-space floor" % floor_gib)
        if not dry_run and free_bytes(base) < floor_bytes:
            print(wa.annotation("warning", "free space under %s is below the %d GiB floor and no idle "
                                "sibling target is left to evict" % (base, floor_gib)))
    log("eviction summary: %d evicted, %d failed, %d busy skipped, %d GiB free (floor %d GiB)" % (
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
        log("skipped symlink %s" % link)
    for path in candidates:
        if path.is_symlink():
            continue
        if is_protected(path, args.protected_root):
            log("skipped protected %s" % path)
            continue
        if not is_within(path, args.work_root):
            log("skipped outside root %s" % path)
            continue
        if args.dry_run:
            log("would remove %s" % path)
            continue
        try:
            status, why = remove_candidate(path, args.work_root, args.protected_root)
            if status == "removed":
                log("removed %s" % path)
            else:
                log("skipped %s: %s" % (path, why))
        except (OSError, RuntimeError) as err:
            failures += 1
            log("could not remove %s: %s" % (path, err), file=sys.stderr)
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
        log("prune_runner_artifacts: refusing: unresolvable path: %s" % err, file=sys.stderr)
        return EXIT_USAGE
    if problem:
        log("prune_runner_artifacts: refusing: %s" % problem, file=sys.stderr)
        return EXIT_USAGE
    if out_of_tree:
        log("protected root %s is outside the work root; nothing to protect" % args.protected_root)
    failures = 0
    try:
        failures = prune_all(args)
    except (OSError, RuntimeError) as err:
        # r3 F1: fail closed on deletion, soft on the exit code.
        failures += 1
        log("prune_runner_artifacts: aborted: %s" % err, file=sys.stderr)
    if failures:
        log("prune_runner_artifacts: %d removal(s) failed" % failures, file=sys.stderr)
    if args.evict_root:
        # #7199 + r3 F1: eviction never reds the job; an error is reported.
        try:
            shared.clear_in_use_marker(Path(args.evict_root) / args.runner_name)
            evict_idle_targets(
                args.evict_root, args.runner_name, args.home, args.idle_target_days,
                args.free_floor_gib, time.time(), dry_run=args.dry_run,
            )
        except (OSError, RuntimeError) as err:
            log("prune_runner_artifacts: eviction aborted: %s" % err, file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
