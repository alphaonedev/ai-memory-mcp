#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Prune a self-hosted runner's persistent cargo target dir at job end (#6118).

THE DEFECT.  On the self-hosted fleet the workspace ``target/`` is PERSISTENT
and is the warm compile cache (#3128): the rlib / rmeta / proc-macro outputs in
``debug/deps``, the build-script outputs in ``debug/build`` and the fingerprints
in ``debug/.fingerprint`` are what make the next job's compile take minutes
instead of an hour.  The ~1000 TEST EXECUTABLES that `cargo test` links into
``debug/deps`` are not cache: cargo relinks every one of them whenever the lib
crate changes, which is every commit, so keeping them past the job buys
nothing.  On the Linux x86_64 runners (packed debuginfo) they cost ~164 MB each
with debuginfo on, ~164 GB per runner, and two runners took the f2 root
filesystem from 224 GB to 78 GB free in two hours (#6118); a parallel pair of
fresh builds would have hit ENOSPC mid-job.

WHAT THIS DOES (``--scope test-bins``, the default, run as the last step of
every self-hosted cargo job, after a successful checkout):
  * deletes every regular, non-symlink, executable file directly under
    ``<target>/<profile>/deps`` and ``<target>/<profile>/examples`` whose name
    does not end in a library / metadata / dep-info / debuginfo suffix
    (KEEP_SUFFIXES), together with its ``<name>.d`` dep-info twin and its
    macOS ``<name>.dSYM`` bundle;
  * deletes the contents of ``<target>/<profile>/incremental`` (CI runs with
    CARGO_INCREMENTAL=0, so anything there is stale state from elsewhere);
  * keeps a hard-linked executable (cargo's uplift source ``deps/<bin>-<hash>``,
    the other link being ``<profile>/<bin>``): deleting one side frees nothing
    while the other exists, and it is one bin, not one of the ~1000 tests;
  * keeps everything else, so the next compile stays warm.
``--scope all`` instead removes the five artifact dirs ``deps``, ``build``,
``incremental``, ``examples`` and ``.fingerprint`` under the profile wholesale:
the operator's disk-emergency prune, equivalent to `cargo clean --profile dev`
for that profile but without needing a toolchain.

OBJECT FILES.  Loose ``deps/*.o`` files are KEPT in both the default scope and
the docs.  At the pinned debuginfo level ``0`` (enforced on every self-hosted
job by scripts/test/test_ci_runner_target_hygiene_6118.py) macOS writes none,
so a rule for them would never fire.  At a non-zero level on macOS
(``split-debuginfo=unpacked``) they are the debug map of EVERY artifact linked
from those crates, the kept bins included, not only of the test executables;
deleting them would break symbolication of what the cache keeps.

SAFETY.  Fail closed, checks in this order, nothing touched on a refusal (exit 2):
  1. ``--profile`` is one path component (not empty, ``.``, ``..`` or a path),
     and ``--target-dir`` is not empty (an empty path would mean the cwd).
  2. ``--target-dir`` is not itself a symlink.  A target dir that does not
     exist yet (a job that failed before its first compile) is "nothing to
     prune", exit 0.  One that is not a directory is refused.
  3. When GITHUB_WORKSPACE is set, the resolved dir lies inside it, or it IS
     the resolved CARGO_TARGET_DIR the runner exported.
  4. It carries cargo's own marker: a regular ``CACHEDIR.TAG`` whose first line
     is the cachedir signature (opened non-blocking and checked with fstat, so a
     FIFO or device swapped in cannot stall the step), or a regular
     ``<profile>/.cargo-lock``.
  5. The profile dir is a real directory, not a symlink.
Every directory is opened with O_NOFOLLOW and held open from the scan to the
delete; every stat, unlink and rmdir is relative to those fds, so swapping a
directory for a symlink between the scan and the delete cannot redirect the
removal outside the tree.  A symlink entry is skipped in ``test-bins`` scope
and removed as a link, never dereferenced, in ``all`` scope.  Only the five
dirs named above under the chosen profile are ever touched.  An entry that
vanished meanwhile is not an error.  Any other error reading a directory or an
entry during the scan, or removing an entry, prints a ``::warning::`` line and
the run continues with the rest; the totals are still printed and the exit code
is 1.  Every name printed is escaped as GitHub escapes a workflow-command value
(``%`` -> ``%25``, CR -> ``%0D``, LF -> ``%0A``), so a hostile file name can
never start a log line of its own.

OUTPUT.  One line per category, then ``freed_bytes=<n>`` and a human-readable
total.  The count is exact, also under ``--dry-run``: a hard-linked file counts
once, and only when every one of its links is removed in this run.

Python 3.9+, standard library only (the fleet nodes ship python3 on PATH; the
``Ensure python3 + node present`` step of ci.yml asserts it).

Usage:
  python3 scripts/ci/prune-runner-target.py --target-dir "${CARGO_TARGET_DIR:-target}"
  python3 scripts/ci/prune-runner-target.py --target-dir target --dry-run
  python3 scripts/ci/prune-runner-target.py --target-dir target --scope all
"""
from __future__ import annotations

import argparse
import errno
import os
import stat
import sys
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

# Outputs under <profile>/deps and <profile>/examples that ARE the warm cache
# (or its dep-info / debuginfo) and are never pruned in test-bins scope, even
# when the file carries an executable bit (proc-macro dylibs do).  ``.o`` stays
# on purpose: see "OBJECT FILES" in the module docstring.
KEEP_SUFFIXES = (".rlib", ".rmeta", ".so", ".dylib", ".dll", ".a", ".d", ".o", ".dwo", ".dwp", ".pdb")
# The only subdirectories of a profile this script ever deletes from.
ARTIFACT_DIRS = ("deps", "build", "incremental", "examples", ".fingerprint")
EXEC_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
EXIT_REFUSED = 2
EXIT_WARNED = 1
# The first line of every CACHEDIR.TAG (https://bford.info/cachedir/); cargo
# writes it at the root of each target dir it creates.
CACHEDIR_SIGNATURE = b"Signature: 8a477f597d28d172789f06886806bc55"
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
WARNING_PREFIX = "::warning::prune-runner-target: "


def _escape(text: str) -> str:
    """GitHub's workflow-command value escaping: one name can never become two log lines."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _warn(errors: List[str], rel: str, exc: OSError) -> None:
    msg = "%s: %s" % (rel, exc.strerror or exc)
    errors.append(msg)
    print(WARNING_PREFIX + _escape(msg))


class Refused(Exception):
    """The target dir fails a safety check; nothing was touched (exit 2)."""


class NothingToPrune(Exception):
    """There is no target dir or no profile dir yet (exit 0, freed 0)."""


def _validate_profile(profile: str) -> None:
    if profile in ("", ".", "..") or "/" in profile or "\\" in profile or "\0" in profile:
        raise Refused("--profile must be one path component, got %r" % profile)


def _open_dir(name: str, dir_fd: Optional[int]) -> int:
    """Open a directory without following a symlink in its last component."""
    return os.open(name, DIR_FLAGS, dir_fd=dir_fd)


def _lstat(name: str, dir_fd: int) -> os.stat_result:
    return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)


def _not_a_real_dir(exc: OSError) -> bool:
    """open(O_NOFOLLOW|O_DIRECTORY) on a symlink or a file: ELOOP on Linux, ENOTDIR on macOS."""
    return exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK)


class Candidate:
    """One entry to remove: ``name`` under the directory held open as ``dir_fd``."""

    def __init__(self, dir_fd: int, name: str, rel: str, category: str) -> None:
        self.dir_fd = dir_fd
        self.name = name
        self.rel = rel
        self.category = category


class Plan:
    """The scan result.  Holds the directory fds every deletion goes through."""

    def __init__(self, root: Path, profile: str, scope: str) -> None:
        self.root = root
        self.profile = profile
        self.scope = scope
        self.fds: List[int] = []
        self.candidates: List[Candidate] = []
        self.kept: List[str] = []
        self.notes: List[str] = []
        self.errors: List[str] = []  # scan-phase warnings, carried into the exit code

    def warn(self, rel: str, exc: OSError) -> None:
        _warn(self.errors, rel, exc)

    def hold(self, fd: int) -> int:
        self.fds.append(fd)
        return fd

    def close(self) -> None:
        while self.fds:
            os.close(self.fds.pop())


class Tally:
    """Exact bytes freed (each inode counted once, only when its LAST link goes)."""

    def __init__(self) -> None:
        self.freed = 0
        self.errors: List[str] = []
        self.lines: List[str] = []
        self.per_category: Dict[str, Tuple[int, int]] = {}
        self._links: Dict[Tuple[int, int], List[int]] = {}

    def account(self, st: os.stat_result) -> None:
        if not stat.S_ISREG(st.st_mode):
            return
        key = (st.st_dev, st.st_ino)
        rec = self._links.get(key)
        if rec is not None:
            rec[1] += 1
            if rec[1] == rec[0]:
                self.freed += st.st_size
        elif st.st_nlink <= 1:
            self.freed += st.st_size
        else:
            # One link of several.  The bytes are freed only if every other link
            # is removed in this run too; a link that survives (the uplifted
            # <profile>/<bin>) keeps them allocated.
            self._links[key] = [st.st_nlink, 1]

    def warn(self, rel: str, exc: OSError) -> None:
        _warn(self.errors, rel, exc)


def _remove(dir_fd: int, name: str, rel: str, tally: Tally, dry_run: bool) -> bool:
    """Remove ``name`` under ``dir_fd`` (a tree depth-first), never following a symlink.

    Returns False when something under it could not be removed (already warned).
    A name that vanished meanwhile is not an error and frees nothing.
    """
    try:
        st = _lstat(name, dir_fd)
    except FileNotFoundError:
        return True
    except OSError as exc:
        tally.warn(rel, exc)
        return False
    if stat.S_ISDIR(st.st_mode):
        try:
            fd = _open_dir(name, dir_fd)
        except FileNotFoundError:
            return True
        except OSError as exc:
            tally.warn(rel, exc)
            return False
        ok = True
        try:
            got = os.fstat(fd)
            if (got.st_dev, got.st_ino) != (st.st_dev, st.st_ino):
                tally.warn(rel, OSError(errno.EAGAIN, "replaced while pruning; left in place"))
                return False
            with os.scandir(fd) as it:
                children = sorted(entry.name for entry in it)
            for child in children:
                ok = _remove(fd, child, rel + "/" + child, tally, dry_run) and ok
        finally:
            os.close(fd)
        if not ok or dry_run:
            return ok
        try:
            os.rmdir(name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        except OSError as exc:
            tally.warn(rel, exc)
            return False
        return True
    if not dry_run:
        try:
            os.unlink(name, dir_fd=dir_fd)
        except FileNotFoundError:
            return True
        except OSError as exc:
            tally.warn(rel, exc)
            return False
    tally.account(st)
    return True


def _is_test_executable(name: str, st: os.stat_result) -> bool:
    """A regular, non-symlink file with an executable bit and no library suffix."""
    return stat.S_ISREG(st.st_mode) and not name.endswith(KEEP_SUFFIXES) and bool(st.st_mode & EXEC_BITS)


def _open_sub(plan: Plan, profile_fd: int, sub: str) -> Optional[int]:
    """Open ``<profile>/<sub>`` O_NOFOLLOW; None when absent, not a real directory or unreadable (warned)."""
    try:
        return plan.hold(_open_dir(sub, profile_fd))
    except FileNotFoundError:
        return None
    except OSError as exc:
        if _not_a_real_dir(exc):
            plan.notes.append("skipped %s/%s: a symlink or not a directory (never followed)" % (plan.profile, sub))
        else:
            plan.warn("%s/%s" % (plan.profile, sub), exc)
        return None


def _list_dir(plan: Plan, fd: int, rel: str) -> Optional[List[str]]:
    """Sorted entry names of the directory held as ``fd``; None (warned) when it cannot be read."""
    try:
        with os.scandir(fd) as it:
            return sorted(entry.name for entry in it)
    except OSError as exc:
        plan.warn(rel, exc)
        return None


def _scan_lstat(plan: Plan, name: str, fd: int, rel: str) -> Optional[os.stat_result]:
    """lstat during the scan: None when the entry vanished (silent) or cannot be read (warned)."""
    try:
        return _lstat(name, fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        plan.warn(rel, exc)
        return None


def _scan_test_bins(plan: Plan, profile_fd: int) -> None:
    for sub in ("deps", "examples"):
        fd = _open_sub(plan, profile_fd, sub)
        if fd is None:
            continue
        names = _list_dir(plan, fd, "%s/%s" % (plan.profile, sub))
        if names is None:
            continue
        present = set(names)
        prefix = "%s/%s/" % (plan.profile, sub)
        for name in names:
            st = _scan_lstat(plan, name, fd, prefix + name)
            if st is None or not _is_test_executable(name, st):
                continue
            if st.st_nlink > 1:
                # cargo's uplift source deps/<bin>-<hash>, hard-linked to
                # <profile>/<bin>: deleting this side frees nothing.
                plan.kept.append(sub + "/" + name)
                continue
            plan.candidates.append(Candidate(fd, name, prefix + name, sub + " executable"))
            for twin, category, want_dir in ((name + ".d", " dep-info", False), (name + ".dSYM", " dSYM", True)):
                if twin not in present:
                    continue
                tst = _scan_lstat(plan, twin, fd, prefix + twin)
                if tst is not None and (stat.S_ISDIR(tst.st_mode) if want_dir else stat.S_ISREG(tst.st_mode)):
                    plan.candidates.append(Candidate(fd, twin, prefix + twin, sub + category))
    fd = _open_sub(plan, profile_fd, "incremental")
    if fd is None:
        return
    prefix = "%s/incremental/" % plan.profile
    for name in _list_dir(plan, fd, prefix.rstrip("/")) or []:
        st = _scan_lstat(plan, name, fd, prefix + name)
        if st is None or stat.S_ISLNK(st.st_mode):
            continue
        plan.candidates.append(Candidate(fd, name, prefix + name, "incremental"))


def _scan_all(plan: Plan, profile_fd: int) -> None:
    for sub in ARTIFACT_DIRS:
        st = _scan_lstat(plan, sub, profile_fd, "%s/%s" % (plan.profile, sub))
        if st is None:
            continue
        if not stat.S_ISDIR(st.st_mode):
            plan.notes.append("skipped %s/%s: a symlink or not a directory (never followed)" % (plan.profile, sub))
            continue
        plan.candidates.append(Candidate(profile_fd, sub, "%s/%s" % (plan.profile, sub), sub + " (whole dir)"))


def _has_cachedir_tag(root_fd: int) -> bool:
    """A regular CACHEDIR.TAG carrying the signature.

    Opened O_NONBLOCK|O_NOFOLLOW and checked with fstat on the open fd: a FIFO
    or device in its place (even one swapped in after a stat) is rejected
    instead of blocking the step until the job times out.
    """
    try:
        fd = os.open("CACHEDIR.TAG", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
    except OSError:
        return False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False
        head = os.read(fd, len(CACHEDIR_SIGNATURE))
    except OSError:
        return False
    finally:
        os.close(fd)
    return head == CACHEDIR_SIGNATURE


def _inside_workspace(root: Path, env: Mapping[str, str]) -> bool:
    workspace = env.get("GITHUB_WORKSPACE", "")
    if not workspace:
        return True
    ws = Path(workspace).resolve()
    if ws in root.parents:
        return True
    explicit = env.get("CARGO_TARGET_DIR", "")
    return bool(explicit) and Path(explicit).resolve() == root


def plan_target(target_dir: str, profile: str, scope: str, env: Mapping[str, str]) -> Plan:
    """Run every safety check, open the directories O_NOFOLLOW and list what to remove.

    Raises Refused (nothing touched) or NothingToPrune.  The caller must
    ``close()`` the returned plan.
    """
    _validate_profile(profile)
    if scope not in ("test-bins", "all"):
        raise Refused("unknown scope %r" % scope)
    if not target_dir.strip():
        raise Refused("--target-dir is empty; an empty path would mean the current directory")
    for fn in (os.open, os.stat, os.unlink, os.rmdir):
        if fn not in os.supports_dir_fd:
            raise Refused("this Python lacks dir_fd support for %s; refusing a path-based delete" % fn.__name__)
    raw = Path(target_dir)
    try:
        raw_st = os.lstat(str(raw))
    except FileNotFoundError:
        raise NothingToPrune("%s does not exist" % raw)
    if stat.S_ISLNK(raw_st.st_mode):
        raise Refused("%s is a symlink; a target dir is never followed through a link" % raw)
    if not stat.S_ISDIR(raw_st.st_mode):
        raise Refused("%s is not a directory" % raw)
    root = raw.resolve(strict=True)
    if not _inside_workspace(root, env):
        raise Refused("%s is outside GITHUB_WORKSPACE (%s) and is not CARGO_TARGET_DIR"
                      % (root, env.get("GITHUB_WORKSPACE", "")))
    plan = Plan(root, profile, scope)
    try:
        try:
            root_fd = plan.hold(_open_dir(str(root), None))
        except OSError as exc:
            raise Refused("cannot open %s without following links: %s" % (root, exc.strerror or exc))
        got = os.fstat(root_fd)
        if (got.st_dev, got.st_ino) != (raw_st.st_dev, raw_st.st_ino):
            raise Refused("%s changed while it was being checked" % raw)
        profile_fd: Optional[int] = None
        profile_problem = ""
        try:
            profile_fd = plan.hold(_open_dir(profile, root_fd))
        except FileNotFoundError:
            pass
        except OSError as exc:
            if not _not_a_real_dir(exc):
                raise Refused("cannot open %s/%s: %s" % (root, profile, exc.strerror or exc))
            profile_problem = "%s/%s is a symlink or not a directory" % (root, profile)
        has_lock = False
        if profile_fd is not None:
            try:
                has_lock = stat.S_ISREG(_lstat(".cargo-lock", profile_fd).st_mode)
            except OSError:
                has_lock = False
        if not (_has_cachedir_tag(root_fd) or has_lock):
            raise Refused("%s has neither a cargo CACHEDIR.TAG (signature checked) nor %s/.cargo-lock; "
                          "not a cargo target dir" % (root, profile))
        if profile_problem:
            raise Refused(profile_problem + "; a profile dir is never followed through a link")
        if profile_fd is None:
            raise NothingToPrune("%s/%s does not exist" % (root, profile))
        if scope == "all":
            _scan_all(plan, profile_fd)
        else:
            _scan_test_bins(plan, profile_fd)
    except BaseException:
        plan.close()
        raise
    return plan


def execute(plan: Plan, dry_run: bool) -> Tally:
    """Remove (or, dry-run, only total) every candidate through the plan's fds."""
    tally = Tally()
    tally.errors.extend(plan.errors)  # scan-phase warnings (already printed) count toward exit 1
    verb = "would delete" if dry_run else "deleted"
    for cand in plan.candidates:
        before = tally.freed
        _remove(cand.dir_fd, cand.name, cand.rel, tally, dry_run)
        size = tally.freed - before
        count, total = tally.per_category.get(cand.category, (0, 0))
        tally.per_category[cand.category] = (count + 1, total + size)
        if dry_run:
            tally.lines.append("  %s %s (%s)" % (verb, _escape(cand.rel), _human(size)))
    return tally


def _refuse(msg: str) -> int:
    print("prune-runner-target: refusing: " + _escape(msg), file=sys.stderr)
    return EXIT_REFUSED


def _human(n: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    value = float(n)
    idx = 0
    while value >= 1024.0 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    return "%.1f %s" % (value, units[idx])


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target-dir", required=True,
                        help="cargo target directory (CARGO_TARGET_DIR or the workspace `target`)")
    parser.add_argument("--profile", default="debug",
                        help="profile subdirectory to prune under (default: debug)")
    parser.add_argument("--scope", choices=("test-bins", "all"), default="test-bins",
                        help="test-bins (default): test/example executables + incremental; "
                             "all: the five artifact dirs wholesale")
    parser.add_argument("--dry-run", action="store_true", help="list and total, delete nothing")
    args = parser.parse_args(argv)

    try:
        _validate_profile(args.profile)
        plan = plan_target(args.target_dir, args.profile, args.scope, os.environ)
    except Refused as exc:
        return _refuse(str(exc))
    except NothingToPrune as exc:
        print("nothing to prune: %s" % _escape(str(exc)))
        print("freed_bytes=0")
        return 0
    except OSError as exc:
        # The root checks raced with a change or hit an unreadable path before
        # anything was opened for deletion: nothing was touched.
        return _refuse("cannot check %s: %s" % (args.target_dir, exc))
    try:
        tally = execute(plan, args.dry_run)
    finally:
        plan.close()

    mode = "dry-run" if args.dry_run else "pruned"
    for line in tally.lines:
        print(line)
    print("%s %s scope=%s" % (mode, _escape(str(plan.root / plan.profile)), plan.scope))
    for category in sorted(tally.per_category):
        count, size = tally.per_category[category]
        print("  %-24s %6d  %s" % (category, count, _human(size)))
    for name in plan.kept:
        print("  kept hard-linked uplift source %s (frees nothing while <profile>/<bin> exists)" % _escape(name))
    for note in plan.notes:
        print("  " + _escape(note))
    print("freed_bytes=%d" % tally.freed)
    print("freed %s (%s)" % (_human(tally.freed), mode))
    if tally.errors:
        print("%d entr%s could not be read or removed (warnings above); exit %d"
              % (len(tally.errors), "y" if len(tally.errors) == 1 else "ies", EXIT_WARNED))
        return EXIT_WARNED
    return 0


if __name__ == "__main__":
    sys.exit(main())
