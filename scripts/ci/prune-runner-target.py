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
  * deletes an example together with its uplift: cargo builds
    ``examples/<name>-<hash>`` and uplifts it as ``examples/<name>`` (on Linux
    one inode, nlink 2, both links in ``examples/``; on macOS/APFS a clone: two
    inodes, nlink 1), so the pair goes in one run, with each name's ``.d`` and
    ``.dSYM`` twin.  ``-`` and ``_`` are one name (cargo builds
    ``my_demo-<hash>`` for the example ``my-demo``);
  * keeps cargo's bin uplift source ``deps/<bin>-<hash>``: the file that has a
    regular executable ``<profile>/<bin>`` of the same size and the same name
    (``-`` = ``_``) and the same bytes, found by NAME, SIZE AND CONTENT because
    cargo hard-links on Linux but copies (an APFS clone, nlink 1) on macOS; a
    same-size file with other bytes is an ordinary test executable.  Pruning the source makes
    cargo report the bin "Dirty" and relink it; also keeps any other
    hard-linked executable (a link whose partner is not the matching examples
    name): deleting one side frees nothing while the other exists;
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
  3. When GITHUB_WORKSPACE is set, the resolved dir lies inside it.  A dir
     outside it is accepted only with ``--allow-outside-workspace`` AND when it
     IS the resolved CARGO_TARGET_DIR the runner exported.  The workflows never
     pass the flag: a target dir shared by several runners would let one job's
     prune delete another job's test binaries while that job runs them.
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
(``%`` -> ``%25``, CR -> ``%0D``, LF -> ``%0A``) and ``#`` -> ``%23`` (the
runner also parses the legacy ``##[command]`` form anywhere in a line), and a
byte that is not UTF-8, and every other control character (C0, DEL, C1), is
written as ``\\xNN``, so a hostile file name can never
start a log line or a command of its own and printing never raises.  A
directory tree nested deeper than MAX_REMOVE_DEPTH (far beyond anything cargo
writes) is warned about and left in place instead of exhausting the stack or
the file descriptors.

OUTPUT.  One line per category, then ``freed_bytes=<n>``, a human-readable
total and ``::notice::prune-runner-target freed_bytes=<n> deleted=<k>
mode=<pruned|dry-run>`` (a job-summary annotation; ``k`` counts the candidates
fully removed).  A category row counts only the candidates fully removed (so the
rows sum to ``k``); a candidate that could not be removed is counted on its own
``failed <category> <n>`` line and in the warnings.  On Linux the count is exact, also under ``--dry-run``: a
hard-linked file counts once, and only when every one of its links is removed in
this run.  On macOS/APFS cargo's uplift copies are clones that share blocks, so
each clone is counted at full size and ``freed_bytes`` is an UPPER BOUND there
(a clone's blocks are released only when its twin goes too).

Python 3.9+, standard library only (the fleet nodes ship python3 on PATH; the
``Ensure python3 + node present`` step of ci.yml asserts it).

Usage:
  python3 scripts/ci/prune-runner-target.py --target-dir "${CARGO_TARGET_DIR:-target}"
  python3 scripts/ci/prune-runner-target.py --target-dir target --dry-run
  python3 scripts/ci/prune-runner-target.py --target-dir target --scope all
  python3 scripts/ci/prune-runner-target.py --target-dir "$CARGO_TARGET_DIR" --allow-outside-workspace
"""
from __future__ import annotations

import argparse
import errno
import os
import re
import stat
import sys
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Set, Tuple

# Outputs under <profile>/deps and <profile>/examples that ARE the warm cache
# (or its dep-info / debuginfo) and are never pruned in test-bins scope, even
# when the file carries an executable bit (proc-macro dylibs do).  ``.o`` stays
# on purpose: see "OBJECT FILES" in the module docstring.
KEEP_SUFFIXES = (".rlib", ".rmeta", ".so", ".dylib", ".dll", ".a", ".d", ".o", ".dwo", ".dwp", ".pdb")
# The only subdirectories of a profile this script ever deletes from.
ARTIFACT_DIRS = ("deps", "build", "incremental", "examples", ".fingerprint")
# cargo's metadata hash on an example: examples/<name>-<16 lowercase hex>.
EXAMPLE_HASH_RE = re.compile(r"[0-9a-f]{16}")
# A tree deeper than this is far beyond any cargo output; it is warned about and
# left in place (each level holds a directory fd and a Python frame).
MAX_REMOVE_DEPTH = 100
EXEC_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
EXIT_REFUSED = 2
EXIT_WARNED = 1
# The first line of every CACHEDIR.TAG (https://bford.info/cachedir/); cargo
# writes it at the root of each target dir it creates.
CACHEDIR_SIGNATURE = b"Signature: 8a477f597d28d172789f06886806bc55"
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
# C0 controls (CR and LF are already %-escaped), DEL and C1: never printed raw (#6254).
CONTROL_RE = re.compile("[\x00-\x1f\x7f-\x9f]")
WARNING_PREFIX = "::warning::prune-runner-target: "


def _escape(text: str) -> str:
    """Make a file name safe to print on a log line.

    Undecodable bytes (a surrogateescape-decoded name on Linux) become ``\\xNN``
    so a strict UTF-8 stdout never raises (R3-F3).  Then GitHub's
    workflow-command escaping (``%``, CR, LF) so one name can never become two
    log lines, and ``#`` -> ``%23`` because the runner's legacy parser accepts
    ``##[command]`` anywhere in a line (SR3-1).  Every other control character
    (C0, DEL, C1: ESC starts an ANSI sequence a log viewer or terminal acts on)
    becomes ``\\xNN`` (#6254).
    """
    text = os.fsencode(text).decode("utf-8", "backslashreplace")
    text = text.replace("%", "%25").replace("#", "%23").replace("\r", "%0D").replace("\n", "%0A")
    return CONTROL_RE.sub(lambda m: "\\x%02x" % ord(m.group()), text)


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
        self.kept: List[Tuple[str, str]] = []  # (name under the profile, why it stays)
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
    """Bytes freed: each inode counted once, only when its LAST link goes.

    Exact on Linux.  On APFS a clone is its own inode, so it is counted at full
    size and the total is an upper bound (clones share blocks).
    """

    def __init__(self) -> None:
        self.freed = 0
        self.deleted = 0  # candidates fully removed (or, dry-run, removable)
        self.errors: List[str] = []
        self.lines: List[str] = []
        self.per_category: Dict[str, Tuple[int, int]] = {}  # category -> (removed, bytes freed)
        self.failed: Dict[str, int] = {}  # category -> candidates that could not be fully removed (#6258)
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


def _remove(dir_fd: int, name: str, rel: str, tally: Tally, dry_run: bool, depth: int = 0) -> bool:
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
        if depth >= MAX_REMOVE_DEPTH:
            tally.warn(rel, OSError(errno.ELOOP, "nested more than %d levels deep; left in place" % MAX_REMOVE_DEPTH))
            return False
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
            try:
                with os.scandir(fd) as it:
                    children = sorted(entry.name for entry in it)
            except OSError as exc:
                tally.warn(rel, exc)
                return False
            for child in children:
                ok = _remove(fd, child, rel + "/" + child, tally, dry_run, depth + 1) and ok
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


def _add_with_twins(plan: Plan, fd: int, name: str, sub: str, present: Set[str], link_dsym: bool) -> None:
    """Queue ``name`` with its ``.d`` (regular) and ``.dSYM`` (dir) twins.

    ``link_dsym``: cargo also uplifts the dSYM of an example as a symlink
    ``examples/<name>.dSYM`` -> ``<name>-<hash>.dSYM``; that link is unlinked as
    a link, never followed.
    """
    prefix = "%s/%s/" % (plan.profile, sub)
    plan.candidates.append(Candidate(fd, name, prefix + name, sub + " executable"))
    for twin, category, want_dir in ((name + ".d", " dep-info", False), (name + ".dSYM", " dSYM", True)):
        if twin not in present:
            continue
        tst = _scan_lstat(plan, twin, fd, prefix + twin)
        if tst is None:
            continue
        if want_dir:
            ok = stat.S_ISDIR(tst.st_mode) or (link_dsym and stat.S_ISLNK(tst.st_mode))
        else:
            ok = stat.S_ISREG(tst.st_mode)
        if ok:
            plan.candidates.append(Candidate(fd, twin, prefix + twin, sub + category))


def _add_dsym_links(plan: Plan, fd: int, sub: str, names: List[str]) -> None:
    """Queue ``<x>.dSYM`` symlinks whose target is a ``.dSYM`` directory queued in this directory (#6257).

    On macOS cargo uplifts an example's packed debuginfo as the symlink
    ``examples/<name>.dSYM`` -> ``<name>-<hash>.dSYM``.  Once the target goes
    the link would dangle.  Only a link whose target is a bare name of a
    candidate of this scan is queued; it is read with readlink and unlinked as a
    link, never followed.  A link to anything else stays.
    """
    prefix = "%s/%s/" % (plan.profile, sub)
    queued = {c.name for c in plan.candidates if c.dir_fd == fd}
    for name in names:
        if not name.endswith(".dSYM") or name in queued:
            continue
        st = _scan_lstat(plan, name, fd, prefix + name)
        if st is None or not stat.S_ISLNK(st.st_mode):
            continue
        try:
            target = os.readlink(name, dir_fd=fd)
        except OSError as exc:
            plan.warn(prefix + name, exc)
            continue
        if target in queued and target.endswith(".dSYM"):
            plan.candidates.append(Candidate(fd, name, prefix + name, sub + " dSYM"))


def _same_bytes(dir_a: int, a: str, dir_b: int, b: str) -> bool:
    """Identical content: the bin's uplift is a hard link or a clone of its source.

    A file that cannot be read counts as identical, so it is kept (fail closed).
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        with open(os.open(a, flags, dir_fd=dir_a), "rb") as fa, open(os.open(b, flags, dir_fd=dir_b), "rb") as fb:
            while True:
                chunk_a, chunk_b = fa.read(1 << 20), fb.read(1 << 20)
                if chunk_a != chunk_b or not chunk_a:
                    return chunk_a == chunk_b
    except OSError:
        return True


def _norm(name: str) -> str:
    """cargo spells a target ``my-demo`` and its crate-style artifact ``my_demo-<hash>``."""
    return name.replace("-", "_")


def _hashed_stem(name: str) -> Optional[str]:
    """``stem`` of ``<stem>-<16 lowercase hex>``, else None."""
    stem, sep, digest = name.rpartition("-")
    if sep and stem and EXAMPLE_HASH_RE.fullmatch(digest):
        return stem
    return None


def _uplift_pair(names: List[str]) -> bool:
    """Exactly ``<name>`` and ``<name>-<16 hex>`` (``-`` = ``_``): cargo's example + its uplift."""
    if len(names) != 2:
        return False
    for plain, hashed in (names, names[::-1]):
        stem = _hashed_stem(hashed)
        if stem is not None and _norm(stem) == _norm(plain):
            return True
    return False


def _profile_bins(plan: Plan, profile_fd: int) -> Dict[str, Dict[int, str]]:
    """``{normalised name: {size: name}}`` of the regular executables directly under the profile dir.

    These are cargo's bin uplifts (``<profile>/<bin>``).  Found by name, because
    on macOS the uplift is a copy (an APFS clone, nlink 1), not a hard link.
    """
    found: Dict[str, Dict[int, str]] = {}
    prefix = plan.profile + "/"
    for name in _list_dir(plan, profile_fd, plan.profile) or []:
        st = _scan_lstat(plan, name, profile_fd, prefix + name)
        if st is not None and _is_test_executable(name, st):
            found.setdefault(_norm(name), {})[st.st_size] = name
    return found


def _scan_test_bins(plan: Plan, profile_fd: int) -> None:
    bins = _profile_bins(plan, profile_fd)
    for sub in ("deps", "examples"):
        fd = _open_sub(plan, profile_fd, sub)
        if fd is None:
            continue
        names = _list_dir(plan, fd, "%s/%s" % (plan.profile, sub))
        if names is None:
            continue
        present = set(names)
        prefix = "%s/%s/" % (plan.profile, sub)
        linked: Dict[Tuple[int, int], List[str]] = {}
        for name in names:
            st = _scan_lstat(plan, name, fd, prefix + name)
            if st is None or not _is_test_executable(name, st):
                continue
            if sub == "deps":
                stem = _hashed_stem(name)
                partner = bins.get(_norm(stem), {}).get(st.st_size) if stem is not None else None
                if partner is not None and not _same_bytes(fd, name, profile_fd, partner):
                    partner = None  # same name and size, other content: an ordinary test executable
                if partner is not None:
                    # cargo's bin uplift source (hard link on Linux, clone on
                    # macOS): pruning it makes cargo relink the bin.
                    plan.kept.append((sub + "/" + name, "uplift source of %s/%s (same name, size and content); "
                                      "pruning it forces a relink" % (plan.profile, partner)))
                    continue
            if st.st_nlink > 1:
                if sub == "examples" and st.st_nlink == 2:
                    linked.setdefault((st.st_dev, st.st_ino), []).append(name)
                    continue
                plan.kept.append((sub + "/" + name, "hard-linked (nlink=%d); frees nothing while its other "
                                  "link exists" % st.st_nlink))
                continue
            _add_with_twins(plan, fd, name, sub, present, False)
        for key in sorted(linked):
            pair = sorted(linked[key])
            if _uplift_pair(pair):
                # Both links of the inode are here: the pair goes together and
                # frees the bytes once (the Tally counts the last link).
                for name in pair:
                    _add_with_twins(plan, fd, name, sub, present, True)
            else:
                plan.kept.extend((sub + "/" + name, "hard-linked example without its matching <name> / "
                                  "<name>-<hash> twin in examples/") for name in pair)
        _add_dsym_links(plan, fd, sub, names)
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


def _inside_workspace(root: Path, env: Mapping[str, str], allow_outside: bool) -> bool:
    workspace = env.get("GITHUB_WORKSPACE", "")
    if not workspace:
        return True
    ws = Path(workspace).resolve()
    if ws in root.parents:
        return True
    if not allow_outside:
        return False
    explicit = env.get("CARGO_TARGET_DIR", "")
    return bool(explicit) and Path(explicit).resolve() == root


def plan_target(target_dir: str, profile: str, scope: str, env: Mapping[str, str],
                allow_outside: bool = False) -> Plan:
    """Run every safety check, open the directories O_NOFOLLOW and list what to remove.

    Raises Refused (nothing touched) or NothingToPrune.  The caller must
    ``close()`` the returned plan.
    """
    _validate_profile(profile)
    if scope not in ("test-bins", "all"):
        raise Refused("unknown scope %r" % scope)
    if not target_dir.strip():
        raise Refused("--target-dir is empty; an empty path would mean the current directory")
    for fn in (os.open, os.stat, os.unlink, os.rmdir, os.readlink):
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
    if not _inside_workspace(root, env, allow_outside):
        raise Refused("%s is outside GITHUB_WORKSPACE (%s); it is pruned only with --allow-outside-workspace "
                      "and only when it is the exported CARGO_TARGET_DIR"
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
        removed = _remove(cand.dir_fd, cand.name, cand.rel, tally, dry_run)
        size = tally.freed - before  # a partly removed tree still freed what went
        count, total = tally.per_category.get(cand.category, (0, 0))
        if removed:
            tally.deleted += 1
            tally.per_category[cand.category] = (count + 1, total + size)
        else:
            tally.failed[cand.category] = tally.failed.get(cand.category, 0) + 1
            if size:
                tally.per_category[cand.category] = (count, total + size)
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
    parser.add_argument("--allow-outside-workspace", action="store_true",
                        help="accept a target dir outside GITHUB_WORKSPACE when it is the exported "
                             "CARGO_TARGET_DIR (manual use; the workflows never pass it)")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")

    try:
        _validate_profile(args.profile)
        plan = plan_target(args.target_dir, args.profile, args.scope, os.environ,
                           args.allow_outside_workspace)
    except Refused as exc:
        return _refuse(str(exc))
    except NothingToPrune as exc:
        print("nothing to prune: %s" % _escape(str(exc)))
        print("freed_bytes=0")
        print("::notice::prune-runner-target freed_bytes=0 deleted=0 mode=%s"
              % ("dry-run" if args.dry_run else "pruned"))
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
    for category in sorted(tally.failed):
        print("  failed %-24s %6d" % (category, tally.failed[category]))
    for name, why in plan.kept:
        print("  kept %s: %s" % (_escape(name), _escape(why)))
    for note in plan.notes:
        print("  " + _escape(note))
    print("freed_bytes=%d" % tally.freed)
    print("freed %s (%s)" % (_human(tally.freed), mode))
    print("::notice::prune-runner-target freed_bytes=%d deleted=%d mode=%s" % (tally.freed, tally.deleted, mode))
    if tally.errors:
        print("%d entr%s could not be read or removed (warnings above); exit %d"
              % (len(tally.errors), "y" if len(tally.errors) == 1 else "ies", EXIT_WARNED))
        return EXIT_WARNED
    return 0


if __name__ == "__main__":
    sys.exit(main())
