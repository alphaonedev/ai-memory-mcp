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
nothing.  At full debuginfo they cost ~170 MB each, ~164 GB per runner, and two
runners took the f2 root filesystem from 224 GB to 78 GB free in two hours
(#6118); a parallel pair of fresh builds would have hit ENOSPC mid-job.

WHAT THIS DOES (``--scope test-bins``, the default, run by every self-hosted
cargo job's last step under ``if: always()``):
  * deletes every regular, non-symlink, executable file directly under
    ``<target>/<profile>/deps`` and ``<target>/<profile>/examples`` whose name
    does not end in a library / metadata / dep-info suffix (``.rlib``,
    ``.rmeta``, ``.so``, ``.dylib``, ``.dll``, ``.a``, ``.d``, ``.o``,
    ``.dwo``), together with its ``<name>.d`` dep-info twin and its macOS
    ``<name>.dSYM`` bundle;
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

SAFETY.  Fail closed: the directory must exist and carry cargo's own marker
(``CACHEDIR.TAG`` at its root, or ``<profile>/.cargo-lock``), or nothing is
touched and the exit code is 2.  Deletion never leaves the resolved target dir,
never follows a symlink (a symlink entry is skipped in ``test-bins`` scope and
removed as a link, never dereferenced, in ``all`` scope), and only ever touches
the five dirs named above under the chosen profile.  ``--dry-run`` lists what
would go and still prints the byte total.

OUTPUT.  One line per category, then ``freed_bytes=<n>`` (exact, also under
``--dry-run``) and a human-readable total.  Exit 0 when nothing needed pruning.

Python 3.9+, standard library only (the fleet nodes ship python3 on PATH; the
``Ensure python3 + node present`` step of ci.yml asserts it).

Usage:
  python3 scripts/ci/prune-runner-target.py --target-dir "${CARGO_TARGET_DIR:-target}"
  python3 scripts/ci/prune-runner-target.py --target-dir target --dry-run
  python3 scripts/ci/prune-runner-target.py --target-dir target --scope all
"""
from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Outputs under <profile>/deps and <profile>/examples that ARE the warm cache
# (or its dep-info) and are never pruned in test-bins scope, even when the
# file carries an executable bit (proc-macro dylibs do).
KEEP_SUFFIXES = (".rlib", ".rmeta", ".so", ".dylib", ".dll", ".a", ".d", ".o", ".dwo", ".dwp", ".pdb")
# The only subdirectories of a profile this script ever deletes from.
ARTIFACT_DIRS = ("deps", "build", "incremental", "examples", ".fingerprint")
EXEC_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
EXIT_REFUSED = 2


class Candidate:
    """One path to delete, with its size (bytes, symlinks counted as 0)."""

    def __init__(self, path: Path, is_dir: bool, size: int, category: str) -> None:
        self.path = path
        self.is_dir = is_dir
        self.size = size
        self.category = category


def _tree_size(root: Path) -> int:
    """Bytes of regular files under ``root`` (lstat; symlinks count 0; never followed)."""
    total = 0
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            st = os.lstat(os.path.join(dirpath, name))
            if stat.S_ISREG(st.st_mode):
                total += st.st_size
    return total


def _entry_size(entry: os.DirEntry) -> int:
    st = entry.stat(follow_symlinks=False)
    if stat.S_ISREG(st.st_mode):
        return st.st_size
    if stat.S_ISDIR(st.st_mode):
        return _tree_size(Path(entry.path))
    return 0


def _is_test_executable(entry: os.DirEntry) -> bool:
    """A regular, non-symlink file with an executable bit and no library suffix."""
    if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
        return False
    if entry.name.endswith(KEEP_SUFFIXES):
        return False
    return bool(entry.stat(follow_symlinks=False).st_mode & EXEC_BITS)


def _is_hard_linked(entry: os.DirEntry) -> bool:
    """True for cargo's uplift source: ``deps/<bin>-<hash>`` hard-linked to ``<profile>/<bin>``.

    Deleting one side frees nothing while the other exists, so the file is kept
    and not counted (it is one bin, not one of the ~1000 test executables).
    """
    return entry.stat(follow_symlinks=False).st_nlink > 1


def _inside(root: Path, path: Path) -> bool:
    """True when ``path`` (not followed) lies under the resolved ``root``."""
    try:
        parent = path.parent.resolve(strict=True)
    except OSError:
        return False
    return parent == root or root in parent.parents


def _candidates_test_bins(profile_dir: Path, root: Path, kept: List[str]) -> List[Candidate]:
    """Candidates for the default scope; ``kept`` collects hard-linked files left in place."""
    found: List[Candidate] = []
    for sub in ("deps", "examples"):
        d = profile_dir / sub
        if not d.is_dir() or d.is_symlink():
            continue
        with os.scandir(d) as it:
            entries = sorted(it, key=lambda e: e.name)
        names = {e.name for e in entries}
        for entry in entries:
            if not _is_test_executable(entry):
                continue
            if _is_hard_linked(entry):
                kept.append(sub + "/" + entry.name)
                continue
            path = Path(entry.path)
            if not _inside(root, path):
                continue
            found.append(Candidate(path, False, _entry_size(entry), sub + " executable"))
            twin = entry.name + ".d"
            if twin in names and not (d / twin).is_symlink() and (d / twin).is_file():
                found.append(Candidate(d / twin, False, (d / twin).lstat().st_size, sub + " dep-info"))
            dsym = entry.name + ".dSYM"
            if dsym in names and not (d / dsym).is_symlink() and (d / dsym).is_dir():
                found.append(Candidate(d / dsym, True, _tree_size(d / dsym), sub + " dSYM"))
    inc = profile_dir / "incremental"
    if inc.is_dir() and not inc.is_symlink():
        with os.scandir(inc) as it:
            for entry in sorted(it, key=lambda e: e.name):
                if entry.is_symlink():
                    continue
                path = Path(entry.path)
                if not _inside(root, path):
                    continue
                found.append(Candidate(path, entry.is_dir(follow_symlinks=False), _entry_size(entry), "incremental"))
    return found


def _candidates_all(profile_dir: Path, root: Path) -> List[Candidate]:
    found: List[Candidate] = []
    for sub in ARTIFACT_DIRS:
        d = profile_dir / sub
        if d.is_symlink() or not d.is_dir():
            continue
        if not _inside(root, d):
            continue
        found.append(Candidate(d, True, _tree_size(d), sub + " (whole dir)"))
    return found


def _refuse(msg: str) -> int:
    print("prune-runner-target: refusing: " + msg, file=sys.stderr)
    return EXIT_REFUSED


def _delete(cand: Candidate) -> None:
    if cand.is_dir:
        # rmtree does not follow symlinks inside the tree; it removes them as links.
        shutil.rmtree(cand.path)
    else:
        os.remove(cand.path)


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

    raw = Path(args.target_dir)
    if not raw.is_dir():
        return _refuse("%s is not a directory" % raw)
    root = raw.resolve(strict=True)
    profile_dir = root / args.profile
    marker_tag = root / "CACHEDIR.TAG"
    marker_lock = profile_dir / ".cargo-lock"
    if not (marker_tag.is_file() or marker_lock.is_file()):
        return _refuse("%s has neither CACHEDIR.TAG nor %s/.cargo-lock; not a cargo target dir" % (root, args.profile))
    if "/" in args.profile or args.profile in ("", ".", ".."):
        return _refuse("--profile must be one path component, got %r" % args.profile)
    if not profile_dir.is_dir():
        print("nothing to prune: %s does not exist" % profile_dir)
        print("freed_bytes=0")
        return 0

    kept: List[str] = []
    if args.scope == "all":
        cands = _candidates_all(profile_dir, root)
    else:
        cands = _candidates_test_bins(profile_dir, root, kept)

    per_category: Dict[str, Tuple[int, int]] = {}
    freed = 0
    verb = "would delete" if args.dry_run else "deleted"
    for cand in cands:
        count, size = per_category.get(cand.category, (0, 0))
        per_category[cand.category] = (count + 1, size + cand.size)
        if args.dry_run:
            print("  %s %s (%s)" % (verb, cand.path.relative_to(root), _human(cand.size)))
        else:
            _delete(cand)
        freed += cand.size
    mode = "dry-run" if args.dry_run else "pruned"
    print("%s %s scope=%s" % (mode, profile_dir, args.scope))
    for category in sorted(per_category):
        count, size = per_category[category]
        print("  %-24s %6d  %s" % (category, count, _human(size)))
    for name in kept:
        print("  kept hard-linked uplift source %s (frees nothing while <profile>/<bin> exists)" % name)
    print("freed_bytes=%d" % freed)
    print("freed %s (%s)" % (_human(freed), mode))
    return 0


if __name__ == "__main__":
    sys.exit(main())
