#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Prune cargo test/bench executables from a self-hosted runner target dir (#6118).

WHY.  The self-hosted runners keep a PERSISTENT workspace ``target/``: it is
the warm build cache for the pg tier (#3128), so it must never be wiped
wholesale.  But one full debug ``cargo test`` build writes ~1000 test
executables of ~170 MB each into ``target/debug/deps`` (~164 GB per runner),
and nothing removed them, so the shared root filesystem ran out of room
(#6118, #3453).  A test executable is a pure output: when it is missing,
cargo rebuilds that one test crate on the next run and reuses every
dependency ``.rlib``, so deleting them is cheap and keeps the cache warm.

WHAT IS DELETED.  Only regular files directly inside
``<target-dir>/debug/deps`` whose name has no extension and that carry an
executable mode bit (that is what cargo names a test or bench executable).
Never ``*.rlib``, ``*.rmeta``, ``*.d``, ``*.so``, ``*.dylib`` or any other
file with an extension; never ``build/``, ``incremental/``, ``.fingerprint/``
or any directory; never a symlink; never anything that resolves outside
``--target-dir``.

EXIT CODES.  0 when the prune ran (also when nothing matched or the target
dir does not exist yet, e.g. a docs-only run); 1 when one or more matching
files could not be removed (each is reported); 2 on a usage error or when
``debug/deps`` resolves outside ``--target-dir`` (refused, nothing deleted).

Run:  python3 -I scripts/ci/prune_test_binaries.py --target-dir target [--dry-run] [--max-age-hours N]
"""
from __future__ import annotations

import argparse
import math
import os
import stat
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

DEPS_REL = Path("debug") / "deps"
EXIT_OK = 0
EXIT_UNLINK_FAILED = 1
EXIT_REFUSED = 2
SECS_PER_HOUR = 3600.0


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def find_candidates(
    target_dir: Path, max_age_hours: float, now: float
) -> Tuple[Optional[str], List[Tuple[Path, int]]]:
    """Return ``(refusal, [(path, size)])`` for the executables to prune.

    ``refusal`` is a message when the deps directory must not be touched.
    """
    root = target_dir.resolve()
    deps = target_dir / DEPS_REL
    if not deps.is_dir():
        return None, []
    deps_real = deps.resolve()
    if not _is_within(deps_real, root):
        return f"{deps} resolves to {deps_real}, outside --target-dir {root}; refusing", []
    min_age_secs = max_age_hours * SECS_PER_HOUR
    found: List[Tuple[Path, int]] = []
    with os.scandir(deps_real) as it:
        for entry in it:
            if "." in entry.name:
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue  # symlinks, directories, sockets: never
            if not st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                continue
            if now - st.st_mtime < min_age_secs:
                continue
            path = deps_real / entry.name
            if not _is_within(path, root):
                continue
            found.append((path, st.st_size))
    found.sort()
    return None, found


def _non_negative_hours(text: str) -> float:
    try:
        value = float(text)
    except ValueError as err:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from err
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError(f"must be a finite number >= 0, got {text!r}")
    return value


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Delete cargo test/bench executables from <target-dir>/debug/deps (#6118)."
    )
    parser.add_argument("--target-dir", required=True, type=Path, help="cargo target directory")
    parser.add_argument(
        "--dry-run", action="store_true", help="report what would be deleted; delete nothing"
    )
    parser.add_argument(
        "--max-age-hours",
        type=_non_negative_hours,
        default=0.0,
        help="only delete executables last modified at least this many hours ago (default 0 = all)",
    )
    args = parser.parse_args(argv)

    target_dir: Path = args.target_dir
    if not target_dir.is_dir():
        print(f"prune_test_binaries: {target_dir} does not exist; freed 0 bytes (0 files)")
        return EXIT_OK

    refusal, candidates = find_candidates(target_dir, args.max_age_hours, time.time())
    if refusal is not None:
        print(f"::error::prune_test_binaries: {refusal}", file=sys.stderr)
        return EXIT_REFUSED

    total = 0
    count = 0
    failed = 0
    for path, size in candidates:
        if args.dry_run:
            print(f"would delete {path} ({size} bytes)")
        else:
            try:
                path.unlink()
            except OSError as err:
                failed += 1
                print(f"::warning::prune_test_binaries: cannot delete {path}: {err}", file=sys.stderr)
                continue
        total += size
        count += 1

    verb = "would free" if args.dry_run else "freed"
    print(f"prune_test_binaries: {verb} {total} bytes ({count} files) from {target_dir / DEPS_REL}")
    return EXIT_UNLINK_FAILED if failed else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
