#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Make every tracked source file newer than any shared-target artifact (#7188).

cargo decides freshness of workspace (path) crates by source mtime versus the
artifact mtime, with paths relative to the package root. With ONE shared
CARGO_TARGET_DIR per host and a separate checkout per runner, a checkout whose
files are older than the last build's artifacts would be treated as fresh and
would link ANOTHER checkout's compiled code. This helper sets the mtime of
every file listed by ``git ls-files`` to ``now + --ahead-secs`` so workspace
crates always rebuild for the current checkout, while registry and git
dependencies (outside the checkout, where the disk footprint is) keep their
artifacts.

The bump is dated AHEAD of now on purpose: a runner may wait on cargo's
build-directory lock while another checkout finishes building; an mtime of
"now" taken before the wait would then be older than that build's artifacts.
The default (6 h) outlives any CI job; the next job on the runner re-bumps.

Symlinks are never followed (the link itself is left alone). Exit codes: 0 ok,
2 bad arguments, 3 git failure. Python 3.9+, standard library only.
"""
import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_GIT = 3
DEFAULT_AHEAD_SECS = 6 * 3600


def tracked_files(root):
    """Return the NUL-separated ``git ls-files`` entries of ``root``."""
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip())
    return [os.fsdecode(raw) for raw in proc.stdout.split(b"\0") if raw]


def bump(root, ahead_secs, now=None):
    """Set mtime to now+ahead on every tracked non-symlink file; return the count."""
    stamp = (time.time() if now is None else now) + ahead_secs
    count = 0
    for rel in tracked_files(root):
        path = Path(root) / rel
        if path.is_symlink() or not path.is_file():
            continue
        os.utime(path, (stamp, stamp))
        count += 1
    return count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".", help="git checkout of this job")
    parser.add_argument("--ahead-secs", type=int, default=DEFAULT_AHEAD_SECS)
    args = parser.parse_args(argv)
    root = Path(args.root)
    if args.ahead_secs < 0 or not root.is_dir():
        print("touch_workspace_sources: bad arguments", file=sys.stderr)
        return EXIT_USAGE
    try:
        count = bump(root, args.ahead_secs)
    except (RuntimeError, OSError) as err:
        print("touch_workspace_sources: %s" % err, file=sys.stderr)
        return EXIT_GIT
    print("touch_workspace_sources: bumped %d tracked files" % count)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
