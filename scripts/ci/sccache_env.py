#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Export the sccache build-cache environment for the self-hosted Linux leg (#7199).

``--github-env FILE`` resolves ``sccache`` on PATH and appends RUSTC_WRAPPER
(absolute path), SCCACHE_DIR, SCCACHE_CACHE_SIZE and SCCACHE_ERROR_LOG to the
$GITHUB_ENV file. It FAILS CLOSED: a missing sccache exits EXIT_MISSING with a
one-line reason and writes nothing, so the job goes red instead of silently
building cold. The cache lives under ``~/.cache/ai-memory-ci/sccache`` (the same
root family as the per-runner cargo targets, never a tmp path) and the whole
user shares one sccache server, so its size cap holds across all runners.
sccache cannot cache incremental artifacts: the workflow already sets
CARGO_INCREMENTAL=0.

``--stats`` prints a summary (at most STATS_MAX_LINES lines) of
``sccache --show-stats`` so hit rates show in the job log. It never fails the job.

Exit codes: 0 ok, 2 bad arguments or home, 3 sccache not found on PATH.
Python 3.9+, standard library only.
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

SCCACHE_BINARY = "sccache"
CACHE_ROOT_RELATIVE = Path(".cache") / "ai-memory-ci"
SCCACHE_DIR_NAME = "sccache"
SCCACHE_ERROR_LOG_NAME = "sccache-error.log"
SCCACHE_CACHE_SIZE = "50G"
STATS_MAX_LINES = 12
STATS_TIMEOUT_SECS = 60
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_MISSING = 3


def resolve_sccache():
    """Return the absolute path of sccache on PATH, or None."""
    found = shutil.which(SCCACHE_BINARY)
    return str(Path(found).resolve()) if found else None


def summarise_stats(text):
    """Return at most STATS_MAX_LINES non-blank lines of the stats output."""
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return lines[:STATS_MAX_LINES]


def print_stats():
    binary = resolve_sccache()
    if binary is None:
        print("sccache_env: sccache not on PATH, no stats")
        return EXIT_OK
    try:
        result = subprocess.run(
            [binary, "--show-stats"], capture_output=True, text=True,
            timeout=STATS_TIMEOUT_SECS, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        print("sccache_env: could not read stats: %s" % err)
        return EXIT_OK
    for line in summarise_stats(result.stdout):
        print(line)
    return EXIT_OK


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--home", default=str(Path.home()), help="runner user home")
    parser.add_argument("--github-env", help="append the sccache variables to this $GITHUB_ENV file")
    parser.add_argument("--stats", action="store_true", help="print a stats summary and exit 0")
    args = parser.parse_args(argv)
    if args.stats:
        return print_stats()
    if not args.github_env:
        parser.error("--github-env is required unless --stats is given")
    home = Path(args.home)
    if not home.is_absolute() or str(home) in ("/", ""):
        print("sccache_env: refusing home %r" % args.home, file=sys.stderr)
        return EXIT_USAGE
    binary = resolve_sccache()
    if binary is None:
        print("sccache_env: sccache not found on PATH; refusing a cold build", file=sys.stderr)
        return EXIT_MISSING
    cache_root = home / CACHE_ROOT_RELATIVE
    cache_dir = cache_root / SCCACHE_DIR_NAME
    cache_dir.mkdir(parents=True, exist_ok=True)
    values = (
        ("RUSTC_WRAPPER", binary),
        ("SCCACHE_DIR", str(cache_dir)),
        ("SCCACHE_CACHE_SIZE", SCCACHE_CACHE_SIZE),
        ("SCCACHE_ERROR_LOG", str(cache_root / SCCACHE_ERROR_LOG_NAME)),
    )
    with open(args.github_env, "a", encoding="utf-8") as handle:
        for name, value in values:
            handle.write("%s=%s\n" % (name, value))
    print("sccache_env: %s, dir %s, cap %s" % (binary, cache_dir, SCCACHE_CACHE_SIZE))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
