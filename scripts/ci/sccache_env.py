#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Export the sccache build-cache environment for the self-hosted Linux leg (#7199).

``--github-env FILE`` resolves ``sccache`` on PATH, starts a DEDICATED sccache
server for CI and appends RUSTC_WRAPPER (absolute path), SCCACHE_DIR,
SCCACHE_CACHE_SIZE, SCCACHE_ERROR_LOG, SCCACHE_SERVER_PORT, SCCACHE_IDLE_TIMEOUT
(0: the server never idles out) and SCCACHE_IGNORE_SERVER_IO_ERROR (1) to the
$GITHUB_ENV file. SCCACHE_DIR, SCCACHE_CACHE_SIZE and SCCACHE_ERROR_LOG are read
only when a server starts, and the dev lanes keep their own server on the
default port SCCACHE_DEFAULT_PORT with its own store; a CI client that attached
to it would write the root disk and ignore the cap. So CI uses its own port
(SCCACHE_SERVER_PORT) and the helper FAILS CLOSED: after ``--start-server`` it
reads ``--show-stats`` and exits EXIT_WRONG_CACHE, writing nothing, unless the
reported cache location is the intended SCCACHE_DIR. A missing sccache exits
EXIT_MISSING with a one-line reason and writes nothing. RUNNER_TRACKING_ID is
dropped from the server's environment so the runner's orphan cleanup does not
kill a server that sibling jobs share. The cache lives under
``~/.cache/ai-memory-ci/sccache`` (the root family of the per-runner cargo
targets, never a tmp path). sccache cannot cache incremental artifacts: the
workflow already sets CARGO_INCREMENTAL=0.

``--stats`` prints a summary (at most STATS_MAX_LINES lines) of
``sccache --show-stats`` on the CI port; a job whose environment lacks that port
(sccache step skipped or refused) prints a skip message. It never fails.

``--stop --home H --runner-name N`` (name required and validated) stops the CI server at job end, on the same
port, unless a sibling runner's in-use marker is fresh (its job still compiles
through the shared server). It never fails the job.

Exit codes: 0 ok, 2 bad arguments or home, 3 sccache not found on PATH,
4 the server's cache location is not the intended SCCACHE_DIR.
Python 3.9+, standard library only.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import shared_cargo_target as shared

SCCACHE_BINARY = "sccache"
CACHE_ROOT_RELATIVE = shared.TARGET_ROOT_RELATIVE.parent
SCCACHE_DIR_NAME = "sccache"
SCCACHE_ERROR_LOG_NAME = "sccache-error.log"
SCCACHE_CACHE_SIZE = "50G"
# sccache's built-in port is held by the dev lanes' server;
# CI must never attach to it, so it gets its own, unused port.
SCCACHE_DEFAULT_PORT = 4226
SCCACHE_SERVER_PORT = 4227
# The server never idles out: an idle-exited server would be auto-restarted by
# the next client under that job's RUNNER_TRACKING_ID and the runner's orphan
# cleanup would then kill the shared server under a sibling job. A client that
# loses the server falls back to a local rustc instead of failing.
SCCACHE_IDLE_TIMEOUT_SECS = "0"
SCCACHE_IGNORE_SERVER_IO_ERROR = "1"
RUNNER_TRACKING_ENV = "RUNNER_TRACKING_ID"
CACHE_LOCATION_PATTERN = re.compile(r'^Cache location\s+.*?"([^"]+)"', re.MULTILINE)
STATS_MAX_LINES = 12
STATS_TIMEOUT_SECS = 60
SERVER_TIMEOUT_SECS = 60
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_MISSING = 3
EXIT_WRONG_CACHE = 4


def resolve_sccache():
    """Return the absolute path of sccache on PATH, or None."""
    found = shutil.which(SCCACHE_BINARY)
    return str(Path(found).resolve()) if found else None


def summarise_stats(text):
    """Return at most STATS_MAX_LINES non-blank lines of the stats output."""
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return lines[:STATS_MAX_LINES]


def ci_server_env(base_env, cache_dir, error_log):
    """Environment for the CI sccache server and its clients (no runner tracking id)."""
    env = {k: v for k, v in base_env.items() if k != RUNNER_TRACKING_ENV}
    env["SCCACHE_DIR"] = str(cache_dir)
    env["SCCACHE_CACHE_SIZE"] = SCCACHE_CACHE_SIZE
    env["SCCACHE_ERROR_LOG"] = str(error_log)
    env["SCCACHE_SERVER_PORT"] = str(SCCACHE_SERVER_PORT)
    env["SCCACHE_IDLE_TIMEOUT"] = SCCACHE_IDLE_TIMEOUT_SECS
    env["SCCACHE_IGNORE_SERVER_IO_ERROR"] = SCCACHE_IGNORE_SERVER_IO_ERROR
    return env


def run_sccache(binary, args, env):
    """Run ``binary args`` and return the CompletedProcess (the subprocess seam)."""
    return subprocess.run(
        [binary] + list(args), env=env, capture_output=True, text=True,
        timeout=SERVER_TIMEOUT_SECS, check=False,
    )


def reported_location(stats_text):
    """Return the cache location named in ``--show-stats`` output, or None."""
    match = CACHE_LOCATION_PATTERN.search(stats_text)
    return match.group(1) if match else None


def same_dir(left, right):
    return left == right or Path(left).resolve() == Path(right).resolve()


def start_and_verify(binary, env, cache_dir):
    """Start the dedicated server and return None when it uses ``cache_dir``, else a reason."""
    try:
        # A server may already be running on this port from an earlier job: the
        # verification below decides, not the exit status of --start-server.
        run_sccache(binary, ["--start-server"], env)
        stats = run_sccache(binary, ["--show-stats"], env)
    except (OSError, subprocess.TimeoutExpired) as err:
        return "could not start or query the CI sccache server: %s" % err
    location = reported_location(stats.stdout)
    if location is None:
        return "sccache --show-stats names no cache location (port %d)" % SCCACHE_SERVER_PORT
    if not same_dir(location, cache_dir):
        return "sccache server on port %d stores to %s, not the intended %s" % (
            SCCACHE_SERVER_PORT, location, cache_dir)
    return None


def print_stats():
    binary = resolve_sccache()
    if binary is None:
        print("sccache_env: sccache not on PATH, no stats")
        return EXIT_OK
    if os.environ.get("SCCACHE_SERVER_PORT") != str(SCCACHE_SERVER_PORT):
        # The sccache step was skipped or refused: never print the dev server's counters.
        print("sccache_env: CI sccache not configured for this job, no stats")
        return EXIT_OK
    env = dict(os.environ)
    env["SCCACHE_SERVER_PORT"] = str(SCCACHE_SERVER_PORT)
    try:
        result = subprocess.run(
            [binary, "--show-stats"], env=env, capture_output=True, text=True,
            timeout=STATS_TIMEOUT_SECS, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        print("sccache_env: could not read stats: %s" % err)
        return EXIT_OK
    for line in summarise_stats(result.stdout):
        print(line)
    return EXIT_OK


def sibling_job_running(home, runner_name, now):
    """True when another runner's target has a fresh in-use marker."""
    root = shared.target_root_dir(home)
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return False
    for entry in entries:
        if entry.name == runner_name or entry.is_symlink() or not entry.is_dir():
            continue
        if shared.valid_runner_name(entry.name) and shared.marker_is_fresh(entry, now):
            return True
    return False


def stop_server(home, runner_name):
    """Stop the CI server at job end unless a sibling job still uses it."""
    binary = resolve_sccache()
    if binary is None:
        return EXIT_OK
    if sibling_job_running(home, runner_name, time.time()):
        print("sccache_env: a sibling job is running, leaving the CI server up")
        return EXIT_OK
    env = dict(os.environ)
    env["SCCACHE_SERVER_PORT"] = str(SCCACHE_SERVER_PORT)
    try:
        run_sccache(binary, ["--stop-server"], env)
    except (OSError, subprocess.TimeoutExpired) as err:
        print("sccache_env: could not stop the CI server: %s" % err)
        return EXIT_OK
    print("sccache_env: stopped the CI server on port %d" % SCCACHE_SERVER_PORT)
    return EXIT_OK


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--home", default=str(Path.home()), help="runner user home")
    parser.add_argument("--github-env", help="append the sccache variables to this $GITHUB_ENV file")
    parser.add_argument("--stats", action="store_true", help="print a stats summary and exit 0")
    parser.add_argument("--stop", action="store_true", help="stop the CI server (needs --runner-name)")
    parser.add_argument("--runner-name", help="this runner's name (its marker is ignored by --stop)")
    args = parser.parse_args(argv)
    if args.stop and not shared.valid_runner_name(args.runner_name):
        parser.error("--stop needs --runner-name with a valid runner name (got %r)" % (args.runner_name,))
    if args.stats:
        return print_stats()
    home = Path(args.home)
    if not home.is_absolute() or str(home) in ("/", ""):
        print("sccache_env: refusing home %r" % args.home, file=sys.stderr)
        return EXIT_USAGE
    if args.stop:
        return stop_server(home, args.runner_name)
    if not args.github_env:
        parser.error("--github-env is required unless --stats or --stop is given")
    binary = resolve_sccache()
    if binary is None:
        print("sccache_env: sccache not found on PATH; refusing a cold build", file=sys.stderr)
        return EXIT_MISSING
    cache_root = home / CACHE_ROOT_RELATIVE
    cache_dir = cache_root / SCCACHE_DIR_NAME
    cache_dir.mkdir(parents=True, exist_ok=True)
    env = ci_server_env(os.environ, cache_dir, cache_root / SCCACHE_ERROR_LOG_NAME)
    problem = start_and_verify(binary, env, cache_dir)
    if problem:
        print("sccache_env: %s; refusing" % problem, file=sys.stderr)
        return EXIT_WRONG_CACHE
    values = (("RUSTC_WRAPPER", binary),) + tuple(
        (name, env[name]) for name in (
            "SCCACHE_DIR", "SCCACHE_CACHE_SIZE", "SCCACHE_ERROR_LOG", "SCCACHE_SERVER_PORT",
            "SCCACHE_IDLE_TIMEOUT", "SCCACHE_IGNORE_SERVER_IO_ERROR"))
    with open(args.github_env, "a", encoding="utf-8") as handle:
        for name, value in values:
            handle.write("%s=%s\n" % (name, value))
    print("sccache_env: %s, dir %s, cap %s, port %d" % (
        binary, cache_dir, SCCACHE_CACHE_SIZE, SCCACHE_SERVER_PORT))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
