#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Hosted-runner PostgreSQL preflight for CI (issue #9235).

A PostgreSQL server whose binary and library packages do not match (for
example `apt-get install postgresql-16-pgvector` upgrading `postgresql-16`
underneath a running postmaster) cannot load `plpgsql.so`; every
Postgres-backed test then panics with `BackendUnavailable` and the job
dies with an unreadable exit 101.  This script runs BEFORE the coverage
step, so the red names the environment.

What it does:
  1. Prints the runner `ImageVersion` and the installed `postgresql-16*`
     package versions (inside the container when `--container` is given).
  2. With `--restart`, restarts the container so the postmaster that
     serves the tests is the binary the installed packages ship (the
     repair), then waits for the server to accept connections.
  3. Probes: server reachable, `DO $$ BEGIN END $$ LANGUAGE plpgsql;`,
     `CREATE EXTENSION IF NOT EXISTS vector;`, `CREATE EXTENSION IF NOT
     EXISTS age;`.
  4. On the first failure prints exactly one class line
     `::error::[<label>] PG-ENV <reason>` and exits 3.  Never a silent
     skip, never exit 0 on a failed probe.

Connection data comes from libpq environment variables (PGHOST, PGPORT,
PGUSER, PGDATABASE, PGPASSWORD, PGSSLMODE, PGSSLROOTCERT); nothing
connection-related is accepted on argv or printed.
"""

from __future__ import annotations

import argparse
import math
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence

DEFAULT_LABEL = "coverage-pg"
DEFAULT_PSQL = "psql"
DEFAULT_PKG_GLOB = "postgresql-16*"
IMAGE_VERSION_ENV = "ImageVersion"
EXIT_OK = 0
EXIT_PG_ENV = 3
PROBE_TIMEOUT_SECS = 60
DOCKER_TIMEOUT_SECS = 180
DEFAULT_WAIT_SECS = 120
WAIT_INTERVAL_SECS = 2
DETAIL_MAX_CHARS = 300

REASON_PSQL_MISSING = "psql not found on the runner"
REASON_UNREACHABLE = "postgres server unreachable"
REASON_PLPGSQL = "plpgsql.so cannot load (server binary and library packages do not match)"
REASON_VECTOR = "CREATE EXTENSION vector failed"
REASON_AGE = "CREATE EXTENSION age failed"
REASON_RESTART = "postgres container restart failed"

SQL_CONNECT = "SHOW server_version;"
SQL_PLPGSQL = "DO $$ BEGIN END $$ LANGUAGE plpgsql;"
SQL_VECTOR = "CREATE EXTENSION IF NOT EXISTS vector;"
SQL_AGE = "CREATE EXTENSION IF NOT EXISTS age;"

# (name, sql, reason) in probe order; the first failing probe decides.
PROBES: tuple[tuple[str, str, str], ...] = (
    ("plpgsql", SQL_PLPGSQL, REASON_PLPGSQL),
    ("vector", SQL_VECTOR, REASON_VECTOR),
    ("age", SQL_AGE, REASON_AGE),
)

_URL_WITH_CREDS = re.compile(r"[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)

Runner = Callable[[Sequence[str]], subprocess.CompletedProcess]


class PsqlMissingError(Exception):
    """The psql executable is not present."""


def default_runner(argv: Sequence[str]) -> subprocess.CompletedProcess:
    """Run one program with an argument list; environment is inherited."""
    return subprocess.run(  # noqa: S603 - argument list, no shell
        list(argv),
        capture_output=True,
        text=True,
        check=False,
        timeout=DOCKER_TIMEOUT_SECS if argv and argv[0] == "docker" else PROBE_TIMEOUT_SECS,
    )


def class_line(label: str, reason: str) -> str:
    """The single, machine-readable failure line."""
    return f"::error::[{label}] PG-ENV {reason}"


def _detail(proc: subprocess.CompletedProcess) -> str:
    text = (proc.stderr or "").strip().splitlines()
    first = text[0] if text else ""
    return _URL_WITH_CREDS.sub("<redacted>", first)[:DETAIL_MAX_CHARS]


def run_psql(runner: Runner, psql: str, sql: str) -> tuple[bool, str, str]:
    """Run one SQL statement. Returns (ok, stdout, detail); raises PsqlMissingError."""
    argv = [psql, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-tA", "-c", sql]
    try:
        proc = runner(argv)
    except FileNotFoundError as exc:
        raise PsqlMissingError(psql) from exc
    except subprocess.TimeoutExpired:
        return False, "", "psql timed out"
    if proc.returncode == 0:
        return True, (proc.stdout or "").strip(), ""
    return False, "", _detail(proc)


def print_environment(runner: Runner, container: str | None, pkg_glob: str) -> None:
    """Print the runner image version and installed postgresql-16* versions."""
    print(f"runner {IMAGE_VERSION_ENV}={os.environ.get(IMAGE_VERSION_ENV, 'unset')}")
    dpkg = ["dpkg-query", "-W", "-f", "${Package} ${Version}\\n", pkg_glob]
    argv = ["docker", "exec", container, *dpkg] if container else dpkg
    try:
        proc = runner(argv)
        ok = proc.returncode == 0
        out = (proc.stdout or "").strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        ok, out = False, ""
    where = f"container {container}" if container else "runner"
    if not ok or not out:
        print(f"pkg ({where}): unavailable")
        return
    for line in out.splitlines():
        print(f"pkg ({where}): {line}")


def restart_container(runner: Runner, container: str) -> bool:
    """Restart the container so the running server matches the installed packages."""
    try:
        proc = runner(["docker", "restart", container])
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def wait_for_server(
    runner: Runner,
    psql: str,
    wait_secs: int,
    sleep: Callable[[float], None],
) -> tuple[bool, str, str]:
    """Poll `SHOW server_version` until it answers or the attempts run out."""
    attempts = max(1, math.ceil(wait_secs / WAIT_INTERVAL_SECS))
    detail = ""
    for attempt in range(attempts):
        ok, out, detail = run_psql(runner, psql, SQL_CONNECT)
        if ok:
            return True, out, ""
        if attempt + 1 < attempts:
            sleep(WAIT_INTERVAL_SECS)
    return False, "", detail


def preflight(
    *,
    label: str,
    psql: str,
    container: str | None,
    restart: bool,
    wait_secs: int,
    runner: Runner,
    sleep: Callable[[float], None],
) -> int:
    """Run the whole preflight; return the process exit code."""
    print_environment(runner, container, DEFAULT_PKG_GLOB)

    def fail(reason: str, detail: str = "") -> int:
        if detail:
            print(f"detail: {detail}")
        print(class_line(label, reason))
        return EXIT_PG_ENV

    try:
        if restart:
            if container is None:
                return fail(REASON_RESTART, "--restart needs --container")
            if not restart_container(runner, container):
                return fail(REASON_RESTART)
            reachable, version, detail = wait_for_server(runner, psql, wait_secs, sleep)
        else:
            reachable, version, detail = run_psql(runner, psql, SQL_CONNECT)
        if not reachable:
            return fail(REASON_UNREACHABLE, detail)
        print(f"server_version={version}")
        for name, sql, reason in PROBES:
            ok, _out, detail = run_psql(runner, psql, sql)
            if not ok:
                return fail(reason, detail)
            print(f"probe {name}: ok")
    except PsqlMissingError:
        return fail(REASON_PSQL_MISSING)
    return EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    runner: Runner = default_runner,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument("--label", default=DEFAULT_LABEL, help="class-line label")
    parser.add_argument("--psql", default=DEFAULT_PSQL, help="psql executable")
    parser.add_argument("--container", help="docker container running the server")
    parser.add_argument(
        "--restart",
        action="store_true",
        help="restart --container first so the server matches the installed packages",
    )
    parser.add_argument("--wait-seconds", type=int, default=DEFAULT_WAIT_SECS)
    args = parser.parse_args(argv)
    return preflight(
        label=args.label,
        psql=args.psql,
        container=args.container,
        restart=args.restart,
        wait_secs=args.wait_seconds,
        runner=runner,
        sleep=sleep,
    )


if __name__ == "__main__":
    sys.exit(main())
