#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#4667 - executed probe: is a PgBouncer pool_mode safe for the Postgres adapter?

The Postgres adapter keeps state on the *server session* that a transaction
pooler does not preserve:

  * the migration advisory lock is taken with the session-level
    ``SELECT pg_try_advisory_lock($1)`` (``MIGRATION_ADVISORY_LOCK_KEY``,
    ``SQL_TRY_MIGRATION_ADVISORY_LOCK`` in ``src/store/postgres.rs``);
  * the connect hook sets ``search_path`` with ``set_config(..., false)`` and
    ``statement_timeout`` / ``lock_timeout`` with plain ``SET``.

This probe runs two real client sessions (A and B) through the pooler under
test, with the pooler's ``default_pool_size`` small enough that they can share
one server backend, and checks three hazards:

  1. LOCK     A takes the migration advisory lock; a second client B must NOT
              also be granted it.
  2. PATH     a session ``search_path`` set by A must NOT be visible to B.
  3. TIMEOUT  a session ``statement_timeout`` set by A must NOT be visible to B.

A client that cannot obtain a server connection at all while A holds one
(session mode, pool size 1) is *blocked*: it was not granted the lock and saw no
state, so the hazard is absent.

Exit codes: 0 = no hazard observed (the pool mode is safe for the adapter),
1 = at least one hazard observed (UNSAFE), 2 = the probe could not run.

Requires the ``psql`` client. The password is read from ``PGPASSWORD`` (never
argv). Usage::

    PGPASSWORD=... scripts/probe-pgbouncer-pool-mode.py \\
        --host 127.0.0.1 --port 6432 --user ai_memory --dbname ai_memory
"""
from __future__ import annotations

import argparse
import os
import re
import select
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_FILE = REPO_ROOT / "src" / "store" / "postgres.rs"
LOCK_KEY_RE = re.compile(r"const\s+MIGRATION_ADVISORY_LOCK_KEY\s*:\s*i64\s*=\s*([0-9A-Fa-fx_]+)\s*;")
SENTINEL = "__PROBE_END__"
PATH_MARKER = "probe_4667_marker_schema"
TIMEOUT_MARKER_MS = 7777
EXIT_SAFE, EXIT_UNSAFE, EXIT_FAULT = 0, 1, 2


class ProbeFault(Exception):
    """The probe itself could not run (not a verdict about the pooler)."""


def read_lock_key(source: Path) -> int:
    """The adapter's migration advisory lock key, read from its source."""
    match = LOCK_KEY_RE.search(source.read_text(encoding="utf-8"))
    if match is None:
        raise ProbeFault("MIGRATION_ADVISORY_LOCK_KEY not found in %s" % source)
    return int(match.group(1).replace("_", ""), 0)


class Session:
    """One long-lived psql client connection (a stand-in for one daemon session)."""

    def __init__(self, name: str, dsn: List[str], wait_secs: float) -> None:
        self.name = name
        self.wait_secs = wait_secs
        self.proc = subprocess.Popen(
            ["psql", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1"] + dsn,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,
        )
        self.blocked = False

    def query(self, sql: str) -> Optional[str]:
        """Run one statement; the single result line, or None if blocked/timed out."""
        if self.proc.poll() is not None or self.proc.stdin is None or self.proc.stdout is None:
            raise ProbeFault("%s: psql exited early (rc=%s)" % (self.name, self.proc.returncode))
        self.proc.stdin.write("%s\n\\echo %s\n" % (sql, SENTINEL))
        self.proc.stdin.flush()
        deadline = time.monotonic() + self.wait_secs
        lines: List[str] = []
        fd = self.proc.stdout.fileno()
        buf = ""
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                chunk = os.read(fd, 4096).decode("utf-8", "replace")
                if chunk == "":
                    raise ProbeFault("%s: psql closed its output: %s" % (self.name, "".join(lines)))
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if line == SENTINEL:
                        return "\n".join(lines).strip()
                    lines.append(line)
            elif self.proc.poll() is not None:
                raise ProbeFault("%s: psql exited (rc=%s): %s" % (self.name, self.proc.returncode, "".join(lines)))
        self.blocked = True
        return None

    def close(self) -> None:
        try:
            if self.proc.poll() is None and not self.blocked and self.proc.stdin is not None:
                self.proc.stdin.write("\\q\n")
                self.proc.stdin.flush()
                self.proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


def admin_show(dsn_base: List[str], admin_db: str, what: str) -> List[Tuple[str, str]]:
    """Rows of a PgBouncer admin SHOW command, as (key, value) pairs."""
    done = subprocess.run(
        ["psql", "-X", "-A", "-t", "-q", "-F", "|"] + dsn_base + ["--dbname", admin_db, "-c", "SHOW %s;" % what],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=30,
    )
    if done.returncode != 0:
        raise ProbeFault("pgbouncer admin console SHOW %s failed: %s" % (what, done.stderr.strip()))
    rows = []
    for line in done.stdout.splitlines():
        parts = line.split("|")
        if len(parts) >= 2:
            rows.append((parts[0], parts[1]))
    return rows


def dsn_args(args: argparse.Namespace, dbname: str) -> List[str]:
    return ["--host", args.host, "--port", str(args.port), "--username", args.user, "--dbname", dbname]


def run_probe(args: argparse.Namespace) -> int:
    key = read_lock_key(Path(args.source))
    config = dict(admin_show(["--host", args.host, "--port", str(args.port), "--username", args.user], args.admin_dbname, "CONFIG"))
    pool_mode = config.get("pool_mode", "<unreported>")
    pool_size = config.get("default_pool_size", "<unreported>")
    print("pooler: %s:%s  pool_mode=%s  default_pool_size=%s" % (args.host, args.port, pool_mode, pool_size))
    print("lock key: %d (MIGRATION_ADVISORY_LOCK_KEY, %s)" % (key, SOURCE_FILE.relative_to(REPO_ROOT)))
    dsn = dsn_args(args, args.dbname)
    hazards: List[str] = []
    a = Session("A", dsn, args.wait_secs)
    b: Optional[Session] = None
    try:
        pid_a = a.query("SELECT pg_backend_pid();")
        got_a = a.query("SELECT pg_try_advisory_lock(%d);" % key)
        a.query("SET search_path = %s, public;" % PATH_MARKER)
        a.query("SET statement_timeout = %d;" % TIMEOUT_MARKER_MS)
        print("client A: backend pid=%s  pg_try_advisory_lock=%s  (search_path and statement_timeout set)" % (pid_a, got_a))
        if got_a != "t":
            raise ProbeFault("client A did not get the lock on an idle server (got %r)" % got_a)
        b = Session("B", dsn, args.wait_secs)
        pid_b = b.query("SELECT pg_backend_pid();")
        if b.blocked:
            print("client B: BLOCKED (no server connection while A holds one, waited %.0fs): lock not granted, no state seen" % args.wait_secs)
        else:
            got_b = b.query("SELECT pg_try_advisory_lock(%d);" % key)
            path_b = b.query("SHOW search_path;")
            stmt_b = b.query("SHOW statement_timeout;")
            print("client B: backend pid=%s  pg_try_advisory_lock=%s  search_path=%s  statement_timeout=%s" % (pid_b, got_b, path_b, stmt_b))
            if got_b == "t":
                hazards.append("LOCK: a second client was also granted the migration advisory lock")
            if path_b is not None and PATH_MARKER in path_b:
                hazards.append("PATH: a session search_path set by one client was seen by another")
            if stmt_b == "%dms" % TIMEOUT_MARKER_MS:
                hazards.append("TIMEOUT: a session statement_timeout set by one client was seen by another")
            if pid_a is not None and pid_a == pid_b:
                print("note: A and B shared server backend pid %s" % pid_a)
            b.query("SELECT pg_advisory_unlock_all();")
            b.query("RESET search_path;")
            b.query("RESET statement_timeout;")
        a.query("SELECT pg_advisory_unlock_all();")
        a.query("RESET search_path;")
        a.query("RESET statement_timeout;")
    finally:
        if b is not None:
            b.close()
        a.close()
    if hazards:
        print("RESULT: UNSAFE under pool_mode=%s default_pool_size=%s" % (pool_mode, pool_size))
        for hazard in hazards:
            print("  HAZARD %s" % hazard)
        return EXIT_UNSAFE
    print("RESULT: SAFE under pool_mode=%s default_pool_size=%s (no hazard observed)" % (pool_mode, pool_size))
    return EXIT_SAFE


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6432)
    parser.add_argument("--user", default="ai_memory")
    parser.add_argument("--dbname", default="ai_memory")
    parser.add_argument("--admin-dbname", default="pgbouncer", help="PgBouncer admin console database")
    parser.add_argument("--source", default=str(SOURCE_FILE), help="file holding MIGRATION_ADVISORY_LOCK_KEY")
    parser.add_argument("--wait-secs", type=float, default=6.0, help="how long client B may wait for a server connection")
    args = parser.parse_args(argv)
    if "PGPASSWORD" not in os.environ:
        print("probe fault: set PGPASSWORD in the environment (the password is never taken from argv)", file=sys.stderr)
        return EXIT_FAULT
    try:
        return run_probe(args)
    except ProbeFault as exc:
        print("probe fault: %s" % exc, file=sys.stderr)
        return EXIT_FAULT
    except (OSError, subprocess.SubprocessError) as exc:
        print("probe fault: %s" % exc, file=sys.stderr)
        return EXIT_FAULT


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
