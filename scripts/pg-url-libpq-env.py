#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#4889 - turn a postgres URL on stdin into libpq environment exports on stdout.

``psql "$url"`` puts the password on the psql argv (visible in ps and /proc). libpq has
no environment variable that carries a whole URL, so the CI steps read the URL from stdin
(a shell builtin printf, never an argv word), run this script, and ``eval`` its output in a
subshell that then execs ``psql`` with flags only:

    pg_url_run() { local u="$1"; shift
        ( eval "$(printf '%s' "$u" | python3 scripts/pg-url-libpq-env.py)"; exec psql "$@" ); }

Output is ``export NAME=<shlex-quoted value>`` lines, so the eval cannot be turned into
command execution by a value. The script fails closed (exit 2, nothing on stdout) on a
non-postgres scheme or on a query parameter it does not map, rather than dropping a
setting such as sslmode and connecting less securely.

Usage:
  printf '%s' "$URL" | scripts/pg-url-libpq-env.py
  scripts/pg-url-libpq-env.py --self-test
"""
import shlex
import subprocess
import sys
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, unquote, urlsplit

# libpq connection parameter -> environment variable.
QUERY_ENV = {
    "sslmode": "PGSSLMODE",
    "sslrootcert": "PGSSLROOTCERT",
    "sslcert": "PGSSLCERT",
    "sslkey": "PGSSLKEY",
    "application_name": "PGAPPNAME",
    "connect_timeout": "PGCONNECT_TIMEOUT",
    "options": "PGOPTIONS",
}


class UrlError(ValueError):
    """The URL cannot be mapped to libpq environment variables without losing a setting."""


def url_to_env(url: str) -> Dict[str, str]:
    """Map a postgres URL to libpq environment variables (fail closed)."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("postgres", "postgresql"):
        raise UrlError("not a postgres:// or postgresql:// URL")
    env: Dict[str, str] = {}
    if parts.hostname:
        env["PGHOST"] = parts.hostname
    if parts.port is not None:
        env["PGPORT"] = str(parts.port)
    if parts.username is not None:
        env["PGUSER"] = unquote(parts.username)
    if parts.password is not None:
        env["PGPASSWORD"] = unquote(parts.password)
    database = unquote(parts.path[1:]) if parts.path.startswith("/") else ""
    if database:
        env["PGDATABASE"] = database
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        name = QUERY_ENV.get(key)
        if name is None:
            raise UrlError("query parameter %r has no libpq environment variable" % key)
        env[name] = value
    return env


def render(env: Dict[str, str]) -> str:
    """Render the exports with shell quoting, one per line, in a stable order."""
    return "".join("export %s=%s\n" % (k, shlex.quote(env[k])) for k in sorted(env))


def self_test() -> int:
    secret = "p@ss:w/rd"
    url = "postgres://ai_memory:p%40ss%3Aw%2Frd@db.example:5439/ai_x?sslmode=verify-full&sslrootcert=/ca.crt"
    env = url_to_env(url)
    expected = {
        "PGHOST": "db.example", "PGPORT": "5439", "PGUSER": "ai_memory", "PGPASSWORD": secret,
        "PGDATABASE": "ai_x", "PGSSLMODE": "verify-full", "PGSSLROOTCERT": "/ca.crt",
    }
    problems: List[str] = []
    if env != expected:
        problems.append("mapping differs: %r" % (env,))
    out = subprocess.run(
        ["bash", "-c", render(env) + 'printf "%s|%s|%s" "$PGPASSWORD" "$PGHOST" "$PGSSLMODE"'],
        capture_output=True, text=True, check=False,
    )
    if out.stdout != secret + "|db.example|verify-full":
        problems.append("a quoted export did not round-trip through bash: %r" % out.stdout)
    hostile = url_to_env("postgres://u:%27%3B%20touch%20x%3B%27@h/d")
    got = subprocess.run(["bash", "-c", render(hostile) + 'printf "%s" "$PGPASSWORD"'],
                         capture_output=True, text=True, check=False).stdout
    if got != "'; touch x;'":
        problems.append("a hostile password was not carried verbatim: %r" % got)
    for bad in ("mysql://u:p@h/d", "postgres://u:p@h/d?target_session_attrs=any", "http://x"):
        try:
            url_to_env(bad)
        except UrlError:
            continue
        problems.append("did not fail closed on %r" % bad)
    if problems:
        for line in problems:
            print("FAIL: pg-url-libpq-env self-test: " + line, file=sys.stderr)
        return 1
    print("PASS: pg-url-libpq-env self-test: mapping, quoting round-trip, hostile value, 3 fail-closed cases")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--self-test"]:
        return self_test()
    if args:
        print("usage: printf '%s' \"$URL\" | pg-url-libpq-env.py   |   --self-test", file=sys.stderr)
        return 2
    try:
        env = url_to_env(sys.stdin.read())
    except UrlError as exc:
        print("pg-url-libpq-env: " + str(exc), file=sys.stderr)
        return 2
    sys.stdout.write(render(env))
    return 0


if __name__ == "__main__":
    sys.exit(main())
