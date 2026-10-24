#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The one non-echoing loader for the enterprise-fed tier credential (#8187).

The tier URL lives in a file in the runner user's home.  This helper is the only code that turns it into a
connection:

* ``run --url-file F [--database DB] [--export-url] -- CMD...`` runs CMD with the connection in libpq
  environment variables (``PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE PGSSLMODE PGSSLROOTCERT``), so no
  credential reaches argv or the process table (#6172).  ``--export-url`` also sets
  ``AI_MEMORY_TEST_POSTGRES_URL`` for CMD (the Postgres isolation wrapper reads it from the environment).
* ``github-env --url-file F --database DB [--age-url]`` prints ``::add-mask::`` lines for the URL and the
  password (decoded, and as encoded when that differs) and only then appends
  ``AI_MEMORY_TEST_POSTGRES_URL=<url for DB>`` (and ``AI_MEMORY_TEST_AGE_URL`` with ``--age-url``) to the file named
  by ``$GITHUB_ENV``; a URL that decodes to a line break or NUL is refused before anything is printed.  The mask
  lines are the only output that carries the credential, and the workflow log masks them.

Both refuse a URL file that is not a regular file or that is group- or world-accessible (#6180).  Every
message is a fixed sentence: it never carries the URL, a URL component, an exception text or the file text,
only the path of the file, its mode, and exception class names (#7971).  Stdlib only; run as ``python3 -I``.
"""

import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from urllib.parse import unquote

EXIT_OK = 0
EXIT_BAD_INPUT = 2
EXIT_MODE = 3
EXIT_NO_COMMAND = 127
# group and other permission bits: a credential file may be accessible to its owner only
FORBIDDEN_MODE_BITS = 0o077
URL_SCHEMES = ("postgres://", "postgresql://")
URL_VAR = "AI_MEMORY_TEST_POSTGRES_URL"
AGE_URL_VAR = "AI_MEMORY_TEST_AGE_URL"
GITHUB_ENV_VAR = "GITHUB_ENV"
DATABASE_RE = re.compile(r"^[a-z0-9_]{1,63}$")
# URL query keys and the libpq variable each maps to; any other key is refused, never dropped
QUERY_TO_ENV = {"sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT",
                "sslkey": "PGSSLKEY", "connect_timeout": "PGCONNECT_TIMEOUT"}


READ_ERRORS = ("UnicodeDecodeError", "FileNotFoundError", "IsADirectoryError", "PermissionError")


def read_error_name(exc):
    """The class name of a read error, from a fixed list (``OSError`` for any other); never the error text."""
    return next((name for name in READ_ERRORS if type(exc).__name__ == name), "OSError")


class CredentialError(Exception):
    """A refusal; ``args[0]`` is a fixed sentence and ``code`` the exit status."""

    def __init__(self, message, code=EXIT_BAD_INPUT):
        super().__init__(message)
        self.code = code


def escape_workflow_command_data(value):
    """Escape the data of a workflow command exactly as ``escapeData`` in ``@actions/core`` does.

    The runner decodes ``%25``, ``%0D`` and ``%0A`` in command data, so ``%`` is escaped first, then CR, then LF;
    every ``::add-mask::``, ``::error::`` and ``::notice::`` line this helper prints goes through here (#8187).
    """
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def report(message):
    """Print one fixed ``::error::`` line (the only output of a refusal)."""
    print("::error::" + escape_workflow_command_data("tier_credential: " + message), file=sys.stderr)


def mode_check(path):
    """Return None when ``path`` is a regular file that only its owner can access, else (exit code, sentence).

    Only the permission refusal names the path and the octal mode; no sentence carries the file text (#6180).
    """
    try:
        info = os.stat(path)
    except OSError as exc:
        return EXIT_BAD_INPUT, "cannot read the tier URL file (%s)" % read_error_name(exc)
    if not stat.S_ISREG(info.st_mode):
        return EXIT_BAD_INPUT, "cannot read the tier URL file (IsADirectoryError)"
    mode = stat.S_IMODE(info.st_mode)
    if mode & FORBIDDEN_MODE_BITS:
        return EXIT_MODE, ("the tier URL file %s is group- or world-accessible (mode %s); run chmod 600 on it"
                           % (path, format(mode, "04o")))
    return None


def mode_problem(path):
    """The sentence of ``mode_check``, or None (the form scripts/ci/check-tier-password.py uses)."""
    refusal = mode_check(path)
    return None if refusal is None else refusal[1]


def load_url(path):
    """Read the URL file after the mode check; raise CredentialError with a fixed sentence otherwise."""
    refusal = mode_check(path)
    if refusal is not None:
        raise CredentialError(refusal[1], refusal[0])
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise CredentialError("cannot read the tier URL file (%s)" % read_error_name(exc))
    url = text[:-1] if text.endswith("\n") else text
    if not url.startswith(URL_SCHEMES) or any(ch in url for ch in "\t\r\n\x00"):
        raise CredentialError("the tier URL file does not hold one postgres:// URL")
    return url


def split_url(url):
    """Return (userinfo, hostlist, path, query) of a postgres URL; raise CredentialError when malformed."""
    rest = url.partition("://")[2].partition("#")[0]
    query = rest.partition("?")[2]
    rest = rest.partition("?")[0]
    authority, slash, path = rest.partition("/")
    userinfo, at, hostlist = authority.rpartition("@")
    if authority.count("[") != authority.count("]"):
        raise CredentialError("the tier URL has unbalanced brackets in its authority")
    return userinfo if at else "", hostlist, (slash + path), query


def host_entry(entry):
    """Return (host, port) of one authority entry: ``h``, ``h:port``, ``[v6]`` or ``[v6]:port``."""
    if entry.startswith("["):
        host, _, tail = entry[1:].partition("]")
        return host, tail[1:] if tail.startswith(":") else ""
    host, sep, port = entry.rpartition(":")
    return (host, port) if sep else (entry, "")


def libpq_env(url):
    """Map a postgres URL to libpq variables; every refusal is a fixed sentence."""
    userinfo, hostlist, path, query = split_url(url)
    user, _, password = userinfo.partition(":")
    env = {}
    if user:
        env["PGUSER"] = unquote(user)
    if password:
        env["PGPASSWORD"] = unquote(password)
    entries = [host_entry(entry) for entry in hostlist.split(",")] if hostlist else []
    if entries:
        env["PGHOST"] = ",".join(unquote(host) for host, _ in entries)
        if any(port for _, port in entries):
            env["PGPORT"] = ",".join(port for _, port in entries)
    database = unquote(path[1:]) if path.startswith("/") else ""
    if database:
        env["PGDATABASE"] = database
    for segment in query.split("&") if query else []:
        key, _, value = segment.partition("=")
        var = QUERY_TO_ENV.get(unquote(key))
        if var is None:
            raise CredentialError("the tier URL carries a query key this helper does not map")
        env[var] = unquote(value)
    if "PGPASSWORD" not in env:
        raise CredentialError("the tier URL carries no password")
    return env


def with_database(url, database):
    """Return ``url`` with its database path segment replaced by ``database`` (names are [a-z0-9_] only)."""
    if not DATABASE_RE.match(database):
        raise CredentialError("the database name is not a lowercase [a-z0-9_] identifier of at most 63 characters")
    head, mark, query = url.partition("?")
    base, slash, _ = head.rpartition("/")
    if not slash or base.endswith("/") or base.endswith(":"):
        raise CredentialError("the tier URL names no database path to replace")
    return base + "/" + database + mark + query


def child_env(url, database, export_url):
    """The environment of the child: inherited variables minus every PG* one, plus the tier connection."""
    if database is not None:
        url = with_database(url, database)
    env = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
    env.update(libpq_env(url))
    if export_url:
        env[URL_VAR] = url
    return env


def cmd_run(args):
    if not args.command:
        raise CredentialError("run needs a command after --")
    env = child_env(load_url(args.url_file), args.database, args.export_url)
    try:
        return subprocess.run(args.command, env=env, check=False).returncode
    except OSError as exc:
        report("cannot start the command (%s)" % read_error_name(exc))
        return EXIT_NO_COMMAND


def cmd_github_env(args):
    target = os.environ.get(GITHUB_ENV_VAR)
    if not target:
        raise CredentialError("%s is not set" % GITHUB_ENV_VAR)
    url = with_database(load_url(args.url_file), args.database)
    if any(ch in unquote(url) for ch in "\r\n\x00"):
        raise CredentialError("the tier URL carries an encoded line break or NUL byte")
    password = libpq_env(url)["PGPASSWORD"]
    # Mask first, then write (#8187): the workflow log masks a value from the line after the command prints it.
    # Each mask is one line: the written URL, the decoded password, and the password as encoded in the URL.
    raw_password = split_url(url)[0].partition(":")[2]
    masks = [url, password] + ([raw_password] if raw_password != password else [])
    for value in masks:
        print("::add-mask::" + escape_workflow_command_data(value), flush=True)
    names = [URL_VAR] + ([AGE_URL_VAR] if args.age_url else [])
    try:
        with open(target, "a", encoding="utf-8") as handle:
            for name in names:
                handle.write("%s=%s\n" % (name, url))
    except OSError as exc:
        raise CredentialError("cannot append to %s (%s)" % (GITHUB_ENV_VAR, read_error_name(exc)))
    return EXIT_OK


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="verb", required=True)
    run = sub.add_parser("run", help="run a command with the tier connection in libpq environment variables")
    run.add_argument("--url-file", required=True)
    run.add_argument("--database")
    run.add_argument("--export-url", action="store_true")
    run.add_argument("command", nargs=argparse.REMAINDER)
    env = sub.add_parser("github-env", help="append the tier URL for a database to $GITHUB_ENV")
    env.add_argument("--url-file", required=True)
    env.add_argument("--database", required=True)
    env.add_argument("--age-url", action="store_true", help="also set AI_MEMORY_TEST_AGE_URL to the same URL")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.verb == "run" and args.command[:1] == ["--"]:
        args.command = args.command[1:]
    try:
        return cmd_run(args) if args.verb == "run" else cmd_github_env(args)
    except CredentialError as exc:
        report(str(exc))
        return exc.code


if __name__ == "__main__":
    sys.exit(main())
