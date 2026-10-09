#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Self-heal the Apache AGE extension on the macos-fed runner (#6161).

AGE on the macos-fed node is a hand-built install whose files live inside the
Homebrew-managed ``postgresql@18`` share/lib trees.  A ``brew upgrade`` relinks
those trees and drops the AGE files, so ``CREATE EXTENSION age`` fails.  A
brew-independent copy lives in a node-local directory (default
``~/pg-age-stack/age-1.8.0`` with ``share/`` and ``lib/``).

The files installed are fixed by ``MANIFEST``: exactly five names, each pinned
to a sha256.  Nothing else in the source directory is ever read or copied.

Behaviour:
  1. Healthy = ``pg_available_extensions`` lists ``age`` (that view reflects the
     ``.control`` file only) AND every manifest file exists at its destination
     as a regular file with the pinned sha256.  Healthy -> exit 0, no writes.
  2. Otherwise validate the source: the age, share and lib dirs and every
     manifest file must be real (no symlinks), owned by the running uid and not
     group/world-writable; each file is read through an ``O_NOFOLLOW`` fd and
     its bytes must match the pinned sha256.  Any failure -> exit 2, no writes.
  3. Install the validated bytes, lib before share, each through a per-process
     ``mkstemp`` temp file + fsync + ``os.replace`` (safe under concurrent
     runners).  On a write error remove the temp file and exit 1 unless another
     runner has meanwhile made the tier healthy.  Files already written stay:
     each carries its pinned bytes, so removing one could only undo a restore
     another runner has verified.
  4. Re-check health; exit 0 when healthy, else one stderr line and non-zero.

The tier URL is read from a file.  Its password is passed to psql through the
``PGPASSWORD`` environment variable and removed from the URL psql receives, so
it never appears on a process argv.  Because urllib and libpq split a URL
differently, the URL is refused (exit 2) when the two could disagree: it holds a
``#`` (libpq has no fragment and reads keys after it), or an ``@`` after the
point where urllib ended the host part.  Every query key other than
``password`` must be on ``ALLOWED_QUERY_KEYS``, a case-sensitive allowlist of
non-secret libpq parameters, so ``sslpassword``, ``oauth_client_secret``,
``scram_client_key``, ``scram_server_key`` (no environment variable) and any
other key are refused.  A refusal names the key, never its value, and neither
form of the URL is printed.

Exit codes: 0 healthy, 1 still unhealthy / probe or install failed,
2 bad input (URL file, pg_config, source validation).
"""

import argparse
import errno
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

EXIT_OK = 0
EXIT_UNAVAILABLE = 1
EXIT_BAD_INPUT = 2

DEFAULT_URL_FILE = Path.home() / ".ai-memory-ci-fed-url"
DEFAULT_AGE_DIR = Path.home() / "pg-age-stack" / "age-1.8.0"
DEFAULT_PG_CONFIG = "/opt/homebrew/opt/postgresql@18/bin/pg_config"
DEFAULT_PSQL = "/opt/homebrew/opt/postgresql@18/bin/psql"
PROBE_SQL = "SELECT count(*) FROM pg_available_extensions WHERE name = 'age'"
URL_SCHEMES = ("postgres", "postgresql")
# Non-secret libpq connection parameters accepted as tier URL query keys,
# compared exactly as libpq does (case-sensitive).  Source: PostgreSQL 18 libpq
# docs, "Connection Strings" > "Parameter Key Words" (LIBPQ-PARAMKEYWORDS).
# ``password`` is handled separately (moved to PGPASSWORD); every other key,
# including the secrets libpq cannot take from the environment, is refused.
ALLOWED_QUERY_KEYS = frozenset((
    "host", "hostaddr", "port", "dbname", "user", "application_name", "connect_timeout",
    "sslmode", "sslrootcert", "sslcert", "sslkey", "sslcrl", "sslsni", "options",
    "target_session_attrs", "client_encoding", "keepalives", "keepalives_idle",
    "keepalives_interval", "keepalives_count", "tcp_user_timeout", "channel_binding",
    "gssencmode", "krbsrvname", "service", "passfile", "requirepeer", "load_balance_hosts",
))
TEMP_SUFFIX = ".age-restore"

# (source subdir, file name, sha256) for AGE 1.8.0 built against postgresql@18.
# "lib" entries go to `pg_config --pkglibdir`, "share" entries to
# `pg_config --sharedir`/extension.  lib is listed (and installed) first so the
# control file never appears ahead of its module.
MANIFEST = (
    ("lib", "age.dylib", "8ecfc082a55b667ed2773d622d726bbc4ca299c0b44248a8ec7d27b1460ed927"),
    ("share", "age--1.6.0--1.7.0.sql", "3f63301c461e2ad3e952f1ead68d380ddadfe004b147ca81606ad63301e0514f"),
    ("share", "age--1.7.0--1.8.0.sql", "9b04323cc00cd57a9d28adc43c01f5de43d236c26d3e1a17682bc3ce039e35af"),
    ("share", "age--1.8.0.sql", "f6c2d353997a4479d1be63d0e0afc4a58fb2e0826d46f9d6d5a0e46d69441d4d"),
    ("share", "age.control", "432d43d2c9e27534c95a8061c968a3334216c6b44de111ed4466693a7fc15f09"),
)


class HelperError(Exception):
    """A failure carrying the exit code and the single stderr message."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def running_uid():
    """The uid every source dir and file must belong to."""
    return os.geteuid()


def psql_target(url):
    """Split the tier URL into (password-free URL for argv, password or None).

    Fails closed on anything that is not a postgres:// URL, because a keyword
    DSN would carry its password on argv; on any URL urllib and libpq could
    split differently (a ``#``, or an ``@`` past urllib's host part); and on any
    query key that is not ``password`` or on ``ALLOWED_QUERY_KEYS``, because it
    would stay on argv.  Messages name a key only, never a value.
    """
    if "#" in url:
        raise HelperError("tier URL file holds a '#'; libpq reads past it, so it is refused", EXIT_BAD_INPUT)
    try:
        parts = urlsplit(url)
    except ValueError:
        raise HelperError("tier URL file does not hold a valid postgres:// URL", EXIT_BAD_INPUT)
    if parts.scheme not in URL_SCHEMES or not parts.netloc:
        raise HelperError("tier URL file does not hold a postgres:// URL", EXIT_BAD_INPUT)
    if "@" in parts.path or "@" in parts.query:
        # libpq ends the userinfo at the first '@' before '/', urllib at '/', '?' or '#'.
        raise HelperError("tier URL file has an '@' after the host part; percent-encode it", EXIT_BAD_INPUT)
    password = None
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        if ":" in userinfo:
            user, raw_password = userinfo.split(":", 1)
            password = unquote(raw_password)
            userinfo = user
        netloc = f"{userinfo}@{hostport}" if userinfo else hostport
    if any(seg and "=" not in seg for seg in parts.query.split("&")):
        # A bare segment is a value, not a key, so it is refused without being named.
        raise HelperError("tier URL file has a query parameter without '='", EXIT_BAD_INPUT)
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    kept = []
    for key, value in query_pairs:
        if key.lower() == "sslpassword":
            raise HelperError("tier URL file carries sslpassword; use a key without a passphrase", EXIT_BAD_INPUT)
        if key == "password":
            password = value
        elif key in ALLOWED_QUERY_KEYS:
            kept.append((key, value))
        else:
            name = key if key.isidentifier() and key.isascii() and len(key) <= 64 else "<unprintable>"
            raise HelperError(f"tier URL file carries query key {name}, which is not on the allowlist of "
                              "non-secret libpq parameters", EXIT_BAD_INPUT)
    query = urlencode(kept) if len(kept) != len(query_pairs) else parts.query
    return urlunsplit((parts.scheme, netloc, parts.path, query, "")), password


def probe_lists_age(psql, url):
    """Return True when the tier lists ``age`` in pg_available_extensions."""
    target, password = psql_target(url)
    env = dict(os.environ)
    if password is not None:
        env["PGPASSWORD"] = password
    try:
        proc = subprocess.run(
            [psql, target, "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", PROBE_SQL],
            capture_output=True, text=True, errors="replace", check=False, timeout=60, env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HelperError(f"age probe could not run psql ({type(exc).__name__})", EXIT_UNAVAILABLE)
    if proc.returncode != 0:
        # psql stderr is deliberately not echoed (it can carry connection detail).
        raise HelperError(f"age probe failed: psql exited {proc.returncode}", EXIT_UNAVAILABLE)
    return proc.stdout.strip() == "1"


def pg_config_value(pg_config, flag):
    try:
        proc = subprocess.run(
            [pg_config, flag], capture_output=True, text=True, errors="replace", check=False, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HelperError(f"pg_config {flag} could not run ({type(exc).__name__})", EXIT_BAD_INPUT)
    value = proc.stdout.strip()
    if proc.returncode != 0 or not value:
        raise HelperError(f"pg_config {flag} failed (exit {proc.returncode})", EXIT_BAD_INPUT)
    return Path(value)


def dest_dirs(pg_config):
    return {
        "lib": pg_config_value(pg_config, "--pkglibdir"),
        "share": pg_config_value(pg_config, "--sharedir") / "extension",
    }


def sha256_of_regular_file(path):
    """sha256 of path when it is a regular file (not a symlink), else None."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)


def installed_ok(dests):
    """True when every manifest file is at its destination with the pinned hash."""
    return all(sha256_of_regular_file(dests[sub] / name) == pin for sub, name, pin in MANIFEST)


def healthy(args, dests, url):
    return installed_ok(dests) and probe_lists_age(args.psql, url)


def check_trusted(st, what):
    if st.st_uid != running_uid():
        raise HelperError(f"age source rejected: {what} is not owned by the running user", EXIT_BAD_INPUT)
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise HelperError(f"age source rejected: {what} is group- or world-writable", EXIT_BAD_INPUT)


def check_dir(path):
    try:
        st = os.lstat(str(path))
    except OSError:
        raise HelperError(f"age source incomplete: {path} is missing", EXIT_BAD_INPUT)
    if stat.S_ISLNK(st.st_mode):
        raise HelperError(f"age source rejected: {path} is a symlink", EXIT_BAD_INPUT)
    if not stat.S_ISDIR(st.st_mode):
        raise HelperError(f"age source rejected: {path} is not a directory", EXIT_BAD_INPUT)
    check_trusted(st, str(path))


def read_source(path, pin):
    """Return (bytes, mode) of a validated manifest file; the hashed bytes are the copied bytes."""
    try:
        if stat.S_ISLNK(os.lstat(str(path)).st_mode):
            raise HelperError(f"age source rejected: {path} is a symlink", EXIT_BAD_INPUT)
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except HelperError:
        raise
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise HelperError(f"age source rejected: {path} is a symlink", EXIT_BAD_INPUT)
        raise HelperError(f"age source incomplete: {path} is missing", EXIT_BAD_INPUT)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise HelperError(f"age source rejected: {path} is not a regular file", EXIT_BAD_INPUT)
        check_trusted(st, str(path))
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read()
    except OSError as exc:
        raise HelperError(f"age source unreadable: {path} ({exc.strerror})", EXIT_BAD_INPUT)
    finally:
        os.close(fd)
    if hashlib.sha256(data).hexdigest() != pin:
        raise HelperError(f"age source rejected: {path} does not match its pinned sha256", EXIT_BAD_INPUT)
    return data, stat.S_IMODE(st.st_mode)


def load_sources(age_dir):
    """Validate the source tree and return [(sub, name, bytes, mode)] in MANIFEST order."""
    check_dir(age_dir)
    for sub in sorted({sub for sub, _, _ in MANIFEST}):
        check_dir(age_dir / sub)
    return [(sub, name) + read_source(age_dir / sub / name, pin) for sub, name, pin in MANIFEST]


def write_atomic(data, mode, dest):
    """Write data to dest via a per-process temp file + fsync + rename."""
    fd, tmp = tempfile.mkstemp(dir=str(dest.parent), prefix=f".{dest.name}.", suffix=TEMP_SUFFIX)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fchmod(fh.fileno(), mode)
            os.fsync(fh.fileno())
        os.replace(tmp, str(dest))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass  # temp already removed; the original error is re-raised below
        raise


def install(sources, dests):
    """Install every source in MANIFEST order (lib before share); raises OSError on a write error.

    A file written before a later failure is left in place: it carries the pinned
    bytes any runner would write, so it is always safe, and removing it could undo
    a restore that a concurrent runner has already verified (#6161 R2-F1).
    """
    for sub, name, data, mode in sources:
        dests[sub].mkdir(parents=True, exist_ok=True)
        write_atomic(data, mode, dests[sub] / name)


def parse_args(argv):
    p = argparse.ArgumentParser(description="Restore the AGE extension files when Homebrew dropped them (#6161).")
    p.add_argument("--url-file", type=Path, default=DEFAULT_URL_FILE, help="file holding the tier URL")
    p.add_argument("--age-dir", type=Path, default=DEFAULT_AGE_DIR,
                   help="node-local AGE dir with share/ and lib/ (tests only; CI uses the default)")
    p.add_argument("--pg-config", default=DEFAULT_PG_CONFIG, help="path to pg_config")
    p.add_argument("--psql", default=DEFAULT_PSQL, help="path to psql")
    return p.parse_args(argv)


def read_url(url_file):
    try:
        url = url_file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        raise HelperError(f"tier URL file {url_file} is unreadable", EXIT_BAD_INPUT)
    if not url:
        raise HelperError(f"tier URL file {url_file} is empty", EXIT_BAD_INPUT)
    psql_target(url)  # validate the shape before any psql call
    return url


def run(args):
    url = read_url(args.url_file)
    dests = dest_dirs(args.pg_config)
    if healthy(args, dests, url):
        print("age extension available (no restore needed)")
        return
    sources = load_sources(args.age_dir)
    try:
        install(sources, dests)
    except OSError as exc:
        # Another runner may have completed the same restore concurrently.
        if healthy(args, dests, url):
            print("age extension available (restored concurrently by another run)")
            return
        raise HelperError(f"age restore failed: {exc.strerror or exc}", EXIT_UNAVAILABLE)
    if not healthy(args, dests, url):
        raise HelperError("age extension still unavailable after restore from " + str(args.age_dir), EXIT_UNAVAILABLE)
    print(f"age extension restored from {args.age_dir} and available")


def main(argv=None):
    try:
        run(parse_args(argv))
    except HelperError as exc:
        print(f"ensure-age-extension: {exc}", file=sys.stderr)
        return exc.code
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
