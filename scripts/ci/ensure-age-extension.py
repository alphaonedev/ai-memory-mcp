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
the password never appears on a process argv.  ONLY the password is moved off
argv: path- and name-valued keys that are allowed (``sslrootcert``, ``sslcert``,
``sslkey``, ``sslcrl``, ``sslcrldir``, ``passfile``, ``krbsrvname``,
``requirepeer``) stay in the URL on psql's argv, as do host, user and database.

Because urllib and libpq split a URL differently, the URL is refused (exit 2,
one stderr line, no value printed) when any of these hold: it does not start
with the exact lowercase ``postgres://`` or ``postgresql://``; it holds a
control character (TAB, CR, LF, NUL), a raw space, a ``#`` (libpq has no
fragment), or a ``%`` not followed by two hex digits; it holds ``%00`` anywhere;
the host part has more than one ``@`` or an ``@`` after it, or is empty
(``postgres:///db``); the query has an empty segment (``a=1&&b=2``; a single
trailing ``&`` is accepted), a segment without exactly one ``=``, or a key not
on ``ALLOWED_QUERY_KEYS``.  These are the checks libpq itself makes
(``conninfo_uri_decode``, ``conninfo_uri_parse_params``) plus fail-closed
refusals where libpq would accept something urlsplit reads differently.  The
helper is stricter than libpq in those cases only; a URL the helper accepts is
read the same way by libpq (the parity oracle in the tests pins this).

Decoding is percent-decoding only: ``%XX`` becomes one raw byte (``%FF``
reaches PGPASSWORD as byte 0xFF, not U+FFFD) and ``+`` stays a literal plus, as
in libpq.  A socket directory given as ``?host=%2F...`` or as a percent-encoded
host works, including with a userinfo password and an empty host
(``postgres://:pw@/db?host=%2Fdir``).  The rewritten URL psql receives drops
the password and keeps every other segment as written.

``ALLOWED_QUERY_KEYS`` is a case-sensitive allowlist that is a SUBSET of libpq's
non-secret parameters.  The remaining keys are refused by name when they are
known libpq keywords: secrets (``sslpassword``, ``oauth_client_secret``,
``scram_client_key``, ``scram_server_key``, which libpq cannot take from the
environment) and keys that change the authentication mechanism or session mode
(``gsslib``, ``gssdelegation``, ``replication``, ``oauth_issuer``,
``oauth_client_id``, ``oauth_scope``).  ``service`` is refused too (#6345): libpq reads a
``pg_service.conf`` entry BEFORE ``PGPASSWORD``, so a service-file password would beat the
password the helper moved off argv, while in the original URL the URL password wins.  For the
same reason psql runs without ``PGSERVICE`` and ``PGSERVICEFILE`` in its environment.  ``ssl=true`` (a JDBC alias libpq maps
to ``sslmode=require``) is refused so that the TLS mode is always spelled ``sslmode``.  ``sslkeylogfile`` (it writes
TLS session secrets to a file) and ``require_auth`` (it changes the accepted authentication methods) are refused too.  A refusal names a key only when it is a known libpq
keyword (an unlisted key can be the tail of a password that held a raw ``&``),
never a value, and neither form of the URL is printed.

psql runs with ``PGCONNECT_TIMEOUT=15`` and a 60 second overall limit.  A
``connect_timeout`` in the URL overrides the default but must be an integer in
1..60 (#6338): libpq reads 0 as "wait forever", which would leave a psql that
outlives a SIGKILLed helper (SIGKILL cannot be caught) holding PGPASSWORD without
bound.  SIGTERM, SIGINT and SIGHUP stop the psql child, print
``ensure-age-extension: interrupted`` and exit 1.  While the child is being
spawned or awaited the handler only records the signal and the probe polls that
flag every 0.2 s (#6337); raising from the handler instead could land between the
fork and the guard around ``communicate`` and orphan psql with PGPASSWORD.

Exit codes: 0 healthy, 1 still unhealthy / probe or install failed,
2 bad input (URL file, pg_config, source validation).
"""

import argparse
import contextlib
import errno
import hashlib
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import unquote, urlsplit

EXIT_OK = 0
EXIT_UNAVAILABLE = 1
EXIT_BAD_INPUT = 2

DEFAULT_URL_FILE = Path.home() / ".ai-memory-ci-fed-url"
DEFAULT_AGE_DIR = Path.home() / "pg-age-stack" / "age-1.8.0"
DEFAULT_PG_CONFIG = "/opt/homebrew/opt/postgresql@18/bin/pg_config"
DEFAULT_PSQL = "/opt/homebrew/opt/postgresql@18/bin/psql"
PROBE_TIMEOUT_SECONDS = 60
PROBE_POLL_SECONDS = 0.2  # how often the probe looks at the interrupt flag (#6337)
MAX_CONNECT_TIMEOUT_SECONDS = PROBE_TIMEOUT_SECONDS  # URL connect_timeout range 1..60 (#6338)
INTERRUPT_SIGNALS = ("SIGTERM", "SIGINT", "SIGHUP")
CONNECT_TIMEOUT_SECONDS = "15"  # PGCONNECT_TIMEOUT for psql; a connect_timeout in the URL overrides it
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
    "gssencmode", "krbsrvname", "passfile", "requirepeer", "load_balance_hosts",
    "fallback_application_name", "sslnegotiation", "sslcompression", "sslcertmode", "sslcrldir",
    "min_protocol_version", "max_protocol_version", "ssl_min_protocol_version", "ssl_max_protocol_version",
))
# Keywords that are refused but safe to name in a message: known libpq keys (and the
# ``ssl`` JDBC alias) that are secret or change the authentication mechanism or the
# session mode.  Every libpq 18 keyword is in this set or on ALLOWED_QUERY_KEYS;
# any other refused key stays unnamed.
REFUSED_KNOWN_KEYS = frozenset((
    "password", "sslpassword", "oauth_client_secret", "scram_client_key", "scram_server_key",
    "service", "sslkeylogfile", "require_auth", "gsslib", "gssdelegation", "replication", "oauth_issuer",
    "oauth_client_id", "oauth_scope", "ssl",
))
KNOWN_KEY_NAMES = ALLOWED_QUERY_KEYS | REFUSED_KNOWN_KEYS
# libpq applies a pg_service.conf entry before PGPASSWORD (#6345), so neither reaches the psql child.
SERVICE_ENV = ("PGSERVICE", "PGSERVICEFILE")
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


def valid_connect_timeout(value):
    """True for 1..MAX_CONNECT_TIMEOUT_SECONDS written as one or two ASCII digits."""
    return re.fullmatch(r"[0-9]{1,2}", value) is not None and 1 <= int(value) <= MAX_CONNECT_TIMEOUT_SECONDS


def psql_target(url):
    """Split the tier URL into (password-free URL for argv, password or None).

    Fails closed on anything that is not a postgres:// URL, because a keyword
    DSN would carry its password on argv; on any URL urllib and libpq could
    split differently (TAB/CR/LF/NUL, a ``#``, several ``@`` in the host part,
    an ``@`` past it, a query segment without exactly one ``=``); and on any
    query key that is not ``password`` or on ``ALLOWED_QUERY_KEYS``, because it
    would stay on argv.  Messages name a key only, never a value.
    """
    if any(ch in url for ch in "\t\r\n\x00"):
        # urlsplit silently drops TAB/CR/LF (joining lines); subprocess refuses NUL.
        raise HelperError("tier URL file holds a TAB, line break or NUL; the URL must be one line", EXIT_BAD_INPUT)
    if "#" in url:
        raise HelperError("tier URL file holds a '#'; libpq reads past it, so it is refused", EXIT_BAD_INPUT)
    if not url.startswith(tuple(f"{scheme}://" for scheme in URL_SCHEMES)):
        # libpq matches the scheme case-sensitively; urlsplit would lower-case it.
        raise HelperError("tier URL file does not hold a postgres:// URL", EXIT_BAD_INPUT)
    if " " in url:
        raise HelperError("tier URL file holds a space; libpq refuses it, use %20", EXIT_BAD_INPUT)
    if re.search(r"%(?![0-9A-Fa-f]{2})", url):
        raise HelperError("tier URL file holds an invalid percent-encoded token; libpq refuses it", EXIT_BAD_INPUT)
    if "%00" in url:
        raise HelperError("tier URL file holds a %00; libpq refuses a percent-encoded NUL", EXIT_BAD_INPUT)
    try:
        parts = urlsplit(url)
    except ValueError:
        raise HelperError("tier URL file does not hold a valid postgres:// URL", EXIT_BAD_INPUT)
    if parts.scheme not in URL_SCHEMES:
        raise HelperError("tier URL file does not hold a postgres:// URL", EXIT_BAD_INPUT)
    if not parts.netloc:
        raise HelperError("tier URL file has an empty host part (postgres:///db...); it is refused",
                          EXIT_BAD_INPUT)
    if "@" in parts.path or "@" in parts.query:
        # libpq ends the userinfo at the first '@' before '/', urllib at '/', '?' or '#'.
        raise HelperError("tier URL file has an '@' after the host part; percent-encode it", EXIT_BAD_INPUT)
    if parts.netloc.count("@") > 1:
        # urllib splits the userinfo at the last '@', libpq at the first.
        raise HelperError("tier URL file has more than one '@' in the host part; percent-encode '@' as %40",
                          EXIT_BAD_INPUT)
    password = None
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        if ":" in userinfo:
            user, raw_password = userinfo.split(":", 1)
            password = unquote(raw_password, errors="surrogateescape")
            userinfo = user
        netloc = f"{userinfo}@{hostport}" if userinfo else hostport
    # libpq accepts one trailing '&' and refuses every other empty segment.
    body = parts.query[:-1] if parts.query.endswith("&") else parts.query
    segments = body.split("&") if parts.query else []
    if any(not seg for seg in segments):
        raise HelperError("tier URL file has an empty query segment; libpq refuses it", EXIT_BAD_INPUT)
    if any("=" not in seg for seg in segments):
        # A bare segment is a value, not a key, so it is refused without being named.
        raise HelperError("tier URL file has a query parameter without '='", EXIT_BAD_INPUT)
    if any(seg.count("=") > 1 for seg in segments):
        # A second '=' makes the remainder (';password=...') part of one value; libpq refuses it.
        raise HelperError("tier URL file has a query parameter with more than one '='", EXIT_BAD_INPUT)
    kept = []
    removed = False
    for seg in segments:
        # libpq percent-decodes only: '+' is a plus, not a space (#6221), and %XX is one raw byte.
        raw_key, raw_value = seg.split("=", 1)
        key = unquote(raw_key, errors="surrogateescape")
        if key.lower() == "sslpassword":
            raise HelperError("tier URL file carries sslpassword; use a key without a passphrase", EXIT_BAD_INPUT)
        if key == "password":
            password = unquote(raw_value, errors="surrogateescape")
            removed = True
        elif key in ALLOWED_QUERY_KEYS:
            if key == "connect_timeout" and not valid_connect_timeout(unquote(raw_value, errors="surrogateescape")):
                # libpq reads 0 as "wait forever": an orphaned psql would then never exit (#6338).
                raise HelperError(f"tier URL file has a connect_timeout outside 1..{MAX_CONNECT_TIMEOUT_SECONDS} "
                                  "seconds; libpq reads 0 as no limit", EXIT_BAD_INPUT)
            kept.append(seg)
        else:
            # An unlisted key can be the tail of a password that held a raw '&': name known keywords only.
            lowered = key.lower()
            name = lowered if lowered in KNOWN_KEY_NAMES else None
            what = "an unlisted query key"
            if name:
                what = f"query key {name}" if key == name else f"query key {name} (keys are case-sensitive)"
            raise HelperError(f"tier URL file carries {what}, which is not on the allowlist of "
                              "non-secret libpq parameters", EXIT_BAD_INPUT)
    if password is not None and "\x00" in password:
        raise HelperError("tier URL file password decodes to a NUL; it cannot be passed to psql", EXIT_BAD_INPUT)
    if password is None:
        return url, None  # nothing moved to the environment: psql gets the URL as written
    query = "&".join(kept) if removed else parts.query
    # Concatenate: urlunsplit drops '//' when the netloc is empty (':pw@' with a host in the query).
    return f"{parts.scheme}://{netloc}{parts.path}" + (f"?{query}" if query else ""), password


_interrupt = {"defer": False, "pending": False}


def note_interrupt(signum, frame):
    """Signal handler: raise, except while a psql child is live, then only record it (#6337).

    Raising between the fork and the guard around ``communicate`` would escape the guard and
    leave psql running with PGPASSWORD; the probe polls ``pending`` and stops the child itself.
    """
    if _interrupt["defer"]:
        _interrupt["pending"] = True
        return
    raise KeyboardInterrupt


@contextlib.contextmanager
def deferred_interrupts():
    """Hold signals as a flag while the psql child is spawned and awaited; re-raise on exit."""
    _interrupt["pending"] = False
    _interrupt["defer"] = True
    try:
        yield
    finally:
        _interrupt["defer"] = False
        if _interrupt["pending"]:
            _interrupt["pending"] = False
            raise KeyboardInterrupt


def wait_for_probe(proc):
    """communicate() in short slices so a recorded signal is noticed within PROBE_POLL_SECONDS."""
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    while True:
        if _interrupt["pending"]:
            raise KeyboardInterrupt
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(proc.args, PROBE_TIMEOUT_SECONDS)
        try:
            stdout, _ = proc.communicate(timeout=min(PROBE_POLL_SECONDS, remaining))
            return stdout
        except subprocess.TimeoutExpired:
            continue


def stop_child(proc):
    """Kill and reap a psql child; it holds PGPASSWORD in its environment."""
    try:
        proc.kill()
        proc.communicate()
    except OSError:
        pass  # already gone


def probe_lists_age(psql, url):
    """Return True when the tier lists ``age`` in pg_available_extensions."""
    target, password = psql_target(url)
    env = dict(os.environ)
    if password is not None:
        env["PGPASSWORD"] = password
    env["PGCONNECT_TIMEOUT"] = CONNECT_TIMEOUT_SECONDS  # a connect_timeout in the URL overrides it
    for name in SERVICE_ENV:
        env.pop(name, None)  # #6345: a service-file password would beat the moved PGPASSWORD
    with deferred_interrupts():
        try:
            proc = subprocess.Popen(
                [psql, target, "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", PROBE_SQL],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace", env=env,
            )
        except ValueError as exc:
            # subprocess refuses a NUL in argv or env before spawning anything.
            raise HelperError(f"age probe refused its psql arguments ({type(exc).__name__})", EXIT_BAD_INPUT)
        except (OSError, subprocess.SubprocessError) as exc:
            raise HelperError(f"age probe could not run psql ({type(exc).__name__})", EXIT_UNAVAILABLE)
        try:
            stdout = wait_for_probe(proc)
        except subprocess.TimeoutExpired:
            stop_child(proc)
            raise HelperError("age probe could not run psql (TimeoutExpired)", EXIT_UNAVAILABLE)
        except BaseException:
            stop_child(proc)  # a recorded signal or error: never leave psql (and its PGPASSWORD) behind
            raise
    if proc.returncode != 0:
        # psql stderr is deliberately not echoed (it can carry connection detail).
        raise HelperError(f"age probe failed: psql exited {proc.returncode}", EXIT_UNAVAILABLE)
    return stdout.strip() == "1"


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
        # SIGTERM and SIGHUP end like SIGINT: the probe stops the psql child first.
        for name in INTERRUPT_SIGNALS:
            signal.signal(getattr(signal, name), note_interrupt)
    except ValueError:
        pass  # not the main thread (in-process callers); the default handlers stay
    try:
        run(parse_args(argv))
    except HelperError as exc:
        print(f"ensure-age-extension: {exc}", file=sys.stderr)
        return exc.code
    except KeyboardInterrupt:
        print("ensure-age-extension: interrupted", file=sys.stderr)
        return EXIT_UNAVAILABLE
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
