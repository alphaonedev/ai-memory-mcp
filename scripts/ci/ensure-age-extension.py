#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Self-heal the Apache AGE extension on the macos-fed runner (#6161).

AGE on the macos-fed node is a hand-built install whose files lived inside the
Homebrew-managed ``postgresql@18`` share/lib trees.  A ``brew upgrade`` relinks
those trees and drops the AGE files, so ``CREATE EXTENSION age`` fails with
``extension "age" is not available``.  A brew-independent copy of the files
lives in a node-local directory (default ``~/pg-age-stack/age-1.8.0`` with
``share/`` and ``lib/`` subdirectories).

Behaviour:
  1. Ask the tier (``pg_available_extensions``) whether ``age`` is available.
  2. If it is, do nothing (idempotent) and exit 0.
  3. Otherwise copy ``<age-dir>/share/*`` into ``<pg_config --sharedir>/extension``
     and ``<age-dir>/lib/*`` into ``<pg_config --pkglibdir>``, then re-check.
  4. Exit 0 when age is available, non-zero with one stderr line otherwise.

The tier URL is read from a file and handed to psql only; it is never printed.

Exit codes: 0 available, 1 still unavailable / probe failed, 2 bad input.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

EXIT_OK = 0
EXIT_UNAVAILABLE = 1
EXIT_BAD_INPUT = 2

ENV_AGE_DIR = "AI_MEMORY_CI_AGE_DIR"
DEFAULT_URL_FILE = Path.home() / ".ai-memory-ci-fed-url"
DEFAULT_AGE_DIR = Path.home() / "pg-age-stack" / "age-1.8.0"
DEFAULT_PG_CONFIG = "/opt/homebrew/opt/postgresql@18/bin/pg_config"
DEFAULT_PSQL = "/opt/homebrew/opt/postgresql@18/bin/psql"
PROBE_SQL = "SELECT count(*) FROM pg_available_extensions WHERE name = 'age'"
REQUIRED_FILES = (("share", "age.control"), ("lib", "age.dylib"))


class HelperError(Exception):
    """A failure carrying the exit code and the single stderr message."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def age_available(psql, url):
    """Return True when the tier lists ``age`` in pg_available_extensions."""
    try:
        proc = subprocess.run(
            [psql, url, "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", PROBE_SQL],
            capture_output=True, text=True, check=False, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HelperError(f"age probe could not run psql ({type(exc).__name__})", EXIT_UNAVAILABLE)
    if proc.returncode != 0:
        # psql stderr is deliberately not echoed (it can carry connection detail).
        raise HelperError(f"age probe failed: psql exited {proc.returncode}", EXIT_UNAVAILABLE)
    return proc.stdout.strip() == "1"


def pg_config_value(pg_config, flag):
    try:
        proc = subprocess.run([pg_config, flag], capture_output=True, text=True, check=False, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise HelperError(f"pg_config {flag} could not run ({type(exc).__name__})", EXIT_BAD_INPUT)
    value = proc.stdout.strip()
    if proc.returncode != 0 or not value:
        raise HelperError(f"pg_config {flag} failed (exit {proc.returncode})", EXIT_BAD_INPUT)
    return Path(value)


def copy_atomic(src, dest_dir):
    """Copy src into dest_dir via a temp name + rename so a reader never sees a torn file."""
    dest = dest_dir / src.name
    tmp = dest_dir / f".{src.name}.age-restore"
    shutil.copy2(src, tmp)
    os.replace(tmp, dest)


def restore(age_dir, pg_config):
    for sub, name in REQUIRED_FILES:
        if not (age_dir / sub / name).is_file():
            raise HelperError(f"age source incomplete: {age_dir / sub / name} is missing", EXIT_BAD_INPUT)
    targets = (
        (age_dir / "share", pg_config_value(pg_config, "--sharedir") / "extension"),
        (age_dir / "lib", pg_config_value(pg_config, "--pkglibdir")),
    )
    for src_dir, dest_dir in targets:
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            for src in sorted(src_dir.iterdir()):
                if src.is_file():
                    copy_atomic(src, dest_dir)
        except OSError as exc:
            raise HelperError(f"age restore into {dest_dir} failed: {exc.strerror}", EXIT_UNAVAILABLE)


def parse_args(argv):
    p = argparse.ArgumentParser(description="Restore the AGE extension files when Homebrew dropped them (#6161).")
    p.add_argument("--url-file", type=Path, default=DEFAULT_URL_FILE, help="file holding the tier URL")
    p.add_argument("--age-dir", type=Path, default=Path(os.environ.get(ENV_AGE_DIR) or DEFAULT_AGE_DIR),
                   help=f"node-local AGE dir with share/ and lib/ (env {ENV_AGE_DIR})")
    p.add_argument("--pg-config", default=DEFAULT_PG_CONFIG, help="path to pg_config")
    p.add_argument("--psql", default=DEFAULT_PSQL, help="path to psql")
    return p.parse_args(argv)


def run(args):
    try:
        url = args.url_file.read_text().strip()
    except OSError:
        raise HelperError(f"tier URL file {args.url_file} is unreadable", EXIT_BAD_INPUT)
    if not url:
        raise HelperError(f"tier URL file {args.url_file} is empty", EXIT_BAD_INPUT)
    if age_available(args.psql, url):
        print("age extension available (no restore needed)")
        return
    restore(args.age_dir, args.pg_config)
    if not age_available(args.psql, url):
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
