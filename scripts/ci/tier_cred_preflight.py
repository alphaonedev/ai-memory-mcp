#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Authenticate to the enterprise-fed CI tier before the leg creates its database (#8686).

The ``Configure enterprise-fed tier`` step of ``.github/workflows/ci.yml`` reads the node-local tier URL file
(``$HOME/.ai-memory-ci-fed-url``) and issues ``CREATE DATABASE`` on the native tier.  When the role password on
the tier and the password in that file diverge, the leg used to fail with a generic "failed to CREATE DATABASE"
line.  This helper connects first with exactly that file and runs ``SELECT 1``, so the failure carries its cause:

=================================  =========  ==============================================================
reason                             exit code  psql stderr (classified, never printed)
=================================  =========  ==============================================================
``tier credential ok``             0          psql exited 0 and printed ``1``
``tier credential mismatch``       3          password authentication failed, no password supplied, or the
                                              role does not exist: the credential source and the tier disagree
``tier TLS verification failed``   1          certificate / host-name / root-certificate errors
``tier unreachable``               1          refused, timeout expired, unknown host, starting / shutting down
``tier pre-flight timed out``      1          psql did not finish within ``--timeout`` seconds
``tier pre-flight failed``         1          anything else, including exit 0 without the ``1`` answer
=================================  =========  ==============================================================

The URL file is read and validated by ``scripts/ci/ensure-age-extension.py`` (one parser for the tier URL, #8187):
a missing, empty, non-``postgres://`` or not ``sslmode=verify-full`` URL is refused with exit 2 before psql runs.
The password reaches psql only through ``PGPASSWORD`` and the database only through ``PGDATABASE``; psql's
environment is that helper's allowlist plus ``LC_ALL=C`` so libpq's messages are classified in one language.
psql's stderr is never echoed (it can carry connection detail); every output line is one GitHub ``::error::`` or
plain notice line built from constants, the URL file path and ``$RUNNER_NAME``.  The classification is a fixed set
of substring tests, linear in the stderr length.
"""

import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_UNAVAILABLE = 1
EXIT_BAD_INPUT = 2
EXIT_MISMATCH = 3

DEFAULT_TIMEOUT_SECONDS = 60
PROBE_SQL = "SELECT 1"
PROBE_ANSWER = "1"
ISSUE = "#8686"

OK_REASON = "tier credential ok"
MISMATCH_REASON = "tier credential mismatch"
TLS_REASON = "tier TLS verification failed"
UNREACHABLE_REASON = "tier unreachable"
TIMEOUT_REASON = "tier pre-flight timed out"
OTHER_REASON = "tier pre-flight failed"

# Checked in this order; the first class with a matching marker wins, so an auth failure printed after a refused
# host of a multi-host URL is still a mismatch.  ``role "<name>" does not exist`` is a mismatch too (role_missing).
CLASSES = (
    (MISMATCH_REASON, EXIT_MISMATCH, (
        "password authentication failed",
        "no password supplied",
    )),
    (TLS_REASON, EXIT_UNAVAILABLE, (
        "certificate verify failed",
        "server certificate for",
        "root certificate file",
        "SSL error",
        "SSL SYSCALL error",
    )),
    (UNREACHABLE_REASON, EXIT_UNAVAILABLE, (
        "Connection refused",
        "timeout expired",
        "could not translate host name",
        "No route to host",
        "Network is unreachable",
        "the database system is starting up",
        "the database system is shutting down",
        "No such file or directory",  # a unix socket path that does not exist
    )),
)
ROLE_MISSING_TAIL = "\" does not exist"

MESSAGES = {
    MISMATCH_REASON: "the tier rejected the credential in {url_file}; re-align the role password or the file "
                     "(rotation: DEV-CI-ENVIRONMENT.md, #8187)",
    TLS_REASON: "TLS verify-full failed against the tier with the root certificate named in {url_file}",
    UNREACHABLE_REASON: "the tier named in {url_file} did not accept a connection",
    TIMEOUT_REASON: "psql did not finish within the pre-flight timeout",
    OTHER_REASON: "psql exited {rc} (stderr withheld)",
}


def load_url_helper():
    """``scripts/ci/ensure-age-extension.py`` as a module (its name has a hyphen; ``python3 -I`` drops sys.path[0])."""
    path = Path(__file__).resolve().parent / "ensure-age-extension.py"
    spec = importlib.util.spec_from_file_location("ensure_age_extension", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def role_missing(stderr):
    """True when stderr carries ``role "<name>" does not exist`` (any name, linear scan)."""
    start = stderr.find("role \"")
    while start != -1:
        close = stderr.find("\"", start + len("role \""))
        if close == -1:
            return False
        if stderr.startswith(ROLE_MISSING_TAIL, close):
            return True
        start = stderr.find("role \"", close + 1)
    return False


def classify(rc, stderr):
    """Return (reason, exit code) for a failed psql run; never inspects anything but the fixed markers."""
    for reason, code, markers in CLASSES:
        if any(marker in stderr for marker in markers) or (reason == MISMATCH_REASON and role_missing(stderr)):
            return reason, code
    return OTHER_REASON, EXIT_UNAVAILABLE


def reason_line(reason, url_file, runner, rc):
    """The one ``::error::`` line for a failure: constants, the URL file path and the runner name only."""
    detail = MESSAGES[reason].format(url_file=url_file, rc=rc)
    return f"::error::enterprise-fed tier pre-flight on {runner}: {reason} ({ISSUE}): {detail}"


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--url-file", type=Path, required=True, help="the tier URL file the workflow reads")
    p.add_argument("--psql", default=None, help="path to psql (default: psql on PATH)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="seconds before psql is killed")
    return p.parse_args(argv)


def probe(args, url_helper):
    """Run the probe; return (reason, exit code, psql rc or None)."""
    try:
        url = url_helper.read_url(args.url_file)  # refuses a bad shape or a non-verify-full URL (exit 2)
        target, password, database = url_helper.probe_target(url)
    except url_helper.HelperError as exc:
        return str(exc), exc.code, None
    psql = args.psql or shutil.which("psql")
    if not psql or not os.access(psql, os.X_OK):
        return "psql not found for the tier pre-flight", EXIT_UNAVAILABLE, None
    env = url_helper.psql_env(password, database)
    env["LC_ALL"] = "C"
    argv = [psql, target, "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", PROBE_SQL]
    try:
        proc = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              errors="replace", timeout=args.timeout)
    except subprocess.TimeoutExpired:
        return TIMEOUT_REASON, EXIT_UNAVAILABLE, None
    except (OSError, ValueError) as exc:
        return f"psql could not run for the tier pre-flight ({type(exc).__name__})", EXIT_UNAVAILABLE, None
    if proc.returncode == 0:
        if proc.stdout.strip() == PROBE_ANSWER:
            return OK_REASON, EXIT_OK, 0
        return OTHER_REASON, EXIT_UNAVAILABLE, 0
    reason, code = classify(proc.returncode, proc.stderr)
    return reason, code, proc.returncode


def main(argv=None):
    args = parse_args(argv)
    runner = os.environ.get("RUNNER_NAME", "this runner")
    reason, code, rc = probe(args, load_url_helper())
    if code == EXIT_OK:
        print(f"enterprise-fed tier pre-flight on {runner}: {OK_REASON} ({args.url_file})")
    elif reason in MESSAGES:
        print(reason_line(reason, args.url_file, runner, rc))
    else:
        # a refusal from the URL helper or a local psql problem: its message names keys and paths only
        print(f"::error::enterprise-fed tier pre-flight on {runner}: {reason} ({ISSUE})")
    sys.stdout.flush()
    return code


if __name__ == "__main__":
    sys.exit(main())
