#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Resolve the PER-RUNNER cargo target directory for self-hosted legs (#7188).

Every linux-fed runner on one host runs as the same user, so a directory tree
under that user's home survives checkout cleaning (it lives outside the
workspace) and is per host by construction. Each runner gets its OWN target,
``~/.cache/ai-memory-ci/cargo-target/<runner-name>``: a target with exactly one
writer cannot have one PR's test binary replaced by another PR's build (cargo
releases its build lock before it executes test binaries), and the dependency
and workspace cache stays warm across the jobs of that runner (compile once).

The runner name is passed explicitly (``--runner-name``) from the workflow. It
FAILS CLOSED: a missing, empty, ``.``/``..`` or non ``[A-Za-z0-9._-]`` name
exits EXIT_USAGE, exports nothing and creates nothing; there is never a shared
fallback path.

This is the ONLY place the path root is defined: the workflow calls this helper
once and exports CARGO_TARGET_DIR (this runner) and AI_MEMORY_CI_TARGET_ROOT
(the whole root, protected by the prune step) through $GITHUB_ENV.

Exit codes: 0 ok, 2 bad arguments or an unusable home directory or runner name.
Python 3.9+, standard library only.
"""
import argparse
import re
import sys
from pathlib import Path

TARGET_ROOT_RELATIVE = Path(".cache") / "ai-memory-ci" / "cargo-target"
ENV_NAME = "CARGO_TARGET_DIR"
ROOT_ENV_NAME = "AI_MEMORY_CI_TARGET_ROOT"
RUNNER_NAME_PATTERN = re.compile(r"\A[A-Za-z0-9._-]+\Z")
DOT_NAMES = (".", "..")
EXIT_OK = 0
EXIT_USAGE = 2


def target_root_dir(home):
    """Return the root holding every runner target (never a tmp path)."""
    return Path(home) / TARGET_ROOT_RELATIVE


def valid_runner_name(name):
    """True for a non-empty name of ``[A-Za-z0-9._-]`` that is not ``.``/``..``."""
    return bool(name) and name not in DOT_NAMES and bool(RUNNER_NAME_PATTERN.match(name))


def runner_target_dir(home, runner_name):
    """Return this runner's target path; raises ValueError on a bad name."""
    if not valid_runner_name(runner_name):
        raise ValueError("invalid runner name %r" % (runner_name,))
    return target_root_dir(home) / runner_name


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--home", default=str(Path.home()), help="runner user home")
    parser.add_argument("--runner-name", default=None, help="runner name (required)")
    parser.add_argument(
        "--github-env", help="append CARGO_TARGET_DIR and the root to this $GITHUB_ENV file"
    )
    args = parser.parse_args(argv)
    home = Path(args.home)
    if not home.is_absolute() or str(home) in ("/", ""):
        print("shared_cargo_target: refusing home %r" % args.home, file=sys.stderr)
        return EXIT_USAGE
    try:
        path = runner_target_dir(home, args.runner_name)
    except ValueError as err:
        print("shared_cargo_target: refusing: %s" % err, file=sys.stderr)
        return EXIT_USAGE
    path.mkdir(parents=True, exist_ok=True)
    if args.github_env:
        with open(args.github_env, "a", encoding="utf-8") as handle:
            handle.write("%s=%s\n" % (ENV_NAME, path))
            handle.write("%s=%s\n" % (ROOT_ENV_NAME, target_root_dir(home)))
    print(path)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
