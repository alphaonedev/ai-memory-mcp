#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Resolve the shared per-host cargo target directory for self-hosted legs (#7188).

Every linux-fed runner on one host runs as the same user, so a directory under
that user's home is shared by all of them, survives checkout cleaning (it lives
outside the workspace) and is per host by construction. cargo's own
build-directory lock serialises compilation into it; tests still run in
parallel afterwards and the dependency cache stays warm across PRs.

This is the ONLY place the path is defined: the workflow calls this helper once
and exports the result as CARGO_TARGET_DIR through $GITHUB_ENV.

Exit codes: 0 ok, 2 bad arguments or an unusable home directory.
Python 3.9+, standard library only.
"""
import argparse
import sys
from pathlib import Path

SHARED_TARGET_RELATIVE = Path(".cache") / "ai-memory-ci" / "cargo-target"
ENV_NAME = "CARGO_TARGET_DIR"
EXIT_OK = 0
EXIT_BAD_ARGS = 2


def shared_target_dir(home):
    """Return the shared target path under ``home`` (never a tmp path)."""
    return Path(home) / SHARED_TARGET_RELATIVE


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--home", default=str(Path.home()), help="runner user home")
    parser.add_argument(
        "--github-env", help="append CARGO_TARGET_DIR=<path> to this $GITHUB_ENV file"
    )
    args = parser.parse_args(argv)
    home = Path(args.home)
    if not home.is_absolute() or str(home) in ("/", ""):
        print("shared_cargo_target: refusing home %r" % args.home, file=sys.stderr)
        return EXIT_BAD_ARGS
    path = shared_target_dir(home)
    path.mkdir(parents=True, exist_ok=True)
    if args.github_env:
        with open(args.github_env, "a", encoding="utf-8") as handle:
            handle.write("%s=%s\n" % (ENV_NAME, path))
    print(path)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
