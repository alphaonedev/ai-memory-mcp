#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""CI failure classifier for annotation lines (issue #9235).

`jev_ci_class` maps a CI log to a class.  This module owns the mapping for
the hosted-runner PostgreSQL preflight annotation emitted by
`scripts/ci/pg_env_preflight.py`:

    ::error::[coverage-pg] PG-ENV <reason>   ->   ci-env

Anything else (a warning, a missing `::error::`, another label, a glued-on
suffix such as `PG-ENVX`) is NOT classified here and yields `None`.

CLI: `ci_failure_class.py [LOGFILE]` (stdin when omitted) prints
`CI-CLASS: ci-env` or `CI-CLASS: none`; exit code 0 always.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

CLASS_CI_ENV = "ci-env"
PG_ENV_LABEL = "coverage-pg"

# The annotation may follow a runner timestamp, so anchor on whitespace or
# line start rather than the whole line; the reason must be non-empty.
PG_ENV_LINE = re.compile(
    r"(?m)(?:^|\s)::error::\[" + re.escape(PG_ENV_LABEL) + r"\] PG-ENV [^\s]"
)


def classify(log_text: str) -> str | None:
    """Return the CI class for the log text, or None when no rule matches."""
    if PG_ENV_LINE.search(log_text):
        return CLASS_CI_ENV
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument("logfile", nargs="?", help="log file (stdin when omitted)")
    args = parser.parse_args(argv)
    if args.logfile:
        text = Path(args.logfile).read_text(encoding="utf-8", errors="replace")
    else:
        text = sys.stdin.read()
    print(f"CI-CLASS: {classify(text) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
