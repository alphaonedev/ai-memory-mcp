#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""CI failure classifier for annotation lines (issue #9235).

`jev_ci_class` maps a CI log to a class.  This module owns the mapping for
the hosted-runner PostgreSQL preflight annotation emitted by
`scripts/ci/pg_env_preflight.py`:

    ::error::[coverage-pg] PG-ENV <reason>   ->   ci-env

The host-slot wait annotation of `scripts/ci/host_semaphore.py` (#9231),
`::error title=infra\x3a no slot::...`, maps to infra-no-slot.

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


CLASS_INFRA_NO_SLOT = "infra-no-slot"

# #9231: scripts/ci/host_semaphore.py ends a wait without a slot with one annotation
#   ::error title=infra%3A no slot::<message>      (workflow_annotation writes the colon as \x3a; %3A and a bare colon also match)
# and exit code 75; no test ran, the class is infrastructure, never a test failure.
NO_SLOT_LINE = re.compile(r"(?m)(?:^|\s)::error title=infra(?:%3[Aa]|\\x3[Aa]|:) no slot::[^\s]")


def classify(log_text: str) -> str | None:
    """Return the CI class for the log text, or None when no rule matches."""
    if PG_ENV_LINE.search(log_text):
        return CLASS_CI_ENV
    if NO_SLOT_LINE.search(log_text):
        return CLASS_INFRA_NO_SLOT
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
