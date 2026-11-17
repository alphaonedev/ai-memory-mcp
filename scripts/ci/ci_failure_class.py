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


def _load_workflow_annotation():
    """The shared module at WA_RELATIVE_PATH from this file's real directory, by path only, never through
    sys.path; every name in WA_REQUIRED must be a callable of it (#9365, one shape in every script)."""
    import importlib.util
    import os
    path = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), WA_RELATIVE_PATH))
    loaded = sys.modules.get("workflow_annotation")
    if loaded is not None and os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
        module = loaded
    else:
        spec = importlib.util.spec_from_file_location("workflow_annotation", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # absent, unreadable or broken: it raises here, the try below catches it
    missing = [name for name in WA_REQUIRED if not callable(getattr(module, name, None))]
    if missing:
        raise AttributeError("workflow_annotation.py lacks " + ", ".join(missing))
    if loaded is None:
        sys.modules["workflow_annotation"] = module
    return module


# The one shared-module load shape of scripts/ (#9365, ruling bcd0a15c; LoaderShape pins it).
WA_PROG = "ci_failure_class"
WA_RELATIVE_PATH = "workflow_annotation.py"
WA_REQUIRED = ("out",)
WA_EXIT_LOAD_REFUSED = 3  # a failed shared-module load; no other meaning in this script
WA_ERROR_TO_STDERR = False

try:
    wa = _load_workflow_annotation()
except (Exception, SystemExit) as exc:  # any failed load: one fixed line built without the module, then exit
    wa_cause = type(exc).__name__
    print("%s: refused: shared module workflow_annotation.py next to the script cannot be loaded (%s)"
          % (WA_PROG, wa_cause if wa_cause.isidentifier() else "BaseException"), file=sys.stderr, flush=True)
    print("::error title=ci_failure_class refused::ci_failure_class: refused: shared module workflow_annotation.py"
          " next to the script cannot be loaded",
          file=sys.stderr if WA_ERROR_TO_STDERR else sys.stdout, flush=True)
    sys.exit(WA_EXIT_LOAD_REFUSED)

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
    wa.out(f"CI-CLASS: {classify(text) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
