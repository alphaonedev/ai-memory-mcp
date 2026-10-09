#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Compliance-document script-name anchor gate (#6141).

The adopted certification texts under ``docs/compliance/`` are verbatim copies
of a reviewed source and cannot be edited in place, so a script rename leaves
the normative text naming a file that no longer exists (#6137 ported
``check-cert-expiry.sh`` to ``check_cert_expiry.py``; #6141).

Rule: every backticked ``check-*.sh`` / ``check_*.py`` script name in a
``docs/compliance/*.md`` file must resolve to a file under ``scripts/``,
unless an erratum line somewhere in ``docs/compliance/`` names it together
with an existing successor path (``scripts/<name>``). An erratum line is a
single line containing the word "erratum", the stale name in backticks, and
the successor in backticks.

Usage:
    python3 -I scripts/check_compliance_script_names.py [--root DIR]
    python3 -I scripts/check_compliance_script_names.py --self-test

Exit codes: 0 green, 1 violation(s) found, 2 usage or self-test failure.
"""

import argparse
import re
import sys
import tempfile
from pathlib import Path

TOKEN_RE = re.compile(r"`((?:scripts/)?check[-_][A-Za-z0-9_-]+\.(?:sh|py))`")
SUCCESSOR_RE = re.compile(r"`scripts/([A-Za-z0-9_./-]+\.(?:sh|py))`")


def scripts_exist(root, name):
    """True when ``name`` (bare or ``scripts/``-prefixed) is a file in scripts/."""
    base = name[len("scripts/"):] if name.startswith("scripts/") else name
    return any(p.is_file() and p.name == base for p in (root / "scripts").rglob(base))


def compliance_docs(root):
    return sorted((root / "docs" / "compliance").rglob("*.md"))


def collect_errata(root, docs):
    """Map stale bare script name -> successor path, from erratum lines."""
    errata = {}
    for doc in docs:
        for line in doc.read_text(encoding="utf-8").splitlines():
            if "erratum" not in line.lower():
                continue
            succ = [s for s in SUCCESSOR_RE.findall(line) if (root / "scripts" / s).is_file()]
            if not succ:
                continue
            for tok in TOKEN_RE.findall(line):
                base = tok[len("scripts/"):] if tok.startswith("scripts/") else tok
                if base not in succ:
                    errata[base] = succ[0]
    return errata


def check(root):
    """Return a list of violation strings for the tree at ``root``."""
    docs = compliance_docs(root)
    errata = collect_errata(root, docs)
    problems = []
    for doc in docs:
        rel = doc.relative_to(root)
        for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            for tok in TOKEN_RE.findall(line):
                if scripts_exist(root, tok):
                    continue
                base = tok[len("scripts/"):] if tok.startswith("scripts/") else tok
                if base in errata:
                    continue
                problems.append(
                    "%s:%d: `%s` does not exist under scripts/ and no erratum names its successor"
                    % (rel, lineno, tok)
                )
    return problems


def self_test():
    scratch = Path(__file__).resolve().parent.parent / ".local-runs"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(scratch)) as d:
        root = Path(d)
        (root / "scripts").mkdir()
        (root / "docs" / "compliance").mkdir(parents=True)
        (root / "scripts" / "check_new.py").write_text("")
        doc = root / "docs" / "compliance" / "A.md"
        doc.write_text("N30 enforcer is `check-old.sh`.\n")
        if not check(root):
            return "stale name without erratum was accepted"
        doc.write_text("N30 enforcer is `check-old.sh`.\nErratum: `check-old.sh` is `scripts/check_new.py`.\n")
        if check(root):
            return "stale name with erratum was rejected"
        doc.write_text("Erratum: `check-old.sh` is `scripts/check_missing.py`.\n")
        if not check(root):
            return "erratum naming a missing successor was accepted"
        doc.write_text("See `check_new.py` and `scripts/check_new.py`.\n")
        if check(root):
            return "resolving names were rejected"
    return None


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        err = self_test()
        if err:
            print("SELF-TEST FAIL: " + err, file=sys.stderr)
            return 2
        print("self-test ok")
        return 0
    problems = check(Path(args.root))
    for p in problems:
        print("FAIL " + p, file=sys.stderr)
    if problems:
        return 1
    print("compliance script-name anchors ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
