#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Rewrite scripts/qc-allowlists/pgbouncer-pool-mode-allow.txt from the tree (#4667, #4741).

The allowlist is a review surface, so this tool never changes it silently:

  * existing entries and their comments keep their order (no reordering);
  * a stale entry (fewer matching mentions than entries) is removed only with
    --drop-stale, and each removal is printed;
  * a mention that is neither approved nor listed is added only with
    --accept-new, appended at the end under a dated comment and each
    addition is printed. The reason comment above the new entries is the text
    given with --reason (checked by the gate: a sentence of at least six words,
    not the placeholder); without --reason it is the placeholder, which the gate
    rejects with rc 2, so this tool cannot turn a red line green on its own
    (#4961). Replace the placeholder with a real reason per entry group.

Without those flags the tool prints what it would change and exits 1, leaving
the file untouched. With --check it never writes. Exit codes: 0 the file already
matches the tree (or was rewritten as asked), 1 changes are pending and were
refused, 2 fault.

Usage:
    scripts/regen-pgbouncer-pool-mode-allow.py [--root DIR] [--check] [--accept-new [--reason TEXT]] [--drop-stale]
"""
import argparse
import datetime
import importlib.util
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_gate(root):
    path = root / "scripts" / "check-pgbouncer-pool-mode-claims.py"
    spec = importlib.util.spec_from_file_location("pool_mode_gate", str(path))
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return gate


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=str(HERE.parent))
    ap.add_argument("--check", action="store_true", help="report only; never write")
    ap.add_argument("--accept-new", action="store_true", help="append unlisted mentions (printed) for review")
    ap.add_argument("--drop-stale", action="store_true", help="remove stale entries (printed)")
    ap.add_argument("--reason", default="", help="the written reason for every line --accept-new adds")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve()
    gate = load_gate(root)
    reason = " ".join(a.reason.split())
    if reason:
        problem = gate.reason_problem(reason)
        if problem:
            print("regen: FAULT: --reason is not a reason: %s" % problem, file=sys.stderr)
            return 2
    allow_path = root / gate.ALLOW_REL
    try:
        raw = allow_path.read_text(encoding="utf-8")
    except OSError as exc:
        print("regen: FAULT: cannot read %s: %s" % (gate.ALLOW_REL, exc), file=sys.stderr)
        return 2
    entries, errors = gate.load_allowlist(root)
    if errors:
        for err in errors:
            print("regen: FAULT: %s" % err, file=sys.stderr)
        return 2
    units, read = gate.scan(root)
    if read == 0:
        print("regen: FAULT: empty scan", file=sys.stderr)
        return 2
    need = Counter((rel, text) for rel, _, text in units if not gate.approved(text))
    have = Counter(entries)
    stale = have - need
    new = need - have
    for (rel, text), n in sorted(stale.items()):
        print("STALE x%d: %s | %s" % (n, rel, text[:160]))
    for (rel, text), n in sorted(new.items()):
        print("NEW   x%d: %s | %s" % (n, rel, text[:160]))
    if not stale and not new:
        print("regen: allowlist matches the tree (%d entries)" % len(entries))
        return 0
    refused = (stale and not a.drop_stale) or (new and not a.accept_new)
    if a.check or refused:
        print("regen: %d stale, %d new; file left unchanged (%s)" % (
            sum(stale.values()), sum(new.values()),
            "--check" if a.check else "pass --drop-stale / --accept-new after reading each line above"))
        return 1
    out = []
    drop = Counter(stale)
    for line in raw.splitlines():
        if line.strip() and not line.lstrip().startswith("#") and gate.SEPARATOR in line:
            key = tuple(line.split(gate.SEPARATOR, 1))
            if drop[key] > 0:
                drop[key] -= 1
                continue
        out.append(line)
    if new:
        out += ["", "# added by regen-pgbouncer-pool-mode-allow.py --accept-new on %s:" % datetime.date.today().isoformat(),
                "# " + (reason or gate.PLACEHOLDER + " before review: say why each line below is safe")]
        for (rel, text), n in sorted(new.items()):
            out += ["%s%s%s" % (rel, gate.SEPARATOR, text)] * n
    tmp = allow_path.with_name(allow_path.name + ".regen")
    tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
    tmp.replace(allow_path)
    print("regen: removed %d, added %d; review the diff" % (sum(stale.values()), sum(new.values())))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
