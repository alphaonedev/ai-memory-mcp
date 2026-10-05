#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Rewrite scripts/qc-allowlists/argv-secrets-operand-allow.txt (#5722, PR 4810 round 11).

5-agent vote (4d3ea1c5), decision eda8d8fb: scripts/check-docs-no-argv-secrets.py flags a
credential-shaped operand under a head it does not model (an unknown program), or in a
bash array body (#5723). The only exemption is a reviewed line in the allowlist, keyed by
file, class and the sha256 of the whole command text, never a program name. This script is
the only writer of that file.

By default it only deletes and reorders: an entry that no longer matches a hit is removed,
the rest are written in tree order (file, then line), and a hit with no entry is printed as
NEW and refused (exit 1) without being added. --accept-new also writes the NEW entries, each
printed so the approval is named in the run output as well as in the diff. --check writes
nothing and exits 1 when a rewrite would change the file or a NEW entry is pending. A file
with a form fault is never rewritten (exit 2). --self-test runs the planner on fixed cases.

F1 (round 12): a hit whose flagged operand value is literal (operand_value_kind in the gate:
neither an expansion nor a placeholder) is never written, even with --accept-new. It is
printed as REFUSED-LITERAL with its file, class, hash, value kind and masked preview, the run
exits 1 in every mode, and the fix is to move the value out of the command line.
The design copies scripts/regen-cloud-init-token-allow.py.

Usage: regen-argv-secrets-allow.py [--accept-new | --check | --self-test] [<repo-root>]
"""
import argparse
import importlib.util
import sys
from collections import Counter
from pathlib import Path

HEADER = [
    "# Reviewed lines exempt from the unknown-head credential-operand rule of",
    "# scripts/check-docs-no-argv-secrets.py (#5722, 5-agent vote (4d3ea1c5)).",
    "# Written ONLY by scripts/regen-argv-secrets-allow.py; adding an entry needs --accept-new.",
    "# Format: path | class | sha256 of the whole command (32 hex) | value kind | masked preview.",
    "# A literal value is never written: the regen script refuses it by name (F1, round 12).",
    "# An entry claims one hit; any edit of the command changes its hash and voids the entry.",
]


def load_gate(root: Path):
    spec = importlib.util.spec_from_file_location("argv_gate", str(root / "scripts/check-docs-no-argv-secrets.py"))
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    return g


def render(header, keys) -> str:
    return "\n".join(list(header) + ["%s | %s | %s | %s | %s" % k for k in keys]) + "\n"


def refused_lines(refused) -> list:
    """F1 (round 12): one named refusal per literal-valued hit; the preview is masked."""
    return ["REFUSED-LITERAL: %s | %s | %s | %s | %s" % k for k in refused]


def plan(g, old_text: str, now, accept: bool):
    """(new text or None on a fault, report lines, NEW count). now: the waivable keys of the
    tree's hits in tree order. Without accept, only entries that still match are kept."""
    entries, faults = g.load_allow(old_text)
    if faults:
        return None, ["FAULT: " + f for f in faults], 0
    header = [x for x in old_text.splitlines() if x.startswith("#")] or HEADER
    have = Counter(entries)
    want = Counter(now)
    removed = have - want
    added = want - have
    keep = Counter(have)
    out = []
    for k in now:
        if accept or keep[k] > 0:
            out.append(k)
            keep[k] -= 1
    lines = ["REMOVED: %s | %s | %s | %s | %s" % k for k in sorted(removed.elements())]
    lines += ["NEW: %s | %s | %s | %s | %s" % k for k in sorted(added.elements())]
    return render(header, out), lines, sum(added.values())


def self_test(g) -> int:
    """Fixed cases for plan(); the keys are synthetic and hold no credential."""
    a = ("docs/a.md", g.UNKNOWN_TAG, "a" * 32, g.VALUE_EXPANSION, "tool -v n=*")
    b = ("docs/b.md", g.UNKNOWN_TAG, "b" * 32, g.VALUE_NONE, "tool -v m=*")
    c = ("scripts/c.sh", g.UNKNOWN_TAG, "c" * 32, g.VALUE_PLACEHOLDER, "tool --set k=*")
    d = ("scripts/d.sh", g.ARRAY_TAG, "d" * 32, g.VALUE_EXPANSION, "-v k=*")
    base = render(HEADER, [a, b])
    cases = [
        # label, old text, tree keys, accept, want text keys (None: fault), want NEW count
        ("clean file is unchanged", base, [a, b], False, [a, b], 0),
        ("stale entry is deleted", render(HEADER, [a, b, c]), [a, b], False, [a, b], 0),
        ("new entry is refused without accept", base, [a, b, c], False, [a, b], 1),
        ("new entry is written with accept", base, [a, b, c], True, [a, b, c], 1),
        ("entries are reordered to tree order", render(HEADER, [b, a]), [a, b], False, [a, b], 0),
        ("a duplicate hit needs its own entry", render(HEADER, [a]), [a, a], False, [a], 1),
        ("a duplicate entry with one hit is deleted", render(HEADER, [a, a]), [a], False, [a], 0),
        ("malformed line refuses any rewrite", base + "tool\n", [a, b], True, None, 0),
        ("unmasked preview refuses any rewrite", base.replace("n=*", "n=hunter2"), [a, b], True, None, 0),
        ("non-waivable class refuses any rewrite", base.replace(g.UNKNOWN_TAG, "env-password-argv", 1),
         [a, b], True, None, 0),
        ("missing file starts from the header", "", [a], True, [a], 1),
        ("an array-body entry is a waivable class", render(HEADER, [a, d]), [a, d], False, [a, d], 0),
        # F1 (round 12): a literal value kind in the file refuses any rewrite.
        ("a literal value entry refuses any rewrite", base.replace(g.VALUE_EXPANSION, g.VALUE_LITERAL, 1),
         [a, b], True, None, 0),
        ("an unknown value kind refuses any rewrite", base.replace(g.VALUE_EXPANSION, "secret", 1),
         [a, b], True, None, 0),
    ]
    bad = 0
    for label, old, now, accept, want, want_new in cases:
        text, lines, n_new = plan(g, old, now, accept)
        ok = (text is None) if want is None else (text == render(
            [x for x in old.splitlines() if x.startswith("#")] or HEADER, want) and n_new == want_new)
        if want is not None and any("hunter2" in x for x in lines):
            ok = False
        if not ok:
            print("REGEN SELF-TEST FAIL: %s: %r %r %r" % (label, text, lines, n_new), file=sys.stderr)
            bad += 1
    bad += literal_self_test(g)
    if not bad:
        print("REGEN SELF-TEST PASS: %d cases, %d literal-refusal probes" % (len(cases), len(LITERAL_PROBES)))
    return 1 if bad else 0


# F1 (round 12): fake literal values only. Each probe must reach the gate as a waivable-class
# hit with a literal value: no allowlist key, a REFUSED-LITERAL line that names it, and neither
# that line nor the hit text carries the value.
# The probes spell the operand name as N@ and the value as V@ and are assembled at run time, so
# this file's own text carries no credential-shaped operand for the gate to flag.
FAKE_VALUE = "hunter2" + "LIVE"
LITERAL_PROBES = [
    ("probe.sh", "mytool --set N@=V@\n", "api_key"),
    ("probe.sh", "mytool -v N@='V@'\n", "pw"),
    ("probe.sh", 'mytool -v N@="V@"\n', "pw"),
    ("probe.sh", "mytool -v N@=V@$X\n", "pw"),
    ("probe.sh", "args=(-v N@=\"V@\")\nmytool \"${args[@]}\"\n", "pw"),
    ("probe.md", "```bash\nmytool --variable=N@=V@\n```\n", "token"),
    ("probe.sh", "mytool -v V@N@\n", "_token"),
]
# The same commands with an expansion or a placeholder value stay waivable.
WAIVABLE_PROBES = [
    ("probe.sh", 'mytool --set N@="$KEY"\n', "api_key", "expansion"),
    ("probe.sh", "mytool -v N@=${PW}\n", "pw", "expansion"),
    ("probe.sh", "mytool -v N@='<password>'\n", "pw", "placeholder"),
    ("probe.sh", "mytool -v N@=xxxx\n", "pw", "placeholder"),
    ("probe.sh", "mytool -v ${X}N@\n", "_token", "expansion"),
]


def probe_body(body: str, name: str) -> str:
    return body.replace("N@", name).replace("V@", FAKE_VALUE)


def literal_self_test(g) -> int:
    bad = 0
    for rel, spelled, name in LITERAL_PROBES:
        body = probe_body(spelled, name)
        hits = g.scan_text(rel, body)
        refused = [k for k in (g.literal_waivable_key(h) for h in hits) if k is not None]
        keys = [k for k in (g.waivable_key(h) for h in hits) if k is not None]
        text, _lines, _n = plan(g, render(HEADER, []), keys, True)
        named = refused_lines(refused)
        if (len(refused) != 1 or keys or text != render(HEADER, []) or not named[0].startswith(
                "REFUSED-LITERAL: %s | " % rel) or "| literal |" not in named[0]
                or any(FAKE_VALUE in x for x in named + [h[2] for h in hits])):
            print("REGEN SELF-TEST FAIL: literal probe %r: hits %r refused %r" % (body, hits, named),
                  file=sys.stderr)
            bad += 1
    for rel, spelled, name, kind in WAIVABLE_PROBES:
        body = probe_body(spelled, name)
        keys = [k for k in (g.waivable_key(h) for h in g.scan_text(rel, body)) if k is not None]
        if len(keys) != 1 or keys[0][3] != kind:
            print("REGEN SELF-TEST FAIL: waivable probe %r: keys %r (want kind %s)" % (body, keys, kind),
                  file=sys.stderr)
            bad += 1
    return bad


def tree_keys(g):
    """(waivable keys, literal-valued keys refused by name, files scanned) in tree order."""
    hits, scanned = g.scan_paths(g.ROOT, g.tracked_files())
    hits, _listed, _stale = g.split_pending(g.ROOT, hits)
    keys = [k for k in (g.waivable_key(h) for h in hits) if k is not None]
    refused = [k for k in (g.literal_waivable_key(h) for h in hits) if k is not None]
    return keys, refused, scanned


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--accept-new", action="store_true", help="also write NEW entries (each is printed)")
    mode.add_argument("--check", action="store_true", help="write nothing; exit 1 if a rewrite or a NEW entry is pending")
    mode.add_argument("--self-test", action="store_true", help="run the planner on fixed cases")
    ap.add_argument("root", nargs="?", default=str(Path(__file__).resolve().parent.parent))
    a = ap.parse_args(argv[1:])
    root = Path(a.root).resolve()
    g = load_gate(root)
    if a.self_test:
        return self_test(g)
    path = root / g.ALLOW_REL
    old = path.read_text(encoding="utf-8") if path.is_file() else ""
    try:
        now, refused, scanned = tree_keys(g)
    except (RuntimeError, OSError, UnicodeDecodeError) as exc:
        print("FAIL: regen-argv-secrets-allow: scanner fault: %s" % exc, file=sys.stderr)
        return 2
    text, lines, n_new = plan(g, old, now, a.accept_new)
    lines += refused_lines(refused)
    if lines:
        print("\n".join(lines))
    if text is None:
        print("refused: fix the allowlist form first; nothing was written", file=sys.stderr)
        return 2
    if refused:
        # F1 (round 12): a literal value is never written, in any mode; the rest of the file
        # is still rewritten (outside --check) so a stale entry never outlives its line.
        if text != old and not a.check:
            path.write_text(text, encoding="utf-8")
        print("refused: %d literal value(s) named above are never allowlisted; move each value out of"
              " the command line (an environment variable, a file, or a placeholder)" % len(refused),
              file=sys.stderr)
        return 1
    if a.check:
        if text != old or n_new:
            print("FAIL: regen-argv-secrets-allow --check: %s would change (%d NEW pending)" % (g.ALLOW_REL, n_new),
                  file=sys.stderr)
            return 1
        print("PASS: regen-argv-secrets-allow --check: %d files scanned, %d entries, no change"
              % (scanned, len(now)))
        return 0
    if text != old:
        path.write_text(text, encoding="utf-8")
    if n_new and not a.accept_new:
        print("refused: %d NEW entr(ies) not written; review each line, then rerun with --accept-new" % n_new,
              file=sys.stderr)
        return 1
    print("entries %d (was %d)" % (len(now), len(g.load_allow(old)[0])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
