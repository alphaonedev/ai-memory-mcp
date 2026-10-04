#!/usr/bin/env python3
"""Rewrite cloud-init-token-allow.txt in template order (#4784; PR #4655 round 4).

Keeps the header comments, keeps every existing 'both' choice where the two
templates agree on order, lists a repeated line once per occurrence, lists each
Terraform directive region (context tf-region) after the triggered lines, and
skips lines that the pending list covers. By default it writes nothing that
changes what is approved: any added, removed or reordered line in any
(template, context) sequence is printed and the file is left unchanged, unless
--accept-new is given, and then every change is printed so the approval is
named in the run output as well as in the diff.
Usage: regen-cloud-init-token-allow.py [--accept-new] <repo-root>
"""
import argparse
import difflib
import importlib.util
import sys
from collections import Counter
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--accept-new", action="store_true",
                    help="write added, removed or reordered lines (each change is printed)")
    a = ap.parse_args()
    root = Path(a.root)
    spec = importlib.util.spec_from_file_location("g", str(root / "scripts/check-cloud-init-serve-flags.py"))
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    templates, _, allow, pend = g.load_repo()
    faults = []
    old = g.load_entries(allow, False, faults, "allow")
    pe = g.load_entries(pend, True, faults, "pending")
    both = {(e[2], e[3]) for e in old if e[0] == "both"}
    pend_keys = {(e[0], e[2], e[3]) for e in pe}
    cache = {}
    seqs = {}
    for nm, text in sorted(templates.items()):
        sc = g.scope_of(nm)
        _, _, _, trig, _ = g.analyse(nm, text, cache)
        seqs[sc] = [(ln.ctx, ln.text) for ln in trig
                    if (sc, ln.ctx, ln.text) not in pend_keys and ("both", ln.ctx, ln.text) not in pend_keys]
        seqs[sc] += [("tf-region", reg) for reg in g.tf_regions(text)]
    A, D = seqs["aws-gpu-burst"], seqs["do-hive"]
    n, m = len(A), len(D)
    L = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            if A[i] == D[j] and A[i] in both:
                L[i][j] = L[i + 1][j + 1] + 1
            else:
                L[i][j] = max(L[i + 1][j], L[i][j + 1])
    out, i, j = [], 0, 0
    while i < n or j < m:
        if i < n and j < m and A[i] == D[j] and A[i] in both and L[i][j] == L[i + 1][j + 1] + 1:
            out.append(("both",) + A[i])
            i += 1
            j += 1
        elif j >= m or (i < n and L[i + 1][j] >= L[i][j + 1]):
            out.append(("aws-gpu-burst",) + A[i])
            i += 1
        else:
            out.append(("do-hive",) + D[j])
            j += 1
    def per_scope(entries):
        c = Counter()
        for sc, ctx, text in entries:
            for s in (("aws-gpu-burst", "do-hive") if sc == "both" else (sc,)):
                c[(s, ctx, text)] += 1
        return c

    was = per_scope((e[0], e[2], e[3]) for e in old)
    now = per_scope(out)
    added, removed = now - was, was - now
    for k in sorted(removed.elements()):
        print("REMOVED: %s | %s | %s" % k)
    for k in sorted(added.elements()):
        print("NEW: %s | %s | %s" % k)

    def seqs_of(entries):
        s = {}
        for sc, ctx, text in entries:
            for t in (("aws-gpu-burst", "do-hive") if sc == "both" else (sc,)):
                s.setdefault((t, ctx), []).append(text)
        return s

    old_seq = seqs_of((e[0], e[2], e[3]) for e in old)
    new_seq = seqs_of(out)
    changed = [k for k in sorted(set(old_seq) | set(new_seq)) if old_seq.get(k, []) != new_seq.get(k, [])]
    for k in changed:
        print("CHANGED: %s | %s" % k)
        for d in difflib.unified_diff(old_seq.get(k, []), new_seq.get(k, []), lineterm="", n=0):
            if d[:1] in "+-" and not d.startswith(("+++", "---")):
                print("    " + d)
    if changed and not a.accept_new:
        print("refused: %d approved sequence(s) changed (%d line(s) added, %d removed); review them, "
              "then rerun with --accept-new" % (len(changed), sum(added.values()), sum(removed.values())),
              file=sys.stderr)
        return 1
    head = [x for x in allow.splitlines() if x.startswith("#")]
    head = head[:next((k for k, x in enumerate(allow.splitlines()) if x and not x.startswith("#")), len(head))]
    body = ["%s | %s | %s" % e for e in out]
    (root / "scripts/qc-allowlists/cloud-init-token-allow.txt").write_text("\n".join(head + body) + "\n", encoding="utf-8")
    print("entries %d (was %d), both %d" % (len(body), len(old), sum(1 for e in out if e[0] == "both")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
