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
It refuses to write anything while the allow or pending list has a form fault or a
pending entry that matches no triggered line (#5116), since such an entry no longer
keeps its line out of the allowlist.
Usage: regen-cloud-init-token-allow.py [--accept-new | --self-test] <repo-root>
"""
import argparse
import difflib
import importlib.util
import sys
from collections import Counter
from pathlib import Path


def pending_refusals(g, templates, allow, pend) -> list:
    """Reasons to refuse any rewrite (#5116). A pending entry excludes its line from the
    allowlist; one the gate drops as a form fault, or one that matches no triggered line,
    excludes nothing, so a rewrite would write that tracked line as approved."""
    faults = []
    g.register_credentials(allow)
    g.register_credentials(pend)
    g.load_entries(allow, False, faults, "allow")
    pe = g.load_entries(pend, True, faults, "pending")
    out = ["FAULT: " + g.mask_credentials(f) for f in faults]
    per = {}
    cache = {}
    for nm, text in sorted(templates.items()):
        _, _, _, trig, _ = g.analyse(nm, text, cache)
        per.setdefault(g.scope_of(nm), set()).update((ln.ctx, ln.text) for ln in trig)

    def live(e):
        # a 'both' entry must match a triggered line in every template, as the gate requires (#5116)
        k = (e[2], e[3])
        if e[0] == "both":
            return bool(per) and all(k in v for v in per.values())
        return k in per.get(e[0], set())

    out += ["STALE PENDING: %s %s | %s | %s" % (e[0], e[1], e[2], g.mask_credentials(e[3])) for e in pe if not live(e)]
    if out:
        out.append("refused: fix the allow or pending list first (%d problem(s)); nothing was written" % len(out))
    return out


def change_report(g, removed, added, changed, old_seq, new_seq) -> list:
    """The REMOVED, NEW and CHANGED lines the rewrite prints. Each carries template text, so
    each goes through g.scrub, and main() prints it through g.say: a template line that holds a password is shown with
    it masked (#5488). Credential text must be registered first (g.analyse does it)."""
    out = ["REMOVED: %s | %s | %s" % (k[0], k[1], g.mask_credentials(k[2])) for k in sorted(removed.elements())]
    out += ["NEW: %s | %s | %s" % (k[0], k[1], g.mask_credentials(k[2])) for k in sorted(added.elements())]
    for k in changed:
        out.append("CHANGED: %s | %s" % k)
        for d in difflib.unified_diff(old_seq.get(k, []), new_seq.get(k, []), lineterm="", n=0):
            if d[:1] in "+-" and not d.startswith(("+++", "---")):
                out.append("    " + g.mask_credentials(d))
    return out


def spelling_problems(g, templates, maintfs, allow, pend) -> list:
    """No credential spelling of g.CRED_SPELLINGS reaches the rewrite report or a stale pending
    line with a byte of the secret, and the report lists the added line (#5546-#5550)."""
    bad = []
    for cls, label, text in g.CRED_SPELLINGS:
        g.CRED_PIECES.clear()
        t, _, a, p, _, _ = g.spelling_templates((templates, maintfs, allow, pend), text)
        _, _, lines, _, _, _ = plan(g, t, a, p)
        shown = "\n".join(lines)
        stale = "\n".join(pending_refusals(g, t, a, p + "aws-gpu-burst #4671 | top | " + text.split("\n")[0] + "\n"))
        if "NEW:" not in shown:
            bad.append("%s %s: the rewrite report did not list the added line" % (cls, label))
        for what, out in (("the rewrite report", shown), ("a stale pending line", stale)):
            if any(n in out for n in g.CRED_NEEDLES):
                bad.append("%s %s: %s printed a byte of the password" % (cls, label, what))
    g.CRED_PIECES.clear()
    return bad


def self_test(g, templates, maintfs, allow, pend) -> int:
    """The clean lists give no refusal; a stale pending entry and an unknown tracker each do."""
    first = next(x for x in pend.splitlines() if x and not x.startswith("#"))
    head, rest = first.split(" | ", 1)
    cases = [
        ("clean lists", pend, False),
        ("stale pending entry", pend.replace(first, head + " | top | nothing-matches:", 1), True),
        ("pending entry under an unknown tracker", pend.replace(first, head.split(" ")[0] + " #1 | " + rest, 1), True),
        ("both-scope pending entry that one template lacks", pend.replace(first, "both " + head.split(" ", 1)[1] + " | " + rest, 1), True),
    ]
    bad = [lbl for lbl, p, want in cases if bool(pending_refusals(g, templates, allow, p)) != want]
    # a stale pending line and a changed line that hold a password print it masked (#5488)
    leak = "postgres://aimemory:Aq7Zk'Bq7Zk@h/x"
    stale = pend.replace(first, head + " | top | " + leak, 1)
    shown = "\n".join(pending_refusals(g, templates, allow, stale))
    if "Bq7Zk" in shown or "STALE PENDING" not in shown:
        bad.append("a stale pending line printed a password, or was not refused")
    g.register_credentials(leak)
    key = ("aws-gpu-burst", "top", leak)
    rep_lines = "\n".join(change_report(g, Counter([key]), Counter([key]), [("aws-gpu-burst", "top")],
                                         {("aws-gpu-burst", "top"): [leak]}, {("aws-gpu-burst", "top"): ["+" + leak]}))
    if "Bq7Zk" in rep_lines or rep_lines.count("REMOVED") != 1 or rep_lines.count("NEW") != 1 or "CHANGED" not in rep_lines:
        bad.append("the rewrite report printed a password, or lost a line")
    bad.extend(spelling_problems(g, templates, maintfs, allow, pend))
    bad.extend(g.print_funnel_problems((g.__file__, __file__)))
    for lbl in bad:
        print("REGEN SELF-TEST FAIL: " + lbl, file=sys.stderr)
    if not bad:
        print("REGEN SELF-TEST PASS: %d cases, %d credential spellings kept off the report" % (len(cases), len(g.CRED_SPELLINGS)))
    return 1 if bad else 0


def plan(g, templates, allow, pend):
    """The rewrite: (entries to write, existing entries, report lines, changed sequences, added, removed).
    It reads and writes no file; main() was split so the report can be pinned (#5549)."""
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
    def seqs_of(entries):
        s = {}
        for sc, ctx, text in entries:
            for t in (("aws-gpu-burst", "do-hive") if sc == "both" else (sc,)):
                s.setdefault((t, ctx), []).append(text)
        return s

    old_seq = seqs_of((e[0], e[2], e[3]) for e in old)
    new_seq = seqs_of(out)
    changed = [k for k in sorted(set(old_seq) | set(new_seq)) if old_seq.get(k, []) != new_seq.get(k, [])]
    lines = change_report(g, removed, added, changed, old_seq, new_seq)
    return out, old, lines, changed, added, removed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--accept-new", action="store_true",
                    help="write added, removed or reordered lines (each change is printed)")
    ap.add_argument("--self-test", action="store_true",
                    help="check that a stale or faulty pending entry refuses a rewrite (#5116)")
    a = ap.parse_args()
    root = Path(a.root)
    spec = importlib.util.spec_from_file_location("g", str(root / "scripts/check-cloud-init-serve-flags.py"))
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    templates, maintfs, allow, pend = g.load_repo()
    if a.self_test:
        return self_test(g, templates, maintfs, allow, pend)
    refusals = pending_refusals(g, templates, allow, pend)
    if refusals:
        print("\n".join(refusals), file=sys.stderr)
        return 1
    out, old, lines, changed, added, removed = plan(g, templates, allow, pend)
    if lines:
        print("\n".join(lines))
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
