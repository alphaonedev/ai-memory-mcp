#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Maintain scripts/qc-allowlists/exec-secret-argv-allow.txt and -pending.txt.

The lists are the approval record of the closed-world gate scripts/check-exec-secret-argv.py
(precedent 19497ef6, fail-closed allowlist gate). This tool is built so that it cannot
launder a finding into the allowlist:

  * DEFAULT MODE writes nothing that adds or deletes an entry. A triggered line that is
    not listed makes the run fail (exit 1) and prints it as file:line with its text.
  * A STALE entry (the line is gone or occurs fewer times than the entry's count) makes the
    default run fail (exit 1). ``--prune`` deletes stale entries and lowers counts; that is
    the only way an entry is removed or reduced, and it can never add.
  * ADDING needs ``--accept-new --why <#issue | reason: text>``. Each addition is printed as
    file:line and its text. ``--why`` is required and must be an issue number or a reason, so
    every entry says why it was accepted.
  * It REFUSES to add to the allowlist a pending line (same text, even under a renamed file), a
    line the prose rules flag, and a line the imported denylist rules flag
    (check-docs-no-argv-secrets.py), and any prose line (prose is never approved). A flagged
    or prose line can only go to the pending list: ``--accept-new --pending --why #<issue>``
    (a pending entry needs an issue number or a reason line, never an approval).
  * It is idempotent: a second run on its own output changes nothing.

The cloud-init regen script this replaces nothing of lacks a guard of this kind (#4831); this
one checks every refusal with ``refusal_cases`` from the gate's ``--self-test``.

Usage:
  scripts/regen-exec-secret-argv-allow.py                 reorder; exit 1 on a new or stale line
  scripts/regen-exec-secret-argv-allow.py --prune         also delete stale entries
  scripts/regen-exec-secret-argv-allow.py --accept-new --why 'reason: text'
  scripts/regen-exec-secret-argv-allow.py --accept-new --pending --why '#1234'
  scripts/regen-exec-secret-argv-allow.py --check         exit 1 if the files would change
"""
import argparse
import importlib.util
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
ALLOW_HEAD = """# Allowlist of the closed-world argv-secret gate scripts/check-exec-secret-argv.py.
# Form:  <why> | <file> | <count> | <normalised logical line>
# <why> is '#<issue>' or 'reason: <text>'. Keyed by file, line text and count, never by line
# number. Every executable-file line that names a secret-like thing must be listed here or
# in exec-secret-argv-pending.txt; an unknown line is red. Edit with
# scripts/regen-exec-secret-argv-allow.py only: additions need --accept-new and a --why.
"""
PENDING_HEAD = """# Lines that put a credential on an argv TODAY, each tied to the issue that fixes it. The gate
# prints them and passes; the entry is deleted in the PR that fixes the line (a stale entry is
# red). Form:  <#issue | reason: text> | <file> | <count> | <normalised logical line>
# Prose (markdown fences, html pre blocks) can only be pending, never allowed.
"""
Entry = Tuple[str, str, int, str, int]


def load_gate(root: Path):
    spec = importlib.util.spec_from_file_location("gate_exec", str(root / "scripts/check-exec-secret-argv.py"))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the gate")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def foreign_comments(head: str, text: str) -> List[str]:
    """Comment lines of an existing list file that render() would drop (#4902)."""
    keep = set(head.splitlines())
    return [ln for ln in text.splitlines() if ln.lstrip().startswith("#") and ln not in keep]


def render(head: str, entries: List[Entry]) -> str:
    rows = sorted(entries, key=lambda e: (e[1], e[3]))
    return head + "".join("%s | %s | %d | %s\n" % (e[0], e[1], e[2], e[3]) for e in rows)


def is_prose(rel: str) -> bool:
    return rel.lower().endswith((".md", ".html", ".htm"))


def plan(gate, found, allow: List[Entry], pend: List[Entry], accept_new: bool, pending: bool,
         why: Optional[str], prune: bool, match: Optional[str] = None, dl=None) -> Tuple[int, List[Entry], List[Entry], List[str]]:
    """Pure core. Returns (exit code, new allow, new pending, messages)."""
    msgs: List[str] = []
    if accept_new and (why is None or not (gate.PEND_WHY_RE if pending else gate.WHY_RE).match(why)):
        return 2, allow, pend, ["--accept-new needs --why '#<issue>' (pending: an issue number only) or --why 'reason: <text>'"]
    if pending and not accept_new:
        return 2, allow, pend, ["--pending only works with --accept-new"]
    amap: Dict[Tuple[str, str], Entry] = {(e[1], e[3]): e for e in allow}
    pmap: Dict[Tuple[str, str], Entry] = {(e[1], e[3]): e for e in pend}
    pend_texts = {e[3] for e in pend}
    rc = 0
    occ: Dict[Tuple[str, str], list] = {}
    for rel, lines in found.items():
        for ln in lines:
            occ.setdefault((rel, ln[1]), []).append(ln)
    # stale handling
    for key in list(amap) + list(pmap):
        e = amap.get(key) or pmap[key]
        have = len(occ.get(key, []))
        listed = e[2]
        if key in amap and key in pmap:
            continue
        if have < listed:
            if prune:
                tgt = amap if key in amap else pmap
                if have == 0:
                    del tgt[key]
                else:
                    tgt[key] = (e[0], e[1], have, e[3], e[4])
                msgs.append("pruned %s:%d -> %d: %s" % (e[1], listed, have, e[3][:80]))
            else:
                rc = 1
                msgs.append("STALE entry (file has %d of %d): %s | %s" % (have, listed, e[1], e[3][:80]))
    # new lines
    if accept_new and match is None:
        fresh = [k for k, v in occ.items() if len(v) > (amap[k][2] if k in amap else 0) + (pmap[k][2] if k in pmap else 0)]
        if len(fresh) > 1:
            return 2, allow, pend, ["--accept-new would take %d new keys at once; pass --match <regex> so each "
                                    "addition is chosen (#4921)" % len(fresh)]
    for key, lines in sorted(occ.items()):
        rel, text = key
        listed = (amap[key][2] if key in amap else 0) + (pmap[key][2] if key in pmap else 0)
        if len(lines) <= listed:
            continue
        if match is not None and not re.search(match, rel + " " + text):
            continue
        extra = lines[listed:]
        for ln in extra:
            if not accept_new:
                rc = 1
                msgs.append("NEW %s:%d: %s" % (rel, ln[0], text[:160]))
        if not accept_new:
            continue
        flagged = any("denylist" in ln[2] for ln in extra)
        if not pending and (flagged or is_prose(rel)):
            rc = 1
            msgs.append("REFUSED %s:%d: %s line cannot be allowed (pending only): %s" % (
                rel, extra[0][0], "denylist-flagged" if flagged else "prose", text[:120]))
            continue
        if not pending:
            # #4902: an allow addition may not launder a pending line (same key, same text under a
            # renamed file, even one pruned in this run) and may not hold a line the prose rules flag.
            if key in pmap or text in pend_texts:
                rc = 1
                msgs.append("REFUSED %s:%d: the line is pending (or was, under another file); an allow entry "
                            "cannot replace a pending one: %s" % (rel, extra[0][0], text[:120]))
                continue
            hits = gate.prose_rule_hits(dl, text)
            if hits:
                rc = 1
                msgs.append("REFUSED %s:%d: the prose rules flag this line (%s); it can only be pending: %s" % (
                    rel, extra[0][0], ",".join(hits[:3]), text[:120]))
                continue
        tgt = pmap if pending else amap
        if key in tgt:
            e = tgt[key]
            tgt[key] = (why or e[0], e[1], e[2] + len(extra), e[3], e[4])
            msgs.append("BUMP %s %s: %d -> %d, reason now %r (was %r)" % (
                "pending" if pending else "allow", rel, e[2], e[2] + len(extra), why, e[0]))
        else:
            tgt[key] = (why or "", rel, len(extra), text, 0)
        for ln in extra:
            msgs.append("ADDED %s %s:%d: %s" % ("pending" if pending else "allow", rel, ln[0], text[:160]))
    return rc, list(amap.values()), list(pmap.values()), msgs


# ---------------------------------------------------------------- refusal cases
REFUSAL_CASE_COUNT = 15


def _f(gate, rel: str, line: str, flagged: bool = False):
    return {rel: [(3, gate.norm(line), ["assign:PW"] + (["denylist"] if flagged else []))]}


def refusal_cases(root: Path) -> List[str]:
    gate = load_gate(root)
    dl = gate.load_denylist(root)
    bad: List[str] = []
    a_line = 'MYSQL_PWD="$PW" mysql db'
    base = _f(gate, "x.sh", a_line)
    allowed: List[Entry] = [("reason: r", "x.sh", 1, gate.norm(a_line), 1)]

    rc, na, _np, _m = plan(gate, base, [], [], False, False, None, False, None, dl)
    if rc != 1 or na:
        bad.append("regen: default mode added or accepted an unlisted line")
    rc, *_ = plan(gate, base, [], [], True, False, None, False, None, dl)
    if rc != 2:
        bad.append("regen: --accept-new without --why was accepted")
    rc, *_ = plan(gate, base, [], [], True, False, "because", False, None, dl)
    if rc != 2:
        bad.append("regen: a free-text --why without 'reason:' was accepted")
    rc, na, _np, _m = plan(gate, _f(gate, "x.sh", 'curl -u a:$B h', True), [], [], True, False, "reason: r", False, None, dl)
    if rc != 1 or na:
        bad.append("regen: a denylist-flagged line was added to the allowlist")
    rc, na, _np, _m = plan(gate, _f(gate, "d.md", "mysql -p$PW db"), [], [], True, False, "reason: r", False, None, dl)
    if rc != 1 or na:
        bad.append("regen: a prose line was added to the allowlist")
    rc, na, _np, _m = plan(gate, {}, allowed, [], False, False, None, False, None, dl)
    if rc != 1 or not na:
        bad.append("regen: a stale entry did not fail the default run")
    rc, na, _np, _m = plan(gate, {}, allowed, [], False, False, None, True, None, dl)
    if rc != 0 or na:
        bad.append("regen: --prune did not delete a stale entry")
    rc, na, _np, msgs = plan(gate, base, [], [], True, False, "reason: reviewed", False, None, dl)
    if rc != 0 or len(na) != 1 or not any(m.startswith("ADDED allow x.sh:3") for m in msgs):
        bad.append("regen: --accept-new did not add and print file:line")
    else:
        t1 = render(ALLOW_HEAD, na)
        rc2, na2, _p2, _m2 = plan(gate, base, na, [], False, False, None, False, None, dl)
        if rc2 != 0 or render(ALLOW_HEAD, na2) != t1:
            bad.append("regen: a second run changed the output (not idempotent)")
    # #4921: a bump takes the new reason, and a bulk accept needs --match
    base2 = {"x.sh": base["x.sh"] * 2}
    rc, na, _np, msgs = plan(gate, base2, allowed, [], True, False, "reason: second site", False, None, dl)
    if rc != 0 or not na or na[0][0] != "reason: second site" or not any(m.startswith("BUMP") for m in msgs):
        bad.append("regen: a count bump kept the old reason (#4921)")
    many = {"x.sh": [(3, gate.norm(a_line), ["assign:PW"]), (4, "tool --token $T", ["assign:T"])]}
    rc, na, _np, _m = plan(gate, many, [], [], True, False, "reason: r", False, None, dl)
    if rc != 2 or na:
        bad.append("regen: --accept-new without --match took several new keys at once (#4921)")
    # #4902: laundering a pending line into allow
    pend_e: List[Entry] = [("#1", "x.sh", 1, gate.norm(a_line), 1)]
    rc, na, _np, _m = plan(gate, base2, [], pend_e, True, False, "reason: r", False, None, dl)
    if rc != 1 or na:
        bad.append("regen: --accept-new moved a pending key into allow (#4902)")
    renamed = _f(gate, "y.sh", a_line)
    rc, na, _np, _m = plan(gate, renamed, [], pend_e, True, False, "reason: renamed", True, None, dl)
    if rc != 1 or na:
        bad.append("regen: a renamed file moved a pending line into allow (#4902)")
    hdr = 'curl -H "X-API-Key: $k" http://h/'
    rc, na, _np, _m = plan(gate, _f(gate, "x.sh", hdr), [], [], True, False, "reason: r", False, None, dl)
    if rc != 1 or na:
        bad.append("regen: a line the prose rules flag was added to allow (#4902)")
    if not foreign_comments(ALLOW_HEAD, ALLOW_HEAD + "# a hand note\n"):
        bad.append("regen: a hand-written comment line would be dropped silently (#4902)")
    return bad


# ---------------------------------------------------------------- cli
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Maintain the exec-secret-argv allow and pending lists.")
    ap.add_argument("--accept-new", action="store_true", help="add triggered lines that are not listed")
    ap.add_argument("--pending", action="store_true", help="with --accept-new: add to the pending list")
    ap.add_argument("--why", help="'#<issue>' or 'reason: <text>' for every addition")
    ap.add_argument("--match", help="with --accept-new: only lines whose '<file> <text>' matches this regex")
    ap.add_argument("--prune", action="store_true", help="delete stale entries and lower counts")
    ap.add_argument("--check", action="store_true", help="write nothing; exit 1 if the files would change")
    ap.add_argument("--root", default=str(ROOT))
    return ap


def main(argv: List[str]) -> int:
    args = build_parser().parse_args(argv[1:])
    root = Path(args.root)
    try:
        gate = load_gate(root)
        dl = gate.load_denylist(root)
        found, _, _ = gate.scan_repo(root, dl)
        allow, pend, faults = gate.load_lists(root)
    except (OSError, RuntimeError, SyntaxError) as exc:
        print("FAULT: %s" % exc, file=sys.stderr)
        return 2
    if faults:
        print("\n".join("FAULT: " + f for f in faults), file=sys.stderr)
        return 2
    cur_allow = (root / gate.ALLOW_FILE).read_text(encoding="utf-8")
    cur_pend = (root / gate.PENDING_FILE).read_text(encoding="utf-8")
    dropped = foreign_comments(ALLOW_HEAD, cur_allow) + foreign_comments(PENDING_HEAD, cur_pend)
    if dropped:
        print("FAULT: a hand-written comment line would be dropped; remove it or move it into the head "
              "of the tool (#4902): %s" % dropped[0][:100], file=sys.stderr)
        return 2
    rc, na, np_, msgs = plan(gate, found, allow, pend, args.accept_new, args.pending, args.why, args.prune,
                             args.match, dl)
    for m in msgs:
        print(m, file=sys.stderr if m.startswith(("NEW", "STALE", "REFUSED")) else sys.stdout)
    if rc == 2:
        return 2
    new_allow = render(ALLOW_HEAD, na)
    new_pend = render(PENDING_HEAD, np_)
    changed = (new_allow != cur_allow) or (new_pend != cur_pend)
    if args.check:
        if changed:
            print("regen: the lists would change", file=sys.stderr)
        return 1 if changed or rc else 0
    if rc == 0:
        if changed:
            (root / gate.ALLOW_FILE).write_text(new_allow, encoding="utf-8")
            (root / gate.PENDING_FILE).write_text(new_pend, encoding="utf-8")
            print("regen: lists written")
        else:
            print("regen: no change")
    else:
        print("regen: nothing written (exit %d)" % rc, file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
