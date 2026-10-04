#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Rewrite scripts/qc-allowlists/pgbouncer-pool-mode-allow.txt from the tree (#4667, #4741).

The allowlist is a review surface, so this tool never changes it silently:

  * existing entries and their comments keep their order (no reordering);
  * a stale entry (fewer matching mentions than entries) is removed only with
    --drop-stale, and each removal is printed;
  * an entry whose text is still in the tree but whose neighbourhood changed (its
    ` | ctx:` fingerprint no longer matches) is re-bound only with --refresh-context
    and a --reason saying why the line is still safe in its new neighbourhood; the
    reason is written above each re-bound entry as a dated "context re-read" record,
    the entry's original reason is kept for the entries after it, and each refresh
    is printed and must be re-read (#5087, #5088, #5208);
  * a mention that is neither approved nor listed is added only with
    --accept-new, appended at the end under a dated comment and each
    addition is printed. The reason comment above the new entries is the text
    given with --reason (checked by the gate: a sentence of at least six words,
    not the placeholder); without --reason it is the placeholder, which the gate
    rejects with rc 2, so this tool cannot turn a red line green on its own
    (#4961). Replace the placeholder with a real reason per entry group.
  * the reason of listed entries is re-written only with --set-reason TEXT and
    --only/--match selecting them, on an allowlist that otherwise matches the
    tree; other entries that shared the old reason keep it (#5091);
  * an unreadable file is added to pgbouncer-pool-mode-unread.txt only under
    --skip-reason, a reason of its own; --reason never excuses a skipped file,
    and the gate refuses a skip entry whose name is a text type.

Without those flags the tool prints what it would change and exits 1, leaving
the file untouched. With --check it never writes. Exit codes: 0 the file already
matches the tree (or was rewritten as asked), 1 changes are pending and were
refused, 2 fault.

Usage:
    scripts/regen-pgbouncer-pool-mode-allow.py [--root DIR] [--check]
        [--accept-new [--reason TEXT | --reasons-file JSON] [--skip-reason TEXT]
                      [--only FILE] [--match TEXT]]
        [--refresh-context --reason TEXT] [--drop-stale]
        [--set-reason TEXT (--only FILE | --match TEXT)]
"""
import argparse
import datetime
import importlib.util
import json
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


def write_unread(gate, root, listed, stale_unread, new_unread, reason):
    """Rewrite the unread-file skip list: drop stale paths, append new ones under one dated reason comment."""
    path = root / gate.UNREAD_REL
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raw = ""
    drop = set(stale_unread)
    out = [line for line in raw.splitlines() if line not in drop]
    if new_unread:
        out += ["", "# added by regen-pgbouncer-pool-mode-allow.py --accept-new on %s:" % datetime.date.today().isoformat(),
                "# " + (reason or gate.PLACEHOLDER + " before review: say why each file below cannot be read as text")]
        out += new_unread
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".regen")
    tmp.write_text("\n".join(out).lstrip("\n") + "\n", encoding="utf-8")
    tmp.replace(path)


def entry_key(gate, line):
    """The (file, text, ctx) key of an allowlist entry line, as the gate loads it."""
    found = gate.CTX.search(line)
    body = line[:found.start()] if found else line
    return tuple(body.split(gate.SEPARATOR, 1)) + (found.group(1) if found else "",)


def set_reasons(gate, raw, picked, text):
    """Rewrite the reason of every picked entry to TEXT, keeping order and every other entry's reason.

    An entry's reason is the comment block directly above its run of entries. Within each such
    group, a run of picked entries is written under "# TEXT" and a run of the others under their
    old reason, so only the picked entries change reason; regen header lines are kept."""
    out, changed = [], 0
    lines = raw.splitlines()
    i = 0
    while i < len(lines):
        if not lines[i].strip() or not (lines[i].lstrip().startswith("#") or gate.SEPARATOR in lines[i]):
            out.append(lines[i])
            i += 1
            continue
        comments = []
        while i < len(lines) and lines[i].strip() and lines[i].lstrip().startswith("#"):
            comments.append(lines[i])
            i += 1
        entries = []
        while i < len(lines) and lines[i].strip() and not lines[i].lstrip().startswith("#") and gate.SEPARATOR in lines[i]:
            entries.append(lines[i])
            i += 1
        marks = [entry_key(gate, line) in picked for line in entries]
        if not any(marks):
            out += comments + entries
            continue
        old = [c for c in comments if not c.lstrip().lstrip("#").strip().startswith(gate.REGEN_HEADER)]
        head = [c for c in comments if c not in old]
        last = None
        for line, mark in zip(entries, marks):
            if mark != last:
                if last is None:
                    out += (head + ["# " + text]) if mark else comments
                else:
                    out += ["# " + text] if mark else old
                last = mark
            out.append(line)
            changed += 1 if mark else 0
    return out, changed


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=str(HERE.parent))
    ap.add_argument("--check", action="store_true", help="report only; never write")
    ap.add_argument("--accept-new", action="store_true", help="append unlisted mentions (printed) for review")
    ap.add_argument("--drop-stale", action="store_true", help="remove stale entries (printed)")
    ap.add_argument("--refresh-context", action="store_true",
                    help="re-bind an entry whose text is still in the tree but whose neighbourhood changed (or that has no "
                         "fingerprint yet) to the new fingerprint; needs --reason, written above each re-bound entry as a dated record; "
                         "every refresh is printed and must be re-read")
    ap.add_argument("--only", default="", metavar="FILE", help="with --accept-new: add only units of this file; "
                    "with --set-reason: select only entries of this file")
    ap.add_argument("--match", default="", metavar="TEXT", help="with --accept-new: add only units whose text contains TEXT "
                    "(so each unit can get its own reason); with --set-reason: select only entries whose text contains TEXT")
    ap.add_argument("--set-reason", default="", metavar="TEXT",
                    help="re-write the reason of the listed entries --only/--match select (printed); the allowlist must "
                         "otherwise match the tree; entries that shared the old reason keep it")
    ap.add_argument("--reasons-file", default="", metavar="JSON",
                    help="with --accept-new: JSON list of {file, match, reason}; each unlisted unit takes the first rule whose file "
                         "equals the unit's file and whose match is a substring of its text; {unit} in a reason becomes the "
                         "first 90 characters of the unit; a unit no rule matches is refused")
    ap.add_argument("--reason", default="", help="the written reason for every line --accept-new adds, and (required) "
                    "for every entry --refresh-context re-binds; it is written above each refreshed entry")
    ap.add_argument("--skip-reason", default="", help="with --accept-new: the written reason for every unreadable file "
                    "added to the skip list (--reason is never reused for it)")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve()
    gate = load_gate(root)
    reason = " ".join(a.reason.split())
    skip_reason = " ".join(a.skip_reason.split())
    set_reason = " ".join(a.set_reason.split())
    for flag, text in (("--reason", reason), ("--skip-reason", skip_reason), ("--set-reason", set_reason)):
        problem = gate.reason_problem(text) if text else None
        if problem:
            print("regen: FAULT: %s is not a reason: %s" % (flag, problem), file=sys.stderr)
            return 2
    allow_path = root / gate.ALLOW_REL
    try:
        raw = allow_path.read_text(encoding="utf-8")
    except OSError as exc:
        print("regen: FAULT: cannot read %s: %s" % (gate.ALLOW_REL, exc), file=sys.stderr)
        return 2
    entries, errors = gate.load_allowlist(root, require_ctx=not a.refresh_context)
    if errors:
        for err in errors:
            print("regen: FAULT: %s" % err, file=sys.stderr)
        return 2
    try:
        units, read, unreadable = gate.scan_detail(root)
    except OSError as exc:
        print("regen: FAULT: %s" % exc, file=sys.stderr)
        return 2
    if read == 0:
        print("regen: FAULT: empty scan", file=sys.stderr)
        return 2
    listed, unread_errors = gate.load_unread(root)
    if unread_errors:
        for err in unread_errors:
            print("regen: FAULT: %s" % err, file=sys.stderr)
        return 2
    need = Counter((rel, text, ctx) for rel, _, text, ctx in units if not gate.approved(text))
    have = Counter(entries)
    stale = have - need
    new = need - have
    refresh = []  # (old entry, new ctx) for entries whose text survives but whose neighbourhood changed
    if a.refresh_context:
        spare = {}
        for key in sorted(new.elements()):
            spare.setdefault(key[:2], []).append(key[2])
        for key in sorted(stale.elements()):
            if spare.get(key[:2]):
                refresh.append((key, spare[key[:2]].pop(0)))
        stale = stale - Counter(old for old, _ in refresh)
        new = new - Counter((old[0], old[1], c) for old, c in refresh)
    if a.set_reason:
        # #5091: a false reason is corrected through this tool, never by hand
        if a.check or a.accept_new or a.drop_stale or a.refresh_context or a.reasons_file or a.reason or a.skip_reason:
            print("regen: FAULT: --set-reason runs alone (with --only/--match)", file=sys.stderr)
            return 2
        if not (a.only or a.match):
            print("regen: FAULT: --set-reason needs --only FILE or --match TEXT to select the entries", file=sys.stderr)
            return 2
        if stale or new or (set(unreadable) != set(listed)):
            print("regen: FAULT: --set-reason needs an allowlist that matches the tree; run --check first", file=sys.stderr)
            return 2
        picked = {k for k in have if (not a.only or k[0] == a.only) and a.match in k[1]}
        if not picked:
            print("regen: FAULT: --only/--match select no listed entry", file=sys.stderr)
            return 2
        out, changed = set_reasons(gate, raw, picked, set_reason)
        for rel, text, ctx in sorted(picked):
            print("REASON: %s | %s | ctx:%s (re-read the new reason)" % (rel, text[:160], ctx))
        tmp = allow_path.with_name(allow_path.name + ".regen")
        tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
        tmp.replace(allow_path)
        print("regen: re-wrote the reason of %d entries; review the diff" % changed)
        return 0
    if a.only or a.match:
        picked = Counter({k: n for k, n in new.items() if (not a.only or k[0] == a.only) and a.match in k[1]})
        if not picked:
            print("regen: FAULT: --only/--match select no unlisted unit", file=sys.stderr)
            return 2
        new = picked
    # #4667 R4: a gate.forbidden_entry line is never allowlistable, reason or not.
    forbidden = sorted(key for key in new if gate.forbidden_entry(key[1]))
    if forbidden and not a.check:
        for rel, text, _ in forbidden:
            print("regen: FAULT: refusing a forbidden entry: %s | %s" % (rel, text[:160]), file=sys.stderr)
        print("regen: correct those lines in the tree; file left unchanged", file=sys.stderr)
        return 2
    per_unit = {}
    if a.reasons_file:
        try:
            rules = json.loads(Path(a.reasons_file).read_text(encoding="utf-8"))
            for key in sorted(new):
                for rule in rules:
                    if rule["file"] == key[0] and rule["match"] in key[1]:
                        text = " ".join(rule["reason"].replace("{unit}", key[1][:90].rstrip()).split())
                        # #5209: the unit is quoted, never its own reason; the written part must be a reason alone
                        written = " ".join(rule["reason"].replace("{unit}", " ").split())
                        problem = gate.reason_problem(written) or gate.reason_problem(text)
                        if problem:
                            print("regen: FAULT: reason for %s is not a reason: %s" % (key[0], problem), file=sys.stderr)
                            return 2
                        per_unit[key] = text
                        break
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print("regen: FAULT: --reasons-file: %s" % exc, file=sys.stderr)
            return 2
        left = [key for key in new if key not in per_unit]
        if left and a.accept_new and not a.check:
            for rel, text, _ in left[:5]:
                print("regen: FAULT: no rule in --reasons-file matches: %s | %s" % (rel, text[:100]), file=sys.stderr)
            return 2
    new_unread = sorted(set(unreadable) - set(listed))
    stale_unread = sorted(set(listed) - set(unreadable))
    for (rel, text, ctx), n in sorted(stale.items()):
        print("STALE x%d: %s | %s | ctx:%s" % (n, rel, text[:160], ctx))
    for (rel, text, ctx), n in sorted(new.items()):
        print("NEW   x%d: %s | %s | ctx:%s" % (n, rel, text[:160], ctx))
    for (rel, text, old), ctx in refresh:
        print("REFRESH: %s | %s | ctx:%s -> ctx:%s (re-read the lines around it)" % (rel, text[:160], old or "none", ctx))
    for rel in stale_unread:
        print("STALE SKIP: %s (readable or no longer tracked)" % rel)
    for rel in new_unread:
        print("NEW SKIP:   %s (%s)" % (rel, unreadable[rel]))
    if not stale and not new and not new_unread and not stale_unread and not refresh:
        print("regen: allowlist matches the tree (%d entries, %d unread-file skips)" % (len(entries), len(listed)))
        return 0
    refused = ((stale or stale_unread) and not a.drop_stale) or ((new or new_unread) and not a.accept_new)
    if refresh and not a.check and not a.refresh_context:
        refused = True
    if refresh and a.refresh_context and not a.check and not reason:
        # #5208: a re-bound neighbourhood is a review decision; it needs a reason and leaves a record
        print("regen: FAULT: --refresh-context needs --reason: say why each re-bound line is still safe in its new "
              "neighbourhood (it is written above each refreshed entry)", file=sys.stderr)
        return 2
    if a.check or refused:
        print("regen: %d stale, %d new, %d stale skip, %d new skip; files left unchanged (%s)" % (
            sum(stale.values()), sum(new.values()), len(stale_unread), len(new_unread),
            "--check" if a.check else "pass --drop-stale / --accept-new after reading each line above"))
        return 1
    if new_unread or stale_unread:
        write_unread(gate, root, listed, stale_unread, new_unread, skip_reason)
        if not (stale or new or refresh):
            print("regen: skip list: removed %d, added %d; review the diff" % (len(stale_unread), len(new_unread)))
            return 0
    out = []
    drop = Counter(stale)
    redo = {}
    for old, ctx in refresh:
        redo.setdefault(old, []).append(ctx)
    block, current, restore = [], "", ""
    start, dropped, kept = 0, False, False

    def close_paragraph() -> None:
        # #5257: a paragraph whose every entry was dropped takes its reason comments with it
        if dropped and not kept:
            del out[start:]  # every entry of this paragraph was dropped

    for line in raw.splitlines():
        if not line.strip():
            close_paragraph()
            start, dropped, kept = len(out), False, False
            block, current, restore = [], "", ""
        elif line.lstrip().startswith("#"):
            text = line.lstrip().lstrip("#").strip()
            if not text.startswith(gate.REGEN_HEADER):
                block.append(text)
            restore = ""
        elif gate.SEPARATOR in line:
            under_comment = bool(block)  # this entry's reason is the comment block directly above it
            if block:
                current, block = " ".join(block), []
            found = gate.CTX.search(line)
            body = line[:found.start()] if found else line
            key = tuple(body.split(gate.SEPARATOR, 1)) + (found.group(1) if found else "",)
            if drop[key] > 0:
                drop[key] -= 1
                dropped = True
                continue
            kept = True
            if redo.get(key):
                line = "%s | ctx:%s" % (body, redo[key].pop(0))
                if current and not under_comment:
                    out.append("# " + current)  # a re-bound entry inside a group keeps the group's reason
                out.append("# context re-read on %s: %s" % (datetime.date.today().isoformat(), reason))
                restore = current
            elif restore:
                out.append("# " + restore)  # the entries after a re-bound one keep their own reason
                restore = ""
        out.append(line)
    close_paragraph()
    if new:
        today = datetime.date.today().isoformat()
        for count, ((rel, text, ctx), n) in enumerate(sorted(new.items())):
            note = per_unit.get((rel, text, ctx)) or reason or gate.PLACEHOLDER + " before review: say why each line below is safe"
            if per_unit or count == 0:
                out += ["", "# added by regen-pgbouncer-pool-mode-allow.py --accept-new on %s:" % today, "# " + note]
            out += ["%s%s%s | ctx:%s" % (rel, gate.SEPARATOR, text, ctx)] * n
    tmp = allow_path.with_name(allow_path.name + ".regen")
    tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
    tmp.replace(allow_path)
    print("regen: removed %d, added %d, refreshed %d; review the diff" % (sum(stale.values()), sum(new.values()), len(refresh)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
