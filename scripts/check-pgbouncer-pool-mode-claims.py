#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#4667 - every mention of a PgBouncer pooler mode in the tree must say session mode.

Why. docs/enterprise-deployment.md section 5.6 once called PgBouncer
`pool_mode = transaction` REQUIRED while the Postgres adapter keeps state on the
server session (migration advisory lock, search_path, statement_timeout) and is
not safe behind a transaction or statement pooler
(scripts/probe-pgbouncer-pool-mode.py). The docs, the template and the prose
drifted from the adapter and nothing noticed.

Threat model. Honest drift: a tired author, a copy of an old paragraph, a
rewording. This gate is not a defence against an adversary who writes a
sentence the patterns do not know; it removes the failure of a RECOGNISED bad
wording slipping past a list of recognised bad wordings.

Form (same as the PR 4655 cloud-init gate, memory 19497ef6): the gate does not
recognise bad wordings. It finds every line that MENTIONS a pooler mode and
requires each one to either state session mode in an approved form or be listed
on the allowlist (scripts/qc-allowlists/pgbouncer-pool-mode-allow.txt).

  Scan      every tracked text file (git ls-files; a directory walk when the
            root is not a git checkout), not only .md and .html. A line is
            HTML-unescaped, stripped of tags, backticks and asterisks,
            whitespace-normalised and case-folded first. Two adjacent lines are
            also joined, so a mention wrapped across a line break is seen, and so
            is a mode word on the line after an approved line (#4950).
  Mention   `pool_mode` in any spelling (pool_mode, pool-mode, pool mode,
            POOL_MODE, PGBOUNCER_POOL_MODE, YAML `pool_mode:`, per-database
            `pool_mode=` overrides, and `pooling mode` in the same spellings), a bare `mode =` / `mode:` key set to a
            non-session mode, a mode word (transaction, transactional,
            statement, txn) anywhere on the same line as a pooler product
            (pgbouncer, pooler, odyssey, supavisor, pgcat), or within sixty
            characters, either order, of pooling or multiplex (#4951), or multiplex within forty characters before
            transactions / statements. A bare `pool` is not a pooler word:
            sqlx and r2d2 connection pools are not PgBouncer modes. Session
            mode / session pooling prose is a mention as well.
  Approved  the line carries a `pool_mode` assignment, every assignment on it is
            `session`, it names no other mode and it holds no negation or hazard
            word (never, not, no, avoid, unsafe, don't, instead, without,
            deprecated, forbidden, retired). Prose that merely says `session
            mode` is NOT approved (#4741 round 2: an inversion such as "session
            mode is unsafe" read as approval); such a line goes on the allowlist,
            where a reviewer reads it. There is no proximity exemption.
  Allowlist `<file> | <normalised line>`, one entry per occurrence: a text that
            occurs twice in a file needs two entries. A stale entry (fewer such
            mentions in that file than entries), a malformed entry and an empty
            scan fail. scripts/regen-pgbouncer-pool-mode-allow.py rewrites the
            file without reordering; it refuses additions and removals unless
            asked (--accept-new / --drop-stale) and prints each one.

Also: infra/pgbouncer/pgbouncer.ini holds exactly one active global
`pool_mode = session`, and docs/enterprise-deployment.md holds at least one
approved `pool_mode = session` line (the pin has something to compare).

Exit codes: 0 clean, 1 a mention is neither approved nor allowlisted, 2 usage /
fault / stale or malformed allowlist / empty scan / self-test failure.

Usage:
    scripts/check-pgbouncer-pool-mode-claims.py [--root DIR]
    scripts/check-pgbouncer-pool-mode-claims.py --self-test
"""
from __future__ import annotations

import argparse
import html
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from collections import Counter
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
INI_REL = Path("infra") / "pgbouncer" / "pgbouncer.ini"
GUIDE_REL = Path("docs") / "enterprise-deployment.md"
ALLOW_REL = Path("scripts") / "qc-allowlists" / "pgbouncer-pool-mode-allow.txt"
SELF_REL = Path("scripts") / "check-pgbouncer-pool-mode-claims.py"
SEPARATOR = " | "
EXIT_OK, EXIT_FINDING, EXIT_FAULT = 0, 1, 2

POOL_MODE = r"pool(?:ing)?[\s_-]*mode"
MENTION_NAME = re.compile(POOL_MODE)
_MODE_WORD = r"(?:transaction(?:al)?|statement|txn)"
_POOLER = r"(?:pgbouncer|pooler|pooling|odyssey|supavisor|pgcat|multiplex(?:es|ed|ing)?)"
_PRODUCT = r"(?:pgbouncer|pooler|odyssey|supavisor|pgcat)"
MENTION_PROSE = re.compile(
    # transaction mode / transaction pooling / transaction-level pooling / statement pool
    r"\b%s[\s-]+(?:level[\s-]+|mode[\s-]+)?(?:mode|pooling|pooler|pool)\b"
    # pooler in transaction mode / pool: transaction / pooling = txn
    r"|\b(?:pooling|pooler|pgbouncer|odyssey|pool)[\s:=-]+(?:(?:in|to|with|using|at|of|is|=)\s+)?%s\b"
    # a pooler word within sixty characters of a mode word, either order
    r"|\b%s\b.{0,60}?\b%s\b|\b%s\b.{0,60}?\b%s\b"
    # a pooler product (pgbouncer, pooler, odyssey, ...) anywhere on the same line as a mode word, either order
    r"|\b%s\b.*?\b%s\b|\b%s\b.*?\b%s\b"
    # a pooler that multiplexes transactions / statements
    r"|\bmultiplex(?:es|ed|ing)?\b.{0,40}?\b(?:transactions|statements)\b"
    # session-mode prose is a mention too, so an inversion ("session mode is unsafe") is scanned
    r"|\bsession[\s-]+(?:mode|pooling|pooler)\b"
    # a bare mode key (supavisor / pgcat / odyssey configs): mode = transaction, mode: statement
    r"|\bmode\s*[:=]\s*[\"']?%s\b"
    % (_MODE_WORD, _MODE_WORD, _POOLER, _MODE_WORD, _MODE_WORD, _POOLER,
       _PRODUCT, _MODE_WORD, _MODE_WORD, _PRODUCT, _MODE_WORD)
)
ASSIGNMENT = re.compile(POOL_MODE + r"\s*(?:[=:]|\bis\b)?\s*[\"']?([a-z]+)")
OTHER_MODE = re.compile(r"\b%s\b" % _MODE_WORD)
NEGATION = re.compile(r"\b(?:never|not|no|avoid|unsafe|don'?t|instead|without|deprecated|forbidden|retired)\b")
TAG = re.compile(r"<[^>]*>")
INI_ACTIVE = re.compile(r"^\s*pool_mode\s*=\s*([A-Za-z]+)\s*(?:[;#].*)?$")
MAX_BYTES = 4 * 1024 * 1024

Unit = Tuple[str, int, str]  # (relative path, line number, normalised text)


def normalise(line: str) -> str:
    text = TAG.sub("", html.unescape(line))
    text = re.sub(r"[`*]", "", text)
    return " ".join(text.split()).casefold()


def mentions(text: str) -> bool:
    return bool(MENTION_NAME.search(text) or MENTION_PROSE.search(text))


def approved(text: str) -> bool:
    """The line states session mode in an approved form and names no other mode."""
    if OTHER_MODE.search(text) or NEGATION.search(text):
        return False
    assignments = ASSIGNMENT.findall(text)
    return bool(assignments) and all(a == "session" for a in assignments)


def tracked_files(root: Path) -> List[str]:
    if (root / ".git").exists():
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=False
        )
        if out.returncode != 0:
            raise OSError("git ls-files failed: %s" % out.stderr.decode("utf-8", "replace").strip())
        return sorted(p for p in out.stdout.decode("utf-8", "surrogateescape").split("\0") if p)
    found = []
    for base, dirs, names in os.walk(str(root)):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in names:
            found.append(Path(base, name).relative_to(root).as_posix())
    return sorted(found)


def scan(root: Path) -> Tuple[List[Unit], int]:
    """Every mentioning line (single or two joined) and the number of files read."""
    units: List[Unit] = []
    read = 0
    for rel in tracked_files(root):
        if Path(rel) in (ALLOW_REL, SELF_REL):
            continue
        path = root / rel
        try:
            if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue
        read += 1
        lines = [normalise(l) for l in data.decode("utf-8", "replace").splitlines()]
        for i, text in enumerate(lines):
            if text and mentions(text):
                units.append((rel, i + 1, text))
            if i + 1 < len(lines) and text and lines[i + 1]:
                joined = text + " " + lines[i + 1]
                nxt = lines[i + 1]
                if mentions(joined) and not mentions(text) and not mentions(nxt):
                    units.append((rel, i + 2, joined))
                elif mentions(text) and approved(text) and not mentions(nxt) and OTHER_MODE.search(nxt):
                    # An approved line must not be qualified by a mode word on the next line (#4950).
                    units.append((rel, i + 2, joined))
    return units, read


def load_allowlist(root: Path) -> Tuple[List[Tuple[str, str]], List[str]]:
    entries: List[Tuple[str, str]] = []
    errors: List[str] = []
    path = root / ALLOW_REL
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], ["%s: unreadable: %s" % (ALLOW_REL, exc)]
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if SEPARATOR not in line:
            errors.append("%s:%d: malformed entry (want `<file> | <normalised line>`)" % (ALLOW_REL, number))
            continue
        rel, text = line.split(SEPARATOR, 1)
        if not rel or " " in rel or not text or text != normalise(text):
            errors.append("%s:%d: malformed entry (file empty/has spaces, or text empty/not normalised)" % (ALLOW_REL, number))
            continue
        entries.append((rel, text))
    return entries, errors


def judge(units: Sequence[Unit], entries: Sequence[Tuple[str, str]]) -> Tuple[List[str], List[str]]:
    """(findings, stale entries). A finding is an unapproved, unlisted mention."""
    budget = Counter(entries)  # one entry per occurrence
    findings = []
    for rel, number, text in units:
        if approved(text):
            continue
        if budget[(rel, text)] > 0:
            budget[(rel, text)] -= 1
            continue
        findings.append("%s:%d: mentions a pooler mode without stating session mode: %s" % (rel, number, text[:170]))
    stale = ["%s: stale allowlist entry (x%d unused): %s | %s" % (ALLOW_REL, n, r, t[:120]) for (r, t), n in budget.items() if n > 0]
    return findings, stale


def fault(message: str) -> int:
    print("check-pgbouncer-pool-mode-claims: FAULT: %s" % message, file=sys.stderr)
    return EXIT_FAULT


def check_template(root: Path) -> Optional[str]:
    try:
        text = (root / INI_REL).read_text(encoding="utf-8")
    except OSError as exc:
        return "cannot read %s: %s" % (INI_REL, exc)
    modes = [m.group(1).lower() for m in (INI_ACTIVE.match(l) for l in text.splitlines()) if m]
    if modes != ["session"]:
        return "%s must hold exactly one active global `pool_mode = session`, found %r" % (INI_REL, modes)
    return None


def run(root: Path) -> int:
    bad = check_template(root)
    if bad:
        return fault(bad)
    try:
        units, read = scan(root)
    except OSError as exc:
        return fault(str(exc))
    if read == 0:
        return fault("no text files scanned under %s (an empty scan is a failure)" % root)
    entries, errors = load_allowlist(root)
    if errors:
        for err in errors:
            print("check-pgbouncer-pool-mode-claims: FAULT: %s" % err, file=sys.stderr)
        return EXIT_FAULT
    guide_ok = [u for u in units if u[0] == GUIDE_REL.as_posix() and approved(u[2]) and ASSIGNMENT.search(u[2])]
    if not guide_ok:
        return fault("%s holds no approved `pool_mode = session` line; the pin has nothing to compare (fail closed)" % GUIDE_REL)
    findings, stale = judge(units, entries)
    if stale:
        for line in stale:
            print("check-pgbouncer-pool-mode-claims: FAULT: %s" % line, file=sys.stderr)
        return EXIT_FAULT
    if findings:
        print("check-pgbouncer-pool-mode-claims: %d mention(s) of a pooler mode do not state session mode:" % len(findings))
        for finding in findings:
            print("  " + finding)
        print("  fix the wording to the `pool_mode = session` form, or run scripts/regen-pgbouncer-pool-mode-allow.py --accept-new and give each new entry in %s a reason comment for review." % ALLOW_REL)
        return EXIT_FINDING
    print("check-pgbouncer-pool-mode-claims: OK (%d files scanned; %d mention lines; %d allowlisted; %d approved pool_mode lines in %s)"
          % (read, len(units), len(entries), len(guide_ok), GUIDE_REL))
    return EXIT_OK


# ---------------------------------------------------------------- self-test

GOOD_GUIDE = "```ini\npool_mode = session\n```\n"
GOOD_INI = "[pgbouncer]\npool_mode = session\n"

# The 20 wordings the PR 4710 review planted (and variants of the same shapes).
PLANTED: List[Tuple[str, str, str]] = [
    ("lowercase ini line", "docs/a.md", "pool_mode = transaction\n"),
    ("uppercase POOL_MODE", "docs/a.md", "POOL_MODE = transaction\n"),
    ("yaml pool_mode:", "deploy/pgb.yaml", "pool_mode: transaction\n"),
    ("yaml POOL_MODE:", "deploy/pgb.yml", "POOL_MODE: statement\n"),
    ("env PGBOUNCER_POOL_MODE", "deploy/.env", "PGBOUNCER_POOL_MODE=transaction\n"),
    ("compose env list item", "deploy/compose.yml", "    - PGBOUNCER_POOL_MODE=transaction\n"),
    ("hyphenated pool-mode", "docs/a.md", "pool-mode = statement\n"),
    ("spaced 'pool mode:'", "docs/a.md", "The pool mode: transaction is recommended.\n"),
    ("prose: PgBouncer in transaction mode", "docs/a.md", "Run PgBouncer in transaction mode for fan-in.\n"),
    ("prose: transaction-level pooling", "docs/a.md", "Use transaction-level pooling in front of Postgres.\n"),
    ("prose: txn pooler", "docs/a.md", "Put a txn pooler in front.\n"),
    ("prose: statement pooling", "ROADMAP.md", "statement pooling cuts connection count\n"),
    ("line-wrapped prose", "docs/a.md", "Front the primary with a pooler in\ntransaction mode.\n"),
    ("html entity underscore", "docs/a.html", "<p>pool&#95;mode = transaction</p>\n"),
    ("split code spans", "docs/a.html", "<code>pool_mode</code> = <code>transaction</code>\n"),
    ("ini file, not markdown", "infra/other/pgb.ini", "pool_mode=transaction\n"),
    ("txt file", "notes/pooling.txt", "pool_mode = statement\n"),
    ("per-database override", "infra/pgbouncer/extra.ini", "ai_memory = host=pg dbname=ai_memory pool_mode=transaction\n"),
    ("retirement word nearby does not excuse (#4667)", "docs/a.md", "see #4667\nno longer an issue\npool_mode = transaction\n"),
    ("unrelated word nearby does not excuse", "docs/a.md", "an earlier revision\nPgBouncer in transaction mode\n"),
    # PR 4710 round-2 security review (#4741): wordings outside the round-1 mention set.
    ("pooling mode to transaction", "docs/a.md", "Set the pooling mode to transaction for the daemon.\n"),
    ("pooling mode to transaction, short form", "docs/a.md", "Set the pooling mode to transaction.\n"),
    ("wrap after an approved line", "docs/a.md", "Run PgBouncer with pool_mode = session or, for more fan-in,\ntransaction.\n"),
    ("ini comment after approved line", "infra/x/pgb.ini", "pool_mode = session\n; or transaction for fan-in\n"),
    ("pooler named far before mode word", "docs/a.md", "Put PgBouncer in front of each module backbone for admission control, then switch it to transaction.\n"),
    ("pooling mode: transaction", "docs/a.md", "Recommended pooling mode: transaction.\n"),
    ("transactional pooling", "docs/a.md", "Use transactional pooling in front of the daemon.\n"),
    ("transaction-scoped pooling", "docs/a.md", "Front the daemon with transaction-scoped pooling.\n"),
    ("pooling per transaction", "docs/a.md", "Use connection pooling per transaction for the daemon.\n"),
    ("multiplex transactions", "docs/a.md", "Have PgBouncer multiplex transactions for the daemon.\n"),
    ("bare yaml mode key", "deploy/supavisor.yaml", "supavisor:\n  mode: transaction\n"),
    # approval inversions: naming session mode is not approval
    ("inversion: pool_mode = session is unsafe", "docs/a.md", "Never use pool_mode = session for the daemon; it is unsafe.\n"),
    ("inversion: session mode is unsafe", "docs/a.md", "PgBouncer session mode is unsafe for the daemon.\n"),
    ("inversion: avoid session pooling", "docs/a.md", "Avoid session pooling; pool_mode = session wastes backends.\n"),
]


def write_tree(root: Path, files: Dict[str, str]) -> None:
    for rel, body in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")


def tree(extra: Optional[Dict[str, str]] = None, allow: str = "", guide: str = GOOD_GUIDE, ini: str = GOOD_INI) -> Dict[str, str]:
    files = {INI_REL.as_posix(): ini, GUIDE_REL.as_posix(): guide, ALLOW_REL.as_posix(): allow}
    files.update(extra or {})
    return files


def run_quiet(root: Path) -> int:
    saved_out, saved_err = sys.stdout, sys.stderr
    sink = open(os.devnull, "w")
    sys.stdout = sys.stderr = sink
    try:
        try:
            return run(root)
        except SystemExit as exc:
            return int(exc.code) if isinstance(exc.code, int) else EXIT_FAULT
    finally:
        sys.stdout, sys.stderr = saved_out, saved_err
        sink.close()


def self_test() -> int:
    scratch_base = os.environ.get("TMPDIR") or str(REPO_ROOT / ".local-runs")
    Path(scratch_base).mkdir(parents=True, exist_ok=True)
    cases: List[Tuple[str, Dict[str, str], int]] = []
    for name, rel, body in PLANTED:
        cases.append(("planted: " + name, tree({rel: body}), EXIT_FINDING))
    stale_line = "docs/gone.md | pool_mode = transaction"
    cases += [
        ("agreeing tree passes", tree(), EXIT_OK),
        ("session prose alone is not approved", tree({"docs/a.md": "PgBouncer session mode is supported.\n"}), EXIT_FINDING),
        ("session prose passes once allowlisted",
         tree({"docs/a.md": "PgBouncer session mode is supported.\n"}, "docs/a.md | pgbouncer session mode is supported.\n"), EXIT_OK),
        ("approved: ini session with comment", tree({"docs/a.md": "pool_mode = session ; supported mode\n"}), EXIT_OK),
        ("approved: yaml session", tree({"deploy/pgb.yaml": "pool_mode: session\n"}), EXIT_OK),
        ("approved: env session", tree({"deploy/.env": "PGBOUNCER_POOL_MODE=session\n"}), EXIT_OK),
        ("a mixed line (session and transaction) is not approved", tree({"docs/a.md": "pool_mode = session, not transaction mode\n"}), EXIT_FINDING),
        ("allowlisted retirement line passes",
         tree({"docs/a.md": "Transaction mode is not supported (#4667).\n"}, "docs/a.md | transaction mode is not supported (#4667).\n"), EXIT_OK),
        ("allowlist entry is bound to its file",
         tree({"docs/b.md": "Transaction mode is not supported (#4667).\n"}, "docs/a.md | transaction mode is not supported (#4667).\n"), EXIT_FAULT),
        ("stale allowlist entry fails", tree({}, stale_line + "\n"), EXIT_FAULT),
        ("malformed allowlist entry fails", tree({}, "no separator here\n"), EXIT_FAULT),
        ("an entry beyond the occurrence count is stale",
         tree({"docs/a.md": "Transaction mode is not supported.\n"}, "docs/a.md | transaction mode is not supported.\ndocs/a.md | transaction mode is not supported.\n"), EXIT_FAULT),
        ("one entry does not cover a second occurrence",
         tree({"docs/a.md": "Transaction mode is not supported.\nx\nTransaction mode is not supported.\n"}, "docs/a.md | transaction mode is not supported.\n"), EXIT_FINDING),
        ("two entries cover two occurrences",
         tree({"docs/a.md": "Transaction mode is not supported.\nx\nTransaction mode is not supported.\n"}, "docs/a.md | transaction mode is not supported.\ndocs/a.md | transaction mode is not supported.\n"), EXIT_OK),
        ("non-normalised allowlist text fails",
         tree({"docs/a.md": "Transaction mode is not supported.\n"}, "docs/a.md | Transaction mode is not supported.\n"), EXIT_FAULT),
        ("fail closed: guide with no approved pool_mode line", tree(guide="No pooler section here.\n"), EXIT_FAULT),
        ("fail closed: template with two active pool_mode lines", tree(ini=GOOD_INI + "pool_mode = session\n"), EXIT_FAULT),
        ("fail closed: template mode is transaction", tree(ini="[pgbouncer]\npool_mode = transaction\n"), EXIT_FAULT),
        ("fail closed: missing allowlist file", {k: v for k, v in tree().items() if k != ALLOW_REL.as_posix()}, EXIT_FAULT),
    ]
    failures = 0
    for name, files, want in cases:
        with tempfile.TemporaryDirectory(dir=scratch_base) as tmp:
            root = Path(tmp)
            write_tree(root, files)
            got = run_quiet(root)
        ok = got == want
        failures += 0 if ok else 1
        print("self-test %s %-70s want=%d got=%d" % ("ok  " if ok else "FAIL", name, want, got))
    failures += mutate_real_allowlist()
    if failures:
        print("check-pgbouncer-pool-mode-claims: SELF-TEST FAILED (%d case(s))" % failures, file=sys.stderr)
        return EXIT_FAULT
    print("check-pgbouncer-pool-mode-claims: self-test OK (%d planted/near-miss cases + allowlist mutations)" % len(cases))
    return EXIT_OK


def mutate_real_allowlist() -> int:
    """Every real allowlist entry is load-bearing: damaging any one must fail the gate."""
    if not (REPO_ROOT / ALLOW_REL).is_file():
        print("self-test FAIL real allowlist missing")
        return 1
    units, _ = scan(REPO_ROOT)
    entries, errors = load_allowlist(REPO_ROOT)
    if errors:
        print("self-test FAIL real allowlist malformed")
        return 1
    findings, stale = judge(units, entries)
    if findings or stale:
        print("self-test FAIL real tree does not judge clean (%d findings, %d stale)" % (len(findings), len(stale)))
        return 1
    bad = 0
    for index, (rel, text) in enumerate(entries):
        for label, mutant in (("text altered", (rel, text + " x")), ("file altered", (rel + ".moved", text))):
            mutated = entries[:index] + [mutant] + entries[index + 1:]
            f2, s2 = judge(units, mutated)
            if not (f2 or s2):
                bad += 1
                print("self-test FAIL allowlist entry %d (%s) survived mutation: %s | %s" % (index + 1, label, rel, text[:80]))
        f3, s3 = judge(units, entries[:index] + entries[index + 1:])
        if not f3:
            bad += 1
            print("self-test FAIL allowlist entry %d is not needed (removal did not raise a finding): %s" % (index + 1, rel))
    print("self-test %s every one of %d allowlist entries is load-bearing (text, file and removal mutations)" % ("ok  " if not bad else "FAIL", len(entries)))
    return bad


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", default=str(REPO_ROOT), help="repository root to scan")
    parser.add_argument("--self-test", action="store_true", help="plant wordings, mutate the allowlist and assert the verdicts")
    args = parser.parse_args(list(argv))
    if args.self_test:
        return self_test()
    try:
        return run(Path(args.root).resolve())
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_FAULT


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
