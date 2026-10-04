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
rewording. The gate does not try to recognise bad wordings; three review rounds
of PR 4710 each found a wording a list did not name (#4741, #4950, #4960).

Form: a closed world that fails closed (precedent: the PR 4655 cloud-init gate,
memories 19497ef6 and d517ebcd; copying that precedent, so no new vote). The
gate finds every line that MENTIONS a pooler mode, and a mention passes only if
it has one of a small set of APPROVED SHAPES or an ALLOWLIST entry with a
written reason. No list of bad or negating words decides anything.

  Scan      every tracked text file (git ls-files; a directory walk when the
            root is not a git checkout). A line is HTML-unescaped, stripped of
            tags, backticks and asterisks, whitespace-normalised and case-folded.
  Mention   (wide; R-rules, each pinned by a self-test mutant)
            R1 name: `pool_mode` in any spelling and plural (pool mode, pool-mode,
               pooling mode, POOL_MODE, PGBOUNCER_POOL_MODE, `pool_modes`).
            R2 prose: a mode word (transaction(s), transactional, statement(s),
               txn, tx, xact) next to a pool word (mode(s), pool(s), pooling,
               pooler), a pool word followed by a mode word, a mode word within
               sixty characters of a pooler word, a mode word anywhere on a line
               that names a pooler product (pgbouncer, pooler, odyssey,
               supavisor, pgcat), multiplexed transactions/statements, session
               next to a pool word, and a bare `mode =` / `mode:` key set to a
               mode word.
            R3 path tokens: a file path or file name (`a/b`, `x.py`) is reduced
               to the product and mode words it contains before R1/R2 run, so
               naming scripts/check-pgbouncer-pool-mode-claims.py is not a
               mention, while `pgbouncer.ini ... transaction` still is.
            R4 wrap: two adjacent lines that only mention when joined.
            R5 paragraph: a line that names a mode word within the two nearest
               non-blank lines (blank lines skipped) of a mention line is joined
               with it and judged as one unit.
            R6 approved-line context: each of the two nearest non-blank lines on
               either side of an approved line must itself be a mention (judged
               on its own) or a NEUTRAL line: a code fence, a config section
               header, or a short config `key = value` line with no mode word.
               Anything else (prose, a prose comment) is joined with the
               approved line and judged as one unit, so `pool_mode = session`
               followed by "is unsafe" is not approved.
  Approved  (closed set, matched against the WHOLE normalised line)
            A1 an assignment: an optional list/quote prefix, a pool-mode key in
               any spelling, `=` or `:`, the value `session` (optionally quoted),
               nothing else.
            A2 the same assignment followed by a `;` / `#` comment whose words
               all come from a closed vocabulary (supported, required, only,
               the, is, mode, session, default, pinned, see, and #NNNN / section
               numbers).
            Prose is never approved: no shape tells "set pool_mode = session"
            from "stop using pool_mode = session" (#4960).
  Allowlist `<file> | <normalised unit>`, one entry per occurrence, every entry
            under a reason comment: the comment block directly above it, or the
            reason of the entry directly above it. A reason that is empty, is
            the regen placeholder (`REASON REQUIRED`), or is shorter than six
            words / thirty characters is a FAULT (rc 2), and so is any comment
            line that still holds the placeholder. A stale entry, a malformed
            entry and an empty scan fail. scripts/regen-pgbouncer-pool-mode-allow.py
            rewrites the file without reordering and cannot make a red line
            green on its own: --accept-new writes the placeholder unless
            --reason gives a real one.

Also: infra/pgbouncer/pgbouncer.ini holds exactly one active global
`pool_mode = session`, and docs/enterprise-deployment.md holds at least one
approved assignment line (the pin has something to compare).

Exit codes: 0 clean, 1 a mention is neither approved nor allowlisted, 2 usage /
fault / stale, malformed or unreasoned allowlist / empty scan / self-test failure.

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
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
INI_REL = Path("infra") / "pgbouncer" / "pgbouncer.ini"
GUIDE_REL = Path("docs") / "enterprise-deployment.md"
ALLOW_REL = Path("scripts") / "qc-allowlists" / "pgbouncer-pool-mode-allow.txt"
SELF_REL = Path("scripts") / "check-pgbouncer-pool-mode-claims.py"
SEPARATOR = " | "
EXIT_OK, EXIT_FINDING, EXIT_FAULT = 0, 1, 2

# ------------------------------------------------------------ mention (wide)

POOL_MODE = r"pool(?:ing)?[\s_-]*mode"
MENTION_NAME = re.compile(POOL_MODE + r"s?")  # R1
_MODE_WORD = r"(?:transaction(?:s|al)?|statements?|txn|tx|xact)"
_ANY_MODE = r"(?:%s|sessions?)" % _MODE_WORD
_POOLER = r"(?:pgbouncer|pooler|pooling|odyssey|supavisor|pgcat|multiplex(?:es|ed|ing)?)"
_PRODUCT = r"(?:pgbouncer|pooler|odyssey|supavisor|pgcat)"
MENTION_PROSE = re.compile(  # R2
    # transaction mode / transaction pooling / transaction-level pooling / statement pools / session mode
    r"\b%s[\s-]+(?:level[\s-]+|mode[\s-]+|scoped[\s-]+)?(?:modes?|pooling|pooler|pools?)\b"
    # pooler in transaction mode / pool: transaction / pooling = txn / pgbouncer in session
    r"|\b(?:pooling|pooler|pgbouncer|odyssey|pools?)[\s:=-]+(?:(?:in|to|with|using|at|of|is|per|=)\s+)?%s\b"
    # a pooler word within sixty characters of a mode word, either order
    r"|\b%s\b.{0,60}?\b%s\b|\b%s\b.{0,60}?\b%s\b"
    # a pooler product (pgbouncer, pooler, odyssey, ...) anywhere on the same line as a mode word, either order
    r"|\b%s\b.*?\b%s\b|\b%s\b.*?\b%s\b"
    # a bare mode key (supavisor / pgcat / odyssey configs): mode = transaction, mode: statement
    r"|\bmode\s*[:=]\s*[\"']?%s\b"
    % (_ANY_MODE, _ANY_MODE, _POOLER, _MODE_WORD, _MODE_WORD, _POOLER,
       _PRODUCT, _MODE_WORD, _MODE_WORD, _PRODUCT, _MODE_WORD)
)
OTHER_MODE = re.compile(r"\b%s\b" % _MODE_WORD)
_QUICK = re.compile(r"mode|pool|pgbouncer|odyssey|supavisor|pgcat|multiplex")
# R3: a file path (has a slash) or a file name (has a known extension).
TOOL_PATH = re.compile(
    r"[\w.~+-]*(?:/[\w.~+#%-]*)+"
    r"|\b[\w-]+(?:\.[\w-]+)*\.(?:py|txt|md|ini|sh|rs|toml|ya?ml|json|sql|conf|cfg|html?|tf|env|log)\b")
_PATH_KEEP = re.compile(r"pgbouncer|pooler|odyssey|supavisor|pgcat|transaction(?:s|al)?|statements?|sessions?|txn|xact|\btx\b")

TAG = re.compile(r"<[^>]*>")
INI_ACTIVE = re.compile(r"^\s*pool_mode\s*=\s*([A-Za-z]+)\s*(?:[;#].*)?$")
MAX_BYTES = 4 * 1024 * 1024
NEIGHBOURS = 2  # non-blank lines inspected on each side (R5, R6)

# ------------------------------------------------------- approved (closed set)

_PREFIX = r"(?:[-*>]\s*)*"
_KEY = r"[\"']?(?:[a-z0-9_]*_)?pool(?:ing)?[_-]?mode[\"']?"
_SESSION = r"[\"']?session[\"']?,?"
_VOCAB = r"(?:supported|required|only|the|is|mode|session|default|pinned|see|#\d+|\(#\d+\)|§?\d+(?:\.\d+)*)"
_COMMENT = r"\s*[;#]\s*%s(?:[\s,.]+%s)*[\s,.]*" % (_VOCAB, _VOCAB)
APPROVED_SHAPES = (
    ("A1 assignment", re.compile(r"^%s%s\s*[=:]\s*%s$" % (_PREFIX, _KEY, _SESSION))),
    ("A2 assignment with a closed-vocabulary comment", re.compile(r"^%s%s\s*[=:]\s*%s%s$" % (_PREFIX, _KEY, _SESSION, _COMMENT))),
)
# Neutral context lines for R6 (closed set).
FENCE = re.compile(r"^(?:```|~~~)[A-Za-z0-9_+-]*$")
_TOKEN = r"[^\s;#]+"
_KV_TOKEN = r"[a-z_][a-z0-9_.-]*=[^\s;#]*"  # host=pg, port=5432: no prose has this shape
NEUTRAL_SHAPES = (
    FENCE,                                                                  # code fence
    re.compile(r"^\[[a-z0-9_.* -]+\]$"),                                    # config section header
    re.compile(r"^%s[a-z_][a-z0-9_.]*\s*=\s*(?:%s(?:\s+%s)?)?(?:%s)?$" % (_PREFIX, _TOKEN, _TOKEN, _COMMENT)),
    re.compile(r"^[a-z_][a-z0-9_.]*\s*=\s*(?:%s\s*)+$" % _KV_TOKEN),         # a [databases] line: name = k=v k=v
    re.compile(r"^%s[a-z0-9]*[_.][a-z0-9_.]*\s*:\s*(?:%s(?:\s+%s)?)?(?:%s)?$" % (_PREFIX, _TOKEN, _TOKEN, _COMMENT)),
)

# ------------------------------------------------------------------ reasons

PLACEHOLDER = "REASON REQUIRED"
REGEN_HEADER = "added by regen-pgbouncer-pool-mode-allow.py"
MIN_REASON_WORDS, MIN_REASON_CHARS = 6, 30

Unit = Tuple[str, int, str]  # (relative path, line number, normalised text)


def normalise(line: str) -> str:
    fence = line.strip()
    if FENCE.match(fence):
        return fence.casefold()  # kept whole: a fence is a neutral context line (R6)
    text = TAG.sub("", html.unescape(line))
    text = re.sub(r"[`*]", "", text)
    return " ".join(text.split()).casefold()


def _path_words(match: "re.Match[str]") -> str:
    return " " + " ".join(_PATH_KEEP.findall(match.group(0))) + " "


def mentions(text: str) -> bool:
    if not _QUICK.search(text):
        return False  # speed only: every R1/R2 pattern needs one of these words
    text = TOOL_PATH.sub(_path_words, text)
    return bool(MENTION_NAME.search(text) or MENTION_PROSE.search(text))


def approved(text: str) -> bool:
    """The whole line has one of the approved shapes (A1, A2). Nothing else is approved."""
    return any(shape.match(text) for _, shape in APPROVED_SHAPES)


def neutral(text: str) -> bool:
    """A context line that cannot qualify an approved line (R6): fence, section, short config line."""
    return not OTHER_MODE.search(text) and any(shape.match(text) for shape in NEUTRAL_SHAPES)


def reason_problem(reason: str) -> Optional[str]:
    """Why a reason comment is not a reason, or None when it is one."""
    words = reason.split()
    if not words:
        return "no reason comment above it"
    if PLACEHOLDER.casefold() in reason.casefold():
        return "the reason is the regen placeholder %r" % PLACEHOLDER
    if len(words) < MIN_REASON_WORDS or len(reason) < MIN_REASON_CHARS:
        return "the reason %r is shorter than a sentence (%d words / %d characters minimum)" % (
            reason[:60], MIN_REASON_WORDS, MIN_REASON_CHARS)
    return None


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


def _neighbours(lines: List[str], i: int) -> List[int]:
    """Indices of the NEIGHBOURS nearest non-blank lines before and after line i."""
    found: List[int] = []
    for step in (-1, 1):
        j, got = i + step, 0
        while 0 <= j < len(lines) and got < NEIGHBOURS:
            if lines[j]:
                found.append(j)
                got += 1
            j += step
    return found


def scan_lines(rel: str, lines: List[str]) -> List[Unit]:
    """The mention units of one file (rules R1-R6)."""
    units: List[Unit] = []
    is_mention = [bool(t) and mentions(t) for t in lines]
    pairs: Set[Tuple[int, int]] = set()

    def pair(a: int, b: int) -> None:
        lo, hi = min(a, b), max(a, b)
        if (lo, hi) not in pairs:
            pairs.add((lo, hi))
            units.append((rel, hi + 1, lines[lo] + " " + lines[hi]))

    for i, text in enumerate(lines):
        if is_mention[i]:
            units.append((rel, i + 1, text))
            ok = approved(text)
            for j in _neighbours(lines, i):
                if is_mention[j]:
                    continue  # judged on its own
                if ok and not neutral(lines[j]):
                    pair(i, j)  # R6: prose next to an approved line
                elif OTHER_MODE.search(lines[j]):
                    pair(i, j)  # R5: a mode word in the same paragraph
        elif text and i + 1 < len(lines) and lines[i + 1] and not is_mention[i + 1]:
            if mentions(text + " " + lines[i + 1]):
                pair(i, i + 1)  # R4: wrapped across a line break
    return units


def scan(root: Path) -> Tuple[List[Unit], int]:
    """Every mention unit and the number of files read."""
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
        units += scan_lines(rel, [normalise(l) for l in data.decode("utf-8", "replace").splitlines()])
    return units, read


def load_allowlist(root: Path) -> Tuple[List[Tuple[str, str]], List[str]]:
    """Entries and errors. Every entry needs a real reason (see reason_problem)."""
    entries: List[Tuple[str, str]] = []
    errors: List[str] = []
    path = root / ALLOW_REL
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], ["%s: unreadable: %s" % (ALLOW_REL, exc)]
    block: List[str] = []   # the comment block being read
    reason: Optional[str] = None  # the reason of the entry directly above, if any
    for number, line in enumerate(raw.splitlines(), 1):
        if line.lstrip().startswith("#") and "reason required" in line.casefold():
            # regen --accept-new writes this placeholder; an entry nobody gave a reason is not reviewed (#4961)
            errors.append("%s:%d: placeholder comment left by --accept-new; write the reason for each entry below it" % (ALLOW_REL, number))
            block, reason = [], None
            continue
        if not line.strip():
            block, reason = [], None
            continue
        if line.lstrip().startswith("#"):
            text = line.lstrip().lstrip("#").strip()
            if not text.startswith(REGEN_HEADER):
                block.append(text)
            reason = None
            continue
        if block:
            reason, block = " ".join(block), []
        if SEPARATOR not in line:
            errors.append("%s:%d: malformed entry (want `<file> | <normalised line>`)" % (ALLOW_REL, number))
            continue
        rel, text = line.split(SEPARATOR, 1)
        if not rel or " " in rel or not text or text != normalise(text):
            errors.append("%s:%d: malformed entry (file empty/has spaces, or text empty/not normalised)" % (ALLOW_REL, number))
            continue
        problem = reason_problem(reason or "")
        if problem:
            errors.append("%s:%d: entry without a written reason (%s)" % (ALLOW_REL, number, problem))
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
        findings.append("%s:%d: mentions a pooler mode without an approved session-mode shape: %s" % (rel, number, text[:170]))
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
    guide_ok = [u for u in units if u[0] == GUIDE_REL.as_posix() and approved(u[2])]
    if not guide_ok:
        return fault("%s holds no approved `pool_mode = session` line; the pin has nothing to compare (fail closed)" % GUIDE_REL)
    findings, stale = judge(units, entries)
    if stale:
        for line in stale:
            print("check-pgbouncer-pool-mode-claims: FAULT: %s" % line, file=sys.stderr)
        return EXIT_FAULT
    if findings:
        print("check-pgbouncer-pool-mode-claims: %d mention(s) of a pooler mode have no approved shape:" % len(findings))
        for finding in findings:
            print("  " + finding)
        print("  fix the wording to a bare `pool_mode = session` line, or run scripts/regen-pgbouncer-pool-mode-allow.py "
              "--accept-new --reason '<why each new line is safe>' and review the diff of %s." % ALLOW_REL)
        return EXIT_FINDING
    print("check-pgbouncer-pool-mode-claims: OK (%d files scanned; %d mention units; %d allowlisted; %d approved lines in %s)"
          % (read, len(units), len(entries), len(guide_ok), GUIDE_REL))
    return EXIT_OK


# ---------------------------------------------------------------- self-test

GOOD_GUIDE = "```ini\npool_mode = session\n```\n"
GOOD_INI = "[pgbouncer]\npool_mode = session\n"
REASON = "# reviewed: this line states the retired mode only to say it is withdrawn\n"

# Red probes: every wording the PR 4710 reviews planted, rounds 1 to 3.
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
    ("wrap: neither line mentions alone", "docs/a.md", "Put PgBouncer in front of the primary and\nswitch it to transaction for the daemon.\n"),
    ("html entity underscore", "docs/a.html", "<p>pool&#95;mode = transaction</p>\n"),
    ("split code spans", "docs/a.html", "<code>pool_mode</code> = <code>transaction</code>\n"),
    ("ini file, not markdown", "infra/other/pgb.ini", "pool_mode=transaction\n"),
    ("txt file", "notes/pooling.txt", "pool_mode = statement\n"),
    ("per-database override", "infra/pgbouncer/extra.ini", "ai_memory = host=pg dbname=ai_memory pool_mode=transaction\n"),
    ("[users] override", "infra/x/pgb.ini", "[users]\nai_memory = pool_mode=transaction\n"),
    ("retirement word nearby does not excuse (#4667)", "docs/a.md", "see #4667\nno longer an issue\npool_mode = transaction\n"),
    ("unrelated word nearby does not excuse", "docs/a.md", "an earlier revision\nPgBouncer in transaction mode\n"),
    # round 2 (#4741)
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
    ("pooling word alone, mode word in the same sentence", "docs/a.md", "Pooling client sessions by transaction suits the daemon.\n"),
    ("multiplexing, no product named", "docs/a.md", "Multiplexing statements onto fewer backends suits the daemon.\n"),
    ("bare yaml mode key", "deploy/supavisor.yaml", "supavisor:\n  mode: transaction\n"),
    ("bare ini mode key in a [pgbouncer] block", "docs/a.md", "[pgbouncer]\nmode = transaction\n"),
    ("inversion: pool_mode = session is unsafe", "docs/a.md", "Never use pool_mode = session for the daemon; it is unsafe.\n"),
    ("inversion: session mode is unsafe", "docs/a.md", "PgBouncer session mode is unsafe for the daemon.\n"),
    ("inversion: avoid session pooling", "docs/a.md", "Avoid session pooling; pool_mode = session wastes backends.\n"),
    # round 3 security review (#4950, #4741): neighbourhood of an approved line, abbreviations
    ("mode word on the line before an approved line", "docs/a.md", "For the most fan-in pick transaction; otherwise\npool_mode = session\n"),
    ("ini comment before the approved line", "infra/x/pgb.ini", "; transaction also works here\npool_mode = session\n"),
    ("three-line wrap after an approved line", "docs/a.md", "Set pool_mode = session or, if you need more fan-in\nand accept the risk described above,\ntransaction.\n"),
    ("blank line after an approved line", "docs/a.md", "pool_mode = session\n\nor transaction, for more fan-in.\n"),
    ("approved line then a mentioning line", "docs/a.md", "pool_mode = session\n(PgBouncer transaction mode also works)\n"),
    ("tx abbreviation with a pooler product", "docs/a.md", "Run PgBouncer in tx mode for the daemon.\n"),
    ("xact abbreviation with a pooler product", "docs/a.md", "PgBouncer xact pooling suits the daemon.\n"),
    # round 3 code review (#4960, #4951): inversions outside any word list, keys, plurals
    ("pooling_mode key alone (pins the pooling spelling)", "deploy/x.yaml", "pooling_mode: transaction\n"),
    ("bare mode key alone (pins the mode-key rule)", "deploy/x.conf", "  mode: transaction\n"),
    ("inversion outside any word list: stop using", "docs/a.md", "Stop using pool_mode = session.\n"),
    ("inversion outside any word list: breaks", "docs/a.md", "pool_mode = session breaks the daemon.\n"),
    ("inversion outside any word list: harmful", "docs/a.md", "pool_mode = session is harmful for the daemon.\n"),
    ("inversion wrapped onto the next line", "docs/a.md", "pool_mode = session\nis unsafe for the daemon.\n"),
    ("inversion two lines after, past a blank line", "docs/a.md", "pool_mode = session\n\nfor the daemon\nis harmful.\n"),
    ("inversion right after a closing code fence", "docs/a.md", "```ini\npool_mode = session\n```\nThe line above is unsafe.\n"),
    ("inversion in a free-text config comment", "infra/x/pgb.ini", "pool_mode = session ; stop using this\n"),
    ("plural: transaction modes", "docs/a.md", "Use transaction or statement modes for the daemon.\n"),
    ("plural: pool modes key", "docs/a.md", "pool_modes: transaction\n"),
    ("plural: transactions next to PgBouncer", "docs/a.md", "PgBouncer pools transactions for the daemon.\n"),
    ("a mode claim beside a tool path is still a mention", "docs/a.md", "Run scripts/probe-pgbouncer-pool-mode.py, then set pool_mode = transaction.\n"),
    ("product named only in a file name", "docs/a.md", "In pgbouncer.ini choose transaction for the daemon.\n"),
]

# Green probes: one per approved shape, plus neutral context and path tokens.
GREEN: List[Tuple[str, str, str]] = [
    ("A1 ini assignment", "docs/a.md", "pool_mode = session\n"),
    ("A1 yaml assignment", "deploy/pgb.yaml", "pool_mode: session\n"),
    ("A1 env assignment", "deploy/.env", "PGBOUNCER_POOL_MODE=session\n"),
    ("A1 compose list item, quoted", "deploy/compose.yml", "    - PGBOUNCER_POOL_MODE='session'\n"),
    ("A1 json member", "deploy/x.json", "  \"pool_mode\": \"session\",\n"),
    ("A2 assignment with a vocabulary comment", "infra/x/pgb.ini", "pool_mode = session ; supported mode\n"),
    ("A2 comment with a section and an issue", "infra/x/pgb.ini", "pool_mode = session ; supported mode, see 5.6.6 (#4667)\n"),
    ("R6 neutral context: config block", "infra/x/pgb.ini",
     "[pgbouncer]\nauth_type = scram-sha-256\npool_mode = session\nserver_reset_query = discard all ; pinned, see 5.6.6\nlisten_port = 6432\n"),
    ("R6 neutral context: fenced block, prose beyond two lines", "docs/a.md",
     "Set this:\n\n```ini\n[pgbouncer]\npool_mode = session\nlisten_port = 6432\n```\n\nThen reload.\n"),
    ("R6 a blank line inside the block is skipped, not judged", "docs/a.md",
     "```ini\npool_mode = session\n\nlisten_port = 6432\n```\n"),
    ("R6 neutral context: a [databases] line of key=value tokens", "infra/x/pgb.ini",
     "[databases]\nai_memory = host=pg port=5432 dbname=ai_memory\n[pgbouncer]\npool_mode = session\n"),
    ("R3 naming the gate or its allowlist is not a mention", "docs/a.md",
     "Run scripts/check-pgbouncer-pool-mode-claims.py; see scripts/qc-allowlists/pgbouncer-pool-mode-allow.txt.\n"),
    ("R3 a bare tool file name is not a mention", "docs/a.md", "regen-pgbouncer-pool-mode-allow.py rewrites the file.\n"),
    ("sqlx pool and a SQL transaction are not a pooler", "src/a.rs", "let mut tx = pool.begin().await?;\n"),
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


def cases() -> List[Tuple[str, Dict[str, str], int]]:
    out: List[Tuple[str, Dict[str, str], int]] = []
    for name, rel, body in PLANTED:
        out.append(("red: " + name, tree({rel: body}), EXIT_FINDING))
    for name, rel, body in GREEN:
        out.append(("green: " + name, tree({rel: body}), EXIT_OK))
    retired = {"docs/a.md": "Transaction mode is not supported (#4667).\n"}
    retired_entry = "docs/a.md | transaction mode is not supported (#4667).\n"
    out += [
        ("agreeing tree passes", tree(), EXIT_OK),
        ("session prose alone is not approved", tree({"docs/a.md": "PgBouncer session mode is supported.\n"}), EXIT_FINDING),
        ("session prose passes once allowlisted with a reason",
         tree({"docs/a.md": "PgBouncer session mode is supported.\n"}, REASON + "docs/a.md | pgbouncer session mode is supported.\n"), EXIT_OK),
        ("R5: an allowlisted line does not cover a mode word on the next line",
         tree({"docs/a.md": "PgBouncer session mode is supported, or\nstatement.\n"},
              REASON + "docs/a.md | pgbouncer session mode is supported, or\n"), EXIT_FINDING),
        ("a mixed line (session and transaction) is not approved", tree({"docs/a.md": "pool_mode = session, not transaction mode\n"}), EXIT_FINDING),
        ("allowlisted retirement line passes", tree(retired, REASON + retired_entry), EXIT_OK),
        ("an entry continues the reason of the entry above",
         tree({"docs/a.md": "Transaction mode is not supported.\nx\nStatement mode is not supported.\n"},
              REASON + "docs/a.md | transaction mode is not supported.\ndocs/a.md | statement mode is not supported.\n"), EXIT_OK),
        ("allowlist entry is bound to its file",
         tree({"docs/b.md": "Transaction mode is not supported (#4667).\n"}, REASON + retired_entry), EXIT_FAULT),
        ("stale allowlist entry fails", tree({}, REASON + "docs/gone.md | pool_mode = transaction\n"), EXIT_FAULT),
        ("malformed allowlist entry fails", tree({}, REASON + "no separator here\n"), EXIT_FAULT),
        ("an entry beyond the occurrence count is stale",
         tree({"docs/a.md": "Transaction mode is not supported.\n"},
              REASON + "docs/a.md | transaction mode is not supported.\ndocs/a.md | transaction mode is not supported.\n"), EXIT_FAULT),
        ("one entry does not cover a second occurrence",
         tree({"docs/a.md": "Transaction mode is not supported.\nx\nTransaction mode is not supported.\n"},
              REASON + "docs/a.md | transaction mode is not supported.\n"), EXIT_FINDING),
        ("non-normalised allowlist text fails",
         tree({"docs/a.md": "Transaction mode is not supported.\n"}, REASON + "docs/a.md | Transaction mode is not supported.\n"), EXIT_FAULT),
        # reasons (#4961): the placeholder, no reason, a short reason, a reason cut off by a blank line
        ("regen placeholder left in the allowlist fails",
         tree(retired, "# REASON REQUIRED before review - say why each line below is safe\n" + retired_entry), EXIT_FAULT),
        ("placeholder in any wording or case fails", tree(retired, "# reason required: todo\n" + REASON + retired_entry), EXIT_FAULT),
        ("a placeholder line above a blank line still fails",
         tree(retired, "# REASON REQUIRED before review\n\n" + REASON + retired_entry), EXIT_FAULT),
        ("an entry with no reason comment fails", tree(retired, retired_entry), EXIT_FAULT),
        ("an entry whose reason is only the regen date header fails",
         tree(retired, "# added by regen-pgbouncer-pool-mode-allow.py --accept-new on 2026-10-04:\n" + retired_entry), EXIT_FAULT),
        ("a reason shorter than a sentence fails", tree(retired, "# ok\n" + retired_entry), EXIT_FAULT),
        ("a blank line ends a reason", tree(retired, REASON + "\n" + retired_entry), EXIT_FAULT),
        # fail closed
        ("fail closed: guide with no approved pool_mode line", tree(guide="No pooler section here.\n"), EXIT_FAULT),
        ("fail closed: guide with only session prose", tree(guide="Use pool_mode = session in production.\n"), EXIT_FAULT),
        ("fail closed: template with two active pool_mode lines", tree(ini=GOOD_INI + "pool_mode = session\n"), EXIT_FAULT),
        ("fail closed: template mode is transaction", tree(ini="[pgbouncer]\npool_mode = transaction\n"), EXIT_FAULT),
        ("fail closed: missing allowlist file", {k: v for k, v in tree().items() if k != ALLOW_REL.as_posix()}, EXIT_FAULT),
    ]
    return out


def _scratch_base() -> str:
    base = os.environ.get("TMPDIR") or str(REPO_ROOT / ".local-runs")
    Path(base).mkdir(parents=True, exist_ok=True)
    return base


def run_cases(verbose: bool) -> int:
    scratch_base = _scratch_base()
    failures = 0
    for name, files, want in cases():
        with tempfile.TemporaryDirectory(dir=scratch_base) as tmp:
            root = Path(tmp)
            write_tree(root, files)
            got = run_quiet(root)
        ok = got == want
        failures += 0 if ok else 1
        if verbose or not ok:
            print("self-test %s %-70s want=%d got=%d" % ("ok  " if ok else "FAIL", name, want, got))
    return failures


# One mutant per rule: the source edit that disables the rule. The self-test runs
# the case set against each mutated copy (in scratch, never in place) and needs at
# least one case to fail; a mutant that survives, or whose text is absent from this
# file, fails the self-test.
MUTANTS: List[Tuple[str, str, str]] = [
    ("R1 name rule", 'MENTION_NAME = re.compile(POOL_MODE + r"s?")', 'MENTION_NAME = re.compile(r"(?!)")'),
    ("R1 pooling spelling", 'POOL_MODE = r"pool(?:ing)?[\\s_-]*mode"', 'POOL_MODE = r"pool[\\s_-]*mode"'),
    ("R1 plural key", 'MENTION_NAME = re.compile(POOL_MODE + r"s?")', 'MENTION_NAME = re.compile(POOL_MODE + r"\\b")'),
    ("R2 abbreviations tx/xact", '|statements?|txn|tx|xact)"', '|statements?|txn)"'),
    ("R2 plural modes", "(?:modes?|pooling|pooler|pools?)", "(?:mode|pooling|pooler|pool)"),
    ("R2 plural transactions", '_MODE_WORD = r"(?:transaction(?:s|al)?|', '_MODE_WORD = r"(?:transaction(?:al)?|'),
    ("R2 transactional", '_MODE_WORD = r"(?:transaction(?:s|al)?|', '_MODE_WORD = r"(?:transactions?|'),
    ("R2 multiplex counts as a pooler word", '_POOLER = r"(?:pgbouncer|pooler|pooling|odyssey|supavisor|pgcat|multiplex(?:es|ed|ing)?)"', '_POOLER = r"(?:pgbouncer|pooler|pooling|odyssey|supavisor|pgcat)"'),
    ("R2 session next to a pool word", '_ANY_MODE = r"(?:%s|sessions?)" % _MODE_WORD', '_ANY_MODE = r"(?:%s)" % _MODE_WORD'),
    ("R2 pooling word in _POOLER", '_POOLER = r"(?:pgbouncer|pooler|pooling|', '_POOLER = r"(?:pgbouncer|pooler|'),
    ("R2 product anywhere on the line", '    r"|\\b%s\\b.*?\\b%s\\b|\\b%s\\b.*?\\b%s\\b"\n', '    r"|\\b%s\\b(?!)\\b%s\\b|\\b%s\\b(?!)\\b%s\\b"\n'),
    ("R2 bare mode key", 'r"|\\bmode\\s*[:=]\\s*[\\"\']?%s\\b"', 'r"|(?!)%s"'),
    ("R3 path tokens", "    text = TOOL_PATH.sub(_path_words, text)\n", ""),
    ("R3 path keeps product words", 'return " " + " ".join(_PATH_KEEP.findall(match.group(0))) + " "', 'return " "'),
    ("R4 wrap", "                pair(i, i + 1)  # R4", "                pass  # R4"),
    ("R5 paragraph", "                    pair(i, j)  # R5", "                    pass  # R5"),
    ("R6 approved-line context", "                    pair(i, j)  # R6", "                    pass  # R6"),
    ("R6 key=value tokens are neutral", '    re.compile(r"^[a-z_][a-z0-9_.]*\\s*=\\s*(?:%s\\s*)+$" % _KV_TOKEN),', '    re.compile(r"(?!)"),'),
    ("R6 blank lines skipped", "            if lines[j]:\n                found.append(j)", "            if True:\n                found.append(j)"),
    ("A1/A2 closed shapes (prose approves again)", "    return any(shape.match(text) for _, shape in APPROVED_SHAPES)",
     '    return bool(re.search(r"pool_mode = session", text)) and not OTHER_MODE.search(text)'),
    ("A2 closed comment vocabulary", '_COMMENT = r"\\s*[;#]\\s*%s(?:[\\s,.]+%s)*[\\s,.]*" % (_VOCAB, _VOCAB)', '_COMMENT = r"\\s*[;#].*"'),
    ("allowlist reason required", "        problem = reason_problem(reason or \"\")\n", "        problem = None\n"),
    ("allowlist placeholder", 'if line.lstrip().startswith("#") and "reason required" in line.casefold():', "if False:"),
    ("allowlist reason length", "    if len(words) < MIN_REASON_WORDS or len(reason) < MIN_REASON_CHARS:", "    if not words:"),
    ("allowlist per-occurrence budget", "            budget[(rel, text)] -= 1\n", ""),
    ("guide pin", "    if not guide_ok:\n", "    if False:\n"),
]


def run_mutants() -> int:
    """Kill every mutant; return the number that survived or did not apply."""
    src = Path(__file__).read_text(encoding="utf-8")
    cut = src.index("\nMUTANTS: List[")  # the rules live above the table; the table itself is not mutated
    head, table = src[:cut], src[cut:]
    scratch_base = _scratch_base()
    bad = 0
    for label, old, new in MUTANTS:
        if head.count(old) != 1:
            bad += 1
            print("self-test FAIL mutant %-44s does not apply (text found %d times)" % (label, head.count(old)))
            continue
        with tempfile.TemporaryDirectory(dir=scratch_base) as tmp:
            copy = Path(tmp) / "gate.py"
            copy.write_text(head.replace(old, new) + table, encoding="utf-8")
            out = subprocess.run([sys.executable, str(copy), "--cases-only"], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, universal_newlines=True, check=False)
        killed = out.returncode != 0
        bad += 0 if killed else 1
        first = next((l for l in out.stdout.splitlines() if "FAIL" in l), "")
        print("self-test %s mutant %-44s %s %s" % ("ok  " if killed else "FAIL", label,
                                                   "killed by" if killed else "SURVIVED", first[15:90].strip()))
    return bad


def self_test() -> int:
    failures = run_cases(verbose=True)
    failures += run_mutants()
    failures += mutate_real_allowlist()
    if failures:
        print("check-pgbouncer-pool-mode-claims: SELF-TEST FAILED (%d case(s))" % failures, file=sys.stderr)
        return EXIT_FAULT
    print("check-pgbouncer-pool-mode-claims: self-test OK (%d cases: %d red probes, %d green probes; %d of %d mutants killed; real allowlist load-bearing)"
          % (len(cases()), len(PLANTED), len(GREEN), len(MUTANTS), len(MUTANTS)))
    return EXIT_OK


def mutate_real_allowlist() -> int:
    """Every real allowlist entry is load-bearing: damaging any one must fail the gate."""
    if not (REPO_ROOT / ALLOW_REL).is_file():
        print("self-test FAIL real allowlist missing")
        return 1
    units, _ = scan(REPO_ROOT)
    entries, errors = load_allowlist(REPO_ROOT)
    if errors:
        print("self-test FAIL real allowlist has %d fault(s), first: %s" % (len(errors), errors[0]))
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
    parser.add_argument("--self-test", action="store_true", help="red and green probes, a mutant per rule, allowlist mutations")
    parser.add_argument("--cases-only", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(list(argv))
    if args.cases_only:
        return EXIT_FAULT if run_cases(verbose=False) else EXIT_OK
    if args.self_test:
        return self_test()
    try:
        return run(Path(args.root).resolve())
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_FAULT


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
