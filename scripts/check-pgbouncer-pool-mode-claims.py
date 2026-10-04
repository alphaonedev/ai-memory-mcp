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
            Long lines (over 4096 characters) are read in overlapping segments
               plus a product-and-mode-word test over the whole line.
            R9 unreadable characters (closed world, #4667 R6): a line whose
               shadow view still holds a character outside DECLARED (printable
               ASCII and a short typographic set) next to an ASCII letter, and
               that names a pool, mode or product word, is a unit of its own;
               a line with U+FFFD (an invalid byte in the file) is one whatever
               its words. Such a character can hide a word from every pattern,
               so the line is red unless an allowlist entry, written by regen
               with a reason, names it. Approved shapes hold DECLARED
               characters only.
            R8 key (closed world): a pooler-prefixed key ending in `mode`
               (pgb_mode, PGBOUNCER_MODE, supavisor-mode, a Terraform variable
               "pgb_mode") whatever its value: a variable, a default on another
               line or a template is not the literal `session`, so it needs an
               allowlist entry with a reason.
            R3 path tokens: a file path or file name (`a/b`, `x.py`) is reduced
               to the product and mode words it contains before R1/R2 run, so
               naming scripts/check-pgbouncer-pool-mode-claims.py is not a
               mention, while `pgbouncer.ini ... transaction` still is.
            R4 wrap: two adjacent lines that only mention when joined.
            R5 paragraph: a line that names a mode word within the two nearest
               non-blank lines (blank lines skipped), or anywhere in the same
               paragraph up to PARAGRAPH_MAX lines away (#4950), of a mention
               line is joined with it and judged as one unit.
            R6 approved-line context: each of the two nearest non-blank lines on
               either side of an approved line must itself be a mention (judged
               on its own) or a NEUTRAL line: a code fence, a config section
               header, or a short config `key = value` line with no mode word.
               Anything else (prose, a prose comment) is joined with the
               approved line and judged as one unit, so `pool_mode = session`
               followed by "is unsafe" is not approved.
            R7 context binding (#5087, #5088): every allowlist entry ends in
               ` | ctx:<12 hex>`, a fingerprint of the lines around its unit (the
               nearest non-blank lines and the paragraph, without the unit's own
               lines). When a line next to an allowlisted one changes, even with
               no mode word, the entry is stale and the neighbourhood goes back
               to review: regen-pgbouncer-pool-mode-allow.py --refresh-context
               re-binds it after a human re-reads the lines.
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
import hashlib
import html
import os
import re
import subprocess
import sys
import tempfile
import unicodedata
import codecs
from pathlib import Path
from collections import Counter
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

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
_MODE_WORD = r"(?:transaction(?:s|al)?|statements?|txn|tx|xact|stmts?|trx|xaction|trans)"
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
    r"|\bmode(?:[\s_-]*type)?\s*[:=]\s*[\"']?%s\b"
    % (_ANY_MODE, _ANY_MODE, _POOLER, _MODE_WORD, _MODE_WORD, _POOLER,
       _PRODUCT, _MODE_WORD, _MODE_WORD, _PRODUCT, _MODE_WORD)
)
# R8 (closed world, #4741): a pooler-prefixed key that ends in `mode` (pgb_mode, PGBOUNCER_MODE, pgcat.mode,
# supavisor-mode, a Terraform variable "pgb_mode") is a mention whatever its value or its line: the value may be a
# variable or a default on another line, so only the literal `session` assignment (A1/A2) is approved.
MENTION_KEY = re.compile(r"\b(?:pgbouncer|pgb|pgcat|odyssey|supavisor|pooler|pool(?:ing)?)(?:[_.-][a-z0-9]+)*[_.-]mode\b")
OTHER_MODE = re.compile(r"\b%s\b" % _MODE_WORD)
_QUICK = re.compile(r"mode|pool|pgbouncer|odyssey|supavisor|pgcat|multiplex|pgb")
# R3: a file path (has a slash) or a file name (has a known extension).
TOOL_PATH = re.compile(
    r"[\w.~+-]*(?:/[\w.~+#%-]*)+"
    r"|\b[\w-]+(?:\.[\w-]+)*\.(?:py|txt|md|ini|sh|rs|toml|ya?ml|json|sql|conf|cfg|html?|tf|env|log)\b")
_PATH_KEEP = re.compile(r"pgbouncer|pooler|odyssey|supavisor|pgcat|transaction(?:s|al)?|statements?|sessions?|txn|xact|\btx\b")

TAG = re.compile(r"<[^>]*>")
# A line longer than LONG_LINE (minified JSON, a data blob) is never handed to the backtracking patterns whole: a
# megabyte-long line would take quadratic time. Its tags are matched with a bounded pattern, and mentions() reads it
# in overlapping segments plus one linear product-and-mode-word test, so it is judged, never skipped (#5090).
LONG_LINE = 4096
SEGMENT, SEGMENT_STEP = 2048, 1536
TAG_LONG = re.compile(r"<[^<>]{0,512}>")
_PRODUCT_WORD = re.compile(r"\b%s\b" % _PRODUCT)
INI_ACTIVE = re.compile(r"^\s*pool_mode\s*=\s*([A-Za-z]+)\s*(?:[;#].*)?$")
# Reading (#5086, #5090): a file is streamed in chunks and judged in line windows, so size is never a reason to
# skip it. A file the gate cannot read as text (NUL bytes outside UTF-16/32, or a binary magic number such as gzip,
# zip, png, pdf) is named in UNREAD_REL with a written reason, or the gate fails: nothing is skipped silently.
UNREAD_REL = Path("scripts") / "qc-allowlists" / "pgbouncer-pool-mode-unread.txt"
CHUNK_BYTES = 1 << 20
WINDOW_LINES = 20000
BINARY_MAGIC = (b"\x1f\x8b", b"PK\x03\x04", b"BZh", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd", b"\x89PNG", b"%PDF",
                b"\xff\xd8\xff", b"\0asm", b"\x7fELF", b"SQLite format 3\0", b"GIF8", b"wOFF", b"wOF2", b"OTTO",
                b"\x00\x01\x00\x00\x00", b"\x1f\x9d", b"7z\xbc\xaf\x27\x1c", b"Rar!")
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
# A1 (#4667 R4): an allowlist entry may describe a non-session mode, never set one. A whole-line
# assignment of transaction/statement (any key spelling, ini/yaml/env/json/toml/compose form) or a
# config line carrying a pool_mode=transaction token is refused (rc 2), whatever its reason says.
FORBIDDEN_ENTRY = (
    re.compile(r"^(?:[-*>]\s*)*[\"']?[a-z0-9_.]*mode(?:[_-]?type)?[\"']?\s*[=:]\s*[\"']?(?:transaction|statement)[\"']?,?\s*(?:[;#].*)?$"),
    re.compile(r"^[a-z_][a-z0-9_.]*\s*=\s*(?:[a-z_][a-z0-9_.-]*=[^\s;#]*\s*)*pool_mode=(?:transaction|statement)\b"),
    re.compile(r"^pool\s+[\"']?(?:transaction|statement)[\"']?$"),
)
FILLER = re.compile(r"\b(?:todo|tbd|fixme|xxx|lorem|ipsum|placeholder|n/?a|tk)\b")
MIN_DISTINCT_WORDS = 5
REGEN_HEADER = "added by regen-pgbouncer-pool-mode-allow.py"
MIN_REASON_WORDS, MIN_REASON_CHARS = 6, 30

Unit = Tuple[str, int, str, str]  # (relative path, line number, normalised text, context fingerprint)
Entry = Tuple[str, str, str]  # (relative path, normalised text, context fingerprint)
CTX = re.compile(r" \| ctx:([0-9a-f]{12})$")  # R7: an allowlist entry is bound to its neighbourhood


def normalise(line: str) -> str:
    fence = line.strip()
    if FENCE.match(fence):
        return fence.casefold()  # kept whole: a fence is a neutral context line (R6)
    text = (TAG_LONG if len(line) > LONG_LINE else TAG).sub("", html.unescape(line))
    text = re.sub(r"[`*]", "", text)
    return " ".join(text.split()).casefold()


def _path_words(match: "re.Match[str]") -> str:
    return " " + " ".join(_PATH_KEEP.findall(match.group(0))) + " "


# U1 (#4667 R4): look-alike letters folded to ASCII for mention detection only.
CONFUSABLE = {ord(k): v for k, v in {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y", "\u0445": "x",
    "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u0501": "d", "\u04bb": "h", "\u0442": "t", "\u043c": "m",
    "\u043d": "h", "\u0432": "b", "\u043a": "k", "\u0261": "g", "\u03bf": "o", "\u03c1": "p", "\u03c4": "t",
    "\u03bd": "v", "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k", "\u03c5": "u", "\u03c7": "x",
    "\u0131": "i", "\u017f": "s",
    # R5: dashes NFKD keeps (transaction\u2011mode reads as transaction-mode)
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-", "\u2212": "-", "\ufe58": "-", "\ufe63": "-",
}.items()}
# R5: letters that render as nothing (Hangul fillers, braille blank) are dropped like format characters.
_INVISIBLE = dict.fromkeys(map(ord, "\u115f\u1160\u3164\uffa0\u2800\u17b4\u17b5"), None)
# R5: a word of mostly ASCII letters with one or two other characters (a look-alike outside CONFUSABLE, or U+FFFD
# where an invalid byte was) is read as the key word it spells when those characters are dropped or wildcarded.
_KEY_WORDS = ("transaction", "transactions", "transactional", "statement", "statements", "pgbouncer", "pooling",
              "pooler", "pool", "mode", "session", "sessions", "odyssey", "supavisor", "pgcat", "multiplexing")
_TOKEN = re.compile(r"(?:[^\W_]|\ufffd)+")


def _fold_word(match: "re.Match[str]") -> str:
    word = match.group(0)
    other = sum(1 for c in word if not c.isascii())
    if not other or other > 2 or len(word) - other < 3:
        return word
    dropped = "".join(c for c in word if c.isascii())
    wild = re.compile("".join(re.escape(c) if c.isascii() else "." for c in word))
    for key in _KEY_WORDS:
        if dropped == key or wild.fullmatch(key):
            return key
    return word
# U2/S1 (#4667 R4): separators that hide a word boundary from \b: underscore, quotes, brackets.
_SEPARATORS = re.compile(r"[\"'{}\[\](),]|_(?=mode)|(?<=pgbouncer)_")


_PG_SPLIT = re.compile(r"\bpg[\s_-]+bouncer", re.I)


def shadow(text: str) -> str:
    """Mention-detection view of a normalised line: NFKD, format and combining marks dropped,
    look-alikes folded, `pg bouncer` spellings joined. The unit text (allowlist key) is unchanged."""
    t = unicodedata.normalize("NFKD", text)
    t = "".join(c for c in t if unicodedata.category(c) not in ("Cf", "Mn")).translate(CONFUSABLE).translate(_INVISIBLE).casefold()
    t = _TOKEN.sub(_fold_word, t)
    return re.sub(r"\bpg[\s_-]+bouncer", "pgbouncer", t)


# R9 (#4667 round 6, closed world): the characters a reader can trust to show what they are. Printable ASCII and a
# short typographic set (curly quotes, dashes, ellipsis, arrows, section sign, middle dot, inequality and
# multiplication signs, box-drawing lines); everything else that touches an ASCII letter after the shadow fold may
# hide a word, and U+FFFD marks an invalid byte the decoder replaced.
DECLARED = frozenset(map(chr, range(0x20, 0x7F))) | frozenset(
    "\u2018\u2019\u201c\u201d\u2013\u2014\u2026\u2190\u2192\u2194\u21d2\u00a7\u00b7\u00d7\u2264\u2265\u2500\u2502")
_ANSI_CSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")  # colour codes in recorded terminal logs render as nothing


def _ascii_letter(c: str) -> bool:
    return c.isascii() and c.isalpha()


def hidden_chars(text: str) -> str:
    """The characters of a normalised line that may hide a word (R9), sorted, or "" when there are none."""
    if text.isascii() and text.isprintable():
        return ""
    found = {"\ufffd"} if "\ufffd" in text else set()
    view = shadow(_ANSI_CSI.sub("", text))
    for i, c in enumerate(view):
        if c in DECLARED or c.isspace():
            continue
        if (i and _ascii_letter(view[i - 1])) or (i + 1 < len(view) and _ascii_letter(view[i + 1])):
            found.add(c)
    return "".join(sorted(found))


def unreadable(text: str) -> bool:
    """R9: a line that may hide a pooler claim: U+FFFD anywhere, or a hiding character on a line that names a
    pool, mode or product word."""
    hidden = hidden_chars(text)
    return bool(hidden) and ("\ufffd" in hidden or bool(_QUICK.search(shadow(text))))


def _mentions_one(text: str) -> bool:
    if not _QUICK.search(text):
        return False  # speed only: every R1/R2 pattern needs one of these words
    text = TOOL_PATH.sub(_path_words, text)
    if MENTION_NAME.search(text) or MENTION_PROSE.search(text) or MENTION_KEY.search(text):
        return True
    split = _SEPARATORS.sub(" ", text)  # PGB_MODE=x, {"mode": "x"}, pool "x", PGBOUNCER_MODE: x
    return bool(MENTION_NAME.search(split) or MENTION_PROSE.search(split))


def _mentions_long(text: str) -> bool:
    for start in range(0, len(text), SEGMENT_STEP):
        if mentions(text[start:start + SEGMENT]):
            return True
    view = text if text.isascii() else shadow(text)
    return bool(_PRODUCT_WORD.search(view) and OTHER_MODE.search(view))  # a product and a mode word anywhere on the line


def mentions(text: str) -> bool:
    if len(text) > LONG_LINE:
        return _mentions_long(text)
    if _mentions_one(text):
        return True
    if text.isascii() and not _PG_SPLIT.search(text):
        return False  # the shadow view only differs for non-ASCII text or a split `pg bouncer`
    alt = shadow(text)
    return alt != text and _mentions_one(alt)


def approved(text: str) -> bool:
    """The whole line has one of the approved shapes (A1, A2). Nothing else is approved."""
    if not all(c in DECLARED for c in text):
        return False  # R9: an approved line holds DECLARED characters only
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
    if FILLER.search(reason.casefold()) or len(set(w.casefold() for w in words)) < MIN_DISTINCT_WORDS:
        return "the reason %r is filler, not a reason" % reason[:60]
    return None


def forbidden_entry(text: str) -> bool:
    """An entry text that sets a non-session mode (A1 R4): never allowlistable."""
    return any(shape.match(text) for shape in FORBIDDEN_ENTRY)


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


PARAGRAPH_MAX = 8  # R5 (#4950): lines of the same paragraph inspected on each side of a mention


def _paragraph(lines: List[str], i: int) -> List[int]:
    """Indices of the non-blank lines of line i's paragraph, at most PARAGRAPH_MAX lines away on each side."""
    found: List[int] = []
    for step in (-1, 1):
        j = i + step
        while 0 <= j < len(lines) and lines[j] and abs(j - i) <= PARAGRAPH_MAX:
            found.append(j)
            j += step
    return found


def scan_lines(rel: str, lines: List[str], base: int = 0, core: Optional[Tuple[int, int]] = None) -> List[Unit]:
    """The mention units of one file (rules R1-R6). `lines` may be a window of a larger file: `base` is the
    absolute index of lines[0], `core` the range of anchors this window answers for. Every pair has exactly one
    anchor (the mention line for R5/R6, the first line for R4), and cores are disjoint, so no pair repeats."""
    raw: List[Tuple[int, str, Tuple[int, ...]]] = []
    lo_core, hi_core = core if core is not None else (0, len(lines))
    is_mention = [bool(t) and mentions(t) for t in lines]

    def pair(a: int, b: int) -> None:
        lo, hi = min(a, b), max(a, b)
        raw.append((base + hi + 1, lines[lo] + " " + lines[hi], (lo, hi)))

    for i in range(lo_core, hi_core):
        text = lines[i]
        if is_mention[i]:
            raw.append((base + i + 1, text, (i,)))
            ok = approved(text)
            for j in sorted(set(_neighbours(lines, i)) | set(_paragraph(lines, i))):
                if is_mention[j]:
                    continue  # judged on its own
                if ok and not neutral(lines[j]):
                    pair(i, j)  # R6: prose next to an approved line
                elif OTHER_MODE.search(lines[j]):
                    pair(i, j)  # R5: a mode word in the same paragraph
        elif text:
            if unreadable(text):
                raw.append((base + i + 1, text, (i,)))  # R9: a character that may hide a word
            if i + 1 < len(lines) and lines[i + 1] and not is_mention[i + 1] and mentions(text + " " + lines[i + 1]):
                pair(i, i + 1)  # R4: wrapped across a line break
    return [(rel, number, text, context(lines, idx)) for number, text, idx in raw]


def context(lines: List[str], idx: Sequence[int]) -> str:
    """R7 (#5087, #5088): fingerprint of the lines around a unit (the nearest non-blank lines and the paragraph, as
    R5/R6 read them), without the unit's own lines. An allowlist entry carries it, so an edit next to an allowlisted
    line that names no mode word (a reversal) makes the entry stale and sends the neighbourhood back to review."""
    near = sorted({j for k in idx for j in set(_neighbours(lines, k)) | set(_paragraph(lines, k))} - set(idx))
    return hashlib.sha256("\n".join(lines[j] for j in near).encode("utf-8")).hexdigest()[:12]


WINDOW_MARGIN = 2 * PARAGRAPH_MAX + 2 * NEIGHBOURS  # non-blank lines kept on each side of a window: a pair's context reaches a paragraph (PARAGRAPH_MAX) beyond its far line, plus the neighbours


def _margin_index(lines: List[str], start: int, step: int) -> Optional[int]:
    """Index of the WINDOW_MARGIN-th non-blank line walking from `start` by `step`, or None if there are fewer."""
    got, j = 0, start
    while 0 <= j < len(lines):
        if lines[j]:
            got += 1
            if got == WINDOW_MARGIN:
                return j
        j += step
    return None


def scan_stream(rel: str, raw_lines: Iterable[str]) -> List[Unit]:
    """scan_lines over a stream: windows of WINDOW_LINES anchors, each with WINDOW_MARGIN non-blank lines of
    left and right margin, so the units equal those of one pass over the whole file."""
    units: List[Unit] = []
    buf: List[str] = []
    base = start = 0
    retry_at = WINDOW_LINES
    for raw in raw_lines:
        buf.append(normalise(raw))
        if len(buf) - start < retry_at:
            continue
        cut = _margin_index(buf, len(buf) - 1, -1)  # buf[cut:] holds WINDOW_MARGIN non-blank lines
        if cut is None or cut <= start:
            retry_at = len(buf) - start + WINDOW_LINES  # a long blank run: look again later, not on every line
            continue
        units += scan_lines(rel, buf, base, (start, cut))
        keep = _margin_index(buf, cut - 1, -1) or 0
        base += keep
        buf = buf[keep:]
        start = cut - keep
        retry_at = WINDOW_LINES
    units += scan_lines(rel, buf, base, (start, len(buf)))
    return units


class Unreadable(Exception):
    """A tracked file the gate cannot read as text (named with a reason in UNREAD_REL, or a FAULT)."""


def _decoder_for(head: bytes):
    if head[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        return codecs.getincrementaldecoder("utf-32")("replace")
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return codecs.getincrementaldecoder("utf-16")("replace")
    zeros = [i for i, b in enumerate(head[:CHUNK_BYTES]) if b == 0]
    if len(zeros) * 4 >= min(len(head), CHUNK_BYTES) > 0:  # BOM-less UTF-16: NULs sit on one byte parity
        odd = sum(1 for i in zeros if i % 2)
        if odd * 10 >= len(zeros) * 9:
            return codecs.getincrementaldecoder("utf-16-le")("replace")
        if (len(zeros) - odd) * 10 >= len(zeros) * 9:
            return codecs.getincrementaldecoder("utf-16-be")("replace")
    return None


def _plain_text(chunk: bytes) -> bool:
    """R5 (#4667): a chunk with no NUL that decodes as UTF-8 is text even when it starts like a magic number
    (GIF8, %PDF, BZh, OTTO, Rar!, wOFF are printable ASCII and can open a markdown file)."""
    if b"\0" in chunk:
        return False
    try:
        codecs.getincrementaldecoder("utf-8")("strict").decode(chunk, final=False)
    except UnicodeDecodeError:
        return False
    return True


# R5 (#4667): a file with one of these extensions is text by name and is never excused by the skip list: a NUL
# byte in it is a defect to fix, not a reason to stop reading it.
TEXT_SUFFIXES = {".md", ".markdown", ".txt", ".rst", ".adoc", ".html", ".htm", ".rs", ".py", ".sh", ".toml", ".yaml",
                 ".yml", ".json", ".ini", ".conf", ".cfg", ".tf", ".env", ".sql", ".log", ".csv", ".xml", ".svg"}


def read_lines(path: Path) -> Iterator[str]:
    """The lines of a text file, streamed. Raises Unreadable for binary content; an OSError propagates."""
    with open(str(path), "rb") as handle:
        chunk = handle.read(CHUNK_BYTES)
        if chunk.startswith(BINARY_MAGIC) and not _plain_text(chunk):
            raise Unreadable("binary or compressed content (magic number %s)" % chunk[:4].hex())
        decoder = _decoder_for(chunk)
        utf8 = decoder is None
        if utf8:
            decoder = codecs.getincrementaldecoder("utf-8")("replace")
        carry = ""
        while True:
            if utf8 and b"\0" in chunk:
                raise Unreadable("NUL bytes in a file that is not UTF-16/32 text")
            text = carry + decoder.decode(chunk, final=not chunk)
            carry = ""
            lines = text.splitlines(keepends=True)
            if chunk and lines and (lines[-1].splitlines()[0] == lines[-1] or lines[-1].endswith("\r")):
                carry = lines.pop()  # an unterminated tail, or a \r that may be half of \r\n
            for line in lines:
                yield line.splitlines()[0] if line.splitlines() else ""
            if not chunk:
                break
            chunk = handle.read(CHUNK_BYTES)
        if carry:
            yield carry


def scan_detail(root: Path) -> Tuple[List[Unit], int, Dict[str, str]]:
    """(mention units, files read, {path: why} of files that could not be read as text)."""
    units: List[Unit] = []
    read = 0
    unread: Dict[str, str] = {}
    for rel in tracked_files(root):
        if Path(rel) in (ALLOW_REL, SELF_REL, UNREAD_REL):
            continue
        path = root / rel
        if not path.is_file() or path.is_symlink():
            continue
        try:
            found = scan_stream(rel, read_lines(path))  # an OSError propagates: run() reports a FAULT
        except Unreadable as exc:
            unread[rel] = str(exc)
            continue
        read += 1
        units += found
    return units, read, unread


def load_unread(root: Path) -> Tuple[Dict[str, str], List[str]]:
    """{path: reason} of the files named as unreadable, and the errors. One exact path per line under a reason."""
    listed: Dict[str, str] = {}
    errors: List[str] = []
    try:
        raw = (root / UNREAD_REL).read_text(encoding="utf-8")
    except FileNotFoundError:
        return listed, errors  # no file: nothing is excused
    except OSError as exc:
        return {}, ["%s: unreadable: %s" % (UNREAD_REL, exc)]
    block: List[str] = []
    reason: Optional[str] = None
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            block, reason = [], None
            continue
        if line.lstrip().startswith("#"):
            text = line.lstrip().lstrip("#").strip()
            if "reason required" in text.casefold():
                errors.append("%s:%d: placeholder comment left by --accept-new; write the reason for each path below it" % (UNREAD_REL, number))
            elif not text.startswith(REGEN_HEADER):
                block.append(text)
            reason = None
            continue
        if block:
            reason, block = " ".join(block), []
        problem = reason_problem(reason or "")
        if not problem and Path(line).suffix.lower() in TEXT_SUFFIXES:
            problem = "a %s file is text and is read, never skipped" % Path(line).suffix.lower()
        if " " in line or problem or line in listed:
            errors.append("%s:%d: bad skip entry %r (%s)" % (UNREAD_REL, number, line[:80],
                          problem or "one exact path without spaces, listed once"))
            continue
        listed[line] = reason or ""
    return listed, errors


def scan(root: Path) -> Tuple[List[Unit], int]:
    """Every mention unit and the number of files read. An unreadable file that is not on the skip list, a skip
    entry that names a readable or untracked file, and a bad skip list are all errors (OSError)."""
    units, read, unread = scan_detail(root)
    listed, errors = load_unread(root)
    missing = ["%s: %s" % (rel, why) for rel, why in sorted(unread.items()) if rel not in listed]
    stale = ["%s: skip entry for a file that is readable or no longer tracked" % rel for rel in sorted(listed) if rel not in unread]
    problems = errors + ["files the gate cannot read as text and that %s does not name with a reason: %s"
                         % (UNREAD_REL, "; ".join(missing[:5]))] * bool(missing) + stale
    if problems:
        raise OSError("; ".join(problems))
    return units, read


def load_allowlist(root: Path, require_ctx: bool = True) -> Tuple[List[Entry], List[str]]:
    """Entries and errors. Every entry needs a real reason (see reason_problem) and, unless regen is migrating the
    file (require_ctx False), a context fingerprint."""
    entries: List[Entry] = []
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
        ctx = CTX.search(line)
        if not ctx and require_ctx:
            errors.append("%s:%d: entry has no ` | ctx:<12 hex>` context fingerprint (regen writes it)" % (ALLOW_REL, number))
            continue
        if ctx:
            line = line[:ctx.start()]
        if SEPARATOR not in line:
            errors.append("%s:%d: malformed entry (want `<file> | <normalised line> | ctx:<hex>`)" % (ALLOW_REL, number))
            continue
        rel, text = line.split(SEPARATOR, 1)
        if not rel or " " in rel or not text or text != normalise(text):
            errors.append("%s:%d: malformed entry (file empty/has spaces, or text empty/not normalised)" % (ALLOW_REL, number))
            continue
        if forbidden_entry(text):
            errors.append("%s:%d: entry sets a non-session pool mode; fix the line, it cannot be allowlisted" % (ALLOW_REL, number))
            continue
        problem = reason_problem(reason or "")
        if problem:
            errors.append("%s:%d: entry without a written reason (%s)" % (ALLOW_REL, number, problem))
            continue
        entries.append((rel, text, ctx.group(1) if ctx else ""))
    return entries, errors


def judge(units: Sequence[Unit], entries: Sequence[Entry]) -> Tuple[List[str], List[str]]:
    """(findings, stale entries). A finding is an unapproved, unlisted mention."""
    budget = Counter(entries)  # one entry per occurrence
    findings = []
    for rel, number, text, ctx in units:
        if approved(text):
            continue
        if budget[(rel, text, ctx)] > 0:
            budget[(rel, text, ctx)] -= 1
            continue
        hidden = hidden_chars(text)
        if hidden:
            findings.append("%s:%d: unreadable-characters (%s) may hide a word; reword in plain text or allowlist with a "
                            "reason (ctx:%s): %s" % (rel, number, " ".join("U+%04X" % ord(c) for c in hidden), ctx, text[:160]))
            continue
        findings.append("%s:%d: mentions a pooler mode without an approved session-mode shape (ctx:%s): %s" % (rel, number, ctx, text[:160]))
    stale = ["%s: stale allowlist entry (x%d unused; text or neighbourhood changed): %s | %s | ctx:%s" % (ALLOW_REL, n, r, t[:120], c)
             for (r, t, c), n in budget.items() if n > 0]
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
UNREAD_REASON = "# reviewed: a compressed archive of generated output that holds no operator guidance\n"

# Red probes: every wording the PR 4710 reviews planted, rounds 1 to 3.
PLANTED: List[Tuple[str, str, str]] = [
    # R5 reviewer (#4667): look-alikes outside CONFUSABLE, invisible letters, dashes NFKD keeps
    ("shadow: Armenian oh", "docs/a.md", "Run PgBouncer with transacti\u0585n pooling.\n"),
    ("shadow: Latin alpha", "docs/a.md", "Run PgBouncer in tr\u0251nsaction mode.\n"),
    ("shadow: Greek lunate sigma", "docs/a.md", "Run PgBouncer in transa\u03f2tion mode.\n"),
    ("shadow: Hangul filler inside the word", "docs/a.md", "Run PgBouncer in trans\u3164action mode.\n"),
    ("shadow: non-breaking hyphen", "docs/a.md", "For fan-in use transaction\u2011mode.\n"),
    ("skip list: an ASCII magic number opens a markdown file", "docs/g.md", "GIF89a is an image format.\nRun PgBouncer in transaction mode.\n"),
    # R9 (#4667 round 6, closed world): characters the fold does not know are red, not read past
    ("R9: three look-alikes the fold does not know", "docs/a.md", "Run PgBouncer in tr\u0251ns\u0251cti\u0254n mode.\n"),
    ("R9: a control character inside a word", "docs/a.md", "Run PgBouncer in tra\x01nsaction mode.\n"),
    ("R9: a symbol joined to the words of a pooler line", "docs/a.md", "Set the pooler to tr\u2016ansaction.\n"),
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
    ("POOLINGMODE key with no separator (pins the pooling spelling)", "deploy/.env", "POOLINGMODE=transaction\n"),
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
    # round 4 security review: abbreviations, separators, other config forms, look-alikes
    ("abbreviation stmt", "docs/a.md", "Run PgBouncer in stmt mode for the daemon.\n"),
    ("abbreviation trx", "docs/a.md", "Run PgBouncer in trx mode for the daemon.\n"),
    ("abbreviation xaction", "docs/a.md", "Use xaction pooling for the daemon.\n"),
    ("spelling pg_bouncer", "docs/a.md", "Run pg_bouncer per transaction for the daemon.\n"),
    ("odyssey pool quoted value", "infra/o/odyssey.conf", "\t\tpool \"transaction\"\n"),
    ("json mode_type", "deploy/t.json", "{\"db_user\": \"ai\", \"mode_type\": \"transaction\"}\n"),
    ("json quoted mode key", "deploy/x.json", "{\"mode\": \"transaction\"}\n"),
    ("env PGB_MODE", "deploy/.env", "PGB_MODE=transaction\n"),
    ("configmap PGBOUNCER_MODE", "deploy/cm.yaml", "data:\n  PGBOUNCER_MODE: transaction\n"),
    ("zero-width inside the key", "docs/a.md", "pool\u200b_mode = transaction\n"),
    ("zero-width inside the mode word", "docs/a.md", "Run PgBouncer in trans\u200baction mode.\n"),
    ("cyrillic look-alike in the mode word", "docs/a.md", "Run PgBouncer in tr\u0430nsaction mode.\n"),
    ("fullwidth letter in the mode word", "docs/a.md", "Run PgBouncer in \uff54ransaction mode.\n"),
    ("soft hyphen in the mode word", "docs/a.md", "Run PgBouncer in trans\u00adaction mode.\n"),
    # round 5 (#4741 closed world): the value is a variable, a default elsewhere or a template, never the literal session
    ("R8 terraform variable named pgb_mode (default on another line)", "deploy/main.tf", "variable \"pgb_mode\" {\n  type = string\n}\n"),
    ("R8 prefixed key set to a variable", "deploy/main.tf", "pgb_mode = var.pooler_choice\n"),
    ("R8 helm value templated", "deploy/values.yaml", "poolMode: {{ .Values.poolMode }}\n"),
    ("R8 env key set to a shell variable", "deploy/.env", "PGBOUNCER_POOL_MODE=${POOL_CHOICE}\n"),
    ("R8 dotted pooler key", "deploy/x.toml", "pgcat.mode = \"${MODE}\"\n"),
    ("R8 hyphenated pooler key", "deploy/x.yaml", "supavisor-mode: {{ .Values.m }}\n"),
    ("R5 mode word 3 non-blank lines from an approved line (#4950)", "docs/x.md",
     "pool_mode = session\nlisten_port = 6432\nauth_type = scram-sha-256\nFor more fan-in, switch to transaction.\n"),
    ("R5 instruction 3 prose lines after a PgBouncer mention (#4950)", "docs/x.md",
     "PgBouncer pool_mode = session is the default.\nIt fronts the primary.\nIt listens on 6432.\nFor fan-in, change it to transaction instead.\n"),
    ("R5 mode word exactly PARAGRAPH_MAX lines from a mention (#4950)", "docs/x.md",
     "pool_mode = session\n" + "listen_port = 6432\n" * 7 + "For fan-in, change it to transaction instead.\n"),
    # round 4 code review (#5089): pins for the reviewer mutants that survived (shapes, products, entities, file classes)
    ("closed vocabulary does not admit 'not'", "infra/x/pgb.ini", "pool_mode = session ; not supported\n"),
    ("closed vocabulary does not admit 'unsafe'", "infra/x/pgb.ini", "pool_mode = session ; unsafe\n"),
    ("a word before an approved line is not a prefix", "docs/a.md", "Avoid: pool_mode = session\n"),
    ("a heading two lines above an approved line", "docs/a.md", "## Never set this\n\npool_mode = session\n"),
    ("odyssey far before the mode word", "docs/a.md", "Odyssey sits in front of each module backbone for admission control; switch it to transaction.\n"),
    ("supavisor far before the mode word", "docs/a.md", "Supavisor sits in front of each module backbone for admission control; switch it to transaction.\n"),
    ("pgcat far before the mode word", "docs/a.md", "PgCat sits in front of each module backbone for admission control; switch it to transaction.\n"),
    ("pooler far before the mode word", "docs/a.md", "A pooler sits in front of each module backbone for admission control; switch it to transaction.\n"),
    ("html entity inside the mode word", "docs/a.html", "<p>PgBouncer &#116;ransaction mode</p>\n"),
    ("shell script", "deploy/run.sh", "export PGBOUNCER_POOL_MODE=transaction\n"),
    ("toml file", "deploy/pgcat.toml", "pool_mode = \"transaction\"\n"),
    ("rust comment", "src/a.rs", "// run pgbouncer with pool_mode = transaction\n"),
    ("Dockerfile", "deploy/Dockerfile", "ENV PGBOUNCER_POOL_MODE=transaction\n"),
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
    ("R9 declared typographic characters on a pool line", "docs/a.md", "The pool has \u2265 2 servers \u2014 see \u00a75.6 \u2192 notes.\n"),
    ("R9 an accented letter folds to ASCII", "docs/a.md", "The caf\u00e9 pool opens at nine.\n"),
    ("R9 a hiding character on a line with no pool word", "docs/a.md", "Latency is 50 \u03bcs per call.\n"),
    ("R9 colour codes in a recorded log", "docs/run.log", "\x1b[33mWARN\x1b[0m pool size 5\n"),
]


def write_tree(root: Path, files: Dict[str, object]) -> None:
    for rel, body in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(body, bytes):
            target.write_bytes(body)
        else:
            target.write_text(body, encoding="utf-8")


def tree(extra: Optional[Dict[str, object]] = None, allow: str = "", guide: str = GOOD_GUIDE, ini: str = GOOD_INI,
         unread: Optional[str] = None) -> Dict[str, object]:
    files: Dict[str, object] = {INI_REL.as_posix(): ini, GUIDE_REL.as_posix(): guide, ALLOW_REL.as_posix(): allow}
    if unread is not None:
        files[UNREAD_REL.as_posix()] = unread
    files.update(extra or {})
    return files


def ent(rel: str, body: str, text: str, nth: int = 0) -> str:
    """The allowlist line, with its context fingerprint, for the nth unit of `body` whose text is `text`."""
    found = [u for u in scan_lines(rel, [normalise(line) for line in body.splitlines()]) if u[2] == text]
    return "%s%s%s | ctx:%s\n" % (rel, SEPARATOR, text, found[nth][3])


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


def cases() -> List[Tuple[str, Dict[str, object], int]]:
    out: List[Tuple[str, Dict[str, object], int]] = []
    for name, rel, body in PLANTED:
        out.append(("red: " + name, tree({rel: body}), EXIT_FINDING))
    for name, rel, body in GREEN:
        out.append(("green: " + name, tree({rel: body}), EXIT_OK))
    retired = {"docs/a.md": "Transaction mode is not supported (#4667).\n"}
    retired_entry = ent("docs/a.md", retired["docs/a.md"], "transaction mode is not supported (#4667).")
    sup = "PgBouncer session mode is supported.\n"
    sup_or = "PgBouncer session mode is supported, or\nstatement.\n"
    two = "Transaction mode is not supported.\nx\nStatement mode is not supported.\n"
    one = "Transaction mode is not supported.\n"
    dup = "Transaction mode is not supported.\nx\nTransaction mode is not supported.\n"
    rev = "Transaction mode is not supported (#4667).\nThat changed: it is now the recommended setting.\n"
    out += [
        ("agreeing tree passes", tree(), EXIT_OK),
        ("session prose alone is not approved", tree({"docs/a.md": "PgBouncer session mode is supported.\n"}), EXIT_FINDING),
        ("session prose passes once allowlisted with a reason",
         tree({"docs/a.md": sup}, REASON + ent("docs/a.md", sup, "pgbouncer session mode is supported.")), EXIT_OK),
        ("R5: an allowlisted line does not cover a mode word on the next line",
         tree({"docs/a.md": sup_or}, REASON + ent("docs/a.md", sup_or, "pgbouncer session mode is supported, or")), EXIT_FINDING),
        ("R7: an allowlisted line does not cover a reversal next to it that names no mode word (#5087, #5088)",
         tree({"docs/a.md": rev}, REASON + ent("docs/a.md", retired["docs/a.md"], "transaction mode is not supported (#4667).")), EXIT_FAULT),
        ("R7: re-reviewing the line (a fresh fingerprint, as regen --refresh-context writes) passes",
         tree({"docs/a.md": rev}, REASON + ent("docs/a.md", rev, "transaction mode is not supported (#4667).")), EXIT_OK),
        ("a mixed line (session and transaction) is not approved", tree({"docs/a.md": "pool_mode = session, not transaction mode\n"}), EXIT_FINDING),
        ("allowlisted retirement line passes", tree(retired, REASON + retired_entry), EXIT_OK),
        ("an entry continues the reason of the entry above",
         tree({"docs/a.md": two}, REASON + ent("docs/a.md", two, "transaction mode is not supported.")
              + ent("docs/a.md", two, "statement mode is not supported.")), EXIT_OK),
        ("allowlist entry is bound to its file",
         tree({"docs/b.md": "Transaction mode is not supported (#4667).\n"}, REASON + retired_entry), EXIT_FAULT),
        ("stale allowlist entry fails", tree({}, REASON + "docs/gone.md | pool_mode = transaction | ctx:000000000000\n"), EXIT_FAULT),
        ("malformed allowlist entry fails", tree({}, REASON + "no separator here\n"), EXIT_FAULT),
        ("an entry beyond the occurrence count is stale",
         tree({"docs/a.md": one}, REASON + ent("docs/a.md", one, "transaction mode is not supported.") * 2), EXIT_FAULT),
        ("one entry does not cover a second occurrence",
         tree({"docs/a.md": dup}, REASON + ent("docs/a.md", dup, "transaction mode is not supported.")), EXIT_FINDING),
        ("non-normalised allowlist text fails",
         tree({"docs/a.md": one}, REASON + ent("docs/a.md", one, "transaction mode is not supported.").replace("| t", "| T")), EXIT_FAULT),
        ("an entry without a context fingerprint fails",
         tree({"docs/a.md": one}, REASON + "docs/a.md | transaction mode is not supported.\n"), EXIT_FAULT),
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
        ("a five-word reason fails even when it is long",
         tree(retired, "# reviewed, retirement statement only here\n" + retired_entry), EXIT_FAULT),
        ("a six-word reason under thirty characters fails", tree(retired, "# a b c d e f g\n" + retired_entry), EXIT_FAULT),
        ("a filler reason (lorem) fails", tree(retired, "# lorem ipsum dolor sit amet consectetur\n" + retired_entry), EXIT_FAULT),
        ("a filler reason (todo x8) fails", tree(retired, "# todo todo todo todo todo todo todo todo\n" + retired_entry), EXIT_FAULT),
        ("a five-word reason under the sentence floor fails", tree(retired, "# retired mode kept for history\n" + retired_entry), EXIT_FAULT),
        ("an entry that sets transaction mode is refused whatever its reason",
         tree({"infra/x/setup.sh": "pool_mode = transaction\n"}, REASON + ent("infra/x/setup.sh", "pool_mode = transaction\n", "pool_mode = transaction")), EXIT_FAULT),
        ("a per-db override entry is refused",
         tree({"infra/x/pgb.ini": "ai = host=pg pool_mode=transaction\n"}, REASON + ent("infra/x/pgb.ini", "ai = host=pg pool_mode=transaction\n", "ai = host=pg pool_mode=transaction")), EXIT_FAULT),
        # files read, not skipped (#5086, #5090)
        ("NUL bytes in a markdown file fail closed", tree({"docs/n.md": "\0\nRun PgBouncer in transaction mode.\n"}), EXIT_FAULT),
        ("a gzip document fails closed", tree({"docs/z.md.gz": b"\x1f\x8b\x08\x00zzz"}), EXIT_FAULT),
        ("a magic number on plain UTF-8 text is read as text and judged (R5)", tree({"docs/p.md": b"%PDF-1.7 Run PgBouncer in transaction mode.\n"}), EXIT_FINDING),
        ("a magic number on binary bytes fails closed", tree({"docs/p.md": b"%PDF-1.7\n\x93\xff Run PgBouncer in transaction mode.\n"}), EXIT_FAULT),
        ("a named unreadable file with a reason passes",
         tree({"docs/z.md.gz": b"\x1f\x8b\x08\x00zzz"}, unread=UNREAD_REASON + "docs/z.md.gz\n"), EXIT_OK),
        ("a skip entry without a reason fails",
         tree({"docs/z.md.gz": b"\x1f\x8b\x08\x00zzz"}, unread="docs/z.md.gz\n"), EXIT_FAULT),
        ("a skip entry with a filler reason fails",
         tree({"docs/z.md.gz": b"\x1f\x8b\x08\x00zzz"}, unread="# todo todo todo todo todo todo todo todo\ndocs/z.md.gz\n"), EXIT_FAULT),
        ("a skip entry with the placeholder fails",
         tree({"docs/z.md.gz": b"\x1f\x8b\x08\x00zzz"}, unread="# REASON REQUIRED before review - say why\ndocs/z.md.gz\n"), EXIT_FAULT),
        ("a stale skip entry (the file is readable text) fails", tree({"docs/ok.md": "Plain text.\n"}, unread=UNREAD_REASON + "docs/ok.md\n"), EXIT_FAULT),
        ("a stale skip entry for a readable file with a binary name fails",
         tree({"assets/ok.bin": "Plain text.\n"}, unread=UNREAD_REASON + "assets/ok.bin\n"), EXIT_FAULT),
        ("a skip entry for an untracked path fails", tree({}, unread=UNREAD_REASON + "docs/gone.md\n"), EXIT_FAULT),
        ("a text file is never excused by the skip list (R5)",
         tree({"docs/n.md": "\0\nRun PgBouncer in transaction mode.\n"}, unread=UNREAD_REASON + "docs/n.md\n"), EXIT_FAULT),
        ("a skip entry does not hide another unreadable file",
         tree({"docs/z.md.gz": b"\x1f\x8b\x08\x00zzz", "docs/y.bin": b"\0\0\0"}, unread=UNREAD_REASON + "docs/z.md.gz\n"), EXIT_FAULT),
        ("a file past the old 4 MiB cap, many windows, is scanned to its end",
         tree({"docs/big.md": ("x" * 99 + "\n") * 43000 + "Run PgBouncer in transaction mode.\n"}), EXIT_FINDING),
        ("a long line with a product at the start and a mode word far away is a mention",
         tree({"docs/long.md": "PgBouncer " + "x " * 3500 + "transaction\n"}), EXIT_FINDING),
        ("a mention straddling a long-line segment boundary is found",
         tree({"docs/long.md": "x " * 1021 + "pool_mode = transaction" + " y" * 1200 + "\n"}), EXIT_FINDING),
        ("a mention that straddles a read chunk is found",
         tree({"docs/big.md": "a" * (CHUNK_BYTES - 10) + " Run PgBouncer in transaction mode.\n"}), EXIT_FINDING),
        ("a UTF-16 file with a BOM is decoded and judged", tree({"docs/u.txt": "Run PgBouncer in transaction mode.\n".encode("utf-16")}), EXIT_FINDING),
        ("a BOM-less UTF-16LE file is decoded and judged", tree({"docs/u.txt": "Run PgBouncer in transaction mode.\n".encode("utf-16-le")}), EXIT_FINDING),
        ("a BOM-less UTF-16BE file is decoded and judged", tree({"docs/u.txt": "Run PgBouncer in transaction mode.\n".encode("utf-16-be")}), EXIT_FINDING),
        ("a UTF-32 file is decoded and judged", tree({"docs/u.txt": "Run PgBouncer in transaction mode.\n".encode("utf-32")}), EXIT_FINDING),
        # R9 (#4667 round 6): closed world over characters
        ("R9: an invalid UTF-8 byte inside the mode word is red", tree({"docs/a.md": b"Run PgBouncer in tr\xffansaction mode.\n"}), EXIT_FINDING),
        ("R9: an invalid UTF-8 byte is red on a line with no pool word", tree({"docs/a.md": b"Our tr\xffansaction notes.\n"}), EXIT_FINDING),
        ("R9: an approved shape with a digit outside DECLARED is not approved",
         tree({"docs/a.md": "pool_mode = session ; see \u0665.\u0666\n"}), EXIT_FINDING),
        ("R9: a hiding line passes once allowlisted with a reason",
         tree({"docs/a.md": "Run PgBouncer in tr\u0251ns\u0251cti\u0254n mode.\n"},
              REASON + ent("docs/a.md", "Run PgBouncer in tr\u0251ns\u0251cti\u0254n mode.\n", "run pgbouncer in tr\u0251ns\u0251cti\u0254n mode.")), EXIT_OK),
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


STREAM_SAMPLE = [
    "intro line", "pool_mode = session", "prose that follows the approved line", "", "more prose, then", "transaction.",
    "Put PgBouncer in front of the primary and", "switch it to transaction for the daemon.", "", "", "",
    "PgBouncer pools", "statements", "for the daemon", "[pgbouncer]", "pool_mode = session", "listen_port = 6432",
    "unrelated", "text", "", "Front the primary with a pooler in", "transaction mode.", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
    "pool_mode: session ; supported mode", "k", "l", "m", "n", "mode = txn", "o", "p",
]


def stream_failures() -> int:
    """The windowed scan equals one pass over the file, and the chunked reader equals str.splitlines()."""
    global WINDOW_LINES, CHUNK_BYTES
    bad = 0
    raw = [line + "\n" for line in STREAM_SAMPLE * 6]
    whole = sorted(scan_lines("f.md", [normalise(l) for l in raw]))
    saved_window = WINDOW_LINES
    try:
        for size in (3, 5, 8, 13, 21):
            WINDOW_LINES = size
            if sorted(scan_stream("f.md", raw)) != whole:
                bad += 1
                print("self-test FAIL windowed scan differs from the whole-file scan at WINDOW_LINES=%d" % size)
    finally:
        WINDOW_LINES = saved_window
    body = "a\r\nb\rc\nd\u2028e\u00e9f\x0cg\r\r\nh\n\n\ni"
    with tempfile.TemporaryDirectory(dir=_scratch_base()) as tmp:
        sample = Path(tmp) / "r.txt"
        sample.write_bytes(body.encode("utf-8"))
        saved_chunk = CHUNK_BYTES
        try:
            for size in (1, 2, 3, 5, 7, 11):
                CHUNK_BYTES = size
                if list(read_lines(sample)) != body.splitlines():
                    bad += 1
                    print("self-test FAIL chunked read differs from splitlines() at CHUNK_BYTES=%d" % size)
        finally:
            CHUNK_BYTES = saved_chunk
    print("self-test %s windowed scan and chunked read equal the whole-file results" % ("ok  " if not bad else "FAIL"))
    return bad


def run_cases(verbose: bool) -> int:
    scratch_base = _scratch_base()
    failures = stream_failures()
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
SKIP = "        if Path(rel) in (ALLOW_REL, SELF_REL, " + "UNREAD_REL):"  # split so the mutated text is found once in the rules


MUTANTS: List[Tuple[str, str, str]] = [
    ("R1 name rule", 'MENTION_NAME = re.compile(POOL_MODE + r"s?")', 'MENTION_NAME = re.compile(r"(?!)")'),
    ("R1 pooling spelling", 'POOL_MODE = r"pool(?:ing)?[\\s_-]*mode"', 'POOL_MODE = r"pool[\\s_-]*mode"'),
    ("R1 plural key", 'MENTION_NAME = re.compile(POOL_MODE + r"s?")', 'MENTION_NAME = re.compile(POOL_MODE + r"\\b")'),
    ("R2 abbreviations tx/xact", '|statements?|txn|tx|xact|', '|statements?|txn|'),
    ("R2 abbreviations stmt/trx/xaction", '|stmts?|trx|xaction|trans)"', ')"'),
    ("R2 plural modes", "(?:modes?|pooling|pooler|pools?)", "(?:mode|pooling|pooler|pool)"),
    ("R2 plural transactions", '_MODE_WORD = r"(?:transaction(?:s|al)?|', '_MODE_WORD = r"(?:transaction(?:al)?|'),
    ("R2 transactional", '_MODE_WORD = r"(?:transaction(?:s|al)?|', '_MODE_WORD = r"(?:transactions?|'),
    ("R2 multiplex counts as a pooler word", '_POOLER = r"(?:pgbouncer|pooler|pooling|odyssey|supavisor|pgcat|multiplex(?:es|ed|ing)?)"', '_POOLER = r"(?:pgbouncer|pooler|pooling|odyssey|supavisor|pgcat)"'),
    ("R2 session next to a pool word", '_ANY_MODE = r"(?:%s|sessions?)" % _MODE_WORD', '_ANY_MODE = r"(?:%s)" % _MODE_WORD'),
    ("R2 pooling word in _POOLER", '_POOLER = r"(?:pgbouncer|pooler|pooling|', '_POOLER = r"(?:pgbouncer|pooler|'),
    ("R2 product anywhere on the line", '    r"|\\b%s\\b.*?\\b%s\\b|\\b%s\\b.*?\\b%s\\b"\n', '    r"|\\b%s\\b(?!)\\b%s\\b|\\b%s\\b(?!)\\b%s\\b"\n'),
    ("R2 bare mode key", 'r"|\\bmode(?:[\\s_-]*type)?\\s*[:=]\\s*[\\"\']?%s\\b"', 'r"|(?!)%s"'),
    ("R8 pooler-prefixed mode key", "    if MENTION_NAME.search(text) or MENTION_PROSE.search(text) or MENTION_KEY.search(text):", "    if MENTION_NAME.search(text) or MENTION_PROSE.search(text):"),
    ("U1 look-alike shadow", "    alt = shadow(text)\n", "    alt = text\n"),
    ("U2 separators", "    split = _SEPARATORS.sub(\" \", text)", "    split = text"),
    ("F1 unread files must be named", "    problems = errors + [", "    problems = [] and errors + ["),
    ("F1 stale skip entries fail", "for rel in sorted(listed) if rel not in unread]", "for rel in sorted(listed) if False]"),
    ("F1 skip entry needs a reason", "        problem = reason_problem(reason or \"\")\n        if not problem and Path(line).suffix", "        problem = None\n        if not problem and Path(line).suffix"),
    ("F1 binary magic numbers", "        if chunk.startswith(BINARY_MAGIC) and not _plain_text(chunk):", "        if False:"),
    ("F1 magic number on plain text is text", "        if chunk.startswith(BINARY_MAGIC) and not _plain_text(chunk):", "        if chunk.startswith(BINARY_MAGIC):"),
    ("F1 a text suffix is never skipped", "        if not problem and Path(line).suffix.lower() in TEXT_SUFFIXES:", "        if False:"),
    ("F1 NUL bytes in non-UTF-16 text", "            if utf8 and b\"\\0\" in chunk:", "            if False:"),
    ("F1 BOM-less UTF-16", "    if len(zeros) * 4 >= min(len(head), CHUNK_BYTES) > 0:", "    if False:"),
    ("F2 long lines: product and mode word anywhere", "    return bool(_PRODUCT_WORD.search(view) and OTHER_MODE.search(view))", "    return False"),
    ("F2 long lines: overlapping segments", "SEGMENT, SEGMENT_STEP = 2048, 1536", "SEGMENT, SEGMENT_STEP = 2048, 2048"),
    ("F2 window margin", "WINDOW_MARGIN = 2 * PARAGRAPH_MAX + 2 * NEIGHBOURS", "WINDOW_MARGIN = 1"),
    ("F2 chunk-boundary carriage return", " or lines[-1].endswith(\"\\r\")", ""),
    ("A1 forbidden entries", "        if forbidden_entry(text):\n", "        if False:\n"),
    ("A1 filler reasons", "    if FILLER.search(reason.casefold()) or", "    if False and"),
    ("R3 path tokens", "    text = TOOL_PATH.sub(_path_words, text)\n", ""),
    ("R3 path keeps product words", 'return " " + " ".join(_PATH_KEEP.findall(match.group(0))) + " "', 'return " "'),
    ("R4 wrap", "                pair(i, i + 1)  # R4", "                pass  # R4"),
    ("R5 paragraph reach (#4950)", "PARAGRAPH_MAX = 8  #", "PARAGRAPH_MAX = 7  #"),
    ("R5 paragraph stops at a blank line", "while 0 <= j < len(lines) and lines[j] and abs(j - i) <= PARAGRAPH_MAX:", "while 0 <= j < len(lines) and abs(j - i) <= PARAGRAPH_MAX:"),
    ("R5 paragraph", "                    pair(i, j)  # R5", "                    pass  # R5"),
    ("R6 approved-line context", "                    pair(i, j)  # R6", "                    pass  # R6"),
    ("R6 key=value tokens are neutral", '    re.compile(r"^[a-z_][a-z0-9_.]*\\s*=\\s*(?:%s\\s*)+$" % _KV_TOKEN),', '    re.compile(r"(?!)"),'),
    ("R6 blank lines skipped", "            if lines[j]:\n                found.append(j)", "            if True:\n                found.append(j)"),
    ("A1/A2 closed shapes (prose approves again)", "    return any(shape.match(text) for _, shape in APPROVED_SHAPES)",
     '    return bool(re.search(r"pool_mode = session", text)) and not OTHER_MODE.search(text)'),
    ("A2 closed comment vocabulary", '_COMMENT = r"\\s*[;#]\\s*%s(?:[\\s,.]+%s)*[\\s,.]*" % (_VOCAB, _VOCAB)', '_COMMENT = r"\\s*[;#].*"'),
    ("allowlist reason required", "        problem = reason_problem(reason or \"\")\n        if problem:\n            errors.append(\"%s:%d: entry without", "        problem = None\n        if problem:\n            errors.append(\"%s:%d: entry without"),
    ("allowlist placeholder", 'if line.lstrip().startswith("#") and "reason required" in line.casefold():', "if False:"),
    ("allowlist reason length", "    if len(words) < MIN_REASON_WORDS or len(reason) < MIN_REASON_CHARS:", "    if not words:"),
    ("R7 context fingerprint", '    return hashlib.sha256("\\n".join(lines[j] for j in near).encode("utf-8")).hexdigest()[:12]', '    return "0" * 12'),
    ("allowlist per-occurrence budget", "            budget[(rel, text, ctx)] -= 1\n", ""),
    ("round-4 W3 vocabulary gains not", '_VOCAB = r"(?:supported|', '_VOCAB = r"(?:not|supported|'),
    ("round-4 W4 vocabulary gains unsafe", '_VOCAB = r"(?:supported|', '_VOCAB = r"(?:unsafe|supported|'),
    ("round-4 W5 approved by search", "    return any(shape.match(text) for _, shape in APPROVED_SHAPES)",
     "    return any(shape.search(text.split(' ', 1)[-1]) or shape.match(text) for _, shape in APPROVED_SHAPES)"),
    ("round-4 W7 markdown heading is neutral", "    FENCE,                                                                  # code fence",
     '    FENCE, re.compile(r"^#+ .*$"),'),
    ("round-4 D4 drop supavisor from _PRODUCT", '_PRODUCT = r"(?:pgbouncer|pooler|odyssey|supavisor|pgcat)"', '_PRODUCT = r"(?:pgbouncer|pooler|odyssey|pgcat)"'),
    ("round-4 D5 drop pgcat from _PRODUCT", '_PRODUCT = r"(?:pgbouncer|pooler|odyssey|supavisor|pgcat)"', '_PRODUCT = r"(?:pgbouncer|pooler|odyssey|supavisor)"'),
    ("round-4 D6 drop pooler from _PRODUCT", '_PRODUCT = r"(?:pgbouncer|pooler|', '_PRODUCT = r"(?:pgbouncer|'),
    ("round-4 D3b drop odyssey from _PRODUCT", '_PRODUCT = r"(?:pgbouncer|pooler|odyssey|', '_PRODUCT = r"(?:pgbouncer|pooler|'),
    ("round-4 D8 drop html unescape", '.sub("", html.unescape(line))', '.sub("", line)'),
    ("round-4 E5 word floor 2", "MIN_REASON_WORDS, MIN_REASON_CHARS = 6, 30", "MIN_REASON_WORDS, MIN_REASON_CHARS = 2, 3"),
    ("round-4 S3 skip .sh", SKIP, SKIP[:-1] + " or rel.endswith('.sh'):"),
    ("round-4 S4 skip .toml", SKIP, SKIP[:-1] + " or rel.endswith('.toml'):"),
    ("round-4 S5 skip .rs", SKIP, SKIP[:-1] + " or rel.endswith('.rs'):"),
    ("round-4 S7 skip Dockerfile", SKIP, SKIP[:-1] + " or 'Dockerfile' in rel:"),
    ("round-4 S1 skip .html", SKIP, SKIP[:-1] + " or rel.endswith('.html'):"),
    ("round-4 S2 skip .ini", SKIP, SKIP[:-1] + " or rel.endswith('.ini'):"),
    ("round-4 S9 skip deploy/", SKIP, SKIP[:-1] + " or rel.startswith('deploy/'):"),
    ("guide pin", "    if not guide_ok:\n", "    if False:\n"),
    ("R9 unreadable lines are units", "                raw.append((base + i + 1, text, (i,)))  # R9", "                pass  # R9"),
    ("R9 U+FFFD always counts", '    found = {"\\ufffd"} if "\\ufffd" in text else set()', "    found = set()"),
    ("R9 approved shapes hold DECLARED characters", "    if not all(c in DECLARED for c in text):\n        return False", "    if False:\n        return False"),
    ("R9 needs a pool word", "or bool(_QUICK.search(shadow(text))))", "or True)"),
    ("R9 colour codes dropped", '    view = shadow(_ANSI_CSI.sub("", text))', "    view = shadow(text)"),
    ("R9 a character touching a letter", "        if (i and _ascii_letter(view[i - 1])) or (i + 1 < len(view) and _ascii_letter(view[i + 1])):", "        if False:"),
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
    for index, (rel, text, ctx) in enumerate(entries):
        for label, mutant in (("text altered", (rel, text + " x", ctx)), ("file altered", (rel + ".moved", text, ctx)),
                              ("context altered", (rel, text, "f" * 12 if ctx != "f" * 12 else "0" * 12))):
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
