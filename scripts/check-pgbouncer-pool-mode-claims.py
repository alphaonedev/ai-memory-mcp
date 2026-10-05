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
               its words, so undecodable text with no NUL byte exits 1 (a
               finding), while a NUL byte outside UTF-16/32 exits 2 (a fault). Such a character can hide a word from every pattern,
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
# A1 (#4667 R4, #5366): an allowlist entry may describe a non-session mode, never set one. A whole-line
# assignment of transaction/statement (any key spelling, ini/yaml/env/json/toml/compose form), a config
# line carrying a pool_mode=transaction token, or a pool_mode key assigned transaction/statement by a command
# (shell export, Dockerfile ENV, docker -e, kubectl set env, helm --set, admin SET), a quoted JSON key, a flow mapping or
# inline table, an env prefix on a command, or a sed/echo style write of the key is refused (rc 2), whatever its reason says.
# Prose that quotes the withdrawn setting (a retirement note) stays allowlistable: a bare key=value inside a
# sentence is not refused. The shapes are matched on the entry text and on its shadow view, so a look-alike
# letter does not slip past.
FORBIDDEN_ENTRY = (
    re.compile(r"^(?:[-*>]\s*)*[\"']?[a-z0-9_.]*mode(?:[_-]?type)?[\"']?\s*[=:]\s*[\"']?(?:transaction|statement)[\"']?,?\s*(?:[;#].*)?$"),
    re.compile(r"^[a-z_][a-z0-9_.]*\s*=\s*(?:[a-z_][a-z0-9_.-]*=[^\s;#]*\s*)*pool_mode=(?:transaction|statement)\b"),
    re.compile(r"^pool\s+[\"']?(?:transaction|statement)[\"']?$"),
    re.compile(r"(?:^|\s)(?:export|env|set|-e|--env|--set|--set-string)(?:\s+[^\s=\"']+){0,4}?(?:\s+|=)[\"']?[a-z0-9_.]*pool[_-]?mode[\"']?(?:\s*=\s*|\s+)[\"']?(?:transaction|statement)\b"),
    re.compile(r"[\"'][a-z0-9_.]*pool[_-]?mode[\"']\s*:\s*[\"'](?:transaction|statement)[\"']"),
    # #5477: a flow mapping or inline table, an env prefix on a command, a stream editor or echo that writes the key
    # (#5555, N03: the lazy [^{}]*? prefix already absorbs a dotted key such as pgbouncer.pool_mode, so no [a-z0-9_.]* is needed)
    re.compile(r"\{[^{}]*?[\"']?pool[_-]?mode[\"']?\s*[:=]\s*[\"']?(?:transaction|statement)\b"),
    re.compile(r"^[a-z0-9_]*pool[_-]?mode=[\"']?(?:transaction|statement)[\"']?\s+(?:\.{1,2}/|/\w|~/|\$|exec\b|sudo\b|bash\b|pgbouncer\b)"),
    re.compile(r"(?:^|[\s;&|])(?:sed|awk|perl|echo|printf|tee|crudini|yq)\b.*pool[_-]?mode\s*[=:]\s*[\"']?(?:transaction|statement)\b"),
)
FILLER = re.compile(r"\b(?:todo|tbd|fixme|xxx|lorem|ipsum|placeholder|n/?a|tk)\b")
MIN_DISTINCT_WORDS = 5
REGEN_HEADER = "added by regen-pgbouncer-pool-mode-allow.py"
MIN_REASON_WORDS, MIN_REASON_CHARS = 6, 30

Unit = Tuple[str, int, str, str]  # (relative path, line number, normalised text, context fingerprint)
Entry = Tuple[str, str, str]  # (relative path, normalised text, context fingerprint)
CTX = re.compile(r" \| ctx:([0-9a-f]{12})$")  # R7: an allowlist entry is bound to its neighbourhood


# #5365: markdown underscore emphasis (_word_, __two words__) is markup like the backtick and the asterisk: a span that
# opens at a word edge and closes at a word edge loses its underscores (never one inside a word: pool_mode, sqlx_s_)
# so the word boundary \b sees the word. Any run of underscores: ___word___ is bold italic (#5476).
_EMPHASIS = re.compile(r"(?<![^\W_])(_+)(?=[^\W_])(.+?)(?<=[^\W_])\1(?![^\W_])")


# #5480 (F6, M14/M15): a lone underscore at a word edge is not emphasis but still hides the word from \b (transaction_ mode,
# _transaction mode, _ transaction_ mode). mentions() reads a second view with those underscores replaced by a space;
# the unit text keeps them, so the allowlist keys do not move.
_EDGE_US = re.compile(r"(?<![^\W_])_+(?=[^\W_])|(?<=[^\W_])_+(?![^\W_])")


def normalise(line: str) -> str:
    fence = line.strip()
    if FENCE.match(fence):
        return fence.casefold()  # kept whole: a fence is a neutral context line (R6)
    text = (TAG_LONG if len(line) > LONG_LINE else TAG).sub("", html.unescape(line))
    text = _EMPHASIS.sub(r"\2", re.sub(r"[`*]", "", text))
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


# #5363: every Latin-script letter folds to the ASCII letter its Unicode name gives (small capitals, strokes), so a
# mode word written in them is read as the word it spells, with no neighbouring ASCII letter needed.
_LATIN_NAME = re.compile(r"^LATIN (?:(?:CAPITAL|SMALL) LETTER|LETTER SMALL CAPITAL) ([A-Z])(?: WITH [A-Z ]+)?$")


class _LatinFold(dict):
    def __missing__(self, cp: int) -> object:
        found = _LATIN_NAME.match(unicodedata.name(chr(cp), "")) if cp > 0x7F else None
        self[cp] = found.group(1).lower() if found else cp
        return self[cp]


_LATIN = _LatinFold()


def shadow(text: str) -> str:
    """Mention-detection view of a normalised line: NFKD, format and combining marks dropped,
    look-alikes folded, `pg bouncer` spellings joined. The unit text (allowlist key) is unchanged."""
    t = unicodedata.normalize("NFKD", text)
    t = "".join(c for c in t if unicodedata.category(c) not in ("Cf", "Mn")).translate(CONFUSABLE).translate(_INVISIBLE)
    t = t.translate(_LATIN).casefold()
    t = _TOKEN.sub(_fold_word, t)
    return re.sub(r"\bpg[\s_-]+bouncer", "pgbouncer", t)


# R9 (#4667 round 6, closed world): the characters a reader can trust to show what they are. Printable ASCII and a
# short typographic set (curly quotes, dashes, ellipsis, arrows, section sign, middle dot, inequality and
# multiplication signs, box-drawing lines); every other letter, and any other character that touches an ASCII letter,
# after the shadow fold may hide a word, and U+FFFD marks an invalid byte the decoder replaced.
DECLARED = frozenset(map(chr, range(0x20, 0x7F))) | frozenset(
    "\u2018\u2019\u201c\u201d\u2013\u2014\u2026\u2190\u2192\u2194\u21d2\u00a7\u00b7\u00d7\u2264\u2265\u2500\u2502")
# #5364: format characters that reorder a line (embeddings, overrides, isolates, directional marks, Arabic letter mark):
# the shadow view drops format characters to join words, so these are reported before that and make a line unreadable.
BIDI = frozenset(map(chr, list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)) + [0x200E, 0x200F, 0x061C]))
_ANSI_CSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")  # colour codes in recorded terminal logs render as nothing


def _ascii_letter(c: str) -> bool:
    return c.isascii() and c.isalpha()


def hidden_chars(text: str) -> str:
    """The characters of a normalised line that may hide a word (R9), sorted, or "" when there are none."""
    if text.isascii() and text.isprintable():
        return ""
    found = {"\ufffd"} if "\ufffd" in text else set()
    plain = _ANSI_CSI.sub("", text)
    found |= {c for c in plain if c in BIDI}
    view = shadow(plain)
    for i, c in enumerate(view):
        if c in DECLARED or c.isspace():
            continue
        if unicodedata.category(c).startswith("L"):
            found.add(c)  # #5363: a letter the fold does not know can spell a word on its own (small capitals)
        elif (i and _ascii_letter(view[i - 1])) or (i + 1 < len(view) and _ascii_letter(view[i + 1])):
            found.add(c)
    return "".join(sorted(found))


_LOOKALIKE_SCRIPTS = frozenset(("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "COPTIC"))
_LOOKALIKE_RUN = 4


def _lookalike_word(view: str) -> bool:
    """#5363: a word of four or more letters that are all non-ASCII letters of a script with Latin look-alikes: it can
    spell a mode word with no ASCII letter and no pool word on the line to give it away."""
    for word in _TOKEN.findall(view):
        if len(word) >= _LOOKALIKE_RUN and all(
                not c.isascii() and unicodedata.name(c, "?").split(" ", 1)[0] in _LOOKALIKE_SCRIPTS for c in word):
            return True
    return False


def unreadable(text: str) -> bool:
    """R9: a line that may hide a pooler claim: U+FFFD anywhere, or a hiding character on a line that names a
    pool, mode or product word."""
    hidden = hidden_chars(text)
    return bool(hidden) and ("\ufffd" in hidden or any(c in BIDI for c in hidden) or bool(_QUICK.search(shadow(text))) or _lookalike_word(shadow(text)))


def _mentions_one(text: str) -> bool:
    if _mentions_view(text):
        return True
    edge = _EDGE_US.sub(" ", text)
    return edge != text and _mentions_view(edge)


def _mentions_view(text: str) -> bool:
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


def other_mode(text: str) -> bool:
    """A mode word on a context line (R5, R6), also behind a look-alike or an invisible character: the context
    line gets the same shadow view as a mention line (#4950, #5085, #5211)."""
    return bool(OTHER_MODE.search(text) or (not text.isascii() and OTHER_MODE.search(shadow(text))))


def neutral(text: str) -> bool:
    """A context line that cannot qualify an approved line (R6): fence, section, short config line.

    #5211 / F6: the other_mode() clause here is an equivalent of the R5 branch in the caller. A context line with a
    mode word makes neutral() False, so R6 pairs it; if neutral() ignored the mode word, the elif R5 branch tests the
    same other_mode() on the same line and pairs it too. neutral() is only reached for an approved mention, so no
    case can tell the two apart: the mutant that reads raw text here is recorded as equivalent, not pinned."""
    return not other_mode(text) and any(shape.match(text) for shape in NEUTRAL_SHAPES)


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
    views = (text, shadow(text))
    return any(shape.search(view) for shape in FORBIDDEN_ENTRY for view in views)


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
                elif other_mode(lines[j]):
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


MAGIC_REASON = "binary or compressed content"  # the one Unreadable reason a skip entry may excuse (#5478)
# #5478, #5552: a magic number is not proof of binary content (GIF8, %PDF, BZh, Rar!, wOFF, OTTO, SQLite format 3 are
# printable). A file the gate cannot read as text is excused only when its raw bytes hold no pool-mode mention.
RAW_MENTION_MARK = "raw bytes hold a pool-mode mention"
RAW_LINE_CAP, RAW_OVERLAP = 1 << 22, 4096  # an overlong raw line is cut in segments that overlap, so no word is lost


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


# R5 (#4667, #5367): the skip list may name only a file whose suffix is on this closed list of binary types. Every
# other file (a .tpl or .service template, a Dockerfile or Makefile with no suffix, a .ts or .hcl source) is text and
# is read: a NUL byte in it is a defect to fix, not a reason to stop reading it. The set may only grow by review.
# #5478: the suffix is necessary, not sufficient: the file must also open with a binary magic number (MAGIC_REASON).
BINARY_SUFFIXES = frozenset((".pdf", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".webp", ".bmp", ".tif", ".tiff", ".woff",
                             ".woff2", ".ttf", ".otf", ".eot", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".7z", ".tar",
                             ".jar", ".wasm", ".so", ".dylib", ".dll", ".exe", ".bin", ".db", ".sqlite", ".mp3", ".mp4",
                             ".mov", ".webm", ".ogg", ".wav", ".class", ".o", ".a", ".rlib"))


def read_lines(path: Path) -> Iterator[str]:
    """The lines of a text file, streamed. Raises Unreadable for binary content; an OSError propagates."""
    with open(str(path), "rb") as handle:
        chunk = handle.read(CHUNK_BYTES)
        if chunk.startswith(BINARY_MAGIC) and not _plain_text(chunk):
            raise Unreadable("%s (magic number %s)" % (MAGIC_REASON, chunk[:4].hex()))
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
            chunk = handle.read(CHUNK_BYTES)  # the final empty read flushes the decoder and keeps no carry


# #5717: the views of a file the gate cannot read as text: latin-1 (every byte value decodes, nothing is replaced) and
# every encoding the text reader decodes (read_lines: UTF-8, UTF-16 and UTF-32 in either byte order), each at every
# code-unit alignment, so a run of text that starts on any byte is read whole in one view.
RAW_VIEWS: Tuple[Tuple[str, int], ...] = (("latin-1", 0), ("utf-8", 0)) + tuple(
    (codec, offset) for codec, width in (("utf-16-le", 2), ("utf-16-be", 2), ("utf-32-le", 4), ("utf-32-be", 4))
    for offset in range(width))
_BYTE_CODECS = frozenset(("latin-1", "utf-8"))
# #5717, speed only: characters that neither fold to an ASCII letter nor hide one (CJK ideographs, Hangul syllables,
# private use, U+FFFD). A view line made only of them and spaces holds no mention and hides no word.
_INERT = re.compile("[\\s\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7a3\ue000-\uf8ff\ufffd\U00020000-\U0002ebef]*")


def _raw_lines(path: Path, codec: str, offset: int, drop_nul: bool) -> Iterator[str]:
    """The bytes of a file from `offset` on, decoded as `codec` with each invalid sequence replaced, as the lines
    str.splitlines() gives. With drop_nul each NUL is removed (a word cut by NULs; in latin-1 and UTF-8 the NUL bytes
    go before decoding, so a multi-byte sequence cut by them is whole again); otherwise each NUL ends a line. A line
    still open at the end of a chunk and longer than RAW_LINE_CAP is cut in segments that overlap by RAW_OVERLAP
    characters, so no word is lost; a line that ends inside its chunk is given whole."""
    decoder = codecs.getincrementaldecoder(codec)("replace")
    nul = "" if drop_nul else "\n"
    carry = ""
    with open(str(path), "rb") as handle:
        handle.seek(offset)
        while True:
            chunk = handle.read(CHUNK_BYTES)
            data = chunk.replace(b"\0", nul.encode("ascii")) if codec in _BYTE_CODECS else chunk
            text = carry + decoder.decode(data, final=not chunk).replace("\0", nul)
            lines = text.splitlines(keepends=True)
            carry = ""
            if chunk and lines and (lines[-1].splitlines()[0] == lines[-1] or lines[-1].endswith("\r")):
                carry = lines.pop()  # #5717: a tail with no line break yet, or a \r that may be half of \r\n
            for line in lines:
                yield line.splitlines()[0]
            while len(carry) > RAW_LINE_CAP:
                yield carry[:RAW_LINE_CAP]
                carry = carry[RAW_LINE_CAP - RAW_OVERLAP:]
            if not chunk:
                return


def raw_mention(path: Path) -> Optional[str]:
    """#5552, #5717: where the first pool-mode mention is in the bytes of a file the gate cannot read as text, under
    the gate's own mention rules R1/R2/R4 with the shadow fold (a line, or a line joined to the one before), as
    "<codec>+<offset> view, line <n>", or None. Every view in RAW_VIEWS is read twice: NUL as a line break, and NUL
    removed. The first bytes of the file decide nothing."""
    for codec, offset in RAW_VIEWS:
        for drop_nul in (False, True):
            before = ""
            for number, raw in enumerate(_raw_lines(path, codec, offset, drop_nul), 1):
                if _INERT.fullmatch(raw):
                    before = ""  # it adds no letter to a joined pair either
                    continue
                text = normalise(raw)
                if text and (mentions(text) or (before and mentions(before + " " + text)) or raw_hides(text)):
                    return "%s+%d view%s, line %d" % (codec, offset, ", NUL removed" if drop_nul else "", number)
                before = text
    return None


SPELL_CAP = 15  # #5717: a longer run is not read as a spelled key word (13 letters at most, and two more)
# Any cap above 15 reads the same runs, since _spelled_word also needs len(word) <= len(key) + 2 <= 15; a cap below
# 15 misses a spelled transactional (the self-test pins 14).


def _lookalike_letter(c: str) -> bool:
    return unicodedata.category(c).startswith("L") and unicodedata.name(c, "?").split(" ", 1)[0] in _LOOKALIKE_SCRIPTS


_SPELL_TOKEN = re.compile(r"[^\s!-/:-@\[-`{-~]+")  # a run with no space and no ASCII punctuation


def _spelled_word(view: str) -> bool:
    """#5717: a run of a shadow view that spells a key word once each character outside ASCII is read as one letter or
    none. The run has at least three ASCII letters and at most two characters more than the key word; at most two
    letters of the key word are missing from its ASCII and look-alike letters; and it holds at most
    max(0, (len(key) - 5) // 2) other characters (a CJK character, a symbol, U+FFFD): none in pool or mode, three in
    transaction. Decoded binary data holds such characters next to ASCII letters everywhere, so a short key word is
    read only from letters."""
    for word in _SPELL_TOKEN.findall(view):
        if word.isascii() or len(word) > SPELL_CAP or sum(1 for c in word if _ascii_letter(c)) < 3:
            continue
        known = sum(1 for c in word if c.isascii() or _lookalike_letter(c))
        wild = re.compile("".join(re.escape(c) if c.isascii() else ".?" for c in word))
        for key in _KEY_WORDS:
            junk = max(0, (len(key) - 5) // 2)
            if len(word) <= len(key) + 2 and known >= len(key) - 2 and len(word) - known <= junk and wild.fullmatch(key):
                return True
    return False


def raw_hides(text: str) -> bool:
    """#5717: R9 for a line of a view of a skipped file, scoped to words, since decoded binary data holds U+FFFD and
    stray letters on almost every line: a reordering character on a line that names a pool, mode or product word read
    either way round, a word of four or more look-alike letters (#5363), or a spelled key word (_spelled_word)."""
    if text.isascii():
        return False  # no reordering character, no letter outside ASCII: mentions() has read the line
    view = shadow(text)
    return (any(c in BIDI for c in text) and bool(_QUICK.search(view) or _QUICK.search(view[::-1]))) \
        or _lookalike_word(view) or _spelled_word(view)


def skip_problem(reason: str) -> Optional[str]:
    """Why a skip entry may not excuse a file whose Unreadable reason is `reason`, or None (shared with regen)."""
    if RAW_MENTION_MARK in reason:
        return "its %s: it is text-like and is read, never skipped" % RAW_MENTION_MARK
    if not reason.startswith(MAGIC_REASON):
        return "it has no binary magic number (%s): it is text and is read, never skipped" % reason
    return None


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
            where = raw_mention(path)  # an OSError propagates: run() reports a FAULT
            unread[rel] = str(exc) + ("" if where is None else "; %s (%s)" % (RAW_MENTION_MARK, where))
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
    except (OSError, UnicodeDecodeError) as exc:  # R5: a decode error is a FAULT (rc 2), not a traceback
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
        if not problem and Path(line).suffix.lower() not in BINARY_SUFFIXES:
            problem = "a %s file is not a declared binary type and is read, never skipped" % (Path(line).suffix.lower() or "suffix-less")
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
    # #5478: a suffix alone proves nothing. Only a file that opens with a known binary magic number may be skipped;
    # text that holds a NUL byte under a binary suffix is still text (PgBouncer %include takes any file name).
    # #5552: a magic number alone proves nothing either (several are printable): a file whose raw bytes hold a
    # pool-mode mention is refused whatever its first bytes are.
    stale += ["%s: skip entry refused: %s" % (rel, skip_problem(unread[rel]))
              for rel in sorted(listed) if rel in unread and skip_problem(unread[rel])]
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
    except (OSError, UnicodeDecodeError) as exc:
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
    except (OSError, UnicodeDecodeError) as exc:
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
    # round-7 sweep: look-alike scripts, markup inside a word, a pool word hidden behind a look-alike letter
    ("R9 sweep: a four-letter Coptic word", "docs/a.md", "Use \u2ca6\u2ca2\u2c80\u2c9a here.\n"),
    ("R9 sweep: a four-letter Cherokee word", "docs/a.md", "Use \u13a2\u13a3\u13a4\u13a5 here.\n"),
    ("R9 sweep: a pool word spelled with look-alike letters on a line with a hiding symbol", "docs/a.md", "Use p\u043e\u043el ab\u2016 here.\n"),
    ("R1 sweep: asterisks inside the mode word", "docs/a.md", "Run PgBouncer in tran*sac*tion mode.\n"),
    # #5370: R9 reads the neighbour on each side of a hiding symbol on its own
    ("R9 #5370: a symbol touching an ASCII letter on its left only", "docs/a.md", "Our pgbouncer runs ab\u2016 for the api tier.\n"),
    ("R9 #5370: a symbol touching an ASCII letter on its right only", "docs/a.md", "Our pgbouncer runs \u2016ab for the api tier.\n"),
    # #5363: a mode word made only of letters the fold does not know (small capitals), with or without an ASCII neighbour
    ("R9 #5363: a mode word of small capitals only", "docs/a.md", "Run PgBouncer in \u1d1b\u0280\u1d00\u0274\ua731\u1d00\u1d04\u1d1b\u026a\u1d0f\u0274 \u1d0d\u1d0f\u1d05\u1d07.\n"),
    ("R9 #5363: small capitals pooling after an ASCII-touching letter", "docs/a.md", "Use \u1d1b\u0280\u1d00\u0274s\u1d00\u1d04\u1d1b\u026a\u1d0f\u0274 \u1d18\u1d0f\u1d0f\u029f\u026a\u0274\u0262.\n"),
    # #5364: bidi controls reorder a line; they are reported, never dropped silently
    ("R9 #5364: a reversed mode word between bidi overrides", "docs/a.md", "Run PgBouncer in \u202enoitcasnart\u202c mode.\n"),
    ("R9 #5364: a reversed pooling word between bidi overrides", "docs/a.md", "Use \u202enoitcasnart\u202c pooling.\n"),
    ("R9 #5364: a bidi isolate on a line with no pool word", "docs/a.md", "Use \u2067noitcasnart\u2069 here.\n"),
    ("R9 #5364: a left-to-right mark on a line with no pool word", "docs/a.md", "Use it\u200e now.\n"),
    ("R9 #5364: a right-to-left mark on a line with no pool word", "docs/a.md", "Use it\u200f now.\n"),
    ("R9 #5364: an Arabic letter mark on a line with no pool word", "docs/a.md", "Use it\u061c now.\n"),
    ("R9 #5364: the first embedding control on a line with no pool word", "docs/a.md", "Use it\u202a now.\n"),
    ("R9 #5364: the last override control on a line with no pool word", "docs/a.md", "Use it\u202e now.\n"),
    ("R9 #5364: the last isolate control on a line with no pool word", "docs/a.md", "Use it\u2069 now.\n"),
    ("R9 #5364: the first isolate control on a line with no pool word", "docs/a.md", "Use it\u2066 now.\n"),
    # #5365: markdown underscore emphasis wraps the mode word
    ("R1 #5365: single underscore emphasis on the mode word", "docs/a.md", "Run PgBouncer in _transaction_ mode.\n"),
    ("R1 #5365: double underscore emphasis over mode and pooling", "docs/a.md", "Use __transaction pooling__.\n"),
    ("R1 #5365: underscore emphasis on the second word only", "docs/a.md", "Use pooling _transaction_ everywhere.\n"),
    ("R1 #5476: triple underscore emphasis on the mode word", "docs/a.md", "Run PgBouncer in ___transaction___ mode.\n"),
    ("R1 #5476: triple underscore emphasis over two words", "docs/a.md", "Use ___transaction pooling___ here.\n"),
    ("R1 #5476: four underscore emphasis on the mode word", "docs/a.md", "Run PgBouncer in ____transaction____ mode.\n"),
    ("R1 #5480: a trailing underscore on the mode word", "docs/a.md", "Run PgBouncer in transaction_ mode.\n"),
    ("R1 #5480: a leading underscore on the mode word", "docs/a.md", "Run PgBouncer in _transaction mode.\n"),
    ("R1 #5480: an underscore on each side with a space", "docs/a.md", "Run PgBouncer in _ transaction_ mode.\n"),
    ("R1 #5480: two trailing underscores on the mode word", "docs/a.md", "Run PgBouncer in transaction__ mode.\n"),
    ("R1 #5480: a leading underscore on the second word", "docs/a.md", "Run PgBouncer in pooling _statement.\n"),
    ("R1 #5480: an emphasis span may not open before a space", "docs/a.md", "Run PgBouncer in _ transaction__transaction mode.\n"),
    ("R1 #5480: an emphasis span may not close after a space", "docs/a.md", "Run PgBouncer in transaction__transaction _ mode.\n"),
    ("R9 #5480: a hidden character splits a four-letter Coptic word", "docs/a.md", "Notes: \u2c80\u2c82\u200b\u2c84\u2c86 here.\n"),
    ("R1 #5480: stroked Latin letters spell the mode word", "docs/a.md", "Use \u0167ransac\u0167\u0268\u00f8n m\u00f8\u0111e.\n"),
    ("R9 #5363: a letter the fold does not know, spaced, on a pool line", "docs/a.md", "Run PgBouncer in \u0434\u0436\u0437\u0438\u044f mode.\n"),
    ("R9 #5363: small capitals on a config context line fold to the mode word", "docs/a.md",
     "```ini\npool_mode = session\ndefault = \u1d1b\u0280\u1d00\u0274s\u1d00\u1d04\u1d1b\u026a\u1d0f\u0274\n```\n"),
    ("R9 #5363: a four-letter foreign word with no pool word on the line", "docs/a.md", "Look at \u0434\u0436\u0437\u044f here.\n"),
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
    ("look-alikes in every pool and mode word (three per word: past the key-word fold)", "docs/a.md",
     "Set the p\u043e\u043el\u0435r to tr\u0430ns\u0430cti\u043en.\n"),
    ("soft hyphen in the mode word", "docs/a.md", "Run PgBouncer in trans\u00adaction mode.\n"),
    ("soft hyphen in a pooling claim with no product word (#5211)", "docs/a.md", "Use tr\u00adansaction pooling.\n"),
    ("zero-width inside the key, nothing else non-ASCII (#5211)", "docs/a.md", "pool_mo\u200bde = transaction\n"),
    # round 6 (#5089): format characters hide the mode word AND the pool word, so only shadow's Cf drop sees it
    ("soft hyphens in the mode word and the pool word (#5089)", "docs/a.md", "Use tr\u00adansaction po\u00adoling.\n"),
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
    ("R9 sweep: a private-mode terminal code on a pooler line renders as nothing", "docs/a.md", "\x1b[?25lour pgbouncer runs the api\x1b[?25h\n"),
    ("R9 #5370: a symbol set apart by spaces hides no word", "docs/a.md", "Our pgbouncer runs \u2016 ab for the api tier.\n"),
    ("R9 #5370: a symbol first on the line does not read the last letter", "docs/a.md", "\u2016 our pgbouncer runs the api\n"),
    ("R9 #5370: a symbol last on the line reads no neighbour past the end", "docs/a.md", "our pgbouncer runs the api \u2016\n"),
    ("R1 #5480: one underscore emphasis on the session value is stripped", "docs/a.md", "pool_mode = _session_\n"),
    ("R1 #5480: two underscore emphasis on the session value is stripped", "docs/a.md", "pool_mode = __session__\n"),
    ("R1 #5480: three underscore emphasis on the session value is stripped", "docs/a.md", "pool_mode = ___session___\n"),
    ("R1 #5480: four underscore emphasis on the session value is stripped", "docs/a.md", "pool_mode = ____session____\n"),
    ("R1 #5555: five underscore emphasis on the session value is stripped", "docs/a.md", "pool_mode = _____session_____\n"),
    ("R1 #5555: eight underscore emphasis on the session value is stripped", "docs/a.md", "pool_mode = ________session________\n"),
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
    ("R9 #5363 a three-letter foreign word and a Hebrew word with no pool word", "docs/a.md", "See \u0434\u0436\u0437 and \u05e9\u05dc\u05d5\u05dd here.\n"),
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


def entry_case(label: str, line: str, ok: bool = False) -> Tuple[str, Dict[str, object], int]:
    """An allowlist entry for `line` in a shell script: refused (rc 2) when it sets the mode, accepted when it only quotes it."""
    rel = "infra/x/setup.sh"
    return (label, tree({rel: line + "\n"}, REASON + ent(rel, line + "\n", normalise(line))), EXIT_OK if ok else EXIT_FAULT)


def skip_tree(rel: str, body: bytes) -> Dict[str, object]:
    """A tree whose one tracked file `rel` is named in the skip list with a reason."""
    return tree({rel: body}, unread=UNREAD_REASON + rel + "\n")


MENTION = b"pool_mode = transaction\n"  # a claim that must never hide in a skipped file (#5552)


def skip_spelled(label: str, spelling: str, codec: str, head: bytes = b"%PDF\n") -> Tuple[str, Dict[str, object], int]:
    """#5717: a skip-listed file whose bytes after a printable magic number spell a mention in `codec`: a fault."""
    body = head + spelling.encode(codec) + b"\n\0"
    return ("a %s mention spelled with %s cannot be skipped (#5717)" % (codec, label), skip_tree("docs/z.bin", body), EXIT_FAULT)


# #5717: spellings the text scan reads as a mention (R4 shadow fold), each hidden in a skipped file in an encoding the
# text reader decodes. The head b"%PDF\n" is five bytes, so a UTF-16 run starts on an odd byte and a UTF-32 run on 1 mod 4.
SPELLED = (
    ("an en dash", "PgBouncer transaction–mode", "utf-8"),
    ("a non-breaking hyphen", "PgBouncer transaction‑mode", "utf-8"),
    ("a Cyrillic a", "Run PgBouncer in trаnsaction mode.", "utf-8"),
    ("a zero-width space", "Run PgBouncer in trans​action mode.", "utf-8"),
    ("a soft hyphen", "Run PgBouncer in trans­action mode.", "utf-8"),
    ("a Greek o and a Cyrillic a", "pοol_mode = trаnsaction", "utf-8"),
    ("a no-break space", "Run PgBouncer in transaction mode.", "utf-8"),
    ("full-width letters", "Run PgBouncer in ｔｒansaction mode.", "utf-8"),
    ("a decomposed accent", "Run PgBouncer in transactión mode.", "utf-8"),
    ("a word joiner", "pool_mo⁠de = transaction", "utf-8"),
    ("a mathematical bold t", "Run PgBouncer in \U0001d42dransaction mode.", "utf-8"),
    ("a Hangul filler", "Run PgBouncer in transㅤaction mode.", "utf-8"),
    ("Latin letters outside the look-alike table", "Run PgBouncer in trɑnsɑctiɔn mode.", "utf-8"),
    ("plain ASCII on an odd byte", "pool_mode = transaction", "utf-16-le"),
    ("a Cyrillic a", "Run PgBouncer in trаnsaction mode.", "utf-16-le"),
    ("full-width letters", "Run PgBouncer in ｔｒansaction mode.", "utf-16-be"),
    ("a mathematical bold t", "Run PgBouncer in \U0001d42dransaction mode.", "utf-16-be"),
    ("a word joiner", "pool_mo⁠de = transaction", "utf-32-le"),
    ("Latin letters outside the look-alike table", "Run PgBouncer in trɑnsɑctiɔn mode.", "utf-32-be"),
    # R9 forms the mention rules do not read, refused in a view by the word-scoped raw_hides()
    ("a right-to-left override", "‮edom_loop = noitcasnart‬", "utf-8"),
    ("a right-to-left override", "‮edom_loop = noitcasnart‬", "utf-16-be"),
    ("a word of Cherokee look-alikes", "ᏢᎾᎾᏞ_mode = transaction", "utf-8"),
    ("a word of Cherokee look-alikes", "ᏢᎾᎾᏞ_mode = transaction", "utf-32-le"),
    ("Cherokee look-alikes around ASCII letters", "Run it in ᎢᎡᎪnsᎪᏟᎢᎥᎾn mode.", "utf-8"),
    ("Cherokee look-alikes around ASCII letters", "Run it in ᎢᎡᎪnsᎪᏟᎢᎥᎾn mode.", "utf-16-le"),
    ("a symbol inside the word", "Run it in trans★action mode.", "utf-8"),
    ("a symbol inside the word", "Run it in trans★action mode.", "utf-32-be"),
    # the edges of each view and of each _spelled_word limit (a mutant of the view list or a limit changes the result)
    ("five mathematical bold letters", "Run it in \U0001d42d\U0001d42b\U0001d41a\U0001d427\U0001d42caction mode.",
     "utf-32-le"),
    ("three look-alike letters inserted in pool", "Run it in po\u0254\u0254\u0254l mode.", "utf-8"),
    ("three look-alike letters inserted in mode", "Run it in transaction m\u0254\u0254\u0254de.", "utf-8"),
    ("a mathematical bold t", "Run it in \U0001d42dransaction mode.", "utf-32-be"),
    ("Latin-1 accented letters", "Run it in trànsàctión mode.", "latin-1"),
    ("a Cyrillic a and a NUL code unit", "Run it in trаns\0action mode.", "utf-16-le"),
    ("Cyrillic letters and a space only", "рооӏ моԁе", "utf-8"),
    ("full-width characters only", "ｐｏｏｌ＿ｍｏｄｅ　＝　"
     "ｔｒａｎｓａｃｔｉｏｎ", "utf-8"),
    ("a word of Cherokee look-alikes and no ASCII letter", "Run it in ᎢᎡᎪᏁᏚᎪᏟᎢ"
     "ᎥᎾᏁ mode.", "utf-8"),
    ("two missing letters and a third star (the known and junk limits)", "Run it in tr★ns★ct★ion mode.",
     "utf-8"),
    ("two stars in a 15-character run (SPELL_CAP)", "Run it in trans★action★al mode.", "utf-8"),
)

# #5717 stated limits: one step past each _spelled_word limit the run is read as data, as decoded binary data is.
PAST_SPELL_LIMITS = (
    ("four stars, one more than transaction allows", "Run it in tr★ns★ct★ion★ mode."),
    ("three missing letters", "Run it in ★r★ns★ction mode."),
    ("three characters more than multiplexing has", "Run it in multi★plex★ing★ mode."),
    ("two ASCII letters", "Run it in pᏅᏅl mode."),
)


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
    # #5211: R5 and R6 context lines get the shadow view
    lk = "PgBouncer session mode is supported.\nIt fronts the primary.\nIt listens on 6432.\nFor fan-in, switch it to tr\u0430nsaction.\n"
    zw = lk.replace("tr\u0430nsaction", "trans\u200baction")
    # round 5 reviews (#5089): R7 binds every part of the neighbourhood; each sub-rule has a pinning case
    para0 = "Transaction mode is not supported (#4667).\na\nb\nc\nd\n"
    para1 = para0.replace("c\n", "It is now recommended.\n")
    far0 = "Transaction mode is not supported (#4667).\n\nOld note.\n"
    far1 = far0.replace("Old note.", "It is now recommended.")
    pr0 = "PgBouncer session mode is supported, or\nstatement.\n\nx\ny\nz\n"
    pr1 = pr0.replace("y\n", "It is now recommended.\n")
    pr_allow = REASON + ent("docs/a.md", pr0, "pgbouncer session mode is supported, or") + ent(
        "docs/a.md", pr0, "pgbouncer session mode is supported, or statement.")
    sep0 = "x\nab\nTransaction mode is not supported (#4667).\nc\n"
    sep1 = "x\na\nTransaction mode is not supported (#4667).\nbc\n"
    ord0 = "x1\nx2\nTransaction mode is not supported (#4667).\n"
    ord1 = "x2\nx1\nTransaction mode is not supported (#4667).\n"
    out += [
        ("R7: an edit in the paragraph beyond the two neighbours makes the entry stale (#5088)",
         tree({"docs/a.md": para1}, REASON + ent("docs/a.md", para0, "transaction mode is not supported (#4667).")), EXIT_FAULT),
        ("R7: an edit to a neighbour across a blank line makes the entry stale (#5087)",
         tree({"docs/a.md": far1}, REASON + ent("docs/a.md", far0, "transaction mode is not supported (#4667).")), EXIT_FAULT),
        ("R7: an edit next to the far line of a pair makes the pair entry stale (#5087)",
         tree({"docs/a.md": pr1}, pr_allow), EXIT_FAULT),
        ("R7: the pair entry passes while its neighbourhood is unchanged", tree({"docs/a.md": pr0}, pr_allow), EXIT_OK),
        ("R7: moving a line break between context lines changes the fingerprint (#5087)",
         tree({"docs/a.md": sep1}, REASON + ent("docs/a.md", sep0, "transaction mode is not supported (#4667).")), EXIT_FAULT),
        ("R7: reordering the neighbours makes the entry stale (#5087)",
         tree({"docs/a.md": ord1}, REASON + ent("docs/a.md", ord0, "transaction mode is not supported (#4667).")), EXIT_FAULT),
        ("R7: text after the fingerprint fails", tree(retired, REASON + retired_entry.replace("\n", " x\n")), EXIT_FAULT),
        ("a reason of two words repeated fails (#4961)",
         tree(retired, "# reviewed history reviewed history reviewed history\n" + retired_entry), EXIT_FAULT),
        ("a NUL byte past the first read chunk fails closed (#5086)",
         tree({"docs/n.md": ("x" * 99 + "\n") * 11000 + "\0\n"}), EXIT_FAULT),
        ("a BOM-less UTF-16LE file with a third NULs is decoded and judged",
         tree({"docs/u.txt": ("Run PgBouncer in transaction mode. " + "\u4e2d" * 20 + "\n").encode("utf-16-le")}), EXIT_FINDING),
        ("a UTF-16 file with a BOM and few NULs is decoded and judged",
         tree({"docs/u.txt": ("\u4e2d" * 200 + "\nRun PgBouncer in transaction mode.\n").encode("utf-16")}), EXIT_FINDING),
        ("a path listed twice on the skip list fails",
         tree({"docs/z.md.gz": b"\x1f\x8b\x08\x00zzz"}, unread=UNREAD_REASON + "docs/z.md.gz\ndocs/z.md.gz\n"), EXIT_FAULT),
        ("R5: a look-alike mode word in the paragraph of an allowlisted line is paired (#5211)",
         tree({"docs/a.md": lk}, REASON + ent("docs/a.md", lk, "pgbouncer session mode is supported.")), EXIT_FINDING),
        ("R5: a zero-width-split mode word in the paragraph of an allowlisted line is paired (#5211)",
         tree({"docs/a.md": zw}, REASON + ent("docs/a.md", zw, "pgbouncer session mode is supported.")), EXIT_FINDING),
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
        # #5365: an underscore inside a word (sqlx_s_, _b_c) is not emphasis, so the entry keeps it
        ("an underscore at the end of a word stays in the entry text",
         tree({"docs/a.md": "Old sqlx_s_ transaction mode is not supported.\n"},
              REASON + ent("docs/a.md", "Old sqlx_s_ transaction mode is not supported.",
                           "old sqlx_s_ transaction mode is not supported.")), EXIT_OK),
        ("an underscore at the start of a word stays in the entry text",
         tree({"docs/a.md": "Old _b_c transaction mode is not supported.\n"},
              REASON + ent("docs/a.md", "Old _b_c transaction mode is not supported.",
                           "old _b_c transaction mode is not supported.")), EXIT_OK),
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
        # #5366: a pool_mode key assigned transaction anywhere on the line is refused, in any spelling
        ("an entry with shell export sets the mode and is refused",
         tree({"infra/x/setup.sh": "export pgbouncer_pool_mode=transaction\n"}, REASON + ent("infra/x/setup.sh", "export pgbouncer_pool_mode=transaction\n", "export pgbouncer_pool_mode=transaction")), EXIT_FAULT),
        ("an entry with inline json sets the mode and is refused",
         tree({"infra/x/setup.sh": "{\"pool_mode\": \"transaction\"}\n"}, REASON + ent("infra/x/setup.sh", "{\"pool_mode\": \"transaction\"}\n", "{\"pool_mode\": \"transaction\"}")), EXIT_FAULT),
        ("an entry with dockerfile env sets the mode and is refused",
         tree({"infra/x/setup.sh": "env pool_mode=transaction\n"}, REASON + ent("infra/x/setup.sh", "env pool_mode=transaction\n", "env pool_mode=transaction")), EXIT_FAULT),
        ("an entry with docker run -e sets the mode and is refused",
         tree({"infra/x/setup.sh": "docker run -e pool_mode=transaction edoburu/pgbouncer\n"}, REASON + ent("infra/x/setup.sh", "docker run -e pool_mode=transaction edoburu/pgbouncer\n", "docker run -e pool_mode=transaction edoburu/pgbouncer")), EXIT_FAULT),
        ("an entry with look-alike letter sets the mode and is refused",
         tree({"infra/x/setup.sh": "pool_mode = tr\u0430nsaction\n"}, REASON + ent("infra/x/setup.sh", "pool_mode = tr\u0430nsaction\n", "pool_mode = tr\u0430nsaction")), EXIT_FAULT),
        # #5368: the fold paths of _fold_word, each on a config-shaped context line that names no pool word, so R9
        # stays quiet and only the fold decides. U+0578 (Armenian) is outside CONFUSABLE on purpose.
        ("fold by wildcard: one foreign letter replaces a letter of the mode word",
         tree({"docs/a.md": "```ini\npool_mode = session\ndefault = tr\u0578nsaction\n```\n"}), EXIT_FINDING),
        ("fold by drop: one foreign letter is inserted into the mode word",
         tree({"docs/a.md": "```ini\npool_mode = session\ndefault = transa\u0578ction\n```\n"}), EXIT_FINDING),
        ("fold by wildcard with two foreign letters",
         tree({"docs/a.md": "```ini\npool_mode = session\ndefault = tr\u0578\u0578saction\n```\n"}), EXIT_FINDING),
        ("a mode word with three foreign letters is not folded",
         tree({"docs/a.md": "```ini\npool_mode = session\ndefault = tr\u0578\u0578\u0578action\n```\n"}), EXIT_OK),
        # round-7 sweep: alternatives of the forbidden shapes, the spaced skip path, and lazy emphasis spans
        ("an entry with a statement export is refused",
         tree({"infra/x/setup.sh": "export pgbouncer_pool_mode=statement\n"}, REASON + ent("infra/x/setup.sh", "export pgbouncer_pool_mode=statement\n", "export pgbouncer_pool_mode=statement")), EXIT_FAULT),
        ("an entry with a poolmode export is refused",
         tree({"infra/x/setup.sh": "export poolmode=transaction\n"}, REASON + ent("infra/x/setup.sh", "export poolmode=transaction\n", "export poolmode=transaction")), EXIT_FAULT),
        ("a skip entry names one exact path without spaces",
         tree({"docs/a b.pdf": b"%PDF-1.7\n\x93\xff\0"}, unread=UNREAD_REASON + "docs/a b.pdf\n"), EXIT_FAULT),
        ("two emphasis spans on one line lose their underscores separately",
         tree({"docs/a.md": "Old _a_ x _b_ transaction mode is not supported.\n"},
              REASON + ent("docs/a.md", "Old _a_ x _b_ transaction mode is not supported.",
                           "old a x b transaction mode is not supported.")), EXIT_OK),
        # #5477: shapes that set the mode and were not refused (round-7 review, F3)
        entry_case("an entry with kubectl set env is refused", "kubectl set env deploy/pgbouncer pool_mode=transaction"),
        entry_case("an entry with oc set env and three arguments is refused", "oc set env dc/pgbouncer -c pgbouncer pool_mode=transaction"),
        entry_case("an entry with env and exactly four arguments is refused (#5554)", "oc env dc/pgbouncer -c pgbouncer -n pool_mode=transaction"),
        entry_case("an entry with an env prefix on a script is refused", "POOL_MODE=transaction ./entrypoint.sh"),
        entry_case("an entry with an env prefix on a parent path is refused", "pool_mode=statement ../run.sh"),
        entry_case("an entry with an env prefix on an absolute path is refused", "pool_mode=transaction /usr/bin/pgbouncer pgbouncer.ini"),
        entry_case("an entry with an env prefix on a home path is refused", "pool_mode=transaction ~/bin/start"),
        entry_case("an entry with an env prefix on a variable is refused", "pool_mode=transaction $PGB_CMD"),
        entry_case("an entry with an env prefix on exec is refused", "pool_mode=transaction exec pgbouncer"),
        entry_case("an entry with an env prefix on sudo is refused", "pool_mode=transaction sudo -u pgbouncer pgbouncer"),
        entry_case("an entry with an env prefix on bash is refused", "pool_mode=transaction bash -c start"),
        entry_case("an entry with an env prefix on pgbouncer is refused", "pool_mode=transaction pgbouncer pgbouncer.ini"),
        entry_case("an entry with a quoted env prefix is refused", "pool_mode=\"transaction\" ./entrypoint.sh"),
        entry_case("an entry with a yaml flow mapping is refused", "environment: { pool_mode: transaction }"),
        entry_case("an entry with a toml inline table is refused", "pgbouncer = { pool_mode = \"transaction\" }"),
        entry_case("an entry with a flow mapping that opens on a comma is refused", "env: {a: 1, pool_mode: statement}"),
        entry_case("an entry with helm --set is refused", "helm install pgb chart --set config.pgbouncer.pool_mode=transaction"),
        entry_case("an entry with helm --set-string is refused", "helm install pgb chart --set-string pool_mode=statement"),
        entry_case("an entry with the admin console SET is refused", "SET pool_mode = 'transaction';"),
        entry_case("an entry with sed is refused", "sed -i 's/pool_mode = session/pool_mode = transaction/' pgbouncer.ini"),
        entry_case("an entry with awk is refused", "awk -v x=1 '{print}' pool_mode=transaction pgbouncer.ini"),
        entry_case("an entry with perl is refused", "perl -pi -e 's/pool_mode = session/pool_mode = transaction/' pgbouncer.ini"),
        entry_case("an entry with echo is refused", "echo 'pool_mode = transaction' >> pgbouncer.ini"),
        entry_case("an entry with printf is refused", "printf 'pool_mode = statement\\n' >> pgbouncer.ini"),
        entry_case("an entry with tee is refused", "tee -a pgbouncer.ini <<< pool_mode=transaction"),
        entry_case("an entry with docker --env= is refused", "docker run --env=POOL_MODE=transaction img"),
        entry_case("an entry with a Dockerfile ENV space form is refused", "ENV POOL_MODE transaction"),
        entry_case("an entry with crudini is refused", "crudini --merge pgbouncer.ini pgbouncer pool_mode=transaction"),
        entry_case("an entry with crudini --set is refused", "crudini --set pgbouncer.ini pgbouncer pool_mode transaction"),
        entry_case("an entry with a quoted key before the equals sign is refused (#5480)", "export \"pool_mode\"=transaction"),
        entry_case("an entry with a quoted json key and the statement value is refused (#5480)", "see \"pool_mode\": \"statement\" in the file"),
        entry_case("an entry with a quoted json key inside a sentence is refused", "see \"pool_mode\": \"transaction\" in the file"),
        entry_case("an entry with yq is refused", "yq -i '.pool_mode = transaction' values.yaml"),
        # the same words in prose stay allowlistable: a retirement note quotes the setting
        entry_case("prose that quotes pool_mode=transaction mid-sentence stays allowed", "Withdrawn: pool_mode=transaction / was required", ok=True),
        entry_case("prose that starts with the key and a space-slash stays allowed", "pool_mode=transaction / max_client_conn were sketched", ok=True),
        # files read, not skipped (#5086, #5090)
        ("NUL bytes in a markdown file fail closed", tree({"docs/n.md": "\0\nRun PgBouncer in transaction mode.\n"}), EXIT_FAULT),
        ("a gzip document fails closed", tree({"docs/z.md.gz": b"\x1f\x8b\x08\x00zzz"}), EXIT_FAULT),
        ("a magic number on plain UTF-8 text is read as text and judged (R5)", tree({"docs/p.md": b"%PDF-1.7 Run PgBouncer in transaction mode.\n"}), EXIT_FINDING),
        ("a magic number on binary bytes fails closed", tree({"docs/p.md": b"%PDF-1.7\n\x93\xff Run PgBouncer in transaction mode.\n"}), EXIT_FAULT),
        ("a named unreadable file with a reason passes",
         tree({"docs/z.md.gz": b"\x1f\x8b\x08\x00zzz"}, unread=UNREAD_REASON + "docs/z.md.gz\n"), EXIT_OK),
        # #5367: the skip list excuses declared binary types only, so a NUL byte in other text cannot hide a claim
        ("a NUL byte in a .tpl file fails closed", tree({"infra/x/cloud-init.tpl": b"Run PgBouncer in transaction mode.\n\0\n"}), EXIT_FAULT),
        ("a .tpl file in the skip list is refused",
         tree({"infra/x/cloud-init.tpl": b"Run PgBouncer in transaction mode.\n\0\n"}, unread=UNREAD_REASON + "infra/x/cloud-init.tpl\n"), EXIT_FAULT),
        ("a suffix-less file in the skip list is refused",
         tree({"infra/x/Dockerfile": b"Run PgBouncer in transaction mode.\n\0\n"}, unread=UNREAD_REASON + "infra/x/Dockerfile\n"), EXIT_FAULT),
        ("a .service file in the skip list is refused",
         tree({"infra/x/pgb.service": b"Run PgBouncer in transaction mode.\n\0\n"}, unread=UNREAD_REASON + "infra/x/pgb.service\n"), EXIT_FAULT),
        ("an upper-case binary suffix is still a declared binary type",
         tree({"docs/z.GZ": b"\x1f\x8b\x08\x00zzz"}, unread=UNREAD_REASON + "docs/z.GZ\n"), EXIT_OK),
        ("a skip entry without a reason fails",
         tree({"docs/z.md.gz": b"\x1f\x8b\x08\x00zzz"}, unread="docs/z.md.gz\n"), EXIT_FAULT),
        ("a skip entry with a filler reason fails",
         tree({"docs/z.md.gz": b"\x1f\x8b\x08\x00zzz"}, unread="# todo todo todo todo todo todo todo todo\ndocs/z.md.gz\n"), EXIT_FAULT),
        ("a skip entry with the placeholder fails",
         tree({"docs/z.md.gz": b"\x1f\x8b\x08\x00zzz"}, unread="# REASON REQUIRED before review - say why\ndocs/z.md.gz\n"), EXIT_FAULT),
        ("a stale skip entry (the file is readable text) fails", tree({"docs/ok.md": "Plain text.\n"}, unread=UNREAD_REASON + "docs/ok.md\n"), EXIT_FAULT),
        ("a stale skip entry for a readable file with a binary name fails",
         tree({"assets/ok.bin": "Plain text.\n"}, unread=UNREAD_REASON + "assets/ok.bin\n"), EXIT_FAULT),
        ("a magic-number file under a text suffix cannot be skipped (#5367)",
         tree({"docs/z.md": b"\x1f\x8b\x08\x00zzz"}, unread=UNREAD_REASON + "docs/z.md\n"), EXIT_FAULT),
        ("a skip entry for an untracked path fails", tree({}, unread=UNREAD_REASON + "docs/gone.md\n"), EXIT_FAULT),
        ("a text file is never excused by the skip list (R5)",
         tree({"docs/n.md": "\0\nRun PgBouncer in transaction mode.\n"}, unread=UNREAD_REASON + "docs/n.md\n"), EXIT_FAULT),
        # #5478: the suffix is not proof of binary content; a NUL-only file under a binary suffix is text with a hidden claim
        ("a .bin file with a NUL byte and no magic number cannot be skipped (#5478)",
         tree({"infra/pgbouncer/override.bin": b"pool_mode = transaction\n\0\n"}, unread=UNREAD_REASON + "infra/pgbouncer/override.bin\n"), EXIT_FAULT),
        ("a .db file with a NUL byte and no magic number cannot be skipped (#5478)",
         tree({"docs/notes.db": b"pool_mode = transaction\n\0\n"}, unread=UNREAD_REASON + "docs/notes.db\n"), EXIT_FAULT),
        ("a .bin file with a NUL byte and no magic number is a fault with no skip entry (#5478)",
         tree({"infra/pgbouncer/override.bin": b"pool_mode = transaction\n\0\n"}), EXIT_FAULT),
        ("a .bin file that opens with a binary magic number may be skipped (#5478)",
         tree({"assets/blob.bin": b"\x7fELF\x02\x01\x01\0zzz"}, unread=UNREAD_REASON + "assets/blob.bin\n"), EXIT_OK),
        # #5552 (#5552): a printable magic number is not proof of binary content; a skipped file must hold no mention at all
        ("GIF8 and a NUL byte over a mention cannot be skipped (#5552)", skip_tree("infra/pgbouncer/override.bin", b"GIF8 = 1\n" + MENTION + b"\0"), EXIT_FAULT),
        ("%PDF and a NUL byte over a mention cannot be skipped (#5552)", skip_tree("infra/pgbouncer/override.bin", b"%PDF\n" + MENTION + b"\0"), EXIT_FAULT),
        ("BZh and a NUL byte over a mention cannot be skipped (#5552)", skip_tree("infra/pgbouncer/override.bin", b"BZh\n" + MENTION + b"\0"), EXIT_FAULT),
        ("Rar! and a NUL byte over a mention cannot be skipped (#5552)", skip_tree("infra/pgbouncer/override.bin", b"Rar!\n" + MENTION + b"\0"), EXIT_FAULT),
        ("wOFF and a NUL byte over a mention cannot be skipped (#5552)", skip_tree("infra/pgbouncer/override.bin", b"wOFF\n" + MENTION + b"\0"), EXIT_FAULT),
        ("OTTO and a NUL byte over a mention cannot be skipped (#5552)", skip_tree("infra/pgbouncer/override.bin", b"OTTO\n" + MENTION + b"\0"), EXIT_FAULT),
        ("SQLite format 3 over a mention cannot be skipped (#5552)", skip_tree("docs/notes.db", b"SQLite format 3\0\n" + MENTION), EXIT_FAULT),
        ("UTF-16 text with a BOM under a binary suffix is read, not skipped (#5552)",
         skip_tree("infra/pgbouncer/override.bin", b"\xff\xfe" + MENTION.decode("ascii").encode("utf-16-le")), EXIT_FAULT),
        ("a mention cut by a NUL byte cannot be skipped (#5552)", skip_tree("infra/pgbouncer/override.bin", b"GIF8\npool_\0mode = transaction\n"), EXIT_FAULT),
        ("a word cut in two by a NUL byte cannot be skipped (#5552)", skip_tree("infra/pgbouncer/override.bin", b"GIF8\npo\0ol_mode = session\n"), EXIT_FAULT),
        ("a mention that only exists with each NUL byte read as a line break cannot be skipped (#5552)",
         skip_tree("docs/z.bin", b"GIF8\npgbouncer statement\0x\n"), EXIT_FAULT),
        ("a product and a mode word split by a NUL byte cannot be skipped (#5552)",
         skip_tree("docs/z.bin", b"GIF8\npgbouncer\0session\n"), EXIT_FAULT),
        ("a NUL-only file with no mention cannot be skipped (#5478)", skip_tree("assets/blob.bin", b"hello\n\0\n"), EXIT_FAULT),
        ("a mention after 1 MiB of padding cannot be skipped (#5552)",
         skip_tree("infra/pgbouncer/override.bin", b"GIF89a\0" + b"\0" * (1 << 20) + MENTION), EXIT_FAULT),
        ("a mention in CRLF lines cannot be skipped (#5552)", skip_tree("infra/pgbouncer/override.bin", b"GIF8\r\n" + MENTION[:-1] + b"\r\n\0"), EXIT_FAULT),
        ("a gzip magic number followed by plain text cannot be skipped (#5552)", skip_tree("docs/z.gz", b"\x1f\x8b" + MENTION), EXIT_FAULT),
        ("a prose mention behind a magic number cannot be skipped (#5552)",
         skip_tree("docs/z.bin", b"%PDF\nRun PgBouncer in transaction mode.\n\0"), EXIT_FAULT),
        ("a mention wrapped across two lines cannot be skipped (#5552)", skip_tree("docs/z.bin", b"GIF8\nuse pool\nmode here\n\0"), EXIT_FAULT),
        ("an upper-case mention cannot be skipped (#5552)", skip_tree("docs/z.bin", b"GIF8\nPOOL_MODE = TRANSACTION\n\0"), EXIT_FAULT),
        ("a mention that straddles a read chunk boundary cannot be skipped (#5552)",
         skip_tree("docs/z.bin", b"GIF8\0" + b"x" * (CHUNK_BYTES - 12) + b"pool_mo" + b"de = session\n"), EXIT_FAULT),
        # #5717: the line runs on past the next chunk, so it is cut while it is read (a line that ends in the chunk is
        # never cut), nine letters into transaction: neither half nor the two halves joined is a mention. The NUL
        # before the line break makes the file binary and starts the line at the same byte in both NUL views.
        ("a mention that straddles a raw segment cut cannot be skipped (#5552)",
         skip_tree("docs/z.bin", b"GIF8\0\n" + b"x" * (RAW_LINE_CAP - 10) + b" transacti" + b"on mode "
                   + b"x" * (CHUNK_BYTES + 10) + b"\n"), EXIT_FAULT),
        ("an unlisted GIF8 file with a NUL byte over a mention is a fault (#5552)",
         tree({"infra/pgbouncer/override.bin": b"GIF8\n" + MENTION + b"\0"}), EXIT_FAULT),
        ("an empty file under a binary suffix cannot be skipped (#5552)", skip_tree("infra/pgbouncer/override.bin", b""), EXIT_FAULT),
        ("a real GIF with no mention may be skipped (#5552)", skip_tree("docs/logo.gif", b"GIF89a\x01\0\x01\0\x80\0\0"), EXIT_OK),
        ("a real PDF with binary bytes and no mention may be skipped (#5552)", skip_tree("docs/l.pdf", b"%PDF-1.6\n\x93\xff\0\0endobj\n"), EXIT_OK),
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
        # a list or template that is not UTF-8 is a FAULT (rc 2), never a traceback (#5207)
        ("an allowlist that is not UTF-8 is a FAULT", tree(retired, (REASON + retired_entry).encode("utf-8") + b"# \xff\n"), EXIT_FAULT),
        ("a skip list that is not UTF-8 is a FAULT", dict(tree(retired, REASON + retired_entry), **{UNREAD_REL.as_posix(): b"# \xff\n"}), EXIT_FAULT),
        ("an ini template that is not UTF-8 is a FAULT", tree(ini=b"[pgbouncer]\npool_mode = session\n; \xff\n"), EXIT_FAULT),
        ("a UTF-32 file is decoded and judged", tree({"docs/u.txt": "Run PgBouncer in transaction mode.\n".encode("utf-32")}), EXIT_FINDING),
        # R9 (#4667 round 6): closed world over characters
        # #5479: undecodable text with no NUL byte is read (decoder replacement) and reported as a finding (rc 1), not a fault
        ("R9 #5479: a markdown file with invalid UTF-8 and no NUL is a finding (rc 1), not a fault",
         tree({"docs/u.md": b"Hello \xff\xfe pool notes\n"}), EXIT_FINDING),
        ("R9 #5479: a template with invalid UTF-8 and no NUL is a finding (rc 1), not a fault",
         tree({"infra/x/u.tpl": b"\xc3\x28\n"}), EXIT_FINDING),
        ("R9 #5479: the same bytes with a NUL byte are a fault (rc 2)",
         tree({"infra/x/u.tpl": b"\xc3\x28\n\0\n"}), EXIT_FAULT),
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
    out += [skip_spelled(*row) for row in SPELLED]
    out += [("a run with %s is read as data, a stated limit (#5717)" % label,
             skip_tree("docs/z.bin", b"%PDF\n" + spelling.encode("utf-8") + b"\n\0"), EXIT_OK)
            for label, spelling in PAST_SPELL_LIMITS]
    out += [
        skip_spelled("plain ASCII on an even byte", "pool_mode = transaction", "utf-16-be", head=b"%PDF\n\n"),
        skip_spelled("plain ASCII on byte 3 mod 4", "pool_mode = transaction", "utf-32-le", head=b"%PDF\n\n\n"),
        skip_spelled("plain ASCII on byte 2 mod 4", "Run PgBouncer in transaction mode.", "utf-32-be", head=b"%PDF\n\n"),
        skip_spelled("plain ASCII on byte 0 mod 4", "Run PgBouncer in transaction mode.", "utf-32-le", head=b"%PDF\n\n\n\n"),
        ("a UTF-8 look-alike cut by a NUL byte cannot be skipped (#5717)",
         skip_tree("docs/z.bin", b"%PDF\nRun PgBouncer in tr\xd0\0\xb0nsaction mode.\n"), EXIT_FAULT),
        ("a UTF-16 mention cut by a NUL code unit cannot be skipped (#5717)",
         skip_tree("docs/z.bin", b"%PDF\n" + "pool_mo\0de = transaction\n".encode("utf-16-le") + b"\0"), EXIT_FAULT),
        ("a UTF-16 mention wrapped over two lines cannot be skipped (#5717)",
         skip_tree("docs/z.bin", b"%PDF\n" + "use pool\nmode here\n".encode("utf-16-le") + b"\0"), EXIT_FAULT),
        ("three invalid UTF-8 bytes for a letter cannot be skipped (#5717)",
         skip_tree("docs/z.bin", b"%PDF\nRun it in tr\xff\xff\xffnsaction mode.\n\0"), EXIT_FAULT),
        ("a short word with a stray byte in a binary file may be skipped (#5717)",
         skip_tree("docs/z.bin", b"%PDF\nxx mo\x93de yy \x9bpoo\x9b\n\0"), EXIT_OK),
        ("three Cyrillic letters each cut by a NUL byte cannot be skipped (#5717)",
         skip_tree("docs/z.bin", b"%PDF\nRun it in tr\xd0\0\xb0ns\xd0\0\xb0cti\xd0\0\xben mode.\n"), EXIT_FAULT),
        ("a line of CJK between two halves of a mention does not join them (#5717)",
         skip_tree("docs/z.bin", b"%PDF\nRun it in transaction\n\xe4\xb8\x80\nmode.\n\0"), EXIT_OK),
        ("a binary file with Cyrillic and Greek words and no mention may be skipped (#5717)",
         skip_tree("docs/z.bin", b"%PDF\n" + "привет καλημέρα".encode("utf-16-le") + b"\n\0\xff"), EXIT_OK),
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


# #5719, #5720, #5721: exact lines of the raw reader with RAW_LINE_CAP 6 and RAW_OVERLAP 2, at chunk sizes that cut
# the input everywhere: (bytes, codec, offset, drop_nul, chunk sizes, lines it must give). A line is cut only while
# it is still open at the end of a chunk; a long line that ends inside its chunk is given whole.
ANY_CHUNK = (1, 2, 3, 5, 26, 64)
RAW_LINE_PINS: List[Tuple[bytes, str, int, bool, Tuple[int, ...], List[str]]] = [
    (b"abcdefghijklmnopqrstuvwxyz\ntail", "latin-1", 0, False, (1, 2, 3, 5, 26),
     ["abcdef", "efghij", "ijklmn", "mnopqr", "qrstuv", "uvwxyz", "tail"]),
    (b"abcdefghijklmnopqrstuvwxyz\ntail", "latin-1", 0, False, (27, 64), ["abcdefghijklmnopqrstuvwxyz", "tail"]),
    (b"ab\r\ncd\ref\x0bg\x1ch\x85i\nj\0k\r\n", "latin-1", 0, False, ANY_CHUNK,
     ["ab", "cd", "ef", "g", "h", "i", "j", "k"]),
    (b"ab\r\ncd\ref\x0bg\x1ch\x85i\nj\0k\r\n", "latin-1", 0, True, ANY_CHUNK, ["ab", "cd", "ef", "g", "h", "i", "jk"]),
    (b"t\xe0s\xc3\xa0\nio\xffn", "latin-1", 0, False, ANY_CHUNK, ["t\u00e0s\u00c3\u00a0", "io\u00ffn"]),
    (b"t\xe0s\xc3\xa0\nio\xffn", "utf-8", 0, False, ANY_CHUNK, ["t\ufffds\u00e0", "io\ufffdn"]),
    (b"\xc3\0\xa0b\xc3", "utf-8", 0, True, ANY_CHUNK, ["\u00e0b\ufffd"]),
    ("x\u0430\0b\U0001d42d".encode("utf-16-le"), "utf-16-le", 0, False, ANY_CHUNK, ["x\u0430", "b\U0001d42d"]),
    (b"\0" + "x\u0430\0b\U0001d42d".encode("utf-16-be"), "utf-16-be", 1, True, ANY_CHUNK, ["x\u0430b\U0001d42d"]),
    (b"\0\0\0" + "q\0r".encode("utf-32-le"), "utf-32-le", 3, False, ANY_CHUNK, ["q", "r"]),
]
# #5721: the exact place raw_mention reports, line numbers counted from 1.
RAW_MENTION_PINS: List[Tuple[bytes, str]] = [
    (b"\x89PNG\nintro\npool_mode = transaction\n", "latin-1+0 view, line 3"),
    (b"\x89PNG\nintro\nuse transac\0tion mode\n", "latin-1+0 view, NUL removed, line 3"),
    (b"\x89PNG\n\0" + "a\nb\nuse trаnsаction mоde".encode("utf-16-be"), "utf-16-be+0 view, line 3"),
]


def raw_line_failures() -> int:
    """#5719, #5720, #5721: _raw_lines gives the exact lines above at every chunk size (cut segments overlap, \\r\\n
    split across chunks is one break, NUL is a break or removed, every byte decodes with replacement), and
    raw_mention reports the exact view and line."""
    global CHUNK_BYTES, RAW_LINE_CAP, RAW_OVERLAP
    bad = 0
    saved = (CHUNK_BYTES, RAW_LINE_CAP, RAW_OVERLAP)
    with tempfile.TemporaryDirectory(dir=_scratch_base()) as tmp:
        sample = Path(tmp) / "r.bin"
        try:
            RAW_LINE_CAP, RAW_OVERLAP = 6, 2
            for body, codec, offset, drop_nul, sizes, want in RAW_LINE_PINS:
                sample.write_bytes(body)
                for size in sizes:
                    CHUNK_BYTES = size
                    got = list(_raw_lines(sample, codec, offset, drop_nul))
                    if got != want:
                        bad += 1
                        print("self-test FAIL raw lines of %r as %s+%d at CHUNK_BYTES=%d: %r" % (body, codec, offset, size, got))
            CHUNK_BYTES, RAW_LINE_CAP, RAW_OVERLAP = saved
            for body, want_at in RAW_MENTION_PINS:
                sample.write_bytes(body)
                got_at = raw_mention(sample)
                if got_at != want_at:
                    bad += 1
                    print("self-test FAIL raw_mention of %r: %r, want %r" % (body, got_at, want_at))
        finally:
            CHUNK_BYTES, RAW_LINE_CAP, RAW_OVERLAP = saved
    print("self-test %s raw reader lines and raw_mention places are exact" % ("ok  " if not bad else "FAIL"))
    return bad


# #5367: the reviewed set of binary suffixes the skip list may name, written out here on purpose: the pin must not
# be derived from BINARY_SUFFIXES itself, or narrowing the set would narrow the pin with it.
REVIEWED_BINARY_SUFFIXES = frozenset(
    ".pdf .jpg .jpeg .png .gif .ico .webp .bmp .tif .tiff .woff .woff2 .ttf .otf .eot .zip .gz .tgz .bz2 .xz .zst .7z "
    ".tar .jar .wasm .so .dylib .dll .exe .bin .db .sqlite .mp3 .mp4 .mov .webm .ogg .wav .class .o .a .rlib".split())


def binary_suffix_failures() -> int:
    """BINARY_SUFFIXES is exactly the reviewed set, every member is lower case with a dot, none is a text type."""
    bad = 0 if BINARY_SUFFIXES == REVIEWED_BINARY_SUFFIXES else 1
    bad += sum(1 for ext in BINARY_SUFFIXES if ext != ext.lower() or not ext.startswith(".") or ext in (".md", ".txt", ".tpl"))
    if bad:
        print("self-test FAIL BINARY_SUFFIXES differs from the reviewed set: %s" % sorted(BINARY_SUFFIXES ^ REVIEWED_BINARY_SUFFIXES))
    return bad


# #5555: each rule below was shown unpinned by a surviving mutant (round-8 review). forbidden_entry is judged directly,
# so a rule is pinned even where normalise() (one space, lower case) would hide the difference from an allowlist case.
FORBIDDEN_PINS = (
    ("N01 env with four arguments", "oc env dc/pgbouncer -c pgbouncer -n pool_mode=transaction", True),
    ("N02 a prefixed key before a command", "pgb_pool_mode=transaction ./run.sh", True),
    ("N03 a dotted key in a flow mapping", '{ "pgbouncer.pool_mode": transaction }', True),
    ("N03 a bare dotted key in a flow mapping", "{ pgbouncer.pool_mode: transaction }", True),
    ("N04 a writer after a semicolon", "true;echo pool_mode=transaction >> p.ini", True),
    ("N04 a writer after an ampersand", "true&echo pool_mode=transaction >> p.ini", True),
    ("N04 a writer after a pipe", "true|tee pool_mode=transaction", True),
    ("N05 the dash spelling with a writer", "echo pool-mode=transaction >> p.ini", True),
    ("N06 a quoted key in a flow mapping", 'environment: { "pool_mode": transaction }', True),
    ("N10 two spaces before the command", "pool_mode=transaction  ./entrypoint.sh", True),
    ("N10 a tab before the command", "pool_mode=transaction\t./entrypoint.sh", True),
    ("a quoted sentence stays allowed", "withdrawn: pool_mode=transaction / was required", False),
)
SKIP_PINS = (
    ("a magic reason with a magic number is excused", MAGIC_REASON + " (magic number 1f8b0800)", False),
    ("N09 a reason that only starts like the magic reason is not excused", "binary other", True),
    ("a NUL reason is not excused", "NUL bytes in a file that is not UTF-16/32 text", True),
    ("a raw mention is not excused", MAGIC_REASON + " (magic number 47494638); " + RAW_MENTION_MARK + " (line 2)", True),
)


def pin_failures() -> int:
    """Direct pins: forbidden_entry (N01-N06, N10), skip_problem (N09), a symlink under a skip path (#5552)."""
    bad = 0
    for label, text, want in FORBIDDEN_PINS:
        if forbidden_entry(normalise(text) if want is False else text) is not want:
            bad += 1
            print("self-test FAIL pin %s: forbidden_entry(%r) is not %s" % (label, text, want))
    for label, reason, want in SKIP_PINS:
        if (skip_problem(reason) is not None) is not want:
            bad += 1
            print("self-test FAIL pin %s: skip_problem(%r)" % (label, reason))
    with tempfile.TemporaryDirectory(dir=_scratch_base()) as tmp:
        root = Path(tmp)
        write_tree(root, tree({"infra/real.md": "Plain text.\n"}, unread=UNREAD_REASON + "infra/link.bin\n"))
        (root / "infra" / "link.bin").symlink_to("real.md")
        if run_quiet(root) != EXIT_FAULT:  # a symlink is never read, so a skip entry for it is stale
            bad += 1
            print("self-test FAIL pin a symlink under a skip path is accepted (#5552)")
    return bad


def run_cases(verbose: bool) -> int:
    scratch_base = _scratch_base()
    failures = stream_failures() + raw_line_failures() + binary_suffix_failures() + pin_failures()
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
    ("F4 a skip entry needs a binary magic number and no raw mention (#5478, #5552)", "if rel in unread and skip_problem(unread[rel])]", "if rel in unread and False]"),
    # #5552: the raw-byte rule (twelve mutants over its lines)
    ("F1 #5552 a raw mention refuses the skip", "    if RAW_MENTION_MARK in reason:", "    if False:"),
    ("F1 #5552 a missing magic number refuses the skip", "    if not reason.startswith(MAGIC_REASON):\n        return \"it has", "    if False:\n        return \"it has"),
    ("F1 #5552 the mention is recorded in the reason", '("" if where is None else "; %s (%s)" % (RAW_MENTION_MARK, where))', '""'),
    ("F1 #5552 the raw mention is looked for", "            where = raw_mention(path)", "            where = None"),
    ("F1 #5552 the NUL-as-break view", "    for drop_nul in (False, True):", "    for drop_nul in (True,):"),
    ("F1 #5552 the NUL-removed view", "    for drop_nul in (False, True):", "    for drop_nul in (False,):"),
    ("F1 #5552 a NUL ends a raw line", 'nul = "" if drop_nul else "\\n"', 'nul = "" if drop_nul else "\\0"'),
    ("F1 #5552 a NUL is removed in its view", 'nul = "" if drop_nul else "\\n"', 'nul = "\\0" if drop_nul else "\\n"'),
    ("F1 #5552 an overlong raw line overlaps its segments", "carry = carry[RAW_LINE_CAP - RAW_OVERLAP:]", "carry = carry[RAW_LINE_CAP:]"),
    ("F1 #5552 a raw line is carried across a chunk", "carry = lines.pop()  # #5717", "lines.pop()  # #5717"),
    ("F1 #5552 a mention wrapped over two raw lines", ' or (before and mentions(before + " " + text))', ""),
    ("F1 #5552 a raw line is normalised", "            text = normalise(raw)\n", "            text = raw\n"),
    # #5717: the raw views and the word-scoped hiding rule (35 mutants; SPELL_CAP 15 -> 16 is equivalent, see SPELL_CAP)
    ("F1 #5717 no utf-8 view", '(("latin-1", 0), ("utf-8", 0)) + tuple(', '(("latin-1", 0),) + tuple('),
    ("F1 #5717 no latin-1 view", '(("latin-1", 0), ("utf-8", 0)) + tuple(', '(("utf-8", 0),) + tuple('),
    ("F1 #5717 no utf-16-le view", '(("utf-16-le", 2), ("utf-16-be", 2), ', '(("utf-16-be", 2), '),
    ("F1 #5717 no utf-16-be view", '("utf-16-be", 2), ("utf-32-le", 4)', '("utf-32-le", 4)'),
    ("F1 #5717 no utf-32-le view", '("utf-32-le", 4), ("utf-32-be", 4))', '("utf-32-be", 4))'),
    ("F1 #5717 no utf-32-be view", ', ("utf-32-be", 4))\n', ')\n'),
    ("F1 #5717 one alignment only", '    for offset in range(width))', '    for offset in range(1))'),
    ("F1 #5717 last alignment dropped", '    for offset in range(width))', '    for offset in range(width - 1))'),
    ("F1 #5717 utf-8 NULs kept before decoding", '_BYTE_CODECS = frozenset(("latin-1", "utf-8"))', '_BYTE_CODECS = frozenset(("latin-1",))'),
    ("F1 #5717 wide NULs not handled", 'decoder.decode(data, final=not chunk).replace("\\0", nul)', 'decoder.decode(data, final=not chunk)'),
    ("F1 #5717 alignment ignored", '        handle.seek(offset)\n', '        handle.seek(0)\n'),
    ("F1 #5717 no hiding rule", ' or raw_hides(text)):', '):'),
    ("F1 #5717 no bidi clause", '    return (any(c in BIDI for c in text) and bool(_QUICK.search(view) or _QUICK.search(view[::-1]))) \\\n        or _lookalike_word', '    return _lookalike_word'),
    ("F1 #5717 bidi not read reversed", ' or _QUICK.search(view[::-1])))', '))'),
    ("F1 #5717 no look-alike word clause", '        or _lookalike_word(view) or _spelled_word(view)', '        or _spelled_word(view)'),
    ("F1 #5717 no spelled word clause", '        or _lookalike_word(view) or _spelled_word(view)', '        or _lookalike_word(view)'),
    ("F1 #5717 junk limit tighter", 'len(word) - known <= junk', 'len(word) - known < junk'),
    ("F1 #5717 junk limit looser", 'junk = max(0, (len(key) - 5) // 2)', 'junk = max(0, (len(key) - 3) // 2)'),
    ("F1 #5717 junk limit removed", ' and len(word) - known <= junk and', ' and'),
    ("F1 #5717 known limit tighter", 'known >= len(key) - 2 and', 'known >= len(key) - 1 and'),
    ("F1 #5717 known limit looser", 'known >= len(key) - 2 and', 'known >= len(key) - 3 and'),
    ("F1 #5717 length limit tighter", 'if len(word) <= len(key) + 2 and', 'if len(word) <= len(key) + 1 and'),
    ("F1 #5717 length limit looser", 'if len(word) <= len(key) + 2 and', 'if len(word) <= len(key) + 3 and'),
    ("F1 #5717 SPELL_CAP 14", 'SPELL_CAP = 15  #', 'SPELL_CAP = 14  #'),
    ("F1 #5717 ascii letters at least 4", 'sum(1 for c in word if _ascii_letter(c)) < 3:', 'sum(1 for c in word if _ascii_letter(c)) < 4:'),
    ("F1 #5717 ascii letters at least 2", 'sum(1 for c in word if _ascii_letter(c)) < 3:', 'sum(1 for c in word if _ascii_letter(c)) < 2:'),
    ("F1 #5717 look-alike letter read as junk", 'known = sum(1 for c in word if c.isascii() or _lookalike_letter(c))', 'known = sum(1 for c in word if c.isascii())'),
    ("F1 #5717 wildcard exact one", 're.escape(c) if c.isascii() else ".?" for c in word))\n        for key', 're.escape(c) if c.isascii() else "." for c in word))\n        for key'),
    ("F1 #5717 inert line keeps the pair", '                    before = ""  # it adds no letter', '                    pass  # it adds no letter'),
    ("F1 #5717 inert widened to Cyrillic", '\\ufffd\\U00020000', '\\ufffd\\u0400-\\u052f\\U00020000'),
    ("F1 #5717 inert takes ASCII letters", '"[\\\\s\\u3400', '"[\\\\sa-z\\u3400'),
    ("F1 #5717 inert widened to full-width forms", '\\ufffd\\U00020000', '\\ufffd\\uff00-\\uffef\\U00020000'),
    ("F1 #5717 ascii shortcut wrong way", '    if text.isascii():\n        return False  # no reordering', '    if not text.isascii():\n        return False  # no reordering'),
    ("F1 #5717 junk floor removed", 'junk = max(0, (len(key) - 5) // 2)', 'junk = (len(key) - 5) // 2'),
    ("F1 #5717 junk floor one", 'junk = max(0, (len(key) - 5) // 2)', 'junk = max(1, (len(key) - 5) // 2)'),
    ("F3a #5719 the raw overlap shorter than a word", "RAW_LINE_CAP, RAW_OVERLAP = 1 << 22, 4096", "RAW_LINE_CAP, RAW_OVERLAP = 1 << 22, 8"),
    ("F3a #5719 one raw cut per chunk", "            while len(carry) > RAW_LINE_CAP:", "            if len(carry) > RAW_LINE_CAP:"),
    ("F3a #5719 a raw segment one short", "yield carry[:RAW_LINE_CAP]", "yield carry[:RAW_LINE_CAP - 1]"),
    ("F3a #5719 the raw overlap one short", "carry = carry[RAW_LINE_CAP - RAW_OVERLAP:]", "carry = carry[RAW_LINE_CAP - RAW_OVERLAP + 1:]"),
    ("F3b #5720 raw decoding drops bad bytes", 'getincrementaldecoder(codec)("replace")', 'getincrementaldecoder(codec)("ignore")'),
    ("F3b #5720 raw decoding is strict", 'getincrementaldecoder(codec)("replace")', 'getincrementaldecoder(codec)("strict")'),
    ("F3b #5720 the latin-1 view read as ASCII", 'getincrementaldecoder(codec)("replace")',
     'getincrementaldecoder("ascii" if codec == "latin-1" else codec)("replace")'),
    ("F3b #5720 a cut sequence at the end of the file is not flushed", "decoder.decode(data, final=not chunk)",
     "decoder.decode(data, final=False)"),
    ("F3c #5721 a NUL read as a space", 'nul = "" if drop_nul else "\\n"', 'nul = "" if drop_nul else " "'),
    ("F3c #5721 raw line numbers from 0", "enumerate(_raw_lines(path, codec, offset, drop_nul), 1)",
     "enumerate(_raw_lines(path, codec, offset, drop_nul), 0)"),
    ("F3c #5721 raw lines split on LF only", '.replace("\\0", nul)\n            lines = text.splitlines(keepends=True)',
     '.replace("\\0", nul)\n            lines = [part for part in re.split("(?<=\\n)", text) if part]'),
    ("F3c #5721 a CR at a chunk end is not carried", ' or lines[-1].endswith("\\r")):\n                carry = lines.pop()  # #5717',
     '):\n                carry = lines.pop()  # #5717'),
    ("F3c #5721 a raw line keeps its CR", "                yield line.splitlines()[0]\n            while len(carry)",
     '                yield line.rstrip("\\n")\n            while len(carry)'),
    # #5554, #5555: rules shown unpinned by mutants N01-N12 (round-8 review)
    ("N01 #5554 set-env reach of four arguments", "[^\\s=\\\"']+){0,4}?", "[^\\s=\\\"']+){0,3}?"),
    ("N02 #5555 a prefixed key before a command", 're.compile(r"^[a-z0-9_]*pool[_-]?mode=', 're.compile(r"^pool[_-]?mode='),
    ("N04 #5555 a writer after ; & or |", "(?:^|[\\s;&|])(?:sed|awk", "(?:^|\\s)(?:sed|awk"),
    ("N05 #5555 the dash spelling with a writer", "\\b.*pool[_-]?mode\\s*[=:]", "\\b.*pool_mode\\s*[=:]"),
    ("N06 #5555 the closing quote of a flow mapping key", 'pool[_-]?mode[\\"\']?\\s*[:=]', 'pool[_-]?mode\\s*[:=]'),
    ("N07 #5555 five or more underscores of emphasis", "_EMPHASIS = re.compile(r\"(?<![^\\W_])(_+)", "_EMPHASIS = re.compile(r\"(?<![^\\W_])(_{1,4})"),
    ("N09 #5555 the magic reason is matched whole", "if not reason.startswith(MAGIC_REASON):", "if not reason.startswith(MAGIC_REASON[:6]):"),
    ("N10 #5555 any whitespace before the command", '[\\"\']?\\s+(?:\\.{1,2}/', '[\\"\']?\\s(?:\\.{1,2}/'),
    ("N11 #5555 set is a set-env verb", "(?:export|env|set|-e|", "(?:export|env|-e|"),
    ("N12 #5555 GIF8 is a binary magic number", 'b"SQLite format 3\\0", b"GIF8", b"wOFF"', 'b"SQLite format 3\\0", b"wOFF"'),
    ("F4 the skip reason names the magic number (#5478)", 'raise Unreadable("%s (magic number %s)" % (MAGIC_REASON, chunk[:4].hex()))', 'raise Unreadable("%s (magic number %s)" % ("", chunk[:4].hex()))'),
    ("F4 a NUL-only file is not binary content (#5478)", 'raise Unreadable("NUL bytes in a file that is not UTF-16/32 text")', 'raise Unreadable("%s NUL bytes in a file that is not UTF-16/32 text" % MAGIC_REASON)'),
    ("F6 #5480 M3 stroked Latin letters fold to their base letter", '(?: WITH [A-Z ]+)?$")', '$")'),
    ("F6 #5480 M7 the foreign word test reads the shadow view", "or _lookalike_word(shadow(text)))", "or _lookalike_word(text))"),
    ("F6 #5480 M9 the A1 command key may be quoted", 'pool[_-]?mode[\\"\']?(?:\\s*=\\s*|\\s+)', 'pool[_-]?mode(?:\\s*=\\s*|\\s+)'),
    ("F6 #5480 M10 the A1 json shape refuses statement", '[\\"\']\\s*:\\s*[\\"\'](?:transaction|statement)[\\"\']"),', '[\\"\']\\s*:\\s*[\\"\'](?:transaction)[\\"\']"),'),
    ("F6 #5480 M14 emphasis opens before a word character", "(_+)(?=[^\\W_])", "(_+)(?=.)"),
    ("F6 #5480 M15 emphasis closes after a word character", "(?<=[^\\W_])\\1", "\\1"),
    ("F6 #5480 the edge underscore view is read", "    return edge != text and _mentions_view(edge)", "    return False"),
    ("F6 #5480 a leading underscore is an edge", "(?<![^\\W_])_+(?=[^\\W_])|(?<=[^\\W_])_+(?![^\\W_])\")", "(?<=[^\\W_])_+(?![^\\W_])\")"),
    ("F6 #5480 a trailing underscore is an edge", "(?<![^\\W_])_+(?=[^\\W_])|(?<=[^\\W_])_+(?![^\\W_])\")", "(?<![^\\W_])_+(?=[^\\W_])\")"),
    ('F6 #5480 M8 the A1 command value may be quoted', '(?:\\s*=\\s*|\\s+)[\\"\']?(?:transaction|statement)\\b"),\n    re.compile(r"[\\"\'][a-z0-9_.]*pool', '(?:\\s*=\\s*|\\s+)(?:transaction|statement)\\b"),\n    re.compile(r"[\\"\'][a-z0-9_.]*pool'),
    ('F6 #5480 M11 the A1 command shape reads --env', '|-e|--env|--set|', '|-e|--set|'),
    ('F6 #5480 M12 the A1 command shape reads set', '(?:export|env|set|-e|', '(?:export|env|-e|'),
    ('F6 #5480 M13 the A1 command shape reads a space between key and value', '[\\"\']?(?:\\s*=\\s*|\\s+)[\\"\']?(?:transaction|statement)\\b"),\n    re.compile(r"[\\"\'][a-z0-9_.]*pool', '[\\"\']?(?:\\s*=\\s*)[\\"\']?(?:transaction|statement)\\b"),\n    re.compile(r"[\\"\'][a-z0-9_.]*pool'),
    ("F1 only a declared binary suffix is skipped (#5367)", "        if not problem and Path(line).suffix.lower() not in BINARY_SUFFIXES:", "        if False:"),
    ("F1 pdf is a declared binary suffix (#5367)", '".pdf", ".jpg", ".jpeg", ".png"', '".jpg", ".jpeg", ".png"'),
    ("F1 a text type is not declared binary (#5367)", '".mov", ".webm"', '".mov", ".tpl", ".webm"'),
    ("R9 fold: two foreign letters still fold (#5368)", "    if not other or other > 2 or len(word) - other < 3:", "    if not other or other > 1 or len(word) - other < 3:"),
    ("R9 fold: three foreign letters never fold (#5368)", "    if not other or other > 2 or len(word) - other < 3:", "    if not other or other > 3 or len(word) - other < 3:"),
    ("R9 fold: wildcard match (#5368)", "        if dropped == key or wild.fullmatch(key):", "        if dropped == key:"),
    ("R9 fold: inserted-letter drop match (#5368)", "        if dropped == key or wild.fullmatch(key):", "        if wild.fullmatch(key):"),
    ("R9 left neighbour of a symbol (#5370)", "        elif (i and _ascii_letter(view[i - 1])) or (i + 1 < len(view) and _ascii_letter(view[i + 1])):",
     "        elif (i + 1 < len(view) and _ascii_letter(view[i + 1])):"),
    ("R9 right neighbour of a symbol (#5370)", "        elif (i and _ascii_letter(view[i - 1])) or (i + 1 < len(view) and _ascii_letter(view[i + 1])):",
     "        elif (i and _ascii_letter(view[i - 1])):"),
    ("R9 first character has no left neighbour (#5370)", "        elif (i and _ascii_letter(view[i - 1]))", "        elif (_ascii_letter(view[i - 1]))"),
    ("R9 last character has no right neighbour (#5370)", "or (i + 1 < len(view) and _ascii_letter(view[i + 1])):", "or (_ascii_letter(view[i + 1])):"),
    ("R9 Coptic is a look-alike script (sweep)", ', "COPTIC"))', "))"),
    ("R9 Cherokee is a look-alike script (sweep)", '"ARMENIAN", "CHEROKEE", "COPTIC"', '"ARMENIAN", "COPTIC"'),
    ("R9 pool word read on the shadow view (sweep)", "or bool(_QUICK.search(shadow(text)))", "or bool(_QUICK.search(text))"),
    ("R1 asterisks stripped (sweep)", 're.sub(r"[`*]", "", text)', 're.sub(r"[`]", "", text)'),
    ("R9 private-mode terminal codes (sweep)", "[0-9;?]*[A-Za-z]", "[0-9;]*[A-Za-z]"),
    ("A1 forbidden statement alternative (sweep)", '[\\"\']?(?:transaction|statement)\\b"),\n    re.compile(r"[\\"\'][a-z0-9_.]*pool', '[\\"\']?(?:transaction)\\b"),\n    re.compile(r"[\\"\'][a-z0-9_.]*pool'),
    ("A1 forbidden key without separator (sweep)", '[a-z0-9_.]*pool[_-]?mode[\\"\']?(?:', '[a-z0-9_.]*pool_mode[\\"\']?(?:'),
    ("F1 skip entry has no spaces (sweep)", '        if " " in line or problem or line in listed:', '        if problem or line in listed:'),
    ("R1 emphasis span is lazy (sweep)", "(.+?)(?<=[^\\W_])\\1", "(.+)(?<=[^\\W_])\\1"),
    ("F1 the suffix is read case-blind (#5367)", "Path(line).suffix.lower() not in BINARY_SUFFIXES", "Path(line).suffix not in BINARY_SUFFIXES"),
    ("F1 NUL bytes in non-UTF-16 text", "            if utf8 and b\"\\0\" in chunk:", "            if False:"),
    ("F1 BOM-less UTF-16", "    if len(zeros) * 4 >= min(len(head), CHUNK_BYTES) > 0:", "    if False:"),
    ("F2 long lines: product and mode word anywhere", "    return bool(_PRODUCT_WORD.search(view) and OTHER_MODE.search(view))", "    return False"),
    ("F2 long lines: overlapping segments", "SEGMENT, SEGMENT_STEP = 2048, 1536", "SEGMENT, SEGMENT_STEP = 2048, 2048"),
    ("F2 window margin", "WINDOW_MARGIN = 2 * PARAGRAPH_MAX + 2 * NEIGHBOURS", "WINDOW_MARGIN = 1"),
    ("F2 chunk-boundary carriage return", ' or lines[-1].endswith("\\r")):\n                carry = lines.pop()  # an un',
     '):\n                carry = lines.pop()  # an un'),
    ("A1 forbidden entries", "        if forbidden_entry(text):\n", "        if False:\n"),
    ("A1 forbidden command assignment (#5366)", '(?:^|\\s)(?:export|env|set|-e|--env|--set|--set-string)', "(?:^|\\s)(?:zzexport)"),
    ("A1 forbidden command words (#5366)", "(?:export|env|set|-e|--env|--set|--set-string)", "(?:export|--set|--set-string)"),
    ("A1 forbidden quoted json key (#5366)", '[\\"\'][a-z0-9_.]*pool[_-]?mode[\\"\']\\s*:', '[\\"\'][a-z0-9_.]*pool[_-]?zzmode[\\"\']\\s*:'),
    ('A1 command word --set (#5477)', 're.compile(r"(?:^|\\s)(?:export|env|set|-e|--env|--set|--set-string)(?:\\s+[^\\s=\\"\']+){0,4}?(?:\\s+|=)[\\"\']?[a-z0-9_.]*pool[_-]?mode[\\"\']?(?:\\s*=\\s*|\\s+)[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|\\s)(?:export|env|set|-e|--env|--set-string)(?:\\s+[^\\s=\\"\']+){0,4}?(?:\\s+|=)[\\"\']?[a-z0-9_.]*pool[_-]?mode[\\"\']?(?:\\s*=\\s*|\\s+)[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 command word --set-string (#5477)', 're.compile(r"(?:^|\\s)(?:export|env|set|-e|--env|--set|--set-string)(?:\\s+[^\\s=\\"\']+){0,4}?(?:\\s+|=)[\\"\']?[a-z0-9_.]*pool[_-]?mode[\\"\']?(?:\\s*=\\s*|\\s+)[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|\\s)(?:export|env|set|-e|--env|--set)(?:\\s+[^\\s=\\"\']+){0,4}?(?:\\s+|=)[\\"\']?[a-z0-9_.]*pool[_-]?mode[\\"\']?(?:\\s*=\\s*|\\s+)[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 command arguments up to four (#5477)', 're.compile(r"(?:^|\\s)(?:export|env|set|-e|--env|--set|--set-string)(?:\\s+[^\\s=\\"\']+){0,4}?(?:\\s+|=)[\\"\']?[a-z0-9_.]*pool[_-]?mode[\\"\']?(?:\\s*=\\s*|\\s+)[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|\\s)(?:export|env|set|-e|--env|--set|--set-string)(?:\\s+[^\\s=\\"\']+){0,1}?(?:\\s+|=)[\\"\']?[a-z0-9_.]*pool[_-]?mode[\\"\']?(?:\\s*=\\s*|\\s+)[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 command word then = (#5477)', 're.compile(r"(?:^|\\s)(?:export|env|set|-e|--env|--set|--set-string)(?:\\s+[^\\s=\\"\']+){0,4}?(?:\\s+|=)[\\"\']?[a-z0-9_.]*pool[_-]?mode[\\"\']?(?:\\s*=\\s*|\\s+)[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|\\s)(?:export|env|set|-e|--env|--set|--set-string)(?:\\s+[^\\s=\\"\']+){0,4}?(?:\\s+)[\\"\']?[a-z0-9_.]*pool[_-]?mode[\\"\']?(?:\\s*=\\s*|\\s+)[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 space form after the key (#5477)', 're.compile(r"(?:^|\\s)(?:export|env|set|-e|--env|--set|--set-string)(?:\\s+[^\\s=\\"\']+){0,4}?(?:\\s+|=)[\\"\']?[a-z0-9_.]*pool[_-]?mode[\\"\']?(?:\\s*=\\s*|\\s+)[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|\\s)(?:export|env|set|-e|--env|--set|--set-string)(?:\\s+[^\\s=\\"\']+){0,4}?(?:\\s+|=)[\\"\']?[a-z0-9_.]*pool[_-]?mode[\\"\']?(?:\\s*=\\s*)[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 equals form after the key (#5477)', 're.compile(r"(?:^|\\s)(?:export|env|set|-e|--env|--set|--set-string)(?:\\s+[^\\s=\\"\']+){0,4}?(?:\\s+|=)[\\"\']?[a-z0-9_.]*pool[_-]?mode[\\"\']?(?:\\s*=\\s*|\\s+)[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|\\s)(?:export|env|set|-e|--env|--set|--set-string)(?:\\s+[^\\s=\\"\']+){0,4}?(?:\\s+|=)[\\"\']?[a-z0-9_.]*pool[_-]?mode[\\"\']?(?:\\s+)[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 env prefix statement (#5477)', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),'),
    ('A1 env prefix quoted value (#5477)', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),'),
    ('A1 env prefix on a parent path (#5477)', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\./|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),'),
    ('A1 env prefix on a relative path (#5477)', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),'),
    ('A1 env prefix on an absolute path (#5477)', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),'),
    ('A1 env prefix on a home path (#5477)', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),'),
    ('A1 env prefix on a variable (#5477)', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),'),
    ('A1 env prefix on exec (#5477)', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|sudo\\b|bash\\b|pgbouncer\\b)"),'),
    ('A1 env prefix on sudo (#5477)', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|bash\\b|pgbouncer\\b)"),'),
    ('A1 env prefix on bash (#5477)', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|pgbouncer\\b)"),'),
    ('A1 env prefix on pgbouncer (#5477)', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b|pgbouncer\\b)"),', 're.compile(r"^[a-z0-9_]*pool[_-]?mode=[\\"\']?(?:transaction|statement)[\\"\']?\\s+(?:\\.{1,2}/|/\\w|~/|\\$|exec\\b|sudo\\b|bash\\b)"),'),
    ('A1 command write statement (#5477)', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction)\\b"),'),
    ('A1 command write with sed (#5477)', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|[\\s;&|])(?:awk|perl|echo|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 command write with awk (#5477)', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|[\\s;&|])(?:sed|perl|echo|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 command write with perl (#5477)', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|echo|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 command write with echo (#5477)', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 command write with printf (#5477)', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 command write with tee (#5477)', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|printf|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 command write with crudini (#5477)', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|printf|tee|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 command write with yq (#5477)', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|printf|tee|crudini|yq)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"(?:^|[\\s;&|])(?:sed|awk|perl|echo|printf|tee|crudini)\\b.*pool[_-]?mode\\s*[=:]\\s*[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 flow mapping opens on a brace (#5477)', 're.compile(r"\\{[^{}]*?[\\"\']?pool[_-]?mode[\\"\']?\\s*[:=]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"\\[[^{}]*?[\\"\']?pool[_-]?mode[\\"\']?\\s*[:=]\\s*[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 flow mapping holds other keys before the key (#5477)', 're.compile(r"\\{[^{}]*?[\\"\']?pool[_-]?mode[\\"\']?\\s*[:=]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"\\{[\\"\']?pool[_-]?mode[\\"\']?\\s*[:=]\\s*[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 flow mapping with an equals sign (#5477)', 're.compile(r"\\{[^{}]*?[\\"\']?pool[_-]?mode[\\"\']?\\s*[:=]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"\\{[^{}]*?[\\"\']?pool[_-]?mode[\\"\']?\\s*[:]\\s*[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 flow mapping with a colon (#5477)', 're.compile(r"\\{[^{}]*?[\\"\']?pool[_-]?mode[\\"\']?\\s*[:=]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"\\{[^{}]*?[\\"\']?pool[_-]?mode[\\"\']?\\s*[=]\\s*[\\"\']?(?:transaction|statement)\\b"),'),
    ('A1 flow mapping statement (#5477)', 're.compile(r"\\{[^{}]*?[\\"\']?pool[_-]?mode[\\"\']?\\s*[:=]\\s*[\\"\']?(?:transaction|statement)\\b"),', 're.compile(r"\\{[^{}]*?[\\"\']?pool[_-]?mode[\\"\']?\\s*[:=]\\s*[\\"\']?(?:transaction)\\b"),'),
    ("A1 forbidden shapes read the shadow view (#5366)", "    views = (text, shadow(text))\n", "    views = (text,)\n"),
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
    # round 5 reviews (#5089): the sub-rules the round-5 range added, each with a pinning case above
    ("R7 context reads the paragraph", "for k in idx for j in set(_neighbours(lines, k)) | set(_paragraph(lines, k))}",
     "for k in idx for j in set(_neighbours(lines, k))}"),
    ("R7 context reads the neighbours", "for k in idx for j in set(_neighbours(lines, k)) | set(_paragraph(lines, k))}",
     "for k in idx for j in set(_paragraph(lines, k))}"),
    ("R7 context reads every line of a pair", "near = sorted({j for k in idx for", "near = sorted({j for k in idx[:1] for"),
    ("R7 context lines joined with a separator", 'hashlib.sha256("\\n".join(lines[j]', 'hashlib.sha256("".join(lines[j]'),
    ("R7 context keeps line order", '"\\n".join(lines[j] for j in near)', '"\\n".join(sorted(lines[j] for j in near))'),
    ("R7 ctx ends the entry", 'CTX = re.compile(r" \\| ctx:([0-9a-f]{12})$")', 'CTX = re.compile(r" \\| ctx:([0-9a-f]{12})")'),
    ("F1 BOM-less UTF-16 NUL share", "if len(zeros) * 4 >= min(len(head), CHUNK_BYTES) > 0:",
     "if len(zeros) * 2 >= min(len(head), CHUNK_BYTES) > 0:"),
    ("F1 UTF-16 BOM", 'if head[:2] in (b"\\xff\\xfe", b"\\xfe\\xff"):', "if False:"),
    ("F1 NUL bytes in every chunk", '            if utf8 and b"\\0" in chunk:',
     '            if utf8 and b"\\0" in chunk and handle.tell() <= CHUNK_BYTES:'),
    ("F1 skip list path listed once", 'if " " in line or problem or line in listed:', 'if " " in line or problem:'),
    ("A1 distinct-word floor", "MIN_DISTINCT_WORDS = 5", "MIN_DISTINCT_WORDS = 1"),
    ("U3 look-alike table", ".translate(CONFUSABLE)", ""),
    ("U3 shadow drops format characters (#5089)", 'if unicodedata.category(c) not in ("Cf", "Mn")', 'if unicodedata.category(c) not in ("Mn",)'),
    ("R5 context line shadow view (#5211)", "(not text.isascii() and OTHER_MODE.search(shadow(text)))", "False"),
    ('H skip list decode error is a fault', '    except (OSError, UnicodeDecodeError) as exc:  # R5: a decode error is a FAULT (rc 2), not a traceback\n        return {}, [', '    except OSError as exc:  # R5: a decode error is a FAULT (rc 2), not a traceback\n        return {}, ['),
    ('H allowlist decode error is a fault', '    except (OSError, UnicodeDecodeError) as exc:\n        return [], ["%s: unreadable', '    except OSError as exc:\n        return [], ["%s: unreadable'),
    ('H template decode error is a fault', '    except (OSError, UnicodeDecodeError) as exc:\n        return "cannot read %s', '    except OSError as exc:\n        return "cannot read %s'),
    ("R9 unreadable lines are units", "                raw.append((base + i + 1, text, (i,)))  # R9", "                pass  # R9"),
    ("R9 U+FFFD always counts", '    found = {"\\ufffd"} if "\\ufffd" in text else set()', "    found = set()"),
    ("R9 approved shapes hold DECLARED characters", "    if not all(c in DECLARED for c in text):\n        return False", "    if False:\n        return False"),
    ("R9 needs a pool word", "or bool(_QUICK.search(shadow(text))) or _lookalike", "or True or _lookalike"),
    ("R9 colour codes dropped", '    plain = _ANSI_CSI.sub("", text)', "    plain = text"),
    ("R9 a character touching a letter", "        elif (i and _ascii_letter(view[i - 1])) or (i + 1 < len(view) and _ascii_letter(view[i + 1])):", "        elif False:"),
    ("R1 #5365 emphasis opens at a word edge", "(?<![^\\W_])(_+)", "(_+)"),
    ("R1 #5365 emphasis closes at a word edge", "\\1(?![^\\W_])", "\\1"),
    ("R1 #5365 emphasis may use two underscores", "(_+)(?=", "(_)(?="),
    ("R1 #5476 emphasis may use three underscores", "(_+)(?=", "(_{1,2})(?="),
    ("R1 #5476 emphasis may use four underscores", "(_+)(?=", "(_{1,3})(?="),
    ("R1 #5476 emphasis may use one underscore", "(_+)(?=", "(_{2,})(?="),
    ("R1 #5365 emphasis is stripped", '    text = _EMPHASIS.sub(r"\\2", re.sub(r"[`*]", "", text))', '    text = re.sub(r"[`*]", "", text)'),
    ("R9 #5364 bidi controls are reported", "    found |= {c for c in plain if c in BIDI}", "    found |= set()"),
    ("R9 #5364 a bidi control makes a line unreadable on its own", 'or any(c in BIDI for c in hidden) or', "or"),
    ("R9 #5364 bidi set keeps the overrides", "list(range(0x202A, 0x202F))", "list(range(0x202A, 0x202A))"),
    ("R9 #5364 bidi set keeps the isolates", "list(range(0x2066, 0x206A))", "list(range(0x2066, 0x2066))"),
    ("R9 #5364 bidi set keeps the left-to-right mark", "[0x200E, 0x200F, 0x061C]", "[0x200F, 0x061C]"),
    ("R9 #5364 bidi set keeps the right-to-left mark", "[0x200E, 0x200F, 0x061C]", "[0x200E, 0x061C]"),
    ("R9 #5364 bidi set keeps the Arabic letter mark", "[0x200E, 0x200F, 0x061C]", "[0x200E, 0x200F]"),
    ("R9 #5364 bidi overrides start at U+202A", "list(range(0x202A, 0x202F))", "list(range(0x202B, 0x202F))"),
    ("R9 #5364 bidi overrides end at U+202E", "list(range(0x202A, 0x202F))", "list(range(0x202A, 0x202E))"),
    ("R9 #5364 bidi isolates start at U+2066", "list(range(0x2066, 0x206A))", "list(range(0x2067, 0x206A))"),
    ("R9 #5364 bidi isolates end at U+2069", "list(range(0x2066, 0x206A))", "list(range(0x2066, 0x2069))"),
    ("R9 #5363 any non-ASCII letter counts", '        if unicodedata.category(c).startswith("L"):', "        if False:"),
    ("R9 #5363 Latin letters fold by name", "    t = t.translate(_LATIN).casefold()", "    t = t.casefold()"),
    ("R9 #5363 a foreign word is unreadable without a pool word", "or _lookalike_word(shadow(text)))", ")"),
    ("R9 #5363 foreign word run length", "_LOOKALIKE_RUN = 4", "_LOOKALIKE_RUN = 3"),
    ("R9 #5363 foreign word run bound", "if len(word) >= _LOOKALIKE_RUN and all(", "if len(word) > _LOOKALIKE_RUN and all("),
    ("R9 #5363 lookalike scripts closed set", '"LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "COPTIC"', '"LATIN", "GREEK", "ARMENIAN", "CHEROKEE", "COPTIC"'),
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
