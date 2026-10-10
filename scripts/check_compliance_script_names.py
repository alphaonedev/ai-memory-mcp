#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Compliance-document script-name anchor gate (#6141).

The adopted certification texts under ``docs/compliance/`` are verbatim copies
of a reviewed source and cannot be edited in place, so a script rename leaves
the normative text naming a file that no longer exists (#6137 ported
``check-cert-expiry.sh`` to ``check_cert_expiry.py``; #6141).

Design B (round 11, 3-agent vote (6def5ab6)): the gate reads bytes, never a
Markdown rendering. It does not emulate a renderer, so no renderer construct can
hide a name from it.

Rule: every ``check-*.sh`` / ``check_*.py`` script name (``TOKEN_RE``, any ASCII
letter case, #6220) in a ``docs/compliance/**/*.md`` document must resolve to
the exact file it names, unless an allowlist entry and an erratum cover it.
Each LF-separated line is read in three views: as written; with HTML and numeric
character references decoded and invisible characters (category Cf and every
Default_Ignorable_Code_Point, #6195) removed; and folded (NFKC, dash variants,
combining marks, look-alike letters, emphasis markers). A name counts wherever
its bytes occur, in or out of comments, fences, links, tags or attribute values.
A line violates the gate when:

1. it names a script that does not exist, in any view, and no erratum-covered
   allowlist entry names it;
2. a decoded or folded view shows a script name more often than the line as
   written (a name hidden behind a character reference, an invisible character,
   a look-alike letter or emphasis), whether or not the script exists;
3. a script name has a non-ASCII letter or mark where it has a letter
   (``LOOSE_RE``, look-alike); a name glued to a run of dots or dashes is a name (#6632);
4. a fragment of a script name (``c`` .. ``check-x.s``, ``HEAD_RE``) is followed by
   markup (``MARKUP``: ``< > \\ ` [ ] ( ) & ! $ { }``, #6622), or continues on the next line into
   markup or into the rest of a name: a renderer can join such pieces into a name;
   when the pieces after such a fragment join into a script name once markup or line
   breaks are dropped (``join_walk``, which reads the rest of the paragraph and tracks each
   comment, tag or link from its opener to its close, #6753, #6757), or the markup cannot be
   resolved, the line violates the gate whatever the allowlist holds (#6621, #6631);
5. it holds a bidirectional control character, raw or as a character reference;
6. it holds a character whose line structure is ambiguous: a C0 control other
   than tab (CR, VT, FF and NUL included), DEL, a C1 control (NEL included),
   U+2028, U+2029, or a byte order mark after the first character.

A bare name means ``scripts/<name>``; a written path is checked at that path
(#6216): leading ``/``, ``.`` and ``..`` components and a URL's host part are
dropped only when ``scripts`` follows. Existence is decided from exact directory
listings (#6220), and a symlink counts only when it resolves inside ``scripts/``
(#6198).

Allowlist (``ALLOW_REL``), one entry per line: ``<doc>:<token>:<count>[:pinned]``.
``<token>`` is a stale script name or a name fragment, matched case-sensitively;
``<count>`` is the exact number of occurrences the document holds (per line, the largest
count over the three views). A count that differs in either direction, a duplicate,
malformed or stale entry, and more entries than ``ALLOW_CEILING`` fail. A fragment entry
suppresses only the fragment report, never a join. A script-name entry is honoured only
while the document carries its own valid erratum for the name (#6170); ``:pinned``
(script names only, closed set ``PINNABLE_DOCS``, #6173) is honoured while any document
carries one.

Erratum (``erratum_block``): an ATX heading ``#.. Erratum ...`` followed by one
paragraph, one of whose lines starts ``Erratum (#<issue>): `` and names the
stale name and an existing successor ``scripts/<name>`` in backticks. Only blank
lines, ATX headings and plain paragraph lines (``PLAIN_ASCII`` plus non-ASCII
letters, numbers, punctuation and symbols) may precede the heading, and the
paragraph holds only plain text and balanced code spans. Any other construct
before or inside it (a comment, ``<details>``, a fence, indented code, a block
quote, a link, a reference definition, a table, a tag, a character reference,
an escape, a list item) is a violation naming the construct and the line, so a
valid erratum is always shown to a reader. An erratum line anywhere else, a
second erratum heading, or a heading with no paragraph is a violation.

Scan set (#6169, #6197): every ``*.md`` file under ``docs/compliance/``, extension
matched in any case. Symlinked directories are refused, never followed; a document
symlink that leaves the repository, loops (#6217) or cannot be resolved is refused.

Usage:
    python3 -I scripts/check_compliance_script_names.py [--root DIR]
    python3 -I scripts/check_compliance_script_names.py --self-test

Exit codes: 0 green, 1 violation(s) found, 2 undecidable: an unreadable (I/O
error or invalid UTF-8) document, directory or allowlist, a missing
``docs/compliance/``, a self-test failure (``SELF-TEST FAIL: ...``, including
``fixture setup`` when ``.local-runs`` is unusable, #6199), a usage error, a
document line longer than ``LINE_CEILING`` (65536) characters (``line too long,
undecidable``, #6635), or an internal error (``FAIL internal error``). No exit prints a traceback.
"""

import argparse
import bisect
import contextlib
import errno
import functools
import html
import io
import os
import re
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

# A script name anywhere on a line, bounded by non-name characters (#6195), in any ASCII letter case
# (#6220). re.ASCII keeps IGNORECASE from folding the Kelvin sign or long s into ASCII letters. A
# name after a run of dots or dashes (``Then...check-x.sh``, ``--check-x.sh``) is a name (#6632).
TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(check[-_][A-Za-z0-9_-]+\.(?:sh|py))(?![A-Za-z0-9_])", re.IGNORECASE | re.ASCII
)
FULL_NAME_RE = re.compile(r"check[-_][A-Za-z0-9_-]+\.(?:sh|py)", re.IGNORECASE | re.ASCII)
# token_spans() finds TOKEN_RE's matches in linear time (#6635): a name's start, and the runs of
# name characters its body is one of.
TOKEN_START_RE = re.compile(r"(?<![A-Za-z0-9_])check[-_]", re.IGNORECASE | re.ASCII)
BODY_RUN_RE = re.compile(r"[A-Za-z0-9_-]+", re.ASCII)
# A name fragment: any non-empty prefix of a script name, bounded on the left like TOKEN_RE.
HEAD_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:check[-_][A-Za-z0-9_.-]*|check|chec|che|ch|c)", re.IGNORECASE | re.ASCII
)
# The characters a renderer can drop or reinterpret between the pieces of a name.
MARKUP = frozenset("<>\\`[]()&!${}")
# The name characters that may continue a fragment at the start of the next line.
NAME_RUN_RE = re.compile(r"[A-Za-z0-9_.-]*", re.ASCII)
PATH_CHARS = frozenset(string.ascii_letters + string.digits + "_./-")
# A run of PATH_CHARS: tokens() finds each run once, so the scan is linear in the line (#6635).
PATH_RUN_RE = re.compile(r"[A-Za-z0-9_./-]+")
NAME_BODY = frozenset(string.ascii_letters + string.digits + "_-")
NAME_WORD = frozenset(string.ascii_letters + string.digits + "_")
# No file in a checkout has a longer root-relative path (Linux PATH_MAX); a longer target is
# missing without a walk, so a long path line stays linear (#6635).
PATH_LIMIT = 4096
# The longest line the gate decides; a longer one is undecidable (exit 2, #6635).
LINE_CEILING = 65536
# The join walk (#6621, #6631): how many characters after a fragment it reads (the rest of the
# line and of its paragraph, #6753, #6757), and how many walk states one line may spend before the
# line is undecidable (red). Markup whose close may lie past JOIN_WINDOW is undecidable (red).
JOIN_WINDOW = 512
JOIN_BUDGET = 4096
NAME_CHARS = frozenset(string.ascii_letters + string.digits + "_.-")
WORD_CHARS = frozenset(string.ascii_letters + string.digits + "_")
# Every prefix of a script name, any ASCII letter case.
NAME_PREFIX_RE = re.compile(
    r"c(?:h(?:e(?:c(?:k(?:[-_][A-Za-z0-9_-]*(?:\.(?:s(?:h)?|p(?:y)?)?)?)?)?)?)?)?", re.IGNORECASE | re.ASCII
)
CHAR_REF_RE = re.compile(r"&(?:#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{0,31});")
# Markup the walk drops on its own: escapes, code-span backticks, emphasis, image and math syntax,
# and closers. ``<``, ``[``, ``(``, ``&`` and the line break have their own steps.
JOIN_DROP = frozenset("\\`*~!${}])>")
SUCCESSOR_RE = re.compile(r"`scripts/([A-Za-z0-9_./-]+\.(?:sh|py))`")
ALLOW_REL = "scripts/qc-allowlists/compliance-script-names-allow.txt"
# The allowlist only shrinks: more entries than this fail the gate.
ALLOW_CEILING = 10
# Dash look-alikes outside category Pd (#6633): box-drawing and horizontal-line marks, the
# macron (which NFKC decomposes to a space and a combining mark, so it is mapped first) and
# the Ogham space mark, which renders as a dash.
DASHES = frozenset("\u02d7\u2043\u2212\u2796\ufe63\uff0d\u2500\u2501\u23af\u23ba\u2e0f\u00af\u1680")
LOOKALIKES = str.maketrans(
    {
        "\u0430": "a", "\u0410": "A", "\u0412": "B", "\u0441": "c", "\u0421": "C", "\u0501": "d",
        "\u0435": "e", "\u0415": "E", "\u04bb": "h", "\u041d": "H", "\u0456": "i", "\u0406": "I",
        "\u0458": "j", "\u0408": "J", "\u043a": "k", "\u041a": "K", "\u04cf": "l", "\u041c": "M",
        "\u043e": "o", "\u041e": "O", "\u0440": "p", "\u0420": "P", "\u051b": "q", "\u051a": "Q",
        "\u0455": "s", "\u0405": "S", "\u0422": "T", "\u051d": "w", "\u051c": "W", "\u0445": "x",
        "\u0425": "X", "\u0443": "y", "\u0423": "Y",
        "\u03b1": "a", "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H", "\u03b9": "i",
        "\u0399": "I", "\u03ba": "k", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u03bd": "v",
        "\u03bf": "o", "\u039f": "O", "\u03c1": "p", "\u03a1": "P", "\u03a4": "T", "\u03c5": "u",
        "\u03a5": "Y", "\u03c7": "x", "\u03a7": "X", "\u0396": "Z",
        "\u0131": "i", "\u0237": "j", "\u0251": "a", "\u0261": "g", "\u0585": "o", "\u057d": "u",
    }
)
# An underscore run at the edge of a word is an emphasis marker, never part of a name.
EDGE_UNDERSCORE_RE = re.compile(r"(?<![A-Za-z0-9])_+|_+(?![A-Za-z0-9])")
ERRATUM_RE = re.compile(r"Erratum \(#[1-9][0-9]*\): ")
ERRATUM_HEAD_RE = re.compile(r"#{1,6} Erratum(?![A-Za-z0-9])")
ATX_RE = re.compile(r"#{1,6}(?: |$)")
LIST_RE = re.compile(r"(?:[0-9]{1,9}[.)]|[-+*])(?: |$)")
# Plain paragraph text: ASCII letters, digits, space and this punctuation, plus non-ASCII letters,
# numbers, punctuation and symbols (no space separator, control, format or unassigned character).
PLAIN_ASCII = frozenset(string.ascii_letters + string.digits + " .,:;'\"!?/#%+=*_@-()")
# Not plain, with the construct each one opens, in the order the message names them.
NOT_PLAIN = (
    ("<!--", "an HTML comment"),
    ("<", "raw HTML or an autolink"),
    (">", "raw HTML or a block quote"),
    ("[", "a link or image bracket"),
    ("]", "a link or image bracket"),
    ("|", "a table pipe"),
    ("&", "a character reference"),
    ("\\", "a backslash escape"),
    ("`", "a code span"),
    ("~", "a strikethrough or tilde fence"),
    ("$", "a math delimiter"),
    ("\t", "a tab"),
)
ENTRY_RE = re.compile(
    r"^(docs/compliance/[A-Za-z0-9_./-]+\.(?i:md)):"
    r"((?i:check)[-_][A-Za-z0-9_-]+\.(?i:sh|py)|(?i:c(?:h(?:e(?:c(?:k(?:[-_][A-Za-z0-9_.-]*)?)?)?)?)?))"
    r":([1-9][0-9]{0,5})(:pinned)?$",
    re.ASCII,
)
# The two documents that cannot carry an erratum, each already guarded by another
# gate: the SHA-256 declaration pin and the cert section 7 gate (#6173).
PINNABLE_DOCS = frozenset(
    {
        "docs/compliance/v1.0.0-DECLARATION.md",
        "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md",
    }
)
# Default_Ignorable_Code_Point (Unicode DerivedCoreProperties.txt) as inclusive ranges; the
# standard library has no lookup for this property (#6195).
DEFAULT_IGNORABLE = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
# Bidirectional controls (#6195): embeddings, overrides, isolates and implicit marks. Each is
# invisible, yet it reorders what a reader sees.
BIDI_CONTROLS = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
# Characters that end a line for some readers and not others, or are not text (design B, item 5).
ODD_EXTRA = frozenset("\u2028\u2029\ufeff")


class LineTooLong(Exception):
    """A compliance document line is longer than LINE_CEILING characters (#6635)."""

    def __init__(self, rel, lineno, length):
        super().__init__("%s:%d" % (rel, lineno))
        self.rel, self.lineno, self.length = rel, lineno, length


class Unreadable(Exception):
    """A compliance document or the allowlist could not be read as UTF-8."""

    def __init__(self, path):
        super().__init__(str(path))
        self.path = path


def read_text(root, path):
    """Read ``path`` as strict UTF-8, mapping I/O and decode errors to Unreadable."""
    try:
        return path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        raise Unreadable(path.relative_to(root))


@functools.lru_cache(maxsize=None)
def invisible(c):
    """True for a character a reader does not see: category Cf or Default_Ignorable_Code_Point.

    Cached per character (#6756): the answer depends on the character alone, and a line repeats few.
    """
    if unicodedata.category(c) == "Cf":
        return True
    cp = ord(c)
    return any(lo <= cp <= hi for lo, hi in DEFAULT_IGNORABLE)


def visible(text):
    """``text`` without invisible characters (category Cf and Default_Ignorable_Code_Point)."""
    return "".join(c for c in text if not invisible(c))


def odd(c):
    """True for a character whose line structure is ambiguous (design B, item 5)."""
    cp = ord(c)
    return (cp < 0x20 and c != "\t") or 0x7F <= cp <= 0x9F or c in ODD_EXTRA


def decoded(line):
    """``line`` with character references decoded and invisible characters removed."""
    return visible(html.unescape(line))


def folded(line):
    """``decoded(line)`` folded: NFKC, dashes to ``-``, marks and look-alikes dropped, emphasis removed."""
    s = "".join("-" if c in DASHES else c for c in decoded(line))
    s = unicodedata.normalize("NFKC", s)
    s = "".join("-" if c in DASHES or unicodedata.category(c) == "Pd" else c for c in s)
    s = "".join(
        c for c in unicodedata.normalize("NFD", s) if not invisible(c) and unicodedata.category(c) not in ("Mn", "Me")
    )
    s = s.translate(LOOKALIKES).replace("*", "").replace("~", "")
    return EDGE_UNDERSCORE_RE.sub("", s)


def views(line):
    """The three views of a line: as written, decoded, folded."""
    return (line, decoded(line), folded(line))


def _loose(word):
    return "".join("(?:%s|[^\\W\\d_A-Za-z])" % c for c in word)


# A script name in any letters (#6214): each letter of ``check``, ``sh`` and ``py`` is that ASCII
# letter or any non-ASCII letter, and a separator may be any non-ASCII, non-space character or
# the Ogham space mark, which renders as a dash (#6633). The middle of a name may hold the same
# characters (#6633), at most 256 of them (#6635).
NON_ASCII = r"(?:[^\x00-\x7f\s]|\u1680)"
# One middle character: an ASCII letter, digit, ``_`` or ``-``, or a NON_ASCII character. The
# alternatives are disjoint, so a run of non-ASCII letters cannot backtrack exponentially (#6635).
NAME_MIDDLE = r"(?:[^\s\x00-\x2c\x2e\x2f\x3a-\x40\x5b-\x5e\x60\x7b-\x7f]|\u1680)"
LOOSE_RE = re.compile(
    r"(?<![A-Za-z0-9_])" + _loose("check") + r"(?:[-_]|" + NON_ASCII + r")" + NAME_MIDDLE
    + r"{1,256}(?:\.|" + NON_ASCII + r")(?:" + _loose("sh") + "|" + _loose("py") + r")(?![A-Za-z0-9_])",
    re.IGNORECASE,
)


def lookalikes(line):
    """Yield each script name in the decoded ``line`` with a non-ASCII letter or mark (#6214)."""
    for m in LOOSE_RE.finditer(decoded(line)):
        if not m.group().isascii():
            yield m.group()


def token_spans(line):
    """Yield (start, name) for each TOKEN_RE match on ``line``, in order, in linear time (#6635).

    ``TOKEN_RE.finditer`` retries its unbounded body from every ``check-`` in a long run of name
    characters. The body cannot hold a dot, so a match is unique: the body is the whole run of name
    characters after ``check-``, and a dot, ``sh`` or ``py`` and a non-word character follow it.
    """
    runs = [(r.start(), r.end()) for r in BODY_RUN_RE.finditer(line)]
    starts = [r[0] for r in runs]
    resume = 0
    for m in TOKEN_START_RE.finditer(line):
        begin = m.start()
        body = m.end()
        if begin < resume or body >= len(line) or line[body] not in NAME_BODY:
            continue
        run_start, run_end = runs[bisect.bisect_right(starts, body) - 1]
        ext = line[run_end + 1 : run_end + 3]
        after = line[run_end + 3 : run_end + 4]
        if line[run_end : run_end + 1] == "." and ext.lower() in ("sh", "py") and ext.isascii() and not (
            after and after in NAME_WORD
        ):
            resume = run_end + 3
            yield begin, line[begin:resume]


def tokens(line):
    """Yield (cited, name, target) for each script name on ``line`` (#6195, #6198, #6216).

    ``cited`` is the name with the path written before it, ``name`` the bare script name (the
    allowlist and erratum key) and ``target`` the root-relative path the citation names. A bare
    name is ``scripts/<name>``. A written path is taken as written, except that its leading
    ``''``/``.``/``..`` components, or a URL's host and path (a prefix starting ``//``), are
    dropped when a ``scripts`` component follows them. A name glued to a run of dots or dashes
    (#6632) is the last component's tail: with a ``/`` before it the whole written component is
    checked, without one the name is bare. A citation whose path would pass
    ``PATH_LIMIT`` bytes names no file: its ``target`` is None and ``cited`` is shortened, so no
    prefix is copied per name and the scan stays linear in the line (#6756).
    """
    runs = [(r.start(), r.end()) for r in PATH_RUN_RE.finditer(line)]
    starts = [r[0] for r in runs]
    shapes = {}
    for token_start, name in token_spans(line):
        # The token lies in a run of path characters; its prefix is that run up to the token. Each
        # run's components are split once, so the scan is linear in the line (#6635).
        run_start, run_end = runs[bisect.bisect_right(starts, token_start) - 1]
        if run_start not in shapes:
            comps = line[run_start:run_end].split("/")
            offsets, at = [], run_start
            for comp in comps:
                offsets.append(at)
                at += len(comp) + 1
            first = comps.index("scripts") if "scripts" in comps else None
            dots = first is not None and all(c in ("", ".", "..") for c in comps[:first])
            shapes[run_start] = (offsets, first, dots)
        offsets, first, dots = shapes[run_start]
        cut = line.rfind("/", run_start, token_start) + 1
        if not cut:
            yield name, name, "scripts/" + name
            continue
        end = token_start + len(name)
        # The components before ``cut`` are those whose offset is below it.
        held = bisect.bisect_left(offsets, cut)
        rooted = first is not None and first < held and (line.startswith("//", run_start, cut) or dots)
        begin = offsets[first] if rooted else run_start
        if end - begin > PATH_LIMIT:
            # No file has this path (#6635); copying it per name made the scan quadratic (#6756).
            yield "%s...%s" % (line[run_start : run_start + 32], line[end - 64 : end]), name, None
        else:
            yield line[run_start:end], name, line[begin:end]


def fragments(line, nxt, follow, budget):
    """Yield (fragment, why, join) for each name fragment on ``line`` that markup or a line break can join.

    ``nxt`` is the following line or None. A whole script name (trailing dots aside) is a name,
    not a fragment. A fragment followed by a ``MARKUP`` character is reported; one that ends the
    line is reported when the next line, leading spaces and tabs removed, starts with markup or
    with characters that complete it into a script name. ``join`` is ``join_walk``'s verdict on
    what follows the fragment: the rest of the line, then ``follow()`` (``paragraph_rest``: the
    rest of the paragraph, #6753, #6757), at most ``JOIN_WINDOW`` characters in all (``budget``
    is the line's walk budget). A fragment glued to a run of
    dots or dashes (``-c``, ``--check``: command-line flags, #6632) is reported only when it joins
    or is unresolved; ``why`` is then None and it counts toward no allowlist entry.
    """
    for m in HEAD_RE.finditer(line):
        frag = m.group()
        if FULL_NAME_RE.fullmatch(frag.rstrip(".")):
            continue
        end = m.end()
        if end < len(line):
            if line[end] not in MARKUP:
                continue
            why = "is followed by %r" % line[end]
        elif nxt is None:
            continue
        else:
            rest = nxt.lstrip(" \t")
            run = NAME_RUN_RE.match(rest).group()
            if rest[:1] in MARKUP:
                why = "ends the line and the next line starts with %r" % rest[0]
            elif run and TOKEN_RE.match(frag + run):
                why = "ends the line and the next line completes it to %s" % (frag + run)
            else:
                continue
        text = line[end : end + JOIN_WINDOW]
        more = end + JOIN_WINDOW < len(line)
        if nxt is not None and not more:
            rest = follow()
            room = JOIN_WINDOW - len(text)
            text += rest[:room]
            more = room < len(rest)
        join = join_walk(frag, text, more, budget)
        if m.start() and line[m.start() - 1] in ".-":
            if join[0]:
                yield frag, None, join
            continue
        yield frag, why, join


def paragraph_rest(doc, start, stop, k):
    """View ``k`` of lines ``start`` .. ``stop - 1`` (the rest of a paragraph), each after a ``\\n``.

    ``doc`` holds each line's ``views``; ``stop`` is the paragraph's next blank line (or the line
    count). With no line left the result is ``"\\n"``. It is cut after ``JOIN_WINDOW + 1``
    characters, enough for ``fragments`` to tell whether the paragraph runs past the window.
    """
    out, size = [], 0
    for j in range(start, stop):
        if size > JOIN_WINDOW:
            break
        piece = "\n" + doc[j][k][:JOIN_WINDOW]
        out.append(piece)
        size += len(piece)
    return "".join(out)[: JOIN_WINDOW + 1] if out else "\n"


def html_end(text, pos):
    """Index just past the HTML construct the ``<`` at ``pos`` opens; None when it does not close in ``text``.

    A comment (``<!--``) ends at its first ``-->`` (``<!-->`` and ``<!--->`` at once), a CDATA
    section at ``]]>``, a processing instruction at ``?>``, and a tag or declaration (``<`` then a
    letter, ``/`` or ``!``) at the first ``>`` outside a quoted run, where any ``"`` or ``'`` opens a
    run closed by the same quote. Each end is never before the end the renderer or a browser finds
    (#6753, #6757), so a construct this finds closed inside ``text`` closes inside it. A ``<`` that
    opens no construct ends at ``pos + 1``.
    """
    if text.startswith("<!-->", pos):
        return pos + 5
    if text.startswith("<!--->", pos):
        return pos + 6
    for opener, closer in (("<!--", "-->"), ("<![CDATA[", "]]>"), ("<?", "?>")):
        if text.startswith(opener, pos):
            i = text.find(closer, pos + len(opener))
            return None if i < 0 else i + len(closer)
    after = text[pos + 1 : pos + 2]
    if not after or not (after in "/!" or after.isascii() and after.isalpha()):
        return pos + 1
    quote = None
    for i in range(pos + 1, len(text)):
        c = text[i]
        if quote:
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == ">":
            return i + 1
    return None


def join_walk(frag, text, truncated, budget):
    """Return ('join', name), ('unresolved', None) or (None, None) for the markup after ``frag``.

    ``text`` is what follows the fragment: the rest of its line and of its paragraph, each later
    line after a ``\\n`` (at most ``JOIN_WINDOW`` characters); ``truncated`` tells whether the
    paragraph runs past it, and ``budget`` is the line's remaining walk states (a one-item list).
    The walk over-approximates a renderer: it drops single markup characters (``JOIN_DROP``), may
    skip from ``<`` past ANY later ``>`` (a tag, a comment, or a hidden element's content), from
    ``[`` past any later ``]`` and from ``(`` past any later ``)`` (a label or a link destination),
    decodes a character reference, and joins across line breaks. Each construct is tracked from
    its opener to its close across the whole window (#6753, #6757): a path that spells a script
    name is a join; a ``<`` whose construct does not close in ``text`` (``html_end``), a ``[`` or
    ``(`` in a truncated window (its close may lie past it), a walk that reaches the end of a
    truncated window, or an exhausted budget is unresolved. Either is red whatever the allowlist
    holds.
    """
    unresolved = False
    closers = {}

    def after(ch, pos):
        """Indices of ``ch`` in ``text`` after ``pos``; each list is built once, on first use."""
        found = closers.get(ch)
        if found is None:
            found, i = [], text.find(ch)
            while i >= 0:
                found.append(i)
                i = text.find(ch, i + 1)
            closers[ch] = found
        return found[bisect.bisect_right(found, pos) :]

    ends_at = {}
    stack, seen = [(0, "")], set()
    while stack:
        pos, acc = stack.pop()
        if (pos, acc) in seen:
            continue
        seen.add((pos, acc))
        if budget[0] <= 0:
            return "unresolved", None
        budget[0] -= 1
        if pos >= len(text):
            unresolved = unresolved or truncated
            continue
        c = text[pos]
        if c == "&":
            m = CHAR_REF_RE.match(text, pos)
            if not m:
                continue
            shown = visible(html.unescape(m.group()))
            if not shown:
                stack.append((m.end(), acc))
                continue
            c, nxt = shown, m.end()
        else:
            nxt = pos + 1
        if c in NAME_CHARS:
            grown = acc + c
            if not NAME_PREFIX_RE.fullmatch(frag + grown):
                continue
            if FULL_NAME_RE.fullmatch(frag + grown) and text[nxt : nxt + 1] not in WORD_CHARS:
                return "join", frag + grown
            stack.append((nxt, grown))
        elif c == "\n":
            while nxt < len(text) and text[nxt] in " \t":
                nxt += 1
            stack.append((nxt, acc))
        elif c == "<":
            if pos not in ends_at:
                ends_at[pos] = html_end(text, pos)
            ends = after(">", pos)
            if not ends or ends_at[pos] is None:
                unresolved = True
            stack.extend((i + 1, acc) for i in ends)
        elif c in "[(":
            if truncated:
                unresolved = True
            stack.append((nxt, acc))
            stack.extend((i + 1, acc) for i in after("]" if c == "[" else ")", pos))
        elif c in JOIN_DROP:
            stack.append((nxt, acc))
    return ("unresolved", None) if unresolved else (None, None)


def path_ok(root, target):
    """True when the root-relative ``target`` is exactly a file contained where it claims (#6216).

    No ``.``/``..``/empty component, every component present under that exact name in its parent's
    directory listing (#6220: a case-insensitive filesystem cannot turn ``CHECK-x.sh`` or
    ``scripts/SUB/`` into an existing file), a regular file at that exact path (no basename
    search), and a symlink only when it resolves inside scripts/ for a ``scripts/...`` target,
    else inside the repository. A target longer than ``PATH_LIMIT`` bytes is no file (#6635).
    """
    if target is None or len(target.encode("utf-8")) > PATH_LIMIT:
        return False
    parts = target.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    base = root / "scripts" if parts[0] == "scripts" else root
    try:
        path = root
        for part in parts:
            if part not in os.listdir(str(path)):
                return False
            path = path / part
        if not path.is_file():
            return False
        path.resolve().relative_to(base.resolve())
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def successor_ok(root, succ):
    """True when ``scripts/<succ>`` is exactly a file that resolves inside scripts/ (#6198)."""
    return path_ok(root, "scripts/" + succ)


def rel_path(root, path):
    """``path`` relative to ``root`` for messages; the raw path when it is not under ``root``."""
    try:
        return Path(path).relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _walk_docs(root, real_root, top, unlistable, docs, problems):
    """Append the Markdown documents under ``top`` to ``docs`` and each refusal to ``problems``."""
    for dirpath, dirnames, filenames in os.walk(str(top), onerror=unlistable):
        for name in dirnames:
            if os.path.islink(os.path.join(dirpath, name)):
                problems.append(
                    "%s: symlinked directory refused (not scanned)" % rel_path(root, Path(dirpath) / name)
                )
        for name in filenames:
            path = Path(dirpath) / name
            if not markdown_like(name.casefold()):
                if markdown_like(name_key(name)):
                    problems.append(
                        "%s: name only looks like a Markdown document (invisible character, trailing space "
                        "or look-alike form; refused)" % rel_path(root, path)
                    )
                continue
            if path.is_symlink():
                try:
                    os.stat(str(path))
                except OSError as err:
                    if err.errno == errno.ELOOP:
                        problems.append("%s: document symlink loop (refused)" % rel_path(root, path))
                        continue
                try:
                    path.resolve().relative_to(real_root)
                except ValueError:
                    problems.append(
                        "%s: document symlink resolves outside the repository (refused)" % rel_path(root, path)
                    )
                    continue
                except (OSError, RuntimeError):
                    problems.append(
                        "%s: document symlink cannot be resolved (symlink loop or I/O error; refused)"
                        % rel_path(root, path)
                    )
                    continue
            docs.append(path)


# GitHub renders each of these as Markdown (#6634).
MARKDOWN_EXTS = (
    ".md", ".markdown", ".mdown", ".mkdn", ".mkd", ".mdwn", ".mdx", ".mkdown", ".livemd", ".ronn", ".scd", ".workbook",
)


def name_key(name):
    """``name`` as a reader sees it: invisible characters removed, NFKC, casefolded, trailing space dropped."""
    return unicodedata.normalize("NFKC", visible(name)).casefold().rstrip()


def markdown_like(key):
    """True when ``key`` ends with a Markdown extension or holds one followed by a dot (``A.md.txt``)."""
    return key.endswith(MARKDOWN_EXTS) or any(ext + "." in key for ext in MARKDOWN_EXTS)


def compliance_docs(root):
    """Return (docs, problems) for the scan set: the Markdown documents under docs/compliance/.

    Scanned (#6634): every directory under docs/ whose name, with invisible characters removed and
    NFKC and casefold applied, is ``compliance`` (docs/compliance/ itself must exist); in them,
    every file whose name in any letter case ends with a GitHub Markdown extension
    (``MARKDOWN_EXTS``) or holds one followed by a dot. A name that is Markdown only once invisible
    characters, a trailing space or an NFKC-only form (a look-alike dot, fullwidth letters) is
    normalised away is refused, never skipped.

    The walk never skips silently (#6169, #6197). A directory that cannot be listed, or a missing
    docs/compliance/, raises Unreadable (exit 2). Symlinked directories, docs/compliance/ itself
    included, are refused and never followed: following one would scan documents outside the
    reviewed tree and admit cycles, and a git checkout of this tree contains none. A symlinked
    document is read only when it resolves inside the repository; one that leaves it is refused.
    """
    top = root / "docs" / "compliance"
    if os.path.islink(str(top)):
        return [], ["%s: symlinked directory refused (not scanned)" % rel_path(root, top)]
    if not os.path.isdir(str(top)):
        raise Unreadable(rel_path(root, top))
    try:
        siblings = sorted(os.listdir(str(root / "docs")))
    except OSError:
        raise Unreadable(rel_path(root, root / "docs")) from None

    def unlistable(err):
        raise Unreadable(rel_path(root, err.filename if err.filename else top))

    docs, problems = [], []
    tops = [top]
    for name in siblings:
        path = root / "docs" / name
        if name == "compliance" or name_key(name) != "compliance":
            continue
        if os.path.islink(str(path)):
            problems.append("%s: symlinked directory refused (not scanned)" % rel_path(root, path))
        elif os.path.isdir(str(path)):
            tops.append(path)
    real_root = root.resolve()
    for walk_top in tops:
        _walk_docs(root, real_root, walk_top, unlistable, docs, problems)
    return sorted(docs), problems



def plain_char(c):
    """True for a character of plain paragraph text (``PLAIN_ASCII``; non-ASCII L, N, P, S)."""
    if c.isascii():
        return c in PLAIN_ASCII
    return unicodedata.category(c)[0] in "LNPS"


def construct(line, in_block):
    """Name the first construct on a non-empty ``line`` that is not plain text, or None.

    Outside the erratum block a line may be an ATX heading or a plain paragraph line. Inside it,
    a line may also hold code spans: balanced single backticks around plain text.
    """
    if not line.strip(" \t"):
        return "a whitespace-only line"
    body = line.lstrip(" ")
    if body.startswith(("```", "~~~")):
        return "a code fence"
    if line.startswith(("    ", "\t")) or (body.startswith("\t") and len(line) - len(body) < 4):
        return "indented code"
    if body.startswith(">"):
        return "a block quote"
    if re.match(r"\[[^\]]*\]:", body):
        return "a link reference definition"
    if re.search(r"<details(?![A-Za-z0-9-])", line, re.IGNORECASE):
        return "a <details> element"
    text = line
    if in_block and "`" in line:
        spans = line.split("`")
        if len(spans) % 2 == 0 or any(not spans[i] for i in range(1, len(spans), 2)):
            return "a code span that is not a balanced single-backtick pair"
        text = "".join(spans)
    for needle, name in NOT_PLAIN:
        if needle in text:
            return name
    heading = ATX_RE.match(line)
    if not heading:
        if line != body:
            return "an indented line"
        if LIST_RE.match(line):
            return "a list item"
        first = line[0]
        if not (first.isascii() and first.isalnum()) and not (
            not first.isascii() and unicodedata.category(first)[0] in "LN"
        ):
            return "a line that does not start with a letter or digit"
    for c in text:
        if not plain_char(c):
            return "character U+%04X outside the plain set" % ord(c)
    return None


def erratum_block(rel, raw):
    """Return (erratum line indexes, problems) for one document's raw lines (design B, item 3).

    The erratum is an ATX heading ``#.. Erratum`` and the paragraph after it. Only blank lines,
    ATX headings and plain paragraph lines may precede the heading, and the paragraph holds
    plain text and balanced code spans only, so a renderer always shows it. Its lines that start
    ``Erratum (#<issue>): `` are the erratum lines. Any other shape, a second heading, a
    heading with no paragraph, or an erratum line anywhere else is a problem; a document with a
    problem carries no erratum.
    """
    heads = [i for i, line in enumerate(raw) if ERRATUM_HEAD_RE.match(line)]
    mentions = [i for i, line in enumerate(raw) if ERRATUM_RE.search(line) or ERRATUM_RE.search(decoded(line))]
    if not heads and not mentions:
        return [], []
    problems = []
    if not heads:
        for i in mentions:
            problems.append(
                "%s:%d: erratum line without an erratum heading (`## Erratum (#<issue>)` above a plain paragraph)"
                % (rel, i + 1)
            )
        return [], problems
    head = heads[0]
    for i in heads[1:]:
        problems.append("%s:%d: a second erratum heading (one erratum block per document)" % (rel, i + 1))
    for i in range(head + 1):
        what = construct(raw[i], False) if raw[i] else None
        if what:
            problems.append(
                "%s:%d: %s %s the erratum heading (only blank lines, ATX headings and plain paragraph"
                " lines may precede it)" % (rel, i + 1, what, "at" if i == head else "before")
            )
    j = head + 1
    while j < len(raw) and not raw[j]:
        j += 1
    block = []
    while j < len(raw) and raw[j]:
        block.append(j)
        j += 1
    if not block:
        problems.append("%s:%d: erratum heading with no paragraph" % (rel, head + 1))
    for i in block:
        # A heading line ends the paragraph: the block would be a heading and a paragraph (#6636).
        what = "a heading" if ATX_RE.match(raw[i]) else construct(raw[i], True)
        if what:
            problems.append(
                "%s:%d: %s in the erratum block (plain text and balanced code spans only)" % (rel, i + 1, what)
            )
    starts = [i for i in block if ERRATUM_RE.match(raw[i])]
    if block and not starts:
        problems.append("%s:%d: no line of the erratum block starts `Erratum (#<issue>): `" % (rel, block[0] + 1))
    for i in mentions:
        if i not in starts:
            problems.append(
                "%s:%d: erratum line outside the erratum block, or not at the start of a block line" % (rel, i + 1)
            )
    return ([] if problems else starts), problems


def erratum_names(root, line):
    """Yield (stale name, successor) for each name an erratum ``line`` gives an existing successor (#6198)."""
    succ = [s for s in SUCCESSOR_RE.findall(line) if successor_ok(root, s)]
    if not succ:
        return
    for _cited, name, path in tokens(line):
        if path not in ["scripts/" + s for s in succ]:
            yield name, succ[0]


def load_allowlist(root):
    """Return ({(doc, token): (count, pinned, lineno)}, problems) from the allowlist (design B, item 2)."""
    path = root / ALLOW_REL
    # Only a path that does not exist is absent (#6353); a symlink loop, a permission error or
    # any other failure to stat it is an unreadable allowlist (exit 2), never "no allowlist".
    try:
        present = stat.S_ISREG(os.stat(str(path)).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        present = False
    except OSError:
        raise Unreadable(ALLOW_REL)
    if not present:
        return {}, []
    entries, problems = {}, []
    for lineno, raw in enumerate(read_text(root, path).split("\n"), 1):
        line = raw.strip(" ")
        if not line or line.startswith("#"):
            continue
        m = ENTRY_RE.match(line)
        full = bool(m) and FULL_NAME_RE.fullmatch(m.group(2)) is not None
        if not m or (m.group(4) and not full):
            problems.append("%s:%d: malformed allowlist entry %r" % (ALLOW_REL, lineno, line))
            continue
        key = (m.group(1), m.group(2))
        if key in entries:
            problems.append("%s:%d: duplicate allowlist entry %s:%s" % (ALLOW_REL, lineno, key[0], key[1]))
            continue
        entries[key] = (int(m.group(3)), m.group(4) is not None, lineno)
        if m.group(4) and key[0] not in PINNABLE_DOCS:
            problems.append(
                "%s:%d: :pinned not permitted for %s:%s (only %s)"
                % (ALLOW_REL, lineno, key[0], key[1], ", ".join(sorted(PINNABLE_DOCS)))
            )
    if len(entries) > ALLOW_CEILING:
        problems.append(
            "%s: %d entries exceed the allowlist ceiling ALLOW_CEILING = %d (the ceiling only falls)"
            % (ALLOW_REL, len(entries), ALLOW_CEILING)
        )
    return entries, problems


def scan_line(root, rel, doc, i, stop):
    """Return (problems, stale, cited_at, frags, why) for line ``i`` of ``doc`` (each line's ``views``).

    ``stop`` is the index of the paragraph's next blank line (or the line count); stale and frags
    map a token to its count.
    """
    lineno, shown, line = i + 1, doc[i], doc[i][0]
    problems = []
    for c in sorted({c for c in line if odd(c)}):
        problems.append(
            "%s:%d: character U+%04X (%s) makes the line structure ambiguous; the gate does not decide it"
            % (rel, lineno, ord(c), unicodedata.name(c, "control"))
        )
    for c in sorted({c for c in line + html.unescape(line) if c in BIDI_CONTROLS}):
        problems.append(
            "%s:%d: bidirectional control character U+%04X (it reorders what a reader sees)" % (rel, lineno, ord(c))
        )
    for name in sorted({n for n in lookalikes(line)}):
        problems.append(
            "%s:%d: look-alike script name %s (a non-ASCII letter or mark where a script name has an ASCII letter)"
            % (rel, lineno, ascii(name))
        )
    found = [list(tokens(v)) for v in shown]
    counts = [{} for _ in shown]
    for k, toks in enumerate(found):
        for _cited, name, _path in toks:
            counts[k][name] = counts[k].get(name, 0) + 1
    for name in sorted(set(counts[1]) | set(counts[2])):
        if max(counts[1].get(name, 0), counts[2].get(name, 0)) > counts[0].get(name, 0):
            problems.append(
                "%s:%d: script name `%s` is shown only after decoding a character reference or folding"
                " an invisible, look-alike or emphasis character" % (rel, lineno, name)
            )
    stale, cited_at = {}, {}
    for k, toks in enumerate(found):
        per = {}
        for cited, name, path in toks:
            if path_ok(root, path):
                continue
            per[name] = per.get(name, 0) + 1
            cited_at.setdefault(name, (cited, path))
        for name, n in per.items():
            stale[name] = max(stale.get(name, 0), n)
    frags, why, joins = {}, {}, set()
    budget = [JOIN_BUDGET]
    for k, (v, w) in enumerate(zip(shown, doc[i + 1] if i + 1 < len(doc) else (None, None, None))):
        per, rest = {}, []

        def follow(k=k, rest=rest):
            if not rest:
                rest.append(paragraph_rest(doc, i + 1, stop, k))
            return rest[0]

        for frag, reason, (kind, name) in fragments(v, w, follow, budget):
            if kind:
                joins.add((frag, kind, name))
            if reason is None:
                continue
            per[frag] = per.get(frag, 0) + 1
            why.setdefault(frag, reason)
        for frag, n in per.items():
            frags[frag] = max(frags.get(frag, 0), n)
    # #6621, #6631: a join is red whatever the allowlist holds; a fragment entry only counts prose.
    for frag, kind, name in sorted(joins, key=lambda j: (j[0], j[1], j[2] or "")):
        if kind == "join":
            problems.append(
                "%s:%d: name fragment `%s` joins into script name `%s` once markup or the line break is"
                " dropped (no allowlist entry suppresses a join)" % (rel, lineno, frag, name)
            )
        else:
            problems.append(
                "%s:%d: name fragment `%s` is followed by markup the gate cannot resolve (a comment, tag or"
                " link that does not close within its paragraph, or more than %d characters or %d steps; no"
                " allowlist entry suppresses this)"
                % (rel, lineno, frag, JOIN_WINDOW, JOIN_BUDGET)
            )
    return problems, stale, cited_at, frags, why


def check(root):
    """Return a list of violation strings for the tree at ``root``."""
    docs, problems = compliance_docs(root)
    texts = []
    for doc in docs:
        text = read_text(root, doc)
        texts.append((doc.relative_to(root).as_posix(), text[1:] if text.startswith("\ufeff") else text))
    allowed, ledger = load_allowlist(root)
    problems.extend(ledger)
    errata, per_doc = {}, {}
    lines_by_doc = []
    for rel, text in texts:
        raw = text.split("\n")
        if raw[-1] == "":
            raw.pop()
        for n, line in enumerate(raw):
            if len(line) > LINE_CEILING:
                raise LineTooLong(rel, n + 1, len(line))
        lines_by_doc.append((rel, raw))
        starts, shape = erratum_block(rel, raw)
        problems.extend(shape)
        for i in starts:
            for name, succ in erratum_names(root, raw[i]):
                errata[name] = succ
                per_doc.setdefault(rel, {})[name] = succ
    seen = {}
    for rel, raw in lines_by_doc:
        doc = [views(line) for line in raw]
        # stops[i]: the paragraph of line i ends before the next blank line (#6753, #6757).
        stops, stop = [0] * len(raw), len(raw)
        for i in range(len(raw) - 1, -1, -1):
            stops[i] = stop
            if not raw[i].strip(" \t"):
                stop = i
        for i in range(len(raw)):
            found, stale, cited_at, frags, why = scan_line(root, rel, doc, i, stops[i])
            problems.extend(found)
            for name, n in sorted(stale.items()):
                seen[(rel, name)] = seen.get((rel, name), 0) + n
                entry = allowed.get((rel, name))
                covered = entry is not None and (name in errata if entry[1] else name in per_doc.get(rel, {}))
                if covered:
                    continue
                cited, path = cited_at[name]
                if path is None:
                    path = "a path longer than %d bytes" % PATH_LIMIT
                problems.append(
                    "%s:%d: `%s` does not exist (checked at %s) and no erratum-covered allowlist"
                    " entry (%s) names it" % (rel, i + 1, cited, path, ALLOW_REL)
                )
            for frag, n in sorted(frags.items()):
                seen[(rel, frag)] = seen.get((rel, frag), 0) + n
                if (rel, frag) in allowed:
                    continue
                problems.append(
                    "%s:%d: name fragment `%s` %s: a renderer can join it into a script name"
                    " (a %s:%s:<count> allowlist entry records it as prose)" % (rel, i + 1, frag, why[frag], rel, frag)
                )
    for (rel, token), (count, pinned, lineno) in sorted(allowed.items()):
        found = seen.get((rel, token), 0)
        if not found:
            problems.append("%s:%d: stale allowlist entry %s:%s suppresses nothing" % (ALLOW_REL, lineno, rel, token))
        elif found != count:
            problems.append(
                "%s:%d: allowlist entry %s:%s expects %d occurrence(s), the document holds %d"
                % (ALLOW_REL, lineno, rel, token, count, found)
            )
        if pinned and token in per_doc.get(rel, {}):
            problems.append(
                "%s:%d: unnecessary :pinned on %s:%s (the document carries its own erratum)"
                % (ALLOW_REL, lineno, rel, token)
            )
    return problems


def run_main(root):
    """Run main() against ``root``; return (exit code or 'traceback', stderr)."""
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = main(["--root", str(root)])
    except Exception as exc:  # a traceback is itself the failure being probed
        return "traceback:" + type(exc).__name__, err.getvalue()
    return rc, err.getvalue()


# Round 11 (design B, 3-agent vote (6def5ab6)): finite enumerated cells, one table per predicate.
# A cell is (name, docs, allowlist text, expected exit code, text the report must contain or None).
# ``docs`` is the text of docs/compliance/A.md (str, or bytes written as is) or a dict of document
# names to texts. Every fixture tree also holds scripts/check_new.py.
R11_ERR = "## Erratum (#1)\n\nErratum (#1): `check-old.sh` is `scripts/check_new.py`.\n\n"
R11_OK = "# Title\n\nIntro line.\n\n" + R11_ERR + "N30 enforcer is `check-old.sh`.\n"
R11_ALLOW = "docs/compliance/A.md:check-old.sh:2\n"
NOT_FOUND = "does not exist"
R11_NAME_CELLS = (
    ("N-plain", "Run check-old.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("N-dash-py", "Run check-old.py daily.\n", "", 1, "`check-old.py` " + NOT_FOUND),
    ("N-under-sh", "Run check_old.sh daily.\n", "", 1, "`check_old.sh` " + NOT_FOUND),
    ("N-under-py", "Run check_old.py daily.\n", "", 1, "`check_old.py` " + NOT_FOUND),
    ("N-upper", "Run CHECK-old.sh daily.\n", "", 1, "`CHECK-old.sh` " + NOT_FOUND),
    ("N-mixed", "Run Check_Old.PY daily.\n", "", 1, "`Check_Old.PY` " + NOT_FOUND),
    ("N-case-existing", "Run check_NEW.py daily.\n", "", 1, "`check_NEW.py` " + NOT_FOUND),
    ("N-comment", "<!-- check-old.sh -->\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("N-fence", "```\ncheck-old.sh\n```\n", "", 1, "A.md:2: `check-old.sh` " + NOT_FOUND),
    ("N-details", "<details>\n\ncheck-old.sh\n</details>\n", "", 1, "A.md:3: `check-old.sh` " + NOT_FOUND),
    ("N-link-dest", "[x](check-old.sh)\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("N-ref-def", "[x]: check-old.sh\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("N-attr", '<a title="check-old.sh">x</a>\n', "", 1, "`check-old.sh` " + NOT_FOUND),
    ("N-scripts-prefix", "Run `scripts/check-old.sh`.\n", "", 1, "`scripts/check-old.sh` " + NOT_FOUND),
    ("N-infra", "Run `infra/check_new.py`.\n", "", 1, "`infra/check_new.py` " + NOT_FOUND),
    ("N-tools-scripts", "Run `tools/scripts/check_new.py`.\n", "", 1, "`tools/scripts/check_new.py` " + NOT_FOUND),
    ("N-dot", "Run `./check_new.py`.\n", "", 1, "`./check_new.py` " + NOT_FOUND),
    ("N-scripts-scripts", "Run `scripts/scripts/check_new.py`.\n", "", 1, "checked at scripts/scripts/check_new.py"),
    ("N-exists", "See `check_new.py` and `scripts/check_new.py`.\n", "", 0, None),
    ("N-exists-paths", "See `./scripts/check_new.py` and `../../scripts/check_new.py`.\n", "", 0, None),
    ("N-bounded", "Run xcheck-old.sh and check-old.shx today.\n", "", 0, None),
)
R11_UNESCAPE_CELLS = (
    ("U-dec", "Run check&#45;old.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-hex", "Run check&#x2d;old.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-named-hyphen", "Run check&hyphen;old.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-named-period", "Run check-old&period;sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-dec-letter", "Run &#99;heck-old.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-zwsp", "Run check-\u200bold.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-shy", "Run check-ol\u00add.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-vs", "Run check-\ufe0fold.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-fullwidth", "Run \uff43heck-old.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-cyrillic", "Run \u0441heck-old.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-mark", "Run che\u0301ck-old.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-minus", "Run check\u2212old.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-star", "Run *check*-old.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-underscore", "Run _check_-old.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-tilde", "Run ~~check~~-old.sh daily.\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("U-hidden-existing", "Run check&#95;new.py daily.\n", "", 1, "`check_new.py` is shown only after"),
    ("U-hidden-zw-existing", "Run check_\u200bnew.py daily.\n", "", 1, "`check_new.py` is shown only after"),
    ("U-lookalike", "Run \u0188heck-old.sh daily.\n", "", 1, "look-alike script name"),
    ("U-lookalike-ref", "Run &#x188;heck-old.sh daily.\n", "", 1, "look-alike script name"),
    ("U-lookalike-zw", "Run \u0188\u200bheck-old.sh daily.\n", "", 1, "look-alike script name"),
    ("U-lookalike-existing", "Run \u0188heck_new.py daily.\n", "", 1, "look-alike script name"),
    ("U-bidi-raw", "Run check_new.py\u202e daily.\n", "", 1, "bidirectional control character U+202E"),
    ("U-bidi-ref", "Run check_new.py&#x202E; daily.\n", "", 1, "bidirectional control character U+202E"),
    ("U-bidi-code", "Run `\u2066` daily.\n", "", 1, "bidirectional control character U+2066"),
    ("U-amp-literal", "Fish &amp;#x202E; chips.\n", "", 0, None),
)
R11_STALE = "N30 enforcer is `check-old.sh`.\n"
R11_DECL = "v1.0.0-DECLARATION.md"
R11_PIN = "docs/compliance/v1.0.0-DECLARATION.md:check-old.sh:1:pinned\n"
R11_B_ERR = "docs/compliance/B.md:check-old.sh:1\n"
R11_ALLOW_CELLS = (
    ("A-ok", R11_OK, R11_ALLOW, 0, None),
    ("A-padded", R11_OK, "  docs/compliance/A.md:check-old.sh:2  \n", 0, None),
    ("A-count-high", R11_OK, "docs/compliance/A.md:check-old.sh:3\n", 1, "expects 3 occurrence(s), the document holds 2"),
    ("A-count-low", R11_OK, "docs/compliance/A.md:check-old.sh:1\n", 1, "expects 1 occurrence(s), the document holds 2"),
    ("A-count-missing", R11_OK, "docs/compliance/A.md:check-old.sh\n", 1, "malformed allowlist entry"),
    ("A-count-zero", R11_OK, "docs/compliance/A.md:check-old.sh:0\n", 1, "malformed allowlist entry"),
    ("A-count-lead-zero", R11_OK, "docs/compliance/A.md:check-old.sh:02\n", 1, "malformed allowlist entry"),
    ("A-count-sign", R11_OK, "docs/compliance/A.md:check-old.sh:+2\n", 1, "malformed allowlist entry"),
    ("A-tail-x", R11_OK, "docs/compliance/A.md:check-old.sh:2x\n", 1, "malformed allowlist entry"),
    ("A-tail-pinnedx", R11_OK, "docs/compliance/A.md:check-old.sh:2:pinnedx\n", 1, "malformed allowlist entry"),
    ("A-tail-word", R11_OK, "docs/compliance/A.md:check-old.sh:2 trailing\n", 1, "malformed allowlist entry"),
    ("A-tail-bogus", R11_OK, "docs/compliance/A.md:check-old.sh:2:bogus\n", 1, "malformed allowlist entry"),
    ("A-junk", R11_OK, R11_ALLOW + "junk # note\n", 1, "malformed allowlist entry"),
    ("A-outside", R11_OK, "notes/A.md:check-old.sh:2\n", 1, "malformed allowlist entry"),
    ("A-duplicate", R11_OK, R11_ALLOW * 2, 1, "duplicate allowlist entry docs/compliance/A.md:check-old.sh"),
    ("A-case", R11_OK, "docs/compliance/A.md:check-OLD.sh:2\n", 1, "`check-old.sh` " + NOT_FOUND),
    ("A-stale-entry", R11_OK, R11_ALLOW + "docs/compliance/A.md:check-gone.sh:1\n", 1, "check-gone.sh suppresses nothing"),
    ("A-none", R11_OK, "", 1, "`check-old.sh` " + NOT_FOUND),
    ("A-no-erratum", R11_STALE, "docs/compliance/A.md:check-old.sh:1\n", 1, "`check-old.sh` " + NOT_FOUND),
    ("A-other-erratum", {"A.md": R11_STALE, "B.md": R11_ERR}, "docs/compliance/A.md:check-old.sh:1\n" + R11_B_ERR,
     1, "A.md:1: `check-old.sh` " + NOT_FOUND),
    ("A-pinned-ok", {R11_DECL: R11_STALE, "B.md": R11_ERR}, R11_PIN + R11_B_ERR, 0, None),
    ("A-pinned-no-erratum", {R11_DECL: R11_STALE}, R11_PIN, 1, "`check-old.sh` " + NOT_FOUND),
    ("A-pinned-outside", {"A.md": R11_STALE, "B.md": R11_ERR},
     "docs/compliance/A.md:check-old.sh:1:pinned\n" + R11_B_ERR, 1, ":pinned not permitted"),
    ("A-pinned-subdir", {"sub/" + R11_DECL: R11_STALE, "B.md": R11_ERR},
     "docs/compliance/sub/v1.0.0-DECLARATION.md:check-old.sh:1:pinned\n" + R11_B_ERR, 1, ":pinned not permitted"),
    ("A-pinned-unnecessary", {R11_DECL: R11_ERR + R11_STALE}, "docs/compliance/v1.0.0-DECLARATION.md:check-old.sh:2:pinned\n",
     1, "unnecessary :pinned"),
    ("A-fragment-ok", "Section (c) applies.\n", "docs/compliance/A.md:c:1\n", 0, None),
    ("A-fragment-count", "Section (c) applies.\n", "docs/compliance/A.md:c:2\n", 1, "expects 2 occurrence(s)"),
    ("A-fragment-case", "Section (c) applies.\n", "docs/compliance/A.md:C:1\n", 1, "fragment `c` is followed by"),
    ("A-fragment-pinned", "Section (c) applies.\n", "docs/compliance/A.md:c:1:pinned\n", 1, "malformed allowlist entry"),
    ("A-ceiling", {"D%02d.md" % i: "Section (c) applies.\n" for i in range(32)},
     "".join("docs/compliance/D%02d.md:c:1\n" % i for i in range(32)), 1, "exceed the allowlist ceiling"),
    ("A-successor-missing", R11_OK.replace("check_new.py", "check_missing.py"), R11_ALLOW, 1, "`check-old.sh` " + NOT_FOUND),
    ("A-successor-dotdot", R11_OK.replace("scripts/check_new.py", "scripts/../check_new.py"), R11_ALLOW, 1,
     "`check-old.sh` " + NOT_FOUND),
    ("A-successor-dot", R11_OK.replace("scripts/check_new.py", "scripts/./check_new.py"), R11_ALLOW, 1,
     "`check-old.sh` " + NOT_FOUND),
    ("A-successor-elsewhere", R11_OK + "Old copy: `scripts/legacy/check_new.py`.\n",
     R11_ALLOW + "docs/compliance/A.md:check_new.py:1\n", 1, "`scripts/legacy/check_new.py` " + NOT_FOUND),
)


def r11_pre(text):
    """R11_OK with ``text`` inserted before the erratum heading."""
    return R11_OK.replace("Intro line.\n", "Intro line.\n\n" + text, 1)


def r11_err(line):
    """R11_OK with the erratum paragraph replaced by ``line``."""
    return R11_OK.replace("Erratum (#1): `check-old.sh` is `scripts/check_new.py`.\n", line, 1)


BEFORE = "before the erratum heading"
IN_BLOCK = "in the erratum block"
R11_ERRATUM_CELLS = (
    ("E-ok", R11_OK, R11_ALLOW, 0, None),
    ("E-ok-top", R11_ERR + R11_STALE, R11_ALLOW, 0, None),
    ("E-ok-two-lines", r11_err("Erratum (#1): `check-old.sh` is `scripts/check_new.py`.\nSee issue 1.\n"), R11_ALLOW, 0, None),
    ("E-pre-comment", r11_pre("<!-- note -->\n"), R11_ALLOW, 1, "an HTML comment " + BEFORE),
    ("E-pre-comment-open", r11_pre("<!--\n\n"), R11_ALLOW, 1, "an HTML comment " + BEFORE),
    ("E-pre-details", r11_pre("<details>\n\n"), R11_ALLOW, 1, "a <details> element " + BEFORE),
    ("E-pre-fence", r11_pre("```\n"), R11_ALLOW, 1, "a code fence " + BEFORE),
    ("E-pre-tilde-fence", r11_pre("~~~\n"), R11_ALLOW, 1, "a code fence " + BEFORE),
    ("E-pre-indented", r11_pre("    code\n"), R11_ALLOW, 1, "indented code " + BEFORE),
    ("E-pre-quote", r11_pre("> quote\n"), R11_ALLOW, 1, ": a block quote " + BEFORE),
    ("E-shape-uncovers", r11_pre("<!-- note -->\n"), R11_ALLOW, 1, "`check-old.sh` " + NOT_FOUND),
    ("E-pre-refdef", r11_pre("[a]: https://example.com\n"), R11_ALLOW, 1, "a link reference definition " + BEFORE),
    ("E-pre-tag", r11_pre("Text <b>x</b>\n"), R11_ALLOW, 1, "raw HTML or an autolink " + BEFORE),
    ("E-pre-link", r11_pre("See [a](b).\n"), R11_ALLOW, 1, "a link or image bracket " + BEFORE),
    ("E-pre-table", r11_pre("a | b\n"), R11_ALLOW, 1, "a table pipe " + BEFORE),
    ("E-pre-charref", r11_pre("Fish &amp; chips\n"), R11_ALLOW, 1, "a character reference " + BEFORE),
    ("E-pre-escape", r11_pre("Back\\slash\n"), R11_ALLOW, 1, "a backslash escape " + BEFORE),
    ("E-pre-code", r11_pre("Use `x` here\n"), R11_ALLOW, 1, "a code span " + BEFORE),
    ("E-pre-bullet", r11_pre("- item\n"), R11_ALLOW, 1, "a list item " + BEFORE),
    ("E-pre-ordered", r11_pre("1. item\n"), R11_ALLOW, 1, "a list item " + BEFORE),
    ("E-pre-ordered-paren", r11_pre("1) item\n"), R11_ALLOW, 1, "a list item " + BEFORE),
    ("E-pre-tab", r11_pre("Tab\there\n"), R11_ALLOW, 1, "a tab " + BEFORE),
    ("E-pre-blankish", r11_pre("   \n"), R11_ALLOW, 1, "a whitespace-only line " + BEFORE),
    ("E-pre-indent-1", r11_pre(" Text\n"), R11_ALLOW, 1, "an indented line " + BEFORE),
    ("E-pre-punct", r11_pre("(paren) start\n"), R11_ALLOW, 1, "does not start with a letter or digit " + BEFORE),
    ("E-pre-setext", r11_pre("Text\n===\n"), R11_ALLOW, 1, "does not start with a letter or digit " + BEFORE),
    ("E-pre-math", r11_pre("Price $5\n"), R11_ALLOW, 1, "a math delimiter " + BEFORE),
    ("E-pre-strike", r11_pre("Strike ~x~\n"), R11_ALLOW, 1, "a strikethrough or tilde fence " + BEFORE),
    ("E-pre-invisible", r11_pre("Zero\u200bwidth\n"), R11_ALLOW, 1, "outside the plain set " + BEFORE),
    ("E-pre-heading-tag", r11_pre("## Heading <b>\n"), R11_ALLOW, 1, "raw HTML or an autolink " + BEFORE),
    ("E-block-lt", r11_err("Erratum (#1): `check-old.sh` is `scripts/check_new.py` for git < 2.30.\n"), R11_ALLOW, 1,
     "raw HTML or an autolink " + IN_BLOCK),
    ("E-block-link", r11_err("Erratum (#1): `check-old.sh` is [`scripts/check_new.py`](x).\n"), R11_ALLOW, 1,
     "a link or image bracket " + IN_BLOCK),
    ("E-block-odd-tick", r11_err("Erratum (#1): `check-old.sh` is `scripts/check_new.py`.`\n"), R11_ALLOW, 1,
     "a code span that is not a balanced single-backtick pair " + IN_BLOCK),
    ("E-block-double-tick", r11_err("Erratum (#1): ``check-old.sh`` is `scripts/check_new.py`.\n"), R11_ALLOW, 1,
     "a code span that is not a balanced single-backtick pair " + IN_BLOCK),
    ("E-block-code-lt", r11_err("Erratum (#1): `check-old.sh` is `scripts/check_new.py`; `a<b`.\n"), R11_ALLOW, 1,
     "raw HTML or an autolink " + IN_BLOCK),
    ("E-block-indented", r11_err("  Erratum (#1): `check-old.sh` is `scripts/check_new.py`.\n"), R11_ALLOW, 1,
     "an indented line " + IN_BLOCK),
    ("E-block-setext", r11_err("Erratum (#1): `check-old.sh` is `scripts/check_new.py`.\n---\n"), R11_ALLOW, 1,
     "does not start with a letter or digit " + IN_BLOCK),
    ("E-block-comment", r11_err("Erratum (#1): `check-old.sh` is `scripts/check_new.py`. <!--\n"), R11_ALLOW, 1,
     "an HTML comment " + IN_BLOCK),
    ("E-no-heading", "Intro.\n\nErratum (#1): `check-old.sh` is `scripts/check_new.py`.\n\n" + R11_STALE, R11_ALLOW, 1,
     "erratum line without an erratum heading"),
    ("E-no-start", r11_err("The enforcer `check-old.sh` is `scripts/check_new.py`.\n"), R11_ALLOW, 1,
     "no line of the erratum block starts"),
    ("E-mid-line", r11_err("See Erratum (#1): `check-old.sh` is `scripts/check_new.py`.\n"), R11_ALLOW, 1,
     "no line of the erratum block starts"),
    ("E-outside", R11_OK + "\nErratum (#2): `check-old.sh` is `scripts/check_new.py`.\n", "docs/compliance/A.md:check-old.sh:3\n",
     1, "erratum line outside the erratum block"),
    ("E-outside-ref", R11_OK + "\nErratum&#32;(#2): x.\n", R11_ALLOW, 1, "erratum line outside the erratum block"),
    ("E-second-heading", R11_OK + "\n## Erratum (#2)\n\nMore.\n", R11_ALLOW, 1, "a second erratum heading"),
    ("E-no-paragraph", R11_STALE + "\n## Erratum (#1)\n", "docs/compliance/A.md:check-old.sh:1\n", 1,
     "erratum heading with no paragraph"),
    ("E-heading-tag", R11_OK.replace("## Erratum (#1)", "## Erratum (#1) <!-- x -->"), R11_ALLOW, 1,
     "an HTML comment at the erratum heading"),
)
R11_ADJACENT_CELLS = (
    ("M-bracket", "Run [check-](x)old.sh.\n", "", 1, "fragment `check-` is followed by ']'"),
    ("M-backtick", "Run `check-`old.sh.\n", "", 1, "fragment `check-` is followed by '`'"),
    ("M-tag", "Run check-<b></b>old.sh.\n", "", 1, "fragment `check-` is followed by '<'"),
    ("M-comment", "Run che<!-- -->ck-old.sh.\n", "", 1, "fragment `che` is followed by '<'"),
    ("M-escape", "Run check\\-old.sh.\n", "", 1, "fragment `check` is followed by '\\\\'"),
    ("M-amp", "Run check&#8203;-old.sh.\n", "", 1, "fragment `check` is followed by '&'"),
    ("M-paren", "Run c(x)heck-old.sh.\n", "", 1, "fragment `c` is followed by '('"),
    ("M-close-paren", "Run check)\n", "", 1, "fragment `check` is followed by ')'"),
    ("M-gt", "Run check-old>.sh\n", "", 1, "fragment `check-old` is followed by '>'"),
    ("M-open-bracket", "Run check_old[.sh]\n", "", 1, "fragment `check_old` is followed by '['"),
    ("M-break", "Run check-\nold.sh daily.\n", "", 1, "ends the line and the next line completes it to check-old.sh"),
    ("M-break-short", "Run chec\nk-old.sh daily.\n", "", 1, "ends the line and the next line completes it to check-old.sh"),
    ("M-break-indent", "Run check-\n\t  old.sh daily.\n", "", 1, "ends the line and the next line completes it"),
    ("M-break-markup", "Run check-\n<b>old.sh</b>\n", "", 1, "ends the line and the next line starts with '<'"),
    ("M-break-entity", "Run check\n&#45;old.sh\n", "", 1, "ends the line and the next line starts with '&'"),
    ("M-prose", "Run the checklist daily.\nCheck in at noon.\n", "", 0, None),
    ("M-prose-break", "Please check-in\nthe lobby.\n", "", 0, None),
    ("M-prose-paren", "Section (b) applies to abc(x).\n", "", 0, None),
)
R11_UNDECIDABLE_CELLS = (
    ("X-tab", "Run\tcheck_new.py\tdaily.\n", "", 0, None),
    ("X-vt", "Run check\x0bold.\n", "", 1, "character U+000B"),
    ("X-ff", "Run check\x0cold.\n", "", 1, "character U+000C"),
    ("X-nel", "Run check\x85old.\n", "", 1, "character U+0085"),
    ("X-ls", "Run check\u2028old.\n", "", 1, "character U+2028"),
    ("X-ps", "Run check\u2029old.\n", "", 1, "character U+2029"),
    ("X-bom-mid", "Run check\ufeffold.\n", "", 1, "character U+FEFF"),
    ("X-bom-second", "\ufeff\ufeffRun.\n", "", 1, "character U+FEFF"),
    ("X-nul", "Run check\x00old.\n", "", 1, "character U+0000"),
    ("X-cr", "Run check.\r\n", "", 1, "character U+000D"),
    ("X-del", "Run check\x7fold.\n", "", 1, "character U+007F"),
    ("X-c1", "Run check\x9bold.\n", "", 1, "character U+009B"),
    ("X-bom-lead", "\ufeffSee `check_new.py`.\n", "", 0, None),
    ("X-invalid-utf8", b"Run \xff\xfe.\n", "", 2, "A.md: unreadable"),
    ("X-truncated-utf8", b"Run \xc3(.\n", "", 2, "A.md: unreadable"),
    ("X-allow-invalid-utf8", "See `check_new.py`.\n", b"docs/compliance/A.md:c\xff:1\n", 2, ALLOW_REL + ": unreadable"),
)
R11_CELLS = (
    R11_NAME_CELLS + R11_UNESCAPE_CELLS + R11_ALLOW_CELLS + R11_ERRATUM_CELLS + R11_ADJACENT_CELLS + R11_UNDECIDABLE_CELLS
)


# Round 12: one table, cells named for the issue they pin.
R12_STALE = "Run check-old.sh daily.\n"
R12_ERR_LINE = "Erratum (#1): `check-old.sh` is `scripts/check_new.py`.\n"
R12_BASE = "Clause (c) applies.\nOther (c) item.\n"
R12_FRAG = "docs/compliance/A.md:c:2\n"
R12_JOIN = "joins into script name `check-gone.sh`"
R12_FRAG1 = "docs/compliance/A.md:c:1\n"
R12_UNRESOLVED = "is followed by markup the gate cannot resolve"
R12_LEFT = "`check-old.sh` does not exist (checked at scripts/check-old.sh)"


def r12_swap(join):
    """R12_BASE with its first allowlisted ``(c)`` replaced by ``join`` (fragment count unchanged)."""
    return R12_BASE.replace("(c)", join, 1)


R12_CELLS = (
    # #6622: an image (``!``) or inline math (``$``, ``{``, ``}``) between the pieces of a name.
    ("M-image-adjacent", "Run check-![](x)old.sh daily.\n", "", 1, "fragment `check-` is followed by '!'"),
    ("M-image-inside", "Run che![ck-old.sh](x) daily.\n", "", 1, "fragment `che` is followed by '!'"),
    ("M-math-text", "Run $\\text{check-old}$.sh daily.\n", "", 1, "fragment `check-old` is followed by '}'"),
    ("M-math-wrap", "Run $check$-old.sh daily.\n", "", 1, "fragment `check` is followed by '$'"),
    ("M-math-brace", "Run $check{-old}.sh$ daily.\n", "", 1, "fragment `check` is followed by '{'"),
    # #6621, #6631: an allowlisted prose fragment re-used to join a script name, count unchanged.
    ("L-frag-base", R12_BASE, R12_FRAG, 0, None),
    ("L-frag-swap-comment", r12_swap("(c<!-- -->heck-gone.sh)"), R12_FRAG, 1, R12_JOIN),
    ("L-frag-swap-tag", r12_swap("(c<b></b>heck-gone.sh)"), R12_FRAG, 1, R12_JOIN),
    ("L-frag-swap-code", r12_swap("(`c`heck-gone.sh)"), R12_FRAG, 1, R12_JOIN),
    ("L-frag-swap-link", r12_swap("([c](#)heck-gone.sh)"), R12_FRAG, 1, R12_JOIN),
    ("L-frag-swap-img", r12_swap("(c![](x)heck-gone.sh)"), R12_FRAG, 1, R12_JOIN),
    ("L-frag-swap-hidden", r12_swap("(c<s hidden>x</s>heck-gone.sh)"), R12_FRAG, 1, R12_JOIN),
    ("L-frag-swap-quoted", r12_swap('(c<b title="a>b">heck-gone.sh)'), R12_FRAG, 1, R12_JOIN),
    ("L-frag-swap-reflink", r12_swap("([c][r]heck-gone.sh)"), R12_FRAG, 1, R12_JOIN),
    ("L-frag-swap-break", r12_swap("c\nheck-gone.sh"), R12_FRAG, 1, R12_JOIN),
    # #6753: the tag closes on the third line of the paragraph, so the join is resolved and named.
    ("L-frag-swap-unclosed", r12_swap("(c<b\nclass=x\ntitle=y>heck-gone.sh)"), R12_FRAG, 1, R12_JOIN),
    ("L-frag-swap-check", "Use check<!-- -->_gone.py now.\n", "docs/compliance/A.md:check:1\n", 1,
     "joins into script name `check_gone.py`"),
    ("L-frag-swap-escape", "Use (check\\-gone.sh) now.\n", "docs/compliance/A.md:check:1\n", 1, R12_JOIN),
    ("L-frag-swap-long", "Calls `check_agent_action`<b></b>.sh here.\n", "docs/compliance/A.md:check_agent_action:1\n",
     1, "joins into script name `check_agent_action.sh`"),
    ("S-enterprise-c", "### Minting conditions (a)\u2013(c<!-- -->heck-gone.sh\n", "docs/compliance/A.md:c:1\n", 1,
     R12_JOIN),
    ("S-nsa-check_agent_action", "Calls check_agent_action<!-- -->.sh here.\n",
     "docs/compliance/A.md:check_agent_action:1\n", 1, "joins into script name `check_agent_action.sh`"),
    ("S-inventory-check", "| x | (cross-PR check<!-- -->-gone.sh |\n", "docs/compliance/A.md:check:1\n", 1, R12_JOIN),
    ("S-inventory-c", "Per recommendation c<!-- -->heck-gone.sh \u2014 done.\n", "docs/compliance/A.md:c:1\n", 1,
     R12_JOIN),
    # #6632: a name after a run of dots or dashes is a name; a path and a longer word are not.
    ("M-left-ellipsis3", "Then...check-old.sh daily.\n", "", 1, R12_LEFT),
    ("M-left-ellipsis2", "Then..check-old.sh daily.\n", "", 1, R12_LEFT),
    ("M-left-dot", "Run .check-old.sh daily.\n", "", 1, R12_LEFT),
    ("M-left-dash", "Run -check-old.sh daily.\n", "", 1, R12_LEFT),
    ("M-left-dashdash", "Run --check-old.sh daily.\n", "", 1, R12_LEFT),
    ("M-left-path", "Run docs/x-check-old.sh daily.\n", "", 1,
     "`docs/x-check-old.sh` does not exist (checked at docs/x-check-old.sh)"),
    ("M-left-frag", "Then...c<!-- -->heck-old.sh daily.\n", "", 1, "joins into script name `check-old.sh`"),
    ("M-left-dot-slash", "Run ./check-x.sh daily.\n", "", 1, "`./check-x.sh` does not exist (checked at ./check-x.sh)"),
    ("M-left-word", "Run xcheck-a.sh daily.\n", "", 0, None),
    ("M-left-digit", "Run 1check-old.sh daily.\n", "", 0, None),
    ("M-left-existing", "Then...check_new.py daily.\n", "", 0, None),
    ("M-left-flags", "Run `sha256sum -c` and `cargo fmt --check` here.\n", "", 0, None),
    ("M-left-flag-join", "Run -c`heck-old.sh` daily.\n", "", 1, "joins into script name `check-old.sh`"),
) + tuple(
    # #6633: a dash or dot look-alike inside a name, or a space mark as its separator.
    ("E-dash-mid-%04X" % cp, "Run check-old%sx.sh daily.\n" % chr(cp), "", 1, "look-alike script name")
    for cp in (0x2500, 0x2501, 0x23AF, 0x23BA, 0x2E0F, 0x00AF, 0x00B7, 0x2027, 0x10191, 0x1680)
) + (
    ("E-dash-sep-1680", "Run check\u1680old.sh daily.\n", "", 1, "look-alike script name"),
    # #6623: the allowlist ceiling boundary (10 entries pass, 11 fail) and an unpaired backtick in
    # an erratum block line whose other spans are non-empty.
    ("A-ceiling-10", {"D%02d.md" % i: "Section (c) applies.\n" for i in range(10)},
     "".join("docs/compliance/D%02d.md:c:1\n" % i for i in range(10)), 0, None),
    ("A-ceiling-11", {"D%02d.md" % i: "Section (c) applies.\n" for i in range(11)},
     "".join("docs/compliance/D%02d.md:c:1\n" % i for i in range(11)), 1, "exceed the allowlist ceiling"),
    ("E-block-single-tick", r11_err("Erratum (#1): `check-old.sh` is `scripts/check_new.py` and ` here.\n"), R11_ALLOW, 1,
     "a code span that is not a balanced single-backtick pair"),
    # #6426: a comment and a tag whose quoted attribute holds ``>`` between two halves of a name.
    ("6426-comment-join", 'Run check-<<!-- -->a title="y>z">old.sh daily.\n', "", 1, "joins into script name"),
    # #6636: a heading inside the erratum paragraph ends it; the block must be one plain paragraph.
    ("K-heading-in-block", r11_err("# Inner\n" + R12_ERR_LINE), R11_ALLOW, 1, "a heading in the erratum block"),
    ("K-heading-in-block-indented", r11_err("   # Inner\n" + R12_ERR_LINE), R11_ALLOW, 1,
     "an indented line in the erratum block"),
    ("K-heading-in-block-last", r11_err(R12_ERR_LINE + "###### Tail\n"), R11_ALLOW, 1, "a heading in the erratum block"),
    ("K-heading-in-block-bare", r11_err(R12_ERR_LINE + "#\n"), R11_ALLOW, 1, "a heading in the erratum block"),
    ("K-setext-equals-in-block", r11_err(R12_ERR_LINE + "===\n"), R11_ALLOW, 1,
     "a line that does not start with a letter or digit in the erratum block"),
    ("K-setext-dashes-in-block", r11_err(R12_ERR_LINE + "  ---\n"), R11_ALLOW, 1, "an indented line in the erratum block"),
) + tuple(
    # #6633: each new DASHES member folds to ``-``, so the folded view shows the name.
    ("E-dash-fold-%04X" % cp, "Run check-old%sx.sh daily.\n" % chr(cp), "", 1, "`check-old-x.sh` is shown only after")
    for cp in (0x2500, 0x2501, 0x23AF, 0x23BA, 0x2E0F, 0x00AF, 0x1680)
) + tuple(
    # #6634: every GitHub Markdown extension, and a ``.md.`` name, is scanned.
    ("L-glob-%s" % ext, {"A.md": "", "B" + ext: R12_STALE}, "", 1, "`check-old.sh` does not exist")
    for ext in (".markdown", ".mdown", ".mkdn", ".mkd", ".mdwn", ".mdx", ".mkdown", ".livemd", ".ronn", ".scd",
                ".workbook", ".MarkDown", ".md.txt")
) + tuple(
    # #6634: a name that only looks like a Markdown document is refused.
    ("L-glob-refused-%d" % i, {"A.md": "", name: R12_STALE}, "", 1, "only looks like a Markdown document")
    for i, name in enumerate(("B.md ", "B.md\u200b", "B\u2024md", "B.\uff4d\uff44", "B.m\u200bd"))
) + (
    # #6634: a docs/ directory that folds to ``compliance`` is scanned as well.
    ("L-glob-Compliance", {"A.md": "", "../Compliance/B.md": R12_STALE}, "", 1, "`check-old.sh` does not exist"),
    ("L-glob-COMPLIANCE-zw", {"A.md": "", "../compli\u200bance/B.md": R12_STALE}, "", 1, "`check-old.sh` does not exist"),
    ("L-glob-compliance-fw", {"A.md": "", "../\uff43ompliance/B.md": R12_STALE}, "", 1, "`check-old.sh` does not exist"),
    # Controls: HTML and text evidence files stay unscanned.
    ("L-glob-control", {"A.md": "", "index.html": R12_STALE, "B.txt": R12_STALE, "C.log": R12_STALE},
     "", 0, None),
    # Round-12 mutant survivors. #6622: the join walk drops ``$``, ``{`` and ``}`` (math syntax).
    ("J-drop-dollar", "Run c$heck-gone.sh daily.\n", R12_FRAG1, 1, R12_JOIN),
    ("J-drop-lbrace", "Run c{heck-gone.sh daily.\n", R12_FRAG1, 1, R12_JOIN),
    ("J-drop-rbrace", "Run c}heck-gone.sh daily.\n", R12_FRAG1, 1, R12_JOIN),
    # #6621: a walk that reaches the window end, or spends the line's state budget, is unresolved.
    ("J-window-end", "Run c" + "`" * 600 + "heck-gone.sh daily.\n", R12_FRAG1, 1, R12_UNRESOLVED),
    ("J-budget", "Run c<x>" + "".join(ch + "<x>" for ch in "heck-") + "a<x>" * 110 + " end.\n", R12_FRAG,
     1, R12_UNRESOLVED),
    # #6621: the walk also decodes a reference left in the decoded view (an over-approximation of
    # a renderer, which decodes once: red, never green).
    ("J-ref-twice", "Run c<b></b>&amp;#104;eck-gone.sh daily.\n", R12_FRAG1, 1, R12_JOIN),
    # #6631: a fragment ending the line is completed by the next line to a ``check_`` or ``.py`` name.
    ("J-break-under", "Run check_\ngone.py daily.\n", "", 1, "completes it to check_gone.py"),
    ("J-break-py", "Run check-gone\n.py daily.\n", "", 1, "completes it to check-gone.py"),
    # #6623: a seven-hash line is no ATX heading, so the erratum line has no heading; a non-ASCII
    # space (category Z) is outside the plain set of an erratum block.
    ("E-atx7-heading", R11_OK.replace("## Erratum", "####### Erratum"), R11_ALLOW, 1,
     "erratum line without an erratum heading"),
    ("E-block-nbsp", r11_err("Erratum (#1): `check-old.sh` is\u00a0`scripts/check_new.py`.\n"), R11_ALLOW, 1,
     "character U+00A0 outside the plain set in the erratum block"),
)


def r11_cells(base, cells, expect, tag="R11"):
    """Run each cell in a fresh tree under ``base``; every red cell must exit as expected with no traceback."""
    for index, (name, docs, allow, want, needle) in enumerate(cells):
        r = base / ("c%03d" % index)
        (r / "scripts" / "qc-allowlists").mkdir(parents=True)
        (r / "docs" / "compliance").mkdir(parents=True)
        (r / "scripts" / "check_new.py").write_text("")
        for rel, text in (docs if isinstance(docs, dict) else {"A.md": docs}).items():
            path = r / "docs" / "compliance" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
        (r / ALLOW_REL).write_bytes(allow if isinstance(allow, bytes) else allow.encode("utf-8"))
        rc, err = run_main(r)
        expect(
            rc == want and (needle is None or needle in err) and "Traceback" not in err,
            "%s-%s: expected exit %d%s, got %r (stderr=%r)"
            % (tag, name, want, "" if needle is None else " naming %r" % needle, rc, err[-300:]),
        )


# #6635: long lines in seconds (exit code, text the report must contain, line). A line over
# LINE_CEILING characters is undecidable (exit 2); one at the ceiling is scanned in linear time.
R12_TIMED = (
    ("I-line-1MB", 2, "line too long", "check-a.sh/" * 95326),
    ("I-path-ceiling", 1, "`check-a.sh` does not exist", "check-a.sh/" * 5957),
    ("I-loose-ceiling", 0, None, "check\u00e9" * 10922),
)
R12_TIME_BOUND = 30
# #6756: a document of ceiling-length path-like lines and one with many name fragments per line are
# scanned in time linear in their size (each was seconds per line before).
R13_TIMED = (
    ("long16", 1, "`x/check-a.sh` " + NOT_FOUND, "Intro.\n\n" + "\n".join(["x/" + "check-a.sh/" * 5900] * 16)),
    ("frag100", 1, "is followed by '('", "Intro.\n\n" + "\n".join(["c( " * 1000] * 100)),
)
R13_TIME_BOUND = 10


def r12_timed_cells(base, expect, cells=R12_TIMED, bound=R12_TIME_BOUND, tag="R12"):
    """Run each timed document in a fresh tree in a child process that must exit within ``bound`` seconds."""
    for name, want, needle, line in cells:
        r = base / name
        (r / "scripts" / "qc-allowlists").mkdir(parents=True)
        (r / "docs" / "compliance").mkdir(parents=True)
        (r / "docs" / "compliance" / "A.md").write_text(line + "\n", encoding="utf-8")
        (r / ALLOW_REL).write_text("")
        try:
            proc = subprocess.run(
                [sys.executable, "-I", str(Path(__file__).resolve()), "--root", str(r)],
                capture_output=True, text=True, timeout=bound, check=False,
            )
        except subprocess.TimeoutExpired:
            expect(False, "%s-%s: no exit within %d s" % (tag, name, bound))
            continue
        expect(
            proc.returncode == want and (needle is None or needle in proc.stderr) and "Traceback" not in proc.stderr,
            "%s-%s: expected exit %d%s, got %r (stderr=%r)"
            % (tag, name, want, "" if needle is None else " naming %r" % needle, proc.returncode, proc.stderr[-300:]),
        )


# #6753, #6757: markup after a name fragment is tracked from its opener to its close across the
# whole paragraph (up to the next blank line), however many lines it spans; a construct that does
# not close within the paragraph and the JOIN_WINDOW cap is unresolved.
R13_FRAG1 = "docs/compliance/A.md:c:1\n"
R13_JOIN_OLD = "joins into script name `check-old.sh`"
R13_CELLS = (
    # Code review round 12 fixtures (#6753).
    ("J1-comment-3line-gt", "Conditions (c<!-- x > y\nz\n-->heck-old.sh) apply.\n", R13_FRAG1, 1, R13_JOIN_OLD),
    ("J1d-comment-4line-gt", "Conditions (c<!-- x > y\nz\nw\n-->heck-old.sh) apply.\n", R13_FRAG1, 1, R13_JOIN_OLD),
    ("J2-tag-attr-3line", 'Conditions (c<span title="a>b"\nclass="x"\n>heck-old.sh</span>) apply.\n', R13_FRAG1, 1,
     R13_JOIN_OLD),
    ("J3-link-title-3line", 'Conditions [c](x "a)\nb\n")heck-old.sh apply.\n', R13_FRAG1, 1, R13_JOIN_OLD),
    # Security review round 12 documents (#6757).
    ("S1-3line-comment", "Intro text.\n\nRun c<!-- note\nx > y\n-->heck-gone.sh now.\n", R13_FRAG1, 1, R12_JOIN),
    ("S2-3line-tag", 'Intro text.\n\nRun c<span title="a\nb>c\nd"></span>heck-gone.sh now.\n', R13_FRAG1, 1, R12_JOIN),
    ("S3-3line-comment-check", "Intro text.\n\nRun check<!-- a\nb > c\n-->-gone.sh now.\n",
     "docs/compliance/A.md:check:1\n", 1, R12_JOIN),
    ("T1-3line-html-block", "Intro text.\n\n<div>c<!-- n\nx > y\n-->heck-gone.sh</div>\n", R13_FRAG1, 1, R12_JOIN),
    ("T2-3line-in-list", "Intro text.\n\n- item c<!-- n\n  x > y\n  -->heck-gone.sh now\n", R13_FRAG1, 1, R12_JOIN),
    ("T8-3line-upper-C", "Intro text.\n\nRun C<!-- n\nx > y\n-->HECK-GONE.SH now.\n", "docs/compliance/A.md:C:1\n", 1,
     "joins into script name `CHECK-GONE.SH`"),
    ("T9-3line-check_agent", "Intro text.\n\nRun check_agent<!-- n\nx > y\n-->_action.sh now.\n",
     "docs/compliance/A.md:check_agent:1\n", 1, "joins into script name `check_agent_action.sh`"),
    ("T10-3line-ref-gt", "Intro text.\n\nRun c<!-- n\nx &gt; y > z\n-->heck-gone.sh now.\n", R13_FRAG1, 1, R12_JOIN),
    # A 3-line comment whose middle line holds '>'.
    ("P-3line-mid-gt", "Run c<!-- a\nx > y\n-->heck-gone.sh now.\n", R13_FRAG1, 1, R12_JOIN),
    # A construct that never closes within its paragraph is unresolved, also inside an HTML block
    # that GitHub continues past the blank line (it renders "Run check-gone.sh").
    ("P-never-closes", "Run c<!-- a > b\nz\n\n-->heck-gone.sh now.\n", R13_FRAG1, 1, R12_UNRESOLVED),
    ("P-never-closes-pre", "<pre>Run c<!-- a > b\n\n-->heck-gone.sh</pre>\n", R13_FRAG1, 1, R12_UNRESOLVED),
    ("P-never-closes-attr-pre", '<pre>Run c<span title="a>b\n\nz">heck-gone.sh</span></pre>\n', R13_FRAG1, 1,
     R12_UNRESOLVED),
    # A construct that closes exactly at the paragraph end: the join on its last line is red, and
    # with nothing after the close the next paragraph is not joined (green).
    ("P-closes-at-end-join", "Run c<!-- a > b\nz\n-->heck-gone.sh\n\nNext.\n", R13_FRAG1, 1, R12_JOIN),
    ("P-closes-at-end", "Run c<!-- a > b\nz\n-->\n\nheck-gone.sh now.\n", R13_FRAG1, 0, None),
    ("P-3line-control", "Run c<!-- a > b\nz\n-->x now.\n", R13_FRAG1, 0, None),
    # The JOIN_WINDOW cap fails closed: an opener whose close lies past the cap is unresolved.
    ("P-cap-paren", "Run c(x " + "y" * 600 + ")\n", R13_FRAG1, 1, R12_UNRESOLVED),
    ("P-cap-tag", 'Run c<b title="' + "y" * 600 + '"> end.\n', R13_FRAG1, 1, R12_UNRESOLVED),
    ("P-cap-tag-gt", 'Run c<b title="x>' + "y" * 600 + '">heck-gone.sh\n', R13_FRAG1, 1, R12_UNRESOLVED),
    # #6754: a fragment that ends its line, followed by a next line longer than the window whose
    # markup only reaches the name past the cut, is unresolved (the next line is truncated too).
    ("next-trunc2", "Run c\n" + "<b></b>" * 90 + "heck-old.sh daily.\n", R13_FRAG1, 1, R12_UNRESOLVED),
    # #6755: a line of exactly LINE_CEILING characters is scanned; one character more is undecidable.
    ("ceiling-exact", "x" * LINE_CEILING + "\n", "", 0, None),
    ("ceiling-exact-name", "x" * (LINE_CEILING - 13) + " check-old.sh\n", "", 1, "`check-old.sh` " + NOT_FOUND),
    ("ceiling-plus-one", "x" * (LINE_CEILING + 1) + "\n", "", 2, "line too long"),
)

# Round-13 review follow-ups: self-test cells that kill the surviving mutants of the join walk.
R14_CELLS = (
    # #6856: the rest of the paragraph is read in the fragment's own view, so a zero-width space or a
    # soft hyphen on the third line of a comment still joins the name (a raw-view read would miss it).
    ("J6856-3line-zero-width", "Run c<!-- a\nx > y\n-->h\u200beck-gone.sh now.\n", R13_FRAG1, 1, R12_JOIN),
    ("J6856-3line-soft-hyphen", "Run c<!-- a\nx > y\n-->he\u00adck-gone.sh now.\n", R13_FRAG1, 1, R12_JOIN),
)

# #6753, #6757: in-place edits of the real tree (a copy of docs/compliance and scripts next to the
# gate, allowlist unchanged) that join an allowlisted fragment into a script name across a
# construct spanning three lines. (name, document, anchor found exactly once, replacement).
R13_PLAN = "docs/compliance/_inventory/v0.7.x-code-changes-test-plan.md"
R13_ENT = "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
R13_TREE_EDITS = (
    ("T1-testplan-comment", R13_PLAN, "recommendation (c) —",
     "recommendation (c<!-- x > y\nz\n-->heck-cert-expiry.sh) —"),
    ("T3-testplan-linktitle", R13_PLAN, "recommendation (c) —",
     'recommendation [c](x "a)\nb\n")heck-cert-expiry.sh —'),
    ("ENT-c-3line-comment", R13_ENT, "never a row. (c) **NOT", "never a row. (c<!-- n\n  y > z\n  -->heck-gone.sh) **NOT"),
    ("ENT-C-3line-blockquote", R13_ENT, "and predicate (C) fails",
     "and predicate (C<!-- n\n> y > z\n> -->HECK-GONE.SH) fails"),
)


def r13_tree_cells(base, expect, skipped):
    """Copy the real docs/compliance and scripts next to the gate; each R13_TREE_EDITS edit is red (exit 1, a join)."""
    repo = Path(__file__).resolve().parent.parent
    if not (repo / "docs" / "compliance").is_dir():
        skipped.append("R13 real-tree cells (no docs/compliance next to %s)" % Path(__file__).name)
        return
    shutil.copytree(str(repo / "docs" / "compliance"), str(base / "docs" / "compliance"), symlinks=True)
    shutil.copytree(str(repo / "scripts"), str(base / "scripts"), symlinks=True)
    rc, err = run_main(base)
    expect(rc == 0, "R13-tree-control: the copied tree must be green, got %r (stderr=%r)" % (rc, err[-300:]))
    for name, rel, anchor, edit in R13_TREE_EDITS:
        path = base / rel
        original = path.read_text(encoding="utf-8")
        if original.count(anchor) != 1:
            expect(False, "R13-tree-%s: anchor %r found %d times in %s" % (name, anchor, original.count(anchor), rel))
            continue
        path.write_text(original.replace(anchor, edit), encoding="utf-8")
        try:
            rc, err = run_main(base)
        finally:
            path.write_text(original, encoding="utf-8")
        expect(
            rc == 1 and "joins into script name" in err and "Traceback" not in err,
            "R13-tree-%s: expected exit 1 naming a join, got %r (stderr=%r)" % (name, rc, err[-300:]),
        )


# The round-10 evidence cells (round10-secrev results-linux.json FAIL-OPEN at tip or base, the MANUAL
# erratum cells E1-E8, and the code-review probe_ws / probe_paren2 cells): each must exit 1.
R11_FIXTURES = (
    ('S10-L2b-00', 'Run [check-](a\x00b)old.sh daily.\n', ''),
    ('S10-L2b-01', 'Run [check-](a\x01b)old.sh daily.\n', ''),
    ('S10-L2b-02', 'Run [check-](a\x02b)old.sh daily.\n', ''),
    ('S10-L2b-03', 'Run [check-](a\x03b)old.sh daily.\n', ''),
    ('S10-L2b-04', 'Run [check-](a\x04b)old.sh daily.\n', ''),
    ('S10-L2b-05', 'Run [check-](a\x05b)old.sh daily.\n', ''),
    ('S10-L2b-06', 'Run [check-](a\x06b)old.sh daily.\n', ''),
    ('S10-L2b-07', 'Run [check-](a\x07b)old.sh daily.\n', ''),
    ('S10-L2b-08', 'Run [check-](a\x08b)old.sh daily.\n', ''),
    ('S10-L2b-0B', 'Run [check-](a\x0bb)old.sh daily.\n', ''),
    ('S10-L2b-0C', 'Run [check-](a\x0cb)old.sh daily.\n', ''),
    ('S10-L2b-0E', 'Run [check-](a\x0eb)old.sh daily.\n', ''),
    ('S10-L2b-0F', 'Run [check-](a\x0fb)old.sh daily.\n', ''),
    ('S10-L2b-10', 'Run [check-](a\x10b)old.sh daily.\n', ''),
    ('S10-L2b-11', 'Run [check-](a\x11b)old.sh daily.\n', ''),
    ('S10-L2b-12', 'Run [check-](a\x12b)old.sh daily.\n', ''),
    ('S10-L2b-13', 'Run [check-](a\x13b)old.sh daily.\n', ''),
    ('S10-L2b-14', 'Run [check-](a\x14b)old.sh daily.\n', ''),
    ('S10-L2b-15', 'Run [check-](a\x15b)old.sh daily.\n', ''),
    ('S10-L2b-16', 'Run [check-](a\x16b)old.sh daily.\n', ''),
    ('S10-L2b-17', 'Run [check-](a\x17b)old.sh daily.\n', ''),
    ('S10-L2b-18', 'Run [check-](a\x18b)old.sh daily.\n', ''),
    ('S10-L2b-19', 'Run [check-](a\x19b)old.sh daily.\n', ''),
    ('S10-L2b-1A', 'Run [check-](a\x1ab)old.sh daily.\n', ''),
    ('S10-L2b-1B', 'Run [check-](a\x1bb)old.sh daily.\n', ''),
    ('S10-L2b-1C', 'Run [check-](a\x1cb)old.sh daily.\n', ''),
    ('S10-L2b-1D', 'Run [check-](a\x1db)old.sh daily.\n', ''),
    ('S10-L2b-1E', 'Run [check-](a\x1eb)old.sh daily.\n', ''),
    ('S10-L2b-1F', 'Run [check-](a\x1fb)old.sh daily.\n', ''),
    ('S10-L2b-7F', 'Run [check-](a\x7fb)old.sh daily.\n', ''),
    ('S10-L3e-cr', 'Run [check-](<a\\\rb>)old.sh daily.\n', ''),
    ('S10-L3e-lf', 'Run [check-](<a\\\nb>)old.sh daily.\n', ''),
    ('S10-L3e-crlf', 'Run [check-](<a\\\r\nb>)old.sh daily.\n', ''),
    ('S10-L6-00', 'Run [check-](\x0bx)old.sh daily.\n', ''),
    ('S10-L6-01', 'Run [check-](x\x0b)old.sh daily.\n', ''),
    ('S10-L6-02', 'Run [check-](\x0cx)old.sh daily.\n', ''),
    ('S10-L6-03', 'Run [check-](x\x0c)old.sh daily.\n', ''),
    ('S10-L6-04', 'Run [check-](\n\x0b\nx)old.sh daily.\n', ''),
    ('S10-L6-05', 'Run [check-](\n\x0c\nx)old.sh daily.\n', ''),
    ('S10-L6-06', 'Run [check-](x\n\x0b\n)old.sh daily.\n', ''),
    ('S10-L6-07', 'Run [check-](x\n\x0b\n"t")old.sh daily.\n', ''),
    ('S10-L6-11', 'Run [check-](x \x0b\n(t))old.sh daily.\n', ''),
    ('S10-L6-12', 'Run [check-](x\r\x0b\r"t)y")old.sh daily.\n', ''),
    ('S10-L6-13', 'Run [check-](\r\n\x0b\r\nx)old.sh daily.\n', ''),
    ('S10-L6-14', 'Run [check-](x "t"\x0b)old.sh daily.\n', ''),
    ('S10-L6-15', 'Run [check-](x "t"\n\x0c\n)old.sh daily.\n', ''),
    ('S10-L7-06', 'Run [check-](x "a\\\\")b")old.sh daily.\n', ''),
    ('S10-U-00', 'Run [check-]((\n)old.sh daily.\n', ''),
    ('S10-U-01', 'Run [check-]((\x01\t)old.sh daily.\n', ''),
    ('S10-U-02', 'Run [check-](a(\t)old.sh daily.\n', ''),
    ('S10-U-03', 'Run [check-](a( )old.sh daily.\n', ''),
    ('S10-U-04', 'Run [check-](a(b )old.sh daily.\n', ''),
    ('S10-U-05', 'Run [check-]((\n"t")old.sh daily.\n', ''),
    ('S10-U-06', 'Run [check-](a(b\n)old.sh daily.\n', ''),
    ('S10-U-08', 'Run [check-](((\n)old.sh daily.\n', ''),
    ('S10-U-09', 'Run [check-](a(b(c )old.sh daily.\n', ''),
    ('S10-U-10', 'Run [check-](a\\((\t)old.sh daily.\n', ''),
    ('S10-R-00', 'Run [check-][a b]old.sh daily.\n\n[a b]: https://x\n', ''),
    ('S10-R-01', 'Run [check-][a\x0bb]old.sh daily.\n\n[a\x0bb]: https://x\n', ''),
    ('S10-R-02', 'Run [check-][a\tb]old.sh daily.\n\n[a b]: https://x\n', ''),
    ('S10-R-07', 'Run [check-][a\\[b]old.sh daily.\n\n[a\\[b]: https://x\n', ''),
    ('S10-Bcp-061C', 'Run check_new.py&#x61C; daily.\n', ''),
    ('S10-Bcpd-061C', 'Run check_new.py&#1564; daily.\n', ''),
    ('S10-Bcp-200E', 'Run check_new.py&#x200E; daily.\n', ''),
    ('S10-Bcpd-200E', 'Run check_new.py&#8206; daily.\n', ''),
    ('S10-Bcp-200F', 'Run check_new.py&#x200F; daily.\n', ''),
    ('S10-Bcpd-200F', 'Run check_new.py&#8207; daily.\n', ''),
    ('S10-Bcp-202A', 'Run check_new.py&#x202A; daily.\n', ''),
    ('S10-Bcpd-202A', 'Run check_new.py&#8234; daily.\n', ''),
    ('S10-Bcp-202B', 'Run check_new.py&#x202B; daily.\n', ''),
    ('S10-Bcpd-202B', 'Run check_new.py&#8235; daily.\n', ''),
    ('S10-Bcp-202C', 'Run check_new.py&#x202C; daily.\n', ''),
    ('S10-Bcpd-202C', 'Run check_new.py&#8236; daily.\n', ''),
    ('S10-Bcp-202D', 'Run check_new.py&#x202D; daily.\n', ''),
    ('S10-Bcpd-202D', 'Run check_new.py&#8237; daily.\n', ''),
    ('S10-Bcp-202E', 'Run check_new.py&#x202E; daily.\n', ''),
    ('S10-Bcpd-202E', 'Run check_new.py&#8238; daily.\n', ''),
    ('S10-Bcp-2066', 'Run check_new.py&#x2066; daily.\n', ''),
    ('S10-Bcpd-2066', 'Run check_new.py&#8294; daily.\n', ''),
    ('S10-Bcp-2067', 'Run check_new.py&#x2067; daily.\n', ''),
    ('S10-Bcpd-2067', 'Run check_new.py&#8295; daily.\n', ''),
    ('S10-Bcp-2068', 'Run check_new.py&#x2068; daily.\n', ''),
    ('S10-Bcpd-2068', 'Run check_new.py&#8296; daily.\n', ''),
    ('S10-Bcp-2069', 'Run check_new.py&#x2069; daily.\n', ''),
    ('S10-Bcpd-2069', 'Run check_new.py&#8297; daily.\n', ''),
    ('S10-Bf-hexlc', 'Run check_new.py&#x202e; daily.\n', ''),
    ('S10-Bf-HEX', 'Run check_new.py&#X202E; daily.\n', ''),
    ('S10-Bf-hex-lead0-6', 'Run check_new.py&#x0202E; daily.\n', ''),
    ('S10-Bf-hex-lead0-7', 'Run check_new.py&#x00202E; daily.\n', ''),
    ('S10-Bf-dec-lead0-7', 'Run check_new.py&#0008238; daily.\n', ''),
    ('S10-Bf-dec-lead0-8', 'Run check_new.py&#00008238; daily.\n', ''),
    ('S10-Bf-rlm', 'Run check_new.py&rlm; daily.\n', ''),
    ('S10-Bc-heading-hex', '# Title &#x202E; x\n', ''),
    ('S10-Bc-heading-dec', '# Title &#8238; x\n', ''),
    ('S10-Bc-setext-hex', 'Title &#x202E; x\n===\n', ''),
    ('S10-Bc-setext-dec', 'Title &#8238; x\n===\n', ''),
    ('S10-Bc-list-hex', '- item &#x202E; x\n', ''),
    ('S10-Bc-list-dec', '- item &#8238; x\n', ''),
    ('S10-Bc-olist-hex', '1. item &#x202E; x\n', ''),
    ('S10-Bc-olist-dec', '1. item &#8238; x\n', ''),
    ('S10-Bc-quote-hex', '> q &#x202E; x\n', ''),
    ('S10-Bc-quote-dec', '> q &#8238; x\n', ''),
    ('S10-Bc-html-block-hex', '<div>\nh &#x202E; x\n</div>\n', ''),
    ('S10-Bc-html-block-dec', '<div>\nh &#8238; x\n</div>\n', ''),
    ('S10-Bc-link-title-hex', '[a](x "t &#x202E;")\n', ''),
    ('S10-Bc-link-title-dec', '[a](x "t &#8238;")\n', ''),
    ('S10-Bc-image-alt-hex', '![a &#x202E;](x)\n', ''),
    ('S10-Bc-image-alt-dec', '![a &#8238;](x)\n', ''),
    ('S10-Bc-table-hex', '| a |\n|---|\n| &#x202E; |\n', ''),
    ('S10-Bc-table-dec', '| a |\n|---|\n| &#8238; |\n', ''),
    ('S10-Bc-details-summary-hex', '<details><summary>s &#x202E;</summary>\n\nb\n</details>\n', ''),
    ('S10-Bc-details-summary-dec', '<details><summary>s &#8238;</summary>\n\nb\n</details>\n', ''),
    ('S10-Bc-ref-def-title-hex', '[r]\n\n[r]: https://x "t &#x202E;"\n', ''),
    ('S10-Bc-ref-def-title-dec', '[r]\n\n[r]: https://x "t &#8238;"\n', ''),
    ('S10-E1-top-fence-3sp-closer', 'N30 enforcer is `check-old.sh`.\n\n<details>\n\n   ```\n</details>\n   ```\n\nErratum (#1): `check-old.sh` is `scripts/check_new.py`.\n', 'docs/compliance/A.md:check-old.sh:2\n'),
    ('S10-E2-top-fence-1sp-closer', 'N30 enforcer is `check-old.sh`.\n\n<details>\n\n ```\n</details>\n ```\n\nErratum (#1): `check-old.sh` is `scripts/check_new.py`.\n', 'docs/compliance/A.md:check-old.sh:2\n'),
    ('S10-E3-top-fence-3sp-erratum', 'N30 enforcer is `check-old.sh`.\n\n   ```\nx\n\nErratum (#1): `check-old.sh` is `scripts/check_new.py`.\n   ```\n', 'docs/compliance/A.md:check-old.sh:2\n'),
    ('S10-E4-top-tilde-2sp-closer', 'N30 enforcer is `check-old.sh`.\n\n<details>\n\n  ~~~\n</details>\n  ~~~\n\nErratum (#1): `check-old.sh` is `scripts/check_new.py`.\n', 'docs/compliance/A.md:check-old.sh:2\n'),
    ('S10-E5-list-fence-closer', 'N30 enforcer is `check-old.sh`.\n\n<details>\n\n- a\n  ```\n</details>\n  ```\n\nErratum (#1): `check-old.sh` is `scripts/check_new.py`.\n', 'docs/compliance/A.md:check-old.sh:2\n'),
    ('S10-E6-control-closed', 'N30 enforcer is `check-old.sh`.\n\n<details>\n\nx\n\n</details>\n\nErratum (#1): `check-old.sh` is `scripts/check_new.py`.\n', 'docs/compliance/A.md:check-old.sh:2\n'),
    ('S10-E7-top-fence-3sp-comment', 'N30 enforcer is `check-old.sh`.\n\n   ```\n<!--\n   ```\n\nErratum (#1): `check-old.sh` is `scripts/check_new.py`.\n-->\n', 'docs/compliance/A.md:check-old.sh:2\n'),
    ('S10-E8-quote-fence-closer', 'N30 enforcer is `check-old.sh`.\n\n<details>\n\n> ```\n</details>\n> ```\n\nErratum (#1): `check-old.sh` is `scripts/check_new.py`.\n', 'docs/compliance/A.md:check-old.sh:2\n'),
    ('S10-X-001', 'Run [check-](\t\x0b\t\n )old.sh daily.\n', ''),
    ('S10-X-002', 'Run [check-](>\x0b\\")old.sh daily.\n', ''),
    ('S10-X-008', 'Run [check-](\x7f\x7fb\x7f\x0c>\xa0)old.sh daily.\n', ''),
    ('S10-X-010', 'Run [check-](\\"]\\\\a\x00``)old.sh daily.\n', ''),
    ('S10-X-015', 'Run [check-](\x7f"\x00>\x0c)old.sh daily.\n', ''),
    ('S10-X-022', "Run [check-](\x00\x00')old.sh daily.\n", ''),
    ('S10-X-026', 'Run [check-](\\"\x00\\")old.sh daily.\n', ''),
    ('S10-X-027', 'Run [check-](\\"\\ab\\a\x00\\a\\ )old.sh daily.\n', ''),
    ('S10-X-028', 'Run [check-](\r\x0b\r\\\n)old.sh daily.\n', ''),
    ('S10-X-030', 'Run [check-](&#41;\\(\\(]``\x0b\\(")old.sh daily.\n', ''),
    ('S10-X-032', 'Run [check-](\x0c&lt;\\(\\")old.sh daily.\n', ''),
    ('S10-X-034', "Run [check-](a\\)'\x7f&lt;\r)old.sh daily.\n", ''),
    ('S10-X-036', 'Run [check-](\t\x7f\\a\xa0)old.sh daily.\n', ''),
    ('S10-X-039', 'Run [check-](\x0ca\\\n )old.sh daily.\n', ''),
    ('S10-X-047', 'Run [check-](\n\u2028\x7f&#41;)old.sh daily.\n', ''),
    ('S10-X-049', 'Run [check-](\\)\\\\(\\\n)old.sh daily.\n', ''),
    ('S10-X-056', 'Run [check-](\x7f \x0c\x0c)old.sh daily.\n', ''),
    ('S10-X-068', 'Run [check-](\x0b)old.sh daily.\n', ''),
    ('S10-X-074', "Run [check-](&lt;'\x0c&#41;a\x7f)old.sh daily.\n", ''),
    ('S10-X-079', 'Run [check-](\ra]\x0b\xa0&#41;\\aa)old.sh daily.\n', ''),
    ('S10-X-100', 'Run [check-](\\)]\x00\\(``\\"\')old.sh daily.\n', ''),
    ('S10-X-102', 'Run [check-](\n\x0b)old.sh daily.\n', ''),
    ('S10-X-112', 'Run [check-](\xa0\xa0\x7f)old.sh daily.\n', ''),
    ('S10-X-115', 'Run [check-](&lt;\\(a\x00\\ \t\t)old.sh daily.\n', ''),
    ('S10-X-116', 'Run [check-](]\xa0b]]\x0c)old.sh daily.\n', ''),
    ('S10-X-120', 'Run [check-](\xa0a\x7f])old.sh daily.\n', ''),
    ('S10-X-129', 'Run [check-](\x0c``)old.sh daily.\n', ''),
    ('S10-X-133', 'Run [check-](\r``\\((\t)old.sh daily.\n', ''),
    ('S10-X-148', 'Run [check-](\\a\x0c\\))old.sh daily.\n', ''),
    ('C10-ws-00', 'Run [check-](<a>\x0b)old.sh daily.\n', ''),
    ('C10-ws-01', 'Run [check-](<a>\x0c)old.sh daily.\n', ''),
    ('C10-ws-02', 'Run [check-](<a>\x0b"t")old.sh daily.\n', ''),
    ('C10-ws-03', 'Run [check-](a\x0b"t")old.sh daily.\n', ''),
    ('C10-ws-04', 'Run [check-](a\x0c"t")old.sh daily.\n', ''),
    ('C10-ws-05', 'Run [check-](\x0ba)old.sh daily.\n', ''),
    ('C10-ws-06', 'Run [check-](\x0c<a>)old.sh daily.\n', ''),
    ('C10-ws-07', 'Run [check-](<a> "t"\x0b)old.sh daily.\n', ''),
    ('C10-ws-08', 'Run [check-](a\x0b"t)")old.sh daily.\n', ''),
    ('C10-ws-09', "Run [check-](a\x0c'x)y')old.sh daily.\n", ''),
    ('C10-ws-10', 'Run [check-](<a\x0bb>)old.sh daily.\n', ''),
    ('C10-ws-11', 'Run [check-](a\x0b(t))old.sh daily.\n', ''),
    ('C10-paren-02', 'Run [check-]((\\ )old.sh daily.\n', ''),
    ('C10-paren-03', 'Run [check-]((\\a )old.sh daily.\n', ''),
    ('C10-paren-04', 'Run [check-]((a\x01\\ )old.sh daily.\n', ''),
    ('C10-paren-05', 'Run [check-]( (\x01\n)\n))old.sh daily.\n', ''),
    ('C10-paren-06', 'Run [check-]((t )old.sh daily.\n', ''),
)


def self_test():
    scratch = Path(__file__).resolve().parent.parent / ".local-runs"
    scratch.mkdir(exist_ok=True)
    fails = []

    def expect(cond, msg):
        if not cond:
            fails.append(msg)

    skipped = []
    euid = getattr(os, "geteuid", lambda: "n/a")()

    with tempfile.TemporaryDirectory(dir=str(scratch)) as d:
        root = Path(d)
        cells = root / "r11"
        cells.mkdir()
        r11_cells(cells, R11_CELLS, expect)
        cells12 = root / "r12"
        cells12.mkdir()
        r11_cells(cells12, R12_CELLS, expect, "R12")
        timed = root / "r12-timed"
        timed.mkdir()
        r12_timed_cells(timed, expect)
        timed13 = root / "r13-timed"
        timed13.mkdir()
        r12_timed_cells(timed13, expect, R13_TIMED, R13_TIME_BOUND, "R13")
        cells13 = root / "r13"
        cells13.mkdir()
        r11_cells(cells13, R13_CELLS, expect, "R13")
        cells14 = root / "r14"
        cells14.mkdir()
        r11_cells(cells14, R14_CELLS, expect, "R14")
        tree13 = root / "r13-tree"
        tree13.mkdir()
        r13_tree_cells(tree13, expect, skipped)
        # Every cell the round-10 evidence found fail-open (any tip or base) is red (design B, item 7).
        fixtures = root / "r11-fixtures"
        fixtures.mkdir()
        r11_cells(fixtures, tuple((n, doc, allow, 1, None) for n, doc, allow in R11_FIXTURES), expect)

        def fresh(name):
            r = root / name
            (r / "scripts" / "qc-allowlists").mkdir(parents=True)
            (r / "docs" / "compliance").mkdir(parents=True)
            (r / "scripts" / "check_new.py").write_text("")
            (r / ALLOW_REL).write_text("")
            return r

        def try_symlink(link, target, label):
            try:
                link.symlink_to(target)
            except OSError as exc:
                skipped.append("%s (symlink unsupported: %s)" % (label, exc))
                return False
            return True

        def denied_rc(target, sroot, label, needle):
            mode = target.stat().st_mode & 0o7777
            target.chmod(0)
            try:
                if os.access(str(target), os.R_OK):
                    skipped.append("%s (chmod 000 does not deny access to euid %s)" % (label, euid))
                    return
                rc, err = run_main(sroot)
            finally:
                target.chmod(mode)
            expect(
                rc == 2 and needle in err,
                "%s: expected exit 2 with %r, got %r (stderr=%r)" % (label, needle, rc, err),
            )

        stale_line = "N30 enforcer is `check-old.sh`.\n"
        # #6169: an unreadable directory, document or allowlist in the scan set exits 2, never 'ok'.
        r = fresh("u-dir")
        (r / "docs" / "compliance" / "locked").mkdir()
        (r / "docs" / "compliance" / "locked" / "X.md").write_text(stale_line)
        denied_rc(r / "docs" / "compliance" / "locked", r, "#6169-dir", "docs/compliance/locked: unreadable")
        r = fresh("u-file")
        (r / "docs" / "compliance" / "C.md").write_text(stale_line)
        denied_rc(r / "docs" / "compliance" / "C.md", r, "#6169-file", "docs/compliance/C.md: unreadable")
        r = fresh("u-allow")
        denied_rc(r / "scripts" / "qc-allowlists", r, "#6169-allowlist", ALLOW_REL + ": unreadable")
        r = fresh("u-missing")
        (r / "docs" / "compliance").rmdir()
        rc, err = run_main(r)
        expect(
            rc == 2 and "docs/compliance: unreadable" in err,
            "#6169-missing: missing docs/compliance: expected exit 2, got %r (stderr=%r)" % (rc, err),
        )

        # #6197: '.MD' documents are scanned; symlinked directories and escaping document symlinks are refused.
        r = fresh("s-md")
        (r / "docs" / "compliance" / "N.MD").write_text(stale_line)
        (r / "docs" / "compliance" / "M.Md").write_text(stale_line)
        (r / "docs" / "compliance" / "T.txt").write_text(stale_line)
        probs = check(r)
        expect(any("N.MD" in p and "check-old.sh" in p for p in probs), "#6197-MD: stale name in a .MD document was accepted")
        expect(any("M.Md" in p and "check-old.sh" in p for p in probs), "#6197-Md: stale name in a .Md document was accepted")
        expect(not any("T.txt" in p for p in probs), "#6197-txt: a non-Markdown file was scanned")
        r = fresh("s-link")
        (r / "elsewhere").mkdir()
        (r / "elsewhere" / "X.md").write_text(stale_line)
        if try_symlink(r / "docs" / "compliance" / "linked", r / "elsewhere", "#6197-dir"):
            expect(
                any("docs/compliance/linked" in p and "symlinked directory" in p for p in check(r)),
                "#6197-dir: a symlinked subdirectory was not refused",
            )
        r = fresh("s-top")
        (r / "docs" / "compliance").rmdir()
        (r / "real").mkdir()
        (r / "real" / "X.md").write_text(stale_line)
        if try_symlink(r / "docs" / "compliance", r / "real", "#6197-top"):
            expect(
                any("docs/compliance" in p and "symlinked directory" in p for p in check(r)),
                "#6197-top: a symlinked docs/compliance was not refused",
            )
        r = fresh("s-escape")
        (root / "ext.md").write_text("Nothing stale here.\n")
        if try_symlink(r / "docs" / "compliance" / "E.md", root / "ext.md", "#6197-escape"):
            expect(
                any("E.md" in p and "outside the repository" in p for p in check(r)),
                "#6197-escape: a document symlink leaving the repository was not refused",
            )
        r = fresh("s-inside")
        (r / "notes.md").write_text(stale_line)
        if try_symlink(r / "docs" / "compliance" / "I.md", r / "notes.md", "#6197-inside"):
            expect(
                any("I.md" in p and "check-old.sh" in p for p in check(r)),
                "#6197-inside: a document symlink inside the repository was not scanned",
            )
        # #6217: a document symlink loop is reported as a loop.
        r = fresh("s-loop")
        if try_symlink(r / "docs" / "compliance" / "L1.md", r / "docs" / "compliance" / "L2.md", "#6217") and try_symlink(
            r / "docs" / "compliance" / "L2.md", r / "docs" / "compliance" / "L1.md", "#6217"
        ):
            probs = check(r)
            expect(
                any("L1.md: document symlink loop (refused)" in p for p in probs)
                and not any("outside the repository" in p for p in probs),
                "#6217: a symlink loop was not reported as a loop (%r)" % (probs,),
            )

        # #6198: a cited name resolves only to that exact path under scripts/, contained in scripts/.
        r = fresh("p-paths")
        doc = r / "docs" / "compliance" / "A.md"
        (r / "outside.py").write_text("")
        (r / "check-gone.sh").write_text("")
        (r / "scripts" / "check-dir.sh").mkdir()
        (r / "scripts" / "fixtures").mkdir()
        (r / "scripts" / "fixtures" / "check-nest.sh").write_text("")
        (r / "scripts" / "sub").mkdir()
        (r / "scripts" / "sub" / "check_sub.py").write_text("")
        (r / "infra").mkdir()
        (r / "infra" / "check_infra.py").write_text("")
        for cited in ("check-nest.sh", "check-gone.sh", "check-dir.sh", "scripts/SUB/check_sub.py"):
            doc.write_text("N30 enforcer is `%s`.\n" % cited)
            expect(any("`%s` does not exist" % cited in p for p in check(r)), "#6198: `%s` resolved" % cited)
        doc.write_text(
            "Runs `scripts/sub/check_sub.py`, `scripts/fixtures/check-nest.sh` and `infra/check_infra.py`.\n"
        )
        expect(not check(r), "#6198/#6216: an exact existing path was rejected")
        if try_symlink(r / "scripts" / "check-esc.sh", r / "outside.py", "#6198-escape"):
            doc.write_text("N30 enforcer is `check-esc.sh`.\n")
            expect(any("check-esc.sh" in p for p in check(r)), "#6198-escape: a symlink escaping scripts/ resolved")
            (r / "scripts" / "check-esc.sh").unlink()
        if try_symlink(r / "scripts" / "check-alias.sh", r / "scripts" / "check_new.py", "#6198-alias"):
            doc.write_text("N30 enforcer is `check-alias.sh`.\n")
            expect(not check(r), "#6198-alias: a symlink inside scripts/ was rejected")
            (r / "scripts" / "check-alias.sh").unlink()
        if try_symlink(r / "scripts" / "check_link.py", r / "outside.py", "#6198-successor"):
            doc.write_text(R11_ERR.replace("scripts/check_new.py", "scripts/check_link.py") + stale_line)
            (r / ALLOW_REL).write_text("docs/compliance/A.md:check-old.sh:2\n")
            expect(any("check-old.sh" in p for p in check(r)), "#6198-successor: an escaping successor symlink was accepted")
            (r / ALLOW_REL).write_text("")

        # P7, Y3, Y4: a resolve() error other than a loop fails closed under its own message.
        real_resolve = Path.resolve

        def check_with_resolve(r, name, exc):
            def resolve(self, *args, **kwargs):
                if self.name == name:
                    raise exc
                return real_resolve(self, *args, **kwargs)

            Path.resolve = resolve
            try:
                return check(r)
            except Exception as err:  # an escaped exception is the failure being probed
                return ["raised %s" % type(err).__name__]
            finally:
                Path.resolve = real_resolve

        r = fresh("r-runtime")
        (r / "docs" / "compliance" / "A.md").write_text("Runs `scripts/check_new.py`.\n")
        probs = check_with_resolve(r, "check_new.py", RuntimeError("Symlink loop"))
        expect(any("check_new.py" in p and "does not exist" in p for p in probs),
               "P7: a RuntimeError from resolve() in path_ok did not fail closed (%r)" % (probs,))
        r = fresh("r-unresolvable")
        (r / "docs" / "compliance" / "real.md").write_text("No script names.\n")
        if try_symlink(r / "docs" / "compliance" / "U.md", r / "docs" / "compliance" / "real.md", "Y3"):
            probs = check_with_resolve(r, "U.md", OSError(errno.EIO, "I/O error"))
            expect(
                any("U.md: document symlink cannot be resolved" in p for p in probs)
                and not any("outside the repository" in p for p in probs),
                "Y3/Y4: an unresolvable document symlink was not refused as such (%r)" % (probs,),
            )

        # #6220 on a case-sensitive runner: emulate a case-insensitive filesystem, so only the
        # exact-name listing walk can reject a case variant of a file or directory.
        real_is_file = Path.is_file

        def ci_is_file(self, *args, **kwargs):
            cur = Path(Path(os.path.abspath(str(self))).anchor)
            for part in Path(os.path.abspath(str(self))).parts[1:]:
                try:
                    hit = [n for n in os.listdir(str(cur)) if n.lower() == part.lower()]
                except OSError:
                    return False
                if not hit:
                    return False
                cur = cur / hit[0]
            return real_is_file(cur)

        r = fresh("ci-case")
        (r / "scripts" / "sub").mkdir()
        (r / "scripts" / "sub" / "check_sub.py").write_text("")
        (r / "docs" / "compliance" / "A.md").write_text("Runs `check_NEW.py` and `scripts/SUB/check_sub.py`.\n")
        Path.is_file = ci_is_file
        try:
            probs = check(r)
        finally:
            Path.is_file = real_is_file
        expect(any("check_NEW.py" in p for p in probs) and any("scripts/SUB/check_sub.py" in p for p in probs),
               "#6220: on an emulated case-insensitive filesystem a case variant resolved (%r)" % (probs,))

        # #6353: an allowlist that exists but cannot be stat'ed is unreadable (exit 2), never absent.
        r = fresh("u-allow-loop")
        (r / ALLOW_REL).unlink()
        if try_symlink(r / ALLOW_REL, r / ALLOW_REL, "#6353-loop"):
            rc, err = run_main(r)
            expect(rc == 2 and ALLOW_REL + ": unreadable" in err,
                   "#6353-loop: allowlist symlink loop: expected exit 2, got %r (stderr=%r)" % (rc, err))
        # A path that exists but is not a regular file holds no entries: the stale name is reported (exit 1).
        r = fresh("u-allow-dir")
        (r / ALLOW_REL).unlink()
        (r / ALLOW_REL).mkdir()
        (r / "docs" / "compliance" / "A.md").write_text(stale_line)
        rc, err = run_main(r)
        expect(rc == 1 and "check-old.sh" in err,
               "#6353-dir: a directory at the allowlist path: expected exit 1, got %r (stderr=%r)" % (rc, err))

        # Design B, item 5: an internal error exits 2 with one FAIL line, never a traceback.
        r = fresh("internal")
        real_docs = globals()["compliance_docs"]

        def broken(_root):
            raise ValueError("probe")

        globals()["compliance_docs"] = broken
        try:
            rc, err = run_main(r)
        finally:
            globals()["compliance_docs"] = real_docs
        expect(rc == 2 and "FAIL internal error: ValueError: probe" in err and "Traceback" not in err,
               "internal error: expected exit 2 with 'FAIL internal error', got %r (stderr=%r)" % (rc, err))

        # #6199: a fixture setup failure exits 2 with 'SELF-TEST FAIL: fixture setup', never a traceback.
        gate_src = Path(__file__).read_text(encoding="utf-8")

        def child_self_test(name, prepare):
            c = root / name
            (c / "scripts").mkdir(parents=True)
            (c / "scripts" / "check_compliance_script_names.py").write_text(gate_src, encoding="utf-8")
            undo = prepare(c / ".local-runs")
            if undo is None:
                return None
            try:
                return subprocess.run(
                    [sys.executable, "-I", str(c / "scripts" / "check_compliance_script_names.py"), "--self-test"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            finally:
                undo()

        def as_file(path):
            path.write_text("not a directory\n")
            return lambda: None

        def read_only(path):
            path.mkdir()
            path.chmod(0o555)
            if os.access(str(path), os.W_OK):
                path.chmod(0o755)
                skipped.append("#6199-readonly (chmod 555 does not deny writes to euid %s)" % euid)
                return None
            return lambda: path.chmod(0o755)

        for label, prepare in (("file", as_file), ("readonly", read_only)):
            res = child_self_test("c-" + label, prepare)
            if res is None:
                continue
            expect(
                res.returncode == 2 and "SELF-TEST FAIL: fixture setup" in res.stderr and "Traceback" not in res.stderr,
                "#6199-%s: .local-runs unusable: expected exit 2 with 'fixture setup', got %r (stderr=%r)"
                % (label, res.returncode, res.stderr[-300:]),
            )
    for note in skipped:
        print("self-test: skipped %s" % note)
    return "; ".join(fails) if fails else None


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        try:
            err = self_test()
        except (OSError, Unreadable) as exc:
            # A scratch or fixture I/O failure is a self-test failure (exit 2), not a violation (#6199).
            err = "fixture setup: %s: %s" % (type(exc).__name__, exc)
        except Exception as exc:  # any other escape is a self-test failure, never a traceback
            err = "internal error: %s: %s" % (type(exc).__name__, exc)
        if err:
            print("SELF-TEST FAIL: " + err, file=sys.stderr)
            return 2
        print("self-test ok")
        return 0
    try:
        problems = check(Path(args.root))
    except Unreadable as exc:
        print("FAIL %s: unreadable" % exc.path, file=sys.stderr)
        return 2
    except LineTooLong as exc:
        print(
            "FAIL %s:%d: line too long, undecidable (%d characters; the ceiling is %d)"
            % (exc.rel, exc.lineno, exc.length, LINE_CEILING),
            file=sys.stderr,
        )
        return 2
    except Exception as exc:  # undecidable: never a traceback, never green (design B, item 5)
        print("FAIL internal error: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 2
    for p in problems:
        print("FAIL " + p, file=sys.stderr)
    if problems:
        return 1
    print("compliance script-name anchors ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
