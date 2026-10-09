#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Compliance-document script-name anchor gate (#6141).

The adopted certification texts under ``docs/compliance/`` are verbatim copies
of a reviewed source and cannot be edited in place, so a script rename leaves
the normative text naming a file that no longer exists (#6137 ported
``check-cert-expiry.sh`` to ``check_cert_expiry.py``; #6141).

Rule: every ``check-*.sh`` / ``check_*.py`` script name in a
``docs/compliance/*.md`` file must resolve to the exact file it names under
``scripts/``, unless BOTH hold (below). A name is found anywhere on a line,
bounded by non-name characters: in or out of backticks, in a fenced block, after
a command (``bash scripts/...``) or a path (``./scripts/...``, a URL), after
invisible characters (category Cf and every Default_Ignorable_Code_Point) are removed
from document lines (#6195). Each line is also scanned as a reader sees it after
rendering (#6214): escapes, entities, inline tags and comments, emphasis markers, dash
variants, combining marks and look-alike letters folded, so a backslash-escaped
hyphen, ``check&#45;x.sh`` or a Cyrillic look-alike letter cannot hide a name.
Names match in any ASCII letter case, and existence is decided by exact names from
directory listings, the same on case-insensitive filesystems (#6220).
A bare name means ``scripts/<name>``. A written path is checked at that path
from the repository root (#6216): leading ``/``, ``.`` and ``..`` components and a
URL's host part are dropped only when ``scripts`` follows, so ``./scripts/x``,
``../../scripts/x`` and a repository URL name ``scripts/x``, while
``infra/check-x.py`` names ``infra/check-x.py`` and ``./check-x.sh`` names no
file. ``scripts/sub/check-x.sh`` names that file, never a same-named file
elsewhere, and a symlink counts only when it resolves inside ``scripts/`` (or,
for a path outside ``scripts/``, inside the repository) (#6198). The allowlist is read strictly (no Cf removal).

1. an erratum line somewhere in ``docs/compliance/`` names it together with an
   existing successor (``scripts/<name>``). An erratum line has one form, the one a
   rendered document always shows (#6196, #6219; 5-agent vote 4d3ea1c5): it starts
   ``Erratum (#<issue>): `` at column 0 and begins a paragraph, outside any fenced or
   ``$$`` block, raw HTML block, HTML comment, processing instruction, CDATA section,
   declaration or tag, with no ``[`` or ``]`` outside code spans (``erratum_lines``).
   Its text, without unrendered raw HTML, names the stale name and the successor in
   backticks. The successor must resolve inside ``scripts/``: a
   ``..`` or ``.`` component, or a symlink escaping ``scripts/``, is rejected.
2. the ``<relative-doc-path>:<stale-name>`` pair is listed in
   ``scripts/qc-allowlists/compliance-script-names-allow.txt``. The allowlist
   is a burn-down ledger of the documents that carry a historical mention
   today (a stale entry that suppresses nothing, a duplicate entry, or a
   malformed entry fails). An erratum therefore never clears the stale name in
   a document written later.

An allowlisted pair is honoured only while the document ITSELF carries an
erratum line for that name (#6170), so deleting the erratum from one document
fails the gate even when another document still carries one. The only
exception is an entry marked ``<doc>:<name>:pinned``, honoured while an erratum
for the name exists in any ``docs/compliance/`` document. ``:pinned`` is a
closed set (#6173): ``PINNABLE_DOCS`` holds exactly the two documents that
cannot carry an erratum, ``v1.0.0-DECLARATION.md`` (SHA-256 pinned) and
``ENTERPRISE-FEDERATION-CERTIFICATION.md`` (cert section 7 gate). A ``:pinned``
entry for any other document is a violation, and so is a ``:pinned`` entry for
a document that carries its own erratum for that name ("unnecessary :pinned").

Scan set (#6169, #6197): every ``*.md`` file under ``docs/compliance/``, extension
matched in any case. A directory that cannot be listed, an unreadable document or
allowlist, or a missing ``docs/compliance/`` exits 2; nothing is skipped silently.
Symlinked directories (``docs/compliance/`` itself included) are refused, never
followed, and a document symlink that resolves outside the repository, forms a loop
(#6217) or cannot be resolved is refused; each is a violation reported as what it is.
A document symlink inside the repository is scanned.

Usage:
    python3 -I scripts/check_compliance_script_names.py [--root DIR]
    python3 -I scripts/check_compliance_script_names.py --self-test

Exit codes: 0 green, 1 violation(s) found, 2 usage error, self-test failure
(including ``SELF-TEST FAIL: fixture setup: ...`` when ``.local-runs`` is unusable),
or an unreadable (non-UTF-8 / I/O error) compliance document, directory or
allowlist.
"""

import argparse
import contextlib
import errno
import html
import io
import os
import re
import string
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

# A script name anywhere on a line, bounded by non-name characters (#6195): inside or outside
# backticks, in a fenced block, after a command or a path prefix.
# Matched in any ASCII letter case (#6220): CHECK-x.sh and check_x.PY name scripts too. re.ASCII
# keeps IGNORECASE from folding the Kelvin sign or long s into ASCII letters.
TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(check[-_][A-Za-z0-9_-]+\.(?:sh|py))(?![A-Za-z0-9_])", re.IGNORECASE | re.ASCII
)
PATH_CHARS = frozenset(string.ascii_letters + string.digits + "_./-")
SUCCESSOR_RE = re.compile(r"`scripts/([A-Za-z0-9_./-]+\.(?:sh|py))`")
ALLOW_REL = "scripts/qc-allowlists/compliance-script-names-allow.txt"
# Rendering folds for stale-name detection (#6214): inline HTML tags and comments, Markdown
# backslash escapes, dash variants, and letters that render like ASCII (a small explicit table:
# the Cyrillic, Greek and Armenian look-alikes of the letters a script name can use).
INLINE_TAG_RE = re.compile(r"<[^<>]*>")
ESCAPE_RE = re.compile(r"\\([!-/:-@\[-`{-~])")
DASHES = frozenset("\u02d7\u2043\u2212\u2796\ufe63\uff0d")
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
# A CommonMark fence line: up to three spaces, then three or more backticks or tildes (#6215).
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
# Raw HTML that GitHub renders as nothing (#6196): a comment, a CDATA section, a processing
# instruction and a declaration (``<!`` and a letter) end at their closer; a tag (``<`` and a
# letter or ``/``) hides its own markup, attribute values included, to its first ``>`` outside
# quotes. Hiding more than GitHub does only fails closed.
HIDDEN_HTML_RE = re.compile(r"<!--|<!\[CDATA\[|<\?|<![A-Za-z]|<[A-Za-z/]")
HIDDEN_HTML_CLOSERS = {"<!--": "-->", "<![CDATA[": "]]>", "<?": "?>"}
# The one erratum form (#6196, #6219; 5-agent vote 4d3ea1c5): a line starting with this at column 0.
ERRATUM_RE = re.compile(r"Erratum \(#[1-9][0-9]*\): ")
# A line opening a raw HTML block (CommonMark types 1, 6, 7; over-approximated: any tag at the start
# of a line). Inside one, backticks are raw text and protect nothing (#6196). A RAW_TEXT_TAGS block
# runs to its closing tag, any other to the next blank line.
HTML_BLOCK_RE = re.compile(r"^ {0,3}<(/?)([A-Za-z][A-Za-z0-9-]*)")
RAW_TEXT_TAGS = frozenset({"pre", "script", "style", "textarea"})
# A line that is only ``$$`` opens or closes a display-math block, rendered as math (#6196).
MATH_FENCE = "$$"
# Appended to a violation when a line names the stale name and a successor with the word
# "erratum" but is not in the erratum form (#6238).
NEAR_HINT = (
    "; line %d is not an erratum (an erratum line starts `Erratum (#<issue>): ` at column 0,"
    " begins a paragraph and is shown as text with no [ or ] outside code spans)"
)
ENTRY_RE = re.compile(
    r"^(docs/compliance/\S+\.md):((?i:check)[-_][A-Za-z0-9_-]+\.(?i:sh|py))(:pinned)?$", re.ASCII
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
# standard library has no lookup for this property (#6195). It includes the members outside
# category Cf: variation selectors, U+034F, Hangul fillers, Khmer inherent vowels, Mongolian free
# variation selectors, and the reserved ranges a later Unicode version may assign as invisible.
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


class Unreadable(Exception):
    """A compliance document or the allowlist could not be read as UTF-8."""

    def __init__(self, path):
        super().__init__(str(path))
        self.path = path


def read_text(root, path):
    """Read ``path`` as UTF-8, mapping I/O and decode errors to Unreadable."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise Unreadable(path.relative_to(root))


def invisible(c):
    """True for a character a reader does not see: category Cf or Default_Ignorable_Code_Point."""
    if unicodedata.category(c) == "Cf":
        return True
    cp = ord(c)
    return any(lo <= cp <= hi for lo, hi in DEFAULT_IGNORABLE)


def doc_lines(root, path):
    """A document's lines with invisible characters removed (#6195).

    A reader does not see a soft hyphen, a zero-width space or joiner, a BOM, a variation
    selector or a Hangul filler (category Cf plus Default_Ignorable_Code_Point), so the gate
    must not either. Only documents are normalised; the allowlist stays strict.
    """
    text = read_text(root, path)
    return "".join(c for c in text if not invisible(c)).splitlines()


def rendered(line):
    """``line`` as a reader sees it, folded for stale-name detection only (#6214).

    Inline tags and comments removed, entities decoded, backslash escapes dropped, NFKC
    (fullwidth and other compatibility forms), every dash folded to ``-``, combining and
    invisible marks removed, look-alike letters mapped to ASCII, emphasis and strikethrough
    markers (``*``, ``~``) dropped. Its tokens are scanned in addition to the line's own, so
    this can only add findings; errata are still read from the unfolded visible text.
    """
    s = ESCAPE_RE.sub(r"\1", html.unescape(INLINE_TAG_RE.sub("", line)))
    s = unicodedata.normalize("NFKC", s)
    s = "".join("-" if c in DASHES or unicodedata.category(c) == "Pd" else c for c in s)
    s = "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) not in ("Mn", "Me"))
    s = "".join(c for c in s if not invisible(c)).translate(LOOKALIKES)
    return s.replace("*", "").replace("~", "")


def tokens(line):
    """Yield (cited, name, target) for each script name on ``line`` (#6195, #6198, #6216).

    ``cited`` is the name with the path written before it, ``name`` the bare script name (the
    allowlist and erratum key) and ``target`` the root-relative path the citation names. A bare
    name is ``scripts/<name>`` (``check-x.sh`` and ``bash scripts/check-x.sh`` alike). A written
    path is taken as written, except that its leading ``''``/``.``/``..`` components, or a URL's
    host and path (a prefix starting ``//``), are dropped when a ``scripts`` component follows
    them: ``./scripts/check-x.sh`` and ``../../scripts/check-x.sh`` name ``scripts/check-x.sh``,
    ``tools/scripts/check-x.sh`` and ``infra/check-x.sh`` name themselves, and ``./check-x.sh``
    keeps its ``.`` component, which names no file.
    """
    for m in TOKEN_RE.finditer(line):
        start = m.start()
        while start > 0 and line[start - 1] in PATH_CHARS:
            start -= 1
        prefix = line[start : m.start()]
        parts = prefix.split("/")[:-1] if prefix else ["scripts"]
        if "scripts" in parts:
            first = parts.index("scripts")
            if prefix.startswith("//") or all(p in ("", ".", "..") for p in parts[:first]):
                parts = parts[first:]
        yield prefix + m.group(1), m.group(1), "/".join(parts + [m.group(1)])


def path_ok(root, target):
    """True when the root-relative ``target`` is exactly a file contained where it claims (#6216).

    No ``.``/``..``/empty component, every component present under that exact name in its parent's
    directory listing (#6220: a case-insensitive filesystem cannot turn ``CHECK-x.sh`` or
    ``scripts/SUB/`` into an existing file), a regular file at that exact path (no basename
    search), and a symlink only when it resolves inside scripts/ for a ``scripts/...`` target,
    else inside the repository.
    """
    parts = target.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    path = root.joinpath(*parts)
    base = root / "scripts" if parts[0] == "scripts" else root
    try:
        parent = root
        for part in parts:
            if part not in os.listdir(str(parent)):
                return False
            parent = parent / part
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


def compliance_docs(root):
    """Return (docs, problems) for the scan set: every ``*.md`` (any case) under docs/compliance/.

    The walk never skips silently (#6169, #6197). A directory that cannot be listed, or a missing
    docs/compliance/, raises Unreadable (exit 2). Symlinked directories, docs/compliance/ itself
    included, are refused and never followed: following one would scan documents outside the
    reviewed tree and admit cycles, and a git checkout of this tree contains none. A symlinked
    document is read only when it resolves inside the repository; one that leaves it is refused.
    """
    top = root / "docs" / "compliance"
    if os.path.islink(str(top)):
        return [], ["%s: symlinked directory refused (not scanned)" % rel_path(root, top)]

    def unlistable(err):
        raise Unreadable(rel_path(root, err.filename if err.filename else top))

    docs, problems = [], []
    real_root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(str(top), onerror=unlistable):
        for name in dirnames:
            if os.path.islink(os.path.join(dirpath, name)):
                problems.append(
                    "%s: symlinked directory refused (not scanned)" % rel_path(root, Path(dirpath) / name)
                )
        for name in filenames:
            if not name.lower().endswith(".md"):
                continue
            path = Path(dirpath) / name
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
    return sorted(docs), problems


def backtick_run(line, i):
    """Length of the run of backticks starting at ``line[i]``."""
    n = i
    while n < len(line) and line[n] == "`":
        n += 1
    return n - i


def next_tick(line, i):
    """Index of the first backtick at or after ``i`` not escaped by a backslash, else -1 (#6196).

    A backtick after an odd number of backslashes is literal text and opens no code span.
    """
    while True:
        tick = line.find("`", i)
        if tick < 0:
            return tick
        k = tick
        while k > i and line[k - 1] == "\\":
            k -= 1
        if (tick - k) % 2 == 0:
            return tick
        i = tick + 1


def code_span_end(line, tick):
    """Index after the code span opened by the backtick run at ``tick``, or -1 when it is unclosed."""
    n = backtick_run(line, tick)
    j = tick + n
    while True:
        j = line.find("`", j)
        if j < 0:
            return j
        if backtick_run(line, j) == n:
            return j + n
        j += backtick_run(line, j)


def comment_open(line, pos, spans=True):
    """The first ``HIDDEN_HTML_RE`` match at or after ``pos`` not inside a code span, else None.

    A code span (an unescaped backtick run closed by the next run of the same length) shows
    ``<!--``, ``<?`` or ``<a`` literally (#6215, #6196); an unmatched run is literal text and opens
    no span. With ``spans`` false (inside a raw HTML block) backticks protect nothing.
    """
    i = pos
    while True:
        start = HIDDEN_HTML_RE.search(line, i)
        tick = next_tick(line, i) if spans else -1
        if start is None or tick < 0 or start.start() < tick:
            return start
        end = code_span_end(line, tick)
        i = tick + backtick_run(line, tick) if end < 0 else end


def outside_code_spans(line):
    """``line`` with every code span, its backticks included, removed (#6196)."""
    out, i = [], 0
    while True:
        tick = next_tick(line, i)
        if tick < 0:
            out.append(line[i:])
            return "".join(out)
        end = code_span_end(line, tick)
        if end < 0:
            out.append(line[i : tick + backtick_run(line, tick)])
            i = tick + backtick_run(line, tick)
        else:
            out.append(line[i:tick])
            i = end


def tag_end(line, pos, quote):
    """Return (index after the tag's closing ``>`` or -1, open quote at the end of ``line``)."""
    for i in range(pos, len(line)):
        c = line[i]
        if quote:
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == ">":
            return i + 1, ""
    return -1, quote


def comment_text_removed(line, inside, spans=True):
    """Return (``line`` without unrendered raw HTML, the open state at the end of ``line``).

    The state is "" (none), the closer of an open comment, CDATA section, processing
    instruction or declaration, or ``"tag"`` plus an open attribute quote (#6196).
    """
    shown, pos = [], 0
    while True:
        if inside.startswith("tag"):
            end, quote = tag_end(line, pos, inside[len("tag"):])
            if end < 0:
                inside = "tag" + quote
                break
            inside, pos = "", end
        elif inside:
            end = line.find(inside, pos)
            if end < 0:
                break
            inside, pos = "", end + len(inside)
        else:
            start = comment_open(line, pos, spans)
            if start is None:
                shown.append(line[pos:])
                break
            shown.append(line[pos:start.start()])
            opener = start.group()
            inside = HIDDEN_HTML_CLOSERS.get(opener, ">" if opener.startswith("<!") else "tag")
            # ``<!-->`` and ``<!--->`` are complete comments: the closer may share the
            # opener's dashes (#6246).
            pos = start.start() + 2 if opener == "<!--" else start.end()
    return "".join(shown), inside


def fence_closes(fence, line):
    """True when ``line`` closes the fenced block opened by the marker ``fence`` (#6215)."""
    if fence == MATH_FENCE:
        return line.strip() == MATH_FENCE
    m = FENCE_RE.match(line)
    return bool(m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not m.group(2).strip())


def erratum_lines(lines):
    """Return {index: text} for the erratum lines of a document (#6196, #6219).

    An erratum exists to tell a reader the text names a removed script, so it has one form that a
    rendered document always shows (5-agent vote 4d3ea1c5): a line starting ``Erratum (#<issue>): ``
    at column 0 that begins a paragraph (the first line, or after a blank line or a closing fence).
    It is not an erratum inside a fenced block or a ``$$`` block (an unclosed one runs to the end),
    inside an open HTML comment, processing instruction, CDATA section, declaration or tag (each
    runs to its closer, across blank lines and fences), or inside a raw HTML block (where backticks
    protect nothing and a ``pre``/``script``/``style``/``textarea`` block runs to its closing tag),
    and not when its text holds ``[`` or ``]`` outside code spans (link, image and footnote syntax
    can hide text). ``text`` is the line without its unrendered raw HTML. Any other shape (a list
    item, a block quote, a definition, a table, after a paragraph line) is not an erratum: rejecting
    a visible one only fails closed. Stale names are still found in all of this text.
    """
    found, inside, fence, html, starts = {}, "", None, "", True
    for i, line in enumerate(lines):
        if fence is not None:
            starts = fence_closes(fence, line)
            if starts:
                fence = None
            continue
        if not inside and not html:
            m = FENCE_RE.match(line)
            if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
                fence, starts = m.group(1), False
                continue
            if line.strip() == MATH_FENCE:
                fence, starts = MATH_FENCE, False
                continue
            block = HTML_BLOCK_RE.match(line)
            if block:
                tag = block.group(2).lower()
                html = "</%s>" % tag if not block.group(1) and tag in RAW_TEXT_TAGS else "\n"
        begins = starts and not inside and not html
        shown, inside = comment_text_removed(line, inside, not html)
        if begins and ERRATUM_RE.match(line) and not any(c in "[]" for c in outside_code_spans(shown)):
            found[i] = shown
        if html == "\n" and not line.strip() or html != "\n" and html and html in line.lower():
            html = ""
        starts = not line.strip()
    return found


def erratum_names(root, line):
    """Yield (stale name, successor) for each name ``line`` gives an existing successor (#6198)."""
    if "erratum" not in line.lower():
        return
    succ = [s for s in SUCCESSOR_RE.findall(line) if successor_ok(root, s)]
    if not succ:
        return
    for _cited, name, path in tokens(line):
        if path not in ["scripts/" + s for s in succ]:
            yield name, succ[0]


def collect_errata(root, lines_by_doc):
    """Return (all, per_doc, near): stale name -> successor, globally and by doc path.

    ``near`` maps doc path -> stale name -> the 1-based number of the first line that names the
    name and an existing successor with the word "erratum" but is not in the erratum form, so
    the violation can say which line to fix (#6238).
    """
    errata, per_doc, near = {}, {}, {}
    for doc, lines in lines_by_doc:
        rel = doc.relative_to(root).as_posix()
        found = erratum_lines(lines)
        for i, line in enumerate(lines):
            if i in found:
                for name, succ in erratum_names(root, found[i]):
                    errata[name] = succ
                    per_doc.setdefault(rel, {})[name] = succ
            else:
                for name, _succ in erratum_names(root, line):
                    near.setdefault(rel, {}).setdefault(name, i + 1)
    return errata, per_doc, near


def load_allowlist(root):
    """Return ({(doc, stale-name): pinned}, list of malformed/duplicate-line problems)."""
    path = root / ALLOW_REL
    try:
        present = path.is_file()
    except OSError:
        raise Unreadable(ALLOW_REL)
    if not present:
        return {}, []
    pairs, problems = {}, []
    for lineno, raw in enumerate(read_text(root, path).splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = ENTRY_RE.match(line)
        if not m:
            problems.append("%s:%d: malformed allowlist entry %r" % (ALLOW_REL, lineno, line))
            continue
        key = (m.group(1), m.group(2))
        if key in pairs:
            problems.append("%s:%d: duplicate allowlist entry %s:%s" % (ALLOW_REL, lineno, key[0], key[1]))
            continue
        pairs[key] = m.group(3) is not None
        if pairs[key] and key[0] not in PINNABLE_DOCS:
            problems.append(
                "%s:%d: :pinned not permitted for %s:%s (only %s)"
                % (ALLOW_REL, lineno, key[0], key[1], ", ".join(sorted(PINNABLE_DOCS)))
            )
    return pairs, problems


def check(root):
    """Return a list of violation strings for the tree at ``root``."""
    docs, problems = compliance_docs(root)
    lines_by_doc = [(doc, doc_lines(root, doc)) for doc in docs]
    errata, per_doc, near = collect_errata(root, lines_by_doc)
    allowed, ledger_problems = load_allowlist(root)
    problems.extend(ledger_problems)
    used = set()
    for doc, lines in lines_by_doc:
        rel = doc.relative_to(root).as_posix()
        for lineno, line in enumerate(lines, 1):
            found = list(tokens(line))
            found += [t for t in tokens(rendered(line)) if t not in found]
            for cited, base, path in found:
                if path_ok(root, path):
                    continue
                pinned = allowed.get((rel, base))
                covered = base in errata if pinned else base in per_doc.get(rel, {})
                if pinned is not None and covered:
                    used.add((rel, base))
                    continue
                hint = near.get(rel, {}).get(base)
                problems.append(
                    "%s:%d: `%s` does not exist (checked at %s) and no erratum-covered allowlist"
                    " entry (%s) names it%s"
                    % (rel, lineno, cited, path, ALLOW_REL, "" if hint is None else NEAR_HINT % hint)
                )
    for (rel, base), pinned in sorted(allowed.items()):
        if pinned and base in per_doc.get(rel, {}):
            problems.append(
                "%s: unnecessary :pinned on %s:%s (the document carries its own erratum)"
                % (ALLOW_REL, rel, base)
            )
    for rel, base in sorted(set(allowed) - used):
        problems.append("%s: stale allowlist entry %s:%s suppresses nothing" % (ALLOW_REL, rel, base))
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
        (root / "scripts" / "qc-allowlists").mkdir(parents=True)
        (root / "docs" / "compliance").mkdir(parents=True)
        (root / "scripts" / "check_new.py").write_text("")
        (root / "outside.py").write_text("not a script under scripts/\n")
        allow = root / ALLOW_REL
        doc = root / "docs" / "compliance" / "A.md"
        other = root / "docs" / "compliance" / "B.md"
        # The one erratum form (#6196, #6219, 5-agent vote 4d3ea1c5): column 0, after a blank line.
        erratum = "\nErratum (#1): `check-old.sh` is `scripts/check_new.py`.\n"

        allow.write_text("")
        doc.write_text("N30 enforcer is `check-old.sh`.\n")
        expect(check(root), "stale name without erratum was accepted")

        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        doc.write_text("N30 enforcer is `check-old.sh`.\n" + erratum)
        expect(not check(root), "allowlisted stale name with erratum was rejected")

        # S-F3: an erratum must not clear the stale name in a doc that is not allowlisted.
        other.write_text("New text cites `check-old.sh` as the enforcer.\n")
        expect(check(root), "new doc citing the stale name was accepted despite an erratum")
        other.unlink()

        # S-F3: an allowlist entry that suppresses nothing is a violation (burn-down ledger).
        allow.write_text("docs/compliance/A.md:check-old.sh\ndocs/compliance/A.md:check-gone.sh\n")
        expect(check(root), "stale allowlist entry was accepted")
        allow.write_text("docs/compliance/A.md:check-old.sh\nnot-an-entry\n")
        expect(check(root), "malformed allowlist entry was accepted")
        allow.write_text("docs/compliance/A.md:check-old.sh\n")

        # R2-F2: a repeated <doc>:<name> line is a violation naming the duplicate.
        allow.write_text("docs/compliance/A.md:check-old.sh\ndocs/compliance/A.md:check-old.sh\n")
        expect(
            any("duplicate allowlist entry" in p for p in check(root)),
            "duplicate allowlist entry was accepted",
        )
        allow.write_text("docs/compliance/A.md:check-old.sh\n")

        # #6170: an allowlisted doc must carry its own erratum even when another doc still does.
        pin = root / "docs" / "compliance" / "v1.0.0-DECLARATION.md"
        both = "docs/compliance/%s:check-old.sh%s\ndocs/compliance/B.md:check-old.sh\n"
        other.write_text(erratum)
        doc.write_text("N30 enforcer is `check-old.sh`.\n")
        allow.write_text(both % ("A.md", ""))
        expect(check(root), "allowlisted doc whose own erratum was removed was accepted")
        # #6170: only a ':pinned' entry (on a PINNABLE_DOCS document) may rely on another doc's erratum.
        doc.unlink()
        pin.write_text("N30 enforcer is `check-old.sh`.\n")
        allow.write_text(both % ("v1.0.0-DECLARATION.md", ":pinned"))
        expect(not check(root), "pinned entry backed by a repository erratum was rejected")
        other.unlink()
        allow.write_text("docs/compliance/v1.0.0-DECLARATION.md:check-old.sh:pinned\n")
        expect(check(root), "pinned entry with no erratum anywhere was accepted")
        pin.unlink()
        doc.write_text("N30 enforcer is `check-old.sh`.\n")
        allow.write_text("docs/compliance/A.md:check-old.sh\n")

        # #6173: ':pinned' is a closed set; the cells use the real pinnable document paths.
        decl = root / "docs" / "compliance" / "v1.0.0-DECLARATION.md"
        cert = root / "docs" / "compliance" / "ENTERPRISE-FEDERATION-CERTIFICATION.md"
        stale = "N30 enforcer is `check-old.sh`.\n"
        other.write_text(erratum)
        doc.write_text(stale)
        allow.write_text("docs/compliance/A.md:check-old.sh:pinned\n")
        expect(
            any(":pinned" in p and "A.md" in p for p in check(root)),
            "#6173: ':pinned' on a document outside PINNABLE_DOCS was accepted",
        )
        # S1 (security R5): PINNABLE_DOCS compares full paths, never basenames.
        (root / "docs" / "compliance" / "sub").mkdir()
        sub = root / "docs" / "compliance" / "sub" / "v1.0.0-DECLARATION.md"
        sub.write_text(stale)
        doc.write_text(stale + erratum)
        allow.write_text(
            "docs/compliance/A.md:check-old.sh\n"
            "docs/compliance/sub/v1.0.0-DECLARATION.md:check-old.sh:pinned\n"
        )
        expect(
            any(":pinned not permitted" in p for p in check(root)),
            "R6-S1: :pinned on a subfolder look-alike of a PINNABLE_DOCS basename was accepted",
        )
        sub.unlink()
        (root / "docs" / "compliance" / "sub").rmdir()
        doc.write_text(stale + erratum)
        decl.write_text(stale + erratum)
        allow.write_text("docs/compliance/v1.0.0-DECLARATION.md:check-old.sh:pinned\n")
        expect(
            any("unnecessary :pinned" in p for p in check(root)),
            "#6173: ':pinned' on a document carrying its own erratum was accepted",
        )
        decl.write_text(stale)
        cert.write_text(stale)
        allow.write_text(
            "docs/compliance/A.md:check-old.sh\n"
            "docs/compliance/v1.0.0-DECLARATION.md:check-old.sh:pinned\n"
            "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md:check-old.sh:pinned\n"
        )
        other.unlink()
        doc.write_text(stale + erratum)
        expect(not check(root), "#6173: the two real pinned documents were rejected")
        decl.unlink()
        cert.unlink()
        doc.write_text("N30 enforcer is `check-old.sh`.\n")
        allow.write_text("docs/compliance/A.md:check-old.sh\n")

        doc.write_text("Erratum (#1): `check-old.sh` is `scripts/check_missing.py`.\n")
        expect(check(root), "erratum naming a missing successor was accepted")

        # S-F1: the successor must resolve inside scripts/.
        doc.write_text("N30 is `check-old.sh`.\n\nErratum (#1): `check-old.sh` is `scripts/../outside.py`.\n")
        expect(check(root), "erratum naming scripts/../outside.py was accepted")
        doc.write_text("N30 is `check-old.sh`.\n\nErratum (#1): `check-old.sh` is `scripts/./check_new.py`.\n")
        expect(check(root), "erratum naming a dot component was accepted")
        link = root / "scripts" / "check_link.py"
        try:
            link.symlink_to(root / "outside.py")
        except OSError:
            link = None
        if link is not None:
            doc.write_text("N30 is `check-old.sh`.\n\nErratum (#1): `check-old.sh` is `scripts/check_link.py`.\n")
            expect(check(root), "erratum naming an escaping symlink was accepted")
            link.unlink()

        # #6141 round 5: pin the exact token, entry, erratum and allowlist semantics.
        stale = "N30 enforcer is `%s`.\n"
        # M7: an allowlist entry must match to end of line (no trailing garbage).
        doc.write_text(stale % "check-old.sh" + erratum)
        for tail in (":pinnedx", ":bogus", " trailing", "x"):
            allow.write_text("docs/compliance/A.md:check-old.sh%s\n" % tail)
            expect(
                any("malformed allowlist entry" in p for p in check(root)),
                "R5-M7: allowlist entry with trailing %r was accepted" % tail,
            )
        # M9/M10: both prefixes (check-, check_) and both suffixes (.sh, .py) are tokens.
        for name in ("check-old.py", "check_old.sh", "check_old.py", "check-old.sh"):
            allow.write_text("")
            doc.write_text(stale % name)
            expect(
                any(name in p for p in check(root)),
                "R5-M9/M10: stale `%s` without erratum was accepted" % name,
            )
            allow.write_text("docs/compliance/A.md:%s\n" % name)
            doc.write_text(stale % name + "\nErratum (#1): `%s` is `scripts/check_new.py`.\n" % name)
            expect(not check(root), "R5-M9/M10: allowlisted `%s` with erratum was rejected" % name)
        # M11: a successor line that does not say "erratum" is not an erratum.
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        doc.write_text(stale % "check-old.sh" + "N30 now uses `scripts/check_new.py` instead of `check-old.sh`.\n")
        expect(check(root), "R5-M11: a successor line without the word erratum was accepted")
        # S2 (security R5): a backticked scripts/-prefixed stale name is flagged.
        allow.write_text("")
        doc.write_text("N30 enforcer is `scripts/check-old.sh`.\n")
        expect(check(root), "R6-S2: stale scripts/-prefixed name was accepted")
        # S6 (security R5): the word "erratum" must be on the line naming the stale name and successor.
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        doc.write_text("Erratum (see below).\n" + stale % "check-old.sh" + "`check-old.sh` is `scripts/check_new.py`.\n")
        expect(check(root), "R6-S6: erratum word on a different line from the successor was accepted")
        # M12: an erratum alone never clears a stale name; the allowlist entry is required.
        allow.write_text("")
        doc.write_text(stale % "check-old.sh" + erratum)
        expect(check(root), "R5-M12: erratum without an allowlist entry was accepted")
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        doc.write_text("N30 enforcer is `check-old.sh`.\n")

        # R6 review: exit code, scripts/-prefixed tokens, scripts/-only resolution, ledger hygiene.
        allow.write_text("")
        doc.write_text("N30 enforcer is `check-old.sh`.\n")
        rc, err = run_main(root)
        expect(rc == 1 and "FAIL " in err, "R6-R1: violation tree: expected exit 1 with FAIL lines, got %r" % (rc,))
        doc.write_text("See `check_new.py`.\n")
        rc, _ = run_main(root)
        expect(rc == 0, "R6-R1: clean tree: expected exit 0, got %r" % (rc,))
        doc.write_text("N30 enforcer is `scripts/check-gone.sh`.\n")
        expect(any("scripts/check-gone.sh" in p for p in check(root)),
               "R6-R2: stale scripts/-prefixed name was accepted")
        (root / "check-gone.sh").write_text("")
        (root / "scripts" / "check-dir.sh").mkdir()
        doc.write_text("N30 is `check-gone.sh` and `check-dir.sh`.\n")
        probs = check(root)
        expect(any("check-gone.sh" in p for p in probs), "R6-R14: name resolving only outside scripts/ was accepted")
        expect(any("check-dir.sh" in p for p in probs), "R6-R14: name resolving to a directory was accepted")
        (root / "check-gone.sh").unlink()
        (root / "scripts" / "check-dir.sh").rmdir()
        doc.write_text("N30 enforcer is `check-old.sh`.\n" + erratum)
        allow.write_text("docs/compliance/A.md:check-old.sh\njunk # note\n")
        expect(any("malformed allowlist entry" in p for p in check(root)),
               "R6-R18: malformed line containing '#' was accepted")
        allow.write_text("  docs/compliance/A.md:check-old.sh  \n")
        expect(not check(root), "R6-R9: whitespace-padded allowlist entry was rejected")
        # R5: an allowlist entry must name a document under docs/compliance/.
        allow.write_text("notes/A.md:check-old.sh\n")
        expect(any("malformed allowlist entry" in p for p in check(root)),
               "R6-R5: allowlist entry outside docs/compliance/ was not reported as malformed")
        # R19: the successor an erratum names is not itself excused at another path.
        allow.write_text("docs/compliance/A.md:check-old.sh\ndocs/compliance/A.md:check_new.py\n")
        doc.write_text(erratum + "Old copy: `scripts/legacy/check_new.py`.\n")
        expect(any("scripts/legacy/check_new.py" in p for p in check(root)),
               "R6-R19: an erratum excused its own successor at a missing path")
        # O14: the path after the FIRST scripts component is the one checked.
        allow.write_text("")
        doc.write_text("N30 enforcer is `scripts/scripts/check_new.py`.\n")
        expect(any("scripts/scripts/check_new.py" in p for p in check(root)),
               "R6-O14: scripts/scripts/<name> resolved to scripts/<name>")
        allow.write_text("")
        doc.write_text("See `check_new.py` and `scripts/check_new.py`.\n")
        expect(not check(root), "resolving names were rejected")

        # C-F2: an unreadable doc is exit 2 with an 'unreadable' line, never a traceback.
        doc.write_bytes(b"\xff\xfe")
        rc, err = run_main(root)
        expect(rc == 2, "non-UTF-8 doc: expected exit 2, got %r" % (rc,))
        expect("A.md: unreadable" in err, "non-UTF-8 doc: missing 'unreadable' line (stderr=%r)" % err)

        # Round 6 (#6169 #6195 #6196 #6197 #6198 #6199): each cell builds its own tree under ``root``.
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
        probs = check(r)
        expect(any("N.MD" in p and "check-old.sh" in p for p in probs), "#6197-MD: stale name in a .MD document was accepted")
        expect(any("M.Md" in p and "check-old.sh" in p for p in probs), "#6197-Md: stale name in a .Md document was accepted")
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

        # #6198: a cited name resolves only to that exact path under scripts/, contained in scripts/.
        allow.write_text("")
        (root / "scripts" / "fixtures").mkdir()
        (root / "scripts" / "fixtures" / "check-nest.sh").write_text("")
        doc.write_text("N30 enforcer is `check-nest.sh`.\n")
        expect(any("check-nest.sh" in p for p in check(root)), "#6198-nested: a nested look-alike cleared a stale name")
        if try_symlink(root / "scripts" / "check-esc.sh", root / "outside.py", "#6198-escape"):
            doc.write_text("N30 enforcer is `check-esc.sh`.\n")
            expect(any("check-esc.sh" in p for p in check(root)), "#6198-escape: a symlink escaping scripts/ cleared a stale name")
            (root / "scripts" / "check-esc.sh").unlink()
        (root / "scripts" / "sub").mkdir()
        (root / "scripts" / "sub" / "check_sub.py").write_text("")
        doc.write_text("Runs `scripts/sub/check_sub.py` and `scripts/fixtures/check-nest.sh`.\n")
        expect(not check(root), "#6198-exact: an exact scripts/<subdir>/ path was rejected")
        if try_symlink(root / "scripts" / "check-alias.sh", root / "scripts" / "check_new.py", "#6198-alias"):
            doc.write_text("N30 enforcer is `check-alias.sh`.\n")
            expect(not check(root), "#6198-alias: a symlink inside scripts/ was rejected")
            (root / "scripts" / "check-alias.sh").unlink()

        # #6195: the stale name is found anywhere on a line, after removing invisible format characters.
        hidden = {
            "soft hyphen": "N30 enforcer is `check-ol­d.sh`.\n",
            "ZWSP": "N30 enforcer is `check-​old.sh`.\n",
            "ZWNJ": "N30 enforcer is `check-old‌.sh`.\n",
            "fenced block": "Run:\n\n```\nbash check-old.sh --verify\n```\n",
            "bash scripts/": "Run `bash scripts/check-old.sh`.\n",
            "./scripts/": "Run `./scripts/check-old.sh`.\n",
            "scripts/<subdir>/": "Run `scripts/sub/check-old.sh`.\n",
            "bare prose": "The enforcer check-old.sh runs on every push.\n",
            "URL": "See https://github.com/o/r/blob/main/scripts/check-old.sh for N30.\n",
        }
        for label, text in sorted(hidden.items()):
            doc.write_text(text)
            expect(any("check-old.sh" in p for p in check(root)), "#6195-%s: stale name was accepted" % label)
        doc.write_text(
            "Run `bash scripts/check_new.py`, `./scripts/check_new.py` and check_new.py;\n"
            "see https://github.com/o/r/blob/main/scripts/check_new.py and `check_​new.py`.\n"
        )
        expect(not check(root), "#6195-resolving: resolving names in prefixed forms were rejected")

        # #6196: an erratum hidden in an HTML comment never clears a stale name.
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        for label, text in (
            ("one-line comment", stale_line + "<!-- " + erratum.strip() + " -->\n"),
            ("multi-line comment", stale_line + "<!-- header\n" + erratum + "-->\n"),
            ("comment opened earlier on the line", stale_line + "<!-- x " + erratum),
        ):
            doc.write_text(text)
            expect(check(root), "#6196-%s: an erratum inside an HTML comment was accepted" % label)
        for label, text in (
            ("after a closed comment", stale_line + "<!-- header -->\n" + erratum),
            ("after a close on the line before", stale_line + "<!-- a\nb -->\n" + erratum),
        ):
            doc.write_text(text)
            expect(not check(root), "#6196-%s: a visible erratum was rejected" % label)

        # R7 review: pins for round-6 survivors N3 N4 N5 N7 N10 N12 N13 N14 N15 N19.
        allow.write_text("")
        for cp in ("‍", "⁠", "﻿", "‎", "\U000e0041"):
            doc.write_text("N30 enforcer is `check-o%sld.sh`.\n" % cp, encoding="utf-8")
            expect(any("check-old.sh" in p for p in check(root)), "R7-N3/N4: Cf U+%04X hid a stale name" % ord(cp))
        doc.write_text("<!-- N30 enforcer was `check-old.sh`. -->\n")
        expect(any("check-old.sh" in p for p in check(root)), "R7-N7: a stale name inside an HTML comment was accepted")
        doc.write_text("Runs `./scripts/fixtures/check_new.py`.\n")
        expect(any("scripts/fixtures/check_new.py" in p for p in check(root)),
               "R7-N12: a non-leading scripts/ path resolved by basename")
        doc.write_text("See `precheck-old.sh`, `x.check-old.sh` and `check-old.shx`.\n")
        expect(not check(root), "R7-N13/N14: a name embedded in a longer word was tokenised")
        doc.write_text("N30 enforcer is `check_NEW.py`.\n")
        expect(any("check_NEW.py" in p for p in check(root)), "R7-N5: a case variant of an existing script resolved")
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        doc.write_text(stale_line + "<!-- a --> x <!-- " + erratum.strip() + " -->\n")
        expect(check(root), "R7-N19: an erratum in a second comment on one line was accepted")
        doc.write_text(stale_line + erratum)
        allow.write_text("docs/compliance/A.md:check-old.sh​\n", encoding="utf-8")
        expect(any("malformed allowlist entry" in p for p in check(root)),
               "R7-N15: a Cf character in an allowlist entry was accepted")
        r = fresh("u-allow-file")
        denied_rc(r / ALLOW_REL, r, "R7-N10", ALLOW_REL + ": unreadable")

        # #6195 (round 7): every Default_Ignorable_Code_Point is removed, not only category Cf.
        allow.write_text("")
        for cp in (0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x180F, 0x2065, 0x3164,
                   0xFE00, 0xFE0F, 0xFFA0, 0xFFF0, 0xE0080, 0xE0100, 0xE01EF):
            doc.write_text("N30 enforcer is `check-o%sld.sh`.\n" % chr(cp), encoding="utf-8")
            expect(any("check-old.sh" in p for p in check(root)), "R7-#6195: U+%04X hid a stale name" % cp)

        # #6215: '<!--' inside a fenced block or a code span is literal and hides nothing.
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        for label, text in (
            ("fence", stale_line + "```html\n<!-- example\n```\n" + erratum),
            ("tilde fence", stale_line + "~~~~\n<!--\n~~~~\n" + erratum),
            ("code span", stale_line + "Write `<!--` to open a comment.\n" + erratum),
            ("double code span", stale_line + "Write ``a `<!--` b`` here.\n" + erratum),
            ("code span on the erratum line",
             stale_line + "\nErratum (#1): `<!--` `check-old.sh` is `scripts/check_new.py`.\n"),
        ):
            doc.write_text(text)
            expect(not check(root), "R7-#6215-%s: a literal '<!--' hid a visible erratum" % label)
        doc.write_text(stale_line + "Text `code` then <!-- " + erratum.strip() + " -->\n")
        expect(check(root), "R7-#6215-control: a comment after a closed code span was not hidden")

        # #6196 (round 7): diagram fences (mermaid '%%' comments) are not reader-visible text.
        for label, text in (
            ("mermaid %%", stale_line + "```mermaid\ngraph TD\n%% " + erratum + "```\n"),
            ("mermaid body", stale_line + "~~~ mermaid\n" + erratum + "~~~\n"),
            ("math", stale_line + "```math\n" + erratum + "```\n"),
            ("unclosed mermaid", stale_line + "```mermaid\n" + erratum),
        ):
            doc.write_text(text)
            expect(check(root), "R7-#6196-%s: an erratum in a diagram fence was accepted" % label)
        doc.write_text(stale_line + "```text\n" + erratum + "```\n")
        expect(check(root), "R8-#6196: an erratum in a plain code fence was accepted (not the erratum form)")
        doc.write_text(stale_line + "```mermaid\ngraph TD\n```\n\n" + erratum)
        expect(not check(root), "R7-#6196-control: an erratum after a closed mermaid fence was rejected")

        # #6219: a link reference definition is never rendered, so it cannot carry an erratum.
        for label, text in (
            ("single line", stale_line + "\n[//]: # (" + erratum.strip() + ")\n"),
            ("next-line title", stale_line + "\n[note]: /x\n(" + erratum.strip() + ")\n"),
            ("continued title", stale_line + "\n[note]: /x 'Note\n" + erratum.strip() + "'\n"),
            ("indented", stale_line + "\n   [//]: # \"" + erratum.strip() + "\"\n"),
        ):
            doc.write_text(text)
            expect(check(root), "R7-#6219-%s: an erratum in a link reference definition was accepted" % label)
        doc.write_text(stale_line + "\n[note]: /x\n\n" + erratum)
        expect(not check(root), "R7-#6219-control: a visible erratum after a definition was rejected")

        # #6214: the stale name a reader sees after Markdown/HTML rendering is checked.
        allow.write_text("")
        for label, text in (
            ("backslash escape", "N30 enforcer is check\\-old.sh.\n"),
            ("numeric entity", "N30 enforcer is check&#45;old.sh.\n"),
            ("hex entity", "N30 enforcer is check&#x2d;old&#46;sh.\n"),
            ("named entity", "N30 enforcer is check&hyphen;old.sh.\n"),
            ("inline tag", "N30 enforcer is check-<span></span>old.sh.\n"),
            ("inline comment", "N30 enforcer is check-<!-- x -->old.sh.\n"),
            ("bold", "N30 enforcer is check-**old**.sh.\n"),
            ("italic", "N30 enforcer is *check*-old.sh.\n"),
            ("strikethrough", "N30 enforcer is check-~~old~~.sh.\n"),
            ("U+2011", "N30 enforcer is check‑old.sh.\n"),
            ("U+2010", "N30 enforcer is check‐old.sh.\n"),
            ("U+2212", "N30 enforcer is check−old.sh.\n"),
            ("Cyrillic", "N30 enforcer is сheck-old.sh.\n"),
            ("Greek", "N30 enforcer is check-οld.sh.\n"),
            ("combining mark", "N30 enforcer is chéck-old.sh.\n"),
            ("fullwidth", "N30 enforcer is ｃheck-old.sh.\n"),
        ):
            doc.write_text(text, encoding="utf-8")
            expect(any("check-old.sh" in p for p in check(root)), "R7-#6214-%s: a rendered stale name was accepted" % label)
        doc.write_text("Runs check\\_new.py and check&#95;new.py and `check_new.py`.\n")
        expect(not check(root), "R7-#6214-control: a rendered existing name was rejected")

        # #6216: a written path outside scripts/ is checked at that path, never as a bare name.
        (root / "infra").mkdir()
        (root / "infra" / "check_infra.py").write_text("")
        for cited in ("infra/check_new.py", "tools/scripts/check_new.py", "./check_new.py"):
            doc.write_text("N30 enforcer is `%s`.\n" % cited)
            expect(any(cited in p for p in check(root)), "R7-#6216: `%s` resolved as its bare name" % cited)
        doc.write_text("N30 enforcer is `infra/check_infra.py` and `../../scripts/check_new.py`.\n")
        expect(not check(root), "R7-#6216-control: an existing path outside scripts/ was rejected")

        # #6217: a document symlink loop is reported as a loop.
        r = fresh("s-loop")
        if try_symlink(r / "docs" / "compliance" / "L1.md", r / "docs" / "compliance" / "L2.md", "#6217") and try_symlink(
            r / "docs" / "compliance" / "L2.md", r / "docs" / "compliance" / "L1.md", "#6217"
        ):
            probs = check(r)
            expect(
                any("L1.md: document symlink loop (refused)" in p for p in probs)
                and not any("outside the repository" in p for p in probs),
                "R7-#6217: a symlink loop was not reported as a loop (%r)" % (probs,),
            )

        # #6220: names match in any letter case; existence is exact-case on every host.
        allow.write_text("")
        for cited in ("CHECK-old.sh", "Check_Old.PY", "check_new.PY"):
            doc.write_text("N30 enforcer is `%s`.\n" % cited)
            expect(any(cited in p for p in check(root)), "R7-#6220: `%s` was not checked" % cited)
        doc.write_text("Runs `scripts/SUB/check_sub.py`.\n")
        expect(any("scripts/SUB/check_sub.py" in p for p in check(root)), "R7-#6220: a case variant of a directory resolved")
        allow.write_text("docs/compliance/A.md:CHECK-old.sh\n")
        doc.write_text("N30 enforcer is `CHECK-old.sh`.\n\nErratum (#1): `CHECK-old.sh` is `scripts/check_new.py`.\n")
        expect(not check(root), "R7-#6220: an allowlisted upper-case name with an erratum was rejected")
        allow.write_text("")

        # Round-7 mutant cells (evidence round7/r7_mutants.py): each pins one branch of the round-7 code.
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        doc.write_text(stale_line + erratum.replace("check-old", "check-️old"), encoding="utf-8")
        expect(not check(root), "R7-D4: a variation selector inside an erratum's stale name voided the erratum")
        for label, text in (
            ("F3/F5 tilde line inside a backtick fence", stale_line + "```mermaid\n~~~\n" + erratum + "```\n"),
            ("F4 shorter closing run", stale_line + "````mermaid\n```\n" + erratum + "````\n"),
            ("F3 closing run with an info string", stale_line + "```mermaid\n``` x\n" + erratum + "```\n"),
            ("F7 unmatched backtick run", stale_line + "Text ``` <!-- " + erratum.strip() + " -->\n"),
            ("F8 backtick in a backtick info string", stale_line + "```x`y\n<!-- " + erratum.strip() + " -->\n"),
            ("G3 upper-case diagram info", stale_line + "```Mermaid\n" + erratum + "```\n"),
            ("T13 look-alike erratum word", stale_line + "\nErrаtum (#1): `check-old.sh` is `scripts/check_new.py`.\n"),
        ):
            doc.write_text(text, encoding="utf-8")
            expect(check(root), "R7-%s: a hidden or invalid erratum was accepted" % label)
        for label, text in (
            ("F9 four-space indent is no fence", stale_line + "\n    ```mermaid\n\n" + erratum),
            ("L3 four-space indent is no definition", stale_line + "\n    [a]: /u\n" + erratum),
            ("F6 double span holding a single backtick",
             stale_line + "\nErratum (#1): ``a ` <!-- b`` `check-old.sh` is `scripts/check_new.py`.\n"),
        ):
            doc.write_text(text)
            expect(not check(root), "R7-%s: a visible erratum was rejected" % label)
        allow.write_text("")
        for label, text in (
            ("T11 entity-encoded invisible character", "N30 enforcer is check&#8203;-old.sh.\n"),
            ("C2 name after a long s", "N30 enforcer is ſcheck-old.sh.\n"),
        ):
            doc.write_text(text, encoding="utf-8")
            expect(any("check-old.sh" in p for p in check(root)), "R7-%s: a stale name was not checked" % label)
        (root / "scripts" / "a" / "scripts").mkdir(parents=True)
        (root / "scripts" / "a" / "scripts" / "check_deep.py").write_text("")
        doc.write_text("Runs `./scripts/a/scripts/check_deep.py`.\n")
        expect(not check(root), "R7-O14: ./scripts/ with a nested scripts/ was not resolved from the first one")
        allow.write_text("docs/compliance/A.md:CHECK-old.SH\n")
        doc.write_text("N30 enforcer is `CHECK-old.SH`.\n\nErratum (#1): `CHECK-old.SH` is `scripts/check_new.py`.\n")
        expect(not check(root), "R7-C4: an allowlist entry with an upper-case suffix was rejected")
        allow.write_text("")

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
               "R7-P7: a RuntimeError from resolve() in path_ok did not fail closed (%r)" % (probs,))
        r = fresh("r-unresolvable")
        (r / "docs" / "compliance" / "real.md").write_text("No script names.\n")
        if try_symlink(r / "docs" / "compliance" / "U.md", r / "docs" / "compliance" / "real.md", "R7-Y3"):
            probs = check_with_resolve(r, "U.md", OSError(errno.EIO, "I/O error"))
            expect(
                any("U.md: document symlink cannot be resolved" in p for p in probs)
                and not any("outside the repository" in p for p in probs),
                "R7-Y3/Y4: an unresolvable document symlink was not refused as such (%r)" % (probs,),
            )

        # Reviewer round 7: pins for survivors N5 N5b X2 X3 X4 X5 X6 X7 X9 X10.
        allow.write_text("")
        for cp in (0xFFF9, 0xFFFB, 0x13430):
            doc.write_text("N30 enforcer is `check-o%sld.sh`.\n" % chr(cp), encoding="utf-8")
            expect(any("check-old.sh" in p for p in check(root)),
                   "R8-X2: Cf U+%04X outside Default_Ignorable hid a stale name" % cp)
        doc.write_text("Runs `tools//scripts/check_new.py`.\n")
        expect(any("tools//scripts/check_new.py" in p for p in check(root)),
               "R8-X3: a '//' inside a written path was read as a URL")
        doc.write_text("Runs `infra/check_infra.py` and check&#95;infra.py.\n")
        expect(any("scripts/check_infra.py" in p for p in check(root)),
               "R8-X10: a rendered citation sharing a raw citation's name was dropped")
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        for label, text in (
            ("X4 fence inside a comment", stale_line + "<!--\n```\n" + erratum + "```\n-->\n"),
            ("X5 diagram info with a second word", stale_line + "```mermaid theme\n" + erratum + "```\n"),
        ):
            doc.write_text(text)
            expect(check(root), "R8-%s: a hidden erratum was accepted" % label)
        for label, text in (
            ("X6 empty label is no definition", stale_line + "[]: x\n" + erratum),
            ("X9 a fence ends a definition paragraph", stale_line + "\n[a]: /u\n```\ncode\n```\n" + erratum),
        ):
            doc.write_text(text)
            expect(not check(root), "R8-%s: a visible erratum was rejected" % label)
        allow.write_text("")
        r = fresh("s-dangling")
        if try_symlink(r / "docs" / "compliance" / "D.md", r / "docs" / "compliance" / "missing.md", "R8-X7"):
            rc, err = run_main(r)
            expect(rc == 2 and "D.md: unreadable" in err and "loop" not in err,
                   "R8-X7: a dangling document symlink gave %r %r" % (rc, err))
        # #6220 on a case-sensitive CI runner: emulate a case-insensitive filesystem, so only the
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

        Path.is_file = ci_is_file
        try:
            doc.write_text("Runs `check_NEW.py` and `scripts/SUB/check_sub.py`.\n")
            probs = check(root)
        finally:
            Path.is_file = real_is_file
        expect(any("check_NEW.py" in p for p in probs) and any("scripts/SUB/check_sub.py" in p for p in probs),
               "R8-N5: on an emulated case-insensitive filesystem a case variant resolved (%r)" % (probs,))

        # #6196 (round 8): raw HTML GitHub renders as nothing cannot carry an erratum: a processing
        # instruction, a CDATA section, a declaration, and a tag's attributes (also across lines).
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        for label, text in (
            ("processing instruction", stale_line + "<? " + erratum.strip() + " ?>\n"),
            ("multi-line processing instruction", stale_line + "<?\n" + erratum + "?>\n"),
            ("processing instruction in a paragraph", stale_line + "Text <? " + erratum.strip() + " ?> end\n"),
            ("CDATA", stale_line + "<![CDATA[ " + erratum.strip() + " ]]>\n"),
            ("declaration", stale_line + "<!DOCTYPE " + erratum.strip() + ">\n"),
            ("attribute", stale_line + '<span title="' + erratum.strip() + '"></span>\n'),
            ("attribute with '>'", stale_line + '<span title="a > ' + erratum.strip() + '"></span>\n'),
            ("multi-line tag", stale_line + "<span\ntitle='" + erratum.strip() + "'></span>\n"),
        ):
            doc.write_text(text)
            expect(check(root), "R8-F9-%s: an erratum GitHub does not render was accepted" % label)
        for label, text in (
            ("after an inline tag", stale_line + "\nErratum (#1): <br> `check-old.sh` is `scripts/check_new.py`.\n"),
            ("after a closed instruction",
             stale_line + "\nErratum (#1): <? x ?> `check-old.sh` is `scripts/check_new.py`.\n"),
            ("code span", stale_line + "Write `<?` or `<a` here.\n" + erratum),
        ):
            doc.write_text(text)
            expect(not check(root), "R8-F9-control %s: a visible erratum was rejected" % label)
        allow.write_text("")

        # #6196, #6219 (round 8, 5-agent vote 4d3ea1c5): the one erratum form is a line starting
        # `Erratum (#<issue>): ` at column 0 that begins a paragraph (first line, after a blank line or
        # a closing fence), outside any fence, $$ block, HTML comment, raw HTML block or open tag, with
        # no link, image or footnote brackets outside code spans. Any other shape is not an erratum.
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        names = "`check-old.sh` is `scripts/check_new.py`.\n"
        line = erratum.lstrip("\n")
        for label, text in (
            ("no issue number", stale_line + "\nErratum: " + names),
            ("lower case", stale_line + "\nerratum (#1): " + names),
            ("indented", stale_line + "\n Erratum (#1): " + names),
            ("continues a paragraph", stale_line + line),
            ("after a heading line", stale_line + "\n# Notes\n" + line),
            ("list item", stale_line + "\n- " + line),
            ("block quote", stale_line + "\n> " + line),
            ("fenced block", stale_line + "\n```\n" + erratum + "```\n"),
            ("unclosed fence", stale_line + "\n~~~\n" + erratum),
            ("footnote definition", stale_line + "\n[^e]: " + line),
            ("link on the line", stale_line + "\nErratum (#1): [`check-old.sh`](x) is `scripts/check_new.py`.\n"),
            ("image on the line", stale_line + "\nErratum (#1): ![`check-old.sh`](x) is `scripts/check_new.py`.\n"),
            ("$$ block", stale_line + "\n$$\n" + erratum + "\n$$\n"),
            ("unclosed $$ block", stale_line + "\n$$\n" + erratum),
            ("open tag past a blank line", stale_line + '\n<span title="x\n' + erratum + '">\n'),
            ("open tag past a fence", stale_line + '\n<span title="x\n```\n' + erratum + '```\n">\n'),
            ("code span '<!--' in an HTML block", stale_line + "\n<div>\n`<!--`\n" + erratum + "\n-->\n"),
            ("code span '<!--' in a pre block", stale_line + "\n<pre>\n`<!--`\n" + erratum + "\n</pre>\n-->\n"),
            ("pre block", stale_line + "\n<PRE>\n" + erratum + "\n</pre>\n"),
            ("fence line in an HTML block", stale_line + "\n<div>\n```\n<!--\n```\n" + erratum + "\n-->\n"),
            ("escaped backtick", stale_line + "\nErratum (#1): \\`<!--` `check-old.sh` is `scripts/check_new.py`. -->\n"),
            ("E1 escaped bracket label", stale_line + '\n[a\\]b]: # "' + erratum.strip() + '"\n'),
            ("E2 label over lines", stale_line + '\n[\nx\n]: # "' + erratum.strip() + '"\n'),
            ("E3 definition in a block quote", stale_line + '\n> [//]: # "' + erratum.strip() + '"\n'),
            ("E4 definition in a list item", stale_line + '\n- [//]: # "' + erratum.strip() + '"\n'),
            ("E5 mermaid in a block quote", stale_line + "\n> ```mermaid\n> %% " + erratum.strip() + "\n> ```\n"),
            ("E6 mermaid in a list item",
             stale_line + "\n- item\n\n    ```mermaid\n    %% " + erratum.strip() + "\n    ```\n"),
            ("E10 escaped backtick before a comment", stale_line + "\n\\`<!--` " + erratum.strip() + " -->\n"),
            ("#6238 '[ ]:' label", stale_line + "\n[ ]: " + line),
            ("#6238 definition after a paragraph line", stale_line + "Text\n[//]: # (" + erratum.strip() + ")\n"),
            ("#6246 '<!-->' on the erratum line", stale_line + "\n<!--> " + line),
            ("#6215 M6 fence holding '<!--', then a mermaid erratum",
             stale_line + "\n```\n<!--\n```\n```mermaid\n%% " + erratum.strip() + "\n```\n"),
        ):
            doc.write_text(text)
            expect(check(root), "R8-canonical-%s: a non-canonical or hidden erratum was accepted" % label)
        for label, text in (
            ("canonical", stale_line + erratum),
            ("first line", line + stale_line),
            ("after a closing fence", stale_line + "\n```\n<!--\n```\n" + line),
            ("after a closed comment block", stale_line + "\n<!--\nnote\n\n-->\n" + erratum),
            ("#6246 after '<!-->'", stale_line + "\n<!-->\n" + erratum),
            ("#6246 after '<!--->'", stale_line + "\n<!--->\n" + erratum),
            ("#6246 after '<!-->' inline", stale_line + "\nText <!--> more.\n" + erratum),
            ("after an HTML block", stale_line + "\n<div>\nx\n</div>\n" + erratum),
            ("after a closed pre block", stale_line + "\n<pre>\nx\n</pre>\n" + erratum),
            ("after a closed $$ block", stale_line + "\n$$\nx\n$$\n" + erratum),
            ("brackets in a code span", stale_line + "\nErratum (#1): `[x]` `check-old.sh` is `scripts/check_new.py`.\n"),
            ("#6238 after a '[ ]:' line", stale_line + "\n[ ]: x\n" + erratum),
        ):
            doc.write_text(text)
            expect(not check(root), "R8-canonical-%s: a canonical erratum was rejected" % label)
        # #6238: a line that names the stale name and a successor with the word erratum, but is not
        # in the erratum form, is named in the violation together with the form to use.
        doc.write_text(stale_line + "\n[ ]: " + line)
        probs = check(root)
        expect(any("line 3 is not an erratum" in p and "Erratum (#<issue>): " in p for p in probs),
               "R8-#6238: a non-canonical erratum line was not named in the violation (%r)" % (probs,))
        doc.write_text(stale_line + "\nN30 now uses `scripts/check_new.py`, not `check-old.sh`.\n")
        expect(not any("is not an erratum" in p for p in check(root)),
               "R8-#6238: a line without the word erratum was named as a non-canonical erratum")

        # #6214 (round 8): a name a reader sees across code spans, links, comments and tags spanning
        # lines is checked (document skeleton), and a name with any non-ASCII letter in a letter
        # position is a look-alike, whatever its script.
        allow.write_text("")
        for label, text in (
            ("D1 backtick split", "Run check-`old.sh` daily.\n"),
            ("D2 adjacent code spans", "Run `check-`<!-- -->`old.sh` daily.\n"),
            ("D3 adjacent links", "Run [check-](a)[old.sh](b) daily.\n"),
            ("D4 comment over lines", "Run check-<!--\n-->old.sh daily.\n"),
            ("tag over lines", "Run check-<span\nclass='x'>old.sh daily.\n"),
            ("empty comment", "Run check-<!-->old.sh daily.\n"),
        ):
            doc.write_text(text, encoding="utf-8")
            expect(any("check-old.sh" in p for p in check(root)), "R8-#6214-%s: a split stale name was accepted" % label)
        doc.write_text("Before.\nRun check-<!--\n\n-->old.sh daily.\n")
        expect(any(":2:" in p and "check-old.sh" in p for p in check(root)),
               "R8-#6214: a skeleton finding was not reported on the line it starts on")
        for label, text in (
            ("D6 U+03F2", "Run `ϲheck-old.sh`.\n"),
            ("D7 U+2CA5", "Run `ⲥheck-old.sh`.\n"),
            ("D8 U+1D04", "Run `ᴄheck-old.sh`.\n"),
            ("D9 U+13DF", "Run `ᏟHECK-OLD.SH`.\n"),
            ("suffix letter", "Run `check-old.ѕh`.\n"),
            ("of an existing script", "Run `сheck_new.py`.\n"),
            ("split and non-ASCII", "Run `Ꮯheck-`old.sh.\n"),
        ):
            doc.write_text(text, encoding="utf-8")
            expect(any("look-alike script name" in p for p in check(root)),
                   "R8-#6214-%s: a look-alike script name was accepted" % label)
        doc.write_text("Runs check_`new.py`, [check_](a)[new.py](b) and café-check_new.py, naïve check_new.py.\n",
                       encoding="utf-8")
        probs = check(root)
        expect(not probs, "R8-#6214-control: split or adjacent existing names were rejected (%r)" % (probs,))

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
    for p in problems:
        print("FAIL " + p, file=sys.stderr)
    if problems:
        return 1
    print("compliance script-name anchors ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
