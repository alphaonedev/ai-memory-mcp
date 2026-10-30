#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Paste-safety guard for fenced shell blocks in the docs (#8311).

An interactive zsh without `interactivecomments` treats `#` as an ordinary
word: a pasted `cmd args   # reason` hands the comment words to `cmd` as
operands, and a comment line holding a backtick or `$(` runs the substitution
before the command lookup fails. A reader pastes a fence whole, so every
bash / sh / zsh / console fence must hold commands only.

Scanned: README.md and every docs/**/*.md. Flagged inside a shell fence:

  (a) a command line carrying a ` # comment` (trailing comment);
  (b) a full-line comment containing a backtick or `$(`;
  (c) a full-line `#` comment that sits between two command lines;
  (d) a quote or expansion still open when the fence ends.

A leading `#!` line, a comment-only fence whose comments hold no backtick
or `$(` (class (b) is still flagged there; class (c) needs commands on both
sides), and the text of a heredoc body are not flagged.

Two grammars are modelled, each with the standard library only:

* Markdown, per CommonMark: lines end only at `\\n`, `\\r\\n` or `\\r`
  (2.1); tabs stop every four columns (2.2); block quote (5.1) and list
  item (5.2) containers are followed, so a fence inside `> ` is scanned; a
  fence (4.5) opens at most three columns into its container and closes
  only on a run of the same character, at least as long, at most three
  columns in, with nothing after it but blanks; up to the opening fence's
  indent is removed from each content line. HTML blocks (4.6) are followed
  with the start and end table of the renderer the docs are read through
  (markdown-it / cmark-gfm): a fence-like line inside one opens nothing.
  Where the two renderers differ (a blank line in a list item ends an HTML
  block of types 1-5 in markdown-it, not in cmark-gfm), each doc is read
  both ways and the hits of both are kept, so the guard fails closed under
  either. What is scanned is the text a reader copies out of the page.
* Shell, per bash: one lexer, shared by the heredoc and comment checks,
  carries quote (`'..'`, `"..."`, `$'..'`), command substitution (`$( )`
  and backticks, both lexed as code) and expansion (`${ }`, `$(( ))`,
  `(( ))`, `$[ ]`) state across lines and joins backslash-continued lines.
  A backtick substitution ends at the first unescaped backtick, whatever
  quote is open inside it. `((` and `$((` are read as arithmetic or as
  subshells when the opener is pushed, as bash's parser does, by a capped
  lookahead that answers subshell when it cannot tell.
  A `#` starts a comment only at the start of a word and outside quotes and
  `${ }` / arithmetic; a heredoc operator counts only where a command could
  be (not in quotes, a comment, `${ }` or arithmetic, not inside backticks,
  and not `<<<`). Its body starts after the whole logical line and ends
  only on the exact terminator line (`<<-` drops leading tabs; an unquoted
  word joins backslash-continued body lines first). A heredoc whose
  terminator never appears is not trusted: its would-be body is scanned as
  normal lines. Once a frame is found still open at the end of the fence,
  the rest of the fence is scanned one physical line at a time with no
  heredoc skip, so the work stays linear. Every doubt is resolved by
  scanning, never by skipping.

OPT-OUT MARKER (one, explicit): a fence whose FIRST line is exactly
`# not-for-paste` is documentation of a script body, not a paste target; the
guard skips that fence. Move comments above the fence as prose instead of
using the marker wherever the block is meant to be pasted.

Run: python3 -I -m unittest discover -s scripts/ci/tests -p test_docs_shell_paste_safe_8311.py
"""
import bisect
import collections
import pathlib
import re
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
SHELL_LANGS = {"bash", "sh", "zsh", "console", "shell"}
MARKER = "# not-for-paste"

# ---- Markdown (CommonMark) ------------------------------------------------

LINE_END_RE = re.compile(r"\r\n|\r|\n")
FENCE_OPEN_RE = re.compile(r"(`{3,}|~{3,})(.*)$")
LANG_RE = re.compile(r"[A-Za-z0-9_+-]*")
LIST_RE = re.compile(r"[-+*]|(\d{1,9})[.)]")
THEMATIC_RE = re.compile(r"[ \t]*([-*_])(?:[ \t]*\1){2,}[ \t]*$")
ATX_RE = re.compile(r"[ \t]*#{1,6}(?:[ \t]|$)")
SETEXT_RE = re.compile(r"[ \t]*(?:=+|-+)[ \t]*$")
TAB = 4

# CommonMark 4.6 HTML blocks, as markdown-it 2.2.0 and cmark-gfm read them
# (the renderers the docs are read through): (type, start, end markers).
# Types 1-5 end on the line that contains one of their end markers; the
# spec states each end condition as a literal string (type 1 compared
# without regard to case), so it is tested with `in`, not a regex:
# this models a renderer, it is not an HTML sanitizer. Types 6-7 have no
# marker (()) and end before a blank line.
HTML_TAGS = (
    "address article aside base basefont blockquote body caption center col "
    "colgroup dd details dialog dir div dl dt fieldset figcaption figure footer "
    "form frame frameset h1 h2 h3 h4 h5 h6 head header hr html iframe legend li "
    "link main menu menuitem nav noframes ol optgroup option p param section "
    "source summary table tbody td tfoot th thead title tr track ul"
).split()
HTML_ATTR = (
    r"""(?:\s+[a-zA-Z_:][a-zA-Z0-9:._-]*"""
    r"""(?:\s*=\s*(?:[^"'=<>`\x00-\x20]+|'[^']*'|"[^"]*"))?)"""
)
HTML_TAG = (
    r"(?:<[A-Za-z][A-Za-z0-9\-]*" + HTML_ATTR + r"*\s*/?>|</[A-Za-z][A-Za-z0-9\-]*\s*>)"
)
HTML_RAW_ENDS = ("</script>", "</pre>", "</style>", "</textarea>")
HTML_BLOCKS = (
    (1, re.compile(r"<(?:script|pre|style|textarea)(?=\s|>|$)", re.I), HTML_RAW_ENDS),
    (2, re.compile(r"<!--"), ("-->",)),
    (3, re.compile(r"<\?"), ("?>",)),
    (4, re.compile(r"<![A-Z]"), (">",)),
    (5, re.compile(r"<!\[CDATA\["), ("]]>",)),
    (6, re.compile(r"</?(?:%s)(?=\s|/?>|$)" % "|".join(HTML_TAGS), re.I), ()),
    (7, re.compile(HTML_TAG + r"\s*$"), ()),
)
# Case folding for the type 1 close tags: ASCII, plus the four letters that
# Python's re.I (and so markdown-it-py) also folds onto an ASCII letter.
HTML_CASE_FOLD = dict(zip(range(ord("A"), ord("Z") + 1), "abcdefghijklmnopqrstuvwxyz"))
HTML_CASE_FOLD.update({0x130: "i", 0x131: "i", 0x17F: "s", 0x212A: "k"})


def split_lines(text):
    """Split on the CommonMark (and shell) line endings only. str.splitlines
    also breaks on VT, FF, FS/GS/RS, NEL and U+2028/U+2029, which would fake
    a terminator line that neither the renderer nor the shell sees."""
    lines = LINE_END_RE.split(text)
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def lead_width(text, col):
    """Columns of leading blanks of `text` starting at column `col`, and the
    index of the first non-blank character (tab stops every 4 columns)."""
    width = 0
    i = 0
    while i < len(text) and text[i] in " \t":
        width += TAB - (col + width) % TAB if text[i] == "\t" else 1
        i += 1
    return width, i


def strip_cols(text, col, n):
    """Remove up to `n` columns of leading blanks; a tab consumed only in part
    leaves its remaining columns as spaces (CommonMark). Returns (rest, col)."""
    removed = 0
    i = 0
    while i < len(text) and removed < n and text[i] in " \t":
        width = 1 if text[i] == " " else TAB - (col + removed) % TAB
        if removed + width > n:
            return " " * (removed + width - n) + text[i + 1:], col + n
        removed += width
        i += 1
    return text[i:], col + removed


def quote_marker(text, col):
    """Consume a block quote marker (`>` and one optional blank)."""
    width, i = lead_width(text, col)
    if width > 3 or i >= len(text) or text[i] != ">":
        return None
    rest, col = text[i + 1:], col + width + 1
    if rest[:1] in (" ", "\t"):
        rest, col = strip_cols(rest, col, 1)
    return rest, col


def list_marker(text, col, para):
    """Consume a list item marker. Returns (rest, col, content width) or None.
    With `para` set, only a marker that may interrupt a paragraph counts."""
    width, i = lead_width(text, col)
    if width > 3 or THEMATIC_RE.match(text):
        return None
    m = LIST_RE.match(text, i)
    if not m:
        return None
    after = text[m.end():]
    if after and after[0] not in " \t":
        return None
    blank = not after.strip()
    if para and (blank or (m.group(1) and m.group(1) != "1")):
        return None
    mlen = len(m.group(0))
    mcol = col + width + mlen
    if blank:
        return "", mcol, width + mlen + 1
    gap, _ = lead_width(after, mcol)
    if gap > 4:
        gap = 1
    rest, rcol = strip_cols(after, mcol, gap)
    return rest, rcol, width + mlen + gap


def fence_open(text, col):
    """Return (char, run, indent, lang) when `text` opens a fence."""
    width, i = lead_width(text, col)
    if width > 3:
        return None
    m = FENCE_OPEN_RE.match(text, i)
    if not m or (m.group(1)[0] == "`" and "`" in m.group(2)):
        return None
    lang = LANG_RE.match(m.group(2).strip()).group(0).lower()
    return m.group(1)[0], len(m.group(1)), width, lang


def fence_closes(text, col, char, run):
    """CommonMark closing fence: same character, at least as long, at most
    three columns in, nothing after it but blanks."""
    width, i = lead_width(text, col)
    if width > 3:
        return False
    return re.fullmatch(re.escape(char) + "{%d,}[ \t]*" % run, text[i:]) is not None


def html_start(text, col, para):
    """Return the end markers of the HTML block (CommonMark 4.6) that `text`
    starts ((), never None, for types 6-7), or None. With `para` set, only
    types 1-6 count (type 7 cannot interrupt a paragraph)."""
    width, i = lead_width(text, col)
    if width > 3 or text[i:i + 1] != "<":
        return None
    for kind, start, end in HTML_BLOCKS:
        if start.match(text, i):
            return None if kind == 7 and para else end
    return None


def starts_block(text, col):
    """True when `text` cannot be a lazy paragraph continuation line. The
    innermost matched container is not the paragraph, so any list marker
    may start a block here (as in cmark)."""
    if not text.strip() or quote_marker(text, col) or fence_open(text, col):
        return True
    if lead_width(text, col)[0] <= 3 and (THEMATIC_RE.match(text) or ATX_RE.match(text)):
        return True
    if html_start(text, col, True) is not None:
        return True
    return list_marker(text, col, False) is not None


def match_containers(stack, line):
    """Match `line` against the open containers, outermost first:
    ["q", 0, False] a block quote; ["li", width, empty] a list item, `empty`
    while it holds only the blank rest of its marker line.

    Returns (rest, col, matched): the text after the matched container
    prefixes, its column, and how many containers matched."""
    rest, col = line, 0
    matched = 0
    for entry in stack:
        kind, width, empty = entry
        if kind == "q":
            got = quote_marker(rest, col)
            if got is None:
                break
            rest, col = got
        elif not rest.strip():
            if empty:
                break  # an item begins with at most one blank line
            rest, col = strip_cols(rest, col, width)
        else:
            if lead_width(rest, col)[0] < width:
                break
            rest, col = strip_cols(rest, col, width)
            entry[2] = False
        matched += 1
    return rest, col, matched


def open_containers(stack, rest, col, para):
    """Open every block quote and list item that starts `rest`.

    Returns (rest, col, para) after their markers."""
    while True:
        got = quote_marker(rest, col)
        if got is not None:
            rest, col = got
            stack.append(["q", 0, False])
            para = False
            continue
        got = list_marker(rest, col, para)
        if got is not None:
            rest, col, width = got
            stack.append(["li", width, not rest.strip()])
            para = False
            continue
        return rest, col, para


def html_ended(end, rest):
    """True when `rest` ends an open HTML block with end markers `end`
    (CommonMark 4.6): it contains one of the literal markers (case folded
    by HTML_CASE_FOLD, which only matters for the type 1 close tags), or,
    for types 6-7 (no markers), it is blank."""
    if not end:
        return rest.strip(" \t") == ""
    folded = rest.translate(HTML_CASE_FOLD)
    return any(marker in folded for marker in end)


def html_item_blank(stack, rest):
    """True for a blank line inside a list item. markdown-it ends an HTML
    block of types 1-5 there; CommonMark and cmark-gfm (what GitHub renders)
    keep it open. fences() takes either reading and scan_text() unions the
    hits of both, so neither renderer can show a fence the guard skipped."""
    return not rest.strip() and any(entry[0] == "li" for entry in stack)


def never(stack, rest):
    """The cmark-gfm reading of html_item_blank(): a blank line never ends
    an HTML block of types 1-5."""
    return False


def fences(text, item_blank_ends_html=True):
    """Yield (lang, first_body_line_no, [content lines]) per fenced block:
    what CommonMark renders, container prefixes and up to the opening
    fence's indent removed. `item_blank_ends_html`: True is the markdown-it
    reading of html_item_blank(), False the cmark-gfm one."""
    item_blank = html_item_blank if item_blank_ends_html else never
    stack = []  # open containers, as match_containers() describes them
    fence = html = None  # html: end markers of the open HTML block
    para = False
    for no, line in enumerate(split_lines(text), 1):
        rest, col, matched = match_containers(stack, line)
        whole = matched == len(stack)
        if fence is not None:
            if whole:
                if fence_closes(rest, col, fence[0], fence[1]):
                    yield fence[3], fence[4], fence[5]
                    fence = None
                else:
                    fence[5].append(strip_cols(rest, col, fence[2])[0])
                continue
            # A container closed under the fence, so the fence closed too
            # (fenced code is never a lazy continuation).
            yield fence[3], fence[4], fence[5]
            fence = None
            para = False
        if html is not None:
            if whole:
                if html_ended(html, rest) or item_blank(stack, rest):
                    html = None  # its end line (types 1-5) or a blank line
                continue
            html = None  # an HTML block ends with its container
        if matched < len(stack):
            if para and not starts_block(rest, col):
                continue  # lazy paragraph continuation line
            del stack[matched:]
            para = False
        rest, col, para = open_containers(stack, rest, col, para)
        if not rest.strip():
            para = False
            continue
        opened = fence_open(rest, col)
        if opened:
            char, run, indent, lang = opened
            fence = [char, run, indent, lang, no + 1, []]
            para = False
            continue
        end = html_start(rest, col, para)
        if end is not None:
            html = None if html_ended(end, rest) else end
            para = False
            continue
        if lead_width(rest, col)[0] > 3:
            continue  # indented code, or paragraph continuation text
        if THEMATIC_RE.match(rest) or ATX_RE.match(rest) or (para and SETEXT_RE.match(rest)):
            para = False
            continue
        para = True
    if fence is not None:
        yield fence[3], fence[4], fence[5]


# ---- Shell (bash) -----------------------------------------------------------

HEREDOC_RE = re.compile(r"<<(-?)[ \t]*(?=[A-Za-z_'\"\\])")
WORD_END = " \t;&|<>()"
WORD_START = " \t;&|()<>\n`"  # a `#` after one of these starts a comment
QUOTES = ("'", '"', "$'", "`")  # open at line end: defer the heredoc skip
# The outer frame of a `((` that bash re-reads as two nested subshells. Its
# text is parsed again on its own, so a heredoc started in it takes no body
# from the lines after it (bash -c runs them as commands), as in backticks.
REREAD = "(sub"
SUBSHELLS = ("(", REREAD)  # code frames that may stay open at the fence end
CODE = (None, "(", "`", REREAD)  # frames where a command (heredoc, comment) can be
LOOKAHEAD_CAP = 4096  # characters one (( or $(( opener may look ahead
OPEN_REASON = "quote or expansion still open at the end of the fence"
TRAIL = "trailing comment on a command line"


class Frames(list):
    """The open-frame stack. It counts its backtick and re-read frames, so
    "is a backtick open" costs O(1) however deep the stack grows."""

    def __init__(self):
        super().__init__()
        self.ticks = 0
        self.rereads = 0

    def __eq__(self, other):
        # ticks and rereads are derived from the items, so list equality is exact
        return list.__eq__(self, other)

    __hash__ = None

    def append(self, frame):
        list.append(self, frame)
        if frame == "`":
            self.ticks += 1
        elif frame == REREAD:
            self.rereads += 1

    def extend(self, frames):
        for frame in frames:
            self.append(frame)

    def pop(self):
        frame = list.pop(self)
        if frame == "`":
            self.ticks -= 1
        elif frame == REREAD:
            self.rereads -= 1
        return frame


LOOK_STOPS = {
    None: re.compile(r"\$\$|[()'\"\\`]|\$\((?!\()|\$'"),  # `$$` first: the PID
    "'": re.compile(r"'"),
    "$'": re.compile(r"['\\]"),  # ANSI-C: a backslash escapes the next character
    '"': re.compile(r'\$\$|["\\`]|\$\((?!\()'),  # `$$` first: the PID
}


class Lookahead:
    """Decide arithmetic or subshell when a `((` or `$((` opener is pushed,
    as bash does (parse_dparen, parse_arith_cmd): the text after the opener
    up to the `)` that closes its inner `(` (parens counted, quotes and
    backslashes skipped; inside an ANSI-C `$'..'` a backslash escapes the
    quote, as in QUOTES, and a `$$`, in code or in "...", is the PID
    parameter, so the quote after it is plain, also when a backslash-newline
    splits it, as bash drops that first; a lone `$` split that way from a
    quote opens `$'`, and from a `(` a `$(`) must be followed at once by
    `)`; otherwise bash re-reads `((` as two nested subshells and `$((` as
    `$( (..) )`.
    bash's scan reads a backtick span or a `$( )` as commands (fresh
    quoting, `#` comments), which a paren count cannot follow, so a
    backtick or a `$(` that is not `$((`, in code or in double quotes,
    answers subshell (fails closed).

    Bounded: one lookahead reads at most LOOKAHEAD_CAP characters, and all
    lookaheads over one fence share a budget of its length plus the cap, so
    the work stays linear. A lookahead that reaches the fence end (or the
    line end, with `single`), the cap or the budget, in any quote state
    (ANSI-C included), answers subshell: code, where a comment is seen,
    which fails closed."""

    def __init__(self, lines, single=False):
        self.lines = lines
        self.single = single
        self.budget = sum(len(line) + 1 for line in lines) + LOOKAHEAD_CAP

    def at(self, k):
        """The lookahead for openers on line `k`: col -> True (arithmetic)."""
        return lambda col: self.arith(k, col)

    def arith(self, k, col):
        """True when the inner text that starts at lines[k][col] closes with
        `))`, read as bash's matched-pair scan reads it. Characters between
        the ones that matter are skipped by a regex search, but still count
        against the cap and the budget."""
        left = min(LOOKAHEAD_CAP, self.budget)
        self.budget -= left  # charged up front; the unused part is refunded
        depth = 0
        quote = None
        lone = False  # the last line ended in a lone `$` and a backslash
        while k < len(self.lines):
            line = self.lines[k]
            if lone:  # bash joins the lone `$` with this line's start
                pair = self.joined(line, quote)
                if pair is None:
                    self.budget += left
                    return False  # a split `$(`: command substitution
                col, quote = pair
                left -= col
            lone, used = False, -1  # used: the column after a `$$` or `\x`
            while True:
                m = LOOK_STOPS[quote].search(line, col)
                left -= (m.end() if m else len(line)) - col
                if left < 0:
                    return False  # cap or budget reached: subshell
                if m is None:
                    break
                ch, col = m.group(), m.end()
                if ch == "\\":
                    lone = col == len(line) and line[col - 2:col - 1] == "$" and used != col - 1
                    col += 1
                    used = col
                elif ch == "$$":
                    used = col  # the PID parameter, read before any quote after it
                elif ch == "$'":
                    quote = ch  # only LOOK_STOPS[None] matches it
                elif ch == "`" or ch.startswith("$("):
                    self.budget += left
                    return False  # command substitution: subshell
                elif quote is not None or ch in "'\"":
                    quote = None if quote is not None else ch
                elif ch == "(":
                    depth += 1
                elif depth:
                    depth -= 1
                else:
                    self.budget += left
                    return line.startswith(")", col)
            if self.single:
                break
            k, col, left = k + 1, 0, left - 1
        self.budget += max(left, 0)
        return False  # no closing paren before the fence (or line) end

    @staticmethod
    def joined(line, quote):
        """Read a lone `$` that ended the last line before a backslash with
        the start of `line`, as bash does once it drops the backslash-newline:
        returns (col to read from, quote), or None for a `$(` (a command
        substitution: subshell). `$$` is the PID; in code a quote after it
        opens an ANSI-C `$'`; in '..' or $'..' the `$` was literal."""
        if quote not in (None, '"') or not line:
            return 0, quote
        if line[0] == "(" and not line.startswith("(("):
            return None
        if line[0] == "$":
            return 1, quote
        if line[0] == "'" and quote is None:
            return 1, "$'"
        return 0, quote


def parse_heredoc_word(line, start):
    """Parse the delimiter word at `start`: it runs to whitespace or a shell
    metachar outside quotes, and quote characters and backslashes are dropped
    (`E"OF"` and `\\EOF` both give `EOF`, as in bash).
    Returns (word, end index, quoted)."""
    out = []
    quote = None
    quoted = False
    i = start
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == quote:
                quote = None
            else:
                out.append(ch)
        elif ch in "'\"":
            quote = ch
            quoted = True
        elif ch == "\\":
            quoted = True
            i += 1
            if i < len(line):
                out.append(line[i])
        elif ch in WORD_END:
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out), i, quoted


def open_expansion(line, i, stack, ahead):
    """Push `$((`, `$(`, `${` or `$[` at `i`; return the characters used.
    `$((` is arithmetic only when `ahead` (a Lookahead) says so; otherwise
    it is `$( (..) )`, two code frames."""
    if line[i] != "$":
        return 0
    if line.startswith("$((", i):
        stack.extend(("((",) if ahead(i + 3) else ("(", "("))
        return 3
    for token, frame in (("$(", "("), ("${", "${"), ("$[", "$[")):
        if line.startswith(token, i):
            stack.append(frame)
            return len(token)
    return 0


def close_backtick(stack):
    """Pop every frame through the innermost backtick frame: bash ends a
    backtick substitution at the first unescaped backtick, whatever quote,
    group or expansion was opened inside it."""
    while stack.pop() != "`":
        pass


def lex_quoted(line, i, stack, ahead):
    """One step inside a `'..'`, `"..."` or `$'..'` frame at `i`. Returns
    (next index, prev), or None when a backslash continues the line."""
    top, ch = stack[-1], line[i]
    if stack.ticks:
        # Inside backticks a quote does not hide the closing backtick; only
        # a backslash escapes it (also inside '..', where \\ and \` are the
        # escapes bash removes before it re-reads the substitution).
        if top == "'" and line.startswith(("\\`", "\\\\"), i):
            return i + 2, line[i + 1]
        if ch == "`":
            close_backtick(stack)
            return i + 1, ch
    if top == "'":
        if ch == "'":
            stack.pop()
        return i + 1, ch
    if ch == "\\":
        if i + 1 == len(line):
            return None
        return i + 2, "x"  # an escaped `$` pairs with no `$` after it
    if ch == ("'" if top == "$'" else top):
        stack.pop()
        return i + 1, ch
    used = 0
    if top == '"':
        if ch == "`":
            stack.append("`")  # command substitution: lexed as code
            used = 1
        elif line.startswith("$$", i):
            # The PID: bash's parser opens no `$(`, `${` or `$[` at the
            # second `$` (`bash -n` accepts "$$(" whole).
            return i + 2, "x"
        else:
            used = open_expansion(line, i, stack, ahead)
    if used:
        return i + used, line[i + used - 1]
    return i + 1, ch


def lex_operator(line, i, stack, top, ahead):
    """Open or close a quote, substitution, expansion or group frame at `i`
    in a code frame. Returns the characters used (0 for none)."""
    ch = line[i]
    if ch == "$":
        if line.startswith("$$", i):
            return 2  # the PID parameter: a quote after it opens no `$'`
        if line.startswith("$'", i):
            stack.append("$'")
            return 2
        if line.startswith('$"', i):
            stack.append('"')
            return 2
        return open_expansion(line, i, stack, ahead)
    if ch == "`" and stack.ticks:
        close_backtick(stack)
        return 1
    if ch in "'\"`":
        stack.append(ch)
        return 1
    if top in CODE and line.startswith("((", i):
        # Decided at the opener, as bash's parser does (Lookahead).
        stack.extend(("((",) if ahead(i + 2) else (REREAD, "("))
        return 2
    if ch == "(" and top in (None, "(", "((", "`", REREAD):
        stack.append("(")
        return 1
    if ch == ")" and top in SUBSHELLS:
        stack.pop()
        return 1
    if top == "((" and line.startswith("))", i):
        stack.pop()
        return 2
    if ch == ")" and top == "((":
        # Fallback for a frame the lookahead read as arithmetic while the
        # lexer sees the inner part close first: re-read it as a subshell.
        stack.pop()
        stack.append(REREAD)
        return 1
    if ch == "}" and top == "${":
        stack.pop()
        return 1
    if ch == "[" and top == "$[":
        stack.append("$[")
        return 1
    if ch == "]" and top == "$[":
        stack.pop()
        return 1
    return 0


def lex_line(line, stack, prev="\n", ahead=None):
    """Lex one physical line with the bash quoting and expansion rules,
    continuing (and updating) the open-frame `stack`. `prev` is the
    character before the line (a newline, or the one before a `\\` that
    continued the previous line); `ahead` decides `((` openers (Lookahead,
    this line alone by default). Returns (comment index or None,
    [(word, strips_tabs, quoted)] heredocs opened, continued, prev)."""
    ahead = ahead or Lookahead([line], True).at(0)
    heredocs = []
    comment = None
    i, prev = pid_tail(line, stack, prev, ahead)
    n = len(line)
    while i < n:
        ch = line[i]
        top = stack[-1] if stack else None
        if top in ("'", '"', "$'"):
            step = lex_quoted(line, i, stack, ahead)
            if step is None:
                return comment, heredocs, True, prev
            i, prev = step
            continue
        # Code frames: top level, $( ), backticks, ${ }, (( )), $[ ].
        if ch == "\\":
            if i + 1 == n:
                return comment, heredocs, True, prev
            prev = "x"  # an escaped character is part of a word
            i += 2
            continue
        used = lex_operator(line, i, stack, top, ahead)
        if not used and top in CODE:
            if ch == "#" and prev in WORD_START:
                comment = i if comment is None else comment
                # A comment inside backticks ends at the closing backtick,
                # which bash finds before it reads the substitution.
                end = backtick_end(line, i) if stack.ticks else -1
                if end < 0:
                    return comment, heredocs, False, prev
                close_backtick(stack)
                prev = "`"
                i = end + 1
                continue
            if line.startswith("<<<", i):
                used = 3
            elif line.startswith("<<", i):
                m = HEREDOC_RE.match(line, i)
                word, end, quoted = parse_heredoc_word(line, m.end()) if m else ("", i, False)
                # Inside backticks (or a re-read `((`) bash parses the text
                # alone, so the outer lines are never its body: no skip there.
                if word and not (stack.ticks or stack.rereads):
                    heredocs.append((word, bool(m.group(1)), quoted))
                    prev = "x"
                    i = end
                    continue
                used = 2
        used = used or 1
        prev = "x" if line[i:i + used] == "$$" else line[i + used - 1]
        i += used
    return comment, heredocs, False, prev


def pid_tail(line, stack, prev, ahead):
    """bash drops a backslash-newline before it lexes, so a lone `$` right
    before the backslash (`prev`) joins the first character of this line:
    with a `$` it is the PID `$$`; in code a quote makes an ANSI-C `$'`;
    in code or in "..." a `(`, `{` or `[` opens `$(`, `${` or `$[`.
    Returns (index to lex from, prev). In '..' or $'..' a `$` is literal."""
    top = stack[-1] if stack else None
    if prev != "$" or not line or top in ("'", "$'"):
        return 0, prev
    if line[0] == "$":
        return 1, "x"
    if line[0] == "'" and top != '"':
        stack.append("$'")
        return 1, "'"
    if line[0] not in "({[":
        return 0, prev
    used = open_expansion("$" + line, 0, stack, lambda col: ahead(col - 1))
    return used - 1, line[used - 2]


def backtick_end(line, i):
    """Index of the first unescaped backtick at or after `i`, or -1."""
    while i < len(line):
        if line[i] == "`":
            return i
        i += 2 if line[i] == "\\" else 1
    return -1


class Terminators:
    """Index of the heredoc terminator candidates of one fence body, so an
    unterminated heredoc costs a lookup, not a scan to the end of the fence.

    A body line group is a run of lines joined by backslash continuation
    (only for an unquoted delimiter); groups end at the same lines from any
    start that is itself a group start."""

    def __init__(self, lines):
        self.lines = lines
        self.cache = {}

    def joined(self, k, strips_tabs, quoted):
        """Return (text, last index) of the group that starts at line `k`."""
        lines = self.lines
        last = k
        # `<<-` drops the leading tabs of the line; an unquoted delimiter
        # makes bash join backslash-continued body lines (whose own tabs
        # stay) before the exact compare.
        # Built from parts, so a long run joins in linear time: the joined
        # text ends in an odd backslash run exactly when its last part does
        # (what precedes that part ends in an even run).
        text = lines[k].lstrip("\t") if strips_tabs else lines[k]
        parts = []
        while not quoted and last + 1 < len(lines) and trailing_backslash(text):
            parts.append(text[:-1])
            last += 1
            text = lines[last]
        parts.append(text)
        return "".join(parts), last

    def table(self, strips_tabs, quoted):
        """{group text: ([group start], [group end])} for one heredoc mode."""
        key = (strips_tabs, quoted)
        if key not in self.cache:
            out = {}
            k = 0
            while k < len(self.lines):
                text, last = self.joined(k, strips_tabs, quoted)
                starts, ends = out.setdefault(text, ([], []))
                starts.append(k)
                ends.append(last)
                k = last + 1
            self.cache[key] = out
        return self.cache[key]

    def find(self, word, strips_tabs, quoted, j):
        """Index of the last line of the first group from `j` that equals
        `word`, or None."""
        lines = self.lines
        if j >= len(lines):
            return None
        if not quoted and j > 0 and trailing_backslash(lines[j - 1]):
            # `j` is inside a continued run: its first group is its own.
            text, last = self.joined(j, strips_tabs, quoted)
            if text == word:
                return last
            j = last + 1
        starts, ends = self.table(strips_tabs, quoted).get(word, ((), ()))
        at = bisect.bisect_left(starts, j)
        return ends[at] if at < len(starts) else None


def skip_heredocs(lines, start, pending, index=None):
    """Return the index after the last terminator of `pending` heredocs whose
    bodies start at `start`. A heredoc with no terminator is not trusted:
    scanning resumes where its body would have started."""
    index = index or Terminators(lines)
    j = start
    for word, strips_tabs, quoted in pending:
        found = index.find(word, strips_tabs, quoted, j)
        if found is None:
            return j
        j = found + 1
    return j


def trailing_backslash(text):
    """True when `text` ends in an odd run of backslashes (a continuation)."""
    run = len(text) - len(text.rstrip("\\"))
    return run % 2 == 1


def scan_logical(lines, first_no, kinds, hits):
    """Scan `lines` as bash reads them: logical lines, frames carried across
    lines, heredoc bodies skipped. Appends to `kinds` and `hits`; returns
    the index of the logical line still holding an open quote or expansion
    at the end of the fence, or None."""
    index = Terminators(lines)
    look = Lookahead(lines)
    i = 0
    stack = Frames()
    cont = False
    prev = "\n"
    pending = []
    start = None  # index of the first line of the current logical line
    while i < len(lines):
        raw = lines[i]
        no = first_no + i
        if not stack and not cont:
            s = raw.strip()
            if not s:
                i += 1
                continue
            if s.startswith("#"):
                kinds.append((no, "comment", s))
                i += 1
                continue
            kinds.append((no, "command", s))
            start = i
            prev = "\n"
        at, docs, cont, prev = lex_line(raw, stack, prev, look.at(i))
        if at is not None:
            hits.append((no, TRAIL))
        pending.extend(docs)
        i += 1
        if cont or (stack and stack[-1] in QUOTES):
            if not cont:
                prev = "\n"
            continue
        prev = "\n"
        if pending:
            i = skip_heredocs(lines, i, pending, index)
            pending = []
    return start if any(f not in SUBSHELLS for f in stack) else None


def scan_physical(lines, first_no, begin, kinds, hits):
    """Scan `lines[begin:]` one physical line at a time with a fresh frame
    stack each, and skip no heredoc. Linear, and fails closed: used once a
    frame was left open, when the logical reading can no longer be trusted.
    A line that leaves a frame (other than a subshell) open is flagged."""
    look = Lookahead(lines[begin:], True)
    for i in range(begin, len(lines)):
        no = first_no + i
        s = lines[i].strip()
        if not s:
            continue
        if s.startswith("#"):
            kinds.append((no, "comment", s))
            continue
        kinds.append((no, "command", s))
        stack = Frames()
        at = lex_line(lines[i], stack, "\n", look.at(i - begin))[0]
        if at is not None:
            hits.append((no, TRAIL))
        if any(f not in SUBSHELLS for f in stack):
            hits.append((no, OPEN_REASON))


def comment_hits(kinds):
    """Classes (b) and (c) over the classified lines of one fence."""
    cmds = [idx for idx, (_, kind, _) in enumerate(kinds) if kind == "command"]
    out = []
    for idx, (no, kind, s) in enumerate(kinds):
        if kind == "command" or s.startswith("#!"):
            continue
        if "`" in s or "$(" in s:
            out.append((no, "comment line holds a backtick or $("))
        elif cmds and cmds[0] < idx < cmds[-1]:
            out.append((no, "comment line between two commands"))
    return out


def scan_block(first_no, body, indent=""):
    """Return [(line_no, reason)] for one shell fence body. `indent` is the
    opening fence's indent for a raw body; up to that many columns are
    removed from each line first (fences() has already done so)."""
    lines = [strip_cols(raw, 0, len(indent))[0] for raw in body]
    if lines and lines[0].strip() == MARKER:
        return []
    kinds = []  # (line_no, "command" | "comment", text)
    hits = []
    start = scan_logical(lines, first_no, kinds, hits)
    if start is not None:
        # (d): a quote or expansion is still open. Skip nothing: flag the
        # line it opened on and rescan the lines after it.
        no = first_no + start
        kinds = [k for k in kinds if k[0] <= no]
        hits = [h for h in hits if h[0] <= no]
        hits.append((no, OPEN_REASON))
        scan_physical(lines, first_no, start + 1, kinds, hits)
    hits.extend(comment_hits(kinds))
    return sorted(hits, key=lambda h: h[0])


def scan_fences(blocks):
    """Return [(line_no, reason)] for the shell fences among `blocks`."""
    out = []
    for lang, first_no, body in blocks:
        if lang in SHELL_LANGS:
            out.extend(scan_block(first_no, body))
    return out


def scan_text(text):
    """Return [(line_no, reason)] for every shell fence in a Markdown text,
    under both renderer readings of a blank line in a list item inside an
    HTML block (html_item_blank). The union is kept, counted as a multiset
    (a hit the two readings share counts once), so the guard fails closed
    under markdown-it and under cmark-gfm alike."""
    first = list(fences(text, True))
    second = list(fences(text, False))
    out = scan_fences(first)
    if second == first:
        return out
    extra = collections.Counter(scan_fences(second)) - collections.Counter(out)
    return sorted(out + list(extra.elements()), key=lambda h: h[0])


def scan_file(path):
    rel = path.relative_to(ROOT).as_posix()
    text = path.read_text(encoding="utf-8", errors="replace")
    return ["%s:%d: %s" % (rel, no, why) for no, why in scan_text(text)]


def doc_files():
    files = [ROOT / "README.md"] + sorted((ROOT / "docs").rglob("*.md"))
    return [f for f in files if f.is_file()]


BASELINE = ROOT / "scripts" / "qc-allowlists" / "docs-shell-paste-baseline-8311.txt"
STRICT = ("docs/DEV-CI-ENVIRONMENT.md", "docs/DEVELOPER_SETUP_NOTES.md")


def read_baseline():
    """Parse `<count> <path>` lines; `#` lines are comments."""
    out = {}
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            n, rel = line.split(None, 1)
            out[rel] = int(n)
    return out


def current_counts():
    counts, detail = {}, {}
    for f in doc_files():
        hits = scan_file(f)
        rel = f.relative_to(ROOT).as_posix()
        if hits:
            counts[rel] = len(hits)
            detail[rel] = hits
    return counts, detail


SCAN_BUDGET_S = 2.0  # a 20000-line fence of any shape scans within this


class DocsShellPasteSafe8311(unittest.TestCase):
    """The two files named by #8311 must be clean; every other doc is held
    to a ratchet baseline that may only fall (thresholds rise, never fall)."""

    def test_8311_named_docs_are_paste_safe(self):
        _, detail = current_counts()
        found = [h for rel in STRICT for h in detail.get(rel, [])]
        self.assertEqual(
            found, [], "%d paste hazard(s):\n%s" % (len(found), "\n".join(found))
        )

    def test_8311_other_docs_do_not_regress(self):
        counts, _ = current_counts()
        base = read_baseline()
        for rel in STRICT:
            self.assertNotIn(rel, base, "%s must not be baselined" % rel)
        worse = [
            "%s: %d > baseline %d" % (rel, n, base.get(rel, 0))
            for rel, n in sorted(counts.items())
            if rel not in STRICT and n > base.get(rel, 0)
        ]
        self.assertEqual(worse, [], "new paste hazards:\n" + "\n".join(worse))
        stale = [
            "%s: baseline %d, now %d" % (rel, n, counts.get(rel, 0))
            for rel, n in sorted(base.items())
            if counts.get(rel, 0) < n
        ]
        self.assertEqual(
            stale, [], "lower the baseline (it only falls):\n" + "\n".join(stale)
        )

    def test_8311_scanner_flags_each_shape(self):
        body = ["a --x   # why", "# note", "b", "echo `x`", "# `y`", "# end"]
        got = {why for _, why in scan_block(1, body)}
        self.assertEqual(
            got,
            {
                TRAIL,
                "comment line between two commands",
                "comment line holds a backtick or $(",
            },
        )
        # S1: class (b) in a comment-only fence.
        self.assertEqual(len(scan_block(1, ["# run `id` first"])), 1)
        self.assertEqual(len(scan_block(1, ["# a", "# $(id)"])), 1)
        # S2/F2: a false heredoc must not hide the next line's hazard.
        for first in (
            "cat <<<word",
            "echo $((1<<FOO))",
            'echo "<<EOF"',
            "echo '<<EOF'",
        ):
            self.assertEqual(len(scan_block(1, [first, "a # b"])), 1, first)
        # An unterminated heredoc is rescanned as normal lines.
        self.assertEqual(len(scan_block(1, ["cat <<EOF", "a # b"])), 1)
        # `<<\EOF` is a quoted-word heredoc: its body is not flagged.
        self.assertEqual(scan_block(1, ["cat <<\\EOF", "a # b", "EOF", "ls"]), [])

    def test_8311_heredoc_ends_only_on_exact_terminator(self):
        # S3: an indented or space-padded line is not a terminator, so the
        # second heredoc stays inside the first and the hazard is seen.
        pad_in = ["data <<X", "EOF", "ls # hazard", "X"]
        for opener, mid in (
            ("cat <<EOF", " EOF"),
            ("cat <<EOF", "EOF "),
            ('cat <<E"OF"', "E"),
            ('cat <<E"OF"', " EOF"),
        ):
            body = [opener, mid] + pad_in
            self.assertEqual(len(scan_block(1, body)), 1, body)
        # An unterminated heredoc is rescanned (the padded line is a command).
        self.assertEqual(len(scan_block(1, ["cat <<EOF", " EOF", "ls # hazard"])), 1)
        # S4: legacy `$[ ]` arithmetic opens no heredoc.
        self.assertEqual(len(scan_block(1, ["echo $[1<<FOO]", "ls # hazard", "FOO"])), 1)

    def test_8311_heredoc_terminator_forms_stay_clean(self):
        # A list-indented fence: the terminator carries only the fence indent.
        self.assertEqual(
            scan_block(1, ["cat <<EOF", "a # b", "  EOF", "ls"], "  "), []
        )
        # `EOFX` never ends an `EOF` heredoc; quoted words reduce to `EOF`.
        self.assertEqual(scan_block(1, ["cat <<EOF", "a # b", "EOFX", "EOF", "ls"]), [])
        self.assertEqual(scan_block(1, ['cat <<E"OF"', "a # b", "EOF", "ls"]), [])
        # `<<-` strips leading tabs only.
        self.assertEqual(scan_block(1, ["cat <<-EOF", "a # b", "\t\tEOF", "ls"]), [])

    def test_8311_scanner_ignores_safe_shapes(self):
        self.assertEqual(scan_block(1, ["# only a comment", "# another"]), [])
        self.assertEqual(scan_block(1, ["#!/bin/sh", "echo '# x' \"# y\" ${#v}"]), [])
        self.assertEqual(scan_block(1, ["cat <<E", "a # b", "E", "ls"]), [])
        self.assertEqual(scan_block(1, [MARKER, "a # b", "# c", "d"]), [])
        self.assertEqual(scan_block(1, ["# lead", "a", "b"]), [])

    def test_8311_fence_follows_commonmark(self):
        # S5: a fence inside a block quote (one or more `>` markers) is scanned.
        quoted = "> x\n>\n> ```bash\n> a\n> # c\n> b\n> ```\n"
        self.assertEqual(scan_text(quoted), [(5, "comment line between two commands")])
        nested = "> > ```sh\n> > a # c\n> > ```\n"
        self.assertEqual(scan_text(nested), [(2, TRAIL)])
        # A line without the `>` closes the quote and the fence with it.
        self.assertEqual(scan_text("> ```bash\n> a\n\nb # c\n```\n"), [])
        # S6: a 4-space-indented run or a run with an info string does not
        # close the fence, so the lines after it are still shell.
        for mid in ("    ```", "```text"):
            text = "```bash\ncat <<EOF\n%s\nEOF\nls # hazard\n```\n" % mid
            self.assertEqual(scan_text(text), [(5, TRAIL)], mid)
        # A longer run, trailing blanks and a 3-space indent do close it; a
        # run of the other character does not.
        for close in ("````", "```   ", "   ```"):
            self.assertEqual(scan_text("```bash\nls\n%s\nx # y\n" % close), [], close)
        self.assertEqual(scan_text("```bash\nls\n~~~\nx # y\n```\n"), [(4, TRAIL)])
        # S7: only \n, \r\n and \r end a line (not FF or U+2028).
        for sep in ("\f", " ", "\x0b", "\x85"):
            text = "```bash\ncat <<EOF\nx%sEOF\ndata <<X\nEOF\nls # hazard\nX\n```\n" % sep
            self.assertEqual(scan_text(text), [(6, TRAIL)], repr(sep))
        self.assertEqual(scan_text("```bash\r\na # b\r\n```\r\n"), [(2, TRAIL)])
        # An empty list item ends at a blank line; four columns is then
        # indented code, not a fence. In an item, a dedented line ends it.
        self.assertEqual(scan_text("-\n\n    ```bash\n    a # b\n    ```\n"), [])
        self.assertEqual(scan_text("- x\n\n  ```bash\n  a\nb # c\n  ```\n"), [])
        self.assertEqual(scan_text("- x\n\n  ```bash\n  a\n\n  b # c\n  ```\n"), [(6, TRAIL)])

    def test_8311_fence_indent_removed_up_to_opener(self):
        # C1: up to the fence indent is removed, so "  EOF" in a 4-space
        # fence renders as "EOF" and ends the heredoc for whoever pastes it.
        hide = ["cat <<EOF", "body", "  EOF", "ls # hazard", "cat <<EOF", "more", "    EOF"]
        self.assertEqual(scan_block(1, hide, "    "), [(4, TRAIL)])
        self.assertEqual(scan_block(1, ["cat <<EOF", "x # y", "  EOF", "ls"], "    "), [])
        # The same through the Markdown parser: a list item fence.
        text = "1. step\n\n      ```bash\n      cat <<EOF\n      body\n     EOF\n      ls # hazard\n      ```\n"
        self.assertEqual(scan_text(text), [(7, TRAIL)])
        # A partly consumed tab renders as spaces, which `<<-` keeps: the
        # body runs on to the later terminator, as it does for the reader.
        self.assertEqual(scan_block(1, ["cat <<-EOF", "\tEOF", "a # b", "EOF", "ls"], "  "), [])

    def test_8311_shell_lexer_follows_bash(self):
        # C2: a heredoc operator inside a comment opens nothing.
        self.assertEqual(
            len(scan_block(1, ["echo hi # cat <<EOF", "ls # hazard", "rm x # h2", "EOF"])), 3
        )
        self.assertIn((2, TRAIL), scan_block(1, ["echo a;# <<EOF", "ls # hazard", "EOF"]))
        # S8: quote state carries across lines; `$'..'` escapes its quote.
        self.assertEqual(scan_block(1, ["echo 'a", "<<EOF'", "ls # hazard", "EOF"]), [(3, TRAIL)])
        self.assertEqual(scan_block(1, ["echo $'it\\'s <<EOF'", "ls # hazard", "EOF"]), [(2, TRAIL)])
        self.assertEqual(scan_block(1, ['echo "a', 'b" # comment']), [(2, TRAIL)])
        self.assertEqual(scan_block(1, ["echo 'a # b", "c'", "ls"]), [])
        # S8: a quote still open at the fence end skips nothing and is flagged.
        self.assertEqual(
            scan_block(1, ["echo 'a <<EOF", "ls # hazard", "EOF"]),
            [(1, "quote or expansion still open at the end of the fence"), (2, TRAIL)],
        )
        # S9: `<<` in a `${ }` pattern is not a heredoc.
        self.assertEqual(
            scan_block(1, ["x=abc; echo ${x#<<EOF}", "ls # hazard", "EOF}"]), [(2, TRAIL)]
        )
        # S10: the body starts after the whole continued line.
        self.assertEqual(scan_block(1, ["cat <<EOF \\", "-n # hazard", "body", "EOF"]), [(2, TRAIL)])
        self.assertEqual(scan_block(1, ["cat <<EOF \\", "-n", "a # b", "EOF", "ls"]), [])
        # An unquoted word joins continued body lines before the compare.
        self.assertEqual(scan_block(1, ["cat <<EOF", "EO\\", "F", "ls # hazard", "EOF"]), [(4, TRAIL)])
        self.assertEqual(scan_block(1, ["cat <<'EOF'", "EO\\", "F", "a # b", "EOF", "ls"]), [])
        # `<<-` drops the tabs of the first line only, not of a continuation.
        self.assertEqual(scan_block(1, ["cat <<-EOF", "\tEO\\", "F", "ls # hazard", "EOF"]), [(4, TRAIL)])
        self.assertEqual(scan_block(1, ["cat <<-EOF", "EO\\", "\tF", "a # b", "EOF", "ls"]), [])
        # Two heredocs on one line are read in order; a real one in `$( )`.
        self.assertEqual(
            scan_block(1, ["cat <<A <<B", "a # x", "A", "b # y", "B", "ls # hazard"]), [(6, TRAIL)]
        )
        self.assertEqual(scan_block(1, ["x=$(cat <<EOF", "a # b", "EOF", ")", "ls"]), [])

    def test_8311_html_blocks_open_no_fence(self):
        # C3: a fence-like line inside an HTML block (CommonMark 4.6) opens
        # nothing, so the real bash fence after the block is scanned.
        comment = "<!--\n```\n-->\n\n```bash\nls # hazard\n```\n"
        self.assertEqual(scan_text(comment), [(6, TRAIL)])
        div = "<div>\n```\n\n```bash\nls # hazard\n```\n"
        self.assertEqual(scan_text(div), [(5, TRAIL)])
        # An HTML block that ends on its start line, or with its container.
        self.assertEqual(scan_text("<!-- x -->\n```bash\nls # hazard\n```\n"), [(3, TRAIL)])
        quoted = "> <!--\n> ```\n\n```bash\nls # hazard\n```\n"
        self.assertEqual(scan_text(quoted), [(5, TRAIL)])
        # In a list item a blank line ends it, as markdown-it reads it.
        item = "- <!--\n\n  ```bash\n  ls # hazard\n  ```\n"
        self.assertEqual(scan_text(item), [(4, TRAIL)])
        # A details block with no blank line holds the fence lines: the page
        # shows no code block, so there is nothing to paste.
        details = "<details>\n<summary>x</summary>\n```bash\nls # c\n```\n</details>\n"
        self.assertEqual(scan_text(details), [])
        # A lone tag starts an HTML block (type 7), except after a paragraph.
        self.assertEqual(scan_text("<b>\n```bash\na # b\n```\n"), [])
        self.assertEqual(scan_text("x\n<b>\n```bash\na # b\n```\n"), [(4, TRAIL)])

    def test_8311_backticks_and_subshells_are_code(self):
        # S11: a backtick substitution is lexed as code, bare or in "...".
        self.assertEqual(scan_block(1, ["echo `ls # c`"]), [(1, TRAIL)])
        self.assertEqual(scan_block(1, ['echo "`ls # c`"']), [(1, TRAIL)])
        self.assertEqual(scan_block(1, ["x=`echo a", "ls # hazard", "echo b`"]), [(2, TRAIL)])
        self.assertEqual(scan_block(1, ["x=`", "ls # hazard", "`"]), [(2, TRAIL)])
        self.assertEqual(scan_block(1, ["echo \"today `date`\" '`#'", "ls"]), [])
        # A heredoc inside backticks has no body outside them.
        self.assertEqual(scan_block(1, ["x=`cat <<EOF`", "ls # hazard", "EOF"]), [(2, TRAIL)])
        # S12: `((cmd) || cmd)` is two subshells once the inner one closes.
        self.assertEqual(scan_block(1, ["((cd . && ls) || echo fail) # done))"]), [(1, TRAIL)])
        self.assertEqual(
            scan_block(1, ["((cd . && ls) || echo fail)", "ls # hazard", "echo b # c))"]),
            [(2, TRAIL), (3, TRAIL)],
        )
        self.assertEqual(scan_block(1, ["echo $(( (1+2) << 3 ))", "(( (a+b) > 2 ))", "ls"]), [])

    def test_8311_html_item_blank_union_of_readings(self):
        # C5: a list item holds an HTML comment, a blank line, an unpaired
        # fence-like line, the comment close, then a bash fence. markdown-it
        # ends the comment at the blank line; cmark-gfm (GitHub) keeps it
        # open and shows the bash fence. The guard keeps both readings' hits.
        probes = (
            ("- item\n  <!--\n\n  ```\n  -->\n  ```bash\n  ls # hazard\n  ```\n", 7),
            ("1. item\n   <!--\n\n   ~~~\n   -->\n   ```bash\n   ls # hazard\n   ```\n", 7),
            ("- a\n  - <!--\n\n    ```\n    -->\n    ```bash\n    ls # hazard\n    ```\n", 7),
            ("> - <!--\n>\n>   ```\n>   -->\n>   ```bash\n>   ls # hazard\n>   ```\n", 6),
        )
        for text, no in probes:
            self.assertEqual(scan_text(text), [(no, TRAIL)], text)
        # The round 5 row still gives one hit, not one per reading.
        self.assertEqual(scan_text("- <!--\n\n  ```bash\n  ls # hazard\n  ```\n"), [(4, TRAIL)])

    def test_8311_html_end_markers_are_literal(self):
        # C6: CommonMark 4.6 states each type 1-5 end condition as a literal
        # string, so the guard tests it with `in` (no regex to misread as an
        # HTML filter). A `--!>` line does not end a type 2 block (markdown-it
        # and cmark-gfm agree); a `-->` line does.
        for _, _, ends in HTML_BLOCKS:
            self.assertIsInstance(ends, tuple)
            self.assertTrue(all(isinstance(m, str) for m in ends), ends)
        bang = "<!--\n--!>\n```\n-->\n\n```bash\nls # hazard\n```\n"
        self.assertEqual(scan_text(bang), [(7, TRAIL)])
        self.assertEqual(scan_text("<!--\n```\n-->\n\n```bash\nls # hazard\n```\n"), [(6, TRAIL)])
        self.assertEqual(scan_text("<PRE>\n```\n</Pre>\n\n```bash\nls # hazard\n```\n"), [(6, TRAIL)])
        # Type 1 folds case as markdown-it-py does (U+017F is an `s`).
        self.assertEqual(scan_text("<pre>\n```\n</ſcript>\n```bash\nls # c\n```\n"), [(5, TRAIL)])

    def test_8311_dparen_decided_at_the_opener(self):
        # S14: bash reads `((` as arithmetic only when the inner `(` closes
        # with `))`; otherwise every line of the frame is a command line.
        self.assertEqual(scan_block(1, ["((", "echo L2 # hazard", ") )"]), [(2, TRAIL)])
        self.assertEqual(scan_block(1, ["((echo L1", "echo L2 # hazard", ") )"]), [(2, TRAIL)])
        self.assertEqual(scan_block(1, ["((echo L1 ; echo L1b # c", ") )"]), [(1, TRAIL)])
        self.assertEqual(scan_block(1, ["x=$((echo L1", "echo L2 # hazard", ") )"]), [(2, TRAIL)])
        # A heredoc in a re-read `((` takes no body from the outer lines.
        self.assertEqual(
            scan_block(1, ["((cat <<E", "echo L2 # hazard", "E", ") )"]), [(2, TRAIL)]
        )
        # Arithmetic stays arithmetic, including a `#` bash would reject.
        self.assertEqual(scan_block(1, ["(( (a+b) ))", "echo $(( x # y ))", "ls"]), [])
        # A lookahead that hits its cap answers subshell (fails closed).
        self.assertEqual(scan_block(1, ["((" + "x" * LOOKAHEAD_CAP, "ls # c", "))"]), [(2, TRAIL)])

    def test_8311_dparen_lookahead_stops_at_substitution(self):
        # S17: bash's scan reads a backtick span or a `$( )` as commands, so
        # a paren run inside one is no `))`; the lookahead answers subshell.
        # S18: inside an ANSI-C `$'..'` a backslash escapes the quote, so a
        # paren run after `\'` is still inside the string. F1: bash reads
        # `$$` as the PID parameter first, so the quote after it is a plain
        # one, where `\'` ends the string. G2: bash drops a backslash-newline
        # before it lexes, so a lone `$` before it and a `$` that starts the
        # next line are one `$$`. G1: in "...", `$$` is the PID before `[`
        # too (C1 below). Each row carries the lines bash 5.2 runs (`bash
        # -c`, echo markers) and the hits.
        probes = (
            (["echo $$'\\'; echo L1 # c'"], [1], "L1"),
            (["(( $$'\\'); echo L1 # c'))", ")"], [1], "L1"),
            (["echo $\\", "$'\\'; echo L2 # c'"], [2], "L2"),
            (["(( $\\", "$'\\'); echo L2 # c'))", ")"], [2], "L2"),
            (["echo a$\\", "$'\\'; echo L2 # c'"], [2], "L2"),
            (['echo "$$["; echo L1 # c "]"'], [1], "L1"),
            (['echo "$\\', '$["; echo L2 # c "]"'], [2], "L2"),
            (["(( `echo ))`; echo L1 # c", ") )"], [1], "L1"),
            (["(( \"$(echo '\"))')\"; echo L1 # c", ") )"], [1], "L1"),
            (["(( $(: # )))", "); echo L2 # c", ") )"], [1, 2], "L2"),
            (["(( $'\\')) '; echo L1 # c", ") )"], [1], "L1"),
            (["(( $'\\')) '", "echo L2 # c", ") )"], [2], "L2"),
            (["(( $')) '; echo L1 # c", ") )"], [1], "L1"),
            # Arithmetic, `$((` in quotes and an ANSI-C operand stay clean.
            (["(( n > 0 )) && echo \")\"", 'echo "$(( 1 + 2 ))"'], [], "3"),
            (["(( x == $'\\'' )) || echo ok"], [], "ok"),
        )
        for lines, want, bash_runs in probes:
            with self.subTest(lines=lines, bash_runs=bash_runs):
                self.assertEqual([no for no, _ in scan_block(1, lines)], want)

    def test_8311_parse_closes_string_not_expansion(self):
        # C1: bash runs a trailing comment whenever its PARSE closes the
        # string, whether or not the word is ever expanded: in "..." `$$`
        # is always the PID and the parser (`bash -n`, rc 0) opens no `$(`,
        # `${` or `$[` at its second `$`. S20: a lone `$` before a
        # backslash-newline joins the first character of the next line: a
        # quote makes an ANSI-C `$'` in code, and a `(` or `{` opens `$(`
        # or `${` in code or in "...". Each row carries the lines bash 5.2
        # runs (`bash -c`, echo markers) and the hits.
        probes = (
            # C1: the quoted PID before `(` or `{` in a word bash never
            # expands: a short-circuited list, `$( )`, a re-read `((`, and
            # split across a continuation.
            (['false && echo "$$("; echo L1 # c ")"'], [1], "L1"),
            (['true || echo "$${"; echo L1 # c "}"'], [1], "L1"),
            (['echo $(echo "$$("); echo L1 # c ")")'], [1], "L1"),
            (['(( echo "$$(" ) ); echo L1 # c ")"'], [1], "L1"),
            (['false && (( "$$(" )); echo L1 # c ")"'], [1], "L1"),
            (['false && echo "$\\', '$("; echo L2 # c ")"'], [2], "L2"),
            (['false && echo "$\\', '${"; echo L2 # c "}"'], [2], "L2"),
            # S20: a lone `$`, a continuation, then a quote (code) or a
            # `(` or `{` (in "...").
            (["echo $\\", "'\\''; echo L2 # c '"], [2], "L2"),
            (["echo a$\\", "'\\''; echo L2 # c '"], [2], "L2"),
            (["(( $\\", "'\\'')); echo L2 # c '))"], [2], "L2"),
            (["x=$(echo $\\", "'\\''); echo L2 # c ')"], [2], "L2"),
            (['echo "$\\', "(echo '\"')\"; echo L2 # c '\"\""], [2], "L2"),
            (['echo "$\\', "{x:-'\"'}\"; echo L2 # c '\"\""], [2], "L2"),
            # A `$$` before the backslash, or an escaped `$`, pairs with
            # nothing; a split `$'` hides the comment in its string.
            (["echo $$\\", "$'\\'; echo L2 # c'"], [], "none"),
            (['echo "\\$\\', '$["; echo L2 # c "]"'], [], "none"),
            (["echo $\\", "'\\'; echo L2 # c'"], [], "none"),
        )
        for lines, want, bash_runs in probes:
            with self.subTest(lines=lines, bash_runs=bash_runs):
                self.assertEqual([no for no, _ in scan_block(1, lines)], want)

    def test_8311_backtick_closes_through_quotes(self):
        # S15: bash ends a backtick substitution at the first unescaped
        # backtick, whatever quote is open inside it.
        self.assertIn((1, TRAIL), scan_block(1, ["echo `echo '`; echo L1 # c", "'`"]))
        self.assertEqual(scan_block(1, ['echo `echo "`; ls # c']), [(1, TRAIL)])
        # Escaped, the backtick stays inside the quote.
        self.assertEqual(scan_block(1, ["echo `echo '\\`'; echo a`", "ls"]), [])

    def test_8311_scan_work_is_linear(self):
        # S13: a fence left open by every line, and a fence of unterminated
        # heredocs, each scan in linear time and stay fail closed. S14: the
        # `((` lookahead shares one budget per fence, so it stays linear.
        shapes = (
            ("x ${", 20000), ("cat <<E", 0), ("((", 0), ("(( `", 0), ("(( $(", 0),
            ("(( $'\\'", 0),  # S18: an escaped quote in an ANSI-C string
            ("(( $$'\\'", 0),  # F1: a double dollar, then a plain quote
            ("$\\", 0),  # G2: a `$$` split by a continuation on every line
            ("$ (( $\\", 0),  # G2: the same in the `((` lookahead
            ('echo "$$["; ls # c "]"', 20000),  # G1: the PID before `[`
            ('false && echo "$$("; ls # c ")"', 20000),  # C1: never expanded
            ("ls $\\\n'\\''; ls # c '", 10000),  # S20: a split `$'`, two lines
        )
        for line, want in shapes:
            began = time.monotonic()
            got = scan_block(1, line.split("\n") * (20000 // len(line.split("\n"))))
            spent = time.monotonic() - began
            self.assertEqual(len(got), want, line)
            self.assertLess(spent, SCAN_BUDGET_S, line)


if __name__ == "__main__":
    unittest.main()
