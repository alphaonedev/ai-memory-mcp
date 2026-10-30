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
  What is scanned is the text a reader copies out of the rendered page.
* Shell, per bash: one lexer, shared by the heredoc and comment checks,
  carries quote (`'..'`, `"..."`, `$'..'`), command substitution (`$( )`
  and backticks, both lexed as code) and expansion (`${ }`, `$(( ))`,
  `(( ))`, `$[ ]`) state across lines and joins backslash-continued lines.
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
# (the renderers the docs are read through): (type, start, end). Types 1-5
# end on the line holding the end marker; types 6-7 end before a blank line.
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
HTML_BLANK_RE = re.compile(r"^[ \t]*$")
HTML_BLOCKS = (
    (1, re.compile(r"<(?:script|pre|style|textarea)(?=\s|>|$)", re.I),
     re.compile(r"</(?:script|pre|style|textarea)>", re.I)),
    (2, re.compile(r"<!--"), re.compile(r"-->")),
    (3, re.compile(r"<\?"), re.compile(r"\?>")),
    (4, re.compile(r"<![A-Z]"), re.compile(r">")),
    (5, re.compile(r"<!\[CDATA\["), re.compile(r"\]\]>")),
    (6, re.compile(r"</?(?:%s)(?=\s|/?>|$)" % "|".join(HTML_TAGS), re.I), HTML_BLANK_RE),
    (7, re.compile(HTML_TAG + r"\s*$"), HTML_BLANK_RE),
)


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
    """Return the end pattern of the HTML block (CommonMark 4.6) that `text`
    starts, or None. With `para` set, only types 1-6 count (type 7 cannot
    interrupt a paragraph)."""
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


def html_item_blank(stack, rest):
    """True for a blank line inside a list item. CommonMark and cmark keep an
    HTML block of types 1-5 open across it; markdown-it ends the block there,
    so the guard ends it too and reads a later fence (fails closed)."""
    return not rest.strip() and any(entry[0] == "li" for entry in stack)


def fences(text):
    """Yield (lang, first_body_line_no, [content lines]) per fenced block.

    Content lines are what CommonMark renders: container prefixes and up to
    the opening fence's indent removed."""
    stack = []  # open containers, as match_containers() describes them
    fence = None
    html = None  # end pattern of the open HTML block
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
                if html.search(rest) or html_item_blank(stack, rest):
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
            html = None if end.search(rest) else end
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
CODE = (None, "(", "`")  # frames where a command (and so a heredoc or comment) can be
OPEN_REASON = "quote or expansion still open at the end of the fence"
TRAIL = "trailing comment on a command line"


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


def open_expansion(line, i, stack):
    """Push `$((`, `$(`, `${` or `$[` at `i`; return the characters used."""
    for token, frame in (("$((", "(("), ("$(", "("), ("${", "${"), ("$[", "$[")):
        if line.startswith(token, i):
            stack.append(frame)
            return len(token)
    return 0


def lex_quoted(line, i, stack):
    """One step inside a `'..'`, `"..."` or `$'..'` frame at `i`. Returns
    (next index, prev), or None when a backslash continues the line."""
    top, ch = stack[-1], line[i]
    if top == "'":
        if ch == "'":
            stack.pop()
        return i + 1, ch
    if ch == "\\":
        if i + 1 == len(line):
            return None
        return i + 2, line[i + 1]
    if ch == ("'" if top == "$'" else top):
        stack.pop()
        return i + 1, ch
    used = 0
    if top == '"':
        if ch == "`":
            stack.append("`")  # command substitution: lexed as code
            used = 1
        else:
            used = open_expansion(line, i, stack)
    if used:
        return i + used, line[i + used - 1]
    return i + 1, ch


def lex_operator(line, i, stack, top):
    """Open or close a quote, substitution, expansion or group frame at `i`
    in a code frame. Returns the characters used (0 for none)."""
    ch = line[i]
    if line.startswith("$'", i):
        stack.append("$'")
        return 2
    if line.startswith('$"', i):
        stack.append('"')
        return 2
    if ch == "`" and top == "`":
        stack.pop()
        return 1
    if ch in "'\"`":
        stack.append(ch)
        return 1
    used = open_expansion(line, i, stack)
    if used:
        return used
    if top in CODE and line.startswith("((", i):
        stack.append("((")
        return 2
    if ch == "(" and top in (None, "(", "((", "`"):
        stack.append("(")
        return 1
    if ch == ")" and top == "(":
        stack.pop()
        return 1
    if top == "((" and line.startswith("))", i):
        stack.pop()
        return 2
    if ch == ")" and top == "((":
        # `((cmd) || cmd)`: the inner subshell closed, so the outer frame
        # is a subshell (code), as bash re-reads it.
        stack[-1] = "("
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


def lex_line(line, stack, prev="\n"):
    """Lex one physical line with the bash quoting and expansion rules,
    continuing (and updating) the open-frame `stack`. `prev` is the
    character before the line (a newline, or the one before a `\\` that
    continued the previous line). Returns (comment index or None,
    [(word, strips_tabs, quoted)] heredocs opened, continued, prev)."""
    heredocs = []
    comment = None
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        top = stack[-1] if stack else None
        if top in ("'", '"', "$'"):
            step = lex_quoted(line, i, stack)
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
        used = lex_operator(line, i, stack, top)
        if not used and top in CODE:
            if ch == "#" and prev in WORD_START:
                comment = i if comment is None else comment
                # A comment inside backticks ends at the closing backtick,
                # which bash finds before it reads the substitution.
                end = backtick_end(line, i) if "`" in stack else -1
                if end < 0:
                    return comment, heredocs, False, prev
                while stack.pop() != "`":
                    pass
                prev = "`"
                i = end + 1
                continue
            if line.startswith("<<<", i):
                used = 3
            elif line.startswith("<<", i):
                m = HEREDOC_RE.match(line, i)
                word, end, quoted = parse_heredoc_word(line, m.end()) if m else ("", i, False)
                # Inside backticks bash re-reads the substitution text alone,
                # so the outer lines are never its body: no skip there.
                if word and "`" not in stack:
                    heredocs.append((word, bool(m.group(1)), quoted))
                    prev = "x"
                    i = end
                    continue
                used = 2
        used = used or 1
        prev = line[i + used - 1]
        i += used
    return comment, heredocs, False, prev


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
        text = lines[k].lstrip("\t") if strips_tabs else lines[k]
        while not quoted and last + 1 < len(lines) and trailing_backslash(text):
            last += 1
            text = text[:-1] + lines[last]
        return text, last

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
    i = 0
    stack = []
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
        at, docs, cont, prev = lex_line(raw, stack, prev)
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
    return start if any(f != "(" for f in stack) else None


def scan_physical(lines, first_no, begin, kinds, hits):
    """Scan `lines[begin:]` one physical line at a time with a fresh frame
    stack each, and skip no heredoc. Linear, and fails closed: used once a
    frame was left open, when the logical reading can no longer be trusted.
    A line that leaves a frame (other than a subshell) open is flagged."""
    for i in range(begin, len(lines)):
        no = first_no + i
        s = lines[i].strip()
        if not s:
            continue
        if s.startswith("#"):
            kinds.append((no, "comment", s))
            continue
        kinds.append((no, "command", s))
        stack = []
        at = lex_line(lines[i], stack)[0]
        if at is not None:
            hits.append((no, TRAIL))
        if any(f != "(" for f in stack):
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


def scan_text(text):
    """Return [(line_no, reason)] for every shell fence in a Markdown text."""
    out = []
    for lang, first_no, body in fences(text):
        if lang in SHELL_LANGS:
            out.extend(scan_block(first_no, body))
    return out


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

    def test_8311_scan_work_is_linear(self):
        # S13: a fence left open by every line, and a fence of unterminated
        # heredocs, each scan in linear time and stay fail closed.
        for line, want in (("x ${", 20000), ("cat <<E", 0)):
            began = time.monotonic()
            got = scan_block(1, [line] * 20000)
            spent = time.monotonic() - began
            self.assertEqual(len(got), want, line)
            self.assertLess(spent, SCAN_BUDGET_S, line)


if __name__ == "__main__":
    unittest.main()
