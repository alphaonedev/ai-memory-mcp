#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""A body-only PR edit never cancels or restarts a required check (#8332).

Defect: ci.yml, coverage.yml and claude-md-rule-compare.yml listed ``edited`` in
their pull_request(_target) types and set ``cancel-in-progress`` for pull_request
runs, so every PR title or body edit cancelled the running required checks and
started them again from zero.

The rules this guard pins (a ratchet over EVERY workflow):

1. No workflow lists ``edited`` under a ``pull_request`` or ``pull_request_target``
   trigger, in ANY YAML form (inline ``types: [..]``, a block sequence ``- edited``, or a
   flow-mapping ``on: {pull_request: {types: [..]}}``), except claude-md-rule-compare.yml
   (a one-entry allow-list; its ``cancel-in-progress`` guard is pinned by rule 2). The
   scan is stdlib only (PyYAML is not installed on every runner and no other workflow
   test imports it): ONE quote-aware scanner (``_Scanner``) reads every line, carrying the
   quote, flow-depth, block-scalar and plain-scalar state across lines. It is a whitelist
   (round 7): a workflow whose ``on:`` section holds any line it does not model (no or a
   second ``on`` key, an anchor, alias or tag, an open quote or flow, an early-closing flow,
   a multi-line plain scalar, a plain value on the line below its key or dash (round 8), a
   double-quoted escape other than backslash-quote and backslash-backslash, an unrecognised
   line, a duplicate trigger key, a pull_request word on a continuation line of another
   trigger, a column-0 line after the section that is not a workflow key) is refused
   by name, never read as a 0, and any ``edited`` word inside a pull_request(_target)
   trigger body counts as listed. An anchor, tag or alias written on a mapping key ANYWHERE
   in the file is refused by name (round 9): the scanner does not model that key's column. So are an
   explicit key (a line led by ``?`` or a bare ``:``) and a double-quoted key holding an escape (round 10, in a
   flow collection also with blanks before its colon, round 12), and a block scalar header with a comment flush
   after it (``run: |#c``, round 12).
   The ``ORACLE`` table pins every shape from rounds 3-9; where PyYAML is importable a
   differential test checks the table, and variants of it, against it.
2. ``cancel-in-progress`` is read only as a direct child of a block ``concurrency:`` key
   (top-level or job-level), through the scanner (round 9); a flow-form or tagged
   ``concurrency`` value, and a ``cancel-in-progress`` or ``concurrency`` key anywhere else,
   are refused by name, and so is a ``cancel-in-progress`` key whose value is not on its own line (round
   10). Where ``edited`` is listed, every such key is the literal ``false``, the guard
   ``${{ github.event_name == 'pull_request' }}``, the body-only guard
   ``${{ github.event.action != 'edited' }}``, or one of those guards joined by ``&&``
   to another clause. An ``||`` form is rejected. A workflow with a pull_request(_target)
   trigger and a concurrency block without the key is a violation; ``CANCEL_ORACLE`` pins the shapes.
3. The only ``pull_request_target`` workflow is claude-md-rule-compare.yml. A second one
   is a failure: no ``pull_request_target`` workflow has ever run in this repository
   (#8337), so a new one would never fire before it lands on the default branch.
4. A base retarget (#7072) is landed only after a new head push, checked at landing by
   scripts/ci/pr_retarget_check.py (tested by test_pr_retarget_check_8332.py).

Linear time (rounds 10-12): every pattern this guard searches or matches per line or per file is compiled at
module level, and the block header walk and the flush-comment check are one split and one pass each.
``test_every_line_pattern_is_linear`` times every one of them, and ``scan``, ``cancel_violations`` and
``edited_listed`` on a workflow carrying the line, on hostile lines of at least HOSTILE_LEN (50,000) characters:
each call must finish under REGEX_CEILING_S.

Stdlib only. Run: ``python3 -I scripts/test/test_workflow_edited_cancel_8332.py``.
"""
import importlib.util
import itertools
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
SCRATCH = ROOT / ".local-runs"
WF = ROOT / ".github" / "workflows"
NO_EDITED = ("ci.yml", "coverage.yml")
EDITED_ALLOW = {"claude-md-rule-compare.yml"}
TARGET_ALLOW = {"claude-md-rule-compare.yml"}
ACCEPTED_GUARDS = (
    "github.event_name == 'pull_request'",
    "github.event.action != 'edited'",
)
KINDS = ("pull_request", "pull_request_target")
ACTIVITY_TYPES = {"assigned", "unassigned", "labeled", "unlabeled", "opened", "edited", "closed", "reopened",
                  "synchronize", "converted_to_draft", "locked", "unlocked", "enqueued", "dequeued",
                  "milestoned", "demilestoned", "ready_for_review", "review_requested",
                  "review_request_removed", "auto_merge_enabled", "auto_merge_disabled"}
ON_KEY_RE = re.compile(r"""^(?:on|"on"|'on')[ \t]*:(?:[ \t]+(.*))?$""")
TOP_KEY_RE = re.compile(r"""^(["']?)(?:name|run-name|on|permissions|env|defaults|concurrency|jobs)\1[ \t]*:(?:[ \t]|$)""")
# An anchor, alias, tag (a bare `!` too), merge key or explicit key anywhere in the `on:` section is refused,
# each by its own name (round 8, REVIEW-8332-code-r7 INFO-2).
PROPERTY_RES = (
    ("an anchor (`&`)", re.compile(r"(?:^|[\s\[{,:])&[^\s\[\]{},]")),
    ("an alias (`*`)", re.compile(r"(?:^|[\s\[{,:])\*[^\s\[\]{},]")),
    ("a tag (`!`)", re.compile(r"(?:^|[\s\[{,:])!")),
    ("a merge key (`<<`)", re.compile(r"<<\s*:")),
    ("an explicit key (`?`)", re.compile(r"(?:^|[\s\[{,])\?(?:\s|$)")),
)
READ_ESCAPES = '(only \\" and \\\\ are read)'
NEXT_LINE_PLAIN = "plain scalar value on the line below its key or dash"
PAST_COMMENT = "a line continues a plain scalar past a comment, which YAML does not allow"
# A block scalar header's indicator characters (`|` or `>`, then indentation and chomping indicators); read by
# ``_block_header`` in one pass (round 11).
BLOCK_INDICATORS, BLOCK_HEADER_TAIL = "|>", frozenset("123456789+-")
PR_WORD_RE = re.compile(r"(?<![\w-])pull_request(?:_target)?(?![\w-])")
SEPARATORS = ("", " ", "\t")
# No quote closed on this line yet: never equal to ``i - 1`` for any index ``i >= 0`` (-1 would match a colon
# at column 0 and refuse a plain key such as ``:x: 1``).
NO_QUOTE_END = -2
PROPERTY_KEY = "an anchor, tag or alias on a mapping key (the scanner does not model that key's column)"
# Round 10 (REVIEW-8332-security-r9 S18, REVIEW-8332-code-r9 F2): an explicit key (a line whose first token,
# after any dashes, is `?` or a bare `:`) and a double-quoted key holding any escape are refused file-wide.
EXPLICIT_KEY_RE = re.compile(r"^[ \t]*(?:-[ \t]+)*[?:](?:[ \t]|$)")
EXPLICIT_KEY = "an explicit key (`?`) or its bare `:` value line (the scanner does not model that key's column)"
ESCAPED_KEY = "a double-quoted key holding an escape (the scanner does not decode a key's escapes)"
# Round 11 (REVIEW-8332-code-r10 F1): outside a flow collection a colon flush against a closing quote is not YAML.
ADJACENT_KEY = "a colon flush against a closing quote outside a flow collection (YAML needs a blank after it)"
NEXT_LINE_CANCEL = "a `cancel-in-progress` key with no value on its line (a value below it is not read)"
# Round 11 (REVIEW-8332-security-r10 INFO-1): YAML folds a plain value's continuation lines into one string.
MULTILINE_CANCEL = "a `cancel-in-progress` value continued on the next line (YAML folds it into one string)"
# Round 12 (REVIEW-8332-security-r11 S-r11-2): libyaml and actionlint read `|#c` as a header and a comment.
FLUSH_COMMENT_HEADER = ("a block scalar header with a comment flush after it (libyaml and actionlint read a header, "
                        "the YAML spec and PyYAML reject it)")
# Round 9 (REVIEW-8332-security-r8 S17): a scanned key line, its key column (group 1 is the indent plus any
# dashes), and a `cancel-in-progress` or `concurrency` key token anywhere in a scanned line.
# Round 10 (REVIEW-8332-security-r9 S20, REVIEW-8332-code-r9 F1): the prefix is `^( *(?:-[ \t]+)*)`; each
# repetition starts at a dash, so a line of dashes and blanks splits one way only and matches in linear time.
KEY_LINE_RE = re.compile(r"""^( *(?:-[ \t]+)*)(["']?)([\w-]+)\2[ \t]*:(?:[ \t]+(.*))?$""")
CANCEL_KEY, CONCURRENCY_KEY = "cancel-in-progress", "concurrency"
TOKEN_RES = {key: re.compile(rf"""(?<![\w-])(["']?){key}\1[ \t]*:""") for key in (CANCEL_KEY, CONCURRENCY_KEY)}
# Round 11 sweep: every pattern searched per line or per file is compiled here, so the linear-time test
# (test_every_line_pattern_is_linear) times each one on 50,000-character hostile lines.
KIND_RES = {kind: re.compile(rf"""(?<![\w-]){kind}(?![\w-])""") for kind in KINDS}
TYPES_WORD_RE, ACTIVITY_WORD_RE = re.compile(r"\btypes\b"), re.compile(r"[a-z_]+")
GUARD_EXPR_RE = re.compile(r"\$\{\{(.*)\}\}")
WORD_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


class ParseFailure(Exception):
    """The workflow trigger section cannot be read; the caller fails closed."""


class Line(NamedTuple):
    """One scanned line: comments cut, quoted and block-scalar text reduced to words (see ``scan``)."""

    text: str  # structure text; inside quotes only word characters survive (others become spaces)
    cont: bool  # starts inside a quoted scalar, continues a plain scalar or is block-scalar content: never a key
    depth: int  # flow-collection depth BEFORE this line
    plain: bool  # continues a multi-line plain scalar (refused inside the `on:` section)
    bad: str  # why this line cannot be read exactly (an unmodelled escape, a next-line plain value), or ""


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _words(raw: str) -> str:
    """Block-scalar content: keep the indent and the word characters only (no brackets, colons or quotes)."""
    body = raw.lstrip(" ")
    return " " * (len(raw) - len(body)) + "".join(c if c in WORD_CHARS else " " for c in body)


def _block_header(text: str) -> bool:
    """True when a scanned line ends with a block scalar header (``|``, ``key: >-``, ``- &a !t |2``).

    decision (round 11, REVIEW-8332-security-r10 S21, REVIEW-8332-code-r10 F2): one pass over the blank-separated
    tokens from the END replaces a regex search that retried at every colon (quadratic in the line length). The
    last token is the indicator; walking back, a token ending with a colon or a lone dash is the header's lead,
    a token starting with ``&`` or ``!`` is a property before the indicator, anything else means no header, and
    no token left means the indicator leads the line.
    """
    if not text or text[-1] in " \t":
        return False  # the indicator ends the line (the scanner strips trailing blanks before this)
    tokens = [tok for tok in text.replace("\t", " ").split(" ") if tok]
    if tokens[-1][0] not in BLOCK_INDICATORS or not set(tokens[-1][1:]) <= BLOCK_HEADER_TAIL:
        return False
    for tok in reversed(tokens[:-1]):
        if tok.endswith(":") or tok == "-":
            return True
        if tok[0] not in "&!":
            return False
    return True


def _flush_comment_header(text: str) -> bool:
    """True when a scanned line holds a block scalar header with a comment flush after it (``run: |#c``).

    decision (round 12, REVIEW-8332-security-r11 S-r11-2): libyaml and yaml.v3 (actionlint) read ``|#c`` as the
    header ``|`` and a comment, the YAML spec and PyYAML reject it, so the scanner cannot know whether the lines
    below are block scalar content; ``scan`` refuses the file by name (fail closed, the precedent of rounds 6-11
    for shapes two readers disagree on) over reading it as libyaml does.

    decision (round 13, REVIEW-8332-code-r12 F1, REVIEW-8332-security-r12 S-r12-1): every candidate token over
    the first candidate, because libyaml reads the header wherever it stands. One forward pass over the
    blank-separated tokens (tabs read as blanks) tests EVERY token led by an indicator and holding a ``#``: it is
    a header when the text before its first ``#`` is the indicator plus indentation and chomping characters and
    the token stands where a value can start (line start, after a token ending with a colon or a lone dash, with
    only ``&anchor`` / ``!tag`` properties between). So ``X >#b: |#c`` and ``- run: |2#c d`` are refused and a
    plain scalar such as ``run: echo |#c`` or ``run: a|#b`` is not; no candidate calls back into
    ``_block_header``, so the pass stays linear on a line of candidates.
    """
    lead = True  # no token yet: an indicator may lead the line
    for tok in text.replace("\t", " ").split(" "):
        if not tok:
            continue
        if lead and tok[0] in BLOCK_INDICATORS and "#" in tok and set(tok[1:tok.index("#")]) <= BLOCK_HEADER_TAIL:
            return True
        lead = tok.endswith(":") or tok == "-" or (lead and tok[0] in "&!")
    return False


class _Scanner:
    """The ONE quote-aware, stateful YAML line scanner of this guard (rounds 6 and 7).

    decision (round 6, REVIEW-8332-security-r5 S9/S10, REVIEW-8332-code-r5 F1): one scanner walks every
    character once, carrying the quote state, the flow depth and the block-scalar state across lines. A
    quoted scalar opens only at a scalar start (line start, after ``[ { ,``, after ``:``/``-``/``?``
    followed by whitespace), as in YAML; ``''`` is honoured; a ``#`` starts a comment only outside quotes
    and after whitespace or at line start; flow brackets count only in flow context or at a scalar start
    (``${{ }}`` in a plain scalar is text); a ``|``/``>`` block scalar's lines are reduced to words.

    decision (round 7, REVIEW-8332-code-r6 F1/F2/F3, REVIEW-8332-security-r6 S12/S13): four rounds of
    shape-chasing each failed open, so the scanner now models the structure it accepts and MARKS every
    line it cannot read exactly; the ``on:`` section refuses a marked line by name (a whitelist, not a
    list of known-bad shapes). A plain scalar's state is carried across lines: a deeper-indented line
    after a plain value (any next line inside a flow) continues that scalar, is scanned with no scalar
    start (a quote or bracket there is text, as in YAML) and is marked ``plain``. A double-quoted escape
    other than backslash-quote and backslash-backslash (hex, unicode, an escaped line break, ...) can
    spell a word the scanner never sees, so it is marked ``bad`` rather than decoded. An anchor, alias or
    tag token at a scalar start is copied whole and keeps the scalar start, so a tagged block scalar is
    still a block scalar. An open quote or flow collection at the end of the file is a ParseFailure.

    decision (round 8, REVIEW-8332-code-r7 F1, REVIEW-8332-security-r7 S14): a value may start on the line
    BELOW its key or bare dash; YAML owns it by that key's (or dash's) column, so a line that ends with an
    empty value carries its owner column to the next content line, which uses it as the parent of its plain
    scalar or block scalar. A continuation at the value's own column is then a continuation (no scalar
    start, never a quote opener), as in YAML. A plain value that starts on the line below is marked ``bad``
    too, so the ``on:`` section refuses it by name (no workflow uses that shape there). A comment (trailing
    or on its own line) ends a plain scalar in YAML, so a deeper line after it that the scanner would read
    as a continuation is not YAML at all: ``scan`` refuses the whole file by name.

    decision (round 9, REVIEW-8332-security-r8 S16): an anchor or tag written before a mapping key, or an
    alias used as a key, starts the key node at the property's column, while the scanner records the
    key's own token column as the parent of its value; a continuation between the two columns could then
    open a quote only the scanner sees. No workflow writes a property on a key (23 workflows, 0 hits), so
    ``scan`` refuses the whole file by name (whitelist-first) rather than modelling that column; a property
    whose token holds a ``:`` (an alias read as a key by YAML parsers) is refused the same way.

    decision (round 10, REVIEW-8332-security-r9 S18, REVIEW-8332-code-r9 F2): an explicit key (``? k`` then
    ``: v``) leaves the owner column of the value line at the key token, and a double-quoted key holding an
    escape spells a key (``concurrency``, ``cancel-in-progress``) the scanner never reads. Neither occurs in
    the 23 workflows, so ``scan`` refuses the whole file by name for a line whose first token (after any
    dashes) is ``?`` or a bare ``:``, and for a key separator after a double-quoted scalar holding any escape.

    decision (round 11, REVIEW-8332-code-r10 F1): inside a flow collection a colon right after the quote that
    closed a quoted scalar is a key separator with or without a blank after it (``{"k":v}``), as YAML and PyYAML
    read it, so the escaped-key refusal sees a JSON-like key too; the closing quote is tracked by its index, so a
    quote inside a plain scalar (``a":"b``) never makes the colon after it a separator or opens a quote there.
    Outside a flow collection the same flush colon (``"k":v``, ``"k":"v"``) is not YAML (PyYAML and actionlint
    reject it), so ``scan`` refuses the whole file by name rather than guess a key there.
    (Corrected in round 12, REVIEW-8332-security-r11 INFO-1: outside a flow collection the ``a":"b`` reading
    comes from the separator rule, which there needs a blank after the colon; the closing-quote index only
    acts inside a flow collection.)

    decision (round 12, REVIEW-8332-code-r11 F1, REVIEW-8332-security-r11 S-r11-1): inside a flow collection
    YAML, PyYAML, libyaml and yaml.v3 also read blanks between the closing quote and the colon (``{"k" :v}``),
    so a blank right after a closing quote carries the closing-quote index forward and the escaped-key refusal
    sees that key too. A block scalar header followed by a comment with no blank (``run: |#c``) is read as a
    header by libyaml and yaml.v3 (actionlint) and rejected by the YAML spec and PyYAML; ``scan`` refuses the
    whole file by name (S-r11-2) rather than pick one reading of the lines below it.
    """

    def __init__(self):
        self.quote = ""
        self.depth = 0
        self.block = -1  # column a block scalar's content lines must exceed, or -1
        self.plain = None  # column a plain scalar's continuation must exceed (-1 in flow), or None
        self.parent = 0  # column of the key or `-` that owns the next value on this line
        self.pparent = 0  # the parent column of the plain scalar being read
        self.tok = 0  # column where the current token began
        self.inplain = False  # a plain scalar is being read
        self.owner = None  # column of a key or `-` whose empty value starts on the next content line
        self.cut = False  # the open plain scalar was ended by a comment: YAML continues it no further
        self.invalid = ""  # why this line is not YAML at all (the whole file is refused), or ""
        self.bad = ""
        self.pendprop = False  # an anchor or tag at this scalar start waits for its node's token
        self.keyprop = False  # the current token carries a property or is an alias (a key there is refused)
        self.keyesc = False  # the current token is a double-quoted scalar holding an escape (a key there is refused)
        self.qend = NO_QUOTE_END  # index on this line of the quote that closed the last quoted scalar

    def _quoted(self, raw: str, i: int, out: list) -> int:
        """Consume one character inside a quoted scalar; return the next index."""
        c = raw[i]
        if self.quote == '"' and c == "\\":
            esc = raw[i + 1:i + 2]
            self.keyesc = True
            if esc not in ('"', "\\") and not self.bad:
                what = f"double-quoted escape \\{esc}" if esc else "escaped line break in a double-quoted scalar"
                self.bad = f"{what} {READ_ESCAPES}"
            out.append("  " if esc else " ")
            return i + 2
        if c == self.quote:
            if self.quote == "'" and raw[i + 1:i + 2] == "'":
                out.append("  ")
                return i + 2
            self.quote, self.qend = "", i
            out.append(c)
            return i + 1
        out.append(c if c in WORD_CHARS else " ")
        return i + 1

    def _property(self, raw: str, i: int, out: list) -> int:
        """An anchor, alias or tag token at a scalar start: copy it whole; return the index after it."""
        j = i
        while j < len(raw) and raw[j] not in " \t,[]{}":
            j += 1
        if ":" in raw[i:j]:
            self.invalid = PROPERTY_KEY
        self.pendprop, self.keyprop = raw[i] != "*", raw[i] == "*"
        out.append(raw[i:j])
        return j

    def _plain(self, raw: str, i: int, out: list, start: bool) -> bool:
        """Account for one character outside quotes; return the new scalar-start state."""
        c, nxt = raw[i], raw[i + 1:i + 2]
        out.append(c)
        if c in " \t":
            if self.depth and self.qend == i - 1:
                self.qend = i  # round 12: a blank after a closing quote keeps the key reading in flow ("k" :v)
            return start
        if self.depth and c in "]},":
            self.inplain = False
            if c == ",":
                return True
            self.depth -= 1
            return False
        if c == ":" and self.qend == i - 1 and not self.depth and nxt not in SEPARATORS:
            self.invalid = ADJACENT_KEY  # block context: YAML needs a blank after the colon ("k":v is not YAML)
        if c == ":" and (nxt in SEPARATORS or (self.qend == i - 1 and self.depth)):
            # a key separator. Right after the quote that CLOSED a quoted scalar, or after only blanks following
            # it, it needs no blank in a flow collection (YAML's JSON-like key, {"k":v} and {"k" :v}, rounds 11
            # and 12). Outside a flow collection this condition alone needs a blank after the colon, so a quote
            # inside a plain scalar (a":"b) never makes its colon a separator there (round 12 correction: that
            # comes from this rule, not from the closing-quote index, which only acts inside a flow collection).
            if self.keyprop:
                self.invalid = PROPERTY_KEY
            if self.keyesc:
                self.invalid = ESCAPED_KEY
            if not self.depth:
                self.parent = self.tok
            self.inplain = self.keyprop = False
            return True
        if not start:
            if c in "[{" and self.depth:
                self.depth += 1
                self.inplain = False
                return True
            return False
        self.tok, self.keyesc = i, False
        self.keyprop, self.pendprop = self.pendprop, False
        if c in "\"'":
            self.quote = c
        elif c in "[{":
            self.depth += 1
            return True
        elif c in "-?" and nxt in SEPARATORS:
            if not self.depth:
                self.parent = i
            return True
        elif not (c in "|>" and not self.depth):
            self.inplain, self.pparent = True, self.parent
        return False

    def _continues(self, raw: str) -> bool:
        """True when this line continues the plain scalar left open by the previous content line."""
        body = raw.lstrip(" \t")
        if self.quote or self.plain is None or not body or body[0] == "#":
            return False  # a blank or comment line keeps the state: a deeper line after it is never a key
        if self.depth:
            ends = body[0] in ",]}" or (body[0] == ":" and body[1:2] in SEPARATORS)
        else:
            ends = _indent(raw) <= self.plain
        if ends:
            self.plain = None
        return not ends

    def _take_owner(self, raw: str):
        """The owner column of a value that starts on this line below its key or dash, or None.

        A blank or comment line keeps the carried column; any other line consumes it.
        """
        body = raw.lstrip(" \t")
        if not body or body[0] == "#":
            return None
        owner, self.owner = self.owner, None
        if owner is None or self.quote or self.depth or _indent(raw) <= owner:
            return None
        return owner

    def _settle(self, text: str, owner, start: bool, cut: bool) -> None:
        """Carry a scanned line's plain-scalar, comment and owner state to the next line."""
        if not text.strip():
            self.cut = self.cut or (cut and self.plain is not None)  # a comment line ends an open plain scalar
            return
        self.plain = (-1 if self.depth else self.pparent) if self.inplain and not self.quote else None
        self.cut = cut and self.plain is not None
        self.owner = self.parent if start and not self.quote and not self.depth else None
        if owner is not None and self.inplain and not self.quote and self.pparent == owner and not self.bad:
            self.bad = NEXT_LINE_PLAIN

    def line(self, raw: str) -> Line:
        """Scan one raw line and return its Line record."""
        depth, cont = self.depth, bool(self.quote)
        if self.block >= 0 and (not raw.strip() or _indent(raw) > self.block):
            return Line(_words(raw), True, depth, False, "")
        self.block, self.bad = -1, ""
        owner = self._take_owner(raw)
        self.parent = _indent(raw) if owner is None else owner
        was_cut = self.cut
        pcont = self.inplain = self._continues(raw)
        self.invalid = PAST_COMMENT if pcont and was_cut else ""
        out, i, cut = [], 0, False
        start = not (cont or pcont)
        self.pendprop = self.keyprop = False
        self.qend = NO_QUOTE_END
        while i < len(raw):
            if self.quote:
                i = self._quoted(raw, i, out)
            elif raw[i] == "#" and (i == 0 or raw[i - 1] in " \t"):
                cut = True
                break
            elif start and raw[i] in "&!*":
                start = raw[i] != "*"  # an anchor or tag keeps the scalar start; an alias is a whole node
                i = self._property(raw, i, out)  # a key token after it is refused (round 9)
            else:
                start = self._plain(raw, i, out, start)
                i += 1
        text = "".join(out).rstrip()
        if not self.invalid and EXPLICIT_KEY_RE.match(text):
            self.invalid = EXPLICIT_KEY  # quoted and block-scalar text is words only: a `?` there never matches
        if not self.invalid and not self.quote and _flush_comment_header(text):
            self.invalid = FLUSH_COMMENT_HEADER  # quoted text has no `#` left; round 12, S-r11-2
        self._settle(text, owner, start, cut)
        if not self.quote and not self.depth and _block_header(text):
            self.block = self.parent
        return Line(text, cont or pcont, depth, pcont, self.bad)


def scan(text: str) -> list:
    """Every line of a workflow as a Line; ParseFailure on a quote or flow still open at the end."""
    sc = _Scanner()
    lines = []
    for n, raw in enumerate(text.splitlines(), 1):
        lines.append(sc.line(raw))
        if sc.invalid:
            raise ParseFailure(f"line {n}: {sc.invalid}")
    if sc.quote:
        raise ParseFailure("unterminated quoted scalar")
    if sc.depth:
        raise ParseFailure("unclosed flow collection; the `on:` section cannot be bounded")
    return lines


def _on_section(lines: list):
    """Locate the one top-level ``on:`` key: (its inline value, its section lines).

    The section runs to the next line at column 0 outside any flow collection and quoted scalar.
    decision (round 6, REVIEW-8332-security-r5 S10): that next column-0 line must be a top-level
    workflow key; anything else means the scanner lost track of the ``on:`` section, so the file is
    refused by name rather than read short. A second top-level ``on:`` is refused too.
    decision (round 7, REVIEW-8332-code-r6 F1/F2, REVIEW-8332-security-r6 S12): a line of the section
    the scanner marked (a multi-line plain scalar, an unmodelled double-quoted escape) is refused by name;
    round 8 (REVIEW-8332-code-r7 F1, REVIEW-8332-security-r7 S14) adds a plain value that starts on the
    line below its key or dash.
    """
    keys = [i for i, ln in enumerate(lines) if not ln.cont and not ln.depth and ON_KEY_RE.match(ln.text)]
    if not keys:
        raise ParseFailure("no top-level `on:` key")
    if len(keys) > 1:
        raise ParseFailure("more than one top-level `on:` key")
    start = keys[0]
    end = start + 1
    while end < len(lines):
        ln = lines[end]
        if ln.text.strip() and not ln.cont and not ln.depth and not ln.text[0].isspace():
            if not TOP_KEY_RE.match(ln.text):
                raise ParseFailure(f"line {end + 1} at column 0 after the `on:` section is not a top-level key")
            break
        end += 1
    for n, ln in enumerate(lines[start:end], start + 1):
        if ln.bad:
            raise ParseFailure(f"line {n}: {ln.bad} in the `on:` section")
        if ln.plain:
            raise ParseFailure(f"line {n}: multi-line plain scalar in the `on:` section")
    rest = (ON_KEY_RE.match(lines[start].text).group(1) or "").strip()
    return rest, [ln for ln in lines[start + 1:end] if ln.text.strip()]


def _flow_body(rest: str, section: list) -> str:
    """The whole flow collection of the ``on:`` section; it must close on the section's last line."""
    tail = section if rest else section[1:]
    if any(not ln.depth for ln in tail):
        raise ParseFailure("flow collection ended before the `on:` section did (unread lines)")
    return "\n".join(([rest] if rest else []) + [ln.text for ln in section])


def _trigger_line_res(child: int) -> tuple:
    """The trigger-key and bare-sequence-item patterns of a block ``on:`` section whose children sit at
    column ``child`` (one compile per section; timed by test_every_line_pattern_is_linear)."""
    return (re.compile(rf"""^ {{{child}}}(?:-[ \t]+)?(["']?)([\w-]+)\1[ \t]*:(?:[ \t]+(.*))?$"""),
            re.compile(rf"""^ {{{child}}}-[ \t]+(["']?)([\w-]+)\1$"""))


def _block_triggers(section: list) -> dict:
    """Map each pull_request(_target) key of a block-form ``on:`` section to its body text.

    decision (round 7, REVIEW-8332-code-r6 F1): a second layer behind the scanner: a continuation or
    open-flow line that holds a pull_request(_target) word while the current trigger is neither is
    refused by name, whatever YAML reads there. Round 8 (REVIEW-8332-code-r7 INFO-3): a trigger key
    that appears twice is refused by name; the last one never wins silently.
    """
    out, current, seen = {}, None, set()
    child = _indent(section[0].text)
    key_re, item_re = _trigger_line_res(child)
    for ln in section:
        x, ind = ln.text, _indent(ln.text)
        if ln.cont or ln.depth or ind > child:
            if current in KINDS:
                out[current] += "\n" + x
            elif (ln.cont or ln.depth) and PR_WORD_RE.search(x):
                raise ParseFailure(f"a pull_request word on a continuation line under the `{current}` trigger")
            continue
        m, seq = key_re.match(x), item_re.match(x)
        if ind < child or not (m or seq):
            raise ParseFailure(f"unrecognised line in the `on:` section: {x.strip()[:40]!r}")
        current = (m or seq).group(2)
        if m and current in seen:
            raise ParseFailure(f"duplicate trigger key `{current}` in the `on:` section")
        if m:
            seen.add(current)
        if current in KINDS:
            out[current] = (m.group(3) or "") if m else ""
    return out


def triggers(text: str) -> dict:
    """Map each pull_request(_target) trigger found in ``on:`` to its body text.

    Raises ParseFailure (the caller fails closed) for anything the scanner cannot account for: no or a
    second ``on:`` key, an anchor, alias, tag, merge key or explicit key (each named), an open quote or
    flow, a flow that closes early, a scalar ``on:`` value with more lines under it, a multi-line plain
    scalar, a plain value on the line below its key or dash, an unmodelled double-quoted escape, an
    unrecognised trigger-level line, a duplicate trigger key, a pull_request word on a continuation line
    of another trigger, or a column-0 line after the section that is not a workflow key.
    """
    rest, section = _on_section(scan(text))
    joined = "\n".join([rest] + [ln.text for ln in section])
    for what, prop in PROPERTY_RES:
        if prop.search(joined):
            raise ParseFailure(f"{what} in the `on:` section")
    first = rest or (section[0].text.strip() if section else "")
    if first[:1] in ("{", "["):
        body = _flow_body(rest, section)
    elif rest:
        if section:
            raise ParseFailure("scalar `on:` value followed by more lines")
        body = rest
    elif section:
        return _block_triggers(section)
    else:
        raise ParseFailure("empty `on:` section")
    return {kind: body for kind in KINDS if KIND_RES[kind].search(body)}


def pr_types(text: str, kinds=KINDS) -> set:
    """Activity types named in the body of every listed pull_request(_target) trigger.

    Over-approximates (any activity word in the body, whatever the YAML form): fail closed.
    """
    out = set()
    for kind, body in triggers(text).items():
        if kind in kinds and TYPES_WORD_RE.search(body):
            out |= set(ACTIVITY_WORD_RE.findall(body.lower())) & ACTIVITY_TYPES
    return out


def has_trigger(text: str, kind: str) -> bool:
    return kind in triggers(text)


def guard_ok(value: str) -> bool:
    """True for literal false, an accepted guard, or an accepted guard joined by &&."""
    value = value.split(" #")[0].strip()
    if value == "false":
        return True
    m = GUARD_EXPR_RE.fullmatch(value)
    if m is None:
        return False
    expr = m.group(1).strip()
    if "||" in expr:
        return False
    return any(clause.strip() in ACCEPTED_GUARDS for clause in expr.split("&&"))


def _concurrency_key(m, n: int, blocks: list):
    """A block ``concurrency:`` key line: open its mapping (key column, cancel values), or record a scalar."""
    value = m.group(4) or ""
    if value[:1] in ("{", "[", "&", "!", "*", "|", ">"):
        raise ParseFailure(f"line {n}: a flow-form, tagged, anchored, aliased or block-scalar `concurrency` value")
    blocks.append([])
    return None if value else (len(m.group(1)), blocks[-1])


def concurrency_blocks(text: str) -> list:
    """The ``cancel-in-progress`` values of every ``concurrency`` mapping, one list per mapping.

    decision (round 9, REVIEW-8332-security-r8 S17): a key is read only as a DIRECT child of a block
    ``concurrency:`` key (its owner column, as the scanner reads it), never by counting raw lines: a
    flow-form ``concurrency`` value and any other ``cancel-in-progress`` or ``concurrency`` key token
    (in a flow collection, a plain scalar, a deeper line, another mapping such as a job ``env:``) is
    refused by name. A scalar ``concurrency`` value is a mapping with no ``cancel-in-progress`` key.
    decision (round 10, REVIEW-8332-code-r9 INFO-2/INFO-3): a ``cancel-in-progress`` key with no value on its
    line is refused by name, even when the line below holds ``false``; a ``concurrency`` key under ``with:``
    or ``env:`` is read as a block with no ``cancel-in-progress`` key (refused; no workflow writes either).
    decision (round 11, REVIEW-8332-code-r10 INFO): a plain line continuing a ``cancel-in-progress`` value is
    refused by name (MULTILINE_CANCEL) over reading its first line, because YAML folds both lines into one string.
    """
    raws, blocks, cur, child, after_cancel = text.splitlines(), [], None, None, False
    for n, ln in enumerate(scan(text), 1):
        x = ln.text
        if not x.strip():
            continue
        if ln.plain and after_cancel:
            raise ParseFailure(f"line {n}: {MULTILINE_CANCEL}")
        after_cancel = False
        m = None if ln.cont or ln.depth else KEY_LINE_RE.match(x)
        if cur is not None and not ln.cont and not ln.depth and _indent(x) <= cur[0]:
            cur = None
        used = {CANCEL_KEY: 0, CONCURRENCY_KEY: 0}
        if cur is not None and m and child in (None, len(m.group(1))):
            child = len(m.group(1))
            if m.group(3) == CANCEL_KEY:
                if not m.group(4):
                    raise ParseFailure(f"line {n}: {NEXT_LINE_CANCEL}")
                cur[1].append(raws[n - 1][m.start(4):len(x)].strip())
                used[CANCEL_KEY], after_cancel = 1, True
        if m and m.group(3) == CONCURRENCY_KEY:
            cur, child, used[CONCURRENCY_KEY] = _concurrency_key(m, n, blocks), None, 1
        for key, token in TOKEN_RES.items():
            if len(token.findall(x)) > used[key]:
                raise ParseFailure(f"line {n}: a `{key}` key outside a block `concurrency:` mapping's direct children")
    return blocks


def cancel_violations(name: str, text: str) -> list:
    """Problems for one workflow file's text (empty list = compliant)."""
    try:
        triggered = bool(triggers(text))
    except ParseFailure as exc:
        return [f"{name}: cannot parse the trigger section ({exc}); failing closed"]
    if not triggered:
        return []
    try:
        blocks = concurrency_blocks(text)
    except ParseFailure as exc:
        return [f"{name}: cannot parse the concurrency keys ({exc}); failing closed"]
    problems = []
    if any(not keys for keys in blocks):
        problems.append(f"{name}: a concurrency block has no cancel-in-progress key")
    if "edited" in pr_types(text):
        for value in (v for keys in blocks for v in keys):
            if not guard_ok(value):
                problems.append(f"{name}: lists `edited` with cancel-in-progress `{value}` and no accepted guard")
    return problems


def edited_listed(name: str, text: str) -> list:
    try:
        listed = "edited" in pr_types(text)
    except ParseFailure as exc:
        return [f"{name}: cannot parse the trigger section ({exc}); failing closed"]
    if listed and name not in EDITED_ALLOW:
        return [f"{name}: lists `edited` under pull_request(_target) types (#8332)"]
    return []


def target_extras(texts: dict) -> list:
    extra, broken = [], []
    for n, t in sorted(texts.items()):
        try:
            if has_trigger(t, "pull_request_target") and n not in TARGET_ALLOW:
                extra.append(n)
        except ParseFailure as exc:
            broken.append(f"{n}: cannot parse the trigger section ({exc}); failing closed")
    return broken + [f"{n}: second pull_request_target workflow; none has ever run in this repository (#8337)"
                     for n in extra]


def _all(directory=WF):
    """Every workflow text, ``*.yml`` and ``*.yaml`` (GitHub reads both; test_workflow_pr_triggers_5447 too)."""
    paths = sorted(list(directory.glob("*.yml")) + list(directory.glob("*.yaml")))
    return {p.name: p.read_text(encoding="utf-8") for p in paths}


BASE_BAD = (
    "on:\n  pull_request:\n    types: [opened, synchronize, reopened, edited]\n"
    "concurrency:\n  group: g\n  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n"
)


class BodyOnlyEditNeverCancels8332(unittest.TestCase):
    def test_every_workflow_cancel_key_is_guarded(self):
        problems = []
        for name, text in _all().items():
            problems += cancel_violations(name, text)
        self.assertEqual(problems, [])

    def test_no_workflow_lists_edited_beyond_the_allow_list(self):
        problems = []
        for name, text in _all().items():
            problems += edited_listed(name, text)
        self.assertEqual(problems, [])

    def test_ci_and_coverage_do_not_list_edited(self):
        for name in NO_EDITED:
            types = pr_types((WF / name).read_text(encoding="utf-8"), ("pull_request",))
            self.assertTrue(types, f"{name}: pull_request.types not found")
            self.assertNotIn("edited", types, name)

    def test_only_one_pull_request_target_workflow(self):
        texts = _all()
        self.assertEqual(target_extras(texts), [])
        self.assertTrue(has_trigger(texts["claude-md-rule-compare.yml"], "pull_request_target"))

    def test_retarget_workflow_is_gone(self):
        self.assertFalse((WF / "pr-retarget.yml").exists())
        self.assertTrue((ROOT / "scripts" / "ci" / "pr_retarget_check.py").is_file())

    def test_rule_compare_keeps_edited_with_guard(self):
        text = (WF / "claude-md-rule-compare.yml").read_text(encoding="utf-8")
        self.assertIn("edited", pr_types(text))
        self.assertEqual(cancel_violations("claude-md-rule-compare.yml", text), [])

    # ---- mutation self-tests: each shape must be caught ----
    def test_mutation_job_level_key_true(self):
        bad = BASE_BAD.replace("${{ github.event_name == 'pull_request' }}", "false") + (
            "jobs:\n  a:\n    concurrency:\n      group: j\n      cancel-in-progress: true\n")
        self.assertEqual(len(cancel_violations("m.yml", bad)), 1)

    def test_mutation_missing_key(self):
        bad = BASE_BAD.replace("  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n", "")
        self.assertEqual(len(cancel_violations("m.yml", bad)), 1)

    def test_mutation_or_true(self):
        bad = BASE_BAD.replace("'pull_request' }}", "'pull_request' || true }}")
        self.assertEqual(len(cancel_violations("m.yml", bad)), 1)

    def test_mutation_or_push_event(self):
        bad = BASE_BAD.replace("'pull_request' }}", "'pull_request' || github.event_name == 'push' }}")
        self.assertEqual(len(cancel_violations("m.yml", bad)), 1)

    def test_accepted_forms(self):
        for value in ("false", "${{ github.event_name == 'pull_request' }}",
                      "${{ github.event.action != 'edited' }}",
                      "${{ github.event_name == 'pull_request' && github.ref != 'refs/heads/main' }}"):
            ok = BASE_BAD.replace("${{ github.event_name == 'pull_request' }}", value)
            self.assertEqual(cancel_violations("ok.yml", ok), [], value)

    def test_mutation_edited_injected_into_ci_and_coverage(self):
        for name in NO_EDITED:
            text = (WF / name).read_text(encoding="utf-8")
            self.assertEqual(edited_listed(name, text), [])
            mutated = text.replace("types: [opened, synchronize, reopened]",
                                   "types: [opened, synchronize, reopened, edited]", 1)
            self.assertNotEqual(mutated, text, name)
            self.assertEqual(len(edited_listed(name, mutated)), 1, name)

    def test_mutation_edited_under_pull_request_target(self):
        bad = BASE_BAD.replace("  pull_request:", "  pull_request_target:")
        self.assertEqual(len(edited_listed("m.yml", bad)), 1)

    def test_mutation_edited_as_block_sequence(self):
        bad = ("on:\n  pull_request:\n    types:\n      - opened\n      - edited\n"
               "concurrency:\n  group: g\n  cancel-in-progress: false\n")
        self.assertEqual(len(edited_listed("m.yml", bad)), 1)
        self.assertIn("edited", pr_types(bad))

    def test_mutation_edited_in_flow_mapping_trigger(self):
        bad = "on: {pull_request: {types: [opened, edited]}}\n"
        self.assertEqual(len(edited_listed("m.yml", bad)), 1)
        tgt = "on: {pull_request_target: {types: [edited]}}\n"
        self.assertEqual(len(edited_listed("m.yml", tgt)), 1)
        self.assertEqual(len(target_extras({"m.yml": tgt})), 1)

    def test_block_and_flow_forms_without_edited_pass(self):
        for good in ("on:\n  pull_request:\n    types:\n      - opened\n      - synchronize\n",
                     "on: {pull_request: {types: [opened, synchronize]}}\n",
                     "on:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\n"):
            self.assertEqual(edited_listed("ok.yml", good), [], good)

    def test_mutation_parse_failure_fails_closed(self):
        for bad in ("name: x\njobs: {}\n",
                    "on: &t\n  pull_request:\n    types: *x\n",
                    "on:\n"):
            self.assertEqual(len(edited_listed("m.yml", bad)), 1, bad)
            self.assertEqual(len(cancel_violations("m.yml", bad)), 1, bad)
            self.assertEqual(len(target_extras({"m.yml": bad})), 1, bad)

    def test_mutation_quoted_trigger_keys(self):
        for q in ('"', "'"):
            block = f"on:\n  {q}pull_request{q}:\n    types: [opened, edited]\n"
            self.assertEqual(len(edited_listed("m.yml", block)), 1, block)
            seq = f"on:\n  {q}pull_request{q}:\n    types:\n      - {q}edited{q}\n"
            self.assertEqual(len(edited_listed("m.yml", seq)), 1, seq)
            tgt = f"on:\n  {q}pull_request_target{q}:\n    types: [edited]\n"
            self.assertEqual(len(target_extras({"m.yml": tgt})), 1, tgt)
            flow = f"on: {{{q}pull_request{q}: {{types: [edited]}}}}\n"
            self.assertEqual(len(edited_listed("m.yml", flow)), 1, flow)

    def test_mutation_multiline_flow_mapping(self):
        for bad in ("on: {\n  pull_request: {\n    types: [opened,\n      edited]\n  }\n}\n",
                    "on:\n  {\n  pull_request: {types: [opened, edited]}\n  }\nname: x\n",
                    "on: [push,\n  pull_request]\n"):
            if "edited" in bad:
                self.assertEqual(len(edited_listed("m.yml", bad)), 1, bad)
            self.assertTrue(has_trigger(bad, "pull_request"), bad)
        tgt = "on: {\n  pull_request_target: {types: [edited]}\n}\n"
        self.assertEqual(len(target_extras({"m.yml": tgt})), 1)
        ok = "on: {\n  pull_request: {types: [opened, synchronize]}\n}\njobs: {}\n"
        self.assertEqual(edited_listed("ok.yml", ok), [])

    def test_mutation_quoted_bracket_in_multiline_flow(self):
        # A quoted `}` or `]` must not end the join early (REVIEW-8332-security-r4 S7).
        for q in ('"', "'"):
            for br in ("}", "]", "}]"):
                bad = (f"on: {{\n  pull_request: {{branches: [{q}rel{br}x{q}],\n"
                       "    types: [edited]}\n}\njobs: {}\n")
                self.assertEqual(len(edited_listed("m.yml", bad)), 1, bad)
        short = "on: {pull_request: {types: [opened]}}\n  types: [edited]\njobs: {}\n"
        out = edited_listed("short.yml", short)
        self.assertEqual(len(out), 1)
        self.assertIn("short.yml", out[0])

    def test_quoted_value_without_brackets_still_joins(self):
        ok = ('on: {\n  pull_request: {branches: ["release/v1", \'main\'],\n'
              "    types: [opened, synchronize]}\n}\njobs: {}\n")
        self.assertEqual(edited_listed("ok.yml", ok), [])
        self.assertTrue(has_trigger(ok, "pull_request"))

    def test_mutation_unclosed_flow_is_refused_by_name(self):
        bad = "on: {\n  pull_request: {types: [opened, edited]\n"
        out = edited_listed("unclosed.yml", bad)
        self.assertEqual(len(out), 1)
        self.assertIn("unclosed.yml", out[0])
        self.assertIn("unclosed flow", out[0])

    def test_mutation_capitalised_edited(self):
        bad = BASE_BAD.replace("edited]", "Edited]")
        self.assertEqual(len(edited_listed("m.yml", bad)), 1)

    def test_yaml_extension_workflows_are_scanned(self):
        SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as tmp:
            d = Path(tmp)
            (d / "a.yml").write_text("on:\n  push:\n", encoding="utf-8")
            (d / "b.yaml").write_text(BASE_BAD, encoding="utf-8")
            texts = _all(d)
            self.assertEqual(sorted(texts), ["a.yml", "b.yaml"])
            self.assertEqual(len(edited_listed("b.yaml", texts["b.yaml"])), 1)

    def test_mutation_second_pull_request_target_workflow(self):
        texts = dict(_all())
        texts["second.yml"] = "on:\n  pull_request_target:\n    types: [opened]\n"
        out = target_extras(texts)
        self.assertEqual(len(out), 1)
        self.assertIn("#8337", out[0])


EDITED, CLEAN, REFUSE = "edited", "clean", "refuse"
CANCEL_TRUE = "concurrency:\n  group: g\n  cancel-in-progress: true\n"
APOSTROPHE_COL0 = ("on: {workflow_dispatch: {inputs: {mode: {description: it's a mode, type: choice, "
                   "options: ['a', 'b']}}},\nKIND: {types: [edited]}}\n")
WD = "on:\n  workflow_dispatch:\n    inputs:\n      x:\n"
# Round 8 (REVIEW-8332-code-r7 F1, REVIEW-8332-security-r7 S14): a value that starts on the line BELOW its
# key or bare dash. Each shape is built under both owners: (owner, prefix, the value's column). ``{v}`` is
# the value's column, ``{m}`` a column between the owner and the value (still owned by the key or dash).
# Round 9 (REVIEW-8332-code-r8 F1): the carried owner column survives a blank or comment line between the
# key or dash and its value, so every shape also runs through those three owners.
NEXT_OWNERS = (("key", WD + "        description:\n", 10), ("bare dash", WD + "        options:\n          -\n", 12),
               ("key, comment line", WD + "        description:\n        # note\n", 10),
               ("key, blank line", WD + "        description:\n\n", 10),
               ("bare dash, comment line", WD + "        options:\n          -\n          # note\n", 12))
PR_EDITED = "  pull_request:\n    types: [edited]"
# Round 9 (REVIEW-8332-security-r8 S16): ``{p}`` is a property written before a key outside ``on:``; the
# real ``on:`` follows, and a later quoted run value holds a column-0 line.
COL0_TAIL = "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: 'x\non:\n  push:\n    branches: [y]'\n"
PROPERTY_ON_KEY = "env:\n  A: &a k\n  {p}: run\n    'mode\n" + "on:\n" + PR_EDITED + "\n" + COL0_TAIL
PROPERTY_ON_KEY_DASH = ("env:\n  A: &a k\n  L:\n    - {p}: run\n        'mode\n" + "on:\n" + PR_EDITED + "\n"
                        + COL0_TAIL)
NEXT_SHAPES = (
    ("single-quote continuation", "{v}run the\n{v}'mode\n", PR_EDITED + "  # it's\n", REFUSE),
    ("single-quote continuation, target", "{v}run the\n{v}'mode\n",
     "  pull_request_target:\n    types: [edited]  # it's\n", REFUSE),
    ("double-quote continuation", '{v}run the\n{v}"mode\n', PR_EDITED + '  # "\n', REFUSE),
    ("bracket continuation", "{v}run the\n{v}[mode\n", PR_EDITED + "\n    branches: main]\n", REFUSE),
    ("escaped trigger key inside a single-quote continuation", "{v}run the\n{v}'mode\n",
     '  "pull_r\\x65quest":\n    types: [edited]  # \'\n', REFUSE, ESCAPED_KEY),
    ("escaped target key inside a single-quote continuation", "{v}run the\n{v}'mode\n",
     '  "pull_r\\x65quest_target":\n    types: [edited]  # \'\n', REFUSE, ESCAPED_KEY),
    ("block indicator on its own line, content to its left", "{v}|\n{m}'mode\n", PR_EDITED + "  # it's\n",
     EDITED),
)
# The oracle: every trigger shape that made the ratchet fail open in rounds 3-8, with what it must read.
# EDITED = edited listed under a pull_request(_target) trigger; CLEAN = not listed; REFUSE = refused by name.
# An optional fourth field is a text the refusal or listing message must contain.
# Round 12 (REVIEW-8332-security-r11 S-r11-2, probes f2, f2b, f2c, verbatim): a block scalar header with a comment
# flush after it; libyaml and actionlint read the lines below as block content, the scanner refuses the file.
FLUSH_HEADER_JOB = ("name: c\non:\n  pull_request_target:\n    types: [opened, edited]\njobs:\n  j:\n"
                    "    runs-on: ubuntu-latest\n    steps:\n")
FLUSH_HEADER_ROWS = (
    ("f2 block scalar header with a comment flush after it hides a job concurrency block",
     FLUSH_HEADER_JOB + '      - run: |#c\n          echo a: "x\n    concurrency:\n      group: g\n'
     '      cancel-in-progress: true\n    env:\n      B: |#c\n        y"\n'),
    ("f2b same with a strip indicator before the flush comment",
     FLUSH_HEADER_JOB + '      - run: |-#c\n          echo a: "x\n    concurrency:\n      group: g\n'
     '      cancel-in-progress: true\n    env:\n      B: >-#c\n        y"\n'),
    ("f2c same, the block content opens a flow",
     FLUSH_HEADER_JOB + "      - run: |#c\n          echo a: [x\n    concurrency:\n      group: g\n"
     "      cancel-in-progress: true\n    env:\n      B: |#c\n        y]\n"),
)
# Round 13 (REVIEW-8332-security-r12 S-r12-2 b-sp and t-tab, REVIEW-8332-code-r12 F2 p-lasthash, verbatim): the
# round-12 helper already refuses all three; each row kills one fail-open helper mutant (last token only, a cut at
# the last `#`, tabs not read as blanks). Refused at line 9, as the rows above.
FLUSH_HEADER_ROWS_R13 = (
    ("b-sp flush comment holding a blank",
     FLUSH_HEADER_JOB + '      - run: |#c d\n          echo a: "x\n    concurrency:\n      group: g\n'
     '      cancel-in-progress: true\n    env:\n      B: x"\n'),
    ("p-lasthash flush comment holding two hashes",
     FLUSH_HEADER_JOB + '      - run: |#c#d\n          echo a: "x\n    concurrency:\n      group: g\n'
     '      cancel-in-progress: true\n    env:\n      B: x"\n'),
    ("t-tab a tab between the key and the flush-comment header",
     FLUSH_HEADER_JOB + '      - run:\t|#c\n          echo a: "x\n    concurrency:\n      group: g\n'
     '      cancel-in-progress: true\n    env:\n      B: x"\n'),
)
# Round 13 (REVIEW-8332-security-r12 S-r12-1 o-b5, o-b6; REVIEW-8332-code-r12 F1 o1, o3; verbatim): a plain key word
# led by an indicator and holding a `#` stands before the real flush-comment header on the same line; the round-12
# helper stopped at the first such token and read the block body as plain lines. (name, text, refused line)
FLUSH_HEADER_AFTER_KEY_ROWS = (
    ("o-b5 with-input key holding ' |#x' before a flush-comment header",
     FLUSH_HEADER_JOB + "      - uses: example-org/example-action@v1\n        with:\n          a |#x: |#c\n"
     '            echo a: "x\n    concurrency:\n      group: g\n      cancel-in-progress: true\n    env:\n'
     '      B: y"\n', 11),
    ("o-b6 with-input key holding ' >#', the header written |2-#c",
     FLUSH_HEADER_JOB + "      - uses: example-org/example-action@v1\n        with:\n          k >#: |2-#c\n"
     '              echo a: "x\n    concurrency:\n      group: g\n      cancel-in-progress: true\n    env:\n'
     '      B: y"\n', 11),
    ("o1 step with-input key holding '>#', then a flush-comment header",
     FLUSH_HEADER_JOB + "      - uses: example/act@v1\n        with:\n          X >#b: |#c\n"
     '            echo a: "x\n    concurrency:\n      group: g\n      cancel-in-progress: true\n    env:\n'
     '      B: |#c\n        y"\n', 11),
    ("o3 job outputs key holding '>#', then a flush-comment header",
     "name: c\non:\n  pull_request_target:\n    types: [opened, edited]\njobs:\n  j:\n"
     '    runs-on: ubuntu-latest\n    outputs:\n      X >#b: |#c\n        echo a: "x\n    concurrency:\n'
     '      group: g\n      cancel-in-progress: true\n    steps:\n      - run: echo hi\n        env:\n'
     '          B: |#c\n            y"\n', 9),
)
ORACLE = (
    ("r3 double-quoted block key", 'on:\n  "pull_request":\n    types: [opened, edited]\n', EDITED),
    ("r3 single-quoted key, quoted sequence item", "on:\n  'pull_request':\n    types:\n      - 'edited'\n", EDITED),
    ("r3 quoted flow key", 'on: {"pull_request": {types: [edited]}}\n', EDITED),
    ("r3 two-line flow", "on: {pull_request: {types: [opened,\n  edited]}}\n", EDITED),
    ("r3 three-line flow", "on: {\n  pull_request: {types: [opened, edited]}\n}\n", EDITED),
    ("r3 five-line flow", "on: {\n  pull_request: {\n    types: [opened,\n      edited]\n  }\n}\n", EDITED),
    ("r3 unclosed flow", "on: {\n  pull_request: {types: [opened, edited]\n", REFUSE),
    ("r3 Edited", "on:\n  pull_request:\n    types: [opened, Edited]\n", EDITED),
    ("r3 EDITED", "on:\n  pull_request:\n    types: [opened, EDITED]\n", EDITED),
    ("r3 list form", "on: [pull_request]\n", CLEAN),
    ("r3 comment lines holding edited", "on:\n  pull_request:\n    # edited\n    types: [opened]  # edited\n", CLEAN),
    ("r4 double-quoted } in a multi-line flow",
     'on: {\n  pull_request: {branches: ["rel}x"],\n    types: [edited]}\n}\n', EDITED),
    ("r4 single-quoted ] in a multi-line flow",
     "on: {\n  pull_request: {branches: ['rel]x'],\n    types: [edited]}\n}\n", EDITED),
    ("r4 short join, indented lines left", "on: {pull_request: {types: [opened]}}\n  types: [edited]\njobs: {}\n", REFUSE),
    ("r5 real comment holding } after the flow", "on: {pull_request: {types: [opened]}}  # }\njobs: {}\n", CLEAN),
    ("r5 real comment holding } inside a multi-line flow",
     "on: {\n  pull_request: {types: [opened]}, # }\n  pull_request_target: {types: [edited]}\n}\n", EDITED),
    ("r5 quoted scalar spanning lines with }}}", 'on: {pull_request: {branches: ["a\n  }}}"], types: [edited]}}\n', EDITED),
    ("r6 quoted space-# dq, block key inline flow", 'on:\n  pull_request: {paths: ["docs #x"], types: [edited]}\n', EDITED),
    ("r6 quoted space-# sq, block key inline flow", "on:\n  pull_request: {paths: ['docs #x'], types: [edited]}\n", EDITED),
    ("r6 quoted space-#, multi-line flow", 'on: {pull_request: {paths: ["docs #x"], types: [\n  edited]}}\n', EDITED),
    ("r6 quoted space-#, single-line flow", 'on: {pull_request: {paths: ["docs #x"], types: [edited]}}\n', EDITED),
    ("r6 quoted space-#, no edited", 'on:\n  pull_request: {paths: ["docs #x"], types: [opened]}\n', CLEAN),
    ("r6 escaped double quote then space-#", 'on:\n  pull_request: {branches: ["a\\" #x"], types: [edited]}\n', EDITED),
    ("r6 doubled single quote then space-#", "on:\n  pull_request: {branches: ['it''s #x'], types: [edited]}\n", EDITED),
    ("r6 apostrophe in a plain scalar, column-0 continuation",
     APOSTROPHE_COL0.replace("KIND", "pull_request"), EDITED),
    ("r6 apostrophe in a plain scalar, column-0 continuation, target",
     APOSTROPHE_COL0.replace("KIND", "pull_request_target"), EDITED),
    ("r6 column-0 continuation", "on: {push: {branches: [main]},\npull_request: {types: [edited]}}\n", EDITED),
    ("r6 apostrophe and quotes in a block plain scalar",
     "on:\n  workflow_dispatch:\n    inputs:\n      x:\n        description: it's a 'mode' [\n"
     "  pull_request:\n    types: [edited]\n", EDITED),
    ("r6 block scalar holding quotes and brackets",
     "on:\n  workflow_dispatch:\n    inputs:\n      x:\n        description: |\n          it's [edited { \"#\n"
     "  pull_request:\n    types: [opened]\n", CLEAN),
    ("r6 column-0 non-key after the on: section", "on:\n  pull_request:\n    types: [opened]\ntypes: [edited]\n", REFUSE),
    ("r6 unterminated quoted scalar", 'on:\n  pull_request:\n    branches: ["a\n    types: [edited]\n', REFUSE),
    ("r6 second top-level on: key", "on:\n  push:\non:\n  pull_request:\n    types: [edited]\n", REFUSE),
    ("r6 whole-document flow mapping", '{"on": {"pull_request": {"types": ["edited"]}}}\n', REFUSE),
    # round 7, REVIEW-8332-code-r6 F1 / REVIEW-8332-security-r6 S12: a plain-scalar continuation line that
    # begins with a quote or bracket opened a scanner-only scalar and swallowed the trigger after it.
    ("r7 plain continuation starting with a single quote",
     WD + "        description: run the\n          'mode\n  pull_request:\n    types: [edited]  # it's\n",
     REFUSE, "multi-line plain scalar"),
    ("r7 plain continuation starting with a double quote",
     WD + "        description: run the\n          \"mode\n  pull_request:\n    types: [edited]  # \"\n",
     REFUSE, "multi-line plain scalar"),
    ("r7 plain continuation starting with a bracket",
     WD + "        description: run the\n          [mode\n  pull_request:\n    types: [edited]\n    branches: main]\n",
     REFUSE, "multi-line plain scalar"),
    ("r7 plain continuation closed by an apostrophe in a later plain scalar, target",
     WD + "        description: run the\n          'mode\n  pull_request_target:\n    types: [edited]\n"
     "    branches: it's\n", REFUSE, "multi-line plain scalar"),
    ("r7 plain continuation in a sequence item",
     WD + "        options:\n          - run the\n            'mode\n  pull_request:\n    types: [edited]  # '\n",
     REFUSE, "multi-line plain scalar"),
    ("r7 plain continuation inside a flow mapping",
     "on: {workflow_dispatch: {inputs: {x: {description: run the\n  'mode}}}, pull_request: {types: [edited]}}  # '\n",
     REFUSE, "multi-line plain scalar"),
    ("r7 tagged block scalar whose content starts with a quote",
     WD + "        description: ! |\n          'mode\n  pull_request:\n    types: [edited]  # it's\n",
     REFUSE, "a tag (`!`)"),
    # round 7, REVIEW-8332-code-r6 F2: an escape could spell an activity word the scanner never saw.
    ("r7 hex escape spells edited", 'on:\n  pull_request:\n    types: ["\\x65dited"]\n', REFUSE, "escape \\x"),
    ("r7 4-digit unicode escape spells edited", 'on:\n  pull_request:\n    types: ["\\u0065dited"]\n',
     REFUSE, "escape \\u"),
    ("r7 8-digit unicode escape spells edited", 'on:\n  pull_request:\n    types: ["\\U00000065dited"]\n',
     REFUSE, "escape \\U"),
    ("r7 escaped line break spells edited", 'on:\n  pull_request:\n    types: ["ed\\\n      ited"]\n',
     REFUSE, "escaped line break"),
    # round 7, REVIEW-8332-code-r6 F3 / REVIEW-8332-security-r6 S13: one row per mutant that survived round 6.
    ("r7 block scalar content starting with a quote, then a trigger",
     WD + "        description: |\n          \"it's [\n  pull_request:\n    types: [edited]  # \"\n", EDITED),
    ("r7 block scalar content starting with a bracket, then a trigger",
     WD + "        description: >\n          [mode\n  pull_request:\n    types: [edited]\n    branches: main]\n",
     EDITED),
    ("r7 unterminated quote, no bracket",
     "on:\n  push:\n    branches: 'main\n  pull_request:\n    types: [edited]\n", REFUSE, "unterminated quoted scalar"),
    ("r7 alias in types to an anchor in env",
     "env:\n  T: &t edited\non:\n  pull_request:\n    types: [*t]\n", REFUSE, "an alias (`*`)"),
    # round 7: the continuation-attribution mutant (REVIEW-8332-security-r6 INFO), the tag before a block
    # indicator or a quote, the second layer, and a one-line plain value that must not be read as continuing.
    ("r7 quoted scalar spanning lines in a block trigger's flow value",
     'on:\n  pull_request: {branches: ["a\n    b"], types: [edited]}\n', EDITED),
    ("r7 tagged block scalar before on:", "env:\n  X: !!str |\n    'a\non:\n  pull_request:\n    types: [edited]\n",
     EDITED),
    ("r7 tagged quoted scalar with a column-0 continuation before on:",
     "env:\n  X: !!str 'a\non: push'\non:\n  pull_request:\n    types: [edited]\n", EDITED),
    ("r7 pull_request word on a quoted continuation under another trigger",
     'on:\n  push:\n    branches: ["a\n  pull_request:\n    types: [edited] b"]\n',
     REFUSE, "continuation line under the `push` trigger"),
    ("r7 one-line plain value under a deeper key, then a trigger",
     WD + "        description: it's a [mode\n        required: false\n  pull_request:\n    types: [edited]\n", EDITED),
    # round 8, REVIEW-8332-code-r7 F2 / REVIEW-8332-security-r7 INFO (OWN-B): the second layer, reached
    # outside any flow bracket (a quoted continuation) and at flow depth with no continuation.
    ("r8 pull_request word on a single-quoted continuation outside brackets",
     "on:\n  workflow_dispatch:\n  push:\n    branches: 'a\n  pull_request:\n    types: [edited] b'\n",
     REFUSE, "continuation line under the `push` trigger"),
    ("r8 pull_request word on a double-quoted continuation outside brackets",
     'on:\n  workflow_dispatch:\n  push:\n    branches: "a\n  pull_request:\n    types: [edited] b"\n',
     REFUSE, "continuation line under the `push` trigger"),
    ("r8 pull_request word at flow depth under another trigger",
     "on:\n  push: {branches: [a,\n    pull_request]}\n  pull_request:\n    types: [opened]\n",
     REFUSE, "continuation line under the `push` trigger"),
    # round 8, REVIEW-8332-code-r7 F1: outside `on:` a next-line plain value is read, not refused.
    ("r8 next-line plain value with a quote continuation before on:",
     "env:\n  X:\n    a\n    'b\non:\n  pull_request:\n    types: [edited]\n", EDITED),
    # round 8: a comment ends a plain scalar in YAML, so a deeper line after it is not YAML (found by the
    # trailing-comment differential variant of the row above); the whole file is refused by name.
    ("r8 deeper line after a plain value cut by a trailing comment",
     "env:\n  X: a  # c\n    'b\non:\n  pull_request:\n    types: [edited]  # '\n", REFUSE, PAST_COMMENT),
    ("r8 deeper line after a comment line inside a plain value",
     "env:\n  X:\n    a\n    # c\n    b\non:\n  pull_request:\n    types: [edited]\n", REFUSE, PAST_COMMENT),
    # round 8, REVIEW-8332-code-r7 INFO-2 / INFO-3: each property is named; a duplicate trigger key refuses.
    ("r8 anchor on a trigger", "on:\n  pull_request: &p\n    types: [opened]\n", REFUSE, "an anchor (`&`)"),
    ("r8 merge key in a trigger", "on:\n  pull_request:\n    <<: {types: [edited]}\n", REFUSE,
     "a merge key (`<<`)"),
    ("r8 explicit trigger key", "on:\n  ? pull_request\n  : {types: [edited]}\n", REFUSE, "an explicit key (`?`)"),
    ("r8 duplicate trigger key, the last one clean",
     "on:\n  pull_request:\n    types: [edited]\n  pull_request:\n    types: [opened]\n",
     REFUSE, "duplicate trigger key `pull_request`"),
    # round 9, REVIEW-8332-code-r8 INFO-1 / REVIEW-8332-security-r8 INFO-1: the owner is taken only by a
    # deeper line; a sibling key or a dash at the key's own column is not the key's value.
    ("r9 sibling key at the column of an empty-valued key",
     WD + "        description:\n        required: false\n  pull_request:\n    types: [edited]\n", EDITED),
    ("r9 dash at the column of an empty-valued key", "on:\n  pull_request:\n    types:\n    - edited\n", EDITED),
    # round 9, REVIEW-8332-security-r8 S16: a property on a VALUE (here a whole mapping) is not on its key.
    ("r9 anchor ending the line of a mapping value before on:",
     "env: &e\n  X: run\n    'mode\non:\n  pull_request:\n    types: [edited]\n", EDITED),
) + tuple(
    # round 9, REVIEW-8332-security-r8 S16: a property on a mapping key outside `on:` (anchor, tag, alias),
    # with a column-0 line inside a later quoted value, at top level and under a bare dash.
    (f"r9 {what} on a key before on:{where}", text.format(p=prop), REFUSE, PROPERTY_KEY)
    for what, prop in (("anchor", "&a X"), ("tag", "!!str X"), ("alias", "*a "), ("alias with no space", "*a"))
    for where, text in (("", PROPERTY_ON_KEY), (", under a bare dash", PROPERTY_ON_KEY_DASH))
) + tuple(
    (f"r8 next-line value under a {owner}: {name}",
     prefix + value.format(v=" " * col, m=" " * (col - 1)) + trigger, want,
     *((msg or [NEXT_LINE_PLAIN]) if want == REFUSE else []))
    for owner, prefix, col in NEXT_OWNERS for name, value, trigger, want, *msg in NEXT_SHAPES
) + tuple(
    # round 10, REVIEW-8332-security-r9 S18: an explicit key outside `on:` (top level, under env:, deeper),
    # with a continuation between the `?` and key columns that opens a quote, then the column-0 decoy.
    (f"r10 explicit key before on:{where}", text + "on:\n" + PR_EDITED + "\n" + COL0_TAIL, REFUSE,
     f"line {n}: {EXPLICIT_KEY}")
    for where, text, n in ((", top level", "? X\n: run\n 'mode\n", 1),
                           (", under env", "env:\n  ? X\n  : run\n   'mode\n", 2),
                           (", anchor-free, deeper", "env:\n  ? Xlongerkey\n  : run\n      'mode\n", 2))
) + tuple(
    # round 10, REVIEW-8332-code-r9 F2: a double-quoted key holding any escape, anywhere in the file.
    (f"r10 double-quoted key with escape {esc} before on:", f'env:\n  "X{esc}": v\non:\n' + PR_EDITED + "\n",
     REFUSE, f"line 2: {ESCAPED_KEY}")
    for esc in ("\\u0058", "\\x58", "\\U00000058", "\\N", '\\"')
) + (
    ("r10 double-quoted key with an escape in a flow mapping before on:",
     'env: {"\\x58": v}\non:\n' + PR_EDITED + "\n", REFUSE, f"line 1: {ESCAPED_KEY}"),
    ("r10 explicit key after a dash before on:", "x:\n  - ? k\n    : v\non:\n" + PR_EDITED + "\n", REFUSE,
     f"line 2: {EXPLICIT_KEY}"),
    # a bare `:` line with no `?` (an empty implicit key): the owner column is the previous line's token.
    ("r10 bare colon line (empty key) before on:",
     "env:\n  Xlongerkey: a\n  : run\n      'mode\non:\n" + PR_EDITED + "\n" + COL0_TAIL, REFUSE,
     f"line 3: {EXPLICIT_KEY}"),
    # controls: `?` and `:` inside values, an escape in a value, a quoted key without escapes, block text
    ("r10 question mark and colon inside values, quoted key without escapes, escaped value",
     'env:\n  A: "x\n    ? y"\n  B: a:b\n  "plain-key": v\n  C: \'? z\'\n  D: "a\\x41 \\" ok"\non:\n'
     + PR_EDITED + "\n", EDITED),
    ("r10 explicit-key text inside a block scalar",
     "jobs:\n  j:\n    steps:\n      - run: |\n          ? k\n          : v\non:\n" + PR_EDITED + "\n", EDITED),
    # round 11, REVIEW-8332-code-r10 F1: a JSON-like quoted key flush against its value in a flow `on:`.
    ("r11 flow on: with a JSON-adjacent escaped trigger key",
     'on: {"pull_r\\x65quest":{types: [edited]}}\n', REFUSE, f"line 1: {ESCAPED_KEY}"),
    ("r11 flow on: with a JSON-adjacent key holding a read escape",
     'on: {pull_request: {types: [opened]}, "x\\"y":{types: [edited]}}\n', REFUSE, f"line 1: {ESCAPED_KEY}"),
    ("r11 flow on: with JSON-adjacent quoted keys without escapes (control)",
     'on: {"pull_request":{"types":[edited]}}\n', EDITED),
    # round 11 (own probe): a quote inside a plain scalar closes nothing, so it opens no quote after a colon.
    ("r11 plain scalar holding quote-colon-quote before on:", 'env:\n  K: a":"x\non:\n' + PR_EDITED + "\n", EDITED),
    ("r11 plain scalar holding single-quote-colon-quote before on:",
     "env:\n  K: a':'x\non:\n" + PR_EDITED + "\n", EDITED),
    # round 11, REVIEW-8332-code-r10 F1 control: outside a flow collection "k":v is not YAML; refused by name.
    ("r11 block quoted key flush against a plain value before on:", 'env:\n  "a":b\non:\n' + PR_EDITED + "\n",
     REFUSE, f"line 2: {ADJACENT_KEY}"),
    ("r11 block quoted key flush against a quoted value before on:", 'env:\n  "a":"b"\non:\n' + PR_EDITED + "\n",
     REFUSE, f"line 2: {ADJACENT_KEY}"),
    ("r11 plain key starting with a colon at column 0 before on: (control)", ":x: 1\non:\n" + PR_EDITED + "\n",
     EDITED),
    # round 11, REVIEW-8332-code-r10 INFO-1 / security-r10 INFO-2 pin: a plain continuation led by `? ` is
    # refused as an explicit key (valid YAML, fail closed, no workflow writes it).
    ("r11 plain continuation line led by a question mark before on:",
     "env:\n  A: some plain\n    ? text\non:\n" + PR_EDITED + "\n", REFUSE, f"line 3: {EXPLICIT_KEY}"),
    # round 12, REVIEW-8332-security-r11 S-r11-2: a flush comment after a block scalar header is refused by name.
    *((f"r12 {name}", text, REFUSE, f"line 9: {FLUSH_COMMENT_HEADER}") for name, text in FLUSH_HEADER_ROWS),
    # round 13, REVIEW-8332-security-r12 S-r12-2 / REVIEW-8332-code-r12 F2: the three mutant-killing rows.
    *((f"r13 {name}", text, REFUSE, f"line 9: {FLUSH_COMMENT_HEADER}") for name, text in FLUSH_HEADER_ROWS_R13),
)
# Round 7 differential variants: each keeps the YAML meaning of a row, or makes it invalid (then only a
# refusal is accepted): a trailing comment on every line, a doubled-quote key before ``on:``, one more
# indentation level, and a quoted scalar continued at column 0 before ``on:``.
VARIANTS = (
    ("trailing comment", lambda t: "".join(ln + "  # t\n" for ln in t.splitlines())),
    ("doubled-quote escape", lambda t: "name: 'it''s \"q\" #x'\n" + t),
    ("extra indentation", lambda t: "".join(" " * _indent(ln) + ln + "\n" for ln in t.splitlines())),
    ("column-0 continuation", lambda t: "run-name: 'a\nb [c # d'\n" + t),
)


# Round 9 (REVIEW-8332-security-r8 S17): the cancel-in-progress binding, read for the allow-listed workflow
# (it lists edited). The third field is a text the first problem must contain, or None for compliant.
CANCEL_HEAD = "name: c\non:\n  pull_request_target:\n    types: [opened, edited]\n"
CANCEL_JOB = "jobs:\n  j:\n    runs-on: ubuntu-latest\n"
CANCEL_STEPS = "    steps:\n      - run: echo hi\n"
CANCEL_ORACLE = (
    ("r9 flow-form concurrency with a decoy key in a job env",
     CANCEL_HEAD + "concurrency: {group: g, cancel-in-progress: true}\n" + CANCEL_JOB
     + "    env:\n      cancel-in-progress: false\n", "flow-form"),
    ("r9 decoy key in a job env, block concurrency without the key",
     CANCEL_HEAD + "concurrency:\n  group: g\n" + CANCEL_JOB + "    env:\n      cancel-in-progress: false\n",
     "outside a block `concurrency:`"),
    ("r9 flow-form job concurrency with a decoy key in the job env",
     CANCEL_HEAD + CANCEL_JOB + "    concurrency: {group: j, cancel-in-progress: true}\n"
     "    env:\n      cancel-in-progress: false\n", "flow-form"),
    ("r9 decoy key in a flow env, block concurrency without the key",
     CANCEL_HEAD + "concurrency:\n  group: g\n" + CANCEL_JOB + "    env: {cancel-in-progress: false}\n",
     "outside a block `concurrency:`"),
    ("r9 key one level deeper than the concurrency children",
     CANCEL_HEAD + "concurrency:\n  group:\n    cancel-in-progress: false\n  cancel-in-progress: true\n" + CANCEL_JOB,
     "outside a block `concurrency:`"),
    ("r9 decoy key in a top-level env after a block concurrency without the key",
     CANCEL_HEAD + "concurrency:\n  group: g\nenv:\n  cancel-in-progress: false\n" + CANCEL_JOB,
     "outside a block `concurrency:`"),
    ("r9 key only one level deeper than the concurrency children",
     CANCEL_HEAD + "concurrency:\n  group:\n    cancel-in-progress: false\n" + CANCEL_JOB,
     "outside a block `concurrency:`"),
    ("r9 top-level block concurrency, true, allow-listed workflow",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: true\n" + CANCEL_JOB,
     "cancel-in-progress `true`"),
    ("r9 job-level block concurrency, true, under a top-level false",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n" + CANCEL_JOB
     + "    concurrency:\n      group: j\n      cancel-in-progress: true\n", "cancel-in-progress `true`"),
    ("r9 top-level and job-level block concurrency, both guarded",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: ${{ github.event.action != 'edited' }}\n"
     + CANCEL_JOB + "    concurrency:\n      group: j\n      cancel-in-progress: false  # f\n", None),
    # round 10, REVIEW-8332-code-r9 F2 (f-own1b, f-own2c, f-own1g): escaped and explicit job-level keys.
    ("r10 f-own1b job-level escaped keys, true",
     CANCEL_HEAD + CANCEL_JOB + '    "concurrenc\\u0079":\n      group: j\n      "cancel\\u002din-progress": true\n'
     + CANCEL_STEPS, f"cannot parse the trigger section (line 8: {ESCAPED_KEY}"),
    ("r10 f-own2c job-level explicit keys, true",
     CANCEL_HEAD + CANCEL_JOB + "    ? concurrency\n    : group: j\n      ? cancel-in-progress\n      : true\n"
     + CANCEL_STEPS, f"cannot parse the trigger section (line 8: {EXPLICIT_KEY}"),
    ("r10 f-own1g pull_request without edited, job-level escaped concurrency without the key",
     "name: c\non:\n  pull_request:\n    types: [opened]\n" + CANCEL_JOB + '    "concurrenc\\u0079":\n'
     "      group: j\n" + CANCEL_STEPS, f"cannot parse the trigger section (line 8: {ESCAPED_KEY}"),
    # round 10, REVIEW-8332-code-r9 INFO-1: the quoted arm of the stray-key pattern.
    ("r10 quoted decoy key in a job env, block concurrency without the key",
     CANCEL_HEAD + "concurrency:\n  group: g\n" + CANCEL_JOB + '    env:\n      "cancel-in-progress": false\n',
     "outside a block `concurrency:`"),
    # round 10, REVIEW-8332-code-r9 INFO-2/INFO-3: pinned over-refusals (see OVER_REFUSALS).
    ("r10 cancel value on the next line, false",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress:\n    false\n" + CANCEL_JOB,
     f"line 7: {NEXT_LINE_CANCEL}"),
    ("r10 cancel value on the next line, true",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress:\n    true\n" + CANCEL_JOB,
     f"line 7: {NEXT_LINE_CANCEL}"),
    ("r10 concurrency key under a step with:",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n" + CANCEL_JOB
     + "    steps:\n      - uses: a/b@v1\n        with:\n          concurrency: 3\n",
     "a concurrency block has no cancel-in-progress key"),
    ("r10 concurrency key under a job env:",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n" + CANCEL_JOB
     + "    env:\n      concurrency: 3\n", "a concurrency block has no cancel-in-progress key"),
    # controls: quoted keys without escapes are read; `?` and `:` inside values are text.
    ("r10 job-level quoted keys without escapes, false",
     CANCEL_HEAD + CANCEL_JOB + '    "concurrency":\n      group: j\n      \'cancel-in-progress\': false\n'
     + CANCEL_STEPS, None),
    ("r10 tab before a trailing comment on a false value",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\t# tab then comment\n" + CANCEL_JOB,
     None),
    ("r10 question mark and colon inside step values",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n" + CANCEL_JOB
     + '    steps:\n      - run: a:b\n      - run: "x ? y : z"\n', None),
    # round 11, REVIEW-8332-code-r10 F1 (probe e1 and a flow f-own1g): escaped JSON-like keys in a flow `jobs:`.
    ("r11 e1 flow jobs, JSON-adjacent escaped job concurrency keys, true",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n"
     'jobs: {j: {runs-on: ubuntu-latest, "concurrenc\\u0079":{group: j, "cancel\\u002din-progress":true},'
     " steps: [{run: echo hi}]}}\n", f"cannot parse the trigger section (line 8: {ESCAPED_KEY}"),
    ("r11 f-own1g flow form, pull_request without edited, JSON-adjacent escaped concurrency without the key",
     "name: c\non:\n  pull_request:\n    types: [opened]\n"
     'jobs: {j: {runs-on: ubuntu-latest, "concurrenc\\u0079":{group: j}, steps: [{run: echo hi}]}}\n',
     f"cannot parse the trigger section (line 5: {ESCAPED_KEY}"),
    # round 11 (own probe): a quote-colon-quote inside a plain env value must not hide the job concurrency.
    ("r11 plain env value holding quote-colon-quote, job-level true",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n" + CANCEL_JOB
     + '    env:\n      K: a":"x\n    concurrency:\n      group: j\n      cancel-in-progress: true\n'
     + '    steps:\n      - run: echo "hi"\n', "cancel-in-progress `true`"),
    ("r11 plain env value holding single-quote-colon-quote, job-level true",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n" + CANCEL_JOB
     + "    env:\n      K: a':'x\n    concurrency:\n      group: j\n      cancel-in-progress: true\n"
     + "    steps:\n      - run: echo 'hi'\n", "cancel-in-progress `true`"),
    # round 11, REVIEW-8332-security-r10 INFO-1: a plain cancel value continued below is one folded string.
    ("r11 cancel value continued on the next line",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n    x\n" + CANCEL_JOB,
     f"line 8: {MULTILINE_CANCEL}"),
    # controls: a JSON-like key without escapes in a flow env is read; block "k":v is refused (not YAML).
    ("r11 JSON-adjacent quoted key without escapes in a flow env",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n" + CANCEL_JOB
     + '    env: {"K":x, \'L\':"y"}\n' + CANCEL_STEPS, None),
    ("r11 block quoted key flush against a plain value in a job env",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n" + CANCEL_JOB
     + '    env:\n      "a":b\n' + CANCEL_STEPS, f"cannot parse the trigger section (line 12: {ADJACENT_KEY}"),
    # round 12, REVIEW-8332-code-r11 F1 (probes g2, g2c) and REVIEW-8332-security-r11 S-r11-1 (probes f1, f1b,
    # verbatim): in a flow collection blanks may sit between a closing quote and its colon; the escaped key is refused.
    ("r12 g2 flow jobs, escaped job concurrency keys, blank before the colon, true",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n"
     'jobs: {j: {runs-on: ubuntu-latest, "concurrenc\\u0079" :{group: j, "cancel\\u002din-progress" :true},'
     " steps: [{run: echo hi}]}}\n", f"cannot parse the trigger section (line 8: {ESCAPED_KEY}"),
    ("r12 g2c flow form f-own1g, escaped concurrency without the key, blank before the colon",
     "name: c\non:\n  pull_request:\n    types: [opened]\n"
     'jobs: {j: {runs-on: ubuntu-latest, "concurrenc\\u0079" :{group: j}, steps: [{run: echo hi}]}}\n',
     f"cannot parse the trigger section (line 5: {ESCAPED_KEY}"),
    ("r12 f1 flow job under block jobs, escaped keys, a space before the colon, true",
     CANCEL_HEAD + 'jobs:\n  j: {runs-on: ubuntu-latest, "concurr\\u0065ncy" :{group: g,'
     ' "cancel-in-pro\\u0067ress" :true}, steps: [{run: echo hi}]}\n',
     f"cannot parse the trigger section (line 6: {ESCAPED_KEY}"),
    ("r12 f1b flow job under block jobs, escaped keys, a tab before the colon, true",
     CANCEL_HEAD + 'jobs:\n  j: {runs-on: ubuntu-latest, "concurr\\u0065ncy"\t:{group: g,'
     ' "cancel-in-pro\\u0067ress"\t:true}, steps: [{run: echo hi}]}\n',
     f"cannot parse the trigger section (line 6: {ESCAPED_KEY}"),
    # control: a quoted flow key without escapes, a blank before its colon, is read as a key and passes.
    ("r12 quoted flow key without escapes, a blank before the colon (control)",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n" + CANCEL_JOB
     + '    env: {"plain-key" : value, "K" :x}\n' + CANCEL_STEPS, None),
    # REVIEW-8332-code-r11 INFO-1: a plain flow scalar holding a colon flush against a quote (a:"b) is one scalar in
    # YAML; neither its colon nor an earlier closed quote on the line makes it a separator, so no quote opens there.
    ("r12 plain flow scalar holding colon-quote before job-level true",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n" + CANCEL_JOB
     + '    env: {A:"x, B: y}\n    concurrency:\n      group: j\n      cancel-in-progress: true\n' + CANCEL_STEPS,
     "cancel-in-progress `true`"),
    ("r12 closed quoted key then a plain flow scalar holding colon-quote before job-level true",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n" + CANCEL_JOB
     + '    env: {"A": x:"y, B: z}\n    concurrency:\n      group: j\n      cancel-in-progress: true\n'
     + CANCEL_STEPS, "cancel-in-progress `true`"),
    # S-r11-2: the flush-comment header rows above, and a plain scalar holding `|#` (control, not a header).
    *((f"r12 {name}", text, f"cannot parse the trigger section (line 9: {FLUSH_COMMENT_HEADER}")
      for name, text in FLUSH_HEADER_ROWS),
    # Round 13 (S-r12-2 / F2, then S-r12-1 / F1): the mutant-killing rows, and every candidate token on the line is
    # tested, not only the first.
    *((f"r13 {name}", text, f"cannot parse the trigger section (line 9: {FLUSH_COMMENT_HEADER}")
      for name, text in FLUSH_HEADER_ROWS_R13),
    *((f"r13 {name}", text, f"cannot parse the trigger section (line {line}: {FLUSH_COMMENT_HEADER}")
      for name, text, line in FLUSH_HEADER_AFTER_KEY_ROWS),
    ("r12 plain step value holding a pipe and a hash (control)",
     CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n" + CANCEL_JOB
     + "    steps:\n      - run: echo |#c\n      - run: a|#b\n", None),
)
# Rows refused by design although YAML reads them as compliant (fail closed; no workflow writes them):
# the PyYAML differential pins that they are over-refusals, not misreadings.
OVER_REFUSALS = {"r10 cancel value on the next line, false", "r10 concurrency key under a step with:",
                 "r10 concurrency key under a job env:"}
# YAML allows a tab before a comment; PyYAML 6 rejects it, so the differential pins that rejection instead. A
# block "k":v is not YAML at all (round 11): the differential pins that PyYAML rejects what the scanner refuses.
PYYAML_REJECTS = {"r10 tab before a trailing comment on a false value",
                  "r11 block quoted key flush against a plain value in a job env",
                  "r12 f1b flow job under block jobs, escaped keys, a tab before the colon, true",
                  *(f"r12 {name}" for name, _ in FLUSH_HEADER_ROWS),
                  *(f"r13 {name}" for name, _ in FLUSH_HEADER_ROWS_R13),
                  *(f"r13 {name}" for name, _, _ in FLUSH_HEADER_AFTER_KEY_ROWS)}
# Round 10 (REVIEW-8332-security-r9 S20): KEY_LINE_RE on a hostile line must finish well inside this many
# seconds (the round-9 prefix took about 1.8 s at 22 repetitions; the linear one takes microseconds).
REGEX_CEILING_S = 0.5
# Round 11 (REVIEW-8332-security-r10 S21, REVIEW-8332-code-r10 F2): the round-10 block scalar header regex, kept
# ONLY as the differential oracle of ``_block_header`` on short generated strings (it is quadratic in the line
# length, so the scanner no longer runs it), and the hostile line length every line pattern is timed at.
BLOCK_SCALAR_ORACLE_RE = re.compile(r"(?:^[ \t]*|:[ \t]+|(?:^|[ \t])-[ \t]+)(?:[&!][^ \t]*[ \t]+)*[|>][1-9+-]*$")
HOSTILE_LEN = 50_000
# Round 13 (REVIEW-8332-security-r12 S-r12-1, the helper cases its fix check ran, verbatim): a scanned line and
# whether ``_flush_comment_header`` reads a block scalar header with a flush comment on it. The last case is the
# lane's own: a later candidate inside the comment, so a helper that keeps only the last candidate's answer fails.
FLUSH_HELPER_CASES = (("- run: |2#c d", True), ("run: echo |#c", False), ("run: a|#b", False),
                      ("k: &a !t |#c", True), ("x &a |#c", False), ("a |#x: |#c", True), ("k >#: |2-#c", True),
                      ("|#c", True), ("run:\t|#c", True), ("run: |0#c", False), ("a: b |#c", False),
                      ("run: |#c |#x", True))
BLOCK_ALPHABET, BLOCK_CORPUS_MAX_LEN = " \t:-&!a|>10+", 5


def _rep(unit: str) -> str:
    """``unit`` repeated to at least HOSTILE_LEN characters."""
    return unit * (HOSTILE_LEN // len(unit) + 1)


def _hostile_lines() -> list:
    """Lines built so a backtracking pattern would retry at every position (rounds 10 and 11 shapes first)."""
    return [": " + _rep("!a: ") + "x", _rep(":\t&"), "-" + _rep("\t -") + "x", _rep("- ") + "k: v", _rep("!a ") + "|",
            _rep('"'), _rep("'"), _rep("a") + ":", " " * HOSTILE_LEN + "x", _rep(":"), "${{" + _rep(" ") + "}",
            _rep("&a "), _rep("cancel-in-progress"), _rep("pull_request "), _rep("{[,"), _rep('a"'), _rep("<<"),
            _rep("types edited "), _rep(" |") + "#", _rep(" |#"), _rep("a |#x: ")]


def _line_checks() -> list:
    """(name, callable) for every pattern searched or matched per line or per file, and the block header walk."""
    key_re, item_re = _trigger_line_res(2)
    checks = [("ON_KEY_RE", ON_KEY_RE.match), ("TOP_KEY_RE", TOP_KEY_RE.match), ("PR_WORD_RE", PR_WORD_RE.search),
              ("EXPLICIT_KEY_RE", EXPLICIT_KEY_RE.match), ("KEY_LINE_RE", KEY_LINE_RE.match),
              ("TYPES_WORD_RE", TYPES_WORD_RE.search), ("ACTIVITY_WORD_RE", ACTIVITY_WORD_RE.findall),
              ("GUARD_EXPR_RE", GUARD_EXPR_RE.fullmatch), ("_trigger_line_res key", key_re.match),
              ("_trigger_line_res item", item_re.match), ("_block_header", _block_header),
              ("_flush_comment_header", _flush_comment_header)]
    checks += [(f"PROPERTY_RES {what}", rx.search) for what, rx in PROPERTY_RES]
    checks += [(f"TOKEN_RES {key}", rx.findall) for key, rx in TOKEN_RES.items()]
    return checks + [(f"KIND_RES {kind}", rx.search) for kind, rx in KIND_RES.items()]


def _scan_or_refusal(name: str, text: str) -> list:
    """``scan`` as a (name, text) call for the timing table: [] or the refusal."""
    try:
        scan(text)
    except ParseFailure as exc:
        return [f"{name}: {exc}"]
    return []


def oracle_verdict(name: str, text: str) -> str:
    """The scanner's reading of one oracle shape: EDITED, CLEAN or REFUSE (by name)."""
    out = edited_listed(name, text)
    if not out:
        return CLEAN
    return REFUSE if "cannot parse" in out[0] and name in out[0] else EDITED


def yaml_verdict(yaml_mod, text: str) -> str:
    """PyYAML's reading: a pull_request(_target) trigger with a types key and the word edited in it."""
    data = yaml_mod.safe_load(text)
    on = data.get("on", data.get(True)) if isinstance(data, dict) else None
    for kind in KINDS:
        body = on.get(kind) if isinstance(on, dict) else None
        if isinstance(body, dict) and "types" in body:
            stack, words = [body], set()
            while stack:
                item = stack.pop()
                if isinstance(item, dict):
                    stack.extend(list(item.keys()) + list(item.values()))
                elif isinstance(item, list):
                    stack.extend(item)
                elif isinstance(item, str):
                    words |= set(re.findall(r"[a-z_]+", item.lower()))
            if "edited" in words:
                return EDITED
    return CLEAN


class EditedRatchetOracle8332(unittest.TestCase):
    """Rounds 6 and 7 (REVIEW-8332-security-r5 S9/S10, REVIEW-8332-code-r5 F1, REVIEW-8332-code-r6 F1-F3,
    REVIEW-8332-security-r6 S12/S13): the oracle table, its message checks and the PyYAML differential."""

    def test_oracle_table(self):
        for name, text, want, *message in ORACLE:
            with self.subTest(name):
                fname = re.sub(r"\W+", "-", name) + ".yml"
                self.assertEqual(oracle_verdict(fname, text), want, text)
                if message:
                    self.assertIn(message[0], edited_listed(fname, text)[0], text)
                if want == REFUSE:
                    self.assertEqual(len(cancel_violations(fname, text)), 1, text)
                    self.assertEqual(len(target_extras({fname: text})), 1, text)
                elif want == EDITED:
                    self.assertGreaterEqual(len(cancel_violations(fname, text + CANCEL_TRUE)), 1, text)

    def test_mutation_apostrophe_and_column0_continuation(self):
        for kind in KINDS:
            text = APOSTROPHE_COL0.replace("KIND", kind)
            self.assertEqual(oracle_verdict("apos.yml", text), EDITED, text)
            self.assertEqual(len(cancel_violations("apos.yml", text + CANCEL_TRUE)), 1, text)
        tgt = APOSTROPHE_COL0.replace("KIND", "pull_request_target")
        self.assertEqual(len(target_extras({"apos.yml": tgt})), 1)
        out = edited_listed("col0.yml", "on:\n  pull_request:\n    types: [opened]\ntypes: [edited]\n")
        self.assertEqual(len(out), 1)
        self.assertIn("col0.yml", out[0])
        self.assertIn("not a top-level key", out[0])

    def test_mutation_quoted_space_hash(self):
        for q in ('"', "'"):
            for text in (f"on:\n  pull_request: {{paths: [{q}docs #x{q}], types: [edited]}}\n",
                         f"on: {{pull_request: {{paths: [{q}docs #x{q}], types: [\n  edited]}}}}\n",
                         f"on: {{pull_request: {{paths: [{q}docs #x{q}], types: [edited]}}}}\n"):
                self.assertEqual(oracle_verdict("hash.yml", text), EDITED, text)
            ok = f"on:\n  pull_request: {{paths: [{q}docs #x{q}], types: [opened]}}\n"
            self.assertEqual(oracle_verdict("hash.yml", ok), CLEAN, ok)
            self.assertTrue(has_trigger(ok, "pull_request"))

    def test_cancel_oracle(self):
        """Round 9 (REVIEW-8332-security-r8 S17): cancel-in-progress is bound to its concurrency block."""
        for name, text, message in CANCEL_ORACLE:
            with self.subTest(name):
                if message is None or "cannot parse the trigger section" not in message:
                    self.assertIn("edited", pr_types(text), text)
                out = cancel_violations("claude-md-rule-compare.yml", text)
                if message is None:
                    self.assertEqual(out, [], text)
                else:
                    self.assertEqual(len(out), 1, text)
                    self.assertIn(message, out[0], text)

    def test_key_line_regex_is_linear(self):
        """Round 10 (REVIEW-8332-security-r9 S20, REVIEW-8332-code-r9 F1, CodeQL py/redos): KEY_LINE_RE and
        the concurrency reader finish a line of repeated dashes and blanks inside REGEX_CEILING_S."""
        lines = ["-" + "\t -" * 22 + "x", "-" + "\t -" * 20 + "x", "-" + "  -" * 2000 + "x", "- " * 2000 + "k: v"]
        for line in lines:
            t0 = time.perf_counter()
            m = KEY_LINE_RE.match(line)
            took = time.perf_counter() - t0
            self.assertLess(took, REGEX_CEILING_S, f"{len(line)} chars took {took:.3f}s")
            self.assertEqual(m is not None, line.endswith("k: v"), line[:40])
        text = CANCEL_HEAD + CANCEL_JOB + "    steps:\n      " + "-" + "\t -" * 22 + "x\n"
        t0 = time.perf_counter()
        self.assertEqual(cancel_violations("claude-md-rule-compare.yml", text), [])
        self.assertLess(time.perf_counter() - t0, REGEX_CEILING_S)

    def test_every_line_pattern_is_linear(self):
        """Round 11 sweep (REVIEW-8332-security-r10 S21, REVIEW-8332-code-r10 F2): every pattern this guard runs per
        line or per file, and the block header walk, finish each hostile line of at least HOSTILE_LEN characters
        inside REGEX_CEILING_S; so do scan, cancel_violations and edited_listed on a workflow carrying it."""
        lines = _hostile_lines()
        for name, check in _line_checks():
            for line in lines:
                t0 = time.perf_counter()
                check(line)
                took = time.perf_counter() - t0
                self.assertLess(took, REGEX_CEILING_S, f"{name}: {line[:12]!r} x{len(line)} took {took:.3f}s")
        head = CANCEL_HEAD + "concurrency:\n  group: g\n  cancel-in-progress: false\n" + CANCEL_JOB
        for line in lines:
            for where in ("    steps:\n      - run: ", "    env:\n      A: "):
                text = head + where + line + "\n"
                for name, call in (("scan", _scan_or_refusal), ("cancel_violations", cancel_violations),
                                   ("edited_listed", edited_listed)):
                    t0 = time.perf_counter()
                    call("claude-md-rule-compare.yml", text)
                    took = time.perf_counter() - t0
                    self.assertLess(took, REGEX_CEILING_S, f"{name}: {where.split()[0]} {line[:12]!r} took {took:.3f}s")

    def test_block_header_matches_the_round10_regex(self):
        """Round 11: the walk agrees with the round-10 regex on every string over BLOCK_ALPHABET up to
        BLOCK_CORPUS_MAX_LEN characters and on every raw and scanned line of every table row and real workflow."""
        samples = ["".join(chars) for size in range(BLOCK_CORPUS_MAX_LEN + 1)
                   for chars in itertools.product(BLOCK_ALPHABET, repeat=size)]
        for text in [t for _, t, *_ in ORACLE] + [t for _, t, _ in CANCEL_ORACLE] + list(_all().values()):
            samples += text.splitlines()
            try:
                samples += [ln.text for ln in scan(text)]
            except ParseFailure:
                continue  # a row the scanner refuses still contributes its raw lines above
        self.assertEqual([s for s in samples if bool(BLOCK_SCALAR_ORACLE_RE.search(s)) != _block_header(s)], [])
        self.assertGreater(len(samples), len(BLOCK_ALPHABET) ** BLOCK_CORPUS_MAX_LEN)

    def test_flush_comment_header_cases(self):
        """Round 13 (REVIEW-8332-security-r12 S-r12-1, REVIEW-8332-code-r12 F1): every candidate token on a line is
        tested where a value can start (after a key colon, a dash or an anchor / tag), not only the first."""
        for text, want in FLUSH_HELPER_CASES:
            with self.subTest(text):
                self.assertEqual(_flush_comment_header(text), want)

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML not importable on this interpreter")
    def test_cancel_oracle_matches_pyyaml(self):
        """Every compliant CANCEL_ORACLE row: PyYAML reads each concurrency cancel value as false or a guard,
        and every refused or violating row holds a true or a missing key somewhere (round 9)."""
        import yaml
        for name, text, message in CANCEL_ORACLE:
            with self.subTest(name):
                if name in PYYAML_REJECTS:
                    self.assertRaises(yaml.YAMLError, yaml.safe_load, text)
                    continue
                data = yaml.safe_load(text)
                found = [data.get("concurrency")] + [j.get("concurrency") for j in data["jobs"].values()]
                values = [c.get(CANCEL_KEY) for c in found if isinstance(c, dict)]
                compliant = bool(values) and all(v is False or guard_ok(str(v)) for v in values)
                self.assertEqual(compliant, message is None or name in OVER_REFUSALS, text)

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML not importable on this interpreter")
    def test_oracle_matches_pyyaml(self):
        """Every row and every VARIANTS form of it: the scanner's verdict is PyYAML's reading, or a refusal.

        A refusal is the fail-closed answer whatever YAML reads (an invalid variant included); a CLEAN or
        EDITED verdict needs PyYAML to load the text and agree (round 7, REVIEW-8332-code-r6 F1).
        """
        import yaml
        cases = [(name, text) for name, text, *_ in ORACLE]
        cases += [(f"{name} + {kind}", form(text)) for name, text, *_ in ORACLE for kind, form in VARIANTS]
        read = 0
        for name, text in cases:
            got = oracle_verdict("diff.yml", text)
            if got == REFUSE:
                continue
            with self.subTest(name):
                self.assertEqual(yaml_verdict(yaml, text), got, text)
                read += 1
        self.assertGreaterEqual(read, len(ORACLE))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
