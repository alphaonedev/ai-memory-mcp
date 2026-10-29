#!/usr/bin/env python3
"""Doc-pin for the v1.0.0 GA certification scope statement (#8262): a pinned-unit allowlist.

Design (round 11, 3-agent vote 6def5ab6, choice B; conductor amendment memory db2a250b; rounds 12
and 13 close the listed scanner gaps without changing the design). The end-to-end content encryption
scope is stated once, in the certification scope statement of
docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md. Every unit of the gated files that names
that subject is pinned verbatim in a closed table (the sidecar JSON PINS_REL), checked in both
directions: a gated unit that is not in the table fails (unpinned), and a pin that is not found
exactly once fails (stale or duplicated). There is no over-claim or under-claim wording rule; a
changed sentence about the subject is a changed pin, and the review pair reads the pin diff as a
named review step. This follows the repository precedent for protected content (closed pinned
sets in test_ci_select_gating_8240.py and test_pg_isolated_binary.py, CODE_STYLE.md:466-467).

Units. Each line is NFKC-normalised and passed through the Cyrillic/Greek confusable map once.
Block structure follows CommonMark/GFM: a line is blank only when it holds nothing but U+0020 and
U+0009 (measured on the raw line, so NBSP, U+3000 and form feed never end a paragraph). Outside a
fenced code block (opened as CommonMark opens one: 0-3 spaces, no backtick in a backtick
info string, closed with its block quote), and after any blockquote markers, three heading forms end the current paragraph
and are never part of a unit: an ATX heading line ("#" to "######" plus a space, also right after a
list marker); a setext heading (the paragraph above a line of only "=" or only "-", at the same
blockquote depth, indented under a list item when the paragraph is one; the paragraph lines plus
the underline are the heading); and an HTML heading element <h1> to <h6> opened and closed on one
line. A thematic break ("---", "***" or "___", spaces allowed, not under paragraph text when it is
dashes) ends the paragraph; it is not a heading and does not end a section. A pipe line starts a table only when the next line is a
delimiter row, and each table row is its own unit; a list item starts a new paragraph, except an
ordered item numbered other than 1, which cannot interrupt a paragraph that did not start with a
list item. Inside a paragraph the splitter ends a sentence at ".", "!" or "?" plus up to four
closers (quote, ")", "]", "*", "_", backtick) plus whitespace; it is one bounded regex, linear and
deterministic. A sentence is subject-bearing when it carries a subject token, or a paired stem
while a pair word is in context. The context is the whole paragraph (for a table row: the row and
the table's header row) plus the nearest preceding heading (any of the three forms) at any level. The unit is that sentence
plus one sentence on each side, inside the paragraph; overlapping or touching windows merge. A
paragraph whose subject straddles a sentence boundary is gated whole. Unit text is compared with
whitespace runs collapsed, so a reflow is not a change. Units are cut from the text, so every
surface is covered: markdown prose, table rows, list items, fenced code, reference-link
definitions, footnotes, HTML comments, and in docs/encryption.html text nodes and every attribute.

Headings. A heading line that carries a subject token, or a paired stem with a pair word in the
heading itself, in the nearest preceding heading or implied by the statement subsection, is
pinned verbatim in the separate "headings" table of the sidecar, checked in both directions.

Subject tokens (matched case-insensitively on three views of a sentence: the folded text; the
folded text with tags and markdown emphasis removed; and the rendered view, which removes HTML
comments and tags, unescapes entities and collapses markdown links and images to their text;
every view drops marks and format characters after NFKD): 8278 in any form (#8278, issue 8278,
the URL); 1968 as a word (#1968, issue 1968, the URL); variant A, variant B, variants A and B,
both variants; end-to-end with any separator (any dash class, spaces) and E2E/E2EE; X25519; scope
key, scope-key, per-namespace key; unreadable to relays or peers; payload confidentiality; content
encryption with any separator. Paired stems encrypt, decrypt, seal, envelope, wrap, ciphertext and
plaintext are subjects only with a pair word (federation/federated, peer, relay, replica or sync)
in context. Inside the certification scope statement subsection the pair word is implied; the
subsection runs from HEADING to the named anchor STATEMENT_END (the "---" rule and the "## 2."
heading that follow the statement), which must occur exactly once and after every statement block;
otherwise the subsection fails closed to the end of the file. A thematic break inside the
statement does not end it. The vocabulary tables carry these names and a selftest holds this
paragraph to them.

Characters. Refused anywhere in a gated file, except the measured (path, code point, count)
entries of EXEMPT_CHARS: every Cf, Mn, Me, Zl and Zp character; every Zs character other than
U+0020; every Cc character other than tab and line feed; and every non-ASCII letter left after
normalisation that is not in the measured LETTER_CENSUS. An HTML comment whose folded content
carries a subject token or a paired stem is refused, except the measured COMMENT_EXEMPT entries.
The one-line HTML heading element is the only HTML heading form read (round 14, fail closed): an
"<h1>" to "<h6>" open tag outside fenced code on any other line (split over lines, wrapped in
another element, or followed by more markup) is refused with its file:line.

CHANGELOG.md is gated from the top down to the line that starts with STOP_HEADING (the
## [0.10.0] release heading); only [Unreleased] and [1.0.0] headings may come before it, and none
of them may carry a release date. The released sections below it are frozen history and exempt.

Accepted residual (refinement 7, verbatim): a claim with no subject token outside any pinned unit
passes, and a PR can pin in a bad sentence. Mitigation: the broad vocabulary above, and the review
pair reads the pin diff as a named review step.

Re-pinning: python3 scripts/ci/tests/test_certification_scope_8262.py --emit-pins prints the table
the docs would need; the unittest path only compares and never writes.
"""
import collections
import difflib
import html
import json
import pathlib
import re
import sys
import unicodedata
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
PINS_REL = "scripts/ci/tests/data/certification_scope_8262_pins.json"
CERT_REL = "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
CERT = ROOT / CERT_REL
CHANGELOG_REL = "CHANGELOG.md"
HTML_REL = "docs/encryption.html"
HEADING = "### Certification scope statement for the v1.0.0 GA candidate"
# Round 13: the statement subsection ends at this named anchor, the rule plus the heading that
# follows the statement (U+00A7 section sign, U+2014 em dash), not at the first "---" line.
STATEMENT_END_HEADING = "## 2. §5.4(2) — machine-checked posture (LOCALHOST-VERIFIED)"
STATEMENT_END = "\n---\n\n" + STATEMENT_END_HEADING + "\n"
ANCHOR = "certification-scope-statement-for-the-v100-ga-candidate-8262"
POINTERS = ["docs/federation.md", "SECURITY.md", "docs/SECURITY.md", "README.md"]
SINGLE_SOURCE_FILES = [CERT_REL, "docs/federation.md", "SECURITY.md",
                       "docs/SECURITY.md", "README.md", CHANGELOG_REL,
                       HTML_REL, "docs/compliance/honest-limitations.md",
                       "docs/compliance/nsa-csi-mcp-security-mapping.md",
                       "docs/enterprise-deployment.md", "docs/federation-identity.md",
                       "ROADMAP.md", "docs/production-deployment.md",
                       "docs/reference/ARCHITECTURE_REFERENCE.md"]
# The CHANGELOG gate stops at the first line that starts with this heading (U+2014 em dash).
STOP_HEADING = "## [0.10.0] — 2026-07-12"
GATED_RELEASE_PREFIX = "## [1.0.0]"
# Measured refused characters that are legitimate: {path: {code point: count}}. U+FE0F is the
# emoji presentation selector, U+03BC the NFKC form of the micro sign, U+03A3 a summation sign.
# Round 12 measured zero Zs (other than U+0020), Zl, Zp and Cc (other than tab and line feed)
# characters in every gated file, so no separator entry is needed.
EXEMPT_CHARS = {
    "SECURITY.md": {0xFE0F: 1},
    CHANGELOG_REL: {0xFE0F: 2, 0x03BC: 5},
    "docs/enterprise-deployment.md": {0xFE0F: 4, 0x03A3: 2},
    "docs/federation-identity.md": {0xFE0F: 1},
    "docs/reference/ARCHITECTURE_REFERENCE.md": {0xFE0F: 1},
}
# Measured census of the non-ASCII letters left after normalisation in the whole of each gated
# file (round 12): {path: {code point: count}}. These are the only non-ASCII letters a gated file
# may carry besides EXEMPT_CHARS; every other letter is refused. Look-alikes stay out on purpose:
# U+0131 dotless i, U+0251 Latin alpha and the small capitals U+1D00-U+1D2B are not listed.
LETTER_CENSUS = {
    CHANGELOG_REL: {0x00EF: 1},  # LATIN SMALL LETTER I WITH DIAERESIS
    "ROADMAP.md": {0x00F6: 1},  # LATIN SMALL LETTER O WITH DIAERESIS
}
LETTER_ALLOW = frozenset(cp for counts in LETTER_CENSUS.values() for cp in counts)
LOOKALIKE_LETTERS = (0x0131, 0x0251) + tuple(range(0x1D00, 0x1D2C))
# Measured HTML comments whose content carries the vocabulary and that are legitimate: the
# licence header of docs/encryption.html ("Encryption atlas" carries the stem encrypt).
COMMENT_EXEMPT = {
    HTML_REL: ("<!--\n  Copyright 2026 AlphaOne LLC\n  SPDX-License-Identifier: Apache-2.0\n"
               "  Encryption atlas — at-rest, in-transit, and integrity surface.\n-->",),
}
TRUST_FILES = ["docs/enterprise-deployment.md", "docs/federation-identity.md"]
TRUST_PARA = "> Peers are **authenticated but NOT trusted"
TRUST_SENTENCE = "Peers **ARE trusted for confidentiality**"
BLOB_PREFIX = ("https://github.com/alphaonedev/ai-memory-mcp/blob/release/v1.0.0/docs/"
               "compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md#")
ISSUE_URL = "https://github.com/alphaonedev/ai-memory-mcp/issues/"

B_IN = ("**Claimed for the GA candidate (IN; certification re-issue under "
        "[#6063](" + ISSUE_URL + "6063)):**")
OLD_B_IN = "Certified for the GA candidate"
B_PENDING = ("**In scope for v1.0.0 GA, certification issued on landing "
             "(not certified today):**")
B_UNLANDED = "**Fail-closed controls required for GA that are NOT yet landed at the pinned SHA.**"
B_NOT = "**NOT claimed for v1.0.0"
BLOCK_MARKERS = [B_IN, B_PENDING, B_UNLANDED, B_NOT]

E2E_CANON = (
    "Federation end-to-end content encryption, variants A and B, is in scope "
    "for v1.0.0 GA and is delivered by [#8278](" + ISSUE_URL + "8278). "
    "The certification is issued only when #8278 has landed on "
    "release/v1.0.0 with its tests green."
)
MTLS_ONLY = (
    "Until #8278 lands, the shipped guarantee for federation content is the "
    "mTLS transport only: peers replicate and store plaintext content."
)
MTLS_IN = "Federation transport is mTLS, and outbound peer server-certificate verification is on by default"
TDE_NOT_CLAIMED = ("Postgres-native TDE as a machine-checked control is "
                   "deliberately NOT claimed for v1.0.0")
SUPERSEDED_FACT = "closed with the `deferred-v1.x` label and is superseded by"

# keyword -> issue numbers the item must cite.
IN_ITEMS = {
    "Federation transport is mTLS": (2448, 232),
    "`sync/since` is peer-scoped": (948,),
    "Every shape requires TLS": (),
    "At-rest AEAD envelope encryption": (),
    "rustls is at the audited version": (3821,),
    "Provenance links refuse a cycle-closing edge": (3041,),
    "Encryption in transit": (3824, 3830),
    # Round 14: #2967 closed by PR #8269 (merge ffc54bd50); the item moved here from UNLANDED_ITEMS.
    "Quarantine of unattributed inbound writes": (2967, 8269),
}
UNLANDED_ITEMS = {
    "Cert-to-peer binding enforced": 8260,
    "Refusal of Claimed (header-asserted) identity": 8265,
}
NOT_ITEMS = {
    "Postgres-native TDE": 8284,
    "Curator namespace-scoped mode": 8264,
    "Batman Form 2": 8255,
    "Top-shelf encryption documentation": 3833,
    "Singleton and Team shapes": 3125,
}
# Round 15 (security r13 INFO 2): the state word an item carries; the other state word is refused.
STATE_WORDS = {"rustls is at the audited version": "closed", "Provenance links refuse a cycle-closing edge": "closed",
               "Encryption in transit": "closed", "Quarantine of unattributed inbound writes": "closed",
               "Cert-to-peer binding enforced": "open", "Refusal of Claimed (header-asserted) identity": "open",
               "Postgres-native TDE": "open", "Curator namespace-scoped mode": "open", "Batman Form 2": "open",
               "Top-shelf encryption documentation": "closed"}
# Round 15 (code r11 LOW-1): IN items that moved from UNLANDED_ITEMS; their issues appear only in the IN block.
LANDED_ITEMS = ("Quarantine of unattributed inbound writes",)
STALE_RE = re.compile(r"1968[^.\n]{0,60}\b(?:open|unresolved|still\s+open)\b", re.IGNORECASE)
HISTORY_LINE_RE = re.compile(r"^Last updated:\s*\d{4}-\d{2}-\d{2}\b")
SECURITY_HISTORY_ENTRY = "federation-is-plaintext (#1968 OPEN) posture note added"
POINTER_HEAD = ("Federation content is not end-to-end encrypted today (mTLS transport only); "
                "the end-to-end content encryption status is stated only in the ")
POINTER_RE = re.compile(re.escape(POINTER_HEAD + "[certification scope statement](")
                        + r"[^)\s]*#" + re.escape(ANCHOR) + r"\)\.")
POINTER_SENTENCE_FILES = ["SECURITY.md", "docs/SECURITY.md", "docs/federation.md",
                          CHANGELOG_REL, CERT_REL, HTML_REL,
                          "docs/compliance/honest-limitations.md",
                          "docs/compliance/nsa-csi-mcp-security-mapping.md"]
SECURITY_E2E_SHAPE = (
    "End-to-end content encryption across federation (per-namespace scope keys, a per-record "
    "content key wrapped to each reader with X25519, envelope version 0x05, sealed on the wire, "
    "reader-scoped, with key rotation) is in scope for v1.0.0 GA and is delivered by "
    "[#8278](" + ISSUE_URL + "8278); it is not live today, and its certification is issued only "
    "when #8278 has landed on release/v1.0.0 with its tests green.")
OLD_E2E_LABELS = ("blind-replica", "ciphertext-only", "reduced-capability")
SYNC_SINCE_PINS = [
    "`sync/since` is peer-scoped while the operator bypass `AI_MEMORY_FED_SYNC_TRUST_PEER=1` is unset",
    "so the empty-envelope and private-visibility claim does not hold under it",
    "`src/federation/peer_attestation.rs:390-392`",
    "consumed at `src/handlers/federation_sync_since.rs:289`",
    "The bypass is outside the asi-hard KNOBS set; only the enterprise posture doctor flags it",
    "`docs/compliance/evidence/cert-385da3a05/posture-*.out`",
]

# ---- normalisation and character refusal ----
_CONFUSABLE_PAIRS = (
    (0x0430, "a"), (0x0435, "e"), (0x043E, "o"), (0x0440, "p"), (0x0441, "c"), (0x0445, "x"),
    (0x0443, "y"), (0x0456, "i"), (0x0458, "j"), (0x0501, "d"), (0x0475, "v"), (0x0455, "s"),
    (0x04BB, "h"), (0x051B, "q"), (0x051D, "w"), (0x04CF, "l"),
    (0x0410, "A"), (0x0412, "B"), (0x0415, "E"), (0x041A, "K"), (0x041C, "M"), (0x041D, "H"),
    (0x041E, "O"), (0x0420, "P"), (0x0421, "C"), (0x0422, "T"), (0x0425, "X"), (0x0405, "S"),
    (0x0406, "I"), (0x0408, "J"),
    (0x03BF, "o"), (0x03BD, "v"), (0x03C1, "p"), (0x03C4, "t"), (0x03C5, "u"), (0x03BA, "k"),
    (0x03B9, "i"), (0x03B1, "a"), (0x03B5, "e"),
    (0x0391, "A"), (0x0392, "B"), (0x0395, "E"), (0x0396, "Z"), (0x0397, "H"), (0x0399, "I"),
    (0x039A, "K"), (0x039C, "M"), (0x039D, "N"), (0x039F, "O"), (0x03A1, "P"), (0x03A4, "T"),
    (0x03A5, "Y"), (0x03A7, "X"),
)
_CONFUSABLES = dict(_CONFUSABLE_PAIRS)
_REFUSED_CATEGORIES = ("Cf", "Mn", "Me", "Zl", "Zp")
_ALLOWED_SPACE = " "
_ALLOWED_CONTROLS = ("\t", "\n")


def normalise(text):
    """NFKC plus the confusable map, once."""
    if text.isascii():
        return text
    return unicodedata.normalize("NFKC", text).translate(_CONFUSABLES)


def _refused_raw(ch):
    cat = unicodedata.category(ch)
    return (cat in _REFUSED_CATEGORIES or (cat == "Zs" and ch != _ALLOWED_SPACE)
            or (cat == "Cc" and ch not in _ALLOWED_CONTROLS))


def refused_chars(raw):
    """{code point: count} of the refused characters: separators, controls and Cf/Mn/Me in the raw
    text, and letters outside ASCII and LETTER_ALLOW after normalisation; one pass over the
    distinct characters of each."""
    out = {}
    for ch in set(raw):
        if _refused_raw(ch):
            out[ord(ch)] = raw.count(ch)
    if raw.isascii():
        return out
    norm = normalise(raw)
    for ch in set(norm):
        if ch.isascii() or ord(ch) in out:
            continue
        cat = unicodedata.category(ch)
        if cat in _REFUSED_CATEGORIES or (cat[0] == "L" and ord(ch) not in LETTER_ALLOW):
            out[ord(ch)] = norm.count(ch)
    return out


def letter_census(raw):
    """{code point: count} of the allowed non-ASCII letters after normalisation."""
    norm = normalise(raw)
    return {ord(ch): norm.count(ch) for ch in set(norm) if ord(ch) in LETTER_ALLOW}


# ---- subject vocabulary ----
_SEP = r"[^a-z0-9]{0,4}"
# Every pattern starts with a literal (the boundary checks are look-behinds after it), so each is a
# fast linear scan; the lists are searched one pattern at a time.
_NB = "(?<![a-z0-9]%s)"
# (name, pattern): the name is the docstring's word for the token and must match its own pattern.
SUBJECT_TABLE = [
    ("8278", r"8278"),
    # Round 13: #1968 is closed and superseded by #8278; a present-tense sentence naming it is a
    # claim about the same subject (code verdict r9 LOW-3, security verdict r11 LOW 2).
    ("1968", r"1968" + _NB % "1968" + r"(?![a-z0-9])"),
    ("variant A", r"variant" + _NB % "variant" + r"s?" + _SEP + r"[ab](?![a-z0-9])"),
    ("both variants", r"both" + _SEP + r"variants"),
    ("end-to-end", r"end" + _NB % "end" + _SEP + r"to" + _SEP + r"end(?![a-z0-9])"),
    ("E2E", r"e2e" + _NB % "e2e" + r"e?(?![a-z0-9])"),
    ("X25519", r"x25519"),
    ("scope key", r"scope" + _SEP + r"keys?(?![a-z0-9])"),
    ("per-namespace key", r"per" + _SEP + r"namespace" + _SEP + r"keys?(?![a-z0-9])"),
    ("unreadable to relays", r"unreadable" + _SEP + r"to" + _SEP + r"(?:relay|peer)"),
    ("payload confidentiality", r"payload" + _SEP + r"confidential"),
    # Round 12: "content encryption" is a subject, not a paired stem: a version cell or deferral
    # next to it reads as a #8278 claim with no pair word anywhere (code verdict row c7-N5).
    ("content encryption", r"content" + _SEP + r"encrypt"),
]
STEM_TABLE = [("encrypt", r"encrypt"), ("decrypt", r"decrypt"), ("seal", r"seal"),
              ("envelope", r"envelope"), ("wrap", r"wrap"), ("ciphertext", r"cipher" + _SEP + r"text"),
              ("plaintext", r"plain" + _SEP + r"text")]
PAIR_TABLE = [("federation", r"federat"), ("peer", r"peer"), ("relay", r"relay"),
              ("replica", r"replica"), ("sync", r"sync(?<![a-z]sync)")]
_SUBJECTS = [p for _, p in SUBJECT_TABLE]
_STEMS = [p for _, p in STEM_TABLE]
_PAIRS = [p for _, p in PAIR_TABLE]
SUBJECT_RES = [re.compile(x) for x in _SUBJECTS]
STEM_RES = [re.compile(x) for x in _STEMS]
PAIR_RES = [re.compile(x) for x in _PAIRS]


def _any(patterns, views):
    return any(rx.search(v) for v in views for rx in patterns)


_TAG_RE = re.compile(r"<[^<>]*>")
# CommonMark raw HTML: open and closing tags, declarations. A quoted attribute value is bounded so a
# failed match cannot rescan the rest of the paragraph from every "<".
_OPEN_TAG_RE = re.compile(r"<[a-z][a-z0-9-]*(?:\s+[a-z_:][a-z0-9_.:-]*(?:\s*=\s*(?:[^\s\"'=<>`]+"
                          r"|'[^'\n]{0,512}'|\"[^\"\n]{0,512}\"))?)*\s*/?>", re.IGNORECASE)
_CLOSE_TAG_RE = re.compile(r"</[a-z][a-z0-9-]*\s*>|<![a-z][^<>]*>", re.IGNORECASE)
_LINK_RE = re.compile(r"!?\[([^\[\]\n]*)\]\((?:[^()\n]|\([^()\n]*\))*\)")
_REFLINK_RE = re.compile(r"!?\[([^\[\]\n]*)\]\[[^\[\]\n]*\]")
_MARKUP_RE = re.compile(r"[*_`~\\]")
_SENT_END_RE = re.compile(r"[.!?][\"')\]*_`]{0,4}\s+")
_ITEM_RE = re.compile(r"[ \t]*(?:>[ \t]*)*(?:[-*+]|(\d{1,9})[.)])[ \t]")
_ROW_RE = re.compile(r"[ \t]*(?:>[ \t]*)*\|")
_MARKER_ONLY_RE = re.compile(r"(?:>[ \t]*)*\d{1,9}[.)]")
_ATX_RE = re.compile(r" {0,3}#{1,6}(?:[ \t]|$)")
# Round 13 (CommonMark): blockquote markers, a setext underline, a thematic break, a list marker
# before an ATX heading, and an HTML heading element on one line.
_QUOTE_RE = re.compile(r"(?: {0,3}>[ \t]?)*")
_SETEXT_RE = re.compile(r"( *)(?:=+|-+)[ \t]*$")
_BREAK_RE = re.compile(r" {0,3}([-*_])[ \t]*(?:\1[ \t]*){2,}$")
_LEAD_ITEM_RE = re.compile(r" {0,3}(?:[-*+]|\d{1,9}[.)])[ \t]+")
_HTML_HEADING_RE = re.compile(r"[ \t]*<h([1-6])(?:\s[^<>]*)?>[^\n]*</h\1\s*>[ \t]*$", re.IGNORECASE)
# Round 14: any HTML heading open tag ("<h1>" to "<h6>", then whitespace, ">", "/" or the end of
# the line); outside fenced code it must sit on a line _line_heading() reads as a heading.
_HTML_HEADING_OPEN_RE = re.compile(r"<h[1-6](?:[\s>/]|$)", re.IGNORECASE)
# Round 15: a fence opens only on 0-3 spaces after the blockquote markers; a closing line keeps the
# permissive form (closing early reads more lines as text, so it fails closed).
_FENCE_OPEN_RE = re.compile(r" {0,3}(`{3,}|~{3,})")
_FENCE_RE = re.compile(r"[ \t>]*(`{3,}|~{3,})")
_DELIM_PREFIX_RE = re.compile(r"[ \t]*(?:>[ \t]*)*")
_DELIM_CHARS = frozenset("|-: \t")
_WS_RE = re.compile(r"\s+")
_RELEASE_HEADING_RE = re.compile(r"^## \[\d+\.\d+\.\d+\]")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_COMMENT_OPEN = "<!--"
_COMMENT_CLOSE = "-->"
_EMPTY_COMMENTS = ("<!-->", "<!--->")


class _DropMarks(dict):
    """translate() table that drops every mark (M*) and format (Cf) character; filled lazily."""

    def __missing__(self, code):
        cat = unicodedata.category(chr(code))
        self[code] = None if cat[0] == "M" or cat == "Cf" else code
        return self[code]


_DROP_MARKS = _DropMarks()


def fold(text):
    """Detection view: entities unescaped, NFKD, every mark and format character dropped, lower."""
    text = html.unescape(text) if "&" in text else text
    if not text.isascii():
        text = unicodedata.normalize("NFKD", normalise(text)).translate(_DROP_MARKS)
    return text.lower()


def html_comments(text):
    """(offset, comment text) for every HTML comment; an unterminated one runs to the end.
    A find() loop, linear in the text."""
    out, pos = [], 0
    while True:
        start = text.find(_COMMENT_OPEN, pos)
        if start < 0:
            return out
        short = [c for c in _EMPTY_COMMENTS if text.startswith(c, start)]
        if short:
            end = start + len(short[0])
        else:
            close = text.find(_COMMENT_CLOSE, start + len(_COMMENT_OPEN))
            end = len(text) if close < 0 else close + len(_COMMENT_CLOSE)
        out.append((start, text[start:end]))
        pos = end


def _strip_comments(text):
    if _COMMENT_OPEN not in text:
        return text
    parts, pos = [], 0
    for start, comment in html_comments(text):
        parts.append(text[pos:start])
        pos = start + len(comment)
    parts.append(text[pos:])
    return "".join(parts)


def rendered(text):
    """Rendered view: HTML comments and tags removed, entities unescaped, NFKD folded, markdown
    links and images collapsed to their text, remaining brackets and emphasis removed."""
    if "<" in text:
        text = _CLOSE_TAG_RE.sub("", _OPEN_TAG_RE.sub("", _strip_comments(text)))
    text = fold(text)
    if "[" in text:
        text = _REFLINK_RE.sub(r"\1", _LINK_RE.sub(r"\1", text)).replace("[", "").replace("]", "")
    return _MARKUP_RE.sub("", text)


def _views(text):
    """The folded view, the folded view with tags and emphasis removed, and the rendered view."""
    raw = fold(text)
    return raw, _MARKUP_RE.sub("", _TAG_RE.sub("", raw)), rendered(text)


def _has_subject(views):
    return _any(SUBJECT_RES, views)


def _is_delimiter_row(line):
    """A GFM table delimiter row: only pipes, dashes, colons and blanks, with a pipe and a dash."""
    body = line[_DELIM_PREFIX_RE.match(line).end():]
    return "|" in body and "-" in body and set(body) <= _DELIM_CHARS


def _is_blank(raw_line):
    """CommonMark blank line: nothing but U+0020 and U+0009."""
    return raw_line.strip(" \t") == ""


def _fence_flags(lines):
    """Per line: True when it opens, closes or sits inside a fenced code block (a heading there is
    code, not a heading). Fail closed (round 15, CommonMark): a fence opens only on 0-3 spaces after
    the blockquote markers, never with a backtick in a backtick fence's info string, and a fence
    closes when a line has fewer blockquote markers than its opener. An unclosed fence runs to the end."""
    flags, fence, depth = [], None, 0
    for line in lines:
        m = _FENCE_RE.match(line)
        here, body = _quote_split(line)
        if fence is not None and here < depth:
            fence = None
        if fence is None:
            o = _FENCE_OPEN_RE.match(body)
            if o and not (o.group(1)[0] == "`" and "`" in body[o.end():]):
                fence, depth = o.group(1), here
            flags.append(fence is not None)
            continue
        flags.append(True)
        if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not line[m.end():].strip():
            fence = None
    return flags


def _windows(para, pair_context, row=False):
    """(start, end) spans of the subject-bearing sentence windows of one paragraph. pair_context
    says a pair word is in context outside the paragraph (the statement subsection, the nearest
    preceding heading, or a table's header row)."""
    whole = _views(para)
    paired = pair_context or _any(PAIR_RES, whole)
    if not _has_subject(whole) and not (paired and _any(STEM_RES, whole)):
        return []
    if row:
        return [(0, len(para))]
    spans, start = [], 0
    for m in _SENT_END_RE.finditer(para):
        spans.append((start, m.start() + 1))
        start = m.end()
    if start < len(para):
        spans.append((start, len(para)))
    # An ordered-list marker ("2.") is not a sentence: it joins the sentence after it.
    joined = []
    for a, b in spans:
        if joined and _MARKER_ONLY_RE.fullmatch(para[joined[-1][0]:joined[-1][1]].strip()):
            joined[-1] = (joined[-1][0], b)
        else:
            joined.append((a, b))
    spans = joined
    if len(spans) == 1:
        return [(0, len(para))]
    hits = []
    for i, (a, b) in enumerate(spans):
        views = _views(para[a:b])
        if _has_subject(views) or (paired and _any(STEM_RES, views)):
            hits.append(i)
    if not hits:
        # The subject or the stem straddles a sentence boundary: gate the paragraph whole.
        return [(0, len(para))]
    out = []
    for i in hits:
        lo, hi = max(0, i - 1), min(len(spans) - 1, i + 1)
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = hi
        else:
            out.append([lo, hi])
    return [(spans[a][0], spans[b][1]) for a, b in out]


def _heading_gated(line, pair_context):
    views = _views(line)
    return _has_subject(views) or (_any(STEM_RES, views) and (pair_context or _any(PAIR_RES, views)))


def _quote_split(line):
    """(blockquote depth, the rest of the line after the blockquote markers)."""
    prefix = _QUOTE_RE.match(line).group(0)
    return prefix.count(">"), line[len(prefix):]


def _line_heading(body):
    """True when a line (after its blockquote markers) is an ATX heading, an ATX heading right after
    a list marker, or an HTML heading element opened and closed on the line."""
    if _ATX_RE.match(body) or _HTML_HEADING_RE.match(body):
        return True
    item = _LEAD_ITEM_RE.match(body)
    return bool(item) and bool(_ATX_RE.match(body[item.end():]) or _HTML_HEADING_RE.match(body[item.end():]))


def html_heading_misuse(text):
    """1-based line numbers of the lines outside fenced code that open an HTML heading element
    ("<h1>" to "<h6>") but are not the one-line heading form _line_heading() reads (round 14: a
    split, wrapped or trailed element is refused rather than read without heading context)."""
    lines = [normalise(x) for x in text.split("\n")]
    fenced = _fence_flags(lines)
    return [n + 1 for n, line in enumerate(lines)
            if not fenced[n] and _HTML_HEADING_OPEN_RE.search(line)
            and not _line_heading(_quote_split(line)[1])]


def _setext_under(cur, line, prev_fenced):
    """True when line is a setext underline for the open paragraph cur: same blockquote depth as
    the paragraph's last line, which holds text, and indented under the list item when the paragraph
    starts with one (otherwise a lazy line, never an underline)."""
    depth, body = _quote_split(line)
    m = _SETEXT_RE.match(body)
    if not cur or prev_fenced or not m:
        return False
    last_depth, last_body = _quote_split(cur[1][-1])
    if depth != last_depth or not last_body.strip(" \t"):
        return False
    indent = len(m.group(1))
    if cur[2]:
        first_body = _quote_split(cur[1][0])[1]
        item = _ITEM_RE.match(first_body)
        need = item.end() if item else 0
        return need <= indent <= need + 3
    return indent <= 3


def _scan(raw, implied=False, first_line=1):
    """Cut raw text into blocks. Returns (paragraphs, headings): paragraphs are
    (first index, normalised lines, pair context, is row); headings are (first index, normalised
    heading text, pair context, last index). implied is True (every line is in the statement
    subsection), False, or an inclusive (first, last) line-index range."""
    raw_lines = raw.split("\n")
    lines = [normalise(x) for x in raw_lines]
    if any("\n" in x for x in lines):
        raise AssertionError("normalisation produced a line break")
    if implied is True:
        lo, hi = 0, len(lines) - 1
    elif implied:
        lo, hi = implied
    else:
        lo, hi = -1, -2
    paras, heads = [], []
    fenced = _fence_flags(lines)
    cur = []  # [first index, lines, starts with a list item, implied]
    state = {"head_pair": False, "header_pair": None}

    def flush():
        if cur:
            paras.append((cur[0], cur[1], cur[3] or state["head_pair"], False))
            del cur[:]

    def heading(first, text, context, last):
        heads.append((first, text, context, last))
        state["head_pair"] = _any(PAIR_RES, _views(text))
        state["header_pair"] = None

    for i, line in enumerate(lines):
        imp = lo <= i <= hi
        if cur and cur[3] != imp:
            flush()
            state["header_pair"] = None
        if _is_blank(raw_lines[i]):
            flush()
            state["header_pair"] = None
            continue
        if not fenced[i]:
            if _setext_under(cur, line, fenced[i - 1] if i else False):
                # The open paragraph is a setext heading: its lines plus this underline.
                first, text, context = cur[0], "\n".join(cur[1] + [line]), cur[3] or state["head_pair"]
                del cur[:]
                heading(first, text, context, i)
                continue
            body = _quote_split(line)[1]
            if _BREAK_RE.match(body):
                # A thematic break ends the paragraph; it is not a heading and ends no section.
                flush()
                state["header_pair"] = None
                continue
            if _line_heading(body):
                flush()
                heading(i, line, imp or state["head_pair"], i)
                continue
        context = imp or state["head_pair"]
        if state["header_pair"] is not None:
            if _ROW_RE.match(line):
                paras.append((i, [line], context or state["header_pair"], True))
                continue
            state["header_pair"] = None
        if (_ROW_RE.match(line) and i + 1 < len(lines) and not _is_blank(raw_lines[i + 1])
                and _is_delimiter_row(lines[i + 1])):
            flush()
            state["header_pair"] = _any(PAIR_RES, _views(line))
            paras.append((i, [line], context, True))
            continue
        item = _ITEM_RE.match(line)
        # An empty item never interrupts a paragraph; an ordered one only when it is numbered 1,
        # unless the paragraph is itself a list item (then it is the next item).
        if (cur and item and line[item.end():].strip(" \t")
                and (cur[2] or item.group(1) is None or item.group(1).lstrip("0") == "1")):
            flush()
        if not cur:
            cur.extend([i, [], bool(item), imp])
        cur[1].append(line)
    flush()
    return paras, heads


def _units(paras, first_line):
    out = []
    for index, plines, context, row in paras:
        para = "\n".join(plines)
        first, pos = first_line + index, 0
        for a, b in _windows(para, context, row):
            first += para.count("\n", pos, a)
            last = first + para.count("\n", a, b)
            out.append((first, last, _WS_RE.sub(" ", para[a:b]).strip()))
            first, pos = last, b
    return out


def gated_units(text, implied_pair=False, first_line=1):
    """(first line, last line, collapsed normalised text) for every gated unit of the text."""
    return _units(_scan(text, implied_pair, first_line)[0], first_line)


def gated_headings(text, implied_pair=False, first_line=1):
    """(line, collapsed normalised heading) for every heading that must be pinned."""
    return [(first_line + i, _WS_RE.sub(" ", line).strip())
            for i, line, context, _ in _scan(text, implied_pair, first_line)[1] if _heading_gated(line, context)]


def _stop_offset(raw):
    """Offset of the first line that starts with STOP_HEADING, or -1."""
    pos = 0
    while True:
        at = raw.find(STOP_HEADING, pos)
        if at < 0:
            return -1
        tail = raw[at + len(STOP_HEADING):at + len(STOP_HEADING) + 1]
        if (at == 0 or raw[at - 1] == "\n") and tail in ("", "\n", " "):
            return at
        pos = at + 1


def scoped_text(rel, raw):
    """The gated part of a file: CHANGELOG.md down to the STOP_HEADING line (all of it if absent)."""
    if rel == CHANGELOG_REL:
        at = _stop_offset(raw)
        return raw[:at] if at >= 0 else raw
    return raw


def _statement_end(text, start):
    """Offset of the named anchor STATEMENT_END that closes the statement starting at start, or -1
    when the anchor is missing, repeated, before the heading, or before a statement block marker
    or the canonical paragraph (the subsection then fails closed to the end of the file)."""
    end = text.find(STATEMENT_END)
    if end < start or text.count(STATEMENT_END) != 1:
        return -1
    tail = text[end:]
    if any(marker in tail for marker in BLOCK_MARKERS) or E2E_CANON in tail:
        return -1
    return end


def _implied_range(rel, text):
    """Inclusive line-index range of the scope statement subsection: HEADING to the line above the
    named anchor STATEMENT_END, or to the end of the file when the anchor fails (fail closed)."""
    if rel != CERT_REL:
        return False
    a = text.find(HEADING)
    if a < 0:
        return False
    b = _statement_end(text, a)
    return text.count("\n", 0, a), text.count("\n", 0, b if b >= 0 else len(text))


def file_units(rel, raw):
    """Units of one gated file; inside the scope statement subsection the pair word is implied."""
    text = scoped_text(rel, raw)
    return gated_units(text, _implied_range(rel, text))


def file_headings(rel, raw):
    text = scoped_text(rel, raw)
    return gated_headings(text, _implied_range(rel, text))


def current_units(root=ROOT):
    return {rel: file_units(rel, (root / rel).read_text(encoding="utf-8")) for rel in SINGLE_SOURCE_FILES}


def current_headings(root=ROOT):
    return {rel: file_headings(rel, (root / rel).read_text(encoding="utf-8")) for rel in SINGLE_SOURCE_FILES}


def load_pins(root=ROOT):
    data = json.loads((root / PINS_REL).read_text(encoding="utf-8"))
    return [(p["file"], p["text"]) for p in data["pins"]]


def load_heading_pins(root=ROOT):
    data = json.loads((root / PINS_REL).read_text(encoding="utf-8"))
    return [(p["file"], p["text"]) for p in data["headings"]]


def emit_pins(units, headings):
    rows = [json.dumps({"file": rel, "text": u[2]}, ensure_ascii=True)
            for rel in SINGLE_SOURCE_FILES for u in units[rel]]
    heads = [json.dumps({"file": rel, "text": h[1]}, ensure_ascii=True)
             for rel in SINGLE_SOURCE_FILES for h in headings[rel]]
    lines = ['{"issue": 8262, "vote": "6def5ab6", "pins": [', ",\n".join(rows),
             '], "headings": [', ",\n".join(heads), "]}"]
    return "\n".join(lines) + "\n"


def _closest_diff(text, candidates):
    head = text[:4000]
    best = max(candidates, key=lambda c: difflib.SequenceMatcher(None, head, c[:4000]).quick_ratio(),
               default="")
    return "\n".join(difflib.unified_diff(best[:4000].split(". "), head.split(". "), "closest pin",
                                          "unit", lineterm=""))


# ---- structural helpers ----
def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _subsection():
    text = CERT.read_text(encoding="utf-8")
    start = text.find(HEADING)
    if start < 0:
        raise AssertionError("scope statement heading missing: " + HEADING)
    end = _statement_end(text, start)
    if end < 0:
        raise AssertionError("the statement anchor must follow the statement exactly once: " + STATEMENT_END_HEADING)
    return text[start:end]


def _blocks():
    """Return {marker: body text after the marker line} in statement order."""
    sec = _subsection()
    positions = []
    for marker in BLOCK_MARKERS:
        if sec.count(marker) != 1:
            raise AssertionError("block marker must appear exactly once: " + marker)
        positions.append(sec.index(marker))
    if positions != sorted(positions):
        raise AssertionError("scope statement blocks are out of order")
    out = {}
    for i, marker in enumerate(BLOCK_MARKERS):
        stop = positions[i + 1] if i + 1 < len(positions) else len(sec)
        body = sec[positions[i]:stop]
        out[marker] = body.split("\n", 1)[1] if "\n" in body else ""
    return out


def _items(body):
    items, cur = [], None
    for ln in body.splitlines():
        if ln.startswith("- "):
            cur = [ln]
            items.append(cur)
        elif cur is not None and ln.startswith("  "):
            cur.append(ln)
    return [" ".join(part.strip() for part in i) for i in items]


def _flat(text):
    return _WS_RE.sub(" ", text)


def _html_text(page):
    """Plain text of an HTML page: links become markdown links, block ends become blank lines."""
    page = re.sub(r"(?is)<(script|style)\b.*?</\1>", "", page)
    page = re.sub(r'(?is)<a\s[^>]*href="([^"]*)"[^>]*>(.*?)</a>', r"[\2](\1)", page)
    page = re.sub(r"(?i)</(?:p|div|li|h\d|tr|section|pre)>", "\n\n", page)
    return html.unescape(re.sub(r"<[^>]+>", "", page))


def _changelog_entry(text):
    """The CHANGELOG entry this issue owns (stale-claim scan only): the '### Docs (#8262' part."""
    start = text.find("### Docs (#8262")
    if start < 0:
        raise AssertionError("CHANGELOG #8262 entry missing")
    nxt = re.search(r"^### ", text[start + 5:], re.MULTILINE)
    return text[start:start + 5 + nxt.start()] if nxt else text[start:]


def _check_items(case, body, expected):
    items = _items(body)
    case.assertEqual(len(items), len(expected), "item count drifted: %d" % len(items))
    for key, nums in expected.items():
        hit = [i for i in items if key in i]
        case.assertEqual(len(hit), 1, "item missing or duplicated: " + key)
        for num in (nums if isinstance(nums, tuple) else (nums,)):
            case.assertRegex(hit[0], r"#%d\b" % num, key + " lost #%d" % num)
        if key in STATE_WORDS:
            word = STATE_WORDS[key]
            case.assertRegex(hit[0], r"\b%s\b" % word, key + " lost its state word: " + word)
            case.assertNotRegex(hit[0], r"\b%s\b" % ("open" if word == "closed" else "closed"), key + " states both")
    return items


class CertificationScope8262(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.units = current_units()
        cls.pins = load_pins()
        cls.headings = current_headings()
        cls.heading_pins = load_heading_pins()

    # ---- the allowlist, both directions ----
    def test_pin_table_is_well_formed(self):
        self.assertEqual(len(self.pins), len(set(self.pins)), "the pin table repeats a pin")
        for rel, _ in self.pins:
            self.assertIn(rel, SINGLE_SOURCE_FILES, "pin for an ungated file: " + rel)

    def test_every_gated_unit_is_pinned(self):
        pinned = set(self.pins)
        bad = []
        for rel, units in self.units.items():
            for first, last, text in units:
                if (rel, text) not in pinned:
                    same = [t for r, t in self.pins if r == rel]
                    bad.append("%s:%d-%d unpinned unit:\n%s\n%s" % (rel, first, last, text[:600],
                                                                    _closest_diff(text, same)))
        self.assertEqual(bad, [], "\n\n".join(bad[:5]))

    def test_every_pin_is_present_exactly_once(self):
        seen = collections.Counter((rel, u[2]) for rel, units in self.units.items() for u in units)
        bad = ["%s pin found %d times (want 1): %s" % (rel, seen[(rel, text)], text[:300])
               for rel, text in self.pins if seen[(rel, text)] != 1]
        self.assertEqual(bad, [], "\n".join(bad[:5]))

    def test_no_unit_holds_a_heading_line(self):
        for rel, units in self.units.items():
            text = scoped_text(rel, _read(rel))
            lines = [normalise(x) for x in text.split("\n")]
            fenced = _fence_flags(lines)
            heads = {n for first, _, _, last in _scan(text, _implied_range(rel, text))[1]
                     for n in range(first + 1, last + 2)}
            bad = ["%s:%d" % (rel, n) for first, last, _ in units for n in range(first, last + 1)
                   if n in heads or (not fenced[n - 1] and _line_heading(_quote_split(lines[n - 1])[1]))]
            self.assertEqual(bad, [], "heading line inside a unit: " + ", ".join(bad[:5]))

    def test_every_gated_heading_is_pinned_exactly_once(self):
        self.assertEqual(len(self.heading_pins), len(set(self.heading_pins)), "the heading table repeats a pin")
        seen = collections.Counter((rel, h[1]) for rel, heads in self.headings.items() for h in heads)
        unpinned = ["%s:%d unpinned heading: %s" % (rel, h[0], h[1]) for rel, heads in self.headings.items()
                    for h in heads if (rel, h[1]) not in set(self.heading_pins)]
        self.assertEqual(unpinned, [], "\n".join(unpinned[:5]))
        stale = ["%s heading pin found %d times (want 1): %s" % (rel, seen[(rel, text)], text)
                 for rel, text in self.heading_pins if seen[(rel, text)] != 1]
        self.assertEqual(stale, [], "\n".join(stale[:5]))

    def test_statement_canonical_paragraph_is_pinned(self):
        hit = [t for r, t in self.pins if r == CERT_REL and E2E_CANON in t]
        self.assertEqual(len(hit), 1, "the canonical paragraph is not in exactly one CERT pin")

    def test_gated_files_refuse_hidden_and_foreign_characters(self):
        for rel in SINGLE_SOURCE_FILES:
            got = refused_chars(_read(rel))
            self.assertEqual(got, EXEMPT_CHARS.get(rel, {}), "%s refused characters: %s" % (
                rel, {"U+%04X" % k: v for k, v in sorted(got.items())}))

    def test_gated_files_letters_match_the_census(self):
        for rel in SINGLE_SOURCE_FILES:
            self.assertEqual(letter_census(_read(rel)), LETTER_CENSUS.get(rel, {}), rel + " letter census drifted")
        self.assertEqual([cp for cp in LOOKALIKE_LETTERS if cp in LETTER_ALLOW], [],
                         "a look-alike letter is in the allowlist")

    def test_gated_files_refuse_comments_with_vocabulary(self):
        for rel in SINGLE_SOURCE_FILES:
            text = scoped_text(rel, _read(rel))
            bad = [comment[:200] for _, comment in html_comments(text)
                   if comment not in COMMENT_EXEMPT.get(rel, ())
                   and (_has_subject(_views(comment)) or _any(STEM_RES, _views(comment)))]
            self.assertEqual(bad, [], rel + " carries an HTML comment with the subject vocabulary")
        for rel, comments in COMMENT_EXEMPT.items():
            text = _read(rel)
            for comment in comments:
                self.assertEqual(text.count(comment), 1, rel + " lost or repeated an exempt comment")

    def test_html_heading_only_in_one_line_form(self):
        bad = ["%s:%d" % (rel, n) for rel in SINGLE_SOURCE_FILES
               for n in html_heading_misuse(scoped_text(rel, _read(rel)))]
        self.assertEqual(bad, [], "an HTML heading element outside the one-line form (open and close tag "
                         "alone on one line) gives no heading context and is refused: " + ", ".join(bad[:10]))
        # Synthetic: the six refused spellings, the accepted one-line forms, and fenced code.
        for text in ("<h2>\nFederation\n</h2>", '<h2\nclass="x">Federation</h2>',
                     "<h2>Federation</h2><!-- x -->", "<h2>Federation</h2><span></span>",
                     "<div><h2>Federation</h2></div>", "Text <H3>Peer</H3> here", "<h6/>"):
            self.assertTrue(html_heading_misuse(text), text)
        for text in ("<h2>Federation</h2>", '  <h3 class="x">Sync</h3>  ', "<H4>Peer</H4>", "- <h2>Notes</h2>",
                     "> <h2>Notes</h2>", "```\n<h2>\nFederation\n</h2>\n```", "~~~\n<div><h2>X</h2></div>\n~~~",
                     "<hr>", "<header>", "<h7>x</h7>", "<html>"):
            self.assertEqual(html_heading_misuse(text), [], text)

    def test_changelog_gate_is_the_current_release_section(self):
        raw = _read(CHANGELOG_REL)
        lines = raw.split("\n")
        stops = [i for i, ln in enumerate(lines) if ln == STOP_HEADING or ln.startswith(STOP_HEADING + " ")]
        self.assertEqual(len(stops), 1, "the CHANGELOG stop heading must appear exactly once")
        scoped = scoped_text(CHANGELOG_REL, raw)
        self.assertEqual(scoped.count("\n"), stops[0], "the gate must end right above the stop heading")
        before = lines[:stops[0]]
        self.assertIn("## [Unreleased]", before)
        self.assertIn("### Docs (#8262", scoped)
        released = [ln for ln in before if _RELEASE_HEADING_RE.match(ln)]
        bad = [ln for ln in released if not ln.startswith(GATED_RELEASE_PREFIX) or _DATE_RE.search(ln)]
        self.assertEqual(bad, [], "a released-version heading sits inside the gated CHANGELOG section")
        self.assertTrue(released, "the [1.0.0] heading is missing from the gated section")

    def test_round12_block_rules_on_synthetic_text(self):
        def texts(raw, implied=False):
            return [u[2] for u in gated_units(raw, implied)]
        # Headings end the paragraph and never sit in a unit; a subject heading is a heading pin.
        self.assertEqual(texts("Intro about X25519.\n## Next\nMore."), ["Intro about X25519."])
        self.assertEqual(gated_headings("## X25519 keys\nIt is fine."), [(1, "## X25519 keys")])
        self.assertEqual(gated_headings("```\n# X25519 note\n```"), [])
        # Pair context: the paragraph, the table header row, the nearest preceding heading.
        self.assertEqual(texts("| Federation feature | Version |\n|---|---|\n| Content encryption | v1.1 |"),
                         ["| Content encryption | v1.1 |"])
        self.assertEqual(texts("Peers replicate over mTLS. This is the transport today. "
                               "Content encryption is deferred to v1.1."),
                         ["This is the transport today. Content encryption is deferred to v1.1."])
        self.assertEqual(texts("## Federation roadmap\n\nContent encryption is deferred to v1.1."),
                         ["Content encryption is deferred to v1.1."])
        self.assertEqual(texts("Federation is mTLS. It moved to v1.1. That was the release decision. "
                               "Content encryption now ships later."),
                         ["That was the release decision. Content encryption now ships later."])
        self.assertEqual(texts("- Federation is mTLS today.\n| Content encryption | v1.1 |"),
                         ["- Federation is mTLS today. | Content encryption | v1.1 |"])
        self.assertEqual(texts("## Notes\n\nContent encryption is deferred to v1.1."),
                         ["Content encryption is deferred to v1.1."])
        self.assertEqual(texts("## OSS commitment\n\n| Content encryption | v1.1 |"), ["| Content encryption | v1.1 |"])
        self.assertEqual(texts("## Notes\n\nThe envelope is deferred to v1.1."), [])
        # Paragraph ends: only U+0020/U+0009 lines are blank; lazy pipe and ordered lines continue.
        para = "Keys are X25519 pairs."
        for sep in (" ", "　", "\x0c"):
            got = texts(para + "\n" + sep + "\nIt is deferred to v1.1.")
            self.assertEqual(len(got), 1, repr(sep))
            self.assertTrue(got[0].startswith(para) and got[0].endswith("It is deferred to v1.1."), repr(sep))
            self.assertIn(ord(sep), refused_chars(para + sep))
        self.assertEqual(texts(para + "\n| It is deferred to v1.1."), [para + " | It is deferred to v1.1."])
        self.assertEqual(texts(para + "\n2. It is deferred to v1.1."), [para + " 2. It is deferred to v1.1."])
        self.assertEqual(texts(para + "\n1. It is deferred to v1.1."), [para])
        self.assertEqual(texts(para + "\n \t\nIt is deferred to v1.1."), [para])
        stmt = HEADING + "\n\nContent encryption is pending.\n| That condition was waived.\n\n---\n"
        self.assertEqual([u[2] for u in file_units(CERT_REL, stmt)],
                         ["Content encryption is pending. | That condition was waived."])
        stmt = HEADING + "\n\nContent encryption is pending.\n \nThat condition was waived.\n\n---\n"
        self.assertEqual(len(file_units(CERT_REL, stmt)), 1)
        self.assertIn("waived", file_units(CERT_REL, stmt)[0][2])

    def test_round12_character_and_markup_rules_on_synthetic_text(self):
        for word, cp in (("Varıants A and B", 0x0131), ("Vɑriant B", 0x0251),
                         ("Variant ᴀ", 0x1D00), ("variant ʙ", 0x0299)):
            self.assertIn(cp, refused_chars(word), word)
        for cp in (0x2028, 0x2029, 0x00A0, 0x3000, 0x2007, 0x000C, 0x000D, 0x000B):
            self.assertIn(cp, refused_chars("x" + chr(cp) + "y"), "U+%04X" % cp)
        self.assertEqual(refused_chars("a b\tc\nd"), {})
        for text in ("#82[78](#scope) is deferred to v1.1.", "[End](#scope)-to-end content protection is late.",
                     "#82<!-- > -->78 is deferred to v1.1.", "#82<b title=\">\"></b>78 is deferred to v1.1.",
                     "![X2](a.png)5519 keys are late.", "#82[78][ref] is deferred."):
            self.assertTrue(gated_units(text), text)
        self.assertEqual([u[2] for u in gated_units("See [#8278](https://example.org/8278) for variants.")],
                         ["See [#8278](https://example.org/8278) for variants."])
        self.assertEqual(gated_units("A [plain link](https://example.org/x) only."), [])
        self.assertEqual([c for _, c in html_comments("a <!-- x --> b <!--> c <!-- open")],
                         ["<!-- x -->", "<!-->", "<!-- open"])

    def test_unit_rules_on_synthetic_text(self):
        para = "One. Two. #8278 is here. Four. Five."
        self.assertEqual([u[2] for u in gated_units(para)], ["Two. #8278 is here. Four."])
        self.assertEqual(gated_units("| a | Variant-B | x |\n|---|---|---|\n| b | c |"), [(1, 1, "| a | Variant-B | x |")])
        self.assertEqual(len(gated_units("- end to end\n- other item")), 1)
        self.assertEqual(gated_units("Content encryption is on."), [(1, 1, "Content encryption is on.")])
        self.assertEqual(gated_units("The envelope is on."), [])
        self.assertEqual(gated_units("The envelope is on.", True, 7), [(7, 7, "The envelope is on.")])
        stmt = file_units(CERT_REL, HEADING + "\n\nOnce again, content encryption is enabled.\n" + STATEMENT_END
                          + "\nThe envelope is on.\n")
        self.assertEqual(stmt, [(3, 3, "Once again, content encryption is enabled.")])
        self.assertEqual(len(gated_units("Rows are sealed. Peers read them.")), 1)
        for text in ('<p title="#8278 is live.">x</p>', "<!-- #8278 -->", "#82​78 x",
                     "8<b>27</b>8 x", "[e2e]: https://example.org/x", "Issue &#56;278 x",
                     "End—to—end x", "Variants A and B x", "X25519 x",
                     "unreadable to relays", "payload confidentiality", "per-namespace key"):
            self.assertTrue(gated_units(normalise(text)), text)

    def test_round13_heading_forms_on_synthetic_text(self):
        def texts(raw, implied=False):
            return [u[2] for u in gated_units(raw, implied)]
        tail = "\n\nThe envelope ships in v1.1."
        # Setext headings carry the pair word to the next paragraph, like an ATX heading.
        for under in ("------------------", "==================", "---", "=", "  ---"):
            self.assertEqual(texts("Federation roadmap\n" + under + tail), ["The envelope ships in v1.1."], under)
        self.assertEqual(gated_headings("X25519 keys\n---\nIt is fine."), [(1, "X25519 keys ---")])
        self.assertEqual(gated_headings("Two line\nX25519 heading\n==="), [(1, "Two line X25519 heading ===")])
        self.assertEqual(texts("> Federation roadmap\n> ---\n> The envelope ships in v1.1."),
                         ["> The envelope ships in v1.1."])
        self.assertEqual(texts("- Federation roadmap\n  ---" + tail), ["The envelope ships in v1.1."])
        # HTML heading elements and list-item ATX headings are headings too.
        for head in ("<h2>Federation</h2>", "<h3 id=\"x\">Federation</h3>", "  <H4>Peer sync</H4>  ",
                     "- ## Federation", "> ## Federation"):
            self.assertEqual(texts(head + tail), ["The envelope ships in v1.1."], head)
        self.assertEqual(gated_headings("<h2>Variant B</h2>"), [(1, "<h2>Variant B</h2>")])
        self.assertEqual(texts("Peers sync.\n<h2>Notes</h2>\nThe envelope ships in v1.1."), [])
        # A thematic break ends a paragraph but is not a heading and keeps the heading context.
        for rule in ("***", "___", "- - -", " * * *", "---"):
            self.assertEqual(texts("## Federation\n\nIntro.\n\n" + rule + tail), ["The envelope ships in v1.1."], rule)
            self.assertEqual(texts("## Notes\n\n" + rule + "\n\nPeers are trusted." + tail), [], rule)
        self.assertEqual(texts("Keys are X25519 pairs.\n***\nIt is deferred."), ["Keys are X25519 pairs."])
        # Not underlines: a lazy line under a list item, an underline at another blockquote depth,
        # a fenced line, an empty blockquote line, four spaces.
        self.assertEqual(texts("- Federation roadmap\n===" + tail), [])
        self.assertEqual(texts("> Federation roadmap\n---" + tail), [])
        self.assertEqual(texts(">\n---" + tail), [])
        self.assertEqual(texts("```\nFederation\n```\n---" + tail), [])
        self.assertEqual(texts("Federation roadmap\n    ---" + tail), [])
        self.assertEqual(gated_headings("```\nX25519 keys\n---\n```"), [])

    def test_fence_opener_follows_commonmark_8262(self):
        # Round 15 (code r11 MEDIUM-1): a line CommonMark does not open a fence with is not a fence (an
        # indented line, a backtick in a backtick info string, a fence its block quote has closed), so
        # the heading after it is read and the claim under it is checked.
        claim = "The envelope ships in v1.1."

        def texts(raw):
            return [u[2] for u in gated_units(raw)]
        for fake in ("    ```", "> ```\n> x", "``` a`b", "\t```"):
            self.assertEqual(texts("## Notes\n\n" + fake + "\n\n## Federation\n\n" + claim), [claim], fake)
        self.assertEqual(html_heading_misuse("## Notes\n\n    ```\n\n<h2>\nFederation\n</h2>\n\n" + claim), [5])
        # Real fences stay code: up to three spaces, a tilde fence with a backtick in its info string,
        # a fence inside a block quote, and a quoted fence closed by its own closing line.
        for real in ("```\n## Federation\n\n" + claim + "\n```", "   ~~~ a`b\n## Federation\n\n" + claim + "\n~~~",
                     "> ```\n> ## Federation\n> ```\n\n" + claim, "```html\n<h2>\nFederation\n</h2>\n```",
                     "> ```\n> <h2>\n> Federation\n> </h2>\n> ```"):
            self.assertEqual(texts("## Notes\n\n" + real), [], real)
            self.assertEqual(html_heading_misuse(real), [], real)
        self.assertEqual(texts("## Notes\n\n> ```\n> x\n> ```\n\n## Federation\n\n" + claim), [claim])

    def test_statement_ends_at_the_named_anchor(self):
        text = CERT.read_text(encoding="utf-8")
        self.assertEqual(text.count(STATEMENT_END), 1, "the statement anchor must appear exactly once")
        self.assertEqual(text.count(STATEMENT_END_HEADING), 1, "the anchor heading must appear exactly once")
        start, end = text.find(HEADING), text.find(STATEMENT_END)
        self.assertLess(start, end, "the anchor heading moved above the statement")
        for marker in BLOCK_MARKERS + [E2E_CANON]:
            self.assertLess(text.find(marker), end, "a statement block sits below the anchor")
        self.assertEqual(_statement_end(text, start), end)
        lo, hi = _implied_range(CERT_REL, text)
        self.assertEqual(text.split("\n")[hi + 1:hi + 4], ["---", "", STATEMENT_END_HEADING])
        # A thematic break inside the statement does not end it; text past the anchor is not implied.
        body = HEADING + "\n\nIntro.\n\n---\n\nThe envelope ships in v1.1.\n" + STATEMENT_END + "\nThe wrap is late.\n"
        self.assertEqual([u[2] for u in file_units(CERT_REL, body)], ["The envelope ships in v1.1."])
        # Missing, repeated or moved anchor: fail closed to the end of the file.
        for broken in (body.replace(STATEMENT_END, "\n---\n\n## 2. Posture\n"),
                       body + STATEMENT_END, STATEMENT_END + body.replace(STATEMENT_END, "\n")):
            self.assertIn("The wrap is late.", [u[2] for u in file_units(CERT_REL, broken)])
        moved = HEADING + "\n" + STATEMENT_END + "\n" + B_NOT + "\n\nThe wrap is late.\n"
        self.assertEqual(_statement_end(moved, 0), -1)
        self.assertEqual(_implied_range(CERT_REL, moved)[1], moved.count("\n"))

    def test_issue_1968_is_a_subject(self):
        for text in ("Federation privacy stays tracked in #1968.", "#1968 remains open as the carrier.",
                     "Issue 1968 is the carrier.", "See https://example.org/issues/1968 today."):
            self.assertTrue(gated_units(text), text)
        for text in ("Built in 19680 steps.", "Port 11968 is used.", "Version 1968b ships."):
            self.assertEqual(gated_units(text), [], text)

    def test_docstring_lists_every_vocabulary_token(self):
        doc = _WS_RE.sub(" ", __doc__).lower()
        def section(first, last):
            start = doc.index(first)
            return doc[start:doc.index(last, start)]
        subjects = section("subject tokens (", "paired stems ")
        stems = section("paired stems ", " are subjects only with a pair word")
        pairs = section("with a pair word (", " in context.")
        for table, section in ((SUBJECT_TABLE, subjects), (STEM_TABLE, stems), (PAIR_TABLE, pairs)):
            for name, pattern in table:
                self.assertIn(name.lower(), section, "the docstring vocabulary omits " + name)
                self.assertIsNotNone(re.search(pattern, fold(name)), name + " does not match its own pattern")
        for name, _ in SUBJECT_TABLE:
            self.assertNotIn(name.lower(), stems + pairs, name + " is a subject but the docstring pairs it")
        self.assertEqual([len(SUBJECT_TABLE), len(STEM_TABLE), len(PAIR_TABLE)],
                         [len(SUBJECT_RES), len(STEM_RES), len(PAIR_RES)])

    # ---- structure of the statement and its pointers ----
    def test_heading_present_and_blocks_in_order(self):
        self.assertIn(HEADING, CERT.read_text(encoding="utf-8"))
        self.assertEqual(len(_blocks()), len(BLOCK_MARKERS))

    def test_in_block_items(self):
        body = _blocks()[B_IN]
        _check_items(self, body, IN_ITEMS)
        self.assertIn(MTLS_IN, _flat(body))

    def test_e2e_canonical_paragraph_in_pending_block(self):
        body = _flat(_blocks()[B_PENDING])
        self.assertEqual(body.count(E2E_CANON), 1)
        self.assertIn(MTLS_ONLY, body)
        self.assertIn(SUPERSEDED_FACT, body)
        self.assertIn("#1968", body)

    def test_unlanded_block_items(self):
        body = _blocks()[B_UNLANDED]
        _check_items(self, body, UNLANDED_ITEMS)
        self.assertIn("open", body)

    def test_open_gaps_only_in_unlanded_block(self):
        blocks = _blocks()
        for marker in (B_IN, B_PENDING, B_NOT):
            for num in UNLANDED_ITEMS.values():
                self.assertNotRegex(blocks[marker], r"#%d\b" % num,
                                    "open gap #%d sits outside the not-yet-landed block" % num)

    def test_landed_items_only_in_claimed_block(self):
        blocks = _blocks()
        for marker in (B_PENDING, B_UNLANDED, B_NOT):
            for num in (n for key in LANDED_ITEMS for n in IN_ITEMS[key]):
                self.assertNotRegex(blocks[marker], r"#%d\b" % num,
                                    "landed item #%d sits outside the claimed block" % num)
        for key in LANDED_ITEMS:
            hit = [i for i in _items(blocks[B_IN]) if key in i]
            self.assertEqual(len(hit), 1, "landed item missing or duplicated: " + key)
            self.assertNotRegex(hit[0], r"(?i)permissive\s+today", key + " says the default is permissive today")

    def test_not_claimed_block_items(self):
        body = _blocks()[B_NOT]
        items = _check_items(self, body, NOT_ITEMS)
        self.assertIn(TDE_NOT_CLAIMED, _flat(body))
        self.assertTrue(any("deferred-v1.x" in i for i in items))

    def test_pointers_present(self):
        for rel in POINTERS:
            self.assertIn(ANCHOR, _read(rel), rel + " lost the pointer")

    def test_readme_pointer_follows_current_release_paragraph(self):
        paras = [p for p in re.split(r"\n\s*\n", _read("README.md")) if p.strip()]
        idx = [i for i, p in enumerate(paras) if ANCHOR in p]
        self.assertEqual(len(idx), 1)
        # U+2014 em dash, written as an escape: the README heading uses it.
        self.assertTrue(paras[idx[0] - 1].startswith("**v1.0.0 — current release.**"))

    def test_pointer_sentence_quoted_in_every_pointer_file(self):
        for rel in POINTER_SENTENCE_FILES:
            text = _read(rel)
            if rel == HTML_REL:
                text = _html_text(text)
            elif rel == CERT_REL:
                text = text.replace(_subsection(), "")
            self.assertIsNotNone(POINTER_RE.search(_flat(text)), rel + " lost the verbatim pointer sentence")

    def test_trust_boundary_sentence_is_pinned(self):
        for rel in TRUST_FILES:
            paras = [p for p in re.split(r"\n\s*\n", _read(rel)) if TRUST_PARA in p]
            self.assertEqual(len(paras), 1, rel + " lost the trust-boundary paragraph")
            self.assertEqual(paras[0].count(TRUST_SENTENCE), 1,
                             rel + " lost the peers-are-trusted-for-confidentiality sentence")

    def test_html_pointer_links_use_the_blob_url(self):
        text = _read(HTML_REL)
        hrefs = re.findall(r'href="([^"]*#' + re.escape(ANCHOR) + r')"', text)
        self.assertEqual(len(hrefs), 2)
        self.assertEqual(re.findall(r'href="(?!https?://)[^"]*\.md', text), [],
                         "docs/encryption.html carries a relative .md link")
        for href in hrefs:
            self.assertTrue(href.startswith(BLOB_PREFIX), "relative or wrong statement link: " + href)

    def test_security_md_e2e_bullet_states_8278_shape_and_condition(self):
        flat = _flat(_read("SECURITY.md"))
        self.assertEqual(flat.count(SECURITY_E2E_SHAPE), 1)
        for label in OLD_E2E_LABELS:
            self.assertNotIn(label, flat.lower(), "SECURITY.md carries the #1968 design label")
        self.assertIn("**Federation is NOT end-to-end encrypted", _read("SECURITY.md"))

    def test_security_md_keeps_dated_history_entry(self):
        lines = _read("SECURITY.md").splitlines()
        self.assertTrue(any(HISTORY_LINE_RE.match(ln) and SECURITY_HISTORY_ENTRY in ln for ln in lines),
                        "the dated 2026-08-16 history entry lost '(#1968 OPEN)'")

    def test_stale_claim_is_caught_outside_history(self):
        for rel in SINGLE_SOURCE_FILES:
            text = _read(rel)
            if rel == CERT_REL:
                text = text.replace(_subsection(), "")
            elif rel == CHANGELOG_REL:
                text = _changelog_entry(text)
            text = "\n".join(ln for ln in text.splitlines() if not HISTORY_LINE_RE.match(ln))
            self.assertIsNone(STALE_RE.search(text), rel + " carries a stale '#1968 open' claim")
        self.assertIsNotNone(STALE_RE.search("End-to-end encryption (#1968) is open today."))

    def test_in_heading_does_not_say_certified_and_cites_reissue(self):
        text = CERT.read_text(encoding="utf-8")
        self.assertNotIn(OLD_B_IN, text, "IN heading says Certified while the status is EXPIRED")
        self.assertEqual(text.count(B_IN), 1)
        self.assertIn("EXPIRED", text[:4000])

    def test_sync_since_item_names_the_operator_bypass(self):
        items = _items(_blocks()[B_IN])
        hit = [i for i in items if "`sync/since` is peer-scoped" in i]
        self.assertEqual(len(hit), 1)
        flat = _flat(hit[0])
        for pin in SYNC_SINCE_PINS:
            self.assertIn(pin, flat, "sync/since item lost: " + pin)
        self.assertLess(flat.index("AI_MEMORY_FED_SYNC_TRUST_PEER=1"), flat.index("empty envelope"),
                        "the bypass condition must precede the empty-envelope claim")


if __name__ == "__main__":
    if sys.argv[1:] == ["--emit-pins"]:
        sys.stdout.write(emit_pins(current_units(), current_headings()))
        sys.exit(0)
    unittest.main()
