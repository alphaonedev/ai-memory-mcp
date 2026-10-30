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

Guard grammar (markdown subset). Round 18, decision B: the hand lexer below cannot converge on
CommonMark, and a mis-parse there fails open, so every gated markdown file must first parse in this
documented subset (grammar_problems(), block_text_problems()); anything outside it is refused as
"unsupported markdown construct: <construct> at <file>:<line>". docs/encryption.html is read as
HTML and is not in the subset. The rules:
  1. A refusal names the construct and its file:line; there is no partial reading of a refused line.
  2. Headings are live only as ATX headings at column 0 outside every container. A heading-like line
     (up to three spaces then "#") that is indented, in a block quote, in a list item or in an HTML
     block is refused, and in the certification file also inside a fence. A setext underline (a
     line of only "=" or "-" directly under text) is refused; a "---" rule needs a blank line above.
  3. Containers sit at top level only. A fence opens and closes at column 0 (closer: the same
     character, at least as long, nothing after it). Four refusals are enforced: an HTML block or
     indented code inside a block quote; a fence-like line inside a fence; a backtick in a fence
     info string; front matter below the top of the file. An indented, quoted or in-item fence
     opener and an unclosed fence are refused too. A block quote is one level at column 0 and may
     not carry a fence, a heading-like line, a list item, an HTML block or indented code; lazy
     continuation is refused. An HTML block line is refused except a one-line "<!-- ... -->" comment
     (exactly one comment per line, nothing before the opener or after the closer, no "--" inside,
     no nested "<!--"; "--->" is refused except as the close of the empty comment "<!---->", which
     is accepted; "<!-- -- -->" is refused) and the measured README.md lines of HTML_BLOCK_ALLOW,
     each followed only by a blank line or another allowed line. YAML front matter is read only at
     the top of a file.
  4. The IN, PENDING, UNLANDED and NOT statement blocks hold only list items ("-", "*", "+" or an
     ordered marker at column 0) and blank lines: one child level (2-4 spaces), continuation lines
     at the item content column, no second paragraph, no other block; every item is digest-pinned.
  5. Blank means empty or ASCII spaces only. Non-ASCII whitespace (U+0085, NBSP, U+1680, U+180E,
     U+2000-U+200B, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF) is refused anywhere, and a tab
     outside a fence, YAML front matter included, is refused.
  6. Mentions of the short trust-peer token in identifier form (trust_peer, trust-peer, any case)
     count wherever they stand, containers ignored: table cells, after a colon, fenced code. A
     markdown escape or emphasis, code or strike markup inside the token does not hide it
     (TRUST\\_PEER, TRUST_**PEER**, TRUST_`PEER`); an underscore between two word characters stays.
The lexer and the unit rules below then read only subset input. The subset is summarised for
maintainers in scripts/ci/tests/data/README.md, next to the pin table.

Units. Each line is NFKC-normalised and passed through the Cyrillic/Greek confusable map once.
Block structure follows CommonMark/GFM: a line is blank only when it holds nothing but U+0020 and
U+0009 (measured on the raw line, so NBSP, U+3000 and form feed never end a paragraph). Code is
read as CommonMark reads it, relative to the container (blockquote depth plus list-item content
column, round 16, _lex()): a fence opens and closes on 0-3 spaces relative to the container (also
right after a list marker), closes only on a same-character run at least as long with nothing after
it, and closes when its container ends; a line 4+ spaces past the container outside a paragraph is
indented code. Fail closed: where this reading and a permissive one (a fence after any spaces, tabs,
blockquote or list markers) disagree, a heading adds its pair word and never clears one, and a
gated file that ends inside an open fence is refused. Outside code, and after the container
prefix, three heading forms end the current paragraph
and are never part of a unit: an ATX heading line ("#" to "######" plus a space, also right after a
list marker); a setext heading (the paragraph above a line of only "=" or only "-", at the same
blockquote depth, indented under a list item when the paragraph is one; the paragraph lines plus
the underline are the heading); and an HTML heading element <h1> to <h6> opened and closed on one
line. A thematic break ("---", "***" or "___", spaces allowed, not under paragraph text when it is
dashes) ends the paragraph; it is not a heading and does not end a section. A pipe line starts a
table only when the next line is a delimiter row, and each table row is its own unit; a list item
starts a new paragraph, except an ordered item numbered other than 1, which cannot interrupt a
paragraph that did not start with a list item. Inside a paragraph the splitter ends a sentence at
".", "!" or "?" plus up to four closers (quote, ")", "]", "*", "_", backtick) plus whitespace; it is
one bounded regex, linear and deterministic. A sentence is subject-bearing when it carries a subject
token, or a paired stem while a pair word is in context. The context is the whole paragraph (for a
table row: the row and the table's header row) plus the nearest preceding heading (any of the three
forms) at any level. The unit is that sentence plus one sentence on each side, inside the paragraph;
overlapping or touching windows merge. A paragraph whose subject straddles a sentence boundary is
gated whole. Unit text is compared with whitespace runs collapsed, so a reflow is not a change.
Units are cut from the text, so every surface is covered: markdown prose, table rows, list items,
fenced code, reference-link definitions, footnotes, HTML comments, and in docs/encryption.html text
nodes and every attribute.

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
"<h1>" to "<h6>" open tag outside code on any other line (split over lines, wrapped in
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
import hashlib
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
# Round 18 (security r16 MEDIUM-1): the PENDING block is one reviewed item, digest-pinned like the others.
PENDING_ITEMS = {"Federation end-to-end content encryption, variants A and B": ()}
UNLANDED_ITEMS = {
    "Cert-to-peer binding enforced": 8260,
    "Refusal of Claimed (header-asserted) identity": 8265,
}
# Round 17 (security r15 MEDIUM-1): the IN and UNLANDED blocks are item lists. The text on and
# below each marker line before the first item is fixed (one entry per line), and every item's
# flattened text is pinned by mention_key() digest, so a two-space continuation cannot add a claim.
BLOCK_LEADS = {
    B_IN: ("",),
    B_PENDING: ("",),
    B_NOT: (" (each is named so the certified claim is unambiguous):**",),
    B_UNLANDED: (" Each is claimed only",
                 "when its issue closes with a landed SHA on the GA candidate. At the pinned SHA the default is the",
                 "permissive one named here, so a reader must not assume the control:"),
}
BLOCK_ITEM_DIGESTS = {
    'Federation transport is mTLS': '7af9d4a0e5ebfcab',
    '`sync/since` is peer-scoped': '5eaba80d5479ca12',
    'Every shape requires TLS': 'f2f1cd1890c59733',
    'At-rest AEAD envelope encryption': 'c6b56fdd1c512bc0',
    'rustls is at the audited version': '2923917ac923eb56',
    'Provenance links refuse a cycle-closing edge': '77db717d70bf2e19',
    'Encryption in transit': 'b4c8bff1f661e05a',
    'Quarantine of unattributed inbound writes': '112a0bacc2dfa45c',
    'Cert-to-peer binding enforced': 'e21ade2059229f64',
    'Refusal of Claimed (header-asserted) identity': 'e190e173786b5f3a',
    # Round 18 (security r16 MEDIUM-1): the PENDING and NOT items are digest-pinned too.
    'Federation end-to-end content encryption, variants A and B': '2d74f6fe90ff2bf0',
    'Postgres-native TDE': 'be7c09b24f64c37c',
    'Curator namespace-scoped mode': '408fc1775a841aca',
    'Batman Form 2': 'fac521e10099a1c6',
    'Top-shelf encryption documentation': 'fd2e106e993f5212',
    'Singleton and Team shapes': 'a8ad0089d42dbdc3',
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
               "Top-shelf encryption documentation": "closed",
               # Round 16 (code r12 INFO-1): every item carries its state; None = cites no issue, no state word.
               "Federation transport is mTLS": "closed", "`sync/since` is peer-scoped": "closed",
               "Every shape requires TLS": None, "At-rest AEAD envelope encryption": None,
               "Singleton and Team shapes": "open"}
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
# Round 16 (R3, security r14): NOT-claimed wording pin of the TDE_NOT_CLAIMED kind; the whole item.
CURATOR_NOT_CLAIMED = (
    "- Curator namespace-scoped mode: the curator daemon is root-equivalent (cross-tenant `for_admin` reads, "
    "`src/curator/reflection_pass.rs:125-127`; [#8264](" + ISSUE_URL + "8264), open, operator milestone decision).")
# Round 16 (R3, security r14): every census unit of a gated file that names the sync trust-peer bypass,
# as (path, mention_key(unit)); round 17: the unit is the paragraph, list item or table row. A new or
# reworded mention (one that endorses setting the bypass, for one) fails until a reviewer reads it and
# the table changes in this source, never in the sidecar.
TRUST_PEER_MENTIONS = [
    (CERT_REL, '5eaba80d5479ca12'),  # - `sync/since` is peer-scoped while the operator
    (CERT_REL, '658752ca4236ef35'),  # The other 10 of 20 are PASS on the bare leg beca
    ('docs/federation.md', '9114c40302e2a16b'),  # | `AI_MEMORY_FED_SYNC_TRUST_PEER` | unset (deny)
    ('docs/federation.md', 'd1c14ba729644f29'),  # Constants: the `*_ENV` consts in [`src/federatio
    ('docs/federation.md', '47076363d44ce9d9'),  # The default posture is **strict**: an inbound wr
    (CHANGELOG_REL, 'ededac0dd5ece961'),  # REFUTED and deliberately not changed: `peer_atte
    (CHANGELOG_REL, 'a3e838fe6f0023a8'),  # - **`ai-memory doctor --posture enterprise-feder
    (CHANGELOG_REL, '929585960b7f29d5'),  # - **sqlite — silently LOSSY (#2491).** The `#193
    (CHANGELOG_REL, 'b1edf98c903951cd'),  # - **Docs / infra:** env-table rows **147** (dele
    (CHANGELOG_REL, 'e8d596cf45dc4483'),  # - **Tests:** `tests/federation_delete_ns_scope_2
    (CHANGELOG_REL, '3219eca3461cf74b'),  # - **Tests:** `tests/federation_pending_ns_scope_
    (CHANGELOG_REL, 'a8dab141ae69592a'),  # - **Tests:** `tests/federation_ns_meta_scope_247
    (CHANGELOG_REL, 'bd39f313d589d398'),  # - **The federated inbound WRITE lane is namespac
    ('docs/enterprise-deployment.md', 'd54f2b0e1a3a798b'),  # - [ ] `AI_MEMORY_FED_TRUST_BODY_AGENT_ID` and `A
    ('docs/federation-identity.md', 'd38d59bf99575bfb'),  # | `AI_MEMORY_FED_SYNC_TRUST_PEER` / `AI_MEMORY_F
    ('docs/reference/ARCHITECTURE_REFERENCE.md', '29a27e586033795a'),  # | 25 | `AI_MEMORY_FED_SYNC_TRUST_PEER` | bool (`
    ('docs/reference/ARCHITECTURE_REFERENCE.md', 'bdb3764974a9ef48'),  # | 147 | `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SC
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
# The same map as a character class: only the characters it names are rewritten (re.sub touches
# the matches, where str.translate() looks up every character of the text).
_CONFUSABLE_RE = re.compile("[" + "".join(chr(code) for code, _ in _CONFUSABLE_PAIRS) + "]")
_REFUSED_CATEGORIES = ("Cf", "Mn", "Me", "Zl", "Zp")
_ALLOWED_SPACE = " "
_ALLOWED_CONTROLS = ("\t", "\n")


def normalise(text):
    """NFKC plus the confusable map, once."""
    if text.isascii():
        return text
    return _CONFUSABLE_RE.sub(lambda m: _CONFUSABLES[ord(m.group())], unicodedata.normalize("NFKC", text))


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
_QUOTE_MARK_RE = re.compile(r"( {0,3})>[ \t]?")  # round 17: one blockquote marker, the spaces before it
_SETEXT_RE = re.compile(r"( *)(?:=+|-+)[ \t]*$")
_BREAK_RE = re.compile(r" {0,3}([-*_])[ \t]*(?:\1[ \t]*){2,}$")
_LEAD_ITEM_RE = re.compile(r" {0,3}(?:[-*+]|\d{1,9}[.)])[ \t]+")
# Round 16: 0-3 spaces of indent, measured after the container prefix (CommonMark 4.6 HTML blocks).
_HTML_HEADING_RE = re.compile(r" {0,3}<h([1-6])(?:\s[^<>]*)?>[^\n]*</h\1\s*>[ \t]*$", re.IGNORECASE)
# Round 14: any HTML heading open tag ("<h1>" to "<h6>", then whitespace, ">", "/" or the end of
# the line); outside code it must sit on a line _line_heading() reads as a heading.
_HTML_HEADING_OPEN_RE = re.compile(r"<h[1-6](?:[\s>/]|$)", re.IGNORECASE)
# Round 16 (code r12 MEDIUM-1/MEDIUM-2, security r14 MEDIUM-1/LOW-1): _lex() reads fences as
# CommonMark does, relative to the container (blockquote depth plus list-item content column). These
# match on the text after that prefix: a fence run, a closing line (the run plus only whitespace),
# a list marker, and the prefix whose tabs expand to four-column stops.
_FENCE_RUN_RE = re.compile(r"(`{3,}|~{3,})")
_FENCE_CLOSE_RE = re.compile(r"(`{3,}|~{3,})[ \t]*$")
_SPACES_RE = re.compile(r" *")
_MARKER_RE = re.compile(r"(?:[-*+]|(\d{1,9})[.)])(?=[ \t]|$)")
_LEAD_PREFIX_RE = re.compile(r"[ \t>]*(?:(?:[-*+]|\d{1,9}[.)])[ \t]+[ \t>]*)*")
# The permissive second reading the backstop compares with (the round-14 form plus list markers):
# a fence opens after any run of spaces, tabs, blockquote and list markers and closes on the next
# run of the same character, at least as long, with nothing after it.
_ALT_OPEN_RE = re.compile(r"[ \t>]*(?:(?:[-*+]|\d{1,9}[.)])[ \t]+)*(`{3,}|~{3,})")
_ALT_CLOSE_RE = re.compile(r"[ \t>]*(`{3,}|~{3,})[ \t]*$")
_DELIM_PREFIX_RE = re.compile(r"[ \t]*(?:>[ \t]*)*")
_DELIM_CHARS = frozenset("|-: \t")
_WS_RE = re.compile(r"\s+")
# Round 16 (R3): the sync trust-peer bypass in any spelling the folded views read. Round 17 (code
# r13 LOW-1, security r15 LOW-1): also the short name, a standalone trust-peer token set to a truthy
# value by an assignment or "to". Round 18 (code r14 LOW-1): the short name in identifier form
# (trust_peer, trust-peer, any case) anywhere, whatever follows it: a table cell, a colon, "set to",
# "Enable", fenced code. Prose ("trust peer-supplied", "TRUST_PEER_LIMIT") is not the token.
TRUST_PEER_RE = re.compile(r"sync[^a-z0-9]{0,4}trust[^a-z0-9]{0,4}peer"
                           r"|(?<![a-z0-9])trust[_-]peer(?![a-z0-9_-])"
                           r"|(?<![a-z0-9])trust[^a-z0-9]{0,4}peer(?![a-z0-9])[^a-z0-9]{0,4}"
                           r"(?:=|to(?![a-z0-9]))[^a-z0-9]{0,4}(?:1|true|on|yes)(?![a-z0-9])")
# Round 17: a census unit starts at a table row or a list item; a table row is a unit of its own.
_TABLE_ROW_RE = re.compile(r"[ \t>]*\|")
_LIST_ITEM_RE = re.compile(r"[ \t>]*(?:[-*+]|\d{1,9}[.)])(?:[ \t]|$)")
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
# Every mark and format character is non-ASCII, so only non-ASCII characters are looked up.
_NON_ASCII_RE = re.compile(r"[^\x00-\x7f]")


def _drop_mark(m):
    return "" if _DROP_MARKS[ord(m.group())] is None else m.group()


def fold(text):
    """Detection view: entities unescaped, NFKD, every mark and format character dropped, lower."""
    text = html.unescape(text) if "&" in text else text
    if not text.isascii():
        text = _NON_ASCII_RE.sub(_drop_mark, unicodedata.normalize("NFKD", normalise(text)))
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


def _expand_lead(line):
    """The line with every tab in its prefix (spaces, tabs, blockquote and list markers) expanded to
    the next four-column stop (CommonMark 2.2); the rest of the line is unchanged."""
    if "\t" not in line:
        return line
    end = _LEAD_PREFIX_RE.match(line).end()
    out, col = [], 0
    for ch in line[:end]:
        pad = 4 - col % 4 if ch == "\t" else 1
        out.append(" " * pad if ch == "\t" else ch)
        col += pad
    return "".join(out) + line[end:]


def _block_start(text):
    """True when text (a line after its indent, at 0-3 spaces) would start a block rather than
    continue a paragraph lazily: a heading, fence, quote, list item, thematic break or HTML tag."""
    return (text[:1] in ("#", "`", "~", ">", "<") or bool(_MARKER_RE.match(text))
            or bool(_BREAK_RE.match(text)))


def _lex(lines):
    """CommonMark reading of code blocks (round 16, sections 4.4, 4.5, 5.1 and 5.2). Returns
    (code, bodies, unclosed, indented_code): code[i] is True when line i opens, closes or sits
    inside a fenced code block, or is an indented code line; bodies[i] is the line after its
    blockquote markers and its list-item content column (what _line_heading() reads); unclosed
    holds the 0-based opening line of a fence still open at the end of the text; indented_code is
    the set of 0-based indented code lines.

    The container is the blockquote depth plus the content column of the innermost open list item
    at that depth. A fence opens on 0-3 spaces relative to the container, also right after a list
    marker ("- ```"), never with a backtick in a backtick fence's info string. It closes on a line
    at the same depth, 0-3 spaces relative to the container, of the same character, at least as
    long, with only whitespace after it; a deeper-quoted or 4+-indented line is content. It also
    closes when its container ends: a line with fewer blockquote markers, or a non-blank line
    indented less than the list item's content column. Outside a paragraph a line 4+ spaces past
    the container is indented code. A list item ends at a non-blank line indented less than its
    content column unless the line continues a paragraph lazily. A line with more blockquote
    markers than the fence's depth is fence content only when its first extra marker sits at or
    past the item's content column (round 17)."""
    code, bodies, unclosed, indented_code = [], [], [], set()
    items = []  # (blockquote depth, content column) of each open list item, outermost first
    fence = None  # [character, length, depth, container column, opening line]
    para = False
    for n, raw in enumerate(lines):
        line = _expand_lead(raw)
        depth, rest = _quote_split(line)
        blank = not rest.strip(" \t")
        ind = len(rest) - len(rest.lstrip(" "))
        if fence is not None and depth > fence[2] and fence[3] > 0:
            # Round 17 (code r13 MEDIUM-1): a deeper blockquote marker left of the list item's content
            # column is not item content: the item ends, its fence closes, the line is a new block.
            gap = _quote_gap(line, fence[2])
            if gap is not None and gap < fence[3]:
                items = [it for it in items if it[0] < fence[2] or (it[0] == fence[2] and it[1] <= gap)]
                fence = None
        if fence is not None:
            if depth > fence[2] or (depth == fence[2] and (blank or ind >= fence[3])):
                body = rest[fence[3]:] if depth == fence[2] else rest
                code.append(True)
                bodies.append(body)
                lead = len(body) - len(body.lstrip(" "))
                m = _FENCE_CLOSE_RE.match(body[lead:]) if depth == fence[2] and lead <= 3 else None
                if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= fence[1]:
                    fence = None
                continue
            fence = None  # the container ended: the fence closes and the line is read afresh
        if blank:
            items = [it for it in items if it[0] <= depth]
            code.append(False)
            bodies.append(rest)
            para = False
            continue
        keep = [it for it in items if it[0] < depth or (it[0] == depth and ind >= it[1])]
        if para and len(keep) < len(items) and not _block_start(rest[ind:]):
            code.append(False)  # a lazy paragraph continuation line: the containers stay open
            bodies.append(rest[ind:])
            continue
        popped, items = len(keep) < len(items), keep
        base = items[-1][1] if items and items[-1][0] == depth else 0
        body = rest[base:]
        if ind - base >= 4 and not para:
            code.append(True)  # indented code: no heading, fence or list marker is read here
            bodies.append(body)
            indented_code.add(n)
            continue
        if ind - base >= 4:
            code.append(False)  # 4+ spaces inside a paragraph: continuation text
            bodies.append(body)
            continue
        col, indented = ind, False
        # Round 19 (code r15 INFO-2): one pass per line. A thematic break needs the whole rest of the
        # line to be one marker character and blanks, so it is tried only from break_from on; the text
        # after a marker is measured by position, never sliced.
        edge = rest.rstrip(" \t")[-1:]
        break_from = len(rest.rstrip(" \t" + edge)) if edge in ("-", "*", "_") else len(rest) + 1
        last_text = len(rest.rstrip(" \t"))
        while True:
            m = _MARKER_RE.match(rest, col)
            if not m or (col >= break_from and _BREAK_RE.match(rest, col)):
                break
            bare = m.end() >= last_text
            if (para and not popped and (bare
                                         or (m.group(1) is not None and m.group(1).lstrip("0") != "1"))):
                break  # an empty item, or one numbered other than 1, does not interrupt a paragraph
            gap = _SPACES_RE.match(rest, m.end()).end() - m.end()
            width = 1 if bare or gap > 4 else gap
            items.append((depth, m.end() + width))
            indented, col, para, popped = gap > 4 and not bare, m.end() + width, False, True
            if indented:
                break
        text = rest[col:]
        o = _FENCE_RUN_RE.match(text)
        if indented or (o and not (o.group(1)[0] == "`" and "`" in text[o.end():])):
            if not indented:
                fence = [o.group(1)[0], len(o.group(1)), depth, items[-1][1] if items and items[-1][0] == depth
                         else 0, n]
            code.append(True)
            bodies.append(body)
            para = False
            continue
        code.append(False)
        bodies.append(body)
        para = not (_ATX_RE.match(text) or _BREAK_RE.match(text) or _HTML_HEADING_RE.match(text))
    if fence is not None:
        unclosed.append(fence[4])
    return code, bodies, unclosed, indented_code


def _quote_gap(line, depth):
    """Spaces before the blockquote marker that follows the first depth markers of line (tabs in its
    prefix already expanded); None when the line has no further marker."""
    pos = 0
    for _ in range(depth):
        m = _QUOTE_MARK_RE.match(line, pos)
        if not m:
            return None
        pos = m.end()
    m = _QUOTE_MARK_RE.match(line, pos)
    return len(m.group(1)) if m else None


def _alt_fence_flags(lines):
    """Per line: True inside a fence under the permissive second reading (_ALT_OPEN_RE and
    _ALT_CLOSE_RE, no list or indent rule). The fail-closed backstop in _scan() compares it
    with _lex(): where the two readings disagree, a heading never resets the pair context.
    Round 17 (code r13 MEDIUM-1, mirrored from _lex()): a fence whose opener sits past column 0
    after its blockquote markers closes on a deeper blockquote marker left of that column, and the
    line is read again as a possible opener."""
    flags, fence = [], None  # fence = (run, blockquote depth, opener column after the markers)
    for line in lines:
        if fence is not None and fence[2] > 0:
            wide = _expand_lead(line)
            if _quote_split(wide)[0] > fence[1]:
                gap = _quote_gap(wide, fence[1])
                if gap is not None and gap < fence[2]:
                    fence = None
        if fence is None:
            m = _ALT_OPEN_RE.match(line)
            if m:
                depth, lead = _quote_split(_expand_lead(line[:m.start(1)]))
                fence = (m.group(1), depth, len(lead))
            flags.append(fence is not None)
            continue
        flags.append(True)
        m = _ALT_CLOSE_RE.match(line)
        if m and m.group(1)[0] == fence[0][0] and len(m.group(1)) >= len(fence[0]):
            fence = None
    return flags


def _fence_flags(lines):
    """Per line: True when _lex() reads it as code (a fenced code block line or an indented code
    line); a heading there is code, not a heading."""
    return _lex(lines)[0]


def _reading(lines, markdown=True):
    """(code, bodies, unclosed, alt) for a gated file. docs/encryption.html is HTML, not Markdown:
    no line is code, an HTML heading element is read at any indent and no ATX line is a heading."""
    if markdown:
        # The permissive reading models fences only, so an indented code line counts as code in
        # both readings: indented code is never a disagreement (security r14 row rv-d8-atx-indent4-code).
        code, bodies, unclosed, indented_code = _lex(lines)
        alt = [flag or i in indented_code for i, flag in enumerate(_alt_fence_flags(lines))]
        return code, bodies, unclosed, alt
    bodies = [x.lstrip(" \t") if _HTML_HEADING_RE.match(x.lstrip(" \t")) else "" for x in lines]
    return [False] * len(lines), bodies, [], [False] * len(lines)


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


def html_heading_misuse(text, markdown=True):
    """1-based line numbers of the lines outside code (fenced or indented) that open an HTML heading
    element ("<h1>" to "<h6>") but are not the one-line heading form _line_heading() reads (round
    14: a split, wrapped or trailed element is refused rather than read without heading context)."""
    lines = [normalise(x) for x in text.split("\n")]
    code, bodies, _, _ = _reading(lines, markdown)
    return [n + 1 for n, line in enumerate(lines)
            if not code[n] and _HTML_HEADING_OPEN_RE.search(line) and not _line_heading(bodies[n])]


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


def _scan(raw, implied=False, first_line=1, markdown=True):
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
    # Round 16 fail-closed backstop: where _lex() and the permissive reading disagree on whether a
    # line is code, a heading there (read either way) adds its pair word and never clears one.
    fenced, bodies, _, alt = _reading(lines, markdown)
    cur = []  # [first index, lines, starts with a list item, implied]
    state = {"head_pair": False, "header_pair": None}

    def flush():
        if cur:
            paras.append((cur[0], cur[1], cur[3] or state["head_pair"], False))
            del cur[:]

    def heading(first, text, context, last, keep=False):
        heads.append((first, text, context, last))
        state["head_pair"] = _any(PAIR_RES, _views(text)) or (keep and state["head_pair"])
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
        split = fenced[i] != alt[i]
        if fenced[i]:
            if split and _line_heading(bodies[i].lstrip(" ")) and _any(PAIR_RES, _views(line)):
                state["head_pair"] = True
        else:
            if _setext_under(cur, line, fenced[i - 1] if i else False):
                # The open paragraph is a setext heading: its lines plus this underline.
                first, text, context = cur[0], "\n".join(cur[1] + [line]), cur[3] or state["head_pair"]
                del cur[:]
                heading(first, text, context, i, split)
                continue
            body = bodies[i]
            if _BREAK_RE.match(body):
                # A thematic break ends the paragraph; it is not a heading and ends no section.
                flush()
                state["header_pair"] = None
                continue
            if _line_heading(body):
                flush()
                heading(i, line, imp or state["head_pair"], i, split)
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


def gated_units(text, implied_pair=False, first_line=1, markdown=True):
    """(first line, last line, collapsed normalised text) for every gated unit of the text."""
    return _units(_scan(text, implied_pair, first_line, markdown)[0], first_line)


def gated_headings(text, implied_pair=False, first_line=1, markdown=True):
    """(line, collapsed normalised heading) for every heading that must be pinned."""
    return [(first_line + i, _WS_RE.sub(" ", line).strip())
            for i, line, context, _ in _scan(text, implied_pair, first_line, markdown)[1]
            if _heading_gated(line, context)]


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
    """The gated part of a file: CHANGELOG.md down to the STOP_HEADING line (all of it if
    absent)."""
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
    return gated_units(text, _implied_range(rel, text), 1, rel != HTML_REL)


def file_headings(rel, raw):
    text = scoped_text(rel, raw)
    return gated_headings(text, _implied_range(rel, text), 1, rel != HTML_REL)


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
    """Items of a statement block: a column-0 item line plus every indented line below it (a child
    item and its continuations fold into the parent, round 18); column-0 text ends the item."""
    items, cur = [], None
    for ln in body.splitlines():
        if _GB_MARKER_RE.match(ln):
            cur = [ln]
            items.append(cur)
        elif cur is not None and ln.startswith(" "):
            cur.append(ln)
        elif ln.strip(" "):
            cur = None
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


def trust_peer_mentions(root=ROOT):
    """(path, unit) for every census unit of a gated file that names the sync trust-peer bypass, in
    any spelling the folded views read (round 16, R3). Round 17 (code r13 LOW-1, security r15
    LOW-1): the unit is the paragraph, list item or table row holding the match, flattened, so a
    sentence next to a reviewed mention (a conditional endorsement that does not repeat the name)
    is reviewed with it. An HTML page is read as its plain text."""
    return [(rel, unit) for rel in SINGLE_SOURCE_FILES
            for unit in trust_peer_units(rel, (root / rel).read_text(encoding="utf-8"))]


def _census_units(para):
    units = []
    for ln in para.split("\n"):
        row = _TABLE_ROW_RE.match(ln) is not None
        if not units or row or _LIST_ITEM_RE.match(ln) or units[-1][0]:
            units.append((row, [ln]))
        else:
            units[-1][1].append(ln)
    return ["\n".join(lines) for _, lines in units]


def trust_peer_units(rel, raw):
    text = scoped_text(rel, raw)
    if rel == HTML_REL:
        text = _html_text(text)
    out = []
    for para in re.split(r"\n[ \t>]*\n", text):
        for unit in _census_units(para):
            unit = _flat(unit).strip()
            if unit and any(TRUST_PEER_RE.search(v) for v in _mention_views(unit)):
                out.append(unit)
    return out


# Round 21 (code r20 MEDIUM-1, security r20 LOW-1, code r20 LOW-1): the dash that spells the "-" of
# the trust-peer identifier is every code point of Unicode category Pd plus U+2212 MINUS SIGN, derived
# from unicodedata at import time. Only a dash BETWEEN "trust" and "peer" is rewritten, after each
# entity-decoding fold(); a dash after the identifier is left alone so the lookahead of TRUST_PEER_RE
# still sees it. Round 22: the class has 26, 27 and 28 code points on Python 3.9, 3.12 and 3.14
# (the Unicode database moves); no measured row depends on the size.
_DASH_CLASS = "".join(re.escape(chr(c)) for c in range(sys.maxunicode + 1)
                      if c == 0x2212 or unicodedata.category(chr(c)) == "Pd")
_TRUST_DASH_RE = re.compile("(?<=trust)[%s](?=peer)" % _DASH_CLASS)


def _fold_mention(text):
    """fold() followed by the narrow trust-peer dash fold (round 21)."""
    return _TRUST_DASH_RE.sub("-", fold(text))


def _mention_views(text):
    """The views of _mention_views_core(); round 23 (security r22 LOW-1): when the line holds an HTML
    comment opener, also the views of the line with the comment delimiters blanked, so a markdown
    spelling of the identifier inside a one-line comment reads as it does outside one. The union
    never counts fewer than the core views alone."""
    views = _mention_views_core(text)
    if "<!--" in text:
        views += _mention_views_core(text.replace("<!--", " ").replace("-->", " "))
    return views


def _mention_views_core(text):
    """_views() with one fold: the folded view, it without tags and emphasis, and a rendered view
    (comments, tags and link syntax removed after unescaping, folded again if an entity remains).
    A dash between "trust" and "peer" is read as "-" after each fold (round 21) and, round 22, as
    the last step of every returned view, so a dash that only comes to sit between the halves once
    comments, tags, links or emphasis are gone is read the same way."""
    low = _fold_mention(text)
    out = low
    if "<" in out:
        out = _CLOSE_TAG_RE.sub("", _OPEN_TAG_RE.sub("", _strip_comments(out)))
    if "&" in out:
        out = _fold_mention(out)
    if "[" in out:
        out = _REFLINK_RE.sub(r"\1", _LINK_RE.sub(r"\1", out)).replace("[", "").replace("]", "")
    views = (low, _MARKUP_RE.sub("", _TAG_RE.sub("", low)), _MARKUP_RE.sub("", out),
             _keep_underscores(out))
    return tuple(_TRUST_DASH_RE.sub("-", view) for view in views)


_ESCAPE_RE = re.compile(r"\\([!-/:-@\[-`{-~])")
_EMPH_RE = re.compile(r"[*`~]")
_EDGE_US_RE = re.compile(r"(?<![a-z0-9])_+|_+(?![a-z0-9])")


def _keep_underscores(text):
    """Round 19 (security r17 LOW-1): the rendered view with markdown backslash escapes undone and
    the emphasis and code delimiters (*, backtick, ~, and underscores that are not inside a word)
    removed, an underscore between two word characters kept: TRUST\\_PEER, TRUST_**PEER** and
    TRUST_`PEER` read as trust_peer."""
    return _EDGE_US_RE.sub("", _EMPH_RE.sub("", _ESCAPE_RE.sub(r"\1", text)))


def mention_key(sentence):
    return hashlib.sha256(sentence.encode("utf-8")).hexdigest()[:16]


# ---- round 18: the markdown subset the guard parses (decision B, vote 6def5ab6, ai-memory 1795854b) ----
# The hand lexer reads only the subset named in the docstring section "Guard grammar (markdown subset)";
# every other construct is refused with "unsupported markdown construct: <construct> at <file>:<line>".
GRAMMAR_MESSAGE = "unsupported markdown construct: %s at %s:%d"
# Rule 3: the measured HTML block allow-list. CERT holds one HTML block (line 1, a one-line comment), so
# the CERT entry is the one-line comment form, which also covers the 25 one-line comments of CHANGELOG.md.
# README.md holds 47 HTML block lines (21 distinct, logo, title and the <details> sections); they are
# accepted only as these exact lines, and an accepted HTML line is followed only by a blank line or
# another accepted line, so no markdown line ever sits inside an HTML block.
HTML_BLOCK_ALLOW = {
    "README.md": frozenset((
        '<p align="center">',
        '  <img src="docs/ai-memory-logo.jpg" alt="ai-memory logo" width="200">',
        '</p>',
        '<h1 align="center">ai-memory</h1>',
        '<p align="center"><em>universal AI memory</em></p>',
        '<details>',
        '<summary>Federation #3582 old-contract fixture census (rule e)</summary>',
        '</details>',
        '<summary><strong>Claude Code</strong> (Anthropic)</summary>',
        '<summary><strong>OpenAI Codex CLI</strong></summary>',
        '<summary><strong>Google Gemini CLI</strong></summary>',
        '<summary><strong>Cursor IDE</strong></summary>',
        '<summary><strong>Windsurf</strong> (Codeium)</summary>',
        '<summary><strong>Continue.dev</strong></summary>',
        '<summary><strong>Grok CLI</strong> (AlphaOne fork — deep integration with auto-recall)</summary>',
        '<summary><strong>xAI Grok API</strong> (API-level, remote MCP)</summary>',
        '<summary><strong>META Llama</strong> (via Llama Stack)</summary>',
        '<summary><strong>OpenClaw</strong></summary>',
        '<summary><strong>Any other MCP client</strong></summary>',
        '  <img src="docs/architecture.svg" alt="ai-memory architecture diagram" width="900">',
        '  <img src="docs/benchmark.svg" alt="LongMemEval benchmark results" width="820">',
    )),
}
# Rule 5: whitespace other than U+0020 that a renderer may treat as a space or a break.
_G_NONASCII_WS = frozenset("\u0085\u00A0\u1680\u180E\u2028\u2029\u202F\u205F\u3000\uFEFF"
                           + "".join(chr(c) for c in range(0x2000, 0x200C)))
_G_ITEM_RE = re.compile(r" *(?:[-*+]|\d{1,9}[.)])(?: +|$)")
_G_HEADLIKE_RE = re.compile(r"#{1,6}(?:[ \t]|$)")
_G_FENCE_RE = re.compile(r"`{3,}|~{3,}")
_G_CLOSER_RE = re.compile(r"(`{3,}|~{3,}) *$")
_G_SETEXT_RE = re.compile(r" *(?:=+|-+) *$")
_G_HTML_RE = re.compile(r"<[a-z/!?]", re.IGNORECASE)
_G_AUTOLINK_RE = re.compile(r"<(?:[a-z][a-z0-9+.-]{1,31}:[^\s<>]*|[^\s@<>]+@[^\s@<>]+)>", re.IGNORECASE)
# Round 19/20: a whole single-line comment, anchored at both ends; the body holds no "--" run and no
# "<!--" (a "<" is allowed only when it does not open one), so a nested opener, even one that shares its
# dashes with the closer ("<!-- a <!-->"), and a second "-->" are not the comment (the line is then
# refused as an HTML block).
_G_COMMENT_LINE_RE = re.compile(r"^<!--(?:[^-<]|<(?!!--)|-(?!-))*-->$")
_G_FRONT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*: \S.*$")
_G_REFDEF_RE = re.compile(r" *\[[^\]\n]+\]:")
# Rule 4: a gated-block item marker at the start of the (unindented) text, one space, then text.
_GB_MARKER_RE = re.compile(r"(?:[-*+]|\d{1,9}[.)]) (?=[^ ])")
_GB_NAMES = ((B_IN, "IN"), (B_PENDING, "PENDING"), (B_UNLANDED, "UNLANDED"), (B_NOT, "NOT"))


def _g_html_start(s):
    return _G_HTML_RE.match(s) is not None and _G_AUTOLINK_RE.match(s) is None


def _g_inner(s):
    """The text after a run of list markers at the start of s, or None when s opens no list item."""
    m = _G_ITEM_RE.match(s)
    if not m:
        return None
    while m:
        s = s[m.end():]
        m = _G_ITEM_RE.match(s)
    return s


def _g_front_matter(lines):
    """Lines of a Jekyll front matter block ("---", key: value lines, "---") at the top of a
    file, or 0."""
    if not lines or lines[0] != "---":
        return 0
    for k in range(1, len(lines)):
        if lines[k] == "---":
            return k + 1 if k > 1 else 0
        if not _G_FRONT_RE.match(lines[k]):
            return 0
    return 0


def _g_quote_problem(ln, prev):
    """The refused construct on a column-0 block quote line, or None (rules 2 and 3)."""
    rest = ln[1:]
    rest = rest[1:] if rest.startswith(" ") else rest
    body = rest.lstrip(" ")
    if body.startswith(">"):
        return "nested block quote"
    if _G_FENCE_RE.match(body):
        return "fence in a block quote"
    if _G_HEADLIKE_RE.match(body):
        return "heading-like line in a block quote"
    if _g_inner(body) is not None:
        return "list item in a block quote"
    if _g_html_start(body):
        return "HTML block in a block quote"
    if body and len(rest) - len(body) >= 4:
        return "indented code in a block quote"
    if body and prev == "quote" and _G_SETEXT_RE.match(body):
        return "setext underline in a block quote"
    return None


def _g_line_problem(ln, prev, allow):
    """(refused construct or None, line kind) for a non-blank line outside a fence and outside
    a quote."""
    lead = len(ln) - len(ln.lstrip(" "))
    s = ln[lead:]
    inner = _g_inner(s)
    if lead and s.startswith(">"):
        return "indented block quote", "text"
    if inner is not None:
        for test, name in ((lambda x: x.startswith(">"), "block quote in a list item"),
                           (_G_FENCE_RE.match, "fence in a list item"),
                           (_G_HEADLIKE_RE.match, "heading-like line in a list item"),
                           (_g_html_start, "HTML block in a list item")):
            if test(inner):
                return name, "text"
    if _G_FENCE_RE.match(s):
        if lead:
            return "indented fence opener", "text"
        run = _G_FENCE_RE.match(s).group()
        if run[0] == "`" and "`" in s[len(run):]:
            return "backtick in a fence info string", "text"
        return None, "fence"
    if _G_HEADLIKE_RE.match(s):
        return ("indented heading-like line" if lead else None), "heading"
    if _g_html_start(s):
        if ln in allow:
            return None, "html"
        if lead or not _G_COMMENT_LINE_RE.match(s):
            return "HTML block", "text"
        return None, "text"
    if prev != "blank" and _G_SETEXT_RE.match(ln):
        return "setext underline", "text"
    return None, "text"


def grammar_problems(rel, text):
    """Round 18 (decision B): every line of a gated markdown file is in the guard's subset, or it is
    refused as "unsupported markdown construct: <construct> at <file>:<line>" (fail closed)."""
    out = []

    def refuse(construct, n):
        out.append(GRAMMAR_MESSAGE % (construct, rel, n))

    allow = HTML_BLOCK_ALLOW.get(rel, frozenset())
    lines = text.split("\n")
    skip = _g_front_matter(lines)
    fence, prev = None, "blank"
    for n, ln in enumerate(lines, 1):
        ws = [ch for ch in ln if ch in _G_NONASCII_WS]
        if ws:
            refuse("non-ASCII whitespace U+%04X" % ord(ws[0]), n)
        if n <= skip:
            if "\t" in ln:
                refuse("tab outside a fence", n)
            continue
        if fence is not None:
            m = _G_CLOSER_RE.match(ln)
            if m and ln[0] == fence[0] and len(m.group(1)) >= fence[1]:
                fence, prev = None, "text"
                continue
            body = ln.lstrip(" \t>")
            run = _G_FENCE_RE.match(body)
            if run and run.group()[0] == fence[0] and len(run.group()) >= fence[1]:
                refuse("fence-like line inside a fence", n)
            elif rel == CERT_REL and _G_HEADLIKE_RE.match(body):
                refuse("heading-like line inside a fence", n)
            continue
        if not ln.strip(" "):
            prev = "blank"
            continue
        if "\t" in ln:
            refuse("tab outside a fence", n)
        if prev == "html" and ln not in allow:
            refuse("heading-like line in an HTML block" if _G_HEADLIKE_RE.match(ln.lstrip(" "))
                   else "markdown inside an HTML block", n)
        if ln.startswith(">"):
            problem = _g_quote_problem(ln, prev)
            if problem:
                refuse(problem, n)
            prev = "quote" if ln[1:].strip(" ") else "quote-blank"
            continue
        if prev == "quote":
            refuse("lazy block-quote continuation", n)
        problem, kind = _g_line_problem(ln, prev, allow)
        if problem:
            refuse(problem, n)
        if kind == "fence" and not problem:
            run = _G_FENCE_RE.match(ln).group()
            fence = (run[0], len(run), n)
        prev = kind
    if fence is not None:
        refuse("unclosed fence", fence[2])
    return out


def _gb_opens_block(rest):
    """True when item or continuation text would open a block instead of continuing inline text."""
    return bool(rest[:1] in (">", "|", " ") or _G_HEADLIKE_RE.match(rest) or _G_ITEM_RE.match(rest)
                or _G_FENCE_RE.match(rest) or _g_html_start(rest) or _G_REFDEF_RE.match(rest)
                or _G_SETEXT_RE.match(rest) or _BREAK_RE.match(rest))


def _gb_toplevel(s, prev):
    """The construct a column-0 non-item line of a gated block is."""
    if s.startswith(">"):
        return "block quote"
    if s.startswith("|"):
        return "table row"
    if _G_FENCE_RE.match(s):
        return "fence"
    if _G_HEADLIKE_RE.match(s):
        return "heading-like line"
    if _g_html_start(s):
        return "HTML block"
    return "lazy continuation" if prev in ("item", "cont") else "paragraph"


def _gb_body_problems(body, first, name, rel):
    """Rule 4 on the lines of one gated block after its fixed lead (body[k] is file line
    first + k + 1)."""
    out, prev, parent, child, cur = [], "blank", None, None, None
    for k, ln in enumerate(body):
        if not ln.strip(" "):
            prev = "blank"
            continue
        construct = None
        lead = len(ln) - len(ln.lstrip(" "))
        s = ln[lead:]
        m = _GB_MARKER_RE.match(s)
        if "\t" in ln:
            construct = "tab"
        elif m and lead == 0:
            parent, child = m.end(), None
            cur = parent
            construct = "nested block in an item" if _gb_opens_block(s[m.end():]) else None
        elif m and child is not None and lead >= child:
            construct = "deeper nesting"
        elif m and parent is not None and parent <= lead <= 4:
            child = lead + m.end()
            cur = child
            construct = "nested block in an item" if _gb_opens_block(s[m.end():]) else None
        elif m:
            construct = "list item at an unsupported indentation"
        elif lead == 0:
            construct = _gb_toplevel(s, prev)
        elif cur is not None and prev in ("item", "cont") and lead == cur:
            construct = "nested block in an item" if _gb_opens_block(s) else None
        elif cur is not None and prev == "blank":
            construct = "second item paragraph"
        else:
            construct = "continuation at an unsupported indentation"
        if construct:
            out.append(GRAMMAR_MESSAGE % ("%s in the %s block" % (construct, name), rel, first + k + 1))
            prev = "bad"
        else:
            prev = "item" if m else "cont"
    return out


def block_text_problems(rel, text):
    """Round 18 rule 4 (security r16 MEDIUM-1): each of the four statement blocks is its fixed lead
    (BLOCK_LEADS, one entry per line, the first entry is the rest of the marker line), one blank
    line, then only list items and blank lines: a "-", "*", "+" or ordered marker at column 0 plus
    one space and inline text, at most one nesting level (a child item indented from the parent's
    content column up to 4 spaces), continuation lines directly under an item or continuation at
    exactly that item's content column. The NOT block ends at the STATEMENT_END rule. Anything
    else is refused as
    "unsupported markdown construct: <construct> in the <block> block at <file>:<line>"."""
    lines = text.split("\n")
    starts = {}
    for marker in BLOCK_MARKERS:
        hit = [n for n, ln in enumerate(lines) if ln.startswith(marker)]
        if len(hit) != 1:
            return [GRAMMAR_MESSAGE % ("block marker not on exactly one line: " + marker, rel, 1)]
        starts[marker] = hit[0]
    end = text.find(STATEMENT_END)
    stop_last = text.count("\n", 0, end) + 1 if end >= 0 and text.count(STATEMENT_END) == 1 else len(lines)
    out = []
    for marker, name in _GB_NAMES:
        first = starts[marker]
        later = [n for n in starts.values() if n > first]
        stop = min(later) if later else (stop_last if stop_last > first else len(lines))
        lead = BLOCK_LEADS[marker]
        body = [lines[first][len(marker):]] + lines[first + 1:stop]
        bad = next((k for k in range(len(lead)) if k >= len(body) or body[k] != lead[k]), None)
        if bad is None and len(body) > len(lead) and body[len(lead)].strip(" "):
            bad = len(lead)
        if bad is not None:
            out.append(GRAMMAR_MESSAGE % ("text after the block marker in the %s block" % name, rel,
                                          first + bad + 1))
        out.extend(_gb_body_problems(body[len(lead) + 1:], first + len(lead) + 1, name, rel))
    return out


BLOCK_ITEMS = ((B_IN, IN_ITEMS), (B_PENDING, PENDING_ITEMS), (B_UNLANDED, UNLANDED_ITEMS), (B_NOT, NOT_ITEMS))


def block_item_problems(text_blocks):
    """Round 17, widened in round 18 (security MEDIUM-1): every item of the four statement blocks
    matches exactly one reviewed key, every key is matched once, and the item's flattened text
    (children folded in) matches its reviewed digest."""
    out = []
    for marker, expected in BLOCK_ITEMS:
        items = _items(text_blocks[marker])
        for item in items:
            keys = [key for key in expected if key in item]
            if len(keys) != 1:
                out.append("item matches %d keys: %s" % (len(keys), item[:60]))
            elif mention_key(item) != BLOCK_ITEM_DIGESTS[keys[0]]:
                out.append("item text changed without review: %s (%s)" % (keys[0], mention_key(item)))
        for key in expected:
            if sum(key in item for item in items) != 1:
                out.append("item missing or duplicated: %s" % key)
    return out


def _check_items(case, body, expected):
    items = _items(body)
    case.assertEqual(len(items), len(expected), "item count drifted: %d" % len(items))
    for key, nums in expected.items():
        hit = [i for i in items if key in i]
        case.assertEqual(len(hit), 1, "item missing or duplicated: " + key)
        for num in (nums if isinstance(nums, tuple) else (nums,)):
            case.assertRegex(hit[0], r"#%d\b" % num, key + " lost #%d" % num)
        # Round 16 (code r12 INFO-1): any case; exactly the item's own state word, never both.
        found = {w for w in ("open", "closed") if re.search(r"\b%s\b" % w, hit[0], re.IGNORECASE)}
        want = STATE_WORDS[key]
        case.assertEqual(found, {want} if want else set(), "%s state words %s, want %s" % (key, sorted(found), want))
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
            fenced, bodies, _, _ = _reading(lines, rel != HTML_REL)
            heads = {n for first, _, _, last in _scan(text, _implied_range(rel, text), 1, rel != HTML_REL)[1]
                     for n in range(first + 1, last + 2)}
            bad = ["%s:%d" % (rel, n) for first, last, _ in units for n in range(first, last + 1)
                   if n in heads or (not fenced[n - 1] and _line_heading(bodies[n - 1]))]
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
               for n in html_heading_misuse(scoped_text(rel, _read(rel)), rel != HTML_REL)]
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

    def test_code_is_read_relative_to_its_container_8262(self):
        # Round 16 (code r12 MEDIUM-1/MEDIUM-2, security r14 MEDIUM-1/LOW-1): fences and indented code
        # are read relative to the list item or block quote that holds them (CommonMark 0.31), so a
        # heading inside code never resets the pair context and a heading outside code always does.
        claim = "The envelope ships in v1.1."

        def texts(raw):
            return [u[2] for u in gated_units(raw)]
        fed, notes = "## Federation\n\n", "## Notes\n\n"
        claimed = (  # the heading inside the code is not read: the claim stays under Federation
            fed + "- item\n\n    ```\n  ## Notes\n    ```\n\n",   # list fence 2 past the content column
            fed + "```\n    ```\n## Notes\n```\n\n",            # a closer 4 spaces in does not close
            fed + "```\n> ```\n## Notes\n```\n\n",              # a quoted closer does not close
            fed + "- ```\n  ## Notes\n  ```\n\n",               # a fence right after the list marker
            fed + "- item\n\n    ```\n    <h2>Notes</h2>\n    ```\n\n",
            fed + "-   item\n\n    ```\n    <h2>Notes</h2>\n    ```\n\n",
            fed + "- ```\n  <h2>Notes</h2>\n  ```\n\n",
            fed + "```\n    ```\n<h2>Notes</h2>\n```\n\n",
            fed + "    <h2>Notes</h2>\n\n",                     # indented code
            notes + "- item\n\n  ```\n  code\n\n" + fed,        # the fence closes when its list item ends
        )
        for raw in claimed:
            self.assertEqual(texts(raw + claim), [claim], raw)
        # Round 17 (code r13 MEDIUM-1): a deeper blockquote marker left of the list item's content
        # column ends the item, so its fence closes and the quoted heading is read.
        close = "\n\n     ```"
        for body, tail in (("- item\n\n  ```\n> ## Federation\n\n", ""),
                           ("- item\n\n  ```\n> ## Federation\n\n", close),
                           ("- item\n\n  ```\n > ## Federation\n\n", close),
                           ("- item\n\n  ```\n> <h2>Federation</h2>\n\n", close),
                           ("1. item\n\n   ```\n> ## Federation\n\n", close),
                           ("> - item\n>\n>   ```\n> > ## Federation\n\n", close)):
            raw = notes + body + claim + tail
            self.assertEqual(texts(raw), [claim], raw)
        # A quote marker at or past the content column stays fence content.
        self.assertEqual(texts(notes + "- item\n\n  ```\n  > ## Federation\n\n  " + claim + "\n  ```"), [])
        # A real fence inside a list item hides the heading in it (no claim under Federation).
        for head, tail in (("- item\n\n    ```\n  ", "\n    ```"), ("- ```\n  ", "\n  ```")):
            raw = notes + head + "## Federation\n\n  " + claim + tail
            self.assertEqual(texts(raw), [], raw)
        # Indented code is code in both readings: a heading in it never adds a pair word.
        self.assertEqual(texts(notes + "    ## Federation roadmap\n\n" + claim), [])
        self.assertEqual(texts(notes + "    <h2>Federation</h2>\n\n" + claim), [])
        # Unclosed at the end: _lex() names the opening line; no gated file ends inside a fence.
        self.assertEqual(_lex(["x", "", "```", "## Federation"])[2], [2])
        self.assertEqual(_lex(["- ```", "  x", "", "y"])[2], [])
        for rel in SINGLE_SOURCE_FILES:
            lines = [normalise(x) for x in scoped_text(rel, _read(rel)).split("\n")]
            self.assertEqual(_reading(lines, rel != HTML_REL)[2], [], rel + " ends inside an open fence")

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

    def test_block_text_is_items_only_8262(self):
        # Round 17 (security r15 MEDIUM-1, D2), widened in round 18 (security r16 MEDIUM-1, rule 4): the
        # IN, PENDING, UNLANDED and NOT blocks hold items only, and each item's whole flattened text is
        # pinned, so no claim rides in them unreviewed.
        text = CERT.read_text(encoding="utf-8")
        self.assertEqual(block_text_problems(CERT_REL, text), [])
        self.assertEqual(block_item_problems(_blocks()), [])
        lines = text.split("\n")
        at = {m: next(n for n, ln in enumerate(lines) if ln.startswith(m)) for m in BLOCK_MARKERS}
        rule = lines.index("---", at[B_NOT])  # the STATEMENT_END rule that closes the NOT block
        tde = "Postgres-native TDE is claimed for v1.0.0."
        last = at[B_PENDING] - 2  # the last line of the last IN item (0-based)
        p_last = at[B_UNLANDED] - 2  # the last line of the PENDING item
        u_last = at[B_NOT] - 2  # the last line of the last UNLANDED item
        n_last = rule - 2  # the last line of the last NOT item

        def problems(pos, add):
            return block_text_problems(CERT_REL, "\n".join(lines[:pos] + add + lines[pos:]))[:1]

        def named(n, construct, name):
            return [GRAMMAR_MESSAGE % ("%s in the %s block" % (construct, name), CERT_REL, n)]
        cases = (  # (0-based insert position, inserted lines, the refused 1-based line, construct, block)
            (last + 1, ["> " + tde], last + 2, "block quote", "IN"),
            (last + 1, [tde], last + 2, "lazy continuation", "IN"),
            (last + 1, ["    " + tde], last + 2, "continuation at an unsupported indentation", "IN"),
            (last + 1, ["", tde], last + 3, "paragraph", "IN"),
            (last + 1, ["  > " + tde], last + 2, "nested block in an item", "IN"),
            (last + 1, ["  # " + tde], last + 2, "nested block in an item", "IN"),
            (last + 1, ["", "  " + tde], last + 3, "second item paragraph", "IN"),
            (last + 1, ["  - nested", "    - " + tde], last + 3, "deeper nesting", "IN"),
            (last + 1, ["     - " + tde], last + 2, "list item at an unsupported indentation", "IN"),
            (last + 1, ["  \t" + tde], last + 2, "tab", "IN"),
            (at[B_IN] + 1, [tde], at[B_IN] + 2, "text after the block marker", "IN"),
            (p_last + 1, ["", tde], p_last + 3, "paragraph", "PENDING"),
            (p_last + 1, ["> " + tde], p_last + 2, "block quote", "PENDING"),
            (p_last + 1, [tde], p_last + 2, "lazy continuation", "PENDING"),
            (u_last + 1, ["> " + tde], u_last + 2, "block quote", "UNLANDED"),
            (u_last + 1, [tde], u_last + 2, "lazy continuation", "UNLANDED"),
            (at[B_UNLANDED] + 1, [tde], at[B_UNLANDED] + 2, "text after the block marker", "UNLANDED"),
            (n_last + 1, ["", tde], n_last + 3, "paragraph", "NOT"),
            (n_last + 1, ["> " + tde], n_last + 2, "block quote", "NOT"),
            (n_last + 1, [tde], n_last + 2, "lazy continuation", "NOT"),
            (n_last + 1, ["", "| " + tde + " |"], n_last + 3, "table row", "NOT"),
            (n_last + 1, ["", "```", tde, "```"], n_last + 3, "fence", "NOT"),
            (n_last + 1, ["", "<p>" + tde + "</p>"], n_last + 3, "HTML block", "NOT"),
        )
        for pos, add, n, construct, name in cases:
            self.assertEqual(problems(pos, add), named(n, construct, name), (construct, name))
        # In-subset controls: a two-space continuation and a one-level child item parse, and the item
        # digest still refuses the changed item text.
        for add in (["  " + tde], ["  - " + tde], ["  1. " + tde]):
            new = lines[:last + 1] + add + lines[last + 1:]
            self.assertEqual(block_text_problems(CERT_REL, "\n".join(new)), [], add)
            sec = "\n".join(new)
            body = sec[sec.index(B_IN):sec.index(B_PENDING)].split("\n", 1)[1]
            blocks = dict(_blocks())
            blocks[B_IN] = body
            self.assertEqual(block_item_problems(blocks),
                             ["item text changed without review: Quarantine of unattributed inbound writes (%s)"
                              % mention_key(_items(body)[-1])])
        # The NOT and PENDING items are digest-pinned (round 18): one more NOT item is refused.
        new = lines[:n_last + 1] + ["- " + tde] + lines[n_last + 1:]
        self.assertEqual(block_text_problems(CERT_REL, "\n".join(new)), [])
        blocks = dict(_blocks())
        blocks[B_NOT] = blocks[B_NOT].rstrip("\n") + "\n- " + tde + "\n"
        self.assertEqual(block_item_problems(blocks),
                         ["item text changed without review: Postgres-native TDE (%s)" % mention_key("- " + tde),
                          "item missing or duplicated: Postgres-native TDE"])

    def test_gated_files_parse_in_the_markdown_subset_8262(self):
        # Round 18 (decision B): every gated markdown file parses in the documented subset; the
        # refusal names the construct and its file:line.
        bad = [p for rel in SINGLE_SOURCE_FILES if rel != HTML_REL
               for p in grammar_problems(rel, scoped_text(rel, _read(rel)))]
        self.assertEqual(bad, [], "\n".join(bad[:20]))
        readme = _read("README.md").split("\n")
        self.assertEqual(sorted(HTML_BLOCK_ALLOW["README.md"] - set(readme)), [],
                         "an HTML allow-list line is gone from README.md; shrink the list")

    def test_markdown_subset_boundary_rows_8262(self):
        # Round 18: one refused row per grammar rule and an in-subset control beside it.
        def got(text, rel="README.md"):
            return [p[len("unsupported markdown construct: "):].rsplit(" at ", 1)[0]
                    for p in grammar_problems(rel, text)]
        self.assertEqual(grammar_problems("README.md", "> > x"),
                         ["unsupported markdown construct: nested block quote at README.md:1"])  # rule 1
        rows = (
            # rule 2: heading liveness
            ("# Federation\n\ntext", [], "README.md"),
            ("    # Federation", ["indented heading-like line"], "README.md"),
            (" # Federation", ["indented heading-like line"], "README.md"),
            ("```\n# Federation\n```", ["heading-like line inside a fence"], CERT_REL),
            ("```\n# comment\n```", [], "README.md"),
            ("> # Federation", ["heading-like line in a block quote"], "README.md"),
            ("- # Federation", ["heading-like line in a list item"], "README.md"),
            ("<details>\n## Federation", ["heading-like line in an HTML block"], "README.md"),
            ("text\n===", ["setext underline"], "README.md"),
            ("text\n---", ["setext underline"], "README.md"),
            ("- item\n    ---", ["setext underline"], "README.md"),
            ("text\n\n---", [], "README.md"),
            ("> text\n> ---", ["setext underline in a block quote"], "README.md"),
            # rule 3: containers only at top level
            ("```\ncode\n```", [], "README.md"),
            ("~~~~\n```\n~~~~", [], "README.md"),
            ("  ```\ncode", ["indented fence opener"], "README.md"),
            ("```\ncode", ["unclosed fence"], "README.md"),
            ("````\n```\n````", [], "README.md"),
            ("```\n```` x\n```", ["fence-like line inside a fence"], "README.md"),
            ("```\n````\n", [], "README.md"),
            ("```\nx\n  ```\n```", ["fence-like line inside a fence"], "README.md"),
            ("``` a`b", ["backtick in a fence info string"], "README.md"),
            ("> ```", ["fence in a block quote"], "README.md"),
            ("- ```", ["fence in a list item"], "README.md"),
            ("1. ~~~", ["fence in a list item"], "README.md"),
            ("  > x", ["indented block quote"], "README.md"),
            ("- > x", ["block quote in a list item"], "README.md"),
            ("> - x", ["list item in a block quote"], "README.md"),
            ("> x\ny", ["lazy block-quote continuation"], "README.md"),
            ("> x\n\ny", [], "README.md"),
            ("> x\n>\ny", [], "README.md"),
            (">     code", ["indented code in a block quote"], "README.md"),
            ("<div>\nx", ["HTML block"], "README.md"),
            ("<!-- note -->\n\nx", [], CERT_REL),
            ("<!-- a\nb -->", ["HTML block"], CERT_REL),
            ("<https://example.com> is a link", [], "README.md"),
            ("> <div>", ["HTML block in a block quote"], "README.md"),
            ("- <div>", ["HTML block in a list item"], "README.md"),
            ("<details>\n\nx", [], "README.md"),
            ("<details>\ntext", ["markdown inside an HTML block"], "README.md"),
            ("<details>", ["HTML block"], CERT_REL),
            ("---\nlayout: doc\n---\n# Title", [], "README.md"),
            ("x\n---\nlayout: doc", ["setext underline"], "README.md"),
            # rule 5: whitespace
            ("a\u00A0b", ["non-ASCII whitespace U+00A0"], "README.md"),
            ("a\u2007b", ["non-ASCII whitespace U+2007"], "README.md"),
            ("a\u200Bb", ["non-ASCII whitespace U+200B"], "README.md"),
            ("\uFEFFx", ["non-ASCII whitespace U+FEFF"], "README.md"),
            ("a\u3000b", ["non-ASCII whitespace U+3000"], "README.md"),
            ("a\tb", ["tab outside a fence"], "README.md"),
            ("x\n\t\ny", ["tab outside a fence"], "README.md"),
            ("```\na\tb\n```", [], "README.md"),
            ("x\n   \ny", [], "README.md"),
        )
        for text, want, rel in rows:
            self.assertEqual(got(text, rel), want, (text, rel))

    def test_trust_peer_markup_spellings_8262(self):
        # Round 19 (security r17 LOW-1, rule 6): an escape or emphasis around the second half of the
        # identifier does not hide it; the intra-word underscore is kept by the fourth mention view.
        for token in ("TRUST\\_PEER", "TRUST_**PEER**", "**TRUST**_PEER", "TRUST_`PEER`", "TRUST_~~PEER~~",
                      "__TRUST_PEER__", "*TRUST*\\_PEER"):
            for text in ("Enable %s on every peer." % token, "| %s | 1 |" % token):
                self.assertEqual(len(trust_peer_units("README.md", text)), 1, text)
        # Round 20 (security r19 LOW-1): a Unicode dash between the halves is the same identifier.
        for dash in "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\uFE58\u2E3A":
            text = "Enable TRUST%sPEER on every peer." % dash
            self.assertEqual(len(trust_peer_units("README.md", text)), 1, "U+%04X" % ord(dash))
        for token in ("TRUST_PEERS_ARE_LISTED", "TRUST\\_PEER\\_LIMIT", "TRUST_**PEER**_LIMIT", "trustpeer",
                      "TRUST\u2013PEERS"):
            text = "Enable %s on every peer." % token
            self.assertEqual(trust_peer_units("README.md", text), [], text)

    def test_trust_peer_dash_between_halves_only_8262(self):
        # Round 21 (code r20 MEDIUM-1, security r20 LOW-1, code r20 LOW-1): only the dash between
        # "trust" and "peer" is read as "-"; a dash after the identifier stays visible to the
        # lookahead, and the identifier is a mention whatever follows it.
        def count(text, rel="README.md"):
            return len(trust_peer_units(rel, text))
        after = ("Never enable TRUST_PEER—it disables the attribution gate.",
                 "Set TRUST_PEER–only for a lab mesh.")
        for text in after:
            self.assertEqual(count(text), 1, text)
            self.assertEqual(count("| Mode | Note |\n| --- | --- |\n| a | %s |" % text), 1, text)
            self.assertEqual(count("- %s" % text), 1, text)
        self.assertEqual(count("Enable TRUST–PEER—now."), 1)
        self.assertEqual(count("Enable TRUST–PEERS now."), 0)
        for spelling in ("&ndash;", "&mdash;", "&minus;", "&hyphen;", "&dash;", "&horbar;", "&#8208;",
                         "&#x2010;", "&#8211;", "&#8212;", "&#8722;", "︱", "︲"):
            self.assertEqual(count("Enable TRUST%sPEER now." % spelling), 1, spelling)
        everyone = [chr(c) for c in range(0x110000)
                    if unicodedata.category(chr(c)) == "Pd" or c == 0x2212]
        self.assertGreater(len(everyone), 20)
        for dash in everyone:
            self.assertEqual(count("Enable TRUST%sPEER now." % dash), 1, "U+%04X" % ord(dash))
        # Controls: a dash elsewhere in the line is not rewritten; ASCII is unchanged; a dash inside
        # an HTML comment reads as the same spelling outside it.
        self.assertEqual(count("A re‐check of the mesh and a peer—note."), 0)
        self.assertEqual(count("Enable TRUST_PEER now."), 1)
        self.assertEqual(count("<!-- TRUST–PEER -->"), count("<!-- TRUST_PEER -->"))
        # Round 22 (code r21 MEDIUM-1, security r21 LOW-1): a dash that sits between the halves only
        # once a comment, tag or link is removed is read as "-" too.
        for text in ("Enable TRUST<!-- x -->–PEER now.", "Enable TRUST–<!-- x -->PEER now.",
                     "Enable TRUST<!---->—PEER now.", "Enable TRUST&ndash;<!-- x -->PEER now.",
                     "Enable TRUST<b>–</b>PEER now.", "Enable TRUST–<br>PEER now.",
                     "Enable [TRUST–PEER](https://example.com/a) now.",
                     "Enable [TRUST](https://example.com/a)–PEER now.",
                     "Enable TRUST<!-- x -->–<!-- y -->PEER now.", "Enable **TRUST**–PEER now."):
            for wrap in ("%s", "| Mode | Note |\n| --- | --- |\n| a | %s |", "- %s", "*%s*"):
                self.assertEqual(count(wrap % text), 1, wrap % text)
        # Controls: the neighbouring characters survive, so a longer word is still not the identifier.
        self.assertEqual(count("Enable TRUST<!-- x -->–PEERS now."), 0)
        self.assertEqual(count("Enable XTRUST<!-- x -->–PEER now."), 0)
        self.assertEqual(count("Enable TRUST<!-- x -->–PEER—now."), 1)
        self.assertEqual(count("Enable TRUST<!-- x --> PEER now."), 0)
        # Round 23 (security r22 LOW-1): a markdown spelling of the identifier inside a one-line HTML
        # comment counts as it does outside one. The comment-blanked views are read as well.
        interior = ("**TRUST**_PEER", "TRUST_`PEER`", "TRUST\\_PEER", "[TRUST](https://example.com/a)_PEER",
                    "TRUST<b>_</b>PEER")
        dashed = tuple(row.replace("_", "–", 1) for row in interior)
        self.assertEqual(len(dashed), len(interior))
        for row in interior + dashed:
            for wrap in ("<!-- %s -->", "| Mode | Note |\n| --- | --- |\n| a | <!-- %s --> |",
                         "- <!-- %s -->", "Enable <!-- %s --> now."):
                self.assertEqual(count(wrap % row), 1, wrap % row)
        # Controls: a longer word, a missing half, an identifier split across the comment delimiter
        # (no half is complete on either view), and the neighbouring characters survive.
        for text in ("<!-- TRUST_PEERS -->", "<!-- **TRUST**_PEERS -->", "<!-- XTRUST_`PEER` -->",
                     "<!-- TRUST_ -->PEER", "TRUST<!-- _ -->PEER", "<!-- TRUST --><!-- _PEER -->",
                     "<!-- TRUST<!-- -->_PEER -->", "<!-- TRUST *-* PEER -->"):
            self.assertEqual(count(text), 0, text)
        self.assertEqual(count("Enable <!-- **TRUST**_PEER --> now."), 1)
        self.assertEqual(count("Enable <!-- **TRUST**_PEERS --> now."), 0)

    def test_trust_peer_dash_position_matrix_8262(self):
        # Round 22 (code r21 MEDIUM-1): every dash of the class, in every position relative to a
        # comment, tag or link and in every wrapper, spells the identifier; none counts fewer than
        # the plain dash between the halves.
        positions = ("TRUST%sPEER", "TRUST<!-- x -->%sPEER", "TRUST%s<!-- x -->PEER",
                     "TRUST<b>%s</b>PEER", "TRUST%s<br>PEER", "[TRUST%sPEER](https://example.com/a)",
                     "[TRUST](https://example.com/a)%sPEER")
        wrappers = ("Enable %s now.", "| Mode | Note |\n| --- | --- |\n| a | %s |", "- %s", "*%s*")
        dashes = [chr(c) for c in range(sys.maxunicode + 1)
                  if unicodedata.category(chr(c)) == "Pd" or c == 0x2212]
        self.assertGreater(len(dashes), 20)
        for dash in dashes:
            for position in positions:
                for wrap in wrappers:
                    text = wrap % (position % dash)
                    self.assertEqual(len(trust_peer_units("README.md", text)), 1,
                                     "U+%04X %r" % (ord(dash), text))

    def test_front_matter_tab_and_comment_rows_8262(self):
        # Round 19 (code r15 LOW-1, LOW-3): rule 5 covers YAML front matter; the one-line comment match
        # is anchored and refuses everything else as an HTML block.
        def got(text, rel="README.md"):
            return [p[len("unsupported markdown construct: "):] for p in grammar_problems(rel, text)]
        self.assertEqual(got("---\nlayout: a\tb\n---\n# T"),
                         ["tab outside a fence at README.md:2"])
        self.assertEqual(got("---\nlayout: a b\n---\n# T\n\n```\na\tb\n```"), [])
        self.assertEqual(got("<!-- note -->\n\nx"), [])
        for text in ("<!-- a\nb -->", "<!-- a --> text", "<!-- a <!-- b -->", "<!-- a --> <!-- b -->", "<!-->",
                     "<!-- a --->", "<!-- a -- b -->", "<!-- a --> ", "<!-- a <!-->", "<!--<!-->",
                     "<!--->"):
            self.assertTrue(got(text), text)
            self.assertIn("HTML block", got(text)[0], text)
        for text in ("<!-- note -->", "<!---->", "<!-- a < b -->", "<!-- <b> -->", "<!-- a - b -->"):
            self.assertEqual(got(text + "\n\nx"), [], text)

    def test_comment_pattern_is_linear_8262(self):
        # Round 20 (code r19 MEDIUM-1): the one-line comment pattern refuses a nested opener at the
        # character level. Worst case for its alternation is a "<" followed by "!-" runs, 100 KB on one
        # line, closed and unclosed; each stays under a 2 s ceiling.
        import time
        for text in ("<!--" + "<!-" * 33400, "<!--" + "<!-" * 33400 + "-->", "<!--" + "<!" * 50000 + "-->",
                     "<!--" + "<" * 100000 + "-->"):
            start = time.perf_counter()
            grammar_problems("README.md", text)
            elapsed = time.perf_counter() - start
            self.assertLess(elapsed, 2.0, "%d chars took %.2f s" % (len(text), elapsed))

    def test_grammar_rules_3_and_5_match_the_readme_8262(self):
        # Round 19 (code r15 LOW-5, INFO-1): the README and the docstring state rules 3 and 5 alike, and
        # the rule 5 code points are the ones the code refuses.
        doc = " ".join((__doc__ or "").split()) + " "
        readme = " ".join(_read("scripts/ci/tests/data/README.md").split()) + " "
        for num, nxt in ((3, 4), (5, 6)):
            want = re.search(r" %d\. (.*?) %d\. " % (num, nxt), doc)
            have = re.search(r" %d\. (.*?) %d\. " % (num, nxt), readme)
            self.assertTrue(want and have, num)
            self.assertEqual(want.group(1), have.group(1), "rule %d differs" % num)
            if num == 3:
                # Round 21 (code r20 INFO-1): the empty-comment exception is stated on both sides.
                self.assertIn('"--->" is refused except as the close of the empty comment "<!---->", '
                              'which is accepted', want.group(1))
        points = set()
        for text in (doc, readme):
            m = re.search(r" 5\. (.*?) 6\. ", text).group(1)
            found = set()
            for lo, hi in re.findall(r"U\+([0-9A-F]{4})(?:-U\+([0-9A-F]{4}))?", m):
                found.update(range(int(lo, 16), int(hi or lo, 16) + 1))
            found.add(0xA0)
            points.add(frozenset(found))
        self.assertEqual(points, {frozenset(ord(c) for c in _G_NONASCII_WS)})

    def test_lexer_is_linear_on_single_line_marker_runs_8262(self):
        # Round 19 (code r15 INFO-2): a single line of nested list or quote markers was quadratic in
        # _lex() (a thematic-break match and a slice of the rest of the line per marker). Each row stays
        # under a 10 s ceiling; the unit text is unchanged. Round 20 (security r19 INFO-1): the ceiling
        # was 2 s; the lexer measured 0.04-1.19 s at nice 19 under load, and the round-18 lexer took
        # 518-587 s on the same input, so 10 s still proves linearity with a 50x margin.
        import time
        rows = (("- " * 5000 + "x"), ("> " * 5000 + "x"), ("1. " * 3400 + "x"), ("- " * 100000 + "x"),
                ("- * " * 50000 + "x"), ("- " * 100000), ("* " * 100000 + "-"))
        for text in rows:
            start = time.perf_counter()
            gated_units(text)
            elapsed = time.perf_counter() - start
            self.assertLess(elapsed, 10.0, "%d chars took %.2f s" % (len(text), elapsed))
        self.assertEqual(gated_units("- - x\n"), [])

    def test_trust_peer_identifier_forms_8262(self):
        # Round 18 (code r14 LOW-1): the short trust-peer token in identifier form is a mention
        # wherever it stands; the five reviewer spellings first, then two more.
        for text in ("| TRUST_PEER | 1 | enables sync |", "```yaml\ntrust_peer: yes\n```",
                     "Recommended: TRUST_PEER: 1 on every peer.", "TRUST_PEER should be set to 1 on every peer.",
                     "Enable TRUST_PEER on every peer.",
                     "Turn on `trust-peer` for every peer.", "| Trust_Peer | enabled |"):
            self.assertEqual(len(trust_peer_units("README.md", text)), 1, text)
        for text in ("Trust peer-supplied sync metadata.", "Set TRUST_PEER_LIMIT to 1.", "The trust peer is one.",
                     "A trust-peer-supplied value.", "Distrust_peer is a word.", "Read trustpeers.md."):
            self.assertEqual(trust_peer_units("README.md", text), [], text)

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
        self.assertEqual([i for i in items if "Curator namespace-scoped mode" in i], [CURATOR_NOT_CLAIMED])
        self.assertTrue(any("deferred-v1.x" in i for i in items))

    def test_trust_peer_bypass_never_endorsed_8262(self):
        # Round 16 (R3): the sync trust-peer bypass is named only by the reviewed census units in
        # TRUST_PEER_MENTIONS, both directions, in every gated file.
        mentions = trust_peer_mentions()
        found = collections.Counter((rel, mention_key(s)) for rel, s in mentions)
        want = collections.Counter(TRUST_PEER_MENTIONS)
        texts = {(rel, mention_key(s)): s for rel, s in mentions}
        self.assertEqual(sorted((found - want).elements()), [],
                         "unreviewed bypass mention: " + " | ".join(texts[k] for k in (found - want)))
        self.assertEqual(sorted((want - found).elements()), [], "reviewed bypass mention gone or reworded")
        # Synthetic: every spelling the folded views read is a mention; an unrelated sentence is not.
        for text in ("Set `AI_MEMORY_FED_SYNC_TRUST_PEER=1` on every peer.", "Enable sync-trust-peer.",
                     "Turn on SYNC&#95;TRUST&#95;PEER for speed.", "<p>Set sync trust peer to 1.</p>"):
            self.assertEqual(len(trust_peer_units(HTML_REL if text.startswith("<") else "README.md", text)),
                             1, text)
        self.assertEqual(trust_peer_units("README.md", "Peers sync and trust the mesh."), [])

    def test_trust_peer_short_name_and_census_unit_8262(self):
        # Round 17 (code r13 LOW-1, security r15 LOW-1, D3): the short name set to a truthy value is a
        # mention, and the census unit is the paragraph, list item or table row holding the match.
        for text in ("Set TRUST_PEER to 1 for every trusted peer.", "Export `TRUST_PEER=true` first.",
                     "Operators set TRUST_PEER to 1 for a full dump on every peer.", "Use trust-peer = yes.",
                     "<p>Set TRUST_PEER to on.</p>"):
            self.assertEqual(len(trust_peer_units(HTML_REL if text.startswith("<") else "README.md", text)),
                             1, text)
        for text in ("Trust peer-supplied sync metadata.",
                     "Set TRUST_PEER_LIMIT to 1.", "Distrust peer to 1 of them.", "The trust peer is one.",
                     "<!-- set AI_MEMORY_FED_SYNC_TRUST_PEER=1 -->"):
            self.assertEqual(trust_peer_units(HTML_REL if text.startswith("<!") else "README.md", text), [], text)
        # The unit is the paragraph, list item or table row: a sentence next to a reviewed mention is
        # read with it, and one table row is never joined with the next.
        para = "The bypass is `AI_MEMORY_FED_SYNC_TRUST_PEER`. Set it only for trusted peers."
        self.assertEqual(trust_peer_units("README.md", para), [para])
        rows = "| a | `AI_MEMORY_FED_SYNC_TRUST_PEER` | x |\n| b | other | y |\n- item\n- `SYNC_TRUST_PEER` item"
        self.assertEqual(trust_peer_units("README.md", rows),
                         ["| a | `AI_MEMORY_FED_SYNC_TRUST_PEER` | x |", "- `SYNC_TRUST_PEER` item"])

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
