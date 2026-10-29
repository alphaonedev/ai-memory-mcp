#!/usr/bin/env python3
"""Doc-pin for the v1.0.0 GA certification scope statement (#8262): a pinned-unit allowlist.

Design (round 11, 3-agent vote 6def5ab6, choice B; conductor amendment memory db2a250b). The
end-to-end content encryption scope is stated once, in the certification scope statement of
docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md. Every unit of the gated files that names
that subject is pinned verbatim in a closed table (the sidecar JSON PINS_REL), checked in both
directions: a gated unit that is not in the table fails (unpinned), and a pin that is not found
exactly once fails (stale or duplicated). There is no over-claim or under-claim wording rule; a
changed sentence about the subject is a changed pin, and the review pair reads the pin diff as a
named review step. This follows the repository precedent for protected content (closed pinned
sets in test_ci_select_gating_8240.py and test_pg_isolated_binary.py, CODE_STYLE.md:466-467).

Units. A file is NFKC-normalised and passed through the Cyrillic/Greek confusable map once. It is
split into blank-line blocks; each table row (a line starting with "|") is its own unit and each
list item (a line starting with "-", "*", "+" or "N." / "N)") starts a new paragraph. Inside a
paragraph the splitter ends a sentence at ".", "!" or "?" plus up to four closers (quote, ")",
"]", "*", "_", backtick) plus whitespace; it is one bounded regex, linear and deterministic. A
sentence is subject-bearing when it carries a subject token, or a paired stem while it or a
neighbour carries a pair word. The unit is that sentence plus one sentence on each side, inside
the paragraph; overlapping or touching windows merge. A paragraph whose subject token straddles
a sentence boundary is gated whole. Unit text is compared with whitespace runs collapsed, so a
reflow is not a change. Every raw surface is covered because units are cut from the raw text:
markdown prose, table rows, list items, fenced code, reference-link definitions, footnotes, HTML
comments, and in docs/encryption.html text nodes and every attribute (title, alt, data-*,
aria-label).

Subject tokens (matched case-insensitively on two views of a sentence: the raw text and the text
with tags and markdown emphasis removed; entities unescaped, NFKD, marks and format characters
dropped): 8278 in any form (#8278, issue 8278, the URL); variant A, variant B, variants A and B,
both variants; end-to-end with any separator (any dash class, spaces) and E2E/E2EE; X25519; scope
key, scope-key, per-namespace key; unreadable to relays or peers; payload confidentiality. Paired
stems encrypt, decrypt, seal, envelope, wrap, ciphertext, plaintext and content encryption are
subjects only when the window also carries federation/federated, peer, relay, replica or sync;
inside the certification scope statement subsection (HEADING to the next "---" rule) the pair word
is implied, so every paired stem there is gated.

Characters. Every Cf, Mn and Me character in the raw file, and every non-Latin letter left after
normalisation, is refused anywhere in a gated file, except the measured (path, code point, count)
entries of EXEMPT_CHARS.

CHANGELOG.md is gated from the top down to the first released-version heading (a "## [" heading
that carries a release date); the released sections below it are frozen history and exempt.

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
ANCHOR = "certification-scope-statement-for-the-v100-ga-candidate-8262"
POINTERS = ["docs/federation.md", "SECURITY.md", "docs/SECURITY.md", "README.md"]
SINGLE_SOURCE_FILES = [CERT_REL, "docs/federation.md", "SECURITY.md",
                       "docs/SECURITY.md", "README.md", CHANGELOG_REL,
                       HTML_REL, "docs/compliance/honest-limitations.md",
                       "docs/compliance/nsa-csi-mcp-security-mapping.md",
                       "docs/enterprise-deployment.md", "docs/federation-identity.md",
                       "ROADMAP.md", "docs/production-deployment.md",
                       "docs/reference/ARCHITECTURE_REFERENCE.md"]
# Measured refused characters that are legitimate: {path: {code point: count}}. U+FE0F is the
# emoji presentation selector, U+03BC the NFKC form of the micro sign, U+03A3 a summation sign.
EXEMPT_CHARS = {
    "SECURITY.md": {0xFE0F: 1},
    CHANGELOG_REL: {0xFE0F: 2, 0x03BC: 5},
    "docs/enterprise-deployment.md": {0xFE0F: 4, 0x03A3: 2},
    "docs/federation-identity.md": {0xFE0F: 1},
    "docs/reference/ARCHITECTURE_REFERENCE.md": {0xFE0F: 1},
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
}
UNLANDED_ITEMS = {
    "Quarantine of unattributed inbound writes": 2967,
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
_REFUSED_CATEGORIES = ("Cf", "Mn", "Me")


def normalise(text):
    """NFKC plus the confusable map, once."""
    if text.isascii():
        return text
    return unicodedata.normalize("NFKC", text).translate(_CONFUSABLES)


def refused_chars(raw):
    """{code point: count} of Cf/Mn/Me characters in the raw text and non-Latin letters after
    normalisation; one pass over the distinct characters of each."""
    out = {}
    if raw.isascii():
        return out
    for ch in set(raw):
        if unicodedata.category(ch) in _REFUSED_CATEGORIES:
            out[ord(ch)] = raw.count(ch)
    norm = normalise(raw)
    for ch in set(norm):
        if ch.isascii() or ord(ch) in out:
            continue
        cat = unicodedata.category(ch)
        if cat in _REFUSED_CATEGORIES or (cat[0] == "L" and not unicodedata.name(ch, "").startswith("LATIN")):
            out[ord(ch)] = norm.count(ch)
    return out


# ---- subject vocabulary ----
_SEP = r"[^a-z0-9]{0,4}"
# Every pattern starts with a literal (the boundary checks are look-behinds after it), so each is a
# fast linear scan; the lists are searched one pattern at a time.
_NB = "(?<![a-z0-9]%s)"
_SUBJECTS = [
    r"8278",
    r"variant" + _NB % "variant" + r"s?" + _SEP + r"[ab](?![a-z0-9])",
    r"both" + _SEP + r"variants",
    r"end" + _NB % "end" + _SEP + r"to" + _SEP + r"end(?![a-z0-9])",
    r"e2e" + _NB % "e2e" + r"e?(?![a-z0-9])",
    r"x25519",
    r"scope" + _SEP + r"keys?(?![a-z0-9])",
    r"per" + _SEP + r"namespace" + _SEP + r"keys?(?![a-z0-9])",
    r"unreadable" + _SEP + r"to" + _SEP + r"(?:relay|peer)",
    r"payload" + _SEP + r"confidential",
]
_STEMS = [r"encrypt", r"decrypt", r"seal", r"envelope", r"wrap", r"cipher" + _SEP + r"text",
          r"plain" + _SEP + r"text", r"content" + _SEP + r"encrypt"]
_PAIRS = [r"federat", r"peer", r"relay", r"replica", r"sync(?<![a-z]sync)"]
SUBJECT_RES = [re.compile(x) for x in _SUBJECTS]
STEM_RES = [re.compile(x) for x in _STEMS]
PAIR_RES = [re.compile(x) for x in _PAIRS]


def _any(patterns, views):
    return any(rx.search(v) for v in views for rx in patterns)


_TAG_RE = re.compile(r"<[^<>]*>")
_MARKUP_RE = re.compile(r"[*_`~\\]")
_SENT_END_RE = re.compile(r"[.!?][\"')\]*_`]{0,4}\s+")
_ITEM_RE = re.compile(r"[ \t]*(?:>[ \t]*)*(?:[-*+]|\d{1,3}[.)])[ \t]")
_ROW_RE = re.compile(r"[ \t]*(?:>[ \t]*)*\|")
_WS_RE = re.compile(r"\s+")
_RELEASED_RE = re.compile(r"^## \[[^\]\n]*\][^\n]*\d{4}-\d{2}-\d{2}", re.MULTILINE)


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


def _views(text):
    """The raw view and the view with tags and markdown emphasis removed."""
    raw = fold(text)
    return raw, _MARKUP_RE.sub("", _TAG_RE.sub("", raw))


def _has_subject(views):
    return _any(SUBJECT_RES, views)


def _paragraphs(lines):
    """(line index, text) per paragraph of a blank-line block: table rows alone, list items split."""
    out, cur, first = [], [], 0
    for i, line in enumerate(lines):
        if _ROW_RE.match(line):
            if cur:
                out.append((first, "\n".join(cur)))
                cur = []
            out.append((i, line))
            continue
        if cur and _ITEM_RE.match(line):
            out.append((first, "\n".join(cur)))
            cur = []
        if not cur:
            first = i
        cur.append(line)
    if cur:
        out.append((first, "\n".join(cur)))
    return out


def _windows(para, implied_pair=False):
    """(start, end) spans of the subject-bearing sentence windows of one paragraph; implied_pair
    treats every sentence as carrying a pair word (the scope statement is about federation)."""
    whole = _views(para)
    if not _has_subject(whole) and not (_any(STEM_RES, whole) if implied_pair else _paired(whole)):
        return []
    if _ROW_RE.match(para):
        return [(0, len(para))]
    spans, start = [], 0
    for m in _SENT_END_RE.finditer(para):
        spans.append((start, m.start() + 1))
        start = m.end()
    if start < len(para):
        spans.append((start, len(para)))
    if len(spans) == 1:
        return [(0, len(para))]
    views = [_views(para[a:b]) for a, b in spans]
    pair = [implied_pair or _any(PAIR_RES, vs) for vs in views]
    hits = []
    for i, vs in enumerate(views):
        near = any(pair[max(0, i - 1):i + 2])
        if _has_subject(vs) or (near and _any(STEM_RES, vs)):
            hits.append(i)
    if not hits:
        return [(0, len(para))] if _has_subject(whole) else []
    out = []
    for i in hits:
        lo, hi = max(0, i - 1), min(len(spans) - 1, i + 1)
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = hi
        else:
            out.append([lo, hi])
    return [(spans[a][0], spans[b][1]) for a, b in out]


def _paired(views):
    return _any(STEM_RES, views) and _any(PAIR_RES, views)


def scoped_text(rel, raw):
    """The gated part of a file: CHANGELOG.md down to the first released-version heading."""
    if rel == CHANGELOG_REL:
        m = _RELEASED_RE.search(raw)
        return raw[:m.start()] if m else raw
    return raw


def gated_units(text, implied_pair=False, first_line=1):
    """(first line, last line, collapsed text) for every gated unit of normalised text."""
    out, block, start = [], [], 0
    for number, line in enumerate(text.split("\n") + [""], first_line):
        if line.strip():
            if not block:
                start = number
            block.append(line)
            continue
        if not block:
            continue
        for line_index, para in _paragraphs(block):
            first, pos = start + line_index, 0
            for a, b in _windows(para, implied_pair):
                first += para.count("\n", pos, a)
                last = first + para.count("\n", a, b)
                out.append((first, last, _WS_RE.sub(" ", para[a:b]).strip()))
                first, pos = last, b
        block = []
    return out


def file_units(rel, raw):
    """Units of one gated file; inside the scope statement subsection the pair word is implied."""
    text = normalise(scoped_text(rel, raw))
    if rel != CERT_REL or HEADING not in text:
        return gated_units(text)
    a = text.index(HEADING)
    b = text.find("\n---\n", a)
    b = len(text) if b < 0 else b
    head_line = text.count("\n", 0, a) + 1
    tail_line = head_line + text.count("\n", a, b)
    return (gated_units(text[:a]) + gated_units(text[a:b], True, head_line)
            + gated_units(text[b:], False, tail_line))


def current_units(root=ROOT):
    return {rel: file_units(rel, (root / rel).read_text(encoding="utf-8")) for rel in SINGLE_SOURCE_FILES}


def load_pins(root=ROOT):
    data = json.loads((root / PINS_REL).read_text(encoding="utf-8"))
    return [(p["file"], p["text"]) for p in data["pins"]]


def emit_pins(units):
    lines = ['{"issue": 8262, "vote": "6def5ab6", "pins": [']
    rows = [json.dumps({"file": rel, "text": u[2]}, ensure_ascii=True)
            for rel in SINGLE_SOURCE_FILES for u in units[rel]]
    lines.append(",\n".join(rows))
    lines.append("]}")
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
    end = text.find("\n---\n", start)
    return text[start:end if end > 0 else len(text)]


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
    return items


class CertificationScope8262(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.units = current_units()
        cls.pins = load_pins()

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

    def test_statement_canonical_paragraph_is_pinned(self):
        hit = [t for r, t in self.pins if r == CERT_REL and E2E_CANON in t]
        self.assertEqual(len(hit), 1, "the canonical paragraph is not in exactly one CERT pin")

    def test_gated_files_refuse_hidden_and_foreign_characters(self):
        for rel in SINGLE_SOURCE_FILES:
            got = refused_chars(_read(rel))
            self.assertEqual(got, EXEMPT_CHARS.get(rel, {}), "%s refused characters: %s" % (
                rel, {"U+%04X" % k: v for k, v in sorted(got.items())}))

    def test_changelog_gate_is_the_current_release_section(self):
        raw = _read(CHANGELOG_REL)
        scoped = scoped_text(CHANGELOG_REL, raw)
        self.assertIn("## [Unreleased]", scoped)
        self.assertIn("### Docs (#8262", scoped)
        self.assertRegex(raw[len(scoped):].split("\n", 1)[0], r"^## \[\d+\.\d+\.\d+\]")

    def test_unit_rules_on_synthetic_text(self):
        para = "One. Two. #8278 is here. Four. Five."
        self.assertEqual([u[2] for u in gated_units(para)], ["Two. #8278 is here. Four."])
        self.assertEqual(gated_units("| a | Variant-B | x |\n| b | c |"), [(1, 1, "| a | Variant-B | x |")])
        self.assertEqual(len(gated_units("- end to end\n- other item")), 1)
        self.assertEqual(gated_units("Content encryption is on."), [])
        self.assertEqual(gated_units("Content encryption is on.", True, 7), [(7, 7, "Content encryption is on.")])
        stmt = file_units(CERT_REL, HEADING + "\n\nOnce again, content encryption is enabled.\n\n---\n\nIt is on.\n")
        self.assertEqual(stmt, [(3, 3, "Once again, content encryption is enabled.")])
        self.assertEqual(len(gated_units("Rows are sealed. Peers read them.")), 1)
        for text in ('<p title="#8278 is live.">x</p>', "<!-- #8278 -->", "#82​78 x",
                     "8<b>27</b>8 x", "[e2e]: https://example.org/x", "Issue &#56;278 x",
                     "End—to—end x", "Variants A and B x", "X25519 x",
                     "unreadable to relays", "payload confidentiality", "per-namespace key"):
            self.assertTrue(gated_units(normalise(text)), text)

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
        sys.stdout.write(emit_pins(current_units()))
        sys.exit(0)
    unittest.main()
