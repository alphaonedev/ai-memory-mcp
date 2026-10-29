#!/usr/bin/env python3
"""Doc-pin for the v1.0.0 GA certification scope statement (#8262).

The statement in docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md is the
single source of truth for what the GA candidate certifies. This guard pins:

* the heading and the four blocks in order (IN, in-scope-pending, not-yet-landed
  fail-closed controls, NOT claimed);
* each block's item list (keyword and issue number, exact item count);
* the load-bearing sentences verbatim: the canonical end-to-end content
  encryption paragraph (in scope for GA, delivered by #8278, certification only
  after landing), the mTLS transport-only sentence, the mTLS IN item and the
  Postgres-native TDE not-claimed sentence;
* that the IN block makes no end-to-end content encryption claim and no
  live/certified over-claim, and that the open fail-closed gaps sit only in
  the not-yet-landed block;
* that every other place that mentions end-to-end content encryption links the
  statement anchor or quotes the canonical paragraph verbatim, and that no
  stale "#1968 open" wording returns.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
CERT_REL = "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
CERT = ROOT / CERT_REL
HEADING = "### Certification scope statement for the v1.0.0 GA candidate"
ANCHOR = "certification-scope-statement-for-the-v100-ga-candidate-8262"
POINTERS = ["docs/federation.md", "SECURITY.md", "docs/SECURITY.md", "README.md"]
# Files whose end-to-end content encryption mentions must defer to the statement.
SINGLE_SOURCE_FILES = [CERT_REL, "docs/federation.md", "SECURITY.md",
                       "docs/SECURITY.md", "README.md", "CHANGELOG.md"]
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
E2E_RE = re.compile(r"end-to-end[- ]+(?:content[- ]+)?(?:encrypt|protect|confiden|seal)"
                    r"|#1968|end-to-end-content|(?-i:\bE2E\b)", re.IGNORECASE)
STALE_RE = re.compile(r"1968[^.\n]{0,60}\bopen\b", re.IGNORECASE)
# A dated history line ("Last updated: 2026-09-11 ... Previous: 2026-08-16 (... #1968 OPEN ...)")
# records what was true on that date and is exempt from the stale and single-source scans.
HISTORY_LINE_RE = re.compile(r"^(?:Last updated:\s*)?\d{4}-\d{2}-\d{2}\b")
SECURITY_HISTORY_ENTRY = "federation-is-plaintext (#1968 OPEN) posture note added"
OVERCLAIM_RE = re.compile(r"\b(live|certified)\b", re.IGNORECASE)
E2E_WORD_RE = re.compile(r"end-to-end|content encryption|\bE2E\b", re.IGNORECASE)
# Over-claim patterns refused in every end-to-end paragraph outside the statement.
NEG_RE = re.compile(r"\b(?:not|no)\b[^.;]{0,60}end-to-end|end-to-end[^.;]{0,60}\bnot\b",
                    re.IGNORECASE)
SCOPE_REFUSED = [
    re.compile(r"\bout of (?:the |ga |v1\.0\.0 |\w+ ){0,3}scope\b", re.IGNORECASE),
    re.compile(r"\bnot in (?:the |ga |v1\.0\.0 |\w+ ){0,3}scope\b", re.IGNORECASE),
    re.compile(r"\bships? in v1\.0\.0", re.IGNORECASE),
    re.compile(r"\b(?:is|are)\s+(?!not\b)(?:\w+\s+){0,2}end-to-end", re.IGNORECASE),
    re.compile(r"end-to-end[^.;]{0,60}\b(?:is|are)\s+(?:provided|supported|enabled|available|"
               r"shipped|implemented)", re.IGNORECASE),
    re.compile(r"\b(?:provides?|supports?|offers?)\s+(?:\w+\s+){0,2}end-to-end", re.IGNORECASE),
    re.compile(r"(?<!not )\b(?:live|certified)\b[^.;]{0,50}end-to-end|"
               r"end-to-end[^.;]{0,50}(?<!not )\b(?:live|certified)\b", re.IGNORECASE),
]
# The one pointer sentence quoted in every file that mentions end-to-end content encryption.
# Only the link target differs per file; the anchor is pinned.
POINTER_HEAD = ("Federation content is not end-to-end encrypted today (mTLS transport only); "
                "the end-to-end content encryption status is stated only in the ")
POINTER_RE = re.compile(re.escape(POINTER_HEAD + "[certification scope statement](")
                        + r"[^)\s]*#" + re.escape(ANCHOR) + r"\)\.")
# Files whose in-scope text (outside the statement) must quote the pointer sentence.
POINTER_SENTENCE_FILES = ["SECURITY.md", "docs/SECURITY.md", "docs/federation.md",
                          "CHANGELOG.md", CERT_REL]
SECURITY_E2E_SHAPE = (
    "End-to-end content encryption across federation (per-namespace scope keys, a per-record "
    "content key wrapped to each reader with X25519, envelope version 0x05, sealed on the wire, "
    "reader-scoped, with key rotation) is in scope for v1.0.0 GA and is delivered by "
    "[#8278](" + ISSUE_URL + "8278); it is not live today, and its certification is issued only "
    "when #8278 has landed on release/v1.0.0 with its tests green.")
OLD_E2E_LABEL = re.compile(r"blind-replica|ciphertext-only|reduced-capability", re.IGNORECASE)
SYNC_SINCE_PINS = [
    "`sync/since` is peer-scoped while the operator bypass `AI_MEMORY_FED_SYNC_TRUST_PEER=1` is unset",
    "`src/federation/peer_attestation.rs:390-392`",
    "consumed at `src/handlers/federation_sync_since.rs:289`",
    "The bypass is outside the asi-hard KNOBS set; only the enterprise posture doctor flags it",
    "`docs/compliance/evidence/cert-385da3a05/posture-*.out`",
]


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


def _plain(text):
    """Flatten and drop markdown emphasis, backticks and link targets before wording scans."""
    text = re.sub(r"\]\([^)]*\)", "]", text)
    return _flat(re.sub(r"[*`]", "", text))


def _units(text):
    """Paragraphs further split at top-level list items, so one bullet is one unit."""
    out = []
    for para in _paragraphs(text):
        out.extend(u for u in re.split(r"\n(?=[-*] )", para) if u.strip())
    return out


def _flat(text):
    return re.sub(r"\s+", " ", text)


def _check_items(case, body, expected):
    items = _items(body)
    case.assertEqual(len(items), len(expected), "item count drifted: %d" % len(items))
    for key, nums in expected.items():
        hit = [i for i in items if key in i]
        case.assertEqual(len(hit), 1, "item missing or duplicated: " + key)
        for num in (nums if isinstance(nums, tuple) else (nums,)):
            case.assertRegex(hit[0], r"#%d\b" % num, key + " lost #%d" % num)
    return items


def _paragraphs(text):
    text = re.sub(r"^[ \t]*>+ ?", "", text, flags=re.MULTILINE)
    return [p for p in re.split(r"\n\s*\n", text) if p.strip()]


def _unreleased(text):
    """The CHANGELOG entry this guard owns: the '### Docs (#8262' subsection."""
    start = text.find("### Docs (#8262")
    if start < 0:
        raise AssertionError("CHANGELOG #8262 entry missing")
    nxt = re.search(r"^### ", text[start + 5:], re.MULTILINE)
    return text[start:start + 5 + nxt.start()] if nxt else text[start:]


class CertificationScope8262(unittest.TestCase):
    def test_heading_present_and_blocks_in_order(self):
        self.assertIn(HEADING, CERT.read_text(encoding="utf-8"))
        self.assertEqual(len(_blocks()), len(BLOCK_MARKERS))

    def test_in_block_items_and_no_overclaim(self):
        body = _blocks()[B_IN]
        _check_items(self, body, IN_ITEMS)
        self.assertIn(MTLS_IN, _flat(body))
        self.assertIsNone(E2E_WORD_RE.search(body), "IN block makes an end-to-end claim")
        self.assertIsNone(OVERCLAIM_RE.search(body.replace("on by default", "")),
                          "IN block carries a live/certified over-claim")

    def test_e2e_canonical_paragraph_in_pending_block(self):
        body = _flat(_blocks()[B_PENDING])
        self.assertIn(E2E_CANON, body)
        self.assertIn(MTLS_ONLY, body)
        self.assertIn(SUPERSEDED_FACT, body)
        self.assertIn("#1968", body)
        self.assertEqual(body.count(E2E_CANON), 1)
        self.assertNotRegex(body.replace(E2E_CANON, ""), r"\b(is|are) (live|certified)\b")
        self.assertNotIn("1968) is open", body.lower())

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
        self.assertIsNone(E2E_WORD_RE.search(body), "NOT-claimed block names end-to-end encryption")
        self.assertTrue(any("deferred-v1.x" in i and not re.search(r"\bso\s+defer", i) for i in items))

    def test_pointers_present(self):
        for rel in POINTERS:
            self.assertIn(ANCHOR, _read(rel), rel + " lost the pointer")

    def test_readme_pointer_follows_current_release_paragraph(self):
        paras = _paragraphs(_read("README.md"))
        idx = [i for i, p in enumerate(paras) if ANCHOR in p]
        self.assertEqual(len(idx), 1)
        self.assertTrue(paras[idx[0] - 1].startswith("**v1.0.0 — current release.**"))

    def _scoped_text(self, rel):
        """The part of a file this guard scans: outside the statement, history lines removed."""
        text = _read(rel)
        if rel == CERT_REL:
            text = text.replace(_subsection(), "")
        elif rel == "CHANGELOG.md":
            text = _unreleased(text)
        return "\n".join(ln for ln in text.splitlines() if not HISTORY_LINE_RE.match(ln))

    def test_single_source_for_e2e_scope(self):
        for rel in SINGLE_SOURCE_FILES:
            text = self._scoped_text(rel)
            self.assertIsNone(STALE_RE.search(text), rel + " carries a stale '#1968 open' claim")
            for unit in _units(text):
                if not E2E_RE.search(unit):
                    continue
                raw = _flat(unit)
                head = rel + ": " + raw[:100]
                self.assertTrue(ANCHOR in raw or E2E_CANON in raw,
                                "end-to-end paragraph without the statement anchor: " + head)
                plain = _plain(unit)
                self.assertRegex(plain, NEG_RE, "end-to-end paragraph lacks the not-E2E "
                                 "statement: " + head)
                for rx in SCOPE_REFUSED:
                    self.assertIsNone(rx.search(plain), "end-to-end over-claim (%s) in %s"
                                      % (rx.pattern[:40], head))

    def test_pointer_sentence_quoted_in_every_pointer_file(self):
        for rel in POINTER_SENTENCE_FILES:
            flat = _flat(self._scoped_text(rel))
            self.assertIsNotNone(POINTER_RE.search(flat),
                                 rel + " lost the verbatim pointer sentence")

    def test_security_md_e2e_bullet_states_8278_shape_and_condition(self):
        flat = _flat(_read("SECURITY.md"))
        self.assertEqual(flat.count(SECURITY_E2E_SHAPE), 1)
        self.assertIsNone(OLD_E2E_LABEL.search(flat), "SECURITY.md carries the #1968 design label")
        self.assertIn("**Federation is NOT end-to-end encrypted", _read("SECURITY.md"))

    def test_security_md_keeps_dated_history_entry(self):
        history = [ln for ln in _read("SECURITY.md").splitlines() if HISTORY_LINE_RE.match(ln)]
        self.assertTrue(any(SECURITY_HISTORY_ENTRY in ln for ln in history),
                        "the dated 2026-08-16 history entry lost '(#1968 OPEN)'")

    def test_stale_claim_is_caught_outside_history(self):
        stale = "End-to-end encryption (#1968) is open today."
        self.assertIsNotNone(STALE_RE.search(stale))
        self.assertIsNone(HISTORY_LINE_RE.match(stale))
        self.assertIsNotNone(HISTORY_LINE_RE.match("Last updated: 2026-09-11 (x). Previous: 2026-08-16"))

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
    unittest.main()
