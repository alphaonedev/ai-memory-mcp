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

B_IN = "**Certified for the GA candidate (IN):**"
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
E2E_RE = re.compile(r"end-to-end[- ]+(content[- ]+)?encrypt|#1968|end-to-end-content",
                    re.IGNORECASE)
STALE_RE = re.compile(r"1968[^.\n]{0,60}\bopen\b", re.IGNORECASE)
OVERCLAIM_RE = re.compile(r"\b(live|certified)\b", re.IGNORECASE)
E2E_WORD_RE = re.compile(r"end-to-end|content encryption|\bE2E\b", re.IGNORECASE)


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
        self.assertTrue(any("deferred-v1.x" in i and "so deferred" not in i for i in items))

    def test_pointers_present(self):
        for rel in POINTERS:
            self.assertIn(ANCHOR, _read(rel), rel + " lost the pointer")

    def test_readme_pointer_follows_current_release_paragraph(self):
        paras = _paragraphs(_read("README.md"))
        idx = [i for i, p in enumerate(paras) if ANCHOR in p]
        self.assertEqual(len(idx), 1)
        self.assertTrue(paras[idx[0] - 1].startswith("**v1.0.0 — current release.**"))

    def test_single_source_for_e2e_scope(self):
        for rel in SINGLE_SOURCE_FILES:
            text = _read(rel)
            if rel == CERT_REL:
                sec = _subsection()
                text = text.replace(sec, "")
            elif rel == "CHANGELOG.md":
                text = _unreleased(text)
            self.assertIsNone(STALE_RE.search(text), rel + " carries a stale '#1968 open' claim")
            for para in _paragraphs(text):
                if E2E_RE.search(para):
                    self.assertTrue(ANCHOR in para or E2E_CANON in _flat(para),
                                    rel + " mentions end-to-end encryption without the "
                                    "statement anchor or the canonical paragraph: "
                                    + _flat(para)[:100])


if __name__ == "__main__":
    unittest.main()
