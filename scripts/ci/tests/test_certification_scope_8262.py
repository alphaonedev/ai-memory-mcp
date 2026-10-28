#!/usr/bin/env python3
"""Doc-pin for the v1.0.0 GA certification scope statement (#8262).

Fails when the subsection heading is missing from the certification doc, when
an item of the NOT-claimed list loses its issue number, or when a pointer to
the subsection disappears from docs/federation.md, SECURITY.md,
docs/SECURITY.md or README.md.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
CERT = ROOT / "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
HEADING = "### Certification scope statement for the v1.0.0 GA candidate"
ANCHOR = "certification-scope-statement-for-the-v100-ga-candidate-8262"
POINTERS = ["docs/federation.md", "SECURITY.md", "docs/SECURITY.md", "README.md"]
# NOT-claimed item keyword -> issue number it must cite.
NOT_CLAIMED = {
    "Federation end-to-end content encryption": 1968,
    "Postgres-native TDE": 8262,
    "Curator namespace-scoped mode": 8264,
    "Batman Form 2": 8255,
    "Top-shelf encryption documentation": 3833,
    "Singleton and Team shapes": 3125,
}


def _subsection():
    text = CERT.read_text(encoding="utf-8")
    start = text.find(HEADING)
    if start < 0:
        raise AssertionError("scope statement heading missing: " + HEADING)
    end = text.find("\n---\n", start)
    return text[start:end if end > 0 else len(text)]


def _not_claimed_items():
    sec = _subsection()
    block = sec.split("**NOT claimed for v1.0.0", 1)
    if len(block) != 2:
        raise AssertionError("NOT-claimed list missing")
    items, cur = [], None
    for ln in block[1].splitlines()[1:]:
        if ln.startswith("- "):
            cur = [ln]
            items.append(cur)
        elif cur is not None and ln.startswith("  "):
            cur.append(ln)
    return ["\n".join(i) for i in items]


class CertificationScope8262(unittest.TestCase):
    def test_heading_present(self):
        self.assertIn(HEADING, CERT.read_text(encoding="utf-8"))

    def test_not_claimed_items_keep_issue_numbers(self):
        items = _not_claimed_items()
        for key, num in NOT_CLAIMED.items():
            hit = [i for i in items if key in i]
            self.assertEqual(len(hit), 1, "NOT-claimed item missing: " + key)
            self.assertRegex(hit[0], r"#%d\b" % num, key + " lost #%d" % num)

    def test_open_gaps_listed_with_issue_numbers(self):
        sec = _subsection()
        for num in (2967, 8260, 8265):
            self.assertRegex(sec, r"#%d\b" % num)

    def test_pointers_present(self):
        for rel in POINTERS:
            txt = (ROOT / rel).read_text(encoding="utf-8")
            self.assertTrue(re.search(re.escape(ANCHOR), txt), rel + " lost the pointer")


if __name__ == "__main__":
    unittest.main()
