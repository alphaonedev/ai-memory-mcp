"""Python mirror of the crypto-erase docs census for the cargo_skip trees (#8346).

src/encryption/mod.rs (the `DOCS_CENSUS_*` constants and `docs_census_8315_on`,
about lines 2130-2240, test `docs_describing_erase_list_every_erasable_version_8315`)
runs `git ls-files -- docs` and reads every tracked .md and .html doc. A PR that
touches only docs/** gets cargo_skip=true, so that Rust test never runs on it.
This file runs the SAME census from the Classify job on every PR (rules.json
`cargo_skip.walk_guards`, the pair shape of #3627). The phrases, the dated-record
carve-outs, the erase doc and the erasable version bytes are parsed from the Rust
source, so a change to the census moves the mirror.
"""
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
RULES = REPO / "scripts" / "ci" / "impact" / "rules.json"
RUST_SRC = "src/encryption/mod.rs"
SCOPE_SRC = "src/encryption/scope.rs"
SCRATCH = REPO / ".local-runs"


def read(rel):
    """Return the text of a tracked source file."""
    return (REPO / rel).read_text()


def const_body(text, name):
    """Return the body of `const <name>: ... = ...;` in the Rust source."""
    match = re.search(r"const %s:[^=]*=\s*(.*?);\n" % re.escape(name), text, re.S)
    if match is None:
        raise AssertionError("%s no longer declares %s" % (RUST_SRC, name))
    return match.group(1)


def strings(body):
    """Return the string literals of a Rust const body, in order."""
    return re.findall(r'"((?:[^"\\]|\\.)*)"', body)


def erasable_bytes(text):
    """Return the `0x..` strings for CRYPTO_ERASABLE_ENVELOPE_VERSIONS (RECORD, SCOPE)."""
    match = re.search(r"CRYPTO_ERASABLE_ENVELOPE_VERSIONS: \[u8; \d+\] =\s*\[(.*?)\];", text, re.S)
    if match is None:
        raise AssertionError("%s no longer declares CRYPTO_ERASABLE_ENVELOPE_VERSIONS" % RUST_SRC)
    names = re.findall(r"[A-Z_]+", match.group(1))
    values = {}
    for src in (text, read(SCOPE_SRC)):
        for name, val in re.findall(r"const ([A-Z_]+_ENVELOPE_VERSION): u8 = 0x([0-9a-fA-F]+);", src):
            values[name] = int(val, 16)
    return ["0x%02x" % values[name] for name in names]


def rules_entry():
    """Return the walk_guards entry rules.json hands to this mirror."""
    for guard in json.loads(RULES.read_text())["cargo_skip"]["walk_guards"]:
        if guard["rust"] == RUST_SRC:
            return guard
    raise AssertionError("rules.json has no walk_guards entry for %s" % RUST_SRC)


class Census:
    """The predicates of docs_census_8315_on, parsed from the Rust source."""

    def __init__(self, text):
        self.phrases = strings(const_body(text, "DOCS_CENSUS_ERASE_PHRASES"))
        self.dated = strings(const_body(text, "DOCS_CENSUS_DATED_RECORDS"))
        self.erase_doc = strings(const_body(text, "DOCS_CENSUS_ERASE_DOC"))[0]
        self.bytes = erasable_bytes(text)

    def reads(self, rel):
        """True when the Rust census reads `rel` at all (extension, not a dated record)."""
        return rel.endswith((".md", ".html")) and not any(rel.startswith(d) for d in self.dated)

    def judge(self, rel, text):
        """Return (in_census, failure or None) for one tracked doc."""
        if not self.reads(rel):
            return False, None
        flat = text.lower()
        if not any(p in flat for p in self.phrases) or not any(b in flat for b in self.bytes):
            return False, None
        missing = [b for b in self.bytes if b not in flat]
        if missing:
            return True, "%s: describes crypto erase but does not list %s" % (rel, ", ".join(missing))
        return True, None

    def run(self, root, listing):
        """Return (census, failures) over the relative paths in `listing`."""
        census, failures = [], []
        for rel in listing:
            if not self.reads(rel):
                continue
            found, failure = self.judge(rel, (root / rel).read_text(encoding="utf-8"))
            if found:
                census.append(rel)
            if failure:
                failures.append(failure)
        return census, failures


def tracked_docs():
    """Return `git ls-files -- docs`, as the Rust census does."""
    out = subprocess.run(["git", "ls-files", "--", "docs"], cwd=str(REPO), check=True,
                         stdout=subprocess.PIPE, universal_newlines=True)
    return out.stdout.splitlines()


class DocsCryptoEraseCensusWalk8346(unittest.TestCase):
    """The docs census of src/encryption/mod.rs, run on every PR."""

    @classmethod
    def setUpClass(cls):
        cls.text = read(RUST_SRC)
        cls.census = Census(cls.text)
        cls.listing = tracked_docs()

    def test_census_constants_were_parsed(self):
        self.assertEqual(self.census.erase_doc, "docs/security/crypto-erase.md")
        self.assertEqual(self.census.bytes, ["0x03", "0x05"])
        self.assertGreaterEqual(len(self.census.phrases), 4)
        self.assertEqual(self.census.dated, ["docs/reviews/", "docs/audit/"])

    def test_live_tree_passes_the_census(self):
        self.assertGreater(len(self.listing), 100)
        census, failures = self.census.run(REPO, self.listing)
        self.assertIn(self.census.erase_doc, census, "the census must reach the erase doc")
        self.assertEqual(failures, [], "erase-describing docs must list every erasable byte:\n"
                         + "\n".join(failures))

    def test_scratch_tree_with_a_rejected_sentence_fails(self):
        SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(SCRATCH), prefix="census-8346-") as scratch:
            root = Path(scratch)
            for rel in self.listing:
                dest = root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(str(REPO / rel), str(dest))
            probe = "docs/probe-8346.md"
            (root / probe).write_text("Only 0x03 envelopes are crypto-erasable.\n")
            census, failures = self.census.run(root, self.listing + [probe])
            self.assertIn(probe, census)
            self.assertEqual([f for f in failures if not f.startswith(probe)], [])
            self.assertEqual(len(failures), 1, failures)
            self.assertIn("0x05", failures[0])

    def test_mirror_agrees_with_the_rust_fixture(self):
        """Every probe the Rust test plants is rejected; the complete doc is accepted."""
        probes = re.findall(r'"(docs/probe-[a-z]\.md)",\s*"([^"]+)"', self.text)
        self.assertGreaterEqual(len(probes), 5)
        for rel, line in probes:
            found, failure = self.census.judge(rel, line)
            self.assertTrue(found and failure, "%s must fail the census: %s" % (rel, line))
        complete = "Crypto erase covers " + " and ".join(self.census.bytes) + "."
        self.assertEqual(self.census.judge("docs/ok.md", complete), (True, None))
        self.assertEqual(self.census.judge("docs/x.md", "Only 0x03 is used here."), (False, None))
        self.assertEqual(self.census.judge("docs/x.txt", "crypto-erase 0x03"), (False, None))
        self.assertEqual(self.census.judge("docs/reviews/x.md", "crypto-erase 0x03"), (False, None))
        self.assertEqual(self.census.judge("docs/audit/x.md", "crypto-erase 0x03"), (False, None))
        self.assertEqual(self.census.judge("docs/x.html", "Crypto-erase 0x03")[0], True)

    def test_rules_json_carries_the_walk_guard_entry(self):
        entry = rules_entry()
        self.assertEqual(entry["roots"], ["docs"])
        self.assertEqual(entry["guard"], "scripts/ci/tests/test_docs_crypto_erase_census_walk_8346.py")
        self.assertTrue((REPO / entry["guard"]).is_file())


if __name__ == "__main__":
    unittest.main()
