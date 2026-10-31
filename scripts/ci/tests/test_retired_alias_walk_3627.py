"""Python mirror of the #3627 retired-alias absence walk for the skippable trees (#8328).

tests/issue_3627_retired_llm_alias.rs walks docs/, scripts/ and changelog.d for a
retired provider token. A PR that touches only docs/** or scripts/ci/tests/**
gets cargo_skip=true, so that Rust test never runs on it (code review r1 F1,
8328). This file runs the SAME absence walk over the trees rules.json
`cargo_skip.walk_guards` names, from the Classify job on every PR, so the
coverage is kept. Roots, extensions, carve-outs and the build-directory skip
list are parsed from the Rust source, so the two walks cannot drift apart.
"""
import json
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
RULES = REPO / "scripts" / "ci" / "impact" / "rules.json"
RUST_TEST = "tests/issue_3627_retired_llm_alias.rs"
SKIPPED_DIRS = (".git", "target", "node_modules")
SUPPORTED_ALIAS = "gem" + "ini"
PRESENCE_FLOOR = 10


def retired_alias():
    """Return the retired token, built so this file does not contain it."""
    return "".join(["dee", "pseek"])


def rust_source():
    """Return the text of the Rust walk this file mirrors."""
    return (REPO / RUST_TEST).read_text()


def const_block(text, name):
    """Return the body of `const <name>: ... = ...;` in the Rust source."""
    match = re.search(r"const %s:[^=]*=\s*(.*?);\n" % re.escape(name), text, re.S)
    if match is None:
        raise AssertionError("%s no longer declares %s" % (RUST_TEST, name))
    return match.group(1)


def rust_strings(body):
    """Return the string literals of a Rust const body, in order."""
    return re.findall(r'"((?:[^"\\]|\\.)*)"', body)


def scanned_extensions(text):
    """Return the extensions the Rust walk reads."""
    return set(rust_strings(const_block(text, "SCANNED_EXTENSIONS")))


def scanned_roots(text):
    """Return the roots the Rust walk starts from."""
    return rust_strings(const_block(text, "SCANNED_ROOTS"))


def carve_outs(text):
    """Return the historical-record paths the Rust walk skips."""
    body = const_block(text, "HISTORICAL_RECORD_CARVE_OUTS")
    return set(re.findall(r'\(\s*"([^"]+)"\s*,', body))


def guarded_roots():
    """Return the roots rules.json hands to this mirror for the #3627 walk."""
    rules = json.loads(RULES.read_text())
    for guard in rules["cargo_skip"]["walk_guards"]:
        if guard["rust"] == RUST_TEST:
            return list(guard["roots"])
    raise AssertionError("rules.json has no walk_guards entry for %s" % RUST_TEST)


def collect(root, extensions, out):
    """Collect the scanned files under `root`, skipping build and VCS trees."""
    if not root.is_dir():
        return
    for entry in sorted(root.iterdir()):
        if entry.is_dir():
            if entry.name not in SKIPPED_DIRS:
                collect(entry, extensions, out)
        elif entry.suffix.lstrip(".") in extensions:
            out.append(entry)


def walk(roots, text):
    """Return (offenders, files with the supported alias, files scanned)."""
    extensions = scanned_extensions(text)
    carved = carve_outs(text)
    retired = retired_alias()
    files = []
    for root in roots:
        collect(REPO / root, extensions, files)
    offenders = []
    supported = 0
    for path in files:
        try:
            body = path.read_text(errors="strict").lower()
        except (OSError, UnicodeDecodeError):
            continue
        if SUPPORTED_ALIAS in body:
            supported += 1
        rel = path.relative_to(REPO).as_posix()
        if retired in body and rel not in carved:
            offenders.append(rel)
    return sorted(offenders), supported, len(files)


class RetiredAliasWalk3627(unittest.TestCase):
    """The absence walk of the Rust test, over the cargo_skip-skippable trees."""

    @classmethod
    def setUpClass(cls):
        cls.text = rust_source()
        cls.roots = guarded_roots()

    def test_guarded_roots_are_roots_of_the_rust_walk(self):
        rust_roots = scanned_roots(self.text)
        for root in self.roots:
            self.assertTrue(
                any(root == r or root.startswith(r + "/") for r in rust_roots),
                "walk_guards root %s is not under a SCANNED_ROOTS entry of %s"
                % (root, RUST_TEST))

    def test_guarded_roots_equal_the_rust_roots(self):
        """Reverse direction (REVIEW-8328-security-r2 F2): no Rust root is unmirrored.

        A root the Rust walk reads but the mirror skips would let a skippable
        file there (a note under tools/ or scripts/) bypass both walks.
        """
        self.assertEqual(sorted(self.roots), sorted(scanned_roots(self.text)),
                         "rules.json walk_guards roots must equal SCANNED_ROOTS of %s" % RUST_TEST)

    def test_carve_outs_are_real_files(self):
        for rel in sorted(carve_outs(self.text)):
            self.assertTrue((REPO / rel).is_file(), "stale carve-out: %s" % rel)

    def test_retired_alias_is_absent_from_the_skippable_trees(self):
        offenders, supported, scanned = walk(self.roots, self.text)
        self.assertGreater(scanned, 100, "the walk read only %d files" % scanned)
        self.assertGreater(
            supported, PRESENCE_FLOOR,
            "presence control: the supported alias is in only %d files" % supported)
        self.assertEqual(
            offenders, [],
            "retired provider token present in current surface(s):\n  "
            + "\n  ".join(offenders))

    def test_walk_flags_a_planted_token(self):
        planted = REPO / ".local-runs" / "walk-3627-planted"
        planted.mkdir(parents=True, exist_ok=True)
        try:
            (planted / "x.md").write_text("text " + retired_alias() + " text")
            files = []
            collect(planted, scanned_extensions(self.text), files)
            self.assertEqual(len(files), 1)
            self.assertIn(retired_alias(), files[0].read_text().lower())
        finally:
            (planted / "x.md").unlink()
            planted.rmdir()


if __name__ == "__main__":
    unittest.main()
