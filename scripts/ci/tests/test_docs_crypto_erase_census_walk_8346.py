"""Python mirror of the crypto-erase docs census for the cargo_skip trees (#8346).

src/encryption/mod.rs (the `DOCS_CENSUS_*` constants and `docs_census_8315_on`,
about lines 2130-2240, test `docs_describing_erase_list_every_erasable_version_8315`)
runs `git ls-files -- docs` and reads every tracked .md and .html doc. A PR that
touches only docs/** gets cargo_skip=true, so that Rust test never runs on it.
This file runs the SAME census from the Classify job on every PR (rules.json
`cargo_skip.walk_guards`, the pair shape of #3627). The phrases, the dated-record
carve-outs, the erase doc, the erasable version bytes, the file-type filter, the
`git ls-files` folder and the list sizes are parsed from the Rust source (a value
that cannot be parsed fails loudly), so a change to the census moves the mirror.

The Rust comments are stripped ONCE from the whole source (`Census.__init__`) and
every search runs on that stripped text, so a stale commented-out copy of a
declaration or of the listing call can never be read instead of the live one.
Rust block comments nest, so the stripper counts the depth (a stray `*/` fails loudly), and every
parsed constant name and the loop head must occur exactly once in the stripped source.
The WHOLE census loop body (comments stripped, string literals masked, whitespace removed) and the
erasable-bytes expression are pinned against one exact expected text, the `ends_with` filter terms
being the only parsed variable part, so any other change to the Rust census fails loudly and names
the drifted statement.
"""
import json
import os
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

RUST_TOKEN = re.compile(
    r'(?P<raw>(?<![A-Za-z0-9_])b?r(?P<h>#*)".*?"(?P=h))'
    r'|(?P<str>"(?:[^"\\]|\\.)*")'
    r"|(?P<chr>'(?:\\.[^'\n]*|[^'\\\n])')"
    r"|(?P<cmt>//[^\n]*|/\*.*?\*/)",
    re.S,
)


def read(rel):
    """Return the text of a tracked source file."""
    return (REPO / rel).read_text(encoding="utf-8")


RUST_LITERAL = re.compile(
    r'(?P<raw>(?<![A-Za-z0-9_])b?r(?P<h>#*)".*?"(?P=h))'
    r'|(?P<str>"(?:[^"\\]|\\.)*")'
    r"|(?P<chr>'(?:\\.[^'\n]*|[^'\\\n])')",
    re.S,
)
LEX_START = re.compile(r"[\"'/*rb]")


def strip_comments(text):
    """Remove `//` and `/* */` comments (block comments nest); literals stay intact.

    String, raw string and char literals such as `'"'` are skipped whole, so a quote inside one
    never opens a string and a comment marker inside a string is kept. A block comment that never
    closes, or a `*/` outside a comment and a literal, raises AssertionError (never read silently).
    """
    out, pos, end = [], 0, len(text)
    while pos < end:
        found = LEX_START.search(text, pos)
        if found is None:
            out.append(text[pos:])
            break
        out.append(text[pos:found.start()])
        pos = found.start()
        literal = RUST_LITERAL.match(text, pos)
        if literal is not None:
            out.append(literal.group(0))
            pos = literal.end()
        elif text.startswith("//", pos):
            newline = text.find("\n", pos)
            pos = end if newline < 0 else newline
            out.append(" ")
        elif text.startswith("/*", pos):
            depth, scan = 1, pos + 2
            while depth:
                opener, closer = text.find("/*", scan), text.find("*/", scan)
                if closer < 0:
                    raise AssertionError("%s has a block comment that never closes" % RUST_SRC)
                if 0 <= opener < closer:
                    depth, scan = depth + 1, opener + 2
                else:
                    depth, scan = depth - 1, closer + 2
            out.append(" ")
            pos = scan
        elif text.startswith("*/", pos):
            raise AssertionError("%s has a `*/` outside any block comment or literal" % RUST_SRC)
        else:
            out.append(text[pos])
            pos += 1
    return "".join(out)


def mask_literals(text):
    """Replace every string, raw string and char literal by NULs of the same length."""
    return RUST_LITERAL.sub(lambda m: "\0" * len(m.group(0)), text)


def declared_once(masked, pattern, what):
    """Raise unless `pattern` occurs exactly once in the literal-masked, comment-stripped source."""
    count = len(re.findall(pattern, masked))
    if count != 1:
        raise AssertionError("%s must declare %s exactly once in live code, found %d"
                             % (RUST_SRC, what, count))


def strings(body):
    """Return the string literals (plain and raw) of a Rust fragment, in order, comments excluded."""
    found = []
    for m in RUST_TOKEN.finditer(body):
        if m.group("str") is not None:
            found.append(m.group("str")[1:-1])
        elif m.group("raw") is not None:
            found.append(re.fullmatch(r'b?r(#*)"(.*)"\1', m.group("raw"), re.S).group(2))
    return found


def const_body(clean, name):
    """Return the body of `const <name>: ... = ...;` in the comment-stripped Rust source."""
    match = re.search(r"const %s:[^=]*=\s*(.*?);\n" % re.escape(name), clean, re.S)
    if match is None:
        raise AssertionError("%s no longer declares %s" % (RUST_SRC, name))
    return match.group(1)


def const_len(clean, name):
    """Return N from the declared type `const <name>: [&str; N]` (comment-stripped source)."""
    match = re.search(r"const %s:\s*\[&str;\s*(\d+)\s*\]" % re.escape(name), clean)
    if match is None:
        raise AssertionError("%s no longer declares %s as [&str; N]" % (RUST_SRC, name))
    return int(match.group(1))


def string_list(clean, name):
    """Return the string literals of const <name>; fail unless there are exactly N."""
    found = strings(const_body(clean, name))
    declared = const_len(clean, name)
    if len(found) != declared:
        raise AssertionError("%s: %s declares [&str; %d] but %d plain string literals were parsed"
                             % (RUST_SRC, name, declared, len(found)))
    return found


LOOP_HEAD = "for rel in stdout.lines() {"
ENDS_TERM = r'rel\.ends_with\(""\)'
ENDS_SLOT = "<ENDS>"
# The census loop body of docs_census_8315_on, split after every `;`, `{` and `}`, whitespace
# removed, every string literal masked to `""`. The only variable part is the `ends_with` term
# group (ENDS_SLOT), whose literals census_filter parses. The two `if .. { continue; }` skips
# are chunks 1-3 and 6-8.
LOOP_CHUNKS = (
    "if!(" + ENDS_SLOT + ")||DOCS_CENSUS_DATED_RECORDS.iter().any(|dir|rel.starts_with(dir)){",
    "continue;",
    "}",
    'lettext=std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e|panic!(""));',
    "letflat=text.to_lowercase();",
    "if!DOCS_CENSUS_ERASE_PHRASES.iter().any(|phrase|flat.contains(phrase))"
    "||!bytes.iter().any(|byte|flat.contains(byte.as_str())){",
    "continue;",
    "}",
    "census.push(rel.to_string());",
    "letmissing:Vec<&str>=bytes.iter().filter(|byte|!flat.contains(byte.as_str()))"
    ".map(String::as_str).collect();",
    "if!missing.is_empty(){",
    'failures.push(format!("",missing.join("")));',
    "}",
)
# The erasable-bytes expression and the two accumulators, literals kept: the byte format is pinned.
BYTES_PREAMBLE = (
    "letbytes:Vec<String>=CRYPTO_ERASABLE_ENVELOPE_VERSIONS.iter()"
    '.map(|version|format!("0x{version:02x}")).collect();'
    "letmutcensus:Vec<String>=Vec::new();letmutfailures:Vec<String>=Vec::new();"
)


def compact(text):
    """Return `text` with all whitespace removed (rustfmt may wrap the clauses)."""
    return re.sub(r"\s+", "", text)


def census_loop(clean):
    """Return the body of the `for rel in stdout.lines()` census loop (comment-stripped source)."""
    start = clean.find(LOOP_HEAD)
    if start < 0:
        raise AssertionError("%s no longer has the `%s` census loop" % (RUST_SRC, LOOP_HEAD))
    start += len(LOOP_HEAD)
    masked = mask_literals(clean)
    depth = 1
    for pos in range(start, len(masked)):
        depth += {"{": 1, "}": -1}.get(masked[pos], 0)
        if depth == 0:
            return clean[start:pos]
    raise AssertionError("%s census loop has no closing brace" % RUST_SRC)


def loop_chunks(body):
    """Return [(pinned form, shown form)] per statement chunk of the loop body.

    The pinned form has literals masked to `""`; the shown form keeps them, so an error names
    the drifted clause. Boundaries are found on the masked text, so a `;`, `{` or `}` inside a
    literal (raw strings included) never splits a chunk and never reads as code.
    """
    masked = mask_literals(body)
    bounds, begin = [], 0
    for m in re.finditer(r"[;{}]", masked):
        bounds.append((begin, m.end()))
        begin = m.end()
    bounds.append((begin, len(masked)))
    pairs = []
    for lo, hi in bounds:
        shown = compact(body[lo:hi])
        if shown:
            pairs.append((re.sub(r"\0+", '""', compact(masked[lo:hi])), shown))
    return pairs


def census_filter(clean):
    """Pin the whole census loop body and return the `ends_with` suffixes it reads.

    Every statement of the loop must equal LOOP_CHUNKS, the `ends_with` term group aside; any
    other change (an added or tightened condition, a `?` return, a macro skip, another `continue`)
    raises AssertionError naming the first chunk that drifted.
    """
    pairs = loop_chunks(census_loop(clean))
    slot = re.compile(r"if!\((%s(\|\|%s)*)\)\|\|" % (ENDS_TERM, ENDS_TERM))
    pinned = [slot.sub("if!(%s)||" % ENDS_SLOT, form, count=1) for form, _ in pairs]
    for index in range(max(len(pinned), len(LOOP_CHUNKS))):
        want = LOOP_CHUNKS[index] if index < len(LOOP_CHUNKS) else "<end of loop body>"
        got = pinned[index] if index < len(pinned) else "<end of loop body>"
        if got != want:
            shown = pairs[index][1] if index < len(pairs) else "<missing>"
            raise AssertionError("%s census loop statement %d changed, the mirror does not follow it: "
                                 "found %r (expected %r)" % (RUST_SRC, index + 1, shown, want))
    group = re.fullmatch(r"if!\((.*)\)\|\|DOCS_CENSUS_DATED_RECORDS.*", pairs[0][1])
    suffixes = []
    for term in group.group(1).split("||"):
        literal = re.fullmatch(r'rel\.ends_with\("([^"]+)"\)', term)
        if literal is None:
            raise AssertionError('%s census filter term is not `rel.ends_with("<literal>")`: %r'
                                 % (RUST_SRC, term))
        suffixes.append(literal.group(1))
    return tuple(suffixes)


def bytes_preamble(clean):
    """Return the compact text from the census `let bytes` to the census loop head."""
    head = clean.find(LOOP_HEAD)
    start = clean.rfind("let bytes", 0, head)
    if head < 0 or start < 0:
        raise AssertionError("%s census loop is not preceded by `let bytes`" % RUST_SRC)
    return compact(clean[start:head])


def census_folder(clean):
    """Return the folder of the census `git ls-files -- <folder>` call."""
    calls = len(re.findall(r'"ls-files"', clean))
    if calls != 1:
        raise AssertionError('%s must have exactly one `"ls-files"` call site, found %d'
                             % (RUST_SRC, calls))
    match = re.search(r'docs_census_git_on\(\s*root,\s*&\["ls-files",\s*"--",\s*"([^"]+)"\s*\]', clean)
    if match is None:
        raise AssertionError("%s no longer runs `git ls-files -- <folder>` through docs_census_git_on"
                             % RUST_SRC)
    return match.group(1)


def erasable_bytes(clean, scope_clean):
    """Return the `0x..` strings for CRYPTO_ERASABLE_ENVELOPE_VERSIONS (RECORD, SCOPE).

    Also pins the `let bytes` expression of the census (`format!("0x{version:02x}")` over exactly
    that constant, nothing chained) and the two accumulators that precede the loop.
    """
    if bytes_preamble(clean) != BYTES_PREAMBLE:
        raise AssertionError("%s census erasable-bytes expression changed, the mirror does not follow it:"
                             " found %r (expected %r)" % (RUST_SRC, bytes_preamble(clean), BYTES_PREAMBLE))
    match = re.search(r"CRYPTO_ERASABLE_ENVELOPE_VERSIONS: \[u8; \d+\] =\s*\[(.*?)\];", clean, re.S)
    if match is None:
        raise AssertionError("%s no longer declares CRYPTO_ERASABLE_ENVELOPE_VERSIONS" % RUST_SRC)
    names = re.findall(r"[A-Z_]+", match.group(1))
    masked = mask_literals(clean) + "\n" + mask_literals(scope_clean)
    values = {}
    for name in names:
        declared_once(masked, r"\bconst %s: u8 =" % re.escape(name), "const " + name)
    for src in (clean, scope_clean):
        for name, val in re.findall(r"const ([A-Z_]+_ENVELOPE_VERSION): u8 = 0x([0-9a-fA-F]+);", src):
            values[name] = int(val, 16)
    return ["0x%02x" % values[name] for name in names]


def rules_entry():
    """Return the walk_guards entry rules.json hands to this mirror."""
    for guard in json.loads(RULES.read_text(encoding="utf-8"))["cargo_skip"]["walk_guards"]:
        if guard["rust"] == RUST_SRC:
            return guard
    raise AssertionError("rules.json has no walk_guards entry for %s" % RUST_SRC)


class Census:
    """The predicates of docs_census_8315_on, parsed from the comment-stripped Rust source."""

    def __init__(self, text):
        clean = strip_comments(text)
        scope_clean = strip_comments(read(SCOPE_SRC))
        self.clean = clean
        masked = mask_literals(clean)
        declared_once(masked, re.escape(LOOP_HEAD), "the `%s` census loop" % LOOP_HEAD)
        for name in ("DOCS_CENSUS_ERASE_PHRASES", "DOCS_CENSUS_DATED_RECORDS",
                     "DOCS_CENSUS_ERASE_DOC", "CRYPTO_ERASABLE_ENVELOPE_VERSIONS"):
            declared_once(masked, r"\bconst %s:" % name, "const " + name)
        self.phrases = string_list(clean, "DOCS_CENSUS_ERASE_PHRASES")
        self.dated = string_list(clean, "DOCS_CENSUS_DATED_RECORDS")
        self.suffixes = census_filter(clean)
        self.folder = census_folder(clean)
        self.erase_doc = strings(const_body(clean, "DOCS_CENSUS_ERASE_DOC"))[0]
        self.bytes = erasable_bytes(clean, scope_clean)

    def reads(self, rel):
        """True when the Rust census reads `rel` at all (extension, not a dated record)."""
        return rel.endswith(self.suffixes) and not any(rel.startswith(d) for d in self.dated)

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


def git_env():
    """Return the environment without the overrides the Rust census removes."""
    drop = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")
    return {k: v for k, v in os.environ.items() if k not in drop}


def tracked_docs(folder):
    """Return `git ls-files -- <folder>`, as the Rust census does."""
    out = subprocess.run(["git", "ls-files", "--", folder], cwd=str(REPO), check=True,
                         stdout=subprocess.PIPE, encoding="utf-8", env=git_env())
    return out.stdout.splitlines()


class DocsCryptoEraseCensusWalk8346(unittest.TestCase):
    """The docs census of src/encryption/mod.rs, run on every PR."""

    @classmethod
    def setUpClass(cls):
        cls.text = read(RUST_SRC)
        cls.census = Census(cls.text)
        cls.listing = tracked_docs(cls.census.folder)

    def test_census_constants_were_parsed(self):
        self.assertEqual(self.census.erase_doc, "docs/security/crypto-erase.md")
        self.assertEqual(self.census.bytes, ["0x03", "0x05"])
        self.assertGreaterEqual(len(self.census.phrases), 4)
        self.assertEqual(self.census.dated, ["docs/reviews/", "docs/audit/"])
        self.assertEqual(self.census.suffixes, (".md", ".html"))
        self.assertEqual(self.census.folder, "docs")

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
            (root / probe).write_text("Only 0x03 envelopes are crypto-erasable.\n", encoding="utf-8")
            census, failures = self.census.run(root, self.listing + [probe])
            self.assertIn(probe, census)
            self.assertEqual([f for f in failures if not f.startswith(probe)], [])
            self.assertEqual(len(failures), 1, failures)
            self.assertIn("0x05", failures[0])

    def test_mirror_agrees_with_the_rust_fixture(self):
        """Every probe the Rust test plants is rejected; the complete doc is accepted."""
        probes = re.findall(r'"(docs/probe-[a-z]\.md)",\s*"([^"]+)"', self.census.clean)
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

    def mutated(self, old, new):
        """Return the Rust source with `old` replaced by `new` (the replace must hit)."""
        self.assertIn(old, self.text)
        return self.text.replace(old, new, 1)

    def test_filter_rejects_a_non_literal_term(self):
        text = self.mutated('rel.ends_with(".html")',
                            'rel.ends_with(".html") || rel.ends_with(DOCS_EXTRA_EXT)')
        with self.assertRaisesRegex(AssertionError, "DOCS_EXTRA_EXT"):
            Census(text)

    def test_filter_rejects_an_added_exclusion_clause(self):
        text = self.mutated('rel.ends_with(".html"))', 'rel.ends_with(".html")) && !rel.contains("drafts")')
        with self.assertRaisesRegex(AssertionError, "drafts"):
            Census(text)

    def test_filter_rejects_a_trailing_skip_clause_8355(self):
        """A clause added AFTER the dated-record test must raise, naming the clause."""
        text = self.mutated(".any(|dir| rel.starts_with(dir))",
                            '.any(|dir| rel.starts_with(dir))\n                || rel.contains("drafts")')
        with self.assertRaisesRegex(AssertionError, r'rel\.contains\("drafts"\)'):
            Census(text)

    def test_loop_rejects_a_separate_skip_statement(self):
        text = self.mutated("let text = std::fs::read_to_string(root.join(rel))",
                            'if rel.contains("sketch") { continue; }\n'
                            "            let text = std::fs::read_to_string(root.join(rel))")
        with self.assertRaisesRegex(AssertionError, "sketch"):
            Census(text)

    def test_commented_out_literal_does_not_count(self):
        first = strings(const_body(self.census.clean, "DOCS_CENSUS_ERASE_PHRASES"))[0]
        text = self.mutated('"%s"' % first, 'SOME_CONST, // "%s"' % first)
        with self.assertRaisesRegex(AssertionError,
                                    r"declares \[&str; \d+\] but \d+ plain string literals"):
            Census(text)
        self.assertEqual(strings('"a//b", /* "x" */ "c" // "d"'), ["a//b", "c"])

    def test_second_ls_files_call_is_rejected(self):
        text = self.text + '\nfn extra() { docs_census_git_on(root, &["ls-files", "--", "other"], None); }\n'
        with self.assertRaisesRegex(AssertionError, "exactly one"):
            Census(text)

    def test_stale_commented_listing_call_is_not_read(self):
        """An old call with folder `doc` commented above the live `docs` call must not win."""
        # These anchors are exact Rust texts: a rustfmt rewrap or a fifth phrase breaks this test at assertIn, loudly and never silently.
        live = 'let listing = docs_census_git_on(root, &["ls-files", "--", "docs"], path)'
        text = self.mutated(live, '// ' + live.replace('"docs"', '"doc"') + "\n        " + live)
        self.assertIn('"doc"]', text)
        self.assertEqual(Census(text).folder, "docs")

    def test_stale_commented_declaration_is_not_read(self):
        """An old phrase-list declaration (five stale phrases) above the live one must not win."""
        # These anchors are exact Rust texts: a rustfmt rewrap or a fifth phrase breaks this test at assertIn, loudly and never silently.
        live = "const DOCS_CENSUS_ERASE_PHRASES: [&str; 4] = ["
        stale = ('// const DOCS_CENSUS_ERASE_PHRASES: [&str; 5] = '
                 '["old one", "old two", "old three", "old four", "old five"];\n    ')
        text = self.mutated(live, stale + live)
        census = Census(text)
        self.assertEqual(census.phrases, self.census.phrases)
        self.assertNotIn("old one", census.phrases)
        self.assertEqual(Census(self.mutated(live, "/* " + stale + "*/ " + live)).phrases,
                         self.census.phrases)

    def test_stripper_knows_char_quote_and_raw_strings(self):
        quote = "let q = '\"'; // c1 \"\nlet s = \"x\"; // c2\n"
        out = strip_comments(quote)
        self.assertNotIn("c1", out)
        self.assertNotIn("c2", out)
        self.assertIn("let s = \"x\";", out)
        raw = 'let r = r#"a " // b"#; // c3\nlet t = r"d // e"; // c4\n'
        out = strip_comments(raw)
        self.assertIn('r#"a " // b"#', out)
        self.assertIn('r"d // e"', out)
        self.assertNotIn("c3", out)
        self.assertNotIn("c4", out)
        self.assertEqual(strings('r#"a " b"#, "c", r"d"'), ['a " b', "c", "d"])
        self.assertEqual(strip_comments("fn f<'a>(x: &'a str) {} // gone").count("gone"), 0)

    def test_ls_files_count_is_one_before_and_after_stripping(self):
        self.assertEqual(len(re.findall(r'"ls-files"', self.text)), 1)
        self.assertEqual(len(re.findall(r'"ls-files"', self.census.clean)), 1)

    def test_loop_rejects_a_tightened_failure_condition(self):
        """`|| !flat.contains("crypto-erase.md")` appended to the missing-bytes test must raise."""
        text = self.mutated("if !missing.is_empty() {",
                            'if !missing.is_empty() || !flat.contains("crypto-erase.md") {')
        with self.assertRaisesRegex(AssertionError, r'crypto-erase\.md'):
            Census(text)

    def test_loop_rejects_a_tightened_phrase_clause(self):
        text = self.mutated("|| !bytes.iter().any(|byte| flat.contains(byte.as_str()))",
                            '|| !bytes.iter().any(|byte| flat.contains(byte.as_str()))\n'
                            '                || flat.contains("draft-only")')
        with self.assertRaisesRegex(AssertionError, r'draft-only'):
            Census(text)

    def census_bytes_expression(self):
        """Return the start offset of the census `let bytes` statement in the Rust source."""
        start = self.text.rfind("let bytes", 0, self.text.find(LOOP_HEAD))
        self.assertGreater(start, 0)
        return start

    def test_bytes_expression_rejects_an_extra_chained_byte(self):
        start = self.census_bytes_expression()
        end = self.text.index(".collect();", start)
        text = self.text[:end] + '\n            .chain(std::iter::once("0x07".to_string()))' + self.text[end:]
        with self.assertRaisesRegex(AssertionError, r"erasable-bytes expression.*0x07"):
            Census(text)

    def test_bytes_expression_rejects_another_byte_format(self):
        start = self.census_bytes_expression()
        end = self.text.index('"0x{version:02x}"', start)
        text = self.text[:end] + '"0x{version:02X}"' + self.text[end + len('"0x{version:02x}"'):]
        with self.assertRaisesRegex(AssertionError, r"erasable-bytes expression.*02X"):
            Census(text)

    def test_loop_rejects_a_changed_lowercase_step(self):
        for flat in ('text.to_lowercase().replace("-", " ")', "text.to_uppercase()", "text.clone()"):
            with self.subTest(flat=flat):
                text = self.mutated("let flat = text.to_lowercase();", "let flat = %s;" % flat)
                with self.assertRaisesRegex(AssertionError, r"letflat=text\."):
                    Census(text)

    def test_loop_rejects_a_question_mark_early_return(self):
        text = self.mutated('.unwrap_or_else(|e| panic!("{rel}: read: {e}"));', "?;")
        with self.assertRaisesRegex(AssertionError, r"read_to_string\(root\.join\(rel\)\)\?;"):
            Census(text)

    def test_loop_rejects_a_skip_done_through_a_macro(self):
        text = self.mutated("let text = std::fs::read_to_string(root.join(rel))",
                            'skip_unless!(rel.contains("sketch"));\n'
                            "            let text = std::fs::read_to_string(root.join(rel))")
        with self.assertRaisesRegex(AssertionError, r'skip_unless!\(rel\.contains\("sketch"\)\)'):
            Census(text)

    def test_loop_ignores_a_continue_inside_a_raw_string(self):
        """Clause and body matching run on the literal-masked body: a raw string is not code."""
        text = self.mutated('panic!("{rel}: read: {e}")',
                            'panic!(r#"{rel}: read: {e} if x { continue; } for rel in stdout.lines() {"#)')
        self.assertEqual(Census(text).suffixes, self.census.suffixes)

    def test_nested_block_comment_hides_a_stale_declaration(self):
        """A stale phrase list inside `/* /* */ */` above the live declaration must not win."""
        live = "const DOCS_CENSUS_ERASE_PHRASES: [&str; 4] = ["
        stale = 'const DOCS_CENSUS_ERASE_PHRASES: [&str; 2] = ["old one", "old two"];'
        text = self.mutated(live, "/* outer /* inner */ " + stale + " */\n    " + live)
        census = Census(text)
        self.assertEqual(census.phrases, self.census.phrases)
        self.assertNotIn("old one", census.phrases)
        self.assertEqual(strip_comments("a /* x /* y */ z */ b"), "a   b")

    def test_unbalanced_block_comment_markers_fail_loudly(self):
        with self.assertRaisesRegex(AssertionError, r"outside any block comment"):
            Census(self.text + "\nfn stray() {} */\n")
        with self.assertRaisesRegex(AssertionError, r"never closes"):
            Census(self.text + "\n/* /* closed once */\n")
        self.assertEqual(strip_comments('let s = "a */ b"; // c */'), 'let s = "a */ b";  ')

    def test_duplicate_declaration_under_cfg_any_is_rejected(self):
        """`#[cfg(any())]` removes a copy from the build; a second declaration must still raise."""
        live = "const DOCS_CENSUS_ERASE_PHRASES: [&str; 4] = ["
        stale = '#[cfg(any())]\n    const DOCS_CENSUS_ERASE_PHRASES: [&str; 1] = ["old one"];\n    '
        with self.assertRaisesRegex(AssertionError, r"const DOCS_CENSUS_ERASE_PHRASES exactly once"):
            Census(self.mutated(live, stale + live))
        with self.assertRaisesRegex(AssertionError, r"census loop exactly once"):
            Census(self.text + "\n#[cfg(any())]\nfn dup() { for rel in stdout.lines() { } }\n")

    def test_every_parsed_name_is_declared_once_in_live_code(self):
        masked = mask_literals(self.census.clean)
        for name in ("DOCS_CENSUS_ERASE_PHRASES", "DOCS_CENSUS_DATED_RECORDS",
                     "DOCS_CENSUS_ERASE_DOC", "CRYPTO_ERASABLE_ENVELOPE_VERSIONS"):
            self.assertEqual(len(re.findall(r"\bconst %s:" % name, masked)), 1, name)
        self.assertEqual(masked.count(LOOP_HEAD), 1)

    def test_rules_json_carries_the_walk_guard_entry(self):
        entry = rules_entry()
        self.assertEqual(entry["roots"], ["docs"])
        self.assertEqual(entry["roots"], [self.census.folder],
                         "rules.json roots must equal the folder the Rust census lists")
        self.assertEqual(entry["guard"], "scripts/ci/tests/test_docs_crypto_erase_census_walk_8346.py")
        self.assertTrue((REPO / entry["guard"]).is_file())


if __name__ == "__main__":
    unittest.main()
