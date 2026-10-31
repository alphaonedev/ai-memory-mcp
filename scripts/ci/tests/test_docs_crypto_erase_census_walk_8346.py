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
Two Rust bodies are pinned statement by statement (comments stripped, whitespace removed, string
literals kept): the WHOLE body of `docs_census_8315_on` (the repository and toplevel checks, the
`ls-files` listing and its asserts, `stdout`, `bytes`, the accumulators, the loop and the final
`Ok(..)`) and the WHOLE body of the `#[test]` fn that asserts on the census, plus the `#[test]`
attribute directly above it. The `ends_with` filter terms and the `ls-files` folder are the only
parsed variable parts. Any other change in those two bodies (an extra or shadowing statement, a
changed assert, a rewritten `stdout`) raises AssertionError naming the drifted statement.
Everything else is read by a value parser: the phrase, dated-record and erase-doc constants, and
the whole `CRYPTO_ERASABLE_ENVELOPE_VERSIONS` array (`[u8; N]`, N equal to the element count, every
element a known `*_ENVELOPE_VERSION` constant). Parsed string literals are unescaped, and a
backslash the decoder does not know raises. Code outside those bodies is not pinned.
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
    A `*/*` is a star followed by a comment opener (`a*/*b*/c` is `a * c` in Rust), so it is not stray.
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
        elif text.startswith("*/", pos) and not text.startswith("*/*", pos):
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


ESCAPE = re.compile(r"\\(?:x([0-7][0-9a-fA-F])|u\{([0-9a-fA-F_]{1,13})\}|([nrt0\\'\"])|\n[ \t\r\n]*)")
SIMPLE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", "'": "'", '"': '"'}


def unescape(literal):
    """Decode the escapes of a plain Rust string literal body; any other backslash raises."""
    def decode(m):
        if m.group(1) is not None:
            return chr(int(m.group(1), 16))
        if m.group(2) is not None:
            return chr(int(m.group(2).replace("_", ""), 16))
        if m.group(3) is not None:
            return SIMPLE_ESCAPES[m.group(3)]
        return ""
    if "\\" in ESCAPE.sub("", literal):
        raise AssertionError("%s has a string literal with an escape the mirror cannot decode: %r"
                             % (RUST_SRC, literal))
    return ESCAPE.sub(decode, literal)


def strings(body):
    """Return the string literals (plain and raw) of a Rust fragment, in order, comments excluded.

    Plain literals are decoded (an `x2d` hex escape, a `u{5f}` escape, the simple escapes, a backslash-newline
    continuation), so the mirror holds the Rust value, not its spelling; a raw string is taken as
    written, and a backslash the decoder does not know raises AssertionError.
    """
    found = []
    for m in RUST_TOKEN.finditer(body):
        if m.group("str") is not None:
            found.append(unescape(m.group("str")[1:-1]))
        elif m.group("raw") is not None:
            found.append(re.fullmatch(r'b?r(#*)"(.*)"\1', m.group("raw"), re.S).group(2))
    return found


def const_body(clean, name):
    """Return the body of `const <name>: ... = ...;` in the comment-stripped Rust source."""
    match = re.search(r"const %s\s*:[^=]*=\s*(.*?);\n" % re.escape(name), clean, re.S)
    if match is None:
        raise AssertionError("%s no longer declares %s" % (RUST_SRC, name))
    return match.group(1)


def const_len(clean, name):
    """Return N from the declared type `const <name>: [&str; N]` (comment-stripped source)."""
    match = re.search(r"const %s\s*:\s*\[&str;\s*(\d+)\s*\]" % re.escape(name), clean)
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
CENSUS_FN = "docs_census_8315_on"
TEST_FN = "docs_describing_erase_list_every_erasable_version_8315"
ENDS_TERM = r'rel\.ends_with\("[^"]+"\)'
ENDS_SLOT = "<ENDS>"
FOLDER_SLOT = "<FOLDER>"
# The WHOLE body of docs_census_8315_on, split after every `;`, `{` and `}` (boundaries found on the
# literal-masked text), whitespace removed, string literals kept (a changed message or path literal
# is a drift too). The only variable parts are the `ends_with` term group (ENDS_SLOT) and the
# `git ls-files` folder (FOLDER_SLOT), both parsed from the source. Every other statement, an extra
# push, a rewritten `stdout`, a shadowing `let` or a changed `Ok(..)` raises AssertionError.
CENSUS_FN_CHUNKS = (
    'if!root.join(".git").exists(){',
    'returnErr(docs_census_skip(ci,DOCS_CENSUS_NO_DOT_GIT));',
    '}',
    'lettoplevel=matchdocs_census_git_on(root,&["rev-parse","--show-toplevel"],path){',
    'Ok(out)ifout.status.success()=>{',
    'String::from_utf8_lossy(&out.stdout).trim().to_string()}',
    'Ok(_)=>returnErr(docs_census_skip(ci,DOCS_CENSUS_TOPLEVEL_FAILED)),Err(e)=>{',
    'returnErr(docs_census_skip(ci,&format!("{DOCS_CENSUS_GIT_NOT_RUN}:{e}"),));',
    '}',
    '}',
    ';',
    'match(std::fs::canonicalize(&toplevel),std::fs::canonicalize(root),){',
    '(Ok(top),Ok(here))iftop==here=>{',
    '}',
    '_=>returnErr(docs_census_skip(ci,DOCS_CENSUS_FOREIGN_TOPLEVEL)),}',
    'assert!(root.join(DOCS_CENSUS_ERASE_DOC).is_file(),'
    '"insideagitcheckoutthecensusmustreach{DOCS_CENSUS_ERASE_DOC},'
    'butitismissingornotafile");',
    'letlisting=docs_census_git_on(root,&["ls-files","--",<FOLDER>],path)'
    '.expect("run`gitls-files--<FOLDER>`");',
    'assert!(listing.status.success(),"`gitls-files--<FOLDER>`failed:{}",'
    'String::from_utf8_lossy(&listing.stderr));',
    'letstdout=String::from_utf8_lossy(&listing.stdout);',
    'letbytes:Vec<String>=CRYPTO_ERASABLE_ENVELOPE_VERSIONS.iter()'
    '.map(|version|format!("0x{version:02x}")).collect();',
    'letmutcensus:Vec<String>=Vec::new();',
    'letmutfailures:Vec<String>=Vec::new();',
    'forrelinstdout.lines(){',
    'if!(<ENDS>)||DOCS_CENSUS_DATED_RECORDS.iter().any(|dir|rel.starts_with(dir)){',
    'continue;',
    '}',
    'lettext=std::fs::read_to_string(root.join(rel))'
    '.unwrap_or_else(|e|panic!("{rel}:read:{e}"));',
    'letflat=text.to_lowercase();',
    'if!DOCS_CENSUS_ERASE_PHRASES.iter().any(|phrase|flat.contains(phrase))'
    '||!bytes.iter().any(|byte|flat.contains(byte.as_str())){',
    'continue;',
    '}',
    'census.push(rel.to_string());',
    'letmissing:Vec<&str>=bytes.iter().filter(|byte|!flat.contains(byte.as_str()))'
    '.map(String::as_str).collect();',
    'if!missing.is_empty(){',
    'failures.push(format!("{rel}:describescryptoerasebutdoesnotlist{}",missing.join(",")'
    '));',
    '}',
    '}',
    'Ok(DocsCensus{',
    'census,failures}',
    ')',
)
# The whole body of the #[test] that asserts on the census (`found.census` / `found.failures`).
TEST_FN_CHUNKS = (
    'letroot=std::path::Path::new(env!("CARGO_MANIFEST_DIR"));',
    'letfound=matchdocs_census_8315(root){',
    'Ok(found)=>found,Err(reason)=>{',
    'eprintln!("skipped:{reason}");',
    'return;',
    '}',
    '}',
    ';',
    'letbytes:Vec<String>=CRYPTO_ERASABLE_ENVELOPE_VERSIONS.iter()'
    '.map(|version|format!("0x{version:02x}")).collect();',
    'assert!(found.census.iter().any(|rel|rel==DOCS_CENSUS_ERASE_DOC),'
    '"thecensusmustreach{DOCS_CENSUS_ERASE_DOC};itfound{:?}",found.census);',
    'assert!(found.failures.is_empty(),'
    '"#8315:everyerase-describingdocmustlisteverybyteof\\CRYPTO_ERASABLE_ENVELOPE_VERSIONS({})'
    ';census{:?}:\\n{}",bytes.join(","),found.census,found.failures.join("\\n"));',
)


def compact(text):
    """Return `text` with all whitespace removed (rustfmt may wrap the clauses)."""
    return re.sub(r"\s+", "", text)


def fn_body(clean, name):
    """Return (text before the fn, body between its braces) of `fn <name>` in the stripped source."""
    masked = mask_literals(clean)
    declared_once(masked, r"\bfn %s\(" % name, "fn " + name)
    found = re.search(r"\bfn %s\(" % name, masked)
    start = masked.index("{", found.end())
    depth = 0
    for pos in range(start, len(masked)):
        depth += {"{": 1, "}": -1}.get(masked[pos], 0)
        if depth == 0:
            return clean[:found.start()], clean[start + 1:pos]
    raise AssertionError("%s fn %s has no closing brace" % (RUST_SRC, name))


def chunks(body):
    """Return the compact statement chunks of a Rust fragment, split at `;`, `{` and `}`.

    Boundaries are found on the literal-masked text, so a `;`, `{` or `}` inside a literal (raw
    strings included) never splits a chunk and never reads as code.
    """
    masked = mask_literals(body)
    out, begin = [], 0
    for m in re.finditer(r"[;{}]", masked):
        out.append(compact(body[begin:m.end()]))
        begin = m.end()
    out.append(compact(body[begin:]))
    return [chunk for chunk in out if chunk]


def pin_chunks(label, got, want):
    """Raise AssertionError naming the first chunk of `got` that differs from `want`."""
    for index in range(max(len(got), len(want))):
        have = got[index] if index < len(got) else "<end of body>"
        need = want[index] if index < len(want) else "<end of body>"
        if have != need:
            raise AssertionError("%s %s statement %d changed, the mirror does not follow it: "
                                 "found %r (expected %r)" % (RUST_SRC, label, index + 1, have, need))


def slotted(chunk, folder):
    """Return `chunk` with the parsed variable parts (the folder, the ends_with terms) slotted."""
    chunk = re.sub(r'("ls-files","--",)"[^"]+"', r"\1" + FOLDER_SLOT, chunk)
    chunk = chunk.replace("ls-files--" + folder, "ls-files--" + FOLDER_SLOT)
    return re.sub(r"if!\((%s(\|\|%s)*)\)\|\|" % (ENDS_TERM, ENDS_TERM),
                  "if!(%s)||" % ENDS_SLOT, chunk, count=1)


def census_filter(clean, folder):
    """Pin the whole docs_census_8315_on body and return the `ends_with` suffixes it reads."""
    _, body = fn_body(clean, CENSUS_FN)
    got = chunks(body)
    pin_chunks(CENSUS_FN, [slotted(chunk, folder) for chunk in got], CENSUS_FN_CHUNKS)
    first = got[next(i for i, want in enumerate(CENSUS_FN_CHUNKS) if ENDS_SLOT in want)]
    group = re.fullmatch(r"if!\((.*)\)\|\|DOCS_CENSUS_DATED_RECORDS.*", first)
    return tuple(strings(term)[0] for term in group.group(1).split("||"))


def pin_test(clean, folder):
    """Pin the #[test] that asserts on the census: the attribute and the whole body."""
    before, body = fn_body(clean, TEST_FN)
    if not before.rstrip().endswith("#[test]"):
        raise AssertionError("%s fn %s is no longer directly under `#[test]`" % (RUST_SRC, TEST_FN))
    pin_chunks(TEST_FN, [slotted(chunk, folder) for chunk in chunks(body)], TEST_FN_CHUNKS)


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

    The census `let bytes` expression is pinned with the rest of docs_census_8315_on. Here the whole
    array is parsed: `[u8; N]`, every element, N equal to the element count, and every element a
    constant name declared once as `const NAME: u8 = 0x..;` (a numeric literal such as `0x07`, an
    expression or an unknown name raises AssertionError instead of being dropped).
    """
    match = re.search(r"CRYPTO_ERASABLE_ENVELOPE_VERSIONS\s*:\s*\[u8;\s*(\d+)\s*\]\s*=\s*\[(.*?)\];",
                      clean, re.S)
    if match is None:
        raise AssertionError("%s no longer declares CRYPTO_ERASABLE_ENVELOPE_VERSIONS as [u8; N]"
                             % RUST_SRC)
    elements = [compact(part) for part in match.group(2).split(",")]
    if elements and elements[-1] == "":
        elements.pop()
    if len(elements) != int(match.group(1)) or "" in elements:
        raise AssertionError("%s: CRYPTO_ERASABLE_ENVELOPE_VERSIONS declares [u8; %s] but %d elements "
                             "were parsed: %r" % (RUST_SRC, match.group(1), len(elements), elements))
    masked = mask_literals(clean) + "\n" + mask_literals(scope_clean)
    values = {}
    for src in (clean, scope_clean):
        for name, val in re.findall(r"const ([A-Z_]+_ENVELOPE_VERSION)\s*:\s*u8\s*=\s*0x([0-9a-fA-F]+);",
                                    src):
            values[name] = int(val, 16)
    for element in elements:
        if element not in values:
            raise AssertionError("%s: CRYPTO_ERASABLE_ENVELOPE_VERSIONS element %r is not a known "
                                 "`*_ENVELOPE_VERSION` constant" % (RUST_SRC, element))
        declared_once(masked, r"\bconst %s\s*:\s*u8\s*=" % re.escape(element), "const " + element)
    return ["0x%02x" % values[element] for element in elements]


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
            declared_once(masked, r"\bconst %s\s*:" % name, "const " + name)
        self.phrases = string_list(clean, "DOCS_CENSUS_ERASE_PHRASES")
        self.dated = string_list(clean, "DOCS_CENSUS_DATED_RECORDS")
        self.folder = census_folder(clean)
        self.suffixes = census_filter(clean, self.folder)
        pin_test(clean, self.folder)
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
        self.assertIn(old, self.text, "mutation anchor %r drifted out of the Rust source" % old)
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
        with self.assertRaisesRegex(AssertionError, r"statement \d+ changed.*0x07"):
            Census(text)

    def test_bytes_expression_rejects_another_byte_format(self):
        start = self.census_bytes_expression()
        end = self.text.index('"0x{version:02x}"', start)
        text = self.text[:end] + '"0x{version:02X}"' + self.text[end + len('"0x{version:02x}"'):]
        with self.assertRaisesRegex(AssertionError, r"statement \d+ changed.*02X"):
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

    def test_chunks_ignore_a_continue_inside_a_raw_string(self):
        """Chunk bounds and the fn lookup run on the literal-masked text: a raw string is not code."""
        raw = 'panic!(r#"if x { continue; } for rel in stdout.lines() {"#);'
        self.assertEqual(chunks("a { " + raw + " }"), ["a{", compact(raw), "}"])
        text = self.text + '\nfn x() { let r = r#"fn docs_census_8315_on( {"#; }\n'
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
            self.assertEqual(len(re.findall(r"\bconst %s\s*:" % name, masked)), 1, name)
        self.assertEqual(masked.count(LOOP_HEAD), 1)

    def test_function_rejects_an_extra_failure_after_the_loop(self):
        text = self.mutated("        Ok(DocsCensus { census, failures })",
                            '        if census.len() < 4 {\n            failures.push("few docs".to_string());\n'
                            "        }\n        Ok(DocsCensus { census, failures })")
        with self.assertRaisesRegex(AssertionError, r"census\.len\(\)<4"):
            Census(text)

    def test_function_rejects_a_rewritten_stdout(self):
        old = "let stdout = String::from_utf8_lossy(&listing.stdout);"
        text = self.mutated(old, old[:-1] + '.replace("docs/reviews/", "docs/kept/");')
        with self.assertRaisesRegex(AssertionError, r"docs/reviews/"):
            Census(text)

    def test_function_rejects_an_extra_listed_file(self):
        old = "let stdout = String::from_utf8_lossy(&listing.stdout);"
        text = self.mutated(old, old + '\n        let stdout = format!("{stdout}\\nREADME.md");')
        with self.assertRaisesRegex(AssertionError, r"README\.md"):
            Census(text)

    def test_function_rejects_a_shadowing_let(self):
        for old, new, shown in (
                ("let mut census: Vec<String> = Vec::new();",
                 "let mut census: Vec<String> = Vec::new();\n        let mut census: Vec<String> = vec![];",
                 r"census:Vec<String>=vec!\[\]"),
                ("let flat = text.to_lowercase();",
                 'let flat = text.to_lowercase();\n            let flat = flat.replace("-", " ");',
                 r"letflat=flat\.replace"),
        ):
            with self.subTest(shown=shown):
                with self.assertRaisesRegex(AssertionError, shown):
                    Census(self.mutated(old, new))

    def test_function_rejects_a_changed_early_statement(self):
        for old, new, shown in (
                ('root.join(".git").exists()', 'root.join(".gitx").exists()', r"\.gitx"),
                ("DOCS_CENSUS_FOREIGN_TOPLEVEL)),\n        }",
                 "DOCS_CENSUS_FOREIGN_TOPLEVEL)),\n        }\n        let _ = 0;", r"let_=0"),
                ("listing.status.success(),", "!listing.status.success(),", r"!listing\.status"),
        ):
            with self.subTest(shown=shown):
                with self.assertRaisesRegex(AssertionError, shown):
                    Census(self.mutated(old, new))

    def test_rust_test_rejects_a_stricter_assertion(self):
        text = self.mutated("            found.failures.is_empty(),\n",
                            "            found.failures.is_empty() && found.census.len() >= 3,\n")
        with self.assertRaisesRegex(AssertionError, r"census\.len\(\)>=3"):
            Census(text)

    def test_rust_test_rejects_an_ignore_attribute_and_a_dropped_assert(self):
        text = self.mutated("    #[test]\n    fn docs_describing_erase_list_every_erasable_version_8315",
                            "    #[test]\n    #[ignore]\n    fn docs_describing_erase_list_every_erasable_version_8315")
        with self.assertRaisesRegex(AssertionError, r"directly under"):
            Census(text)
        text = self.mutated('found.census.iter().any(|rel| rel == DOCS_CENSUS_ERASE_DOC)', "true")
        with self.assertRaisesRegex(AssertionError, r"assert!\(true"):
            Census(text)

    def test_erasable_bytes_rejects_a_literal_or_unknown_element(self):
        old = "[RECORD_ENVELOPE_VERSION, SCOPE_ENVELOPE_VERSION];"
        for new, shown in (("[RECORD_ENVELOPE_VERSION, 0x07];", r"element '0x07' is not a known"),
                           ("[RECORD_ENVELOPE_VERSION, OTHER_ENVELOPE_VERSION];", r"OTHER_ENVELOPE_VERSION"),
                           ("[RECORD_ENVELOPE_VERSION, SCOPE_ENVELOPE_VERSION, 0x07];", r"\[u8; 2\] but 3"),
                           ("[RECORD_ENVELOPE_VERSION];", r"\[u8; 2\] but 1")):
            with self.subTest(new=new):
                with self.assertRaisesRegex(AssertionError, shown):
                    Census(self.mutated(old, new))
        with self.assertRaisesRegex(AssertionError, r"\[u8; 3\] but 2"):
            Census(self.mutated("CRYPTO_ERASABLE_ENVELOPE_VERSIONS: [u8; 2]",
                                "CRYPTO_ERASABLE_ENVELOPE_VERSIONS: [u8; 3]"))
        self.assertEqual(Census(self.mutated(old, "[RECORD_ENVELOPE_VERSION, SCOPE_ENVELOPE_VERSION,];")).bytes,
                         ["0x03", "0x05"])

    def test_escapes_in_parsed_literals_are_decoded(self):
        self.assertEqual(strings(r'"crypto\x2deras", "a\u{5f}b", "c\\d", "e\"f", "g\
                                   h"'), ["crypto-eras", "a_b", "c\\d", 'e"f', "gh"])
        with self.assertRaisesRegex(AssertionError, r"escape the mirror cannot decode"):
            strings(r'"a\qb"')
        phrase = self.mutated('"crypto-eras",', r'"crypto\x2deras",')
        self.assertEqual(Census(phrase).phrases, self.census.phrases)
        suffix = self.mutated('rel.ends_with(".md")', r'rel.ends_with(".m\x64")')
        self.assertEqual(Census(suffix).suffixes, self.census.suffixes)

    def test_star_slash_star_is_not_a_stray_closer(self):
        self.assertEqual(strip_comments("a*/*b*/c"), "a* c")
        self.assertEqual(Census(self.text + "\nfn f() { let _ = a*/*b*/c; }\n").suffixes,
                         self.census.suffixes)

    def test_spaced_const_colon_is_read_and_counted(self):
        live = "const DOCS_CENSUS_ERASE_PHRASES: [&str; 4] = ["
        spaced = "const DOCS_CENSUS_ERASE_PHRASES : [&str; 4] = ["
        self.assertEqual(Census(self.mutated(live, spaced)).phrases, self.census.phrases)
        stale = '#[cfg(any())]\n    const DOCS_CENSUS_ERASE_PHRASES: [&str; 1] = ["old one"];\n    '
        with self.assertRaisesRegex(AssertionError, r"const DOCS_CENSUS_ERASE_PHRASES exactly once"):
            Census(self.mutated(live, stale + spaced))

    def test_mutation_anchor_that_drifts_names_itself(self):
        with self.assertRaisesRegex(AssertionError, r"mutation anchor.*not-in-the-source"):
            self.mutated("not-in-the-source", "x")

    def test_rules_json_carries_the_walk_guard_entry(self):
        entry = rules_entry()
        self.assertEqual(entry["roots"], ["docs"])
        self.assertEqual(entry["roots"], [self.census.folder],
                         "rules.json roots must equal the folder the Rust census lists")
        self.assertEqual(entry["guard"], "scripts/ci/tests/test_docs_crypto_erase_census_walk_8346.py")
        self.assertTrue((REPO / entry["guard"]).is_file())


if __name__ == "__main__":
    unittest.main()
