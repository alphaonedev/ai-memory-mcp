"""Key-dir name mentions in the files the cargo skip set covers (#9730, #9842).

The Rust guard tests/key_dir_bind_guard_9730.rs judges every tracked file that
may spell a key-dir name. A change that touches only a file of the cargo_skip
set (scripts/ci/tests/**, docs/**, any *.md) skips cargo, so a Rust test that
reads such a file never runs on that change (#9842 round 1: the ledger gate
`test_no_read_path_is_in_the_skip_set` and `test_every_walked_file_is_cargo_
relevant_or_mirrored` were red for 20 such paths). The Rust guard therefore
leaves that domain to this module, which the ledger gate (ci.yml job
`build-script-vetting`, `python3 -m unittest discover -s scripts/ci/tests`)
runs on every change.

The judged domain (JUDGED_SUFFIX, JUDGED_PREFIXES) is the same as the Rust
constants PY_JUDGED_SUFFIX and PY_JUDGED_PREFIXES; a test below parses them
from the Rust source and compares. Another test proves the domain covers the
whole cargo_skip set, so a path that skips cargo is always judged here.

Rules, the same as the Rust guard applies to a file it does not compile:
the file is decoded (byte order mark, UTF-16, UTF-8, else Latin-1), every
escape is replaced by the character it stands for once, and the mentions of
the three names are counted left to right without overlap. The count must
equal the row of EXPECTED_ROWS written out below (a file with no row must hold
no mention), and a row that matches no tracked file is a failure.

Names are built from parts so that this file holds no mention itself.
"""

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scripts" / "ci"))

from impact import cargo_skip  # noqa: E402

RUST_GUARD = REPO / "tests" / "key_dir_bind_guard_9730.rs"
GIT_TIMEOUT_S = 120
GUARD = "#9730 guard: "

# The judged domain: the cargo_skip globs `**/*.md`, `docs/**` and
# `scripts/ci/tests/**`, minus a file Rust compiles (the Rust guard scans it).
JUDGED_SUFFIX = ".md"
JUDGED_PREFIXES = ("docs/", "scripts/ci/tests/")
RUST_SUFFIX = ".rs"
SKIP_GLOBS = ("**/*.md", "docs/**", "scripts/ci/tests/**")

# The three names, built from parts.
VAR_NAME = "_".join(("AI", "MEMORY", "KEY", "DIR"))
CONST_NAME = "_".join(("KEY", "DIR", "ENV"))
CALL_NAME = "_".join(("bind", "key", "dir"))
NAMES = (VAR_NAME, CONST_NAME, CALL_NAME)

# Decoding and unescaping limits, the same as the Rust guard.
UTF16LE_BOM = b"\xff\xfe"
UTF16BE_BOM = b"\xfe\xff"
UTF8_BOM = b"\xef\xbb\xbf"
MAX_BRACED_HEX = 6
MAX_OCTAL_DIGITS = 3
MAX_ENTITY_DIGITS = 7
UNICODE_MAX = 0x10FFFF
SURROGATES = range(0xD800, 0xE000)

# The kind of file a row covers.
DOCS = "documentation or a changelog entry that names the variable; it sets nothing"
DATA = "recorded data that names the variable; nothing reads it as configuration"
REVIEW_DATA = "a review record that names the variable; nothing reads it as configuration"
TOOLING = "a script or its test that sets the variable for a process it starts or checks how tests bind it"
REASONS = (DOCS, DATA, REVIEW_DATA, TOOLING)

# Every judged file that holds a mention, its count and its reason. Written
# out, never computed from the files.
EXPECTED_ROWS = (
    ("CHANGELOG.md", 4, DOCS),
    ("changelog.d/3584.fixed.md", 6, DOCS),
    ("changelog.d/7181.fixed.md", 1, DOCS),
    ("changelog.d/7229.fixed.md", 1, DOCS),
    ("docs/ADMIN_GUIDE.md", 2, DOCS),
    ("docs/CLI_REFERENCE.md", 5, DOCS),
    ("docs/a2a-integration.html", 4, DOCS),
    ("docs/a2a-integration.md", 4, DOCS),
    ("docs/agent-skills.md", 1, DOCS),
    ("docs/attestation.md", 5, DOCS),
    ("docs/compliance/evidence/cert-385da3a05/recapture-posture.sh", 3, TOOLING),
    ("docs/compliance/evidence/cert-55/SANITIZATION.md", 1, DOCS),
    ("docs/federation-identity.md", 1, DOCS),
    ("docs/federation.md", 2, DOCS),
    ("docs/forensic-export.md", 1, DOCS),
    ("docs/governance/agent-action-rules.md", 3, DOCS),
    ("docs/internal/v070-feature-inventory.md", 2, DOCS),
    ("docs/production-deployment.md", 1, DOCS),
    ("docs/reference/ARCHITECTURE_REFERENCE.md", 7, DOCS),
    ("docs/reviews/AI-MEMORY-COMPETITIVE-ADVANTAGE-FACET-REGISTER-2026-09-27.md", 8, DOCS),
    ("docs/reviews/US-AGENT-MEMORY-MARKET-3x3-AUDIT-2026-09-27.md", 2, DOCS),
    ("docs/reviews/branch-hygiene-3x7-2026-09-18.tsv", 1, REVIEW_DATA),
    ("docs/reviews/gpt6-astra-20260905-evidence/issues-coverage.csv", 3, REVIEW_DATA),
    ("docs/security/audit-trail.md", 1, DOCS),
    ("docs/signed-events-v4.md", 1, DOCS),
    ("docs/zero-touch-quickstart.md", 1, DOCS),
    ("docs/zero-touch-trust.html", 1, DOCS),
    ("scripts/bench/README.md", 1, DOCS),
    ("scripts/ci/tests/data/certification_scope_8262_pins.json", 1, DATA),
    ("scripts/ci/tests/test_recapture_cert_3607_5038.py", 7, TOOLING),
    ("sdk/python/README.md", 4, DOCS),
    ("sdk/typescript/README.md", 4, DOCS),
)
EXPECTED_ROW_COUNT = 32


def is_judged(path: str) -> bool:
    """True when this module judges `path` (and the Rust guard does not)."""
    if PurePosixPath(path).suffix.lower() == RUST_SUFFIX:
        return False
    return path.endswith(JUDGED_SUFFIX) or path.startswith(JUDGED_PREFIXES)


def decode_text(data: bytes) -> str:
    """UTF-16 by byte order mark or NUL placement, else UTF-8, else Latin-1."""
    if data.startswith(UTF16LE_BOM):
        return utf16(data[len(UTF16LE_BOM):], "utf-16-le")
    if data.startswith(UTF16BE_BOM):
        return utf16(data[len(UTF16BE_BOM):], "utf-16-be")
    if data.startswith(UTF8_BOM):
        return utf8_or_latin1(data[len(UTF8_BOM):])
    pairs = len(data) // 2
    even = data[0::2].count(0)
    odd = data[1::2].count(0)
    if pairs > 0 and odd * 2 >= pairs and even * 4 < pairs:
        return utf16(data, "utf-16-le")
    if pairs > 0 and even * 2 >= pairs and odd * 4 < pairs:
        return utf16(data, "utf-16-be")
    return utf8_or_latin1(data)


def utf16(data: bytes, codec: str) -> str:
    """Decode whole code units; an odd last byte is dropped, a lone half is U+FFFD."""
    return data[: len(data) // 2 * 2].decode(codec, errors="replace")


def utf8_or_latin1(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def digits(text: str, start: int, radix: int, limit: int) -> tuple[int, int]:
    """The value of up to `limit` ASCII digits of `radix` at `start`, and how many."""
    value = 0
    taken = 0
    while taken < limit and start + taken < len(text):
        ch = text[start + taken]
        if not ch.isascii() or not ch.isalnum():
            break
        try:
            digit = int(ch, 36)
        except ValueError:
            break
        if digit >= radix:
            break
        value = value * radix + digit
        taken += 1
    return value, taken


def scalar(value: int) -> str | None:
    """The character of a Unicode scalar value, None for anything else."""
    if value > UNICODE_MAX or value in SURROGATES:
        return None
    return chr(value)


def exact(text: str, at: int, begin: int, radix: int, width: int) -> tuple[str, int] | None:
    value, taken = digits(text, at + begin, radix, width)
    char = scalar(value)
    if taken != width or char is None:
        return None
    return char, begin + width


def escape_at(text: str, at: int) -> tuple[str, int] | None:
    """The character an escape at `at` stands for and its length, else None."""
    first = text[at]
    second = text[at + 1] if at + 1 < len(text) else ""
    if first == "\\":
        if second == "x":
            return exact(text, at, 2, 16, 2)
        if second == "u" and text[at + 2:at + 3] == "{":
            value, taken = digits(text, at + 3, 16, MAX_BRACED_HEX)
            char = scalar(value)
            if taken > 0 and text[at + 3 + taken:at + 4 + taken] == "}" and char is not None:
                return char, 4 + taken
            return None
        if second == "u":
            return exact(text, at, 2, 16, 4)
        if second == "U":
            return exact(text, at, 2, 16, 8)
        if second == "\\":
            return "\\", 2
        if second in tuple("01234567"):
            value, taken = digits(text, at + 1, 8, MAX_OCTAL_DIGITS)
            char = scalar(value)
            return None if char is None else (char, 1 + taken)
        return None
    if first == "&" and second == "#":
        radix, begin = (16, 3) if text[at + 2:at + 3] in ("x", "X") else (10, 2)
        value, taken = digits(text, at + begin, radix, MAX_ENTITY_DIGITS)
        char = scalar(value)
        if taken > 0 and text[at + begin + taken:at + begin + taken + 1] == ";" and char is not None:
            return char, begin + taken + 1
        return None
    if first == "%":
        return exact(text, at, 1, 16, 2)
    return None


def unescape(text: str) -> str:
    """`text` with every escape replaced by the character it stands for, once."""
    out: list[str] = []
    at = 0
    while at < len(text):
        found = escape_at(text, at)
        if found is None:
            out.append(text[at])
            at += 1
        else:
            out.append(found[0])
            at += found[1]
    return "".join(out)


def mention_count(data: bytes) -> int:
    """The mentions of the three names, left to right, without overlap."""
    text = unescape(decode_text(data))
    count = 0
    at = 0
    while at < len(text):
        name = next((n for n in NAMES if text.startswith(n, at)), None)
        if name is None:
            at += 1
        else:
            count += 1
            at += len(name)
    return count


def read_regular(root: Path, name: str) -> bytes | str:
    """The bytes of a tracked regular file, or the finding that it cannot be read."""
    path = root / name
    try:
        if not path.is_symlink() and path.is_file():
            return path.read_bytes()
    except OSError as err:
        return f"{GUARD}{name} cannot be read: {err}"
    try:
        path.lstat()
    except OSError as err:
        return f"{GUARD}{name} cannot be read: {err}"
    return f"{GUARD}{name} is not a regular file; the guard cannot classify it"


def check_tree(root: Path, listing: list[str], rows: dict[str, int]) -> list[str]:
    """The findings of every judged file in `listing` against `rows` (path to count)."""
    out: list[str] = []
    used: set[str] = set()
    for name in sorted(listing):
        if not is_judged(name):
            continue
        data = read_regular(root, name)
        if isinstance(data, str):
            out.append(data)
            continue
        count = mention_count(data)
        if name in rows:
            used.add(name)
            if count != rows[name]:
                out.append(
                    f"{GUARD}{name} holds {count} key-dir name mention(s); its row says {rows[name]}"
                )
        elif count:
            out.append(f"{GUARD}{name} holds {count} key-dir name mention(s) and has no row")
    for name in sorted(rows):
        if name not in used:
            out.append(f"{GUARD}row {name} matches no tracked judged file; remove the row")
    return out


def tracked_files(root: Path) -> list[str]:
    done = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True, timeout=GIT_TIMEOUT_S, check=False,
    )
    if done.returncode != 0:
        raise AssertionError(f"{GUARD}git ls-files failed: {done.returncode}")
    return [n.decode("utf-8") for n in done.stdout.split(b"\0") if n]


def expected_map() -> dict[str, int]:
    return {path: count for path, count, _ in EXPECTED_ROWS}


class TrackedTree(unittest.TestCase):
    """The real tree: every judged file matches its row."""

    def test_judged_files_match_their_rows(self):
        got = check_tree(REPO, tracked_files(REPO), expected_map())
        self.assertEqual(got, [], "\n".join(got))


class Rows(unittest.TestCase):
    """The table itself."""

    def test_row_count_is_pinned(self):
        self.assertEqual(len(EXPECTED_ROWS), EXPECTED_ROW_COUNT)

    def test_every_row_is_judged_here_has_a_mention_and_a_known_reason(self):
        seen: set[str] = set()
        for path, count, reason in EXPECTED_ROWS:
            self.assertTrue(is_judged(path), path)
            self.assertGreater(count, 0, path)
            self.assertIn(reason, REASONS, path)
            self.assertNotIn(path, seen, path)
            seen.add(path)

    def test_rows_have_no_duplicate_path(self):
        paths = [p for p, _, _ in EXPECTED_ROWS]
        self.assertEqual(len(paths), len(set(paths)))


class Domain(unittest.TestCase):
    """The judged domain covers the whole cargo_skip set and matches the Rust guard."""

    def test_skip_globs_are_the_judged_domain(self):
        section = cargo_skip.load_section()
        self.assertEqual(tuple(sorted(section["skip_globs"])), tuple(sorted(SKIP_GLOBS)))

    def test_every_skippable_tracked_path_is_judged_here(self):
        section = cargo_skip.load_section()
        missed = [
            name for name in tracked_files(REPO)
            if cargo_skip.is_skippable(section, name) and not is_judged(name)
        ]
        self.assertEqual(missed, [], f"skippable files no guard judges: {missed}")

    def test_rust_guard_leaves_exactly_this_domain_to_this_module(self):
        text = RUST_GUARD.read_text(encoding="utf-8")
        suffix = re.search(r'const PY_JUDGED_SUFFIX: &str = "([^"]+)";', text)
        prefixes = re.search(r"const PY_JUDGED_PREFIXES: \[&str; \d+\] = \[([^\]]*)\];", text)
        self.assertIsNotNone(suffix, "PY_JUDGED_SUFFIX is missing from the Rust guard")
        self.assertIsNotNone(prefixes, "PY_JUDGED_PREFIXES is missing from the Rust guard")
        self.assertEqual(suffix.group(1), JUDGED_SUFFIX)
        # The Rust constant writes a slash as a hex escape so the cargo skip
        # ledger does not count the guard as a reader of that directory.
        written = tuple(
            re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), item)
            for item in re.findall(r'"([^"]+)"', prefixes.group(1))
        )
        self.assertEqual(written, JUDGED_PREFIXES)
        home = re.search(r'const PY_HOME: &str = "([^"]+)";', text)
        self.assertIsNotNone(home, "PY_HOME is missing from the Rust guard")
        home_path = re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), home.group(1))
        self.assertEqual(home_path, Path(__file__).resolve().relative_to(REPO).as_posix())

    def test_ledger_gate_discovers_this_module(self):
        workflow = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        # The whole-directory run step, alone on its line: a narrower run of one
        # module (`... -p test_x.py`) does not discover this module.
        self.assertRegex(
            workflow,
            re.compile(r"^\s*run: python3 -m unittest discover -s scripts/ci/tests\s*$", re.MULTILINE),
        )
        self.assertRegex(Path(__file__).name, r"^test.*\.py$")
        self.assertEqual(Path(__file__).resolve().parent, REPO / "scripts" / "ci" / "tests")


class Decoding(unittest.TestCase):
    """Every spelling the Rust guard counts is counted here."""

    def forms(self, name: str) -> list[tuple[str, bytes]]:
        first = ord(name[0])
        rest = name[1:]
        return [
            ("plain", name.encode()),
            ("utf8-bom", UTF8_BOM + name.encode()),
            ("utf16le-bom", UTF16LE_BOM + name.encode("utf-16-le")),
            ("utf16be-bom", UTF16BE_BOM + name.encode("utf-16-be")),
            ("utf16le-no-bom", name.encode("utf-16-le")),
            ("utf16be-no-bom", name.encode("utf-16-be")),
            ("hex-x", f"\\x{first:02X}{rest}".encode()),
            ("brace-u", f"\\u{{{first:x}}}{rest}".encode()),
            ("short-u", f"\\u{first:04x}{rest}".encode()),
            ("long-U", f"\\U{first:08x}{rest}".encode()),
            ("octal", f"\\{first:o}{rest}".encode()),
            ("decimal-entity", f"&#{first};{rest}".encode()),
            ("hex-entity", f"&#x{first:x};{rest}".encode()),
            ("percent", f"%{first:02X}{rest}".encode()),
        ]

    def test_every_name_in_every_form_counts_once(self):
        for name in NAMES:
            for label, data in self.forms(name):
                with self.subTest(name=name[:4], form=label):
                    self.assertEqual(mention_count(data), 1)

    def test_latin1_text_counts(self):
        self.assertEqual(mention_count(b"\xe9 " + VAR_NAME.encode() + b" \xff"), 1)

    def test_names_count_left_to_right_without_overlap(self):
        joined = f"{VAR_NAME}_ENV {CONST_NAME} {CALL_NAME}{VAR_NAME}"
        self.assertEqual(mention_count(joined.encode()), 4)

    def test_unescape_runs_once(self):
        doubled = "\\\\x" + f"{ord(VAR_NAME[0]):02X}" + VAR_NAME[1:]
        self.assertEqual(mention_count(doubled.encode()), 0)

    def test_text_without_a_name_counts_zero(self):
        for data in (b"", b"plain text", UTF16LE_BOM, "ключ".encode(), b"\\x41\\u{42}&#67;%44"):
            with self.subTest(data=data[:12]):
                self.assertEqual(mention_count(data), 0)

    def test_a_half_name_counts_zero(self):
        self.assertEqual(mention_count(VAR_NAME[:-1].encode()), 0)
        self.assertEqual(mention_count(CALL_NAME[1:].encode()), 0)

    def test_invalid_escapes_stay_text(self):
        for text in ("\\xZZ", "\\u{110000}", "\\ud800", "&#;", "&#xD800;", "%G0", "\\u{}"):
            with self.subTest(text=text):
                self.assertEqual(unescape(text), text)


class Findings(unittest.TestCase):
    """A fixture tree and the exact findings the checks report (red on a broken check)."""

    def tree(self, files: dict[str, bytes]) -> Path:
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        for name, data in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return root

    def test_new_file_with_a_mention_and_no_row(self):
        files = {"docs/old.md": VAR_NAME.encode(), "docs/new.md": f"uses {CALL_NAME}".encode()}
        got = check_tree(self.tree(files), sorted(files), {"docs/old.md": 1})
        self.assertEqual(got, [f"{GUARD}docs/new.md holds 1 key-dir name mention(s) and has no row"])

    def test_new_mention_in_a_listed_file(self):
        files = {"docs/old.md": f"{VAR_NAME} and {CONST_NAME}".encode()}
        got = check_tree(self.tree(files), sorted(files), {"docs/old.md": 1})
        self.assertEqual(got, [f"{GUARD}docs/old.md holds 2 key-dir name mention(s); its row says 1"])

    def test_row_with_no_file(self):
        files = {"docs/old.md": VAR_NAME.encode()}
        rows = {"docs/old.md": 1, "docs/gone.md": 1}
        got = check_tree(self.tree(files), sorted(files), rows)
        self.assertEqual(got, [f"{GUARD}row docs/gone.md matches no tracked judged file; remove the row"])

    def test_row_whose_file_lost_its_mention(self):
        files = {"docs/old.md": b"nothing here"}
        got = check_tree(self.tree(files), sorted(files), {"docs/old.md": 1})
        self.assertEqual(got, [f"{GUARD}docs/old.md holds 0 key-dir name mention(s); its row says 1"])

    def test_names_outside_the_domain_are_the_rust_guards(self):
        files = {"cfg/a.toml": VAR_NAME.encode(), "src/lib.rs": VAR_NAME.encode(), "a.MD": b""}
        self.assertEqual(check_tree(self.tree(files), sorted(files), {}), [])

    def test_domain_edges(self):
        judged = ["a.md", "x/y/z.md", "docs/a.html", "docs/a", "scripts/ci/tests/a.py", "scripts/ci/tests/data/a.json"]
        left = ["a.MD", "docs", "doc/a.html", "scripts/ci/a.py", "scripts/ci/tests", "docs/a.rs", "a.rs", "a.RS", "x.mdx"]
        self.assertEqual([p for p in judged if not is_judged(p)], [])
        self.assertEqual([p for p in left if is_judged(p)], [])

    def test_escaped_utf16_and_bom_forms_in_a_judged_file(self):
        forms = {
            "docs/a.md": f"\\x{ord(VAR_NAME[0]):02X}{VAR_NAME[1:]}".encode(),
            "docs/b.md": UTF16LE_BOM + VAR_NAME.encode("utf-16-le"),
            "docs/c.md": UTF8_BOM + CALL_NAME.encode(),
        }
        got = check_tree(self.tree(forms), sorted(forms), {})
        self.assertEqual(
            got,
            [f"{GUARD}{name} holds 1 key-dir name mention(s) and has no row" for name in sorted(forms)],
        )

    def test_unreadable_and_non_regular_files_are_findings(self):
        root = self.tree({"docs/real.md": b"x"})
        (root / "docs" / "link.md").symlink_to(root / "docs" / "real.md")
        got = check_tree(root, ["docs/real.md", "docs/link.md", "docs/missing.md"], {})
        self.assertEqual(len(got), 2, got)
        self.assertTrue(got[0].startswith(f"{GUARD}docs/link.md is not a regular file"), got)
        self.assertTrue(got[1].startswith(f"{GUARD}docs/missing.md cannot be read"), got)
        if os.geteuid() != 0:
            locked = root / "docs" / "locked.md"
            locked.write_bytes(VAR_NAME.encode())
            locked.chmod(0)
            self.addCleanup(locked.chmod, 0o600)
            got = check_tree(root, ["docs/locked.md"], {})
            self.assertEqual(len(got), 1, got)
            self.assertTrue(got[0].startswith(f"{GUARD}docs/locked.md cannot be read"), got)

    def test_size_bound(self):
        text = (f"{VAR_NAME}\n" + "line of prose\n" * 10) * 20000
        data = text.encode()
        self.assertGreater(len(data), 100_000)
        self.assertEqual(mention_count(data), 20000)


if __name__ == "__main__":
    unittest.main()
