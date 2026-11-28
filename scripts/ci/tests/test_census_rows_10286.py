"""Run the census row scanner (#10290) as CI runs it: `--check` passes on the
committed tables and is red, with its exact message, on every tamper."""
from pathlib import Path
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCANNER = ROOT / "scripts/ci/census_rows_10286.py"
ROWS = Path("tests/common/census_rows_10176.rs")
SITES = Path("tests/common/census_sites_10286.rs")
SCRATCH = ROOT / ".local-runs"
OK_LINE = "census_rows_10286: 2 tables match a fresh scan"
REWRITE = "; run scripts/ci/census_rows_10286.py --write and review the change"
EXIT_OK = 0
EXIT_DIFF = 1
EXIT_SCAN = 2
FIXTURE = {
    "src/run.rs": "fn f() {\n    let _ = std::process::Command::new(\"sh\");\n}\n",
    "src/clean.rs": "fn g() -> u8 {\n    1\n}\n",
    # The scanner reads which files start a process from the census START_ROWS.
    "tests/process_start_census_10176.rs":
        "// START_ROWS_BEGIN\nconst START_ROWS: &[(&str, usize)] = &[(\"src/run.rs\", 1)];\n// START_ROWS_END\n",
}
CENSUS = Path("tests/process_start_census_10176.rs")


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", str(SCANNER), *args],
        capture_output=True, text=True, check=False, timeout=600,
    )


class CensusRows10286(unittest.TestCase):
    def setUp(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        self._tmp = tempfile.TemporaryDirectory(prefix="census-rows-10286-", dir=SCRATCH)
        self.root = Path(self._tmp.name)
        for rel, text in FIXTURE.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        (self.root / "tests/common").mkdir(parents=True, exist_ok=True)
        w = run("--write", "--root", str(self.root))
        self.assertEqual(w.returncode, EXIT_OK, w.stderr)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def check(self) -> subprocess.CompletedProcess[str]:
        return run("--check", "--root", str(self.root))

    def test_the_committed_tables_match_a_fresh_scan_10290(self) -> None:
        r = run("--check")
        self.assertEqual((r.returncode, r.stdout.strip(), r.stderr), (EXIT_OK, OK_LINE, ""))

    def test_a_fresh_write_checks_clean_10290(self) -> None:
        r = self.check()
        self.assertEqual((r.returncode, r.stdout.strip()), (EXIT_OK, OK_LINE))
        sites = (self.root / SITES).read_text(encoding="utf-8")
        self.assertIn('("src/run.rs", &[', sites)
        self.assertNotIn("src/clean.rs", sites)

    def test_a_changed_count_is_red_10290(self) -> None:
        p = self.root / ROWS
        text = p.read_text(encoding="utf-8")
        # Two watched tokens: `process` and `Command`.
        old = '("src/run.rs", 2, R_TOK_START),'
        self.assertIn(old, text)
        p.write_text(text.replace(old, '("src/run.rs", 3, R_TOK_START),'), encoding="utf-8")
        r = self.check()
        self.assertEqual(r.returncode, EXIT_DIFF)
        self.assertEqual(
            r.stderr.strip(),
            f"census_rows_10286: {ROWS} differs from a fresh scan at line "
            f"{text.splitlines().index('    ' + old) + 1}: committed "
            f"{chr(39)}(\"src/run.rs\", 3, R_TOK_START),{chr(39)}, scan {old!r}{REWRITE}",
        )

    def test_a_changed_site_digest_is_red_10290(self) -> None:
        p = self.root / SITES
        lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
        i = next(n for n, x in enumerate(lines) if x.startswith('        "'))
        digest = lines[i].strip()[1:-2]
        swapped = ("0" if digest[0] != "0" else "1") + digest[1:]
        lines[i] = f'        "{swapped}",\n'
        p.write_text("".join(lines), encoding="utf-8")
        r = self.check()
        self.assertEqual(r.returncode, EXIT_DIFF)
        self.assertEqual(
            r.stderr.strip(),
            f"census_rows_10286: {SITES} differs from a fresh scan at line {i + 1}: committed "
            f"{repr(chr(34) + swapped + chr(34) + ',')}, scan {repr(chr(34) + digest + chr(34) + ',')}{REWRITE}",
        )

    def test_an_edit_next_to_a_watched_token_is_red_10290(self) -> None:
        src = self.root / "src/run.rs"
        src.write_text(src.read_text(encoding="utf-8").replace("::new(", "::other("), encoding="utf-8")
        r = self.check()
        self.assertEqual(r.returncode, EXIT_DIFF)
        self.assertTrue(r.stderr.startswith(f"census_rows_10286: {SITES} differs from a fresh scan at line "),
                        r.stderr)

    def test_a_new_watched_file_is_red_10290(self) -> None:
        (self.root / "src/clean.rs").write_text("use std::process;\n", encoding="utf-8")
        r = self.check()
        self.assertEqual(r.returncode, EXIT_DIFF)
        self.assertEqual(r.stderr.count("differs from a fresh scan"), 2, r.stderr)

    def test_a_missing_table_is_red_10290(self) -> None:
        (self.root / SITES).unlink()
        r = self.check()
        self.assertEqual(r.returncode, EXIT_DIFF)
        self.assertTrue(r.stderr.startswith(f"census_rows_10286: {SITES}: unreadable ("), r.stderr)

    def test_a_table_that_is_not_utf8_fails_the_scan_10290(self) -> None:
        # The tables are .rs files in the walked tree, so the scan reads them first.
        (self.root / ROWS).write_bytes(b"\xff\xfe")
        r = self.check()
        self.assertEqual(r.returncode, EXIT_SCAN)
        self.assertTrue(r.stderr.startswith("census_rows_10286: scan failed: "), r.stderr)

    def test_a_source_that_is_not_utf8_fails_the_scan_10290(self) -> None:
        (self.root / "src/bad.rs").write_bytes(b"fn f() {}\xff\n")
        r = self.check()
        self.assertEqual(r.returncode, EXIT_SCAN)
        self.assertTrue(r.stderr.startswith("census_rows_10286: scan failed: "), r.stderr)

    def test_a_census_without_start_rows_fails_the_scan_10290(self) -> None:
        (self.root / CENSUS).write_text("const START_ROWS: &[(&str, usize)] = &[];\n", encoding="utf-8")
        r = self.check()
        self.assertEqual(r.returncode, EXIT_SCAN)
        self.assertEqual(r.stderr.strip(), "census_rows_10286: scan failed: substring not found")

    def test_check_and_write_are_required_and_exclusive_10290(self) -> None:
        for args in ((), ("--check", "--write")):
            r = run(*args)
            self.assertEqual(r.returncode, EXIT_SCAN, args)
            self.assertIn("usage: census_rows_10286.py", r.stderr)


LEX_TABLE = ROOT / "tests/common/census_lex_parity_10305.json"
LEX_ROWS = 36


def scanner_module():
    """The scanner loaded as a module (its CLI runs only under __main__)."""
    spec = importlib.util.spec_from_file_location("census_rows_10286", SCANNER)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {SCANNER}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class LexParity10305(unittest.TestCase):
    """#10305: the rows the Rust test `lexer_parity_table_10305` reads, with
    the same hand-written expected token strings, lexed by the Python side."""

    def test_lexer_parity_table(self) -> None:
        rows = json.loads(LEX_TABLE.read_text(encoding="utf-8"))
        self.assertEqual(len(rows), LEX_ROWS)
        m = scanner_module()
        bad = []
        for i, (text, want) in enumerate(rows):
            toks = m.lex(text)
            have = m.encode(toks, 0, len(toks) - 1)
            if have != want:
                bad.append(f"row {i} {text!r}: lexed {have!r}, want {want!r}")
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
