"""Run the census row scanner (#10290) as CI runs it: `--check` passes on the
committed tables and is red, with its exact message, on every tamper."""
from pathlib import Path
import importlib.util
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
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

    def test_an_over_cap_statement_fails_the_scan_10303(self) -> None:
        m = scanner_module()
        (self.root / "src/big.rs").write_text("process" + " x" * m.STMT_CAP + ";\n", encoding="utf-8")
        r = self.check()
        self.assertEqual(r.returncode, EXIT_SCAN)
        self.assertEqual(r.stderr.strip(), "census_rows_10286: scan failed: src/big.rs: "
                         + OVER_CAP.format(n=m.STMT_CAP + 2, cap=m.STMT_CAP))

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


STMT_TABLE = ROOT / "tests/common/census_stmt_parity_10303.json"
STMT_ROWS = 23
MUTANT_TABLE = ROOT / "tests/common/census_stmt_mutants_10303.json"
MUTANT_ROWS = 16
PINS_RS = ROOT / "tests/common/census_pins_10286.rs"
STMT_CAP_RE = re.compile(r"^pub\(crate\) const STMT_CAP: usize = ([0-9_]+);$", re.M)
DIGEST_HEX = 32
LINEAR_TOKENS = 100_000
LINEAR_SECONDS = 20
OVER_CAP = ("line 1: a watched statement of {n} tokens is over STMT_CAP {cap}; "
            "a pin never cuts a statement (#10303)")


def pins(m, text: str) -> list[str]:
    """The site pins of one text with the seed names (each table text binds no alias)."""
    return m.sites_of(m.lex(text), set(m.WATCHED_SEED), set(m.ENV_MOD_SEED | m.ENV_FN_SEED),
                      set(m.ENV_FN_SEED))


class StatementPin10303(unittest.TestCase):
    """#10302, #10303: a pin covers its whole statement, 32 hex digits, the same
    tables the Rust tests in `tests/common/census_stmt_10303.rs` read."""

    def setUp(self) -> None:
        self.m = scanner_module()

    def test_statement_table(self) -> None:
        rows = json.loads(STMT_TABLE.read_text(encoding="utf-8"))
        self.assertEqual(len(rows), STMT_ROWS)
        bad = []
        for i, (text, want) in enumerate(rows):
            t = self.m.lex(text)
            have = [self.m.encode(t, a, b) for a, b in self.m.statements(t)]
            if have != want:
                bad.append(f"row {i} {text!r}: statements {have!r}, want {want!r}")
        self.assertEqual(bad, [])

    def test_mutant_table(self) -> None:
        rows = json.loads(MUTANT_TABLE.read_text(encoding="utf-8"))
        self.assertEqual(len(rows), MUTANT_ROWS)
        bad = []
        for name, want, a, b in rows:
            da, db = pins(self.m, a), pins(self.m, b)
            self.assertTrue(da, name)
            self.assertEqual(len(da), len(db), name)
            verdict = "same" if da == db else "change"
            if verdict != want:
                bad.append(f"{name}: want {want}, the pins {verdict}")
        self.assertEqual(bad, [])

    def test_a_digest_is_32_hex_digits(self) -> None:
        self.assertEqual(self.m.DIGEST_HEX, DIGEST_HEX)
        self.assertEqual(self.m.digest("T", "I1:a"), hashlib.sha256(b"TI1:a").hexdigest()[:DIGEST_HEX])
        for d in pins(self.m, "fn f() { std::process::exit(1); }"):
            self.assertRegex(d, r"^[0-9a-f]{32}$")

    def test_the_cap_is_the_rust_cap(self) -> None:
        found = STMT_CAP_RE.search(PINS_RS.read_text(encoding="utf-8"))
        self.assertIsNotNone(found)
        self.assertEqual(int(found.group(1).replace("_", "")), self.m.STMT_CAP)

    def test_a_statement_over_the_cap_is_refused(self) -> None:
        cap = self.m.STMT_CAP
        at_cap = self.m.lex("process" + " x" * (cap - 2) + ";")
        self.assertEqual(len(at_cap), cap)
        self.assertEqual(len(self.m.sites_of(at_cap, {"process"}, set(), set())), 1)
        over = self.m.lex("process" + " x" * (cap - 1) + ";")
        with self.assertRaises(ValueError) as cm:
            self.m.sites_of(over, {"process"}, set(), set())
        self.assertEqual(str(cm.exception), OVER_CAP.format(n=cap + 1, cap=cap))

    def test_many_statements_in_linear_time(self) -> None:
        unit = "std::process::exit(1);\n"
        reps = LINEAR_TOKENS // len(self.m.lex(unit)) + 1
        t0 = time.monotonic()
        d = pins(self.m, unit * reps)
        self.assertEqual(len(d), reps)
        self.assertLess(time.monotonic() - t0, LINEAR_SECONDS)

    def test_a_long_statement_in_linear_time(self) -> None:
        cap = self.m.STMT_CAP
        # One statement of cap tokens with a site on every other token; the
        # statement is hashed once, not once per site.
        text = "f(" + " process ," * ((cap - 3) // 2) + ");"
        t = self.m.lex(text)
        self.assertLessEqual(len(t), cap)
        t0 = time.monotonic()
        d = self.m.sites_of(t, {"process"}, set(), set())
        self.assertEqual(len(d), (cap - 3) // 2)
        self.assertEqual(len(set(d)), 1)
        self.assertLess(time.monotonic() - t0, LINEAR_SECONDS)


CLOSURE_TABLE = ROOT / "tests/common/census_closure_parity_10304.json"
CLOSURE_ROWS = 25
CHAIN_BYTES = 100_000
CHAIN_SECONDS = 5
RING_HOPS = 64
CHAIN_HOPS = {
    "use": ("a", "use a{i} as a{j};\n"),
    "type": ("T", "type T{j} = T{i};\n"),
    "macro": ("m", "macro_rules! m{j} {{ () => {{ m{i} }} }}\n"),
}


def closure_of(m, text: str, seed: list[str]) -> set[str]:
    return m.closure(m.prepare([("t.rs", m.lex(text))]), frozenset(seed))


class RenameClosure10304(unittest.TestCase):
    """#10304: the rename closure is one worklist over a graph built once; the
    same table the Rust tests in `tests/common/census_closure_10304.rs` read."""

    def setUp(self) -> None:
        self.m = scanner_module()

    def test_closure_table(self) -> None:
        rows = json.loads(CLOSURE_TABLE.read_text(encoding="utf-8"))
        self.assertEqual(len(rows), CLOSURE_ROWS)
        bad = []
        for i, (text, seed, want) in enumerate(rows):
            have = closure_of(self.m, text, seed)
            if have != set(want):
                bad.append(f"row {i} {text!r}: closure {sorted(have)!r}, want {sorted(want)!r}")
        self.assertEqual(bad, [])

    def test_reversed_rename_chains_are_linear(self) -> None:
        for kind, (first, hop) in CHAIN_HOPS.items():
            lines: list[str] = []
            size = 0
            while size < CHAIN_BYTES:
                i = len(lines)
                lines.append(hop.format(i=i, j=i + 1))
                size += len(lines[-1])
            hops = len(lines)
            text = "".join(reversed(lines))
            t0 = time.monotonic()
            got = closure_of(self.m, text, [f"{first}0"])
            dt = time.monotonic() - t0
            self.assertEqual(len(got), hops + 1, kind)
            self.assertIn(f"{first}{hops}", got, kind)
            self.assertLess(dt, CHAIN_SECONDS, f"reversed {kind} chain of {hops} hops took {dt:.1f} s (#10304)")

    def test_the_worklist_pushes_each_node_once(self) -> None:
        rows = json.loads(CLOSURE_TABLE.read_text(encoding="utf-8"))
        ring = "".join(f"use r{i} as r{(i + 1) % RING_HOPS};\n" for i in range(RING_HOPS))
        rows.append([ring, ["r0"], [f"r{i}" for i in range(RING_HOPS)]])
        bad = []
        for i, (text, seed, want) in enumerate(rows):
            g = self.m.RenameGraph(self.m.prepare([("t.rs", self.m.lex(text))]))
            names, pushes = g.walk(frozenset(seed))
            if pushes > g.nodes():
                bad.append(f"row {i}: {pushes} pushes over {g.nodes()} nodes")
            if names != set(want):
                bad.append(f"row {i}: closure {sorted(names)!r}")
        self.assertEqual(bad, [], "#10304 worklist pushes")


INCLUDE_START = "fn f() { std::process::Command::new(\"x\"); }\n"


class IncludeSites10300(unittest.TestCase):
    """#10300: every include and #[path] site of a walked file is resolved; a code
    target is lexed whatever its extension or directory and a site that cannot be
    resolved stops the scan with its exact line (the Rust census gives the same
    lines, `tests/common/census_include_10300.rs`)."""

    def setUp(self) -> None:
        self.m = scanner_module()
        SCRATCH.mkdir(exist_ok=True)
        self._tmp = tempfile.TemporaryDirectory(prefix="census-include-10300-", dir=SCRATCH)
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def tree(self, files: dict[str, str], links: dict[str, str] | None = None) -> None:
        files = {**files, str(CENSUS): FIXTURE[str(CENSUS)]}
        for rel, text in files.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        for rel, to in (links or {}).items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.symlink_to(to)

    def refused(self, want: str) -> None:
        with self.assertRaises(ValueError) as cm:
            self.m.scan(self.root)
        self.assertIn(want, str(cm.exception).splitlines())

    def test_an_include_of_a_non_rs_file_is_lexed(self) -> None:
        self.tree({"src/a.rs": "include!(\"gen.txt\");\n", "src/gen.txt": INCLUDE_START})
        rows, _sites, _totals = self.m.scan(self.root)
        self.assertIn('("src/gen.txt", 2, R_TOK_NAME),', rows)

    def test_a_path_module_in_a_skipped_dir_is_lexed(self) -> None:
        self.tree({"src/a.rs": "#[path = \"../target/m.rs\"]\nmod m;\n", "target/m.rs": INCLUDE_START})
        rows, _sites, _totals = self.m.scan(self.root)
        self.assertIn('("target/m.rs", 2, R_TOK_NAME),', rows)

    def test_a_non_literal_argument_is_refused(self) -> None:
        self.tree({"src/a.rs": "include!(concat!(\"b\", \".rs\"));\n"})
        self.refused("src/a.rs:1: include! with an argument that is not one string literal; "
                     "the census cannot resolve it (#10300)")

    def test_a_target_outside_the_root_is_refused(self) -> None:
        self.tree({"src/a.rs": "const X: &[u8] = include_bytes!(\"../../x\");\n"})
        self.refused("src/a.rs:1: include_bytes! \"../../x\" leaves the repository root (#10300)")

    def test_a_link_target_is_refused(self) -> None:
        self.tree({"src/a.rs": "include!(\"l.rs\");\n", "src/real.txt": INCLUDE_START}, {"src/l.rs": "real.txt"})
        self.refused("src/a.rs:1: include! \"l.rs\" names src/l.rs, a symbolic link or a path through one; "
                     "the census never follows links (#10300)")

    def test_an_include_str_target_is_a_data_candidate(self) -> None:
        self.tree({"src/a.rs": "const X: &str = include_str!(\"d.txt\");\n", "src/d.txt": "data\n"})
        _rows, _sites, totals = self.m.scan(self.root)
        self.assertEqual(totals["include_data"], {("src/a.rs", "include_str!"): (1, "7b2e103513d3575000027cc3cee87521")})


if __name__ == "__main__":
    unittest.main()
