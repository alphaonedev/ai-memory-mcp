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
        self.tree({"src/a.rs": "include!(\"../../x\");\n"})
        self.refused("src/a.rs:1: include! \"../../x\" leaves the repository root (#10300)")

    def test_a_link_target_is_refused(self) -> None:
        self.tree({"src/a.rs": "include!(\"l.rs\");\n", "src/real.txt": INCLUDE_START}, {"src/l.rs": "real.txt"})
        self.refused("src/a.rs:1: include! \"l.rs\" names src/l.rs, a symbolic link or a path through one; "
                     "the census never follows links (#10300)")

    def test_an_include_str_target_is_not_lexed(self) -> None:
        self.tree({"src/a.rs": "const X: &str = include_str!(\"d.txt\");\n", "src/d.txt": INCLUDE_START})
        rows, _sites, _totals = self.m.scan(self.root)
        self.assertNotIn("src/d.txt", rows)

    def test_sites_match_the_parity_table(self) -> None:
        table = json.loads(INCLUDE_TABLE.read_text(encoding="utf-8"))
        self.assertEqual(len(table), INCLUDE_ROWS)
        bad = []
        for i, (text, want) in enumerate(table):
            t = self.m.lex(text)
            got = [[line, form, arg] for _k, form, line, arg in self.m.include_sites(t, self.m.brackets(t))]
            if got != want:
                bad.append(f"row {i}: {text!r} gave {got!r}")
        self.assertEqual(bad, [], "#10300 site table")

    def test_sites_are_linear_on_large_inputs(self) -> None:
        flat = "include!(\"a.rs\");\n" * (INCLUDE_BOUND_BYTES // 18 + 1)
        depth = INCLUDE_BOUND_BYTES // 12
        nested = "#[" + "cfg_attr(a, " * depth + "path = \"p.rs\"" + ")" * depth + "]\nmod m;\n"
        for text, want in ((flat, INCLUDE_BOUND_BYTES // 18 + 1), (nested, 1)):
            self.assertGreaterEqual(len(text), INCLUDE_BOUND_BYTES)
            t0 = time.monotonic()
            t = self.m.lex(text)
            got = self.m.include_sites(t, self.m.brackets(t))
            self.assertLess(time.monotonic() - t0, LINEAR_SECONDS)
            self.assertEqual(len(got), want)


INCLUDE_TABLE = ROOT / "tests/common/census_include_parity_10300.json"
INCLUDE_ROWS = 22
INCLUDE_BOUND_BYTES = 100_000


ASSERT_CMD_TABLE = ROOT / "tests/common/census_assert_cmd_10314.json"
ASSERT_CMD_ROWS = 8
# The assert_cmd start names, written out (never read from either scanner).
ASSERT_CMD_NAMES = frozenset({"cargo_bin", "cargo_bin_cmd"})
RUST_WATCHED_RE = re.compile(r"^const WATCHED: &\[&str\] = &\[\n(.*?)^\];$", re.M | re.S)
RUST_NAME_RE = re.compile(r'^    "([^"\\]+)",$', re.M)


def rust_watched() -> frozenset[str]:
    """The Rust census WATCHED list, read from its source (one list, one name a line)."""
    src = (ROOT / CENSUS).read_text(encoding="utf-8")
    found = RUST_WATCHED_RE.findall(src)
    if len(found) != 1:
        raise AssertionError(f"{CENSUS}: {len(found)} WATCHED lists, want 1")
    body = found[0]
    names = RUST_NAME_RE.findall(body)
    if len(names) != len(body.splitlines()):
        raise AssertionError(f"{CENSUS}: a WATCHED line is not one quoted name")
    return frozenset(names)


class AssertCmd10314(unittest.TestCase):
    """#10314: `cargo_bin` and `cargo_bin_cmd` are watched names on both sides,
    the two watched lists are one list, and the Python token count of each
    row of the table the Rust test `the_assert_cmd_forms_are_start_sites_and_
    watched_tokens_10314` reads is its hand-written count."""

    def setUp(self) -> None:
        self.m = scanner_module()

    def test_watched_seed_is_the_rust_watched_list(self) -> None:
        self.assertEqual(sorted(self.m.WATCHED_SEED ^ rust_watched()), [])

    def test_the_assert_cmd_names_are_watched(self) -> None:
        self.assertEqual(sorted(ASSERT_CMD_NAMES - self.m.WATCHED_SEED), [])

    def test_token_counts_of_the_shared_table(self) -> None:
        rows = json.loads(ASSERT_CMD_TABLE.read_text(encoding="utf-8"))
        self.assertEqual(len(rows), ASSERT_CMD_ROWS)
        bad = []
        for i, (text, tokens, _sites, _lines) in enumerate(rows):
            prepared = self.m.prepare([("src/e.rs", self.m.lex(text))])
            watched = self.m.RenameGraph(prepared).reach(self.m.WATCHED_SEED)
            have = sum(1 for t in self.m.lex(text) if t.kind == self.m.IDENT and t.text in watched)
            if have != tokens:
                bad.append(f"row {i} {text!r}: {have} watched tokens, want {tokens}")
        self.assertEqual(bad, [])


ENV_NAME_TABLE = ROOT / "tests/common/census_env_name_10299.json"
ENV_NAME_ROWS_10299 = 28
ENV_NAME_BOUND_BYTES = 100_000
ENV_NAME_BOUND_ITEMS = 2_500
ENV_NAME_BOUND_SECONDS = 20


class EnvName10299(unittest.TestCase):
    """#10299: an environment-name argument that is a name is a named constant
    only when a `const` or `static` with one string literal binds it and nothing
    else binds it anywhere; the Python count of each row of the table the Rust
    test `an_env_name_is_a_constant_only_when_a_literal_const_binds_it_10299`
    reads is its hand-written count."""

    def setUp(self) -> None:
        self.m = scanner_module()

    def count(self, text: str) -> int:
        self.assertTrue(hasattr(self.m, "env_counts"), "the scanner has no env_counts (#10299)")
        prepared = self.m.prepare([("src/e.rs", self.m.lex(text))])
        env_fns = self.m.RenameGraph(prepared).reach(self.m.ENV_FN_SEED)
        return self.m.env_counts(prepared, env_fns).get("src/e.rs", 0)

    def test_env_counts_of_the_shared_table(self) -> None:
        rows = json.loads(ENV_NAME_TABLE.read_text(encoding="utf-8"))
        self.assertEqual(len(rows), ENV_NAME_ROWS_10299)
        bad = []
        for i, (text, want) in enumerate(rows):
            have = self.count(text)
            if have != want:
                bad.append(f"row {i} {text!r}: {have} env names, want {want}")
        self.assertEqual(bad, [])

    def test_the_bound_name_pass_is_linear_on_a_100k_file(self) -> None:
        n = ENV_NAME_BOUND_ITEMS
        text = "use std::env::set_var;\nconst A7: &str = \"x\";\n"
        text += "".join(f"const C{i}: &str = \"PROPTEST_FORK\";\n" for i in range(n))
        text += "fn f(o: u8) {\n" + "".join(f"    set_var(C{i}, \"1\");\n" for i in range(n))
        text += "    match o {\n" + "".join(f"        A{i} => match o {{ _ => {{}} }}\n" for i in range(n))
        text += "    }\n    set_var(A7, \"1\");\n}\n"
        self.assertGreaterEqual(len(text), ENV_NAME_BOUND_BYTES)
        started = time.monotonic()
        have = self.count(text)
        took = time.monotonic() - started
        self.assertEqual(have, 1)
        self.assertLess(took, ENV_NAME_BOUND_SECONDS)


CONFIG_TABLE = ROOT / "tests/common/census_config_10301.json"
CONFIG_ROWS_10301 = 23
CONFIG_BYTE_ROWS_10301 = 1
CONFIG_BOUND_ENTRIES = 7_000
CONFIG_BOUND_BYTES = 100_000
CONFIG_BOUND_SECONDS = 20
RUST_CARGO = ROOT / "tests/common/census_cargo_10289.rs"
RUST_CRATES_RE = re.compile(r"^pub\(crate\) const WATCHED_CRATES: &\[&str\] =\n\s*&\[([^\]]*)\];$", re.M)
CONFIG_PATCH_LINE = (".cargo/config.toml: patch.crates-io.libc patches the watched crate libc; "
                     "a patched watched crate runs code the census never reads (#10301)")


class CargoConfig10301(unittest.TestCase):
    """#10301: every `.cargo/config.toml` and `.cargo/config` is read; the Python
    lines of each row of the table the Rust test `every_cargo_config_form_is_read_
    or_refused_10301` reads are its hand-written lines, and a config finding fails
    the scan."""

    def setUp(self) -> None:
        self.m = scanner_module()
        self.assertTrue(hasattr(self.m, "config_findings"), "the scanner has no config_findings (#10301)")

    def lines(self, rel: str, data: bytes) -> list[str]:
        return sorted(self.m.config_findings(rel, data)) if self.m.is_config(rel) else []

    def test_config_lines_of_the_shared_table(self) -> None:
        table = json.loads(CONFIG_TABLE.read_text(encoding="utf-8"))
        self.assertEqual(len(table["rows"]), CONFIG_ROWS_10301)
        self.assertEqual(len(table["bytes"]), CONFIG_BYTE_ROWS_10301)
        bad = []
        for i, (rel, text, want) in enumerate(table["rows"]):
            have = self.lines(rel, text.encode("utf-8"))
            if have != want:
                bad.append(f"row {i} {rel} {text!r}: {have}")
        for i, (rel, data, want) in enumerate(table["bytes"]):
            have = self.lines(rel, bytes(data))
            if have != want:
                bad.append(f"byte row {i} {rel} {data!r}: {have}")
        self.assertEqual(bad, [])

    def test_watched_crates_are_the_rust_list(self) -> None:
        found = RUST_CRATES_RE.findall(RUST_CARGO.read_text(encoding="utf-8"))
        self.assertEqual(len(found), 1, "one Rust WATCHED_CRATES list")
        rust = frozenset(re.findall(r'"([^"\\]+)"', found[0]))
        self.assertEqual(sorted(self.m.WATCHED_CRATES ^ rust), [])

    def test_a_large_config_is_read_in_linear_time(self) -> None:
        text = "[alias]\n" + "".join(f'a{i:05} = "test"\n' for i in range(CONFIG_BOUND_ENTRIES))
        text += '[patch.crates-io.libc]\npath = "l"\n'
        self.assertGreater(len(text), CONFIG_BOUND_BYTES)
        started = time.monotonic()
        have = self.lines(".cargo/config.toml", text.encode("utf-8"))
        self.assertLess(time.monotonic() - started, CONFIG_BOUND_SECONDS)
        self.assertEqual(have, [CONFIG_PATCH_LINE])

    def test_a_config_finding_fails_the_scan(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="census-config-10301-", dir=SCRATCH) as tmp:
            root = Path(tmp)
            for rel, text in FIXTURE.items():
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8")
            (root / "tests/common").mkdir(parents=True, exist_ok=True)
            (root / ".cargo").mkdir()
            (root / ".cargo/config.toml").write_text('[patch.crates-io.libc]\npath = "l"\n', encoding="utf-8")
            r = run("--write", "--root", str(root))
            self.assertEqual(r.returncode, EXIT_SCAN)
            self.assertEqual(r.stderr.strip(), "census_rows_10286: scan failed: " + CONFIG_PATCH_LINE)


if __name__ == "__main__":
    unittest.main()
