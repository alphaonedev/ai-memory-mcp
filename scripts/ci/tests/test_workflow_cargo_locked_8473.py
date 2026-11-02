#!/usr/bin/env python3
"""Workflow lint (#8473 item 6, round 2): every cargo invocation that resolves
dependencies in a `run:` block, or in a shell script a `run:` block names,
carries --locked, and `cargo update` never appears, so CI builds the reviewed
Cargo.lock or fails.

Shapes covered: compound lines (`;`, `&&`, `||`, `|`, `$( )`), the body of
`bash -c` / `sh -c`, global options between `cargo` and the verb, the aliases
b and t, tree and metadata, and the cargo-fuzz and cargo-cyclonedx
subcommands. cargo-fuzz 0.13.2 and cargo-cyclonedx 0.5.9 have no --locked
option, so those two are satisfied by a `cargo metadata --locked` earlier in the
SAME run block (or the same script file); a metadata call in another run block
does not count. Python scripts that build a `["cargo", ...]` argument list are
checked for "--locked" in the same list.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only (workflows are read as text).
"""
import re
import shlex
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WORKFLOWS = REPO / ".github" / "workflows"
LOCKED_VERBS = ("build", "b", "test", "t", "clippy", "check", "run", "doc", "bench",
                "llvm-cov", "nextest", "fetch", "tree", "metadata")
SATISFIED_BY_METADATA = ("fuzz", "cyclonedx")
ALL_VERBS = LOCKED_VERBS + SATISFIED_BY_METADATA + ("update",)
SKIP_WORDS = ("if", "then", "elif", "else", "while", "until", "do", "!", "time", "exec",
              "command", "env", "sudo")
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
RUN_KEY_RE = re.compile(r"^(\s*)(?:-\s+)?run:\s*(.*)$")
SCRIPT_REF_RE = re.compile(r"(?<![\w./-])((?:\./)?scripts/[\w./-]+\.(?:sh|py))")
PY_LIST_RE = re.compile(r"\[\s*[\"']cargo[\"']\s*,([^\]]*)\]")
MIN_SITES_WORKFLOWS = 40
MIN_SITES_SCRIPTS = 2


def run_blocks(text):
    """Return one [(lineno, line), ...] list per `run:` value."""
    lines = text.splitlines()
    blocks, i = [], 0
    while i < len(lines):
        m = RUN_KEY_RE.match(lines[i])
        if not m:
            i += 1
            continue
        indent, rest = len(m.group(1)), m.group(2).strip()
        if rest and not re.match(r"^[|>][-+]?\d*$", rest):
            blocks.append([(i + 1, rest)])
            i += 1
            continue
        i += 1
        block = []
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
            block.append((i + 1, lines[i]))
            i += 1
        blocks.append(block)
    return blocks


def logical_lines(block):
    """Join backslash continuations: [(first_lineno, text)]."""
    out, cur, first = [], "", None
    for no, raw in block:
        line = raw.rstrip()
        if first is None:
            first = no
        if line.endswith("\\"):
            cur += line[:-1] + " "
            continue
        out.append((first, cur + line))
        cur, first = "", None
    if cur:
        out.append((first, cur))
    return out


def split_commands(line):
    """Split a shell line at unquoted ;, &&, ||, |, ( ), backtick and $( )."""
    parts, cur, quote, i = [], [], None, 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < len(line):
                cur.append(ch + line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            elif ch == "$" and quote == '"' and line[i + 1:i + 2] == "(":
                parts.append("".join(cur))
                cur, i = [], i + 2
                continue
            cur.append(ch)
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch == "\\" and i + 1 < len(line):
            cur.append(ch + line[i + 1])
            i += 2
            continue
        elif ch in ";|()`" or (ch == "&" and line[i + 1:i + 2] == "&"):
            parts.append("".join(cur))
            cur = []
            if line[i:i + 2] in ("&&", "||"):
                i += 1
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def words(command):
    """Tokenise one command, dropping trailing comments; fall back to split()."""
    try:
        lex = shlex.shlex(command, posix=True)
        lex.whitespace_split = True
        lex.commenters = "#"
        return list(lex)
    except ValueError:
        return command.split()


def scan_command(command, state, no, sites):
    """Record the cargo calls in one command; recurse into bash -c / sh -c bodies."""
    toks = words(command)
    while toks and (toks[0] in SKIP_WORDS or ASSIGN_RE.match(toks[0])):
        toks = toks[1:]
    if toks and toks[0] == "nice":
        toks = toks[1:]
        while toks and toks[0].startswith("-"):
            toks = toks[2:] if toks[0] == "-n" else toks[1:]
    if not toks or toks[0] in ("echo", "printf"):
        return
    if toks[0] in ("bash", "sh") and "-c" in toks:
        idx = toks.index("-c")
        if idx + 1 < len(toks):
            scan_line(toks[idx + 1], state, no, sites)
        return
    if toks[0] != "cargo":
        return
    i, global_locked = 1, False
    if i < len(toks) and toks[i].startswith("+"):
        i += 1
    while i < len(toks) and toks[i].startswith("-"):
        global_locked = global_locked or toks[i] == "--locked"
        i += 1
    if i >= len(toks) or toks[i] not in ALL_VERBS:
        return
    verb = toks[i]
    args = toks[i + 1:]
    if "--" in args:
        args = args[:args.index("--")]
    locked = global_locked or "--locked" in args
    if verb == "metadata" and locked:
        state["metadata_locked"] = True
    if verb in SATISFIED_BY_METADATA:
        ok = bool(state["metadata_locked"])
    elif verb == "update":
        ok = False
    else:
        ok = locked
    sites.append((no, verb, ok, command[:100]))


def scan_line(line, state, no, sites):
    for command in split_commands(line):
        scan_command(command, state, no, sites)


def find_sites_in_blocks(blocks):
    """Return [(lineno, verb, ok, command)] for command-position cargo calls."""
    sites = []
    for block in blocks:
        state = {"metadata_locked": False}
        for no, line in logical_lines(block):
            if line.strip().startswith("#"):
                continue
            scan_line(line, state, no, sites)
    return sites


def find_sites(workflow_text):
    return find_sites_in_blocks(run_blocks(workflow_text))


def find_script_sites(script_text, python=False):
    """Shell script: the whole file is one block. Python: `["cargo", ...]` argument lists only
    (docstrings and comments in a .py file are prose, not commands)."""
    sites = []
    if not python:
        sites = find_sites_in_blocks([[(n + 1, ln) for n, ln in enumerate(script_text.splitlines())]])
    for n, ln in enumerate(script_text.splitlines(), 1):
        m = PY_LIST_RE.search(ln)
        if not m:
            continue
        items = re.findall(r"[\"']([^\"']*)[\"']", m.group(1))
        verb = next((x for x in items if not x.startswith("-") and not x.startswith("+")), None)
        if verb in LOCKED_VERBS or verb == "update":
            sites.append((n, verb, verb != "update" and "--locked" in items, ln.strip()[:100]))
    return sites


def referenced_scripts(workflow_text):
    """Existing repo scripts that a run block names, as sorted repo-relative paths."""
    found = set()
    for block in run_blocks(workflow_text):
        for _, line in block:
            for m in SCRIPT_REF_RE.finditer(line):
                rel = m.group(1)[2:] if m.group(1).startswith("./") else m.group(1)
                if (REPO / rel).is_file():
                    found.add(rel)
    return sorted(found)


def describe(name, sites):
    bad = []
    for no, verb, ok, line in sites:
        if ok:
            continue
        if verb == "update":
            bad.append("%s:%d cargo update must not run in CI: %s" % (name, no, line))
        elif verb in SATISFIED_BY_METADATA:
            bad.append("%s:%d cargo %s has no cargo metadata --locked before it in the same block: %s"
                       % (name, no, verb, line))
        else:
            bad.append("%s:%d cargo %s without --locked: %s" % (name, no, verb, line))
    return bad


def scan_repo():
    """Return (workflow_sites_seen, script_sites_seen, problems) for the working tree."""
    problems, seen_wf, seen_sc, scripts = [], 0, 0, set()
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        text = wf.read_text()
        sites = find_sites(text)
        seen_wf += len(sites)
        problems += describe(wf.name, sites)
        scripts.update(referenced_scripts(text))
    for rel in sorted(scripts):
        sites = find_script_sites((REPO / rel).read_text(), python=rel.endswith(".py"))
        seen_sc += len(sites)
        problems += describe(rel, sites)
    return seen_wf, seen_sc, problems


class WorkflowCargoLocked(unittest.TestCase):
    def test_every_cargo_invocation_is_locked_and_none_updates(self):
        seen_wf, seen_sc, bad = scan_repo()
        self.assertGreaterEqual(seen_wf, MIN_SITES_WORKFLOWS,
                                "the scanner found too few workflow cargo invocations to be trusted")
        self.assertGreaterEqual(seen_sc, MIN_SITES_SCRIPTS,
                                "the scanner found too few script cargo invocations to be trusted")
        self.assertEqual(bad, [], "%d site(s):\n%s" % (len(bad), "\n".join(bad)))

    def test_the_named_scripts_are_scanned(self):
        scripts = set()
        for wf in WORKFLOWS.glob("*.yml"):
            scripts.update(referenced_scripts(wf.read_text()))
        self.assertIn("scripts/check-bootstrap-cert-gate.sh", scripts)
        sites = find_script_sites((REPO / "scripts/check-bootstrap-cert-gate.sh").read_text())
        self.assertGreaterEqual(len([s for s in sites if s[1] == "build"]), 2)
        self.assertTrue(all(s[2] for s in sites), sites)

    def test_build_index_metadata_call_is_locked(self):
        sites = find_script_sites((REPO / "scripts/ci/impact/build_index.py").read_text(), python=True)
        self.assertEqual([(s[1], s[2]) for s in sites], [("metadata", True)])


def wf(*run_lines):
    body = "".join("          %s\n" % ln for ln in run_lines)
    return "jobs:\n  a:\n    steps:\n      - run: |\n" + body


def shape(*run_lines):
    return [(v, ok) for _, v, ok, _ in find_sites(wf(*run_lines))]


class ScannerShapes(unittest.TestCase):
    def test_original_shapes(self):
        text = (
            "jobs:\n  a:\n    steps:\n"
            "      - run: cargo test --lib\n"
            "      - run: |\n"
            "          echo \"cargo build is quoted\"\n"
            "          cargo build \\\n            --release --locked\n"
            "          cargo clippy --all-targets -- -D warnings && cargo update\n"
            "          # cargo check in a comment\n"
        )
        got = [(v, ok) for _, v, ok, _ in find_sites(text)]
        self.assertEqual(got, [("test", False), ("build", True), ("clippy", False), ("update", False)])

    def test_compound_lines_are_split(self):
        self.assertEqual(shape("cargo build --locked && cargo test"),
                         [("build", True), ("test", False)])
        self.assertEqual(shape("cargo build --locked; cargo check"),
                         [("build", True), ("check", False)])
        self.assertEqual(shape("cargo build --locked || cargo test --locked"),
                         [("build", True), ("test", True)])
        self.assertEqual(shape("cargo metadata --locked | cargo test"),
                         [("metadata", True), ("test", False)])
        self.assertEqual(shape("x=$(cargo metadata --format-version 1)"), [("metadata", False)])
        self.assertEqual(shape("echo \"$(cargo test)\""), [])

    def test_echo_and_comments_are_skipped(self):
        self.assertEqual(shape("echo cargo test", "printf 'cargo build'", "# cargo check"), [])
        self.assertEqual(shape("cargo test --locked # cargo build"), [("test", True)])

    def test_shell_wrapper_bodies_are_scanned(self):
        self.assertEqual(shape("bash -c \"cargo test\""), [("test", False)])
        self.assertEqual(shape("bash -c 'cargo test --locked'"), [("test", True)])
        self.assertEqual(shape("sh -c \"cargo build --locked && cargo check\""),
                         [("build", True), ("check", False)])
        self.assertEqual(shape("bash -euo pipefail -c 'cargo run'"), [("run", False)])

    def test_global_options_do_not_hide_the_verb(self):
        self.assertEqual(shape("cargo -q build"), [("build", False)])
        self.assertEqual(shape("cargo --quiet --color=always test --locked"), [("test", True)])
        self.assertEqual(shape("cargo +nightly -q check"), [("check", False)])
        self.assertEqual(shape("cargo --locked build"), [("build", True)])

    def test_aliases_tree_and_metadata_need_locked(self):
        self.assertEqual(shape("cargo b"), [("b", False)])
        self.assertEqual(shape("cargo t --locked"), [("t", True)])
        self.assertEqual(shape("cargo tree -i openssl-sys"), [("tree", False)])
        self.assertEqual(shape("cargo tree --locked -i openssl-sys"), [("tree", True)])
        self.assertEqual(shape("cargo metadata --format-version 1"), [("metadata", False)])

    def test_multiline_conditional_cargo_tree(self):
        got = shape("if cargo tree \\", "  -e normal \\", "  -i openssl-sys >/dev/null 2>&1; then", "  echo bad", "fi")
        self.assertEqual(got, [("tree", False)])
        got = shape("if cargo tree --locked \\", "  -i openssl-sys >/dev/null 2>&1; then", "  echo bad", "fi")
        self.assertEqual(got, [("tree", True)])

    def test_fuzz_and_cyclonedx_need_a_locked_metadata_call_in_the_same_block(self):
        self.assertEqual(shape("cd fuzz", "cargo fuzz run fuzz_validate -- -max_len=512"),
                         [("fuzz", False)])
        self.assertEqual(shape("cargo metadata --locked --format-version 1 >/dev/null",
                               "cd fuzz", "cargo fuzz run fuzz_validate -- -max_len=512"),
                         [("metadata", True), ("fuzz", True)])
        self.assertEqual(shape("cargo cyclonedx --format json"), [("cyclonedx", False)])
        self.assertEqual(shape("cargo metadata --locked --format-version 1 >/dev/null",
                               "cargo cyclonedx --format json"),
                         [("metadata", True), ("cyclonedx", True)])
        self.assertEqual(shape("cargo metadata --format-version 1 >/dev/null",
                               "cargo cyclonedx --format json"),
                         [("metadata", False), ("cyclonedx", False)])

    def test_a_metadata_call_in_another_run_block_does_not_count(self):
        text = ("jobs:\n  a:\n    steps:\n"
                "      - run: cargo metadata --locked --format-version 1 >/dev/null\n"
                "      - run: cargo fuzz run fuzz_validate\n")
        self.assertEqual([(v, ok) for _, v, ok, _ in find_sites(text)],
                         [("metadata", True), ("fuzz", False)])

    def test_locked_after_double_dash_is_a_program_argument(self):
        self.assertEqual(shape("cargo run -- --locked"), [("run", False)])

    def test_script_text_shell_and_python_shapes(self):
        sh = "set -e\ncargo build --quiet --bin x \\\n  --target-dir t || exit 3\ncargo test --locked\n"
        self.assertEqual([(s[1], s[2]) for s in find_script_sites(sh)], [("build", False), ("test", True)])
        py = 'cmd = ["cargo", "metadata", "--format-version", "1"] + extra\n'
        self.assertEqual([(x[1], x[2]) for x in find_script_sites(py, python=True)], [("metadata", False)])
        py = 'cmd = ["cargo", "metadata", "--locked", "--format-version", "1"] + extra\n'
        self.assertEqual([(x[1], x[2]) for x in find_script_sites(py, python=True)], [("metadata", True)])
        prose = '"""Runs cargo metadata --format-version 1 for the report."""\n'
        self.assertEqual(find_script_sites(prose, python=True), [])

    def test_script_references_come_from_run_blocks_only(self):
        text = ("# scripts/check-x.sh in a comment-free key\njobs:\n  a:\n    steps:\n"
                "      - run: bash scripts/check-bootstrap-cert-gate.sh\n"
                "      - name: scripts/check-no-such-file.sh\n")
        self.assertEqual(referenced_scripts(text), ["scripts/check-bootstrap-cert-gate.sh"])


if __name__ == "__main__":
    unittest.main()
