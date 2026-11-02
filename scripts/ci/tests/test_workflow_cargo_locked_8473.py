#!/usr/bin/env python3
"""Workflow lint (#8473 item 6, round 2): every cargo invocation that resolves
dependencies in a `run:` block, or in a shell script a `run:` block names,
carries --locked, and `cargo update` never appears, so CI builds the reviewed
Cargo.lock or fails.

Shapes covered: compound lines (`;`, `&&`, `||`, `|`, `$( )`), the body of
`bash -c` / `sh -c`, wrapper prefixes (`timeout <dur>`, `nice [-n N]`, `xargs`,
`nohup`, `stdbuf`), a cargo path ending in `/cargo`, global options between
`cargo` and the verb, the aliases b and t, tree, metadata, install and miri,
`generate-lockfile` (like `update`: never allowed), and the cargo-fuzz and
cargo-cyclonedx subcommands. cargo invoked through a variable (`"$CARGO" build`)
cannot be verified and is flagged. cargo-fuzz 0.13.2 and cargo-cyclonedx 0.5.9
have no --locked option, so those two are satisfied by a `cargo metadata
--locked` earlier in the SAME run block (or the same script file) for the SAME
manifest directory (from --manifest-path or the last `cd`); a metadata call in
another run block, in another directory, or followed by `|| true` / `|| :`
does not count. Python scripts that build a `["cargo", ...]` argument list
(also across lines) are checked for "--locked" in the same list.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only (workflows are read as text).
"""
import posixpath
import re
import shlex
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WORKFLOWS = REPO / ".github" / "workflows"
LOCKED_VERBS = ("build", "b", "test", "t", "clippy", "check", "run", "doc", "bench",
                "llvm-cov", "nextest", "fetch", "tree", "metadata", "install", "miri")
SATISFIED_BY_METADATA = ("fuzz", "cyclonedx")
NEVER_IN_CI = ("update", "generate-lockfile")
ALL_VERBS = LOCKED_VERBS + SATISFIED_BY_METADATA + NEVER_IN_CI
SKIP_WORDS = ("if", "then", "elif", "else", "while", "until", "do", "!", "time", "exec",
              "command", "env", "sudo", "nohup")
SWALLOWERS = (["true"], [":"])
DURATION_RE = re.compile(r"^\d+(\.\d+)?[smhd]?$")
TIMEOUT_VALUE_OPTS = ("-k", "-s", "--kill-after", "--signal")
XARGS_VALUE_OPTS = ("-n", "-I", "-P", "-L", "-d", "-E", "-s", "-a")
VARIABLE_VERB = "variable"
VARIABLE_RE = re.compile(r"\$\{?\w+(?::[-=+][^}]*)?\}?")
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
RUN_KEY_RE = re.compile(r"^(\s*)(?:-\s+)?run:\s*(.*)$")
SCRIPT_REF_RE = re.compile(r"(?<![\w./-])((?:\./)?scripts/[\w./-]+\.(?:sh|py))")
PY_LIST_RE = re.compile(r"\[\s*[\"'](?:[^\"']*/)?cargo[\"']\s*,([^\]]*)\]")
MIN_SITES_WORKFLOWS = 40
MIN_SITES_SCRIPTS = 2
# Scripts scanned even when no workflow run block names them: contributors and
# release tooling run them and they invoke cargo.
EXTRA_SCRIPTS = ("scripts/coverage.sh",)


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


def split_commands_ops(line):
    """Split a shell line at unquoted ;, &&, ||, |, ( ), backtick and $( ).

    Returns [(command, op)] where op is the separator that follows the command
    (";", "&&", "||", "|" or "" for the last one).
    """
    parts, cur, quote, i = [], [], None, 0

    def push(op):
        text = "".join(cur).strip()
        if text:
            parts.append((text, op))
        elif parts and op:
            parts[-1] = (parts[-1][0], op)

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
                push(";")
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
            op = line[i:i + 2] if line[i:i + 2] in ("&&", "||") else (ch if ch in ";|" else ";")
            push(op)
            cur = []
            if len(op) == 2:
                i += 1
        else:
            cur.append(ch)
        i += 1
    push("")
    return parts


def split_commands(line):
    return [text for text, _ in split_commands_ops(line)]


def words(command):
    """Tokenise one command, dropping trailing comments; fall back to split()."""
    try:
        lex = shlex.shlex(command, posix=True)
        lex.whitespace_split = True
        lex.commenters = "#"
        return list(lex)
    except ValueError:
        return command.split()


def strip_wrappers(toks):
    """Drop shell keywords, assignments and wrapper prefixes in front of the real command."""
    while toks:
        head = toks[0]
        if head in SKIP_WORDS or ASSIGN_RE.match(head):
            toks = toks[1:]
        elif head == "nice":
            toks = toks[1:]
            while toks and toks[0].startswith("-"):
                toks = toks[2:] if toks[0] in ("-n", "--adjustment") else toks[1:]
        elif head == "timeout":
            toks = toks[1:]
            while toks and toks[0].startswith("-"):
                toks = toks[2:] if toks[0] in TIMEOUT_VALUE_OPTS else toks[1:]
            if toks and DURATION_RE.match(toks[0]):
                toks = toks[1:]
        elif head == "xargs":
            toks = toks[1:]
            while toks and toks[0].startswith("-"):
                toks = toks[2:] if toks[0] in XARGS_VALUE_OPTS else toks[1:]
        elif head == "stdbuf":
            toks = toks[1:]
            while toks and toks[0].startswith("-"):
                toks = toks[2:] if toks[0] in ("-i", "-o", "-e") else toks[1:]
        else:
            break
    return toks


def join_dir(cwd, arg):
    """Directory after `cd arg`; "?" when it cannot be known statically."""
    if cwd == "?" or not arg or arg == "-" or arg[0] in "$~" or "$" in arg:
        return "?"
    return posixpath.normpath(arg if arg.startswith("/") else posixpath.join(cwd, arg))


def manifest_dir(args, cwd):
    """Directory of the manifest a cargo call resolves: --manifest-path or the cwd."""
    for i, a in enumerate(args):
        value = None
        if a == "--manifest-path" and i + 1 < len(args):
            value = args[i + 1]
        elif a.startswith("--manifest-path="):
            value = a.split("=", 1)[1]
        if value is not None:
            return join_dir(cwd, posixpath.dirname(value) or ".")
    return cwd


def is_cargo(word):
    """cargo, or a path to it (`/usr/local/cargo/bin/cargo`, `./cargo`); a bare `/cargo` is
    a regex or path fragment, not a command."""
    return word == "cargo" or (word.endswith("/cargo") and word != "/cargo")


def scan_command(command, state, no, sites, swallowed=False):
    """Record the cargo calls in one command; recurse into bash -c / sh -c bodies."""
    toks = strip_wrappers(words(command))
    if not toks or toks[0] in ("echo", "printf"):
        return
    if toks[0] in ("cd", "pushd"):
        state["cwd"] = join_dir(state["cwd"], toks[1] if len(toks) > 1 else "")
        return
    if toks[0] == "popd":
        state["cwd"] = "?"
        return
    if toks[0] in ("bash", "sh") and "-c" in toks:
        idx = toks.index("-c")
        if idx + 1 < len(toks):
            scan_line(toks[idx + 1], state, no, sites)
        return
    through_variable = bool(VARIABLE_RE.fullmatch(toks[0])) and "cargo" in toks[0].lower()
    if not is_cargo(toks[0]) and not through_variable:
        return
    i, global_locked = 1, False
    if i < len(toks) and toks[i].startswith("+"):
        i += 1
    while i < len(toks) and toks[i].startswith("-"):
        global_locked = global_locked or toks[i] == "--locked"
        i += 1
    if i >= len(toks) or toks[i] not in ALL_VERBS:
        return
    if through_variable:
        sites.append((no, VARIABLE_VERB, False, command[:100]))
        return
    verb = toks[i]
    args = toks[i + 1:]
    if "--" in args:
        args = args[:args.index("--")]
    banner = ("--help", "-h") if verb == "install" else ("--version", "-V", "--help", "-h")
    if any(a in banner for a in args):
        return  # prints a banner, resolves nothing
    locked = global_locked or "--locked" in args
    here = manifest_dir(args, state["cwd"])
    if verb == "metadata" and locked and not swallowed and here != "?":
        state["meta_dirs"].add(here)
    if verb == "llvm-cov" and locked:
        state["llvm_cov_locked"] = True
    if verb in SATISFIED_BY_METADATA:
        ok = here in state["meta_dirs"]
    elif verb == "llvm-cov" and args[:1] == ["report"]:
        ok = bool(state["llvm_cov_locked"])  # renders the profile data a locked run just wrote
    elif verb in NEVER_IN_CI:
        ok = False
    else:
        ok = locked
    sites.append((no, verb, ok, command[:100]))


def scan_line(line, state, no, sites):
    pieces = split_commands_ops(line)
    for idx, (command, op) in enumerate(pieces):
        swallowed = (op == "||" and idx + 1 < len(pieces)
                     and words(pieces[idx + 1][0]) in SWALLOWERS)
        scan_command(command, state, no, sites, swallowed)


def new_state():
    return {"meta_dirs": set(), "llvm_cov_locked": False, "cwd": "."}


def find_sites_in_blocks(blocks):
    """Return [(lineno, verb, ok, command)] for command-position cargo calls."""
    sites = []
    for block in blocks:
        state = new_state()
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
    for m in PY_LIST_RE.finditer(script_text):
        n = script_text.count("\n", 0, m.start()) + 1
        items = re.findall(r"[\"']([^\"']*)[\"']", m.group(1))
        verb = next((x for x in items if not x.startswith("-") and not x.startswith("+")), None)
        if verb in LOCKED_VERBS or verb in NEVER_IN_CI:
            sites.append((n, verb, verb not in NEVER_IN_CI and "--locked" in items,
                          " ".join(m.group(0).split())[:100]))
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
        if verb in NEVER_IN_CI:
            bad.append("%s:%d cargo %s must not run in CI: %s" % (name, no, verb, line))
        elif verb == VARIABLE_VERB:
            bad.append("%s:%d cargo invoked through a variable cannot be verified: %s" % (name, no, line))
        elif verb in SATISFIED_BY_METADATA:
            bad.append("%s:%d cargo %s has no cargo metadata --locked for its directory before it in "
                       "the same block: %s" % (name, no, verb, line))
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
    scripts.update(EXTRA_SCRIPTS)
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

    def test_coverage_script_is_scanned_and_locked(self):
        sites = find_script_sites((REPO / "scripts/coverage.sh").read_text())
        self.assertGreaterEqual(len([s for s in sites if s[1] == "llvm-cov"]), 2)
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
        self.assertEqual(shape("cargo metadata --locked --format-version 1 --manifest-path fuzz/Cargo.toml "
                               ">/dev/null", "cd fuzz", "cargo fuzz run fuzz_validate -- -max_len=512"),
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

    def test_version_probes_are_not_resolutions(self):
        self.assertEqual(shape("cargo llvm-cov --version", "cargo fuzz --help"), [])

    def test_llvm_cov_report_needs_a_locked_llvm_cov_run_in_the_same_block(self):
        self.assertEqual(shape("cargo llvm-cov report --json"), [("llvm-cov", False)])
        self.assertEqual(shape("cargo llvm-cov --locked --no-report", "cargo llvm-cov report --json"),
                         [("llvm-cov", True), ("llvm-cov", True)])
        self.assertEqual(shape("cargo llvm-cov --no-report", "cargo llvm-cov report --json"),
                         [("llvm-cov", False), ("llvm-cov", False)])

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


class ScannerShapesRound3(unittest.TestCase):
    """One fixture per shape the round-2 reviews showed the lint missing (#8473 round 3)."""

    def test_timeout_wrapper(self):
        self.assertEqual(shape("timeout 600 cargo build"), [("build", False)])
        self.assertEqual(shape("timeout -k 5 600 cargo test --locked"), [("test", True)])
        self.assertEqual(shape("timeout --signal KILL 30s cargo check"), [("check", False)])

    def test_xargs_wrapper(self):
        self.assertEqual(shape("echo a | xargs cargo build"), [("build", False)])
        self.assertEqual(shape("echo a | xargs -n 1 -P 4 cargo test --locked"), [("test", True)])

    def test_nohup_and_stdbuf_wrappers(self):
        self.assertEqual(shape("nohup cargo build"), [("build", False)])
        self.assertEqual(shape("stdbuf -oL cargo test"), [("test", False)])
        self.assertEqual(shape("stdbuf -o L cargo test --locked"), [("test", True)])
        self.assertEqual(shape("nohup nice -n 5 timeout 9 cargo run"), [("run", False)])

    def test_cargo_path_is_cargo(self):
        self.assertEqual(shape("/usr/local/cargo/bin/cargo build"), [("build", False)])
        self.assertEqual(shape("~/.cargo/bin/cargo test --locked"), [("test", True)])
        self.assertEqual(shape("grep -c '/cargo test' file"), [])

    def test_cargo_through_a_variable_is_unverifiable(self):
        self.assertEqual(shape('"$CARGO" build'), [(VARIABLE_VERB, False)])
        self.assertEqual(shape("${CARGO_BIN} test --locked"), [(VARIABLE_VERB, False)])
        self.assertEqual(shape("$CARGO_HOME/bin/tool run"), [])
        bad = describe("x.yml", find_sites(wf('"$CARGO" build')))
        self.assertEqual(len(bad), 1)
        self.assertIn("through a variable", bad[0])

    def test_install_needs_locked(self):
        self.assertEqual(shape("cargo install cargo-fuzz --version 0.13.2"), [("install", False)])
        self.assertEqual(shape("cargo install cargo-fuzz --version 0.13.2 --locked"), [("install", True)])
        self.assertEqual(shape("cargo install --help"), [])

    def test_miri_needs_locked(self):
        self.assertEqual(shape("cargo miri test"), [("miri", False)])
        self.assertEqual(shape("cargo miri test --locked"), [("miri", True)])

    def test_generate_lockfile_is_never_allowed(self):
        self.assertEqual(shape("cargo generate-lockfile"), [("generate-lockfile", False)])
        self.assertEqual(shape("cargo generate-lockfile --locked"), [("generate-lockfile", False)])
        bad = describe("x.yml", find_sites(wf("cargo generate-lockfile")))
        self.assertIn("must not run in CI", bad[0])

    def test_multiline_python_list_is_joined(self):
        py = 'cmd = [\n    "cargo",\n    "metadata",\n    "--format-version", "1",\n]\n'
        self.assertEqual([(x[1], x[2]) for x in find_script_sites(py, python=True)], [("metadata", False)])
        py = 'cmd = [\n    "cargo",\n    "metadata",\n    "--locked",\n    "--format-version", "1",\n]\n'
        self.assertEqual([(x[1], x[2]) for x in find_script_sites(py, python=True)], [("metadata", True)])
        py = 'cmd = ["/usr/bin/cargo", "install", "x"]\n'
        self.assertEqual([(x[1], x[2]) for x in find_script_sites(py, python=True)], [("install", False)])

    def test_swallowed_locked_metadata_does_not_satisfy_a_later_call(self):
        for tail in ("|| true", "|| :"):
            self.assertEqual(shape("cargo metadata --locked --format-version 1 >/dev/null %s" % tail,
                                   "cargo cyclonedx --format json"),
                             [("metadata", True), ("cyclonedx", False)], tail)
        self.assertEqual(shape("cargo metadata --locked --format-version 1 >/dev/null || exit 1",
                               "cargo cyclonedx --format json"),
                         [("metadata", True), ("cyclonedx", True)])

    def test_metadata_must_cover_the_directory_of_the_later_call(self):
        # root metadata, then cd fuzz, then a fuzz run: the fuzz manifest was never checked
        self.assertEqual(shape("cargo metadata --locked --format-version 1 >/dev/null", "cd fuzz",
                               "cargo fuzz run fuzz_validate"),
                         [("metadata", True), ("fuzz", False)])
        # a fuzz-manifest metadata call does not cover a root cyclonedx run
        self.assertEqual(shape("cargo metadata --locked --manifest-path fuzz/Cargo.toml >/dev/null",
                               "cargo cyclonedx --format json"),
                         [("metadata", True), ("cyclonedx", False)])
        # cd into the directory first, plain metadata there
        self.assertEqual(shape("cd fuzz", "cargo metadata --locked --format-version 1 >/dev/null",
                               "cargo fuzz run fuzz_validate"),
                         [("metadata", True), ("fuzz", True)])
        # a directory held in a variable is unknown and never matches
        self.assertEqual(shape('cd "$DIR"', "cargo metadata --locked >/dev/null", "cargo fuzz run x"),
                         [("metadata", True), ("fuzz", False)])


if __name__ == "__main__":
    unittest.main()
