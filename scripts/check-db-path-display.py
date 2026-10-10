#!/usr/bin/env python3
"""check-db-path-display.py - #6698: a database path is rendered only through
`crate::url_display::db_path_display`.

The database-path value (`--db`, `AI_MEMORY_DB`, config `db`) is where a
mistyped store DSN lands, password included (#6102, #6106, #6698). Since
#6699 a URL or a key/value DSN is refused before any store opens, but a
scheme-less `postgres:/svc:<pw>@host/db` is still a legal file name, so every
sink that prints the path (a banner, a `--json` field, an error context, a
log line) must render it through the ONE allowlist renderer (ERRORS-09).

The gate fails on `<name>.display()` where `<name>` is a database-path
binding (`db_path`, `db`, `db_file`, optionally behind a field path such as
`env.db_path` or `self.db`) anywhere in `src/` outside test code: a
`#[cfg(test)]` item (brace-matched, or a `mod x;` line), a file whose name
ends in `tests.rs`, or a file under a `tests/` directory. There is no
allowlist: a site that must print the raw path does not exist (an operator
who needs the real path has it in their own config).

Exit codes: 0 clean, 1 findings (or a failed self-test), 2 usage / IO error.
`--self-test` plants offending and clean shapes in a scratch tree under
`.local-runs/` (never /tmp) and requires the gate to classify each.
"""
import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path

SINK = re.compile(r"\b(?:[A-Za-z_][A-Za-z0-9_]*\.)*(db_path|db|db_file)\.display\(\)")
CFG_TEST = re.compile(r"^\s*#\[cfg\((?:all\()?test\b")


def test_file(path: Path) -> bool:
    return path.name.endswith("tests.rs") or "tests" in path.parts[:-1]


def strip_strings_and_comments(line: str) -> str:
    """Blank out `//` comments; good enough for brace matching per line."""
    out = []
    in_str = False
    i = 0
    while i < len(line):
        c = line[i]
        if not in_str and line.startswith("//", i):
            break
        if c == '"' and (i == 0 or line[i - 1] != "\\"):
            in_str = not in_str
        elif not in_str:
            out.append(c)
        i += 1
    return "".join(out)


def test_line_mask(lines):
    """True for each line inside a `#[cfg(test)]` item."""
    mask = [False] * len(lines)
    i = 0
    n = len(lines)
    while i < n:
        if not CFG_TEST.match(lines[i]):
            i += 1
            continue
        start = i
        depth = 0
        opened = False
        j = i
        while j < n:
            code = strip_strings_and_comments(lines[j])
            if j > start and not opened and code.rstrip().endswith(";") and "{" not in code:
                break
            depth += code.count("{") - code.count("}")
            if "{" in code:
                opened = True
            if opened and depth <= 0:
                break
            j += 1
        for k in range(start, min(j, n - 1) + 1):
            mask[k] = True
        i = j + 1
    return mask


def scan(root: Path):
    findings = []
    src = root / "src"
    if not src.is_dir():
        raise FileNotFoundError(str(src))
    for path in sorted(src.rglob("*.rs")):
        rel = path.relative_to(root)
        if test_file(rel):
            continue
        lines = path.read_text(encoding="utf-8").split("\n")
        mask = test_line_mask(lines)
        for no, line in enumerate(lines, 1):
            if mask[no - 1] or line.lstrip().startswith("//"):
                continue
            if SINK.search(line):
                findings.append("%s:%d: %s" % (rel, no, line.strip()))
    return findings


def self_test() -> int:
    base = Path(".local-runs")
    base.mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="db-path-display-", dir=str(base)))
    try:
        (scratch / "src" / "cli").mkdir(parents=True)
        (scratch / "src" / "cli" / "bad.rs").write_text(
            'fn a(db_path: &Path) { eprintln!("{}", db_path.display()); }\n'
            'fn b(env: &Env) -> String { env.db_path.display().to_string() }\n'
            'fn c(db: &Path) { let _ = format!("open {}", db.display()); }\n'
            "#[cfg(test)]\n"
            "mod tests {\n"
            '    fn t(db_path: &Path) { let _ = db_path.display(); }\n'
            "}\n"
            'fn d(db_file: &Path) { println!("{}", db_file.display()); }\n',
            encoding="utf-8",
        )
        (scratch / "src" / "good.rs").write_text(
            "fn a(db_path: &Path) -> String { crate::url_display::db_path_display(db_path) }\n"
            "fn b(path: &Path) -> String { path.display().to_string() }\n"
            "// db_path.display() in a comment is not a sink\n"
            "#[cfg(test)]\n"
            "mod t;\n"
            "fn c(sidecar: &Path) -> String { sidecar.display().to_string() }\n"
            "#[cfg(test)]\n"
            "fn helper(db: &Path) { let _ = db.display(); }\n",
            encoding="utf-8",
        )
        (scratch / "src" / "cli" / "tests").mkdir()
        (scratch / "src" / "cli" / "tests" / "x.rs").write_text(
            "fn t(db_path: &Path) { let _ = db_path.display(); }\n", encoding="utf-8"
        )
        (scratch / "src" / "x_tests.rs").write_text(
            "fn t(db_path: &Path) { let _ = db_path.display(); }\n", encoding="utf-8"
        )
        got = scan(scratch)
        want = {"src/cli/bad.rs:%d" % n for n in (1, 2, 3, 8)}
        have = {f.split(": ", 1)[0] for f in got}
        if have != want:
            print("self-test FAIL: want %s, got %s" % (sorted(want), sorted(have)))
            return 1
        print("self-test OK: %d planted sinks found, test code and other bindings ignored" % len(want))
        return 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true", help="prove the gate classifies planted shapes")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    try:
        findings = scan(args.root)
    except (OSError, UnicodeDecodeError) as e:
        print("check-db-path-display: %s" % e, file=sys.stderr)
        return 2
    for f in findings:
        print(f)
    if findings:
        print(
            "check-db-path-display: %d database-path sink(s) render the raw value; use "
            "crate::url_display::db_path_display (#6698)" % len(findings)
        )
        return 1
    print("check-db-path-display: OK (no raw database-path sink in src/)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
