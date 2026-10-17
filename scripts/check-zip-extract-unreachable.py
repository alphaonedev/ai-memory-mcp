#!/usr/bin/env python3
"""Guard for the cargo-audit ignores RUSTSEC-2026-0367, -0368 and -0369 (#7301).

zip 7.2.0 reaches the build only through candle-core 0.10.x. The three
advisories need zip's `extract()` / `ZipStreamReader::extract()` path, which
no candle release outside zip >= 9 can leave. The ignores in
`.cargo/audit.toml` are therefore sound only while that path is unreachable.
This guard fails (exit 1) when any of these holds:

  (a) `cargo tree -i zip` shows a direct parent that is not a `candle-*` crate;
  (b) the root Cargo.toml declares a direct `zip` dependency;
  (c) src/, tests/, benches/ or build.rs use zip directly, or call a candle
      npy / npz / pth loader (the only candle code that opens a zip archive).

Exit codes: 0 pass, 1 violation, 2 usage or tool error.

Pattern scope for `.extract(`: a bare `.extract(` is flagged only in a file
that also names zip or an archive type, so unrelated uses (regex, iterators)
cannot false-positive. Measured on the base: zero `.extract(` hits in src/,
tests/, benches/ and build.rs.

Printed paths escape CR and LF so a hostile file name cannot inject a GitHub
workflow command. Every violation line starts with `violation:`.

Remove this guard, and the audit ignores, when candle supports zip >= 9.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_USAGE = 2

ZIP_CRATE = 'zip'
# Exact crates that depend on zip today (candle-nn / candle-transformers 0.10.2
# have no zip dependency). Widening this set needs an edit here and in audit.toml.
ALLOWED_PARENTS = frozenset({'candle-core'})
SCAN_DIRS = ('src', 'tests', 'benches')
SCAN_FILES = ('build.rs',)
# Dev edges are included so a zip dev-dependency (also under a target-cfg table)
# is seen; `all` is not used because it adds `zip feature` lines.
CARGO_TREE_ARGS = (
    'tree', '-i', ZIP_CRATE, '--edges', 'normal,build,dev', '--depth', '1',
    '--prefix', 'depth', '--target', 'all', '--all-features', '--offline', '--locked',
)

# Direct zip use, plus the candle code paths that open a zip archive.
# Loader names come from candle-core / candle-nn 0.10.2 (npy.rs, pickle.rs,
# var_builder.rs).
FORBIDDEN = (
    ('zip-path', re.compile(r'\bzip\s*::')),
    ('zip-use', re.compile(r'\b(?:use|extern\s+crate)\s+zip\b')),
    ('zip-type', re.compile(r'\b(?:ZipStreamReader|ZipArchive|ZipWriter|ZipFile)\b')),
    ('candle-loader', re.compile(
        r'\b(?:read_npz\w*|read_npy|write_npz|write_npy|read_pth\w*|from_pth\w*|'
        r'from_npz|NpzTensors|PthTensors|read_all_with_key)\b')),
    ('candle-pickle', re.compile(r'\bpickle\s*::')),
)
EXTRACT_CALL = re.compile(r'\.\s*extract\s*\(')
ZIP_CONTEXT = re.compile(r'\bzip\b|\bZip\w*|\barchive\b|\bArchive\b')

DEP_SECTION = re.compile(r'^\s*\[\s*(?:[\w.\-"\' ]+\.)?(dependencies|dev-dependencies|build-dependencies)\s*\]\s*$')
DEP_TABLE_ZIP = re.compile(r'^\s*\[\s*(?:[\w.\-"\' ]+\.)?(?:dependencies|dev-dependencies|build-dependencies)\.zip\s*\]\s*$')
ANY_SECTION = re.compile(r'^\s*\[')
ZIP_KEY = re.compile(r'^\s*zip\s*(?:=|\.)')
ZIP_PACKAGE = re.compile(r'\bpackage\s*=\s*["\']zip["\']')


def escape_text(text):
    """Escape CR, LF and other controls so output cannot inject workflow commands."""
    out = []
    for ch in str(text):
        if ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ord(ch) < 0x20 or ord(ch) == 0x7f:
            out.append('\\x%02x' % ord(ch))
        else:
            out.append(ch)
    return ''.join(out)


def violation(location, message):
    return 'violation: %s: %s' % (escape_text(location), escape_text(message))


class ToolError(RuntimeError):
    """A tool or input problem: the guard cannot decide, so it exits 2 (fail closed)."""


ROOT_LINE = re.compile(r'^0?zip v\S+')
DEPTH_LINE = re.compile(r'^(\d+)(\S.*)$')
DRAWN_LINE = re.compile(r'^(?:[|`+\-│├└─ ]{3,})(\S.*)$')


def parse_tree(tree_text):
    """Direct parents of zip from `cargo tree -i zip --depth 1` output.

    Accepts the `--prefix depth` form (`0zip v7.2.0`, `1candle-core v0.10.2`)
    and the default drawn form (`+-- name`, box characters). Requires the zip
    root line and rejects any line it cannot place: a tree that is empty or not
    understood is a tool error, never a pass.
    """
    root_seen = False
    parents = []
    for raw in tree_text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if ROOT_LINE.match(line):
            root_seen = True
            continue
        depth_match = DEPTH_LINE.match(line)
        if depth_match:
            if int(depth_match.group(1)) == 1:
                parents.append(depth_match.group(2).split()[0])
            continue
        drawn = DRAWN_LINE.match(line)
        if drawn:
            parents.append(drawn.group(1).split()[0])
            continue
        raise ToolError('cannot parse cargo tree line: %r' % line[:120])
    if not root_seen:
        raise ToolError('cargo tree output has no zip root line (empty or unrecognised)')
    return parents


def check_tree(tree_text):
    problems = []
    for name in parse_tree(tree_text):
        if name not in ALLOWED_PARENTS:
            problems.append(violation(
                'cargo-tree', 'zip parent %s is not one of: %s' % (name, ', '.join(sorted(ALLOWED_PARENTS)))))
    return problems


def check_manifest(root):
    manifest = root / 'Cargo.toml'
    problems = []
    in_deps = False
    for number, line in enumerate(manifest.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
        if DEP_TABLE_ZIP.match(line):
            problems.append(violation('Cargo.toml:%d' % number, 'direct zip dependency'))
            in_deps = False
            continue
        if ANY_SECTION.match(line):
            in_deps = bool(DEP_SECTION.match(line))
            continue
        if in_deps and (ZIP_KEY.match(line) or ZIP_PACKAGE.search(line)):
            problems.append(violation('Cargo.toml:%d' % number, 'direct zip dependency'))
    return problems


def iter_sources(root):
    for name in SCAN_FILES:
        path = root / name
        if path.is_file():
            yield path
    for directory in SCAN_DIRS:
        base = root / directory
        if base.is_dir():
            for path in sorted(base.rglob('*.rs')):
                if path.is_file():
                    yield path


def check_sources(root):
    problems = []
    for path in iter_sources(root):
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding='utf-8', errors='replace')
        zip_context = bool(ZIP_CONTEXT.search(text))
        for number, line in enumerate(text.splitlines(), 1):
            for label, pattern in FORBIDDEN:
                if pattern.search(line):
                    problems.append(violation('%s:%d' % (rel, number), label))
            if zip_context and EXTRACT_CALL.search(line):
                problems.append(violation('%s:%d' % (rel, number), 'zip-flavoured extract call'))
    return problems


NO_MATCH = 'did not match any packages'


def lock_has_zip(root):
    """True when Cargo.lock lists a package named zip. An unreadable lock is a tool error."""
    lock = root / 'Cargo.lock'
    try:
        text = lock.read_text(encoding='utf-8')
    except (OSError, ValueError) as exc:
        raise ToolError('cannot read %s: %s' % (lock, exc))
    return re.search(r'^name\s*=\s*"zip"\s*$', text, re.MULTILINE) is not None


def cargo_tree_output(root):
    """Run cargo tree. Returns (stdout, absent); absent means zip is not in the graph."""
    try:
        result = subprocess.run(
            ['cargo', *CARGO_TREE_ARGS], cwd=str(root), capture_output=True, text=True, check=False)
    except OSError as exc:
        raise ToolError('cannot run cargo: %s' % exc)
    if result.returncode != 0 and NO_MATCH in result.stderr:
        return '', True
    if result.returncode != 0:
        raise ToolError('cargo tree failed rc=%d: %s' % (result.returncode, result.stderr.strip()[-400:]))
    return result.stdout, False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--root', default=str(Path(__file__).resolve().parents[1]),
                        help='repository root (default: this checkout)')
    parser.add_argument('--cargo-tree-file',
                        help='read `cargo tree -i zip` output from this file instead of running cargo')
    args = parser.parse_args(argv)
    root = Path(args.root)
    if not (root / 'Cargo.toml').is_file():
        print('error: no Cargo.toml under %s' % escape_text(root), file=sys.stderr)
        return EXIT_USAGE
    try:
        if args.cargo_tree_file:
            tree_text = Path(args.cargo_tree_file).read_text(encoding='utf-8')
            absent = False
        else:
            tree_text, absent = cargo_tree_output(root)
        if absent:
            # decision: pass with an explicit message over exit 2 because once zip
            # leaves the graph the advisories are moot and the guard plus ignores
            # are to be removed (#7302), not to break CI; cross-checked against
            # Cargo.lock so a cargo that merely fails to see zip cannot pass.
            if lock_has_zip(root):
                raise ToolError('cargo tree says zip is absent but Cargo.lock lists it')
            print('check-zip-extract-unreachable: zip not in graph (nothing to guard); '
                  'remove this guard and the audit ignores (#7302)')
            tree_problems = []
        else:
            tree_problems = check_tree(tree_text)
        problems = tree_problems + check_manifest(root) + check_sources(root)
    except (OSError, ValueError, ToolError) as exc:
        print('error: %s' % escape_text(exc), file=sys.stderr)
        return EXIT_USAGE
    for problem in problems:
        print(problem)
    if problems:
        print('check-zip-extract-unreachable: %d violation(s)' % len(problems))
        return EXIT_VIOLATION
    print('check-zip-extract-unreachable: ok')
    return EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
