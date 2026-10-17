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
ALLOWED_PARENT_PREFIX = 'candle-'
SCAN_DIRS = ('src', 'tests', 'benches')
SCAN_FILES = ('build.rs',)
CARGO_TREE_ARGS = (
    'tree', '-i', ZIP_CRATE, '--edges', 'normal,build', '--depth', '1',
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


def parse_parents(tree_text):
    """Direct parents of zip from `cargo tree -i zip --depth 1` output.

    Accepts the `--prefix depth` form (`1candle-core v0.10.2`) and the default
    drawn form (`+-- name`, `|-- name`, box characters).
    """
    parents = []
    for raw in tree_text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        depth_match = re.match(r'^(\d+)(\S.*)$', line)
        if depth_match:
            if int(depth_match.group(1)) != 1:
                continue
            body = depth_match.group(2)
        else:
            drawn = re.match(r'^(?:[|`+\-│├└─ ]{3,})(\S.*)$', line)
            if not drawn:
                continue
            body = drawn.group(1)
        parents.append(body.split()[0])
    return parents


def check_tree(tree_text):
    problems = []
    for name in parse_parents(tree_text):
        if not name.startswith(ALLOWED_PARENT_PREFIX):
            problems.append(violation('cargo-tree', 'zip parent %s is not a candle-* crate' % name))
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


def cargo_tree_output(root):
    result = subprocess.run(
        ['cargo', *CARGO_TREE_ARGS], cwd=str(root), capture_output=True, text=True, check=False)
    if result.returncode != 0 and 'did not match any packages' in result.stderr:
        return ''  # zip left the graph entirely: nothing to guard
    if result.returncode != 0:
        raise RuntimeError('cargo tree failed rc=%d: %s' % (result.returncode, result.stderr.strip()[-400:]))
    return result.stdout


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
        else:
            tree_text = cargo_tree_output(root)
    except (OSError, RuntimeError) as exc:
        print('error: %s' % escape_text(exc), file=sys.stderr)
        return EXIT_USAGE
    problems = check_tree(tree_text) + check_manifest(root) + check_sources(root)
    for problem in problems:
        print(problem)
    if problems:
        print('check-zip-extract-unreachable: %d violation(s)' % len(problems))
        return EXIT_VIOLATION
    print('check-zip-extract-unreachable: ok')
    return EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
