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
import os
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
SCAN_DIRS = ('src', 'tests', 'benches', 'examples')
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
    ('zip-use', re.compile(r'\b(?:use|extern\s+crate)\s+(?:::)?zip\b')),
    ('zip-use-brace', re.compile(r'\buse\s+(?:::)?\{[^}]*(?<![\w:])zip\b(?!\s*::)')),
    ('zip-type', re.compile(r'\b(?:ZipStreamReader|ZipArchive|ZipWriter|ZipFile)\b')),
    ('zip-extract-unwrapped', re.compile(r'\bextract_unwrapped_root_dir\b')),
    ('candle-loader', re.compile(
        r'\b(?:read_npz\w*|read_npy|write_npz|write_npy|read_pth\w*|from_pth\w*|'
        r'from_npz|NpzTensors|PthTensors|read_all_with_key)\b')),
    ('candle-pickle', re.compile(r'\bpickle\s*::')),
)
EXTRACT_CALL = re.compile(r'\.\s*extract\s*\(')
ZIP_CONTEXT = re.compile(r'\bzip\b|\bZip\w*|\barchive\b|\bArchive\b')
# A bare `zip` token that is neither a method call (`.zip(`), a path segment
# (`iter::zip`) nor a call (`zip(a, b)`): in macro input it can be the crate.
MACRO_ZIP = re.compile(r'(?<![\w.:])zip\b(?!\s*(?:\(|::))')
MACRO_OPEN = re.compile(r'\b[A-Za-z_]\w*\s*!\s*([(\[{])')
# Matched on the masked text (comments and string bodies blanked), so a quoted
# `#[path = ..]` in test code is not mistaken for an attribute; the literal is
# then read from the raw text at the same offset.
PATH_ATTR = re.compile(r'#\s*!?\[[^\]]*?\bpath\s*=')
PATH_LITERAL = re.compile(r'\s*"([^"]+)"')
INCLUDE_ANY = re.compile(r'\binclude\s*!\s*[(\[{]')
INCLUDE_LITERAL = re.compile(r'\binclude\s*!\s*\(\s*"([^"]+)"\s*\)')
CLOSERS = {'(': ')', '[': ']', '{': '}'}


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


DEP_KINDS = ('dependencies', 'dev-dependencies', 'build-dependencies')
KEY_SEGMENT = re.compile(r'\s*(?:"((?:[^"\\]|\\.)*)"|\'([^\']*)\'|([A-Za-z0-9_\-]+))\s*')
KEY_LINE_END = re.compile(r'\s*=')
HEADER_END = re.compile(r'\s*(\]\]?)\s*(?:#.*)?$')
ZIP_IN_VALUE = re.compile(r'(?<![\w\-])["\']?zip["\']?\s*[=.]')
PACKAGE_ZIP = re.compile(r'\bpackage\s*=\s*["\']zip["\']')
PACKAGE_VALUE_ZIP = re.compile(r'^\s*["\']zip["\']\s*(?:#.*)?$')


def parse_key(text, pos=0):
    """Parse a TOML dotted key at `pos`. Returns (segments, end_pos); raises ValueError."""
    parts = []
    while True:
        match = KEY_SEGMENT.match(text, pos)
        if not match:
            raise ValueError('not a key')
        if match.group(1) is not None:
            parts.append(match.group(1).replace('\\"', '"').replace('\\\\', '\\'))
        elif match.group(2) is not None:
            parts.append(match.group(2))
        else:
            parts.append(match.group(3))
        pos = match.end()
        if pos < len(text) and text[pos] == '.':
            pos += 1
            continue
        return parts, pos


def dependency_rest(path):
    """Segments after the dependency-kind segment of a TOML path, or None.

    A path is dependency-rooted at `<kind>`, `target.<cfg>.<kind>` or
    `workspace.dependencies`, wherever the dotted key or table header split it.
    """
    if len(path) >= 1 and path[0] in DEP_KINDS:
        return list(path[1:])
    if len(path) >= 3 and path[0] == 'target' and path[2] in DEP_KINDS:
        return list(path[3:])
    if len(path) >= 2 and path[0] == 'workspace' and path[1] == 'dependencies':
        return list(path[2:])
    return None


def iter_manifest_entries(text):
    """Yield ('header', n, table_path, '') and ('key', n, full_key_path, value) per line.

    A line-level TOML reader for Python 3.9 / 3.10 (no tomllib). It tracks the
    current table path from `[a.b."c(d)".e]` and `[[bin]]` headers (quoted
    segments, cfg() expressions), joins it with each key line's dotted key, and
    skips multi-line string bodies. Lines it cannot place are ignored.
    """
    table = []
    in_multiline = None
    for number, line in enumerate(text.splitlines(), 1):
        if in_multiline is not None:
            if in_multiline in line:
                in_multiline = None
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if stripped.startswith('['):
            array = stripped.startswith('[[')
            try:
                parts, end = parse_key(stripped, 2 if array else 1)
            except ValueError:
                continue
            if not HEADER_END.match(stripped, end):
                continue
            table = parts
            yield 'header', number, parts, ''
            continue
        try:
            parts, end = parse_key(stripped)
        except ValueError:
            continue
        eq = KEY_LINE_END.match(stripped, end)
        if not eq:
            continue
        value = stripped[eq.end():]
        for quote in ('"""', "'''"):
            if value.count(quote) % 2 == 1:
                in_multiline = quote
        yield 'key', number, table + parts, value


def fallback_manifest_hits(text):
    """Dependency-table check on the line-level reader. Returns (line, detail) pairs."""
    hits = []
    for kind, number, path, value in iter_manifest_entries(text):
        rest = dependency_rest(path)
        if rest is None:
            continue
        if rest and rest[0] == ZIP_CRATE:
            hits.append((number, 'direct zip dependency'))
        elif kind == 'key' and len(rest) == 1 and PACKAGE_ZIP.search(value):
            hits.append((number, 'dependency renamed to package zip'))
        elif kind == 'key' and len(rest) == 2 and rest[1] == 'package' and PACKAGE_VALUE_ZIP.match(value):
            hits.append((number, 'dependency renamed to package zip'))
        elif kind == 'key' and not rest and (ZIP_IN_VALUE.search(value) or PACKAGE_ZIP.search(value)):
            hits.append((number, 'direct zip dependency (inline table)'))
    return hits


def guess_line(text, name_pattern):
    for number, line in enumerate(text.splitlines(), 1):
        if re.search(name_pattern, line):
            return number
    return 1


def tomllib_manifest_hits(text):
    """Structural check with tomllib (Python 3.11+). Raises ToolError on invalid TOML."""
    try:
        import tomllib
    except ImportError:
        raise ToolError('--manifest-parser tomllib needs Python 3.11+')
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ToolError('Cargo.toml is not valid TOML: %s' % exc)
    tables = []
    for kind in DEP_KINDS:
        tables.append((kind, data.get(kind)))
    for cfg, body in (data.get('target') or {}).items():
        for kind in DEP_KINDS:
            if isinstance(body, dict):
                tables.append(('target.%s.%s' % (cfg, kind), body.get(kind)))
    workspace = data.get('workspace')
    if isinstance(workspace, dict):
        tables.append(('workspace.dependencies', workspace.get('dependencies')))
    hits = []
    line_hint = r'^\s*(?:\[.*\bzip\b.*\]|["\']?zip["\']?\s*[=.]|.*\bpackage\s*=\s*["\']zip["\'])'
    for label, table in tables:
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            renamed = isinstance(spec, dict) and spec.get('package') == ZIP_CRATE
            if name == ZIP_CRATE or renamed:
                hits.append((guess_line(text, line_hint), 'direct zip dependency in [%s]' % label))
    return hits


def check_manifest(manifest_text, parser='auto'):
    if parser == 'auto':
        try:
            import tomllib  # noqa: F401
            parser = 'tomllib'
        except ImportError:
            parser = 'fallback'
    if parser == 'tomllib':
        hits = tomllib_manifest_hits(manifest_text)
    else:
        hits = fallback_manifest_hits(manifest_text)
    return [violation('Cargo.toml:%d' % number, detail) for number, detail in hits]


def mask_rust(text):
    """Blank out comments, string and char literal bodies; newlines are kept.

    Keeps columns and line numbers stable so the macro scan can report the
    original line.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        two = text[i:i + 2]
        if two == '//':
            j = text.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i))
            i = j
        elif two == '/*':
            depth, j = 1, i + 2
            while j < n and depth:
                if text[j:j + 2] == '/*':
                    depth, j = depth + 1, j + 2
                elif text[j:j + 2] == '*/':
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            out.append(re.sub(r'[^\n]', ' ', text[i:j]))
            i = j
        elif ch == 'r' and re.match(r'r#*"', text[i:i + 40]) and (i == 0 or not text[i - 1].isalnum()):
            hashes = len(re.match(r'r(#*)"', text[i:]).group(1))
            end = text.find('"' + '#' * hashes, i + 2 + hashes)
            j = n if end < 0 else end + 1 + hashes
            out.append(re.sub(r'[^\n]', ' ', text[i:j]))
            i = j
        elif ch == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == '\\' else 1
            j = min(j + 1, n)
            out.append(re.sub(r'[^\n]', ' ', text[i:j]))
            i = j
        elif ch == "'" and re.match(r"'(?:\\.[^']*|[^\\'])'", text[i:i + 12]):
            j = i + len(re.match(r"'(?:\\.[^']*|[^\\'])'", text[i:i + 12]).group(0))
            out.append(' ' * (j - i))
            i = j
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def macro_input_hits(text, masked):
    """Line numbers where a bare `zip` token sits inside a macro invocation."""
    lines = set()
    for opener in MACRO_OPEN.finditer(masked):
        depth, j = 0, opener.end() - 1
        start = j
        while j < len(masked):
            if masked[j] in '([{':
                depth += 1
            elif masked[j] in ')]}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        for hit in MACRO_ZIP.finditer(masked, start, j):
            lines.add(masked.count('\n', 0, hit.start()) + 1)
    return sorted(lines)


def manifest_source_paths(manifest_text):
    """Source files Cargo.toml declares outside src/: package.build and target `path` keys."""
    paths = []
    for kind, _number, parts, value in iter_manifest_entries(manifest_text):
        if kind != 'key':
            continue
        literal = re.match(r'\s*(?:"([^"]*)"|\'([^\']*)\')', value)
        if not literal:
            continue
        text = literal.group(1) if literal.group(1) is not None else literal.group(2)
        if parts in (['package', 'build'], ['build']) or (
                parts[-1] == 'path' and parts[0] in ('lib', 'bin', 'example', 'test', 'bench')):
            paths.append(text)
    return paths


def read_source(path, rel):
    try:
        return path.read_text(encoding='utf-8')
    except (OSError, ValueError) as exc:
        raise ToolError('cannot read %s: %s' % (rel, exc))


def seed_sources(root, manifest_text):
    seeds = []
    for name in SCAN_FILES:
        seeds.append(root / name)
    for directory in SCAN_DIRS:
        base = root / directory
        if base.is_dir():
            seeds.extend(sorted(base.rglob('*.rs')))
    for declared in manifest_source_paths(manifest_text):
        seeds.append(root / declared)
    return seeds


def resolve_target(root, source, value, is_path_attr):
    """Resolve a #[path] / include! target; returns (path or None, problem or None)."""
    candidates = [source.parent / value]
    if is_path_attr:
        candidates.append(source.parent / source.stem / value)
    for candidate in candidates:
        resolved = Path(os.path.realpath(str(candidate)))
        if resolved.is_file():
            try:
                resolved.relative_to(root)
            except ValueError:
                return None, 'target %s is outside the repository' % value
            return resolved, None
    return None, 'target %s does not resolve to a file' % value


def check_sources(root, manifest_text=''):
    root = Path(os.path.realpath(str(root)))
    problems = []
    queue = [Path(os.path.realpath(str(p))) for p in seed_sources(root, manifest_text)]
    seen = set()
    while queue:
        path = queue.pop(0)
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            problems.append(violation(str(path), 'source outside the repository'))
            continue
        text = read_source(path, rel)
        zip_context = bool(ZIP_CONTEXT.search(text))
        for number, line in enumerate(text.splitlines(), 1):
            where = '%s:%d' % (rel, number)
            for label, pattern in FORBIDDEN:
                if pattern.search(line):
                    problems.append(violation(where, label))
            if zip_context and EXTRACT_CALL.search(line):
                problems.append(violation(where, 'zip-flavoured extract call'))
        masked = mask_rust(text)
        for attr in PATH_ATTR.finditer(masked):
            number = masked.count('\n', 0, attr.start()) + 1
            where = '%s:%d' % (rel, number)
            literal = PATH_LITERAL.match(text, attr.end())
            if not literal:
                problems.append(violation(where, '#[path] with a non-literal value cannot be followed'))
                continue
            target, problem = resolve_target(root, path, literal.group(1), True)
            if problem:
                problems.append(violation(where, '#[path] ' + problem))
            else:
                queue.append(target)
        for include in INCLUDE_ANY.finditer(masked):
            number = masked.count('\n', 0, include.start()) + 1
            where = '%s:%d' % (rel, number)
            literal = INCLUDE_LITERAL.match(text, include.start())
            if not literal:
                problems.append(violation(where, 'include! with a non-literal path cannot be followed'))
                continue
            target, problem = resolve_target(root, path, literal.group(1), False)
            if problem:
                problems.append(violation(where, 'include! ' + problem))
            else:
                queue.append(target)
        for number in macro_input_hits(text, masked):
            problems.append(violation('%s:%d' % (rel, number), 'zip named in macro input'))
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
    parser.add_argument('--manifest-parser', choices=('auto', 'tomllib', 'fallback'), default='auto',
                        help='Cargo.toml reader: tomllib (Python 3.11+), the built-in fallback, or auto')
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
        manifest_text = read_source(root / 'Cargo.toml', 'Cargo.toml')
        problems = (tree_problems + check_manifest(manifest_text, args.manifest_parser)
                    + check_sources(root, manifest_text))
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
