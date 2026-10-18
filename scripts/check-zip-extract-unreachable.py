#!/usr/bin/env python3
"""Guard for the cargo-audit ignores RUSTSEC-2026-0367, -0368 and -0369 (#7301).

zip 7.2.0 reaches the build only through candle-core 0.10.x. The three
advisories need zip's `extract()` / `ZipStreamReader::extract()` path, which
no candle release outside zip >= 9 can leave. The ignores in
`.cargo/audit.toml` are therefore sound only while that path is unreachable.
This guard fails (exit 1) when any of these holds:

  (a) `cargo tree -i zip --edges normal,build,dev --workspace` shows a direct
      parent that is not registry candle-core 0.10.2 exactly (a path or git
      source, any other version including a later 0.10 patch, or any other
      crate fails; #7309), the zip root line carries a source suffix (#7311),
      or Cargo.lock lists candle-core with another version or a source other
      than crates.io, or any zip entry that is not registry zip 7.2.0 (#7311);
  (b) the root Cargo.toml declares a direct `zip` dependency in any form,
      patches or replaces candle-core or zip (a `[replace]` key may be `name`,
      `name:version`, `name@version` or a registry package ID ending in
      `#name@version`; inline-table `workspace` / `patch` values are read too
      on the fallback reader; #7306, #7311), or declares workspace members;
      direct zip dependency forms are:
      [dependencies], [dev-dependencies], [build-dependencies], any
      [target.<cfg>.*] table, [workspace.dependencies], [dependencies.zip],
      top-level dotted keys, or a rename with `package = "zip"`;
  (c) src/, tests/, benches/, examples/, build.rs, the declared build script
      or any declared target path use zip directly, name zip in macro input,
      call a candle npy / npz / pth loader (the only candle code that opens a
      zip archive, also when a `paste!` `[< .. >]` group joins its name from
      pieces; #7307), or pull in other files with `#[path]` / `include!` (those
      files are followed and scanned; an unresolvable one is a violation);
      a local zip binding exempts a macro input only inside its own fn body
      (#7308); a `mod name;` that resolves to no file on disk is a violation
      because only a build step could create it, and build scripts are also
      scanned with their string bodies kept, so a loader call written out of a
      string literal is seen (#7310);
  (d) every local package `cargo metadata --locked --format-version 1` lists
      (a path dependency or an implicit workspace member, not only the root)
      is scanned by rule (c) (#7305).

Fail closed: if cargo tree exits 0 but prints nothing parseable or no zip root
line, or any scanned file is unreadable or not UTF-8, the guard exits 2.
If zip is absent from the graph and from Cargo.lock it exits 0 with a
"zip not in graph" message: the guard and the ignores are then to be removed.
The Cargo.toml reader is tomllib on Python 3.11+, else a built-in line reader
(--manifest-parser forces one).

Exit codes: 0 pass, 1 violation, 2 usage or tool error.

Pattern scope for `.extract(`: a bare `.extract(` is flagged only in a file
that also names zip or an archive type, so unrelated uses (regex, iterators)
cannot false-positive. `extract_unwrapped_root_dir` is flagged everywhere.
Measured on the base: zero `.extract(` hits in src/, tests/, benches/ and
build.rs.

Printed paths escape CR and LF so a hostile file name cannot inject a GitHub
workflow command. Every violation line starts with `violation:`.

Remove this guard, and the audit ignores, when candle supports zip >= 9.
"""
import argparse
import json
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
# The audited parent: crates.io candle-core 0.10.2, the release the audit record in
# .cargo/audit.toml covers (#7309); a later patch release needs a new audit and an
# edit here. A tree line for it carries no `(<source>)` suffix (path and git
# packages print one); `(*)` marks a repeat.
AUDITED_CANDLE_VERSION = '0.10.2'
AUDITED_ZIP_VERSION = '7.2.0'
ALLOWED_PARENT_LINE = re.compile(r'^candle-core v0\.10\.2(?: \(\*\))?$')
# The zip root line of the tree: plain, or `(*)`; a `(<path or git>)` suffix is a patched zip.
ZIP_ROOT_LINE_OK = re.compile(r'^0?zip v\S+(?: \(\*\))?$')
LOCK_REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
PINNED_PACKAGES = ('candle-core', ZIP_CRATE)
SCAN_DIRS = ('src', 'tests', 'benches', 'examples')
SCAN_FILES = ('build.rs',)
# Dev edges are included so a zip dev-dependency (also under a target-cfg table)
# is seen; `all` is not used because it adds `zip feature` lines.
CARGO_TREE_ARGS = (
    'tree', '-i', ZIP_CRATE, '--edges', 'normal,build,dev', '--depth', '1',
    '--prefix', 'depth', '--target', 'all', '--all-features', '--workspace',
    '--locked',
)
# No --offline: `--target all` needs every platform's crates and a clean runner has
# fetched only its own. --locked keeps Cargo.lock authoritative; cargo may download
# the lockfile-pinned sources it is missing.

# Direct zip use, plus the candle code paths that open a zip archive.
# Loader names come from candle-core / candle-nn 0.10.2 (npy.rs, pickle.rs,
# var_builder.rs).
LOADER_NAMES = (
    'read_npz', 'read_npy', 'write_npz', 'write_npy', 'read_pth', 'from_pth',
    'from_npz', 'NpzTensors', 'PthTensors', 'read_all_with_key',
)
# Loader names that are a prefix of a longer identifier (`read_npz_by_name`).
LOADER_OPEN_ENDED = frozenset({'read_npz', 'read_pth', 'from_pth'})


def loader_alternation(paste_form):
    """Regex alternation over LOADER_NAMES; the paste! form drops `_` and lowercases (N5, L3)."""
    parts = []
    for name in LOADER_NAMES:
        text = name.replace('_', '').lower() if paste_form else name
        parts.append(text + (r'\w*' if name in LOADER_OPEN_ENDED else ''))
    return '(?:' + '|'.join(parts) + ')'


FORBIDDEN = (
    ('zip-path', re.compile(r'\bzip\s*::')),
    ('zip-use', re.compile(r'\b(?:use|extern\s+crate)\s+(?:::)?zip\b')),
    ('zip-use-brace', re.compile(r'\buse\s+(?:::)?\{[^}]*(?<![\w:])zip\b(?!\s*::)')),
    ('zip-type', re.compile(r'\b(?:ZipStreamReader|ZipArchive|ZipWriter|ZipFile)\b')),
    ('zip-extract-unwrapped', re.compile(r'\bextract_unwrapped_root_dir\b')),
    ('candle-loader', re.compile(r'\b' + loader_alternation(False) + r'\b')),
    ('candle-pickle', re.compile(r'\bpickle\s*::')),
)
EXTRACT_CALL = re.compile(r'\.\s*extract\s*\(')
ZIP_CONTEXT = re.compile(r'\bzip\b|\bZip\w*|\barchive\b|\bArchive\b')
# `.zip(..)`, `iter::zip(..)` and `zip(..)` are Iterator::zip calls, not the crate.
ZIP_CALL = re.compile(r'(?:\.\s*|::\s*)?\bzip\s*\(')
# Keywords that can sit before `!` (`if !(x)`) and so are not macro names.
NOT_MACRO = frozenset({'if', 'while', 'return', 'match', 'in', 'else', 'let', 'for', 'loop', 'break',
                       'mut', 'as', 'move', 'await', 'where', 'unsafe', 'yield', 'ref', 'box'})
# A local binding named zip: `let zip`, a `zip:` parameter or field pattern,
# `for zip in`, or a closure parameter.
ZIP_BINDING = re.compile(
    r'\blet\s+(?:mut\s+|ref\s+)*zip\b|(?<![\w:.])zip\s*:(?!:)|\bfor\s+zip\b|\|[^|\n]*\bzip\b[^|\n]*\|')
FN_KEYWORD = re.compile(r'\bfn\b')
# A bare `zip` token that is neither a method call (`.zip(`), a path segment
# (`iter::zip`) nor a call (`zip(a, b)`): in macro input it can be the crate.
MACRO_ZIP = re.compile(r'(?<![\w.:])zip\b(?!\s*(?:\(|::))')
MACRO_OPEN = re.compile(r'\b([A-Za-z_]\w*)\s*!\s*([(\[{])')
# Matched on the masked text (comments and string bodies blanked), so a quoted
# `#[path = ..]` in test code is not mistaken for an attribute; the literal is
# then read from the raw text at the same offset.
ATTR_OPEN = re.compile(r'#\s*!?\[')
PATH_KEY = re.compile(r'\bpath\s*=')


def attribute_bodies(masked):
    """(offset, body) of every `#[ .. ]` / `#![ .. ]` attribute, brackets balanced (strings are masked)."""
    for opening in ATTR_OPEN.finditer(masked):
        depth = 1
        index = opening.end()
        while index < len(masked) and depth:
            char = masked[index]
            if char == '[':
                depth += 1
            elif char == ']':
                depth -= 1
            index += 1
        yield opening.end(), masked[opening.end():index - 1 if depth == 0 else index]


def path_key_loads(body, position):
    """True when the `path =` key at `position` of an attribute body loads a module file.

    Only `#[path = ..]` and the arguments after the first one of `#[cfg_attr(<predicate>, .., path = ..)]`
    do, at any `cfg_attr(.., cfg_attr(.., path = ..))` nesting depth (N). A `path =` inside a predicate
    or another attribute's arguments loads nothing, so it must not count as a #[path] load (F2).
    """
    head = body[:position]
    if not head.strip():
        return True
    opened = re.match(r'\s*cfg_attr\s*\(', head)
    if not opened:
        return False
    depth = 1
    last_comma = -1
    for index in range(opened.end(), len(head)):
        char = head[index]
        if char in '([{':
            depth += 1
        elif char in ')]}':
            depth -= 1
            if depth < 1:
                return False
        elif char == ',' and depth == 1:
            last_comma = index
    if last_comma < 0:
        return False
    tail = head[last_comma + 1:]
    if not tail.strip():
        return depth == 1
    # The key sits in a nested attribute of the argument list: `cfg_attr(.., cfg_attr(.., path = ..))`.
    return path_key_loads(body[last_comma + 1:], position - (last_comma + 1))
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
                parents.append(depth_match.group(2).strip())
            continue
        drawn = DRAWN_LINE.match(line)
        if drawn:
            parents.append(drawn.group(1).strip())
            continue
        raise ToolError('cannot parse cargo tree line: %r' % line[:120])
    if not root_seen:
        raise ToolError('cargo tree output has no zip root line (empty or unrecognised)')
    return parents


def check_tree(tree_text):
    problems = []
    for parent in parse_tree(tree_text):
        if not ALLOWED_PARENT_LINE.match(parent):
            problems.append(violation(
                'cargo-tree', 'zip parent %r is not registry candle-core %s (no path or git source)'
                % (parent, AUDITED_CANDLE_VERSION)))
    for raw in tree_text.splitlines():
        line = raw.rstrip()
        if ROOT_LINE.match(line) and not ZIP_ROOT_LINE_OK.match(line):
            problems.append(violation('cargo-tree', 'zip root %r carries a source suffix (not registry zip)' % line))
    return problems


def lock_packages(root):
    """Cargo.lock packages as {name: [(version, source or None), ...]}; unreadable is a tool error."""
    lock = root / 'Cargo.lock'
    try:
        text = lock.read_text(encoding='utf-8')
    except (OSError, ValueError) as exc:
        raise ToolError('cannot read %s: %s' % (lock, exc))
    packages = {}
    for block in text.split('[[package]]')[1:]:
        fields = dict(re.findall(r'^(name|version|source)\s*=\s*"([^"]*)"\s*$', block, re.MULTILINE))
        if 'name' in fields:
            packages.setdefault(fields['name'], []).append((fields.get('version', ''), fields.get('source')))
    return packages


def check_lock(root):
    """candle-core in Cargo.lock must be crates.io 0.10.2 and every zip entry crates.io 7.2.0."""
    packages = lock_packages(root)
    entries = packages.get('candle-core', [])
    if not entries:
        return [violation('Cargo.lock', 'candle-core is the audited zip parent but has no lock entry')]
    problems = []
    for version, source in entries:
        if source != LOCK_REGISTRY or version != AUDITED_CANDLE_VERSION:
            problems.append(violation(
                'Cargo.lock', 'candle-core %s source %s is not crates.io %s'
                % (version, source, AUDITED_CANDLE_VERSION)))
    for version, source in packages.get(ZIP_CRATE, []):
        if source != LOCK_REGISTRY or version != AUDITED_ZIP_VERSION:
            problems.append(violation(
                'Cargo.lock', 'zip %s source %s is not crates.io %s' % (version, source, AUDITED_ZIP_VERSION)))
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


def open_multiline_quote(value):
    """The triple quote that opens a multi-line string left open at the end of `value`, or None.

    Walks the value as TOML does: a complete one-line `"..."` or `'...'` string
    (and a same-line `\"\"\"..\"\"\"`) is skipped whole, so a triple quote inside
    one cannot toggle the multi-line state; a `#` ends the scan.
    """
    i, n = 0, len(value)
    while i < n:
        ch = value[i]
        if value.startswith('"""', i) or value.startswith("'''", i):
            quote = value[i:i + 3]
            end = value.find(quote, i + 3)
            if end < 0:
                return quote
            i = end + 3
        elif ch == '"':
            i += 1
            while i < n and value[i] != '"':
                i += 2 if value[i] == '\\' else 1
            i += 1
        elif ch == "'":
            end = value.find("'", i + 1)
            i = n if end < 0 else end + 1
        elif ch == '#':
            return None
        else:
            i += 1
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
        in_multiline = open_multiline_quote(value)
        yield 'key', number, table + parts, value


# `name`, `name:version`, `name@version`, or a registry package ID `<url>#name@version`.
REPLACE_KEY = re.compile(r'(?:^|[#/])(candle-core|zip)(?:[:@]|$)')
PACKAGE_PINNED = re.compile(r'\bpackage\s*=\s*["\'](candle-core|zip)["\']')
PACKAGE_PINNED_VALUE = re.compile(r'^\s*["\'](candle-core|zip)["\']\s*(?:#.*)?$')
# Inline-table values the fallback reader sees on one line: `workspace = { members = [..] }` and
# `crates-io = { zip = { path = ".." } }` (also `patch = { crates-io = { .. } }`).
INLINE_MEMBERS = re.compile(r'["\']?members["\']?\s*=\s*\[\s*[^\]\s]')
INLINE_PINNED = re.compile(
    r'(?<![\w\-])["\']?(?:candle-core|zip)["\']?\s*[=.]|\bpackage\s*=\s*["\'](?:candle-core|zip)["\']')
WORKSPACE_DETAIL = 'workspace members are not scanned by this guard (extend it before adding one)'


def override_detail(kind, path, value):
    """Detail when this manifest entry redirects candle-core or zip, or declares workspace members."""
    if path[:2] == ['workspace', 'members'] and kind == 'key' and value.strip() not in ('[]', ''):
        return WORKSPACE_DETAIL
    if path == ['workspace'] and kind == 'key' and INLINE_MEMBERS.search(value):
        return WORKSPACE_DETAIL
    if path[0] == 'patch' and len(path) <= 2 and kind == 'key' and INLINE_PINNED.search(value):
        return '[patch] of a pinned package (inline table)'
    if path[0] == 'patch' and len(path) >= 3:
        if path[2] in PINNED_PACKAGES:
            return '[patch] of %s' % path[2]
        if len(path) == 3 and kind == 'key' and PACKAGE_PINNED.search(value):
            return '[patch] of a renamed pinned package'
        if len(path) == 4 and path[3] == 'package' and PACKAGE_PINNED_VALUE.match(value):
            return '[patch] of a renamed pinned package'
    if path[0] == 'replace' and len(path) >= 2 and REPLACE_KEY.search(path[1]):
        return '[replace] of %s' % path[1]
    return None


def fallback_manifest_hits(text):
    """Dependency-table check on the line-level reader. Returns (line, detail) pairs."""
    hits = []
    for kind, number, path, value in iter_manifest_entries(text):
        detail = override_detail(kind, path, value)
        if detail:
            hits.append((number, detail))
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
    if isinstance(workspace, dict) and workspace.get('members'):
        hits.append((guess_line(text, r'^\s*(?:workspace\.)?members\s*='), WORKSPACE_DETAIL))
    patch = data.get('patch')
    for source, body in (patch.items() if isinstance(patch, dict) else ()):
        for name, spec in (body.items() if isinstance(body, dict) else ()):
            renamed = spec.get('package') if isinstance(spec, dict) else None
            for pinned in (name, renamed):
                if pinned in PINNED_PACKAGES:
                    hits.append((guess_line(text, r'\b%s\b' % re.escape(name)), '[patch] of %s' % pinned))
    replace = data.get('replace')
    for key in (replace if isinstance(replace, dict) else ()):
        if REPLACE_KEY.search(key):
            hits.append((guess_line(text, re.escape(key)), '[replace] of %s' % key))
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


# A raw string opener with its optional byte (`b`) or C (`c`) prefix: r"..", br#".."#, cr"..".
RAW_OPEN = re.compile(r'[bc]?r(#*)"')


def mask_rust(text, keep_strings=False):
    """Blank out comments, string and char literal bodies; newlines are kept.

    Keeps columns and line numbers stable so the macro scan can report the
    original line. `keep_strings` leaves string bodies in place (comments are
    still blanked): used for build scripts, whose strings can be generated code.
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
        elif ch in 'rbc' and RAW_OPEN.match(text, i) and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == '_')):
            raw = RAW_OPEN.match(text, i)
            hashes = len(raw.group(1))
            end = text.find('"' + '#' * hashes, raw.end())
            j = n if end < 0 else end + 1 + hashes
            out.append(text[i:j] if keep_strings else re.sub(r'[^\n]', ' ', text[i:j]))
            i = j
        elif ch == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == '\\' else 1
            j = min(j + 1, n)
            out.append(text[i:j] if keep_strings else re.sub(r'[^\n]', ' ', text[i:j]))
            i = j
        elif ch == "'" and re.match(r"'(?:\\.[^']*|[^\\'])'", text[i:i + 12]):
            j = i + len(re.match(r"'(?:\\.[^']*|[^\\'])'", text[i:i + 12]).group(0))
            out.append(' ' * (j - i))
            i = j
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def match_close(masked, open_index):
    """Index of the bracket that closes the one at `open_index` (the text length if unbalanced)."""
    depth, j = 0, open_index
    while j < len(masked):
        if masked[j] in '([{':
            depth += 1
        elif masked[j] in ')]}':
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return j


def fn_body_spans(masked):
    """(start of `fn`, closing brace) for every fn that has a body; a bodyless declaration has none."""
    spans = []
    for keyword in FN_KEYWORD.finditer(masked):
        depth, j = 0, keyword.end()
        while j < len(masked):
            ch = masked[j]
            if ch in '([':
                depth += 1
            elif ch in ')]':
                depth -= 1
            elif depth <= 0 and ch in ';}':
                break
            elif depth <= 0 and ch == '{':
                spans.append((keyword.start(), match_close(masked, j)))
                break
            j += 1
    return spans


def macro_input_hits(text, masked):
    """Line numbers where a bare `zip` token sits inside a macro invocation."""
    lines = set()
    spans = fn_body_spans(masked)
    for opener in MACRO_OPEN.finditer(masked):
        if opener.group(1) in NOT_MACRO:
            continue
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
            # A zip bound in the enclosing fn (parameter or let) is a local, not the
            # crate; the exemption covers that fn's body only (#7308).
            inside = [span for span in spans if span[0] < hit.start() < span[1]]
            if inside and ZIP_BINDING.search(masked, max(inside)[0], hit.start()):
                continue
            lines.add(masked.count('\n', 0, hit.start()) + 1)
    return sorted(lines)


def manifest_source_paths(manifest_text, builds_only=False):
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
                not builds_only and parts[-1] == 'path' and parts[0] in ('lib', 'bin', 'example', 'test', 'bench')):
            paths.append(text)
    return paths


def read_source(path, rel):
    try:
        return path.read_text(encoding='utf-8')
    except (OSError, ValueError) as exc:
        raise ToolError('cannot read %s: %s' % (rel, exc))


def seed_sources(root, manifest_text, targets=()):
    seeds = []
    for name in SCAN_FILES:
        seeds.append(root / name)
    for directory in SCAN_DIRS:
        base = root / directory
        if base.is_dir():
            seeds.extend(sorted(base.rglob('*.rs')))
    for declared in list(manifest_source_paths(manifest_text)) + [str(t) for t, _build in targets]:
        seeds.append(root / declared)
    return seeds


def lexical(path):
    """`..` and `.` folded away textually; symlinks are NOT resolved (rustc resolves from this path, S)."""
    return Path(os.path.normpath(str(path)))


def real_of(path):
    return Path(os.path.realpath(str(path)))


def logical_path(root, path):
    """The path as rustc sees it. One outside the repository (an absolute `cargo metadata` path) is
    anchored on the real parent directory only, so the file's own name is kept."""
    path = lexical(path)
    try:
        path.relative_to(root)
        return path
    except ValueError:
        return lexical(real_of(path.parent) / path.name)


SYMLINK_DOTDOT = "crosses a symlink with '..'"


def target_joins(source, value, is_path_attr, inline=()):
    """The UNFOLDED joins a #[path] / include! value can name from `source` (the logical path of the file).

    rustc: a `#[path]` is relative to the directory of the file, plus the names of the enclosing
    inline `mod y { .. }` blocks (H); in a plain `name.rs` file those sit under `name/`, so both
    bases are candidates. Over-listing is the fail-closed direction.
    """
    if not is_path_attr:
        return [source.parent / value]
    sub = Path(*inline) if inline else Path()
    return [base / sub / value for base in (source.parent, source.parent / source.stem)]


def target_candidates(source, value, is_path_attr, inline=()):
    """The joins of `target_joins`, with `.` and `..` folded away textually."""
    return [lexical(join) for join in target_joins(source, value, is_path_attr, inline)]


def crosses_symlink_dotdot(join):
    """True when the OS resolves `join` (a `..` after a symlinked component walks out of the link
    target) to a different file than the textual fold of it (F1, r5 regression)."""
    if '..' not in join.parts:
        return False
    folded = lexical(join)
    if not (join.is_file() or folded.is_file()):
        return False
    return os.path.realpath(str(join)) != os.path.realpath(str(folded))


def resolve_target(root, source, value, is_path_attr, inline=()):
    """Resolve a #[path] / include! target; returns ([logical paths of the existing files], problem or None)."""
    for join in target_joins(source, value, is_path_attr, inline):
        if crosses_symlink_dotdot(join):
            return [], SYMLINK_DOTDOT
    found = []
    for candidate in target_candidates(source, value, is_path_attr, inline):
        if candidate.is_file():
            try:
                real_of(candidate).relative_to(root)
            except ValueError:
                return [], 'target %s is outside the repository' % value
            found.append(candidate)
    if not found:
        return [], 'target %s does not resolve to a file' % value
    return found, None


PASTE_GROUP = re.compile(r'\[<(.*?)>\]', re.DOTALL)
PASTE_MODIFIER = re.compile(r':(?:lower|upper|snake|camel|lower_camel|upper_camel)\b')
# The candle-loader names of FORBIDDEN with underscores removed and lowercased, without the
# leading word boundary: paste! case modifiers and spacing cannot hide them, and a piece can
# prefix them (`[<try_ read_npz>]`). Built from the same LOADER_NAMES tuple, so the two
# lists cannot drift (N5, L3).
PASTE_LOADER_NORMAL = re.compile(loader_alternation(True) + r'\b')
MOD_DECL = re.compile(r'(?<![\w])mod\s+(?:r#)?([A-Za-z_]\w*)\s*;')
MACRO_RULES = re.compile(r'\bmacro_rules\s*!\s*(?:r#)?([A-Za-z_]\w*)\s*(?=[(\[{])')
MACRO_MOD = re.compile(r'(?<![\w$])mod\s+(?:r#)?\$?\s*[A-Za-z_]\w*\s*;')
INLINE_MOD_OR_BRACE = re.compile(r'\bmod\s+(?:r#)?([A-Za-z_]\w*)\s*\{|[{}]')
INLINE_MOD_OPEN = re.compile(r'\bmod\s+(?:r#)?[A-Za-z_]\w*\s*\{')
# The `mod` keyword in any form but `mod name;` / `mod name {` / `mod $name;` (F3): handed to a
# macro as input tokens it emits a file module the guard never sees. `r#mod` and `$mod` are not it.
MOD_KEYWORD_OTHER = re.compile(r'(?<![\w$#])mod\b(?!\s*(?:r#)?\$?\s*[A-Za-z_]\w*\s*[;{])')


def mod_keyword_hits(masked):
    """Line numbers of a `mod` keyword the guard cannot follow (F3); masked text, so strings and comments are out."""
    return sorted({masked.count('\n', 0, hit.start()) + 1 for hit in MOD_KEYWORD_OTHER.finditer(masked)})


def inline_mod_path_keys(masked):
    """(line, offset of the `path` key) for each `#[path = ..]` / `cfg_attr(.., path = ..)` ON an inline `mod y { .. }` (F2).

    Such a key moves the directory of the child `mod` loads of `y`, which the guard does not model, so it
    is a violation (fail closed) instead of an unscanned directory.
    """
    hits = []
    for opener in INLINE_MOD_OPEN.finditer(masked):
        window_start = max(0, opener.start() - 300)
        window = masked[window_start:opener.start()]
        cut = max(window.rfind(sep) for sep in ';{}') + 1
        before = window[cut:]
        for offset, body in attribute_bodies(before):
            for key in PATH_KEY.finditer(body):
                if path_key_loads(body, key.start()):
                    absolute = window_start + cut + offset + key.start()
                    hits.append((masked.count('\n', 0, absolute) + 1, absolute))
    return hits


def paste_loader_hits(text, masked):
    """Line numbers where a `paste!` `[< .. >]` group joins to a candle loader name (#7307)."""
    lines = set()
    # Every group, whatever the macro is called or aliased: `[< .. >]` is not Rust syntax elsewhere.
    for group in PASTE_GROUP.finditer(text):
        joined = PASTE_MODIFIER.sub('', group.group(1))
        joined = re.sub(r'[\s"\'$_]', '', joined).lower()
        if PASTE_LOADER_NORMAL.search(joined):
            lines.add(text.count('\n', 0, group.start()) + 1)
    return sorted(lines)


def enclosing_inline_mods(masked, pos):
    """Names of the inline `mod x { .. }` blocks that enclose `pos`, outermost first."""
    stack = []
    for token in INLINE_MOD_OR_BRACE.finditer(masked, 0, pos):
        if token.group(0) == '}':
            if stack:
                stack.pop()
        else:
            stack.append(token.group(1))
    return [name for name in stack if name]


MODE_RS = 'mod-rs'
MODE_PLAIN = 'plain'


def module_decls(masked):
    """(line, name, sub) for each `mod name;` that is not an unconditional #[path] module (#7310).

    `sub` is the directory of the enclosing inline `mod x { .. }` blocks.
    """
    decls = []
    for decl in MOD_DECL.finditer(masked):
        before = masked[max(0, decl.start() - 300):decl.start()]
        before = re.split(r'[;{}]', before)[-1]
        if re.search(r'#\s*\[\s*path\s*=', before):
            # An UNCONDITIONAL #[path] module: followed (or flagged) by the path-attribute scan.
            # A cfg_attr(<cond>, path = ..) module is not exempt: when the condition is false
            # cargo loads the default file, which a build step could generate (#7310).
            continue
        inline = enclosing_inline_mods(masked, decl.start())
        decls.append((masked.count('\n', 0, decl.start()) + 1, decl.group(1), Path(*inline) if inline else Path()))
    return decls


def module_candidates(base, sub, name):
    return (base / sub / (name + '.rs'), base / sub / name / 'mod.rs')


def load_base(path, mode):
    """rustc: a mod-rs load looks for `mod x;` beside the file, a plain load in a directory named after it."""
    return path.parent if mode == MODE_RS else path.parent / path.stem


def existing_candidates(path, decls, bases):
    """Logical paths of the module files `mod x;` can resolve to (bases come from the logical path, S)."""
    found = []
    for _line, name, sub in decls:
        for base in bases:
            for candidate in module_candidates(base, sub, name):
                if candidate.is_file():
                    found.append(lexical(candidate))
    return found


def propagate_modes(files, roots, path_targets):
    """Modes in which each file is loaded, to a fixpoint (F, #7310).

    rustc decides the base per LOAD, not per file: crate roots, `#[path]` targets and `mod.rs`
    files are loaded mod-rs; a `name.rs` found for `mod name;` is a plain load. One file can be
    loaded in both modes (`mod a;` plus `#[path = "a.rs"] mod b;`), and its modules must resolve
    under the base of every mode. Walk order is arbitrary, hence the iteration.
    """
    modes = {}
    for path, _rel, _decls in files:
        if path in roots or path in path_targets or path.name == 'mod.rs':
            modes[path] = {MODE_RS}
    changed = True
    while changed:
        changed = False
        for path, _rel, decls in files:
            for mode in tuple(modes.get(path, (MODE_PLAIN,))):
                for _line, name, sub in decls:
                    for candidate in module_candidates(load_base(path, mode), sub, name):
                        if not candidate.is_file():
                            continue
                        logical = lexical(candidate)
                        child = MODE_RS if logical.name == 'mod.rs' else MODE_PLAIN
                        if child not in modes.setdefault(logical, set()):
                            modes[logical].add(child)
                            changed = True
    return modes


def missing_mod_hits(path, decls, modes):
    """(line, name) for each `mod name;` with no file under the base of some mode the file is loaded in (#7310)."""
    hits = []
    for line, name, sub in decls:
        for mode in sorted(modes.get(path, (MODE_PLAIN,))):
            if not any(c.is_file() for c in module_candidates(load_base(path, mode), sub, name)):
                hits.append((line, name))
                break
    return hits


def build_script_paths(root, manifest_text, targets=()):
    names = (list(SCAN_FILES) + manifest_source_paths(manifest_text, builds_only=True)
             + [str(t) for t, is_build in targets if is_build])
    return {Path(os.path.realpath(str(root / name))) for name in names}


def crate_roots(root, manifest_text, targets=()):
    """Files cargo treats as crate roots: `mod x;` beside them is `x.rs`, not `<stem>/x.rs`."""
    found = {root / 'src' / 'lib.rs', root / 'src' / 'main.rs', root / 'build.rs'}
    for declared in list(manifest_source_paths(manifest_text)) + [str(t) for t, _build in targets]:
        found.add(root / declared)
    for directory in ('src/bin', 'tests', 'benches', 'examples'):
        base = root / directory
        if base.is_dir():
            found.update(base.glob('*.rs'))
            found.update(base.glob('*/main.rs'))
    return {logical_path(root, p) for p in found}


def macro_mod_hits(masked):
    """(line, macro name) for each `mod x;` / `mod $x;` inside a `macro_rules!` body (M).

    The module file is looked up where the macro is INVOKED, which the guard cannot follow, so
    such a declaration is a violation (fail closed) instead of an invisible, unscanned module.
    """
    hits = []
    for macro in MACRO_RULES.finditer(masked):
        opening = macro.end()
        closing = match_close(masked, opening)
        for decl in MACRO_MOD.finditer(masked, opening, closing):
            hits.append((masked.count('\n', 0, decl.start()) + 1, macro.group(1)))
    return hits


class SourceFile(object):
    """One scanned file (by realpath) and what it references; each logical path it is reached by is a view."""

    def __init__(self, real, rel, decls, refs):
        self.real = real
        self.rel = rel
        self.decls = decls
        self.refs = refs
        self.views = set()


def source_refs(text, masked):
    """(kind, line, value or None, inline mods, loads) for each #[path] attribute and include! (H, N)."""
    refs = []
    on_inline_mod = {absolute for _line, absolute in inline_mod_path_keys(masked)}
    for offset, body in attribute_bodies(masked):
        for key in PATH_KEY.finditer(body):
            if offset + key.start() in on_inline_mod:
                continue  # reported as a whole by `inline_mod_path_keys`; its value is a directory, not a file
            number = masked.count('\n', 0, offset + key.start()) + 1
            literal = PATH_LITERAL.match(text, offset + key.end())
            inline = tuple(enclosing_inline_mods(masked, offset + key.start()))
            refs.append(('path', number, literal.group(1) if literal else None, inline,
                         path_key_loads(body, key.start())))
    for include in INCLUDE_ANY.finditer(masked):
        number = masked.count('\n', 0, include.start()) + 1
        literal = INCLUDE_LITERAL.match(text, include.start())
        refs.append(('include', number, literal.group(1) if literal else None, (), False))
    return refs


def check_sources(root, manifest_text='', label='', targets=()):
    """`targets`: (src_path, is_build_script) from `cargo metadata`; covers every TOML form of a target (#7310).

    Bases for `mod x;` and `#[path]` come from the LOGICAL path (symlinks unresolved, S); the realpath
    only keys the seen-set and the escape check.
    """
    root = real_of(root)
    builds = build_script_paths(root, manifest_text, targets)
    problems = []

    def report(text):
        if text not in problems:
            problems.append(text)

    queue = [logical_path(root, p) for p in seed_sources(root, manifest_text, targets)]
    roots = crate_roots(root, manifest_text, targets)
    for declared in list(manifest_source_paths(manifest_text)) + [str(t) for t, _build in targets]:
        target = real_of(root / declared)
        if not target.is_file():
            try:
                shown = label + target.relative_to(root).as_posix()
            except ValueError:
                shown = label + declared
            report(violation(shown, 'declared target has no file on disk; a build step could generate it'))
    seen = {}
    mod_files = []
    path_targets = set()

    def show(logical):
        try:
            return label + logical.relative_to(root).as_posix()
        except ValueError:
            return label + str(logical)

    def expand(logical, info):
        """Queue what `info` references, resolved from the logical path `logical`."""
        rel = show(logical)
        for kind, number, value, inline, loads in info.refs:
            where = '%s:%d' % (rel, number)
            if value is None:
                what = '#[path] with a non-literal value' if kind == 'path' else 'include! with a non-literal path'
                report(violation(where, what + ' cannot be followed'))
                continue
            found, problem = resolve_target(root, logical, value, kind == 'path', inline)
            if problem == SYMLINK_DOTDOT:
                report(violation(where, '#[path]/include! target ' + problem))
                continue
            if problem:
                report(violation(where, ('#[path] ' if kind == 'path' else 'include! ') + problem))
                continue
            # Scanned whatever the attribute. Only a real load makes it a mod-rs file: a `path =`
            # inside a cfg predicate loads nothing and adds no exemption (F2).
            if loads:
                path_targets.update(found)
            queue.extend(found)
        # Every module file `mod x;` can resolve to is scanned, wherever it sits (E): over-scanning
        # both bases is the fail-closed direction.
        queue.extend(existing_candidates(logical, info.decls, (logical.parent, logical.parent / logical.stem)))
        mod_files.append((logical, rel, info.decls))

    while queue:
        logical = queue.pop(0)
        if not logical.is_file():
            continue
        path = real_of(logical)
        known = seen.get(path)
        if known is not None:
            if logical not in known.views:
                known.views.add(logical)
                expand(logical, known)
            continue
        rel = show(logical)
        try:
            path.relative_to(root)
        except ValueError:
            seen[path] = SourceFile(path, rel, [], [])
            report(violation(str(path), 'source outside the repository'))
            continue
        text = read_source(path, rel)
        # Code patterns run on the masked text: comments and string bodies are
        # not code, so a doc comment naming `zip::ZipArchive` is not a use.
        masked = mask_rust(text)
        zip_context = bool(ZIP_CONTEXT.search(ZIP_CALL.sub(' ', masked)))
        # A build script can write generated code out of a string literal, so its
        # string bodies are scanned too (#7310); comments stay masked.
        scan = mask_rust(text, keep_strings=True) if path in builds else masked
        for number, line in enumerate(scan.split('\n'), 1):
            where = '%s:%d' % (rel, number)
            for rule, pattern in FORBIDDEN:
                if pattern.search(line):
                    report(violation(where, rule))
            if zip_context and EXTRACT_CALL.search(line):
                report(violation(where, 'zip-flavoured extract call'))
        for number, macro in macro_mod_hits(masked):
            report(violation('%s:%d' % (rel, number),
                             'mod declared inside macro_rules! %s resolves where the macro is invoked and cannot be '
                             'followed' % macro))
        for number, _absolute in inline_mod_path_keys(masked):
            report(violation('%s:%d' % (rel, number), '#[path] on an inline mod is not supported'))
        for number in mod_keyword_hits(masked):
            report(violation('%s:%d' % (rel, number), 'mod keyword in a form the guard cannot follow'))
        for number in macro_input_hits(text, masked):
            report(violation('%s:%d' % (rel, number), 'zip named in macro input'))
        for number in paste_loader_hits(text, masked):
            report(violation('%s:%d' % (rel, number), 'candle-loader (paste! pieces)'))
        info = SourceFile(path, rel, module_decls(masked), source_refs(text, masked))
        info.views.add(logical)
        seen[path] = info
        expand(logical, info)
    # After the walk: every file's load modes, whatever the visit order.
    modes = propagate_modes(mod_files, roots, path_targets)
    for logical, rel, decls in mod_files:
        for number, name in missing_mod_hits(logical, decls, modes):
            report(violation(
                '%s:%d' % (rel, number), 'mod %s; resolves to no file on disk (a build step could generate it)' % name))
    return problems


def metadata_packages(metadata_text, root):
    """(name, directory, targets, is_root) of every local package in `cargo metadata` JSON (#7305, #7310).

    targets are (src_path, is_build_script) from packages[].targets[].src_path. A document
    without the root package is a tool error (N4).
    """
    root = Path(os.path.realpath(str(root)))
    found = []
    has_root = False
    try:
        for package in json.loads(metadata_text)['packages']:
            if package.get('source') is not None:
                continue
            directory = Path(os.path.realpath(str(Path(package['manifest_path']).parent)))
            targets = []
            listed = package.get('targets')
            if not isinstance(listed, list) or not listed:
                raise ToolError('cargo metadata package %s has no targets' % package.get('name', '?'))
            for target in listed:
                targets.append((str(target['src_path']), 'custom-build' in (target.get('kind') or [])))
            has_root = has_root or directory == root
            found.append((str(package.get('name', '?')), directory, targets, directory == root))
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ToolError('cannot parse cargo metadata output: %s' % exc)
    if not has_root:
        raise ToolError('cargo metadata output has no package with manifest_path %s' % (root / 'Cargo.toml'))
    return found


def root_targets(metadata_text, root):
    for _name, _directory, targets, is_root in metadata_packages(metadata_text, root):
        if is_root:
            return targets
    return []


def check_local_packages(metadata_text, root):
    """Rule (c) over every local package other than the root: path dependencies and implicit members."""
    root = Path(os.path.realpath(str(root)))
    problems = []
    for name, directory, targets, is_root in metadata_packages(metadata_text, root):
        if is_root:
            continue
        try:
            label = directory.relative_to(root).as_posix() + '/'
        except ValueError:
            label = name + '/'
        manifest = directory / 'Cargo.toml'
        problems += check_sources(directory, read_source(manifest, label + 'Cargo.toml'), label, targets)
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


CARGO_TIMEOUT_SECS = 600


def run_cargo(args, root):
    """Run cargo with a timeout; a hang or a missing binary is a tool error (rc 2), never a pass (L-c)."""
    command = 'cargo ' + ' '.join(args)
    try:
        return subprocess.run(
            ['cargo', *args], cwd=str(root), capture_output=True, text=True, check=False,
            timeout=CARGO_TIMEOUT_SECS)
    except subprocess.TimeoutExpired:
        raise ToolError('`%s` timed out after %d s' % (command, CARGO_TIMEOUT_SECS))
    except OSError as exc:
        raise ToolError('cannot run cargo: %s' % exc)


def cargo_tree_output(root):
    """Run cargo tree. Returns (stdout, absent); absent means zip is not in the graph."""
    result = run_cargo(CARGO_TREE_ARGS, root)
    if result.returncode != 0 and NO_MATCH in result.stderr:
        return '', True
    if result.returncode != 0:
        raise ToolError('cargo tree failed rc=%d: %s' % (result.returncode, result.stderr.strip()[-400:]))
    return result.stdout, False


CARGO_METADATA_ARGS = ('metadata', '--locked', '--format-version', '1')
# Not --no-deps: the local packages that matter (path dependencies) are found through the
# resolved graph; a workspace-only listing would miss one outside the workspace.


def cargo_metadata_output(root):
    result = run_cargo(CARGO_METADATA_ARGS, root)
    if result.returncode != 0:
        raise ToolError('cargo metadata failed rc=%d: %s' % (result.returncode, result.stderr.strip()[-400:]))
    return result.stdout


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--root', default=str(Path(__file__).resolve().parents[1]),
                        help='repository root (default: this checkout)')
    parser.add_argument('--manifest-parser', choices=('auto', 'tomllib', 'fallback'), default='auto',
                        help='Cargo.toml reader: tomllib (Python 3.11+), the built-in fallback, or auto')
    parser.add_argument('--cargo-tree-file',
                        help='read `cargo tree -i zip` output from this file instead of running cargo')
    parser.add_argument('--cargo-metadata-file',
                        help='read `cargo metadata` JSON from this file instead of running cargo '
                             '(required with --cargo-tree-file: without it no local package would be scanned)')
    args = parser.parse_args(argv)
    if args.cargo_tree_file and not args.cargo_metadata_file:
        parser.error('--cargo-tree-file requires --cargo-metadata-file')
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
            tree_problems = check_tree(tree_text) + check_lock(root)
        if args.cargo_metadata_file:
            metadata_text = Path(args.cargo_metadata_file).read_text(encoding='utf-8')
        else:
            metadata_text = cargo_metadata_output(root)
        manifest_text = read_source(root / 'Cargo.toml', 'Cargo.toml')
        problems = (tree_problems + check_manifest(manifest_text, args.manifest_parser)
                    + check_sources(root, manifest_text, '', root_targets(metadata_text, root))
                    + check_local_packages(metadata_text, root))
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
