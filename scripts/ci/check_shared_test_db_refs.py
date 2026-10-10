#!/usr/bin/env python3
"""Refuse new references to the shared ``ai_memory_test`` database (#7031 H4).

The bare name ``ai_memory_test`` is the long-lived shared database on the
Postgres test hosts; its lineage high-water mark poisons every clone (#6983).
Lanes must mint an ephemeral ``ai_memory_test_*`` database instead.  Names that
merely start with ``ai_memory_test_`` never match.

Rules, applied to non-comment lines only (NAME is the bare shared name):
  R1  URL literal         slash + NAME followed by a quote, ?, space or EOL
  R2  POSTGRES_DB[=:]     NAME
  R3  --db / --db= / --dbname / -d (optionally quoted)  NAME
  R4  pg_isready ... -d   NAME
  R5  PGDATABASE / dbname / any *DB* variable assignment  NAME

A line that matches several rules gets one annotation listing all of them.
A static gate cannot follow computed names (concat!, string building); the
runtime refusals (tests/common/lane_db.rs, the pg_isolated_binary.py base rule)
cover those.  An unreadable file or a bad argument exits 2, never 0.

Allowlist lines are ``path[:line]  # citation``.  It is a ratchet: an entry
that no longer matches a hit exits 2, so the baseline may only shrink.
Exit: 0 clean, 1 violations, 2 usage error or stale allowlist entry.
"""
import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

DB = 'ai_memory' + '_test'
RULES = (
    ('R1', re.compile(r'/' + DB + r'(["\'?\s]|$)')),
    ('R2', re.compile(r'POSTGRES_DB[=:]\s*' + DB + r'\b')),
    ('R3', re.compile(r'(--db(name)?|-d)(\s+|=)["\']?' + DB + r'\b')),
    ('R4', re.compile(r'pg_isready .* -d ' + DB + r'\b')),
    ('R5', re.compile(r'\b(PGDATABASE|[A-Z0-9_]*DB[A-Z0-9_]*|dbname)\s*[=:]\s*["\']?' + DB + r'(["\'\s&?]|$)')),
)
DEFAULT_PATHS = ['.github/workflows', 'tests', 'scripts', 'infra', 'src', 'packaging', 'docs']
DEFAULT_ALLOWLIST = 'scripts/qc-allowlists/shared-test-db-allow.txt'
SKIP_TOP = {'target', '.git', '.local-runs'}
SKIP_ANY = {'node_modules', '__pycache__'}
COMMENT = re.compile(r'^\s*(#|//|--(\s|$))')

Hit = Tuple[str, int, str]


def skipped(rel: Path) -> bool:
    return rel.parts[0] in SKIP_TOP or bool(SKIP_ANY.intersection(rel.parts))


def iter_files(root: Path, paths: List[str]) -> List[Path]:
    out = []  # type: List[Path]
    for rel in paths:
        base = (root / rel).resolve()
        base.relative_to(root.resolve())  # ValueError when outside --root
        if base.is_file():
            out.append(base)
        elif base.is_dir():
            out.extend(p for p in sorted(base.rglob('*'))
                       if p.is_file() and not skipped(p.relative_to(root.resolve())))
    return out


def scan(root: Path, paths: List[str]) -> Tuple[List[Hit], Set[str], List[str]]:
    hits = []  # type: List[Hit]
    scanned = set()  # type: Set[str]
    unreadable = []  # type: List[str]
    top = root.resolve()
    for path in iter_files(root, paths):
        rel = path.relative_to(top).as_posix()
        scanned.add(rel)
        try:
            text = path.read_bytes().decode('utf-8', errors='surrogateescape')
        except OSError:
            unreadable.append(rel)
            continue
        for number, line in enumerate(text.split('\n'), 1):
            line = line.rstrip('\r')
            if DB not in line or COMMENT.match(line):
                continue
            rules = [rule for rule, pattern in RULES if pattern.search(line)]
            if rules:
                hits.append((rel, number, ','.join(rules)))
    return hits, scanned, unreadable


def load_allowlist(path: Path) -> List[Tuple[str, Optional[int]]]:
    entries = []  # type: List[Tuple[str, Optional[int]]]
    for raw in path.read_text(encoding='utf-8').splitlines():
        body = raw.split('#', 1)[0].strip()
        if not body:
            continue
        name, sep, tail = body.rpartition(':')
        if sep and tail.isdigit():
            entries.append((name, int(tail)))
        else:
            entries.append((body, None))
    return entries


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--root', required=True, help='repository root')
    parser.add_argument('--paths', nargs='+', default=DEFAULT_PATHS, help='files or directories under --root')
    parser.add_argument('--allowlist', help='allowlist file (default: <root>/%s)' % DEFAULT_ALLOWLIST)
    parser.add_argument('--list', action='store_true', help='print every hit and exit 0')
    args = parser.parse_args(argv)
    root = Path(args.root)
    allow_path = Path(args.allowlist) if args.allowlist else root / DEFAULT_ALLOWLIST
    if not root.is_dir():
        print('usage: --root %s is not a directory' % root, file=sys.stderr)
        return 2
    try:
        entries = load_allowlist(allow_path)
    except (OSError, UnicodeDecodeError) as exc:
        print('usage: cannot read allowlist %s: %s' % (allow_path, exc), file=sys.stderr)
        return 2
    try:
        hits, scanned, unreadable = scan(root, args.paths)
    except (OSError, ValueError) as exc:
        print('usage: bad --paths entry: %s' % exc, file=sys.stderr)
        return 2
    for rel in unreadable:
        print('::error file=%s::unreadable file, cannot be checked (fail closed)' % rel)
    whole = {name for name, line in entries if line is None}
    pinned = {(name, line) for name, line in entries if line is not None}

    def allowed(hit: Hit) -> bool:
        return hit[0] in whole or (hit[0], hit[1]) in pinned

    if args.list:
        for rel, number, rule in hits:
            print('%s:%d %s%s' % (rel, number, rule, ' [allowed]' if allowed((rel, number, rule)) else ''))
        return 2 if unreadable else 0
    hit_files = {h[0] for h in hits}  # type: Set[str]
    hit_lines = {(h[0], h[1]) for h in hits}
    stale = []  # type: List[str]
    for name, line in entries:
        if (root / name).is_file() and name not in scanned:
            continue
        if (line is None and name not in hit_files) or (line is not None and (name, line) not in hit_lines):
            stale.append(name if line is None else '%s:%d' % (name, line))
    violations = [h for h in hits if not allowed(h)]
    for rel, number, rule in violations:
        print('::error file=%s,line=%d::%s shared %s reference; mint an ephemeral %s_* database (#7031)'
              % (rel, number, rule, DB, DB))
    for entry in stale:
        print('stale allowlist entry (no longer matches a hit): %s' % entry, file=sys.stderr)
    if stale or unreadable:
        return 2
    if violations:
        return 1
    print('ok: no new shared %s references (%d allowlisted hits)' % (DB, len(hits)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
