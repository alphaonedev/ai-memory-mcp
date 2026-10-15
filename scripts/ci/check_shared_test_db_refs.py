#!/usr/bin/env python3
"""Refuse new references to the shared ``ai_memory_test`` database (#7031 H4).

The bare name ``ai_memory_test`` is the long-lived shared database on the
Postgres test hosts; its lineage high-water mark poisons every clone (#6983).
Lanes must mint an ephemeral ``ai_memory_test_*`` database instead.  Names that
merely start with ``ai_memory_test_`` never match.

Rules, applied to non-comment lines only (NAME is the bare shared name):
  R1  URL literal         slash + NAME not followed by a name character
  R2  POSTGRES_DB[=:]     NAME
  R3  --db / --db= / --dbname / -d / glued -dNAME (optionally quoted)  NAME
  R4  pg_isready ... -d   NAME
  R5  KEY [=:] NAME, KEY being PGDATABASE, dbname, db, database, db_name,
      database_name (any case), a lower-case key ending in _db, _dbname,
      _db_name, _database or _database_name, or an upper-case word containing
      DB or DATABASE; the key may be quoted
  R6  a quoted literal    "NAME" or 'NAME'
  R7  SQL                 DATABASE NAME (any case: GRANT/DROP/ALTER/CREATE ...)
  R8  positional argument NAME as a word after psql, createdb, dropdb, pg_dump
                          or pg_restore (reported only when R2/R3 did not match)

A line that matches several rules gets one annotation listing all of them.
Every rule scans in linear time (no nested or overlapping quantifiers), so a
one MiB single-line file cannot stall the CI classify job.

Scan scope: the DEFAULT_PATHS directories (all must exist, a renamed one exits
2), every file directly under --root (Dockerfile*, install.sh, entrypoint
scripts), and any ``--paths`` entry (it must exist).  A symlinked directory is
not traversed.  An ``--`` line is a comment only in .sql files.

A static gate cannot follow computed names (concat!, string building); the
runtime refusals (tests/common/lane_db.rs, the pg_isolated_binary.py base rule)
cover those.  An unreadable file or directory, a missing path and a bad
argument exit 2, never 0.

Allowlist lines are ``path:line  # citation``: line-pinned only, a non-empty
citation is required, a duplicate pin or a whole-file entry exits 2.  It is a
ratchet: an entry that no longer matches a hit exits 2, so the baseline may
only shrink.  The one bounded exception is a citation carrying
``[landing-order #7088]`` on the seven pins of scripts/ci/tests/test_pg_isolated_binary.py
(LANDING_ORDER_COUPLED): those lines are added by PR #7088, so such a pin is
excused only while its line does not exist yet (file absent or pin past EOF).
Any other PR number or path exits 2; a coupled pin whose line exists but is not
a hit is stale; a coupled pin that matches a hit prints a ``::warning`` asking
for the marker's removal.  Remove the constants and markers once #7088 lands.
Exit: 0 clean, 1 violations, 2 usage error, bad allowlist or stale entry.
"""
import argparse
import os
import re
import sys
from pathlib import Path
from typing import Callable, List, Optional, Set, Tuple

DB = 'ai_memory' + '_test'
NAME_CHAR = r'[A-Za-z0-9_]'
NOT_NAME_CONT = r'(?!' + NAME_CHAR + r')'
DEFAULT_PATHS = ['.github/workflows', 'tests', 'scripts', 'infra', 'src', 'packaging', 'docs',
                 'benches', 'clients', 'conformance', 'deploy', 'examples', 'hooks', 'loadtest',
                 'ops', 'plugins', 'sdk', 'tools']
DEFAULT_ALLOWLIST = 'scripts/qc-allowlists/shared-test-db-allow.txt'
SKIP_TOP = {'target', '.git', '.local-runs'}
SKIP_ANY = {'node_modules', '__pycache__'}
COMMENT = re.compile(r'^\s*(#|//)')
COMMENT_SQL = re.compile(r'^\s*(#|//|--(\s|$))')
SQL_SUFFIX = '.sql'
QUOTES = '"\''
TOKEN_STRIP = '"\'`;,()<>'
KEY_LOWER = {'pgdatabase', 'dbname', 'db', 'database', 'db_name', 'database_name'}
KEY_LOWER_SUFFIXES = ('_db', '_dbname', '_db_name', '_database', '_database_name')
KEY_UPPER_PARTS =('DB', 'DATABASE')
COUPLED_MARK = re.compile(r'\[landing-order #(\d+)\]')
# The only PR whose pinned lines may be absent until it lands, and the only path it may mark (#7164).
# Remove both constants and the seven markers in the change that lands after #7088.
LANDING_ORDER_PRS = frozenset({7088})
LANDING_ORDER_COUPLED = frozenset({('scripts/ci/tests/test_pg_isolated_binary.py', 7088)})
POSITIONAL_COMMANDS = {'psql', 'createdb', 'dropdb', 'pg_dump', 'pg_restore'}

Hit = Tuple[str, int, str]
LinePredicate = Callable[[str], bool]


def _key_is_database(key: str) -> bool:
    lowered = key.lower()
    if lowered in KEY_LOWER or lowered.endswith(KEY_LOWER_SUFFIXES):
        return True
    return key == key.upper() and any(part in key for part in KEY_UPPER_PARTS)


def _is_word_char(char: str) -> bool:
    return char.isalnum() or char == '_'


def _assignment_key(line: str, name_at: int) -> str:
    """Return the key of ``KEY [quote] [=:] [quote] NAME`` ending at name_at, or ''."""
    pos = name_at
    while pos > 0 and line[pos - 1] in QUOTES:
        pos -= 1
    while pos > 0 and line[pos - 1].isspace():
        pos -= 1
    if pos == 0 or line[pos - 1] not in '=:':
        return ''
    pos -= 1
    while pos > 0 and line[pos - 1].isspace():
        pos -= 1
    while pos > 0 and line[pos - 1] in QUOTES:
        pos -= 1
    end = pos
    while pos > 0 and _is_word_char(line[pos - 1]):
        pos -= 1
    return line[pos:end]


def _name_offsets(line: str) -> List[int]:
    """Offsets of every NAME occurrence that is not the start of a longer name."""
    out = []  # type: List[int]
    at = line.find(DB)
    while at != -1:
        after = at + len(DB)
        if after >= len(line) or not _is_word_char(line[after]):
            out.append(at)
        at = line.find(DB, at + 1)
    return out


def rule_r5(line: str) -> bool:
    return any(_key_is_database(_assignment_key(line, at)) for at in _name_offsets(line))


def rule_r4(line: str) -> bool:
    return 'pg_isready' in line and bool(R4_FLAG.search(line))


def rule_r8(line: str) -> bool:
    tokens = line.split()
    seen_command = False
    for token in tokens:
        bare = token.strip(TOKEN_STRIP)
        if bare.rsplit('/', 1)[-1] in POSITIONAL_COMMANDS:
            seen_command = True
        elif seen_command and bare == DB:
            return True
    return False


R4_FLAG = re.compile(r'\s-d\s+' + DB + NOT_NAME_CONT)
RULES = (
    ('R1', re.compile('/' + DB + NOT_NAME_CONT).search),
    ('R2', re.compile(r'POSTGRES_DB[=:]\s*' + DB + NOT_NAME_CONT).search),
    ('R3', re.compile(r'(--db(name)?|-d)(\s+|=)?["\']?' + DB + NOT_NAME_CONT).search),
    ('R4', rule_r4),
    ('R5', rule_r5),
    ('R6', re.compile('["\']' + DB + '["\']').search),
    ('R7', re.compile(r'\bDATABASE\s+' + DB + NOT_NAME_CONT, re.IGNORECASE).search),
    ('R8', rule_r8),
)  # type: Tuple[Tuple[str, LinePredicate], ...]
R8_SUPPRESSED_BY = ('R2', 'R3')


def skipped(rel: Path) -> bool:
    return rel.parts[0] in SKIP_TOP or bool(SKIP_ANY.intersection(rel.parts))


def line_rules(line: str) -> List[str]:
    rules = [rule for rule, check in RULES if check(line)]
    if 'R8' in rules and any(other in rules for other in R8_SUPPRESSED_BY):
        rules.remove('R8')
    return rules


def iter_files(root: Path, paths: List[str], unreadable: List[str]) -> List[Path]:
    top = root.resolve()
    out = []  # type: List[Path]

    def walk_error(exc: OSError) -> None:
        failed = Path(exc.filename) if exc.filename else top
        unreadable.append(failed.relative_to(top).as_posix() if failed != top else '.')

    for rel in paths:
        base = (root / rel).resolve()
        base.relative_to(top)  # ValueError when outside --root
        if base.is_file():
            out.append(base)
        elif base.is_dir():
            for here, dirs, files in os.walk(str(base), onerror=walk_error):
                here_rel = Path(here).relative_to(top)
                dirs[:] = sorted(d for d in dirs if not skipped(here_rel / d))
                out.extend(Path(here) / f for f in sorted(files) if not skipped(here_rel / f))
        else:
            raise ValueError('path does not exist: %s' % rel)
    return out


def root_files(root: Path) -> List[str]:
    return sorted(p.name for p in root.iterdir() if p.is_file() and not skipped(Path(p.name)))


def scan(root: Path, paths: List[str]) -> Tuple[List[Hit], Set[str], List[str]]:
    hits = []  # type: List[Hit]
    scanned = set()  # type: Set[str]
    unreadable = []  # type: List[str]
    top = root.resolve()
    for path in iter_files(root, paths, unreadable):
        rel = path.relative_to(top).as_posix()
        scanned.add(rel)
        try:
            text = path.read_bytes().decode('utf-8', errors='surrogateescape')
        except OSError:
            unreadable.append(rel)
            continue
        comment = COMMENT_SQL if path.suffix == SQL_SUFFIX else COMMENT
        for number, line in enumerate(text.split('\n'), 1):
            line = line.rstrip('\r')
            if DB not in line or comment.match(line):
                continue
            rules = line_rules(line)
            if rules:
                hits.append((rel, number, ','.join(rules)))
    return hits, scanned, unreadable


class AllowlistError(Exception):
    """A malformed allowlist line (exit 2)."""


def load_allowlist(path: Path) -> Tuple[List[Tuple[str, int]], Set[Tuple[str, int]]]:
    """Return (pins, coupled pins).  A coupled pin names a line another open PR adds."""
    entries = []  # type: List[Tuple[str, int]]
    coupled = set()  # type: Set[Tuple[str, int]]
    seen = set()  # type: Set[Tuple[str, int]]
    for number, raw in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        body, hash_sep, citation = raw.partition('#')
        body = body.strip()
        if not body:
            continue
        where = 'allowlist line %d (%s)' % (number, raw.strip())
        name, sep, tail = body.rpartition(':')
        if not sep or not name or not tail.isdigit() or int(tail) < 1:
            raise AllowlistError('%s: expected path:line, whole-file entries are not allowed' % where)
        if not hash_sep or not citation.strip():
            raise AllowlistError('%s: a non-empty # citation is required' % where)
        pin = (name, int(tail))
        if pin in seen:
            raise AllowlistError('%s: duplicate pin' % where)
        seen.add(pin)
        entries.append(pin)
        marker = COUPLED_MARK.search(citation)
        if marker:
            pr_number = int(marker.group(1))
            if pr_number not in LANDING_ORDER_PRS or (name, pr_number) not in LANDING_ORDER_COUPLED:
                raise AllowlistError('%s: unknown landing-order marker (only %s may carry it)'
                                     % (where, ', '.join('%s #%d' % pair for pair in sorted(LANDING_ORDER_COUPLED))))
            coupled.add(pin)
    return entries, coupled


def line_exists(path: Path, number: int) -> bool:
    """True when ``path`` is a readable file with at least ``number`` lines (an unreadable file counts as existing)."""
    try:
        text = path.read_bytes().decode('utf-8', errors='surrogateescape')
    except FileNotFoundError:
        return False
    except OSError:
        return True
    count = text.count('\n') + (0 if text.endswith('\n') or not text else 1)
    return number <= count


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--root', required=True, help='repository root')
    parser.add_argument('--paths', nargs='+', help='files or directories under --root (default: the whole tree)')
    parser.add_argument('--allowlist', help='allowlist file (default: <root>/%s)' % DEFAULT_ALLOWLIST)
    parser.add_argument('--list', action='store_true', help='print every hit and exit 0')
    args = parser.parse_args(argv)
    root = Path(args.root)
    allow_path = Path(args.allowlist) if args.allowlist else root / DEFAULT_ALLOWLIST
    if not root.is_dir():
        print('usage: --root %s is not a directory' % root, file=sys.stderr)
        return 2
    try:
        entries, coupled = load_allowlist(allow_path)
    except (OSError, UnicodeDecodeError) as exc:
        print('usage: cannot read allowlist %s: %s' % (allow_path, exc), file=sys.stderr)
        return 2
    except AllowlistError as exc:
        print('usage: %s: %s' % (allow_path, exc), file=sys.stderr)
        return 2
    paths = args.paths if args.paths else DEFAULT_PATHS + (root_files(root) if root.is_dir() else [])
    try:
        hits, scanned, unreadable = scan(root, paths)
    except (OSError, ValueError) as exc:
        print('usage: bad --paths entry: %s' % exc, file=sys.stderr)
        return 2
    for rel in unreadable:
        print('::error file=%s::unreadable file or directory, cannot be checked (fail closed)' % rel)
    pinned = set(entries)
    hit_lines = {(h[0], h[1]) for h in hits}
    if args.list:
        for rel, number, rule in hits:
            print('%s:%d %s%s' % (rel, number, rule, ' [allowed]' if (rel, number) in pinned else ''))
        return 2 if unreadable else 0
    stale = []  # type: List[str]
    for name, line in entries:
        if (root / name).is_file() and name not in scanned:
            continue
        if (name, line) in hit_lines:
            if (name, line) in coupled:
                print('::warning file=%s,line=%d::coupled pin now matches a hit; remove its [landing-order] marker'
                      % (name, line))
        elif (name, line) not in coupled or line_exists(root / name, line):
            stale.append('%s:%d' % (name, line))
    violations = [h for h in hits if (h[0], h[1]) not in pinned]
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
