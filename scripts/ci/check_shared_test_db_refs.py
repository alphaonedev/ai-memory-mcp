#!/usr/bin/env python3
"""Refuse new references to the shared ai_memory_test database (#7031 H4).

The bare name ai_memory_test is the long-lived shared database on the
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
  R6  a quoted literal    "NAME", 'NAME' or `NAME` (a backtick in Markdown is a prose
                          code span and is not matched there)
  R7  SQL                 DATABASE NAME (any case: GRANT/DROP/ALTER/CREATE ...)
  R8  positional argument NAME as a word after psql, createdb, dropdb, pg_dump
                          or pg_restore (reported only when R2/R3 did not match)
  R9  psql meta-command   \\c NAME or \\connect NAME at the start of a line
Matching is case-insensitive for the name (Postgres folds unquoted identifiers).
A shell line that ends in a backslash is also scanned joined with the lines it
continues (not in .sql); the hit is reported at its first physical line.

A line that matches several rules gets one annotation listing all of them.
Every rule scans in linear time (no nested or overlapping quantifiers), so a
one MiB single-line file cannot stall the CI classify job.

Comments are suffix-aware: ``//`` starts a comment in Rust, C-family, JS/TS and
Go files only, ``#`` in shell, Python, YAML, TOML, Dockerfile-style and
suffix-less files only; ``#[``, ``#!`` and C preprocessor lines are code.  A
file of unknown suffix treats both as comments.  An ``--`` line is a comment
only in .sql files.

Scan scope is a deny list: every top-level directory except SKIP_TOP (build
output, VCS, scratch, changelog fragments, vendored code), every file directly
under --root (Dockerfile*, install.sh, entrypoint scripts), and any ``--paths``
entry (it must exist).  The DEFAULT_PATHS directories must all exist (a renamed
one exits 2).  A symlinked directory is not traversed.

Encoding: a UTF-8 BOM is stripped; a UTF-16 or UTF-32 BOM exits 2 naming the
file (it cannot be decoded as text, fail closed); a file with NUL bytes is
scanned both as is and with the NULs removed.

Not scanned, by design: a static gate cannot follow computed names.  That is
env indirection (``TARGET=NAME`` then ``psql -d "$TARGET"``),
string concatenation (``concat!``, string building), an ``_`` escape or a split
of the name, and a percent-encoded URL.  The runtime refusals (tests/common/lane_db.rs,
the pg_isolated_binary.py base rule) cover those.  An unreadable file or
directory, a missing path and a bad argument exit 2, never 0.

Allowlist lines are ``path:line  # citation``: line-pinned only, a non-empty
citation is required, a duplicate pin or a whole-file entry exits 2.  The path
is normalised (``./x`` is ``x``); an absolute path or a ``..`` segment exits 2.  It is a
ratchet: an entry that no longer matches a hit exits 2, so the baseline may
only shrink.  There is no landing-order exception: a citation carrying ``[landing-order`` exits 2
(#7884), so a pin whose line does not exist yet is stale like any other.
Exit: 0 clean, 1 violations, 2 usage error, bad allowlist or stale entry.
"""
import argparse
import codecs
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, List, Optional, Set, Tuple

DB = 'ai_memory' + '_test'
NAME_CHAR = r'[A-Za-z0-9_]'
NOT_NAME_CONT = r'(?!' + NAME_CHAR + r')'
DEFAULT_PATHS = ['.github', 'tests', 'scripts', 'infra', 'src', 'packaging', 'docs',
                 'benches', 'clients', 'conformance', 'deploy', 'examples', 'hooks', 'loadtest',
                 'ops', 'plugins', 'sdk', 'tools']
DEFAULT_ALLOWLIST = 'scripts/qc-allowlists/shared-test-db-allow.txt'
SKIP_TOP = frozenset({'target', '.git', '.local-runs', 'changelog.d', 'vendor', 'node_modules'})
SKIP_ANY = {'node_modules', '__pycache__'}
COMMENT_SQL = re.compile(r'^\s*(#|//|--(\s|$))')
SQL_SUFFIX = '.sql'
SLASH_SUFFIXES = frozenset({'.rs', '.js', '.mjs', '.ts', '.tsx', '.jsx', '.go', '.c', '.h', '.cc', '.cpp', '.hpp',
                            '.java'})
HASH_SUFFIXES = frozenset({'.sh', '.bash', '.py', '.yml', '.yaml', '.toml', '.cfg', '.ini', '.conf', '.env',
                           '.rb', '.pl', '.mk', ''})
PREPROCESSOR = re.compile(r'#\s*(define|include|ifn?def|if|else|elif|endif|pragma|undef|error|warning)\b')
NOT_COMMENT_AFTER_HASH = ('#[', '#!')
UTF_WIDE_BOMS = (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)
NAME_RE = re.compile(DB, re.IGNORECASE)
CONTINUATION = '\\'
QUOTES = '"\''
TOKEN_STRIP = '"\'`;,()<>'
KEY_LOWER = {'pgdatabase', 'dbname', 'db', 'database', 'db_name', 'database_name'}
KEY_LOWER_SUFFIXES = ('_db', '_dbname', '_db_name', '_database', '_database_name')
KEY_UPPER_PARTS =('DB', 'DATABASE')
RETIRED_MARK = '[landing-order'  # retired coupled-pin marker; a citation carrying it exits 2 (#7884)
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
    for found in NAME_RE.finditer(line):
        after = found.end()
        if after >= len(line) or not _is_word_char(line[after]):
            out.append(found.start())
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
        elif seen_command and bare.lower() == DB:
            return True
    return False


R4_FLAG = re.compile(r'\s-d\s+' + DB + NOT_NAME_CONT, re.IGNORECASE)
RULES = (
    ('R1', re.compile('/' + DB + NOT_NAME_CONT, re.IGNORECASE).search),
    ('R2', re.compile(r'POSTGRES_DB[=:]\s*' + DB + NOT_NAME_CONT, re.IGNORECASE).search),
    ('R3', re.compile(r'(--db(name)?|-d)(\s+|=)?["\']?' + DB + NOT_NAME_CONT, re.IGNORECASE).search),
    ('R4', rule_r4),
    ('R5', rule_r5),
    ('R6', re.compile('["\']' + DB + '["\']', re.IGNORECASE).search),
    ('R7', re.compile(r'\bDATABASE\s+' + DB + NOT_NAME_CONT, re.IGNORECASE).search),
    ('R8', rule_r8),
    ('R9', re.compile(r'^\s*\\(c|connect)\s+["\']?' + DB + NOT_NAME_CONT, re.IGNORECASE).search),
)  # type: Tuple[Tuple[str, LinePredicate], ...]
R8_SUPPRESSED_BY = ('R2', 'R3')
BACKTICK_LITERAL = re.compile('(?<!`)`' + DB + '`(?!`)', re.IGNORECASE).search  # an R6 form outside prose files
PROSE_SUFFIXES = frozenset({'.md', '.markdown'})


def skipped(rel: Path) -> bool:
    return rel.parts[0] in SKIP_TOP or bool(SKIP_ANY.intersection(rel.parts))


def raw_rules(line: str, prose: bool = False) -> Set[str]:
    if not NAME_RE.search(line):
        return set()
    found = {rule for rule, check in RULES if check(line)}
    if not prose and BACKTICK_LITERAL(line):
        found.add('R6')
    return found


def finish_rules(found: Set[str]) -> List[str]:
    rules = [rule for rule, _check in RULES if rule in found]
    if 'R8' in rules and any(other in rules for other in R8_SUPPRESSED_BY):
        rules.remove('R8')
    return rules


def line_rules(line: str) -> List[str]:
    return finish_rules(raw_rules(line))


def is_comment(line: str, suffix: str) -> bool:
    if suffix == SQL_SUFFIX:
        return bool(COMMENT_SQL.match(line))
    body = line.lstrip()
    if suffix in SLASH_SUFFIXES:
        return body.startswith('//')
    hash_comment = body.startswith('#') and not body.startswith(NOT_COMMENT_AFTER_HASH)
    if suffix in HASH_SUFFIXES:
        return hash_comment
    return (hash_comment and not PREPROCESSOR.match(body)) or body.startswith('//')


def continues(line: str, suffix: str) -> bool:
    return line.endswith(CONTINUATION) and not is_comment(line, suffix)


def join_continuation(lines: List[str], start: int, suffix: str) -> str:
    """Join the chain that starts at ``start``; it ends at the first line that does not continue.

    A comment line ends the chain (it never continues), so the next chain starts after it and each
    physical line is joined at most once: the whole scan stays linear (#7171).
    """
    parts = [lines[start][:-1]]
    pos = start
    while continues(lines[pos], suffix) and pos + 1 < len(lines):
        pos += 1
        parts.append(lines[pos][:-1] if lines[pos].endswith(CONTINUATION) else lines[pos])
    return ' '.join(part.strip() for part in parts)


def scan_text(text: str, suffix: str) -> Dict[int, List[str]]:
    """Map line number to the rules it hits.  A continued shell line is also scanned joined."""
    lines = [raw.rstrip('\r') for raw in text.split('\n')]
    joins = suffix != SQL_SUFFIX
    out = {}  # type: Dict[int, List[str]]
    prose = suffix in PROSE_SUFFIXES
    for index, line in enumerate(lines):
        if is_comment(line, suffix):
            continue
        found = raw_rules(line, prose)
        if joins and continues(line, suffix) and not (index and continues(lines[index - 1], suffix)):
            found |= raw_rules(join_continuation(lines, index, suffix), prose)
        rules = finish_rules(found)
        if rules:
            out[index + 1] = rules
    return out


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


def default_scan_paths(root: Path) -> List[str]:
    """Deny-list scope: every top-level directory except SKIP_TOP, plus DEFAULT_PATHS and the root files."""
    tops = sorted(p.name for p in root.iterdir() if p.is_dir() and not p.is_symlink() and p.name not in SKIP_TOP)
    return sorted(set(DEFAULT_PATHS) | set(tops)) + root_files(root)


def scan(root: Path, paths: List[str]) -> Tuple[List[Hit], Set[str], List[str]]:
    hits = []  # type: List[Hit]
    scanned = set()  # type: Set[str]
    unreadable = []  # type: List[str]
    top = root.resolve()
    for path in iter_files(root, paths, unreadable):
        rel = path.relative_to(top).as_posix()
        scanned.add(rel)
        try:
            data = path.read_bytes()
        except OSError:
            unreadable.append(rel)
            continue
        if data.startswith(UTF_WIDE_BOMS):
            unreadable.append(rel)  # UTF-16/32 cannot be scanned as text: fail closed
            continue
        if data.startswith(codecs.BOM_UTF8):
            data = data[len(codecs.BOM_UTF8):]
        found = scan_text(data.decode('utf-8', errors='surrogateescape'), path.suffix)
        if b'\x00' in data:
            stripped = data.replace(b'\x00', b'').decode('utf-8', errors='surrogateescape')
            for number, rules in scan_text(stripped, path.suffix).items():
                found.setdefault(number, rules)
        for number in sorted(found):
            hits.append((rel, number, ','.join(found[number])))
    return hits, scanned, unreadable


class AllowlistError(Exception):
    """A malformed allowlist line (exit 2)."""


def load_allowlist(path: Path) -> List[Tuple[str, int]]:
    """Return the line-pinned entries."""
    entries = []  # type: List[Tuple[str, int]]
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
        if RETIRED_MARK in citation:
            raise AllowlistError('%s: the landing-order marker is retired, pin the plain line' % where)
        if not hash_sep or not citation.strip():
            raise AllowlistError('%s: a non-empty # citation is required' % where)
        pure = PurePosixPath(name)
        if pure.is_absolute() or '..' in pure.parts or not pure.parts:
            raise AllowlistError('%s: the path must be relative without .. segments' % where)
        name = pure.as_posix()
        pin = (name, int(tail))
        if pin in seen:
            raise AllowlistError('%s: duplicate pin' % where)
        seen.add(pin)
        entries.append(pin)
    return entries


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
        entries = load_allowlist(allow_path)
    except (OSError, UnicodeDecodeError) as exc:
        print('usage: cannot read allowlist %s: %s' % (allow_path, exc), file=sys.stderr)
        return 2
    except AllowlistError as exc:
        print('usage: %s: %s' % (allow_path, exc), file=sys.stderr)
        return 2
    paths = args.paths if args.paths else default_scan_paths(root)
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
        if args.paths and (root / name).is_file() and name not in scanned:  # narrowed scan only (#7173)
            continue
        if (name, line) not in hit_lines:
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
