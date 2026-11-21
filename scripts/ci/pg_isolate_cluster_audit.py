#!/usr/bin/env python3
"""Cluster-global operation audit of the integration test binaries (#9592, 3-agent vote (71472661) I-7).

A per-binary clone isolates one database, not the cluster. A binary whose
tests run a cluster-global operation (roles, tablespaces, ALTER SYSTEM, a
backend signal or a pg_stat_activity read not scoped to its own database), or
assert on wall time (the load-sensitive class, PR 8230 defect 2, issue 6796),
must be on the residual list: it then runs alone on the shared database after
the pool has drained. One linear pass per line; a hit on a line that is not
scoped counts, so an unclassified form is routed to the residual list.

Usage: pg_isolate_cluster_audit.py --root REPO --residual-file FILE
Exit 0 prints ``[#9592] cluster audit ok: hits=N binaries=M``; 1 prints one
FAIL line per binary hit that is not on the residual list; 2 is an unreadable input.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

TAG = '[#9592] cluster audit'
TESTS_DIR = 'tests'
ASSERT_WINDOW_LINES = 6
CLUSTER_RE = re.compile(r'\b(?:(?:create|alter|drop)\s+(?:role|user)|create\s+tablespace|alter\s+system'
                        r'|pg_reload_conf|pg_terminate_backend|pg_stat_activity)\b', re.I)
SCOPED_RE = re.compile(r'\bdatname\b|current_database\(\)|pg_blocking_pids', re.I)
SCOPABLE = ('pg_terminate_backend', 'pg_stat_activity')
ASSERT_RE = re.compile(r'\b(?:debug_)?assert(?:_eq|_ne)?!\s*\(')
ELAPSED = 'elapsed()'
WORD_RE = re.compile(r'\w+')
MESSAGE_RE = re.compile(r'\b(?:e?println|panic)!\s*\(|\.(?:expect|context|with_context)\(\s*"')


def _statements(text: str):
    """``(first line, text)`` per logical line: a trailing-backslash continuation joins the next line."""
    start, parts = 0, []
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith('//'):
            continue
        start = start or number
        parts.append(line)
        if not line.rstrip().endswith('\\'):
            yield start, number, ' '.join(parts)
            start, parts = 0, []
    if parts:
        yield start, start + len(parts) - 1, ' '.join(parts)


def audit_text(text: str):
    """Yield ``(line, kind, token)`` for every cluster-global or wall-time-assert hit."""
    window = 0
    for first, last, line in _statements(text):
        scoped = SCOPED_RE.search(line) is not None
        if not MESSAGE_RE.search(line):
            for match in CLUSTER_RE.finditer(line):
                token = ' '.join(match.group(0).lower().split())
                if not (scoped and token in SCOPABLE):
                    yield first, 'cluster', token
        if ASSERT_RE.search(line):
            window = ASSERT_WINDOW_LINES
        if window and ELAPSED in line:
            yield first, 'load', ELAPSED
        window = 0 if line.rstrip().endswith(');') else max(0, window - 1 - (last - first))


def _owners(root: Path) -> tuple[dict[Path, set[str]], dict[Path, str]]:
    """Every test file and the binaries that compile it: its own binary, or for a shared helper
    (``tests/common/x.rs``) every binary that names it, through other helpers too (fail safe: a
    mention counts)."""
    tests = root / TESTS_DIR
    files = sorted(tests.rglob('*.rs'))
    texts = {p: p.read_text(encoding='utf-8', errors='replace') for p in files}
    def binary_of(p: Path) -> str | None:
        parts = p.relative_to(tests).parts
        if len(parts) == 1:
            return p.stem
        own = tests / parts[0]
        return parts[0] if (own.with_suffix('.rs').is_file() or (own / 'main.rs').is_file()) else None
    words = {p: set(WORD_RE.findall('\n'.join(s for _, _, s in _statements(texts[p])))) for p in files}
    owners = {p: {b} for p in files if (b := binary_of(p))}
    helpers = [p for p in files if p not in owners]
    users = {h: [p for p in files if p != h and (h.parent.name if h.name == 'mod.rs' else h.stem) in words[p]]
             for h in helpers}
    for _ in helpers:  # mention closure (code lines only); at most one pass per helper
        grew = False
        for h in helpers:
            got = set().union(*[owners.get(p, set()) for p in users[h]])
            if not got <= owners.get(h, set()):
                owners[h] = owners.get(h, set()) | got
                grew = True
        if not grew:
            break
    return {p: owners.get(p, {p.relative_to(tests).parts[0]}) for p in files}, texts


def audit_repo(root: Path) -> dict[str, list[tuple[str, str, int, str, str]]]:
    """``{binary: [(binary, rel, line, kind, token)]}``; a helper's hit counts for every binary using it."""
    found: dict[str, list[tuple[str, str, int, str, str]]] = {}
    owners, texts = _owners(root)
    for path in sorted(owners):
        rel = path.relative_to(root).as_posix()
        for line, kind, token in audit_text(texts[path]):
            for binary in sorted(owners[path]):
                found.setdefault(binary, []).append((binary, rel, line, kind, token))
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--root', required=True)
    parser.add_argument('--residual-file', required=True)
    args = parser.parse_args(argv)
    try:
        lines = Path(args.residual_file).read_text(encoding='utf-8').splitlines()
        found = audit_repo(Path(args.root))
    except OSError as exc:
        print('%s FAIL: cannot read an input: %s' % (TAG, exc))
        return 2
    residual = {ln.split()[-1] for ln in lines if ln.strip() and not ln.lstrip().startswith('#')}
    bad = [hits[0] for name, hits in sorted(found.items()) if name not in residual]
    for name, rel, line, kind, token in bad:
        print('%s FAIL: %s has a %s hit at %s:%d (%s) but is not on the residual list'
              % (TAG, name, kind, rel, line, token))
    if bad:
        return 1
    print('%s ok: hits=%d binaries=%d' % (TAG, sum(map(len, found.values())), len(found)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
