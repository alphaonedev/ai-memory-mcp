#!/usr/bin/env python3
"""Ratchet on hard-coded ``src/`` path literals in tests, scripts and workflows (#7260).

A gate or test that names ``src/...`` by literal path silently goes blind when
that tree is moved (the failure class of #7260). This ratchet counts the
literals per file in ``tests/``, ``scripts/`` and ``.github/workflows/`` and
compares them with ``scripts/qc-allowlists/src-path-literals-baseline.txt``.

Exit codes: 0 clean, 1 a file gained a literal (or a new file has one),
2 setup error (missing or moved scan root, missing baseline, bad baseline).
The baseline may only shrink: ``--update-baseline`` lowers counts and drops
cleared files, and refuses an increase or a new file.

Run: python3 scripts/ci/check_src_path_literals.py [--root DIR] [--baseline FILE] [--update-baseline]
"""
import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pathpin  # noqa: E402  (path set above)

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_RED = 2
BASELINE_REL = 'scripts/qc-allowlists/src-path-literals-baseline.txt'
# (scan root, glob that must match at least one file) pairs; each is pinned.
SCAN_ROOTS = (
    ('tests', '*.rs'),
    ('scripts', '*.py'),
    ('.github/workflows', '*.yml'),
)
SCAN_SUFFIXES = frozenset({'.rs', '.py', '.sh', '.yml', '.yaml', '.awk'})
SKIPPED_PARTS = frozenset({'__pycache__', 'node_modules', 'target'})
# ``src/`` not preceded by a path or word character: ``tsrc/`` and ``a/src/`` do not count.
LITERAL_RE = re.compile(r'(?<![\w./-])src/')
BASELINE_HEADER = (
    '# src-path-literals baseline (#7260): count of hard-coded src/ path literals per file.\n'
    '# A ratchet: it may only shrink. Lower it with\n'
    '#   python3 scripts/ci/check_src_path_literals.py --update-baseline\n'
    '# Format: <count> <repo-relative path>\n'
)


class RatchetError(Exception):
    """A setup or baseline problem (exit 2) or an illegal baseline change."""


def count_literals(text: str) -> int:
    return len(LITERAL_RE.findall(text))


def parse_baseline(text: str) -> Dict[str, int]:
    counts = {}  # type: Dict[str, int]
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        head, _, path = line.partition(' ')
        if not head.isdigit() or not path.strip():
            raise RatchetError(f'baseline line {number} is not "<count> <path>": {raw!r}')
        path = path.strip()
        if path in counts:
            raise RatchetError(f'baseline line {number} repeats {path}')
        counts[path] = int(head)
    return counts


def render_baseline(counts: Dict[str, int]) -> str:
    body = ''.join(f'{counts[path]} {path}\n' for path in sorted(counts))
    return BASELINE_HEADER + body


def compare(current: Dict[str, int], baseline: Dict[str, int]) -> Tuple[List[str], List[str]]:
    """Return (violations, shrinkable) for the current counts against the baseline."""
    violations = []  # type: List[str]
    shrinkable = []  # type: List[str]
    for path in sorted(set(current) | set(baseline)):
        have = current.get(path, 0)
        allowed = baseline.get(path, 0)
        if have > allowed:
            violations.append(f'{path}: {have} src/ path literal(s), baseline allows {allowed}')
        elif have < allowed:
            shrinkable.append(f'{path}: {have} src/ path literal(s), baseline has {allowed}')
    return violations, shrinkable


def lowered_baseline(current: Dict[str, int], baseline: Dict[str, int]) -> Dict[str, int]:
    """The baseline lowered to the current counts; refuses a raise or a new file."""
    violations, _ = compare(current, baseline)
    if violations:
        raise RatchetError('the baseline may only shrink: ' + '; '.join(violations))
    return {path: have for path, have in current.items() if have > 0}


def _scan_files(root: Path, rel: str) -> List[Path]:
    base = root / rel
    return sorted(p for p in base.rglob('*')
                  if p.is_file() and p.suffix in SCAN_SUFFIXES
                  and not SKIPPED_PARTS.intersection(p.relative_to(root).parts))


def scan(root: Path) -> Dict[str, int]:
    """Pin every scan root, then count literals per file (files with none are omitted)."""
    root = Path(root)
    for rel, glob in SCAN_ROOTS:
        try:
            pathpin.pin_path(root, rel, glob=glob)
        except pathpin.PinError as err:
            raise RatchetError(str(err)) from err
    counts = {}  # type: Dict[str, int]
    for rel, _ in SCAN_ROOTS:
        for path in _scan_files(root, rel):
            hits = count_literals(path.read_bytes().decode('utf-8', errors='replace'))
            if hits:
                counts[path.relative_to(root).as_posix()] = hits
    return counts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--root', default=str(Path(__file__).resolve().parents[2]),
                        help='repository root (default: this checkout)')
    parser.add_argument('--baseline', default=None,
                        help=f'baseline file (default: <root>/{BASELINE_REL})')
    parser.add_argument('--update-baseline', action='store_true',
                        help='lower the baseline to the current counts (never raises)')
    return parser


def run(args: argparse.Namespace) -> int:
    root = Path(args.root)
    baseline_path = Path(args.baseline) if args.baseline else root / BASELINE_REL
    if not baseline_path.is_file():
        raise RatchetError(f'missing baseline {baseline_path}')
    baseline = parse_baseline(baseline_path.read_bytes().decode('utf-8'))
    current = scan(root)
    if args.update_baseline:
        try:
            lowered = lowered_baseline(current, baseline)
        except RatchetError as err:
            print(f'src-path-literals: {err}', file=sys.stderr)
            return EXIT_VIOLATION
        baseline_path.write_text(render_baseline(lowered))
        print(f'src-path-literals: baseline written, {len(lowered)} file(s), '
              f'{sum(lowered.values())} literal(s)')
        return EXIT_OK
    violations, shrinkable = compare(current, baseline)
    for line in violations:
        print(f'src-path-literals: RED {line}', file=sys.stderr)
    if violations:
        print('src-path-literals: use pathpin (tests/common/pathpin.rs, scripts/ci/pathpin.py) '
              'or a named constant instead of a new src/ literal', file=sys.stderr)
        return EXIT_VIOLATION
    for line in shrinkable:
        print(f'src-path-literals: shrinkable {line} (run --update-baseline)')
    print(f'src-path-literals: OK files={len(current)} literals={sum(current.values())} '
          f'baseline_files={len(baseline)}')
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except RatchetError as err:
        print(f'src-path-literals: {err}', file=sys.stderr)
        return EXIT_RED


if __name__ == '__main__':
    sys.exit(main())
