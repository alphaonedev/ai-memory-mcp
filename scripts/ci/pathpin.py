#!/usr/bin/env python3
"""Fail-closed path pins for gates and scripts (#7260).

A gate that names a ``src/`` path literally scans nothing, and passes, once the
path moves. This module resolves a pinned path against the repository root and
raises (library) or exits 2 (CLI) when the path is missing or when fewer than
the required files or symbol matches are found. The counts are printed on
success so a log shows what was actually scanned.

Library::

    from pathpin import pin_path, pin_matches, PinError
    files = pin_path(root, 'src', glob='*.rs', min_files=1)
    hits = pin_matches(root, 'src', r'fn\\s+resolve_governance_policy', glob='*.rs')

CLI (exit 0 pinned, 2 missing or too few)::

    pathpin.py --path src --glob '*.rs' --min-files 50
    pathpin.py --path src/store --glob '*.rs' --symbol 'fn\\s+lease_acquire' --min-matches 1

``--path`` may repeat; each path is pinned with the same options. ``--root``
defaults to the repository root (two levels above this file). Globs match file
names, recursively. Standard library only, Python 3.9+.
"""
import argparse
import re
import sys
from pathlib import Path
from typing import List, Optional

EXIT_OK = 0
EXIT_RED = 2
DEFAULT_MIN = 1
DEFAULT_GLOB = '*'
REPO_ROOT = Path(__file__).resolve().parents[2]


class PinError(Exception):
    """A pinned path is missing or yields fewer files or matches than required."""


def _resolve(root: Path, rel: str) -> Path:
    """Resolve ``rel`` under ``root``; an escape or a missing path is a PinError."""
    base = Path(root).resolve()
    target = (base / rel).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        raise PinError(f'pathpin: {rel} escapes the root {base}') from None
    if not target.exists():
        raise PinError(f'pathpin: missing path {rel} under {base}')
    return target


def _check_minimum(minimum: int, what: str) -> None:
    if minimum < DEFAULT_MIN:
        raise PinError(f'pathpin: {what} must be at least {DEFAULT_MIN}, got {minimum}')


def _files(target: Path, glob: str) -> List[Path]:
    if target.is_file():
        return [target]
    return sorted(p for p in target.rglob(glob) if p.is_file())


def pin_path(root, rel: str, glob: str = DEFAULT_GLOB, min_files: int = DEFAULT_MIN) -> int:
    """Pin ``rel`` under ``root``: it must exist and hold at least ``min_files`` files.

    A file path counts as one file. Returns the file count.
    """
    _check_minimum(min_files, 'min_files')
    target = _resolve(Path(root), rel)
    count = len(_files(target, glob))
    if count < min_files:
        raise PinError(f'pathpin: {rel} holds {count} files matching {glob}, need at least {min_files}'
                       f' (0 files means the path moved or the glob is stale)')
    return count


def pin_matches(root, rel: str, pattern: str, glob: str = DEFAULT_GLOB,
                min_matches: int = DEFAULT_MIN) -> int:
    """Pin a symbol: ``pattern`` must match at least ``min_matches`` times under ``rel``.

    Returns the total match count over every file selected by ``glob``.
    """
    _check_minimum(min_matches, 'min_matches')
    try:
        regex = re.compile(pattern, re.MULTILINE)
    except re.error as err:
        raise PinError(f'pathpin: invalid symbol pattern {pattern!r}: {err}') from None
    target = _resolve(Path(root), rel)
    total = 0
    for path in _files(target, glob):
        total += len(regex.findall(path.read_text(encoding='utf-8', errors='replace')))
    if total < min_matches:
        raise PinError(f'pathpin: {rel} holds {total} matches of {pattern!r} in files matching {glob},'
                       f' need at least {min_matches} (0 matches means the symbol or file moved)')
    return total


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--root', default=str(REPO_ROOT), help='repository root (default: this checkout)')
    parser.add_argument('--path', action='append', required=True, help='pinned path, relative to the root')
    parser.add_argument('--glob', default=DEFAULT_GLOB, help='file-name glob, matched recursively')
    parser.add_argument('--min-files', type=int, default=DEFAULT_MIN)
    parser.add_argument('--symbol', help='regex that must match inside the pinned path')
    parser.add_argument('--min-matches', type=int, default=DEFAULT_MIN)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        for rel in args.path:
            files = pin_path(args.root, rel, glob=args.glob, min_files=args.min_files)
            line = f'pathpin: OK path={rel} files={files} glob={args.glob} min_files={args.min_files}'
            if args.symbol is not None:
                hits = pin_matches(args.root, rel, args.symbol, glob=args.glob,
                                   min_matches=args.min_matches)
                line += f' matches={hits} min_matches={args.min_matches}'
            print(line)
    except PinError as err:
        print(str(err), file=sys.stderr)
        return EXIT_RED
    return EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
