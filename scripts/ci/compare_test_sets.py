#!/usr/bin/env python3
"""Compare the tests two runners executed, and how each one ended (#7259).

Proves a runner swap (``cargo test`` -> ``cargo nextest run``) ran the same
tests with the same outcomes. The baseline is a ``cargo test`` log (libtest
``test <name> ... ok|FAILED|ignored`` lines grouped under their ``Running``
header). The candidate is a nextest run: its status lines
(``PASS [ 0.011s] <binary id> <name>``) and/or its JUnit XML.

Both sides are reduced to ``{(binary, test name): "pass" | "fail"}``. Ignored
and skipped tests are not executed tests and are left out of both sides; doc
tests are left out too (nextest does not run them, they stay on
``cargo test --doc``). Binary names are normalised so ``ai-memory`` (the lib),
``ai-memory::bin/ai-memory`` and ``ai-memory::recall_basic`` line up with the
``Running unittests src/lib.rs`` / ``src/main.rs`` / ``tests/recall_basic.rs``
headers.

Usage::

    compare_test_sets.py --cargo-log A.log [B.log ...] \\
        (--nextest-log C.log [...] | --nextest-junit junit.xml [...])

Exit codes: 0 identical sets AND identical outcomes, 1 they differ (a readable
diff is printed), 2 unusable input: an empty, missing or unparseable file is a
failure, never a pass (fail closed). Standard library only, Python 3.9+.
"""
import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple

EXIT_IDENTICAL = 0
EXIT_DIFFERENT = 1
EXIT_UNUSABLE = 2
PASS = 'pass'
FAIL = 'fail'
LIB_KEY = 'lib'
BIN_PREFIX = 'bin/'
DEFAULT_MAX_LIST = 40

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
_STAMP_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T[\d:.]+Z ?')
_RUNNING_RE = re.compile(r'^\s*Running (?:(?P<unit>unittests) )?(?P<src>\S+)(?: \((?P<exe>[^)]+)\))?\s*$')
_DOCTEST_RE = re.compile(r'^\s*Doc-tests\b')
_CARGO_TEST_RE = re.compile(r'^test (?P<name>.+?) \.\.\. (?P<res>ok|FAILED|ignored)\b')
_HASH_RE = re.compile(r'-[0-9a-f]{16}$')
_NEXTEST_RE = re.compile(
    r'^\s*(?P<st>PASS|LEAK-FAIL|LEAK|FAIL|TIMEOUT|ABORT|SIG[A-Z0-9]+|EXEC-?FAIL|FLAKY(?: \d+/\d+)?)'
    r'\s+\[[^\]]*\]\s+(?:\(\s*\d+/\s*\d+\)\s+)?(?P<bin>\S+)\s+(?P<name>.+?)\s*$')
_NEXTEST_PASS = ('PASS', 'LEAK')

Key = Tuple[str, str]
Outcomes = Dict[Key, str]


class ParseError(Exception):
    """Unusable input: empty, unparseable or contradictory (fail closed)."""


class Report(NamedTuple):
    baseline: Outcomes
    candidate: Outcomes
    only_baseline: List[Key]
    only_candidate: List[Key]
    outcome_diffs: List[Tuple[Key, str, str]]

    @property
    def identical(self) -> bool:
        return not (self.only_baseline or self.only_candidate or self.outcome_diffs)


def _clean(line: str) -> str:
    return _STAMP_RE.sub('', _ANSI_RE.sub('', line)).rstrip()


def _norm(name: str) -> str:
    return name.replace('-', '_')


def _merge(into: Outcomes, key: Key, outcome: str) -> None:
    if into.get(key) == FAIL:
        return  # a failure is never overwritten by a later pass
    into[key] = outcome


def _cargo_binary(match: 're.Match[str]') -> str:
    exe = (match.group('exe') or match.group('src')).strip()
    stem = _norm(_HASH_RE.sub('', Path(exe).name))
    if match.group('unit'):
        src = match.group('src').strip()
        if src.endswith('lib.rs'):
            return LIB_KEY
        return BIN_PREFIX + stem
    return stem


def parse_cargo_log(text: str) -> Outcomes:
    """``cargo test`` log -> ``{(binary, test): pass|fail}`` (ignored tests and doc tests excluded)."""
    out: Outcomes = {}
    current: Optional[str] = None
    in_doc = False
    for raw in text.splitlines():
        line = _clean(raw)
        running = _RUNNING_RE.match(line)
        if running and (running.group('src').endswith('.rs') or '/deps/' in running.group('src')):
            current, in_doc = _cargo_binary(running), False
            continue
        if _DOCTEST_RE.match(line):
            current, in_doc = None, True
            continue
        found = _CARGO_TEST_RE.match(line)
        if not found:
            continue
        if in_doc or found.group('res') == 'ignored':
            continue
        if current is None:
            raise ParseError('cargo log: test line %r before any "Running" header' % line[:80])
        _merge(out, (current, found.group('name')), PASS if found.group('res') == 'ok' else FAIL)
    if not out:
        raise ParseError('cargo log: no executed tests found')
    return out


def _nextest_binary(binary_id: str) -> str:
    rest = binary_id.split('::', 1)[1] if '::' in binary_id else ''
    return _norm(rest) if rest else LIB_KEY


def parse_nextest_log(text: str) -> Outcomes:
    """nextest status lines -> ``{(binary, test): pass|fail}`` (retry attempts and skips excluded)."""
    out: Outcomes = {}
    for raw in text.splitlines():
        line = _clean(raw)
        found = _NEXTEST_RE.match(line)
        if not found:
            continue
        status = found.group('st')
        ok = status in _NEXTEST_PASS or status.startswith('FLAKY')
        _merge(out, (_nextest_binary(found.group('bin')), found.group('name')), PASS if ok else FAIL)
    if not out:
        raise ParseError('nextest log: no PASS/FAIL result lines found')
    return out


def parse_junit(text: str) -> Outcomes:
    """nextest JUnit XML -> ``{(binary, test): pass|fail}`` (skipped cases excluded)."""
    if '<!DOCTYPE' in text.upper():
        raise ParseError('junit: DOCTYPE is refused')
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ParseError('junit: not well-formed XML: %s' % exc)
    out: Outcomes = {}
    for suite in root.iter('testsuite'):
        for case in suite.iter('testcase'):
            tags = {child.tag for child in case}
            if 'skipped' in tags:
                continue
            binary = _nextest_binary(case.get('classname') or suite.get('name') or '')
            failed = bool(tags & {'failure', 'error'})  # flakyFailure = a retried attempt, the final result passed
            _merge(out, (binary, case.get('name') or ''), FAIL if failed else PASS)
    if not out:
        raise ParseError('junit: no executed test cases found')
    return out


def compare(baseline: Outcomes, candidate: Outcomes) -> Report:
    """Set and outcome difference; an empty side is refused."""
    if not baseline or not candidate:
        raise ParseError('refusing to compare an empty test set (baseline=%d candidate=%d)'
                         % (len(baseline), len(candidate)))
    only_base = sorted(set(baseline) - set(candidate))
    only_cand = sorted(set(candidate) - set(baseline))
    diffs = [(k, baseline[k], candidate[k]) for k in sorted(set(baseline) & set(candidate))
             if baseline[k] != candidate[k]]
    return Report(baseline, candidate, only_base, only_cand, diffs)


def _count(outcomes: Outcomes, which: str) -> int:
    return sum(1 for v in outcomes.values() if v == which)


def _section(title: str, rows: List[str], max_list: int) -> List[str]:
    lines = ['%s: %d' % (title, len(rows))]
    lines += ['  ' + r for r in rows[:max_list]]
    if len(rows) > max_list:
        lines.append('  ... and %d more' % (len(rows) - max_list))
    return lines


def render(report: Report, max_list: int = DEFAULT_MAX_LIST) -> str:
    """Readable summary and diff."""
    b, c = report.baseline, report.candidate
    lines = ['executed tests: baseline=%d candidate=%d' % (len(b), len(c)),
             'outcomes: baseline pass=%d fail=%d | candidate pass=%d fail=%d'
             % (_count(b, PASS), _count(b, FAIL), _count(c, PASS), _count(c, FAIL))]
    lines += _section('only in baseline (cargo test)', ['%s %s' % k for k in report.only_baseline], max_list)
    lines += _section('only in candidate (nextest)', ['%s %s' % k for k in report.only_candidate], max_list)
    lines += _section('outcome differences', ['%s %s: %s -> %s' % (k[0], k[1], was, now)
                                              for k, was, now in report.outcome_diffs], max_list)
    lines.append('RESULT: %s' % ('IDENTICAL (same executed set, same outcomes)' if report.identical else 'DIFFERENT'))
    return '\n'.join(lines)


def _read(paths: List[str]) -> List[str]:
    texts = []
    for path in paths:
        try:
            texts.append(Path(path).read_text(encoding='utf-8', errors='replace'))
        except OSError as exc:
            raise ParseError('cannot read %s: %s' % (path, exc))
    return texts


def _load(parser, paths: List[str]) -> Outcomes:
    merged: Outcomes = {}
    for text in _read(paths):
        for key, outcome in parser(text).items():
            _merge(merged, key, outcome)
    return merged


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--cargo-log', nargs='+', required=True, metavar='FILE', help='baseline: cargo test log(s)')
    parser.add_argument('--nextest-log', nargs='+', default=[], metavar='FILE', help='candidate: nextest output log(s)')
    parser.add_argument('--nextest-junit', nargs='+', default=[], metavar='FILE', help='candidate: nextest JUnit XML')
    parser.add_argument('--max-list', type=int, default=DEFAULT_MAX_LIST, help='rows printed per difference list')
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_UNUSABLE
    try:
        if not (args.nextest_log or args.nextest_junit):
            raise ParseError('a candidate is required: --nextest-log and/or --nextest-junit')
        baseline = _load(parse_cargo_log, args.cargo_log)
        candidate = _load(parse_nextest_log, args.nextest_log)
        for key, outcome in _load(parse_junit, args.nextest_junit).items():
            _merge(candidate, key, outcome)
        report = compare(baseline, candidate)
    except ParseError as exc:
        print('compare_test_sets: %s' % exc, file=sys.stderr)
        return EXIT_UNUSABLE
    print(render(report, max(args.max_list, 0)))
    return EXIT_IDENTICAL if report.identical else EXIT_DIFFERENT


if __name__ == '__main__':
    sys.exit(main())
