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

Totals reconciliation (#7298 F2). Each log also carries its runner's own total, and the
tool refuses (exit 2) a log whose parsed per-test lines disagree with it, so a line lost
the same way on both sides can never read as IDENTICAL:

* cargo: the sum of ``passed`` + ``failed`` of the LAST top-level ``test result: ok|FAILED.
  N passed; M failed; ...`` line of each non-doc-test binary (ignored tests are not
  executed tests; doc tests are not parsed; a test that re-executes its own test binary
  prints child ``running 1 test`` / ``test result:`` blocks into the parent's log before the
  parent's closing line, so earlier result lines of the same binary are not its total).
* nextest: the sum of ``N`` over ``Summary [ ... ] N tests run: P passed, ...`` lines.

The unique (binary, test) keys parsed from a side must equal its total. A log with no totals
line at all (an older format, a truncated log) is refused with a message naming the missing
total. A JUnit-only candidate has no totals line and is not reconciled. The step log prints
``totals: cargo N of N, nextest N of N`` when both agree.

Exit codes: 0 identical sets AND identical outcomes, 1 they differ (a readable
diff is printed), 2 unusable input: an empty, missing, unparseable or
total-inconsistent file is a failure, never a pass (fail closed). Standard
library only, Python 3.9+.
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
EXAMPLE_PREFIX = 'example/'
EXAMPLE_SRC_PREFIX = 'examples/'
DEFAULT_MAX_LIST = 40

# ESC, or the two characters ^[ that `gh run view --log` prints in its place.
_ANSI_RE = re.compile(r'(?:\x1b|\^\[)\[[0-9;]*[A-Za-z]')
# GitHub inserts a byte-order mark at log-chunk boundaries, anywhere in a line.
_BOM = '\ufeff'
_STAMP_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T[\d:.]+Z ?')
# `gh run view --log` puts `<job>\t<step>\t` in front of every line's timestamp (#7298 F1); a tab pair is
# only a prefix when a timestamp follows it, so tabs inside ordinary test output are left alone.
_GH_PREFIX_RE = re.compile(r'^[^\t]*\t[^\t]*\t(?=\d{4}-\d{2}-\d{2}T[\d:.]+Z)')
_RUNNING_RE = re.compile(r'^\s*Running (?:(?P<unit>unittests) )?(?P<src>\S+)(?: \((?P<exe>[^)]+)\))?\s*$')
_DOCTEST_RE = re.compile(r'^\s*Doc-tests\b')
# libtest prints ``test <name> - should panic ... ok`` for #[should_panic] tests; the suffix is
# not part of the name nextest reports. A test that logs mid-line leaves the verdict either glued
# to the noise (``ok<noise>``) or alone on a later line (``test <name> ... <noise>`` then ``ok``).
# Another thread's unterminated stderr write can land in front of a result line (#7299), so the
# result is searched for anywhere in the line; a non-blank prefix is counted as a spliced line.
_CARGO_TEST_RE = re.compile(
    r'test (?P<name>\S+)(?: - should panic)? \.\.\. (?P<res>ok|FAILED|ignored)(?![A-Za-z])')
_CARGO_OPEN_RE = re.compile(r'^test (?P<name>.+?)(?: - should panic)? \.\.\.(?: |$)')
_CARGO_VERDICT_RE = re.compile(r'^(?P<res>ok|FAILED|ignored)(?![A-Za-z])')
_HASH_RE = re.compile(r'-[0-9a-f]{16}$')
# A test that spawns its own libtest child prints a nested `running N test(s)` block (inline after
# `test <name> ... ` or on its own line) that ends with its own `test result:` line.
_NESTED_START_RE = re.compile(r'(?:^|\s)running \d+ tests?$')
_RESULT_RE = re.compile(r'^test result: ')
_TOTAL_RE = re.compile(r'^test result: (?:ok|FAILED)\. (?P<passed>\d+) passed; (?P<failed>\d+) failed;')
_SUMMARY_RE = re.compile(r'Summary \[[^\]]*\]\s+(?P<run>\d+) tests? run:')
_NEXTEST_RE = re.compile(
    r'(?P<st>PASS|LEAK-FAIL|LEAK|FAIL|TIMEOUT|ABORT|SIG[A-Z0-9]+|EXEC-?FAIL|FLAKY(?: \d+/\d+)?)'
    r'\s+\[[^\]]*\]\s+(?:\(\s*\d+/\s*\d+\)\s+)?(?P<bin>\S+)\s+(?P<name>.+?)\s*$')
_NEXTEST_PASS = ('PASS', 'LEAK')

Key = Tuple[str, str]
Outcomes = Dict[Key, str]


class ParseError(Exception):
    """Unusable input: empty, unparseable or contradictory (fail closed)."""


class Scan(NamedTuple):
    """One log parsed: the outcomes, how many result lines carried a spliced prefix (#7299), the
    unique per-test keys parsed, and the runner's own total (summed) with the number of totals lines."""
    outcomes: Outcomes
    spliced: int
    parsed: int
    total: int
    total_lines: int


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
    return _STAMP_RE.sub('', _GH_PREFIX_RE.sub('', _ANSI_RE.sub('', line.replace(_BOM, '')))).rstrip()


def _spliced(line: str, found: 're.Match[str]') -> bool:
    """True when non-blank text was glued in front of the matched result."""
    return bool(line[:found.start()].strip())


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
        if src.startswith(EXAMPLE_SRC_PREFIX):
            return EXAMPLE_PREFIX + stem  # nextest id `<package>::example/<name>`
        return BIN_PREFIX + stem
    return stem


def parse_cargo_log(text: str) -> Outcomes:
    """``cargo test`` log -> ``{(binary, test): pass|fail}`` (ignored tests and doc tests excluded)."""
    return scan_cargo_log(text).outcomes


def _close_section(total: int, total_lines: int, section_total: Optional[int]) -> Tuple[int, int]:
    """Add the finished binary's own total (if it printed one) to the running sums."""
    if section_total is None:
        return total, total_lines
    return total + section_total, total_lines + 1


def scan_cargo_log(text: str) -> Scan:
    """``parse_cargo_log`` plus the count of result lines that carried a spliced prefix."""
    out: Outcomes = {}
    spliced = total = total_lines = 0
    section_total: Optional[int] = None  # passed + failed of the last top-level result of this binary
    current: Optional[str] = None
    pending: Optional[str] = None
    parents: List[Optional[str]] = []  # parent verdicts waiting while a nested child block runs
    in_doc = False
    for raw in text.splitlines():
        line = _clean(raw)
        running = _RUNNING_RE.match(line)
        if running and (running.group('src').endswith('.rs') or '/deps/' in running.group('src')):
            total, total_lines = _close_section(total, total_lines, section_total)
            section_total = None
            current, in_doc, pending, parents = _cargo_binary(running), False, None, []
            continue
        if _DOCTEST_RE.match(line):
            total, total_lines = _close_section(total, total_lines, section_total)
            section_total = None
            current, in_doc, pending, parents = None, True, None, []
            continue
        if parents or (pending and _NESTED_START_RE.search(line)):
            # inside a child libtest block: its lines are not tests of this binary
            if _NESTED_START_RE.search(line):
                parents.append(pending)
                pending = None
            elif _RESULT_RE.match(line):
                pending = parents.pop()
            continue
        totals = _TOTAL_RE.match(line)
        if totals:
            pending = None
            if not in_doc:
                section_total = int(totals.group('passed')) + int(totals.group('failed'))
            continue
        found = _CARGO_TEST_RE.search(line)
        if found:
            name, res, pending = found.group('name'), found.group('res'), None
            spliced += _spliced(line, found)
        else:
            verdict = _CARGO_VERDICT_RE.match(line) if pending else None
            if verdict:
                name, res, pending = pending, verdict.group('res'), None
            else:
                opened = _CARGO_OPEN_RE.match(line)
                if opened:
                    pending = opened.group('name')
                    if _NESTED_START_RE.search(line):  # child block opens on the same line
                        parents.append(pending)
                        pending = None
                continue
        if in_doc or res == 'ignored':
            continue
        if current is None:
            raise ParseError('cargo log: test line %r before any "Running" header' % line[:80])
        _merge(out, (current, name), PASS if res == 'ok' else FAIL)
    total, total_lines = _close_section(total, total_lines, section_total)
    if not out:
        raise ParseError('cargo log: no executed tests found')
    return Scan(out, spliced, len(out), total, total_lines)


def _nextest_binary(binary_id: str) -> str:
    rest = binary_id.split('::', 1)[1] if '::' in binary_id else ''
    return _norm(rest) if rest else LIB_KEY


def parse_nextest_log(text: str) -> Outcomes:
    """nextest status lines -> ``{(binary, test): pass|fail}`` (retry attempts and skips excluded)."""
    return scan_nextest_log(text).outcomes


def scan_nextest_log(text: str) -> Scan:
    """``parse_nextest_log`` plus the count of status lines that carried a spliced prefix."""
    out: Outcomes = {}
    spliced = total = total_lines = 0
    for raw in text.splitlines():
        line = _clean(raw)
        summary = _SUMMARY_RE.search(line)
        if summary:
            total += int(summary.group('run'))
            total_lines += 1
            continue
        found = _NEXTEST_RE.search(line)
        if not found:
            continue
        spliced += _spliced(line, found)
        status = found.group('st')
        ok = status in _NEXTEST_PASS or status.startswith('FLAKY')
        _merge(out, (_nextest_binary(found.group('bin')), found.group('name')), PASS if ok else FAIL)
    if not out:
        raise ParseError('nextest log: no PASS/FAIL result lines found')
    return Scan(out, spliced, len(out), total, total_lines)


def check_totals(label: str, scan: Scan) -> None:
    """Refuse a side whose parsed per-test lines disagree with its runner's own total (#7298 F2)."""
    missing = {'cargo': "no top-level 'test result: ok|FAILED. N passed; M failed' totals line",
               'nextest': "no 'Summary [ ... ] N tests run:' totals line"}[label]
    if not scan.total_lines:
        raise ParseError('%s log: %s found, so the %d parsed test lines cannot be reconciled with the '
                         "runner's own total" % (label, missing, scan.parsed))
    if scan.parsed != scan.total:
        raise ParseError("%s log: parsed %d per-test lines but the runner reports %d executed tests "
                         "(%d totals lines); a result line was lost or merged" %
                         (label, scan.parsed, scan.total, scan.total_lines))


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


def _load(scanner, paths: List[str]) -> Scan:
    """Merge every log of one side: outcomes merged, counters and totals summed over the logs."""
    merged: Outcomes = {}
    spliced = parsed = total = total_lines = 0
    for text in _read(paths):
        scan = scanner(text)
        spliced += scan.spliced
        parsed += scan.parsed
        total += scan.total
        total_lines += scan.total_lines
        for key, outcome in scan.outcomes.items():
            _merge(merged, key, outcome)
    return Scan(merged, spliced, parsed, total, total_lines)


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
        base_scan = _load(scan_cargo_log, args.cargo_log)
        cand_scan = _load(scan_nextest_log, args.nextest_log)
        check_totals('cargo', base_scan)
        if args.nextest_log:
            check_totals('nextest', cand_scan)
        baseline, candidate = base_scan.outcomes, cand_scan.outcomes
        for text in _read(args.nextest_junit):
            for key, outcome in parse_junit(text).items():
                _merge(candidate, key, outcome)
        report = compare(baseline, candidate)
    except ParseError as exc:
        print('compare_test_sets: %s' % exc, file=sys.stderr)
        return EXIT_UNUSABLE
    print(render(report, max(args.max_list, 0)))
    print('totals: cargo %d of %d, nextest %s (parsed per-test lines of the runners\' own totals)'
          % (base_scan.parsed, base_scan.total,
             ('%d of %d' % (cand_scan.parsed, cand_scan.total)) if args.nextest_log else 'junit only, no totals'))
    print('spliced result lines (stderr glued in front, still counted): baseline=%d candidate=%d'
          % (base_scan.spliced, cand_scan.spliced))
    return EXIT_IDENTICAL if report.identical else EXIT_DIFFERENT


if __name__ == '__main__':
    sys.exit(main())
