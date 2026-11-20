#!/usr/bin/env python3
"""Per-test parity of the isolated and the serial serial-shard runs (#9592).

3-agent vote (71472661) I-4 / I-5: with per-binary Postgres isolation on, every
test of every serial-shard binary must end with the same outcome (ok, FAILED or
ignored) as on the serial path, residual binaries included, and the comparison
fails closed on a missing log, a zero-test binary, a duplicate binary log and a
log without a ``test result:`` line.

Usage:
  pg_isolate_parity.py --iso-log-dir DIR --targets-file FILE --serial-log FILE
                       [--residual-file FILE]

Exit 0 prints ``[#9592] parity ok: ...``; 1 prints one ``[#9592] parity FAIL:``
line per reason; 2 means an input could not be read. The scan is one linear
pass per log (a 500 x 200 corpus stays under PARITY_CEILING_SECS).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PARITY_CEILING_SECS = 10.0
TAG = '[#9592] parity'
OUTCOMES = {'ok': 'ok', 'FAILED': 'failed', 'ignored': 'ignored'}

RUNNING_RE = re.compile(r'^\s*Running \S+ \((?:\S*/)?deps/([A-Za-z0-9_]+)-[0-9a-f]+(?:\.exe)?\)\s*$')
TEST_RE = re.compile(r'^test (\S+) \.\.\. (ok|FAILED|ignored)\b')
RESULT_RE = re.compile(r'^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;')


class Segment:
    """One binary's part of a cargo test log."""

    __slots__ = ('name', 'tests', 'totals')

    def __init__(self, name: str) -> None:
        self.name = name
        self.tests: dict[str, str] = {}
        self.totals: tuple[int, int, int] | None = None


def segments(text: str) -> list[Segment]:
    """Every ``Running`` segment of ``text``, in order (one linear pass)."""
    out: list[Segment] = []
    for line in text.splitlines():
        if (m := RUNNING_RE.match(line)):
            out.append(Segment(m.group(1)))
        elif out and (m := TEST_RE.match(line)):
            out[-1].tests[m.group(1)] = m.group(2)
        elif out and out[-1].totals is None and (m := RESULT_RE.match(line)):
            out[-1].totals = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return out


def structural(seg: Segment, side: str) -> str | None:
    """The fail-closed reason of one segment, or None when it is well formed."""
    if not seg.tests:
        return 'zero tests: %s (%s)' % (seg.name, side)
    if seg.totals is None:
        return 'no test result line: %s (%s)' % (seg.name, side)
    counted = tuple(sum(1 for o in seg.tests.values() if o == word) for word in ('ok', 'FAILED', 'ignored'))
    if counted != seg.totals:
        return 'result totals differ from the test lines: %s (%s)' % (seg.name, side)
    return None


def compare_logs(iso_logs: dict[str, str], serial_text: str,
                 expected_names: list[str]) -> tuple[list[str], dict[str, int]]:
    """``(reasons, summary)``; no reason means per-test parity holds."""
    reasons: list[str] = []
    iso: dict[str, list[tuple[str, Segment]]] = {}
    for filename in sorted(iso_logs):
        found = segments(iso_logs[filename])
        if not found:
            reasons.append('no test binary ran: %s (isolated)' % filename)
        for seg in found:
            iso.setdefault(seg.name, []).append((filename, seg))
    serial: dict[str, list[Segment]] = {}
    for seg in segments(serial_text):
        serial.setdefault(seg.name, []).append(seg)
    summary = {'binaries': len(expected_names), 'tests': 0, 'ok': 0, 'failed': 0, 'ignored': 0}
    for name in expected_names:
        iso_hits, serial_hits = iso.get(name, []), serial.get(name, [])
        problem = None
        if not iso_hits:
            problem = 'missing log: %s (isolated)' % name
        elif len(iso_hits) > 1:
            problem = 'duplicate binary log: %s (isolated: %s)' % (name, ', '.join(f for f, _ in iso_hits))
        elif not serial_hits:
            problem = 'missing log: %s (serial)' % name
        elif len(serial_hits) > 1:
            problem = 'duplicate binary log: %s (serial)' % name
        else:
            problem = structural(iso_hits[0][1], 'isolated') or structural(serial_hits[0], 'serial')
        if problem:
            reasons.append(problem)
            continue
        left, right = iso_hits[0][1].tests, serial_hits[0].tests
        for test in sorted(left.keys() | right.keys()):
            a, b = left.get(test, 'absent'), right.get(test, 'absent')
            if a != b:
                reasons.append('outcome differs: %s::%s isolated=%s serial=%s' % (name, test, a, b))
        for outcome in left.values():
            summary['tests'] += 1
            summary[OUTCOMES[outcome]] += 1
    wanted = set(expected_names)
    reasons += ['unexpected binary: %s (isolated)' % name for name in sorted(iso) if name not in wanted]
    return reasons, summary


def target_names(lines: list[str]) -> list[str]:
    return [ln.split()[-1] for ln in lines if ln.strip() and not ln.lstrip().startswith('#')]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--iso-log-dir', required=True)
    parser.add_argument('--targets-file', required=True)
    parser.add_argument('--serial-log', required=True)
    parser.add_argument('--residual-file', help='residual binaries (they are compared like the rest)')
    args = parser.parse_args(argv)
    try:
        expected = target_names(Path(args.targets_file).read_text(encoding='utf-8').splitlines())
        if args.residual_file:
            missing = sorted(set(target_names(Path(args.residual_file).read_text(encoding='utf-8').splitlines()))
                             - set(expected))
            if missing:
                print('%s FAIL: residual binaries not in the targets file: %s' % (TAG, ', '.join(missing)))
                return 1
        iso_dir = Path(args.iso_log_dir)
        if not iso_dir.is_dir():
            raise OSError('%s is not a directory' % iso_dir)
        logs = {p.name: p.read_text(encoding='utf-8', errors='replace') for p in sorted(iso_dir.glob('*.log'))}
        serial_text = Path(args.serial_log).read_text(encoding='utf-8', errors='replace')
    except OSError as exc:
        print('%s FAIL: cannot read an input: %s' % (TAG, exc))
        return 2
    if not expected:
        print('%s FAIL: the targets file lists no binary' % TAG)
        return 1
    reasons, s = compare_logs(logs, serial_text, expected)
    for reason in reasons:
        print('%s FAIL: %s' % (TAG, reason))
    if reasons:
        return 1
    print('%s ok: binaries=%d tests=%d ok=%d failed=%d ignored=%d'
          % (TAG, s['binaries'], s['tests'], s['ok'], s['failed'], s['ignored']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
