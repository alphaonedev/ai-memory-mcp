#!/usr/bin/env python3
"""Per-test parity of the isolated and the serial serial-shard runs (#9592).

3-agent vote (71472661) I-4 / I-5: with per-binary Postgres isolation on, every
test of every serial-shard binary must end with the same outcome (ok, FAILED or
ignored) as on the serial path, residual binaries included, and the comparison
fails closed on a missing log, a zero-test binary, a duplicate binary log and a
log without a ``test result:`` line.

One rule in one place, ``evidence_reason`` (PR 9841 r1), also applied by the
serial step (scripts/ci/pg_isolate_serial_step.py) to every isolated binary: a
segment is well formed only when it has at least one test line (ok, FAILED or
ignored; a result line alone is "zero tests"), its ok / FAILED / ignored test
lines equal the passed / failed / ignored totals of its real result line, and
that line says ``0 filtered out``. The real result line is the LAST one of the
segment; an earlier one is accepted only inside a libtest captured-output body
(after a ``---- X stdout ----`` or ``---- X stderr ----`` header, which
``--show-output`` prints before the real line, and before the ``successes:`` /
``failures:`` name list that ends the bodies); anywhere else the segment is
refused. ``ignored_reason`` compares the ignored test NAMES with the binary's
own ``--list --ignored``.

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

# ci.yml sets CARGO_TERM_COLOR=always, so cargo's status word arrives as
# ``ESC[1mESC[92m     RunningESC[0m ...`` (job 136822077211). plain() removes the
# well-formed 7-bit escape sequences of a line before any match: CSI
# (ESC [ params intermediates final, ECMA-48 5.4) and OSC (ESC ] ... BEL or ESC \).
# A lone or cut-off ESC is left in place, so such a line never matches.
# Linear: no class of either pattern contains ESC, so each match is read once.
ANSI_RE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)')
RUNNING_RE = re.compile(r'^\s*Running \S+ \((?:\S*/)?deps/([A-Za-z0-9_]+)-[0-9a-f]+(?:\.exe)?\)\s*$')
TEST_RE = re.compile(r'^test (\S+) \.\.\. (ok|FAILED|ignored)\b')
# A test that spawns a child process: the child's stderr follows "test X ... "
# on the same line and the outcome arrives alone on a later line (in-binary
# --test-threads=1, so at most one test is open at a time).
OPEN_RE = re.compile(r'^test (\S+) \.\.\. ')
LONE_OUTCOME_RE = re.compile(r'^(ok|FAILED|ignored)(?:, .*)?$')
RESULT_RE = re.compile(r'^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;'
                       r'(?: \d+ measured; (\d+) filtered out;)?')
# libtest's captured-output header (``--show-output`` successes, and failures): test output follows it.
BODY_RE = re.compile(r'^---- \S+ std(?:out|err) ----$')
# libtest's name-list header after the bodies ends them: the real result line follows it outside any body,
# so a result line printed after the real one is never inside a body (a test that prints this header
# itself only ends its body early, which turns a later printed result line red, never green).
BODY_END_RE = re.compile(r'^(?:successes|failures):$')
LIST_TEST_SUFFIX = ': test'
IGNORED_SHOWN_MAX = 20


class Segment:
    """One binary's part of a cargo test log."""

    __slots__ = ('name', 'tests', 'totals', 'filtered', 'stray_result', 'in_body', 'last_in_body')

    def __init__(self, name: str) -> None:
        self.name = name
        self.tests: dict[str, str] = {}
        # Taken from the LAST result line of the segment, the real one (libtest prints it last).
        self.totals: tuple[int, int, int] | None = None
        self.filtered: int | None = None
        # An earlier result line outside a captured-output body: the segment is refused.
        self.stray_result = False
        self.in_body = False
        self.last_in_body = False


def plain(line: str) -> str:
    """``line`` without its ANSI CSI / OSC escape sequences (cargo colour, hyperlinks)."""
    return ANSI_RE.sub('', line) if '\x1b' in line else line


def segments(text: str) -> list[Segment]:
    """Every ``Running`` segment of ``text``, in order (one linear pass, colour codes ignored)."""
    out: list[Segment] = []
    open_test: str | None = None
    for raw in text.splitlines():
        line = plain(raw)
        if (m := RUNNING_RE.match(line)):
            out.append(Segment(m.group(1)))
            open_test = None
        elif out and (m := TEST_RE.match(line)):
            out[-1].tests[m.group(1)] = m.group(2)
            open_test = None
        elif out and (m := OPEN_RE.match(line)):
            open_test = m.group(1)
        elif out and open_test is not None and (m := LONE_OUTCOME_RE.match(line)):
            out[-1].tests[open_test] = m.group(1)
            open_test = None
        elif out and (m := RESULT_RE.match(line)):
            seg = out[-1]
            if seg.totals is not None and not seg.last_in_body:
                seg.stray_result = True
            seg.totals = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            seg.filtered = None if m.group(4) is None else int(m.group(4))
            seg.last_in_body = seg.in_body
            open_test = None
        elif out and BODY_RE.match(line):
            out[-1].in_body = True
            open_test = None
        elif out and BODY_END_RE.match(line):
            out[-1].in_body = False
    return out


def evidence_reason(seg: Segment) -> str | None:
    """The fail-closed reason of one segment, or None when its test lines prove its result line.

    The one definition (PR 9841 r1) of "every runnable test of this binary ran", read from the test
    lines, never from the totals alone: at least one test line (ok, FAILED or ignored), one real result
    line, its passed / failed / ignored totals equal to the counted ok / FAILED / ignored lines, and
    ``0 filtered out``."""
    if not seg.tests:
        return 'zero tests: %s' % seg.name
    if seg.totals is None:
        return 'no test result line: %s' % seg.name
    if seg.stray_result:
        return 'more than one test result line: %s' % seg.name
    counted = tuple(sum(1 for o in seg.tests.values() if o == word) for word in ('ok', 'FAILED', 'ignored'))
    if counted != seg.totals:
        return 'result totals differ from the test lines: %s' % seg.name
    if seg.filtered is None:
        return 'no filtered-out count on the test result line: %s' % seg.name
    if seg.filtered:
        return 'tests filtered out: %s (%d)' % (seg.name, seg.filtered)
    return None


def structural(seg: Segment, side: str) -> str | None:
    """The fail-closed reason of one segment (``evidence_reason`` naming the side), or None."""
    reason = evidence_reason(seg)
    return None if reason is None else '%s (%s)' % (reason, side)


def listed_names(list_output: str) -> set[str]:
    """The test names of a binary's ``--list --ignored`` output (``<name>: test`` lines; benches are not tests)."""
    return {line[:-len(LIST_TEST_SUFFIX)] for line in list_output.splitlines() if line.endswith(LIST_TEST_SUFFIX)}


def _names_shown(names: set[str]) -> str:
    shown = sorted(names)
    text = ', '.join(shown[:IGNORED_SHOWN_MAX])
    if len(shown) > IGNORED_SHOWN_MAX:
        text += ' (+%d more)' % (len(shown) - IGNORED_SHOWN_MAX)
    return text or 'none'


def ignored_reason(seg: Segment, listed: set[str]) -> str | None:
    """None when the ignored test NAMES of ``seg`` equal ``listed`` (the binary's ``--list --ignored``)."""
    logged = {test for test, outcome in seg.tests.items() if outcome == 'ignored'}
    if logged == listed:
        return None
    if len(logged) != len(listed):
        return 'ignored count differs from --list --ignored: %s (log=%d list=%d)' % (seg.name, len(logged),
                                                                                    len(listed))
    return 'ignored tests differ from --list --ignored: %s (log only: %s; list only: %s)' % (
        seg.name, _names_shown(logged - listed), _names_shown(listed - logged))


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
