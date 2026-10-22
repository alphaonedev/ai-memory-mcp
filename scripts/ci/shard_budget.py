#!/usr/bin/env python3
"""Fail-fast gate and budget ratchet of the sharded enterprise-fed suite (#7343).

Two subcommands, both stdlib only (Python 3.9+), both read what the #6344
partitioner and the #1492 watchdog already write:

``gate``     after the partition and before any shard starts: a shard whose
             calibrated estimate is above its budget fails the step at once and
             names the shard, the estimate and the budget. The watchdog is the
             hang guard and is not touched; this catches a shard that cannot fit.
``ratchet``  after the shards: a shard that PASSED but used more than 85% of its
             budget warns, more than 95% fails, so the budget cannot be eaten
             silently one binary at a time.

Calibration: the partitioner's raw estimates are weights, not wall time. On
run 39063295132 the serial shard took 0.66 of its raw estimate and the two
parallel shards 1.76x and 2.63x theirs (see ESTIMATE_SCALE); the gate compares
raw x scale with the budget so it fails on a shard that really cannot fit and
does not fail every run on the weights' known bias.

Exit codes: 0 ok, 1 ratchet failure, 2 gate failure or unusable input.
"""
import argparse
import json
import math
import re
import sys
from pathlib import Path

SHARDS = ('serial', 'parallel_1', 'parallel_2')
# Manifest key (estimate_seconds) holding each shard's raw estimate.
MANIFEST_KEY = {
    'serial': 'serial_threads_1',
    'parallel_1': 'parallel_1_est_min_tests_threads',
    'parallel_2': 'parallel_2_est_min_tests_threads',
}
# Measured seconds / raw estimate on run 39063295132 (linux-fed enterprise-fed).
ESTIMATE_SCALE = {'serial': 0.66, 'parallel_1': 1.76, 'parallel_2': 2.63}
WARN_FRACTION = 0.85
FAIL_FRACTION = 0.95
PERCENT = 100
RC_OK, RC_RATCHET, RC_BAD = 0, 1, 2
NOTICE_RE = re.compile(r"'\[(?P<shard>\w+)\] [^']*' ran (?P<ran>\d+)s of the (?P<of>\d+)s per-invocation watchdog budget")


class BudgetError(Exception):
    """Unusable input; main() prints it as ::error:: and exits 2 (fail closed)."""


def pair(text, what):
    """Parse 'shard=N' into (shard, int N)."""
    name, sep, val = text.partition('=')
    if not sep or name not in SHARDS:
        raise BudgetError('%s %r is not <%s>=<integer>' % (what, text, '|'.join(SHARDS)))
    try:
        num = int(val)
    except ValueError:
        raise BudgetError('%s %r: %r is not an integer' % (what, text, val))
    return name, num


def pairs(items, what, positive):
    out = {}
    for item in items or []:
        name, num = pair(item, what)
        if positive and num <= 0:
            raise BudgetError('%s %r must be positive' % (what, item))
        out[name] = num
    missing = [s for s in SHARDS if s not in out]
    if missing:
        raise BudgetError('%s missing for shard %s' % (what, ', '.join(missing)))
    return out


def percent(used, budget):
    return int(used * PERCENT / budget + 0.5)


def gate(args):
    budgets = pairs(args.budget, '--budget', True)
    try:
        est = json.loads(Path(args.manifest).read_text())['estimate_seconds']
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise BudgetError('cannot read estimate_seconds from %s: %s' % (args.manifest, exc))
    if not isinstance(est, dict):
        raise BudgetError('manifest %s estimate_seconds must be an object' % args.manifest)
    estimates = {}
    for shard in SHARDS:
        key = MANIFEST_KEY[shard]
        try:
            value = est[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError('not a number')
            raw = float(value)
            scaled = raw * ESTIMATE_SCALE[shard]
            if not math.isfinite(raw) or raw < 0 or not math.isfinite(scaled):
                raise ValueError('not finite and nonnegative after calibration')
            # Budgets are integer seconds: ceil preserves every fractional overrun
            # while exact equality still passes, without an epsilon tolerance.
            estimates[shard] = (raw, math.ceil(scaled))
        except (KeyError, TypeError, ValueError, OverflowError):
            raise BudgetError('manifest %s %s must be numeric, finite and nonnegative '
                              'with finite calibration' % (args.manifest, key))
    failed = False
    for shard in SHARDS:
        raw, calibrated = estimates[shard]
        budget = budgets[shard]
        line = 'shard %s estimate %ds (raw %ss x %.2f; ceiling) vs budget %ds' % (
            shard, calibrated, format(raw, '.17g'), ESTIMATE_SCALE[shard], budget)
        if calibrated > budget:
            failed = True
            print('::error::[#7343 fail-fast] %s: the estimate exceeds the budget; move binaries to a '
                  'parallel shard (scripts/ci/serial_to_parallel_moves.txt) instead of raising it' % line,
                  file=sys.stderr)
        else:
            print('[#7343 fail-fast] %s (%d%% used)' % (line, percent(calibrated, budget)))
    return RC_BAD if failed else RC_OK


def ratchet(args):
    rcs = pairs(args.rc, '--rc', False)
    worst = RC_OK
    for shard in SHARDS:
        if rcs[shard] != 0:
            continue  # its own exit code already fails the step
        base = Path(args.dir)
        try:
            budget = int((base / (shard + '.budget')).read_text().strip())
            log = (base / (shard + '.log')).read_text(errors='replace')
        except (OSError, ValueError) as exc:
            raise BudgetError('shard %s: cannot read its budget or log under %s: %s' % (shard, base, exc))
        if budget <= 0:
            raise BudgetError('shard %s: budget %d is not positive' % (shard, budget))
        used = sum(int(m.group('ran')) for m in NOTICE_RE.finditer(log) if m.group('shard') == shard)
        what = 'shard %s used %ds of %ds (%d%%)' % (shard, used, budget, percent(used, budget))
        if used * PERCENT > int(FAIL_FRACTION * PERCENT) * budget:
            print('::error::[#7343 ratchet] %s, above the %d%% fail line; move binaries to a parallel shard'
                  % (what, FAIL_FRACTION * PERCENT), file=sys.stderr)
            worst = max(worst, RC_RATCHET)
        elif used * PERCENT > int(WARN_FRACTION * PERCENT) * budget:
            print('::warning::[#7343 ratchet] %s, above the %d%% warn line' % (what, WARN_FRACTION * PERCENT))
        else:
            print('[#7343 budget] %s' % what)
    return worst


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    g = sub.add_parser('gate', help='fail when a shard estimate exceeds its budget (before the shards start)')
    g.add_argument('--manifest', required=True, help='manifest.json written by partition_test_binaries.py')
    g.add_argument('--budget', action='append', metavar='SHARD=SECS', help='per-shard budget; all three required')
    r = sub.add_parser('ratchet', help='warn above 85%%, fail above 95%% of a green shard budget')
    r.add_argument('--dir', required=True, help='directory holding <shard>.log and <shard>.budget')
    r.add_argument('--rc', action='append', metavar='SHARD=RC', help='per-shard exit code; all three required')
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return gate(args) if args.cmd == 'gate' else ratchet(args)
    except BudgetError as exc:
        print('::error::[#7343 shard-budget] %s' % exc, file=sys.stderr)
        return RC_BAD


if __name__ == '__main__':
    sys.exit(main())
