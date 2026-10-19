#!/usr/bin/env python3
"""Per-runner host load gate for the self-hosted CI legs (#6795).

Waits (bounded) while the 1-minute load average exceeds ``ratio x cores``, then
proceeds. It NEVER fails on load alone: after ``--max-wait-secs`` it prints a
``::warning::`` and exits 0, so a busy host delays a leg but never turns it red.
With a budget, exit 3 refuses admission below the configured suite reserve
(including on an idle host). Exit 2 is reserved for bad arguments.

Usage: python3 scripts/ci/load_gate.py --label "<os>/<tier>" [--max-ratio 1.5]
       [--max-wait-secs 1200] [--poll-secs 30]

Python 3.9+, standard library only.
"""
import argparse
import os
import sys
import time

TAG = '[#6795 load gate]'
SECONDS_PER_MINUTE = 60
TEARDOWN_RESERVE_SECS = 300
BUDGET_REFUSED = 3


def should_wait(load, cores, ratio):
    """True when the host is busier than ``ratio x cores``. Unknown cores: never wait."""
    if not cores or cores <= 0:
        return False
    return load > ratio * cores


def format_notice(label, load, cores, ratio, waited):
    return "::notice::%s '%s': load=%.2f cores=%d ratio=%s waited=%ds" % (
        TAG, label, load, cores, ratio, waited)


def _plain(label, load, cores, ratio, waited):
    """Intermediate poll line: plain log text, not an annotation (GitHub caps annotations per step)."""
    return "%s '%s': waiting, load=%.2f cores=%d ratio=%s waited=%ds" % (
        TAG, label, load, cores, ratio, waited)


def run(label, max_ratio, max_wait_secs, poll_secs, cores, load_fn, sleep_fn,
        budget_secs=None, min_suite_secs=None, clock_fn=time.monotonic):
    """Bound waiting by real elapsed time; reserve test time before admission."""
    started = clock_fn()
    first = True
    while True:
        # Charge load sampling and scheduling delays as well as requested sleep.
        load_error = None
        try:
            load = load_fn()
        except (OSError, AttributeError) as exc:
            load_error = exc
        waited = max(0, clock_fn() - started)
        remaining = None if budget_secs is None else budget_secs - waited
        if remaining is not None and remaining < min_suite_secs:
            print('::error::%s %r: remaining budget %d s < configured suite '
                  'reserve %d s; refusing admission (waited=%.0fs)'
                  % (TAG, label, int(remaining // 1), min_suite_secs, waited), flush=True)
            return BUDGET_REFUSED
        if load_error is not None:
            print('::warning::%s %r: cannot read the load average (%s); '
                  'proceeding without the load gate'
                  % (TAG, label, load_error), flush=True)
            return 0
        if first:
            print(format_notice(label, load, cores, max_ratio, waited), flush=True)
            first = False
        if not should_wait(load, cores, max_ratio):
            break
        wait_left = max_wait_secs - waited
        if remaining is not None:
            wait_left = min(wait_left, remaining - min_suite_secs)
        if wait_left <= 0:
            print('::warning::%s %r: load=%.2f still above %s x %d cores after %.0fs; '
                  'proceeding anyway (the gate never fails on load alone)'
                  % (TAG, label, load, max_ratio, cores, waited), flush=True)
            break
        if waited:
            print(_plain(label, load, cores, max_ratio, waited), flush=True)
        sleep_fn(min(poll_secs, wait_left))
    print(format_notice(label, load, cores, max_ratio, waited), flush=True)
    return 0


def _positive_float(text):
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError('must be > 0')
    return value


def _positive_int(text):
    value = int(text)
    if value <= 0:
        raise argparse.ArgumentTypeError('must be > 0')
    return value


def _non_negative_int(text):
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError('must be >= 0')
    return value


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--max-ratio', type=_positive_float, default=1.5)
    p.add_argument('--max-wait-secs', type=_non_negative_int, default=1200)
    p.add_argument('--poll-secs', type=_positive_int, default=30)
    p.add_argument('--label', default='unlabelled')
    budgets = p.add_mutually_exclusive_group()
    budgets.add_argument('--budget-secs', type=int,
                         help='remaining usable seconds at entry, after teardown reserve')
    budgets.add_argument('--job-timeout-minutes', type=_positive_int,
                         help='job cap; subtract elapsed JOB_T0 and 300s teardown once')
    p.add_argument('--min-suite-secs', type=_non_negative_int,
                   help='evidence-backed admission reserve; zero for targeted subsets')
    args = p.parse_args(argv)  # argparse exits 2 on bad arguments
    has_budget = args.budget_secs is not None or args.job_timeout_minutes is not None
    if has_budget != (args.min_suite_secs is not None):
        p.error('a budget and --min-suite-secs must be supplied together')
    budget = args.budget_secs
    if args.job_timeout_minutes is not None:
        job_start = os.environ.get('JOB_T0', '')
        if (not job_start.isascii() or not job_start.isdecimal()
                or job_start.startswith('0')):
            p.error('JOB_T0 must be positive epoch seconds without a leading zero')
        elapsed = time.time() - int(job_start)
        if elapsed < 0:
            p.error('JOB_T0 cannot be in the future')
        budget = (args.job_timeout_minutes * SECONDS_PER_MINUTE
                  - elapsed - TEARDOWN_RESERVE_SECS)
    return run(args.label, args.max_ratio, args.max_wait_secs, args.poll_secs,
               os.cpu_count(), lambda: os.getloadavg()[0], time.sleep,
               budget_secs=budget, min_suite_secs=args.min_suite_secs)


if __name__ == '__main__':
    sys.exit(main())
