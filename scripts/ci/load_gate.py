#!/usr/bin/env python3
"""Per-runner host load gate for the self-hosted CI legs (#6795).

Waits (bounded) while the 1-minute load average exceeds ``ratio x cores``, then
proceeds. It NEVER fails on load alone: after ``--max-wait-secs`` it prints a
``::warning::`` and exits 0, so a busy host delays a leg but never turns it red.
Exit 2 is reserved for bad arguments.

Usage: python3 scripts/ci/load_gate.py --label "<os>/<tier>" [--max-ratio 1.5]
       [--max-wait-secs 1200] [--poll-secs 30]

Python 3.9+, standard library only.
"""
import argparse
import os
import sys
import time

TAG = '[#6795 load gate]'


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


def run(label, max_ratio, max_wait_secs, poll_secs, cores, load_fn, sleep_fn):
    """Poll until the load is acceptable or the wait budget is spent. Always returns 0."""
    waited = 0
    try:
        load = load_fn()
    except (OSError, AttributeError) as exc:
        print('::warning::%s %r: cannot read the load average (%s); proceeding without the gate'
              % (TAG, label, exc), flush=True)
        return 0
    print(format_notice(label, load, cores, max_ratio, waited), flush=True)
    while should_wait(load, cores, max_ratio):
        if waited >= max_wait_secs:
            print('::warning::%s %r: load=%.2f still above %s x %d cores after %ds; '
                  'proceeding anyway (the gate never fails on load alone)'
                  % (TAG, label, load, max_ratio, cores, waited), flush=True)
            break
        step = min(poll_secs, max_wait_secs - waited)
        sleep_fn(step)
        waited += step
        try:
            load = load_fn()
        except (OSError, AttributeError) as exc:
            print('::warning::%s %r: load average became unreadable (%s); proceeding'
                  % (TAG, label, exc), flush=True)
            return 0
        if should_wait(load, cores, max_ratio):
            print(_plain(label, load, cores, max_ratio, waited), flush=True)
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
    args = p.parse_args(argv)  # argparse exits 2 on bad arguments
    return run(args.label, args.max_ratio, args.max_wait_secs, args.poll_secs,
               os.cpu_count(), lambda: os.getloadavg()[0], time.sleep)


if __name__ == '__main__':
    sys.exit(main())
