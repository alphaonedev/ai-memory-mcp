#!/usr/bin/env python3
"""Warn when a GREEN test shard used most of its watchdog budget (#7343).

The #1492 watchdog notice prints ``% used`` after every shard, but a green shard
creeping toward 100 % stays invisible until it goes red (PR #7298: the serial
shard ran 3611 s of its 3611 s budget). ``run_tests`` calls this after every
green invocation; above ``--threshold`` percent it prints a GitHub Actions
``::warning::`` line, so the ratchet shows in the run summary first.

Never fails the step: a zero or negative budget prints nothing and exits 0 (a
margin warning must not turn a green run red). Exit 2 is reserved for argparse
usage errors (a missing or non-integer argument); the workflow ignores it with
``|| true``. Every value written into the workflow command is escaped (``%``,
CR and LF), so a hostile label cannot start a second command line (#7350).

Python 3.9+, standard library only.
"""
import argparse
import sys

DEFAULT_THRESHOLD_PCT = 85


def percent_used(elapsed, budget):
    """Whole percent of the budget used; None when the budget is not positive."""
    if budget <= 0:
        return None
    return elapsed * 100 // budget


def escape_data(value):
    """GitHub Actions workflow-command data escaping: % -> %25, CR -> %0D, LF -> %0A (% first)."""
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def warning_for(label, elapsed, budget, threshold, tier, node):
    """Return the ::warning:: line when used% exceeds the threshold, else None."""
    pct = percent_used(elapsed, budget)
    if pct is None or pct <= threshold:
        return None
    return (
        "::warning::[#7343] '%s' passed but used %ds of the %ds watchdog budget "
        "(%d%% used, over the %d%% margin guard, %ds left; tier=%s node=%s): "
        "the shard is close to going red under host load"
        % (escape_data(label), elapsed, budget, pct, threshold, budget - elapsed, escape_data(tier), escape_data(node))
    )


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--label", required=True)
    ap.add_argument("--elapsed", type=int, required=True)
    ap.add_argument("--budget", type=int, required=True)
    ap.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD_PCT)
    ap.add_argument("--tier", default="unknown")
    ap.add_argument("--node", default="unknown")
    a = ap.parse_args(argv)
    line = warning_for(a.label, a.elapsed, a.budget, a.threshold, a.tier, a.node)
    if line:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
