#!/usr/bin/env python3
"""Decide which ``Check`` matrix tiers run on this workflow run (#8174).

The ``Check`` job in ``.github/workflows/ci.yml`` has four legs. Two of them
(``linux-fed,enterprise-fed`` and ``macos-fed,enterprise-fed``) run the sharded
sal-postgres suite on a self-hosted ``linux-fed`` / ``macos-fed`` runner. Run on
EVERY topic-branch pull request, the linux-fed leg held one of the four
linux-fed runners for 2 h 09 min to 2 h 37 min per PR run, green or red
(measured: runs 40172299587 and 40181658963 passed in 2 h 09-2 h 11; job
121109122420 ran 17:56Z-20:31Z and the #1492 watchdog then killed the serial
shard). The justification is compute, not signal. sal-postgres coverage for
topic PRs lives in ``cert-postgres-age.yml`` and ``postgres-ignored.yml``; both run on every
same-repo ``pull_request`` to ``release/**``, ``rehearsal/**`` and ``chain/**`` (neither is
label-gated).

Rule, one place:

* ``pull_request`` whose BASE branch starts with ``chain/`` and whose head
  branch does NOT (a topic PR into a chain carrier): only the ``sqlite`` tier
  is active. The hosted no-op is sound only because the chain carrier PR runs
  the real legs afterwards, so a PR that lands anywhere else (``release/**``,
  ``rehearsal/**``, ``main``, ``develop``) keeps both tiers (security r1 F1).
* every other run (``pull_request`` from a ``chain/`` carrier branch or into a non-chain base, ``push``,
  ``merge_group``, ``schedule`` and anything unknown; ci.yml itself triggers only on
  ``push``, ``pull_request`` and ``merge_group``):
  both tiers are active. The chain branch is tested ONLY through the
  ``pull_request`` runs of its carrier PR, so "push only" would drop the chain
  from coverage; the ``chain/`` carve-out keeps it.

Fail closed: an event this script does not recognise runs everything.

The workflow keeps all four legs (the check names never change). A leg whose
tier is inactive is rerouted to a hosted runner: the checkout and the notice
step run and the tier-guarded steps are skipped, the same no-op shape the
docs-only path already uses, so no self-hosted runner is held and the contexts
still report.

Usage (in the ``classify`` job, context passed through env, never inlined):
    EVENT_NAME=pull_request HEAD_REF=fix/x BASE_REF=chain/x python3 -I scripts/ci/check_legs.py \\
        --github-output "$GITHUB_OUTPUT"
prints ``check_tiers=sqlite`` (comma separated) and, with ``--github-output``,
appends the same line to that file.

Exit codes: 0 success, 2 bad arguments (empty ``EVENT_NAME``) or a malformed
event (``pull_request`` with an empty ``HEAD_REF`` or ``BASE_REF``: loud, never a silent
drop of the enterprise-fed tier).

Python 3.9+, standard library only.
"""
import argparse
import os
import sys

TIER_SQLITE = 'sqlite'
TIER_ENTERPRISE_FED = 'enterprise-fed'
ALL_TIERS = (TIER_SQLITE, TIER_ENTERPRISE_FED)
EVENT_PULL_REQUEST = 'pull_request'
CHAIN_BRANCH_PREFIX = 'chain/'
OUTPUT_KEY = 'check_tiers'
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_MALFORMED_EVENT = 2


def active_tiers(event_name, head_ref, base_ref):
    """Return the tuple of tiers the ``Check`` job runs for this event."""
    if (event_name == EVENT_PULL_REQUEST and base_ref.startswith(CHAIN_BRANCH_PREFIX)
            and not head_ref.startswith(CHAIN_BRANCH_PREFIX)):
        return (TIER_SQLITE,)
    return ALL_TIERS


def output_line(tiers):
    return '%s=%s' % (OUTPUT_KEY, ','.join(tiers))


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--event-name', default=os.environ.get('EVENT_NAME', ''))
    parser.add_argument('--head-ref', default=os.environ.get('HEAD_REF', ''))
    parser.add_argument('--base-ref', default=os.environ.get('BASE_REF', ''))
    parser.add_argument('--github-output', default=None,
                        help='file to append the output line to (the $GITHUB_OUTPUT file)')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if not args.event_name:
        print('check_legs: EVENT_NAME is empty', file=sys.stderr)
        return EXIT_USAGE
    if args.event_name == EVENT_PULL_REQUEST and not args.head_ref:
        print('check_legs: malformed event: pull_request with an empty head ref (HEAD_REF)',
              file=sys.stderr)
        return EXIT_MALFORMED_EVENT
    if args.event_name == EVENT_PULL_REQUEST and not args.base_ref:
        print('check_legs: malformed event: pull_request with an empty base ref (BASE_REF)',
              file=sys.stderr)
        return EXIT_MALFORMED_EVENT
    line = output_line(active_tiers(args.event_name, args.head_ref, args.base_ref))
    print(line)
    if args.github_output:
        with open(args.github_output, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')
    return EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
