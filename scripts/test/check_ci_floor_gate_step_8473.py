#!/usr/bin/env python3
"""ci.yml invariant (#8473 round 2): the Dependency floor gate (OSV) step.

The step must (1) carry `!cancelled()` in its `if:` so a failed earlier step
(a red cargo audit, a red test leg) never skips it, (2) keep the cargo_skip and
matrix.once conditions, and (3) sit BEFORE the Security audit step in the same
job. Exit 0 when all hold, 1 otherwise, 2 when the step cannot be found.

Usage: python3 -I scripts/test/check_ci_floor_gate_step_8473.py [--ci-yml PATH]
Python 3.9+, standard library only.
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STEP_NAME = "Dependency floor gate (OSV)"
AUDIT_NAME = "Security audit"
STEP_RE = re.compile(r"^(\s*)- name: (.+?)\s*$")
IF_RE = re.compile(r"^\s+if:\s*(.*?)\s*$")


def find_steps(lines, name):
    """Return [(line_index, if_expression_or_None)] for every step with this name."""
    found = []
    for idx, line in enumerate(lines):
        m = STEP_RE.match(line)
        if not m or m.group(2) != name:
            continue
        indent = len(m.group(1))
        cond = None
        for nxt in lines[idx + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            im = IF_RE.match(nxt)
            if im:
                cond = im.group(1)
                break
        found.append((idx, cond))
    return found


def check(text):
    """Return a list of problems for a ci.yml text."""
    lines = text.splitlines()
    gate = find_steps(lines, STEP_NAME)
    audit = find_steps(lines, AUDIT_NAME)
    if len(gate) != 1:
        return None, ["expected exactly one '%s' step, found %d" % (STEP_NAME, len(gate))]
    problems = []
    idx, cond = gate[0]
    if cond is None:
        problems.append("the gate step has no if: condition")
        cond = ""
    if "!cancelled()" not in cond:
        problems.append("the gate step if: lacks !cancelled(), a red earlier step would skip it: %s" % cond)
    if "needs.classify.outputs.cargo_skip != 'true'" not in cond:
        problems.append("the gate step if: lost the cargo_skip condition: %s" % cond)
    if "matrix.once" not in cond:
        problems.append("the gate step if: lost matrix.once: %s" % cond)
    if len(audit) != 1:
        problems.append("expected exactly one '%s' step, found %d" % (AUDIT_NAME, len(audit)))
    elif idx > audit[0][0]:
        problems.append("the gate step sits after the Security audit step")
    return gate, problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ci-yml", default=str(ROOT / ".github" / "workflows" / "ci.yml"))
    args = ap.parse_args(argv)
    gate, problems = check(Path(args.ci_yml).read_text())
    if gate is None:
        print("ci-floor-gate-step: %s" % problems[0], file=sys.stderr)
        return 2
    for msg in problems:
        print("ci-floor-gate-step: FAIL %s" % msg, file=sys.stderr)
    if problems:
        return 1
    print("ci-floor-gate-step: ok (!cancelled(), cargo_skip, matrix.once, before Security audit)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
