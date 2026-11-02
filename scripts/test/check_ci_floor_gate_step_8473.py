#!/usr/bin/env python3
"""ci.yml invariant (#8473 round 3): the OSV dependency floor gate job.

Round 2 kept the gate as a step of the `check` job. A skipped `check` job or a
skipped matrix leg hid it, and a step-level `!cancelled()` cannot rescue a
job-level skip. Round 3 moves it into its own job and this check asserts:

1. job `dependency-floors` exists once, `needs: classify`, runs on
   ubuntu-latest, has `timeout-minutes: 15`, and its job-level `if:` is a
   conjunction whose terms include, exactly, `!cancelled()` and
   `needs.classify.result != 'skipped'` (no `||`);
2. the job runs the gate script, then the scripts/ci/tests suite after a
   setup-python step pinned to 3.12 and again after one pinned to 3.x (current
   stable); python 3.9 is end of life and is never a leg (memory 59123ea0);
3. no other job carries a step named "Dependency floor gate (OSV)";
4. the Security audit step in `check` (exactly one) has an `if:` conjunction
   with the exact terms `!cancelled()`, `needs.classify.outputs.cargo_skip !=
   'true'` and `matrix.once`.

Terms are compared as whole tokens of the `&&` split, so `!matrix.once` or a
substring inside a longer term never satisfies a requirement.
Exit 0 when all hold, 1 otherwise, 2 when the job cannot be found.

Usage: python3 -I scripts/test/check_ci_floor_gate_step_8473.py [--ci-yml PATH]
Python 3.9+, standard library only.
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
JOB_ID = "dependency-floors"
RUNNER = "ubuntu-latest"
PY_LEGS = ("3.12", "3.x")
GATE_NAME = "Dependency floor gate (OSV)"
AUDIT_NAME = "Security audit"
AUDIT_JOB = "check"
JOB_TERMS = ("!cancelled()", "needs.classify.result != 'skipped'")
AUDIT_TERMS = ("!cancelled()", "needs.classify.outputs.cargo_skip != 'true'", "matrix.once")
JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
STEP_RE = re.compile(r"^(\s*)- name: (.+?)\s*$")
IF_RE = re.compile(r"^(\s+)if:\s*(.*?)\s*$")


def split_jobs(text):
    """Return {job id: [lines]} for the top-level jobs of a workflow text."""
    jobs, cur, in_jobs = {}, None, False
    for line in text.splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if line and not line.startswith(" ") and not line.startswith("#"):
            break
        m = JOB_RE.match(line)
        if m:
            cur = m.group(1)
            jobs[cur] = []
        elif cur is not None:
            jobs[cur].append(line)
    return jobs


def terms(expr):
    """Tokenise an if: expression into its top-level `&&` terms.

    Returns (terms, has_or). `${{ }}` wrapping is removed first. A term is
    compared whole, so `!matrix.once` is not `matrix.once`.
    """
    expr = expr.strip()
    m = re.match(r"^\$\{\{\s*(.*?)\s*\}\}$", expr)
    if m:
        expr = m.group(1)
    return [t.strip() for t in expr.split("&&")], "||" in expr


def job_field(lines, key):
    """Value of a job-level (4-space) key, or None."""
    pat = re.compile(r"^    %s:\s*(.*?)\s*$" % re.escape(key))
    for line in lines:
        m = pat.match(line)
        if m:
            return m.group(1)
    return None


def steps(lines):
    """[(name, if_expression_or_None, block_text)] for the named steps of a job."""
    out = []
    for idx, line in enumerate(lines):
        m = STEP_RE.match(line)
        if not m:
            continue
        indent = len(m.group(1))
        cond, block = None, [line]
        for nxt in lines[idx + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent and not nxt.lstrip().startswith("#"):
                break
            block.append(nxt)
            im = IF_RE.match(nxt)
            if im and cond is None and len(im.group(1)) == indent + 2:
                cond = im.group(2)
        out.append((m.group(2), cond, "\n".join(block)))
    return out


def conjunction_problems(label, expr, required):
    if expr is None or not expr.strip():
        return ["%s has no if: condition" % label]
    got, has_or = terms(expr)
    problems = []
    if has_or:
        problems.append("%s if: contains ||, a disjunction can widen the run: %s" % (label, expr))
    for need in required:
        if need not in got:
            problems.append("%s if: lacks the exact term %s: %s" % (label, need, expr))
    return problems


def check(text):
    """Return (job_lines_or_None, [problems]) for a ci.yml text."""
    jobs = split_jobs(text)
    if JOB_ID not in jobs:
        return None, ["no job '%s' found" % JOB_ID]
    lines = jobs[JOB_ID]
    problems = []
    problems += conjunction_problems("job %s" % JOB_ID, job_field(lines, "if"), JOB_TERMS)
    if job_field(lines, "needs") != "classify":
        problems.append("job %s must have needs: classify, found %r" % (JOB_ID, job_field(lines, "needs")))
    if job_field(lines, "runs-on") != RUNNER:
        problems.append("job %s must run on ubuntu-latest, found %r" % (JOB_ID, job_field(lines, "runs-on")))
    if job_field(lines, "timeout-minutes") != "15":
        problems.append("job %s must set timeout-minutes: 15, found %r"
                        % (JOB_ID, job_field(lines, "timeout-minutes")))
    body = "\n".join(lines)
    gate_pos = body.find("scripts/check-dependency-floors.py")
    if gate_pos < 0:
        problems.append("job %s does not run scripts/check-dependency-floors.py" % JOB_ID)
    setups = [(m.start(), m.group(1)) for m in
              re.finditer(r"python-version:\s*['\"]?([0-9][0-9.x]*)['\"]?\s*$", body, re.M)]
    if any(v.startswith("3.9") for _, v in setups):
        problems.append("job %s has a python 3.9 leg; 3.9 is end of life" % JOB_ID)
    suite_word = "unittest discover -s scripts/ci/tests"
    if body.find(suite_word) < 0:
        problems.append("job %s does not run the scripts/ci/tests suite" % JOB_ID)
    for want in PY_LEGS:
        starts = [pos for pos, v in setups if v == want]
        if not starts:
            problems.append("job %s has no setup-python step pinned to python-version %s" % (JOB_ID, want))
            continue
        end = min([pos for pos, _ in setups if pos > starts[0]] + [len(body)])
        if body.find(suite_word, starts[0], end) < 0:
            problems.append("job %s does not run the suite after the %s setup-python step" % (JOB_ID, want))
    for other, other_lines in jobs.items():
        if other != JOB_ID and any(name == GATE_NAME for name, _, _ in steps(other_lines)):
            problems.append("job %s still carries a '%s' step" % (other, GATE_NAME))
    audit = [s for s in steps(jobs.get(AUDIT_JOB, [])) if s[0] == AUDIT_NAME]
    if len(audit) != 1:
        problems.append("expected exactly one '%s' step in job %s, found %d"
                        % (AUDIT_NAME, AUDIT_JOB, len(audit)))
    else:
        problems += conjunction_problems("step %s" % AUDIT_NAME, audit[0][1], AUDIT_TERMS)
    return lines, problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ci-yml", default=str(ROOT / ".github" / "workflows" / "ci.yml"))
    args = ap.parse_args(argv)
    job, problems = check(Path(args.ci_yml).read_text())
    if job is None:
        print("ci-floor-gate-step: %s" % problems[0], file=sys.stderr)
        return 2
    for msg in problems:
        print("ci-floor-gate-step: FAIL %s" % msg, file=sys.stderr)
    if problems:
        return 1
    print("ci-floor-gate-step: ok (own job, !cancelled() and classify not skipped, py3.12 and 3.x legs, "
          "audit step !cancelled())")
    return 0


if __name__ == "__main__":
    sys.exit(main())
