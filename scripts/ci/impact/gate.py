"""ci-gate: fold the `toJSON(needs)` of the aggregate job into one verdict (#8240).

Usage:
    python3 -I scripts/ci/impact/gate.py --needs <json | @file> \
        [--github-ref <ref>] [--rules rules.json]

Fail closed. A job that succeeded passes. A SKIPPED job passes only when
  - `classify` succeeded and recorded docs_only 'true' (the gated jobs carry
    that condition themselves), or
  - `select` succeeded AND its recorded output for the job's domain is the
    literal 'false', or
  - the ref is a version tag and the job is listed in rules.json
    tag_skip_jobs.
Every other outcome fails: failure, cancelled, timed_out, an unknown or
missing result, a skip while `select` failed, was cancelled or skipped, a skip
with an empty, missing or malformed domain output. A job with no key in
rules.json job_map (select, classify, build-script-vetting) must succeed.
A job of REQUIRED_NEEDS that is absent from the needs payload fails the gate
with the fixed reason `missing-needed-job` naming the job.
decision: the gate requires the full expected job set over tolerating an
absent job because an absent result is indistinguishable from a skipped gate
Exit 0 only when every job passed.
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from impact import common  # noqa: E402

RESULT_SUCCESS = "success"
RESULT_SKIPPED = "skipped"
FILE_PREFIX = "@"
SELECT_JOB = "select"
CLASSIFY_JOB = "classify"
DOMAIN_FALSE = "false"
DOCS_ONLY_KEY = "docs_only"
DOCS_ONLY_TRUE = "true"
TAG_REF_PREFIX = "refs/tags/v"
MISSING_REASON = "missing-needed-job"
# #9231: the `check` matrix job exports one output per leg, `slot_starved_<index>`,
# set to 'true' by scripts/ci/host_semaphore.py when no host slot was free and no
# test ran. A failed `check` with such an output is the named outcome below; it
# is still NOT a pass (a required check must never pass on a job that judged
# nothing) and it exits with its own code so the verdict says "not a test failure".
INFRA_JOB = "check"
INFRA_OUTPUT_PREFIX = "slot_starved"
INFRA_OUTPUT_TRUE = "true"
INFRA_RESULT = "infra: no slot"
RESULT_FAILURE = "failure"
EXIT_INFRA = 4
# The `needs:` list of the ci-gate job in .github/workflows/ci.yml; a test
# keeps the two in step.
REQUIRED_NEEDS = ("select", "classify", "build-script-vetting", "check",
                  "mobile-cross-compile")


def outputs_of(needs: dict, job: str) -> dict:
    """Return the outputs object of `job` (empty when absent or malformed)."""
    outputs = (needs.get(job) or {}).get("outputs")
    return outputs if isinstance(outputs, dict) else {}


def result_of(needs: dict, job: str) -> Optional[str]:
    """Return the result string of `job`, or None."""
    return (needs.get(job) or {}).get("result")


def skip_allowed(needs: dict, job: str, key: Optional[str], github_ref: str,
                 tag_skip_jobs: Iterable[str]) -> bool:
    """Return True when a skipped `job` is a legitimate, recorded skip."""
    if key is None:
        return False
    if (result_of(needs, CLASSIFY_JOB) == RESULT_SUCCESS
            and outputs_of(needs, CLASSIFY_JOB).get(DOCS_ONLY_KEY) == DOCS_ONLY_TRUE):
        return True
    if github_ref.startswith(TAG_REF_PREFIX) and job in set(tag_skip_jobs):
        return True
    return (result_of(needs, SELECT_JOB) == RESULT_SUCCESS
            and outputs_of(needs, SELECT_JOB).get(key) == DOMAIN_FALSE)


def no_slot_outcome(needs: dict, job: str) -> bool:
    """True when `job` is the check job, failed, and a leg recorded that no host slot was free."""
    if job != INFRA_JOB or result_of(needs, job) != RESULT_FAILURE:
        return False
    return any(key.startswith(INFRA_OUTPUT_PREFIX + "_") and value == INFRA_OUTPUT_TRUE
               for key, value in outputs_of(needs, job).items())


def evaluate(needs: dict, job_map: Dict[str, str], github_ref: str = "",
             tag_skip_jobs: Iterable[str] = (),
             required: Iterable[str] = ()) -> Tuple[bool, List[dict]]:
    """Return (ok, rows) for a needs document; every `required` job must be present."""
    rows: List[dict] = []
    ok = True
    tag_skip = list(tag_skip_jobs)
    for job in sorted(set(required) - set(needs)):
        ok = False
        rows.append({"job": job, "result": MISSING_REASON, "selected": True,
                     "ok": False})
    for job in sorted(needs):
        result = result_of(needs, job)
        key = job_map.get(job)
        excused = skip_allowed(needs, job, key, github_ref, tag_skip)
        if result == RESULT_SUCCESS:
            passed = True
        elif result == RESULT_SKIPPED:
            passed = excused
        else:
            passed = False
        ok = ok and passed
        infra = (not passed) and no_slot_outcome(needs, job)
        rows.append({"job": job, "result": INFRA_RESULT if infra else result,
                     "selected": not excused, "ok": passed, "infra": infra})
    return ok, rows


def render(rows: List[dict]) -> str:
    """Render the verdict table."""
    width = max([len(r["job"]) for r in rows] + [3])
    rwidth = max([len(str(r["result"])) for r in rows] + [10])
    lines = ["%-*s  %-*s  %-8s  %s" % (width, "job", rwidth, "result", "selected", "ok")]
    for row in rows:
        lines.append("%-*s  %-*s  %-8s  %s" % (
            width, row["job"], rwidth, row["result"], "yes" if row["selected"] else "no",
            "pass" if row["ok"] else "FAIL"))
    return "\n".join(lines)


def only_infra_failures(rows: List[dict]) -> bool:
    """True when at least one row failed and every failed row is the no-slot outcome."""
    failed = [r for r in rows if not r["ok"]]
    return bool(failed) and all(r.get("infra") for r in failed)


def read_needs(arg: str) -> dict:
    """Parse the --needs argument (JSON text, or @path to a JSON file)."""
    text = Path(arg[len(FILE_PREFIX):]).read_text() if arg.startswith(FILE_PREFIX) else arg
    doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ValueError("needs must be a JSON object")
    return doc


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--needs", required=True)
    parser.add_argument("--github-ref", default="", help="github.ref of the run")
    parser.add_argument("--rules", help="alternative rules.json")
    args = parser.parse_args(argv)
    try:
        needs = read_needs(args.needs)
        rules = common.load_rules(Path(args.rules) if args.rules else None)
        job_map = rules["job_map"]
        tag_skip_jobs = rules.get("tag_skip_jobs", [])
    except (ValueError, OSError, KeyError) as exc:
        common.log("gate: unusable input: %s" % exc)
        return common.EXIT_USAGE
    ok, rows = evaluate(needs, job_map, args.github_ref, tag_skip_jobs, REQUIRED_NEEDS)
    print(render(rows))
    for row in rows:
        if row["result"] == MISSING_REASON:
            print("ci-gate: %s: %s" % (MISSING_REASON, row["job"]))
    if not ok and only_infra_failures(rows):
        print("ci-gate: INFRA (%s): not a test failure, no test ran; the gate stays red, re-run the job"
              % INFRA_RESULT)
        return EXIT_INFRA
    print("ci-gate: %s" % ("pass" if ok else "FAIL"))
    return common.EXIT_OK if ok else common.EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
