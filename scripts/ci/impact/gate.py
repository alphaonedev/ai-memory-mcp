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


def evaluate(needs: dict, job_map: Dict[str, str], github_ref: str = "",
             tag_skip_jobs: Iterable[str] = ()) -> Tuple[bool, List[dict]]:
    """Return (ok, rows) for a needs document."""
    rows: List[dict] = []
    ok = True
    tag_skip = list(tag_skip_jobs)
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
        rows.append({"job": job, "result": result, "selected": not excused,
                     "ok": passed})
    return ok, rows


def render(rows: List[dict]) -> str:
    """Render the verdict table."""
    width = max([len(r["job"]) for r in rows] + [3])
    lines = ["%-*s  %-10s  %-8s  %s" % (width, "job", "result", "selected", "ok")]
    for row in rows:
        lines.append("%-*s  %-10s  %-8s  %s" % (
            width, row["job"], row["result"], "yes" if row["selected"] else "no",
            "pass" if row["ok"] else "FAIL"))
    return "\n".join(lines)


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
    ok, rows = evaluate(needs, job_map, args.github_ref, tag_skip_jobs)
    print(render(rows))
    print("ci-gate: %s" % ("pass" if ok else "FAIL"))
    return common.EXIT_OK if ok else common.EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
