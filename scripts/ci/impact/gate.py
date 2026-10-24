"""ci-gate: fold the `toJSON(needs)` of the aggregate job into one verdict (#8240).

Usage:
    python3 -I scripts/ci/impact/gate.py --needs <json | @file> \
        --jobs <comma list> --all <true|false> [--rules rules.json]

A job that succeeded passes. A job skipped by selection passes (its job key
is not in the selection and `--all` is false). Every other outcome fails:
failure, cancelled, timed_out, an unknown or missing result, or a skipped job
that WAS selected. A job with no key in rules.json job_map (select, classify)
is always required to succeed. Exit 0 only when every selected job succeeded.
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from impact import common  # noqa: E402

RESULT_SUCCESS = "success"
RESULT_SKIPPED = "skipped"
FILE_PREFIX = "@"


def evaluate(needs: dict, selected_jobs: Set[str], all_flag: bool,
             job_map: Dict[str, str]) -> Tuple[bool, List[dict]]:
    """Return (ok, rows) for a needs document and a selection."""
    rows: List[dict] = []
    ok = True
    for job in sorted(needs):
        result = (needs[job] or {}).get("result")
        key = job_map.get(job)
        selected = True if key is None else (all_flag or key in selected_jobs)
        if result == RESULT_SUCCESS:
            passed = True
        elif result == RESULT_SKIPPED:
            passed = not selected
        else:
            passed = False
        ok = ok and passed
        rows.append({"job": job, "result": result, "selected": selected, "ok": passed})
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
    parser.add_argument("--jobs", default="", help="comma list of selected job keys")
    parser.add_argument("--all", default="false", help="true when the full matrix was selected")
    parser.add_argument("--rules", help="alternative rules.json")
    args = parser.parse_args(argv)
    try:
        needs = read_needs(args.needs)
        job_map = common.load_rules(Path(args.rules) if args.rules else None)["job_map"]
    except (ValueError, OSError, KeyError) as exc:
        common.log("gate: unusable input: %s" % exc)
        return common.EXIT_USAGE
    selected = {j for j in args.jobs.split(",") if j}
    ok, rows = evaluate(needs, selected, args.all.lower() == "true", job_map)
    print(render(rows))
    print("ci-gate: %s" % ("pass" if ok else "FAIL"))
    return common.EXIT_OK if ok else common.EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
