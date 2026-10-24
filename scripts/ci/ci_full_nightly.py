"""Nightly full CI: dispatch ci.yml, wait for it, report a red run (#8240).

Usage:
    python3 -I scripts/ci/ci_full_nightly.py dispatch --repo <owner/name> \
        --ref <branch> [--github-output <file>]
    python3 -I scripts/ci/ci_full_nightly.py report --repo <owner/name> \
        --job-result <result> --conclusion <conclusion> --run-url <url> --ref <branch>

`dispatch` starts ci.yml on `--ref` through `gh workflow run`, finds the run it
created, waits for it to complete and writes `conclusion=` and `run_url=` to
the GitHub output file. It exits 1 only when it cannot dispatch, find or wait
for the run.

`report` exits 0 only when the dispatch job and the dispatched run both
succeeded. Otherwise it opens ONE issue labelled `ci-full-red` (deduped by
exact title; an existing open issue gets a comment) and exits 1, so a red
nightly is visible and the workflow run itself is red.
"""
import argparse
import json
import re
import subprocess
import sys
import time
from typing import Callable, List, Optional, Tuple

WORKFLOW_FILE = "ci.yml"
ISSUE_LABEL = "ci-full-red"
ISSUE_LABEL_COLOR = "B60205"
ISSUE_TITLE = "CI full (nightly) is red"
REF_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}$")
CONCLUSION_SUCCESS = "success"
RESULT_SUCCESS = "success"
STATUS_COMPLETED = "completed"
POLL_INTERVAL_S = 30
FIND_ATTEMPTS = 20
WAIT_ATTEMPTS = 680
GH_TIMEOUT_S = 120
EXIT_OK = 0
EXIT_FAIL = 1
RUN_FIELDS = "databaseId,url"

Runner = Callable[[List[str]], Tuple[int, str]]


class NightlyError(RuntimeError):
    """The dispatch could not be started, found or awaited."""


def gh_runner(args: List[str]) -> Tuple[int, str]:
    """Run `gh <args>` and return (returncode, stdout). Never uses a shell."""
    try:
        res = subprocess.run(["gh"] + args, capture_output=True, text=True,
                             timeout=GH_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return res.returncode, res.stdout


def validate_ref(ref: str) -> str:
    """Return `ref` when it is a safe branch or tag name, else raise ValueError."""
    if not REF_RE.match(ref) or ".." in ref:
        raise ValueError("unsafe or empty ref: %r" % ref[:60])
    return ref


def list_runs(gh: Runner, repo: str, ref: str) -> List[dict]:
    """Return recent workflow_dispatch runs of ci.yml on `ref`."""
    code, out = gh(["run", "list", "--repo", repo, "--workflow", WORKFLOW_FILE,
                    "--event", "workflow_dispatch", "--branch", ref,
                    "--limit", "20", "--json", RUN_FIELDS])
    if code != 0:
        raise NightlyError("gh run list failed")
    try:
        rows = json.loads(out or "[]")
    except ValueError as exc:
        raise NightlyError("gh run list returned invalid JSON") from exc
    return [row for row in rows if isinstance(row, dict) and "databaseId" in row]


def dispatch_and_wait(gh: Runner, repo: str, ref: str,
                      sleep: Callable[[float], None] = time.sleep,
                      find_attempts: int = FIND_ATTEMPTS,
                      wait_attempts: int = WAIT_ATTEMPTS) -> dict:
    """Dispatch ci.yml on `ref`, wait, and return {run_id, url, conclusion}."""
    ref = validate_ref(ref)
    known = {row["databaseId"] for row in list_runs(gh, repo, ref)}
    code, out = gh(["workflow", "run", WORKFLOW_FILE, "--repo", repo, "--ref", ref])
    if code != 0:
        raise NightlyError("gh workflow run failed: %s" % out.strip()[-200:])
    run = None
    for _ in range(find_attempts):
        fresh = [r for r in list_runs(gh, repo, ref) if r["databaseId"] not in known]
        if fresh:
            run = max(fresh, key=lambda r: r["databaseId"])
            break
        sleep(POLL_INTERVAL_S)
    if run is None:
        raise NightlyError("the dispatched ci.yml run did not appear")
    for _ in range(wait_attempts):
        code, out = gh(["run", "view", str(run["databaseId"]), "--repo", repo,
                        "--json", "status,conclusion"])
        if code == 0:
            try:
                state = json.loads(out)
            except ValueError:
                state = {}
            if state.get("status") == STATUS_COMPLETED:
                return {"run_id": run["databaseId"], "url": run.get("url", ""),
                        "conclusion": state.get("conclusion") or ""}
        sleep(POLL_INTERVAL_S)
    raise NightlyError("the dispatched ci.yml run did not complete in time")


def ensure_label(gh: Runner, repo: str) -> None:
    """Create the label when absent; an existing label is not an error."""
    gh(["label", "create", ISSUE_LABEL, "--repo", repo, "--color", ISSUE_LABEL_COLOR,
        "--description", "Nightly full CI run is red"])


def find_open_issue(gh: Runner, repo: str) -> Optional[int]:
    """Return the number of the open issue titled exactly ISSUE_TITLE."""
    code, out = gh(["issue", "list", "--repo", repo, "--label", ISSUE_LABEL,
                    "--state", "open", "--limit", "50", "--json", "number,title"])
    if code != 0:
        return None
    try:
        rows = json.loads(out or "[]")
    except ValueError:
        return None
    for row in rows:
        if isinstance(row, dict) and row.get("title") == ISSUE_TITLE:
            return int(row["number"])
    return None


def report(gh: Runner, repo: str, job_result: str, conclusion: str, run_url: str,
           ref: str) -> int:
    """Return 0 for a green nightly, else file or update the issue and return 1."""
    if job_result == RESULT_SUCCESS and conclusion == CONCLUSION_SUCCESS:
        return EXIT_OK
    body = ("The nightly full run of ci.yml on `%s` is red.\n\n"
            "- dispatch job result: `%s`\n- dispatched run conclusion: `%s`\n"
            "- run: %s\n" % (ref, job_result or "unknown", conclusion or "unknown",
                            run_url or "not available"))
    number = find_open_issue(gh, repo)
    if number is None:
        ensure_label(gh, repo)
        code, out = gh(["issue", "create", "--repo", repo, "--title", ISSUE_TITLE,
                        "--label", ISSUE_LABEL, "--body", body])
    else:
        code, out = gh(["issue", "comment", str(number), "--repo", repo,
                        "--body", body])
    if code != 0:
        print("ci-full: could not file the issue: %s" % out.strip()[-200:],
              file=sys.stderr)
    return EXIT_FAIL


def write_output(path: Optional[str], values: dict) -> None:
    """Append key=value lines to the GitHub output file."""
    if not path:
        return
    with open(path, "a") as handle:
        for key, value in values.items():
            handle.write("%s=%s\n" % (key, str(value).replace("\n", " ")))


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    disp = sub.add_parser("dispatch")
    disp.add_argument("--repo", required=True)
    disp.add_argument("--ref", required=True)
    disp.add_argument("--github-output")
    rep = sub.add_parser("report")
    rep.add_argument("--repo", required=True)
    rep.add_argument("--ref", required=True)
    rep.add_argument("--job-result", default="")
    rep.add_argument("--conclusion", default="")
    rep.add_argument("--run-url", default="")
    args = parser.parse_args(argv)
    if args.command == "dispatch":
        try:
            result = dispatch_and_wait(gh_runner, args.repo, args.ref)
        except (NightlyError, ValueError) as exc:
            print("ci-full: %s" % exc, file=sys.stderr)
            return EXIT_FAIL
        write_output(args.github_output, {"conclusion": result["conclusion"],
                                          "run_url": result["url"]})
        print("ci-full: run %s concluded %s" % (result["run_id"], result["conclusion"]))
        return EXIT_OK
    return report(gh_runner, args.repo, args.job_result, args.conclusion,
                  args.run_url, args.ref)


if __name__ == "__main__":
    sys.exit(main())
