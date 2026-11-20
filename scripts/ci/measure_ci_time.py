# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Measure where the minutes of a CI test job go (#9710). Read-only.

For the newest green runs of ci.yml and coverage.yml on one branch it reads the
jobs API (`gh api` GET only) and prints, per test job and runner kind, the queue
wait, setup and cache restore, compile, test run, cache save and post steps, and
the total, as median and range over the runs.

Compile and test often share one step (`Run tests`, `Generate coverage JSON`).
The split comes from the job log: the first cargo `Finished ... target(s) in
<duration>` line gives the compile time cargo reported, and the rest of that step
is the test run. A step whose log holds no such line is reported as "not
separable". The log is fetched to a scratch file, parsed here and deleted; no log
text is printed.

Usage:
    python3 -I scripts/ci/measure_ci_time.py --repo OWNER/NAME --branch BRANCH \
        [--runs 10] [--scratch DIR] [--no-logs] [--json-out FILE]
    python3 -I scripts/ci/measure_ci_time.py --repo OWNER/NAME --branch BRANCH --rank-job JOB_ID

`--rank-job` prints the test binaries with the longest `finished in` time from one job log.

Exit codes: 0 done, 2 usage error (argparse), 3 a gh call failed, 4 no green run found.
"""
import argparse
import json
import re
import statistics
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

EXIT_OK = 0
EXIT_GH_FAILED = 3
EXIT_NO_RUNS = 4
WORKFLOWS = ("ci.yml", "coverage.yml")
MAX_RUNS = 30  # one API page is 100 rows; the request is capped well below that
MAX_JOB_PAGES = 3
JOBS_PER_PAGE = 100
GH_TIMEOUT_SECS = 120
LOG_TIMEOUT_SECS = 300
TEST_JOB_RE = re.compile(r"^(Check \(|Per-Module Coverage)")
COMBINED_STEP_RE = re.compile(r"^(Run tests|Generate coverage JSON)")
COMPILE_STEP_RE = re.compile(r"^(Prebuild|Build release)")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
LOG_TS_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z ")
FINISHED_RE = re.compile(r"Finished `[^`]+` profile .* target\(s\) in (?:(\d+)m )?([\d.]+)s")
RUNNING_RE = re.compile(r"Running (?:unittests )?(\S+)")
RESULT_RE = re.compile(r"test result: \w+\. (\d+) passed;.* finished in ([\d.]+)s")
RANK_TOP = 16
STAGES = ("queue", "setup", "compile", "test", "post", "total")
NOT_MEASURED = "not measured"


def parse_ts(text):
    """GitHub timestamp (`2026-11-16T01:54:55Z` or with a fraction) to epoch seconds, None when unusable."""
    if not text:
        return None
    try:
        return datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S").timestamp() + (
            float("0." + text[20:-1]) if len(text) > 20 and text[19] == "." else 0.0)
    except ValueError:
        return None


def runner_kind(labels):
    """hosted, macos-fed or self-hosted Linux, from the job labels."""
    if "macos-fed" in labels:
        return "macos-fed"
    if "linux-fed" in labels or "self-hosted" in labels:
        return "self-hosted Linux"
    return "hosted"


def step_secs(step):
    start, end = parse_ts(step.get("started_at")), parse_ts(step.get("completed_at"))
    return max(0.0, end - start) if start is not None and end is not None else 0.0


def first_finished(lines, win_start=None, win_end=None):
    """(timestamp, reported compile seconds) of the first cargo Finished line inside the window, else None."""
    for raw in lines:
        line = ANSI_RE.sub("", raw)
        hit = FINISHED_RE.search(line)
        stamp = LOG_TS_RE.match(line)
        if not hit or not stamp:
            continue
        when = parse_ts(stamp.group(1) + ("." + stamp.group(2) if stamp.group(2) else "") + "Z")
        if (win_start is not None and when < win_start - 1) or (win_end is not None and when > win_end + 1):
            continue
        return when, int(hit.group(1) or 0) * 60 + float(hit.group(2))
    return None


def split_job(job, log_lines=None):
    """Seconds per stage for one jobs-API job object; None for a stage that cannot be derived.

    queue: created to started, None when the job was carried over from an earlier attempt (started before created).
    setup: every step before the first compile/test step. compile/test: the combined step split by the log, or the
    separate compile steps. post: every step after the combined step except a compile step.
    """
    created, started, done = parse_ts(job.get("created_at")), parse_ts(job.get("started_at")), parse_ts(job.get("completed_at"))
    out = dict.fromkeys(STAGES)
    out["total"] = done - started if started is not None and done is not None else None
    if created is not None and started is not None and started >= created:
        out["queue"] = started - created
    steps = job.get("steps") or []
    main = next((i for i, s in enumerate(steps) if COMBINED_STEP_RE.match(s.get("name", ""))), None)
    if main is None:
        return out
    out["setup"] = sum(step_secs(s) for s in steps[:main] if not COMPILE_STEP_RE.match(s["name"]))
    extra_compile = sum(step_secs(s) for s in steps if COMPILE_STEP_RE.match(s["name"]))
    out["post"] = sum(step_secs(s) for s in steps[main + 1:] if not COMPILE_STEP_RE.match(s["name"]))
    wall = step_secs(steps[main])
    found = first_finished(log_lines, parse_ts(steps[main].get("started_at")), parse_ts(steps[main].get("completed_at"))) if log_lines else None
    if found:
        out["compile"] = found[1] + extra_compile
        out["test"] = max(0.0, wall - found[1])
    else:
        out["compile"] = extra_compile or None
    out["combined_wall"] = wall
    return out


def rank_binaries(lines):
    """[(seconds, passed, target)] longest first, pairing each cargo `Running <target>` with the next `test result:`.

    Valid for one sequential shard; a log with interleaved shards can mispair, which the caller must name.
    """
    pending, rows = [], []
    for raw in lines:
        body = LOG_TS_RE.sub("", ANSI_RE.sub("", raw), count=1).strip()
        run = RUNNING_RE.match(body)
        if run:
            pending.append(run.group(1))
            continue
        res = RESULT_RE.search(body)
        if res and pending:
            rows.append((float(res.group(2)), int(res.group(1)), pending.pop(0)))
    return sorted(rows, reverse=True)


def summarize(values):
    """(median, min, max, n) over the numbers in values, None entries dropped; None when nothing is left."""
    nums = [v for v in values if v is not None]
    return (statistics.median(nums), min(nums), max(nums), len(nums)) if nums else None


def fmt(stat):
    if stat is None:
        return NOT_MEASURED
    return f"{stat[0]:.0f} ({stat[1]:.0f}-{stat[2]:.0f}) n={stat[3]}"


def gh_get(args):
    """Run `gh api <args>` (a GET); returns stdout text. Raises RuntimeError with the exact error."""
    proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True, timeout=GH_TIMEOUT_SECS, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"gh api {' '.join(args)} exit {proc.returncode}: {proc.stderr.strip()[:300]}")
    return proc.stdout


def list_runs(repo, workflow, branch, count):
    path = f"repos/{repo}/actions/workflows/{workflow}/runs?branch={branch}&status=success&per_page={min(count, MAX_RUNS)}"
    rows = json.loads(gh_get([path, "--jq", "[.workflow_runs[]|{id,head_sha,run_attempt,created_at}]"]))
    return rows[:count]


def list_jobs(repo, run_id):
    jobs = []
    for page in range(1, MAX_JOB_PAGES + 1):
        batch = json.loads(gh_get([f"repos/{repo}/actions/runs/{run_id}/jobs?per_page={JOBS_PER_PAGE}&page={page}",
                                   "--jq", "[.jobs[]|{id,name,labels,created_at,started_at,completed_at,steps:[.steps[]|{name,started_at,completed_at,conclusion}]}]"]))
        jobs += batch
        if len(batch) < JOBS_PER_PAGE:
            break
    return jobs


def fetch_log_lines(repo, job_id, scratch):
    """Download one job log to scratch, return its lines, delete the file. None plus the error when it fails."""
    target = scratch / f"job-{job_id}.log"
    try:
        with target.open("wb") as handle:
            proc = subprocess.run(["gh", "api", "--allow-escape-sequences", f"repos/{repo}/actions/jobs/{job_id}/logs"],
                                  stdout=handle, stderr=subprocess.PIPE, timeout=LOG_TIMEOUT_SECS, check=False)
        if proc.returncode != 0:
            return None, f"gh exit {proc.returncode}: {proc.stderr.decode(errors='replace').strip()[:200]}"
        return target.read_text(encoding="utf-8", errors="replace").splitlines(), None
    except (subprocess.TimeoutExpired, OSError) as exc:
        return None, str(exc)[:200]
    finally:
        target.unlink(missing_ok=True)


def collect(repo, branch, count, scratch, want_logs):
    rows, errors = [], []
    for workflow in WORKFLOWS:
        for run in list_runs(repo, workflow, branch, count):
            for job in list_jobs(repo, run["id"]):
                if not TEST_JOB_RE.match(job["name"]):
                    continue
                lines = None
                if want_logs:
                    lines, err = fetch_log_lines(repo, job["id"], scratch)
                    if err:
                        errors.append(f"run {run['id']} job {job['id']} log: {err}")
                row = split_job(job, lines)
                row.update(workflow=workflow, run=run["id"], head=run["head_sha"][:10], job=job["name"],
                           kind=runner_kind(job.get("labels") or []), job_id=job["id"])
                rows.append(row)
    return rows, errors


def print_table(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[(row["workflow"], row["job"], row["kind"])].append(row)
    print("workflow | job | runner kind | " + " | ".join(f"{s} s" for s in STAGES))
    for key in sorted(groups):
        print(" | ".join(key) + " | " + " | ".join(fmt(summarize([r[s] for r in groups[key]])) for s in STAGES))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--scratch", type=Path, default=Path(".local-runs"))
    parser.add_argument("--no-logs", action="store_true", help="skip the log split; compile/test stay unseparated")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--rank-job", type=int, help="print the longest test binaries of this job id's log and exit")
    args = parser.parse_args(argv)
    args.scratch.mkdir(parents=True, exist_ok=True)
    if args.rank_job:
        lines, err = fetch_log_lines(args.repo, args.rank_job, args.scratch)
        if err:
            print(f"{NOT_MEASURED}: {err}", file=sys.stderr)
            return EXIT_GH_FAILED
        for secs, passed, target in rank_binaries(lines)[:RANK_TOP]:
            print(f"{secs:8.2f} s {passed:5d} tests {target}")
        return EXIT_OK
    try:
        rows, errors = collect(args.repo, args.branch, args.runs, args.scratch, not args.no_logs)
    except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"gh failed: {exc}", file=sys.stderr)
        return EXIT_GH_FAILED
    if not rows:
        print("no green test job found", file=sys.stderr)
        return EXIT_NO_RUNS
    if args.json_out:
        args.json_out.write_text(json.dumps({"rows": rows, "errors": errors}, indent=1), encoding="utf-8")
    print_table(rows)
    for err in errors:
        print(f"{NOT_MEASURED}: {err}", file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
