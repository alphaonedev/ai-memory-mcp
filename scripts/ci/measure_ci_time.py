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

Every duration is computed from two UTC timestamps that are both present and ordered, or the row is reported as
`unmeasured` with a named reason (missing-timestamp, negative, compile-longer-than-step, missing-step-name) and left
out of every median and range. The table is followed by a footer line that counts them. A value that could not be
measured is never printed as 0 s. Link time is inside cargo's one `Finished` compile figure and is not split out.

`--bench-dir DIR` reads the stored logs of the nextest-against-cargo-test runs (compile.log, cglist.log, nxlist.log,
cargotest-1/2.log, nextest-1/2.log, nextest-solo1.log, nextest-solo.log, nextest-solo-j1.log) and prints, with the UTC
time it was read and each file's write time, the cargo build time, the test counts, the reconciliation of the
`test result:` rows with the list (rows printed by a child process inside a test are counted apart as nested), the
nextest summaries and the failed-test sets. A missing log is `not measured` with its error and exit 6.

Exit codes: 0 done, 2 usage error (argparse; `--runs` outside 1..30 is one), 3 a gh call failed, 4 no green run found,
5 the API payload had an unexpected shape (one line on stderr), 6 a stored bench log is missing.
"""
import argparse
import json
import re
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

EXIT_OK = 0
EXIT_GH_FAILED = 3
EXIT_NO_RUNS = 4
EXIT_BAD_INPUT = 5
MIN_RUNS = 1
WORKFLOWS = ("ci.yml", "coverage.yml")
MAX_RUNS = 30  # one API page is 100 rows; a request above this is refused, not cut
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
STDERR_MARK = "--- stderr ---"
HEADER_RE = re.compile(r"^running (\d+) tests?$")
TEST_RESULT_RE = re.compile(
    r"^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([\d.]+)s")
NEXTEST_FAIL_RE = re.compile(r"^\s+FAIL \[\s*[\d.]+s\] \(\s*\d+/\d+\)\s+(.+?)\s*$")
NEXTEST_SUMMARY_RE = re.compile(
    r"Summary \[\s*([\d.]+)s\] (\d+) tests? run: (\d+) passed(?: \(\d+ slow\))?(?:, (\d+) failed)?(?:, (\d+) skipped)?")
LIST_TEST_RE = re.compile(r"^\S.*: test$")
NEXTEST_LIST_RE = re.compile(r"^ai-memory(?:::\w+)? \S+$")
BENCH_COMPILE = "compile.log"
BENCH_CARGO_LIST = "cglist.log"
BENCH_NEXTEST_LIST = "nxlist.log"
BENCH_CARGO_RUNS = ("cargotest-1.log", "cargotest-2.log")
BENCH_NEXTEST_RUNS = ("nextest-1.log", "nextest-2.log")
BENCH_PROBES = ("nextest-solo1.log", "nextest-solo.log", "nextest-solo-j1.log")
BENCH_FILES = (BENCH_COMPILE, BENCH_CARGO_LIST, BENCH_NEXTEST_LIST, *BENCH_CARGO_RUNS, *BENCH_NEXTEST_RUNS, *BENCH_PROBES)
EXIT_BENCH_MISSING = 6
RANK_TOP = 16
STAGES = ("queue", "setup", "compile", "test", "post", "total")
NOT_MEASURED = "not measured"
REASON_MISSING_TS = "missing-timestamp"
REASON_NEGATIVE = "negative"
REASON_COMPILE_LONGER = "compile-longer-than-step"
REASON_MISSING_NAME = "missing-step-name"
REASONS = (REASON_MISSING_TS, REASON_NEGATIVE, REASON_COMPILE_LONGER, REASON_MISSING_NAME)
UNMEASURED_KEY = "unmeasured"


def parse_ts(text):
    """GitHub timestamp (`2026-11-16T01:54:55Z` or with a fraction) to UTC epoch seconds, None when unusable.

    The value is read as UTC whatever the TZ of the process is.
    """
    if not text or not isinstance(text, str):
        return None
    try:
        base = datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        return base + (float("0." + text[20:-1]) if len(text) > 20 and text[19] == "." else 0.0)
    except ValueError:
        return None


def duration(start_text, end_text):
    """(seconds, None) when both timestamps are usable and ordered, else (None, reason)."""
    start, end = parse_ts(start_text), parse_ts(end_text)
    if start is None or end is None:
        return None, REASON_MISSING_TS
    if end < start:
        return None, REASON_NEGATIVE
    return end - start, None


def runner_kind(labels):
    """hosted, macos-fed or self-hosted Linux, from the job labels."""
    if "macos-fed" in labels:
        return "macos-fed"
    if "linux-fed" in labels or "self-hosted" in labels:
        return "self-hosted Linux"
    return "hosted"


def step_secs(step):
    """(seconds, reason) of one jobs-API step."""
    return duration(step.get("started_at"), step.get("completed_at"))


def sum_steps(steps):
    """(sum of step seconds, None), or (None, reason) when any step in the range is unmeasured."""
    total, bad = 0.0, None
    for step in steps:
        secs, why = step_secs(step)
        if why:
            bad = bad or why
        else:
            total += secs
    return (None, bad) if bad else (total, None)


def first_finished(lines, win_start=None, win_end=None):
    """(timestamp, reported compile seconds) of the first cargo Finished line inside the window, else None."""
    for raw in lines:
        line = ANSI_RE.sub("", raw)
        hit = FINISHED_RE.search(line)
        stamp = LOG_TS_RE.match(line)
        if not hit or not stamp:
            continue
        when = parse_ts(stamp.group(1) + ("." + stamp.group(2) if stamp.group(2) else "") + "Z")
        if when is None:
            continue
        if (win_start is not None and when < win_start - 1) or (win_end is not None and when > win_end + 1):
            continue
        return when, int(hit.group(1) or 0) * 60 + float(hit.group(2))
    return None


def split_job(job, log_lines=None):
    """Seconds per stage for one jobs-API job object; None for a stage that cannot be derived.

    queue: created to started, None when the job was carried over from an earlier attempt (started before created).
    setup: every step before the first compile/test step. compile/test: the combined step split by the log, or the
    separate compile steps. post: every step after the combined step except a compile step.
    Link time is inside the compile figure: cargo prints one `Finished` time for compile and link together.
    A stage that cannot be derived because a timestamp is missing, a duration is negative, the compile time cargo
    reported is longer than its step or a step has no name is None, and `unmeasured` lists `stage:reason` for it.
    """
    out = dict.fromkeys(STAGES)
    out[UNMEASURED_KEY] = []

    def flag(stage, reason):
        out[stage] = None
        out[UNMEASURED_KEY].append(f"{stage}:{reason}")

    total, why = duration(job.get("started_at"), job.get("completed_at"))
    out["total"] = total
    if why:
        flag("total", why)
    created, started = parse_ts(job.get("created_at")), parse_ts(job.get("started_at"))
    if created is None or started is None:
        flag("queue", REASON_MISSING_TS)
    elif started >= created:
        out["queue"] = started - created
    steps = job.get("steps") or []
    main = next((i for i, s in enumerate(steps) if COMBINED_STEP_RE.match(s.get("name") or "")), None)
    if main is None:
        return out
    if any(not s.get("name") for s in steps):
        for stage in ("setup", "compile", "test", "post"):
            flag(stage, REASON_MISSING_NAME)
        out["combined_wall"] = None
        return out

    def named(chunk, wanted):
        return [s for s in chunk if bool(COMPILE_STEP_RE.match(s["name"])) is wanted]

    setup, why = sum_steps(named(steps[:main], False))
    if why:
        flag("setup", why)
    else:
        out["setup"] = setup
    post, why = sum_steps(named(steps[main + 1:], False))
    if why:
        flag("post", why)
    else:
        out["post"] = post
    extra_compile, extra_why = sum_steps(named(steps, True))
    wall, wall_why = step_secs(steps[main])
    out["combined_wall"] = wall
    if wall_why or extra_why:
        for stage in ("compile", "test"):
            flag(stage, wall_why or extra_why)
        return out
    found = first_finished(log_lines, parse_ts(steps[main].get("started_at")), parse_ts(steps[main].get("completed_at"))) if log_lines else None
    if found and found[1] > wall:
        for stage in ("compile", "test"):
            flag(stage, REASON_COMPILE_LONGER)
    elif found:
        out["compile"] = found[1] + extra_compile
        out["test"] = wall - found[1]
    else:
        out["compile"] = extra_compile or None
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


def clean_lines(text):
    """Lines of a stored log with ANSI colour removed and trailing blanks stripped."""
    return [ANSI_RE.sub("", ln).rstrip() for ln in text.splitlines()]


def parse_cargo_results(lines):
    """(top, nested): the `test result:` rows of a stored `cargo test` log, split by who printed them.

    Only the stdout part (before the stderr marker) is read. A binary prints `running N tests` and later one result
    row whose passed + failed + ignored + measured equals N: that row is top-level. Any other row inside that
    window, and any header inside it, was printed by a child process of a test (nested) and is counted apart.
    """
    top, nested, open_count = [], [], None
    for line in lines:
        if line == STDERR_MARK:
            break
        head = HEADER_RE.match(line)
        if head:
            open_count = int(head.group(1)) if open_count is None else open_count
            continue
        res = TEST_RESULT_RE.match(line)
        if not res:
            continue
        row = {"passed": int(res.group(1)), "failed": int(res.group(2)), "ignored": int(res.group(3)),
               "measured": int(res.group(4)), "secs": float(res.group(6))}
        if open_count is not None and row["passed"] + row["failed"] + row["ignored"] + row["measured"] == open_count:
            row["header"] = open_count
            top.append(row)
            open_count = None
        else:
            nested.append(row)
    return top, nested


def parse_nextest(lines):
    """Summary and distinct failed test names of a stored `cargo nextest run` log; summary None when absent."""
    summary, fails = None, set()
    for line in lines:
        fail = NEXTEST_FAIL_RE.match(line)
        if fail:
            fails.add(fail.group(1))
        done = NEXTEST_SUMMARY_RE.search(line)
        if done:
            summary = {"secs": float(done.group(1)), "run": int(done.group(2)), "passed": int(done.group(3)),
                       "failed": int(done.group(4) or 0), "skipped": int(done.group(5) or 0)}
    return summary, fails


def count_list(lines, pattern):
    """Number of lines of a stored `list` output that match the compiled pattern."""
    return sum(1 for ln in lines if pattern.match(ln))


def utc_text(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def yes_no(flag):
    return "yes" if flag else "NO"


def bench_report(directory, now):
    """(report lines, missing file names) for the stored nextest-against-cargo-test logs in one directory."""
    missing, logs, mtimes = [], {}, {}
    for name in BENCH_FILES:
        path = directory / name
        try:
            logs[name] = clean_lines(path.read_text(encoding="utf-8", errors="replace"))
            mtimes[name] = utc_text(path.stat().st_mtime)
        except OSError as exc:
            missing.append(f"{name}: {str(exc)[:120]}")
    if missing:
        return [], missing
    out = [f"read at {utc_text(now)} UTC from {directory}"]
    build = next((FINISHED_RE.search(ln) for ln in logs[BENCH_COMPILE] if FINISHED_RE.search(ln)), None)
    build_secs = int(build.group(1) or 0) * 60 + float(build.group(2)) if build else None
    out.append(f"build: {BENCH_COMPILE} (written {mtimes[BENCH_COMPILE]}) cargo Finished in "
               f"{NOT_MEASURED if build_secs is None else f'{build_secs:.0f} s'}")
    list_total = count_list(logs[BENCH_CARGO_LIST], LIST_TEST_RE)
    nextest_list = count_list(logs[BENCH_NEXTEST_LIST], NEXTEST_LIST_RE)
    out.append(f"list: {BENCH_CARGO_LIST} (written {mtimes[BENCH_CARGO_LIST]}) {list_total} `: test` lines; "
               f"{BENCH_NEXTEST_LIST} (written {mtimes[BENCH_NEXTEST_LIST]}) {nextest_list} test lines")
    for name in BENCH_CARGO_RUNS:
        top, nested = parse_cargo_results(logs[name])
        head = sum(r["header"] for r in top)
        passed, ignored = sum(r["passed"] for r in top), sum(r["ignored"] for r in top)
        nest_passed = sum(r["passed"] for r in nested)
        out.append(f"{name} (written {mtimes[name]}): {len(top)} top-level result rows, header sum {head}, "
                   f"{passed} passed, {sum(r['failed'] for r in top)} failed, {ignored} ignored, "
                   f"sum of finished-in {sum(r['secs'] for r in top):.1f} s; {len(nested)} nested result rows "
                   f"({nest_passed} passed) printed inside the lib test output; all rows {passed + nest_passed} passed")
        out.append(f"  reconcile: header sum == list {yes_no(head == list_total)}; "
                   f"top-level passed + ignored == list {yes_no(passed + ignored == list_total)}; "
                   f"all rows passed - list = {passed + nest_passed - list_total}, "
                   f"explained by nested rows ({nest_passed}) minus ignored ({ignored}) = {nest_passed - ignored}: "
                   f"{yes_no(passed + nest_passed - list_total == nest_passed - ignored)}")
    sets = []
    for name in BENCH_NEXTEST_RUNS:
        summary, fails = parse_nextest(logs[name])
        sets.append(fails)
        if summary is None:
            out.append(f"{name} (written {mtimes[name]}): {NOT_MEASURED}: no Summary line")
            continue
        out.append(f"{name} (written {mtimes[name]}): nextest Summary {summary['secs']:.1f} s, {summary['run']} run, "
                   f"{summary['passed']} passed, {summary['failed']} failed, {summary['skipped']} skipped; "
                   f"{len(fails)} distinct FAIL names (== failed: {yes_no(len(fails) == summary['failed'])})")
    out.append(f"nextest fail sets over runs 1 and 2: {len(sets[0] & sets[1])} in both, {len(sets[0] | sets[1])} in either")
    for name in BENCH_PROBES:
        summary, fails = parse_nextest(logs[name])
        out.append(f"{name} (written {mtimes[name]}): " + (NOT_MEASURED + ": no Summary line" if summary is None else
                   f"nextest Summary {summary['secs']:.1f} s, {summary['run']} run, {summary['passed']} passed, "
                   f"{summary['failed']} failed"))
    first = parse_nextest(logs[BENCH_NEXTEST_RUNS[0]])[0]
    same = first is not None and first["run"] + first["skipped"] == list_total
    out.append(f"same test count: nextest run + skipped == cargo list {yes_no(same)}; nextest list == nextest run "
               f"{yes_no(first is not None and nextest_list == first['run'])}")
    return out, []


def summarize(values):
    """(median, min, max, n) over the numbers in values, None entries dropped; None when nothing is left."""
    nums = [v for v in values if v is not None]
    return (statistics.median(nums), min(nums), max(nums), len(nums)) if nums else None


def unmeasured_footer(rows):
    """One line counting the cells left out of the table, by reason."""
    counts = dict.fromkeys(REASONS, 0)
    cells = bad_rows = 0
    for row in rows:
        entries = row.get(UNMEASURED_KEY) or []
        bad_rows += bool(entries)
        for entry in entries:
            cells += 1
            reason = entry.split(":", 1)[1]
            counts[reason] = counts.get(reason, 0) + 1
    detail = f" ({', '.join(f'{r}={n}' for r, n in counts.items() if n)})" if cells else ""
    return f"unmeasured: {cells} cells in {bad_rows} of {len(rows)} rows{detail}"


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
    path = f"repos/{repo}/actions/workflows/{workflow}/runs?branch={branch}&status=success&per_page={count}"
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
                if not TEST_JOB_RE.match(job.get("name") or ""):
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
    print(unmeasured_footer(rows))


def runs_arg(text):
    """argparse type for --runs: an integer in MIN_RUNS..MAX_RUNS, else a reason."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer; --runs takes {MIN_RUNS}..{MAX_RUNS}") from None
    if not MIN_RUNS <= value <= MAX_RUNS:
        raise argparse.ArgumentTypeError(f"{value} is outside {MIN_RUNS}..{MAX_RUNS}; --runs takes {MIN_RUNS}..{MAX_RUNS}")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--runs", type=runs_arg, default=10, metavar=f"{MIN_RUNS}..{MAX_RUNS}")
    parser.add_argument("--scratch", type=Path, default=Path(".local-runs"))
    parser.add_argument("--no-logs", action="store_true", help="skip the log split; compile/test stay unseparated")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--rank-job", type=int, help="print the longest test binaries of this job id's log and exit")
    parser.add_argument("--bench-dir", type=Path,
                        help="read the stored cargo test and nextest logs of one directory, print their counts and exit")
    args = parser.parse_args(argv)
    if args.bench_dir:
        report, missing = bench_report(args.bench_dir, time.time())
        for reason in missing:
            print(f"{NOT_MEASURED}: {reason}", file=sys.stderr)
        for line in report:
            print(line)
        return EXIT_BENCH_MISSING if missing else EXIT_OK
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
    except (KeyError, TypeError, AttributeError, ValueError, IndexError) as exc:
        print(f"unexpected input from the API: {type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
        return EXIT_BAD_INPUT
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
