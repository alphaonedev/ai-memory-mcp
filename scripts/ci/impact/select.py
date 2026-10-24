"""Map a git diff to CI job keys, crates and ordered test targets (#8240).

Usage:
    python3 -I scripts/ci/impact/select.py --db <file> --base <sha> --head <sha> \
        [--repo .] [--advice <json>] [--event pull_request] [--base-ref <name>] \
        [--enforce <CI_IMPACT_ENFORCE>] --out <json> [--github-output <file>]

The GitHub output carries one `<job key>=true|false` line per known job. A key
is `false` only when `--enforce` is the literal `true` and the selection left
that job out; otherwise (and for any full-matrix selection) it is `true`.

Per changed path the first matching rule (lowest priority number) wins and
the selections are unioned. `ALL`, an unclassified path, an empty diff, an
unreadable diff or index, a non-pull_request event and a release-branch base
all select the full matrix. The optional advice file can only ADD known job
keys; an unknown key is rejected with exit status 2 and nothing is written.
"""
import argparse
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from impact import common  # noqa: E402

GIT_TIMEOUT_S = 120
UNKNOWN_DURATION_S = float("inf")
RESULT_FAILED = "failed"


class AdviceError(ValueError):
    """The advice document is malformed or names an unknown job key."""


def load_path_rules(con: sqlite3.Connection) -> List[dict]:
    """Return rules ordered by priority: [{priority, glob, jobs}]."""
    rules: Dict[int, dict] = {}
    for priority, glob, job in con.execute(
            "select priority, glob, job_key from path_rules order by priority, rowid"):
        rule = rules.setdefault(priority, {"priority": priority, "glob": glob, "jobs": []})
        rule["jobs"].append(job)
    return [rules[p] for p in sorted(rules)]


def owning_crate(path: str, crates: Dict[str, str]) -> Optional[str]:
    """Return the crate whose src_root is the longest prefix of `path`."""
    best, best_len = None, -1
    for name, root in crates.items():
        if root == ".":
            hit, length = True, 0
        else:
            hit, length = path == root or path.startswith(root + "/"), len(root)
        if hit and length > best_len:
            best, best_len = name, length
    return best


def reverse_closure(seed: Set[str], edges: List[tuple]) -> Set[str]:
    """Return `seed` plus every crate that depends on it, transitively."""
    dependants: Dict[str, Set[str]] = {}
    for crate, dep in edges:
        dependants.setdefault(dep, set()).add(crate)
    closure = set(seed)
    frontier = list(seed)
    while frontier:
        for parent in dependants.get(frontier.pop(), ()):
            if parent not in closure:
                closure.add(parent)
                frontier.append(parent)
    return closure


def validate_advice(advice: Optional[list], known: Set[str]) -> List[dict]:
    """Return normalised advice entries or raise AdviceError."""
    if advice is None:
        return []
    if not isinstance(advice, list):
        raise AdviceError("advice must be a JSON list")
    entries = []
    for item in advice:
        if not isinstance(item, dict) or "job_key" not in item or "reason" not in item:
            raise AdviceError("each advice entry needs job_key and reason")
        if item["job_key"] not in known:
            raise AdviceError("unknown job key in advice: %r" % (item["job_key"],))
        entries.append({"job_key": item["job_key"], "reason": str(item["reason"])})
    return entries


def order_tests(con: sqlite3.Connection, crates: Set[str]) -> List[str]:
    """Return test target names for `crates` ordered by history.

    Last result failed first, then flaky count descending, then duration
    ascending (unknown durations last), then name.
    """
    history = {t: (r, f, d) for t, d, r, f in con.execute(
        "select target, duration_s, last_result, flaky_count from history")}
    names = {n for n, c in con.execute(
        "select name, crate from test_targets where kind = 'test'") if c in crates}

    def key(name: str):
        result, flaky, duration = history.get(name, (None, 0, None))
        return (0 if result == RESULT_FAILED else 1, -(flaky or 0),
                UNKNOWN_DURATION_S if duration is None else duration, name)

    return sorted(names, key=key)


def compute_selection(db: Path, changed: List[str], force_all: Optional[str] = None,
                      advice: Optional[list] = None) -> dict:
    """Compute the selection for `changed` paths against the index at `db`."""
    con = common.open_existing_db(Path(db))
    try:
        return _select(con, changed, force_all, advice)
    finally:
        con.close()


def _select(con: sqlite3.Connection, changed: List[str], force_all: Optional[str],
            advice: Optional[list]) -> dict:
    settings = common.load_settings(con)
    known = set(settings["known_jobs"])
    entries = validate_advice(advice, known)
    rules = load_path_rules(con)
    include_files = set(settings.get(common.INCLUDE_FILES_KEY) or [])
    # A missing key means an index from before the scan existed: fail closed.
    include_unresolved = bool(settings.get(common.INCLUDE_UNRESOLVED_KEY, True))
    crates = dict(con.execute("select name, src_root from crates"))
    edges = list(con.execute("select crate, dep from crate_deps"))
    jobs: Set[str] = set(settings["always_on"])
    reasons: Dict[str, str] = {}
    seeds: Set[str] = set()
    rust_unowned = False
    full = False
    cell_hit = False
    for path in changed:
        if path in include_files:
            # Compiled in by include_str!/include_bytes!: a Rust change (S3).
            rule = {"glob": common.REASON_INCLUDE, "jobs": [common.RUST_KEY]}
        else:
            rule = next((r for r in rules if common.match_glob(r["glob"], path)), None)
        if (rule is not None and include_unresolved and rule["jobs"] == [common.DOCS_KEY]
                and path.endswith(".md")):
            # An include the scan could not resolve might read this file.
            reasons[path] = common.REASON_INCLUDE_UNRESOLVED
            full = True
            continue
        if rule is None:
            reasons[path] = common.REASON_UNCLASSIFIED
            full = True
            continue
        reasons[path] = rule["glob"]
        if common.ALL_KEY in rule["jobs"]:
            full = True
            continue
        jobs.update(rule["jobs"])
        if common.RUST_KEY in rule["jobs"]:
            owner = owning_crate(path, crates)
            if owner is None:
                rust_unowned = True
            else:
                seeds.add(owner)
        if any(common.match_glob(g, path) for g in settings["cell_globs"]):
            cell_hit = True
    if not changed:
        reasons[common.REASON_KEY] = common.FAIL_CLOSED_EMPTY
        full = True
    if force_all:
        reasons[common.REASON_KEY] = force_all
        full = True
    closure = set(crates) if rust_unowned else reverse_closure(seeds, edges)
    if closure & set(settings["cell_crates"]) or cell_hit:
        jobs.add(common.CELLS_KEY)
    for entry in entries:
        jobs.add(entry["job_key"])
    if full:
        jobs = set(known)
        closure = set(crates)
    return {"all": full, "jobs": sorted(jobs), "crates": sorted(closure),
            "tests": order_tests(con, closure), "reasons": reasons,
            "advice": entries}


def git_changed_paths(repo: Path, base: str, head: str) -> List[str]:
    """Return changed paths between base and head (renames list both sides)."""
    res = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--no-renames", base, head],
        cwd=str(repo), capture_output=True, timeout=GIT_TIMEOUT_S)
    if res.returncode != 0:
        raise RuntimeError("git diff failed: %s"
                           % res.stderr.decode("utf-8", "replace").strip()[-300:])
    return [item.decode("utf-8", "surrogateescape")
            for item in res.stdout.split(common.NUL.encode()) if item]


def force_reason(event: str, base_ref: str, rules: dict) -> Optional[str]:
    """Return why this run must be the full matrix, or None."""
    if event != common.EVENT_PULL_REQUEST:
        return "event:%s" % event
    if base_ref:
        if base_ref in rules["force_all_base_names"]:
            return "base-ref:%s" % base_ref
        if any(base_ref.startswith(p) for p in rules["force_all_base_prefixes"]):
            return "base-ref:%s" % base_ref
    return None


def fail_closed(rules: dict, reason: str) -> dict:
    """The full-matrix result used when the diff or the index is unusable."""
    return {"all": True, "jobs": sorted(rules["known_jobs"]), "crates": [],
            "tests": [], "reasons": {common.REASON_KEY: reason}, "advice": []}


def domain_outputs(result: dict, known_jobs: List[str], enforce: str) -> Dict[str, str]:
    """Return {domain: 'true'|'false'} for the step outputs.

    Every gated job reads its own domain and may be skipped ONLY on an explicit
    'false'. While enforcement is off (anything but the literal 'true') every
    domain is 'true'; a full-matrix selection is 'true' for every domain.
    """
    enforced = enforce == common.ENFORCE_VALUE
    selected = set(result["jobs"])
    return {job: "true" if (not enforced or result["all"] or job in selected) else "false"
            for job in sorted(known_jobs)}


def write_outputs(result: dict, out: Optional[Path], github_output: Optional[Path],
                  known_jobs: Optional[List[str]] = None, enforce: str = "") -> None:
    """Write the JSON result and the GitHub step-output lines."""
    if out is not None:
        Path(out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if github_output is not None:
        lines = ["jobs=%s" % ",".join(result["jobs"]),
                 "all=%s" % ("true" if result["all"] else "false"),
                 "crates=%s" % ",".join(result["crates"])]
        domains = domain_outputs(result, known_jobs or result["jobs"], enforce)
        lines += ["%s=%s" % (job, value) for job, value in domains.items()]
        with open(str(github_output), "a") as handle:
            handle.write("\n".join(lines) + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--advice", help="JSON list of {job_key, reason}; additive only")
    parser.add_argument("--event", default=common.EVENT_PULL_REQUEST)
    parser.add_argument("--base-ref", default="")
    parser.add_argument("--out", help="write the selection JSON here")
    parser.add_argument("--github-output", help="append jobs=, all=, crates= lines here")
    parser.add_argument("--rules", help="alternative rules.json (fail-closed fallback)")
    parser.add_argument("--enforce", default="",
                        help="the CI_IMPACT_ENFORCE value; only 'true' lets a domain say false")
    args = parser.parse_args(argv)
    rules = common.load_rules(Path(args.rules) if args.rules else None)
    advice = None
    if args.advice:
        try:
            advice = json.loads(Path(args.advice).read_text())
            validate_advice(advice, set(rules["known_jobs"]))
        except (AdviceError, ValueError, OSError) as exc:
            common.log("impact: advice rejected: %s" % exc)
            return common.EXIT_USAGE
    forced = force_reason(args.event, args.base_ref, rules)
    try:
        changed = git_changed_paths(Path(args.repo), args.base, args.head)
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        common.log("impact: %s; selecting the full matrix" % exc)
        write_outputs(fail_closed(rules, common.FAIL_CLOSED_DIFF),
                      Path(args.out) if args.out else None,
                      Path(args.github_output) if args.github_output else None,
                      rules["known_jobs"], args.enforce)
        return common.EXIT_OK
    try:
        result = compute_selection(Path(args.db), changed, forced, advice)
    except (FileNotFoundError, ValueError, sqlite3.Error) as exc:
        common.log("impact: index unusable (%s); selecting the full matrix" % exc)
        result = fail_closed(rules, common.FAIL_CLOSED_INDEX)
    write_outputs(result, Path(args.out) if args.out else None,
                  Path(args.github_output) if args.github_output else None,
                  rules["known_jobs"], args.enforce)
    print("impact selection: all=%s jobs=%s crates=%s"
          % (result["all"], ",".join(result["jobs"]), ",".join(result["crates"])))
    return common.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
