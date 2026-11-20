"""Docs-only short-circuit decider shared by the heavy PR jobs (#9683).

One decision for cert-postgres-age, postgres-ignored and token-budget: does
the whole pull request (base sha to the checked-out merge ref) change only
documentation that no test reads? The allowlist is the one coverage already
uses: rules.json cargo_skip docs_globs minus every never-skip glob, test-read
glob and walk guard (cargo_skip.is_doc). Nothing here widens it.

Two subcommands:

    decide --stdin --rules R --event-name E --base-ref B [--repo DIR]
        Reads NUL-separated `git diff --name-status -z` bytes on stdin as
        data (no path is ever evaluated, expanded or passed to a shell) and
        exits with the decision:
            EXIT_FULL_RUN   0  run the job in full
            EXIT_USAGE      2  bad arguments (argparse)
            EXIT_DOCS_ONLY  3  every changed path is docs no test reads
            EXIT_UNREADABLE 4  the list cannot be trusted; the caller runs in full
        Only EXIT_DOCS_ONLY ever lets a job skip work, so every other exit,
        including a crash, is a full run.

    step
        The composite action (.github/actions/docs-only-gate) runs this. It
        reads DOCS_GATE_EVENT_NAME, DOCS_GATE_BASE_SHA, DOCS_GATE_BASE_REF,
        GITHUB_WORKSPACE, GITHUB_OUTPUT and RUNNER_TEMP, and writes exactly one
        line, docs_only=true or docs_only=false, to GITHUB_OUTPUT. It always
        exits 0: a doubt is docs_only=false, which runs the job in full.
        The decider that judges the diff is read from the BASE commit
        (git cat-file blob <base>:scripts/ci/impact/<file>) into RUNNER_TEMP
        and run with -I, so a PR cannot judge its own diff with an edited
        decider or allowlist; a base without the decider is a full run.

Unreadable input: an empty or absent path, a path that is not strict UTF-8,
holds a control or line-break character or a backslash, is absolute, ends in
a slash, or has an empty, ".", ".." or dash-leading segment; a status other
than A, D, M, T or R/C with a three-digit score; a status with too few paths;
a list not ended by NUL; more than MAX_PATHS paths or MAX_INPUT_BYTES bytes.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from impact import cargo_skip  # noqa: E402
from impact import common  # noqa: E402

EXIT_FULL_RUN = 0
EXIT_USAGE = 2
EXIT_DOCS_ONLY = 3
EXIT_UNREADABLE = 4

DOCS_SECTION = cargo_skip.SECTION
MAX_PATHS = 100_000
MAX_INPUT_BYTES = 32 * 1024 * 1024
DECIDER_TIMEOUT_S = 300
PULL_REQUEST = common.EVENT_PULL_REQUEST
NUL = b"\0"
ONE_PATH_STATUS = re.compile(r"[ADMT]")
TWO_PATH_STATUS = re.compile(r"[RC][0-9]{3}")
SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
# C0 and C1 controls, DEL, backslash and every Unicode line break.
BAD_CHARS = re.compile("[\x00-\x1f\x7f-\x9f\\\\%s]" % re.escape(common.LINE_BREAK_CHARS))
BAD_SEGMENTS = frozenset(("", ".", ".."))
DASH = "-"
IMPACT_REL = "scripts/ci/impact"
GATE_FILES = ("__init__.py", "common.py", "cargo_skip.py", "docs_only_gate.py", "rules.json")
OUTPUT_KEY = "docs_only"
TRUE = "true"
FALSE = "false"
REASON_EMPTY = cargo_skip.REASON_EMPTY
REASON_EVENT = "not-a-pull-request-full-run"
REASON_BOUND = "over the bound of %d %s"


def load_section(path: Optional[Path] = None) -> dict:
    """Return the validated cargo_skip section: the single docs allowlist."""
    return cargo_skip.load_section(path)


def check_path(raw: bytes) -> Tuple[Optional[str], str]:
    """Return (path, "") for a well-formed repository path, else (None, reason)."""
    try:
        path = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None, "path is not UTF-8"
    if not path:
        return None, "empty path"
    if BAD_CHARS.search(path):
        return None, "control, line-break or backslash character in a path"
    for segment in path.split("/"):
        if segment in BAD_SEGMENTS:
            return None, "absolute path, trailing slash or empty/./.. segment"
        if segment.startswith(DASH):
            return None, "path segment starts with a dash"
    return path, ""


def parse(raw: bytes) -> Tuple[Optional[List[str]], str]:
    """Return (paths, "") from `--name-status -z` bytes, else (None, reason).

    Both sides of a rename or copy are returned, so a rename between a docs
    path and a code path is judged on the code path. Linear in len(raw).
    """
    if len(raw) > MAX_INPUT_BYTES:
        return None, REASON_BOUND % (MAX_INPUT_BYTES, "bytes")
    if not raw.endswith(NUL):
        return None, "list is not NUL-terminated"
    fields = raw[:-1].split(NUL)
    paths: List[str] = []
    i = 0
    while i < len(fields):
        status = fields[i].decode("ascii", "replace")
        if ONE_PATH_STATUS.fullmatch(status):
            want = 1
        elif TWO_PATH_STATUS.fullmatch(status):
            want = 2
        else:
            return None, "unknown status %r" % cargo_skip.clean_text(status)
        if i + want >= len(fields):
            return None, "status %s without its path" % status
        for raw_path in fields[i + 1:i + 1 + want]:
            path, why = check_path(raw_path)
            if path is None:
                return None, why
            paths.append(path)
        if len(paths) > MAX_PATHS:
            return None, REASON_BOUND % (MAX_PATHS, "paths")
        i += 1 + want
    return paths, ""


def decide(section: dict, raw: bytes, event: str, base_ref: str,
           repo: Optional[Path] = None) -> Tuple[int, str]:
    """Return (exit code, one-line reason) for the whole-PR diff bytes `raw`."""
    if event != PULL_REQUEST:
        return EXIT_FULL_RUN, REASON_EVENT
    if not raw:
        return EXIT_FULL_RUN, REASON_EMPTY
    paths, why = parse(raw)
    if paths is None:
        return EXIT_UNREADABLE, "unreadable diff: %s" % why
    unique = list(dict.fromkeys(paths))
    verdict = cargo_skip.classify(section, unique, event, base_ref, repo)
    reason = verdict["cargo_skip_reason"]
    if verdict["docs_only"] == cargo_skip.TRUE:
        return EXIT_DOCS_ONLY, reason
    return EXIT_FULL_RUN, reason


def cmd_decide(args: argparse.Namespace) -> int:
    """Decide on stdin; any error is a full run (exit EXIT_FULL_RUN)."""
    try:
        section = load_section(Path(args.rules))
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        repo = Path(args.repo) if args.repo else None
        code, reason = decide(section, raw, args.event_name, args.base_ref, repo)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError,
            subprocess.SubprocessError) as exc:
        common.log("docs_only_gate: %s" % cargo_skip.clean_text(str(exc)))
        return EXIT_FULL_RUN
    common.log("docs_only_gate: exit %d %s" % (code, cargo_skip.clean_text(reason)))
    return code


def git(workspace: Path, args: List[str], what: str) -> bytes:
    """Run git in `workspace` with repository-locating variables removed."""
    return cargo_skip.git_output(workspace, args, what)


def judge_step(workspace: Path, runner_temp: Path, event: str, base: str,
               base_ref: str) -> Tuple[str, str]:
    """Return (docs_only value, notice) for the step; never raises for a doubt."""
    if event != PULL_REQUEST:
        return FALSE, "event %r is not a pull request" % cargo_skip.clean_text(event)
    if not SHA_RE.fullmatch(base):
        return FALSE, "base sha is missing or malformed"
    try:
        git(workspace, ["cat-file", "-e", base + "^{commit}"], "git cat-file base")
    except RuntimeError:
        try:
            git(workspace, ["fetch", "--no-tags", "--no-recurse-submodules", "--depth=1",
                            "origin", base], "git fetch base")
            git(workspace, ["cat-file", "-e", base + "^{commit}"], "git cat-file base")
        except RuntimeError as exc:
            return FALSE, "base commit unavailable: %s" % exc
    trusted = Path(tempfile.mkdtemp(prefix="docs-gate-", dir=str(runner_temp)))
    impact = trusted / "impact"
    impact.mkdir()
    for name in GATE_FILES:
        try:
            blob = git(workspace, ["cat-file", "blob", "%s:%s/%s" % (base, IMPACT_REL, name)],
                       "git cat-file decider")
        except RuntimeError:
            return FALSE, "decider %s absent from the base commit" % name
        (impact / name).write_bytes(blob)
    try:
        diff = git(workspace, ["diff", "--no-renames", "--no-ext-diff", "--no-textconv",
                               "--name-status", "-z", base, "HEAD", "--"], "git diff")
    except RuntimeError as exc:
        return FALSE, "whole-PR diff unreadable: %s" % exc
    try:
        res = subprocess.run(
            [sys.executable, "-I", str(impact / "docs_only_gate.py"), "decide", "--stdin",
             "--rules", str(impact / "rules.json"), "--event-name", event,
             "--base-ref", base_ref, "--repo", str(workspace)],
            input=diff, capture_output=True, timeout=DECIDER_TIMEOUT_S,
            cwd=str(trusted), env=cargo_skip.git_environment(), check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return FALSE, "base decider did not run: %s" % exc
    detail = cargo_skip.clean_text(res.stderr.decode("utf-8", "replace").splitlines()[-1]
                                   if res.stderr.strip() else "")
    if res.returncode == EXIT_DOCS_ONLY:
        return TRUE, "docs only (base decider): %s" % detail
    return FALSE, "full run (base decider rc=%d): %s" % (res.returncode, detail)


def cmd_step(_args: argparse.Namespace) -> int:
    """Write docs_only=<true|false> to GITHUB_OUTPUT; always exit 0."""
    env = os.environ
    value, notice = FALSE, "internal error"
    try:
        workspace = Path(env.get("GITHUB_WORKSPACE") or ".").resolve()
        runner_temp = Path(env.get("RUNNER_TEMP") or str(workspace)).resolve()
        value, notice = judge_step(workspace, runner_temp,
                                   env.get("DOCS_GATE_EVENT_NAME", ""),
                                   env.get("DOCS_GATE_BASE_SHA", ""),
                                   env.get("DOCS_GATE_BASE_REF", ""))
    except Exception as exc:  # noqa: BLE001 - every doubt is a full run
        value, notice = FALSE, "error: %s" % exc
    print("::notice::docs-only gate (#9683): docs_only=%s; %s"
          % (value, cargo_skip.clean_text(notice)))
    output = env.get("GITHUB_OUTPUT", "")
    if not output:
        print("::warning::GITHUB_OUTPUT unset; docs_only stays empty, the job runs in full")
        return EXIT_FULL_RUN
    try:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write("%s=%s\n" % (OUTPUT_KEY, value))
    except OSError as exc:
        print("::warning::cannot write GITHUB_OUTPUT (%s); the job runs in full"
              % cargo_skip.clean_text(str(exc)))
    return EXIT_FULL_RUN


def main(argv: Optional[List[str]] = None) -> int:
    """Parse the subcommand and run it."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    dec = sub.add_parser("decide", help="judge NUL-separated --name-status -z bytes on stdin")
    dec.add_argument("--stdin", action="store_true", required=True)
    dec.add_argument("--rules", default=str(common.RULES_PATH))
    dec.add_argument("--event-name", default="")
    dec.add_argument("--base-ref", default="")
    dec.add_argument("--repo", default="",
                     help="work tree for cargo_skip's tracked-symlink scan")
    dec.set_defaults(func=cmd_decide)
    step = sub.add_parser("step", help="run as the composite action's step")
    step.set_defaults(func=cmd_step)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
