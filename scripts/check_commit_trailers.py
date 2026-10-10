#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Refuse commits that carry a `Claude-Session:` trailer (#6580).

The attribution rules (docs/AI_DEVELOPER_WORKFLOW.md §5.2) allow the
`Co-Authored-By:` trailer naming the model; a session-URL trailer is not
allowed. Run on the commits a branch adds:

    python3 -I scripts/check_commit_trailers.py --range <base>..HEAD

Only the trailer block git itself parses counts (`%(trailers:only,unfold)`),
so prose that names the key passes. The key is matched case-insensitively.

Exit codes: 0 no offending commit; 1 at least one offending commit (each is
listed); 2 the range cannot be listed or holds no commits (fail closed).
"""

import argparse
from pathlib import Path
import subprocess
import sys

FORBIDDEN_KEY = "claude-session"
RECORD_SEP = "\x1e"
FIELD_SEP = "\x1f"


def offending_keys(trailers):
    """Return the trailer keys in `trailers` that are the forbidden key."""
    found = []
    for line in trailers.splitlines():
        key, sep, _value = line.partition(":")
        if sep and key.strip().lower() == FORBIDDEN_KEY:
            found.append(key.strip())
    return found


def list_commits(repo, rng):
    """Return [(sha, subject, trailers)] for every commit in `rng`, or raise."""
    fmt = "%H" + FIELD_SEP + "%s" + FIELD_SEP + "%(trailers:only,unfold)" + RECORD_SEP
    done = subprocess.run(["git", "-C", str(repo), "log", "--format=" + fmt, rng, "--"],
                          capture_output=True, text=True)
    if done.returncode != 0:
        first = (done.stderr.strip().splitlines() or ["git log failed"])[0][:300]
        raise RuntimeError(f"cannot list {rng}: {first}")
    commits = []
    for record in done.stdout.split(RECORD_SEP):
        record = record.strip("\n")
        if not record:
            continue
        parts = record.split(FIELD_SEP)
        if len(parts) != 3:
            raise RuntimeError(f"cannot list {rng}: unexpected git log record")
        commits.append((parts[0], parts[1], parts[2]))
    return commits


def check(repo, rng):
    try:
        commits = list_commits(repo, rng)
    except (OSError, RuntimeError) as err:
        print(f"check_commit_trailers: {err}", file=sys.stderr)
        return 2
    if not commits:
        print(f"check_commit_trailers: no commits in {rng}", file=sys.stderr)
        return 2
    bad = [(sha, subject) for sha, subject, trailers in commits if offending_keys(trailers)]
    for sha, subject in bad:
        print(f"{sha} carries a Claude-Session trailer: {subject}")
    print(f"{len(commits)} commits checked, {len(bad)} carry a Claude-Session trailer")
    return 1 if bad else 0


def self_test():
    cases = [
        ("none", "Refs: #1\nCo-Authored-By: X <x@example.invalid>", []),
        ("exact", "Refs: #1\nClaude-Session: https://example.invalid", ["Claude-Session"]),
        ("lower", "claude-session: u", ["claude-session"]),
        ("upper-spaced", "CLAUDE-SESSION : u", ["CLAUDE-SESSION"]),
        ("prefix-only", "Claude-Sessions: u\nX-Claude-Session: u", []),
        ("no-colon", "Claude-Session u", []),
    ]
    failed = 0
    for name, trailers, want in cases:
        got = offending_keys(trailers)
        ok = got == want
        failed += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'} {name}: {got!r}")
    print(f"commit-trailers self-test: {failed} failed")
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--range", dest="rng", help="git revision range, e.g. <base>..HEAD")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="repository path")
    parser.add_argument("--self-test", action="store_true", help="run the built-in cases")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.rng:
        parser.error("--range is required unless --self-test is given")
    return check(args.repo, args.rng)


if __name__ == "__main__":
    sys.exit(main())
