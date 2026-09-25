#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#3872: refuse promotion heads missing release-base commits.

Exit 0: PASS or explicitly INAPPLICABLE event; 1: BEHIND; 2: cannot prove.
No network, checkout, index, branch or configuration mutation by the check.
--self-test creates and removes its own Git repositories only.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


RELEASE = "release/v1.0.0"
REMOTE_BASE = "refs/remotes/origin/" + RELEASE
ROOT = Path(__file__).resolve().parent.parent


class CannotProve(Exception):
    """Missing/ambiguous evidence must not become a pass."""


def git(repo, *args, input_text=None):
    # Resolve the requested repository, not an inherited worktree/index override.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        result = subprocess.run(
            ["git", "-c", "core.warnAmbiguousRefs=true", "-C", str(repo), *args], input=input_text,
            capture_output=True, text=True, env=env, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CannotProve(f"git {args[0]} could not complete: {exc}") from exc
    if result.returncode:
        raise CannotProve(f"git {args[0]} exited {result.returncode}: {result.stderr.strip()}")
    if "ambiguous" in result.stderr.lower():
        raise CannotProve(f"ambiguous Git reference: {result.stderr.strip()}")
    return result.stdout.strip()


def geometry(repo, base_ref, head_ref):
    if git(repo, "rev-parse", "--is-shallow-repository") != "false":
        raise CannotProve("shallow history: fetch full history before measuring ancestry")
    grafts = Path(git(repo, "rev-parse", "--git-path", "info/grafts"))
    if not grafts.is_absolute():
        grafts = repo / grafts
    if grafts.exists() and grafts.read_text().strip():
        raise CannotProve("legacy info/grafts changes ancestry; refusing altered history")
    base = git(repo, "rev-parse", "--verify", "--end-of-options", base_ref + "^{commit}")
    head = git(repo, "rev-parse", "--verify", "--end-of-options", head_ref + "^{commit}")
    ahead = int(git(repo, "rev-list", "--count", f"{base}..{head}"))
    behind = int(git(repo, "rev-list", "--count", f"{head}..{base}"))
    print(f"promotion-geometry: base={base} ({base_ref}) head={head} ({head_ref}) "
          f"ahead={ahead} behind={behind}")
    if behind:
        print("FAIL #3872: candidate is BEHIND release; cut-only evidence cannot certify "
              "the PR merge tree. Integrate/re-measure the pinned base before promotion.")
        return 1
    print("PASS #3872: base is an ancestor of candidate; merge tree equals candidate tree")
    return 0


def event_refs(path, event_name):
    if not event_name:
        raise CannotProve("--github-event requires GITHUB_EVENT_NAME (or --event-name)")
    if event_name != "pull_request":
        print(f"INAPPLICABLE #3872: event {event_name!r} is not a promotion pull_request")
        return None
    try:
        event = json.loads(path.read_text())
        pr = event["pull_request"]
        base_ref = pr["base"]["ref"]
        if not isinstance(base_ref, str) or not base_ref:
            raise ValueError("missing base ref")
        if base_ref != RELEASE:
            print(f"INAPPLICABLE #3872: PR base {base_ref!r} is not {RELEASE}")
            return None
        base, head = pr["base"]["sha"], pr["head"]["sha"]
        if not all(isinstance(s, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", s)
                   for s in (base, head)):
            raise ValueError("promotion base/head must be full commit SHAs")
        return base, head
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise CannotProve(f"invalid promotion event: {exc}") from exc


def self_test():
    """Exercise the actual CLI against histories, including a misleading merge HEAD."""
    script = Path(__file__).resolve()
    count = 0
    # Explicit workspace scratch: never the system temporary directory/tmpfs.
    scratch = ROOT / ".local-runs"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="promotion-geometry-3872-", dir=scratch) as td:
        repo = Path(td) / "repo"
        repo.mkdir()
        git(repo, "init", "--quiet", "--initial-branch=fixture")
        # Only this disposable repository; never read or use a signing key.
        git(repo, "config", "user.name", "Geometry fixture")
        git(repo, "config", "user.email", "geometry@example.invalid")
        git(repo, "config", "commit.gpgsign", "false")

        def commit(name):
            (repo / name).write_text(name + "\n")
            git(repo, "add", "--", name)
            git(repo, "commit", "--quiet", "--no-gpg-sign", "-m", name)
            return git(repo, "rev-parse", "HEAD")

        def check(name, expected, *args, target=repo, contains=None):
            nonlocal count
            result = subprocess.run(
                [sys.executable, str(script), "--repo", str(target), *args],
                capture_output=True, text=True, timeout=60, check=False,
            )
            output = result.stdout + result.stderr
            if result.returncode != expected or (contains and contains not in output):
                raise CannotProve(f"self-test {name}: expected exit {expected}, "
                                  f"got {result.returncode}\n{output}")
            count += 1
            print(f"self-test PASS: {name} (observed exit {result.returncode})")
            return output

        root = commit("root.txt")
        head = commit("candidate.txt")
        check("equal", 0, "--base", root, "--head", root, contains="behind=0")
        check("ahead-only", 0, "--base", root, "--head", head, contains="ahead=1 behind=0")
        check("behind-only", 1, "--base", head, "--head", root, contains="behind=1")
        git(repo, "checkout", "--quiet", "--detach", root)
        base = commit("release-only-offender.txt")
        negative = check("BEHIND-diverged-known-negative", 1, "--base", base, "--head", head,
                         contains="ahead=1 behind=1")
        print(negative.strip())
        check("missing-object", 2, "--base", "refs/heads/absent", "--head", head)
        git(repo, "update-ref", "refs/remotes/origin/" + RELEASE, base)
        tree = git(repo, "merge-tree", "--write-tree", base, head).splitlines()[0]
        merge = git(repo, "-c", "commit.gpgsign=false", "commit-tree", tree,
                    "-p", base, "-p", head, input_text="synthetic PR merge\n")
        git(repo, "checkout", "--quiet", "--detach", merge)
        check("synthetic-checkout-would-hide-BEHIND-control", 0,
              "--base", base, "--head", "HEAD", contains="behind=0")
        event = Path(td) / "event.json"

        def payload(b, h, ref=RELEASE):
            event.write_text(json.dumps({"pull_request": {
                "base": {"ref": ref, "sha": b}, "head": {"sha": h}}}))

        payload(base, head)
        check("PR-event-uses-original-head-not-merge-HEAD", 1, "--github-event", str(event),
              "--event-name", "pull_request", contains="behind=1")
        payload(root, head)
        check("PR-ahead-only", 0, "--github-event", str(event), "--event-name", "pull_request")
        payload(base, head, "next/v1.1.0")
        check("non-promotion-PR", 0, "--github-event", str(event),
              "--event-name", "pull_request", contains="INAPPLICABLE")
        check("push-event", 0, "--github-event", str(event), "--event-name", "push",
              contains="INAPPLICABLE")
        payload(base, "HEAD")
        check("malformed-promotion-SHA", 2, "--github-event", str(event),
              "--event-name", "pull_request")
        event.write_text("{}")
        check("missing-promotion-fields", 2, "--github-event", str(event),
              "--event-name", "pull_request")
        event.write_text("not JSON")
        check("invalid-event-JSON", 2, "--github-event", str(event), "--event-name", "pull_request")
        check("event-cannot-be-overridden", 2, "--github-event", str(event), "--head", head)
        git(repo, "checkout", "--quiet", "--detach", head)
        git(repo, "update-ref", "refs/heads/origin/" + RELEASE, head)
        check("local-branch-cannot-shadow-default-remote-base", 1, contains="behind=1")
        check("ambiguous-explicit-ref-refused", 2, "--base", "origin/" + RELEASE,
              "--head", head, contains="ambiguous")
        git(repo, "commit", "--quiet", "--no-gpg-sign", "--allow-empty", "-m", "base empty")
        empty_base = git(repo, "rev-parse", "HEAD")
        check("BEHIND-even-with-equal-tree", 1, "--base", empty_base, "--head", head)
        # Replacement objects must not turn BEHIND into a false ancestor proof.
        replacement = git(repo, "-c", "commit.gpgsign=false", "commit-tree", tree,
                          "-p", base, input_text="misleading replacement\n")
        git(repo, "replace", head, replacement)
        check("replace-object-cannot-hide-BEHIND", 1, "--base", base, "--head", head)
        shallow = Path(td) / "shallow"
        git(repo, "clone", "--quiet", "--depth=1", repo.as_uri(), str(shallow))
        check("shallow-history", 2, "--base", "HEAD", "--head", "HEAD",
              target=shallow, contains="shallow history")
        (repo / ".git/info/grafts").write_text(f"{head} {base}\n")
        check("legacy-graft-refused", 2, "--base", base, "--head", head, contains="grafts")
    print(f"promotion-geometry self-test: {count} passed; 0 failed (BEHIND negative controls refused)")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--base", help=f"pinned release base (default: {REMOTE_BASE})")
    parser.add_argument("--head", help="unmerged candidate (default: HEAD)")
    parser.add_argument("--github-event", type=Path, help="use original PR head/base from event JSON")
    parser.add_argument("--event-name", default=os.environ.get("GITHUB_EVENT_NAME"))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.github_event and (args.base or args.head):
        parser.error("--github-event cannot be combined with --base/--head")
    if args.self_test and (args.base or args.head or args.github_event):
        parser.error("--self-test cannot be combined with a geometry selection")
    try:
        if args.self_test:
            return self_test()
        refs = (args.base or REMOTE_BASE, args.head or "HEAD")
        if args.github_event:
            refs = event_refs(args.github_event, args.event_name)
            if refs is None:
                return 0
        return geometry(args.repo.resolve(), *refs)
    except (CannotProve, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR #3872 (fail closed): {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
