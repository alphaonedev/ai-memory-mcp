#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Carrier-base freshness gate (#6143).

THE DEFECT CLASS. `chain/**` and `rehearsal/**` are `pull_request` base
branches of the gating workflows but carry no ruleset requiring an up-to-date
head. GitHub does not re-run `pull_request` workflows when the base moves, so
a green gate is a verdict on the merge ref as it was built. If the base tip has
since moved, the gates judged a tree that is not the tree that will land.

THE RULE. On a `pull_request` whose base is `chain/**` or `rehearsal/**`, the
merge commit this job checked out (GITHUB_SHA) must have:

  * first parent  == the LIVE tip of origin/<GITHUB_BASE_REF> (fetched fresh,
                     never a cached tracking ref), and
  * second parent == PR_HEAD_SHA.

Otherwise the head is BEHIND its base and every other gate's green is stale:
the gate FAILS CLOSED with the remedy (`gh pr update-branch`, wait for the new
run). Any missing input, unresolvable ref or git failure is also a failure.

Other events and other base branches are N/A (exit 0, loudly): `release/**`
and `main` are covered by branch protection `strict: true`.

LIMIT, stated plainly. This closes the window "merge ref built -> this job
started" and makes a stale green detectable by a re-run (a re-run of a
pull_request job reuses the same GITHUB_SHA, so it re-fetches the live tip and
turns RED if the base has moved). It cannot close "job finished -> merge click"
on its own; that needs the carrier ruleset in docs/ci/CARRIER-BRANCH-GATES.md
(strict required status checks), which is a repository-settings change.

Exit: 0 pass / N/A, 1 gate failure, 2 usage.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CARRIER_PREFIXES = ("chain/", "rehearsal/")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class GateError(Exception):
    """Fail-closed gate failure; the message is the operator-facing reason."""


def run_git(repo, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, env=env, timeout=120, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError(f"git {args[0]} could not complete: {exc}") from exc


def git_text(repo, *args):
    proc = run_git(repo, *args)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git {args[0]} exited {proc.returncode}: {err}")
    return proc.stdout.decode("utf-8", "replace").strip()


def is_carrier_base(base_ref):
    return base_ref.startswith(CARRIER_PREFIXES)


def live_base_tip(repo, base_ref):
    """Fetch origin/<base_ref> unconditionally and return its tip sha."""
    if base_ref.startswith("-") or ".." in base_ref or any(c.isspace() for c in base_ref):
        raise GateError(f"GITHUB_BASE_REF {base_ref!r} is not a plain branch name (fail-closed)")
    tracking = f"refs/remotes/origin/{base_ref}"
    proc = run_git(
        repo, "fetch", "--no-tags", "--quiet", "--end-of-options", "origin",
        f"+refs/heads/{base_ref}:{tracking}",
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"cannot fetch the live base ref origin/{base_ref}: {err} (fail-closed)")
    tip = git_text(repo, "rev-parse", "--verify", "--end-of-options", tracking + "^{commit}")
    if not SHA_RE.match(tip):
        raise GateError(f"live base tip {tip!r} is not a full sha (fail-closed)")
    return tip


def check(repo, env):
    """Return a human message on pass / N/A; raise GateError on failure."""
    event = env.get("GITHUB_EVENT_NAME", "")
    if event != "pull_request":
        return f"N/A: event {event or '<unset>'!r} is not pull_request (nothing to judge)"
    base_ref = env.get("GITHUB_BASE_REF", "")
    if not base_ref:
        raise GateError("GITHUB_BASE_REF is unset on a pull_request event (fail-closed)")
    if not is_carrier_base(base_ref):
        return f"N/A: base {base_ref!r} is not a chain/** or rehearsal/** carrier"
    merge_sha = env.get("GITHUB_SHA", "")
    head_sha = env.get("PR_HEAD_SHA", "")
    for key, val in (("GITHUB_SHA", merge_sha), ("PR_HEAD_SHA", head_sha)):
        if not SHA_RE.match(val):
            raise GateError(f"{key} is unset or not a full sha (fail-closed)")
    parents = git_text(repo, "rev-list", "--parents", "-n", "1", "--end-of-options", merge_sha).split()
    if len(parents) != 3 or parents[0] != merge_sha:
        raise GateError(
            f"{merge_sha[:12]} is not a two-parent merge commit (parents: {parents[1:]}); "
            "cannot prove the judged tree is the tree that lands (fail-closed)"
        )
    first, second = parents[1], parents[2]
    if second != head_sha:
        raise GateError(
            f"merge commit second parent {second[:12]} != PR head {head_sha[:12]}: the checkout "
            "is not this PR head's merge ref (fail-closed)"
        )
    tip = live_base_tip(repo, base_ref)
    if first != tip:
        raise GateError(
            f"BEHIND: the merge ref was built on {first[:12]} but origin/{base_ref} is now "
            f"{tip[:12]}. Every other gate on this run judged a tree that is not the tree that "
            "will land (#6143). Run `gh pr update-branch <PR>` (or merge the base into the head) "
            "and wait for the new run before merging."
        )
    return f"OK: merge ref first parent {first[:12]} is the live tip of origin/{base_ref}"


# ---------------------------------------------------------------------------
# self-test: plant-a-violation corpus in a scratch repo (never /tmp)
# ---------------------------------------------------------------------------


def _g(repo, *args):
    return git_text(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    "-c", "commit.gpgsign=false", *args)


def _commit(repo, name):
    Path(repo, name).write_text(name, encoding="utf-8")
    _g(repo, "add", name)
    _g(repo, "commit", "-q", "-m", name)
    return _g(repo, "rev-parse", "HEAD")


def self_test():
    scratch_root = os.environ.get("TMPDIR") or str(REPO_ROOT / ".local-runs")
    Path(scratch_root).mkdir(parents=True, exist_ok=True)
    failures = []

    def expect(label, repo, env, want_ok, needle):
        try:
            out = check(repo, env)
            ok, text = True, out
        except GateError as exc:
            ok, text = False, str(exc)
        if ok != want_ok or needle not in text:
            failures.append(f"{label}: ok={ok} (want {want_ok}) text={text!r} (want {needle!r})")

    with tempfile.TemporaryDirectory(dir=scratch_root, prefix="carrier-fresh-") as tmp:
        origin = Path(tmp, "origin.git")
        work = Path(tmp, "work")
        _g(tmp, "init", "-q", "--bare", "-b", "chain/x", str(origin))
        _g(tmp, "clone", "-q", str(origin), str(work))
        _g(work, "checkout", "-q", "-b", "chain/x")
        b0 = _commit(work, "b0")
        _g(work, "push", "-q", "origin", "chain/x")
        _g(work, "checkout", "-q", "-b", "pr", b0)
        head = _commit(work, "pr-change")
        _g(work, "checkout", "-q", "-b", "mref", b0)
        _g(work, "merge", "-q", "--no-ff", "-m", "merge", head)
        merge = _g(work, "rev-parse", "HEAD")
        env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_BASE_REF": "chain/x",
               "GITHUB_SHA": merge, "PR_HEAD_SHA": head}

        expect("fresh", work, env, True, "live tip")
        expect("non-pr", work, dict(env, GITHUB_EVENT_NAME="push"), True, "N/A")
        expect("non-carrier base", work, dict(env, GITHUB_BASE_REF="release/v1.0.0"), True, "N/A")
        expect("no base ref", work, {k: v for k, v in env.items() if k != "GITHUB_BASE_REF"},
               False, "GITHUB_BASE_REF is unset")
        expect("bad head sha", work, dict(env, PR_HEAD_SHA="abc"), False, "PR_HEAD_SHA")
        expect("wrong head", work, dict(env, PR_HEAD_SHA=b0), False, "second parent")
        expect("option base", work, dict(env, GITHUB_BASE_REF="chain/--x y"), False, "plain branch name")
        expect("not a merge", work, dict(env, GITHUB_SHA=head), False, "not a two-parent merge")
        expect("unfetchable base", work, dict(env, GITHUB_BASE_REF="chain/missing"), False, "cannot fetch")

        # Move the live base after the merge ref was built (the #6143 shape).
        _g(work, "checkout", "-q", "chain/x")
        b1 = _commit(work, "b1")
        _g(work, "push", "-q", "origin", "chain/x")
        _g(work, "checkout", "-q", "mref")
        expect("stale merge ref", work, env, False, "BEHIND")
        expect("stale merge ref names tip", work, env, False, b1[:12])
        expect("rehearsal base also judged", work,
               dict(env, GITHUB_BASE_REF="rehearsal/none"), False, "cannot fetch")

    if failures:
        for line in failures:
            print(f"SELF-TEST FAIL {line}", file=sys.stderr)
        return 1
    print("check_carrier_base_fresh self-test: 12 cases OK")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Carrier-base freshness gate (#6143).")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo", default=str(REPO_ROOT))
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        print(check(args.repo, dict(os.environ)))
    except GateError as exc:
        print(f"carrier-base-fresh: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
