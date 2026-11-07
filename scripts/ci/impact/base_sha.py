"""Resolve the LIVE base sha a pull request or merge group is judged against (#8240).

decision: the live base is the first parent of the pull_request merge ref and
merge_group.base_sha over pull_request.base.sha because base.sha is frozen at
PR-open time and github.sha on merge_group contains the PR

This module is a library kept for the unit tests that pin its behaviour; no
workflow step runs it. The `select` and `ci-gate` jobs derive the base inline
in their materialise steps, before any checkout file executes, so a resolver
that ran from the checkout could be rewritten by the code it judges. The
contract below is what those tests pin:

  EVENT_NAME             github.event_name
  HEAD_SHA               pull_request.head.sha, or merge_group.head_sha
  MERGE_GROUP_BASE_SHA   github.event.merge_group.base_sha
  BASE_REF               github.base_ref, or merge_group.base_ref

pull_request: the checked-out commit is the merge ref (`actions/checkout`
default), so its first parent is the base branch tip at merge-ref creation:
`git rev-parse HEAD^1`. HEAD^2 must equal HEAD_SHA, else the checkout is not
the merge ref and the run fails closed. merge_group: MERGE_GROUP_BASE_SHA.
Any other event fails closed.

Both candidates must (1) be an ancestor of origin/<BASE_REF> and (2) not
contain HEAD_SHA (a base that contains the head would let the change judge
itself). Output (stdout and, with --github-output, the step output file):
`sha=<40 hex>` and `reason=<token>`; on any failure sha is empty, the reason
is a fixed token (never document text) and the exit code is 1.
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REF_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._/-]*$")
HEADS_PREFIX = "refs/heads/"
GIT_TIMEOUT_S = 120


class BaseRejected(Exception):
    """The live base cannot be established; the message is a fixed reason token."""


def git(repo, *args):
    """Run git in `repo`; a launch failure or timeout fails closed."""
    try:
        return subprocess.run(["git", "-C", str(repo)] + list(args), capture_output=True,
                              timeout=GIT_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired):
        raise BaseRejected("git-failed")


def rev_parse(repo, spec):
    res = git(repo, "rev-parse", "--verify", "--quiet", spec)
    value = res.stdout.decode("utf-8", "replace").strip()
    return value if res.returncode == 0 and SHA_RE.match(value) else ""


def is_ancestor(repo, older, newer):
    """True when `older` is an ancestor of, or equal to, `newer`; error fails closed."""
    res = git(repo, "merge-base", "--is-ancestor", older, newer)
    if res.returncode == 0:
        return True
    if res.returncode == 1:
        return False
    raise BaseRejected("git-failed")


def base_ref_tip(repo, base_ref):
    """Return the sha of origin/<base_ref>, fetching it once when absent."""
    if not REF_RE.match(base_ref) or ".." in base_ref or base_ref.endswith((".lock", "/")):
        raise BaseRejected("base-ref-invalid")
    local = "refs/remotes/origin/" + base_ref
    tip = rev_parse(repo, local + "^{commit}")
    if not tip:
        git(repo, "fetch", "--no-tags", "origin", "+%s%s:%s" % (HEADS_PREFIX, base_ref, local))
        tip = rev_parse(repo, local + "^{commit}")
    if not tip:
        raise BaseRejected("base-ref-unavailable")
    return tip


def candidate(repo, env, head):
    """Return (candidate base sha, reason token) for the event, or reject."""
    event = env.get("EVENT_NAME", "")
    if event == "pull_request":
        parent2 = rev_parse(repo, "HEAD^2^{commit}")
        if parent2 != head:
            raise BaseRejected("merge-ref-unexpected")
        parent1 = rev_parse(repo, "HEAD^1^{commit}")
        if not parent1:
            raise BaseRejected("merge-ref-unexpected")
        return parent1, "live-base-first-parent"
    if event == "merge_group":
        raw = env.get("MERGE_GROUP_BASE_SHA", "")
        if not SHA_RE.match(raw):
            raise BaseRejected("base-sha-invalid")
        if not rev_parse(repo, raw + "^{commit}"):
            raise BaseRejected("base-sha-invalid")
        return raw, "live-base-merge-group"
    raise BaseRejected("base-event-unsupported")


def resolve(repo, env):
    """Return (sha, reason) or raise BaseRejected(reason)."""
    if env.get("EVENT_NAME", "") not in ("pull_request", "merge_group"):
        raise BaseRejected("base-event-unsupported")
    head = env.get("HEAD_SHA", "")
    if not SHA_RE.match(head):
        raise BaseRejected("head-sha-invalid")
    base_ref = env.get("BASE_REF", "")
    if base_ref.startswith(HEADS_PREFIX):
        base_ref = base_ref[len(HEADS_PREFIX):]
    base, reason = candidate(repo, env, head)
    if not rev_parse(repo, head + "^{commit}"):
        raise BaseRejected("head-sha-invalid")
    if is_ancestor(repo, head, base):
        raise BaseRejected("base-contains-head")
    tip = base_ref_tip(repo, base_ref)
    if not is_ancestor(repo, base, tip):
        raise BaseRejected("base-not-on-base-ref")
    return base, reason


def emit(sha, reason, output_path):
    lines = "sha=%s\nreason=%s\n" % (sha, reason)
    sys.stdout.write(lines)
    if output_path:
        with open(output_path, "a") as handle:
            handle.write(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--repo", default=".")
    parser.add_argument("--github-output", default=None)
    args = parser.parse_args(argv)
    try:
        sha, reason = resolve(Path(args.repo), dict(os.environ))
    except BaseRejected as exc:
        emit("", str(exc), args.github_output)
        return 1
    emit(sha, reason, args.github_output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
