#!/usr/bin/env python3
"""External-PR operator-approval gate (#3591 policy, #6117 / #6193 every-event evaluation).

RULE (unchanged from the inline gate it replaces): a pull request whose author is
not OWNER / MEMBER / COLLABORATOR, or whose head lives in another repository (a
fork, or a deleted head repository), may merge only after an APPROVED review by
the accountable operator account is the operator's latest review of the PR's
CURRENT head sha (#6329: a later CHANGES_REQUESTED or a dismissal revokes it).
Team PRs from a same-repository head pass.

#6117 / #6193: the gate is a REQUIRED context, and a push (or merge_group) run
reports it on the same sha as the pull_request run. The old inline step answered
every non-pull_request event "not applicable (pass)", so a push run on an external
PR's head sha could stand in for the PR run. On any event other than pull_request
this evaluator lists the OPEN pull requests of the repository, keeps every one
whose head sha is the run's sha, and applies the same rule to each. No PR heads the
sha: pass. Any API error, unparsable page or malformed entry: FAIL (fail closed).

#6227: on merge_group GITHUB_SHA is the queue commit, which is never a PR head, so
the "heads this sha" lookup would pass vacuously. The PR under test is instead named
by the event payload: merge_group.head_ref is
refs/heads/gh-readonly-queue/<base>/pr-<N>-<sha>. The evaluator parses N, finds the
OPEN pull request N and judges it at its own current head sha by the same rule. A
payload that is unreadable, a head_ref it cannot parse, or a PR that is not open:
FAIL (fail closed). Mirrors the pull_request arm (the event names the PR).

#6242 / #6325: the <sha> in that ref is merge_group.base_sha, the queue commit's
PARENT (merge_group.head_sha is the queue commit itself). It must be a full lowercase
commit sha equal to merge_group.base_sha, which GitHub sets; otherwise FAIL.

Exit 0: pass. Exit 1: approval missing, or the verdict cannot be established.
Standard library only; Python 3.9+.
"""

import argparse
import json
import os
import re
import subprocess
import sys

TEAM_ASSOCIATIONS = frozenset(("OWNER", "MEMBER", "COLLABORATOR"))
SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# GitHub limits: owner <= 39, repository name <= 100 characters (#6259).
REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}")
# A login is 1-39 characters; a GitHub App account carries exactly one "[bot]" suffix (#6259).
LOGIN_RE = re.compile(r"[A-Za-z0-9-]{1,39}(?:\[bot\])?")
ASSOC_RE = re.compile(r"[A-Z_]{1,32}")
# GitHub token shapes, plus any HTTP authorization value after its scheme word (#6328).
TOKEN_RE = re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,}"
                      r"|(?i:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,})")
# #6329: the operator's latest deciding review of the head decides. Fixed-width UTC timestamps
# compare correctly as strings (no datetime parsing, identical on 3.9 and 3.14).
DECIDING_REVIEW_STATES = frozenset(("APPROVED", "CHANGES_REQUESTED", "DISMISSED"))
IGNORED_REVIEW_STATES = frozenset(("COMMENTED", "PENDING"))
REVIEW_TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
QUEUE_REF_RE = re.compile(r"refs/heads/gh-readonly-queue/.+/pr-([0-9]{1,9})-([^/]*)")


class GateError(Exception):
    """The verdict cannot be established; the gate fails closed."""


def workflow_error(message):
    """One ``::error::`` workflow command whose data cannot start another command (#6243).

    Tokens are redacted, other control characters are replaced, and ``%``, CR and LF are
    percent-encoded exactly as the runner decodes workflow-command data.
    """
    text = TOKEN_RE.sub("[redacted]", str(message))
    text = re.sub("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x85\u2028\u2029]", "?", text)
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return "::error::" + text



def parse_pages(raw):
    """Parse `gh api --paginate` output: one or more concatenated JSON arrays."""
    decoder = json.JSONDecoder()
    items = []
    pos = 0
    seen = 0
    text = raw if isinstance(raw, str) else ""
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        try:
            page, pos = decoder.raw_decode(text, pos)
        except ValueError as exc:
            raise GateError(f"API output is not JSON at offset {pos}: {exc}") from exc
        if not isinstance(page, list):
            raise GateError(f"API page is a {type(page).__name__}, not an array (an error body?)")
        items.extend(page)
        seen += 1
    if seen == 0:
        raise GateError("API output is empty")
    return items


def gh_api(path):
    """GET one paginated REST path through the gh CLI; any failure raises GateError."""
    try:
        proc = subprocess.run(["gh", "api", "--paginate", path],
                              capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError(f"gh api {path}: {exc}") from exc
    if proc.returncode != 0:
        first = (proc.stderr.strip().splitlines() or [""])[0]
        first = TOKEN_RE.sub("[redacted]", first)[:300]
        raise GateError(f"gh api {path} exited {proc.returncode}: {first}")
    return parse_pages(proc.stdout)


def _head(pr):
    if not isinstance(pr, dict):
        raise GateError("pull request entry is not an object")
    number = pr.get("number")
    head = pr.get("head")
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        raise GateError("pull request entry has no valid number")
    if not isinstance(head, dict):
        raise GateError(f"PR #{number} has no head object")
    sha = head.get("sha")
    if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
        raise GateError(f"PR #{number} has no valid head sha")
    return number, sha, head


def is_external(pr, repo):
    """True unless a team author opened the PR from a head in this repository."""
    _number, _sha, head = _head(pr)
    assoc = pr.get("author_association")
    head_repo = head.get("repo")
    full_name = head_repo.get("full_name") if isinstance(head_repo, dict) else None
    return not (assoc in TEAM_ASSOCIATIONS and full_name == repo)


def operator_approved(reviews, operator, sha):
    """True iff the operator's LATEST deciding review of exactly `sha` is APPROVED (#6329).

    Only `operator`'s reviews whose commit_id is `sha` count. APPROVED, CHANGES_REQUESTED and
    DISMISSED decide; COMMENTED and PENDING do not; any other state is a GateError. Deciding
    reviews are ordered by (submitted_at, id); a deciding review whose submitted_at is not a
    UTC "YYYY-MM-DDTHH:MM:SSZ" string or whose id is not an integer is a GateError.
    """
    deciding = []
    for review in reviews:
        if not isinstance(review, dict):
            raise GateError("review entry is not an object")
        user = review.get("user")
        login = user.get("login") if isinstance(user, dict) else None
        if login != operator or review.get("commit_id") != sha:
            continue
        state = review.get("state")
        if state in IGNORED_REVIEW_STATES:
            continue
        if state not in DECIDING_REVIEW_STATES:
            shown = state if isinstance(state, str) and len(state) <= 40 else type(state).__name__
            raise GateError(f"operator review on {sha} has an unknown state {shown!r}")
        submitted_at = review.get("submitted_at")
        review_id = review.get("id")
        if not isinstance(submitted_at, str) or not REVIEW_TIME_RE.fullmatch(submitted_at):
            raise GateError(f"operator review on {sha} has no valid submitted_at")
        if not isinstance(review_id, int) or isinstance(review_id, bool):
            raise GateError(f"operator review on {sha} has no valid id")
        deciding.append((submitted_at, review_id, state))
    return bool(deciding) and max(deciding)[2] == "APPROVED"


def pr_verdict(pr, repo, operator, api):
    """(passed, line) for one pull request."""
    number, sha, head = _head(pr)
    user = pr.get("user")
    author = user.get("login") if isinstance(user, dict) else None
    if not isinstance(author, str) or not LOGIN_RE.fullmatch(author):
        raise GateError(f"PR #{number} has an invalid author login")
    assoc = pr.get("author_association")
    if assoc is not None and (not isinstance(assoc, str) or not ASSOC_RE.fullmatch(assoc)):
        raise GateError(f"PR #{number} has an invalid author_association")
    head_repo = head.get("repo")
    full_name = head_repo.get("full_name") if isinstance(head_repo, dict) else None
    if full_name is not None and (not isinstance(full_name, str) or not REPO_RE.fullmatch(full_name)):
        raise GateError(f"PR #{number} has an invalid head repository name")
    if not is_external(pr, repo):
        return True, f"PR #{number}: author={author} ({assoc}), same-repo head - team PR (pass)"
    reviews = api(f"repos/{repo}/pulls/{number}/reviews?per_page=100")
    if operator_approved(reviews, operator, sha):
        return True, f"PR #{number}: latest review by @{operator} of head {sha} is APPROVED (pass)"
    return False, (
        workflow_error(f"External-PR operator-approval gate FAILED for PR #{number}. Authored by "
        f"'{author}' ({assoc}) from '{full_name}'. Contributions from outside the team can only "
        f"merge after @{operator} has reviewed the exact head commit ({sha}) and submitted an "
        f"APPROVED review on it (docs/AI_DEVELOPER_GOVERNANCE.md). After approving, re-run this "
        f"job. Any new push voids the approval."))


def merge_group_pr_number(event):
    """The PR number named by merge_group.head_ref; GateError when it cannot be derived."""
    group = event.get("merge_group") if isinstance(event, dict) else None
    ref = group.get("head_ref") if isinstance(group, dict) else None
    match = QUEUE_REF_RE.fullmatch(ref) if isinstance(ref, str) else None
    number = int(match.group(1)) if match else 0
    if number <= 0:
        shown = ref if isinstance(ref, str) and len(ref) <= 120 else f"<{type(ref).__name__} of unusable shape>"
        raise GateError(f"merge_group head_ref {shown!r} does not name a pull request "
                        "(expected refs/heads/gh-readonly-queue/<base>/pr-<N>-<sha>, N at most 9 digits)")
    # The ref is attacker-influenced text; base_sha is GitHub's own field. GitHub names the queue
    # ref after the queue commit's PARENT, merge_group.base_sha, not after merge_group.head_sha
    # (#6325). The ref sha must be a full commit sha equal to base_sha, or the verdict is not
    # about this queue entry (#6242).
    ref_sha = match.group(2)
    base_sha = group.get("base_sha")
    if (not SHA_RE.fullmatch(ref_sha) or not isinstance(base_sha, str)
            or not SHA_RE.fullmatch(base_sha) or ref_sha != base_sha):
        raise GateError(f"merge_group head_ref sha {ref_sha[:80]!r} is not merge_group.base_sha "
                        "(the queue commit's parent)")
    return number


def run_gate(event_name, event, repo, sha, operator, api):
    """Return (exit code, output lines). Never raises on a malformed input: fails closed."""
    lines = []
    try:
        if not isinstance(repo, str) or not REPO_RE.fullmatch(repo):
            raise GateError(f"repository {repo!r} is not owner/name")
        if not isinstance(operator, str) or not operator:
            raise GateError("no operator login configured (OPERATOR_LOGIN)")
        if event_name == "pull_request":
            pr = event.get("pull_request") if isinstance(event, dict) else None
            if not isinstance(pr, dict):
                raise GateError("pull_request event has no pull_request payload")
            prs = [pr]
            lines.append("event=pull_request: judging the event's pull request")
        elif event_name == "merge_group":
            number = merge_group_pr_number(event)
            open_prs = api(f"repos/{repo}/pulls?state=open&per_page=100")
            prs = [pr for pr in open_prs if _head(pr)[0] == number]
            if len(prs) != 1:
                raise GateError(f"merge_group names PR #{number}, which is not an open pull request")
            lines.append(f"event=merge_group: judging PR #{number} named by the queue ref")
        else:
            if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
                raise GateError(f"event={event_name}: run sha {sha!r} is not a full commit sha")
            open_prs = api(f"repos/{repo}/pulls?state=open&per_page=100")
            prs = [pr for pr in open_prs if _head(pr)[1] == sha]
            lines.append(f"event={event_name}: {len(prs)} open PR(s) of {len(open_prs)} head {sha}")
            if not prs:
                lines.append("no open pull request heads this sha; nothing to approve (pass)")
                return 0, lines
        failed = False
        for pr in prs:
            passed, line = pr_verdict(pr, repo, operator, api)
            lines.append(line)
            failed = failed or not passed
        return (1 if failed else 0), lines
    except GateError as exc:
        lines.append(workflow_error(f"External-PR operator-approval gate cannot establish its verdict "
                                    f"(event={event_name}): {exc}. Failing closed."))
        return 1, lines


def self_test():
    # e is merge_group.base_sha and the sha in the queue ref; c is the queue commit (#6325).
    repo, op, a, b, c, e = "o/r", "op", "a" * 40, "b" * 40, "c" * 40, "e" * 40

    def pr(n, sha, assoc="NONE", head_repo="fork/r"):
        return {"number": n, "author_association": assoc, "user": {"login": "x"},
                "head": {"sha": sha, "repo": {"full_name": head_repo} if head_repo else None}}

    def api_for(pulls, reviews=None, fail=False):
        def api(path):
            if fail:
                raise GateError("HTTP 502")
            m = re.search(r"/pulls/(\d+)/reviews", path)
            if m:
                return (reviews or {}).get(int(m.group(1)), [])
            return pulls
        return api

    approved = {"id": 1, "user": {"login": op}, "state": "APPROVED", "commit_id": a,
                "submitted_at": "2026-10-01T00:00:00Z"}
    revoked = {"id": 2, "user": {"login": op}, "state": "CHANGES_REQUESTED", "commit_id": a,
               "submitted_at": "2026-10-02T00:00:00Z"}
    cases = [
        ("push-unapproved-external", 1, "push", a, api_for([pr(1, a)])),
        ("push-approved-external", 0, "push", a, api_for([pr(1, a)], {1: [approved]})),
        ("push-approved-then-changes-requested", 1, "push", a, api_for([pr(1, a)], {1: [revoked, approved]})),
        ("push-team-same-repo", 0, "push", a, api_for([pr(2, a, "MEMBER", repo)])),
        ("push-contributor-same-repo-unapproved", 1, "push", a, api_for([pr(2, a, "CONTRIBUTOR", repo)])),
        ("push-no-pr-heads-sha", 0, "push", a, api_for([pr(1, b)])),
        ("push-api-error", 1, "push", a, api_for([], fail=True)),
        ("merge-group-unapproved", 1, "merge_group", c, api_for([pr(1, a)])),
        ("merge-group-approved", 0, "merge_group", c, api_for([pr(1, a)], {1: [approved]})),
        ("merge-group-release-base-approved", 0, "merge_group", c, api_for([pr(1, a)], {1: [approved]})),
        ("merge-group-release-base-unapproved", 1, "merge_group", c, api_for([pr(1, a)])),
        ("merge-group-no-pr-in-ref", 1, "merge_group", c, api_for([pr(1, a)])),
        ("merge-group-ref-sha-is-head-sha-not-base-sha", 1, "merge_group", c,
         api_for([pr(1, a)], {1: [approved]})),
        ("merge-group-missing-base-sha", 1, "merge_group", c, api_for([pr(1, a)], {1: [approved]})),
    ]
    failures = 0

    def queue(base="main", ref_sha=e, base_sha=e):
        group = {"head_sha": c, "base_ref": "refs/heads/" + base,
                 "head_ref": f"refs/heads/gh-readonly-queue/{base}/pr-1-{ref_sha}"}
        if base_sha is not None:
            group["base_sha"] = base_sha
        return {"merge_group": group}

    events = {
        "merge-group-release-base-approved": queue("release/v1.0.0"),
        "merge-group-release-base-unapproved": queue("release/v1.0.0"),
        "merge-group-no-pr-in-ref": {},
        "merge-group-ref-sha-is-head-sha-not-base-sha": queue(ref_sha=c),
        "merge-group-missing-base-sha": queue(base_sha=None),
    }
    for name, want, event_name, sha, api in cases:
        event = events.get(name, queue() if event_name == "merge_group" else {})
        rc, _lines = run_gate(event_name, event, repo, sha, op, api)
        ok = rc == want
        failures += 0 if ok else 1
        print(f"self-test {'PASS' if ok else 'FAIL'}: {name} (exit {rc}, want {want})")
    for bad in ("", "x", '{"message": "Bad credentials"}', "[1] trailing"):
        try:
            parse_pages(bad)
        except GateError:
            print(f"self-test PASS: parse_pages refuses {bad!r}")
            continue
        failures += 1
        print(f"self-test FAIL: parse_pages accepted {bad!r}")
    print(f"external-pr-approval self-test: {'0 failed' if not failures else str(failures) + ' failed'}")
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    event = {}
    path = os.environ.get("GITHUB_EVENT_PATH", "")
    if event_name in ("pull_request", "merge_group"):
        try:
            with open(path, encoding="utf-8") as fh:
                event = json.load(fh)
        except (OSError, ValueError) as exc:
            print(workflow_error(f"cannot read the {event_name} event payload ({exc}); failing closed"))
            return 1
    rc, lines = run_gate(event_name, event, os.environ.get("GITHUB_REPOSITORY", ""),
                         os.environ.get("GITHUB_SHA", ""),
                         os.environ.get("OPERATOR_LOGIN", ""), gh_api)
    for line in lines:
        print(line)
    return rc


if __name__ == "__main__":
    sys.exit(main())
