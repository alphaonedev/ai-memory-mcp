#!/usr/bin/env python3
"""ci-commit-range.py - choose the commit range a CI gate checks (#5579).

Closed-world and fail-closed: the range is derived only from the GitHub event
that triggered the run, and anything that cannot be decided is refused. There
is no fallback range (the old "HEAD~1..HEAD" fallback checked a single commit
and silently skipped the rest of a multi-commit push; it is removed).

Inputs (a flag overrides the environment variable of the same role):

    --event NAME      GITHUB_EVENT_NAME    pull_request | merge_group | push
    --head-sha SHA    GITHUB_SHA           push: the new tip
    --before SHA      GITHUB_EVENT_BEFORE  push: the previous tip
    --pr-base SHA     PR_BASE_SHA          pull_request: base.sha
    --pr-head SHA     PR_HEAD_SHA          pull_request: head.sha
    --mg-base SHA     MG_BASE_SHA          merge_group: base_sha
    --mg-head SHA     MG_HEAD_SHA          merge_group: head_sha
    --repo DIR        repository to resolve against (default: cwd)
    --base-only       print only the base side of the range (#5604): the one
                      older commit a gate compares a file against

Rules:

    pull_request  merge-base(base, head)..head
    merge_group   base_sha..head_sha
    push          before..head, only when before is a full non-zero sha that
                  resolves to a commit in this repository
    anything else refuse

A refusal for a push whose previous tip is missing, all-zero or not in this
checkout names its cause (the creation push or force-push of a protected branch
has no comparable previous tip) and says the next ordinary push produces a
comparable range; a refused run is red and a re-run cannot turn it green
(#5603, #5604). A merge_group refusal for a missing base_sha says the same.

Every sha must be exactly 40 lowercase hex characters, must not be all zeros
and must resolve to a commit here before it reaches git as an argument (git is
always called with an argument list, never a shell).

Output: one line "A..B" (or just "A" with --base-only) on stdout and exit 0, or one "ci-commit-range: REFUSED"
line on stderr and exit 1. Usage errors exit 2. A failed --self-test exits 3.

    python3 scripts/ci-commit-range.py --self-test
    python3 scripts/ci-commit-range.py --red-proof   # old YAML block vs fixtures
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

EVENTS = ("pull_request", "merge_group", "push")
SHA_RE = re.compile(r"[0-9a-f]{40}")
ZERO_SHA = "0" * 40
WORKFLOW = Path(".github/workflows/c8-precheck.yml")
# The two jobs that call the helper in the workflow, and the two jobs whose
# SCRIPT calls it (the workflow only passes the event inputs to the script).
SCRIPT_GATE_JOBS = {"cert-expiry-gate": "check-cert-expiry.sh"}
GATE_JOBS = ("stale-contract-assertions-gate", "count-assertion-declared-gate",
             "cert-expiry-gate")
# The only expressions a script-gate step may use: each one exactly once.
SCRIPT_GATE_ENV = (
    "GITHUB_EVENT_NAME: ${{ github.event_name }}",
    "GITHUB_EVENT_BEFORE: ${{ github.event.before }}",
    "PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}",
    "PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
    "MG_BASE_SHA: ${{ github.event.merge_group.base_sha }}",
    "MG_HEAD_SHA: ${{ github.event.merge_group.head_sha }}",
)
HELPER_NAME = "ci-commit-range.py"
LAYER_ATTEMPTS = [0]
CALL = 'range="$(python3 scripts/ci-commit-range.py)"'


NEXT_PUSH = ("; the next ordinary push produces a comparable range "
             "(this run is red and a re-run cannot turn it green)")
PUSH_CAUSE = (" (a creation push or a force-push of a protected branch has no "
              "comparable previous tip)")
MG_CAUSE = " (the merge_group event carries no usable base_sha)"


class Refused(Exception):
    """The range cannot be decided; the message says why.

    kind is "absent" (missing, empty, all-zero), "unresolved" (a well-formed sha
    that is not a commit here) or "malformed"; callers add a cause text to the
    first two only.
    """

    def __init__(self, message, kind="malformed"):
        Exception.__init__(self, message)
        self.kind = kind


def git(repo, *args):
    """Run git with an argument list; return (returncode, stdout)."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1")
    proc = subprocess.run(
        ["git", "-C", str(repo)] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        universal_newlines=True,
        env=env,
    )
    return proc.returncode, proc.stdout.strip()


def checked_sha(repo, role, value):
    """Return value when it is a strict, non-zero sha naming a local commit."""
    if value is None or value == "":
        raise Refused("%s is missing or empty" % role, "absent")
    if SHA_RE.fullmatch(value) is None:
        raise Refused("%s is not a full 40-char lowercase hex sha" % role)
    if value == ZERO_SHA:
        raise Refused("%s is the all-zero sha" % role, "absent")
    code, out = git(repo, "rev-parse", "--verify", "--quiet", value + "^{commit}")
    if code != 0 or out != value:
        raise Refused("%s %s does not resolve to a commit here" % (role, value), "unresolved")
    return value


def with_cause(check, cause, repo, role, value):
    """Run a sha check; name the cause on an absent or unresolved sha (D6)."""
    try:
        return check(repo, role, value)
    except Refused as exc:
        if exc.kind in ("absent", "unresolved"):
            raise Refused("%s%s%s" % (exc, cause, NEXT_PUSH), exc.kind)
        raise


def choose(repo, event, head, before, pr_base, pr_head, mg_base, mg_head):
    """Return the range for one event, or raise Refused."""
    if event not in EVENTS:
        raise Refused("event %r is not one of %s" % (event, ", ".join(EVENTS)))
    if event == "pull_request":
        base = checked_sha(repo, "pull_request base sha", pr_base)
        tip = checked_sha(repo, "pull_request head sha", pr_head)
        code, out = git(repo, "merge-base", base, tip)
        if code != 0 or SHA_RE.fullmatch(out) is None:
            raise Refused("no merge-base between the pull_request base and head")
        return "%s..%s" % (out, tip)
    if event == "merge_group":
        base = with_cause(checked_sha, MG_CAUSE, repo, "merge_group base_sha", mg_base)
        tip = checked_sha(repo, "merge_group head_sha", mg_head)
        return "%s..%s" % (base, tip)
    prev = with_cause(checked_sha, PUSH_CAUSE, repo, "push before sha", before)
    tip = checked_sha(repo, "push head sha", head)
    return "%s..%s" % (prev, tip)


def base_of(rng):
    """The base side of an "A..B" range (the one older commit to compare with)."""
    left = rng.split("..", 1)[0]
    if SHA_RE.fullmatch(left) is None:
        raise Refused("internal: range %r has no 40-char base" % rng)
    return left


def env_or(value, name):
    """A flag wins; otherwise the environment variable (None when unset)."""
    return value if value is not None else os.environ.get(name)


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

# Frozen copy of the pre-fix step body (c8-precheck.yml at 3371b37f), kept so
# the red-first evidence can be re-run against the same fixtures.
OLD_BLOCK = r"""set -euo pipefail
if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
  base="$(git merge-base "$PR_BASE_SHA" "$PR_HEAD_SHA")"
  range="$base..$PR_HEAD_SHA"
elif [ -n "${GITHUB_EVENT_BEFORE:-}" ] && [ "$GITHUB_EVENT_BEFORE" != "0000000000000000000000000000000000000000" ] \
     && git rev-parse --verify --quiet "$GITHUB_EVENT_BEFORE^{commit}" >/dev/null; then
  range="$GITHUB_EVENT_BEFORE..$GITHUB_SHA"
else
  range="HEAD~1..HEAD"
fi
echo "$range"
"""


def run_git(repo, *args):
    """Run git inside a fixture repo, fail loudly on error."""
    proc = subprocess.run(
        ["git", "-C", str(repo)] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if proc.returncode != 0:
        raise RuntimeError("git %s failed: %s" % (" ".join(args), proc.stderr))
    return proc.stdout.strip()


def build_fixture(root):
    """Return (repo, shas): main c1..c3, a branch off c1 (b1), a shallow clone."""
    repo = root / "repo"
    repo.mkdir()
    run_git(repo, "init", "-q", "-b", "main")
    for key, val in (("user.name", "t"), ("user.email", "t@example.invalid"),
                     ("commit.gpgsign", "false")):
        run_git(repo, "config", key, val)
    shas = {}
    for name in ("c1", "c2", "c3"):
        (repo / (name + ".txt")).write_text(name)
        run_git(repo, "add", name + ".txt")
        run_git(repo, "commit", "-q", "-m", name)
        shas[name] = run_git(repo, "rev-parse", "HEAD")
    run_git(repo, "checkout", "-q", "-b", "feat", shas["c1"])
    (repo / "b1.txt").write_text("b1")
    run_git(repo, "add", "b1.txt")
    run_git(repo, "commit", "-q", "-m", "b1")
    shas["b1"] = run_git(repo, "rev-parse", "HEAD")
    run_git(repo, "checkout", "-q", "main")
    # A sha that is syntactically fine but absent from the repo.
    shas["ghost"] = "ab" * 20
    # Objects that exist but are not commits.
    shas["tree"] = run_git(repo, "rev-parse", "main^{tree}")
    shas["blob"] = run_git(repo, "rev-parse", "main:c1.txt")
    shallow = root / "shallow"
    proc = subprocess.run(
        ["git", "clone", "-q", "--depth", "1", "file://" + str(repo), str(shallow)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if proc.returncode != 0:
        raise RuntimeError("shallow clone failed: " + proc.stderr)
    return repo, shallow, shas


def cases(shas):
    """(label, event, kwargs, expected) ; expected None = refusal, str = range."""
    c1, c2, c3, b1 = shas["c1"], shas["c2"], shas["c3"], shas["b1"]
    ghost = shas["ghost"]
    out = []

    def case(label, event, expected, **kw):
        out.append((label, event, kw, expected))

    case("push normal", "push", "%s..%s" % (c1, c3), before=c1, head=c3)
    case("push empty range (before == head)", "push", "%s..%s" % (c3, c3), before=c3, head=c3)
    case("push all-zero before", "push", None, before=ZERO_SHA, head=c3)
    case("push unreachable before", "push", None, before=ghost, head=c3)
    case("push missing before", "push", None, head=c3)
    case("push empty before", "push", None, before="", head=c3)
    case("push short before", "push", None, before=c1[:12], head=c3)
    case("push abbreviated 39 chars", "push", None, before=c1[:39], head=c3)
    case("push 41 chars", "push", None, before=c1 + "a", head=c3)
    case("push uppercase before", "push", None, before=c1.upper(), head=c3)
    case("push leading-dash before", "push", None, before="-" + c1[1:], head=c3)
    case("push option-looking before", "push", None, before="--output=x", head=c3)
    case("push whitespace before", "push", None, before=c1 + " ", head=c3)
    case("push leading whitespace before", "push", None, before=" " + c1, head=c3)
    case("push trailing newline before", "push", None, before=c1 + "\n", head=c3)
    case("push embedded newline before", "push", None, before=c1[:20] + "\n" + c1[21:], head=c3)
    case("push ref name before", "push", None, before="HEAD", head=c3)
    case("push range-syntax before", "push", None, before=c1 + "..", head=c3)
    case("push non-hex 40 chars", "push", None, before="g" * 40, head=c3)
    case("push missing head", "push", None, before=c1)
    case("push zero head", "push", None, before=c1, head=ZERO_SHA)
    case("push unreachable head", "push", None, before=c1, head=ghost)
    case("push head malformed", "push", None, before=c1, head="HEAD")
    case("push before is a tree", "push", None, before=shas["tree"], head=c3)
    case("push before is a blob", "push", None, before=shas["blob"], head=c3)
    case("push head is a tree", "push", None, before=c1, head=shas["tree"])
    case("merge_group base is a tree", "merge_group", None, mg_base=shas["tree"], mg_head=c3)
    case("merge_group head is a blob", "merge_group", None, mg_base=c1, mg_head=shas["blob"])
    case("pull_request base is a tree", "pull_request", None, pr_base=shas["tree"], pr_head=b1)
    case("pull_request head is a blob", "pull_request", None, pr_base=c3, pr_head=shas["blob"])
    case("push ignores merge_group/pr inputs", "push", "%s..%s" % (c1, c3),
         before=c1, head=c3, mg_base=ghost, pr_base=ghost)
    case("merge_group good", "merge_group", "%s..%s" % (c1, c3), mg_base=c1, mg_head=c3)
    case("merge_group missing base", "merge_group", None, mg_head=c3)
    case("merge_group empty base", "merge_group", None, mg_base="", mg_head=c3)
    case("merge_group zero base", "merge_group", None, mg_base=ZERO_SHA, mg_head=c3)
    case("merge_group unreachable base", "merge_group", None, mg_base=ghost, mg_head=c3)
    case("merge_group malformed base", "merge_group", None, mg_base="main", mg_head=c3)
    case("merge_group uppercase base", "merge_group", None, mg_base=c1.upper(), mg_head=c3)
    case("merge_group dash base", "merge_group", None, mg_base="-" + c1[1:], mg_head=c3)
    case("merge_group missing head", "merge_group", None, mg_base=c1)
    case("merge_group zero head", "merge_group", None, mg_base=c1, mg_head=ZERO_SHA)
    case("merge_group unreachable head", "merge_group", None, mg_base=c1, mg_head=ghost)
    case("merge_group does not fall back to before", "merge_group", None,
         before=c1, head=c3, mg_head=c3)
    case("merge_group does not fall back to push head", "merge_group", None,
         head=c3, mg_base=c1)
    case("pull_request good (merge-base)", "pull_request", "%s..%s" % (c1, b1),
         pr_base=c3, pr_head=b1)
    case("pull_request base is ancestor", "pull_request", "%s..%s" % (c1, c3),
         pr_base=c1, pr_head=c3)
    case("pull_request unreachable base", "pull_request", None, pr_base=ghost, pr_head=b1)
    case("pull_request unreachable head", "pull_request", None, pr_base=c3, pr_head=ghost)
    case("pull_request missing base", "pull_request", None, pr_head=b1)
    case("pull_request missing head", "pull_request", None, pr_base=c3)
    case("pull_request zero base", "pull_request", None, pr_base=ZERO_SHA, pr_head=b1)
    case("pull_request malformed base", "pull_request", None, pr_base="origin/main", pr_head=b1)
    case("pull_request uppercase head", "pull_request", None, pr_base=c3, pr_head=b1.upper())
    case("pull_request dash head", "pull_request", None, pr_base=c3, pr_head="-" + b1[1:])
    case("pull_request does not fall back to before", "pull_request", None,
         before=c1, head=c3)
    for name in ("workflow_dispatch", "schedule", "pull_request_target", "release",
                 "", "PUSH", "Push", "push ", " push", "pull_request\n", "merge_group2",
                 "-push", "push;id"):
        case("unknown event %r" % name, name, None, before=c1, head=c3,
             pr_base=c3, pr_head=b1, mg_base=c1, mg_head=c3)
    return out


def invoke(repo, event, kw):
    """Run the CLI as a subprocess with the inputs in the environment."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("GITHUB_EVENT_NAME", "GITHUB_EVENT_BEFORE", "GITHUB_SHA",
                        "PR_BASE_SHA", "PR_HEAD_SHA", "MG_BASE_SHA", "MG_HEAD_SHA")}
    mapping = {"before": "GITHUB_EVENT_BEFORE", "head": "GITHUB_SHA",
               "pr_base": "PR_BASE_SHA", "pr_head": "PR_HEAD_SHA",
               "mg_base": "MG_BASE_SHA", "mg_head": "MG_HEAD_SHA"}
    env["GITHUB_EVENT_NAME"] = event
    for key, value in kw.items():
        env[mapping[key]] = value
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "--repo", str(repo)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=env)
    return proc.returncode, proc.stdout, proc.stderr


def job_block(text, job):
    """Return the text of one top-level job of the workflow, or None."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line == "  %s:" % job:
            start = i
            break
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if re.match(r"  [A-Za-z0-9_-]+:", lines[j]) or re.match(r"[A-Za-z]", lines[j]):
            end = j
            break
    return "\n".join(lines[start:end])


FORBIDDEN_IN_RANGE_STEP = ("HEAD~1", "merge-base", "GITHUB_EVENT_BEFORE", "rev-parse",
                           "elif", "else", "if [", "0000000000")


def step_run_body(block):
    """The run body of the step that obtains the range (the one with CALL)."""
    steps = re.split(r"\n      - ", block)
    picked = [s for s in steps if "range=" in s]
    return picked


def script_gate_violations(job, block):
    """Pin for a job whose script calls the helper (#5603, #5604): closed-world."""
    problems = []
    script = SCRIPT_GATE_JOBS[job]
    run_line = "        run: bash scripts/%s" % script
    steps = [st for st in re.split(r"\n      - ", block)
             if re.search(r"(?m)^%s$" % re.escape(run_line), st)]
    if len(steps) != 1:
        return ["%s: expected exactly one step running %s, found %d" % (job, script, len(steps))]
    step = steps[0]
    if len(re.findall(r"(?m)^          fetch-depth: 0$", block)) != 1:
        problems.append("%s: checkout lacks fetch-depth: 0" % job)
    for line in SCRIPT_GATE_ENV:
        if step.count(line) != 1:
            problems.append("%s: the step must pass %r exactly once" % (job, line))
    exprs = re.findall(r"\$\{\{.*?\}\}", step)
    allowed = [line.split(": ", 1)[1] for line in SCRIPT_GATE_ENV]
    for expr in exprs:
        if expr not in allowed:
            problems.append("%s: expression %s is not an allowed event input" % (job, expr))
    keys = re.findall(r"(?m)^          ([A-Za-z_]+):", step)
    if sorted(keys) != sorted(line.split(":", 1)[0] for line in SCRIPT_GATE_ENV):
        problems.append("%s: env keys are %s, expected exactly the six event inputs" % (job, sorted(keys)))
    for bad in ("||", "&&", "HEAD~", "CERT_EXPIRY_", "DECLARATION_GATE_", "N/A"):
        if bad in step:
            problems.append("%s: the step contains %r" % (job, bad))
    if re.search(r"HEAD(?!_SHA)", step):
        problems.append("%s: the step names HEAD (no default base)" % job)
    return problems


def pin_violations(text):
    """Static pin: every gate job takes its range only from the helper. Returns problems."""
    problems = []
    if "HEAD~1" in text:
        problems.append("HEAD~1 appears in the workflow")
    for job in GATE_JOBS:
        block = job_block(text, job)
        if block is None:
            problems.append("%s: job not found" % job)
            continue
        if job in SCRIPT_GATE_JOBS:
            problems.extend(script_gate_violations(job, block))
            continue
        steps = step_run_body(block)
        if len(steps) != 1:
            problems.append("%s: expected exactly one step assigning range, found %d"
                            % (job, len(steps)))
            continue
        body = steps[0]
        if body.count(CALL) != 1:
            problems.append("%s: the range step does not contain exactly one helper call" % job)
        if len(re.findall(r"(?m)^\s*range=", body)) != 1:
            problems.append("%s: range is assigned other than once" % job)
        run_part = body.split("        run: |", 1)[-1] if "        run: |" in body else None
        if run_part is None:
            problems.append("%s: range step has no run: | body" % job)
            continue
        for bad in FORBIDDEN_IN_RANGE_STEP:
            if bad in run_part:
                problems.append("%s: range step still contains %r" % (job, bad))
        for needed, why in (("MG_BASE_SHA: ${{ github.event.merge_group.base_sha }}", "merge_group base"),
                            ("MG_HEAD_SHA: ${{ github.event.merge_group.head_sha }}", "merge_group head"),
                            ("GITHUB_EVENT_BEFORE: ${{ github.event.before }}", "push before"),
                            ("PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}", "pr base"),
                            ("PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}", "pr head"),
                            ("GITHUB_EVENT_NAME: ${{ github.event_name }}", "event name")):
            if needed not in body:
                problems.append("%s: the range step does not pass %s" % (job, why))
        if "set -euo pipefail" not in run_part:
            problems.append("%s: range step lacks set -euo pipefail" % job)
    return problems


SCRIPT_PINS = {
    "check-cert-expiry.sh": {
        "need": (HELPER_NAME,),
        "forbid": ("ZERO_SHA_RE", "return 3", "rc == 3", "N/A", "workflow_dispatch)", "rc=3"),
        "regex": (r"\$\{?GITHUB_EVENT_BEFORE",),
    },
}


def script_text_violations(name, text):
    """Static pin on a gate script: no event-before read, no default base, no skip."""
    problems = []
    pins = SCRIPT_PINS[name]
    for needed in pins["need"]:
        if needed not in text:
            problems.append("%s: does not call %s" % (name, needed))
    for bad in pins["forbid"]:
        if bad in text:
            problems.append("%s: contains %r" % (name, bad))
    for pattern in pins["regex"]:
        if re.search(pattern, text):
            problems.append("%s: matches %s" % (name, pattern))
    return problems


def layer_tests():
    """Each validation layer must refuse on its own (git stubbed to accept)."""
    failures = 0
    good = "c" * 40
    real = globals()["git"]

    ran = [0]

    def attempt(stub, call):
        ran[0] += 1
        globals()["git"] = stub
        try:
            call()
        except Refused:
            return "refused"
        except Exception as exc:  # any other failure is a defect, not a refusal
            return "crash:%r" % (exc,)
        finally:
            globals()["git"] = real
        return "accepted"

    accept_all = lambda repo, *args: (0, args[-1][:-len("^{commit}")] if args[-1].endswith("^{commit}") else "c" * 40)
    shape_only = [None, "", good[:39], good + "a", good.upper(), "-" + good[1:], good + " ",
                  " " + good, good + "\n", "HEAD", "main", "g" * 40, ZERO_SHA, good + "..", "--output=x"]
    for bad in shape_only:
        got = attempt(accept_all, lambda b=bad: checked_sha(".", "x", b))
        if got != "refused":
            failures += 1
            print("FAIL shape layer alone accepted/crashed on %r: %s" % (bad, got))
    if attempt(accept_all, lambda: checked_sha(".", "x", good)) != "accepted":
        failures += 1
        print("FAIL stubbed git: a valid sha was refused")
    for label, stub in (("git says missing", lambda repo, *a: (1, "")),
                        ("git echoes a different sha", lambda repo, *a: (0, "d" * 40)),
                        ("git ok but empty", lambda repo, *a: (0, ""))):
        got = attempt(stub, lambda: checked_sha(".", "x", good))
        if got != "refused":
            failures += 1
            print("FAIL resolve layer alone: %s -> %s" % (label, got))

    def mb(code, out):
        def stub(repo, *a):
            if a[0] == "merge-base":
                return code, out
            return 0, a[-1][:-len("^{commit}")]
        return stub

    for label, code, out in (("merge-base fails", 1, ""), ("merge-base garbage", 0, "garbage"),
                             ("merge-base empty", 0, ""), ("merge-base short", 0, "abc")):
        got = attempt(mb(code, out), lambda: choose(".", "pull_request", None, None, good, "e" * 40, None, None))
        if got != "refused":
            failures += 1
            print("FAIL merge-base layer: %s -> %s" % (label, got))
    got = attempt(mb(0, "f" * 40), lambda: choose(".", "pull_request", None, None, good, "e" * 40, None, None))
    if got != "accepted":
        failures += 1
        print("FAIL merge-base layer: a valid merge-base was refused: " + got)
    LAYER_ATTEMPTS[0] = ran[0]
    return failures


def self_test():
    """Run every fixture case; return the number of failures."""
    failures = 0
    base_tmp = Path(os.environ.get("TMPDIR") or ".local-runs").resolve()
    base_tmp.mkdir(parents=True, exist_ok=True)
    total = 0
    with tempfile.TemporaryDirectory(prefix="ci-commit-range-", dir=str(base_tmp)) as tmp:
        repo, shallow, shas = build_fixture(Path(tmp))
        for label, event, kw, expected in cases(shas):
            total += 1
            code, out, err = invoke(repo, event, kw)
            if expected is None:
                good = code == 1 and out == "" and "REFUSED" in err
            else:
                good = code == 0 and out == expected + "\n" and err == ""
            if not good:
                failures += 1
                print("FAIL %s: exit=%s out=%r err=%r want=%r" % (label, code, out, err, expected))
        # Shallow clone: the previous tip is not present, so a push must refuse.
        total += 1
        code, out, err = invoke(shallow, "push", {"before": shas["c1"], "head": run_git(shallow, "rev-parse", "HEAD")})
        if not (code == 1 and out == "" and "REFUSED" in err):
            failures += 1
            print("FAIL shallow clone push: exit=%s out=%r err=%r" % (code, out, err))
        total += 1
        code, out, err = invoke(shallow, "merge_group", {"mg_base": shas["c1"], "mg_head": run_git(shallow, "rev-parse", "HEAD")})
        if not (code == 1 and out == "" and "REFUSED" in err):
            failures += 1
            print("FAIL shallow clone merge_group: exit=%s out=%r err=%r" % (code, out, err))
        # Argument flags override the environment.
        total += 1
        code, out, err = invoke(repo, "push", {"before": shas["ghost"], "head": shas["c3"]})
        proc = subprocess.run(
            [sys.executable, os.path.abspath(__file__), "--repo", str(repo), "--event", "push",
             "--before", shas["c1"], "--head-sha", shas["c3"]],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
            env=dict(os.environ, GITHUB_EVENT_BEFORE=shas["ghost"]))
        if not (code == 1 and proc.returncode == 0
                and proc.stdout == "%s..%s\n" % (shas["c1"], shas["c3"])):
            failures += 1
            print("FAIL flag override: %r %r" % (proc.returncode, proc.stdout))
        # D6: a refusal names its cause and says what produces a comparable range.
        c1, c3 = shas["c1"], shas["c3"]
        for label, event, kw, words in (
                ("push all-zero before", "push", {"before": ZERO_SHA, "head": c3},
                 ("creation push", "force-push", "no comparable previous tip",
                  "next ordinary push", "cannot turn it green")),
                ("push empty before", "push", {"before": "", "head": c3},
                 ("creation push", "next ordinary push")),
                ("push unreachable before", "push", {"before": shas["ghost"], "head": c3},
                 ("force-push", "next ordinary push")),
                ("merge_group missing base", "merge_group", {"mg_head": c3},
                 ("merge_group base_sha", "next ordinary push")),
                ("merge_group empty base", "merge_group", {"mg_base": "", "mg_head": c3},
                 ("merge_group", "next ordinary push"))):
            total += 1
            code, out, err = invoke(repo, event, kw)
            missing = [w for w in words if w not in err]
            if code != 1 or out != "" or missing:
                failures += 1
                print("FAIL refusal text %s: exit=%s missing=%s err=%r" % (label, code, missing, err))
        # A malformed value is not a creation push: no misleading cause text.
        total += 1
        code, out, err = invoke(repo, "push", {"before": c1[:39], "head": c3})
        if code != 1 or "creation push" in err:
            failures += 1
            print("FAIL malformed before must not claim a creation push: %r" % err)
        # Frozen old block: the cases whose answer changed are accepted by it.
        # (Covered by --red-proof; the self-test only needs the new behaviour.)
    total += 1
    failures += layer_tests()
    total += 1
    if LAYER_ATTEMPTS[0] < 24:
        failures += 1
        print("FAIL only %d layer attempts ran (expected at least 24)" % LAYER_ATTEMPTS[0])
    # Static pin against the workflow itself, plus mutation of that text.
    wf = WORKFLOW if WORKFLOW.exists() else Path(__file__).resolve().parent.parent / WORKFLOW
    text = wf.read_text()
    total += 1
    problems = pin_violations(text)
    if problems:
        failures += 1
        print("FAIL workflow pin: " + "; ".join(problems))
    # Mutants are only meaningful against a clean pin (the anchors exist).
    muts = [] if problems else pin_mutations(text)
    total += 1
    if problems:
        muts = [("pin is not clean; no mutants generated", text)] * 15
    if len(muts) < 15:
        failures += 1
        print("FAIL only %d pin mutants generated (expected at least 15)" % len(muts))
    checked = 0
    for label, mutate in muts:
        total += 1
        checked += 1
        if not pin_violations(mutate):
            failures += 1
            print("FAIL pin mutant not detected: " + label)
    if checked != len(muts):
        failures += 1
        print("FAIL checked %d of %d pin mutants" % (checked, len(muts)))
    # Static pin on the gate scripts themselves, with text mutants.
    scripts_dir = Path(__file__).resolve().parent
    for name in SCRIPT_PINS:
        stext = (scripts_dir / name).read_text()
        total += 1
        bad = script_text_violations(name, stext)
        if bad:
            failures += 1
            print("FAIL script pin %s: %s" % (name, "; ".join(bad)))
        smuts = script_mutations(name, stext)
        total += 1
        if len(smuts) < 5:
            failures += 1
            print("FAIL only %d script mutants for %s" % (len(smuts), name))
        for label, mutate in smuts:
            total += 1
            if not script_text_violations(name, mutate):
                failures += 1
                print("FAIL script mutant not detected (%s): %s" % (name, label))
    print("ci-commit-range self-test: %d cases, %d failed" % (total, failures))
    return failures


def pin_mutations(text):
    """Text mutants of the workflow that the static pin must each reject."""
    out = []
    first = text.index(CALL)
    second = text.index(CALL, first + 1)
    out.append(("helper call removed from first gate", text.replace(CALL, 'range="x"', 1)))
    out.append(("HEAD~1 fallback restored", text.replace(
        CALL, CALL + '\n          [ -n "$range" ] || range="HEAD~1..HEAD"', 1)))
    out.append(("inline merge-base restored", text.replace(
        CALL, 'base="$(git merge-base "$PR_BASE_SHA" "$PR_HEAD_SHA")"\n          ' + CALL, 1)))
    out.append(("helper call removed from second gate", text[:second] + 'range="x"' + text[second + len(CALL):]))
    out.append(("second call duplicated", text[:second] + CALL + "\n          " + text[second:]))
    out.append(("MG_BASE_SHA env dropped", text.replace(
        "MG_BASE_SHA: ${{ github.event.merge_group.base_sha }}", "MG_UNUSED: x")))
    out.append(("MG_HEAD_SHA env dropped from one", text.replace(
        "MG_HEAD_SHA: ${{ github.event.merge_group.head_sha }}", "MG_UNUSED: x", 1)))
    ev = "GITHUB_EVENT_NAME: ${{ github.event_name }}"
    for label, pos in (("first", text.rindex(ev, 0, first)), ("second", text.rindex(ev, 0, second))):
        out.append(("event name env dropped from %s gate" % label,
                    text[:pos] + "X_EVENT: x" + text[pos + len(ev):]))
    for label, pos in (("first", text.rindex("set -euo pipefail", 0, first)),
                       ("second", text.rindex("set -euo pipefail", 0, second))):
        out.append(("set -e dropped from %s gate" % label,
                    text[:pos] + "set -u" + text[pos + len("set -euo pipefail"):]))
    out.append(("HEAD~1 elsewhere in the workflow", "# HEAD~1 note\n" + text))
    out.append(("range reassigned in the step", text.replace(CALL, CALL + '\n          range="$range"', 1)))
    selftest_step = "\n      - name: Self-test the gate (regression evidence)"
    out.append(("second range step added to first gate", text[:text.index(selftest_step, first)]
                + '\n      - name: extra\n        run: range="z"' + text[text.index(selftest_step, first):]))
    out.append(("second range step added to second gate", text[:text.index(selftest_step, second)]
                + '\n      - name: extra\n        run: range="z"' + text[text.index(selftest_step, second):]))
    out.append(("GITHUB_EVENT_BEFORE read in the step", text.replace(
        CALL, CALL + '\n          echo "$GITHUB_EVENT_BEFORE"', 1)))
    out.append(("elif branch added", text.replace(CALL, CALL + "\n          elif true", 1)))
    out.append(("else branch added", text.replace(CALL, CALL + "\n          else", 1)))
    out.append(("job renamed away", text.replace(
        "  count-assertion-declared-gate:", "  count-assertion-declared-gate-x:", 1)))
    for job, script in SCRIPT_GATE_JOBS.items():
        out.extend(script_job_mutations(text, job, script))
    return out


def in_job(text, job, old, new, count=1):
    """Replace old by new inside one job block only; the mutant must differ."""
    block = job_block(text, job)
    if block is None or old not in block:
        raise RuntimeError("mutation anchor %r missing in %s" % (old, job))
    return text.replace(block, block.replace(old, new, count), 1)


def script_job_mutations(text, job, script):
    """Mutants of a script-gate job: inlined before, added base env, dropped inputs."""
    out = []
    env_anchor = "          GITHUB_EVENT_NAME: ${{ github.event_name }}\n"
    run_anchor = "        run: bash scripts/%s\n" % script
    for label, key in (("CERT_EXPIRY_BASE", "CERT_EXPIRY_BASE"), ("DECLARATION_GATE_BASE", "DECLARATION_GATE_BASE"),
                       ("CERT_EXPIRY_HEAD", "CERT_EXPIRY_HEAD"), ("DECLARATION_GATE_PREVIOUS_PIN", "DECLARATION_GATE_PREVIOUS_PIN")):
        out.append(("%s: %s override added" % (job, label),
                    in_job(text, job, env_anchor, env_anchor + "          %s: x\n" % key)))
    out.append(("%s: inlined github.event.before with a default" % job,
                in_job(text, job, env_anchor, env_anchor + "          X_BASE: ${{ github.event.pull_request.base.sha || github.event.before }}\n")))
    out.append(("%s: HEAD default env added" % job,
                in_job(text, job, env_anchor, env_anchor + "          X_BASE: HEAD\n")))
    out.append(("%s: HEAD~1 env added" % job,
                in_job(text, job, env_anchor, env_anchor + "          X_BASE: HEAD~1\n")))
    out.append(("%s: event.before wrapped in a fallback" % job,
                in_job(text, job, "${{ github.event.before }}", "${{ github.event.before || 'x' }}")))
    out.append(("%s: extra event input" % job,
                in_job(text, job, env_anchor, env_anchor + "          X_REF: ${{ github.ref }}\n")))
    for line in SCRIPT_GATE_ENV:
        out.append(("%s: %s dropped" % (job, line.split(":", 1)[0]),
                    in_job(text, job, "          " + line + "\n", "")))
    out.append(("%s: fetch-depth dropped" % job, in_job(text, job, "          fetch-depth: 0\n", "          fetch-depth: 1\n")))
    out.append(("%s: script call guarded by || true" % job,
                in_job(text, job, run_anchor, run_anchor.rstrip("\n") + " || true\n")))
    out.append(("%s: script call guarded by an if" % job,
                in_job(text, job, run_anchor, "        run: |\n          if [ \"$GITHUB_EVENT_NAME\" = pull_request ]; then bash scripts/%s; fi\n" % script)))
    out.append(("%s: job renamed away" % job,
                text.replace("  %s:\n" % job, "  %s-x:\n" % job, 1)))
    return out


def script_mutations(name, text):
    """Text mutants of a gate script that the static script pin must reject."""
    out = [("helper call removed", text.replace(HELPER_NAME, "helper-removed.py")),
           ("N/A skip text restored", text + "\n# echo 'N/A skip'\n")]
    if name == "check-cert-expiry.sh":
        out += [("zero-sha regex restored", text + "\nZERO_SHA_RE='^0+$'\n"),
                ("return 3 skip restored", text + "\n# return 3\n"),
                ("event before read in the script", text + '\nbefore="${GITHUB_EVENT_BEFORE:-}"\n'),
                ("workflow_dispatch skip arm restored", text + "\n        workflow_dispatch)\n")]
    return out


def red_proof():
    """Run the frozen pre-fix block against the same fixtures; list divergences."""
    base_tmp = Path(os.environ.get("TMPDIR") or ".local-runs").resolve()
    base_tmp.mkdir(parents=True, exist_ok=True)
    diverged = 0
    with tempfile.TemporaryDirectory(prefix="ci-commit-range-red-", dir=str(base_tmp)) as tmp:
        repo, _shallow, shas = build_fixture(Path(tmp))
        for label, event, kw, expected in cases(shas):
            if event not in ("push", "pull_request", "merge_group"):
                env_event = event
            else:
                env_event = event
            env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "PR_", "MG_"))}
            env.update({"GITHUB_EVENT_NAME": env_event,
                        "GITHUB_EVENT_BEFORE": kw.get("before", ""),
                        "GITHUB_SHA": kw.get("head", ""),
                        "PR_BASE_SHA": kw.get("pr_base", ""),
                        "PR_HEAD_SHA": kw.get("pr_head", "")})
            proc = subprocess.run(["bash", "-c", OLD_BLOCK], cwd=str(repo), env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  universal_newlines=True)
            old = proc.stdout.strip() if proc.returncode == 0 else None
            new = expected
            if old != new:
                diverged += 1
                print("RED(old!=new) %-50s old=%s new=%s" % (label, old, new))
    print("red-proof: %d cases where the frozen pre-fix block differs from the required result" % diverged)
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description="Choose the commit range for a CI gate (fail-closed).")
    ap.add_argument("--event")
    ap.add_argument("--head-sha")
    ap.add_argument("--before")
    ap.add_argument("--pr-base")
    ap.add_argument("--pr-head")
    ap.add_argument("--mg-base")
    ap.add_argument("--mg-head")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--base-only", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--red-proof", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return 3 if self_test() else 0
    if args.red_proof:
        return red_proof()
    try:
        rng = choose(
            args.repo,
            env_or(args.event, "GITHUB_EVENT_NAME"),
            env_or(args.head_sha, "GITHUB_SHA"),
            env_or(args.before, "GITHUB_EVENT_BEFORE"),
            env_or(args.pr_base, "PR_BASE_SHA"),
            env_or(args.pr_head, "PR_HEAD_SHA"),
            env_or(args.mg_base, "MG_BASE_SHA"),
            env_or(args.mg_head, "MG_HEAD_SHA"),
        )
    except Refused as exc:
        sys.stderr.write("ci-commit-range: REFUSED: %s\n" % exc)
        return 1
    if args.base_only:
        try:
            rng = base_of(rng)
        except Refused as exc:
            sys.stderr.write("ci-commit-range: REFUSED: %s\n" % exc)
            return 1
    sys.stdout.write(rng + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
