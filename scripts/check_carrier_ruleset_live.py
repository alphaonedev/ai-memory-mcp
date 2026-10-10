#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Read-only check that a LIVE ruleset guards the carrier branches (#6143).

Three committed files are the declaration; this script never writes any of
them and never writes to GitHub (GET only):

  docs/ci/carrier-ruleset.json            the exact POST body ai:god-f2 applies
  scripts/qc-allowlists/required-contexts-carrier.txt
                                          the hand-authored carrier context set
  scripts/qc-allowlists/carrier-ruleset-state.json
                                          {"state": "pending-apply"|"applied",
                                           "tracking_issue": N}

Offline (always): the payload must be a strict, unbypassable branch ruleset on
refs/heads/chain/** + refs/heads/rehearsal/** whose contexts equal the carrier
declaration, each pinned to the GitHub Actions app (integration_id 15368), and
the carrier declaration must contain every release-required context
(required-contexts-release.txt).

Live: every ACTIVE branch ruleset that carries a required_status_checks rule
and covers a carrier ref, or that has the payload's name, is a CANDIDATE and is
judged in full against the payload (name == payload name, include == exactly the
two carrier patterns, exclude == [], bypass_actors == [], the payload's exact rule
types, strict, do_not_enforce_on_create, the exact context set with no repeated
context, integration_id). A wider ruleset, another name or two matching rulesets
never match, so the printed id is never a wrong PUT target (#6436). The carriers
are protected only when a candidate matches.

State machine (5-agent vote (4d3ea1c5), memory a03dd15d). The state file must
name tracking issue TRACKING_ISSUE (#6182) and no other, and the state is
coupled to the promotion of this verifier's own context (VERIFIER_CONTEXT):
  applied        the verifier context must be in required-contexts-release.txt,
                 required-contexts-carrier.txt and the payload, and its job
                 (VERIFIER_JOB_ID) must be gone from
                 required-contexts-not-required.txt; pending-apply requires
                 the reverse in every place. A half promotion is FAIL.
  applied        match -> OK; no candidate or drift -> FAIL.
  pending-apply  no candidate and the tracking issue is OPEN -> WARN
                 "UNPROTECTED" and exit 0; the issue closed, missing or
                 unreadable -> FAIL; any candidate that drifts -> FAIL; a
                 matching candidate -> FAIL "flip the state to applied" (a
                 stale marker fails in both directions).
  anything else  FAIL.
Unreadable rulesets API (including an empty body) -> FAIL in every state
(no degrade).

--pre-apply (run by ai:god-f2 BEFORE the POST/PUT): lists every live
refs/heads/chain/** and refs/heads/rehearsal/** branch and, for each carrier
that is not frozen, reads .github/workflows/c8-precheck.yml at its tip and
FAILS unless both #6143 jobs (CARRIER_JOBS) are defined there. A carrier is
frozen only when an active branch ruleset with an `update` rule names it
exactly, does not exclude it, and shows bypass_actors == [] (so run it with an
admin token). The ruleset requires the freshness context on every carrier
base; a carrier whose tip lacks the job could never merge a pull request.

With state `applied` it also reads .github/workflows/c8-precheck.yml at the tip of
release/v1.0.0 (RELEASE_REF) and FAILS unless the verifier job (VERIFIER_JOB_ID) is
defined there and the workflow triggers on pull_request for that base, because the PUT
makes the verifier required on release/v1.0.0 too (open non-carrier PRs would never
report it). Every unfrozen carrier tip must also trigger on pull_request for its own
base (trigger_covers), or its required contexts would never report. The OK and flip
lines print the matched ruleset id, which the promotion PUT needs.

bypass_actors is omitted by GitHub for low-privilege readers (the Actions
GITHUB_TOKEN). An omitted field is UNVERIFIED, never treated as []: a WARN by
default, a FAIL under --require-full-view (run that with an admin token after
applying the ruleset). Only an actual empty JSON list is verified empty; null,
a non-list or a non-empty list always fails.

LIMIT: a pull_request run executes the PR's own copy of this script and of the
declaration (the #6140 self-judged-gate class). The job is advisory until it
is required (#6182) and #6140's trusted base-copy posture covers it.

Exit: 0 pass (or pending WARN), 1 drift/unreadable, 2 usage.
"""

import argparse
import functools
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PAYLOAD = REPO_ROOT / "docs" / "ci" / "carrier-ruleset.json"
CARRIER_DECL = REPO_ROOT / "scripts" / "qc-allowlists" / "required-contexts-carrier.txt"
RELEASE_DECL = REPO_ROOT / "scripts" / "qc-allowlists" / "required-contexts-release.txt"
STATE_FILE = REPO_ROOT / "scripts" / "qc-allowlists" / "carrier-ruleset-state.json"
REQUIRED_PATTERNS = ("refs/heads/chain/**", "refs/heads/rehearsal/**")
CARRIER_PREFIXES = ("refs/heads/chain/", "refs/heads/rehearsal/")
ACTIONS_APP_ID = 15368
STATES = ("pending-apply", "applied")
GH_TIMEOUT_SECONDS = 60
POST_CMD = ("gh api -X POST repos/alphaonedev/ai-memory-mcp/rulesets "
            "--input docs/ci/carrier-ruleset.json")
LEDGER = REPO_ROOT / "scripts" / "qc-allowlists" / "required-contexts-not-required.txt"
LEDGER_WORKFLOW = "c8-precheck.yml"
WORKFLOW_PATH = ".github/workflows/" + LEDGER_WORKFLOW
# R2-F2 (security): the only issue the pending-apply state may name.
TRACKING_ISSUE = 6182
VERIFIER_JOB_ID = "carrier-ruleset-live-gate"
VERIFIER_CONTEXT = "Carrier-ruleset live verifier (#6143)"
FRESHNESS_JOB_ID = "carrier-base-fresh-gate"
FRESHNESS_CONTEXT = "Carrier-base freshness gate (#6143)"
CARRIER_JOBS = ((FRESHNESS_JOB_ID, FRESHNESS_CONTEXT), (VERIFIER_JOB_ID, VERIFIER_CONTEXT))
SHA_HEX_LEN = 40


class VerifyError(Exception):
    """A declaration or API problem that fails the gate."""


def _no_dup(pairs):
    """object_pairs_hook: a repeated key is ambiguous input (#6439); the last value must never win."""
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def loads_strict(text):
    """json.loads that rejects a duplicate key at any depth with ValueError (#6439)."""
    return json.loads(text, object_pairs_hook=_no_dup)


def read_decl(path):
    """Declaration lines: non-empty, not starting with '#', kept byte-exact."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise VerifyError(f"cannot read {path}: {exc}") from exc
    return [line for line in text.splitlines() if line.strip() and not line.startswith("#")]


def read_json(path):
    try:
        return loads_strict(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise VerifyError(f"cannot read {path}: {exc}") from exc


def rsc_rules(ruleset):
    return [r for r in (ruleset.get("rules") or []) if r.get("type") == "required_status_checks"]


def check_payload(payload, carrier_decl, release_decl):
    """Offline: the committed payload is executable and complete. Returns reasons."""
    reasons = []
    if payload.get("target") != "branch" or payload.get("enforcement") != "active":
        reasons.append("payload must be target=branch, enforcement=active")
    if payload.get("bypass_actors") != []:
        reasons.append("payload bypass_actors must be []")
    ref = (payload.get("conditions") or {}).get("ref_name") or {}
    if ref.get("include") != list(REQUIRED_PATTERNS) or ref.get("exclude") != []:
        reasons.append(f"payload must include exactly {list(REQUIRED_PATTERNS)} and exclude []")
    rules = rsc_rules(payload)
    if len(rules) != 1 or len(payload.get("rules") or []) != 1:
        reasons.append("payload must carry exactly one rule, of type required_status_checks")
        return reasons
    params = rules[0].get("parameters") or {}
    for key in ("strict_required_status_checks_policy", "do_not_enforce_on_create"):
        if params.get(key) is not True:
            reasons.append(f"payload {key} must be true")
    checks = params.get("required_status_checks") or []
    contexts = [c.get("context") for c in checks]
    for c in checks:
        if c.get("integration_id") != ACTIONS_APP_ID:
            reasons.append(f"payload context {c.get('context')!r} must pin integration_id {ACTIONS_APP_ID}")
    if len(set(contexts)) != len(contexts):
        reasons.append("payload contexts contain duplicates")
    if sorted(contexts, key=str) != sorted(carrier_decl):
        extra = sorted(set(contexts) - set(carrier_decl), key=str)
        missing = sorted(set(carrier_decl) - set(contexts))
        reasons.append(f"payload contexts drift from {CARRIER_DECL.name}: extra {extra}, missing {missing}")
    gap = [c for c in release_decl if c not in carrier_decl]
    if gap:
        reasons.append(f"{CARRIER_DECL.name} lacks release-required contexts {gap}")
    return reasons


def payload_contexts(payload):
    rules = rsc_rules(payload)
    if len(rules) != 1:
        return []
    return [c.get("context") for c in (rules[0].get("parameters") or {}).get("required_status_checks") or []]


def ledger_has_job(ledger, job_id):
    """A ledger line is `<workflow> <job-id> <date> <issue> <reason>`."""
    return any(line.split()[:2] == [LEDGER_WORKFLOW, job_id] for line in ledger)


def check_promotion(state_name, payload, carrier_decl, release_decl, ledger):
    """R2-F1: the state marker moves only together with the verifier's promotion."""
    places = (("release declaration", VERIFIER_CONTEXT in release_decl),
              ("carrier declaration", VERIFIER_CONTEXT in carrier_decl),
              ("payload", VERIFIER_CONTEXT in payload_contexts(payload)))
    ledgered = ledger_has_job(ledger, VERIFIER_JOB_ID)
    reasons = []
    if state_name == "applied":
        missing = [name for name, present in places if not present]
        if missing:
            reasons.append(f"state applied but the verifier context {VERIFIER_CONTEXT!r} is not promoted: "
                           f"missing from {missing}")
        if ledgered:
            reasons.append(f"state applied but {LEDGER.name} still lists {VERIFIER_JOB_ID} as unrequired")
    elif state_name == "pending-apply":
        present = [name for name, here in places if here]
        if present:
            reasons.append(f"state pending-apply but the verifier context {VERIFIER_CONTEXT!r} is already "
                           f"promoted into {present}")
        if not ledgered:
            reasons.append(f"state pending-apply but {LEDGER.name} lacks the {VERIFIER_JOB_ID} line")
    return reasons


def covers_carrier(ruleset):
    ref = (ruleset.get("conditions") or {}).get("ref_name") or {}
    for pat in ref.get("include") or []:
        if pat in ("~ALL",) or pat in REQUIRED_PATTERNS or pat.startswith(CARRIER_PREFIXES):
            return True
    return False


def candidates(rulesets, payload):
    out = []
    for rs in rulesets:
        if rs.get("target") != "branch" or rs.get("enforcement") != "active":
            continue
        if rs.get("name") == payload.get("name") or (rsc_rules(rs) and covers_carrier(rs)):
            out.append(rs)
    return out


def ruleset_label(rs):
    """`carrier ruleset <id> ('<name>')`: the id the promotion PUT targets (code R3-F2)."""
    return f"carrier ruleset {rs.get('id')} ({rs.get('name')!r})"


def judge_one(rs, payload, require_full_view):
    """Compare one live ruleset to the payload. Returns (reasons, warnings)."""
    rid = f"ruleset {rs.get('id')} ({rs.get('name')!r})"
    reasons, warnings = [], []
    ref = (rs.get("conditions") or {}).get("ref_name") or {}
    if rs.get("name") != payload.get("name"):
        reasons.append(f"{rid}: name must be {payload.get('name')!r}: only the ruleset of that name "
                       "is ever the PUT target (5-agent vote (4d3ea1c5), #6436)")
    include = ref.get("include")
    include = include if isinstance(include, list) else []
    missing_pat = [p for p in REQUIRED_PATTERNS if p not in include]
    if missing_pat:
        reasons.append(f"{rid}: include lacks {missing_pat}")
    if sorted(map(repr, include)) != sorted(map(repr, REQUIRED_PATTERNS)):
        reasons.append(f"{rid}: include must be exactly {list(REQUIRED_PATTERNS)} (no ~ALL, "
                       f"~DEFAULT_BRANCH, other pattern or repeat), has {include!r}")
    if ref.get("exclude") != []:
        reasons.append(f"{rid}: exclude must be empty, has {ref.get('exclude')!r}")
    if "bypass_actors" not in rs:
        msg = f"{rid}: bypass_actors UNVERIFIED (field hidden from this token; rerun with an admin token)"
        (reasons if require_full_view else warnings).append(msg)
    elif not (isinstance(rs["bypass_actors"], list) and rs["bypass_actors"] == []):
        reasons.append(f"{rid}: bypass_actors must be an empty list, has {rs['bypass_actors']!r}")
    rules = rsc_rules(rs)
    if not rules:
        reasons.append(f"{rid}: no required_status_checks rule")
        return reasons, warnings
    have_types = sorted(str(r.get("type")) for r in rs.get("rules") or [])
    want_types = sorted(str(r.get("type")) for r in payload.get("rules") or [])
    if have_types != want_types:
        reasons.append(f"{rid}: rule types must be exactly {want_types}, has {have_types}")
    want = {c["context"]: c.get("integration_id") for c in
            rsc_rules(payload)[0]["parameters"]["required_status_checks"]}
    for rule in rules:
        params = rule.get("parameters") or {}
        sub = []
        for key in ("strict_required_status_checks_policy", "do_not_enforce_on_create"):
            if params.get(key) is not True:
                sub.append(f"{rid}: {key} is not true")
        have = {}
        for c in params.get("required_status_checks") or []:
            if c.get("context") in have:
                sub.append(f"{rid}: duplicate required context {c.get('context')!r}")
            have[c.get("context")] = c.get("integration_id")
        if set(have) != set(want):
            sub.append(f"{rid}: required contexts drift: missing {sorted(set(want) - set(have))}, "
                       f"extra {sorted(set(have) - set(want), key=str)}")
        bad_app = sorted(k for k in have if k in want and have[k] != want[k])
        if bad_app:
            sub.append(f"{rid}: integration_id must be {ACTIONS_APP_ID} for {bad_app}")
        if not sub:
            return reasons, warnings
        reasons.extend(sub)
    return reasons, warnings


def verify(payload, carrier_decl, release_decl, ledger, state, rulesets, issue_state, require_full_view):
    """Return (rc, lines). issue_state is a callable returning 'open'/'closed' or raising."""
    lines = []
    reasons = check_payload(payload, carrier_decl, release_decl)
    st = state.get("state") if isinstance(state, dict) else None
    issue = state.get("tracking_issue") if isinstance(state, dict) else None
    if st not in STATES:
        reasons.append(f"carrier-ruleset state must be one of {list(STATES)}, got {st!r}")
    if not isinstance(issue, int) or isinstance(issue, bool) or issue <= 0:
        reasons.append(f"carrier-ruleset state tracking_issue must be a positive issue number, got {issue!r}")
    elif issue != TRACKING_ISSUE:
        reasons.append(f"carrier-ruleset state tracking_issue must be #{TRACKING_ISSUE}, got #{issue}")
    reasons.extend(check_promotion(st, payload, carrier_decl, release_decl, ledger))
    if reasons:
        return 1, [f"FAIL: {r}" for r in reasons]
    cands = candidates(rulesets, payload)
    matched = []
    drift = []
    for rs in cands:
        rs_reasons, rs_warn = judge_one(rs, payload, require_full_view)
        lines.extend(f"WARN: {w}" for w in rs_warn)
        if rs_reasons:
            drift.extend(rs_reasons)
        else:
            matched.append(rs)
    if len(matched) > 1:
        drift.append(f"ambiguous: {len(matched)} rulesets named {payload.get('name')!r} match "
                     f"(ids {[m.get('id') for m in matched]}); the PUT target must be unique")
        matched = []
    if st == "applied":
        if matched:
            lines.append(f"OK: {ruleset_label(matched[0])} is live and matches")
            return 0, lines
        if not cands:
            drift.append("no carrier ruleset is live (state applied): the carriers are unprotected")
        return 1, lines + [f"FAIL: {r}" for r in drift]
    # pending-apply
    if cands:
        if matched and not drift:
            return 1, lines + [f"FAIL: {ruleset_label(matched[0])} is live and matches; flip "
                               f"{STATE_FILE.name} to \"applied\" and promote the verifier (#{issue}); "
                               f"the PUT targets ruleset id {matched[0].get('id')}"]
        if matched:
            return 1, lines + [f"FAIL: {r}" for r in drift] + [
                f"FAIL: {ruleset_label(matched[0])} is live and matches, but other candidates drift; "
                f"flip {STATE_FILE.name} to \"applied\" (#{issue})"]
        return 1, lines + [f"FAIL: {r}" for r in drift]
    try:
        live_state = issue_state(issue)
    except VerifyError as exc:
        return 1, lines + [f"FAIL: tracking issue #{issue} unreadable ({exc}); pending-apply needs it OPEN"]
    if live_state != "open":
        return 1, lines + [f"FAIL: tracking issue #{issue} is {live_state} but the state is still "
                           "pending-apply; apply the ruleset or reopen the issue"]
    return 0, lines + [f"WARN: UNPROTECTED: no carrier ruleset is live (state pending-apply, tracking "
                       f"#{issue}); ai:god-f2 applies it with: {POST_CMD}"]


def gh_run(args):
    try:
        proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True,
                              check=False, timeout=GH_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerifyError(f"gh api {args[-1]}: {exc}") from exc
    if proc.returncode != 0:
        raise VerifyError(proc.stderr.strip() or f"gh api {args[-1]} exited {proc.returncode}")
    return proc.stdout


def parse_pages(text):
    """`gh api --paginate` prints one JSON array per page; concatenate them."""
    dec = json.JSONDecoder(object_pairs_hook=_no_dup)
    out, i, pages = [], 0, 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            if not pages:
                # R2-F3: zero items is `[]` (one page); an empty body is unreadable.
                raise ValueError("empty response body (no JSON page)")
            return out
        page, i = dec.raw_decode(text, i)
        if not isinstance(page, list):
            raise ValueError("rulesets page is not a JSON array")
        pages += 1
        out.extend(page)


def is_int_id(value):
    return isinstance(value, int) and not isinstance(value, bool)


def live_rulesets(repo, run=gh_run):
    """List then read each ruleset. A detail that is not the listed ruleset is unreadable (#6231)."""
    try:
        listing = parse_pages(run(["--paginate", f"repos/{repo}/rulesets?per_page=100"]))
        out = []
        for item in listing:
            if not (isinstance(item, dict) and is_int_id(item.get("id"))):
                raise VerifyError(f"ruleset listing entry has no integer id: {item!r}")
            rid = item["id"]
            try:
                detail = loads_strict(run([f"repos/{repo}/rulesets/{rid}"]))
            except ValueError as exc:
                raise VerifyError(f"ruleset {rid} detail unreadable: {exc}") from exc
            if not (isinstance(detail, dict) and is_int_id(detail.get("id")) and detail["id"] == rid
                    and isinstance(detail.get("target"), str) and isinstance(detail.get("enforcement"), str)):
                raise VerifyError(f"ruleset {rid} detail unreadable: not the requested ruleset")
            out.append(detail)
        return out
    except (ValueError, TypeError) as exc:
        raise VerifyError(f"rulesets response unparseable: {exc}") from exc


def live_issue_state(repo, run=gh_run):
    def fetch(number):
        try:
            data = loads_strict(run([f"repos/{repo}/issues/{int(number)}"]))
        except ValueError as exc:
            raise VerifyError(f"issue response unparseable: {exc}") from exc
        if not (isinstance(data, dict) and is_int_id(data.get("number")) and data["number"] == number
                and data.get("state") in ("open", "closed")):
            raise VerifyError(f"issue #{number} response is not that issue")
        if "pull_request" in data:
            raise VerifyError(f"#{number} is a pull request, not an issue")
        return data["state"]
    return fetch


def frozen_by(ref, rulesets):
    """Id of an active ruleset that freezes `ref` outright, else None (fail closed)."""
    for rs in rulesets:
        if rs.get("target") != "branch" or rs.get("enforcement") != "active":
            continue
        if not any(r.get("type") == "update" for r in rs.get("rules") or []):
            continue
        cond = (rs.get("conditions") or {}).get("ref_name") or {}
        if ref not in (cond.get("include") or []) or ref in (cond.get("exclude") or []):
            continue
        if isinstance(rs.get("bypass_actors"), list) and rs["bypass_actors"] == []:
            return rs.get("id")
    return None


def job_defined(workflow_text, job_id, name):
    """True when `jobs.<job_id>` in the workflow text carries `name: <name>`."""
    lines = workflow_text.splitlines()
    for i, line in enumerate(lines):
        if line.rstrip() != f"  {job_id}:":
            continue
        for body in lines[i + 1:]:
            if body.strip() and not body.startswith("   "):
                break
            if body.startswith("    name:"):
                value = body[len("    name:"):].strip()
                return value in (name, f'"{name}"', f"'{name}'")
        return False
    return False


RELEASE_REF = "release/v1.0.0"
RUN_TYPES = ("opened", "synchronize", "reopened")


def _glob(pattern):
    """GitHub branch filter glob: `**` crosses `/`, `*` does not."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _code_lines(text):
    """Lines without comments or blanks (a quoted `#` does not occur in a branch filter)."""
    out = []
    for raw in text.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
        if line.strip():
            out.append(line)
    return out


def _items(block, start):
    """Values of the list whose key is block[start]: a flow list (maybe multi-line) or `- x` lines."""
    key_indent = _indent(block[start])
    rest = block[start].split(":", 1)[1].strip()
    values = []
    if rest.startswith("["):
        joined, j = rest, start
        while "]" not in joined and j + 1 < len(block):
            j += 1
            joined += " " + block[j].strip()
        values = joined[1:joined.index("]")].split(",") if "]" in joined else []
    elif not rest:
        for line in block[start + 1:]:
            if _indent(line) <= key_indent and not line.lstrip().startswith("- "):
                break
            if line.lstrip().startswith("- "):
                values.append(line.lstrip()[2:])
    else:
        values = [rest]
    return [v.strip().strip("\"'") for v in values if v.strip()]


def trigger_covers(workflow_text, branch):
    """True when the workflow's `on.pull_request` fires for EVERY PR whose BASE is `branch` (#6232).

    Fail closed: a flow mapping, a `paths`/`paths-ignore` filter, or a `types` list without
    opened/synchronize/reopened is False, because the workflow would be skipped for some pull
    requests and a required context would never report (#6429, #6430)."""
    lines = _code_lines(workflow_text)
    for i, line in enumerate(lines):
        if _indent(line) == 0 and line.startswith("on:"):
            inline = line[3:].strip()
            if inline:
                if inline.startswith("{"):
                    return False  # flow mapping: not parsed, so it never "covers" (#6429)
                return "pull_request" in re.findall(r"[\w-]+", inline)
            block = []
            for body in lines[i + 1:]:
                if _indent(body) == 0:
                    break
                block.append(body)
            break
    else:
        return False
    if not block:
        return False
    event_indent = _indent(block[0])
    for j, body in enumerate(block):
        head = re.match(r"pull_request\s*:\s*(.*)$", body.strip()) if _indent(body) == event_indent else None
        if head:
            if head.group(1) not in ("", "null", "~"):
                return False  # a flow mapping or any inline value after the colon is not parsed (#6429)
            sub = []
            for deeper in block[j + 1:]:
                if _indent(deeper) <= event_indent:
                    break
                sub.append(deeper)
            keys = {}
            for k, deeper in enumerate(sub):
                m = re.match(r"(branches(?:-ignore)?|paths(?:-ignore)?|types)\s*:", deeper.strip())
                if m and _indent(deeper) == _indent(sub[0]):
                    keys[m.group(1)] = _items(sub, k)
            if "branches" in keys and "branches-ignore" in keys:
                return False  # GitHub rejects both filters on one event: the workflow is invalid (#6438)
            if "paths" in keys or "paths-ignore" in keys:
                return False  # a path filter skips the workflow for some pull requests (#6430)
            if "types" in keys and not set(RUN_TYPES) <= set(keys["types"]):
                return False  # the default activity types are what a required context needs (#6430)
            if "branches" in keys:
                hit = False
                for pat in keys["branches"]:
                    if pat.startswith("!"):
                        hit = hit and not _glob(pat[1:]).match(branch)
                    elif _glob(pat).match(branch):
                        hit = True
                return hit
            if "branches-ignore" in keys:
                return not any(_glob(pat).match(branch) for pat in keys["branches-ignore"])
            return True
    return False


def branch_name(ref):
    return ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref


def check_tip(label, text, branch, jobs):
    """Reasons a workflow at `label` cannot report the required #6143 contexts for PRs into `branch`."""
    reasons = []
    lacking = [name for job_id, name in jobs if not job_defined(text, job_id, name)]
    if lacking:
        reasons.append(f"{label} lacks {lacking}: land this change on it before applying the ruleset")
    if not trigger_covers(text, branch):
        reasons.append(f"{label}: {WORKFLOW_PATH} does not trigger on pull_request for {branch}: "
                       "the required context would never report")
    return reasons


def pre_apply(payload, carrier_decl, release_decl, rulesets, carriers, fetch_workflow,
              state=None, release_workflow=None):
    """R2-F4: refuse the POST/PUT while an unfrozen carrier tip lacks a #6143 job.

    carriers: list of (ref, sha); fetch_workflow(sha) returns the c8-precheck.yml
    text at that commit or raises VerifyError. Each unfrozen tip must define the jobs
    AND trigger on pull_request for its own base (#6232). Once `state` is applied the
    PUT also makes the verifier required on release/v1.0.0, so release_workflow()
    (the c8-precheck.yml text at the release tip) must define it there too (code R3-F1)."""
    reasons = check_payload(payload, carrier_decl, release_decl)
    st = state.get("state") if isinstance(state, dict) else None
    if state is not None and st not in STATES:
        reasons.append(f"carrier-ruleset state must be one of {list(STATES)}, got {st!r}")
    lines = []
    unfrozen = 0
    if not carriers:
        reasons.append("no carrier branch found under refs/heads/chain/ or refs/heads/rehearsal/")
    for ref, sha in carriers:
        rid = frozen_by(ref, rulesets)
        if rid is not None:
            lines.append(f"PRE-APPLY: {ref} frozen by ruleset {rid} (update rule, no bypass); skipped")
            continue
        unfrozen += 1
        try:
            text = fetch_workflow(sha)
        except VerifyError as exc:
            reasons.append(f"{ref} @ {sha}: {WORKFLOW_PATH} unreadable ({exc})")
            continue
        problems = check_tip(f"{ref} @ {sha}", text, branch_name(ref), CARRIER_JOBS)
        if problems:
            reasons.extend(problems)
        else:
            lines.append(f"PRE-APPLY: {ref} @ {sha} carries both #6143 jobs and triggers on its base")
    if st == "applied":
        reasons.extend(check_release_tip(release_workflow, lines))
    if carriers and not unfrozen:
        reasons.append("every carrier is frozen; nothing to protect, refusing to apply blind")
    if reasons:
        return 1, lines + [f"FAIL: {r}" for r in reasons]
    return 0, lines + [f"PRE-APPLY OK: {unfrozen} unfrozen carrier(s) carry the #6143 jobs; apply with: {POST_CMD}"]


def check_release_tip(release_workflow, lines):
    """Reasons the release tip cannot report the verifier context the PUT makes required there."""
    if release_workflow is None:
        return [f"{RELEASE_REF} @ tip unreadable (no reader): the PUT makes the verifier required there"]
    try:
        text = release_workflow()
    except VerifyError as exc:
        return [f"{RELEASE_REF} @ tip: {WORKFLOW_PATH} unreadable ({exc})"]
    problems = check_tip(f"{RELEASE_REF} @ tip", text, RELEASE_REF, ((VERIFIER_JOB_ID, VERIFIER_CONTEXT),))
    if not problems:
        lines.append(f"PRE-APPLY: {RELEASE_REF} tip defines {VERIFIER_JOB_ID} and triggers on pull_request")
    return problems


def live_carriers(repo):
    out = []
    try:
        for prefix in CARRIER_PREFIXES:
            heads = prefix[len("refs/"):]
            for ref in parse_pages(gh_run(["--paginate", f"repos/{repo}/git/matching-refs/{heads}?per_page=100"])):
                name, sha = ref["ref"], ref["object"]["sha"]
                if not (isinstance(name, str) and name.startswith(prefix) and isinstance(sha, str)
                        and len(sha) == SHA_HEX_LEN and all(ch in "0123456789abcdef" for ch in sha)):
                    raise ValueError(f"unexpected ref entry {ref!r}")
                out.append((name, sha))
    except (ValueError, KeyError, TypeError) as exc:
        raise VerifyError(f"carrier refs response unparseable: {exc}") from exc
    return out


def live_workflow(repo):
    def fetch(sha):
        return gh_run(["-H", "Accept: application/vnd.github.raw", f"repos/{repo}/contents/{WORKFLOW_PATH}?ref={sha}"])
    return fetch


def self_test():
    """Offline regression cases. Every case is isolated: an exception is a failed case."""
    # Independent oracle values (deliberately not the module constants).
    v_ctx, v_job, pinned = "Carrier-ruleset live verifier (#6143)", "carrier-ruleset-live-gate", 6182
    qc = REPO_ROOT / "scripts" / "qc-allowlists"
    payload = read_json(PAYLOAD)
    carrier = read_decl(CARRIER_DECL)
    release = read_decl(RELEASE_DECL)
    ledger = read_decl(qc / "required-contexts-not-required.txt")
    wf_text = (REPO_ROOT / ".github" / "workflows" / "c8-precheck.yml").read_text(encoding="utf-8")

    def copy(v):
        return json.loads(json.dumps(v))

    def params(rs):
        return rs["rules"][0]["parameters"]

    promoted_payload = copy(payload)
    params(promoted_payload)["required_status_checks"].append({"context": v_ctx, "integration_id": ACTIONS_APP_ID})
    ledger_p = [line for line in ledger if line.split()[:2] != ["c8-precheck.yml", v_job]]
    committed = (payload, carrier, release, ledger)
    promoted = (promoted_payload, carrier + [v_ctx], release + [v_ctx], ledger_p)
    good_c = copy(payload)
    good_c["id"] = 1
    good = copy(promoted_payload)
    good["id"] = 1

    def mut(fn, base=None):
        rs = copy(good if base is None else base)
        fn(rs)
        return rs

    def is_open(_):
        return "open"

    def is_closed(_):
        return "closed"

    def unreadable(_):
        raise VerifyError("HTTP 404")

    applied = {"state": "applied", "tracking_issue": pinned}
    pending = {"state": "pending-apply", "tracking_issue": pinned}
    hidden = mut(lambda rs: rs.pop("bypass_actors"))
    cases = [
        # label, bundle, rulesets, state, issue_state, require_full_view, want_rc, needle
        ("applied good", promoted, [good], applied, is_open, False, 0, "OK: carrier ruleset 1 ("),
        ("applied absent", promoted, [], applied, is_open, False, 1, "no carrier ruleset"),
        ("exclude", promoted, [mut(lambda rs: rs["conditions"]["ref_name"].update(exclude=["refs/heads/chain/x"]))],
         applied, is_open, False, 1, "exclude"),
        ("bypass", promoted, [mut(lambda rs: rs.update(bypass_actors=[{"actor_id": 5, "actor_type": "RepositoryRole",
                                                                        "bypass_mode": "always"}]))],
         applied, is_open, False, 1, "bypass_actors must be"),
        ("integration_id", promoted,
         [mut(lambda rs: params(rs)["required_status_checks"][0].update(integration_id=999))],
         applied, is_open, False, 1, "integration_id"),
        ("no integration_id", promoted,
         [mut(lambda rs: params(rs)["required_status_checks"][0].pop("integration_id"))],
         applied, is_open, False, 1, "integration_id"),
        ("create", promoted, [mut(lambda rs: params(rs).pop("do_not_enforce_on_create"))],
         applied, is_open, False, 1, "do_not_enforce_on_create"),
        ("not strict", promoted, [mut(lambda rs: params(rs).update(strict_required_status_checks_policy=False))],
         applied, is_open, False, 1, "strict_required_status_checks_policy"),
        ("missing ctx", promoted, [mut(lambda rs: params(rs)["required_status_checks"].pop())],
         applied, is_open, False, 1, "contexts drift"),
        ("extra ctx", promoted, [mut(lambda rs: params(rs)["required_status_checks"].append(
            {"context": "x", "integration_id": ACTIONS_APP_ID}))], applied, is_open, False, 1, "extra"),
        ("one pattern", promoted,
         [mut(lambda rs: rs["conditions"]["ref_name"].update(include=[REQUIRED_PATTERNS[0]]))],
         applied, is_open, False, 1, "include lacks"),
        ("disabled", promoted, [mut(lambda rs: rs.update(enforcement="disabled"))], applied, is_open, False, 1,
         "no carrier ruleset"),
        ("hidden bypass warn", promoted, [hidden], applied, is_open, False, 0, "UNVERIFIED"),
        ("hidden bypass strict", promoted, [hidden], applied, is_open, True, 1, "UNVERIFIED"),
        # R2-F1 (security): only an actual empty list is verified empty.
        ("bypass null strict", promoted, [mut(lambda rs: rs.update(bypass_actors=None))], applied, is_open, True, 1,
         "bypass_actors must be an empty list"),
        ("bypass null", promoted, [mut(lambda rs: rs.update(bypass_actors=None))], applied, is_open, False, 1,
         "bypass_actors must be an empty list"),
        ("bypass not a list", promoted, [mut(lambda rs: rs.update(bypass_actors="[]"))], applied, is_open, True, 1,
         "bypass_actors must be an empty list"),
        ("pending absent open", committed, [], pending, is_open, False, 0, "UNPROTECTED"),
        ("pending absent closed", committed, [], pending, is_closed, False, 1, "#6182 is closed"),
        ("pending absent unreadable", committed, [], pending, unreadable, False, 1, "unreadable"),
        ("pending live match", committed, [good_c], pending, is_open, False, 1, "flip"),
        # R3-F2 (code): the flip line names the ruleset (and its id) the PUT must target.
        ("pending live match names id", committed, [good_c], pending, is_open, False, 1, "carrier ruleset 1 ("),
        ("pending renamed weak", committed,
         [mut(lambda rs: (rs.update(name="other"), params(rs).update(strict_required_status_checks_policy=False)),
              base=good_c)],
         pending, is_open, False, 1, "strict_required_status_checks_policy"),
        ("archive-freeze ignored", committed,
         [{"id": 2, "name": "archive", "target": "branch", "enforcement": "active",
           "conditions": {"ref_name": {"include": ["refs/heads/chain/promo6"], "exclude": []}},
           "rules": [{"type": "update"}]}], pending, is_open, False, 0, "UNPROTECTED"),
        ("bogus state", committed, [], {"state": "later", "tracking_issue": pinned}, is_open, False, 1,
         "state must be"),
        ("bad issue", committed, [], {"state": "pending-apply", "tracking_issue": str(pinned)}, is_open, False, 1,
         "tracking_issue"),
        # R2-F2 (security): the pending state names #6182 and no other issue.
        ("other tracking issue", committed, [], {"state": "pending-apply", "tracking_issue": 1234}, is_open, False,
         1, f"must be #{pinned}"),
        # R2-F1 (code): the state moves only together with the verifier's promotion.
        ("applied but not promoted", committed, [good_c], applied, is_open, False, 1, "is not promoted"),
        ("pending but promoted", promoted, [], pending, is_open, False, 1, "already promoted"),
        ("applied payload lacks verifier", (payload, carrier + [v_ctx], release + [v_ctx], ledger_p), [good_c],
         applied, is_open, False, 1, "missing from ['payload']"),
        ("applied release lacks verifier", (promoted_payload, carrier + [v_ctx], release, ledger_p), [good],
         applied, is_open, False, 1, "missing from ['release declaration']"),
        ("applied ledger kept", (promoted_payload, carrier + [v_ctx], release + [v_ctx], ledger), [good],
         applied, is_open, False, 1, "still lists " + v_job),
        ("pending ledger dropped", (payload, carrier, release, ledger_p), [], pending, is_open, False, 1,
         "lacks the " + v_job),
    ]
    failures = []
    total = 0

    def check(label, fn):
        nonlocal total
        total += 1
        try:
            problem = fn()
        except Exception as exc:  # noqa: BLE001 - the harness reports every crash as a failed case
            problem = f"raised {type(exc).__name__}: {exc}"
        if problem:
            failures.append(f"{label}: {problem}")

    def verify_case(bundle, rulesets, state, issue_state, full, want_rc, needle):
        rc, lines = verify(*bundle, state, rulesets, issue_state, full)
        text = "\n".join(lines)
        if rc != want_rc or needle not in text:
            return f"rc={rc} (want {want_rc}) needle {needle!r} in {text!r}"
        return None

    for label, bundle, rulesets, state, issue_state, full, want_rc, needle in cases:
        check(label, lambda b=bundle, r=rulesets, s=state, i=issue_state, f=full, w=want_rc, n=needle:
              verify_case(b, r, s, i, f, w, n))
    # offline payload drift
    offline = [
        ("payload bypass", mut(lambda rs: rs.update(bypass_actors=[{"actor_id": 1}]), base=good_c), carrier,
         release, "bypass_actors"),
        ("payload decl drift", good_c, carrier[:-1], release, "drift"),
        ("release gap", good_c, carrier, release + ["only-release"], "lacks release-required"),
    ]
    for label, p, decl, rel, needle in offline:
        check(label, lambda p=p, d=decl, r=rel, n=needle:
              None if n in "\n".join(check_payload(p, d, r)) else f"offline check missed {n!r}")
    check("committed payload", lambda: check_payload(payload, carrier, release) or None)
    check("paginate", lambda: None if parse_pages('[{"id":1}]\n[{"id":2},{"id":3}]') == [
        {"id": 1}, {"id": 2}, {"id": 3}] else "parse_pages does not concatenate paginated arrays")
    check("zero rulesets", lambda: None if parse_pages("[]\n") == [] else "parse_pages('[]') is not []")

    # R2-F3 (security): an empty gh body is unreadable, never "zero rulesets".
    def empty_body(text):
        try:
            parse_pages(text)
        except ValueError:
            return None
        return f"parse_pages({text!r}) accepted an empty body"
    check("empty body", lambda: empty_body(""))
    check("whitespace body", lambda: empty_body(" \n"))

    # R2-F4 (security): the pre-apply check refuses while an unfrozen carrier lacks a #6143 job.
    no_fresh = wf_text.replace("\n  carrier-base-fresh-gate:\n", "\n  carrier-base-fresh-gate-gone:\n")
    no_verifier = wf_text.replace("\n  carrier-ruleset-live-gate:\n", "\n  carrier-ruleset-live-gate-gone:\n")
    sha_a, sha_b, sha_c = "a" * 40, "b" * 40, "c" * 40
    live_two = [("refs/heads/chain/promo6-ssh", sha_a), ("refs/heads/rehearsal/audit-wip-ssh", sha_b)]
    freeze = {"id": 24733250, "target": "branch", "enforcement": "active", "bypass_actors": [],
              "conditions": {"ref_name": {"include": ["refs/heads/chain/old"], "exclude": []}},
              "rules": [{"type": "update"}, {"type": "deletion"}]}
    freeze_hidden = copy(freeze)
    freeze_hidden.pop("bypass_actors")

    def fetcher(texts):
        def fetch(sha):
            if sha not in texts:
                raise VerifyError("HTTP 404")
            return texts[sha]
        return fetch

    pre_cases = [
        # label, payload, rulesets, carriers, texts, want_rc, needle
        ("pre-apply ok", payload, [], live_two, {sha_a: wf_text, sha_b: wf_text}, 0, "PRE-APPLY OK"),
        ("pre-apply stale carrier", payload, [], live_two, {sha_a: wf_text, sha_b: no_fresh}, 1,
         "refs/heads/rehearsal/audit-wip-ssh"),
        ("pre-apply verifier job missing", payload, [], live_two, {sha_a: no_verifier, sha_b: wf_text}, 1,
         v_ctx),
        ("pre-apply frozen skipped", payload, [freeze], live_two + [("refs/heads/chain/old", sha_c)],
         {sha_a: wf_text, sha_b: wf_text}, 0, "frozen by ruleset 24733250"),
        ("pre-apply hidden-bypass freeze not trusted", payload, [freeze_hidden],
         live_two + [("refs/heads/chain/old", sha_c)], {sha_a: wf_text, sha_b: wf_text}, 1, "refs/heads/chain/old"),
        ("pre-apply unreadable tip", payload, [], live_two, {sha_a: wf_text}, 1, "unreadable"),
        ("pre-apply no carriers", payload, [], [], {}, 1, "no carrier branch"),
        ("pre-apply payload drift", mut(lambda rs: rs.update(bypass_actors=[{"actor_id": 1}]), base=good_c), [],
         live_two, {sha_a: wf_text, sha_b: wf_text}, 1, "bypass_actors"),
    ]

    def pre_case(p, rulesets, carriers, texts, want_rc, needle):
        rc, lines = pre_apply(p, carrier, release, rulesets, carriers, fetcher(texts))
        text = "\n".join(lines)
        if rc != want_rc or needle not in text:
            return f"rc={rc} (want {want_rc}) needle {needle!r} in {text!r}"
        return None

    for label, p, rulesets, carriers, texts, want_rc, needle in pre_cases:
        check(label, lambda p=p, r=rulesets, c=carriers, t=texts, w=want_rc, n=needle: pre_case(p, r, c, t, w, n))
    # R3-F1 (security) / #6231: the per-ruleset detail and the tracking-issue reads
    # are validated; a body that is not the requested object is unreadable.
    def fake_run(routes):
        def run(args):
            for needle, body in routes:
                if needle in args[-1]:
                    return body
            raise VerifyError("HTTP 404")
        return run

    def read_raises(fn):
        try:
            fn()
        except VerifyError:
            return None
        return "accepted a malformed response"

    listing = '[{"id": 7}]'
    detail_ok = '{"id": 7, "target": "branch", "enforcement": "active"}'
    for label, routes in (
            ("detail empty object", (("/rulesets/7", "{}"), ("/rulesets?", listing))),
            ("detail other id", (("/rulesets/7", '{"id": 8, "target": "branch", "enforcement": "active"}'),
                                 ("/rulesets?", listing))),
            ("detail array", (("/rulesets/7", "[]"), ("/rulesets?", listing))),
            ("detail empty body", (("/rulesets/7", ""), ("/rulesets?", listing))),
            ("detail target missing", (("/rulesets/7", '{"id": 7, "enforcement": "active"}'),
                                       ("/rulesets?", listing))),
            ("detail enforcement not a string", (("/rulesets/7", '{"id": 7, "target": "branch", "enforcement": 1}'),
                                                 ("/rulesets?", listing))),
            ("listing item bool id", (("/rulesets?", '[{"id": true}]'),)),
            ("listing item not an object", (("/rulesets?", "[7]"),)),
            ("listing item without id", (("/rulesets?", "[{}]"),))):
        check(label, lambda r=routes: read_raises(lambda: live_rulesets("o/r", run=fake_run(r))))
    check("detail valid", lambda: None if live_rulesets(
        "o/r", run=fake_run((("/rulesets/7", detail_ok), ("/rulesets?", listing)))) == [json.loads(detail_ok)]
        else "valid detail not returned")
    for label, body in (
            ("issue other number", '{"number": 1, "state": "open"}'),
            ("issue array", "[]"),
            ("issue empty body", ""),
            ("issue state unknown", '{"number": 6182, "state": "weird"}'),
            ("issue state missing", '{"number": 6182}'),
            ("issue is a pull request", '{"number": 6182, "state": "open", "pull_request": {}}')):
        check(label, lambda b=body: read_raises(lambda: live_issue_state("o/r", run=fake_run((("/issues/", b),)))(
            pinned)))
    check("issue valid", lambda: None if live_issue_state("o/r", run=fake_run((
        ("/issues/", '{"number": 6182, "state": "closed"}'),)))(pinned) == "closed" else "valid issue not read")

    # R3-F2 (security) / #6232: a freeze that EXCLUDES the carrier is not trusted, and an
    # unfrozen tip must trigger on pull_request for its base.
    freeze_excl = copy(freeze)
    freeze_excl["conditions"]["ref_name"]["exclude"] = ["refs/heads/chain/old"]
    flow = 'branches: [main, develop, "release/**", "rehearsal/**", "chain/**"]'
    no_chain = wf_text.replace(flow, 'branches: [main, develop, "release/**", "rehearsal/**"]')
    no_pr = wf_text.replace("\n  pull_request:\n", "\n  pull_request_target_gone:\n")
    pre_cases2 = [
        ("pre-apply freeze that excludes the carrier is not trusted", [freeze_excl],
         live_two + [("refs/heads/chain/old", sha_c)], {sha_a: wf_text, sha_b: wf_text}, 1, "refs/heads/chain/old"),
        ("pre-apply tip without the chain trigger", [], live_two, {sha_a: no_chain, sha_b: wf_text}, 1,
         "does not trigger on pull_request for chain/promo6-ssh"),
        ("pre-apply tip without pull_request", [], live_two, {sha_a: wf_text, sha_b: no_pr}, 1,
         "does not trigger on pull_request for rehearsal/audit-wip-ssh"),
    ]
    for label, rulesets, carriers, texts, want_rc, needle in pre_cases2:
        check(label, lambda r=rulesets, c=carriers, t=texts, w=want_rc, n=needle: pre_case(payload, r, c, t, w, n))
    for label, text, branch, want in (
            ("trigger flow list", wf_text, "chain/x", True),
            ("trigger flow list nested", wf_text, "rehearsal/a/b", True),
            ("trigger release", wf_text, "release/v1.0.0", True),
            ("trigger not listed", wf_text, "feature/x", False),
            ("trigger single star stops at slash", "on:\n  pull_request:\n    branches: ['chain/*']\n",
             "chain/a/b", False),
            ("trigger block list", "on:\n  pull_request:\n    branches:\n      - 'chain/**'\n", "chain/a", True),
            ("trigger no branch filter", "on:\n  pull_request:\n    types: [opened, synchronize, reopened]\n",
             "chain/a", True),
            # #6430: `types: [opened]` alone never re-runs on a new commit, so it is not coverage.
            ("trigger types opened only", "on:\n  pull_request:\n    types: [opened]\n", "chain/a", False),
            ("trigger branches-ignore", "on:\n  pull_request:\n    branches-ignore: ['chain/**']\n", "chain/a",
             False),
            ("trigger negated pattern", "on:\n  pull_request:\n    branches: ['chain/**', '!chain/a']\n",
             "chain/a", False),
            ("trigger push only", "on:\n  push:\n    branches: ['chain/**']\n", "chain/a", False),
            ("trigger no on block", "name: x\n", "chain/a", False)):
        check(label, lambda t=text, b=branch, w=want: None if trigger_covers(t, b) is w
              else f"trigger_covers({b!r}) is not {w}")

    # R3-F1 (code): once the state is `applied`, release/v1.0.0 must define the verifier job
    # (the same availability class as the carriers) before the PUT makes it required there.
    def pre_release(state_name, release_text, want_rc, needle):
        rel = None if release_text is None else (lambda: release_text)
        rc, lines = pre_apply(payload, carrier, release, [], live_two, fetcher({sha_a: wf_text, sha_b: wf_text}),
                              state={"state": state_name, "tracking_issue": pinned}, release_workflow=rel)
        text = "\n".join(lines)
        if rc != want_rc or needle not in text:
            return f"rc={rc} (want {want_rc}) needle {needle!r} in {text!r}"
        return None
    for label, state_name, release_text, want_rc, needle in (
            ("pre-apply applied release carries the job", "applied", wf_text, 0, "release/v1.0.0"),
            ("pre-apply applied release lacks the job", "applied", no_verifier, 1,
             "release/v1.0.0 @ tip lacks " + repr([v_ctx])),
            ("pre-apply applied release does not trigger", "applied", no_pr, 1,
             "does not trigger on pull_request for release/v1.0.0"),
            ("pre-apply applied release unreadable", "applied", None, 1, "release/v1.0.0"),
            ("pre-apply pending does not read release", "pending-apply", no_verifier, 0, "PRE-APPLY OK")):
        check(label, lambda s=state_name, t=release_text, w=want_rc, n=needle: pre_release(s, t, w, n))
    check("pre-apply bogus state", lambda: pre_release("later", wf_text, 1, "state must be"))

    # #6439: duplicate JSON keys are ambiguous input; the last value must never silently win.
    def read_dup_file(text):
        scratch = REPO_ROOT / ".local-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch, prefix="carrier-ruleset-selftest-") as tmp:
            path = Path(tmp) / "dup.json"
            path.write_text(text, encoding="utf-8")
            return read_json(path)

    def rejects(fn):
        try:
            fn()
        except (VerifyError, ValueError):
            return None
        return "accepted a duplicate JSON key"

    dup_detail = '{"id": 7, "id": 7, "target": "branch", "enforcement": "active"}'
    for label, fn in (
            ("dup key in a state file", lambda: read_dup_file(
                '{"state": "applied", "state": "pending-apply", "tracking_issue": 6182}')),
            ("dup bypass_actors in a payload", lambda: read_dup_file(
                '{"bypass_actors": [{"actor_id": 1}], "bypass_actors": []}')),
            ("dup key in a ruleset listing", lambda: parse_pages('[{"id": 7, "id": 8}]')),
            ("dup key in a ruleset detail", lambda: live_rulesets(
                "o/r", run=fake_run((("/rulesets/7", dup_detail), ("/rulesets?", listing))))),
            ("dup key nested in a ruleset detail", lambda: live_rulesets("o/r", run=fake_run((
                ("/rulesets/7", '{"id": 7, "target": "branch", "enforcement": "active", '
                                '"rules": [{"type": "update", "type": "deletion"}]}'),
                ("/rulesets?", listing))))),
            ("dup number in an issue body", lambda: live_issue_state("o/r", run=fake_run((
                ("/issues/", '{"number": 1, "number": 6182, "state": "open"}'),)))(pinned))):
        check(label, lambda f=fn: rejects(f))

    # #6440: id and number checks are type-strict (True == 1 and 6182.0 == 6182 in Python).
    def detail_of(rid_json):
        return '{"id": %s, "target": "branch", "enforcement": "active"}' % rid_json

    for label, routes in (
            ("detail id bool for listing id 1", (("/rulesets/1", detail_of("true")), ("/rulesets?", '[{"id": 1}]'))),
            ("detail id float for listing id 7", (("/rulesets/7", detail_of("7.0")), ("/rulesets?", listing))),
            # Only is_int_id can stop this one: the fake route DOES return a valid detail for id True.
            ("listing id bool with a valid detail", (("/rulesets/True", detail_of("1")),
                                                     ("/rulesets?", '[{"id": true}]')))):
        check(label, lambda r=routes: read_raises(lambda: live_rulesets("o/r", run=fake_run(r))))
    check("issue number float", lambda: read_raises(lambda: live_issue_state("o/r", run=fake_run((
        ("/issues/", '{"number": 6182.0, "state": "open"}'),)))(pinned)))
    check("issue number bool", lambda: read_raises(lambda: live_issue_state("o/r", run=fake_run((
        ("/issues/", '{"number": true, "state": "open"}'),)))(1)))

    # #6436: a live ruleset is OK only when it is exactly the payload: the exact include set, the
    # exact rule set, no duplicate context, the payload name, and one match (the PUT target).
    def with_include(extra):
        return mut(lambda rs: rs["conditions"]["ref_name"].update(
            include=list(REQUIRED_PATTERNS) + extra))

    # The unpinned copy comes FIRST so the pinned copy "wins" in a dict build (the shape that passed).
    dup_unpinned = mut(lambda rs: params(rs)["required_status_checks"].insert(
        0, {"context": params(rs)["required_status_checks"][0]["context"]}))
    dup_pinned = mut(lambda rs: params(rs)["required_status_checks"].append(
        dict(params(rs)["required_status_checks"][0])))
    other_id = mut(lambda rs: rs.update(id=2))
    for label, rulesets, needle in (
            ("wide include ~ALL", [mut(lambda rs: rs["conditions"]["ref_name"].update(
                include=list(REQUIRED_PATTERNS) + ["~ALL"]))], "include must be exactly"),
            ("wide include release/*", [with_include(["refs/heads/release/*"])], "include must be exactly"),
            ("wide include ~DEFAULT_BRANCH", [with_include(["~DEFAULT_BRANCH"])], "include must be exactly"),
            ("include repeats a pattern", [mut(lambda rs: rs["conditions"]["ref_name"].update(
                include=[REQUIRED_PATTERNS[0], REQUIRED_PATTERNS[0], REQUIRED_PATTERNS[1]]))],
             "include must be exactly"),
            ("only ~ALL", [mut(lambda rs: rs["conditions"]["ref_name"].update(include=["~ALL"]))], "include"),
            ("exclude null", [mut(lambda rs: rs["conditions"]["ref_name"].update(exclude=None))], "exclude"),
            ("extra rule type", [mut(lambda rs: rs["rules"].append({"type": "pull_request", "parameters": {}}))],
             "rule types"),
            ("extra update rule", [mut(lambda rs: rs["rules"].append({"type": "update"}))], "rule types"),
            ("duplicate context unpinned", [dup_unpinned], "duplicate"),
            ("duplicate context pinned", [dup_pinned], "duplicate"),
            ("other name, exact content", [mut(lambda rs: rs.update(name="other-ruleset"))], "name must be"),
            ("two rulesets match", [good, other_id], "ambiguous")):
        check(label, lambda r=rulesets, n=needle: verify_case(promoted, r, applied, is_open, False, 1, n))
    check("renamed ruleset is never the PUT target", lambda: (lambda rc, lines: None if (
        rc == 1 and "the PUT targets" not in "\n".join(lines)
        and "OK:" not in "\n".join(lines)) else f"rc={rc} lines={lines!r}")(
            *verify(*committed, pending, [mut(lambda rs: rs.update(name="other-ruleset"), base=good_c)],
                    is_open, False)))

    # #6429: a flow-mapping pull_request trigger is not parsed, so it fails closed (never "covers").
    def trigger_cells(cells):
        for label, text, branch, want in cells:
            check(label, lambda t=text, b=branch, w=want: None if trigger_covers(t, b) is w
                  else f"trigger_covers({b!r}) is not {w}")

    def pre_tip(label_text, want_rc, needle):
        return pre_case(payload, [], live_two, {sha_a: label_text, sha_b: wf_text}, want_rc, needle)

    trigger_cells((
        ("trigger inline flow mapping", "on: {pull_request: {branches: [main]}}\n", "chain/a", False),
        ("trigger inline flow mapping covering", "on: {pull_request: {branches: ['chain/**']}}\n", "chain/a",
         False),
        ("trigger flow mapping value", "on:\n  pull_request: {branches: [main]}\n", "chain/a", False),
        ("trigger flow mapping empty", "on:\n  pull_request: {}\n", "chain/a", False),
        ("trigger null value", "on:\n  pull_request: null\n", "chain/a", True),
        ("trigger tilde value", "on:\n  pull_request: ~\n", "chain/a", True),
        ("trigger inline scalar", "on: pull_request\n", "chain/a", True),
        ("trigger inline flow list", "on: [push, pull_request]\n", "chain/a", True),
        ("trigger inline flow list without it", "on: [push]\n", "chain/a", False)))
    flow_tip = wf_text.replace("\n  pull_request:\n    branches: [", "\n  pull_request: {branches: [", 1)
    flow_tip = flow_tip.replace('"chain/**"]\n', '"chain/**"]}\n', 1) if flow_tip != wf_text else flow_tip
    check("pre-apply tip with a flow-mapping trigger", lambda: pre_tip(
        flow_tip, 1, "does not trigger on pull_request for chain/promo6-ssh"))

    # #6430: paths, paths-ignore and a types list without opened/synchronize/reopened stop the
    # workflow from running on some pull requests, so a required context would never report.
    pr = "on:\n  pull_request:\n    branches: ['chain/**']\n"
    trigger_cells((
        ("trigger paths filter", pr + "    paths: ['src/**']\n", "chain/a", False),
        ("trigger paths-ignore filter", pr + "    paths-ignore: ['docs/**']\n", "chain/a", False),
        ("trigger types closed only", pr + "    types: [closed]\n", "chain/a", False),
        ("trigger types lacks synchronize", pr + "    types: [opened, reopened]\n", "chain/a", False),
        ("trigger types lacks opened (block list)",
         pr + "    types:\n      - synchronize\n      - reopened\n", "chain/a", False),
        ("trigger types default set", pr + "    types: [opened, synchronize, reopened]\n", "chain/a", True),
        ("trigger types superset", pr + "    types: [opened, synchronize, reopened, labeled]\n", "chain/a", True),
        ("trigger types block list", pr + "    types:\n      - opened\n      - synchronize\n      - reopened\n",
         "chain/a", True)))
    check("pre-apply tip with a paths filter", lambda: pre_tip(
        wf_text.replace('"chain/**"]\n', '"chain/**"]\n    paths: [\'src/**\']\n', 1), 1,
        "does not trigger on pull_request for chain/promo6-ssh"))

    # #6438: GitHub rejects `branches` together with `branches-ignore` (the workflow is invalid).
    both = "on:\n  pull_request:\n    branches: ['chain/**']\n    branches-ignore: ['feature/**']\n"
    trigger_cells((
        ("trigger branches with branches-ignore", both, "chain/a", False),
        ("trigger branches-ignore first, then branches",
         "on:\n  pull_request:\n    branches-ignore: ['feature/**']\n    branches: ['chain/**']\n", "chain/a", False),
        ("trigger branches alone is still fine", "on:\n  pull_request:\n    branches: ['chain/**']\n", "chain/a",
         True)))
    check("pre-apply tip with branches and branches-ignore", lambda: pre_tip(
        wf_text.replace('"chain/**"]\n', '"chain/**"]\n    branches-ignore: [\'feature/**\']\n', 1), 1,
        "does not trigger on pull_request for chain/promo6-ssh"))

    # R3-F5 (code): TRACKING_ISSUE is assigned once and never read from env vars.
    own = Path(__file__).read_text(encoding="utf-8")
    pin_assign = r"(?<![A-Za-z_])TRACKING_ISSUE\s*(?:[-+*/|&]?=(?!=)|:=)"
    check("pin assigned once", lambda: None if len(re.findall(pin_assign, own)) == 1
          else "TRACKING_ISSUE must be assigned exactly once")
    check("pin never rebound by global", lambda: None if not re.search(r"\bglob" + r"al\s+TRACKING_ISSUE", own)
          else "TRACKING_ISSUE must not be rebound through a global statement")
    check("verifier reads no env vars", lambda: None if not re.search(
        r"\benv" + r"iron\b|\bget" + r"env\b|^\s*(?:import|from)\s+os\b", own, re.M)
          else "the verifier must not read env vars")
    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
        print(f"check_carrier_ruleset_live self-test: {len(failures)} of {total} cases FAILED", file=sys.stderr)
        return 1
    print(f"check_carrier_ruleset_live self-test: {total} cases OK")
    return 0


def fixture_carriers(path):
    """--carrier-tips-file: {ref: {"sha": sha, "workflow": text | null}}."""
    tips = read_json(path)
    if not isinstance(tips, dict):
        raise VerifyError("carrier tips fixture must be a JSON object")
    try:
        carriers = [(ref, tip["sha"]) for ref, tip in tips.items()]
        texts = {tip["sha"]: tip["workflow"] for tip in tips.values()}
    except (KeyError, TypeError) as exc:
        raise VerifyError(f"carrier tips fixture malformed: {exc}") from exc

    def fetch(sha):
        if not isinstance(texts.get(sha), str):
            raise VerifyError(f"{WORKFLOW_PATH} absent at {sha}")
        return texts[sha]
    return carriers, fetch


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--pre-apply", action="store_true",
                    help="before the POST/PUT: fail unless every unfrozen carrier tip defines both #6143 jobs")
    ap.add_argument("--repo", default="alphaonedev/ai-memory-mcp")
    ap.add_argument("--require-full-view", action="store_true",
                    help="fail when bypass_actors is hidden from the token (admin verification)")
    ap.add_argument("--rulesets-file", help="fixture: JSON array of full rulesets (skips the API)")
    ap.add_argument("--state-file", default=str(STATE_FILE))
    ap.add_argument("--tracking-issue-state", choices=("open", "closed"),
                    help="fixture: tracking issue state (skips the API)")
    ap.add_argument("--payload-file", default=str(PAYLOAD), help="fixture: ruleset payload")
    ap.add_argument("--carrier-decl-file", default=str(CARRIER_DECL), help="fixture: carrier declaration")
    ap.add_argument("--release-decl-file", default=str(RELEASE_DECL), help="fixture: release declaration")
    ap.add_argument("--ledger-file", default=str(LEDGER), help="fixture: not-required ledger")
    ap.add_argument("--release-workflow-file",
                    help="fixture for --pre-apply: c8-precheck.yml text at the release/v1.0.0 tip (skips the API)")
    ap.add_argument("--carrier-tips-file",
                    help='fixture for --pre-apply: {ref: {"sha": sha, "workflow": text|null}} (skips the API)')
    args = ap.parse_args(argv)
    try:
        if args.self_test:
            return self_test()
        payload = read_json(args.payload_file)
        carrier_decl = read_decl(args.carrier_decl_file)
        release_decl = read_decl(args.release_decl_file)
        rulesets = read_json(args.rulesets_file) if args.rulesets_file else live_rulesets(args.repo)
        if not isinstance(rulesets, list):
            raise VerifyError("rulesets must be a JSON array")
        if args.pre_apply:
            if args.carrier_tips_file:
                carriers, fetch = fixture_carriers(args.carrier_tips_file)
            else:
                carriers, fetch = live_carriers(args.repo), live_workflow(args.repo)
            state = read_json(args.state_file)
            if args.release_workflow_file:
                def release_workflow():
                    try:
                        return Path(args.release_workflow_file).read_text(encoding="utf-8")
                    except OSError as exc:
                        raise VerifyError(f"cannot read {args.release_workflow_file}: {exc}") from exc
            elif args.carrier_tips_file:
                release_workflow = None
            else:
                release_workflow = functools.partial(live_workflow(args.repo), RELEASE_REF)
            rc, lines = pre_apply(payload, carrier_decl, release_decl, rulesets, carriers, fetch,
                                  state=state, release_workflow=release_workflow)
        else:
            state = read_json(args.state_file)
            if args.tracking_issue_state:
                fixed = args.tracking_issue_state

                def issue_state(_):
                    return fixed
            else:
                issue_state = live_issue_state(args.repo)
            rc, lines = verify(payload, carrier_decl, release_decl, read_decl(args.ledger_file), state,
                               rulesets, issue_state, args.require_full_view)
    except VerifyError as exc:
        print(f"carrier-ruleset-live: FAIL: {exc}", file=sys.stderr)
        return 1
    for line in lines:
        print(f"carrier-ruleset-live: {line}", file=sys.stderr if line.startswith(("FAIL", "WARN")) else sys.stdout)
    return rc


if __name__ == "__main__":
    sys.exit(main())
