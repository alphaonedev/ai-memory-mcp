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
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_subset():
    """Load the shared fail-closed workflow reader by path (the script may run under `python3 -I`)."""
    path = Path(__file__).resolve().parent / "workflow_yaml_subset.py"
    spec = importlib.util.spec_from_file_location("workflow_yaml_subset", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"carrier-ruleset-live: FAIL: cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["workflow_yaml_subset"] = module
    spec.loader.exec_module(module)
    return module


SUBSET = _load_subset()
Unparsed = SUBSET.Unparsed
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


def _on_node(root):
    """The top-level `on:` key (plain or quoted), or None."""
    return next((k for k in root.keys() if k.name in SUBSET.ON_KEYS), None)


def job_defined(workflow_text, job_id, name):
    """True when `jobs.<job_id>.name` is the scalar `name`, read through the accessor; False on a refusal."""
    try:
        _node, value = SUBSET.read(SUBSET.parse_workflow(workflow_text), ("jobs", job_id, "name"), SUBSET.SCALAR)
    except Unparsed:
        return False
    return value == name


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


UNSUPPORTED_GLOB = re.compile(r"[?+\[\]]")
PR_FILTER_KEYS = ("branches", "branches-ignore", "paths", "paths-ignore", "types")


def _unsupported_glob(keys):
    """True when a parsed branch pattern uses `?`, `+` or `[...]`, which this verifier does not translate (#6437)."""
    return any(UNSUPPORTED_GLOB.search(pat) for name in ("branches", "branches-ignore") for pat in keys.get(name, ()))


def _filter_list(node):
    """The parsed entries of one `pull_request` filter: a scalar, a flow sequence or a block sequence of scalars."""
    got = SUBSET.value(node, SUBSET.SCALAR + (SUBSET.FLOW_SEQ, SUBSET.SEQ))
    form = SUBSET.shape(node)
    if form in SUBSET.SCALAR:
        return [got]
    if form == SUBSET.FLOW_SEQ:
        if not all(isinstance(item, str) for item in got):
            raise Unparsed(f"{SUBSET.where(node)} holds an entry that is not a scalar")
        return [str(item) for item in got]
    return [SUBSET.value(item, SUBSET.SCALAR) for item in node.items()]


EVENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")


def _event_key(node):
    """The event name of a key under `on:`; anything the reader does not model is Unparsed (#6481)."""
    name = node.name
    if not EVENT_NAME.fullmatch(name):
        raise Unparsed(f"line {node.line}: trigger name {SUBSET.echo_name(name)} is not a plain ASCII word")
    if name.lower() in SUBSET.YAML11_BOOLEANS + ("null",):
        raise Unparsed(f"line {node.line}: trigger name {SUBSET.echo_name(name)} reads as a boolean or null in YAML 1.1")
    return name


ON_SHAPES = SUBSET.SCALAR + (SUBSET.FLOW_SEQ, SUBSET.FLOW_MAP, SUBSET.MAP, SUBSET.SEQ)


def on_events(workflow_text):
    """Event names of the workflow's `on:`, read through the allowed-shape accessor (#6481, #6545, #6610).

    The block keys, the entries of a block sequence, the words of a flow list, the keys of a flow
    mapping or a scalar are all names; a block scalar or an empty `on:`, a quoted, escaped, fullwidth,
    aliased or merged key, a second document, a duplicate `on:` or any other construct the reader does
    not model raises Unparsed ("line N: ...") so the caller fails closed. A scalar yields its words
    too: a superset, which only ever adds names."""
    on = _on_node(SUBSET.parse_workflow(workflow_text))
    if on is None:
        return set()
    got = SUBSET.value(on, ON_SHAPES)
    form = SUBSET.shape(on)
    names = []
    if form in SUBSET.SCALAR:
        names.extend([got] + re.findall(r"[\w-]+", got))
    elif form == SUBSET.FLOW_MAP:
        names.extend(got)
    elif form == SUBSET.FLOW_SEQ:
        for item in got:
            if not isinstance(item, str):
                raise Unparsed(f"line {on.line}: on: list entry is not a scalar")
            names.append(str(item))
    elif form == SUBSET.MAP:
        names.extend(_event_key(child) for child in on.keys())
    else:
        for item in on.items():
            if SUBSET.shape(item) not in SUBSET.SCALAR:
                raise Unparsed(f"line {item.line}: on: sequence entry is not a scalar ({SUBSET.shape(item)})")
            names.append(SUBSET.value(item, SUBSET.SCALAR))
    return set(names)


FORBIDDEN_TRIGGERS = ("pull_request_target", "workflow_run", "workflow_call")


def forbidden_triggers(workflow_text):
    """Sorted names from FORBIDDEN_TRIGGERS that the workflow `on:` names, in any letter case (#6453, #6544).

    pull_request_target and workflow_run run in the base repository context with a write-capable
    token; workflow_call lets another workflow run these jobs with its own secrets and token. A pull
    request must never be able to add one of them to the workflow that carries the #6143 jobs."""
    return sorted({name.lower() for name in on_events(workflow_text)} & set(FORBIDDEN_TRIGGERS))


GITHUB_TOKEN_EXPR = "${{ github.token }}"
TOKEN_ENV_NAMES = ("GH_TOKEN", "GITHUB_TOKEN")
SECRETS_REF = re.compile(r"\bsecrets\b", re.I)
NEEDS_REF = re.compile(r"\bneeds\s*(?:[.\[:])", re.I)
EXPRESSION_OPEN = "${{"
# #6610: the only token permission levels a workflow carrying the #6143 jobs may grant.
PERMISSION_LEVELS = ("read", "none")
PERMISSION_SCOPE = re.compile(r"[a-z][a-z-]*\Z")
PERMISSIONS_PROBLEM = "permissions grant write or are not read/none in a block mapping"
# Closed shape specs (3-agent vote (6def5ab6), option C): a key outside a spec, or a value of a
# shape the spec does not list, is a refusal naming its line.
WORKFLOW_SPEC = {
    "name": SUBSET.SCALAR, "run-name": SUBSET.SCALAR, "on": ON_SHAPES, "permissions": (SUBSET.MAP,),
    "env": (SUBSET.MAP,), "defaults": (SUBSET.MAP,), "concurrency": SUBSET.SCALAR + (SUBSET.MAP,),
    "jobs": (SUBSET.MAP,),
}
CONCURRENCY_SPEC = {"group": SUBSET.SCALAR, "cancel-in-progress": SUBSET.SCALAR}
DEFAULTS_SPEC = {"run": (SUBSET.MAP,)}
DEFAULTS_RUN_SPEC = {"shell": SUBSET.SCALAR, "working-directory": SUBSET.SCALAR}
CARRIER_JOB_SPEC = {
    "name": SUBSET.SCALAR, "runs-on": (SUBSET.PLAIN,), "timeout-minutes": (SUBSET.PLAIN,),
    "permissions": (SUBSET.MAP,), "env": (SUBSET.MAP,), "steps": (SUBSET.SEQ,),
}
STEP_SPEC = {
    "name": SUBSET.SCALAR, "id": (SUBSET.PLAIN,), "uses": (SUBSET.PLAIN,), "with": (SUBSET.MAP,),
    "env": (SUBSET.MAP,), "run": SUBSET.SCALAR + (SUBSET.BLOCK_SCALAR,),
}
PINNED_ACTION = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}\Z")
TIMEOUT_MINUTES = re.compile(r"[1-9][0-9]{0,2}\Z")


def _scalar_map(node):
    """Check that an env / with block mapping holds one scalar per key (Unparsed otherwise)."""
    SUBSET.value(node, (SUBSET.MAP,))
    for sub in node.keys():
        SUBSET.value(sub, SUBSET.SCALAR)


def _scope_problems(label, node, is_job):
    """Token-source problems inside one workflow section or job (#6452, #6482, #6542, #6617).

    The scan reads the parsed strings of the section (keys, scalars, flow entries, block-scalar
    lines) through the accessor, so a comment never hides text and a quote never shifts it."""
    problems = []
    for number, owner, text in SUBSET.owned_strings(node):
        # #6781 #6783: a problem names the owning key and the length of the value, never the value text; a key
        # (owner "") is a name, not a value, and is shown masked.
        shown = SUBSET.withhold_value(owner, text) if owner else SUBSET.clip(text.strip())
        if SECRETS_REF.search(text):
            problems.append(f"{label} references a repository secret (line {number}): {shown}")
        if is_job and NEEDS_REF.search(text):
            problems.append(f"{label} reads a needs output or declares needs (line {number}): {shown}")
    for sub in node.walk():
        if sub.kind == "key" and SUBSET.key_name(sub.name).upper() in TOKEN_ENV_NAMES:
            got = SUBSET.value(sub, SUBSET.SCALAR)
            if got != GITHUB_TOKEN_EXPR:
                # #6681: a credential slot's literal value is never reprinted, only its length.
                problems.append(f"{label} {SUBSET.clip(sub.name)} is not {GITHUB_TOKEN_EXPR} (line {sub.line});"
                                f" its value is withheld ({len(got)} characters)")
    return problems


def _permissions_problems(label, holder, required):
    """#6610: `permissions` of `holder` must be a block mapping of lowercase scopes to read or none."""
    try:
        node = SUBSET.child(holder, "permissions")
        if node is None:
            if required:
                return [f"{label} {PERMISSIONS_PROBLEM}: no permissions block, so the repository default applies"]
            return []
        SUBSET.value(node, (SUBSET.MAP,))
        bad = []
        for sub in node.keys():
            scope, level = SUBSET.key_name(sub.name), SUBSET.value(sub, (SUBSET.PLAIN,))
            if not PERMISSION_SCOPE.match(scope) or level not in PERMISSION_LEVELS:
                bad.append(f"{SUBSET.clip(scope)}: {SUBSET.clip(level)} (line {sub.line})")
    except Unparsed as exc:
        return [f"{label} {PERMISSIONS_PROBLEM} ({exc})"]
    return [f"{label} {PERMISSIONS_PROBLEM}: " + "; ".join(bad)] if bad else []


def _guarded(problems, label, fn, *args):
    """Run one pin; a refusal from the accessor becomes a problem naming its line."""
    try:
        problems.extend(fn(*args) or [])
    except Unparsed as exc:
        problems.append(f"{label} is refused by the allowed-shape accessor: {exc}")


def _workflow_shape(root):
    """The top level and its sections are in WORKFLOW_SPEC and its nested specs (Unparsed otherwise)."""
    top = SUBSET.read_map(root, WORKFLOW_SPEC)
    if "concurrency" in top and SUBSET.shape(top["concurrency"]) == SUBSET.MAP:
        SUBSET.read_map(top["concurrency"], CONCURRENCY_SPEC)
    if "defaults" in top:
        for sub in SUBSET.read_map(top["defaults"], DEFAULTS_SPEC).values():
            SUBSET.read_map(sub, DEFAULTS_RUN_SPEC)
    if "env" in top:
        _scalar_map(top["env"])


def _carrier_job_shape(label, job, context):
    """A #6143 job is a closed shape: CARRIER_JOB_SPEC keys, pinned actions, a plain runner, a timeout."""
    problems = []
    keys = SUBSET.read_map(job, CARRIER_JOB_SPEC)
    name = SUBSET.value(keys["name"], SUBSET.SCALAR) if "name" in keys else None
    if name != context:
        problems.append(f"{label} does not carry name: {context}")
    runner = SUBSET.value(keys["runs-on"], (SUBSET.PLAIN,)) if "runs-on" in keys else None
    if runner is None or EXPRESSION_OPEN in runner:
        problems.append(f"{label} runs-on is not one plain runner label (line {job.line})")
    timeout = SUBSET.value(keys["timeout-minutes"], (SUBSET.PLAIN,)) if "timeout-minutes" in keys else None
    if timeout is None or not TIMEOUT_MINUTES.match(timeout):
        problems.append(f"{label} timeout-minutes is not a plain whole number of minutes (line {job.line})")
    if "env" in keys:
        _scalar_map(keys["env"])
    steps = keys.get("steps")
    for step in steps.items() if steps is not None else []:
        fields = SUBSET.read_map(step, STEP_SPEC)
        for part in ("with", "env"):
            if part in fields:
                _scalar_map(fields[part])
        if "uses" in fields and not PINNED_ACTION.match(SUBSET.value(fields["uses"], (SUBSET.PLAIN,))):
            problems.append(f"{label} step uses an action not pinned to a full commit sha (line {step.line})")
    return problems


def job_token_problems(workflow_text):
    """Problems with the token source of the workflow and of the two #6143 jobs; empty is clean.

    Every value is read through the allowed-shape accessor in scripts/workflow_yaml_subset.py
    (3-agent vote (6def5ab6), option C): a shape the pin does not allow is a problem naming its line,
    and nothing is compared as raw text. Everything outside `jobs:` (workflow `env:`, `defaults:`,
    `permissions:`) is inherited by every job, so it is held to the same rule as the jobs: no
    repository secret, no GH_TOKEN/GITHUB_TOKEN that is not exactly `${{ github.token }}` (its literal
    value is never reprinted, #6681). Every `jobs.<id>` must be a block mapping (#6679). The
    workflow `permissions:` block must exist and every job's `permissions:` must be a block mapping
    of read/none (#6610). No job name may be an expression (#6618). A #6143 job also takes no
    `needs:` (an output can carry a credential), has the closed CARRIER_JOB_SPEC shape, and its check
    name is claimed by it alone: another job id that differs only in case or space, or another job
    whose parsed `name:` is the same, is a problem (#6542). The verifier job must set GH_TOKEN, or
    `gh` has no credential."""
    root = SUBSET.parse_workflow(workflow_text)
    problems = []
    _guarded(problems, "workflow", _workflow_shape, root)
    problems.extend(_permissions_problems("workflow", root, True))
    for top in root.keys():
        if top.name != "jobs":
            _guarded(problems, "workflow", _scope_problems, "workflow", top, False)
    jobs_node = root.get("jobs")
    jobs = jobs_node.keys() if jobs_node is not None else []
    names = {}
    for node in jobs:
        label = f"job {SUBSET.clip(node.name)}"
        form = SUBSET.shape(node)
        if form != SUBSET.MAP:  # #6679: refuse, never skip; no pin may read a flow job as "no name"
            problems.append(f"{label} (line {node.line}) is not a block mapping ({form}); every job must be"
                            f" one, so its name and permissions are read by the pins (#6679)")
            continue
        problems.extend(_permissions_problems(label, node, False))
        try:
            name_node = SUBSET.child(node, "name")
            names[node.name] = SUBSET.value(name_node, SUBSET.SCALAR) if name_node is not None else None
        except Unparsed as exc:
            problems.append(f"{label} name is refused by the allowed-shape accessor: {exc}")
            continue
        if names[node.name] is not None and EXPRESSION_OPEN in names[node.name]:
            problems.append(f"{label} name is an expression (line {name_node.line}); GitHub evaluates it, so it"
                            f" can report a #6143 check name (#6618)")
    for job_id, context in CARRIER_JOBS:
        wanted = None
        for node in jobs:
            same_id = node.name.strip().casefold() == job_id.casefold()
            parsed = names.get(node.name)
            claims = parsed is not None and parsed.strip().casefold() == context.casefold()
            if node.name == job_id:
                wanted = node
            elif same_id or claims:
                problems.append(f"job {SUBSET.clip(node.name)} (line {node.line}) imitates {job_id} / {context!r}")
        if wanted is None:
            problems.append(f"job {job_id} not found")
            continue
        label = f"job {job_id}"
        _guarded(problems, label, _scope_problems, label, wanted, True)
        if wanted.get("needs") is not None:
            problems.append(f"{label} declares needs (line {wanted.get('needs').line})")
        _guarded(problems, label, _carrier_job_shape, label, wanted, context)
        if job_id == VERIFIER_JOB_ID and not any(
                n.kind == "key" and n.name == "GH_TOKEN" and SUBSET.shape(n) in SUBSET.SCALAR
                and SUBSET.value(n, SUBSET.SCALAR) == GITHUB_TOKEN_EXPR for n in wanted.walk()):
            problems.append(f"{label} does not set GH_TOKEN: {GITHUB_TOKEN_EXPR}")
    return problems


def workflow_pin_problems(workflow_text):
    """Every pin on the workflow that carries the #6143 jobs; a construct the reader refuses is a problem."""
    try:
        problems = [f"workflow names the forbidden trigger {name}" for name in forbidden_triggers(workflow_text)]
        return problems + job_token_problems(workflow_text)
    except Unparsed as exc:
        return [f"workflow is not readable by the fail-closed reader: {exc}"]


def trigger_covers(workflow_text, branch):
    """True when the workflow's `on.pull_request` fires for EVERY PR whose BASE is `branch` (#6232).

    Read through the allowed-shape accessor; a refusal is False (fail closed). Also False for a flow
    mapping `on:` or `pull_request:`, a `paths`/`paths-ignore` filter, or a `types` list without
    opened/synchronize/reopened, because the workflow would be skipped for some pull requests and a
    required context would never report (#6429, #6430); for `branches` together with
    `branches-ignore` (invalid on GitHub, #6438); for a pattern using `?`, `+` or `[...]` (not
    translated, #6437); and for a `pull_request` key other than the five filters."""
    try:
        return _covers(SUBSET.parse_workflow(workflow_text), branch)
    except Unparsed:
        return False


def _covers(root, branch):
    on = _on_node(root)
    if on is None:
        return False
    form = SUBSET.shape(on)
    if form in SUBSET.SCALAR:
        return "pull_request" in re.findall(r"[\w-]+", SUBSET.value(on, SUBSET.SCALAR))
    if form == SUBSET.FLOW_SEQ:
        return "pull_request" in [str(item) for item in SUBSET.value(on, (SUBSET.FLOW_SEQ,)) if isinstance(item, str)]
    if form == SUBSET.SEQ:
        return any(SUBSET.shape(item) in SUBSET.SCALAR and SUBSET.value(item, SUBSET.SCALAR) == "pull_request"
                   for item in on.items())
    if form != SUBSET.MAP:
        return False  # a flow mapping is not read as a trigger list (#6429)
    pr = SUBSET.child(on, "pull_request")
    if pr is None:
        return False
    pr_form = SUBSET.shape(pr)
    if pr_form == SUBSET.PLAIN and SUBSET.value(pr, (SUBSET.PLAIN,)) in ("null", "~"):
        return True
    if pr_form == SUBSET.EMPTY:
        return True
    if pr_form != SUBSET.MAP:
        return False  # a flow mapping or any other inline value is not read (#6429)
    keys = {}
    for sub in pr.keys():
        name = SUBSET.key_name(sub.name)
        if name not in PR_FILTER_KEYS:
            return False
        keys[name] = _filter_list(sub)
    if _unsupported_glob(keys):
        return False  # ?, + and [...] are glob syntax this verifier does not translate (#6437)
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
    reasons.extend(f"{label}: {problem}" for problem in workflow_pin_problems(text))
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

    check("round7 pin: the committed c8-precheck.yml parses and carries no trigger or token problem",
          lambda: None if not workflow_pin_problems(wf_text) else f"{workflow_pin_problems(wf_text)!r}")

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
        # round8 #6619: check_tip routes every tip through workflow_pin_problems; each needle below is
        # produced only by that wiring (reviewer mutant R6 deletes it).
        ("round8 #6619: pre-apply tip with a forbidden trigger", payload, [], live_two,
         {sha_a: wf_text.replace("\non:\n", "\non:\n  workflow_call:\n", 1), sha_b: wf_text}, 1,
         "workflow names the forbidden trigger workflow_call"),
        ("round8 #6619: pre-apply tip without a workflow permissions block", payload, [], live_two,
         {sha_a: wf_text, sha_b: wf_text.replace("\npermissions:\n  contents: read\n", "\n", 1)}, 1,
         "no permissions block, so the repository default applies"),
        ("round8 #6619: pre-apply tip the reader refuses names the construct and line", payload, [], live_two,
         {sha_a: wf_text + "".join(" " * i + f"k{i}:\n" for i in range(80)), sha_b: wf_text}, 1,
         "not readable by the fail-closed reader: line"),
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

    # #6437: GitHub filters give `?`, `+` and `[...]` meaning; the verifier does not translate them,
    # so a pattern using one is unsupported and fails closed (a negation written with them was ignored).
    def br(items):
        return "on:\n  pull_request:\n    branches: [" + ", ".join(items) + "]\n"

    trigger_cells((
        ("trigger negation with ?", br(["'chain/**'", "'!chain/a?'"]), "chain/ab", False),
        ("trigger negation with +", br(["'chain/**'", "'!chain/a+'"]), "chain/a", False),
        ("trigger negation with a class", br(["'chain/**'", "'!chain/[ab]'"]), "chain/a", False),
        ("trigger negation with ? (block list)",
         "on:\n  pull_request:\n    branches:\n      - 'chain/**'\n      - '!chain/a?'\n", "chain/ab", False),
        ("trigger negation with a class (block list)",
         "on:\n  pull_request:\n    branches:\n      - 'chain/**'\n      - '!chain/[ab]'\n", "chain/a", False),
        ("trigger positive ?", br(["'chain/a?'"]), "chain/ab", False),
        ("trigger positive class", br(["'chain/[a-z]'"]), "chain/a", False),
        ("trigger ignore with ?",
         "on:\n  pull_request:\n    branches-ignore: ['chain/a?']\n", "chain/ab", False),
        ("trigger plain negation excludes", br(["'chain/**'", "'!chain/a'"]), "chain/a", False),
        ("trigger plain negation keeps others", br(["'chain/**'", "'!chain/a'"]), "chain/b", True)))
    qneg = wf_text.replace('"chain/**"]\n', '"chain/**", "!chain/promo6-ss?"]\n', 1)
    check("pre-apply tip whose negation uses ?", lambda: pre_tip(
        qneg, 1, "does not trigger on pull_request for chain/promo6-ssh"))

    # Mutant S14 (round 4): a `pull_request_target` trigger would run fork code with a write token.
    # No gate looked at the event set, so the mutation survived every test.
    target_wf = wf_text.replace("\n  pull_request:\n", "\n  pull_request_target:\n    branches: ['chain/**']\n"
                                "  pull_request:\n", 1)
    for label, text, event, want in (
            ("events: committed workflow has no pull_request_target", wf_text, "pull_request_target", False),
            ("events: committed workflow has pull_request", wf_text, "pull_request", True),
            ("events: pull_request_target block key", target_wf, "pull_request_target", True),
            ("events: pull_request_target inline list", "on: [push, pull_request_target]\n",
             "pull_request_target", True),
            ("events: pull_request_target inline flow mapping", "on: {pull_request_target: {}}\n",
             "pull_request_target", True),
            ("events: pull_request_target scalar", "on: pull_request_target\n", "pull_request_target", True),
            ("events: pull_request is not pull_request_target", "on:\n  pull_request:\n", "pull_request_target",
             False),
            ("events: no on block", "name: x\n", "pull_request_target", False)):
        check(label, lambda t=text, e=event, w=want: None if (e in on_events(t)) is w
              else f"{e!r} in on_events is not {w}")

    # #6453 (security round 4, mutant S14): neither `pull_request_target` nor `workflow_run` may be
    # named by the workflow `on:` block. Both run in the base repository context with a write token.
    wr_wf = wf_text.replace("\n  pull_request:\n", "\n  workflow_run:\n    workflows: ['x']\n  pull_request:\n", 1)
    for label, text, want in (
            ("forbidden triggers: committed workflow has none", wf_text, []),
            ("forbidden triggers: pull_request_target block key", target_wf, ["pull_request_target"]),
            ("forbidden triggers: workflow_run block key", wr_wf, ["workflow_run"]),
            ("forbidden triggers: both inline", "on: [push, workflow_run, pull_request_target]\n",
             ["pull_request_target", "workflow_run"]),
            ("forbidden triggers: workflow_run flow mapping", "on: {workflow_run: {}}\n", ["workflow_run"]),
            ("forbidden triggers: plain pull_request is allowed", "on:\n  pull_request:\n", []),
            ("forbidden triggers: no on block", "name: x\n", [])):
        check(label, lambda t=text, w=want: None if forbidden_triggers(t) == w
              else f"forbidden_triggers is {forbidden_triggers(t)!r}, want {w!r}")

    # #6452 (security round 4, mutant S13): both #6143 jobs take their token from `github.token`
    # and never reference a repository secret.
    live_at = wf_text.index("  carrier-ruleset-live-gate:\n")
    fresh_at = wf_text.index("  carrier-base-fresh-gate:\n")
    pat = "GH_TOKEN: ${{ secrets.PAT }}"
    tok = "GH_TOKEN: ${{ github.token }}"
    s13 = wf_text[:live_at] + wf_text[live_at:].replace(tok, pat, 1)
    fresh_secret = wf_text[:fresh_at] + wf_text[fresh_at:].replace(
        "    steps:\n", "    steps:\n      - run: echo ${{ secrets.OTHER }}\n", 1)
    no_tok = wf_text[:live_at] + wf_text[live_at:].replace("          " + tok + "\n", "", 1)
    for label, text, want in (
            ("job token: committed workflow is clean", wf_text, 0),
            ("job token: verifier GH_TOKEN from a repository secret", s13, 1),
            ("job token: secret in the freshness job", fresh_secret, 1),
            ("job token: verifier GH_TOKEN absent", no_tok, 1),
            ("job token: bracket secrets syntax", wf_text[:live_at] + wf_text[live_at:].replace(
                tok, "GH_TOKEN: ${{ secrets['PAT'] }}", 1), 1),
            ("job token: github.token with a suffix", wf_text[:live_at] + wf_text[live_at:].replace(
                tok, "GH_TOKEN: ${{ github.token }}x", 1), 1),
            ("job token: a #6143 job is missing", wf_text.replace("  carrier-ruleset-live-gate:\n",
                                                                "  carrier-ruleset-gone:\n", 1), 1)):
        check(label, lambda t=text, w=want: None if (len(job_token_problems(t)) >= 1) is bool(w)
              else f"job_token_problems is {job_token_problems(t)!r}, want {'problems' if w else 'none'}")

    # Round 7 (#6481 #6482 #6483 #6542 #6543 #6544 #6545): the pins read the workflow through the
    # fail-closed YAML-subset reader (scripts/workflow_yaml_subset.py), not regexes. A construct the
    # reader does not model must make the pin FAIL, naming the construct and its line.
    def closed(fn, text, construct, line):
        try:
            fn(text)
        except Exception as exc:  # noqa: BLE001 - the cell asserts what the refusal says
            msg = str(exc)
            if construct in msg and f"line {line}" in msg:
                return None
            return f"refused without naming {construct!r} at line {line}: {msg}"
        return "did not fail closed"

    def refused(fn, text):
        try:
            return None if fn(text) else "returned nothing"
        except Exception:  # noqa: BLE001 - a refusal is the fail-closed answer
            return None

    for label, text, construct, line in (
            ("round7 trigger: double-quoted key", "on:\n  \"pull_request_target\":\n    branches: [x]\n",
             "quoted mapping key", 2),
            ("round7 trigger: single-quoted key", "on:\n  'workflow_run':\n    workflows: [x]\n",
             "quoted mapping key", 2),
            ("round7 trigger: escaped quoted key", "on:\n  \"pull_request\\x5ftarget\":\n", "backslash", 2),
            ("round7 trigger: quoted key in a flow mapping", "on: {\"pull_request_target\": {}}\n",
             "quoted key", 1),
            ("round7 trigger: fullwidth key", "on:\n  ｐull_request_target:\n", "non-ASCII", 2),
            ("round7 trigger: merge key", "env: &t\n  workflow_run: x\non:\n  <<: *t\n", "anchor", 1),
            ("round7 trigger: alias value", "on:\n  push: *t\n", "alias", 2),
            ("round7 trigger: multi-line flow list", "on: [push,\n  pull_request_target]\n", "flow collection", 1),
            ("round7 trigger: second document", "on: push\n---\non: [pull_request_target]\n",
             "top-level row", 2),
            ("round7 trigger: duplicate on key", "on: push\njobs: {}\non: [pull_request_target]\n",
             "repeated top-level key", 3),
            ("round7 trigger: U+2028 in a scalar", "name: \"a b\"\non: push\n", "U+2028", 1),
            ("round7 trigger: tab", "on:\n\tpush:\n", "whitespace", 2)):
        check(label, lambda t=text, c=construct, n=line: closed(forbidden_triggers, t, c, n))

    for label, text, want in (
            ("round7 trigger: quoted on key", "\"on\": [push, pull_request_target]\n", ["pull_request_target"]),
            ("round7 trigger: single-quoted on key", "'on':\n  workflow_run:\n", ["workflow_run"]),
            ("round7 trigger: block sequence", "on:\n  - push\n  - pull_request_target\n", ["pull_request_target"]),
            ("round7 trigger: quoted scalar value", "on: \"workflow_run\"\n", ["workflow_run"]),
            ("round7 trigger: quoted item in a flow list", "on: [\"workflow_run\"]\n", ["workflow_run"]),
            ("round7 trigger: case variant", "on:\n  Pull_Request_Target:\n", ["pull_request_target"]),
            ("round7 trigger: workflow_call block key", "on:\n  workflow_call:\n", ["workflow_call"]),
            ("round7 trigger: workflow_call scalar", "on: workflow_call\n", ["workflow_call"]),
            ("round7 trigger: workflow_dispatch is allowed", "on:\n  workflow_dispatch:\n", [])):
        check(label, lambda t=text, w=want: None if forbidden_triggers(t) == w
              else f"forbidden_triggers is {forbidden_triggers(t)!r}, want {w!r}")

    def swap(text, old, new):
        assert old in text, old
        return text.replace(old, new, 1)

    def in_verifier(extra_step):
        marker = "        run: python3 -I scripts/check_carrier_ruleset_live.py --self-test\n"
        return wf_text[:live_at] + swap(wf_text[live_at:], marker, marker + extra_step)

    def in_job(job_at, old, new):
        return wf_text[:job_at] + swap(wf_text[job_at:], old, new)

    mint = ("  tokmint:\n    runs-on: ubuntu-latest\n    outputs:\n      t: ${{ steps.s.outputs.t }}\n"
            "    steps:\n      - id: s\n        env:\n          P: ${{ secrets.PAT }}\n"
            "        run: echo t=1 >> \"$GITHUB_OUTPUT\"\n\n")
    with_mint = swap(wf_text, "  carrier-base-fresh-gate:\n", mint + "  carrier-base-fresh-gate:\n")
    live_m = with_mint.index("  carrier-ruleset-live-gate:\n")
    needs_wf = with_mint[:live_m] + swap(with_mint[live_m:], "  carrier-ruleset-live-gate:\n",
                                         "  carrier-ruleset-live-gate:\n    needs: tokmint\n")
    leak = "      - name: leak\n        env:\n          GH_TOKEN: ${{ needs.tokmint.outputs.t }}\n        run: gh api user\n"
    nbsp_leak = ("      - name: leak\n        env:\n          X: a #${{ secrets.PAT }}\n"
                 "        run: GH_TOKEN=\"${X#*#}\" gh api user\n")
    ideo_leak = nbsp_leak.replace(" ", "　")
    decoy = ("  Carrier-Ruleset-Live-Gate:\n    name: Carrier-ruleset live verifier (#6143)\n"
             "    runs-on: ubuntu-latest\n    steps:\n      - env:\n          GH_TOKEN: ${{ secrets.PAT }}\n"
             "        run: gh api user\n\n")
    decoy_named = ("  decoy:\n    name: Carrier-ruleset live verifier (#6143)\n    runs-on: ubuntu-latest\n"
                   "    steps:\n      - run: \"true\"\n\n")
    top_env = "\nenv:\n  GH_TOKEN: ${{ secrets.PAT }}\n"
    for label, text in (
            ("round7 token: workflow-level env GH_TOKEN secret", swap(wf_text, "\npermissions:\n", top_env + "\npermissions:\n")),
            ("round7 token: workflow-level env other-name secret", swap(
                wf_text, "\npermissions:\n", "\nenv:\n  CARRIER_PAT: ${{ secrets.PAT }}\n\npermissions:\n")),
            ("round7 token: workflow-level env secret read by a run body", in_verifier(
                "      - name: leak\n        run: GH_TOKEN=\"$T\" gh api user\n").replace(
                    "\npermissions:\n", "\nenv:\n  T: ${{ secrets.PAT }}\n\npermissions:\n", 1)),
            ("round7 token: workflow-level defaults secret", swap(
                wf_text, "\npermissions:\n", "\ndefaults:\n  run:\n    shell: ${{ secrets.PAT }}\n\npermissions:\n")),
            ("round7 token: workflow-level write-all permissions", swap(
                wf_text, "\npermissions:\n  contents: read\n", "\npermissions: write-all\n")),
            ("round7 token: job-level contents write", in_job(
                live_at, "      contents: read\n      issues: read\n", "      contents: write\n      issues: read\n")),
            ("round7 token: needs key on the verifier job", needs_wf),
            ("round7 token: needs output read by the verifier", with_mint.replace(
                "  carrier-ruleset-live-gate:\n", "  carrier-ruleset-live-gate:\n    needs: tokmint\n", 1)
                .replace("        run: python3 -I scripts/check_carrier_ruleset_live.py --self-test\n",
                         "        run: python3 -I scripts/check_carrier_ruleset_live.py --self-test\n" + leak, 1)),
            ("round7 token: no-break space before # hides a secret", in_verifier(nbsp_leak)),
            ("round7 token: ideographic space before # hides a secret", in_verifier(ideo_leak)),
            ("round7 token: second job claims the verifier check name", swap(
                wf_text, "  carrier-base-fresh-gate:\n", decoy_named + "  carrier-base-fresh-gate:\n")),
            ("round7 token: #6483 freshness GITHUB_TOKEN with a suffix", in_job(
                fresh_at, "    steps:\n", "    env:\n      GITHUB_TOKEN: ${{ github.token }}x\n    steps:\n")),
            ("round7 token: #6483 freshness GH_TOKEN with a prefix", in_job(
                fresh_at, "    steps:\n", "    env:\n      GH_TOKEN: x${{ github.token }}\n    steps:\n")),
            ("round7 token: #6483 freshness GITHUB_TOKEN from secrets.GITHUB_TOKEN", in_job(
                fresh_at, "    steps:\n", "    env:\n      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n    steps:\n"))):
        check(label, lambda t=text: None if job_token_problems(t) else "job_token_problems is empty")
    def case_variant_refused():
        try:
            problems = job_token_problems(swap(
                wf_text, "  carrier-base-fresh-gate:\n", decoy + "  carrier-base-fresh-gate:\n"))
        except Unparsed as exc:
            ok = "carrier-ruleset-live-gate" in str(exc) and "line" in str(exc)
            return None if ok else f"refusal lacks the id or a line: {exc}"
        return None if problems else "a case-variant job id was accepted"
    check("round7 token: case-variant job id is refused (reader or policy)", case_variant_refused)
    check("round7 token: #6483 freshness GITHUB_TOKEN github.token is clean", lambda: (
        None if not job_token_problems(in_job(
            fresh_at, "    steps:\n", "    env:\n      GITHUB_TOKEN: ${{ github.token }}\n    steps:\n"))
        else "a github.token GITHUB_TOKEN must be clean"))

    for label, text, construct, line_of in (
            ("round7 token: alias env", in_verifier("      - name: leak\n        env: *x\n        run: gh api user\n"),
             "alias", None),
            ("round7 token: anchor env", swap(wf_text, "  carrier-base-fresh-gate:\n",
                                              "  anchorhold:\n    env: &x\n      A: b\n    runs-on: x\n\n"
                                              "  carrier-base-fresh-gate:\n"), "anchor", None),
            ("round7 token: quoted env key", in_verifier(
                "      - name: leak\n        env:\n          \"GH_TOKEN\": ${{ secrets.PAT }}\n        run: gh api user\n"),
             "quoted mapping key", None),
            ("round7 token: U+2028 in a quoted scalar", in_verifier(
                "      - name: x\n        run: \"echo ok   zz:\"\n"), "U+2028", None),
            ("round7 token: tab indentation", in_verifier("      - name: x\n\trun: x\n"), "whitespace", None),
            ("round7 token: second document", wf_text + "---\non: [pull_request_target]\n", "top-level row", None),
            ("round7 token: duplicate top-level key", wf_text + "on: push\n", "repeated top-level key", None)):
        def expect(t=text, c=construct):
            try:
                job_token_problems(t)
            except Exception as exc:  # noqa: BLE001
                msg = str(exc)
                return None if c in msg and re.search(r"line \d+", msg) else f"refusal lacks {c!r} or a line: {msg}"
            return "did not fail closed"
        check(label, expect)
    check("round7 token: flow-mapping env GH_TOKEN is refused or flagged", lambda: refused(job_token_problems, in_verifier(
        "      - name: leak\n        env: {GH_TOKEN: x}\n        run: gh api user\n")) or None)

    # Round 8 (#6610 #6617 #6618, round-6 reviews): every pin reads the parsed value through one
    # allowed-shape accessor (3-agent vote (6def5ab6), option C). A spelling the accessor does not
    # allow is a refusal; nothing is compared as raw text. Each cell must yield a pin problem.
    job_perm = "    permissions:\n      contents: read\n      issues: read\n"
    top_perm = "\npermissions:\n  contents: read\n"
    vstep = "        run: python3 -I scripts/check_carrier_ruleset_live.py --self-test\n"

    def r8_in_live(old, new):
        return wf_text[:live_at] + swap(wf_text[live_at:], old, new)

    def r8_after_vstep(extra):
        return swap(wf_text, vstep, vstep + extra)

    def r8_decoy(block):
        return swap(wf_text, "  carrier-base-fresh-gate:\n", block + "  carrier-base-fresh-gate:\n")

    first_job_at = wf_text.index("\njobs:\n") + len("\njobs:\n")
    first_job_steps = wf_text.index("    steps:\n", first_job_at)
    other_job_write = (wf_text[:first_job_steps] + "    permissions:\n      contents: write\n"
                       + wf_text[first_job_steps:])
    for label, text in (
            ("round8 #6610: job permissions flow mapping write",
             r8_in_live(job_perm, "    permissions: {contents: write, issues: read}\n")),
            ("round8 #6610: job permissions flow mapping quoted write",
             r8_in_live(job_perm, "    permissions: {contents: \"write\", issues: read}\n")),
            ("round8 #6610: job permissions flow mapping id-token write",
             r8_in_live(job_perm, "    permissions: {contents: read, issues: read, id-token: write}\n")),
            ("round8 #6610: job permission folded block scalar write",
             r8_in_live(job_perm, "    permissions:\n      contents: >-\n        write\n      issues: read\n")),
            ("round8 #6610: job permission literal block scalar write",
             r8_in_live(job_perm, "    permissions:\n      contents: |-\n        write\n      issues: read\n")),
            ("round8 #6610: job permissions write-all folded",
             r8_in_live(job_perm, "    permissions: >-\n      write-all\n")),
            ("round8 #6610: job permissions read-all scalar",
             r8_in_live(job_perm, "    permissions: read-all\n")),
            ("round8 #6610: job permission key not lowercase",
             r8_in_live(job_perm, "    permissions:\n      Contents: read\n      issues: read\n")),
            ("round8 #6610: job Permissions key case variant",
             r8_in_live(job_perm, "    Permissions:\n      contents: write\n")),
            ("round8 #6610: workflow permissions flow mapping write", swap(wf_text, top_perm, "\npermissions: {contents: write}\n")),
            ("round8 #6610: workflow permissions write-all folded", swap(wf_text, top_perm, "\npermissions: >-\n  write-all\n")),
            ("round8 #6610: workflow permissions write-all literal", swap(wf_text, top_perm, "\npermissions: |\n  write-all\n")),
            ("round8 #6610: workflow permissions read-all", swap(wf_text, top_perm, "\npermissions: read-all\n")),
            ("round8 #6610: workflow permissions absent (repository default)", swap(wf_text, top_perm, "\n")),
            ("round8 #6610: workflow Permissions key case variant", swap(wf_text, top_perm, "\nPermissions:\n  contents: read\n")),
            ("round8 #6610: verifier inherits a flow-mapping write grant",
             swap(r8_in_live(job_perm, ""), top_perm, "\npermissions: {contents: write, issues: read}\n")),
            ("round8 #6610: another job grants write", other_job_write),
            ("round8 #6617: quote in a plain key hides a secret in step env", r8_after_vstep(
                "      - name: q\n        env:\n          a'b: 'z #${{ secrets.PAT }}'\n        run: printenv\n")),
            ("round8 #6617: quote in a plain key hides a secret in workflow env", swap(
                wf_text, top_perm, "\nenv:\n  a'b: 'z #${{ secrets.PAT }}'\n" + top_perm)),
            ("round8 #6617: double quote in a plain key hides a secret in with:", r8_after_vstep(
                "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
                "        with:\n          a\"b: \"z #${{ secrets.PAT }}\"\n")),
            ("round8 #6617: quote in a plain key hides a needs output", r8_after_vstep(
                "      - name: q\n        env:\n          a'b: 'z #${{ needs.mint.outputs.t }}'\n        run: printenv\n")),
            ("round8 #6618: decoy job name is a string-literal expression", r8_decoy(
                "  decoy:\n    name: ${{ 'Carrier-ruleset live verifier (#6143)' }}\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: \"true\"\n\n")),
            ("round8 #6618: decoy job name is built from a matrix value", r8_decoy(
                "  decoy:\n    name: Carrier-ruleset live verifier (${{ matrix.n }})\n    strategy:\n      matrix:\n"
                "        n: ['#6143']\n    runs-on: ubuntu-latest\n    steps:\n      - run: \"true\"\n\n")),
            ("round8 #6618: decoy job name is a format() expression", r8_decoy(
                "  decoy:\n    name: \"${{ format('Carrier-base freshness gate ({0})', '#6143') }}\"\n"
                "    runs-on: ubuntu-latest\n    steps:\n      - run: \"true\"\n\n")),
            ("round8 #6618: verifier's own name is an expression", swap(
                wf_text, "    name: Carrier-ruleset live verifier (#6143)\n",
                "    name: ${{ 'Carrier-ruleset live verifier (#6143)' }}\n"))):
        check(label, lambda t=text: None if workflow_pin_problems(t) else "workflow_pin_problems is empty")

    # round8 #6620: GitHub expression contexts are case-insensitive, so a `secrets` reference in any
    # letter case is a repository secret (review mutant R23); `gh` reads only GH_TOKEN, so a verifier
    # that sets just a lowercase gh_token has no credential (review mutant R16).
    for label, text, needle in (
            ("round8 #6620: upper-case SECRETS context in a #6143 job", r8_after_vstep(
                "      - name: s\n        env:\n          X: ${{ SECRETS.PAT }}\n        run: printenv\n"),
             "job carrier-ruleset-live-gate references a repository secret"),
            ("round8 #6620: mixed-case Secrets context in a #6143 job", r8_after_vstep(
                "      - name: s\n        env:\n          X: ${{ Secrets.PAT }}\n        run: printenv\n"),
             "job carrier-ruleset-live-gate references a repository secret"),
            ("round8 #6620: upper-case SECRETS context at workflow level", swap(
                wf_text, top_perm, "\nenv:\n  X: ${{ SECRETS.PAT }}\n" + top_perm),
             "workflow references a repository secret"),
            ("round8 #6620: mixed-case sEcReTs context at workflow level", swap(
                wf_text, top_perm, "\nenv:\n  X: ${{ sEcReTs.PAT }}\n" + top_perm),
             "workflow references a repository secret"),
            ("round8 #6620: verifier sets only a lowercase gh_token", r8_in_live(
                "          GH_TOKEN: ${{ github.token }}\n", "          gh_token: ${{ github.token }}\n"),
             "job carrier-ruleset-live-gate does not set GH_TOKEN")):
        check(label, lambda t=text, n=needle: None if any(n in p for p in workflow_pin_problems(t))
              else f"workflow_pin_problems does not report {n!r}")

    # round8 mutant campaign: each closed-shape rule and each kind of parsed string has a cell whose
    # needle only that rule produces (#6610 #6617).
    for label, text, needle in (
            ("round8 #6610: a non-carrier job spells Permissions with a capital", r8_decoy(
                "  other:\n    Permissions:\n      contents: read\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: echo\n\n"), "Permissions is not spelled permissions"),
            ("round8 #6617: a secret in a flow entry under on:", swap(
                wf_text, "\non:\n", "\non:\n  schedule: [{cron: \"${{ secrets.CRON }}\"}]\n"),
             "workflow references a repository secret (line"),
            ("round8 #6617: a secret in a workflow env key name", swap(
                wf_text, top_perm, "\nenv:\n  ${{ secrets.PAT }}: x\n" + top_perm),
             "workflow references a repository secret (line"),
            ("round8 #6617: a quote inside a plain key is refused by name", r8_after_vstep(
                "      - name: q\n        env:\n          a'b: x\n        run: printenv\n"),
             "quote character inside a plain mapping key"),
            ("round8 #6610: verifier step uses an action by tag", r8_in_live(
                "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n",
                "      - uses: actions/checkout@v4\n"), "step uses an action not pinned to a full commit sha"),
            ("round8 #6610: verifier runs-on is an expression", r8_in_live(
                "    runs-on: ubuntu-latest\n", "    runs-on: ${{ github.event.pull_request.title }}\n"),
             "runs-on is not one plain runner label"),
            ("round8 #6610: verifier has no timeout-minutes", r8_in_live("    timeout-minutes: 5\n", ""),
             "timeout-minutes is not a plain whole number of minutes"),
            ("round8 #6610: verifier timeout-minutes is an expression", r8_in_live(
                "    timeout-minutes: 5\n", "    timeout-minutes: ${{ 5 }}\n"),
             "timeout-minutes is not a plain whole number of minutes")):
        check(label, lambda t=text, n=needle: None if any(n in p for p in workflow_pin_problems(t))
              else f"workflow_pin_problems does not report {n!r}")

    # round8 #6612: nesting past SUBSET.MAX_DEPTH is a named refusal with a line, never a RecursionError.
    for label, text, needle in (
            ("round8 #6612: 1500-level block nesting is a named refusal",
             wf_text + "".join(" " * i + f"k{i}:\n" for i in range(1500)), "nesting deeper than 64 levels"),
            ("round8 #6612: 2000-level flow nesting is a named refusal",
             wf_text + "deep: " + "[" * 2000 + "]" * 2000 + "\n", "flow collection nested deeper than 64 levels")):
        check(label, lambda t=text, n=needle: None if any(n in p and "line " in p for p in workflow_pin_problems(t))
              else f"workflow_pin_problems does not name {n!r} with a line")

    # round9 #6679: a job written as a flow mapping (or as a scalar or empty value) is refused with its
    # line; SUBSET.child never reads "absent" from a node that is not a block mapping. P01 P02 P23 are
    # the round-7 code-review probes (they passed with zero problems before the fix).
    r9_ctx = "Carrier-ruleset live verifier (#6143)"
    for label, block in (
            ("round9 #6679 P01: flow-mapping decoy job claims the verifier check name",
             '  decoy: {runs-on: ubuntu-latest, name: "%s", steps: [{run: "true"}]}\n' % r9_ctx),
            ("round9 #6679 P02: flow-mapping decoy job with permissions write-all",
             '  decoy: {runs-on: ubuntu-latest, permissions: write-all, steps: [{run: "true"}]}\n'),
            ("round9 #6679 P23: flow-mapping decoy job with an expression name",
             "  decoy: {runs-on: ubuntu-latest, name: \"${{ 'x' }}\", steps: [{run: \"true\"}]}\n"),
            ("round9 #6679: flow-mapping decoy job with no name",
             '  decoy: {runs-on: ubuntu-latest, steps: [{run: "true"}]}\n'),
            ("round9 #6679: decoy job with an empty value", "  decoy:\n"),
            ("round9 #6679: decoy job with a scalar value", "  decoy: ubuntu-latest\n")):
        text = r8_decoy(block)
        at = text.split("\n").index(block.split("\n")[0]) + 1
        needle = f"job decoy (line {at}) is not a block mapping"
        check(label, lambda t=text, n=needle: None if any(n in p for p in workflow_pin_problems(t))
              else f"workflow_pin_problems does not report {n!r}: {workflow_pin_problems(t)!r}")
    jobs_at = wf_text.index("\njobs:\n")
    for label, text, needle in (
            ("round9 #6679: flow-mapping permissions on the verifier job", r8_in_live(
                job_perm, "    permissions: {contents: read, issues: read}\n"), "permissions has the shape flow mapping"),
            ("round9 #6679: flow-mapping steps element in the verifier job", r8_after_vstep(
                '      - {name: q, run: "true"}\n'), "sequence entry has the shape flow mapping"),
            ("round9 #6679: scalar jobs value", wf_text[:jobs_at] + "\njobs: none\n", "jobs has the shape plain scalar"),
            ("round9 #6679: flow-mapping jobs value", wf_text[:jobs_at] + "\njobs: {decoy: {runs-on: x}}\n",
             "jobs has the shape flow mapping")):
        check(label, lambda t=text, n=needle: None if any(n in p and "line " in p for p in workflow_pin_problems(t))
              else f"workflow_pin_problems does not report {n!r} with a line")

    # round9 #6680: a repeated key inside a flow mapping is refused (exact and case variant), never last-wins.
    for label, row in (
            ("round9 #6680: repeated flow mapping key", "        with: {ref: main, ref: evil}\n"),
            ("round9 #6680: case-variant repeated flow mapping key", "        with: {ref: main, REF: evil}\n"),
            ("round9 #6680: repeated key in a nested flow mapping", "        with: {a: {b: 1, b: 2}}\n")):
        text = r8_after_vstep("      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n" + row)
        at = text.split("\n").index(row.rstrip("\n")) + 1
        check(label, lambda t=text, a=at: None if any(f"line {a}: repeated flow mapping key" in p
                                                      for p in workflow_pin_problems(t))
              else f"no 'line {a}: repeated flow mapping key' in {workflow_pin_problems(t)!r}")

    # round9 #6681: a problem or refusal never reprints more than SUBSET.ECHO_LIMIT characters of a row,
    # never a GitHub-token-shaped string, and never the literal value of a credential-named key.
    r9_tokens = ("gh" + "p_" + "A1b2C3d4" * 5, "github" + "_pat_" + "11AB" + "c9" * 14 + "_" + "c9" * 16, "gh" + "s_" + "Zz09" * 9)
    r9_fake = "FAKE" + "0" * 37
    r9_cells = [
        ("round9 #6681: a 3000-character refused row is cut", r8_after_vstep(
            "      - name: &a " + "Z" * 3000 + "\n"), "Z" * 121),
        ("round9 #6681: a 3000-character secret row is cut", r8_after_vstep(
            "      - name: q\n        env:\n          X: ${{ secrets.PAT }}" + "Z" * 3000 + "\n        run: printenv\n"),
         "Z" * 121),
        ("round9 #6681: a literal GH_TOKEN value is withheld (problem path)", r8_in_live(
            "          GH_TOKEN: ${{ github.token }}\n", f"          GH_TOKEN: {r9_fake}\n"), r9_fake[:12]),
        ("round9 #6681: a literal GH_TOKEN value is withheld (unclosed quote refusal)", r8_in_live(
            "          GH_TOKEN: ${{ github.token }}\n", f"          GH_TOKEN: \"{r9_fake}\n"), r9_fake[:12]),
        ("round9 #6681: a literal GH_TOKEN value is withheld (anchor refusal)", r8_in_live(
            "          GH_TOKEN: ${{ github.token }}\n", f"          GH_TOKEN: &a {r9_fake}\n"), r9_fake[:12]),
    ]
    for tok in r9_tokens:
        r9_cells.append((f"round9 #6681: {tok[:4]} token masked in a secret problem", r8_after_vstep(
            f"      - name: q\n        env:\n          X: ${{{{ secrets.PAT }}}} {tok}\n        run: printenv\n"), tok[-12:]))
        r9_cells.append((f"round9 #6681: {tok[:4]} token masked in a refusal", r8_after_vstep(
            f"      - name: q\n        env:\n          X: \"{tok}\n        run: printenv\n"), tok[-12:]))
    r9_cells.append(("round9 #6681: a token-shaped permission level is masked", r8_in_live(
        job_perm, f"    permissions:\n      contents: {r9_tokens[0]}\n      issues: read\n"), r9_tokens[0][-12:]))
    r9_cells.append(("round9 #6681: a 3000-character refused trigger name is cut", swap(
        wf_text, "\non:\n", "\non:\n  " + "Z" * 3000 + ".x:\n"), "Z" * 121))
    r9_cells.append(("round9 #6681: a 3000-character key of the wrong shape is cut in the refusal", swap(
        wf_text, top_perm, top_perm + "  " + "Z" * 3000 + ": [read]\n"), "Z" * 121))
    for label, text, leak in r9_cells:
        check(label, lambda t=text, s=leak: (
            "workflow_pin_problems is empty" if not workflow_pin_problems(t)
            else None if not any(s in p for p in workflow_pin_problems(t))
            else f"a problem echoes {s[:16]!r}..."))

    # round10 #6735 #6736 #6737 #6738 #6739 #6745: the whole value of a credential-named key is withheld
    # (no stop character, no kept literal after an expression), glued tokens are masked, and the
    # credential vocabulary covers authorization, bearer, auth, pass, pwd, access keys, sessions and cookies.
    r10_tail = "LEAK" + "TAIL123"

    def r10_env(row):
        return r8_after_vstep(f"      - name: q\n        env:\n          {row}\n        run: printenv\n")

    r10_cells = [
        ("round10 #6735: comma inside a refused credential value", r10_env(f"API_KEY: &a abc,{r10_tail}"), r10_tail),
        ("round10 #6735: ] inside an unclosed-quote credential value", r10_env(f'PASSWORD: "abc]{r10_tail}'), r10_tail),
        ("round10 #6735: literal text after an expression in a secret problem",
         r10_env("PASSWORD: ${{ secrets.P }} " + r10_tail), r10_tail),
        ("round10 #6735: KEY=value in a run line with a comma", r8_after_vstep(
            "      - name: q\n        run: echo ${{ secrets.P }} && export TOKEN=abc," + r10_tail + "\n"), r10_tail),
        ("round10 #6735: credential value in a flow mapping owned by its key", r8_after_vstep(
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
            '        with: {PASSWORD: "${{ secrets.P }} ' + r10_tail + '"}\n'), r10_tail),
        ("round10 #6735: block scalar owned by a credential key", r8_after_vstep(
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
            "        with:\n          PASSWORD: |\n            ${{ secrets.P }} " + r10_tail + "\n"), r10_tail),
        ("round10 #6735: block sequence item owned by a credential key", r8_after_vstep(
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
            "        with:\n          PASSWORD:\n            - ${{ secrets.P }} " + r10_tail + "\n"), r10_tail),
        ("round10 #6735: flow sequence item owned by a credential key", r8_after_vstep(
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
            '        with:\n          PASSWORD: ["${{ secrets.P }} ' + r10_tail + '"]\n'), r10_tail),
        ("round10 #6738: # inside a refused credential value", r10_env(f"API_KEY: &a abc#{r10_tail}"), r10_tail),
        ("round10 #6738: } inside a refused credential value", r10_env(f"API_KEY: &a abc}}{r10_tail}"), r10_tail),
        ("round10 #6738: string literal inside an expression", r10_env('API_KEY: "${{ \'' + r10_tail + '\' }}'), r10_tail),
    ]
    for word in ("AUTHORIZATION", "BEARER", "NPM_AUTH", "DB_PASS", "PASSPHRASE", "PWD", "AWS_ACCESS_KEY_ID",
                 "SESSION_ID", "COOKIE", "SIGNING_KEY"):
        r10_cells.append((f"round10 #6739: {word} value withheld in a refusal",
                          r10_env(f"{word}: &a {r10_tail}"), r10_tail))
    for glue in ("MY_", "9", "x", "%3A"):
        for tok in r9_tokens[:2]:
            r10_cells.append((f"round10 #6736 #6737: {tok[:4]} token glued after {glue!r} masked in a secret problem",
                              r10_env("X: ${{ secrets.PAT }} " + glue + tok), tok[-12:]))
            r10_cells.append((f"round10 #6736 #6737: {tok[:4]} token glued after {glue!r} masked in a refusal",
                              r10_env("X: &a " + glue + tok), tok[-12:]))
    r10_cells.append(("round10 #6745: uppercase-first repeated flow key", r8_after_vstep(
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
        "        with: {REF: main, ref: evil}\n"), "repeated flow mapping key"))
    for label, text, leak in r10_cells:
        if "#6745" in label:
            check(label, lambda t=text, s=leak: None if any(s in p for p in workflow_pin_problems(t))
                  else f"no {s!r} problem in {workflow_pin_problems(t)!r}")
            continue
        check(label, lambda t=text, s=leak: (
            "workflow_pin_problems is empty" if not workflow_pin_problems(t)
            else None if not any(s in p for p in workflow_pin_problems(t))
            else f"a problem echoes {s[:16]!r}..."))


    # round11 #6791 #6792 #6780 #6781 #6782 #6783: the echo mask masks a token cut by its window, keeps only a
    # marker it produced itself, owns nested values by the credential key above them, withholds a literal
    # operand of an expression, and never reprints a value (problems) or the part of a row after its key.
    r11_tail = "LEAK" + "TAIL123"
    r11_ref = "${{ secrets.P }} "
    r11_uses = "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"

    def r11_with(body):
        return r8_after_vstep(r11_uses + "        with:\n" + body)

    def r11_run(line):
        return r8_after_vstep("      - name: q\n        run: " + line + "\n")

    def r11_straddle(lead, k):
        """A row of `lead`, five long tokens and a token that starts at column k, so the 480-character mask
        window cuts it and the shrunk text puts the cut token inside the 120-character echo (#6791)."""
        body = k - len(lead) - 25
        sizes = [body // 5 + (1 if i < body % 5 else 0) for i in range(5)]
        head = lead + "".join("gh" + "p_" + "A" * n + " " for n in sizes)
        return head + "gh" + "p_" + "Zq7" * 40

    def r11_straddle_leak():
        for k in range(455, 490):
            for lead in ("", "          X: &a "):
                shown = SUBSET.clip(r11_straddle(lead, k))
                if "ghp_Z" in shown:
                    return f"clip at column {k} echoes {shown[-30:]!r}"
        return None

    def r11_straddle_refusal():
        for k in range(455, 490):
            text = r10_env("X: &a " + r11_straddle("", k - 16)[0:])
            if any("ghp_Z" in p for p in workflow_pin_problems(text)):
                return f"a refusal at column {k} echoes the start of a cut token"
        return None

    check("round11 #6791: a token cut by the mask window is masked in clip()", r11_straddle_leak)
    check("round11 #6791: a token cut by the mask window is masked in a refusal", r11_straddle_refusal)
    r11_cells = [
        ("round11 #6792: a value starting with the withheld marker text (secret problem)",
         r10_env("PASSWORD: <withheld " + r11_ref + r11_tail), r11_tail),
        ("round11 #6792: a value starting with the withheld marker text (refusal)",
         r10_env("API_KEY: &a <withheld 9 chars> " + r11_tail), r11_tail),
        ("round11 #6780: a block mapping under a credential key", r11_with(
            "          PASSWORD:\n            inner: " + r11_ref + r11_tail + "\n"), r11_tail),
        ("round11 #6780: a sequence of mappings under a credential key", r11_with(
            "          PASSWORD:\n            - a: " + r11_ref + r11_tail + "\n"), r11_tail),
        ("round11 #6781: a credential key holding a character outside the key class", r11_with(
            "          TOKEN+X: " + r11_ref + r11_tail + "\n"), r11_tail),
        ("round11 #6782: a decimal literal operand in a secret problem",
         r10_env("PIN_TOKEN: ${{ secrets.P || 31337" + "424242 }}"), "31337" + "424242"),
        ("round11 #6782: a hex literal operand in a secret problem",
         r10_env("PIN_TOKEN: ${{ secrets.P || 0x" + "DEADBEEF42 }}"), "DEADBEEF42"),
        ("round11 #6782: an exponent literal operand in a secret problem",
         r10_env("PIN_TOKEN: ${{ secrets.P || 1.5e" + "7777 }}"), "7777"),
        ("round11 #6782: a numeric literal alone in a tab-led refusal row",
         "      - name: q\n        env:\n\t  PIN_TOKEN: ${{ 31337" + "424242 }}\n", "31337" + "424242"),
        ("round11 #6782: a numeric literal alone in an over-indented refusal row",
         r10_env("A: b") + "               PIN_TOKEN: ${{ 31337" + "424242 }}\n", "31337" + "424242"),
        ("round11 #6783: a --password flag value in a run line", r11_run(
            "|\n          tool --password " + r11_ref + r11_tail), r11_tail),
        ("round11 #6783: a -p glued flag value in a run line", r11_run(
            "mysql -u r -p" + r11_ref.strip() + r11_tail), r11_tail),
        ("round11 #6783: URL userinfo in a run line", r11_run(
            "curl " + r11_ref + "https://user:" + r11_tail + "@host.example"), r11_tail),
        ("round11 #6783: a header written without a separator in a run line", r11_run(
            "curl " + r11_ref + "-H X-Api-Key " + r11_tail), r11_tail),
        ("round11 #6783: a Cyrillic look-alike credential key (secret problem)",
         r10_env("TОKEN: " + r11_ref + r11_tail), r11_tail),
        ("round11 #6783: a fullwidth credential key (refusal)",
         r10_env("ＴＯＫＥＮ: &a " + r11_tail), r11_tail),
        ("round11 #6783: a token whose underscore is percent-encoded (secret problem)",
         r10_env("X: " + r11_ref + "ghp%5F" + "Zq7" * 12), "Zq7Zq7Zq7"),
        ("round11 #6783: a literal after the key in an over-indented refusal row",
         r10_env("A: b") + "               NOTE: &a " + r11_tail + "\n", r11_tail),
    ]
    for label, text, leak in r11_cells:
        check(label, lambda t=text, s=leak: (
            "workflow_pin_problems is empty" if not workflow_pin_problems(t)
            else None if not any(s in p for p in workflow_pin_problems(t))
            else f"a problem echoes {s[:16]!r}..."))

    # round11 #6800 #6801 #6802 #6803: test gaps found by the round-10 mutant run (comma after a kept expression,
    # text between two expressions, an underscore inside a token body, the owner on the needs problem path).
    r11_gap_tail = "LEAK" + "TAIL123"
    r11_pat = "github" + "_pat_" + "Qx" * 8 + "_" + "Qx" * 20
    for label, row, leak in (
            ("round11 #6800: a comma after a kept expression withholds the value",
             "PASSWORD: ${{ secrets.P }}," + r11_gap_tail, r11_gap_tail),
            ("round11 #6801: text between two expressions is withheld",
             "PASSWORD: ${{ secrets.A }} " + r11_gap_tail + " ${{ secrets.B }}", r11_gap_tail),
            ("round11 #6802: a github_pat token with an underscore inside its body is masked whole",
             "X: " + r11_pat, "Qx" * 8)):
        check(label, lambda r=row, s=leak: None if s not in SUBSET.mask(r) and s not in SUBSET.clip(r)
              else f"mask or clip echoes {s[:16]!r}...")
    check("round11 #6803: the needs problem names the owning key and withholds the value", lambda: (
        None if (lambda ps: ps and not any(r11_gap_tail in p for p in ps)
                 and any("PASSWORD: <withheld " in p for p in ps))(
            workflow_pin_problems(r10_env("PASSWORD: ${{ needs.a.outputs.b }} " + r11_gap_tail)))
        else "the needs problem echoes the value or lacks the owning key"))

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
