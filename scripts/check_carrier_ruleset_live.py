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
judged in full against the payload (include, exclude == [], bypass_actors == [],
strict, do_not_enforce_on_create, the exact context set, integration_id). The
carriers are protected only when a candidate matches.

State machine (5-agent vote (4d3ea1c5), memory a03dd15d):
  applied        match -> OK; no candidate or drift -> FAIL.
  pending-apply  no candidate and the tracking issue is OPEN -> WARN
                 "UNPROTECTED" and exit 0; the issue closed, missing or
                 unreadable -> FAIL; any candidate that drifts -> FAIL; a
                 matching candidate -> FAIL "flip the state to applied" (a
                 stale marker fails in both directions).
  anything else  FAIL.
Unreadable rulesets API -> FAIL in every state (no degrade).

bypass_actors is omitted by GitHub for low-privilege readers (the Actions
GITHUB_TOKEN). An omitted field is UNVERIFIED, never treated as []: a WARN by
default, a FAIL under --require-full-view (run that with an admin token after
applying the ruleset). A visible non-empty list always fails.

LIMIT: a pull_request run executes the PR's own copy of this script and of the
declaration (the #6140 self-judged-gate class). The job is advisory until it
is required (#6182) and #6140's trusted base-copy posture covers it.

Exit: 0 pass (or pending WARN), 1 drift/unreadable, 2 usage.
"""

import argparse
import json
import subprocess
import sys
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


class VerifyError(Exception):
    """A declaration or API problem that fails the gate."""


def read_decl(path):
    """Declaration lines: non-empty, not starting with '#', kept byte-exact."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise VerifyError(f"cannot read {path}: {exc}") from exc
    return [line for line in text.splitlines() if line.strip() and not line.startswith("#")]


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
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


def judge_one(rs, payload, require_full_view):
    """Compare one live ruleset to the payload. Returns (reasons, warnings)."""
    rid = f"ruleset {rs.get('id')} ({rs.get('name')!r})"
    reasons, warnings = [], []
    ref = (rs.get("conditions") or {}).get("ref_name") or {}
    include = ref.get("include") or []
    missing_pat = [p for p in REQUIRED_PATTERNS if p not in include and "~ALL" not in include]
    if missing_pat:
        reasons.append(f"{rid}: include lacks {missing_pat}")
    if ref.get("exclude"):
        reasons.append(f"{rid}: exclude must be empty, has {ref.get('exclude')}")
    if "bypass_actors" not in rs:
        msg = f"{rid}: bypass_actors UNVERIFIED (field hidden from this token; rerun with an admin token)"
        (reasons if require_full_view else warnings).append(msg)
    elif rs.get("bypass_actors"):
        reasons.append(f"{rid}: bypass_actors must be empty, has {rs.get('bypass_actors')}")
    rules = rsc_rules(rs)
    if not rules:
        reasons.append(f"{rid}: no required_status_checks rule")
        return reasons, warnings
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


def verify(payload, carrier_decl, release_decl, state, rulesets, issue_state, require_full_view):
    """Return (rc, lines). issue_state is a callable returning 'open'/'closed' or raising."""
    lines = []
    reasons = check_payload(payload, carrier_decl, release_decl)
    st = state.get("state") if isinstance(state, dict) else None
    issue = state.get("tracking_issue") if isinstance(state, dict) else None
    if st not in STATES:
        reasons.append(f"carrier-ruleset state must be one of {list(STATES)}, got {st!r}")
    if not isinstance(issue, int) or isinstance(issue, bool) or issue <= 0:
        reasons.append(f"carrier-ruleset state tracking_issue must be a positive issue number, got {issue!r}")
    if reasons:
        return 1, [f"FAIL: {r}" for r in reasons]
    cands = candidates(rulesets, payload)
    matched = False
    drift = []
    for rs in cands:
        rs_reasons, rs_warn = judge_one(rs, payload, require_full_view)
        lines.extend(f"WARN: {w}" for w in rs_warn)
        if rs_reasons:
            drift.extend(rs_reasons)
        else:
            matched = True
    if st == "applied":
        if matched:
            lines.append("OK")
            return 0, lines
        if not cands:
            drift.append("no carrier ruleset is live (state applied): the carriers are unprotected")
        return 1, lines + [f"FAIL: {r}" for r in drift]
    # pending-apply
    if cands:
        if matched and not drift:
            return 1, lines + [f"FAIL: carrier ruleset is live and matches; flip {STATE_FILE.name} to "
                               f"\"applied\" and promote the verifier (#{issue})"]
        if matched:
            return 1, lines + [f"FAIL: {r}" for r in drift] + [
                f"FAIL: carrier ruleset is live and matches, but other candidates drift; "
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
    dec = json.JSONDecoder()
    out, i = [], 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return out
        page, i = dec.raw_decode(text, i)
        if not isinstance(page, list):
            raise ValueError("rulesets page is not a JSON array")
        out.extend(page)


def live_rulesets(repo):
    try:
        listing = parse_pages(gh_run(["--paginate", f"repos/{repo}/rulesets?per_page=100"]))
        return [json.loads(gh_run([f"repos/{repo}/rulesets/{int(r['id'])}"])) for r in listing]
    except (ValueError, KeyError, TypeError) as exc:
        raise VerifyError(f"rulesets response unparseable: {exc}") from exc


def live_issue_state(repo):
    def fetch(number):
        try:
            data = json.loads(gh_run([f"repos/{repo}/issues/{int(number)}"]))
        except ValueError as exc:
            raise VerifyError(f"issue response unparseable: {exc}") from exc
        if "pull_request" in data:
            raise VerifyError(f"#{number} is a pull request, not an issue")
        return data.get("state") or "missing"
    return fetch


def self_test():
    payload = read_json(PAYLOAD)
    carrier = read_decl(CARRIER_DECL)
    release = read_decl(RELEASE_DECL)
    good = json.loads(json.dumps(payload))
    good["id"] = 1

    def mut(fn):
        rs = json.loads(json.dumps(good))
        fn(rs)
        return rs

    def params(rs):
        return rs["rules"][0]["parameters"]

    def is_open(_):
        return "open"

    def is_closed(_):
        return "closed"

    def unreadable(_):
        raise VerifyError("HTTP 404")

    applied = {"state": "applied", "tracking_issue": 6182}
    pending = {"state": "pending-apply", "tracking_issue": 6182}
    hidden = mut(lambda rs: rs.pop("bypass_actors"))
    cases = [
        # label, rulesets, state, issue_state, require_full_view, want_rc, needle
        ("applied good", [good], applied, is_open, False, 0, "OK"),
        ("applied absent", [], applied, is_open, False, 1, "no carrier ruleset"),
        ("exclude", [mut(lambda rs: rs["conditions"]["ref_name"].update(exclude=["refs/heads/chain/x"]))],
         applied, is_open, False, 1, "exclude"),
        ("bypass", [mut(lambda rs: rs.update(bypass_actors=[{"actor_id": 5, "actor_type": "RepositoryRole",
                                                              "bypass_mode": "always"}]))],
         applied, is_open, False, 1, "bypass_actors must be empty"),
        ("integration_id", [mut(lambda rs: params(rs)["required_status_checks"][0].update(integration_id=999))],
         applied, is_open, False, 1, "integration_id"),
        ("no integration_id", [mut(lambda rs: params(rs)["required_status_checks"][0].pop("integration_id"))],
         applied, is_open, False, 1, "integration_id"),
        ("create", [mut(lambda rs: params(rs).pop("do_not_enforce_on_create"))],
         applied, is_open, False, 1, "do_not_enforce_on_create"),
        ("not strict", [mut(lambda rs: params(rs).update(strict_required_status_checks_policy=False))],
         applied, is_open, False, 1, "strict_required_status_checks_policy"),
        ("missing ctx", [mut(lambda rs: params(rs)["required_status_checks"].pop())],
         applied, is_open, False, 1, "contexts drift"),
        ("extra ctx", [mut(lambda rs: params(rs)["required_status_checks"].append(
            {"context": "x", "integration_id": ACTIONS_APP_ID}))], applied, is_open, False, 1, "extra"),
        ("one pattern", [mut(lambda rs: rs["conditions"]["ref_name"].update(include=[REQUIRED_PATTERNS[0]]))],
         applied, is_open, False, 1, "include lacks"),
        ("disabled", [mut(lambda rs: rs.update(enforcement="disabled"))], applied, is_open, False, 1,
         "no carrier ruleset"),
        ("hidden bypass warn", [hidden], applied, is_open, False, 0, "UNVERIFIED"),
        ("hidden bypass strict", [hidden], applied, is_open, True, 1, "UNVERIFIED"),
        ("pending absent open", [], pending, is_open, False, 0, "UNPROTECTED"),
        ("pending absent closed", [], pending, is_closed, False, 1, "#6182 is closed"),
        ("pending absent unreadable", [], pending, unreadable, False, 1, "unreadable"),
        ("pending live match", [good], pending, is_open, False, 1, "flip"),
        ("pending renamed weak", [mut(lambda rs: (rs.update(name="other"),
                                                  params(rs).update(strict_required_status_checks_policy=False)))],
         pending, is_open, False, 1, "strict_required_status_checks_policy"),
        ("archive-freeze ignored", [{"id": 2, "name": "archive", "target": "branch", "enforcement": "active",
                                     "conditions": {"ref_name": {"include": ["refs/heads/chain/promo6"],
                                                                 "exclude": []}},
                                     "rules": [{"type": "update"}]}], pending, is_open, False, 0, "UNPROTECTED"),
        ("bogus state", [], {"state": "later", "tracking_issue": 6182}, is_open, False, 1, "state must be"),
        ("bad issue", [], {"state": "pending-apply", "tracking_issue": "6182"}, is_open, False, 1,
         "tracking_issue"),
    ]
    failures = []
    for label, rulesets, state, issue_state, full, want_rc, needle in cases:
        rc, lines = verify(payload, carrier, release, state, rulesets, issue_state, full)
        text = "\n".join(lines)
        if rc != want_rc or needle not in text:
            failures.append(f"{label}: rc={rc} (want {want_rc}) needle {needle!r} in {text!r}")
    # offline payload drift
    offline = [
        ("payload bypass", mut(lambda rs: rs.update(bypass_actors=[{"actor_id": 1}])), carrier, "bypass_actors"),
        ("payload decl drift", good, carrier[:-1], "drift"),
        ("release gap", good, carrier, "lacks release-required"),
    ]
    for label, p, decl, needle in offline:
        rel = release + ["only-release"] if label == "release gap" else release
        text = "\n".join(check_payload(p, decl, rel))
        if needle not in text:
            failures.append(f"{label}: offline check missed {needle!r}: {text!r}")
    if check_payload(payload, carrier, release):
        failures.append(f"committed payload fails the offline check: {check_payload(payload, carrier, release)}")
    if parse_pages('[{"id":1}]\n[{"id":2},{"id":3}]') != [{"id": 1}, {"id": 2}, {"id": 3}]:
        failures.append("parse_pages does not concatenate paginated arrays")
    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
        return 1
    print(f"check_carrier_ruleset_live self-test: {len(cases) + len(offline) + 2} cases OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--repo", default="alphaonedev/ai-memory-mcp")
    ap.add_argument("--require-full-view", action="store_true",
                    help="fail when bypass_actors is hidden from the token (admin verification)")
    ap.add_argument("--rulesets-file", help="fixture: JSON array of full rulesets (skips the API)")
    ap.add_argument("--state-file", default=str(STATE_FILE))
    ap.add_argument("--tracking-issue-state", choices=("open", "closed"),
                    help="fixture: tracking issue state (skips the API)")
    args = ap.parse_args(argv)
    try:
        if args.self_test:
            return self_test()
        payload = read_json(PAYLOAD)
        state = read_json(args.state_file)
        rulesets = read_json(args.rulesets_file) if args.rulesets_file else live_rulesets(args.repo)
        if not isinstance(rulesets, list):
            raise VerifyError("rulesets must be a JSON array")
        if args.tracking_issue_state:
            fixed = args.tracking_issue_state

            def issue_state(_):
                return fixed
        else:
            issue_state = live_issue_state(args.repo)
        rc, lines = verify(payload, read_decl(CARRIER_DECL), read_decl(RELEASE_DECL), state,
                           rulesets, issue_state, args.require_full_view)
    except VerifyError as exc:
        print(f"carrier-ruleset-live: FAIL: {exc}", file=sys.stderr)
        return 1
    for line in lines:
        print(f"carrier-ruleset-live: {line}", file=sys.stderr if line.startswith(("FAIL", "WARN")) else sys.stdout)
    return rc


if __name__ == "__main__":
    sys.exit(main())
