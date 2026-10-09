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
        ("applied good", promoted, [good], applied, is_open, False, 0, "OK"),
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
    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
        print(f"check_carrier_ruleset_live self-test: {len(failures)} of {total} cases FAILED", file=sys.stderr)
        return 1
    print(f"check_carrier_ruleset_live self-test: {total} cases OK")
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
