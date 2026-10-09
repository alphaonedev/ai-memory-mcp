#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Read-only check that a LIVE ruleset guards the carrier branches (#6143).

Fetches `GET /repos/<repo>/rulesets` (and each ruleset's detail), never writes,
and requires an ACTIVE branch ruleset that (a) includes both
`refs/heads/chain/**` and `refs/heads/rehearsal/**`, (b) carries a
`required_status_checks` rule with `strict_required_status_checks_policy: true`
and (c) requires every context in REQUIRED_CONTEXTS. Fail-closed: an
unreadable API is a failure (use --allow-unreadable for the CI degrade, which
only WARNs). Not wired into a PR workflow while the ruleset does not exist; the
conductor runs it after the ruleset is applied (docs/ci/CARRIER-BRANCH-GATES.md).

Exit: 0 pass, 1 drift/unreadable, 2 usage.
"""

import argparse
import json
import subprocess
import sys

REQUIRED_PATTERNS = ("refs/heads/chain/**", "refs/heads/rehearsal/**")
REQUIRED_CONTEXTS = (
    "Enterprise-federation cert-expiry gate (cert §7 / F7)",
    "Carrier-base freshness gate (#6143)",
)


def judge(rulesets):
    """Return a list of failure strings for a list of full ruleset objects."""
    reasons = []
    for rs in rulesets:
        if rs.get("target") != "branch" or rs.get("enforcement") != "active":
            continue
        includes = (rs.get("conditions") or {}).get("ref_name", {}).get("include", [])
        if not all(p in includes for p in REQUIRED_PATTERNS):
            continue
        for rule in rs.get("rules", []):
            if rule.get("type") != "required_status_checks":
                continue
            params = rule.get("parameters") or {}
            if params.get("strict_required_status_checks_policy") is not True:
                reasons.append(f"ruleset {rs.get('id')}: strict_required_status_checks_policy is not true")
                continue
            have = {c.get("context") for c in params.get("required_status_checks", [])}
            missing = [c for c in REQUIRED_CONTEXTS if c not in have]
            if missing:
                reasons.append(f"ruleset {rs.get('id')}: missing required contexts {missing}")
                continue
            return []
    return reasons or [
        "no active branch ruleset includes both refs/heads/chain/** and refs/heads/rehearsal/** "
        "with a strict required_status_checks rule"
    ]


def gh_json(*path):
    proc = subprocess.run(["gh", "api", *path], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"gh api {path} exited {proc.returncode}")
    return json.loads(proc.stdout)


def self_test():
    good = {"id": 1, "target": "branch", "enforcement": "active",
            "conditions": {"ref_name": {"include": list(REQUIRED_PATTERNS)}},
            "rules": [{"type": "required_status_checks", "parameters": {
                "strict_required_status_checks_policy": True,
                "required_status_checks": [{"context": c} for c in REQUIRED_CONTEXTS]}}]}
    cases = [
        ("good", [good], True),
        ("empty", [], False),
        ("not strict", [json.loads(json.dumps(good).replace("true", "false"))], False),
        ("disabled", [dict(good, enforcement="disabled")], False),
        ("tag target", [dict(good, target="tag")], False),
        ("one pattern", [dict(good, conditions={"ref_name": {"include": [REQUIRED_PATTERNS[0]]}})], False),
        ("missing ctx", [dict(good, rules=[{"type": "required_status_checks", "parameters": {
            "strict_required_status_checks_policy": True, "required_status_checks": []}}])], False),
    ]
    bad = [label for label, rs, ok in cases if (judge(rs) == []) != ok]
    if bad:
        print(f"SELF-TEST FAIL: {bad}", file=sys.stderr)
        return 1
    print(f"check_carrier_ruleset_live self-test: {len(cases)} cases OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--repo", default="alphaonedev/ai-memory-mcp")
    ap.add_argument("--allow-unreadable", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        listing = gh_json(f"repos/{args.repo}/rulesets")
        full = [gh_json(f"repos/{args.repo}/rulesets/{r['id']}") for r in listing]
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        if args.allow_unreadable:
            print(f"WARN carrier-ruleset-live: rulesets unreadable ({exc}); degraded", file=sys.stderr)
            return 0
        print(f"carrier-ruleset-live: FAIL: rulesets unreadable: {exc}", file=sys.stderr)
        return 1
    reasons = judge(full)
    for r in reasons:
        print(f"carrier-ruleset-live: FAIL: {r}", file=sys.stderr)
    if not reasons:
        print("carrier-ruleset-live: OK")
    return 1 if reasons else 0


if __name__ == "__main__":
    sys.exit(main())
