#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/check-ci-job-claims.sh
#
# v1.0.0 CERT GATE 2 — NAMED-CI-JOB EXISTENCE + ENFORCEMENT-TRUTHFULNESS
# (3x7 claims register 3.3.3, `docs/audit/3x7-claims-register-2026-08-01.md`).
#
# THE DEFECT CLASS. Four published claims, all the same shape — "a
# control was removed and the prose was not":
#
#   C-24  `ci.yml`'s "Code Coverage" job is cited as the live coverage
#         gate in BOTH `ROADMAP.md` and `README.md`. It was REMOVED in
#         #1993. README even documents the removal in a parenthetical
#         two clauses after asserting the job enforces a ratchet.
#   C-23  `docs/v1.0.0/release-notes.md` says the postgres/AGE stack is
#         "gated **nightly** by the `postgres-age` CI job". That job was
#         deleted in `da3fb9cc`; `postgres-parity-nightly.yml` says in
#         its own header that the coverage is "gone rather than
#         repaired".
#   C-21  `PERFORMANCE.md` cites an AGE bench gate in CI
#         (`.github/workflows/bench.yml`, AGE job).
#         `grep -rni 'age' .github/workflows/bench.yml` -> ZERO hits.
#   C-31  `PERFORMANCE.md` says `bench.yml` "gates every PR and trunk
#         push". `bench.yml:18` says, in its own words, "Bench is
#         advisory (not in required-status-checks)", and
#         `grep -ic bench scripts/qc-allowlists/required-contexts-release.txt`
#         is 0.
#
# TWO RULES, in strength order.
#
#   EXISTENCE (unambiguous). Every workflow file and every named CI job
#   cited in the scanned docs must RESOLVE — to a file under
#   `.github/workflows/`, or to a parsed job `name:` / job key / matrix
#   expansion within one. Catches C-24 and C-23 outright.
#
#   ENFORCEMENT-TRUTHFULNESS (the rule that counters the bias the
#   register identified: "the drift direction is consistently toward
#   MORE CLAIMED ENFORCEMENT THAN EXISTS"). A doc that says a named job
#   or workflow *gates* / *blocks merge* / *fails the PR* / *is
#   required* must resolve to a context that is actually declared in
#   `scripts/qc-allowlists/required-contexts-release.txt`. Existence
#   alone would have greened C-31: `bench.yml` exists, its job exists,
#   and the claim that it gates anything is still false. Catches C-31
#   and C-21.
#
# The parse follows the SAME YAML scalar rule the #2473 required-context
# gate established — a `#` preceded by whitespace opens a comment, so
# an unquoted `name: Foo #123` is really `Foo`, while `(#1174 PR10)` is
# not a comment. Reproducing that rule here matters: a job whose
# DECLARED name differs from the name GitHub reports is exactly how a
# malformed context entered the live required set.
#
# PENDING-FIX ledger: `scripts/qc-allowlists/ci-job-claims-pending.txt`
# (stale entry = loud NOTICE, never a failure — see that file's header).
#
# CLI:
#   scripts/check-ci-job-claims.sh              — run the gate (exit 0/1)
#   scripts/check-ci-job-claims.sh --self-test  — plant C-21/C-23/C-24/C-31
#       in a throwaway copy UNDER `.local-runs/` (never system /tmp,
#       never `mktemp -d`) and prove the gate rejects each, alongside
#       NEAR-MISS controls that must PASS.

set -euo pipefail

# --------------------------------------------------------------------
# Self-test, dispatched first so it can drive the real script.
# --------------------------------------------------------------------
if [[ "${1:-}" == "--self-test" ]]; then
    SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    FIX="$ROOT/.local-runs/ci-job-claims-selftest-$$"
    rm -rf "$FIX"
    mkdir -p "$FIX/.github/workflows" "$FIX/docs/v1.0.0" "$FIX/scripts/qc-allowlists"
    trap 'rm -rf "$FIX"' EXIT

    cat > "$FIX/.github/workflows/ci.yml" <<'WFEOF'
name: CI
on:
  pull_request:
    branches: [main, "release/**"]
jobs:
  lint:
    name: Lint (fmt + clippy)
    runs-on: ubuntu-latest
    steps:
      - run: true
WFEOF
    cat > "$FIX/.github/workflows/bench.yml" <<'WFEOF'
name: bench
# Bench is advisory (not in required-status-checks).
on:
  pull_request:
    branches: [main]
jobs:
  bench:
    name: ai-memory bench (ubuntu-latest)
    runs-on: ubuntu-latest
    steps:
      - run: true
WFEOF
    printf 'Lint (fmt + clippy)\n' > "$FIX/scripts/qc-allowlists/required-contexts-release.txt"
    # #2977 — the frozen-page exemption SSOT. The fixture carries a REAL
    # one (not an empty stub) so the html legs below can prove BOTH
    # directions of the boundary: an enroll-by-default live page is
    # scanned, a listed frozen page is not.
    printf '# fixture\ndocs/whats-new-v\n' \
        > "$FIX/scripts/qc-allowlists/html-doc-frozen-exempt.txt"

    run_fixture() { ( AI_MEMORY_CIJOB_GATE_ROOT="$FIX" "$SELF" >/dev/null 2>&1; echo "$?" ); }
    run_fixture_out() { AI_MEMORY_CIJOB_GATE_ROOT="$FIX" "$SELF" 2>&1 || true; }

    write_clean() {
        rm -f "$FIX"/README.md "$FIX"/ROADMAP.md "$FIX"/PERFORMANCE.md \
              "$FIX"/docs/v1.0.0/release-notes.md \
              "$FIX"/docs/at-a-glance.html "$FIX"/docs/whats-new-v09.html \
              "$FIX"/scripts/qc-allowlists/ci-job-claims-pending.txt
        # NEAR-MISS CONTROLS — every one must PASS:
        #  * a job cited by its real name that IS in the required set,
        #    with an enforcement verb (the truthful claim)
        #  * a job cited by its yaml KEY
        #  * a workflow cited with NO enforcement verb (bench is real;
        #    describing it without claiming it gates is honest)
        #  * a `.yml` that is not a workflow at all
        cat > "$FIX/README.md" <<'MDEOF'
The `Lint (fmt + clippy)` job (`.github/workflows/ci.yml`) gates every PR and blocks merge.
The `bench` job runs on every PR.
`.github/workflows/bench.yml` runs `ai-memory bench` and uploads an artifact.
The `bench` job runs four `#[ignore]`-gated parity binaries.
Release cuts through `.github/workflows/bench.yml` stay operator-gated.
Compose lives in `stack-compose.yml`.
MDEOF
        printf 'placeholder\n' > "$FIX/stack-compose.yml"
    }

    write_clean
    rc="$(run_fixture)"
    if [[ "$rc" != "0" ]]; then
        echo "FAIL: self-test — the CLEAN near-miss control tree was REJECTED (exit $rc)." >&2
        run_fixture_out | sed 's/^/       /' >&2
        exit 1
    fi
    echo "PASS: self-test control — a truthful enforcement claim, a yaml-key citation, a non-enforcement workflow mention, a non-workflow .yml, and the HYPHEN-COMPOUND \`#[ignore]\`-gated / operator-gated adjectives all PASS"

    # ---- C-24: a job REMOVED in #1993, still cited as live -----------
    write_clean
    printf '(1) `ci.yml`'"'"'s "Code Coverage" job — an absolute floor MIN_COVERAGE_PCT=90.\n' >> "$FIX/README.md"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test C-24 — a removed job cited as live was ACCEPTED" >&2; exit 1; }
    run_fixture_out | grep -q 'Code Coverage' || {
        echo "FAIL: self-test C-24 — violation did not name the unresolvable job" >&2; exit 1; }
    echo "PASS: self-test C-24 — \"<wf>.yml's \\\"<Name>\\\" job\" naming a job that does not exist is REJECTED"

    # ---- C-23: a nightly job deleted in da3fb9cc ---------------------
    write_clean
    printf 'The stack is now gated **nightly** by the `postgres-age` CI job.\n' \
        > "$FIX/docs/v1.0.0/release-notes.md"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test C-23 — a deleted nightly job cited as gating was ACCEPTED" >&2; exit 1; }
    run_fixture_out | grep -q 'postgres-age' || {
        echo "FAIL: self-test C-23 — violation did not name the deleted job" >&2; exit 1; }
    echo "PASS: self-test C-23 — a '\`<name>\` CI job' citation that resolves to nothing is REJECTED"

    # ---- C-31: bench described as GATING when it is advisory ---------
    # THE LOAD-BEARING LEG. `bench.yml` EXISTS and its job EXISTS, so an
    # existence-only rule passes this. Only the enforcement rule catches
    # it, and this defect class is the register's stated systematic bias.
    write_clean
    printf '| `bench.yml` CI workflow | landed | gates every PR and trunk push |\n' > "$FIX/PERFORMANCE.md"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test C-31 — an ADVISORY workflow described as gating was ACCEPTED." >&2
        echo "       bench.yml exists and its job exists; only the enforcement rule can catch this." >&2
        exit 1; }
    run_fixture_out | grep -q 'WORKFLOW_ENFORCEMENT' || {
        echo "FAIL: self-test C-31 — rejected, but NOT by the enforcement rule (wrong reason)" >&2; exit 1; }
    run_fixture_out | grep -q 'required status check' || {
        echo "FAIL: self-test C-31 — violation did not state the enforcement claim is false" >&2; exit 1; }
    echo "PASS: self-test C-31 — an EXISTING but ADVISORY workflow claimed to 'gate every PR' is REJECTED"

    # And the near-miss in the other direction: the SAME workflow, same
    # doc, WITHOUT an enforcement verb, must still pass. Otherwise the
    # rule bans mentioning bench at all.
    write_clean
    printf '`.github/workflows/bench.yml` runs `ai-memory bench --scale 10000` and uploads results.\n' > "$FIX/PERFORMANCE.md"
    [[ "$(run_fixture)" = "0" ]] || {
        echo "FAIL: self-test C-31 near-miss — a NON-enforcement mention of the same workflow was rejected" >&2; exit 1; }
    echo "PASS: self-test C-31 near-miss — the same workflow described WITHOUT an enforcement claim PASSES"

    # ---- WF_WORD: the bare-stem citation shape (3x7 lane-3, 2026-08-09).
    # README carried "The `token-budget` workflow is a **required status
    # check**" while token-budget appears NOWHERE in the required-context
    # mirror. WF_TICK needs a .yml suffix and JOB_CITE needs the literal
    # word "job", so the ENFORCEMENT rule -- built for exactly this false
    # claim -- could not see the most-quoted enforcement sentence in the
    # tier-1 doc. R-203: the leg asserts the pre-fix shape is REJECTED,
    # and that the rejection comes from the ENFORCEMENT rule.
    write_clean
    printf 'The `bench` workflow is a **required status check**.\n' > "$FIX/README.md"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test WF_WORD — a bare-stem workflow citation claiming required-status was ACCEPTED." >&2
        echo "       This is the README:795 token-budget shape; without WF_WORD the gate is blind to it." >&2
        exit 1; }
    run_fixture_out | grep -q 'WORKFLOW_ENFORCEMENT' || {
        echo "FAIL: self-test WF_WORD — rejected, but NOT by the enforcement rule (wrong reason)" >&2; exit 1; }
    echo "PASS: self-test WF_WORD — a bare-stem workflow-stem citation + required-status claim is REJECTED"

    # Near-miss: the same bare-stem citation with NO enforcement verb must
    # PASS, so the shape does not ban naming an advisory workflow.
    write_clean
    printf 'The `bench` workflow runs on every PR and uploads a baseline JSON artifact.\n' > "$FIX/README.md"
    [[ "$(run_fixture)" = "0" ]] || {
        echo "FAIL: self-test WF_WORD near-miss — a non-enforcement bare-stem mention was rejected" >&2; exit 1; }
    echo "PASS: self-test WF_WORD near-miss — bare-stem mention without an enforcement verb PASSES"

    # ---- C-21: a job cited inside a workflow that has no such job ----
    write_clean
    printf 'The **J8 CI gate** (see `.github/workflows/bench.yml`, AGE job) blocks merge.\n' > "$FIX/PERFORMANCE.md"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test C-21 — an AGE job cited in bench.yml was ACCEPTED" >&2; exit 1; }
    echo "PASS: self-test C-21 — a job cited as living inside a named workflow that has no such job is REJECTED"

    # ---- workflow-file existence -------------------------------------
    write_clean
    printf 'See `.github/workflows/postgres-age.yml` for the nightly.\n' >> "$FIX/README.md"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test — a cited workflow FILE that does not exist was ACCEPTED" >&2; exit 1; }
    echo "PASS: self-test — a cited .github/workflows/<file> that does not exist is REJECTED"

    # ---- LEDGER, all three directions --------------------------------
    led="$FIX/scripts/qc-allowlists/ci-job-claims-pending.txt"
    write_clean
    printf '(1) `ci.yml`'"'"'s "Code Coverage" job is the gate.\n' >> "$FIX/README.md"
    printf 'The stack is gated nightly by the `postgres-age` CI job.\n' > "$FIX/docs/v1.0.0/release-notes.md"
    # The one line emits TWO citations — the possessive `ci.yml`'s
    # "Code Coverage" (owner-scoped) and the bare `Code Coverage` job —
    # so both keys are ledgered; suppressing one must not suppress the
    # other by accident.
    printf 'README.md Code Coverage #1\nREADME.md ci.yml:Code Coverage #1\n' > "$led"
    out="$(run_fixture_out)"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test ledger — an UNLEDGERED claim was suppressed" >&2; exit 1; }
    grep -q 'FAIL: ci-job-claims .*README.md' <<<"$out" && {
        echo "FAIL: self-test ledger — a LEDGERED claim was still reported" >&2; exit 1; }
    grep -q 'postgres-age' <<<"$out" || {
        echo "FAIL: self-test ledger — the unledgered claim was not reported" >&2; exit 1; }
    echo "PASS: self-test ledger — suppresses exactly its own key and nothing else"

    write_clean
    printf 'README.md Code Coverage #1\n' > "$led"
    [[ "$(run_fixture)" = "0" ]] || { echo "FAIL: self-test ledger — a STALE entry FAILED the gate" >&2; exit 1; }
    run_fixture_out | grep -q 'ledger entry is STALE' || {
        echo "FAIL: self-test ledger — a STALE entry produced no NOTICE (the ledger can rot)" >&2; exit 1; }
    echo "PASS: self-test ledger — a STALE entry is a loud NOTICE, not a failure"

    write_clean
    printf 'README.md\n' > "$led"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test ledger — a MALFORMED entry did not fail" >&2; exit 1; }
    run_fixture_out | grep -q 'malformed entry' || {
        echo "FAIL: self-test ledger — malformed entry not named" >&2; exit 1; }
    echo "PASS: self-test ledger — a MALFORMED entry HARD-FAILS"

    # ---- fail CLOSED on an analysis-engine error (CB-2 / #2713) -------
    # An internal engine error (a UnicodeDecodeError on one non-UTF-8 byte
    # in a scanned doc; a logic bug) must NEVER print PASS. R-203: first
    # reproduce the pre-fix SHAPE — `x="$(crashing-python)" || true` —
    # which swallows a crash into an empty value and would print a false
    # PASS; then prove the FIXED gate fails closed under an injected fault.
    write_clean
    prefix_shape="$(v="$(python3 -c 'import sys; sys.exit(3)')" || true; [[ -z "$v" ]] && echo "WOULD-PRINT-PASS")"
    [[ "$prefix_shape" == "WOULD-PRINT-PASS" ]] || {
        echo "FAIL: self-test R-203 — the pre-fix \`|| true\` shape did not reproduce the false-PASS fail-open" >&2; exit 1; }
    fault_rc=0
    fault_out="$(AI_MEMORY_CIJOB_GATE_ROOT="$FIX" AI_MEMORY_CIJOB_GATE_SELFTEST_FAULT=1 "$SELF" 2>&1)" || fault_rc=$?
    [[ "$fault_rc" -ne 0 ]] || {
        echo "FAIL: self-test #2713 — the gate exited 0 on an injected analysis-engine fault (fail-OPEN)" >&2
        printf '%s\n' "$fault_out" | sed 's/^/       /' >&2; exit 1; }
    grep -q 'gate: PASS' <<<"$fault_out" && {
        echo "FAIL: self-test #2713 — the gate printed a PASS banner despite an engine fault" >&2; exit 1; }
    grep -q 'analysis engine errored' <<<"$fault_out" || {
        echo "FAIL: self-test #2713 — engine fault did not produce the distinct fail-closed message" >&2; exit 1; }
    echo "PASS: self-test #2713 — an analysis-engine error FAILS CLOSED (exit $fault_rc, distinct message, no PASS banner)"

    # ================================================================
    # #2977 — the GitHub-Pages (.html) surface
    # ================================================================
    # THE DEFECT: the html half of DOCS was a THREE-FILE allowlist AND
    # every citation regex required a MARKDOWN code span, so a bench /
    # CI-enforcement claim on any of the other ~70 published Jekyll pages
    # was invisible for TWO independent reasons. Campaign finding C6 is
    # the verbatim shape planted below.

    # ---- RED: an enforcement claim on a page that was NOT in the old
    # three-file html allowlist, written in the HTML code-span dialect.
    write_clean
    printf '<li>Published p95/p99 budgets + CI guard (<code>bench.yml</code>)</li>\n' \
        > "$FIX/docs/at-a-glance.html"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test #2977 — an html-dialect enforcement claim on an enroll-by-default page was ACCEPTED." >&2
        echo "       bench.yml is advisory; this is the C6 shape and the gate must see it." >&2
        exit 1; }
    out="$(run_fixture_out)"
    grep -q 'WORKFLOW_ENFORCEMENT' <<<"$out" || {
        echo "FAIL: self-test #2977 — rejected, but NOT by the enforcement rule (wrong reason)" >&2; exit 1; }
    grep -q 'docs/at-a-glance.html' <<<"$out" || {
        echo "FAIL: self-test #2977 — the violation did not name the html page" >&2; exit 1; }
    echo "PASS: self-test #2977 RED — an html <code>-span enforcement claim on an enroll-by-default page is REJECTED"

    # ---- GREEN-on-fixed: the corrected advisory phrasing PASSES, so the
    # rule is not a blanket ban on naming bench.yml from an html page.
    write_clean
    printf '<li>Published p95/p99 budgets + advisory bench regression check (<code>bench.yml</code>)</li>\n' \
        > "$FIX/docs/at-a-glance.html"
    [[ "$(run_fixture)" = "0" ]] || {
        echo "FAIL: self-test #2977 GREEN — the CORRECTED advisory phrasing was still rejected" >&2
        run_fixture_out | sed 's/^/       /' >&2
        exit 1; }
    echo "PASS: self-test #2977 GREEN — the corrected advisory phrasing on the same html page PASSES"

    # ---- RED: html-dialect JOB_EXISTS. The verbatim
    # docs/reproducible-baselines.html shape — a `<workflow> · <job-key>`
    # composite display name that resolves to no declared job.
    write_clean
    printf 'the advisory <code>Bench &middot; bench</code> CI job\n' \
        > "$FIX/docs/at-a-glance.html"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test #2977 — an html-dialect citation of a non-existent CI job was ACCEPTED" >&2; exit 1; }
    run_fixture_out | grep -q 'JOB_EXISTS' || {
        echo "FAIL: self-test #2977 — rejected, but NOT by the existence rule (wrong reason)" >&2; exit 1; }
    echo "PASS: self-test #2977 RED — an html-dialect citation of a job that resolves to nothing is REJECTED"

    # ---- FROZEN EXEMPTION is load-bearing, in BOTH directions. The very
    # same claim on a page listed in html-doc-frozen-exempt.txt must PASS:
    # a "what's new in vN" page is, by construction, a statement about vN.
    write_clean
    printf '<li>Published p95/p99 budgets + CI guard (<code>bench.yml</code>)</li>\n' \
        > "$FIX/docs/whats-new-v09.html"
    [[ "$(run_fixture)" = "0" ]] || {
        echo "FAIL: self-test #2977 — a FROZEN page (html-doc-frozen-exempt.txt) was scanned" >&2
        run_fixture_out | sed 's/^/       /' >&2
        exit 1; }
    echo "PASS: self-test #2977 — a page named in html-doc-frozen-exempt.txt is EXEMPT (the same claim passes there)"

    # ---- the exemption SSOT is REQUIRED: resolving the html scan set
    # without its frozen boundary would either red every frozen page or
    # silently drop the widening. Refuse instead.
    write_clean
    mv "$FIX/scripts/qc-allowlists/html-doc-frozen-exempt.txt" "$FIX/exempt.bak"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test #2977 — a MISSING frozen-exemption SSOT did not fail the gate" >&2; exit 1; }
    run_fixture_out | grep -q 'html-doc-frozen-exempt.txt' || {
        echo "FAIL: self-test #2977 — the missing-SSOT failure did not name the file" >&2; exit 1; }
    mv "$FIX/exempt.bak" "$FIX/scripts/qc-allowlists/html-doc-frozen-exempt.txt"
    echo "PASS: self-test #2977 — a missing frozen-exemption SSOT FAILS CLOSED"

    # ---- never a silent no-op ----------------------------------------
    rm -rf "$FIX/.github/workflows"
    mkdir -p "$FIX/.github/workflows"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test — an EMPTY workflow set passed; the gate can no-op to green (#2444 shape)" >&2; exit 1; }
    echo "PASS: self-test — an empty workflow set fails CLOSED rather than reporting an unearned pass"
    exit 0
fi

if [[ -n "${AI_MEMORY_CIJOB_GATE_ROOT:-}" ]]; then
    REPO_ROOT="$AI_MEMORY_CIJOB_GATE_ROOT"
else
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
cd "$REPO_ROOT"

LEDGER="$REPO_ROOT/scripts/qc-allowlists/ci-job-claims-pending.txt"
REQUIRED_MIRROR="$REPO_ROOT/scripts/qc-allowlists/required-contexts-release.txt"

wf_count="$(find "$REPO_ROOT/.github/workflows" -maxdepth 1 -name '*.yml' 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$wf_count" -eq 0 ]]; then
    printf 'FAIL: ci-job-claims: ZERO workflows found under .github/workflows (gate would be a no-op)\n' >&2
    exit 1
fi

if ! violations="$(
    REPO_ROOT="$REPO_ROOT" REQUIRED_MIRROR="$REQUIRED_MIRROR" python3 - <<'PY'
import glob
import os
import re

root = os.environ["REPO_ROOT"].rstrip("/")
mirror_path = os.environ["REQUIRED_MIRROR"]

# Self-test fault-injection (#2713): when this env var is set the analysis
# engine raises, so the gate's own --self-test can prove the gate FAILS
# CLOSED (exits non-zero, prints no PASS) on an engine error instead of
# swallowing it into an empty violation set. Never set in production / CI.
if os.environ.get("AI_MEMORY_CIJOB_GATE_SELFTEST_FAULT"):
    raise RuntimeError("check-ci-job-claims self-test: injected analysis-engine fault (#2713)")


def yaml_scalar(raw):
    """The real YAML scalar rule, mirroring scripts/check-required-contexts.sh.

    A `#` PRECEDED BY WHITESPACE opens a comment; `(#1174 PR10)` does
    not. Reproducing it here is not decoration: a job whose DECLARED
    name differs from the name GitHub reports is exactly how the #2473
    truncated context entered the live required set, and a doc citing
    the untruncated name must still resolve.
    """
    raw = raw.strip()
    if raw[:1] in ('"', "'") and len(raw) > 1:
        q = raw[0]
        end = raw.find(q, 1)
        if end != -1:
            return raw[1:end]
    m = re.search(r"\s#", raw)
    if m:
        raw = raw[: m.start()]
    return raw.strip()


# ---- parse workflows -------------------------------------------------
workflows = {}            # basename -> {"jobs": {key: name}, "wfname": str}
resolvable = set()        # every token a doc may legitimately cite
for path in sorted(glob.glob(os.path.join(root, ".github/workflows/*.yml"))):
    base = os.path.basename(path)
    jobs, wfname, in_jobs, cur = {}, None, False, None
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if re.match(r"^name:\s*\S", line):
            wfname = yaml_scalar(line.split(":", 1)[1])
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if in_jobs and re.match(r"^\S", line):
            in_jobs = False
        if not in_jobs:
            continue
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            cur = m.group(1)
            jobs[cur] = cur
            continue
        m = re.match(r"^    name:\s*(\S.*)$", line)
        if m and cur:
            jobs[cur] = yaml_scalar(m.group(1))
    # A `workflow_dispatch`-ONLY workflow can never be a required PR
    # status check — it runs only when a human presses the button. It is
    # therefore exempt from the ENFORCEMENT rule (never from EXISTENCE):
    # demanding that `release.yml` appear in the required-context mirror
    # would be incoherent, and "operator-gated" is a true statement about
    # it. A `schedule:`-only nightly is NOT exempt: claiming a nightly
    # gates a pull request is exactly the false-enforcement shape.
    body = open(path, encoding="utf-8").read()
    triggers = set(re.findall(r"^  (push|pull_request|schedule|workflow_dispatch|workflow_run):",
                              body, re.MULTILINE))
    workflows[base] = {
        "jobs": jobs,
        "wfname": wfname,
        "dispatch_only": triggers == {"workflow_dispatch"},
    }
    resolvable.add(base)
    resolvable.add(base[:-4] if base.endswith(".yml") else base)
    if wfname:
        resolvable.add(wfname)
    for key, name in jobs.items():
        resolvable.add(key)
        resolvable.add(name)
        # A matrix name resolves both with the placeholder intact and
        # with it stripped (`Check (${{ matrix.os }})` vs `Check`).
        stripped = re.sub(r"\s*\(\$\{\{[^}]*\}\}\)\s*$", "", name).strip()
        if stripped:
            resolvable.add(stripped)

required = set()
if os.path.exists(mirror_path):
    for line in open(mirror_path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line:
            required.add(line)


def workflow_is_required(base):
    """At least one job of this workflow is a declared required context."""
    wf = workflows.get(base)
    if not wf:
        return False
    for name in wf["jobs"].values():
        if name in required:
            return True
        stripped = re.sub(r"\s*\(\$\{\{[^}]*\}\}\)\s*$", "", name).strip()
        if any(r == stripped or r.startswith(stripped + " (") for r in required):
            return True
    return False


def job_is_required(token):
    if token in required:
        return True
    return any(r.startswith(token + " (") for r in required)


# #2977 — the html half of this corpus was a THREE-FILE allowlist, so the
# bench / CI-enforcement claims on the other ~70 published Jekyll pages
# were unscanned (campaign finding C6: at-a-glance.html's bench claim).
# The html set is now ENROLL-BY-DEFAULT over `docs/**/*.html` minus the
# frozen pages named in scripts/qc-allowlists/html-doc-frozen-exempt.txt —
# the SAME exemption SSOT scripts/check-docs-vs-ssot.sh reads, so the two
# gates cannot disagree about where the frozen boundary sits. An
# enumerated INCLUDE list cannot close this class: the rot is exactly that
# a NEW page lands unscanned.
#
# FAIL-CLOSED on a missing exemption file: resolving the scan set without
# its boundary would either red every frozen page or silently drop the
# widening, and both are worse than refusing.
exempt_path = os.path.join(root, "scripts/qc-allowlists/html-doc-frozen-exempt.txt")
html_frozen = []
if os.path.exists(exempt_path):
    for line in open(exempt_path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line:
            html_frozen.append(line)
elif os.path.exists(os.path.join(root, "docs")):
    raise RuntimeError(
        "check-ci-job-claims: missing scripts/qc-allowlists/html-doc-frozen-exempt.txt "
        "— refusing to resolve the html scan set without its frozen-page exemption SSOT (#2977)"
    )

html_docs = sorted(
    p[len(root) + 1:]
    for p in glob.glob(os.path.join(root, "docs/**/*.html"), recursive=True)
    if not any(frozen in p[len(root) + 1:] for frozen in html_frozen)
)

DOCS = ["README.md", "ROADMAP.md", "PERFORMANCE.md",
        "docs/DEVELOPER_GUIDE.md", "docs/ENGINEERING_STANDARDS.md",
        "docs/CLI_REFERENCE.md", "docs/CONFIG_SCHEMA.md",
        ] + html_docs + sorted(glob.glob(
    os.path.join(root, "docs/v1.0.0/*.md")))

# YAML trigger / structural keywords are not job names.
NOT_A_JOB = {
    "workflow_dispatch", "pull_request", "push", "schedule", "cron",
    "workflow_run", "jobs", "steps", "runs-on", "needs", "matrix", "on",
}

# A claim of ENFORCEMENT: the doc says the thing blocks something.
#
# A HYPHEN-PREFIXED `-gated` is deliberately EXCLUDED, and the carve-out
# is structural rather than a growing list of phrases. `X-gated` is a
# COMPOUND ADJECTIVE naming what gates something, never a claim that a CI
# job blocks a merge: `operator-gated` is human release authority
# (CLAUDE.md's tag-cut gate), `#[ignore]-gated` is a Rust test attribute,
# and `feature-gated` / `admin-gated` are compile and authz concepts.
# Enumerating them one at a time would have failed on the next one — and
# it did: the first cut excluded only `operator-gated` and then
# false-flagged `docs/v1.0.0/release-notes.md` for the phrase "four
# `#[ignore]`-gated cross-backend parity binaries", which makes no
# enforcement claim at all.
#
# The real claims all read `gates <something>` / `gated <by|nightly>` with
# a SPACE before the verb, so requiring a non-hyphen predecessor keeps
# every true positive (C-31's "gates every PR and trunk push", C-23's
# "gated **nightly** by the `postgres-age` CI job") while dropping the
# adjectival class wholesale.
ENFORCE = re.compile(
    r"(?<!-)(?<!operator )\bgates?\b|(?<!-)(?<!operator )\bgating\b|"
    r"(?<!-)(?<!operator )\bgated\b|blocks? merge|blocked from merging|"
    r"fails? the PR|is required\b|required[- ]status|must pass\b|"
    r"hard[- ]block|CI gate\b|CI guard\b",
    re.IGNORECASE,
)

# How far from a citation an enforcement verb may sit and still be read
# as attaching TO IT. Line-level attribution alone is too coarse: a
# ROADMAP "Code anchors" line names five workflows and one gate, and
# only one of the five is the gate's subject. 90 characters comfortably
# spans "`bench.yml` ... gates every PR" and the "`X` CI guard" /
# "gated nightly by the `Y` CI job" shapes, without reaching across a
# markdown table cell boundary into an unrelated clause.
ENFORCE_PROXIMITY = 90


def enforcement_near(line, start, end):
    """Is an enforcement verb close enough to attach to this citation?"""
    lo = max(0, start - ENFORCE_PROXIMITY)
    hi = min(len(line), end + ENFORCE_PROXIMITY)
    return bool(ENFORCE.search(line[lo:hi]))

# MARKUP DIALECT (#2977). The citation shapes below were written against
# MARKDOWN code spans. Adding the .html corpus to DOCS without teaching
# them the html spelling would have been a widening that scans 53 more
# pages and can see NOTHING on them — the #2444 "reports success while
# doing nothing" shape, in the very gate built to catch that class.
# `CO`/`CC` therefore admit BOTH `` ` `` and `<code>`/`</code>`; a .md
# file never contains `<code>` and a .html file never contains a code
# backtick, so neither dialect widens the other's match set.
#
# Measured effect on the tree at 57b7fe35: the citation
# `<li>Published p95/p99 budgets + CI guard (<code>bench.yml</code>)</li>`
# in docs/at-a-glance.html is invisible to a backtick-only WF_TICK and is
# an ENFORCEMENT claim about an advisory workflow once seen.
CO = r"(?:`|<code>)"
CC = r"(?:`|</code>)"

WF_PATH = re.compile(r"\.github/workflows/([A-Za-z0-9_.-]+\.ya?ml)")
WF_TICK = re.compile(CO + r"([A-Za-z0-9_.-]+\.ya?ml)" + CC)
POSSESSIVE = re.compile(
    CO + r"([A-Za-z0-9_.-]+\.ya?ml)" + CC + r"'s\s+(?:\"([^\"]+)\"|"
    + CO + r"([^`<]+)" + CC + r")\s+job")
# `<stem>` workflow -- the bare-stem citation shape (3x7 lane-3,
# 2026-08-09). README said "The `token-budget` workflow is a **required
# status check**" while `token-budget` appears NOWHERE in
# required-contexts-release.txt. Neither WF_TICK (needs a .yml suffix)
# nor JOB_CITE (needs the literal word "job") could see it, so the
# ENFORCEMENT rule -- the rule built for exactly that false claim --
# was structurally blind to the single most-quoted enforcement
# sentence in the tier-1 doc. Resolves the stem to <stem>.yml.
WF_WORD = re.compile(CO + r"([A-Za-z0-9_.-]{2,40})" + CC + r"\s+workflow\b")
JOB_CITE = re.compile(
    r"(?:" + CO + r"([^`<\n]{2,60})" + CC + r"|\"([^\"\n]{2,60})\")"
    r"\s+(?:CI\s+|nightly\s+)?job\b")
JOB_IN_WF = re.compile(
    CO + r"(?:\.github/workflows/)?([A-Za-z0-9_.-]+\.ya?ml)" + CC + r"\s*[,)]?\s*"
    r"(?:the\s+)?([A-Za-z0-9_][A-Za-z0-9_ -]{0,28}?)\s+job\b")


def emit(rule, f, ln, token, ctx, detail):
    print(f"{rule}\t{f}\t{ln}\t{token}\t{ctx[:150]}\t{detail}")


for d in DOCS:
    p = d if os.path.isabs(d) else os.path.join(root, d)
    rel = p[len(root) + 1:] if p.startswith(root + "/") else p
    try:
        text = open(p, encoding="utf-8").read()
    except OSError:
        continue
    for ln, line in enumerate(text.splitlines(), 1):
        ctx = line.strip()

        # ---- workflow FILE existence ---------------------------------
        cited_wfs = {}
        for m in WF_PATH.finditer(line):
            cited_wfs.setdefault(m.group(1), (m.start(), m.end()))
            if not os.path.exists(os.path.join(root, ".github/workflows", m.group(1))):
                emit("WORKFLOW_FILE", rel, ln, m.group(1), ctx,
                     "no such file under .github/workflows/")
        for m in WF_TICK.finditer(line):
            name = m.group(1)
            if os.path.exists(os.path.join(root, ".github/workflows", name)):
                cited_wfs.setdefault(name, (m.start(), m.end()))
                continue
            # A `.yml` that is not a workflow is fine as long as it
            # exists SOMEWHERE in the tree (compose files, fixtures).
            if not glob.glob(os.path.join(root, "**", name), recursive=True):
                emit("YAML_FILE", rel, ln, name, ctx, "cited .yml exists nowhere in the tree")
        for m in WF_WORD.finditer(line):
            stem = m.group(1)
            if stem.endswith((".yml", ".yaml")):
                continue
            for cand in (stem + ".yml", stem + ".yaml"):
                if os.path.exists(os.path.join(root, ".github/workflows", cand)):
                    cited_wfs.setdefault(cand, (m.start(), m.end()))
                    break

        # ---- named JOB existence -------------------------------------
        cited_jobs = []
        for m in POSSESSIVE.finditer(line):
            cited_jobs.append((m.group(2) or m.group(3), m.group(1), m.start(), m.end()))
        for m in JOB_CITE.finditer(line):
            cited_jobs.append(((m.group(1) or m.group(2)), None, m.start(), m.end()))
        for m in JOB_IN_WF.finditer(line):
            cited_jobs.append((m.group(2).strip(), m.group(1), m.start(), m.end()))

        seen = set()
        for token, owner, c_start, c_end in cited_jobs:
            token = (token or "").strip()
            if not token or token in NOT_A_JOB or (token, owner) in seen:
                continue
            seen.add((token, owner))
            if owner:
                wf = workflows.get(owner)
                if wf is not None and token not in wf["jobs"] \
                        and token not in wf["jobs"].values():
                    emit("JOB_IN_WORKFLOW", rel, ln, f"{owner}:{token}", ctx,
                         f"{owner} declares no job named or keyed '{token}'")
                    continue
            if token not in resolvable:
                emit("JOB_EXISTS", rel, ln, token, ctx,
                     "resolves to no job name, job key, or workflow in .github/workflows/")
                continue
            if enforcement_near(line, c_start, c_end) and not job_is_required(token) \
                    and not (owner and workflow_is_required(owner)):
                emit("JOB_ENFORCEMENT", rel, ln, token, ctx,
                     "claimed to gate/block, but it is not a required status check "
                     "(absent from scripts/qc-allowlists/required-contexts-release.txt)")

        # ---- workflow-level ENFORCEMENT claim ------------------------
        for base in sorted(cited_wfs):
            span = cited_wfs[base]
            if enforcement_near(line, span[0], span[1]):
                if base in workflows and not workflows[base]["dispatch_only"] \
                        and not workflow_is_required(base):
                    emit("WORKFLOW_ENFORCEMENT", rel, ln, base, ctx,
                         "claimed to gate/block, but NO job of this workflow is a required "
                         "status check (absent from scripts/qc-allowlists/required-contexts-release.txt)")
PY
)"; then
    # FAIL CLOSED (#2713): the analysis engine exited non-zero (an
    # uncaught exception — e.g. a UnicodeDecodeError on one non-UTF-8 byte
    # in a scanned doc, or the injected self-test fault). The pre-fix
    # `|| true` swallowed that into an empty violation set and printed a
    # FALSE "PASS". Refuse loudly instead of attesting to work never done.
    printf 'FAIL: check-ci-job-claims: analysis engine errored (python exited non-zero) — refusing to report PASS (#2713 fail-closed)\n' >&2
    exit 2
fi

# ---- PENDING-FIX ledger ---------------------------------------------
# Format: `<doc-file> <token> #<issue> <note>`; token is the workflow
# file, the job name, or `<workflow>:<job>` exactly as the gate reports
# it. Job names contain spaces, so the token is everything between the
# doc path and the `#`.
ledger_keys=""
ledger_used=""
fail_count=0

if [[ -f "$LEDGER" ]]; then
    while IFS= read -r raw; do
        entry="${raw%%#*}"
        entry="$(printf '%s' "$entry" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [[ -z "$entry" ]] && continue
        docfile="${entry%% *}"
        token="${entry#* }"
        token="$(printf '%s' "$token" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        if [[ -z "$docfile" || -z "$token" || "$docfile" == "$token" ]] \
            || ! grep -qE '#[0-9]+' <<<"$raw"; then
            printf 'FAIL: ci-job-claims ledger: malformed entry "%s"\n' "$raw" >&2
            printf '       expected: <doc-file> <token> #<issue>\n' >&2
            fail_count=$((fail_count + 1))
            continue
        fi
        ledger_keys="${ledger_keys}${docfile}|${token}"$'\n'
    done < "$LEDGER"
fi

if [[ -n "$violations" ]]; then
    while IFS=$'\t' read -r rule f ln token ctx detail; do
        [[ -z "${rule:-}" ]] && continue
        key="${f}|${token}"
        if [[ -n "$ledger_keys" ]] && grep -Fxq "$key" <<<"$ledger_keys"; then
            ledger_used="${ledger_used}${key}"$'\n'
            continue
        fi
        printf 'FAIL: ci-job-claims [%s]: %s:%s cites "%s" — %s\n' \
            "$rule" "$f" "$ln" "$token" "$detail" >&2
        printf '       context: %s\n' "$ctx" >&2
        fail_count=$((fail_count + 1))
    done <<<"$violations"
fi

if [[ -n "$ledger_keys" ]]; then
    while IFS= read -r k; do
        [[ -z "$k" ]] && continue
        if ! grep -Fxq "$k" <<<"$ledger_used"; then
            printf 'NOTICE: ci-job-claims ledger entry is STALE (suppresses nothing) — delete it: %s\n' \
                "$(tr '|' ' ' <<<"$k")" >&2
        fi
    done < <(sort -u <<<"$ledger_keys")
fi

if [[ "$fail_count" -gt 0 ]]; then
    printf '\n❌ named-CI-job existence + enforcement-truthfulness gate: %d violation(s)\n' "$fail_count" >&2
    printf '   Either fix the prose, or make the claim true.\n' >&2
    exit 1
fi
printf '✅ named-CI-job existence + enforcement-truthfulness gate: PASS (%s workflows parsed)\n' "$wf_count"
