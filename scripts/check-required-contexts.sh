#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# v1.0.0 required-context SOUNDNESS gate (#2494 / #2496) — FAIL-CLOSED.
#
# THE DEFECT CLASS THIS CLOSES. A branch-protection required-status-check set
# reads as N gates and can FUNCTION as far fewer. Three independent ways, all
# observed live on `release/v1.0.0`:
#
#   (1) THE WEDGE (#2494). `ci.yml` job `mobile-cross-compile` was BOTH a
#       `strategy: matrix` job AND carried a job-level
#       `if: needs.classify.outputs.docs_only != 'true'`. GitHub evaluates a
#       job-level `if:` BEFORE matrix expansion, so a skipped matrix job emits
#       exactly ONE check-run bearing the UNEXPANDED template name. Probed on
#       docs-only commit 45ba8741:
#           skipped  Cross-compile (${{ matrix.target }})
#           Cross-compile (aarch64-apple-ios)      present: 0
#           Cross-compile (aarch64-linux-android)  present: 0
#       Both of those absent names ARE required contexts. An absent required
#       context is `pending` indefinitely and `enforce_admins: true` means no
#       admin merge clears it — the branch wedges for that PR shape. On the
#       SAME commit `Check (ubuntu/macos/windows-latest)` all EXPANDED and
#       reported `success`, because the `check` job carries NO job-level `if:`
#       and guards every STEP instead. That contrast is the whole rule: a
#       matrix job whose name carries a required context must never take a
#       job-level `if:`.
#
#   (2) THE SKIPPED-COUNTS-AS-SATISFIED FAIL-OPEN. A non-matrix required job
#       with a job-level `if:` reports `skipped`, which GitHub counts as
#       SATISFIED. Eight required contexts do this on a docs-only diff. That
#       is only safe while the classifier is correct — and it was not (#2496:
#       PR #2031 merged 22 non-docs files to `main` with zero compilation).
#       Rule (b2) is therefore a RATCHET, not a ban: the existing eight are
#       allowlisted with a dated justification and the list may only SHRINK.
#
#   (2-bis) THE UNREQUIRED DECIDER (#2494 residual). The job that DECIDES the
#       skipped/ran disposition of case (2) was not itself a required context.
#       `Classify changes` (ci.yml) and `Coverage classify (docs-only
#       short-circuit)` (coverage.yml) between them governed ELEVEN required
#       contexts while being required by nothing — so the whole ratchet in
#       case (2) rested on a job no gate protected. Both are now declared in
#       the mirror. Requiring a decider is free (it always runs; it reported
#       `success` even on the docs-only commit 45ba8741 that wedged the branch)
#       but it creates a NEW obligation, which rule (b4) enforces: a decider
#       must never acquire a job-level `if:`. A skipped decider skips every
#       dependent, and each skipped dependent counts as SATISFIED — so ONE
#       allowlisted decider would neutralise its entire dependent subtree at
#       once. That is why (b4) is a hard fail and NOT ratchetable, unlike (b2).
#
#   (3) THE UNREPORTABLE CONTEXT. A required context whose carrying workflow
#       has a `paths:` / `paths-ignore:` filter on its `pull_request` trigger
#       simply never runs for an out-of-filter PR — the context is never
#       created and the branch wedges exactly as in (1), with no `if:` in
#       sight. Rule (c).
#
#   (4) THE CANCELLED DUPLICATE (#2508). A workflow that triggers on BOTH
#       `push` and `pull_request`, whose `push.branches` patterns can match a
#       PR HEAD branch, under a `concurrency` group that resolves to the SAME
#       key for both events with `cancel-in-progress: true`. Every push to
#       that head branch starts two runs for ONE sha in one group, so one is
#       ALWAYS cancelled — guaranteed, not occasional — and the cancelled
#       check-run row is PERMANENT. Live on `tool-count-drift.yml` and caught
#       on PRs #2499 + #2505 simultaneously:
#           #2499  tool-count grep gate  CANCELLED  run 30532798041  event=push
#           #2499  tool-count grep gate  SUCCESS    run 30532801197
#       `cancelled` is a FIFTH disposition that READS AS PASS in
#       `gh pr checks` (it renders a cancelled run's rows as `pass`) while
#       branch protection does not count it as satisfied — so the standard
#       triage command conceals it, and the day the context is added to
#       `required_status_checks.contexts` the branch wedges on every PR from
#       such a branch with the cause invisible in the obvious place. That is
#       why rule (d) is scoped to EVERY workflow in the directory and not
#       merely to today's required-context carriers: the artefact pollutes any
#       PR's rollup and becomes a wedge the moment the context is required.
#       The carrier itself was fixed in #2509 (trigger narrowing); rule (d) is
#       the structural half that keeps the shape from re-landing.
#
# DATA-INTEGRITY posture (North Star): a required-check set that reads as 22
# gates and functions as 9 is a control that reports success while doing
# nothing — the "defaults lie" class. This gate DEGRADES a drifting
# configuration to a loud non-zero exit rather than letting an unvalidated
# change merge behind green checks. Fail-closed, never fail-silent: anything
# this parser cannot resolve with confidence is a FAILURE, not a pass.
#
# WHY STATIC, AND WHY A COMMITTED MIRROR. The branch-protection API needs an
# admin-scoped token; the Actions `GITHUB_TOKEN` does not have it. So the gate
# runs STATICALLY at PR time against a hand-authored mirror of the required
# set at `scripts/qc-allowlists/required-contexts-release.txt`.
#
#   *** THE MIRROR IS HAND-AUTHORED FROM INTENT. NEVER GENERATE IT FROM LIVE
#   *** API STATE. The canonical demonstration is #2473: one required context
#   *** WAS
#   ***     L3-boundary perma-ban gate (§25.3 S5 / RQ-10
#   *** a YAML TRUNCATION ARTIFACT — `c8-precheck.yml` wrote the job name
#   *** UNQUOTED as `... / RQ-10 #1853)`, and in YAML a `#` PRECEDED BY
#   *** WHITESPACE opens a comment, so the parsed job name (and therefore the
#   *** check-run GitHub reported, and therefore the required context an
#   *** operator copied off a PR) stopped at `RQ-10`. It MATCHED, so the gate
#   *** was green on a name nobody intended. Had the mirror been regenerated
#   *** from live state the truncation would have been laundered into the
#   *** declaration and rule (a) would be a tautology that passes forever —
#   *** that is the failure mode this warning exists for, and it is why the
#   *** truncation was deliberately preserved here until the coupled fix.
#   ***
#   *** #2473 CLOSED it: the workflow name is now QUOTED, this mirror declares
#   *** the FULL string, and NEW RULE (e) hard-fails ANY job whose unquoted
#   *** `name:` contains ` #`, so the class cannot re-land silently. The
#   *** hand-authored-from-intent rule is UNCHANGED and is the reason the
#   *** defect was visible at all.
#
#   (Contrast: `(#1174 PR10)` / `(#2146)` / `(#1989)` names do NOT truncate,
#   because there the `#` is preceded by `(`, not whitespace. This parser
#   implements the real YAML rule, so it reproduces both outcomes.)
#
# RULES — any one => exit 1:
#   (a) every mirror context equals a parsed static job `name`, or an EXPANDED
#       matrix name, belonging to a workflow whose `pull_request.branches`
#       covers the protected branch the mirror scopes to.
#   (b1) HARD-FAIL, never allowlistable: a required context's job has BOTH
#       `strategy.matrix` AND a job-level `if:` — the exact #2494 wedge shape.
#   (b4) HARD-FAIL, never allowlistable: a required context's job is a
#       DECIDER — at least one other job in the same workflow declares
#       `needs: <that job id>` — AND it carries a job-level `if:`. See
#       case (2-bis): a skipped decider skips its whole dependent subtree,
#       every member of which then counts as satisfied.
#   (b2) a required context's job has a job-level `if:` at all (the
#       skipped-counts-as-satisfied class) => fail unless the context is
#       listed in the burn-down ratchet
#       `scripts/qc-allowlists/required-contexts-joblevel-if-allow.txt`
#       (`hardcoded-literals-baseline.txt` style: entries may only be
#       REMOVED; a STALE entry — one whose job no longer has a job-level
#       `if:`, or which is no longer a required context — also fails, so the
#       ratchet cannot silently rot).
#   (e) HARD-FAIL, never allowlistable, for ANY job in ANY workflow in the
#       directory (not only required-context carriers): a job `name:` written
#       as an UNQUOTED scalar whose raw value contains whitespace-then-`#`.
#       That is the #2473 shape — YAML silently truncates the name at the
#       `#`, so the DECLARED name and the check-run GitHub actually reports
#       differ, and an operator copying the reported name into branch
#       protection pins the truncation. The remedy is one character of
#       quoting, so there is no legitimate instance and no ratchet: write
#       `name: "… #1853)"`. A name whose `#` is preceded by `(` — the
#       `(#1174 PR10)` / `(#2146)` / `(#1989)` family — does NOT truncate and
#       is NOT flagged, which is what keeps this rule aimed at the defect
#       rather than at the neighbourhood. A deliberate trailing YAML comment
#       on a name line is still expressible: quote the scalar first
#       (`name: "Foo"  # note`) and the rule passes.
#       Scope is repo-wide by the rule-(d) argument: a truncated name is a
#       declared≠actual lie in every UI today and becomes a branch wedge the
#       moment someone requires that context.
#   (c) the carrying workflow's `pull_request` trigger exists and has NO
#       `paths:` / `paths-ignore:` filter.
#   (b3) in ANY job with `needs: classify` and NO job-level `if:`, EVERY step
#       carries a `docs_only` guard. One unguarded step silently runs the
#       heavy work on docs-only PRs (or, worse, half-runs it). The single
#       structural exemption is a bare `actions/checkout@*` step, which is
#       what the `check` job's proven pattern does.
#   (d) HARD-FAIL for ANY workflow in the directory (not only required-context
#       carriers — see case (4)): it triggers on BOTH `push` and
#       `pull_request` (i), at least one `push.branches` pattern can match a
#       PR HEAD branch (ii), and it declares a `concurrency.group` with
#       `cancel-in-progress: true` whose key is not event-distinct (iii).
#
#       (ii) is decided by `glob_match`-ing each pattern against the declared
#       PR_HEAD_PROBES corpus below — the same globbing routine rule (a) uses,
#       so the two rules cannot disagree about what a pattern means. `main` /
#       `develop` / `release/**` are deliberately NOT probes (this repo's base
#       branches; the residual merge-up-PR twin is declared at the corpus).
#
#       (iii) is a DELIBERATELY CONSERVATIVE structural test, not a general
#       expression evaluator: a group containing `github.event_name` is proven
#       event-distinct and exempt; anything else is treated as colliding. The
#       real evaluation is not needed to be sound in the safe direction, and
#       trying it would be the wrong kind of clever — the house key
#       (`… head.repo == repository && head.ref || pull_request.number ||
#       github.ref_name`) is precisely the shape that LOOKS event-aware and
#       collides anyway, because on a push event every `pull_request.*` term
#       is empty and the ternary falls through to `github.ref_name`. A rule
#       that had to be smart enough to see that is a rule that will be wrong
#       about the next expression; requiring the discriminator to be VISIBLE
#       is both checkable and the thing a reviewer can confirm by eye.
#       Cost of the conservatism: a group that separates the events some other
#       way is flagged and must either adopt `github.event_name` or take a
#       ledger entry. No such group exists in this repo.
#
#       A workflow with no `concurrency` block, or with
#       `cancel-in-progress: false`, is NOT flagged: it produces two SUCCESS
#       runs — wasteful, but no `cancelled` row, so not this defect class.
#
# CLI:
#   scripts/check-required-contexts.sh              — run the gate (exit 0/1)
#   scripts/check-required-contexts.sh --self-test  — plant the historical
#       shapes in a throwaway copy UNDER the repo (never system /tmp) and
#       confirm the gate rejects EACH: the (b1) matrix+`if:` wedge, an (a)
#       mirror context matching no job, the (e) #2473 unquoted ` #` job name
#       (which first asserts through `--dump` that the parse IS truncated at
#       the `#`, so a parser that quietly stopped truncating could not make
#       the rule fire for the wrong reason), a (c) `paths:`-filtered carrier, a
#       (b3) unguarded step in a `needs: classify` job, and a (b4) decider
#       carrying a job-level `if:` (rejected EVEN WHEN allowlisted, which is
#       the property that distinguishes (b4) from (b2)), and the (d) #2508
#       cancelled-duplicate carrier — planted as the VERBATIM pre-#2509
#       `tool-count-drift.yml` trigger + concurrency block (R-203), alongside
#       four near-miss shapes that must each PASS (the #2509-narrowed
#       triggers, `cancel-in-progress: false`, push-only, and an
#       `event_name`-keyed group) so the rule is proven to fire on the defect
#       rather than on the neighbourhood — plus a clean control that must
#       PASS. Proves the gate is load-bearing, not decorative.
#   scripts/check-required-contexts.sh --dump       — print the raw parse
#       record stream (diagnostic; shows which job `name:` was resolved, and
#       the PUSH / CONC records rule (d) decides on).
#
# Env overrides (so --self-test can point at planted fixtures):
#   RQC_WORKFLOW_DIR      (default <root>/.github/workflows)
#   RQC_MIRROR_FILE       (default <root>/scripts/qc-allowlists/required-contexts-release.txt)
#   RQC_ALLOW_FILE        (default <root>/scripts/qc-allowlists/required-contexts-joblevel-if-allow.txt)
#   RQC_DUPTRIG_ALLOW_FILE (default <root>/scripts/qc-allowlists/dual-trigger-cancel-allow.txt)
#   RQC_PROTECTED_BRANCH  (default release/v1.0.0)
#   RQC_CLASSIFY_JOB      (default classify)  — the job id rule (b3) keys on
#
# Mirrors the structure + `--self-test` convention of the sibling gates
# (`scripts/check-migration-ladder.sh`, `scripts/check-vendor-literals.sh`).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WORKFLOW_DIR="${RQC_WORKFLOW_DIR:-$ROOT/.github/workflows}"
MIRROR_FILE="${RQC_MIRROR_FILE:-$ROOT/scripts/qc-allowlists/required-contexts-release.txt}"
ALLOW_FILE="${RQC_ALLOW_FILE:-$ROOT/scripts/qc-allowlists/required-contexts-joblevel-if-allow.txt}"
DUPTRIG_ALLOW_FILE="${RQC_DUPTRIG_ALLOW_FILE:-$ROOT/scripts/qc-allowlists/dual-trigger-cancel-allow.txt}"
PROTECTED_BRANCH="${RQC_PROTECTED_BRANCH:-release/v1.0.0}"
CLASSIFY_JOB="${RQC_CLASSIFY_JOB:-classify}"

# --- rule (d) PR-HEAD PROBE CORPUS -----------------------------------------
#
# Rule (d) has to answer one question about a `push.branches` pattern: CAN it
# match a branch this repository opens pull requests FROM? That is not
# decidable from the pattern alone, so it is decided against a declared corpus
# of head-branch shapes and the answer is `glob_match(pattern, probe)` for some
# probe — the same globbing routine rule (a) uses, so the two rules cannot
# disagree about what a pattern means.
#
# Provenance of the corpus (measured 2026-07-30 over the 300 most recent PRs in
# this repo, cross-checked against the commit-type vocabulary CLAUDE.md pins,
# which is also the branch-prefix convention):
#     fix 150 · feat 38 · docs 35 · campaign 34 · test 8 · refactor 5 · ci 5
#     · chore 5 · sec 3 · security 1 · infra 1 · local 1
# plus `perf` / `build` / `style` / `coverage` / `qc` / `hotfix`, which are in
# the documented type vocabulary but have not been used as a head yet, and two
# STRUCTURAL probes — a slash-less topic branch and a deep nested name — so a
# bare `*` or `**` push pattern is caught even though no prefix matches it.
#
# DELIBERATELY ABSENT, and this is the load-bearing half: `main`, `develop` and
# `release/**`. They are this repo's BASE branches; the everyday PR flow never
# heads from them. The residual is DECLARED, not overlooked — a merge-up PR
# (`release/v0.9.0` -> `main`, 4 in repo history) does get the #2508 duplicate
# while it is open. Narrowing `push.branches` to exclude the protected branches
# would cost the push-event lane on the integration branch itself, which is the
# primary lane; that trade is worse than the twin, so the twin is accepted and
# named here rather than silently unmodelled.
#
# An exact LITERAL that happens to look like a head (`feat/v0.7.0-grand-slam`
# in coverage.yml) matches no probe and is therefore NOT flagged: it names one
# historical branch, it cannot match a CLASS of future heads, and a pattern
# that cannot match a class cannot carry the recurring defect.
PR_HEAD_PROBES=(
    fix/2508-probe feat/2508-probe docs/2508-probe chore/2508-probe
    ci/2508-probe test/2508-probe refactor/2508-probe perf/2508-probe
    infra/2508-probe build/2508-probe style/2508-probe coverage/2508-probe
    qc/2508-probe campaign/2508-probe sec/2508-probe security/2508-probe
    hotfix/2508-probe local/2508-probe
    topic-probe-2508
    fix/nested/2508-probe
)

FAILURES=0

fail() {
    printf '%s\n' "❌ required-contexts: $*" >&2
    FAILURES=$((FAILURES + 1))
}

# --- The YAML subset parser -------------------------------------------------
#
# Deliberately a narrow, indentation-driven scanner over THIS repo's workflow
# style (2-space indent, no tabs, jobs at indent 2, job keys at 4, steps at 6,
# step keys at 8) rather than a general YAML implementation — the house idiom
# is bash + awk with no new dependencies. It is fail-closed by construction:
# it emits only what it positively recognised, and an unrecognised or
# unexpandable shape leaves a mirror context UNMATCHED, which rule (a) fails.
#
# It correctly implements the two YAML scalar rules this gate turns on:
#   * a `#` PRECEDED BY WHITESPACE in an unquoted scalar opens a comment
#     (the `RQ-10 #1853)` truncation), while `(#1174` does not;
#   * a quoted scalar is taken verbatim with no comment stripping.
# It skips block scalars (`|` / `>`) entirely so a `run:` body can never be
# misread as workflow structure.
#
# Record stream (TAB-delimited; workflow files in this repo contain no tabs):
#   WF   <file> <pr_trigger> <pr_paths> <branches-csv>
#   PUSH <file> <push_trigger> <push-branches-csv>
#   CONC <file> <has_concurrency> <cancel_in_progress> <group-expr>
#   JOB  <file> <jobid> <name> <job_if> <has_matrix> <needs-csv> <name_truncation_risk>
#   MX   <file> <jobid> <key> <value>
#   STEP <file> <jobid> <idx> <has_if> <guarded> <uses> <name>
parse_workflows() {
    local f
    for f in "$WORKFLOW_DIR"/*.yml "$WORKFLOW_DIR"/*.yaml; do
        [ -f "$f" ] || continue
        awk -v FNAME="$(basename "$f")" '
        function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
        function indent(l,   n) { n = 0; while (substr(l, n + 1, 1) == " ") n++; return n }
        # YAML-faithful scalar extraction for a "key: value" tail.
        function scalar(v,   ch, q, out, i, c, p) {
            v = trim(v)
            if (v == "") return ""
            ch = substr(v, 1, 1)
            if (ch == "\"" || ch == "'"'"'") {
                q = ch; out = ""
                for (i = 2; i <= length(v); i++) {
                    c = substr(v, i, 1)
                    if (c == q) break
                    out = out c
                }
                return out
            }
            # unquoted: a "#" preceded by whitespace opens a comment
            for (i = 1; i <= length(v); i++) {
                if (substr(v, i, 1) != "#") continue
                if (i == 1) { v = ""; break }
                p = substr(v, i - 1, 1)
                if (p == " " || p == "\t") { v = substr(v, 1, i - 1); break }
            }
            return trim(v)
        }
        # Split a flow sequence "[a, b, \"c\"]" into scalars.
        function flowseq(v, out,   n, i, parts, item) {
            v = trim(v)
            if (substr(v, 1, 1) != "[") return 0
            sub(/^\[/, "", v); sub(/\][ \t]*$/, "", v)
            n = split(v, parts, ",")
            for (i = 1; i <= n; i++) {
                item = scalar(parts[i])
                if (item != "") out[++out[0]] = item
            }
            return out[0]
        }
        function flushstep() {
            if (cur_step > 0)
                printf "STEP\t%s\t%s\t%d\t%d\t%d\t%s\t%s\n", FNAME, job, cur_step, s_hasif, s_guard, s_uses, s_name
            cur_step = 0; s_hasif = 0; s_guard = 0; s_uses = ""; s_name = ""
        }
        # RULE (e) probe. 1 iff a job `name:` is an UNQUOTED scalar whose RAW
        # value contains whitespace-then-`#` — i.e. YAML silently truncated it
        # (the #2473 shape). Computed on the RAW tail, deliberately BEFORE
        # scalar() strips the comment, because after stripping the evidence is
        # gone. A quoted scalar is exempt: quoting is the fix, and it is also
        # how a deliberate trailing comment stays expressible.
        function name_truncation_risk(v,   ch, i, p) {
            v = trim(v)
            if (v == "") return 0
            ch = substr(v, 1, 1)
            if (ch == "\"" || ch == "'"'"'") return 0
            for (i = 2; i <= length(v); i++) {
                if (substr(v, i, 1) != "#") continue
                p = substr(v, i - 1, 1)
                if (p == " " || p == "\t") return 1
            }
            return 0
        }
        function flushjob() {
            flushstep()
            if (job != "")
                printf "JOB\t%s\t%s\t%s\t%d\t%d\t%s\t%d\n", FNAME, job, j_name, j_if, j_matrix, j_needs, j_namerisk
            job = ""; j_name = ""; j_if = 0; j_matrix = 0; j_needs = ""
            j_namerisk = 0
            in_steps = 0; in_strategy = 0; in_matrix = 0; in_include = 0
        }
        BEGIN {
            blockind = -1; section = ""; on_key = ""
            pr_trigger = 0; pr_paths = 0; branches = ""
            push_trigger = 0; push_branches = ""
            conc_seen = 0; conc_cancel = 0; conc_group = ""
            job = ""; cur_step = 0; j_namerisk = 0
            seqkey = ""; seqind = -1
        }
        {
            line = $0
            ind = indent(line)
            # --- block scalar skip (a run: body must never be parsed) ---
            if (blockind >= 0) {
                if (trim(line) == "" || ind > blockind) next
                blockind = -1
            }
            if (trim(line) == "") next
            body = trim(line)
            if (substr(body, 1, 1) == "#") next

            # --- pending block-sequence continuation ("key:" then "- item") ---
            if (seqind >= 0) {
                if (ind == seqind && substr(body, 1, 2) == "- ") {
                    item = scalar(substr(body, 3))
                    if (seqkey == "branches") branches = (branches == "" ? item : branches "," item)
                    else if (seqkey == "push_branches") push_branches = (push_branches == "" ? item : push_branches "," item)
                    else if (seqkey == "needs") j_needs = (j_needs == "" ? item : j_needs "," item)
                    else if (seqkey ~ /^mx:/) {
                        k = substr(seqkey, 4)
                        printf "MX\t%s\t%s\t%s\t%s\n", FNAME, job, k, item
                    }
                    next
                }
                seqind = -1; seqkey = ""
            }

            # --- key: value split (structure lines only) ---
            key = ""; val = ""
            if (match(body, /^[-]? *[A-Za-z0-9_.:$-]+:/)) {
                kv = substr(body, RSTART, RLENGTH)
                val = substr(body, RSTART + RLENGTH)
                sub(/^- */, "", kv)
                sub(/:$/, "", kv)
                key = kv
            }
            rawval = trim(val)
            isblock = (rawval ~ /^[|>][0-9+-]*$/)

            # --- top level ---
            if (ind == 0) {
                flushjob()
                section = key
                on_key = ""
                # A TOP-LEVEL `concurrency:` is the only one rule (d) reads: a
                # job-level one lands at indent 4 inside `jobs:` and cannot
                # coalesce two whole runs of the workflow.
                if (key == "concurrency") conc_seen = 1
                if (isblock) blockind = ind
                next
            }

            if (section == "on") {
                if (ind == 2) {
                    on_key = key
                    if (key == "pull_request") pr_trigger = 1
                    else if (key == "push") push_trigger = 1
                } else if (ind == 4 && on_key == "pull_request") {
                    if (key == "paths" || key == "paths-ignore") pr_paths = 1
                    else if (key == "branches") {
                        delete bs; bs[0] = 0
                        if (flowseq(rawval, bs) > 0) {
                            for (i = 1; i <= bs[0]; i++)
                                branches = (branches == "" ? bs[i] : branches "," bs[i])
                        } else if (rawval == "") { seqkey = "branches"; seqind = 6 }
                        else branches = (branches == "" ? scalar(rawval) : branches "," scalar(rawval))
                    }
                } else if (ind == 4 && on_key == "push") {
                    # `tags:` / `paths:` under push are deliberately ignored:
                    # neither prevents the duplicate run that rule (d) is about.
                    if (key == "branches") {
                        delete pbs; pbs[0] = 0
                        if (flowseq(rawval, pbs) > 0) {
                            for (i = 1; i <= pbs[0]; i++)
                                push_branches = (push_branches == "" ? pbs[i] : push_branches "," pbs[i])
                        } else if (rawval == "") { seqkey = "push_branches"; seqind = 6 }
                        else push_branches = (push_branches == "" ? scalar(rawval) : push_branches "," scalar(rawval))
                    }
                }
                if (isblock) blockind = ind
                next
            }

            if (section == "concurrency") {
                if (ind == 2) {
                    # The group is captured RAW (not through scalar()): rule (d)
                    # only substring-tests it for an event discriminator, and a
                    # `${{ ... }}` expression must never be comment-trimmed.
                    if (key == "group") conc_group = rawval
                    else if (key == "cancel-in-progress") {
                        # Fail-closed: anything that is not literally `false`
                        # is treated as cancelling.
                        conc_cancel = (tolower(trim(rawval)) == "false" ? 0 : 1)
                    }
                }
                if (isblock) blockind = ind
                next
            }

            if (section != "jobs") { if (isblock) blockind = ind; next }

            # --- jobs ---
            if (ind == 2) { flushjob(); job = key; next }
            if (job == "") { if (isblock) blockind = ind; next }

            if (ind == 4) {
                flushstep()
                in_steps = 0; in_strategy = 0; in_matrix = 0; in_include = 0
                if (key == "name") { j_name = scalar(rawval); j_namerisk = name_truncation_risk(rawval) }
                else if (key == "if") j_if = 1
                else if (key == "needs") {
                    delete ns; ns[0] = 0
                    if (flowseq(rawval, ns) > 0) {
                        for (i = 1; i <= ns[0]; i++) j_needs = (j_needs == "" ? ns[i] : j_needs "," ns[i])
                    } else if (rawval == "") { seqkey = "needs"; seqind = 6 }
                    else j_needs = scalar(rawval)
                }
                else if (key == "strategy") in_strategy = 1
                else if (key == "steps") in_steps = 1
                if (isblock) blockind = ind
                next
            }

            if (in_strategy && ind == 6) {
                if (key == "matrix") { j_matrix = 1; in_matrix = 1; in_include = 0 }
                else { in_matrix = 0; in_include = 0 }
                if (isblock) blockind = ind
                next
            }

            if (in_matrix && ind == 8) {
                in_include = 0
                if (key == "include") { in_include = 1 }
                else if (key != "" && key != "exclude") {
                    delete vs; vs[0] = 0
                    if (flowseq(rawval, vs) > 0) {
                        for (i = 1; i <= vs[0]; i++)
                            printf "MX\t%s\t%s\t%s\t%s\n", FNAME, job, key, vs[i]
                    } else if (rawval == "") { seqkey = "mx:" key; seqind = 10 }
                    else printf "MX\t%s\t%s\t%s\t%s\n", FNAME, job, key, scalar(rawval)
                }
                if (isblock) blockind = ind
                next
            }

            if (in_include && (ind == 10 || ind == 12)) {
                if (key != "")
                    printf "MX\t%s\t%s\t%s\t%s\n", FNAME, job, key, scalar(rawval)
                if (isblock) blockind = ind
                next
            }

            if (in_steps && ind == 6 && substr(body, 1, 2) == "- ") {
                flushstep()
                cur_step = ++stepno[job]
                if (key == "if") { s_hasif = 1; if (rawval ~ /docs_only/) s_guard = 1 }
                else if (key == "uses") s_uses = scalar(rawval)
                else if (key == "name") s_name = scalar(rawval)
                if (isblock) blockind = ind
                next
            }

            if (in_steps && ind == 8 && cur_step > 0) {
                if (key == "if") { s_hasif = 1; if (rawval ~ /docs_only/) s_guard = 1 }
                else if (key == "uses") s_uses = scalar(rawval)
                else if (key == "name") s_name = scalar(rawval)
                if (isblock) blockind = ind
                next
            }

            if (isblock) blockind = ind
        }
        END {
            flushjob()
            printf "WF\t%s\t%d\t%d\t%s\n", FNAME, pr_trigger, pr_paths, branches
            printf "PUSH\t%s\t%d\t%s\n", FNAME, push_trigger, push_branches
            printf "CONC\t%s\t%d\t%d\t%s\n", FNAME, conc_seen, conc_cancel, conc_group
        }
        ' "$f"
    done
}

# glob_match <pattern> <branch-ref>
# GitHub workflow `branches:` globbing: `**` spans `/`, `*` does not.
glob_match() {
    local pat="$1" ref="$2" rx="" i ch
    for ((i = 0; i < ${#pat}; i++)); do
        ch="${pat:i:1}"
        case "$ch" in
            '*')
                if [ "${pat:i:2}" = "**" ]; then rx+='.*'; i=$((i + 1)); else rx+='[^/]*'; fi
                ;;
            '?') rx+='[^/]' ;;
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\') rx+="\\$ch" ;;
            *) rx+="$ch" ;;
        esac
    done
    [[ "$ref" =~ ^${rx}$ ]]
}

read_list() {
    # Whole-line `#` comments and blanks only. Inline `#` is NOT a comment:
    # several required context names legitimately contain one, e.g.
    # `Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10)`.
    local file="$1" line
    [ -f "$file" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        case "$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//')" in
            '' | '#'*) continue ;;
        esac
        printf '%s\n' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
    done < "$file"
}

run_gate() {
    local records
    records="$(parse_workflows)"

    if [ -z "$records" ]; then
        fail "parsed ZERO records from $WORKFLOW_DIR — refusing to pass on an empty parse (fail-closed)"
        return 1
    fi
    if [ ! -f "$MIRROR_FILE" ]; then
        fail "mirror file missing: $MIRROR_FILE (fail-closed — the gate cannot verify an undeclared required set)"
        return 1
    fi

    local -a contexts=() allow=()
    mapfile -t contexts < <(read_list "$MIRROR_FILE")
    mapfile -t allow < <(read_list "$ALLOW_FILE")

    if [ "${#contexts[@]}" -eq 0 ]; then
        fail "mirror $MIRROR_FILE declares NO contexts — refusing to pass a vacuous mirror (fail-closed)"
        return 1
    fi

    # ---- index the parsed records -----------------------------------------
    declare -A JOB_NAME=() JOB_IF=() JOB_MATRIX=() JOB_NEEDS=() JOB_FILE=()
    declare -A JOB_NAMERISK=()
    declare -A WF_PR=() WF_PATHS=() WF_BRANCHES=()
    declare -A WF_PUSH=() WF_PUSHBR=()
    declare -A WF_CONC=() WF_CANCEL=() WF_GROUP=()
    declare -A MXKEYS=()   # "file|job|key" -> space-joined values
    declare -a JOBKEYS=() WFKEYS=()

    # Split on US (0x1f), NOT on TAB. `read` treats space/tab/newline in IFS as
    # IFS WHITESPACE and collapses runs of them into ONE delimiter, so with a
    # tab IFS an EMPTY MIDDLE field silently shifts every later field left —
    # e.g. a JOB record for a job with no `needs:` handed the name-truncation
    # flag to `f` and left `g` empty, which made rule (e) blind on exactly the
    # jobs it exists for (every c8-precheck gate has no `needs:`). 0x1f is not
    # IFS whitespace, so empty fields are preserved positionally. The record
    # stream itself stays TAB-delimited — `--dump` and its awk consumers
    # (`-F'\t'`, which never collapses) are unaffected.
    local rec kind a b c d e f g
    while IFS=$'\x1f' read -r kind a b c d e f g; do
        case "$kind" in
            WF)
                WFKEYS+=("$a")
                WF_PR["$a"]="$b"; WF_PATHS["$a"]="$c"; WF_BRANCHES["$a"]="$d"
                ;;
            PUSH)
                WF_PUSH["$a"]="$b"; WF_PUSHBR["$a"]="$c"
                ;;
            CONC)
                WF_CONC["$a"]="$b"; WF_CANCEL["$a"]="$c"; WF_GROUP["$a"]="$d"
                ;;
            JOB)
                local jk="$a|$b"
                JOBKEYS+=("$jk")
                JOB_FILE["$jk"]="$a"; JOB_NAME["$jk"]="$c"
                JOB_IF["$jk"]="$d"; JOB_MATRIX["$jk"]="$e"; JOB_NEEDS["$jk"]="$f"
                JOB_NAMERISK["$jk"]="$g"
                ;;
            MX)
                local mk="$a|$b|$c"
                MXKEYS["$mk"]="${MXKEYS[$mk]:-} $d"
                ;;
        esac
    done <<< "${records//$'\t'/$'\x1f'}"

    # ---- rule (e): a job name that YAML silently truncates (#2473) --------
    #
    # Checked FIRST, and repo-wide rather than per-required-context, for two
    # reasons. (1) A truncated name makes the DECLARED name and the REPORTED
    # check-run name differ, so every downstream verdict in this gate is
    # reasoning about a string the workflow author never wrote — including
    # rule (a), which would otherwise report the confusing "matches NO parsed
    # job name" for a job that plainly exists. (2) Scope: a job that is not a
    # required context today becomes one the moment somebody adds it to
    # `required_status_checks.contexts`, and the operator will copy the
    # TRUNCATED name off the PR because that is the only name GitHub shows.
    # That is precisely how the #2473 artifact entered the live set.
    local risky_jk
    for risky_jk in "${JOBKEYS[@]}"; do
        [ "${JOB_NAMERISK[$risky_jk]:-0}" = "1" ] || continue
        fail "RULE (e) HARD-FAIL — job $risky_jk has an UNQUOTED 'name:' containing whitespace-then-'#', so YAML TRUNCATES it at the '#'. Parsed name: '${JOB_NAME[$risky_jk]}'."
        echo "     The name GitHub reports as the check-run — and therefore the string branch protection would pin — is the truncated one, NOT what the workflow appears to declare (#2473: 'L3-boundary perma-ban gate (§25.3 S5 / RQ-10 #1853)' reported as 44 chars ending at 'RQ-10')." >&2
        echo "     FIX: quote the scalar — name: \"…\". One character each side; there is no legitimate instance and no allowlist. To keep a genuine trailing YAML comment, quote the name FIRST: name: \"Foo\"  # note." >&2
        echo "     NOT flagged, and deliberately so: a '#' preceded by '(' — the '(#1174 PR10)' / '(#2146)' / '(#1989)' family — is not a comment in YAML and reports verbatim." >&2
    done

    # ---- expand job names into the concrete context names they report -----
    declare -A CTX_JOB=()      # context name -> "file|job"
    declare -a UNEXPANDABLE=()
    local jk name mvar vals v expanded
    for jk in "${JOBKEYS[@]}"; do
        name="${JOB_NAME[$jk]}"
        [ -n "$name" ] || continue
        if [[ "$name" != *'${{'* ]]; then
            [ -n "${CTX_JOB[$name]:-}" ] || CTX_JOB["$name"]="$jk"
            continue
        fi
        # Exactly one `${{ matrix.<key> }}` is expandable; anything else is
        # reported as unexpandable and (if required) fails rule (a).
        if [[ "$name" =~ ^([^$]*)\$\{\{[[:space:]]*matrix\.([A-Za-z0-9_-]+)[[:space:]]*\}\}(.*)$ ]]; then
            local pre="${BASH_REMATCH[1]}" post="${BASH_REMATCH[3]}"
            mvar="${BASH_REMATCH[2]}"
            if [[ "$post" == *'${{'* ]]; then
                UNEXPANDABLE+=("$jk :: $name (more than one expression)")
                continue
            fi
            vals="${MXKEYS[${jk}|${mvar}]:-}"
            if [ -z "${vals// /}" ]; then
                UNEXPANDABLE+=("$jk :: $name (no matrix.$mvar values found)")
                continue
            fi
            for v in $vals; do
                expanded="${pre}${v}${post}"
                [ -n "${CTX_JOB[$expanded]:-}" ] || CTX_JOB["$expanded"]="$jk"
            done
        else
            UNEXPANDABLE+=("$jk :: $name")
        fi
    done

    # ---- index the DECIDER relation (rule b4) ------------------------------
    # A job is a DECIDER when at least one other job in the SAME workflow
    # declares `needs: <its id>`. Derived from the parsed `needs:` edges rather
    # than a hardcoded job-id list, so a renamed or newly-added decider is
    # covered automatically.
    declare -A DEPENDED=()   # "file|jobid" -> space-joined dependent job ids
    local dwf djobid dneed
    local -a _dneeds=()
    for jk in "${JOBKEYS[@]}"; do
        dwf="${JOB_FILE[$jk]}"
        djobid="${jk#*|}"
        IFS=',' read -r -a _dneeds <<< "${JOB_NEEDS[$jk]}"
        for dneed in "${_dneeds[@]}"; do
            [ -n "$dneed" ] || continue
            [ "$dneed" != "$djobid" ] || continue
            DEPENDED["$dwf|$dneed"]="${DEPENDED[$dwf|$dneed]:-} $djobid"
        done
    done

    # ---- rules (a) / (b1) / (b4) / (b2) / (c), per required context --------
    declare -A ALLOWED=()
    local ctx
    for ctx in "${allow[@]}"; do ALLOWED["$ctx"]=1; done
    declare -A ALLOW_USED=()

    local wf
    for ctx in "${contexts[@]}"; do
        jk="${CTX_JOB[$ctx]:-}"
        if [ -z "$jk" ]; then
            fail "RULE (a) — required context '$ctx' matches NO parsed job name (static or matrix-expanded) in $WORKFLOW_DIR."
            echo "     A required context that no job produces is never created, so it stays 'Expected — waiting' forever and the branch WEDGES (enforce_admins cannot clear it)." >&2
            echo "     FIX: correct the mirror to the name the workflow actually reports, or add/rename the job. Do NOT regenerate the mirror from live API state — see the header warning about the §25.3 truncation artifact." >&2
            if [ "${#UNEXPANDABLE[@]}" -gt 0 ]; then
                echo "     NOTE: these job names could not be expanded by the parser and may be the intended carrier:" >&2
                printf '       %s\n' "${UNEXPANDABLE[@]}" >&2
            fi
            continue
        fi
        wf="${JOB_FILE[$jk]}"

        # (b1) the wedge shape — never allowlistable.
        if [ "${JOB_MATRIX[$jk]}" = "1" ] && [ "${JOB_IF[$jk]}" = "1" ]; then
            fail "RULE (b1) HARD-FAIL — required context '$ctx' comes from $jk, which has BOTH 'strategy.matrix' AND a job-level 'if:' (the #2494 wedge)."
            echo "     GitHub evaluates a job-level 'if:' BEFORE matrix expansion, so when that 'if:' is false the job emits ONE check-run with the UNEXPANDED template name and '$ctx' is NEVER CREATED — pending forever, unmergeable." >&2
            echo "     FIX: delete the job-level 'if:', keep 'needs:', and move that condition onto EVERY step (the 'check' job in ci.yml is the proven pattern). NOT 'if: always()' — that reports success even when the dependency failed." >&2
            continue
        fi

        # (b4) the DECIDER shape — never allowlistable, checked BEFORE the
        # (b2) ratchet so a decider can never be absolved by an allowlist entry.
        if [ -n "${DEPENDED[$jk]:-}" ] && [ "${JOB_IF[$jk]}" = "1" ]; then
            fail "RULE (b4) HARD-FAIL — required context '$ctx' comes from $jk, a DECIDER (job(s) [${DEPENDED[$jk]# }] declare 'needs: ${jk#*|}'), and it carries a job-level 'if:'."
            echo "     When that 'if:' is false the decider reports 'skipped', which skips EVERY dependent job — and branch protection counts each skipped required dependent as SATISFIED. One skipped decider therefore neutralises its whole dependent subtree at once, which is why this is NOT allowlistable via $ALLOW_FILE (contrast rule (b2))." >&2
            echo "     FIX: delete the job-level 'if:' and move that condition onto every step, or stop requiring '$ctx' (drop it from the mirror AND from branch protection, in that order)." >&2
            continue
        fi

        # (b2) skipped-counts-as-satisfied — ratcheted.
        if [ "${JOB_IF[$jk]}" = "1" ]; then
            if [ -n "${ALLOWED[$ctx]:-}" ]; then
                ALLOW_USED["$ctx"]=1
            else
                fail "RULE (b2) — required context '$ctx' comes from $jk, which carries a job-level 'if:'. It will report 'skipped', which branch protection COUNTS AS SATISFIED — the gate fails OPEN."
                echo "     FIX (preferred): move the condition onto every step so the job runs and reports real 'success'/'failure'." >&2
                echo "     OR, if the fail-open is a deliberate, dated, justified carry-over: add '$ctx' to $ALLOW_FILE. That file is a BURN-DOWN ratchet — entries may only be removed." >&2
                continue
            fi
        fi

        # (c) the carrying workflow must actually fire for this branch, unfiltered.
        if [ "${WF_PR[$wf]:-0}" != "1" ]; then
            fail "RULE (c) — required context '$ctx' is carried by $wf, which has NO 'pull_request' trigger. It can never report on a PR, so the context stays pending and the branch wedges."
            continue
        fi
        if [ "${WF_PATHS[$wf]:-0}" = "1" ]; then
            fail "RULE (c) — required context '$ctx' is carried by $wf, whose 'pull_request' trigger has a 'paths:'/'paths-ignore:' filter."
            echo "     An out-of-filter PR never triggers the workflow, so '$ctx' is never created — the same wedge as (b1) with no 'if:' in sight. FIX: drop the path filter, or gate inside the job with per-step guards." >&2
            continue
        fi
        local br matched=0
        IFS=',' read -r -a _brs <<< "${WF_BRANCHES[$wf]:-}"
        for br in "${_brs[@]}"; do
            [ -n "$br" ] || continue
            if glob_match "$br" "$PROTECTED_BRANCH"; then matched=1; break; fi
        done
        if [ "$matched" != "1" ]; then
            fail "RULE (a) — required context '$ctx' is carried by $wf, whose pull_request 'branches:' (${WF_BRANCHES[$wf]:-<none>}) does NOT cover the protected branch '$PROTECTED_BRANCH'."
            echo "     FIX: add a matching pattern (e.g. \"release/**\") to that trigger, or drop the context from the mirror + from branch protection." >&2
        fi
    done

    # ---- ratchet hygiene: no stale allowlist entries ----------------------
    for ctx in "${allow[@]}"; do
        if [ -z "${ALLOW_USED[$ctx]:-}" ]; then
            fail "RATCHET STALE — '$ctx' is listed in $ALLOW_FILE but is no longer a required context whose job carries a job-level 'if:'."
            echo "     The allowlist is a burn-down ledger, not a junk drawer: remove the entry (thresholds tighten, never loosen)." >&2
        fi
    done

    # ---- rule (b3): every step guarded in an unguarded needs:classify job -
    local needs step_recs
    for jk in "${JOBKEYS[@]}"; do
        needs=",${JOB_NEEDS[$jk]},"
        [[ "$needs" == *",${CLASSIFY_JOB},"* ]] || continue
        [ "${JOB_IF[$jk]}" = "0" ] || continue
        wf="${JOB_FILE[$jk]}"
        local jobid="${jk#*|}"
        step_recs="$(printf '%s\n' "$records" | awk -F'\t' -v w="$wf" -v j="$jobid" '$1=="STEP" && $2==w && $3==j')"
        if [ -z "$step_recs" ]; then
            fail "RULE (b3) — job $jk has 'needs: $CLASSIFY_JOB' and no job-level 'if:', but the parser found NO steps. Refusing to pass an unverifiable job (fail-closed)."
            continue
        fi
        local sidx shasif sguard suses sname
        # 0x1f for the same reason as the JOB loop above: a `run:` step has an
        # EMPTY `uses` field in the middle of the record, and a tab IFS would
        # collapse it and slide the step NAME into `suses`.
        while IFS=$'\x1f' read -r _ _ _ sidx shasif sguard suses sname; do
            [ -n "$sidx" ] || continue
            if [ "$sguard" = "1" ]; then continue; fi
            # Structural exemption: a bare checkout, exactly as the proven
            # `check` job does. Nothing else is exempt.
            if [ "$shasif" = "0" ] && [[ "$suses" == actions/checkout@* ]]; then continue; fi
            fail "RULE (b3) — job $jk (needs: $CLASSIFY_JOB, no job-level 'if:') has step #$sidx ['${sname:-${suses:-<unnamed>}}'] with NO '${CLASSIFY_JOB}.outputs.docs_only' guard."
            echo "     This job's contract is 'runs always, no-ops on docs-only'. An unguarded step silently executes the heavy work on every docs-only PR — burning runner time and, worse, half-running a job whose other steps skipped." >&2
            echo "     FIX: add 'if: needs.${CLASSIFY_JOB}.outputs.docs_only != '\''true'\''' (or the '== '\''true'\''' short-circuit notice form) to that step. Only a bare 'actions/checkout@*' step is exempt." >&2
        done <<< "${step_recs//$'\t'/$'\x1f'}"
    done

    # ---- rule (d): the #2508 cancelled-duplicate carrier class -------------
    #
    # Scope is EVERY workflow in the directory, NOT just required-context
    # carriers. The permanent `cancelled` row pollutes any PR's rollup, and it
    # converts into a branch wedge the instant someone adds that context to
    # `required_status_checks.contexts` — a reasonable-looking hardening step.
    # The class has to be dead BEFORE anyone reaches for it, so the sweep is
    # repo-wide and the rule is not gated on the mirror.
    #
    # DUPTRIG_ALLOW holds a bare presence marker and DUPTRIG_REF the issue
    # citation — deliberately two arrays rather than one keyed by the citation.
    # If presence WERE the citation, a malformed (issue-less) entry would store
    # an empty value and be silently ignored, so the format check above would
    # "pass" for the wrong reason and could be deleted without any self-test
    # noticing. Split, an entry that reaches the map suppresses, and the format
    # check is the only thing standing between a malformed line and that.
    declare -A DUPTRIG_ALLOW=() DUPTRIG_REF=() DUPTRIG_USED=()
    local -a duptrig_lines=()
    mapfile -t duptrig_lines < <(read_list "$DUPTRIG_ALLOW_FILE")
    local dline dfile dpat dref
    for dline in "${duptrig_lines[@]}"; do
        # FORMAT: <workflow-file> <push-branches-pattern> #<issue> [note…]
        read -r dfile dpat dref _ <<< "$dline"
        if [ -z "$dfile" ] || [ -z "$dpat" ] || [[ ! "$dref" =~ ^#[0-9]+$ ]]; then
            fail "PENDING-FIX LEDGER MALFORMED — '$dline' in $DUPTRIG_ALLOW_FILE."
            echo "     Every entry MUST be '<workflow-file> <push-branches-pattern> #<issue>' so the ledger can never rot into an unexplained suppression: the pattern scopes the excuse to the ONE overlap that was reviewed, and the issue is the thing that closes it." >&2
            continue
        fi
        DUPTRIG_ALLOW["$dfile|$dpat"]=1
        DUPTRIG_REF["$dfile|$dpat"]="$dref"
    done

    local wfk pat probe hit
    for wfk in "${WFKEYS[@]}"; do
        # (i) BOTH triggers — one event alone can never produce the twin.
        # The `push` half is defence-in-depth rather than a distinct branch:
        # the parser only records `push.branches` underneath `on.push`, so an
        # empty pattern list already short-circuits the loop below. It stays so
        # that a future parser change cannot turn a stray branch list into a
        # verdict about a workflow that has no push trigger at all.
        [ "${WF_PR[$wfk]:-0}" = "1" ] || continue
        [ "${WF_PUSH[$wfk]:-0}" = "1" ] || continue
        # (iii) a cancelling concurrency group whose key is not event-distinct.
        # `cancel-in-progress: false` (or no concurrency block at all) yields
        # two SUCCESS runs — wasteful, but no `cancelled` row and no wedge, so
        # it is deliberately NOT this rule's business.
        [ "${WF_CONC[$wfk]:-0}" = "1" ] || continue
        [ "${WF_CANCEL[$wfk]:-0}" = "1" ] || continue
        # `github.event_name` is the one discriminator that PROVES the two
        # events resolve to different group keys. Everything else is treated
        # as colliding — fail-closed: this rule refuses to reason its way to a
        # pass on an expression it cannot evaluate.
        if [[ "${WF_GROUP[$wfk]:-}" == *'github.event_name'* ]]; then continue; fi

        local -a _pushpats=()
        IFS=',' read -r -a _pushpats <<< "${WF_PUSHBR[$wfk]:-}"
        for pat in "${_pushpats[@]}"; do
            [ -n "$pat" ] || continue
            # (ii) can this pattern match a branch we open PRs from?
            hit=""
            for probe in "${PR_HEAD_PROBES[@]}"; do
                if glob_match "$pat" "$probe"; then hit="$probe"; break; fi
            done
            [ -n "$hit" ] || continue

            if [ -n "${DUPTRIG_ALLOW[$wfk|$pat]:-}" ]; then
                DUPTRIG_USED["$wfk|$pat"]=1
                echo "ℹ️  required-contexts: RULE (d) PENDING FIX — $wfk push pattern '$pat' overlaps PR head branches (e.g. '$hit') and leaves a permanent CANCELLED check-run on every such PR. Tracked by ${DUPTRIG_REF[$wfk|$pat]:-<no issue>}; suppressed here so an unrelated PR is not red for someone else's carrier." >&2
                continue
            fi

            fail "RULE (d) HARD-FAIL — $wfk triggers on BOTH 'push' and 'pull_request', its push.branches pattern '$pat' CAN match a PR HEAD branch (e.g. '$hit'), and its concurrency group cancels in-progress runs on a key that resolves to the SAME value for both events."
            echo "     Every push to such a head branch starts TWO runs for ONE sha under ONE group key: the push run (no 'pull_request' context, so the group expression falls through to github.ref_name = the head branch) and the same-repo pull_request run (head.ref = the identical string). With 'cancel-in-progress: true' one of the two is ALWAYS cancelled — guaranteed, not occasional — and the cancelled check-run row is PERMANENT (#2508; observed simultaneously on PRs #2499 and #2505)." >&2
            echo "     Why this is not cosmetic: 'cancelled' is a fifth disposition that READS AS PASS in 'gh pr checks' (it renders a cancelled run's rows as 'pass') while branch protection does not count it as satisfied. So the moment this context is added to required_status_checks.contexts — a reasonable-looking hardening step — '$PROTECTED_BRANCH' wedges on every PR from such a branch, and the standard triage command actively conceals the cause." >&2
            echo "     FIX (preferred; exactly what #2509 did to tool-count-drift.yml): narrow push.branches to branches that are NEVER a PR head — main / develop / release/** — the shape ci.yml and coverage.yml already use, and the reason their always-run jobs were safe to require while this one was not. NO coverage is lost: the pull_request trigger's 'branches:' list is a BASE-branch filter, so every PR is still gated from any head branch; the only runs dropped are push-event runs on a topic branch with no PR open, which is not where this verdict is consumed." >&2
            echo "     FIX (alternative, rarely the right call): fold '\${{ github.event_name }}' into the concurrency group so the two events cannot share a key. That KEEPS both runs on every push — double the runner cost for one sha — so prefer the trigger narrowing unless the push-event run genuinely has to exist on head branches." >&2
            echo "     LAST RESORT: add '$wfk $pat #<issue>' to $DUPTRIG_ALLOW_FILE. That is a PENDING-FIX ledger, not an absolution: the entry excuses EXACTLY that one pattern on that one workflow and must name the tracking issue." >&2
        done
    done

    # A STALE pending-fix entry is announced, never fatal. Unlike the (b2)
    # ratchet — where a stale line could absolve a DIFFERENT context — an entry
    # here excuses one (workflow, pattern) pair and nothing else, so once the
    # carrier is fixed the line can only suppress a failure that no longer
    # happens. Failing on it would red whichever PR merely LOST THE RACE to the
    # carrier fix (#2506 is fixing token-budget.yml in parallel with this gate),
    # which is a false alarm charged to the wrong author. It is printed on every
    # run until removed, and it cannot silently cover a re-acquired overlap,
    # because a different pattern is a different key and fails normally.
    local akey
    for akey in "${!DUPTRIG_ALLOW[@]}"; do
        [ -z "${DUPTRIG_USED[$akey]:-}" ] || continue
        echo "ℹ️  required-contexts: RULE (d) PENDING-FIX ENTRY IS NOW STALE — '${akey%%|*}' pattern '${akey#*|}' (${DUPTRIG_REF[$akey]:-<no issue>}) no longer trips rule (d). The carrier was fixed: DELETE that line from $DUPTRIG_ALLOW_FILE." >&2
    done

    [ "$FAILURES" -eq 0 ]
}

# --- self-test --------------------------------------------------------------
selftest() {
    echo "required-contexts gate: self-test (clean control -> PASS; #2494 (b1) matrix+if wedge -> FAIL; (a) unmatched mirror context -> FAIL; #2473 (e) unquoted ' #' job name -> FAIL (and the parse is asserted truncated); (c) paths-filtered carrier -> FAIL; (b3) unguarded step -> FAIL; (b4) decider with job-level if -> FAIL even when allowlisted; #2508 (d) verbatim cancelled-duplicate carrier -> FAIL, its four near-miss shapes -> PASS)"

    # Fixtures are staged under the repo's gitignored `.local-runs/` scratch
    # root — never system /tmp (project hard rule), and never `mktemp -d`,
    # whose TMPDIR-honouring default is exactly how that rule gets violated by
    # accident. The path is PID-scoped so two concurrent self-tests cannot
    # stomp each other. Nothing here is visible to the gate under test except
    # through the RQC_* env overrides below, so a staged fixture cannot be
    # confused with a real workflow (and, conversely, the gate never scans
    # `.local-runs/`, so there is no #2516-style exclusion that could make
    # these fixtures invisible to the function under test).
    local scratch="$ROOT/.local-runs/required-contexts-selftest-$$"
    mkdir -p "$ROOT/.local-runs"
    rm -rf "${scratch:?}"
    mkdir -p "$scratch"
    # shellcheck disable=SC2064
    trap "rm -rf '$scratch'" RETURN

    local wf="$scratch/wf" al="$scratch/allow.txt" mi="$scratch/mirror.txt"
    local dal="$scratch/duptrig-allow.txt"
    mkdir -p "$wf"
    : > "$al"
    : > "$dal"

    # A minimal but structurally faithful fixture: one matrix job following
    # the proven per-step-guard pattern, plus a plain required job.
    write_clean() {
        cat > "$wf/ci.yml" <<'YAML'
name: CI
on:
  push:
    branches: [main, "release/**"]
  pull_request:
    branches: [main, develop, "release/**"]
jobs:
  classify:
    name: Classify changes
    runs-on: ubuntu-latest
    outputs:
      docs_only: ${{ steps.cls.outputs.docs_only }}
    steps:
      - uses: actions/checkout@v4
      - id: cls
        shell: bash
        run: |
          # a run: body that LOOKS like structure must never be parsed:
          #       - name: not a real step
          #         if: bogus
          echo "docs_only=false" >> "$GITHUB_OUTPUT"
  check:
    name: Check (${{ matrix.os }})
    needs: classify
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - name: docs-only short-circuit
        if: needs.classify.outputs.docs_only == 'true'
        run: echo noop
      - name: Run tests
        if: needs.classify.outputs.docs_only != 'true'
        run: echo test
  mobile:
    name: Cross-compile (${{ matrix.target }})
    needs: classify
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - target: aarch64-apple-ios
            os: macos-latest
          - target: aarch64-linux-android
            os: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: cargo check
        if: needs.classify.outputs.docs_only != 'true'
        run: echo build
  quoted:
    name: "Quoted gate (§X / RQ-10 #1853)"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: run
        run: echo ok
  parens:
    name: Paren gate (#1174 PR10)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: run
        run: echo ok
YAML
        cat > "$mi" <<'TXT'
# self-test mirror
Classify changes
Check (ubuntu-latest)
Check (windows-latest)
Cross-compile (aarch64-apple-ios)
Cross-compile (aarch64-linux-android)
Quoted gate (§X / RQ-10 #1853)
Paren gate (#1174 PR10)
TXT
        : > "$al"
        : > "$dal"
        rm -f "$wf/dup.yml"
    }

    run_fixture() {
        (
            set +e
            RQC_WORKFLOW_DIR="$wf" RQC_MIRROR_FILE="$mi" RQC_ALLOW_FILE="$al" \
                RQC_DUPTRIG_ALLOW_FILE="$dal" \
                RQC_PROTECTED_BRANCH="release/v1.0.0" \
                bash "${BASH_SOURCE[0]}" >/dev/null 2>&1
            echo $?
        )
    }

    # write_dup <push-branches-flow-seq> <cancel-in-progress> <group-suffix-expr> [omit_pr]
    # Plants a second workflow carrying ONLY the rule (d) shape under test.
    # Its jobs are deliberately outside the mirror and carry no
    # `needs: classify`, so no other rule can claim the verdict.
    write_dup() {
        local pushb="$1" cancel="$2" group="$3" omit_pr="${4:-}"
        {
            printf 'name: dup-carrier\n\non:\n'
            printf '  push:\n    branches: %s\n' "$pushb"
            [ -n "$omit_pr" ] || printf '  pull_request:\n    branches: [main, develop, "release/**"]\n'
            printf '\nconcurrency:\n  group: %s\n  cancel-in-progress: %s\n' "$group" "$cancel"
            printf '\njobs:\n  gate:\n    name: dup carrier gate\n    runs-on: ubuntu-latest\n'
            printf '    steps:\n      - uses: actions/checkout@v4\n      - name: run\n        run: echo ok\n'
        } > "$wf/dup.yml"
    }

    local rc parsed_name e_out

    # ---- control: clean tree must PASS (and must exercise both YAML rules)
    write_clean
    rc="$(run_fixture)"
    if [ "$rc" != "0" ]; then
        echo "  [control] clean fixture REJECTED (exit $rc) — the gate is over-strict; a false positive is as bad as a miss" >&2
        RQC_WORKFLOW_DIR="$wf" RQC_MIRROR_FILE="$mi" RQC_ALLOW_FILE="$al" \
            RQC_PROTECTED_BRANCH="release/v1.0.0" bash "${BASH_SOURCE[0]}" >&2 || true
        return 2
    fi
    echo "  [control] clean fixture PASSES (incl. the QUOTED ' #' name + the unquoted '(#' non-truncation YAML rule)"

    # ---- (e) the #2473 truncation shape: UNQUOTE the quoted job's name.
    #
    # THREE assertions, and the third is the one that matters. "The gate went
    # red" is NOT the claim being made — a bare unquoting also makes the mirror
    # entry unmatchable, so rule (a) fires and the leg would pass while rule
    # (e) was stone blind. (That is not hypothetical: it is exactly what this
    # leg did before the 0x1f field-split fix, on a tree where every
    # required-context job has no `needs:`.) So the mirror is ALSO rewound to
    # the TRUNCATED string, which is the historically faithful state — every
    # other rule is satisfied, rule (e) is the only thing left that can fail —
    # and the failure output is required to NAME rule (e).
    #
    # Assertion 1 (--dump): the parse really does truncate at the '#'. If the
    # parser silently stopped implementing the YAML rule, rule (e) could fire
    # for the wrong reason while rule (a)'s meaning changed underneath it.
    write_clean
    perl -0pi -e 's/^    name: "Quoted gate \(§X \/ RQ-10 #1853\)"$/    name: Quoted gate (§X \/ RQ-10 #1853)/m' "$wf/ci.yml"
    grep -q '^    name: Quoted gate ' "$wf/ci.yml" || {
        echo "  [e] fixture injection FAILED (self-test is broken, not the gate)" >&2; return 2; }
    perl -0pi -e 's/^Quoted gate \(§X \/ RQ-10 #1853\)$/Quoted gate (§X \/ RQ-10/m' "$mi"
    grep -qx 'Quoted gate (§X / RQ-10' "$mi" || {
        echo "  [e] mirror rewind FAILED (self-test is broken, not the gate)" >&2; return 2; }
    parsed_name="$(RQC_WORKFLOW_DIR="$wf" RQC_MIRROR_FILE="$mi" RQC_ALLOW_FILE="$al" \
        RQC_DUPTRIG_ALLOW_FILE="$dal" RQC_PROTECTED_BRANCH="release/v1.0.0" \
        bash "${BASH_SOURCE[0]}" --dump 2>/dev/null \
        | awk -F'\t' '$1 == "JOB" && $3 == "quoted" { print $4 }')"
    if [ "$parsed_name" != "Quoted gate (§X / RQ-10" ]; then
        echo "  [e] parser no longer truncates an unquoted ' #' name (got '$parsed_name') — the YAML rule this gate turns on has regressed" >&2
        return 2
    fi
    # Assertions 2 + 3: the gate rejects, and it rejects BY RULE (e).
    e_out="$(RQC_WORKFLOW_DIR="$wf" RQC_MIRROR_FILE="$mi" RQC_ALLOW_FILE="$al" \
        RQC_DUPTRIG_ALLOW_FILE="$dal" RQC_PROTECTED_BRANCH="release/v1.0.0" \
        bash "${BASH_SOURCE[0]}" 2>&1 || true)"
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [e] unquoted job name containing ' #' (the #2473 truncation): NOT CAUGHT (gate passed) — FAIL" >&2
        return 2
    fi
    case "$e_out" in
        *"RULE (e)"*) ;;
        *)
            echo "  [e] the gate rejected the tree but NOT via rule (e) — the leg would pass for the wrong reason. Output was:" >&2
            printf '%s\n' "$e_out" >&2
            return 2
            ;;
    esac
    case "$e_out" in
        *"RULE (a)"*)
            echo "  [e] rule (a) also fired — the mirror rewind did not take, so this leg is not isolating rule (e)" >&2
            return 2
            ;;
    esac
    echo "  [e] #2473 unquoted ' #' job name: CAUGHT BY RULE (e) ALONE (mirror rewound to the truncated string so every other rule is satisfied), with the parse confirmed truncated at '#'"

    # ---- (b1) the #2494 wedge: add a job-level if: to the matrix job
    write_clean
    perl -0pi -e 's/(  mobile:\n    name: Cross-compile \(\$\{\{ matrix\.target \}\}\)\n    needs: classify\n)/$1    if: needs.classify.outputs.docs_only != \x27true\x27\n/' "$wf/ci.yml"
    grep -q "^    if: needs.classify.outputs.docs_only" "$wf/ci.yml" || {
        echo "  [b1] fixture injection FAILED (self-test is broken, not the gate)" >&2; return 2; }
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [b1] matrix + job-level 'if:' wedge: NOT CAUGHT (gate passed) — FAIL" >&2
        return 2
    fi
    echo "  [b1] #2494 matrix + job-level 'if:' wedge (the confirmed branch-wedge shape): CAUGHT"

    # ---- (a) a mirror context matching no job
    write_clean
    printf 'Gate That Does Not Exist\n' >> "$mi"
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [a] mirror context matching no job: NOT CAUGHT (gate passed) — FAIL" >&2
        return 2
    fi
    echo "  [a] mirror context matching no parsed job name (the #2473 truncation class): CAUGHT"

    # ---- (c) a paths:-filtered carrier
    write_clean
    perl -0pi -e "s/(  pull_request:\n    branches: \[main, develop, \"release\/\*\*\"\]\n)/\$1    paths:\n      - 'src\/**'\n/" "$wf/ci.yml"
    grep -q "^    paths:" "$wf/ci.yml" || {
        echo "  [c] fixture injection FAILED (self-test is broken, not the gate)" >&2; return 2; }
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [c] paths:-filtered workflow carrying a required context: NOT CAUGHT (gate passed) — FAIL" >&2
        return 2
    fi
    echo "  [c] paths:-filtered pull_request trigger on a required-context carrier: CAUGHT"

    # ---- (b3) an unguarded step in a needs: classify job
    write_clean
    perl -0pi -e 's/(      - name: cargo check\n)/      - name: unguarded leak\n        run: echo this runs on docs-only PRs\n$1/' "$wf/ci.yml"
    grep -q "unguarded leak" "$wf/ci.yml" || {
        echo "  [b3] fixture injection FAILED (self-test is broken, not the gate)" >&2; return 2; }
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [b3] unguarded step in a 'needs: classify' job: NOT CAUGHT (gate passed) — FAIL" >&2
        return 2
    fi
    echo "  [b3] unguarded step in a 'needs: classify' job with no job-level 'if:': CAUGHT"

    # ---- (b4) a DECIDER carrying a job-level if: — hard fail, NOT ratchetable
    # `classify` is `needs:`-ed by `check` + `mobile` in the fixture, so it is a
    # decider. Skipping it skips both dependents, and each skipped required
    # dependent counts as SATISFIED — the fail-open that (b2)'s ratchet exists
    # to acknowledge, except here ONE entry would buy the whole subtree. The
    # second half of this leg is the load-bearing half: the gate must STILL
    # reject the shape when the context is allowlisted.
    write_clean
    perl -0pi -e 's/(  classify:\n    name: Classify changes\n)/$1    if: github.event_name != \x27schedule\x27\n/' "$wf/ci.yml"
    grep -q "^    if: github.event_name" "$wf/ci.yml" || {
        echo "  [b4] fixture injection FAILED (self-test is broken, not the gate)" >&2; return 2; }
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [b4] decider with a job-level 'if:': NOT CAUGHT (gate passed) — FAIL" >&2
        return 2
    fi
    printf 'Classify changes\n' > "$al"
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [b4] an ALLOWLISTED decider 'if:' was accepted — (b4) must outrank the (b2) ratchet — FAIL" >&2
        return 2
    fi
    echo "  [b4] decider (another job declares 'needs:' it) carrying a job-level 'if:': CAUGHT, and NOT allowlistable"

    # ---- (b2) ratchet: allowlisted passes, stale entry fails
    write_clean
    perl -0pi -e 's/(  parens:\n    name: Paren gate \(#1174 PR10\)\n)/$1    needs: classify\n    if: needs.classify.outputs.docs_only != \x27true\x27\n/' "$wf/ci.yml"
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [b2] un-allowlisted job-level 'if:' on a required context: NOT CAUGHT — FAIL" >&2
        return 2
    fi
    printf 'Paren gate (#1174 PR10)\n' > "$al"
    rc="$(run_fixture)"
    if [ "$rc" != "0" ]; then
        echo "  [b2] allowlisted job-level 'if:' still REJECTED (exit $rc) — the ratchet does not work" >&2
        return 2
    fi
    printf 'Paren gate (#1174 PR10)\nSome Retired Gate\n' > "$al"
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [b2] STALE ratchet entry: NOT CAUGHT — FAIL" >&2
        return 2
    fi
    echo "  [b2] job-level 'if:' fail-open ratchet (un-allowlisted FAILS, allowlisted PASSES, stale entry FAILS): CAUGHT"

    # ---- (d) the #2508 cancelled-duplicate carrier -------------------------
    # R-203: the CAUGHT fixture is the VERBATIM pre-#2509 `tool-count-drift.yml`
    # trigger + concurrency block (git 3d4f9baf) — not a paraphrase — so this
    # leg is anchored to the shape that actually shipped and actually produced
    # the cancelled rows observed on PRs #2499 and #2505. If rule (d) ever
    # stops rejecting THIS text, the historical defect can re-land.
    write_clean
    cat > "$wf/dup.yml" <<'YAML'
name: tool-count-drift

on:
  push:
    branches: [main, develop, "feat/**", "fix/**", "release/**"]
  pull_request:
    branches: [main, develop, "feat/**", "release/**"]

# Fork-PR-safe concurrency key: coalesces push + same-branch internal
# PR events; isolates fork PRs by PR number so they cannot collide
# with protected-branch keys. See ci.yml for full rationale.
concurrency:
  group: tool-count-drift-${{ github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.head.ref || github.event.pull_request.number || github.ref_name }}
  cancel-in-progress: true

jobs:
  grep-gate:
    name: tool-count grep gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: 'registry-vs-profile parity (count derived from src/mcp/registry.rs)'
        shell: bash
        run: echo ok
YAML
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [d] the VERBATIM pre-#2509 tool-count-drift.yml shape: NOT CAUGHT (gate passed) — FAIL" >&2
        return 2
    fi
    echo "  [d] R-203: the verbatim pre-#2509 tool-count-drift.yml trigger+concurrency block (the historical #2508 shape): CAUGHT"

    # The four NEAR MISSES. Each removes exactly ONE of the three conditions
    # and must PASS, so the rule is proven to fire on the defect rather than on
    # the neighbourhood — a rule that also rejects the FIX is worthless.
    local house_key event_key
    house_key='dup-${{ github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.head.ref || github.event.pull_request.number || github.ref_name }}'
    event_key='dup-${{ github.event_name }}-${{ github.ref_name }}'

    write_clean
    write_dup '[main, develop, "release/**"]' 'true' "$house_key"
    rc="$(run_fixture)"
    if [ "$rc" != "0" ]; then
        echo "  [d] the #2509 FIX shape (push.branches narrowed to base branches) was REJECTED (exit $rc) — the rule forbids its own remedy" >&2
        return 2
    fi
    write_clean
    write_dup '[main, develop, "feat/**", "fix/**"]' 'false' "$house_key"
    rc="$(run_fixture)"
    if [ "$rc" != "0" ]; then
        echo "  [d] overlapping push branches with 'cancel-in-progress: false' was REJECTED (exit $rc) — two SUCCESS runs are not the cancelled-duplicate class" >&2
        return 2
    fi
    write_clean
    write_dup '[main, develop, "feat/**", "fix/**"]' 'true' "$house_key" omit_pr
    rc="$(run_fixture)"
    if [ "$rc" != "0" ]; then
        echo "  [d] a push-ONLY workflow with overlapping branches was REJECTED (exit $rc) — one trigger cannot produce a duplicate" >&2
        return 2
    fi
    write_clean
    write_dup '[main, develop, "feat/**", "fix/**"]' 'true' "$event_key"
    rc="$(run_fixture)"
    if [ "$rc" != "0" ]; then
        echo "  [d] an event-DISTINCT concurrency group (\${{ github.event_name }}) was REJECTED (exit $rc) — that key cannot collide across events" >&2
        return 2
    fi
    echo "  [d] the four near-miss shapes (#2509-narrowed triggers / cancel-in-progress:false / push-only / event_name-keyed group) all PASS: the rule fires on the defect, not the neighbourhood"

    # The pending-fix ledger: scoped to ONE (workflow, pattern) pair, and an
    # entry that does not name a tracking issue is itself a failure.
    write_clean
    write_dup '[main, develop, "fix/**"]' 'true' "$house_key"
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [d] un-ledgered overlapping carrier: NOT CAUGHT — FAIL" >&2
        return 2
    fi
    printf 'dup.yml fix/** #2506\n' > "$dal"
    rc="$(run_fixture)"
    if [ "$rc" != "0" ]; then
        echo "  [d] a correctly-ledgered pending fix was still REJECTED (exit $rc) — the ledger does not work" >&2
        return 2
    fi
    printf 'dup.yml feat/** #2506\n' > "$dal"
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [d] a ledger entry for a DIFFERENT pattern absolved the real overlap — the ledger must be per-pattern — FAIL" >&2
        return 2
    fi
    printf 'dup.yml fix/**\n' > "$dal"
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [d] a ledger entry with NO tracking issue was accepted — an unexplained suppression — FAIL" >&2
        return 2
    fi
    echo "  [d] pending-fix ledger (correct entry PASSES, wrong-pattern entry FAILS, issue-less entry FAILS): per-pattern and self-documenting"

    echo "required-contexts gate self-test: PASS (load-bearing — catches the #2494 (b1) wedge, the (a) unmatched-context class, the (c) path-filtered carrier, the (b3) unguarded step, the (b4) unallowlistable decider 'if:', both directions of the (b2) ratchet, and the (d) #2508 cancelled-duplicate carrier in its verbatim historical form; spares a clean tree and all four near-miss shapes)"
}

if [ "${1:-}" = "--self-test" ]; then
    selftest
    exit $?
fi

# --dump prints the raw parse record stream. Diagnostic only — use it to see
# exactly which job `name:` the parser resolved (e.g. to confirm the §25.3
# YAML truncation is being reproduced rather than accidentally matched).
if [ "${1:-}" = "--dump" ]; then
    parse_workflows
    exit 0
fi

if [ "${1:-}" != "" ]; then
    echo "usage: $0 [--self-test|--dump]" >&2
    exit 2
fi

if run_gate; then
    echo "check-required-contexts: OK (${PROTECTED_BRANCH}: every mirrored required context maps to a reporting job; no matrix+if wedge; no decider with a job-level if; no path-filtered carrier; every needs-${CLASSIFY_JOB} step guarded; no dual-trigger cancelled-duplicate carrier)"
    exit 0
fi

echo "" >&2
echo "FAIL (#2494/#2496/#2508): the required-status-check set is not sound — see the rule citations above." >&2
echo "Mirror:    $MIRROR_FILE  (HAND-AUTHORED from intent — never regenerate from live API state)" >&2
echo "Ratchet:   $ALLOW_FILE   (burn-down; entries may only be removed)" >&2
echo "Pending:   $DUPTRIG_ALLOW_FILE   (rule (d) pending-fix ledger; each entry names its tracking issue)" >&2
echo "Self-test: scripts/check-required-contexts.sh --self-test" >&2
exit 1
