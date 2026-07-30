#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# R-203 behavioural + static proofs for the ci.yml invariants this PR lands.
#
#   SECTION A — the #2496 classification-base split (behavioural).
#   SECTION B — the #2500 test-invocation completeness invariant (static).
#
# THE DEFECT. `.github/workflows/ci.yml`'s `classify` job resolved ONE diff
# base and used it for BOTH `docs_only` classification AND test-impact
# selection. On `pull_request` `synchronize` that base was `github.event.before`
# — the PREVIOUS PR HEAD — so a PR whose LAST push was docs-only classified
# docs-only for its ENTIRE head, and eight required contexts went `skipped`
# (which branch protection counts as SATISFIED). Confirmed twice in the wild:
#   * PR #2031 merged to `main` as f5697a95 on 2026-07-14 with 22 of 23 files
#     non-docs (tests/conformance_corpus.rs, two interpreter readers, 18 .hex
#     vectors) and a final commit `docs(#1837): ...` — Lint / MSRV / Postgres /
#     SAL-only / actionlint / Dockerfile / Cross-compile all `skipped`, with
#     zero compilation, zero tests, zero clippy.
#   * PR #2497 (a CWE-284 federated-delete confinement fix), head 6d73ff0b,
#     third commit CLAUDE.md-only: `--- Changed files (1 files) --- CLAUDE.md`,
#     `docs-only diff — skipping Rust pipeline`, on a 12-file two-backend
#     security change.
#
# WHAT THIS TEST DOES. It EXTRACTS the classifier shell block verbatim from
# `.github/workflows/ci.yml` and executes it against throwaway git fixtures, so
# the assertions cannot drift from the workflow the way a hand-copied snippet
# would. `scripts/ci-test-impact.sh` is stubbed with a passthrough that records
# the base it was handed — that is what lets scenario 1 assert BOTH halves of
# the fix at once: classification widened to the PR base WHILE selection stayed
# incremental.
#
# It also runs scenario 1 against the PRE-FIX classifier, frozen as the
# committed fixture `scripts/test/fixtures/ci-classify-prefix-2496.sh`, and
# asserts that shape yields `docs_only=true`. That is the #2496 R-203
# requirement ("must fail against the 6c97e644 shape"), and it is what keeps
# this test load-bearing rather than tautological: if `extract_cls` ever
# silently stops finding the real block, every assertion above would go vacuous
# and only this leg would notice. The block is a committed fixture rather than a
# `git show` of the pre-fix commit precisely so it survives CI's shallow
# checkout — a regression leg that silently SKIPs in CI is not a regression leg.
#
# Scratch lives UNDER the repo (never system /tmp), trap-cleaned.
#
# CLI:
#   scripts/test/test-ci-workflow-invariants.sh   — run (exit 0/1)
# Env:
#   CI_YML                  — workflow to extract the live block from
#   CLASSIFY_BASELINE_FILE  — frozen pre-fix block (default the fixture above)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CI_YML="${CI_YML:-$ROOT/.github/workflows/ci.yml}"
BASELINE_FILE="${CLASSIFY_BASELINE_FILE:-$ROOT/scripts/test/fixtures/ci-classify-prefix-2496.sh}"

PASS=0
FAIL=0

ok()   { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  FAIL  %s\n         %s\n' "$1" "$2" >&2; FAIL=$((FAIL + 1)); }

# extract_cls <ci.yml-path>
# Pull the `run: |` body of the `classify` job's `- id: cls` step, dedented.
# Fails loudly if the step cannot be located — an extraction that silently
# returns nothing would make every assertion below vacuous.
extract_cls() {
    awk '
      /^      - id: cls$/ { instep = 1; next }
      instep && /^        run: \|$/ { inrun = 1; next }
      inrun {
        if ($0 == "") { print ""; next }
        if ($0 ~ /^          /) { print substr($0, 11); next }
        exit
      }
    ' "$1"
}

# ---------------------------------------------------------------------------
# Fixture builder. Creates a repo whose history is:
#   B  (base tip)              <- $PR_BASE_SHA
#   C1 (first PR commit)       <- $PR_BEFORE on synchronize
#   C2 (second PR commit)      <- HEAD
# The caller decides what C1 and C2 touch.
# ---------------------------------------------------------------------------
build_fixture() {
    local dir="$1" c1_kind="$2" c2_kind="$3"
    mkdir -p "$dir"
    (
        cd "$dir"
        git init -q .
        git config user.email ci@example.invalid
        git config user.name CI
        git config commit.gpgsign false
        mkdir -p src docs scripts tests
        echo "fn main() {}" > src/lib.rs
        echo "# readme" > README.md
        echo "# claude" > CLAUDE.md
        echo "# doc" > docs/a.md
        # Passthrough stub: records the base it was handed, then emits the
        # outputs the real script would. Asserting on this is how we prove the
        # SELECTION base stayed incremental while CLASSIFICATION widened.
        # Passthrough stub that MIRRORS the real script's `__SKIP__` rule: it
        # emits `__SKIP__` when ITS OWN (incremental) diff is all-docs. That is
        # what makes scenario 1 exercise the second-order guard — the real
        # script did exactly this on the live run and no-op'd `cargo test` on a
        # 9-non-docs-file PR. It also records the base it was handed, which is
        # how we prove SELECTION stayed incremental while CLASSIFICATION widened.
        cat > scripts/ci-test-impact.sh <<'STUB'
#!/usr/bin/env bash
echo "impact_base_received=$1"
echo "impact_base_received=$1" >> "$GITHUB_OUTPUT"
inc="$(git diff --name-only "$1" HEAD)"
if [ -n "$inc" ] && ! printf '%s\n' "$inc" | grep -qvE '^(docs/|.*\.md$)'; then
  echo "test_impact=__SKIP__" >> "$GITHUB_OUTPUT"
  echo "test_impact_reason=docs-only" >> "$GITHUB_OUTPUT"
else
  echo "test_impact=__STUB__" >> "$GITHUB_OUTPUT"
  echo "test_impact_reason=stub" >> "$GITHUB_OUTPUT"
fi
STUB
        chmod +x scripts/ci-test-impact.sh
        git add -A && git commit -qm base

        case "$c1_kind" in
            code)  echo "// c1 code" >> src/lib.rs ;;
            docs)  echo "c1 docs" >> docs/a.md ;;
            empty) : ;;
        esac
        if [ "$c1_kind" = "empty" ]; then git commit -q --allow-empty -m c1
        else git add -A && git commit -qm c1; fi

        case "$c2_kind" in
            code)    echo "// c2 code" >> src/lib.rs ;;
            docs)    echo "c2 docs" >> CLAUDE.md ;;
            revert)  git revert --no-edit HEAD >/dev/null 2>&1 ;;
            empty)   : ;;
        esac
        if [ "$c2_kind" = "revert" ]; then :
        elif [ "$c2_kind" = "empty" ]; then git commit -q --allow-empty -m c2
        else git add -A && git commit -qm c2; fi
    )
}

# run_cls <fixture-dir> <block-file> <env assignments...>
# Executes the extracted block inside the fixture and prints its STDOUT
# followed by its GITHUB_OUTPUT. Order matters: `getout` takes the LAST match,
# so GITHUB_OUTPUT (what the job actually consumes) authoritatively wins over
# any same-named key a sub-script merely echoed to the log. Stdout is included
# because the impact script reports there too, and the second-order guard
# deliberately does NOT forward its scratch keys to the real outputs.
run_cls() {
    local dir="$1" block="$2"; shift 2
    (
        cd "$dir"
        : > .gh_output
        env GITHUB_OUTPUT="$PWD/.gh_output" "$@" bash "$block" 2>/dev/null || true
        cat .gh_output
    )
}

getout() { printf '%s\n' "$1" | grep -E "^$2=" | tail -1 | cut -d= -f2-; }

SCRATCH="$(mktemp -d "$ROOT/.required-contexts-selftest.classifyXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT

BLOCK="$SCRATCH/cls-fixed.sh"
extract_cls "$CI_YML" > "$BLOCK"
if ! grep -q 'cls_base' "$BLOCK"; then
    echo "EXTRACTION FAILED: could not find the two-base classifier block in $CI_YML" >&2
    echo "(the test harness is broken, not the workflow — fix extract_cls)" >&2
    exit 2
fi
echo "ci.yml invariants — R-203 proofs (A: #2496 classify-base split, B: #2500 --no-fail-fast)"
echo "  extracted $(wc -l < "$BLOCK") lines of classifier shell from $CI_YML"

ZERO=0000000000000000000000000000000000000000

# --- Scenario 1: THE regression. Code earlier in the PR, docs-only LAST push.
F="$SCRATCH/s1"; build_fixture "$F" code docs
B="$(git -C "$F" rev-parse HEAD~2)"; C1="$(git -C "$F" rev-parse HEAD~1)"
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$C1")"
[ "$(getout "$OUT" docs_only)" = "false" ] \
    && ok "s1 code-then-docs PR (the #2031/#2497 shape) classifies docs_only=false" \
    || bad "s1 code-then-docs PR must NOT classify docs-only" "got docs_only=$(getout "$OUT" docs_only)"
[ "$(getout "$OUT" impact_base_received)" = "$C1" ] \
    && ok "s1 test-impact SELECTION still uses the incremental previous head" \
    || bad "s1 impact base must stay incremental (the optimisation must survive)" "expected $C1, got $(getout "$OUT" impact_base_received)"
# The SECOND-ORDER guard: the impact lane derived `__SKIP__` from the
# incremental (all-docs) diff. Honouring it would no-op `cargo test` on a code
# PR — exactly what the live run did before this guard existed.
[ "$(getout "$OUT" test_impact)" = "__ALL__" ] \
    && ok "s1 __SKIP__ from the incremental base is OVERRIDDEN to __ALL__ (tests are NOT no-op'd on a code PR)" \
    || bad "s1 test_impact must not stay __SKIP__ when the PR is not docs-only" "got test_impact=$(getout "$OUT" test_impact)"
[ "$(getout "$OUT" test_impact_reason)" = "impact-skip-overridden-not-docs-only" ] \
    && ok "s1 reports the second-order override reason token" \
    || bad "s1 override reason token" "got $(getout "$OUT" test_impact_reason)"

# --- Scenario 2: a genuinely docs-only PR must still short-circuit.
F="$SCRATCH/s2"; build_fixture "$F" docs docs
B="$(git -C "$F" rev-parse HEAD~2)"; C1="$(git -C "$F" rev-parse HEAD~1)"
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$C1")"
[ "$(getout "$OUT" docs_only)" = "true" ] \
    && ok "s2 genuinely docs-only PR still classifies docs_only=true (fast path preserved)" \
    || bad "s2 all-docs PR should still short-circuit" "got docs_only=$(getout "$OUT" docs_only)"
# The override must NOT fire here: __SKIP__ is legitimate when the classifier
# genuinely reached docs-only, and suppressing it would destroy the fast path.
[ "$(getout "$OUT" test_impact)" = "__SKIP__" ] \
    && ok "s2 __SKIP__ is HONOURED on a genuinely docs-only PR (override is not over-broad)" \
    || bad "s2 __SKIP__ must survive when docs_only is genuinely true" "got test_impact=$(getout "$OUT" test_impact)"

# --- Scenario 3: empty diff vs the PR base (the amend-force-push shape).
F="$SCRATCH/s3"; build_fixture "$F" code revert
B="$(git -C "$F" rev-parse HEAD~2)"; C1="$(git -C "$F" rev-parse HEAD~1)"
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$C1")"
[ "$(getout "$OUT" docs_only)" = "false" ] \
    && ok "s3 empty net diff FAILS CLOSED to docs_only=false (was docs_only=true)" \
    || bad "s3 empty diff must fail closed, not classify docs-only" "got docs_only=$(getout "$OUT" docs_only)"
[ "$(getout "$OUT" test_impact)" = "__ALL__" ] \
    && ok "s3 empty net diff selects __ALL__ (was __SKIP__)" \
    || bad "s3 empty diff must select __ALL__" "got test_impact=$(getout "$OUT" test_impact)"
[ "$(getout "$OUT" test_impact_reason)" = "empty-diff-fail-closed" ] \
    && ok "s3 reports the fail-closed reason token" \
    || bad "s3 reason token" "got $(getout "$OUT" test_impact_reason)"

# --- Scenario 4: `opened` (no PR_BEFORE) — both bases are the PR base.
F="$SCRATCH/s4"; build_fixture "$F" code docs
B="$(git -C "$F" rev-parse HEAD~2)"
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=opened PR_BASE_SHA="$B" PR_BEFORE="")"
[ "$(getout "$OUT" docs_only)" = "false" ] \
    && ok "s4 opened action classifies against the PR base" \
    || bad "s4 opened action" "got docs_only=$(getout "$OUT" docs_only)"
[ "$(getout "$OUT" impact_base_received)" = "$B" ] \
    && ok "s4 opened action widens the impact base to the PR base" \
    || bad "s4 opened impact base" "expected $B, got $(getout "$OUT" impact_base_received)"

# --- Scenario 5: reopened — PR_BEFORE present but action is not synchronize.
#     This is the path the `gh pr close && gh pr reopen` workaround exercised.
F="$SCRATCH/s5"; build_fixture "$F" code docs
B="$(git -C "$F" rev-parse HEAD~2)"; C1="$(git -C "$F" rev-parse HEAD~1)"
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=reopened PR_BASE_SHA="$B" PR_BEFORE="$C1")"
[ "$(getout "$OUT" docs_only)" = "false" ] && [ "$(getout "$OUT" impact_base_received)" = "$B" ] \
    && ok "s5 reopened ignores PR_BEFORE for both bases" \
    || bad "s5 reopened" "docs_only=$(getout "$OUT" docs_only) impact=$(getout "$OUT" impact_base_received)"

# --- Scenario 6: unresolvable classification base fails closed.
F="$SCRATCH/s6"; build_fixture "$F" code docs
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$ZERO" PR_BEFORE="")"
[ "$(getout "$OUT" docs_only)" = "false" ] && [ "$(getout "$OUT" test_impact_reason)" = "base-unreachable" ] \
    && ok "s6 all-zero classification base fails closed (base-unreachable)" \
    || bad "s6 base-unreachable" "docs_only=$(getout "$OUT" docs_only) reason=$(getout "$OUT" test_impact_reason)"

# --- Scenario 7: push-event semantics preserved (delta vs previous branch tip).
F="$SCRATCH/s7"; build_fixture "$F" docs docs
C1="$(git -C "$F" rev-parse HEAD~1)"
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=push PR_ACTION="" PR_BASE_SHA="" PR_BEFORE="$C1")"
[ "$(getout "$OUT" docs_only)" = "true" ] \
    && ok "s7 push event still classifies its own delta (no PR base exists)" \
    || bad "s7 push event" "got docs_only=$(getout "$OUT" docs_only)"

# --- Scenario 8: unknown event fails closed.
F="$SCRATCH/s8"; build_fixture "$F" code docs
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=schedule PR_ACTION="" PR_BASE_SHA="" PR_BEFORE="")"
[ "$(getout "$OUT" docs_only)" = "false" ] \
    && ok "s8 unknown event fails closed" \
    || bad "s8 unknown event" "got docs_only=$(getout "$OUT" docs_only)"

# --- Regression leg: the PRE-FIX block MUST mis-classify scenario 1. --------
# Fail-closed: a missing or repaired fixture is a FAILURE, never a SKIP. A
# regression leg that can quietly opt out is not evidence of anything.
if [ ! -s "$BASELINE_FILE" ]; then
    bad "regression leg: frozen pre-fix fixture missing" "$BASELINE_FILE"
elif ! grep -qE '^\s*base="\$PR_BEFORE"' "$BASELINE_FILE"; then
    bad "regression leg: frozen pre-fix fixture no longer carries the single-base shape" \
        "$BASELINE_FILE was 'fixed' — it is a historical artefact and must stay defective"
else
    F="$SCRATCH/r1"; build_fixture "$F" code docs
    B="$(git -C "$F" rev-parse HEAD~2)"; C1="$(git -C "$F" rev-parse HEAD~1)"
    OUT="$(run_cls "$F" "$BASELINE_FILE" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$C1")"
    [ "$(getout "$OUT" docs_only)" = "true" ] \
        && ok "regression: the frozen PRE-FIX block DOES mis-classify s1 as docs-only — the test is load-bearing" \
        || bad "regression leg did not reproduce the defect" \
               "got docs_only=$(getout "$OUT" docs_only) — extraction may be silently broken, making every assertion above vacuous"
    OUT="$(run_cls "$F" "$BASELINE_FILE" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$(git -C "$F" rev-parse HEAD)")"
    [ "$(getout "$OUT" docs_only)" = "true" ] \
        && ok "regression: the frozen PRE-FIX block ALSO classified an empty diff as docs-only" \
        || bad "regression: pre-fix empty-diff arm" "got docs_only=$(getout "$OUT" docs_only)"
fi

# ===========================================================================
# SECTION B — #2500: the watchdog-wrapped `cargo test` invocations must carry
# `--no-fail-fast`.
#
# WHY THIS IS A SEPARATE KIND OF CHECK from `check-required-contexts.sh`. That
# gate reasons about whether a required context CAN report at all — the
# success / skipped / absent / cancelled disposition space. This is about
# whether a run that DID report got as far as the binary carrying the proof.
# No context goes missing and nothing counts as vacuously satisfied: the
# context correctly goes RED. What is lost is the evidence after the first
# failing binary. So it is a diagnostic-completeness invariant, not a
# required-set soundness rule, and it deliberately lives here rather than in
# that gate — whose parser also skips `run:` block bodies by design, and so
# structurally cannot see a cargo invocation.
#
# THE EVIDENCE. PR #2497 run 30518877707 ATTEMPT 1 (job 90794703373):
# `e2_post_ship_dry_run` failed on a crates.io `[16] Error in the HTTP2
# framing layer` inside its nested `cargo build`; the invocation aborted and
# `tests/federation_delete_ns_scope_2488_pg.rs` — the binary proving a
# CWE-284 GA-blocker closed on postgres — appears NOWHERE in the log.
# (That evidence is only visible via `/runs/{id}/attempts/1/jobs`; the default
# `/runs/{id}/jobs` endpoint returns the latest attempt only, where the job
# shows `cancelled` and the abort is invisible. Same concealment family as
# `gh pr checks` reporting `pass` off a cancelled run.)
# ===========================================================================
echo "  --- Section B: #2500 test-invocation completeness ---"

# Every `cargo test` that is wrapped by the #1492 watchdog runs a MULTI-binary
# selection and must not fail fast. Single-target invocations (`--lib`,
# `--test <one>`) are unaffected by the flag and are not required to carry it.
watchdog_lines="$(grep -nE '(TIMEOUT_BIN|--kill-after=60)[^|]*cargo test' "$CI_YML" || true)"
if [ -z "$watchdog_lines" ]; then
    bad "B: found no watchdog-wrapped 'cargo test' invocation in $CI_YML" \
        "the #1492 watchdog wrapper was removed or renamed — this guard has gone blind"
else
    n_total=0; n_bad=0
    while IFS= read -r l; do
        [ -n "$l" ] || continue
        n_total=$((n_total + 1))
        case "$l" in
            *--no-fail-fast*) ;;
            *) n_bad=$((n_bad + 1)); printf '         missing --no-fail-fast: %s\n' "$l" >&2 ;;
        esac
    done <<< "$watchdog_lines"
    [ "$n_bad" -eq 0 ] \
        && ok "B: all $n_total watchdog-wrapped 'cargo test' invocations carry --no-fail-fast" \
        || bad "B: $n_bad of $n_total watchdog-wrapped 'cargo test' invocations lack --no-fail-fast" \
               "a single transient flake would discard every later binary's result (#2500)"
    # The un-wrapped fallback arm of each wrapper must match its wrapped twin,
    # or a runner without GNU timeout silently reverts to fail-fast.
    fallback_bad="$(grep -nE '^\s+cargo test "\$@"' "$CI_YML" || true)"
    [ -z "$fallback_bad" ] \
        && ok "B: no watchdog-fallback 'cargo test \"\$@\"' arm reverts to fail-fast" \
        || bad "B: a watchdog-fallback arm lacks --no-fail-fast" "$fallback_bad"
fi

# ===========================================================================
# SECTION C — #2494 RESIDUAL: the two DECIDER contexts are declared, reporting,
# and structurally kept that way.
#
# WHAT LANDED IN #2505. The wedge and the classifier were fixed, and the
# soundness gate + this harness shipped. What #2505 deliberately did NOT do was
# require the two jobs that DECIDE the docs-only short-circuit:
# `Classify changes` (ci.yml) and `Coverage classify (docs-only short-circuit)`
# (coverage.yml). One unrequired job pair governed the disposition of eleven
# required contexts.
#
# WHY REQUIRING THEM IS SAFE — the premise, asserted here rather than assumed.
# Both jobs have no `needs:`, no job-level `if:`, no `strategy:` and sit behind
# no `paths:` filter, so they ALWAYS run and always report a real
# success/failure. On the docs-only commit 45ba8741 that PROVED the #2494 wedge,
# both reported `success` — they are the only two contexts in these pipelines
# that report a genuine success on a docs-only diff rather than `skipped`.
# And the #2508 cancelled-duplicate hazard does not apply, because neither
# carrier's `push:` branch list can match a PR HEAD branch, so exactly one run
# exists per SHA. (Contrast `tool-count-drift.yml`, whose push branches include
# `fix/**` — on PR #2505's head 3fa45067 its context appears twice, once
# `cancelled` and once `success`. That is #2508. Deliberately NOT asserted here:
# coupling this leg to that file would make L0-b's fix fail this test.)
#
# Each of those four premises is a live property of the workflows, so each is
# checked, not trusted. C1 additionally re-derives the context STRINGS from the
# workflows through the gate's own audited parser (`--dump`) instead of a
# hand-copied literal, so a job rename that is not mirrored fails here as well
# as at gate rule (a) — the #2473 class applied to the new contexts.
# ===========================================================================
echo "  --- Section C: #2494 residual — the two decider contexts ---"

GATE="$ROOT/scripts/check-required-contexts.sh"
MIRROR="${RQC_MIRROR_FILE:-$ROOT/scripts/qc-allowlists/required-contexts-release.txt}"
PREFIX_MIRROR="${REQUIRED_CONTEXTS_BASELINE_FILE:-$ROOT/scripts/test/fixtures/required-contexts-prefix-2494.txt}"
# Overridable so each leg below can be mutation-tested against a planted copy
# without touching the real workflows.
WF_DIR="${RQC_WORKFLOW_DIR:-$ROOT/.github/workflows}"

# job_fact <workflow-basename> <job-id> <field>
# field: name | if | matrix | needs. Reads the audited parser's record stream so
# this harness cannot disagree with the gate about what the YAML says.
job_fact() {
    RQC_WORKFLOW_DIR="$WF_DIR" bash "$GATE" --dump 2>/dev/null | awk -F'\t' -v w="$1" -v j="$2" -v f="$3" '
        $1 == "JOB" && $2 == w && $3 == j {
            if (f == "name")   print $4
            if (f == "if")     print $5
            if (f == "matrix") print $6
            if (f == "needs")  print $7
        }'
}

# pr_branches <workflow-basename> / pr_paths <workflow-basename>
wf_fact() {
    RQC_WORKFLOW_DIR="$WF_DIR" bash "$GATE" --dump 2>/dev/null | awk -F'\t' -v w="$1" -v f="$2" '
        $1 == "WF" && $2 == w {
            if (f == "pr")       print $3
            if (f == "paths")    print $4
            if (f == "branches") print $5
        }'
}

# push_branches <workflow-path> — the gate's parser records only the
# pull_request branch list, so read the push list directly.
push_branches() {
    awk '
      function indent(l,  n) { n = 0; while (substr(l, n + 1, 1) == " ") n++; return n }
      /^[A-Za-z]/ { section = $0; sub(/:.*/, "", section) }
      section == "on" {
        ind = indent($0)
        line = $0; sub(/^[ \t]+/, "", line)
        if (ind == 2) { onkey = line; sub(/:.*/, "", onkey) }
        else if (ind == 4 && onkey == "push" && line ~ /^branches:/) {
          sub(/^branches:[ \t]*/, "", line); print line; exit
        }
      }
    ' "$1"
}

# declared_in_mirror <mirror-file> <context>
# Same comment rules as the gate's read_list: whole-line `#` only, so a context
# mentioned inside a KNOWN-GAPS comment does NOT count as declared. That
# distinction is the entire point of the regression leg below.
declared_in_mirror() {
    awk -v want="$2" '
        { line = $0; sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line) }
        line == "" { next }
        substr(line, 1, 1) == "#" { next }
        line == want { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$1"
}

# The two deciders: <workflow-basename> <job-id> <expected-mirror-context>
DECIDERS=(
    "ci.yml classify"
    "coverage.yml classify"
)

for entry in "${DECIDERS[@]}"; do
    set -- $entry
    dwf="$1"; djob="$2"
    dname="$(job_fact "$dwf" "$djob" name)"

    # C1 — the name the workflow actually reports is DECLARED in the mirror.
    if [ -z "$dname" ]; then
        bad "C1 $dwf job '$djob' could not be parsed" \
            "the harness or the parser is broken, not the workflow"
    elif declared_in_mirror "$MIRROR" "$dname"; then
        ok "C1 $dwf decider name '$dname' is DECLARED in the mirror"
    else
        bad "C1 $dwf decider '$dname' is NOT declared in $MIRROR" \
            "a required decider that the mirror does not declare is a context no gate rule is ever applied to (#2494 residual); if the job was renamed, update the mirror in the SAME change"
    fi

    # C2 — the premise that makes requiring it safe: it always runs.
    if [ "$(job_fact "$dwf" "$djob" if)" = "0" ] && [ "$(job_fact "$dwf" "$djob" matrix)" = "0" ]; then
        ok "C2 $dwf|$djob has NO job-level 'if:' and NO matrix (always runs, reports a real success/failure)"
    else
        bad "C2 $dwf|$djob acquired a job-level 'if:' or a matrix" \
            "a skipped decider skips every dependent, and each skipped required dependent counts as SATISFIED — gate rule (b4) hard-fails this"
    fi

    # C3 — the carrier fires on PRs to release/**, unfiltered.
    if [ "$(wf_fact "$dwf" pr)" = "1" ] && [ "$(wf_fact "$dwf" paths)" = "0" ] \
        && case ",$(wf_fact "$dwf" branches)," in *",release/**,"*) true ;; *) false ;; esac; then
        ok "C3 $dwf pull_request trigger covers release/** with no paths: filter"
    else
        bad "C3 $dwf pull_request trigger no longer covers release/** unfiltered" \
            "pr=$(wf_fact "$dwf" pr) paths=$(wf_fact "$dwf" paths) branches=$(wf_fact "$dwf" branches) — an unreportable required context wedges the branch"
    fi

    # C4 — the #2508 precondition: no push-branch pattern may match a PR head
    # branch, or every SHA carries a second `cancelled` row for this context.
    # Ratchet-shaped: the list must stay within the protected-branch patterns
    # below. `feat/v0.7.0-grand-slam` is a grandfathered LITERAL (a legacy pin
    # in coverage.yml), not a wildcard, so it cannot match a class of heads.
    pushb="$(push_branches "$WF_DIR/$dwf")"
    unexpected=""
    for tok in $(printf '%s' "$pushb" | tr -d '[]"' | tr ',' ' '); do
        case "$tok" in
            main | develop | 'release/**' | feat/v0.7.0-grand-slam) ;;
            "") ;;
            *) unexpected="$unexpected $tok" ;;
        esac
    done
    if [ -z "$unexpected" ]; then
        ok "C4 $dwf push branches are protected-branch-only ($pushb) — one run per SHA, no #2508 cancelled twin"
    else
        bad "C4 $dwf push: trigger gained branch pattern(s):$unexpected" \
            "if any of those can match a PR HEAD branch, this context gets a duplicate CANCELLED check-run on every SHA (#2508) and must not stay a required context in that shape"
    fi
done

# --- Regression leg (R-203): the frozen PRE-FIX mirror must FAIL C1. --------
# Fail-closed: a missing or repaired fixture is a FAILURE, never a SKIP.
if [ ! -s "$PREFIX_MIRROR" ]; then
    bad "C regression leg: frozen pre-fix mirror fixture missing" "$PREFIX_MIRROR"
elif declared_in_mirror "$PREFIX_MIRROR" "Classify changes" \
    || declared_in_mirror "$PREFIX_MIRROR" "Coverage classify (docs-only short-circuit)"; then
    bad "C regression leg: the frozen pre-fix mirror was 'repaired'" \
        "$PREFIX_MIRROR is a historical artefact and must keep BOTH deciders undeclared, or C1 becomes tautological"
else
    ok "C regression: the frozen PRE-FIX mirror declares NEITHER decider — C1 is load-bearing"

    # The behavioural half. Plant a job-level `if:` on ci.yml's decider in a
    # throwaway copy and run the REAL gate twice: with the live mirror it must
    # hard-fail rule (b4); with the frozen pre-fix mirror it must pass — which
    # is exactly the blind spot the declaration closes.
    MUT="$SCRATCH/mutated-wf"
    mkdir -p "$MUT"
    cp "$WF_DIR"/*.yml "$MUT"/
    awk '
      { print }
      /^    name: Classify changes$/ && !done { print "    if: github.event_name != '\''schedule'\''"; done = 1 }
    ' "$WF_DIR/ci.yml" > "$MUT/ci.yml"
    if ! grep -q "^    if: github.event_name" "$MUT/ci.yml"; then
        bad "C regression leg: could not plant the decider 'if:' fixture" \
            "the harness is broken, not the workflow"
    else
        live_rc=0
        RQC_WORKFLOW_DIR="$MUT" bash "$GATE" >/dev/null 2>&1 || live_rc=$?
        prefix_rc=0
        RQC_WORKFLOW_DIR="$MUT" RQC_MIRROR_FILE="$PREFIX_MIRROR" bash "$GATE" >/dev/null 2>&1 || prefix_rc=$?
        if [ "$live_rc" -ne 0 ] && [ "$prefix_rc" -eq 0 ]; then
            ok "C regression: a decider 'if:' is CAUGHT under the live mirror (b4) and passes SILENTLY under the frozen pre-fix mirror — the declaration is what makes the rule reachable"
        elif [ "$live_rc" -eq 0 ]; then
            bad "C regression: a job-level 'if:' on the ci.yml decider did NOT fail the gate" \
                "rule (b4) has gone blind — nine dependent required contexts could all go skipped-and-satisfied at once"
        else
            bad "C regression: the frozen pre-fix mirror also rejected the decider 'if:'" \
                "the baseline no longer reproduces the pre-fix blind spot (exit $prefix_rc) — the fixture may have been repaired"
        fi
    fi
fi

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "ci.yml invariants: $PASS/$PASS PASS"
    exit 0
fi
echo "ci.yml invariants: $FAIL FAILED, $PASS passed" >&2
exit 1
