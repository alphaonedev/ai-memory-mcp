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
extract_step() {
    awk -v id="$2" '
      $0 == "      - id: " id { instep = 1; next }
      instep && /^        run: \|$/ { inrun = 1; next }
      inrun {
        if ($0 == "") { print ""; next }
        if ($0 ~ /^          /) { print substr($0, 11); next }
        exit
      }
    ' "$1"
}
extract_cls() { extract_step "$1" cls; }

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
        # #8322: the cls block now calls scripts/ci/impact/cargo_skip.py, so the
        # fixture carries the REAL helper and rules (never a stub: the skip set
        # is the thing under test).
        mkdir -p scripts/ci/impact scripts/ci/tests
        cp "$ROOT/scripts/ci/impact/__init__.py" "$ROOT/scripts/ci/impact/common.py" \
           "$ROOT/scripts/ci/impact/cargo_skip.py" "$ROOT/scripts/ci/impact/rules.json" \
           scripts/ci/impact/
        echo "# ci test" > scripts/ci/tests/test_fixture.py
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
echo "$1" > .impact_base_received
inc="$(git diff --name-only "$1" HEAD)"
if [ -n "$inc" ] && ! printf '%s\n' "$inc" | grep -qvE '^(docs/|.*\.md$)'; then
  echo "test_impact=__SKIP__" >> "$GITHUB_OUTPUT"
  echo "test_impact_count=0" >> "$GITHUB_OUTPUT"
  echo "test_impact_total=0" >> "$GITHUB_OUTPUT"
  echo "test_impact_reason=docs-only" >> "$GITHUB_OUTPUT"
else
  echo "test_impact=__STUB__" >> "$GITHUB_OUTPUT"
  echo "test_impact_count=1" >> "$GITHUB_OUTPUT"
  echo "test_impact_total=1" >> "$GITHUB_OUTPUT"
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
            docs)    echo "c2 docs" >> docs/b.md ;;
            claude)  echo "c2 claude" >> CLAUDE.md ;;
            citests) echo "c2 citest" >> scripts/ci/tests/test_fixture.py ;;
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
#
# Round 3 (#8328, #8338): the test-impact selector runs in its own `impact`
# step with its own output file. When IMPACT_BLOCK names that step body, it is
# run after the cls block with the cls step outputs as its env (as the workflow
# wires them), and its output file is printed after the cls one. A frozen
# historical block is run with IMPACT_BLOCK empty.
run_cls() {
    local dir="$1" block="$2"; shift 2
    (
        cd "$dir"
        : > .gh_output
        rm -f .impact_base_received
        env GITHUB_OUTPUT="$PWD/.gh_output" "$@" bash --noprofile --norc -eo pipefail "$block" 2>/dev/null || true
        cat .gh_output
        if [ -n "${IMPACT_BLOCK:-}" ]; then
            local cls_out
            cls_out="$(cat .gh_output)"
            : > .gh_output_impact
            env GITHUB_OUTPUT="$PWD/.gh_output_impact" \
                CLS_BASE="$(getout "$cls_out" cls_base)" \
                IMPACT_BASE="$(getout "$cls_out" impact_base)" \
                DOCS_ONLY="$(getout "$cls_out" docs_only)" \
                IMPACT_FORCED_REASON="$(getout "$cls_out" impact_forced_reason)" \
                bash --noprofile --norc -eo pipefail "$IMPACT_BLOCK" > /dev/null 2>&1 || true
            cat .gh_output_impact
            if [ -f .impact_base_received ]; then
                echo "impact_base_received=$(cat .impact_base_received)"
            fi
        fi
    )
}

getout() { printf '%s\n' "$1" | grep -E "^$2=" | tail -1 | cut -d= -f2-; }

SCRATCH="$(mktemp -d "$ROOT/.required-contexts-selftest.classifyXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT

BLOCK="$SCRATCH/cls-fixed.sh"
extract_cls "$CI_YML" > "$BLOCK"
IMPACT_BLOCK="$SCRATCH/impact-fixed.sh"
extract_step "$CI_YML" impact > "$IMPACT_BLOCK"
if ! grep -q 'allow_re=' "$IMPACT_BLOCK"; then
    echo "EXTRACTION FAILED: could not find the impact step block in $CI_YML" >&2
    exit 2
fi
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
# #8328 (code review r1 F2): a push event always runs the full pipeline, so a
# docs-shaped delta no longer short-circuits either verdict.
[ "$(getout "$OUT" docs_only)" = "false" ] \
    && [ "$(getout "$OUT" cargo_skip)" = "false" ] \
    && case "$(getout "$OUT" cargo_skip_reason)" in push-event-full-ci*) true ;; *) false ;; esac \
    && ok "s7 push event forces docs_only=false and cargo_skip=false (push-event-full-ci)" \
    || bad "s7 push event must force the full pipeline" \
           "docs_only=$(getout "$OUT" docs_only) cargo_skip=$(getout "$OUT" cargo_skip) reason=$(getout "$OUT" cargo_skip_reason)"

# --- Scenario 8: unknown event fails closed.
F="$SCRATCH/s8"; build_fixture "$F" code docs
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=schedule PR_ACTION="" PR_BASE_SHA="" PR_BEFORE="")"
[ "$(getout "$OUT" docs_only)" = "false" ] \
    && ok "s8 unknown event fails closed" \
    || bad "s8 unknown event" "got docs_only=$(getout "$OUT" docs_only)"

# --- Scenario 9 (#3089, Merge Queue): a `merge_group` event MUST run the full
# pipeline — docs_only=false + __ALL__ — regardless of what the diff would be,
# so a queued PR's required contexts all report on the merge_group ref. Even a
# docs-shaped fixture must NOT short-circuit here.
F="$SCRATCH/s9"; build_fixture "$F" docs docs
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=merge_group PR_ACTION="" PR_BASE_SHA="" PR_BEFORE="")"
[ "$(getout "$OUT" docs_only)" = "false" ] \
    && [ "$(getout "$OUT" test_impact)" = "__ALL__" ] \
    && [ "$(getout "$OUT" test_impact_reason)" = "merge_group-full-pipeline" ] \
    && ok "s9 merge_group runs the full pipeline (docs_only=false, __ALL__) — no docs-only short-circuit" \
    || bad "s9 merge_group must run everything" \
           "docs_only=$(getout "$OUT" docs_only) impact=$(getout "$OUT" test_impact) reason=$(getout "$OUT" test_impact_reason)"

# --- Scenarios 10-13 (#8322): cargo_skip, the superset verdict the cargo legs
# consume. docs_only is now tightened to docs no Rust test reads.
F="$SCRATCH/s10"; build_fixture "$F" docs citests
B="$(git -C "$F" rev-parse HEAD~2)"; C1="$(git -C "$F" rev-parse HEAD~1)"
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$C1")"
[ "$(getout "$OUT" cargo_skip)" = "true" ] && [ "$(getout "$OUT" docs_only)" = "false" ] \
    && ok "s10 docs + scripts/ci/tests-only PR: cargo_skip=true, docs_only=false (#8322)" \
    || bad "s10 cargo_skip on tests-only diff" "cargo_skip=$(getout "$OUT" cargo_skip) docs_only=$(getout "$OUT" docs_only)"
[ "$(getout "$OUT" test_impact)" != "__SKIP__" ] \
    && ok "s10 __SKIP__ is not honoured unless docs_only is true (second-order guard intact)" \
    || bad "s10 __SKIP__ leak" "got test_impact=$(getout "$OUT" test_impact)"

F="$SCRATCH/s11"; build_fixture "$F" docs claude
B="$(git -C "$F" rev-parse HEAD~2)"; C1="$(git -C "$F" rev-parse HEAD~1)"
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$C1")"
[ "$(getout "$OUT" cargo_skip)" = "false" ] && [ "$(getout "$OUT" docs_only)" = "false" ] \
    && ok "s11 a PR touching CLAUDE.md (read by Rust tests) stays on full CI: cargo_skip=false, docs_only=false (#8322)" \
    || bad "s11 test-read doc must not skip" "cargo_skip=$(getout "$OUT" cargo_skip) docs_only=$(getout "$OUT" docs_only)"

F="$SCRATCH/s12"; build_fixture "$F" code docs
B="$(git -C "$F" rev-parse HEAD~2)"; C1="$(git -C "$F" rev-parse HEAD~1)"
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$C1")"
[ "$(getout "$OUT" cargo_skip)" = "false" ] \
    && ok "s12 a PR with src/ in the whole-PR diff keeps cargo_skip=false (classification base = PR base)" \
    || bad "s12 src diff must not skip" "cargo_skip=$(getout "$OUT" cargo_skip)"

F="$SCRATCH/s13"; build_fixture "$F" code revert
B="$(git -C "$F" rev-parse HEAD~2)"
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$B")"
O2="$(run_cls "$F" "$BLOCK" EVENT_NAME=merge_group PR_ACTION="" PR_BASE_SHA="" PR_BEFORE="")"
O3="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=opened PR_BASE_SHA=0000000000000000000000000000000000000000 PR_BEFORE="")"
[ "$(getout "$OUT" cargo_skip)" = "false" ] && [ "$(getout "$O2" cargo_skip)" = "false" ] && [ "$(getout "$O3" cargo_skip)" = "false" ] \
    && ok "s13 empty diff, merge_group and unresolvable base all fail closed: cargo_skip=false (#8322)" \
    || bad "s13 fail-closed cargo_skip" "empty=$(getout "$OUT" cargo_skip) merge_group=$(getout "$O2" cargo_skip) zero-base=$(getout "$O3" cargo_skip)"

# --- Scenarios 14-17 (#8328 round 2): trust root and forced full runs. ------
# s14: a push on any branch with a tests-only delta still runs in full.
F="$SCRATCH/s14"; build_fixture "$F" docs citests
C1="$(git -C "$F" rev-parse HEAD~1)"
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=push PR_ACTION="" PR_BASE_SHA="" PR_BEFORE="$C1")"
[ "$(getout "$OUT" cargo_skip)" = "false" ] && [ "$(getout "$OUT" docs_only)" = "false" ] \
    && ok "s14 push event with a tests-only delta: cargo_skip=false, docs_only=false (#8328)" \
    || bad "s14 push must force the full pipeline" "cargo_skip=$(getout "$OUT" cargo_skip) docs_only=$(getout "$OUT" docs_only)"

# s15: a PR into a protected base (release/*, main, develop) runs in full.
F="$SCRATCH/s15"; build_fixture "$F" docs citests
B="$(git -C "$F" rev-parse HEAD~2)"; C1="$(git -C "$F" rev-parse HEAD~1)"
S15_OK=true
for base_ref in release/v1.0.0 main develop; do
    OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$C1" PR_BASE_REF="$base_ref")"
    [ "$(getout "$OUT" cargo_skip)" = "false" ] && [ "$(getout "$OUT" docs_only)" = "false" ] || S15_OK=false
done
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$C1" PR_BASE_REF=chain/promo6-ssh-r2)"
[ "$(getout "$OUT" cargo_skip)" = "true" ] || S15_OK=false
$S15_OK \
    && ok "s15 PR into release/*, main, develop forces cargo_skip=false; a chain base keeps the skip (#8328)" \
    || bad "s15 protected base must force the full pipeline" "last cargo_skip=$(getout "$OUT" cargo_skip)"

# s16: a PR that rewrites its own classifier cannot pre-empt the verdict. The
# decider is read from the merge-base tree; the edit is itself a full run.
F="$SCRATCH/s16"; build_fixture "$F" docs citests
B="$(git -C "$F" rev-parse HEAD~2)"; C1="$(git -C "$F" rev-parse HEAD~1)"
printf '%s\n' 'print("docs_only=true")' 'print("cargo_skip=true")' 'print("cargo_skip_reason=planted")' > "$F/scripts/ci/impact/cargo_skip.py"
printf '%s\n' 'raise SystemExit(0)' > "$F/scripts/ci/impact/json.py"
echo "fn main() { let _ = 1; }" > "$F/src/lib.rs"
git -C "$F" add -A >/dev/null 2>&1
git -C "$F" commit -q -m "plant" >/dev/null 2>&1
C1="$(git -C "$F" rev-parse HEAD~1)"
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$C1")"
[ "$(getout "$OUT" cargo_skip)" = "false" ] && [ "$(getout "$OUT" docs_only)" = "false" ] \
    && ok "s16 a PR rewriting its classifier and planting a stdlib shadow still gets cargo_skip=false (#8328)" \
    || bad "s16 planted classifier must not decide" "cargo_skip=$(getout "$OUT" cargo_skip) docs_only=$(getout "$OUT" docs_only) reason=$(getout "$OUT" cargo_skip_reason)"

# s17: only the base tree is trusted: a base without the classifier fails closed.
F="$SCRATCH/s17"; build_fixture "$F" docs citests
B="$(git -C "$F" rev-parse HEAD~2)"; C1="$(git -C "$F" rev-parse HEAD~1)"
git -C "$F" rm -q -r scripts/ci/impact >/dev/null 2>&1
git -C "$F" commit -q -m "drop" >/dev/null 2>&1
S17_BASE="$(git -C "$F" rev-parse HEAD)"
echo "s17 doc" >> "$F/docs/a.md"
git -C "$F" commit -q -am "s17 pr" >/dev/null 2>&1
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$S17_BASE" PR_BEFORE="")"
[ "$(getout "$OUT" cargo_skip)" = "false" ] \
    && case "$(getout "$OUT" cargo_skip_reason)" in trusted-classifier-missing-in-base*) true ;; *) false ;; esac \
    && ok "s17 a base tree without the classifier fails closed (trusted-classifier-missing-in-base)" \
    || bad "s17 missing base classifier must fail closed" "cargo_skip=$(getout "$OUT" cargo_skip) reason=$(getout "$OUT" cargo_skip_reason)"

# s17b (REVIEW-8328-code-r2 F2): a base WITHOUT the classifier, a PR tree WITH one.
# The workspace copy must never stand in for the missing base-tree copy.
F="$SCRATCH/s17b"; build_fixture "$F" docs citests
S17B_DONOR="$(git -C "$F" rev-parse HEAD)"
git -C "$F" rm -q -r scripts/ci/impact >/dev/null 2>&1
git -C "$F" commit -q -m "drop" >/dev/null 2>&1
S17B_BASE="$(git -C "$F" rev-parse HEAD)"
git -C "$F" checkout -q "$S17B_DONOR" -- scripts/ci/impact >/dev/null 2>&1
echo "s17b doc" >> "$F/docs/a.md"
git -C "$F" add -A >/dev/null 2>&1
git -C "$F" commit -q -m "s17b pr: workspace has a classifier the base lacks" >/dev/null 2>&1
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$S17B_BASE" PR_BEFORE="")"
[ -f "$F/scripts/ci/impact/cargo_skip.py" ] \
    && [ "$(getout "$OUT" cargo_skip)" = "false" ] && [ "$(getout "$OUT" docs_only)" = "false" ] \
    && [ "$(getout "$OUT" cargo_skip_reason)" = "trusted-classifier-missing-in-base-fail-closed cargo_skip-rules" ] \
    && ok "s17b base lacks the classifier while the workspace has one: reason trusted-classifier-missing-in-base-fail-closed" \
    || bad "s17b a workspace classifier must not replace a missing base-tree classifier" \
           "cargo_skip=$(getout "$OUT" cargo_skip) docs_only=$(getout "$OUT" docs_only) reason=$(getout "$OUT" cargo_skip_reason)"

# s18 (#8338 class, REVIEW-8328-code-r2 F1): the two-step shape. The selector
# script of the PR tree emits a multi-line value opener; the cls verdict is
# written by a step that never ran it, so it stays authoritative, and the
# selector output degrades to the full selection.
F="$SCRATCH/s18"; build_fixture "$F" docs citests
B="$(git -C "$F" rev-parse HEAD~2)"; C1="$(git -C "$F" rev-parse HEAD~1)"
printf '%s\n' '#!/usr/bin/env bash' \
    'printf "%s\n" "x<""<EOF" >> "$GITHUB_OUTPUT"' \
    'printf "%s\n" "docs_only=true" "cargo_skip=true" >> "$GITHUB_OUTPUT"' > "$F/scripts/ci-test-impact.sh"
git -C "$F" add -A >/dev/null 2>&1
git -C "$F" commit -q -m "s18 selector edit" >/dev/null 2>&1
OUT="$(run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$C1")"
[ "$(getout "$OUT" docs_only)" = "false" ] && [ "$(getout "$OUT" cargo_skip)" = "false" ] \
    && [ "$(getout "$OUT" test_impact)" = "__ALL__" ] \
    && [ "$(getout "$OUT" test_impact_reason)" = "impact-output-rejected-fail-closed" ] \
    && ok "s18 a selector emitting a multi-line opener cannot change cls verdicts (false/false) and degrades to __ALL__" \
    || bad "s18 hostile selector output must leave the verdicts and degrade" \
           "docs_only=$(getout "$OUT" docs_only) cargo_skip=$(getout "$OUT" cargo_skip) impact=$(getout "$OUT" test_impact) reason=$(getout "$OUT" test_impact_reason)"
CLS_ONLY="$(IMPACT_BLOCK= run_cls "$F" "$BLOCK" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$C1")"
case "$CLS_ONLY" in
    *test_impact*) bad "s18 the cls step must not emit test_impact keys" "$(printf '%s' "$CLS_ONLY" | grep test_impact | head -1)" ;;
    *) ok "s18 the cls step output carries no test_impact key (they come from the impact step)" ;;
esac

# s19 (#8338 class; REVIEW-8328-*-r3 F1, REVIEW-8328-*-r4 F1/F2): the consumer
# is the boundary, and it is tested as the WHOLE step, not an extracted block.
# The consumer-check mode of scripts/ci/tests/test_impact_cargo_skip_8328.py
# runs the entire `Run tests (impact-aware)` step with a fake cargo on PATH
# for every selection shape (__SKIP__ with any docs_only, a name list, a word
# that starts with a dash, a glob, a newline, an unknown name) and compares
# the cargo argv with the full-suite or lib-plus-names argv. It also checks
# the exact step if:, the single reader of test_impact in any spacing or index
# form (if:, env:, with:), that nothing reads the selection before the
# boundary, that no exit or return sits between the boundary and the
# dispatch, and that the dispatch has exactly two arms.
S19_RC=0
S19_OUT="$(python3 -I "$ROOT/scripts/ci/tests/test_impact_cargo_skip_8328.py" consumer-check 2>&1)" || S19_RC=$?
S19_CLEAN="$(printf '%s\n' "$S19_OUT" | grep -cE '^consumer-check rows=[1-9][0-9]* problems=0$' || true)"
[ "$S19_RC" = "0" ] && [ "$S19_CLEAN" = "1" ] \
    && ok "s19 the whole test step maps __SKIP__ and every unvalidated selection to the full suite and runs only existing test names (every row and shape check clean)" \
    || bad "s19 the test consumer must run only validated existing test names" "rc=$S19_RC $(printf '%s\n' "$S19_OUT" | grep -E '^(problem|consumer-check)' | head -5 | tr '\n' ' ')"

# s20 (REVIEW-8328-code-r3 F2, REVIEW-8328-security-r3 F2/INFO-a): the impact
# step defuses workflow commands in the selector's STDOUT, and a long selector
# log (the `head` SIGPIPE under pipefail) does not fail the step.
F="$SCRATCH/s20"; mkdir -p "$F/scripts"
printf '%s\n' '#!/usr/bin/env bash' 'echo "::set-output name=x::y"' 'for i in $(seq 1 20000); do echo "noise $i"; done' \
    'printf "%s\n" "test_impact=a_test" "test_impact_count=1" "test_impact_total=2" "test_impact_reason=r" >> "$GITHUB_OUTPUT"' > "$F/scripts/ci-test-impact.sh"
S20_RC=0
S20_STDOUT="$(cd "$F" && : > out && env GITHUB_OUTPUT="$F/out" RUNNER_TEMP="$F" CLS_BASE=b IMPACT_BASE=b DOCS_ONLY=false IMPACT_FORCED_REASON= \
    bash --noprofile --norc -eo pipefail "$IMPACT_BLOCK" 2>&1)" || S20_RC=$?
S20_RAW="$(printf '%s\n' "$S20_STDOUT" | grep -c '^::' || true)"
S20_DEFUSED="$(printf '%s\n' "$S20_STDOUT" | grep -c '^: :set-output name=x: :y$' || true)"
[ "$S20_RC" = "0" ] && [ "$S20_RAW" = "0" ] && [ "$S20_DEFUSED" = "1" ] && [ "$(getout "$(cat "$F/out")" test_impact)" = "a_test" ] \
    && ok "s20 selector stdout is defused (no line starts with a double colon) and a 20000-line log does not fail the step" \
    || bad "s20 defuse or truncation broken" "rc=$S20_RC raw=$S20_RAW defused=$S20_DEFUSED"

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
    OUT="$(IMPACT_BLOCK= run_cls "$F" "$BASELINE_FILE" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$C1")"
    [ "$(getout "$OUT" docs_only)" = "true" ] \
        && ok "regression: the frozen PRE-FIX block DOES mis-classify s1 as docs-only — the test is load-bearing" \
        || bad "regression leg did not reproduce the defect" \
               "got docs_only=$(getout "$OUT" docs_only) — extraction may be silently broken, making every assertion above vacuous"
    OUT="$(IMPACT_BLOCK= run_cls "$F" "$BASELINE_FILE" EVENT_NAME=pull_request PR_ACTION=synchronize PR_BASE_SHA="$B" PR_BEFORE="$(git -C "$F" rev-parse HEAD)")"
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
#
# SCOPE OF "FROZEN" (#2473). The behavioural half below runs the REAL gate with
# the frozen mirror against the REAL workflow directory and requires exit 0, so
# the fixture must stay rule-(a)-consistent with the LIVE workflows for every
# context OTHER than the two under test. A job rename that the fixture does not
# track therefore fails this leg — correctly, but with a misleading message, so
# the fixture header states which of its properties is frozen (the decider
# absence, asserted mechanically just below) and which merely tracks reality.
# #2473's quoting of `l3-boundary-gate`'s name is the first instance.
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
        # The assertion is on WHICH RULE fires, not on the exit code (#2636).
        # Exit codes stopped being able to express this claim the moment rule
        # (f) landed: under the frozen mirror the undeclared jobs are exactly
        # what (f) exists to catch, so the pre-fix run now exits non-zero for a
        # reason that has nothing to do with the blind spot under test. Keying
        # on the rule name states the real property — "rule (b4) cannot see
        # this decider until the mirror declares it" — and is strictly stronger
        # than the exit-code form it replaces, which a single unrelated new
        # rule was able to invalidate.
        live_out="$(RQC_WORKFLOW_DIR="$MUT" bash "$GATE" 2>&1 || true)"
        prefix_out="$(RQC_WORKFLOW_DIR="$MUT" RQC_MIRROR_FILE="$PREFIX_MIRROR" bash "$GATE" 2>&1 || true)"
        case "$live_out" in *"RULE (b4)"*) live_b4=1 ;; *) live_b4=0 ;; esac
        case "$prefix_out" in *"RULE (b4)"*) prefix_b4=1 ;; *) prefix_b4=0 ;; esac
        if [ "$live_b4" -eq 1 ] && [ "$prefix_b4" -eq 0 ]; then
            ok "C regression: a decider 'if:' is CAUGHT BY RULE (b4) under the live mirror and is INVISIBLE to (b4) under the frozen pre-fix mirror — the declaration is what makes the rule reachable"
        elif [ "$live_b4" -eq 0 ]; then
            bad "C regression: a job-level 'if:' on the ci.yml decider did NOT trip rule (b4)" \
                "rule (b4) has gone blind — nine dependent required contexts could all go skipped-and-satisfied at once"
        else
            bad "C regression: the frozen pre-fix mirror ALSO tripped rule (b4)" \
                "the baseline no longer reproduces the pre-fix blind spot — the fixture may have been repaired"
        fi
    fi
fi

# ===========================================================================
# SECTION D — #2657: the watchdog must time test RUNTIME, not compile+run.
#
# THE DEFECT. `ci.yml` carries TWO near-identical test-runner shell functions:
# `run_tests` in the `check` job and `pg_test` in the `Postgres feature gate`
# job. #1989 hoisted compilation OUT of the timed window in `run_tests` and
# never touched its twin, so for the whole of the v1.0.0 epic the postgres
# gate's 2100s cap measured compile+run.
#
# MEASURED on run 30718303500 attempt 2: the timed invocation began 22:16:43
# and the first `Running tests/...` line appeared at 22:24:41 — 478s (23% of
# the cap) spent compiling 316 crates INSIDE the window. Tests then ran 1605s
# before the SIGTERM; 478 + 1605 = 2083s against a 2100s cap, and the kill
# landed 99% of the way through (547 of 550 binaries had run). Nothing hung.
#
# WHY IT IS A SEPARATE INVARIANT FROM SECTION B. B is about diagnostic
# completeness — a run that DID report should reach the binary carrying the
# proof. This is about a MEASUREMENT being of the wrong quantity: the cap is
# hang-detection, and a hang is a property of the RUN. Worse, the error it
# produces is a `::error::[#1492 watchdog] ... exceeded the timeout` naming a
# hang that did not occur, so the misfire actively misdirects triage.
#
# WHY IT MUST BE A GATE RATHER THAN A FIX. The failure mode is TWIN DRIFT: two
# copies of one discipline, one fixed and one silently left behind. Fixing
# `pg_test` alone would leave the class open the next time a runner is added.
# So this rule is stated over EVERY watchdog-wrapped invocation, not over the
# two functions that exist today.
#
# WHY THE SHORT-CIRCUIT IS PART OF THE RULE. The prebuild must be
# `... || return "$?"`: a compile failure has to fail the job at the prebuild,
# not fall through into a `timeout` run that reports a second, confusing error.
# ===========================================================================
echo "  --- Section D: #2657 watchdog measures RUNTIME, not compile+run ---"

# d_scan <ci.yml-path> — prints "<bad>/<total>" over the watchdog-wrapped
# `cargo test` invocations in that file. A wrapped invocation is COVERED when a
# short-circuiting `--no-run` prebuild appears between the opener of its own
# enclosing shell function and the invocation itself. Factored out so the R-203
# regression leg below can run the IDENTICAL logic against a mutated copy.
d_scan() {
    local file="$1" total=0 bad=0 line w opener prebuild
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        total=$((total + 1))
        w="${line%%:*}"
        # Nearest enclosing `name() {` opener above the invocation.
        opener="$(awk -v w="$w" '
            NR < w && /^[[:space:]]+[A-Za-z_][A-Za-z0-9_]*\(\)[[:space:]]*\{[[:space:]]*$/ { n = NR }
            END { print n + 0 }' "$file")"
        if [ "$opener" -eq 0 ]; then
            bad=$((bad + 1))
            printf '         watchdog line %s is not inside a shell function\n' "$w" >&2
            continue
        fi
        prebuild="$(awk -v a="$opener" -v b="$w" '
            NR > a && NR < b && /cargo test --no-run "\$@"( "\$\{sel\[@\]\}")? \|\| return "\$\?"/ { n = NR }
            END { print n + 0 }' "$file")"
        if [ "$prebuild" -eq 0 ]; then
            bad=$((bad + 1))
            printf '         no short-circuiting `cargo test --no-run "$@" || return "$?"` between the function opener (line %s) and the timed invocation (line %s)\n' \
                "$opener" "$w" >&2
        fi
    done <<< "$(grep -nE '(TIMEOUT_BIN|--kill-after=60)[^|]*cargo test' "$file" || true)"
    printf '%s/%s' "$bad" "$total"
}

d_result="$(d_scan "$CI_YML")"
d_bad="${d_result%%/*}"
d_total="${d_result##*/}"
if [ "$d_total" -eq 0 ]; then
    bad "D: found no watchdog-wrapped 'cargo test' invocation in $CI_YML" \
        "the #1492 watchdog wrapper was removed or renamed — this guard has gone blind"
elif [ "$d_bad" -eq 0 ]; then
    ok "D: all $d_total watchdog-wrapped 'cargo test' invocations hoist compilation out of the timed window"
else
    bad "D: $d_bad of $d_total watchdog-wrapped 'cargo test' invocations compile INSIDE the timed window" \
        "the per-invocation cap then measures compile+run and shrinks as test files are added, and its ::error:: names a hang that did not occur (#2657; #1989 fixed only the check-job twin)"
fi

# R-203 regression leg: strip the prebuild from a throwaway copy and require
# the scan to CATCH it. Without this, a scan whose regex silently stopped
# matching would report 0/0-clean forever — the same vacuous-assertion hazard
# Sections A and C each carry a frozen-fixture leg against. Scratch lives under
# the repo (never system /tmp), trap-cleaned by the SCRATCH dir above.
if [ "$d_total" -gt 0 ]; then
    D_MUT="$SCRATCH/ci-2657-mutant.yml"
    grep -vE 'cargo test --no-run "\$@"( "\$\{sel\[@\]\}")? \|\| return "\$\?"' "$CI_YML" > "$D_MUT"
    d_mut_result="$(d_scan "$D_MUT" 2>/dev/null)"
    d_mut_bad="${d_mut_result%%/*}"
    if [ "$d_mut_bad" -eq "$d_total" ]; then
        ok "D regression: stripping every --no-run prebuild makes ALL $d_total invocations fail the scan — the rule is load-bearing"
    else
        bad "D regression: the prebuild-stripped mutant did not fail the scan ($d_mut_result)" \
            "the scan has gone blind — every assertion above is vacuous"
    fi
fi

# ===========================================================================
# SECTION E — #3496: coverage profile aggregation stays executable and exact.
#
# cargo-llvm-cov 0.9.0 rejects `--no-clean --no-report`. The ordinary sweep
# must therefore stop before reporting, while the one explicitly named,
# ignored PostgreSQL proof retains those profiles and renders the combined
# JSON. Keep the local wrapper token-for-token aligned with CI.
# ===========================================================================
echo "  --- Section E: #3496 coverage profile aggregation ---"

COVERAGE_YML="$ROOT/.github/workflows/coverage.yml"
COVERAGE_SH="$ROOT/scripts/coverage.sh"
RUST_ACTION_PIN="f8be11a05b1d4f3fcebe6410cc16743212b999b0"

coverage_toolchain_ok() {
    local file="$1"
    [ "$(grep -Fxc "        uses: dtolnay/rust-toolchain@$RUST_ACTION_PIN # 1.98.0" "$file" || true)" -eq 1 ] \
        && [ "$(grep -Fxc '          toolchain: "1.98.0"' "$file" || true)" -eq 1 ]
}

if coverage_toolchain_ok "$COVERAGE_YML"; then
    ok "E: coverage pins the action revision and Rust toolchain to exact 1.98.0"
else
    bad "E: coverage Rust toolchain is floating or mis-pinned" \
        "pin dtolnay/rust-toolchain@$RUST_ACTION_PIN and toolchain 1.98.0"
fi

# R-203: prove both halves of the pin are load-bearing. A floating action ref
# or a floating toolchain input must independently fail the structural gate.
E_ACTION_MUT="$SCRATCH/coverage-3496-action-mutant.yml"
awk '
  !mutated && /uses: dtolnay\/rust-toolchain@/ {
    sub(/dtolnay\/rust-toolchain@[^[:space:]]+/, "dtolnay/rust-toolchain@stable"); mutated = 1
  }
  { print }
' "$COVERAGE_YML" > "$E_ACTION_MUT"
if coverage_toolchain_ok "$E_ACTION_MUT"; then
    bad "E regression: floating Rust action mutant passed" \
        "the exact dtolnay/rust-toolchain action revision check is vacuous"
else
    ok "E regression: floating Rust action mutant is rejected"
fi

E_TOOLCHAIN_MUT="$SCRATCH/coverage-3496-toolchain-mutant.yml"
awk '
  !mutated && /toolchain: "1\.98\.0"/ {
    sub(/toolchain: "1\.98\.0"/, "toolchain: \"stable\""); mutated = 1
  }
  { print }
' "$COVERAGE_YML" > "$E_TOOLCHAIN_MUT"
if coverage_toolchain_ok "$E_TOOLCHAIN_MUT"; then
    bad "E regression: floating Rust toolchain mutant passed" \
        "the exact 1.98.0 toolchain input check is vacuous"
else
    ok "E regression: floating Rust toolchain mutant is rejected"
fi

# Print each backslash-continued cargo-llvm-cov command on one normalized line.
coverage_commands() {
    awk '
      /^[[:space:]]*cargo llvm-cov([[:space:]]|$)/ && !in_cmd {
        in_cmd = 1; cmd = $0
        if ($0 !~ /\\[[:space:]]*$/) { print cmd; in_cmd = 0 }
        next
      }
      in_cmd {
        cmd = cmd " " $0
        if ($0 !~ /\\[[:space:]]*$/) { print cmd; in_cmd = 0 }
      }
    ' "$1" | sed 's/[[:space:]\\][[:space:]\\]*/ /g; s/^ //; s/ $//'
}

coverage_sequence_ok() {
    local file="$1" commands ordinary named
    commands="$(coverage_commands "$file")"
    ordinary="$(printf '%s\n' "$commands" | grep -- '--lib --tests' || true)"
    named="$(printf '%s\n' "$commands" \
        | grep -- '-- schema_init_postgres_embedding_dim_conversion' || true)"
    [ "$(printf '%s\n' "$ordinary" | grep -c . || true)" -eq 1 ] \
        && [ "$(printf '%s\n' "$named" | grep -c . || true)" -eq 1 ] \
        && [[ "$ordinary" == *"--no-report"* ]] \
        && [[ "$ordinary" != *"--no-clean"* ]] \
        && [[ "$named" == *"--no-clean"* ]] \
        && [[ "$named" != *"--no-report"* ]] \
        && [[ "$named" == *"--json"* ]] \
        && [[ "$named" == *"--output-path coverage/current.json"* ]] \
        && [[ "$named" == *"--ignored --test-threads=1"* ]]
}

if coverage_sequence_ok "$COVERAGE_YML" && coverage_sequence_ok "$COVERAGE_SH"; then
    yml_commands="$(coverage_commands "$COVERAGE_YML")"
    sh_commands="$(coverage_commands "$COVERAGE_SH")"
    yml_ordinary="$(printf '%s\n' "$yml_commands" | grep -- '--lib --tests')"
    sh_ordinary="$(printf '%s\n' "$sh_commands" | grep -- '--lib --tests')"
    yml_named="$(printf '%s\n' "$yml_commands" | grep -- '-- schema_init_postgres_embedding_dim_conversion')"
    sh_named="$(printf '%s\n' "$sh_commands" | grep -- '-- schema_init_postgres_embedding_dim_conversion')"
    if [ "$yml_ordinary" = "$sh_ordinary" ] && [ "$yml_named" = "$sh_named" ]; then
        ok "E: CI and local coverage use identical valid ordinary + PostgreSQL aggregation commands"
    else
        bad "E: CI and local coverage command tokens drifted" \
            "scripts/coverage.sh must mirror coverage.yml for both aggregation phases"
    fi
else
    bad "E: coverage aggregation command shape is invalid" \
        "require ordinary --no-report, then named --no-clean + JSON report; never combine --no-clean with --no-report"
fi

# R-203: plant the exact cargo-llvm-cov 0.9.0-invalid option pair and require
# this gate to reject it, proving the argument scan is not vacuous.
E_MUT="$SCRATCH/coverage-3496-mutant.yml"
awk '
  !mutated && /--no-clean/ {
    sub(/--no-clean/, "--no-clean --no-report"); mutated = 1
  }
  { print }
' "$COVERAGE_YML" > "$E_MUT"
if coverage_sequence_ok "$E_MUT"; then
    bad "E regression: cargo-llvm-cov-invalid mutant passed" \
        "the scan failed to detect --no-clean combined with --no-report"
else
    ok "E regression: --no-clean + --no-report mutant is rejected"
fi

# SECTION F (#5447): pull_request / push branch-filter pins across every
# workflow. rehearsal/** must gate PRs (pull_request.branches) and must never
# overlap push.branches (#2506, #2523, #2508). Closed-world, stdlib-only reader.
if python3 "$ROOT/scripts/test/test_workflow_pr_triggers_5447.py" >"$SCRATCH/f-5447.out" 2>&1; then
    ok "F: every workflow pins rehearsal/** in pull_request.branches and never in push.branches (#5447)"
else
    bad "F: workflow trigger pin failed (#5447)" \
        "$(grep -E 'R-(PR|PUSH|SHAPE)|^FAIL|^ERROR' "$SCRATCH/f-5447.out" | head -12)"
fi

# ===========================================================================
# SECTION G — #6383 / #6386: the opt-in per-binary Postgres isolation lane.
# The checks live in Python (review r1 L1): scripts/ci/check_pg_isolate_invariants.py,
# unit-tested with one mutant per check in scripts/ci/tests/.
# ===========================================================================
if python3 "$ROOT/scripts/ci/check_pg_isolate_invariants.py" --root "$ROOT" --ci-yml "$CI_YML"; then ok "G: #6383 pg-isolation invariants (opt-in, run-scoped, no URL argv, selected prebuild, watchdog, logs)"; else bad "G: #6383 pg-isolation invariants failed" "see output above"; fi

# ===========================================================================
# SECTION H — #8332: a body-only PR edit never cancels or restarts the required
# checks. Any workflow that lists `edited` on a pull_request(_target) trigger
# must carry the body-only guard on cancel-in-progress; ci.yml and coverage.yml
# do not list `edited` (a base retarget lands only after a new head push, checked by
# scripts/ci/pr_retarget_check.py).
# The checks live in Python: scripts/test/test_workflow_edited_cancel_8332.py.
# ===========================================================================
if python3 -I "$ROOT/scripts/test/test_workflow_edited_cancel_8332.py" >"$SCRATCH/h-8332.out" 2>&1; then
    ok "H: a body-only PR edit never cancels or restarts a required check (#8332)"
else
    bad "H: a workflow lists 'edited' with cancel-in-progress and no body-only guard (#8332)" \
        "$(grep -E '^(FAIL|ERROR)|AssertionError|lists .edited.' "$SCRATCH/h-8332.out" | head -12)"
fi

# The retarget check (live gh path through a stub gh, exit 0/65/70) runs here too: this script is
# the CI step (c8-precheck.yml) that executes it (REVIEW-8332-code-r2 F2).
if python3 -I "$ROOT/scripts/test/test_pr_retarget_check_8332.py" >"$SCRATCH/h-8332-retarget.out" 2>&1; then
    ok "H: the base-retarget landing check refuses stale, fails closed on gh errors (#8332)"
else
    bad "H: scripts/ci/pr_retarget_check.py live-path test failed (#8332)" \
        "$(grep -E '^(FAIL|ERROR)|AssertionError' "$SCRATCH/h-8332-retarget.out" | head -12)"
fi

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "ci.yml invariants: $PASS/$PASS PASS"
    exit 0
fi
echo "ci.yml invariants: $FAIL FAILED, $PASS passed" >&2
exit 1
