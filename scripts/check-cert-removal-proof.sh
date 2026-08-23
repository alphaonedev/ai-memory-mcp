#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# CERT GATE — §5.4(5) removal proof + negative control
# (2026-08-01 cutline ruling, docs/audit/3x7-v1-cutline-ruling-2026-08-01.md).
#
# WHY THIS EXISTS. The ruling §5.4(5) requires: "every cited control has a test
# that FAILS when the control is deleted, and at least one deliberately broken
# control is shown turning the certification RED." The existing federation-
# confinement lane tests (#2447/#2478/#2479/#2488/#2708 + pg twins) exercise the
# controls END-TO-END through the `/sync/push` handler, so a passing suite does
# NOT, on its own, PROVE each control is load-bearing — a control could be dead
# code and the suite still green if some other guard happened to cover the case.
# This harness closes that gap MECHANICALLY: for each cited control it MUTATES
# the guard to always-allow (the deliberately-broken control), runs the guard's
# lane test, and asserts the test goes RED; then reverts and asserts GREEN. A
# control whose mutation does NOT turn its lane test red is NOT load-bearing —
# that is a cert-RED finding, not a pass.
#
# This is the `--self-test` "plant-a-violation, confirm-rejection" discipline the
# repo's other CERT/lint gates use (check-vendor-literals.sh, check-docs-vs-ssot.sh),
# applied to runtime security controls instead of to source text.
#
# PER-ROW TARGET + TWO MUTATION SHAPES (PR-0, forensic-audit-trail wave). Each
# control row names its OWN target file (there is no single global TARGET_FILE),
# and each row declares a mutation SHAPE so a control that is not expressible as
# a first-statement `return` can still be neutralized:
#
#   shape=return : insert <mutation-payload> as the FIRST statement of the named
#                  `pub fn <control>` body — forces the always-allow disposition
#                  (the original, and only, grammar before PR-0).
#   shape=body   : REPLACE THE ENTIRE BODY of the named `pub fn <control>` with
#                  <mutation-payload> — neutralizes a control expressed as a
#                  multi-term `&&` guard or a multi-branch verdict fn, where a
#                  single injected first statement cannot bypass every arm.
#   shape=subst  : literal find/replace ONE unique occurrence of <OLD> with
#                  <NEW>, where <mutation-payload> = "<OLD>>>><NEW>" (the `>>>`
#                  delimiter never appears in Rust). Neutralizes a control that
#                  is a SINGLE FIELD BINDING / expression buried mid-function
#                  (not a whole guard fn) — e.g. the consolidate builder's
#                  `confidence` floor or `memory_kind` stamp, where neither a
#                  first-statement return nor a whole-body swap can target the
#                  one binding without breaking the surrounding function. <NEW>
#                  MUST embed the `// CERT-REMOVAL-PROOF-MUTATION` marker (the
#                  harness greps it to confirm the edit landed + a clean
#                  revert). The `<ctl>` column is a descriptive control LABEL
#                  (the function locator is not used for this shape). A payload
#                  whose <OLD> matches 0 or >1 sites is a hard error (exit 3) so
#                  a subst can never silently over-mutate.
#
# SAFETY (#3119 — hardened after the #3118 near-miss; read this before editing).
# This harness DISABLES PRODUCTION SECURITY CONTROLS IN THE WORKING TREE for the
# duration of a guard run. On 2026-08-22 an aborted run (killed at a two-minute
# timeout) left `inbound_write_namespace_authorized` short-circuited to
# always-allow — a cross-tenant inbound federated-write authorization BYPASS —
# and a later `git add -A` swept it onto a pushed PR branch (#3118, never
# merged, base never affected). Root cause was STRUCTURAL: restoration happened
# only on the happy/handled paths, with no `trap`, so any signal/crash left the
# control off with nothing in `git status` a human reads as "security control
# disabled". Four layers now stand between a mutation and a commit:
#
#   1. TRAP. Every path this run mutates is registered in `MUTATED` BEFORE it is
#      rewritten; an EXIT/INT/TERM/HUP trap restores all of them and then
#      PROPAGATES the original disposition (see `on_exit` / `on_signal`).
#   2. START GUARD. A pre-existing marker in `src/` (an aborted earlier run)
#      makes the harness REFUSE to start — loudly, non-zero — instead of piling
#      a second mutation on a disabled control. `--force-restore` is the
#      deliberate, backed-up recovery path.
#   3. END ASSERTION. Both the normal end of the run and the trap assert the
#      marker is ABSENT from `src/`, and shout `SECURITY: mutation still present
#      in <files>` + exit non-zero if it is not.
#   4. REPO-WIDE GATE. `scripts/check-mutation-marker.sh` (wired into CI's
#      L3-boundary perma-ban job) fails on the marker anywhere under `src/`,
#      however it got there.
#
# Restoration is `git checkout HEAD -- <paths>` (index AND worktree), and the
# PER-ROW guard therefore refuses when ITS OWN target differs from HEAD in
# EITHER — an index-only restore would have re-written the #3118 staged mutation
# straight back into the worktree. An unrelated dirty file still never aborts
# the run, and a revert can never clobber real edits to the file under test.
# Evidence is written under .local-runs/.
#
# USAGE:
#   scripts/check-cert-removal-proof.sh                 # all controls
#   scripts/check-cert-removal-proof.sh <control-name>  # one control
#   scripts/check-cert-removal-proof.sh --list          # print the control map
#   scripts/check-cert-removal-proof.sh --self-test     # prove the mutation
#                                                        # shapes rewrite source
#                                                        # as intended AND that
#                                                        # an interrupted run
#                                                        # leaves a clean tree
#                                                        # (no cargo)
#   scripts/check-cert-removal-proof.sh --force-restore # recover a tree an
#                                                        # aborted run left
#                                                        # mutated (backs up
#                                                        # first, then exits 0)
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="$REPO_ROOT/scripts/$(basename "${BASH_SOURCE[0]}")"
cd "$REPO_ROOT"
EVIDENCE_DIR=".local-runs/cert-54-evidence"
mkdir -p "$EVIDENCE_DIR"

# ─── #3119 interrupt-safety substrate ────────────────────────────────────────

# The mutation marker — SSOT for the trap, the start guard, the end assertion
# and the python mutator (exported as CERT_MARK). The `subst` rows in MAP embed
# the same literal in their payloads by necessity (the payload IS the replacement
# text); the mutator REJECTS a subst whose replacement omits the marker, which is
# what keeps the two from drifting apart.
MUT_MARK='CERT-REMOVAL-PROOF-MUTATION'

MUTATED=()          # every path this run has begun rewriting (register-then-mutate)
GUARD_CHILD_PID=""  # backgrounded guard run, so a trap can reap it promptly

# Reap the backgrounded guard run (cargo / self-test stub) if one is live.
kill_guard_child() {
  [[ -n "$GUARD_CHILD_PID" ]] || return 0
  kill -TERM "$GUARD_CHILD_PID" 2>/dev/null || true
  GUARD_CHILD_PID=""
}

# Restore every registered mutation. IDEMPOTENT — a second call is a no-op, and
# a path registered but never actually rewritten restores to itself.
#
# `git checkout HEAD --` (not `git checkout --`) is deliberate: it resets BOTH
# the index and the worktree. The index half is what makes the #3118 shape
# unrepeatable — a `git add -A` that races the harness stages the disabled
# control, and an index-only restore would write the MUTATED content back into
# the worktree. Every registered path is proven byte-identical to HEAD before it
# is touched (the per-row guard in run_one), so resetting to HEAD can never
# destroy real work.
restore_mutations() {
  (( ${#MUTATED[@]} )) || return 0
  local paths=("${MUTATED[@]}")
  MUTATED=()
  if ! git checkout HEAD -- "${paths[@]}" 2>/dev/null; then
    git checkout -- "${paths[@]}" 2>/dev/null || true
  fi
}

# Files under src/ currently carrying the marker. Prints nothing when clean.
# Exit 0 = scan succeeded (list on stdout), 2 = COULD NOT SCAN (fail closed —
# an unscannable tree is never reported as clean).
marked_src_files() {
  local files rc=0
  # --untracked: an aborted run that never `git add`ed the rewrite is still
  # a live disabled control (#3119 Fable gate). rc>1 → could not scan.
  files="$(git grep -l --untracked -e "$MUT_MARK" -- src tests conformance examples sdk 2>/dev/null)" || rc=$?
  if (( rc > 1 )); then
    return 2
  fi
  [[ -n "$files" ]] && printf '%s\n' "$files"
  return 0
}

# Assert the marker is ABSENT from src/. Loud + non-zero when it is not: a
# surviving marker means a production security control is DISABLED right now.
assert_no_mutation_in_src() {
  local files
  if ! files="$(marked_src_files)"; then
    echo "SECURITY: could not scan src/ for the mutation marker — refusing to report clean" >&2
    return 1
  fi
  [[ -z "$files" ]] && return 0
  {
    echo ""
    echo "══════════════════════════════════════════════════════════════════════"
    echo "SECURITY: mutation still present in $(printf '%s' "$files" | tr '\n' ' ')"
    echo ""
    echo "A production security control is DISABLED in this working tree."
    echo "Do NOT commit. Do NOT 'git add -A'. Recover with:"
    echo "    scripts/check-cert-removal-proof.sh --force-restore"
    echo "══════════════════════════════════════════════════════════════════════"
  } >&2
  return 1
}

# EXIT — restore, assert, then propagate the run's REAL status. `rc=$?` is
# captured before anything else runs, so a normal PASS still exits 0 and a
# CERT-RED still exits 1; a failed restoration UPGRADES a 0 to 9 and never
# downgrades a failure.
on_exit() {
  local rc=$?
  trap - EXIT INT TERM HUP QUIT PIPE
  kill_guard_child
  restore_mutations
  if ! assert_no_mutation_in_src; then
    (( rc == 0 )) && rc=9
  fi
  exit "$rc"
}

# INT/TERM/HUP — restore, assert, then RE-RAISE. These deliberately do NOT
# `exit`: the handler is cleared and the signal is re-sent to this very shell
# (`kill -s "$sig" $$`) so the process dies of the ORIGINAL signal and every
# parent — `timeout`, a shell job, a CI runner, a `wait` in a driver script —
# observes WIFSIGNALED / 128+N exactly as it would have with no trap installed.
# `exit 130` would merely LOOK like a signal death; a driver that distinguishes
# "cancelled" from "failed" (or a `timeout --preserve-status`) would be lied to.
on_signal() {
  local sig="$1"
  trap - EXIT INT TERM HUP QUIT PIPE
  echo "" >&2
  echo "[$sig] interrupted — restoring ${#MUTATED[@]} mutated file(s) before dying…" >&2
  kill_guard_child
  restore_mutations
  assert_no_mutation_in_src || true
  kill -s "$sig" "$$"
  # Only reachable if the signal is somehow blocked/ignored. Fail closed.
  exit 3
}

trap on_exit EXIT
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM
trap 'on_signal HUP' HUP
trap 'on_signal QUIT' QUIT
trap 'on_signal PIPE' PIPE

# control-name | shape | mutation-payload | target-file | lane-test-crate | lane-test-fn
# shape ∈ {return, body} — see the header for the two grammars. The payload is the
# always-allow disposition (return-statement, or whole-body expression).
MAP=(
  "inbound_write_namespace_authorized|return|return true;|src/federation/receive_auth.rs|federation_write_ns_scope_2447|federated_write_outside_peer_scope_refused_2447"
  "inbound_by_id_namespace_authorized|return|return true;|src/federation/receive_auth.rs|federation_delete_ns_scope_2488|enrolled_unscoped_federated_deletion_refused_by_default_2488"
  "inbound_namespace_meta_authorized|return|return true;|src/federation/receive_auth.rs|federation_ns_meta_scope_2479|exploit_set_rebinds_out_of_scope_victim_standard_2479"
  # NOTE: peer_enrolled_in_allowlist is NOT a standalone row — its sole production
  # call site is src/federation/receive_auth.rs:1094 INSIDE inbound_write_namespace_authorized,
  # so it is COMPOSITE-PROVEN by that control's removal proof (mutating the whole
  # function to `return true` already bypasses this sub-check). The tofu unknown-peer
  # refusal (x_peer_id_not_in_allowlist) is a SEPARATE earlier envelope gate.
  "require_push_namespace_scope_enabled|return|return false;|src/federation/receive_auth.rs|federation_write_ns_scope_2447|enrolled_peer_without_declared_namespaces_denied_by_default_2447"
  "authorize_remote_checkpoint_resolution|return|return CheckpointResolutionAuthz::Accept;|src/federation/receive_auth.rs|federation_1936_checkpoint_fed|strict_refuses_unenrolled_resolver"
  # L4 (PR-3, forensic-audit-trail wave) — the fn that folds the per-row
  # audit-SIGNATURE coverage into is_clean. Neutralized to the always-clean
  # `Unenforced` verdict (body shape — a multi-branch verdict fn a single
  # first-statement return cannot bypass). GUARD FIXTURE is the SKIP-CLASS
  # DOWNGRADE (a lineage_signed row relabeled + signature-stripped, chain
  # otherwise perfect, WITH the pin enrolled) — proving the CLOSED GAP CLASS,
  # not merely that the code is reached. Neutralization => is_clean stays true
  # under the pin => the guard test's dirty assertion goes RED.
  "compute_signature_verdict|body|SignatureCheck::Unenforced { checked: 0, unverified: 0 }|src/signed_events.rs|audit_signature_pin_l4|downgraded_lineage_row_under_pin_dirties_l4"
  # #2948 (forensic-audit-trail wave, honest-path lane) — the fn that routes the
  # primary CREATE funnel's (`db::insert`) `ON CONFLICT DO UPDATE SET content =
  # excluded.content` in-place overwrite through the signed `memory_revisions`
  # ledger. Neutralized to the no-op `Ok(())` body (body shape — the whole
  # emission is the control) so an armed upsert-merge stops appending its
  # SUPERSEDE leaf => the lane test's `leaves.len() == 1` assertion goes RED,
  # proving the #2948 wiring (not the shared emitter) is load-bearing.
  "emit_upsert_supersede_leaf_if_enabled|body|Ok(())|src/storage/mod.rs|append_only_upsert_supersede_2948|armed_upsert_merge_emits_one_identity_only_supersede_leaf"
  # #2954 (GA Wave-2) — the sqlite fn that routes the FEDERATION newer-wins LWW
  # overwrite (`db::insert_if_newer`, `content = CASE WHEN excluded.updated_at >
  # memories.updated_at … THEN excluded.content …`) through the signed
  # `memory_revisions` ledger. This is a DISTINCT control from the #2948 create
  # funnel above (a conditional inbound-WIN overwrite, not the unconditional
  # `= excluded.content`). Neutralized to the no-op `Ok(())` body (body shape —
  # the whole emission is the control) so an armed inbound-WIN overwrite stops
  # appending its SUPERSEDE leaf => the lane test's `leaves.len() == 1` assertion
  # goes RED, proving the #2954 wiring (not the shared emitter, not merely the
  # static `APPEND-ONLY-SANCTIONED` marker) is load-bearing. The pg twin
  # (`apply_remote_memory`) is END-TO-END pinned against a live PG by
  # append_only_spine_flagon_g6::postgres_twins::pg_apply_remote_memory_newer_wins_writes_one_supersede_leaf.
  "emit_federation_newer_wins_supersede_leaf_if_enabled|body|Ok(())|src/storage/mod.rs|append_only_spine_flagon_g6|federation_newer_wins_emits_one_identity_only_supersede_leaf"
  # L7 (PR-4, forensic-audit-trail wave) — the EXONERATION-authenticity gate.
  # `return true` (the always-allow disposition) lets an UNAUTHENTICATED forensic
  # watermark exonerate, defeating the L7 asymmetry. GUARD FIXTURE is the
  # CLOSED GAP CLASS itself: a pin enrolled + an UNSIGNED watermark + a CLEAN
  # chain (which a watermark-trusting verifier WOULD render NotDetected on both
  # lanes). Honest guard => Unknown withheld on both lanes; mutated `return true`
  # => NotDetected => the guard test's `assert_eq!(…, Unknown)` goes RED.
  "audit_watermark_exoneration_authenticated|return|return true;|src/governance/audit.rs|audit_exoneration_asymmetry_l7|unauthenticated_watermark_under_pin_withholds_exoneration_l7"
  # D1 (2x7 re-audit) — consolidation-laundering closure (#2935/#2936). The
  # controls are two SINGLE BINDINGS in the sqlite `db::consolidate` builder,
  # not guard fns, so they use the `subst` shape (return/body cannot target one
  # field without breaking the function). Row 1 neutralizes the confidence
  # FLOOR (relaxes the running min back to a hardcoded 1.0 => the laundering
  # regression); row 2 neutralizes the derived-KIND stamp (Claim => Observation).
  # The lane test (`trust_propagation_1958_1959.rs`, SQLite in-memory — no live
  # PG needed) asserts BOTH invariants, so either mutation reds it. The pg twin
  # (`src/store/postgres.rs`) is END-TO-END pinned by
  # cov_postgres_governance.rs::consolidate_merges_sources against a live PG.
  "consolidate_confidence_floor_2935|subst|min_confidence = min_confidence.min(mem.confidence);>>>min_confidence = min_confidence.min(1.0); // CERT-REMOVAL-PROOF-MUTATION|src/storage/mod.rs|trust_propagation_1958_1959|consolidate_floors_confidence_and_stamps_claim_2935"
  "consolidate_derived_kind_2935|subst|memory_kind: crate::models::MemoryKind::Claim,>>>memory_kind: crate::models::MemoryKind::Observation, // CERT-REMOVAL-PROOF-MUTATION|src/storage/mod.rs|trust_propagation_1958_1959|consolidate_floors_confidence_and_stamps_claim_2935"
  # #2955 — forensic watermark PER-DATABASE scoping. The control is a `match`
  # arm in `scan_file_last_watermark` (not a guard fn), so it uses `subst`:
  # neutralizing the `(Some(row_db_id), Some(mine)) if row_db_id != mine =>
  # continue` arm's guard to `if false` stops the cross-DB skip, so a SIBLING
  # database's watermark (a different genesis `db_id`) is honored as THIS db's
  # high-water — the exact cross-DB watermark bleed #2955 closes. The lane test
  # asserts a foreign-`db_id` watermark is NOT returned to a scoped reader; the
  # mutation makes it returned => RED. Both backends read through this ONE shared
  # reader (`last_audit_watermark`), so the pg twin is composite-covered by the
  # same proof. (v1.0.0 #3006/#3068 rewrote this branch from an `if let` guard to
  # a `match` returning a `WatermarkScan`; the IDENTITY-LESS-reader arm
  # `(Some(_), None)` added there is a SEPARATE control proven by
  # `empty_migrated_store_not_convicted_on_sibling_watermark`.)
  "scan_file_last_watermark_db_id_scope_2955|subst|(Some(row_db_id), Some(mine)) if row_db_id != mine => continue,>>>(Some(row_db_id), Some(mine)) if false => continue, // CERT-REMOVAL-PROOF-MUTATION|src/governance/audit.rs|audit_watermark_db_id_scope_2955|foreign_db_watermark_not_honored_as_this_db_high_water"
  # #3065 (Wave-2 Cluster B) — the ADMIN_HEADER_TRUST identity boot-gate verdict.
  # `return` shape (a first-statement `return None;` — the always-permit
  # disposition): the body carries a `format!` refusal string whose `{...}`
  # captures would confuse the `body`-shape brace matcher, and a first-statement
  # early-return neutralizes every branch just the same. Neutralized => the
  # daemon stops refusing boot on the dangerous multi-fingerprint header-trust
  # topology => the lane test's `.is_some()` refusal assertion goes RED. Pure fn
  # (no I/O); the boot caller in daemon_runtime::run only gathers its live
  # inputs, so this ONE fn is the load-bearing decision on both backends.
  "admin_header_trust_boot_refusal|return|return None;|src/handlers/admin_role.rs|admin_header_trust_boot_gate_3065|dangerous_combo_refuses_boot"
  # #2991 (GA Wave-2) — the R40 post-quorum execution EXEMPTION discrimination.
  # The L1-6 escalate producer re-escalates an already-approved write on replay;
  # `consume_execution_exemption` lets it through ONLY when its CID-bound,
  # single-use exemption matches (never namespace-scoped, never "any store").
  # `return` shape (first-statement `return true;` — the always-exempt
  # disposition): neutralized, EVERY escalated write is admitted, so a write
  # whose CID was never registered (a DIFFERENT, unapproved store) is wrongly
  # exempted — reinstating the CWE-306 replay-bypass class the ballot flagged
  # (residual risk #1). The lane test asserts an UNREGISTERED CID is never
  # consumed (and the registered CID is single-use); the mutation makes the
  # unregistered consume return true => `assert!(!consume(...))` goes RED. Pure
  # process-global registry (no I/O, no backend) — both backends' approve
  # funnels + the producer consult this ONE fn, so it is composite-covered.
  "consume_execution_exemption|return|return true;|src/approvals.rs|r40_approval_chokepoint|exemption_discriminates_unregistered_cid"
)

# Apply MUTATION to function CTL in TARGET, per SHAPE.
#   return : inserts <payload> as the first statement of the body.
#   body   : replaces the entire `{ ... }` body with <payload>.
# Both stamp the `// CERT-REMOVAL-PROOF-MUTATION` marker so run_one can confirm
# the edit landed and grep for a clean revert. Exit 3 if CTL cannot be located.
apply_mutation() {
  local ctl="$1" shape="$2" payload="$3" target="$4"
  CERT_CTL="$ctl" CERT_SHAPE="$shape" CERT_PAYLOAD="$payload" CERT_TARGET="$target" \
  CERT_MARK="$MUT_MARK" \
  python3 - <<'PY'
import os, re, sys

path    = os.environ["CERT_TARGET"]
ctl     = os.environ["CERT_CTL"]
shape   = os.environ["CERT_SHAPE"]
payload = os.environ["CERT_PAYLOAD"]
MARK    = " // " + os.environ["CERT_MARK"]

lines = open(path).read().splitlines(keepends=True)

# subst — literal find/replace of ONE unique <OLD> with <NEW>. The function
# locator below is not used for this shape (the control is a mid-function
# binding, not a `pub fn`). A payload matching 0 or >1 sites is a hard error so
# a subst can never silently over-mutate.
if shape == 'subst':
    old, sep, new = payload.partition('>>>')
    if not sep:
        sys.stderr.write("subst payload missing '>>>' delimiter\n")
        sys.exit(3)
    # #3119: a subst whose NEW omits the marker would be INVISIBLE to the trap,
    # the start guard, the end assertion and the repo-wide gate — the exact
    # blind spot the #3118 near-miss lived in. Refuse it.
    if MARK.strip() not in new:
        sys.stderr.write("subst NEW must embed the mutation marker comment\n")
        sys.exit(3)
    text = ''.join(lines)
    n = text.count(old)
    if n != 1:
        sys.stderr.write("subst OLD matched %d sites (want exactly 1)\n" % n)
        sys.exit(3)
    open(path, 'w').write(text.replace(old, new, 1))
    sys.exit(0)

# Locate `[pub] fn <ctl>` signature line.
sig = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?fn %s\b' % re.escape(ctl))
start = next((i for i, ln in enumerate(lines) if sig.match(ln)), None)
if start is None:
    sys.exit(3)

# Walk to the body-open brace: the first line at/after the signature whose
# trimmed text ends in `{` (single- or multi-line signature).
open_i = start
while open_i < len(lines) and not lines[open_i].rstrip().endswith('{'):
    open_i += 1
if open_i >= len(lines):
    sys.exit(3)

indent      = re.match(r'\s*', lines[start]).group(0)
body_indent = indent + '    '

if shape == 'return':
    lines.insert(open_i + 1, '%s%s%s\n' % (body_indent, payload, MARK))
    open(path, 'w').write(''.join(lines))
    sys.exit(0)

if shape == 'body':
    # Depth-count from the body-open brace to its matching close, skipping
    # braces that live inside comments / string / char / raw-string literals so
    # a `'{'` char literal or a `"}"` string can never miscount the body bounds.
    text = ''.join(lines[open_i:])
    k    = text.index('{')            # the body-open brace within `text`
    i, n, depth, close = k, len(text), 0, None
    line_c = block_c = in_str = in_raw = False
    hashes = 0
    while i < n:
        c, two = text[i], text[i:i+2]
        if line_c:
            if c == '\n': line_c = False
            i += 1; continue
        if block_c:
            if two == '*/': block_c = False; i += 2; continue
            i += 1; continue
        if in_str:
            if c == '\\': i += 2; continue
            if c == '"': in_str = False
            i += 1; continue
        if in_raw:
            if c == '"' and text[i+1:i+1+hashes] == '#'*hashes:
                in_raw = False; i += 1 + hashes; continue
            i += 1; continue
        if two == '//': line_c = True; i += 2; continue
        if two == '/*': block_c = True; i += 2; continue
        m = re.match(r'r(#*)"', text[i:i+8])
        if m:
            hashes = len(m.group(1)); in_raw = True; i += m.end(); continue
        if c == '"': in_str = True; i += 1; continue
        if c == "'":
            ch = re.match(r"'(\\.|[^\\'])'", text[i:i+4])   # char literal vs lifetime tick
            i += ch.end() if ch else 1; continue
        if c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0: close = i; break
        i += 1
    if close is None:
        sys.exit(3)
    new_text = '%s\n%s%s%s\n%s%s' % (
        text[:k+1], body_indent, payload, MARK, indent, text[close:])
    open(path, 'w').write(''.join(lines[:open_i]) + new_text)
    sys.exit(0)

sys.stderr.write("unknown mutation shape: %s\n" % shape)
sys.exit(3)
PY
}

# --list — print each row's target file, shape, and guard test.
list_map() {
  printf '%-42s  %-6s  %-30s  %s\n' "control" "shape" "target" "lane_test::fn"
  local row ctl shape mut tf crate fn
  for row in "${MAP[@]}"; do
    IFS='|' read -r ctl shape mut tf crate fn <<<"$row"
    printf '%-42s  %-6s  %-30s  tests/%s.rs::%s\n' "$ctl" "$shape" "$tf" "$crate" "$fn"
  done
}

# --self-test — prove ALL THREE mutation grammars rewrite Rust source as intended,
# WITHOUT compiling anything. Mirrors the plant-a-violation discipline the repo's
# other gates carry; the cargo RED/GREEN acceptance run below exercises the shipped
# MAP (all 14 shipped rows across the three shapes — return/body/subst), so this is
# the mechanical, compile-free proof that each grammar — including the PR-0 `body`
# grammar and the 2x7 `subst` grammar — rewrites exactly what it claims to.
self_test() {
  if ! grep -qF "$MUT_MARK" "$SELF"; then
    echo "FAIL: harness no longer carries the mutation MARKER literal" >&2
    return 1
  fi
  local dir="$EVIDENCE_DIR/self-test"
  rm -rf "$dir"; mkdir -p "$dir"
  local fx="$dir/fixture.rs"
  cat >"$fx" <<'RS'
pub fn demo_guard(x: char) -> bool {
    // a char literal '{' must not fool the brace matcher
    if x == '{' && x != '}' {
        return false;
    }
    true
}
RS
  local rc=0

  # return shape — first statement injected, original arms still present.
  cp "$fx" "$dir/ret.rs"
  apply_mutation demo_guard return "return true;" "$dir/ret.rs"
  if grep -q "return true; // CERT-REMOVAL-PROOF-MUTATION" "$dir/ret.rs" \
     && grep -q "return false;" "$dir/ret.rs"; then
    echo "  [ok] return-shape: first-statement injected, body preserved"
  else
    echo "  [FAIL] return-shape did not rewrite as expected"; rc=1
  fi

  # body shape — whole body replaced, original arms gone, braces balanced.
  cp "$fx" "$dir/body.rs"
  apply_mutation demo_guard body "true" "$dir/body.rs"
  if grep -q "true // CERT-REMOVAL-PROOF-MUTATION" "$dir/body.rs" \
     && ! grep -q "return false;" "$dir/body.rs" \
     && [[ "$(tr -cd '{' <"$dir/body.rs" | wc -c)" == "$(tr -cd '}' <"$dir/body.rs" | wc -c)" ]]; then
    echo "  [ok] body-shape: whole body replaced, braces balanced"
  else
    echo "  [FAIL] body-shape did not rewrite as expected"; rc=1
  fi

  # subst shape — one unique OLD replaced with NEW (marker embedded).
  cp "$fx" "$dir/subst.rs"
  apply_mutation subst_label subst "return false;>>>return true; // CERT-REMOVAL-PROOF-MUTATION" "$dir/subst.rs"
  if grep -q "return true; // CERT-REMOVAL-PROOF-MUTATION" "$dir/subst.rs" \
     && ! grep -q "return false;" "$dir/subst.rs"; then
    echo "  [ok] subst-shape: unique OLD replaced, marker embedded"
  else
    echo "  [FAIL] subst-shape did not rewrite as expected"; rc=1
  fi

  # subst shape — a non-unique OLD (2 sites) MUST hard-error (never over-mutate).
  cp "$fx" "$dir/subst-dup.rs"
  printf 'pub fn a() { let x = 1; }\npub fn b() { let x = 1; }\n' >"$dir/subst-dup.rs"
  if apply_mutation subst_label subst "let x = 1;>>>let x = 2; // $MUT_MARK" "$dir/subst-dup.rs" 2>/dev/null; then
    echo "  [FAIL] subst-shape accepted a non-unique OLD (should exit 3)"; rc=1
  else
    echo "  [ok] subst-shape: non-unique OLD rejected (exit 3)"
  fi

  # ─── #3119 INTERRUPT SAFETY ────────────────────────────────────────────────
  # The three legs above prove the mutation GRAMMARS. These two prove the thing
  # the #3118 near-miss actually needed: that a run killed mid-mutation leaves
  # the working tree CLEAN. They drive the REAL harness against a REAL control
  # in the REAL src/ tree, with the guard-test step stubbed to a
  # sentinel-touch + long sleep (CERT_PROOF_STUB_RUN), so the harness is
  # GUARANTEED to be sitting on a live, disabled security control when the
  # signal lands — and no cargo/toolchain is involved.
  local probe_ctl="inbound_write_namespace_authorized"
  local probe_tf="src/federation/receive_auth.rs"
  local sentinel="$dir/mutation-was-live"

  # Shared assertions for one interrupted run.
  _assert_interrupt_clean() {
    local leg="$1" krc="$2"
    local ok=0
    if [[ ! -f "$sentinel" ]]; then
      echo "  [FAIL] $leg: the harness never reached the guard step — the mutation was"
      echo "         never live, so this leg proved nothing. Is $probe_tf dirty?"
      return 1
    fi
    local porcelain
    porcelain="$(git status --porcelain -- src)"
    if [[ -n "$porcelain" ]]; then
      echo "  [FAIL] $leg: src/ left DIRTY after the interrupt:"
      printf '%s\n' "$porcelain" | sed 's/^/           /'
      ok=1
    fi
    if git grep -q -e "$MUT_MARK" -- src 2>/dev/null; then
      echo "  [FAIL] $leg: SECURITY — mutation marker still present in src/ after the interrupt"
      ok=1
    fi
    if [[ $krc -eq 0 ]]; then
      echo "  [FAIL] $leg: interrupted run exited 0 (must never read as success)"
      ok=1
    fi
    return $ok
  }

  # (4) `timeout 2` — SIGTERM lands while the control is disabled.
  rm -f "$sentinel"
  local trc=0
  CERT_PROOF_STUB_RUN="$sentinel" timeout 2 bash "$SELF" "$probe_ctl" \
    >"$dir/timeout.out" 2>&1 || trc=$?
  if _assert_interrupt_clean "timeout-2" "$trc"; then
    echo "  [ok] timeout-2: SIGTERM mid-mutation → src/ clean, marker absent, rc=$trc"
  else
    rc=1
  fi

  # (5) RE-RAISE FIDELITY — SIGINT is re-raised, not simulated. `wait` reports
  # 128+SIGINT = 130 only if the harness genuinely DIED OF the signal; a trap
  # that ended in `exit 130` would be indistinguishable to `$?` but NOT to a
  # parent that inspects WIFSIGNALED, so this is the assertion that pins the
  # re-raise rather than a hardcoded status.
  #
  # `set -m` is REQUIRED here, not cosmetic: with job control OFF a bash script's
  # ASYNCHRONOUS children start with SIGINT *ignored*, and a signal ignored on
  # entry cannot be trapped — the harness would never see the INT at all and this
  # leg would hang rather than assert. Job control gives the child its own process
  # group and a default SIGINT disposition, which is what a real Ctrl-C delivers.
  rm -f "$sentinel"
  set -m
  CERT_PROOF_STUB_RUN="$sentinel" bash "$SELF" "$probe_ctl" >"$dir/sigint.out" 2>&1 &
  local hpid=$! waited=0
  set +m
  while [[ ! -f "$sentinel" && $waited -lt 200 ]]; do sleep 0.05; waited=$((waited + 1)); done
  kill -INT "$hpid" 2>/dev/null || true
  local irc=0
  wait "$hpid" || irc=$?
  if _assert_interrupt_clean "sigint-reraise" "$irc" && [[ $irc -eq 130 ]]; then
    echo "  [ok] sigint-reraise: died OF SIGINT (rc=130), src/ clean, marker absent"
  else
    [[ $irc -ne 130 ]] && echo "  [FAIL] sigint-reraise: rc=$irc, want 130 (128+SIGINT) — signal not re-raised"
    rc=1
  fi

  echo
  if [[ $rc -eq 0 ]]; then
    echo "self-test: PASS — three mutation shapes sound; interrupted runs leave a clean tree"
  else
    echo "self-test: FAIL"
  fi
  return $rc
}

# Run one control's guard test, capturing to <out>.
#
# The command runs in the BACKGROUND and is `wait`ed on, which is load-bearing
# for #3119: bash defers a trap until the current FOREGROUND command returns, so
# a foreground `cargo test` would postpone the restoring trap for the entire
# length of the test run — precisely the window the #3118 near-miss died in.
# `wait` IS interruptible, so the trap fires immediately and reaps the child.
#
# CERT_PROOF_STUB_RUN is a SELF-TEST-ONLY hook: it replaces the cargo invocation
# with "touch a sentinel, then sleep", so `--self-test` can drive the real
# harness under `timeout` with a LIVE mutation in the tree and no toolchain. It
# can never manufacture a PASS — the stub never returns 0, so both the broken
# and the restored leg are non-zero and run_one reports CERT-RED (fail closed).
run_guard_test() {
  local crate="$1" fn="$2" out="$3"
  if [[ -n "${CERT_PROOF_STUB_RUN:-}" ]]; then
    # `exec` so the backgrounded pid IS the sleep — kill_guard_child then reaps
    # it directly instead of orphaning it under a dying subshell.
    ( : >"$CERT_PROOF_STUB_RUN"; exec sleep 300 ) >"$out" 2>&1 &
  else
    AI_MEMORY_NO_CONFIG=1 cargo test --features sal --test "$crate" "$fn" \
      -- --exact --nocapture >"$out" 2>&1 &
  fi
  GUARD_CHILD_PID=$!
  local rc=0
  wait "$GUARD_CHILD_PID" || rc=$?
  GUARD_CHILD_PID=""
  # A stubbed run must NEVER read as a green guard test (fail closed).
  [[ -n "${CERT_PROOF_STUB_RUN:-}" && $rc -eq 0 ]] && rc=3
  return $rc
}

run_one() {
  local ctl="$1" shape="$2" mut="$3" tf="$4" crate="$5" fn="$6"
  echo "════ control: $ctl  (shape: $shape)  target: $tf  guard: tests/${crate}.rs::${fn}"

  # PER-ROW dirty guard — refuse ONLY when THIS row's target differs from HEAD,
  # so a revert cannot clobber real edits while an unrelated dirty file never
  # aborts the run. Compared against HEAD rather than the index (#3119): the
  # restore is `git checkout HEAD --`, which would destroy a STAGED edit, and an
  # index-only restore would resurrect a staged mutation into the worktree.
  if ! git diff --quiet HEAD -- "$tf"; then
    echo "  [REFUSE] $tf differs from HEAD (staged and/or unstaged); commit/stash first (revert safety)."
    return 2
  fi

  # 1. deliberately break the control.
  #    REGISTER BEFORE MUTATING — the trap must be able to restore a file that a
  #    crash left HALF-REWRITTEN between these two statements. Registering a path
  #    that ends up unmodified is free (restore_mutations is idempotent).
  MUTATED+=("$tf")
  apply_mutation "$ctl" "$shape" "$mut" "$tf" \
    || { echo "  [ERR] could not locate/mutate $ctl in $tf"; restore_mutations; return 3; }
  if ! grep -q "$MUT_MARK" "$tf"; then echo "  [ERR] mutation marker absent"; restore_mutations; return 3; fi

  # 2. run the guarding lane test — MUST fail (RED) with the control broken
  echo "  → running guard with BROKEN control (expect RED)…"
  local broken_rc=0
  run_guard_test "$crate" "$fn" "$EVIDENCE_DIR/removal-${ctl}-broken.out" || broken_rc=$?

  # 3. revert
  restore_mutations
  if grep -q "$MUT_MARK" "$tf"; then
    MUTATED+=("$tf")
    echo "  [ERR] revert FAILED — mutation still present!"
    echo "  dump: git diff HEAD -- $tf" >&2
    git diff HEAD -- "$tf" >&2 || true
    restore_mutations
    return 3
  fi
  if ! git diff --quiet HEAD -- "$tf"; then
    echo "  [ERR] post-restore $tf still differs from HEAD" >&2
    git diff HEAD -- "$tf" >&2 || true
    restore_mutations
    return 3
  fi

  # 4. run again — MUST pass (GREEN) with the control restored
  echo "  → running guard with RESTORED control (expect GREEN)…"
  local restored_rc=0
  run_guard_test "$crate" "$fn" "$EVIDENCE_DIR/removal-${ctl}-restored.out" || restored_rc=$?

  if [[ $broken_rc -ne 0 && $restored_rc -eq 0 ]]; then
    echo "  [PROVEN] control is load-bearing: broken→RED (rc=$broken_rc), restored→GREEN (rc=$restored_rc)"
    return 0
  else
    echo "  [CERT-RED] control NOT proven load-bearing: broken→rc=$broken_rc (want !=0), restored→rc=$restored_rc (want 0)"
    return 1
  fi
}

# --force-restore (#3119) — the deliberate recovery path from an aborted run.
# Backs the mutated files up FIRST (reversibility: the backup is the only
# durable record of what the aborted run left behind, and an operator may need
# to diff it), then resets them to HEAD and exits 0.
force_restore() {
  local files
  if ! files="$(marked_src_files)"; then
    echo "❌ --force-restore: could not scan src/ (git grep failed) — refusing to act blind." >&2
    exit 4
  fi
  if [[ -z "$files" ]]; then
    echo "--force-restore: nothing to restore — src/ carries no mutation marker."
    exit 0
  fi
  local stamp backup f
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup="$EVIDENCE_DIR/force-restore-$stamp"
  echo "⚠️  --force-restore: mutated file(s) found in src/:"
  MUTATED=()
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    echo "      $f"
    mkdir -p "$backup/$(dirname "$f")"
    cp "$f" "$backup/$f"
    MUTATED+=("$f")
  done <<<"$files"
  echo "    backup written to $backup"
  restore_mutations
  if ! assert_no_mutation_in_src; then
    echo "❌ --force-restore FAILED — the marker survives the reset." >&2
    exit 5
  fi
  echo "✅ --force-restore: src/ reset to HEAD; the marker is gone."
  exit 0
}

# START GUARD (#3119) — a marker already in src/ means an EARLIER run aborted
# and left a production security control DISABLED. Refuse loudly rather than
# stack a second mutation on top of it (and rather than silently "fixing" it,
# which would hide the incident). Deliberately applies to --list and
# --self-test too: nothing about this harness should proceed on a tree whose
# controls are off.
preflight_no_stale_mutation() {
  local files
  if ! files="$(marked_src_files)"; then
    echo "❌ could not scan src/ for a stale mutation marker — refusing to run." >&2
    exit 4
  fi
  [[ -z "$files" ]] && return 0
  {
    echo ""
    echo "══════════════════════════════════════════════════════════════════════"
    echo "REFUSING TO RUN — a PRIOR run of this harness aborted and left a"
    echo "DISABLED security control in the working tree:"
    echo ""
    printf '%s\n' "$files" | sed 's/^/      /'
    echo ""
    echo "This is the #3118 shape. Do NOT commit and do NOT 'git add -A'."
    echo "Recover with:"
    echo "    scripts/check-cert-removal-proof.sh --force-restore"
    echo "══════════════════════════════════════════════════════════════════════"
  } >&2
  exit 4
}

case "${1:-}" in
  --force-restore) force_restore ;;
esac

preflight_no_stale_mutation

case "${1:-}" in
  --list)      list_map;   exit 0 ;;
  --self-test) self_test;  exit $? ;;
esac

sel="${1:-ALL}"
overall=0
for row in "${MAP[@]}"; do
  IFS='|' read -r ctl shape mut tf crate fn <<<"$row"
  [[ "$sel" != "ALL" && "$sel" != "$ctl" ]] && continue
  local_rc=0
  run_one "$ctl" "$shape" "$mut" "$tf" "$crate" "$fn" || local_rc=$?
  if [[ $local_rc -eq 3 ]]; then
    echo "❌ revert failed on $ctl — refusing to continue the MAP (tree may still be mutated)" >&2
    restore_mutations
    assert_no_mutation_in_src || true
    exit 3
  fi
  [[ $local_rc -ne 0 ]] && overall=1
done

echo
if [[ $overall -eq 0 ]]; then echo "overall: PASS — every checked control proven load-bearing (§5.4.5)"; else echo "overall: CERT-RED — a control failed the removal proof (§5.4.5)"; fi
exit $overall
