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
# SAFETY: mutations are applied in-place then reverted via `git checkout --`.
# The dirty-working-tree guard is PER ROW — each row refuses only when ITS OWN
# target file has uncommitted changes, so an unrelated dirty file never aborts
# the run and a revert can never clobber real edits to the file under test.
# Evidence is written under .local-runs/.
#
# USAGE:
#   scripts/check-cert-removal-proof.sh                 # all controls
#   scripts/check-cert-removal-proof.sh <control-name>  # one control
#   scripts/check-cert-removal-proof.sh --list          # print the control map
#   scripts/check-cert-removal-proof.sh --self-test     # prove BOTH mutation
#                                                        # shapes rewrite source
#                                                        # as intended (no cargo)
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
EVIDENCE_DIR=".local-runs/cert-54-evidence"
mkdir -p "$EVIDENCE_DIR"

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
)

# Apply MUTATION to function CTL in TARGET, per SHAPE.
#   return : inserts <payload> as the first statement of the body.
#   body   : replaces the entire `{ ... }` body with <payload>.
# Both stamp the `// CERT-REMOVAL-PROOF-MUTATION` marker so run_one can confirm
# the edit landed and grep for a clean revert. Exit 3 if CTL cannot be located.
apply_mutation() {
  local ctl="$1" shape="$2" payload="$3" target="$4"
  CERT_CTL="$ctl" CERT_SHAPE="$shape" CERT_PAYLOAD="$payload" CERT_TARGET="$target" \
  python3 - <<'PY'
import os, re, sys

path    = os.environ["CERT_TARGET"]
ctl     = os.environ["CERT_CTL"]
shape   = os.environ["CERT_SHAPE"]
payload = os.environ["CERT_PAYLOAD"]
MARK    = " // CERT-REMOVAL-PROOF-MUTATION"

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

# --self-test — prove BOTH mutation grammars rewrite Rust source as intended,
# WITHOUT compiling anything. Mirrors the plant-a-violation discipline the repo's
# other gates carry; the cargo RED/GREEN acceptance run below only exercises the
# `return` shape (all 5 shipped rows), so this is the mechanical proof that the
# PR-0 `body` grammar is load-bearing.
self_test() {
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
  if apply_mutation subst_label subst "let x = 1;>>>let x = 2;" "$dir/subst-dup.rs" 2>/dev/null; then
    echo "  [FAIL] subst-shape accepted a non-unique OLD (should exit 3)"; rc=1
  else
    echo "  [ok] subst-shape: non-unique OLD rejected (exit 3)"
  fi

  echo
  if [[ $rc -eq 0 ]]; then echo "self-test: PASS — all three mutation shapes sound"; else echo "self-test: FAIL"; fi
  return $rc
}

run_one() {
  local ctl="$1" shape="$2" mut="$3" tf="$4" crate="$5" fn="$6"
  echo "════ control: $ctl  (shape: $shape)  target: $tf  guard: tests/${crate}.rs::${fn}"

  # PER-ROW dirty guard — refuse ONLY when THIS row's target is dirty so a revert
  # cannot clobber real edits, while an unrelated dirty file never aborts the run.
  if ! git diff --quiet -- "$tf"; then
    echo "  [REFUSE] $tf has uncommitted changes; commit/stash first (revert safety)."
    return 2
  fi

  # 1. deliberately break the control
  apply_mutation "$ctl" "$shape" "$mut" "$tf" \
    || { echo "  [ERR] could not locate/mutate $ctl in $tf"; git checkout -- "$tf" 2>/dev/null; return 3; }
  if ! grep -q "CERT-REMOVAL-PROOF-MUTATION" "$tf"; then echo "  [ERR] mutation marker absent"; git checkout -- "$tf"; return 3; fi

  # 2. run the guarding lane test — MUST fail (RED) with the control broken
  echo "  → running guard with BROKEN control (expect RED)…"
  AI_MEMORY_NO_CONFIG=1 cargo test --features sal --test "$crate" "$fn" -- --exact --nocapture \
    > "$EVIDENCE_DIR/removal-${ctl}-broken.out" 2>&1
  local broken_rc=$?

  # 3. revert
  git checkout -- "$tf"
  grep -q "CERT-REMOVAL-PROOF-MUTATION" "$tf" && { echo "  [ERR] revert FAILED — mutation still present!"; return 3; }

  # 4. run again — MUST pass (GREEN) with the control restored
  echo "  → running guard with RESTORED control (expect GREEN)…"
  AI_MEMORY_NO_CONFIG=1 cargo test --features sal --test "$crate" "$fn" -- --exact --nocapture \
    > "$EVIDENCE_DIR/removal-${ctl}-restored.out" 2>&1
  local restored_rc=$?

  if [[ $broken_rc -ne 0 && $restored_rc -eq 0 ]]; then
    echo "  [PROVEN] control is load-bearing: broken→RED (rc=$broken_rc), restored→GREEN (rc=$restored_rc)"
    return 0
  else
    echo "  [CERT-RED] control NOT proven load-bearing: broken→rc=$broken_rc (want !=0), restored→rc=$restored_rc (want 0)"
    return 1
  fi
}

case "${1:-}" in
  --list)      list_map;   exit 0 ;;
  --self-test) self_test;  exit $? ;;
esac

sel="${1:-ALL}"
overall=0
for row in "${MAP[@]}"; do
  IFS='|' read -r ctl shape mut tf crate fn <<<"$row"
  [[ "$sel" != "ALL" && "$sel" != "$ctl" ]] && continue
  run_one "$ctl" "$shape" "$mut" "$tf" "$crate" "$fn" || overall=1
done

echo
if [[ $overall -eq 0 ]]; then echo "overall: PASS — every checked control proven load-bearing (§5.4.5)"; else echo "overall: CERT-RED — a control failed the removal proof (§5.4.5)"; fi
exit $overall
