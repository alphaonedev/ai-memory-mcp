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
# SAFETY: mutations are applied in-place then reverted via `git checkout --`.
# The script refuses to run on a dirty working tree for the target file so a
# revert can never clobber real edits. Evidence is written under .local-runs/.
#
# USAGE:
#   scripts/check-cert-removal-proof.sh                 # all controls
#   scripts/check-cert-removal-proof.sh <control-name>  # one control
#   scripts/check-cert-removal-proof.sh --list          # print the control map
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
TARGET_FILE="src/federation/receive_auth.rs"
EVIDENCE_DIR=".local-runs/cert-54-evidence"
mkdir -p "$EVIDENCE_DIR"

# control-name | mutation-return-statement | lane-test-crate | lane-test-fn
# The mutation is inserted as the FIRST statement of the named function body,
# forcing the always-allow disposition (the "deliberately broken control").
MAP=(
  "inbound_write_namespace_authorized|return true;|federation_write_ns_scope_2447|federated_write_outside_peer_scope_refused_2447"
  "inbound_by_id_namespace_authorized|return true;|federation_delete_ns_scope_2488|enrolled_unscoped_federated_deletion_refused_by_default_2488"
  "inbound_namespace_meta_authorized|return true;|federation_ns_meta_scope_2479|exploit_set_rebinds_out_of_scope_victim_standard_2479"
  # NOTE: peer_enrolled_in_allowlist is NOT a standalone MAP row. Its sole
  # production call site is src/federation/receive_auth.rs:1094 INSIDE helper
  # layer2_unscoped_peer_authorized (declared :1081), which is called from BOTH
  # inbound_write_namespace_authorized (:1049) AND inbound_by_id_namespace_authorized
  # (:1219) — not "inside inbound_write_namespace_authorized" alone. Mutating
  # peer_enrolled_in_allowlist itself is behaviorally MASKED on the previously
  # mapped lane (recorded broken→rc=0; defense-in-depth via row 1 plus the
  # earlier x_peer_id_not_in_allowlist envelope gate). It is therefore
  # asserted, not individually removal-proven. Decisive standalone test:
  # issue #2912. Do NOT add it as a MAP row until that test exists.
  "require_push_namespace_scope_enabled|return false;|federation_write_ns_scope_2447|enrolled_peer_without_declared_namespaces_denied_by_default_2447"
  "authorize_remote_checkpoint_resolution|return CheckpointResolutionAuthz::Accept;|federation_1936_checkpoint_fed|strict_refuses_unenrolled_resolver"
)

if [[ "${1:-}" == "--list" ]]; then
  printf '%-42s -> %s::%s\n' "control" "lane_test" "fn"
  for row in "${MAP[@]}"; do IFS='|' read -r ctl _ tf fn <<<"$row"; printf '%-42s -> tests/%s.rs::%s\n' "$ctl" "$tf" "$fn"; done
  exit 0
fi

# Insert MUTATION as the first statement of function CTL's body in TARGET_FILE.
# Finds `pub fn CTL` then the first subsequent line whose trimmed text ends in
# `{` (the signature-close/body-open, single- or multi-line signature), and
# inserts the mutation immediately after it.
apply_mutation() {
  local ctl="$1" mut="$2"
  python3 - "$TARGET_FILE" "$ctl" "$mut" <<'PY'
import sys, re
path, ctl, mut = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(path).read().splitlines(keepends=True)
out, i, done = [], 0, False
sig = re.compile(r'^\s*pub fn %s\b' % re.escape(ctl))
while i < len(lines):
    out.append(lines[i])
    if not done and sig.match(lines[i]):
        j = i
        # walk to the body-open brace (line ending in '{')
        while j < len(lines) and not lines[j].rstrip().endswith('{'):
            j += 1
            out.append(lines[j])
        indent = re.match(r'\s*', lines[i]).group(0) + '    '
        out.append('%s%s // CERT-REMOVAL-PROOF-MUTATION\n' % (indent, mut))
        done = True
        i = j
    i += 1
open(path, 'w').write(''.join(out))
sys.exit(0 if done else 3)
PY
}

run_one() {
  local ctl="$1" mut="$2" tf="$3" fn="$4"
  echo "════ control: $ctl  (mutation: ${mut})  guard: tests/${tf}.rs::${fn}"

  # 1. deliberately break the control
  apply_mutation "$ctl" "$mut" || { echo "  [ERR] could not locate/ mutate $ctl"; return 3; }
  if ! grep -q "CERT-REMOVAL-PROOF-MUTATION" "$TARGET_FILE"; then echo "  [ERR] mutation marker absent"; git checkout -- "$TARGET_FILE"; return 3; fi

  # 2. run the guarding lane test — MUST fail (RED) with the control broken
  echo "  → running guard with BROKEN control (expect RED)…"
  AI_MEMORY_NO_CONFIG=1 cargo test --features sal --test "$tf" "$fn" -- --exact --nocapture \
    > "$EVIDENCE_DIR/removal-${ctl}-broken.out" 2>&1
  local broken_rc=$?

  # 3. revert
  git checkout -- "$TARGET_FILE"
  grep -q "CERT-REMOVAL-PROOF-MUTATION" "$TARGET_FILE" && { echo "  [ERR] revert FAILED — mutation still present!"; return 3; }

  # 4. run again — MUST pass (GREEN) with the control restored
  echo "  → running guard with RESTORED control (expect GREEN)…"
  AI_MEMORY_NO_CONFIG=1 cargo test --features sal --test "$tf" "$fn" -- --exact --nocapture \
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

# refuse on a dirty target so revert cannot clobber real edits
if ! git diff --quiet -- "$TARGET_FILE"; then
  echo "REFUSING: $TARGET_FILE has uncommitted changes; commit/stash first (revert safety)." >&2
  exit 2
fi

sel="${1:-ALL}"
overall=0
for row in "${MAP[@]}"; do
  IFS='|' read -r ctl mut tf fn <<<"$row"
  [[ "$sel" != "ALL" && "$sel" != "$ctl" ]] && continue
  run_one "$ctl" "$mut" "$tf" "$fn" || overall=1
done

echo
if [[ $overall -eq 0 ]]; then echo "overall: PASS — every checked control proven load-bearing (§5.4.5)"; else echo "overall: CERT-RED — a control failed the removal proof (§5.4.5)"; fi
exit $overall
