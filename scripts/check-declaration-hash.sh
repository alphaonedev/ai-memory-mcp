#!/usr/bin/env bash
# check-declaration-hash.sh — #3557 (N22): the §0.2 SLO/RPO/RTO declaration is
# PRE-REGISTERED and never revised after a miss.
#
# The Mission-Critical Certification Standard (docs/compliance/
# MISSION-CRITICAL-CERTIFICATION-STANDARD-v1.md §0.2) requires the declaration to be
# written BEFORE testing, hashed, and never softened afterwards: a run whose
# `envelope_ref` differs from the pinned hash is FAIL, and a target may not move after
# a miss. Prose cannot enforce that; this gate does, statically, on every PR:
#
#   D1  the declaration's SHA-256 equals the pin in scripts/qc-allowlists/declaration.sha256
#       AND the file's `revision:` equals the pinned revision — so the file cannot change
#       without the pin moving in the same commit;
#   D1b the pin may move only with a revision bump: when the pin differs from its
#       PREVIOUS committed content (the PR base — `DECLARATION_GATE_BASE`, a git ref/sha,
#       default HEAD; or the file named by `DECLARATION_GATE_PREVIOUS_PIN` in the
#       self-test), the new pinned revision must be strictly greater than the old one —
#       so "edit, re-hash, same revision" is refused as loudly as "edit, no re-hash";
#   D2  a pinned revision N > 1 requires at least N-1 dated
#       `revised after miss (YYYY-MM-DD): <reason>` lines in the file — so a re-pin
#       without the bump AND the reason is refused (HARD-FAIL, never allowlistable);
#   D3  the declaration contains no placeholder (`TBD`, `TODO`, `XXX`, `<fill`) — a
#       declared target is a number, not a promise to pick one;
#   D4  every N-id cited in §6 of the adopted standard has a row in the declaration's
#       §6 N-id → issue table (§7.4 of the standard: the ids match the filed issues).
#
# Two-disposition rule: D1–D4 are FAIL. There is no pending ledger for this gate: a
# declaration that does not hash is not a declaration.
#
# --self-test plants each defect in a throwaway copy under .local-runs/ (never system
# /tmp) and asserts the gate rejects it, with a clean control that must PASS and the
# legal-revision control (bump + dated reason + re-pin) that must PASS.
set -euo pipefail

# --- #3801 portable in-place edit (BSD + GNU) --------------------------------
# GNU and BSD/macOS `sed -i` disagree: BSD reads the next token as a mandatory
# backup suffix, so the GNU `sed -i EXPR FILE` form errors (or eats the script)
# on macOS. Writing to a sibling temp then mv is byte-identical on both. Same
# args as `sed -i`: sed_i EXPR FILE. No change to what the gate checks.
sed_i() {
    local __expr=$1 __file=$2 __tmp
    __tmp="${__file}.sedi.$$"
    sed "$__expr" "$__file" >"$__tmp" && mv "$__tmp" "$__file"
}

ROOT="${DECLARATION_GATE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DECL="${ROOT}/docs/compliance/v1.0.0-DECLARATION.md"
PIN="${ROOT}/scripts/qc-allowlists/declaration.sha256"
STD="${ROOT}/docs/compliance/MISSION-CRITICAL-CERTIFICATION-STANDARD-v1.md"

fail() { echo "::error::declaration-hash gate: $*" >&2; exit 1; }

sha_of() { sha256sum "$1" | cut -d' ' -f1; }

run_gate() {
  [ -f "$DECL" ] || fail "missing $DECL (D1)"
  [ -f "$PIN" ]  || fail "missing $PIN (D1)"
  [ -f "$STD" ]  || fail "missing $STD (D4)"
  local pin_line pinned_sha pinned_rev actual_sha file_rev
  pin_line=$(grep -vE '^\s*(#|$)' "$PIN" | tail -1 || true)
  [ -n "$pin_line" ] || fail "pin file carries no <sha256>  <revision> line (D1)"
  pinned_sha=$(echo "$pin_line" | awk '{print $1}')
  pinned_rev=$(echo "$pin_line" | awk '{print $2}')
  [[ "$pinned_sha" =~ ^[0-9a-f]{64}$ ]] || fail "pin is not a sha256 (D1): $pinned_sha"
  [[ "$pinned_rev" =~ ^[0-9]+$ ]] || fail "pin revision is not an integer (D1): $pinned_rev"
  actual_sha=$(sha_of "$DECL")
  file_rev=$(grep -E '^revision:\s*[0-9]+\s*$' "$DECL" | head -1 | awk '{print $2}' || true)
  [ -n "$file_rev" ] || fail "declaration carries no 'revision: N' line (D1)"
  if [ "$actual_sha" != "$pinned_sha" ]; then
    fail "declaration changed without re-pinning (D1): file sha $actual_sha != pinned $pinned_sha. A change is legal ONLY with a 'revision:' bump, a dated 'revised after miss (YYYY-MM-DD): <reason>' line in §5, and the new sha + revision in $PIN — a target is never revised after a miss (§0.2)."
  fi
  [ "$file_rev" = "$pinned_rev" ] || fail "declaration revision $file_rev != pinned revision $pinned_rev (D1)"
  # D1b — the pin moved: the revision must have moved up with it.
  local prev_line="" prev_sha="" prev_rev=""
  if [ -n "${DECLARATION_GATE_PREVIOUS_PIN:-}" ]; then
    [ -f "$DECLARATION_GATE_PREVIOUS_PIN" ] && prev_line=$(grep -vE '^\s*(#|$)' "$DECLARATION_GATE_PREVIOUS_PIN" | tail -1 || true)
  elif git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    local base="${DECLARATION_GATE_BASE:-HEAD}"
    prev_line=$(git -C "$ROOT" show "${base}:scripts/qc-allowlists/declaration.sha256" 2>/dev/null | grep -vE '^\s*(#|$)' | tail -1 || true)
  fi
  if [ -n "$prev_line" ]; then
    prev_sha=$(echo "$prev_line" | awk '{print $1}'); prev_rev=$(echo "$prev_line" | awk '{print $2}')
    if [ "$prev_sha" != "$pinned_sha" ] && [ "${pinned_rev}" -le "${prev_rev:-0}" ]; then
      fail "the pin moved ($prev_sha -> $pinned_sha) but the revision did not (${prev_rev} -> ${pinned_rev}) (D1b): a re-pin is legal only with a 'revision:' bump and a dated 'revised after miss' line"
    fi
  fi
  if [ "$pinned_rev" -gt 1 ]; then
    local reasons
    reasons=$(grep -cE 'revised after miss \(20[0-9]{2}-[0-9]{2}-[0-9]{2}\): \S' "$DECL" || true)
    [ "$reasons" -ge $((pinned_rev - 1)) ] || fail "revision $pinned_rev requires at least $((pinned_rev - 1)) dated 'revised after miss (YYYY-MM-DD): <reason>' line(s); found $reasons (D2)"
  fi
  if grep -nE '\bTBD\b|\bTODO\b|\bXXX\b|<fill' "$DECL" >/dev/null; then
    fail "declaration carries a placeholder (D3): $(grep -nE '\bTBD\b|\bTODO\b|\bXXX\b|<fill' "$DECL" | head -3 | tr '\n' ' ')"
  fi
  # D4 — N-ids cited in the standard's §6 table rows must have a row in the declaration's §6 table.
  local missing=0 nid
  while read -r nid; do
    [ -z "$nid" ] && continue
    if ! grep -qE "^\| ${nid} \| #[0-9]+ \|" "$DECL"; then
      echo "::error::declaration-hash gate: standard §6 cites ${nid} but the declaration's §6 table has no '| ${nid} | #<issue> |' row (D4)" >&2
      missing=1
    fi
  done < <(awk '/^## 6\. Execution list/{f=1} /^## 7\./{f=0} f' "$STD" | grep -oE '\bN[0-9]+\b' | sort -u)
  [ "$missing" = 0 ] || exit 1
  echo "declaration-hash gate: PASS (sha ${actual_sha:0:12}, revision ${file_rev}, no placeholders, §6 ids indexed)"
}

self_test() {
  local scratch="${ROOT}/.local-runs/declaration-gate-selftest"
  rm -rf "$scratch"; mkdir -p "$scratch/docs/compliance" "$scratch/scripts/qc-allowlists"
  cp "$DECL" "$scratch/docs/compliance/"; cp "$PIN" "$scratch/scripts/qc-allowlists/"; cp "$STD" "$scratch/docs/compliance/"
  local me="${BASH_SOURCE[0]}" ok=0 total=0
  # Every leg sees the PRISTINE pin as "previous", so D1b is exercised deliberately
  # and never by accident of the repo's committed pin.
  cp "$PIN" "$scratch/previous.pin"
  export DECLARATION_GATE_PREVIOUS_PIN="$scratch/previous.pin"
  leg() { # $1 name, $2 expect (pass|fail), $3 rule tag the refusal must name (optional)
    total=$((total+1)); local out r
    if out=$(DECLARATION_GATE_ROOT="$scratch" bash "$me" 2>&1); then r=pass; else r=fail; fi
    if [ "$r" != "$2" ]; then echo "  FAIL $1: expected $2, got $r"; return; fi
    if [ -n "${3:-}" ] && ! grep -q "($3)" <<<"$out"; then echo "  FAIL $1: refused, but not by $3: $(echo "$out" | head -1 | cut -c1-120)"; return; fi
    echo "  ok   $1 (expected $2${3:+ by $3})"; ok=$((ok+1))
  }
  local D="$scratch/docs/compliance/v1.0.0-DECLARATION.md" P="$scratch/scripts/qc-allowlists/declaration.sha256"
  repin() { local rev="$1"; printf '%s  %s\n' "$(sha_of "$D")" "$rev" > "$P"; }
  legal_bump() { # bump to revision 2 with a dated reason line, re-pin
    sed_i 's/^revision: 1$/revision: 2/' "$D"
    printf '| 2 | 2026-09-19 | revised after miss (2026-09-19): self-test leg — the hot keyword p95 was missed at 10k on the qualification host |\n' >> "$D"
    repin 2
  }
  leg "clean control" pass
  # D1: an edited target without a re-pin
  sed_i 's/^| `memory_recall` hot, keyword (depth 1) | SQLite | 40 | 80 | 150 |/| `memory_recall` hot, keyword (depth 1) | SQLite | 40 | 800 | 1500 |/' "$D"
  leg "D1 target softened, pin untouched" fail D1
  # D1b: re-pinned (sha moved) but revision not bumped
  repin 1
  leg "D1b re-pinned without a revision bump (pin sha moved, revision still 1)" fail D1b
  # D2: revision bumped + re-pinned but no dated reason line
  sed_i 's/^revision: 1$/revision: 2/' "$D"; repin 2
  leg "D2 revision bumped, re-pinned, no dated reason line" fail D2
  # legal revision: reason line present
  printf '| 2 | 2026-09-19 | revised after miss (2026-09-19): self-test leg — the hot keyword p95 was missed at 10k on the qualification host |\n' >> "$D"; repin 2
  leg "legal revision: bump + dated reason + re-pin" pass
  # D3: placeholder (on top of a legal revision so only D3 can refuse)
  printf '| 3 | 2026-09-20 | TBD |\n' >> "$D"; repin 2
  leg "D3 placeholder TBD" fail D3
  cp "$DECL" "$D"; cp "$PIN" "$P"
  # D4: drop an N-id row the standard cites (on top of a legal revision so only D4 can refuse)
  legal_bump; sed_i '/^| N16 | #3559 |/d' "$D"; repin 2
  leg "D4 standard cites N16 but the declaration index lost its row" fail D4
  cp "$DECL" "$D"; cp "$PIN" "$P"
  leg "clean control (restored)" pass
  unset DECLARATION_GATE_PREVIOUS_PIN
  rm -rf "$scratch"
  echo "declaration-hash gate self-test: $ok/$total"
  [ "$ok" = "$total" ] || exit 1
}

case "${1:-}" in
  --self-test) self_test ;;
  "") run_gate ;;
  *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
