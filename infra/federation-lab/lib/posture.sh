# shellcheck shell=bash
# =============================================================================
# infra/federation-lab/lib/posture.sh — the lab's asi-hard security posture.
# =============================================================================
# SSOT for the hardened posture is `src/security_profile.rs::KNOBS` (rendered
# for operators as `docs/deploy/asi-hard.env`). That table has SEVENTEEN pinned
# knobs and a NO-DISABLE contract: under `AI_MEMORY_SECURITY_PROFILE=asi-hard`
# each knob is pinned to its hard floor, and setting any of them BELOW that
# floor REFUSES boot.
#
# THE LAB RUNS 16 OF THE 17 — and does NOT set
# `AI_MEMORY_SECURITY_PROFILE=asi-hard`. Why, stated plainly:
#
#   The 17th knob, AI_MEMORY_REQUIRE_ROLLBACK_CHECK, cannot COLD-BOOT a fresh
#   node. In require-mode the open-time rollback-evidence check treats an
#   ABSENT off-table head anchor as refuse-to-open, and that anchor is emitted
#   only by the witness watermark cadence over the `signed_events` chain —
#   which is empty on a brand-new database. Fresh DB => no anchor => exit 75.
#   Tracked as issue #2942 (OPEN as of 2026-08-15).
#
#   Because the profile knob's contract is pin-and-refuse, we cannot say
#   "asi-hard, but with rollback-check off": setting the profile AND lowering
#   one pin is exactly the case the profile refuses. So the lab sets the 16
#   satisfiable knobs to their hard-floor values DIRECTLY and leaves
#   REQUIRE_ROLLBACK_CHECK at its safe default (emit-evidence-and-continue).
#   This is the same 16/17 shape a persistent hive node runs today.
#
#   The caveat probe (on by default; disable with `run.sh --no-caveat-probe`)
#   DEMONSTRATES the caveat rather than asserting it: it cold-boots one
#   throwaway node under the full 17-knob profile and records the actual exit
#   code and stderr.
#
# Two of the seventeen are PERMISSIVE hatches whose hard floor is "unset"
# (AI_MEMORY_ALLOW_SCHEMA_AHEAD #2445, AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS
# #2477). The lab actively UNSETS them rather than leaving whatever the
# operator's shell happened to export — an inherited hatch is exactly the
# silent weakening the posture exists to prevent.
# =============================================================================

# The 14 knobs the lab SETS to their hard-floor value.
# Format: NAME=VALUE. Order mirrors src/security_profile.rs::KNOBS.
LAB_POSTURE_SET=(
  "AI_MEMORY_SECRET_SCREEN_MODE=refuse"
  "AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1"
  "AI_MEMORY_FED_REQUIRE_WRITE_SIG=1"
  "AI_MEMORY_FED_REQUIRE_SIGNAL_SIG=1"
  "AI_MEMORY_FED_REQUIRE_TRANSITION_SIG=1"
  "AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG=1"
  "AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED=1"
  "AI_MEMORY_CID_ENFORCE=1"
  "AI_MEMORY_REQUIRE_WITNESS=1"
  "AI_MEMORY_REQUIRE_CAUSE_BINDING=1"
  "AI_MEMORY_REQUIRE_ROLE_SEPARATION=1"
  "AI_MEMORY_REQUIRE_IDENTITY_LINEAGE=1"
  "AI_MEMORY_FED_REQUIRE_SERVER_VERIFY=1"
  "AI_MEMORY_DB_SYNCHRONOUS=FULL"
)

# The 2 PERMISSIVE hatches whose hard floor is "not in force" — unset them.
LAB_POSTURE_UNSET=(
  "AI_MEMORY_ALLOW_SCHEMA_AHEAD"
  "AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS"
)

# The 1 knob deliberately NOT at its hard floor (issue #2942).
LAB_POSTURE_OMITTED="AI_MEMORY_REQUIRE_ROLLBACK_CHECK"
LAB_POSTURE_OMITTED_ISSUE="2942"

# lab_posture_count — 14 set + 2 unset = 16 of the 17 pinned knobs.
lab_posture_count() { echo $(( ${#LAB_POSTURE_SET[@]} + ${#LAB_POSTURE_UNSET[@]} )); }

# lab_posture_export — apply the 16/17 posture to the CURRENT shell.
# Callers run each daemon in a subshell so the posture never leaks between
# steps (the seeding phase deliberately runs WITHOUT it — see run.sh).
lab_posture_export() {
  local kv
  for kv in "${LAB_POSTURE_SET[@]}"; do
    export "${kv?}"
  done
  for kv in "${LAB_POSTURE_UNSET[@]}"; do
    unset "$kv"
  done
  unset "$LAB_POSTURE_OMITTED"
}

# lab_posture_render — one `NAME=VALUE` per line, for the run manifest and
# for the reader who wants to diff the lab against docs/deploy/asi-hard.env.
lab_posture_render() {
  printf '%s\n' "${LAB_POSTURE_SET[@]}"
  local k
  for k in "${LAB_POSTURE_UNSET[@]}"; do printf '%s=<unset — permissive hatch NOT in force>\n' "$k"; done
  printf '%s=<left at default — see issue #%s>\n' "$LAB_POSTURE_OMITTED" "$LAB_POSTURE_OMITTED_ISSUE"
}

# lab_posture_ssot_check <repo-root> — DRIFT GUARD.
#
# Re-derives the pinned-knob set from the Rust SSOT and asserts the lab's
# list is exactly it, minus the one documented omission. Runs only when the
# source tree is present (the kit also works from a release tarball). Echoes
# a one-line verdict; returns 0 on agreement, 1 on drift, 2 on "cannot check".
#
# Only the literal `env: "AI_MEMORY_…"` rows are machine-comparable; three
# KNOBS rows name a Rust const instead of a literal, so their env NAMES are
# resolved from the const definitions. If a future row uses a shape this
# cannot resolve, the check reports "cannot check" rather than passing —
# a drift guard that silently degrades to green is worse than none.
lab_posture_ssot_check() {
  local root="$1" src="$1/src/security_profile.rs"
  [ -f "$src" ] || { echo "skip: no source tree at $root (release-tarball mode)"; return 2; }

  local knobs_block ssot=() resolved
  knobs_block="$(awk '/^const KNOBS: &\[KnobSpec\] = &\[/,/^\];/' "$src")"
  [ -n "$knobs_block" ] || { echo "cannot check: KNOBS table not found in $src"; return 2; }

  while IFS= read -r line; do
    case "$line" in
      *'env: "'*)
        ssot+=("$(printf '%s' "$line" | sed -n 's/.*env: "\([^"]*\)".*/\1/p')" )
        ;;
      *'env: crate::'*)
        # `env: crate::path::CONST_NAME,` — resolve CONST_NAME's literal.
        local cname
        cname="$(printf '%s' "$line" | sed -n 's/.*env: crate::.*::\([A-Z0-9_]*\),.*/\1/p')"
        [ -n "$cname" ] || { echo "cannot check: unparseable KNOBS row: $line"; return 2; }
        resolved="$(grep -rhoE "pub const ${cname}: &str = \"[^\"]*\"" "$root/src" \
                    | head -1 | sed -n 's/.*= "\([^"]*\)".*/\1/p')"
        [ -n "$resolved" ] || { echo "cannot check: could not resolve const $cname"; return 2; }
        ssot+=("$resolved")
        ;;
    esac
  done <<<"$knobs_block"

  [ "${#ssot[@]}" -gt 0 ] || { echo "cannot check: KNOBS table parsed to zero rows"; return 2; }

  # lab set = SET names + UNSET names + the documented omission
  local lab=() kv
  for kv in "${LAB_POSTURE_SET[@]}"; do lab+=("${kv%%=*}"); done
  lab+=("${LAB_POSTURE_UNSET[@]}" "$LAB_POSTURE_OMITTED")

  local a b
  a="$(printf '%s\n' "${ssot[@]}" | sort)"
  b="$(printf '%s\n' "${lab[@]}" | sort)"
  if [ "$a" = "$b" ]; then
    echo "ok: lab posture covers all ${#ssot[@]} SSOT knobs ($(lab_posture_count)/${#ssot[@]} at hard floor, 1 omitted per #$LAB_POSTURE_OMITTED_ISSUE)"
    return 0
  fi
  echo "DRIFT: lab posture list disagrees with src/security_profile.rs::KNOBS"
  echo "  only in SSOT: $(comm -23 <(printf '%s\n' "$a") <(printf '%s\n' "$b") | tr '\n' ' ')"
  echo "  only in lab:  $(comm -13 <(printf '%s\n' "$a") <(printf '%s\n' "$b") | tr '\n' ' ')"
  return 1
}
