# shellcheck shell=bash
# =============================================================================
# infra/federation-lab/lib/posture.sh — the lab's asi-hard security posture.
# =============================================================================
# SSOT for the hardened posture is `src/security_profile.rs::KNOBS` (rendered
# for operators as `docs/deploy/asi-hard.env`). That table pins every knob it lists
# (the count is read from the table, never written here) under a NO-DISABLE contract: under `AI_MEMORY_SECURITY_PROFILE=asi-hard`
# each knob is pinned to its hard floor, and setting any of them BELOW that
# floor REFUSES boot.
#
# THE LAB RUNS EVERY PINNED KNOB AT ITS HARD FLOOR — but does NOT set
# `AI_MEMORY_SECURITY_PROFILE=asi-hard`. Why, stated plainly:
#
#   The profile knob's contract is pin-and-refuse, so a lab that must also UNSET
#   permissive hatches itself and report each knob by name sets every pinned knob to
#   its hard-floor value DIRECTLY (LAB_POSTURE_SET below) instead of delegating to the
#   profile. The result is the same pinned set the profile enforces, and the drift
#   guard below proves the lab's list is exactly src/security_profile.rs::KNOBS.
#
#   History (issue #2942, CLOSED, fixed by PR #3096): AI_MEMORY_REQUIRE_ROLLBACK_CHECK
#   used to be left out because, in require-mode, the open-time rollback-evidence
#   check treated an ABSENT off-table head anchor as refuse-to-open, and a brand-new
#   database has none (exit 75). On a current build a fresh cold boot succeeds under
#   the full profile, so the lab now sets the knob like every other (issue #4938).
#
#   The cold-boot probe (on by default; disable with `run.sh --no-caveat-probe`)
#   keeps that fix honest: it cold-boots one throwaway node on a fresh database
#   under the FULL asi-hard profile and requires it to come up listening. A boot that
#   REFUSES is a FAIL (a regression of #2942 or a new refusal), never a documented
#   caveat. `run.sh --probe-mutation` re-runs the probe with the knob lowered below
#   its floor and requires the probe to go red, proving the probe can fail.
#
# The PERMISSIVE hatches have a hard floor of "unset" (LAB_POSTURE_UNSET
# below, e.g. AI_MEMORY_ALLOW_SCHEMA_AHEAD #2445 and
# AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS #2477). The lab actively UNSETS them rather than leaving whatever the
# operator's shell happened to export — an inherited hatch is exactly the
# silent weakening the posture exists to prevent.
# =============================================================================

# The knobs the lab SETS to their hard-floor value.
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
  "AI_MEMORY_REQUIRE_ROLLBACK_CHECK=1"
  "AI_MEMORY_REQUIRE_WITNESS=1"
  "AI_MEMORY_REQUIRE_CAUSE_BINDING=1"
  "AI_MEMORY_REQUIRE_ROLE_SEPARATION=1"
  "AI_MEMORY_REQUIRE_IDENTITY_LINEAGE=1"
  "AI_MEMORY_FED_REQUIRE_SERVER_VERIFY=1"
  "AI_MEMORY_DB_SYNCHRONOUS=FULL"
  "AI_MEMORY_FED_REQUIRE_SIG=1"
  "AI_MEMORY_FED_REQUIRE_NONCE=1"
  "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1"
  "AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=1"
  "AI_MEMORY_MIGRATION_REQUIRE_CORE_TABLES=1"
  "AI_MEMORY_PERMISSIONS_MODE=enforce"
  "AI_MEMORY_FED_REQUIRE_POLICY_CURRENT=1"
  "AI_MEMORY_FED_CERT_PEER_BINDING=enforce"
  "AI_MEMORY_UNSTAMPED_MUTATION=refuse"
  "AI_MEMORY_REQUIRE_FORENSIC_SINK=1"
)

# The PERMISSIVE hatches whose hard floor is "not in force" — unset them.
LAB_POSTURE_UNSET=(
  "AI_MEMORY_ALLOW_SCHEMA_AHEAD"
  "AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS"
  "AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR"
  "AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS"
  "AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS"
  "AI_MEMORY_AGENT_API_KEY_FILE_ALLOW_LAX_PERMS"
)

# lab_posture_count — the knobs at their hard floor: every SET plus every UNSET entry.
lab_posture_count() { echo $(( ${#LAB_POSTURE_SET[@]} + ${#LAB_POSTURE_UNSET[@]} )); }

# lab_posture_export — apply the lab posture to the CURRENT shell.
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
}

# lab_posture_render — one `NAME=VALUE` per line, for the run manifest and
# for the reader who wants to diff the lab against docs/deploy/asi-hard.env.
lab_posture_render() {
  printf '%s\n' "${LAB_POSTURE_SET[@]}"
  local k
  for k in "${LAB_POSTURE_UNSET[@]}"; do printf '%s=<unset — permissive hatch NOT in force>\n' "$k"; done
}

# lab_posture_ssot_check <repo-root> — DRIFT GUARD.
#
# Re-derives the pinned-knob set from the Rust SSOT and asserts the lab's
# list is exactly it. Runs only when the
# source tree is present (the kit also works from a release tarball). Echoes
# a one-line verdict; returns 0 on agreement, 1 on drift, 2 on "cannot check".
#
# Both the env NAME and the hard VALUE of every KNOBS row are compared (#5078):
# a SET entry must equal the row's hard value, an UNSET entry must be a row whose
# hard value is "". Rows may name a Rust const instead of a literal (`env: crate::…::NAME`,
# `hard_value: crate::…::MODE_REFUSE`); those are resolved from the const definitions
# (`pub const` and `pub(crate) const`, the value on the same line or the next one).
# If a future row uses a shape this cannot resolve, the check reports "cannot
# check" rather than passing — a drift guard that silently degrades to green is
# worse than none. `run.sh --posture-selftest` proves the guard can fail.
# _lab_posture_const <root> <CONST_NAME> — the string literal of `pub const NAME: &str`
# (also `pub(crate)`, value on the same line or the next), or empty if unresolvable.
_lab_posture_const() {
  grep -rhzoE "pub(\(crate\))? const $2: &str =[[:space:]]*\"[^\"]*\"" "$1/src" \
    | tr '\0\n' '  ' | sed -n 's/^[^"]*"\([^"]*\)".*/\1/p'
}

# _lab_posture_expr <root> <expr> — resolve one KNOBS field expression: a string
# literal ("refuse") or a `crate::path::CONST` reference. Echoes the value (which
# may be the empty string); returns 1 if a const cannot be resolved.
_lab_posture_expr() {
  local root="$1" expr="$2" cname val
  case "$expr" in
    \"*\") printf '%s' "$expr" | sed -n 's/^"\(.*\)"$/\1/p'; return 0 ;;
    crate::*)
      cname="$(printf '%s' "$expr" | sed -n 's/.*::\([A-Z0-9_]*\)$/\1/p')"
      [ -n "$cname" ] || return 1
      val="$(_lab_posture_const "$root" "$cname")"
      [ -n "$val" ] || return 1
      printf '%s' "$val"; return 0 ;;
  esac
  return 1
}

lab_posture_ssot_check() {
  local root="$1" src="$1/src/security_profile.rs"
  [ -f "$src" ] || { echo "skip: no source tree at $root (release-tarball mode)"; return 2; }

  local knobs_block
  knobs_block="$(awk '/^const KNOBS: &\[KnobSpec\] = &\[/,/^\];/' "$src")"
  [ -n "$knobs_block" ] || { echo "cannot check: KNOBS table not found in $src"; return 2; }

  # One `env-expr<TAB>hard-value-expr` pair per KnobSpec row, then resolve both
  # sides (#4938/#5078: the NAME and the hard VALUE are both compared).
  local pairs ssot=() ssot_val=() line envx valx name val
  pairs="$(printf '%s\n' "$knobs_block" | awk '
    /^[[:space:]]*env:/        { sub(/^[[:space:]]*env:[[:space:]]*/, ""); sub(/,[[:space:]]*$/, ""); e = $0 }
    /^[[:space:]]*hard_value:/ { sub(/^[[:space:]]*hard_value:[[:space:]]*/, ""); sub(/,[[:space:]]*$/, ""); printf "%s\t%s\n", e, $0 }')"
  while IFS=$'\t' read -r envx valx; do
    [ -n "$envx" ] || continue
    name="$(_lab_posture_expr "$root" "$envx")" \
      || { echo "cannot check: could not resolve KNOBS env expression $envx"; return 2; }
    [ -n "$name" ] || { echo "cannot check: could not resolve KNOBS env expression $envx"; return 2; }
    val="$(_lab_posture_expr "$root" "$valx")" \
      || { echo "cannot check: could not resolve KNOBS hard_value expression $valx (knob $name)"; return 2; }
    ssot+=("$name"); ssot_val+=("$val")
  done <<<"$pairs"

  [ "${#ssot[@]}" -gt 0 ] || { echo "cannot check: KNOBS table parsed to zero rows"; return 2; }

  # lab set = SET names + UNSET names
  local lab=() kv
  for kv in "${LAB_POSTURE_SET[@]}"; do lab+=("${kv%%=*}"); done
  lab+=("${LAB_POSTURE_UNSET[@]}")

  local a b
  a="$(printf '%s\n' "${ssot[@]}" | sort)"
  b="$(printf '%s\n' "${lab[@]}" | sort)"
  if [ "$a" != "$b" ]; then
    echo "DRIFT: lab posture list disagrees with src/security_profile.rs::KNOBS"
    echo "  only in SSOT: $(comm -23 <(printf '%s\n' "$a") <(printf '%s\n' "$b") | tr '\n' ' ')"
    echo "  only in lab:  $(comm -13 <(printf '%s\n' "$a") <(printf '%s\n' "$b") | tr '\n' ' ')"
    return 1
  fi

  # Value check: a SET entry must equal the knob's hard value (and the hard
  # value must be non-empty); an UNSET entry must be a knob whose hard floor is
  # the empty string (permissive hatch not in force).
  local i k want drift=0
  for kv in "${LAB_POSTURE_SET[@]}"; do
    k="${kv%%=*}"; val="${kv#*=}"; want=""
    for i in "${!ssot[@]}"; do [ "${ssot[$i]}" = "$k" ] && want="${ssot_val[$i]}"; done
    if [ -z "$want" ] || [ "$val" != "$want" ]; then
      echo "DRIFT: $k value '$val' != hard value '$want' in src/security_profile.rs::KNOBS"; drift=1
    fi
  done
  for k in "${LAB_POSTURE_UNSET[@]}"; do
    for i in "${!ssot[@]}"; do
      if [ "${ssot[$i]}" = "$k" ] && [ -n "${ssot_val[$i]}" ]; then
        echo "DRIFT: $k is unset in the lab but its hard value is '${ssot_val[$i]}' in src/security_profile.rs::KNOBS"; drift=1
      fi
    done
  done
  [ "$drift" -eq 0 ] || return 1

  echo "ok: lab posture covers all ${#ssot[@]} SSOT knobs ($(lab_posture_count) of ${#ssot[@]} at hard floor, names and values compared)"
  return 0
}

# lab_posture_selftest <repo-root> — prove the drift guard can fail (#5078).
# Each leg mutates the lab posture arrays in a subshell and the check must
# return the expected code: the control passes; a weakened value (plain and
# const-valued), a dropped name and a SET knob moved to UNSET all go red.
# Prints one line per leg; returns 0 only if every leg behaved.
lab_posture_selftest() {
  local root="$1" bad=0 rc name want
  _leg() {  # <name> <want-rc> — runs the check in the CURRENT subshell's arrays
    local out; out="$(lab_posture_ssot_check "$root")"; rc=$?
    if [ "$rc" -eq "$2" ]; then echo "  PASS $1 (rc=$rc)"; else echo "  FAIL $1: rc=$rc, wanted $2: $out"; return 1; fi
  }
  ( _leg "control: lab posture equals the SSOT names and values" 0 ) || bad=1
  ( LAB_POSTURE_SET=("${LAB_POSTURE_SET[@]/AI_MEMORY_PERMISSIONS_MODE=enforce/AI_MEMORY_PERMISSIONS_MODE=advisory}")
    _leg "weakened value AI_MEMORY_PERMISSIONS_MODE=advisory is refused" 1 ) || bad=1
  ( LAB_POSTURE_SET=("${LAB_POSTURE_SET[@]/AI_MEMORY_CID_ENFORCE=1/AI_MEMORY_CID_ENFORCE=0}")
    _leg "weakened boolean AI_MEMORY_CID_ENFORCE=0 is refused" 1 ) || bad=1
  ( LAB_POSTURE_SET=("${LAB_POSTURE_SET[@]/AI_MEMORY_UNSTAMPED_MUTATION=refuse/AI_MEMORY_UNSTAMPED_MUTATION=warn}")
    _leg "weakened const-valued knob AI_MEMORY_UNSTAMPED_MUTATION=warn is refused" 1 ) || bad=1
  ( LAB_POSTURE_SET=("${LAB_POSTURE_SET[@]/AI_MEMORY_REQUIRE_FORENSIC_SINK=1}")
    _leg "dropped knob name is refused" 1 ) || bad=1
  ( LAB_POSTURE_SET=("${LAB_POSTURE_SET[@]/AI_MEMORY_CID_ENFORCE=1}")
    LAB_POSTURE_UNSET+=("AI_MEMORY_CID_ENFORCE")
    _leg "a pinned knob moved to the unset list is refused" 1 ) || bad=1
  unset -f _leg
  return "$bad"
}
