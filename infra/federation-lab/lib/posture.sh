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
# _lab_posture_const <root> <CONST_NAME> [<module/path>] — the string literal of
# `pub const NAME: &str` (also `pub(crate)`, value on the same line or the next), or
# empty if unresolvable. The file the KNOBS row names (`crate::a::b::NAME` is
# src/a/b.rs or src/a/b/mod.rs) is searched first; only when the const is not
# defined there (a re-export, or an associated const) is all of src searched. Either way
# more than one DISTINCT value is refused as unresolvable (#5124): a shadowing duplicate
# must never be picked by file order.
_lab_posture_const() {
  local root="$1" name="$2" modp="${3:-}" files=() f vals=""
  if [ -n "$modp" ]; then
    for f in "$root/src/$modp.rs" "$root/src/$modp/mod.rs"; do [ -f "$f" ] && files+=("$f"); done
  fi
  if [ "${#files[@]}" -gt 0 ]; then vals="$(_lab_posture_const_vals "$name" "${files[@]}")"; fi
  if [ -z "$vals" ]; then vals="$(_lab_posture_const_vals "$name" -R "$root/src")"; fi
  [ -n "$vals" ] || return 0
  [ "$(printf '%s\n' "$vals" | wc -l)" -eq 1 ] || return 0
  printf '%s' "$vals"
}

# _lab_posture_const_vals <NAME> <grep file args...> — the distinct literals, one per line.
_lab_posture_const_vals() {
  local name="$1"; shift
  grep -hzoE "pub(\(crate\))? const $name: &str =[[:space:]]*\"[^\"]*\"" "$@" 2>/dev/null \
    | tr '\0\n' '  ' | grep -oE '"[^"]*"' | sed 's/^"//; s/"$//' | sort -u
}

# _lab_posture_expr <root> <expr> — resolve one KNOBS field expression: a string
# literal ("refuse") or a `crate::path::CONST` reference. Echoes the value (which
# may be the empty string); returns 1 if a const cannot be resolved.
_lab_posture_expr() {
  local root="$1" expr="$2" cname val modp
  case "$expr" in
    \"*\") printf '%s' "$expr" | sed -n 's/^"\(.*\)"$/\1/p'; return 0 ;;
    crate::*)
      cname="$(printf '%s' "$expr" | sed -n 's/.*::\([A-Z0-9_]*\)$/\1/p')"
      [ -n "$cname" ] || return 1
      # Module path of the const: `crate::a::b::NAME` -> a/b, `crate::tls::NAME` -> tls; a
      # type segment (`AppConfig::NAME`) is dropped so the file that owns the type is
      # searched. Every row prints a path (#4511-R6: `p` must not depend on a `::` left).
      modp="$(printf '%s' "$expr" | sed -n 's/^crate:://; s/::[A-Z0-9_]*$//; s/::[A-Z][A-Za-z0-9]*$//; s|::|/|g; p')"
      val="$(_lab_posture_const "$root" "$cname" "$modp")"
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

# #5155: true when a boot refusal in <file> names the lowered rollback-check knob.
# One awk pass reads the whole file: no pipe (a `grep -q` reader closing early returns 141
# under pipefail) and no here-string or here-document (bash spills a large one to a temp file
# under $TMPDIR, /tmp when unset; #5197, #5259). Lines naming INFO are the profile's pin line, never a refusal.
# The trailing colon pins the whole knob name. An unreadable file is "not detected".
# Trust root (#5586): PATH. The matcher runs only when awk resolves to an external file at call time
# (a shell function, an enabled builtin, or an alias with expand_aliases on, named awk, is refused with
# rc 2, never run), and it runs that file as `command awk`. [[ ]] is a shell keyword, so a function named
# [ cannot fake the guard; `builtin` and `type` are checked by the self-test, not here. An awk file that
# an earlier PATH entry or a hash -p entry supplies IS an external file and is not detected here.
lab_probe_refusal_names_knob() {
  [[ $(builtin type -t awk) == file ]] || return 2
  command awk 'index($0, "INFO") == 0 && index($0, "refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK:") { f = 1 }
       END { exit (f ? 0 : 1) }' "$1" 2>/dev/null
}

# #5539, #5540, #5541: the one matcher statement the structural self-test leg accepts, as `declare -f` prints it with every
# run of whitespace collapsed to one space. Closed world: a body is allowed only when it EQUALS this text, so any other
# command, redirect, substitution, second statement or awk program is refused without being named (a denylist cannot be closed).
# Changing the matcher means changing this text in the same commit.
lab_probe_expected_body() {
  local q="'"
  printf '%s' "lab_probe_refusal_names_knob () { [[ \$(builtin type -t awk) == file ]] || return 2; command awk ${q}index(\$0, \"INFO\") == 0 && index(\$0, \"refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK:\") { f = 1 } END { exit (f ? 0 : 1) }${q} \"\$1\" 2> /dev/null }"
}

# lab_probe_body_allowed <declare -f text> — true only when the text, whitespace-normalized, equals the expected body.
lab_probe_body_allowed() {
  local norm IFS=$' \t\n'
  norm="$(set -f; set -- $1; printf '%s' "$*")"
  [ "$norm" = "$(lab_probe_expected_body)" ]
}

# lab_posture_selftest <repo-root> — prove the drift guard can fail (#5078).
# 56 legs. Five mutate the lab posture arrays in a subshell and the check must go red: a weakened
# value (plain, boolean and const-valued), a dropped name, a SET knob moved to UNSET. The other 51
# leave the arrays alone (#5262): the control (must pass), three const-shadow legs (a duplicate
# const in a scratch src tree), seven probe-matcher legs (lab_probe_refusal_names_knob against
# generated logs), one structural leg (the matcher body equals the one allowed statement, #5539), a
# globbing-and-IFS leg, a mutant-builder control, twenty-six closed-world legs (a mutated body of
# each spelling must be refused: twenty-two spill spellings (cp, dd, install, sort -o or tee, a stderr
# redirect to a near name, process substitution, here-string, here-document, pipe, coproc, command
# substitution, extra statement, function call, eval, exec redirect, a changed awk program, ...), four
# guard spellings (guard dropped, plain awk, guard returning 0, guard weakened, #5586)), ten shadow legs (#5586: an awk-resolves-to-file
# control, an awk function, an awk alias, a shell function named cat, mktemp, grep, sed, tr or printf that
# the matcher must never call, and no function named builtin, type or command), and one layout
# leg (this comment sits directly on the function).
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
  # #5124: a const resolves from the file the KNOBS row names; a shadowing duplicate elsewhere
  # in src must neither change a named-path result nor be picked by file order when the
  # const has to be found by name alone (then two distinct values are "cannot check", rc 2).
  local shadow; shadow="$(mktemp -d "${TMPDIR:-.}/posture-shadow.XXXXXX")" || return 1
  mkdir -p "$shadow/src" && local e
  for e in "$root"/src/*; do ln -s "$e" "$shadow/src/$(basename "$e")"; done
  printf 'pub const MODE_REFUSE: &str = "warn";\n' > "$shadow/src/aaa_shadow.rs"
  local real_root="$root"; root="$shadow"
  ( _leg "a shadow duplicate of a path-named const does not change the result" 0 ) || bad=1
  printf 'pub const FED_CERT_PEER_BINDING_ENV: &str = "SHADOW_ENV";\n' >> "$shadow/src/aaa_shadow.rs"
  ( _leg "a shadow duplicate of a single-module path-named const (crate::tls) does not change the result" 0 ) || bad=1
  # ENV_DB_SYNCHRONOUS is a re-export (`crate::storage` does not define it), so it is found by name.
  printf 'pub const ENV_DB_SYNCHRONOUS: &str = "SHADOW_ENV";\n' >> "$shadow/src/aaa_shadow.rs"
  ( _leg "a name-only const with two distinct values is cannot-check, not first-match" 2 ) || bad=1
  root="$real_root"; rm -rf "$shadow"
  # #5155: the probe-mutation matcher names the knob WITH its trailing colon, ignores INFO pin
  # lines, and reads the whole log (a large log must not turn a detection into "inconclusive").
  local plog; plog="$(mktemp -d "${TMPDIR:-.}/probe-matcher.XXXXXX")" || return 1
  printf 'fatal: refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: floor 1\n' > "$plog/ok.log"
  printf 'fatal: refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK_STRICT: nope\n' > "$plog/other-knob.log"
  printf 'boot\nINFO refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: pinned\n' > "$plog/info-only.log"
  printf 'INFO refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: pinned\nfatal: refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: floor 1\n' > "$plog/info-then-refusal.log"
  printf 'fatal: refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: floor 1\nINFO refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: pinned\n' > "$plog/refusal-then-info.log"
  printf '2026-01-01T00:00:00Z INFO refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: pinned\n' > "$plog/info-prefixed.log"
  # The refusal is printed in END, after the filler (#5292). /dev/null is the input so END
  # runs without reading stdin (an awk program with only an END block reads stdin).
  awk 'END { for (i = 0; i < 200000; i++) print "filler line to fill the pipe buffer"
             print "fatal: refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK: floor 1" }' /dev/null > "$plog/big.log"
  ( lab_probe_refusal_names_knob "$plog/ok.log" ) \
    && echo "  PASS probe matcher: refusal naming the knob is detected" \
    || { echo "  FAIL probe matcher: refusal naming the knob not detected"; bad=1; }
  ( lab_probe_refusal_names_knob "$plog/other-knob.log" ) \
    && { echo "  FAIL probe matcher: a refusal for a longer knob name was counted"; bad=1; } \
    || echo "  PASS probe matcher: a refusal for a longer knob name is not counted"
  ( lab_probe_refusal_names_knob "$plog/info-only.log" ) \
    && { echo "  FAIL probe matcher: an INFO pin line was counted"; bad=1; } \
    || echo "  PASS probe matcher: an INFO pin line is not counted"
  ( lab_probe_refusal_names_knob "$plog/info-prefixed.log" ) \
    && { echo "  FAIL probe matcher: an INFO pin line with a timestamp prefix was counted"; bad=1; } \
    || echo "  PASS probe matcher: an INFO pin line with a timestamp prefix is not counted"
  ( lab_probe_refusal_names_knob "$plog/info-then-refusal.log" ) \
    && echo "  PASS probe matcher: a refusal after an INFO line naming the knob is detected" \
    || { echo "  FAIL probe matcher: a refusal after an INFO line naming the knob not detected"; bad=1; }
  ( lab_probe_refusal_names_knob "$plog/refusal-then-info.log" ) \
    && echo "  PASS probe matcher: a refusal followed by an INFO line naming the knob is detected" \
    || { echo "  FAIL probe matcher: a refusal followed by an INFO line naming the knob not detected"; bad=1; }
  ( set -o pipefail; lab_probe_refusal_names_knob "$plog/big.log" ) \
    && echo "  PASS probe matcher: detection in a large log survives pipefail" \
    || { echo "  FAIL probe matcher: detection in a large log lost"; bad=1; }
  # #5197, #5259, #5519, #5539: the matcher is ONE awk statement reading "$1" with one stderr redirect to /dev/null.
  # The leg is an allowlist: the normalized body must equal lab_probe_expected_body. A here-string, here-document,
  # pipe, process substitution, temp file (mktemp, cp, dd, install, sort -o, tee, an exec or output redirect) and any
  # other extra command are refused because they are not that one statement.
  if lab_probe_body_allowed "$(declare -f lab_probe_refusal_names_knob)"; then
    echo "  PASS probe matcher: the body is exactly the one allowed awk statement (one awk command, its program, \"\$1\", one 2> /dev/null)"
  else
    echo "  FAIL probe matcher: the body is not exactly the one allowed awk statement"; bad=1
  fi
  # #5539: the comparison must not depend on the caller's globbing or IFS: a one-character file name would expand the
  # standalone ? of the awk program, and a changed IFS would split the words differently.
  : > "$plog/x"
  if ( cd "$plog" && IFS=: && lab_probe_body_allowed "$(declare -f lab_probe_refusal_names_knob)" ); then
    echo "  PASS probe matcher: the allowlist compare ignores a one-character file name and a changed IFS"
  else
    echo "  FAIL probe matcher: the allowlist compare depends on globbing or IFS"; bad=1
  fi
  # #5539, #5540, #5541: each spelling below is a way to read the log other than that statement; every one must be refused.
  local exp head core tail
  exp="$(lab_probe_expected_body)"; head="lab_probe_refusal_names_knob () { "
  core="${exp#"$head"}"; core="${core% \}}"; tail=' "$1" 2> /dev/null'
  _refuse() {  # <spelling> <mutated body> — the allowlist must say no
    if lab_probe_body_allowed "$2"; then echo "  FAIL probe matcher: a matcher that $1 is accepted"; return 1
    else echo "  PASS probe matcher: a matcher that $1 is refused"; fi
  }
  # Builder control: the unmutated pieces reassembled must be ALLOWED, so a refusal below is the mutation's doing.
  if lab_probe_body_allowed "${head}${core} }"; then echo "  PASS probe matcher: the mutant builder reassembles the allowed body unchanged (control)"
  else echo "  FAIL probe matcher: the mutant builder does not reassemble the allowed body (control)"; bad=1; fi
  _refuse "copies the log with cp into a spill file (M3)" "${head}"'cp "$1" /dev/shm/lab-probe.$$ ; '"${core} }" || bad=1
  _refuse "copies the log with cp into \$TMP (M4)" "${head}"'cp "$1" "$TMP/lab-probe.$$" ; '"${core} }" || bad=1
  _refuse "copies the log with dd into \$HOME (M8)" "${head}"'dd if="$1" of="${HOME}/.lab-probe.$$" status=none ; '"${core} }" || bad=1
  _refuse "redirects stderr to /dev/null.spill (M5)" "${head}${core%"$tail"}"' "$1" 2> /dev/null.spill }' || bad=1
  _refuse "reads the log through process substitution (M7)" "${head}${core%"$tail"}"' < <(cat "$1" 2> /dev/null) }' || bad=1
  _refuse "copies the log with tee into \$TEMP" "${head}"'tee "$TEMP/lab-probe.$$" < "$1" ; '"${core} }" || bad=1
  _refuse "copies the log with install into \$TEMP" "${head}"'install -m 600 "$1" "$TEMP/lab-probe.$$" ; '"${core} }" || bad=1
  _refuse "writes a sorted copy with sort -o" "${head}"'sort -o "$HOME/lab-probe.$$" "$1" ; '"${core} }" || bad=1
  _refuse "opens an exec redirect to a file" "${head}"'exec 3> /tmp/lab-probe.$$ ; '"${core} }" || bad=1
  _refuse "reads the log through a here-string" "${head}${core%"$tail"}"' <<< "$(cat "$1")" }' || bad=1
  _refuse "reads the log through a here-document" "${head}${core%"$tail"}"' <<EOF $(cat "$1") EOF }' || bad=1
  _refuse "pipes the log into awk" "${head}"'cat "$1" | '"${core%"$tail"}"' 2> /dev/null }' || bad=1
  _refuse "pipes with |& into awk" "${head}"'cat "$1" |& '"${core%"$tail"}"' 2> /dev/null }' || bad=1
  _refuse "starts a coproc" "${head}"'coproc cat "$1" ; '"${core} }" || bad=1
  _refuse "captures the log with a command substitution" "${head}"'x="$(cat "$1")" ; '"${core} }" || bad=1
  _refuse "runs a second statement after a semicolon" "${head}${core} ; true }" || bad=1
  _refuse "calls a helper function" "${head}"'lab_helper "$1" ; '"${core} }" || bad=1
  _refuse "evals a copy command" "${head}"'eval "cp $1 /dev/shm/lab-probe.$$" ; '"${core} }" || bad=1
  _refuse "makes a temp file with mktemp" "${head}"'t=$(mktemp) ; cp "$1" "$t" ; '"${core} }" || bad=1
  _refuse "duplicates stderr instead of discarding it" "${head}${core%"$tail"}"' "$1" 2>&1 > /dev/null }' || bad=1
  _refuse "has awk write a file from its own program" "${head}${core/\{ f = 1 \}/\{ f = 1; print \$0 > \"/dev/shm/lab-probe\" \}}"' }' || bad=1
  _refuse "changes the awk program (the INFO skip anchored)" "${head}${core/index(\$0, \"INFO\") == 0/\$0 !~ /^INFO/} }" || bad=1
  _refuse "drops the external-awk guard" "${head}${core#*return 2; }"' }' || bad=1
  _refuse "calls awk by bare name instead of command awk" "${head}${core/command awk/awk} }" || bad=1
  _refuse "makes the guard return 0 for a shadowed awk" "${head}${core/return 2/return 0} }" || bad=1
  _refuse "weakens the guard to refuse only a function" "${head}${core/== file/!= function} }" || bad=1
  unset -f _refuse
  # #5586: the matcher must refuse a shadowed awk and must call no other external command.
  local canary="$plog/canary"
  if [[ $(builtin type -t awk) == file ]]; then
    echo "  PASS probe matcher: control - awk resolves to an external file here, so each shadow leg starts from the accepted state"
  else echo "  FAIL probe matcher: control - awk does not resolve to an external file here"; bad=1; fi
  ( rm -f "$canary"; awk() { : > "$canary"; command awk "$@"; }
    lab_probe_refusal_names_knob "$plog/ok.log"; rc=$?
    [ "$rc" -eq 2 ] && [ ! -e "$canary" ] ) \
    && echo "  PASS probe matcher: an awk shell function is refused (rc 2) and never called" \
    || { echo "  FAIL probe matcher: an awk shell function was run or accepted"; bad=1; }
  ( rm -f "$canary"; shopt -s expand_aliases; alias awk="${plog}/canary-awk"
    lab_probe_refusal_names_knob "$plog/ok.log"; rc=$?
    [ "$rc" -eq 2 ] && [ ! -e "$canary" ] ) \
    && echo "  PASS probe matcher: an awk alias (expand_aliases on) is refused (rc 2) and never run" \
    || { echo "  FAIL probe matcher: an awk alias was run or accepted"; bad=1; }
  # An enable -f builtin named awk needs a loadable module and is not expressible here; type -t reports it as builtin,
  # which is not file, so the same guard refuses it. That is a statement about the guard, not a leg.
  local nb
  for nb in cat mktemp grep sed tr printf; do
    ( rm -f "$canary"
      eval "$nb() { : > \"\$canary\"; command $nb \"\$@\"; }"
      lab_probe_refusal_names_knob "$plog/ok.log"; r1=$?
      lab_probe_refusal_names_knob "$plog/info-only.log"; r2=$?
      [ "$r1" -eq 0 ] && [ "$r2" -eq 1 ] && [ ! -e "$canary" ] ) \
      && echo "  PASS probe matcher: a shell function named $nb is never called by the matcher, the verdicts are unchanged" \
      || { echo "  FAIL probe matcher: the matcher called a shell function named $nb or changed its verdict"; bad=1; }
  done
  if [[ -z $(declare -F builtin type command) ]]; then
    echo "  PASS probe matcher: no shell function shadows builtin, type or command at matcher time"
  else echo "  FAIL probe matcher: a shell function shadows builtin, type or command"; bad=1; fi
  rm -rf "$plog"
  # #5198: the doc comment sits on the function it describes (a helper between them is drift).
  if [ "$(grep -B1 '^lab_posture_selftest() {' "${BASH_SOURCE[0]}" | head -n 1)" = "# Prints one line per leg; returns 0 only if every leg behaved." ]; then
    echo "  PASS doc comment: lab_posture_selftest is documented by the comment directly above it"
  else
    echo "  FAIL doc comment: another function sits between the lab_posture_selftest comment and the function"; bad=1
  fi
  unset -f _leg
  return "$bad"
}
