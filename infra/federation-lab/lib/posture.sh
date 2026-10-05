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
#
# Closed world (#5586, #5588, #5591): the matcher and its guard run EVERY command from ONE table, LAB_PROBE_CMDS, and
# the guard lab_probe_cmds_proven refuses (rc 2, reason in LAB_PROBE_WHY, nothing run) unless each row resolves, at call
# time, to the kind the row names. Rows: the keyword [[ , and the builtins builtin, type and return. Each name is
# probed twice, by plain `type -t` and by `builtin type -t`, so a function shadowing type or builtin is seen by the
# other probe. awk is never looked up by name: it is run from the first absolute path in LAB_PROBE_AWK_PATHS that is a
# regular executable file and is not itself shadowed by a function, so PATH, the hash table, an awk function, an awk
# alias, an exported awk function and an awk earlier on PATH are not consulted. No other command is called, and no
# redirect, here-string or substitution reads the log (the structural leg pins both bodies).
# COVERED routes (each has a self-test leg): a function, an exported function (BASH_FUNC_), an alias defined
# before the call with expand_aliases on, `enable -n`, a PATH entry and a changed IFS or shell option, for every table row; and for awk a
# function, alias, exported function and PATH entry (ignored) or a function named by the absolute path (skipped).
# NOT covered, said plainly: (1) a caller that shadows BOTH probe commands (a function type AND a function builtin) and
# answers both falsely; bash has no in-shell defence against that. (2) an alias that existed only while this file was
# sourced and was removed before the call: it is in the parsed body, and only the structural leg of --posture-selftest sees it.
# (3) a hostile regular file at one of the absolute awk paths, or a replaced guard or matcher function. (4) an enabled loadable
# builtin named after a row is refused as not-the-row-kind; one named awk is not consulted. bash 3.2 was not run.
LAB_PROBE_CMDS=('[[:keyword' 'builtin:builtin' 'type:builtin' 'return:builtin')
LAB_PROBE_AWK_PATHS=(/usr/bin/awk /bin/awk)
lab_probe_cmds_proven() {
  LAB_PROBE_AWK=""; LAB_PROBE_WHY=""
  for _lab_row in "${LAB_PROBE_CMDS[@]}"; do
    _lab_n=${_lab_row%%:*}; _lab_k=${_lab_row#*:}
    [[ $(type -t "$_lab_n") == "$_lab_k" && $(builtin type -t "$_lab_n") == "$_lab_k" ]] || LAB_PROBE_WHY="${LAB_PROBE_WHY}${_lab_n} is not the ${_lab_k} the matcher needs; "
  done
  for _lab_a in "${LAB_PROBE_AWK_PATHS[@]}"; do
    [[ -z $LAB_PROBE_AWK && -f $_lab_a && -x $_lab_a && $(builtin type -t "$_lab_a") == file ]] && LAB_PROBE_AWK=$_lab_a
  done
  [[ -n $LAB_PROBE_AWK ]] || LAB_PROBE_WHY="${LAB_PROBE_WHY}no trusted awk file in ${LAB_PROBE_AWK_PATHS[*]}; "
  [[ -z $LAB_PROBE_WHY ]] || LAB_PROBE_AWK=""
  [[ -z $LAB_PROBE_WHY ]]
}
lab_probe_refusal_names_knob() {
  lab_probe_cmds_proven || return 2
  "$LAB_PROBE_AWK" 'index($0, "INFO") == 0 && index($0, "refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK:") { f = 1 }
       END { exit (f ? 0 : 1) }' "$1" 2>/dev/null
}

# #5588: the report a caller prints. Prints `detected`, `not-detected` or `refused: <reason>` and returns the matcher's rc (0, 1,
# 2), so a matcher that could not prove its commands is never reported as "not detected" for the lowered knob.
lab_probe_verdict() {
  local rc=0
  lab_probe_refusal_names_knob "$1" || rc=$?
  case "$rc" in
    0) printf 'detected\n' ;;
    1) printf 'not-detected\n' ;;
    *) printf 'refused: %s\n' "${LAB_PROBE_WHY:-no reason recorded}" ;;
  esac
  return "$rc"
}

# #5539, #5540, #5541, #5588: the two function bodies the structural self-test leg accepts, as `declare -f` prints them with every
# run of whitespace collapsed to one space. Closed world: a body is allowed only when it EQUALS this text, so any other
# command, redirect, substitution, second statement or awk program is refused without being named (a denylist cannot be closed).
# Changing the matcher or the guard means changing this text in the same commit.
lab_probe_expected_body() {
  local q="'"
  printf '%s' "lab_probe_refusal_names_knob () { lab_probe_cmds_proven || return 2; \"\$LAB_PROBE_AWK\" ${q}index(\$0, \"INFO\") == 0 && index(\$0, \"refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK:\") { f = 1 } END { exit (f ? 0 : 1) }${q} \"\$1\" 2> /dev/null }"
}
lab_probe_expected_guard_body() {
  printf '%s' 'lab_probe_cmds_proven () { LAB_PROBE_AWK=""; LAB_PROBE_WHY=""; for _lab_row in "${LAB_PROBE_CMDS[@]}"; do _lab_n=${_lab_row%%:*}; _lab_k=${_lab_row#*:}; [[ $(type -t "$_lab_n") == "$_lab_k" && $(builtin type -t "$_lab_n") == "$_lab_k" ]] || LAB_PROBE_WHY="${LAB_PROBE_WHY}${_lab_n} is not the ${_lab_k} the matcher needs; "; done; for _lab_a in "${LAB_PROBE_AWK_PATHS[@]}"; do [[ -z $LAB_PROBE_AWK && -f $_lab_a && -x $_lab_a && $(builtin type -t "$_lab_a") == file ]] && LAB_PROBE_AWK=$_lab_a; done; [[ -n $LAB_PROBE_AWK ]] || LAB_PROBE_WHY="${LAB_PROBE_WHY}no trusted awk file in ${LAB_PROBE_AWK_PATHS[*]}; "; [[ -z $LAB_PROBE_WHY ]] || LAB_PROBE_AWK=""; [[ -z $LAB_PROBE_WHY ]] }'
}

# lab_probe_body_allowed <declare -f text> [expected-generator] — true only when the text, whitespace-normalized, equals the expected body.
# The comparison is EQUALITY of the whole text (#5587). A substring, prefix or suffix compare is NOT equivalent to it:
# each accepts the allowed body with extra text around it. The self-test pins that with two legs (extra text after the
# allowed body, extra text before it), so the substring, prefix and suffix mutants of this line are killed, not tolerated.
lab_probe_body_allowed() {
  local norm IFS=$' \t\n'
  norm="$(set -f; set -- $1; printf '%s' "$*")"
  [ "$norm" = "$(${2:-lab_probe_expected_body})" ]
}

# lab_posture_selftest <repo-root> — prove the drift guard can fail (#5078).
# 131 legs. Five mutate the lab posture arrays in a subshell and the check must go red: a weakened
# value (plain, boolean and const-valued), a dropped name, a SET knob moved to UNSET. The other 126
# leave the arrays alone (#5262): the control (must pass), three const-shadow legs (a duplicate
# const in a scratch src tree), seven probe-matcher legs (lab_probe_refusal_names_knob against
# generated logs), three structural legs (the matcher body and the guard body each equal the one allowed text, #5539 and
# #5588, and the command table equals its literal), a globbing-and-IFS leg, a mutant-builder control, twenty-seven
# closed-world matcher legs (a mutated body of each spelling must be refused: twenty-two spill spellings (cp, dd,
# install, sort -o or tee, a stderr redirect to a near name, process substitution, here-string, here-document, pipe,
# coproc, command substitution, extra statement, function call, eval, exec redirect, a changed awk program, ...), three
# guard-call spellings (guard dropped, bare awk, guard returning 0, #5586) and two extra-text spellings (text after, text
# before, #5587)), seven closed-world guard-body mutants (#5588), two probe-verdict legs, seventy-three shadow-matrix legs (#5588: the control, one
# cell per table row per route (function, exported function, alias, enable -n, enable -n with a PATH file, a lying
# function for builtin and type), the keyword row, awk by every bare-name route and by the absolute paths (with a guard-only no-trusted-awk refusal and first-path-wins), eleven neighbour
# commands by function and by PATH file, eight IFS values, twelve shell options, and the LAB_PROBE_WHY reason), and one layout
# leg (this comment sits directly on the function).
# Prints one line per leg; returns 0 only if every leg behaved.
lab_posture_selftest() {
  local root="$1" bad=0 rc name want v1 v2 v3 v4 vr1 vr2 vr3 vok
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
  # #5197, #5259, #5519, #5539, #5588: the matcher is a guard call plus ONE awk statement reading "$1" with one stderr redirect to /dev/null.
  # The leg is an allowlist: the normalized body must equal lab_probe_expected_body. A here-string, here-document,
  # pipe, process substitution, temp file (mktemp, cp, dd, install, sort -o, tee, an exec or output redirect) and any
  # other extra command are refused because they are not that one statement. The guard body is pinned the same way.
  if lab_probe_body_allowed "$(declare -f lab_probe_refusal_names_knob)"; then
    echo "  PASS probe matcher: the body is exactly the guard call plus the one allowed awk statement (its program, \"\$1\", one 2> /dev/null)"
  else
    echo "  FAIL probe matcher: the body is not exactly the guard call plus the one allowed awk statement"; bad=1
  fi
  if lab_probe_body_allowed "$(declare -f lab_probe_cmds_proven)" lab_probe_expected_guard_body; then
    echo "  PASS probe matcher: the guard body is exactly the allowed table walk (type and builtin type per row, absolute awk file)"
  else
    echo "  FAIL probe matcher: the guard body is not exactly the allowed table walk"; bad=1
  fi
  # #5588: ONE table. These two rows are the whole inventory of commands the matcher and the guard use; a row removed from
  # LAB_PROBE_CMDS would silently drop its legs from the loop below, so the table and the awk paths are compared to the literals.
  if [ "${LAB_PROBE_CMDS[*]}" = "[[:keyword builtin:builtin type:builtin return:builtin" ] && [ "${LAB_PROBE_AWK_PATHS[*]}" = "/usr/bin/awk /bin/awk" ]; then
    echo "  PASS probe matcher: the command table is exactly [[ (keyword), builtin, type, return (builtins) and the awk paths /usr/bin/awk /bin/awk"
  else
    echo "  FAIL probe matcher: the command table or the awk paths changed"; bad=1
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
  _refuse "calls awk by bare name instead of the guarded absolute path" "${head}${core/\"\$LAB_PROBE_AWK\"/awk} }" || bad=1
  _refuse "makes the guard return 0 for a shadowed awk" "${head}${core/return 2/return 0} }" || bad=1
  # #5588: mutants of the guard body, refused by the same equality (the behavioural matrix below kills them as well).
  local gexp; gexp="$(lab_probe_expected_guard_body)"
  _refuse_guard() {  # <spelling> <mutated guard body>
    if lab_probe_body_allowed "$2" lab_probe_expected_guard_body; then echo "  FAIL probe matcher: a guard that $1 is accepted"; return 1
    else echo "  PASS probe matcher: a guard that $1 is refused"; fi
  }
  _refuse_guard "probes only with plain type" "${gexp/ && \$(builtin type -t \"\$_lab_n\") == \"\$_lab_k\"/}" || bad=1
  _refuse_guard "probes only with builtin type" "${gexp/\$(type -t \"\$_lab_n\") == \"\$_lab_k\" && /}" || bad=1
  _refuse_guard "accepts a row when either probe agrees" "${gexp/\"\$_lab_k\" && /\"\$_lab_k\" || }" || bad=1
  _refuse_guard "drops the regular-file test on the awk path" "${gexp/ -f \$_lab_a \&\&/}" || bad=1
  _refuse_guard "drops the executable test on the awk path" "${gexp/ -x \$_lab_a \&\&/}" || bad=1
  _refuse_guard "accepts an awk path that a function shadows" "${gexp/== file ]]/!= function ]]}" || bad=1
  _refuse_guard "keeps the awk path when it refuses" "${gexp/ || LAB_PROBE_AWK=\"\"; /; }" || bad=1
  unset -f _refuse_guard
  # #5587: lab_probe_body_allowed is equality, not a substring, prefix or suffix compare.
  _refuse "has extra text after the allowed body (kills a prefix or substring compare)" "${exp} ; cp \"\$1\" /dev/shm/lab-probe" || bad=1
  _refuse "has extra text before the allowed body (kills a suffix or substring compare)" "cp \"\$1\" /dev/shm/lab-probe ; ${exp}" || bad=1
  unset -f _refuse
  : > "$plog/no.log"
  # #5588: lab_probe_verdict, the report run.sh prints, says detected, not-detected, or refused with the reason.
  v1="$(lab_probe_verdict "$plog/ok.log")"; vr1=$?; v2="$(lab_probe_verdict "$plog/no.log")"; vr2=$?
  if [ "$v1" = detected ] && [ "$vr1" -eq 0 ] && [ "$v2" = not-detected ] && [ "$vr2" -eq 1 ]; then
    echo "  PASS probe verdict: detected (rc 0) for a refusal line, not-detected (rc 1) for none"
  else echo "  FAIL probe verdict: got [$v1] rc $vr1 and [$v2] rc $vr2"; bad=1; fi
  v3="$( builtin() { command builtin "$@"; }; lab_probe_verdict "$plog/ok.log" )"; vr3=$?
  v4="$( builtin() { command builtin "$@"; }; lab_probe_verdict "$plog/ok.log" >/dev/null; echo $? )"
  case "$v3" in "refused: builtin is not the builtin the matcher needs; "*) vok=1 ;; *) vok=0 ;; esac
  if [ "$vok" -eq 1 ] && [ "$v4" -eq 2 ]; then
    echo "  PASS probe verdict: a shadowed builtin reports refused with the reason (rc 2), never not-detected"
  else echo "  FAIL probe verdict: a shadowed builtin gave [$v3] rc $v4"; bad=1; fi
  # #5588: the shadow matrix. One loop over the SAME table the guard walks. Each cell shadows one command by one route in a
  # fresh subshell (or child bash, for an exported function) and runs the matcher on a log it must detect and on one it must not.
  # "refused" means rc >= 2 on both (the matcher said it cannot prove its commands; for a shadowed return the refusal path
  # itself is the shadow, which falls through to a failing empty command, never to a detection). "unchanged" means rc 0 and 1.
  # No cell may report a detection for the log without a refusal line, and no hostile awk may ever run.
  local canary="$plog/canary" ph="$plog/hostile-bin" self="${BASH_SOURCE[0]}" r1 r2
  mkdir -p "$ph"
  local hn
  for hn in awk cat mktemp grep sed tr printf command declare echo env rm builtin type return '['; do
    printf '#!/bin/sh\n: > "%s"\nexit 0\n' "$canary" > "$ph/$hn"; chmod +x "$ph/$hn"
  done
  _cell() {  # <label> <expect: refused|unchanged> <setup> [child] — setup runs in a fresh shell before the matcher
    local label="$1" want="$2" setup="$3" child="${4:-}" got
    rm -f "$canary"
    # The rc of each run is the status of its subshell: no output command is called, so a shadowed command cannot hide it.
    if [ -n "$child" ]; then
      ( eval "$setup"; "$BASH" -c '. "$1"; lab_probe_refusal_names_knob "$2"' _ "$self" "$plog/ok.log" ) 2>/dev/null; r1=$?
      ( eval "$setup"; "$BASH" -c '. "$1"; lab_probe_refusal_names_knob "$2"' _ "$self" "$plog/no.log" ) 2>/dev/null; r2=$?
    else
      ( eval "$setup"; lab_probe_refusal_names_knob "$plog/ok.log" ) 2>/dev/null; r1=$?
      ( eval "$setup"; lab_probe_refusal_names_knob "$plog/no.log" ) 2>/dev/null; r2=$?
    fi
    if [ "$want" = unchanged ]; then
      [ "$r1" = 0 ] && [ "$r2" = 1 ] && got=ok || got=bad
    else
      { [ "$r1" -ge 2 ] && [ "$r2" -ge 2 ]; } && got=ok || got=bad
    fi
    if [ "$got" = ok ]; then echo "  PASS shadow matrix: $label ($want, rc $r1 $r2)"; return 0; fi
    echo "  FAIL shadow matrix: $label wanted $want, got rc $r1 $r2"; return 1
  }
  _cell_clean() {  # <label> <setup> — as _cell unchanged, and the hostile canary must never have been written
    _cell "$1" unchanged "$2" "${3:-}" || return 1
    [ ! -e "$canary" ] || { echo "  FAIL shadow matrix: $1 ran the hostile command"; return 1; }
  }
  _cell "control: nothing shadowed" unchanged ':' || bad=1
  local row n k
  for row in "${LAB_PROBE_CMDS[@]}"; do
    n="${row%%:*}"; k="${row#*:}"
    if [ "$k" = keyword ]; then
      # A keyword wins over a function and an alias is not expanded in the parsed body: each is "unchanged", never run.
      _cell_clean "a shell function named $n (the keyword wins)" "eval '$n() { : > \"\$canary\"; }'" || bad=1
      continue
    fi
    _cell "a shell function named $n (forwarding)" refused "eval \"$n() { : > \\\"\$canary\\\"; command $n \\\"\\\$@\\\"; }\"" || bad=1
    _cell "a shell function named $n (exported to a child bash)" refused "eval \"$n() { : > \\\"\$canary\\\"; command $n \\\"\\\$@\\\"; }\"; export -f $n" child || bad=1
    _cell "an alias named $n (expand_aliases on)" refused "shopt -s expand_aliases; alias $n='$ph/$n'" || bad=1
    _cell "$n disabled with enable -n" refused "enable -n $n" || bad=1
    _cell "$n disabled with enable -n and an executable $n earlier on PATH" refused "enable -n $n; PATH=\"$ph:\$PATH\"" || bad=1
    case "$n" in builtin|type)
      _cell "a shell function named $n that answers $k to every probe" refused "eval \"$n() { echo $k; }\"" || bad=1 ;;
    esac
  done
  # awk is run by absolute path and never looked up by name: every bare-name route is unchanged and never runs.
  _cell_clean "a shell function named awk" "awk() { : > \"\$canary\"; command awk \"\$@\"; }" || bad=1
  _cell_clean "a shell function named awk (exported to a child bash)" "awk() { : > \"\$canary\"; command awk \"\$@\"; }; export -f awk" child || bad=1
  _cell_clean "an alias named awk (expand_aliases on) to an existing script that writes the canary" "shopt -s expand_aliases; alias awk='$ph/awk'" || bad=1
  _cell_clean "an awk file earlier on PATH" "PATH=\"$ph:\$PATH\"" || bad=1
  _cell_clean "hash -p pointing awk at a hostile file" "hash -p $ph/awk awk" || bad=1
  _cell_clean "a function named by the first absolute awk path (the second path is used)" "function ${LAB_PROBE_AWK_PATHS[0]} { : > \"\$canary\"; }" || bad=1
  _cell_clean "a caller-set LAB_PROBE_AWK pointing at a hostile file is reset by the guard" "LAB_PROBE_AWK=$ph/awk" || bad=1
  _cell "functions named by every absolute awk path" refused "function ${LAB_PROBE_AWK_PATHS[0]} { :; }; function ${LAB_PROBE_AWK_PATHS[1]} { :; }" || bad=1
  _cell "no absolute awk path is an executable file" refused "LAB_PROBE_AWK_PATHS=(/nonexistent/awk $plog)" || bad=1
  # The refusal for "no trusted awk" must come from the guard itself (rc exactly 2, a reason recorded), not from a failed exec.
  ( LAB_PROBE_AWK_PATHS=(/nonexistent/awk); lab_probe_refusal_names_knob "$plog/ok.log"; exit $? ) 2>/dev/null; r1=$?
  if [ "$r1" = 2 ]; then echo "  PASS shadow matrix: no trusted awk is refused by the guard with rc 2"; else echo "  FAIL shadow matrix: no trusted awk gave rc $r1, wanted 2 from the guard"; bad=1; fi
  # The FIRST trusted awk path wins: a later executable path must never run.
  printf '#!/bin/sh\n: > "%s"\nexec /usr/bin/awk "$@"\n' "$plog/first.mark" > "$ph/awk-first"; chmod +x "$ph/awk-first"
  printf '#!/bin/sh\n: > "%s"\nexec /usr/bin/awk "$@"\n' "$plog/second.mark" > "$ph/awk-second"; chmod +x "$ph/awk-second"
  rm -f "$plog/first.mark" "$plog/second.mark"
  ( LAB_PROBE_AWK_PATHS=("$ph/awk-first" "$ph/awk-second"); lab_probe_refusal_names_knob "$plog/ok.log"; exit $? ) 2>/dev/null; r1=$?
  if [ "$r1" = 0 ] && [ -e "$plog/first.mark" ] && [ ! -e "$plog/second.mark" ]; then echo "  PASS shadow matrix: the first trusted awk path wins and the second never runs"; else echo "  FAIL shadow matrix: first-path-wins rc $r1"; bad=1; fi
  # Neighbour commands the matcher must never call, shadowed by a function and by a PATH file.
  for hn in cat mktemp grep sed tr printf command declare echo env rm; do
    _cell_clean "a shell function named $hn is never called" "eval \"$hn() { : > \\\"\$canary\\\"; command $hn \\\"\\\$@\\\"; }\"" || bad=1
    _cell_clean "a $hn file earlier on PATH is never run" "PATH=\"$ph:\$PATH\"" || bad=1
  done
  # IFS and shell options the caller may carry into the call.
  local ifsv
  for ifsv in ':' '/' ' ' 'b' 'ai' $'\n' ''; do
    _cell_clean "IFS=$(printf '%q' "$ifsv")" "IFS='$ifsv'" || bad=1
  done
  _cell_clean "IFS unset" "unset IFS" || bad=1
  local opt
  for opt in 'set -f' 'set -u' 'set -e' 'set -x' 'set -o noclobber' 'set -o pipefail' 'set -o posix' 'shopt -s nullglob' 'shopt -s failglob' 'shopt -s extglob' 'shopt -s nocasematch' 'shopt -s dotglob'; do
    _cell_clean "shell option: $opt" "$opt" || bad=1
  done
  unset -f _cell _cell_clean
  # The refusal reason is reported through LAB_PROBE_WHY (the caller prints it; the guard calls no printing command).
  if ( type() { echo builtin; }; builtin() { command builtin "$@"; }; lab_probe_refusal_names_knob "$plog/ok.log"; [ -n "$LAB_PROBE_WHY" ] ); then
    echo "  PASS shadow matrix: a refusal names the shadowed command in LAB_PROBE_WHY"
  else echo "  FAIL shadow matrix: a refusal left LAB_PROBE_WHY empty"; bad=1; fi
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
