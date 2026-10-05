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
# The trailing colon pins the whole knob name. An unreadable file is refused (exit 4), never "not detected".
#
# Closed world by a fresh interpreter (#5586, #5588, #5591, #5662). The caller's shell can rebind any command name it
# runs (a function, an alias, an exported function, `enable -n`, PATH, hash), and four rounds of in-process guards each
# missed one name (command, builtin, type, return). So the match runs in a CHILD bash that inherits none of that state:
# lab_probe_refusal_names_knob runs, in a subshell switched to posix mode (POSIXLY_CORRECT=1, so the special builtin exec
# is found before any function named exec), `exec -c` of the first absolute path in LAB_PROBE_BASH_PATHS that is a
# regular executable file. exec looks up no function for a path and replaces the process, so no function, alias, trap or
# shell option of the caller survives; -c empties the environment, so no exported function (BASH_FUNC_), BASH_ENV, ENV,
# SHELLOPTS, BASHOPTS or PS4 reaches the child. The child runs awk from the first absolute path in LAB_PROBE_AWK_PATHS that
# is a regular executable file, with the program and the log passed as arguments; the program exits 10 when a refusal line
# names the knob and 11 when none does. The verdict is that exit status alone: 10 detected, 11 not detected, and EVERY other
# status (a guard refusal, a failed exec, no awk file (3), an unreadable log (4), an awk error, a killed child) is refused.
# Nothing on the verdict path calls return, printf or echo: lab_probe_verdict sets LAB_PROBE_VERDICT by assignment.
# In-process, before the exec, the guard lab_probe_cmds_proven refuses (reason in LAB_PROBE_WHY) unless each row of
# LAB_PROBE_CMDS resolves, at call time, to the kind the row names by both plain `type -t` and `builtin type -t` (rows: the
# keyword [[, and the builtins builtin, type and exec), and an absolute bash file exists. It also refuses (#5663) when
# xtrace, functrace, errtrace or extdebug is on, or any function carries the trace attribute (read with builtin declare
# -F; a failed read refuses): only those let caller code run INSIDE the guard and the subshell (a DEBUG or RETURN trap
# runs inside a function only under functrace, extdebug or the trace attribute, an ERR trap only under errtrace, and PS4
# is expanded before each command only under xtrace). An untraced trap runs only at the caller's own level.
# Covered (each is a self-test leg): a function, exported function, alias, `enable -n`, or `enable -n` with a PATH file
# for every builtin row; a lying type or builtin; lying type and builtin together with a function named exec (posix mode
# runs the builtin); a function named return, exit, local, set, shopt or any other neighbour; awk or bash by function,
# exported function, alias, PATH file, hash -p, or a function named by an absolute path; a caller-set LAB_PROBE_BASH;
# BASH_ENV, ENV, exported SHELLOPTS and BASHOPTS; a relative path in either path table; eight IFS values; twelve shell
# options; an alias for exec present while this file is sourced (the structural leg refuses the changed body); xtrace
# (also with a PS4 that assigns), functrace, errtrace, extdebug and the trace attribute, each refused; DEBUG, RETURN and
# ERR traps with none of those on, which never run inside; both #5663 reproducers.
# Not covered: a trap that runs before the guard's first check (bash runs a DEBUG trap before the command it traces, so
# a trap written against the matcher's own steps, for example one that clears LAB_PROBE_WHY and sets the status, or a
# RETURN trap that rewrites LAB_PROBE_VERDICT after lab_probe_verdict returns, is not stopped: no in-shell check can
# come first); lying type and builtin together with `enable -n exec` and a function named exec; a hostile regular
# file at an absolute bash or awk path, or a replaced guard, matcher or table (LAB_PROBE_CMDS, LAB_PROBE_BASH_PATHS,
# LAB_PROBE_AWK_PATHS); ignored signals, umask, cwd, open fds and ulimits cross exec (they can only make the child fail,
# which reads as refused); a log path that begins with "-" is passed to awk as before.
LAB_PROBE_CMDS=('[[:keyword' 'builtin:builtin' 'type:builtin' 'exec:builtin')
LAB_PROBE_BASH_PATHS=(/bin/bash /usr/bin/bash)
LAB_PROBE_AWK_PATHS=(/usr/bin/awk /bin/awk)
lab_probe_cmds_proven() {
  LAB_PROBE_BASH=""; LAB_PROBE_WHY=""
  [[ $- != *x* && ! -o functrace && ! -o errtrace && $BASHOPTS != *extdebug* ]] || LAB_PROBE_WHY="xtrace, functrace, errtrace or extdebug is on; "
  _lab_t=$(builtin declare -F) && [[ ! $_lab_t =~ -f[a-z]*t ]] || LAB_PROBE_WHY="${LAB_PROBE_WHY}a function carries the trace attribute (or declare -F failed); "
  for _lab_row in "${LAB_PROBE_CMDS[@]}"; do
    _lab_n=${_lab_row%%:*}; _lab_k=${_lab_row#*:}
    [[ $(type -t "$_lab_n") == "$_lab_k" && $(builtin type -t "$_lab_n") == "$_lab_k" ]] || LAB_PROBE_WHY="${LAB_PROBE_WHY}${_lab_n} is not the ${_lab_k} the matcher needs; "
  done
  for _lab_b in "${LAB_PROBE_BASH_PATHS[@]}"; do
    [[ -z $LAB_PROBE_BASH && $_lab_b == /* && -f $_lab_b && -x $_lab_b ]] && LAB_PROBE_BASH=$_lab_b
  done
  [[ -n $LAB_PROBE_BASH ]] || LAB_PROBE_WHY="${LAB_PROBE_WHY}no bash file in ${LAB_PROBE_BASH_PATHS[*]}; "
  [[ -z $LAB_PROBE_WHY ]]
}
lab_probe_refusal_names_knob() {
  lab_probe_cmds_proven && ( POSIXLY_CORRECT=1; exec -c "$LAB_PROBE_BASH" --noprofile --norc -c '[[ -r $1 ]] || exit 4; for a in "${@:3}"; do if [[ $a == /* && -f $a && -x $a ]]; then "$a" "$2" "$1"; exit; fi; done; exit 3' lab-probe "$1" 'index($0, "INFO") == 0 && index($0, "refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK:") { f = 1 }
       END { exit (f ? 10 : 11) }' "${LAB_PROBE_AWK_PATHS[@]}" ) 2>/dev/null
}

# #5588, #5662: the report a caller reads. Sets LAB_PROBE_VERDICT to `detected` (child status 10), `not-detected` (11) or
# `refused: <reason>` (any other status, or any reason recorded), so a matcher that could not run its child is never
# reported as "not detected" for the lowered knob. It calls no command after the matcher: only assignments and case.
lab_probe_verdict() {
  _lab_s=0; lab_probe_refusal_names_knob "$1" || _lab_s=$?
  case "$_lab_s:$LAB_PROBE_WHY" in
    10:) LAB_PROBE_VERDICT=detected ;;
    11:) LAB_PROBE_VERDICT=not-detected ;;
    *) LAB_PROBE_VERDICT="refused: ${LAB_PROBE_WHY:-the probe child exited $_lab_s, which is not a verdict}" ;;
  esac
}

# lab_probe_report <verdict> <boot exit> (#5664): the probe line run.sh prints, in LAB_PROBE_LINE, and the outcome: true
# only for detected. not-detected and every refused verdict return false, so run.sh reports them with no, never ok.
lab_probe_report() {
  case "$1" in
    detected) LAB_PROBE_LINE="probe mutation detected: the boot refused (exit $2) and the refusal names AI_MEMORY_REQUIRE_ROLLBACK_CHECK" ;;
    not-detected) LAB_PROBE_LINE="probe mutation inconclusive: the boot refused (exit $2) but not for the lowered rollback-check knob" ;;
    *) LAB_PROBE_LINE="probe mutation inconclusive: the probe matcher $1" ;;
  esac
  [[ $1 == detected ]]
}

# #5539, #5540, #5541, #5588: the two function bodies the structural self-test leg accepts, as `declare -f` prints them with every
# run of whitespace collapsed to one space. Closed world: a body is allowed only when it EQUALS this text, so any other
# command, redirect, substitution, second statement or awk program is refused without being named (a denylist cannot be closed).
# Changing the matcher or the guard means changing this text in the same commit.
lab_probe_expected_body() {
  local q="'"
  printf '%s' "lab_probe_refusal_names_knob () { lab_probe_cmds_proven && ( POSIXLY_CORRECT=1; exec -c \"\$LAB_PROBE_BASH\" --noprofile --norc -c ${q}[[ -r \$1 ]] || exit 4; for a in \"\${@:3}\"; do if [[ \$a == /* && -f \$a && -x \$a ]]; then \"\$a\" \"\$2\" \"\$1\"; exit; fi; done; exit 3${q} lab-probe \"\$1\" ${q}index(\$0, \"INFO\") == 0 && index(\$0, \"refuses to disable AI_MEMORY_REQUIRE_ROLLBACK_CHECK:\") { f = 1 } END { exit (f ? 10 : 11) }${q} \"\${LAB_PROBE_AWK_PATHS[@]}\" ) 2> /dev/null }"
}
lab_probe_expected_guard_body() {
  printf '%s' 'lab_probe_cmds_proven () { LAB_PROBE_BASH=""; LAB_PROBE_WHY=""; [[ $- != *x* && ! -o functrace && ! -o errtrace && $BASHOPTS != *extdebug* ]] || LAB_PROBE_WHY="xtrace, functrace, errtrace or extdebug is on; "; _lab_t=$(builtin declare -F) && [[ ! $_lab_t =~ -f[a-z]*t ]] || LAB_PROBE_WHY="${LAB_PROBE_WHY}a function carries the trace attribute (or declare -F failed); "; for _lab_row in "${LAB_PROBE_CMDS[@]}"; do _lab_n=${_lab_row%%:*}; _lab_k=${_lab_row#*:}; [[ $(type -t "$_lab_n") == "$_lab_k" && $(builtin type -t "$_lab_n") == "$_lab_k" ]] || LAB_PROBE_WHY="${LAB_PROBE_WHY}${_lab_n} is not the ${_lab_k} the matcher needs; "; done; for _lab_b in "${LAB_PROBE_BASH_PATHS[@]}"; do [[ -z $LAB_PROBE_BASH && $_lab_b == /* && -f $_lab_b && -x $_lab_b ]] && LAB_PROBE_BASH=$_lab_b; done; [[ -n $LAB_PROBE_BASH ]] || LAB_PROBE_WHY="${LAB_PROBE_WHY}no bash file in ${LAB_PROBE_BASH_PATHS[*]}; "; [[ -z $LAB_PROBE_WHY ]] }'
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
# 191 legs. Five mutate the lab posture arrays in a subshell and the check must go red: a weakened
# value (plain, boolean and const-valued), a dropped name, a SET knob moved to UNSET. The other 186
# leave the arrays alone (#5262): the control (must pass), three const-shadow legs (a duplicate
# const in a scratch src tree), eight probe-matcher legs (lab_probe_refusal_names_knob against generated logs, each
# checking the exact child status: 10, 11, or 4 for an unreadable log, #5662), three structural legs (the matcher body
# and the guard body each equal the one allowed text, #5539 and #5588, and the command and path tables equal their
# literals), a globbing-and-IFS leg, a source-time alias leg, a mutant-builder control, thirty-four closed-world matcher
# legs (a mutated body must be refused: twenty-one spill spellings (cp twice, dd, install, sort -o, tee, a stderr
# redirect to a near name or to stdout's target, process substitution, here-string, here-document, pipe, |&, coproc,
# command substitution, extra statement, function call, eval, mktemp, exec redirect, awk writing a file), a changed awk
# program, ten child spellings (guard dropped or not chained, bash by bare name, no exec, exec without -c, no posix
# mode, awk exits 0 or 1, awk by bare name, a relative awk path accepted, no readability check) and two extra-text
# spellings (#5587)), twelve closed-world guard-body mutants (#5588, #5662, #5663), six probe-verdict legs (the two
# verdicts, a shadowed builtin, every non-verdict status, a recorded reason over status 10, the #5662 return reproducer,
# a DEBUG trap under functrace forcing status 10, #5663), one hundred and five shadow-matrix legs (#5588: the control, one cell per table row per route (function, exported function,
# alias, enable -n, enable -n with a PATH file, a lying function for builtin and type), the keyword row, lying type and
# builtin with a function named exec, ten awk and bash cells (bare-name routes, absolute-path functions, caller-set
# LAB_PROBE_BASH, relative path), four environment cells, three missing-file cells, two first-path-wins cells, sixteen
# neighbour commands by function and by PATH file, eight IFS values, eleven shell options, thirteen trace-route cells
# (#5663: xtrace, xtrace with an assigning PS4, functrace, errtrace, extdebug, the trace attribute, enable -n declare, a
# function named declare, reproducer a, and DEBUG, RETURN and ERR traps with no trace option), reproducer b, and the
# LAB_PROBE_WHY reason), four probe-report legs (#5664: detected is ok, not-detected, refused and empty are no), a
# run.sh pin and four run.sh branch legs (#5664: run.sh's own probe-verdict lines run with stub ok and no reach ok,
# not-detected, and refused for a missing awk and a shadowed exec), a run.sh pin leg (run.sh turns on no trace route,
# #5663), and one layout leg (this comment sits
# directly on the function).
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
  # #5662: the matcher's status is the child's: 10 detected, 11 not detected, any other status refused.
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
  _det() {  # <label> <log> <wanted status> [shell option]
    ( ${4:+set -o $4}; lab_probe_refusal_names_knob "$2" ); rc=$?
    if [ "$rc" -eq "$3" ]; then echo "  PASS probe matcher: $1 (status $rc)"; return 0; fi
    echo "  FAIL probe matcher: $1: status $rc, wanted $3"; return 1
  }
  _det "a refusal naming the knob is detected" "$plog/ok.log" 10 || bad=1
  _det "a refusal for a longer knob name is not counted" "$plog/other-knob.log" 11 || bad=1
  _det "an INFO pin line is not counted" "$plog/info-only.log" 11 || bad=1
  _det "an INFO pin line with a timestamp prefix is not counted" "$plog/info-prefixed.log" 11 || bad=1
  _det "a refusal after an INFO line naming the knob is detected" "$plog/info-then-refusal.log" 10 || bad=1
  _det "a refusal followed by an INFO line naming the knob is detected" "$plog/refusal-then-info.log" 10 || bad=1
  _det "detection in a large log survives pipefail" "$plog/big.log" 10 pipefail || bad=1
  _det "an unreadable log is refused by the child (exit 4), never not-detected" "$plog/missing.log" 4 || bad=1
  unset -f _det
  # #5197, #5259, #5519, #5539, #5588, #5662: the matcher is the guard call, then ONE exec of a fresh child bash in a posix-mode
  # subshell, with one stderr redirect to /dev/null. The leg is an allowlist: the normalized body must equal
  # lab_probe_expected_body. A here-string, here-document, pipe, process substitution, temp file (mktemp, cp, dd, install,
  # sort -o, tee, an exec or output redirect) and any other extra command are refused because they are not that one
  # statement. The guard body is pinned the same way.
  if lab_probe_body_allowed "$(declare -f lab_probe_refusal_names_knob)"; then
    echo "  PASS probe matcher: the body is exactly the guard call plus the one exec of a fresh child bash (its program, the awk program, \"\$1\", one 2> /dev/null)"
  else
    echo "  FAIL probe matcher: the body is not exactly the guard call plus the one exec of a fresh child bash"; bad=1
  fi
  if lab_probe_body_allowed "$(declare -f lab_probe_cmds_proven)" lab_probe_expected_guard_body; then
    echo "  PASS probe matcher: the guard body is exactly the allowed table walk (type and builtin type per row, absolute bash file)"
  else
    echo "  FAIL probe matcher: the guard body is not exactly the allowed table walk"; bad=1
  fi
  # #5588: ONE table. These rows are the whole inventory of commands the guard and the matcher run in the caller's shell; a
  # row removed from LAB_PROBE_CMDS would silently drop its legs from the loop below, so the tables are compared to the literals.
  if [ "${LAB_PROBE_CMDS[*]}" = "[[:keyword builtin:builtin type:builtin exec:builtin" ] && [ "${LAB_PROBE_BASH_PATHS[*]}" = "/bin/bash /usr/bin/bash" ] && [ "${LAB_PROBE_AWK_PATHS[*]}" = "/usr/bin/awk /bin/awk" ]; then
    echo "  PASS probe matcher: the command table is exactly [[ (keyword), builtin, type, exec (builtins), the bash paths /bin/bash /usr/bin/bash and the awk paths /usr/bin/awk /bin/awk"
  else
    echo "  FAIL probe matcher: the command table, the bash paths or the awk paths changed"; bad=1
  fi
  # #5539: the comparison must not depend on the caller's globbing or IFS: a one-character file name would expand the
  # standalone ? of the awk program, and a changed IFS would split the words differently.
  : > "$plog/x"
  if ( cd "$plog" && IFS=: && lab_probe_body_allowed "$(declare -f lab_probe_refusal_names_knob)" ); then
    echo "  PASS probe matcher: the allowlist compare ignores a one-character file name and a changed IFS"
  else
    echo "  FAIL probe matcher: the allowlist compare depends on globbing or IFS"; bad=1
  fi
  # #5662: an alias present while the file is sourced is expanded into the parsed body; the structural compare refuses it.
  if "$BASH" -c 'shopt -s expand_aliases; alias exec="exec /bin/true"; . "$1"; lab_probe_body_allowed "$(declare -f lab_probe_refusal_names_knob)"' _ "${BASH_SOURCE[0]}" 2>/dev/null; then
    echo "  FAIL probe matcher: an alias for exec defined while the file is sourced is accepted by the structural compare"; bad=1
  else
    echo "  PASS probe matcher: an alias for exec defined while the file is sourced is refused by the structural compare"
  fi
  # #5539, #5540, #5541, #5662: each spelling below is a way to read the log other than that statement, or a way to let the
  # caller's shell reach the match; every one must be refused.
  local exp head core
  exp="$(lab_probe_expected_body)"; head="lab_probe_refusal_names_knob () { "
  core="${exp#"$head"}"; core="${core% \}}"
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
  _refuse "redirects stderr to /dev/null.spill (M5)" "${head}${core% 2> /dev/null} 2> /dev/null.spill }" || bad=1
  local psub='<(cat "$1")'
  _refuse "reads the log through process substitution (M7)" "${head}${core/lab-probe \"\$1\"/lab-probe $psub} }" || bad=1
  _refuse "copies the log with tee into \$TEMP" "${head}"'tee "$TEMP/lab-probe.$$" < "$1" ; '"${core} }" || bad=1
  _refuse "copies the log with install into \$TEMP" "${head}"'install -m 600 "$1" "$TEMP/lab-probe.$$" ; '"${core} }" || bad=1
  _refuse "writes a sorted copy with sort -o" "${head}"'sort -o "$HOME/lab-probe.$$" "$1" ; '"${core} }" || bad=1
  _refuse "opens an exec redirect to a file" "${head}"'exec 3> /tmp/lab-probe.$$ ; '"${core} }" || bad=1
  _refuse "reads the log through a here-string" "${head}${core% 2> /dev/null}"' <<< "$(cat "$1")" 2> /dev/null }' || bad=1
  _refuse "reads the log through a here-document" "${head}${core% 2> /dev/null}"' <<EOF $(cat "$1") EOF 2> /dev/null }' || bad=1
  _refuse "pipes the log into the child" "${head}"'cat "$1" | '"${core} }" || bad=1
  _refuse "pipes with |& into the child" "${head}"'cat "$1" |& '"${core} }" || bad=1
  _refuse "starts a coproc" "${head}"'coproc cat "$1" ; '"${core} }" || bad=1
  _refuse "captures the log with a command substitution" "${head}"'x="$(cat "$1")" ; '"${core} }" || bad=1
  _refuse "runs a second statement after a semicolon" "${head}${core} ; true }" || bad=1
  _refuse "calls a helper function" "${head}"'lab_helper "$1" ; '"${core} }" || bad=1
  _refuse "evals a copy command" "${head}"'eval "cp $1 /dev/shm/lab-probe.$$" ; '"${core} }" || bad=1
  _refuse "makes a temp file with mktemp" "${head}"'t=$(mktemp) ; cp "$1" "$t" ; '"${core} }" || bad=1
  _refuse "duplicates stderr instead of discarding it" "${head}${core% 2> /dev/null} 2>&1 > /dev/null }" || bad=1
  _refuse "has awk write a file from its own program" "${head}${core/\{ f = 1 \}/\{ f = 1; print \$0 > \"/dev/shm/lab-probe\" \}} }" || bad=1
  _refuse "changes the awk program (the INFO skip anchored)" "${head}${core/index(\$0, \"INFO\") == 0/\$0 !~ /^INFO/} }" || bad=1
  _refuse "drops the guard call" "${head}${core#lab_probe_cmds_proven && } }" || bad=1
  _refuse "runs the child even when the guard refuses" "${head}${core/lab_probe_cmds_proven &&/lab_probe_cmds_proven ;} }" || bad=1
  _refuse "starts the child by the bare name bash (PATH, hash and functions decide)" "${head}${core/exec -c \"\$LAB_PROBE_BASH\"/exec -c bash} }" || bad=1
  _refuse "runs the child bash without exec (a function named by its path would run)" "${head}${core/exec -c /} }" || bad=1
  _refuse "keeps the caller's environment (exec without -c)" "${head}${core/exec -c/exec} }" || bad=1
  _refuse "leaves posix mode off (a function named exec would win)" "${head}${core/POSIXLY_CORRECT=1; /} }" || bad=1
  _refuse "has awk exit 0 or 1 (a failing child would read as a verdict)" "${head}${core/f ? 10 : 11/f ? 0 : 1} }" || bad=1
  _refuse "has the child run awk by bare name" "${head}${core/\"\$a\" \"\$2\" \"\$1\"/awk \"\$2\" \"\$1\"} }" || bad=1
  _refuse "has the child accept a relative awk path" "${head}${core/\$a == \/\* \&\& /} }" || bad=1
  _refuse "has the child read an unreadable log as not detected" "${head}${core/\[\[ -r \$1 \]\] || exit 4; /} }" || bad=1
  # #5588, #5662: mutants of the guard body, refused by the same equality (the behavioural legs below kill them as well).
  local gexp; gexp="$(lab_probe_expected_guard_body)"
  _refuse_guard() {  # <spelling> <mutated guard body>
    if lab_probe_body_allowed "$2" lab_probe_expected_guard_body; then echo "  FAIL probe matcher: a guard that $1 is accepted"; return 1
    else echo "  PASS probe matcher: a guard that $1 is refused"; fi
  }
  _refuse_guard "probes only with plain type" "${gexp/ && \$(builtin type -t \"\$_lab_n\") == \"\$_lab_k\"/}" || bad=1
  _refuse_guard "probes only with builtin type" "${gexp/\$(type -t \"\$_lab_n\") == \"\$_lab_k\" && /}" || bad=1
  _refuse_guard "accepts a row when either probe agrees" "${gexp/\"\$_lab_k\" && /\"\$_lab_k\" || }" || bad=1
  _refuse_guard "drops the regular-file test on the bash path" "${gexp/ -f \$_lab_b \&\&/}" || bad=1
  _refuse_guard "drops the executable test on the bash path" "${gexp/ \&\& -x \$_lab_b/}" || bad=1
  _refuse_guard "accepts a relative bash path" "${gexp/ \$_lab_b == \/\* \&\&/}" || bad=1
  _refuse_guard "lets the last bash path win" "${gexp/-z \$LAB_PROBE_BASH \&\& /}" || bad=1
  _refuse_guard "keeps a caller-set LAB_PROBE_BASH" "${gexp/LAB_PROBE_BASH=\"\"; /}" || bad=1
  _refuse_guard "keeps a caller-set LAB_PROBE_WHY" "${gexp/ LAB_PROBE_WHY=\"\";/}" || bad=1
  _refuse_guard "drops the xtrace, functrace, errtrace and extdebug check (#5663)" "${gexp/\$- != \*x\* \&\& /}" || bad=1
  _refuse_guard "drops the trace-attribute check (#5663)" "${gexp/ \&\& \[\[ ! \$_lab_t =~ -f\[a-z\]\*t \]\]/}" || bad=1
  _refuse_guard "ignores a failed declare -F (#5663)" "${gexp/_lab_t=\$(builtin declare -F) \&\& /_lab_t=\$(builtin declare -F); }" || bad=1
  unset -f _refuse_guard
  # #5587: lab_probe_body_allowed is equality, not a substring, prefix or suffix compare.
  _refuse "has extra text after the allowed body (kills a prefix or substring compare)" "${exp} ; cp \"\$1\" /dev/shm/lab-probe" || bad=1
  _refuse "has extra text before the allowed body (kills a suffix or substring compare)" "cp \"\$1\" /dev/shm/lab-probe ; ${exp}" || bad=1
  unset -f _refuse
  : > "$plog/no.log"
  # #5588, #5662: lab_probe_verdict, the report run.sh reads, sets LAB_PROBE_VERDICT to detected, not-detected, or refused with
  # the reason. Only status 10 and 11 with no reason recorded are verdicts; every other status reads as refused.
  v1="$(lab_probe_verdict "$plog/ok.log"; printf '%s' "$LAB_PROBE_VERDICT")"; v2="$(lab_probe_verdict "$plog/no.log"; printf '%s' "$LAB_PROBE_VERDICT")"
  if [ "$v1" = detected ] && [ "$v2" = not-detected ]; then
    echo "  PASS probe verdict: detected for a refusal line, not-detected for none"
  else echo "  FAIL probe verdict: got [$v1] and [$v2]"; bad=1; fi
  v3="$( builtin() { command builtin "$@"; }; lab_probe_verdict "$plog/ok.log"; command printf '%s' "$LAB_PROBE_VERDICT" )"
  case "$v3" in "refused: builtin is not the builtin the matcher needs; "*) vok=1 ;; *) vok=0 ;; esac
  if [ "$vok" -eq 1 ]; then
    echo "  PASS probe verdict: a shadowed builtin reports refused with the reason, never not-detected"
  else echo "  FAIL probe verdict: a shadowed builtin gave [$v3]"; bad=1; fi
  vok=1
  for v4 in 0 1 2 3 4 9 12 126 127 137; do
    v3="$( lab_probe_refusal_names_knob() { LAB_PROBE_WHY=""; return "$v4"; }; LAB_PROBE_VERDICT=stale; lab_probe_verdict "$plog/ok.log"; printf '%s' "$LAB_PROBE_VERDICT" )"
    [ "$v3" = "refused: the probe child exited $v4, which is not a verdict" ] || { echo "  FAIL probe verdict: status $v4 gave [$v3]"; vok=0; }
  done
  if [ "$vok" -eq 1 ]; then echo "  PASS probe verdict: every status other than 10 and 11 (0 1 2 3 4 9 12 126 127 137) reads as refused"; else bad=1; fi
  v3="$( lab_probe_refusal_names_knob() { LAB_PROBE_WHY="a recorded reason; "; return 10; }; lab_probe_verdict "$plog/ok.log"; printf '%s' "$LAB_PROBE_VERDICT" )"
  if [ "$v3" = "refused: a recorded reason; " ]; then echo "  PASS probe verdict: a recorded reason wins over a child status of 10"
  else echo "  FAIL probe verdict: a recorded reason with status 10 gave [$v3]"; bad=1; fi
  # #5662: the reported reproducer. One function named return (no second function) used to make the matcher run awk after the
  # guard refused, reporting not-detected for a log that holds the refusal line. No return is called on the verdict path now.
  v1="$( return() { LAB_PROBE_AWK=/bin/false; }; lab_probe_verdict "$plog/ok.log"; command printf '%s' "$LAB_PROBE_VERDICT" )"
  v2="$( return() { LAB_PROBE_AWK=/usr/bin/awk; }; lab_probe_verdict "$plog/no.log"; command printf '%s' "$LAB_PROBE_VERDICT" )"
  if [ "$v1" = detected ] && [ "$v2" = not-detected ]; then echo "  PASS probe verdict: a function named return changes no verdict (#5662)"
  else echo "  FAIL probe verdict: a function named return gave [$v1] and [$v2] (#5662)"; bad=1; fi
  # #5588: the shadow matrix. One loop over the SAME table the guard walks. Each cell shadows one command by one route in a
  # fresh subshell (or child bash, for an exported function) and runs the matcher on a log it must detect and on one it must not.
  # "refused" means a status other than 10 and 11 on both (the matcher did not produce a verdict). "unchanged" means 10 and 11.
  # No cell may report a detection for the log without a refusal line, and no hostile command may ever run.
  local canary="$plog/canary" ph="$plog/hostile-bin" self="${BASH_SOURCE[0]}" r1 r2
  mkdir -p "$ph"
  local hn
  for hn in awk bash cat mktemp grep sed tr printf command declare echo env rm builtin type return exec exit local set shopt '['; do
    printf '#!/bin/sh\n: > "%s"\nexit 0\n' "$canary" > "$ph/$hn"; chmod +x "$ph/$hn"
  done
  printf ': > "%s"\n' "$canary" > "$ph/bashenv"
  printf '#!/bin/sh\n: > "%s"\nexit 10\n' "$canary" > "$plog/awk-rel"; chmod +x "$plog/awk-rel"
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
      [ "$r1" = 10 ] && [ "$r2" = 11 ] && got=ok || got=bad
    else
      case "$r1:$r2" in 10:*|11:*|*:10|*:11) got=bad ;; *) got=ok ;; esac
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
  # #5662: two coordinated lying probes (type and builtin answer each row's kind) plus a function named exec: posix mode finds the
  # special builtin exec before the function, so the function never runs and the child gives the true verdict.
  _cell_clean "lying type and builtin plus a function named exec (posix mode runs the builtin exec)" "type() { case \${2-} in '[[') echo keyword ;; *) echo builtin ;; esac; }; builtin() { case \${3-} in '[[') echo keyword ;; *) echo builtin ;; esac; }; exec() { : > \"\$canary\"; return 10; }" || bad=1
  # awk and bash run in the child by absolute path and are never looked up by name: every bare-name route is unchanged and never runs.
  _cell_clean "a shell function named awk" "awk() { : > \"\$canary\"; command awk \"\$@\"; }" || bad=1
  _cell_clean "a shell function named awk (exported to a child bash)" "awk() { : > \"\$canary\"; command awk \"\$@\"; }; export -f awk" child || bad=1
  _cell_clean "an alias named awk (expand_aliases on) to an existing script that writes the canary" "shopt -s expand_aliases; alias awk='$ph/awk'" || bad=1
  _cell_clean "an awk file and a bash file earlier on PATH" "PATH=\"$ph:\$PATH\"" || bad=1
  _cell_clean "hash -p pointing awk and bash at hostile files" "hash -p $ph/awk awk; hash -p $ph/bash bash" || bad=1
  _cell_clean "a function named by the first absolute awk path (the child never sees it)" "function ${LAB_PROBE_AWK_PATHS[0]} { : > \"\$canary\"; }" || bad=1
  _cell_clean "functions named by every absolute awk path (the child never sees them)" "function ${LAB_PROBE_AWK_PATHS[0]} { : > \"\$canary\"; }; function ${LAB_PROBE_AWK_PATHS[1]} { : > \"\$canary\"; }" || bad=1
  _cell_clean "functions named by every absolute bash path (exec looks up no function)" "function ${LAB_PROBE_BASH_PATHS[0]} { : > \"\$canary\"; return 10; }; function ${LAB_PROBE_BASH_PATHS[1]} { : > \"\$canary\"; return 10; }" || bad=1
  _cell_clean "a caller-set LAB_PROBE_BASH pointing at a hostile file is reset by the guard" "LAB_PROBE_BASH=$ph/bash" || bad=1
  _cell_clean "a relative awk path in the table is never run (the next absolute path is used)" "cd \"$plog\"; LAB_PROBE_AWK_PATHS=(awk-rel \"\${LAB_PROBE_AWK_PATHS[@]}\")" || bad=1
  # The child's environment is empty (exec -c): nothing the caller exports reaches it.
  _cell_clean "BASH_ENV naming a script that writes the canary never reaches the child" "export BASH_ENV=$ph/bashenv" || bad=1
  _cell_clean "ENV naming a script that writes the canary never reaches the child" "export ENV=$ph/bashenv" || bad=1
  _cell_clean "an exported function named exit (used only inside the child) never reaches the child" "exit() { : > \"\$canary\"; builtin exit 10; }; export -f exit" || bad=1
  _cell_clean "exported SHELLOPTS and BASHOPTS never reach the child" "set -o noclobber; shopt -s nocasematch; export SHELLOPTS BASHOPTS" || bad=1
  _cell "no absolute awk path is an executable file" refused "LAB_PROBE_AWK_PATHS=(/nonexistent/awk $plog)" || bad=1
  # The refusal for "no awk file" comes from the child (exit 3, no awk run), and "no bash file" from the guard with its reason.
  ( LAB_PROBE_AWK_PATHS=(/nonexistent/awk); lab_probe_refusal_names_knob "$plog/ok.log"; exit $? ) 2>/dev/null; r1=$?
  if [ "$r1" = 3 ]; then echo "  PASS shadow matrix: no awk file is refused by the child with exit 3"; else echo "  FAIL shadow matrix: no awk file gave rc $r1, wanted 3 from the child"; bad=1; fi
  v1="$( LAB_PROBE_BASH_PATHS=(bash /nonexistent/bash); lab_probe_verdict "$plog/ok.log"; printf '%s' "$LAB_PROBE_VERDICT" )"
  if [ "$v1" = "refused: no bash file in bash /nonexistent/bash; " ]; then echo "  PASS shadow matrix: no absolute bash file is refused by the guard with its reason"; else echo "  FAIL shadow matrix: no bash file gave [$v1]"; bad=1; fi
  # The FIRST usable awk path and the FIRST usable bash path win: a later executable path must never run.
  printf '#!/bin/sh\n: > "%s"\nexec /usr/bin/awk "$@"\n' "$plog/first.mark" > "$ph/awk-first"; chmod +x "$ph/awk-first"
  printf '#!/bin/sh\n: > "%s"\nexec /usr/bin/awk "$@"\n' "$plog/second.mark" > "$ph/awk-second"; chmod +x "$ph/awk-second"
  rm -f "$plog/first.mark" "$plog/second.mark"
  ( LAB_PROBE_AWK_PATHS=("$ph/awk-first" "$ph/awk-second"); lab_probe_refusal_names_knob "$plog/ok.log"; exit $? ) 2>/dev/null; r1=$?
  if [ "$r1" = 10 ] && [ -e "$plog/first.mark" ] && [ ! -e "$plog/second.mark" ]; then echo "  PASS shadow matrix: the first awk path wins and the second never runs"; else echo "  FAIL shadow matrix: awk first-path-wins rc $r1"; bad=1; fi
  printf '#!/bin/sh\n: > "%s"\nexec %s "$@"\n' "$plog/first.mark" "${LAB_PROBE_BASH_PATHS[0]}" > "$ph/bash-first"; chmod +x "$ph/bash-first"
  printf '#!/bin/sh\n: > "%s"\nexec %s "$@"\n' "$plog/second.mark" "${LAB_PROBE_BASH_PATHS[0]}" > "$ph/bash-second"; chmod +x "$ph/bash-second"
  rm -f "$plog/first.mark" "$plog/second.mark"
  ( LAB_PROBE_BASH_PATHS=("$ph/bash-first" "$ph/bash-second"); lab_probe_refusal_names_knob "$plog/ok.log"; exit $? ) 2>/dev/null; r1=$?
  if [ "$r1" = 10 ] && [ -e "$plog/first.mark" ] && [ ! -e "$plog/second.mark" ]; then echo "  PASS shadow matrix: the first bash path wins and the second never runs"; else echo "  FAIL shadow matrix: bash first-path-wins rc $r1"; bad=1; fi
  # Neighbour commands the matcher must never call in the caller's shell, shadowed by a function and by a PATH file.
  for hn in cat mktemp grep sed tr printf command declare echo env rm return exit local set shopt; do
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
  for opt in 'set -f' 'set -u' 'set -e' 'set -o noclobber' 'set -o pipefail' 'set -o posix' 'shopt -s nullglob' 'shopt -s failglob' 'shopt -s extglob' 'shopt -s nocasematch' 'shopt -s dotglob'; do
    _cell_clean "shell option: $opt" "$opt" || bad=1
  done
  # #5663: caller code that runs INSIDE the guard and the subshell. A DEBUG or RETURN trap runs inside a function only under
  # functrace, extdebug or the function's trace attribute, an ERR trap only under errtrace, and PS4 is expanded before every
  # command only under xtrace; each of those is refused. An untraced trap runs only at the caller's own level, never inside.
  _cell "xtrace (set -x)" refused 'set -x' || bad=1
  _cell "xtrace with a PS4 that assigns the matcher's status" refused 'PS4="\$((_lab_s=10))"; set -x' || bad=1
  _cell "functrace (set -T)" refused 'set -T' || bad=1
  _cell "errtrace (set -E)" refused 'set -E' || bad=1
  _cell "extdebug" refused 'shopt -s extdebug' || bad=1
  _cell "the trace attribute on the guard and the matcher with a DEBUG trap" refused 'declare -ft lab_probe_cmds_proven lab_probe_refusal_names_knob; trap ": > \"\$canary\"" DEBUG' || bad=1
  _cell "the trace attribute on an unrelated function" refused 'f() { :; }; declare -ft f' || bad=1
  _cell "declare disabled with enable -n (the trace check cannot run)" refused 'enable -n declare' || bad=1
  _cell_clean "a shell function named declare (builtin declare is called)" 'declare() { : > "$canary"; }' || bad=1
  rm -f "$canary"
  if _cell "functrace with a DEBUG trap that defines a function at the absolute awk path (#5663 reproducer a)" refused "set -T; trap 'function ${LAB_PROBE_AWK_PATHS[0]} { : > \"\$canary\"; }' DEBUG" && [ ! -e "$canary" ]; then :; else
    echo "  FAIL shadow matrix: reproducer a ran the hostile function"; bad=1; fi
  _cell_clean "a DEBUG trap with no functrace never runs inside the matcher" 'trap "[[ \${FUNCNAME[0]-} == lab_probe_* ]] && : > \"\$canary\"" DEBUG' || bad=1
  _cell_clean "a RETURN trap with no functrace never runs inside the matcher" 'trap ": > \"\$canary\"" RETURN' || bad=1
  _cell_clean "an ERR trap with no errtrace never runs inside the matcher" 'trap "[[ \${FUNCNAME[0]-} == lab_probe_* ]] && : > \"\$canary\"" ERR' || bad=1
  unset -f _cell _cell_clean
  # #5663 reproducer b: extdebug, a forwarding builtin and a DEBUG trap that skips every LAB_PROBE_WHY assignment. The trap
  # can drop the reasons, but the child still gives the true verdict: ok.log is detected or refused, no.log not-detected or refused.
  # set +u as in the reported reproducer: under run.sh's set -u the skipped reset leaves LAB_PROBE_WHY unset and the shell exits.
  v1="$( set +u; shopt -s extdebug; builtin() { command builtin "$@"; }; trap '[[ $BASH_COMMAND != LAB_PROBE_WHY=* ]]' DEBUG; lab_probe_verdict "$plog/ok.log"; trap - DEBUG; shopt -u extdebug; unset -f builtin; printf '%s' "$LAB_PROBE_VERDICT" )"
  v2="$( set +u; shopt -s extdebug; builtin() { command builtin "$@"; }; trap '[[ $BASH_COMMAND != LAB_PROBE_WHY=* ]]' DEBUG; lab_probe_verdict "$plog/no.log"; trap - DEBUG; shopt -u extdebug; unset -f builtin; printf '%s' "$LAB_PROBE_VERDICT" )"
  case "$v1:$v2" in
    detected:not-detected|detected:refused*|refused*:not-detected|refused*:refused*) echo "  PASS shadow matrix: a DEBUG trap that skips the refusal reasons cannot invert the verdict (#5663 reproducer b: [$v1] [$v2])" ;;
    *) echo "  FAIL shadow matrix: reproducer b gave [$v1] [$v2]"; bad=1 ;;
  esac
  # #5663: functrace with a DEBUG trap that forces the child status to 10 just before the verdict is read. Without the option
  # refusal this reported detected for a log with no refusal line; the recorded reason now makes it refused.
  v1="$( set -T; trap '[[ $BASH_COMMAND == case* ]] && _lab_s=10' DEBUG; lab_probe_verdict "$plog/no.log"; trap - DEBUG; set +T; printf '%s' "$LAB_PROBE_VERDICT" )"
  case "$v1" in
    "refused: xtrace, functrace, errtrace or extdebug is on; "*) echo "  PASS probe verdict: a DEBUG trap under functrace that forces status 10 reads as refused, never detected (#5663)" ;;
    *) echo "  FAIL probe verdict: a DEBUG trap under functrace that forces status 10 gave [$v1] (#5663)"; bad=1 ;;
  esac
  # #5664: lab_probe_report, the outcome run.sh prints. Only detected is ok; not-detected, every refused verdict and any
  # other text return false with the line naming why.
  local rl
  rl="$( lab_probe_report detected 75 && printf 'ok|%s' "$LAB_PROBE_LINE" || printf 'no|%s' "$LAB_PROBE_LINE" )"
  if [ "$rl" = "ok|probe mutation detected: the boot refused (exit 75) and the refusal names AI_MEMORY_REQUIRE_ROLLBACK_CHECK" ]; then
    echo "  PASS probe report: detected is ok with the boot exit and the knob named"
  else echo "  FAIL probe report: detected gave [$rl]"; bad=1; fi
  rl="$( lab_probe_report not-detected 75 && printf 'ok|%s' "$LAB_PROBE_LINE" || printf 'no|%s' "$LAB_PROBE_LINE" )"
  if [ "$rl" = "no|probe mutation inconclusive: the boot refused (exit 75) but not for the lowered rollback-check knob" ]; then
    echo "  PASS probe report: not-detected is no, inconclusive"
  else echo "  FAIL probe report: not-detected gave [$rl]"; bad=1; fi
  rl="$( lab_probe_report 'refused: exec is not the builtin the matcher needs; ' 75 && printf 'ok|%s' "$LAB_PROBE_LINE" || printf 'no|%s' "$LAB_PROBE_LINE" )"
  if [ "$rl" = "no|probe mutation inconclusive: the probe matcher refused: exec is not the builtin the matcher needs; " ]; then
    echo "  PASS probe report: a refused verdict is no and names the reason, never ok"
  else echo "  FAIL probe report: a refused verdict gave [$rl]"; bad=1; fi
  rl="$( lab_probe_report '' 75 && printf 'ok|%s' "$LAB_PROBE_LINE" || printf 'no|%s' "$LAB_PROBE_LINE" )"
  if [ "${rl%%|*}" = no ]; then echo "  PASS probe report: an empty verdict is no"
  else echo "  FAIL probe report: an empty verdict gave [$rl]"; bad=1; fi
  # #5664: run.sh's own probe-verdict lines, taken from run.sh and run with stub ok and no, reach each branch: a refusal
  # line gives ok, a log with none gives no, and a refused matcher (no awk file, child exit 3) gives no naming the reason.
  local rb
  rb="$(grep -E '^[[:space:]]*(lab_probe_verdict "\$PROBE"$|if lab_probe_report "\$LAB_PROBE_VERDICT" "\$PROBE_RC"; then )' "$root/infra/federation-lab/run.sh")"
  if [ "$(printf '%s\n' "$rb" | grep -c .)" = 2 ] && [ "$(grep -cF 'if lab_probe_report "$LAB_PROBE_VERDICT" "$PROBE_RC"; then ok "$LAB_PROBE_LINE"; else no "$LAB_PROBE_LINE"; fi' "$root/infra/federation-lab/run.sh")" = 1 ]; then
    echo "  PASS run.sh pin: run.sh calls lab_probe_verdict and reports through lab_probe_report, ok only when it returns true"
  else echo "  FAIL run.sh pin: run.sh's probe-verdict lines changed"; bad=1; fi
  _runsh_branch() {  # <log> [setup] — runs run.sh's probe-verdict lines with stub ok and no
    ( ok() { printf 'ok|%s' "$1"; }; no() { printf 'no|%s' "$1"; }; PROBE="$1"; PROBE_RC=75; eval "${2:-:}"; eval "$rb" )
  }
  rl="$(_runsh_branch "$plog/ok.log")"
  case "$rl" in "ok|probe mutation detected: the boot refused (exit 75)"*) echo "  PASS run.sh branch: a refusal naming the knob reaches ok" ;;
    *) echo "  FAIL run.sh branch: a refusal naming the knob gave [$rl]"; bad=1 ;; esac
  rl="$(_runsh_branch "$plog/no.log")"
  case "$rl" in "no|probe mutation inconclusive: the boot refused (exit 75) but not for"*) echo "  PASS run.sh branch: a log with no refusal line reaches no" ;;
    *) echo "  FAIL run.sh branch: a log with no refusal line gave [$rl]"; bad=1 ;; esac
  rl="$(_runsh_branch "$plog/ok.log" 'LAB_PROBE_AWK_PATHS=(/nonexistent/awk)')"
  if [ "$rl" = "no|probe mutation inconclusive: the probe matcher refused: the probe child exited 3, which is not a verdict" ]; then
    echo "  PASS run.sh branch: a refused matcher reaches no and names the reason, even for a log holding the refusal line"
  else echo "  FAIL run.sh branch: a refused matcher gave [$rl]"; bad=1; fi
  rl="$(_runsh_branch "$plog/ok.log" 'exec() { return 10; }')"
  case "$rl" in "no|probe mutation inconclusive: the probe matcher refused: exec is not the builtin the matcher needs; "*) echo "  PASS run.sh branch: a shadowed exec reaches no with the guard's reason" ;;
    *) echo "  FAIL run.sh branch: a shadowed exec gave [$rl]"; bad=1 ;; esac
  unset -f _runsh_branch
  # #5663: run.sh (and the common.sh it sources) must not itself turn on xtrace, functrace, errtrace or extdebug, set a
  # DEBUG, RETURN or ERR trap, or give a function the trace attribute, or every real probe would be refused.
  if [ -r "$root/infra/federation-lab/run.sh" ] && ! grep -nE 'trap .*(DEBUG|RETURN|ERR)|set -[a-zA-Z]*[xTE]|extdebug|functrace|errtrace|xtrace|declare -[a-z]*t' "$root/infra/federation-lab/run.sh" "$root/infra/federation-lab/lib/common.sh" >/dev/null; then
    echo "  PASS run.sh pin: run.sh and lib/common.sh set no DEBUG, RETURN or ERR trap, no xtrace, functrace, errtrace or extdebug, no trace attribute"
  else echo "  FAIL run.sh pin: run.sh or lib/common.sh turns on a trace route the probe guard refuses"; bad=1; fi
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
