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
#       PREVIOUS committed content, the new pinned revision must be strictly greater
#       than the old one — so "edit, re-hash, same revision" is refused as loudly as
#       "edit, no re-hash". The previous pin is read at the base side of
#       scripts/ci-commit-range.py (--base-only); there is no default base, and an
#       undecidable or unresolvable base is a red gate, never a skip (#5604);
#   D2  a pinned revision N > 1 requires at least N-1 dated
#       `revised after miss (YYYY-MM-DD): <reason>` lines in the file — so a re-pin
#       without the bump AND the reason is refused (HARD-FAIL, never allowlistable);
#   D3  the declaration contains no placeholder (`TBD`, `TODO`, `XXX`, `<fill`) — a
#       declared target is a number, not a promise to pick one;
#   D4  every N-id cited in §6 of the adopted standard has a row in the declaration's
#       §6 N-id → issue table (§7.4 of the standard: the ids match the filed issues).
#
# BASE SOURCE (#5970; GOD ruling 2026-10-05; 5-agent vote 4d3ea1c5, decision 424172a1).
# In CI the base comes ONLY from scripts/ci-commit-range.py. Closed-world on the
# environment: every exported DECLARATION_GATE_* variable other than the three local
# overrides (DECLARATION_GATE_LOCAL_BASE, DECLARATION_GATE_LOCAL_PREVIOUS_PIN,
# DECLARATION_GATE_LOCAL_ROOT) is refused wherever it is set, even when empty; the
# local overrides are refused whenever GITHUB_ACTIONS is set (even to an empty
# string), and setting both LOCAL_BASE and LOCAL_PREVIOUS_PIN is refused. A refusal
# exits 1 and names the variable.
#
# CREATION PUSH (#5851). A push that creates a branch carries an all-zero before;
# ci-commit-range.py has no base for it, so this gate is RED on that run, never
# not-applicable and never a skip. The verdict is ADVISORY by construction: a
# required status check does not gate a branch-creation push (the branch already
# exists when the job runs), so only a repository ruleset that restricts branch
# creation can stop one.
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

ROOT="${DECLARATION_GATE_LOCAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
RANGE_HELPER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ci-commit-range.py"
DECL="${ROOT}/docs/compliance/v1.0.0-DECLARATION.md"
PIN="${ROOT}/scripts/qc-allowlists/declaration.sha256"
STD="${ROOT}/docs/compliance/MISSION-CRITICAL-CERTIFICATION-STANDARD-v1.md"

fail() { echo "::error::declaration-hash gate: $*" >&2; exit 1; }

sha_of() { sha256sum "$1" | cut -d' ' -f1; }

# refuse_overrides — the environment cannot name the D1b base in CI (#5970).
refuse_overrides() {
  local name bad=()
  while IFS= read -r name; do
    case "$name" in
      DECLARATION_GATE_LOCAL_BASE | DECLARATION_GATE_LOCAL_PREVIOUS_PIN | DECLARATION_GATE_LOCAL_ROOT)
        [ -z "${GITHUB_ACTIONS+set}" ] || bad+=("$name (a local override; GITHUB_ACTIONS is set)") ;;
      DECLARATION_GATE_*) bad+=("$name") ;;
    esac
  done < <(compgen -e)
  if [ -n "${DECLARATION_GATE_LOCAL_BASE+set}" ] && [ -n "${DECLARATION_GATE_LOCAL_PREVIOUS_PIN+set}" ]; then
    bad+=("DECLARATION_GATE_LOCAL_BASE with DECLARATION_GATE_LOCAL_PREVIOUS_PIN (two previous-pin sources)")
  fi
  [ "${#bad[@]}" -eq 0 ] || fail "refused (#5970, fail-closed): ${bad[*]} set in the gate's environment; the D1b base comes only from scripts/ci-commit-range.py"
}

run_gate() {
  refuse_overrides
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
  # D1b — the pin moved: the revision must have moved up with it. The previous pin is
  # never skipped (#5604): its base comes from scripts/ci-commit-range.py (base side
  # only); outside CI a local override may name a commit or a pin file by hand
  # (#5970); an undecidable or unresolvable base is a red gate. There is no default base.
  local prev_line="" prev_sha="" prev_rev=""
  if [ -n "${DECLARATION_GATE_LOCAL_PREVIOUS_PIN+set}" ]; then
    [ -f "$DECLARATION_GATE_LOCAL_PREVIOUS_PIN" ] || fail "DECLARATION_GATE_LOCAL_PREVIOUS_PIN names no file: $DECLARATION_GATE_LOCAL_PREVIOUS_PIN (D1b)"
    prev_line=$(grep -vE '^\s*(#|$)' "$DECLARATION_GATE_LOCAL_PREVIOUS_PIN" | tail -1 || true)
  else
    local base=""
    if [ -n "${DECLARATION_GATE_LOCAL_BASE+set}" ]; then
      base="$DECLARATION_GATE_LOCAL_BASE"
    elif [ -n "${GITHUB_EVENT_NAME:-}" ]; then
      base=$(python3 "$RANGE_HELPER" --repo "$ROOT" --base-only) \
        || fail "the base of the previous pin cannot be decided (D1b, fail-closed); the helper refusal is above"
    else
      fail "no base for the previous pin (D1b, fail-closed): run under a pull_request, merge_group or push event, or outside CI set DECLARATION_GATE_LOCAL_BASE to a commit"
    fi
    git -C "$ROOT" rev-parse --verify --quiet "${base}^{commit}" >/dev/null 2>&1 \
      || fail "the D1b base '$base' does not resolve to a commit in this checkout (fail-closed)"
    git -C "$ROOT" cat-file -e "${base}:scripts/qc-allowlists/declaration.sha256" 2>/dev/null \
      || fail "the pin file does not exist at the D1b base $base (fail-closed)"
    prev_line=$(git -C "$ROOT" show "${base}:scripts/qc-allowlists/declaration.sha256" | grep -vE '^\s*(#|$)' | tail -1 || true)
  fi
  [ -n "$prev_line" ] || fail "the previous pin carries no <sha256>  <revision> line (D1b, fail-closed)"
  prev_sha=$(echo "$prev_line" | awk '{print $1}'); prev_rev=$(echo "$prev_line" | awk '{print $2}')
  [[ "$prev_sha" =~ ^[0-9a-f]{64}$ && "$prev_rev" =~ ^[0-9]+$ ]] \
    || fail "the previous pin is malformed (D1b, fail-closed): $prev_line"
  if [ "$prev_sha" != "$pinned_sha" ] && [ "$pinned_rev" -le "$prev_rev" ]; then
    fail "the pin moved ($prev_sha -> $pinned_sha) but the revision did not (${prev_rev} -> ${pinned_rev}) (D1b): a re-pin is legal only with a 'revision:' bump and a dated 'revised after miss' line"
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
  done < <(awk '/^## 6\. Execution list/{f=1} /^## 7\./{f=0} f' "$STD" | grep -oE '\bN[0-9]+\b' | LC_ALL=C sort -u)
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
  export DECLARATION_GATE_LOCAL_PREVIOUS_PIN="$scratch/previous.pin"
  leg() { # $1 name, $2 expect (pass|fail), $3 rule tag the refusal must name (optional)
    total=$((total+1)); local out r
    if out=$(env -u GITHUB_ACTIONS DECLARATION_GATE_LOCAL_ROOT="$scratch" bash "$me" 2>&1); then r=pass; else r=fail; fi
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
  unset DECLARATION_GATE_LOCAL_PREVIOUS_PIN
  # D1b base legs (#5604): the previous pin comes from a real git base, never from a
  # skip. The scratch is its own repo: c1 = pin at revision 1; c2 = a re-pin that kept
  # revision 1 (the defect). Each refusal must come from the named cause.
  git -C "$scratch" init -q -b main
  local g=(git -C "$scratch" -c user.name=t -c user.email=t@e.invalid -c commit.gpgsign=false)
  "${g[@]}" add -A >/dev/null && "${g[@]}" commit -q -m c1
  local c1 c2 zero ab
  c1=$("${g[@]}" rev-parse HEAD)
  printf '\nsoftened\n' >> "$D"; repin 1
  "${g[@]}" add -A >/dev/null && "${g[@]}" commit -q -m c2
  c2=$("${g[@]}" rev-parse HEAD)
  zero=$(printf '0%.0s' $(seq 1 40)); ab=$(printf 'ab%.0s' $(seq 1 20))
  bleg() { # $1 name, $2 expect, $3 reason text the output must contain, rest: env assignments
    total=$((total+1)); local name="$1" want="$2" text="$3" out r; shift 3
    if out=$(env -u DECLARATION_GATE_LOCAL_PREVIOUS_PIN -u DECLARATION_GATE_LOCAL_BASE -u GITHUB_EVENT_NAME \
        -u GITHUB_EVENT_BEFORE -u PR_BASE_SHA -u PR_HEAD_SHA -u MG_BASE_SHA -u MG_HEAD_SHA -u GITHUB_ACTIONS \
        DECLARATION_GATE_LOCAL_ROOT="$scratch" "$@" bash "$me" 2>&1); then r=pass; else r=fail; fi
    if [ "$r" != "$want" ]; then echo "  FAIL $name: expected $want, got $r: $(echo "$out" | head -1 | cut -c1-140)"; return; fi
    local want_text; local -a wants=()
    [ -z "$text" ] || IFS='|' read -r -a wants <<<"$text"
    for want_text in "${wants[@]}"; do
      if ! grep -qF -- "$want_text" <<<"$out"; then echo "  FAIL $name: wrong reason, wanted '$want_text': $(echo "$out" | head -1 | cut -c1-140)"; return; fi
    done
    echo "  ok   $name (expected $want)"; ok=$((ok+1))
  }
  bleg "D1b base leg: re-pin without a bump vs a real base is red" fail "(D1b)" DECLARATION_GATE_LOCAL_BASE="$c1"
  bleg "D1b base leg: pull_request base=c1 head=c2 is red by D1b" fail "(D1b)" GITHUB_EVENT_NAME=pull_request PR_BASE_SHA="$c1" PR_HEAD_SHA="$c2"
  bleg "D1b base leg: merge_group base_sha=c1 head_sha=c2 is red by D1b" fail "(D1b)" GITHUB_EVENT_NAME=merge_group MG_BASE_SHA="$c1" MG_HEAD_SHA="$c2"
  bleg "D1b base leg: push before=c1 sha=c2 is red by D1b" fail "(D1b)" GITHUB_EVENT_NAME=push GITHUB_EVENT_BEFORE="$c1" GITHUB_SHA="$c2"
  bleg "D1b base leg: unchanged pin vs its own commit passes" pass "" DECLARATION_GATE_LOCAL_BASE="$c2"
  bleg "D1b base leg: all-zero push before is red, not skipped" fail "cannot be decided" GITHUB_EVENT_NAME=push GITHUB_EVENT_BEFORE="$zero" GITHUB_SHA="$c2"
  bleg "D1b base leg: empty push before is red, not skipped" fail "cannot be decided" GITHUB_EVENT_NAME=push GITHUB_EVENT_BEFORE="" GITHUB_SHA="$c2"
  bleg "D1b base leg: unreachable push before is red, not skipped" fail "cannot be decided" GITHUB_EVENT_NAME=push GITHUB_EVENT_BEFORE="$ab" GITHUB_SHA="$c2"
  bleg "D1b base leg: merge_group without base_sha is red, not skipped" fail "cannot be decided" GITHUB_EVENT_NAME=merge_group MG_HEAD_SHA="$c2"
  bleg "D1b base leg: unknown event is red, not skipped" fail "cannot be decided" GITHUB_EVENT_NAME=schedule
  bleg "D1b base leg: no event and no base is red (no default HEAD)" fail "no base for the previous pin"
  bleg "D1b base leg: explicit unresolvable base is red" fail "does not resolve to a commit" DECLARATION_GATE_LOCAL_BASE="$ab"
  bleg "D1b base leg: explicit all-zero base is red" fail "does not resolve to a commit" DECLARATION_GATE_LOCAL_BASE="$zero"
  printf '# only a comment\n' > "$scratch/empty.pin"; printf 'zz  1\n' > "$scratch/bad.pin"
  bleg "D1b previous-pin leg: a previous pin with no line is red" fail "carries no <sha256>" DECLARATION_GATE_LOCAL_PREVIOUS_PIN="$scratch/empty.pin"
  bleg "D1b previous-pin leg: a malformed previous pin is red" fail "previous pin is malformed" DECLARATION_GATE_LOCAL_PREVIOUS_PIN="$scratch/bad.pin"
  bleg "D1b previous-pin leg: a missing previous-pin file is red" fail "names no file" DECLARATION_GATE_LOCAL_PREVIOUS_PIN="$scratch/none.pin"
  "${g[@]}" rm -q --cached scripts/qc-allowlists/declaration.sha256 && "${g[@]}" commit -q -m c3-no-pin
  bleg "D1b base leg: pin file absent at the base is red" fail "does not exist at the D1b base" DECLARATION_GATE_LOCAL_BASE="$("${g[@]}" rev-parse HEAD)"
  # Override legs (#5970; GOD ruling 2026-10-05; 5-agent vote 4d3ea1c5, decision 424172a1):
  # every DECLARATION_GATE_* name other than the local overrides is refused wherever it is
  # set, even empty; a local override is refused whenever GITHUB_ACTIONS is set.
  local src="ci-commit-range.py"
  bleg "override leg: DECLARATION_GATE_BASE is refused" fail "DECLARATION_GATE_BASE|$src" DECLARATION_GATE_BASE="$c2"
  bleg "override leg: empty DECLARATION_GATE_BASE is refused" fail "DECLARATION_GATE_BASE|$src" DECLARATION_GATE_BASE=
  bleg "override leg: DECLARATION_GATE_PREVIOUS_PIN is refused" fail "DECLARATION_GATE_PREVIOUS_PIN|$src" DECLARATION_GATE_PREVIOUS_PIN="$scratch/previous.pin"
  bleg "override leg: DECLARATION_GATE_ROOT is refused" fail "DECLARATION_GATE_ROOT|$src" DECLARATION_GATE_ROOT="$scratch"
  bleg "override leg: an unknown DECLARATION_GATE_ name is refused" fail "DECLARATION_GATE_HEAD|$src" DECLARATION_GATE_HEAD=HEAD
  bleg "override leg: DECLARATION_GATE_BASE wins nothing under a creation push" fail "DECLARATION_GATE_BASE|$src" GITHUB_ACTIONS=true GITHUB_EVENT_NAME=push GITHUB_EVENT_BEFORE="$zero" GITHUB_SHA="$c2" DECLARATION_GATE_BASE="$c2"
  bleg "override leg: a local base under GITHUB_ACTIONS=true is refused" fail "DECLARATION_GATE_LOCAL_BASE (a local override|$src" GITHUB_ACTIONS=true DECLARATION_GATE_LOCAL_BASE="$c2"
  bleg "override leg: a local base under an empty GITHUB_ACTIONS is refused" fail "DECLARATION_GATE_LOCAL_BASE (a local override|$src" GITHUB_ACTIONS= DECLARATION_GATE_LOCAL_BASE="$c2"
  bleg "override leg: a local previous pin under GITHUB_ACTIONS=true is refused" fail "DECLARATION_GATE_LOCAL_PREVIOUS_PIN (a local override|$src" GITHUB_ACTIONS=true DECLARATION_GATE_LOCAL_PREVIOUS_PIN="$scratch/previous.pin"
  bleg "override leg: a local base with a local previous pin is refused" fail "two previous-pin sources|$src" DECLARATION_GATE_LOCAL_BASE="$c2" DECLARATION_GATE_LOCAL_PREVIOUS_PIN="$scratch/previous.pin"
  bleg "override leg: a lowercase look-alike is not an input and changes nothing" pass "" declaration_gate_base="$c1" DECLARATION_GATE_LOCAL_BASE="$c2"
  # Workflow-env runtime legs (#5970 F1, #5851): plant the variable in a copy of the real
  # workflow at job level or workflow level, resolve the env that reaches the gate step
  # with ci-commit-range.py --gate-step-env, and run the gate with exactly that env under
  # GITHUB_ACTIONS=true and a creation push (all-zero before). Every leg must be red.
  local wf="$ROOT/.github/workflows/c8-precheck.yml" mwf="$scratch/wf.yml" head
  head=$(git -C "$ROOT" rev-parse HEAD)
  wleg() { # $1 name, $2 level (none|job|workflow), $3 NAME, $4 YAML value, $5 '|'-separated texts
    total=$((total+1)); local name="$1" level="$2" var="$3" val="$4" text="$5" out r line want_text
    local -a resolved=() wants=()
    case "$level" in
      none) cp "$wf" "$mwf" ;;
      job) awk -v k="$var" -v v="$val" '{print} $0=="  declaration-hash-gate:"{print "    env:"; print "      " k ": " v}' "$wf" > "$mwf" ;;
      workflow) awk -v k="$var" -v v="$val" '$0=="jobs:"{print "env:"; print "  " k ": " v} {print}' "$wf" > "$mwf" ;;
    esac
    if ! out=$(python3 "$RANGE_HELPER" --gate-step-env declaration-hash-gate --workflow "$mwf" 2>&1); then
      echo "  FAIL $name: the step env cannot be resolved: $(echo "$out" | head -1 | cut -c1-140)"; return
    fi
    while IFS= read -r line; do
      case "$line" in *'${{'*) ;; *) resolved+=("$line") ;; esac
    done <<<"$out"
    if [ "$level" != none ] && ! printf '%s\n' "${resolved[@]}" | grep -q "^$var="; then
      echo "  FAIL $name: $var did not reach the gate step"; return
    fi
    if out=$(env -i PATH="$PATH" HOME="$HOME" GITHUB_ACTIONS=true GITHUB_EVENT_NAME=push \
        GITHUB_EVENT_BEFORE="$zero" GITHUB_SHA="$head" "${resolved[@]}" bash "$me" 2>&1); then r=pass; else r=fail; fi
    if [ "$r" != fail ]; then echo "  FAIL $name: expected a red gate, got $r: $(echo "$out" | head -1 | cut -c1-140)"; return; fi
    if grep -qE 'N[/]A|[Ss]kip' <<<"$out"; then echo "  FAIL $name: the refusal reads as not-applicable or a skip: $(echo "$out" | head -1 | cut -c1-140)"; return; fi
    IFS='|' read -r -a wants <<<"$text"
    for want_text in "${wants[@]}"; do
      if ! grep -qF -- "$want_text" <<<"$out"; then echo "  FAIL $name: wrong reason, wanted '$want_text': $(echo "$out" | head -1 | cut -c1-140)"; return; fi
    done
    ok=$((ok+1)); echo "  ok   $name (expected fail)"
  }
  wleg "workflow leg: creation push with the unmutated workflow is red (#5851)" none "" "" "cannot be decided"
  wleg "workflow leg: job-level DECLARATION_GATE_BASE reaches the gate and is refused" job DECLARATION_GATE_BASE HEAD "DECLARATION_GATE_BASE|$src"
  wleg "workflow leg: workflow-level DECLARATION_GATE_BASE reaches the gate and is refused" workflow DECLARATION_GATE_BASE HEAD "DECLARATION_GATE_BASE|$src"
  wleg "workflow leg: job-level empty DECLARATION_GATE_BASE is refused" job DECLARATION_GATE_BASE '""' "DECLARATION_GATE_BASE|$src"
  wleg "workflow leg: job-level DECLARATION_GATE_PREVIOUS_PIN is refused" job DECLARATION_GATE_PREVIOUS_PIN scripts/qc-allowlists/declaration.sha256 "DECLARATION_GATE_PREVIOUS_PIN|$src"
  wleg "workflow leg: workflow-level DECLARATION_GATE_PREVIOUS_PIN is refused" workflow DECLARATION_GATE_PREVIOUS_PIN scripts/qc-allowlists/declaration.sha256 "DECLARATION_GATE_PREVIOUS_PIN|$src"
  wleg "workflow leg: job-level DECLARATION_GATE_LOCAL_BASE is refused under CI" job DECLARATION_GATE_LOCAL_BASE HEAD "DECLARATION_GATE_LOCAL_BASE (a local override|$src"
  wleg "workflow leg: job-level DECLARATION_GATE_ROOT is refused" job DECLARATION_GATE_ROOT . "DECLARATION_GATE_ROOT|$src"
  rm -rf "$scratch"
  echo "declaration-hash gate self-test: $ok/$total"
  [ "$ok" = "$total" ] || exit 1
}

case "${1:-}" in
  --self-test) self_test ;;
  "") run_gate ;;
  *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
