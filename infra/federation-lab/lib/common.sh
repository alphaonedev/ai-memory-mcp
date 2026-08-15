# shellcheck shell=bash
# =============================================================================
# infra/federation-lab/lib/common.sh — shared plumbing for the laptop
# federation lab: logging, the PASS/FAIL ledger, prereq checks, and the
# daemon lifecycle (launch / poll / stop) used by run.sh.
# =============================================================================
# Sourced, never executed. Every path a caller hands in is expected to live
# INSIDE the lab work dir ($LAB_RUN) — this kit deliberately writes nothing
# to /tmp, so a laptop with a locked-down or noexec /tmp still runs it and a
# single `rm -rf` of one directory is a complete cleanup.
# =============================================================================

# ── logging ────────────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_OK=$'\033[32m'; C_NO=$'\033[31m'; C_HD=$'\033[1;36m'; C_DIM=$'\033[2m'; C_0=$'\033[0m'
else
  C_OK=''; C_NO=''; C_HD=''; C_DIM=''; C_0=''
fi

step()  { printf '\n%s══ %s %s\n' "$C_HD" "$*" "$C_0"; }
info()  { printf '   %sinfo%s %s\n' "$C_DIM" "$C_0" "$*"; }
warn()  { printf '   %swarn%s %s\n' "$C_NO" "$C_0" "$*"; }

# ── PASS/FAIL ledger ───────────────────────────────────────────────────────
# Every assertion goes through ok/no so the closing summary is a count the
# reader can check against the printed lines, not a claim.
LAB_PASS=0
LAB_FAIL=0
LAB_LEDGER=()

ok() { LAB_PASS=$((LAB_PASS + 1)); LAB_LEDGER+=("PASS|$1"); printf '   %sPASS%s %s\n' "$C_OK" "$C_0" "$1"; }
no() { LAB_FAIL=$((LAB_FAIL + 1)); LAB_LEDGER+=("FAIL|$1"); printf '   %sFAIL%s %s\n' "$C_NO" "$C_0" "$1"; }

# Print the ledger + the counts. Returns non-zero iff anything failed, so
# `summary || exit 1` is the whole exit-code contract.
summary() {
  step "SUMMARY"
  local row
  for row in "${LAB_LEDGER[@]}"; do
    case "$row" in
      PASS\|*) printf '   %sPASS%s %s\n' "$C_OK" "$C_0" "${row#PASS|}" ;;
      FAIL\|*) printf '   %sFAIL%s %s\n' "$C_NO" "$C_0" "${row#FAIL|}" ;;
    esac
  done
  printf '\n   %d PASS / %d FAIL\n' "$LAB_PASS" "$LAB_FAIL"
  [ "$LAB_FAIL" -eq 0 ]
}

# ── prereqs ────────────────────────────────────────────────────────────────
# Fail LOUD and early with the exact package names, rather than dying eight
# steps in with an empty variable.
require_tools() {
  local missing=() t
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    warn "missing required tool(s): ${missing[*]}"
    warn "  Debian/Ubuntu: sudo apt-get install -y openssl curl jq sqlite3"
    warn "  macOS (brew):  brew install openssl curl jq sqlite"
    return 1
  fi
  return 0
}

# ── daemon lifecycle ───────────────────────────────────────────────────────
LAB_PIDS=()

# lab_track_pid <pid> — register a daemon for cleanup.
lab_track_pid() { LAB_PIDS+=("$1"); }

# lab_stop_all — TERM every tracked daemon, then KILL what survives. Safe to
# call twice (the EXIT trap and an explicit call both land here).
lab_stop_all() {
  local p
  for p in "${LAB_PIDS[@]:-}"; do
    [ -n "$p" ] || continue
    kill "$p" 2>/dev/null || true
  done
  for p in "${LAB_PIDS[@]:-}"; do
    [ -n "$p" ] || continue
    local i=0
    while kill -0 "$p" 2>/dev/null && [ "$i" -lt 40 ]; do sleep 0.25; i=$((i + 1)); done
    kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null || true
  done
  LAB_PIDS=()
}

# lab_wait_https <url> <client-cert> <client-key> [tries] — poll an mTLS
# endpoint until it answers. Returns 0 on first answer, 1 on exhaustion.
lab_wait_https() {
  local url="$1" cert="$2" key="$3" tries="${4:-120}" i
  for ((i = 0; i < tries; i++)); do
    if curl -sk --cert "$cert" --key "$key" --max-time 3 "$url" -o /dev/null 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# lab_port_free <port> — true when nothing is listening on 127.0.0.1:<port>.
# Used to tell "the daemon refused to boot for the reason we are testing" apart
# from "the daemon could not bind" — a negative lane that accepts ANY non-zero
# exit will happily pass on a port collision, which is a false green.
lab_port_free() {
  ! (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null
}
