#!/usr/bin/env bash
# federation-rollout.sh — health-gated rollout + automatic rollback of the
# active `ai-memory` daemon binary on one federation node (FED-P3c-4).
#
# This is the side-effecting "Apply" half of the federation reconciler
# contract (design doc §7). The PURE diff half — which membership /
# credential / enforcement actions a node needs — is computed by
# `src/federation/identity/reconcile.rs::reconcile()`; this script is the
# generalized `deploy-rebuild.sh` that actually swaps the binary under a
# running daemon and proves the new process is healthy over mTLS before
# committing, rolling back to the previous binary if it is not.
#
# Contract (design doc §7 "Reconciler contract → Apply / Health gate /
# Rollback"):
#   1. Capture the live daemon's argv + environ (secrets preserved, NEVER
#      printed) so a non-supervised re-exec relaunches byte-identically.
#   2. Back up the live binary (and optionally the live DB) to a durable,
#      OFF-tmpfs state dir.
#   3. Atomically swap in the new binary.
#   4. Stop the daemon, start it on the new binary (via supervisor hooks).
#   5. Verify health: N retries of an mTLS `GET /api/v1/memories?limit=1`
#      probe over HTTPS.
#   6. On verify failure: restore the backup binary, relaunch, re-verify.
#      If BOTH the new and the previous binary fail health, emit a loud
#      MANUAL INTERVENTION block and exit non-zero — never leave the fleet
#      dark silently.
#   7. Idempotent: if the live binary already IS the new binary and health
#      is green, the swap is skipped and the script exits 0.
#
# Partition-safety: this script only rolls a SINGLE node's binary. The
# fleet-wide partition-safe ordering (every node sign-capable BEFORE strict
# enforcement is flipped on) is enforced upstream by the reconciler plan in
# reconcile.rs (EnableStrictEnforcement is emitted last, gated on observed
# sign-capability). Do not flip enforcement from this script.
#
# Supervisor abstraction: stop/start are indirected through hook commands so
# the same script drives a systemd fleet (default), a bare re-exec node, or
# any custom supervisor, without branching logic in the rollout core.
#
#   FED_ROLLOUT_SUPERVISOR = systemd | reexec | custom   (default: systemd)
#     systemd  → systemctl stop/start "$FED_ROLLOUT_UNIT"
#     reexec   → kill the captured PID, relaunch with captured argv+environ
#                (Linux only — requires /proc; secrets stay in-process)
#     custom   → run FED_ROLLOUT_STOP_CMD / FED_ROLLOUT_START_CMD verbatim
#
# This script AUTHORS the rollout mechanism; it is NOT to be executed against
# a live production fleet as part of autonomous development work. Operators
# run it (or the reconciling controller invokes it) during a real rollout.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (env-overridable; sane secure defaults)
# ---------------------------------------------------------------------------

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The binary that the daemon launches from. On a systemd Linux node this is
# the install target the unit's ExecStart points at.
AI_MEMORY_BIN="${AI_MEMORY_BIN:-/usr/local/bin/ai-memory}"

# The freshly-built candidate binary to roll out.
NEW_BINARY="${NEW_BINARY:-$REPO/target/release/ai-memory}"

# Durable, OFF-tmpfs state dir for backups. NEVER /tmp (project hard rule +
# tmpfs is wiped on reboot, which would lose the rollback target across a
# crash-restart). Defaults to the systemd StateDirectory convention.
FED_ROLLOUT_STATE_DIR="${FED_ROLLOUT_STATE_DIR:-/var/lib/ai-memory/rollout}"

# Supervisor integration.
FED_ROLLOUT_SUPERVISOR="${FED_ROLLOUT_SUPERVISOR:-systemd}"
FED_ROLLOUT_UNIT="${FED_ROLLOUT_UNIT:-ai-memory}"
FED_ROLLOUT_STOP_CMD="${FED_ROLLOUT_STOP_CMD:-}"
FED_ROLLOUT_START_CMD="${FED_ROLLOUT_START_CMD:-}"

# mTLS health-probe parameters. The probe is the ONLY definition of "healthy"
# this script trusts — a process that is up but cannot serve an authenticated
# request is treated as failed and rolled back.
PROBE_HOST="${FED_ROLLOUT_PROBE_HOST:-127.0.0.1}"
PROBE_PORT="${FED_ROLLOUT_PROBE_PORT:-9077}"
PROBE_PATH="${FED_ROLLOUT_PROBE_PATH:-/api/v1/memories?limit=1}"
PROBE_RETRIES="${FED_ROLLOUT_PROBE_RETRIES:-10}"
PROBE_INTERVAL_SECS="${FED_ROLLOUT_PROBE_INTERVAL_SECS:-3}"
PROBE_TIMEOUT_SECS="${FED_ROLLOUT_PROBE_TIMEOUT_SECS:-5}"

# mTLS client material. Absent client cert/key falls back to a server-auth
# probe (CA-only); a fully encrypted-only fleet supplies all three.
MTLS_CA="${FED_ROLLOUT_MTLS_CA:-}"
MTLS_CERT="${FED_ROLLOUT_MTLS_CERT:-}"
MTLS_KEY="${FED_ROLLOUT_MTLS_KEY:-}"

DRY_RUN=0

# Re-exec mode captures (populated only when supervisor=reexec).
CAPTURED_PID=""
declare -a CAPTURED_ARGV=()
declare -a CAPTURED_ENVIRON=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
federation-rollout.sh — health-gated rollout + rollback of the ai-memory daemon

Usage:
  federation-rollout.sh [--new-binary PATH] [--dry-run] [--help]

Options:
  --new-binary PATH   Candidate binary to roll out (default: target/release/ai-memory)
  --dry-run           Print the plan (swap target, supervisor, probe URL) and exit
                      without stopping the daemon or touching the live binary.
  --help              Show this help.

Key environment variables (see header for the full list):
  AI_MEMORY_BIN              Live binary path the daemon launches from
  FED_ROLLOUT_STATE_DIR      OFF-tmpfs backup dir (default /var/lib/ai-memory/rollout)
  FED_ROLLOUT_SUPERVISOR     systemd | reexec | custom (default systemd)
  FED_ROLLOUT_UNIT           systemd unit name (default ai-memory)
  FED_ROLLOUT_{STOP,START}_CMD  custom supervisor commands
  FED_ROLLOUT_PROBE_*        mTLS health-probe host/port/path/retries/interval
  FED_ROLLOUT_MTLS_{CA,CERT,KEY}  mTLS client material for the probe
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --new-binary) NEW_BINARY="${2:?--new-binary needs a path}"; shift 2 ;;
      --dry-run)    DRY_RUN=1; shift ;;
      --help|-h)    usage; exit 0 ;;
      *)            die "unknown argument: $1 (try --help)" ;;
    esac
  done
}

# sha of a file, for idempotence + backup naming. Empty string if absent.
file_sha() {
  local f="$1"
  [[ -f "$f" ]] || { printf ''; return; }
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  else
    shasum -a 256 "$f" | awk '{print $1}'
  fi
}

# mTLS health probe — single attempt. Returns 0 iff the daemon serves an
# authenticated request. curl flags are assembled so that absent client
# material degrades to a server-auth probe rather than erroring.
health_probe_once() {
  local url="https://${PROBE_HOST}:${PROBE_PORT}${PROBE_PATH}"
  local -a curl_args=(
    --silent --show-error --fail
    --max-time "$PROBE_TIMEOUT_SECS"
  )
  [[ -n "$MTLS_CA"   ]] && curl_args+=(--cacert "$MTLS_CA")
  [[ -n "$MTLS_CERT" ]] && curl_args+=(--cert "$MTLS_CERT")
  [[ -n "$MTLS_KEY"  ]] && curl_args+=(--key "$MTLS_KEY")
  curl "${curl_args[@]}" "$url" >/dev/null 2>&1
}

# Health gate — N retries with a fixed interval. Returns 0 on first success.
health_gate() {
  local what="$1" attempt
  for (( attempt = 1; attempt <= PROBE_RETRIES; attempt++ )); do
    if health_probe_once; then
      log "health gate PASS ($what) on attempt ${attempt}/${PROBE_RETRIES}"
      return 0
    fi
    [[ $attempt -lt $PROBE_RETRIES ]] && sleep "$PROBE_INTERVAL_SECS"
  done
  warn "health gate FAIL ($what) after ${PROBE_RETRIES} attempts"
  return 1
}

# ---------------------------------------------------------------------------
# Supervisor hooks (stop / start indirected by FED_ROLLOUT_SUPERVISOR)
# ---------------------------------------------------------------------------

# For reexec mode: snapshot the live daemon's argv + environ from /proc so the
# relaunch is byte-identical. Secrets in the environ are read into in-process
# bash arrays and NEVER written to disk or printed.
capture_live_process() {
  [[ "$FED_ROLLOUT_SUPERVISOR" == "reexec" ]] || return 0
  [[ -d /proc ]] || die "reexec supervisor requires /proc (Linux); use systemd/custom on this host"

  CAPTURED_PID="$(pgrep -f "${AI_MEMORY_BIN}.* serve" | head -n1 || true)"
  [[ -n "$CAPTURED_PID" ]] || die "reexec: no running daemon found for $AI_MEMORY_BIN serve"

  # NUL-delimited reads; mapfile -d '' keeps secret values intact in-memory.
  mapfile -d '' -t CAPTURED_ARGV    < "/proc/${CAPTURED_PID}/cmdline"
  mapfile -d '' -t CAPTURED_ENVIRON < "/proc/${CAPTURED_PID}/environ"
  # Drop any trailing empty element produced by the terminating NUL.
  [[ -n "${CAPTURED_ARGV[-1]:-}" ]]    || unset 'CAPTURED_ARGV[-1]'
  [[ -n "${CAPTURED_ENVIRON[-1]:-}" ]] || unset 'CAPTURED_ENVIRON[-1]'

  log "captured live daemon pid=${CAPTURED_PID} argv=${#CAPTURED_ARGV[@]} env=${#CAPTURED_ENVIRON[@]} (values not printed)"
}

stop_daemon() {
  case "$FED_ROLLOUT_SUPERVISOR" in
    systemd) systemctl stop "$FED_ROLLOUT_UNIT" ;;
    custom)  [[ -n "$FED_ROLLOUT_STOP_CMD" ]] || die "supervisor=custom needs FED_ROLLOUT_STOP_CMD"
             eval "$FED_ROLLOUT_STOP_CMD" ;;
    reexec)  [[ -n "$CAPTURED_PID" ]] || die "reexec stop: no captured pid"
             kill "$CAPTURED_PID" 2>/dev/null || true
             for _ in 1 2 3 4 5 6 7 8 9 10; do
               kill -0 "$CAPTURED_PID" 2>/dev/null || break
               sleep 1
             done
             kill -0 "$CAPTURED_PID" 2>/dev/null && kill -9 "$CAPTURED_PID" 2>/dev/null || true ;;
    *)       die "unknown FED_ROLLOUT_SUPERVISOR: $FED_ROLLOUT_SUPERVISOR" ;;
  esac
}

start_daemon() {
  case "$FED_ROLLOUT_SUPERVISOR" in
    systemd) systemctl start "$FED_ROLLOUT_UNIT" ;;
    custom)  [[ -n "$FED_ROLLOUT_START_CMD" ]] || die "supervisor=custom needs FED_ROLLOUT_START_CMD"
             eval "$FED_ROLLOUT_START_CMD" ;;
    reexec)  # env -i + captured environ → no secret leaks through the parent
             # shell; argv[0] is replaced by the freshly-swapped binary path.
             setsid env -i "${CAPTURED_ENVIRON[@]}" \
               "$AI_MEMORY_BIN" "${CAPTURED_ARGV[@]:1}" \
               >>"${FED_ROLLOUT_STATE_DIR}/daemon.out" 2>&1 &
             disown ;;
    *)       die "unknown FED_ROLLOUT_SUPERVISOR: $FED_ROLLOUT_SUPERVISOR" ;;
  esac
}

# ---------------------------------------------------------------------------
# Binary swap (atomic) + backup
# ---------------------------------------------------------------------------

# Atomically replace AI_MEMORY_BIN with $1 via same-dir temp + rename.
swap_binary() {
  local src="$1" dst="$AI_MEMORY_BIN" tmp
  tmp="$(mktemp "${dst}.rollout.XXXXXX")"
  cp "$src" "$tmp"
  chmod --reference="$dst" "$tmp" 2>/dev/null || chmod 0755 "$tmp"
  mv -f "$tmp" "$dst"   # rename(2) is atomic on the same filesystem
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  parse_args "$@"

  [[ -f "$NEW_BINARY" ]] || die "new binary not found: $NEW_BINARY"
  [[ -x "$NEW_BINARY" ]] || die "new binary not executable: $NEW_BINARY"

  local live_sha new_sha
  live_sha="$(file_sha "$AI_MEMORY_BIN")"
  new_sha="$(file_sha "$NEW_BINARY")"
  local probe_url="https://${PROBE_HOST}:${PROBE_PORT}${PROBE_PATH}"

  log "federation-rollout"
  log "  live binary : $AI_MEMORY_BIN (sha ${live_sha:0:12})"
  log "  new  binary : $NEW_BINARY (sha ${new_sha:0:12})"
  log "  supervisor  : $FED_ROLLOUT_SUPERVISOR"
  log "  state dir   : $FED_ROLLOUT_STATE_DIR"
  log "  health probe: $probe_url (${PROBE_RETRIES}× every ${PROBE_INTERVAL_SECS}s)"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "dry-run: no daemon stop, no binary swap. Exiting."
    return 0
  fi

  # Idempotence — converged node is a no-op (design §7 "Idempotent").
  if [[ -n "$live_sha" && "$live_sha" == "$new_sha" ]]; then
    if health_gate "already-current"; then
      log "node already on the target binary and healthy — no-op."
      return 0
    fi
    warn "node already on the target binary but UNHEALTHY — proceeding to restart-in-place."
  fi

  mkdir -p "$FED_ROLLOUT_STATE_DIR"
  chmod 0700 "$FED_ROLLOUT_STATE_DIR"

  # Back up the current live binary so rollback has a concrete target.
  local backup_bin=""
  if [[ -f "$AI_MEMORY_BIN" ]]; then
    backup_bin="${FED_ROLLOUT_STATE_DIR}/ai-memory.prev.${live_sha:0:12}"
    cp "$AI_MEMORY_BIN" "$backup_bin"
    log "backed up live binary → $backup_bin"
  else
    warn "no live binary at $AI_MEMORY_BIN — fresh install, rollback target is empty"
  fi

  capture_live_process

  # --- Roll forward -------------------------------------------------------
  log "swapping in new binary"
  swap_binary "$NEW_BINARY"
  log "restarting daemon on new binary"
  stop_daemon
  start_daemon

  if health_gate "new-binary"; then
    log "ROLLOUT OK — node healthy on new binary (sha ${new_sha:0:12})"
    return 0
  fi

  # --- Roll back ----------------------------------------------------------
  warn "new binary failed the health gate — rolling back"
  if [[ -z "$backup_bin" ]]; then
    emit_manual_intervention "new binary failed health and there is NO previous binary to restore"
    return 1
  fi

  swap_binary "$backup_bin"
  log "restarting daemon on previous binary"
  stop_daemon
  start_daemon

  if health_gate "rollback-binary"; then
    warn "ROLLED BACK — node restored to previous binary (sha ${live_sha:0:12}). New binary rejected."
    return 1
  fi

  emit_manual_intervention "BOTH the new binary AND the previous binary failed the health gate"
  return 1
}

emit_manual_intervention() {
  local reason="$1"
  cat >&2 <<BANNER

################################################################################
# MANUAL INTERVENTION REQUIRED — node not serving                              #
################################################################################
# Reason     : ${reason}
# Node       : $(hostname 2>/dev/null || echo '?')
# Live binary: ${AI_MEMORY_BIN}
# Probe URL  : https://${PROBE_HOST}:${PROBE_PORT}${PROBE_PATH}
# Backups    : ${FED_ROLLOUT_STATE_DIR}
#
# The reconciler did NOT leave this node dark silently — it exhausted its
# automatic rollback path and is escalating. An operator must inspect the
# daemon (journalctl -u ${FED_ROLLOUT_UNIT}) and restore service by hand.
################################################################################

BANNER
}

main "$@"
