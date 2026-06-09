#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Batman-active MAXIMUM-SECURE posture for the whole fleet (Secure Enterprise
# Federated Reference Architecture). Two concerns, both idempotent:
#
#   1. ENV battery (every daemon-bearing node): strip-then-append the Batman env
#      battery (lib.sh BATMAN_ENV_*) to each node's 0400 EnvironmentFile so the
#      v0.7.0 secure-default surfaces are LIVE over the wire — per-message
#      federation signing + nonce anti-replay + peer enrollment, agent
#      attestation on every write, enforce-mode permissions, fail-CLOSED
#      governance, Form-5 auto-confidence / shadow / decay. The strip-then-append
#      mirrors 45_zero_touch.sh exactly so re-runs converge to the same file.
#
#   2. Form-7 governance activation (peers only): via the golden ai-memory binary
#      over SSH — `rules keygen` (operator key), `rules sign-seed`, then enable
#      R001..R004 with `--sign` (the seed rules), then bind the Form2/6 namespace
#      Batman policy on the campaign namespace (`namespace batman-policy --json`
#      piped to `namespace set-standard`). Mirrors the command recipe in repo-
#      root scripts/install-batman-active.sh (steps 1-3 + 7); that script is NOT
#      invoked verbatim because it targets a sqlite operator host (~/.claude.json,
#      macOS launchd) — our peers are postgres-backed daemons, so we drive the
#      same CLI verbs against each peer's own --store-url (read from its 0400 env
#      file on the node, so the secret never reaches our command line). The
#      curator daemon is started under systemd on every peer.
#
# DELIBERATELY NOT SET: AI_MEMORY_ENCRYPT_AT_REST (see lib.sh BATMAN_ENV block):
# it is a sqlite/sqlcipher data-at-rest feature and a NO-OP on these postgres-
# backed peers. For postgres peers, data-at-rest is a Postgres/disk concern
# (cluster --data-checksums + host-disk encryption) and data-in-transit is the
# Leg-3 verify-full daemon→PG TLS leg; we do NOT rebuild the golden binary for
# sqlcipher.
#
# Ordering: runs AFTER 45_zero_touch.sh (its env appends must already be in the
# file) and BEFORE 50_federation.sh (the sole pusher of the EnvironmentFile +
# the daemon (re)start that LOADS this env). 46 therefore only mutates the LOCAL
# render-dir env file + drives the (postgres-resident) governance state; 50 then
# ships the file and restarts the daemon so the Batman env takes effect.
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$DO_ROOT/../.." && pwd)"
SECRETS_DIR="$RUN_DIR/secrets"
BIN="/usr/local/bin/ai-memory"
# Per-peer operator key + Form-7 governance live on the postgres-backed daemon,
# so the rules verbs run with the peer's own --store-url. The operator key is
# written to this node-local key dir (root-only).
REMOTE_KEY_DIR="/etc/ai-memory/keys"

require_inventory

# --- regex of the env names we manage, for the idempotent strip (bash-3.2) ----
# Build NAME1|NAME2|... from BATMAN_ENV_NAMES so the strip-then-append is a pure
# function of the SSOT list — adding a knob in lib.sh needs no edit here.
batman_strip_regex() {
  local re="" n
  for n in "${BATMAN_ENV_NAMES[@]}"; do
    re="${re:+$re|}$n"
  done
  printf '^(%s)=' "$re"
}

# --- append the Batman env battery to a node's local env file (idempotent) -----
append_batman_env() {
  local host="$1"
  local local_env="$SECRETS_DIR/$host.env"
  [ -s "$local_env" ] || die "[$host] secret env file missing ($local_env) — run provision/30_config.sh / 45_zero_touch.sh first"
  local re; re="$(batman_strip_regex)"
  local tmp_env="$local_env.tmp"
  grep -vE "$re" "$local_env" > "$tmp_env" || true
  local i=0
  while [ "$i" -lt "${#BATMAN_ENV_NAMES[@]}" ]; do
    printf '%s=%s\n' "${BATMAN_ENV_NAMES[$i]}" "${BATMAN_ENV_VALUES[$i]}" >> "$tmp_env"
    i=$((i + 1))
  done
  mv "$tmp_env" "$local_env"; chmod 600 "$local_env"
  log "[$host] Batman env battery appended (${#BATMAN_ENV_NAMES[@]} vars, strip-then-append)"
}

# --- Form-7 governance activation on a peer over SSH (idempotent) --------------
# Drives the golden binary against the peer's OWN postgres --store-url, read from
# the 0400 env file on the node (never on our command line). Mirrors
# scripts/install-batman-active.sh steps 1-3 + 7.
activate_form7_on_peer() {
  local ip="$1" host="$2"
  log "[$host] Form-7 governance activation (keygen + sign-seed + enable R001..R004 --sign)"

  # Space-joined seed-rule ids from the SSOT list (no literal in the heredoc).
  local rules_csv="" r
  for r in "${BATMAN_SEED_RULES[@]}"; do rules_csv="${rules_csv:+$rules_csv }$r"; done

  # Remote recipe. The store URL is sourced from the 0400 env file INSIDE the
  # remote shell so the secret never appears in our local argv / `ps`. AGENT_ID
  # for the governance writes is the peer's stable id (matches 50_federation).
  # All verbs are idempotent: keygen skips if the key exists, enable/sign-seed
  # are no-ops when already applied.
  ssh_node "$ip" "
    set -u
    export HOME=/root
    export AI_MEMORY_KEY_DIR='$REMOTE_KEY_DIR'
    mkdir -p '$REMOTE_KEY_DIR'; chmod 700 '$REMOTE_KEY_DIR'
    # Pull only the store URL out of the 0400 env file (root-readable) and export
    # it for the rules verbs; never echoed.
    STORE_URL=\$(grep -E '^AI_MEMORY_STORE_URL=' '$REMOTE_ENVFILE' 2>/dev/null | head -1 | cut -d= -f2-)
    AM() { '$BIN' \${STORE_URL:+--store-url \"\$STORE_URL\"} \"\$@\"; }
    # 1. operator key (idempotent)
    if [ ! -f '$REMOTE_KEY_DIR/operator.key' ]; then AM rules keygen >/dev/null 2>&1 || true; fi
    # 2. sign the seed rules (idempotent no-op if already signed)
    AM rules sign-seed >/dev/null 2>&1 || true
    # 3. enable + sign R001..R004 (idempotent)
    for r in $rules_csv; do AM rules enable --id \"\$r\" --sign >/dev/null 2>&1 || true; done
    # 7. bind the Form2/6 Batman namespace policy on the campaign namespace.
    POLICY_JSON=\$(AM namespace batman-policy --json 2>/dev/null | grep -vE '^ai-memory: loaded config')
    if [ -n \"\$POLICY_JSON\" ]; then
      STD_ID=\$(AM store --namespace '$DEFAULT_NAMESPACE' --tier long --priority 10 \
        --title 'batman-active standard for $DEFAULT_NAMESPACE' \
        --content 'Form 2 synchronous atomise-before-embed + Form 6 auto-classify (regex_then_llm) namespace standard. Set by provision/46_batman.sh on peer $host.' \
        --json 2>/dev/null | grep -vE '^ai-memory: loaded config' | tr -d '\n' | sed -n 's/.*\"id\"[^\"]*\"\([^\"]*\)\".*/\1/p')
      if [ -n \"\$STD_ID\" ]; then
        AM namespace set-standard --namespace '$DEFAULT_NAMESPACE' --id \"\$STD_ID\" --governance \"\$POLICY_JSON\" >/dev/null 2>&1 || true
      fi
    fi
  " || log "[$host] WARN: Form-7 activation returned non-zero (verbs are best-effort idempotent — 50_federation restart + test/run.sh nsa_gaps re-assert live state)"
}

# --- start the curator daemon (Form-1/5/6 upkeep) on a peer (idempotent) -------
# systemd unit; the Form-5 env battery is already in the EnvironmentFile so the
# curator inherits AUTO_CONFIDENCE / SHADOW / DECAY when 50 (re)starts the stack.
install_curator_on_peer() {
  local ip="$1" host="$2"
  local unit="/etc/systemd/system/ai-memory-curator.service"
  ssh_node "$ip" "cat > '$unit' <<UNIT
[Unit]
Description=ai-memory autonomous curator (Batman Mode, $CAMPAIGN peer $host)
After=network-online.target ai-memory.service
Wants=network-online.target

[Service]
Type=simple
Environment=HOME=/root
EnvironmentFile=$REMOTE_ENVFILE
# systemd does literal \${VAR} substitution (NOT shell :+ expansion); the
# postgres peers always carry AI_MEMORY_STORE_URL (50_federation), so pass it
# unconditionally. #1547: --store-url is a `curator` subcommand flag, so it
# MUST appear AFTER the `curator` token (clap rejects it as a global flag and
# exits 2 -> crash-loop otherwise). Mirrors `curator --store-url ...` usage.
ExecStart=$BIN curator --daemon --store-url \\\${AI_MEMORY_STORE_URL} --interval-secs $BATMAN_CURATOR_INTERVAL_SECS --max-ops $BATMAN_CURATOR_MAX_OPS
Restart=on-failure
RestartSec=30
Nice=5

[Install]
WantedBy=multi-user.target
UNIT
  chmod 0644 '$unit'; systemctl daemon-reload; systemctl enable ai-memory-curator.service >/dev/null 2>&1 || true; systemctl restart ai-memory-curator.service 2>/dev/null || true" \
    && log "[$host] curator daemon unit installed + started (interval=${BATMAN_CURATOR_INTERVAL_SECS}s, max-ops=$BATMAN_CURATOR_MAX_OPS)" \
    || log "[$host] WARN: curator unit install returned non-zero (50_federation brings the daemon up first; re-run is idempotent)"
}

# --- acceptance line per node (mirror scripts/batman-mode-acceptance.sh idea) --
# Best-effort: confirm the Batman env battery is present in the node's pushed
# env file count once 50 has shipped it. At THIS step the file is local-only, so
# emit the local count as the acceptance signal.
batman_acceptance_line() {
  local host="$1"
  local local_env="$SECRETS_DIR/$host.env"
  local re; re="$(batman_strip_regex)"
  local n; n="$(grep -cE "$re" "$local_env" 2>/dev/null || true)"
  log "[$host] BATMAN-ACCEPTANCE: ${n:-0}/${#BATMAN_ENV_NAMES[@]} max-secure env vars staged; encrypt-at-rest=postgres-disk-concern(not sqlcipher)"
}

# ============================================================================
# Drive every node. The Batman env battery goes on every DAEMON-BEARING node
# (peer/agent/ctrl — those have a 30_config EnvironmentFile). pg nodes run no
# ai-memory daemon (no env file), so they are skipped for env + governance; their
# data-at-rest is the Postgres/disk concern documented above.
# Form-7 governance + curator run on PEERS only (the postgres-backed daemons).
# ============================================================================
inv_all | while IFS="$(printf '\t')" read -r host role region pub priv; do
  case "$role" in
    pg)
      log "[$host] role=pg (PostgreSQL substrate, no daemon) — Batman env N/A; at-rest is Postgres/disk concern, in-transit is Leg-3 verify-full"
      continue
      ;;
    peer)
      append_batman_env "$host"
      activate_form7_on_peer "$pub" "$host"
      install_curator_on_peer "$pub" "$host"
      batman_acceptance_line "$host"
      ;;
    agent|ctrl)
      # Pure mTLS API clients (no mesh membership / no governance DB), but they
      # still carry the Batman env battery so their CLI/API writes attest + the
      # permission mode is enforce.
      append_batman_env "$host"
      batman_acceptance_line "$host"
      ;;
    *)
      log "[$host] unknown role '$role' — skipping Batman activation"
      ;;
  esac
done

log "Batman-active posture staged on all daemon-bearing nodes (env battery + Form-7 on peers + curator); 50_federation.sh will ship the env + restart to make it LIVE"
