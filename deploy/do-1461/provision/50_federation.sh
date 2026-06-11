#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Bring up the federated peer mesh: install a systemd unit on every PEER that
# runs `ai-memory serve` against ITS REGION's PG/AGE substrate (20_pg_age.sh) on
# its own within-region ic_peer_<K> schema, over TLS verify-full to that region
# pg node's private VPC IP, with the full v0.7 federation + TLS + mTLS stack
# wired in, then enable/start and health-check each node over the encrypted path.
#
# Why peers only run a daemon: 15_tls.sh issues SERVER certs to peers (HTTPS
# serve) + each region's pg (the PG TLS leg). Peers are the only long-running
# HTTPS daemons; pg nodes run PostgreSQL, not `serve`. Any agent/ctrl roles
# would hold a CLIENT cert only (pure mTLS API clients, exercised in P3).
#
# Federation shape (ServeArgs / ADR-0001):
#   * --quorum-writes $(quorum_writes) — the SYNCHRONOUS write quorum. Every
#     HTTP write commits LOCALLY, then waits for W-1 REMOTE acks within the
#     quorum timeout before returning OK. W is SMALL by design (lib.sh
#     FED_SYNC_QUORUM_W=2 → local-commit + 1 cross-region remote ack): ai-memory
#     federation is PRIMARILY EVENTUAL (async catch-up below), so a full
#     cross-region majority is the wrong/fragile model — the synchronous gate
#     proves at-least-one-remote durability and the async catch-up converges the
#     write to EVERY peer in EVERY region (the harness asserts that convergence).
#     NO hardcoded quorum literal — it derives from inventory via quorum_writes().
#   * --quorum-peers <every OTHER peer's https base url, ALL regions> (this node
#     excluded). The quorum mesh spans all three regions over PUBLIC IPs.
#   * outbound federation POSTs present the node's mTLS CLIENT cert and verify
#     peer SERVER certs against the campaign CA (self-signed -> --quorum-ca-cert
#     is mandatory, #333).
#   * inbound /sync/push (and the whole port) is gated by --mtls-allowlist:
#     client_auth_mandatory over the entire HTTPS port (src/tls.rs).
#
# Secret handling: the fleet-wide PG password (20_pg_age.sh) is composed into a
# per-peer store URL (store_url_for_schema → the peer's REGION pg node's PRIVATE
# VPC IP, the peer's within-region ic_peer_<K> search_path schema,
# sslmode=verify-full) that lives ONLY in the per-node EnvironmentFile (mode
# 0400, root-only) and is pulled into ExecStart via systemd
# ${AI_MEMORY_STORE_URL} expansion — the unit file itself carries NO secret. The
# daemon's `--store-url` has no env binding in the pinned golden binary, so the
# expanded argv is visible to root via `ps`; on these single-tenant,
# firewall-closed (pg_port tag-scoped east-west) hosts that residual is
# acceptable and documented rather than hidden.
source "$(dirname "$0")/lib.sh"

RENDER_DIR="$RUN_DIR/render"; mkdir -p "$RENDER_DIR"
SECRETS_DIR="$RUN_DIR/secrets"
PG_PW_FILE="$SECRETS_DIR/pg.pw"
REMOTE_TLS="/etc/ai-memory/tls"
REMOTE_UNIT="/etc/systemd/system/ai-memory.service"
BIN="/usr/local/bin/ai-memory"

require_inventory
[ -s "$PG_PW_FILE" ] || die "PG password missing ($PG_PW_FILE) — run provision/20_pg_age.sh first"
PG_PW="$(cat "$PG_PW_FILE")"

# Cross-region write quorum (W = floor(peer_count/2)+1 unless QUORUM_WRITES is
# pinned). Computed ONCE from inventory — no literal lives at the call site.
QW="$(quorum_writes)"
PEER_N="$(inv_peer_count)"
log "cross-region write quorum: W=$QW of N=$PEER_N peers (regions: $(inv_regions | tr '\n' ' '))"

# Comma-joined https base urls of every peer EXCEPT the one whose public IP is
# $1 — across ALL regions (the cross-region quorum mesh rides public IPs). bash-
# 3.2 has no process substitution (#66 SIGTRAP class) — feed via a pipe.
build_peers_csv() {
  local self_ip="$1"
  inv_peer_urls | while IFS= read -r url; do
    case "$url" in *"//$self_ip:"*) continue ;; esac
    printf '%s\n' "$url"
  done | paste -sd, -
}

inv_all | while IFS="$(printf '\t')" read -r host role region pub priv; do
  [ "$role" = "peer" ] || { log "[$host] role=$role is a pure mTLS client (no serve daemon) — skipping"; continue; }

  fed_id="$CAMPAIGN/$region/$host"          # stable, trust-domain-scoped federation identity
  agent_id="ai:$host@$CAMPAIGN"             # stable, NON-reserved (never the reserved 'daemon', #1231)
  # Regional-PG store URL: this peer's WITHIN-REGION ic_peer_<K> schema on ITS
  # region pg node's PRIVATE VPC IP, sslmode=verify-full + campaign CA
  # (store_url_for_schema). Region resolved from inventory — no hardcoded host.
  pg_priv="$(inv_pg_private_ip_for_region "$region")"
  [ -n "$pg_priv" ] || die "[$host] region $region has no pg private VPC IP — run provision/20_pg_age.sh / check inventory"
  schema_idx="$(peer_schema_index_in_region "$host")" || die "[$host] not found in its region's sorted peer set — inventory/role mismatch"
  store_url="$(store_url_for_schema "$(peer_schema "$schema_idx")" "$pg_priv" "$PG_PW")"
  peers_csv="$(build_peers_csv "$pub")"
  [ -n "$peers_csv" ] || die "[$host] no other peers resolved for quorum — inventory must list >=2 peers"

  # --- per-node EnvironmentFile: API key (from 30_config.sh) + federation env --
  # Reuse the file 30_config.sh rendered, strip any federation lines we manage,
  # then append fresh ones so re-runs stay idempotent. Secret never echoed.
  local_env="$SECRETS_DIR/$host.env"
  [ -s "$local_env" ] || die "[$host] secret env file missing ($local_env) — run provision/30_config.sh first"
  tmp_env="$local_env.tmp"
  grep -vE '^(AI_MEMORY_STORE_URL|AI_MEMORY_AGENT_ID|AI_MEMORY_FED_IDENTITY)=' "$local_env" > "$tmp_env" || true
  {
    printf 'AI_MEMORY_STORE_URL=%s\n' "$store_url"
    printf 'AI_MEMORY_AGENT_ID=%s\n'  "$agent_id"
    printf 'AI_MEMORY_FED_IDENTITY=%s\n' "$fed_id"
  } >> "$tmp_env"
  mv "$tmp_env" "$local_env"; chmod 600 "$local_env"

  log "[$host] pushing federation EnvironmentFile (mode 0400)"
  scp_to "$local_env" "$pub" "$REMOTE_ENVFILE"
  ssh_node "$pub" "chmod 0400 '$REMOTE_ENVFILE'"

  # --- systemd unit (no secret in the unit; store URL via ${VAR} expansion) ----
  outdir="$RENDER_DIR/$host"; mkdir -p "$outdir"
  unit="$outdir/ai-memory.service"
  cat > "$unit" <<UNIT
[Unit]
Description=ai-memory federated daemon ($CAMPAIGN peer $host)
# The autonomous tier loads its embedder from the co-located native Ollama
# (25_ollama_embed.sh) on localhost:11434 — order after it so the embedder API
# is up before the daemon's first embed call (no Docker anywhere on the fleet).
After=network-online.target ollama.service
Wants=network-online.target ollama.service

[Service]
Type=simple
# HOME drives the default config search ($host config.toml is at
# /root/.config/ai-memory/config.toml, mirrored to /etc/ai-memory).
Environment=HOME=/root
EnvironmentFile=$REMOTE_ENVFILE
ExecStart=$BIN serve \\
  --host 0.0.0.0 \\
  --port $FEDERATION_PORT \\
  --store-url \${AI_MEMORY_STORE_URL} \\
  --tls-cert $REMOTE_TLS/server.pem \\
  --tls-key $REMOTE_TLS/server.key \\
  --mtls-allowlist $REMOTE_TLS/mtls-allowlist.txt \\
  --quorum-writes $QW \\
  --quorum-peers $peers_csv \\
  --quorum-client-cert $REMOTE_TLS/client.pem \\
  --quorum-client-key $REMOTE_TLS/client.key \\
  --quorum-ca-cert $REMOTE_TLS/ca.pem \\
  --quorum-timeout-ms $FED_QUORUM_TIMEOUT_MS \\
  --catchup-interval-secs $FED_CATCHUP_INTERVAL_SECS \\
  --federation-identity $fed_id \\
  --shutdown-grace-secs $FED_SHUTDOWN_GRACE_SECS
Restart=on-failure
RestartSec=3
TimeoutStopSec=45
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

  log "[$host] installing systemd unit -> $REMOTE_UNIT (quorum W=$QW of $PEER_N, peers=$peers_csv)"
  scp_to "$unit" "$pub" "$REMOTE_UNIT"
  ssh_node "$pub" "chmod 0644 '$REMOTE_UNIT'; systemctl daemon-reload; systemctl enable ai-memory.service >/dev/null 2>&1 || true; systemctl restart ai-memory.service"

  # #1587 — AI_MEMORY_STORE_URL is written into the EnvironmentFile above (this
  # step owns it). The curator unit (installed by 46_batman) depends on it but
  # runs BEFORE this step, so 46 deferred its first start to avoid an
  # empty-store-url crash-loop. Now that the env carries the URL, (re)start the
  # curator here — but only on peers where the unit exists + the var is set, and
  # `reset-failed` first so any historical backoff counter from a prior race
  # doesn't keep the unit in failed state.
  ssh_node "$pub" "if [ -f /etc/systemd/system/ai-memory-curator.service ] && grep -qE '^AI_MEMORY_STORE_URL=.+' '$REMOTE_ENVFILE' 2>/dev/null; then systemctl reset-failed ai-memory-curator.service 2>/dev/null || true; systemctl restart ai-memory-curator.service 2>/dev/null || true; fi"

  # --- health gate over the FULL TLS+mTLS path -------------------------------
  # Verify from the node itself: connect to 127.0.0.1 but SNI/verify against the
  # DNS:<host> SAN (15_tls.sh puts both IP:<pub> and DNS:<host> on the server
  # cert) and present the node's allowlisted client cert. Proves rustls server
  # auth + fingerprint mTLS + a live handler in one probe.
  log "[$host] waiting for federated daemon health (TLS+mTLS /api/v1/health)"
  ssh_node "$pub" "for i in \$(seq 1 60); do \
      curl -fsS --max-time 8 --resolve $host:$FEDERATION_PORT:127.0.0.1 \
        --cacert $REMOTE_TLS/ca.pem --cert $REMOTE_TLS/client.pem --key $REMOTE_TLS/client.key \
        https://$host:$FEDERATION_PORT/api/v1/health >/dev/null 2>&1 && exit 0; \
      sleep 2; done; \
      echo '[$host] health probe FAILED — last journal:' >&2; \
      journalctl -u ai-memory.service -n 40 --no-pager >&2; exit 1" \
    || die "[$host] federated daemon failed health check"
  log "[$host] federated peer daemon UP (identity=$fed_id, agent_id=$agent_id)"
done

log "federation bring-up complete — cross-region peer mesh serving over TLS+mTLS (quorum W=$QW of $PEER_N, regions: $(inv_regions | tr '\n' ' '))"
