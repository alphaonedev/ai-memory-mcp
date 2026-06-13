#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Bring up the federated peer mesh: install a systemd unit on every PEER that
# runs `ai-memory serve` against the local PG/AGE substrate (20_pg_age.sh) with
# the full v0.7 federation + TLS + mTLS stack wired in, then enable/start and
# health-check each node over the encrypted path.
#
# Why peers only: 40_tls.sh issues SERVER certs to peers exclusively. Agents
# and ctrl hold a CLIENT cert only — they are pure mTLS API clients of the peer
# mesh (their NHI / loadgen drivers are exercised in the P3 test phase). The
# only long-running HTTPS daemon on the fleet is the peer's `serve`.
#
# Federation shape (ServeArgs / ADR-0001):
#   * --quorum-writes 2 of N=3  -> majority write quorum across the 3 peers;
#     every HTTP write commits locally + collects W-1=1 peer ack within the
#     quorum timeout before returning OK.
#   * --quorum-peers <other two peers' https base urls> (this node excluded).
#   * outbound federation POSTs present the node's mTLS CLIENT cert and verify
#     peer SERVER certs against the campaign CA (self-signed -> --quorum-ca-cert
#     is mandatory, #333).
#   * inbound /sync/push (and the whole port) is gated by --mtls-allowlist:
#     client_auth_mandatory over the entire HTTPS port (src/tls.rs).
#
# Secret handling: the PG password (20_pg_age.sh) is composed into a store URL
# that lives ONLY in the per-node EnvironmentFile (mode 0400, root-only) and is
# pulled into ExecStart via systemd ${AI_MEMORY_STORE_URL} expansion — the unit
# file itself carries NO secret. The daemon's `--store-url` has no env binding
# in the pinned golden binary, so the expanded argv is visible to root via
# `ps`; on these single-tenant, firewall-closed (5432 localhost-bound) hosts
# that residual is acceptable and documented rather than hidden.
source "$(dirname "$0")/lib.sh"

RENDER_DIR="$RUN_DIR/render"; mkdir -p "$RENDER_DIR"
SECRETS_DIR="$RUN_DIR/secrets"
PG_PW_FILE="$SECRETS_DIR/pg.pw"
REMOTE_TLS="/etc/ai-memory/tls"
REMOTE_ENVFILE="/etc/ai-memory/ai-memory.env"
REMOTE_UNIT="/etc/systemd/system/ai-memory.service"
BIN="/usr/local/bin/ai-memory"

require_inventory
[ -s "$PG_PW_FILE" ] || die "PG password missing ($PG_PW_FILE) — run provision/20_pg_age.sh first"
PG_PW="$(cat "$PG_PW_FILE")"

# Comma-joined https base urls of every peer EXCEPT the one whose public IP is
# $1. bash-3.2 has no process substitution (#66 SIGTRAP class) — feed via a pipe.
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
  store_url="postgres://aimemory:$PG_PW@127.0.0.1:5432/aimemory"
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
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

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
  --quorum-writes 2 \\
  --quorum-peers $peers_csv \\
  --quorum-client-cert $REMOTE_TLS/client.pem \\
  --quorum-client-key $REMOTE_TLS/client.key \\
  --quorum-ca-cert $REMOTE_TLS/ca.pem \\
  --quorum-timeout-ms 2000 \\
  --catchup-interval-secs 30 \\
  --federation-identity $fed_id \\
  --shutdown-grace-secs 30
Restart=on-failure
RestartSec=3
TimeoutStopSec=45
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

  log "[$host] installing systemd unit -> $REMOTE_UNIT (quorum W=2, peers=$peers_csv)"
  scp_to "$unit" "$pub" "$REMOTE_UNIT"
  ssh_node "$pub" "chmod 0644 '$REMOTE_UNIT'; systemctl daemon-reload; systemctl enable ai-memory.service >/dev/null 2>&1 || true; systemctl restart ai-memory.service"

  # --- health gate over the FULL TLS+mTLS path -------------------------------
  # Verify from the node itself: connect to 127.0.0.1 but SNI/verify against the
  # DNS:<host> SAN (40_tls.sh puts both IP:<pub> and DNS:<host> on the server
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

log "federation bring-up complete — peer mesh serving over TLS+mTLS (quorum W=2 of 3)"
