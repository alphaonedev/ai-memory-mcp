#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Generate the campaign TLS/mTLS trust material and fan it out. All test
# traffic on the fleet is TLS+mTLS — the peer HTTPS port enforces
# client_auth_mandatory, so EVERY node that talks to a peer (peers themselves
# for quorum, agents + ctrl as API clients) needs an allowlisted client cert.
#
# Trust model (src/tls.rs):
#   * Layer-1 server auth: outbound quorum/API clients verify the peer's
#     SERVER cert against the campaign CA (ca.pem) — SAN pins the public IP.
#   * Layer-2 mTLS: the peer accepts an inbound client cert ONLY if the
#     SHA-256 of its DER bytes is on mtls-allowlist.txt. The CA chain is
#     IGNORED for client auth — fingerprint pinning is the trust anchor
#     (SSH known_hosts model).
#
# Everything is generated LOCALLY in the gitignored run dir (keys mode 0600
# local / 0400 remote, NEVER committed, NEVER echoed) and scp'd into place at
# /etc/ai-memory/tls (created by cloud-init base.yaml.tpl).
source "$(dirname "$0")/lib.sh"

TLS="$RUN_DIR/tls"; mkdir -p "$TLS"; chmod 700 "$TLS"
REMOTE_TLS="/etc/ai-memory/tls"
CA_DAYS="${CA_DAYS:-3650}"
LEAF_DAYS="${LEAF_DAYS:-825}"

require_inventory

# --- campaign CA (generate once; reused on re-runs for stable trust) ----------
if [ ! -s "$TLS/ca.pem" ] || [ ! -s "$TLS/ca.key" ]; then
  log "generating campaign CA (CN=$CAMPAIGN fleet CA, ${CA_DAYS}d)"
  openssl genrsa -out "$TLS/ca.key" 4096 2>/dev/null
  chmod 600 "$TLS/ca.key"
  openssl req -x509 -new -nodes -key "$TLS/ca.key" -sha256 -days "$CA_DAYS" \
    -subj "/O=AlphaOne/CN=$CAMPAIGN fleet CA" -out "$TLS/ca.pem" 2>/dev/null
else
  log "reusing existing campaign CA ($TLS/ca.pem)"
fi

# --- per-node leaf certs (server cert only for peers; client cert for all) ----
issue_server_cert() {
  local host="$1" ip="$2"
  [ -s "$TLS/$host.server.pem" ] && return 0
  cat > "$TLS/$host.server.ext" <<EXT
subjectAltName = IP:$ip, DNS:$host
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EXT
  openssl genrsa -out "$TLS/$host.server.key" 2048 2>/dev/null; chmod 600 "$TLS/$host.server.key"
  openssl req -new -key "$TLS/$host.server.key" -subj "/O=AlphaOne/CN=$host" -out "$TLS/$host.server.csr" 2>/dev/null
  openssl x509 -req -in "$TLS/$host.server.csr" -CA "$TLS/ca.pem" -CAkey "$TLS/ca.key" \
    -CAserial "$TLS/ca.srl" -CAcreateserial -days "$LEAF_DAYS" -sha256 \
    -extfile "$TLS/$host.server.ext" -out "$TLS/$host.server.pem" 2>/dev/null
}

issue_client_cert() {
  local host="$1"
  [ -s "$TLS/$host.client.pem" ] && return 0
  cat > "$TLS/$host.client.ext" <<EXT
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EXT
  openssl genrsa -out "$TLS/$host.client.key" 2048 2>/dev/null; chmod 600 "$TLS/$host.client.key"
  openssl req -new -key "$TLS/$host.client.key" -subj "/O=AlphaOne/CN=$host-client" -out "$TLS/$host.client.csr" 2>/dev/null
  openssl x509 -req -in "$TLS/$host.client.csr" -CA "$TLS/ca.pem" -CAkey "$TLS/ca.key" \
    -CAserial "$TLS/ca.srl" -CAcreateserial -days "$LEAF_DAYS" -sha256 \
    -extfile "$TLS/$host.client.ext" -out "$TLS/$host.client.pem" 2>/dev/null
}

der_sha256() { openssl x509 -in "$1" -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}'; }

log "issuing leaf certs for every node"
inv_all | while IFS="$(printf '\t')" read -r host role region pub priv; do
  [ "$role" = "peer" ] && issue_server_cert "$host" "$pub"
  issue_client_cert "$host"
done

# --- build the fleet mTLS allowlist (every node's client-cert fingerprint) ----
ALLOWLIST="$TLS/mtls-allowlist.txt"
{
  printf '# %s fleet mTLS client-cert allowlist (SHA-256 of DER)\n' "$CAMPAIGN"
  inv_all | while IFS="$(printf '\t')" read -r host role region pub priv; do
    fp="$(der_sha256 "$TLS/$host.client.pem")"
    printf '%s  # %s (%s)\n' "$fp" "$host" "$role"
  done
} > "$ALLOWLIST"
log "mTLS allowlist built ($(grep -c '^[0-9a-fA-F]' "$ALLOWLIST") entries)"

# --- fan out: CA + allowlist everywhere; server certs to peers; client to all -
inv_all | while IFS="$(printf '\t')" read -r host role region pub priv; do
  log "[$host] pushing TLS material (role=$role) -> $REMOTE_TLS"
  ssh_node "$pub" "mkdir -p $REMOTE_TLS && chmod 700 $REMOTE_TLS"
  scp_to "$TLS/ca.pem"           "$pub" "$REMOTE_TLS/ca.pem"
  scp_to "$ALLOWLIST"            "$pub" "$REMOTE_TLS/mtls-allowlist.txt"
  scp_to "$TLS/$host.client.pem" "$pub" "$REMOTE_TLS/client.pem"
  scp_to "$TLS/$host.client.key" "$pub" "$REMOTE_TLS/client.key"
  if [ "$role" = "peer" ]; then
    scp_to "$TLS/$host.server.pem" "$pub" "$REMOTE_TLS/server.pem"
    scp_to "$TLS/$host.server.key" "$pub" "$REMOTE_TLS/server.key"
  fi
  ssh_node "$pub" "chmod 0400 $REMOTE_TLS/client.key $([ "$role" = "peer" ] && echo "$REMOTE_TLS/server.key") 2>/dev/null; chmod 0444 $REMOTE_TLS/ca.pem $REMOTE_TLS/mtls-allowlist.txt $REMOTE_TLS/client.pem"
done
log "TLS/mTLS material fan-out complete (CA + allowlist + per-node leaves)"
