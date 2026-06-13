#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# docker-1461 provision step 40 — TLS + mTLS material.
#
# Mirrors deploy/hive-1461/provision/40_tls.sh, but writes into each
# peer's gitignored node dir (bind-mounted into the container at
# $REMOTE_TLS_DIR) instead of pushing over SSH. Idempotent: existing
# CA / client material is reused so the trust topology is stable across
# re-runs; only missing pieces are minted.
#
# Layout produced (per the entrypoint TLS contract):
#   $TLS_ROOT/ca.{pem,key}            campaign CA (key 0600)
#   $TLS_ROOT/client.{pem,key}        shared mTLS API-client identity
#   <node>/tls/server.{pem,key}       per-peer server cert (SAN: name,localhost,127.0.0.1)
#   <node>/tls/client.{pem,key}       client identity (quorum + harness)
#   <node>/tls/ca.pem                 CA cert (server-cert verification)
#   <node>/tls/mtls-allowlist.txt     SHA-256(DER(client.pem)) — the pinned fingerprint
#
# The mTLS allowlist pins the SINGLE shared client cert: every peer's
# outbound quorum client and the host test harness present the same
# cert, so one fingerprint authorises the whole mesh. Adding a peer
# never edits another peer's allowlist (that is the zero-touch arm's
# job at the application layer; this layer is pure transport pinning).

set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SELF_DIR/lib.sh"

CERT_DAYS="${DOCKER_1461_CERT_DAYS:-3650}"
EC_CURVE="${DOCKER_1461_EC_CURVE:-prime256v1}"

umask 077
mkdir -p "$TLS_ROOT"

_gen_key() { openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$EC_CURVE" -out "$1" 2>/dev/null; }

# --------------------------------------------------------------------------
# 1. Campaign CA (minted once, reused thereafter).
# --------------------------------------------------------------------------
CA_KEY="$TLS_ROOT/ca.key"
CA_CERT="$TLS_ROOT/ca.pem"
if [ ! -s "$CA_CERT" ] || [ ! -s "$CA_KEY" ]; then
  log "tls: minting campaign CA ($FED_ISSUER_ID)"
  _gen_key "$CA_KEY"
  openssl req -x509 -new -key "$CA_KEY" -out "$CA_CERT" -days "$CERT_DAYS" \
    -subj "/CN=${FED_ISSUER_ID}" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  chmod 0600 "$CA_KEY"; chmod 0644 "$CA_CERT"
else
  log "tls: reusing campaign CA"
fi

# Sign a leaf CSR with the CA, attaching SAN + EKU via an extfile.
#   $1 = csr  $2 = out-cert  $3 = extfile
_sign_leaf() {
  openssl x509 -req -in "$1" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$2" -days "$CERT_DAYS" -extfile "$3" 2>/dev/null
}

# --------------------------------------------------------------------------
# 2. Shared mTLS client identity (quorum client + host harness).
# --------------------------------------------------------------------------
CLIENT_KEY="$TLS_ROOT/client.key"
CLIENT_CERT="$TLS_ROOT/client.pem"
if [ ! -s "$CLIENT_CERT" ] || [ ! -s "$CLIENT_KEY" ]; then
  log "tls: minting shared mTLS client identity"
  _gen_key "$CLIENT_KEY"
  csr="$TLS_ROOT/client.csr"; ext="$TLS_ROOT/client.ext"
  {
    printf 'basicConstraints=CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature\n'
    printf 'extendedKeyUsage=clientAuth\n'
  } >"$ext"
  openssl req -new -key "$CLIENT_KEY" -out "$csr" \
    -subj "/CN=${CAMPAIGN}-mtls-client" 2>/dev/null
  _sign_leaf "$csr" "$CLIENT_CERT" "$ext"
  rm -f "$csr" "$ext"
  chmod 0600 "$CLIENT_KEY"; chmod 0644 "$CLIENT_CERT"
else
  log "tls: reusing shared mTLS client identity"
fi

# --------------------------------------------------------------------------
# 3. The pinned fingerprint: lowercase hex SHA-256 of the client cert DER.
#    Tolerated allowlist format (src/tls.rs): hex, optional ':'/'sha256:',
#    blank lines + '#' comments. We emit a single bare hex line + a comment.
# --------------------------------------------------------------------------
client_fpr() {
  openssl x509 -in "$CLIENT_CERT" -outform DER 2>/dev/null \
    | openssl dgst -sha256 2>/dev/null \
    | sed -E 's/^.*= *//' | tr '[:upper:]' '[:lower:]'
}
FPR="$(client_fpr)"
[ -n "$FPR" ] || die "tls: failed to compute client cert fingerprint"
log "tls: client fingerprint sha256:$FPR"

# --------------------------------------------------------------------------
# 4. Per-peer server cert (SAN: <peer-name>, localhost, 127.0.0.1) + the
#    full TLS bundle copied into each node dir.
# --------------------------------------------------------------------------
i=1
while [ "$i" -le "$PEER_COUNT" ]; do
  name="$(peer_name "$i")"
  ntls="$NODES_ROOT/$name/tls"
  mkdir -p "$ntls"

  skey="$ntls/server.key"; scert="$ntls/server.pem"
  if [ ! -s "$scert" ] || [ ! -s "$skey" ]; then
    log "tls: minting server cert for $name"
    _gen_key "$skey"
    csr="$ntls/server.csr"; ext="$ntls/server.ext"
    {
      printf 'basicConstraints=CA:FALSE\n'
      printf 'keyUsage=critical,digitalSignature,keyEncipherment\n'
      printf 'extendedKeyUsage=serverAuth\n'
      printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\n' "$name"
    } >"$ext"
    openssl req -new -key "$skey" -out "$csr" -subj "/CN=${name}" 2>/dev/null
    _sign_leaf "$csr" "$scert" "$ext"
    rm -f "$csr" "$ext"
    chmod 0600 "$skey"; chmod 0644 "$scert"
  else
    log "tls: reusing server cert for $name"
  fi

  # Bundle: CA + shared client identity + the pinned allowlist.
  cp "$CA_CERT"     "$ntls/ca.pem"
  cp "$CLIENT_CERT" "$ntls/client.pem"
  cp "$CLIENT_KEY"  "$ntls/client.key"
  chmod 0644 "$ntls/ca.pem" "$ntls/client.pem"; chmod 0600 "$ntls/client.key"
  {
    printf '# docker-1461 mTLS allowlist — pinned SHA-256(DER) of the shared client cert.\n'
    printf '# Regenerated by provision/40_tls.sh; one entry authorises the whole mesh.\n'
    printf '%s\n' "$FPR"
  } >"$ntls/mtls-allowlist.txt"
  chmod 0644 "$ntls/mtls-allowlist.txt"

  i=$((i + 1))
done

# --------------------------------------------------------------------------
# 5. PostgreSQL server cert (the daemon -> PG store leg, third encrypted
#    leg of the mesh). A CA-signed leaf whose SAN covers the intra-bridge
#    DNS name + loopback, so a daemon dialing `pg-age` under
#    sslmode=verify-full validates the chain AND the hostname against the
#    SAME campaign CA the API + federation legs already trust — no separate
#    PKI. The key is bind-mounted into the PG container and re-installed
#    postgres-owned by its entrypoint wrapper (a bind-mounted host key keeps
#    its host uid; PostgreSQL refuses an ssl_key_file it does not own).
# --------------------------------------------------------------------------
pgtls="$PG_NODE_DIR/tls"
mkdir -p "$pgtls"
pgkey="$pgtls/server.key"; pgcert="$pgtls/server.pem"
if [ ! -s "$pgcert" ] || [ ! -s "$pgkey" ]; then
  log "tls: minting PG server cert ($PG_HOSTNAME)"
  _gen_key "$pgkey"
  csr="$pgtls/server.csr"; ext="$pgtls/server.ext"
  {
    printf 'basicConstraints=CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature,keyEncipherment\n'
    printf 'extendedKeyUsage=serverAuth\n'
    printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\n' "$PG_HOSTNAME"
  } >"$ext"
  openssl req -new -key "$pgkey" -out "$csr" -subj "/CN=${PG_HOSTNAME}" 2>/dev/null
  _sign_leaf "$csr" "$pgcert" "$ext"
  rm -f "$csr" "$ext"
  chmod 0600 "$pgkey"; chmod 0644 "$pgcert"
else
  log "tls: reusing PG server cert"
fi

log "tls: OK — CA + client + $PEER_COUNT server certs + PG server cert (curve=$EC_CURVE, days=$CERT_DAYS)"
