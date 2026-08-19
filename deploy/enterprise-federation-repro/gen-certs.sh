#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# enterprise-federation-repro — TLS + mTLS material for BOTH encrypted legs.
#
# NO SECRETS ARE COMMITTED. This script MINTS the material into the gitignored
# run dir; generation is part of the reproduction. Idempotent — existing
# material is reused so the trust topology is stable across re-runs; only
# missing pieces are minted. Mirrors deploy/docker-1461/provision/40_tls.sh
# (same CA + leaf + fingerprint-allowlist mechanics) but shaped for the audit:
# ONE store leg (daemon -> PG, verify-full + client cert) + ONE API leg
# (AI NHI -> daemon :9077, mTLS + fingerprint allowlist).
#
# Layout produced (all under $TLS_DIR, gitignored):
#   ca.crt / ca.key                 campaign CA (key 0600)
#   pg-server.crt / pg-server.key   PG leaf   (SAN IP:127.0.0.1,DNS:localhost)
#   pg-client.crt / pg-client.key   PG client (CN = the pg role $PG_USER)
#   daemon-server.crt / .key        daemon leaf (SAN IP:127.0.0.1,DNS:localhost)
#   client-good.crt / client-good.key   ALLOWED API client identity
#   allowlist.txt                   sha256(DER(client-good)) fingerprint pin

set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SELF_DIR/lib.sh"

command -v openssl >/dev/null 2>&1 || die "openssl not found — required to mint the TLS/mTLS material"

umask 077
mkdir -p "$TLS_DIR"

_gen_key() { openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${EC_CURVE}" -out "$1" 2>/dev/null; }

# --------------------------------------------------------------------------
# 1. Campaign CA (minted once, reused thereafter).
# --------------------------------------------------------------------------
if [ ! -s "$CA_CERT" ] || [ ! -s "$CA_KEY" ]; then
  log "certs: minting campaign CA"
  _gen_key "$CA_KEY"
  openssl req -x509 -new -key "$CA_KEY" -out "$CA_CERT" -days "$CERT_DAYS" \
    -subj "/CN=${CAMPAIGN}-ca" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  chmod 0600 "$CA_KEY"; chmod 0644 "$CA_CERT"
else
  log "certs: reusing campaign CA"
fi

# _sign_leaf <csr> <out-cert> <extfile>
_sign_leaf() {
  openssl x509 -req -in "$1" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$2" -days "$CERT_DAYS" -extfile "$3" 2>/dev/null
}

# _mint_server_leaf <key> <cert> <CN>  — SAN covers loopback IP + localhost so
# a verify-full connect to 127.0.0.1 validates chain AND hostname.
_mint_server_leaf() {
  local key="$1" cert="$2" cn="$3"
  [ -s "$cert" ] && [ -s "$key" ] && { log "certs: reusing server cert ($cn)"; return 0; }
  log "certs: minting server cert ($cn)"
  _gen_key "$key"
  local csr="${cert%.crt}.csr" ext="${cert%.crt}.ext"
  {
    printf 'basicConstraints=CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature,keyEncipherment\n'
    printf 'extendedKeyUsage=serverAuth\n'
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n'
  } >"$ext"
  openssl req -new -key "$key" -out "$csr" -subj "/CN=${cn}" 2>/dev/null
  _sign_leaf "$csr" "$cert" "$ext"
  rm -f "$csr" "$ext"
  chmod 0600 "$key"; chmod 0644 "$cert"
}

# _mint_client_leaf <key> <cert> <CN>
_mint_client_leaf() {
  local key="$1" cert="$2" cn="$3"
  [ -s "$cert" ] && [ -s "$key" ] && { log "certs: reusing client cert ($cn)"; return 0; }
  log "certs: minting client cert ($cn)"
  _gen_key "$key"
  local csr="${cert%.crt}.csr" ext="${cert%.crt}.ext"
  {
    printf 'basicConstraints=CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature\n'
    printf 'extendedKeyUsage=clientAuth\n'
  } >"$ext"
  openssl req -new -key "$key" -out "$csr" -subj "/CN=${cn}" 2>/dev/null
  _sign_leaf "$csr" "$cert" "$ext"
  rm -f "$csr" "$ext"
  chmod 0600 "$key"; chmod 0644 "$cert"
}

# --------------------------------------------------------------------------
# 2. Store leg (daemon -> PG). PG server leaf + client leaf whose CN is the
#    pg role so scram + cert identity line up.
# --------------------------------------------------------------------------
_mint_server_leaf "$PG_SERVER_KEY" "$PG_SERVER_CERT" "${PG_HOST}"
_mint_client_leaf "$PG_CLIENT_KEY" "$PG_CLIENT_CERT" "${PG_USER}"

# --------------------------------------------------------------------------
# 3. API leg (AI NHI -> daemon :9077). Daemon server leaf + an ALLOWED client.
# --------------------------------------------------------------------------
_mint_server_leaf "$DAEMON_SERVER_KEY" "$DAEMON_SERVER_CERT" "${DAEMON_HOST}"
_mint_client_leaf "$CLIENT_GOOD_KEY" "$CLIENT_GOOD_CERT" "${CAMPAIGN}-api-client"

# --------------------------------------------------------------------------
# 4. The pinned fingerprint: lowercase hex SHA-256 of the client cert DER.
#    Tolerated allowlist format (src/tls.rs): hex, optional ':'/'sha256:',
#    blank lines + '#' comments. Emit ONE bare hex line + a comment.
# --------------------------------------------------------------------------
_client_fpr() {
  openssl x509 -in "$CLIENT_GOOD_CERT" -outform DER 2>/dev/null \
    | openssl dgst -sha256 2>/dev/null \
    | sed -E 's/^.*= *//' | tr '[:upper:]' '[:lower:]'
}
FPR="$(_client_fpr)"
[ -n "$FPR" ] || die "certs: failed to compute client-good cert fingerprint"
{
  printf '# enterprise-federation-repro mTLS allowlist — pinned SHA-256(DER) of client-good.crt.\n'
  printf '# Regenerated by gen-certs.sh; one entry authorises the audit API client.\n'
  printf '%s\n' "$FPR"
} >"$MTLS_ALLOWLIST"
chmod 0644 "$MTLS_ALLOWLIST"

log "certs: OK — CA + PG server/client + daemon server + client-good (curve=${EC_CURVE}, days=${CERT_DAYS})"
log "certs: client-good fingerprint sha256:${FPR}"
