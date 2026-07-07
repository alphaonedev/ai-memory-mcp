#!/usr/bin/env bash
# =============================================================================
# gen-certs.sh — crypto material for the v0.9.0 "crypto-hardened DO round".
# =============================================================================
# Produces, under $OUT_DIR (default ./out), everything the three encryption
# legs need:
#
#   ca.crt / ca.key                 Root CA that signs every leaf below.
#   server.crt / server.key         Daemon HTTPS/mTLS server cert.
#                                     SANs: 127.0.0.1, ::1, localhost + $EXTRA_SAN*.
#   client-good.crt / .key          Authorised API client (goes on the allowlist).
#   client-bad.crt  / .key          Well-formed cert NOT on the allowlist (negative).
#   peerA.crt/.key  peerB.crt/.key  Federation node server+client certs (leg 2).
#   pg-server.crt / pg-server.key   Postgres server cert (leg 3). CN/SAN = $PG_HOST.
#   allowlist.txt                   SHA-256(DER) of client-good  (API mTLS allowlist).
#   peerA.allowlist / peerB.allowlist  each peer pins the OTHER peer's client cert.
#   fingerprints.txt                Human-readable index of every fingerprint.
#
# The daemon's mTLS verifier (src/tls.rs::FingerprintAllowlistVerifier) pins
# SHA-256 over the raw client-cert DER — identical to
#   openssl x509 -in <cert> -outform DER | openssl dgst -sha256
# CA chain is intentionally IGNORED by the verifier (SSH known_hosts model),
# so client-bad is signed by the SAME CA yet is still refused: proof the pin,
# not the CA, is the trust anchor.
#
# Postgres verify-full DOES use the CA chain + hostname, so pg-server is CA-
# signed and its SAN must match the host the daemon connects to ($PG_HOST).
#
# Ed25519 leaf keys (fast, small). Postgres/rustls both accept them.
# Usage:
#   ./gen-certs.sh                        # localhost-only material
#   EXTRA_SAN_IP=167.71.175.191 EXTRA_SAN_DNS=hive-substrate \
#   PG_HOST=10.20.0.5 ./gen-certs.sh      # add DO substrate SANs
# =============================================================================
set -euo pipefail

OUT_DIR="${OUT_DIR:-$(cd "$(dirname "$0")" && pwd)/out}"
DAYS="${DAYS:-825}"
PG_HOST="${PG_HOST:-localhost}"        # host the daemon uses in the postgres URL
EXTRA_SAN_IP="${EXTRA_SAN_IP:-}"       # e.g. the DO substrate private IP
EXTRA_SAN_DNS="${EXTRA_SAN_DNS:-}"     # e.g. hive-substrate

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

fp() { openssl x509 -in "$1" -outform DER | openssl dgst -sha256 | awk '{print $NF}'; }

# --- Root CA -----------------------------------------------------------------
openssl genpkey -algorithm ed25519 -out ca.key
openssl req -x509 -new -key ca.key -days "$DAYS" -out ca.crt \
  -subj "/CN=ai-memory-do-round-CA"

# helper: mint a leaf cert <name> <CN> <SAN-extfile-body>
mint() {
  local name="$1" cn="$2" san="$3"
  openssl genpkey -algorithm ed25519 -out "${name}.key"
  openssl req -new -key "${name}.key" -out "${name}.csr" -subj "/CN=${cn}"
  cat > "${name}.ext" <<EOF
subjectAltName=${san}
EOF
  openssl x509 -req -in "${name}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "$DAYS" -out "${name}.crt" -extfile "${name}.ext"
  rm -f "${name}.csr" "${name}.ext"
  chmod 600 "${name}.key"
}

# --- Daemon server cert (API mTLS, leg 1) ------------------------------------
SERVER_SAN="DNS:localhost,IP:127.0.0.1,IP:0:0:0:0:0:0:0:1"
[ -n "$EXTRA_SAN_IP" ]  && SERVER_SAN="${SERVER_SAN},IP:${EXTRA_SAN_IP}"
[ -n "$EXTRA_SAN_DNS" ] && SERVER_SAN="${SERVER_SAN},DNS:${EXTRA_SAN_DNS}"
mint server "ai-memory-daemon" "$SERVER_SAN"

# --- API clients (leg 1) -----------------------------------------------------
mint client-good "api-client-good" "DNS:api-client-good"
mint client-bad  "api-client-bad"  "DNS:api-client-bad"

# --- Federation peers (leg 2): each peer has ONE cert used both as its server
#     cert and its outbound client cert. -----------------------------------
PEERA_SAN="DNS:localhost,IP:127.0.0.1"; PEERB_SAN="DNS:localhost,IP:127.0.0.1"
[ -n "$EXTRA_SAN_IP" ] && { PEERA_SAN="${PEERA_SAN},IP:${EXTRA_SAN_IP}"; PEERB_SAN="${PEERB_SAN},IP:${EXTRA_SAN_IP}"; }
mint peerA "ai-memory-peerA" "$PEERA_SAN"
mint peerB "ai-memory-peerB" "$PEERB_SAN"

# --- Postgres server cert (leg 3) -------------------------------------------
# verify-full checks hostname == cert SAN/CN, so CN + SAN must be $PG_HOST.
PG_SAN="DNS:${PG_HOST}"
case "$PG_HOST" in *[0-9].[0-9]*) PG_SAN="IP:${PG_HOST},DNS:${PG_HOST}";; esac
mint pg-server "$PG_HOST" "$PG_SAN"
# postgres wants key owned by the postgres user, mode 0600; caller chowns.

# --- Allowlists --------------------------------------------------------------
fp client-good.crt > allowlist.txt      # API mTLS: only client-good is trusted
fp peerB.crt > peerA.allowlist          # peerA trusts peerB's client cert
fp peerA.crt > peerB.allowlist          # peerB trusts peerA's client cert

# --- Index -------------------------------------------------------------------
{
  echo "# fingerprints (SHA-256 of cert DER) generated $(date -u)"
  for c in server client-good client-bad peerA peerB pg-server; do
    printf '%-14s %s\n' "$c" "$(fp ${c}.crt)"
  done
} > fingerprints.txt

echo "OK — crypto material in $OUT_DIR"
cat fingerprints.txt
