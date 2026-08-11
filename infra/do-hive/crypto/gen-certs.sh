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
# Key algorithm: RSA (CA 4096 / leaf 2048), matching the certified pg-TLS lane
# deploy/do-1461/provision/15_tls.sh. This is NOT a "fast/small" nicety — it is
# REQUIRED for the Postgres leg. Under sslmode=verify-full + scram-sha-256 with
# channel binding (tls-server-end-point, RFC 5929), libpq hashes the server
# certificate using the digest named in its signatureAlgorithm. An Ed25519
# certificate has NO such digest (its signatureAlgorithm carries no separate
# hash OID), so libpq aborts the handshake with
#   "could not find digest for NID UNDEF"
# before it ever authenticates. RSA/SHA-256 (and EC/P-256/SHA-256) carry a real
# digest and bind cleanly. rustls (the API/federation mTLS legs) accepts RSA
# leaves just as it did Ed25519, so one RSA chain serves every leg. See
# test-pg-verifyfull.sh's scram+channel-binding leg for the guarding regression.
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
# RSA/SHA-256 chain (see header): required for the pg scram + channel-binding
# leg, accepted by rustls for the mTLS legs.
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -sha256 -days "$DAYS" -out ca.crt \
  -subj "/CN=ai-memory-do-round-CA"

# helper: mint a leaf cert <name> <CN> <SAN-extfile-body>
mint() {
  local name="$1" cn="$2" san="$3"
  openssl genrsa -out "${name}.key" 2048
  openssl req -new -key "${name}.key" -out "${name}.csr" -subj "/CN=${cn}"
  cat > "${name}.ext" <<EOF
subjectAltName=${san}
EOF
  openssl x509 -req -in "${name}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "$DAYS" -sha256 -out "${name}.crt" -extfile "${name}.ext"
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

# --- Track D hive nodes (ADDITIVE; skipped unless HIVE_NODE_IPS is set) ------
# HIVE_NODE_IPS="10.20.0.5 10.20.0.6" mints one leaf per DO memory droplet
# (hive-node-1..N, CN = the droplet name, SAN = localhost + 127.0.0.1 + that
# node's PRIVATE VPC ip) and writes a per-node allowlist. Unset => this block
# does nothing and the output is byte-identical to the legacy
# localhost/peerA/peerB set, so every existing crypto leg keeps its exact
# material.
#
# Each hive-node-N.allowlist pins exactly TWO classes of fingerprint, and no
# more -- every additional entry is one more key whose loss opens the mesh:
#   * every OTHER node  -- the mutually authenticated quorum channel
#   * the node ITSELF   -- its own client cert is the ONLY one it holds, and
#                          both the on-droplet fed-bootstrap and federate.sh's
#                          post-boot assertions probe :9077 with it (the
#                          assertions run ON a node over ssh, because the
#                          peer URLs are PRIVATE VPC addresses that are not
#                          routable from the orchestrator host). Trusting your
#                          own client cert grants an attacker nothing new:
#                          holding it means already holding the server key
#                          sitting beside it.
# There is deliberately NO separate operator/bastion client cert: nothing needs
# one, and an unused trust anchor is a liability, not a convenience.
if [ -n "${HIVE_NODE_IPS:-}" ]; then
  hive_idx=0
  for hive_ip in $HIVE_NODE_IPS; do
    hive_idx=$((hive_idx + 1))
    mint "hive-node-$hive_idx" "ai-memory-hive-memory-$hive_idx" \
      "DNS:localhost,IP:127.0.0.1,IP:$hive_ip"
  done

  hive_total=$hive_idx
  hive_idx=0
  for _hive_ip in $HIVE_NODE_IPS; do
    hive_idx=$((hive_idx + 1))
    : > "hive-node-$hive_idx.allowlist"
    hive_j=0
    while [ "$hive_j" -lt "$hive_total" ]; do
      hive_j=$((hive_j + 1))
      fp "hive-node-$hive_j.crt" >> "hive-node-$hive_idx.allowlist"
    done
  done

  {
    echo "# Track D hive-node fingerprints generated $(date -u)"
    hive_idx=0
    for _hive_ip in $HIVE_NODE_IPS; do
      hive_idx=$((hive_idx + 1))
      printf '%-14s %s\n' "hive-node-$hive_idx" "$(fp "hive-node-$hive_idx.crt")"
    done
  } >> fingerprints.txt
fi

echo "OK — crypto material in $OUT_DIR"
cat fingerprints.txt
