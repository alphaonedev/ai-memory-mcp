#!/bin/sh
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# #3705 — "only encrypted data in transit": one-shot TLS provisioner for
# the LAN-parity stack (and any compose fleet with the same shape).
#
# Under #3705 the daemon refuses every plaintext hop: the listener serves
# TLS only, federation peers must be https://, and the PostgreSQL DSN must
# pin `sslmode=verify-full&sslrootcert=<ca>` at the connect funnel. The
# former `AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS=1` acknowledgement this stack
# used to carry is a REMOVED downgrade path (a truthy value refuses boot),
# so the fleet needs real certificates. This script mints them into the
# shared `ic-parity-tls` volume, mounted read-only at /tls by every other
# service:
#
#   /tls/ca.pem                 the fleet CA (public half; daemons + host trust it)
#   /tls/ca.key                 CA private key (root, 0600; never mounted elsewhere)
#   /tls/pg/server.crt|.key     PostgreSQL server pair, SAN DNS:pg-age, DNS:localhost,
#                               IP:127.0.0.1 (host-loopback 15432 mapping), owned by
#                               uid 999 (`postgres` in the image), key 0600 — postgres
#                               refuses a key it does not own or that is group-readable
#   /tls/<daemon>/server.pem|.key   the daemon's listener pair (SAN DNS:<daemon>, IP:127.0.0.1)
#   /tls/<daemon>/client.pem|.key   the daemon's quorum-client pair (SAN DNS:<daemon>)
#   /tls/<daemon>/ca.pem            copy of the CA — entrypoint.plan-c.sh passes it as
#                                   --quorum-ca-cert only when a client pair is present
#
# entrypoint.plan-c.sh reads `AI_MEMORY_TLS_DIR` (default /etc/ai-memory-a2a/tls)
# for exactly these names: server.pem, server.key, client.pem, client.key,
# ca.pem. Each daemon service sets AI_MEMORY_TLS_DIR=/tls/<its hostname>.
#
# Idempotent: an existing /tls/ca.pem is reused (re-running `compose up`
# must not rotate the fleet CA under running daemons). Set
# PROVISION_TLS_FORCE=1 to regenerate everything.
#
# Runs in the ai-memory-pg-age-vector image (Debian, `openssl` installed by
# Dockerfile.pg-age-vector) as root. POSIX sh — no bashisms.

set -eu

OUT="${TLS_OUT_DIR:-/tls}"
DAEMONS="${TLS_DAEMONS:?missing TLS_DAEMONS (space-separated daemon hostnames)}"
PG_HOST="${TLS_PG_HOST:-pg-age}"
PG_UID="${TLS_PG_UID:-999}"
DAYS="${TLS_DAYS:-825}"
FORCE="${PROVISION_TLS_FORCE:-0}"

log() { echo "[provision-tls] $*"; }

mkdir -p "$OUT"
if [ -f "$OUT/ca.pem" ] && [ "$FORCE" != 1 ]; then
  log "CA already present at $OUT/ca.pem — reusing (PROVISION_TLS_FORCE=1 to rotate)"
else
  log "minting fleet CA"
  openssl genpkey -algorithm ed25519 -out "$OUT/ca.key"
  chmod 600 "$OUT/ca.key"
  openssl req -x509 -new -key "$OUT/ca.key" -days "$DAYS" \
    -subj "/CN=ai-memory lan-parity fleet CA (#3705)" -out "$OUT/ca.pem"
  chmod 644 "$OUT/ca.pem"
fi

# issue <dir> <basename> <cn> <san-list>
issue() {
  dir="$1"; base="$2"; cn="$3"; san="$4"
  mkdir -p "$dir"
  if [ -f "$dir/$base.crt" ] && [ "$FORCE" != 1 ]; then
    log "$dir/$base.crt present — keeping"
    return 0
  fi
  openssl genpkey -algorithm ed25519 -out "$dir/$base.key"
  chmod 600 "$dir/$base.key"
  openssl req -new -key "$dir/$base.key" -subj "/CN=$cn" -out "$dir/$base.csr"
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=CA:FALSE\n' "$san" \
    > "$dir/$base.ext"
  openssl x509 -req -in "$dir/$base.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" \
    -CAcreateserial -days "$DAYS" -extfile "$dir/$base.ext" -out "$dir/$base.crt"
  rm -f "$dir/$base.csr" "$dir/$base.ext"
  chmod 644 "$dir/$base.crt"
  log "issued $dir/$base.crt (SAN $san)"
}

# PostgreSQL server pair. The host-side cargo run reaches the container on
# 127.0.0.1:15432, so the IP SAN and DNS:localhost are load-bearing for
# `sslmode=verify-full` from the host as well as from the bridge.
issue "$OUT/pg" server "$PG_HOST" "DNS:$PG_HOST,DNS:localhost,IP:127.0.0.1"
chown -R "$PG_UID:$PG_UID" "$OUT/pg"
chmod 700 "$OUT/pg"
chmod 600 "$OUT/pg/server.key"

for d in $DAEMONS; do
  issue "$OUT/$d" server "$d" "DNS:$d,DNS:localhost,IP:127.0.0.1"
  issue "$OUT/$d" client "$d" "DNS:$d"
  # entrypoint.plan-c.sh names: server.pem/server.key/client.pem/client.key/ca.pem
  cp "$OUT/$d/server.crt" "$OUT/$d/server.pem"
  cp "$OUT/$d/client.crt" "$OUT/$d/client.pem"
  cp "$OUT/ca.pem" "$OUT/$d/ca.pem"
  chmod 644 "$OUT/$d/server.pem" "$OUT/$d/client.pem" "$OUT/$d/ca.pem"
  # The daemons run as root in their image: root-owned 0600 keys are readable.
  chmod 600 "$OUT/$d/server.key" "$OUT/$d/client.key"
done

log "done — CA fingerprint (sha256 DER): $(openssl x509 -in "$OUT/ca.pem" -outform DER | openssl dgst -sha256 | awk '{print $NF}')"
