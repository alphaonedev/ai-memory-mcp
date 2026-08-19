#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# enterprise-federation-repro — ONE-COMMAND, IDEMPOTENT standup of the EXACT
# environment the v1.0.0 enterprise-federation audit used.
#
#   stack  -> certs -> keys -> schema-init -> seed -> migrate -> certified daemon
#
# Every step is idempotent (re-running is safe) and every scratch artifact
# lands under $RUN_DIR (gitignored; NEVER /tmp). Nothing is committed.
#
# Prereqs: docker (or a drop-in), openssl, curl, cargo (only if no prebuilt
# ai-memory binary is supplied via AI_MEMORY_BIN or target/release/).
#
# The certified daemon boots ONLY when `ai-memory doctor --posture
# enterprise-federation` reports every control PASS (the boot-refusing gate,
# AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1). If any control fails,
# repro.sh prints the failing controls + remediation and REFUSES to declare
# the substrate certified — degrade/refuse, never falsely claim certified.

set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SELF_DIR/lib.sh"

# --------------------------------------------------------------------------
# 0. Preflight.
# --------------------------------------------------------------------------
command -v openssl >/dev/null 2>&1 || die "openssl not found"
command -v curl    >/dev/null 2>&1 || die "curl not found"
command -v "$CONTAINER_RUNTIME" >/dev/null 2>&1 || die "$CONTAINER_RUNTIME not found (set EF_REPRO_CONTAINER_RUNTIME=podman to use podman)"
DK() { "$CONTAINER_RUNTIME" "$@"; }

log "repro: run dir = $RUN_DIR"
mkdir -p "$RUN_DIR" "$TLS_DIR" "$KEYS_DIR" "$SEED_DIR" "$LOG_DIR" "$REPORTS_DIR" \
         "$DAEMON_KEY_DIR" "$WITNESS_KEY_DIR" "$RECORDER_KEY_DIR" "$JUDGE_KEY_DIR" "$STOPPER_KEY_DIR" \
         "$RUN_DIR/home/.config/ai-memory"

# --------------------------------------------------------------------------
# 1. Resolve or BUILD the ai-memory binary. The certified posture requires
#    the sqlcipher feature (posture control #15) alongside sal-postgres.
# --------------------------------------------------------------------------
if ! BIN="$(resolve_ai_memory_bin)"; then
  command -v cargo >/dev/null 2>&1 || die "no ai-memory binary and no cargo to build one — set AI_MEMORY_BIN to a prebuilt binary built with: --features $CARGO_FEATURES"
  log "repro: building ai-memory (release, --features $CARGO_FEATURES) — this is the slow step"
  ( cd "$REPO_ROOT" && cargo build --release --features "$CARGO_FEATURES" )
  BIN="$(resolve_ai_memory_bin)" || die "build completed but ai-memory binary not found at target/release/ai-memory"
fi
log "repro: ai-memory binary = $BIN ($("$BIN" --version 2>/dev/null || echo '?'))"

# --------------------------------------------------------------------------
# 2. Certs (both encrypted legs). Idempotent — reuses existing material.
# --------------------------------------------------------------------------
"$SELF_DIR/gen-certs.sh"

# --------------------------------------------------------------------------
# 3. Ed25519 key ceremony. Raw 32-byte <label>.priv (0600) + <label>.pub
#    (0644) — the on-disk format src/identity/keypair.rs::save writes. The
#    daemon signing key makes the audit chain SIGNED; the operator +
#    witness + recorder/judge/stopper keys satisfy the asi-hard boot gate
#    and a CLEAN verify-audit-trail. Pubkey pins are URL-safe-no-pad base64.
# --------------------------------------------------------------------------
_ed25519_keypair() {
  # $1 = dir  $2 = label ; writes <label>.priv (32B seed) + <label>.pub (32B)
  local dir="$1" label="$2" pem="$1/.$2.pem"
  if [ -s "$dir/$label.priv" ] && [ -s "$dir/$label.pub" ]; then return 0; fi
  ( umask 077
    openssl genpkey -algorithm ed25519 -out "$pem" 2>/dev/null
    # ed25519 PKCS#8 DER = fixed 16-byte prefix + 32-byte seed → tail -c 32.
    openssl pkey -in "$pem" -outform DER 2>/dev/null | tail -c 32 > "$dir/$label.priv"
    # SubjectPublicKeyInfo DER = 12-byte header + 32-byte pubkey → tail -c 32.
    openssl pkey -in "$pem" -pubout -outform DER 2>/dev/null | tail -c 32 > "$dir/$label.pub"
    rm -f "$pem"
    chmod 0600 "$dir/$label.priv"; chmod 0644 "$dir/$label.pub" )
}
_pubkey_b64url() {
  # base64url-no-pad of a 32-byte raw pubkey file.
  openssl base64 -A -in "$1" 2>/dev/null | tr '+/' '-_' | tr -d '='
}

_ed25519_keypair "$DAEMON_KEY_DIR"   "$DAEMON_AGENT_ID"        # daemon signer (SIGNED chain)
_ed25519_keypair "$WITNESS_KEY_DIR"  "audit-witness"
_ed25519_keypair "$RECORDER_KEY_DIR" "governance-recorder"
_ed25519_keypair "$JUDGE_KEY_DIR"    "governance-judge"
_ed25519_keypair "$STOPPER_KEY_DIR"  "governance-stopper"
_ed25519_keypair "$KEYS_DIR"         "operator"               # asi-hard operator pubkey

WITNESS_PUB="$(_pubkey_b64url "$WITNESS_KEY_DIR/audit-witness.pub")"
RECORDER_PUB="$(_pubkey_b64url "$RECORDER_KEY_DIR/governance-recorder.pub")"
JUDGE_PUB="$(_pubkey_b64url "$JUDGE_KEY_DIR/governance-judge.pub")"
STOPPER_PUB="$(_pubkey_b64url "$STOPPER_KEY_DIR/governance-stopper.pub")"
OPERATOR_PUB="$(_pubkey_b64url "$KEYS_DIR/operator.pub")"
log "repro: key ceremony OK (daemon + witness + recorder/judge/stopper + operator)"

# --------------------------------------------------------------------------
# 4. PG password (minted once, 0600, never echoed).
# --------------------------------------------------------------------------
if [ ! -s "$PG_PASSWORD_FILE" ]; then
  ( umask 077; pw="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 48 || true)"
    printf '%s' "$pw" >"$PG_PASSWORD_FILE" )
  chmod 0600 "$PG_PASSWORD_FILE"
  log "repro: minted PG password ($PG_PASSWORD_FILE, 0600)"
else
  log "repro: reusing PG password"
fi

# --------------------------------------------------------------------------
# 5. PG image — build from the CANONICAL docker-1461 Dockerfile (extend, do
#    not fork). Pins arrive as --build-arg from the docker-1461 SSOT. Skipped
#    when the image already exists (override with EF_REPRO_FORCE_REBUILD=1).
# --------------------------------------------------------------------------
if [ "${EF_REPRO_FORCE_REBUILD:-0}" = "1" ] || ! DK image inspect "$PG_IMAGE" >/dev/null 2>&1; then
  [ -f "$DOCKER_1461_DOCKERFILE" ] || die "canonical Dockerfile missing: $DOCKER_1461_DOCKERFILE"
  log "repro: building $PG_IMAGE from $DOCKER_1461_DOCKERFILE (PG $PG_APT_VERSION + AGE $AGE_APT_VERSION + pgvector $PGVECTOR_APT_VERSION)"
  DK build \
    --build-arg "AGE_BASE_IMAGE=$AGE_BASE_IMAGE" \
    --build-arg "PG_MAJOR=$PG_MAJOR" \
    --build-arg "PG_APT_VERSION=$PG_APT_VERSION" \
    --build-arg "AGE_APT_VERSION=$AGE_APT_VERSION" \
    --build-arg "PGVECTOR_APT_VERSION=$PGVECTOR_APT_VERSION" \
    -f "$DOCKER_1461_DOCKERFILE" -t "$PG_IMAGE" \
    "$(dirname "$DOCKER_1461_DOCKERFILE")"
else
  log "repro: reusing PG image $PG_IMAGE"
fi

# --------------------------------------------------------------------------
# 6. Run the PG tier (TLS 1.3, hostssl-only, client-cert mTLS enforced).
#    The entrypoint wrapper installs the bind-mounted server cert/key to a
#    postgres-OWNED path (PG refuses an ssl_key_file it does not own), then
#    hands the `postgres ... ssl GUCs` command to the stock entrypoint.
# --------------------------------------------------------------------------
_pg_running() { [ "$(DK inspect -f '{{.State.Running}}' "$PG_CONTAINER" 2>/dev/null)" = "true" ]; }
_pg_exists()  { DK inspect "$PG_CONTAINER" >/dev/null 2>&1; }

if _pg_running; then
  log "repro: PG container $PG_CONTAINER already running — reusing"
elif _pg_exists; then
  log "repro: starting existing PG container $PG_CONTAINER"
  DK start "$PG_CONTAINER" >/dev/null
else
  log "repro: launching PG container $PG_CONTAINER on 127.0.0.1:$PG_PORT"
  PGPW="$(pg_password)"
  DK run -d --name "$PG_CONTAINER" \
    -e POSTGRES_USER="$PG_USER" \
    -e POSTGRES_PASSWORD="$PGPW" \
    -e POSTGRES_DB="$PG_DB" \
    -e POSTGRES_INITDB_ARGS="--data-checksums" \
    -e PGDATA=/var/lib/postgresql/data/pgdata \
    -e PGUSER="$PG_USER" -e PGDATABASE="$PG_DB" \
    -p "127.0.0.1:${PG_PORT}:5432" \
    -v "${PG_VOLUME}:/var/lib/postgresql/data" \
    -v "${PG_SERVER_CERT}:/certs/server.pem:ro" \
    -v "${PG_SERVER_KEY}:/certs/server.key:ro" \
    -v "${CA_CERT}:/certs/ca.pem:ro" \
    -v "${SELF_DIR}/initdb/pg_hba.conf:${PG_HBA_CONTAINER_PATH}:ro" \
    -v "${SELF_DIR}/initdb/01-extensions.sql:${PG_INIT_SQL_CONTAINER_PATH}:ro" \
    -v "${DOCKER_1461_HEALTHCHECK}:/usr/local/bin/pg-hostssl-healthcheck.sh:ro" \
    --entrypoint /bin/bash \
    "$PG_IMAGE" \
    -c "install -d -o postgres -g postgres -m 0750 ${PG_TLS_INSTALL_DIR} && \
        install -o postgres -g postgres -m 0644 /certs/server.pem ${PG_TLS_INSTALL_DIR}/server.pem && \
        install -o postgres -g postgres -m 0600 /certs/server.key ${PG_TLS_INSTALL_DIR}/server.key && \
        exec /usr/local/bin/docker-entrypoint.sh \"\$@\"" bash \
      postgres \
        -c shared_preload_libraries=age \
        -c ssl=on \
        -c "ssl_cert_file=${PG_TLS_INSTALL_DIR}/server.pem" \
        -c "ssl_key_file=${PG_TLS_INSTALL_DIR}/server.key" \
        -c ssl_ca_file=/certs/ca.pem \
        -c ssl_min_protocol_version=TLSv1.2 \
        -c "hba_file=${PG_HBA_CONTAINER_PATH}" >/dev/null
fi

# Gate on the fail-CLOSED hostssl healthcheck (proves cleartext is refused
# pre-auth — a silent cleartext disarm fails the wait, never a false ready).
log "repro: waiting for PG hostssl-armed health"
_ok=0
for _t in $(seq 1 60); do
  if DK exec "$PG_CONTAINER" /usr/local/bin/pg-hostssl-healthcheck.sh >/dev/null 2>&1; then _ok=1; break; fi
  sleep 2
done
[ "$_ok" = 1 ] || die "PG did not become hostssl-armed healthy — check '$CONTAINER_RUNTIME logs $PG_CONTAINER'"
log "repro: PG healthy (hostssl armed, cleartext refused pre-auth)"

# --------------------------------------------------------------------------
# 7. Render the store-url secret file (0600) + the certified posture env.
#    The posture env EXTENDS the checked-in docs/deploy/enterprise-federation.env
#    (only its KEY=VALUE assignments) + appends the per-deployment values.
# --------------------------------------------------------------------------
( umask 077; store_dsn >"$STORE_URL_FILE" )
chmod 0600 "$STORE_URL_FILE"

# Peer fingerprint pin file (posture control #10 needs a readable file). A
# single self-referential parseable pin — this single-node audit runs no
# outbound federation, so the pin is present-and-valid but unused.
PEER_FP_FILE="$RUN_DIR/peer-fingerprints.pins"
DAEMON_FPR="$(openssl x509 -in "$DAEMON_SERVER_CERT" -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null | sed -E 's/^.*= *//' | tr '[:upper:]' '[:lower:]')"
{
  printf '# enterprise-federation-repro peer server-cert pin file (posture #10).\n'
  printf '# Single-node audit: present + parseable, no outbound federation uses it.\n'
  printf '%s %s\n' "$DAEMON_HOST" "$DAEMON_FPR"
} >"$PEER_FP_FILE"
chmod 0644 "$PEER_FP_FILE"

TEMPLATE_ENV="$REPO_ROOT/docs/deploy/enterprise-federation.env"
[ -f "$TEMPLATE_ENV" ] || die "certified posture template missing: $TEMPLATE_ENV"
{
  printf '# GENERATED by repro.sh from docs/deploy/enterprise-federation.env + per-deployment values.\n'
  printf '# DO NOT COMMIT (embeds no secret, but is run-dir scoped).\n\n'
  printf '# --- inherited certified posture (KEY=VALUE lines of the checked-in template) ---\n'
  grep -E '^[A-Z_]+=' "$TEMPLATE_ENV"
  printf '\n# --- per-deployment values (posture controls #9/#10/#11-12 + audit custody) ---\n'
  printf 'AI_MEMORY_FED_TRUST_DOMAIN=%s\n' "$FED_TRUST_DOMAIN"
  printf 'AI_MEMORY_FED_PEER_FINGERPRINTS=%s\n' "$PEER_FP_FILE"
  # Valid JSON, one peer scoped to a REAL namespace (never a bare `**`).
  printf 'AI_MEMORY_FED_PEER_ATTESTATION={"peer-a@%s":{"allowed_namespaces":["%s/*"]}}\n' \
    "$FED_TRUST_DOMAIN" "$SEED_NAMESPACE"
  printf '\n# --- audit custody key dirs + K1 pubkey pins ---\n'
  printf 'AI_MEMORY_KEY_DIR=%s\n' "$DAEMON_KEY_DIR"
  printf 'AI_MEMORY_WITNESS_KEY_DIR=%s\n' "$WITNESS_KEY_DIR"
  printf 'AI_MEMORY_WITNESS_PUBKEY=%s\n' "$WITNESS_PUB"
  printf 'AI_MEMORY_RECORDER_KEY_DIR=%s\n' "$RECORDER_KEY_DIR"
  printf 'AI_MEMORY_RECORDER_PUBKEY=%s\n' "$RECORDER_PUB"
  printf 'AI_MEMORY_JUDGE_KEY_DIR=%s\n' "$JUDGE_KEY_DIR"
  printf 'AI_MEMORY_JUDGE_PUBKEY=%s\n' "$JUDGE_PUB"
  printf 'AI_MEMORY_STOPPER_KEY_DIR=%s\n' "$STOPPER_KEY_DIR"
  printf 'AI_MEMORY_STOPPER_PUBKEY=%s\n' "$STOPPER_PUB"
  printf 'AI_MEMORY_OPERATOR_PUBKEY=%s\n' "$OPERATOR_PUB"
  printf '\n# --- daemon identity + the encrypted store link (non-argv channel) ---\n'
  printf 'AI_MEMORY_AGENT_ID=%s\n' "$DAEMON_AGENT_ID"
  printf 'AI_MEMORY_STORE_URL_FILE=%s\n' "$STORE_URL_FILE"
  # Local MiniLM (all-MiniLM-L6-v2, 384-d) under loopback-only egress — the
  # audit embedder. OFFLINE forces the local candle path (no vendor egress).
  printf 'AI_MEMORY_EMBED_OFFLINE=1\n'
  # at-rest control #15: a passphrase for any incidental local sqlite open
  # (the memory store is postgres, so this is belt-and-suspenders). See the
  # repro doc §at-rest for the honest pg-tier caveat (#3061).
  printf 'AI_MEMORY_DB_PASSPHRASE_FILE=%s\n' "$RUN_DIR/db.passphrase"
} >"$POSTURE_ENV_FILE"
chmod 0600 "$POSTURE_ENV_FILE"
# The at-rest passphrase (0400) — required whenever ENCRYPT_AT_REST is on.
if [ ! -s "$RUN_DIR/db.passphrase" ]; then
  ( umask 077; LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 48 >"$RUN_DIR/db.passphrase" || true )
  chmod 0400 "$RUN_DIR/db.passphrase"
fi

# A kit-isolated HOME so the daemon reads OUR config (tier=semantic → the
# local MiniLM embedder), never the operator's real ~/.config.
cat >"$RUN_DIR/home/.config/ai-memory/config.toml" <<TOML
# GENERATED by repro.sh — kit-isolated daemon config.
schema_version = 2
tier = "semantic"
TOML

# --------------------------------------------------------------------------
# 8. schema-init over the encrypted store link (creates the app schema +
#    AGE create_graph('memory_graph'); idempotent).
# --------------------------------------------------------------------------
DSN="$(store_dsn)"
log "repro: schema-init (embedding-dim $EMBED_DIM) over verify-full TLS + client-cert mTLS"
AI_MEMORY_NO_CONFIG=1 "$BIN" schema-init --store-url "$DSN" --embedding-dim "$EMBED_DIM"

# --------------------------------------------------------------------------
# 9. Deterministic seed corpus (sqlite) + migrate into the pg tier verbatim.
# --------------------------------------------------------------------------
AI_MEMORY_BIN="$BIN" "$SELF_DIR/seed-corpus.sh"
log "repro: migrate seed corpus -> pg tier (memories + links + embeddings verbatim, #3054/#3060)"
AI_MEMORY_NO_CONFIG=1 "$BIN" migrate --from "sqlite://${SEED_DB}" --to "$DSN" --batch 1000

# --------------------------------------------------------------------------
# 10. Certified-posture readout BEFORE serving. The daemon's boot-refusing
#     gate refuses to start unless every control passes; so gate here too and
#     print the readout either way (fail-loud, never falsely certified).
# --------------------------------------------------------------------------
log "repro: ai-memory doctor --posture enterprise-federation"
set -a; . "$POSTURE_ENV_FILE"; set +a
export HOME="$RUN_DIR/home"
if AI_MEMORY_NO_CONFIG=1 "$BIN" doctor --posture enterprise-federation >"$REPORTS_DIR/doctor-posture.txt" 2>&1; then
  log "repro: doctor --posture enterprise-federation = ALL PASS"
else
  warn "repro: doctor --posture reported one or more FAIL controls — the certified daemon will NOT boot:"
  cat "$REPORTS_DIR/doctor-posture.txt" >&2 || true
  die "refusing to declare the substrate certified while a posture control fails (see $REPORTS_DIR/doctor-posture.txt + remediation lines above)"
fi

# --------------------------------------------------------------------------
# 11. Start the certified daemon (client<->daemon mTLS API :9077) under the
#     full posture env. Backgrounded with a pid + log. Idempotent.
# --------------------------------------------------------------------------
if [ -s "$DAEMON_PID_FILE" ] && kill -0 "$(cat "$DAEMON_PID_FILE")" 2>/dev/null; then
  log "repro: certified daemon already running (pid $(cat "$DAEMON_PID_FILE"))"
else
  log "repro: starting certified daemon on https://${DAEMON_HOST}:${DAEMON_PORT} (mTLS)"
  # HOME + posture env already exported above; serve reads the store from
  # AI_MEMORY_STORE_URL_FILE (non-argv secure channel), binds mTLS on :9077.
  nohup "$BIN" serve \
    --host "$DAEMON_HOST" --port "$DAEMON_PORT" \
    --tls-cert "$DAEMON_SERVER_CERT" --tls-key "$DAEMON_SERVER_KEY" \
    --mtls-allowlist "$MTLS_ALLOWLIST" \
    >"$DAEMON_LOG" 2>&1 &
  echo $! >"$DAEMON_PID_FILE"
  log "repro: certified daemon pid $(cat "$DAEMON_PID_FILE") (log: $DAEMON_LOG)"
fi

# Wait for the mTLS health endpoint.
log "repro: waiting for daemon mTLS health"
_ok=0
for _t in $(seq 1 45); do
  if api_curl GET /api/v1/health >/dev/null 2>&1 && [ -n "$(api_curl GET /api/v1/health)" ]; then _ok=1; break; fi
  # bail early if the daemon died
  if [ -s "$DAEMON_PID_FILE" ] && ! kill -0 "$(cat "$DAEMON_PID_FILE")" 2>/dev/null; then
    warn "repro: daemon exited — last 40 log lines:"; tail -40 "$DAEMON_LOG" >&2 || true
    die "certified daemon failed to stay up (see $DAEMON_LOG)"
  fi
  sleep 2
done
[ "$_ok" = 1 ] || { tail -40 "$DAEMON_LOG" >&2 || true; die "daemon mTLS health did not come up (see $DAEMON_LOG)"; }

log "repro: OK — certified enterprise-federation substrate is LIVE"
log "repro:   PG tier   : ${PG_HOST}:${PG_PORT} (PG ${EXPECTED_PG_VERSION} + AGE ${EXPECTED_AGE_VERSION} + pgvector ${EXPECTED_PGVECTOR_VERSION}, hostssl+mTLS)"
log "repro:   daemon API: https://${DAEMON_HOST}:${DAEMON_PORT} (client<->daemon mTLS, agent=${DAEMON_AGENT_ID})"
log "repro:   verify    : $SELF_DIR/verify.sh"
