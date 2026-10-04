#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Stand up the federated peer DB substrate: Docker + a pinned PG16/AGE/pgvector
# image, localhost-bound, persistent volume, then the idempotent SQL bootstrap
# + ai-memory schema-init (v55 + ai_memory_kg graph). Peers only.
#
# Secret handling: a single fleet PG password is generated once into the
# gitignored run dir (mode 0600) and never written to a committed file or
# echoed. It reaches the peers over ssh STDIN into 0600 files, and from those
# files into docker (--env-file), psql (\getenv in bootstrap.sql) and
# schema-init (AI_MEMORY_STORE_URL_FILE) — never as an argv word on this host,
# on the peer (the ssh remote command string is argv there), or in docker's
# process list (#4603, #4617).
source "$(dirname "$0")/lib.sh"

# #4797: schema-init reads AI_MEMORY_STORE_URL_FILE only from 1.0.0. Refuse
# (fail closed) before any Postgres secret is generated or staged on a peer.
require_schema_init_store_url_channel

SECRETS_DIR="$RUN_DIR/secrets"; mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"
PG_PW_FILE="$SECRETS_DIR/pg.pw"
SU_PW_FILE="$SECRETS_DIR/pg-super.pw"
if [ ! -s "$PG_PW_FILE" ]; then openssl rand -hex 24 > "$PG_PW_FILE"; chmod 600 "$PG_PW_FILE"; log "generated aimemory PG password -> $PG_PW_FILE"; fi
if [ ! -s "$SU_PW_FILE" ]; then openssl rand -hex 24 > "$SU_PW_FILE"; chmod 600 "$SU_PW_FILE"; log "generated postgres superuser password -> $SU_PW_FILE"; fi
PG_PW="$(cat "$PG_PW_FILE")"
SU_PW="$(cat "$SU_PW_FILE")"

# put_secret <ip> <remote-path>: write STDIN to a 0600 root-only file on the peer.
# ssh_node uses -n (no stdin), so this talks to ssh directly; the path is the
# only argv, the secret travels on stdin.
put_secret() {
  # shellcheck disable=SC2086
  ssh $SSH_OPTS "root@${1}" "umask 077; cat > '$2'"
}

DOCKERFILE="$HIVE_ROOT/provision/pg-age/Dockerfile"
BOOTSTRAP="$HIVE_ROOT/provision/pg-age/bootstrap.sql"
SECRET_DIR="/opt/hive/pg-age/.secrets"
TLS_DIR="/opt/hive/pg-age/tls"
# Data volume and TLS mount shared by the init container and its recreate.
PG_RUN_ARGS="--name hive-pg-age --restart unless-stopped -p 127.0.0.1:5432:5432 -v hive-pgdata:/var/lib/postgresql/data -v '$TLS_DIR':/tls:ro"
PG_SSL_ARGS="-c ssl=on -c ssl_cert_file=/tls/server.crt -c ssl_key_file=/tls/server.key"

# #4897: the peer-side secret files must not outlive an iteration on ANY exit
# path (set -e failure, die, signal), so they are removed from an EXIT trap,
# not only at the end of the happy path. #4896: a container that still carries
# the init-only superuser environment is removed on the failure path too (the
# data volume is kept; a re-run recreates the container).
cleanup_peer() {
  if [ "${SU_ENV_CONTAINER:-0}" = 1 ]; then
    ssh_node "$ip" "docker rm -f hive-pg-age >/dev/null 2>&1" || true
  fi
  ssh_node "$ip" "rm -rf '$SECRET_DIR'" || true
}

# The loop body runs in THIS shell (not a pipeline subshell) so the EXIT trap
# fires on every failure path; bash does not run an EXIT trap set inside an
# implicit pipeline subshell on a set -e exit (#4897, measured).
PEER_IPS="$(inv_ips_by_role peer)"
while read -r ip; do
  [ -n "$ip" ] || continue
  host="$(inv_name_for_ip "$ip")"
  SU_ENV_CONTAINER=0
  trap cleanup_peer EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  log "[$host] installing docker + building pinned PG/AGE/pgvector image"
  ssh_node "$ip" "command -v docker >/dev/null 2>&1 || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io); systemctl enable --now docker"
  ssh_node "$ip" "mkdir -p /opt/hive/pg-age"
  scp_to "$DOCKERFILE" "$ip" "/opt/hive/pg-age/Dockerfile"
  scp_to "$BOOTSTRAP" "$ip" "/opt/hive/pg-age/bootstrap.sql"
  ssh_node "$ip" "docker build --build-arg AGE_IMAGE='$AGE_IMAGE' -t hive-pg-age:local /opt/hive/pg-age" >/dev/null

  ssh_node "$ip" "umask 077; mkdir -p '$SECRET_DIR'; chmod 0700 '$SECRET_DIR'"
  printf 'POSTGRES_PASSWORD=%s\n' "$SU_PW" | put_secret "$ip" "$SECRET_DIR/su-init.env"
  printf 'PGPASSWORD=%s\nAIMEMORY_PW=%s\n' "$SU_PW" "$PG_PW" | put_secret "$ip" "$SECRET_DIR/psql.env"
  # #4860 / #3705: ai-memory refuses a Postgres DSN that does not pin
  # sslmode=verify-full, loopback included.
  printf 'postgres://aimemory:%s@127.0.0.1:5432/aimemory?sslmode=verify-full&sslrootcert=%s/ca.crt\n' "$PG_PW" "$TLS_DIR" \
    | put_secret "$ip" "$SECRET_DIR/store-url"

  # #4860: a peer-local CA signs a server certificate for IP 127.0.0.1; the CA
  # key stays root-only on the peer, the server key is handed to the
  # container's postgres uid (999), read-only.
  log "[$host] issuing the peer-local Postgres TLS CA and server certificate (127.0.0.1)"
  ssh_node "$ip" "set -e; umask 077; mkdir -p '$TLS_DIR'; cd '$TLS_DIR'; \
    [ -s ca.key ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
      -subj '/CN=hive-pg-age-ca' -keyout ca.key -out ca.crt 2>/dev/null; \
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj '/CN=127.0.0.1' \
      -keyout server.key -out server.csr 2>/dev/null; \
    printf 'subjectAltName=IP:127.0.0.1\\nbasicConstraints=CA:FALSE\\nkeyUsage=digitalSignature,keyEncipherment\\nextendedKeyUsage=serverAuth\\n' > server.ext; \
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 \
      -extfile server.ext -out server.crt 2>/dev/null; \
    rm -f server.csr server.ext; chown 999:999 server.key server.crt; chmod 0600 server.key ca.key; \
    chmod 0644 server.crt ca.crt; chmod 0755 '$TLS_DIR'"

  log "[$host] (re)starting hive-pg-age container (localhost:5432, persistent volume)"
  SU_ENV_CONTAINER=1
  ssh_node "$ip" "docker rm -f hive-pg-age 2>/dev/null || true; docker volume create hive-pgdata >/dev/null; \
    docker run -d $PG_RUN_ARGS --env-file '$SECRET_DIR/su-init.env' hive-pg-age:local $PG_SSL_ARGS >/dev/null"

  log "[$host] waiting for postgres ready"
  ssh_node "$ip" "for i in \$(seq 1 60); do docker exec hive-pg-age pg_isready -U postgres >/dev/null 2>&1 && exit 0; sleep 2; done; echo 'pg not ready' >&2; exit 1"

  log "[$host] running idempotent SQL bootstrap (role/db/age/vector/grants/search_path)"
  ssh_node "$ip" "docker exec -i --env-file '$SECRET_DIR/psql.env' hive-pg-age psql -v ON_ERROR_STOP=1 -U postgres -f - < /opt/hive/pg-age/bootstrap.sql >/dev/null"

  log "[$host] verifying extensions"
  exts="$(ssh_node "$ip" "docker exec --env-file '$SECRET_DIR/psql.env' hive-pg-age psql -tAqc \"SELECT extname FROM pg_extension WHERE extname IN ('age','vector') ORDER BY extname\" -U postgres aimemory")"
  echo "$exts" | grep -q age    || die "[$host] age extension missing"
  echo "$exts" | grep -q vector || die "[$host] vector(pgvector) extension missing"
  log "[$host] extensions OK: $(echo $exts | tr '\n' ' ')"

  log "[$host] ai-memory schema-init (v55 + ai_memory_kg graph, vector($EMBED_DIM))"
  ssh_node "$ip" "AI_MEMORY_STORE_URL_FILE='$SECRET_DIR/store-url' /usr/local/bin/ai-memory schema-init --embedding-dim $EMBED_DIM"

  # #4896: POSTGRES_PASSWORD is init-only (the entrypoint reads it only while
  # the data directory is empty). Recreate the container without --env-file so
  # the superuser password does not stay in the container config (docker
  # inspect) or in the postgres process environment for the container's life.
  log "[$host] recreating hive-pg-age without the init-only superuser environment"
  ssh_node "$ip" "docker rm -f hive-pg-age >/dev/null; docker run -d $PG_RUN_ARGS hive-pg-age:local $PG_SSL_ARGS >/dev/null"
  SU_ENV_CONTAINER=0
  ssh_node "$ip" "for i in \$(seq 1 60); do docker exec hive-pg-age pg_isready -U postgres >/dev/null 2>&1 && exit 0; sleep 2; done; echo 'pg not ready' >&2; exit 1"
  ssh_node "$ip" "docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' hive-pg-age | grep -q '^POSTGRES_PASSWORD=' && exit 1 || exit 0" \
    || die "[$host] superuser password still present in the container config"

  cleanup_peer
  trap - EXIT INT TERM
  log "[$host] PG+AGE substrate ready"
done <<< "$PEER_IPS"
log "peer DB substrate complete on all peers"
