#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Stand up the federated peer DB substrate: Docker + a pinned PG16/AGE/pgvector
# image, localhost-bound, persistent volume, then the idempotent SQL bootstrap
# + ai-memory schema-init (v55 + ai_memory_kg graph). Peers only.
#
# Secret handling: a single fleet PG password is generated once into the
# gitignored run dir (mode 0600) and passed by env / psql var — never written
# to a committed file and never echoed.
source "$(dirname "$0")/lib.sh"

SECRETS_DIR="$RUN_DIR/secrets"; mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"
PG_PW_FILE="$SECRETS_DIR/pg.pw"
SU_PW_FILE="$SECRETS_DIR/pg-super.pw"
if [ ! -s "$PG_PW_FILE" ]; then openssl rand -hex 24 > "$PG_PW_FILE"; chmod 600 "$PG_PW_FILE"; log "generated aimemory PG password -> $PG_PW_FILE"; fi
if [ ! -s "$SU_PW_FILE" ]; then openssl rand -hex 24 > "$SU_PW_FILE"; chmod 600 "$SU_PW_FILE"; log "generated postgres superuser password -> $SU_PW_FILE"; fi
PG_PW="$(cat "$PG_PW_FILE")"
SU_PW="$(cat "$SU_PW_FILE")"

DOCKERFILE="$HIVE_ROOT/provision/pg-age/Dockerfile"
BOOTSTRAP="$HIVE_ROOT/provision/pg-age/bootstrap.sql"

inv_ips_by_role peer | while read -r ip; do
  host="$(inv_name_for_ip "$ip")"
  log "[$host] installing docker + building pinned PG/AGE/pgvector image"
  ssh_node "$ip" "command -v docker >/dev/null 2>&1 || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io); systemctl enable --now docker"
  ssh_node "$ip" "mkdir -p /opt/hive/pg-age"
  scp_to "$DOCKERFILE" "$ip" "/opt/hive/pg-age/Dockerfile"
  scp_to "$BOOTSTRAP" "$ip" "/opt/hive/pg-age/bootstrap.sql"
  ssh_node "$ip" "docker build --build-arg AGE_IMAGE='$AGE_IMAGE' -t hive-pg-age:local /opt/hive/pg-age" >/dev/null

  log "[$host] (re)starting hive-pg-age container (localhost:5432, persistent volume)"
  ssh_node "$ip" "docker rm -f hive-pg-age 2>/dev/null || true; docker volume create hive-pgdata >/dev/null; \
    docker run -d --name hive-pg-age --restart unless-stopped \
      -p 127.0.0.1:5432:5432 -v hive-pgdata:/var/lib/postgresql/data \
      -e POSTGRES_PASSWORD='$SU_PW' hive-pg-age:local >/dev/null"

  log "[$host] waiting for postgres ready"
  ssh_node "$ip" "for i in \$(seq 1 60); do docker exec hive-pg-age pg_isready -U postgres >/dev/null 2>&1 && exit 0; sleep 2; done; echo 'pg not ready' >&2; exit 1"

  log "[$host] running idempotent SQL bootstrap (role/db/age/vector/grants/search_path)"
  ssh_node "$ip" "docker exec -i -e PGPASSWORD='$SU_PW' hive-pg-age psql -v ON_ERROR_STOP=1 -v pw='$PG_PW' -U postgres -f - < /opt/hive/pg-age/bootstrap.sql >/dev/null"

  log "[$host] verifying extensions"
  exts="$(ssh_node "$ip" "docker exec -e PGPASSWORD='$SU_PW' hive-pg-age psql -tAqc \"SELECT extname FROM pg_extension WHERE extname IN ('age','vector') ORDER BY extname\" -U postgres aimemory")"
  echo "$exts" | grep -q age    || die "[$host] age extension missing"
  echo "$exts" | grep -q vector || die "[$host] vector(pgvector) extension missing"
  log "[$host] extensions OK: $(echo $exts | tr '\n' ' ')"

  log "[$host] ai-memory schema-init (v55 + ai_memory_kg graph, vector($EMBED_DIM))"
  ssh_node "$ip" "/usr/local/bin/ai-memory schema-init --embedding-dim $EMBED_DIM --store-url 'postgres://aimemory:$PG_PW@127.0.0.1:5432/aimemory'"
  log "[$host] PG+AGE substrate ready"
done
log "peer DB substrate complete on all peers"
