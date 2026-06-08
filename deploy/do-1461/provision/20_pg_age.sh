#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Stand up the per-REGION PostgreSQL 18.4 + Apache AGE 1.7.0 + pgvector 0.8.2
# substrate droplets (role=pg, ONE per region) — NATIVE, no Docker (operator
# decision: zero Docker anywhere on the DO fleet). Within each region every peer
# keys to its own search_path schema (ic_peer_<K>) on THAT region's pg node and
# dials it on the region's PRIVATE VPC IP under TLS verify-full — the third
# encrypted leg of the mesh (15_tls.sh lays the CA-signed server cert at
# /etc/ai-memory/tls/server.pem with the region pg's private IP in its SAN
# BEFORE this step runs). Schema indices are WITHIN a region: each regional pg
# independently hosts ic_peer_1..K for its own K peers.
#
# Install vector (verified against the live pgdg noble repo — see lib.sh):
#   * postgresql-18          18.4   exact pgdg .deb
#   * postgresql-18-pgvector 0.8.2  exact pgdg .deb
#   * postgresql-18-age      age.control default_version='1.7.0' (extversion
#     1.7.0) — same commit as the apache/age:release_PG18_1.7.0 image; the
#     pgdg "~rc0" is only a Debian revision label. No source build.
#
# Native specifics vs. the old container model:
#   * The cluster is (re)created with --data-checksums for parity with the
#     container's POSTGRES_INITDB_ARGS, gated by a sentinel so re-runs are
#     idempotent (never wipes an initialized cluster).
#   * The ai_memory role + database are created via `sudo -u postgres psql`
#     (native install ships only the postgres superuser — there is no
#     POSTGRES_USER entrypoint). CREATE EXTENSION age/vector require superuser,
#     so the init SQL is applied as postgres into the ai_memory database.
#   * Server GUCs (ssl, cert paths, listen_addresses, shared_preload_libraries
#     ='age', scram, matrix knobs) are set via ALTER SYSTEM (always-included
#     postgresql.auto.conf) and take effect on the restart at the end.
#   * pg_hba.conf is hostssl-ONLY: a non-TLS TCP connection is rejected
#     pre-auth. The local unix socket stays `trust` for the postgres probes.
#
# Benchmark-matrix knobs (#172) are EMPTY by default → stock PG18.4 = the B0
# control. A matrix arm re-provisions with exactly ONE knob set (lib.sh).
#
# Secret handling: a SINGLE fleet PG password is generated once into the
# gitignored run dir (mode 0600) and reused on EVERY region's pg node — so the
# ai_memory role uses the same credential fleet-wide and each peer's store URL
# (50_federation.sh) composes against its own region's pg with that one secret.
# It is rendered into a 0600 role.sql, scp'd to each pg droplet, applied, then
# shredded remotely — never echoed, never on a command line, never committed.
source "$(dirname "$0")/lib.sh"

require_inventory

SECRETS_DIR="$RUN_DIR/secrets"; mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"
PG_PW_FILE="$SECRETS_DIR/pg.pw"
if [ ! -s "$PG_PW_FILE" ]; then
  # url-safe chars only — the password is embedded verbatim in each peer's
  # postgres:// store URL, so no shell/URL-special characters. Subshell with
  # pipefail off so the early `head` close can't SIGPIPE-abort us (#66 class).
  ( set +o pipefail; LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48 ) > "$PG_PW_FILE"
  chmod 600 "$PG_PW_FILE"
  log "generated fleet-wide PG ($PG_USER) password -> $PG_PW_FILE"
fi
PG_PW="$(cat "$PG_PW_FILE")"

REMOTE_TLS="/etc/ai-memory/tls"

# Provision exactly one pg node per region (terraform validation pins that
# invariant). Loop over the pg hostnames so adding a region is a data edit only.
PG_HOSTS="$(inv_names_by_role pg)"
[ -n "$PG_HOSTS" ] || die "no pg node in inventory (role=pg) — terraform must declare one per region"

provision_region_pg() {
  local pg_host="$1" region pg_pub pg_priv peer_n
  region="$(inv_peer_region "$pg_host")"
  [ -n "$region" ] || die "[$pg_host] pg node has no region in inventory"
  pg_pub="$(inv_pg_public_ip_for_region "$region")"
  pg_priv="$(inv_pg_private_ip_for_region "$region")"
  [ -n "$pg_pub" ]  || die "[$pg_host] region $region pg has no public IP"
  [ -n "$pg_priv" ] || die "[$pg_host] region $region pg has no private VPC IP — its peers cannot reach it"

  # Within-region peer set -> ic_peer_1..K on THIS region's pg.
  local peers_in_region; peers_in_region="$(inv_peer_names_sorted_in_region "$region")"
  peer_n="$(printf '%s\n' "$peers_in_region" | grep -c . || true)"
  [ "${peer_n:-0}" -ge 1 ] || die "[$pg_host] region $region has no peers — nothing to key schemas for"
  log "region $region pg: $pg_host pub=$pg_pub priv=$pg_priv peers=$peer_n (schemas $(peer_schema 1)..$(peer_schema "$peer_n"))"

  ssh_node "$pg_pub" "test -s $REMOTE_TLS/server.pem && test -s $REMOTE_TLS/server.key" \
    || die "[$pg_host] PG server cert missing at $REMOTE_TLS — run provision/15_tls.sh before 20_pg_age.sh"

  # ------------------------------------------------------------------------
  # 1. Render init SQL + pg_hba.conf locally from lib.sh constants (SSOT — no
  #    hand-written role/db/schema literal). create_graph is guarded so the
  #    explicit (idempotent) re-apply is safe on re-runs. Per-region render dir
  #    keeps the artifacts isolated.
  # ------------------------------------------------------------------------
  local RENDER_DIR="$RUN_DIR/render/pg/$region"; mkdir -p "$RENDER_DIR"
  local INIT_SQL="$RENDER_DIR/init-age.sql"
  local PG_HBA="$RENDER_DIR/pg_hba.conf"
  local SYSTEM_SQL="$RENDER_DIR/system.sql"
  local ROLE_SQL="$RENDER_DIR/role.sql"
  local INSTALL_SH="$RENDER_DIR/pg-install.sh"

  {
    printf -- '-- GENERATED by provision/20_pg_age.sh from provision/lib.sh — DO NOT EDIT.\n'
    printf -- "CREATE EXTENSION IF NOT EXISTS age;\n"
    printf -- 'CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;\n\n'
    printf -- "LOAD 'age';\n"
    # "$user" is a literal PostgreSQL search_path keyword (per-role schema),
    # NOT a shell variable — it must reach the .sql file un-expanded.
    # shellcheck disable=SC2016
    printf -- 'SET search_path = ag_catalog, "$user", public;\n'
    # Idempotent graph create (AGE has no CREATE GRAPH IF NOT EXISTS).
    printf -- 'DO $$ BEGIN\n'
    printf -- "  IF NOT EXISTS (SELECT 1 FROM ag_catalog.ag_graph WHERE name = '%s') THEN\n" "$AGE_GRAPH_NAME"
    printf -- "    PERFORM create_graph('%s');\n" "$AGE_GRAPH_NAME"
    printf -- '  END IF;\n'
    printf -- 'END $$;\n\n'
    # Per-peer search-path schemas for THIS region's peers (ic_peer_1 .. ic_peer_K).
    local schemas="" i=1
    while [ "$i" -le "$peer_n" ]; do
      local s; s="$(peer_schema "$i")"
      printf -- 'CREATE SCHEMA IF NOT EXISTS %s AUTHORIZATION %s;\n' "$s" "$PG_USER"
      if [ -z "$schemas" ]; then schemas="$s"; else schemas="${schemas}, $s"; fi
      i=$((i + 1))
    done
    printf -- '\nGRANT ALL PRIVILEGES ON DATABASE %s TO %s;\n' "$PG_DB" "$PG_USER"
    printf -- 'GRANT ALL PRIVILEGES ON SCHEMA public, %s, ag_catalog TO %s;\n' "$schemas" "$PG_USER"
    printf -- 'GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA ag_catalog TO %s;\n' "$PG_USER"
    printf -- 'GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ag_catalog TO %s;\n' "$PG_USER"
    printf -- 'GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA ag_catalog TO %s;\n' "$PG_USER"
    # A1 matrix knob: per-DB pgvector ef_search default (empty → stock).
    if [ -n "$PG_HNSW_EF_SEARCH" ]; then
      printf -- '\nALTER DATABASE %s SET hnsw.ef_search = %s;\n' "$PG_DB" "$PG_HNSW_EF_SEARCH"
    fi
  } > "$INIT_SQL"
  chmod 0644 "$INIT_SQL"
  log "[$pg_host] rendered $INIT_SQL"

  {
    printf -- '# GENERATED by provision/20_pg_age.sh from provision/lib.sh — DO NOT EDIT.\n'
    printf -- '# hostssl-ONLY: a non-TLS TCP connection is rejected pre-auth with\n'
    printf -- '# "no pg_hba.conf entry ... no encryption" (3rd encrypted mesh leg).\n'
    printf -- '# TYPE     DATABASE  USER  ADDRESS      METHOD\n'
    printf -- 'local      all       all                trust\n'
    printf -- 'hostssl    all       all   0.0.0.0/0    scram-sha-256\n'
    printf -- 'hostssl    all       all   ::/0         scram-sha-256\n'
  } > "$PG_HBA"
  chmod 0644 "$PG_HBA"
  log "[$pg_host] rendered $PG_HBA (hostssl-only)"

  # Server GUCs via ALTER SYSTEM (postgresql.auto.conf — always included, takes
  # effect on the final restart). listen on loopback + the region's private VPC
  # IP only (that region's peers reach it east-west; never the public interface).
  # Matrix knobs append one ALTER SYSTEM each (empty → omitted → stock B0).
  {
    printf -- "-- GENERATED by provision/20_pg_age.sh — DO NOT EDIT.\n"
    printf -- "ALTER SYSTEM SET listen_addresses = 'localhost,%s';\n" "$pg_priv"
    printf -- "ALTER SYSTEM SET port = %s;\n" "$PG_PORT"
    printf -- "ALTER SYSTEM SET ssl = on;\n"
    printf -- "ALTER SYSTEM SET ssl_cert_file = '%s/server.pem';\n" "$PG_TLS_DIR"
    printf -- "ALTER SYSTEM SET ssl_key_file = '%s/server.key';\n" "$PG_TLS_DIR"
    printf -- "ALTER SYSTEM SET shared_preload_libraries = 'age';\n"
    printf -- "ALTER SYSTEM SET password_encryption = 'scram-sha-256';\n"
    [ -n "$PG_SYNCHRONOUS_COMMIT" ]   && printf -- "ALTER SYSTEM SET synchronous_commit = '%s';\n"   "$PG_SYNCHRONOUS_COMMIT"
    [ -n "$PG_SHARED_BUFFERS" ]       && printf -- "ALTER SYSTEM SET shared_buffers = '%s';\n"        "$PG_SHARED_BUFFERS"
    [ -n "$PG_EFFECTIVE_CACHE_SIZE" ] && printf -- "ALTER SYSTEM SET effective_cache_size = '%s';\n"  "$PG_EFFECTIVE_CACHE_SIZE"
    [ -n "$PG_WORK_MEM" ]             && printf -- "ALTER SYSTEM SET work_mem = '%s';\n"              "$PG_WORK_MEM"
    [ -n "$PG_MAINTENANCE_WORK_MEM" ] && printf -- "ALTER SYSTEM SET maintenance_work_mem = '%s';\n"  "$PG_MAINTENANCE_WORK_MEM"
    [ -n "$PG_MAX_CONNECTIONS" ]      && printf -- "ALTER SYSTEM SET max_connections = %s;\n"          "$PG_MAX_CONNECTIONS"
    true
  } > "$SYSTEM_SQL"
  chmod 0644 "$SYSTEM_SQL"
  log "[$pg_host] rendered $SYSTEM_SQL (ssl + GUCs + matrix knobs)"

  # Role + database. SECRET: the password is inline here, so this file is 0600
  # and is shredded on the droplet immediately after apply. CREATE DATABASE can
  # not run inside a DO/transaction block, so it is emitted via \gexec. The same
  # fleet-wide password is applied on every region's pg (single ai_memory cred).
  {
    printf -- "DO \$\$ BEGIN\n"
    printf -- "  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%s') THEN\n" "$PG_USER"
    printf -- "    CREATE ROLE %s LOGIN PASSWORD '%s';\n" "$PG_USER" "$PG_PW"
    printf -- "  ELSE\n"
    printf -- "    ALTER ROLE %s LOGIN PASSWORD '%s';\n" "$PG_USER" "$PG_PW"
    printf -- "  END IF;\n"
    printf -- "END \$\$;\n"
    printf -- "SELECT format('CREATE DATABASE %%I OWNER %%I', '%s', '%s')\n" "$PG_DB" "$PG_USER"
    printf -- "WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '%s')\\gexec\n" "$PG_DB"
  } > "$ROLE_SQL"
  chmod 0600 "$ROLE_SQL"
  log "[$pg_host] rendered $ROLE_SQL (mode 0600, shredded remotely after apply)"

  # ------------------------------------------------------------------------
  # 2. Render the idempotent native installer (no secret inline) and run it on
  #    the pg droplet with the staged artifacts.
  # ------------------------------------------------------------------------
  {
    cat <<EOF
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
PG_MAJOR='$PG_MAJOR'; PG_CLUSTER='$PG_CLUSTER'
PG_CONF_DIR='$PG_CONF_DIR'; PG_TLS_DIR='$PG_TLS_DIR'; PG_STAGE_DIR='$PG_STAGE_DIR'
PG_USER='$PG_USER'; PG_DB='$PG_DB'; PGDG_CODENAME='$PGDG_CODENAME'
PG_APT_VERSION='$PG_APT_VERSION'; PGVECTOR_APT_VERSION='$PGVECTOR_APT_VERSION'; AGE_APT_VERSION='$AGE_APT_VERSION'
REMOTE_TLS='$REMOTE_TLS'
EOF
    cat <<'EOS'
log(){ printf '[pg-install] %s\n' "$*" >&2; }

# 0. prerequisites for the repo-add (fresh droplet may lack curl/gnupg)
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg

# 1. pgdg apt repo (idempotent)
if [ ! -f /etc/apt/sources.list.d/pgdg.list ]; then
  log "adding pgdg apt repo ($PGDG_CODENAME)"
  install -d /usr/share/keyrings
  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /usr/share/keyrings/pgdg.gpg
  echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] http://apt.postgresql.org/pub/repos/apt ${PGDG_CODENAME}-pgdg main" > /etc/apt/sources.list.d/pgdg.list
fi
apt-get update -qq

# 2. pinned native install (server + client + pgvector + AGE)
log "installing pinned PG${PG_MAJOR} + pgvector + AGE"
apt-get install -y -qq \
  "postgresql-${PG_MAJOR}=${PG_APT_VERSION}" \
  "postgresql-client-${PG_MAJOR}" \
  "postgresql-${PG_MAJOR}-pgvector=${PGVECTOR_APT_VERSION}" \
  "postgresql-${PG_MAJOR}-age=${AGE_APT_VERSION}"

# 3. fresh cluster WITH data checksums (parity with the container initdb),
#    gated by a sentinel so re-runs never wipe an initialized cluster.
SENTINEL=/etc/do-1461-pg.initialized
if [ ! -f "$SENTINEL" ]; then
  log "creating cluster ${PG_MAJOR}/${PG_CLUSTER} with --data-checksums"
  pg_dropcluster --stop "$PG_MAJOR" "$PG_CLUSTER" 2>/dev/null || true
  pg_createcluster "$PG_MAJOR" "$PG_CLUSTER" -- --data-checksums >/dev/null
  touch "$SENTINEL"
fi

# 4. TLS material postgres-owned (server refuses an ssl_key_file it doesn't own)
log "installing TLS material postgres-owned -> $PG_TLS_DIR"
install -d -o postgres -g postgres -m 0750 "$PG_TLS_DIR"
install -o postgres -g postgres -m 0644 "$REMOTE_TLS/server.pem" "$PG_TLS_DIR/server.pem"
install -o postgres -g postgres -m 0600 "$REMOTE_TLS/server.key" "$PG_TLS_DIR/server.key"

# 5. hostssl-only pg_hba (overwrite the cluster's)
install -o postgres -g postgres -m 0640 "$PG_STAGE_DIR/pg_hba.conf" "$PG_CONF_DIR/pg_hba.conf"

# 6. start cluster so we can ALTER SYSTEM
pg_ctlcluster "$PG_MAJOR" "$PG_CLUSTER" start 2>/dev/null || true
for i in $(seq 1 60); do sudo -u postgres pg_isready -q && break; sleep 1; done

# 7. server GUCs (ssl, listen, shared_preload_libraries='age', matrix knobs)
log "applying ALTER SYSTEM GUCs"
sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -f "$PG_STAGE_DIR/system.sql" >/dev/null

# 8. role + database (secret), then shred the secret file. role.sql is 0600
#    root-owned, so the postgres peer cannot read it with `-f`; pipe it on stdin
#    instead — root's shell reads the file (secret stays off the command line and
#    off any ps listing), psql consumes the SQL (incl \gexec) from stdin.
log "creating role + database"
sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres < "$PG_STAGE_DIR/role.sql" >/dev/null
shred -u "$PG_STAGE_DIR/role.sql" 2>/dev/null || rm -f "$PG_STAGE_DIR/role.sql"

# 9. restart to apply ssl + shared_preload_libraries + listen_addresses; enable
log "restarting cluster to apply GUCs"
pg_ctlcluster "$PG_MAJOR" "$PG_CLUSTER" restart 2>/dev/null || systemctl restart "postgresql@${PG_MAJOR}-${PG_CLUSTER}"
systemctl enable "postgresql@${PG_MAJOR}-${PG_CLUSTER}" >/dev/null 2>&1 || true
systemctl enable postgresql >/dev/null 2>&1 || true
for i in $(seq 1 60); do sudo -u postgres pg_isready -q && break; sleep 1; done

# 10. extensions / graph / per-peer schemas / grants (superuser into the db)
log "applying init SQL (extensions, graph, peer schemas, grants)"
sudo -u postgres psql -v ON_ERROR_STOP=1 -d "$PG_DB" -f "$PG_STAGE_DIR/init-age.sql" >/dev/null
log "native PG substrate install complete"
EOS
  } > "$INSTALL_SH"
  chmod 0755 "$INSTALL_SH"

  log "[$pg_host] staging native installer + artifacts -> $PG_STAGE_DIR"
  ssh_node "$pg_pub" "mkdir -p $PG_STAGE_DIR && chmod 0755 $PG_STAGE_DIR"
  scp_to "$INSTALL_SH" "$pg_pub" "$PG_STAGE_DIR/pg-install.sh"
  scp_to "$INIT_SQL"   "$pg_pub" "$PG_STAGE_DIR/init-age.sql"
  scp_to "$PG_HBA"     "$pg_pub" "$PG_STAGE_DIR/pg_hba.conf"
  scp_to "$SYSTEM_SQL" "$pg_pub" "$PG_STAGE_DIR/system.sql"
  scp_to "$ROLE_SQL"   "$pg_pub" "$PG_STAGE_DIR/role.sql"
  ssh_node "$pg_pub" "chmod 0600 $PG_STAGE_DIR/role.sql"

  log "[$pg_host] running native PG18.4 + AGE1.7.0 + pgvector0.8.2 install (this builds nothing — pinned .debs)"
  ssh_node "$pg_pub" "bash $PG_STAGE_DIR/pg-install.sh"

  log "[$pg_host] waiting for postgres ready"
  ssh_node "$pg_pub" "for i in \$(seq 1 60); do sudo -u postgres pg_isready -q && exit 0; sleep 2; done; echo 'pg not ready' >&2; exit 1"

  log "[$pg_host] verifying extensions"
  local exts
  exts="$(ssh_node "$pg_pub" "sudo -u postgres psql -tAqc \"SELECT extname FROM pg_extension WHERE extname IN ('age','vector') ORDER BY extname\" -d '$PG_DB'")"
  echo "$exts" | grep -q age    || die "[$pg_host] age extension missing"
  echo "$exts" | grep -q vector || die "[$pg_host] vector (pgvector) extension missing"
  log "[$pg_host] extensions OK: $(echo $exts | tr '\n' ' ')"

  log "region $region PG18.4/AGE1.7.0/pgvector substrate ready ($pg_host @ $pg_priv:$PG_PORT, $peer_n peer schemas, NATIVE/no-docker)"
}

# Drive each region's pg node. bash-3.2: feed the hostname list via a here-doc
# (no process substitution, no mapfile).
while IFS= read -r pg_host; do
  [ -n "$pg_host" ] || continue
  provision_region_pg "$pg_host"
done <<EOF
$PG_HOSTS
EOF

log "all regional PG18.4/AGE1.7.0/pgvector substrates ready ($(inv_regions | tr '\n' ' ')— one pg per region, NATIVE/no-docker)"
