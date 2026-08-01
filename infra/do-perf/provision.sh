#!/usr/bin/env bash
# ai-memory v1.0.0 -- dedicated DigitalOcean performance environment.
#
# WHY THIS EXISTS
# ---------------
# Several perf findings in this campaign were closed as UNSUPPORTED because the
# numbers came off a box at load 12-45 with six concurrent lanes, a shared
# postgres instance mutated mid-run by sibling processes, and one measurement
# that turned out to be reading a neighbour's scratch index (catalog oid 75335
# against ~29xxx for every pre-existing index). See #2616, #2624, #2598, #2622.
#
# A dedicated pair of droplets removes that entire class: the data tier gets a
# box nobody else touches, and the load generator sits on a SEPARATE box so the
# client's own CPU never competes with postgres for cores.
#
# TOPOLOGY
#   droplet 1  ai-memory-perf-datatier   PG 18.4 + AGE + pgvector, VPC-only, TLS-enforced
#   droplet 2  ai-memory-perf-loadgen    builds + runs ai-memory, drives load
#
# HARD RULES ENFORCED HERE
#   * NOTHING about the postgres stack is written by hand. The Dockerfile, the
#     pg service, and both initdb scripts are SPLICED from the certified local
#     stack (pg-age-stack/). A hand-written paraphrase failed four times, every
#     time on something the certified files had already solved -- $${VAR}
#     escaping, missing ca-certificates, non-ASCII em-dashes (#1880), and the
#     PG18 /var/lib/postgresql mount convention. Splicing makes divergence
#     between the droplet and the local tier impossible, not merely discouraged.
#   * The binary under test is built from the CURRENT release/v1.0.0 HEAD and
#     its SHA is recorded with every number. Operator directive 2026-08-01:
#     "make sure testing with current compiled ai-memory v1.0.0 whenever
#     testing." A stale binary already produced one phantom regression (#1315).
#   * Postgres traffic is ENCRYPTED and cleartext is REFUSED, not merely
#     discouraged. The provision proves the refusal before handing the tier
#     back; a tier that silently downgraded would yield benchmark numbers off an
#     unencrypted path while the writeup claimed an encrypted one.
#   * Provisioning is fail-closed throughout. Abort, never report.
#   * Nothing is destroyed automatically. Teardown is explicit.
set -euo pipefail

REGION="${REGION:-nyc3}"
DATATIER_SIZE="${DATATIER_SIZE:-m-4vcpu-32gb}"   # 4 DEDICATED vCPU / 32 GB.
# Deliberate: the 8-vCPU options on this account are all s-* SHARED CPU. A shared-CPU box
# reintroduces exactly the noisy-neighbour variance this droplet exists to escape -- the same
# class that invalidated #2616/#2624/#2598. Dedicated-4 beats shared-8 for measurement fidelity.
LOADGEN_SIZE="${LOADGEN_SIZE:-c-4}"             # 4 dedicated vCPU / 8 GB (CPU-optimized)
IMAGE="ubuntu-24-04-x64"
TAG="ai-memory-perf"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$REPO_ROOT/.local-runs/do-perf"      # project HARD RULE: never /tmp
CERT_DIR="$OUT/certs"
mkdir -p "$OUT" "$CERT_DIR"

die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "[provision] $*"; }
have() { grep -qF -- "$2" "$1" || die "spliced $(basename "$1") is missing required content: $2"; }
# Comment-blind. The certified compose file documents the PG18 mount trap in a
# comment that literally contains the forbidden string
#   "mount at /var/lib/postgresql, NOT /var/lib/postgresql/data"
# so a naive grep over the whole fragment would fail on a CORRECT splice.
lacks() {
  if grep -vE '^[[:space:]]*#' "$1" | grep -qF -- "$2"; then
    die "spliced $(basename "$1") still contains forbidden content in live config: $2"
  fi
}

# --- preflight -------------------------------------------------------------
command -v doctl >/dev/null || die "doctl not installed"
doctl account get >/dev/null 2>&1 || die "doctl not authenticated -- run: doctl auth init"
command -v openssl >/dev/null || die "openssl not installed (needed for cert generation)"
command -v iconv >/dev/null || die "iconv not installed (needed for the ASCII splice guard)"

SSH_FP="${SSH_FP:-${DIGITALOCEAN_SSH_KEY_FINGERPRINT:-$(doctl compute ssh-key list --format FingerPrint --no-header | head -1)}}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
[ -f "$SSH_KEY" ] || die "ssh private key not found at $SSH_KEY (set SSH_KEY=...)"
[ -n "$SSH_FP" ] || die "no SSH key on the DO account; add one before provisioning"
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

# The binary under test must come from a known commit, not from whatever is
# checked out. Resolve and pin it up front so it lands in every artifact.
BUILD_SHA="$(git -C "$REPO_ROOT" rev-parse origin/release/v1.0.0)"
BUILD_SHA_SHORT="${BUILD_SHA:0:8}"
note "pinning ai-memory build to release/v1.0.0 @ $BUILD_SHA_SHORT"

PGPASS="${PGPASS:-$(openssl rand -hex 24)}"
umask 077
printf '%s\n' "$PGPASS" > "$OUT/pgpass"        # 0600, never echoed to stdout
umask 022

# ===========================================================================
# SPLICE THE CERTIFIED STACK
# ===========================================================================
# Prior code first; copy nothing by hand. Each source is transliterated to ASCII
# (#1880) and then guarded, so a failed splice aborts the provision instead of
# producing a droplet that diverges from the certified tier.
CERTIFIED_DIR="${CERTIFIED_DIR:-/home/fate_two/v07/pg-age-stack}"
CERTIFIED_DOCKERFILE="${CERTIFIED_DOCKERFILE:-$CERTIFIED_DIR/Dockerfile}"
CERTIFIED_COMPOSE="${CERTIFIED_COMPOSE:-$CERTIFIED_DIR/docker-compose.yml}"
CERTIFIED_INITDB_EXT="${CERTIFIED_INITDB_EXT:-$CERTIFIED_DIR/initdb/00-extensions.sql}"
CERTIFIED_INITDB_TLS="${CERTIFIED_INITDB_TLS:-$CERTIFIED_DIR/initdb/01-tls-hba.sh}"
for f in "$CERTIFIED_DOCKERFILE" "$CERTIFIED_COMPOSE" "$CERTIFIED_INITDB_EXT" "$CERTIFIED_INITDB_TLS"; do
  [ -f "$f" ] || die "certified source not found: $f"
done

# The certified files carry typographic characters in their COMMENTS. They are
# harmless to docker/psql but a single non-ASCII byte makes cloud-init silently
# discard the entire config (#1880). Transliterate, then prove it worked.
to_ascii() {
  iconv -f UTF-8 -t ASCII//TRANSLIT "$1" > "$2" || die "could not transliterate $1 to ASCII"
  if LC_ALL=C grep -qP '[^\x00-\x7F]' "$2"; then
    die "transliteration left non-ASCII bytes in $(basename "$1") -- refusing (see #1880)"
  fi
}

note "splicing certified Dockerfile from $CERTIFIED_DOCKERFILE"
to_ascii "$CERTIFIED_DOCKERFILE" "$OUT/Dockerfile.ascii"
have "$OUT/Dockerfile.ascii" 'ca-certificates'          # failure mode 2
have "$OUT/Dockerfile.ascii" 'ARG PG_IMAGE=postgres:18.4-trixie'
have "$OUT/Dockerfile.ascii" 'AGE_SHA=806fa2ebdb300b3e76ef30cdba61803babbf2683'
have "$OUT/Dockerfile.ascii" 'PGVECTOR_SHA=8ee86c96f0fd72390f890aa8a336fda6d3ab4c6c'

note "splicing certified initdb scripts"
to_ascii "$CERTIFIED_INITDB_EXT" "$OUT/00-extensions.ascii"
have "$OUT/00-extensions.ascii" 'CREATE EXTENSION IF NOT EXISTS age;'
have "$OUT/00-extensions.ascii" 'CREATE EXTENSION IF NOT EXISTS vector;'
# Perf-tier addendum: ai-memory's own schema-init would create the graph, but the
# provisioning proof asserts memory_graph exists, so the tier is born with it.
# create_graph is schema-qualified because the ALTER DATABASE search_path above
# does not apply to the session that is executing this very script.
cat >> "$OUT/00-extensions.ascii" <<'EOF'

-- ---------------------------------------------------------------------------
-- perf-tier addendum (NOT part of the certified file): pre-create the graph so
-- verify.sh can assert the AGE path is live before any benchmark runs.
--
-- The SET is load-bearing and schema-qualifying the call is NOT a substitute
-- for it. create_graph() builds a btree index using the `graphid_ops` operator
-- class, and an operator-class name is resolved through the SESSION
-- search_path -- so `SELECT ag_catalog.create_graph(...)` still fails with
--     operator class "graphid_ops" does not exist for access method "btree"
-- The certified file's ALTER DATABASE ... SET search_path does not apply to the
-- session already executing this script. Observed 2026-08-01: this error
-- aborted the whole initdb loop under ON_ERROR_STOP=1.
-- ---------------------------------------------------------------------------
LOAD 'age';
SET search_path = ag_catalog, public;
SELECT create_graph('memory_graph');
EOF

to_ascii "$CERTIFIED_INITDB_TLS" "$OUT/01-tls-hba.ascii"
have "$OUT/01-tls-hba.ascii" 'hostssl'
# The whole point: no uncommented plain `host` line may survive the splice, or a
# cleartext TCP connection would be accepted instead of refused.
if LC_ALL=C grep -qE '^[[:space:]]*host[[:space:]]' "$OUT/01-tls-hba.ascii"; then
  die "spliced pg_hba writer contains a plain 'host' line -- cleartext would be ACCEPTED"
fi

# --- the pg service ---------------------------------------------------------
# Extracted verbatim from the certified compose file, then given exactly the
# perf-tier deltas it needs. Everything not listed below -- the PG18 mount path,
# the whole ssl=* block, the initdb + certs mounts, shm_size, the healthcheck --
# is byte-identical to the certified tier by construction.
note "splicing certified pg service from $CERTIFIED_COMPOSE"
to_ascii "$CERTIFIED_COMPOSE" "$OUT/compose.ascii"
awk 'BEGIN{n=0}
     /^  pg-main:/{f=1}
     f && /^  pg-ladder:/{f=0}
     f{a[n++]=$0}
     END{ while (n>0 && a[n-1] ~ /^[[:space:]]*$/) n--;
          for(i=0;i<n;i++) print a[i] }' "$OUT/compose.ascii" > "$OUT/compose-pg.raw"
[ -s "$OUT/compose-pg.raw" ] || die "could not extract the pg-main service from $CERTIFIED_COMPOSE"

sed -e 's|^  pg-main:|  pg:|' \
    -e 's|container_name: ai-memory-pg-main|container_name: ai-memory-pg-perf|' \
    -e 's|- "127.0.0.1:5433:5432"|- "${BIND_ADDR}:5433:5432"|' \
    -e 's|POSTGRES_PASSWORD: ai_memory_test|POSTGRES_PASSWORD: ${PGPASS}|' \
    -e 's|- pg-main-data:|- pgdata:|' \
    "$OUT/compose-pg.raw" > "$OUT/compose-pg.spliced"

# Perf-tier tuning, appended to the certified command list. These are DELIBERATE
# and must be recorded alongside any published number -- an untuned comparison
# against a tuned local tier would measure the config, not the code.
# m-4vcpu-32gb: shared_buffers ~25% RAM, effective_cache_size ~75% RAM.
cat >> "$OUT/compose-pg.spliced" <<'EOF'
      # --- perf-tier tuning (appended by infra/do-perf/provision.sh) ---------
      # NOT part of the certified local stack. Sized for m-4vcpu-32gb and
      # recorded with every published number.
      - -c
      - shared_buffers=8GB
      - -c
      - effective_cache_size=24GB
      - -c
      - work_mem=64MB
      - -c
      - maintenance_work_mem=1GB
      - -c
      - random_page_cost=1.1
      - -c
      - effective_io_concurrency=200
      - -c
      - track_io_timing=on
EOF

# Guards. Each of these corresponds to a way the hand-written version broke, or
# to an encryption guarantee that must not be silently lost in a future edit.
have   "$OUT/compose-pg.spliced" '- pgdata:/var/lib/postgresql'
lacks  "$OUT/compose-pg.spliced" '/var/lib/postgresql/data'          # failure mode 4
have   "$OUT/compose-pg.spliced" '  pg:'
have   "$OUT/compose-pg.spliced" 'container_name: ai-memory-pg-perf'
have   "$OUT/compose-pg.spliced" 'POSTGRES_PASSWORD: ${PGPASS}'
have   "$OUT/compose-pg.spliced" '- "${BIND_ADDR}:5433:5432"'
lacks  "$OUT/compose-pg.spliced" '127.0.0.1:5433'                    # must not bind loopback
have   "$OUT/compose-pg.spliced" './initdb:/docker-entrypoint-initdb.d:ro'
have   "$OUT/compose-pg.spliced" './certs:/etc/ai-memory-certs:ro'
have   "$OUT/compose-pg.spliced" 'shared_preload_libraries=age'
have   "$OUT/compose-pg.spliced" 'ssl=on'
have   "$OUT/compose-pg.spliced" 'ssl_cert_file=/etc/ai-memory-certs/server.crt'
have   "$OUT/compose-pg.spliced" 'ssl_key_file=/etc/ai-memory-certs/server.key'
have   "$OUT/compose-pg.spliced" 'ssl_ca_file=/etc/ai-memory-certs/ca.crt'
have   "$OUT/compose-pg.spliced" 'ssl_min_protocol_version=TLSv1.2'

# --- network ---------------------------------------------------------------
VPC_NAME="ai-memory-perf-vpc"
VPC_CIDR="10.118.0.0/20"
if ! doctl vpcs list --format Name --no-header | grep -qx "$VPC_NAME"; then
  note "creating VPC $VPC_NAME ($VPC_CIDR) in $REGION"
  doctl vpcs create --name "$VPC_NAME" --region "$REGION" --ip-range "$VPC_CIDR" >/dev/null
fi
VPC_ID="$(doctl vpcs list --format ID,Name --no-header | awk -v n="$VPC_NAME" '$2==n{print $1}')"

# --- render ----------------------------------------------------------------
render_cloudinit() {
  sed -e "s|\${PGPASS}|$PGPASS|g" \
      -e "s|\${VPC_CIDR}|$VPC_CIDR|g" \
      "$HERE/cloud-init-datatier.yaml.tpl" \
  | awk -v dockerfile="$OUT/Dockerfile.ascii" \
        -v composepg="$OUT/compose-pg.spliced" \
        -v initext="$OUT/00-extensions.ascii" \
        -v inittls="$OUT/01-tls-hba.ascii" '
      function splice(f,   line) { while ((getline line < f) > 0) print "      " line; close(f) }
      $0 == "@@CERTIFIED_DOCKERFILE@@"        { splice(dockerfile); next }
      $0 == "@@CERTIFIED_COMPOSE_PG@@"        { splice(composepg);  next }
      $0 == "@@CERTIFIED_INITDB_EXTENSIONS@@" { splice(initext);    next }
      $0 == "@@CERTIFIED_INITDB_TLS_HBA@@"    { splice(inittls);    next }
      { print }
    '
}
render_cloudinit > "$OUT/cloud-init-datatier.rendered.yaml"

# Every placeholder must have been consumed; an unspliced @@...@@ would ship a
# literal marker into a Dockerfile or a compose file.
# Placeholders occupy a whole line; the template's own prose mentions the marker
# form, so match the line-anchored shape rather than a bare "@@".
if grep -qE '^@@[A-Z_]+@@$' "$OUT/cloud-init-datatier.rendered.yaml"; then
  die "rendered cloud-init still contains an unspliced placeholder line: $(grep -m1 -E '^@@[A-Z_]+@@$' "$OUT/cloud-init-datatier.rendered.yaml")"
fi
# #1880: a single non-ASCII byte makes cloud-init silently discard the whole
# config and boot a bare droplet. Check the RENDERED file, not just the source.
# NOTE: -P is load-bearing. Plain grep does NOT interpret \x escapes inside a bracket
# expression -- it reads [^\x00-\x7F] as "any char except \ x 0 7 F -", which matches
# almost every line and fails the provision on a clean file. Verified: the -P form
# reports clean on a pure-ASCII file, the non-P form reports a match.
if LC_ALL=C grep -qP '[^\x00-\x7F]' "$OUT/cloud-init-datatier.rendered.yaml"; then
  die "rendered cloud-init contains non-ASCII bytes -- would silently no-op (see #1880)"
fi
# A malformed block scalar is the other way a cloud-init silently no-ops. Parse
# the rendered file if pyyaml is available, and treat a parse error as fatal --
# only an ABSENT parser is a soft skip.
if python3 -c 'import yaml' 2>/dev/null; then
  python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' \
    "$OUT/cloud-init-datatier.rendered.yaml" \
    || die "rendered cloud-init is not valid YAML -- would silently no-op"
  note "rendered cloud-init parses as YAML"
else
  note "WARNING: pyyaml unavailable -- skipping the rendered-YAML parse check"
fi
# The TLS-enforcing pg_hba writer MUST sort before every other initdb script.
# The entrypoint runs them in lexical order under ON_ERROR_STOP=1: a failure in
# an earlier script aborts the init loop, the container restarts onto a
# now-non-empty PGDATA, initdb is SKIPPED, and the database serves forever on
# the default fail-OPEN pg_hba.conf -- healthy-looking, cleartext accepted.
# Observed 2026-08-01. This guard keeps a future edit from re-arming that.
TLS_INITDB="$(grep -oE '/opt/ai-memory-perf/initdb/[0-9]+-tls-hba\.sh' "$OUT/cloud-init-datatier.rendered.yaml" | head -1)"
EXT_INITDB="$(grep -oE '/opt/ai-memory-perf/initdb/[0-9]+-extensions\.sql' "$OUT/cloud-init-datatier.rendered.yaml" | head -1)"
[ -n "$TLS_INITDB" ] && [ -n "$EXT_INITDB" ] \
  || die "rendered cloud-init is missing one of the two initdb scripts"
[[ "$(basename "$TLS_INITDB")" < "$(basename "$EXT_INITDB")" ]] \
  || die "initdb ordering regression: $(basename "$TLS_INITDB") must sort BEFORE $(basename "$EXT_INITDB") or a failure in the extensions script silently disarms TLS enforcement"

chmod 600 "$OUT/cloud-init-datatier.rendered.yaml"   # it carries PGPASS

if [ "${RENDER_ONLY:-0}" = "1" ]; then
  note "RENDER_ONLY=1 -- rendered cloud-init at $OUT/cloud-init-datatier.rendered.yaml"
  exit 0
fi

# --- droplets --------------------------------------------------------------
note "creating data-tier droplet ($DATATIER_SIZE)"
doctl compute droplet create ai-memory-perf-datatier \
  --region "$REGION" --size "$DATATIER_SIZE" --image "$IMAGE" \
  --vpc-uuid "$VPC_ID" --ssh-keys "$SSH_FP" --tag-name "$TAG" \
  --user-data-file "$OUT/cloud-init-datatier.rendered.yaml" --wait >/dev/null

note "creating load-generator droplet ($LOADGEN_SIZE)"
doctl compute droplet create ai-memory-perf-loadgen \
  --region "$REGION" --size "$LOADGEN_SIZE" --image "$IMAGE" \
  --vpc-uuid "$VPC_ID" --ssh-keys "$SSH_FP" --tag-name "$TAG" --wait >/dev/null

DT_PUB="$(doctl compute droplet get ai-memory-perf-datatier --format PublicIPv4 --no-header)"
DT_PRIV="$(doctl compute droplet get ai-memory-perf-datatier --format PrivateIPv4 --no-header)"
LG_PUB="$(doctl compute droplet get ai-memory-perf-loadgen --format PublicIPv4 --no-header)"
[ -n "$DT_PRIV" ] || die "data tier has no VPC private IP"

# ===========================================================================
# TLS MATERIAL -- generated FOR THIS DROPLET
# ===========================================================================
# The server cert SAN must carry the droplet's VPC private IP, because that is
# the address the load generator connects to and sslmode=verify-full checks the
# SAN against it. That IP does not exist until the droplet does, so the certs
# cannot be baked into user-data; cloud-init blocks on their arrival instead
# (wait-for-certs.sh) and refuses to start postgres without them.
GEN_CERTS="${GEN_CERTS:-$REPO_ROOT/infra/do-hive/crypto/gen-certs.sh}"
[ -f "$GEN_CERTS" ] || die "gen-certs.sh not found at $GEN_CERTS"
note "generating TLS material for the data tier (SAN carries $DT_PRIV)"
OUT_DIR="$CERT_DIR" PG_HOST="$DT_PRIV" EXTRA_SAN_IP="$DT_PRIV" bash "$GEN_CERTS" >/dev/null \
  || die "gen-certs.sh failed"
# gen-certs.sh names the postgres leaf pg-server.*; the certified compose expects
# server.* under /etc/ai-memory-certs. Rename mechanically, do not re-mint.
install -m 0644 "$CERT_DIR/pg-server.crt" "$CERT_DIR/server.crt"
install -m 0600 "$CERT_DIR/pg-server.key" "$CERT_DIR/server.key"
chmod 600 "$CERT_DIR"/*.key
openssl x509 -in "$CERT_DIR/server.crt" -noout -ext subjectAltName \
  | grep -q "IP Address:$DT_PRIV" \
  || die "server cert SAN does not carry the droplet private IP $DT_PRIV -- verify-full would fail"
openssl verify -CAfile "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt" >/dev/null \
  || die "server cert does not verify against the generated CA"
note "TLS material in $CERT_DIR (keys 0600)"

note "waiting for ssh on the data tier so the TLS material can be delivered"
for i in $(seq 1 60); do
  ssh "${SSH_OPTS[@]}" -o ConnectTimeout=8 "root@$DT_PUB" true 2>/dev/null && break
  sleep 10
done
ssh "${SSH_OPTS[@]}" "root@$DT_PUB" 'install -d -m 0755 /opt/ai-memory-perf/certs' \
  || die "could not prepare the cert directory on the data tier"
scp "${SSH_OPTS[@]}" -q "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt" "$CERT_DIR/server.key" \
  "root@$DT_PUB:/opt/ai-memory-perf/certs/" \
  || die "could not ship TLS material to the data tier"
note "TLS material delivered; cloud-init will start postgres once the image is built"

cat > "$OUT/env" <<EOF
# generated $(date -u +%FT%TZ) -- source this before running benchmarks
export DT_PUB=$DT_PUB
export DT_PRIV=$DT_PRIV
export LG_PUB=$LG_PUB
export BUILD_SHA=$BUILD_SHA
# TLS is REQUIRED by the server: a cleartext connection is refused, not
# downgraded. verify-full pins both the CA and the host, matching the SAN.
export AI_MEMORY_TEST_POSTGRES_URL="postgres://ai_memory:$PGPASS@$DT_PRIV:5433/ai_memory_test?sslmode=verify-full&sslrootcert=/opt/ai-memory-perf/ca.crt"
EOF
chmod 600 "$OUT/env"

note "data tier  public=$DT_PUB  private=$DT_PRIV"
note "load gen   public=$LG_PUB"
note "credentials + env written to $OUT/env (0600)"

# --- fail-closed stack + TLS verification ----------------------------------
note "waiting for the data tier to finish provisioning (AGE + pgvector compile from source; allow ~20 min)"
# Wait for cloud-init to COMPLETE. Waiting merely for the log file to exist is wrong:
# `tee` creates it empty at once, so the loop breaks before anything has been written.
for i in $(seq 1 180); do
  st="$(ssh "${SSH_OPTS[@]}" -o ConnectTimeout=8 "root@$DT_PUB" \
        'cloud-init status 2>/dev/null | head -1' 2>/dev/null || true)"
  case "$st" in
    *done*|*error*|*degraded*) note "cloud-init: $st"; break ;;
  esac
  [ $((i % 10)) -eq 0 ] && note "  still provisioning (${i}0s elapsed) -- $st"
  sleep 10
done
STACK="$(ssh "${SSH_OPTS[@]}" "root@$DT_PUB" 'cat /var/log/ai-memory-provision.log' 2>&1 || true)"
echo "$STACK" | tee "$OUT/stack-verification.txt"
echo "$STACK" | grep -q 'PROVISION OK' \
  || die "data tier did not verify -- refusing to hand back a droplet that would produce numbers for an unknown stack"
# The cleartext refusal is the load-bearing proof. PROVISION OK alone is not
# enough: assert the specific line, so a future edit that drops CHECK 3 cannot
# quietly hand back an unencrypted tier.
echo "$STACK" | grep -q 'CHECK 3 PASS - cleartext connection REFUSED' \
  || die "data tier did not PROVE that cleartext is refused -- refusing to hand back the tier"
echo "$STACK" | grep -q 'CHECK 4 PASS' \
  || die "data tier did not prove sslmode=verify-full connects -- refusing to hand back the tier"

# --- build the binary under test, on the load generator --------------------
# Built from the pinned SHA. Version asserted. Abort, never report, on drift.
note "shipping the CA and source @ $BUILD_SHA_SHORT to the load generator"
# The load generator needs the CA to satisfy sslmode=verify-full. The private key
# never leaves the data tier.
ssh "${SSH_OPTS[@]}" "root@$LG_PUB" 'install -d -m 0755 /opt/ai-memory-perf' \
  || die "could not prepare /opt/ai-memory-perf on the load generator"
scp "${SSH_OPTS[@]}" -q "$CERT_DIR/ca.crt" "root@$LG_PUB:/opt/ai-memory-perf/ca.crt" \
  || die "could not ship the CA to the load generator"

# The repo is PRIVATE. We ship a git archive of the pinned SHA over ssh rather than
# cloning on the droplet, so no GitHub credential ever leaves this host.
SRC_DIR="/opt/ai-memory-src-$BUILD_SHA_SHORT"   # unique per build; no recursive deletes needed
git -C "$REPO_ROOT" archive --format=tar "$BUILD_SHA" > "$OUT/src.tar"
scp "${SSH_OPTS[@]}" -q "$OUT/src.tar" "root@$LG_PUB:/opt/src.tar"
rm -f "$OUT/src.tar"

note "building ai-memory @ $BUILD_SHA_SHORT on the load generator"
ssh "${SSH_OPTS[@]}" "root@$LG_PUB" bash -s <<REMOTE
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential pkg-config libssl-dev git curl jq postgresql-client >/dev/null
command -v cargo >/dev/null || { curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y >/dev/null 2>&1; }
. "\$HOME/.cargo/env"
install -d "$SRC_DIR"
tar -xf /opt/src.tar -C "$SRC_DIR"
rm -f /opt/src.tar
cd "$SRC_DIR"
cargo build --release --features sal-postgres 2>&1 | tail -3
install -m 0755 target/release/ai-memory /usr/local/bin/ai-memory
VER="\$(ai-memory --version 2>&1 | head -1)"
echo "BUILT: \$VER"
echo "\$VER" | grep -q '1\.0\.0' || { echo "VERSION MISMATCH - expected 1.0.0, got \$VER" >&2; exit 1; }
echo "$BUILD_SHA" > /opt/ai-memory-build-sha
REMOTE

# --- end-to-end encryption proof, from the CLIENT box ----------------------
# The on-droplet checks prove the server enforces TLS. This proves the actual
# client -> data tier path over the VPC does too: same host, same credentials,
# cleartext refused and verify-full accepted.
note "proving the load generator -> data tier path is encrypted"
E2E="$(ssh "${SSH_OPTS[@]}" "root@$LG_PUB" \
  "export PGPASSWORD='$PGPASS'
   if psql 'postgresql://ai_memory@$DT_PRIV:5433/ai_memory_test?sslmode=disable' -tAc 'select 1' >/dev/null 2>&1; then
     echo 'E2E CHECK FAIL - cleartext from the load generator SUCCEEDED'
   else
     echo 'E2E CHECK PASS - cleartext from the load generator REFUSED'
   fi
   psql 'postgresql://ai_memory@$DT_PRIV:5433/ai_memory_test?sslmode=verify-full&sslrootcert=/opt/ai-memory-perf/ca.crt' -tAc \
     \"select 'E2E TLS ' || version || ' ' || cipher from pg_stat_ssl where pid = pg_backend_pid()\" 2>&1" || true)"
printf '%s\n' "$E2E" | tee -a "$OUT/stack-verification.txt"
printf '%s' "$E2E" | grep -q 'E2E CHECK PASS' \
  || die "the load generator could reach postgres in cleartext -- refusing to hand back the tier"
printf '%s' "$E2E" | grep -q 'E2E TLS TLSv1' \
  || die "the load generator could not establish a verify-full TLS session to the data tier"

note "done."
cat <<EOF

  Provisioned:
    data tier   $DT_PUB  (postgres on $DT_PRIV:5433, VPC-only, TLS REQUIRED)
    load gen    $LG_PUB  (ai-memory built from $BUILD_SHA_SHORT, version-asserted 1.0.0)

  Encryption: proven, not assumed. sslmode=disable is REFUSED by pg_hba.conf and
  sslmode=verify-full succeeds against the CA in $CERT_DIR. See
  $OUT/stack-verification.txt.

  Every benchmark MUST record: build SHA $BUILD_SHA_SHORT, droplet sizes
  ($DATATIER_SIZE / $LOADGEN_SIZE), region $REGION, and the postgres settings
  in the compose command block. A number without its configuration is not a
  result -- that is what invalidated #2616/#2624/#2598.

  Teardown when finished:   $HERE/teardown.sh
  These droplets bill hourly. Do not leave them running.
EOF
