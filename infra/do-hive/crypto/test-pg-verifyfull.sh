#!/usr/bin/env bash
# =============================================================================
# test-pg-verifyfull.sh — LEG 3 (daemon->Postgres sslmode=verify-full) pos+neg.
# =============================================================================
# Spins an EPHEMERAL PostgreSQL 16 cluster on $PGPORT with TLS enabled using the
# CA-signed pg-server cert from gen-certs.sh, then proves the exact sslmode
# surface the daemon's sqlx PgConnectOptions consumes:
#
#   POS  sslmode=verify-full + sslrootcert=ca.crt against host=localhost (matches
#        the cert SAN) CONNECTS with full server-cert verification.
#   POS2 the SAME connect under scram-sha-256 auth with channel_binding=require
#        succeeds. This is the leg that guards the cert KEY ALGORITHM: libpq's
#        tls-server-end-point channel binding hashes the server cert with the
#        digest in its signatureAlgorithm, so an Ed25519 chain aborts here with
#        "could not find digest for NID UNDEF" while the RSA/SHA-256 chain
#        gen-certs.sh now mints binds cleanly (regression for #2658 / the
#        misleading "Postgres accepts Ed25519" claim). The certified pg-TLS lane
#        (deploy/do-1461) and 20_pg_age.sh's pg_hba are scram-sha-256; this
#        mirrors that auth method so the local pre-flight exercises the real
#        channel-binding path, not just trust auth.
#   NEG1 sslmode=disable (plaintext) is REFUSED — pg_hba is hostssl-only.
#   NEG2 sslmode=verify-full against host=127.0.0.1 (NOT in the cert SAN) is
#        REFUSED on the hostname check ("server certificate for ... does not
#        match host name").
#   NEG3 sslmode=verify-full with an UNRELATED CA as sslrootcert is REFUSED on
#        chain verification ("self-signed certificate" / "unable to get local
#        issuer").
#
# If the ai-memory binary was built --features sal,sal-postgres, ALSO proves the
# real daemon serves a verify-full store-url end to end (best-effort; skipped
# with a clear note otherwise).
#
# Requires: ./out from gen-certs.sh (PG_HOST=localhost), pg16 initdb/pg_ctl/psql.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$HERE/out}"
ROOT="$HERE/../../.."
BIN="${BIN:-$ROOT/target/release/ai-memory}"
PGBIN="${PGBIN:-/usr/lib/postgresql/16/bin}"
PGPORT="${PGPORT:-5433}"
PGDATA="$(mktemp -d)/data"
PGUSER=aimemory; PGPASS=aimempw; PGDB=aimemory
pass=0; fail=0
ok(){ echo "PASS: $1"; pass=$((pass+1)); }
no(){ echo "FAIL: $1"; fail=$((fail+1)); }
cleanup(){ "$PGBIN/pg_ctl" -D "$PGDATA" -m immediate stop >/dev/null 2>&1; [ -n "${DPID:-}" ] && kill "$DPID" 2>/dev/null; rm -rf "$(dirname "$PGDATA")"; }
trap cleanup EXIT

# --- init ephemeral cluster --------------------------------------------------
"$PGBIN/initdb" -D "$PGDATA" -U postgres --auth=trust >/dev/null 2>&1
# stage the TLS material owned+readable by us (server runs as current user)
cp "$OUT/pg-server.crt" "$PGDATA/server.crt"; cp "$OUT/pg-server.key" "$PGDATA/server.key"
chmod 600 "$PGDATA/server.key"
cat >> "$PGDATA/postgresql.conf" <<EOF
listen_addresses = 'localhost'
port = $PGPORT
unix_socket_directories = '$PGDATA'
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
password_encryption = 'scram-sha-256'
EOF
# hostssl-only => a plaintext connection is refused at the HBA. The APP user
# ($PGUSER) authenticates with scram-sha-256 — mirroring the certified lane
# (deploy/do-1461 20_pg_age.sh) — so the POS2 leg below exercises the real
# scram channel-binding path (the one that trips over an Ed25519 server cert).
# The postgres superuser stays trust so the bootstrap probes below stay simple.
cat > "$PGDATA/pg_hba.conf" <<EOF
local   all all                       trust
hostssl all postgres 127.0.0.1/32     trust
hostssl all postgres ::1/128          trust
hostssl all all      127.0.0.1/32     scram-sha-256
hostssl all all      ::1/128          scram-sha-256
EOF
"$PGBIN/pg_ctl" -D "$PGDATA" -l "$PGDATA/pg.log" -w start >/dev/null 2>&1 || { echo "pg start failed"; tail -20 "$PGDATA/pg.log"; exit 1; }
"$PGBIN/psql" -h localhost -p "$PGPORT" -U postgres -d postgres -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<SQL
CREATE ROLE $PGUSER LOGIN PASSWORD '$PGPASS';
CREATE DATABASE $PGDB OWNER $PGUSER;
SQL
"$PGBIN/psql" -h localhost -p "$PGPORT" -U postgres -d "$PGDB" >/dev/null 2>&1 <<SQL
CREATE EXTENSION IF NOT EXISTS vector; CREATE EXTENSION IF NOT EXISTS age;
GRANT ALL ON SCHEMA ag_catalog TO $PGUSER;
SQL
export PGPASSWORD="$PGPASS"
CA="$OUT/ca.crt"

# --- POSITIVE: verify-full, correct host, pinned CA -------------------------
if "$PGBIN/psql" "host=localhost port=$PGPORT user=$PGUSER dbname=$PGDB sslmode=verify-full sslrootcert=$CA" \
     -tAc "SELECT 'tls-ok';" 2>"$OUT/../pg.pos.err" | grep -q tls-ok; then
  ok "leg3 POS: sslmode=verify-full + pinned CA + host=localhost connected"
else no "leg3 POS: verify-full connect failed ($(cat "$OUT/../pg.pos.err"))"; fi

# --- POSITIVE 2: scram-sha-256 auth + verify-full + channel_binding=require ---
# tls-server-end-point channel binding hashes the server cert using the digest
# named in its signatureAlgorithm. An Ed25519 chain has none => libpq aborts
# with "could not find digest for NID UNDEF"; the RSA/SHA-256 chain binds. This
# is the leg that would have caught the #2658 Ed25519 breakage — the older
# trust-auth-only suite never negotiated scram, so it never reached this path.
if "$PGBIN/psql" "host=localhost port=$PGPORT user=$PGUSER dbname=$PGDB sslmode=verify-full sslrootcert=$CA channel_binding=require" \
     -tAc "SELECT 'cb-ok';" 2>"$OUT/../pg.pos2.err" | grep -q cb-ok; then
  ok "leg3 POS2: scram-sha-256 + verify-full + channel_binding=require connected (RSA chain binds)"
else no "leg3 POS2: scram channel-binding connect failed ($(cat "$OUT/../pg.pos2.err"))"; fi

# --- NEGATIVE 1: plaintext (sslmode=disable) refused by hostssl-only HBA -----
if "$PGBIN/psql" "host=localhost port=$PGPORT user=$PGUSER dbname=$PGDB sslmode=disable" \
     -tAc "SELECT 1;" >/dev/null 2>"$OUT/../pg.neg1.err"; then
  no "leg3 NEG1: plaintext connection unexpectedly succeeded"
else
  ok "leg3 NEG1: plaintext (sslmode=disable) refused ($(grep -oiE 'no pg_hba|SSL.*required|no encryption' "$OUT/../pg.neg1.err" | head -1))"
fi

# --- NEGATIVE 2: verify-full but host=127.0.0.1 not in cert SAN --------------
if "$PGBIN/psql" "host=127.0.0.1 port=$PGPORT user=$PGUSER dbname=$PGDB sslmode=verify-full sslrootcert=$CA" \
     -tAc "SELECT 1;" >/dev/null 2>"$OUT/../pg.neg2.err"; then
  no "leg3 NEG2: verify-full with mismatched host unexpectedly succeeded"
else
  ok "leg3 NEG2: verify-full host mismatch refused ($(grep -oiE 'does not match|certificate.*host' "$OUT/../pg.neg2.err" | head -1))"
fi

# --- NEGATIVE 3: verify-full with an UNRELATED CA (unpinned) refused ---------
openssl genpkey -algorithm ed25519 -out "$OUT/../otherca.key" 2>/dev/null
openssl req -x509 -new -key "$OUT/../otherca.key" -days 1 -out "$OUT/../otherca.crt" -subj "/CN=other-CA" 2>/dev/null
if "$PGBIN/psql" "host=localhost port=$PGPORT user=$PGUSER dbname=$PGDB sslmode=verify-full sslrootcert=$OUT/../otherca.crt" \
     -tAc "SELECT 1;" >/dev/null 2>"$OUT/../pg.neg3.err"; then
  no "leg3 NEG3: verify-full with unrelated CA unexpectedly succeeded"
else
  ok "leg3 NEG3: verify-full unpinned/invalid CA refused ($(grep -oiE 'issuer|self.signed|certificate verify' "$OUT/../pg.neg3.err" | head -1))"
fi
rm -f "$OUT/../otherca.key" "$OUT/../otherca.crt" "$OUT/../pg.*.err" 2>/dev/null

# --- Optional: real daemon serves a verify-full store-url (needs sal-postgres)
STORE="postgres://$PGUSER:$PGPASS@localhost:$PGPORT/$PGDB?sslmode=verify-full&sslrootcert=$CA"
DLOG="$(mktemp)"
AI_MEMORY_NO_CONFIG=1 AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0 \
  "$BIN" serve --host 127.0.0.1 --port 19078 --store-url "$STORE" >"$DLOG" 2>&1 &
DPID=$!
sleep 8
if grep -qiE "sal-postgres|requires .*features" "$DLOG"; then
  echo "SKIP: daemon binary lacks --features sal-postgres; psql-level verify-full proof stands. (DO round uses a sal-postgres build.)"
elif curl -s --max-time 5 "http://127.0.0.1:19078/api/v1/health" -o /dev/null; then
  ok "leg3 EXTRA: daemon connected over verify-full TLS and served /health"
else
  echo "INFO: daemon did not bind within window; log tail:"; tail -5 "$DLOG"
fi
kill "$DPID" 2>/dev/null; rm -f "$DLOG"

echo "----"; echo "leg3 summary: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
