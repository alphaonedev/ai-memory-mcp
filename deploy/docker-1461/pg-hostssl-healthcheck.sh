#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# docker-1461 PostgreSQL healthcheck (#2658) -- fail-CLOSED hostssl proof.
#
# THE FAIL-OPEN THIS CLOSES. The prior compose healthcheck was
# `pg_isready -U <user> -d <db>`, which speaks over the LOCAL unix socket
# (pg_hba `local ... trust`). That probe reports "healthy" whenever the
# postmaster is up -- REGARDLESS of whether hostssl enforcement was armed
# on the TCP listener. So a run in which the TLS/hostssl arming silently
# did not take effect (a lost bind-mount of pg_hba.conf, an ssl GUC that
# never applied, PGDATA non-empty so init was skipped, ...) would bring
# PostgreSQL up ACCEPTING CLEARTEXT on TCP while the container reported
# healthy and provisioning proceeded. That is a silent security disarm in
# the certified provisioning lane (issue #2658).
#
# THE GUARD. This script reports healthy ONLY when BOTH hold:
#   (1) the server is ready (pg_isready over the local socket), AND
#   (2) hostssl is PROVABLY armed -- a plaintext (sslmode=disable) TCP
#       connection to the loopback listener is REFUSED PRE-AUTH by
#       pg_hba.conf ("no pg_hba.conf entry ... no encryption").
# Any outcome in which the cleartext TCP connection is ACCEPTED (it
# succeeds, or it reaches authentication -- proving the transport was
# admitted in cleartext) FAILS the healthcheck. The container therefore
# never reports healthy while cleartext is accepted, and the provisioning
# gate (provision/50_up.sh) that blocks on `healthy` fails LOUD instead of
# declaring a cleartext-accepting mesh ready.
#
# DEGRADE-NEVER-DISARM. Fail-closed by construction: any probe outcome
# other than a proven pre-auth refusal is treated as "hostssl NOT proven"
# and the healthcheck fails. Worst case is a mesh that will not come up
# (loud), never a mesh that comes up cleartext (silent).
#
# `--self-test` exercises the classifier over simulated psql outputs with
# NO live PostgreSQL (mirrors scripts/check-*.sh --self-test), so the
# decision logic is CI-provable.

set -u

PGUSER_EFF="${POSTGRES_USER:-${PGUSER:-postgres}}"
PGDB_EFF="${POSTGRES_DB:-${PGDATABASE:-$PGUSER_EFF}}"
PGPORT_EFF="${PGPORT:-5432}"
PGHOST_PLAINTEXT="127.0.0.1"

# classify_plaintext_probe <combined-psql-output>
#   -> stdout one of: armed | cleartext_accepted | unknown
#   armed              : plaintext TCP refused PRE-AUTH by hostssl pg_hba
#                        ("no pg_hba.conf entry ... no encryption").
#   cleartext_accepted : the non-TLS transport was admitted -- either the
#                        query ran (trust) or it reached authentication
#                        (a password/auth error is proof the cleartext
#                        connection was accepted at the transport layer).
#   unknown            : neither signature -- treated as NOT proven
#                        (fail-closed) by the caller.
classify_plaintext_probe() {
  local out="$1"
  case "$out" in
    *"no pg_hba.conf entry"*|*"no encryption"*)
      printf 'armed\n'; return 0 ;;
  esac
  case "$out" in
    *"password"*|*"authentication"*|*"fe_sendauth"*|*"no password supplied"*)
      printf 'cleartext_accepted\n'; return 0 ;;
  esac
  # A successful scalar result (the query RAN over cleartext) is the worst
  # case. `$(...)` strips trailing newlines, so a clean `SELECT 1` collapses
  # to the exact string "1"; guard the last-line form too.
  case "$out" in
    1) printf 'cleartext_accepted\n'; return 0 ;;
  esac
  case "$out" in
    *"
1") printf 'cleartext_accepted\n'; return 0 ;;
  esac
  printf 'unknown\n'
}

run_healthcheck() {
  # (1) readiness over the local socket.
  if ! pg_isready -U "$PGUSER_EFF" -d "$PGDB_EFF" >/dev/null 2>&1; then
    echo "[hostssl-healthcheck] not ready: pg_isready failed" >&2
    return 1
  fi

  # (2) plaintext TCP probe -- MUST be refused pre-auth by the hostssl pg_hba.
  # `-w` so a stock (non-hostssl) pg_hba that reaches auth fails without a
  # password prompt rather than hanging; the point is that reaching auth AT
  # ALL proves the cleartext transport was admitted.
  local conn probe_out verdict
  conn="host=${PGHOST_PLAINTEXT} port=${PGPORT_EFF} user=${PGUSER_EFF} dbname=${PGDB_EFF} sslmode=disable connect_timeout=5"
  probe_out="$(psql "$conn" -w -tAc 'SELECT 1' 2>&1)"
  verdict="$(classify_plaintext_probe "$probe_out")"

  case "$verdict" in
    armed)
      return 0 ;;
    cleartext_accepted)
      echo "[hostssl-healthcheck] FAIL-CLOSED (#2658): a plaintext sslmode=disable TCP connection to ${PGHOST_PLAINTEXT}:${PGPORT_EFF} was ACCEPTED -- hostssl is NOT armed. Refusing to report healthy. probe: ${probe_out}" >&2
      return 1 ;;
    *)
      echo "[hostssl-healthcheck] FAIL-CLOSED (#2658): could not PROVE the plaintext sslmode=disable TCP connection to ${PGHOST_PLAINTEXT}:${PGPORT_EFF} was refused pre-auth -- treating hostssl as NOT proven. probe: ${probe_out}" >&2
      return 1 ;;
  esac
}

self_test() {
  local fails=0 got
  check() { # <label> <expected> <probe-output>
    got="$(classify_plaintext_probe "$3")"
    if [ "$got" = "$2" ]; then
      echo "  ok   $1 -> $got"
    else
      echo "  FAIL $1 -> got '$got', want '$2'"; fails=$((fails + 1))
    fi
  }
  echo "[hostssl-healthcheck --self-test] classifier decision table:"
  # hostssl armed: canonical pre-auth refusal.
  check hostssl_refusal armed \
    'psql: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  no pg_hba.conf entry for host "127.0.0.1", user "ai_memory", database "ai_memory", no encryption'
  check no_encryption_only armed 'FATAL:  no encryption'
  # cleartext accepted: reached auth (transport admitted) or ran the query.
  check stock_no_password cleartext_accepted 'psql: error: connection ... failed: fe_sendauth: no password supplied'
  check stock_auth_failed cleartext_accepted 'psql: error: FATAL:  password authentication failed for user "ai_memory"'
  check trust_query_ran cleartext_accepted '1'
  # ambiguous -> fail-closed (unknown).
  check tcp_refused unknown 'psql: error: connection to server at "127.0.0.1", port 5432 failed: Connection refused'
  check timeout unknown 'psql: error: connection ... failed: timeout expired'
  if [ "$fails" -eq 0 ]; then
    echo "[hostssl-healthcheck --self-test] PASS"
    return 0
  fi
  echo "[hostssl-healthcheck --self-test] FAIL ($fails)"
  return 1
}

case "${1:-}" in
  --self-test) self_test ;;
  *)           run_healthcheck ;;
esac
