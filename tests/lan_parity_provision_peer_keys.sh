#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Issue #1803 — IronClaw lan-parity peer-key auto-provisioning
# integration test.
#
# Targets `infra/lan-parity-test/provision-peer-keys.sh` standalone
# (mirrors the `tests/plan_c_preflight.sh` precedent for
# `infra/plan-c/peer-preflight.sh`: testing the standalone script
# avoids requiring a live 2-daemon Docker mesh for `cargo test` / a dev
# workstation run).
#
# Asserts:
#   1. Happy path — both sides' `.pub` files pre-exist → the script
#      cross-copies each into the OTHER side's directory under the
#      SAME filename (the exact lookup `identity::verify::
#      lookup_peer_public_key_in` performs on receive), leaves the
#      original files untouched, and never touches any `.priv` file.
#   2. Timeout path — neither side's `.pub` file appears within the
#      configured wait budget → exit 1 with the timeout diagnostic on
#      stderr, and NO cross-copy occurs (fail-closed, not a silent
#      partial enrollment).
#   3. Required-env guard — a missing AI_MEMORY_FED_IDENTITY_ALICE /
#      _BOB aborts immediately (`set -eu` + `${VAR:?}`) rather than
#      silently defaulting to an unenrolled/empty identity.
#
# Run directly:
#   bash tests/lan_parity_provision_peer_keys.sh
#
# Scratch lives under `.local-runs/` per the project no-`/tmp` rule
# and is cleaned up on success.
#
# Exit codes:
#   0 — all assertions passed
#   1 — at least one assertion failed (script aborts on first failure)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROVISION="${REPO_ROOT}/infra/lan-parity-test/provision-peer-keys.sh"
SCRATCH="${REPO_ROOT}/.local-runs/lan-parity-provision-peer-keys-$(date +%s)"

if [ ! -f "$PROVISION" ]; then
  echo "FAIL: provisioning script not found at $PROVISION" >&2
  exit 1
fi

mkdir -p "$SCRATCH"
cleanup() { rm -rf "$SCRATCH"; }

#
# Assertion 1: happy path cross-copy.
#
echo "=== Test 1: pre-existing keypairs are cross-enrolled by filename ==="
ALICE_DIR="$SCRATCH/t1/alice"
BOB_DIR="$SCRATCH/t1/bob"
mkdir -p "$ALICE_DIR" "$BOB_DIR"
ALICE_ID="host:ic-parity-alice"
BOB_ID="host:ic-parity-bob"
printf 'alice-fake-pubkey-bytes' >"$ALICE_DIR/$ALICE_ID.pub"
printf 'alice-fake-privkey-bytes' >"$ALICE_DIR/$ALICE_ID.priv"
printf 'bob-fake-pubkey-bytes' >"$BOB_DIR/$BOB_ID.pub"
printf 'bob-fake-privkey-bytes' >"$BOB_DIR/$BOB_ID.priv"

STDOUT_LOG="$SCRATCH/test1.stdout"
AI_MEMORY_FED_IDENTITY_ALICE="$ALICE_ID" \
  AI_MEMORY_FED_IDENTITY_BOB="$BOB_ID" \
  ALICE_KEY_DIR="$ALICE_DIR" \
  BOB_KEY_DIR="$BOB_DIR" \
  PROVISION_MAX_TRIES=5 PROVISION_SLEEP_SECS=1 \
  sh "$PROVISION" >"$STDOUT_LOG" 2>&1
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "FAIL: expected exit 0 on the happy path, got $RC" >&2
  cat "$STDOUT_LOG" >&2
  cleanup
  exit 1
fi
if [ ! -f "$BOB_DIR/$ALICE_ID.pub" ]; then
  echo "FAIL: bob's dir should now hold alice's pubkey named $ALICE_ID.pub" >&2
  cleanup
  exit 1
fi
if [ ! -f "$ALICE_DIR/$BOB_ID.pub" ]; then
  echo "FAIL: alice's dir should now hold bob's pubkey named $BOB_ID.pub" >&2
  cleanup
  exit 1
fi
if [ "$(cat "$BOB_DIR/$ALICE_ID.pub")" != "alice-fake-pubkey-bytes" ]; then
  echo "FAIL: bob's copy of alice's pubkey has the wrong content" >&2
  cleanup
  exit 1
fi
if [ "$(cat "$ALICE_DIR/$BOB_ID.pub")" != "bob-fake-pubkey-bytes" ]; then
  echo "FAIL: alice's copy of bob's pubkey has the wrong content" >&2
  cleanup
  exit 1
fi
# Originals must survive untouched.
if [ "$(cat "$ALICE_DIR/$ALICE_ID.pub")" != "alice-fake-pubkey-bytes" ]; then
  echo "FAIL: alice's own pubkey file was mutated" >&2
  cleanup
  exit 1
fi
# Private keys are NEVER copied cross-side.
if [ -f "$BOB_DIR/$ALICE_ID.priv" ] || [ -f "$ALICE_DIR/$BOB_ID.priv" ]; then
  echo "FAIL: a private key leaked across sides — the provisioner must only ever copy .pub files" >&2
  cleanup
  exit 1
fi
echo "PASS: alice<->bob cross-enrolled by resolved federation identity filename"

#
# Assertion 2: timeout path — neither side ever produces its keypair.
#
echo "=== Test 2: missing keypairs time out fail-closed (no partial enrollment) ==="
ALICE_DIR2="$SCRATCH/t2/alice"
BOB_DIR2="$SCRATCH/t2/bob"
mkdir -p "$ALICE_DIR2" "$BOB_DIR2"
STDERR_LOG2="$SCRATCH/test2.stderr"
set +e
AI_MEMORY_FED_IDENTITY_ALICE="host:ic-parity-alice" \
  AI_MEMORY_FED_IDENTITY_BOB="host:ic-parity-bob" \
  ALICE_KEY_DIR="$ALICE_DIR2" \
  BOB_KEY_DIR="$BOB_DIR2" \
  PROVISION_MAX_TRIES=1 PROVISION_SLEEP_SECS=1 \
  sh "$PROVISION" >/dev/null 2>"$STDERR_LOG2"
RC2=$?
set -e
if [ "$RC2" -eq 0 ]; then
  echo "FAIL: expected a non-zero exit when neither keypair ever appears" >&2
  cleanup
  exit 1
fi
if ! grep -q "timed out" "$STDERR_LOG2"; then
  echo "FAIL: stderr should carry the timeout diagnostic" >&2
  cat "$STDERR_LOG2" >&2
  cleanup
  exit 1
fi
if [ -n "$(find "$ALICE_DIR2" "$BOB_DIR2" -type f 2>/dev/null)" ]; then
  echo "FAIL: no files should exist after a timed-out provisioning attempt" >&2
  cleanup
  exit 1
fi
echo "PASS: provisioner times out fail-closed with no partial cross-copy"

#
# Assertion 3: missing required identity env aborts immediately.
#
echo "=== Test 3: missing AI_MEMORY_FED_IDENTITY_ALICE aborts (set -eu guard) ==="
ALICE_DIR3="$SCRATCH/t3/alice"
BOB_DIR3="$SCRATCH/t3/bob"
mkdir -p "$ALICE_DIR3" "$BOB_DIR3"
STDERR_LOG3="$SCRATCH/test3.stderr"
set +e
AI_MEMORY_FED_IDENTITY_BOB="host:ic-parity-bob" \
  ALICE_KEY_DIR="$ALICE_DIR3" \
  BOB_KEY_DIR="$BOB_DIR3" \
  sh "$PROVISION" >/dev/null 2>"$STDERR_LOG3"
RC3=$?
set -e
if [ "$RC3" -eq 0 ]; then
  echo "FAIL: expected a non-zero exit when AI_MEMORY_FED_IDENTITY_ALICE is unset" >&2
  cleanup
  exit 1
fi
echo "PASS: missing required identity env aborts the provisioner"

cleanup
echo "All lan-parity peer-key provisioning assertions passed."
