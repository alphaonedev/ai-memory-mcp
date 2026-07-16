#!/bin/sh
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# #1803 — IronClaw lan-parity peer-key auto-provisioning.
#
# Cross-enrolls alice <-> bob's federation push-signing public keys so
# a bare `docker compose -f infra/lan-parity-test/docker-compose.yml
# up -d` yields a WORKING enrolled mesh, closing the manual-step gap
# the 2026-06-24 live IronClaw A2A campaign hit (issue #1803): alice's
# signed `/sync/push` to bob 401'd even after a manual `.pub` copy,
# because the copied key didn't match what alice's daemon actually
# signs with.
#
# Root cause (pinned by reading the source, not by live iteration):
# each daemon's OUTBOUND federation signing key is loaded by
# `governance::audit::load_daemon_signing_key(&sender_agent_id)`
# (src/federation/peer.rs), keyed by the RESOLVED federation identity
# (`AI_MEMORY_FED_IDENTITY` here — see docker-compose.yml) — a
# DIFFERENT on-disk file from the fixed `DAEMON_KEYPAIR_LABEL =
# "daemon"` keypair used for link/audit signing. `ai-memory serve` has
# no auto-generate fallback for the federation-identity-labeled key;
# `entrypoint.plan-c.sh` (this stack's entrypoint, baked into
# Dockerfile.tier2-trackb) mints it on first boot. The RECEIVING side's
# `identity::verify::lookup_peer_public_key_in` — the SAME lookup that
# backs the `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT` "peer_not_enrolled"
# gate — looks for `<sender_agent_id>.pub` in ITS OWN key directory.
# So the fix is symmetric: copy each side's REAL, freshly-minted
# `<fed_identity>.pub` into the OTHER side's key volume under that
# exact filename. No `ai-memory identity import`/CLI round-trip is
# needed for this step — the on-disk key format is already the raw
# bytes `identity import` would write (`src/identity/keypair.rs`), so a
# byte-for-byte file copy between the two named docker volumes is
# sufficient and avoids depending on the daemon's HTTP surface being
# reachable from this container.
#
# This script runs as a one-shot compose service
# (`ic-parity-peer-key-provisioner`) with BOTH `ic-parity-alice-keys`
# and `ic-parity-bob-keys` volumes mounted read-write, gated on
# `depends_on: {alice,bob}: condition: service_healthy` so each
# daemon's own entrypoint keygen has already run by the time this
# fires. It is idempotent (safe to re-run / re-provision on every
# `compose up`) and exits 0 once both `.pub` files are cross-copied.

set -eu

ALICE_ID="${AI_MEMORY_FED_IDENTITY_ALICE:?missing AI_MEMORY_FED_IDENTITY_ALICE}"
BOB_ID="${AI_MEMORY_FED_IDENTITY_BOB:?missing AI_MEMORY_FED_IDENTITY_BOB}"
ALICE_DIR="${ALICE_KEY_DIR:-/keys/alice}"
BOB_DIR="${BOB_KEY_DIR:-/keys/bob}"
MAX_TRIES="${PROVISION_MAX_TRIES:-90}"
SLEEP_SECS="${PROVISION_SLEEP_SECS:-2}"

echo "[provision-peer-keys] alice=$ALICE_ID (dir=$ALICE_DIR) bob=$BOB_ID (dir=$BOB_DIR)"

tries=0
while [ ! -f "$ALICE_DIR/$ALICE_ID.pub" ] || [ ! -f "$BOB_DIR/$BOB_ID.pub" ]; do
  tries=$((tries + 1))
  if [ "$tries" -gt "$MAX_TRIES" ]; then
    echo "[provision-peer-keys] timed out after $((MAX_TRIES * SLEEP_SECS))s waiting for" \
      "$ALICE_DIR/$ALICE_ID.pub and $BOB_DIR/$BOB_ID.pub — did the daemon entrypoint's" \
      "federation-key keygen run?" >&2
    exit 1
  fi
  sleep "$SLEEP_SECS"
done

# Cross-copy: alice's public key lands in bob's key dir (named after
# alice's identity) and vice versa. Deliberately never touch the
# `.priv` files — this provisioner only ever reads/writes public
# material, so it cannot leak or clobber a signing key.
cp "$ALICE_DIR/$ALICE_ID.pub" "$BOB_DIR/$ALICE_ID.pub"
cp "$BOB_DIR/$BOB_ID.pub" "$ALICE_DIR/$BOB_ID.pub"

echo "[provision-peer-keys] cross-enrolled: $ALICE_DIR now has {$ALICE_ID,$BOB_ID}.pub;" \
  "$BOB_DIR now has {$ALICE_ID,$BOB_ID}.pub"
echo "[provision-peer-keys] mesh is enrolled — alice<->bob signed /sync/push should verify"
