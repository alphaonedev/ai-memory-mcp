#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Acquire the pinned ai-memory binary and fan it out to every node atomically.
#
# Provenance (peer-reproducible, in precedence order):
#   1. $AI_MEMORY_BINARY  — explicit path to a prebuilt linux-x86_64 binary.
#   2. .local-runs/fleet/ai-memory-golden — the campaign golden artifact.
#   3. (documented) build from the pinned git ref with
#      `--features sal,sal-postgres,sqlite-bundled` and point $AI_MEMORY_BINARY
#      at target/release/ai-memory.
#
# The version (0.7.0) + schema (v55) are the reproducible guarantees and are
# asserted post-install. The sha256 pins THIS artifact for THIS run; a
# from-source rebuild on a different host may differ bitwise (LTO/path), so a
# mismatch warns (set ALLOW_SHA_MISMATCH=1 to proceed) rather than hard-fails.
source "$(dirname "$0")/lib.sh"

BIN="${AI_MEMORY_BINARY:-$DO_ROOT/../../.local-runs/fleet/ai-memory-golden}"
[ -f "$BIN" ] || die "binary not found at '$BIN' — set AI_MEMORY_BINARY or build from the pinned ref (see README)"

local_sha="$(shasum -a 256 "$BIN" | awk '{print $1}')"
log "local binary: $BIN sha256=$local_sha"
if [ "$local_sha" != "$GOLDEN_SHA256" ]; then
  if [ "${ALLOW_SHA_MISMATCH:-0}" = "1" ]; then
    log "WARN: sha != golden ($GOLDEN_SHA256) — proceeding (ALLOW_SHA_MISMATCH=1); version+schema still gated"
  else
    die "sha256 mismatch (got $local_sha, want $GOLDEN_SHA256). Set ALLOW_SHA_MISMATCH=1 for an intentional from-source rebuild."
  fi
fi

inv_all_ips | while read -r ip; do
  host="$(inv_name_for_ip "$ip")"
  log "[$host] stopping any running daemons + staging new binary"
  ssh_node "$ip" "systemctl stop ai-memory ai-memory-curator 2>/dev/null || true; mkdir -p /usr/local/bin"
  scp_to "$BIN" "$ip" "/usr/local/bin/.ai-memory.new"
  remote_sha="$(ssh_node "$ip" "sha256sum /usr/local/bin/.ai-memory.new | awk '{print \$1}'")"
  [ "$remote_sha" = "$local_sha" ] || die "[$host] transfer corruption: remote $remote_sha != local $local_sha"
  # Atomic swap — NO broad pkill (that SIGTERMs the install shell itself, the #W1 bug).
  ssh_node "$ip" "chmod 0755 /usr/local/bin/.ai-memory.new && mv -f /usr/local/bin/.ai-memory.new /usr/local/bin/ai-memory"
  ver="$(ssh_node "$ip" "/usr/local/bin/ai-memory --version 2>/dev/null" || true)"
  log "[$host] installed: $ver (sha $remote_sha)"
  case "$ver" in
    *"$EXPECTED_VERSION"*) : ;;
    *) die "[$host] version assertion failed: got '$ver', want *$EXPECTED_VERSION*" ;;
  esac
done
log "binary fan-out complete on all nodes (version $EXPECTED_VERSION, sha pinned)"
