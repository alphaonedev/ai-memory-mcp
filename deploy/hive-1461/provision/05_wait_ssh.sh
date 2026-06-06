#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Block until every node is SSH-reachable and cloud-init base has finished
# (the /etc/ai-memory/.cloud-init-done marker written by base.yaml.tpl).
source "$(dirname "$0")/lib.sh"

DEADLINE=$(( $(date +%s) + ${WAIT_TIMEOUT_SECS:-600} ))

inv_all_ips | while read -r ip; do
  host="$(inv_name_for_ip "$ip")"
  while :; do
    if ssh_node "$ip" "test -f /etc/ai-memory/.cloud-init-done" 2>/dev/null; then
      log "ready: $host ($ip) cloud-init done=$(ssh_node "$ip" 'cat /etc/ai-memory/.cloud-init-done' 2>/dev/null)"
      break
    fi
    [ "$(date +%s)" -lt "$DEADLINE" ] || die "timeout waiting for $host ($ip)"
    sleep 8
  done
done
log "all nodes reachable + cloud-init complete"
