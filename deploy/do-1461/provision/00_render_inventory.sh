#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Render the live inventory from Terraform state into the gitignored run dir.
# Deterministic: inventory.json is a pure projection of `terraform output fleet`.
source "$(dirname "$0")/lib.sh"

log "rendering inventory from terraform state -> $INV_JSON"
( cd "$TF_DIR" && terraform output -json fleet ) > "$INV_JSON"

[ -s "$INV_JSON" ] || die "terraform produced no fleet output — is the fleet applied?"

n="$(jq 'length' "$INV_JSON")"
log "inventory: $n nodes"
printf '%-22s %-6s %-6s %-16s %-16s\n' HOST ROLE REGION PUBLIC_IP PRIVATE_IP
inv_all | while IFS=$'\t' read -r host role region pub priv; do
  printf '%-22s %-6s %-6s %-16s %-16s\n' "$host" "$role" "$region" "$pub" "$priv"
done
