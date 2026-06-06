#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# docker-1461 provision step 45 — zero-touch first-party enrollment.
#
# Mirrors deploy/hive-1461/provision/45_zero_touch.sh, writing into each
# peer's gitignored node dir (bind-mounted into the container) instead of
# pushing over SSH. Drives the first-party issuer example `fed_issue`
# (never linked into the golden binary) through the four verbs:
#
#   mint-ca       once per campaign  -> CA keypair (host-only, 0600)
#   export-bundle once per campaign  -> publish ONLY the CA verifying key
#   gen-node      per peer           -> node signing keypair, nested by fed_id
#   issue         per peer           -> short-lived CA-signed credential
#
# Receivers trust the CA verifying key ALONE — adding a peer never
# reconfigures any other peer. The daemon's outbound signer loads the
# node key by the resolved federation identity (AI_MEMORY_FED_IDENTITY),
# so the on-disk keypair MUST be keyed by the slashed fed_id; gen-node
# nests it exactly that way under the node's keys/ dir.
#
# Footgun guard (docs/zero-touch-quickstart.md §5): FED_ISSUER_ID must be
# slash-free or TrustBundle::from_dir (non-recursive) yields an empty
# bundle -> UnknownIssuer on every verify. lib.sh derives a safe id and
# fed_issue's validate_issuer_id rejects slashed ids at the boundary.

set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SELF_DIR/lib.sh"

CA_DIR="$ZT_ROOT/ca"
BUNDLE_DIR="$ZT_ROOT/trust"

# fed_issue invocation — built on first call, cache hits thereafter.
fed_issue() {
  cargo run --quiet --manifest-path "$REPO_ROOT/Cargo.toml" --example fed_issue -- "$@"
}

umask 077
mkdir -p "$CA_DIR" "$BUNDLE_DIR"

# --------------------------------------------------------------------------
# 1. Campaign CA + published trust bundle (once per campaign; idempotent).
# --------------------------------------------------------------------------
log "zerotouch: mint-ca ($FED_ISSUER_ID)"
fed_issue mint-ca --key-dir "$CA_DIR" --issuer-id "$FED_ISSUER_ID"
# CA private key host-only, restrictive.
[ -f "$CA_DIR/$FED_ISSUER_ID.priv" ] && chmod 0600 "$CA_DIR/$FED_ISSUER_ID.priv"

log "zerotouch: export-bundle -> $BUNDLE_DIR/$FED_ISSUER_ID.pub"
fed_issue export-bundle --key-dir "$CA_DIR" --issuer-id "$FED_ISSUER_ID" \
  --bundle-dir "$BUNDLE_DIR"
[ -s "$BUNDLE_DIR/$FED_ISSUER_ID.pub" ] \
  || die "zerotouch: export-bundle produced no $FED_ISSUER_ID.pub (slashed issuer id?)"

# --------------------------------------------------------------------------
# 2. Per-peer node keypair + CA-signed credential.
# --------------------------------------------------------------------------
i=1
while [ "$i" -le "$PEER_COUNT" ]; do
  name="$(peer_name "$i")"
  fed_id="$(peer_fed_id "$i")"
  nkeys="$NODES_ROOT/$name/keys"
  ntrust="$NODES_ROOT/$name/trust"
  ncred="$NODES_ROOT/$name/credential"
  mkdir -p "$nkeys" "$ntrust"

  log "zerotouch: gen-node $name ($fed_id)"
  fed_issue gen-node --key-dir "$nkeys" --agent-id "$fed_id"
  # Node private key nests under the slashed fed_id; lock it down.
  [ -f "$nkeys/$fed_id.priv" ] && chmod 0600 "$nkeys/$fed_id.priv"

  log "zerotouch: issue credential for $name (ttl=${CREDENTIAL_TTL_SECS}s)"
  fed_issue issue \
    --key-dir "$CA_DIR" --issuer-id "$FED_ISSUER_ID" \
    --trust-domain "$FED_TRUST_DOMAIN" \
    --subject-agent-id "$fed_id" \
    --subject-pub-file "$nkeys/$fed_id.pub" \
    --ttl-secs "$CREDENTIAL_TTL_SECS" \
    --out "$ncred"
  [ -s "$ncred" ] || die "zerotouch: issue produced no credential for $name"
  chmod 0600 "$ncred"

  # Publish the CA verifying key (the sole trust anchor) into the node's
  # trust dir. The daemon's TrustBundle::from_dir reads <issuer-id>.pub.
  cp "$BUNDLE_DIR/$FED_ISSUER_ID.pub" "$ntrust/$FED_ISSUER_ID.pub"
  chmod 0444 "$ntrust/$FED_ISSUER_ID.pub"

  i=$((i + 1))
done

log "zerotouch: OK — CA + bundle + $PEER_COUNT enrolled peers (domain=$FED_TRUST_DOMAIN)"
