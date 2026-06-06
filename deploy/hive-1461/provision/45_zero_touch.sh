#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Zero-touch first-party trust enrollment for the peer mesh.
#
# Replaces the O(N^2) per-peer public-key push (every node holding every other
# node's `.pub`) with an O(1) "trust the CA" model: one campaign CA mints a
# short-lived, domain-scoped credential for each peer, and every receiver holds
# ONLY the CA verifying key. A peer joins the mesh by presenting its CA-signed
# credential (X-Memory-Cred) plus a per-message signature (X-Memory-Sig) whose
# key the credential binds — no operator ever pushes that peer's key to anyone
# else. With AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1 the receiver fails CLOSED
# on an unenrolled/uncredentialed peer (handlers/federation_signing_check.rs).
#
# What the daemon reads at serve time (all via the per-node EnvironmentFile, so
# no secret or path is baked into the systemd unit):
#   * AI_MEMORY_KEY_DIR                  -> dir holding THIS node's signing
#       keypair at `<key_dir>/<fed_id>.{pub,priv}`. The outbound federation
#       signer loads it by the resolved federation identity
#       (governance::audit::load_daemon_signing_key(sender_agent_id),
#       peer.rs:154), so the file MUST be keyed by the slashed fed_id.
#   * AI_MEMORY_FED_CRED_PATH            -> this node's CA-signed credential
#       (text `v1=<base64(CBOR)>`); the outbound path attaches it as
#       X-Memory-Cred and a renewal worker hot-swaps it (daemon_runtime.rs:3752).
#   * AI_MEMORY_FED_TRUST_BUNDLE_DIR     -> dir holding `<issuer_id>.pub` (the
#       CA verifying key, raw 32 bytes) — the only trust anchor a receiver
#       needs. TrustBundle::from_dir is NON-RECURSIVE, so the issuer-id MUST be
#       slash-free (enforced by FED_ISSUER_ID = "$CAMPAIGN-ca" + the issuer
#       tool's validate_issuer_id boundary check).
#   * AI_MEMORY_FED_TRUST_DOMAIN         -> scopes the bundle; a credential from
#       another domain is rejected (TrustBundle::with_trust_domain isolation).
#   * AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1 -> fail closed on unenrolled peers.
#
# All CA / node / credential material is minted LOCALLY in the gitignored run
# dir (private keys mode 0600 local / 0400 remote, NEVER committed, NEVER
# echoed) by the first-party `fed_issue` example (examples/fed_issue.rs) — NO
# Cargo.toml change, the pinned golden binary is untouched. Peers only: agents
# and ctrl are pure mTLS API clients, not mesh members (mirrors 40_tls.sh /
# 50_federation.sh peer scoping).
#
# Ordering: runs AFTER 30_config.sh (the per-node EnvironmentFile it appends to
# must exist) and BEFORE 50_federation.sh (which is the sole pusher of that
# EnvironmentFile and the step that (re)starts the daemon — it preserves the
# zero-touch lines this step appends). Re-running this step on a live fleet
# requires a subsequent 50_federation.sh (or daemon restart) to load the new
# env.
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$HIVE_ROOT/../.." && pwd)"
SECRETS_DIR="$RUN_DIR/secrets"

# Local zero-touch trust material (gitignored run dir; NEVER /tmp, NEVER committed).
ZT_DIR="$RUN_DIR/zero-touch"
CA_KEY_DIR="$ZT_DIR/ca"        # issuer keypair (<issuer_id>.pub/.priv)
NODE_KEY_DIR="$ZT_DIR/keys"    # per-node keypairs (<fed_id>.pub/.priv, nested)
BUNDLE_DIR="$ZT_DIR/trust"     # published CA verifying key (<issuer_id>.pub)
CRED_DIR="$ZT_DIR/cred"        # per-host credential header files

# Remote layout under the cloud-init-created /etc/ai-memory tree.
REMOTE_BASE="/etc/ai-memory"
REMOTE_KEY_DIR="$REMOTE_BASE/keys"
REMOTE_BUNDLE_DIR="$REMOTE_BASE/trust"
REMOTE_CRED="$REMOTE_BASE/credential"

# Remote file modes (private key root-only; world-readable public material).
REMOTE_PRIV_MODE="0400"
REMOTE_CRED_MODE="0400"
REMOTE_PUB_MODE="0444"

require_inventory
command -v cargo >/dev/null 2>&1 || die "cargo not found — the zero-touch issuer (examples/fed_issue.rs) is built from $REPO_ROOT"

mkdir -p "$ZT_DIR"; chmod 700 "$ZT_DIR"
mkdir -p "$CA_KEY_DIR" "$NODE_KEY_DIR" "$CRED_DIR"; chmod 700 "$CA_KEY_DIR" "$NODE_KEY_DIR" "$CRED_DIR"
mkdir -p "$BUNDLE_DIR"

# First-party issuer tool. --quiet suppresses cargo's build chatter so only the
# tool's own stdout (the printed pubkeys/paths) is captured. The first call
# compiles; the rest are cache hits.
fed_issue() {
  cargo run --quiet --manifest-path "$REPO_ROOT/Cargo.toml" --example fed_issue -- "$@"
}

# --- phase 1: mint the campaign CA + publish its verifying key (idempotent) ---
log "minting campaign CA (issuer=$FED_ISSUER_ID, domain=$FED_TRUST_DOMAIN)"
fed_issue mint-ca --key-dir "$CA_KEY_DIR" --issuer-id "$FED_ISSUER_ID" >/dev/null \
  || die "mint-ca failed for issuer $FED_ISSUER_ID"
fed_issue export-bundle --key-dir "$CA_KEY_DIR" --issuer-id "$FED_ISSUER_ID" \
  --bundle-dir "$BUNDLE_DIR" >/dev/null \
  || die "export-bundle failed for issuer $FED_ISSUER_ID"
BUNDLE_KEY="$BUNDLE_DIR/$FED_ISSUER_ID.pub"
[ -s "$BUNDLE_KEY" ] || die "published CA key missing ($BUNDLE_KEY)"

# --- phase 2: per-peer keypair + credential, fan out, wire env (idempotent) ---
inv_all | while IFS="$(printf '\t')" read -r host role region pub priv; do
  [ "$role" = "peer" ] || { log "[$host] role=$role is a pure mTLS client (not a mesh member) — skipping"; continue; }

  fed_id="$CAMPAIGN/$region/$host"          # resolved federation identity (== --federation-identity in 50)
  node_pub="$NODE_KEY_DIR/$fed_id.pub"
  node_priv="$NODE_KEY_DIR/$fed_id.priv"
  cred_file="$CRED_DIR/$host.cred"

  # Node keypair (nested under NODE_KEY_DIR for the slashed fed_id — relies on
  # the #1514 keypair::save nested-parent fix). Idempotent: reused if present.
  log "[$host] generating node keypair (fed_id=$fed_id)"
  fed_issue gen-node --key-dir "$NODE_KEY_DIR" --agent-id "$fed_id" >/dev/null \
    || die "[$host] gen-node failed for $fed_id"
  [ -s "$node_pub" ] && [ -s "$node_priv" ] || die "[$host] node keypair missing ($node_pub / $node_priv)"

  # Short-lived CA-signed credential binding fed_id -> node verifying key.
  log "[$host] issuing credential (issuer=$FED_ISSUER_ID, domain=$FED_TRUST_DOMAIN)"
  fed_issue issue --key-dir "$CA_KEY_DIR" --issuer-id "$FED_ISSUER_ID" \
    --trust-domain "$FED_TRUST_DOMAIN" --subject-agent-id "$fed_id" \
    --subject-pub-file "$node_pub" --out "$cred_file" >/dev/null \
    || die "[$host] issue failed for $fed_id"
  [ -s "$cred_file" ] || die "[$host] credential file missing ($cred_file)"

  # Fan out: node keypair (nested parents), CA bundle, credential.
  remote_node_pub="$REMOTE_KEY_DIR/$fed_id.pub"
  remote_node_priv="$REMOTE_KEY_DIR/$fed_id.priv"
  remote_bundle_key="$REMOTE_BUNDLE_DIR/$FED_ISSUER_ID.pub"
  log "[$host] pushing zero-touch material -> $REMOTE_BASE"
  ssh_node "$pub" "mkdir -p '$(dirname "$remote_node_pub")' '$REMOTE_BUNDLE_DIR' && chmod 700 '$REMOTE_KEY_DIR' '$REMOTE_BUNDLE_DIR'"
  scp_to "$node_pub"    "$pub" "$remote_node_pub"
  scp_to "$node_priv"   "$pub" "$remote_node_priv"
  scp_to "$BUNDLE_KEY"  "$pub" "$remote_bundle_key"
  scp_to "$cred_file"   "$pub" "$REMOTE_CRED"
  ssh_node "$pub" "chmod $REMOTE_PRIV_MODE '$remote_node_priv'; chmod $REMOTE_CRED_MODE '$REMOTE_CRED'; chmod $REMOTE_PUB_MODE '$remote_node_pub' '$remote_bundle_key'"

  # Wire the daemon env (idempotent: strip the keys we manage, then append).
  local_env="$SECRETS_DIR/$host.env"
  [ -s "$local_env" ] || die "[$host] secret env file missing ($local_env) — run provision/30_config.sh first"
  tmp_env="$local_env.tmp"
  grep -vE '^(AI_MEMORY_KEY_DIR|AI_MEMORY_FED_TRUST_BUNDLE_DIR|AI_MEMORY_FED_TRUST_DOMAIN|AI_MEMORY_FED_CRED_PATH|AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT)=' "$local_env" > "$tmp_env" || true
  {
    printf 'AI_MEMORY_KEY_DIR=%s\n'                   "$REMOTE_KEY_DIR"
    printf 'AI_MEMORY_FED_TRUST_BUNDLE_DIR=%s\n'      "$REMOTE_BUNDLE_DIR"
    printf 'AI_MEMORY_FED_TRUST_DOMAIN=%s\n'          "$FED_TRUST_DOMAIN"
    printf 'AI_MEMORY_FED_CRED_PATH=%s\n'             "$REMOTE_CRED"
    printf 'AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=%s\n' "1"
  } >> "$tmp_env"
  mv "$tmp_env" "$local_env"; chmod 600 "$local_env"
  log "[$host] zero-touch enrolled (key=$remote_node_pub, cred=$REMOTE_CRED, bundle=$remote_bundle_key)"
done

log "zero-touch enrollment complete — peers present CA-signed credentials; receivers trust only $FED_ISSUER_ID (fail-closed on unenrolled peers)"
