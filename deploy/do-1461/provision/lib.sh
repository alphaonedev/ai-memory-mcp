# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Shared library for the push-based provisioning + validation toolkit.
# Sourced by every provision/*.sh and validate/*.sh script. bash-3.2 safe
# (macOS default): indexed arrays only, no associative arrays, no process
# substitution (the #66 SIGTRAP class), no `mapfile`.

set -euo pipefail

DO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Run-state (inventory, generated TLS, render artifacts) lives in the gitignored
# project-local scratch dir per the no-/tmp hard rule. NEVER under /tmp.
RUN_DIR="${DO_1461_RUN_DIR:-$DO_ROOT/../../.local-runs/do-1461}"
mkdir -p "$RUN_DIR"

TF_DIR="$DO_ROOT/terraform"
INV_JSON="$RUN_DIR/inventory.json"

# Campaign + pinned-artifact constants (single source of truth for the toolkit).
CAMPAIGN="${CAMPAIGN:-do-1461}"
FEDERATION_PORT="${FEDERATION_PORT:-9077}"

# Cross-region SYNCHRONOUS write quorum W (ai-memory --quorum-writes). EMPTY
# (default) = auto: quorum_writes() derives W from the live inventory.
#
# DESIGN (2026-06-08, issue #1535): ai-memory federation is PRIMARILY EVENTUAL —
# every HTTP write commits LOCALLY, then the async catch-up poller
# (--catchup-interval-secs) and the post-quorum detach fan-out converge it to
# every peer in every region. The synchronous --quorum-writes layer is an
# OPTIONAL strong-durability gate on the write's HTTP response: it makes the 2xx
# wait for W-1 REMOTE acks before returning. A true cross-region MAJORITY
# (W=floor(N/2)+1 = 5 of 9) is the WRONG model for a 3-region demo — it is
# fragile (any 5th ack stalls behind the slowest inter-region RTT or a single
# down peer turns every write into a 503) and it conflates "durable enough to
# ack" with "converged everywhere". We therefore pin a SMALL synchronous quorum
# (FED_SYNC_QUORUM_W below): commit-local + ONE cross-region remote ack, which
# proves at-least-one-remote durability on the synchronous path WITHOUT making
# the write hostage to a full majority; the harness then asserts FULL 3-region
# CONVERGENCE via the async catch-up window (test/run.sh federation.convergence,
# validate/run.sh). Override QUORUM_WRITES with an explicit integer ONLY for a
# benchmark/chaos arm — NEVER hardcode a literal at a call site; always
# interpolate $(quorum_writes).
QUORUM_WRITES="${QUORUM_WRITES:-}"

# FED_SYNC_QUORUM_W — the derived synchronous quorum when QUORUM_WRITES is unset.
# 2 = local commit + 1 cross-region remote ack (at-least-one-remote durability on
# the synchronous path). Clamped down to the available node count on tiny fleets
# (a 1-peer inventory falls back to W=1 = commit-local-then-async-converge) so
# quorum_writes() never returns a W the mesh cannot satisfy.
FED_SYNC_QUORUM_W="${FED_SYNC_QUORUM_W:-2}"

# Federation timing knobs — named here (SSOT) so NO literal lives at the
# 50_federation.sh serve call site. FED_QUORUM_TIMEOUT_MS: synchronous-quorum
# ack wait (2000ms comfortably covers one cross-region ack RTT ~150-250ms at
# FED_SYNC_QUORUM_W=2). FED_CATCHUP_INTERVAL_SECS: async /sync/since pull cadence
# (the PRIMARY convergence mechanism). FED_SHUTDOWN_GRACE_SECS: graceful-drain
# window on daemon stop. Override any via env for tighter/looser SLAs.
# 8000ms (was 2000): the synchronous quorum ack must cover a CROSS-CONTINENT
# round trip (fra1↔nyc3↔sgp1) PLUS the receiver's per-memory work — which can
# include a ~1s nomic embed-on-receive when the incoming row carries no vector
# (e.g. after a v29 embedding-dim migration NULLs embeddings) and the AGE
# projection. 2000ms was tuned for same-DC and is too tight here, causing
# push `deadline_exceeded` → DLQ. The write still commits LOCALLY first, so a
# longer remote-ack wait only affects the synchronous-durability gate, not the
# local write; async catch-up converges the remaining peers regardless.
FED_QUORUM_TIMEOUT_MS="${FED_QUORUM_TIMEOUT_MS:-8000}"
FED_CATCHUP_INTERVAL_SECS="${FED_CATCHUP_INTERVAL_SECS:-30}"
FED_SHUTDOWN_GRACE_SECS="${FED_SHUTDOWN_GRACE_SECS:-30}"

# FED_CRED_TTL_SECS — lifetime of each zero-touch CA-signed peer credential
# (45_zero_touch.sh `fed_issue issue --ttl-secs`). The substrate default is
# DEFAULT_CREDENTIAL_TTL_SECS = SECS_PER_HOUR (1h) — appropriate for a
# short-lived issue/verify proof, but a LONG-LIVED hive silently partitions ~1h
# after provision once every peer's credential expires: the receiver's
# credential-chain verify fails `credential_expired`, falls through to legacy
# per-peer enrollment (which is empty under zero-touch), and FED_REQUIRE_SIG=1 +
# FED_REQUIRE_PEER_ENROLLMENT=1 then 401-reject BOTH /sync/push (quorum) AND
# /sync/since (catch-up) — observed LIVE on do-1461 (issue #1535). We mint
# hive-lifetime credentials (7 days) so the zero-touch credential path keeps
# verifying for the campaign's duration WITHOUT weakening any security gate.
# Re-running 45_zero_touch.sh re-mints fresh credentials (idempotent rotation).
FED_CRED_TTL_SECS="${FED_CRED_TTL_SECS:-604800}"   # 7 * SECS_PER_DAY

# Zero-touch first-party trust constants (45_zero_touch.sh). Derived from
# CAMPAIGN so there is a single source of truth and no bare literal.
#   * FED_ISSUER_ID  — the campaign CA identity. MUST be slash-free: a trust
#     bundle is non-recursive, so a slashed issuer-id would nest the published
#     `<issuer-id>.pub` in a skipped sub-dir → empty bundle → UnknownIssuer.
#   * FED_TRUST_DOMAIN — scopes every minted credential; a receiver bound to a
#     different domain rejects it (TrustBundle::with_trust_domain isolation).
FED_ISSUER_ID="${FED_ISSUER_ID:-$CAMPAIGN-ca}"
FED_TRUST_DOMAIN="${FED_TRUST_DOMAIN:-$CAMPAIGN.fleet}"
# Golden ai-memory linux-x86_64 sha256, --features sal,sal-postgres,sqlite-bundled.
# Re-pinned for release/v0.7.0 @ d7fff95c (2026-06-10 GA drive, #1579 close):
# rebuilt from the post-#1579 HEAD that carries the FULL 16-item performance
# remediation train (A1-A5, B1-B10, #1581 mTLS) advancing schema v55 → v56
# (composite list/archive indexes) → v57 (postgres stored generated tsvector),
# PLUS the post-merge 10-agent security audit fixes #1582 (admin read-visibility
# authn gate), #1583 (MCP governance hook), #1584 (federation shipped-vector
# finite+L2-norm validation), #1585 (to_store_err redaction), #1586
# (list_unembedded ctx guard). Supersedes the 21bd6899 / 4bb54c4d pre-train
# golden. Default suite 7842/0 + sal-postgres 9050/0 at the pin commit.
# Re-pinned 2026-06-11 (#1598 Phase-2 fleet rewire): the prior fc78a9e6 pin was
# minted from a DEFAULT-features `cargo build --release` — it lacks the
# sal-gated `serve --store-url` (80 subcommands, not 82) and crash-loops every
# postgres-backed peer with `error: unexpected argument '--store-url' found`
# (observed live on do-1461-peer-fra1-01, restart counter 38). This pin is the
# same release/v0.7.0 @ 5b064f38 source rebuilt WITH the required
# `--features sal,sal-postgres,sqlite-bundled`.
# Re-pinned 2026-06-11 (#1588 dogfood RE-RUN fix train): release/v0.7.0 @
# c8d0ef5f rebuilt with the same SAL feature set. Carries #1604 (rerank
# input-sequence cap — warm autonomous recall 4013ms → 1206ms on the f2
# corpus), #1605 (capabilities enforced_actions = snake_case wire kinds),
# #1606 (memory_recall example uses `context`), and #1607 (postgres
# touch_after_recall GREATEST extension floor — the fleet-relevant #1596
# parity fix; pre-fix every recall on a postgres-backed peer pulled a
# mid-tier row's +7d backstop in to now+1d). Schema stays v57 (no new
# migrations). Supersedes the e0ad8c34 Phase-3 golden.
# Re-pinned 2026-06-12 (GA coverage campaign): release/v0.7.0 @ 5ffc33bb.
# Carries the full GA fix train on top of e8783689 PLUS the COV-4
# postgres source fix ffb87b6e (bind updated_at as ::timestamptz in
# {bind,revoke}_agent_pubkey — the prior text bind broke on pg), which
# changes the sal-postgres binary, so the golden is re-pinned off the
# 9300e7d8 (ee00d8bb) build. Prior train still rides: #1608 (27-column
# store_with_embedding + store/store_batch QW-2 parity), #1542
# (AGE-projection SAVEPOINT isolation — links no longer silently
# rolled back on LOAD-refused roles), #1539 (PUT /agents/{id}/pubkey,
# routes 89/75), #1536 tooling fixes ride the repo not the binary,
# plus the uniform-90 coverage-lift tests (no production codegen
# change beyond ffb87b6e). Schema stays v57. Supersedes 9300e7d8.
GOLDEN_SHA256="${GOLDEN_SHA256:-c7c0bddaee3b601c8b18e07ec0a16d5d1e13a937a62e8d0827a147d66ee5fcac}"
EXPECTED_VERSION="${EXPECTED_VERSION:-0.7.0}"
EXPECTED_SCHEMA="${EXPECTED_SCHEMA:-57}"

# ---------------------------------------------------------------------------
# Batman-active MAXIMUM-SECURE posture (46_batman.sh). The full env-var battery
# every fleet node carries so the v0.7.0 secure-default surfaces are LIVE over
# the wire: per-message federation signing + nonce anti-replay + peer
# enrollment, agent attestation on every write, enforce-mode permissions,
# fail-CLOSED governance, and the Form-5 auto-confidence / shadow / decay
# curator loop. Each entry is NAME=VALUE; 46_batman.sh strip-then-appends them
# to each node's 0400 EnvironmentFile (bash-3.2: an indexed array, NOT an
# associative array). NO bare literal lives in the script — the list is here.
#
# DELIBERATELY ABSENT: AI_MEMORY_ENCRYPT_AT_REST. That flag is a sqlite-at-rest
# (sqlcipher) feature and these peers are POSTGRES-backed, so it is a no-op
# (its DB-open gate only fires on the sqlite path). For postgres peers,
# data-at-rest is a Postgres/disk concern (cluster --data-checksums + host-disk
# encryption) and data-in-transit is covered by the Leg-3 verify-full daemon→PG
# TLS leg; we do NOT rebuild the golden binary with --features sqlcipher.
BATMAN_ENV_NAMES=(
  AI_MEMORY_FED_REQUIRE_SIG
  AI_MEMORY_FED_REQUIRE_NONCE
  AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT
  AI_MEMORY_REQUIRE_AGENT_ATTESTATION
  AI_MEMORY_PERMISSIONS_MODE
  AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR
  AI_MEMORY_AUTO_CONFIDENCE
  AI_MEMORY_CONFIDENCE_SHADOW
  AI_MEMORY_CONFIDENCE_DECAY
)
BATMAN_ENV_VALUES=(
  1            # AI_MEMORY_FED_REQUIRE_SIG            — reject missing/invalid X-Memory-Sig (401)
  1            # AI_MEMORY_FED_REQUIRE_NONCE          — reject nonce replay (401)
  1            # AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT— reject unenrolled X-Peer-Id (401)
  1            # AI_MEMORY_REQUIRE_AGENT_ATTESTATION  — unsigned write -> 403 ATTESTATION_FAILED
  enforce      # AI_MEMORY_PERMISSIONS_MODE           — K3/K9 governance enforce
  0            # AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR — fail CLOSED on rule errors
  1            # AI_MEMORY_AUTO_CONFIDENCE            — Form-5 auto-confidence
  1            # AI_MEMORY_CONFIDENCE_SHADOW          — Form-5 shadow pipeline
  1            # AI_MEMORY_CONFIDENCE_DECAY           — Form-5 decay sweep
)

# Form-7 governance seed rules enabled (--sign) on every peer (R001..R004), and
# the curator daemon cadence. Named constants — no literal in 46_batman.sh.
BATMAN_SEED_RULES=(R001 R002 R003 R004)
BATMAN_CURATOR_INTERVAL_SECS="${BATMAN_CURATOR_INTERVAL_SECS:-300}"
BATMAN_CURATOR_MAX_OPS="${BATMAN_CURATOR_MAX_OPS:-100}"
# Curator-liveness gate (#1550): the curator daemon must be `active` with
# at most this many systemd auto-restarts. A crash-loop (the #1547 unit
# bug exited 2 → hundreds of restarts) trips the test harness curator group.
CURATOR_HEALTH_MAX_RESTARTS="${CURATOR_HEALTH_MAX_RESTARTS:-3}"

# ---------------------------------------------------------------------------
# Pinned PostgreSQL 18.4 + Apache AGE 1.7.0 + pgvector 0.8.2 substrate — NATIVE
# (NO Docker anywhere on the DO fleet, per operator decision). Installed from
# the official PostgreSQL apt repository (pgdg) on the droplet's own distro.
# Assessment (verified against the live pgdg noble repo): apt is a complete,
# pinned install vector for all three —
#   * postgresql-18         18.4   (exact)
#   * postgresql-18-pgvector 0.8.2 (exact)
#   * postgresql-18-age      ships age.control default_version='1.7.0' and
#     age--1.7.0.sql, built from the SAME commit (806fa2eb) as the
#     apache/age:release_PG18_1.7.0 image docker-1461 used — the pgdg "~rc0"
#     is only a Debian revision label, so CREATE EXTENSION age reports
#     extversion = 1.7.0 (asserted by the validate harness). No source build.
# Every version literal lives HERE (SSOT) and is asserted post-install.
PG_MAJOR="${PG_MAJOR:-18}"                                          # server major (apt pkg suffix)
PGDG_CODENAME="${PGDG_CODENAME:-noble}"                            # droplet distro codename (Ubuntu 24.04)
PG_APT_VERSION="${PG_APT_VERSION:-18.4-1.pgdg24.04+1}"             # pinned exact pgdg server .deb
PGVECTOR_APT_VERSION="${PGVECTOR_APT_VERSION:-0.8.2-1.pgdg24.04+1}" # pinned pgvector 0.8.2
AGE_APT_VERSION="${AGE_APT_VERSION:-1.7.0~rc0-1.pgdg24.04+1}"      # AGE 1.7.0 (extversion 1.7.0)
# Reproducibility assertion anchors — the validate harness asserts these exact
# upstream-reported versions (directive: results must reflect 18.4 + AGE 1.7.0).
EXPECTED_PG_VERSION="${EXPECTED_PG_VERSION:-18.4}"
EXPECTED_AGE_VERSION="${EXPECTED_AGE_VERSION:-1.7.0}"
EXPECTED_PGVECTOR_VERSION="${EXPECTED_PGVECTOR_VERSION:-0.8.2}"

# Native cluster identity (Debian/Ubuntu postgresql-common layout). Applied
# identically on EACH region's pg droplet; the daemon-owned TLS material is
# installed to PG_TLS_DIR (postgres owned, key 0600) so the server can read its
# ssl_key_file.
PG_CLUSTER="${PG_CLUSTER:-main}"                                   # pg_lsclusters cluster name
PG_CONF_DIR="${PG_CONF_DIR:-/etc/postgresql/$PG_MAJOR/$PG_CLUSTER}"
PG_TLS_DIR="${PG_TLS_DIR:-$PG_CONF_DIR/tls}"                       # postgres-owned cert/key copy
PG_STAGE_DIR="${PG_STAGE_DIR:-/opt/do-1461/pg}"                    # in-droplet render staging

# Per-peer CPU embedder — NATIVE Ollama (pinned release binary + systemd unit,
# localhost-bound). No container. Mirrors the pinned 0.6.8 the image used.
OLLAMA_VERSION="${OLLAMA_VERSION:-0.6.8}"

# ---------------------------------------------------------------------------
# Benchmark-matrix knobs (#172). Each is EMPTY by default → the value is NOT
# emitted → the server runs at its stock PG18.4 setting. That stock bring-up
# IS the B0 control arm. A matrix arm (A1/A4/A6 …) re-provisions with exactly
# ONE knob set so its effect is isolated. Server-level knobs become `-c k=v`
# postgres args (20_pg_age.sh); the hnsw GUC is a per-DB default applied in the
# rendered init SQL. NEVER hardcode an arm value here — override via env at
# provision time so B0 stays the committed default.
PG_SYNCHRONOUS_COMMIT="${PG_SYNCHRONOUS_COMMIT:-}"      # A4: local | off (W=2 gives cross-node durability)
PG_SHARED_BUFFERS="${PG_SHARED_BUFFERS:-}"              # A6: e.g. 2GB
PG_EFFECTIVE_CACHE_SIZE="${PG_EFFECTIVE_CACHE_SIZE:-}"  # A6: e.g. 6GB
PG_WORK_MEM="${PG_WORK_MEM:-}"                          # A6: e.g. 64MB
PG_MAINTENANCE_WORK_MEM="${PG_MAINTENANCE_WORK_MEM:-}"  # A1: faster HNSW build
PG_MAX_CONNECTIONS="${PG_MAX_CONNECTIONS:-}"            # A5: widen server-side cap
PG_HNSW_EF_SEARCH="${PG_HNSW_EF_SEARCH:-}"              # A1: recall/latency tradeoff (per-DB GUC)

# ---------------------------------------------------------------------------
# Regional PG substrate wiring (one pg node PER REGION; every peer keyed to its
# own search_path schema ic_peer_<K> on ITS region's pg). A region's peers reach
# THAT region's pg node on the region's private VPC IP over TLS (verify-full):
# encrypt AND validate the server cert against the campaign CA AND match its SAN
# to the dialed host. This is the third encrypted leg of the mesh (the others:
# cross-region federation/quorum mTLS + API mTLS). Schema indices are WITHIN a
# region: each regional pg hosts ic_peer_1..K for that region's K peers, so the
# nyc3 pg and the fra1 pg each independently host ic_peer_1, ic_peer_2, ...
PG_USER="${PG_USER:-ai_memory}"
PG_DB="${PG_DB:-ai_memory}"
PG_PORT="${PG_PORT:-5432}"
PEER_SCHEMA_PREFIX="${PEER_SCHEMA_PREFIX:-ic_peer_}"        # ic_peer_1 .. ic_peer_K per region
AGE_GRAPH_NAME="${AGE_GRAPH_NAME:-memory_graph}"
PG_SSL_MODE="${PG_SSL_MODE:-verify-full}"
# In-droplet path to the campaign CA the daemon verifies the PG server cert
# against (15_tls.sh lays ca.pem into each peer's tls dir).
PG_SSL_ROOT_CERT="${PG_SSL_ROOT_CERT:-/etc/ai-memory/tls/ca.pem}"

# peer_schema <1-based-within-region-index> -> ic_peer_1 ; pure function of the
# index. The index is a peer's position within its OWN region's sorted peer set
# (peer_schema_index_in_region), so each regional pg hosts ic_peer_1..K.
peer_schema() { printf '%s%s' "$PEER_SCHEMA_PREFIX" "$1"; }

# Autonomous-tier substrate model wiring (matches entrypoint.plan-c.sh's
# proven shape: cloud LLM + local CPU Ollama nomic embedder + cross-encoder).
# The peers run NO GPU: the chat LLM is a cloud OpenAI-compatible endpoint
# (OpenRouter Gemma 4 26B) while the 768-dim nomic embedder runs on a pinned
# CPU Ollama sidecar bound to localhost. The embedder is selected by the
# autonomous tier preset (NomicEmbedV15) and pointed at the sidecar via the
# legacy flat `embed_url`/`ollama_url` fields — `build_embedder` reads those,
# NOT the v2 `[embeddings].url` section (src/config.rs::effective_embed_url).
EMBED_MODEL="${EMBED_MODEL:-nomic-embed-text}"          # Ollama-registry id (768-dim)
# Embedding column dimension for the peer pgvector schema. MUST match the
# embedder's output width or every embedding insert fails the vector(N) check.
# nomic-embed-text (v1.5) emits 768; the ai-memory baseline schema defaults to
# 384 (MiniLM), so `schema-init` is invoked with --embedding-dim "$EMBED_DIM"
# to template `vector(768)`. Override in lockstep with EMBED_MODEL for forks.
EMBED_DIM="${EMBED_DIM:-768}"
EMBED_OLLAMA_URL="${EMBED_OLLAMA_URL:-http://127.0.0.1:11434}"
# Peer chat LLM is provider-agnostic (genericized #1490): backend/key-env/model
# are independent knobs. Defaults = the documented no-GPU OpenRouter Gemma path;
# override all three in lockstep to drive a different OpenAI-compatible provider
# (e.g. PEER_LLM_BACKEND=xai PEER_LLM_API_KEY_ENV=XAI_API_KEY PEER_LLM_MODEL=grok-4.3).
PEER_LLM_BACKEND="${PEER_LLM_BACKEND:-openrouter}"
PEER_LLM_API_KEY_ENV="${PEER_LLM_API_KEY_ENV:-OPENROUTER_API_KEY}"
PEER_LLM_MODEL="${PEER_LLM_MODEL:-google/gemma-4-26b-a4b-it}"  # chat id for $PEER_LLM_BACKEND

# #1598 API embeddings (operator decisions 2026-06-11: USA models, paid tier,
# Ollama only on GPU nodes — do-1461 peers are CPU-only). The embed secret
# rides the SAME EnvironmentFile env var as [llm] (OpenRouter key). dim=768 is
# the fleet-wide Matryoshka pin: gemini-embedding-2 truncates server-side so
# the PG regions' vector(768) schemas + ANN indexes (pgvector 2000-dim cap)
# stay untouched. Override the trio in lockstep for forks.
PEER_EMBED_BACKEND="${PEER_EMBED_BACKEND:-openrouter}"
PEER_EMBED_MODEL="${PEER_EMBED_MODEL:-google/gemini-embedding-2}"
PEER_EMBED_DIM="${PEER_EMBED_DIM:-768}"
AGENT_LLM_MODEL="${AGENT_LLM_MODEL:-grok-4.3}"                 # xAI chat id (agent NHI)
DEFAULT_NAMESPACE="${DEFAULT_NAMESPACE:-do-1461}"

SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4"

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die()  { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

# ssh_node <ip> <remote-command-string>
# -n protects stdin so loops over `inv_*` output don't get consumed by ssh.
ssh_node() {
  local ip="$1"; shift
  # shellcheck disable=SC2086
  ssh -n $SSH_OPTS "root@${ip}" "$@"
}

# scp_to <local> <ip> <remote>
scp_to() {
  local src="$1" ip="$2" dst="$3"
  # shellcheck disable=SC2086
  scp $SSH_OPTS "$src" "root@${ip}:${dst}"
}

require_inventory() {
  [ -s "$INV_JSON" ] || die "inventory missing ($INV_JSON) — run provision/00_render_inventory.sh after terraform apply"
}

# Inventory accessors. One node per line where applicable.
inv_all()           { require_inventory; jq -r 'to_entries[] | "\(.key)\t\(.value.role)\t\(.value.region)\t\(.value.public_ip)\t\(.value.private_ip)"' "$INV_JSON"; }
inv_ips_by_role()   { require_inventory; jq -r --arg r "$1" 'to_entries[]|select(.value.role==$r)|.value.public_ip' "$INV_JSON"; }
inv_names_by_role() { require_inventory; jq -r --arg r "$1" 'to_entries[]|select(.value.role==$r)|.key' "$INV_JSON"; }
inv_name_for_ip()   { require_inventory; jq -r --arg ip "$1" 'to_entries[]|select(.value.public_ip==$ip)|.key' "$INV_JSON"; }
inv_all_ips()       { require_inventory; jq -r 'to_entries[]|.value.public_ip' "$INV_JSON"; }
inv_peer_urls()     { require_inventory; jq -r --arg p "$FEDERATION_PORT" 'to_entries[]|select(.value.role=="peer")|"https://\(.value.public_ip):\($p)"' "$INV_JSON"; }

# Regional-PG accessors. ONE pg node per region; a region's peers dial THAT
# region's pg on its private VPC IP. <region> selects the pg whose region
# matches (head -1 is defensive — terraform validation pins exactly one pg per
# region, so the match is unique).
inv_pg_public_ip_for_region()  { require_inventory; jq -r --arg r "$1" 'to_entries[]|select(.value.role=="pg" and .value.region==$r)|.value.public_ip'  "$INV_JSON" | head -1; }
inv_pg_private_ip_for_region() { require_inventory; jq -r --arg r "$1" 'to_entries[]|select(.value.role=="pg" and .value.region==$r)|.value.private_ip' "$INV_JSON" | head -1; }
inv_pg_name_for_region()       { require_inventory; jq -r --arg r "$1" 'to_entries[]|select(.value.role=="pg" and .value.region==$r)|.key'              "$INV_JSON" | head -1; }

# Region of a peer (or any node) hostname, from inventory.
inv_peer_region() { require_inventory; jq -r --arg h "$1" 'to_entries[]|select(.key==$h)|.value.region' "$INV_JSON" | head -1; }

# Distinct regions present in the fleet, sorted (matches main.tf's sort()).
inv_regions() { require_inventory; jq -r 'to_entries[]|.value.region' "$INV_JSON" | sort -u; }

# Sorted peer hostnames across the WHOLE fleet, one per line. Used for the
# cross-region quorum count (inv_peer_count) — NOT for schema assignment, which
# is per-region (inv_peer_names_sorted_in_region).
inv_peer_names_sorted() { require_inventory; jq -r 'to_entries[]|select(.value.role=="peer")|.key' "$INV_JSON" | sort; }

# Sorted peer hostnames WITHIN one region, one per line. The Kth line (1-based)
# maps to schema ic_peer_<K> on THAT region's pg node — so each regional pg
# independently hosts ic_peer_1..K for its own peers.
inv_peer_names_sorted_in_region() { require_inventory; jq -r --arg r "$1" 'to_entries[]|select(.value.role=="peer" and .value.region==$r)|.key' "$INV_JSON" | sort; }

# Count of peer nodes across all regions (the cross-region quorum denominator).
inv_peer_count() { inv_peer_names_sorted | grep -c . ; }

# Within-region schema index (1-based) for a peer hostname, by its position in
# its OWN region's sorted peer set. This is the index passed to peer_schema().
peer_schema_index_in_region() {
  local target="$1" region i=1 name
  region="$(inv_peer_region "$target")"
  [ -n "$region" ] || return 1
  while IFS= read -r name; do
    [ "$name" = "$target" ] && { printf '%s' "$i"; return 0; }
    i=$((i + 1))
  done <<EOF
$(inv_peer_names_sorted_in_region "$region")
EOF
  return 1
}

# quorum_writes -> the configured SYNCHRONOUS write quorum W. Echoes
# $QUORUM_WRITES if the operator pinned one (benchmark/chaos arm); otherwise
# returns the small synchronous quorum $FED_SYNC_QUORUM_W (default 2 =
# local-commit + 1 cross-region remote ack), CLAMPED to the node count N = 1
# (local) + peer_count so a tiny inventory can always satisfy it (a 1-peer
# fleet → W=1 = commit-local-then-async-converge). The federation is eventual:
# full 3-region propagation is asserted by the harness convergence poll over the
# async catch-up window, NOT by this synchronous W. See the FED_SYNC_QUORUM_W
# rationale block above (#1535). NO bare literal at any call site — always
# interpolate $(quorum_writes).
quorum_writes() {
  if [ -n "$QUORUM_WRITES" ]; then printf '%s' "$QUORUM_WRITES"; return 0; fi
  local peers n w; peers="$(inv_peer_count)"
  [ "$peers" -ge 1 ] || die "quorum_writes: no peers in inventory"
  n=$(( peers + 1 ))                       # local node + remote peers
  w="$FED_SYNC_QUORUM_W"
  [ "$w" -ge 1 ] || w=1
  [ "$w" -le "$n" ] || w="$n"              # clamp: never exceed the node count
  printf '%s' "$w"
}

# Postgres store URL for a peer schema against its REGIONAL pg node (private IP).
# search_path pins the per-peer schema first, then ag_catalog (AGE) + public
# (pgvector). Password is read from the gitignored secret file at call time and
# never echoed / never placed on a command line. sslmode=verify-full +
# sslrootcert keep the daemon->PG leg encrypted and authenticated. The caller
# passes the region's pg private IP (inv_pg_private_ip_for_region).
#   store_url_for_schema <schema> <pg_host> [pg_password]
store_url_for_schema() {
  local schema="$1" host="$2" pw="${3:-}"
  [ -n "$pw" ] || die "store_url_for_schema: pg password required (never echo it)"
  printf 'postgres://%s:%s@%s:%s/%s?options=-csearch_path%%3D%s%%2Cag_catalog%%2Cpublic&sslmode=%s&sslrootcert=%s' \
    "$PG_USER" "$pw" "$host" "$PG_PORT" "$PG_DB" "$schema" "$PG_SSL_MODE" "$PG_SSL_ROOT_CERT"
}

# ---------------------------------------------------------------------------
# Agent attestation (#626 Layer-3) — the fleet runs Batman MAXIMUM-SECURE with
# AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1, so an UNSIGNED POST /api/v1/memories is
# refused 403 ATTESTATION_FAILED. A POSITIVE functional write must present a
# detached Ed25519 `signature` (standard base64) + the `created_at` (RFC3339) it
# signed; the daemon re-derives the SignableWrite envelope and verifies it
# against the agent's bound public key. The signing is delegated to the repo's
# OWN crypto via the `attest_sign` example (built once from REPO_ROOT) so the
# canonical RFC-8949 CBOR encoding is byte-identical to the verifier — NO Ed25519
# / canonical-encoding is reimplemented in bash. The harness agent identity +
# its key files live under the gitignored run dir; the private seed is NEVER
# echoed and NEVER committed. Named constants only — no literal at a call site.
# In-droplet TLS material dir (server + allowlisted client cert + campaign CA).
# Set locally by the test/validate harnesses too; defaulted here so the
# attestation helpers below are usable standalone. ${VAR:=} keeps an existing
# caller value.
REMOTE_TLS="${REMOTE_TLS:-/etc/ai-memory/tls}"
# In-droplet path to the daemon's 0400 EnvironmentFile (store URL, agent id,
# Batman env battery). SSOT here so every provision/test script uses the SAME
# named constant — no duplicated literal path, no unbound-variable footguns.
REMOTE_ENVFILE="${REMOTE_ENVFILE:-/etc/ai-memory/ai-memory.env}"
# #1536 — the daemon's LOCAL sqlite path (governance_rules + every other
# local-sqlite surface on a postgres-backed peer). The systemd unit has no
# WorkingDirectory, so the compiled relative default `ai-memory.db` has
# always resolved to `/ai-memory.db`; this const makes that lived path
# EXPLICIT and shared between the serve unit (50_federation.sh `--db`)
# and the Form-7 activation verbs (46_batman.sh) — pre-#1536 the ssh'd
# CLI verbs resolved `/root/ai-memory.db` instead (cwd split-brain) so
# the rules they wrote were never the ones the daemon consulted.
REMOTE_GOV_DB="${REMOTE_GOV_DB:-/ai-memory.db}"
# The harness write identity. Kept == the test/validate harness's AID_H
# (`ai:test-harness@<campaign>`) so the SAME enrolled+bound agent both
# authenticates (X-Agent-Id) AND owns the attested signature — one identity to
# enroll, no drift between the auth principal and the signing key.
HARNESS_AGENT_ID="${HARNESS_AGENT_ID:-ai:test-harness@$CAMPAIGN}"
HARNESS_AGENT_TYPE="${HARNESS_AGENT_TYPE:-ai:harness}"

# nsa_gaps signed-events-chain probe (test/run.sh check 5). The golden
# `verify-signed-events-chain` CLI verb is SQLITE-ONLY (it takes `--db`, rejects
# `--store-url`), so it cannot verify a POSTGRES-backed daemon's chain — filed as
# GH #1541 (same class as #1536/#1539). The harness instead (a) drives one L4
# `POST /api/v1/capture_turn` write per peer — the identity-bearing write that
# DOES populate the postgres signed_events chain in-tx via
# `pg_append_signed_event_with_chain_in_tx` (the regular `POST /memories` write
# path does NOT emit signed_events on postgres; also surfaced in #1541) — then
# (b) verifies the chain DIRECTLY via SQL on the peer's regional pg node. These
# name the L4 capture-turn probe payload so NO bare literal lives at the call
# site. SECS_PER_* discipline: SE_CHAIN_RECALL_* are poll knobs, small ints.
SE_CHAIN_PROBE_ROLE="${SE_CHAIN_PROBE_ROLE:-assistant}"
SE_CHAIN_PROBE_HOST_KIND="${SE_CHAIN_PROBE_HOST_KIND:-p3-nsa-probe}"

# nsa_gaps provenance-envelope probe (test/run.sh check 6). A verbose recall with
# `verbose_provenance=true` surfaces the provenance envelope (memory_kind /
# citations / confidence_tier) for any matching row. The prior check recalled the
# EMPTY `_test` namespace → count:0 → no envelope. The harness now writes ONE
# attested provenance-bearing memory (kind=claim) to a KNOWN namespace, polls
# until it is recallable (embedder backfill window), then verbose-recalls THAT
# namespace + a unique term and asserts the envelope is present. Named here so no
# literal kind/namespace lives at the call site.
PROV_PROBE_KIND="${PROV_PROBE_KIND:-claim}"
PROV_PROBE_NS="${PROV_PROBE_NS:-$DEFAULT_NAMESPACE}"
# Recallable-poll knobs (small ints — not durations): attempts × interval seconds
# bound the wait for the just-written memory to clear the async embedder backfill.
PROV_RECALL_POLL_TRIES="${PROV_RECALL_POLL_TRIES:-20}"
PROV_RECALL_POLL_SLEEP_SECS="${PROV_RECALL_POLL_SLEEP_SECS:-2}"
HARNESS_KEY_DIR="${HARNESS_KEY_DIR:-$RUN_DIR/harness-keys}"
HARNESS_PRIV="$HARNESS_KEY_DIR/$HARNESS_AGENT_ID.priv"
HARNESS_PUB="$HARNESS_KEY_DIR/$HARNESS_AGENT_ID.pub"
# Build artifacts: the repo-linked golden binary (identity keygen) + the
# attest_sign example (the signer). REPO_ROOT is two levels up from DO_ROOT.
ATTEST_REPO_ROOT="${ATTEST_REPO_ROOT:-$(cd "$DO_ROOT/../.." && pwd)}"
GOLDEN_BIN="${GOLDEN_BIN:-$ATTEST_REPO_ROOT/.local-runs/fleet/ai-memory-golden}"
ATTEST_FEATURES="${ATTEST_FEATURES:-sal,sal-postgres,sqlite-bundled}"
# Cargo writes the example to target/<profile>/examples/attest_sign; resolved by
# attest_signer_bin() which builds it on first use (cache hit thereafter).
ATTEST_SIGNER_BIN="${ATTEST_SIGNER_BIN:-}"

# ---------------------------------------------------------------------------
# Atlas Corpus ingest constants (#1535). The atlas harness (deploy/do-1461/atlas)
# loads a 7855-distinct copyright-clean knowledge corpus into the max-secure hive
# via ATTESTED writes. A DEDICATED loader identity (NOT the test harness) owns the
# corpus writes so the corpus author is auditable + isolated from the throwaway
# _test/_verify markers. All atlas literals live here so NO bare literal sits at
# an atlas call site (corpus path + sha come from the committed CORPUS_MANIFEST).
ATLAS_DIR="${ATLAS_DIR:-$DO_ROOT/atlas}"
ATLAS_MANIFEST="${ATLAS_MANIFEST:-$ATLAS_DIR/CORPUS_MANIFEST.json}"
ATLAS_NAMESPACE="${ATLAS_NAMESPACE:-atlas-corpus}"
ATLAS_AGENT_ID="${ATLAS_AGENT_ID:-ai:atlas-loader@$CAMPAIGN}"
# Region whose first sorted peer is the Atlas write-anchor (the hive federates
# the rest). Named here so no region slug is hardcoded at the atlas call site;
# override to re-anchor ingest in a different region.
ATLAS_ANCHOR_REGION="${ATLAS_ANCHOR_REGION:-nyc3}"
# A DEDICATED federation-convergence probe identity, distinct from the loader.
# The loader writes all 7855 corpus rows and so EXHAUSTS its per-agent daily
# federation quota (AI_MEMORY_MAX_MEMORIES_PER_DAY, default 1000) — past which
# the receive path 429s every push (charged against the author's quota) and the
# rows dead-letter instead of converging. The federation assertion therefore
# probes convergence with THIS fresh-quota identity (one atlas memory) so it
# tests the federation CAPABILITY for atlas content, isolated from the loader's
# bulk-ingest quota exhaustion. The corpus-scale-vs-quota gap is reported as a
# distinct, honest finding (raise the peer quota or shard across identities to
# fully federate a corpus larger than the per-agent cap).
ATLAS_FED_PROBE_AGENT_ID="${ATLAS_FED_PROBE_AGENT_ID:-ai:atlas-fedprobe@$CAMPAIGN}"
# Corpus row count + distinct (title,namespace) the ingest must converge to. Read
# from the manifest at runtime by the atlas harness; defaulted here so the
# constant exists even if the manifest is unreadable (the harness re-reads + pins).
ATLAS_DISTINCT_EXPECTED="${ATLAS_DISTINCT_EXPECTED:-7855}"
# The substrate POST /api/v1/memories validator rejects the corpus
# source:"atlas-knowledge-card" (not in VALID_SOURCES) and a bare https source_uri
# (validate_source_uri requires uri:/doc:/file:). The batch signer remaps both —
# source -> a VALID_SOURCES value, source_uri -> uri:<url> — preserving the
# original corpus source under metadata. NEITHER field is in the signed
# SignableWrite envelope, so the remap never weakens attestation. on_conflict=merge
# makes the ingest idempotent (re-runnable without 409s on already-present rows).
ATLAS_SOURCE="${ATLAS_SOURCE:-import}"
ATLAS_ON_CONFLICT="${ATLAS_ON_CONFLICT:-merge}"
# Ingest tuning. Throughput on the 4-vCPU peers is pg-write/embedder-bound at
# ~3 rec/s regardless of client parallelism, so the attestation freshness window
# (±300s on created_at) is held by RE-SIGNING each chunk with a fresh created_at
# right before that chunk is POSTed — a chunk of $ATLAS_CHUNK records at
# $ATLAS_POST_PARALLEL-way parallelism completes well inside 300s. Small ints
# (counts, not durations) — SECS_PER_* discipline N/A.
ATLAS_CHUNK="${ATLAS_CHUNK:-500}"
ATLAS_POST_PARALLEL="${ATLAS_POST_PARALLEL:-8}"
ATLAS_POST_MAX_TIME="${ATLAS_POST_MAX_TIME:-30}"
# Representative recall probes present in the corpus (market / finance / psychology
# domains). The atlas recall assertion GETs /api/v1/recall for each and asserts
# >=1 atlas-corpus hit. Space-separated, letters-only terms so postgres FTS
# to_tsquery tokenizes them deterministically.
ATLAS_RECALL_TERMS="${ATLAS_RECALL_TERMS:-stocks inflation psychology}"
# Recallable-poll knobs (small ints): bound the wait for async embedder backfill.
ATLAS_RECALL_POLL_TRIES="${ATLAS_RECALL_POLL_TRIES:-30}"
ATLAS_RECALL_POLL_SLEEP_SECS="${ATLAS_RECALL_POLL_SLEEP_SECS:-2}"
# Federation convergence-poll knobs (small ints).
ATLAS_CONVERGE_POLL_TRIES="${ATLAS_CONVERGE_POLL_TRIES:-30}"
ATLAS_CONVERGE_POLL_SLEEP_SECS="${ATLAS_CONVERGE_POLL_SLEEP_SECS:-2}"
# The batch signer example (Option A): reads the corpus JSONL + the loader key in
# ONE process and emits ready-to-POST attested bodies (signature + created_at
# injected). Built once via atlas_signer_batch_bin().
ATLAS_BATCH_SIGNER_BIN="${ATLAS_BATCH_SIGNER_BIN:-}"

# atlas_signer_batch_bin -> path to the built `attest_sign_batch` example,
# building it once (cache hit thereafter). Build chatter to stderr.
atlas_signer_batch_bin() {
  if [ -n "$ATLAS_BATCH_SIGNER_BIN" ] && [ -x "$ATLAS_BATCH_SIGNER_BIN" ]; then
    printf '%s' "$ATLAS_BATCH_SIGNER_BIN"; return 0
  fi
  command -v cargo >/dev/null 2>&1 || die "cargo not found — attest_sign_batch (examples/attest_sign_batch.rs) is built from $ATTEST_REPO_ROOT"
  cargo build --quiet --manifest-path "$ATTEST_REPO_ROOT/Cargo.toml" \
    --example attest_sign_batch --features "$ATTEST_FEATURES" >&2 \
    || die "failed to build the attest_sign_batch signer example"
  local bin="$ATTEST_REPO_ROOT/target/debug/examples/attest_sign_batch"
  [ -x "$bin" ] || die "attest_sign_batch built but not found at $bin"
  ATLAS_BATCH_SIGNER_BIN="$bin"
  printf '%s' "$bin"
}

# attest_signer_bin -> path to the built `attest_sign` example, building it once.
# Echoes the binary path on stdout; build chatter goes to stderr.
attest_signer_bin() {
  if [ -n "$ATTEST_SIGNER_BIN" ] && [ -x "$ATTEST_SIGNER_BIN" ]; then
    printf '%s' "$ATTEST_SIGNER_BIN"; return 0
  fi
  command -v cargo >/dev/null 2>&1 || die "cargo not found — attest_sign (examples/attest_sign.rs) is built from $ATTEST_REPO_ROOT"
  cargo build --quiet --manifest-path "$ATTEST_REPO_ROOT/Cargo.toml" \
    --example attest_sign --features "$ATTEST_FEATURES" >&2 \
    || die "failed to build the attest_sign signer example"
  local bin="$ATTEST_REPO_ROOT/target/debug/examples/attest_sign"
  [ -x "$bin" ] || die "attest_sign built but not found at $bin"
  ATTEST_SIGNER_BIN="$bin"
  printf '%s' "$bin"
}

# harness_keypair_ensure -> generate the harness Ed25519 keypair under
# HARNESS_KEY_DIR (idempotent: reused if present). Uses the golden binary's
# `identity generate` so the on-disk `.priv`/`.pub` shape is the substrate's
# own (raw 32-byte seed). Echoes the URL-safe-no-pad public key on stdout.
harness_keypair_ensure() {
  mkdir -p "$HARNESS_KEY_DIR"; chmod 700 "$HARNESS_KEY_DIR"
  if [ ! -s "$HARNESS_PRIV" ] || [ ! -s "$HARNESS_PUB" ]; then
    [ -x "$GOLDEN_BIN" ] || die "golden binary missing ($GOLDEN_BIN) — needed for harness identity keygen"
    "$GOLDEN_BIN" identity generate --agent-id "$HARNESS_AGENT_ID" \
      --key-dir "$HARNESS_KEY_DIR" --json >/dev/null 2>&1 \
      || die "harness identity keygen failed for $HARNESS_AGENT_ID"
  fi
  [ -s "$HARNESS_PUB" ] || die "harness public key missing ($HARNESS_PUB)"
  # The .pub is the raw 32-byte verifying key; mint its URL-safe-no-pad b64 via
  # the substrate so the encoding matches keypair::public_base64 exactly.
  "$GOLDEN_BIN" identity export-pub --agent-id "$HARNESS_AGENT_ID" \
    --key-dir "$HARNESS_KEY_DIR" --json 2>/dev/null \
    | sed -n 's/.*"public_key_b64"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

# harness_pubkey_b64 -> the harness agent's URL-safe-no-pad public key (cached).
harness_pubkey_b64() {
  [ -n "${HARNESS_PUBKEY_B64:-}" ] && { printf '%s' "$HARNESS_PUBKEY_B64"; return 0; }
  HARNESS_PUBKEY_B64="$(harness_keypair_ensure)"
  [ -n "$HARNESS_PUBKEY_B64" ] || die "could not derive harness public key b64"
  printf '%s' "$HARNESS_PUBKEY_B64"
}

# agent_pubkey_b64 <agent_id> -> that agent's URL-safe-no-pad public key,
# generating the keypair on first use. Used to enroll non-harness attesting
# identities (e.g. $AID_ALPHA) on a peer.
agent_pubkey_b64() {
  local aid="$1"
  agent_priv_path "$aid" >/dev/null
  "$GOLDEN_BIN" identity export-pub --agent-id "$aid" --key-dir "$HARNESS_KEY_DIR" --json 2>/dev/null \
    | sed -n 's/.*"public_key_b64"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

# agent_priv_path <agent_id> -> path to that agent's .priv under HARNESS_KEY_DIR,
# generating the keypair on first use (idempotent). All attesting identities
# (the harness + any a2a/ai_nhi agent ids) share one gitignored key dir.
agent_priv_path() {
  # Split the declaration: referencing $aid in the same `local` line that
  # declares it trips `set -u` (the name is not yet bound when `priv=` is
  # evaluated) on bash where this function is the first to bind `aid` in a fresh
  # scope. Declaring `aid` first, then `priv`, is the bash-3.2-safe form.
  local aid="$1"
  local priv="$HARNESS_KEY_DIR/$aid.priv"
  if [ ! -s "$priv" ]; then
    mkdir -p "$HARNESS_KEY_DIR"; chmod 700 "$HARNESS_KEY_DIR"
    [ -x "$GOLDEN_BIN" ] || die "golden binary missing ($GOLDEN_BIN) — needed for $aid keygen"
    "$GOLDEN_BIN" identity generate --agent-id "$aid" --key-dir "$HARNESS_KEY_DIR" --json >/dev/null 2>&1 \
      || die "identity keygen failed for $aid"
  fi
  [ -s "$priv" ] || die "private key missing for $aid ($priv)"
  printf '%s' "$priv"
}

# attested_sign <namespace> <title> <kind> <created_at> <content> [agent_id]
# -> stdout: the standard-base64 Ed25519 signature over the SignableWrite
# envelope. Content is piped via stdin so a payload with shell metacharacters
# never lands on a command line; the private seed is NEVER echoed. agent_id
# defaults to $HARNESS_AGENT_ID; pass an explicit id (e.g. $AID_ALPHA) to sign as
# a different attesting identity (it must be enrolled+bound on the write peer).
attested_sign() {
  local ns="$1" title="$2" kind="$3" created="$4" content="$5" aid="${6:-$HARNESS_AGENT_ID}"
  local signer priv; signer="$(attest_signer_bin)"; priv="$(agent_priv_path "$aid")"
  printf '%s' "$content" | "$signer" \
    --agent-id "$aid" --namespace "$ns" --title "$title" \
    --kind "$kind" --created-at "$created" --content-file - --priv-file "$priv"
}

# attested_body <namespace> <title> <kind> <scope> <content> [agent_id] ->
# stdout: a JSON request body for POST /api/v1/memories carrying `signature` +
# `created_at` so the write attests under the maximum-secure gate. The caller
# passes the returned body to body_req/mtls_curl with X-Agent-Id = the SAME
# agent_id (default $HARNESS_AGENT_ID). created_at is stamped NOW (well inside the
# +/-300s freshness window) and signed verbatim. Title/content/namespace/kind
# MUST match what is signed — built together here so they cannot drift.
# JSON-escapes the title + content (the only caller-variable free text).
_json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
attested_body() {
  local ns="$1" title="$2" kind="$3" scope="$4" content="$5" aid="${6:-$HARNESS_AGENT_ID}"
  local created sig
  created="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
  sig="$(attested_sign "$ns" "$title" "$kind" "$created" "$content" "$aid")"
  [ -n "$sig" ] || die "attested_body: empty signature for title=$title (agent=$aid)"
  printf '{"title":"%s","content":"%s","namespace":"%s","kind":"%s","scope":"%s","signature":"%s","created_at":"%s"}' \
    "$(_json_escape "$title")" "$(_json_escape "$content")" "$ns" "$kind" "$scope" "$sig" "$created"
}

# agent_enroll_peer <peer_public_ip> <agent_id> -> register an attesting agent on
# a peer (HTTP, lands in the peer's postgres _agents row) and bind its public key
# so that agent's attested writes verify there. Registration is the daemon HTTP
# surface; the pubkey bind mirrors PostgresStore::bind_agent_pubkey (augment the
# _agents-row metadata with agent_pubkey + pubkey_bound_at) executed via psql ON
# the region's pg node against the peer's search_path schema. Idempotent.
#
# The bind is required because the attestation gate resolves the bound key from
# the RECEIVING peer's OWN postgres store (PostgresStore::agent_pubkey reads
# metadata->>'agent_pubkey' WHERE namespace='_agents' AND title='agent:<id>').
agent_enroll_peer() {
  local peer_ip="$1" aid="$2"
  local host region schema pg_pub pub_b64 api_key
  host="$(inv_name_for_ip "$peer_ip")"
  region="$(inv_peer_region "$host")"
  schema="$(peer_schema "$(peer_schema_index_in_region "$host")")"
  pg_pub="$(inv_pg_public_ip_for_region "$region")"
  pub_b64="$(agent_pubkey_b64 "$aid")"
  [ -n "$pub_b64" ] || die "agent_enroll_peer: could not derive pubkey for $aid"
  api_key=""; [ -s "$RUN_DIR/secrets/api.pw" ] && api_key="$(cat "$RUN_DIR/secrets/api.pw")"

  # 1) register over mTLS (idempotent — re-register just rewrites the _agents row).
  local keyhdr=""; [ -n "$api_key" ] && keyhdr="-H 'x-api-key: $api_key'"
  ssh_node "$peer_ip" "curl -fsS --max-time 12 --resolve $host:$FEDERATION_PORT:127.0.0.1 \
    --cacert $REMOTE_TLS/ca.pem --cert $REMOTE_TLS/client.pem --key $REMOTE_TLS/client.key \
    $keyhdr -H 'content-type: application/json' \
    --data '{\"agent_id\":\"$aid\",\"agent_type\":\"$HARNESS_AGENT_TYPE\",\"capabilities\":[\"attested-write\"]}' \
    -X POST https://$host:$FEDERATION_PORT/api/v1/agents" >/dev/null 2>&1 \
    || log "[$host] register $aid returned non-2xx (may already be registered) — continuing to bind"

  # 2) bind the pubkey into the peer's _agents row (psql on the regional pg node).
  # #1613 — RETURNING 1 proves the UPDATE matched a row: psql exits 0 on
  # `UPDATE 0`, so without it a missing _agents row (e.g. the register
  # step above was refused and its non-2xx swallowed) logged
  # "enrolled + pubkey bound" while the attestation gate had no key and
  # every attested write 403'd with misleading provision evidence.
  [ -n "$pg_pub" ] || die "agent_enroll_peer: no pg node for region $region"
  local bind_rows
  bind_rows="$(ssh_node "$pg_pub" "sudo -u postgres psql -d $PG_DB -tA -v ON_ERROR_STOP=1 <<SQL
SET search_path = $schema, ag_catalog, public;
UPDATE memories
   SET metadata = jsonb_set(jsonb_set(metadata, '{agent_pubkey}', to_jsonb('$pub_b64'::text), true), '{pubkey_bound_at}', to_jsonb(now()::text), true),
       content  = (jsonb_set(jsonb_set(metadata, '{agent_pubkey}', to_jsonb('$pub_b64'::text), true), '{pubkey_bound_at}', to_jsonb(now()::text), true))::text,
       updated_at = now()
 WHERE namespace='_agents' AND title='agent:$aid'
 RETURNING 1;
SQL" 2>/dev/null)" || die "[$host] pubkey bind failed for $aid (schema=$schema on $region pg)"
  printf '%s' "$bind_rows" | grep -q 1 \
    || die "[$host] pubkey bind matched 0 rows for $aid (no _agents row in schema=$schema — register step failed?)"
  log "[$host] agent $aid enrolled + pubkey bound (schema=$schema, region=$region)"
}

# harness_enroll_peer <peer_public_ip> -> enroll the default harness identity.
harness_enroll_peer() { agent_enroll_peer "$1" "$HARNESS_AGENT_ID"; }

# ---------------------------------------------------------------------------
# Zero-touch CA trust-chain verification. The zero-touch arm (45_zero_touch.sh)
# mints per-peer credentials signed by the campaign CA and publishes ONLY the CA
# verifying key into the trust bundle. A receiver trusts a peer iff its
# credential chains to that CA. The `fed_issue verify-cred` subcommand runs the
# SAME TrustBundle::verify the receive path runs, so the harness can assert the
# trust chain directly. Material lives in the gitignored zero-touch run dir.
ZT_TRUST_DIR="${ZT_TRUST_DIR:-$RUN_DIR/zero-touch/trust}"
ZT_CRED_DIR="${ZT_CRED_DIR:-$RUN_DIR/zero-touch/cred}"

# fed_issue_bin -> path to the built `fed_issue` example, building it once.
fed_issue_bin() {
  if [ -n "${FED_ISSUE_BIN:-}" ] && [ -x "$FED_ISSUE_BIN" ]; then
    printf '%s' "$FED_ISSUE_BIN"; return 0
  fi
  command -v cargo >/dev/null 2>&1 || die "cargo not found — fed_issue (examples/fed_issue.rs) is built from $ATTEST_REPO_ROOT"
  cargo build --quiet --manifest-path "$ATTEST_REPO_ROOT/Cargo.toml" \
    --example fed_issue --features "$ATTEST_FEATURES" >&2 \
    || die "failed to build the fed_issue example"
  local bin="$ATTEST_REPO_ROOT/target/debug/examples/fed_issue"
  [ -x "$bin" ] || die "fed_issue built but not found at $bin"
  FED_ISSUE_BIN="$bin"
  printf '%s' "$bin"
}

# verify_cred_chain <host> -> exit 0 iff <host>'s minted credential verifies
# against the campaign CA bundle scoped to FED_TRUST_DOMAIN (the zero-touch trust
# chain). Echoes the verified subject_agent_id on stdout on success. Non-zero on
# any chain failure (unknown issuer / wrong domain / bad signature / expired).
verify_cred_chain() {
  local host="$1"
  local cred="$ZT_CRED_DIR/$host.cred"
  local fi
  [ -s "$cred" ] || { log "verify_cred_chain: no credential file for $host ($cred)"; return 1; }
  fi="$(fed_issue_bin)"
  "$fi" verify-cred --cred-file "$cred" --bundle-dir "$ZT_TRUST_DIR" \
    --trust-domain "$FED_TRUST_DOMAIN" 2>/dev/null \
    | sed -n 's/.*subject=\([^ ]*\) .*/\1/p' | head -1
}
