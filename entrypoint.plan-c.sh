#!/usr/bin/env bash
# Plan C — ai-memory daemon entrypoint.
# Generates daemon keypair on first start, writes config, then exec's serve.
set -euo pipefail

# Required env (validated):
: "${AI_MEMORY_AGENT_ID:?missing}"
: "${AI_MEMORY_STORE_URL:?missing}"
: "${AI_MEMORY_LISTEN_HOST:?missing}"
: "${AI_MEMORY_LISTEN_PORT:?missing}"
: "${OLLAMA_BASE_URL:?missing}"

# Optional env
TIER="${AI_MEMORY_TIER:-autonomous}"
LLM_MODEL="${AI_MEMORY_LLM_MODEL:-gemma4:e4b}"
# v0.7.0 L15 — auto_tag goes through a fast, non-thinking model to keep
# the autonomy hook bounded by the H8 30s per-LLM-call timeout. Gemma 4
# e4b in thinking mode generates 396-564 tokens for a 5-tag prompt
# (Plan C R4 cert observed `H8: LLM call (auto_tag) exceeded 30s`).
# Gemma 3 4b runs the same prompt in ~0.7s. Override via env if the
# operator has a different fast model loaded.
AUTO_TAG_MODEL="${AI_MEMORY_AUTO_TAG_MODEL:-gemma3:4b}"
EMBED_MODEL="${AI_MEMORY_EMBED_MODEL:-nomic-embed-text}"
PEER_URLS="${AI_MEMORY_PEER_URLS:-}"
TLS_DIR="${AI_MEMORY_TLS_DIR:-/etc/ai-memory-a2a/tls}"

mkdir -p /etc/ai-memory /root/.config/ai-memory

# Daemon self-signing keypair (refuse-by-default per Round-4 fix).
#
# The daemon runtime loads this key by the LITERAL label
# DAEMON_KEYPAIR_LABEL = "daemon" (src/daemon_runtime.rs, src/mcp/mod.rs),
# so the on-disk basename is fixed; expose it as a var to single-source
# the guard, the generate flag, and the path check below.
#
# KEY DIR RESOLUTION BUG FIX: `ai-memory identity generate` resolves its
# storage dir from AI_MEMORY_KEY_DIR (keypair::default_key_dir,
# src/identity/keypair.rs:137) — the bind-mounted /etc/ai-memory/keys in
# this deployment — NOT /root/.config/ai-memory/keys. The previous guard
# checked the latter, so it never matched the real key, keygen re-ran on
# every boot, and a re-run with the persisted key present tripped the
# refuse-by-default and crash-looped the container. Guard and generate
# now share one resolved $KEY_DIR so the key is minted once and reused
# across restarts (stable daemon identity).
DAEMON_KEY_LABEL="${AI_MEMORY_DAEMON_KEY_LABEL:-daemon}"
KEY_DIR="${AI_MEMORY_KEY_DIR:-/etc/ai-memory/keys}"
mkdir -p "$KEY_DIR"
if [ ! -f "$KEY_DIR/$DAEMON_KEY_LABEL.priv" ]; then
  /usr/local/bin/ai-memory identity generate \
    --key-dir "$KEY_DIR" --agent-id "$DAEMON_KEY_LABEL" --json
fi

# #1803 — federation push-signing key auto-provisioning.
#
# `ai-memory serve`'s `FederationConfig::build()` loads the OUTBOUND
# `/sync/push` signing key via
# `governance::audit::load_daemon_signing_key(&sender_agent_id)`
# (src/federation/peer.rs), keyed by the RESOLVED federation identity
# (`federation::identity::resolver::resolve_federation_identity`:
# AI_MEMORY_FED_IDENTITY env > configured identity > `host:<hostname>`)
# — a DIFFERENT on-disk file from the fixed `DAEMON_KEYPAIR_LABEL =
# "daemon"` keypair generated just above (that one backs link/audit
# signing only, per the block comment there). The RECEIVING side's
# `identity::verify::lookup_peer_public_key_in` looks up the SAME
# `<sender_agent_id>.pub` name in ITS OWN key directory, so the two
# ends must agree on that exact filename for signature verification
# (and the `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT` "peer_not_enrolled"
# gate, which consults the identical lookup) to pass.
#
# Unlike the "daemon" key, `ai-memory serve` has NO auto-generate-on-
# boot fallback for this one — absent, federation pushes go out
# silently UNSIGNED and any peer enforcing `AI_MEMORY_FED_REQUIRE_SIG`
# / `AI_MEMORY_FED_REQUIRE_WRITE_SIG` (both v0.7.0+/v1.0.0 secure
# defaults) rejects them with a 401. This was the root cause behind
# "manual .pub enrollment doesn't unblock the live mesh" in #1803: a
# peer's `.pub` copied under the resolved identity name has nothing to
# verify against unless THIS side also minted a real keypair under
# that same name. Pre-provisioning it here means a bare `docker
# compose up` (paired with the peer-key cross-copy step in
# infra/lan-parity-test/provision-peer-keys.sh) yields a daemon that
# can sign, and be verified, out of the box.
#
# Computed with the SAME precedence `resolve_federation_identity` uses
# for this deployment shape (env > host — no `[federation]` config
# section is ever written above, so the "configured" layer never
# applies here). Deliberately NOT reusing $KEY_DIR: that var defaults
# to /etc/ai-memory/keys for back-compat with Plan C's historical bind
# mount, but `ai-memory serve` resolves its OWN key directory via
# `identity::keypair::default_key_dir()` (AI_MEMORY_KEY_DIR env, else
# the platform config dir — `$HOME/.config/ai-memory/keys` on Linux),
# so this key MUST land wherever THAT resolves or `serve` will never
# find it.
#
# Hostname fallback deliberately reads /proc/sys/kernel/hostname (always
# present on Linux, no extra package needed) rather than shelling out to
# the external `hostname` binary, which this image's runtime stage does
# NOT install — falls through to `hostname` (in case some other base
# image lacks /proc) and finally to the literal `unknown-host`, mirroring
# `resolve_federation_identity`'s own `UNKNOWN_HOSTNAME_FALLBACK`
# (src/federation/identity/resolver.rs) so the degenerate case matches
# the Rust side byte-for-byte. This branch is a no-op for lan-parity
# (which always sets AI_MEMORY_FED_IDENTITY explicitly below) and only
# matters for other deployments (e.g. Plan C) using this entrypoint
# without an explicit override.
FED_KEY_DIR="${AI_MEMORY_KEY_DIR:-$HOME/.config/ai-memory/keys}"
FED_IDENTITY="${AI_MEMORY_FED_IDENTITY:-host:$(cat /proc/sys/kernel/hostname 2>/dev/null || hostname 2>/dev/null || echo unknown-host)}"
mkdir -p "$FED_KEY_DIR"
if [ ! -f "$FED_KEY_DIR/$FED_IDENTITY.priv" ]; then
  /usr/local/bin/ai-memory identity generate \
    --key-dir "$FED_KEY_DIR" --agent-id "$FED_IDENTITY" --json
fi

# #845: optional api_key when AI_MEMORY_API_KEY is set. NOTE the
# substrate error message says "set [api] api_key" but the actual
# AppConfig schema (src/config.rs:2283) has `api_key` as a TOP-LEVEL
# Option<String> field — NOT inside an [api] section. Serde silently
# ignores unknown top-level subsections like [api], so the daemon
# sees api_key=None and the S5-C1 guard refuses to bind 0.0.0.0.
# Error-message drift filed as a separate sub-defect.
API_KEY_TOML=""
if [ -n "${AI_MEMORY_API_KEY:-}" ]; then
  API_KEY_TOML="api_key = \"${AI_MEMORY_API_KEY}\""
fi

# config.toml — top-level fields per AppConfig (see src/config.rs line 1433).
# Sections [memory], [autonomous], [governance], [federation] are NOT valid
# AppConfig keys — serde silently ignores them, falling through to defaults.
# Federation comes from CLI flags below. Plan C uses autonomous tier:
# Gemma 4 LLM + nomic-embed-text 768-dim embedder via Ollama + cross-encoder.
cat >/root/.config/ai-memory/config.toml <<TOML
tier = "${TIER}"
ollama_url = "${OLLAMA_BASE_URL}"
embed_url = "${OLLAMA_BASE_URL}"
embedding_model = "nomic_embed_v15"
llm_model = "${LLM_MODEL}"
auto_tag_model = "${AUTO_TAG_MODEL}"
cross_encoder = true
${API_KEY_TOML}

[audit]
enabled = true
path = "/var/log/ai-memory/audit"
redact_content = true
hash_chain = true

[permissions]
mode = "enforce"
TOML
mkdir -p /etc/ai-memory
cp /root/.config/ai-memory/config.toml /etc/ai-memory/config.toml

# Server-side TLS flags (HTTPS + mTLS via fingerprint allowlist).
# `serve` accepts only --tls-cert, --tls-key, --mtls-allowlist on the
# server path. CA cert is only used on the outbound quorum-client path
# (--quorum-ca-cert below).
TLS_FLAGS=""
if [ -f "$TLS_DIR/server.pem" ] && [ -f "$TLS_DIR/server.key" ]; then
  TLS_FLAGS="--tls-cert $TLS_DIR/server.pem --tls-key $TLS_DIR/server.key"
  if [ -f "$TLS_DIR/mtls-allowlist.txt" ]; then
    TLS_FLAGS="$TLS_FLAGS --mtls-allowlist $TLS_DIR/mtls-allowlist.txt"
  fi
fi

# Quorum mTLS (when peer set + client cert)
QUORUM_FLAGS=""
if [ -n "$PEER_URLS" ]; then
  QUORUM_FLAGS="--quorum-writes 2 --quorum-peers $PEER_URLS"
  if [ -f "$TLS_DIR/client.pem" ] && [ -f "$TLS_DIR/client.key" ]; then
    QUORUM_FLAGS="$QUORUM_FLAGS --quorum-client-cert $TLS_DIR/client.pem --quorum-client-key $TLS_DIR/client.key"
    [ -f "$TLS_DIR/ca.pem" ] && QUORUM_FLAGS="$QUORUM_FLAGS --quorum-ca-cert $TLS_DIR/ca.pem"
  fi
fi

# Issue #878 — peer-mesh reach preflight.
#
# Plan-C re-test surfaced that `host.docker.internal:<port>` URLs in the
# peer mesh silently shadow when another host process owns those ports
# (SSH forwards, python -m http.server, stale docker proxy after
# `colima delete`, etc.). The published port-bind "succeeds" but quorum
# POSTs land on the unrelated process and 404 / hang forever.
#
# Long-term fix: user-defined bridge + container-DNS in
# `infra/plan-c/docker-compose.yml` (peer URLs become `http://ic-bob:19077`
# routed through the docker network, never touching the host). For
# operators still on the `host.docker.internal` recipe, the preflight
# below probes every declared peer URL before exec'ing `serve` and
# aborts with EX_CONFIG (78) if any peer is unreachable.
#
# Logic lives in `infra/plan-c/peer-preflight.sh` so it can be unit-
# tested via `tests/plan_c_preflight.sh` without bringing the rest of
# the entrypoint side-effects (mkdir /etc, /root/.config) into scope.
# Opt-out: `AI_MEMORY_SKIP_PEER_PREFLIGHT=1` disables the check.
PREFLIGHT="${AI_MEMORY_PEER_PREFLIGHT_SCRIPT:-/usr/local/lib/ai-memory/peer-preflight.sh}"
if [ ! -f "$PREFLIGHT" ]; then
  for candidate in \
    "$(dirname "$0")/infra/plan-c/peer-preflight.sh" \
    "/usr/local/lib/ai-memory/peer-preflight.sh"; do
    if [ -f "$candidate" ]; then
      PREFLIGHT="$candidate"
      break
    fi
  done
fi
if [ -f "$PREFLIGHT" ]; then
  PEER_URLS="$PEER_URLS" \
  AI_MEMORY_SKIP_PEER_PREFLIGHT="${AI_MEMORY_SKIP_PEER_PREFLIGHT:-0}" \
    bash "$PREFLIGHT" || exit $?
else
  echo "[entrypoint] #878 preflight script not found at any candidate path — skipping" >&2
fi

echo "[entrypoint] starting ai-memory:"
echo "  agent_id=$AI_MEMORY_AGENT_ID tier=$TIER listen=$AI_MEMORY_LISTEN_HOST:$AI_MEMORY_LISTEN_PORT"
echo "  store_url=$(echo $AI_MEMORY_STORE_URL | sed -E 's|//[^@]+@|//<redacted>@|')"
echo "  ollama=$OLLAMA_BASE_URL llm=$LLM_MODEL embed=$EMBED_MODEL auto_tag=$AUTO_TAG_MODEL"
echo "  peers=${PEER_URLS:-(none)}"
echo "  tls_flags='$TLS_FLAGS'"
echo "  quorum_flags='$QUORUM_FLAGS'"

unset AI_MEMORY_DB
# #1231 (2026-05-25) — DO NOT override AI_MEMORY_AGENT_ID to the
# reserved sentinel `daemon`. The wire-side validator
# `validate::validate_agent_id` (src/validate.rs:366) was hardened by
# #977 (commit d81df2d7c) to reject every member of
# `RESERVED_AGENT_IDS` (which includes `daemon`) when supplied via env
# var or wire callers. Setting AI_MEMORY_AGENT_ID=daemon here causes
# `identity::resolve_agent_id` (src/identity/mod.rs:153) to bail with
# `agent_id 'daemon' is reserved for internal use and cannot be
# supplied by wire callers`, crashlooping the daemon container.
#
# The daemon's self-signing keypair is loaded by the LITERAL label
# `DAEMON_KEYPAIR_LABEL = "daemon"` via
# `crate::identity::keypair::load("daemon", &dir)`
# (src/daemon_runtime.rs:1937, src/mcp/mod.rs:2038) — that path does
# NOT read AI_MEMORY_AGENT_ID and stays correct regardless of the
# daemon process's resolved agent_id. The operator-supplied
# AI_MEMORY_AGENT_ID (e.g. `ai:ic-parity-alice@lan-parity` set by
# docker-compose) flows through unchanged and is honoured by
# `resolve_agent_id` step 2.
export RUST_LOG="${RUST_LOG:-ai_memory=info}"

exec /usr/local/bin/ai-memory serve \
  --host "$AI_MEMORY_LISTEN_HOST" --port "$AI_MEMORY_LISTEN_PORT" \
  --store-url "$AI_MEMORY_STORE_URL" \
  $TLS_FLAGS \
  $QUORUM_FLAGS
