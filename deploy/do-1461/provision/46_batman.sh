#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Batman-active MAXIMUM-SECURE posture for the whole fleet (Secure Enterprise
# Federated Reference Architecture). Two concerns, both idempotent:
#
#   1. ENV battery (every daemon-bearing node): strip-then-append the Batman env
#      battery (lib.sh BATMAN_ENV_*) to each node's 0400 EnvironmentFile so the
#      v0.7.0 secure-default surfaces are LIVE over the wire — per-message
#      federation signing + nonce anti-replay + peer enrollment, agent
#      attestation on every write, enforce-mode permissions, fail-CLOSED
#      governance, Form-5 auto-confidence / shadow / decay. The strip-then-append
#      mirrors 45_zero_touch.sh exactly so re-runs converge to the same file.
#
#   2. Form-7 governance activation (peers only): via the golden ai-memory binary
#      over SSH — `rules keygen` (operator key), `rules sign-seed`, then enable
#      R001..R004 with `--sign` (the seed rules) against the daemon's LOCAL
#      sqlite at $REMOTE_GOV_DB (#1536 — the rules engine is sqlite-substrate-
#      scoped on every backend; the runtime checks read the daemon's local db,
#      NOT the postgres store), verified in-place via
#      `governance check-action` (a /tmp write must refuse). The Form-2/6
#      namespace Batman policy is then bound through the daemon's HTTP surface
#      (attested store + POST /namespaces/{ns}/standard) so it lands in the
#      peer's LIVE postgres store. The curator daemon is started under systemd
#      on every peer.
#
# DELIBERATELY NOT SET: AI_MEMORY_ENCRYPT_AT_REST (see lib.sh BATMAN_ENV block):
# it is a sqlite/sqlcipher data-at-rest feature and a NO-OP on these postgres-
# backed peers. For postgres peers, data-at-rest is a Postgres/disk concern
# (cluster --data-checksums + host-disk encryption) and data-in-transit is the
# Leg-3 verify-full daemon→PG TLS leg; we do NOT rebuild the golden binary for
# sqlcipher.
#
# Ordering: runs AFTER 45_zero_touch.sh (its env appends must already be in the
# file) and BEFORE 50_federation.sh (the sole pusher of the EnvironmentFile +
# the daemon (re)start that LOADS this env). 46 therefore only mutates the LOCAL
# render-dir env file + drives the (postgres-resident) governance state; 50 then
# ships the file and restarts the daemon so the Batman env takes effect.
source "$(dirname "$0")/lib.sh"

REPO_ROOT="$(cd "$DO_ROOT/../.." && pwd)"
SECRETS_DIR="$RUN_DIR/secrets"
BIN="/usr/local/bin/ai-memory"
# Per-peer operator key + Form-7 governance live on the postgres-backed daemon,
# so the rules verbs run with the peer's own --store-url. The operator key is
# written to this node-local key dir (root-only).
REMOTE_KEY_DIR="/etc/ai-memory/keys"

require_inventory

# --- regex of the env names we manage, for the idempotent strip (bash-3.2) ----
# Build NAME1|NAME2|... from BATMAN_ENV_NAMES so the strip-then-append is a pure
# function of the SSOT list — adding a knob in lib.sh needs no edit here.
batman_strip_regex() {
  local re="" n
  for n in "${BATMAN_ENV_NAMES[@]}"; do
    re="${re:+$re|}$n"
  done
  printf '^(%s)=' "$re"
}

# --- append the Batman env battery to a node's local env file (idempotent) -----
append_batman_env() {
  local host="$1"
  local local_env="$SECRETS_DIR/$host.env"
  [ -s "$local_env" ] || die "[$host] secret env file missing ($local_env) — run provision/30_config.sh / 45_zero_touch.sh first"
  local re; re="$(batman_strip_regex)"
  local tmp_env="$local_env.tmp"
  grep -vE "$re" "$local_env" > "$tmp_env" || true
  local i=0
  while [ "$i" -lt "${#BATMAN_ENV_NAMES[@]}" ]; do
    printf '%s=%s\n' "${BATMAN_ENV_NAMES[$i]}" "${BATMAN_ENV_VALUES[$i]}" >> "$tmp_env"
    i=$((i + 1))
  done
  mv "$tmp_env" "$local_env"; chmod 600 "$local_env"
  log "[$host] Batman env battery appended (${#BATMAN_ENV_NAMES[@]} vars, strip-then-append)"
}

# --- Form-7 governance activation on a peer over SSH (idempotent) --------------
# Drives the golden binary against the daemon's LOCAL sqlite ($REMOTE_GOV_DB) —
# the substrate the runtime rule checks consult on every backend (#1536) — and
# binds the Form-2/6 namespace standard through the live HTTP surface. Mirrors
# scripts/install-batman-active.sh steps 1-3 + 7.
activate_form7_on_peer() {
  local ip="$1" host="$2"
  log "[$host] Form-7 governance activation (keygen + sign-seed + enable R001..R004 --sign)"

  # Space-joined seed-rule ids from the SSOT list (no literal in the heredoc).
  local rules_csv="" r
  for r in "${BATMAN_SEED_RULES[@]}"; do rules_csv="${rules_csv:+$rules_csv }$r"; done

  # Remote recipe. All verbs are idempotent: keygen skips if the key exists,
  # enable/sign-seed are no-ops when already applied.
  #
  # #1536 — the rules verbs run against the peer's LOCAL sqlite --db ON
  # PURPOSE: the Form-7 rules engine is sqlite-substrate-scoped by design
  # (the runtime checks — MCP memory_check_agent_action and the HTTP
  # /api/v1/governance surface — read the daemon's local sqlite
  # governance_rules table on EVERY backend, including postgres-backed
  # peers). The pre-#1536 wrapper appended --store-url to every verb;
  # `rules` / `store` / `namespace` don't accept that flag (only
  # `serve` / `curator` do), so every call was a clap parse error
  # swallowed by `>/dev/null 2>&1 || true` — Form-7 activation was a
  # SILENT NO-OP on every postgres peer. Errors are now surfaced.
  ssh_node "$ip" "
    set -u
    export HOME=/root
    export AI_MEMORY_KEY_DIR='$REMOTE_KEY_DIR'
    mkdir -p '$REMOTE_KEY_DIR'; chmod 700 '$REMOTE_KEY_DIR'
    AM() { '$BIN' --db '$REMOTE_GOV_DB' \"\$@\"; }
    # 1. operator key (idempotent)
    if [ ! -f '$REMOTE_KEY_DIR/operator.key' ]; then
      AM rules keygen >/dev/null || echo \"WARN: rules keygen failed on $host\" >&2
    fi
    # 2. sign the seed rules (idempotent no-op if already signed)
    AM rules sign-seed >/dev/null || echo \"WARN: rules sign-seed failed on $host\" >&2
    # 3. enable + sign R001..R004 (idempotent)
    for r in $rules_csv; do
      AM rules enable --id \"\$r\" --sign >/dev/null || echo \"WARN: rules enable \$r failed on $host\" >&2
    done
    # 4. verify: the runtime check the harness PreToolUse hook calls
    # must REFUSE a /tmp write. Fails loudly when activation didn't
    # take (the pre-#1536 silent no-op class).
    VERDICT=\$(AM governance check-action --kind filesystem_write --path /tmp/probe-1536 --json 2>/dev/null | grep -o '\"decision\":\"[a-z]*\"' | head -1)
    case \"\$VERDICT\" in
      *refuse*) : ;;
      *) echo \"WARN: Form-7 verify on $host expected refuse for /tmp write, got '\$VERDICT'\" >&2; exit 64 ;;
    esac
  " || log "[$host] WARN: Form-7 activation/verification FAILED (see stderr above — rules engine may be inactive on this peer)"

  # 7. bind the Form2/6 Batman namespace policy on the campaign
  # namespace — via the daemon's HTTP surface so it lands in the
  # peer's LIVE store (postgres on do-1461 peers). The pre-#1536 form
  # wrote it to the peer's local sqlite via CLI one-shots, which a
  # postgres-backed daemon never reads (and the calls were the same
  # silent clap-error no-ops as above). Uses the validate-harness
  # client pattern: on-node loopback curl, mTLS client cert + the
  # x-api-key from the run-dir secret; the standard row is written by
  # the enrolled harness agent (attested store — the fleet runs
  # REQUIRE_AGENT_ATTESTATION=1).
  local api_key policy_json std_id std_title
  api_key="$(cat "$RUN_DIR/secrets/api.pw" 2>/dev/null || true)"
  if [ -z "$api_key" ]; then
    log "[$host] WARN: api.pw missing — skipping Form-2/6 namespace-standard bind"
    return 0
  fi
  policy_json="$(ssh_node "$ip" "'$BIN' namespace batman-policy --json 2>/dev/null" | grep -vE '^ai-memory: loaded config' || true)"
  if [ -z "$policy_json" ]; then
    log "[$host] WARN: batman-policy emitted nothing — skipping namespace-standard bind"
    return 0
  fi
  harness_keypair_ensure >/dev/null
  harness_enroll_peer "$ip" >/dev/null 2>&1 || true
  std_title="batman-active standard for $DEFAULT_NAMESPACE"
  local std_body curl_base
  std_body="$(attested_body "$DEFAULT_NAMESPACE" "$std_title" observation collective \
    "Form 2 synchronous atomise-before-embed + Form 6 auto-classify (regex_then_llm) namespace standard. Set by provision/46_batman.sh on peer $host.")"
  curl_base="--max-time 8 --resolve $host:$FEDERATION_PORT:127.0.0.1 --cacert $REMOTE_TLS/ca.pem --cert $REMOTE_TLS/client.pem --key $REMOTE_TLS/client.key"
  std_id="$(ssh_node "$ip" "curl -fsS $curl_base -H 'x-api-key: $api_key' -H 'x-agent-id: $HARNESS_AGENT_ID' -X POST -H 'content-type: application/json' --data '$std_body' https://$host:$FEDERATION_PORT/api/v1/memories" 2>/dev/null | sed -n 's/.*"id"[^"]*"\([^"]*\)".*/\1/p')"
  if [ -z "$std_id" ]; then
    log "[$host] WARN: namespace-standard store refused — Form-2/6 bind skipped"
    return 0
  fi
  local std_payload
  std_payload="$(printf '{"id":"%s","governance":%s}' "$std_id" "$policy_json")"
  if ssh_node "$ip" "curl -fsS $curl_base -H 'x-api-key: $api_key' -H 'x-agent-id: $HARNESS_AGENT_ID' -X POST -H 'content-type: application/json' --data '$std_payload' https://$host:$FEDERATION_PORT/api/v1/namespaces/$DEFAULT_NAMESPACE/standard" >/dev/null 2>&1; then
    log "[$host] Form-2/6 namespace standard bound on $DEFAULT_NAMESPACE (id=$std_id, live store)"
  else
    log "[$host] WARN: namespace set-standard HTTP call failed — Form-2/6 bind incomplete"
  fi
}

# --- start the curator daemon (Form-1/5/6 upkeep) on a peer (idempotent) -------
# systemd unit; the Form-5 env battery is already in the EnvironmentFile so the
# curator inherits AUTO_CONFIDENCE / SHADOW / DECAY when 50 (re)starts the stack.
install_curator_on_peer() {
  local ip="$1" host="$2"
  local unit="/etc/systemd/system/ai-memory-curator.service"
  ssh_node "$ip" "cat > '$unit' <<UNIT
[Unit]
Description=ai-memory autonomous curator (Batman Mode, $CAMPAIGN peer $host)
After=network-online.target ai-memory.service
Wants=network-online.target

[Service]
Type=simple
Environment=HOME=/root
EnvironmentFile=$REMOTE_ENVFILE
# systemd does literal \${VAR} substitution (NOT shell :+ expansion); the
# postgres peers always carry AI_MEMORY_STORE_URL (50_federation), so pass it
# unconditionally. #1547: --store-url is a `curator` subcommand flag, so it
# MUST appear AFTER the `curator` token (clap rejects it as a global flag and
# exits 2 -> crash-loop otherwise). Mirrors `curator --store-url ...` usage.
ExecStart=$BIN curator --daemon --store-url \\\${AI_MEMORY_STORE_URL} --interval-secs $BATMAN_CURATOR_INTERVAL_SECS --max-ops $BATMAN_CURATOR_MAX_OPS
Restart=on-failure
RestartSec=30
Nice=5

[Install]
WantedBy=multi-user.target
UNIT
  chmod 0644 '$unit'; systemctl daemon-reload; systemctl enable ai-memory-curator.service >/dev/null 2>&1 || true; \
  if grep -qE '^AI_MEMORY_STORE_URL=.+' '$REMOTE_ENVFILE' 2>/dev/null; then systemctl restart ai-memory-curator.service 2>/dev/null || true; fi" \
    && log "[$host] curator daemon unit installed + enabled (interval=${BATMAN_CURATOR_INTERVAL_SECS}s, max-ops=$BATMAN_CURATOR_MAX_OPS; #1587: first start deferred to 50_federation when AI_MEMORY_STORE_URL not yet written)" \
    || log "[$host] WARN: curator unit install returned non-zero (50_federation brings the daemon up first; re-run is idempotent)"
}

# --- acceptance line per node (mirror scripts/batman-mode-acceptance.sh idea) --
# Best-effort: confirm the Batman env battery is present in the node's pushed
# env file count once 50 has shipped it. At THIS step the file is local-only, so
# emit the local count as the acceptance signal.
batman_acceptance_line() {
  local host="$1"
  local local_env="$SECRETS_DIR/$host.env"
  local re; re="$(batman_strip_regex)"
  local n; n="$(grep -cE "$re" "$local_env" 2>/dev/null || true)"
  log "[$host] BATMAN-ACCEPTANCE: ${n:-0}/${#BATMAN_ENV_NAMES[@]} max-secure env vars staged; encrypt-at-rest=postgres-disk-concern(not sqlcipher)"
}

# ============================================================================
# Drive every node. The Batman env battery goes on every DAEMON-BEARING node
# (peer/agent/ctrl — those have a 30_config EnvironmentFile). pg nodes run no
# ai-memory daemon (no env file), so they are skipped for env + governance; their
# data-at-rest is the Postgres/disk concern documented above.
# Form-7 governance + curator run on PEERS only (the postgres-backed daemons).
# ============================================================================
inv_all | while IFS="$(printf '\t')" read -r host role region pub priv; do
  case "$role" in
    pg)
      log "[$host] role=pg (PostgreSQL substrate, no daemon) — Batman env N/A; at-rest is Postgres/disk concern, in-transit is Leg-3 verify-full"
      continue
      ;;
    peer)
      append_batman_env "$host"
      activate_form7_on_peer "$pub" "$host"
      install_curator_on_peer "$pub" "$host"
      batman_acceptance_line "$host"
      ;;
    agent|ctrl)
      # Pure mTLS API clients (no mesh membership / no governance DB), but they
      # still carry the Batman env battery so their CLI/API writes attest + the
      # permission mode is enforce.
      append_batman_env "$host"
      batman_acceptance_line "$host"
      ;;
    *)
      log "[$host] unknown role '$role' — skipping Batman activation"
      ;;
  esac
done

log "Batman-active posture staged on all daemon-bearing nodes (env battery + Form-7 on peers + curator); 50_federation.sh will ship the env + restart to make it LIVE"
