#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# =============================================================================
# federate.sh -- Track D post-apply federation wiring for the DO memory nodes.
# =============================================================================
#
# Completes the mesh that `spawn.sh apply -var memory_count=N` (N >= 2) parks
# in a fail-closed wait. It NEVER calls terraform, NEVER spawns a droplet, and
# NEVER spends money -- it only SSHes into an already-provisioned cluster and
# refuses (non-zero, no side effects) if the terraform outputs do not describe
# one. Same safety property `infra/pillar4-envelope/measure-capacity-ramp.sh`
# declares for the measurement ramp.
#
# WHY THIS STEP EXISTS AT ALL (and is not folded into terraform):
#
#   1. PEER IPs. A DO droplet's private IPv4 is allocated at create time and
#      `digitalocean_droplet` has no input for it, so node N's cloud-init
#      cannot reference node M's address: with `count`, terraform models the
#      resource as ONE graph node and any self-reference is a hard
#      `Cycle: digitalocean_droplet.memory` at plan time. Peer wiring is
#      therefore necessarily post-create.
#
#   2. SECRETS. Anything terraform renders into `user_data` lives verbatim in
#      `terraform.tfstate` -- which `spawn.sh` COPIES into
#      `.local-runs/do-hive-runs/<ts>/` on every apply -- and is also readable
#      from the droplet's own metadata service. Minting the CA + leaf keys
#      HERE and pushing them over SSH keeps every private key out of both.
#      The nodes' Ed25519 federation signing keys are generated ON the
#      droplets and their private halves never move at all; only `.pub` files
#      cross the wire (the same public-material-only discipline
#      `infra/lan-parity-test/provision-peer-keys.sh` follows for the docker
#      mesh, #1803).
#
# Modes:
#   ./federate.sh            # wire the mesh, then run the assertions
#   ./federate.sh wire       # wire only
#   ./federate.sh verify     # re-run the assertions against a wired mesh
#
# Requires on the ORCHESTRATOR host: terraform (for `output -json` only), jq,
# curl, openssl, ssh/scp, and a release build with the postgres features plus
# the signer example:
#   cargo build --release --features sal,sal-postgres
#   cargo build --release --example attest_sign
# =============================================================================

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
OUT_DIR="${OUT_DIR:-${HERE}/crypto/out}"
BIN="${BIN:-${REPO_ROOT}/target/release/ai-memory}"
SIGNER="${SIGNER:-${REPO_ROOT}/target/release/examples/attest_sign}"
AUTHOR_ID="${AUTHOR_ID:-ai:hive-author}"
AUTHOR_KEY_DIR="${AUTHOR_KEY_DIR:-${HERE}/crypto/author-keys}"
SSH_USER="${SSH_USER:-root}"
# RESIDUAL RISK, disclosed: this SSH channel carries the CA private key and each
# node's leaf node.key, and it defaults to StrictHostKeyChecking=accept-new --
# trust-on-first-use. A first-contact MITM on the operator->droplet path would
# obtain that material. Accepted here because the hive is ephemeral,
# money-gated, and operator->own-droplet. To close it: pre-seed known_hosts
# from the DO console host keys, or export
# SSH_OPTS='-o StrictHostKeyChecking=yes -o ConnectTimeout=15' with the host
# key pinned.
SSH_OPTS="${SSH_OPTS:--o StrictHostKeyChecking=accept-new -o ConnectTimeout=15}"
# #5274: every ssh and scp call passes SSH_BATCH first. ssh uses the first value given for an
# option, so no SSH_OPTS override can turn batch mode off: a node cannot put a password or
# keyboard-interactive prompt on the operator terminal or hang the run waiting for input.
SSH_BATCH="-o BatchMode=yes"
FED_DIR=/etc/ai-memory/fed
NS="${NS:-fed-cert}"
WAIT_TRIES="${WAIT_TRIES:-180}"
WAIT_SLEEP="${WAIT_SLEEP:-10}"

pass=0
fail=0
ok() { echo "PASS: $1"; pass=$((pass + 1)); }
no() { echo "FAIL: $1"; fail=$((fail + 1)); }
die() { echo "[federate] REFUSE: $*" >&2; exit 2; }

# --- inputs ------------------------------------------------------------------

read_nodes() {
  command -v jq >/dev/null 2>&1 || die "jq is required"
  cd "$HERE" || die "cannot cd to $HERE"
  NODES_JSON="$(terraform output -json memory_nodes 2>/dev/null)" \
    || die "no terraform outputs here; run spawn.sh apply -var memory_count=2 first"
  [ -n "$NODES_JSON" ] && [ "$NODES_JSON" != "null" ] \
    || die "terraform output memory_nodes is empty"
  NODE_COUNT="$(echo "$NODES_JSON" | jq 'length')"
  [ "$NODE_COUNT" -ge 1 ] \
    || die "memory_nodes is empty; apply at least memory_count=1"
  PUBLIC_IPS=($(echo "$NODES_JSON" | jq -r '.[].public_ip'))
  PRIVATE_IPS=($(echo "$NODES_JSON" | jq -r '.[].private_ip'))
  FED_IDS=($(echo "$NODES_JSON" | jq -r '.[].fed_identity'))
  PEER_URLS=($(echo "$NODES_JSON" | jq -r '.[].peer_url'))
  echo "[federate] ${NODE_COUNT} memory nodes:"
  for i in $(seq 0 $((NODE_COUNT - 1))); do
    echo "  node $((i + 1)): public=${PUBLIC_IPS[$i]} private=${PRIVATE_IPS[$i]} identity=${FED_IDS[$i]}"
  done
}

on_node() { ssh $SSH_BATCH $SSH_OPTS "${SSH_USER}@$1" "$2"; }

# --- wire --------------------------------------------------------------------

wire() {
  [ -x "$BIN" ] || die "no ai-memory release binary at $BIN (cargo build --release --features sal,sal-postgres)"

  # 1. Crypto material. Reuses crypto/gen-certs.sh (prior art) via its ADDITIVE
  #    HIVE_NODE_IPS mode, so the legacy localhost/peerA/peerB material is
  #    regenerated exactly as before alongside the per-droplet leaves.
  echo "[federate] minting crypto material for ${NODE_COUNT} nodes -> $OUT_DIR"
  HIVE_NODE_IPS="${PRIVATE_IPS[*]}" HIVE_NODE_PUBLIC_IPS="${PUBLIC_IPS[*]}" \
    PG_HOST=localhost OUT_DIR="$OUT_DIR" \
    "$HERE/crypto/gen-certs.sh" >/dev/null || die "gen-certs.sh failed"

  # 2. Author identity for the CONTENT write-sig lane. The PRIVATE half stays
  #    on this host and is used only to sign the probe write; only the public
  #    half is ever pushed to a droplet.
  mkdir -p "$AUTHOR_KEY_DIR"
  chmod 0700 "$AUTHOR_KEY_DIR"
  if [ ! -f "$AUTHOR_KEY_DIR/$AUTHOR_ID.priv" ]; then
    AI_MEMORY_NO_CONFIG=1 "$BIN" identity generate --agent-id "$AUTHOR_ID" \
      --key-dir "$AUTHOR_KEY_DIR" >/dev/null 2>&1 \
      || die "could not generate the author identity $AUTHOR_ID"
  fi
  AUTHOR_PUB="$(AI_MEMORY_NO_CONFIG=1 "$BIN" identity export-pub --agent-id "$AUTHOR_ID" \
    --key-dir "$AUTHOR_KEY_DIR" 2>/dev/null | tail -1)"
  [ -n "$AUTHOR_PUB" ] || die "could not export the author public key"
  echo "[federate] author $AUTHOR_ID pubkey $AUTHOR_PUB (private half stays on this host)"

  # 3. Push each node its bundle + the peer list every OTHER node must dial.
  for i in $(seq 0 $((NODE_COUNT - 1))); do
    n=$((i + 1))
    host="${PUBLIC_IPS[$i]}"
    peers=""
    for j in $(seq 0 $((NODE_COUNT - 1))); do
      [ "$j" -eq "$i" ] && continue
      peers="${peers:+$peers,}${PEER_URLS[$j]}"
    done
    echo "[federate] node $n ($host): peers=$peers"
    printf 'AI_MEMORY_QUORUM_PEERS=%s\n' "$peers" > "$OUT_DIR/peers.conf.node$n"
    printf '%s' "$AUTHOR_ID" > "$OUT_DIR/author.id"
    printf '%s' "$AUTHOR_PUB" > "$OUT_DIR/author.pub"

    on_node "$host" "install -d -m 0750 $FED_DIR $FED_DIR/peers" >/dev/null 2>&1 \
      || die "node $n: cannot create $FED_DIR (is the droplet up + reachable on 22?)"
    scp $SSH_BATCH $SSH_OPTS -q \
      "$OUT_DIR/ca.crt" \
      "${SSH_USER}@${host}:$FED_DIR/ca.crt" >/dev/null 2>&1 || die "node $n: scp ca.crt failed"
    scp $SSH_BATCH $SSH_OPTS -q "$OUT_DIR/hive-node-$n.crt" "${SSH_USER}@${host}:$FED_DIR/node.crt" >/dev/null 2>&1 \
      || die "node $n: scp node.crt failed"
    scp $SSH_BATCH $SSH_OPTS -q "$OUT_DIR/hive-node-$n.key" "${SSH_USER}@${host}:$FED_DIR/node.key" >/dev/null 2>&1 \
      || die "node $n: scp node.key failed"
    scp $SSH_BATCH $SSH_OPTS -q "$OUT_DIR/hive-node-$n.allowlist" "${SSH_USER}@${host}:$FED_DIR/peers.allowlist" >/dev/null 2>&1 \
      || die "node $n: scp peers.allowlist failed"
    scp $SSH_BATCH $SSH_OPTS -q "$OUT_DIR/peers.conf.node$n" "${SSH_USER}@${host}:$FED_DIR/peers.conf" >/dev/null 2>&1 \
      || die "node $n: scp peers.conf failed"
    scp $SSH_BATCH $SSH_OPTS -q "$OUT_DIR/author.id" "$OUT_DIR/author.pub" "${SSH_USER}@${host}:$FED_DIR/" >/dev/null 2>&1 \
      || die "node $n: scp author material failed"
    on_node "$host" "chmod 0600 $FED_DIR/node.key" >/dev/null 2>&1 || die "node $n: chmod node.key failed"
  done

  # 4. Collect each node's freshly-minted federation .pub (published by the
  #    on-droplet bootstrap stage A) and cross-copy it to every other node.
  #    Public material only -- this never touches a .priv.
  echo "[federate] waiting for each node to publish its federation public key"
  for i in $(seq 0 $((NODE_COUNT - 1))); do
    n=$((i + 1))
    host="${PUBLIC_IPS[$i]}"
    pub="${FED_IDS[$i]}.pub"
    t=0
    until on_node "$host" "test -s '$FED_DIR/$pub'" >/dev/null 2>&1; do
      t=$((t + 1))
      [ "$t" -gt "$WAIT_TRIES" ] && die "node $n never published $FED_DIR/$pub (journalctl -u ai-memory-fed-bootstrap)"
      [ $((t % 6)) -eq 1 ] && echo "  node $n: waiting for $pub ... $t/$WAIT_TRIES"
      sleep "$WAIT_SLEEP"
    done
    scp $SSH_BATCH $SSH_OPTS -q "${SSH_USER}@${host}:$FED_DIR/$pub" "$OUT_DIR/$pub" >/dev/null 2>&1 \
      || die "node $n: could not fetch $pub"
    echo "  node $n: collected $pub"
  done
  for i in $(seq 0 $((NODE_COUNT - 1))); do
    n=$((i + 1))
    host="${PUBLIC_IPS[$i]}"
    for j in $(seq 0 $((NODE_COUNT - 1))); do
      [ "$j" -eq "$i" ] && continue
      scp $SSH_BATCH $SSH_OPTS -q "$OUT_DIR/${FED_IDS[$j]}.pub" "${SSH_USER}@${host}:$FED_DIR/peers/" >/dev/null 2>&1 \
        || die "node $n: could not install peer pubkey ${FED_IDS[$j]}"
    done
    echo "[federate] node $n cross-enrolled with $((NODE_COUNT - 1)) peer key(s)"
  done

  # 5. Release the fail-closed wait on every node, then wait for MESH READY.
  for i in $(seq 0 $((NODE_COUNT - 1))); do
    on_node "${PUBLIC_IPS[$i]}" "touch $FED_DIR/ENROLLED" >/dev/null 2>&1 \
      || die "node $((i + 1)): could not mark ENROLLED"
  done
  for i in $(seq 0 $((NODE_COUNT - 1))); do
    n=$((i + 1))
    host="${PUBLIC_IPS[$i]}"
    t=0
    until on_node "$host" "test -f '$FED_DIR/MESH-READY'" >/dev/null 2>&1; do
      t=$((t + 1))
      if [ "$t" -gt "$WAIT_TRIES" ]; then
        # #5171: node output never reaches this terminal; the operator reads the log on the node.
        echo "[federate] node $n federation log: ssh ${SSH_USER}@$host tail -30 /var/log/ai-memory-federation.log" >&2
        die "node $n never reached MESH READY"
      fi
      [ $((t % 6)) -eq 1 ] && echo "  node $n: waiting for MESH READY ... $t/$WAIT_TRIES"
      sleep "$WAIT_SLEEP"
    done
    echo "[federate] node $n MESH READY"
  done
}

# Enroll the off-DO Phase-A driver only after wire has minted the shared-CA
# leaf. The bundle stays outside git and every file is mode 0600.
loadgen() {
  [ -s "$OUT_DIR/hive-loadgen-f2.crt" ] || die "run '$0 wire' first"
  loadgen_fp="$(openssl x509 -in "$OUT_DIR/hive-loadgen-f2.crt" -outform DER | openssl dgst -sha256 | awk '{print $NF}')"
  for i in $(seq 0 $((NODE_COUNT - 1))); do
    node_sh "$i" <<EOS >/dev/null 2>&1 || die "node $((i + 1)): loadgen enrollment failed"
set -e
grep -qx '$loadgen_fp' '$FED_DIR/peers.allowlist' || printf '%s\n' '$loadgen_fp' >> '$FED_DIR/peers.allowlist'
systemctl restart ai-memory
EOS
  done
  run_dir="$REPO_ROOT/.local-runs/do-hive-runs/$(date -u +%Y-%m-%dT%H-%M-%SZ)/loadgen"
  install -d -m 0700 "$run_dir"
  install -m 0600 "$OUT_DIR/hive-loadgen-f2.crt" "$run_dir/client.crt"
  install -m 0600 "$OUT_DIR/hive-loadgen-f2.key" "$run_dir/client.key"
  install -m 0600 "$OUT_DIR/ca.crt" "$run_dir/ca.crt"
  echo "[federate] loadgen bundle: $run_dir"
  # The key is a credential: it goes to a 0600 file in the 0700 run dir, never to the terminal or a log.
  local keyf="$run_dir/api-key" keytmp
  rm -f -- "$keyf"
  # bash noclobber adds O_EXCL only when the name does not exist yet; an entry planted at a known
  # name (a symlink to a FIFO or a terminal) is still opened and written through. So the key goes
  # to an unpredictable new name (O_EXCL), is checked there, and is renamed over
  # api-key: rename replaces whatever entry sits at that name and never writes through it.
  # grep -a: GNU grep treats a NUL as a line end in a binary file, so key+NUL would count as one line.
  # The file is at most 65 bytes, has exactly one line of 64 hex, and starts with a hex digit (so an
  # empty first line followed by the key is refused): the key, optionally one newline, nothing else.
  keytmp="$(mktemp -u "$run_dir/.api-key.XXXXXXXXXX")" || die "mktemp failed in $run_dir"
  # An interrupt between the first key byte and the rename must not leave a partial key at the temp name.
  trap 'rm -f -- "$keytmp"; exit 130' INT TERM HUP
  # The key is written only to a file descriptor this run created: nothing may exist at the new
  # name (a FIFO, symlink, directory or device there is refused), the descriptor is opened with
  # noclobber (O_EXCL), and it must be a regular file (-f follows the descriptor) that the name still
  # points to (-ef), BEFORE the first key byte is written to it. A swap inside that window yields a
  # refusal, never a key write; the key never reaches a FIFO, a terminal or another entry.
  if ! ( umask 077; set -o noclobber
         [ ! -e "$keytmp" ] && [ ! -L "$keytmp" ] && exec 9> "$keytmp" \
           && [ -f /dev/fd/9 ] && [ "$keytmp" -ef /dev/fd/9 ] \
           && on_node "${PUBLIC_IPS[0]}" 'cat /etc/ai-memory/api-key' >&9 2>/dev/null ) \
     || [ "$(LC_ALL=C wc -c < "$keytmp")" -gt 65 ] \
     || [ "$(LC_ALL=C grep -aEcx '[0123456789abcdef]{64}' "$keytmp")" != 1 ] \
     || ! LC_ALL=C head -c 1 -- "$keytmp" | LC_ALL=C grep -q '[0123456789abcdef]' \
     || ! mv -f -T -- "$keytmp" "$keyf"; then
    rm -f -- "$keytmp"
    trap - INT TERM HUP
    die "could not fetch a 64-hex node API key into $keyf"
  fi
  trap - INT TERM HUP
  echo "[federate] Phase A API key written to $keyf (0600)"
}

# --- verify ------------------------------------------------------------------
#
# EVERY assertion runs ON a droplet over ssh, never from this host. The peer
# URLs are PRIVATE VPC addresses (`https://10.20.x.y:9077`) and the `:9077`
# firewall rule admits only hive droplet ids, so an orchestrator-host curl
# could not reach them even if the address routed. Running on-node also means
# the only client certs in play are ones the mesh already trusts, so the
# verification introduces no new trust anchor -- which is why there is no
# separate operator/bastion cert in `gen-certs.sh`'s HIVE_NODE_IPS mode.

# node_sh <idx0> -- run the script on stdin as root on that node.
node_sh() { ssh $SSH_BATCH $SSH_OPTS "${SSH_USER}@${PUBLIC_IPS[$1]}" "bash -s"; }

# Closed-world output (#4999, 5-agent vote 4d3ea1c5): no byte of a node reply reaches this terminal.
# verify suspends xtrace on its first line (#5237), so no reply reaches an xtrace log either; outside
# verify a node reply only ever goes to a file or to /dev/null. A PASS or FAIL line names a node-derived
# value only through these three helpers, whose output comes from a closed set. A static test
# (scripts/test/test_do_hive_argv_secrets_4604_4866_4678.py) follows node-derived names and applies
# these rules:
#  - ok, no, die, echo, printf, cat and tee may not name one; a positional parameter on such a line is
#    allowed only in ok, no, die and the three helpers; a command substitution or a backtick in such a
#    line is refused; a cat of a file is refused (#5236, #5362, #5408);
#  - any other command that names a node-derived variable is refused, except the test words [, [[,
#    test, case, for, true, false and :, and plain_id; local, export, readonly, declare and typeset
#    may take it only as the value of name=value, never as a name; a numeric test, an arithmetic
#    expansion, a substring offset or length, an array subscript and the :? expansion are refused
#    because bash prints the operand in its error message (#5361, #5406, #5411);
#  - a command that reads a file or an input redirect and is the last stage of a pipeline prints that
#    file, so it is refused unless its output goes to a file, it is wc or curl, or it is grep with a
#    -q, -c, -l or -L style flag (#5409);
#  - a redirect decides where output goes by the LAST fd-1 redirect: only a plain path or /dev/null is a
#    file; a dup, any other /dev path, /proc, or a target computed by a command substitution, a
#    backtick or a process substitution is the terminal (#5412);
#  - a pipe into base64 is exempt only when it continues into curl, and the b64 helper only while its
#    body is exactly the pinned one (#5413);
#  - a function that wraps a node channel is followed as a source, in every spelling of the definition
#    (#5360, #5414);
#  - outside main the scan refuses eval, read, mapfile, printf -v, indirect expansion, here-strings,
#    here-documents not fed to a node, indexed and escaped-space assignments, default-assign and :?
#    expansions, let, ((, process substitution and backticks (#5236, #5359, #5407, #5408, #5410).
# It is a static aid and not a proof; a form it cannot decide is reported, not trusted (#5418, #5523):
# a redirect target with an expansion or a glob is a
# file only as "$VAR/<segments>" where each segment starts with a literal character, so a target held in a
# variable, a segment held in a variable, and any ".." segment count as the terminal; the VALUE of a
# variable inside a segment (r$n) and symbolic links are not decided. A command it does not list that
# names a file this script writes is reported unless it ends in a file redirect or is a silent file
# command. Whole-verify probes check the printed bytes.
# reply_status prints a 3-digit HTTP
# status, or the word non-status for anything else. reply_len prints the reply's byte count.
# reply_version prints a version token only when it is 1 to 3 dot-separated groups of 1 to 3 ASCII
# digits, and the byte count of the whole reply otherwise.
reply_status() {
  case "$1" in
    [0123456789][0123456789][0123456789]) printf '%s' "$1" ;;
    *) printf 'non-status' ;;
  esac
}
reply_len() { printf '%s bytes' "$(printf '%s' "$1" | LC_ALL=C wc -c | LC_ALL=C tr -cd '0123456789')"; }
reply_version() { # <token> <whole reply>
  case "$1" in
    '' | *[!0123456789.]* | .* | *. | *..* | *.*.*.* | *[0123456789][0123456789][0123456789][0123456789]*)
      reply_len "$2" ;;
    *) printf '%s' "$1" ;;
  esac
}

# node_get <idx0> <memory-id> -- read one memory from that node over its own
# loopback mTLS listener, using the node's own cert + its own api key.
# plain_id <id> -- the verify steps ask this BEFORE node_get so a refused id is reported as a
# refused id, not retried 20 times as a replication failure. Same list as the node_get check
# below (a test pins that the two accept the same characters); explicit, locale-proof: a range would match non-ASCII.
plain_id() { [[ "$1" =~ ^[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-]{1,64}$ ]]; }

node_get() {
  # The id comes from a node HTTP response and is spliced into a root heredoc on
  # another node: accept only a plain id (explicit list, locale-proof: a range would match non-ASCII).
  [[ "$2" =~ ^[0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]{1,64}$ ]] || return 3
  node_sh "$1" <<EOS 2>/dev/null
K=\$(cat /etc/ai-memory/api-key); [[ "\$K" =~ ^[0123456789abcdef]{64}\$ ]] || exit 3
printf 'header = "x-api-key: %s"\\n' "\$K" | curl -sS --max-time 15 --config - \\
  --cacert /etc/ai-memory/fed/ca.crt \\
  --cert /etc/ai-memory/fed/node.crt --key /etc/ai-memory/fed/node.key \\
  -H 'x-agent-id: $AUTHOR_ID' \\
  https://127.0.0.1:9077/api/v1/memories/$2 2>/dev/null
EOS
}

# node_post <idx0> <base64-json-body> -- POST /api/v1/memories on that node.
# The body rides base64 so no JSON quoting has to survive the ssh command line.
node_post() {
  node_sh "$1" <<EOS 2>/dev/null
BODY=\$(printf '%s' '$2' | base64 -d)
K=\$(cat /etc/ai-memory/api-key); [[ "\$K" =~ ^[0123456789abcdef]{64}\$ ]] || exit 3
printf 'header = "x-api-key: %s"\\n' "\$K" | curl -sS --max-time 30 --config - \\
  --cacert /etc/ai-memory/fed/ca.crt \\
  --cert /etc/ai-memory/fed/node.crt --key /etc/ai-memory/fed/node.key \\
  -H 'content-type: application/json' \\
  -H 'x-agent-id: $AUTHOR_ID' \\
  -X POST https://127.0.0.1:9077/api/v1/memories -d "\$BODY" -w '\\n%{http_code}' 2>/dev/null
EOS
}

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

verify() {
  # Neither the key nor any node reply may reach an xtrace log: suspend -x for the whole of verify (#5237);
  # the end of verify restores it.
  case $- in *x*) _fed_xtrace=1; { set +x; } 2>/dev/null ;; *) _fed_xtrace=0 ;; esac
  # A1 -- each node answers /health over mTLS with an authorised cert, and
  #       REFUSES a caller presenting no cert (mTLS mandatory, not optional).
  for i in $(seq 0 $((NODE_COUNT - 1))); do
    n=$((i + 1))
    code=$(node_sh "$i" <<'EOS' 2>/dev/null
curl -sS --max-time 15 --cacert /etc/ai-memory/fed/ca.crt \
  --cert /etc/ai-memory/fed/node.crt --key /etc/ai-memory/fed/node.key \
  -o /dev/null -w '%{http_code}' https://127.0.0.1:9077/api/v1/health 2>/dev/null
EOS
)
    if [ "$code" = "200" ]; then
      ok "node $n /health over mTLS (200)"
    else
      no "node $n /health over mTLS got '$(reply_status "$code")' (expected 200)"
    fi

    if node_sh "$i" <<'EOS' >/dev/null 2>&1
curl -sS --max-time 10 --cacert /etc/ai-memory/fed/ca.crt \
  -o /dev/null https://127.0.0.1:9077/api/v1/health 2>/dev/null
EOS
    then
      no "node $n accepted a client presenting NO cert (mTLS not enforced)"
    else
      ok "node $n refuses a client presenting no cert"
    fi
  done

  # Certified data-tier pins, asserted from the provisioned hosts.
  for i in $(seq 0 $((NODE_COUNT - 1))); do
    versions="$(node_sh "$i" <<'EOS' 2>/dev/null
sudo -u postgres psql -d aimemory -Atc "SELECT current_setting('server_version')"
sudo -u postgres psql -d aimemory -Atc "SELECT extname || '=' || extversion FROM pg_extension WHERE extname IN ('age','vector') ORDER BY extname"
EOS
)"
    # #5172: the server_version token (first line, up to the first space) must be exactly 18.6.
    # A sed pipeline, not ${versions%%...}: bash suffix removal is quadratic in the reply length (#5247).
    pg_ver="$(printf '%s\n' "$versions" | LC_ALL=C sed -n '1{s/ .*//;p;q;}')"
    # #5275: each extension version comes only from its own labelled line after server_version and must
    # equal the pin exactly, and the label must appear exactly once (counted below): an absent or repeated
    # label fails.
    age_ver="$(printf '%s\n' "$versions" | LC_ALL=C sed -n '2,$s/^age=//p')"
    vec_ver="$(printf '%s\n' "$versions" | LC_ALL=C sed -n '2,$s/^vector=//p')"
    # $(...) strips trailing newlines, so a repeated EMPTY label that comes last would leave the value
    # above unchanged (#5357): count the labelled lines too (the count is digits only) and require one each.
    age_n="$(printf '%s\n' "$versions" | LC_ALL=C sed -n '2,$p' | LC_ALL=C grep -c '^age=')"
    vec_n="$(printf '%s\n' "$versions" | LC_ALL=C sed -n '2,$p' | LC_ALL=C grep -c '^vector=')"
    [ "$pg_ver" = 18.6 ] && ok "node $((i + 1)) PostgreSQL 18.6 (certified)" || no "node $((i + 1)) PostgreSQL is not 18.6 (got $(reply_version "$pg_ver" "$versions"))"
    # #5417: a label count other than 1 is its own fixed line, tested BEFORE any version token is printed,
    # so the line never says "(got X)" about a token it does not use and prints no byte of the reply.
    if [ "$age_n" != 1 ]; then
      no "node $((i + 1)) AGE is not 1.8.0 (the labelled row count is not 1)"
    elif [ "$age_ver" = 1.8.0 ]; then
      ok "node $((i + 1)) AGE 1.8.0"
    else
      no "node $((i + 1)) AGE is not 1.8.0 (got $(reply_version "$age_ver" "$versions"))"
    fi
    if [ "$vec_n" != 1 ]; then
      no "node $((i + 1)) pgvector is not 0.8.6 (the labelled row count is not 1)"
    elif [ "$vec_ver" = 0.8.6 ]; then
      ok "node $((i + 1)) pgvector 0.8.6"
    else
      no "node $((i + 1)) pgvector is not 0.8.6 (got $(reply_version "$vec_ver" "$versions"))"
    fi
  done

  # These two assertions intentionally originate on f2/public internet.
  if [ -s "$OUT_DIR/hive-loadgen-f2.crt" ] && grep -qx "$(openssl x509 -in "$OUT_DIR/hive-loadgen-f2.crt" -outform DER | openssl dgst -sha256 | awk '{print $NF}')" "$OUT_DIR/hive-node-1.allowlist" 2>/dev/null; then
    : # legacy local allowlist is not authoritative after remote enrollment
  fi
  code="$(curl -sS --max-time 15 --cacert "$OUT_DIR/ca.crt" --cert "$OUT_DIR/hive-loadgen-f2.crt" --key "$OUT_DIR/hive-loadgen-f2.key" -o /dev/null -w '%{http_code}' "https://${PUBLIC_IPS[0]}:9077/api/v1/health" 2>/dev/null)"
  [ "$code" = 200 ] && ok "f2 loadgen reaches public /health over mTLS (200)" || no "f2 public mTLS /health got '$(reply_status "$code")'"
  if curl -sS --max-time 10 --cacert "$OUT_DIR/ca.crt" -o /dev/null "https://${PUBLIC_IPS[0]}:9077/api/v1/health" 2>/dev/null; then
    no "public endpoint accepted a client with no certificate"
  else
    ok "public endpoint refuses a client with no certificate"
  fi

  # Admin admission over the network: allowlisted NAME + request authn (API
  # key) + enrolled client cert. Header trust is OFF on the droplet, so the
  # same request under a non-allowlisted name must be refused (403).
  api_key="$(on_node "${PUBLIC_IPS[0]}" 'cat /etc/ai-memory/api-key' 2>/dev/null || true)"
  # The key is node-supplied and becomes a curl config line on THIS host: only the
  # minted 64-hex form can carry no quote or newline, so refuse anything else.
  if [ -n "$api_key" ] && ! [[ "$api_key" =~ ^[0123456789abcdef]{64}$ ]]; then
    die "node api key is not 64 lowercase hex; refusing to build a curl config from it"
  fi
  if [ -n "$api_key" ]; then
    probe="ai:verify-probe-$(date -u +%s)"
    lg_curl() { printf 'header = "X-API-Key: %s"\n' "$api_key" | curl -sS --max-time 15 --config - --cacert "$OUT_DIR/ca.crt" --cert "$OUT_DIR/hive-loadgen-f2.crt" --key "$OUT_DIR/hive-loadgen-f2.key" "$@"; }
    lg_curl -o /dev/null -X POST -H 'content-type: application/json' -H "X-Agent-Id: ai:hive-loadgen-f2" \
      -d "{\"agent_id\":\"$probe\",\"agent_type\":\"ai:verify\"}" "https://${PUBLIC_IPS[0]}:9077/api/v1/agents" 2>/dev/null || true
    dummy_pub="$(head -c 32 /dev/zero | base64)"
    code="$(lg_curl -o /dev/null -w '%{http_code}' -X PUT -H 'content-type: application/json' -H "X-Agent-Id: ai:hive-loadgen-f2" \
      -d "{\"pubkey_b64\":\"$dummy_pub\"}" "https://${PUBLIC_IPS[0]}:9077/api/v1/agents/$probe/pubkey" 2>/dev/null)"
    # A PASS needs a 3-digit 2xx status: "2" and any other bytes is not one.
    case "$code" in 2[0123456789][0123456789]) ok "loadgen admin (ai:hive-loadgen-f2 + API key + mTLS) may bind agent keys ($(reply_status "$code"))";; *) no "loadgen admin bind got '$(reply_status "$code")' (expected 2xx)";; esac
    code="$(lg_curl -o /dev/null -w '%{http_code}' -X PUT -H 'content-type: application/json' -H "X-Agent-Id: ai:not-an-admin" \
      -d "{\"pubkey_b64\":\"$dummy_pub\"}" "https://${PUBLIC_IPS[0]}:9077/api/v1/agents/$probe/pubkey" 2>/dev/null)"
    [ "$code" = 403 ] && ok "non-allowlisted name is refused admin (403) - header trust is off" || no "non-admin bind got '$(reply_status "$code")' (expected 403)"
  else
    no "could not read the node API key for the admin-admission check"
  fi

  # A2 -- CROSS-HOST mTLS: node 1 reaches node 2 on its PRIVATE VPC address
  #       with its own peer cert. This is precisely the assertion the local
  #       2-daemon legs structurally cannot make.
  if [ "$NODE_COUNT" -ge 2 ]; then
  peerurl="${PEER_URLS[1]}"
  code=$(node_sh 0 <<EOS 2>/dev/null
curl -sS --max-time 15 --cacert /etc/ai-memory/fed/ca.crt \\
  --cert /etc/ai-memory/fed/node.crt --key /etc/ai-memory/fed/node.key \\
  -o /dev/null -w '%{http_code}' $peerurl/api/v1/health 2>/dev/null
EOS
)
  if [ "$code" = "200" ]; then
    ok "CROSS-HOST: node 1 reaches node 2 at $peerurl over mutual TLS (200)"
  else
    no "CROSS-HOST: node 1 -> node 2 ($peerurl) got '$(reply_status "$code")' (expected 200)"
  fi

  # A3 -- a W-of-N quorum write admitted at node 1 commits AND replicates.
  #       201 = quorum_met; 202 = locally durable with a late ack. Both prove
  #       the mutually authenticated peer channel carried it; the replication
  #       itself is asserted separately by READING node 2.
  # #2854: v1.0.0 fail-closes UNSIGNED HTTP-direct writes (POST /api/v1/memories)
  # with 403 ATTESTATION_FAILED, so the quorum probe MUST be signed (like A4)
  # or it never reaches the fanout it is meant to assert.
  QTITLE="hive-quorum-probe-$$"
  QCONTENT="a federated write that must replicate across the DO mTLS quorum mesh"
  QCREATED="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
  QSIG=""
  [ -x "$SIGNER" ] && QSIG="$("$SIGNER" --agent-id "$AUTHOR_ID" --namespace "$NS" \
    --title "$QTITLE" --kind observation --created-at "$QCREATED" --content "$QCONTENT" \
    --priv-file "$AUTHOR_KEY_DIR/$AUTHOR_ID.priv" 2>/dev/null)"
  body=$(jq -nc --arg t "$QTITLE" --arg c "$QCONTENT" --arg ns "$NS" --arg s "$QSIG" --arg ca "$QCREATED" \
    '{title:$t,content:$c,namespace:$ns,tier:"mid"} + (if $s != "" then {signature:$s,created_at:$ca} else {} end)')
  resp=$(node_post 0 "$(b64 "$body")")
  qcode=$(echo "$resp" | tail -1)
  qjson=$(echo "$resp" | sed '$d')
  QID=$(echo "$qjson" | jq -r '.id // empty' 2>/dev/null)
  case "$qcode" in
    201|202)
      # #5145: an accepted write with no id cannot be read back at node 2, so it is not a PASS.
      if [ -z "$QID" ]; then
        no "quorum write at node 1 was accepted ($(reply_status "$qcode")) with no memory id; replication to node 2 cannot be checked"
      elif ! plain_id "$QID"; then
        : # one FAIL with one cause: the not-a-plain-id check below prints it, and no PASS precedes it
      elif [ "$qcode" = 201 ]; then
        ok "W-of-N quorum write at node 1 committed + replicated (201 quorum_met)"
      else
        ok "quorum write at node 1 locally durable (202; peer ack timing) -- the mesh channel carried it"
      fi ;;
    *)   no "quorum write at node 1 got '$(reply_status "$qcode")' ($(reply_len "$qjson"))"
         QID="" ;; # a rejected write is not read back: node 2 must not print a PASS for it
  esac
  if [ -n "$QID" ] && ! plain_id "$QID"; then
    no "quorum write at node 1 returned a memory id that is not a plain id; it is not read back"
    QID=""
  fi
  if [ -n "$QID" ]; then
    landed=""
    for _ in $(seq 1 20); do
      landed=$(node_get 1 "$QID" | jq -r '(.memory.id // .id) // empty' 2>/dev/null)
      [ -n "$landed" ] && break
      sleep 2
    done
    if [ -n "$landed" ]; then
      ok "quorum write replicated: the memory id node 1 returned is readable at node 2"
    else
      no "quorum write never appeared at node 2 (replication failure)"
    fi
  fi

  # A4 -- a SIGNED write authored on node 1 reaches attest_level=agent_attested
  #       at node 2. The cross-peer CONTENT write-sig lane: it needs the author
  #       key enrolled at BOTH nodes (fed-bootstrap stage H) and the v1.0.0
  #       default-on AI_MEMORY_FED_REQUIRE_WRITE_SIG at the receiver. The
  #       signature is computed HERE; the author private key never leaves this
  #       host.
  if [ ! -x "$SIGNER" ]; then
    no "no attest_sign signer at $SIGNER -- build it (cargo build --release --example attest_sign) and re-run verify; the cross-peer attestation leg is NOT proven without it"
  else
    STITLE="hive-attest-probe-$$"
    SCONTENT="A v1.0.0 federation write-sig probe authored on the DO hive and relayed across the mTLS quorum mesh."
    CREATED="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
    SIG="$("$SIGNER" --agent-id "$AUTHOR_ID" --namespace "$NS" --title "$STITLE" \
      --kind observation --created-at "$CREATED" --content "$SCONTENT" \
      --priv-file "$AUTHOR_KEY_DIR/$AUTHOR_ID.priv" 2>/dev/null)"
    if [ -z "$SIG" ]; then
      no "signer produced no signature for $AUTHOR_ID"
    else
      sbody=$(jq -nc --arg t "$STITLE" --arg c "$SCONTENT" --arg ns "$NS" \
        --arg sig "$SIG" --arg ca "$CREATED" \
        '{title:$t,content:$c,namespace:$ns,tier:"mid",signature:$sig,created_at:$ca}')
      sresp=$(node_post 0 "$(b64 "$sbody")")
      scode=$(echo "$sresp" | tail -1)
      sjson=$(echo "$sresp" | sed '$d')
      SID=$(echo "$sjson" | jq -r '.id // empty' 2>/dev/null)
      srefused=""
      if [ -n "$SID" ] && ! plain_id "$SID"; then
        no "signed write at node 1 returned a memory id that is not a plain id; it is not read back"
        SID=""; srefused=1
      fi
      # A refused id is one failure with one cause: do not report it again as a rejected write.
      if [ "$scode" = "201" ] && [ -n "$SID" ]; then
        ok "signed write accepted at node 1 (201)"
      elif [ -z "$srefused" ]; then
        no "signed write at node 1 got '$(reply_status "$scode")' ($(reply_len "$sjson"))"
        SID="" # a rejected write is not read back: node 2 must not print a PASS for it
      fi
      if [ -n "$SID" ]; then
        lvl=""
        for _ in $(seq 1 20); do
          lvl=$(node_get 1 "$SID" | jq -r '(.memory.metadata.attest_level // .metadata.attest_level) // empty' 2>/dev/null)
          [ -n "$lvl" ] && break
          sleep 2
        done
        case "$lvl" in
          agent_attested) ok "signed cross-peer write lands attest_level=agent_attested at node 2" ;;
          "")             no "signed write never reached node 2 (replication or author-enrollment failure)" ;;
          *)              no "signed write reached node 2 at an attest_level other than agent_attested ($(reply_len "$lvl"))" ;;
        esac
      fi
    fi
  fi
  fi # NODE_COUNT >= 2 federation-only assertions

  echo "----"
  echo "federate verify: $pass PASS / $fail FAIL"
  api_key=""
  [ "$_fed_xtrace" = 1 ] && set -x
  [ "$fail" -eq 0 ]
}

# --- main --------------------------------------------------------------------

case "${1:-all}" in
  wire)
    read_nodes
    wire
    echo "[federate] mesh wired. Run '$0 verify' for the Track D assertions."
    ;;
  verify)
    read_nodes
    verify
    ;;
  loadgen)
    read_nodes
    loadgen
    ;;
  all)
    read_nodes
    wire
    verify
    ;;
  *)
    echo "usage: federate.sh {wire|loadgen|verify|all}" >&2
    exit 1
    ;;
esac
