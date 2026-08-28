#!/usr/bin/env bash
# Wave-1 C3 follow-up: recapture §2 four-leg doctor --posture evidence at
# the current release tip (20 checks). Docs/evidence only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/docs/compliance/evidence/cert-55"
FIX="$ROOT/.local-runs/cert-55-fixtures"
DEFAULT_BIN="${DEFAULT_BIN:-/home/fate_two/.cache/cargo-target-grok-cert55-default/release/ai-memory}"
SQLCIPHER_BIN="${SQLCIPHER_BIN:-/home/fate_two/.cache/cargo-target-grok-cert55-sqlcipher/release/ai-memory}"
export TMPDIR="${TMPDIR:-$ROOT/.local-runs/tmp}"
mkdir -p "$OUT" "$FIX" "$TMPDIR"
chmod 0700 "$FIX" "$TMPDIR"

python3 - <<'PY'
from pathlib import Path
import os, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

fix = Path(os.environ.get("FIX") or Path.cwd() / ".local-runs/cert-55-fixtures")
fix.mkdir(parents=True, exist_ok=True)
keys = fix / "keys"
keys.mkdir(mode=0o700, exist_ok=True)
os.chmod(keys, 0o700)
sk = Ed25519PrivateKey.generate()
priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
(keys / "ai-memory.priv").write_bytes(priv)
(keys / "ai-memory.pub").write_bytes(pub)
os.chmod(keys / "ai-memory.priv", 0o600)
os.chmod(keys / "ai-memory.pub", 0o644)
(fix / "operator.pub.b64").write_text(base64.b64encode(pub).decode() + "\n")
(fix / "peer-fingerprints.txt").write_text(
    "peer-a.fleet.example 1111111111111111111111111111111111111111111111111111111111111111\n"
)
(fix / "peer-attestation.json").write_text(
    '{"peer-a":{"allowed_sender_agent_ids":["agent-a"],"allowed_namespaces":["team-x/ops","team-x/shared"]}}\n'
)
print("fixtures ok", keys)
PY
FIX="$FIX"
OPUB="$(tr -d '\n' < "$FIX/operator.pub.b64")"
ATTEST="$(cat "$FIX/peer-attestation.json")"

sanitize() {
  # collapse absolute repo + fixture paths
  sed -e "s|$ROOT|<repo-root>|g" \
      -e "s|$FIX|<repo-root>/.local-runs/cert-55-fixtures|g" \
      -e "s|$HOME|<home>|g"
}

run_posture() {
  local bin="$1"
  shift
  env -i \
    PATH="/usr/bin:/bin:$HOME/.cargo/bin" \
    HOME="$HOME" \
    TMPDIR="$TMPDIR" \
    AI_MEMORY_NO_CONFIG=1 \
    AI_MEMORY_AGENT_ID=ai-memory \
    AI_MEMORY_KEY_DIR="$FIX/keys" \
    "$@" \
    "$bin" doctor --posture enterprise-federation
}

# --- leg 1: bare ---
set +e
run_posture "$DEFAULT_BIN" >"$OUT/posture-bare-env.out.raw" 2>&1
e1=$?
set -e
sanitize <"$OUT/posture-bare-env.out.raw" >"$OUT/posture-bare-env.out"
rm -f "$OUT/posture-bare-env.out.raw"

HARD=(
  AI_MEMORY_SECURITY_PROFILE=asi-hard
  AI_MEMORY_FED_TRUST_DOMAIN=cert-fleet-01
  AI_MEMORY_FED_PEER_FINGERPRINTS="$FIX/peer-fingerprints.txt"
  AI_MEMORY_FED_PEER_ATTESTATION="$ATTEST"
  AI_MEMORY_ENCRYPT_AT_REST=1
  AI_MEMORY_APPEND_ONLY=1
  AI_MEMORY_OPERATOR_PUBKEY="$OPUB"
)

# --- leg 2: hardened non-sqlcipher, boot gate NOT armed ---
set +e
run_posture "$DEFAULT_BIN" "${HARD[@]}" >"$OUT/posture-hardened-env.out.raw" 2>&1
e2=$?
set -e
sanitize <"$OUT/posture-hardened-env.out.raw" >"$OUT/posture-hardened-env.out"
rm -f "$OUT/posture-hardened-env.out.raw"

# --- leg 3: hardened non-sqlcipher, boot gate ARMED ---
# Boot refuse is NOT doctor --posture (that subcommand bypasses the gate).
# Use `config show` (goes through main, not doctor --posture).
set +e
env -i \
  PATH="/usr/bin:/bin:$HOME/.cargo/bin" \
  HOME="$HOME" \
  TMPDIR="$TMPDIR" \
  AI_MEMORY_NO_CONFIG=1 \
  AI_MEMORY_AGENT_ID=ai-memory \
  AI_MEMORY_KEY_DIR="$FIX/keys" \
  "${HARD[@]}" \
  AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1 \
  "$DEFAULT_BIN" doctor >"$OUT/posture-hardened-boot-refusal.out.raw" 2>&1
e3=$?
set -e
sanitize <"$OUT/posture-hardened-boot-refusal.out.raw" >"$OUT/posture-hardened-boot-refusal.out"
rm -f "$OUT/posture-hardened-boot-refusal.out.raw"

# --- leg 4: sqlcipher + encrypt + boot gate ---
if [[ ! -x "$SQLCIPHER_BIN" ]]; then
  echo "sqlcipher binary missing: $SQLCIPHER_BIN" >&2
  echo "leg4 skipped"
  e4=missing
else
  set +e
  run_posture "$SQLCIPHER_BIN" "${HARD[@]}" \
    AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1 \
    >"$OUT/posture-sqlcipher-pass.out.raw" 2>&1
  e4=$?
  set -e
  sanitize <"$OUT/posture-sqlcipher-pass.out.raw" >"$OUT/posture-sqlcipher-pass.out"
  rm -f "$OUT/posture-sqlcipher-pass.out.raw"
fi

{
  echo "# posture-legs transcript — recorded exit codes (2026-08-28 recapture @ $(git -C "$ROOT" rev-parse --short HEAD))"
  echo "# each leg: the doctor invocation shape, then the observed shell exit status."
  echo
  echo "## leg 1: bare (env -i, AI_MEMORY_NO_CONFIG=1 only)"
  echo "exit: $e1"
  echo "## leg 2: hardened non-sqlcipher, boot gate NOT armed"
  echo "exit: $e2"
  echo "## leg 3: hardened non-sqlcipher, boot gate ARMED (AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1)"
  echo "exit: $e3"
  echo "## leg 4: sqlcipher build, ENCRYPT_AT_REST=1, boot gate ARMED"
  echo "exit: $e4"
} >"$OUT/posture-legs-exit-codes.txt"

cp "$FIX/peer-fingerprints.txt" "$OUT/peer-fingerprints.txt"
cp "$FIX/peer-attestation.json" "$OUT/peer-attestation.json"

echo "exits e1=$e1 e2=$e2 e3=$e3 e4=$e4"
echo "FAIL/PASS counts:"
for f in posture-bare-env.out posture-hardened-env.out posture-sqlcipher-pass.out; do
  if [[ -f "$OUT/$f" ]]; then
    echo -n "$f FAIL=$(grep -c '\[FAIL\]' "$OUT/$f" || true) PASS=$(grep -c '\[PASS\]' "$OUT/$f" || true) "
    grep -E 'overall:' "$OUT/$f" || true
  fi
done
