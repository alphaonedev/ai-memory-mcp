#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# make-signed-pool.sh -- mint a pool of PRE-SIGNED, ready-to-POST attested
# write bodies for the #2921 capacity bench.
#
# WHY THIS EXISTS. At v1.0.0 an unsigned `POST /api/v1/memories` is refused
# (`AI_MEMORY_REQUIRE_AGENT_ATTESTATION`, fail-closed by compiled default),
# and the federation receive path refuses an unsigned THIRD-PARTY relayed
# write (`AI_MEMORY_FED_REQUIRE_WRITE_SIG`, likewise fail-closed as of the
# v1.0.0 flip). Both were confirmed empirically before this script was
# written: an unsigned write is accepted locally only with the opt-out, and
# a peer answers `2xx but 1 item(s) skipped (refused/not applied by
# receiver)` and the sender DLQs the row. So MEASURING THE SHIPPED POSTURE
# requires every offered write to carry a valid Ed25519 attestation.
#
# Signing inside the load driver would benchmark the driver's signing loop.
# Signing happens here instead, AHEAD of the timed window, using the in-tree
# `examples/attest_sign_batch` -- the same crate code (`identity::sign`
# over `SignableWrite`) the verifier runs, so a body this emits is valid by
# construction rather than by a re-implementation that might drift.
#
# SHELF LIFE. The signature commits to a `created_at` stamped once for the
# whole batch and the server enforces a bounded freshness window (+/-300s).
# A pool is therefore PERISHABLE: mint it immediately before the run that
# consumes it. The consumer records the pool's age with every result.
#
# Usage:
#   make-signed-pool.sh --signer <path to attest_sign_batch> \
#       --author ai:bench-author@cap2921 --priv <keydir>/ai:...priv \
#       --namespace cap2921 --count 20000 --prefix store --out pool.ndjson
set -euo pipefail

SIGNER=""; AUTHOR=""; PRIV=""; NAMESPACE=""; COUNT=""; PREFIX="pool"; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --signer) SIGNER="$2"; shift 2 ;;
    --author) AUTHOR="$2"; shift 2 ;;
    --priv) PRIV="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --count) COUNT="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
for v in SIGNER AUTHOR PRIV NAMESPACE COUNT OUT; do
  eval "val=\${$v:-}"
  [ -n "$val" ] || { echo "FATAL: --$(echo "$v" | tr 'A-Z_' 'a-z-') is required" >&2; exit 2; }
done
[ -x "$SIGNER" ] || { echo "FATAL: signer $SIGNER is not executable (build it with: cargo build --release --example attest_sign_batch)" >&2; exit 2; }
[ -f "$PRIV" ] || { echo "FATAL: private seed $PRIV not found" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Every record is UNIQUE in (title, namespace): a signed body is consumed
# exactly once by the driver, and replaying one would exercise the conflict
# path instead of an insert.
python3 - "$COUNT" "$NAMESPACE" "$PREFIX" >"$TMP/corpus.jsonl" <<'PY'
import json, sys
n, ns, prefix = int(sys.argv[1]), sys.argv[2], sys.argv[3]
out = sys.stdout
for i in range(n):
    out.write(json.dumps({
        "title": f"{prefix}-{i:08d}",
        # Fixed-shape ~120-byte content. A capacity number is only
        # comparable across runs if the payload size is fixed; it is
        # recorded in the results doc alongside every figure.
        "content": (f"capacity envelope 2921 record {i:08d} "
                    "keyword token envelope probe payload "
                    "fixed width filler for a stable body size"),
        "namespace": ns,
        "tier": "short",
        "kind": "observation",
        "source": "api",
    }) + "\n")
PY

"$SIGNER" --agent-id "$AUTHOR" --priv-file "$PRIV" \
  --corpus "$TMP/corpus.jsonl" >"$OUT"

lines="$(wc -l <"$OUT")"
[ "$lines" -eq "$COUNT" ] || {
  echo "FATAL: signed pool has $lines bodies, expected $COUNT -- a skipped record is a silent shortfall, refusing" >&2
  exit 71
}
echo "[make-signed-pool] $lines attested bodies -> $OUT (namespace=$NAMESPACE author=$AUTHOR)"
