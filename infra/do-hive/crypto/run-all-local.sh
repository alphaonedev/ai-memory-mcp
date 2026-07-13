#!/usr/bin/env bash
# =============================================================================
# run-all-local.sh — regenerate crypto material + run every leg's pos/neg suite
# locally. Non-zero exit if any leg fails. This is the "free" pre-flight before
# the operator provisions the paid DO hive.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
rc=0
echo "############ gen-certs ############"; ./gen-certs.sh >/dev/null && echo "certs OK" || { echo "cert-gen FAILED"; exit 1; }
for leg in test-api-mtls.sh test-federation-mtls.sh test-pg-verifyfull.sh test-attestation.sh test-fed-write-sig-attestation.sh test-semantic-recall.sh; do
  echo; echo "############ $leg ############"
  ./"$leg" || rc=1
done
echo; echo "############ OVERALL ############"
[ "$rc" -eq 0 ] && echo "ALL LEGS GREEN" || echo "SOME LEGS FAILED (see above)"
exit "$rc"
