#!/usr/bin/env bash
# Destroy the ai-memory perf environment. Explicit, never automatic.
# These droplets bill hourly; leaving them running is the only real cost risk.
set -euo pipefail
TAG="ai-memory-perf"
command -v doctl >/dev/null || { echo "doctl not installed" >&2; exit 1; }

echo "About to DESTROY every droplet tagged '$TAG':"
doctl compute droplet list --tag-name "$TAG" --format Name,PublicIPv4,Size,Created --no-header || true
echo
read -r -p "Type DESTROY to confirm: " ans
[ "$ans" = "DESTROY" ] || { echo "aborted"; exit 1; }

doctl compute droplet delete --tag-name "$TAG" --force
echo "droplets destroyed."
echo "NOTE: the VPC is retained (free, and reusable). Remove manually if you want it gone:"
echo "  doctl vpcs list --format ID,Name --no-header | awk '\$2==\"ai-memory-perf-vpc\"{print \$1}'"
