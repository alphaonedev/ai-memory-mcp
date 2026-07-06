#!/usr/bin/env bash
# check-cloud-init-ascii.sh — fail if any DigitalOcean cloud-init template
# contains a non-ASCII byte.
#
# Why (issue #1880): a stray non-ASCII byte (a U+2014 em-dash in a comment,
# whose 0x80 continuation byte the cloud-init YAML parser rejects as
# "unacceptable character #x0080") made `terraform apply` render a
# cloud-config that cloud-init silently DISCARDED — the droplet booted BARE
# (no postgres / AGE / pgvector) with only a `degraded done` status. The
# failure is silent at provision time and only surfaces on SSH triage.
# cloud-config is safest as pure ASCII; this gate keeps it that way.
#
# Scope: infra/do-hive/*.tpl (the templatefile() inputs). Exit 0 = clean,
# 1 = a non-ASCII byte found (offender printed), 2 = usage/self-test failure.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_GLOB="${AI_MEMORY_CLOUDINIT_GLOB:-${HERE}/infra/do-hive/*.tpl}"

scan() {
  local found=0 f
  for f in $1; do
    [ -f "$f" ] || continue
    # grep -P byte class: any byte outside 0x00-0x7F. -n gives line numbers.
    if LC_ALL=C grep -naP '[^\x00-\x7F]' "$f" >/tmp/_cia_$$  2>/dev/null; then
      found=1
      echo "NON-ASCII in $f:" >&2
      sed 's/^/  /' /tmp/_cia_$$ >&2
    fi
  done
  rm -f /tmp/_cia_$$
  return $found
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  # em-dash (U+2014) in a comment — the exact #1880 shape.
  printf '#cloud-config\n# Track E1 \xe2\x80\x94 bootstrap\n' > "$tmp/bad.tpl"
  if scan "$tmp/bad.tpl" 2>/dev/null; then
    echo "SELF-TEST FAIL: gate did not catch a non-ASCII cloud-init template" >&2
    rm -rf "$tmp"; exit 2
  fi
  printf '#cloud-config\n# clean ascii only\n' > "$tmp/ok.tpl"
  if ! scan "$tmp/ok.tpl" 2>/dev/null; then
    echo "SELF-TEST FAIL: gate flagged a clean ASCII template" >&2
    rm -rf "$tmp"; exit 2
  fi
  rm -rf "$tmp"
  echo "check-cloud-init-ascii self-test OK"
  exit 0
fi

if scan "$TARGET_GLOB"; then
  echo "check-cloud-init-ascii: OK (all cloud-init templates are pure ASCII)"
  exit 0
else
  echo "" >&2
  echo "FAIL (#1880): cloud-init templates must be pure ASCII — a non-ASCII byte" >&2
  echo "makes cloud-init silently discard the config and boot a BARE droplet." >&2
  echo "Replace em-dashes/smart-quotes/etc. with ASCII equivalents." >&2
  exit 1
fi
