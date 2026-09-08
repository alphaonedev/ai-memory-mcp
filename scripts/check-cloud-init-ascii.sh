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
# 1 = a non-ASCII byte found (offender printed), 2 = scanner/usage/self-test failure.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_GLOB="${AI_MEMORY_CLOUDINIT_GLOB:-${HERE}/infra/do-hive/*.tpl}"

mkdir -p "${HERE}/.local-runs"
scratch="$(mktemp -d "${HERE}/.local-runs/cloud-init-ascii.XXXXXX")"
trap '(cd "$HERE" && rm -rf ".local-runs/${scratch##*/}")' EXIT

scan() {
  local found=0 f status
  for f in $1; do
    [ -f "$f" ] || continue
    # Bash supplies literal range endpoints; C locale makes this a byte range.
    # -a also scans NUL-containing files; -n retains offender line numbers.
    if LC_ALL=C grep -na $'[\200-\377]' "$f" >"$scratch/matches"; then
      found=1
      echo "NON-ASCII in $f:" >&2
      cat "$scratch/matches" >&2
    else
      status=$?
      if [ "$status" -ne 1 ]; then
        echo "FAIL: ASCII scanner exited $status for $f" >&2
        return 2
      fi
    fi
  done
  return "$found"
}

if [ "${1:-}" = "--self-test" ]; then
  templates=("${HERE}"/infra/do-hive/*.tpl)
  cp "${templates[0]}" "$scratch/copied.tpl"
  printf '\200' >> "$scratch/copied.tpl"
  printf '\200' > "$scratch/empty-with-byte.tpl"
  printf '#cloud-config\n# en dash: \342\200\223\n' > "$scratch/utf8.tpl"
  for fixture in copied empty-with-byte utf8; do
    status=0
    scan "$scratch/$fixture.tpl" >"$scratch/output" 2>&1 || status=$?
    if [ "$status" -ne 1 ]; then
      cat "$scratch/output" >&2
      echo "SELF-TEST FAIL: $fixture expected detection (exit 1), got $status" >&2
      exit 2
    fi
    echo "SELF-TEST PASS: $fixture non-ASCII detected (exit 1)"
  done
  printf '#cloud-config\n# clean ASCII\t\r\177\000\n' > "$scratch/ok.tpl"
  : > "$scratch/empty.tpl"
  for fixture in ok empty; do
    if scan "$scratch/$fixture.tpl"; then
      echo "SELF-TEST PASS: $fixture ASCII accepted (exit 0)"
    else
      echo "SELF-TEST FAIL: gate rejected $fixture ASCII template" >&2
      exit 2
    fi
  done
  echo "check-cloud-init-ascii self-test OK"
  exit 0
fi

status=0
scan "$TARGET_GLOB" || status=$?
case "$status" in
  0)
    echo "check-cloud-init-ascii: OK (all cloud-init templates are pure ASCII)"
    ;;
  1)
    echo "" >&2
    echo "FAIL (#1880): cloud-init templates must be pure ASCII — a non-ASCII byte" >&2
    echo "makes cloud-init silently discard the config and boot a BARE droplet." >&2
    echo "Replace em-dashes/smart-quotes/etc. with ASCII equivalents." >&2
    ;;
  *)
    echo "FAIL: cloud-init ASCII scan could not complete" >&2
    ;;
esac
exit "$status"
