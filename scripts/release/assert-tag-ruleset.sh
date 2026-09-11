#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# assert-tag-ruleset.sh — refuse to release unless an ACTIVE repository
# ruleset protects release tags from being moved or deleted (#3546).
#
# The live repository had exactly one ruleset, targeting branches;
# `GET tags/protection` was a 404; nothing stopped a tag moving between
# the preflight job and a publish job. Creating the ruleset is a repository
# admin action (it is not something a workflow can or should grant itself),
# so this script does not create anything: it reads the rulesets and
# refuses when none of them is
#
#   * `target: tag`, `enforcement: active`,
#   * scoped to `refs/tags/v*` (or `~ALL`) in `conditions.ref_name.include`,
#   * carrying BOTH a `deletion` rule and an `update` rule.
#
# Usage: assert-tag-ruleset.sh --repo OWNER/NAME
#        assert-tag-ruleset.sh --from-dir DIR   (fixtures: DIR/list.json plus
#                                                DIR/<id>.json per ruleset)
# Exit codes: 0 protected · 1 refused · 2 usage / API error.

set -euo pipefail

usage() {
  echo "usage: assert-tag-ruleset.sh --repo OWNER/NAME | --from-dir DIR" >&2
  exit 2
}

repo=""
from_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) repo="${2:-}"; shift 2 ;;
    --from-dir) from_dir="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$repo" ] || [ -n "$from_dir" ] || usage

fetch_list() {
  if [ -n "$from_dir" ]; then cat "$from_dir/list.json"; else gh api "repos/$repo/rulesets?per_page=100"; fi
}
fetch_one() {
  if [ -n "$from_dir" ]; then cat "$from_dir/$1.json"; else gh api "repos/$repo/rulesets/$1"; fi
}

if ! list="$(fetch_list)"; then
  echo "assert-tag-ruleset: REFUSED — could not list rulesets (fail-closed)" >&2
  exit 2
fi

ids="$(printf '%s' "$list" | jq -r '.[] | select(.target == "tag" and .enforcement == "active") | .id')"
for id in $ids; do
  if ! detail="$(fetch_one "$id")"; then
    echo "assert-tag-ruleset: REFUSED — could not read ruleset $id (fail-closed)" >&2
    exit 2
  fi
  if printf '%s' "$detail" | jq -e '
      (.target == "tag") and (.enforcement == "active")
      and ((.conditions.ref_name.include // []) | any(. == "refs/tags/v*" or . == "~ALL"))
      and ([.rules[]?.type] | (index("deletion") != null) and (index("update") != null))
    ' >/dev/null; then
    name="$(printf '%s' "$detail" | jq -r '.name')"
    echo "assert-tag-ruleset: OK — active tag ruleset $id ('$name') forbids update and deletion of refs/tags/v*"
    exit 0
  fi
done

echo "assert-tag-ruleset: REFUSED — no active ruleset targets refs/tags/v* with both 'update' and 'deletion' rules. A repository admin must create it before any release (payload: .github/rulesets/release-tags.json; apply with: gh api -X POST repos/<owner>/<repo>/rulesets --input .github/rulesets/release-tags.json)." >&2
exit 1
