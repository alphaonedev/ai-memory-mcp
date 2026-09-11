#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# assert-tag-unmoved.sh — re-assert, immediately before a publish step, that
# the release tag on the remote is still the tag object preflight verified
# (#3546).
#
# Pinning every checkout to the preflight SHA makes a tag move irrelevant to
# what gets BUILT. It does not make it irrelevant to what gets PUBLISHED:
# `softprops/action-gh-release` and friends attach assets by `tag_name`, so a
# tag moved between preflight and upload would carry artifacts built from one
# tree onto a release page that names another. This script closes that gap:
# it reads the remote ref and refuses unless
#
#   * refs/tags/<tag> resolves to exactly the tag object preflight recorded
#     (a re-signed, re-pointed tag is a DIFFERENT tag object, so this also
#     catches an attacker who holds a signing key), and
#   * refs/tags/<tag>^{} peels to exactly the commit preflight recorded.
#
# Usage: assert-tag-unmoved.sh --remote <url|path> --tag <tag>
#                              --tag-object <id> --sha <commit>
# Exit codes: 0 unmoved · 1 moved/missing · 2 usage error.

set -euo pipefail

usage() {
  echo "usage: assert-tag-unmoved.sh --remote <url|path> --tag <tag> --tag-object <id> --sha <commit>" >&2
  exit 2
}

remote=""
tag=""
want_object=""
want_sha=""
while [ $# -gt 0 ]; do
  case "$1" in
    --remote) remote="${2:-}"; shift 2 ;;
    --tag) tag="${2:-}"; shift 2 ;;
    --tag-object) want_object="${2:-}"; shift 2 ;;
    --sha) want_sha="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$remote" ] && [ -n "$tag" ] && [ -n "$want_object" ] && [ -n "$want_sha" ] || usage

ref="refs/tags/$tag"
if ! listing="$(git ls-remote "$remote" "$ref" "$ref^{}")"; then
  echo "assert-tag-unmoved: REFUSED — could not list $ref on $remote" >&2
  exit 1
fi

got_object="$(printf '%s\n' "$listing" | awk -v r="$ref" '$2 == r { print $1 }')"
got_sha="$(printf '%s\n' "$listing" | awk -v r="$ref^{}" '$2 == r { print $1 }')"

if [ -z "$got_object" ]; then
  echo "assert-tag-unmoved: REFUSED — $ref no longer exists on $remote" >&2
  exit 1
fi
if [ "$got_object" != "$want_object" ]; then
  echo "assert-tag-unmoved: REFUSED — $ref on $remote is tag object $got_object, but preflight verified $want_object (the tag moved after verification)" >&2
  exit 1
fi
if [ "$got_sha" != "$want_sha" ]; then
  echo "assert-tag-unmoved: REFUSED — $ref on $remote peels to '${got_sha:-<none>}', but preflight verified $want_sha" >&2
  exit 1
fi

echo "assert-tag-unmoved: OK — $ref on $remote is still $want_object -> $want_sha"
