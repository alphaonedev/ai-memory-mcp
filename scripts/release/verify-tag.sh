#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# verify-tag.sh — release preflight tag verification (#3546).
#
# Before #3546 the release preflight did a SemVer regex and
# `git rev-parse "$TAG^{commit}"` and nothing else, while its job name said
# "tag exists + is annotated". A LIGHTWEIGHT tag, an UNSIGNED tag, or a tag
# signed by a key nobody enrolled all resolved to a commit and the release
# built from it. This script is the check the job name promised:
#
#   1. the tag name is SemVer `v<MAJ>.<MIN>.<PATCH>(-pre)?`;
#   2. `refs/tags/<tag>` is an ANNOTATED tag object (`cat-file -t` == tag),
#      never a lightweight ref straight to a commit;
#   3. the tag object's own headers agree with the ref: `type commit`, a
#      `tag <name>` header equal to the requested tag, and an `object`
#      equal to the peeled commit. A signature covers the headers, not the
#      ref name, so without the header check a legitimately signed tag
#      object for v0.9.0 could be re-pointed under refs/tags/v1.0.0;
#   4. the signature is an SSH signature (`-----BEGIN SSH SIGNATURE-----`),
#      so it can only be judged against the pinned allowlist below and never
#      against whatever GPG keyring the runner happens to carry;
#   5. `git verify-tag` succeeds with `gpg.ssh.allowedSignersFile` pointed
#      at the RELEASE signer allowlist (operator key only), and reports a
#      Good signature.
#
# On success it prints `sha=<peeled commit>` and `tag_object=<tag object
# id>`, and appends the same two lines to $GITHUB_OUTPUT when that is set.
# `tag_object` is what the publish jobs re-assert against the remote right
# before upload (scripts/release/assert-tag-unmoved.sh): a moved tag has a
# different tag object even when an attacker re-signs it.
#
# TRUST ANCHOR. The allowlist and this script must come from a checkout of
# the protected branch (github.workflow_sha), never from the tree the tag
# points at. A tag that pointed at a commit carrying its own `exit 0`
# verifier, or an allowlist with the attacker's key appended, would
# otherwise approve itself. release.yml enforces that; the fixture harness
# scripts/test/test-release-hardening.sh pins it structurally.
#
# Usage: verify-tag.sh --repo <dir> --tag <tag> --signers <allowed_signers>
# Exit codes: 0 verified · 1 refused · 2 usage error.

set -euo pipefail

SEMVER_TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.\-]+)?$'
SSH_SIG_HEADER='-----BEGIN SSH SIGNATURE-----'

refuse() {
  echo "verify-tag: REFUSED — $*" >&2
  exit 1
}

usage() {
  echo "usage: verify-tag.sh --repo <dir> --tag <tag> --signers <allowed_signers>" >&2
  exit 2
}

repo=""
tag=""
signers=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) repo="${2:-}"; shift 2 ;;
    --tag) tag="${2:-}"; shift 2 ;;
    --signers) signers="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$repo" ] && [ -n "$tag" ] && [ -n "$signers" ] || usage

# 1. SemVer. Refuse before the name reaches any git plumbing.
if [[ ! "$tag" =~ $SEMVER_TAG_RE ]]; then
  refuse "tag '$tag' does not match SemVer v<MAJ>.<MIN>.<PATCH>(-pre)?"
fi

# The allowlist must exist and name at least one principal. This is an
# explicit assertion, not something left to fall out of a later command's
# exit status (the #2486 L5 lesson: an empty registry must never read as
# "nothing to check").
if [ ! -f "$signers" ]; then
  refuse "release signer allowlist $signers is missing (fail-closed)"
fi
if [ -z "$(grep -vE '^[[:space:]]*(#|$)' "$signers" || true)" ]; then
  refuse "release signer allowlist $signers has zero enrolled keys (fail-closed)"
fi

ref="refs/tags/$tag"
if ! git -C "$repo" rev-parse --verify --quiet "$ref" >/dev/null; then
  refuse "$ref does not exist in $repo"
fi

# 2. Annotated, not lightweight.
kind="$(git -C "$repo" cat-file -t "$ref")"
if [ "$kind" != "tag" ]; then
  refuse "$ref is a lightweight tag (points at a $kind, not a tag object); a release tag must be annotated and signed"
fi

tag_object="$(git -C "$repo" rev-parse "$ref")"
body="$(git -C "$repo" cat-file -p "$tag_object")"

# 3. The tag object's headers must agree with the ref. Headers end at the
# first blank line.
header_value() {
  printf '%s\n' "$body" | awk -v k="$1" 'NF == 0 { exit } $1 == k { sub(/^[^ ]+ /, ""); print; exit }'
}
obj_type="$(header_value type)"
obj_name="$(header_value tag)"
obj_target="$(header_value object)"
if [ "$obj_type" != "commit" ]; then
  refuse "tag object $tag_object has type '$obj_type', expected 'commit' (a tag of a tag is not a release)"
fi
if [ "$obj_name" != "$tag" ]; then
  refuse "tag object $tag_object names itself '$obj_name' but sits at $ref (a signed tag object re-pointed under another name)"
fi
sha="$(git -C "$repo" rev-parse "$ref^{commit}")"
if [ "$obj_target" != "$sha" ]; then
  refuse "tag object $tag_object targets '$obj_target' but $ref peels to $sha"
fi

# 4. SSH signature only.
if ! printf '%s\n' "$body" | grep -qxF -- "$SSH_SIG_HEADER"; then
  refuse "$ref carries no SSH signature; release tags are signed with an enrolled SSH key (git tag -s with gpg.format=ssh)"
fi

# 5. Verify against the pinned allowlist, with no ambient git config able to
# redirect it (-c overrides any repo/global setting for this invocation).
if ! verify_out="$(git -C "$repo" \
  -c gpg.format=ssh \
  -c "gpg.ssh.allowedSignersFile=$signers" \
  verify-tag "$tag" 2>&1)"; then
  refuse "signature on $ref does not verify against $signers: $verify_out"
fi
if ! printf '%s\n' "$verify_out" | grep -q 'Good "git" signature'; then
  refuse "git verify-tag accepted $ref without a Good signature line: $verify_out"
fi

echo "verify-tag: OK — $ref is annotated, SSH-signed by an enrolled release key, and peels to $sha"
echo "sha=$sha"
echo "tag_object=$tag_object"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "sha=$sha"
    echo "tag_object=$tag_object"
  } >>"$GITHUB_OUTPUT"
fi
