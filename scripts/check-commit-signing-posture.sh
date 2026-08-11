#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# check-commit-signing-posture.sh — CI posture gate for #2486
# ([control-integrity] "commit-signing posture regressed silently on
# 2026-07-22 and nothing detected it").
#
# THE DEFECT CLASS THIS CLOSES. A host-local `git config user.email` (or
# `user.name`) can silently drift to an identity GitHub cannot bind to the
# enrolled `alphaonedev` account — e.g. `Claude Opus 5 <noreply@anthropic.com>`
# — and every subsequent commit on that host lands under the drifted
# identity. The commit can still carry a cryptographically valid signature
# (the SSH private key on disk is unchanged), so a naive "is this commit
# signed?" check stays green; GitHub reports `unknown_key` because the
# COMMITTER PRINCIPAL the signature is checked against is not the enrolled
# one. #2486's own investigation reproduced this LIVE on the operating
# host (this repo's shared `.git/config` carried exactly that override,
# unset as part of the #2486 fix) — proving the class is not hypothetical
# and can recur on ANY host working this repo, silently, with no gate
# watching for it before this change.
#
# THE RULE. For every commit in a PR's own range (never a GitHub web-flow
# merge/squash artifact — those exist only AFTER merge, outside the PR
# branch's history, and are the separate, explicitly-out-of-scope #2486
# item 3 "merge-mechanism decision"), BOTH must hold or the PR is refused:
#
#   1. The committer email AND the author email are each a principal
#      enrolled in scripts/qc-allowlists/enrolled-commit-signers.txt (an
#      ALLOWLIST of account-bound identities, not a blocklist of known-bad
#      vendor domains — a blocklist can never enumerate every unbound
#      identity an agent's local git config might drift to; this repo's
#      own `sole-authority-operator` rule means exactly ONE identity class
#      is ever legitimate here, so an allowlist is both stricter and
#      simpler).
#   2. `git log --format=%G?` for that commit, verified against THAT SAME
#      registry via `gpg.ssh.allowedSignersFile`, reports exactly `G`
#      (good signature, principal matched). Every other code — `N` (no
#      signature at all), `B` (bad signature), `E` (signature present but
#      unverifiable against the registry — an unenrolled key, INCLUDING a
#      forged claim of an enrolled email backed by a different key), `X`/
#      `Y`/`R` (expired/expired-key/revoked) — is a refusal. This is
#      deliberately the STRICT accept-list of `%G?` values (only `G`), not
#      "anything but `N`": accepting `E`/`B` would let an unenrolled key
#      sign under a spoofed enrolled email and pass, which is precisely
#      the "reports success while doing nothing" shape this repo's #2444
#      class exists to close.
#
# WHAT THIS DOES NOT CLAIM. This gate proves the PR's OWN commits are
# authored+signed by an enrolled identity holding the enrolled private key
# — it does NOT reproduce GitHub's own server-side "Verified" badge
# computation (a separate system, not queried here) and it does NOT touch
# the `required_signatures` branch ruleset, which #2486 separately
# documents as self-satisfying under API squash-merges (see
# .github/branch-protection.yml) and therefore not a control this gate
# can or should stand in for. The squash-merge commit that eventually
# lands on `release/v1.0.0` is produced by GitHub AFTER this check runs
# and is out of scope (#2486 item 3, tracked separately) — this gate's
# job is the PR's SOURCE commits, which is what #2486 calls "the
# load-bearing item".
#
# Exit codes: 0 clean (or non-`pull_request` event, N/A) · 1 violation ·
# 2 usage / self-test failure.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGNERS_FILE_DEFAULT="$REPO_ROOT/scripts/qc-allowlists/enrolled-commit-signers.txt"

# Extracts the set of enrolled principal emails (column 1 of each
# non-comment, non-blank allowed_signers line) from the registry, one per
# output line, lower-cased for a case-insensitive compare (RFC 5321 says
# the local-part MAY be case-sensitive, but this control's threat model is
# "did the identity drift to something obviously unenrolled", not
# mailbox-exact pedantry — a case-only variant of an enrolled address is
# not the attack this gate defends against).
enrolled_principals() {
  local signers_file="$1"
  grep -vE '^[[:space:]]*(#|$)' "$signers_file" | awk '{print tolower($1)}' | sort -u
}

is_enrolled_principal() {
  local email_lc="$1"
  local principals="$2"
  printf '%s\n' "$principals" | grep -qxF "$email_lc"
}

# check_range BASE_SHA HEAD_SHA SIGNERS_FILE REPO_DIR
# Walks every commit in BASE_SHA..HEAD_SHA inside REPO_DIR and prints one
# "VIOLATION: <sha> <reason>" line per failing commit to stdout. Returns 1
# if any violation was found, 0 otherwise (including an empty range).
check_range() {
  local base="$1" head="$2" signers_file="$3" repo_dir="${4:-$REPO_ROOT}"
  local principals violations=0
  principals="$(enrolled_principals "$signers_file")"

  if ! git -C "$repo_dir" rev-parse --verify --quiet "${base}^{commit}" >/dev/null \
    || ! git -C "$repo_dir" rev-parse --verify --quiet "${head}^{commit}" >/dev/null; then
    echo "check-commit-signing-posture: ERROR — cannot resolve range ${base}..${head} (fail-closed)" >&2
    return 1
  fi

  local line sha author_email committer_email sig_status
  while IFS='|' read -r sha author_email committer_email sig_status; do
    [ -z "$sha" ] && continue
    local a_lc c_lc
    a_lc="$(printf '%s' "$author_email" | tr '[:upper:]' '[:lower:]')"
    c_lc="$(printf '%s' "$committer_email" | tr '[:upper:]' '[:lower:]')"

    if ! is_enrolled_principal "$a_lc" "$principals"; then
      echo "VIOLATION: $sha unbound-author-email ($author_email)"
      violations=1
    fi
    if ! is_enrolled_principal "$c_lc" "$principals"; then
      echo "VIOLATION: $sha unbound-committer-email ($committer_email)"
      violations=1
    fi
    if [ "$sig_status" != "G" ]; then
      echo "VIOLATION: $sha signature-not-verified (%G?=$sig_status)"
      violations=1
    fi
  done < <(git -C "$repo_dir" \
    -c "gpg.ssh.allowedSignersFile=$signers_file" \
    -c gpg.format=ssh \
    log --format='%H|%ae|%ce|%G?' "${base}..${head}")

  [ "$violations" -eq 0 ]
}

run_gate() {
  local event_name="${GITHUB_EVENT_NAME:-}"
  if [ "$event_name" != "pull_request" ]; then
    echo "check-commit-signing-posture: N/A — event '$event_name' has no PR commit range to check (this gate scopes to pull_request events only; the PR's own commits were already checked on its pull_request run before merge)."
    return 0
  fi

  local base="${PR_BASE_SHA:-}"
  local head="${PR_HEAD_SHA:-HEAD}"
  if [ -z "$base" ]; then
    echo "check-commit-signing-posture: ERROR — PR_BASE_SHA is unset on a pull_request event (fail-closed)" >&2
    return 1
  fi

  local out
  if out="$(check_range "$base" "$head" "$SIGNERS_FILE_DEFAULT" "$REPO_ROOT")"; then
    echo "check-commit-signing-posture: OK — every commit in ${base}..${head} is an enrolled, signature-verified identity"
    return 0
  else
    echo "check-commit-signing-posture: VIOLATION — one or more commits in ${base}..${head} are not an enrolled, signature-verified identity:" >&2
    echo "$out" >&2
    echo "" >&2
    echo "  Fix: reset the committer/author identity to an account-bound one" >&2
    echo "  enrolled in scripts/qc-allowlists/enrolled-commit-signers.txt" >&2
    echo "  (check for a stray local 'git config user.email' override — this" >&2
    echo "  is the exact #2486 defect class), re-sign, and re-push." >&2
    return 1
  fi
}

self_test() {
  local tmp
  tmp="$REPO_ROOT/.local-runs/check-commit-signing-posture-selftest.$$"
  mkdir -p "$tmp"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  local enrolled_key="$tmp/enrolled_key" rogue_key="$tmp/rogue_key"
  ssh-keygen -q -t ed25519 -N '' -f "$enrolled_key" -C 'selftest-enrolled'
  ssh-keygen -q -t ed25519 -N '' -f "$rogue_key" -C 'selftest-rogue'

  local signers="$tmp/signers.txt"
  {
    echo "# self-test registry"
    printf 'dev@example.test %s\n' "$(cut -d' ' -f1,2 "$enrolled_key.pub")"
  } >"$signers"

  local repo="$tmp/repo"
  mkdir -p "$repo"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.name "Dev"
  git -C "$repo" config user.email "dev@example.test"
  git -C "$repo" config gpg.format ssh
  git -C "$repo" config gpg.ssh.allowedSignersFile "$signers"
  git -C "$repo" config commit.gpgsign false

  echo base >"$repo/f.txt"
  git -C "$repo" add f.txt
  git -C "$repo" commit -q -m "base"
  local base_sha
  base_sha="$(git -C "$repo" rev-parse HEAD)"

  # (a) CLEAN control: enrolled email, signed with the enrolled key. MUST PASS.
  git -C "$repo" config commit.gpgsign true
  git -C "$repo" config user.signingkey "$enrolled_key.pub"
  echo clean >"$repo/f.txt"
  git -C "$repo" add f.txt
  git -C "$repo" commit -q -m "clean: enrolled identity, valid signature"
  local clean_sha
  clean_sha="$(git -C "$repo" rev-parse HEAD)"

  # (b) VIOLATION — unbound email AND unsigned (the #2486 identity-drift
  # shape: a committer identity GitHub cannot bind to the enrolled account,
  # landing with no signature at all).
  git -C "$repo" config commit.gpgsign false
  GIT_AUTHOR_NAME="Claude Opus 5" GIT_AUTHOR_EMAIL="noreply@anthropic.com" \
    GIT_COMMITTER_NAME="Claude Opus 5" GIT_COMMITTER_EMAIL="noreply@anthropic.com" \
    git -C "$repo" commit -q -m "bad: unbound identity, unsigned" --allow-empty \
    --author="Claude Opus 5 <noreply@anthropic.com>"
  local drift_sha
  drift_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" reset -q --hard "$clean_sha"

  # (c) VIOLATION — enrolled email, but ENTIRELY UNSIGNED (isolates the
  # signature check from the email check: proves each fires independently).
  git -C "$repo" config commit.gpgsign false
  git -C "$repo" commit -q -m "bad: enrolled identity, no signature" --allow-empty
  local unsigned_sha
  unsigned_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" reset -q --hard "$clean_sha"

  # (d) VIOLATION — enrolled email CLAIMED, but signed with a ROGUE
  # (non-enrolled) key: proves the gate rejects an identity spoof that a
  # bare "has-a-signature" check would miss.
  git -C "$repo" config commit.gpgsign true
  git -C "$repo" config user.signingkey "$rogue_key.pub"
  git -C "$repo" commit -q -m "bad: enrolled identity, rogue-key signature" --allow-empty
  local rogue_sha
  rogue_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" reset -q --hard "$clean_sha"

  local failed=0

  # (a) clean control MUST pass.
  if ! out="$(check_range "$base_sha" "$clean_sha" "$signers" "$repo")"; then
    echo "self-test FAILED: clean enrolled+signed commit was REJECTED:" >&2
    echo "$out" >&2
    failed=1
  fi

  # (b) identity-drift + unsigned MUST fail, naming BOTH the email and
  # signature violations (proves the two checks are independent, not one
  # masking the other).
  if out="$(check_range "$base_sha" "$drift_sha" "$signers" "$repo" 2>&1)"; then
    echo "self-test FAILED: #2486 identity-drift shape was NOT rejected" >&2
    failed=1
  else
    if ! printf '%s\n' "$out" | grep -q "unbound-committer-email"; then
      echo "self-test FAILED: identity-drift rejection did not name unbound-committer-email:" >&2
      echo "$out" >&2
      failed=1
    fi
    if ! printf '%s\n' "$out" | grep -q "signature-not-verified"; then
      echo "self-test FAILED: identity-drift rejection did not name signature-not-verified:" >&2
      echo "$out" >&2
      failed=1
    fi
  fi

  # (c) enrolled email but unsigned MUST fail on signature alone (email
  # check must NOT fire — proves independence in the other direction).
  if out="$(check_range "$base_sha" "$unsigned_sha" "$signers" "$repo" 2>&1)"; then
    echo "self-test FAILED: unsigned enrolled-identity commit was NOT rejected" >&2
    failed=1
  else
    if ! printf '%s\n' "$out" | grep -q "signature-not-verified"; then
      echo "self-test FAILED: unsigned-commit rejection did not name signature-not-verified:" >&2
      echo "$out" >&2
      failed=1
    fi
    if printf '%s\n' "$out" | grep -q "unbound-.*-email"; then
      echo "self-test FAILED: unsigned-but-enrolled commit incorrectly also flagged an email violation:" >&2
      echo "$out" >&2
      failed=1
    fi
  fi

  # (d) enrolled email claimed, rogue-key signature MUST fail — proves the
  # gate verifies the signature against the REGISTRY, not merely "some
  # signature is present" (the E status: unenrolled key rejects a spoofed
  # enrolled email).
  if out="$(check_range "$base_sha" "$rogue_sha" "$signers" "$repo" 2>&1)"; then
    echo "self-test FAILED: rogue-key signature under a spoofed enrolled email was NOT rejected" >&2
    failed=1
  else
    if ! printf '%s\n' "$out" | grep -q "signature-not-verified"; then
      echo "self-test FAILED: rogue-key rejection did not name signature-not-verified:" >&2
      echo "$out" >&2
      failed=1
    fi
  fi

  # (e) missing/unresolvable range fails CLOSED, not silently passes.
  if check_range "0000000000000000000000000000000000000000" "$clean_sha" "$signers" "$repo" >/dev/null 2>&1; then
    echo "self-test FAILED: an unresolvable base SHA did not fail closed" >&2
    failed=1
  fi

  if [ "$failed" -ne 0 ]; then
    exit 2
  fi
  echo "check-commit-signing-posture self-test OK (clean identity passes; #2486 identity-drift, unsigned-but-enrolled, and rogue-key-spoofed-identity shapes all rejected with the correct named violation; unresolvable range fails closed)"
}

case "${1:-}" in
  --self-test)
    self_test
    ;;
  "")
    run_gate
    ;;
  *)
    echo "usage: $(basename "$0") [--self-test]" >&2
    exit 2
    ;;
esac
