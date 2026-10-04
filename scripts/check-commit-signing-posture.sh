#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# check-commit-signing-posture.sh — CI posture gate for #2486
# ([control-integrity] "commit-signing posture regressed silently on
# 2026-07-22 and nothing detected it"), repaired for #5045 / #5046 / #5047.
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
# watching for it before this change. The host-config half of the SAME
# class is still open as #5048 and is deliberately NOT touched here (a
# shared `.git/config` is read by ~200 concurrent worktrees; mutating it
# underneath them mid-campaign is the cross-lane hazard #856 exists to
# prevent).
#
# THE RULE. Over the PR's own range — `merge-base(BASE, HEAD)..HEAD` — every
# commit is EVALUATED except a merge that satisfies the content-neutral
# web-flow exemption described below, and BOTH of the following must hold for
# every EVALUATED commit or the PR is refused:
#
#   1. The committer email AND the author email are each a principal
#      enrolled in scripts/qc-allowlists/enrolled-commit-signers.txt (an
#      ALLOWLIST of account-bound identities, not a blocklist of known-bad
#      vendor domains — a blocklist can never enumerate every unbound
#      identity an agent's local git config might drift to; this repo's
#      own `sole-authority-operator` rule means exactly ONE identity class
#      is ever legitimate here, so an allowlist is both stricter and
#      simpler).
#   2. `git log --format=%G?` reports exactly `G` (good signature,
#      principal matched) AND `git log --format=%GF` — the fingerprint of
#      the key that ACTUALLY VERIFIED — is a member of the PINNED
#      FINGERPRINT SET (see "THE PINNED FINGERPRINT SET" below). Every
#      other `%G?` code — `N` (no signature at all), `B` (bad signature),
#      `E` (signature present but unverifiable), `U` (valid signature,
#      key not trusted), `X`/`Y`/`R` (expired/expired-key/revoked) — is a
#      refusal. This is deliberately the STRICT accept-list of `%G?`
#      values (only `G`), not "anything but `N`": accepting `E`/`B` would
#      let an unenrolled key sign under a spoofed enrolled email and pass,
#      which is precisely the "reports success while doing nothing" shape
#      this repo's #2444 class exists to close.
#
# THE WEB-FLOW MERGE EXEMPTION (#5046, NARROWED BY #5065). This gate's rule
# has ALWAYS been scoped to the PR's own source commits and never to a GitHub
# web-flow merge/squash artifact — but before #5046 that scope was DOCUMENTED
# ONLY, never implemented, so the gate refused 8 two-parent web-flow merge
# commits for `unbound-committer-email` (committer `GitHub
# <noreply@github.com>`, which is not and must not be an enrolled principal).
# Unimplemented documented behavior is docs-drift, a real defect under this
# repo's prime directive.
#
# #5046's FIRST implementation was a blanket `--no-merges`, and that was too
# wide by two INDEPENDENT measures. Both were measured, not argued, and the
# remedy below was decided by `5-agent vote (4d3ea1c5)` — OPTION B, 4-1,
# unanimous on substance:
#
#   1. It is not the scope the header documents. Measured on
#      `4fff967ce..6e3f6066b`: 487 commits = 386 non-merge + 101 merges (all
#      exactly two parents, zero octopus), so `--no-merges` exempted 101
#      commits in order to clear 8. The other 93 are LOCAL
#      `Justin@alpha-one.mobi` merges exempt purely for having two parents —
#      nothing to do with web flow. Narrowing to the web-flow committer costs
#      ZERO refusals (all 93 report `%G? = G` under the enrolled SSH
#      fingerprint and would have PASSED had they been scanned) and raises
#      coverage from 386/487 to 479/487.
#   2. `--no-merges` is content-blind, and so is an identity-only narrowing.
#      `GIT_COMMITTER_NAME` / `GIT_COMMITTER_EMAIL` are plain environment
#      variables — no key, no privilege, no config write — and
#      `git commit-tree <ARBITRARY-TREE> -p p1 -p p2` points a two-parent
#      merge at ANY tree its author chooses. Measured on the constructed
#      merge `31f7610477`: a file ABSENT from both parents
#      (`git cat-file -e p1:backdoor.txt` and `p2:backdoor.txt` each rc=128)
#      is PRESENT in the merge's recorded tree and in `ls-tree -r HEAD`,
#      while `git log --no-merges BASE..EVIL` lists only the two parents. So
#      content existing in NEITHER parent and in NO scanned commit lands
#      through an exemption that tests identity alone.
#
# THE EXEMPTION PREDICATE. A merge is exempt if and only if ALL THREE hold:
#
#   (1) its COMMITTER email is the GitHub web-flow identity
#       (WEBFLOW_COMMITTER_EMAIL below), AND
#   (2) `%P` names EXACTLY TWO parents — an octopus merge is NEVER exempt,
#       because `merge-tree --write-tree` is a two-parent operation and a
#       third parent's content would go unchecked, AND
#   (3) its RECORDED tree (`%T`) is identical to
#       `git merge-tree --write-tree p1 p2`, the clean automerge of its own
#       two parents.
#
# Every other merge is scanned under the normal rule above — including every
# local `--no-ff` merge and every conflict-resolving merge.
#
# WHY (3) IS THE LOAD-BEARING TERM. (1) and (2) are both forgeable by anyone
# who can set an environment variable; (3) is the only term an attacker
# cannot set, and it is what makes the exemption CONTENT-NEUTRAL. Every byte
# of an exempt merge's tree derives mechanically from two parents that this
# same walk already scanned (measured: of the 202 parents of the 101 in-range
# merges, ZERO are outside the scanned set), so an exempt merge can introduce
# no content that nothing reviewed. The forgeable string match is not
# eliminated — it is made HARMLESS, which is the property this gate actually
# protects. Precedent for a content check inside a gate, copied rather than
# invented: `scripts/check_promotion_geometry.py:142` already runs
# `git merge-tree --write-tree`, and `scripts/check-declaration-hash.sh:66-70`
# recomputes a sha256 and refuses on inequality with no identity involved.
#
# THE FALSE-REFUSAL COST IS MEASURED, NOT ASSUMED: 0 of 382. Every web-flow
# merge in all reachable history reproduces its recorded tree under
# `merge-tree --write-tree` — including 18 that touched `CHANGELOG.md`, which
# carries `merge=union` in `.gitattributes`, and 1 with renames: zero DIFF,
# zero CONFLICT. Runtime is 0.043s per merge, 4.4s for all 101. If git's
# merge resolution ever drifts, a formerly tree-equal merge falls to the
# NORMAL rule and is REFUSED — fail-closed, never fail-open. The remedy on
# that day is the capability probe below plus this comment trail, NEVER a
# wider exemption.
#
# WHY GITHUB'S WEB-FLOW KEY IS STILL NOT PINNED — `B5690EEEBB952194`,
# REJECTED 5-0 in the same vote, on two independent grounds. The 8 web-flow
# merges in the cohort are NOT unsigned: all 8 carry an OpenPGP signature by
# that key and read `%G? = E` only because it is not enrolled. (a) Pinning it
# would extend this repo's sole-authority trust boundary to a third-party key
# whose continued ownership no self-test can ever prove. (b) Without
# importing the key material the pin would be VACUOUS anyway, because `%GK`
# is read from the UNVERIFIED signature packet: measured, a forged evil merge
# with that `gpgsig` block grafted on reads
# `E | B5690EEEBB952194 | noreply@github.com` — byte-identical to the real
# cohort on every field. Tree-equality is what substitutes for the key pin.
# NOTE this says NOTHING about the `%GF` pin for ENROLLED signers below: that
# is a different mechanism, it is unaffected, and it stays exactly as it is.
#
# "CANNOT COMPUTE" IS NEVER "EXEMPT" — THE CAPABILITY PROBE IS MANDATORY.
# The CI runner is bare `ubuntu-latest` with no container and no git pin
# (.github/workflows/c8-precheck.yml), so `merge-tree --write-tree` is not
# version-pinned. assert_merge_tree_usable runs a HERMETIC known-clean
# three-commit merge before the walk and requires rc=0, exactly ONE 40-hex
# line, a resolvable tree object, and the MERGED content of both sides;
# anything else is exit 2 (INOPERATIVE). There is deliberately no `|| true`
# and no `2>/dev/null` anywhere on that path — a missing subcommand fails
# LOUD (rc=129 plus usage) and a bad rev yields rc=1 with empty stdout, and
# both must reach the operator as "the gate could not do its job", never as a
# silent exemption. Sibling precedents for the enclosing range shape:
# check-cert-expiry.sh, check-shared-namespace-claims.sh,
# check-count-assertion-declared.sh.
#
# A "exclude commits already reachable from the protected branch"
# predicate was considered and REJECTED, measured:
# `git rev-list --left-right --count origin/release/v1.0.0...HEAD` = `0 487`
# on the #5045 cohort — it excludes ZERO commits. A no-op predicate added
# to a gate with no non-vacuity floor is how #2444 gates are born.
#
# THE PINNED FINGERPRINT SET. git dispatches signature verification on the
# signature TYPE IN THE COMMIT OBJECT (`gpgsig -----BEGIN PGP SIGNATURE-----`
# vs `-----BEGIN SSH SIGNATURE-----`); `gpg.format` does NOT override that
# dispatch. So this repo has TWO verification paths and needs TWO pins,
# unioned into ONE accept test so that neither path can be widened without
# breaking the other path's self-tests too:
#
#   * SSH half — the SHA256 fingerprint of every key in
#     enrolled-commit-signers.txt, derived with `ssh-keygen -lf`. `%GF` on
#     the SSH path is that exact `SHA256:<base64>` string (base64, so it is
#     compared CASE-SENSITIVELY).
#   * OpenPGP half — every 40-hex fingerprint pinned in
#     enrolled-gpg-commit-signers.txt, whose public key material lives in
#     enrolled-gpg-commit-signers.asc. This is #5045: an OpenPGP-signed
#     commit is verified against the OpenPGP keyring, which on a stock CI
#     runner is EMPTY, so `%G?` is `E` and the gate refused 67 commits the
#     operator legitimately signed. The remedy is a HERMETIC, job-scoped
#     GNUPGHOME built inside this script (never the ambient runner keyring,
#     never a live GitHub API call) holding exactly the enrolled key.
#
# WHY THE `%GF` PIN IS LOAD-BEARING, AND WHY NOT `%GK`. Importing the
# operator's key alone would be a gate that reports success while proving
# nothing: ANY key merely present in the keyring with ownertrust also
# yields `%G? = G`, so trust would silently become "whatever is in the
# runner keyring". `%GF` is only ever populated for a signature that
# ACTUALLY verified, so pinning it closes that. `%GK` must NEVER be pinned:
# it is read from the UNVERIFIED signature packet, is populated even against
# an EMPTY keyring, and is populated on commits whose `%GF` is empty — a
# `%GK` pin is forgeable. Both facts are measured evidence on the #5045
# cohort. The self-test's rogue-key-in-the-SAME-keyring case is the only
# thing that catches a future edit dropping the `%GF` branch while keeping
# the keyring import; it must never be deleted.
#
# THE NON-VACUITY FLOOR (#5047, REBUILT FOR #5065). Before #5047 an EMPTY
# range PASSED: the walk simply found nothing and reported OK — a gate that
# reports success while scanning nothing, with no self-test case covering it
# (#2444 shape, inside the very gate that exists to close that class). Zero
# commits EVALUATED is a FAIL (exit 2) with a diagnostic naming the resolved
# base and head SHAs and whether each ref resolved. Siblings that already
# carry the floor: check-sdk-tls-scheme.sh, check-docs-vs-ssot.sh.
#
# #5047's first implementation counted NON-MERGE commits, which said nothing
# about merges because `--no-merges` had already dropped them. Now that
# merges ARE evaluated, the floor counts EVALUATED commits with EXEMPTED
# merges EXCLUDED, and reports all three numbers on the OK line:
# `SCANNED: N commits (M merges evaluated, X merges exempted content-neutral
# web-flow)`. Excluding exemptions from the count is the load-bearing half: an
# exemption is never evidence that the rule was applied, so a range
# consisting ENTIRELY of exempt web-flow merges still fails closed at exit 2
# rather than passing on a count of zero.
#
# WHAT THIS DOES NOT CLAIM. This gate proves the PR's OWN commits are
# authored+signed by an enrolled identity holding an enrolled private key
# — it does NOT reproduce GitHub's own server-side "Verified" badge
# computation (a separate system, not queried here), it does NOT prove
# which GitHub *account* holds a pinned key (a public key carries no
# identity of its own; account binding is the operator's out-of-band
# enrollment record, reviewed as a PR diff to the two registries), and it
# does NOT touch the `required_signatures` branch ruleset, which #2486
# separately documents as self-satisfying under API squash-merges (see
# .github/branch-protection.yml) and therefore not a control this gate
# can or should stand in for. The squash-merge commit that eventually
# lands on `release/v1.0.0` is produced by GitHub AFTER this check runs
# and is out of scope (#2486 item 3, tracked separately) — this gate's
# job is the PR's SOURCE commits, which is what #2486 calls "the
# load-bearing item". This job also remains a DECLARED-BUT-NOT-REQUIRED
# status check (scripts/qc-allowlists/required-contexts-not-required.txt);
# promoting it is the operator-sequenced #3554 lockstep, not this script.
#
# Exit codes: 0 clean (or non-`pull_request` event, N/A) · 1 a commit in
# range violated the rule · 2 the gate could not do its job and refuses to
# report PASS (usage error, self-test failure, missing/zero-principal
# registry, unresolvable range, hermetic-keyring setup failure, or ZERO
# commits scanned).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGNERS_FILE_DEFAULT="$REPO_ROOT/scripts/qc-allowlists/enrolled-commit-signers.txt"
GPG_SIGNERS_FILE_DEFAULT="$REPO_ROOT/scripts/qc-allowlists/enrolled-gpg-commit-signers.txt"
GPG_PUBKEY_FILE_DEFAULT="$REPO_ROOT/scripts/qc-allowlists/enrolled-gpg-commit-signers.asc"

# The GitHub web-flow committer identity — the ONLY committer identity under
# which a merge can be exempted (#5065), and term (1) of the three-term
# exemption predicate documented in the header. It is deliberately NOT an
# enrolled principal and must never become one: it is a shared GitHub-side
# identity, not an account-bound operator key, which is exactly why the
# exemption also requires the content term (3). Compared lower-cased, like
# every other identity in this gate.
WEBFLOW_COMMITTER_EMAIL='noreply@github.com'

# One per-process scratch root, under the project-local .local-runs/ (project
# HARD RULE: never /tmp, never any tmpfs), removed by a single EXIT trap so
# neither the hermetic keyring nor the self-test fixtures can outlive the run.
GATE_SCRATCH_ROOT="$REPO_ROOT/.local-runs/check-commit-signing-posture.$$"
cleanup_gate_scratch() {
  if [ -n "${GATE_SCRATCH_ROOT:-}" ] && [ -d "$GATE_SCRATCH_ROOT" ]; then
    rm -rf "$GATE_SCRATCH_ROOT"
  fi
  return 0
}
trap cleanup_gate_scratch EXIT

# Extracts the set of enrolled principal emails (column 1 of each
# non-comment, non-blank allowed_signers line) from the registry, one per
# output line, lower-cased for a case-insensitive compare (RFC 5321 says
# the local-part MAY be case-sensitive, but this control's threat model is
# "did the identity drift to something obviously unenrolled", not
# mailbox-exact pedantry — a case-only variant of an enrolled address is
# not the attack this gate defends against).
enrolled_principals() {
  local signers_file="$1"
  awk '/^[[:space:]]*(#|$)/ { next } { print tolower($1) }' "$signers_file" | sort -u
}

# enrolled_ssh_fingerprints SIGNERS_FILE — the `SHA256:<base64>` fingerprint
# of every enrolled SSH public key, derived with ssh-keygen(1): exactly the
# string git reports as `%GF` when it verifies an SSH signature against this
# same registry. Derived, never hand-maintained: a hand-typed mirror of a key
# already in the file is a second place to drift.
#
# Deliberately permissive on the derivation step (`|| true`) and strict on the
# RESULT: the explicit non-empty assertion in assert_pinned_fingerprints_usable
# is where the fail-closed property lives, rather than relying on a pipeline's
# incidental exit status (the same discipline assert_registry_usable documents).
enrolled_ssh_fingerprints() {
  local signers_file="$1"
  {
    awk '/^[[:space:]]*(#|$)/ { next }
         { $1 = ""; sub(/^[[:space:]]+/, ""); print }' "$signers_file" \
      | ssh-keygen -lf - 2>/dev/null || true
  } | awk '$2 ~ /^SHA256:/ { print $2 }' | sort -u
}

# enrolled_gpg_fingerprints GPG_SIGNERS_FILE — column 1 of every non-comment,
# non-blank line, upper-cased, kept only when it is exactly 40 hex characters.
# A malformed line is NOT a pin; if that leaves zero fingerprints the gate
# fails closed via assert_gpg_registry_usable.
enrolled_gpg_fingerprints() {
  local gpg_signers_file="$1"
  awk '/^[[:space:]]*(#|$)/ { next }
       { fpr = toupper($1); if (fpr ~ /^[0-9A-F]{40}$/) print fpr }' \
    "$gpg_signers_file" | sort -u
}

# pinned_fingerprints SIGNERS_FILE GPG_SIGNERS_FILE — the ONE accept set:
# the union of the SSH half and the OpenPGP half. Unioned on purpose: with a
# single pin covering both paths, an edit that drops the `%GF` check cannot
# quietly widen only the OpenPGP path — it breaks every SSH self-test case as
# well, which is what makes the widening tamper-evident.
pinned_fingerprints() {
  local signers_file="$1" gpg_signers_file="$2"
  {
    enrolled_ssh_fingerprints "$signers_file"
    enrolled_gpg_fingerprints "$gpg_signers_file"
  } | sort -u
}

# assert_registry_usable SIGNERS_FILE — EXPLICIT fail-closed guard for a
# missing or empty enrolled-signer registry. This is deliberately NOT left
# to fall out incidentally from `set -e`/`pipefail` reacting to grep's
# no-match exit status inside `enrolled_principals` (Fable review finding
# L5, #2486): that property was real today but ACCIDENTAL — a future
# refactor of `enrolled_principals` (e.g. `local principals=$(...)`, which
# swallows the command-substitution exit status per bash's own documented
# behavior, or an errant `|| true`) could silently flip a missing/empty
# registry from "every commit rejected" to "every commit accepted", with
# no test catching the regression because nothing asserted the property
# directly. This function is the direct, explicit, self-tested assertion:
# it is the ONLY place this gate's fail-closed-on-missing-registry
# property is proven, independent of how `enrolled_principals` is
# implemented.
assert_registry_usable() {
  local signers_file="$1"
  if [ ! -f "$signers_file" ]; then
    echo "check-commit-signing-posture: ERROR — enrolled-signers registry $signers_file is missing (fail-closed)" >&2
    return 1
  fi
  local principals
  principals="$(enrolled_principals "$signers_file")"
  if [ -z "$principals" ]; then
    echo "check-commit-signing-posture: ERROR — enrolled-signers registry $signers_file has zero enrolled principals (fail-closed)" >&2
    return 1
  fi
  return 0
}

# assert_gpg_registry_usable GPG_SIGNERS_FILE — the same explicit fail-closed
# guard for the OpenPGP fingerprint registry (#5045). A missing file or a file
# with zero well-formed 40-hex fingerprints is a refusal, never a pass.
assert_gpg_registry_usable() {
  local gpg_signers_file="$1"
  if [ ! -f "$gpg_signers_file" ]; then
    echo "check-commit-signing-posture: ERROR — enrolled OpenPGP fingerprint registry $gpg_signers_file is missing (fail-closed)" >&2
    return 1
  fi
  local fprs
  fprs="$(enrolled_gpg_fingerprints "$gpg_signers_file")"
  if [ -z "$fprs" ]; then
    echo "check-commit-signing-posture: ERROR — enrolled OpenPGP fingerprint registry $gpg_signers_file has zero pinned fingerprints (fail-closed)" >&2
    return 1
  fi
  return 0
}

# assert_pinned_fingerprints_usable PINNED — the union must be non-empty AND
# must carry at least one fingerprint from EACH half, so losing one path's pin
# can never degrade into "the other path still passes, nothing noticed".
assert_pinned_fingerprints_usable() {
  local pinned="$1"
  if [ -z "$pinned" ]; then
    echo "check-commit-signing-posture: ERROR — the pinned fingerprint set is EMPTY; no commit could ever be accepted and no key is pinned (fail-closed)" >&2
    return 1
  fi
  if ! grep -qE '^SHA256:' <<<"$pinned"; then
    echo "check-commit-signing-posture: ERROR — the pinned fingerprint set has no SSH (SHA256:) fingerprint; the SSH half of the pin was lost (fail-closed)" >&2
    return 1
  fi
  if ! grep -qE '^[0-9A-F]{40}$' <<<"$pinned"; then
    echo "check-commit-signing-posture: ERROR — the pinned fingerprint set has no OpenPGP (40-hex) fingerprint; the OpenPGP half of the pin was lost (fail-closed)" >&2
    return 1
  fi
  return 0
}

is_enrolled_principal() {
  local email_lc="$1"
  local principals="$2"
  # Pipe-free (#3608 / #2414): `printf | grep -qx` under pipefail turns a
  # first-line HIT into a miss when grep -q closes the pipe (false
  # unbound-committer-email on an enrolled principal).
  grep -qxF "$email_lc" <<<"$principals"
}

# is_pinned_fingerprint FPR PINNED — exact membership in the pinned set.
# An SSH `SHA256:<base64>` fingerprint is compared case-SENSITIVELY (base64
# is case-significant); an OpenPGP 40-hex fingerprint is additionally retried
# upper-cased, because hex case carries no information. An empty `%GF` is
# never a member (that is the "nothing actually verified" shape).
is_pinned_fingerprint() {
  local fpr="$1" pinned="$2"
  if [ -z "$fpr" ]; then
    return 1
  fi
  if grep -qxF "$fpr" <<<"$pinned"; then
    return 0
  fi
  if [[ "$fpr" =~ ^[0-9A-Fa-f]{40}$ ]]; then
    local fpr_uc
    fpr_uc="$(printf '%s' "$fpr" | tr '[:lower:]' '[:upper:]')"
    if grep -qxF "$fpr_uc" <<<"$pinned"; then
      return 0
    fi
  fi
  return 1
}

# prepare_hermetic_gnupghome GPG_PUBKEY_FILE GPG_SIGNERS_FILE DEST
#
# Builds a HERMETIC, job-scoped OpenPGP keyring at DEST and leaves it holding
# exactly the enrolled key material, with ultimate ownertrust granted to
# EXACTLY the fingerprints pinned in GPG_SIGNERS_FILE. The ambient runner
# keyring is never read and never written; no network call is made.
#
# Why ownertrust is set at all (measured, #5045): a bare `gpg --import` of a
# public key yields `%G? = U` ("good signature, unknown validity"), not `G`,
# because `%G?` folds gpg's trust model in. Granting ultimate trust to the
# pinned fingerprints is the mechanical form of "this key is hand-enrolled
# from operator custody", and it is granted ONLY to the pinned fingerprints:
# a key that arrives in the `.asc` but is absent from the pinned registry
# gets no ownertrust and so reads `U`, not `G`.
#
# THE SCOPE OF THAT SECOND LAYER, STATED EXACTLY (#5065 N4). The sentence
# above is true of a PUBLIC-ONLY import, which is the only shape this
# function builds in production — it imports `.asc` public key material and
# never a secret key. It is NOT a general property of gpg: a key whose
# SECRET half is in the keyring is implicitly ultimately trusted and yields
# `%G? = G` with no `--import-ownertrust` grant at all. The self-test's own
# `5065-merge-signed-by-unpinned-key` cell is precisely that shape — the
# rogue key is created with `gpg --quick-generate-key` inside the self-test
# GNUPGHOME, so its secret is present — and its shape guard asserts the
# signature reads `%G? = G` while the fingerprint is NOT pinned. That cell is
# refused, and it is refused by the `%GF` pin alone.
#
# So the two layers are not symmetric and must not be read as interchangeable:
# the `%GF` pin in the accept test is the LOAD-BEARING layer and holds against
# any key the keyring can verify, secret present or not; the ownertrust
# restriction is defence in depth that holds for public-only imports. Any
# future change that weakens the `%GF` pin on the strength of "ownertrust
# already stops it" would be relying on a property the keyring does not have.
prepare_hermetic_gnupghome() {
  local pubkey_file="$1" gpg_signers_file="$2" dest="$3"

  if [ -z "$dest" ]; then
    echo "check-commit-signing-posture: ERROR — no destination for the hermetic keyring (fail-closed)" >&2
    return 1
  fi
  if ! command -v gpg >/dev/null 2>&1; then
    echo "check-commit-signing-posture: ERROR — gpg(1) is not available, so OpenPGP-signed commits cannot be verified; refusing to report PASS (fail-closed)" >&2
    return 1
  fi
  if [ ! -f "$pubkey_file" ]; then
    echo "check-commit-signing-posture: ERROR — enrolled OpenPGP public-key material $pubkey_file is missing (fail-closed)" >&2
    return 1
  fi

  rm -rf "$dest"
  mkdir -p "$dest"
  chmod 700 "$dest"

  if ! GNUPGHOME="$dest" gpg --batch --quiet --no-tty --import "$pubkey_file" >/dev/null 2>&1; then
    echo "check-commit-signing-posture: ERROR — importing $pubkey_file into the hermetic keyring failed (fail-closed)" >&2
    return 1
  fi

  local fpr trusted=0
  while IFS= read -r fpr; do
    [ -z "$fpr" ] && continue
    if ! GNUPGHOME="$dest" gpg --batch --quiet --no-tty --list-keys --with-colons "$fpr" >/dev/null 2>&1; then
      echo "check-commit-signing-posture: ERROR — pinned OpenPGP fingerprint $fpr is not present in $pubkey_file; the registry and its key material have drifted apart (fail-closed)" >&2
      return 1
    fi
    if ! printf '%s:6:\n' "$fpr" | GNUPGHOME="$dest" gpg --batch --quiet --no-tty --import-ownertrust >/dev/null 2>&1; then
      echo "check-commit-signing-posture: ERROR — could not grant ownertrust to pinned OpenPGP fingerprint $fpr in the hermetic keyring (fail-closed)" >&2
      return 1
    fi
    trusted=$((trusted + 1))
  done < <(enrolled_gpg_fingerprints "$gpg_signers_file")

  if [ "$trusted" -eq 0 ]; then
    echo "check-commit-signing-posture: ERROR — the hermetic keyring ended with ZERO trusted pinned keys (fail-closed)" >&2
    return 1
  fi
  return 0
}

# assert_merge_tree_usable [GIT_BIN] — the #5065 MANDATORY CAPABILITY PROBE.
#
# Term (3) of the exemption predicate is a `git merge-tree --write-tree`
# comparison, so this gate's correctness now depends on a git subcommand the
# CI runner does not pin (bare `ubuntu-latest`, no container, no git version
# pin). The one disposition this gate must NEVER take is "I could not compute
# the automerge, therefore the merge is exempt": that would turn a tool
# regression into a silent widening of a security carve-out, which is the
# #2444 "reports success while doing nothing" class this whole file exists to
# close. So the capability is PROVEN before the walk, and a failure here is
# exit 2 (INOPERATIVE), never a pass and never an exemption.
#
# The fixture is HERMETIC — three commits in a throwaway repository under the
# per-process scratch root, never the repository under test. The probe must
# prove the TOOL works; a probe run against real history could fail for a
# reason belonging to that history and would teach the next reader to loosen
# it. The two sides touch DIFFERENT files, so the clean automerge is
# deterministic across every git that implements the subcommand at all.
#
# Four assertions, because a weaker probe would be shape-validated and never
# resolved (the defect class this repo tracks by that name):
#   * rc is EXACTLY 0 — a missing subcommand is rc=129 plus usage, a bad rev
#     is rc=1 with empty stdout, and a true conflict is rc=1.
#   * stdout is EXACTLY ONE line matching 40 hex characters. (A sha256
#     repository would print 64; that is deliberately INOPERATIVE rather than
#     silently accepted, because `%T` would then not compare against this
#     gate's own literal expectation either.)
#   * that oid really resolves as a TREE object.
#   * the tree carries the MERGED content of BOTH sides — so a hypothetical
#     implementation that returned one parent's tree unchanged cannot pass.
#
# There is no `|| true` and no `2>/dev/null` on any call here, by design: when
# the tool is broken the operator must see the tool's own diagnostic.
#
# GIT_BIN is a self-test seam (default `git`), so the INOPERATIVE path is a
# branch a test actually takes rather than a branch nothing ever exercises.
# Production callers never pass it.
assert_merge_tree_usable() {
  local git_bin="${1:-git}"
  local probe="$GATE_SCRATCH_ROOT/merge-tree-probe"

  rm -rf "$probe"
  mkdir -p "$probe"

  local -a gc=("$git_bin" -C "$probe" -c "user.name=signing-posture-probe"
    -c "user.email=probe@invalid" -c "commit.gpgsign=false")

  if ! "$git_bin" init -q -b probe-main "$probe"; then
    echo "check-commit-signing-posture: ERROR — could not create the hermetic merge-tree capability-probe fixture with '$git_bin' (fail-closed; #5065 term (3) cannot be evaluated, and 'cannot compute' is NEVER 'exempt')" >&2
    return 1
  fi

  printf 'a0\n' >"$probe/a.txt"
  printf 'b0\n' >"$probe/b.txt"
  if ! "${gc[@]}" add a.txt b.txt || ! "${gc[@]}" commit -q -m probe-base; then
    echo "check-commit-signing-posture: ERROR — could not build the merge-tree capability-probe base commit (fail-closed)" >&2
    return 1
  fi
  local probe_base probe_p1 probe_p2
  if ! probe_base="$("${gc[@]}" rev-parse HEAD)" || [ -z "$probe_base" ]; then
    echo "check-commit-signing-posture: ERROR — could not resolve the merge-tree capability-probe base commit (fail-closed)" >&2
    return 1
  fi
  printf 'a1\n' >"$probe/a.txt"
  if ! "${gc[@]}" commit -q -a -m probe-side1 \
    || ! probe_p1="$("${gc[@]}" rev-parse HEAD)"; then
    echo "check-commit-signing-posture: ERROR — could not build the merge-tree capability-probe first side (fail-closed)" >&2
    return 1
  fi
  if ! "${gc[@]}" checkout -q --detach "$probe_base"; then
    echo "check-commit-signing-posture: ERROR — could not detach the merge-tree capability-probe fixture back to its base (fail-closed)" >&2
    return 1
  fi
  printf 'b1\n' >"$probe/b.txt"
  if ! "${gc[@]}" commit -q -a -m probe-side2 \
    || ! probe_p2="$("${gc[@]}" rev-parse HEAD)"; then
    echo "check-commit-signing-posture: ERROR — could not build the merge-tree capability-probe second side (fail-closed)" >&2
    return 1
  fi

  local mt_out="" mt_rc=0
  mt_out="$("${gc[@]}" merge-tree --write-tree "$probe_p1" "$probe_p2")" || mt_rc=$?
  if [ "$mt_rc" -ne 0 ]; then
    echo "check-commit-signing-posture: ERROR — 'git merge-tree --write-tree' is INOPERATIVE: it returned rc=$mt_rc on a hermetic known-clean two-side merge (rc=129 plus a usage line means this git is too old to carry the subcommand this gate's #5065 exemption depends on). Refusing to report PASS; a merge whose automerge cannot be computed is NEVER exempt." >&2
    return 1
  fi
  if [ -z "$mt_out" ] || [ "$(printf '%s' "$mt_out" | wc -l)" -ne 0 ]; then
    echo "check-commit-signing-posture: ERROR — 'git merge-tree --write-tree' returned rc=0 on a known-clean merge but did not print exactly one line (got: '${mt_out}'); the gate cannot tell a tree oid from a diagnostic and refuses to report PASS (fail-closed)" >&2
    return 1
  fi
  if [[ ! "$mt_out" =~ ^[0-9a-f]{40}$ ]]; then
    echo "check-commit-signing-posture: ERROR — 'git merge-tree --write-tree' printed '${mt_out}', which is not a 40-hex tree oid; the gate refuses to compare '%T' against it (fail-closed)" >&2
    return 1
  fi
  if ! "${gc[@]}" rev-parse --verify --quiet "${mt_out}^{tree}" >/dev/null; then
    echo "check-commit-signing-posture: ERROR — 'git merge-tree --write-tree' printed ${mt_out}, which does not resolve as a TREE object in the probe fixture (fail-closed)" >&2
    return 1
  fi

  # The merged tree must carry BOTH sides' edits. An implementation that
  # returned one parent's tree unchanged would satisfy every assertion above
  # and would make the exemption meaningless, so the content is checked too.
  local probe_a probe_b
  probe_a="$("${gc[@]}" cat-file blob "${mt_out}:a.txt")" || probe_a="<unreadable>"
  probe_b="$("${gc[@]}" cat-file blob "${mt_out}:b.txt")" || probe_b="<unreadable>"
  if [ "$probe_a" != "a1" ] || [ "$probe_b" != "b1" ]; then
    echo "check-commit-signing-posture: ERROR — 'git merge-tree --write-tree' produced a tree that does not carry BOTH sides of a known-clean merge (a.txt='${probe_a}' expected 'a1'; b.txt='${probe_b}' expected 'b1'); the automerge comparison this gate's #5065 exemption rests on is not trustworthy and the gate refuses to report PASS (fail-closed)" >&2
    return 1
  fi

  return 0
}

# automerge_tree GIT_BIN REPO_DIR P1 P2 — the CLEAN automerge tree of P1 and
# P2, printed on stdout with no trailing newline, or NOTHING with a non-zero
# return when the merge does not resolve cleanly to exactly one tree oid.
#
# Every non-clean outcome is a non-zero return, and the caller treats that as
# NOT EXEMPT (so the merge is scanned under the normal rule). That direction
# is the fail-closed one: a conflicting merge prints its tree oid AND conflict
# detail at rc=1, so rc is checked before anything is believed.
automerge_tree() {
  local git_bin="$1" repo_dir="$2" p1="$3" p2="$4"
  local out="" rc=0
  out="$("$git_bin" -C "$repo_dir" merge-tree --write-tree "$p1" "$p2" </dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    return 1
  fi
  if [ -z "$out" ] || [ "$(printf '%s' "$out" | wc -l)" -ne 0 ]; then
    return 1
  fi
  if [[ ! "$out" =~ ^[0-9a-f]{40}$ ]]; then
    return 1
  fi
  printf '%s' "$out"
  return 0
}

# walk_record_well_formed SHA SIG_STATUS SIG_FPR COMMIT_TREE PARENTS — the
# shape every field of one walk record must have before ANY of them is used
# (#5138). The NUL-delimited record already cannot shift (no field can hold a
# NUL), so this is the second, independent layer: a value git never emits for
# these placeholders is a broken walk, and a broken walk is INOPERATIVE, never
# a verdict. The two email fields are free text by design and are not
# shape-checked; they are only ever compared against the enrolled set.
walk_record_well_formed() {
  local sha="$1" sig_status="$2" sig_fpr="$3" commit_tree="$4" parents="$5"
  # Glob and length tests, not `=~` with `{40}`: the regex is recompiled on
  # every call and doubled the walk's wall clock on a 487-commit range.
  local oid
  local -a parent_words=()
  read -r -a parent_words <<<"$parents"
  for oid in "$sha" "$commit_tree" "${parent_words[@]}"; do
    if { [ "${#oid}" -ne 40 ] && [ "${#oid}" -ne 64 ]; } || [[ "$oid" == *[!0-9a-f]* ]]; then
      return 1
    fi
  done
  # `%P` is the oids separated by single spaces and nothing else.
  if [ "$parents" != "${parent_words[*]}" ]; then
    return 1
  fi
  case "$sig_status" in
    G | B | U | X | Y | R | E | N) : ;;
    *) return 1 ;;
  esac
  # `%GF`: empty, a 40-hex OpenPGP fingerprint, or an SSH `SHA256:<base64>`.
  if [[ "$sig_fpr" == *[!A-Za-z0-9:+/=]* ]]; then
    return 1
  fi
  return 0
}

# check_range BASE_SHA HEAD_SHA SIGNERS_FILE [REPO_DIR] [GPG_SIGNERS_FILE]
#             [GPG_PUBKEY_FILE] [PREPARED_GNUPGHOME] [MERGE_TREE_GIT]
#             [WALK_GIT]
#
# Walks EVERY commit in `merge-base(BASE,HEAD)..HEAD` inside REPO_DIR —
# merges included (#5065) — and prints, to stdout, one `SCANNED: <n> ...` line
# followed by one `VIOLATION: <sha> <reason>` line per failing commit. The
# ONLY commits not evaluated are merges that satisfy all three terms of the
# content-neutral web-flow exemption documented in the header.
#
# Returns 0 clean · 1 at least one violation · 2 the gate could not do its
# job (registry loss, unresolvable range, hermetic-keyring failure, an
# INOPERATIVE `git merge-tree --write-tree`, or ZERO commits evaluated — the
# #5047 non-vacuity floor). An empty range is NO LONGER a pass, and neither
# is a range whose every commit was exempted.
#
# PREPARED_GNUPGHOME is a self-test seam: when non-empty the keyring at that
# path is used verbatim instead of building a hermetic one, so the self-test
# can plant ephemeral keys. Production callers never pass it.
#
# MERGE_TREE_GIT is the second self-test seam (default `git`): the git binary
# used for the #5065 capability probe and for the automerge computation, so a
# self-test cell can drive the INOPERATIVE path with a git that does not
# implement `merge-tree --write-tree`. Production callers never pass it, and
# it is a POSITIONAL parameter rather than an environment variable on purpose
# — an env var would be an out-of-band way for a caller to redirect the
# content check, which is exactly the kind of backdoor this gate must not
# grow.
#
# WALK_GIT is the third self-test seam (default `git`), positional for the
# same reason: the git binary that performs the commit walk (`log`) and its
# `rev-list --count` cross-check, so a self-test cell can drive a walk that
# dies partway, comes up short, tears a record, or emits a malformed field
# (#5272, #5138). Production callers never pass it.
check_range() {
  local base="$1" head="$2" signers_file="$3" repo_dir="${4:-$REPO_ROOT}"
  local gpg_signers_file="${5:-$GPG_SIGNERS_FILE_DEFAULT}"
  local gpg_pubkey_file="${6:-$GPG_PUBKEY_FILE_DEFAULT}"
  local prepared_gnupghome="${7:-}"
  local merge_tree_git="${8:-git}"
  local walk_git="${9:-git}"
  local principals pinned violations=0

  if ! assert_registry_usable "$signers_file"; then
    return 2
  fi
  if ! assert_gpg_registry_usable "$gpg_signers_file"; then
    return 2
  fi
  principals="$(enrolled_principals "$signers_file")"
  pinned="$(pinned_fingerprints "$signers_file" "$gpg_signers_file")"
  if ! assert_pinned_fingerprints_usable "$pinned"; then
    return 2
  fi

  # #5065 MANDATORY CAPABILITY PROBE, before the walk. Term (3) of the
  # exemption predicate is a `git merge-tree --write-tree` comparison, and the
  # gate must never answer "I could not compute the automerge, therefore the
  # merge is exempt". A broken or absent subcommand is INOPERATIVE (rc=2),
  # never a pass.
  if ! assert_merge_tree_usable "$merge_tree_git"; then
    return 2
  fi

  # Resolve BOTH endpoints and say which one failed. #5047 wants the floor's
  # diagnostic to distinguish "the base ref does not exist" from "the range
  # is genuinely empty"; before this change both reported the same thing (and
  # the empty range reported nothing at all, and passed).
  local base_resolved head_resolved base_state head_state
  if base_resolved="$(git -C "$repo_dir" rev-parse --verify --quiet "${base}^{commit}")"; then
    base_state="resolved"
  else
    base_resolved=""
    base_state="UNRESOLVED"
  fi
  if head_resolved="$(git -C "$repo_dir" rev-parse --verify --quiet "${head}^{commit}")"; then
    head_state="resolved"
  else
    head_resolved=""
    head_state="UNRESOLVED"
  fi
  if [ "$base_state" != "resolved" ] || [ "$head_state" != "resolved" ]; then
    echo "check-commit-signing-posture: ERROR — cannot resolve range ${base}..${head} (fail-closed): base '${base}' ${base_state} (${base_resolved:-<none>}), head '${head}' ${head_state} (${head_resolved:-<none>})" >&2
    return 2
  fi

  local merge_base
  if ! merge_base="$(git -C "$repo_dir" merge-base "$base_resolved" "$head_resolved" 2>/dev/null)" \
    || [ -z "$merge_base" ]; then
    echo "check-commit-signing-posture: ERROR — no merge base between base '${base}' (${base_resolved}) and head '${head}' (${head_resolved}); the range cannot be scoped (fail-closed)" >&2
    return 2
  fi

  # The hermetic OpenPGP keyring must exist BEFORE the walk, because `%G?`
  # and `%GF` are computed during the walk.
  local gnupghome
  if [ -n "$prepared_gnupghome" ]; then
    gnupghome="$prepared_gnupghome"
  else
    gnupghome="$GATE_SCRATCH_ROOT/hermetic-gnupghome"
    mkdir -p "$GATE_SCRATCH_ROOT"
    if ! prepare_hermetic_gnupghome "$gpg_pubkey_file" "$gpg_signers_file" "$gnupghome"; then
      return 2
    fi
  fi

  # THE COMMIT WALK, streamed into the judging loop and checked BEFORE any
  # verdict is printed (findings are only emitted after the loop).
  #
  # Record format (#5138): seven fields, each terminated by a NUL (`-z` plus
  # `%x00` between placeholders), read one field per `read -d ''`. The two
  # email fields are author-chosen text, and git stores a literal `|` in
  # them; an earlier `%H|%ae|%ce|%G?|%GF|%T|%P` line split on `|` let a pipe
  # in an email move email text into the signature-status and fingerprint
  # fields, which made an UNSIGNED non-merge commit read as `%G?=G` with the
  # pinned `%GF` and PASS (measured: base df880a3f5 rc=1, bdc0723ae rc=0). A
  # NUL cannot occur inside any commit header field, so no field can shift;
  # walk_record_well_formed is the independent second layer.
  #
  # Completeness (#5272): a process substitution discards its exit status, so
  # the producer writes git's status to a file after git exits; the loop sees
  # EOF only once the producer has exited, so the file is complete when it is
  # read, and a missing or non-numeric status is itself INOPERATIVE. The
  # number of records read must also equal `rev-list --count` over the same
  # range. (The walk is streamed, not captured first: signature verification
  # in `git log` and the per-record checks then overlap, as they did before.) A walk that died partway, came up
  # short, or tore its last record is INOPERATIVE (2), never a PASS over the
  # commits it happened to read — the floor below refuses only ZERO.
  local walk_status walk_rc="" expected_count
  if ! mkdir -p "$GATE_SCRATCH_ROOT" \
    || ! walk_status="$(mktemp "$GATE_SCRATCH_ROOT/walk-status.XXXXXX")"; then
    echo "check-commit-signing-posture: ERROR — cannot create the commit-walk status file under ${GATE_SCRATCH_ROOT} (fail-closed)" >&2
    return 2
  fi
  if ! expected_count="$("$walk_git" -C "$repo_dir" rev-list --count "${merge_base}..${head_resolved}")" \
    || [[ ! "$expected_count" =~ ^[0-9]+$ ]]; then
    echo "check-commit-signing-posture: ERROR — cannot count the commits in ${merge_base}..${head_resolved} to cross-check the walk (#5272; fail-closed)" >&2
    return 2
  fi

  local sha author_email committer_email sig_status sig_fpr commit_tree parents
  local scanned=0 merges_evaluated=0 merges_exempted=0 walked=0
  local findings=""
  sha=""
  while IFS= read -r -d '' sha; do
    if ! IFS= read -r -d '' author_email \
      || ! IFS= read -r -d '' committer_email \
      || ! IFS= read -r -d '' sig_status \
      || ! IFS= read -r -d '' sig_fpr \
      || ! IFS= read -r -d '' commit_tree \
      || ! IFS= read -r -d '' parents; then
      echo "check-commit-signing-posture: ERROR — the commit walk ended inside the record for '${sha}'; a torn record is not a verdict (#5272; fail-closed)" >&2
      return 2
    fi
    walked=$((walked + 1))
    if ! walk_record_well_formed "$sha" "$sig_status" "$sig_fpr" "$commit_tree" "$parents"; then
      echo "check-commit-signing-posture: ERROR — malformed commit-walk record (sha='${sha}' %G?='${sig_status}' %GF='${sig_fpr}' %T='${commit_tree}' %P='${parents}'); a field git never emits is a broken walk, not a verdict (#5138; fail-closed)" >&2
      return 2
    fi
    local a_lc c_lc
    a_lc="$(printf '%s' "$author_email" | tr '[:upper:]' '[:lower:]')"
    c_lc="$(printf '%s' "$committer_email" | tr '[:upper:]' '[:lower:]')"

    # ---- #5065 THE THREE-TERM CONTENT-NEUTRAL WEB-FLOW MERGE EXEMPTION ----
    # Evaluated in increasing cost, and ONLY for a commit that already has
    # more than one parent. `read -r -a` (never `set --`, which would clobber
    # this function's own positional parameters, including the two self-test
    # seams).
    local -a parent_arr=()
    read -r -a parent_arr <<<"$parents"
    local parent_count="${#parent_arr[@]}"
    if [ "$parent_count" -gt 1 ]; then
      # Term (1): committer identity. Checked FIRST and on its own, so that an
      # enrolled operator's conflict-resolving merge never reaches the content
      # term at all — those merges legitimately do not reproduce under
      # `merge-tree` (10 of them in the measured cohort) and are meant to pass
      # through the NORMAL rule, not to be judged on tree equality.
      if [ "$c_lc" != "$WEBFLOW_COMMITTER_EMAIL" ]; then
        merges_evaluated=$((merges_evaluated + 1))
      # Term (2): exactly two parents. An octopus merge is NEVER exempt — the
      # automerge of a 3+-way merge is not what `merge-tree p1 p2` computes,
      # so there is no content check that would cover it. Zero octopus merges
      # exist in the measured cohort; this term keeps that true by refusing to
      # guess.
      elif [ "$parent_count" -ne 2 ]; then
        merges_evaluated=$((merges_evaluated + 1))
      else
        # Term (3): the recorded tree must equal the CLEAN automerge of the
        # two parents. This is the only term of the predicate an attacker
        # cannot set: `GIT_COMMITTER_EMAIL` is a plain environment variable
        # and a `gpgsig` header can be grafted, but the tree is the content.
        # Any non-clean outcome (true conflict, missing object, unexpected
        # output shape) returns non-zero from `automerge_tree` and the merge
        # is EVALUATED — the fail-closed direction.
        local automerge=""
        if automerge="$(automerge_tree "$merge_tree_git" "$repo_dir" "${parent_arr[0]}" "${parent_arr[1]}")" \
          && [ -n "$automerge" ] && [ "$automerge" = "$commit_tree" ]; then
          merges_exempted=$((merges_exempted + 1))
          continue
        fi
        merges_evaluated=$((merges_evaluated + 1))
      fi
    fi

    scanned=$((scanned + 1))

    if ! is_enrolled_principal "$a_lc" "$principals"; then
      findings+="VIOLATION: $sha unbound-author-email ($author_email)"$'\n'
      violations=1
    fi
    if ! is_enrolled_principal "$c_lc" "$principals"; then
      findings+="VIOLATION: $sha unbound-committer-email ($committer_email)"$'\n'
      violations=1
    fi
    # `elif`, not a second `if`: when `%G?` is not `G` nothing verified, so
    # `%GF` is empty by construction and a second "key not pinned" line would
    # be noise on the same root cause. The two reasons stay DISTINCT so a
    # rogue-key-in-the-keyring refusal is visibly its own failure mode.
    if [ "$sig_status" != "G" ]; then
      findings+="VIOLATION: $sha signature-not-verified (%G?=$sig_status)"$'\n'
      violations=1
    elif ! is_pinned_fingerprint "$sig_fpr" "$pinned"; then
      findings+="VIOLATION: $sha signing-key-not-pinned (%GF=${sig_fpr:-<empty>})"$'\n'
      violations=1
    fi
  done < <(
    GNUPGHOME="$gnupghome" "$walk_git" -C "$repo_dir" \
      -c "gpg.ssh.allowedSignersFile=$signers_file" \
      -c gpg.format=ssh \
      log -z --format='%H%x00%ae%x00%ce%x00%G?%x00%GF%x00%T%x00%P' \
      "${merge_base}..${head_resolved}"
    printf '%s' "$?" >"$walk_status"
  )
  walk_rc="$(cat "$walk_status")" || walk_rc=""
  rm -f "$walk_status"
  if [[ ! "$walk_rc" =~ ^[0-9]+$ ]]; then
    echo "check-commit-signing-posture: ERROR — the commit walk's exit status was not recorded ('${walk_rc}'); an unconfirmed walk is not a verdict (#5272; fail-closed)" >&2
    return 2
  fi
  if [ "$walk_rc" -ne 0 ]; then
    echo "check-commit-signing-posture: ERROR — the commit walk (git log over ${merge_base}..${head_resolved}) exited ${walk_rc}; a partial walk is not a verdict (#5272; fail-closed)" >&2
    return 2
  fi
  if [ -n "$sha" ]; then
    echo "check-commit-signing-posture: ERROR — the commit walk ended with an unterminated field '${sha}'; a torn record is not a verdict (#5272; fail-closed)" >&2
    return 2
  fi
  if [ "$walked" -ne "$expected_count" ]; then
    echo "check-commit-signing-posture: ERROR — the commit walk returned ${walked} record(s) but ${merge_base}..${head_resolved} holds ${expected_count} commit(s); a short walk is not a verdict (#5272; fail-closed)" >&2
    return 2
  fi

  # #5047 NON-VACUITY FLOOR, REBUILT FOR #5065. It counts EVALUATED commits
  # (every non-merge plus every merge the exemption did not cover), so zero is
  # a FAIL whether the range was empty, unreachable, or made ENTIRELY of
  # exempted web-flow merges. A gate that reports OK while having judged
  # nothing is the #2444 shape, and "every commit was exempt" is exactly that
  # shape wearing the carve-out's clothes.
  if [ "$scanned" -eq 0 ]; then
    echo "check-commit-signing-posture: ERROR — EVALUATED ZERO commits and refuses to report PASS (#5047 non-vacuity floor as rebuilt by #5065; fail-closed). base '${base}' ${base_state} -> ${base_resolved}; head '${head}' ${head_state} -> ${head_resolved}; merge-base -> ${merge_base}; range '${merge_base}..${head_resolved}'; ${merges_exempted} merge(s) were exempted as content-neutral web-flow merges and an all-exempt range is NOT a pass" >&2
    return 2
  fi

  echo "SCANNED: $scanned commits (${merges_evaluated} merges evaluated, ${merges_exempted} merges exempted content-neutral web-flow) in ${merge_base}..${head_resolved}"
  if [ -n "$findings" ]; then
    printf '%s' "$findings"
  fi

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
    # Exit 2, not 1: nothing was scanned, so this is the gate being
    # INOPERATIVE (a CI-wiring fault — `fetch-depth`, a renamed env var, a
    # workflow edit), not a commit violating the rule. Reporting it as 1 would
    # misattribute a wiring fault to the PR author, and 1 is the code this
    # gate's documented contract reserves for "a commit in range violated the
    # rule". Sibling precedent for the same env var and the same fail-closed
    # shape: check-cert-expiry.sh.
    echo "check-commit-signing-posture: ERROR — PR_BASE_SHA is unset on a pull_request event (fail-closed)" >&2
    return 2
  fi

  local out status=0
  out="$(check_range "$base" "$head" "$SIGNERS_FILE_DEFAULT" "$REPO_ROOT")" || status=$?

  local scanned_line
  scanned_line="$(grep -m1 '^SCANNED:' <<<"$out" || true)"

  case "$status" in
    0)
      echo "check-commit-signing-posture: OK — ${scanned_line:-SCANNED: (unreported)}; every EVALUATED commit is an enrolled identity whose signature verified against a PINNED key fingerprint (range ${base}..${head}; merges are evaluated too, and the only exempted ones are content-neutral web-flow merges whose tree equals the clean automerge of their two parents — #5065)"
      return 0
      ;;
    1)
      echo "check-commit-signing-posture: VIOLATION — one or more commits in ${base}..${head} are not an enrolled, signature-verified, PINNED-key identity (${scanned_line:-SCANNED: (unreported)}):" >&2
      grep -v '^SCANNED:' <<<"$out" >&2 || true
      echo "" >&2
      echo "  Fix (unbound-author-email / unbound-committer-email): reset the" >&2
      echo "  committer/author identity to an account-bound one enrolled in" >&2
      echo "  scripts/qc-allowlists/enrolled-commit-signers.txt (check for a" >&2
      echo "  stray local 'git config user.email' override — this is the exact" >&2
      echo "  #2486 defect class), re-sign, and re-push." >&2
      echo "  Fix (signature-not-verified): sign the commit with an enrolled" >&2
      echo "  key; %G?=N means it is unsigned, E means the key is not enrolled," >&2
      echo "  U means it verified but is not trusted in this job's keyring." >&2
      echo "  Fix (signing-key-not-pinned): the signature verified, but the key" >&2
      echo "  that produced it is NOT pinned. Enroll it via a reviewed PR to" >&2
      echo "  scripts/qc-allowlists/enrolled-commit-signers.txt (SSH) or to" >&2
      echo "  scripts/qc-allowlists/enrolled-gpg-commit-signers.txt plus its" >&2
      echo "  .asc sibling (OpenPGP) — never by widening the accept test." >&2
      return 1
      ;;
    *)
      echo "check-commit-signing-posture: INOPERATIVE — the gate could not do its job over ${base}..${head} and refuses to report PASS (see the fail-closed diagnostic above)." >&2
      return 2
      ;;
  esac
}

# st_report CASE OBSERVED_RC EXPECTED_RC — one stdout line per self-test case
# naming the case, the exit code it actually produced and the code it must
# produce. This is deliberately part of the gate rather than an out-of-band
# harness: the per-case exit codes are the acceptance evidence for #5045 /
# #5046 / #5047, so they are reproducible by anyone running `--self-test` and
# readable straight out of the CI job log, forever.
st_report() {
  printf 'self-test case (%s): rc=%s (expected %s)\n' "$1" "$2" "$3"
}


# st_field SHA FORMAT REPO_DIR GNUPGHOME SIGNERS_FILE — one `git log -1
# --format` field for a self-test fixture commit, computed with the SAME
# keyring and allowed-signers file `check_range` itself uses. The self-test's
# shape guards MUST see exactly what the gate sees; computing them any other
# way would let a guard and the gate disagree about `%G?` and call a vacuous
# cell sound.
st_field() {
  GNUPGHOME="$4" git -C "$3" -c "gpg.ssh.allowedSignersFile=$5" \
    -c gpg.format=ssh log -1 --format="$2" "$1"
}

self_test() {
  local tmp
  tmp="$GATE_SCRATCH_ROOT/selftest"
  mkdir -p "$tmp"

  if ! command -v gpg >/dev/null 2>&1; then
    echo "self-test FAILED: gpg(1) is unavailable, so the OpenPGP half of this gate (#5045) cannot be proven; refusing to report a partial PASS" >&2
    exit 2
  fi

  local enrolled_key="$tmp/enrolled_key" rogue_key="$tmp/rogue_key"
  ssh-keygen -q -t ed25519 -N '' -f "$enrolled_key" -C 'selftest-enrolled'
  ssh-keygen -q -t ed25519 -N '' -f "$rogue_key" -C 'selftest-rogue'

  local signers="$tmp/signers.txt"
  {
    echo "# self-test registry"
    printf 'dev@example.test %s\n' "$(cut -d' ' -f1,2 "$enrolled_key.pub")"
  } >"$signers"

  # OpenPGP half (#5045): TWO ephemeral keys in ONE ephemeral keyring. Both
  # are locally generated, so gpg gives BOTH ultimate ownertrust and BOTH
  # yield `%G? = G` — which is precisely the measured threat shape: a rogue
  # key merely PRESENT in the runner keyring verifies. Only the first is
  # pinned, so the ONLY thing that can reject the second is the `%GF` pin.
  local gpg_home="$tmp/gnupg"
  mkdir -p "$gpg_home"
  chmod 700 "$gpg_home"
  GNUPGHOME="$gpg_home" gpg --batch --quiet --no-tty --pinentry-mode loopback \
    --passphrase '' --quick-generate-key 'Selftest Pinned <pinned@example.test>' \
    ed25519 sign 0 >/dev/null 2>&1
  GNUPGHOME="$gpg_home" gpg --batch --quiet --no-tty --pinentry-mode loopback \
    --passphrase '' --quick-generate-key 'Selftest Rogue <rogue@example.test>' \
    ed25519 sign 0 >/dev/null 2>&1
  local pinned_gpg_fpr rogue_gpg_fpr
  pinned_gpg_fpr="$(GNUPGHOME="$gpg_home" gpg --batch --with-colons --list-secret-keys 'pinned@example.test' 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')"
  rogue_gpg_fpr="$(GNUPGHOME="$gpg_home" gpg --batch --with-colons --list-secret-keys 'rogue@example.test' 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')"
  if [ -z "$pinned_gpg_fpr" ] || [ -z "$rogue_gpg_fpr" ] || [ "$pinned_gpg_fpr" = "$rogue_gpg_fpr" ]; then
    echo "self-test FAILED: could not plant two DISTINCT ephemeral OpenPGP keys (pinned='$pinned_gpg_fpr' rogue='$rogue_gpg_fpr')" >&2
    exit 2
  fi

  local gpg_signers="$tmp/gpg_signers.txt"
  {
    echo "# self-test OpenPGP fingerprint registry"
    printf '%s selftest-pinned\n' "$pinned_gpg_fpr"
  } >"$gpg_signers"

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
  # (non-enrolled) SSH key: proves the gate rejects an identity spoof that a
  # bare "has-a-signature" check would miss.
  git -C "$repo" config commit.gpgsign true
  git -C "$repo" config user.signingkey "$rogue_key.pub"
  git -C "$repo" commit -q -m "bad: enrolled identity, rogue-key signature" --allow-empty
  local rogue_sha
  rogue_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" reset -q --hard "$clean_sha"

  # (h) CLEAN — enrolled email, signed with the PINNED ephemeral OpenPGP key
  # (#5045). MUST PASS. The range also contains the SSH-signed (a) commit, so
  # this case additionally proves both verification paths pass in ONE range
  # under ONE unioned pin.
  git -C "$repo" config gpg.format openpgp
  git -C "$repo" config user.signingkey "$pinned_gpg_fpr"
  GNUPGHOME="$gpg_home" git -C "$repo" commit -q -m "clean: enrolled identity, pinned OpenPGP signature" --allow-empty
  local gpg_clean_sha
  gpg_clean_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" reset -q --hard "$clean_sha"

  # (i) VIOLATION — enrolled email, a signature that FULLY VERIFIES (`%G?=G`)
  # against a key that is IN THE SAME KEYRING but is NOT PINNED (#5045).
  #
  # ****  LOAD-BEARING. NEVER DELETE THIS CASE.  ****
  # This commit PASSED the gate before #5045 would have, once the keyring
  # import existed, and it is the ONLY case that fails if a future edit drops
  # the `%GF` pinned-fingerprint branch while keeping the keyring import. Drop
  # that branch and the OpenPGP path silently widens from "the enrolled
  # operator key" to "ANY key present in the runner keyring with trust" — a
  # gate that reports success while proving nothing (#2444), and the exact
  # trap the #5045 crossroads verdict (`5-agent vote (4d3ea1c5)`, memory
  # 86c7ae16-2591-461c-a797-dfd779f05edf) identified in the naive fix. The
  # rogue key here is ultimately trusted on purpose, so `%G?` really is `G`
  # and the pin is the only thing standing between it and a PASS.
  git -C "$repo" config user.signingkey "$rogue_gpg_fpr"
  GNUPGHOME="$gpg_home" git -C "$repo" commit -q -m "bad: enrolled identity, UNPINNED OpenPGP key in the same keyring" --allow-empty
  local gpg_rogue_sha
  gpg_rogue_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" reset -q --hard "$clean_sha"
  git -C "$repo" config gpg.format ssh
  git -C "$repo" config user.signingkey "$enrolled_key.pub"

  local failed=0 out rc

  # ---- #5065 MERGE FIXTURES ----------------------------------------------
  # The carve-out this section replaced (`--no-merges`) meant NO self-test
  # case ever contained a merge at all, which is why a blanket exemption
  # survived three review passes: there was nothing in the gate's own
  # evidence that a merge was even reachable. Every cell below is built so
  # that the ONLY commit whose disposition is in question is the merge —
  # side1/side2/side3 are enrolled + SSH-signed and pass on their own.
  #
  # The two sides touch DIFFERENT files, so `merge-tree --write-tree` has a
  # deterministic clean result on every git that implements the subcommand.
  git -C "$repo" config commit.gpgsign true
  git -C "$repo" config gpg.format ssh
  git -C "$repo" config user.signingkey "$enrolled_key.pub"
  local side1_sha side2_sha side3_sha
  git -C "$repo" checkout -q --detach "$clean_sha"
  printf 's1\n' >"$repo/s1.txt"
  git -C "$repo" add s1.txt
  git -C "$repo" commit -q -m "side1"
  side1_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" checkout -q --detach "$clean_sha"
  printf 's2\n' >"$repo/s2.txt"
  git -C "$repo" add s2.txt
  git -C "$repo" commit -q -m "side2"
  side2_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" checkout -q --detach "$clean_sha"
  printf 's3\n' >"$repo/s3.txt"
  git -C "$repo" add s3.txt
  git -C "$repo" commit -q -m "side3"
  side3_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" checkout -q --detach "$clean_sha"
  # (#5278) Two more enrolled, SSH-signed sides that DO conflict: both add
  # `conflict.txt` with different content, so `merge-tree --write-tree` of
  # them exits 1 and prints a conflicted tree oid plus conflict detail.
  local cf1_sha cf2_sha
  printf 'cf1\n' >"$repo/conflict.txt"
  git -C "$repo" add conflict.txt
  git -C "$repo" commit -q -m "conflict side 1"
  cf1_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" checkout -q --detach "$clean_sha"
  printf 'cf2\n' >"$repo/conflict.txt"
  git -C "$repo" add conflict.txt
  git -C "$repo" commit -q -m "conflict side 2"
  cf2_sha="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" checkout -q --detach "$clean_sha"

  # The CLEAN automerge of side1+side2, computed through the gate's own
  # automerge_tree helper so the fixture and the gate cannot disagree about
  # what "the automerge" is.
  local auto_tree evil_tree octo_tree backdoor_blob aux_index="$tmp/aux-index"
  if ! auto_tree="$(automerge_tree git "$repo" "$side1_sha" "$side2_sha")" \
    || [ -z "$auto_tree" ]; then
    echo "self-test FAILED: could not compute the clean automerge of the two self-test sides, so no #5065 cell can be built (fail-closed)" >&2
    exit 2
  fi

  # The EVIL tree: the automerge plus a file that exists in NEITHER parent.
  # This is the measured attack shape from the #5065 vote — content that is
  # in no scanned commit, landing through a content-blind merge exemption.
  backdoor_blob="$(printf 'backdoor\n' | git -C "$repo" hash-object -w --stdin)"
  rm -f "$aux_index"
  GIT_INDEX_FILE="$aux_index" git -C "$repo" read-tree "$auto_tree"
  GIT_INDEX_FILE="$aux_index" git -C "$repo" update-index --add \
    --cacheinfo "100644,$backdoor_blob,backdoor.txt"
  evil_tree="$(GIT_INDEX_FILE="$aux_index" git -C "$repo" write-tree)"
  rm -f "$aux_index"
  # The octopus cell's tree is the CLEAN TWO-PARENT AUTOMERGE of its first
  # two parents, byte for byte (#5271). Term (3) compares the recorded tree
  # with `merge-tree --write-tree p1 p2` and nothing else, so on this tree
  # term (3) is SATISFIED: if the parent-count term (2) were ignored, this
  # three-parent web-flow merge would be exempted. Term (2) is therefore the
  # ONLY term that can refuse it, which is what makes the cell load-bearing
  # for term (2). (The earlier fixture added side3's file, so term (3)
  # refused it on its own and deleting term (2) left every cell green.)
  octo_tree="$auto_tree"
  if [ -z "$evil_tree" ] || [ "$evil_tree" = "$auto_tree" ]; then
    echo "self-test FAILED: the #5065 evil tree equals the automerge tree, so every negative merge cell would be VACUOUS (auto=$auto_tree evil=$evil_tree)" >&2
    exit 2
  fi

  # A third ephemeral OpenPGP key in a SEPARATE keyring the gate never sees.
  # It is the fixture analogue of GitHub's own web-flow key: a real signature
  # over the real commit, by a key the verifier does not hold, which is why
  # the 8 real web-flow merges read `%G? = E` rather than `N`.
  local absent_home="$tmp/gnupg-absent" absent_gpg_fpr
  mkdir -p "$absent_home"
  chmod 700 "$absent_home"
  GNUPGHOME="$absent_home" gpg --batch --quiet --no-tty --pinentry-mode loopback \
    --passphrase '' --quick-generate-key 'Selftest Absent <absent@example.test>' \
    ed25519 sign 0 >/dev/null 2>&1
  absent_gpg_fpr="$(GNUPGHOME="$absent_home" gpg --batch --with-colons --list-secret-keys 'absent@example.test' 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')"
  if [ -z "$absent_gpg_fpr" ]; then
    echo "self-test FAILED: could not plant the ephemeral OpenPGP key for the #5065 (7b) realistic-signature cell" >&2
    exit 2
  fi

  # (7a) Forged web-flow committer, exactly two parents, tree != automerge,
  # BARE UNSIGNED (`%G? = N`). `GIT_COMMITTER_EMAIL` is a plain environment
  # variable: no key, no privilege, no config write.
  local m7a_sha m7b_sha m7c_sha m_octo_sha m_local_sha m_rogue_sha
  local m_conflict_sha m_exempt_sha m_pipe_sha
  m7a_sha="$(GIT_AUTHOR_NAME='Dev' GIT_AUTHOR_EMAIL='dev@example.test' \
    GIT_COMMITTER_NAME='GitHub' GIT_COMMITTER_EMAIL="$WEBFLOW_COMMITTER_EMAIL" \
    git -C "$repo" commit-tree "$evil_tree" -p "$side1_sha" -p "$side2_sha" \
    -m 'Merge pull request #7a from side2 (forged, unsigned)')"

  # (7b) The SAME forgery, but carrying a real OpenPGP signature from a key
  # the gate's keyring does not hold: `%G? = E` with a populated `%GK`,
  # byte-identical in shape to the 8 real web-flow merges. This is the
  # REALISTIC cell: (7a) alone would be left green by any future `%G? != N`
  # filter while the hole stayed open.
  m7b_sha="$(GNUPGHOME="$absent_home" GIT_AUTHOR_NAME='Dev' \
    GIT_AUTHOR_EMAIL='dev@example.test' GIT_COMMITTER_NAME='GitHub' \
    GIT_COMMITTER_EMAIL="$WEBFLOW_COMMITTER_EMAIL" \
    git -C "$repo" -c gpg.format=openpgp commit-tree "$evil_tree" \
    -p "$side1_sha" -p "$side2_sha" -S"$absent_gpg_fpr" \
    -m 'Merge pull request #7b from side2 (forged, signed by an absent key)')"

  # (7c) The POSITIVE cell for the NAMED RESIDUAL: the same forged web-flow
  # identity, but the tree EQUALS the automerge. It stays exempt, on purpose.
  # Every byte of it derives from two parents that are themselves scanned
  # (parent closure measured 0 of 202 outside the scanned set), so it is
  # content-harmless. This cell exists so the residual is PINNED in both
  # directions rather than left implicit — a future edit that "tightens" the
  # exemption into a key pin has to confront this case deliberately.
  m7c_sha="$(GIT_AUTHOR_NAME='Dev' GIT_AUTHOR_EMAIL='dev@example.test' \
    GIT_COMMITTER_NAME='GitHub' GIT_COMMITTER_EMAIL="$WEBFLOW_COMMITTER_EMAIL" \
    git -C "$repo" commit-tree "$auto_tree" -p "$side1_sha" -p "$side2_sha" \
    -m 'Merge pull request #7c from side2 (content-neutral)')"

  # (octopus) Web-flow committer, THREE parents, tree = the clean automerge
  # of the first two (so term (3) holds — see octo_tree above). `merge-tree
  # p1 p2` does not compute the automerge of a 3+-way merge, so there is no
  # content check that covers it and term (2) refuses it. Zero octopus merges
  # exist in the measured cohort; this cell keeps that true by refusing to
  # guess rather than by assuming it stays true.
  m_octo_sha="$(GIT_AUTHOR_NAME='Dev' GIT_AUTHOR_EMAIL='dev@example.test' \
    GIT_COMMITTER_NAME='GitHub' GIT_COMMITTER_EMAIL="$WEBFLOW_COMMITTER_EMAIL" \
    git -C "$repo" commit-tree "$octo_tree" -p "$side1_sha" -p "$side2_sha" \
    -p "$side3_sha" -m 'Merge pull requests (octopus)')"

  # (local) An ENROLLED committer's ordinary `git merge --no-ff` with signing
  # off: two parents, the automerge tree, no signature. 93 merges of this
  # committer identity were exempted by the blanket carve-out purely for
  # having two parents; the ONLY violation this cell can produce is
  # signature-not-verified, because its identity is enrolled.
  m_local_sha="$(GIT_AUTHOR_NAME='Dev' GIT_AUTHOR_EMAIL='dev@example.test' \
    GIT_COMMITTER_NAME='Dev' GIT_COMMITTER_EMAIL='dev@example.test' \
    git -C "$repo" commit-tree "$auto_tree" -p "$side1_sha" -p "$side2_sha" \
    -m "Merge branch 'side2'")"

  # (unpinned-key merge) The merge variant of LOAD-BEARING case (i): an
  # enrolled committer, a signature that FULLY VERIFIES (`%G? = G`) against a
  # key that is in the SAME keyring but is NOT PINNED. Under `--no-merges`
  # this commit was never looked at; now it must be refused SPECIFICALLY as
  # signing-key-not-pinned, which is the only way to prove the `%GF` pin — not
  # merely the identity check — reaches merges too.
  m_rogue_sha="$(GNUPGHOME="$gpg_home" GIT_AUTHOR_NAME='Dev' \
    GIT_AUTHOR_EMAIL='dev@example.test' GIT_COMMITTER_NAME='Dev' \
    GIT_COMMITTER_EMAIL='dev@example.test' \
    git -C "$repo" -c gpg.format=openpgp commit-tree "$auto_tree" \
    -p "$side1_sha" -p "$side2_sha" -S"$rogue_gpg_fpr" \
    -m "Merge branch 'side2' (unpinned key)")"

  # (enrolled conflict merge) The shape of the operator's 10 real
  # conflict-resolving merges: enrolled identity, enrolled signature, and a
  # tree that does NOT reproduce under `merge-tree` (all 10 are genuine rc=1
  # conflicts). It MUST PASS through the normal rule. This is the cell that
  # would catch an implementation that applied the tree test to EVERY merge
  # instead of only to web-flow-committed ones — the false-refusal failure
  # mode, which would block the operator's own landings.
  m_conflict_sha="$(GIT_AUTHOR_NAME='Dev' GIT_AUTHOR_EMAIL='dev@example.test' \
    GIT_COMMITTER_NAME='Dev' GIT_COMMITTER_EMAIL='dev@example.test' \
    git -C "$repo" -c gpg.format=ssh commit-tree "$evil_tree" \
    -p "$side1_sha" -p "$side2_sha" -S"$enrolled_key.pub" \
    -m "Merge branch 'side2' (conflict resolution)")"

  # (all-exempt) A web-flow merge whose SECOND parent is already an ancestor
  # of the first, with p1's own tree recorded: the clean automerge IS p1's
  # tree, so this merge is genuinely exempt, and the range
  # `side1_sha..m_exempt_sha` holds EXACTLY this one commit. It is the
  # all-exempt range that the rebuilt #5047 floor must still refuse.
  m_exempt_sha="$(GIT_AUTHOR_NAME='Dev' GIT_AUTHOR_EMAIL='dev@example.test' \
    GIT_COMMITTER_NAME='GitHub' GIT_COMMITTER_EMAIL="$WEBFLOW_COMMITTER_EMAIL" \
    git -C "$repo" commit-tree "$(git -C "$repo" rev-parse "${side1_sha}^{tree}")" \
    -p "$side1_sha" -p "$clean_sha" -m 'Merge pull request (no-op)')"

  # (#5276 merge-only ranges) The same no-op merge shape made LOCALLY by the
  # enrolled identity, once SSH-signed and once unsigned. Each range
  # `side1_sha..<merge>` holds that one EVALUATED merge and NO non-merge
  # commit, which is the only kind of range on which the rebuilt #5047 floor
  # (count EVALUATED commits) and the pre-#5065 floor (count non-merge
  # commits) disagree. Every other range in this self-test carries a
  # non-merge commit, so without these two cells a revert to the old floor
  # ships green.
  # (#5278 web-flow conflict) A web-flow-identity, UNSIGNED, two-parent
  # merge of the conflicting sides whose recorded tree IS the conflicted tree
  # oid that `merge-tree --write-tree` prints first at rc=1. Terms (1) and (2)
  # hold, so only automerge_tree's refusal of a non-clean result keeps it out
  # of the exemption: a version that believed the first line of a conflicted
  # result would find `%T` equal and exempt it.
  local wf_conflict_tree="" wf_conflict_rc=0 m_wf_conflict_sha
  wf_conflict_tree="$(git -C "$repo" merge-tree --write-tree "$cf1_sha" "$cf2_sha" </dev/null)" || wf_conflict_rc=$?
  wf_conflict_tree="${wf_conflict_tree%%$'\n'*}"
  if [ "$wf_conflict_rc" -ne 1 ] || [[ ! "$wf_conflict_tree" =~ ^[0-9a-f]{40}$ ]]; then
    echo "self-test FAILED: the #5278 fixture needs a CONFLICTING pair (merge-tree rc=1 and a tree oid first); got rc=$wf_conflict_rc first-line='$wf_conflict_tree'" >&2
    exit 2
  fi
  m_wf_conflict_sha="$(GIT_AUTHOR_NAME='Dev' GIT_AUTHOR_EMAIL='dev@example.test' \
    GIT_COMMITTER_NAME='GitHub' GIT_COMMITTER_EMAIL="$WEBFLOW_COMMITTER_EMAIL" \
    git -C "$repo" commit-tree "$wf_conflict_tree" -p "$cf1_sha" -p "$cf2_sha" \
    -m 'Merge pull request (conflicted tree recorded)')"

  local m_only_signed_sha m_only_unsigned_sha
  m_only_signed_sha="$(GIT_AUTHOR_NAME='Dev' GIT_AUTHOR_EMAIL='dev@example.test' \
    GIT_COMMITTER_NAME='Dev' GIT_COMMITTER_EMAIL='dev@example.test' \
    git -C "$repo" -c gpg.format=ssh commit-tree "$(git -C "$repo" rev-parse "${side1_sha}^{tree}")" \
    -p "$side1_sha" -p "$clean_sha" -S"$enrolled_key.pub" \
    -m "Merge branch 'clean' (local, signed, no-op)")"
  m_only_unsigned_sha="$(GIT_AUTHOR_NAME='Dev' GIT_AUTHOR_EMAIL='dev@example.test' \
    GIT_COMMITTER_NAME='Dev' GIT_COMMITTER_EMAIL='dev@example.test' \
    git -C "$repo" commit-tree "$(git -C "$repo" rev-parse "${side1_sha}^{tree}")" \
    -p "$side1_sha" -p "$clean_sha" \
    -m "Merge branch 'clean' (local, unsigned, no-op)")"

  # (pipe) A two-parent merge whose AUTHOR email is `evil|noreply@github.com`
  # and whose REAL committer is the enrolled local identity. `git` records a
  # literal `|` in an email. Under the earlier `|`-split walk record that pipe
  # moved `noreply@github.com` into the committer field and forged term (1)
  # of the exemption; only term (3) refused it. With the NUL-delimited record
  # (#5138) no email text can leave its field: the walk reads the real
  # committer, term (1) refuses, the merge is EVALUATED, and it is refused as
  # unsigned with the WHOLE author email quoted as unbound. The cell pins that
  # the exemption cannot be entered through any field the author writes.
  #
  # The tree is the CLEAN automerge on purpose: the content is innocent, so
  # if a shift ever returned, nothing in the tree would refuse it for an
  # unrelated reason.
  m_pipe_sha="$(GIT_AUTHOR_NAME='Dev' \
    GIT_AUTHOR_EMAIL="evil|$WEBFLOW_COMMITTER_EMAIL" \
    GIT_COMMITTER_NAME='Dev' GIT_COMMITTER_EMAIL='dev@example.test' \
    git -C "$repo" commit-tree "$auto_tree" -p "$side1_sha" -p "$side2_sha" \
    -m 'Merge branch side2 (author email carries a pipe)')"

  # (#5138 NON-MERGE record shift) The measured fail-OPEN shapes; the third,
  # f2r's, follows below. All are UNSIGNED single-parent commits (`%G? = N`),
  # built with nothing but `GIT_AUTHOR_EMAIL` / `GIT_COMMITTER_EMAIL`, no key. Against a walk that
  # splits `%H|%ae|%ce|%G?|%GF|%T|%P` on `|`, the email text lands in the
  # signature-status and fingerprint fields: `sig_status=G` and
  # `sig_fpr=<the pinned fingerprint>`, while the real `N` is pushed into the
  # parents remainder. Measured end to end before the fix: base `df880a3f5`
  # refused both (rc=1, its last field absorbed the remainder), PR #5083 tip
  # `bdc0723ae` PASSED both (rc=0). The walk must read the commit's REAL
  # fields, so both must be refused naming `signature-not-verified (%G?=N)`.
  local nm_tree nm_shift2_sha nm_shift1_sha
  nm_tree="$(git -C "$repo" rev-parse "${clean_sha}^{tree}")"
  nm_shift2_sha="$(GIT_AUTHOR_NAME='Dev' \
    GIT_AUTHOR_EMAIL='dev@example.test|dev@example.test|G' \
    GIT_COMMITTER_NAME='Dev' GIT_COMMITTER_EMAIL="$pinned_gpg_fpr" \
    git -C "$repo" commit-tree "$nm_tree" -p "$clean_sha" \
    -m 'non-merge: two pipes in the author email, pinned fingerprint as committer email')"
  nm_shift1_sha="$(GIT_AUTHOR_NAME='Dev' \
    GIT_AUTHOR_EMAIL='dev@example.test|dev@example.test' \
    GIT_COMMITTER_NAME='Dev' GIT_COMMITTER_EMAIL="G|$pinned_gpg_fpr" \
    git -C "$repo" commit-tree "$nm_tree" -p "$clean_sha" \
    -m 'non-merge: one pipe in the author email, crafted committer email')"
  # The shape f2r executed on PR #5083: ONE attacker-written field. The author
  # email carries `<enrolled>|<enrolled>|G|<pinned>` and the committer is the
  # ordinary enrolled identity, so no committer check can notice anything.
  local nm_shift3_sha
  nm_shift3_sha="$(GIT_AUTHOR_NAME='Dev' \
    GIT_AUTHOR_EMAIL="dev@example.test|dev@example.test|G|$pinned_gpg_fpr" \
    GIT_COMMITTER_NAME='Dev' GIT_COMMITTER_EMAIL='dev@example.test' \
    git -C "$repo" commit-tree "$nm_tree" -p "$clean_sha" \
    -m 'non-merge: the whole shift in the author email, enrolled committer')"

  # FIXTURE SHAPE GUARDS. Every assertion below is on the shape a cell must
  # have for its verdict to mean anything. Without them a fixture regression
  # (a signature that silently stopped being produced, an evil tree that
  # became the automerge) would turn a negative cell into a tautology that
  # still reported rc=1 for the wrong reason.
  local shape_g shape_gk
  local shape_ae shape_t shape_p shape_ce
  shape_ae="$(st_field "$m_pipe_sha" '%ae' "$repo" "$gpg_home" "$signers")"
  case "$shape_ae" in
    *'|'*) : ;;
    *)
      echo "self-test FAILED: the #5065 pipe cell needs git to have RECORDED a literal '|' in the author email; git reports %ae='$shape_ae'. Without the pipe the cell is an ordinary unenrolled-author commit and proves nothing about the exemption predicate." >&2
      failed=1
      ;;
  esac
  shape_t="$(st_field "$m_pipe_sha" '%T' "$repo" "$gpg_home" "$signers")"
  if [ "$shape_t" != "$auto_tree" ]; then
    echo "self-test FAILED: the #5065 pipe cell must record the CLEAN automerge tree so that its content is innocent and only the cannot-compute rule can refuse it; %T='$shape_t' auto_tree='$auto_tree'" >&2
    failed=1
  fi
  shape_p="$(st_field "$m_pipe_sha" '%P' "$repo" "$gpg_home" "$signers")"
  # `read -r -a`, never `set --`: this function's own positional parameters
  # carry the self-test's invocation and clobbering them here would be a
  # silent action at a distance (the same reason the walk uses `read -r -a`).
  local -a pipe_parents=()
  read -r -a pipe_parents <<<"$shape_p"
  if [ "${#pipe_parents[@]}" -ne 2 ]; then
    echo "self-test FAILED: the #5065 pipe cell must have exactly two parents (so term (2) cannot be what refuses it); %P='$shape_p'" >&2
    failed=1
  fi
  shape_ce="$(st_field "$m_pipe_sha" '%ce' "$repo" "$gpg_home" "$signers")"
  if [ "$shape_ce" = "$WEBFLOW_COMMITTER_EMAIL" ]; then
    echo "self-test FAILED: the #5065 pipe cell's REAL committer must NOT be the web-flow identity — the whole point is that the shifted field forges term (1) while the commit itself is a local one; %ce='$shape_ce'" >&2
    failed=1
  fi
  local nm_sha
  for nm_sha in "$nm_shift2_sha" "$nm_shift1_sha" "$nm_shift3_sha"; do
    shape_g="$(st_field "$nm_sha" '%G?' "$repo" "$gpg_home" "$signers")"
    shape_ae="$(st_field "$nm_sha" '%ae' "$repo" "$gpg_home" "$signers")"
    shape_p="$(st_field "$nm_sha" '%P' "$repo" "$gpg_home" "$signers")"
    if [ "$shape_g" != "N" ] || [ "$shape_p" != "$clean_sha" ]; then
      echo "self-test FAILED: a #5138 non-merge shift cell must be an UNSIGNED (%G?=N) single-parent commit, or a refusal would prove nothing about the parser; $nm_sha has %G?='$shape_g' %P='$shape_p'" >&2
      failed=1
    fi
    case "$shape_ae" in
      *'|'*) : ;;
      *)
        echo "self-test FAILED: a #5138 non-merge shift cell needs git to have RECORDED a literal '|' in the author email; $nm_sha has %ae='$shape_ae'" >&2
        failed=1
        ;;
    esac
  done
  if [ "$(st_field "$m_octo_sha" '%T' "$repo" "$gpg_home" "$signers")" != "$auto_tree" ]; then
    echo "self-test FAILED: the #5065 octopus cell must record the CLEAN two-parent automerge tree so that term (3) is satisfied and ONLY the parent-count term (2) can refuse it (#5271)" >&2
    failed=1
  fi
  shape_g="$(st_field "$m7a_sha" '%G?' "$repo" "$gpg_home" "$signers")"
  if [ "$shape_g" != "N" ]; then
    echo "self-test FAILED: #5065 cell (7a) must be BARE UNSIGNED (%G?=N) to be the shape it claims; git reports %G?='$shape_g'" >&2
    failed=1
  fi
  shape_g="$(st_field "$m7b_sha" '%G?' "$repo" "$gpg_home" "$signers")"
  shape_gk="$(st_field "$m7b_sha" '%GK' "$repo" "$gpg_home" "$signers")"
  if [ "$shape_g" != "E" ] || [ -z "$shape_gk" ]; then
    echo "self-test FAILED: #5065 cell (7b) must carry a signature from a key the keyring lacks (%G?=E with a populated %GK, the measured shape of the 8 real web-flow merges); git reports %G?='$shape_g' %GK='${shape_gk:-<empty>}'. Without this the cell degenerates into (7a) and a future '%G? != N' filter would leave the hole open." >&2
    failed=1
  fi
  shape_g="$(st_field "$m_rogue_sha" '%G?' "$repo" "$gpg_home" "$signers")"
  if [ "$shape_g" != "G" ]; then
    echo "self-test FAILED: the #5065 unpinned-key MERGE cell must FULLY VERIFY (%G?=G) so that the %GF pin is the only thing that can reject it; git reports %G?='$shape_g'" >&2
    failed=1
  fi
  shape_g="$(st_field "$m_conflict_sha" '%G?' "$repo" "$gpg_home" "$signers")"
  if [ "$shape_g" != "G" ]; then
    echo "self-test FAILED: the #5065 enrolled conflict-merge cell must FULLY VERIFY (%G?=G) or its PASS would prove nothing; git reports %G?='$shape_g'" >&2
    failed=1
  fi
  if [ "$(st_field "$m_conflict_sha" '%T' "$repo" "$gpg_home" "$signers")" = "$auto_tree" ]; then
    echo "self-test FAILED: the #5065 enrolled conflict-merge cell records the AUTOMERGE tree, so it no longer exercises the non-reproducing shape of the operator's 10 real conflict resolutions" >&2
    failed=1
  fi
  if [ "$(st_field "$m7c_sha" '%T' "$repo" "$gpg_home" "$signers")" != "$auto_tree" ]; then
    echo "self-test FAILED: the #5065 (7c) positive cell does NOT record the automerge tree, so it is not the exempt shape it claims to pin" >&2
    failed=1
  fi

  # (a) clean control MUST pass.
  rc=0
  out="$(check_range "$base_sha" "$clean_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home")" || rc=$?
  st_report "a" "$rc" "0"
  if [ "$rc" -ne 0 ]; then
    echo "self-test FAILED: clean enrolled+signed commit was REJECTED (rc=$rc):" >&2
    echo "$out" >&2
    failed=1
  fi

  # (b) identity-drift + unsigned MUST fail, naming BOTH the email and
  # signature violations (proves the two checks are independent, not one
  # masking the other).
  rc=0
  out="$(check_range "$base_sha" "$drift_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "b" "$rc" "non-zero"
  if [ "$rc" -eq 0 ]; then
    echo "self-test FAILED: #2486 identity-drift shape was NOT rejected" >&2
    failed=1
  else
    if ! grep -q "unbound-committer-email" <<<"$out"; then
      echo "self-test FAILED: identity-drift rejection did not name unbound-committer-email:" >&2
      echo "$out" >&2
      failed=1
    fi
    if ! grep -q "signature-not-verified" <<<"$out"; then
      echo "self-test FAILED: identity-drift rejection did not name signature-not-verified:" >&2
      echo "$out" >&2
      failed=1
    fi
  fi

  # (c) enrolled email but unsigned MUST fail on signature alone (email
  # check must NOT fire — proves independence in the other direction).
  rc=0
  out="$(check_range "$base_sha" "$unsigned_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "c" "$rc" "non-zero"
  if [ "$rc" -eq 0 ]; then
    echo "self-test FAILED: unsigned enrolled-identity commit was NOT rejected" >&2
    failed=1
  else
    if ! grep -q "signature-not-verified" <<<"$out"; then
      echo "self-test FAILED: unsigned-commit rejection did not name signature-not-verified:" >&2
      echo "$out" >&2
      failed=1
    fi
    if grep -q "unbound-.*-email" <<<"$out"; then
      echo "self-test FAILED: unsigned-but-enrolled commit incorrectly also flagged an email violation:" >&2
      echo "$out" >&2
      failed=1
    fi
  fi

  # (d) enrolled email claimed, rogue SSH-key signature MUST fail — proves
  # the gate verifies the signature against the REGISTRY, not merely "some
  # signature is present" (the E status: unenrolled key rejects a spoofed
  # enrolled email).
  rc=0
  out="$(check_range "$base_sha" "$rogue_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "d" "$rc" "non-zero"
  if [ "$rc" -eq 0 ]; then
    echo "self-test FAILED: rogue-key signature under a spoofed enrolled email was NOT rejected" >&2
    failed=1
  else
    if ! grep -q "signature-not-verified" <<<"$out"; then
      echo "self-test FAILED: rogue-key rejection did not name signature-not-verified:" >&2
      echo "$out" >&2
      failed=1
    fi
  fi

  # (e) missing/unresolvable range fails CLOSED with exit 2 — never 0, and
  # never the exit-1 "a commit violated the rule" code, because nothing was
  # scanned (#5047: an inoperative gate is its own disposition).
  rc=0
  check_range "0000000000000000000000000000000000000000" "$clean_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" >/dev/null 2>&1 || rc=$?
  st_report "e" "$rc" "2"
  if [ "$rc" -ne 2 ]; then
    echo "self-test FAILED: an unresolvable base SHA returned $rc, expected 2 (fail-closed, inoperative)" >&2
    failed=1
  fi

  # (f) MISSING registry file fails CLOSED — the explicit
  # assert_registry_usable guard (#2486 Fable finding L5), not an
  # incidental pipefail. A future refactor that swallows
  # enrolled_principals' exit status would flip this fail-open silently
  # if it were not directly asserted here.
  rc=0
  check_range "$base_sha" "$clean_sha" "$tmp/does-not-exist-registry.txt" "$repo" "$gpg_signers" "" "$gpg_home" >/dev/null 2>&1 || rc=$?
  st_report "f" "$rc" "2"
  if [ "$rc" -ne 2 ]; then
    echo "self-test FAILED: a missing enrolled-signers registry returned $rc, expected 2 (fail-closed)" >&2
    failed=1
  fi

  # (g) EMPTY registry (present file, zero enrolled principals after
  # stripping comments/blanks) fails CLOSED — same explicit guard,
  # proven independently of the missing-file case so a fix that only
  # checks `[ -f ... ]` cannot pass this self-test.
  local empty_signers="$tmp/empty_signers.txt"
  printf '# no principals enrolled\n\n' >"$empty_signers"
  rc=0
  check_range "$base_sha" "$clean_sha" "$empty_signers" "$repo" "$gpg_signers" "" "$gpg_home" >/dev/null 2>&1 || rc=$?
  st_report "g" "$rc" "2"
  if [ "$rc" -ne 2 ]; then
    echo "self-test FAILED: an empty enrolled-signers registry returned $rc, expected 2 (fail-closed)" >&2
    failed=1
  fi

  # (g2) MISSING and EMPTY OpenPGP fingerprint registries fail CLOSED too
  # (#5045) — the second registry gets the same explicit guard as the first,
  # so losing the OpenPGP pin can never degrade into "the SSH half still
  # passes, nothing noticed".
  rc=0
  check_range "$base_sha" "$clean_sha" "$signers" "$repo" "$tmp/does-not-exist-gpg-registry.txt" "" "$gpg_home" >/dev/null 2>&1 || rc=$?
  st_report "g2-missing" "$rc" "2"
  if [ "$rc" -ne 2 ]; then
    echo "self-test FAILED: a missing OpenPGP fingerprint registry returned $rc, expected 2 (fail-closed)" >&2
    failed=1
  fi
  local empty_gpg_signers="$tmp/empty_gpg_signers.txt"
  printf '# no fingerprints pinned\nnot-a-fingerprint comment\n\n' >"$empty_gpg_signers"
  rc=0
  check_range "$base_sha" "$clean_sha" "$signers" "$repo" "$empty_gpg_signers" "" "$gpg_home" >/dev/null 2>&1 || rc=$?
  st_report "g2-empty" "$rc" "2"
  if [ "$rc" -ne 2 ]; then
    echo "self-test FAILED: an OpenPGP fingerprint registry with zero well-formed fingerprints returned $rc, expected 2 (fail-closed)" >&2
    failed=1
  fi

  # (h) PINNED OpenPGP signature MUST pass (#5045) — the whole point of the
  # repair: the operator's OpenPGP-signed commits stop being refused, and the
  # same range still accepts the SSH-signed commit.
  rc=0
  out="$(check_range "$base_sha" "$gpg_clean_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "h" "$rc" "0"
  if [ "$rc" -ne 0 ]; then
    echo "self-test FAILED: a commit signed with the PINNED OpenPGP key was REJECTED (rc=$rc):" >&2
    echo "$out" >&2
    failed=1
  fi

  # (i) LOAD-BEARING (NEVER DELETE): a fully-verifying (`%G?=G`) OpenPGP
  # signature from an UNPINNED key in the SAME keyring MUST be refused, and
  # refused specifically as signing-key-not-pinned. See the long comment at
  # the planting site above for why this is the only guard against the
  # OpenPGP path silently widening to "any key in the runner keyring".
  rc=0
  out="$(check_range "$base_sha" "$gpg_rogue_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "i" "$rc" "non-zero"
  if [ "$rc" -eq 0 ]; then
    echo "self-test FAILED: an UNPINNED OpenPGP key present in the same keyring was NOT rejected — the OpenPGP path has widened to 'any key in the runner keyring' (#5045):" >&2
    echo "$out" >&2
    failed=1
  else
    if ! grep -q "signing-key-not-pinned" <<<"$out"; then
      echo "self-test FAILED: the unpinned-OpenPGP-key rejection did not name signing-key-not-pinned (so it was refused for the wrong reason, and the %GF pin is not what rejected it):" >&2
      echo "$out" >&2
      failed=1
    fi
  fi

  # (j) EMPTY RANGE fails CLOSED with exit 2, never 0 (#5047). Before this
  # change an empty range reported OK: a gate that passes while scanning
  # nothing. Asserted on an exact code so "it failed for some other reason"
  # cannot be mistaken for the floor firing.
  rc=0
  check_range "$clean_sha" "$clean_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" >/dev/null 2>&1 || rc=$?
  st_report "j" "$rc" "2"
  if [ "$rc" -ne 2 ]; then
    echo "self-test FAILED: an EMPTY commit range returned $rc, expected 2 (#5047 non-vacuity floor)" >&2
    failed=1
  fi


  # ---------------------------------------------------------------------
  # #5065 MERGE CELLS. Decided by `5-agent vote (4d3ea1c5)`, OPTION B 4-1:
  # a merge is exempt IFF its committer is the web-flow identity AND it has
  # exactly two parents AND its recorded tree equals the clean
  # `git merge-tree --write-tree` of those two parents. Every one of the
  # negative cells below returns 0 on the `--no-merges` implementation this
  # replaced — the merge was dropped before any evaluation — which is what
  # makes them red-first rather than decorative.
  # ---------------------------------------------------------------------

  # (7a) forged web-flow identity, two parents, tree != automerge, UNSIGNED.
  # MUST be refused naming signature-not-verified.
  rc=0
  out="$(check_range "$base_sha" "$m7a_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "7a-forged-webflow-unsigned-evil-tree" "$rc" "non-zero"
  if [ "$rc" -eq 0 ]; then
    echo "self-test FAILED: a two-parent merge with a FORGED web-flow committer identity, carrying content present in NEITHER parent, was EXEMPTED (#5065). GIT_COMMITTER_EMAIL is a plain environment variable; an identity-only exemption is content-blind:" >&2
    echo "$out" >&2
    failed=1
  elif ! grep -q "signature-not-verified" <<<"$out"; then
    echo "self-test FAILED: the #5065 (7a) refusal did not name signature-not-verified, so the merge was refused for some other reason and the signature rule still does not reach merges:" >&2
    echo "$out" >&2
    failed=1
  fi

  # (7b) THE REALISTIC SHAPE: the same forgery carrying a real signature from
  # a key the keyring lacks (%G?=E, %GK populated) — indistinguishable on
  # every field from the 8 genuine web-flow merges. MUST be refused naming
  # signature-not-verified.
  rc=0
  out="$(check_range "$base_sha" "$m7b_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "7b-forged-webflow-E-status-evil-tree" "$rc" "non-zero"
  if [ "$rc" -eq 0 ]; then
    echo "self-test FAILED: a forged web-flow merge whose signature reads %G?=E with a populated %GK — the exact shape of the 8 genuine web-flow merges — was EXEMPTED while carrying content present in neither parent (#5065):" >&2
    echo "$out" >&2
    failed=1
  elif ! grep -q "signature-not-verified" <<<"$out"; then
    echo "self-test FAILED: the #5065 (7b) refusal did not name signature-not-verified:" >&2
    echo "$out" >&2
    failed=1
  fi

  # (7c) POSITIVE: the SAME forged identity, tree == automerge, stays EXEMPT.
  # This is the NAMED RESIDUAL of the adopted option, recorded rather than
  # papered over: the merge is content-harmless because every byte of it
  # derives from two parents that are themselves scanned.
  rc=0
  out="$(check_range "$base_sha" "$m7c_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "7c-webflow-tree-equals-automerge-EXEMPT" "$rc" "0"
  if [ "$rc" -ne 0 ]; then
    echo "self-test FAILED: a content-neutral web-flow merge (tree == the clean automerge of its two parents) was REFUSED (rc=$rc). That is the false-refusal cost the #5065 vote measured at 0 of 382 real web-flow merges; refusing it here means the exemption no longer covers the shape it exists for:" >&2
    echo "$out" >&2
    failed=1
  elif ! grep -q '1 merges exempted content-neutral web-flow' <<<"$out"; then
    echo "self-test FAILED: the #5065 (7c) cell passed, but the SCANNED line does not report exactly one exempted merge, so the pass may be coming from somewhere other than the exemption:" >&2
    echo "$out" >&2
    failed=1
  fi

  # (octopus) web-flow identity, THREE parents, and a tree EQUAL to the clean
  # automerge of the first two (#5271). Terms (1) and (3) both hold, so term
  # (2) is the only thing that refuses it: `merge-tree p1 p2` is not the
  # automerge of a 3-way merge, so no content check covers it and the gate
  # declines to guess. Delete term (2) and this cell goes RED.
  rc=0
  out="$(check_range "$base_sha" "$m_octo_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "5065-octopus-webflow-three-parents" "$rc" "non-zero"
  if [ "$rc" -eq 0 ]; then
    echo "self-test FAILED: a THREE-parent web-flow merge was exempted (#5065 term 2). There is no two-parent automerge that covers an octopus merge's content, so exempting one is a content-blind exemption by another name:" >&2
    echo "$out" >&2
    failed=1
  elif ! grep -q "signature-not-verified" <<<"$out"; then
    echo "self-test FAILED: the #5065 octopus refusal did not name signature-not-verified:" >&2
    echo "$out" >&2
    failed=1
  fi

  # (local unsigned merge) An ENROLLED committer's `git merge --no-ff` with
  # signing off. 93 merges of this identity were exempted by `--no-merges`
  # purely for having two parents. Its identity is enrolled, so the ONLY
  # violation it can name is signature-not-verified — which makes it the
  # cleanest proof that the signature rule now reaches merges.
  rc=0
  out="$(check_range "$base_sha" "$m_local_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "5065-local-unsigned-no-ff-merge" "$rc" "non-zero"
  if [ "$rc" -eq 0 ]; then
    echo "self-test FAILED: a locally-created UNSIGNED merge under an enrolled identity was exempted (#5065). This is the 93-merge cohort the blanket carve-out passed without looking at:" >&2
    echo "$out" >&2
    failed=1
  else
    if ! grep -q "signature-not-verified" <<<"$out"; then
      echo "self-test FAILED: the #5065 local-unsigned-merge refusal did not name signature-not-verified:" >&2
      echo "$out" >&2
      failed=1
    fi
    if grep -q "unbound-.*-email" <<<"$out"; then
      echo "self-test FAILED: the #5065 local-unsigned-merge cell also flagged an email violation, so it is no longer isolating the signature rule:" >&2
      echo "$out" >&2
      failed=1
    fi
  fi

  # (pipe) A merge whose AUTHOR email contains a literal `|` MUST be REFUSED
  # and MUST be counted as EVALUATED, never exempted, and the walk must read
  # its REAL committer (enrolled) and its REAL `%G?` (N). This is the cell
  # that proves the exemption cannot be entered through a field the author
  # writes. If it ever reports rc=0, or reports the merge as exempted, or
  # names an unbound committer, email text is reaching another field again.
  rc=0
  out="$(check_range "$base_sha" "$m_pipe_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "5065-merge-author-email-pipe" "$rc" "non-zero"
  if [ "$rc" -eq 0 ]; then
    echo "self-test FAILED: a two-parent merge whose AUTHOR email carries a '|' was ACCEPTED (#5065). No author-written text may reach exemption term (1) (#5138):" >&2
    echo "$out" >&2
    failed=1
  else
    if ! grep -q "0 merges exempted" <<<"$out"; then
      echo "self-test FAILED: the #5065 pipe cell was refused, but the SCANNED line does not report ZERO exempted merges — so the refusal came from somewhere other than the merge being evaluated, and the exemption may still be reachable through a shifted field:" >&2
      echo "$out" >&2
      failed=1
    fi
    if ! grep -q "1 merges evaluated" <<<"$out"; then
      echo "self-test FAILED: the #5065 pipe cell was refused, but its merge was not counted as EVALUATED:" >&2
      echo "$out" >&2
      failed=1
    fi
    if ! grep -q "VIOLATION: $m_pipe_sha unbound-author-email" <<<"$out"; then
      echo "self-test FAILED: the #5065 pipe cell was refused, but not with an unbound-author-email line naming the merge itself, so the named reason does not match the shape under test:" >&2
      echo "$out" >&2
      failed=1
    fi
    if ! grep -qF "VIOLATION: $m_pipe_sha unbound-author-email (evil|$WEBFLOW_COMMITTER_EMAIL)" <<<"$out"; then
      echo "self-test FAILED: the #5065 pipe cell's author-email violation does not quote the WHOLE recorded email 'evil|$WEBFLOW_COMMITTER_EMAIL', so the walk split an email field (#5138):" >&2
      echo "$out" >&2
      failed=1
    fi
    if grep -q "unbound-committer-email" <<<"$out"; then
      echo "self-test FAILED: the #5065 pipe cell reported an unbound committer, but its real committer is the enrolled identity: email text has leaked into the committer field (#5138):" >&2
      echo "$out" >&2
      failed=1
    fi
    if ! grep -qF "VIOLATION: $m_pipe_sha signature-not-verified (%G?=N)" <<<"$out"; then
      echo "self-test FAILED: the #5065 pipe cell was not refused as unsigned with its REAL %G?=N, so the signature field was not read from git (#5138):" >&2
      echo "$out" >&2
      failed=1
    fi
  fi

  # (unpinned-key merge) The merge variant of LOAD-BEARING case (i): a
  # signature that fully verifies against a key in the SAME keyring that is
  # NOT pinned. MUST be refused SPECIFICALLY as signing-key-not-pinned —
  # proving the `%GF` pin, and not merely the identity check, reaches merges.
  rc=0
  out="$(check_range "$base_sha" "$m_rogue_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "5065-merge-signed-by-unpinned-key" "$rc" "non-zero"
  if [ "$rc" -eq 0 ]; then
    echo "self-test FAILED: a merge signed with an UNPINNED key present in the same keyring was exempted (#5065 + #5045): the OpenPGP path has widened to 'any key in the runner keyring' for merges:" >&2
    echo "$out" >&2
    failed=1
  elif ! grep -q "signing-key-not-pinned" <<<"$out"; then
    echo "self-test FAILED: the unpinned-key MERGE was refused, but NOT as signing-key-not-pinned, so the %GF pin is not what rejected it:" >&2
    echo "$out" >&2
    failed=1
  fi

  # (enrolled conflict merge) MUST PASS. The shape of the operator's 10 real
  # conflict-resolving merges (ae47ebfad 680a63afb ebddad8f5 f67c7bb83
  # 8e59b1835 b078f8d8e 544cf329e 6c6ca5152 c99f7163a 224d32d02): enrolled,
  # signed, and NOT reproducing under `merge-tree` because they are genuine
  # conflict resolutions. The tree test must never be applied to them.
  rc=0
  out="$(check_range "$base_sha" "$m_conflict_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "5065-enrolled-signed-conflict-merge-PASSES" "$rc" "0"
  if [ "$rc" -ne 0 ]; then
    echo "self-test FAILED: an enrolled, SIGNED conflict-resolving merge whose tree does not reproduce under merge-tree was REFUSED (rc=$rc). The content term applies ONLY to web-flow-committed merges; applying it to every merge blocks the operator's own landings (10 such merges in the measured cohort):" >&2
    echo "$out" >&2
    failed=1
  elif ! grep -q '1 merges evaluated' <<<"$out"; then
    echo "self-test FAILED: the enrolled conflict merge passed, but the SCANNED line does not report it as EVALUATED — so it may have passed by being exempted instead, which would re-open the carve-out:" >&2
    echo "$out" >&2
    failed=1
  fi

  # (all-exempt floor) A range made ENTIRELY of exempted web-flow merges is
  # NOT a pass. This is the #5047 floor rebuilt for #5065: before the rebuild
  # the floor counted non-merge commits, so a range of nothing but merges
  # would have reported PASS while evaluating nothing — the #2444 shape
  # wearing the carve-out's clothes.
  rc=0
  out="$(check_range "$side1_sha" "$m_exempt_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
  st_report "5065-all-exempt-range-floor" "$rc" "2"
  if [ "$rc" -ne 2 ]; then
    echo "self-test FAILED: a range consisting of nothing but EXEMPTED web-flow merges returned $rc, expected 2 (#5047 non-vacuity floor as rebuilt by #5065). A gate that reports OK after evaluating zero commits is the #2444 defect class:" >&2
    echo "$out" >&2
    failed=1
  elif ! grep -qF "EVALUATED ZERO commits and refuses to report PASS" <<<"$out"; then
    echo "self-test FAILED: the all-exempt range returned 2, but not from the evaluated-commit floor (#5276):" >&2
    echo "$out" >&2
    failed=1
  fi

  # (#5276) A range whose ONLY commit is one EVALUATED merge: the rebuilt
  # floor counts it, so the gate JUDGES it (0 signed, 1 unsigned) instead of
  # reporting INOPERATIVE. The pre-#5065 floor (non-merge commits only)
  # returns 2 on both; the mutant "floor counts scanned minus merges
  # evaluated" is the one these two cells kill.
  local mo_label mo_sha mo_expect mo_count
  for mo_label in signed unsigned; do
    if [ "$mo_label" = "signed" ]; then
      mo_sha="$m_only_signed_sha"
      mo_expect=0
    else
      mo_sha="$m_only_unsigned_sha"
      mo_expect=1
    fi
    mo_count="$(git -C "$repo" rev-list --count "${side1_sha}..${mo_sha}")"
    if [ "$mo_count" != "1" ]; then
      echo "self-test FAILED: the #5276 merge-only fixture must hold exactly ONE commit in ${side1_sha}..${mo_sha}; rev-list --count says '$mo_count'" >&2
      failed=1
    fi
    rc=0
    out="$(check_range "$side1_sha" "$mo_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
    st_report "5276-merge-only-range-$mo_label" "$rc" "$mo_expect"
    if [ "$rc" -ne "$mo_expect" ]; then
      echo "self-test FAILED: a range holding ONE evaluated ${mo_label} merge and no non-merge commit returned $rc, expected $mo_expect. The #5047 floor must count EVALUATED commits, not non-merge commits (#5276):" >&2
      echo "$out" >&2
      failed=1
    elif ! grep -qF "SCANNED: 1 commits (1 merges evaluated, 0 merges exempted" <<<"$out"; then
      echo "self-test FAILED: the #5276 ${mo_label} merge-only cell did not report its one merge as SCANNED and EVALUATED:" >&2
      echo "$out" >&2
      failed=1
    elif [ "$mo_label" = "unsigned" ] && ! grep -qF "VIOLATION: $mo_sha signature-not-verified (%G?=N)" <<<"$out"; then
      echo "self-test FAILED: the #5276 unsigned merge-only cell was not refused as signature-not-verified (%G?=N):" >&2
      echo "$out" >&2
      failed=1
    fi
  done

  # (probe: subcommand absent) The MANDATORY CAPABILITY PROBE. The runner is
  # bare `ubuntu-latest` with no container and no git pin, so the subcommand
  # term (3) depends on is not version-pinned. When it is unusable the gate is
  # INOPERATIVE (2) — never a PASS, and never "cannot compute, therefore
  # exempt". Driven through the MERGE_TREE_GIT seam with a shim that passes
  # every other subcommand through to real git and fails ONLY merge-tree, the
  # way a git too old to carry it does (rc=129 + usage).
  local shim_dir="$tmp/shims"
  mkdir -p "$shim_dir"
  cp "$REPO_ROOT/scripts/selftest-git-shim-merge-tree.py" "$shim_dir/shim.py"
  chmod +x "$shim_dir/shim.py"
  ln -sf shim.py "$shim_dir/git-absent-merge-tree"
  ln -sf shim.py "$shim_dir/git-lying-merge-tree"
  ln -sf shim.py "$shim_dir/git-twoline-merge-tree"
  ln -sf shim.py "$shim_dir/git-nonhex-merge-tree"
  ln -sf shim.py "$shim_dir/git-ghost-merge-tree"
  ln -sf shim.py "$shim_dir/git-terse-merge-tree"

  # The shim must RUN before any cell below can mean anything (#5277). Each
  # probe failure returns 2, and so does a shim that never executes (a lost
  # exec bit gives 126 at the probe's first `git init`). A pass-through call
  # proves the interpreter, the shebang and the exec bit; and every cell
  # below asserts the refusal text of the ONE probe assertion it targets, so
  # a shim that stopped running cannot keep them green.
  local shim_rc=0
  "$shim_dir/git-absent-merge-tree" --version >/dev/null 2>&1 || shim_rc=$?
  if [ "$shim_rc" -ne 0 ]; then
    echo "self-test FAILED: the git shim at '$shim_dir/shim.py' does not execute (pass-through 'git --version' returned $shim_rc), so every shim-driven cell would return 2 for the wrong reason (#5277)" >&2
    failed=1
  fi

  # (probe cells) The MANDATORY CAPABILITY PROBE, one cell per refusal it
  # can make. Each row is: cell name, the git it is handed, and the refusal
  # text of the assertion that must fire.
  #   -absent   rc=129 + usage, a git too old to carry the subcommand.
  #   -lies     rc 0 and a REAL tree oid that is one parent's tree, not the
  #             merge of both: only the content assertion refuses it, which
  #             is what makes that assertion load-bearing.
  #   -binary-missing  no git at all: refused at fixture creation.
  #   5277-two-lines / -non-hex / -ghost-oid  rc 0 with two lines, rc 0
  #             with a non-hex line, rc 0 with a 40-hex oid naming no object:
  #             each reaches exactly one of the probe's shape assertions,
  #             which no other cell reaches.
  local probe_row probe_cell probe_git probe_reason
  for probe_row in \
    "5065-probe-merge-tree-absent|$shim_dir/git-absent-merge-tree|is INOPERATIVE: it returned rc=129" \
    "5065-probe-merge-tree-lies|$shim_dir/git-lying-merge-tree|does not carry BOTH sides of a known-clean merge" \
    "5065-probe-git-binary-missing|$tmp/no-such-git-binary|could not create the hermetic merge-tree capability-probe fixture" \
    "5277-probe-merge-tree-two-lines|$shim_dir/git-twoline-merge-tree|did not print exactly one line" \
    "5277-probe-merge-tree-non-hex|$shim_dir/git-nonhex-merge-tree|which is not a 40-hex tree oid" \
    "5277-probe-merge-tree-ghost-oid|$shim_dir/git-ghost-merge-tree|which does not resolve as a TREE object"; do
    IFS='|' read -r probe_cell probe_git probe_reason <<<"$probe_row"
    rc=0
    out="$(check_range "$base_sha" "$clean_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" "$probe_git" 2>&1)" || rc=$?
    st_report "$probe_cell" "$rc" "2"
    if [ "$rc" -ne 2 ]; then
      echo "self-test FAILED: with the merge-tree capability probe handed '$probe_git' the gate returned $rc over a range it would otherwise PASS, expected 2 (INOPERATIVE). 'I could not compute the automerge' must never resolve to a pass or to an exemption:" >&2
      echo "$out" >&2
      failed=1
    elif ! grep -qF -- "$probe_reason" <<<"$out"; then
      echo "self-test FAILED: the $probe_cell cell returned 2, but not from the probe assertion it targets ('$probe_reason'), so that assertion is not what refused (#5277):" >&2
      echo "$out" >&2
      failed=1
    fi
  done

  # (#5278) The web-flow conflict merge, through real git and through the
  # terse shim (real merge-tree, real rc, FIRST line only). Real git kills
  # "take the first line as the tree" (mutant A4); the terse shim, whose
  # conflicted output is a single valid oid at rc=1, is what makes the rc
  # check itself load-bearing (mutants A1 to A3): without it the conflicted
  # oid passes the one-line and 40-hex checks, equals `%T`, and is exempted.
  local wfc_git
  for wfc_git in git "$shim_dir/git-terse-merge-tree"; do
    rc=0
    out="$(check_range "$base_sha" "$m_wf_conflict_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" "$wfc_git" 2>&1)" || rc=$?
    if [ "$wfc_git" = "git" ]; then
      st_report "5278-webflow-conflict-merge-real-git" "$rc" "1"
    else
      st_report "5278-webflow-conflict-merge-terse-git" "$rc" "1"
    fi
    if [ "$rc" -ne 1 ]; then
      echo "self-test FAILED: an UNSIGNED web-flow merge of CONFLICTING parents, recording the conflicted tree, returned $rc through '$wfc_git', expected 1. A merge whose automerge is not clean is never exempt (#5278):" >&2
      echo "$out" >&2
      failed=1
    elif ! grep -qF "1 merges evaluated, 0 merges exempted" <<<"$out" \
      || ! grep -qF "VIOLATION: $m_wf_conflict_sha signature-not-verified (%G?=N)" <<<"$out"; then
      echo "self-test FAILED: the #5278 cell through '$wfc_git' was refused, but its merge was not EVALUATED and refused as unsigned:" >&2
      echo "$out" >&2
      failed=1
    fi
  done

  # (#5138 non-merge shift, two pipes) Unsigned, single parent, author email
  # `dev@example.test|dev@example.test|G`, committer email = the PINNED
  # OpenPGP fingerprint. Fail-OPEN at bdc0723ae (rc=0). MUST be refused, and
  # the refusal MUST quote the commit's REAL `%G?` (N), which proves the walk
  # read the signature field from git rather than from an email.
  local nm_label
  # The one-pipe shape: author email `dev@example.test|dev@example.test`,
  # committer email `G|<pinned>`, the same record reached with a pipe in each
  # email. The author-only shape: f2r's, every shifted value in `%ae` and an
  # enrolled committer.
  for nm_label in two-pipe one-pipe author-only; do
    case "$nm_label" in
      two-pipe) nm_sha="$nm_shift2_sha" ;;
      one-pipe) nm_sha="$nm_shift1_sha" ;;
      *) nm_sha="$nm_shift3_sha" ;;
    esac
    rc=0
    out="$(check_range "$base_sha" "$nm_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" 2>&1)" || rc=$?
    st_report "5138-nonmerge-${nm_label}-email-shift" "$rc" "1"
    if [ "$rc" -ne 1 ]; then
      echo "self-test FAILED: an UNSIGNED non-merge commit whose email fields carry '|' returned $rc, expected 1 (#5138). The walk must read the commit's own %G?/%GF, never text an author wrote into an email:" >&2
      echo "$out" >&2
      failed=1
    elif ! grep -qF "VIOLATION: $nm_sha signature-not-verified (%G?=N)" <<<"$out"; then
      echo "self-test FAILED: the #5138 ${nm_label} shift cell was refused, but not as signature-not-verified with the commit's REAL %G?=N, so the walk is still reading a shifted field:" >&2
      echo "$out" >&2
      failed=1
    fi
  done

  # (#5272 walk integrity) The walk is the gate's only source of commits. A
  # walk that dies partway, ends short with a clean status, tears its last
  # record, carries a field git never emits, ends inside an unterminated
  # field, or whose producer dies before recording git's exit status must be
  # INOPERATIVE (2) —
  # never a PASS over the commits it happened to read. Range base..side1 is
  # TWO enrolled, SSH-signed commits that PASS through a healthy walk (the
  # control row), so every non-2 result below is the walk damage leaking out.
  ln -sf shim.py "$shim_dir/git-truncated-log"
  ln -sf shim.py "$shim_dir/git-short-log"
  ln -sf shim.py "$shim_dir/git-torn-log"
  ln -sf shim.py "$shim_dir/git-malformed-log"
  ln -sf shim.py "$shim_dir/git-trailing-log"
  ln -sf shim.py "$shim_dir/git-orphan-log"
  rc=0
  out="$(check_range "$base_sha" "$side1_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" git git 2>&1)" || rc=$?
  st_report "5272-walk-control-two-commits" "$rc" "0"
  if [ "$rc" -ne 0 ] || ! grep -q '^SCANNED: 2 commits' <<<"$out"; then
    echo "self-test FAILED: the #5272 walk control range (two enrolled, SSH-signed commits) did not PASS with SCANNED: 2, so the walk-damage cells below would prove nothing:" >&2
    echo "$out" >&2
    failed=1
  fi
  local walk_mode walk_reason
  for walk_mode in truncated-log short-log torn-log malformed-log trailing-log orphan-log; do
    rc=0
    out="$(check_range "$base_sha" "$side1_sha" "$signers" "$repo" "$gpg_signers" "" "$gpg_home" git "$shim_dir/git-$walk_mode" 2>&1)" || rc=$?
    st_report "5272-walk-$walk_mode" "$rc" "2"
    # The exit code alone is not the assertion (#5277): a shim that never
    # ran also yields 2. Each damage mode has exactly one refusal reason, and
    # the truncated mode must quote the shim's OWN exit status (128).
    case "$walk_mode" in
      truncated-log) walk_reason="a partial walk is not a verdict" ;;
      short-log) walk_reason="a short walk is not a verdict" ;;
      torn-log) walk_reason="a torn record is not a verdict" ;;
      trailing-log) walk_reason="ended with an unterminated field" ;;
      orphan-log) walk_reason="an unconfirmed walk is not a verdict" ;;
      *) walk_reason="malformed commit-walk record" ;;
    esac
    if [ "$rc" -ne 2 ]; then
      echo "self-test FAILED: a commit walk damaged as '$walk_mode' returned $rc, expected 2 (INOPERATIVE). A gate that judges only the records it happened to read and reports the result is the #2444 defect class (#5272):" >&2
      echo "$out" >&2
      failed=1
    elif ! grep -qF "$walk_reason" <<<"$out"; then
      echo "self-test FAILED: the '$walk_mode' walk cell returned 2 but not for the reason it pins ('$walk_reason'), so the damage was never parsed:" >&2
      echo "$out" >&2
      failed=1
    elif [ "$walk_mode" = "truncated-log" ] && ! grep -qF "exited 128;" <<<"$out"; then
      echo "self-test FAILED: the truncated walk cell did not report the shim's exit status 128, so the shim did not run as the walk:" >&2
      echo "$out" >&2
      failed=1
    fi
  done

  # (k) The SHIPPED registries and the SHIPPED key material agree, and a
  # HERMETIC keyring really can be built from them (#5045) — no ephemeral
  # stand-in, no `prepared_gnupghome` seam. This is what proves the import
  # step the CI job depends on is not vapour, and that
  # enrolled-gpg-commit-signers.txt has not drifted from its .asc sibling.
  rc=0
  prepare_hermetic_gnupghome "$GPG_PUBKEY_FILE_DEFAULT" "$GPG_SIGNERS_FILE_DEFAULT" \
    "$tmp/shipped-gnupghome" >/dev/null 2>&1 || rc=$?
    st_report "k" "$rc" "0"
  if [ "$rc" -ne 0 ]; then
    echo "self-test FAILED: a hermetic keyring could not be built from the SHIPPED $GPG_PUBKEY_FILE_DEFAULT + $GPG_SIGNERS_FILE_DEFAULT (rc=$rc)" >&2
    prepare_hermetic_gnupghome "$GPG_PUBKEY_FILE_DEFAULT" "$GPG_SIGNERS_FILE_DEFAULT" "$tmp/shipped-gnupghome" >&2 || true
    failed=1
  fi
  local shipped_pinned
  shipped_pinned="$(pinned_fingerprints "$SIGNERS_FILE_DEFAULT" "$GPG_SIGNERS_FILE_DEFAULT")"
  if ! assert_pinned_fingerprints_usable "$shipped_pinned" >/dev/null 2>&1; then
    echo "self-test FAILED: the SHIPPED pinned fingerprint set is missing one of its two halves:" >&2
    printf '%s\n' "$shipped_pinned" >&2
    failed=1
  fi

  # (l) `run_gate`'s OWN dispositions, which none of the check_range cases
  # above can reach because they call check_range directly: the
  # non-pull_request N/A skip, and a pull_request event carrying no
  # PR_BASE_SHA. Sibling precedent: check-cert-expiry.sh's self-test case (k),
  # which covers the identical fail-closed shape for the identical env var.
  # Without this case the gate's entry point — the part CI actually invokes —
  # had no self-test at all, so a wiring regression there (an N/A skip that
  # swallowed a real pull_request, or an unset base that reported PASS) would
  # not have been caught by anything.
  local gate_self="${BASH_SOURCE[0]}"
  rc=0
  out="$(GITHUB_EVENT_NAME=push bash "$gate_self" 2>&1)" || rc=$?
  st_report "l-na" "$rc" "0"
  if [ "$rc" -ne 0 ]; then
    echo "self-test FAILED: a non-pull_request event did not report N/A cleanly (rc=$rc):" >&2
    echo "$out" >&2
    failed=1
  elif ! grep -q "N/A" <<<"$out"; then
    echo "self-test FAILED: a non-pull_request event exited 0 without saying N/A, so a silent skip is indistinguishable from a PASS:" >&2
    echo "$out" >&2
    failed=1
  fi
  rc=0
  out="$(env -u PR_BASE_SHA GITHUB_EVENT_NAME=pull_request bash "$gate_self" 2>&1)" || rc=$?
  st_report "l-unset-base" "$rc" "2"
  if [ "$rc" -ne 2 ]; then
    echo "self-test FAILED: a pull_request event with PR_BASE_SHA unset returned $rc, expected 2 (fail-closed, inoperative — NOT 0 and NOT 1):" >&2
    echo "$out" >&2
    failed=1
  fi

  if [ "$failed" -ne 0 ]; then
    exit 2
  fi
  echo "check-commit-signing-posture self-test OK: (a) clean enrolled+SSH-signed commit passes; (b) #2486 identity-drift shape (unbound email, unsigned) rejected naming both violations; (c) enrolled-but-unsigned commit rejected (signature check isolated from email check); (d) enrolled-email-claimed-with-rogue-SSH-key-signature rejected (verification is against the registry, not mere signature presence); (e) unresolvable commit range fails closed with exit 2; (f) missing enrolled-signers registry fails closed; (g) empty enrolled-signers registry fails closed; (g2) missing AND zero-fingerprint OpenPGP registries fail closed; (h) a commit signed with the PINNED OpenPGP key PASSES alongside an SSH-signed commit in the same range (#5045); (i) a fully-verifying OpenPGP signature from an UNPINNED key in the SAME keyring is rejected as signing-key-not-pinned — LOAD-BEARING, the only guard against the OpenPGP path widening to 'any key in the runner keyring'; (j) an EMPTY range fails closed with exit 2 (#5047 non-vacuity floor, which previously PASSED); (k) a hermetic keyring builds from the SHIPPED registry + .asc material and the shipped pin carries both halves; (l) run_gate's own entry-point dispositions — a non-pull_request event reports N/A at exit 0, and a pull_request event with PR_BASE_SHA unset fails closed at exit 2 (inoperative), never 0 and never 1. (f)/(g)/(g2) prove the fail-closed-on-registry-loss property is an EXPLICIT assertion (assert_registry_usable / assert_gpg_registry_usable / assert_pinned_fingerprints_usable), not incidental pipefail behavior. #5065 merge-evaluation cases, per 5-agent vote (4d3ea1c5) — merges are no longer dropped by --no-merges, they are evaluated unless all three exemption terms hold: (7a) a two-parent web-flow-identity merge that is UNSIGNED (%G?=N) and whose tree is NOT the clean automerge of its two parents is REFUSED naming signature-not-verified; (7b) the same shape carrying a signature that does not verify (%G?=E with a populated %GK — the realistic shape, since the real web-flow cohort reads E) is REFUSED the same way, so a future '%G? != N' filter cannot silently reopen the hole 7a alone would catch; (7c) LOAD-BEARING POSITIVE — a two-parent web-flow-identity merge whose recorded tree EQUALS git merge-tree --write-tree p1 p2 stays EXEMPT and is reported as exempted, pinning the adopted predicate's zero-cost property AND the named residual in both directions; (5065-octopus) a web-flow merge with THREE parents whose tree EQUALS the clean automerge of its first two is EVALUATED, not exempted: terms (1) and (3) hold, so the parent-count term alone refuses it (#5271); (5065-local) a non-web-flow unsigned two-parent merge is REFUSED naming signature-not-verified and no email violation — this is the red-first cell the identity narrowing needs, and it is impossible to satisfy by dropping merges; (5065-unpinned-key) a merge whose OpenPGP signature fully verifies (%G?=G) from a key in the SAME keyring that is NOT pinned is REFUSED as signing-key-not-pinned, extending case (i) across the merge boundary; (5065-conflict) an enrolled, SSH-signed, conflict-resolving merge whose tree differs from the automerge PASSES and is counted as EVALUATED — this is what proves the operator's own conflict resolutions are not false-refused and that a PASS can never come from an exemption; (5065-floor) a range whose only commits are exempted web-flow merges fails CLOSED with exit 2, because the rebuilt #5047 non-vacuity floor counts EVALUATED commits rather than non-merge commits and an all-exempt range is not a pass; (5065-pipe-author-email) a two-parent merge whose AUTHOR email is 'evil|noreply@github.com' and whose real committer is enrolled is REFUSED, counted as EVALUATED, quoted whole as an unbound author email, with no committer violation — no author-written text reaches exemption term (1); (5138-nonmerge-two-pipe / -one-pipe / -author-only) three UNSIGNED non-merge commits whose email fields carry '|' and copy the pinned fingerprint are REFUSED as signature-not-verified (%G?=N), because the walk record is NUL-delimited and no email text can occupy a signature field; (5272-walk-truncated / -short / -torn / -malformed / -trailing / -orphan) a commit walk that exits non-zero, ends short, tears its last record, carries a value git never emits, ends inside an unterminated field, or whose producer dies before recording git's exit status is INOPERATIVE (exit 2) with its named reason, against a two-commit control range that PASSES through the same seam; (5065-probe-absent / -lies / -missing, 5277-probe-two-lines / -non-hex / -ghost-oid) the MANDATORY merge-tree capability probe exits 2 (INOPERATIVE) when the subcommand is absent, returns a well-formed but WRONG tree oid, cannot be executed at all, prints two lines, prints a non-hex line, or prints an oid naming no object, and each cell asserts the refusal text of the one probe assertion it targets after a pass-through call proves the shim executes (#5277) — the gate never degrades to cannot-compute-therefore-exempt; (5276-merge-only-range-signed / -unsigned) a range whose only commit is one evaluated local merge is JUDGED (0 signed, 1 unsigned), never INOPERATIVE, because the floor counts evaluated commits, not non-merge commits; (5278-webflow-conflict-merge-real-git / -terse-git) an unsigned web-flow merge of CONFLICTING parents recording the conflicted tree is EVALUATED and refused, through real git and through a merge-tree that prints only the conflicted oid at rc=1, so the rc check of automerge_tree is load-bearing."
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
