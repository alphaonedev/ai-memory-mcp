#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# check-git-dependency-sources.sh — FAIL-CLOSED supply-chain gate: no cargo
# dependency in this repo may resolve from a `git` source. Registry
# (crates.io) or in-tree `path = "vendor/<crate>"` only.
#
# THE DEFECT CLASS THIS CLOSES (#2050, and its 15-day silent recurrence #2512).
#
# `Cargo.toml` carried, under `[patch.crates-io]`:
#
#     paste = { git = "https://github.com/alphaonedev/paste", rev = "6a30252" }
#
# a fork-pin adopted as the RUSTSEC-2024-0436 workaround (`paste` 1.x is
# unmaintained). On 2026-07-15 that pin stopped resolving:
#
#     Updating git repository `https://github.com/alphaonedev/paste`
#     error: failed to load source for dependency `paste`
#       unable to update https://github.com/alphaonedev/paste?rev=6a30252#6a302522
#       revision 6a302522990cbfd9de4e0c61d91854622f7b2999 not found
#
# The `alphaonedev/paste` repository had been DELETED outright (`git ls-remote`
# → "Repository not found"; `GET /repos/alphaonedev/paste` → 404). Nothing in
# this repo changed. A dependency edge that had been green for months became
# permanently unresolvable because of an out-of-band action in ANOTHER
# repository — one no CI signal here was watching.
#
# THREE PROPERTIES MAKE THIS CLASS PARTICULARLY BAD, AND ALL THREE FIRED:
#
#   (1) IT IS UNILATERAL AND IRREVERSIBLE FROM HERE. A git-source pin's
#       availability is controlled by whoever owns that remote. GitHub does not
#       preserve a deleted repository's objects, and cargo has no fallback
#       source for a git dependency the way it does for a yanked registry
#       crate. `rev` pinning buys immutability of CONTENT, never of EXISTENCE.
#
#   (2) IT PRESENTS AS FLAKE, THEN AS NOTHING. Jobs with a warm
#       `~/.cargo/git/db` cache kept passing; only cold resolves failed, so it
#       first read as intermittent CI (#2050 was filed against "PRs #2037 and
#       #2043" before the shared cause was found). Every developer machine
#       stayed green indefinitely — this repo's own cache still holds the
#       orphaned commit today. A gate that only fires on a cold runner is a
#       gate that does not fire.
#
#   (3) IT SURVIVED ITS OWN FIX FOR 15 DAYS. #2051 fixed it on
#       `release/v1.0.0` (vendored `paste` 1.0.15 to `vendor/paste/`) and the
#       fix was verified by PR-time CI on that branch. But `main` — the
#       DEFAULT branch, and therefore the ONLY branch GitHub runs `schedule:`
#       workflows from — never received it. `postgres-parity-nightly` has been
#       hard-red on the identical error every night since 2026-07-15, and it
#       was rediscovered from scratch on 2026-07-30 as #2512. The class is
#       therefore not just "a pin can vanish" but "a pin can vanish on a
#       branch nobody is reading, and stay vanished".
#
# WHY A BAN RATHER THAN A LIVE REACHABILITY PROBE. Probing every git remote at
# PR time would make this repo's CI depend on third-party availability — it
# would go red for network reasons and teach reviewers to ignore it. A ban is
# static, offline, deterministic, and expresses the actual rule: third-party
# source we depend on lives in-tree under `vendor/` where it is reviewable,
# diffable, and rebuildable with no network at all. That is the same posture
# #2051 adopted for `paste`; this gate makes it structural instead of a
# convention recorded in a manifest comment.
#
# DATA-INTEGRITY posture (North Star): DEGRADE, NEVER CORRUPT. The failure
# being prevented is not a wrong answer, it is a build that cannot be
# reproduced — which erases the ability to rebuild, audit, or bisect any
# artifact this repo has ever shipped. Refusing the un-vendorable edge up front
# is the fail-closed choice; discovering it on a cold runner months later is
# not.
#
# SCOPE. Every `Cargo.toml` and `Cargo.lock` tracked in this repo, excluding
# `target/` and `.local-runs/` build output. `vendor/` IS scanned: a vendored
# crate that itself reaches for a git source re-imports the whole problem.
#
# EXIT CODES: 0 = clean, 1 = a git source found (offenders printed),
# 2 = usage / self-test failure.
set -euo pipefail

ROOT="${AI_MEMORY_GITDEP_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ALLOW_FILE="${AI_MEMORY_GITDEP_ALLOW:-${ROOT}/scripts/qc-allowlists/git-dependency-sources-allow.txt}"

# A manifest git source. Matches both spellings cargo accepts:
#   inline table : foo = { git = "https://…", rev = "…" }
#   section form : [dependencies.foo]\ngit = "https://…"
# The leading class keeps `codegit = "…"`-style keys from matching, and
# `repository = "…"` / `homepage = "…"` never match because the key differs.
MANIFEST_RE='(^|[[:space:]{,])git[[:space:]]*=[[:space:]]*"'
# A lockfile git source. `Cargo.lock` records these as
#   source = "git+https://github.com/owner/repo?rev=abc#abcdef…"
LOCK_RE='^[[:space:]]*source[[:space:]]*=[[:space:]]*"git\+'

# Allowlist entries are `<repo-relative-path>:<matched-key-or-crate>` lines;
# `#` comments and blank lines ignored. Currently EMPTY by design.
allowed() {
  local needle="$1"
  [ -f "$ALLOW_FILE" ] || return 1
  grep -vE '^[[:space:]]*(#|$)' "$ALLOW_FILE" 2>/dev/null | grep -qxF "$needle"
}

# scan <dir> — prints offenders to stderr; returns 0 when CLEAN, 1 when a git
# source was found. (Same return convention as check-cloud-init-ascii.sh.)
#
# NOTE ON THE `.local-runs` EXCLUSION BELOW — it is deliberately ANCHORED to
# `$dir` (`"${dir}/.local-runs/*"`) rather than written as the free glob
# `'*/.local-runs/*'`. `--self-test` stages its fixtures under
# `$ROOT/.local-runs/` (project hard rule: scratch under the repo, never system
# /tmp), so a free glob would make every staged fixture INVISIBLE to this
# function — the three violation assertions would then pass VACUOUSLY and the
# gate would report a green self-test while detecting nothing. Anchoring keeps
# both properties: the live scan (`$dir` == `$ROOT`) still skips the real
# scratch directory, and a fixture root nested inside it is still scanned.
# Do not "simplify" this back to a free glob.
scan() {
  local dir="$1" found=0 f rel line

  while IFS= read -r f; do
    rel="${f#"${dir}"/}"
    while IFS= read -r line; do
      allowed "${rel}:${line%%:*}" && continue
      found=1
      echo "GIT SOURCE in ${rel}:${line}" >&2
    done < <(grep -nE "$MANIFEST_RE" "$f" || true)
  done < <(find "$dir" -type f -name Cargo.toml \
             -not -path '*/target/*' -not -path "${dir}/.local-runs/*" \
             -not -path '*/.git/*' | sort)

  while IFS= read -r f; do
    rel="${f#"${dir}"/}"
    while IFS= read -r line; do
      allowed "${rel}:${line%%:*}" && continue
      found=1
      echo "GIT SOURCE in ${rel}:${line}" >&2
    done < <(grep -nE "$LOCK_RE" "$f" || true)
  done < <(find "$dir" -type f -name Cargo.lock \
             -not -path '*/target/*' -not -path "${dir}/.local-runs/*" \
             -not -path '*/.git/*' | sort)

  return $found
}

if [ "${1:-}" = "--self-test" ]; then
  # Project hard rule: scratch UNDER the repo, never system /tmp (zero-strike).
  # Mirrors `check-migration-ladder.sh` / `check-required-contexts.sh`, the two
  # newest gates. `.local-runs/` is gitignored (`.gitignore:53` — `/.local-runs/*`),
  # so a staged fixture can never be committed, and `$$` keeps concurrent runs
  # from colliding.
  tmp="${ROOT}/.local-runs/gitdep-selftest-$$"
  mkdir -p "$tmp"
  trap 'rm -rf "$tmp"' EXIT

  # (1) The exact #2050 shape: a `[patch.crates-io]` git+rev pin.
  mkdir -p "$tmp/bad-manifest"
  cat > "$tmp/bad-manifest/Cargo.toml" <<'EOF'
[package]
name = "probe"
version = "0.0.0"

[patch.crates-io]
paste = { git = "https://github.com/alphaonedev/paste", rev = "6a30252" }
EOF
  if scan "$tmp/bad-manifest" 2>/dev/null; then
    echo "SELF-TEST FAIL: gate missed an inline git+rev dependency (#2050 shape)" >&2
    exit 2
  fi

  # (2) Section form — `[dependencies.foo]` + a bare `git =` line.
  mkdir -p "$tmp/bad-section"
  cat > "$tmp/bad-section/Cargo.toml" <<'EOF'
[dependencies.somedep]
git = "https://example.invalid/somedep"
branch = "main"
EOF
  if scan "$tmp/bad-section" 2>/dev/null; then
    echo "SELF-TEST FAIL: gate missed a [dependencies.x] section-form git source" >&2
    exit 2
  fi

  # (3) Lockfile form — the resolved `git+` source that outlives a reverted
  #     manifest edit. A Cargo.toml fix with a stale Cargo.lock still breaks
  #     `--locked` cold resolves, so the lock must be scanned independently.
  mkdir -p "$tmp/bad-lock"
  cat > "$tmp/bad-lock/Cargo.lock" <<'EOF'
version = 3

[[package]]
name = "paste"
version = "1.0.15"
source = "git+https://github.com/alphaonedev/paste?rev=6a30252#6a302522990cbfd9de4e0c61d91854622f7b2999"
EOF
  if scan "$tmp/bad-lock" 2>/dev/null; then
    echo "SELF-TEST FAIL: gate missed a Cargo.lock git+ source" >&2
    exit 2
  fi

  # (4) Clean control — the post-#2051 vendored shape plus keys that merely
  #     LOOK like git sources. None of these may trip the gate.
  mkdir -p "$tmp/good"
  cat > "$tmp/good/Cargo.toml" <<'EOF'
[package]
name = "probe"
version = "0.0.0"
repository = "https://github.com/alphaonedev/ai-memory-mcp"
homepage = "https://github.com/alphaonedev/ai-memory-mcp"

[dependencies]
serde = "1"

[patch.crates-io]
paste = { path = "vendor/paste" }
EOF
  cat > "$tmp/good/Cargo.lock" <<'EOF'
version = 3

[[package]]
name = "paste"
version = "1.0.15"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
EOF
  if ! scan "$tmp/good" 2>/dev/null; then
    echo "SELF-TEST FAIL: gate flagged the clean vendored/registry control" >&2
    exit 2
  fi

  echo "check-git-dependency-sources self-test OK (3 violation shapes caught, clean control passed)"
  exit 0
fi

if [ "${1:-}" != "" ]; then
  echo "usage: $(basename "$0") [--self-test]" >&2
  exit 2
fi

if scan "$ROOT"; then
  echo "check-git-dependency-sources: OK (no git-source cargo dependencies; registry + vendor/ only)"
  exit 0
else
  echo "" >&2
  echo "FAIL (#2050 / #2512): cargo dependencies must NOT resolve from a git source." >&2
  echo "" >&2
  echo "A git-source pin's EXISTENCE is controlled by another repository's owner;" >&2
  echo "\`rev\` pinning makes the content immutable but not the remote. When" >&2
  echo "\`alphaonedev/paste\` was deleted, rev 6a30252 became unfetchable forever and" >&2
  echo "every cold cargo resolve in this repo failed — while warm-cache machines and" >&2
  echo "warm CI jobs kept reporting green, so it read as flake for days." >&2
  echo "" >&2
  echo "Use one of:" >&2
  echo "  * crates.io   — \`foo = \"1.2\"\` (registry crates are immutable once published)" >&2
  echo "  * in-tree     — vendor the source under \`vendor/<crate>/\` and depend on it" >&2
  echo "                  with \`path = \"vendor/<crate>\"\`, as #2051 did for \`paste\`." >&2
  echo "                  Reviewable, diffable, and resolvable with no network." >&2
  echo "" >&2
  echo "If a git source is genuinely unavoidable, add a dated justification line to" >&2
  echo "  scripts/qc-allowlists/git-dependency-sources-allow.txt" >&2
  echo "(ratchet: entries may only be REMOVED) and say in the PR who guarantees that" >&2
  echo "remote stays reachable for the lifetime of every artifact built from it." >&2
  exit 1
fi
