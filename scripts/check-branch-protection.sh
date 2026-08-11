#!/usr/bin/env bash
# check-branch-protection.sh — one-declaration-source gate for the required
# status-check set (#2534).
#
# THE RULE. `.github/branch-protection.yml` MUST NOT declare a `required_checks`
# key. Live branch protection lives on the GitHub API and is the authoritative
# artefact; the in-repo DECLARATION of the required-status-check set is
# `scripts/qc-allowlists/required-contexts-release.txt` (verified by
# scripts/check-required-contexts.sh). A second, hand-maintained list of check
# names inside branch-protection.yml is EXACTLY how #2443 happened: that file
# once carried per-branch `required_checks:` lists that were wrong in both
# directions (over-declared unrequireable `<workflow> / <job>` strings AND
# omitting 22 live-required contexts), while asserting `enforce_admins: true`
# over them — a committed policy file MANUFACTURING assurance an enterprise
# reviewer reads instead of the API.
#
# #2443 reconciled the file to a single POINTER (`required_checks_declaration:`)
# at the one true declaration. This gate keeps the regressive `required_checks:`
# key from ever re-landing. It fails CLOSED if the file is missing.
#
# WHAT IS NOT A VIOLATION. The pointer key `required_checks_declaration:` is the
# intended shape and MUST pass — the match is anchored so `required_checks`
# followed by `_declaration` (or any other identifier character) is not a hit;
# only a bare `required_checks:` key (optionally a `- required_checks:` list
# item) fails.
#
# Exit codes: 0 clean · 1 violation · 2 usage / self-test failure.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BP_FILE_DEFAULT="$REPO_ROOT/.github/branch-protection.yml"

# A YAML key `required_checks:` — optionally a `- required_checks:` list item —
# at any indentation. `[^_[:alnum:]]`-style boundary after the name is enforced
# by requiring optional whitespace then `:` IMMEDIATELY, so
# `required_checks_declaration:` (next char `_`) can never match.
VIOLATION_RE='^[[:space:]]*(-[[:space:]]+)?required_checks[[:space:]]*:'

check_file() {
  local f="$1"
  if [ ! -f "$f" ]; then
    echo "check-branch-protection: ERROR — $f not found (fail-closed)" >&2
    return 1
  fi
  local hits
  # -v skips YAML comments so a `# ... required_checks: ...` prose line never
  # trips the gate; the declaration itself is never a comment.
  hits="$(grep -nE "$VIOLATION_RE" "$f" | grep -vE '^[0-9]+:[[:space:]]*#' || true)"
  if [ -n "$hits" ]; then
    echo "check-branch-protection: VIOLATION — $f declares a bare 'required_checks' key:" >&2
    echo "$hits" | sed 's/^/    /' >&2
    echo "" >&2
    echo "  The required-status-check set has ONE declaration source:" >&2
    echo "    scripts/qc-allowlists/required-contexts-release.txt" >&2
    echo "  (verified by scripts/check-required-contexts.sh). Do NOT list check" >&2
    echo "  names in branch-protection.yml — see #2443 / #2534." >&2
    return 1
  fi
  return 0
}

self_test() {
  local tmp
  tmp="$REPO_ROOT/.local-runs/check-branch-protection-selftest.$$"
  mkdir -p "$tmp"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  # (1) The pointer-only shape (the reconciled #2443 form) MUST PASS.
  cat > "$tmp/clean.yml" <<'YML'
version: 2
required_checks_declaration:
  release_branches:
    file: scripts/qc-allowlists/required-contexts-release.txt
branches:
  - pattern: release/**
    enforce_admins: true
# A prose mention of required_checks: in a comment must not trip the gate.
YML
  if ! check_file "$tmp/clean.yml" >/dev/null 2>&1; then
    echo "self-test FAILED: clean pointer-only file was rejected" >&2
    exit 2
  fi

  # (2) A bare per-branch `required_checks:` key MUST FAIL (the #2443 regression).
  cat > "$tmp/dirty.yml" <<'YML'
version: 2
branches:
  - pattern: release/**
    required_checks:
      - "Check (ubuntu-latest)"
YML
  if check_file "$tmp/dirty.yml" >/dev/null 2>&1; then
    echo "self-test FAILED: a bare required_checks key was NOT rejected" >&2
    exit 2
  fi

  # (3) A `- required_checks:` list-item form MUST FAIL too.
  cat > "$tmp/dirty2.yml" <<'YML'
version: 2
- required_checks: []
YML
  if check_file "$tmp/dirty2.yml" >/dev/null 2>&1; then
    echo "self-test FAILED: a '- required_checks:' list item was NOT rejected" >&2
    exit 2
  fi

  # (4) A missing file MUST FAIL closed.
  if check_file "$tmp/does-not-exist.yml" >/dev/null 2>&1; then
    echo "self-test FAILED: a missing file passed (should fail closed)" >&2
    exit 2
  fi

  echo "check-branch-protection self-test OK (pointer passes; bare key, list-item, and missing file all fail)"
}

case "${1:-}" in
  --self-test)
    self_test
    ;;
  "")
    if check_file "$BP_FILE_DEFAULT"; then
      echo "check-branch-protection: OK — .github/branch-protection.yml declares no bare 'required_checks' key"
    else
      exit 1
    fi
    ;;
  *)
    echo "usage: $(basename "$0") [--self-test]" >&2
    exit 2
    ;;
esac
