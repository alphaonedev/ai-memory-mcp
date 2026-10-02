#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/check-release-features.sh - release feature-set guard (#4480).
#
# THE DEFECT CLASS. A shipped artifact lacks a capability its docs advertise:
# release.yml built `--features sal` only, so the advertised PostgreSQL + AGE +
# pgvector tier was absent from every release binary (#4480, the #2676 /
# #2728 / #3996 class). The durable control is one declaration and checks that
# the build, the assertion, the SBOM, the image, the proof job and the docs all
# follow it - and that a BROKEN declaration fails the build instead of silently
# degrading it (bash -e does not abort on a failed command substitution that
# sits inside another command's arguments).
#
# Fails (exit 1) when ANY of:
#   1. scripts/release-features.sh does not declare `sal-postgres`;
#   2. release.yml / release-shape.yml / the Dockerfile use the declaration
#      INLINE (`cmd "$(bash scripts/release-features.sh)"`): every use must be
#      its own assignment statement, so a failure aborts under -e;
#   3. release.yml's build step does not take `--features "$FEATURES"` (or a
#      hard-coded list is present), the assert steps do not pass
#      `--strict $REQUIRE_FLAGS`, or the SBOM step (`cargo cyclonedx`) does not
#      pass `--features "$FEATURES"` (the SBOM must list what the artifact links);
#   4. the Dockerfile build does not use --locked + the declaration, does not
#      COPY Cargo.lock / release-features.sh, or does not assert --strict;
#   5. .github/workflows/release-shape.yml is missing or does not build from the
#      declaration and run scripts/release-shape-pg-proof.sh;
#   6. docs/INSTALL.md "Pre-built Binaries" does not name sal-postgres or still
#      says the postgres path needs a source build.
#
# Usage:
#   scripts/check-release-features.sh [repo-root]
#   scripts/check-release-features.sh --self-test   # a failing / empty declaration
#                                                   # must make the release build step and the
#                                                   # Dockerfile RUN fail (executes them under -e)
# shellcheck disable=SC2016,SC2094 # literal `$(`/backtick patterns are searched for on purpose
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
bad() { echo "check-release-features: FAIL: $*" >&2; fail=1; }
fail=0

# ---------------------------------------------------------------- self-test --
if [[ "${1:-}" == "--self-test" ]]; then
  root="$(cd "$here/.." && pwd)"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/relfeat-selftest.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/scripts"
  # The release build step's run block, with the build replaced by an echo.
  awk '/- name: Build release binary/{f=1} f&&/- name: Assert compiled features/{exit} f' \
    "$root/.github/workflows/release.yml" \
    | awk '/^        run: \|/{r=1;next} r' | sed -e 's/^          //' \
    | sed -e 's/\${{ matrix.target }}/x/g' -e 's/^cargo build/echo cargo-build/' > "$tmp/build-step.sh"
  # The Dockerfile RUN, de-continued, with cargo/strip/assert replaced.
  awk '/^RUN set -eu/{f=1} f{print} f&&!/\\$/{exit}' "$root/Dockerfile" \
    | sed -e 's/^RUN //' -e 's/\\$//' \
    | sed -e 's/cargo build/echo cargo-build/' -e 's/strip target/echo strip target/' \
          -e 's#bash scripts/assert-compiled-features.sh#echo assert#' > "$tmp/docker-run.sh"
  [[ -s "$tmp/build-step.sh" && -s "$tmp/docker-run.sh" ]] \
    || { echo "check-release-features: self-test could not extract the build step / RUN" >&2; exit 1; }
  run_with() { # $1 declaration body, $2 script, $3 shell
    printf '%s\n' "$1" > "$tmp/scripts/release-features.sh"
    (cd "$tmp" && "$3" -c "set -e; $(cat "$2")") >/dev/null 2>&1
  }
  good='echo sal,sal-postgres'
  [[ "$(bash "$here/release-features.sh" --require-flags)" == *sal-postgres* ]] || true
  st=0
  for step in "build-step.sh:bash" "docker-run.sh:sh"; do
    f="${step%%:*}"; sh="${step##*:}"
    # control: a sane declaration passes (the extracted step is runnable)
    cp "$here/release-features.sh" "$tmp/scripts/release-features.sh"
    if ! (cd "$tmp" && "$sh" -c "set -e; $(cat "$tmp/$f")") >/dev/null 2>&1; then
      echo "self-test FAIL: $f does not pass with the real declaration" >&2; st=1
    fi
    for mutant in 'exit 1' 'true' 'echo ""; exit 0'; do
      if run_with "$mutant" "$tmp/$f" "$sh"; then
        echo "self-test FAIL: $f PASSED with a broken declaration ($mutant): fail-open" >&2; st=1
      fi
    done
  done
  : "$good"
  [[ $st -eq 0 ]] || exit 1
  echo "check-release-features: self-test OK (a failing or empty declaration fails the build step and the Dockerfile RUN)"
  exit 0
fi

# -------------------------------------------------------------------- guard --
root="${1:-$(cd "$here/.." && pwd)}"
rel="$root/.github/workflows/release.yml"
shape="$root/.github/workflows/release-shape.yml"
feat="$root/scripts/release-features.sh"
install="$root/docs/INSTALL.md"
dockerfile="$root/Dockerfile"

[[ -f "$feat" ]] || bad "scripts/release-features.sh is missing"
[[ -f "$rel" ]] || bad ".github/workflows/release.yml is missing"
[[ $fail -eq 0 ]] || exit 1

declared="$(bash "$feat")"
case ",$declared," in
  *,sal-postgres,*) ;;
  *) bad "release-features.sh declares [$declared], without sal-postgres" ;;
esac

# 2. no inline use of the declaration: every use is its own assignment.
assign_re='^[[:space:]]*(RUN set -eu; \\)?[[:space:]]*(FEATURES|REQUIRE_FLAGS)="\$\(bash scripts/release-features\.sh( --require-flags)?\)";?( \\)?$'
for f in "$rel" "$shape" "$dockerfile"; do
  [[ -f "$f" ]] || continue
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" == *'$(bash scripts/release-features.sh'* ]] && ! [[ "$line" =~ $assign_re ]]; then
      bad "$(basename "$f"): inline use of the declaration (a failure would be swallowed): $line"
    fi
  done < "$f"
done

# 3. release.yml build / assert / SBOM follow the declaration.
if grep -E '^[[:space:]]*cargo build .*--target' "$rel" | grep -qv -- '--features "\$FEATURES"'; then
  bad "release.yml build step does not take --features \"\$FEATURES\""
fi
grep -qE '^[[:space:]]*cargo build .*--target .*--features "\$FEATURES"' "$rel" \
  || bad "release.yml has no 'cargo build --target ... --features \"\$FEATURES\"' line"
grep -q 'FEATURES="$(bash scripts/release-features.sh)"' "$rel" \
  || bad "release.yml does not assign FEATURES from the declaration"
grep -q 'REQUIRE_FLAGS="$(bash scripts/release-features.sh --require-flags)"' "$rel" \
  || bad "release.yml assert step does not assign REQUIRE_FLAGS from the declaration"
grep -q 'assert-compiled-features.sh "\$bin" --strict \$REQUIRE_FLAGS' "$rel" \
  || bad "release.yml assert step does not pass --strict \$REQUIRE_FLAGS"
if ! grep -E 'cargo cyclonedx' "$rel" | grep -q -- '--features "\$FEATURES"'; then
  bad "release.yml SBOM step (cargo cyclonedx) does not pass --features \"\$FEATURES\" (the SBOM would omit what the artifact links)"
fi

# 4. the Dockerfile follows the same declaration, fail-closed, locked.
if [[ ! -f "$dockerfile" ]]; then
  bad "Dockerfile is missing"
else
  grep -qE 'cargo build --locked .*--features "\$FEATURES"' "$dockerfile" \
    || bad "Dockerfile cargo build does not use --locked and --features \"\$FEATURES\""
  grep -q 'FEATURES="$(bash scripts/release-features.sh)"' "$dockerfile" \
    || bad "Dockerfile does not assign FEATURES from scripts/release-features.sh"
  grep -q 'REQUIRE_FLAGS="$(bash scripts/release-features.sh --require-flags)"' "$dockerfile" \
    || bad "Dockerfile does not assign REQUIRE_FLAGS from the declaration"
  grep -q -- '--strict \$REQUIRE_FLAGS' "$dockerfile" \
    || bad "Dockerfile assert step does not pass --strict \$REQUIRE_FLAGS"
  grep -q '^COPY Cargo.toml Cargo.lock' "$dockerfile" \
    || bad "Dockerfile does not COPY Cargo.lock before the build"
  grep -q 'COPY scripts/release-features.sh' "$dockerfile" \
    || bad "Dockerfile does not COPY scripts/release-features.sh into the build stage"
fi

# 5. the release-shaped proof exists and follows the declaration.
if [[ ! -f "$shape" ]]; then
  bad ".github/workflows/release-shape.yml is missing (no release-shaped proof)"
else
  grep -q 'scripts/release-features.sh' "$shape" \
    || bad "release-shape.yml does not build from scripts/release-features.sh"
  grep -q 'scripts/release-shape-pg-proof.sh' "$shape" \
    || bad "release-shape.yml does not run scripts/release-shape-pg-proof.sh"
fi

# 6. the install docs state the shipped feature set.
section="$(sed -n '/^## Pre-built Binaries/,/^## /p' "$install" 2>/dev/null || true)"
case "$section" in
  *sal-postgres*) ;;
  *) bad "docs/INSTALL.md 'Pre-built Binaries' does not name sal-postgres" ;;
esac
# shellcheck disable=SC2016 # the backticks are literal doc text
case "$section" in
  *'daemon path is NOT'*|*'requires a `--features sal,sal-postgres` source build'*)
    bad "docs/INSTALL.md still says the postgres path needs a source build" ;;
esac

if [[ $fail -ne 0 ]]; then
  exit 1
fi
echo "check-release-features: OK (release features: $declared)"
