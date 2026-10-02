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
  # ---- the GUARD itself must not be bypassable (comment / multi-line forms).
  mk_root() { # fresh copy of the repo files the guard reads
    local r="$1"; rm -rf "$r"; mkdir -p "$r/.github/workflows" "$r/scripts" "$r/docs"
    cp "$root/.github/workflows/release.yml" "$root/.github/workflows/release-shape.yml" "$r/.github/workflows/"
    cp "$root/Dockerfile" "$r/"; cp "$root/docs/INSTALL.md" "$r/docs/"
    cp "$root/scripts/release-features.sh" "$r/scripts/"
  }
  expect_guard() { # $1 name, $2 want (pass|fail), $3 root
    if bash "$here/check-release-features.sh" "$3" >/dev/null 2>&1; then got=pass; else got=fail; fi
    if [[ "$got" != "$2" ]]; then echo "self-test FAIL: guard case '$1' wanted $2, got $got" >&2; st=1; fi
  }
  # replace one block of text in a file (literal), via perl so no quoting games.
  mutate() { # $1 file, $2 old-file, $3 new-file
    OLD="$(cat "$2")" NEW="$(cat "$3")" perl -0pi -e 'BEGIN{$o=$ENV{OLD};$n=$ENV{NEW}} $i=index($_,$o); die "mutation anchor missing\n" if $i<0; substr($_,$i,length($o))=$n;' "$1"
  }
  g="$tmp/guard"; m="$tmp/mut"; mkdir -p "$m"
  rel_build='          FEATURES="$(bash scripts/release-features.sh)"
          test -n "$FEATURES"
          cargo build --locked --release --target ${{ matrix.target }} --features "$FEATURES"'
  printf '%s' "$rel_build" > "$m/old-build"
  mk_root "$g"; expect_guard "unmutated" pass "$g"
  # control: a VALID multi-line build must still pass.
  mk_root "$g"
  printf '%s' '          FEATURES="$(bash scripts/release-features.sh)"
          test -n "$FEATURES"
          cargo build --locked --release \
            --target ${{ matrix.target }} \
            --features "$FEATURES"' > "$m/new"
  mutate "$g/.github/workflows/release.yml" "$m/old-build" "$m/new"
  expect_guard "valid multi-line build" pass "$g"
  # bypass 1: multi-line INLINE use.
  mk_root "$g"
  printf '%s' '          cargo build --locked --release \
            --target ${{ matrix.target }} \
            --features "$(bash scripts/release-features.sh)"' > "$m/new"
  mutate "$g/.github/workflows/release.yml" "$m/old-build" "$m/new"
  expect_guard "multi-line inline build" fail "$g"
  # bypass 2: the assignment survives only inside a COMMENT.
  mk_root "$g"
  printf '%s' '          # FEATURES="$(bash scripts/release-features.sh)"
          FEATURES=sal
          cargo build --locked --release --target ${{ matrix.target }} --features "$FEATURES"' > "$m/new"
  mutate "$g/.github/workflows/release.yml" "$m/old-build" "$m/new"
  expect_guard "assignment only in a comment" fail "$g"
  # bypass 3: Dockerfile builds WITHOUT --locked, a comment carries the text.
  mk_root "$g"
  printf '%s' 'cargo build --locked --release --features "$FEATURES"' > "$m/old"
  printf '%s' 'cargo build --release --features "$FEATURES"' > "$m/new"
  mutate "$g/Dockerfile" "$m/old" "$m/new"
  printf '%s' 'RUN set -eu;' > "$m/old"
  printf '%s' '# cargo build --locked --release --features "$FEATURES"
RUN set -eu;' > "$m/new"
  mutate "$g/Dockerfile" "$m/old" "$m/new"
  expect_guard "Dockerfile --locked only in a comment" fail "$g"
  [[ $st -eq 0 ]] || exit 1
  echo "check-release-features: self-test OK (a failing or empty declaration fails the build step and the Dockerfile RUN)"
  exit 0
fi

# -------------------------------------------------------------------- guard --
# Every check reads NORMALISED text: full-line comments dropped and `\`
# continuations joined, so (1) a comment that merely CONTAINS the expected text
# (`# FEATURES="$(...)"`, `# cargo build --locked ...`) cannot satisfy a check
# and (2) a multi-line `run: |` / continued `RUN` is judged as the one command
# it is.
norm() {
  sed -E '/^[[:space:]]*#/d' "$1" \
    | awk '{ line=$0; if (sub(/\\[[:space:]]*$/, "", line)) { buf = buf line " " } else { print buf line; buf = "" } } END { if (buf != "") print buf }'
}

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

rel_n="$(norm "$rel")"
shape_n=""; [[ -f "$shape" ]] && shape_n="$(norm "$shape")"
docker_n=""; [[ -f "$dockerfile" ]] && docker_n="$(norm "$dockerfile")"
has() { grep -qE -- "$2" <<<"$1"; }

# 2. no inline use of the declaration: every use is its own assignment.
allowed_re='(FEATURES|REQUIRE_FLAGS)="\$\(bash scripts/release-features\.sh( --require-flags)?\)"'
for pair in "release.yml:$rel_n" "release-shape.yml:$shape_n" "Dockerfile:$docker_n"; do
  name="${pair%%:*}"; text="${pair#*:}"
  stripped="$(sed -E "s#$allowed_re##g" <<<"$text")"
  if grep -qE '\$\(bash [^)]*release-features\.sh' <<<"$stripped"; then
    bad "$name: inline use of the declaration (a failure would be swallowed; assign it in its own statement)"
  fi
done

# 3. release.yml build / assert / SBOM follow the declaration.
# The release matrix build (the mobile static-library builds use --target "$TARGET").
build_lines="$(grep -E 'cargo build .*--target \$\{\{ matrix\.target \}\}' <<<"$rel_n" || true)"
[[ -n "$build_lines" ]] || bad "release.yml has no release-matrix 'cargo build --target' command"
if [[ -n "$build_lines" ]] && grep -qv -- '--features "\$FEATURES"' <<<"$build_lines"; then
  bad "release.yml build command does not take --features \"\$FEATURES\""
fi
if [[ -n "$build_lines" ]] && grep -qv -- '--locked' <<<"$build_lines"; then
  bad "release.yml build command does not use --locked"
fi
# The assignment must sit in the SAME step, just before the command that uses it
# (an assignment elsewhere in the file does not protect this build).
assigned_before() { # $1 normalised text, $2 command-line regex
  RE="$2" awk '
    BEGIN { re = ENVIRON["RE"] }
    { a[NR]=$0 }
    END { for (i=1;i<=NR;i++) if (a[i] ~ re) { ok=0
            for (k=i-3;k<i;k++) if (k>0 && a[k] ~ /FEATURES="\$\(bash scripts\/release-features\.sh\)"/) ok=1
            if (!ok) exit 1 ; found=1 }
          if (!found) exit 1 }' <<<"$1"
}
assigned_before "$rel_n" 'cargo build .*--target \$\{\{ matrix\.target \}\}' \
  || bad "release.yml build is not preceded by its own FEATURES=\"\$(bash scripts/release-features.sh)\" assignment"
assigned_before "$rel_n" 'cargo cyclonedx' \
  || bad "release.yml SBOM step is not preceded by its own FEATURES assignment"
has "$rel_n" 'REQUIRE_FLAGS="\$\(bash scripts/release-features\.sh --require-flags\)"' \
  || bad "release.yml assert step does not assign REQUIRE_FLAGS from the declaration"
has "$rel_n" 'assert-compiled-features\.sh "\$bin" --strict \$REQUIRE_FLAGS' \
  || bad "release.yml assert step does not pass --strict \$REQUIRE_FLAGS"
sbom_lines="$(grep -E 'cargo cyclonedx' <<<"$rel_n" || true)"
if [[ -z "$sbom_lines" ]] || grep -qv -- '--features "\$FEATURES"' <<<"$sbom_lines"; then
  bad "release.yml SBOM step (cargo cyclonedx) does not pass --features \"\$FEATURES\" (the SBOM would omit what the artifact links)"
fi

# 4. the Dockerfile follows the same declaration, fail-closed, locked.
if [[ ! -f "$dockerfile" ]]; then
  bad "Dockerfile is missing"
else
  has "$docker_n" 'cargo build --locked [^;]*--features "\$FEATURES"' \
    || bad "Dockerfile cargo build does not use --locked and --features \"\$FEATURES\""
  has "$docker_n" 'FEATURES="\$\(bash scripts/release-features\.sh\)"' \
    || bad "Dockerfile does not assign FEATURES from scripts/release-features.sh"
  has "$docker_n" 'REQUIRE_FLAGS="\$\(bash scripts/release-features\.sh --require-flags\)"' \
    || bad "Dockerfile does not assign REQUIRE_FLAGS from the declaration"
  has "$docker_n" '--strict \$REQUIRE_FLAGS' \
    || bad "Dockerfile assert step does not pass --strict \$REQUIRE_FLAGS"
  has "$docker_n" '^COPY Cargo\.toml Cargo\.lock' \
    || bad "Dockerfile does not COPY Cargo.lock before the build"
  has "$docker_n" 'COPY scripts/release-features\.sh' \
    || bad "Dockerfile does not COPY scripts/release-features.sh into the build stage"
fi

# 5. the release-shaped proof exists and follows the declaration.
if [[ ! -f "$shape" ]]; then
  bad ".github/workflows/release-shape.yml is missing (no release-shaped proof)"
else
  has "$shape_n" 'scripts/release-features\.sh' \
    || bad "release-shape.yml does not build from scripts/release-features.sh"
  has "$shape_n" 'scripts/release-shape-pg-proof\.sh' \
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
