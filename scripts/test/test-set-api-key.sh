#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# #4291 — fixture test for scripts/docker/set-api-key.sh, the init-batman
# rewrite of the TOP-LEVEL `api_key` in config.toml (#3838 / #4213). No
# Docker: each case writes a config.toml, runs the script, and checks the
# file byte for byte, the exit code and the "rotated" message.
#
# SET_API_KEY_SCRIPT overrides the script under test, which is how the
# red-first run drives the pre-#4291 rewrite through the same cases.
#
# Scratch lives under .local-runs/ (project rule: never /tmp).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${SET_API_KEY_SCRIPT:-${ROOT}/scripts/docker/set-api-key.sh}"
T="${ROOT}/.local-runs/set-api-key-4291-$$"
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT

NEW_KEY="new-key-0123456789abcdef0123456789abcdef"
OLD_KEY="old-key-0123456789abcdef0123456789abcdef"
failures=0
case_no=0

# run_case <name> <input> <expected output> <expected exit> <expect rotated: yes|no>
run_case() {
  local name=$1 input=$2 expected=$3 want_rc=$4 want_rot=$5
  case_no=$((case_no + 1))
  local cfg="$T/case${case_no}.toml" out rc got
  printf '%s' "$input" >"$cfg"
  out=$(AI_MEMORY_API_KEY="$NEW_KEY" bash "$SCRIPT" "$cfg" 2>&1)
  rc=$?
  got=$(cat "$cfg"; printf x)
  got=${got%x}
  local bad=""
  [ "$rc" = "$want_rc" ] || bad+=" exit=${rc} (want ${want_rc})"
  [ "$got" = "$expected" ] || bad+=" file differs"
  if [ "$want_rot" = yes ]; then
    [[ $out == *"API key rotated"* ]] || bad+=" no rotation message"
  else
    [[ $out != *"API key rotated"* ]] || bad+=" false rotation message"
  fi
  if [ -z "$bad" ]; then
    echo "ok ${case_no} - ${name}"
  else
    echo "not ok ${case_no} - ${name}:${bad}"
    printf '  --- got ---\n%s  --- want ---\n%s  --- output ---\n%s\n' "$got" "$expected" "$out"
    failures=$((failures + 1))
  fi
}

want_line="api_key = \"${NEW_KEY}\""
old_line="api_key = \"${OLD_KEY}\""

# 1. A fresh file gets the key first; nothing rotated.
run_case "fresh file: key added first, no rotation message" \
  $'schema_version = 2\ntier = "autonomous"\n' \
  "${want_line}"$'\nschema_version = 2\ntier = "autonomous"\n' 0 no

# 2. A changed top-level key is replaced exactly once and reported.
run_case "changed top-level key: replaced once, rotation reported" \
  "${old_line}"$'\nschema_version = 2\ntier = "autonomous"\n' \
  "${want_line}"$'\nschema_version = 2\ntier = "autonomous"\n' 0 yes

# 3. The same key: the file is left exactly as it was.
run_case "same key: file untouched, nothing reported" \
  "${want_line}"$'\nschema_version = 2\n' \
  "${want_line}"$'\nschema_version = 2\n' 0 no

# 4. (L8 note 1) A key inside a table is not the daemon key: kept.
run_case "table-scoped api_key kept while the top-level key rotates" \
  "${old_line}"$'\ntier = "autonomous"\n\n[custom]\napi_key = "keep-me"\n' \
  "${want_line}"$'\ntier = "autonomous"\n\n[custom]\napi_key = "keep-me"\n' 0 yes

# 5. (L8 note 1) Only a table-scoped key: no rotation happened.
run_case "only a table-scoped api_key: kept, and no false rotation message" \
  $'tier = "autonomous"\n\n[custom]\napi_key = "keep-me"\n' \
  "${want_line}"$'\ntier = "autonomous"\n\n[custom]\napi_key = "keep-me"\n' 0 no

# 6. (L8 note 2) A line of a multi-line string is string content.
run_case "api_key line inside a multi-line string is kept" \
  "${old_line}"$'\nnote = """\napi_key = "inside the string"\n"""\ntier = "autonomous"\n' \
  "${want_line}"$'\nnote = """\napi_key = "inside the string"\n"""\ntier = "autonomous"\n' 0 yes

# 7. An array element starting `[` is not a table header: the top-level key
#    after the array is still top-level and is replaced (no-regression control).
run_case "array element starting [ is not a table header" \
  $'tier = "autonomous"\nlist = [\n  [1, 2],\n]\n'"${old_line}"$'\n' \
  "${want_line}"$'\ntier = "autonomous"\nlist = [\n  [1, 2],\n]\n' 0 yes

# 8. An unterminated multi-line string: scope unknown, refuse, file untouched.
run_case "unterminated multi-line string: refused (64), file untouched" \
  "${old_line}"$'\nnote = """\nnever closed\n' \
  "${old_line}"$'\nnote = """\nnever closed\n' 64 no

echo "1..${case_no}"
if ((failures > 0)); then
  echo "FAIL: ${failures} of ${case_no} case(s) failed (#4291)" >&2
  exit 1
fi
echo "PASS: ${case_no} case(s) (#4291)"
