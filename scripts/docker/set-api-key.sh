#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# #4291 — set the TOP-LEVEL `api_key` of an ai-memory config.toml to
# $AI_MEMORY_API_KEY. Called by the init-batman service of
# scripts/docker/docker-compose.batman-active.yml (#3838 / #4213).
#
# Usage: AI_MEMORY_API_KEY=<key> set-api-key.sh <config.toml>
#
# Only the TOP-LEVEL key is this script's to change. A line is top-level when
# it comes before the first table header and lies outside a multi-line string
# and a multi-line array value. Everything else (an `api_key` inside `[llm]`
# or any other table, a line of a multi-line string) is left byte-for-byte:
# the #4213 rewrite dropped every `^api_key =` line in the file, which edited
# operator config it does not own, and reported a rotation that did not
# happen when the only key was table-scoped.
#
# The new key goes FIRST, where a TOML top-level key must go. Shell builtins
# only, so the key never reaches argv. The file is rewritten under umask 077
# and moved into place.
#
# Exit 0: done. "API key rotated" is printed only when a top-level key
#         existed and changed.
# Exit 64: the file's top-level scope cannot be established (an unterminated
#          multi-line string or array, or a top-level key whose value spans
#          lines). Guessing could leave two top-level keys, which the daemon
#          refuses to boot on, or drop a line the operator wrote, so the file
#          is left untouched and the reason is printed.

set -euo pipefail

cfg=${1:?usage: set-api-key.sh <config.toml>}
: "${AI_MEMORY_API_KEY:?AI_MEMORY_API_KEY must be set}"
want="api_key = \"${AI_MEMORY_API_KEY}\""

refuse() {
  echo "set-api-key: ${cfg}: $1; not rewriting it (#4291). Put the top-level api_key on one line, before any table." >&2
  exit 64
}

# Occurrences of $2 in $1.
count_of() {
  local stripped=${1//"$2"/}
  echo $(((${#1} - ${#stripped}) / ${#2}))
}

# Net `[` minus `]` of a line, outside simple quoted strings and comments.
bracket_delta() {
  local s=$1
  while [[ $s =~ (\"([^\"\\]|\\.)*\") ]]; do s=${s/"${BASH_REMATCH[1]}"/}; done
  while [[ $s =~ (\'[^\']*\') ]]; do s=${s/"${BASH_REMATCH[1]}"/}; done
  s=${s%%#*}
  local opens=${s//[^\[]/} closes=${s//[^\]]/}
  echo $((${#opens} - ${#closes}))
}

top=1      # still before the first table header
ml=""      # the delimiter of the multi-line string we are inside, if any
depth=0    # open brackets of a multi-line array value
n=0
have=""
declare -A drop=()
while IFS= read -r line || [ -n "$line" ]; do
  n=$((n + 1))
  if [ -n "$ml" ]; then
    # Inside a multi-line string: never a key, never a header.
    if (($(count_of "$line" "$ml") % 2 == 1)); then ml=""; fi
    continue
  fi
  if ((top == 1 && depth == 0)); then
    if [[ $line =~ ^[[:space:]]*\[ ]]; then
      top=0
      continue
    fi
    if [[ $line =~ ^[[:space:]]*api_key[[:space:]]*= ]]; then
      # A key whose value opens a multi-line string or array cannot be
      # replaced line by line.
      if (($(count_of "$line" '"""') % 2 == 1 || $(count_of "$line" "'''") % 2 == 1)) ||
        (($(bracket_delta "$line") != 0)); then
        refuse "the top-level api_key at line ${n} spans lines"
      fi
      [ -n "$have" ] || have=$line
      drop[$n]=1
      continue
    fi
  fi
  if ((top == 1)); then
    if (($(count_of "$line" '"""') % 2 == 1)); then
      ml='"""'
    elif (($(count_of "$line" "'''") % 2 == 1)); then
      ml="'''"
    else
      depth=$((depth + $(bracket_delta "$line")))
      ((depth >= 0)) || refuse "line ${n} closes an array that was never opened"
    fi
  fi
done <"$cfg"
if ((top == 1)); then
  [ -z "$ml" ] || refuse "a multi-line string is never closed"
  ((depth == 0)) || refuse "a multi-line array is never closed"
fi

# Already right: exactly one top-level key, and it is the wanted one.
if [ "$have" = "$want" ] && ((${#drop[@]} == 1)); then
  exit 0
fi

(
  umask 077
  {
    printf '%s\n' "$want"
    n=0
    while IFS= read -r line || [ -n "$line" ]; do
      n=$((n + 1))
      [ -n "${drop[$n]:-}" ] || printf '%s\n' "$line"
    done <"$cfg"
  } >"$cfg.new"
)
mv "$cfg.new" "$cfg"
if [ -n "$have" ] && [ "$have" != "$want" ]; then
  echo "init-batman: API key rotated (the services restart with it: depends_on restart: true)"
fi
