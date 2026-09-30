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

# The key rules are enforced HERE, not only by the compose init, so the script
# is safe on its own: the charset keeps the key a plain TOML basic string (no
# quote, backslash or whitespace can break out of it), checked in the C locale
# (#3838 L8), and at least 32 characters. Refused before the file is read.
export LC_ALL=C
case "$AI_MEMORY_API_KEY" in
  '' | *[!A-Za-z0-9._~+/=-]*)
    echo "set-api-key: AI_MEMORY_API_KEY must be non-empty and use only [A-Za-z0-9._~+/=-]; ${1} not changed" >&2
    exit 64
    ;;
esac
if ((${#AI_MEMORY_API_KEY} < 32)); then
  echo "set-api-key: AI_MEMORY_API_KEY must be at least 32 characters (e.g. openssl rand -hex 32); ${1} not changed" >&2
  exit 64
fi
want="api_key = \"${AI_MEMORY_API_KEY}\""

refuse() {
  echo "set-api-key: ${cfg}: $1; not rewriting it (#4291). Put the top-level api_key on one line, before any table." >&2
  exit 64
}

# The VALUE of a one-line top-level `api_key = ...` line: a basic ("...") or
# literal ('...') string, followed only by whitespace or a comment. Prints
# nothing when the line is not that shape (it is then never "the same key").
key_value() {
  local rest=${1#*=}
  rest=${rest#"${rest%%[![:space:]]*}"}
  local quote=${rest:0:1} body tail
  case "$quote" in
    \" | \') ;;
    *) return 0 ;;
  esac
  body=${rest:1}
  [[ $body == *"$quote"* ]] || return 0
  tail=${body#*"$quote"}
  body=${body%%"$quote"*}
  tail=${tail#"${tail%%[![:space:]]*}"}
  [[ -z $tail || $tail == \#* ]] || return 0
  printf '%s' "$body"
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

# Already right: exactly one top-level key, holding the wanted VALUE in any
# valid spelling (spacing, quote style, trailing comment). The file is left
# exactly as it is and nothing is reported (f2r, #4291).
have_value=""
[ -z "$have" ] || have_value=$(key_value "$have")
if [ -n "$have" ] && [ "$have_value" = "$AI_MEMORY_API_KEY" ] && ((${#drop[@]} == 1)); then
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
if [ -n "$have" ] && [ "$have_value" != "$AI_MEMORY_API_KEY" ]; then
  echo "init-batman: API key rotated (the services restart with it: depends_on restart: true)"
fi
