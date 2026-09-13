#!/usr/bin/env bash
# check-truthy-grammar.sh — #3688 gate 3, the durable close for #3200.
#
# This binary has ONE truthiness grammar: `security_profile::is_truthy`, which
# accepts 1 | true | yes | on. Every time a new knob hand-rolls a narrower one
# (exact "1", or only "true"), an operator who writes a synonym that works for
# every OTHER knob in the same product gets SILENT FAIL-OPEN on the control they
# believe they enabled.
#
# #3200 has tracked this since v0.7 and new instances keep landing DURING the GA
# freeze (#3660's AI_MEMORY_READ_AUDIT_STRICT was the third). Catching them one
# at a time in review is not a fix: the issue closes and reopens with the next
# knob. This gate is the fix.
set -u
cd "$(dirname "$0")/.." || exit 2
ALLOW=scripts/qc-allowlists/truthy-grammar.txt
FAIL=0

# Find AI_MEMORY_* env reads, then look at the next few lines for a hand-rolled
# comparison instead of the shared helper.
while IFS= read -r hit; do
  file=${hit%%:*}; rest=${hit#*:}; line=${rest%%:*}
  win=$(sed -n "${line},$((line+8))p" "$file")
  printf '%s' "$win" | grep -q 'is_truthy' && continue
  bad=$(printf '%s' "$win" | grep -nE '== *"1"|== *"true"|eq_ignore_ascii_case\( *"true" *\)|eq_ignore_ascii_case\( *"1" *\)' | head -1)
  [ -z "$bad" ] && continue
  var=$(printf '%s' "$win" | grep -oE 'AI_MEMORY_[A-Z0-9_]+' | head -1)
  key="$file:$var"
  [ -f "$ALLOW" ] && grep -qxF "$key" "$ALLOW" && continue
  echo "  $file:$line  $var — hand-rolled truthiness; use security_profile::is_truthy"
  FAIL=$((FAIL+1))
done < <(grep -rnE 'var(_os)?\( *"?AI_MEMORY_[A-Z0-9_]+|AI_MEMORY_[A-Z0-9_]+' src/ --include=*.rs 2>/dev/null | grep -vE '^src/security_profile\.rs')

if [ "$FAIL" -ne 0 ]; then
  cat <<'MSG'

truthy-grammar gate (#3688/3, closes #3200): a knob parses its own truthiness.

This binary accepts `1 | true | yes | on` everywhere via
`security_profile::is_truthy`. A knob that accepts less means an operator who
writes `=yes` — valid for every other knob here — gets SILENT FAIL-OPEN on a
control they believe they enabled. On a security knob that is a vulnerability,
not an inconsistency.

Route the value through `security_profile::is_truthy`. If a knob must genuinely
be stricter, add it to scripts/qc-allowlists/truthy-grammar.txt as
`<file>:<AI_MEMORY_VAR>` WITH a comment giving the reason.
MSG
  exit 1
fi
echo "truthy-grammar: clean"
