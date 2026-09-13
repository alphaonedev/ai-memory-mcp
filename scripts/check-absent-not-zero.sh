#!/usr/bin/env bash
# check-absent-not-zero.sh — #3688 gate 1.
#
# A metric that measures a MOMENT IN TIME must never use 0 to mean "no
# measurement". 0 is 1970-01-01, so the natural alert `time() - g > N` reads as
# fifty-six years stale: it fires immediately and permanently on every fresh
# node, gets muted, and is then silent when the thing genuinely breaks.
#
# Four instances reached review before this gate existed:
#   #3654 catchup_interval_seconds   — scalar gauge, help promised "absent"
#   #3651 log_last_delivery_seconds  — help said "0 = none yet" on a UNIX time
#   #3657 wake counters              — values nobody measured
#   #3660 last_gap_at_seconds        — help said "0 = none since boot"
#
# NOT flagged: counters. "Zero events so far" is a real measured observation and
# a monotonic counter is SUPPOSED to start at zero. The test is whether zero is
# a value the thing can actually take: a count can be zero, a moment cannot.
set -u
cd "$(dirname "$0")/.." || exit 2
FAIL=0

# A time-shaped metric name registered as a SCALAR gauge (IntGauge/Gauge, not
# *Vec), whose help text says zero means "none"/"never".
while IFS= read -r hit; do
  file=${hit%%:*}; rest=${hit#*:}; line=${rest%%:*}
  # Pull the registration block: the name line plus the following 6 lines of help.
  block=$(sed -n "${line},$((line+6))p" "$file")
  name=$(printf '%s' "$block" | grep -oE '"ai_memory_[a-z0-9_]*(_seconds|_at|_timestamp|_unix)"' | head -1)
  [ -z "$name" ] && continue
  # Only scalar gauges — a *Vec with no child emits no series and is correct.
  printf '%s' "$block" | grep -qE 'IntGaugeVec|GaugeVec' && continue
  if printf '%s' "$block" | grep -qiE '\b0 *= *(none|never|no |unset|absent)'; then
    echo "  $file:$line  $name — help says 0 means \"none\"; emit NO SERIES instead"
    FAIL=$((FAIL+1))
  fi
done < <(grep -rnE '(IntGauge|Gauge)::new\(' src/ --include=*.rs 2>/dev/null)

if [ "$FAIL" -ne 0 ]; then
  cat <<'MSG'

absent-not-zero gate (#3688/1): a time-shaped metric uses 0 as a sentinel.

Zero is 1970-01-01. `time() - <gauge> > N` then reads as ~56 years stale, so the
alert fires on every fresh node, gets muted, and is silent when it matters.

Fix by making the series ABSENT until there is a real measurement:
  - register an IntGaugeVec/GaugeVec (no child => no series), or
  - collect the gauge conditionally: `if let Some(v) = observed { ...collect() }`

Counters are exempt and correct as-is: zero events is a real observation.
MSG
  exit 1
fi
echo "absent-not-zero: clean"
