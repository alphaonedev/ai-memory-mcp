#!/usr/bin/env bash
# check-count-assertion-declared.sh — #3688 gate 5, the declaration half of the
# silent-count-auto-merge rule.
#
# Two branches each add one doctor section. Each edits the SAME test line
# `assert_eq!(report.sections.len(), 18)` to 19 — for different reasons. git
# sees two identical edits and merges them WITHOUT A CONFLICT; the merged tree
# asserts 19 and produces 20. Nothing in either branch is wrong; the defect
# exists only in the combination, and the first place it surfaces is a
# five-hour gate. The chain-12 rehearsal found it (#3124 + #3651); the wave-2
# rehearsal found it again with no conflict at all (#3651 + #3652).
#
# This cannot be prevented inside a branch. It is a merge property. So the
# rule has two halves:
#   DECLARE  — a commit that changes a `.len()` count assertion says so in its
#              message, so the merger knows a shared count moved:
#                  Count: doctor sections 18 -> 19 (adds "Logging pipeline")
#              (`# count: ...` is accepted too — but note `git commit` strips
#              `#`-prefixed lines unless --cleanup=verbatim, which is why the
#              trailer form is preferred.)
#   RE-DERIVE — the merger sets the merged assertion from the ARITHMETIC over
#              every declaration in the chain, never from whichever number
#              survived the merge. That half is the rehearsal lane's job.
# This gate enforces DECLARE.
set -u
cd "$(dirname "$0")/.." || exit 2
RANGE="HEAD~1..HEAD"; SELF_TEST=0
while [ $# -gt 0 ]; do case "$1" in
  --range) RANGE=$2; shift 2;; --self-test) SELF_TEST=1; shift;;
  *) echo "usage: $0 [--range A..B | --self-test]" >&2; exit 2;; esac; done

# A changed count assertion: an added or removed line asserting `<expr>.len()`
# (or `.count()`) against a NUMERIC literal. A variable on the right is not a
# shared count and is not flagged.
COUNT_RE='^[-+][^-+].*assert(_eq)?!\(.*\.(len|count)\(\) *, *[0-9][0-9_]*\)'
NOTE_RE='(^|[[:space:]#])[Cc]ount:'

check_range() { # $1 = A..B ; prints findings; returns 1 on any
  local fail=0 c
  for c in $(git rev-list --no-merges "$1"); do
    local hits; hits=$(git show "$c" --format= -- src tests 2>/dev/null | grep -E "$COUNT_RE" | head -5)
    [ -z "$hits" ] && continue
    git log -1 --format=%B "$c" | grep -qE "$NOTE_RE" && continue
    echo "  $(git rev-parse --short "$c")  $(git log -1 --format=%s "$c" | cut -c1-70)"
    printf '%s\n' "$hits" | sed 's/^/        /' | cut -c1-120
    fail=1
  done
  return $fail
}

if [ "$SELF_TEST" -eq 1 ]; then
  # Negative control (#3124, chain 12): the commit that changed the doctor
  # sections assertion 18 -> 19 with no declaration — the exact shape that
  # later auto-merged silently against #3651's identical edit.
  neg=$(check_range dbcfea710~1..dbcfea710); nrc=$?
  if [ $nrc -ne 1 ] || ! printf '%s' "$neg" | grep -q 'sections.len()'; then
    echo "count-assertion-declared self-test: FAIL — did not flag dbcfea710 (#3124): $neg"; exit 1
  fi
  # Positive control: the same diff under a commit whose message declares the
  # count must pass. Synthesised in a throwaway clone under the repo scratch.
  T=.local-runs/count-selftest; rm -rf "$T"; git worktree add -q --detach "$T" dbcfea710~1 2>/dev/null || { echo "self-test: cannot create scratch worktree"; exit 1; }
  ( cd "$T" && git cherry-pick --no-commit dbcfea710 >/dev/null 2>&1 && git -c user.name=g -c user.email=g@x commit -q -am "test: same change, declared" -m "Count: doctor sections 18 -> 19 (#3124 unstamped owners)" \
    && pos=$(check_range HEAD~1..HEAD) ; rc=$?; echo "$rc" > ../count-selftest.rc )
  prc=$(cat .local-runs/count-selftest.rc 2>/dev/null); git worktree remove --force "$T" >/dev/null 2>&1; rm -f .local-runs/count-selftest.rc
  if [ "$prc" != "0" ]; then echo "count-assertion-declared self-test: FAIL — flagged a declared count change (rc=$prc)"; exit 1; fi
  echo "count-assertion-declared self-test: PASS (flags the undeclared #3124 count change; passes it once declared)"; exit 0
fi

out=$(check_range "$RANGE"); rc=$?
if [ $rc -ne 0 ]; then
  printf '%s\n' "$out"
  cat <<MSG

count-assertion-declared gate (#3688/5): a commit changes a shared \`.len()\` count
assertion without declaring it (range: $RANGE).

Two branches that each bump the same count auto-merge to the SAME wrong number
with no conflict (chain 12: #3124 + #3651 both wrote 19; the truth was 20). The
merger can only re-derive the total if every bump is DECLARED. Add to the
commit message:
    Count: <what> <old> -> <new> (<why>)
MSG
  exit 1
fi
echo "count-assertion-declared: clean ($RANGE)"
