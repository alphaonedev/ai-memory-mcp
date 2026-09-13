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
  # SELF-CONTAINED FIXTURES. The previous self-test drove real chain-12
  # candidate commits (dbcfea710 etc). None of them is an ancestor of
  # release/v1.0.0, so on a clean CI clone the objects do not exist and the
  # self-test cannot run -- a gate whose self-test reds on the published head
  # cannot be a required context. Fixtures are synthesised here instead, so the
  # check is provable from any checkout with no history dependency.
  T=.local-runs/count-selftest; rm -rf "$T"; mkdir -p "$T" || { echo "self-test: cannot create $T"; exit 1; }
  (
    cd "$T" || exit 1
    git init -q . && git config user.name g && git config user.email g@x
    mkdir -p tests
    printf 'fn a() { assert_eq!(sections.len(), 18); }\n' > tests/f.rs
    git add -A && git commit -q -m "base"
    # (1) undeclared count bump -> MUST be flagged
    printf 'fn a() { assert_eq!(sections.len(), 19); }\n' > tests/f.rs
    git commit -q -am "test: bump sections"
    # (2) the same shape WITH a declaration -> MUST pass
    printf 'fn a() { assert_eq!(sections.len(), 20); }\n' > tests/f.rs
    git commit -q -am "test: bump sections again" -m "Count: sections.len() 19 -> 20 (fixture)"
  ) || { echo "count-assertion-declared self-test: FAIL — fixture setup"; rm -rf "$T"; exit 1; }
  neg=$( cd "$T" && check_range HEAD~2..HEAD~1 ); nrc=$?
  if [ $nrc -ne 1 ] || ! printf '%s' "$neg" | grep -q 'sections.len()'; then
    echo "count-assertion-declared self-test: FAIL — did not flag the undeclared bump: $neg"; rm -rf "$T"; exit 1
  fi
  pos=$( cd "$T" && check_range HEAD~1..HEAD ); prc=$?
  if [ $prc -ne 0 ]; then
    echo "count-assertion-declared self-test: FAIL — flagged a DECLARED count change (rc=$prc): $pos"; rm -rf "$T"; exit 1
  fi
  rm -rf "$T"
  echo "count-assertion-declared self-test: PASS (flags an undeclared count change; passes it once declared; fixtures synthesised, no history dependency)"; exit 0
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
