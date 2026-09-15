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
#
# HOW A CHANGE IS FOUND — whole-file, not diff-line. rustfmt splits any
# `assert_eq!` past ~100 columns onto three lines, so the number sits on a line
# of its own and, when ONLY the number changes, the `.len()` line is not in the
# diff at all; a per-line regex over `git show` misses exactly the shape the
# gate exists for. So for every file a commit touches under src/ and tests/,
# the OLD and NEW contents are parsed whole (comments stripped, string
# literals blanked), every count assertion is extracted as
# (normalised expression, numeric literal), and the two sets are compared:
# an assertion whose literal moved, appeared or disappeared is a count change.
# The named-const spelling — `assert_eq!(x.len(), EXPECTED)` with
# `const EXPECTED: usize = 19;` — is resolved the same way: a const that a
# count assertion names, whose literal moved, is a count change.
set -u
cd "$(dirname "$0")/.." || exit 2
RANGE="HEAD~1..HEAD"; SELF_TEST=0
while [ $# -gt 0 ]; do case "$1" in
  --range) RANGE=$2; shift 2;; --self-test) SELF_TEST=1; shift;;
  *) echo "usage: $0 [--range A..B | --self-test]" >&2; exit 2;; esac; done

NOTE_RE='(^|[[:space:]#])[Cc]ount:'

# count_changes <commit> — prints one line per changed count assertion:
#   <file>  <expr>.len()  <old> -> <new>
count_changes() {
  local c=$1
  python3 - "$c" <<'PY'
import re, subprocess, sys
c = sys.argv[1]
def git(*a):
    r = subprocess.run(['git', *a], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ''
files = [f for f in git('show', '--format=', '--name-only', c).split('\n')
         if f and (f.startswith('src/') or f.startswith('tests/')) and f.endswith('.rs')]
LIT = re.compile(r'"(?:[^"\\]|\\.)*"', re.S)
def clean(t):
    t = re.sub(r'//[^\n]*', '', t)                       # line comments
    return LIT.sub('""', t)                              # string literals are not code
# assert!(...) / assert_eq!(...) whose LEFT side is `<expr>.len()` / `.count()` and whose
# RIGHT side is a numeric literal or an UPPER_CASE const — across line breaks.
ASSERT = re.compile(
    r'assert(?:_eq)?!\s*\(\s*(?P<expr>[^;{}]*?)\.(?P<m>len|count)\(\)\s*,\s*(?P<rhs>[0-9][0-9_]*|[A-Z][A-Z0-9_]{2,})\s*[,)]', re.S)
CONST = re.compile(r'\bconst\s+(?P<name>[A-Z][A-Z0-9_]{2,})\s*:\s*(?:usize|u\d+|i\d+)\s*=\s*(?P<val>[0-9][0-9_]*)\s*;')
def extract(text):
    text = clean(text)
    consts = {m.group('name'): m.group('val').replace('_', '') for m in CONST.finditer(text)}
    out = {}
    for m in ASSERT.finditer(text):
        expr = re.sub(r'\s+', '', m.group('expr')) + '.' + m.group('m') + '()'
        rhs = m.group('rhs')
        val = rhs.replace('_', '') if rhs[0].isdigit() else consts.get(rhs)
        if val is None: continue                         # a const defined elsewhere: not a literal count
        if not rhs[0].isdigit(): expr += f' [{rhs}]'        # name the const the count is spelled through
        out.setdefault(expr, set()).add(val)
    return out
for f in files:
    old = extract(git('show', f'{c}^:{f}')); new = extract(git('show', f'{c}:{f}'))
    for expr in sorted(set(old) | set(new)):
        o, n = old.get(expr, set()), new.get(expr, set())
        if o != n:
            print(f"  {f}  {expr}  {','.join(sorted(o)) or '(none)'} -> {','.join(sorted(n)) or '(none)'}")
PY
}

check_range() { # $1 = A..B ; prints findings; returns 1 on any
  local fail=0 c
  for c in $(git rev-list --no-merges "$1"); do
    local hits; hits=$(count_changes "$c" | head -8)
    [ -z "$hits" ] && continue
    git log -1 --format=%B "$c" | grep -qE "$NOTE_RE" && continue
    echo "  $(git rev-parse --short "$c")  $(git log -1 --format=%s "$c" | cut -c1-70)"
    printf '%s\n' "$hits" | sed 's/^/      /' | cut -c1-140
    fail=1
  done
  return $fail
}

if [ "$SELF_TEST" -eq 1 ]; then
  # SELF-CONTAINED FIXTURES (no history dependency): a single-line bump, the
  # rustfmt THREE-LINE shape where only the number's line changes, the
  # named-const shape, and the same changes DECLARED. Scratch under
  # .local-runs/, never /tmp.
  T=.local-runs/count-selftest; rm -rf "$T"; mkdir -p "$T" || { echo "self-test: cannot create $T"; exit 1; }
  (
    cd "$T" || exit 1
    git init -q . && git config user.name g && git config user.email g@x
    mkdir -p tests
    printf 'fn a() { assert_eq!(sections.len(), 18); }\n' > tests/f.rs
    printf 'fn b() {\n    assert_eq!(\n        report.minimal_sections_with_a_deliberately_long_name.len(),\n        5\n    );\n}\n' > tests/multi.rs
    printf 'const EXPECTED_SECTIONS: usize = 18;\nfn c() { assert_eq!(report.sections.len(), EXPECTED_SECTIONS); }\n' > tests/named.rs
    printf 'fn d() { let n = 3; assert_eq!(items.len(), n); assert!(msg.contains("len() = 4")); }\n' > tests/ctrl.rs
    git add -A && git commit -q -m "base"
    # (1) single-line undeclared bump -> flagged
    printf 'fn a() { assert_eq!(sections.len(), 19); }\n' > tests/f.rs
    git commit -q -am "test: bump sections"
    # (2) rustfmt three-line shape: ONLY the number's line changes -> flagged
    printf 'fn b() {\n    assert_eq!(\n        report.minimal_sections_with_a_deliberately_long_name.len(),\n        6\n    );\n}\n' > tests/multi.rs
    git commit -q -am "test: bump minimal sections (multi-line)"
    # (3) named const bump -> flagged
    printf 'const EXPECTED_SECTIONS: usize = 19;\nfn c() { assert_eq!(report.sections.len(), EXPECTED_SECTIONS); }\n' > tests/named.rs
    git commit -q -am "test: bump named const"
    # (4) CONTROL: a variable rhs and a string literal mentioning len() -> NOT a count change
    printf 'fn d() { let n = 4; assert_eq!(items.len(), n); assert!(msg.contains("len() = 5")); }\n' > tests/ctrl.rs
    git commit -q -am "test: control edits"
    # (5) the same three shapes WITH a declaration -> pass
    printf 'fn a() { assert_eq!(sections.len(), 20); }\n' > tests/f.rs
    printf 'fn b() {\n    assert_eq!(\n        report.minimal_sections_with_a_deliberately_long_name.len(),\n        7\n    );\n}\n' > tests/multi.rs
    printf 'const EXPECTED_SECTIONS: usize = 20;\nfn c() { assert_eq!(report.sections.len(), EXPECTED_SECTIONS); }\n' > tests/named.rs
    git commit -q -am "test: bump all three, declared" -m "Count: sections 19 -> 20, minimal 6 -> 7, EXPECTED_SECTIONS 19 -> 20 (fixture)"
  ) || { echo "count-assertion-declared self-test: FAIL — fixture setup"; rm -rf "$T"; exit 1; }
  bad=0
  expect_red() { # $1 range $2 needle $3 label
    local out; out=$( cd "$T" && check_range "$1" ); local rc=$?
    if [ $rc -ne 1 ] || ! printf '%s' "$out" | grep -q -- "$2"; then echo "  [FAIL] expected RED: $3 — $out"; bad=1; else echo "  ok   RED: $3"; fi
  }
  expect_green() { # $1 range $2 label
    local out; out=$( cd "$T" && check_range "$1" ); local rc=$?
    if [ $rc -ne 0 ]; then echo "  [FAIL] expected GREEN: $2 — $out"; bad=1; else echo "  ok   GREEN: $2"; fi
  }
  expect_red   HEAD~5..HEAD~4 'sections.len()  18 -> 19'  'single-line undeclared bump'
  expect_red   HEAD~4..HEAD~3 'long_name.len()  5 -> 6'    'rustfmt three-line shape, only the number line in the diff'
  expect_red   HEAD~3..HEAD~2 'EXPECTED_SECTIONS'          'named-const bump (assert names the const, the const literal moved)'
  expect_green HEAD~2..HEAD~1 'variable rhs + a string literal mentioning len() are not count changes'
  expect_green HEAD~1..HEAD   'the same three shapes, declared with a Count: trailer'
  rm -rf "$T"
  # REFUSAL LEGS (Conductor ruling, #3688 c5660422072): "clean" must mean examined-and-found-nothing,
  # never could-not-look. Re-invoke this script with (a) a range whose start does not resolve and
  # (b) GIT_DIR pointed at a non-repository (the git-less-export shape): both must REFUSE, exit 2,
  # and neither may print "clean".
  SELF_PATH=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
  r_out=$(bash "$SELF_PATH" --range nosuch-3688..HEAD 2>&1); r_rc=$?
  g_out=$(GIT_DIR=/nonexistent-3688 bash "$SELF_PATH" 2>&1); g_rc=$?
  refuse_ok=1
  { [ "$r_rc" -eq 2 ] && printf '%s' "$r_out" | grep -q REFUSED && ! printf '%s' "$r_out" | grep -q ': clean'; } || refuse_ok=0
  { [ "$g_rc" -eq 2 ] && printf '%s' "$g_out" | grep -q REFUSED && ! printf '%s' "$g_out" | grep -q ': clean'; } || refuse_ok=0
  [ "$refuse_ok" -eq 1 ] || { echo "count-assertion-declared self-test: FAIL — an uncomputable range or a non-repository did not REFUSE (rc=$r_rc/$g_rc): $r_out | $g_out"; exit 1; }
  [ $bad -eq 0 ] && { echo "count-assertion-declared self-test: PASS (whole-file assertion sets: single-line, rustfmt multi-line and named-const bumps RED; variable rhs and string mentions GREEN; declared bumps GREEN; fixtures synthesised, no history dependency; an uncomputable range or a non-repository is REFUSED, never clean)"; exit 0; }
  echo "count-assertion-declared self-test: FAIL"; exit 1
fi

GATE=count-assertion-declared
# CLEAN MUST MEAN EXAMINED AND FOUND NOTHING, NEVER "COULD NOT LOOK" (Conductor ruling, #3688
# c5660422072): outside a git checkout, or with a range whose ends do not resolve, `git diff` /
# `git rev-list` print an error and an EMPTY diff, and the gate used to print `clean` over it.
# Refuse instead, with a non-zero exit, before anything is examined.
refuse_unless_range_computable() { # $1 = A..B
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "$GATE: REFUSED — not inside a git checkout; the range $1 cannot be computed (run from the repo root, not an export)" >&2; exit 2; }
  case "$1" in *..*) ;; *) echo "$GATE: REFUSED — range '$1' is not of the form A..B" >&2; exit 2;; esac
  git rev-parse --verify --quiet "${1%%..*}^{commit}" >/dev/null || { echo "$GATE: REFUSED — range start '${1%%..*}' does not resolve to a commit" >&2; exit 2; }
  git rev-parse --verify --quiet "${1##*..}^{commit}" >/dev/null || { echo "$GATE: REFUSED — range end '${1##*..}' does not resolve to a commit" >&2; exit 2; }
}
refuse_unless_range_computable "$RANGE"
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
