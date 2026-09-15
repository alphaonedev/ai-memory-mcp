#!/usr/bin/env bash
# check-shared-namespace-claims.sh — #3688 gate 6 (#3702): claims on a SHARED
# NAMESPACE made by INDEPENDENT candidate branches.
#
# git merges two branches without comment when they touch different lines, or
# the same line with the same text for different reasons. The result is clean
# and wrong, and no single-tree gate can fire, because the defect exists only
# BETWEEN branches. So this gate takes an explicit LIST of live candidates and
# a base, derives each branch's claims against its own merge-base, and reports
# every namespace two branches both claim — BEFORE anything is merged.
#
# Three real instances from 2026-09-13, all reproduced by --self-test:
#   SCHEMA VERSION  fix/3655-doctor-sync-freshness-v2 adds 0083_v99 + bumps
#                   SCHEMA_VERSION to 99; #3690 (tombstone store, unpushed)
#                   was independently built as v99. Two migration bodies under
#                   one number: a database that runs either records
#                   schema_version=99 and NEVER runs the other — not on
#                   upgrade, repair or restore. Two fleet nodes both "at v99"
#                   with different physical schemas, unreachable after the
#                   fact. Caught by a status line crossing a desk. CRITICAL.
#   CEILING TABLE   fix/2462-2463 and gates/3688-recurring-classes both wrote
#                   ("src/storage/migrations.rs", 7_440); #3655-v3 wrote 7_400.
#                   The IDENTICAL pair is the dangerous half: git takes it in
#                   silence. The merge result measured 7378, so BOTH candidate
#                   values pass and the ceiling gate cannot tell you which one
#                   you got. This gate prints the projected merge-result size
#                   against every candidate so a human sees that.
#   DUPLICATE       fix/3152-sal-update-single-commit{,-v2,-v3}: v3's src+tests
#   BRANCHES        surface is byte-identical to the already-approved v2, so a
#                   wrong-branch merge goes green and reports nothing.
#
# Usage:
#   scripts/check-shared-namespace-claims.sh --base <sha> [<branch|sha>...]
#                                            [--anchor <ref>] [--scan-origin] [--self-test]
#
# THE CANDIDATE SET IS DERIVED, NOT HAND-MAINTAINED. A hand list is the
# denominator of this gate, and a denominator someone types is the artefact that
# rots: the branch nobody typed is exactly the one whose SCHEMA_VERSION=99
# collides. With no branches named, the candidates are every `origin/*` branch
# (main / develop / release/* excluded) whose tip is NOT already in --base and
# whose merge-base with --base is AT OR AFTER the anchor — the published release
# head, `origin/release/v1.0.0` unless --anchor says otherwise. That is "every
# branch built on the current release head or a later candidate"; a branch cut
# from an older head is stale by construction (it needs a rebase before it can
# be merged, and its claims are re-derived then). Naming branches NARROWS the set
# — the gate still derives it and WARNs about every derived candidate the list
# left out, so a hand list cannot rot in silence.
# Cargo-free. Nothing is merged; every claim is read from the branch tip and
# its merge-base with --base.
set -u
cd "$(dirname "$0")/.." || exit 2
ALLOW=scripts/qc-allowlists/shared-namespace-claims.txt
BASE=""; SELF_TEST=0; SCAN_ORIGIN=0; CANDS=(); ANCHOR="origin/release/v1.0.0"
while [ $# -gt 0 ]; do case "$1" in
  --base) BASE=$2; shift 2;; --self-test) SELF_TEST=1; shift;; --scan-origin) SCAN_ORIGIN=1; shift;;
  --anchor) ANCHOR=$2; shift 2;;
  -h|--help) sed -n '2,40p' "$0"; exit 0;; *) CANDS+=("$1"); shift;; esac; done

run_check() { # $1 = base; rest = candidates. Prints findings. Exit 1 on FAIL, 0 otherwise.
  local base=$1; shift
  mkdir -p .local-runs
  local args=.local-runs/shared-claims-args.$$; printf '%s\n' "$@" > "$args"
  python3 - "$base" "$args" "$ALLOW" "$SCAN_ORIGIN" <<'PY'
import re, sys, subprocess, hashlib, itertools
base, argsf, allowf, scan_origin = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == '1'
cands = [l.strip() for l in open(argsf) if l.strip()]
def git(*a):
    r = subprocess.run(['git', *a], capture_output=True, text=True); return r.stdout if r.returncode == 0 else ''
def short(r): return git('rev-parse', '--short', r).strip() or r
def show(ref, path): return git('show', f'{ref}:{path}')
def merge_base(a, b): return git('merge-base', a, b).strip()
try: allow = {l.strip() for l in open(allowf) if l.strip() and not l.startswith('#')}
except OSError: allow = set()
findings = []   # (severity, key, text)
def note(sev, key, text): findings.append((sev, key, text))

# ---------- claim extraction --------------------------------------------------
CONST_SQLITE = re.compile(r'const CURRENT_SCHEMA_VERSION: i64 = (\d+)')
CONST_PG     = re.compile(r'const CURRENT_SCHEMA_VERSION: i32 = (\d+)')
RUNG = re.compile(r'^migrations/(sqlite|postgres)/(\d{4})_v(\d+)_[^/]+\.sql$')
def schema_claims(ref, mb):
    """versions this branch NEWLY claims (const bumps beyond merge-base; rungs added)."""
    out = {'const': {}, 'rungs': []}
    for ad, path, rx in (('sqlite','src/storage/migrations.rs',CONST_SQLITE), ('pg','src/store/postgres.rs',CONST_PG)):
        m0 = rx.search(show(mb, path) or ''); m1 = rx.search(show(ref, path) or '')
        if m0 and m1 and m1.group(1) != m0.group(1): out['const'][ad] = int(m1.group(1))
    added = git('diff', '--name-only', '--diff-filter=A', f'{mb}..{ref}', '--', 'migrations').split()
    for p in added:
        m = RUNG.match(p)
        if m:
            body = show(ref, p); out['rungs'].append((m.group(1), int(m.group(2)), int(m.group(3)), p, hashlib.sha256(body.encode()).hexdigest()[:12]))
    return out
TUPLE = re.compile(r'\("(src/[^"]+\.rs)", *([0-9_]+)\)')
def ceiling_table(ref):
    s = show(ref, 'tests/qual_10_module_size_ceiling.rs') or ''
    s = re.sub(r'/\*.*?\*/', '', s, flags=re.S); s = '\n'.join(l for l in s.splitlines() if not l.lstrip().startswith('//'))
    return {p: int(v.replace('_','')) for p, v in TUPLE.findall(s)}
def ceiling_claims(ref, mb):
    b, t = ceiling_table(mb), ceiling_table(ref)
    return {p: v for p, v in t.items() if b.get(p) != v}
def wc(ref, path):
    s = show(ref, path); return s.count('\n') if s else 0
ISSUE = re.compile(r'(?:^|/)[a-z]+/(\d{4})')
def issue_of(name):
    m = ISSUE.search(name); return m.group(1) if m else None

# ---------- gather -------------------------------------------------------------
claims = {}
for c in cands:
    mb = merge_base(c, base)
    if not mb: note('FAIL', f'input:{c}', f'{c}: cannot resolve a merge-base with {short(base)}'); continue
    claims[c] = {'mb': mb, 'schema': schema_claims(c, mb), 'ceil': ceiling_claims(c, mb), 'issue': issue_of(c)}

# ---------- 1. schema version namespace ----------------------------------------
base_sqlite = CONST_SQLITE.search(show(base,'src/storage/migrations.rs') or ''); base_v = int(base_sqlite.group(1)) if base_sqlite else None
by_version = {}   # version -> [(cand, adapter, rungpath, bodyhash)]
by_prefix  = {}   # (adapter, prefix) -> [(cand, path)]
for c, d in claims.items():
    for ad, v in d['schema']['const'].items():
        by_version.setdefault(v, []).append((c, ad, f'const:{ad}', ''))
    for ad, prefix, v, path, h in d['schema']['rungs']:
        by_version.setdefault(v, []).append((c, ad, path, h))
        by_prefix.setdefault((ad, prefix), []).append((c, path))
for v, items in sorted(by_version.items()):
    cs = sorted({c for c, *_ in items})
    if base_v is not None and v <= base_v:
        for c in cs: note('FAIL', f'schema:stale:{c}:v{v}', f'{c} claims schema v{v} but the base {short(base)} is already at v{base_v} — the branch needs a new number')
    if len(cs) >= 2:
        # same number claimed by >1 branch: CRITICAL unless every rung file is identical (same path + same body)
        rungs = sorted({(ad, path, h) for c, ad, path, h in items if not path.startswith('const:')})
        bodies = {(ad, path): h for ad, path, h in rungs}
        distinct = {}
        for c, ad, path, h in items:
            if not path.startswith('const:'): distinct.setdefault(c, set()).add((ad, path, h))
        identical = len({frozenset(s) for s in distinct.values()}) <= 1 and all(distinct.get(c) for c in cs)
        sev = 'INFO' if identical else 'CRITICAL'
        detail = '; '.join(f'{c}: ' + (', '.join(sorted(f'{ad} {path} [{h}]' for ad, path, h in distinct.get(c, set()))) or 'const bump only') for c in cs)
        note(sev, f'schema:v{v}:' + '+'.join(short(c) for c in cs),
             f'schema v{v} is claimed by {len(cs)} branches — {detail}. ' + ('Same rung files, same bodies: one branch is the other rebased.' if identical else
             'DIFFERENT migration bodies under ONE version number: a database that runs either records schema_version=' + str(v) + ' and never runs the other (not on upgrade, repair or restore). Renumber one of them and every rung/arm/const it carries.'))
for (ad, prefix), items in by_prefix.items():
    paths = sorted({p for _, p in items})
    if len(paths) >= 2:
        note('CRITICAL', f'rung-prefix:{ad}:{prefix:04d}', f'migration prefix {prefix:04d} ({ad}) is used by {len(paths)} different files across the queue: ' + ', '.join(f'{c}:{p}' for c, p in items) + ' — the ladder gate will red the merge; renumber before merging')

# ---------- 2. ceiling-table namespace ----------------------------------------
by_file = {}
for c, d in claims.items():
    for p, v in d['ceil'].items(): by_file.setdefault(p, []).append((c, v))
base_ceil = ceiling_table(base)
for p, items in sorted(by_file.items()):
    if len(items) < 2: continue
    values = sorted({v for _, v in items})
    # projected merge-result size: base actual + sum of each claimant's own delta vs its merge-base
    size = wc(base, p) + sum(wc(c, p) - wc(claims[c]['mb'], p) for c, _ in items)
    # ALL queue branches' deltas count toward the file, not only the claimants
    size_all = wc(base, p) + sum(wc(c, p) - wc(d['mb'], p) for c, d in claims.items())
    pairs_identical = [(a, b, va) for (a, va), (b, vb) in itertools.combinations(items, 2) if va == vb]
    verdicts = ', '.join(f'{v:,}'.replace(',', '_') + (' PASSES' if v >= size_all else ' WOULD RED') for v in values)
    passes_all = all(v >= size_all for v in values)
    key = f'ceiling:{p}='
    # An acknowledgement names the DECIDED value, so it settles the collision --
    # it does not bless a branch that claims some other number. Checking only
    # that *something* was acknowledged let #3655-v3 claim 7_400 against a
    # decided 7_440 and grade INFO, which is precisely the value the chain-13
    # rehearsal watched land SILENTLY before a later branch forced the conflict.
    _dec = [a[len(key):].strip() for a in allow if a.startswith(key)]
    decided = None
    if _dec:
        try: decided = int(_dec[0].replace('_', ''))
        except ValueError: decided = None
    acked = bool(_dec)
    mismatched = [(c, v) for c, v in items if decided is not None and v != decided]
    if decided is not None and mismatched:
        sev = 'FAIL'
    elif _dec:
        sev = 'INFO'
    else:
        sev = 'FAIL' if pairs_identical else 'WARN'
    who = ', '.join(f'{c}={v:,}'.replace(',', '_') for c, v in items)
    ptxt = ''
    if decided is not None and mismatched:
        ptxt += (' DECIDED VALUE IS ' + f'{decided:,}'.replace(',', '_') + ' (allowlist) but ' +
                 '; '.join(f'{c} claims {v:,}'.replace(',', '_') for c, v in mismatched) +
                 ' — that branch will land the wrong number and the merge need not conflict.')
    if pairs_identical:
        ptxt = ' IDENTICAL PAIR ' + '; '.join(f'{a} + {b} both write {va:,}'.replace(',', '_') for a, b, va in pairs_identical) + ' — git merges that in SILENCE, no conflict.'
    note(sev, f'ceiling:{p}', f'{p} ceiling is claimed by {len(items)} branches: {who}.{ptxt} Projected merge-result size {size_all} lines (base {wc(base,p)} + queue deltas); candidates: {verdicts}.' + (' EVERY candidate passes, so the ceiling gate cannot tell you which one landed — decide it explicitly' if passes_all and len(values) > 1 else '') + (' (acknowledged in allowlist)' if acked else ''))

# ---------- 3. duplicate branches per issue -----------------------------------
by_issue = {}
for c, d in claims.items():
    if d['issue']: by_issue.setdefault(d['issue'], []).append(c)
for iss, cs in sorted(by_issue.items()):
    if len(cs) >= 2:
        same = []
        for a, b in itertools.combinations(cs, 2):
            if subprocess.run(['git','diff','--quiet',a,b,'--','src','tests']).returncode == 0: same.append((a, b))
        # keyed on BRANCH NAMES (`origin/` stripped), never on SHAs: a sha key is invalidated by every
        # push to either branch, which is how the first form of this ledger went stale within hours
        names = '+'.join(sorted(c.replace('origin/', '', 1) for c in cs))
        acked = any(a == f'dup:{iss}={names}' for a in allow)
        if same:
            sev = 'FAIL'   # identical surface: one is the other re-cut; a wrong-branch merge goes green
        else:
            sev = 'INFO' if acked else 'WARN'   # two different deliverables under one issue (gates 1+3 / 2+4+5) are legitimate once acknowledged
        note(sev, f'dup-branch:{iss}', f'issue #{iss} has {len(cs)} candidate branches in the queue: ' + ', '.join(f'{c}@{short(c)}' for c in cs) + ('. IDENTICAL src+tests surface: ' + '; '.join(f'{a} == {b}' for a, b in same) + ' — a wrong-branch merge goes green and reports nothing; the queue must name exactly ONE.' if same else ('. Different surfaces' + (' (acknowledged as complementary in the allowlist)' if acked else ' — confirm both are wanted, or acknowledge with `dup:<issue>=<branchA>+<branchB>` (branch names, sorted, no origin/ prefix)'))))
if scan_origin:
    origin = git('for-each-ref', '--format=%(refname:short)', 'refs/remotes/origin/').split()
    for c, d in claims.items():
        if not d['issue']: continue
        sibs = [o for o in origin if issue_of(o) == d['issue'] and o != c and short(o) != short(c) and o != f'origin/{c}']
        if sibs: note('INFO', f'siblings:{d["issue"]}', f'issue #{d["issue"]}: queue names {c}@{short(c)}; origin also has ' + ', '.join(f'{s}@{short(s)}' for s in sibs) + ' — superseded? do not merge a sibling by mistake')

# ---------- report -------------------------------------------------------------
order = {'CRITICAL': 0, 'FAIL': 1, 'WARN': 2, 'INFO': 3}
findings.sort(key=lambda f: (order[f[0]], f[1]))
for sev, key, text in findings: print(f'  [{sev}] {key}\n         {text}')
n = {s: sum(1 for f in findings if f[0] == s) for s in order}
print(f'shared-namespace-claims: {len(cands)} candidates on {short(base)} — CRITICAL {n["CRITICAL"]}, FAIL {n["FAIL"]}, WARN {n["WARN"]}, INFO {n["INFO"]}')
sys.exit(1 if (n['CRITICAL'] or n['FAIL']) else 0)
PY
  local rc=$?; rm -f "$args"; return $rc
}

if [ "$SELF_TEST" -eq 1 ]; then
  ALLOW=/dev/null   # the live baseline must never soften a control
  # Fixtures live in throwaway worktrees under the repo's gitignored .local-runs/ (never /tmp).
  T=.local-runs/shared-claims-selftest; rm -rf "$T"; mkdir -p "$T"; ok=1
  mk() { # $1 name  $2 base ; then commands run inside the worktree via stdin
    git worktree add -q --detach "$T/$1" "$2" 2>/dev/null || return 1
    ( cd "$T/$1" && bash -s && git add -A >/dev/null && git -c user.name=g -c user.email=g@x commit -q -m "fixture $1" ) && git -C "$T/$1" rev-parse HEAD; }
  bump_schema() { # $1 = version $2 = rung slug ; writes a fixture v$1 on both adapters
    cat <<SH
V=$1; SLUG=$2
printf -- '-- fixture %s\n' "\$SLUG" > migrations/sqlite/0083_v\${V}_\${SLUG}.sql
printf -- '-- fixture %s\n' "\$SLUG" > migrations/postgres/0056_v\${V}_\${SLUG}.sql
sed -i "s/const CURRENT_SCHEMA_VERSION: i64 = [0-9]*/const CURRENT_SCHEMA_VERSION: i64 = \$V/" src/storage/migrations.rs
sed -i "s/const CURRENT_SCHEMA_VERSION: i32 = [0-9]*/const CURRENT_SCHEMA_VERSION: i32 = \$V/" src/store/postgres.rs
SH
  }
  B=$(git rev-parse HEAD)
  # (1) two branches at the SAME new version with DIFFERENT bodies -> CRITICAL
  A1=$(bump_schema 99 sync_peer_contact | mk a1 "$B"); A2=$(bump_schema 99 tombstone_store | mk a2 "$B")
  out=$(run_check "$B" "$A1" "$A2"); rc=$?
  if [ $rc -ne 1 ] || ! printf '%s' "$out" | grep -q 'CRITICAL\] schema:v99'; then echo "self-test FAIL (1): same-version different-body not CRITICAL: $out"; ok=0; fi
  # (1b) negative control: two branches at DIFFERENT new versions -> pass (rung prefixes differ too)
  A3=$(bump_schema 100 tombstone_store | mk a3 "$B"); sed -i 's/0083_v100/0084_v100/; s/0056_v100/0057_v100/' /dev/null 2>/dev/null
  git -C "$T/a3" mv migrations/sqlite/0083_v100_tombstone_store.sql migrations/sqlite/0084_v100_tombstone_store.sql 2>/dev/null; git -C "$T/a3" mv migrations/postgres/0056_v100_tombstone_store.sql migrations/postgres/0057_v100_tombstone_store.sql 2>/dev/null; git -C "$T/a3" -c user.name=g -c user.email=g@x commit -q -am "renumber" 2>/dev/null; A3=$(git -C "$T/a3" rev-parse HEAD)
  out=$(run_check "$B" "$A1" "$A3"); rc=$?
  if [ $rc -ne 0 ]; then echo "self-test FAIL (1b): different versions flagged: $out"; ok=0; fi
  # (2) ceiling: identical pair on one file + a third different value -> FAIL naming the pair and both verdicts
  C1=$(printf 'sed -i "s/(\\"src\\/storage\\/migrations.rs\\", *[0-9_]*)/(\\"src\\/storage\\/migrations.rs\\", 7_440)/" tests/qual_10_module_size_ceiling.rs; for i in $(seq 69); do echo "// pad $i" >> src/storage/migrations.rs; done\n' | mk c1 "$B")
  C2=$(printf 'sed -i "s/(\\"src\\/storage\\/migrations.rs\\", *[0-9_]*)/(\\"src\\/storage\\/migrations.rs\\", 7_440)/" tests/qual_10_module_size_ceiling.rs\n' | mk c2 "$B")
  C3=$(printf 'sed -i "s/(\\"src\\/storage\\/migrations.rs\\", *[0-9_]*)/(\\"src\\/storage\\/migrations.rs\\", 7_400)/" tests/qual_10_module_size_ceiling.rs; for i in $(seq 25); do echo "// pad $i" >> src/storage/migrations.rs; done\n' | mk c3 "$B")
  out=$(run_check "$B" "$C1" "$C2" "$C3"); rc=$?
  if [ $rc -ne 1 ] || ! printf '%s' "$out" | grep -q 'IDENTICAL PAIR' || ! printf '%s' "$out" | grep -q 'PASSES'; then echo "self-test FAIL (2): ceiling triple not reported with verdicts: $out"; ok=0; fi
  # (2b) negative control: two branches bumping DIFFERENT ceiling entries -> pass
  C4=$(printf 'sed -i "s/(\\"src\\/llm.rs\\", *[0-9_]*)/(\\"src\\/llm.rs\\", 7_000)/" tests/qual_10_module_size_ceiling.rs\n' | mk c4 "$B")
  out=$(run_check "$B" "$C2" "$C4"); rc=$?
  if [ $rc -ne 0 ]; then echo "self-test FAIL (2b): unrelated ceiling entries flagged: $out"; ok=0; fi
  # (3) duplicate branches per issue with identical src+tests surface -> FAIL; needs NAMED refs
  git branch -f fixture/3152-dup-v2 "$C2" >/dev/null; git branch -f fixture/3152-dup-v3 "$C2" >/dev/null
  ( cd "$T/c2" && echo "doc only" >> CHANGELOG.md && git add -A && git -c user.name=g -c user.email=g@x commit -q -m "v3 docs" ) && git branch -f fixture/3152-dup-v3 "$(git -C "$T/c2" rev-parse HEAD)" >/dev/null
  out=$(run_check "$B" fixture/3152-dup-v2 fixture/3152-dup-v3); rc=$?
  if [ $rc -ne 1 ] || ! printf '%s' "$out" | grep -q 'IDENTICAL src+tests surface'; then echo "self-test FAIL (3): duplicate branches not flagged: $out"; ok=0; fi
  for w in a1 a2 a3 c1 c2 c3 c4; do git worktree remove --force "$T/$w" >/dev/null 2>&1; done; git branch -D fixture/3152-dup-v2 fixture/3152-dup-v3 >/dev/null 2>&1; rm -rf "$T"
  [ $ok -eq 1 ] && { echo "shared-namespace-claims self-test: PASS (CRITICAL on same-version/different-body; ceiling identical pair + projected size; duplicate-issue identical surface; both negative controls pass)"; exit 0; }
  exit 1
fi

[ -z "$BASE" ] && { echo "usage: $0 --base <sha> [<branch|sha>...] [--anchor <ref>] [--scan-origin] [--self-test]" >&2; exit 2; }

# derive_candidates <base> <anchor> — every origin branch built on the anchor or later, not yet in base
derive_candidates() {
  local base=$1 anchor=$2 b s mb
  git rev-parse --verify -q "$anchor^{commit}" >/dev/null || { echo "anchor $anchor does not resolve — pass --anchor <ref>" >&2; return 2; }
  git for-each-ref --format='%(refname:short) %(objectname)' refs/remotes/origin | grep -vE '^origin/(HEAD|main|develop|release/)' | while read -r b s; do
    git merge-base --is-ancestor "$s" "$base" 2>/dev/null && continue          # already in the base
    mb=$(git merge-base "$s" "$base" 2>/dev/null) || continue
    git merge-base --is-ancestor "$anchor" "$mb" 2>/dev/null && echo "$b"        # cut from the anchor or later
  done
  return 0
}
DERIVED=$(derive_candidates "$BASE" "$ANCHOR") || exit 2
if [ "${#CANDS[@]}" -eq 0 ]; then
  [ -z "$DERIVED" ] && { echo "shared-namespace-claims: no candidate branches derived (nothing on origin is built on $ANCHOR or later and not yet in $BASE)"; exit 0; }
  mapfile -t CANDS <<< "$DERIVED"
  echo "candidates DERIVED from origin (built on $ANCHOR or later, not in $BASE): ${#CANDS[@]}"
else
  missing=$(comm -23 <(printf '%s\n' "$DERIVED" | sort) <(printf '%s\n' "${CANDS[@]}" | sed 's#^refs/remotes/##' | sort))
  if [ -n "$missing" ]; then
    echo "  [WARN] the named list NARROWS the derived set — derived candidates you did not name (a list is the denominator, and this is how it rots):"
    printf '%s\n' "$missing" | sed 's/^/         /'
  fi
fi
run_check "$BASE" "${CANDS[@]}"; rc=$?
if [ $rc -ne 0 ]; then cat <<'MSG'

shared-namespace-claims gate (#3688/6, #3702): two candidate branches claim the same
shared namespace — a schema version, a ceiling-table entry, or one issue number.
git merges these without comment; the result is clean and wrong. Resolve BEFORE merging:
renumber a schema claim (every rung, arm and const it carries); decide a single
ceiling value explicitly, knowing the projected size printed above; name exactly ONE
branch per issue. Acknowledge a decided ceiling with `ceiling:<file>=<value>` in
scripts/qc-allowlists/shared-namespace-claims.txt WITH the reason.
MSG
fi
exit $rc
