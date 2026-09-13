#!/usr/bin/env bash
# check-stale-contract-assertions.sh — #3688 gate 4.
#
# When a lane changes a string literal in src/ that some TEST asserts on — a wire
# string, an error message, a doctor fact key — and updates only its own tests,
# every OTHER test that pinned the old text goes red in the next full gate. Two
# five-hour cycles were lost this way in one day:
#   #3638  the reflect wire string changed; two reflect tests still pinned it
#   #3648  "Ollama pull failed (…)" became a bounded ProviderError; a test
#          elsewhere still asserted `.contains("Ollama pull failed")`
# Both were caught by the gate, not by review, because the asserting test lived
# outside the files the lane was looking at.
#
# The check is a cheap approximation of "did you update everyone's tests":
#   1. take the diff of a commit range (default HEAD~1..HEAD; --range A..B;
#      --staged for the index);
#   2. collect string literals that appear on REMOVED lines of non-test src/
#      files and do not survive on any ADDED line of the same file (i.e. the
#      text is gone or changed);
#   3. split each on format placeholders into fragments >= 8 chars;
#   4. find every test-side literal (tests/, src/**/tests*, `mod tests`
#      regions) that is a substring of a fragment or contains one;
#   5. FAIL on any such test file the diff does not also touch.
# Cargo-free, so the rehearsal lane can run it pre-merge over a merge range.
#
# KNOWN BLIND SPOT (documented, not hidden): a pin on a RENDERED fragment whose
# runtime values are substituted — #3638's `contains("depth 2")` and
# `contains("namespace='team/r-depth'")` — shares no verbatim text with the
# template it came from once the template is redacted around it. The
# shared-identifier rule below catches the `max_reflection_depth 1` shape only
# when the identifier disappears from production PROSE; #3638 kept it. Those
# pins are the rehearsal lane's to find (it runs the real tests' text guards).
set -u
cd "$(dirname "$0")/.." || exit 2
RANGE="HEAD~1..HEAD"; STAGED=0; SELF_TEST=0
while [ $# -gt 0 ]; do case "$1" in
  --range) RANGE=$2; shift 2;; --staged) STAGED=1; shift;; --self-test) SELF_TEST=1; shift;;
  *) echo "usage: $0 [--range A..B | --staged | --self-test]" >&2; exit 2;; esac; done

run_check() { # $1 = END revision (tests read there; or WORKTREE); $2 = START revision (old-side regions); diff on stdin
  # The diff goes through a project-local scratch file: `python3 -` takes its
  # SCRIPT from stdin, so the heredoc would otherwise swallow the piped diff.
  mkdir -p .local-runs; local df=.local-runs/stale-contract-diff.$$; cat > "$df"
  python3 - "$1" "$df" "$2" <<'PY'
import re, sys, subprocess
endrev = sys.argv[1]
diff = open(sys.argv[2], encoding='utf-8', errors='replace').read()
MOD_TESTS = re.compile(r'^\s*(pub )?mod tests\b', re.M)
_batch = None
def read_at(path):
    """File text at endrev. One `git cat-file --batch` process serves every read."""
    global _batch
    if endrev == 'WORKTREE':
        try: return open(path, encoding='utf-8', errors='replace').read()
        except OSError: return ''
    if _batch is None:
        _batch = subprocess.Popen(['git','cat-file','--batch'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    _batch.stdin.write(f'{endrev}:{path}\n'.encode()); _batch.stdin.flush()
    hdr = _batch.stdout.readline().decode().split()
    if len(hdr) < 3 or hdr[1] == 'missing': return ''
    n = int(hdr[2]); body = _batch.stdout.read(n); _batch.stdout.read(1)
    return body.decode('utf-8', errors='replace')
def listing():
    if endrev == 'WORKTREE':
        return subprocess.run(['git','ls-files','tests','src'], capture_output=True, text=True).stdout.split()
    return subprocess.run(['git','ls-tree','-r','--name-only',endrev,'--','tests','src'], capture_output=True, text=True).stdout.split()
def is_test_path(p):
    return p.startswith('tests/') or '/tests/' in p or p.endswith(('/tests.rs','_test.rs','_tests.rs'))
def split_regions(path, text):
    """(production_text, test_text) for a file at endrev."""
    if is_test_path(path): return '', text
    m = MOD_TESTS.search(text)
    return (text, '') if not m else (text[:m.start()], text[m.start():])
LIT = re.compile(r'"((?:[^"\\]|\\.){8,}?)"')
def fragments(lit):
    out = []
    for part in re.split(r'\{[^}]*\}', lit):
        part = part.replace('\\"', '"').replace('\\n', ' ').strip()
        if len(part) >= 8: out.append(part)
    return out
# 1. literals on REMOVED production lines of src/ in the diff
startrev = sys.argv[3]
def old_test_start(path):
    """Line where the OLD file's `mod tests` begins (None = no in-file test region)."""
    if startrev == 'WORKTREE': r = subprocess.run(['git','show',f'HEAD:{path}'], capture_output=True, text=True)
    else: r = subprocess.run(['git','show',f'{startrev}:{path}'], capture_output=True, text=True)
    if r.returncode != 0: return None
    for i, l in enumerate(r.stdout.splitlines(), 1):
        if MOD_TESTS.match(l): return i
    return None
cur = None; removed = {}; oldno = 0; test_from = None
HUNK = re.compile(r'^@@ -(\d+)(?:,\d+)? ')
for ln in diff.splitlines():
    if ln.startswith('+++ b/'): cur = ln[6:]; test_from = old_test_start(cur); continue
    m = HUNK.match(ln)
    if m: oldno = int(m.group(1)); continue
    if cur is None or ln.startswith('---'): continue
    if ln.startswith('-'):
        # a removed line at OLD line `oldno`: skip it if it sat in the old file's test region
        if not (test_from and oldno >= test_from):
            removed.setdefault(cur, []).append(ln[1:])
        oldno += 1
    elif ln.startswith('+'):
        pass
    else:
        oldno += 1
frags = {}
for f, lines in removed.items():
    if not (f.startswith('src/') and f.endswith('.rs')) or is_test_path(f): continue
    keep = [ln for ln in lines if not (ln.strip().startswith('//') or ln.strip().startswith('#[') or 'assert' in ln)]
    # A `\`-continued string literal spans several physical lines; glue ONLY
    # those continuations back together so the literal is seen whole (the
    # #3638 REFLECTION_DEPTH_EXCEEDED message), then scan line by line.
    glued = []
    for ln in keep:
        if glued and glued[-1].rstrip().endswith('\\'):
            glued[-1] = glued[-1].rstrip()[:-1] + ln.lstrip()
        else:
            glued.append(ln)
    for ln in glued:
        for lit in LIT.findall(ln):
            for fr in fragments(lit): frags.setdefault(fr, f)
if not frags: sys.exit(0)
# 2. at the END revision: which fragments are gone from every PRODUCTION region,
#    yet still asserted in some TEST region?
files = [p for p in listing() if p.endswith('.rs')]
prod_text = []; test_regions = []
for p in files:
    t = read_at(p)
    if not t: continue
    prod, test = split_regions(p, t)
    if prod: prod_text.append(prod)
    if test: test_regions.append((p, test))
prod_all = '\n'.join(prod_text)
# Non-comment production text, for the prose-identifier rule below.
prod_code = '\n'.join(l for l in prod_all.splitlines() if not l.lstrip().startswith('//'))
gone = {fr: src for fr, src in frags.items() if fr not in prod_all}
if not gone: sys.exit(0)
# Rare identifier tokens inside the gone fragments (`max_reflection_depth`): a
# test that asserts a RENDERED fragment with runtime values substituted
# ("max_reflection_depth 1", the #3638 shape) shares no verbatim substring with
# the template, but it shares the identifier — and an identifier that long is
# not a coincidence.
IDENT = re.compile(r'[a-z][a-z0-9]*(?:_[a-z0-9]+)+')
def rare_idents(text): return {t for t in IDENT.findall(text) if len(t) >= 12}
def prose(t, text): return re.search(r'(^|\s)' + re.escape(t) + r'(\s|$)', text) is not None
# An identifier used as PROSE in the gone message (whitespace on both sides,
# unlike `field: value` / `name=3` code usages) with no prose usage left in
# non-comment production text.
gone_idents = {}
for fr, src in gone.items():
    for t in rare_idents(fr):
        if prose(t, fr) and not prose(t, prod_code): gone_idents[t] = (fr, src)
# `.expect("…")` is the test's OWN failure message, never a pin on production text.
ASSERT = re.compile(r'assert|contains\(|starts_with\(|ends_with\(|==|matches!')
def glue_lines(text):
    out = []
    for ln in text.splitlines():
        if out and out[-1].rstrip().endswith('\\'):
            out[-1] = out[-1].rstrip()[:-1] + ln.lstrip()
        else:
            out.append(ln)
    return out
_templates = None
def covers(parts, tl):
    """Can a format template (fixed `parts` around placeholders) render a string
    that CONTAINS `tl`? `tl` may start inside a placeholder or mid-part and end
    likewise, so the first and last fixed parts match as suffix / prefix. At
    least 8 literal characters must take part, or a `{a}{b}` template would
    cover everything."""
    n = len(parts)
    for a in range(n):
        if len(parts[a]) >= 8 and tl in parts[a]: return True
        for b in range(a + 1, n):
            suf = '(?P<s>' + '|'.join(re.escape(parts[a][i:]) for i in range(len(parts[a]) + 1)) + ')'
            mid = ''.join('(?P<m%d>%s).*?' % (k, re.escape(parts[k])) for k in range(a + 1, b))
            pre = '(?P<e>' + '|'.join(re.escape(parts[b][:j]) for j in range(len(parts[b]) + 1)) + ')'
            m = re.match('^' + suf + '.*?' + mid + pre + '$', tl, re.S)
            if m and sum(len(g) for g in m.groups() if g) >= 8: return True
    return False
def producible(tl):
    """Is `tl` still renderable by SOME production format template? Built lazily
    from per-line literals (continuations glued) — only candidates pay for it."""
    global _templates
    if _templates is None:
        _templates = []
        for ln in glue_lines(prod_all):
            for lit in LIT.findall(ln):
                if '{' not in lit: continue
                parts = re.split(r'\{[^}]*\}', lit.replace('\\"', '"'))
                if sum(len(x) for x in parts) >= 8: _templates.append(parts)
    # Prefilter: a template can only cover `tl` if some fixed part shares an
    # 8-character run with it. Cheap set lookups before the regex work.
    grams = {tl[i:i + 8] for i in range(len(tl) - 7)}
    def shares(parts):
        return any(pt[i:i + 8] in grams for pt in parts for i in range(len(pt) - 7))
    return any(covers(parts, tl) for parts in _templates if shares(parts))
def still_live(tl): return tl in prod_all or producible(tl)
seen = set()
for p, region in test_regions:
    for ln in region.splitlines():
        if not ASSERT.search(ln): continue
        for tl in LIT.findall(ln):
            tl = tl.replace('\\"', '"')
            for fr, src in gone.items():
                # fr in tl: the test pins the whole old text (placeholders aside).
                # tl in fr: the test pins a PHRASE of it — a phrase, not a single
                # token: single words ("observation") match everything.
                phrase = len(tl) >= 16 and ' ' in tl
                if (fr in tl or (phrase and tl in fr)) and (p, tl) not in seen:
                    # The pinned text itself still exists in production: not stale
                    # even though the message changed around it. (Checked lazily —
                    # prod_all is megabytes; only candidates pay for the scan.)
                    if still_live(tl): continue
                    seen.add((p, tl))
                    print(f'  {p} still asserts "{tl}" — {src} removed/changed "{fr[:60]}" and no production text carries it any more')
            for t in rare_idents(tl) & set(gone_idents):
                fr, src = gone_idents[t]
                if prose(t, tl) and (p, tl) not in seen and not still_live(tl):
                    seen.add((p, tl))
                    print(f'  {p} still asserts "{tl}" — {src} removed/changed "{fr[:60]}" (shares identifier `{t}`, gone from production)')
sys.exit(1 if seen else 0)
PY
  local rc=$?; rm -f "$df"; return $rc
}

if [ "$SELF_TEST" -eq 1 ]; then
  # SELF-CONTAINED FIXTURES. The previous self-test drove real chain-12
  # candidate commits (1fd7e29d5 #3648, 74c87d599 the repair). Neither is an
  # ancestor of release/v1.0.0, so on a clean CI clone those objects do not
  # exist and the self-test cannot run -- a gate whose self-test reds on the
  # published head cannot be a required context. Fixtures are synthesised here.
  T=.local-runs/stale-selftest; rm -rf "$T"; mkdir -p "$T" || { echo "self-test: cannot create $T"; exit 1; }
  (
    cd "$T" || exit 1
    git init -q . && git config user.name g && git config user.email g@x
    mkdir -p src tests
    printf 'pub fn e() -> String { "Ollama pull failed (boom)".into() }\n' > src/p.rs
    printf 'fn t() { assert!(e().contains("Ollama pull failed")); }\n'     > tests/p.rs
    git add -A && git commit -q -m "base"
    # (1) src literal changes, the asserting test is NOT touched -> MUST flag
    printf 'pub fn e() -> String { ProviderError::Pull.to_string() }\n' > src/p.rs
    git commit -q -am "fix: bounded ProviderError"
    # (2) the repair: src changes AND every asserting test changes -> MUST pass
    printf 'pub fn e() -> String { ProviderError::Pull2.to_string() }\n' > src/p.rs
    printf 'fn t() { assert!(e().contains("provider pull")); }\n'        > tests/p.rs
    git commit -q -am "fix: bounded ProviderError and its pins"
  ) || { echo "stale-contract-assertions self-test: FAIL — fixture setup"; rm -rf "$T"; exit 1; }
  neg=$( cd "$T" && git diff HEAD~2..HEAD~1 | run_check HEAD~1 HEAD~2 ); nrc=$?
  if [ $nrc -ne 1 ] || ! printf '%s' "$neg" | grep -q 'Ollama pull failed'; then
    echo "stale-contract-assertions self-test: FAIL — did not flag the stale pin (rc=$nrc): $neg"; rm -rf "$T"; exit 1
  fi
  pos=$( cd "$T" && git diff HEAD~1..HEAD | run_check HEAD HEAD~1 ); prc=$?
  if [ $prc -ne 0 ]; then
    echo "stale-contract-assertions self-test: FAIL — flagged the repair commit: $pos"; rm -rf "$T"; exit 1
  fi
  rm -rf "$T"
  echo "stale-contract-assertions self-test: PASS (flags a stale pin; passes its repair; fixtures synthesised, no history dependency)"; exit 0
fi

if [ "$STAGED" -eq 1 ]; then out=$(git diff --cached | run_check WORKTREE WORKTREE); rc=$?
else out=$(git diff "$RANGE" | run_check "${RANGE##*..}" "${RANGE%%..*}"); rc=$?; fi
if [ $rc -ne 0 ]; then
  printf '%s\n' "$out"
  cat <<MSG

stale-contract-assertions gate (#3688/4): a string literal changed in src/ is still
asserted by a test the change did not touch (range: $( [ "$STAGED" -eq 1 ] && echo staged || echo "$RANGE" )).

Update every asserting test in the SAME change, or keep the old text. A lane that
updates only its own tests reds the next full gate for everyone (#3638, #3648).
MSG
  exit 1
fi
echo "stale-contract-assertions: clean ($( [ $STAGED -eq 1 ] && echo staged || echo "$RANGE"))"
