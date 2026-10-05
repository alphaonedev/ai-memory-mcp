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
#   DECLARE  — a commit that changes a `.len()` count assertion says so, in a
#              trailer of its OWN message, so the merger knows a shared count moved:
#                  Count: <what> <old> -> <new> (<why>)
#              several changes may share one line, separated by ", ":
#                  Count: doctor sections 18 -> 19, hooks 4 -> 5 (adds a section and a hook)
#   RE-DERIVE — the merger sets the merged assertion from the ARITHMETIC over
#              every declaration in the chain, never from whichever number
#              survived the merge. That half is the rehearsal lane's job.
# This gate enforces DECLARE.
#
# DECLARATION RULES (5-agent vote (4d3ea1c5), decision memory
# 0b54a489-d788-48bc-83b3-3653e7a5ed4b; #5499 #5517 #5518):
#   * A declaration is read ONLY from the TRAILER BLOCK, the last paragraph of a
#     message, as `git interpret-trailers --parse` sees it. Prose that happens to
#     contain `count:`, a declaration line in the middle of the body, a `# count:`
#     line and a declaration in the subject line are NOT declarations.
#   * <old> and <new> must equal the gate's own finding, and <what> must name the
#     assertion (#5575): the whole asserted expression, or words of at least 3
#     characters that are each a WHOLE token (case-insensitive) of the expression or
#     of the file-name stem; a one-letter word, a punctuation-only word, a directory
#     name and a bare `len`/`count` name nothing. EVERY changed assertion of the commit must be
#     covered; a declaration that covers only some of them leaves the commit red.
#     Several correct declarations (own line plus later ones) are pooled, and the
#     items are CONSUMED ONE-TO-ONE against the hits (#5576): each changed
#     assertion needs its own item, so one item can never stand for two
#     assertions that merely share old and new values.
#   * LATE DECLARATION. A missed declaration cannot be added by rewriting the
#     history (force-push and rebase are forbidden), so a LATER commit of the same
#     range may declare for the offender, in its own trailer block:
#         Count-Declared: <40-char sha> <what> <old> -> <new> (<why>)
#     The sha must be the full 40 lowercase hex characters, must be inside the
#     range being checked, and must be an ancestor of the declaring commit (a
#     declaration cannot reach backwards or sideways). Declarations are read from
#     merge commits too; only non-merge commits are offenders.
#   * A malformed, mismatched, out-of-range or non-ancestor declaration NEVER
#     satisfies an offender and is REPORTED on stderr (`IGNORED`), but it is not
#     red by itself: a bad trailer cannot be removed without a rebase, and
#     making it fatal would recreate the trap. An offender is green ONLY by an
#     exact match, so the gate stays fail-closed. An offender outside the range
#     (a stacked PR) is neither examined nor required.
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
#
# FILE LISTING (#5518) — `git diff-tree -M -C --find-copies-harder`. A renamed or
# copied file is compared with its SOURCE path, so rename-plus-bump and
# copy-plus-bump stay red. An assertion is skipped as new (no earlier count
# exists to drift from; #5499) only when its file has status A in that same
# commit AND the asserted expression or constant exists in no other file of the
# parent tree. A new assertion in an EXISTING file stays red until declared.
set -u
cd "$(dirname "$0")/.." || exit 2
RANGE="HEAD~1..HEAD"; SELF_TEST=0
while [ $# -gt 0 ]; do case "$1" in
  --range) RANGE=$2; shift 2;; --self-test) SELF_TEST=1; shift;;
  *) echo "usage: $0 [--range A..B | --self-test]" >&2; exit 2;; esac; done

# gate_py check <A..B>   — findings on stdout, IGNORED reports on stderr, rc 1 on any red.
# gate_py selftest       — builds scratch repositories under .local-runs/count-selftest.
gate_py() {
  python3 - "$@" <<'PY'
import os, re, shutil, subprocess, sys

sys.setrecursionlimit(20000)       # covers() recurses once per hit of a commit

REPO = None                      # directory every git call runs in (None = the current one)
DIFF_FLAGS = ['-M', '-C', '--find-copies-harder']
FULL_SHA = re.compile(r'^[0-9a-f]{40}$')
ITEM_RE = re.compile(r'^(?P<what>\S.*?)\s+(?P<old>\(none\)|[0-9][0-9,]*)\s*->\s*(?P<new>\(none\)|[0-9][0-9,]*)$')
WHY_RE = re.compile(r'\s*\((?!none\))[^()]*\)\s*$')


def git(*a, inp=None):
    kw = {'input': inp} if inp is not None else {'stdin': subprocess.DEVNULL}
    r = subprocess.run(['git', *a], cwd=REPO, capture_output=True, text=True,
                       encoding='utf-8', errors='replace', **kw)
    return r.stdout if r.returncode == 0 else ''


def git_rc(*a):
    return subprocess.run(['git', *a], cwd=REPO, capture_output=True, stdin=subprocess.DEVNULL).returncode


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
    """-> ({expr-key: {literal, ...}}, {const names defined})"""
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
    return out, set(consts)


def eligible(p):
    return (p.startswith('src/') or p.startswith('tests/')) and p.endswith('.rs')


def read_blobs(specs):
    """One `git cat-file --batch` for many `<rev>:<path>` specs -> {spec: text}."""
    specs = [s for s in specs if '\n' not in s]
    if not specs: return {}
    p = subprocess.run(['git', 'cat-file', '--batch'], cwd=REPO, input=('\n'.join(specs) + '\n').encode(),
                       capture_output=True)
    buf, pos, out = p.stdout, 0, {}
    for s in specs:
        nl = buf.find(b'\n', pos)
        if nl < 0: break
        hdr = buf[pos:nl].split(); pos = nl + 1
        if len(hdr) == 3 and hdr[1] == b'blob':
            size = int(hdr[2]); out[s] = buf[pos:pos + size].decode('utf-8', 'replace'); pos += size + 1
    return out


_PARENT_INDEX = {}


def parent_index(parent):
    """Every count-assertion key and every const name that exists in ANY eligible file of the parent tree."""
    if parent in _PARENT_INDEX: return _PARENT_INDEX[parent]
    paths = [p for p in git('ls-tree', '-r', '--name-only', parent, '--', 'src', 'tests').split('\n') if eligible(p)]
    keys, names = set(), set()
    for text in read_blobs([f'{parent}:{p}' for p in paths]).values():
        ex, cn = extract(text)
        for k in ex:
            keys.add(k); keys.add(k.split(' [', 1)[0])
        names |= cn
    _PARENT_INDEX[parent] = (keys, names)
    return keys, names


def exists_elsewhere(parent, expr):
    keys, names = parent_index(parent)
    if expr in keys or expr.split(' [', 1)[0] in keys: return True
    return '[' in expr and expr.rsplit('[', 1)[1].rstrip(']') in names


def changed_files(c):
    """-> [(status, old_path or None, new_path or None)] with rename and copy detection (#5518)."""
    toks = git('diff-tree', '--root', *DIFF_FLAGS, '-l0', '-r', '--no-commit-id', '--name-status', '-z', c).split('\0')
    out, i = [], 0
    while i < len(toks) and toks[i]:
        st = toks[i][0]
        if st in 'RC':
            out.append((st, toks[i + 1], toks[i + 2])); i += 3
        else:
            p = toks[i + 1] if i + 1 < len(toks) else ''
            out.append((st, None if st == 'A' else p, None if st == 'D' else p)); i += 2
    return out


def count_changes(c):
    """-> [(file, expr, old, new)] one per changed count assertion of commit c."""
    parent = git('rev-parse', '--verify', '--quiet', c + '^').strip()
    entries = [e for e in changed_files(c)
               if (e[1] and eligible(e[1])) or (e[2] and eligible(e[2]))]
    specs = [f'{parent}:{e[1]}' for e in entries if parent and e[1]] + [f'{c}:{e[2]}' for e in entries if e[2]]
    blobs = read_blobs(list(dict.fromkeys(specs)))
    hits = []
    for st, op, np_ in entries:
        old, _ = extract(blobs.get(f'{parent}:{op}', '') if (parent and op) else '')
        new, _ = extract(blobs.get(f'{c}:{np_}', '') if np_ else '')
        for expr in sorted(set(old) | set(new)):
            o, n = old.get(expr, set()), new.get(expr, set())
            if o == n: continue
            if st == 'A' and not exists_elsewhere(parent, expr):
                continue                                 # a brand-new assertion in a brand-new file (#5499)
            hits.append((np_ or op, expr, ','.join(sorted(o)) or '(none)', ','.join(sorted(n)) or '(none)'))
    return hits


def trailers(msg):
    """-> [(key, value)] from the trailer block (last paragraph) only."""
    if 'count' not in msg.lower(): return []
    out = []
    for line in git('interpret-trailers', '--parse', inp=msg.rstrip('\n') + '\n').split('\n'):
        k, sep, v = line.partition(':')
        if sep and k.strip(): out.append((k.strip(), v.strip()))
    return out


def parse_items(s):
    """`<what> <old> -> <new>[, <what> <old> -> <new> ...] [(<why>)]` -> [(what, old, new)] or None."""
    s = WHY_RE.sub('', s.strip(), count=1)
    items = []
    for part in re.split(r',\s+', s):
        m = ITEM_RE.match(part.strip())
        if not m: return None
        items.append((m.group('what'), m.group('old'), m.group('new')))
    return items or None


# <what> must NAME the assertion by a real token match, never by substring (#5575). Closed-world: a word that is not
# a whole token of the asserted expression or of the file-name stem names nothing. Two accepted forms:
#   (1) the whole asserted expression, whitespace ignored (with or without its `[CONST]` suffix) — the only form that can
#       name a short variable such as `v.len()`; it cannot be met by accident;
#   (2) words, each holding identifier chunks of at least MIN_WHAT_CHUNK characters, every chunk a whole token of the
#       expression or of the file-name STEM (a directory name never counts), and at least one chunk that is not a bare
#       method name every hit carries (len, count).
MIN_WHAT_CHUNK = 3
WHAT_STOP = frozenset({'len', 'count'})
CHUNK = re.compile(r'[A-Za-z0-9_]+')


def tokens_of(text):
    """Whole identifiers and their underscore-separated parts, lower-cased."""
    out = set()
    for ident in CHUNK.findall(text):
        ident = ident.lower(); out.add(ident); out.update(q for q in ident.split('_') if q)
    return out


def names_assertion(what, hit):
    key = re.sub(r'\s+', '', hit[1]); w = re.sub(r'\s+', '', what)
    if w and w in (key, key.split('[', 1)[0]): return True        # form (1): the whole expression
    words = what.split()
    if not words or any(not CHUNK.search(x) for x in words): return False   # a punctuation-only word names nothing
    chunks = CHUNK.findall(what)
    if any(len(c) < MIN_WHAT_CHUNK for c in chunks): return False
    toks = tokens_of(hit[1]) | tokens_of(os.path.basename(hit[0]).split('.', 1)[0])
    return all(c.lower() in toks for c in chunks) and any(c.lower() not in WHAT_STOP for c in chunks)


def item_matches(item, hit):
    what, old, new = item
    return old == hit[2] and new == hit[3] and names_assertion(what, hit)


def covers(items, hits):
    """True when EVERY hit can be given its OWN item (one-to-one assignment, augmenting paths) (#5576).

    One item names one assertion: it can never stand for two hits that merely share old and new values.
    """
    owner = {}                                            # item index -> hit index

    def place(h, seen):
        for i, it in enumerate(items):
            if i in seen or not item_matches(it, hits[h]): continue
            seen.add(i)
            if i not in owner or place(owner[i], seen):
                owner[i] = h; return True
        return False
    return all(place(h, set()) for h in range(len(hits)))


def short(c):
    return c[:9]


def check_range(rng):
    """-> (rc, stdout lines, stderr lines)"""
    out, err = [], []
    commits, msgs = [], {}
    for rec in git('log', '-z', '--format=%H%x1f%B', rng).split('\0'):
        h, _, body = rec.partition('\x1f'); h = h.strip()
        if h: commits.append(h); msgs[h] = body
    in_range = set(commits)
    # Only non-merge commits are offenders. diff-tree without -m prints nothing for a merge, so --no-merges is also
    # what a future -m would need; the self-test leg 'merge commit whose tree moves a shared count' pins the pair (#5499).
    offenders = git('rev-list', '--no-merges', rng).split()
    hits = {}
    for c in offenders:
        h = count_changes(c)
        if h: hits[c] = h
    accepted = {}                                         # offender sha -> [items that match a hit]
    for d in commits:                                     # merge commits included
        for key, val in trailers(msgs[d]):
            if key.lower() != 'count-declared': continue
            m = re.match(r'^(\S+)\s+(.+)$', val)
            sha = m.group(1) if m else val
            why = None
            if not m: why = 'malformed (want: <40-char sha> <what> <old> -> <new> (<why>))'
            elif not FULL_SHA.match(sha): why = f'{sha!r} is not a full 40-character lowercase sha'
            elif sha not in in_range: why = f'{short(sha)} is outside the range {rng} (a stacked-PR offender is not checked here)'
            elif git_rc('merge-base', '--is-ancestor', sha, d) != 0: why = f'{short(sha)} is not an ancestor of the declaring commit'
            elif sha not in hits: why = f'{short(sha)} changes no count assertion'
            else:
                items = parse_items(m.group(2))
                if items is None: why = 'malformed items (want: <what> <old> -> <new>[, ...] (<why>))'
            if why:
                err.append(f'count-assertion-declared: IGNORED Count-Declared in {short(d)}: {why}'); continue
            for it in items:
                if any(item_matches(it, h) for h in hits[sha]): accepted.setdefault(sha, []).append(it)
                else: err.append(f'count-assertion-declared: IGNORED Count-Declared in {short(d)}: "{it[0]} {it[1]} -> {it[2]}" matches no change of {short(sha)}')
    rc = 0
    for c in offenders:
        if c not in hits: continue
        own = []
        for key, val in trailers(msgs[c]):
            if key.lower() != 'count': continue
            items = parse_items(val)
            if items is None: err.append(f'count-assertion-declared: IGNORED Count in {short(c)}: malformed (want: <what> <old> -> <new>[, ...] (<why>))'); continue
            for it in items:
                if any(item_matches(it, h) for h in hits[c]): own.append(it)
                else: err.append(f'count-assertion-declared: IGNORED Count in {short(c)}: "{it[0]} {it[1]} -> {it[2]}" matches no change of this commit')
        declared = own + accepted.get(c, [])
        if covers(declared, hits[c]): continue
        subj = msgs[c].split('\n', 1)[0]
        out.append(f'  {short(c)}  {subj[:70]}')
        for h in hits[c][:8]: out.append(f'      {h[0]}  {h[1]}  {h[2]} -> {h[3]}')
        rc = 1
    return rc, out, err


# ----------------------------------------------------------------------------- self-test
GENV = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
            GIT_AUTHOR_NAME='g', GIT_AUTHOR_EMAIL='g@x', GIT_COMMITTER_NAME='g', GIT_COMMITTER_EMAIL='g@x')
PAD = ''.join('// pad %d\n' % i for i in range(20))


def f_rs(n): return PAD + 'fn a() { assert_eq!(sections.len(), %s); }\n' % n
def multi_rs(n): return 'fn b() {\n    assert_eq!(\n        report.minimal_sections_with_a_deliberately_long_name.len(),\n        %s\n    );\n}\n' % n
def named_rs(n): return 'const EXPECTED_SECTIONS: usize = %s;\nfn c() { assert_eq!(report.sections.len(), EXPECTED_SECTIONS); }\n' % n
def ctrl_rs(n, m): return 'fn d() { let n = %s; assert_eq!(items.len(), n); assert!(msg.contains("len() = %s")); }\n' % (n, m)
OTHER_RS = 'fn o() { assert_eq!(shared.len(), 7); }\n'
K7_RS = 'fn k() { assert_eq!(fired.len(), 2); }\n'


class Scratch:
    def __init__(self, path):
        self.p = path; os.makedirs(path)
        self.g('init', '-q', '-b', 'main'); self.g('config', 'commit.gpgsign', 'false')
        self.tick = 0

    def g(self, *a, inp=None):
        r = subprocess.run(['git', *a], cwd=self.p, input=inp, capture_output=True, text=True, env=GENV)
        if r.returncode != 0: raise RuntimeError('git %s: %s' % (' '.join(a), r.stderr))
        return r.stdout.strip()

    def w(self, rel, text):
        fp = os.path.join(self.p, rel); os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, 'w') as f: f.write(text)

    def commit(self, msg):
        self.g('add', '-A', '--', '.'); self.g('commit', '-q', '--cleanup=verbatim', '-F', '-', inp=msg)
        return self.g('rev-parse', 'HEAD')

    def base(self):
        self.w('tests/f.rs', f_rs(18)); self.w('tests/multi.rs', multi_rs(5)); self.w('tests/named.rs', named_rs(18))
        self.w('tests/ctrl.rs', ctrl_rs(3, 4)); self.w('tests/other.rs', OTHER_RS); self.w('tests/k7.rs', K7_RS)
        self.w('notes.txt', '0\n')
        return self.commit('base')

    def touch(self, msg):                                 # a commit with no .rs change
        self.tick += 1; self.w('notes.txt', '%d\n' % self.tick); return self.commit(msg)


def selftest():
    global REPO
    root = '.local-runs/count-selftest'; shutil.rmtree(root, ignore_errors=True); os.makedirs(root)
    state = {'bad': 0, 'n': 0}

    def case(label, build, red, needles=(), errs=(), noerrs=()):
        state['n'] += 1
        global REPO
        s = Scratch(os.path.join(root, 'c%02d' % state['n']))
        b = s.base(); rng = build(s, b)
        REPO = s.p
        try:
            rc, out, err = check_range(rng)
        finally:
            REPO = None
        o, e = '\n'.join(out), '\n'.join(err)
        ok = (rc == (1 if red else 0)) and all(x in o for x in needles) and all(x in e for x in errs) and not any(x in e for x in noerrs)
        if red and not needles and not out: ok = False
        if ok: print('  ok   %s: %s' % ('RED  ' if red else 'GREEN', label))
        else:
            state['bad'] = 1
            print('  [FAIL] expected %s: %s\n    rc=%s needles=%s errs=%s\n    stdout=%s\n    stderr=%s' % ('RED' if red else 'GREEN', label, rc, list(needles), list(errs), o, e))

    D = 'Count-Declared: '
    def msg(subject, trailer=None, prose=None):
        m = subject
        if prose: m += '\n\n' + prose
        if trailer: m += '\n\n' + trailer
        return m + '\n'
    def late(off, items, sha=None):
        return D + (sha or off) + ' ' + items
    def bump_f(s, n=19): s.w('tests/f.rs', f_rs(n))
    def two_hits(s): s.w('tests/f.rs', f_rs(19)); s.w('tests/multi.rs', multi_rs(6))
    S_FF = 'sections 18 -> 19 (fixture)'

    # ---- the original fixtures (no history dependency) ---------------------------------------
    def c_single(s, b): bump_f(s); s.commit('test: bump sections'); return b + '..HEAD'
    case('single-line undeclared bump', c_single, True, ['sections.len()  18 -> 19'])
    def c_multi(s, b): s.w('tests/multi.rs', multi_rs(6)); s.commit('test: bump minimal sections (multi-line)'); return b + '..HEAD'
    case('rustfmt three-line shape, only the number line in the diff', c_multi, True, ['long_name.len()  5 -> 6'])
    def c_named(s, b): s.w('tests/named.rs', named_rs(19)); s.commit('test: bump named const'); return b + '..HEAD'
    case('named-const bump (assert names the const, the const literal moved)', c_named, True, ['EXPECTED_SECTIONS'])
    def c_ctrl(s, b): s.w('tests/ctrl.rs', ctrl_rs(4, 5)); s.commit('test: control edits'); return b + '..HEAD'
    case('variable rhs + a string literal mentioning len() are not count changes', c_ctrl, False)
    def c_decl3(s, b):
        s.w('tests/f.rs', f_rs(19)); s.w('tests/multi.rs', multi_rs(6)); s.w('tests/named.rs', named_rs(19))
        s.commit(msg('test: bump all three, declared', 'Count: sections 18 -> 19, minimal 5 -> 6, EXPECTED_SECTIONS 18 -> 19 (fixture)')); return b + '..HEAD'
    case('the same three shapes, declared with a Count: trailer', c_decl3, False)

    # ---- #5518: rename and copy detection, new-file skip -------------------------------------
    def c_rename(s, b):
        s.g('mv', 'tests/f.rs', 'tests/g.rs'); s.w('tests/g.rs', f_rs(19)); s.commit('test: move and bump'); return b + '..HEAD'
    case('rename plus bump is compared with its source', c_rename, True, ['sections.len()  18 -> 19'])
    def c_rename_d(s, b):
        s.g('mv', 'tests/f.rs', 'tests/g.rs'); s.w('tests/g.rs', f_rs(19)); s.commit(msg('test: move and bump', 'Count: sections 18 -> 19 (moved)')); return b + '..HEAD'
    case('rename plus bump, declared against the source values', c_rename_d, False)
    def c_copy(s, b):
        s.w('tests/g.rs', f_rs(19)); s.commit('test: copy and bump'); return b + '..HEAD'
    case('copy plus bump is compared with its source', c_copy, True, ['sections.len()  18 -> 19'])
    def c_pure_rename(s, b):
        s.g('mv', 'tests/f.rs', 'tests/g.rs'); s.commit('test: move only'); return b + '..HEAD'
    case('a pure rename moves no count', c_pure_rename, False)
    def c_exist_new(s, b):
        s.w('tests/f.rs', f_rs(18) + 'fn z() { assert_eq!(builds.len(), 1); }\n'); s.commit('test: new assertion, existing file'); return b + '..HEAD'
    case('a new assertion in an EXISTING file stays red', c_exist_new, True, ['builds.len()  (none) -> 1'])
    def c_newfile(s, b):
        s.w('tests/new_pin.rs', 'fn t() { assert_eq!(builds.len(), 1); }\n'); s.w('changelog.d/1.fixed.md', 'x\n'); s.commit('test: new file'); return b + '..HEAD'
    case('a new file with a new assertion, same commit, is green', c_newfile, False)
    def c_newfile_dup(s, b):
        s.w('tests/new_pin.rs', 'fn t() { assert_eq!(shared.len(), 9); }\n'); s.commit('test: new file, expression exists elsewhere'); return b + '..HEAD'
    case('a new file whose expression exists in another file stays red', c_newfile_dup, True, ['shared.len()  (none) -> 9'])
    def c_newfile_const(s, b):
        s.w('tests/new_pin.rs', 'const EXPECTED_SECTIONS: usize = 9;\nfn t() { assert_eq!(fresh.len(), EXPECTED_SECTIONS); }\n'); s.commit('test: new file, const exists elsewhere'); return b + '..HEAD'
    case('a new file naming a const that exists in another file stays red', c_newfile_const, True, ['EXPECTED_SECTIONS'])

    # ---- #5517: the own Count: line must match the diff --------------------------------------
    def c_own_ok(s, b): bump_f(s); s.commit(msg('test: bump', 'Count: sections 18 -> 19 (fixture)')); return b + '..HEAD'
    case('own Count: trailer matching the diff', c_own_ok, False)
    def c_prose(s, b): bump_f(s); s.commit(msg('test: bump', None, 'the row count: stays readable')); return b + '..HEAD'
    case('prose containing count: is not a declaration', c_prose, True, ['sections.len()  18 -> 19'])
    def c_hash(s, b): bump_f(s); s.commit(msg('test: bump', None, '# count: sections 18 -> 19')); return b + '..HEAD'
    case('a # count: line is not a declaration', c_hash, True)
    def c_own_oldbad(s, b): bump_f(s); s.commit(msg('test: bump', 'Count: sections 17 -> 19 (fixture)')); return b + '..HEAD'
    case('own Count: with a wrong old', c_own_oldbad, True, ['18 -> 19'], ['matches no change of this commit'])
    def c_own_newbad(s, b): bump_f(s); s.commit(msg('test: bump', 'Count: sections 18 -> 20 (fixture)')); return b + '..HEAD'
    case('own Count: with a wrong new', c_own_newbad, True, ['18 -> 19'])
    def c_own_wrongwhat(s, b): bump_f(s); s.commit(msg('test: bump', 'Count: zzz 18 -> 19 (fixture)')); return b + '..HEAD'
    case('own Count: naming a different assertion', c_own_wrongwhat, True)
    def c_own_partial(s, b): two_hits(s); s.commit(msg('test: bump two', 'Count: sections 18 -> 19 (fixture)')); return b + '..HEAD'
    case('own Count: covering one of two hits', c_own_partial, True, ['long_name.len()  5 -> 6'])
    def c_own_outside(s, b): bump_f(s); s.commit('test: bump\n\nCount: sections 18 -> 19 (fixture)\n\nclosing prose follows the line\n'); return b + '..HEAD'
    case('own Count: line outside the trailer block (prose after it)', c_own_outside, True)
    def c_own_subject(s, b): bump_f(s); s.commit('Count: sections 18 -> 19 (fixture)'); return b + '..HEAD'
    case('own Count: as the subject line only', c_own_subject, True)
    def c_own_delete(s, b): s.w('tests/f.rs', PAD + 'fn a() {}\n'); s.commit(msg('test: drop', 'Count: sections 18 -> (none) (removed)')); return b + '..HEAD'
    case('own Count: for a removed assertion, 18 -> (none)', c_own_delete, False)

    # ---- #5575: <what> names the assertion by whole-token match, never by substring ---------------
    def one_decl(what):
        def f_(s, b): bump_f(s); s.commit(msg('test: bump', 'Count: %s 18 -> 19 (fixture)' % what)); return b + '..HEAD'
        return f_
    for lbl, w, red in [('one-letter word', 'e', True), ('two-letter word', 'se', True), ('punctuation-only word', '..', True),
                        ('directory token only', 'tests', True), ('a number', '18', True), ('a substring of a token', 'sect', True),
                        ('a bare method name', 'len', True), ('a good word beside a one-letter word', 'sections e', True),
                        ('the whole expression', 'sections.len()', False), ('a token and the method name', 'sections len', False),
                        ('a token in upper case', 'SECTIONS', False)]:
        case('what = %s (%s)' % (w, lbl), one_decl(w), red, ['sections.len()  18 -> 19'] if red else ())
    def c_stem(s, b): s.w('tests/multi.rs', multi_rs(6)); s.commit(msg('test: bump', 'Count: multi 5 -> 6 (fixture)')); return b + '..HEAD'
    case('what = a token of the file-name stem', c_stem, False)
    def c_late_short(s, b):
        bump_f(s); o = s.commit('test: bump without a declaration'); s.touch(msg('docs: declare', late(o, 'e 18 -> 19 (fixture)'))); return b + '..HEAD'
    case('late declaration with a one-letter what', c_late_short, True, ['sections.len()  18 -> 19'])

    # ---- #5576: items are consumed one-to-one against hits -----------------------------------------------
    def two_same(s): bump_f(s); s.w('tests/named.rs', named_rs(19))       # two different assertions, both 18 -> 19, both name `sections`
    def decl_two(items):
        def f_(s, b): two_same(s); s.commit(msg('test: bump two', 'Count: %s (fixture)' % items)); return b + '..HEAD'
        return f_
    case('one item for two assertions sharing old and new (#5576)', decl_two('sections 18 -> 19'), True, ['EXPECTED_SECTIONS', 'sections.len()  18 -> 19'])
    case('the same item twice covers two assertions', decl_two('sections 18 -> 19, sections 18 -> 19'), False)
    case('two distinct items, token then const', decl_two('sections 18 -> 19, EXPECTED_SECTIONS 18 -> 19'), False)
    case('two distinct items, const then token (assignment order)', decl_two('EXPECTED_SECTIONS 18 -> 19, sections 18 -> 19'), False)
    case('the const item alone leaves the other assertion uncovered', decl_two('EXPECTED_SECTIONS 18 -> 19'), True, ['sections.len()  18 -> 19'])
    case('an item that matches nothing plus one real item for two hits', decl_two('zzzz 18 -> 19, sections 18 -> 19'), True)
    def c_pool(s, b):                                     # own item plus a late item are pooled and consumed once each
        two_same(s); o = s.commit(msg('test: bump two', 'Count: sections 18 -> 19 (fixture)'))
        s.touch(msg('docs: declare the other', late(o, 'EXPECTED_SECTIONS 18 -> 19 (fixture)'))); return b + '..HEAD'
    case('own item plus a late item cover two assertions', c_pool, False)
    def c_pool_dup(s, b):                                 # the same item declared twice (own and late) covers ONE hit twice
        two_same(s); o = s.commit(msg('test: bump two', 'Count: sections 18 -> 19 (fixture)'))
        s.touch(msg('docs: declare again', late(o, 'sections 18 -> 19 (fixture)'))); return b + '..HEAD'
    case('own and late item with the SAME value pair cover two assertions (one each)', c_pool_dup, False)
    def c_late_one(s, b):
        two_same(s); o = s.commit('test: bump two without a declaration')
        s.touch(msg('docs: declare once', late(o, 'sections 18 -> 19 (fixture)'))); return b + '..HEAD'
    case('one late item for two assertions sharing old and new', c_late_one, True, ['EXPECTED_SECTIONS'])
    def c_three(s, b):
        two_same(s); s.w('tests/multi.rs', multi_rs(6)); s.commit(msg('test: bump three', 'Count: sections 18 -> 19, minimal 5 -> 6 (fixture)')); return b + '..HEAD'
    case('three assertions, two items', c_three, True)

    # ---- #5499: late declaration -------------------------------------------------------------
    def offender(s, b, two=False):
        (two_hits if two else bump_f)(s); return s.commit('test: bump without a declaration')
    def c_late_ok(s, b):
        o = offender(s, b); s.touch(msg('docs: declare', late(o, S_FF))); return b + '..HEAD'
    case('late declaration naming the offender', c_late_ok, False)
    def c_late_badsha(s, b):
        o = offender(s, b); s.touch(msg('docs: declare', late(o, S_FF, sha=o[:-1] + ('0' if o[-1] != '0' else '1')))); return b + '..HEAD'
    case('late declaration with a wrong sha', c_late_badsha, True, ['sections.len()  18 -> 19'], ['IGNORED'])
    def c_late_oldbad(s, b):
        o = offender(s, b); s.touch(msg('docs: declare', late(o, 'sections 17 -> 19 (fixture)'))); return b + '..HEAD'
    case('late declaration with a wrong old', c_late_oldbad, True, ['18 -> 19'], ['matches no change of'])
    def c_late_newbad(s, b):
        o = offender(s, b); s.touch(msg('docs: declare', late(o, 'sections 18 -> 20 (fixture)'))); return b + '..HEAD'
    case('late declaration with a wrong new', c_late_newbad, True, ['18 -> 19'], ['matches no change of'])
    def c_late_whatbad(s, b):
        o = offender(s, b); s.touch(msg('docs: declare', late(o, 'zzz 18 -> 19 (fixture)'))); return b + '..HEAD'
    case('late declaration naming a different assertion', c_late_whatbad, True, ['18 -> 19'])
    def c_late_abbrev(s, b):
        o = offender(s, b); s.touch(msg('docs: declare', late(o, S_FF, sha=o[:12]))); return b + '..HEAD'
    case('late declaration with an abbreviated sha', c_late_abbrev, True, ['18 -> 19'], ['40-character'])
    def c_late_partial(s, b):
        o = offender(s, b, two=True); s.touch(msg('docs: declare', late(o, S_FF))); return b + '..HEAD'
    case('late declaration covering one of two hits', c_late_partial, True, ['long_name.len()  5 -> 6'])
    def c_late_union(s, b):
        o = offender(s, b, two=True)
        s.touch(msg('docs: declare one', late(o, S_FF))); s.touch(msg('docs: declare two', late(o, 'minimal 5 -> 6 (fixture)'))); return b + '..HEAD'
    case('two correct declarations that together cover both hits', c_late_union, False)
    def c_late_both(s, b):
        o = offender(s, b, two=True); s.touch(msg('docs: declare', late(o, 'sections 18 -> 19, minimal 5 -> 6 (fixture)'))); return b + '..HEAD'
    case('one late declaration covering both hits', c_late_both, False)
    def c_late_earlier(s, b):                             # the declaring commit is NOT a descendant of the offender
        o = offender(s, b)
        s.g('checkout', '-q', '-b', 'side', b); s.touch(msg('docs: declare early', late(o, S_FF)))
        s.g('checkout', '-q', 'main'); s.g('merge', '-q', '--no-ff', '-m', 'merge side', 'side'); return b + '..HEAD'
    case('declaration in a commit that is not a descendant of the offender', c_late_earlier, True, ['18 -> 19'], ['not an ancestor'])
    def c_evil_merge(s, b):                               # a merge whose tree moves a shared count is not an offender (only non-merge commits are)
        s.g('checkout', '-q', '-b', 'side', b); s.w('side.txt', '1\n'); s.commit('side work')
        s.g('checkout', '-q', 'main'); s.touch('main work')
        s.g('merge', '-q', '--no-ff', '--no-commit', 'side'); bump_f(s); s.commit('merge side with a bump in the merge tree'); return b + '..HEAD'
    case('merge commit whose tree moves a shared count is not an offender (#5499)', c_evil_merge, False)
    def c_plain_same(s, b): bump_f(s); s.commit('test: same bump as a plain commit'); return b + '..HEAD'
    case('non-merge commit with the same bump is an offender (#5499)', c_plain_same, True, ['sections.len()  18 -> 19'])
    def c_late_merge(s, b):                               # declaration read from a MERGE commit
        o = offender(s, b)
        s.g('checkout', '-q', '-b', 'side', b); s.touch('docs: side work'); s.g('checkout', '-q', 'main')
        s.g('merge', '-q', '--no-ff', '-m', msg('merge side', late(o, S_FF)), 'side'); return b + '..HEAD'
    case('declaration carried by a merge commit', c_late_merge, False)
    def c_late_outside(s, b):
        o = offender(s, b); s.touch('docs: declare outside the trailer block\n\n' + late(o, S_FF) + '\n\nclosing prose after the declaration\n'); return b + '..HEAD'
    case('declaration phrase outside the trailer block', c_late_outside, True, ['18 -> 19'])
    def c_late_middle(s, b):
        o = offender(s, b); s.touch(msg('docs: declare in the body', None, late(o, S_FF) + '\nmore prose on the next line')); return b + '..HEAD'
    case('declaration in a prose paragraph', c_late_middle, True, ['18 -> 19'])
    def c_late_stack(s, b):                               # the offender is below the range start: neutral
        o = offender(s, b); s.touch(msg('docs: declare', late(o, S_FF))); return o + '..HEAD'
    case('stacked-PR offender outside the range is neutral', c_late_stack, False, [], ['outside the range'])
    def c_late_stack2(s, b):
        offender(s, b); s.touch('docs: unrelated'); return 'HEAD~1..HEAD'
    case('an undeclared offender outside the range is not required', c_late_stack2, False)
    def c_late_badgood(s, b):
        o = offender(s, b)
        s.touch(msg('docs: declare badly', late(o, 'sections 17 -> 19 (fixture)'))); s.touch(msg('docs: declare correctly', late(o, S_FF))); return b + '..HEAD'
    case('a bad declaration followed by a correct one', c_late_badgood, False, [], ['IGNORED'])
    def c_late_nooff(s, b):
        n = s.touch('docs: no count change'); s.touch(msg('docs: declare a non-offender', late(n, S_FF))); return b + '..HEAD'
    case('a declaration naming a commit that changes no count is reported, not red', c_late_nooff, False, [], ['changes no count assertion'])
    def c_late_malformed(s, b):
        o = offender(s, b); s.touch(msg('docs: declare', D + o)); return b + '..HEAD'
    case('a late declaration without items is malformed', c_late_malformed, True, ['18 -> 19'], ['IGNORED'])
    def c_late_delete(s, b):
        s.w('tests/f.rs', PAD + 'fn a() {}\n'); o = s.commit('test: drop assertion')
        s.touch(msg('docs: declare', late(o, 'sections 18 -> (none) (removed)'))); return b + '..HEAD'
    case('late declaration for a removed assertion, 18 -> (none)', c_late_delete, False)

    def c_multival(s, b):                                 # one expression asserted with two literals: the set moves as a whole
        s.w('tests/rec.rs', 'fn r() { assert_eq!(recs.len(), 2); assert_eq!(recs.len(), 3); }\n'); c1 = s.commit('test: new file')
        s.w('tests/rec.rs', 'fn r() { assert_eq!(recs.len(), 3); assert_eq!(recs.len(), 4); }\n')
        s.commit(msg('test: bump', 'Count: recs 2,3 -> 3,4 (fixture)')); return c1 + '..HEAD'
    case('own Count: for an expression asserted with two literals, 2,3 -> 3,4', c_multival, False)
    def c_bigrename(s, b):                                # more candidates than diff.renameLimit allows (-l0 is load-bearing)
        s.g('config', 'diff.renameLimit', '3')
        for i in range(8): s.w('tests/big/b%d.rs' % i, 'fn x%d() { let a = %d; }\n' % (i, i))
        b2 = s.commit('base: many files')
        for i in range(8): s.w('tests/big/n%d.rs' % i, 'fn y%d() { let a = %d; }\n' % (i, i + 7))
        s.w('tests/g.rs', f_rs(19)); s.commit('test: copy and bump among many new files'); return b2 + '..HEAD'
    case('copy plus bump in a commit with more candidates than diff.renameLimit', c_bigrename, True, ['sections.len()  18 -> 19'])
    def c_nowhy(s, b): bump_f(s); s.commit(msg('test: bump', 'Count: sections 18 -> 19')); return b + '..HEAD'
    case('own Count: without a (why) is still compared with the diff', c_nowhy, False)
    def c_nowhy_none(s, b): s.w('tests/f.rs', PAD + 'fn a() {}\n'); s.commit(msg('test: drop', 'Count: sections 18 -> (none)')); return b + '..HEAD'
    case('own Count: 18 -> (none) without a (why)', c_nowhy_none, False)

    # ---- the two real carriers ---------------------------------------------------------------
    def c_carrier_new(s, b):                              # 7bf6d358a: new test file, src edit, changelog fragment
        s.w('src/cost/postgres.rs', 'pub fn cost() -> usize { 1 }\n'); s.w('changelog.d/3946.fixed.md', 'x\n')
        s.w('tests/containment_relational_3946.rs', 'fn t() { assert_eq!(rewound.len(), 3); assert_eq!(stamped.len(), 2); }\n')
        s.commit(msg('fix(#3946): read relational lineage', 'Closes #3946')); return b + '..HEAD'
    case('carrier 7bf6d358a shape: new test file with new assertions', c_carrier_new, False)
    def c_carrier_none(s, b):                             # d478016b7: (none) -> 1 in an existing test file
        s.w('tests/k7.rs', K7_RS + 'fn k2() { assert_eq!(signed.len(), 1); }\n'); s.w('src/subscriptions.rs', 'pub fn s() {}\n')
        s.commit(msg('fix(#3941): snapshot the secret', 'Closes #3941')); return b + '..HEAD'
    case('carrier d478016b7 shape: (none) -> 1 in an existing file, undeclared', c_carrier_none, True, ['signed.len()  (none) -> 1'])
    def c_carrier_late(s, b):
        s.w('tests/k7.rs', K7_RS + 'fn k2() { assert_eq!(signed.len(), 1); }\n'); o = s.commit(msg('fix(#3941): snapshot the secret', 'Closes #3941'))
        s.touch(msg('docs: declare', late(o, 'signed (none) -> 1 (new pin)'))); return b + '..HEAD'
    case('carrier d478016b7 shape, declared late', c_carrier_late, False)

    shutil.rmtree(root, ignore_errors=True)
    return state['bad']


mode = sys.argv[1] if len(sys.argv) > 1 else ''
if mode == 'check':
    rc, out, err = check_range(sys.argv[2])
    for line in out: print(line)
    sys.stdout.flush()
    for line in err: print(line, file=sys.stderr)
    sys.exit(rc)
if mode == 'selftest':
    sys.exit(selftest())
sys.exit(2)
PY
}

check_range() { gate_py check "$1"; } # $1 = A..B ; findings on stdout, reports on stderr, rc 1 on any red

if [ "$SELF_TEST" -eq 1 ]; then
  # SELF-CONTAINED FIXTURES (no history dependency): scratch repositories under
  # .local-runs/count-selftest, never /tmp, one per case; every case builds its own
  # base, offender and declarations, so no case depends on another.
  gate_py selftest; bad=$?
  # REFUSAL LEGS (Conductor ruling, #3688 c5660422072): "clean" must mean examined-and-found-nothing,
  # never could-not-look. Re-invoke this script with (a) a range whose start does not resolve and
  # (b) GIT_DIR pointed at a non-repository (the git-less-export shape): both must REFUSE, exit 2,
  # and neither may print "clean".
  SELF_PATH=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
  # The detection flags are pinned by their literal text: -C implies -M and --find-copies-harder implies -C
  # in git, so dropping one alone changes no behaviour and no fixture can tell; the three are listed
  # explicitly because the #5518 decision names them, and this pin keeps the list whole.
  grep -qE "DIFF_FLAGS = \\['-M', '-C', '--find-copies-harder'\\]" "$SELF_PATH" || { echo "  [FAIL] DIFF_FLAGS must list -M -C --find-copies-harder (#5518)"; bad=1; }
  r_out=$(bash "$SELF_PATH" --range nosuch-3688..HEAD 2>&1); r_rc=$?
  g_out=$(GIT_DIR=/nonexistent-3688 bash "$SELF_PATH" 2>&1); g_rc=$?
  refuse_ok=1
  { [ "$r_rc" -eq 2 ] && printf '%s' "$r_out" | grep -q REFUSED && ! printf '%s' "$r_out" | grep -q ': clean'; } || refuse_ok=0
  { [ "$g_rc" -eq 2 ] && printf '%s' "$g_out" | grep -q REFUSED && ! printf '%s' "$g_out" | grep -q ': clean'; } || refuse_ok=0
  [ "$refuse_ok" -eq 1 ] || { echo "count-assertion-declared self-test: FAIL — an uncomputable range or a non-repository did not REFUSE (rc=$r_rc/$g_rc): $r_out | $g_out"; exit 1; }
  [ "$bad" -eq 0 ] && { echo "count-assertion-declared self-test: PASS (whole-file assertion sets; rename/copy-aware new-file skip; own Count: and late Count-Declared: trailers compared with the diff for every hit; fixtures synthesised, no history dependency; an uncomputable range or a non-repository is REFUSED, never clean)"; exit 0; }
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
commit's trailer block (the last paragraph of the message):
    Count: <what> <old> -> <new> (<why>)
or, from a LATER commit of the same range (the range cannot be rewritten):
    Count-Declared: <40-char sha of the offender> <what> <old> -> <new> (<why>)
<old> and <new> must equal the finding above for EVERY changed assertion.
MSG
  exit 1
fi
echo "count-assertion-declared: clean ($RANGE)"
