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
#   DECLARE  — a commit that changes a `.len()`/`.count()` count assertion says so, in a
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
#     assertion (#5575): either the whole asserted expression, or words of which AT
#     LEAST ONE is a whole token (case-insensitive) of the expression or of the
#     file-name stem, other than `len`/`count`; the other words are free prose of at
#     least 3 characters. A word with a chunk of one or two characters, or a
#     punctuation-only word, refuses the whole item; the file path or file name of
#     the assertion is skipped as context (#5712). EVERY changed assertion of the commit must be
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
# gate exists for. So for every .rs file a commit touches under the
# repository-root src/ and tests/ directories (#5711, #5716; tools/*/src, examples/,
# benches/ and fuzz/ are not checked),
# the OLD and NEW contents are parsed whole (`//` line comments stripped and
# double-quoted string literals blanked; a `/* */` block comment is read as code,
# and a raw string is blanked only up to its first inner quote, #5712, #5715), every
# count assertion is extracted as (normalised expression, value), and the two
# sets are compared: an assertion whose value moved, appeared or disappeared is a
# count change, except that an assertion whose values are all undecidable
# `?<spelling>` values holding no `#` neither appears nor disappears (a
# `?NAME#unresolved`, `?NAME#ambiguous(..)` or `?count#ambiguous` value is
# never exempt). Reversed operands and `assert_ne!`
# are not read (#5714).
# WHAT IS READ (#5759) — the WHOLE first argument decides, never the first count
# call found inside it:
#   * assert_eq!: read only when the first argument is ONE operand that ends in
#     `.len()` or `.count()` (so `v.iter().filter(|x| x.len() == 2).count()` reads
#     as itself). A first argument whose last term is not exactly `.len()` or
#     `.count()` (a tuple, `v.len() + 1`, `v.len() as u32`, `&v[..v.len()]`,
#     `f(v.len())`, a path call `<[u8]>::len(v)`, `v.len ()` with a space inside
#     the call) is neither read nor tracked (#5799, #5801).
#   * assert!: read only when the first argument has exactly one `==` outside
#     every bracket, no `&&` and no `|` outside every bracket, and the left
#     operand ends in `.len()` or `.count()`.
#   * AMBIGUOUS assert! (#5797, #5798): any other first argument in which the
#     LEFT OPERAND of some `==`, at any bracket depth, holds a count call
#     (`.len()` or `.count()`, spaces allowed after the dot and inside the
#     call, never an argument). That operand
#     runs back from the `==` to the nearest `&&`, `||`, `==`, `!=`, `=>`, `,`
#     or `;` at the same depth, or to the bracket that opens that depth, so
#     nothing between the call and the `==` hides it: a cast to any type, braces,
#     a block comment, a method chain such as `.into()`, a line break or
#     arithmetic. Every shape the reader does not bind is decided by this rule
#     alone: a comparison inside a closure only, behind `&&` or `||`, negated,
#     parenthesised or chained with a second `==` is ambiguous exactly when such
#     a left operand holds the count call. It is never guessed: it is
#     tracked under its whole spelling with the value `?count#ambiguous`, which
#     is never exempt (so adding, removing or rewording it is a count change),
#     and every const name in it is tracked as `<spelling> [NAME]` with the
#     const's value, so bumping that const is a count change too.
#   * NOT READ assert! (stated limits): a count call only on the right of every
#     `==` (reversed operands, `18 == v.len()`, also behind `&&`; #5714); a count
#     compared without `==` (`v.len().eq(&18)`, `matches!(v.len(), 18)`; #5800);
#     a count spelled as a path call (`<[u8]>::len(v) == 18`), a free function
#     (`row_count() == 18`) or a call with an argument (`m.count(k) == 18`; #5801).
# The named-const spelling — `assert_eq!(x.len(), EXPECTED)` with
# `const EXPECTED: usize = 19;` — is resolved the same way: a const that a
# count assertion names, whose literal moved, is a count change.
#
# FILE LISTING (#5518) — `git diff-tree -M -C --find-copies-harder`. A renamed or
# copied file is compared with its SOURCE path, so rename-plus-bump and
# copy-plus-bump stay red. An assertion is skipped as new (no earlier count
# exists to drift from; #5499) only when its file has status A in that same
# commit AND the asserted expression or constant exists in no checked (src/ or
# tests/) .rs file of the parent tree. A new assertion in an EXISTING file stays
# red until declared.
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
# a value is `(none)`, or comma-joined decimal integers and/or `?<spelling>` undecidable right-hand sides (#5577)
VALTOK = r'(?:[0-9]+|\?[^\s,]+?)'
VAL = r'(?:\(none\)|' + VALTOK + r'(?:,' + VALTOK + r')*)(?=\s|,|->|$)'
ITEM_RE = re.compile(r'^(?P<what>\S.*?)\s+(?P<old>' + VAL + r')\s*->\s*(?P<new>' + VAL + r')$')
WHY_RE = re.compile(r'\s*\((?!none\))[^()]+\)\s*$')


def git(*a, inp=None):
    kw = {'input': inp} if inp is not None else {'stdin': subprocess.DEVNULL}
    r = subprocess.run(['git', *a], cwd=REPO, capture_output=True, text=True,
                       encoding='utf-8', errors='replace', **kw)
    return r.stdout if r.returncode == 0 else ''


def git_rc(*a):
    return subprocess.run(['git', *a], cwd=REPO, capture_output=True, stdin=subprocess.DEVNULL).returncode


LIT = re.compile(r'"(?:[^"\\]|\\.)*"', re.S)
CHR = re.compile(r"'(?:[^'\\\n]|\\[^\n]|\\u\{[0-9a-fA-F_]+\})'")


def clean(t):
    t = re.sub(r'//[^\n]*', '', t)                       # line comments
    return CHR.sub("''", LIT.sub('""', t))               # string and char literals are not code


# The full Rust integer literal grammar (#5577): decimal, 0x, 0o, 0b, underscores, a type suffix. Normalised to decimal.
INT_RE = re.compile(r'^(?P<body>0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+|[0-9][0-9_]*)'
                    r'(?:_?(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize))?$')
PATH_CONST = re.compile(r'^(?:[A-Za-z_][A-Za-z0-9_]*::)*(?P<name>[A-Z][A-Z0-9_]*)$')   # NAME, crate::NAME, a::b::NAME


def int_value(tok):
    """-> decimal string of an integer literal, or None when tok is not exactly one."""
    m = INT_RE.match(tok.strip())
    if not m: return None
    body = m.group('body'); base = {'0x': 16, '0o': 8, '0b': 2}.get(body[:2], 10)
    digits = body[2:] if base != 10 else body
    digits = digits.replace('_', '')
    return str(int(digits, base)) if digits else None


# assert_eq!(<expr>.len()|.count(), <rhs>[, message]) and assert!(<expr>.len()|.count() == <rhs>[, message]) (#5710),
# where the WHOLE first argument has that shape (#5759; see WHAT IS READ in the header);
# HEAD has no word boundary, so a prefixed name (debug_assert_eq!, debug_assert!) matches too. The macro arguments are
# cut out with balanced brackets, so a right-hand side of ANY shape is seen (a typed literal, an expression, a path).
HEAD = re.compile(r'assert(?P<eq>_eq)?!\s*\(')
TAIL = re.compile(r'^(?P<expr>\S.*)\.(?P<m>len|count)\(\)$', re.S)     # a WHOLE operand that ends in .len() or .count()
# a count call: `.len()` or `.count()`, spaces allowed around the name and inside the parentheses
COUNT_CALL = re.compile(r'\.\s*(?:len|count)\s*\(\s*\)')
# what ends the left operand of a `==` at its own bracket depth (scanning back from the `==`)
OPERAND_STOPS = ('&&', '||', '==', '!=', '=>')
CONST = re.compile(r'\bconst\s+(?P<name>[A-Z][A-Z0-9_]*)\s*:\s*(?:usize|u\d+|i\d+)\s*=\s*(?P<val>[^;]+?)\s*;')


def macro_args(t, i):
    """t[i:] follows a macro's '('. -> the text up to the matching ')', or None when unbalanced, when a ';' is met at
    depth 0, or when the first depth-0 closer is not ')'."""
    depth, angle, j, n = 0, 0, i, len(t)
    while j < n:
        ch = t[j]
        if ch in '([{': depth += 1
        elif ch in ')]}':
            if depth == 0: return t[i:j] if ch == ')' else None
            depth -= 1
        elif ch == ';' and depth == 0: return None
        j += 1
    return None


def split_arg(rest):
    """-> (the first top-level comma-separated argument of `rest`, stripped; the text after its comma, or None when
    there is no further argument). Turbofish commas do not split."""
    depth, angle, j, n = 0, 0, 0, len(rest)
    while j < n:
        ch = rest[j]
        if rest.startswith('::<', j): angle += 1; j += 3; continue
        if angle and ch == '<': angle += 1
        elif angle and ch == '>' and rest[j - 1:j] != '-': angle -= 1
        elif ch in '([{': depth += 1
        elif ch in ')]}': depth -= 1
        elif ch == ',' and depth == 0 and angle == 0: return rest[:j].strip(), rest[j + 1:]
        j += 1
    return rest.strip(), None


def first_arg(rest):
    return split_arg(rest)[0]


def top_ops(arg):
    """-> (offsets of every `==` at paren, bracket and brace depth 0 of `arg`; True when depth 0 also holds `&&` or a
    `|`, i.e. a logical operator or a closure)."""
    depth, eqs, logic, j, n = 0, [], False, 0, len(arg)
    while j < n:
        ch = arg[j]
        if ch in '([{': depth += 1
        elif ch in ')]}': depth -= 1
        elif depth == 0 and arg.startswith('==', j): eqs.append(j); j += 2; continue
        elif depth == 0 and (ch == '|' or arg.startswith('&&', j)): logic = True
        j += 1
    return eqs, logic


AMBIG = '?count#ambiguous'


def compares_count(arg):
    """True when the LEFT OPERAND of some `==` of `arg`, at ANY bracket depth, holds a count call (#5797, #5798).
    The left operand runs back from the `==` to the nearest `&&`, `||`, `==`, `!=`, `=>`, `,` or `;` at the same
    depth, or to the bracket that opens that depth; whatever else sits between the call and the `==` (a cast to any
    type, braces, a block comment, a method chain, a line break, arithmetic) keeps the call in the operand."""
    starts, j, n = [0], 0, len(arg)                       # starts[-1]: where the current operand begins at this depth
    while j < n:
        ch, two = arg[j], arg[j:j + 2]
        if ch in '([{': starts.append(j + 1)
        elif ch in ')]}':
            if len(starts) > 1: starts.pop()
        elif two == '==':
            if COUNT_CALL.search(arg, starts[-1], j): return True
            starts[-1] = j + 2; j += 2; continue
        elif two in OPERAND_STOPS: starts[-1] = j + 2; j += 2; continue
        elif ch in ',;': starts[-1] = j + 1
        j += 1
    return False


def read_cond(arg):
    """assert!'s first argument -> (expr, method, rhs) when the WHOLE argument is `<expr>.len()|.count() == <rhs>`: one
    `==` at depth 0, no depth-0 `&&` or `|`, and the left operand ends in the count call (#5710, #5759). Any other
    argument in which the left operand of some `==`, at any bracket depth, holds a count call (compares_count) ->
    AMBIG, never a guess (#5797, #5798); otherwise -> None."""
    eqs, logic = top_ops(arg)
    if len(eqs) == 1 and not logic:
        m = TAIL.match(arg[:eqs[0]].strip())
        if m: return m.group('expr'), m.group('m'), arg[eqs[0] + 2:].strip()
    return AMBIG if compares_count(arg) else None


# A const-shaped name (NAME, a::NAME, <T as Tr>::NAME) anywhere in an ambiguous assert!'s first argument; a name right
# after `::` is qualified even when no path word precedes it.
NAMES = re.compile(r'(?<![A-Za-z0-9_])(?P<path>(?:[A-Za-z_][A-Za-z0-9_]*::)*)(?P<name>[A-Z][A-Z0-9_]*)(?![A-Za-z0-9_])')


def named(consts, name, qualified):
    """A const name's value: this file's const when the name is unqualified, else `@NAME` for resolve()."""
    v = consts.get(name) if not qualified else None
    return v if v is not None else '@' + name


def extract(text):
    """-> ({expr-key: {value, ...}}, {const name: value}, {const names referenced from another file}).
    A value is a decimal integer, `?<spelling>` (undecidable right-hand side) or `@NAME` (a name not defined as a const in
    this file: resolved by resolve() against every eligible .rs file of the tree, never guessed here)."""
    text = clean(text)
    consts = {}
    for m in CONST.finditer(text):
        v = int_value(m.group('val'))
        consts[m.group('name')] = v if v is not None else '?' + re.sub(r'\s+', '', m.group('val'))   # a non-literal value is undecidable, never dropped (#5578)
    out = {}
    for h in HEAD.finditer(text):
        args = macro_args(text, h.end())
        if args is None: continue
        first, more = split_arg(args)
        if h.group('eq'):                                 # assert_eq!: the WHOLE first argument is the count call
            m = TAIL.match(first)
            if not m or more is None: continue
            got, rhs = (m.group('expr'), m.group('m')), first_arg(more)
        else:                                             # assert!: the WHOLE first argument is `<expr>.len() == <rhs>`
            got = read_cond(first)
            if got is None: continue
            if got == AMBIG:                              # undecidable shape: tracked by its whole spelling, never exempt
                key = re.sub(r'\s+', '', first)
                out.setdefault(key, set()).add(AMBIG)
                for nm in NAMES.finditer(first):          # and every const it names, so a bump of one moves it
                    out.setdefault(f"{key} [{nm.group('name')}]", set()).add(named(consts, nm.group('name'), nm.group('path') or first[:nm.start()].endswith('::')))
                continue
            got, rhs = got[:2], got[2]
        expr = re.sub(r'\s+', '', got[0]) + '.' + got[1] + '()'
        val = int_value(rhs)
        if val is None:
            pc = PATH_CONST.match(rhs)
            if pc:                                        # a named const: this file first, else the whole tree (#5578)
                name = pc.group('name')
                val = named(consts, name, '::' in rhs)
                expr += f' [{name}]'                      # name the const the count is spelled through
            else:
                val = '?' + re.sub(r'\s+', '', rhs)         # undecidable: neither a literal nor a const (#5577)
        out.setdefault(expr, set()).add(val)
    refs = {v[1:] for vs in out.values() for v in vs if v.startswith('@')}
    return out, consts, refs


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


# ---- tree-wide state (#5578): every eligible file's assertions and consts, kept incrementally commit to commit ------
_STATE = {}     # rev -> {path: (assertions, consts)}
_DEFS = {}      # rev -> {const name: [(path, value), ...]}
_KEYS = {}      # rev -> (all assertion keys, all const names)


def build_state(rev):
    """Full state of one tree: ONE cat-file batch over every eligible file."""
    if rev in _STATE: return _STATE[rev]
    paths = [p for p in git('ls-tree', '-r', '--name-only', rev, '--', 'src', 'tests').split('\n') if eligible(p)]
    st = {}
    for spec, text in read_blobs([f'{rev}:{p}' for p in paths]).items():
        st[spec.split(':', 1)[1]] = extract(text)
    _STATE[rev] = st
    return st


def defs_of(rev):
    """{const name: [(path, value)]} over every eligible (src/, tests/) .rs file of rev."""
    if rev not in _DEFS:
        d = {}
        for path, (_, consts, _r) in _STATE[rev].items():
            for n, v in consts.items(): d.setdefault(n, []).append((path, v))
        _DEFS[rev] = d
    return _DEFS[rev]


def resolve(rev, assertions):
    """Replace every `@NAME` with its value over the eligible files of the tree: exactly one definition -> its value; none -> `?NAME#unresolved`;
    several (two files define the name) -> `?NAME#ambiguous(<every value>)`, so a bump of either definition still moves it. Closed-world: a name that cannot be resolved to ONE integer
    stays a `?` state, which is a move unless the state is identical on both sides (#5578, #5672)."""
    out = {}
    for k, vals in assertions.items():
        rv = set()
        for v in vals:
            if v.startswith('@'):
                ds = defs_of(rev).get(v[1:], [])
                v = ds[0][1] if len(ds) == 1 else (f"?{v[1:]}#ambiguous({','.join(sorted(x[1] for x in ds))})" if ds else f'?{v[1:]}#unresolved')
            rv.add(v)
        out[k] = rv
    return out


def exists_elsewhere(parent, expr):
    if parent not in _KEYS:
        keys, names = set(), set()
        for ex, cn, _r in build_state(parent).values():
            for k in ex:
                keys.add(k); keys.add(k.split(' [', 1)[0])
            names |= set(cn)
        _KEYS[parent] = (keys, names)
    keys, names = _KEYS[parent]
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
    """-> [(file, expr, old, new)] one per changed count assertion of commit c, consts resolved over the eligible files of the tree."""
    parent = git('rev-parse', '--verify', '--quiet', c + '^').strip()
    entries = [e for e in changed_files(c)
               if (e[1] and eligible(e[1])) or (e[2] and eligible(e[2]))]
    old_st = build_state(parent) if parent else {}
    if parent: _STATE.setdefault(parent, old_st)
    specs = [f'{c}:{e[2]}' for e in entries if e[2] and eligible(e[2])]
    blobs = read_blobs(list(dict.fromkeys(specs)))
    new_st = dict(old_st)
    for st, op, np_ in entries:
        if st in 'RD' and op: new_st.pop(op, None)
        if np_ and eligible(np_): new_st[np_] = extract(blobs.get(f'{c}:{np_}', ''))
    _STATE[c] = new_st
    pairs = [(st, op, np_) for st, op, np_ in entries]
    # a const defined elsewhere that moved: every assertion spelled through its name is re-read (M12)
    moved = set()
    for st, op, np_ in entries:
        o = old_st.get(op, ({}, {}, set()))[1] if op else {}
        n = new_st.get(np_, ({}, {}, set()))[1] if np_ else {}
        moved |= {k for k in set(o) | set(n) if o.get(k) != n.get(k)}
    touched = {e[2] for e in entries if e[2]}
    if moved:
        for path, (_e, _c, refs) in new_st.items():
            if path not in touched and not moved.isdisjoint(refs): pairs.append(('M', path, path))
    hits = []
    for st, op, np_ in pairs:
        old = resolve(parent, old_st[op][0]) if (parent and op and op in old_st) else {}
        new = resolve(c, new_st[np_][0]) if (np_ and np_ in new_st) else {}
        for expr in sorted(set(old) | set(new)):
            o, n = old.get(expr, set()), new.get(expr, set())
            if o == n: continue
            if (not o and all(v.startswith('?') and '#' not in v for v in n)) or (not n and all(v.startswith('?') and '#' not in v for v in o)):
                continue                                 # an assertion with no literal count on either side moves no count (#5577)
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
#   (2) words, none holding an identifier chunk shorter than MIN_WHAT_CHUNK characters or no identifier at all, with
#       at least one chunk that is a whole token of the expression or of the file-name STEM (a directory name never
#       counts) and is not a bare method name every hit carries (len, count). The hit's own path may appear as a word.
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
    path, base = hit[0], os.path.basename(hit[0])
    toks = tokens_of(hit[1]) | tokens_of(base.split('.', 1)[0])
    named = False
    for word in what.split():
        if word in (path, base): continue                         # the file the assertion lives in: context, names nothing alone
        chunks = CHUNK.findall(word)
        if not chunks: return False                               # a punctuation-only word names nothing
        if any(len(c) < MIN_WHAT_CHUNK for c in chunks): return False   # a one- or two-character word is never accepted
        if any(c.lower() in toks and c.lower() not in WHAT_STOP for c in chunks): named = True   # a whole-token match
    return named                                                  # other (>= 3 character) words are free prose


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
    for c in reversed(offenders):                         # oldest first: each commit's tree state is built from its parent's
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
    case('what = a token plus free prose of 3+ characters', one_decl('sections trail test'), False)
    case('what = a good token plus a punctuation-only word is refused', one_decl('sections ..'), True)
    case('what = the hit path plus a token', one_decl('tests/f.rs sections'), False)
    case('what = the hit path alone names nothing', one_decl('tests/f.rs'), True)
    case('what = a token plus a two-letter word is refused', one_decl('sections to'), True)
    # #5760: ONE word that holds a short chunk beside a good token refuses the item (the header's "a word with a chunk of
    # one or two characters ... refuses the whole item"); the same bump named by the good token alone is the control
    case('what = one word with a two-character chunk beside a token (ab-sections) is refused', one_decl('ab-sections'), True,
         ['sections.len()  18 -> 19'], ['IGNORED Count', '"ab-sections 18 -> 19" matches no change'])
    case('what = the same token without the short chunk (sections) is the green control', one_decl('sections'), False)
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

    # ---- #5577: any right-hand-side spelling is seen (typed, based, underscored, expression); undecidable never silent -------------
    def typed(old_rhs, new_rhs, decl=None, expr='sections.len()'):
        def f_(s, b):
            s.w('tests/typed.rs', 'fn t() { assert_eq!(%s, %s); }\n' % (expr, old_rhs)); t0 = s.commit('test: add typed fixture')
            s.w('tests/typed.rs', 'fn t() { assert_eq!(%s, %s); }\n' % (expr, new_rhs))
            s.commit(msg('test: bump', 'Count: %s (fixture)' % decl) if decl else 'test: bump without a declaration'); return t0 + '..HEAD'
        return f_
    for o_, n_ in [('18usize', '19usize'), ('1_8', '1_9'), ('0x12', '0x13'), ('0o22', '0o23'), ('0b10010', '0b10011'),
                   ('18_usize', '19_usize'), ('18u8', '19u8'), ('0x12_usize', '0x13_usize'), ('18i64', '19i64'), ('18_u32', '19_u32')]:
        case('undeclared %s -> %s is a move' % (o_, n_), typed(o_, n_), True, ['sections.len()  18 -> 19'])
        case('declared %s -> %s is accepted' % (o_, n_), typed(o_, n_, 'sections 18 -> 19'), False)
    case('a spelling change only (18 -> 18usize) is no count move', typed('18', '18usize'), False)
    case('a spelling change only (0x12 -> 18) is no count move', typed('0x12', '18'), False)
    case('an expression right-hand side that changes is a move, undecidable', typed('18 + 1', '18 + 2'), True, ['sections.len()  ?18+1 -> ?18+2'])
    case('an expression right-hand side declared with its spelling', typed('18 + 1', '18 + 2', 'sections ?18+1 -> ?18+2'), False)
    case('an expression right-hand side declared with decimal values does not match', typed('18 + 1', '18 + 2', 'sections 18 -> 19'), True)
    case('a literal replaced by an expression is a move', typed('18', 'N as usize'), True, ['sections.len()  18 -> ?Nasusize'])
    case('a parenthesised right-hand side is seen', typed('(18)', '(19)'), True, ['?(18) -> ?(19)'])
    case('a nested-call left side with a comma is seen', typed('18', '19', None, 'f(a, b).len()'), True, ['f(a,b).len()  18 -> 19'])
    case('a turbofish left side with a comma is seen', typed('18', '19', None, 'v.iter().collect::<HashMap<K, V>>().len()'), True)
    case('a trailing message argument does not hide the literal', typed('18', '19', None, 'sections.len()'), True)
    case('a call right-hand side with a comma is read whole', typed('max(18, 19)', 'max(18, 20)'), True, ['?max(18,19) -> ?max(18,20)'])
    case('a turbofish right-hand side with a comma is read whole', typed('size_of::<HashMap<K, V>>()', 'size_of::<HashMap<K, W>>()'), True, ['K,V', 'K,W'])
    def c_added_expr(s, b):
        s.w('tests/typed.rs', 'fn t() { assert_eq!(a.len(), 1); }\n'); t0 = s.commit('test: add')
        s.w('tests/typed.rs', 'fn t() { assert_eq!(a.len(), 1); assert_eq!(x.len(), y.len()); }\n'); s.commit('test: add a length comparison'); return t0 + '..HEAD'
    case('a newly added length comparison with no literal is no count move', c_added_expr, False)
    def c_removed_expr(s, b):
        s.w('tests/typed.rs', 'fn t() { assert_eq!(a.len(), 1); assert_eq!(x.len(), y.len()); }\n'); t0 = s.commit('test: add')
        s.w('tests/typed.rs', 'fn t() { assert_eq!(a.len(), 1); }\n'); s.commit('test: drop a length comparison'); return t0 + '..HEAD'
    case('a removed length comparison with no literal is no count move', c_removed_expr, False)
    def c_msgarg(s, b):
        s.w('tests/typed.rs', 'fn t() { assert_eq!(sections.len(), 18, "a, b"); }\n'); t0 = s.commit('test: add')
        s.w('tests/typed.rs', 'fn t() { assert_eq!(sections.len(), 19, "a, b"); }\n'); s.commit('test: bump'); return t0 + '..HEAD'
    case('a trailing message argument with a comma does not hide the literal', c_msgarg, True, ['sections.len()  18 -> 19'])

    # ---- #5578: a const defined in ANOTHER file is resolved over the whole tree; unresolvable is never 'unchanged' --------------
    SH = 'tests/shared_use.rs'
    def shared(use_rs, lib0, lib1, extra0=None, extra1=None, decl=None):
        def f_(s, b):
            s.w('src/lib.rs', lib0); s.w(SH, use_rs)
            for k, v in (extra0 or {}).items(): s.w(k, v)
            t0 = s.commit('test: add shared fixture')
            s.w('src/lib.rs', lib1)
            for k, v in (extra1 or {}).items(): s.w(k, v)
            s.commit(msg('test: bump', 'Count: %s (fixture)' % decl) if decl else 'test: bump without a declaration'); return t0 + '..HEAD'
        return f_
    A = lambda rhs: 'fn t() { assert_eq!(report.sections.len(), %s); }\n' % rhs
    L = lambda n: 'pub const EXPECTED_N: usize = %s;\n' % n
    case('shared const bumped in src/lib.rs, assertion in tests/ via crate::NAME', shared(A('crate::EXPECTED_N'), L(18), L(19)), True, ['sections.len() [EXPECTED_N]  18 -> 19'])
    case('the same, declared', shared(A('crate::EXPECTED_N'), L(18), L(19), decl='sections 18 -> 19'), False)
    case('the same through a bare imported name', shared('use ai_memory::EXPECTED_N;\n' + A('EXPECTED_N'), L(18), L(19)), True, ['18 -> 19'])
    case('the same through a deep path module::NAME', shared(A('ai_memory::cfg::EXPECTED_N'), L(18), L(19)), True, ['18 -> 19'])
    case('the same through a typed const value', shared(A('crate::EXPECTED_N'), L('18usize'), L('19usize')), True, ['18 -> 19'])
    case('the same through a hex const value', shared(A('crate::EXPECTED_N'), L('0x12'), L('0x13')), True, ['18 -> 19'])
    case('a second definition of the name makes it ambiguous (assertion unchanged)',
         shared(A('crate::EXPECTED_N'), L(18), L(18), None, {'src/other.rs': L(3)}), True, ['?EXPECTED_N#ambiguous'])
    case('a name defined nowhere, newly asserted, is flagged unresolved', shared('fn t() {}\n', L(18), L(18), None, {SH: A('ext::MISSING_N')}), True, ['?MISSING_N#unresolved'])
    case('a const whose value is an expression moves as an undecidable spelling',
         shared(A('crate::EXPECTED_N'), 'pub const EXPECTED_N: usize = 9 + 9;\n', 'pub const EXPECTED_N: usize = 9 + 10;\n'), True, ['?9+9 -> ?9+10'])
    case('a shared const bumped that no assertion uses is no move', shared('fn t() {}\n', L(18), L(19)), False)
    case('a QUALIFIED name is never the local const of the same spelling',
         shared('const EXPECTED_N: usize = 5;\n' + A('crate::EXPECTED_N'), L(18), L(19)), True, ['#ambiguous(18,5) -> ?EXPECTED_N#ambiguous(19,5)'])
    case('a shared const bumped while the asserting file is also edited is ONE move, declared once',
         shared(A('crate::EXPECTED_N') + '// a\n', L(18), L(19), None, {SH: A('crate::EXPECTED_N') + '// b\n'}, 'sections 18 -> 19'), False)
    case('a local const of the same name shadows the shared one',
         shared('const EXPECTED_N: usize = 5;\n' + A('EXPECTED_N'), L(18), L(19)), False)
    case('a shared const unchanged while its file changes is no move', shared(A('crate::EXPECTED_N'), L(18) + '// a\n', L(18) + '// b\n'), False)
    # ---- #5672: "an identical state on both sides is no move" for the unresolved and the ambiguous state ------------
    case('an unresolved name unchanged on both sides is no move',
         shared(A('ext::MISSING_N') + '// a\n', L(18), L(18), None, {SH: A('ext::MISSING_N') + '// b\n'}), False)
    case('an ambiguous name unchanged on both sides is no move',
         shared(A('crate::EXPECTED_N') + '// a\n', L(18), L(18), {'src/other.rs': L(3)}, {SH: A('crate::EXPECTED_N') + '// b\n'}), False)
    case('an ambiguous name newly asserted is a move',
         shared('fn t() {}\n', L(18), L(18), {'src/other.rs': L(3)}, {SH: A('crate::EXPECTED_N')}), True, ['?EXPECTED_N#ambiguous'])
    case('an unresolved name that becomes resolved is a move',
         shared(A('crate::MISSING_N'), L(18), L(18) + 'pub const MISSING_N: usize = 4;\n'), True, ['?MISSING_N#unresolved -> 4'])
    case('an ambiguous name that becomes resolved is a move',
         shared(A('crate::EXPECTED_N'), L(18), L(18), {'src/other.rs': L(3)}, {'src/other.rs': 'pub fn x() {}\n'}), True, ['?EXPECTED_N#ambiguous(18,3) -> 18'])
    # ---- #5673: the changelog scope clause: assert(_eq)!(<expr>.len()|.count(), <rhs>) in an eligible src/ or tests/ .rs file ----
    def scoped(path, body0, body1):
        def f_(s, b):
            s.w(path, body0); t0 = s.commit('test: add scope fixture'); s.w(path, body1)
            s.commit('test: bump scope fixture'); return t0 + '..HEAD'
        return f_
    E = lambda macro, meth, n: 'fn t() { %s!(items.%s(), %s); }\n' % (macro, meth, n)
    case('a .count() left side is seen', scoped('tests/scope.rs', E('assert_eq', 'count', 18), E('assert_eq', 'count', 19)), True, ['items.count()  18 -> 19'])
    # #5710: assert! is read only in its compiling count form assert!(<expr>.len()|.count() == <rhs>[, message])
    Q = lambda n, tail='': 'fn t() { assert!(items.len() == %s%s); }\n' % (n, tail)
    case('an assert!(<expr>.len() == <rhs>) is seen', scoped('tests/scope.rs', Q(18), Q(19)), True, ['items.len()  18 -> 19'])
    case('an assert!(<expr>.len() == <rhs>, message) is seen', scoped('tests/scope.rs', Q(18, ', "m {}", 1'), Q(19, ', "m {}", 1')), True, ['items.len()  18 -> 19'])
    case('an assert!(<expr>.count() == <rhs>) is seen', scoped('tests/scope.rs', E('assert', 'count', 18).replace('(), 18', '() == 18'), E('assert', 'count', 19).replace('(), 19', '() == 19')), True, ['items.count()  18 -> 19'])
    case('an assert!(<expr>.len() != <rhs>) is not a count assertion', scoped('tests/scope.rs', Q(18).replace('==', '!='), Q(19).replace('==', '!=')), False)
    case('the non-compiling comma form assert!(<expr>.len(), <rhs>) is not a count assertion', scoped('tests/scope.rs', E('assert', 'len', 18), E('assert', 'len', 19)), False)
    case('a non-count assert!(i < b.len(), message) whose message spelling changes is no move',
         scoped('tests/scope.rs', 'fn t() { assert!(i < b.len(), "m"); }\n', 'fn t() { assert!(i < b.len(), M); }\n'), False)
    case('assert_eq! and assert! with the same expression and value are one assertion (a rewrite is no move)',
         scoped('tests/scope.rs', E('assert_eq', 'len', 18), Q(18)), False)
    case('a prefixed macro name (debug_assert_eq!) is seen', scoped('tests/scope.rs', E('debug_assert_eq', 'len', 18), E('debug_assert_eq', 'len', 19)), True, ['items.len()  18 -> 19'])
    case('a prefixed macro name (debug_assert!) is seen', scoped('tests/scope.rs', Q(18).replace('assert!', 'debug_assert!'), Q(19).replace('assert!', 'debug_assert!')), True, ['items.len()  18 -> 19'])
    # ---- #5759: the WHOLE first argument decides which count an assertion binds to (WHAT IS READ in the header) ------------
    def scoped_m(path, body0, body1, m):
        def f_(s, b):
            s.w(path, body0); t0 = s.commit('test: add scope fixture'); s.w(path, body1)
            s.commit(m); return t0 + '..HEAD'
        return f_
    FK = 'v.iter().filter(|x|x.len()==2).count()'
    FA = lambda n, c='': c + 'fn u(v: &[&str]) { assert!(v.iter().filter(|x| x.len() == 2).count() == %s); }\n' % n
    FC = lambda n: FA('N', 'const N: usize = %s;\n' % n)
    case('assert! with an inner closure comparison binds to the outer count (const bump)', scoped('tests/scope.rs', FC(3), FC(4)), True, [FK + ' [N]  3 -> 4'])
    case('assert! with an inner closure comparison binds to the outer count (literal bump)', scoped('tests/scope.rs', FA(3), FA(4)), True, [FK + '  3 -> 4'])
    case('assert! with an inner closure comparison that appears is flagged', scoped('tests/scope.rs', 'fn t() {}\n', FA(3)), True, [FK + '  (none) -> 3'])
    case('assert! with an inner closure comparison that disappears is flagged', scoped('tests/scope.rs', FA(3), 'fn t() {}\n'), True, [FK + '  3 -> (none)'])
    case('assert! with an inner closure comparison, declared by a whole token (filter), is green',
         scoped_m('tests/scope.rs', FA(3), FA(4), msg('test: bump', 'Count: filter 3 -> 4 (fixture)')), False)
    case('the inner comparison is not a separate assertion: an unchanged outer count with a moved inner literal is a key change',
         scoped('tests/scope.rs', FA(3), FA(3).replace('== 2)', '== 5)')), True, [FK + '  3 -> (none)', 'v.iter().filter(|x|x.len()==5).count()  (none) -> 3'])
    FB = lambda n: 'fn u(v: &[&str]) {\n    assert!(\n        v.iter().filter(|x| { x.len() == 2 }).count() == %s,\n        "m {}",\n        1,\n    );\n}\n' % n
    case('a multi-line assert! with a block closure, a message and a trailing comma binds to the outer count',
         scoped('tests/scope.rs', FB(3), FB(4)), True, ['v.iter().filter(|x|{x.len()==2}).count()  3 -> 4'])
    case('a debug_assert! with an inner closure comparison binds to the outer count',
         scoped('tests/scope.rs', FA(3).replace('assert!', 'debug_assert!'), FA(4).replace('assert!', 'debug_assert!')), True, [FK + '  3 -> 4'])
    MK = 'v.iter().map(|x|max(x.len(),1)).count()'
    MA = lambda n: 'fn u(v: &[&str]) { assert_eq!(v.iter().map(|x| max(x.len(), 1)).count(), %s); }\n' % n
    case('assert_eq! whose count call holds an inner .len(), call binds to the outer count (appears)', scoped('tests/scope.rs', 'fn t() {}\n', MA(3)), True, [MK + '  (none) -> 3'])
    case('assert_eq! whose count call holds an inner .len(), call binds to the outer count (disappears)', scoped('tests/scope.rs', MA(3), 'fn t() {}\n'), True, [MK + '  3 -> (none)'])
    case('assert_eq! whose count call holds an inner .len(), call binds to the outer count (bump)', scoped('tests/scope.rs', MA(3), MA(4)), True, [MK + '  3 -> 4'])
    # an assert_eq! first argument whose last term is not the count call is not read (the stated limit)
    for a_ in ('(items.len(), 1)', 'items.len() + 1', 'items.len() as u32', '&v[..items.len()]', 'f(items.len())'):
        case('an assert_eq! first argument %s is not read' % a_,
             scoped('tests/scope.rs', 'fn t() { assert_eq!(%s, 18); }\n' % a_, 'fn t() { assert_eq!(%s, 19); }\n' % a_), False)
    # AMBIGUOUS assert! shapes: tracked by the whole spelling as ?count#ambiguous, never exempt, never guessed
    AA = 'fn u(v: &[&str]) { assert!(v.iter().any(|x| x.len() == 2)); }\n'
    AK = 'v.iter().any(|x|x.len()==2)'
    case('an ambiguous assert! (a count comparison inside a closure only) that appears is flagged', scoped('tests/scope.rs', 'fn t() {}\n', AA), True, [AK + '  (none) -> ?count#ambiguous'])
    case('an ambiguous assert! that disappears is flagged', scoped('tests/scope.rs', AA, 'fn t() {}\n'), True, [AK + '  ?count#ambiguous -> (none)'])
    case('an ambiguous assert! that appears, declared with the ?count#ambiguous value, is green',
         scoped_m('tests/scope.rs', 'fn t() {}\n', AA, msg('test: add', 'Count: any (none) -> ?count#ambiguous (fixture)')), False)
    case('an ambiguous assert! that is unchanged beside an unrelated edit is no move', scoped('tests/scope.rs', AA, AA + 'fn w() {}\n'), False)
    case('a reworded ambiguous assert! is flagged on both spellings', scoped('tests/scope.rs', AA, AA.replace('== 2', '== 3')), True,
         [AK + '  ?count#ambiguous -> (none)', 'v.iter().any(|x|x.len()==3)  (none) -> ?count#ambiguous'])
    NA = lambda n: 'const N: usize = %s;\nfn u(v: &[u8], k: usize) { assert!(k > 0 && v.len() == N); }\n' % n
    case('a const named in an ambiguous assert! (behind &&) that is bumped is flagged', scoped('tests/scope.rs', NA(3), NA(4)), True, ['k>0&&v.len()==N [N]  3 -> 4'])
    case('a const named through a path in an ambiguous assert! resolves over the tree',
         shared('fn u(v: &[u8], k: usize) { assert!(k > 0 && v.len() == crate::EXPECTED_N); }\n', L(18), L(19)), True, ['k>0&&v.len()==crate::EXPECTED_N [EXPECTED_N]  18 -> 19'])
    for a_, k_ in (('(items.len()) == %s', '(items.len())==%s'), ('items.len() as u32 == %s', 'items.len()asu32==%s'),
                   ('!(items.len() == %s)', '!(items.len()==%s)'), ('items.len() == %s || ok', 'items.len()==%s||ok'),
                   ('ok && items.len() == %s', 'ok&&items.len()==%s')):
        case('an assert!(%s) is ambiguous and its literal bump is flagged' % (a_ % 'N'),
             scoped('tests/scope.rs', 'fn t() { assert!(%s); }\n' % (a_ % 18), 'fn t() { assert!(%s); }\n' % (a_ % 19)), True,
             [(k_ % 18) + '  ?count#ambiguous -> (none)', (k_ % 19) + '  (none) -> ?count#ambiguous'])
    def amb_leg(label, a_):                               # assert!(a_ % 18) -> assert!(a_ % 19), undeclared: both spellings flagged
        k_ = re.sub(r'\s+', '', a_)
        case('%s: assert!(%s) is ambiguous and its literal bump is flagged' % (label, a_ % 'N'),
             scoped('tests/scope.rs', 'fn t() { assert!(%s); }\n' % (a_ % 18), 'fn t() { assert!(%s); }\n' % (a_ % 19)), True,
             [(k_ % 18) + '  ?count#ambiguous -> (none)', (k_ % 19) + '  (none) -> ?count#ambiguous'])
    # #5797 (round-6 F1): a cast to ANY type between the count call and == leaves the call in the left operand
    for l_, a_ in (('M1 path cast behind &&', 'ok && v.len() as core::primitive::usize == %s'),
                   ('M7 generic cast behind &&', 'ok && v.len() as Wrapping<usize> == %s'),
                   ('path cast', 'v.len() as core::primitive::usize == %s'), ('reference cast', 'v.len() as &usize == %s'),
                   ('pointer cast', 'v.len() as *const usize == %s'), ('nested generic cast', 'v.len() as Option<Vec<usize>> == %s'),
                   ('double cast', 'v.len() as usize as u64 == %s'), ('negated path cast', '!(v.len() as core::primitive::usize == %s)'),
                   ('closure-only path cast', 'v.iter().any(|x| x.len() as core::primitive::usize == %s)'),
                   ('closure without parameters, path cast', '(|| v.len() as a::T == %s)()'),
                   ('a second count behind &&, path cast', 'v.len() > 0 && v.len() as a::T == %s')):
        amb_leg(l_, a_)
    # #5798 (round-6 F2): braces, a block comment, a method chain or anything else between the count call and ==
    for l_, a_ in (('M2 braces behind &&', 'ok && { v.len() } == %s'), ('M4 block comment behind &&', 'ok && v.len() /* n */ == %s'),
                   ('M8 .into() behind &&', 'ok && v.len().into() == %s'), ('braces', '{ v.len() } == %s'),
                   ('block comment', 'v.len() /* n */ == %s'), ('line break behind &&', 'ok && v.len()\n        == %s'),
                   ('.into()', 'v.len().into() == %s'), ('.try_into().unwrap()', 'v.len().try_into().unwrap() == %s'),
                   ('space inside the call', 'v.len () == %s'), ('.count() with spaces inside the call', 'v.iter().count( ) == %s && ok'),
                   ('count call as a call argument', 'f(v.len(), 2) == %s'), ('if-expression operand', 'if ok { v.len() } else { 0 } == %s'),
                   ('arithmetic after a cast', 'ok && v.len() as u64 + 0 == %s'), ('closure-only braces', 'v.iter().any(|x| { x.len() } == %s)'),
                   ('match arm after =>', 'match k { _ => v.len() as a::T == %s }'), ('tuple operand', '(v.len(), 2) == (%s, 2)'),
                   ('a block with a statement', '{ let n = v.len(); n } == %s'),
                   ('an array operand', '[v.len(), 0][0] == %s'), ('space after the dot', 'v. len() == %s')):
        amb_leg(l_, a_)
    # stated limits, pinned with today's reading (a move here is NOT flagged): #5799 #5800 #5801 #5714
    for l_, a0_ in (('M3 an assert_eq! tuple first argument (#5799)', 'assert_eq!((v.len(), v.len()), (2, %s))'),
                    ('an assert_eq! first argument cast to a path type (#5799)', 'assert_eq!(v.len() as core::primitive::usize, %s)'),
                    ('an assert! comparing the count with .eq() (#5800)', 'assert!(v.len().eq(&%s))'),
                    ('an assert! comparing the count with matches! (#5800)', 'assert!(matches!(v.len(), %s))'),
                    ('an assert! with a path-call count (#5801)', 'assert!(<[u8]>::len(v) == %s)'),
                    ('an assert_eq! with a path-call count (#5801)', 'assert_eq!(<[u8]>::len(v), %s)'),
                    ('an assert_eq! with a space inside the count call (#5801)', 'assert_eq!(v.len (), %s)'),
                    ('a reversed operand behind && (#5714)', 'assert!(ok && %s == v.len())'),
                    ('a free-function count such as row_count() (#5801)', 'assert!(row_count() == %s)'),
                    ('a .count(..) call with an argument (#5801)', 'assert!(m.count(k) == %s)')):
        case('stays unread: %s' % l_, scoped('tests/scope.rs', 'fn t() { %s; }\n' % (a0_ % 18), 'fn t() { %s; }\n' % (a0_ % 19)), False)
    case('a count call behind && in a closure, with == on another operand, is not read',
         scoped('tests/scope.rs', 'fn t() { assert!(v.iter().all(|x| x.len() > 0 && x[0] == 18)); }\n',
                'fn t() { assert!(v.iter().all(|x| x.len() > 0 && x[0] == 19)); }\n'), False)
    case('a count call compared with >, with == on another operand behind &&, is not read',
         scoped('tests/scope.rs', 'fn t() { assert!(v.len() > 0 && n == 18); }\n', 'fn t() { assert!(v.len() > 0 && n == 19); }\n'), False)
    # every operand stop is pinned: a count call before the stop, with == after it on another operand, is not read
    for l_, a0_ in (('a comma', 'assert!(f(v.len(), n == %s))'), ('a semicolon', 'assert!({ let k = v.len(); n == %s })'),
                    ('||', 'assert!(v.len() > 0 || n == %s)'), ('a match arm =>', 'assert!(match k { _ if v.len() > 0 => n == %s, _ => true })')):
        case('operand stop %s: a count call before it, with == after it, is not read' % l_,
             scoped('tests/scope.rs', 'fn t() { %s; }\n' % (a0_ % 18), 'fn t() { %s; }\n' % (a0_ % 19)), False)
    case('an assert! comparing the count with <= is not read',
         scoped('tests/scope.rs', 'fn t() { assert!(v.len() <= 18); }\n', 'fn t() { assert!(v.len() <= 19); }\n'), False)
    case('an assert! with a closure count comparison that is not == is not read',
         scoped('tests/scope.rs', 'fn t() { assert!(v.iter().all(|x| x.len() > 2)); }\n', 'fn t() { assert!(v.iter().all(|x| x.len() > 3)); }\n'), False)
    # #5761 (S2): which comparison an assert! binds to is pinned: only ONE == outside every bracket ((), [] and {}) binds
    case('an inner comparison in the RIGHT operand does not bind: the left count is the assertion',
         scoped('tests/scope.rs', 'fn t() { assert!(items.len() == v.iter().filter(|x| x.len() == 2).count()); }\n',
                'fn t() { assert!(items.len() == v.iter().filter(|x| x.len() == 3).count()); }\n'), True,
         ['items.len()  ?v.iter().filter(|x|x.len()==2).count() -> ?v.iter().filter(|x|x.len()==3).count()'])
    case('two == outside every bracket are ambiguous (not bound to the first)',
         scoped('tests/scope.rs', 'fn t() { assert!(items.len() == 18 == ok); }\n', 'fn t() { assert!(items.len() == 19 == ok); }\n'), True,
         ['items.len()==18==ok  ?count#ambiguous -> (none)', 'items.len()==19==ok  (none) -> ?count#ambiguous'])
    case('two == outside every bracket are ambiguous (not bound to the last)',
         scoped('tests/scope.rs', 'fn t() { assert!(ok == items.len() == 18); }\n', 'fn t() { assert!(ok == items.len() == 19); }\n'), True,
         ['ok==items.len()==18  ?count#ambiguous -> (none)', 'ok==items.len()==19  (none) -> ?count#ambiguous'])
    case('a == inside braces (a struct literal) is inside a bracket and does not bind',
         scoped('tests/scope.rs', 'fn t() { assert!(S { a: k == 1 }.n.len() == 3); }\n', 'fn t() { assert!(S { a: k == 1 }.n.len() == 4); }\n'), True,
         ['S{a:k==1}.n.len()  3 -> 4'])
    case('a closure outside every bracket makes the assert! ambiguous',
         scoped('tests/scope.rs', 'fn t() { assert!(|x: &[u8]| x.len() == 18); }\n', 'fn t() { assert!(|x: &[u8]| x.len() == 19); }\n'), True,
         ['|x:&[u8]|x.len()==18  ?count#ambiguous -> (none)'])
    case('assert_eq! with two inner .len() calls binds to the outer count',
         scoped('tests/scope.rs', 'fn t() { assert_eq!(v.iter().filter(|x| x.len() == w.len()).count(), 3); }\n',
                'fn t() { assert_eq!(v.iter().filter(|x| x.len() == w.len()).count(), 4); }\n'), True, ['v.iter().filter(|x|x.len()==w.len()).count()  3 -> 4'])
    case('assert_eq! with a parenthesised receiver is read', scoped('tests/scope.rs', 'fn t() { assert_eq!((items).len(), 18); }\n', 'fn t() { assert_eq!((items).len(), 19); }\n'), True, ['(items).len()  18 -> 19'])
    case('an ambiguous assert! whose closure compares a .count() is flagged when it appears',
         scoped('tests/scope.rs', 'fn t() {}\n', 'fn t() { assert!(v.iter().any(|x| x.chars().count() == 2)); }\n'), True, ['v.iter().any(|x|x.chars().count()==2)  (none) -> ?count#ambiguous'])
    case('a path-qualified const in an ambiguous assert! is resolved over the tree, not to a same-named local const',
         shared('const EXPECTED_N: usize = 5;\nfn u(v: &[u8], k: usize) { assert!(k > 0 && v.len() == crate::EXPECTED_N); }\n', L(18), L(19)), True,
         ['k>0&&v.len()==crate::EXPECTED_N [EXPECTED_N]  ?EXPECTED_N#ambiguous(18,5) -> ?EXPECTED_N#ambiguous(19,5)'])
    case('a const named through <T as Tr>:: in an ambiguous assert! is tracked and resolved over the tree',
         shared('const EXPECTED_N: usize = 5;\nfn u(v: &[u8], k: usize) { assert!(k > 0 && v.len() == <S as Tr>::EXPECTED_N); }\n', L(18), L(19)), True,
         ['k>0&&v.len()==<SasTr>::EXPECTED_N [EXPECTED_N]  ?EXPECTED_N#ambiguous(18,5) -> ?EXPECTED_N#ambiguous(19,5)'])
    # ---- end #5759 ----
    case('a .rs file under benches/ is not checked', scoped('benches/scope.rs', E('assert_eq', 'len', 18), E('assert_eq', 'len', 19)), False)
    case('a non-.rs file under tests/ is not checked', scoped('tests/scope.txt', E('assert_eq', 'len', 18), E('assert_eq', 'len', 19)), False)
    case('a .rs file under src/ is checked', scoped('src/scope.rs', E('assert_eq', 'len', 18), E('assert_eq', 'len', 19)), True, ['items.len()  18 -> 19'])
    # #5711: eligibility is anchored at the REPOSITORY ROOT: src/ and tests/ at any depth below it, nothing nested elsewhere
    case('a .rs file in a subdirectory of tests/ is checked', scoped('tests/sub/scope.rs', E('assert_eq', 'len', 18), E('assert_eq', 'len', 19)), True, ['items.len()  18 -> 19'])
    for p_ in ('tools/x/src/scope.rs', 'tools/x/tests/scope.rs', 'examples/scope.rs', 'fuzz/fuzz_targets/scope.rs'):
        case('a .rs file under %s is not checked (not the repository-root src/ or tests/)' % p_.rsplit('/', 1)[0],
             scoped(p_, E('assert_eq', 'len', 18), E('assert_eq', 'len', 19)), False)
    # ---- #5712: clause pins from the sentence sweep of the changelog and this header (#5714 #5715 #5716 pin the limits) ----
    case('a reversed operand order assert_eq!(<rhs>, <expr>.len()) is not read',
         scoped('tests/scope.rs', 'fn t() { assert_eq!(18, items.len()); }\n', 'fn t() { assert_eq!(19, items.len()); }\n'), False)
    case('a reversed operand order assert!(<rhs> == <expr>.len()) is not read', scoped('tests/scope.rs', 'fn t() { assert!(18 == items.len()); }\n', 'fn t() { assert!(19 == items.len()); }\n'), False)
    case('assert_ne! is not read', scoped('tests/scope.rs', E('assert_ne', 'len', 18), E('assert_ne', 'len', 19)), False)
    case('an assertion inside a block comment is read as code', scoped('tests/scope.rs', '/* ' + E('assert_eq', 'len', 18) + ' */\n', '/* ' + E('assert_eq', 'len', 19) + ' */\n'), True, ['items.len()  18 -> 19'])
    case('an assertion after a line comment marker is not read', scoped('tests/scope.rs', '// ' + E('assert_eq', 'len', 18), '// ' + E('assert_eq', 'len', 19)), False)
    case('an assertion inside a double-quoted string literal is not read', scoped('tests/scope.rs', 'const S: &str = "%s";\n' % E('assert_eq', 'len', 18).strip(), 'const S: &str = "%s";\n' % E('assert_eq', 'len', 19).strip()), False)
    case('a raw string is blanked only up to its first inner quote', scoped('tests/scope.rs', 'const S: &str = r#"q " %s "#;\n' % E('assert_eq', 'len', 18).strip(), 'const S: &str = r#"q " %s "#;\n' % E('assert_eq', 'len', 19).strip()), True, ['items.len()  18 -> 19'])
    def c_parent_tools(s, b):                              # the parent holds the expression only in a file that is not checked
        s.w('tools/x/src/old.rs', 'fn t() { assert_eq!(builds.len(), 1); }\n'); t0 = s.commit('test: tools file')
        s.w('tests/n1.rs', 'fn t() { assert_eq!(builds.len(), 2); }\n'); s.commit('test: new file'); return t0 + '..HEAD'
    case('a new file whose expression exists in the parent only in an unchecked file is skipped as new', c_parent_tools, False)
    case('a const of the same name in an unchecked file is not a second definition',
         shared(A('crate::EXPECTED_N'), L(18), L(19), {'tools/x/src/lib.rs': L(3)}), True, ['sections.len() [EXPECTED_N]  18 -> 19'])
    case('a const defined only in an unchecked file stays unresolved, so its bump there moves nothing',
         shared(A('crate::OTHER_N') + '// a\n', L(18), L(18), {'tools/x/src/lib.rs': 'pub const OTHER_N: usize = 1;\n'},
                {'tools/x/src/lib.rs': 'pub const OTHER_N: usize = 2;\n', SH: A('crate::OTHER_N') + '// b\n'}), False)
    def c_ren(s, b):                                       # the defining file is renamed with the bump
        s.w('src/lib.rs', L(18) + PAD); s.w(SH, A('crate::EXPECTED_N')); t0 = s.commit('test: add')
        s.g('mv', 'src/lib.rs', 'src/consts.rs'); s.w('src/consts.rs', L(19) + PAD); s.commit('test: move and bump'); return t0 + '..HEAD'
    case('the defining file renamed with the bump is a move', c_ren, True, ['18 -> 19'])
    def c_del(s, b):                                       # the defining file is deleted: the assertion no longer resolves
        s.w('src/lib.rs', L(18)); s.w(SH, A('crate::EXPECTED_N')); t0 = s.commit('test: add')
        s.g('rm', '-q', 'src/lib.rs'); s.commit('test: drop the const'); return t0 + '..HEAD'
    case('the defining file deleted leaves the assertion unresolved', c_del, True, ['?EXPECTED_N#unresolved'])

    # ---- #5580: the changelog sentence "the same expression added in two new files of one commit is skipped in both" ----
    def c_two_new(s, b):
        s.w('tests/n1.rs', 'fn t() { assert_eq!(builds.len(), 1); }\n'); s.w('tests/n2.rs', 'fn t() { assert_eq!(builds.len(), 1); }\n')
        s.commit('test: two new files, same expression'); return b + '..HEAD'
    case('the same expression added in two NEW files of one commit is skipped in both (changelog pin)', c_two_new, False)
    def c_two_new_then(s, b):
        s.w('tests/n1.rs', 'fn t() { assert_eq!(builds.len(), 1); }\n'); s.commit('test: add'); t0 = s.g('rev-parse', 'HEAD')
        s.w('tests/n2.rs', 'fn t() { assert_eq!(builds.len(), 2); }\n'); s.commit('test: new file, same expression, other value'); return t0 + '..HEAD'
    case('a new file repeating an expression of the parent tree is NOT skipped', c_two_new_then, True, ['builds.len()  (none) -> 2'])

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
    def c_late_upper(s, b):
        o = offender(s, b); s.touch(msg('docs: declare', late(o, S_FF, sha=o.upper()))); return b + '..HEAD'
    case('late declaration with an upper-case sha', c_late_upper, True, ['18 -> 19'], ['40-character'])
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
