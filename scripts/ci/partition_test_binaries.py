#!/usr/bin/env python3
"""Partition the compiled test executables into one serial and two parallel shards (#6344).

Input is the stdout of ``cargo test --no-run --message-format=json`` (or
``json-render-diagnostics``), read from ``--build-json`` or stdin, plus the
repository sources. Output is written to ``--out-dir``:

* ``serial.txt``      class (a): Postgres / ``#[serial]`` / ``federat`` in the name /
                      unknown source. Run at ``--test-threads=1`` in ONE process.
                      Also carries ``--lib`` (the lib unittests filtered to the
                      Postgres test-name prefixes).
* ``parallel_1.txt``  class (b), first half, carries ``--lib`` (the lib unittests
  ``parallel_2.txt``  with ``--skip`` of the same prefixes) in half 1 only.
                      Run at ``--test-threads=3`` each, as two concurrent processes.
* ``lib_pg_filters.txt``  the lib Postgres test-name prefixes (one per line).
* ``manifest.json``   per-executable class, reason and weight; set sizes; estimates.

Classification reads the union of every source file a target compiles: the
crate root, every ``mod name;`` (``name.rs`` / ``name/mod.rs``), every
``#[path = "..."] mod name;`` and every ``include!("...")``, recursively. A file
that two or more targets compile (``tests/common/``) is a shared helper: its
Postgres / ``#[serial]`` / fixed-port evidence counts only for the targets that
reference the helper item carrying it, unless the file itself declares tests,
in which case it is unioned like any other. A ``mod`` that resolves to no file
is class (a) (fail closed).

Every list line is one cargo target selector: ``--lib``, ``--bin NAME``,
``--test NAME`` or ``--example NAME``.

Fail closed (exit 2, ``::error::`` on stderr) when:

* the three sets are not disjoint, or their union is not every executable
  (re-read from the files that were written, so a writer bug is caught too);
* the build output has no test executable at all;
* the lib is present but ``lib_pg_prefixes.txt`` is empty or a lib code site
  names ``AI_MEMORY_TEST_POSTGRES_URL`` (directly, in a string, or through a
  const/static whose value holds it) at a test path no prefix occurs in (a new
  lib Postgres test would otherwise run in a parallel shard against the shared
  database);
* a target name contains a character outside ``[A-Za-z0-9_.-]`` (the shell
  consumer word-splits the lines).

Python 3.9+, standard library only.
"""
import argparse
import bisect
import json
import os
import re
import sys
from pathlib import Path

# Class (a) evidence. Scout report CI-SHARD-SCOUT-2026-10-09, plus the shared
# lane-database helpers under tests/common that only Postgres cells use.
PG_RE = re.compile(
    r'AI_MEMORY_TEST_POSTGRES_URL|postgres_url\(|postgres_env|PostgresEnv|PgPool'
    r'|sqlx::|PostgresStore|pg_test_client|feature\s*=\s*"sal-postgres"|postgres://'
    r'|pg_barrier|lane_db|pg_sources|pg_blocking_pids'
)
SERIAL_RE = re.compile(r'serial_test|#\[serial')
FEDERAT_RE = re.compile(r'federat', re.IGNORECASE)
# Class (b) binaries carrying these run in the SAME half so two of them never
# run in different processes at once.
PORT_RE = re.compile(r'(?:127\.0\.0\.1|localhost|0\.0\.0\.0):(?!0\b)\d{2,5}\b')
SHARED_PATH_RE = re.compile(r'"/(?:tmp|var/tmp|dev/shm)/')
ENV_RE = re.compile(r'env::set_var|env::remove_var|set_current_dir')
SAFE_NAME_RE = re.compile(r'^[A-Za-z0-9_.-]+$')

KIND_FLAG = {'test': '--test', 'bin': '--bin', 'example': '--example', 'bench': '--bench'}
LIB_KINDS = {'lib', 'rlib', 'cdylib', 'staticlib', 'dylib', 'proc-macro'}


class PartitionError(Exception):
    """A fail-closed condition; main() prints it as ::error:: and exits 2."""


class Exe:
    """One compiled test executable."""

    def __init__(self, kind, name, src_path, executable):
        self.kind = kind
        self.name = name
        self.src_path = src_path
        self.executable = executable
        self.cls = None
        self.reasons = []
        self.shared = []
        self.test_count = None  # test fns in the sources it compiles; None = unknown

    @property
    def key(self):
        return '%s:%s' % (self.kind, self.name)

    @property
    def selector(self):
        return '--lib' if self.kind == 'lib' else '%s %s' % (KIND_FLAG[self.kind], self.name)


def parse_build_json(lines):
    """Return the unique test executables from cargo's JSON message stream."""
    exes = {}
    for raw in lines:
        raw = raw.strip()
        if not raw.startswith('{'):
            continue
        try:
            msg = json.loads(raw)
        except ValueError:
            continue
        if msg.get('reason') != 'compiler-artifact':
            continue
        executable = msg.get('executable')
        profile = msg.get('profile') or {}
        if not executable or not profile.get('test'):
            continue
        target = msg.get('target') or {}
        kinds = target.get('kind') or []
        if any(k in LIB_KINDS for k in kinds):
            kind = 'lib'
        else:
            kind = next((k for k in kinds if k in KIND_FLAG), None)
        if kind is None:
            raise PartitionError('unrecognised test target kind %r for %s' % (kinds, executable))
        name = target.get('name')
        if not name or not SAFE_NAME_RE.match(name):
            raise PartitionError('unsafe test target name %r' % (name,))
        exes[executable] = Exe(kind, name, target.get('src_path') or '', executable)
    ordered = sorted(exes.values(), key=lambda e: (e.kind, e.name))
    keys = [e.key for e in ordered]
    if len(keys) != len(set(keys)):
        raise PartitionError('two executables share a kind:name key (ambiguous selector)')
    if not ordered:
        raise PartitionError('the build output lists no test executable')
    return ordered


# ---------------------------------------------------------------------------
# Rust source graph (#6344 review r1 B1/B2). A small lexer and module walker:
# enough of the Rust module rules to follow `mod name;`, `#[path = "..."] mod
# name;` and `include!("...")` from a crate root, and to tell, for any byte
# offset, which inline `mod` blocks and which `fn` enclose it. It never needs
# to be a parser: every ambiguity resolves towards "more evidence".
# ---------------------------------------------------------------------------
IDENT_CH = re.compile(r'[A-Za-z0-9_]')
MOD_DECL_RE = re.compile(r'\bmod\s+(r#)?([A-Za-z_][A-Za-z0-9_]*)\s*([;{])')
FN_RE = re.compile(r'\bfn\s+(r#)?([A-Za-z_][A-Za-z0-9_]*)')
INCLUDE_RE = re.compile(r'\binclude!\s*\(\s*"')
PATH_ATTR_RE = re.compile(r'#\s*\[\s*path\s*=\s*"')
# A test-fn attribute: #[test], #[tokio::test(..)], #[sqlx::test], #[rstest], #[test_case(..)],
# #[test_log::test]. Not #[cfg(test)] / #[cfg_attr(test, ..)]: those mark helpers (r2 F3).
TEST_ATTR_RE = re.compile(r'#\s*\[\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*(?:test|rstest|test_case)\b')
ITEM_RE = re.compile(
    r'\b(?:(fn|struct|enum|union|trait|type|const|static|mod)\s+(?:mut\s+)?(?:r#)?([A-Za-z_][A-Za-z0-9_]*)'
    r'|(macro_rules!)\s*([A-Za-z_][A-Za-z0-9_]*)|(impl)\b)')
FN_BEFORE_RE = re.compile(r'\bfn\s+$')  # the name is being defined here, not called
SHARD_THREADS = 3  # --test-threads of each parallel shard
PG_TOKEN = 'AI_MEMORY_TEST_POSTGRES_URL'
PG_TOKEN_RE = re.compile(r'\bAI_MEMORY_TEST_POSTGRES_URL\b')
PG_CONST_RE = re.compile(
    r'\b(?:const|static)\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:[^=;]*=\s*"[^"]*AI_MEMORY_TEST_POSTGRES_URL')
RUST_KEYWORDS = frozenset(
    'as async await break const continue crate dyn else enum extern false fn for if impl in let loop match mod '
    'move mut pub ref return self Self static struct super trait true type union unsafe use where while'.split())


def mask(src):
    """Return (code, shape): two views of ``src`` with the same length.

    ``code`` blanks comments and keeps literals; ``shape`` also blanks the
    contents of string and char literals (so braces and keywords inside them
    are not structure). Newlines are kept in both, so offsets line up.
    """
    n = len(src)
    code, shape = list(src), list(src)

    def blank(view, a, b):
        for k in range(a, b):
            if view[k] != '\n':
                view[k] = ' '

    i = 0
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ''
        if c == '/' and nxt == '/':
            j = src.find('\n', i)
            j = n if j < 0 else j
            blank(code, i, j)
            blank(shape, i, j)
            i = j
            continue
        if c == '/' and nxt == '*':
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith('/*', j):
                    depth, j = depth + 1, j + 2
                elif src.startswith('*/', j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(code, i, j)
            blank(shape, i, j)
            i = j
            continue
        prev_ident = i > 0 and IDENT_CH.match(src[i - 1])
        if c in 'rb' and not prev_ident:
            j = i + 1 if c == 'r' else (i + 2 if nxt == 'r' else -1)
            if j > 0:
                k = j
                while k < n and src[k] == '#':
                    k += 1
                if k < n and src[k] == '"':
                    close = '"' + '#' * (k - j)
                    end = src.find(close, k + 1)
                    end = n if end < 0 else end + len(close)
                    blank(shape, k + 1, max(k + 1, end - len(close)))
                    i = end
                    continue
        if c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == '\\' else 1
            blank(shape, i + 1, min(j, n))
            i = j + 1
            continue
        if c == "'":
            if nxt == '\\':
                j = src.find("'", i + 2)
                j = n if j < 0 else j
                if src[i + 2:i + 3] == "'":
                    j = src.find("'", i + 3)
                    j = n if j < 0 else j
                blank(shape, i + 1, j)
                i = j + 1
                continue
            if i + 2 < n and src[i + 2] == "'":
                blank(shape, i + 1, i + 2)
                i += 3
                continue
        i += 1
    return ''.join(code), ''.join(shape)


class RustFile:
    """One source file: both views plus brace structure, computed once."""

    def __init__(self, path, text):
        self.path = path
        self.text = text
        self.code, self.shape = mask(text)
        openers = {}
        for m in MOD_DECL_RE.finditer(self.shape):
            if m.group(3) == '{':
                openers[m.end() - 1] = ('mod', m.group(2), False)
        for m in FN_RE.finditer(self.shape):
            j = m.end()
            while j < len(self.shape) and self.shape[j] not in '{;':
                j += 1
            if j < len(self.shape) and self.shape[j] == '{':
                lead = self.shape[self._item_start(m.start()):m.start()]
                openers[j] = ('fn', m.group(2), bool(TEST_ATTR_RE.search(lead)))
        self.braces = [(m.start(), m.group(0)) for m in re.finditer(r'[{}]', self.shape)]
        self.openers = openers

    def _item_start(self, pos):
        """Offset just after the previous `;`, `{` or `}` (start of this item's attributes)."""
        k = max(self.shape.rfind(ch, 0, pos) for ch in ';{}')
        return k + 1

    def contexts(self, positions):
        """For each offset, the stack of enclosing ('mod'|'fn'|'blk', name, is_test)."""
        order = sorted(range(len(positions)), key=lambda x: positions[x])
        out = [None] * len(positions)
        stack, bi = [], 0
        for idx in order:
            pos = positions[idx]
            while bi < len(self.braces) and self.braces[bi][0] < pos:
                at, ch = self.braces[bi]
                if ch == '{':
                    stack.append(self.openers.get(at, ('blk', '', False)))
                elif stack:
                    stack.pop()
                bi += 1
            out[idx] = list(stack)
        return out

    def literal_at(self, quote_pos):
        """The string literal whose opening quote is at quote_pos (from the code view)."""
        end = self.code.find('"', quote_pos + 1)
        return self.code[quote_pos + 1:end] if end > 0 else None

    def preceding_path_attr(self, pos):
        lead_start = self._item_start(pos)
        m = None
        for m in PATH_ATTR_RE.finditer(self.shape, lead_start, pos):
            pass
        return self.literal_at(m.end() - 1) if m else None


def _read(path, cache):
    key = str(path)
    if key not in cache:
        try:
            cache[key] = RustFile(path, Path(path).read_text(errors='replace'))
        except OSError:
            cache[key] = None
    return cache[key]


def walk_crate(root, root_mod='', root_like=True, cache=None):
    """Follow the module tree from ``root``.

    Returns (units, unresolved): units is a list of (RustFile, module_path)
    for every reachable file (each once); unresolved lists `mod` declarations
    whose file does not exist (a cfg'd-out module, or a missing file).
    """
    cache = {} if cache is None else cache
    units, unresolved, seen = [], [], set()
    root = Path(os.path.normpath(str(root)))
    child_dir = root.parent if root_like or root.name == 'mod.rs' else root.with_suffix('')
    todo = [(root, root_mod, child_dir, root.parent)]
    while todo:
        path, modp, cdir, pdir = todo.pop()
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        rf = _read(path, cache)
        if rf is None:
            unresolved.append(key)
            continue
        units.append((rf, modp))
        decls = [m for m in MOD_DECL_RE.finditer(rf.shape) if m.group(3) == ';']
        incs = list(INCLUDE_RE.finditer(rf.shape))
        ctxs = rf.contexts([m.start() for m in decls] + [m.start() for m in incs])
        for m, ctx in zip(decls + incs, ctxs):
            inline = [s[1] for s in ctx if s[0] == 'mod']
            if any(s[0] != 'mod' for s in ctx):
                continue  # a `mod x;` inside a fn body is not a file module
            base_dir = cdir.joinpath(*inline) if inline else cdir
            sub = '::'.join(p for p in [modp] + inline if p)
            if m.re is INCLUDE_RE:
                lit = rf.literal_at(m.end() - 1)
                if lit:
                    target = Path(os.path.normpath(str(path.parent / lit)))
                    todo.append((target, sub, base_dir, base_dir if inline else pdir))
                continue
            name = m.group(2)
            child_mod = '::'.join(p for p in [sub, name] if p)
            lit = rf.preceding_path_attr(m.start())
            if lit is not None:
                target = Path(os.path.normpath(str((base_dir if inline else pdir) / lit)))
                todo.append((target, child_mod, target.parent, target.parent))
                continue
            flat, nested = base_dir / (name + '.rs'), base_dir / name / 'mod.rs'
            if flat.is_file():
                todo.append((flat, child_mod, base_dir / name, base_dir))
            elif nested.is_file():
                todo.append((nested, child_mod, nested.parent, nested.parent))
            else:
                unresolved.append('%s (mod %s)' % (key, name))
    return units, unresolved


def top_level_items(rf):
    """(name, start, end) of items whose enclosing stack holds only `mod` blocks.

    An `impl ... Type {` block is reported under the last identifier before its
    brace (the implemented type), so evidence inside methods attaches to Type.
    """
    found = []
    ms = list(ITEM_RE.finditer(rf.shape))
    ctxs = rf.contexts([m.start() for m in ms])
    for m, ctx in zip(ms, ctxs):
        if any(s[0] != 'mod' for s in ctx):
            continue
        kind = m.group(1) or m.group(3) or m.group(5)
        if kind == 'mod':
            continue
        j = m.end()
        while j < len(rf.shape) and rf.shape[j] not in '{;':
            j += 1
        if kind == 'impl':
            head = rf.shape[m.end():j]
            prev = None
            while prev != head:
                prev, head = head, re.sub(r'<[^<>{]*>', ' ', head)
            idents = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', re.split(r'\bwhere\b', head)[0])
            idents = [x for x in idents if x not in RUST_KEYWORDS]
            if not idents:
                continue
            name = idents[-1]
        else:
            name = m.group(2) or m.group(4)
        if name in RUST_KEYWORDS:
            continue
        end = j + 1
        if j < len(rf.shape) and rf.shape[j] == '{':
            depth = 0
            for at, ch in rf.braces[bisect.bisect_left(rf.braces, (j, '')):]:
                depth += 1 if ch == '{' else -1
                if depth == 0:
                    end = at + 1
                    break
            else:
                end = len(rf.shape)
        found.append((name, m.start(), end))
    return found


EVIDENCE = (('pg', PG_RE), ('serial', SERIAL_RE), ('port', PORT_RE), ('shared-path', SHARED_PATH_RE))
# A test declared in a SHARED file runs in every binary that compiles the file,
# so it would move every one of them into the serial shard. It counts only when
# its CODE uses Postgres: a Postgres type, module or helper call in the shape
# view (comments and string contents blanked), or a direct env read of the test
# URL, in the test fn or in any helper it calls (transitively). Naming Postgres
# in a string (a ``postgres://`` URL fixture, an error message quoting
# ``AI_MEMORY_TEST_POSTGRES_URL``) is not use: the URL-predicate unit tests in
# tests/common/{postgres_env,lane_db}.rs are pure and stay with their binaries.
PG_CODE_RE = re.compile(
    r'postgres_url\(|postgres_env|PostgresEnv|PgPool|sqlx::|PostgresStore|pg_test_client'
    r'|pg_barrier|lane_db|pg_sources|pg_blocking_pids'
)
PG_ENV_READ_RE = re.compile(r'\bvar(?:_os)?\s*\(\s*"AI_MEMORY_TEST_POSTGRES_URL"')


def full_evidence(rf, a, b):
    """Every marker on the raw slice (comments and strings included): fail closed."""
    return {t for t, rx in EVIDENCE if rx.search(rf.text, a, b)}


def code_evidence(rf, a, b, pg_consts=None):
    """Markers that show the slice's code does it (see PG_CODE_RE)."""
    tags = set()
    if PG_CODE_RE.search(rf.shape, a, b) or PG_ENV_READ_RE.search(rf.code, a, b):
        tags.add('pg')
    elif pg_consts is not None and pg_consts.search(rf.shape, a, b):
        tags.add('pg')
    if SERIAL_RE.search(rf.shape, a, b):
        tags.add('serial')
    return tags


class SourceIndex:
    """Cross-target view of the test sources (#6344 r1 B1).

    A file reached by exactly one target is part of that binary. A file reached
    by two or more targets (``tests/common/*``) is a shared helper: its evidence
    attaches to its top-level item names (fn, struct, impl'd type, const,
    macro), transitively, and a binary inherits the evidence of every such name
    its own sources reference. A test fn declared in a shared file runs in
    every binary that compiles the file, so each of them also inherits that
    test's ``code_evidence``, including that of every helper it calls.
    """

    def __init__(self, exes):
        self.cache = {}
        self.walks = {}
        reach = {}
        for e in exes:
            units, unresolved = self._walk(e)
            self.walks[e.key] = (units, unresolved)
            for rf, _ in units:
                reach[str(rf.path)] = reach.get(str(rf.path), 0) + 1
        self.reach = reach
        helpers = {}
        for units, _ in self.walks.values():
            for rf, _ in units:
                if reach[str(rf.path)] >= 2:
                    helpers[str(rf.path)] = rf
        self.helper_files = set(helpers)
        files = list(helpers.values())
        self.evidence = self._helper_evidence(files, full_evidence)
        self.name_re = self._names_re(self.evidence)
        consts = sorted({m.group(1) for rf in files for m in PG_CONST_RE.finditer(rf.code)})
        pg_consts = re.compile(r'\b(%s)\b' % '|'.join(consts)) if consts else None
        self.code_ev = self._helper_evidence(files, lambda rf, a, b: code_evidence(rf, a, b, pg_consts))
        self.code_name_re = self._names_re(self.code_ev)
        self.shared_test_tags = {path: self._shared_test_tags(rf, pg_consts) for path, rf in helpers.items()}

    @staticmethod
    def _names_re(ev):
        names = sorted(ev, key=lambda x: (-len(x), x))
        return re.compile(r'\b(%s)\b' % '|'.join(map(re.escape, names))) if names else None

    def _shared_test_tags(self, rf, pg_consts):
        """{tag: reason} carried by the test fns a shared file declares."""
        tags = {}
        if not TEST_ATTR_RE.search(rf.shape):
            return tags
        label = '%s#tests' % Path(rf.path).name
        for name, a, b in top_level_items(rf):
            if not TEST_ATTR_RE.search(rf.shape, rf._item_start(a), a):
                continue
            for tag in sorted(code_evidence(rf, a, b, pg_consts)):
                tags.setdefault(tag, '%s:%s' % (label, name))
            if self.code_name_re is not None:
                for m in self.code_name_re.finditer(rf.shape, a, b):
                    if m.group(1) != name:
                        for tag in sorted(self.code_ev[m.group(1)]):
                            tags.setdefault(tag, '%s:%s' % (label, m.group(1)))
        return tags

    def _walk(self, exe):
        if not exe.src_path or not Path(exe.src_path).is_file():
            return [], ['<root>']
        return walk_crate(exe.src_path, cache=self.cache)

    @staticmethod
    def _helper_evidence(files, evidence_of):
        items = []
        for rf in files:
            for name, a, b in top_level_items(rf):
                items.append((name, rf, a, b, evidence_of(rf, a, b)))
            for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]*)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)', rf.code):
                items.append((m.group(2), rf, m.start(), m.end(), set()))
        ev = {}
        for name, _, _, _, tags in items:
            if tags:
                ev.setdefault(name, set()).update(tags)
        changed = True
        while changed and ev:
            changed = False
            rx = re.compile(r'\b(%s)\b' % '|'.join(map(re.escape, sorted(ev))))
            for name, rf, a, b, _ in items:
                got = set()
                for m in rx.finditer(rf.code, a, b):
                    if m.group(1) != name:
                        got |= ev[m.group(1)]
                if got - ev.get(name, set()):
                    ev.setdefault(name, set()).update(got)
                    changed = True
        return ev

    def own_text(self, exe):
        """(raw text, unresolved mods, inherited evidence) for one target, or None if unreadable."""
        units, unresolved = self.walks.get(exe.key) or self._walk(exe)
        if not units:
            return None
        own = [rf for rf, _ in units if str(rf.path) not in self.helper_files]
        extras = stem_dir_extras(exe.src_path, {os.path.normpath(str(rf.path)) for rf, _ in units})
        if extras is None:
            return None
        inherited = {}
        for rf, _ in units:
            for tag, why in sorted(self.shared_test_tags.get(str(rf.path), {}).items()):
                inherited.setdefault(tag, why)
        if self.name_re is not None:
            for code in [rf.code for rf in own] + [mask(t)[0] for t in extras]:
                for m in self.name_re.finditer(code):
                    for tag in sorted(self.evidence[m.group(1)]):
                        inherited.setdefault(tag, m.group(1))
        return '\n'.join([rf.text for rf in own] + extras), unresolved, inherited


def stem_dir_extras(src_path, seen):
    """Texts of files under the sibling ``<stem>/`` directory not already in ``seen``.

    Kept from r0: not a Rust module rule, but more evidence never hurts. None
    when one of them is unreadable.
    """
    p = Path(src_path)
    base = p.parent if p.name == 'main.rs' else p.with_suffix('')
    texts = []
    if base.is_dir():
        for f in sorted(base.rglob('*.rs')):
            if os.path.normpath(str(f)) in seen:
                continue
            try:
                texts.append(f.read_text(errors='replace'))
            except OSError:
                return None
    return texts


def read_sources(src_path):
    """Source text of one target on its own: every file its module tree reaches
    (``mod name;``, ``#[path = "..."] mod name;``, ``include!``; the
    ``name.rs``, ``name/mod.rs`` and path-attribute forms), plus any file under
    the sibling ``<stem>/`` directory.

    Returns None when the root is unreadable (unknown source: class a).
    """
    if not src_path or not Path(src_path).is_file():
        return None
    units, _ = walk_crate(src_path)
    if not units:
        return None
    seen = {os.path.normpath(str(rf.path)) for rf, _ in units}
    extras = stem_dir_extras(src_path, seen)
    if extras is None:
        return None
    return '\n'.join([rf.text for rf, _ in units] + extras)


def classify(exe, index=None):
    """Set exe.cls ('a' or 'b'), exe.reasons and exe.shared. Not for the lib.

    Without an index every reachable file counts (most evidence); with one,
    shared helper files count through the names the target references.
    """
    inherited, unresolved, text = {}, [], None
    if index is None:
        text = read_sources(exe.src_path)
        if text is not None:
            unresolved = walk_crate(exe.src_path)[1]
    else:
        got = index.own_text(exe)
        if got is not None:
            text, unresolved, inherited = got
    if text is None:
        exe.cls, exe.reasons = 'a', ['unknown-source']
        return
    reasons = []
    m = PG_RE.search(text)
    if m:
        reasons.append('pg:' + m.group(0)[:32])
    elif 'pg' in inherited:
        reasons.append('pg-helper:' + inherited['pg'])
    if SERIAL_RE.search(text):
        reasons.append('serial')
    elif 'serial' in inherited:
        reasons.append('serial-helper:' + inherited['serial'])
    if FEDERAT_RE.search(exe.name):
        reasons.append('name:federat')
    if unresolved:
        reasons.append('unresolved-mod')
    if reasons:
        exe.cls, exe.reasons = 'a', reasons
        return
    exe.cls = 'b'
    if ENV_RE.search(text):
        exe.reasons.append('env')
    if PORT_RE.search(text) or 'port' in inherited:
        exe.shared.append('port')
    if SHARED_PATH_RE.search(text) or 'shared-path' in inherited:
        exe.shared.append('shared-path')


def module_path_of(src_file, src_root):
    """Lib module path of a file under src/ (store/postgres.rs -> store::postgres)."""
    rel = src_file.relative_to(src_root).with_suffix('')
    parts = list(rel.parts)
    if parts and parts[-1] == 'mod':
        parts = parts[:-1]
    return '::'.join(parts)


def lib_units(src_root):
    """(RustFile, module path) for every lib source file.

    Files reached from ``src/lib.rs`` carry their real module path, including
    ``#[path]`` and ``include!`` targets. Any other ``.rs`` under ``src/`` that
    the ``src/main.rs`` tree does not claim falls back to its file path
    (``store/postgres.rs`` -> ``store::postgres``), so nothing is unscanned.
    """
    root = Path(src_root)
    cache, units, claimed = {}, [], set()
    if (root / 'lib.rs').is_file():
        units, _ = walk_crate(root / 'lib.rs', cache=cache)
        claimed = {os.path.normpath(str(rf.path)) for rf, _ in units}
    if (root / 'main.rs').is_file():
        claimed |= {os.path.normpath(str(rf.path)) for rf, _ in walk_crate(root / 'main.rs', cache=cache)[0]}
    for f in sorted(root.rglob('*.rs')):
        if f.name in ('lib.rs', 'main.rs') or os.path.normpath(str(f)) in claimed:
            continue
        rf = _read(f, cache)
        if rf is not None:
            units.append((rf, module_path_of(f, root)))
    return units


USE_RE = re.compile(r'\buse\s+([^;]*);')
USE_TOKEN_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*|::|[{},*]')


def expand_use_tree(text):
    """Expand a use tree into (segments, alias, glob) triples.

    ``a::{b, c as d, self}`` -> (a,b), (a,c,'d'), (a,) ; ``a::*`` -> (a,) with
    glob set. A trailing ``self`` is dropped (it names the module itself).
    """
    toks = USE_TOKEN_RE.findall(text)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def tree(prefix):
        segs = list(prefix)
        while True:
            t = peek()
            if t == '::':
                pos[0] += 1
            elif t == '{':
                pos[0] += 1
                out = []
                while peek() not in (None, '}'):
                    out += tree(segs)
                    if peek() == ',':
                        pos[0] += 1
                pos[0] += 1
                return out
            elif t == '*':
                pos[0] += 1
                return [(tuple(segs), None, True)]
            elif t is not None and t not in (',', '}', 'as'):
                segs.append(t)
                pos[0] += 1
                if peek() == 'as':
                    alias = toks[pos[0] + 1] if pos[0] + 1 < len(toks) else None
                    pos[0] += 2
                    return [(tuple(segs[:-1] if segs[-1] == 'self' and len(segs) > 1 else segs), alias, False)]
                if peek() != '::':
                    return [(tuple(segs[:-1] if segs[-1] == 'self' and len(segs) > 1 else segs), None, False)]
            else:
                return []

    return tree(())


class UseScope:
    """What `use` items bind inside one module (a module path tuple)."""

    def __init__(self):
        self.items = []   # (segments, local name) for every non-glob import
        self.globs = []   # segments of every `use path::*`


def module_tuple(modp, ctx):
    """Module path tuple for a position (file module + inline mods, stopping at a test fn)."""
    parts = [x for x in modp.split('::') if x]
    for kind, name, is_test in ctx:
        if kind == 'fn' and is_test:
            break
        if kind == 'mod':
            parts.append(name)
    return tuple(parts)


def resolve_modules(segs, here, scopes):
    """Module tuples a path prefix can name from module ``here`` (crate/self/super and `use` aliases)."""
    cur = None
    for seg in segs:
        if cur is None:
            if seg == 'crate':
                cur = {()}
            elif seg == 'self':
                cur = {here}
            elif seg == 'super':
                cur = {here[:-1]}
            else:
                cur = {here + (seg,), (seg,)}
                for target in scopes.get(here, UseScope()).items:
                    if target[1] == seg:
                        cur |= resolve_modules(target[0], here, {})
        elif seg == 'super':
            cur = {q[:-1] for q in cur}
        elif seg == 'self':
            continue
        else:
            nxt = {q + (seg,) for q in cur}
            for q in cur:
                for target in scopes.get(q, UseScope()).items:
                    if target[1] == seg:
                        nxt |= resolve_modules(target[0], q, {})
            cur = nxt
    return cur or set()


def collect_use_scopes(units):
    """({module tuple: UseScope}, {file path: [(start, end)]}) for every `use` item in the lib."""
    scopes, spans = {}, {}
    for rf, modp in units:
        found = list(USE_RE.finditer(rf.shape))
        spans[rf.path] = [(m.start(), m.end()) for m in found]
        for m, ctx in zip(found, rf.contexts([m.start() for m in found])):
            scope = scopes.setdefault(module_tuple(modp, ctx), UseScope())
            for segs, alias, glob in expand_use_tree(m.group(1)):
                if glob:
                    scope.globs.append(segs)
                elif segs:
                    scope.items.append((segs, alias or segs[-1]))
    return scopes, spans


CRATE_ROOTS = ('crate', 'self', 'super')
DEF_KINDS = ('fn', 'struct', 'enum', 'union', 'trait', 'type', 'const', 'static', 'mod')


class ModuleFacts:
    """Per-module `use` scopes, item definitions and the set of known module tuples of the lib."""

    def __init__(self, units):
        self.scopes, self.spans = collect_use_scopes(units)
        self.defs = {}    # module tuple -> names of items defined directly in it
        self.known = {()}  # module tuples that exist (file modules, inline mods and their prefixes)
        for rf, modp in units:
            parts = tuple(x for x in modp.split('::') if x)
            self.known.update(parts[:i] for i in range(1, len(parts) + 1))
            found = list(ITEM_RE.finditer(rf.shape))
            for m, ctx in zip(found, rf.contexts([m.start() for m in found])):
                if m.group(1) not in DEF_KINDS or any(kind != 'mod' for kind, _n, _t in ctx):
                    continue  # impl items, fn-local items, macros: not module-level names
                here = module_tuple(modp, ctx)
                self.defs.setdefault(here, set()).add(m.group(2))
                if m.group(1) == 'mod':
                    self.known.add(here + (m.group(2),))

    def modules(self, segs, here):
        """(known module tuples ``segs`` can name from ``here``, whether the path is unresolvable in-crate).

        Unresolvable means the path starts at the crate (or at a name this module imports) yet
        reaches no known module (an enum, a type, a macro-made module): the caller then fails
        closed instead of treating the name as a different item.
        """
        found = resolve_modules(segs, here, self.scopes) & self.known
        if found:
            return found, False
        imported = {local for _s, local in self.scopes.get(here, UseScope()).items}
        return set(), bool(segs) and (segs[0] in CRATE_ROOTS or segs[0] in imported)


class HelperResolver:
    """Whether a name, seen from a module, may denote one free-fn Postgres helper (fail closed)."""

    def __init__(self, defmod, name, facts):
        self.defmod, self.name, self.facts = defmod, name, facts

    def offers(self, mod, ident, seen):
        """Whether ``ident`` bound in module ``mod`` (defined, imported, glob-imported or re-exported) may be the helper."""
        if (mod, ident) in seen:
            return False  # cycle guard: the other branches of the search decide
        seen.add((mod, ident))
        if ident == self.name and mod == self.defmod:
            return True
        if ident in self.facts.defs.get(mod, ()):
            return False  # a different item defined here shadows any glob
        scope = self.facts.scopes.get(mod, UseScope())
        explicit = [segs for segs, local in scope.items if local == ident]
        if explicit:
            return any(self.item_offers(segs, mod, seen) for segs in explicit)
        return any(self.glob_offers(g, mod, ident, seen) for g in scope.globs)

    def item_offers(self, segs, mod, seen):
        if len(segs) < 2:
            return False
        mods, unresolved = self.facts.modules(segs[:-1], mod)
        return unresolved or any(self.offers(q, segs[-1], seen) for q in sorted(mods))

    def glob_offers(self, glob, mod, ident, seen):
        mods, unresolved = self.facts.modules(glob, mod)
        return unresolved or any(self.offers(q, ident, seen) for q in sorted(mods))

    def hit(self, ref, here, qual):
        """Whether ``ref`` (qualifier ``qual``) in module ``here`` names the helper."""
        if not qual:
            return self.offers(here, ref, set())
        mods, unresolved = self.facts.modules(qual, here)
        return unresolved or any(self.offers(q, ref, set()) for q in sorted(mods))


def helper_hit(resolver, is_method, ref, here, qual):
    """Whether the reference ``ref`` (qualifier ``qual``) in module ``here`` names the helper."""
    if is_method:
        return ref == resolver.name
    return resolver.hit(ref, here, qual)


def macro_spans(rf):
    """[(name, start, end)] of every ``macro_rules!`` body in a file; end None when the body cannot be delimited."""
    out = []
    for m in MACRO_RE.finditer(rf.shape):
        close = {'{': '}', '(': ')', '[': ']'}[m.group(2)]
        depth, i = 0, m.end() - 1
        while i < len(rf.shape):
            ch = rf.shape[i]
            depth += (ch == m.group(2)) - (ch == close)
            if depth == 0:
                break
            i += 1
        out.append((m.group(1), m.end(), i if depth == 0 else None))
    return out


MACRO_RE = re.compile(r'\bmacro_rules\s*!\s*([A-Za-z_][A-Za-z0-9_]*)\s*([{(\[])')


def macro_callers(units, hit_positions, site_path):
    """Sites that invoke a macro whose body reaches the Postgres URL (#6425).

    ``hit_positions`` is [(RustFile, offset)] of every direct URL token and helper call. A
    ``macro_rules!`` whose body holds one is a hot macro (transitively, through macros that
    invoke a hot macro; a body that cannot be delimited counts as hot, fail closed); every
    invocation of a hot macro by name, by any path (``m!``, ``crate::m!``, ``$crate::m!``), is a
    site at the invoking test, so the macro's defining module is not the only place recorded.
    """
    spans = {rf.path: macro_spans(rf) for rf, _m in units}
    hot, changed = set(), True
    for rf, _m in units:
        for name, lo, hi in spans[rf.path]:
            if hi is None or any(h is rf and lo <= at < hi for h, at in hit_positions):
                hot.add(name)
    inv_re = lambda names: re.compile(r'\b(%s)\s*!(?!\s*=)' % '|'.join(map(re.escape, sorted(names))))
    while changed and hot:
        changed = False
        pat = inv_re(hot)
        for rf, _m in units:
            for name, lo, hi in spans[rf.path]:
                if name not in hot and hi is not None and pat.search(rf.shape, lo, hi):
                    hot.add(name)
                    changed = True
    out = []
    if not hot:
        return out
    pat = inv_re(hot)
    for rf, modp in units:
        found = [m for m in pat.finditer(rf.shape)
                 if not re.search(r'macro_rules\s*!\s*$', rf.shape[max(0, m.start() - 32):m.start()])]
        for m, ctx in zip(found, rf.contexts([m.start() for m in found])):
            path, _ = site_path(modp, ctx)
            out.append((path, '%s:%d (invokes macro %s)' % (rf.path, rf.code.count('\n', 0, m.start()) + 1, m.group(1))))
    return out


def helper_callers(units, helpers, site_path):
    """(sites, hit positions) of callers of a Postgres helper, resolved by module path, `use` and globs.

    Strings and comments are blanked (``shape`` view). A free-fn helper matches a name only when
    the name is defined, imported (plain, aliased, group), glob-imported or re-exported (``pub
    use``) along a chain that reaches it, followed transitively with a cycle guard, so
    ``mod tests { use super::*; }`` sees what its parent imports. A name the resolver cannot prove
    is a different item counts as the helper (fail closed, the posture of the bare-name matcher
    this replaced); only a same-module different definition, a method call, or a path that
    provably leaves the crate is excluded (#6412). A helper that is itself an impl/trait method
    has no path to resolve, so any non-definition mention of its name counts.
    """
    facts = ModuleFacts(units)
    names = {n for (_m, n) in helpers}
    grew = True
    while grew:  # every local name a chain of imports can give a helper (alias of an alias)
        grew = False
        for sc in facts.scopes.values():
            for segs, local in sc.items:
                if segs[-1] in names and local not in names:
                    names.add(local)
                    grew = True
    resolvers = {key: HelperResolver(key[0], key[1], facts) for key in helpers}
    pat = re.compile(r'\b(%s)\b' % '|'.join(map(re.escape, sorted(names))))
    out, hits = [], []
    for rf, modp in units:
        refs = []
        for m in pat.finditer(rf.shape):
            if any(a <= m.start() < b for a, b in facts.spans[rf.path]):
                continue  # an import, not a reference
            before = rf.shape[max(0, m.start() - 256):m.start()]
            after = rf.shape[m.end():m.end() + 4]
            if FN_BEFORE_RE.search(before) or re.match(r'\s*(!|:(?!:)|::(?!\s*<))', after):
                continue  # definition, macro, field/param/label or a module prefix
            q = re.search(r'((?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)+)$', before)
            qual = tuple(re.findall(r'[A-Za-z_][A-Za-z0-9_]*', q.group(1))) if q else ()
            head = before[:q.start()] if q else before
            refs.append((m, qual, head.rstrip().endswith('.')))
        if not refs:
            continue
        for (m, qual, dotted), ctx in zip(refs, rf.contexts([r[0].start() for r in refs])):
            here = module_tuple(modp, ctx)
            path, _ = site_path(modp, ctx)
            for key, (is_method, def_paths) in helpers.items():
                if dotted and not is_method:
                    continue  # `x.name()` is a method call, never the free fn
                if path not in def_paths and helper_hit(resolvers[key], is_method, m.group(1), here, qual):
                    out.append((path, '%s:%d (calls %s)' % (rf.path, rf.code.count('\n', 0, m.start()) + 1, key[1])))
                    hits.append((rf, m.start()))
    return out, hits


def lib_pg_sites(src_root):
    """Every lib code site that names the Postgres test URL.

    A site is an ``AI_MEMORY_TEST_POSTGRES_URL`` token in code or a string
    literal (comments do not count: they cannot read the environment), or any
    use of a const/static whose value contains it (``env::var(PG_URL_ENV)``).
    Yields (test path, file:line): the path of the enclosing ``#[test]`` fn
    when there is one, else the enclosing module (a helper fn can be called by
    any test in that module, so the whole module must be covered).
    """
    units = lib_units(src_root)
    consts = set()
    for rf, _ in units:
        consts.update(m.group(1) for m in PG_CONST_RE.finditer(rf.code))
    const_re = re.compile(r'\b(%s)\b' % '|'.join(map(re.escape, sorted(consts)))) if consts else None
    out, direct = [], []
    helpers = {}  # (module tuple, fn name) -> [is method, def paths]: a non-test fn that names the URL (r2 F2; resolved by path, #6412)

    def site_path(modp, ctx):
        parts = [modp] if modp else []
        test_fn = None
        for kind, name, is_test in ctx:
            if kind == 'mod' and test_fn is None:
                parts.append(name)
            elif kind == 'fn' and is_test and test_fn is None:
                test_fn = name
        if test_fn:
            parts.append(test_fn)
        return '::'.join(parts), test_fn

    for rf, modp in units:
        pos = [m.start() for m in PG_TOKEN_RE.finditer(rf.code)]
        if const_re is not None:
            pos += [m.start() for m in const_re.finditer(rf.code)]
        if not pos:
            continue
        direct.extend((rf, at) for at in pos)
        for at, ctx in zip(pos, rf.contexts(pos)):
            path, test_fn = site_path(modp, ctx)
            if test_fn is None:
                fn_at = [i for i, (kind, _n, _t) in enumerate(ctx) if kind == 'fn']
                if fn_at:  # innermost enclosing fn: a helper any other test may call
                    i = fn_at[-1]
                    entry = helpers.setdefault((module_tuple(modp, ctx), ctx[i][1]), [False, set()])
                    entry[0] = entry[0] or (i > 0 and ctx[i - 1][0] == 'blk')  # impl/trait method: resolved by name only
                    entry[1].add(path)
            line = rf.code.count('\n', 0, at) + 1
            out.append((path, '%s:%d' % (rf.path, line)))
    hits = [(rf, at) for rf, at in direct]
    if helpers:
        found, more = helper_callers(units, helpers, site_path)
        out.extend(found)
        hits.extend(more)
    out.extend(macro_callers(units, hits, site_path))
    return out


def uncovered_lib_pg_modules(src_root, prefixes):
    """Lib test paths that name the Postgres test URL but that no prefix selects.

    libtest's filter is a substring match on the full test path, and the same
    prefixes are a positional filter in the serial shard and ``--skip`` in the
    parallel one, so a site at path T is covered iff some prefix p occurs in T.
    (r0 also accepted ``p.startswith(T)``: one test's prefix "covered" its whole
    module, and ``store::postgres`` "covered" ``store``. #6344 review r1 B2.)
    """
    missing = set()
    for path, _where in lib_pg_sites(src_root):
        if not any(p in path for p in prefixes):
            missing.add(path or '<crate root>')
    return sorted(missing)


def load_prefixes(path):
    out = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            out.append(line)
    return out


def load_weights(path):
    try:
        data = json.loads(Path(path).read_text())
        return {str(k): float(v) for k, v in data['weights'].items()}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise PartitionError('cannot read weight table %s: %s' % (path, exc))


def weight_of(exe, weights, class_mean):
    return weights.get(exe.key, class_mean.get(exe.cls, 0.0))


def class_means(exes, weights):
    sums = {'a': [0.0, 0], 'b': [0.0, 0]}
    for e in exes:
        if e.key in weights and e.cls in sums:
            sums[e.cls][0] += weights[e.key]
            sums[e.cls][1] += 1
    all_s = sum(v[0] for v in sums.values())
    all_n = sum(v[1] for v in sums.values())
    fallback = all_s / all_n if all_n else 0.0
    return {c: (v[0] / v[1] if v[1] else fallback) for c, v in sums.items()}


def balance(items, base1, base2):
    """Greedy longest-first split of (weight, [exes]) items into two halves."""
    h1, h2 = [], []
    t1, t2 = base1, base2
    for weight, group in sorted(items, key=lambda it: (-it[0], it[1][0].key)):
        if t1 <= t2:
            h1.extend(group)
            t1 += weight
        else:
            h2.extend(group)
            t2 += weight
    return h1, h2, t1, t2


def partition(exes, weights, prefixes, with_doc=False):
    """Return (serial, half1, half2, lib_in_half1, totals). Lists hold Exe objects.

    Each target is classified on the union of the sources it compiles (its
    ``mod``/``#[path]``/``include!`` tree), with shared helper files folded in
    per referenced item (see ``SourceIndex``). With ``with_doc`` the doc tests,
    which the serial shard runs after its binaries, add ``weights['doc:tests']``
    to the serial estimate.
    """
    lib = [e for e in exes if e.kind == 'lib']
    others = [e for e in exes if e.kind != 'lib']
    index = SourceIndex(others)
    for e in others:
        classify(e, index)
        units = index.walks.get(e.key, ([], []))[0]
        e.test_count = sum(len(TEST_ATTR_RE.findall(rf.shape)) for rf, _ in units) or None
    means = class_means(others, weights)
    serial = [e for e in others if e.cls == 'a']
    b_exes = [e for e in others if e.cls == 'b']
    shared = [e for e in b_exes if e.shared]
    free = [e for e in b_exes if not e.shared]
    items = [(weight_of(e, weights, means), [e]) for e in free]
    if shared:
        items.append((sum(weight_of(e, weights, means) for e in shared), sorted(shared, key=lambda x: x.key)))
    lib_nonpg = weights.get('lib:nonpg', 0.0) if lib else 0.0
    lib_pg = weights.get('lib:pg', 0.0) if lib else 0.0
    h1, h2, t1, t2 = balance(items, lib_nonpg, 0.0)
    doc = weights.get('doc:tests', 0.0) if with_doc else 0.0
    ts = lib_pg + doc + sum(weight_of(e, weights, means) for e in serial)

    def est(exes_, base):
        # a binary's tests use at most min(test count, threads) threads (r2 F4); unknown count = full threads
        return base / SHARD_THREADS + sum(
            weight_of(e, weights, means) / min(e.test_count or SHARD_THREADS, SHARD_THREADS) for e in exes_)

    totals = {'serial': ts, 'parallel_1': t1, 'parallel_2': t2,
              'parallel_1_est': est(h1, lib_nonpg), 'parallel_2_est': est(h2, 0.0)}
    return serial, h1, h2, bool(lib), totals, means


def write_lists(out_dir, serial, h1, h2, has_lib):
    out_dir.mkdir(parents=True, exist_ok=True)
    spec = {'serial': serial, 'parallel_1': h1, 'parallel_2': h2}
    for name, exes in spec.items():
        lines = [e.selector for e in sorted(exes, key=lambda x: x.key)]
        if has_lib and name in ('serial', 'parallel_1'):
            lines.insert(0, '--lib')
        (out_dir / (name + '.txt')).write_text(''.join(l + '\n' for l in lines))


def verify_written(out_dir, exes):
    """Re-read the three list files; assert disjoint and complete. Fail loudly."""
    expected = {e.selector for e in exes if e.kind != 'lib'}
    got = {}
    for name in ('serial', 'parallel_1', 'parallel_2'):
        lines = [l for l in (out_dir / (name + '.txt')).read_text().splitlines() if l]
        non_lib = [l for l in lines if l != '--lib']
        if len(non_lib) != len(set(non_lib)):
            raise PartitionError('%s.txt lists a target twice' % name)
        got[name] = (set(non_lib), '--lib' in lines)
    s, p1, p2 = (got[n][0] for n in ('serial', 'parallel_1', 'parallel_2'))
    overlap = (s & p1) | (s & p2) | (p1 & p2)
    if overlap:
        raise PartitionError('shards overlap: %s' % sorted(overlap))
    union = s | p1 | p2
    if union != expected:
        raise PartitionError('union is not every executable: missing=%s extra=%s'
                             % (sorted(expected - union), sorted(union - expected)))
    has_lib = any(e.kind == 'lib' for e in exes)
    if has_lib != (got['serial'][1] and got['parallel_1'][1]) or got['parallel_2'][1]:
        raise PartitionError('--lib must appear in serial.txt and parallel_1.txt only (and only when the lib was built)')


def run(args):
    lines = sys.stdin if args.build_json == '-' else Path(args.build_json).read_text().splitlines()
    exes = parse_build_json(lines)
    repo = Path(args.repo_root)
    prefixes = load_prefixes(args.lib_pg_prefixes)
    has_lib = any(e.kind == 'lib' for e in exes)
    if has_lib:
        if not prefixes:
            raise PartitionError('lib_pg_prefixes is empty: the whole lib would run in the serial shard unfiltered')
        missing = uncovered_lib_pg_modules(repo / 'src', prefixes)
        if missing:
            raise PartitionError('lib modules read AI_MEMORY_TEST_POSTGRES_URL but no prefix in %s covers them: %s'
                                 % (args.lib_pg_prefixes, ', '.join(missing)))
    weights = load_weights(args.weights)
    serial, h1, h2, has_lib, totals, means = partition(exes, weights, prefixes, args.with_doc == '1')
    out_dir = Path(args.out_dir)
    write_lists(out_dir, serial, h1, h2, has_lib)
    (out_dir / 'lib_pg_filters.txt').write_text(''.join(p + '\n' for p in prefixes))
    verify_written(out_dir, exes)
    manifest = {
        'executables': len(exes),
        'counts': {'serial': len(serial) + (1 if has_lib else 0),
                   'parallel_1': len(h1) + (1 if has_lib else 0), 'parallel_2': len(h2)},
        'class_mean_seconds': means,
        'doc_tests_in_serial': args.with_doc == '1',
        'estimate_seconds': {
            'serial_threads_1': round(totals['serial'], 1),
            'parallel_1_serial_work': round(totals['parallel_1'], 1),
            'parallel_2_serial_work': round(totals['parallel_2'], 1),
            'parallel_1_ideal_threads_3': round(totals['parallel_1'] / 3, 1),
            'parallel_2_ideal_threads_3': round(totals['parallel_2'] / 3, 1),
            'parallel_1_est_min_tests_threads': round(totals['parallel_1_est'], 1),
            'parallel_2_est_min_tests_threads': round(totals['parallel_2_est'], 1),
        },
        'targets': {e.key: {'class': e.cls, 'reasons': e.reasons, 'shared': e.shared}
                    for e in exes if e.kind != 'lib'},
    }
    (out_dir / 'manifest.json').write_text(json.dumps(manifest, indent=1, sort_keys=True) + '\n')
    print('[#6344] shards: serial=%d parallel_1=%d parallel_2=%d of %d executables; '
          'estimate serial=%.0fs parallel=%.0fs/%.0fs (per-binary min(tests, 3) threads; ideal %.0fs/%.0fs)'
          % (manifest['counts']['serial'], manifest['counts']['parallel_1'], manifest['counts']['parallel_2'],
             len(exes), totals['serial'], totals['parallel_1_est'], totals['parallel_2_est'],
             totals['parallel_1'] / 3, totals['parallel_2'] / 3))
    return 0


def build_parser():
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--build-json', default='-', help="cargo --message-format=json output file ('-' = stdin)")
    ap.add_argument('--repo-root', default='.', help='repository root (for src/ scanning)')
    ap.add_argument('--out-dir', required=True, help='directory for the list files and manifest')
    ap.add_argument('--weights', default=str(here / 'test_binary_weights.json'))
    ap.add_argument('--lib-pg-prefixes', default=str(here / 'lib_pg_prefixes.txt'))
    ap.add_argument('--with-doc', choices=('0', '1'), default='0',
                    help='1 when the serial shard also runs the doc tests (adds doc:tests to its estimate)')
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except PartitionError as exc:
        print('::error::[#6344 shard] %s' % exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
