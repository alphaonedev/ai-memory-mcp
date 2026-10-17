#!/usr/bin/env python3
"""#7347 gate -- INVARIANT: in an integration-test file that mutates the process environment,
every test function that can race those writers must hold THE lock the writers use.

Why. `cargo test` runs every test of one binary as a thread of ONE process. A test that never
writes the environment but triggers an unsynchronised C-level `getenv` while a sibling runs
`set_var` / `remove_var` can read a freed `environ` block and die with SIGSEGV (`setenv` may
realloc `environ`). Rust `std::env::var` reads are NOT the crash path: std serialises them with
`set_var` under its own env lock, so they only see a stale or wrong value. The crash path is a
C reader: here the bundled SQLite, whose `sqlite3_os_init` -> `unixTempFileInit` calls
`getenv("SQLITE_TMPDIR")` / `getenv("TMPDIR")` without a lock on the FIRST SQLite open of the
process (libsqlite3-sys sqlite3.c ~44352). That is the #7347 shape
(`federation_pending_resurrection_2529`: three locked writers, one unlocked `db::open` reader;
SIGSEGV 0.09 s after `running 4 tests`). A nextest leg runs one process per test and cannot hit it.

Model. A `tests/*.rs` is an env-mutating file when it has a WRITE SITE: a direct `env::set_var` /
`env::remove_var`, a tests/common guard (EnvVarGuard::set/remove, MultiEnvVarGuard::apply,
install_test_operator_key; each holds tests/common ENV_LOCK while it writes), a tests/common Once
setter (ensure_no_config_env, permissive_attestation_for_tests), or a pg_isolate writer
(isolated_url, publish_env_within). Each write site gets a PROTECTION SET: the tokens held at the
write, that is
  * locks bound with `let <name> = ...` (not `let _ = ...`) earlier in a block that encloses the
    write and not released by `drop(<name>)` before it: `ENV_LOCK.lock()`, `.blocking_lock()`,
    `.lock().await`, `env_lock()`, a same-file helper that returns a guard (also a helper that
    wraps such a helper), a tests/common guard;
  * the locks every same-file caller holds at its call, intersected over the callers and followed
    up the whole same-file call graph (the issue_4357 shape: the writer is two calls below the
    test that holds SERIAL);
  * `once:<setter>` for a Once-gated setter: after that setter returns its write never happens
    again, so a caller that ran it first cannot race it;
  * `#[serial]` for a serial test.
A write site inside an `#[ignore]` test, or reachable only from ignored tests, is skipped: CI runs
ignored tests one at a time (`--test-threads=1` in postgres-ignored.yml, coverage.yml and
cert-postgres-age.yml; `--exact` in token-budget.yml; pinned by a unit test).

Rule. In an env-mutating file with at least two non-ignored test fns (a single-test binary has
nothing to race in-process) that is not marked `// env-mutation-gate: process-isolated -- <reason>`,
a non-ignored, non-`#[serial]` test fn is VIOLATING when one of its READERS, or one in a same-file
fn or method it calls (followed HELPER_DEPTH levels, closures and loops included), is reached
without holding, at that point, one token of EVERY write site's protection set. Write sites with
an empty set (an unlocked writer) are not required of the readers, because the unlocked writer is
itself flagged; when no write site has any protection, every reader is flagged. Readers are:
  * strong (a C getenv or a write): SQLite / store / router / config open, `reqwest`, `sqlx`,
    `PgPool`, `postgres_url()`, DNS (`ToSocketAddrs`), `Local::now`, a tests/common helper that
    reaches one of those (computed from tests/common), and every write site;
  * weak (a Rust env read, a logical race): `env::var*` of a variable some write site writes
    (literal or a same-file `const`; an unknown name counts). `use` items are not readers.
A token is held when it is acquired before the reader in a block that encloses it; a lock helper
that holds the lock while it works (`with_env_lock(|| ..)`) covers only its own call.

Known limits, stated plainly:
  * resolution is by name, same file only (free fns, `Type::method`, `.method()` on any same-file
    impl), plus the tests/common reader census; code in src/ is judged only by the tokens above;
  * the reader check is a token heuristic; a fn that reaches a C getenv only through code the
    tokens do not name is treated as pure;
  * a `drop(<guard>)` anywhere between the lock and the reader releases it, even in a branch;
  * macro-generated test fns and env writes in tests/<dir>/ sub-modules are not seen;
  * `#[serial]` is trusted without checking its key.

Ratchet. Existing violations live in scripts/qc-allowlists/test-env-mutation-unlocked-baseline.txt,
one `<path>::<fn>` per line (`<path>::<mod>::<fn>` for a nested module). CI fails on (a) a violating
fn that is not in the baseline (a new unlocked fn fails even when another one was fixed in the
same change) and (b) a baseline entry that no longer violates: delete the line, so the list only
shrinks.

Usage:
  scripts/check-test-env-mutation.py                    # scan tests/ against the baseline
  scripts/check-test-env-mutation.py --list             # print current <path>::<fn> lines
  scripts/check-test-env-mutation.py --update-baseline  # rewrite the baseline (reviewable diff)
  scripts/check-test-env-mutation.py --root DIR         # scan DIR/tests, baseline under DIR
Cargo-free, stdlib python3 only. Fixtures for the tests live under .local-runs/, never a tmp dir.
"""
import argparse
import collections
import pathlib
import re
import sys

BASELINE_REL = "scripts/qc-allowlists/test-env-mutation-unlocked-baseline.txt"
TESTS_REL = "tests"
COMMON_REL = "tests/common"
SRC_REL = "src"
ISOLATED_MARKER = re.compile(r"^\s*//\s*env-mutation-gate:\s*process-isolated\b", re.M)
# Direct writers: env::set_var / remove_var, qualified or imported bare (not `fn set_var`, not `.set_var`).
DIRECT_MUTATION = re.compile(r"(?<![\w.])(?:(?:std::)?env::)?(?:set_var|remove_var)\s*\(")
ONCE_SETTERS = ("ensure_no_config_env", "permissive_attestation_for_tests")
# tests/common guards: each takes tests/common/mod.rs ENV_LOCK and holds it for its lifetime.
COMMON_GUARD_METHODS = {"EnvVarGuard": ("set", "remove"), "MultiEnvVarGuard": ("apply",)}
COMMON_GUARD_FNS = ("install_test_operator_key",)
LOCAL_GUARD_TYPE = "EnvGuard"  # a file-local guard type; a same-file impl is followed, else a lock of its own
PG_ISOLATE_ONCE = "isolated_url"  # get_or_init-gated: mints and publishes the URL once
PG_ISOLATE_WRITER = "publish_env_within"  # writes under pg_isolate's own env lock
COMMON_ENV_LOCK = "common::ENV_LOCK"
PG_ISOLATE_LOCK = COMMON_ENV_LOCK  # pg_isolate::lock_env_bounded try-locks super::ENV_LOCK
ONCE_PREFIX = "once:"
SERIAL_TOKEN = "#[serial]"
ANY_VAR = "*"
ONCE_BODY = re.compile(r"\b(?:call_once|get_or_init)\b")
# STRONG readers reach a C getenv (the crash path): SQLite open (first-open unixTempFileInit),
# router / config build, network name resolution (reqwest, sqlx, PgPool, a Postgres connect), local time. WEAK readers
# are Rust env reads, which std serialises with set_var (a logical race: stale or wrong value).
STRONG_READER = re.compile(
    r"\b(?:db|storage)\s*::\s*open\w*|\bConnection\s*::\s*open\w*|\bopen_(?:db|store|conn|unmigrated)\w*|"
    r"\bSqliteStore\s*::|\bfresh_(?:conn|db)\w*|\bdb_at\b|"
    r"\bAppConfig\s*::|\bConfig\s*::\s*load\w*|\bbuild_router\w*|\brouter\s*\(|"
    r"\breqwest\b|\bsqlx\s*::\s*(?:[A-Za-z_]\w*\s*::\s*)*(?:Pg\w*|connect\w*)|\bPgPool\w*|\b(?:PostgresStore|PgConnection)\s*::\s*connect\w*|\btokio_postgres\s*::\s*connect\w*|"
    r"\bpostgres_url\s*\(|\bToSocketAddrs\b|\bLocal\s*::\s*now\b")
WEAK_READER = re.compile(r"\benv\s*::\s*var\w*")
FN_DECL = re.compile(r"\b(?:async\s+)?fn\s+([A-Za-z_]\w*)")
TEST_ATTR = re.compile(r"#\[\s*(?:[A-Za-z_]\w*::)*(?:test|test_case|rstest)\b")
CFG_ATTR = re.compile(r"#\[\s*cfg_attr\s*\(")
SERIAL_ATTR = re.compile(r"#\[\s*(?:[A-Za-z_]\w*::)*serial\b")
IGNORE_ATTR = re.compile(r"#\[\s*ignore\b")
USE_ITEM = re.compile(r"(?<![\w:])use\s+[A-Za-z_:{*][^;]*;")
CONST_STR = re.compile(r"\bconst\s+([A-Za-z_]\w*)\s*:\s*&\s*(?:'static\s+)?str\s*=\s*\"([^\"\\]*)\"")
STR_LIT = re.compile(r"\"((?:[^\"\\]|\\.)*)\"")
IDENT = re.compile(r"[A-Za-z_]\w*")
CALL = re.compile(r"((?:[A-Za-z_]\w*\s*::\s*)*)([A-Za-z_]\w*)\s*\(")
LOCK_METHOD = re.compile(r"\.\s*(?:blocking_lock|lock_owned|lock)\s*\(")
LET_BOUND = re.compile(r"^\s*let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=]*)?=(?!=)")
LET_TUPLE = re.compile(r"^\s*let\s+\(([^)]*)\)\s*(?::[^=]*)?=(?!=)")
LET_HEAD = re.compile(r"^\s*let\s+(?:\([^)]*\)|(?:mut\s+)?[A-Za-z_]\w*)\s*(?::[^=]*)?=(?!=)")
CHAR_LIT = re.compile(r"'(?:\\.[^']{0,8}|[^\\'])'")
BLOCK_HEADER = re.compile(
    r"(?:(?<=[;{}\]])|^)\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:(mod)\s+([A-Za-z_]\w*)\s*\{|(impl)\b([^;{}]*)\{)")
HELPER_DEPTH = 6  # same-file call levels followed below a test fn when looking for its readers
CALL_WINDOW = 8  # chars before a call scanned for a `.` (method call) or a `fn` (declaration)
GENERIC_NAMES = frozenset((
    "lock", "locks", "locked", "blocking_lock", "lock_owned", "try_lock", "into_inner", "unlock",
    "RwLock", "OnceLock", "LazyLock", "Mutex", "MutexGuard", "RwLockReadGuard", "RwLockWriteGuard",
    "PoisonError", "poison", "is_poisoned"))
LOCK_TYPE_NAMES = frozenset((
    "RwLock", "OnceLock", "LazyLock", "Mutex", "MutexGuard", "RwLockReadGuard", "RwLockWriteGuard",
    "PoisonError"))
PATH_SELF = ("self", "super", "crate")
MACRO_RULES = re.compile(r"\bmacro_rules\s*!\s*([A-Za-z_]\w*)\s*\{")
MACRO_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*!\s*[({\[]")
META_CALL = re.compile(r"\$([A-Za-z_]\w*)\s*\(")
WORKFLOW_IGNORED = re.compile(r"--(?:include-)?ignored\b")
HEADER = (
    "# scripts/qc-allowlists/test-env-mutation-unlocked-baseline.txt -- issue #7347 ratchet.\n"
    "#\n"
    "# Format: <path>::<test fn>   (one line per violating fn; <path>::<mod>::<fn> in a nested module)\n"
    "#\n"
    "# A test fn of a tests/*.rs that mutates the process environment must hold the lock its\n"
    "# writers use when it can reach an env / C getenv reader (see scripts/check-test-env-mutation.py).\n"
    "# An entry that no longer violates must be removed: the list may only shrink.\n"
    "# Regenerate with: scripts/check-test-env-mutation.py --update-baseline\n"
)

Acq = collections.namedtuple("Acq", "pos end tokens kind bound names")
Site = collections.namedtuple("Site", "index fn pos base protect names")
Summary = collections.namedtuple("Summary", "persist ret work")
EMPTY = frozenset()
EMPTY_SUMMARY = Summary(EMPTY, EMPTY, EMPTY)


def scrub(src):
    """Blank comments, string and char literals (newlines kept) so braces and idents are real."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c == "r" and re.match(r'r#*"', src[i:i + 12]) and (i == 0 or not src[i - 1].isalnum() and src[i - 1] != "_"):
            hashes = re.match(r"r(#*)\"", src[i:]).group(1)
            end = '"' + hashes
            j = src.find(end, i + 2 + len(hashes))
            j = n if j < 0 else j + len(end)
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c == "'":
            m = CHAR_LIT.match(src, i)
            if m:
                out.append(" " * (m.end() - i))
                i = m.end()
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def blank_use_items(scrubbed):
    """Blank `use ...;` items (same length) so an import never reads as an opener or a call."""
    return USE_ITEM.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), scrubbed)


def common_imports(scrubbed):
    """(names, glob): names a file imports from tests/common, and whether it glob-imports it."""
    names, glob = set(), False
    for m in USE_ITEM.finditer(scrubbed):
        item = m.group(0)
        if not re.search(r"\bcommon\s*::", item):
            continue
        tail = item.split("common", 1)[1]
        glob = glob or "*" in tail
        names.update(IDENT.findall(tail))
    return names, glob


def match_brace(text, open_idx):
    """Index just past the `}` closing the `{` at open_idx, or len(text) if unbalanced."""
    depth = 0
    for j in range(open_idx, len(text)):
        ch = text[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j + 1
    return len(text)


def match_paren(text, open_idx):
    """Index just past the `)` closing the `(` at open_idx, or len(text) if unbalanced."""
    depth = 0
    for j in range(open_idx, len(text)):
        ch = text[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return j + 1
    return len(text)


def innermost_open(body, pos):
    """Index of the innermost `{` of body that is still open at pos (0 = the fn body brace)."""
    depth = 0
    for j in range(pos - 1, -1, -1):
        ch = body[j]
        if ch == "}":
            depth += 1
        elif ch == "{":
            if depth == 0:
                return j
            depth -= 1
    return 0


def has_lock_word(ident):
    """True when the identifier carries a `lock` word (snake or CamelCase), not block/clock."""
    for part in ident.split("_"):
        if not part:
            continue
        if part.lower() in ("lock", "locks", "locked"):
            return True
        words = re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", part)
        if any(w.lower() in ("lock", "locks") for w in words):
            return True
    return False


def is_lock_name(ident):
    return has_lock_word(ident) and ident not in GENERIC_NAMES and not ident.startswith("_")


def is_lock_fn_name(name):
    """A free fn named like a lock helper (`env_lock`, `forensic_lock`, `lock`)."""
    return has_lock_word(name) and name not in LOCK_TYPE_NAMES and not name.startswith("_")


class Fn:
    """One fn item: qualified name, owner type, attrs and the scrubbed body (starting at `{`)."""

    def __init__(self, name, mods, owner, attrs, body, offset):
        self.name, self.mods, self.owner, self.attrs, self.body = name, mods, owner, attrs, body
        self.offset = offset
        self.is_test = self._is_test(attrs)
        self.serial = bool(SERIAL_ATTR.search(attrs))
        self.ignored = self.is_test and bool(IGNORE_ATTR.search(attrs))

    @staticmethod
    def _is_test(attrs):
        if TEST_ATTR.search(attrs):
            return True
        for m in CFG_ATTR.finditer(attrs):
            # `cfg_attr(<predicate>, <attrs>)`: a `test` after the first top-level comma is a test attr.
            depth, k = 1, m.end()
            while k < len(attrs) and depth:
                depth += {"(": 1, ")": -1}.get(attrs[k], 0)
                if depth == 1 and attrs[k] == ",":
                    return bool(re.search(r"(?<![\w])test\b", attrs[k:]))
                k += 1
        return False

    @property
    def qual(self):
        return "::".join(list(self.mods) + [self.name])

    @property
    def key(self):
        return "%s::%s" % (self.owner, self.name) if self.owner else self.name


def impl_type(header):
    """Type named by the header of an `impl [<..>] [Trait for] Type {` block."""
    h = header.split(" where ")[0]
    if re.search(r"\bfor\b", h):
        h = re.split(r"\bfor\b", h)[-1]
    h = re.sub(r"^\s*<[^>]*>", "", h)
    m = IDENT.search(h)
    return m.group(0) if m else None


def parse_fns(scrubbed):
    """Return every fn item of scrubbed source with its enclosing mods and impl type."""
    blocks = []
    for m in BLOCK_HEADER.finditer(scrubbed):
        brace = m.end() - 1
        end = match_brace(scrubbed, brace)
        if m.group(1):
            blocks.append((brace, end, "mod", m.group(2)))
        else:
            blocks.append((brace, end, "impl", impl_type(m.group(4))))
    macro_spans = [(m.end() - 1, match_brace(scrubbed, m.end() - 1))
                   for m in re.finditer(r"\bmacro_rules\s*!\s*\w+\s*\{", scrubbed)]
    fns = []
    for m in FN_DECL.finditer(scrubbed):
        if any(a < m.start() < b for a, b in macro_spans):
            continue  # a macro_rules body is a template, not a test fn (macro expansions are not seen)
        start = max(scrubbed.rfind(";", 0, m.start()), scrubbed.rfind("}", 0, m.start()),
                    scrubbed.rfind("{", 0, m.start())) + 1
        attrs = scrubbed[start:m.start()]
        brace = scrubbed.find("{", m.end())
        semi = scrubbed.find(";", m.end())
        if brace < 0 or (0 <= semi < brace):
            continue
        mods = [b[3] for b in blocks if b[2] == "mod" and b[0] < m.start() < b[1]]
        owners = [b[3] for b in blocks if b[2] == "impl" and b[0] < m.start() < b[1]]
        fns.append(Fn(m.group(1), mods, owners[-1] if owners else None, attrs,
                      scrubbed[brace:match_brace(scrubbed, brace)], brace))
    return fns


def let_names(prefix):
    """Non-`_` names bound by a `let <name> = ..` / `let (a, _b) = ..` statement prefix, else ().

    `let _ = guard;` drops the guard at once and binds nothing.
    """
    m = LET_BOUND.match(prefix)
    if m:
        return () if m.group(1) == "_" else (m.group(1),)
    m = LET_TUPLE.match(prefix)
    if not m:
        return ()
    parts = (p.strip().replace("mut ", "").strip() for p in m.group(1).split(","))
    return tuple(p for p in parts if p not in ("", "_"))


def let_bound(prefix):
    return bool(let_names(prefix))


def depth_at(body, pos):
    return body.count("{", 0, pos) - body.count("}", 0, pos)


def stmt_prefix(body, pos):
    """Text of the statement containing pos, from the previous `;`/`{`/`}` up to pos."""
    start = max(body.rfind(";", 0, pos), body.rfind("{", 0, pos), body.rfind("}", 0, pos)) + 1
    return body[start:pos]


def lock_tokens(prefix):
    """Lock names in the receiver of a `.lock()`: lock-word idents and an ALL_CAPS static."""
    expr = LET_HEAD.sub("", prefix, count=1)  # the binding name is not the lock
    names = {i for i in IDENT.findall(expr) if is_lock_name(i)}
    tail = re.search(r"([A-Za-z_]\w*)\s*(?:\([^()]*\)\s*)?$", expr)
    if tail and re.fullmatch(r"[A-Z][A-Z0-9_]*", tail.group(1)):
        names.add(tail.group(1))  # a static such as ENV_LOCK; a db or conn receiver never qualifies
    return names


def is_tail(body, pos):
    """True when the expression at pos is the value of its block (no `;` before the closing `}`)."""
    depth = 0
    for j in range(pos, len(body)):
        ch = body[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                if ch == "}":
                    return True
                continue  # leaving an enclosing call or tuple: keep looking for the statement end
            depth -= 1
        elif ch == ";" and depth == 0:
            return False
    return True


def path_segments(prefix):
    return IDENT.findall(prefix)


def first_arg_text(body, open_idx):
    """(start, end) of the first argument of the call whose `(` is at open_idx, in body."""
    depth, j = 0, open_idx
    while j < len(body):
        ch = body[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return open_idx + 1, j
        elif ch == "," and depth == 1:
            return open_idx + 1, j
        j += 1
    return open_idx + 1, len(body)


class Source:
    """Raw and scrubbed text of one file (same length), with its string `const`s."""

    def __init__(self, raw, fallback=None):
        self.raw = raw
        self.scrubbed = blank_use_items(scrub(raw)) if raw is not None else None
        self.consts = dict(fallback or {})
        self.consts.update(CONST_STR.findall(raw) if raw is not None else ())

    def arg_name(self, fn, open_idx):
        """Env var named by the first argument of a call: a literal or a const, else ANY_VAR."""
        if self.raw is None or open_idx < 0 or open_idx >= len(fn.body) or fn.body[open_idx] != "(":
            return ANY_VAR
        a, b = first_arg_text(fn.body, open_idx)
        text = self.raw[fn.offset + a:fn.offset + b].strip().lstrip("&").strip()
        m = STR_LIT.fullmatch(text)
        if m:
            return m.group(1)
        if re.fullmatch(r"(?:[A-Za-z_]\w*\s*::\s*)*[A-Za-z_]\w*", text):
            return self.consts.get(IDENT.findall(text)[-1], ANY_VAR)
        return ANY_VAR

    def literals(self, fn, open_idx):
        """Every string literal inside the call parens at open_idx (MultiEnvVarGuard::apply keys)."""
        if self.raw is None:
            return {ANY_VAR}
        end = match_paren(fn.body, open_idx)
        return set(STR_LIT.findall(self.raw[fn.offset + open_idx:fn.offset + end])) or {ANY_VAR}


class CommonModel:
    """tests/common census: free fns that reach a strong reader, and the vars each helper writes."""

    def __init__(self, root=None):
        self.fns = {}
        self.sources = {}
        self._strong, self._vars = {}, {}
        self.src_consts = self._src_consts(root)
        base = pathlib.Path(root) / COMMON_REL if root is not None else None
        if base is None or not base.is_dir():
            return
        for path in sorted(base.rglob("*.rs")):
            src = Source(path.read_text(encoding="utf-8", errors="replace"), self.src_consts)
            for f in parse_fns(src.scrubbed):
                if not f.is_test:
                    self.fns.setdefault(f.key, f)
                    self.sources[id(f)] = src

    @staticmethod
    def _src_consts(root):
        """`const NAME: &str = "..."` across src/ (a name with two different values stays unknown)."""
        values = {}
        base = pathlib.Path(root) / SRC_REL if root is not None else None
        if base is None or not base.is_dir():
            return {}
        for path in sorted(base.rglob("*.rs")):
            for name, value in CONST_STR.findall(path.read_text(encoding="utf-8", errors="replace")):
                values.setdefault(name, set()).add(value)
        return {name: vals.pop() for name, vals in values.items() if len(vals) == 1}

    @property
    def free_names(self):
        return {k for k, f in self.fns.items() if f.owner is None}

    def _callees(self, fn):
        for m in CALL.finditer(fn.body):
            segs = path_segments(m.group(1))
            key = "%s::%s" % (segs[-1], m.group(2)) if segs else m.group(2)
            hit = self.fns.get(key) or (self.fns.get(m.group(2)) if not segs or segs[-1] in PATH_SELF else None)
            if hit is not None and hit is not fn:
                yield m, hit

    def strong(self, name, stack=()):
        fn = self.fns.get(name)
        if fn is None or id(fn) in stack:
            return False
        if id(fn) not in self._strong:
            hit = any(IDENT.findall(m.group(0))[-1] not in self.fns for m in STRONG_READER.finditer(fn.body))
            hit = hit or any(self.strong(c.key, stack + (id(fn),)) for _, c in self._callees(fn))
            self._strong[id(fn)] = hit
        return self._strong[id(fn)]

    def written_vars(self, name, stack=()):
        """Vars a tests/common helper writes (literal or const), ANY_VAR when unknown."""
        fn = self.fns.get(name)
        if fn is None:
            return {ANY_VAR}
        if id(fn) in stack:
            return set()
        if id(fn) not in self._vars:
            src, out = self.sources[id(fn)], set()
            for m in DIRECT_MUTATION.finditer(fn.body):
                out.add(src.arg_name(fn, m.end() - 1))
            for m, callee in self._callees(fn):
                if callee.owner in COMMON_GUARD_METHODS:
                    out.add(src.arg_name(fn, m.end() - 1))
                elif DIRECT_MUTATION.search(callee.body) or callee.owner is None:
                    out |= self.written_vars(callee.key, stack + (id(fn),))
            self._vars[id(fn)] = out
        return self._vars[id(fn)] or {ANY_VAR}


class FileModel:
    """Write sites, their protection sets, lock acquisitions and readers of one tests/*.rs."""

    def __init__(self, scrubbed, raw=None, common=None):
        self.common = common if common is not None else CommonModel()
        self.imports, self.glob = common_imports(scrubbed)
        scrubbed = blank_use_items(scrubbed)
        self.src = (Source(raw, self.common.src_consts) if raw is not None and len(raw) == len(scrubbed)
                    else Source(None))
        self.fns = parse_fns(scrubbed)
        self.tests = [f for f in self.fns if f.is_test and not f.ignored]
        self.mod_names = {m for f in self.fns for m in f.mods}
        self.by_key, self.by_method = {}, {}
        for f in self.fns:
            if f.is_test:
                continue
            self.by_key.setdefault(f.key, f)
            if f.owner:
                self.by_method.setdefault(f.name, []).append(f)
        self.once_fns = {id(f) for f in self.fns
                         if not f.is_test and ONCE_BODY.search(f.body) and DIRECT_MUTATION.search(f.body)}
        self._calls, self._acq, self._summary, self._ctx, self._live = {}, {}, {}, {}, {}
        self._encl, self._viol = {}, {}
        self.blamed = set()
        self.callers = {id(f): [] for f in self.fns}
        for f in self.fns:
            for pos, callee, _, method in self.calls(f):
                self.callers[id(callee)].append((f, pos, method))
        self._macro_callers(scrubbed)
        for f in self.fns:
            if f.name == "drop" and f.owner:
                # `impl Drop for T`: the drop runs in the scope that made the T, so the callers of
                # T's other fns (its constructors) are its callers.
                for g in self.fns:
                    if g.owner == f.owner and g is not f:
                        self.callers[id(f)].extend(self.callers[id(g)])
        self.sites = self._write_sites()
        self.site_at = {(id(s.fn), s.pos): s for s in self.sites}
        self.written = set()
        for s in self.sites:
            self.written |= s.names
        protected = [s for s in self.sites if s.protect]
        locked = [s for s in protected if any(not t.startswith(ONCE_PREFIX) for t in s.protect)]
        if locked:
            # (g) a Once setter is the lock only when every writer is one-time-gated; with a real
            # lock in play the Once sites are readers that must hold it, not a requirement.
            protected = locked
        if protected:
            self.required = [(s.index, s.protect, self.roots(s.fn)) for s in protected]
        else:
            # nobody locks: a reader is safe only from the writes of its own test
            self.required = [(s.index, EMPTY, self.roots(s.fn)) for s in self.sites]

    def _macro_callers(self, scrubbed):
        """A `macro_rules!` test template that calls `$f(..)` calls every same-file fn named in an
        invocation of that macro (or of a macro that forwards to it), holding what the template holds."""
        templates, forwards, spans = {}, {}, []
        for m in MACRO_RULES.finditer(scrubbed):
            start, end = m.end() - 1, match_brace(scrubbed, m.end() - 1)
            spans.append((start, end))
            body = scrubbed[start:end]
            sites = []
            for f in parse_fns(body):
                f.offset += start
                if not f.is_test:
                    continue
                for c in META_CALL.finditer(f.body):
                    sites.append((f, c.start()))
            templates[m.group(1)] = sites
            forwards[m.group(1)] = {c.group(1) for c in MACRO_CALL.finditer(body)} - {m.group(1)}

        def expand(name, seen):
            out = list(templates.get(name, ()))
            for nxt in forwards.get(name, ()):
                if nxt not in seen:
                    out.extend(expand(nxt, seen | {nxt}))
            return out

        free = {f.name: f for f in self.fns if not f.is_test and f.owner is None}
        for m in MACRO_CALL.finditer(scrubbed):
            if m.group(1) not in templates or any(a <= m.start() < b for a, b in spans):
                continue
            sites = expand(m.group(1), {m.group(1)})
            if not sites:
                continue
            args = scrubbed[m.end() - 1:match_paren(scrubbed, m.end() - 1)]
            for name in set(IDENT.findall(args)):
                if name in free:
                    for tfn, pos in sites:
                        self.callers[id(free[name])].append((tfn, pos, False))

    # ---- call graph -------------------------------------------------------------------------
    def resolve(self, owner, prefix, name):
        """Same-file non-test fn a path call refers to (free fn or Type::method), else None."""
        seg = path_segments(prefix)
        if seg:
            ty = owner if seg[-1] == "Self" else seg[-1]
            hit = self.by_key.get("%s::%s" % (ty, name))
            if hit:
                return hit
            if seg[-1] not in PATH_SELF and seg[-1] not in self.mod_names:
                return None
        return self.by_key.get(name)

    def calls(self, fn):
        """[(pos, callee, call_end, is_method)] for same-file calls in fn (not declarations)."""
        if id(fn) in self._calls:
            return self._calls[id(fn)]
        out, body = [], fn.body
        for m in CALL.finditer(body):
            before = body[max(0, m.start() - CALL_WINDOW):m.start()].rstrip()
            if re.search(r"\bfn$", before):
                continue
            method = before.endswith(".")
            if method:
                cands = self.by_method.get(m.group(2), [])
            else:
                hit = self.resolve(fn.owner, m.group(1), m.group(2))
                cands = [hit] if hit is not None else []
            end = match_paren(body, m.end() - 1)
            for c in cands:
                if c is not fn:
                    out.append((m.start(), c, end, method))
        self._calls[id(fn)] = out
        return out

    def external(self, fn):
        """[(pos, kind, token, open_idx, name)] for calls to tests/common env helpers and lock fns."""
        out, body = [], fn.body
        resolved = {pos for pos, _, _, method in self.calls(fn) if not method}
        for m in CALL.finditer(body):
            before = body[max(0, m.start() - CALL_WINDOW):m.start()].rstrip()
            if m.start() in resolved or before.endswith(".") or re.search(r"\bfn$", before):
                continue
            segs, name, open_idx = path_segments(m.group(1)), m.group(2), m.end() - 1
            ty = segs[-1] if segs else None
            if ty in COMMON_GUARD_METHODS and name in COMMON_GUARD_METHODS[ty] or name in COMMON_GUARD_FNS:
                out.append((m.start(), "guard", COMMON_ENV_LOCK, open_idx, name if ty is None else ty))
            elif ty == LOCAL_GUARD_TYPE:
                out.append((m.start(), "guard", LOCAL_GUARD_TYPE, open_idx, ty))
            elif name in ONCE_SETTERS:
                out.append((m.start(), "once", ONCE_PREFIX + name, open_idx, name))
            elif name == PG_ISOLATE_ONCE:
                out.append((m.start(), "once-writer", ONCE_PREFIX + name, open_idx, name))
            elif name == PG_ISOLATE_WRITER:
                out.append((m.start(), "writer", PG_ISOLATE_LOCK, open_idx, name))
            elif not segs and is_lock_fn_name(name) or segs and is_lock_fn_name(name) and "common" in segs:
                out.append((m.start(), "lock", name, open_idx, name))
            elif self._is_common_reader(segs, name):
                out.append((m.start(), "reader", None, open_idx, name))
        return out

    def _is_common_reader(self, segs, name):
        if name not in self.common.fns or self.common.fns[name].owner is not None:
            return False
        if not ("common" in segs or (not segs and (name in self.imports or self.glob))):
            return False
        return self.common.strong(name)

    # ---- acquisitions -----------------------------------------------------------------------
    def acquisitions(self, fn, stack=()):
        if id(fn) in self._acq:
            return self._acq[id(fn)]
        body, out = fn.body, []

        def add(pos, tokens, kind, end=None):
            if tokens:
                names = let_names(stmt_prefix(body, pos))
                out.append(Acq(pos, pos if end is None else end, frozenset(tokens), kind, bool(names), names))

        for m in LOCK_METHOD.finditer(body):
            add(m.start(), lock_tokens(stmt_prefix(body, m.start())), "lock")
        for pos, kind, token, _, _ in self.external(fn):
            if kind in ("guard", "lock"):
                add(pos, {token}, "lock")
            elif kind in ("once", "once-writer"):
                add(pos, {token}, "once")
        if id(fn) in self.once_fns:
            m = ONCE_BODY.search(body)
            paren = body.find("(", m.end())
            if paren >= 0:
                add(match_paren(body, paren), {ONCE_PREFIX + fn.key}, "once")
        inner = stack + (id(fn),)
        for pos, callee, end, _ in self.calls(fn):
            if id(callee) in inner:
                continue
            s = self.summary(callee, inner)
            add(pos, s.persist | ({ONCE_PREFIX + callee.key} if id(callee) in self.once_fns else EMPTY), "once")
            add(pos, s.ret, "lock")
            add(pos, s.work, "cover", end)
        out.sort(key=lambda a: a.pos)
        if not stack or id(fn) not in stack:
            self._acq[id(fn)] = out
        return out

    def summary(self, fn, stack=()):
        """What a same-file helper gives its caller: persist (Once tokens that stay held after it
        returns), ret (lock tokens of a guard it returns), work (tokens held while it works)."""
        if id(fn) in self._summary:
            return self._summary[id(fn)]
        if id(fn) in stack:
            return EMPTY_SUMMARY
        body = fn.body
        acqs = self.acquisitions(fn, stack)
        persist, ret = set(), set()
        for a in acqs:
            if a.kind == "once":
                persist |= a.tokens
            elif a.kind == "lock":
                if not a.bound:
                    expr = LET_HEAD.sub("", stmt_prefix(body, a.pos), count=1)
                    if is_tail(body, a.pos) or re.match(r"\s*return\b", expr) or re.match(r"\s*[A-Za-z_]\w*\s*:(?!:)", expr):
                        ret |= a.tokens
                elif self._escapes(body, a):
                    ret |= a.tokens
        last_calls = [m.start() for m in CALL.finditer(body)]
        work_pos = max(last_calls) if last_calls else len(body) - 1
        work = self.held_own(fn, work_pos, acqs)
        s = Summary(frozenset(persist), frozenset(ret), frozenset(work))
        self._summary[id(fn)] = s
        return s

    @staticmethod
    def _escapes(body, acq):
        """A bound guard that is used again (moved into a returned struct), not only dropped."""
        stmt_end = body.find(";", acq.pos)
        rest = body[stmt_end + 1:] if stmt_end >= 0 else ""
        for name in acq.names:
            rest_wo_drop = re.sub(r"\bdrop\s*\(\s*%s\s*\)" % re.escape(name), " ", rest)
            if re.search(r"(?<![\w.])%s\b(?!\s*:(?!:))" % re.escape(name), rest_wo_drop):
                return True
        return False

    def encloses(self, fn, a, r):
        key = (id(fn), a)
        if key not in self._encl:
            self._encl[key] = match_brace(fn.body, innermost_open(fn.body, a))
        return r < self._encl[key]

    def held_own(self, fn, r, acqs=None):
        """Tokens fn itself holds at body position r."""
        acqs = self.acquisitions(fn) if acqs is None else acqs
        held = set()
        for a in acqs:
            if a.kind == "cover":
                if a.pos <= r < a.end:
                    held |= a.tokens
                continue
            if a.pos >= r or not self.encloses(fn, a.pos, r):
                continue
            if a.kind == "once":
                held |= a.tokens
            elif a.bound and not any(re.search(r"\bdrop\s*\(\s*%s\s*\)" % re.escape(n), fn.body[a.pos:r])
                                     for n in a.names):
                held |= a.tokens
        if fn.serial:
            held.add(SERIAL_TOKEN)
        return held

    # ---- write sites ------------------------------------------------------------------------
    def ctx(self, fn, stack=()):
        """Tokens every same-file caller holds at its call of fn, up the whole call graph."""
        if fn.is_test:
            return frozenset({SERIAL_TOKEN}) if fn.serial else EMPTY
        if id(fn) in self._ctx:
            return self._ctx[id(fn)]
        if id(fn) in stack:
            return None
        edges = [e for e in self.callers[id(fn)] if not (e[0].is_test and e[0].ignored)]
        edges = [e for e in edges if not e[2]] or edges  # path calls first: a `.m()` may be another type's m
        res = None
        for caller, pos, _ in edges:
            c = self.ctx(caller, stack + (id(fn),))
            if c is None:
                continue
            held = frozenset(self.held_own(caller, pos)) | c
            res = held if res is None else res & held
        res = res if res is not None else EMPTY
        if not stack:
            self._ctx[id(fn)] = res
        return res

    def roots(self, fn, stack=()):
        """Ids of the non-ignored test fns that reach fn (fn itself when nothing calls it)."""
        if fn.is_test:
            return frozenset({id(fn)})
        out = set()
        for caller, _, _ in self.callers[id(fn)]:
            if id(caller) not in stack and not (caller.is_test and caller.ignored):
                out |= self.roots(caller, stack + (id(fn),))
        return frozenset(out) if out or stack else frozenset({id(fn)})

    def live(self, fn, stack=()):
        """False when fn runs only under `#[ignore]` tests (CI runs those one at a time)."""
        if fn.is_test:
            return not fn.ignored
        if id(fn) in self._live:
            return self._live[id(fn)]
        callers = self.callers[id(fn)]
        res = not callers or any(self.live(c, stack + (id(fn),)) for c, _, _ in callers if id(c) not in stack)
        if not stack:
            self._live[id(fn)] = res
        return res

    def _write_sites(self):
        sites = []

        def add(fn, pos, base, names):
            # A Once token protects only against its own setter's write: holding once:X says
            # nothing about a write that another setter (or an unlocked caller) makes.
            held = frozenset(self.held_own(fn, pos)) | self.ctx(fn)
            protect = frozenset(t for t in held if not t.startswith(ONCE_PREFIX)) | base
            sites.append(Site(len(sites), fn, pos, base, protect, frozenset(names)))

        for fn in self.fns:
            if not self.live(fn):
                continue
            once = frozenset({ONCE_PREFIX + fn.key}) if id(fn) in self.once_fns else EMPTY
            for m in DIRECT_MUTATION.finditer(fn.body):
                add(fn, m.start(), once, {self.src.arg_name(fn, m.end() - 1)})
            for pos, kind, token, open_idx, name in self.external(fn):
                if kind == "guard":
                    if name == "MultiEnvVarGuard":
                        names = self.src.literals(fn, open_idx)
                    elif name in COMMON_GUARD_METHODS:
                        names = {self.src.arg_name(fn, open_idx)}
                    else:
                        names = self.common.written_vars(name)
                    add(fn, pos, frozenset({token}), names)
                elif kind == "once-writer":
                    # isolated_url: get_or_init-gated AND published under ENV_LOCK (publish_env_within)
                    add(fn, pos, frozenset({token, PG_ISOLATE_LOCK}), self.common.written_vars(name))
                elif kind in ("once", "writer"):
                    add(fn, pos, frozenset({token}), self.common.written_vars(name))
        return sites

    # ---- readers ----------------------------------------------------------------------------
    def readers(self, fn):
        """[(pos, site or None)] of strong readers and of weak reads of a written var in fn."""
        body, out = fn.body, []
        for m in STRONG_READER.finditer(body):
            if IDENT.findall(m.group(0))[-1] not in self.by_key:
                out.append((m.start(), None))
        for m in DIRECT_MUTATION.finditer(body):
            out.append((m.start(), self.site_at.get((id(fn), m.start()))))
        for pos, kind, _, _, _ in self.external(fn):
            if kind in ("guard", "once-writer", "writer"):
                out.append((pos, self.site_at.get((id(fn), pos))))
            elif kind == "reader":
                out.append((pos, None))
        for m in WEAK_READER.finditer(body):
            j = m.end()
            while j < len(body) and body[j].isspace():
                j += 1
            name = ANY_VAR if m.group(0).endswith(("vars", "vars_os")) else self.src.arg_name(fn, j)
            if name == ANY_VAR or ANY_VAR in self.written or name in self.written:
                out.append((m.start(), None))
        return out

    def satisfied(self, held, site, root):
        ok = True
        for index, need, roots in self.required:
            if site is not None and index == site.index or roots <= {id(root)}:
                continue  # a test does not race its own writes
            if not need & held:
                ok = False
                if not need:
                    self.blamed |= roots - {id(root)}  # the unlocked writer is the other half of the race
        return ok

    def violates(self, fn, ctx, depth, stack=(), root=None):
        root = fn if root is None else root
        key = (id(fn), ctx, depth, id(root))
        if key in self._viol:
            return self._viol[key]
        res = False
        for pos, site in self.readers(fn):
            held = set(ctx) | self.held_own(fn, pos) | (site.base if site else EMPTY)
            if not self.satisfied(held, site, root):
                res = True
                break
        if not res and depth > 0:
            for pos, callee, _, _ in self.calls(fn):
                if id(callee) in stack:
                    continue
                held = frozenset(set(ctx) | self.held_own(fn, pos))
                if self.violates(callee, held, depth - 1, stack + (id(fn),), root):
                    res = True
                    break
        self._viol[key] = res
        return res


def violating_fns(scrubbed, raw=None, common=None):
    """Names (qualified) of violating test fns in one scrubbed file, or [] when the file is exempt."""
    model = FileModel(scrubbed, raw, common)
    if not model.required or len(model.tests) < 2:
        return []
    out = []
    for fn in model.tests:
        if fn.serial:
            continue
        if model.violates(fn, model.ctx(fn), HELPER_DEPTH):
            out.append(fn.qual)
    out.extend(fn.qual for fn in model.tests if id(fn) in model.blamed and not fn.serial)
    return sorted(set(out))


def scan_file(path, common=None):
    """Return the violating test fn names of an env-mutating, non-isolated file."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    if ISOLATED_MARKER.search(raw):
        return []
    return violating_fns(scrub(raw), raw, common)


def scan_tree(root):
    """Return the set of `<path>::<fn>` keys that violate the rule."""
    root = pathlib.Path(root)
    common = CommonModel(root)
    found = set()
    for path in sorted((root / TESTS_REL).glob("*.rs")):
        rel = path.relative_to(root).as_posix()
        found.update("%s::%s" % (rel, name) for name in scan_file(path, common))
    return found


def ignored_test_runs(workflows_dir):
    """[(workflow file, line, command)] for every cargo command in a workflow that runs #[ignore] tests.

    Continuation lines (`\\`) are joined; comments, step names and `--list` runs are skipped. The
    unit tests pin that every such run is single-threaded, which is what exempts #[ignore] fns.
    """
    out = []
    for path in sorted(pathlib.Path(workflows_dir).glob("*.yml")):
        cmd, first = [], 0
        for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            text = line.strip()
            if not cmd and (text.startswith("#") or re.match(r"-?\s*name\s*:", text)):
                continue
            if not cmd:
                first = lineno
            cmd.append(text.rstrip("\\").strip())
            if text.endswith("\\"):
                continue
            joined = " ".join(cmd)
            cmd = []
            if "cargo" in joined and WORKFLOW_IGNORED.search(joined) and "--list" not in joined:
                out.append((path.name, first, joined))
    return out


def read_baseline(path):
    out = set()
    if not path.exists():
        return out
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ".rs::" not in line:
            raise SystemExit("%s:%d: malformed baseline line (want <path>::<fn>): %r" % (path, lineno, line))
        out.add(line)
    return out


def render(found):
    return HEADER + "".join("%s\n" % key for key in sorted(found))


def compare(found, baseline):
    """Return problem lines: NEW (violating fn not in the baseline) and STALE (entry no longer violates)."""
    problems = []
    for key in sorted(found - baseline):
        problems.append("NEW   %s: test fn can race the env writers without their lock (not in baseline)" % key)
    for key in sorted(baseline - found):
        problems.append("STALE %s: no longer violates -- delete the baseline line" % key)
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=None, help="repo root (default: the repo holding this script)")
    ap.add_argument("--list", action="store_true", help="print current <path>::<fn> lines")
    ap.add_argument("--update-baseline", action="store_true", help="rewrite the baseline file")
    args = ap.parse_args(argv)
    root = pathlib.Path(args.root) if args.root else pathlib.Path(__file__).resolve().parents[1]
    found = scan_tree(root)
    baseline_path = root / BASELINE_REL
    if args.list:
        sys.stdout.write("".join("%s\n" % key for key in sorted(found)))
        return 0
    if args.update_baseline:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(render(found))
        print("wrote %s (%d entries)" % (BASELINE_REL, len(found)))
        return 0
    problems = compare(found, read_baseline(baseline_path))
    for line in problems:
        print(line, file=sys.stderr)
    if problems:
        print("check-test-env-mutation: FAIL (%d problem(s)); a racing test fn of an env-mutating "
              "tests/*.rs must hold the writers' env lock (#7347)" % len(problems), file=sys.stderr)
        return 1
    files = len({key.split("::", 1)[0] for key in found})
    print("check-test-env-mutation: ok (%d baselined fn(s) in %d file(s))" % (len(found), files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
