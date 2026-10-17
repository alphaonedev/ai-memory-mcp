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

Rule. A `tests/*.rs` is an env-mutating file when it calls `env::set_var` / `env::remove_var`
directly, or through a tests/common helper (EnvVarGuard::set/remove, MultiEnvVarGuard::apply,
ensure_no_config_env, permissive_attestation_for_tests, install_test_operator_key, isolated_url).
In such a file a `#[test]` / `#[tokio::test]` / `cfg_attr(.., test)` fn is VIOLATING when all hold:
  1. the file has at least two test fns (a single-test binary has nothing to race in-process);
  2. the file is not marked `// env-mutation-gate: process-isolated -- <reason>` and the fn has
     no `#[serial]` attribute;
  3. the fn can reach an env/C reader: its body (or a same-file fn it calls, ONE level) reads env,
     opens SQLite / a router / a config, or mutates env. Pure fns are exempt;
  4. it does not hold the writers' lock: a `let <name> = ...` binding (not `let _ = ...`, which
     drops at once) that lives for the fn body (brace depth 1), taken before the first such
     reader, on a lock the file's writers use (same static / fn name, e.g. `ENV_LOCK.lock()`,
     `.blocking_lock()`, `.lock().await`, `env_lock()`), or through a tests/common guard
     constructor, or a Once-gated setter called first, or a same-file helper (one level) that
     does so. An unrelated `.lock()` (`db.lock()`, `conn.lock()`) does not count.

Known limits, stated plainly:
  * helper resolution is one level deep and by name (free fns and `Type::method`); a lock taken
    two calls down, or in tests/common beyond the named guard constructors, is not seen;
  * the reader check is a token heuristic (db/router/config open, env reads, reqwest); a fn that
    reaches a C getenv only through code the tokens do not name is treated as pure;
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
import pathlib
import re
import sys

BASELINE_REL = "scripts/qc-allowlists/test-env-mutation-unlocked-baseline.txt"
TESTS_REL = "tests"
ISOLATED_MARKER = re.compile(r"^\s*//\s*env-mutation-gate:\s*process-isolated\b", re.M)
# Direct writers: env::set_var / remove_var, qualified or imported bare (not `fn set_var`, not `.set_var`).
DIRECT_MUTATION = re.compile(r"(?<![\w.])(?:(?:std::)?env::)?(?:set_var|remove_var)\s*\(")
# tests/common helpers that mutate the process env (all of them, see tests/common/mod.rs, pg_isolate.rs).
GUARD_CTORS = re.compile(
    r"\b(?:MultiEnvVarGuard\s*::\s*apply|EnvVarGuard\s*::\s*(?:set|remove)|EnvGuard\s*::\s*\w+|"
    r"install_test_operator_key)\s*\(")
ONCE_SETTERS = ("ensure_no_config_env", "permissive_attestation_for_tests")
WRITER_ONLY_HELPERS = re.compile(r"\b(?:isolated_url|publish_env_within)\s*\(")
ONCE_CALL_RE = re.compile(r"\b(?:%s)\s*\(" % "|".join(ONCE_SETTERS))
# STRONG readers reach a C getenv (the crash path): SQLite open (first-open unixTempFileInit),
# router / config build, network name resolution, local time. WEAK readers are Rust env reads, which
# std serialises with set_var (a logical race: stale or wrong value, not a crash).
STRONG_READER = re.compile(
    r"\b(?:db|storage)\s*::\s*open\w*|\bConnection\s*::\s*open\w*|\bopen_(?:db|store|conn|unmigrated)\w*|"
    r"\brusqlite\b|\bSqliteStore\b|\bfresh_(?:conn|db)\w*|\bdb_at\b|"
    r"\bAppConfig\s*::|\bConfig\s*::\s*load\w*|\bbuild_router\w*|\brouter\s*\(|"
    r"\breqwest\b|\bToSocketAddrs\b|\bLocal\s*::\s*now\b")
WEAK_READER = re.compile(r"\benv\s*::\s*var\w*")
FN_DECL = re.compile(r"\b(?:async\s+)?fn\s+([A-Za-z_]\w*)")
TEST_ATTR = re.compile(r"#\[\s*(?:[A-Za-z_]\w*::)*(?:test|test_case|rstest)\b")
CFG_ATTR = re.compile(r"#\[\s*cfg_attr\s*\(")
SERIAL_ATTR = re.compile(r"#\[\s*(?:[A-Za-z_]\w*::)*serial\b")
IDENT = re.compile(r"[A-Za-z_]\w*")
CALL = re.compile(r"((?:[A-Za-z_]\w*\s*::\s*)*)([A-Za-z_]\w*)\s*\(")
LOCK_METHOD = re.compile(r"\.\s*(?:blocking_lock|lock_owned|lock)\s*\(")
LET_BOUND = re.compile(r"^\s*let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=]*)?=(?!=)")
LET_TUPLE = re.compile(r"^\s*let\s+\(([^)]*)\)\s*(?::[^=]*)?=(?!=)")
CHAR_LIT = re.compile(r"'(?:\\.[^']{0,8}|[^\\'])'")
BLOCK_HEADER = re.compile(
    r"(?:(?<=[;{}\]])|^)\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:(mod)\s+([A-Za-z_]\w*)\s*\{|(impl)\b([^;{}]*)\{)")
HELPER_DEPTH = 3  # same-file helper levels followed when deciding what a fn reaches
LOCK_HELPER_DEPTH = 2  # same-file helper levels followed when looking for a lock the helper takes
GENERIC_NAMES = frozenset((
    "lock", "locks", "locked", "blocking_lock", "lock_owned", "try_lock", "into_inner", "unlock",
    "RwLock", "OnceLock", "LazyLock", "Mutex", "MutexGuard", "RwLockReadGuard", "RwLockWriteGuard",
    "PoisonError", "poison", "is_poisoned"))
LOCK_TYPE_NAMES = frozenset((
    "RwLock", "OnceLock", "LazyLock", "Mutex", "MutexGuard", "RwLockReadGuard", "RwLockWriteGuard",
    "PoisonError"))
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


class Fn:
    """One fn item: qualified name, owner type, attrs and the scrubbed body (starting at `{`)."""

    def __init__(self, name, mods, owner, attrs, body):
        self.name, self.mods, self.owner, self.attrs, self.body = name, mods, owner, attrs, body
        self.is_test = self._is_test(attrs)
        self.serial = bool(SERIAL_ATTR.search(attrs))

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
        start =max(scrubbed.rfind(";", 0, m.start()), scrubbed.rfind("}", 0, m.start()),
                    scrubbed.rfind("{", 0, m.start())) + 1
        attrs = scrubbed[start:m.start()]
        brace = scrubbed.find("{", m.end())
        semi = scrubbed.find(";", m.end())
        if brace < 0 or (0 <= semi < brace):
            continue
        mods = [b[3] for b in blocks if b[2] == "mod" and b[0] < m.start() < b[1]]
        owners = [b[3] for b in blocks if b[2] == "impl" and b[0] < m.start() < b[1]]
        fns.append(Fn(m.group(1), mods, owners[-1] if owners else None, attrs,
                      scrubbed[brace:match_brace(scrubbed, brace)]))
    return fns


def let_bound(prefix):
    """True when the statement is `let <name> = ..` or `let (a, _b) = ..` with a non-`_` binding.

    `let _ = guard;` drops the guard at once and does not count.
    """
    m = LET_BOUND.match(prefix)
    if m:
        return m.group(1) != "_"
    m = LET_TUPLE.match(prefix)
    return bool(m) and any(p.strip().replace("mut ", "").strip() not in ("", "_") for p in m.group(1).split(","))


def depth_at(body, pos):
    return body.count("{", 0, pos) - body.count("}", 0, pos)


def stmt_prefix(body, pos):
    """Text of the statement containing pos, from the previous `;`/`{`/`}` up to pos."""
    start = max(body.rfind(";", 0, pos), body.rfind("{", 0, pos), body.rfind("}", 0, pos)) + 1
    return body[start:pos]


def writer_locks(fn):
    """Lock names this fn (a direct env writer) holds: receivers of .lock() and lock-word calls."""
    names = set()
    body = fn.body
    for m in LOCK_METHOD.finditer(body):
        prefix = stmt_prefix(body, m.start())
        names.update(i for i in IDENT.findall(prefix) if is_lock_name(i))
        tail = re.search(r"([A-Za-z_]\w*)\s*(?:\([^()]*\)\s*)?$", prefix)
        if tail and re.fullmatch(r"[A-Z][A-Z0-9_]*", tail.group(1)):
            names.add(tail.group(1))  # a static such as ENV_LOCK; a db or conn receiver never qualifies
    for m in CALL.finditer(body):
        name = m.group(2)
        if body[max(0, m.start() - 1):m.start()] == ".":
            continue  # a method call such as `x.lock()` is handled above
        # A free fn named `lock` / `env_lock` / `forensic_lock` is a lock helper; the generic method
        # names are only excluded for the method form.
        if has_lock_word(name) and name not in LOCK_TYPE_NAMES and not name.startswith("_"):
            names.add(name)
    return names


class FileModel:
    def __init__(self, scrubbed):
        self.fns = parse_fns(scrubbed)
        self.tests = [f for f in self.fns if f.is_test]
        self.by_key = {}
        for f in self.fns:
            if not f.is_test:
                self.by_key.setdefault(f.key, f)
        writers = [f for f in self.fns if DIRECT_MUTATION.search(f.body)]
        self.has_writer = bool(writers) or any(
            GUARD_CTORS.search(f.body) or ONCE_CALL_RE.search(f.body) or WRITER_ONLY_HELPERS.search(f.body)
            for f in self.fns)
        self.locks = set()
        self.once_fns = set()
        # The lock may be held by the CALLER of the writer fn (the 2529 shape), so a fn that calls a
        # writer (one level) contributes its lock names too.
        writer_keys = {f.key for f in writers if not f.is_test}
        lock_sources = list(writers)
        for f in self.fns:
            if f not in writers and any(c.key in writer_keys for _, c in self._calls_unfiltered(f)):
                lock_sources.append(f)
        for f in lock_sources:
            self.locks |= writer_locks(f)
        for f in writers:
            if re.search(r"\b(?:call_once|get_or_init)\b", f.body):
                self.once_fns.add(f.name)

    def _calls_unfiltered(self, fn):
        for m in CALL.finditer(fn.body):
            if fn.body[max(0, m.start() - 1):m.start()] == ".":
                continue
            callee = self.resolve(fn.owner, m.group(1), m.group(2))
            if callee is not None and callee is not fn:
                yield m.start(), callee

    def resolve(self, owner, prefix, name):
        """Same-file non-test fn a call refers to (free fn or Type::method), else None."""
        seg = re.findall(r"[A-Za-z_]\w*", prefix)
        if seg:
            ty = owner if seg[-1] == "Self" else seg[-1]
            hit = self.by_key.get("%s::%s" % (ty, name))
            if hit:
                return hit
        return self.by_key.get(name)

    def calls(self, fn):
        """Yield (pos, callee Fn) for same-file calls in fn (skipping method calls and decls)."""
        for m in CALL.finditer(fn.body):
            before = fn.body[max(0, m.start() - 3):m.start()]
            if before.endswith(".") or re.search(r"\bfn\s*$", fn.body[max(0, m.start() - 4):m.start()]):
                continue
            callee = self.resolve(fn.owner, m.group(1), m.group(2))
            if callee is not None and callee is not fn:
                yield m.start(), callee

    def direct_acquisitions(self, fn, with_ctors):
        """(pos, bound_ok, depth1) of lock acquisitions made directly in fn's own body."""
        body, out = fn.body, []

        def add(pos, plain_ok=False):
            bound = let_bound(stmt_prefix(body, pos))
            out.append((pos, bound or plain_ok, depth_at(body, pos) == 1))

        for m in LOCK_METHOD.finditer(body):
            prefix = stmt_prefix(body, m.start())
            if any(i in self.locks for i in IDENT.findall(prefix)):
                add(m.start())
        for name in self.locks:
            if not has_lock_word(name):
                continue
            for m in re.finditer(r"(?<![\w.])%s\s*\(" % re.escape(name), body):
                add(m.start())
        if with_ctors and not self.locks:
            for m in GUARD_CTORS.finditer(body):
                add(m.start())
        for m in ONCE_CALL_RE.finditer(body):
            add(m.start(), plain_ok=True)
        for name in self.once_fns:
            for m in re.finditer(r"(?<![\w.])%s\s*\(" % re.escape(name), body):
                add(m.start(), plain_ok=True)
        return out

    def provides(self, fn, level, seen=()):
        """How a same-file fn gives its caller the writers' lock: 'inside', 'guard' or None.

        'inside': it takes the lock (or calls the Once setter) at its top level and holds it while it
        works. 'guard': it only returns a guard, so the caller must bind it. Resolution follows calls
        up to `level` further helpers (cycle-safe); beyond that the helper is not seen.
        """
        if fn.name in self.once_fns:
            return "inside"  # a Once-gated setter: callers that run it first read only after it is done
        acq = self.direct_acquisitions(fn, with_ctors=True)
        if any(bound and top for _, bound, top in acq):
            return "inside"
        if acq:
            return "guard"
        if level > 0:
            for pos, callee in self.calls(fn):
                if callee.key in seen or depth_at(fn.body, pos) != 1:
                    continue
                if self.provides(callee, level - 1, seen + (fn.key,)) == "inside":
                    return "inside"
        return None

    def reaches(self, fn, level, seen=()):
        """'strong', 'weak' or None: what env / C reader fn reaches, following calls `level` deep."""
        body = fn.body
        strong = DIRECT_MUTATION.search(body) or WRITER_ONLY_HELPERS.search(body) or any(
            IDENT.findall(m.group(0))[-1] not in self.by_key for m in STRONG_READER.finditer(body))
        if strong:
            return "strong"
        found = "weak" if WEAK_READER.search(body) else None
        if level > 0:
            for _, callee in self.calls(fn):
                if callee.key in seen or self.provides(callee, LOCK_HELPER_DEPTH):
                    continue
                got = self.reaches(callee, level - 1, seen + (fn.key,))
                if got == "strong":
                    return "strong"
                found = found or got
        return found

    def reader_positions(self, fn):
        """(strong, weak) positions in fn of tokens that read env or reach a C getenv.

        Same-file calls count up to HELPER_DEPTH levels deep. A token naming a same-file fn (for
        example a local `fresh_db()` that only builds a path) is judged by that fn's body.
        """
        body = fn.body
        strong = [m.start() for m in STRONG_READER.finditer(body)
                  if IDENT.findall(m.group(0))[-1] not in self.by_key]
        strong += [m.start() for m in DIRECT_MUTATION.finditer(body)]
        strong += [m.start() for m in WRITER_ONLY_HELPERS.finditer(body)]
        weak = [m.start() for m in WEAK_READER.finditer(body)]
        for p, callee in self.calls(fn):
            if self.provides(callee, LOCK_HELPER_DEPTH):
                continue  # a lock provider: what it does happens under the lock it takes
            got = self.reaches(callee, HELPER_DEPTH - 1, (fn.key,))
            if got == "strong":
                strong.append(p)
            elif got == "weak":
                weak.append(p)
        return strong, weak

    def holds_lock(self, fn, first_reader):
        """True when fn holds the writers' lock (depth 1, bound, before first_reader)."""
        for pos, bound, top in self.direct_acquisitions(fn, with_ctors=True):
            if bound and top and pos < first_reader:
                return True
        for pos, callee in self.calls(fn):
            if pos >= first_reader or depth_at(fn.body, pos) != 1:
                continue
            kind = self.provides(callee, LOCK_HELPER_DEPTH, (fn.key,))
            if kind == "inside" or (kind == "guard" and let_bound(stmt_prefix(fn.body, pos))):
                return True
        return False


def violating_fns(scrubbed):
    """Names (qualified) of violating test fns in one scrubbed file, or [] when the file is exempt."""
    model = FileModel(scrubbed)
    if not model.has_writer or len(model.tests) < 2:
        return []
    out = []
    for fn in model.tests:
        if fn.serial:
            continue
        strong, weak = model.reader_positions(fn)
        if not strong and not weak:
            continue
        # Before a C reader the lock must already be held; a fn that only reads Rust env may take
        # the lock anywhere at depth 1 (std serialises the read itself).
        if model.holds_lock(fn, min(strong) if strong else len(fn.body)):
            continue
        out.append(fn.qual)
    return sorted(set(out))


def scan_file(path):
    """Return the violating test fn names of an env-mutating, non-isolated file."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    if ISOLATED_MARKER.search(raw):
        return []
    return violating_fns(scrub(raw))


def scan_tree(root):
    """Return the set of `<path>::<fn>` keys that violate the rule."""
    found = set()
    for path in sorted((root / TESTS_REL).glob("*.rs")):
        rel = path.relative_to(root).as_posix()
        found.update("%s::%s" % (rel, name) for name in scan_file(path))
    return found


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
