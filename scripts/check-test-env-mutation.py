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
  * locks credited ONLY in the CANONICAL shape (see below), earlier in the fn than the write:
    `ENV_LOCK.lock()`, `.blocking_lock()`, `.lock().await`, `env_lock()`, a same-file helper that
    returns a guard (the helper shape below), a tests/common guard;
  * the locks every same-file caller holds at its call, intersected over the callers and followed
    up the whole same-file call graph (the issue_4357 shape: the writer is two calls below the
    test that holds SERIAL);
  * `once:<setter>` for a Once-gated setter: after that setter returns its write never happens
    again, so a caller that ran it first cannot race it;
  * `#[serial]` / `#[serial(<key>)]` for a serial test, one token per key: serial_test excludes a
    serial test only from other serial tests with the same key, so it protects a reader only when
    every writer it races is serial with that key too.
A write site is a direct write in a fn body, or an invocation `name!(..)` of a same-file
`macro_rules!` whose body writes the environment (or forwards to one that does); the locks that
macro body binds before its write are part of the site's protection.
A write site inside an `#[ignore]` test, or reachable only from ignored tests, is skipped: CI runs
ignored tests one at a time (`--test-threads=1` in postgres-ignored.yml, coverage.yml and
cert-postgres-age.yml; `--exact` in token-budget.yml; pinned by a unit test).

Rule. In an env-mutating file with at least two non-ignored test fns (a single-test binary has
nothing to race in-process) that is not marked `// env-mutation-gate: process-isolated -- <reason>`
(a whole-line `//` comment with a non-empty reason; the text inside a string or a block comment
does not count), a non-ignored test fn is VIOLATING when one of its READERS, or one in a same-file
fn or method it calls (followed HELPER_DEPTH levels, closures and loops included), is reached
without holding, at that point, one token of EVERY write site's protection set. Write sites with
an empty set (an unlocked writer) are not required of the readers, because the unlocked writer is
itself flagged; when no write site has any protection, every reader is flagged. Readers are:
  * strong (a C getenv or a write): SQLite / store / router / config open (`AppConfig::` except a
    derived `AppConfig::default()`), a `cli::<cmd>::run*` command, `reqwest` (unless IP-only), `sqlx`,
    `PgPool`, `postgres_url()`, DNS (`ToSocketAddrs`), `Local::now`, a tests/common helper that
    reaches one of those (computed from tests/common), and every write site;
  * weak (a Rust env read, a logical race): `env::var*` of a variable some write site writes.
    A variable name is a literal or a same-file `const`, or a parameter, a `for` variable over a
    parameter or a `self.<field>` set from a parameter, resolved through every same-file call
    (a `.name(..)` method call never reaches an associated fn without `self`); an unknown name
    counts as every variable. `use` items are not readers.
A token is held when it is acquired before the reader in a block that encloses it; a lock helper
that holds the lock while it works (`with_env_lock(|| ..)`) covers only its own call.

Canonical shape (#7623-#7627; the only way a lock is credited, everything else fails closed):

    let [mut] <name> = <KNOWN_LOCK_EXPR>;        // directly in the top-level block of the test fn

where <name> is a plain identifier (`_guard` is fine, a lone `_` is not), the statement comes before
the first env write, and <name> is NEVER mentioned again anywhere after it: no `drop`, move, match,
field access, return, shadowing, reassignment or closure capture. KNOWN_LOCK_EXPR is a plain receiver
path ending in a lock call (`ENV_LOCK.lock().await`, `ENV_LOCK.blocking_lock()`, `env_lock()`,
`Type::set(..)` of a tests/common guard) followed only by guard-preserving calls (GUARD_CHAIN: `lock`,
`unwrap`, `expect`, `unwrap_or_else`, `await`); a `lock()` / `lock_owned()` must go on with `.await` (tokio) or an
unwrap / expect / `?` (std), because an unawaited tokio lock is a future and holds nothing (#7992). The
gate does not model Rust moves or drops: a guard
the test touches again, a lock in a nested block or a loop body, a tuple pattern, a struct field, a
guard returned through a binding or a `match` is simply not credited. To restructure such a test, move
the body of the loop into a fn that takes the lock canonically, or end the lock's life with the fn.
Two named exceptions exist and nothing else: the tuple helper `let (<key>, <guard>) =
install_test_operator_key();` (TUPLE_GUARD_SLOTS, judged on the guard slot) and the HELPER shape: a
non-test fn that does `let <lock> = <KNOWN_LOCK_EXPR>;` at its top level and mentions <lock> exactly
once more, as a field initialiser of the struct literal that is its tail expression (`Self { prev,
_lock: lock }`) or, as the second named helper shape (#7993), a non-test fn whose whole top-level tail or
`return` value IS the lock expression (`fn env_lock() -> MutexGuard<..> { LOCK.get_or_init(..).lock()
.unwrap_or_else(..) }`); the caller is credited only through its own canonical `let _g = helper();`.
A Once setter (or a same-file fn that persists one) is credited only as a statement, or the whole initialiser
of a `let`, of its block (#7995): not inside an unbraced closure, behind `#[cfg(..)]` or in
any wrapping expression. A closure or async block handed to `spawn` / `spawn_blocking` (#7994) runs detached: it inherits no
lock of the spawner, of its callers or of `#[serial]`. Open the connection or read the env before the
spawn, on the test thread, and move the result into the closure.
A same-file fn that hands one of its parameters to a spawn (#8044), directly, through a closure it binds, or
through another such fn, is a detaching helper: the argument of every call of it runs detached.
A closure variable or fn item rebound with `let g = f;` before the spawn is followed to a fixpoint (#8045),
bounded by MAX_REBIND_HOPS; a longer chain is flagged, never cleared.
A macro_rules! whose body invokes a spawning macro, or a detaching helper, detaches too (#8046): the
forwarding is closed transitively.
In a `macro_rules!` body (a template, not a fn) the statement may sit in any block that encloses the
macro's first env write.

Reader classification for network clients (#7526). A `reqwest` client with rustls reads only Rust-side
env, and a request to an IP-literal URL never calls getaddrinfo, so `reqwest` is a strong reader
only when the file is not IP-only: a file is IP-only when it has IP evidence (`scheme://<ipv4|[ipv6]>`
or `local_addr()`) and no hostname URL, `localhost`, `.resolve(..)` or resolver word, and no URL whose
host is a placeholder without a `local_addr()` in the file. Anything unresolved stays a reader.

Known limits, stated plainly:
  * resolution is by name, same file only (free fns, `Type::method`, `.method()` on any same-file
    impl), plus the tests/common reader census; code in src/ is judged only by the tokens above;
  * the reader check is a token heuristic; a fn that reaches a C getenv only through code the
    tokens do not name is treated as pure;
  * a held-but-flagged shape stays flagged by design (#7628): a lock the test mentions again is not
    credited even when the mention is harmless; rewrite it to the canonical shape;
  * a reader behind a runtime branch still counts (the child half of a re-exec test that returns
    early unless its marker variable is set);
  * macro-generated test fns and env writes in tests/<dir>/ sub-modules are not seen; a writer
    macro is followed only when it is a `macro_rules!` of the same file;
  * a struct literal is told from a block by its head (a CamelCase path after `=`, `(`, `,`, `:`,
    `|`, `=>` or at a statement start, and no `if`/`while`/`match`/`for` in the statement).

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
# #7384: matched only at the start of a real `//` line comment, and a reason after `--` is required.
ISOLATED_MARKER = re.compile(r"//[ \t]*env-mutation-gate:[ \t]*process-isolated[ \t]*--[ \t]*\S")
# #7383: a raw string, raw byte string (`br`) or raw C string (`cr`) opener.
RAW_STR_OPEN = re.compile(r'(?:[bc]?r)(#*)"')
# Direct writers: env::set_var / remove_var, qualified or imported bare (not `fn set_var`, not `.set_var`).
# #7996: also the libc writers, a turbofish (`set_var::<&str, &str>(..)`) and a bare mention of the fn as a
# value (`let f = set_var;`, no call parenthesis): such a pointer can be called anywhere, so it is a write of
# an unknown var. `use .. set_var as sv;` aliases are added per file by mutation_re.
MUTATION_NAMES = ("set_var", "remove_var", "setenv", "unsetenv", "putenv", "clearenv")


def mutation_re(aliases=()):
    names = "|".join(re.escape(n) for n in MUTATION_NAMES + tuple(sorted(aliases)))
    return re.compile(r"(?<![\w.])(?:(?:std::)?env::|libc::)?(?:%s)\b(?:\s*::\s*<[^;{}]*?>)?(?:\s*\()?" % names)


def use_aliases(scrubbed):
    """Names a file imports a writer under: `use std::env::set_var as sv;` / `{remove_var as rv, ..}`.

    An alias of an alias (`use sv as sv2;`, #8037) is a writer too, in any order of the `use` items:
    the set grows until no `use` item adds a name.
    """
    items = [item.group(0) for item in USE_ITEM.finditer(scrubbed)]
    out = set()
    while True:
        known = "|".join(re.escape(n) for n in MUTATION_NAMES + tuple(sorted(out)))
        found = {m.group(1) for item in items for m in re.finditer(MUTATION_ALIAS % known, item)}
        if found <= out:
            return out
        out |= found


MUTATION_ALIAS = r"\b(?:%s)\s+as\s+([A-Za-z_]\w*)"
DIRECT_MUTATION = mutation_re()
# #7994: a call that hands its argument to another thread or task. The closure or async block it takes
# runs outside the spawner's guard scope (the handle may outlive the guard), so it never inherits a lock.
DETACH = re.compile(r"(?<![\w])(?<!fn )(?:spawn|spawn_blocking|spawn_local|spawn_on|spawn_pinned|"
                    r"spawn_unchecked|spawn_scoped)\s*(?:::\s*<[^;{}]*?>\s*)?\(")
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
SERIAL_TOKEN = "#[serial:%s]"  # one token per serial_test key ("" for a bare #[serial])
ANY_VAR = "*"
ONCE_BODY = re.compile(r"\b(?:call_once|get_or_init)\b")
# STRONG readers reach a C getenv (the crash path): SQLite open (first-open unixTempFileInit),
# router / config build, network name resolution (reqwest, sqlx, PgPool, a Postgres connect), local time. WEAK readers
# are Rust env reads, which std serialises with set_var (a logical race: stale or wrong value).
STRONG_READER = re.compile(
    r"\b(?:db|storage)\s*::\s*open\w*|\bConnection\s*::\s*open\w*|\bopen_(?:db|store|conn|unmigrated)\w*|"
    r"\bSqliteStore\s*::|\bfresh_(?:conn|db)\w*|\bdb_at\b|"
    r"\bAppConfig\s*::(?!\s*default\s*\()|\bConfig\s*::\s*load\w*|"
    r"\bcli\s*::\s*(?:[A-Za-z_]\w*\s*::\s*)*run\w*\s*\(|\bbuild_router\w*|\brouter\s*\(|"
    r"\bsqlx\s*::\s*(?:[A-Za-z_]\w*\s*::\s*)*(?:Pg\w*|connect\w*)|\bPgPool\w*|\b(?:PostgresStore|PgConnection)\s*::\s*connect\w*|\btokio_postgres\s*::\s*connect\w*|"
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
# #8033: `let [mut] <name> [: T] = [async] [move] |..| ..` / `async [move] { .. }`: the initialiser starts at the match end
CLOSURE_LET = r"\blet\s+(?:mut\s+)?%s\b[^=;]*=\s*(?:async\b\s*(?:move\b\s*)?|move\b\s*)?(?=\||\{)"
FN_VALUE = re.compile(r"\s*((?:[A-Za-z_]\w*\s*::\s*)*)([A-Za-z_]\w*)\s*,?\s*")
MACRO_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*!\s*[({\[]")
META_CALL = re.compile(r"\$([A-Za-z_]\w*)\s*\(")
# #8045: `let [mut] <name> [: T] = [&] [path::]<ident>;` -- a plain rebinding of a closure variable or fn item
REBIND_LET = r"\blet\s+(?:mut\s+)?%s\b\s*(?::[^=;]*)?=\s*(?:&\s*)?((?:[A-Za-z_]\w*\s*::\s*)*)([A-Za-z_]\w*)\s*;"
MAX_REBIND_HOPS = 8  # #8045: rebinding steps followed from a spawn argument; a longer chain flags the whole fn
ANY_CLOSURE_LET = CLOSURE_LET % r"[A-Za-z_]\w*"  # every closure or async-block `let` initialiser of a fn
# #7623-#7627: the canonical guard binding (see the module docstring). Nothing models moves or drops.
LET_PAIR = re.compile(r"^\s*let\s+\(\s*(?:mut\s+)?([A-Za-z_]\w*)\s*,\s*(?:mut\s+)?([A-Za-z_]\w*)\s*\)\s*(?::[^=]*)?=(?!=)")
# The ONE tuple helper shape the tree uses: `let (<key>, <guard>) = install_test_operator_key();`
# (tests/common returns `(SigningKey, EnvVarGuard)`); the value is the 0-based slot of the guard.
TUPLE_GUARD_SLOTS = {"install_test_operator_key": 1}
# Method calls allowed after the lock call in a canonical initialiser: they keep the guard a guard.
GUARD_CHAIN = frozenset(("lock", "blocking_lock", "lock_owned", "unwrap", "expect", "unwrap_or_else", "await"))
# What may sit between `=` and the lock call: a plain receiver path (`ENV_LOCK`, `env_lock()`, `a::b().c`).
RECEIVER_TEXT = re.compile(r"[\w\s:.()]*")
# #7526: a reqwest client reads only Rust-side env, and a request to an IP-literal URL skips getaddrinfo.
REQWEST = re.compile(r"\breqwest\b")
URL_LIT = re.compile(r"\b[a-z][a-z0-9+.-]*://([^/?#\s\"]*)")
RESOLVER_WORDS = re.compile(r"\.\s*resolve(?:_to_addrs)?\s*\(|\bresolver\b|\bdns_resolver\b|\blocalhost\b", re.IGNORECASE)
IP_HOST = re.compile(r"\[[0-9a-fA-F:.]+\]|\d{1,3}(?:\.\d{1,3}){3}")
URL_PLACEHOLDER_HOST = re.compile(r"\{[^{}]*\}")
# #8036: the one canonical `local_addr()` shape: `<path>.local_addr()` plus `.unwrap()`, `.expect(..)` or `?`.
LOCAL_ADDR_CALL = re.compile(
    r"[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*\s*\.\s*local_addr\s*\(\s*\)"
    r"(?:\s*\?|\s*\.\s*unwrap\s*\(\s*\)|\s*\.\s*expect\s*\([^()]*\))*")
BLOCK_KEYWORDS = re.compile(r"\b(?:if|while|match|for|loop|impl|fn|struct|enum|union|trait|mod|where)\b")
STRUCT_LIT_HEAD = re.compile(
    r"(?:^|[=(,:\[|]|=>|\breturn)\s*(?:[A-Za-z_]\w*\s*::\s*)*[A-Z]\w*(?:\s*::\s*<[^;{}]*>)?\s*$")
WORKFLOW_IGNORED = re.compile(r"--(?:include-)?ignored\b")
HEADER = (
    "# scripts/qc-allowlists/test-env-mutation-unlocked-baseline.txt -- issue #7347 ratchet.\n"
    "#\n"
    "# Format: <path>::<test fn>   (one line per violating fn; <path>::<mod>::<fn> in a nested module)\n"
    "#\n"
    "# A test fn of a tests/*.rs that mutates the process environment must hold the lock its\n"
    "# writers use when it can reach an env / C getenv reader (see scripts/check-test-env-mutation.py).\n"
    "# The lock is credited only in the canonical shape: `let _guard = <lock>;` directly in the test fn's\n"
    "# top-level block, before the first env write, and never mentioned again. Anything else fails closed.\n"
    "# An entry that no longer violates must be removed: the list may only shrink.\n"
    "# Regenerate with: scripts/check-test-env-mutation.py --update-baseline\n"
)

Acq = collections.namedtuple("Acq", "pos end tokens kind bound names")
Site = collections.namedtuple("Site", "index fn pos base protect names")
Summary = collections.namedtuple("Summary", "persist ret work")
EMPTY = frozenset()
EMPTY_SUMMARY = Summary(EMPTY, EMPTY, EMPTY)


def scrub(src, line_comments=None):
    """Blank comments, string and char literals (newlines kept) so braces and idents are real.

    Raw strings take every prefix Rust has (`r`, `br`, `cr`, any number of `#`); byte and C strings
    (`b".."`, `c".."`) and byte chars (`b'.'`) scrub like ordinary ones. When line_comments is a
    list, the (start, end) span of every real `//` comment is appended to it.
    """
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            if line_comments is not None:
                line_comments.append((i, j))
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
        elif c in "rbc" and RAW_STR_OPEN.match(src, i) and (i == 0 or not src[i - 1].isalnum() and src[i - 1] != "_"):
            opener = RAW_STR_OPEN.match(src, i)
            end = '"' + opener.group(1)
            j = src.find(end, opener.end())
            j = n if j < 0 else j + len(end)
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif (c == "c" and src[i + 1:i + 2] == '"' or c == "b" and src[i + 1:i + 2] in ('"', "'")) and (
                i == 0 or not src[i - 1].isalnum() and src[i - 1] != "_"):
            out.append(" ")  # the b / c prefix of a byte or C literal; the literal scrubs next
            i += 1
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


def stmt_end(text, start):
    """Index of the `;` that ends the expression starting at `start` (depth 0), or of its enclosing close."""
    depth = 0
    for j in range(start, len(text)):
        ch = text[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return j
            depth -= 1
        elif ch == ";" and depth == 0:
            return j
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


def open_of(body, close_idx):
    """Index of the `{` matched by the `}` at close_idx, or -1."""
    depth = 0
    for j in range(close_idx, -1, -1):
        ch = body[j]
        if ch == "}":
            depth += 1
        elif ch == "{":
            depth -= 1
            if depth == 0:
                return j
    return -1


def is_struct_literal(body, brace):
    """True when the `{` at brace opens a struct literal (`Holder { .. }`), not a block (#7390)."""
    if brace <= 0:
        return False
    prefix = stmt_prefix(body, brace)
    return not BLOCK_KEYWORDS.search(prefix) and bool(STRUCT_LIT_HEAD.search(prefix))


def scope_open(body, pos):
    """The `{` of the block that scopes a value made at pos: struct literal braces are skipped."""
    brace = innermost_open(body, pos)
    while brace > 0 and is_struct_literal(body, brace):
        brace = innermost_open(body, brace)
    return brace


def expr_end(body, pos):
    """Index where the expression starting at pos ends: a `,` / `;` or an unmatched closer at depth 0."""
    depth = 0
    for j in range(pos, len(body)):
        ch = body[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return j
            depth -= 1
        elif ch in ",;" and depth == 0:
            return j
    return len(body)


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

    def __init__(self, name, mods, owner, attrs, body, offset, is_async=False):
        self.name, self.mods, self.owner, self.attrs, self.body = name, mods, owner, attrs, body
        self.is_async = is_async
        self.offset = offset
        self.params, self.has_self = (), False  # #8044: parameter names (None = pattern), receiver apart
        self.is_test = self._is_test(attrs)
        self.serial_tokens = self._serial_tokens(attrs)
        self.serial = bool(self.serial_tokens)
        self.ignored = self.is_test and bool(IGNORE_ATTR.search(attrs))

    @staticmethod
    def _serial_tokens(attrs):
        """One SERIAL_TOKEN per serial_test key of `#[serial]` / `#[serial(a, b)]` (#7386)."""
        out = set()
        for m in SERIAL_ATTR.finditer(attrs):
            rest = attrs[m.end():].lstrip()
            keys = []
            if rest.startswith("("):
                args = rest[1:match_paren(rest, 0) - 1]
                keys = [k.strip() for k in args.split(",") if k.strip() and "=" not in k]
            out.update(SERIAL_TOKEN % k for k in (keys or [""]))
        return frozenset(out)

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
        fn = Fn(m.group(1), mods, owners[-1] if owners else None, attrs,
                scrubbed[brace:match_brace(scrubbed, brace)], brace, m.group(0).startswith("async"))
        fn.params, fn.has_self = fn_params(scrubbed, m.end(), brace)
        fns.append(fn)
    return fns


def split_top_level(text, start, end):
    """[(start, end)] of the comma separated items of text[start:end] at bracket depth 0 (#8044). A `|..|`
    closure parameter list that opens an item is skipped whole; the `>` of `->` is not a bracket."""
    out, depth, j, first = [], 0, start, start
    while j < end:
        ch = text[j]
        if ch == "-" and text[j + 1:j + 2] == ">":
            j += 1
        elif ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        elif ch == "|" and depth == 0 and (not text[first:j].strip() or re.search(r"\bmove\s*$", text[first:j])):
            j = text.find("|", j + 1)
            if j < 0:
                break
        elif ch == "," and depth == 0:
            out.append((first, j))
            first = j + 1
        j += 1
    if text[first:end].strip():
        out.append((first, end))
    return out


def fn_params(text, name_end, brace):
    """((names), has_self) of the fn whose name ends at name_end and whose body opens at brace (#8044)."""
    k = name_end
    while k < brace and text[k].isspace():
        k += 1
    if text[k:k + 1] == "<":
        depth = 0
        while k < brace:
            if text[k] == "-" and text[k + 1:k + 2] == ">":
                k += 1
            elif text[k] == "<":
                depth += 1
            elif text[k] == ">":
                depth -= 1
                if not depth:
                    k += 1
                    break
            k += 1
    while k < brace and text[k].isspace():
        k += 1
    if text[k:k + 1] != "(":
        return (), False
    names, has_self = [], False
    for a, b in split_top_level(text, k + 1, match_paren(text, k) - 1):
        piece = text[a:b]
        if re.match(r"\s*(?:&\s*(?:'\w+\s*)?)?(?:mut\s+)?self\b", piece):
            has_self = True
            continue
        m = re.match(r"\s*(?:mut\s+)?([A-Za-z_]\w*)\s*:", piece)
        names.append(m.group(1) if m else None)
    return tuple(names), has_self


def let_names(prefix):
    """[name] for a plain `let [mut] <name> [: T] =` statement prefix, else [].

    Only a single identifier counts. A tuple, struct or slice pattern binds nothing here. A lone `_`
    is no binding, and what it does depends on the right-hand side (#7628): `let _ = LOCK.call();`
    drops a temporary at the end of the statement, but `let _ = g;` names a place, does not move
    `g` and leaves the guard held (the gate still does not credit it, because `g` is mentioned
    again). `_guard` style names are bindings.
    """
    m = LET_BOUND.match(prefix)
    if m and m.group(1) != "_":
        return [m.group(1)]
    return []


def mask_brackets(text):
    """text with every character inside (), [] or {} blanked, so only depth-0 syntax remains."""
    out, depth = [], 0
    for ch in text:
        if ch in "([{":
            out.append(ch if depth == 0 else " ")
            depth += 1
        elif ch in ")]}":
            depth = max(depth - 1, 0)
            out.append(ch if depth == 0 else " ")
        else:
            out.append(ch if depth == 0 else " ")
    return "".join(out)


def balanced(text):
    """True when every bracket opened in text is closed in it."""
    depth = 0
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


PLACEHOLDER = re.compile(r"\{([^{}:]*)(?::[^{}]*)?\}")
LET_INIT = r"\blet\s+(?:mut\s+)?%s\b[^=;]*=\s*([^;]*);"
IP_STR = re.compile(r"\"(\[[0-9a-fA-F:.]+\]|\d{1,3}(?:\.\d{1,3}){3})\"")


def format_args(text, end):
    """Top-level comma-separated args of the macro call whose literal closes just before `end`."""
    depth, cur, out, i = 1, [], [], end
    while i < len(text) and depth:
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if not depth:
                break
        if ch == "," and depth == 1:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    out.append("".join(cur).strip())
    return [a for a in out if a]


def rebound(text, name, sig):
    """True when `name` is bound by anything other than a plain `let` of the fn body (#8035).

    A parameter of the fn (sig), a `for` variable, a closure parameter, a `let` or `match` pattern or an
    `@` binding shadows or replaces the plain `let`, so which value reaches the use site is undecidable
    here and the caller fails closed.
    """
    n = re.escape(name)
    shapes = (
        r"\bfor\s+[^{;]*?\b%s\b[^{;]*?\bin\b" % n,
        r"\|[^|{};]*\b%s\b[^|{};]*\|" % n,
        r"\blet\s+(?!(?:mut\s+)?%s\s*[:=])[^=;]*?\b%s\b" % (n, n),
        r"\(\s*[^()]*\b%s\b[^()]*\)\s*(?:if\b[^=]*)?=>" % n,
        r"\b%s\s*(?:@|=>)" % n,
    )
    return bool(re.search(r"(?<![\w.])%s\b" % n, sig)) or any(re.search(x, text) for x in shapes)


def ip_expr(expr, text, at=0, sig="", depth=0):
    """True when expr is an IP literal, the canonical `local_addr()` call, or a `let` of the same fn that
    precedes the use at `at` and is bound to one (#7997, #8035, #8036). Anything else fails closed."""
    expr = expr.strip().lstrip("&").strip()
    if LOCAL_ADDR_CALL.fullmatch(expr) or IP_STR.fullmatch(expr):
        return True
    if depth < 4 and re.fullmatch(r"[A-Za-z_]\w*", expr):
        if rebound(text, expr, sig):
            return False
        inits = [mm for mm in re.finditer(LET_INIT % re.escape(expr), text) if mm.start() < at]
        return bool(inits) and all(ip_expr(mm.group(1), text, mm.start(), sig, depth + 1) for mm in inits)
    return False


def url_host_is_ip(text, m, sig=""):
    """True when the URL literal matched at m names an IP host: an IP literal, or one placeholder that data
    flows from `local_addr()` or an IP literal (#7997). `sig` is the signature of the fn holding `text`.
    Anything else fails closed."""
    host = m.group(1).rsplit("@", 1)[-1]
    bare = re.sub(r"(?<=\]|\d|\}):\d+$", "", host)
    if IP_HOST.fullmatch(bare):
        return True
    ph = PLACEHOLDER.fullmatch(bare)
    if not ph:
        return False
    open_q = text.rfind('"', 0, m.start())
    close = text.find('"', m.end())
    if open_q < 0 or close < 0:
        return False
    args = format_args(text, close + 1)
    literal = text[open_q + 1:close]
    name = ph.group(1).strip()
    if name == "" or name.isdigit():
        if name:
            index = int(name)
        else:
            before = literal[:m.start() - (open_q + 1)]
            index = len([p for p in PLACEHOLDER.finditer(before) if p.group(1).strip() == ""])
        return index < len(args) and ip_expr(args[index], text, m.start(), sig)
    for arg in args:
        named = re.fullmatch(r"%s\s*=\s*(.*)" % re.escape(name), arg, re.DOTALL)
        if named:
            return ip_expr(named.group(1), text, m.start(), sig)
    return ip_expr(name, text, m.start(), sig)


def ip_only_text(raw, sig=""):
    """True when raw source text (one fn) reaches the network only through IP hosts (#7526, #7997).

    A reqwest client with rustls reads Rust-side env only, and a request to an IP literal never calls
    getaddrinfo, so no C getenv is reachable. Every URL literal must name an IP host: an IP literal, or a
    single `{..}` placeholder whose value (a positional or named format argument, or a same-text `let`)
    comes from `local_addr()` or an IP literal. `local_addr(` elsewhere in the text is not evidence. No URL
    literal at all, a hostname, `localhost`, a resolver word, a scheme placeholder or any other host shape
    keeps the reader.
    """
    return ip_only_parts([(raw, sig)])


def ip_only_parts(parts):
    """ip_only_text over [(raw, signature)] of several fns: each URL literal is judged inside its own fn (#8035),
    so a binding of another fn is no evidence. At least one URL literal must exist in all the parts together."""
    total = 0
    for raw, sig in parts:
        if raw is None or RESOLVER_WORDS.search(raw):
            return False
        for m in URL_LIT.finditer(raw):
            total += 1
            if not url_host_is_ip(raw, m, sig):
                return False
    return total > 0


AWAIT_OR_UNWRAP = frozenset(("await", "unwrap", "expect", "unwrap_or_else"))


def guard_materialised(body, pos, end):
    """False for a tokio `.lock()` / `.lock_owned()` that is never awaited (#7992).

    On a tokio mutex `lock` and `lock_owned` return a future: `let _g = ENV_LOCK.lock();` binds the
    future and holds nothing. The initialiser must go on with `.await` (tokio) or `.unwrap()` /
    `.expect(..)` / `.unwrap_or_else(..)` / `?` (a std lock). `blocking_lock` and a lock fn call
    (`env_lock()`) are not affected.
    """
    text = body[pos:end]
    first = re.match(r"\.\s*([A-Za-z_]\w*)", text)
    if not first or first.group(1) not in ("lock", "lock_owned"):
        return True
    names = set(re.findall(r"\.\s*([A-Za-z_]\w*)", mask_brackets(text)))
    return bool(names & AWAIT_OR_UNWRAP) or text.rstrip().endswith("?")


AWAITED = re.compile(r"\s*\.\s*await\b")


def unawaited_async(body, pos, async_names):
    """True when the call at pos names an `async fn` and is not followed by `.await` (#8034).

    An async lock helper called without `.await` returns a future, not a guard: `let _g = env_lock();`
    holds nothing. Only an awaited call earns lock credit. A name that is not a known async fn (a sync
    helper, a method) is judged by the other rules.
    """
    m = CALL.match(body, pos)
    if not m or m.group(2) not in async_names:
        return False
    return not AWAITED.match(body, match_paren(body, m.end() - 1))


def canonical_guard(body, pos, call=None, write=None):
    """[name] when the lock acquisition at pos is the CANONICAL guard binding, else [] (#7623-#7627).

    Canonical: a statement `let [mut] <name> = <lock expr>;` directly in the top-level block of the fn
    (index 0 of body), where the lock expression is a plain receiver path ending in the lock call
    (`ENV_LOCK.lock().await`, `ENV_LOCK.blocking_lock()`, `env_lock()`, `EnvVarGuard::set(..)`), followed
    only by guard-preserving calls (GUARD_CHAIN) and `?`, and where <name> is never mentioned again
    anywhere after the statement (no move, drop, match, field access, return, shadowing or capture).
    The one tuple shape is `let (<key>, <guard>) = <call in TUPLE_GUARD_SLOTS>(..);`, judged on the
    guard slot. Every other shape is not credited, so it fails closed. A `macro_rules!` body is a
    template, not a fn: there write is the position of its first env write and the statement may sit in
    any block that encloses it.
    """
    prefix = stmt_prefix(body, pos)
    brace = innermost_open(body, pos - len(prefix))
    if brace != 0 and (write is None or match_brace(body, brace) <= write):
        return []
    slot = TUPLE_GUARD_SLOTS.get(call)
    head = LET_PAIR.match(prefix) if slot is not None else None
    if head:
        names = [head.group(slot + 1)]
    else:
        head, names = LET_BOUND.match(prefix), let_names(prefix)
    if not names or names[0] == "_":
        return []
    before = prefix[head.end():]
    if not RECEIVER_TEXT.fullmatch(before) or not balanced(before):
        return []
    end = expr_end(body, pos)
    if any(n not in GUARD_CHAIN for n in re.findall(r"\.\s*([A-Za-z_]\w*)", mask_brackets(body[pos:end]))):
        return []
    if not guard_materialised(body, pos, end):
        return []
    if re.search(r"(?<![\w$])%s\b" % re.escape(names[0]), body[end:]):
        return []
    return names


def depth_at(body, pos):
    return body.count("{", 0, pos) - body.count("}", 0, pos)


HELPER_TAIL = re.compile(r"(?s).*[;}]\s*(?:Self|[A-Z]\w*)\s*\{([^{}]*)\}\s*\}\s*")


def helper_ret_guard(body, pos):
    """True for the ONE helper shape that hands its lock to the caller inside a struct (#7623-#7627).

    `let <name> = <lock expr>;` directly in the top-level block of the helper, then <name> appears
    exactly once afterwards: as a field initialiser (`field: <name>` or shorthand) of the struct
    literal that is the helper's tail expression (`Self { prev, _lock: lock }`). Any other mention
    (drop, move, match, a second use) is not this shape. The caller is then credited only through
    its own canonical `let _g = helper();` binding.
    """
    prefix = stmt_prefix(body, pos)
    head = LET_BOUND.match(prefix)
    if not head or head.group(1) == "_" or innermost_open(body, pos - len(prefix)) != 0:
        return False
    if not RECEIVER_TEXT.fullmatch(prefix[head.end():]) or not balanced(prefix[head.end():]):
        return False
    end = expr_end(body, pos)
    if any(n not in GUARD_CHAIN for n in re.findall(r"\.\s*([A-Za-z_]\w*)", mask_brackets(body[pos:end]))):
        return False
    if not guard_materialised(body, pos, end):
        return False
    rest, name = body[end:], re.escape(head.group(1))
    tail = HELPER_TAIL.fullmatch(rest)
    if not tail or len(re.findall(r"(?<![\w$])%s\b" % name, rest)) != 1:
        return False
    return bool(re.search(r"(?:^|,)\s*(?:\w+\s*:\s*)?%s\s*(?:,|$)" % name, tail.group(1)))


RETURN_HEAD = re.compile(r"\s*return\b\s*")
RETURN_TAIL = re.compile(r"\s*;\s*\}\s*")
BODY_END = re.compile(r"\s*\}\s*")


def plain_receiver(text):
    """True when text is a plain receiver path: `a`, `a::b`, `a.b()`, `LOCK.get_or_init(|| M::new(()))`.

    Identifier segments joined by `.` or `::`, each optionally followed by one balanced `(..)` argument
    list that is skipped whole. No keyword, operator, `&`, `*`, `:` (a struct field) or lone word fits.
    """
    i, n = 0, len(text)
    while True:
        while i < n and text[i].isspace():
            i += 1
        m = IDENT.match(text, i)
        if not m:
            return False
        i = m.end()
        j = i
        while j < n and text[j].isspace():
            j += 1
        if j < n and text[j] == "(":
            i = match_paren(text, j)
            j = i
            while j < n and text[j].isspace():
                j += 1
        if j >= n:
            return True
        if text.startswith("::", j):
            i = j + 2
        elif text[j] == ".":
            i = j + 1
        else:
            return False


def tail_guard(body, pos):
    """True when the lock acquisition at pos IS the whole value a helper returns (#7993).

    The second named helper shape beside helper_ret_guard: a non-test fn whose top-level tail expression
    (or its last statement `return <expr>;`) is exactly <receiver>.lock-call(..) plus GUARD_CHAIN calls, or
    a lock-fn call such as `env_lock()`. The guard then leaves the fn as its return value, so the caller's
    canonical `let _g = helper();` really holds it. A lock call wrapped in `drop(..)` or `size_of_val(&..)`,
    a field initialiser, a branch, a `match` scrutinee, an unawaited tokio future or anything after the
    chain is not this shape.
    """
    prefix = stmt_prefix(body, pos)
    if innermost_open(body, pos - len(prefix)) != 0 or not balanced(prefix):
        return False
    ret = RETURN_HEAD.match(prefix)
    receiver = prefix[ret.end():] if ret else prefix
    if body[pos] == "." and not plain_receiver(receiver) or body[pos] != "." and receiver.strip():
        return False
    end = expr_end(body, pos)
    if any(n not in GUARD_CHAIN for n in re.findall(r"\.\s*([A-Za-z_]\w*)", mask_brackets(body[pos:end]))):
        return False
    if not guard_materialised(body, pos, end):
        return False
    return bool((RETURN_TAIL if ret else BODY_END).fullmatch(body[end:]))


ONCE_STMT_HEAD = re.compile(r"\s*(?:let\s+[^=;{}|]*=\s*)?")


def statement_call(body, pos):
    """True when the call at pos is a statement, or the whole initialiser of a plain `let`, of its block (#7995):
    the call certainly runs before every later statement of that block, and `encloses` keeps its credit inside
    the block. An unbraced closure (`let _c = || call();`), a `#[cfg(..)]`-attributed statement, a match arm or
    any wrapping expression is not a statement call.
    """
    return ONCE_STMT_HEAD.fullmatch(stmt_prefix(body, pos)) is not None


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
        self.dm = mutation_re(use_aliases(scrub(raw))) if raw is not None else DIRECT_MUTATION
        self.consts = dict(fallback or {})
        self.consts.update(CONST_STR.findall(raw) if raw is not None else ())

    def arg_name(self, fn, open_idx):
        """Env var named by the first argument of a call: a literal or a const, else ANY_VAR."""
        if self.raw is None or open_idx < 0 or open_idx >= len(fn.body) or fn.body[open_idx] != "(":
            return ANY_VAR
        a, b = first_arg_text(fn.body, open_idx)
        return self.name_in(fn.offset + a, fn.offset + b)

    def name_in(self, a, b):
        """Env var named by raw[a:b]: a string literal or a const path, else ANY_VAR."""
        if self.raw is None:
            return ANY_VAR
        text = self.raw[a:b].strip().lstrip("&").strip()
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
            hit = hit or bool(REQWEST.search(fn.body))  # a shared helper does not know its URL
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
            for m in src.dm.finditer(fn.body):
                out.add(src.arg_name(fn, m.end() - 1))
            for m, callee in self._callees(fn):
                if callee.owner in COMMON_GUARD_METHODS:
                    out.add(src.arg_name(fn, m.end() - 1))
                elif self.sources[id(callee)].dm.search(callee.body) or callee.owner is None:
                    out |= self.written_vars(callee.key, stack + (id(fn),))
            self._vars[id(fn)] = out
        return self._vars[id(fn)] or {ANY_VAR}


class FileModel:
    """Write sites, their protection sets, lock acquisitions and readers of one tests/*.rs."""

    def __init__(self, scrubbed, raw=None, common=None):
        self.common = common if common is not None else CommonModel()
        self.imports, self.glob = common_imports(scrubbed)
        self.dm = mutation_re(use_aliases(scrubbed))
        scrubbed = blank_use_items(scrubbed)
        self.src = (Source(raw, self.common.src_consts) if raw is not None and len(raw) == len(scrubbed)
                    else Source(None))
        self.fns = parse_fns(scrubbed)
        self.async_names = {f.name for f in self.fns if f.is_async} | {n for n, f in self.common.fns.items() if f.is_async}
        # #8038: a macro_rules! whose body spawns detaches the arguments of every invocation of it
        macro_bodies = {m.group(1): scrubbed[m.end():match_brace(scrubbed, m.end() - 1)]
                        for m in re.finditer(r"\bmacro_rules\s*!\s*([A-Za-z_]\w*)\s*\{", scrubbed)}
        self.detach_macros = {n for n, b in macro_bodies.items() if DETACH.search(b)}
        self.helpers = {}  # #8044: id(fn) -> indices of the parameters the fn hands to a spawn
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
                         if not f.is_test and ONCE_BODY.search(f.body) and self.dm.search(f.body)}
        self._calls, self._acq, self._summary, self._ctx, self._live = {}, {}, {}, {}, {}
        self._detached = {}
        self._encl, self._viol, self._ip_only = {}, {}, {}
        self._close_detachers(macro_bodies)
        self.blamed = set()
        self.callers = {id(f): [] for f in self.fns}
        for f in self.fns:
            for pos, callee, _, method in self.calls(f):
                self.callers[id(callee)].append((f, pos, method))
        self._macro_callers(scrubbed)
        self.macro_writers = self._macro_writers(scrubbed)
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

    def _macro_writers(self, scrubbed):
        """{macro name: (vars, locks)} for same-file `macro_rules!` whose body writes the environment,
        directly or through another such macro it invokes (#7385). locks are the lock tokens the
        body binds before its write; an invocation of the macro is a write site holding them."""
        bodies = {}
        for m in MACRO_RULES.finditer(scrubbed):
            start = m.end() - 1
            bodies.setdefault(m.group(1), (start, scrubbed[start:match_brace(scrubbed, start)]))
        found = {}
        for name, (start, body) in bodies.items():
            writes = list(self.dm.finditer(body))
            if not writes:
                continue
            names = set()
            for w in writes:
                if body[w.end() - 1] != "(":
                    names.add(ANY_VAR)  # a pointer mention: called somewhere unknown
                    continue
                a, b = first_arg_text(body, w.end() - 1)
                names.add(self.src.name_in(start + a, start + b))
            first = writes[0].start()
            locks = set()
            for lm in LOCK_METHOD.finditer(body, 0, first):
                if canonical_guard(body, lm.start(), write=first):
                    locks |= lock_tokens(stmt_prefix(body, lm.start()))
            for cm in CALL.finditer(body, 0, first):
                if (is_lock_fn_name(cm.group(2)) and not unawaited_async(body, cm.start(), self.async_names)
                        and canonical_guard(body, cm.start(), write=first)):
                    locks.add(cm.group(2))
            found[name] = (frozenset(names), frozenset(locks))
        changed = True
        while changed:
            changed = False
            for name, (_, body) in bodies.items():
                if name in found:
                    continue
                inner = [found[c.group(1)] for c in MACRO_CALL.finditer(body) if c.group(1) in found]
                if inner:
                    names = frozenset().union(*(v for v, _ in inner))
                    locks = frozenset.intersection(*(lk for _, lk in inner))
                    found[name] = (names, locks)
                    changed = True
        return found

    def macro_writes(self, fn):
        """[(pos, vars, locks)] for the writer-macro invocations in fn's body."""
        return [(m.start(),) + self.macro_writers[m.group(1)]
                for m in MACRO_CALL.finditer(fn.body) if m.group(1) in self.macro_writers]

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
        for a, b in self.spawn_roots(fn):
            # #8038: a fn item handed to spawn by name (`spawn(work)`) runs detached: it is reached from here
            # with the context of its position inside the spawn argument, which is empty (fail closed).
            # #8045: the same through a chain of `let g = f;` rebindings; past the hop bound every fn is reached.
            v = FN_VALUE.fullmatch(body, a, b)
            if not v:
                continue
            _, chain, over = self.expand(body, a, b)
            hits = list(self.by_key.values()) if over else [self.resolve(fn.owner, p, n) for p, n in chain]
            for hit in hits:
                if hit is not None and hit is not fn:
                    out.append((v.start(2), hit, b, False))
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

        def add(pos, tokens, kind, end=None, call=None, stmt=True):
            if kind == "once" and stmt and not statement_call(body, pos):
                return  # #7995: only a call that certainly ran earns the one-time credit
            if kind == "lock" and unawaited_async(body, pos, self.async_names):
                return  # #8034: an async helper called without .await returns a future and holds nothing
            if tokens:
                names = canonical_guard(body, pos, call) if kind == "lock" else []
                held = bool(names) or (kind == "lock" and helper_ret_guard(body, pos))
                out.append(Acq(pos, pos if end is None else end, frozenset(tokens), kind, held, names))

        for m in LOCK_METHOD.finditer(body):
            add(m.start(), lock_tokens(stmt_prefix(body, m.start())), "lock")
        for pos, kind, token, _, name in self.external(fn):
            if kind in ("guard", "lock"):
                add(pos, {token}, "lock", call=name)
            elif kind in ("once", "once-writer"):
                add(pos, {token}, "once")
        if id(fn) in self.once_fns:
            m = ONCE_BODY.search(body)
            paren = body.find("(", m.end())
            if paren >= 0:
                add(match_paren(body, paren), {ONCE_PREFIX + fn.key}, "once", stmt=False)
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
                # #7993: two named helper shapes hand a lock to the caller: the struct helper
                # (helper_ret_guard) and a lock call that IS the whole returned value (tail_guard).
                # A tail, `return` or field initialiser that merely contains a lock call is not credited.
                if a.bound and not a.names and helper_ret_guard(body, a.pos):
                    ret |= a.tokens
                elif not a.bound and tail_guard(body, a.pos):
                    ret |= a.tokens
        last_calls = [m.start() for m in CALL.finditer(body)]
        work_pos = max(last_calls) if last_calls else len(body) - 1
        work = self.held_own(fn, work_pos, acqs)
        s = Summary(frozenset(persist), frozenset(ret), frozenset(work))
        self._summary[id(fn)] = s
        return s

    def encloses(self, fn, a, r):
        key = (id(fn), a)
        if key not in self._encl:
            self._encl[key] = match_brace(fn.body, scope_open(fn.body, a))
        return r < self._encl[key]

    def spawn_roots(self, fn):
        """[(start, end)] of every argument that fn hands to another thread directly (#7994, #8038, #8044): a
        `spawn(..)` call, an invocation of a spawning macro_rules!, or the argument a same-file detaching
        helper hands to its own spawn (`fn bg<F>(f: F) { spawn(f); }`)."""
        body, out = fn.body, []
        for m in DETACH.finditer(body):
            out.append((m.end(), match_paren(body, m.end() - 1) - 1))
        for m in MACRO_CALL.finditer(body):
            if m.group(1) in self.detach_macros:
                out.append((m.end(), match_paren(body, m.end() - 1) - 1))
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
            args = None
            for c in cands:
                for i in self.helpers.get(id(c), ()):
                    args = split_top_level(body, m.end(), match_paren(body, m.end() - 1) - 1) if args is None else args
                    j = i + (0 if method or not c.has_self else 1)
                    if j < len(args):
                        out.append(args[j])
        return out

    def expand(self, body, a, b):
        """(spans, chain, overflow) for the spawn argument body[a:b] (#8033, #8045): spans are the closure or
        async-block initialisers of the variables the argument resolves to through `let g = f;` rebindings,
        chain is every (path prefix, name) reached, overflow says MAX_REBIND_HOPS was hit. On overflow every
        closure initialiser of the fn is a span: a long chain is flagged, never cleared."""
        v = FN_VALUE.fullmatch(body, a, b)
        if not v:
            return [], [], False
        chain, frontier = [(v.group(1), v.group(2))], ([v.group(2)] if not v.group(1) else [])
        for _ in range(MAX_REBIND_HOPS):
            nxt = []
            for name in frontier:
                for lm in re.compile(REBIND_LET % re.escape(name)).finditer(body, 0, a):
                    tgt = (lm.group(1), lm.group(2))
                    if tgt not in chain:
                        chain.append(tgt)
                        if not tgt[0]:
                            nxt.append(tgt[1])
            frontier = nxt
            if not frontier:
                break
        over = bool(frontier)
        spans = []
        if over:
            spans = [(lm.end(), stmt_end(body, lm.end())) for lm in re.compile(ANY_CLOSURE_LET).finditer(body)]
        else:
            for prefix, name in chain:
                if not prefix:
                    spans += [(lm.end(), stmt_end(body, lm.end()))
                              for lm in re.compile(CLOSURE_LET % re.escape(name)).finditer(body, 0, a)]
        return spans, chain, over

    def spawn_spans(self, fn):
        """[(start, end)] of every argument list of fn that runs detached (#7994, #8038, #8044, #8045): the
        roots, plus the closures the variables among them (through rebinding) hold (#8033)."""
        spans = self.spawn_roots(fn)
        for a, b in list(spans):
            spans += self.expand(fn.body, a, b)[0]
        return spans

    def _spawned_params(self, fn):
        """Indices of the parameters of fn that reach a spawn: named in a spawn argument, in a closure a spawn
        argument variable holds, or in the argument of a call to another detaching helper (#8044)."""
        roots = self.spawn_roots(fn)
        if not roots:
            return set()
        texts, names, over = [], set(), False
        for a, b in roots:
            spans, chain, ov = self.expand(fn.body, a, b)
            texts += [fn.body[x:y] for x, y in [(a, b)] + spans]
            names |= {n for prefix, n in chain if not prefix}
            over = over or ov
        return {i for i, pn in enumerate(fn.params)
                if over or pn is None or pn in names or any(re.search(r"\b%s\b" % re.escape(pn), t) for t in texts)}

    def _close_detachers(self, macro_bodies):
        """Close the detach model to a fixpoint (#8044, #8046): a macro whose body invokes a detaching macro or
        a detaching helper detaches; a fn that hands a parameter to a spawn, a detaching macro or a detaching
        helper is itself a detaching helper. The sets only grow, so the loop ends."""
        changed = True
        while changed:
            changed = False
            helper_names = {f.name for f in self.fns if self.helpers.get(id(f))}
            for name, body in macro_bodies.items():
                if name not in self.detach_macros and (
                        any(c.group(1) in self.detach_macros for c in MACRO_CALL.finditer(body))
                        or any(c.group(2) in helper_names for c in CALL.finditer(body))):
                    self.detach_macros.add(name)
                    changed = True
            for f in self.fns:
                if f.is_test or not f.params:
                    continue
                idxs = self._spawned_params(f)
                if idxs - self.helpers.get(id(f), set()):
                    self.helpers[id(f)] = idxs | self.helpers.get(id(f), set())
                    changed = True

    def detached(self, fn, r):
        """(start, end) of the innermost spawn argument of fn that contains body position r, else None (#7994)."""
        spans = self._detached.get(id(fn))
        if spans is None:
            spans = []
            spans = self.spawn_spans(fn)
            self._detached[id(fn)] = spans
        inside = [s for s in spans if s[0] <= r < s[1]]
        return min(inside, key=lambda s: s[1] - s[0]) if inside else None

    def inherit(self, fn, r, ctx):
        """The caller-supplied lock context that still holds at body position r: none inside a detached spawn."""
        return EMPTY if self.detached(fn, r) else ctx

    def held_own(self, fn, r, acqs=None):
        """Tokens fn itself holds at body position r. Inside a detached spawn argument (#7994) only the
        acquisitions made inside that same argument count: not the spawner's guards, not #[serial]."""
        acqs = self.acquisitions(fn) if acqs is None else acqs
        span = self.detached(fn, r)
        held = set()
        for a in acqs:
            if span and not span[0] <= a.pos < span[1]:
                continue
            if a.kind == "cover":
                if a.pos <= r < a.end:
                    held |= a.tokens
                continue
            if a.pos >= r or not self.encloses(fn, a.pos, r):
                continue
            if a.kind == "once":
                held |= a.tokens
            elif a.bound:
                held |= a.tokens
        if not span:
            held |= fn.serial_tokens
        return held

    # ---- env var names ----------------------------------------------------------------------
    def params(self, fn):
        """Parameter names of fn in order (`self` for a receiver), from its signature."""
        text = self.src.scrubbed
        if text is None:
            return []
        heads = list(re.compile(r"\bfn\s+%s\b" % re.escape(fn.name)).finditer(text, 0, fn.offset))
        if not heads:
            return []
        paren = text.find("(", heads[-1].end(), fn.offset)
        if paren < 0:
            return []
        inner = text[paren + 1:match_paren(text, paren) - 1]
        out, depth, cur = [], 0, []
        for ch in inner + ",":
            if ch in "([{<":
                depth += 1
            elif ch in ")]}>":
                depth -= 1
            if ch == "," and depth == 0:
                part = "".join(cur).strip()
                cur = []
                if part:
                    m = re.match(r"(?:&\s*(?:'\w+\s+)?)?(?:mut\s+)?([A-Za-z_]\w*)", part)
                    out.append(m.group(1) if m else "")
                continue
            cur.append(ch)
        return out

    def key_names(self, fn, a, b, depth=0):
        """Env var names the key expression body[a:b] of fn can take (#7475): a literal or a const, a
        parameter (resolved at every same-file call), a `for` variable over a parameter, or a `self`
        field set from a parameter of the type's fns; anything else is ANY_VAR."""
        name = self.src.name_in(fn.offset + a, fn.offset + b)
        if name != ANY_VAR or depth >= HELPER_DEPTH or self.src.raw is None:
            return {name}
        text = self.src.raw[fn.offset + a:fn.offset + b].strip().lstrip("&*").strip()
        field = re.fullmatch(r"self\s*\.\s*([A-Za-z_]\w*)", text)
        if field and fn.owner:
            out, found = set(), False
            for g in self.fns:
                if g.owner == fn.owner and field.group(1) in self.params(g):
                    found = True
                    out |= self.param_names(g, field.group(1), depth + 1)
            return out if found else {ANY_VAR}
        if not IDENT.fullmatch(text):
            return {ANY_VAR}
        for loop in re.compile(r"\bfor\s+(\([^)]*\)|[A-Za-z_]\w*)\s+in\s+&?\s*(?:mut\s+)?([A-Za-z_]\w*)"
                               ).finditer(fn.body, 0, a):
            if text in IDENT.findall(loop.group(1)):
                text = loop.group(2)
        if text in self.params(fn):
            return self.param_names(fn, text, depth + 1)
        return {ANY_VAR}

    def param_names(self, fn, pname, depth):
        """Env var names parameter pname of fn can take: the union over every same-file call of fn."""
        params = self.params(fn)
        calls = self.callers[id(fn)] if fn.name != "drop" else []
        if pname not in params or not calls:
            return {ANY_VAR}
        out = set()
        for caller, pos, method in calls:
            if method and params[0] != "self":
                continue  # `x.set(..)` on another type: an associated fn without `self` is never a method call
            idx = params.index(pname) - (1 if params and params[0] == "self" and method else 0)
            body = caller.body
            open_idx = body.find("(", pos)
            close = match_paren(body, open_idx) - 1 if open_idx >= 0 else -1
            args, depth_b, s = [], 0, open_idx + 1
            for j in range(open_idx + 1, max(close, open_idx + 1)):
                ch = body[j]
                if ch in "([{":
                    depth_b += 1
                elif ch in ")]}":
                    depth_b -= 1
                elif ch == "," and depth_b == 0:
                    args.append((s, j))
                    s = j + 1
            if close > s or (close == s and args):
                args.append((s, close))
            if open_idx < 0 or not 0 <= idx < len(args):
                return {ANY_VAR}
            out |= self.arg_names(caller, args[idx][0], args[idx][1], depth)
        return out

    def arg_names(self, fn, a, b, depth):
        """Env var names in a call argument body[a:b]: one key expression, or the literals and consts
        of a compound (`&[(KEY, "1")]`); an identifier that is not a const or a parameter is ANY_VAR."""
        whole = self.key_names(fn, a, b, depth)
        if ANY_VAR not in whole:
            return whole
        raw = self.src.raw[fn.offset + a:fn.offset + b]
        out = set(STR_LIT.findall(raw))
        for m in re.finditer(r"(?:[A-Za-z_]\w*\s*::\s*)*([A-Za-z_]\w*)", fn.body[a:b]):
            ident = m.group(1)
            if ident in self.src.consts:
                out.add(self.src.consts[ident])
            elif ident in self.params(fn):
                out |= self.param_names(fn, ident, depth + 1)
            else:
                return {ANY_VAR}
        return out

    def write_names(self, fn, open_idx):
        """Env var names written by the call whose `(` is at open_idx (its first argument)."""
        name = self.src.arg_name(fn, open_idx)
        if name != ANY_VAR or open_idx < 0 or open_idx >= len(fn.body) or fn.body[open_idx] != "(":
            return {name}
        a, b = first_arg_text(fn.body, open_idx)
        return self.key_names(fn, a, b)

    # ---- write sites ------------------------------------------------------------------------
    def ctx(self, fn, stack=()):
        """Tokens every same-file caller holds at its call of fn, up the whole call graph."""
        if fn.is_test:
            return fn.serial_tokens
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
            held = frozenset(self.held_own(caller, pos)) | self.inherit(caller, pos, c)
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
            held = frozenset(self.held_own(fn, pos)) | self.inherit(fn, pos, self.ctx(fn))
            protect = frozenset(t for t in held if not t.startswith(ONCE_PREFIX)) | base
            sites.append(Site(len(sites), fn, pos, base, protect, frozenset(names)))

        for fn in self.fns:
            if not self.live(fn):
                continue
            once = frozenset({ONCE_PREFIX + fn.key}) if id(fn) in self.once_fns else EMPTY
            for m in self.dm.finditer(fn.body):
                add(fn, m.start(), once, self.write_names(fn, m.end() - 1))
            for pos, names, locks in self.macro_writes(fn):
                add(fn, pos, locks, names)
            for pos, kind, token, open_idx, name in self.external(fn):
                if kind == "guard":
                    if name == "MultiEnvVarGuard":
                        names = self.src.literals(fn, open_idx)
                    elif name in COMMON_GUARD_METHODS:
                        names = self.write_names(fn, open_idx)
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
    def readers(self, fn, root=None):
        """[(pos, site or None)] of strong readers and of weak reads of a written var in fn."""
        body, out = fn.body, []
        for m in STRONG_READER.finditer(body):
            if IDENT.findall(m.group(0))[-1] not in self.by_key:
                out.append((m.start(), None))
        if REQWEST.search(body) and not self.ip_only(fn if root is None else root):
            out.extend((m.start(), None) for m in REQWEST.finditer(body))
        for m in self.dm.finditer(body):
            out.append((m.start(), self.site_at.get((id(fn), m.start()))))
        for pos, _, _ in self.macro_writes(fn):
            out.append((pos, self.site_at.get((id(fn), pos))))
        for pos, kind, _, _, _ in self.external(fn):
            if kind in ("guard", "once-writer", "writer"):
                out.append((pos, self.site_at.get((id(fn), pos))))
            elif kind == "reader":
                out.append((pos, None))
        for m in WEAK_READER.finditer(body):
            j = m.end()
            while j < len(body) and body[j].isspace():
                j += 1
            names = {ANY_VAR} if m.group(0).endswith(("vars", "vars_os")) else self.write_names(fn, j)
            if ANY_VAR in names or ANY_VAR in self.written or names & self.written:
                out.append((m.start(), None))
        return out

    def fn_sig(self, fn):
        """Raw signature text of fn (from its `fn name` to its `{`): the parameters bind names too (#8035)."""
        raw = self.src.raw
        if raw is None:
            return ""
        head = raw[max(0, fn.offset - 4000):fn.offset]
        starts = [m.start() for m in re.finditer(r"\bfn\s+%s\b" % re.escape(fn.name), head)]
        return head[starts[-1]:] if starts else head

    def fn_raw(self, fn):
        """Raw text of fn with its `//` comments blanked (length preserved)."""
        raw = self.src.raw
        if raw is None:
            return None
        text = raw[fn.offset:fn.offset + len(fn.body)]
        spans = []
        scrub(text, spans)
        for x, y in spans:
            text = text[:x] + " " * (y - x) + text[y:]
        return text

    def tree_fns(self, root):
        """root and every same-file fn it calls within HELPER_DEPTH (the data-flow unit of #7997)."""
        seen, todo = {id(root): root}, [(root, HELPER_DEPTH)]
        while todo:
            fn, depth = todo.pop()
            if depth <= 0:
                continue
            for _, callee, _, _ in self.calls(fn):
                if id(callee) not in seen:
                    seen[id(callee)] = callee
                    todo.append((callee, depth - 1))
        return list(seen.values())

    def ip_only(self, root):
        """#7526, #7997: this test fn, with the same-file fns it calls, reaches the network only through IP
        hosts. The verdict is per root test fn, so a `local_addr()` in an unrelated fn is no evidence."""
        key = id(root)
        if key not in self._ip_only:
            self._ip_only[key] = ip_only_parts([(self.fn_raw(f), self.fn_sig(f)) for f in self.tree_fns(root)])
        return self._ip_only[key]

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
        for pos, site in self.readers(fn, root):
            held = set(self.inherit(fn, pos, ctx)) | self.held_own(fn, pos) | (site.base if site else EMPTY)
            if not self.satisfied(held, site, root):
                res = True
                break
        if not res and depth > 0:
            for pos, callee, _, _ in self.calls(fn):
                if id(callee) in stack:
                    continue
                held = frozenset(set(self.inherit(fn, pos, ctx)) | self.held_own(fn, pos))
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
        if model.violates(fn, model.ctx(fn), HELPER_DEPTH):
            out.append(fn.qual)
    out.extend(fn.qual for fn in model.tests if id(fn) in model.blamed)
    return sorted(set(out))


def scan_file(path, common=None):
    """Return the violating test fn names of an env-mutating, non-isolated file."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    comments = []
    scrubbed = scrub(raw, comments)
    if process_isolated(raw, comments):
        return []
    return violating_fns(scrubbed, raw, common)


def process_isolated(raw, comments):
    """True when a whole-line `//` comment carries the marker and a reason (#7384)."""
    for start, end in comments:
        if raw[raw.rfind("\n", 0, start) + 1:start].strip():
            continue  # a trailing comment after code
        if ISOLATED_MARKER.match(raw, start, end):
            return True
    return False


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
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
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
        baseline_path.write_text(render(found), encoding="utf-8")
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
