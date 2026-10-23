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
Any other carrier of a closure into a spawn (#8051: `Box::new(f)`, `f.clone()`, `Some(f)`, a struct field,
a `for` or match-arm binding, a wrapping closure) is followed through its `let`, assignment and `for`
bindings; a name that holds a closure makes that initialiser detached, and a carrier that cannot be
traced (or more than MAX_CARRIER_NAMES) flags every closure of the fn, never credits it.
A detaching helper in tests/common (#8052), reached as `common::f`, through a `use common::f` or glob
import, or as `Type::f`, and one in a `#[path = ".."] mod m;` or `mod m;` file of the test (`m::f` or a
`use m::f` name) detaches the argument of every call of it. #8059 `use common::bg as detach;` is
resolved to the helper it names; #8060 a nested `common::a::b::f` path reaches the fn of a submodule
file, and one fixpoint runs over every tests/common file together, so a common helper that calls a
detacher of another common file detaches too.
General rule (#8056 #8057 #8058 #8065-#8069; fail closed, decision 27ef27dc): a closure or async-block
literal is credited only when provably invoked on this thread before the fn returns. Every literal is
DETACHED unless one of these shapes is proven: (1) it is invoked in place, `(|| ..)()`; (2) it is bound by
a plain `let name = <closure>;` and every use of `name` in its scope is a direct call `name(..)` outside
any other closure literal; (3) it is the value a same-thread closure returns and that value is consumed in
place, `mk()()`, or by a `let v = mk();` whose every use is a call (an async block: `.await`ed in place);
a returned closure that is stored, passed on or returned again is detached (#8066); (4) it is the whole
argument of a callee that PROVABLY runs that parameter inline: a same-file, tests/common or module fn
(alias and nested path resolved) whose parameter is in the positive inline-only fixpoint (every use of the
parameter is a direct call, a `let q = p;` alias that is itself inline-only, or an argument of a callee
that is inline-only in turn; a store, a return, a use inside another closure or a re-binding is not),
never a callee that merely does not spawn it (#8065); or an unresolved runner named by its FULL path
(TRUSTED_FN_PATHS, a crate-qualified allowlist; WRAPPER_CALLEES such as std::panic::AssertUnwindSafe recurse;
that list only names INLINE RUNNERS for the inline-runner rule and NEVER proves a type or a receiver std, #8103), or
a std iterator/Option/Once adaptor (TRUSTED_METHOD_PATHS) whose receiver chain roots in a local, a literal, a
std type or a callee that builds no parallel iterator (#8068, #8069); a receiver is credited only when
the gate can positively PROVE its provenance (#8093): every token of the chain, of each `let` initialiser it leads
to and of each wrapper or aggregate (Some, Box::new, vec!, an array, a tuple, a struct literal) must be a literal, a
std path, a callee that builds no parallel iterator or a local whose initialiser is proven in turn, so a wrapper is
transparent only when everything inside it is. A name resolves to the innermost binding in a block still OPEN at the
use (ScopeMap, #8095), and a name bound by a `for` pattern, a match arm, `if let`, `while let`, a closure parameter
or a destructuring `let` is DETACHED (#8094). PARALLEL_ITER (every
rayon par_* adapter, PARALLEL_METHODS, #8090) is judged through a fixpoint over callee bodies, so a helper
that builds a rayon-style iterator taints its callers (#8069).

Type origin (#8102 .. #8107). ONE predicate, type_origin(text) -> STD | CRATE | UNKNOWN, judges every type the
gate reasons about (let annotation, const / static type, fn parameter, return type, turbofish, a method's
trust); SPELLING NEVER PROVES STD. A name is STD only when it resolves through a same-file `use std::` /
`core::` / `alloc::` import (nested braces and `as` aliases followed) or a fully qualified std / core / alloc
path, and the file defines no item of that name and imports no non-std item of that name (tokio, futures,
rayon and every other crate are CRATE). `_`, an absent or partly inferred annotation, `impl`, `dyn` and a
generic are UNKNOWN. CRATE and UNKNOWN are DETACHED (doubt is detached); an annotation is a proof only when
it is std-only without placeholders, otherwise the initialiser is judged (`let v: Vec<_> = vec![1u8]` stays
clean). A const / static is judged by its DECLARED type, a fn parameter by its declared type, a method call is
trusted only when the file imports no non-std trait (`use x::Trait;` never used by name, `as _`) and no
non-std glob other than `super::*` / `common::*` (#8105). A container is judged apart from its elements
(container_links, #8107): the literal root of a receiver that is only iterated or measured is not an element.

File-scope symbol table (r11, #8120 #8121 #8122). Names are resolved through ONE table built before any
classification (FileModel.symbols: name -> SYM_STD | SYM_ITEM | SYM_FOREIGN | SYM_GENERIC), never by spelling a
std name: a later kind wins (a std import < an item the file defines < a non-std import < a generic parameter of
a fn or an impl, in the bound list or the where clause), and a name is STD only when the table says SYM_STD or the
name is absent from the table and on the named std list. A trait imported by a non-std `use` keeps trait_risk set
while it is only NAMED in a bound, `impl X for`, `dyn X`, `impl X` or a `<T as X>` cast (trait_positions): only a
value or plain type use clears it. A const is neutral only as an array length (`[u8; N]`, array_len_spans), never
as the name of a type. Futures are closure VALUES (r11, #8123 #8124): a call to a same-file async fn, to a fn that
returns an `impl Future`, an `async` block and an `async move` block run on this thread only when awaited in place,
let-bound and only awaited, or handed whole to a known runner resolved by its FULL path (RUNTIME_ROOTS and
RUNTIME_RUNNERS: a tokio Runtime, Handle or Builder chain that reaches `build`, however it was reached through a
same-file fn, parameter or local; futures::executor::block_on); everything else is detached, so `x.block_on(async
{..})` on an unresolved receiver flags. Rule inventory (r11, #8125): every FileModel method that classifies by an
origin predicate is registered with @origin_rule (ORIGIN_RULES); the unit tests derive the rule set from the
module's own AST, require a RED probe for each, and run a mutant of each rule (always credits, credits UNKNOWN too).

Callee origin (r12, #8136 #8137 #8138 #8139). The credit side has ONE predicate too, callee_origin(segs, name, kind) ->
STD | CRATE | UNKNOWN, used by the rules arg_inline and await_macro_arg. A macro or a free fn is trusted by its
RESOLVED path (resolve_path: `use` items, renames, an unshadowed crate root), never by its last name segment: a join!
or select! counts only as tokio:: / futures:: (AWAIT_MACROS holds resolved paths), a crate macro of the same name, a
`macro_rules!` of the file and an unresolvable name are detached. An async closure (`async || ..`, `|| async ..`) yields a future per CALL: it is credited
only when every call is awaited in place or handed whole to a resolved runner (future_credited), as for an async fn.

Callee trust invariant (r13, #8154 #8155 #8156 #8157 #8158): a callee that does not resolve to an allowlisted
crate-qualified path is never trusted; there is no bare-name trust anywhere in this module. callee_origin resolves
first and compares the WHOLE resolved path with an allowlist (AWAIT_MACROS, TRUSTED_FN_PATHS, TRUSTED_METHOD_PATHS,
WRAPPER_CALLEES); a CalleeTrustInvariant unit test walks the module AST and fails on any membership test of a trust
table whose left operand is not a path bound from resolve_path or method_path. A bare macro name that a
`macro_rules!` of the file, of a declared module file or of tests/common defines resolves to nothing (textual macro
scope beats a `use`, #8154). A method resolves to (std, name) only when no in-scope method provider may supply that
name (#8155): every non-std import is a provider of the methods it may supply (FileModel.provider: a vetted trait of
KNOWN_TRAIT_METHODS its listed methods, a vetted type of KNOWN_FOREIGN_TYPES, a module, a fn or a src/ type none, a
src/ trait its declared fns, any other name everything unless the file uses it as a value or a plain type), and a
glob supplies everything. `extern crate X as A;` binds A to X before any root is trusted (#8156). A `Name::f(..)`
path root never proves that Name is a type, whatever the arguments, because a UFCS trait call is spelled the same
(#8157). A free fn is trusted only by its whole resolved path, never by its last segment (#8158).

Form inventory (#8098, #8099, #8100). span_safe is a CLOSED whitelist and the ONLY decision point for a receiver:
each expression form the tokenizer can yield has exactly one rule, a form with no rule is DETACHED, and every
branch records its form through form() (SPAN_FORMS; the FormInventory test pins this table, the tuple, the
branches and one probe per form). Doubt is detached.
  form                 rule
  `literal`            a literal, array, tuple or borrow root: its elements are decided token by token
  `keyword`            a keyword (`true`, `as`, `mut`, ..) is never a value
  `primitive`          a primitive type name (`u8` in a cast)
  `macro_vec`          `vec![..]` (std path prefix allowed); its elements are decided token by token
  `macro_value`        VALUE_MACROS (`format!`, `concat!`, ..); every other macro is `macro_other`: DETACHED
  `field`              a field of a safe value
  `method_inline`      a method on the INLINE_METHODS allowlist (disjoint from PARALLEL_METHODS)
  `method_resolved`    a same-file or tests/common method: no candidate parallel and every return value safe
  `method_other`       any other method (an unknown or extension-trait one, `into_pool`): DETACHED
  `label_binder`       a struct-literal label or a name `let` / `ref` introduces
  `call_std`           `Some` / `Ok` / `Err`, a std-origin path or name (type_origin STD: a `use std::` import
                       or a fully qualified std path; a locally defined or non-std name never qualifies)
  `call_resolved`      a same-file or tests/common fn: not parallel and every return value safe (MAX_RETURN_DEPTH)
  `call_adt`           a same-file tuple struct or enum variant constructor
  `call_other`         any other call (an unresolved crate fn, an uppercase fn): DETACHED
  `name_local`         a `let` whose declared type is STD without `_` / impl / dyn (the type is the proof), or, with
                       no or a partly inferred type, whose initialiser is proven; a CRATE / UNKNOWN declared type
                       is DETACHED; a rebinding is followed
  `name_closure_param` a parameter of a `closure_iife` / `closure_arg` closure
  `name_opaque`        every other binder (`for`, match arm, `if let`, destructuring): DETACHED
  `name_param`         `self`, or a fn parameter whose declared type is STD (impl / dyn / generic / crate: DETACHED)
  `name_std`           `None`, a name whose type_origin is STD (imported from std, not shadowed)
  `name_const`         a same-file `const` / `static` by its DECLARED type: STD is a proof; a same-file ADT type with
                       a safe initialiser is safe; any other (crate / unknown) is DETACHED
  `name_fn_item`       a same-file fn used as a value: not parallel and every return value safe
  `name_adt`           a same-file struct or `Self`
  `name_other`         an unresolvable name of ANY casing (`GLOBAL`, `P`): DETACHED
  `path_std`           a path whose type_origin is STD: `std::` / `core::` / `alloc::`, a primitive's item, an item of
                       a type imported from std
  `path_const`         `self::` / `crate::` / `module::` const, judged by its initialiser
  `path_variant`       a variant of a same-file enum
  `path_other`         any other path (`ai_memory::pool::GLOBAL`): DETACHED
  `closure_iife`       a closure invoked in place `(|..| ..)(args)`, args safe; its body tokens are decided in turn
  `closure_arg`        the argument of an INLINE_METHODS method whose receiver is safe; body decided in turn
  `closure_other`      a closure in any other position (`let f = |..|`, a path-call argument): DETACHED
  `async_block`        an `async` block: DETACHED
  `turbofish_std`      every turbofish type is STD by type_origin (`_` allowed inside a std type)
  `turbofish_other`    a turbofish type of another crate or file (`collect::<Pool>()`): DETACHED
  `block_root`         a chain rooted in a block or a struct literal: DETACHED
`&|| ..` and `&mut || ..` are closure literals (#8067). Anything else (inside Box::new, Some, a struct
field, vec!, a tuple, a method receiver, an assignment, a return, a loop, another closure, an unresolved
free function or crate path) is detached. A spawn used as a fn value (`.map(std::thread::spawn)`,
VALUE_DETACH) detaches every closure of the fn, and a carrier re-assigned later in an enclosing loop is
followed through that later binding (loop_end).
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
  * two tests/common files that define a fn of the same name share one detacher entry (their
    parameter indices are unioned), which can only flag more, never credit;
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
DETACH_WORDS = ("spawn|spawn_blocking|spawn_local|spawn_on|spawn_pinned|"
                "spawn_unchecked|spawn_scoped")
DETACH = re.compile(r"(?<![\w])(?<!fn )(?:%s)\s*(?:::\s*<[^;{}]*?>\s*)?\(" % DETACH_WORDS)
# #8057: a spawn name that is NOT called (`.map(std::thread::spawn)`, `let s = spawn;`) is a fn value
VALUE_DETACH = re.compile(r"(?<![\w])(?<!fn )(?:%s)\b(?!\s*::(?!\s*<))(?!\s*(?:::\s*<[^;{}]*?>\s*)?\()" % DETACH_WORDS)
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
MAX_CARRIER_NAMES = 32  # #8051: distinct local names followed from a spawn argument; more flags the whole fn
ASSIGN = r"(?<![\w.])%s\s*=(?![=>])"  # `g = <init>;` (a re-assignment of a carrier variable)
LOCAL_NAME = re.compile(r"(?<![\w.:])([A-Za-z_]\w*)\b(?!\s*::)")  # an identifier that is not a path segment or field
MOD_DECL = re.compile(r'(?:#\[\s*path\s*=\s*"([^"]+)"\s*\]\s*)?(?:pub(?:\([^)]*\))?\s+)?\bmod\s+([A-Za-z_]\w*)\s*;')
LOOP_BIND = r"\bfor\b[^{};]*\b%s\b[^{};]*\bin\b"  # `for g in <expr> {`
ARM_BIND = r"(?<![\w.])%s\b\s*(?:[,)|]\s*)*=>"  # a match-arm pattern naming the variable
PARAM_BIND = r"\|[^|;{}]*\b%s\b[^|;{}]*\|"  # a closure parameter list naming the variable
SHADOW_BINDS = (r"\blet\b[^=;]*\b%s\b[^=;]*=(?!=)", LOOP_BIND, ARM_BIND)  # #8065: a re-binding of a parameter name
ANY_CLOSURE_LET = CLOSURE_LET % r"[A-Za-z_]\w*"  # every closure or async-block `let` initialiser of a fn
# #8056: a closure or async-block LITERAL: `[async] [move] |params|` / `||` or `async [move] {`. A bare `|` opens
# a closure only after one of CLOSURE_PREV (or `=>` / `return`); after an operand it is a bit-or or an or-pattern.
CLOSURE_OPEN = re.compile(r"(?<![\w$])(?:async\s+(?:move\s+)?\{|(?:(?:async\s+)?move\s+|async\s+)?\|\|?)")
CLOSURE_PREV = "(,={;[:&"  # #8067: `&` and `&mut` borrow a closure literal; a bit-and never precedes one
BORROW_MUT = re.compile(r"&\s*mut$")
INLINE_ROOTS = frozenset(("std", "core", "alloc", "tokio", "futures"))  # #8068: path roots of the known inline runners
# (rayon is left out on purpose: its pool runs a closure on another thread, so a rayon-qualified path is detached)
# #8065, r13 (#8158): a pass-through wrapper, judged by where its value goes; RESOLVED paths, never a last segment
WRAPPER_CALLEES = frozenset((("std", "panic", "AssertUnwindSafe"), ("core", "panic", "AssertUnwindSafe")))
RECEIVER_CTORS = frozenset(("Some", "Ok", "Err"))  # #8069: prelude constructors that root an iterator chain
# r10 (#8102-#8107): ONE predicate, FileModel.type_origin, decides whether a type, a path or a name is std. Its three
# results; CRATE and UNKNOWN are both DETACHED. Spelling never proves std: only a binding does.
STD, CRATE, UNKNOWN = "std", "crate", "unknown"
# r11 (#8120-#8122): the kinds of the ONE file-scope symbol table (FileModel.symbols). A name the table holds is bound by
# the file and shadows the std name; precedence is generic > foreign import > file item > std import.
SYM_STD, SYM_ITEM, SYM_FOREIGN, SYM_GENERIC = "std-import", "item", "foreign-import", "generic"
# r11 (#8123, #8124): the runners that run a future to completion on the calling thread, as RESOLVED paths. A future
# (an async block, the result of an async fn or of a fn returning impl Future) is credited only when awaited in
# place or when it is the whole argument of one of these. Keyed by the type path of the receiver + the method.
RUNTIME_RUNNERS = frozenset((
    ("tokio", "runtime", "Runtime", "block_on"), ("tokio", "runtime", "Handle", "block_on"),
    ("futures", "executor", "block_on")))
RUNNER_NAME = "block_on"  # the method / fn name RUNTIME_RUNNERS is looked up for
# r11: the resolved paths a runtime value can be rooted at (`Runtime::new()`, `Handle::current()`, a Builder chain).
RUNTIME_ROOTS = frozenset((
    ("tokio", "runtime", "Runtime"), ("tokio", "runtime", "Handle"), ("tokio", "runtime", "Builder")))
# r11: the links of a runtime chain that hand the runtime (or its handle) on unchanged.
RUNTIME_LINKS = frozenset((
    "new", "new_current_thread", "new_multi_thread", "build", "unwrap", "expect", "enable_all", "enable_io",
    "enable_time", "worker_threads", "thread_name", "current", "try_current", "handle", "clone"))
# r12 (#8136): macros that poll their future arguments on the calling task, as RESOLVED paths. A macro is trusted only
# when its path resolves (resolve_path: `use` items, renames, an unshadowed crate root) to one of these; a name that
# resolves anywhere else, or that nothing resolves, is detached.
AWAIT_MACROS = frozenset((
    ("tokio", "join"), ("tokio", "try_join"), ("tokio", "select"),
    ("futures", "join"), ("futures", "try_join"), ("futures", "select")))
# r12 (#8136, #8137): the kinds of callee that callee_origin judges.
CALLEE_MACRO, CALLEE_FN, CALLEE_METHOD = "macro", "fn", "method"
# r11 (#8123): library fns that return a future built around their argument; a future argument is credited when
# the wrapper call is itself driven in place. Resolved path -> index of the future argument.
FUTURE_WRAPPERS = {("tokio", "time", "timeout"): 1}
# r13 (#8158): the free fns that run their closure argument on the calling thread, as RESOLVED paths. A free fn is
# trusted only when its path resolves to one of these; a fn that merely ends in a trusted name is not.
TRUSTED_FN_PATHS = frozenset((
    ("std", "panic", "catch_unwind"), ("tokio", "time", "timeout"))) | WRAPPER_CALLEES
# r13 (#8157): `Name::..` after an imported name: a path-root use, which proves no type use of an UpperCamel name
PATH_ROOT_USE = re.compile(r"\s*::")
# r13 (#8156): `extern crate NAME;` / `extern crate NAME as ALIAS;`; an alias is a crate root bound by the file.
EXTERN_CRATE = re.compile(r"(?<![\w$])extern\s+crate\s+([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?\s*;")
EXTERN_SELF = "self"  # `extern crate self as NAME;` binds NAME to the crate being compiled
CRATE_ROOT = ("crate",)  # the path `extern crate self as NAME;` stands for
# r13 (#8155): the trait-method sets of the non-std traits whose import the tests use, read from the locked crate
# sources (tower 0.5.3 util/mod.rs, http-body-util 0.1.3 lib.rs, digest 0.10.7 digest.rs and mac.rs), keyed by every
# path the trait is imported through. A trait in this table supplies exactly these methods; any other imported
# non-std trait (or one this file cannot tell from a type) may supply ANY method.
TOWER_SERVICE_EXT = frozenset((
    "and_then", "boxed", "boxed_clone", "call_all", "filter", "filter_async", "map_err", "map_future", "map_request",
    "map_response", "map_result", "oneshot", "ready", "ready_oneshot", "then"))
HTTP_BODY_EXT = frozenset((
    "boxed", "boxed_unsync", "collect", "frame", "into_data_stream", "map_err", "map_frame", "with_trailers"))
DIGEST_TRAIT = frozenset((
    "chain_update", "digest", "finalize", "finalize_into", "finalize_into_reset", "finalize_reset", "new",
    "new_with_prefix", "output_size", "reset", "update"))
MAC_TRAIT = frozenset((
    "chain_update", "finalize", "finalize_reset", "generate_key", "new", "new_from_slice", "reset", "update", "verify",
    "verify_reset", "verify_slice", "verify_slice_reset", "verify_truncated_left", "verify_truncated_right"))
KNOWN_TRAIT_METHODS = {
    ("tower", "ServiceExt"): TOWER_SERVICE_EXT, ("tower", "util", "ServiceExt"): TOWER_SERVICE_EXT,
    ("http_body_util", "BodyExt"): HTTP_BODY_EXT,
    ("sha2", "Digest"): DIGEST_TRAIT, ("digest", "Digest"): DIGEST_TRAIT,
    ("hmac", "Mac"): MAC_TRAIT, ("digest", "Mac"): MAC_TRAIT,
}
# r13 (#8155, #8157): non-std import paths that name a struct or a type alias (never a trait) in the locked crate
# sources (chrono 0.4.44, axum 0.8.9 / axum-core 0.5.6, http 1.4.0, tokio 1.53.1, wiremock 0.6.5, sha2 0.10.9,
# hmac 0.12.1); such an import supplies no method even when the file only calls `Name::f(..)` through it.
KNOWN_FOREIGN_TYPES = frozenset((
    ("chrono", "Utc"), ("axum", "body", "Body"), ("axum_core", "body", "Body"), ("axum", "http", "Request"),
    ("http", "Request"), ("axum", "http", "StatusCode"), ("http", "StatusCode"), ("tokio", "sync", "Mutex"),
    ("tokio", "sync", "RwLock"), ("wiremock", "Mock"), ("wiremock", "MockServer"), ("wiremock", "ResponseTemplate"),
    ("sha2", "Sha256"), ("hmac", "Hmac")))
FILE_ROOTS = frozenset(("crate", "self", "super"))  # import roots inside the test crate itself (the file, its mods)
ANY_METHOD = None  # a method provider whose method set is unknown: it may supply any method name
CARGO_MANIFEST = "Cargo.toml"  # the manifest whose [package] name is the crate the tests import as a path root
PACKAGE_NAME = re.compile(r'(?ms)^\[package\][^\[]*?^name\s*=\s*"([^"]+)"')
DEP_HEADER = re.compile(r"""^\[\s*(?:.*\.)?(?:dev-|build-)?dependencies(?:\.([\w'"-]+))?\s*\]""")  # r14 (G2): a dependency table
DEP_ENTRY = re.compile(r"""^["']?([\w-]+)["']?\s*=\s*(.*)$""")  # `name = <value>` of a dependency table
DEP_DOTTED_PACKAGE = re.compile(r"""^["']?([\w-]+)["']?\.package\s*=\s*"([^"]+)\"""")  # `name.package = "x"`
DEP_PACKAGE = re.compile(r'\bpackage\s*=\s*"([^"]+)"')  # the `package = "x"` key of an inline table or a [dependencies.name] table
DEP_QUOTES = "'\""  # the quote characters TOML allows around a dependency name
DEP_AMBIGUOUS = "?"  # r14 (G2): the real crate of a dependency name that two tables point at different crates; trusted by no table
INLINE_MOD = re.compile(r"(?<![\w$])mod\s+([A-Za-z_]\w*)\s*\{")  # r14 (G3): an inline module and its opening brace
SRC_TRAIT = re.compile(r"(?<![\w$])trait\s+([A-Za-z_]\w*)[^{;]*\{")  # a trait declaration of src/ and its body
SRC_TYPE = re.compile(r"(?<![\w$])(?:struct|enum|union|type)\s+([A-Za-z_]\w*)")  # a src/ type that is not a trait
FN_NAME = re.compile(r"(?<![\w$])fn\s+([A-Za-z_]\w*)")  # every fn a trait body declares (nested ones included)
MACRO_RULES_NAME = re.compile(r"(?<![\w$])macro_rules\s*!\s*([A-Za-z_]\w*)")  # a macro_rules! definition
# r12 (#8139): `async [move] |..|`: an async closure, whose call yields a future that runs the body when polled.
ASYNC_CLOSURE = re.compile(r"async\s+(?:move\s+)?\|")
FUTURE_RET = re.compile(r"Future")  # a declared return type that names a future (impl Future, BoxFuture, Pin<Box<dyn Future>>)
GENERIC_OWNER = re.compile(r"\b(?:(?:fn|trait|struct|enum|union|type)\s+[A-Za-z_]\w*|impl)\s*<")  # an item that declares generics
TRAIT_RUN = re.compile(r"\b(?:impl|dyn)\b([^{};,=)]*)")  # text after impl / dyn that can name a trait
WHERE_RUN = re.compile(r"\bwhere\b([^{};]*)")  # a where clause: every name in it is in a bound position
TRAIT_CAST = re.compile(r"\bas\s+([A-Za-z_][\w:]*)\s*>")  # `<T as Trait>`
PRELUDE_TYPES = frozenset(("String", "Vec", "Option", "Result", "Box"))  # the std prelude's types (shadowable)
PRELUDE_VALUES = RECEIVER_CTORS | frozenset(("None",))  # the std prelude's value names (shadowable)
TYPE_NEUTRAL = frozenset(("mut", "const", "ref"))  # words of a type text that name nothing
TYPE_OPAQUE = frozenset(("_", "impl", "dyn", "fn", "for", "where", "unsafe", "extern", "Self"))  # name no type: UNKNOWN
# r10 (#8107): the methods that act on a container (array, Vec, iterator over it) without handing an element back as a
# receiver; a chain made only of these is judged without the elements of its root literal.
CONTAINER_METHODS = frozenset((
    "chain", "clone", "cloned", "collect", "copied", "enumerate", "filter", "for_each", "into_iter", "is_empty", "iter",
    "iter_mut", "len", "map", "rev", "skip", "take", "to_vec", "zip"))
MAX_CHAIN_STEPS = 64  # #8069: method-chain links followed from a closure's receiver back to its root; more is unresolved
Detacher = collections.namedtuple("Detacher", "idxs has_self inline parallel value_safe")  # one fn of a file outside the test file
# #8056: library calls that run their closure argument inline on the calling thread (Option / Result / Iterator /
# slice adaptors, the rusqlite row mappers, a runtime's block_on, timeout, catch_unwind). A same-file or tests/common
# fn of the same name is judged by its own body first; with rayon in the fn none of these is trusted.
SAME_THREAD_CALLEES = frozenset((
    "map", "and_then", "or_else", "unwrap_or_else", "map_or", "map_or_else", "map_err", "ok_or_else", "is_some_and",
    "is_none_or", "is_ok_and", "is_err_and", "filter", "filter_map", "flat_map", "find", "find_map", "any", "all",
    "position", "rposition", "take_while", "skip_while", "map_while", "inspect", "fold", "try_fold", "for_each",
    "sort_by", "sort_by_key", "sort_unstable_by", "sort_unstable_by_key", "retain", "max_by", "max_by_key", "min_by",
    "min_by_key", "get_or_insert_with", "or_insert_with", "query_row", "query_map", "query_and_then", "block_on",
    "timeout", "catch_unwind", "AssertUnwindSafe", "with_default", "call_once", "call_once_force", "get_or_init",
    "get_or_try_init", "force"))
# #8090, #8096: every rayon parallel-iterator entry point, matched as a WHOLE method name (the `par_sort*` family
# by prefix). The source is rayon's full `par_*` adapter set (ParallelSlice, ParallelSliceMut, ParallelString,
# IntoParallelIterator, ParallelBridge, ParallelExtend, ParallelDrain); the tuple is kept sorted.
PARALLEL_METHODS = (
    "into_par_iter", "par_bridge", "par_bytes", "par_char_indices", "par_chars", "par_chunk_by", "par_chunk_by_mut",
    "par_chunks", "par_chunks_exact", "par_chunks_exact_mut", "par_chunks_mut", "par_drain", "par_encode_utf16",
    "par_extend", "par_iter", "par_iter_mut", "par_lines", "par_match_indices", "par_matches", "par_rchunks",
    "par_rchunks_exact", "par_rchunks_exact_mut", "par_rchunks_mut", "par_split", "par_split_inclusive",
    "par_split_inclusive_mut", "par_split_mut", "par_split_terminator", "par_split_whitespace", "par_windows",
)
PARALLEL_ITER = re.compile(r"\brayon\b|\b(?:%s|par_sort\w*)\b" % "|".join(PARALLEL_METHODS))
# r13 (#8155): a method call resolves to (STD_METHOD_ROOT, name) only when no non-std provider in scope (an imported
# trait, an `as _` import, a glob) can supply a method of that name (FileModel.method_path); a method is trusted only
# when that resolved path is in TRUSTED_METHOD_PATHS. Its bare name never suffices.
STD_METHOD_ROOT = "std"
TRUSTED_METHOD_PATHS = frozenset(
    (STD_METHOD_ROOT, name) for name in SAME_THREAD_CALLEES if not PARALLEL_ITER.search(name))
KEYWORDS = frozenset((
    "as", "async", "await", "break", "continue", "const", "crate", "dyn", "else", "false", "fn", "for", "if", "impl",
    "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "static", "struct", "super", "true",
    "unsafe", "use", "where", "while"))  # #8093: words that are never a value token
PRIMS = frozenset((
    "bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
    "f32", "f64"))  # #8093: primitive type names (casts, turbofish) are not values
VALUE_MACROS = frozenset((
    "format", "concat", "stringify", "matches", "json", "include_str", "include_bytes", "env", "option_env", "line",
    "file", "column", "module_path"))  # #8093: macros that build a plain value on the calling thread (vec! is judged inside)
STD_ROOTS = frozenset(("std", "core", "alloc"))  # #8098: the roots of a fully qualified std path
MAX_RETURN_DEPTH = 4  # #8098: callee levels a fn's return values are followed through; the limit is detached
CLOSURE_HEAD = re.compile(r"(?:async\s+)?(?:move\s+)?(?:\|\||\|[^|]*\|)\s*(?:->\s*[^{]+?(?=\s*\{))?")
BINDER = re.compile(r"\b(?:let|ref)(?:\s+mut)?$")  # text that ends right before a name a pattern introduces
# #8100: the closed allowlist of std methods that run on the calling thread and hand back a value of the receiver's
# own provenance (iterator, collection, string, Option and Result adapters). A method that is not here is detached.
# It never holds a rayon method (a test asserts INLINE_METHODS and PARALLEL_METHODS are disjoint).
INLINE_METHODS = frozenset((
    "all", "and", "and_then", "any", "as_bytes", "as_deref", "as_mut", "as_ref", "as_slice", "as_str", "borrow",
    "borrow_mut", "build", "by_ref", "bytes", "chain", "char_indices", "chars", "chunks", "chunks_exact", "clone",
    "cloned", "collect", "column_count", "concat", "contains", "copied", "count", "cycle", "drain", "enable_all",
    "enumerate",
    "eq", "err", "expect", "expect_err", "filter", "filter_map", "find", "find_map", "first", "flat_map", "flatten",
    "fold", "fuse", "get", "get_mut", "inspect", "into", "into_boxed_slice", "into_iter", "into_keys",
    "into_values", "is_empty", "is_none", "is_some", "iter", "iter_mut", "join", "keys", "last", "len", "lines",
    "lock", "map", "map_err", "map_or", "map_or_else", "map_while", "max", "max_by", "max_by_key", "min", "min_by",
    "min_by_key", "next", "next_back", "nth", "ok", "ok_or", "ok_or_else", "or", "or_else", "parse", "peekable",
    "position", "prepare", "product", "read", "reduce", "repeat", "rev", "rposition", "skip", "skip_while", "split", "split_terminator",
    "split_whitespace", "step_by", "strip_prefix", "strip_suffix", "sum", "take", "take_while", "to_lowercase",
    "to_owned", "to_string", "to_uppercase", "to_vec", "trim", "trim_end", "trim_start", "try_into", "unwrap",
    "unwrap_err", "unwrap_or", "unwrap_or_default", "unwrap_or_else", "values", "values_mut", "windows", "worker_threads", "write",
    "zip"))
# #8098-#8100: every expression form span_safe can decide. Each branch of the predicate names its form through
# form(); a label outside this tuple cannot be recorded. The module docstring tabulates form -> rule, and the
# FormInventory test pins this tuple to the source and to one probe per form.
SPAN_FORMS = (
    "literal", "keyword", "primitive", "macro_vec", "macro_value", "macro_other", "field", "method_inline",
    "method_resolved", "method_other", "label_binder", "call_std", "call_resolved", "call_adt", "call_other",
    "name_local", "name_closure_param", "name_opaque", "name_param", "name_std", "name_const", "name_fn_item",
    "name_adt", "name_other", "path_std", "path_const", "path_variant", "path_other", "closure_iife", "closure_arg",
    "closure_other", "async_block", "turbofish_std", "turbofish_other", "block_root")
FORM_TRACE = None  # a list while a test records the (form, ok) of every decision, else None


def form(label, ok):
    """Record that the branch `label` decided `ok` (see SPAN_FORMS) and return ok. A label with no inventory entry is a bug."""
    assert label in SPAN_FORMS, label
    if FORM_TRACE is not None:
        FORM_TRACE.append((label, bool(ok)))
    return ok


CLOSURE_LET_HEAD = re.compile(r"\s*let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]*)?=\s*")
CALLEE_TAIL = re.compile(r"((?:[A-Za-z_]\w*\s*::\s*)*)([A-Za-z_]\w*)\s*$")
LOOP_HEADER = re.compile(r"\b(?:for|while|loop)\b")
LET_BINDER = re.compile(r"\blet\s+(?:mut\s+)?$")  # text that ends right before a let-bound name
CLOSURE_TAIL_HEAD = re.compile(r"(?:async\s+)?(?:move\s+)?\|[^|]*\|")  # a closure head: its tail value is what it returns
CALL_OPENER = re.compile(r"\s*\)\s*\(")
USE_ALIAS = re.compile(r"\b([A-Za-z_]\w*)\s+as\s+([A-Za-z_]\w*)")
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


LITERAL_ROOT = re.compile(r"\s*(?:&\s*(?:mut\s+)?)*(?:vec\s*!\s*)?\[")  # r10: a root array / vec![..] literal
USE_TOKEN = re.compile(r"::|[{},*]|[A-Za-z_]\w*")
ITEM_NAME = re.compile(r"(?<![\w$'])(?:struct|enum|union|trait|type|const|static|fn|mod)\s+(?:mut\s+)?([A-Za-z_]\w*)"
                       r"|\bmacro_rules\s*!\s*([A-Za-z_]\w*)")


def use_leaves(item):
    """[(path segments, bound name)] of one `use` item (#8103): nested braces, `as` aliases and `self` leaves are
    resolved; a glob leaf has the bound name None and an `as _` leaf the name `_`."""
    toks = USE_TOKEN.findall(item)
    pos, out = [1 if toks[:1] == ["use"] else 0], []

    def emit(path, name):
        if path and path[-1] == "self":
            path = path[:-1]
        if path and name == "self":
            name = path[-1]
        if path and name:
            out.append((tuple(path), name))

    def tree(prefix):
        path = list(prefix)
        while pos[0] < len(toks):
            tok = toks[pos[0]]
            if tok == "::":
                pos[0] += 1
            elif tok == "{":
                pos[0] += 1
                while pos[0] < len(toks) and toks[pos[0]] != "}":
                    tree(tuple(path))
                    if pos[0] < len(toks) and toks[pos[0]] == ",":
                        pos[0] += 1
                pos[0] += 1
                return
            elif tok == "*":
                pos[0] += 1
                out.append((tuple(path), None))
                return
            elif tok in (",", "}"):
                break
            elif tok == "as" and len(path) > len(prefix):
                alias = toks[pos[0] + 1] if pos[0] + 1 < len(toks) else "_"
                pos[0] += 2
                emit(path, alias)
                return
            else:
                path.append(tok)
                pos[0] += 1
        if len(path) > len(prefix):
            emit(path, path[-1])

    tree(())
    return out


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


def closure_literals(body):
    """[(start, end)] of every closure or async-block literal of body (#8056), start at its `move` / `async` /
    `|`, end past its last token. A bare `|` after an operand is a bit-or or an or-pattern, not a closure."""
    out = []
    for m in CLOSURE_OPEN.finditer(body):
        tok = m.group(0)
        if tok.endswith("{"):
            bstart = m.end() - 1
        else:
            if tok in ("|", "||"):
                prev = body[:m.start()].rstrip()
                if prev and (prev[-1] not in CLOSURE_PREV or prev[-2:] in ("==", "!=", "<=", ">=", "&&")) \
                        and not prev.endswith("=>") and not re.search(r"\breturn$", prev) \
                        and not BORROW_MUT.search(prev):
                    continue
            pend = m.end() if tok.endswith("||") else body.find("|", m.end()) + 1
            if pend <= 0:
                continue
            bstart = body.find("{", pend) if re.match(r"\s*->", body[pend:]) else pend
            while 0 <= bstart < len(body) and body[bstart].isspace():
                bstart += 1
        if bstart < 0:
            continue
        end = match_brace(body, bstart) if body[bstart:bstart + 1] == "{" else expr_end(body, bstart)
        out.append((m.start(), end))
    return out


def open_group(body, close_idx):
    """Index of the `(` / `[` matched by the `)` / `]` at close_idx, or -1 (#8069)."""
    depth = 0
    for j in range(close_idx, -1, -1):
        if body[j] in ")]":
            depth += 1
        elif body[j] in "([":
            depth -= 1
            if depth == 0:
                return j
    return -1


def scope_uses(body, name, start):
    """Matches of the identifier `name` after body[start] within the scope of a value bound at start: up to the end
    of the enclosing block, or of the statement that re-binds the name (#8056, #8066). Paths and fields excluded."""
    esc = re.escape(name)
    limit = match_brace(body, scope_open(body, start))
    shadow = re.compile(r"\blet\s+(?:mut\s+)?%s\b" % esc).search(body, start, limit)
    if shadow:
        limit = stmt_end(body, shadow.end())
    return [um for um in re.finditer(r"(?<![\w.:])%s\b(?!\s*::)" % esc, body[:limit])
            if um.start() >= start and not (shadow and um.start() == shadow.end() - len(name))]


def loop_end(body, pos):
    """End of the outermost `for` / `while` / `loop` body that encloses pos, else pos (#8058): a binding made
    later in that loop body reaches the next iteration, so it is a binding of the carrier at pos."""
    end, brace = pos, innermost_open(body, pos)
    while brace > 0:
        if LOOP_HEADER.search(stmt_prefix(body, brace)):
            end = match_brace(body, brace)
        brace = innermost_open(body, brace)
    return end


IDENT_END = re.compile(r"([A-Za-z_]\w*)\s*$")
IDPATH = re.compile(r"(?<![\w$'])[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*")
FOR_HEAD = re.compile(r"\bfor\b([^{};=]*?)\bin\b")
COND_LET = re.compile(r"(?:\bif|\bwhile|&&|\|\|)$")
PATTERN_NAME = re.compile(r"(?<![\w:.$'])([a-z_]\w*)\b(?!\s*(?:::|\(|!))")
PATTERN_SKIP = frozenset(("mut", "ref", "box", "in", "if", "as", "true", "false", "let", "else", "move", "dyn", "impl",
                          "for", "_"))
# init: (start, end) of a plain `let` initialiser or a `for` iterable, else None; per_item: a `for` name is ONE ITEM of its iterable
Binding = collections.namedtuple("Binding", "name lo hi init per_item", defaults=(False,))


def callee_path(text):
    """(start, prefix, name) of the callee path that ends text (`a::b::name`, prefix `a::b::`), a turbofish anywhere
    in it (`std::vec::Vec::<u8>::new`, `x.collect::<T>`) skipped; start indexes text. None when text ends in no
    name (#8093: a std path with a generic argument is a positive match, not a doubt)."""
    s = strip_turbofish(text.rstrip())
    m = IDENT_END.search(s)
    if m is None:
        return None
    name, segs, start = m.group(1), [], m.start(1)
    while True:
        before = s[:start].rstrip()
        if not before.endswith("::"):
            break
        before = strip_turbofish(before[:-2].rstrip())
        pm = IDENT_END.search(before)
        if pm is None:
            break
        segs.insert(0, pm.group(1))
        start = pm.start(1)
    return start, "".join(g + "::" for g in segs), name


def chain_start(body, end):
    """Index where the postfix chain (root, `.field`, `.method(..)`, `[i]`, `?`) that ends at body[:end] begins, or
    None when its root is a block or a struct literal (`}`) or the walk cannot be followed (#8093). A blank root
    (a string or char literal, which the scrubber blanks) starts where the text before it ends."""
    for _ in range(MAX_CHAIN_STEPS):
        head = body[:end].rstrip()
        if not head:
            return 0
        ch = head[-1]
        if ch == "?":
            end = len(head) - 1
            continue
        if ch == "}":
            return None
        if ch in ")]":
            op = open_group(head, len(head) - 1)
            if op < 0:
                return None
            before = head[:op].rstrip()
            if before.endswith("!") and IDENT_END.search(before[:-1]):  # a macro call: vec![..], format!(..)
                start = callee_path(before[:-1])[0]
            elif ch == "]":
                if not before or not (before[-1] in "_)]?" or before[-1].isalnum()):
                    return op  # an array literal
                end = len(before)  # an index `x[i]`
                continue
            else:
                cp = callee_path(before)
                if cp is None or cp[2] in KEYWORDS:
                    if before and before[-1] in ")]?":  # a call on a call result
                        end = len(before)
                        continue
                    return op  # a parenthesised expression or a tuple
                start = cp[0]
            pre = body[:start].rstrip()
            if pre.endswith(".") and not pre.endswith(".."):
                end = len(pre) - 1
                continue
            return start
        m = re.search(r"\w+$", head)
        if m is None:
            return len(head)  # a blank literal
        pre = head[:m.start()].rstrip()
        if m.group(0)[0].isdigit():
            if pre.endswith("."):
                fm = re.search(r"(?<![\w.])\d\w*$", pre[:-1])
                if fm is None:  # a tuple field `.0`
                    end = len(pre) - 1
                    continue
                return fm.start()  # a float literal
            return m.start()
        start = callee_path(head)[0]
        pre = head[:start].rstrip()
        if pre.endswith(".") and not pre.endswith(".."):
            end = len(pre) - 1
            continue
        return start
    return None


def generic_groups(text):
    """[(start, end)] of every turbofish generic-argument list `::<..>` of text, `::` through the closing `>` (#8093, #8100)."""
    out = []
    for m in re.finditer(r"::\s*<", text):
        depth = 0
        for j in range(m.end() - 1, len(text)):
            ch = text[j]
            if ch == "<":
                depth += 1
            elif ch == ">" and text[j - 1:j] != "-":
                depth -= 1
                if depth == 0:
                    out.append((m.start(), j + 1))
                    break
            elif ch in ";{}":
                break
    return out


def blank_generics(text):
    """text with every turbofish generic-argument list `::<..>` replaced by spaces of the same length (#8093)."""
    out = list(text)
    for a, b in generic_groups(text):
        out[a:b] = " " * (b - a)
    return "".join(out)


def declared_generics(text):
    """([generic parameter names], [text of every generics list]) of the items text declares (r11, #8121): the `<..>`
    after `fn name`, `trait Name`, `struct Name`, `enum Name`, `union Name`, `type Name` and `impl`. A lifetime is not
    a name; `const N: usize` declares N; a bound (`T: Bound`) is part of the list text."""
    names, lists = [], []
    for m in GENERIC_OWNER.finditer(text):
        depth, end = 0, -1
        for j in range(m.end() - 1, len(text)):
            ch = text[j]
            if ch == "<":
                depth += 1
            elif ch == ">" and text[j - 1:j] != "-":
                depth -= 1
                if depth == 0:
                    end = j
                    break
            elif ch in ";{}":
                break
        if end < 0:
            continue
        lists.append(text[m.end():end])
        for a, b in split_top_level(text, m.end(), end):
            piece = text[a:b].strip()
            if piece.startswith("'"):
                continue
            pm = re.match(r"(?:const\s+)?([A-Za-z_]\w*)", piece)
            if pm:
                names.append(pm.group(1))
    return names, lists


def trait_positions(text):
    """Every identifier of text that stands where a TRAIT can be named (r11, #8120): a generics list or where clause
    (bounds), the text after `impl` / `dyn` (`impl X for S`, `impl X`, `dyn X`) and `<T as X>`. An imported name found
    here keeps its methods in scope on every receiver, whether or not the file also calls it by name."""
    out = set()
    runs = list(declared_generics(text)[1]) + [m.group(1) for m in TRAIT_RUN.finditer(text)]
    runs += [m.group(1) for m in WHERE_RUN.finditer(text)] + [m.group(1) for m in TRAIT_CAST.finditer(text)]
    for run in runs:
        out.update(IDENT.findall(run))
    return out


def array_len_spans(text):
    """[(start, end)] of the length expression of every array type `[T; N]` of text (r11, #8122): the only place a
    same-file const is neutral in a type text."""
    out, stack = [], []
    for j, ch in enumerate(text):
        if ch == "[":
            stack.append([j, -1])
        elif ch == ";" and stack and stack[-1][1] < 0:
            stack[-1][1] = j + 1
        elif ch == "]" and stack:
            _, semi = stack.pop()
            if semi >= 0:
                out.append((semi, j))
    return out


def return_exprs(body):
    """[(start, end)] of the value expressions a fn body (starting at its `{`) returns (#8098): the tail after the last
    depth-0 `;` of the block, and every `return <expr>`. A unit block has no tail."""
    inner_end = body.rfind("}")
    out, depth, last = [], 0, 1
    for j in range(1, inner_end):
        ch = body[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == ";" and depth == 0:
            last = j + 1
    if body[last:inner_end].strip() and not body[last:inner_end].lstrip().startswith("}"):
        out.append((last, inner_end))
    for m in re.finditer(r"\breturn\b", body):
        end = expr_end(body, m.end())
        if body[m.end():end].strip():
            out.append((m.end(), end))
    return out


def pattern_names(text):
    """The lowercase names a pattern may bind (an over-approximation: a field label counts too, which only makes
    a binding opaque, never trusted)."""
    return [n for n in PATTERN_NAME.findall(text) if n not in PATTERN_SKIP]


def block_after(body, pos):
    """Index of the first `{` at bracket depth 0 at or after pos, or -1 when a `;` or a closer comes first."""
    depth = 0
    for j in range(pos, len(body)):
        ch = body[j]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
            if depth < 0:
                return -1
        elif ch == "{" and depth == 0:
            return j
        elif ch == ";" and depth == 0:
            return -1
    return -1


def arm_arrow(body, pos, end):
    """Index of the `=>` at bracket depth 0 in body[pos:end], or -1."""
    depth = 0
    for j in range(pos, end):
        ch = body[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return -1
        elif ch == "=" and depth == 0 and body[j + 1:j + 2] == ">":
            return j
    return -1


class ScopeMap:
    """Every name a fn body binds, with the span in which the binding is visible (#8094, #8095). A plain
    `let [mut] name [: T] = init;` carries its initialiser and is visible from the end of its statement to the
    end of the block that is open there, so an inner block's `let` stops hiding an outer one once the block
    closes; `for name in <iterable>` binds name like a `let` of the iterable (an item is as safe as its
    collection). Every other binder (a destructuring `let`, a destructuring `for` pattern, a match arm,
    `if let` / `while let`, a closure parameter) is opaque: it shadows an outer name and is never trusted."""

    def __init__(self, body):
        self.items = []
        self._lets(body)
        for m in FOR_HEAD.finditer(body):
            brace = block_after(body, m.end())
            if brace < 0 or m.group(1).lstrip().startswith("<"):
                continue
            hi = match_brace(body, brace)
            sm = re.fullmatch(r"\s*(?:mut\s+)?([A-Za-z_]\w*)\s*", m.group(1))
            if sm and sm.group(1) != "_":  # `for name in <iterable>`: an item is as safe as the iterable it comes from
                self.items.append(Binding(sm.group(1), brace, hi, (m.end(), brace), True))
            else:
                self._opaque(pattern_names(m.group(1)), brace, hi)
        for m in re.finditer(r"\bmatch\b", body):
            brace = block_after(body, m.end())
            if brace >= 0:
                self._arms(body, brace)
        for s, e in closure_literals(body):
            cm = re.match(r"(?:async\s+)?(?:move\s+)?\|([^|]*)\|", body[s:e])
            if cm:
                self._opaque(pattern_names(cm.group(1)), s, e)

    def _opaque(self, names, lo, hi):
        self.items.extend(Binding(n, lo, hi, None) for n in names)

    def _lets(self, body):
        for m in re.finditer(r"\blet\b", body):
            eq, depth = -1, 0
            for j in range(m.end(), len(body)):
                ch = body[j]
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth -= 1
                    if depth < 0:
                        break
                elif ch == ";" and depth == 0:
                    break
                elif ch == "=" and depth == 0 and body[j + 1:j + 2] not in ("=", ">") and body[j - 1:j] not in "=!<>":
                    eq = j
                    break
            if eq < 0:
                continue
            pat = body[m.end():eq]
            if COND_LET.search(body[:m.start()].rstrip()):  # `if let` / `while let`: bound in the block that follows
                brace = block_after(body, eq + 1)
                if brace >= 0:
                    self._opaque(pattern_names(pat), brace, match_brace(body, brace))
                continue
            end = stmt_end(body, eq + 1)
            hi = match_brace(body, scope_open(body, m.start()))
            sm = re.fullmatch(r"\s*(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=]*)?", pat)
            if sm:
                if sm.group(1) != "_":
                    self.items.append(Binding(sm.group(1), end, hi, (eq + 1, end)))
            else:
                self._opaque(pattern_names(pat), end, hi)

    def _arms(self, body, brace):
        end = match_brace(body, brace) - 1
        pos = brace + 1
        while pos < end:
            arrow = arm_arrow(body, pos, end)
            if arrow < 0:
                return
            bs = arrow + 2
            while bs < end and body[bs].isspace():
                bs += 1
            be = match_brace(body, bs) if body[bs:bs + 1] == "{" else min(expr_end(body, bs), end)
            self._opaque(pattern_names(re.split(r"\bif\b", body[pos:arrow], 1)[0]), pos, be)
            pos = be
            while pos < end and (body[pos].isspace() or body[pos] == ","):
                pos += 1

    def visible(self, name, pos):
        """The binding of name in force at pos: the innermost one in an open block (the greatest start), an opaque one
        winning a tie; None when nothing binds it."""
        best = None
        for b in self.items:
            if b.name == name and b.lo <= pos < b.hi \
                    and (best is None or b.lo > best.lo or (b.lo == best.lo and b.init is None)):
                best = b
        return best


def arg_slot(body, a, b):
    """(open paren index, argument index) when body[a:b] is exactly one whole argument of a call, else None."""
    depth, commas, sep = 0, 0, None
    for j in range(a - 1, -1, -1):
        ch = body[j]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                if ch != "(":
                    return None
                sep = j if sep is None else sep
                if body[sep + 1:a].strip() or body[b:].lstrip()[:1] not in (",", ")"):
                    return None
                return j, commas
            depth -= 1
        elif ch == ";" and depth == 0:
            return None
        elif ch == "," and depth == 0:
            sep = j if sep is None else sep
            commas += 1
    return None


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
        self.param_types = {}  # #8106: parameter name -> declared type text (a pattern parameter has none)
        self.ret = None  # #8098: the declared return type text, None when the fn declares none
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


def fn_body_open(text, pos):
    """Index of the `{` that opens the body of the fn whose name ends at pos, or -1 for a declaration without a body
    (a trait item ending in `;`). A `;` inside `[..]` / `(..)`, as in a `-> [T; 5]` return type, does not end the
    signature (#8078), and a `{` inside `[..]`, `(..)` or a generic argument list `<..>` is a const block of the
    signature (`-> A<{ 3 }>`, `[u8; { N * 2 }]`, `where [(); { N }]: Sized`), skipped whole (#8091). The `>` of `->`
    is not a bracket; angle depth is counted outside `(..)` / `[..]` only, where a `<` is a comparison."""
    depth = angle = 0
    j = pos
    while j < len(text):
        ch = text[j]
        if ch == "-" and text[j + 1:j + 2] == ">":
            j += 2
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "<" and depth <= 0:
            angle += 1
        elif ch == ">" and depth <= 0:
            angle = max(0, angle - 1)
        elif ch == "{":
            if depth > 0 or angle > 0:
                j = match_brace(text, j)
                continue
            return j
        elif ch == ";" and depth <= 0 and angle == 0:
            return -1
        j += 1
    return -1


def strip_turbofish(text):
    """text without a trailing `::<..>` generic-argument list (`x.collect::<Vec<_>>`), else text unchanged (#8089)."""
    s = text.rstrip()
    if not s.endswith(">"):
        return text
    depth = 0
    for j in range(len(s) - 1, -1, -1):
        if s[j] == ">":
            depth += 1
        elif s[j] == "<":
            depth -= 1
            if depth == 0:
                return s[:j].rstrip()[:-2].rstrip() if s[:j].rstrip().endswith("::") else text
    return text


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
        brace = fn_body_open(scrubbed, m.end())
        if brace < 0:
            continue
        mods = [b[3] for b in blocks if b[2] == "mod" and b[0] < m.start() < b[1]]
        owners = [b[3] for b in blocks if b[2] == "impl" and b[0] < m.start() < b[1]]
        fn = Fn(m.group(1), mods, owners[-1] if owners else None, attrs,
                scrubbed[brace:match_brace(scrubbed, brace)], brace, m.group(0).startswith("async"))
        fn.params, fn.has_self, fn.param_types = fn_params(scrubbed, m.end(), brace)
        fn.ret = fn_return_type(scrubbed, m.end(), brace)
        fns.append(fn)
    return fns


def fn_return_type(text, name_end, brace):
    """The declared return type of the fn whose name ends at name_end and whose body opens at brace (#8098), else None."""
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
        return None
    m = re.match(r"\s*->\s*(.*?)\s*(?:\bwhere\b.*)?$", text[match_paren(text, k):brace], re.S)
    return m.group(1) if m else None


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
        return (), False, {}
    names, has_self, types = [], False, {}
    for a, b in split_top_level(text, k + 1, match_paren(text, k) - 1):
        piece = text[a:b]
        if re.match(r"\s*(?:&\s*(?:'\w+\s*)?)?(?:mut\s+)?self\b", piece):
            has_self = True
            continue
        m = re.match(r"\s*(?:mut\s+)?([A-Za-z_]\w*)\s*:(?!:)", piece)
        names.append(m.group(1) if m else None)
        if m:
            types[m.group(1)] = piece[m.end():].strip()  # r10 (#8106): the declared type, judged by type_origin
    return tuple(names), has_self, types


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


TRAIT_WORD = re.compile(r"(?<![\w$])trait\b")  # r14 (G1): a macro_rules! body that declares a trait
MAX_ALIAS_PASSES = 16  # r14 (G1): re-export alias levels followed from a trait name; a longer chain stays unresolved


def merge_methods(a, b):
    """The union of two method-name sets where ANY_METHOD (unknown, may be any method) absorbs the other (r14, G1)."""
    return ANY_METHOD if a is ANY_METHOD or b is ANY_METHOD else a | b


def trait_fns(body):
    """The method names a trait body declares, ANY_METHOD when an item-level macro invocation (`mk_fn!();`) can generate
    fns the text does not show (r14, G1). A macro call inside a default method body generates no trait item."""
    top, depth = [], 0
    for ch in body:
        if ch == "}":
            depth -= 1
        top.append(ch if depth <= 0 else " ")
        if ch == "{":
            depth += 1
    return ANY_METHOD if MACRO_CALL.search("".join(top)) else frozenset(FN_NAME.findall(body))


def trait_generators(text):
    """The macro_rules! names whose body declares a trait (r14, G1): each invocation names the traits it generates."""
    return {m.group(1) for m in MACRO_RULES.finditer(text) if TRAIT_WORD.search(text[m.end():match_brace(text, m.end() - 1)])}


class ItemIndex:
    """What the crate's source texts define, decided from the definitions and never from a name's spelling (r14, G1):
    `traits` maps a trait name to the methods it may supply (ANY_METHOD when unknown) and `types` holds the struct /
    enum / union / type names. A name counts as a trait when a `trait` item declares it, when a macro_rules! that
    declares a trait is invoked with it, or when a re-export alias (`pub use path::Real as Name;`) renames a trait,
    whatever else shares the name (a struct of another module never hides it)."""

    def __init__(self, generators=()):
        self.generators = set(generators)  # macro_rules! names, from the whole crate, that declare a trait
        self.traits, self.types, self.aliases = {}, set(), []

    def add_trait(self, name, methods):
        self.traits[name] = merge_methods(self.traits[name], methods) if name in self.traits else methods

    def add(self, text):
        """Index one scrubbed source text."""
        for m in SRC_TRAIT.finditer(text):
            self.add_trait(m.group(1), trait_fns(text[m.end():match_brace(text, m.end() - 1)]))
        self.types.update(SRC_TYPE.findall(text))
        for gen in self.generators | trait_generators(text):
            for m in re.finditer(r"(?<![\w$])%s\s*!\s*[({\[]" % re.escape(gen), text):
                for ident in IDENT.findall(text[m.end():match_paren(text, m.end() - 1)]):
                    self.add_trait(ident, ANY_METHOD)
        for um in USE_ITEM.finditer(text):
            self.aliases.extend((name, path[-1]) for path, name in use_leaves(um.group(0))
                                if name not in (None, "_") and name != path[-1])

    def close(self):
        """Resolve the aliases to a fixpoint (bounded by MAX_ALIAS_PASSES); returns self."""
        for _ in range(MAX_ALIAS_PASSES):
            before = {k: v for k, v in self.traits.items()}
            for name, target in self.aliases:
                if target in self.traits:
                    self.add_trait(name, self.traits[target])
            if before == self.traits:
                break
        return self


class CommonModel:
    """tests/common census: free fns that reach a strong reader, and the vars each helper writes."""

    def __init__(self, root=None):
        self.fns = {}
        self.sources = {}
        self.detachers = {}  # #8052: key -> (parameter indices handed to a spawn, has_self) for EVERY tests/common fn
        self.mod_names = set()  # #8060: module names of tests/common (files, directories, inline mods)
        self.items = set()  # r11: every item name tests/common declares (a glob import of it binds them all)
        self._mods = {}
        self._strong, self._vars = {}, {}
        self.src_consts = self._src_consts(root)
        self.macro_names = set()  # r13 (#8154): every macro_rules! name tests/common defines
        self._mod_macros = {}  # r13 (#8154): module file -> the macro_rules! names it defines (None: unreadable)
        # r13 (#8155, #8157): the crate the tests import (its [package] name), and per src/ trait name the methods it
        # declares; src_types holds the struct / enum / union / type names, which never supply a method
        self.crate_name, self.src_traits, self.src_types = self._src_items(root)
        self.dep_roots = self._dep_roots(root)  # r14 (G2): Cargo.toml `package =` renames: dependency name -> crate
        base = pathlib.Path(root) / COMMON_REL if root is not None else None
        if base is None or not base.is_dir():
            return
        texts = []
        for path in sorted(base.rglob("*.rs")):
            src = Source(path.read_text(encoding="utf-8", errors="replace"), self.src_consts)
            for f in parse_fns(src.scrubbed):
                self.mod_names.update(f.mods)
                if not f.is_test:
                    self.fns.setdefault(f.key, f)
                    self.sources[id(f)] = src
            parts = list(path.relative_to(base).with_suffix("").parts)
            self.mod_names.update(parts)
            text = src.scrubbed
            self.items.update(m.group(1) or m.group(2) for m in ITEM_NAME.finditer(text))
            self.macro_names.update(MACRO_RULES_NAME.findall(text))
            for part in reversed(parts[:-1] if parts[-1] == "mod" else parts):
                text = "mod %s {\n%s\n}" % (part, text)
            texts.append(text)
        # #8060: one fixpoint over every tests/common file, each file wrapped in its module path, so a helper
        # that calls a detaching helper of another common file (`super::spawn::bg(f)`) detaches too.
        self.detachers = detaching_fns("mod common {\n%s\n}" % "\n".join(texts))

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

    @staticmethod
    def _src_items(root):
        """(crate name, {trait name: method names}, type names) of the crate under root (r13, #8155, #8157). The
        crate name is the Cargo.toml [package] name with `-` read as `_` (None without a manifest); a trait name
        declared twice keeps the union of the method names, which only widens what it may supply."""
        if root is None:
            return None, {}, set()
        root = pathlib.Path(root)
        crate_name = None
        try:
            m = PACKAGE_NAME.search((root / CARGO_MANIFEST).read_text(encoding="utf-8", errors="replace"))
            crate_name = m.group(1).replace("-", "_") if m else None
        except OSError:
            crate_name = None
        base = root / SRC_REL
        if not base.is_dir():
            return crate_name, {}, set()
        files = sorted(base.rglob("*.rs"))
        generators = set()  # first pass: every macro_rules! of the crate that declares a trait
        for path in files:
            raw = path.read_text(encoding="utf-8", errors="replace")
            if "macro_rules" in raw and "trait" in raw:
                generators |= trait_generators(scrub(raw))
        index = ItemIndex(generators)
        for path in files:
            index.add(scrub(path.read_text(encoding="utf-8", errors="replace")))
        index.close()
        return crate_name, dict(index.traits), index.types

    @staticmethod
    def _dep_roots(root):
        """{dependency name: the crate it really is} for the renamed dependencies of Cargo.toml (r14, G2). Stdlib
        `tomllib` is not in Python 3.9, so this reads the manifest line by line: a `[dependencies]`,
        `[dev-dependencies]`, `[build-dependencies]`, `[workspace.dependencies]` or `[target.<cfg>.dependencies]` table
        holding `name = { package = "x", .. }` or `name.package = "x"`, and a `[dependencies.name]` table holding
        `package = "x"`. Names read `-` as `_`. A name that two tables point at different crates maps to DEP_AMBIGUOUS,
        which no trust table lists; a name that every entry leaves as itself is not renamed and is left out."""
        if root is None:
            return {}
        try:
            lines = (pathlib.Path(root) / CARGO_MANIFEST).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return {}
        seen, table, entry = {}, False, None  # name -> set of real crates; in a dependency table; in [dependencies.name]
        for line in lines:
            line = line.strip()
            if line.startswith("["):
                m = DEP_HEADER.match(line)
                table = bool(m) and not m.group(1)
                entry = m.group(1).strip(DEP_QUOTES).replace("-", "_") if m and m.group(1) else None
                if entry:
                    seen.setdefault(entry, set()).add(entry)
                continue
            if entry:
                m = DEP_PACKAGE.match(line)
                if m:
                    seen[entry].discard(entry)
                    seen[entry].add(m.group(1).replace("-", "_"))
            elif table:
                dotted = DEP_DOTTED_PACKAGE.match(line)
                if dotted:
                    name = dotted.group(1).replace("-", "_")
                    seen.setdefault(name, set()).add(dotted.group(2).replace("-", "_"))
                    continue
                m = DEP_ENTRY.match(line)
                if m:
                    name = m.group(1).replace("-", "_")
                    pkg = DEP_PACKAGE.search(m.group(2))
                    seen.setdefault(name, set()).add(pkg.group(1).replace("-", "_") if pkg else name)
        return {name: (next(iter(real)) if len(real) == 1 else DEP_AMBIGUOUS)
                for name, real in seen.items() if real != {name}}

    def module_macros(self, path, raw):
        """The macro_rules! names that the `#[path = ".."] mod m;` / `mod m;` files a test file declares define, plus
        those of tests/common (r13, #8154). A `#[macro_use]` module puts them in textual scope ahead of a `use`d
        macro of the same name; the gate does not track which module carries the attribute, so every one counts. The
        walk is transitive (r14, G3): every `mod x;` that a module file declares, at any depth and inside any inline
        `mod y { .. }`, is read in turn; a file read once is not read again, so a cycle ends."""
        out, seen = set(self.macro_names), set()
        for rel, name, base in self._mod_decls(raw, pathlib.Path(path).parent, pathlib.Path(path).parent):
            if name != "common":
                out |= self._mod_file_macros(rel, name, base, seen)
        return out

    @staticmethod
    def _mod_decls(raw, base, path_base):
        """[(path attribute or None, module name, directory it is declared relative to)] for each `mod m;` of raw. The
        directory is base (or path_base for a `#[path]` attribute) plus the name of every inline `mod y { .. }` that
        encloses the declaration (r14, G3)."""
        scrubbed, out = scrub(raw), []
        for m in MOD_DECL.finditer(raw):
            here = path_base if m.group(1) else base
            for inline in INLINE_MOD.finditer(scrubbed, 0, m.start()):
                if match_brace(scrubbed, inline.end() - 1) > m.start():
                    here = here / inline.group(1)
            out.append((m.group(1), m.group(2), here))
        return out

    def _mod_file_macros(self, rel, name, base, seen):
        """The macro_rules! names of the module file that `mod name;` declares and of every module file below it."""
        cands = [base / rel] if rel else [base / (name + ".rs"), base / name / "mod.rs"]
        for cand in cands:
            if cand not in self._mod_macros:
                try:
                    text = cand.read_text(encoding="utf-8", errors="replace")
                    self._mod_macros[cand] = (set(MACRO_RULES_NAME.findall(scrub(text))), text)
                except OSError:
                    self._mod_macros[cand] = None
            if self._mod_macros[cand] is None:
                continue
            if cand in seen:
                return set()
            seen.add(cand)
            out, text = set(self._mod_macros[cand][0]), self._mod_macros[cand][1]
            below = cand.parent if cand.name == "mod.rs" else cand.parent / cand.stem
            for crel, cname, cbase in self._mod_decls(text, below, cand.parent):
                out |= self._mod_file_macros(crel, cname, cbase, seen)
            return out
        return set()

    def path_modules(self, path, raw):
        """{module name: detaching_fns} for the `#[path = ".."] mod m;` and `mod m;` files a test file declares
        (#8052). A file that is missing is skipped; tests/common is the common census, not a module."""
        out, here = {}, pathlib.Path(path).parent
        for m in MOD_DECL.finditer(raw):
            name = m.group(2)
            if name == "common":
                continue
            cands = [here / m.group(1)] if m.group(1) else [here / (name + ".rs"), here / name / "mod.rs"]
            for cand in cands:
                if cand not in self._mods:
                    try:
                        text = cand.read_text(encoding="utf-8", errors="replace")
                        self._mods[cand] = detaching_fns(blank_use_items(scrub(text)))
                    except OSError:
                        self._mods[cand] = None
                if self._mods[cand] is not None:
                    out[name] = self._mods[cand]
                    break
        return out

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


ORIGIN_RULES = {}  # r11 (#8125): rule name -> FileModel method; every method that classifies by an origin predicate


def origin_rule(method):
    """Register a FileModel method as a classifying rule in ORIGIN_RULES. The unit tests derive their rule inventory
    from this mapping and from the AST (every method that calls an origin predicate must be registered), so a rule
    cannot be added without a RED probe: a hand-kept list of rule names cannot go stale."""
    ORIGIN_RULES[method.__name__] = method
    return method


class FileModel:
    """Write sites, their protection sets, lock acquisitions and readers of one tests/*.rs."""

    def __init__(self, scrubbed, raw=None, common=None, modules=None, macros=None):
        self.common = common if common is not None else CommonModel()
        # r13 (#8154): macro_rules! names of the declared module files and tests/common (CommonModel.module_macros)
        self.module_macros = set(macros or ()) | self.common.macro_names
        self.imports, self.glob = common_imports(scrubbed)
        self.modules = modules or {}  # #8052: module name -> detaching_fns of its file
        self.mod_imported = {}  # name -> module it is `use`-imported from
        for um in USE_ITEM.finditer(scrubbed):
            for mod in self.modules:
                if re.search(r"\b%s\s*::" % re.escape(mod), um.group(0)):
                    for n in IDENT.findall(um.group(0).split(mod, 1)[1]):
                        self.mod_imported.setdefault(n, mod)
        self.aliases = {}  # #8059: `use path::name as alias;` -> alias: name
        for um in USE_ITEM.finditer(scrubbed):
            for orig, alias in USE_ALIAS.findall(um.group(0)):
                self.aliases.setdefault(alias, orig)
        self.dm = mutation_re(use_aliases(scrubbed))
        with_uses = scrubbed  # r10: the import table is read from the text that still holds the `use` items
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
        self._detached, self._lits = {}, {}
        self._encl, self._viol, self._ip_only = {}, {}, {}
        self._close_detachers(macro_bodies)
        self.inline = {}  # #8065: id(fn) -> indices of the parameters the fn PROVABLY only calls on its own thread
        self.parallel = set()  # #8069: id(fn) of the fns whose body (or a callee's) builds a parallel iterator
        self._fn_lits = {}
        self.text = scrubbed
        self._index_items(scrubbed)  # #8098: the same-file consts, statics, structs and enum variants span_safe resolves
        self._index_imports(with_uses, scrubbed)  # r10: what every name of the file is bound to (type_origin)
        self._ret_ok, self._ret_stack, self._closure_memo, self._closure_stack = set(), [], {}, set()
        self._closed = False  # the verdicts are cached only once the parallel set stops growing
        self._close_inline()
        self._closed = True
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
        for m in VALUE_DETACH.finditer(body):
            # #8057: spawn used as a fn value may run any same-file fn item detached; every one is reached
            # from the (detached) position of the name, with an empty context.
            out.extend((m.start(), hit, m.end(), False) for hit in self.by_key.values() if hit is not fn)
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
            hits = [(self.helpers.get(id(c), ()), c.has_self) for c in cands]
            if not cands:
                hits += [(h.idxs, h.has_self) for h in self.external_helpers(m.group(1), m.group(2), method)]
            for idxs, has_self in hits:
                for i in idxs:
                    args = split_top_level(body, m.end(), match_paren(body, m.end() - 1) - 1) if args is None else args
                    j = i + (0 if method or not has_self else 1)
                    if j < len(args):
                        out.append(args[j])
        return out

    def external_helpers(self, prefix, name, method):
        """[(parameter indices, has_self)] of the detaching fns outside this file that a call may reach (#8052):
        `common::f`, a `use`-imported or glob-imported tests/common name, `Type::f` of an imported common type,
        `m::f` of a declared module file, or a `use`-imported name of one; a method call matches any common
        method of that name. An unresolvable call is none. #8059: a `use .. as alias` name or module is resolved to
        the name it stands for. #8060: a nested path (`common::a::b::f`) reaches the fn of a submodule file, and
        the table (see CommonModel) lists every known fn, a non-detaching one with no indices, so a hit means
        the callee is known."""
        segs, table = [self.aliases.get(s, s) for s in path_segments(prefix)], self.common.detachers
        real = name if method else self.aliases.get(name, name)
        if method:
            return [hit for key, hit in table.items() if key.endswith("::" + real) and hit[1]]
        if not segs:
            if real in self.mod_imported:
                return [h for h in [self.modules[self.mod_imported[real]].get(real)] if h]
            return [h for h in [table.get(real)] if h] if (real in self.imports or self.glob) else []
        if segs[-1] in self.modules:
            return [h for h in [self.modules[segs[-1]].get(real)] if h]
        if "common" in segs or segs[-1] in self.imports or self.glob:
            keys = ["%s::%s" % (segs[-1], real), real] if "common" in segs or segs[-1] in self.common.mod_names \
                else ["%s::%s" % (segs[-1], real)]
            return [h for h in [table.get(k) for k in keys] if h]
        return []

    def literal_spans(self, fn):
        """[(start, end)] of every closure or async-block literal of fn that runs detached (#8056): ALL of them
        unless one is PROVEN to run on this thread (see same_thread): credit is positive proof, never the mere
        absence of a spawn. Never credits otherwise."""
        if id(fn) in self._lits:
            return self._lits[id(fn)]
        body = fn.body
        lits = closure_literals(body)
        if VALUE_DETACH.search(body):  # #8057: spawn used as a fn value hands anything it is mapped over away
            out = list(lits) + [(lm.end(), stmt_end(body, lm.end())) for lm in re.finditer(ANY_CLOSURE_LET, body)]
            out += [(m.start(), m.end()) for m in VALUE_DETACH.finditer(body)]
        else:
            out = [lit for n, lit in enumerate(lits) if not self.same_thread(fn, lits, n)]
        out += self.future_spans(fn)  # r11 (#8123): a future-valued call is a closure value too
        self._lits[id(fn)] = out
        return out

    def lits(self, fn):
        """closure_literals of fn, cached."""
        if id(fn) not in self._fn_lits:
            self._fn_lits[id(fn)] = closure_literals(fn.body)
        return self._fn_lits[id(fn)]

    def same_thread(self, fn, lits, n):
        """True when literal lits[n] of fn is PROVEN to run on this thread before fn returns (#8056, #8065, #8066).
        Exactly these shapes: (1) invoked in place, `(|| ..)()`; (2) `let name = <literal>;` whose every later use in
        its scope is a direct call `name(..)` outside every other closure literal; (3) the tail value of a
        same-thread closure whose own value is consumed in place (`mk()()`, or `let v = mk();` that is only
        called; an async block only when awaited); (4) the whole argument of a callee that provably runs it inline
        (arg_inline). Anything else is detached."""
        body, (s, e) = fn.body, lits[n]
        is_async = bool(re.match(r"async\b", body[s:]))
        if ASYNC_CLOSURE.match(body, s):  # r12 (#8139): `async |..| ..` yields a future per call, it is not a future itself
            return self.async_closure_same_thread(fn, lits, (s, e))
        if body[:s].rstrip().endswith("(") and CALL_OPENER.match(body, e):
            return True
        if is_async and AWAITED.match(body, e):  # r11: an async block awaited in place
            return True
        head = CLOSURE_LET_HEAD.fullmatch(stmt_prefix(body, s))
        if head and body[e:].lstrip().startswith(";"):
            return self.only_called(body, lits, head.group(1), e, (s, e), is_async)
        for k, (ks, ke) in enumerate(lits):
            if k != n and ks < s and e <= ke and body[e:ke].strip() in ("", "}") and CLOSURE_TAIL_HEAD.match(body, ks):
                return self.same_thread(fn, lits, k) and self.value_inline(fn, lits, k, body.startswith("async", s))
        return self.arg_inline(fn, s, e, is_async)

    def async_closure_same_thread(self, fn, lits, span):
        """True when the async closure literal body[span] only ever yields futures that are driven in place (r12,
        #8139): it is invoked in place, `(async || ..)()`, or bound by a plain `let f = async || ..;` whose every use is
        a call `f(..)`; each call yields a future that must be credited like an async fn call (future_credited). Handed
        whole to a callee instead, it runs wherever that callee decides: arg_inline decides, as for any closure."""
        body, (s, e) = fn.body, span
        opener = CALL_OPENER.match(body, e)
        if body[:s].rstrip().endswith("(") and opener:
            return self.future_credited(fn, lits, (len(body[:s].rstrip()) - 1, match_paren(body, opener.end() - 1)))
        head = CLOSURE_LET_HEAD.fullmatch(stmt_prefix(body, s))
        if not (head and body[e:].lstrip().startswith(";")):
            return self.arg_inline(fn, s, e, True)
        for um in scope_uses(body, head.group(1), e):
            op = body.find("(", um.end())
            if not re.match(r"\s*\(", body[um.end():]) or op < 0:
                return False
            if any(x <= um.start() < y for x, y in lits if not (x <= s and e <= y)):
                return False
            if not self.future_credited(fn, lits, (um.start(), match_paren(body, op))):
                return False
        return True

    def future_credited(self, fn, lits, call):
        """True when the future that the call expression body[call[0]:call[1]] yields is driven in place: awaited, bound
        by a `let` that is only awaited (value_consumed), the whole argument of a resolved runner or wrapper
        (arg_inline), or an argument of a resolved join / select macro (await_macro_arg)."""
        return (self.value_consumed(fn, lits, call, True) or self.arg_inline(fn, call[0], call[1], True)
                or self.await_macro_arg(fn, call))

    @staticmethod
    def only_called(body, lits, name, start, anchor, awaited=False):
        """True when every use of `name` after start in its scope is a direct call `name(..)` (`name.await` when
        awaited) outside every closure literal that does not enclose anchor (#8056, #8066)."""
        for um in scope_uses(body, name, start):
            if not re.match(r"\s*\.\s*await\b" if awaited else r"\s*\(", body[um.end():]):
                return False
            if any(x <= um.start() < y for x, y in lits if not (x <= anchor[0] and anchor[1] <= y)):
                return False
        return True

    def value_inline(self, fn, lits, k, is_async):
        """True when the value that closure lits[k] returns is consumed in place at every call of lits[k] (#8066):
        `mk()()` or `let v = mk(); v();`, or `.await` for an async block. lits[k] must itself be invoked in place or
        be a plain `let` that is only called; a value passed on in any other way is detached."""
        body, (ks, ke) = fn.body, lits[k]
        calls, opener = [], CALL_OPENER.match(body, ke)
        if body[:ks].rstrip().endswith("(") and opener:
            calls.append((len(body[:ks].rstrip()) - 1, match_paren(body, opener.end() - 1)))
        else:
            head = CLOSURE_LET_HEAD.fullmatch(stmt_prefix(body, ks))
            if not (head and body[ke:].lstrip().startswith(";")):
                return False
            for um in scope_uses(body, head.group(1), ke):
                op = body.find("(", um.end())
                if not re.match(r"\s*\(", body[um.end():]) or op < 0:
                    return False
                calls.append((um.start(), match_paren(body, op)))
        if is_async:  # r12 (#8139): `|| async {..}` called as `block_on(f())`: the call's future goes to a runner
            return all(self.future_credited(fn, lits, call) for call in calls)
        return all(self.value_consumed(fn, lits, call, is_async) for call in calls)

    def value_consumed(self, fn, lits, call, is_async):
        """True when the call expression body[call[0]:call[1]] yields a closure that is invoked (an async block:
        awaited) right there, or bound by a plain `let v = <call>;` that is only ever called (awaited)."""
        body, (cs, ce) = fn.body, call
        rest = body[ce:]
        if re.match(r"\s*\.\s*await\b" if is_async else r"\s*\(", rest):
            return True
        head = CLOSURE_LET_HEAD.fullmatch(stmt_prefix(body, cs))
        return bool(head and rest.lstrip().startswith(";")
                    and self.only_called(body, lits, head.group(1), ce, call, is_async))

    def callee_origin(self, segs, name, kind):
        """STD, CRATE or UNKNOWN for a callee that the gate would trust to run its argument on this thread (r12, #8136,
        #8137; r13, #8154-#8158): the ONE predicate of the credit side, as type_origin is of the classification side.
        Every callee is first RESOLVED to a crate-qualified path and trusted only when that whole path is on an
        allowlist: a macro when it resolves into AWAIT_MACROS, a free fn when it resolves into TRUSTED_FN_PATHS, a
        method when method_path resolves it into TRUSTED_METHOD_PATHS (no in-scope non-std trait, `as _` import or
        glob may supply a method of that name). A bare macro name that a `macro_rules!` of the file, of a declared
        module file or of tests/common defines resolves to nothing, because textual macro scope wins over a `use`
        (#8154). CRATE when the path resolves anywhere else, UNKNOWN when nothing resolves (a glob, an item of the
        file, a generic, a shadowing macro_rules!). Both CRATE and UNKNOWN are DETACHED: no name is trusted for how it
        is spelled, so a shadow of a trusted name is never trusted."""
        if kind == CALLEE_METHOD:
            full = self.method_path(name)
            return STD if full in TRUSTED_METHOD_PATHS else UNKNOWN
        if kind == CALLEE_MACRO and not segs and name in self.macro_names:
            return UNKNOWN
        full = self.resolve_path(list(segs) + [name])
        if full is None:
            return UNKNOWN
        if kind == CALLEE_MACRO:
            return STD if full in AWAIT_MACROS else CRATE
        return STD if full in TRUSTED_FN_PATHS else CRATE

    def method_path(self, name):
        """The resolved path of a method call `.name(..)` on a receiver whose type the gate cannot name (r13, #8155):
        (STD_METHOD_ROOT, name) when no in-scope non-std method provider (FileModel.providers: an imported trait, an
        `as _` import, a glob) may supply a method of that name, so only a std inherent or std trait method can be
        called; else None. The resolver never looks at whether the name is trusted, only at who may supply it."""
        for supplied in self.providers:
            if supplied is ANY_METHOD or name in supplied:
                return None
        full = (STD_METHOD_ROOT, name)
        return full

    @origin_rule
    def arg_inline(self, fn, a, b, future=False):
        """True when body[a:b] is a whole call argument that the callee PROVABLY runs on this thread (#8065, #8068,
        #8069). A resolved callee (same file, tests/common, module, alias or nested path) must have that parameter
        in its inline-only set (see param_inline); an unresolved one is trusted only as a known inline runner named
        by its FULL path (INLINE_ROOTS) or as a method of a receiver whose chain roots in a local, a literal, a std
        path or a callee that builds no parallel iterator. An unresolved free function is detached."""
        body = fn.body
        slot = arg_slot(body, a, b)
        tail = CALLEE_TAIL.search(body, 0, slot[0]) if slot else None
        if tail is None or tail.group(2) in ("if", "while", "match", "for", "return"):
            return False
        before = body[:tail.start()].rstrip()
        if re.search(r"\bfn$", before) or before.endswith("!"):
            return False
        prefix, name = tail.group(1), tail.group(2)
        method = before.endswith(".")
        if method:
            cands = self.by_method.get(name, [])
        else:
            hit = self.resolve(fn.owner, prefix, name)
            cands = [hit] if hit is not None else []
        facts = [(self.inline.get(id(c), EMPTY), c.has_self) for c in cands]
        if not cands:
            facts = [(h.inline, h.has_self) for h in self.external_helpers(prefix, name, method)]
        if future:  # r11 (#8123): a future is a closure VALUE, credited only by a known runner at the first slot
            return not facts and self.future_arg_inline(fn, tail, slot, before, method)
        if not facts and self.aliases.get(name, name) == RUNNER_NAME:  # a runner is judged by its resolved path
            return self.future_arg_inline(fn, tail, slot, before, method)
        if facts:
            return all(
                slot[1] - (0 if method or not has_self else 1) >= 0
                and slot[1] - (0 if method or not has_self else 1) in idxs for idxs, has_self in facts)
        if id(fn) in self.parallel or PARALLEL_ITER.search(body):  # a test fn is outside the fixpoint (#8089)
            return False
        segs = path_segments(prefix)
        if self.callee_origin(segs, name, CALLEE_METHOD if method else CALLEE_FN) != STD:
            return False  # r12: the callee is trusted by its resolved path (a method: by trait_risk), never by name
        if method:
            return self.receiver_ok(fn, len(before) - 1, elements=False, direct=True)
        full = self.resolve_path(segs + [name])
        if full in WRAPPER_CALLEES:
            return self.arg_inline(fn, tail.start(), match_paren(body, slot[0]))
        return True

    def resolve_path(self, segs):
        """The full path that the path segs stands for (r11, #8124; r13, #8156): a first segment imported by a `use`
        item (std or not, renames included) or bound by `extern crate X as A;` is replaced by the path it is imported
        from, and an `extern crate` alias at the head of that import path by its crate; a first segment that nothing
        in the file binds (no `use`, item, generic or extern crate alias) and that names an inline-runner crate
        (INLINE_ROOTS) is itself the full path; else None."""
        if not segs:
            return None
        first, kind = segs[0], self.symbols.get(segs[0])
        if kind in (SYM_STD, SYM_FOREIGN) and first in self.import_paths:
            return self.resolve_extern(tuple(self.import_paths[first]) + tuple(segs[1:]))
        if kind is not None:
            return None
        full = self.rename_root(segs)
        return full if full[0] in INLINE_ROOTS else None

    def rename_root(self, path):
        """path with its first segment replaced by the crate Cargo.toml says that dependency name is (r14, G2): a
        `tk = { package = "tokio" }` root is tokio, a `futures = { package = "other" }` root is NOT futures. Every
        root is mapped before any INLINE_ROOTS or allowlist test, so a name never vouches for a crate."""
        path = tuple(path)
        real = self.common.dep_roots.get(path[0]) if path else None
        return (real,) + path[1:] if real else path

    @origin_rule
    def type_runtime(self, text):
        """The resolved runtime root (RUNTIME_ROOTS) a type text names, else None (r11, #8124): exactly one path of
        the text resolves to a runtime root and every other path is std (a Result of one, a borrow of one)."""
        roots = []
        for m in IDPATH.finditer(text or ""):
            segs = re.split(r"\s*::\s*", m.group(0))
            full = self.resolve_path(segs)
            if full in RUNTIME_ROOTS:
                roots.append(full)
            elif self.path_origin(segs) != STD:
                return None
        return roots[0] if len(roots) == 1 else None

    def runtime_value(self, fn, start, end, hops=0):
        """The runtime root (RUNTIME_ROOTS) that the value expression body[start:end] of fn provably is, else None
        (r11, #8124): a root call (`Runtime::new()`, `Handle::current()`, a `Builder` chain that reaches `build`)
        followed only by RUNTIME_LINKS, a same-file fn whose declared return type names the runtime, a parameter or
        const whose declared type does, or a local bound once to one of these (at most MAX_REBIND_HOPS names)."""
        body, links = fn.body, set()
        if hops > MAX_REBIND_HOPS:
            return None
        text = body[start:end].strip()
        while True:
            text = text.rstrip("? \t\r\n").lstrip("& \t\r\n")
            if not text.endswith(")"):
                break
            op = open_group(text, len(text) - 1)
            s = strip_turbofish(text[:op].rstrip()) if op > 0 else ""
            cp = callee_path(s) if s else None
            if cp is None:
                return None
            cstart, prefix, name = cp
            pre = s[:cstart].rstrip()
            if pre.endswith(".") and not prefix:
                if name not in RUNTIME_LINKS:
                    return None
                links.add(name)
                text = pre[:-1]
                continue
            if prefix:
                full = self.resolve_path(path_segments(prefix) + [name])
                root = full[:-1] if full else None
                if root not in RUNTIME_ROOTS or (root[-1] == "Builder" and "build" not in links):
                    return None
                return ("tokio", "runtime", "Runtime") if root[-1] == "Builder" else root
            hit = self.by_key.get(name)
            return self.type_runtime(hit.ret) if hit is not None and not hit.is_async else None
        m = re.fullmatch(r"(?:mut\s+)?([A-Za-z_]\w*)", text)
        if m is None or links - {"clone", "handle", "unwrap", "expect"}:
            return None
        name = m.group(1)
        bound = self.scopes(fn).visible(name, start)
        if bound is not None:
            if bound.init is None:
                return None
            typed = self.let_type(body, bound.init[0])
            if typed is not None:
                return self.type_runtime(typed)
            return self.runtime_value(fn, bound.init[0], bound.init[1], hops + 1)
        if name in fn.params:
            return self.type_runtime(fn.param_types.get(name))
        if self.consts.get(name) is not None:
            return self.type_runtime(self.consts[name][2])
        return None

    @staticmethod
    def let_type(body, init_start):
        """The declared type text of the `let` whose initialiser starts at init_start, else None."""
        heads = [h.start() for h in re.finditer(r"\blet\b", body[:init_start])]
        m = re.match(r"let\b[^:=]*?:(?!:)(.*)=$", body[heads[-1]:init_start].rstrip(), re.S) if heads else None
        return m.group(1) if m else None

    def runtime_runner(self, fn, prefix, name, method, dot):
        """True when the call `prefix + name` (a method whose receiver chain ends at body[dot] when method) is a
        known runtime runner (RUNTIME_RUNNERS) by its RESOLVED path (r11, #8124): `futures::executor::block_on`
        however imported, or `block_on` on a receiver that provably is a tokio `Runtime` or `Handle`."""
        if method:
            start = chain_start(fn.body, dot)
            root = self.runtime_value(fn, start, dot) if start is not None else None
            return root is not None and root + (RUNNER_NAME,) in RUNTIME_RUNNERS
        return self.resolve_path(path_segments(prefix) + [name]) in RUNTIME_RUNNERS

    def future_arg_inline(self, fn, tail, slot, before, method):
        """True when the future that is the whole argument of the call at `tail` runs to completion on this thread,
        in place (r11, #8123, #8124): the callee is a runner (runtime_runner) given the future as its first
        argument, or a FUTURE_WRAPPERS call (`tokio::time::timeout`) at the right slot whose own result is consumed
        in place. Anything else, an unresolved callee included, hands the future away: detached."""
        body, prefix, name = fn.body, tail.group(1), tail.group(2)
        if id(fn) in self.parallel or PARALLEL_ITER.search(body):
            return False
        if self.aliases.get(name, name) == RUNNER_NAME:
            return slot[1] == 0 and self.runtime_runner(fn, prefix, name, method, len(before) - 1)
        full = None if method else self.resolve_path(path_segments(prefix) + [name])
        if full in FUTURE_WRAPPERS and slot[1] == FUTURE_WRAPPERS[full]:
            call = (tail.start(), match_paren(body, slot[0]))
            return self.value_consumed(fn, self.lits(fn), call, True) or self.arg_inline(fn, call[0], call[1], True)
        return False

    def future_spans(self, fn):
        """[(start, end)] of every call in fn that yields a future and is not PROVEN to be driven in place (r11,
        #8123): a call of a same-file async fn or of a fn declared to return a future, or of an async fn of
        tests/common. Credited like an async block: awaited in place, bound by a `let` that is only awaited, the
        whole argument of a runner or wrapper (arg_inline), or an argument of a join / select macro. A call of that
        kind handed to anything else runs wherever the callee decides, so the span detaches it."""
        body, out = fn.body, []
        for m in CALL.finditer(body):
            head = body[:m.start()].rstrip()
            name, method = m.group(2), head.endswith(".") and not head.endswith("..")
            if re.search(r"\bfn$", head) or name in KEYWORDS:
                continue
            if method:
                cands = self.by_method.get(name, [])
            else:
                hit = self.resolve(fn.owner, m.group(1), name)
                cands = [hit] if hit is not None else []
            if cands:
                fut = any(c.is_async or FUTURE_RET.search(c.ret or "") for c in cands)
            else:
                fut = (not method and not m.group(1).strip() and name in self.async_names
                       and (name in self.imports or bool(self.glob)))  # a bare tests/common async fn
            if not fut:
                continue
            start = chain_start(body, len(head) - 1) if method else m.start()
            call = (m.start() if start is None else start, match_paren(body, m.end() - 1))
            if not self.future_credited(fn, self.lits(fn), call):
                out.append(call)
        return out

    @origin_rule
    def await_macro_arg(self, fn, call):
        """True when body[call[0]:call[1]] is a whole argument of a macro that RESOLVES into AWAIT_MACROS
        (`tokio::join!`, `use futures::join; join!`), which polls it on the calling task (r11, #8123; r12, #8136): the
        macro path is resolved like a runner's, so a crate macro of the same name, a `macro_rules!` of the file and a
        bare name nothing imports are all detached."""
        slot = arg_slot(fn.body, call[0], call[1])
        before = fn.body[:slot[0]].rstrip() if slot else ""
        m = CALLEE_TAIL.search(before[:-1]) if before.endswith("!") else None
        return bool(m) and self.callee_origin(path_segments(m.group(1)), m.group(2), CALLEE_MACRO) == STD

    def scopes(self, fn):
        """ScopeMap of fn, cached."""
        cache = self.__dict__.setdefault("_scope_maps", {})
        if id(fn) not in cache:
            cache[id(fn)] = ScopeMap(fn.body)
        return cache[id(fn)]

    def _index_items(self, text):
        """The same-file items span_safe needs to resolve a name (#8098): struct / union names, enum variants and
        const / static initialisers as (start, end) in text (None when the name is declared twice)."""
        self.adts, self.variants, self.consts = set(), {}, {}
        for m in re.finditer(r"\b(?:struct|union)\s+([A-Za-z_]\w*)", text):
            self.adts.add(m.group(1))
        for m in re.finditer(r"\benum\s+([A-Za-z_]\w*)[^{;]*\{", text):
            end, depth, names, item = match_brace(text, m.end() - 1) - 1, 0, set(), ""
            for j in range(m.end(), end + 1):
                ch = text[j] if j < end else ","
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth -= 1
                if ch == "," and depth == 0:
                    first = IDENT.findall(re.sub(r"#\s*\[.*?\]", "", item, flags=re.S))
                    if first:
                        names.add(first[0])
                    item = ""
                else:
                    item += ch
            self.variants.setdefault(m.group(1), set()).update(names)
        for m in re.finditer(r"\b(?:const|static)\s+(?:mut\s+)?([A-Za-z_]\w*)\s*:(?!:)", text):
            if text[:m.start()].rstrip()[-1:] in ("<", ",", "*"):
                continue  # a const generic parameter or a raw pointer type
            depth, eq = 0, -1
            for j in range(m.end(), len(text)):
                ch = text[j]
                if ch in "<([":
                    depth += 1
                elif ch in ")]" or (ch == ">" and text[j - 1:j] != "-"):
                    depth -= 1
                elif ch in "{}" or (ch == ";" and depth <= 0):
                    break
                elif ch == "=" and depth <= 0 and text[j + 1:j + 2] not in ("=", ">"):
                    eq = j + 1
                    break
            if eq < 0:
                continue
            span = (eq, stmt_end(text, eq), text[m.end():eq - 1])
            self.consts[m.group(1)] = None if m.group(1) in self.consts else span

    def _index_imports(self, with_uses, text):
        """What every name of the file is bound to (r10, #8103, #8105): std_names (name -> std path) from
        `use std::|core::|alloc::` items, foreign_names from every other import (a non-std import of a name wins
        over a std one), foreign_globs (non-std globs other than `super::*` / tests/common), items (every type,
        struct, enum, union, trait, const, static, fn, mod and macro_rules name the file defines) and trait_risk:
        a non-std glob exists, or a non-std import that nothing in the file uses as a value or a plain type (an
        imported trait, whose methods can shadow a std method, even when it is named in a bound, `impl X for`, `dyn X`,
        `impl X` or a cast) exists. r11 (#8120-#8122): also import_paths (name -> full import path), generics and
        symbols, the one file-scope table that path_origin and type_origin consult before any std naming."""
        self.std_names, self.foreign_names, self.foreign_globs, imported = {}, set(), [], []
        self.import_paths, common_glob = {}, False  # r11: name -> the full path it is imported from
        for um in USE_ITEM.finditer(with_uses):
            for path, name in use_leaves(um.group(0)):
                common = "common" in path
                if name is not None and name != "_":
                    self.import_paths[name] = path
                if path[0] in STD_ROOTS:
                    if name is not None:
                        self.std_names[name] = path
                elif name is None:
                    common_glob = common_glob or common
                    if path != ("super",) and not common:
                        self.foreign_globs.append(path)
                else:
                    self.foreign_names.add(name)
                    if not common:
                        imported.append((path, name))
        self.extern_paths = {}  # r13 (#8156): `extern crate X as A;` -> A: (X,); a crate root the file binds
        for crate, alias in EXTERN_CRATE.findall(with_uses):
            if alias and alias != "_":
                self.extern_paths[alias] = CRATE_ROOT if crate == EXTERN_SELF else (crate,)
        for alias, path in self.extern_paths.items():
            self.import_paths[alias] = path
            if path[0] in STD_ROOTS:
                self.std_names[alias] = path
            else:
                self.foreign_names.add(alias)
        for name in self.foreign_names:
            self.std_names.pop(name, None)
        self.items = {m.group(1) or m.group(2) for m in ITEM_NAME.finditer(text)}
        self.macro_defs = {m.group(2) for m in ITEM_NAME.finditer(text) if m.group(2)}
        self.macro_names = self.macro_defs | self.module_macros  # r13 (#8154): every macro_rules! in textual scope
        self.generics = set(declared_generics(text)[0])
        # r11 (#8120-#8122): the ONE file-scope symbol table. Every name the file binds, in the order of weakest to
        # strongest; a name the table holds is never taken for the std name it is spelled like.
        self.symbols = {n: SYM_STD for n in self.std_names}
        self.symbols.update({n: SYM_ITEM for n in self.items | (self.common.items if common_glob else set())})
        self.symbols.update({n: SYM_FOREIGN for n in self.foreign_names})
        self.symbols.update({n: SYM_GENERIC for n in self.generics})
        traits = trait_positions(text)  # an imported name used as a bound / impl target keeps its methods in scope
        # r13 (#8155): every in-scope non-std method provider: a glob (ANY_METHOD) or an import that may be a trait,
        # with the method names it may supply (method_path); trait_risk is "some provider exists"
        self._with_uses, self._local_index = with_uses, None  # r14 (G1): the text local_index reads, and its cache
        self.providers = [ANY_METHOD] * len(self.foreign_globs)
        for path, name in imported:
            supplied = self.provider(self.resolve_extern(path), name, text, traits)
            if supplied != frozenset():
                self.providers.append(supplied)
        self.trait_risk = bool(self.providers)

    def resolve_extern(self, path):
        """path with an `extern crate X as A;` alias at its head replaced by X (r13, #8156) and its root mapped through the
        Cargo.toml renames (r14, G2)."""
        path = tuple(path)
        if path and path[0] in self.extern_paths:
            path = tuple(self.extern_paths[path[0]]) + path[1:]
        return self.rename_root(path)

    def provider(self, path, name, text, traits):
        """The method names the non-std import `path` (bound as name) may supply on a receiver of another crate
        (r13, #8155, #8157; r14, G1): frozenset() when it supplies none, ANY_METHOD when it may supply any. A trait of
        KNOWN_TRAIT_METHODS supplies its listed methods. A path into the test crate or into this crate's src/ is
        decided from the RESOLVED definition (ItemIndex): a `trait` item, a macro-generated trait or a re-export alias
        of a trait supplies the methods it may declare (ANY_METHOD when a macro generates some), whatever its spelling
        and whatever struct shares the name; a src/ type that is no trait supplies none. Only a path that no index
        can resolve falls back to the spelling: a lowercase leaf of another crate is a module or a fn (rustc's
        non_camel_case_types, denied by -D warnings) and supplies none; any other name supplies none only when the
        file uses it as a value, a plain type or a constructor, never names it as a bound or an impl target, and did
        not import it `as _`. A `Name::f` path root proves no type use (a UFCS trait call is spelled the same)."""
        if path in KNOWN_TRAIT_METHODS:
            return KNOWN_TRAIT_METHODS[path]
        leaf, common = path[-1], self.common
        if path[0] in FILE_ROOTS:  # an item of the test crate: a trait of the file supplies the fns it declares
            own = self.local_index()
        elif common.crate_name is not None and path[0] == common.crate_name:
            own = None
            if leaf in common.src_traits:
                return common.src_traits[leaf]
            if leaf in common.src_types:
                return frozenset()
        else:
            own = None
        if own is not None:
            if leaf in own.traits:
                return own.traits[leaf]
            if leaf in own.types:
                return frozenset()
        if leaf[:1].islower() or path in KNOWN_FOREIGN_TYPES:
            return frozenset()
        if name != "_" and name not in traits and self.type_use(name, text):
            return frozenset()
        return ANY_METHOD

    def local_index(self):
        """The ItemIndex of this file's own text, its `use` items included (r14, G1), built once."""
        if self._local_index is None:
            index = ItemIndex(trait_generators(self._with_uses))
            index.add(self._with_uses)
            self._local_index = index.close()
        return self._local_index

    @staticmethod
    def type_use(name, text):
        """True when the imported name is used in text as a value, a plain type or a constructor (r12, #8138; r13,
        #8157). A use as a path root (`Name::f(..)` with any arguments, `Name::f::<T>(..)`, `Name::f` as a fn value)
        proves nothing for an UpperCamel name: it is a UFCS call of a trait as much as an associated item of a type, and
        the trait stays in scope as a method provider. A lowercase name (a module, a fn) is never a trait (rustc's non_camel_case_types, denied
        by -D warnings), so any use of it is a use."""
        uses = [m for m in re.finditer(r"(?<![\w$'])%s\b" % re.escape(name), text)]
        if name[:1].islower():
            return bool(uses)
        return any(not PATH_ROOT_USE.match(text, m.end()) for m in uses)

    def path_origin(self, segs, name=None):
        """STD, CRATE or UNKNOWN for the path segs + name, decided by its FIRST segment (r10, #8103): a name the
        file defines or imports from a non-std path is CRATE whatever it is spelled like; std / core / alloc, a name
        imported from one, a primitive, and a prelude std type or value (unless a non-std glob could shadow it) are
        STD; `crate` / `self` / `super` and any other multi-segment path are CRATE; a bare unresolved name,
        `Self` and anything else is UNKNOWN."""
        full = list(segs) + ([name] if name else [])
        if not full:
            return UNKNOWN
        first = full[0]
        kind = self.symbols.get(first)
        if kind == SYM_GENERIC:
            return UNKNOWN  # r11 (#8121): a generic parameter is whatever the caller instantiates it with
        if kind in (SYM_ITEM, SYM_FOREIGN):
            return CRATE
        if first in STD_ROOTS or kind == SYM_STD or first in PRIMS:
            return STD
        if first in PRELUDE_TYPES or first in PRELUDE_VALUES:
            return UNKNOWN if self.foreign_globs else STD
        if first in PATH_SELF:
            return CRATE
        return CRATE if len(full) > 1 and first != "Self" else UNKNOWN

    def type_origin(self, text, infer_ok=False, adts_ok=False):
        """THE std predicate (r10, #8102-#8106): STD, CRATE or UNKNOWN for a type text (a `let` or parameter or
        const type, a return type, a turbofish group). STD only when EVERY path the text names resolves to std
        through path_origin: a name counts as std because the file binds it to std (a `use std::..` import,
        possibly aliased or nested, or a fully qualified std / core / alloc path), never because of how it is
        spelled; tokio, futures, rayon and every other crate are CRATE, as is anything the file defines or imports
        from a non-std path. `_`, `impl`, `dyn`, `fn`, `Self`, a bare generic `T` and any unresolved bare name are
        UNKNOWN. With infer_ok a `_` / `impl` / `dyn` placeholder is neutral (an inferred type proves nothing but
        names nothing); with adts_ok a same-file struct, enum or union and a same-file const (an array length) are
        neutral. CRATE and UNKNOWN are both DETACHED; a text that names nothing is STD."""
        worst = STD
        adts = (self.adts | set(self.variants)) if adts_ok else ()
        lens = array_len_spans(text)  # r11 (#8122): a const is neutral only as an array length
        for m in IDPATH.finditer(text):
            segs = re.split(r"\s*::\s*", m.group(0))
            first = segs[0]
            if len(segs) == 1:
                if first in TYPE_NEUTRAL or (infer_ok and first in ("_", "impl", "dyn")):
                    continue
                if first in TYPE_OPAQUE:
                    return UNKNOWN
                if first in self.consts and self.symbols.get(first) == SYM_ITEM and any(
                        a <= m.start() < b for a, b in lens):
                    continue
                if first in adts and self.symbols.get(first) == SYM_ITEM:
                    continue
            got = self.path_origin(segs)
            if got == UNKNOWN:
                return UNKNOWN
            if got == CRATE:
                worst = CRATE
        return worst

    def method_origin(self, name):
        """STD when the method `name` is a std method (r10, #8105): it is on the INLINE_METHODS allowlist and no
        imported non-std trait or non-std glob can supply a method of that name ahead of the std one (trait_risk);
        else UNKNOWN (detached)."""
        if name in INLINE_METHODS and not PARALLEL_ITER.search(name) and not self.trait_risk:
            return STD
        return UNKNOWN

    @staticmethod
    def literal_span(text):
        """(open, close) indexes of the root array / `vec![..]` literal of text (a borrow of it too), else None."""
        m = LITERAL_ROOT.match(text)
        if m is None:
            return None
        depth = 0
        for j in range(m.end() - 1, len(text)):
            if text[j] == "[":
                depth += 1
            elif text[j] == "]":
                depth -= 1
                if not depth:
                    return m.end() - 1, j
        return None

    def container_links(self, text):
        """True when every link after the root literal of text is a container-level method (CONTAINER_METHODS) and
        nothing indexes it (r10, #8107): such a chain never hands an element back as a receiver."""
        lit = self.literal_span(text)
        tail = text[lit[1] + 1:] if lit else text
        if re.search(r"[\w)\]]\s*\[", tail):
            return False
        return all(n in CONTAINER_METHODS for n in re.findall(r"\.\s*([A-Za-z_]\w*)", tail))

    def receiver_ok(self, fn, dot, floor=None, hops=0, elements=True, direct=False):
        """True when the receiver whose method chain ends at index dot has a PROVEN provenance (#8069, #8089,
        #8093, #8098-#8100). The chain's start is found by walking it back (chain_start; with floor set it is floor,
        a whole `let` initialiser). A block or a struct literal as the chain root is detached (block_root). Every
        token of the span is then decided by span_safe, the ONLY decision point: a closed whitelist whose default
        is DETACHED (see SPAN_FORMS and the form table in the module docstring). With elements False the caller
        only needs the CONTAINER (a callee that runs its closure inline); the elements of a root literal are then
        judged only when the chain extracts one (#8107)."""
        start = floor if floor is not None else chain_start(fn.body, dot)
        if start is None:
            return form("block_root", False)
        return self.span_safe(fn, start, dot, hops, elements, direct)

    @origin_rule
    def span_safe(self, fn, a, b, hops, elements=True, direct=False):
        """True when EVERY expression form of fn.body[a:b] is whitelisted (#8093, #8098, #8099, #8100). Each token
        the tokenizer yields gets exactly one rule (a SPAN_FORMS label, recorded through form()); a form with no
        rule cannot exist, because form() refuses a label outside SPAN_FORMS. A closure literal inside the span is
        decided by closure_ok first; its parameter list is blanked and its body is scanned like any other text. A
        turbofish type argument must be a std path or a primitive (generics_ok) and is blanked afterwards."""
        body = fn.body
        text = list(body[a:b])
        for s, e in self.lits(fn):
            if s >= a and e <= b and body[s:e].strip():
                if not self.closure_ok(fn, s, e, hops, elements):
                    return False
                hm = CLOSURE_HEAD.match(body, s)
                if hm:
                    text[s - a:hm.end() - a] = " " * (hm.end() - s)
        text = "".join(text)
        root = text.lstrip()[:1]
        if not (root.isalpha() or root == "_"):
            form("literal", True)  # a literal, array, tuple or borrow root: its elements are decided token by token
        for g0, g1 in generic_groups(text):
            if self.type_origin(text[g0:g1], infer_ok=True) != STD:
                return form("turbofish_other", False)
            form("turbofish_std", True)
        text = blank_generics(text)
        if not elements:  # #8107: the caller needs the container only; its elements matter once the chain extracts one
            if self.container_links(text):
                lit = self.literal_span(text)
                if lit:
                    text = text[:lit[0] + 1] + " " * (lit[1] - lit[0] - 1) + text[lit[1]:]
            else:
                elements = True
        root_pos = len(text) - len(text.lstrip())
        for m in IDPATH.finditer(text):
            segs = re.split(r"\s*::\s*", m.group(0))
            name, prefix = segs[-1], "".join(g + "::" for g in segs[:-1])
            pre, rest = text[:m.start()].rstrip(), text[m.end():]
            call = rest.lstrip().startswith("(")
            if re.match(r"\s*!(?!=)", rest):
                ok = self.macro_ok(prefix, name)
            elif pre.endswith(".") and not pre.endswith(".."):  # a method or a field of the value before it
                ok = self.member_ok(name, call)
            elif not prefix and name in KEYWORDS:
                ok = form("keyword", True)
            elif not prefix and name in PRIMS:
                ok = form("primitive", True)
            elif (re.match(r"\s*:(?!:)", rest) and not prefix) or BINDER.search(pre):
                ok = form("label_binder", True)  # a struct-literal label or a name a `let` / `ref` introduces
            elif call:
                ok = self.call_ok(fn, prefix, name)
            elif prefix:
                ok = self.path_ok(fn, prefix, name)
            else:
                ok = self.name_ok(fn, name, a + m.start(), hops, elements or m.start() != root_pos,
                                  direct and m.start() == root_pos and not text[m.end():].strip())
            if not ok:
                return False
        return True

    @origin_rule
    def macro_ok(self, prefix, name):
        """`vec!` and the VALUE_MACROS (a std path prefix allowed) are whitelisted; every other macro is detached."""
        if name in self.macro_defs or name in self.foreign_names:
            return form("macro_other", False)  # a macro the file defines or imports shadows the std one
        if prefix and self.path_origin(path_segments(prefix), name) != STD:
            return form("macro_other", False)
        if name == "vec":
            return form("macro_vec", True)
        return form("macro_value", True) if name in VALUE_MACROS else form("macro_other", False)

    @origin_rule
    def member_ok(self, name, call):
        """A field of a safe value is safe. A method is safe when a same-file or tests/common method of that name
        exists and EVERY candidate builds no parallel iterator and returns only safe values, else only when it is on
        the explicit INLINE_METHODS allowlist and no imported non-std trait can shadow it (method_origin, #8105); an
        unknown or extension-trait method is detached (#8100)."""
        if not call:
            return form("field", True)
        cands = self.by_method.get(name, [])
        ext = self.external_helpers("", name, True)
        if cands or ext:
            return form("method_resolved", all(id(c) not in self.parallel and self.returns_safe(c) for c in cands)
                        and all(not h.parallel and h.value_safe for h in ext))
        if self.method_origin(name) == STD:
            return form("method_inline", True)
        return form("method_other", False)

    @origin_rule
    def call_ok(self, fn, prefix, name):
        """A call `prefix::name(..)` is safe when it is a prelude ctor or a std path, a resolved same-file or
        tests/common fn that builds no parallel iterator and returns only safe values, or a ctor of a same-file struct
        or enum variant; every other call (an uppercase fn too, an unresolved crate fn) is detached (#8098)."""
        segs = path_segments(prefix)
        if self.path_origin(segs, name) == STD:
            return form("call_std", True)
        hit = self.resolve(fn.owner, prefix, name)
        if hit is not None:
            return form("call_resolved", id(hit) not in self.parallel and self.returns_safe(hit))
        ext = self.external_helpers(prefix, name, False)
        if ext:
            return form("call_resolved", all(not h.parallel and h.value_safe for h in ext))
        ty = (fn.owner if segs and segs[-1] == "Self" else segs[-1]) if segs else None
        if (not segs and (name in self.adts or name == "Self")) or (segs and name in self.variants.get(ty, ())):
            return form("call_adt", True)
        return form("call_other", False)

    @origin_rule
    def path_ok(self, fn, prefix, name):
        """A prefixed path that is not a call: std, an enum variant of the same file, or a same-file const reached as
        `self::` / `crate::` / `super::` / `module::`, judged by its initialiser; anything else is detached (#8098)."""
        segs = path_segments(prefix)
        if self.path_origin(segs, name) == STD:
            return form("path_std", True)
        ty = fn.owner if segs and segs[-1] == "Self" else (segs[-1] if segs else None)
        if name in self.variants.get(ty, ()):
            return form("path_variant", True)
        if name in self.consts and segs and (segs[-1] in PATH_SELF or segs[-1] in self.mod_names):
            return form("path_const", self.const_ok(name))
        return form("path_other", False)

    @origin_rule
    def name_ok(self, fn, name, use, hops, elements=True, direct=False):
        """A bare name is PROVEN safe or detached, whatever its casing (#8094, #8095, #8098): the innermost binding
        in a block still open at use wins (ScopeMap). A plain `let` is judged by its initialiser (receiver_ok, through
        at most MAX_REBIND_HOPS names); a closure parameter is safe when its closure is a whitelisted form; every other
        binder (a `for` pattern, a match arm, `if let`, `while let`, a destructuring `let`) is opaque. A name nothing
        binds is safe as `self`, a parameter whose declared type is std (type_origin), a name that resolves to std,
        a same-file const or static whose declared type is std (or a same-file type with a safe initialiser), a
        same-file fn item that returns only safe values, or a same-file struct; else it is detached."""
        if hops >= MAX_REBIND_HOPS:
            return form("name_local", False)
        bound = self.scopes(fn).visible(name, use)
        if bound is not None:
            if bound.init is not None:
                typed = self.annotation(fn.body, bound.init[0])
                if typed is not None:  # a declared type decides: std only is the proof, anything else is detached
                    return form("name_local", typed)
                return form("name_local", self.receiver_ok(
                    fn, bound.init[1], floor=bound.init[0], hops=hops + 1, elements=elements or bound.per_item,
                    direct=direct))
            if (bound.lo, bound.hi) in self.lit_set(fn):
                return form("name_closure_param", self.closure_ok(fn, bound.lo, bound.hi, hops, True))
            return form("name_opaque", False)
        if name == "self":
            return form("name_param", True)
        if name in fn.params:  # #8106: a parameter is judged by its DECLARED type, never by being a parameter
            return form("name_param", self.type_origin(fn.param_types.get(name, "Self")) == STD)
        if self.path_origin([], name) == STD:
            return form("name_std", True)
        if name in self.consts:
            return form("name_const", self.const_ok(name))
        hit = self.resolve(fn.owner, "", name)
        if hit is not None:
            return form("name_fn_item", id(hit) not in self.parallel and self.returns_safe(hit))
        if name in self.adts or name == "Self":
            return form("name_adt", True)
        return form("name_other", False)

    def lit_set(self, fn):
        """The closure and async-block literal spans of fn as a set, cached."""
        cache = self.__dict__.setdefault("_lit_sets", {})
        if id(fn) not in cache:
            cache[id(fn)] = set(self.lits(fn))
        return cache[id(fn)]

    def closure_ok(self, fn, s, e, hops, elements=True):
        """True when the closure literal body[s:e] is a whitelisted form (#8099): invoked in place `(|..| ..)(args)`
        with safe arguments, or the whole argument of an INLINE_METHODS method whose receiver is safe in turn. Its
        value is then derived from safe values; its body tokens are scanned by the span that holds it. A closure in any
        other position (a `let`, a path-call argument, an element, a return) and an async block are detached."""
        key = (id(fn), s, e, elements)
        if key in self._closure_memo:
            return self._closure_memo[key]
        if key in self._closure_stack:
            return False  # a cycle is detached
        self._closure_stack.add(key)
        try:
            ok = self.closure_form(fn, s, e, hops, elements)
        finally:
            self._closure_stack.discard(key)
        if self._closed and (ok or not self._ret_stack):  # the parallel set grows until the fixpoint ends
            self._closure_memo[key] = ok
        return ok

    @origin_rule
    def closure_form(self, fn, s, e, hops, elements=True):
        body = fn.body
        if re.match(r"async\s+(?:move\s+)?\{", body[s:]):
            return form("async_block", False)
        before, opener = body[:s].rstrip(), CALL_OPENER.match(body, e)
        if before.endswith("(") and opener and not re.search(r"[\w)\]?>]$", before[:-1].rstrip()):
            op = opener.end() - 1
            return form("closure_iife", self.span_safe(fn, op + 1, match_paren(body, op) - 1, hops + 1))
        slot = arg_slot(body, s, e)
        tail = CALLEE_TAIL.search(body, 0, slot[0]) if slot else None
        if tail is not None:
            pre = body[:tail.start()].rstrip()
            if pre.endswith(".") and not pre.endswith("..") and self.method_origin(tail.group(2)) == STD:
                return form("closure_arg", self.receiver_ok(fn, len(pre) - 1, hops=hops + 1, elements=elements))
        return form("closure_other", False)

    @origin_rule
    def annotation(self, body, init_start):
        """What the type annotation of the `let` whose initialiser starts at init_start proves (#8100, #8102): None
        when there is none, or when it is std except for `_` / `impl` / `dyn` placeholders (an inferred type proves
        nothing, so the initialiser decides: `let v: Vec<_> = vec![1u8];` stays clean); True when type_origin is STD
        (`let k: [&str; 2] = [crate::A, "B"];` is a value of a std type); False when it names a crate or an
        unresolved type (`let p: ai_memory::pool::Pool = it.collect();` is detached)."""
        heads = [h.start() for h in re.finditer(r"\blet\b", body[:init_start])]
        m = re.match(r"let\b[^:=]*?:(?!:)(.*)=$", body[heads[-1]:init_start].rstrip(), re.S) if heads else None
        if m is None:
            return None
        if self.type_origin(m.group(1)) == STD:
            return True
        return None if self.type_origin(m.group(1), infer_ok=True) == STD else False

    def const_fn(self, name):
        """A pseudo fn whose body is the initialiser of the same-file const or static `name`, cached."""
        cache = self.__dict__.setdefault("_const_fns", {})
        if name not in cache:
            a, b, _ = self.consts[name]
            cache[name] = Fn(name, (), None, "", self.text[a:b], a)
        return cache[name]

    @origin_rule
    def const_ok(self, name):
        """True when the same-file const or static `name` (declared once) is classified by its DECLARED type
        (#8098, #8104): a std-only type is the proof (`const KEYS: [&str; 2] = [crate::A, "B"]`); a type of the same
        file's own structs and enums is safe when the initialiser is; a crate type
        (`static P: OnceLock<crate::Pool> = OnceLock::new()`), an unresolved or an inferred one is detached
        whatever the initialiser is."""
        if self.consts.get(name) is None:
            return False
        if self.type_origin(self.consts[name][2]) == STD:
            return True
        if self.type_origin(self.consts[name][2], adts_ok=True) != STD:
            return False
        stack = self.__dict__.setdefault("_const_stack", set())
        if name in stack:
            return False
        stack.add(name)
        try:
            fn = self.const_fn(name)
            return self.span_safe(fn, 0, len(fn.body), 0)
        finally:
            stack.discard(name)

    @origin_rule
    def returns_safe(self, fn):
        """True when every return expression of fn (its tail and each `return ..`) is safe (#8098, fixpoint through
        the callees, MAX_RETURN_DEPTH deep; a cycle or the limit is detached)."""
        key = id(fn)
        if key in self._ret_ok:
            return True
        if fn.ret is not None and self.type_origin(fn.ret) == STD:
            return True  # a declared std return type is the proof (`fn keys() -> [&'static str; 2]`)
        if key in self._ret_stack or len(self._ret_stack) >= MAX_RETURN_DEPTH:
            return False
        self._ret_stack.append(key)
        try:
            ok = all(self.span_safe(fn, x, y, 0) for x, y in return_exprs(fn.body))
        finally:
            self._ret_stack.pop()
        if ok and self._closed:
            self._ret_ok.add(key)
        return ok

    def param_inline(self, fn, name, depth=0):
        """True when EVERY use of parameter `name` in fn is a direct call `name(..)` / `(name)(..)`, a plain
        `let q = name;` whose q is itself only used so, or a whole argument that arg_inline proves is run inline
        (#8065). A use inside a closure literal, a shadowing binding, a return, a store or anything unclassified
        is not inline-only: positive proof, never an absence-of-spawn guess."""
        body, esc = fn.body, re.escape(name)
        binds = sum(len(re.findall(pat % esc, body)) for pat in SHADOW_BINDS)
        if depth > MAX_REBIND_HOPS or binds > (1 if depth else 0):  # an alias is bound once, by its own `let`
            return False
        lits = self.lits(fn)
        for um in re.finditer(r"(?<![\w.$])(?<!::)%s\b" % esc, body):
            u, e = um.start(), um.end()
            rest, before = body[e:], body[:u].rstrip()
            if depth and LET_BINDER.search(body[:u]):
                continue  # the alias's own `let g =`
            if re.match(r"\s*::", rest) or any(x <= u < y for x, y in lits) or before.endswith("."):
                return False
            if re.match(r"\s*\(", rest) or (before.endswith("(") and CALL_OPENER.match(rest)):
                continue
            head = CLOSURE_LET_HEAD.fullmatch(stmt_prefix(body, u))
            if head and rest.lstrip().startswith(";") and self.param_inline(fn, head.group(1), depth + 1):
                continue
            if not self.arg_inline(fn, u, e):
                return False
        return True

    def _close_inline(self):
        """Least fixpoint of the inline-only parameter sets and the parallel-iterator set over every non-test fn of
        the file (#8065, #8069). The sets only grow, so the loop ends; a parameter that is never proven is never
        credited."""
        changed = True
        while changed:
            changed = False
            for f in self.fns:
                if f.is_test:
                    continue
                done = self.inline.setdefault(id(f), set())
                for i, pn in enumerate(f.params):
                    if i not in done and pn is not None and self.param_inline(f, pn):
                        done.add(i)
                        changed = True
                if id(f) not in self.parallel and self.builds_parallel(f):
                    self.parallel.add(id(f))
                    changed = True

    def builds_parallel(self, fn, text=None):
        """True when fn (or just the source text given, such as a closure literal) mentions a parallel iterator or
        calls a same-file or external fn that does (#8069, #8093)."""
        src = fn.body if text is None else text
        if PARALLEL_ITER.search(src):
            return True
        for m in CALL.finditer(src):
            before = src[max(0, m.start() - CALL_WINDOW):m.start()].rstrip()
            if re.search(r"\bfn$", before):
                continue
            if before.endswith("."):
                if any(id(c) in self.parallel for c in self.by_method.get(m.group(2), [])):
                    return True
                continue
            hit = self.resolve(fn.owner, m.group(1), m.group(2))
            if hit is not None:
                if id(hit) in self.parallel:
                    return True
            elif any(h.parallel for h in self.external_helpers(m.group(1), m.group(2), False)):
                return True
        return False

    def carried(self, body, a, b):
        """(spans, texts, over) for the spawn argument body[a:b] (#8051): every identifier in the argument,
        and in each initialiser it leads to, is followed through its `let`, assignment and `for` bindings
        (a boxed, cloned, optional, field-held or looped carrier included). A name that holds a closure or
        async-block `let` makes that initialiser a span. A name bound by a match arm or a closure parameter
        cannot be traced, and more than MAX_CARRIER_NAMES names is too many: both set over, and every
        closure initialiser of the fn is then a span. texts are the initialisers followed. Never credits."""
        spans, texts, seen, over = [], [], set(), False
        lim = loop_end(body, a)  # #8058: a binding later in an enclosing loop body reaches the next iteration
        literal = re.match(r"\s*(?:async\b\s*)?(?:move\b\s*)?[|{]", body[a:b]) is not None
        queue = [(n, not literal) for n in LOCAL_NAME.findall(body[a:b])]
        while queue:
            name, bare = queue.pop()
            if name in seen:
                continue
            seen.add(name)
            esc, found = re.escape(name), []
            for lm in re.finditer(CLOSURE_LET % esc, body[:lim]):
                spans.append((lm.end(), stmt_end(body, lm.end())))
                found.append(spans[-1])
            for pat in (r"\blet\b[^=;]*\b%s\b[^=;]*=(?!=)\s*" % esc, ASSIGN % esc):
                found += [(lm.end(), stmt_end(body, lm.end())) for lm in re.finditer(pat, body[:lim])]
            for lm in re.finditer(LOOP_BIND % esc, body[:lim]):
                brace = body.find("{", lm.end())
                found.append((lm.end(), len(body) if brace < 0 else brace))
            called = bare or re.search(r"\b%s\s*\(" % esc, body[a:b]) is not None
            over = over or (called and any(re.search(pat % esc, body[:lim]) for pat in (ARM_BIND, PARAM_BIND)))
            if len(texts) > MAX_CARRIER_NAMES:
                return spans, texts, True
            for x, y in found:
                # #8056: a closure literal written inside a followed initialiser (`Box::new(move || ..)`) is the
                # closure that reaches the spawn, so it is a span; the variable is not the only holder.
                spans += [(x + s, x + e) for s, e in closure_literals(body[x:y])]
                texts.append(body[x:y])
                queue += [(n, False) for n in LOCAL_NAME.findall(body[x:y])]
        return spans, texts, over

    def expand(self, body, a, b):
        """(spans, chain, overflow) for the spawn argument body[a:b] (#8033, #8045, #8051): spans are the
        closure or async-block initialisers of the variables the argument resolves to through `let g = f;`
        rebindings or any other carrier (see carried), chain is every (path prefix, name) reached by the
        rebindings, overflow says MAX_REBIND_HOPS was hit or a carrier could not be traced. On overflow every
        closure initialiser of the fn is a span: a long chain or an unknown carrier is flagged, never cleared."""
        spans, _, cover = self.carried(body, a, b)
        every = [(lm.end(), stmt_end(body, lm.end())) for lm in re.compile(ANY_CLOSURE_LET).finditer(body)]
        v = FN_VALUE.fullmatch(body, a, b)
        if not v:
            return (spans + every if cover else spans), [], cover
        chain, frontier = [(v.group(1), v.group(2))], ([v.group(2)] if not v.group(1) else [])
        lim = loop_end(body, a)
        for _ in range(MAX_REBIND_HOPS):
            nxt = []
            for name in frontier:
                for lm in re.compile(REBIND_LET % re.escape(name)).finditer(body, 0, lim):
                    tgt = (lm.group(1), lm.group(2))
                    if tgt not in chain:
                        chain.append(tgt)
                        if not tgt[0]:
                            nxt.append(tgt[1])
            frontier = nxt
            if not frontier:
                break
        over = bool(frontier) or cover
        if over:
            spans += every
        else:
            for prefix, name in chain:
                if not prefix:
                    spans += [(lm.end(), stmt_end(body, lm.end()))
                              for lm in re.compile(CLOSURE_LET % re.escape(name)).finditer(body, 0, lim)]
        return spans, chain, over

    def spawn_spans(self, fn):
        """[(start, end)] of every argument list of fn that runs detached (#7994, #8038, #8044, #8045): the
        roots, plus the closures the variables among them (through rebinding) hold (#8033)."""
        spans = self.spawn_roots(fn)
        for a, b in list(spans):
            spans += self.expand(fn.body, a, b)[0]
        return spans + self.literal_spans(fn)  # #8056: and every closure literal not provably same-thread

    def _spawned_params(self, fn):
        """Indices of the parameters of fn that reach a spawn: named in a spawn argument, in a closure a spawn
        argument variable holds, or in the argument of a call to another detaching helper (#8044)."""
        if VALUE_DETACH.search(fn.body):  # #8057: spawn as a fn value can take any parameter: all of them
            return set(range(len(fn.params)))
        roots = self.spawn_roots(fn)
        if not roots:
            return set()
        texts, names, over = [], set(), False
        for a, b in roots:
            spans, chain, ov = self.expand(fn.body, a, b)
            texts += [fn.body[x:y] for x, y in [(a, b)] + spans] + self.carried(fn.body, a, b)[1]
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


def detaching_fns(scrubbed):
    """{fn key: (parameter indices handed to a spawn, has_self)} of one scrubbed file (#8052): the same-file
    #8044 fixpoint, run on a tests/common or module file so a call of its fns from a test file detaches."""
    model = FileModel(scrubbed)
    out = {}
    for f in model.fns:
        if not f.is_test:
            inline = frozenset(model.inline.get(id(f), ()))
            prev = out.get(f.key)
            safe = model.returns_safe(f)
            if prev is None:
                out[f.key] = Detacher(frozenset(model.helpers.get(id(f), ())), f.has_self, inline, id(f) in model.parallel,
                                      safe)
            else:  # same name twice: detach if either does, credit inline only if both prove it (fail closed)
                out[f.key] = Detacher(prev.idxs | frozenset(model.helpers.get(id(f), ())), prev.has_self or f.has_self,
                                      prev.inline & inline, prev.parallel or id(f) in model.parallel,
                                      prev.value_safe and safe)
    return out


def violating_fns(scrubbed, raw=None, common=None, modules=None, macros=None):
    """Names (qualified) of violating test fns in one scrubbed file, or [] when the file is exempt."""
    model = FileModel(scrubbed, raw, common, modules, macros)
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
    if common is None:
        return violating_fns(scrubbed, raw)
    return violating_fns(scrubbed, raw, common, common.path_modules(path, raw), common.module_macros(path, raw))


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
