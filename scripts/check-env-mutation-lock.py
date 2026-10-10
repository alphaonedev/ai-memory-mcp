#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Lib-test env-mutation lock gate (#6123) -- FAIL-CLOSED.

THE DEFECT CLASS THIS CLOSES. Every `src/**/*.rs` file compiles into ONE lib
test binary, and the process environment is ONE table shared by every test
thread in it. A test that calls `std::env::set_var` / `std::env::remove_var`
without holding the crate's process-env lock races every other test that
reads or writes the same variables. #6123 recorded five doctor / migrate /
rules lib tests failing together once under a parallel `--lib` run and
passing on rerun: the classic signature of an unserialised env mutation.
Edition 2024 marks both calls `unsafe` precisely because of this race; the
`// SAFETY:` comment beside each one is a claim, and this gate checks it.

THE RULE. In test code (a `#[cfg(test)]` module or item, a `#[test]` /
`#[tokio::test]` fn, or a file mounted as `#[cfg(test)] mod x;`), every
`set_var(` / `remove_var(` / `set_current_dir(` call must sit in a function
that is COVERED (the working directory is the same class of process-global
state: the #6123 reproduction was a `migrate` test that `chdir`ed into a
tempdir, unserialised, while a `recover` test built its scratch path from the
cwd, so the recover test's files landed in a directory deleted under it):

  1. HOLDS a lock: it calls one of the crate's two process-wide env locks --
     `crate::config::test_env_lock()` / `test_env_mutex()` (lock A) or
     `crate::identity::agent_id_env_test_lock()` (lock B) -- or a wrapper
     whose return type is a `Mutex` / `MutexGuard` and whose body reaches
     one of them, and that call textually PRECEDES the mutation and is not
     dropped on the spot (`let _ = lock()` releases immediately); or
  2. runs in an ISOLATED CHILD: it calls
     `run_env_isolated_child_or_spawn`, whose body executes only in a
     single-threaded child process; or
  3. is ONLY CALLED FROM covered functions (helpers such as an RAII env
     scope): at least one call site exists in test code and every call site
     is itself covered, with the lock taken before the call. `drop` in
     `impl Drop for T` is covered when every function of `impl T` in the
     same file is covered (the guard can only be built under the lock).

  4. is a SET-ONCE fixture named in `SET_ONCE_EXEMPT` (a closed list that
     may only shrink; see the comment there for why those must not lock).

A module-local `static LOCK: Mutex<()>` does NOT count: it only serialises
its own module, which is the per-module-mutex defect this crate already hit
on `$HOME` three times (#1998 -> #2115 -> #2127) and unified in #3523.

`src/main.rs` is skipped: it is the bin target, whose tests run in their own
process and cannot reach the lib's `cfg(test)` locks.

The analysis is lexical (comments and string literals are blanked first; no
macro expansion). It errs toward reporting: an unresolvable caller makes a
helper uncovered.

Exit codes: 0 clean, 1 violations, 2 usage / internal error.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# The two process-wide env locks (lock A and lock B). Keyed by the file
# that defines them so a same-named module-local fn elsewhere never counts.
BASE_ACQUIRERS = {
    ("src/config.rs", "test_env_lock"),
    ("src/config.rs", "test_env_mutex"),
    ("src/identity/mod.rs", "agent_id_env_test_lock"),
}
# Set-once fixtures: the write runs at most once per process inside a
# `Once::call_once` / `OnceLock::get_or_init` initialiser and is never
# restored. They must NOT take the env lock: a test already holding it that
# reaches the initialiser while another thread is inside it would wait on the
# Once while the initialiser waits on the lock (a lock-order deadlock). The
# set is closed and may only shrink; each entry names its gate.
SET_ONCE_EXEMPT = {
    ("src/identity/test_key_dir.rs", "set_env"): "OnceLock-gated key-dir sandbox arm/bind",
    ("src/identity/test_key_dir.rs", "unset_env"): "restore half of the OnceLock-gated bind",
    ("src/identity/attest.rs", "permissive_attestation_for_lib_tests"): "Once-gated, monotonic",
    ("src/handlers/tests.rs", "install_security_bypass_for_legacy_tests"): "Once-gated, monotonic",
    ("src/cli/test_utils.rs", "ensure_no_config_env"): "Once-gated, monotonic",
}
ISOLATED_CHILD_FN = "run_env_isolated_child_or_spawn"
TURBOFISH = r"(?:::\s*<[^;{}()]*>\s*)?"
SITE_RE = re.compile(r"(?<![\w.])(?:(?:std::)?env::)?(set_var|remove_var|set_current_dir)\s*" + TURBOFISH + r"\(")
# Any other mention (use-alias, fn pointer, macro argument) is a way to write the env
# without a call the lexical gate can attribute to a lock: refuse it.
REF_RE = re.compile(r"(?<![\w.])(set_var|remove_var|set_current_dir)\b(?!\s*" + TURBOFISH + r"\()")
SPAWN_RE = re.compile(r"\bspawn(?:_blocking|_local|_scoped)?\s*$")
AGENT_ID_KEY = "AI_MEMORY_AGENT_ID"
POISON_RE = re.compile(r"[\w:\s<>,]*\(\s*\)\s*\.\s*lock\s*\(\s*\)\s*\.\s*(?:unwrap|expect)\s*\(")
CALL_RE = re.compile(r"(?<![\w.])((?:\w+\s*::\s*)*)(\w+)\s*(?:::\s*<[^;{}()]*>\s*)?\(")
FN_RE = re.compile(r"\bfn\s+(\w+)")
MOD_RE = re.compile(r"\bmod\s+(\w+)\s*$")
IMPL_RE = re.compile(r"\bimpl\b(?:\s*<[^{}]*?>)?\s*(.*?)\s*$", re.S)
RECEIVER_RE = re.compile(r"\bfn\s+\w+\s*(?:<[^()]*>)?\s*\(\s*(?:&\s*(?:'\w+\s+)?(?:mut\s+)?)?(?:mut\s+)?self\b")
ATTR_RE = re.compile(r"#\s*\[(.*?)\]\s*", re.S)
KEYWORDS = {
    "if", "while", "for", "match", "loop", "return", "fn", "unsafe", "Some",
    "None", "Ok", "Err", "move", "as", "in", "let", "mut", "ref", "where",
    "impl", "dyn", "box", "await", "async", "type", "struct", "enum",
}


def sanitize(src: str) -> str:
    """Blank comments, string and char literals; keep offsets and newlines."""
    out = list(src)
    i, n = 0, len(src)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
            i = j
        elif src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c in "rb" and re.match(r"(?:br|r)#*\"", src[i:i + 300]) and (
            i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")
        ):
            m = re.match(r"(?:br|r)(#*)\"", src[i:])
            hashes = m.group(1)
            start = i + m.end()
            end = src.find('"' + hashes, start)
            end = n if end == -1 else end + 1 + len(hashes)
            blank(i, end)
            i = end
        elif c == '"' or (c == "b" and src.startswith('b"', i) and (
            i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")
        )):
            j = i + (2 if c == "b" else 1)
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            blank(i, j + 1)
            i = j + 1
        elif c == "'":
            m = re.match(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'\n])'", src[i:])
            if m:
                blank(i, i + m.end())
                i += m.end()
            else:
                i += 1  # lifetime / label
        else:
            i += 1
    return "".join(out)


@dataclass
class Fn:
    file: str
    name: str
    start: int  # body '{'
    end: int  # body '}'
    header: str
    test: bool
    impl_type: Optional[str]
    impl_trait: Optional[str]
    module_tail: str  # last module path segment of the file
    inner_mod: Optional[str] = None  # nearest enclosing inline `mod x { }`


@dataclass
class FileInfo:
    rel: str
    src: str
    san: str
    fns: list[Fn] = field(default_factory=list)
    test_mods: list[str] = field(default_factory=list)  # `#[cfg(test)] mod x;`
    test_paths: list[str] = field(default_factory=list)  # `#[cfg(test)] #[path = ".."] mod x;`
    test_ranges: list[list[int]] = field(default_factory=list)  # [start, end] of test scopes
    file_is_test: bool = False


def is_test_attr(attrs: list[str]) -> bool:
    for a in attrs:
        a = " ".join(a.split())
        if re.match(r"^(?:\w+::)*test\b", a) or a.startswith("rstest"):
            return True
        if a.startswith("cfg(") and re.search(r"\btest\b", a) and "not(test" not in a:
            return True
    return False


def module_tail(rel: str) -> str:
    p = Path(rel)
    if p.name in ("mod.rs", "lib.rs", "main.rs"):
        return p.parent.name
    return p.stem


def parse_file(rel: str, src: str, file_is_test: bool) -> FileInfo:
    san = sanitize(src)
    info = FileInfo(rel, src, san)
    info.file_is_test = file_is_test
    rstack: list[Optional[int]] = []
    # scope stack entries: (kind, test, impl_type, impl_trait, fn_obj)
    stack: list[tuple] = [("file", file_is_test, None, None, None)]
    header_start = 0
    paren = 0
    for i, c in enumerate(san):
        if c in "([":
            paren += 1
        elif c in ")]":
            paren = max(0, paren - 1)
        elif c == ";" and paren == 0:
            header = san[header_start:i]
            attrs = ATTR_RE.findall(header)
            stripped = ATTR_RE.sub(" ", header).strip()
            m = re.search(r"\bmod\s+(\w+)$", stripped)
            if m and (is_test_attr(attrs) or stack[-1][1]):
                info.test_mods.append(m.group(1))
                pm = re.search(r"#\s*\[\s*path\s*=\s*\"([^\"]+)\"\s*\]", src[header_start:i])
                if pm:
                    info.test_paths.append(pm.group(1))
            header_start = i + 1
        elif c == "{" and paren == 0:
            header = san[header_start:i]
            attrs = ATTR_RE.findall(header)
            stripped = ATTR_RE.sub(" ", header)
            parent = stack[-1]
            test = parent[1] or is_test_attr(attrs)
            fm = FN_RE.search(stripped)
            if fm and "=" not in stripped[: fm.start()].split("\n")[-1]:
                in_impl = parent[0] == "impl"
                fn = Fn(rel, fm.group(1), i, -1, stripped, test,
                        parent[2] if in_impl else None,
                        parent[3] if in_impl else None, module_tail(rel),
                        next((e[2] for e in reversed(stack) if e[0] == "mod"), None))
                info.fns.append(fn)
                stack.append(("fn", test, None, None, fn))
            elif MOD_RE.search(stripped.strip()):
                stack.append(("mod", test, MOD_RE.search(stripped.strip()).group(1), None, None))
            elif re.search(r"(?:^|\s)impl\b", stripped) and parent[0] in ("file", "mod"):
                im = IMPL_RE.search(stripped)
                body = im.group(1) if im else ""
                body = re.sub(r"\bwhere\b.*$", "", body, flags=re.S).strip()
                trait, typ = None, body
                if re.search(r"\bfor\b", body):
                    trait, typ = re.split(r"\bfor\b", body, maxsplit=1)
                    trait = trait.strip()
                tn = re.findall(r"(\w+)", re.sub(r"<.*", "", typ.strip(), flags=re.S))
                stack.append(("impl", test, tn[-1] if tn else None,
                              (re.findall(r"(\w+)", re.sub(r"<.*", "", trait, flags=re.S)) or [None])[-1]
                              if trait else None, None))
            else:
                stack.append(("block", test, None, None, None))
            if stack[-1][1] and not parent[1]:
                info.test_ranges.append([i, -1])
                rstack.append(len(info.test_ranges) - 1)
            else:
                rstack.append(None)
            header_start = i + 1
        elif c == "}" and paren == 0:
            if len(stack) > 1:
                kind, _t, _a, _b, fn = stack.pop()
                ri = rstack.pop() if rstack else None
                if ri is not None:
                    info.test_ranges[ri][1] = i
                if kind == "fn" and fn is not None:
                    fn.end = i
            header_start = i + 1
    return info


def parse_imports(san: str) -> dict[str, tuple[str, str]]:
    """`use a::b::{x, y as z};` / `use a::b::x [as z];` ->
    {local name: (module tail, original name)}. A `super` / `self` / `crate`
    -only path maps to tail "" (same file)."""
    out: dict[str, tuple[str, str]] = {}

    def tail_of(path: str) -> str:
        segs = [x for x in re.split(r"\s*::\s*", path.strip()) if x]
        segs = [x for x in segs if x not in ("crate", "super", "self")]
        return segs[-1] if segs else ""

    for m in re.finditer(r"\buse\s+([\w:\s]+?)::\s*\{([^}]*)\}\s*;", san):
        tail = tail_of(m.group(1))
        for item in m.group(2).split(","):
            parts = item.split()
            if parts and re.fullmatch(r"\w+", parts[0]):
                local = parts[2] if len(parts) == 3 and parts[1] == "as" else parts[0]
                out[local] = (tail, parts[0])
    for m in re.finditer(r"\buse\s+((?:\w+\s*::\s*)+)(\w+)(?:\s+as\s+(\w+))?\s*;", san):
        out[m.group(3) or m.group(2)] = (tail_of(m.group(1)), m.group(2))
    return out


def innermost_fn(info: FileInfo, off: int) -> Optional[Fn]:
    best = None
    for fn in info.fns:
        if fn.start < off < (fn.end if fn.end >= 0 else len(info.san)):
            if best is None or fn.start > best.start:
                best = fn
    return best


def in_test_scope(info: FileInfo, off: int) -> bool:
    if info.file_is_test:
        return True
    return any(a < off < (b if b >= 0 else len(info.san)) for a, b in info.test_ranges)


def line_of(src: str, off: int) -> int:
    return src.count("\n", 0, off) + 1


class Index:
    def __init__(self, files: list[FileInfo]):
        self.files = files
        self.by_name: dict[str, list[Fn]] = {}
        for f in files:
            for fn in f.fns:
                self.by_name.setdefault(fn.name, []).append(fn)
        self.info_of = {f.rel: f for f in files}
        self.imports = {f.rel: parse_imports(f.san) for f in files}
        self.acq_kinds: dict[int, set] = {}
        self.acquirers = self._acquirers()
        self.calls = self._calls()

    def resolve(self, caller_file: str, qual: str, name: str) -> list[Fn]:
        imported = self.imports.get(caller_file, {}).get(name) if not qual.strip() else None
        if imported:
            name = imported[1]
        cands = self.by_name.get(name, [])
        segs = [s for s in re.split(r"\s*::\s*", qual.strip()) if s]
        segs = [s for s in segs if s not in ("crate", "super", "self")]
        if not segs:
            local = [c for c in cands if c.file == caller_file]
            if imported and imported[0]:
                local += [c for c in cands if c.module_tail == imported[0]]
            return local
        tail = segs[-1]
        alias = self.imports.get(caller_file, {}).get(tail)
        if alias and len(segs) == 1:
            tail = alias[1]  # `use a::b as kp;` then `kp::f()`
        if tail == "Self" or tail[:1].isupper():
            typ = tail
            return [c for c in cands if c.impl_type == typ or (tail == "Self" and c.file == caller_file)]
        return [c for c in cands if tail in (c.module_tail, c.inner_mod)]

    def body_calls(self, fn: Fn):
        info = self.info_of[fn.file]
        body = info.san[fn.start:fn.end if fn.end >= 0 else len(info.san)]
        for m in CALL_RE.finditer(body):
            name = m.group(2)
            if name in KEYWORDS:
                continue
            pre = body[max(0, m.start() - 4):m.start()]
            if re.search(r"fn\s*$", pre):
                continue
            yield fn.start + m.start(), m.group(1), name

    def _delegates_to_a(self, fn: Fn) -> bool:
        """True when the identity lock is just the crate-wide env mutex."""
        return any(name in ("test_env_lock", "test_env_mutex")
                   for _o, _q, name in self.body_calls(fn))

    def _acquirers(self) -> set[int]:
        acq: set[int] = set()
        for f in self.files:
            for fn in f.fns:
                if (fn.file, fn.name) in BASE_ACQUIRERS:
                    acq.add(id(fn))
                    self.acq_kinds[id(fn)] = {"A"}
                    if fn.name == "agent_id_env_test_lock" and not self._delegates_to_a(fn):
                        # A separate mutex: excludes only other lock-B holders.
                        self.acq_kinds[id(fn)] = {"B"}
        changed = True
        while changed:
            changed = False
            for f in self.files:
                for fn in f.fns:
                    if not re.search(r"->[^{]*\bMutex", fn.header) or (fn.file, fn.name) in BASE_ACQUIRERS:
                        continue
                    for _off, q, name in self.body_calls(fn):
                        tg = [t for t in self.resolve(fn.file, q, name) if id(t) in acq]
                        if tg:
                            kinds = set().union(*(self.acq_kinds.get(id(t), set()) for t in tg))
                            if id(fn) not in acq or not kinds <= self.acq_kinds.get(id(fn), set()):
                                acq.add(id(fn))
                                self.acq_kinds.setdefault(id(fn), set()).update(kinds)
                                changed = True
                            break
        return acq

    def _calls(self):
        """callee id -> list of (caller Fn, offset)."""
        calls: dict[int, list] = {}
        for f in self.files:
            for fn in f.fns:
                for off, q, name in self.body_calls(fn):
                    if innermost_fn(f, off) is not fn:
                        continue
                    for t in self.resolve(fn.file, q, name):
                        calls.setdefault(id(t), []).append((fn, off))
        return calls

    def literal_sites(self, typ: str, file: str) -> list[tuple]:
        """Fns in `file` that build `typ` by literal (`T`, `T { .. }`,
        `T(..)`) outside its own impl blocks. Type names are file-local:
        several modules declare their own `EnvGuard`."""
        pat = re.compile(r"(?<![\w:])" + re.escape(typ) + r"\b(?!\s*::)")
        sites = []
        for f in (self.info_of[file],):
            for m in pat.finditer(f.san):
                fn = innermost_fn(f, m.start())
                if fn is None or fn.impl_type == typ:
                    continue
                before = f.san[max(0, m.start() - 40):m.start()]
                if re.search(r"(?:->|:|<|&|\bstruct|\bimpl|\bfor|\benum|\bas)\s*(?:mut\s+)?$", before):
                    continue  # a type position, not a value
                sites.append((fn, m.start()))
        return sites

    def by_name_type(self, typ: str, file: str) -> list[Fn]:
        return [fn for fn in self.info_of[file].fns if fn.impl_type == typ]

    def type_holds_guard(self, info: FileInfo, typ: str) -> bool:
        m = re.search(r"\bstruct\s+" + re.escape(typ) + r"\b[^;{(]*([{(])", info.san)
        if not m:
            return False
        close = "}" if m.group(1) == "{" else ")"
        end = info.san.find(close, m.end())
        if "MutexGuard" not in info.san[m.end():end if end != -1 else len(info.san)]:
            return False
        # A MutexGuard field only proves a lock when every construction of the
        # type is in a fn that reaches a base acquirer (a foreign `Mutex` guard
        # field would otherwise count). No construction found => unproven.
        pat = re.compile(r"(?<![\w:])(?:" + re.escape(typ) + r"|Self)\s*[{(]")
        built = False
        for fn in info.fns:
            body = info.san[fn.start:fn.end if fn.end >= 0 else len(info.san)]
            for mm in pat.finditer(body):
                if mm.group(0).startswith("Self") and fn.impl_type != typ:
                    continue
                before = body[max(0, mm.start() - 40):mm.start()]
                if re.search(r"(?:->|:|<|&|\bstruct|\bimpl|\bfor|\benum|\bas)\s*(?:mut\s+)?$", before):
                    continue
                built = True
                if not any(id(t) in self.acquirers
                           for _o, q, n in self.body_calls(fn) for t in self.resolve(fn.file, q, n)):
                    return False
        return built

    def spawn_floor(self, fn: Fn, off: int) -> Optional[int]:
        """Offset of the `(` of the innermost enclosing `spawn(..)` call, if any:
        a closure handed to a thread outlives the guard its parent holds."""
        san = self.info_of[fn.file].san
        depth, k = 0, off
        while k > fn.start:
            k -= 1
            c = san[k]
            if c == ")":
                depth += 1
            elif c == "(":
                if depth:
                    depth -= 1
                elif SPAWN_RE.search(san[max(0, k - 30):k]):
                    return k
        return None

    def guard_live(self, info: FileInfo, coff: int, off: int) -> bool:
        """The acquirer call at `coff` yields a guard that is still held at `off`."""
        san = info.san
        start = max(san.rfind(";", 0, coff), san.rfind("{", 0, coff), san.rfind("}", 0, coff)) + 1
        prefix = san[start:coff]
        if re.search(r"\blet\s+_\s*[=:]", prefix):
            return False  # `let _ = lock()` drops on the spot
        named = re.search(r"\blet\s+(?:mut\s+)?([A-Za-z]\w*)\b", prefix)
        held = bool(named) or bool(re.search(r"\b(?:let|match|while|for)\b", prefix)) \
            or bool(re.match(r"^\s*\w+\s*:\s*$", prefix)) \
            or bool(re.search(r"\b[A-Z]\w*\s*\(\s*$", prefix))
        if not held:
            return False
        between = san[coff:off]
        depth = 0
        for ch in between:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth < 0:
                    return False  # the block that owned the guard closed
        if named and re.search(r"\b(?:mem\s*::\s*)?drop\s*\(\s*" + re.escape(named.group(1)) + r"\s*\)", between):
            return False
        return True

    def takes_lock(self) -> set:
        """Ids of fns that (transitively) call a base acquirer: calling one while
        a guard is held re-locks the non-reentrant mutex."""
        if hasattr(self, "_takes"):
            return self._takes
        # `-> &Mutex<..>` accessors hand out the mutex without locking it.
        accessor = {id(fn) for f in self.files for fn in f.fns
                    if re.search(r"->\s*&[^{]*\bMutex\b(?!Guard)", fn.header)}
        takes = {i for i in self.acquirers if i not in accessor}
        changed = True
        while changed:
            changed = False
            for f in self.files:
                for fn in f.fns:
                    if id(fn) in takes or id(fn) in accessor or fn.name == ISOLATED_CHILD_FN:
                        continue
                    for _o, q, n in self.body_calls(fn):
                        if any(id(t) in takes for t in self.resolve(fn.file, q, n)):
                            takes.add(id(fn))
                            changed = True
                            break
        self._takes = takes
        return takes

    def yields_guard(self, fn: Fn) -> bool:
        if id(fn) in self.acquirers:
            return True
        m = re.search(r"->\s*([A-Za-z_][\w:]*)", fn.header)
        if not m or id(fn) not in self.takes_lock():
            return False
        typ = m.group(1).split("::")[-1]
        if typ == "Self":
            typ = fn.impl_type or ""
        info = self.info_of[fn.file]
        return bool(typ) and self.type_holds_guard(info, typ)

    def relocks(self, fn: Fn) -> list:
        """Offsets where `fn` calls a lock-taking fn while a guard it took is live."""
        info = self.info_of[fn.file]
        takes = self.takes_lock()
        calls = [(o, q, n) for o, q, n in self.body_calls(fn) if innermost_fn(info, o) is fn]
        out = []
        for o1, q1, n1 in calls:
            if not any(self.yields_guard(t) for t in self.resolve(fn.file, q1, n1)):
                continue
            for o2, q2, n2 in calls:
                if o2 <= o1 or n2 == ISOLATED_CHILD_FN:
                    continue
                if any(id(t) in takes for t in self.resolve(fn.file, q2, n2)) \
                        and self.guard_live(info, o1, o2) and self.spawn_floor(fn, o2) is None:
                    out.append(o2)
        return sorted(set(out))

    def lock_before(self, fn: Fn, off: int, lo: int = -1) -> set:
        """Kinds of lock held at `off` ({'A','B','ISO'}); empty set = none."""
        info = self.info_of[fn.file]
        kinds: set = set()
        for coff, q, name in self.body_calls(fn):
            if coff >= off or coff < lo:
                continue
            if name == ISOLATED_CHILD_FN:
                kinds.add("ISO")
                continue
            tg = [t for t in self.resolve(fn.file, q, name) if id(t) in self.acquirers]
            if tg and self.guard_live(info, coff, off):
                for t in tg:
                    kinds |= self.acq_kinds.get(id(t), {"A"})
        return kinds

    @staticmethod
    def sufficient(kinds: set, key: Optional[str]) -> bool:
        return "A" in kinds or "ISO" in kinds or ("B" in kinds and key == AGENT_ID_KEY)

    def covered(self, fn: Fn, off: int, key: Optional[str] = None, seen: frozenset = frozenset()) -> bool:
        floor = self.spawn_floor(fn, off)
        if floor is not None:
            return self.sufficient(self.lock_before(fn, off, floor), key)
        if self.sufficient(self.lock_before(fn, off), key):
            return True
        if id(fn) in seen:
            return False
        seen = seen | {id(fn)}
        if fn.impl_type and RECEIVER_RE.search(fn.header):
            # A method (incl. `Drop::drop`) runs on an instance; the instance
            # is covered when it carries the guard itself, or when every
            # receiver-less constructor of the type is covered.
            info = self.info_of[fn.file]
            if self.type_holds_guard(info, fn.impl_type):
                return True
            ctors = [g for g in self.by_name_type(fn.impl_type, fn.file)
                     if g.impl_trait is None and not RECEIVER_RE.search(g.header)]
            sites = [(g, g.end) for g in ctors] + self.literal_sites(fn.impl_type, fn.file)
            return bool(sites) and all(self.covered(g, o, key, seen) for g, o in sites)
        callers = [c for c in self.calls.get(id(fn), []) if c[0].test]
        if not callers:
            return False
        return all(self.covered(c, o, key, seen) for c, o in callers)


def load(root: Path) -> tuple:
    srcdir = root / "src"
    if not srcdir.is_dir():
        raise SystemExit(f"error: {srcdir} is not a directory")
    raw = {}
    symlinks: list[str] = []
    for dirpath, dirnames, filenames in os.walk(srcdir, followlinks=False):
        dirnames.sort()
        for dn in list(dirnames):
            if os.path.islink(os.path.join(dirpath, dn)):
                symlinks.append((Path(dirpath) / dn).relative_to(root).as_posix())
                dirnames.remove(dn)
        for fnm in sorted(filenames):
            full = Path(dirpath) / fnm
            if not fnm.endswith(".rs"):
                continue
            if full.is_symlink():
                symlinks.append(full.relative_to(root).as_posix())
                continue
            if full == srcdir / "main.rs":
                continue  # bin target: its tests run in their own process, not the lib binary
            raw[full.relative_to(root).as_posix()] = full.read_text(encoding="utf-8", errors="replace")
    infos = {rel: parse_file(rel, s, False) for rel, s in raw.items()}
    test_files: set[str] = set()
    for rel, info in infos.items():
        base = Path(rel)
        d = base.parent if base.name in ("mod.rs", "lib.rs", "main.rs") else base.with_suffix("")
        for m in info.test_mods:
            for cand in (d / f"{m}.rs", d / m / "mod.rs"):
                if cand.as_posix() in raw:
                    test_files.add(cand.as_posix())
        for pth in info.test_paths:
            cand = Path(os.path.normpath((base.parent / pth).as_posix()))
            if cand.as_posix() in raw:
                test_files.add(cand.as_posix())
    # propagate into sub-files of test files
    changed = True
    while changed:
        changed = False
        for rel in list(raw):
            if rel in test_files:
                continue
            parent_dir = Path(rel).parent
            for t in list(test_files):
                tp = Path(t)
                tdir = tp.parent if tp.name == "mod.rs" else tp.with_suffix("")
                if parent_dir == tdir or tdir in parent_dir.parents:
                    test_files.add(rel)
                    changed = True
                    break
    return [parse_file(rel, s, True) if rel in test_files else infos[rel] for rel, s in raw.items()], symlinks


def scan(root: Path) -> list[str]:
    files, symlinks = load(root)
    idx = Index(files)
    violations = []
    for rel in symlinks:
        violations.append(f"{rel}:0: symlink in fn `{Path(rel).stem}` "
                          "is a symlink under src/ (not scanned; refused)")
    for f in files:
        for m in list(SITE_RE.finditer(f.san)) + list(REF_RE.finditer(f.san)):
            pre = f.san[max(0, m.start() - 4):m.start()]
            if re.search(r"fn\s*$", pre):
                continue
            is_call = SITE_RE.match(f.san, m.start()) is not None
            fn = innermost_fn(f, m.start())
            ln = line_of(f.src, m.start())
            if fn is None:
                if in_test_scope(f, m.start()):
                    violations.append(f"{f.rel}:{ln}: {m.group(1)} in fn `item_scope` is outside any fn "
                                      "in test code (macro body / import / alias)")
                continue
            if not fn.test:
                continue
            if (f.rel, fn.name) in SET_ONCE_EXEMPT:
                continue
            if not is_call:
                violations.append(f"{f.rel}:{ln}: {m.group(1)} in fn `{fn.name}` "
                                  "is referenced without a direct call (alias / fn pointer)")
                continue
            km = re.match(r"\s*(?:::\s*<[^;{}()]*>\s*)?\(\s*\"([^\"]*)\"", f.src[m.end() - 1:] if False else f.src[m.start():][len(m.group(0)) - 1:])
            key = km.group(1) if km else None
            if m.group(1) == "set_current_dir":
                key = None
            if not idx.covered(fn, m.start(), key):
                violations.append(f"{f.rel}:{ln}: {m.group(1)} in fn `{fn.name}` "
                                  "is not under the process-env lock")
        for fn in f.fns:
            if not fn.test:
                continue
            for o2 in idx.relocks(fn):
                violations.append(f"{f.rel}:{line_of(f.src, o2)}: relock in fn `{fn.name}` "
                                  "takes the process-env mutex while a guard from it is still held "
                                  "(std Mutex is not re-entrant: self-deadlock)")
            for coff, q, name in idx.body_calls(fn):
                tg = [t for t in idx.resolve(fn.file, q, name) if id(t) in idx.acquirers
                      and re.search(r"->[^{]*&[^{]*\bMutex", t.header)]
                if tg and POISON_RE.match(f.san[coff:]):
                    violations.append(f"{f.rel}:{line_of(f.src, coff)}: poison in fn `{fn.name}` "
                                      "locks the shared env mutex with .lock().unwrap()/.expect(); "
                                      "use unwrap_or_else(PoisonError::into_inner) or test_env_lock()")
    return violations


SELF_TEST_FIXTURE = {
    "src/config.rs": """
#[cfg(test)]
pub(crate) fn test_env_mutex() -> &'static std::sync::Mutex<()> { todo!() }
#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    test_env_mutex().lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
pub fn production() { unsafe { std::env::set_var("PROD_OK", "1") }; }
""",
    "src/identity/mod.rs": """
#[cfg(test)]
pub(crate) fn agent_id_env_test_lock() -> std::sync::MutexGuard<'static, ()> { todo!() }
""",
    "src/good.rs": """
#[cfg(test)]
mod tests {
    fn lock() -> std::sync::MutexGuard<'static, ()> { crate::config::test_env_lock() }
    fn raw() -> &'static std::sync::Mutex<()> { crate::config::test_env_mutex() }
    struct Scope(&'static str);
    impl Scope {
        fn set(k: &'static str) -> Self { unsafe { std::env::set_var(k, "1") }; Self(k) }
    }
    impl Drop for Scope {
        fn drop(&mut self) { unsafe { std::env::remove_var(self.0) }; }
    }
    #[test]
    fn wrapper_guard() { let _g = lock(); unsafe { std::env::set_var("A", "1") }; }
    #[test]
    fn raw_mutex() {
        let _g = raw().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let _s = Scope::set("B");
    }
    #[test]
    fn locked_chdir() { let _g = lock(); std::env::set_current_dir("/").unwrap(); }
    #[test]
    fn identity_lock() {
        let _g = crate::identity::agent_id_env_test_lock();
        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
    }
    #[test]
    fn isolated() {
        if crate::config::run_env_isolated_child_or_spawn("x") { return; }
        unsafe { std::env::set_var("D", "1") };
    }
    struct Held { _g: std::sync::MutexGuard<'static, ()> }
    impl Held {
        fn new() -> Self { Held { _g: lock() } }
    }
    impl Drop for Held {
        fn drop(&mut self) { unsafe { std::env::remove_var("G") }; }
    }
    #[test]
    fn holds_via_ctor() { let _h = Held::new(); }
    #[test]
    fn sequential_not_relock() {
        { let _a = lock(); unsafe { std::env::set_var("SQ", "1") }; }
        let _b = lock();
        let m = crate::config::test_env_mutex();
        let _same = (m, raw());
    }
    #[test]
    fn agent_id_under_lock_b() {
        let _g = crate::identity::agent_id_env_test_lock();
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "x") };
    }
    #[test]
    fn spawn_locks_inside() {
        std::thread::spawn(|| {
            let _g = lock();
            unsafe { std::env::set_var("S", "1") };
        });
    }
    #[test]
    fn write_then_drop() { let g = lock(); unsafe { std::env::set_var("W", "1") }; drop(g); }
    #[test]
    fn nested_block_still_held() {
        let _g = lock();
        { if true { unsafe { std::env::set_var("N", "1") }; } }
    }
    struct Ctor { _g: std::sync::MutexGuard<'static, ()> }
    impl Ctor {
        fn new() -> Self { Ctor { _g: crate::config::test_env_lock() } }
        fn poke(&self) { unsafe { std::env::set_var("CT", "1") }; }
    }
    #[test]
    fn guard_type_acquires_in_ctor() { Ctor::new().poke(); }
    // a comment mentioning std::env::set_var("E", "1") is not a site
    #[test]
    fn string_is_not_a_site() { let _s = "std::env::set_var(\\"F\\", \\"1\\")"; }
}
""",
    "src/bad.rs": """
#[cfg(test)]
mod tests {
    fn local_lock() -> &'static std::sync::Mutex<()> {
        static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(|| std::sync::Mutex::new(()))
    }
    fn helper() { unsafe { std::env::set_var("H", "1") }; }
    #[test]
    fn no_lock() { unsafe { std::env::set_var("BAD1", "1") }; }
    #[test]
    fn module_local_lock() { let _g = local_lock().lock().unwrap(); unsafe { std::env::set_var("BAD2", "1") }; }
    #[test]
    fn dropped_guard() { let _ = crate::config::test_env_lock(); unsafe { std::env::set_var("BAD3", "1") }; }
    #[test]
    fn lock_after() { unsafe { std::env::set_var("BAD4", "1") }; let _g = crate::config::test_env_lock(); }
    #[test]
    fn unlocked_caller() { helper(); }
    #[test]
    fn unlocked_chdir() { std::env::set_current_dir("/").unwrap(); }
    struct Leaky;
    impl Leaky {
        fn new() -> Self { Self }
        fn poke(&self) { unsafe { std::env::set_var("BAD5", "1") }; }
    }
    #[test]
    fn unlocked_instance() { Leaky::new().poke(); }
    #[test]
    fn turbofish_site() { unsafe { std::env::set_var::<&str, &str>("BAD6", "1") }; }
    #[test]
    fn fn_pointer() {
        let f = std::env::set_var::<&str, &str>;
        let _ = f;
    }
    #[test]
    fn block_released() {
        { let _g = crate::config::test_env_lock(); }
        unsafe { std::env::set_var("BAD7", "1") };
    }
    #[test]
    fn relock_direct() { let _a = lock(); let _b = lock(); unsafe { std::env::set_var("RL", "1") }; }
    fn takes_inside() { let _t = lock(); }
    #[test]
    fn relock_via_helper() { let _a = lock(); takes_inside(); unsafe { std::env::set_var("RH", "1") }; }
    #[test]
    fn drop_released() {
        let g = crate::config::test_env_lock();
        drop(g);
        unsafe { std::env::set_var("BAD8", "1") };
    }
    #[test]
    fn multiline_dropped() {
        let _ =
            crate::config::test_env_lock();
        unsafe { std::env::set_var("BAD9", "1") };
    }
    #[test]
    fn conditional_lock() {
        if false { let _g = crate::config::test_env_lock(); }
        unsafe { std::env::set_var("BAD10", "1") };
    }
    #[test]
    fn lock_b_wrong_var() {
        let _g = crate::identity::agent_id_env_test_lock();
        unsafe { std::env::set_var("AI_MEMORY_DB", "1") };
    }
    #[test]
    fn spawned_write() {
        let _g = crate::config::test_env_lock();
        std::thread::spawn(|| {
            unsafe { std::env::set_var("BAD11", "1") };
        });
    }
    fn mixed_helper() { unsafe { std::env::set_var("BAD12", "1") }; }
    #[test]
    fn mixed_locked_caller() { let _g = crate::config::test_env_lock(); mixed_helper(); }
    #[test]
    fn mixed_unlocked_caller() { mixed_helper(); }
    #[test]
    fn run_prefix_not_isolated() {
        crate::config::run_x("x");
        unsafe { std::env::set_var("BAD13", "1") };
    }
}
""",
    "src/alias.rs": """
#[cfg(test)]
mod tests {
    use std::env::set_var as sv;
    #[test]
    fn via_alias() { unsafe { sv("X", "1") }; }
}
""",
    "src/macro_site.rs": """
#[cfg(test)]
mod tests {
    macro_rules! setx { () => { unsafe { std::env::set_var("X", "1") } }; }
    #[test]
    fn via_macro() { setx!(); }
}
""",
    "src/guardty.rs": """
#[cfg(test)]
mod tests {
    fn local() -> &'static std::sync::Mutex<()> {
        static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(|| std::sync::Mutex::new(()))
    }
    struct G { _g: std::sync::MutexGuard<'static, ()> }
    impl G {
        fn new() -> Self { G { _g: local().lock().unwrap_or_else(std::sync::PoisonError::into_inner) } }
        fn poke(&self) { unsafe { std::env::set_var("X", "1") }; }
    }
    #[test]
    fn via_foreign_guard() { G::new().poke(); }
}
""",
    "src/pm.rs": """
#[cfg(test)]
#[path = "pm_extra_tests.rs"]
mod extra;
""",
    "src/pm_extra_tests.rs": """
fn path_helper() { unsafe { std::env::set_var("X", "1") }; }
#[test]
fn via_path_mount() { path_helper(); }
""",
    "src/m.rs": """
#[cfg(test)]
mod t;
""",
    "src/m/t.rs": """
fn mounted_helper() { unsafe { std::env::set_var("X", "1") }; }
#[test]
fn mounted_test() { mounted_helper(); }
""",
    "src/bare.rs": """
#[test]
fn bare_test() { unsafe { std::env::set_var("X", "1") }; }
""",
    "src/poison.rs": """
#[cfg(test)]
mod tests {
    fn w() -> &'static std::sync::Mutex<()> { crate::config::test_env_mutex() }
    #[test]
    fn poison_unwrap() {
        let _g = w().lock().unwrap();
        unsafe { std::env::set_var("X", "1") };
    }
    #[test]
    fn poison_expect() {
        let _g = crate::config::test_env_mutex().lock().expect("env");
        unsafe { std::env::set_var("Y", "1") };
    }
}
""",
    "src/zbad.rs": """
#[cfg(test)]
mod tests {
    #[test]
    fn zbad_test() { unsafe { std::env::set_var("X", "1") }; }
}
""",
}
SELF_TEST_EXPECTED = {
    ("src/bad.rs", "helper"), ("src/bad.rs", "no_lock"),
    ("src/bad.rs", "module_local_lock"), ("src/bad.rs", "dropped_guard"),
    ("src/bad.rs", "lock_after"), ("src/bad.rs", "poke"), ("src/bad.rs", "relock_direct"), ("src/bad.rs", "relock_via_helper"),
    ("src/bad.rs", "unlocked_chdir"),
    ("src/bad.rs", "turbofish_site"), ("src/bad.rs", "fn_pointer"),
    ("src/bad.rs", "block_released"), ("src/bad.rs", "drop_released"),
    ("src/bad.rs", "multiline_dropped"), ("src/bad.rs", "conditional_lock"),
    ("src/bad.rs", "lock_b_wrong_var"), ("src/bad.rs", "spawned_write"),
    ("src/bad.rs", "mixed_helper"), ("src/bad.rs", "run_prefix_not_isolated"),
    ("src/alias.rs", "item_scope"), ("src/macro_site.rs", "item_scope"),
    ("src/guardty.rs", "poke"), ("src/pm_extra_tests.rs", "path_helper"),
    ("src/m/t.rs", "mounted_helper"), ("src/bare.rs", "bare_test"),
    ("src/poison.rs", "poison_unwrap"), ("src/poison.rs", "poison_expect"),
    ("src/zbad.rs", "zbad_test"), ("src/linked", "linked"),
}


def self_test() -> int:
    scratch_parent = Path.cwd() / ".local-runs"
    scratch_parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch_parent) as d:
        root = Path(d)
        for rel, body in SELF_TEST_FIXTURE.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        # a symlinked directory under src/ is not scanned: the gate refuses it
        os.symlink(root / "src" / "m", root / "src" / "linked")
        got = set()
        for v in scan(root):
            m = re.match(r"(\S+?):\d+: \w+ in fn `(\w+)`", v)
            if m:
                got.add((m.group(1), m.group(2)))
        ok = got == SELF_TEST_EXPECTED
        # the gate must also fail as a process on the fixture
        proc = subprocess.run([sys.executable, "-I", __file__, "--root", str(root)],
                              capture_output=True, text=True, check=False)
        ok = ok and proc.returncode == 1
        if not ok:
            print("SELF-TEST FAIL")
            print(f"  expected: {sorted(SELF_TEST_EXPECTED)}")
            print(f"  got:      {sorted(got)}")
            print(f"  subprocess exit: {proc.returncode}")
            return 1
    print(f"SELF-TEST PASS ({len(SELF_TEST_EXPECTED)} planted violations caught, "
          "covered shapes accepted (wrapper, raw mutex, guard-holding type, isolated child, identity lock for AI_MEMORY_AGENT_ID), comments/strings/production ignored)")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=".", help="repository root (default: .)")
    ap.add_argument("--self-test", action="store_true", help="run the synthetic fixture cells")
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code not in (0, None) else 0
    if args.self_test:
        return self_test()
    try:
        violations = scan(Path(args.root))
    except (OSError, SystemExit) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if violations:
        print(f"FAIL: {len(violations)} unguarded env / cwd mutation(s) in lib test code (#6123):")
        for v in violations:
            print(f"  {v}")
        print("Fix: take crate::config::test_env_lock() (or the identity lock for the "
              "agent-id surface) before mutating the environment; see the script docstring.")
        return 1
    print("PASS: every lib-test env / cwd mutation runs under the process-env lock (#6123)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
