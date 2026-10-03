#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
r"""#4491 gate -- the cheap invariants behind the type-enforced PermissionsMode lock.

Since #4491 (5-agent vote 4d3ea1c5, option B) the compiler proves the lock is held: every writer of
the process-global PermissionsMode (``set_active_permissions_mode``,
``override_active_permissions_mode_for_test``, ``clear_permissions_mode_override_for_test``) takes a
``&PermissionsModeGuard``. The guard's only field is private and its only constructor is
``lock_permissions_mode_for_test``, so a write without the lock, a write after the guard is dropped,
a guard moved into another thread and a guard forged from another mutex are compile errors (the
``compile_fail`` doctests on ``PermissionsModeGuard`` in src/config.rs pin each one).

This gate keeps the few properties the type system cannot see on its own:
  slot_home      ``ACTIVE_PERMISSIONS_MODE`` is mentioned only in src/config.rs.
  slot_writes    it is declared once, written only in ``store_permissions_mode`` (``.write(``) and
                 read only in ``active_permissions_mode`` (``.read(``).
  store_home     ``store_permissions_mode`` is defined once, private, in src/config.rs, and is not
                 mentioned anywhere else.
  one_lock       exactly one ``fn lock_permissions_mode_for_test`` and one
                 ``static PERMISSIONS_MODE_LOCK``, both in src/config.rs; the static is mentioned
                 only inside that fn.
  boot_entry     ``install_boot_permissions_mode`` is defined in src/config.rs and called exactly
                 once, from src/main.rs; any other mention is refused.
  guard_private  ``struct PermissionsModeGuard`` is defined once, in src/config.rs, with no ``pub``
                 field; it is built (``PermissionsModeGuard {``) only inside the lock fn, and its
                 only trait impl is ``Drop``.
  unsafe_guard   an ``unsafe`` block, fn or impl whose body names ``PermissionsModeGuard``, and an
                 ``unsafe`` inside the arguments of a writer call (an inferred forgery that never
                 names the type), are refused.
  alias          a ``type`` alias of the guard and a ``use .. as`` rename to or from it are refused.
  paste          any ``paste`` / ``concat_idents`` mention is refused (token pasting can build
                 names the scan cannot see).
  fixture        the ``compile_fail,E0061`` and ``compile_fail,E0451`` doctests are present in
                 src/config.rs.

The scan set is the compiled set: src/ (required) plus tests/, benches/ and examples/ when present,
closed over ``mod`` declarations (with ``#[path]``), ``include!`` and ``.rs`` ``include_str!``. An
unreadable or non-UTF-8 file, an unreadable or symlinked directory, a missing ``--root``, and an
unresolvable ``mod`` / ``include!`` exit 2 (fail closed).

Residual (tracked separately): ``unsafe`` code that conjures a guard through inference outside a
writer call's arguments is not visible to a lexical scan; ``#![forbid(unsafe_code)]`` in test
crates is the structural fix.

Usage:
  scripts/check_permissions_mode_lock.py                 # scan; exit 1 on any violation
  scripts/check_permissions_mode_lock.py --self-test     # fixtures under TMPDIR or .local-runs
  scripts/check_permissions_mode_lock.py --mutation-sweep  # disable each check; self-test must go red
  scripts/check_permissions_mode_lock.py --root src --root tests
Exit codes: 0 clean, 1 violations (or self-test / sweep failure), 2 usage or fail-closed I/O error.
Python 3.9+, standard library only.
"""
import argparse
import os
import pathlib
import re
import shutil
import sys
import tempfile
from typing import Dict, List, NamedTuple, Optional, Set, Tuple

SLOT = "ACTIVE_PERMISSIONS_MODE"
STORE = "store_permissions_mode"
READER = "active_permissions_mode"
LOCK_FN = "lock_permissions_mode_for_test"
LOCK_STATIC = "PERMISSIONS_MODE_LOCK"
BOOT = "install_boot_permissions_mode"
GUARD = "PermissionsModeGuard"
WRITERS = ("set_active_permissions_mode", "override_active_permissions_mode_for_test",
           "clear_permissions_mode_override_for_test")
CONFIG = "src/config.rs"
MAIN = "src/main.rs"
PASTE_RE = re.compile(r"\b(?:paste|concat_idents)\b")
FIXTURE_CODES = ("E0061", "E0451")

CHECKS = ("slot_home", "slot_writes", "store_home", "one_lock", "boot_entry", "guard_private",
          "unsafe_guard", "alias", "paste", "fixture", "lexer", "strict_read", "unreadable_dir",
          "symlink_dir", "follow_mod", "follow_include", "unresolved_mod")
DISABLED: Set[str] = set()
REPO_ROOT: Optional[pathlib.Path] = None


def on(check: str) -> bool:
    return check not in DISABLED


class GateError(Exception):
    """Fail closed: the scan cannot vouch for the tree (exit 2)."""


class Violation(NamedTuple):
    path: str
    line: int
    check: str
    why: str


# --------------------------------------------------------------------------------------------
# Lexing
# --------------------------------------------------------------------------------------------
CHAR_LIT = re.compile(r"'(\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^\\'])'")


def _ident_before(src: str, i: int) -> bool:
    return i > 0 and (src[i - 1].isalnum() or src[i - 1] == "_")


def blank_literals(src: str) -> str:
    """Blank comments and every string/char literal (all prefixes), keeping offsets and newlines."""
    if not on("lexer"):
        return src
    out = list(src)
    n = len(src)
    i = 0

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif two == "/*":
            depth, j = 1, i + 2
            while j < n and depth:
                if src[j:j + 2] == "/*":
                    depth, j = depth + 1, j + 2
                elif src[j:j + 2] == "*/":
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif (c.isalpha() or c == "_") and not _ident_before(src, i):
            head = src[i:i + 300]
            m = re.match(r"(?:br|cr|r)(#*)\"", head)
            if m is not None:
                close = '"' + m.group(1)
                j = src.find(close, i + m.end())
                j = n if j < 0 else j + len(close)
                blank(i, j)
                i = j
                continue
            if re.match(r"[bc]\"", head):
                j = i + 2
                while j < n and src[j] != '"':
                    j += 2 if src[j] == "\\" else 1
                blank(i, j + 1)
                i = j + 1
                continue
            if head.startswith("b'"):
                m = CHAR_LIT.match(src, i + 1)
                if m is not None:
                    blank(i, m.end())
                    i = m.end()
                    continue
            m = re.match(r"\w+", head)
            i += m.end() if m is not None else 1
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            blank(i, j + 1)
            i = j + 1
        elif c == "'":
            m = CHAR_LIT.match(src, i)
            if m:
                blank(i, m.end())
                i = m.end()
            else:
                i += 1  # lifetime / label
        else:
            i += 1
    return "".join(out)


def match_close(text: str, open_off: int, pair: str = "{}") -> int:
    """Offset just past the bracket matching text[open_off]; len(text) if unbalanced."""
    depth = 0
    for k in range(open_off, len(text)):
        ch = text[k]
        if ch == pair[0]:
            depth += 1
        elif ch == pair[1]:
            depth -= 1
            if depth == 0:
                return k + 1
    return len(text)


def word(name: str) -> "re.Pattern[str]":
    return re.compile(r"(?<![\w])(?:r#)?" + re.escape(name) + r"\b")


def fn_spans(text: str, name: str) -> List[Tuple[int, int]]:
    """(start, end) of every `fn <name>` item with a body."""
    out = []
    for m in re.finditer(r"\bfn\s+(?:r#)?" + re.escape(name) + r"\b", text):
        j = m.end()
        depth = 0
        while j < len(text):
            ch = text[j]
            if ch in "([<":
                depth += 1
            elif ch in ")]>" and not (ch == ">" and text[j - 1] == "-"):
                depth -= 1
            elif ch == ";" and depth <= 0:
                break
            elif ch == "{" and depth <= 0:
                out.append((m.start(), match_close(text, j)))
                break
            j += 1
    return out


def inside(off: int, spans: List[Tuple[int, int]]) -> bool:
    return any(a <= off < b for a, b in spans)


# --------------------------------------------------------------------------------------------
# The compiled set
# --------------------------------------------------------------------------------------------
def read_source(path: pathlib.Path) -> str:
    """Strict read: an unreadable or non-UTF-8 file is a GateError (exit 2), never skipped."""
    try:
        if on("strict_read"):
            return path.read_text(encoding="utf-8")
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError) as e:
        raise GateError(f"{path}: cannot read as UTF-8 ({type(e).__name__}: {e})")


def walk_rs(root: pathlib.Path) -> List[pathlib.Path]:
    """Every .rs file under root; an unreadable or symlinked directory is a GateError."""
    found: List[pathlib.Path] = []
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as e:
            if on("unreadable_dir"):
                raise GateError(f"{d}: cannot list directory ({type(e).__name__}: {e})")
            continue
        for e in entries:
            ep = pathlib.Path(d) / e.name
            if e.is_symlink() and e.is_dir():
                if on("symlink_dir"):
                    raise GateError(f"{ep}: symlinked directory; scan its target explicitly")
                continue
            if e.is_dir(follow_symlinks=False):
                stack.append(ep)
            elif e.name.endswith(".rs"):
                found.append(ep)
    return sorted(found)


def _abs(p: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.path.normpath(str(p))))


def _literal_at(raw: str, k: int) -> Optional[str]:
    m = re.compile(r"\s*(?:\"([^\"\\]*)\"|r(#*)\"(.*?)\"\2)", re.S).match(raw, k)
    if m is None:
        return None
    return m.group(1) if m.group(1) is not None else m.group(3)


def stmt_start(text: str, off: int) -> int:
    k = max(text.rfind(";", 0, off), text.rfind("{", 0, off), text.rfind("}", 0, off))
    return k + 1


def compiled_children(path: pathlib.Path) -> List[pathlib.Path]:
    """Files this file compiles in: `mod x;` (with #[path]) and include!/include_str!("..rs"),
    whichever bracket the macro uses. An unresolvable one is a GateError."""
    raw = read_source(path)
    text = blank_literals(raw)
    d, stem = path.parent, path.stem
    inline = [(m.group(1), m.end() - 1, match_close(text, m.end() - 1))
              for m in re.finditer(r"\bmod\s+(?:r#)?([A-Za-z_]\w*)\s*\{", text)]
    out: List[pathlib.Path] = []
    if on("follow_mod"):
        for m in re.finditer(r"\bmod\s+(?:r#)?([A-Za-z_]\w*)\s*;", text):
            name = m.group(1)
            chain = [n for n, o, c in sorted(inline, key=lambda t: t[1]) if o < m.start() < c]
            bases = [d.joinpath(*chain), d.joinpath(stem, *chain)]
            seg_at = stmt_start(text, m.start())
            values = []
            for pm in re.finditer(r"\bpath\s*=", text[seg_at:m.start()]):
                lit = _literal_at(raw, seg_at + pm.end())
                if lit is None:
                    raise GateError(f"{path}: `mod {name};` has a non-literal path attribute")
                values.append(lit)
            unconditional = re.search(r"#\s*\[\s*path\s*=", text[seg_at:m.start()]) is not None
            pbases = [d] if not chain else bases
            hit: List[pathlib.Path] = []
            for v in values:
                hit += [c for c in (_abs(b / v) for b in pbases) if c.is_file()]
            if not unconditional:
                hit += [c for c in (_abs(b / f"{name}.rs") for b in bases) if c.is_file()]
                hit += [c for c in (_abs(b / name / "mod.rs") for b in bases) if c.is_file()]
            if not hit and on("unresolved_mod"):
                raise GateError(f"{path}: `mod {name};` resolves to no file")
            out += hit
    if on("follow_include"):
        for m in re.finditer(r"\binclude(_str)?\s*!\s*[(\[{]", text):
            lit = _literal_at(raw, m.end())
            is_str = m.group(1) is not None
            if lit is None:
                if is_str:
                    continue  # include_str! of a computed path is data, not code
                raise GateError(f"{path}: include! with a non-literal argument")
            if is_str and not lit.endswith(".rs"):
                continue
            c = _abs(d / lit)
            if not c.is_file():
                raise GateError(f"{path}: include of {lit!r} resolves to no file")
            out.append(c)
    return out


def rust_files(roots: List[pathlib.Path]) -> List[pathlib.Path]:
    found: List[pathlib.Path] = []
    for r in roots:
        if r.is_file():
            found.append(_abs(r))
        elif r.is_dir():
            found += [_abs(p) for p in walk_rs(r)]
        else:
            raise GateError(f"{r}: scan root does not exist")
    seen = set(found)
    queue = list(found)
    while queue:
        for c in compiled_children(queue.pop()):
            if c not in seen:
                seen.add(c)
                found.append(c)
                queue.append(c)
    return found


def rel(path: pathlib.Path) -> str:
    if REPO_ROOT is not None:
        try:
            return _abs(path).relative_to(_abs(REPO_ROOT)).as_posix()
        except ValueError:
            pass
    return path.as_posix()


# --------------------------------------------------------------------------------------------
# The checks
# --------------------------------------------------------------------------------------------
class Src(NamedTuple):
    rel: str
    raw: str
    text: str

    def line(self, off: int) -> int:
        return self.raw.count("\n", 0, off) + 1


def scan(files: List[pathlib.Path]) -> List[Violation]:
    srcs = []
    for p in files:
        raw = read_source(p)
        srcs.append(Src(rel(p), raw, blank_literals(raw)))
    bad: List[Violation] = []

    def v(s: Src, off: int, check: str, why: str) -> None:
        if on(check):
            bad.append(Violation(s.rel, s.line(off), check, why))

    cfg = [s for s in srcs if s.rel == CONFIG]
    if len(cfg) != 1:
        raise GateError(f"{CONFIG} is not in the scan set exactly once; the gate cannot vouch")
    config = cfg[0]
    lock_spans = fn_spans(config.text, LOCK_FN)
    store_spans = fn_spans(config.text, STORE)
    reader_spans = fn_spans(config.text, READER)

    # one_lock / store_home / guard definitions: count across the whole scan set
    lock_defs = [(s, m.start()) for s in srcs for m in re.finditer(r"\bfn\s+" + LOCK_FN + r"\b", s.text)]
    if len(lock_defs) != 1 or lock_defs[0][0].rel != CONFIG:
        for s, off in lock_defs or [(config, 0)]:
            v(s, off, "one_lock", f"`fn {LOCK_FN}` must be defined exactly once, in {CONFIG}")
    static_defs = [(s, m.start()) for s in srcs
                   for m in re.finditer(r"\bstatic\s+" + LOCK_STATIC + r"\b", s.text)]
    if len(static_defs) != 1 or static_defs[0][0].rel != CONFIG:
        for s, off in static_defs or [(config, 0)]:
            v(s, off, "one_lock", f"`static {LOCK_STATIC}` must be declared exactly once, in {CONFIG}")
    store_defs = [(s, m.start()) for s in srcs for m in re.finditer(r"\bfn\s+" + STORE + r"\b", s.text)]
    if len(store_defs) != 1 or store_defs[0][0].rel != CONFIG:
        for s, off in store_defs or [(config, 0)]:
            v(s, off, "store_home", f"`fn {STORE}` must be defined exactly once, in {CONFIG}")
    for s, off in store_defs:
        if re.search(r"\bpub\b[^;{}]*$", s.text[stmt_start(s.text, off):off]):
            v(s, off, "store_home", f"`{STORE}` must stay private")
    guard_defs = [(s, m.start(), m.end()) for s in srcs
                  for m in re.finditer(r"\bstruct\s+" + GUARD + r"\b", s.text)]
    if len(guard_defs) != 1 or guard_defs[0][0].rel != CONFIG:
        for s, off, _ in guard_defs or [(config, 0, 0)]:
            v(s, off, "guard_private", f"`struct {GUARD}` must be defined exactly once, in {CONFIG}")
    struct_spans: List[Tuple[int, int]] = []
    for s, off, end in guard_defs:
        brace = s.text.find("{", end)
        semi = s.text.find(";", end)
        if brace < 0 or (0 <= semi < brace):
            v(s, off, "guard_private", f"`{GUARD}` must be a struct with named private fields")
            continue
        close = match_close(s.text, brace)
        if s.rel == CONFIG:
            struct_spans.append((off, close))
        if re.search(r"\bpub\b", s.text[brace:close]):
            v(s, off, "guard_private", f"a field of `{GUARD}` is `pub`")

    for s in srcs:
        is_cfg = s.rel == CONFIG
        # slot_home / slot_writes
        for m in word(SLOT).finditer(s.text):
            if not is_cfg:
                v(s, m.start(), "slot_home", f"`{SLOT}` mentioned outside {CONFIG}")
                continue
            if re.match(r"static\s", s.text[stmt_start(s.text, m.start()):m.start()].strip() + " "):
                continue
            after = s.text[m.end():m.end() + 40]
            if inside(m.start(), store_spans) and re.match(r"\s*\.\s*write\s*\(", after):
                continue
            if inside(m.start(), reader_spans) and re.match(r"\s*\.\s*read\s*\(", after):
                continue
            v(s, m.start(), "slot_writes",
              f"`{SLOT}` may only be written in `{STORE}` and read in `{READER}`")
        if is_cfg:
            decls = re.findall(r"\bstatic\s+" + SLOT + r"\b", s.text)
            if len(decls) != 1:
                v(s, 0, "slot_writes", f"`{SLOT}` must be declared exactly once")
        # store_home: no mention outside config.rs
        if not is_cfg:
            for m in word(STORE).finditer(s.text):
                v(s, m.start(), "store_home", f"`{STORE}` mentioned outside {CONFIG}")
        # one_lock: the static is mentioned only in its declaration and inside the lock fn
        for m in word(LOCK_STATIC).finditer(s.text):
            if re.search(r"\bstatic\s+$", s.text[max(0, m.start() - 20):m.start()]):
                continue
            if not (is_cfg and inside(m.start(), lock_spans)):
                v(s, m.start(), "one_lock", f"`{LOCK_STATIC}` mentioned outside `{LOCK_FN}`")
        # boot_entry
        for m in word(BOOT).finditer(s.text):
            if is_cfg and re.search(r"\bfn\s+$", s.text[max(0, m.start() - 10):m.start()]):
                continue
            if is_cfg and re.search(r"\bfn\s+" + BOOT, s.text[max(0, m.start() - 20):m.end()]):
                continue
            if s.rel == MAIN and re.match(r"\s*\(", s.text[m.end():]):
                continue
            v(s, m.start(), "boot_entry", f"`{BOOT}` may only be called from {MAIN}")
        if s.rel == MAIN:
            calls = [m for m in word(BOOT).finditer(s.text) if re.match(r"\s*\(", s.text[m.end():])]
            if len(calls) != 1:
                v(s, 0, "boot_entry", f"{MAIN} must call `{BOOT}` exactly once (found {len(calls)})")
        # guard_private: construction and impls
        for m in re.finditer(r"\b" + GUARD + r"\s*\{", s.text):
            if is_cfg and (inside(m.start(), struct_spans) or inside(m.start(), lock_spans)):
                continue
            if re.search(r"->\s*(?:[\w]+\s*::\s*)*$", s.text[max(0, m.start() - 200):m.start()]):
                continue  # a return type followed by the fn body
            if re.search(r"\bimpl\b[^{;]*$", s.text[stmt_start(s.text, m.start()):m.start()]):
                continue
            v(s, m.start(), "guard_private", f"`{GUARD}` is built outside `{LOCK_FN}`")
        for m in re.finditer(r"\bimpl\b([^{;]*?)\bfor\s+(?:[\w:]*::)?" + GUARD + r"\b", s.text):
            trait = m.group(1)
            if is_cfg and re.search(r"\bDrop\s*$", trait.strip() + " ") and "unsafe" not in trait:
                continue
            v(s, m.start(), "guard_private", f"`{GUARD}` may only implement `Drop` (in {CONFIG})")
        # unsafe_guard
        for m in re.finditer(r"\bunsafe\b", s.text):
            brace = s.text.find("{", m.end())
            if brace < 0:
                continue
            end = match_close(s.text, brace)
            # the unsafe item/block itself, plus the statement it sits in (`let g: Guard = unsafe {..}`)
            if word(GUARD).search(s.text, stmt_start(s.text, m.start()), end):
                v(s, m.start(), "unsafe_guard", f"`unsafe` code names `{GUARD}`")
        for w in WRITERS:
            for m in re.finditer(r"\b" + w + r"\s*\(", s.text):
                end = match_close(s.text, m.end() - 1, "()")
                if re.search(r"\bunsafe\b", s.text[m.end():end]):
                    v(s, m.start(), "unsafe_guard", f"`unsafe` inside the arguments of `{w}`")
        # alias
        for m in re.finditer(r"\btype\s+\w+\s*(?:<[^=]*>)?\s*=[^;]*\b" + GUARD + r"\b", s.text):
            v(s, m.start(), "alias", f"`type` alias of `{GUARD}`")
        for m in re.finditer(r"\buse\b[^;]*;", s.text):
            seg = m.group(0)
            if re.search(r"\b" + GUARD + r"\s+as\b", seg) or re.search(r"\bas\s+" + GUARD + r"\b", seg):
                v(s, m.start(), "alias", f"`use .. as` rename of `{GUARD}`")
        # paste
        for m in PASTE_RE.finditer(s.text):
            v(s, m.start(), "paste", "token pasting can build names the scan cannot see")
    # fixture
    for code in FIXTURE_CODES:
        if not re.search(r"///\s*```compile_fail," + code + r"\b", config.raw):
            v(config, 0, "fixture", f"the `compile_fail,{code}` doctest on `{GUARD}` is missing")
    return bad


# --------------------------------------------------------------------------------------------
# Self-test and mutation sweep
# --------------------------------------------------------------------------------------------
GOOD_CONFIG = r'''
static ACTIVE_PERMISSIONS_MODE: std::sync::RwLock<Option<u8>> = std::sync::RwLock::new(None);
static PERMISSIONS_MODE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// ```compile_fail,E0061
/// x();
/// ```
/// ```compile_fail,E0451
/// x();
/// ```
pub struct PermissionsModeGuard {
    _held: std::sync::MutexGuard<'static, ()>,
}
impl Drop for PermissionsModeGuard {
    fn drop(&mut self) {}
}
fn store_permissions_mode(_p: &PermissionsModeGuard, m: Option<u8>) {
    *ACTIVE_PERMISSIONS_MODE.write().unwrap() = m;
}
pub fn install_boot_permissions_mode(m: u8) {
    let g = lock_permissions_mode_for_test();
    store_permissions_mode(&g, Some(m));
}
pub fn set_active_permissions_mode(g: &PermissionsModeGuard, m: u8) { store_permissions_mode(g, Some(m)); }
pub fn active_permissions_mode() -> u8 {
    ACTIVE_PERMISSIONS_MODE.read().ok().and_then(|g| *g).unwrap_or(0)
}
pub fn lock_permissions_mode_for_test() -> PermissionsModeGuard {
    let _held = PERMISSIONS_MODE_LOCK.lock().unwrap();
    PermissionsModeGuard { _held }
}
// a comment naming ACTIVE_PERMISSIONS_MODE and "install_boot_permissions_mode(" is inert
'''
GOOD_MAIN = "fn main() {\n    ai_memory::config::install_boot_permissions_mode(1);\n}\n"
GOOD_LIB = "pub mod config;\n"
GOOD_TEST = ("fn pin() -> ai_memory::config::PermissionsModeGuard {\n"
             "    ai_memory::config::lock_permissions_mode_for_test()\n}\n"
             "#[test]\nfn t() {\n    let g = pin();\n"
             "    ai_memory::config::set_active_permissions_mode(&g, 1);\n}\n")


def tree(**over: str) -> Dict[str, str]:
    files = {"src/lib.rs": GOOD_LIB, "src/config.rs": GOOD_CONFIG, "src/main.rs": GOOD_MAIN,
             "tests/t.rs": GOOD_TEST}
    for k, val in over.items():
        files[k.replace("__", "/").replace("_DOT_", ".")] = val
    return files


def cfg_with(old: str, new: str) -> str:
    if old not in GOOD_CONFIG:
        raise GateError(f"self-test fixture anchor missing: {old!r}")
    return GOOD_CONFIG.replace(old, new)


def t(body: str) -> str:
    return "#[test]\nfn x() {\n" + body + "\n}\n"


# (label, files, expected check name or None for clean, or "<gate>" for exit 2)
FIXTURES: List[Tuple[str, Dict[str, str], Optional[str]]] = [
    ("clean tree", tree(), None),
    ("slot named in a test file", tree(tests__s_DOT_rs=t("let _ = &ACTIVE_PERMISSIONS_MODE;")), "slot_home"),
    ("slot written outside store fn", tree(src__config_DOT_rs=cfg_with(
        "pub fn active_permissions_mode() -> u8 {",
        "pub fn rogue() { *ACTIVE_PERMISSIONS_MODE.write().unwrap() = None; }\n"
        "pub fn active_permissions_mode() -> u8 {")), "slot_writes"),
    ("slot written in the reader", tree(src__config_DOT_rs=cfg_with(
        "ACTIVE_PERMISSIONS_MODE.read().ok()", "ACTIVE_PERMISSIONS_MODE.write().ok()")), "slot_writes"),
    ("slot declared twice", tree(src__config_DOT_rs=GOOD_CONFIG + "mod m { static ACTIVE_PERMISSIONS_MODE: u8 = 0; }\n"),
     "slot_writes"),
    ("store fn made pub", tree(src__config_DOT_rs=cfg_with("fn store_permissions_mode(", "pub fn store_permissions_mode(")),
     "store_home"),
    ("store fn named in a test", tree(tests__s_DOT_rs=t("let _f = store_permissions_mode;")), "store_home"),
    ("second lock fn", tree(tests__s_DOT_rs="fn lock_permissions_mode_for_test() {}\n"), "one_lock"),
    ("second lock static", tree(tests__s_DOT_rs="static PERMISSIONS_MODE_LOCK: u8 = 0;\n"), "one_lock"),
    ("lock static used elsewhere in config", tree(src__config_DOT_rs=GOOD_CONFIG + "fn f() { let _ = PERMISSIONS_MODE_LOCK.lock(); }\n"),
     "one_lock"),
    ("boot entry called from a test", tree(tests__s_DOT_rs=t("ai_memory::config::install_boot_permissions_mode(1);")),
     "boot_entry"),
    ("boot entry imported", tree(tests__s_DOT_rs="use ai_memory::config::install_boot_permissions_mode;\n"), "boot_entry"),
    ("boot entry called twice in main", tree(src__main_DOT_rs="fn main() {\n    install_boot_permissions_mode(1);\n"
                                                              "    install_boot_permissions_mode(2);\n}\n"), "boot_entry"),
    ("boot entry missing from main", tree(src__main_DOT_rs="fn main() {}\n"), "boot_entry"),
    ("guard field made pub", tree(src__config_DOT_rs=cfg_with("    _held: std::sync", "    pub _held: std::sync")),
     "guard_private"),
    ("guard built in a test", tree(tests__s_DOT_rs=t("let g = PermissionsModeGuard { _held: m.lock().unwrap() };")),
     "guard_private"),
    ("guard built outside the lock fn", tree(src__config_DOT_rs=GOOD_CONFIG + "fn f() -> PermissionsModeGuard { PermissionsModeGuard { _held: x() } }\n"),
     "guard_private"),
    ("guard defined twice", tree(tests__s_DOT_rs="struct PermissionsModeGuard { a: u8 }\n"), "guard_private"),
    ("guard gains Clone impl", tree(src__config_DOT_rs=GOOD_CONFIG + "impl Clone for PermissionsModeGuard { fn clone(&self) -> Self { todo!() } }\n"),
     "guard_private"),
    ("unsafe Send impl", tree(tests__s_DOT_rs="unsafe impl Send for ai_memory::config::PermissionsModeGuard {}\n"),
     "guard_private"),
    ("unsafe block names the guard", tree(tests__s_DOT_rs=t(
        "let g: ai_memory::config::PermissionsModeGuard = unsafe { std::mem::transmute(o) };")), "unsafe_guard"),
    ("unsafe block names the guard via turbofish", tree(tests__s_DOT_rs=t(
        "let g = unsafe { std::mem::zeroed::<PermissionsModeGuard>() };")), "unsafe_guard"),
    ("unsafe inside writer arguments", tree(tests__s_DOT_rs=t(
        "ai_memory::config::set_active_permissions_mode(&unsafe { std::mem::zeroed() }, 1);")), "unsafe_guard"),
    ("type alias of the guard", tree(tests__s_DOT_rs="type G = ai_memory::config::PermissionsModeGuard;\n"), "alias"),
    ("use-as rename of the guard", tree(tests__s_DOT_rs="use ai_memory::config::PermissionsModeGuard as G;\n"), "alias"),
    ("paste macro", tree(tests__s_DOT_rs="paste::paste! { fn x() {} }\n"), "paste"),
    ("compile_fail fixture removed", tree(src__config_DOT_rs=cfg_with("compile_fail,E0451", "ignore")), "fixture"),
    ("writer call with guard in a string is inert", tree(tests__s_DOT_rs=t(
        'let s = "unsafe { PermissionsModeGuard {} }"; let r = r#"paste!"#;')), None),
    ("include! with braces is followed", tree(tests__s_DOT_rs="include!{\"frag.rs\"}\n",
                                              tests__frag_DOT_rs="static PERMISSIONS_MODE_LOCK: u8 = 0;\n"), "one_lock"),
    ("include! with brackets is followed", tree(tests__s_DOT_rs="include![\"frag.rs\"];\n",
                                                tests__frag_DOT_rs="type G = PermissionsModeGuard;\n"), "alias"),
    ("#[path] mod is followed", tree(src__lib_DOT_rs=GOOD_LIB + "#[path = \"../extra/x.rs\"]\nmod x;\n",
                                     extra__x_DOT_rs="type G = PermissionsModeGuard;\n"), "alias"),
    ("unresolvable mod exits 2", tree(src__lib_DOT_rs=GOOD_LIB + "mod nowhere;\n"), "<gate>"),
    ("unresolvable include exits 2", tree(tests__s_DOT_rs="include!(\"missing.rs\");\n"), "<gate>"),
    ("non-UTF-8 file exits 2", tree(tests__bad_DOT_rs="\udcff"), "<gate>"),
]


def write_tree(root: pathlib.Path, files: Dict[str, str]) -> None:
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content.encode("utf-8", errors="surrogateescape"))


def run_fixture(root: pathlib.Path) -> Set[str]:
    global REPO_ROOT
    saved = REPO_ROOT
    REPO_ROOT = root
    try:
        roots = [root / "src"] + [root / d for d in ("tests",) if (root / d).is_dir()]
        return {x.check for x in scan(rust_files(roots))}
    except GateError:
        return {"<gate>"}
    finally:
        REPO_ROOT = saved


def extra_checks(work: pathlib.Path) -> List[Tuple[str, bool]]:
    out = []
    # a missing explicit --root exits 2
    rc = run_quiet(["--root", str(work / "does-not-exist")])
    out.append(("missing --root exits 2", rc == 2))
    # a symlinked directory exits 2
    root = work / "symlink"
    write_tree(root, tree())
    (root / "elsewhere").mkdir()
    try:
        os.symlink(str(root / "elsewhere"), str(root / "tests" / "link"))
        out.append(("symlinked directory exits 2", run_fixture(root) == {"<gate>"}))
    except OSError:
        out.append(("symlinked directory exits 2 (symlink unsupported: skipped as pass)", True))
    # an unreadable directory exits 2 (skipped when running as root, which can read anything)
    root = work / "unreadable"
    write_tree(root, tree())
    locked = root / "tests" / "locked"
    locked.mkdir()
    os.chmod(str(locked), 0)
    try:
        readable = os.access(str(locked), os.R_OK)
        out.append(("unreadable directory exits 2", readable or run_fixture(root) == {"<gate>"}))
    finally:
        os.chmod(str(locked), 0o755)
    return out


def run_quiet(argv: List[str]) -> int:
    saved = sys.stderr, sys.stdout
    try:
        with open(os.devnull, "w") as dn:
            sys.stderr = sys.stdout = dn
            return main(argv)
    finally:
        sys.stderr, sys.stdout = saved


def self_test(quiet: bool = False) -> int:
    base = pathlib.Path(os.environ.get("TMPDIR") or ".local-runs")
    base.mkdir(parents=True, exist_ok=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix="pml4491-", dir=str(base)))
    failures = total = 0
    try:
        for idx, (label, files, expect) in enumerate(FIXTURES):
            root = work / f"c{idx}"
            write_tree(root, files)
            got = run_fixture(root)
            ok = (not got) if expect is None else (expect in got)
            total += 1
            failures += 0 if ok else 1
            if not quiet:
                print(f"  [{'ok' if ok else 'FAIL'}] {label} -> {sorted(got) or 'clean'}"
                      f" (expected {expect or 'clean'})")
        for label, ok in extra_checks(work):
            total += 1
            failures += 0 if ok else 1
            if not quiet:
                print(f"  [{'ok' if ok else 'FAIL'}] {label}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if not quiet:
        print(f"self-test: {total - failures}/{total} fixtures behaved")
    return 1 if failures else 0


def mutation_sweep() -> int:
    """Disable each check in turn; the self-test must go red every time (else the check is dead)."""
    if self_test(quiet=True) != 0:
        print("mutation-sweep: the self-test is red on the unmutated gate", file=sys.stderr)
        return 1
    red = 0
    for name in CHECKS:
        DISABLED.clear()
        DISABLED.add(name)
        try:
            went_red = self_test(quiet=True) != 0
        finally:
            DISABLED.clear()
        red += 1 if went_red else 0
        print(f"  [{'red' if went_red else 'STILL GREEN'}] disable {name}")
    print(f"mutation-sweep: {red}/{len(CHECKS)} checks turn the self-test red when disabled")
    return 0 if red == len(CHECKS) else 1


def main(argv: Optional[List[str]] = None) -> int:
    global REPO_ROOT
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--root", action="append", default=None,
                    help="directory or .rs file to scan (repeatable; default: src + tests/benches/examples)")
    ap.add_argument("--self-test", action="store_true", help="run positive and negative fixtures")
    ap.add_argument("--mutation-sweep", action="store_true",
                    help="disable each check; the self-test must turn red for every one")
    args = ap.parse_args(argv)
    repo = pathlib.Path(__file__).resolve().parent.parent
    try:
        if args.self_test:
            return self_test()
        if args.mutation_sweep:
            return mutation_sweep()
        REPO_ROOT = repo
        if args.root:
            roots = [pathlib.Path(r) for r in args.root]
        else:
            roots = [repo / "src"] + [repo / d for d in ("tests", "benches", "examples") if (repo / d).is_dir()]
        files = rust_files(roots)
        if not files:
            raise GateError("no .rs files under " + ", ".join(map(str, roots)))
        bad = scan(files)
    except GateError as e:
        print(f"check_permissions_mode_lock: {e}", file=sys.stderr)
        return 2
    for x in sorted(bad):
        print(f"{x.path}:{x.line}: [{x.check}] {x.why}")
    if bad:
        print(f"check_permissions_mode_lock: {len(bad)} violation(s) of the #4491 lock invariants",
              file=sys.stderr)
        return 1
    print(f"check_permissions_mode_lock: {len(files)} files; the PermissionsMode slot, lock, guard "
          f"and boot entry hold their #4491 invariants")
    return 0


if __name__ == "__main__":
    sys.exit(main())
