#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
r"""#4491 gate -- INVARIANT: every write of the process-global PermissionsMode, other than the
production boot setter, must run in a scope that holds a LIVE
``crate::config::lock_permissions_mode_for_test()`` guard.

The active mode is one process-wide slot. ``cargo test --lib`` runs many cells that flip it
(governance matrices, rules scopes, link-attest, ck_trigger, the postgres ``live_governance_*``
cells). A cell that writes the slot without the serialisation lock races every other mode-flipping
cell, so a guard that is supposed to prove Deny/Pending behaviour flakes under ``--test-threads=4``.
The discipline was convention only and recurred three times: #1465, #2165, #4468.

WRITERS (the three functions in src/config.rs that mutate the slot):
  set_active_permissions_mode, override_active_permissions_mode_for_test,
  clear_permissions_mode_override_for_test.
The lock: lock_permissions_mode_for_test.

WHO MAY WRITE WITHOUT THE LOCK (fail closed: an allowlist of exact (file, fn) pairs, not a
classification of lines). ``main`` in src/main.rs (the boot setter) and
``override_active_permissions_mode_for_test`` in src/config.rs (the alias that forwards to the
setter). Every other writer call in the scanned tree is checked, whatever the #3623 test/production
boundary says about its line, so a ``#[test]`` fn on a line the boundary mis-classes as production
(src/bench.rs, #4755), a ``#[cfg(any(test, ..))]`` item, or a test module in a separately named
file cannot hide a write. A fn carrying ``#[test]`` / ``#[tokio::test]`` / ``#[sqlx::test]`` is never
allowlisted.

RULE, per writer call that is not allowlisted: the enclosing fn must hold a LIVE guard at that call.
A guard is live when ALL of these hold:
  1. it is bound by ``let [mut] <ident> = <lock>(..);`` where ``<lock>`` is the lock itself or a
     DELEGATE; ``let _ = ..``, a bare ``<lock>();`` statement and a longer expression drop the
     guard at once and do not count;
  2. the binding statement ends before the writer call and the writer call sits inside the block
     the guard is bound in (a guard bound in an inner block that has closed, in a branch not
     taken, or in a closure that is not the writer's, covers nothing outside it);
  3. there is no ``drop(<ident>)`` between the binding and the writer call.
Every writer call in the fn is checked, not only the first.
A DELEGATE is a fn that returns the guard to its caller: its return type is ``MutexGuard<..>`` or a
struct that owns one, it binds the lock (or another delegate) as in 1., and that binding is used
again after the statement (moved into the return value) without a ``drop``. A helper that locks and
releases on return (unit return) is NOT a delegate. Delegates are derived by a fixpoint over the
scanned tree; the name counts only when EVERY fn carrying it qualifies (one unlocked homonym
disqualifies it).
A ``fn drop`` in ``impl Drop for T`` may reset the mode without a binding when T is a struct (a
``MutexGuard`` owner) that a delegate returns, i.e. T carries the mode lock, which is released only
after ``drop`` returns (the ``RulesScope`` / ``RulesGuard`` shape). A type that owns some other
MutexGuard does not qualify.
A writer call in no function at all is refused.

ALIASING (refused, since a lexical gate cannot follow it): ``use .. writer as x``, and any mention
of a writer that is not a direct call and not a plain ``use`` import or its ``fn`` definition (a fn
pointer, ``let f = path::writer;``, passing it as an argument).

BOUNDARY (secondary). The #3623 policy of scripts/lib/production-lines.{sh,awk} is ported
(a file whose stem matches ``(^|_)tests?(_|$)``, or that sits under a directory named ``tests``
RELATIVE to the scan root's parent, is entirely test; ``#![cfg(test)]``; ``#[cfg(test)]`` and
``#[cfg(all(test,`` items). It no longer decides what is checked; it feeds ``--parity`` and a
non-failing note listing ``#[test]`` fns on production-classed lines (visible, never silently
excluded: src/bench.rs is the live case, #4755). The directory rule is a deliberate deviation from
the awk, which has none; ``--parity`` skips those files.

LEXING. Comments (``//``, nested ``/* */``) and string/char literals (including raw strings) are
blanked before any matching, so a writer or lock name inside a comment or a string neither raises
nor satisfies the rule.

SCOPE, stated honestly: roots default to ``src`` (lib tests, which share one process and are the
#4468 shape). Integration binaries under tests/ are NOT scanned by default (``--root tests`` scans
them; 38 unlocked writes in 25 files on 5f66513a1, tracked as #4754). The check is lexical and
name-based: it does not model moves of the guard into another owner, shadowing, or control flow
beyond the brace structure.

Usage:
  scripts/check_permissions_mode_lock.py              # scan src/ -- exit 1 on any violation
  scripts/check_permissions_mode_lock.py --self-test  # fixtures under TMPDIR/.local-runs, never /tmp
  scripts/check_permissions_mode_lock.py --mutation-sweep  # disable each check; the self-test must go red
  scripts/check_permissions_mode_lock.py --parity     # boundary parity vs scripts/lib/production-lines.awk
  scripts/check_permissions_mode_lock.py --root src --root tests
Exit codes: 0 clean, 1 violations (or self-test/parity/sweep failure), 2 usage, an unreadable or
undecodable file, or an internal error (fail closed). Python 3.9+, standard library only.
"""
import argparse
import bisect
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, Dict, List, NamedTuple, Optional, Set, Tuple

WRITERS = (
    "set_active_permissions_mode",
    "override_active_permissions_mode_for_test",
    "clear_permissions_mode_override_for_test",
)
LOCK = "lock_permissions_mode_for_test"

# Production writers allowed without the lock: (path relative to the scan root or its parent, fn).
ALLOWED_WRITERS = (
    ("src/main.rs", "main"),
    ("src/config.rs", "override_active_permissions_mode_for_test"),
)

STEM_TEST = re.compile(r"(^|_)tests?(_|$)")
TEST_ATTR = re.compile(r"#\s*\[\s*(?:\w+\s*::\s*)*(?:test|rstest|test_case)\b")

# Check names, for --mutation-sweep: disabling any ONE must turn the self-test red.
CHECKS = (
    "lexer", "no_enclosing_fn", "all_lines", "allowlist_path", "allowlist_test_attr",
    "top_level_binding", "bound_ident", "lock_before_write", "drop_check", "each_write",
    "delegate_return_type", "delegate_guard_moved", "delegate_homonym", "fixpoint",
    "drop_mode_guard", "alias_use", "alias_value", "tests_dir_relative", "strict_read",
    "boundary_note",
)
DISABLED: Set[str] = set()


def on(check: str) -> bool:
    return check not in DISABLED


class GateError(Exception):
    """An unreadable/undecodable input: the gate cannot vouch for the tree (exit 2)."""


# Root each scanned file was found under (for root-relative path rules).
ROOT_OF: Dict[pathlib.Path, pathlib.Path] = {}


def rel_forms(path: pathlib.Path) -> Tuple[str, str]:
    """(path relative to its scan root, path relative to the scan root's parent), posix."""
    root = ROOT_OF.get(path)
    if root is None or root == path:
        return path.name, path.name
    try:
        a = path.relative_to(root).as_posix()
        b = path.relative_to(root.parent).as_posix()
    except ValueError:
        return path.as_posix(), path.as_posix()
    return a, b


def in_tests_dir(path: pathlib.Path) -> bool:
    if not on("tests_dir_relative"):
        return "tests" in path.parts
    return "tests" in pathlib.PurePosixPath(rel_forms(path)[1]).parts[:-1]


# --------------------------------------------------------------------------------------------
# #3623 production-lines boundary (port of scripts/lib/production-lines.awk) -- secondary
# --------------------------------------------------------------------------------------------
def test_line_mask(path: pathlib.Path, lines: List[str]) -> List[bool]:
    """True for each line that is TEST code (blanked by production-lines)."""
    if STEM_TEST.search(path.stem) or in_tests_dir(path):
        return [True] * len(lines)
    if any(re.match(r"^\s*#!\[cfg\(test\)\]", ln) for ln in lines):
        return [True] * len(lines)
    mask = [False] * len(lines)
    skipping = False
    opened = False
    anchor = 0
    tail = re.compile(r"[;]?\s*(//.*)?$")
    for i, ln in enumerate(lines):
        s = ln.lstrip()
        indent = len(ln) - len(s)
        if not skipping and s.startswith("#[cfg(test)]"):
            skipping, anchor = True, indent
        if not skipping and re.match(r"^#\[cfg\(all\(test[,)]", s):
            skipping, anchor = True, indent
        if skipping:
            mask[i] = True
            s = re.sub(r"^#\[cfg\(test\)\]\s*", "", s, count=1)
            if s.startswith("#") or s.startswith("//") or s == "":
                continue
            if not opened and "{" in s:
                opened = True
            end_semi = (not opened) and re.search(r";\s*(//.*)?$", s)
            end_brace = opened and indent == anchor and re.match(r"^\}" + tail.pattern, s)
            end_inline = opened and indent == anchor and re.search(r"\{.*\}" + tail.pattern, s)
            if end_semi or end_brace or end_inline:
                skipping = False
                opened = False
    return mask


# --------------------------------------------------------------------------------------------
# Lexer: blank comments and string/char literals, keep newlines and offsets
# --------------------------------------------------------------------------------------------
def blank_literals(src: str) -> str:
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
        elif c in "rb" and re.match(r"b?r#*\"", src[i:i + 40]) and not _ident_before(src, i):
            m = re.match(r"b?r(#*)\"", src[i:i + 40])
            if m is None:
                raise GateError("lexer: raw-string prefix vanished")
            close = '"' + m.group(1)
            j = src.find(close, i + m.end())
            j = n if j < 0 else j + len(close)
            blank(i, j)
            i = j
        elif c == '"' or (c == "b" and src[i + 1:i + 2] == '"' and not _ident_before(src, i)):
            j = i + (2 if c == "b" else 1)
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            blank(i, j + 1)
            i = j + 1
        elif c == "'":
            m = re.match(r"'(\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^\\'])'", src[i:i + 16])
            if m:
                blank(i, i + m.end())
                i += m.end()
            else:
                i += 1  # lifetime / label
        else:
            i += 1
    return "".join(out)


def _ident_before(src: str, i: int) -> bool:
    return i > 0 and (src[i - 1].isalnum() or src[i - 1] == "_")


# --------------------------------------------------------------------------------------------
# Function model
# --------------------------------------------------------------------------------------------
class Fn(NamedTuple):
    name: str
    path: pathlib.Path
    kw_off: int      # offset of `fn`
    open_off: int    # offset of body `{`
    close_off: int   # offset one past body `}`
    is_test: bool    # `fn` keyword sits on a line the #3623 boundary classes as test
    in_drop_of: Optional[str]  # type T when inside `impl Drop for T`
    sig: str         # text between the name and the body `{`
    has_test_attr: bool


FN_RE = re.compile(r"\bfn\s+([A-Za-z_]\w*)")
DROP_IMPL_RE = re.compile(r"\bimpl\b[^{;]*?\bDrop\s+for\s+([A-Za-z_]\w*)[^{;]*\{")


def match_brace(text: str, open_off: int) -> int:
    depth = 0
    for k in range(open_off, len(text)):
        ch = text[k]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return k + 1
    return len(text)


def match_paren(text: str, open_off: int) -> int:
    depth = 0
    for k in range(open_off, len(text)):
        ch = text[k]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return k + 1
    return len(text)


def find_fns(text: str, line_starts: List[int], mask: List[bool], path: pathlib.Path) -> List[Fn]:
    drop_spans: List[Tuple[int, int, str]] = []
    for m in DROP_IMPL_RE.finditer(text):
        ob = m.end() - 1
        drop_spans.append((ob, match_brace(text, ob), m.group(1)))
    fns: List[Fn] = []
    for m in FN_RE.finditer(text):
        k = m.end()
        depth = 0
        body_open = -1
        while k < len(text):
            ch = text[k]
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
            elif depth == 0 and ch == ";":
                break
            elif depth == 0 and ch == "{":
                body_open = k
                break
            k += 1
        if body_open < 0:
            continue
        line = bisect.bisect_right(line_starts, m.start()) - 1
        in_drop = None
        for a, b, t in drop_spans:
            if a < m.start() < b and m.group(1) == "drop":
                in_drop = t
        seg_start = max(text.rfind(";", 0, m.start()), text.rfind("{", 0, m.start()),
                        text.rfind("}", 0, m.start())) + 1
        has_attr = bool(TEST_ATTR.search(text[seg_start:m.start()]))
        fns.append(Fn(m.group(1), path, m.start(), body_open, match_brace(text, body_open),
                      mask[line], in_drop, text[m.end():body_open], has_attr))
    return fns


# --------------------------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------------------------
class Violation(NamedTuple):
    path: pathlib.Path
    line: int
    fn: str
    why: str


class FileModel(NamedTuple):
    path: pathlib.Path
    text: str
    line_starts: List[int]
    mask: List[bool]
    fns: List[Fn]


def read_source(path: pathlib.Path) -> str:
    """Strict read: an unreadable or non-UTF-8 file is a GateError (exit 2), never skipped."""
    try:
        if on("strict_read"):
            return path.read_text(encoding="utf-8")
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError) as e:
        raise GateError(f"{path}: cannot read as UTF-8 ({type(e).__name__}: {e})")


def load(path: pathlib.Path) -> FileModel:
    raw = read_source(path)
    lines = raw.split("\n")
    mask = test_line_mask(path, lines)
    text = blank_literals(raw)
    starts, off = [], 0
    for ln in lines:
        starts.append(off)
        off += len(ln) + 1
    return FileModel(path, text, starts, mask, find_fns(text, starts, mask, path))


def line_of(fm: FileModel, off: int) -> int:
    return bisect.bisect_right(fm.line_starts, off)  # 1-based


def innermost(fns: List[Fn], off: int) -> Optional[Fn]:
    best: Optional[Fn] = None
    for f in fns:
        if f.open_off < off < f.close_off and (best is None or f.open_off > best.open_off):
            best = f
    return best


def call_offsets(text: str, name: str, a: int, b: int) -> List[int]:
    """Offsets of call sites of `name` in text[a:b] (excludes `fn name` definitions)."""
    hits = []
    for m in re.finditer(r"\b" + re.escape(name) + r"\s*\(", text[a:b]):
        off = a + m.start()
        if re.search(r"\bfn\s+$", text[max(0, off - 12):off]):
            continue
        hits.append(off)
    return hits


def guard_owning_structs(models: List[FileModel]) -> Dict[str, Set[pathlib.Path]]:
    """struct name -> files where a struct of that name owns a MutexGuard field."""
    out: Dict[str, Set[pathlib.Path]] = {}
    for fm in models:
        for m in re.finditer(r"\bstruct\s+([A-Za-z_]\w*)", fm.text):
            k = m.end()
            while k < len(fm.text) and fm.text[k] not in "{(;":
                k += 1
            if k >= len(fm.text) or fm.text[k] == ";":
                continue
            end = match_brace(fm.text, k) if fm.text[k] == "{" else match_paren(fm.text, k)
            if "MutexGuard" in fm.text[k:end]:
                out.setdefault(m.group(1), set()).add(fm.path)
    return out


def return_type(sig: str) -> str:
    k = sig.find("(")
    if k < 0:
        return ""
    rest = sig[match_paren(sig, k):]
    arrow = rest.find("->")
    if arrow < 0:
        return ""
    return re.split(r"\bwhere\b", rest[arrow + 2:])[0].strip()


# --------------------------------------------------------------------------------------------
# Guard bindings
# --------------------------------------------------------------------------------------------
class Binding(NamedTuple):
    ident: Optional[str]
    end: int        # offset one past the `;` of the binding statement
    scope_end: int  # offset one past the `}` of the block the guard lives in


LET_RE = re.compile(r"\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]*)?=(?!=)")
CALL_HEAD = re.compile(r"^(?:self\s*\.\s*|(?:[A-Za-z_]\w*\s*::\s*)*)([A-Za-z_]\w*)\s*\(")


def brace_spans(text: str, a: int, b: int) -> List[Tuple[int, int]]:
    """(open, close-exclusive) of every `{..}` block inside text[a:b]."""
    stack: List[int] = []
    spans: List[Tuple[int, int]] = []
    for k in range(a, b):
        if text[k] == "{":
            stack.append(k)
        elif text[k] == "}" and stack:
            spans.append((stack.pop(), k + 1))
    return spans


def statement_end(text: str, start: int, limit: int) -> int:
    """Offset of the `;` that ends the statement beginning at `start`, or -1."""
    depth = 0
    for k in range(start, limit):
        ch = text[k]
        if ch in "{([":
            depth += 1
        elif ch in "})]":
            depth -= 1
            if depth < 0:
                return -1
        elif ch == ";" and depth == 0:
            return k
    return -1


def lock_bindings(fm: FileModel, f: Fn, lockers: Set[str]) -> List[Binding]:
    """Guards of the mode lock bound by `let <ident> = <lock>(..);` directly in a block of f.

    A binding is live from the end of its statement to the end of the innermost block that
    contains it, so a guard bound in an inner block, a branch or a closure does not cover code
    outside that block.
    """
    text = fm.text
    if not on("top_level_binding"):
        # Old, lexical behaviour: any lock/delegate call in the fn counts, wherever it sits.
        return [Binding(None, o, f.close_off) for g in sorted(lockers)
                for o in call_offsets(text, g, f.open_off, f.close_off)]
    spans = brace_spans(text, f.open_off, f.close_off)
    found: List[Binding] = []
    for m in LET_RE.finditer(text, f.open_off + 1, f.close_off):
        ident = m.group(1)
        if ident == "_" and on("bound_ident"):
            continue  # `let _ = ..` drops the guard at once
        if innermost(fm.fns, m.start()) is not f:
            continue  # belongs to a nested fn
        semi = statement_end(text, m.end(), f.close_off)
        if semi < 0:
            continue
        rhs = text[m.end():semi].strip()
        h = CALL_HEAD.match(rhs)
        if h is None or h.group(1) not in lockers:
            continue
        if rhs[match_paren(rhs, h.end() - 1):].strip() != "":
            continue  # the guard is a temporary of a longer expression
        scope_end = min((e for o, e in spans if o < m.start() < e), key=lambda e: e,
                        default=f.close_off)
        found.append(Binding(ident, semi + 1, scope_end))
    return found


def dropped(text: str, ident: Optional[str], a: int, b: int) -> bool:
    if ident is None or not on("drop_check"):
        return False
    return re.search(r"\bdrop\s*\(\s*(?:&\s*mut\s+|&\s*)?" + re.escape(ident) + r"\b",
                     text[a:b]) is not None


def guard_live_at(fm: FileModel, bindings: List[Binding], write: int) -> bool:
    for b in bindings:
        if on("lock_before_write") and b.end > write:
            continue
        if on("top_level_binding") and write >= b.scope_end:
            continue  # the guard's block closed before this write
        if dropped(fm.text, b.ident, b.end, write):
            continue
        return True
    return False


# --------------------------------------------------------------------------------------------
# Delegates
# --------------------------------------------------------------------------------------------
class Delegates(NamedTuple):
    names: Set[str]
    types: Set[str]  # struct names returned by a qualifying delegate


def qualifies(fm: FileModel, f: Fn, lockers: Set[str], guard_types: Set[str]) -> Optional[str]:
    """None if fn f does not return the mode guard; else the return type text."""
    rtype = return_type(f.sig)
    if on("delegate_return_type"):
        ok = "MutexGuard" in rtype or any(re.search(r"\b" + re.escape(t) + r"\b", rtype)
                                          for t in guard_types)
        if not ok:
            return None
    binds = lock_bindings(fm, f, lockers)
    if on("delegate_guard_moved"):
        moved = False
        for b in binds:
            if b.ident is None:
                continue
            if (re.search(r"\b" + re.escape(b.ident) + r"\b", fm.text[b.end:b.scope_end])
                    and not dropped(fm.text, b.ident, b.end, b.scope_end)):
                moved = True
        if not moved:
            return None
    elif not binds:
        return None
    return rtype


def compute_delegates(models: List[FileModel]) -> Delegates:
    owners = guard_owning_structs(models)
    guard_types = set(owners)
    by_name: Dict[str, List[Tuple[FileModel, Fn]]] = {}
    for fm in models:
        for f in fm.fns:
            by_name.setdefault(f.name, []).append((fm, f))
    names: Set[str] = set()
    types: Set[str] = set()
    changed = True
    while changed:
        changed = False
        lockers = {LOCK, *names}
        for name, defs in by_name.items():
            if name in names or name == LOCK:
                continue
            rtypes = [qualifies(fm, f, lockers, guard_types) for fm, f in defs]
            good = [r for r in rtypes if r is not None]
            if (on("delegate_homonym") and len(good) == len(defs)) or \
                    (not on("delegate_homonym") and good):
                names.add(name)
                for r in good:
                    types.update(t for t in guard_types if re.search(r"\b" + re.escape(t) + r"\b", r))
                changed = bool(on("fixpoint"))
    return Delegates(names, types)


# --------------------------------------------------------------------------------------------
# Writer references
# --------------------------------------------------------------------------------------------
def use_spans(text: str) -> List[Tuple[int, int]]:
    return [(m.start(), m.end()) for m in re.finditer(r"\buse\b[^;]*;", text)]


def writer_refs(fm: FileModel) -> Tuple[List[int], List[Tuple[int, str]]]:
    """(call offsets, [(offset, why)] for aliasing / non-call references)."""
    spans = use_spans(fm.text)
    calls: List[int] = []
    bad: List[Tuple[int, str]] = []
    for w in WRITERS:
        for m in re.finditer(r"\b" + re.escape(w) + r"\b", fm.text):
            off = m.start()
            if re.search(r"\bfn\s+$", fm.text[max(0, off - 12):off]):
                continue
            if any(a <= off < b for a, b in spans):
                if on("alias_use") and re.match(r"\s+as\b", fm.text[m.end():m.end() + 8]):
                    bad.append((off, f"writer {w} renamed with `as` in a use"))
                continue
            if re.match(r"\s*\(", fm.text[m.end():m.end() + 8]):
                calls.append(off)
            elif on("alias_value"):
                bad.append((off, f"writer {w} used as a value (alias / fn pointer)"))
    return sorted(calls), sorted(bad)


def allowed_writer(fm: FileModel, f: Fn) -> bool:
    if f.has_test_attr and on("allowlist_test_attr"):
        return False
    rels = rel_forms(fm.path)
    for path, name in ALLOWED_WRITERS:
        if f.name == name and (not on("allowlist_path") or path in rels):
            return True
    return False


def drop_exempt(f: Fn, dg: Delegates) -> bool:
    if not f.in_drop_of:
        return False
    if on("drop_mode_guard"):
        return f.in_drop_of in dg.types
    return True


# --------------------------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------------------------
def scan(files: List[pathlib.Path]) -> List[Violation]:
    models = [load(p) for p in files]
    dg = compute_delegates(models)
    lockers = {LOCK, *dg.names}
    out: List[Violation] = []
    for fm in models:
        calls, bad = writer_refs(fm)
        for off, why in bad:
            out.append(Violation(fm.path, line_of(fm, off), "<reference>", why))
        by_fn: Dict[Optional[int], List[int]] = {}
        for off in calls:
            if not on("all_lines") and not fm.mask[line_of(fm, off) - 1]:
                continue  # old behaviour: production-classed line ignored
            f = innermost(fm.fns, off)
            by_fn.setdefault(None if f is None else f.open_off, []).append(off)
        by_open = {f.open_off: f for f in fm.fns}
        for key, offs in by_fn.items():
            if key is None:
                if on("no_enclosing_fn"):
                    out.append(Violation(fm.path, line_of(fm, offs[0]), "<no enclosing fn>",
                                         "mode write outside any function"))
                continue
            f = by_open[key]
            if allowed_writer(fm, f) or drop_exempt(f, dg):
                continue
            bindings = lock_bindings(fm, f, lockers)
            for off in (offs if on("each_write") else offs[:1]):
                if guard_live_at(fm, bindings, off):
                    continue
                anywhere = [o for g in sorted(lockers)
                            for o in call_offsets(fm.text, g, f.open_off, f.close_off)]
                if not anywhere:
                    why = ("mode write is not preceded by lock_permissions_mode_for_test (or a "
                           "delegate that takes it)")
                else:
                    why = ("no live lock guard at this mode write (lock taken after it, bound "
                           "only in an inner block/branch/closure, dropped, or not bound by "
                           "`let <ident>`)")
                out.append(Violation(fm.path, line_of(fm, off), f.name, why))
                break
    return out


def boundary_gaps(files: List[pathlib.Path]) -> Dict[pathlib.Path, int]:
    """Per file: count of test-attribute fns on lines the #3623 boundary classes as production."""
    if not on("boundary_note"):
        return {}
    gaps: Dict[pathlib.Path, int] = {}
    for p in files:
        fm = load(p)
        n = sum(1 for f in fm.fns if f.has_test_attr and not fm.mask[line_of(fm, f.kw_off) - 1])
        if n:
            gaps[p] = n
    return gaps


def rust_files(roots: List[pathlib.Path]) -> List[pathlib.Path]:
    found: List[pathlib.Path] = []
    for r in roots:
        if r.is_file():
            found.append(r)
            ROOT_OF[r] = r
        elif r.is_dir():
            for p in sorted(r.rglob("*.rs")):
                found.append(p)
                ROOT_OF[p] = r
    return found


# --------------------------------------------------------------------------------------------
# Parity with the awk boundary
# --------------------------------------------------------------------------------------------
def parity(files: List[pathlib.Path], repo: pathlib.Path) -> int:
    awk = shutil.which("awk")
    if awk is None:
        print("parity: awk not found", file=sys.stderr)
        return 2
    awk_script = repo / "scripts/lib/production-lines.awk"
    bad = 0
    for p in files:
        lines = read_source(p).split("\n")
        mask = test_line_mask(p, lines)
        if STEM_TEST.search(p.stem) or in_tests_dir(p):
            awk_prod = [""] * len(lines)  # production_lines() prints nothing for these stems
        else:
            try:
                res = subprocess.run([awk, "-f", str(awk_script), str(p)], capture_output=True,
                                     text=True, check=True)
            except (OSError, subprocess.CalledProcessError) as e:
                raise GateError(f"parity: awk failed on {p}: {e}")
            awk_prod = res.stdout.split("\n")
            if awk_prod and awk_prod[-1] == "" and len(awk_prod) > len(lines):
                awk_prod = awk_prod[:len(lines)]
        for i, ln in enumerate(lines):
            awk_is_test = (i >= len(awk_prod)) or awk_prod[i] != ln
            if ln.strip() == "":
                continue
            if awk_is_test != mask[i]:
                print(f"parity MISMATCH {p}:{i + 1}")
                bad += 1
                break
    print(f"parity: {len(files)} files, {bad} mismatching")
    return 1 if bad else 0


# --------------------------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------------------------
W = "crate::config::override_active_permissions_mode_for_test(crate::config::PermissionsMode::Enforce);"
CLR = "crate::config::clear_permissions_mode_override_for_test();"
LK = "crate::config::lock_permissions_mode_for_test()"
L = f"let _g = {LK};"
GT = "std::sync::MutexGuard<'static, ()>"


def tm(body: str, pre: str = "") -> str:
    """A cfg(test) module around `body`."""
    return f"{pre}#[cfg(test)]\nmod tests {{\n{body}\n}}\n"


def t_fn(body: str, name: str = "t", attr: str = "#[test]") -> str:
    return f"    {attr}\n    fn {name}() {{\n{body}\n    }}\n"


# (label, {relative path: content}, expect_violation)
FIXTURES: List[Tuple[str, Dict[str, str], bool]] = [
    ("unpaired write in cfg(test) mod is refused", {"src/a.rs": tm(t_fn(f"        {W}"))}, True),
    ("unpaired set_active write in a *_tests.rs file is refused", {"src/b_tests.rs":
        "#[test]\nfn t() {\n    crate::config::set_active_permissions_mode(crate::config::PermissionsMode::Off);\n}\n"}, True),
    ("unpaired clear in a tests.rs file is refused", {"src/c/tests.rs": f"fn reset() {{\n    {CLR}\n}}\n"}, True),
    ("lock taken AFTER the write is refused", {"src/d.rs": tm(t_fn(f"        {W}\n        {L}"))}, True),
    ("lock named only in a comment does not satisfy", {"src/e.rs":
        tm(t_fn(f"        // {LK}\n        {W}"))}, True),
    ("homonym delegate that does not lock disqualifies the name", {"src/f.rs": tm(
        f"    fn scope() -> u8 {{ 0 }}\n    mod inner {{\n        fn scope() -> {GT} {{ let g = {LK}; g }}\n    }}\n"
        + t_fn(f"        let _s = scope();\n        {W}"))}, True),
    ("Drop impl whose type owns no guard is refused", {"src/g.rs": tm(
        f"    struct S {{ n: u8 }}\n    impl Drop for S {{\n        fn drop(&mut self) {{ {CLR} }}\n    }}")}, True),
    ("write outside any fn is refused", {"src/h_tests.rs": f"static X: () = {{ {W} }};\n"}, True),
    ("production fn writing the mode is refused (only main may)", {"src/i.rs":
        f"pub fn boot() {{\n    crate::config::set_active_permissions_mode(m);\n}}\n"}, True),
    ("fn main in src/main.rs is the one allowed production writer", {"src/main.rs":
        "fn main() {\n    crate::config::set_active_permissions_mode(m);\n}\n"}, False),
    ("another fn in src/main.rs is refused", {"src/main.rs":
        "fn main() {}\nfn helper() {\n    crate::config::set_active_permissions_mode(m);\n}\n"}, True),
    ("fn main in another file is refused", {"src/other.rs":
        "fn main() {\n    crate::config::set_active_permissions_mode(m);\n}\n"}, True),
    ("a #[test] fn named main in src/main.rs is refused", {"src/main.rs":
        f"#[test]\nfn main() {{\n    {W}\n}}\n"}, True),
    ("config.rs alias forwarding to the setter is allowed", {"src/config.rs":
        "pub fn override_active_permissions_mode_for_test(m: u8) {\n    set_active_permissions_mode(m);\n}\n"
        "pub fn set_active_permissions_mode(m: u8) { let _ = m; }\n"}, False),
    ("another fn in config.rs writing the mode is refused", {"src/config.rs":
        "pub fn set_active_permissions_mode(m: u8) { let _ = m; }\npub fn sneaky(m: u8) {\n    set_active_permissions_mode(m);\n}\n"}, True),
    ("the alias name in another file is refused", {"src/x.rs":
        "pub fn override_active_permissions_mode_for_test(m: u8) {\n    set_active_permissions_mode(m);\n}\n"}, True),
    ("direct lock then write is accepted", {"src/j.rs": tm(t_fn(f"        {L}\n        {W}\n        {CLR}"))}, False),
    ("guard live through every later write is accepted", {"src/j2.rs": tm(
        t_fn(f"        {L}\n        {W}\n        {CLR}\n        {W}"))}, False),
    ("guard bound inside an async block / closure that also holds the write is accepted", {"src/j4.rs": tm(
        t_fn(f"        with_env(async {{\n            {L}\n            {W}\n        }});"))}, False),
    ("guard bound in an inner block covers writes in that block and its sub-blocks", {"src/j5.rs": tm(
        t_fn(f"        {{\n            {L}\n            if c {{ {W} }}\n        }}"))}, False),
    ("write inside a closure under a top-level guard is accepted", {"src/j3.rs": tm(
        t_fn(f"        {L}\n        let f = || {{ {W} }};\n        f();"))}, False),
    ("registered delegate returning the guard (one level) is accepted", {"src/k.rs": tm(
        f"    fn rules_scope() -> {GT} {{\n        let g = {LK};\n        g\n    }}\n"
        + t_fn(f"        let _s = rules_scope();\n        {W}"))}, False),
    ("delegate of a delegate (fixpoint), guard-returning, is accepted", {"src/l.rs": tm(
        f"    fn inner() -> {GT} {{ let g = {LK}; g }}\n    fn outer() -> {GT} {{ let h = inner(); h }}\n"
        + t_fn(f"        let _s = outer();\n        {W}"))}, False),
    ("delegate of a delegate that returns unit (lock and release) is refused", {"src/l2.rs": tm(
        f"    fn inner() {{ {L} }}\n    fn outer() {{ inner(); }}\n"
        + t_fn(f"        outer();\n        {W}"))}, True),
    ("lock-and-release helper (guard dies on return) does not bless its caller", {"src/l3.rs": tm(
        f"    fn sync_point() {{ {L} }}\n"
        + t_fn(f"        let _s = sync_point();\n        {W}"))}, True),
    ("helper with a guard return type that drops the guard is not a delegate", {"src/l4.rs": tm(
        f"    fn sneaky() -> {GT} {{\n        let g = {LK};\n        drop(g);\n        OTHER.lock().unwrap_or_else(|e| e.into_inner())\n    }}\n"
        + t_fn(f"        let _s = sneaky();\n        {W}"))}, True),
    ("helper that moves the guard into a call but returns unit is not a delegate", {"src/l6.rs": tm(
        f"    fn sneaky() {{ let g = {LK}; consume(g); }}\n"
        + t_fn(f"        let _s = sneaky();\n        {W}"))}, True),
    ("helper returning a guard type that never keeps the mode guard is not a delegate", {"src/l5.rs": tm(
        f"    fn sneaky() -> {GT} {{\n        let g = {LK};\n        OTHER.lock().unwrap_or_else(|e| e.into_inner())\n    }}\n"
        + t_fn(f"        let _s = sneaky();\n        {W}"))}, True),
    ("Drop impl whose type is returned by a mode-lock delegate is accepted", {"src/m.rs": tm(
        f"    struct S {{ _m: {GT} }}\n    fn scope() -> S {{ let m = {LK}; S {{ _m: m }} }}\n"
        f"    impl Drop for S {{\n        fn drop(&mut self) {{ {CLR} }}\n    }}")}, False),
    ("Drop impl whose type owns an UNRELATED MutexGuard is refused", {"src/m2.rs": tm(
        f"    struct S {{ _m: {GT} }}\n    fn other() -> S {{ S {{ _m: OTHER.lock().unwrap_or_else(|e| e.into_inner()) }} }}\n"
        f"    impl Drop for S {{\n        fn drop(&mut self) {{ {CLR} }}\n    }}")}, True),
    ("writer names in comments, doc comments, strings and raw strings are ignored", {"src/n_tests.rs":
        "/// call set_active_permissions_mode(x) here\n// override_active_permissions_mode_for_test(Mode::Off);\n"
        "/* clear_permissions_mode_override_for_test(); */\nfn t() {\n"
        "    let _a = \"set_active_permissions_mode(x)\";\n"
        "    let _b = r#\"override_active_permissions_mode_for_test(y)\"#;\n    let _c = '\\'';\n}\n"}, False),
    ("a writer DEFINITION line is not a call", {"src/o_tests.rs":
        "pub fn set_active_permissions_mode(mode: u8) { let _ = mode; }\n"}, False),
    ("whole-file #![cfg(test)] file is refused when unpaired", {"src/p.rs":
        f"#![cfg(test)]\nfn t() {{\n    {W}\n}}\n"}, True),
    ("cfg(any(test, feature)) item with an unlocked write is refused", {"src/q.rs":
        f"#[cfg(any(test, feature = \"x\"))]\nfn helper() {{\n    {W}\n}}\n"}, True),
    ("cfg(any(test, feature)) item that takes the lock is accepted", {"src/q2.rs":
        f"#[cfg(any(test, feature = \"x\"))]\nfn helper() {{\n    {L}\n    {W}\n}}\n"}, False),
    ("#[test] fn in a plain mod tests with no cfg(test) (the bench.rs shape) is refused", {"src/bench.rs":
        f"pub fn run() {{}}\nmod tests {{\n    #[test]\n    fn t() {{\n        {W}\n    }}\n}}\n"}, True),
    ("test module in an out-of-line file with a non-test stem is refused", {"src/recover/in_tx_fault.rs":
        f"use super::*;\nfn t() {{\n    {W}\n}}\n"}, True),
    ("#[tokio::test] async fn with an unlocked write is refused", {"src/r.rs": tm(
        "    #[tokio::test]\n    async fn t() {\n        " + W + "\n    }")}, True),
    ("guard bound in an inner block that closes before the write is refused", {"src/s1.rs": tm(
        t_fn(f"        {{ {L} }}\n        {W}"))}, True),
    ("explicit drop(guard) before the write is refused", {"src/s2.rs": tm(
        t_fn(f"        {L}\n        drop(_g);\n        {W}"))}, True),
    ("a second write after drop(guard) is refused", {"src/s2b.rs": tm(
        t_fn(f"        {L}\n        {W}\n        drop(_g);\n        {W}"))}, True),
    ("lock only in a dead branch is refused", {"src/s3.rs": tm(
        t_fn(f"        if false {{ {L} }}\n        {W}"))}, True),
    ("lock only in a closure that is never called is refused", {"src/s4.rs": tm(
        t_fn(f"        let _f = || {{ {L} }};\n        {W}"))}, True),
    ("write in a thread spawned after the guard's block ended is refused", {"src/s5.rs": tm(
        t_fn(f"        {{ {L} }}\n        std::thread::spawn(|| {{ {W} }});"))}, True),
    ("`let _ = lock()` drops the guard at once and is refused", {"src/s6.rs": tm(
        t_fn(f"        let _ = {LK};\n        {W}"))}, True),
    ("`let _ = rules_scope()` (delegate dropped at once) is refused", {"src/s6b.rs": tm(
        f"    fn rules_scope() -> {GT} {{ let g = {LK}; g }}\n"
        + t_fn(f"        let _ = rules_scope();\n        {W}"))}, True),
    ("bare `lock();` statement is refused", {"src/s7.rs": tm(
        t_fn(f"        {LK};\n        {W}"))}, True),
    ("guard held by a longer expression (temporary) is refused", {"src/s8.rs": tm(
        t_fn(f"        let n = {LK}.clone();\n        {W}"))}, True),
    ("use ... as rename of a writer is refused", {"src/u1.rs": tm(
        "    use crate::config::override_active_permissions_mode_for_test as flip;\n"
        + t_fn(f"        {L}\n        flip(m);"))}, True),
    ("grouped use with a rename of a writer is refused", {"src/u2.rs": tm(
        "    use crate::config::{set_active_permissions_mode as flip, PermissionsMode};\n"
        + t_fn(f"        {L}\n        flip(m);"))}, True),
    ("writer taken as a fn pointer is refused", {"src/u3.rs": tm(
        t_fn(f"        {L}\n        let f = crate::config::set_active_permissions_mode;\n        f(m);"))}, True),
    ("plain use import of a writer plus a locked call is accepted", {"src/u4.rs": tm(
        "    use crate::config::set_active_permissions_mode;\n"
        + t_fn(f"        {L}\n        set_active_permissions_mode(m);"))}, False),
    ("test file under tests/ with an unlocked write is refused", {"tests/x.rs":
        f"#[test]\nfn t() {{\n    {W}\n}}\n"}, True),
]


def extra_checks(work: pathlib.Path) -> List[Tuple[str, Callable[[], bool]]]:
    """Checks that are not 'scan this tree and see if it is refused'."""

    def undecodable_exit2() -> bool:
        d = work / "x_undecodable" / "src"
        d.mkdir(parents=True, exist_ok=True)
        (d / "bad.rs").write_bytes(b"fn t() {}\n// \xff\xfe not utf-8\n")
        return run_main(["--root", str(d)]) == 2

    def unreadable_exit2() -> bool:
        d = work / "x_unreadable" / "src"
        d.mkdir(parents=True, exist_ok=True)
        (d / "dangling.rs").symlink_to(d / "missing_target.rs")
        return run_main(["--root", str(d)]) == 2

    def tests_dir_is_root_relative() -> bool:
        # The checkout lives under a directory literally named `tests`; src/a.rs is NOT test code.
        d = work / "x_reldir" / "tests" / "checkout" / "src"
        d.mkdir(parents=True, exist_ok=True)
        f = d / "a.rs"
        f.write_text("pub fn prod() {}\n", encoding="utf-8")
        rust_files([d])
        prod = test_line_mask(f, ["pub fn prod() {}"]) == [False]
        # ...while a file under a `tests` dir RELATIVE to the scan root is test code.
        td = work / "x_reldir2" / "tests"
        td.mkdir(parents=True, exist_ok=True)
        g = td / "b.rs"
        g.write_text("pub fn prod() {}\n", encoding="utf-8")
        rust_files([td])
        return prod and test_line_mask(g, ["pub fn prod() {}"]) == [True]

    def bench_shape_is_visible() -> bool:
        d = work / "x_bench" / "src"
        d.mkdir(parents=True, exist_ok=True)
        f = d / "bench.rs"
        f.write_text("mod tests {\n    #[test]\n    fn a() {}\n    #[test]\n    fn b() {}\n}\n",
                     encoding="utf-8")
        ok = rust_files([d])
        return boundary_gaps(ok) == {f: 2}

    return [
        ("a non-UTF-8 file exits 2 (fail closed)", undecodable_exit2),
        ("an unreadable file (dangling symlink) exits 2 (fail closed)", unreadable_exit2),
        ("`tests` in an ancestor dir does not class src/ as test (root-relative rule)",
         tests_dir_is_root_relative),
        ("#[test] fns on production-classed lines are reported, not silently excluded",
         bench_shape_is_visible),
    ]


def run_main(argv: List[str]) -> int:
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
    failures = 0
    total = 0
    work = pathlib.Path(tempfile.mkdtemp(prefix="pml4491-", dir=str(base)))

    def report(ok: bool, label: str, detail: str) -> None:
        if not quiet:
            print(f"  [{'ok' if ok else 'FAIL'}] {label} -> {detail}")

    try:
        for idx, (label, files_, expect_bad) in enumerate(FIXTURES):
            root = work / f"c{idx}"
            for rel, content in files_.items():
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
            try:
                got = scan(rust_files([root]))
            except GateError as e:
                got = [Violation(root, 0, "<gate>", str(e))]
            ok = bool(got) == expect_bad
            failures += 0 if ok else 1
            total += 1
            report(ok, label, f"{'refused' if got else 'accepted'} (expected "
                              f"{'refused' if expect_bad else 'accepted'})")
        for label, fn in extra_checks(work):
            try:
                ok = bool(fn())
            except GateError:
                ok = False
            failures += 0 if ok else 1
            total += 1
            report(ok, label, "behaved" if ok else "did NOT behave")
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
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--root", action="append", default=None,
                    help="directory or .rs file to scan (repeatable; default: src)")
    ap.add_argument("--self-test", action="store_true", help="run positive and negative fixtures")
    ap.add_argument("--mutation-sweep", action="store_true",
                    help="disable each check; the self-test must turn red for every one")
    ap.add_argument("--parity", action="store_true",
                    help="assert the boundary port matches scripts/lib/production-lines.awk")
    args = ap.parse_args(argv)
    repo = pathlib.Path(__file__).resolve().parent.parent
    try:
        if args.self_test:
            return self_test()
        if args.mutation_sweep:
            return mutation_sweep()
        roots = [pathlib.Path(r) for r in (args.root or [str(repo / "src")])]
        files = rust_files(roots)
        if not files:
            print("check_permissions_mode_lock: no .rs files under " + ", ".join(map(str, roots)),
                  file=sys.stderr)
            return 2
        if args.parity:
            return parity(files, repo)
        bad = scan(files)
        gaps = boundary_gaps(files)
    except GateError as e:
        print(f"check_permissions_mode_lock: {e}", file=sys.stderr)
        return 2
    for p, n in sorted(gaps.items()):
        print(f"note: {p}: {n} #[test] fn(s) on lines the #3623 boundary classes as production "
              f"(#4755); every writer call there is checked regardless", file=sys.stderr)
    for v in sorted(bad):
        print(f"{v.path}:{v.line}: fn {v.fn}: {v.why}")
    if bad:
        print(f"check_permissions_mode_lock: {len(bad)} unlocked PermissionsMode write(s) or "
              f"alias(es) (#4491; recurrences #1465 #2165 #4468)", file=sys.stderr)
        return 1
    print(f"check_permissions_mode_lock: {len(files)} files, every PermissionsMode write holds a "
          f"live lock_permissions_mode_for_test guard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
