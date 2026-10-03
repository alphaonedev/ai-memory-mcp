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

THE SLOT ITSELF (#4763). The static behind the setters, ``ACTIVE_PERMISSIONS_MODE`` in
src/config.rs, is modelled too: any mention of it that is not its declaration or a ``.read()`` is a
write and is checked like a writer call. The scan exits 2 if src/config.rs is scanned and the static
is not declared exactly once.

WHO MAY WRITE WITHOUT THE LOCK (fail closed: an allowlist of exact (repo-relative file, TOP-LEVEL
fn) pairs, not a classification of lines). ``main`` in src/main.rs (the boot setter), and in
src/config.rs the alias ``override_active_permissions_mode_for_test`` plus the two bodies that touch
the slot, ``set_active_permissions_mode`` and ``clear_permissions_mode_override_for_test``. The path
is compared against the repository-relative path only (``tests/src/main.rs`` is not ``src/main.rs``)
and the fn must sit at brace depth 0 (a ``fn main`` in a test module or an impl is not the boot
setter, #4764). Every other writer call in the scanned tree is checked, whatever the #3623 test/production
boundary says about its line, so a ``#[test]`` fn on a line the boundary mis-classes as production
(src/bench.rs, #4755), a ``#[cfg(any(test, ..))]`` item, or a test module in a separately named
file cannot hide a write. A fn carrying ``#[test]`` / ``#[tokio::test]`` / ``#[sqlx::test]``, or the same through
``#[cfg_attr(<cond>, test)]``, is never allowlisted.

RULE, per writer call that is not allowlisted: the enclosing fn must hold a LIVE guard at that call.
A guard is live when ALL of these hold:
  1. it is bound by ``let [mut] <ident> = <lock>(..);`` where ``<lock>`` is the lock itself or a
     DELEGATE; ``let _ = ..``, a bare ``<lock>();`` statement and a longer expression drop the
     guard at once and do not count;
  2. the binding statement ends before the writer call and the writer call sits inside the block
     the guard is bound in (a guard bound in an inner block that has closed, in a branch not
     taken, or in a closure that is not the writer's, covers nothing outside it);
  3. the guard identifier is not mentioned again between the binding and the writer call: a later
     mention (``drop(g)``, a rebind, a move into a Vec / struct / inner block, a reassignment, a
     by-value pass) may end the guard's life, so the guard's cover ends at its next mention after
     binding (fail closed; live code never mentions the guard again);
  4. a writer call inside the argument of ``spawn`` / ``spawn_blocking`` / ``spawn_local`` /
     ``spawn_scoped`` (thread, tokio, ``Builder``) may run after the spawner's guard is released, so
     it is covered only by a guard acquired INSIDE that argument or moved INTO it (a ``move``
     closure that rebinds the guard, or borrows it with ``&``, and does not mention it again).
Every writer call in the fn is checked, not only the first.
A DELEGATE is a fn that returns the guard to its caller: its return type is ``MutexGuard<..>`` or a
struct that owns one, it binds the lock (or another delegate) as in 1. in its own top-level block,
and its tail expression and every ``return`` operand yield that binding (the bare identifier, or a
struct literal / tuple struct of a guard-owning type built from it); every mention of the binding
must sit in such an operand. Returning ``None`` / ``Some(..)``, another guard, or a borrow of the
guard does not qualify. A helper that locks and releases on return (unit return) is NOT a delegate. Delegates are derived by a fixpoint over the
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
name-based: it does not follow the guard into another owner (a mention ends its cover instead), or control flow
beyond the brace structure and the guard's mentions.

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
# The static behind the setters (src/config.rs). A mention of it that is not a read is a write of
# the slot itself and is modelled exactly like a writer call (#4763).
SLOT = "ACTIVE_PERMISSIONS_MODE"
SLOT_READ = re.compile(r"\s*\.\s*(?:try_)?read\s*\(")

# Production writers allowed without the lock: (path relative to the scan root or its parent, fn).
# Only a TOP-LEVEL fn of that name in that file counts (#4764): not a nested or test-module fn.
ALLOWED_WRITERS = (
    ("src/main.rs", "main"),
    ("src/config.rs", "override_active_permissions_mode_for_test"),
    ("src/config.rs", "set_active_permissions_mode"),
    ("src/config.rs", "clear_permissions_mode_override_for_test"),
)

STEM_TEST = re.compile(r"(^|_)tests?(_|$)")
TEST_ATTR = re.compile(r"#\s*\[\s*(?:\w+\s*::\s*)*(?:test|rstest|test_case)\b")
CFG_ATTR = re.compile(r"#\s*\[\s*cfg_attr\s*\(")
TEST_ITEM = re.compile(r"^(?:\w+\s*::\s*)*(?:test|rstest|test_case)\b")

# Check names, for --mutation-sweep: disabling any ONE must turn the self-test red.
CHECKS = (
    "lexer", "no_enclosing_fn", "all_lines", "allowlist_path", "allowlist_test_attr",
    "top_level_binding", "bound_ident", "lock_before_write", "each_write",
    "delegate_return_type", "delegate_return_expr", "delegate_homonym", "fixpoint",
    "drop_mode_guard", "alias_use", "alias_value", "tests_dir_relative", "strict_read",
    "boundary_note", "mention_ends_cover", "spawn_refuse", "spawn_moved_in_strict",
    "cfg_attr_test", "repo_relative_allowlist", "allowlist_top_level", "slot_write",
    "slot_decl_once",
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


# Repository root for the exact-path allowlist (set by main(), and per fixture by the self-test).
REPO_ROOT: Optional[pathlib.Path] = None


def repo_rel(path: pathlib.Path) -> Optional[str]:
    """Posix path of `path` relative to the repository root, or None if it is not under it."""
    if REPO_ROOT is None:
        return None
    for a, b in ((path, REPO_ROOT), (path.resolve(), REPO_ROOT.resolve())):
        try:
            return a.relative_to(b).as_posix()
        except ValueError:
            continue
    return None


def has_test_attribute(seg: str) -> bool:
    """`seg` (the attribute run before a fn) carries a test attribute, directly or through
    ``#[cfg_attr(<cond>, .., test, ..)]`` (the condition itself does not count)."""
    if TEST_ATTR.search(seg):
        return True
    if not on("cfg_attr_test"):
        return False
    for m in CFG_ATTR.finditer(seg):
        close = match_paren(seg, m.end() - 1)
        for item in split_top(seg[m.end():close - 1])[1:]:
            if TEST_ITEM.match(item.strip()):
                return True
    return False


def split_top(s: str) -> List[str]:
    """Split on commas that are not nested in (), [], {}."""
    parts: List[str] = []
    depth, last = 0, 0
    for k, ch in enumerate(s):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(s[last:k])
            last = k + 1
    parts.append(s[last:])
    return parts


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
        has_attr = has_test_attribute(text[seg_start:m.start()])
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


def mentions(text: str, ident: str, a: int, b: int) -> List["re.Match[str]"]:
    return list(re.finditer(r"\b" + re.escape(ident) + r"\b", text[a:b]))


def cover_end(fm: FileModel, b: Binding) -> int:
    """Where the binding stops covering writes: its block's end, or (N1) its next mention.

    Any later mention of the guard identifier -- `drop(g)`, a rebind, a move into a Vec / struct /
    inner block, a reassignment -- may end the guard's life, and a lexical gate cannot follow it,
    so cover ends there (fail closed). Live code never mentions the guard again after binding it.
    """
    if b.ident is None or not on("mention_ends_cover"):
        return b.scope_end
    found = mentions(fm.text, b.ident, b.end, b.scope_end)
    return b.end + found[0].start() if found else b.scope_end


def guard_live_at(fm: FileModel, bindings: List[Binding], write: int) -> bool:
    for b in bindings:
        if on("lock_before_write") and b.end > write:
            continue
        if on("top_level_binding") and write >= b.scope_end:
            continue  # the guard's block closed before this write
        if write >= cover_end(fm, b):
            continue  # the guard was mentioned (moved / dropped / reassigned) before this write
        return True
    return False


SPAWN_RE = re.compile(r"\bspawn(?:_[A-Za-z0-9_]+)?\s*\(")
REBIND_RE = re.compile(r"\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]*)?=\s*$")


def spawn_spans(fm: FileModel, f: Fn) -> List[Tuple[int, int]]:
    """(open paren, one past close paren) of every spawn / spawn_blocking / spawn_local .. call."""
    out: List[Tuple[int, int]] = []
    for m in SPAWN_RE.finditer(fm.text, f.open_off + 1, f.close_off):
        if re.search(r"\bfn\s+$", fm.text[max(0, m.start() - 12):m.start()]):
            continue
        a = m.end() - 1
        out.append((a, match_paren(fm.text, a)))
    return out


def moved_into_spawn(fm: FileModel, b: Binding, a: int, c: int, write: int) -> bool:
    """The outer guard `b` is moved into the spawn argument (a, c) and still held at `write`."""
    if b.ident is None or b.end > a or a >= b.scope_end:
        return False
    found = mentions(fm.text, b.ident, b.end, b.scope_end)
    if not found:
        return False
    first = b.end + found[0].start()
    if not (a < first < write < c):
        return False
    if not on("spawn_moved_in_strict"):
        return True
    if not re.search(r"\bmove\b", fm.text[a:first]):
        return False  # a non-`move` closure borrows the guard; the task may outlive it
    before = fm.text[max(a, first - 80):first]
    after = fm.text[first + len(b.ident):first + len(b.ident) + 8].lstrip()
    reb = REBIND_RE.search(before)
    if reb is not None and after.startswith(";"):
        # `let k = g;` -- the new owner must live to the write and be unmentioned before it
        spans = [(o, e) for o, e in brace_spans(fm.text, a, c) if o < first < e]
        blk_end = min((e for o, e in spans), default=c)
        return write < blk_end and not mentions(fm.text, reb.group(1), first, write)
    if re.search(r"&\s*(?:mut\s+)?$", before) and not mentions(fm.text, b.ident, first + 1, write):
        return True  # `&g` / `&mut g` inside a `move` closure keeps the captured guard alive
    return False


def covered(fm: FileModel, f: Fn, bindings: List[Binding], write: int) -> bool:
    """A live guard at `write`; a write inside a spawn(..) argument may run after the spawner's
    guard is released, so there the guard must be acquired inside the closure or moved into it."""
    spans = [(a, c) for a, c in spawn_spans(fm, f) if a < write < c] if on("spawn_refuse") else []
    if not spans:
        return guard_live_at(fm, bindings, write)
    for a, c in spans:
        ok = any(guard_live_at(fm, [b], write) for b in bindings if b.end > a) or \
            any(moved_into_spawn(fm, b, a, c, write) for b in bindings)
        if not ok:
            return False
    return True


# --------------------------------------------------------------------------------------------
# Delegates
# --------------------------------------------------------------------------------------------
class Delegates(NamedTuple):
    names: Set[str]
    types: Set[str]  # struct names returned by a qualifying delegate


def tail_expr(body: str) -> str:
    """The trailing expression of a block body: the text after the last depth-0 `;`, or after a
    depth-0 block statement `{..}` that something still follows (so `if c { return g; } g` -> `g`,
    while a trailing struct literal `S { m: g }` stays whole)."""
    depth, last = 0, -1
    for k, ch in enumerate(body):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if ch == "}" and depth == 0 and body[k + 1:].strip():
                last = k
        elif ch == ";" and depth == 0:
            last = k
    return body[last + 1:].strip()


def return_operands(fm: FileModel, f: Fn) -> List[Tuple[int, int]]:
    """(start, end) of the operand of every `return` in f (nested fns excluded)."""
    out: List[Tuple[int, int]] = []
    for m in re.finditer(r"\breturn\b", fm.text[f.open_off + 1:f.close_off]):
        start = f.open_off + 1 + m.end()
        if innermost(fm.fns, start) is not f:
            continue
        depth, k = 0, start
        while k < f.close_off:
            ch = fm.text[k]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth < 0:
                    break
            elif ch == ";" and depth == 0:
                break
            k += 1
        out.append((start, k))
    return out


def yields_guard(expr: str, ident: str, guard_types: Set[str]) -> bool:
    """`expr` is the guard itself, or a struct (of a guard-owning type) built from it."""
    e = expr.strip()
    if e == ident:
        return True
    m = re.match(r"^([A-Za-z_]\w*)\s*\{(.*)\}$", e, re.S)
    if m and (m.group(1) in guard_types or m.group(1) == "Self"):
        return any(re.fullmatch(r"(?:\w+\s*:\s*)?" + re.escape(ident), p.strip())
                   for p in split_top(m.group(2)))
    m = re.match(r"^([A-Za-z_]\w*)\s*\((.*)\)$", e, re.S)
    if m and (m.group(1) in guard_types or m.group(1) == "Self"):
        return any(p.strip() == ident for p in split_top(m.group(2)))
    return False


def returns_guard(fm: FileModel, f: Fn, b: Binding, guard_types: Set[str]) -> bool:
    """Every path of f (its tail expression and each `return`) yields the guard bound by b."""
    if b.ident is None or b.scope_end != f.close_off:
        return False  # the guard must live in the fn's own top-level block
    body = fm.text[f.open_off + 1:f.close_off - 1]
    tail = tail_expr(body)
    if not tail or not yields_guard(tail, b.ident, guard_types):
        return False
    tail_at = f.open_off + 1 + body.rfind(tail)
    spans = [(tail_at, tail_at + len(tail))]
    for a, c in return_operands(fm, f):
        if not yields_guard(fm.text[a:c], b.ident, guard_types):
            return False
        spans.append((a, c))
    total = mentions(fm.text, b.ident, b.end, f.close_off)
    inside = [m for m in total if any(a <= b.end + m.start() < c for a, c in spans)]
    return len(total) == len(inside)  # any other mention (&g, drop, reassignment) disqualifies


def qualifies(fm: FileModel, f: Fn, lockers: Set[str], guard_types: Set[str]) -> Optional[str]:
    """None if fn f does not return the mode guard; else the return type text."""
    rtype = return_type(f.sig)
    if on("delegate_return_type"):
        ok = "MutexGuard" in rtype or any(re.search(r"\b" + re.escape(t) + r"\b", rtype)
                                          for t in guard_types)
        if not ok:
            return None
    binds = lock_bindings(fm, f, lockers)
    if on("delegate_return_expr"):
        if not any(returns_guard(fm, f, b, guard_types) for b in binds):
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
    if on("slot_write"):
        for m in re.finditer(r"\b" + SLOT + r"\b", fm.text):
            off = m.start()
            if any(a <= off < b for a, b in spans):
                continue
            if re.search(r"\bstatic\s+$", fm.text[max(0, off - 12):off]):
                continue  # the declaration itself
            if SLOT_READ.match(fm.text, m.end()):
                continue  # a read of the slot is not a write
            calls.append(off)
    return sorted(calls), sorted(bad)


def brace_depth_at(text: str, off: int) -> int:
    return text.count("{", 0, off) - text.count("}", 0, off)


def allowed_writer(fm: FileModel, f: Fn) -> bool:
    if f.has_test_attr and on("allowlist_test_attr"):
        return False
    if on("repo_relative_allowlist"):
        here = repo_rel(fm.path)
        forms: Tuple[str, ...] = () if here is None else (here,)
    else:
        forms = rel_forms(fm.path)
    for path, name in ALLOWED_WRITERS:
        if f.name == name and (not on("allowlist_path") or path in forms):
            if on("allowlist_top_level") and brace_depth_at(fm.text, f.kw_off) != 0:
                continue
            return True
    return False


def check_slot_declared(models: List[FileModel]) -> None:
    """When src/config.rs is scanned, the slot static must be declared exactly once (else the
    slot model is blind): fail closed (exit 2) rather than scan a tree the gate cannot vouch for."""
    if not on("slot_decl_once") or not any(repo_rel(m.path) == "src/config.rs" for m in models):
        return
    n = sum(len(re.findall(r"\bstatic\s+" + SLOT + r"\b", m.text)) for m in models)
    if n != 1:
        raise GateError(f"the {SLOT} static is declared {n} times in the scanned tree (expected "
                        f"1): the slot-write model cannot vouch for it")


def drop_exempt(f: Fn, dg: Delegates) -> bool:
    if not f.in_drop_of:
        return False
    if on("drop_mode_guard"):
        return f.in_drop_of in dg.types
    return True


# --------------------------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------------------------
def scan(files: List[pathlib.Path], require_slot: bool = False) -> List[Violation]:
    models = [load(p) for p in files]
    if require_slot:
        check_slot_declared(models)
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
                if covered(fm, f, bindings, off):
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
    ("helper whose return type is not a guard type is not a delegate even if it returns the binding", {"src/l7.rs": tm(
        f"    fn sneaky() -> u8 {{ let g = {LK}; g }}\n"
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

    # ---- N1 (#4765): a moved / rebound / dropped / reassigned guard no longer covers ----
    ("guard rebound then the rebind dropped before the write is refused", {"src/v1.rs": tm(
        t_fn(f"        {L}\n        let g2 = _g;\n        drop(g2);\n        {W}"))}, True),
    ("guard moved into a Vec that is dropped before the write is refused", {"src/v2.rs": tm(
        t_fn(f"        {L}\n        let v = vec![_g];\n        drop(v);\n        {W}"))}, True),
    ("guard moved into a struct that is dropped before the write is refused", {"src/v3.rs": tm(
        f"    struct H({GT});\n" + t_fn(f"        {L}\n        let h = H(_g);\n        drop(h);\n        {W}"))}, True),
    ("guard moved into an inner block that closes before the write is refused", {"src/v4.rs": tm(
        t_fn(f"        {L}\n        {{ let _m = _g; }}\n        {W}"))}, True),
    ("guard reassigned (the mode guard dropped) before the write is refused", {"src/v5.rs": tm(
        t_fn(f"        let mut _g = {LK};\n        _g = OTHER.lock().unwrap_or_else(|e| e.into_inner());\n        {W}"))}, True),
    ("guard dropped through an aliased mem::drop is refused", {"src/v6.rs": tm(
        "    use core::mem::drop as release;\n" + t_fn(f"        {L}\n        release(_g);\n        {W}"))}, True),
    ("std::mem::drop(guard) before the write is refused", {"src/v7.rs": tm(
        t_fn(f"        {L}\n        std::mem::drop(_g);\n        {W}"))}, True),
    ("guard mentioned only AFTER the last write (dropped at the end) is accepted", {"src/v8.rs": tm(
        t_fn(f"        {L}\n        {W}\n        {CLR}\n        drop(_g);"))}, False),
    # ---- N2 (#4766): a write inside a spawn(..) argument ----
    ("write in a thread spawned from a block whose guard ended is refused", {"src/w1.rs": tm(
        t_fn(f"        let h = {{ {L} std::thread::spawn(|| {{ {W} }}) }};\n        h.join().unwrap();"))}, True),
    ("write in a thread spawned under a guard that is dropped before the join is refused", {"src/w2.rs": tm(
        t_fn(f"        {L}\n        let h = std::thread::spawn(|| {{ {W} }});\n        drop(_g);\n        h.join().unwrap();"))}, True),
    ("write in a tokio::spawn task under a guard the task outlives is refused", {"src/w3.rs": tm(
        t_fn(f"        {L}\n        tokio::spawn(async {{ {W} }});", attr="#[tokio::test]").replace("fn t", "async fn t"))}, True),
    ("write in spawn_blocking under a guard is refused", {"src/w4.rs": tm(
        t_fn(f"        {L}\n        tokio::task::spawn_blocking(|| {{ {W} }});"))}, True),
    ("write in a std::thread::Builder spawn under a guard is refused", {"src/w5.rs": tm(
        t_fn(f"        {L}\n        std::thread::Builder::new().spawn(|| {{ {W} }}).unwrap();"))}, True),
    ("a non-move spawn closure that only borrows the guard is refused", {"src/w6.rs": tm(
        t_fn(f"        {L}\n        std::thread::spawn(|| {{ let _r = &_g; {W} }});"))}, True),
    ("a move closure that rebinds the guard and drops the rebind is refused", {"src/w7.rs": tm(
        t_fn(f"        {L}\n        std::thread::spawn(move || {{ let k = _g; drop(k); {W} }});"))}, True),
    ("a move closure that hands the guard to a fn (may drop it) is refused", {"src/w8.rs": tm(
        t_fn(f"        {L}\n        std::thread::spawn(move || {{ consume(_g); {W} }});"))}, True),
    ("guard acquired INSIDE the spawn closure is accepted", {"src/w9.rs": tm(
        t_fn(f"        std::thread::spawn(|| {{ {L} {W} }}).join().unwrap();"))}, False),
    ("guard moved INTO a move spawn closure and kept is accepted", {"src/w10.rs": tm(
        t_fn(f"        {L}\n        std::thread::spawn(move || {{ let _k = _g; {W} }}).join().unwrap();"))}, False),
    # ---- N3 (#4767): a delegate must yield the mode guard on every path ----
    ("delegate that borrows the guard and returns an unrelated guard is refused", {"src/y1.rs": tm(
        f"    fn sneaky() -> {GT} {{ let g = {LK}; let _r = &g; OTHER.lock().unwrap_or_else(|e| e.into_inner()) }}\n"
        + t_fn(f"        let _s = sneaky();\n        {W}"))}, True),
    ("delegate returning Some(guard) / None is refused", {"src/y2.rs": tm(
        f"    fn maybe(c: bool) -> Option<{GT}> {{ let g = {LK}; if c {{ Some(g) }} else {{ None }} }}\n"
        + t_fn(f"        let _s = maybe(false);\n        {W}"))}, True),
    ("delegate with an early `return` of another guard is refused", {"src/y3.rs": tm(
        f"    fn early(c: bool) -> {GT} {{ let g = {LK}; if c {{ return OTHER.lock().unwrap_or_else(|e| e.into_inner()); }} g }}\n"
        + t_fn(f"        let _s = early(true);\n        {W}"))}, True),
    ("delegate whose every path (tail and return) yields the guard is accepted", {"src/y4.rs": tm(
        f"    fn both(c: bool) -> {GT} {{ let g = {LK}; if c {{ return g; }} g }}\n"
        + t_fn(f"        let _s = both(true);\n        {W}"))}, False),
    # ---- N4 (#4764): cfg_attr tests, exact top-level allowlist ----
    ("#[cfg_attr(test, test)] fn main in src/main.rs is refused", {"src/main.rs":
        f"#[cfg_attr(test, test)]\nfn main() {{\n    {W}\n}}\n"}, True),
    ("#[cfg_attr(feature, tokio::test)] fn main in src/main.rs is refused", {"src/main.rs":
        f"#[cfg_attr(feature = \"x\", tokio::test)]\nasync fn main() {{\n    {W}\n}}\n"}, True),
    ("#[cfg_attr(test, derive(Debug))] on the real fn main is not a test attribute (accepted)", {"src/main.rs":
        f"#[cfg_attr(test, allow(dead_code))]\nfn main() {{\n    crate::config::set_active_permissions_mode(m);\n}}\n"}, False),
    ("a nested `fn main` in a cfg(test) module of src/main.rs is refused", {"src/main.rs":
        f"fn main() {{}}\n#[cfg(test)]\nmod tests {{\n    fn main() {{\n        {W}\n    }}\n}}\n"}, True),
    ("a `fn main` method in an impl in src/main.rs is refused", {"src/main.rs":
        f"struct X;\nimpl X {{\n    fn main(&self) {{\n        {W}\n    }}\n}}\n"}, True),
    # ---- #4763: a direct write to the mode slot ----
    ("a direct slot .write() in a cfg(test) mod of config.rs is refused", {"src/config.rs":
        "static ACTIVE_PERMISSIONS_MODE: std::sync::RwLock<Option<u8>> = std::sync::RwLock::new(None);\n"
        "pub fn set_active_permissions_mode(m: u8) {\n    if let Ok(mut w) = ACTIVE_PERMISSIONS_MODE.write() { *w = Some(m); }\n}\n"
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        *ACTIVE_PERMISSIONS_MODE.write().unwrap() = Some(1);\n    }\n}\n"}, True),
    ("a new raw slot setter fn in config.rs is refused", {"src/config.rs":
        "static ACTIVE_PERMISSIONS_MODE: std::sync::RwLock<Option<u8>> = std::sync::RwLock::new(None);\n"
        "pub fn raw(m: u8) {\n    if let Ok(mut w) = ACTIVE_PERMISSIONS_MODE.write() { *w = Some(m); }\n}\n"}, True),
    ("the slot taken by reference (alias) outside a setter is refused", {"src/config.rs":
        "static ACTIVE_PERMISSIONS_MODE: std::sync::RwLock<Option<u8>> = std::sync::RwLock::new(None);\n"
        "pub fn leak() -> &'static std::sync::RwLock<Option<u8>> {\n    &ACTIVE_PERMISSIONS_MODE\n}\n"}, True),
    ("the slot written in a locked test is accepted", {"src/config.rs":
        "static ACTIVE_PERMISSIONS_MODE: std::sync::RwLock<Option<u8>> = std::sync::RwLock::new(None);\n"
        f"#[cfg(test)]\nmod tests {{\n    #[test]\n    fn t() {{\n        {L}\n        *ACTIVE_PERMISSIONS_MODE.write().unwrap() = Some(1);\n    }}\n}}\n"}, False),
    ("the real setter, clearer and reader of the slot are accepted", {"src/config.rs":
        "static ACTIVE_PERMISSIONS_MODE: std::sync::RwLock<Option<u8>> = std::sync::RwLock::new(None);\n"
        "pub fn set_active_permissions_mode(m: u8) {\n    if let Ok(mut w) = ACTIVE_PERMISSIONS_MODE.write() { *w = Some(m); }\n}\n"
        "pub fn clear_permissions_mode_override_for_test() {\n    if let Ok(mut w) = ACTIVE_PERMISSIONS_MODE.write() { *w = None; }\n}\n"
        "pub fn active() -> Option<u8> {\n    ACTIVE_PERMISSIONS_MODE.read().ok().and_then(|g| *g)\n}\n"}, False),
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

    def tests_src_main_not_allowlisted() -> bool:
        # `--root tests` over tests/src/main.rs: root-relative `src/main.rs` is NOT the repo's.
        global REPO_ROOT
        top = work / "x_testsmain"
        d = top / "tests" / "src"
        d.mkdir(parents=True, exist_ok=True)
        (d / "main.rs").write_text("fn main() {\n    crate::config::set_active_permissions_mode(m);\n}\n",
                                   encoding="utf-8")
        saved, REPO_ROOT = REPO_ROOT, top
        try:
            refused = bool(scan(rust_files([top / "tests"])))
            (top / "src").mkdir(exist_ok=True)
            (top / "src" / "main.rs").write_text((d / "main.rs").read_text(encoding="utf-8"),
                                                 encoding="utf-8")
            accepted = not scan(rust_files([top / "src"]))
        finally:
            REPO_ROOT = saved
        return refused and accepted

    def slot_declared_exactly_once() -> bool:
        global REPO_ROOT
        top = work / "x_slot"
        (top / "src").mkdir(parents=True, exist_ok=True)
        cfg = top / "src" / "config.rs"
        saved, REPO_ROOT = REPO_ROOT, top
        try:
            res = []
            for n in (0, 2):
                decl = "static ACTIVE_PERMISSIONS_MODE: u8 = 0;\n" * n
                cfg.write_text(decl + "pub fn f() {}\n", encoding="utf-8")
                try:
                    scan(rust_files([top / "src"]), require_slot=True)
                    res.append(False)
                except GateError:
                    res.append(True)
            cfg.write_text("static ACTIVE_PERMISSIONS_MODE: u8 = 0;\n", encoding="utf-8")
            res.append(scan(rust_files([top / "src"]), require_slot=True) == [])
        finally:
            REPO_ROOT = saved
        return all(res)

    return [
        ("tests/src/main.rs under --root tests is not the allowlisted src/main.rs",
         tests_src_main_not_allowlisted),
        ("the slot static declared 0 or 2 times exits 2; exactly once is clean",
         slot_declared_exactly_once),
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
    global REPO_ROOT
    saved_root = REPO_ROOT
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
            REPO_ROOT = root
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
        REPO_ROOT = saved_root
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
        REPO_ROOT = repo
        roots = [pathlib.Path(r) for r in (args.root or [str(repo / "src")])]
        files = rust_files(roots)
        if not files:
            print("check_permissions_mode_lock: no .rs files under " + ", ".join(map(str, roots)),
                  file=sys.stderr)
            return 2
        if args.parity:
            return parity(files, repo)
        bad = scan(files, require_slot=True)
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
