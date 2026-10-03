#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
r"""#4491 gate -- INVARIANT: every test-side write of the process-global PermissionsMode must run in
a scope that holds ``crate::config::lock_permissions_mode_for_test()``.

The active mode is one process-wide slot. ``cargo test --lib`` runs many cells that flip it
(governance matrices, rules scopes, link-attest, ck_trigger, the postgres ``live_governance_*``
cells). A cell that writes the slot without the serialisation lock races every other mode-flipping
cell, so a guard that is supposed to prove Deny/Pending behaviour flakes under ``--test-threads=4``.
The discipline was convention only and recurred three times: #1465, #2165, #4468.

WRITERS (the three functions in src/config.rs that mutate the slot):
  set_active_permissions_mode, override_active_permissions_mode_for_test,
  clear_permissions_mode_override_for_test.
The lock: lock_permissions_mode_for_test.

RULE, per function whose ``fn`` keyword sits on a TEST line (the #3623 boundary below):
  1. The function calls a writer, then it must ALSO take the lock BEFORE its first writer call --
     directly, or by calling a DELEGATE (a test-side function that itself takes the lock, found by
     a fixpoint over the scanned tree, e.g. ``rules_scope``, ``chunkc_lock_perms``,
     ``pin_governance_enforce_for_test``, ``enforce_mode_serialised``).
  2. A ``fn drop`` in ``impl Drop for T`` may reset the mode without calling the lock when struct
     ``T`` (same file) owns a ``MutexGuard`` field: the guard fields are released only AFTER
     ``drop`` returns, so the reset runs under the lock (the ``RulesScope`` / ``RulesGuard`` shape).
  3. A writer call that sits on a test line but in no function at all is refused.
Production lines (the boot setter in src/main.rs, the setters in src/config.rs) are ignored.

DELEGATE RESOLUTION is by bare name. A name counts as a delegate only when EVERY test-side function
carrying that name takes the lock (fail closed: one unlocked homonym disqualifies it). One level of
name collision with a production fn is not chased; none exists on the live tree.

BOUNDARY. Production-vs-test is the #3623 policy of scripts/lib/production-lines.{sh,awk}, ported
line for line: a file whose stem matches ``(^|_)tests?(_|$)`` is entirely test; ``#![cfg(test)]``
makes the whole file test; ``#[cfg(test)]`` and ``#[cfg(all(test,`` items are test from their
attribute to the closing brace at the attribute's indent; unknown cfg expressions stay production.
``--parity`` runs the real awk over every scanned file and asserts the two agree (needs awk).

LEXING. Comments (``//``, nested ``/* */``) and string/char literals (including raw strings) are
blanked before any matching, so a writer or lock name inside a comment or a string neither raises
nor satisfies the rule.

SCOPE, stated honestly: roots default to ``src`` (lib tests, which share one process and are the
#4468 shape). Integration binaries under tests/ are NOT scanned by default; ``--root tests`` scans
them, and today several of those files write the mode without the lock (see the #4491 PR notes).
Delegate resolution is name-based and one flat namespace; a delegate called through a method
receiver is matched by the method name.

Usage:
  scripts/check_permissions_mode_lock.py              # scan src/ -- exit 1 on any violation
  scripts/check_permissions_mode_lock.py --self-test  # fixtures under TMPDIR/.local-runs, never /tmp
  scripts/check_permissions_mode_lock.py --parity     # boundary parity vs scripts/lib/production-lines.awk
  scripts/check_permissions_mode_lock.py --root src --root tests
Exit codes: 0 clean, 1 violations (or self-test/parity failure), 2 usage or internal error.
Python 3.9+, standard library only.
"""
import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List, NamedTuple, Optional, Set, Tuple

WRITERS = (
    "set_active_permissions_mode",
    "override_active_permissions_mode_for_test",
    "clear_permissions_mode_override_for_test",
)
LOCK = "lock_permissions_mode_for_test"

STEM_TEST = re.compile(r"(^|_)tests?(_|$)")


# --------------------------------------------------------------------------------------------
# #3623 production-lines boundary (port of scripts/lib/production-lines.awk)
# --------------------------------------------------------------------------------------------
def test_line_mask(path: pathlib.Path, lines: List[str]) -> List[bool]:
    """True for each line that is TEST code (blanked by production-lines)."""
    if STEM_TEST.search(path.stem):
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
            assert m is not None
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
    is_test: bool
    in_drop_of: Optional[str]  # type T when inside `impl Drop for T`


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


def find_fns(text: str, line_starts: List[int], mask: List[bool], path: pathlib.Path) -> List[Fn]:
    import bisect

    drop_spans: List[Tuple[int, int, str]] = []
    for m in DROP_IMPL_RE.finditer(text):
        ob = m.end() - 1
        drop_spans.append((ob, match_brace(text, ob), m.group(1)))
    fns: List[Fn] = []
    for m in FN_RE.finditer(text):
        k = m.end()
        # skip params then find `{` or `;` at depth 0 (angle brackets/where clauses carry no braces)
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
        fns.append(Fn(m.group(1), path, m.start(), body_open, match_brace(text, body_open),
                      mask[line], in_drop))
    return fns


def calls(text: str, name: str, a: int, b: int) -> List[int]:
    """Offsets of call sites of `name` in text[a:b] (excludes `fn name` definitions)."""
    hits = []
    for m in re.finditer(r"\b" + re.escape(name) + r"\s*\(", text[a:b]):
        off = a + m.start()
        if re.search(r"\bfn\s+$", text[max(0, off - 12):off]):
            continue
        hits.append(off)
    return hits


# --------------------------------------------------------------------------------------------
# Scan
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


def load(path: pathlib.Path) -> FileModel:
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = raw.split("\n")
    mask = test_line_mask(path, lines)
    text = blank_literals(raw)
    starts, off = [], 0
    for ln in lines:
        starts.append(off)
        off += len(ln) + 1
    return FileModel(path, text, starts, mask, find_fns(text, starts, mask, path))


def line_of(fm: FileModel, off: int) -> int:
    import bisect
    return bisect.bisect_right(fm.line_starts, off)  # 1-based


def owns_guard(fm: FileModel, type_name: str) -> bool:
    for m in re.finditer(r"\bstruct\s+" + re.escape(type_name) + r"\b[^;{]*\{", fm.text):
        body = fm.text[m.end() - 1:match_brace(fm.text, m.end() - 1)]
        if "MutexGuard" in body:
            return True
    return False


def innermost(fns: List[Fn], off: int) -> Optional[Fn]:
    best: Optional[Fn] = None
    for f in fns:
        if f.open_off < off < f.close_off and (best is None or f.open_off > best.open_off):
            best = f
    return best


def compute_delegates(models: List[FileModel]) -> Set[str]:
    """Names for which EVERY test-side fn of that name takes the lock (directly or by delegate)."""
    by_name: Dict[str, List[Tuple[FileModel, Fn]]] = {}
    for fm in models:
        for f in fm.fns:
            if f.is_test:
                by_name.setdefault(f.name, []).append((fm, f))
    delegates: Set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, defs in by_name.items():
            if name in delegates:
                continue
            ok = True
            for fm, f in defs:
                if not any(calls(fm.text, g, f.open_off, f.close_off)
                           for g in (LOCK, *sorted(delegates))):
                    ok = False
                    break
            if ok:
                delegates.add(name)
                changed = True
    delegates.discard(LOCK)
    return delegates


def scan(files: List[pathlib.Path]) -> List[Violation]:
    models = [load(p) for p in files]
    delegates = compute_delegates(models)
    lockers = (LOCK, *sorted(delegates))
    out: List[Violation] = []
    for fm in models:
        writes: List[int] = []
        for w in WRITERS:
            writes += calls(fm.text, w, 0, len(fm.text))
        by_fn: Dict[Optional[int], List[int]] = {}
        for off in sorted(writes):
            ln = line_of(fm, off)
            if not fm.mask[ln - 1]:
                continue  # production line: the boot setter, the setters themselves
            f = innermost(fm.fns, off)
            by_fn.setdefault(None if f is None else f.open_off, []).append(off)
        by_open = {f.open_off: f for f in fm.fns}
        for key, offs in by_fn.items():
            first = offs[0]
            if key is None:
                out.append(Violation(fm.path, line_of(fm, first), "<no enclosing fn>",
                                     "mode write outside any function"))
                continue
            f = by_open[key]
            if f.in_drop_of and owns_guard(fm, f.in_drop_of):
                continue
            lock_offs = [o for g in lockers for o in calls(fm.text, g, f.open_off, f.close_off)]
            if any(o < first for o in lock_offs):
                continue
            why = ("mode write is not preceded by lock_permissions_mode_for_test (or a "
                   "delegate that takes it)" if not lock_offs else
                   "lock is taken only AFTER the first mode write")
            out.append(Violation(fm.path, line_of(fm, first), f.name, why))
    return out


def rust_files(roots: List[pathlib.Path]) -> List[pathlib.Path]:
    found: List[pathlib.Path] = []
    for r in roots:
        if r.is_file():
            found.append(r)
        elif r.is_dir():
            found += sorted(r.rglob("*.rs"))
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
        lines = p.read_text(encoding="utf-8", errors="replace").split("\n")
        mask = test_line_mask(p, lines)
        if STEM_TEST.search(p.stem):
            awk_prod = [""] * len(lines)  # production_lines() prints nothing for these stems
        else:
            res = subprocess.run([awk, "-f", str(awk_script), str(p)], capture_output=True,
                                 text=True, check=True)
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
L = "let _g = crate::config::lock_permissions_mode_for_test();"

FIXTURES: List[Tuple[str, str, str, bool]] = [
    # (label, relative path, content, expect_violation)
    ("unpaired write in cfg(test) mod is refused", "src/a.rs",
     f"pub fn prod() {{}}\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn t() {{\n        {W}\n    }}\n}}\n", True),
    ("unpaired set_active write in a *_tests.rs file is refused", "src/b_tests.rs",
     "#[test]\nfn t() {\n    crate::config::set_active_permissions_mode(crate::config::PermissionsMode::Off);\n}\n", True),
    ("unpaired clear in a tests.rs file is refused", "src/c/tests.rs",
     f"fn reset() {{\n    {CLR}\n}}\n", True),
    ("lock taken AFTER the write is refused", "src/d.rs",
     f"#[cfg(test)]\nmod tests {{\n    #[test]\n    fn t() {{\n        {W}\n        {L}\n    }}\n}}\n", True),
    ("lock named only in a comment does not satisfy", "src/e.rs",
     f"#[cfg(test)]\nmod tests {{\n    #[test]\n    fn t() {{\n        // lock_permissions_mode_for_test()\n        {W}\n    }}\n}}\n", True),
    ("homonym delegate that does not lock disqualifies the name", "src/f.rs",
     f"#[cfg(test)]\nmod tests {{\n    fn scope() -> u8 {{ 0 }}\n    mod inner {{\n        fn scope() {{ {L} }}\n    }}\n"
     f"    #[test]\n    fn t() {{\n        let _s = scope();\n        {W}\n    }}\n}}\n", True),
    ("Drop impl whose type owns no guard is refused", "src/g.rs",
     f"#[cfg(test)]\nmod tests {{\n    struct S {{ n: u8 }}\n    impl Drop for S {{\n        fn drop(&mut self) {{ {CLR} }}\n    }}\n}}\n", True),
    ("write outside any fn is refused", "src/h_tests.rs",
     f"static X: () = {{ {W} }};\n", True),
    ("production write in the same file as a test mod is ignored", "src/i.rs",
     f"pub fn boot() {{\n    crate::config::set_active_permissions_mode(m);\n}}\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn ok() {{}}\n}}\n"
     f"pub fn boot_after_tests() {{\n    crate::config::set_active_permissions_mode(m);\n}}\n", False),
    ("direct lock then write is accepted", "src/j.rs",
     f"#[cfg(test)]\nmod tests {{\n    #[test]\n    fn t() {{\n        {L}\n        {W}\n        {CLR}\n    }}\n}}\n", False),
    ("registered delegate (one level) is accepted", "src/k.rs",
     f"#[cfg(test)]\nmod tests {{\n    fn rules_scope() -> std::sync::MutexGuard<'static, ()> {{\n        {L}\n        _g\n    }}\n"
     f"    #[test]\n    fn t() {{\n        let _s = rules_scope();\n        {W}\n    }}\n}}\n", False),
    ("delegate of a delegate (fixpoint) is accepted", "src/l.rs",
     f"#[cfg(test)]\nmod tests {{\n    fn inner() {{ {L} }}\n    fn outer() {{ inner(); }}\n"
     f"    #[test]\n    fn t() {{\n        outer();\n        {W}\n    }}\n}}\n", False),
    ("Drop impl whose type owns a MutexGuard is accepted", "src/m.rs",
     f"#[cfg(test)]\nmod tests {{\n    struct S {{ _m: std::sync::MutexGuard<'static, ()> }}\n    impl Drop for S {{\n"
     f"        fn drop(&mut self) {{ {CLR} }}\n    }}\n}}\n", False),
    ("writer names in comments, doc comments, strings and raw strings are ignored", "src/n_tests.rs",
     "/// call set_active_permissions_mode(x) here\n// override_active_permissions_mode_for_test(Mode::Off);\n"
     "/* clear_permissions_mode_override_for_test(); */\nfn t() {\n"
     "    let _a = \"set_active_permissions_mode(x)\";\n"
     "    let _b = r#\"override_active_permissions_mode_for_test(y)\"#;\n    let _c = '\\'';\n}\n", False),
    ("a writer DEFINITION line is not a call", "src/o_tests.rs",
     "pub fn set_active_permissions_mode(mode: u8) { let _ = mode; }\n", False),
    ("whole-file #![cfg(test)] file is test code (refused when unpaired)", "src/p.rs",
     f"#![cfg(test)]\nfn t() {{\n    {W}\n}}\n", True),
    ("cfg(any(test, feature)) stays production (write ignored)", "src/q.rs",
     f"#[cfg(any(test, feature = \"x\"))]\nfn helper() {{\n    {W}\n}}\n", False),
]


def self_test() -> int:
    base = pathlib.Path(os.environ.get("TMPDIR") or ".local-runs")
    base.mkdir(parents=True, exist_ok=True)
    failures = 0
    work = pathlib.Path(tempfile.mkdtemp(prefix="pml4491-", dir=str(base)))
    try:
        for idx, (label, rel, content, expect_bad) in enumerate(FIXTURES):
            root = work / f"c{idx}"
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            got = scan(rust_files([root]))
            ok = bool(got) == expect_bad
            failures += 0 if ok else 1
            print(f"  [{'ok' if ok else 'FAIL'}] {label}"
                  f" -> {'refused' if got else 'accepted'} (expected "
                  f"{'refused' if expect_bad else 'accepted'})")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    total = len(FIXTURES)
    print(f"self-test: {total - failures}/{total} fixtures behaved")
    return 1 if failures else 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--root", action="append", default=None,
                    help="directory or .rs file to scan (repeatable; default: src)")
    ap.add_argument("--self-test", action="store_true", help="run positive and negative fixtures")
    ap.add_argument("--parity", action="store_true",
                    help="assert the boundary port matches scripts/lib/production-lines.awk")
    args = ap.parse_args(argv)
    repo = pathlib.Path(__file__).resolve().parent.parent
    if args.self_test:
        return self_test()
    roots = [pathlib.Path(r) for r in (args.root or [str(repo / "src")])]
    files = rust_files(roots)
    if not files:
        print("check_permissions_mode_lock: no .rs files under " + ", ".join(map(str, roots)),
              file=sys.stderr)
        return 2
    if args.parity:
        return parity(files, repo)
    bad = scan(files)
    for v in sorted(bad):
        print(f"{v.path}:{v.line}: fn {v.fn}: {v.why}")
    if bad:
        print(f"check_permissions_mode_lock: {len(bad)} unlocked test-side PermissionsMode "
              f"write(s) (#4491; recurrences #1465 #2165 #4468)", file=sys.stderr)
        return 1
    print(f"check_permissions_mode_lock: {len(files)} files, every test-side PermissionsMode "
          f"write holds lock_permissions_mode_for_test")
    return 0


if __name__ == "__main__":
    sys.exit(main())
