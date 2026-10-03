#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Release feature-set guard (#4480, hardened by #4719).

THE DEFECT CLASS. A shipped artifact lacks a capability its docs advertise:
release.yml built ``--features sal`` only, so the advertised PostgreSQL + AGE +
pgvector tier was absent from every release binary (#4480, the #2676 / #2728 /
#3996 class). The durable control is ONE declaration (scripts/release-features.sh)
and a check that the build, the assertion, the SBOM, the image, the proof job
and the docs all follow it, and that a BROKEN declaration fails the build
instead of silently degrading it.

This is the Python port of scripts/check-release-features.sh (operator rule: no
new shell). It fixes the four forms the shell guard accepted (#4719):

  (a) ``FEATURES=...`` reassigned between the declaration and the release.yml
      build (or the SBOM / assert step), or any second mutation of the variable;
  (b) the same inside the Dockerfile RUN;
  (c) ``--locked`` present only in a trailing comment on the build line;
  (d) ``--no-default-features`` (or ``--all-features`` / a literal feature list)
      on a build.

Review round 2 (R1-R4, F1-F5 of the #4719 code and security reviews):

  * REFUSAL searches read a FAIL-CLOSED view: only standalone full-line comments
    are removed. A trailing ``#`` is never trusted to hide code, because the
    guard cannot model every way bash decides a ``#`` is not a comment
    (``${x:+ #}``, ``"$(: " #")"``). Extra visible text can only add refusals.
  * PRESENCE checks (``--locked``, the SBOM, the proof strings) read the
    conservative comment-stripped view, so a comment never satisfies them.
  * The strict assert must be exactly ``bash scripts/assert-compiled-features.sh
    "$bin" --strict $REQUIRE_FLAGS`` (Dockerfile: ``target/release/ai-memory``),
    ``bin`` assigned once to the matrix artifact path, and must not be skippable:
    no step ``if:`` / ``continue-on-error:`` / non-bash ``shell:``, no ``&&`` /
    ``||`` neighbour, no pipe or background, no conditional/loop, no ``set +e``,
    ``trap``, ``exit``; in a workflow step and in a Dockerfile RUN alike.
  * The release.yml matrix build must exist as a real build step (an SBOM step
    alone does not count).
  * Unreadable or non-UTF-8 input exits 2 (it never raises).

Exit codes: 0 = guard passes, 1 = guard failure (or self-test failure),
2 = usage / internal error. A guard that cannot parse its input fails closed.

Usage:
  scripts/check_release_features.py [repo-root]
  scripts/check_release_features.py --self-test
"""
from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent

ALLOWED_FEATURES = 'FEATURES="$(bash scripts/release-features.sh)"'
ALLOWED_REQUIRE = 'REQUIRE_FLAGS="$(bash scripts/release-features.sh --require-flags)"'
ALLOWED_BIN = 'bin="target/${{ matrix.target }}/release/${{ matrix.artifact }}"'
ASSERT_WORKFLOW = 'bash scripts/assert-compiled-features.sh "$bin" --strict $REQUIRE_FLAGS'
ASSERT_DOCKER = "bash scripts/assert-compiled-features.sh target/release/ai-memory --strict $REQUIRE_FLAGS"
INLINE_USE_RE = re.compile(r"\$\(bash [^)]*release-features\.sh")
STEP_START_RE = re.compile(
    r"^\s*-\s+(?:name|uses|id|run|if|env|shell|with|working-directory|continue-on-error|timeout-minutes):"
)
STEP_KEY_RE = re.compile(r"""(?:^\s*(?:-\s+)?|[{,]\s*)["']?(if|continue-on-error)["']?\s*:""", re.M)
SHELL_KEY_RE = re.compile(r"""^\s*(?:-\s+)?["']?shell["']?\s*:\s*(.*?)\s*$""", re.M)
CARGO_BUILD_RE = re.compile(r"\bcargo(?:\s+\+\S+)?\s+build\b")
CARGO_SBOM_RE = re.compile(r"\bcargo(?:\s+\+\S+)?\s+cyclonedx\b")
COMPOUND_OPEN = ("if", "case", "for", "while", "until", "select")
COMPOUND_CLOSE = ("fi", "esac", "done")
LEADING_KEYWORDS = ("then", "do", "else", "elif", "{", "!")


# ------------------------------------------------------------ text helpers --
def strip_comment(line: str) -> str:
    """Drop a shell comment (full-line or trailing), quote- and escape-aware.

    ``#`` starts a comment only at the start of a word outside quotes, so
    ``${#x}``, ``$#`` and ``"a # b"`` are preserved.
    """
    quote: Optional[str] = None
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and quote != "'":
            i += 2
            continue
        if quote is None:
            if c in ("'", '"'):
                quote = c
            elif c == "#" and (i == 0 or line[i - 1] in " \t;&|("):
                return line[:i].rstrip()
        elif c == quote:
            quote = None
        i += 1
    return line.rstrip()


class Stmt(str):
    """A shell statement that remembers the operator on each side of it."""

    op_before = ""
    op_after = ""


def logical_lines(text: str) -> List[str]:
    """Fail-closed view: drop STANDALONE comment lines, keep everything else.

    A trailing ``#`` is deliberately kept (R2): the guard cannot model every way
    bash decides a ``#`` is not a comment, so hiding text after it could hide
    live code. A comment line inside a ``\\`` continuation is kept as well (bash
    ends the command there, so the extra text is only ever a superset).
    A line ending in ``\\``, ``&&``, ``||`` or ``|`` continues onto the next one.
    """
    out: List[str] = []
    buf = ""
    for raw in text.splitlines():
        if not buf and raw.lstrip().startswith("#"):
            continue
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1].strip() + " "
            continue
        if re.search(r"(?:&&|\|\||\|)$", line) and not re.search(r":\s*\|[-+]?$", line):
            buf += line.strip() + " "
            continue
        out.append((buf + line).strip())
        buf = ""
    if buf.strip():
        out.append(buf.strip())
    return [ln for ln in out if ln]


def split_statements(line: str) -> List[str]:
    """Split one logical line on ``;``, ``&&``, ``||`` outside quotes.

    Each returned :class:`Stmt` carries the operator before and after it.
    """
    parts: List[Tuple[str, str]] = []
    cur: List[str] = []
    op = ""
    quote: Optional[str] = None
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and quote != "'" and i + 1 < len(line):
            cur.append(line[i : i + 2])
            i += 2
            continue
        if quote is None:
            if c in ("'", '"'):
                quote = c
            elif c == ";" or line.startswith("&&", i) or line.startswith("||", i):
                parts.append((op, "".join(cur)))
                cur = []
                op = c if c == ";" else line[i : i + 2]
                i += 1 if c == ";" else 2
                continue
        elif c == quote:
            quote = None
        cur.append(c)
        i += 1
    parts.append((op, "".join(cur)))
    result: List[Stmt] = []
    for k, (before, part) in enumerate(parts):
        stmt = part.strip()
        changed = True
        while changed:
            changed = False
            for kw in LEADING_KEYWORDS:
                if stmt == kw:
                    stmt = ""
                elif stmt.startswith(kw + " "):
                    stmt = stmt[len(kw) :].strip()
                    changed = True
        if stmt:
            st = Stmt(re.sub(r"\s+", " ", stmt))
            st.op_before = before
            st.op_after = parts[k + 1][0] if k + 1 < len(parts) else ""
            result.append(st)
    return result


def statements(text: str) -> List[str]:
    out: List[str] = []
    for ln in logical_lines(text):
        out.extend(split_statements(ln))
    return out


def code_view(text: str) -> str:
    """PRESENCE view: statements with any trailing comment stripped (conservative:
    it may hide live code, so it is only ever used to ask "is X really there")."""
    return "\n".join(strip_comment(s) for s in statements(text))


def has_unquoted(stmt: str, chars: str) -> bool:
    """True when ``stmt`` has an unquoted pipe/background operator (not a redirect)."""
    quote: Optional[str] = None
    i = 0
    while i < len(stmt):
        c = stmt[i]
        if c == "\\" and quote != "'":
            i += 2
            continue
        if quote is None:
            if c in ("'", '"'):
                quote = c
            elif c in chars:
                prev = stmt[i - 1] if i else ""
                nxt = stmt[i + 1] if i + 1 < len(stmt) else ""
                if not (c == "&" and (prev in "<>" or nxt == ">")):
                    return True
        elif c == quote:
            quote = None
        i += 1
    return False


def yaml_steps(text: str) -> List[str]:
    """Split a workflow into raw step texts at ``- name:`` style boundaries."""
    steps: List[List[str]] = [[]]
    for line in text.splitlines():
        if STEP_START_RE.match(line):
            steps.append([])
        steps[-1].append(line)
    return ["\n".join(s) for s in steps]


def mutates(stmt: str, var: str) -> bool:
    """True when ``stmt`` assigns, appends to, reads into or unsets ``var``."""
    v = re.escape(var)
    pats = (
        rf"(?:^|[\s(])(?:(?:export|declare|typeset|local|readonly)\s+(?:-\w+\s+)*)?{v}\+?=",
        rf"(?:^|\s)(?:read|mapfile|readarray)\s[^<>|;&]*?(?<![\w$-]){v}(?![\w=])",
        rf"^printf\s+-v\s+{v}(?:\s|$)",
        rf"^unset\s+(?:-\w+\s+)*{v}(?:\s|$)",
        rf"^(?:export|declare|typeset|local|readonly)\s+(?:-\w+\s+)*(?:\S+\s+)*{v}(?:\s|$)",
    )
    return any(re.search(p, stmt) for p in pats)


def compound_depths(stmts: List[str]) -> List[int]:
    """Conditional/loop nesting depth at each statement (0 = unconditional)."""
    depths: List[int] = []
    depth = 0
    for s in stmts:
        first = s.split(" ", 1)[0]
        if first in COMPOUND_CLOSE:
            depth = max(0, depth - 1)
        depths.append(depth)
        if first in COMPOUND_OPEN:
            depth += 1
    return depths


# ------------------------------------------------------------------ checks --
class Report:
    def __init__(self) -> None:
        self.errors: List[str] = []

    def bad(self, msg: str) -> None:
        self.errors.append(msg)


class InputError(Exception):
    """An input file could not be read or decoded: exit 2, never a traceback."""


def tokens_of(stmt: str, name: str, rep: Report) -> Optional[List[str]]:
    try:
        return shlex.split(stmt)
    except ValueError as exc:
        rep.bad(f"{name}: cannot parse statement ({exc}): {stmt[:80]}")
        return None


def is_exact(stmt: str, allowed: str) -> bool:
    """``stmt`` is ``allowed``, optionally followed by a real trailing comment
    (a ``#`` after whitespace that ends a complete word is unambiguous)."""
    return stmt == allowed or stmt.startswith(allowed + " #")


def check_cargo_args(name: str, stmt: str, need_locked: bool, rep: Report) -> None:
    """The build/SBOM command takes exactly --features "$FEATURES", never a
    narrowed or widened set, and (for builds) --locked as a real argument.

    Refusals read the fail-closed tokens (trailing comment included); the
    --locked PRESENCE check reads the comment-stripped tokens."""
    ltoks = tokens_of(stmt, name, rep)
    if ltoks is None:
        return
    toks = tokens_of(strip_comment(stmt), name, rep) or []
    if need_locked and "--locked" not in toks:
        rep.bad(f'{name}: build command does not use --locked (a comment does not count)')
    values: List[str] = []
    i = 0
    while i < len(ltoks):
        t = ltoks[i]
        if t == "--features":
            if i + 1 < len(ltoks):
                values.append(ltoks[i + 1])
            i += 2
            continue
        if t.startswith("--features=") or t == "-F" or (t.startswith("-F") and len(t) > 2 and need_locked):
            values.append(t)
        if t in ("--no-default-features", "--all-features"):
            rep.bad(f"{name}: {t} changes the compiled set away from the declaration (refused)")
        i += 1
    if values != ["$FEATURES"]:
        rep.bad(f'{name}: command must take exactly one --features "$FEATURES" (found {values or "none"})')


def check_unit(
    name: str,
    stmts: List[str],
    var: str,
    allowed: str,
    consumers: List[int],
    rep: Report,
) -> None:
    """One step / RUN: ``var`` is assigned exactly once, from the declaration, in
    its own statement, before every consumer, and never mutated again."""
    muts = [i for i, s in enumerate(stmts) if mutates(s, var)]
    if len(muts) != 1:
        rep.bad(f"{name}: {var} is mutated {len(muts)} times in this step (exactly one declaration assignment allowed)")
        return
    if stmts[muts[0]] != allowed:
        rep.bad(f'{name}: the only {var} assignment is not `{allowed}`: {stmts[muts[0]][:80]}')
    for c in consumers:
        if muts[0] >= c:
            rep.bad(f"{name}: {var} assignment does not precede its consumer: {stmts[c][:80]}")
    for s in stmts:
        if re.search(r"(?:^|\s)eval\s", s):
            rep.bad(f"{name}: `eval` in a release step can rewrite {var} (refused)")
        if re.match(r"^(?:source|\.)\s", s) or re.match(r"^(?:declare|typeset|local)\s+(?:-\w+\s+)*-\w*n", s):
            rep.bad(f"{name}: `{s[:30]}` can rewrite {var} out of sight (refused)")
        if re.match(r"^set\s+(?:\S+\s+)*\+(?:[a-z]*e[a-z]*|o\s+errexit)(?:\s|$)", s):
            rep.bad(f"{name}: `{s[:30]}` turns off errexit, so a failing assert would be ignored (refused)")
        if re.match(r"^(?:trap|exit|return)(?:\s|$)", s):
            rep.bad(f"{name}: `{s[:30]}` can end or divert the step before the assert (refused)")


def check_unconditional(name: str, stmts: List[str], idxs: List[int], rep: Report) -> None:
    """Each statement in ``idxs`` (build / SBOM / assert) runs unconditionally and
    its failure is not swallowed: no if/case/loop, no ``&&`` / ``||`` neighbour,
    no pipe or background (#4719)."""
    depths = compound_depths(stmts)
    for i in idxs:
        s = stmts[i]
        where = s[:70]
        if depths[i] != 0:
            rep.bad(f"{name}: `{where}` is inside a conditional/loop, so it can be skipped for a target (#4719)")
        before = getattr(s, "op_before", "")
        if before in ("&&", "||"):
            rep.bad(f"{name}: `{where}` runs only conditionally (`{before}` before it) (#4719)")
        if getattr(s, "op_after", "") == "||":
            rep.bad(f"{name}: `{where}` is followed by `||`, which swallows its failure (#4719)")
        if has_unquoted(s, "|&"):
            rep.bad(f"{name}: `{where}` is piped or backgrounded, which hides its exit status (#4719)")


def check_step_keys(name: str, step: str, rep: Report) -> None:
    """A build / SBOM / assert step carries no ``if:`` / ``continue-on-error:`` and
    only the default ``bash`` shell: each can skip or ignore the step (#4719)."""
    for m in STEP_KEY_RE.finditer(step):
        rep.bad(f"{name}: the step carries `{m.group(1)}:`, which can skip it or ignore its failure (#4719)")
    for m in SHELL_KEY_RE.finditer(step):
        if m.group(1) != "bash":
            rep.bad(f"{name}: the step sets `shell: {m.group(1)}` (only `bash` is allowed; a custom shell can swallow errors)")


def check_workflow_build(name: str, text: str, require_matrix: bool, rep: Report) -> int:
    """Check every release build / SBOM step in a workflow; return how many REAL
    builds were seen (an SBOM-only step does not count as a build)."""
    builds_seen = 0
    for step in yaml_steps(text):
        stmts = statements(step)
        all_builds = [i for i, s in enumerate(stmts) if CARGO_BUILD_RE.search(s)]
        release = bool(all_builds) and (not require_matrix or any("matrix.target" in stmts[i] for i in all_builds))
        builds = all_builds if release else []
        sboms = [i for i, s in enumerate(stmts) if CARGO_SBOM_RE.search(s)]
        if not builds and not sboms:
            continue
        builds_seen += 1 if builds else 0
        check_step_keys(name, step, rep)
        for i in builds:
            check_cargo_args(f"{name} build", stmts[i], True, rep)
        for i in sboms:
            check_cargo_args(f"{name} SBOM (cargo cyclonedx)", stmts[i], False, rep)
        check_unconditional(f"{name} build/SBOM step", stmts, builds + sboms, rep)
        check_unit(f"{name} build/SBOM step", stmts, "FEATURES", ALLOWED_FEATURES, builds + sboms, rep)
    return builds_seen


def check_workflow_assert(name: str, text: str, rep: Report) -> int:
    seen = 0
    for step in yaml_steps(text):
        stmts = statements(step)
        asserts = [i for i, s in enumerate(stmts) if "assert-compiled-features.sh" in s]
        if not asserts:
            continue
        seen += 1
        check_step_keys(name, step, rep)
        check_unconditional(f"{name} assert step", stmts, asserts, rep)
        for i in asserts:
            if not is_exact(stmts[i], ASSERT_WORKFLOW):
                rep.bad(f"{name}: the assert is not exactly `{ASSERT_WORKFLOW}`: {stmts[i][:90]}")
        check_unit(f"{name} assert step", stmts, "bin", ALLOWED_BIN, asserts, rep)
        check_unit(f"{name} assert step", stmts, "REQUIRE_FLAGS", ALLOWED_REQUIRE, asserts, rep)
    return seen


def docker_runs(text: str) -> List[List[str]]:
    """Statements of each RUN instruction (standalone comments dropped, joined)."""
    runs: List[List[str]] = []
    for ln in logical_lines(text):
        if ln.startswith("RUN "):
            runs.append(split_statements(ln[4:]))
    return runs


def check_dockerfile(text: str, rep: Report) -> None:
    norm = "\n".join(strip_comment(ln) for ln in logical_lines(text))
    if not re.search(r"^COPY Cargo\.toml Cargo\.lock", norm, re.M):
        rep.bad("Dockerfile does not COPY Cargo.lock before the build")
    if not re.search(r"COPY scripts/release-features\.sh", norm):
        rep.bad("Dockerfile does not COPY scripts/release-features.sh into the build stage")
    seen = 0
    for stmts in docker_runs(text):
        builds = [i for i, s in enumerate(stmts) if CARGO_BUILD_RE.search(s)]
        if not builds:
            continue
        seen += 1
        for i in builds:
            check_cargo_args("Dockerfile build", stmts[i], True, rep)
        asserts = [i for i, s in enumerate(stmts) if "assert-compiled-features.sh" in s]
        if not asserts:
            rep.bad("Dockerfile RUN has no assert-compiled-features.sh step")
        for i in asserts:
            if not is_exact(stmts[i], ASSERT_DOCKER):
                rep.bad(f"Dockerfile assert is not exactly `{ASSERT_DOCKER}`: {stmts[i][:90]}")
        check_unconditional("Dockerfile RUN", stmts, builds + asserts, rep)
        check_unit("Dockerfile RUN", stmts, "FEATURES", ALLOWED_FEATURES, builds, rep)
        check_unit("Dockerfile RUN", stmts, "REQUIRE_FLAGS", ALLOWED_REQUIRE, asserts, rep)
    if seen == 0:
        rep.bad("Dockerfile has no `RUN ... cargo build` instruction")


def check_inline_use(name: str, text: str, rep: Report) -> None:
    """Every use of the declaration is its own assignment statement."""
    for s in statements(text):
        if s in (ALLOWED_FEATURES, ALLOWED_REQUIRE):
            continue
        stripped = s.replace(ALLOWED_FEATURES, "").replace(ALLOWED_REQUIRE, "")
        if INLINE_USE_RE.search(stripped):
            rep.bad(f"{name}: inline use of the declaration (a failure would be swallowed; assign it in its own statement): {s[:80]}")


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        raise InputError(f"cannot read {path.name}: {exc}") from exc


def run_guard(root: Path) -> Tuple[List[str], str]:
    rep = Report()
    feat = root / "scripts" / "release-features.sh"
    rel_p = root / ".github" / "workflows" / "release.yml"
    shape_p = root / ".github" / "workflows" / "release-shape.yml"
    docker_p = root / "Dockerfile"
    install_p = root / "docs" / "INSTALL.md"

    if not feat.is_file():
        rep.bad("scripts/release-features.sh is missing")
    if not rel_p.is_file():
        rep.bad(".github/workflows/release.yml is missing")
    if rep.errors:
        return rep.errors, ""

    declared = ""
    try:
        proc = subprocess.run(["bash", str(feat)], capture_output=True, text=True, check=False, timeout=60)
        declared = proc.stdout.strip()
        if proc.returncode != 0:
            rep.bad(f"release-features.sh exited {proc.returncode}")
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        rep.bad(f"cannot run release-features.sh: {exc}")
    if "sal-postgres" not in declared.split(","):
        rep.bad(f"release-features.sh declares [{declared}], without sal-postgres")

    rel = read(rel_p)
    shape = read(shape_p) if shape_p.is_file() else None
    docker = read(docker_p) if docker_p.is_file() else None

    for name, text in (("release.yml", rel), ("release-shape.yml", shape or ""), ("Dockerfile", docker or "")):
        check_inline_use(name, text, rep)

    # release.yml: matrix build, SBOM, strict assert on every target.
    if check_workflow_build("release.yml", rel, True, rep) == 0:
        rep.bad("release.yml has no release-matrix 'cargo build --target' command")
    if not any(CARGO_SBOM_RE.search(strip_comment(s)) for s in statements(rel)):
        rep.bad("release.yml has no SBOM step (cargo cyclonedx)")
    if check_workflow_assert("release.yml", rel, rep) == 0:
        rep.bad("release.yml has no strict assert step")

    # Dockerfile.
    if docker is None:
        rep.bad("Dockerfile is missing")
    else:
        check_dockerfile(docker, rep)

    # release-shape proof.
    if shape is None:
        rep.bad(".github/workflows/release-shape.yml is missing (no release-shaped proof)")
    else:
        nshape = code_view(shape)
        if "scripts/release-features.sh" not in nshape:
            rep.bad("release-shape.yml does not build from scripts/release-features.sh")
        if "scripts/release-shape-pg-proof.sh" not in nshape:
            rep.bad("release-shape.yml does not run scripts/release-shape-pg-proof.sh")
        check_workflow_build("release-shape.yml", shape, False, rep)

    # install docs.
    install = read(install_p) if install_p.is_file() else ""
    m = re.search(r"^## Pre-built Binaries.*?(?=^## (?!Pre-built Binaries))", install, re.M | re.S)
    section = m.group(0) if m else ""
    if "sal-postgres" not in section:
        rep.bad("docs/INSTALL.md 'Pre-built Binaries' does not name sal-postgres")
    if "daemon path is NOT" in section or "requires a `--features sal,sal-postgres` source build" in section:
        rep.bad("docs/INSTALL.md still says the postgres path needs a source build")
    return rep.errors, declared


# --------------------------------------------------------------- self-test --
def mutate_file(path: Path, old: str, new: str, every: bool = False) -> None:
    """Replace ``old`` with ``new`` (first match, or all with ``every``). An empty
    ``old`` overwrites the whole file with ``new`` (surrogateescape bytes)."""
    if old == "":
        path.write_bytes(new.encode("utf-8", "surrogateescape"))
        return
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"mutation anchor missing in {path.name}: {old[:60]!r}")
    path.write_text(text.replace(old, new) if every else text.replace(old, new, 1), encoding="utf-8")


def mk_root(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    for rel in (
        ".github/workflows/release.yml",
        ".github/workflows/release-shape.yml",
        "Dockerfile",
        "docs/INSTALL.md",
        "scripts/release-features.sh",
    ):
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src / rel, dst / rel)


Edit = Tuple[str, str, str, bool]  # (file, old, new, every)
REL = ".github/workflows/release.yml"
SHAPE = ".github/workflows/release-shape.yml"
DOCKER = "Dockerfile"
INSTALL = "docs/INSTALL.md"
DECL = "scripts/release-features.sh"
IND = "          "
ASSIGN = IND + 'FEATURES="$(bash scripts/release-features.sh)"\n'
REL_BUILD = (
    ASSIGN + IND + 'test -n "$FEATURES"\n'
    + IND + 'cargo build --locked --release --target ${{ matrix.target }} --features "$FEATURES"'
)
REL_BUILD_CMD = IND + 'cargo build --locked --release --target ${{ matrix.target }} --features "$FEATURES"'
REL_ASSERT = IND + ASSERT_WORKFLOW
BIN_LINE = IND + ALLOWED_BIN
ASSERT_NAME = "      - name: Assert compiled features (#2676, #2728)\n"
ASSERT_HDR = ASSERT_NAME + "        shell: bash\n"
BUILD_HDR = "      - name: Build release binary\n"
SBOM_HDR = "      - name: Generate CycloneDX SBOM (JSON)\n"
SBOM_CMD = IND + 'cargo cyclonedx --format json --features "$FEATURES"'
RF_LINE = IND + 'REQUIRE_FLAGS="$(bash scripts/release-features.sh --require-flags)"\n'
DOCKER_BUILD = 'cargo build --locked --release --features "$FEATURES"; \\'
DOCKER_ASSERT = "    " + ASSERT_DOCKER


def _hdr_key(hdr: str, key: str) -> List[Edit]:
    """Add a step-level YAML key to a release.yml step header."""
    return [(REL, hdr, hdr + "        " + key + "\n", False)]


def _rel(old: str, new: str, every: bool = False) -> Edit:
    return (REL, old, new, every)


# name -> (want, edits). want: "pass" (guard accepts), "fail" (guard refuses),
# "input-error" (guard exits 2). Each "fail" case isolates ONE refusal; the
# mutation harness (see the PR) disables each refusal in turn and requires
# --self-test to go red.
CASES: Dict[str, Tuple[str, List[Edit]]] = {
    "unmutated": ("pass", []),
    "valid multi-line build": ("pass", [_rel(
        REL_BUILD_CMD,
        IND + 'cargo build --locked --release \\\n            --target ${{ matrix.target }} \\\n            --features "$FEATURES"')]),
    "valid build with a harmless trailing comment": ("pass", [_rel(
        REL_BUILD_CMD, REL_BUILD_CMD + "  # locked build on the declared set")]),
    "valid assert with a trailing comment": ("pass", [_rel(REL_ASSERT, REL_ASSERT + "  # strict exact-set")]),
    # --- issue forms (a)-(d)
    "multi-line inline use": ("fail", [_rel(
        REL_BUILD_CMD,
        IND + 'cargo build --locked --release \\\n            --target ${{ matrix.target }} \\\n'
        '            --features "$(bash scripts/release-features.sh)"')]),
    "inline use of the declaration beside a valid assignment": ("fail", [_rel(
        IND + 'test -n "$FEATURES"\n' + REL_BUILD_CMD,
        IND + 'test -n "$FEATURES"\n' + IND + 'echo "$(bash scripts/release-features.sh)" > /dev/null\n' + REL_BUILD_CMD)]),
    "assignment only in a comment": ("fail", [_rel(
        REL_BUILD,
        IND + '# FEATURES="$(bash scripts/release-features.sh)"\n' + IND + 'FEATURES=sal\n' + REL_BUILD_CMD)]),
    "Dockerfile --locked only in a comment": ("fail", [
        (DOCKER, DOCKER_BUILD, 'cargo build --release --features "$FEATURES"; \\', False),
        (DOCKER, "RUN set -eu; \\", '# cargo build --locked --release --features "$FEATURES"\nRUN set -eu; \\', False)]),
    "bypass (a) FEATURES reassigned before the release.yml build": ("fail", [_rel(
        IND + 'test -n "$FEATURES"\n' + IND + "cargo build",
        IND + 'FEATURES=sal\n' + IND + 'test -n "$FEATURES"\n' + IND + "cargo build")]),
    "bypass (a) FEATURES reassigned as a command prefix": ("fail", [_rel(
        IND + "cargo build --locked --release --target ${{ matrix.target }}",
        IND + "FEATURES=sal cargo build --locked --release --target ${{ matrix.target }}")]),
    "bypass (b) FEATURES reassigned inside the Dockerfile RUN": ("fail", [(
        DOCKER, '    test -n "$FEATURES"; \\', '    FEATURES=sal; \\\n    test -n "$FEATURES"; \\', False)]),
    "bypass (b) FEATURES appended inside the Dockerfile RUN": ("fail", [(
        DOCKER, '    test -n "$FEATURES"; \\', '    FEATURES+=,x; \\\n    test -n "$FEATURES"; \\', False)]),
    "bypass (c) --locked only in a trailing comment (release.yml)": ("fail", [_rel(
        "cargo build --locked --release --target ${{ matrix.target }}",
        "cargo build --release --target ${{ matrix.target }}")]),
    "bypass (c) --locked only in a trailing comment (release.yml, text kept)": ("fail", [_rel(
        REL_BUILD_CMD, REL_BUILD_CMD.replace("--locked ", "") + "  # --locked")]),
    "bypass (d) --no-default-features (release.yml)": ("fail", [_rel(REL_BUILD_CMD, REL_BUILD_CMD + " --no-default-features")]),
    "bypass (d) --all-features (release.yml)": ("fail", [_rel(REL_BUILD_CMD, REL_BUILD_CMD + " --all-features")]),
    "bypass (d) --no-default-features (Dockerfile)": ("fail", [(
        DOCKER, DOCKER_BUILD, 'cargo build --locked --release --no-default-features --features "$FEATURES"; \\', False)]),
    "hard-coded feature list": ("fail", [_rel(REL_BUILD_CMD, REL_BUILD_CMD.replace('"$FEATURES"', "sal"))]),
    "REQUIRE_FLAGS reassigned before the strict assert": ("fail", [_rel(
        IND + 'test -n "$REQUIRE_FLAGS"', IND + 'REQUIRE_FLAGS="--require sal"\n' + IND + 'test -n "$REQUIRE_FLAGS"')]),
    "Dockerfile REQUIRE_FLAGS reassigned": ("fail", [(
        DOCKER, '    test -n "$REQUIRE_FLAGS"; \\', '    REQUIRE_FLAGS="--require sal"; \\\n    test -n "$REQUIRE_FLAGS"; \\', False)]),
    "FEATURES assigned after the build (order)": ("fail", [_rel(
        REL_BUILD, REL_BUILD_CMD + "\n" + ASSIGN.rstrip("\n"))]),
    "eval in the build step": ("fail", [_rel(
        IND + 'test -n "$FEATURES"\n' + IND + "cargo build", IND + 'test -n "$FEATURES"\n' + IND + 'eval "echo hi"\n' + IND + "cargo build")]),
    "source in the build step": ("fail", [_rel(
        IND + 'test -n "$FEATURES"\n' + IND + "cargo build", IND + 'test -n "$FEATURES"\n' + IND + 'source ./x.sh\n' + IND + "cargo build")]),
    "nameref in the build step": ("fail", [_rel(
        IND + 'test -n "$FEATURES"\n' + IND + "cargo build", IND + 'test -n "$FEATURES"\n' + IND + 'declare -n r=FEATURES\n' + IND + "cargo build")]),
    "read into FEATURES with an env prefix": ("fail", [_rel(
        IND + 'test -n "$FEATURES"\n' + IND + "cargo build",
        IND + 'IFS=, read -r FEATURES <<< sal\n' + IND + 'test -n "$FEATURES"\n' + IND + "cargo build")]),
    "mapfile into FEATURES": ("fail", [_rel(
        IND + 'test -n "$FEATURES"\n' + IND + "cargo build",
        IND + 'mapfile -t FEATURES < /dev/null\n' + IND + 'test -n "$FEATURES"\n' + IND + "cargo build")]),
    "second build with a +toolchain (hard-coded sal)": ("fail", [_rel(
        REL_BUILD_CMD,
        REL_BUILD_CMD + "\n" + IND + "cargo +1.98.0 build --locked --release --target ${{ matrix.target }} --features sal")]),
    # --- R2: a '#' bash does not treat as a comment must never hide code
    "R2 ${x:+ #} hides FEATURES=sal (release.yml)": ("fail", [_rel(
        IND + 'test -n "$FEATURES"\n' + IND + "cargo build",
        IND + ': ${x:+ #}; FEATURES=sal\n' + IND + 'test -n "$FEATURES"\n' + IND + "cargo build")]),
    "R2 quoted $(...) hides FEATURES=sal (release.yml)": ("fail", [_rel(
        IND + 'test -n "$FEATURES"\n' + IND + "cargo build",
        IND + ': "$(: " #")"; FEATURES=sal\n' + IND + 'test -n "$FEATURES"\n' + IND + "cargo build")]),
    "R2 ${x:+ #} hides a second hard-coded build": ("fail", [_rel(
        REL_BUILD_CMD,
        REL_BUILD_CMD + "\n" + IND + ': ${x:+ #}; cargo build --release --target ${{ matrix.target }} --features sal')]),
    "R2 ${x:+ #} hides FEATURES=sal (Dockerfile)": ("fail", [(
        DOCKER, '    test -n "$FEATURES"; \\', '    : ${x:+ #}; FEATURES=sal; \\\n    test -n "$FEATURES"; \\', False)]),
    # --- R1 / F2: the assert is pinned to the release binary
    "R1 assert targets another binary": ("fail", [_rel(REL_ASSERT, REL_ASSERT.replace('"$bin"', '"$bin.checked"'))]),
    "R1 assert targets /bin/ls": ("fail", [_rel(REL_ASSERT, REL_ASSERT.replace('"$bin"', "/bin/ls"))]),
    "R1 bin assigned from another path": ("fail", [_rel(BIN_LINE, IND + 'bin="/opt/known-good/ai-memory"')]),
    "R1 bin reassigned before the assert": ("fail", [_rel(REL_ASSERT, IND + "bin=/bin/ls\n" + REL_ASSERT)]),
    "R1 Dockerfile assert targets another binary": ("fail", [(
        DOCKER, "assert-compiled-features.sh target/release/ai-memory", "assert-compiled-features.sh /bin/ls", False)]),
    "assert without --strict (release.yml)": ("fail", [_rel(REL_ASSERT, REL_ASSERT.replace("--strict ", ""))]),
    "assert with a literal --require instead of $REQUIRE_FLAGS": ("fail", [_rel(
        REL_ASSERT, REL_ASSERT.replace("$REQUIRE_FLAGS", "--require sal"))]),
    "Dockerfile assert not strict": ("fail", [(DOCKER, "--strict $REQUIRE_FLAGS", "$REQUIRE_FLAGS", False)]),
    "assert removed (release.yml)": ("fail", [_rel(REL_ASSERT, IND + "true")]),
    "Dockerfile has no assert": ("fail", [(DOCKER, DOCKER_ASSERT, "    true", False)]),
    # --- R4 / F1: a skippable assert (and build / SBOM)
    "strict assert skipped behind a shell if (non-native skip, #4719)": ("fail", [_rel(
        REL_ASSERT, IND + 'if [[ "$bin" != *x86_64-apple-darwin* ]]; then\n' + REL_ASSERT + "\n" + IND + "fi")]),
    "R4 step-level if: on the assert step": ("fail", _hdr_key(ASSERT_NAME, "if: matrix.target != 'x86_64-apple-darwin'")),
    "R4 continue-on-error on the assert step": ("fail", _hdr_key(ASSERT_NAME, "continue-on-error: true")),
    "R4 step-level if: on the build step": ("fail", _hdr_key(BUILD_HDR, "if: matrix.os != 'macos-latest'")),
    "R4 continue-on-error on the SBOM step": ("fail", _hdr_key(SBOM_HDR, "continue-on-error: true")),
    "R4 non-bash shell on the assert step": ("fail", [_rel(ASSERT_HDR, ASSERT_HDR.replace("shell: bash", "shell: sh"))]),
    "R4 assert || true": ("fail", [_rel(REL_ASSERT, REL_ASSERT + " || true")]),
    "R4 assert || :": ("fail", [_rel(REL_ASSERT, REL_ASSERT + " || :")]),
    "R4 assert followed by || on the next line": ("fail", [_rel(REL_ASSERT, REL_ASSERT + " ||\n" + IND + "true")]),
    "R4 build || true": ("fail", [_rel(REL_BUILD_CMD, REL_BUILD_CMD + " || true")]),
    "R4 SBOM || true": ("fail", [_rel(SBOM_CMD, SBOM_CMD + " || true")]),
    "R4 build piped to tee": ("fail", [_rel(REL_BUILD_CMD, REL_BUILD_CMD + " | tee build.log")]),
    "R4 SBOM in the background": ("fail", [_rel(SBOM_CMD, SBOM_CMD + " &")]),
    "R4 one-line test && assert": ("fail", [_rel(
        REL_ASSERT, IND + '[[ "$bin" != *x86_64-apple-darwin* ]] && ' + ASSERT_WORKFLOW)]),
    "R4 one-line test || assert": ("fail", [_rel(REL_ASSERT, IND + 'false || ' + ASSERT_WORKFLOW)]),
    "R4 assert piped to cat": ("fail", [_rel(REL_ASSERT, REL_ASSERT + " | cat")]),
    "R4 assert in the background": ("fail", [_rel(REL_ASSERT, REL_ASSERT + " &")]),
    "R4 set +e before the assert": ("fail", [_rel(REL_ASSERT, IND + "set +e\n" + REL_ASSERT)]),
    "R4 trap before the assert": ("fail", [_rel(REL_ASSERT, IND + "trap 'exit 0' ERR\n" + REL_ASSERT)]),
    "R4 exit 0 before the assert": ("fail", [_rel(REL_ASSERT, IND + "exit 0\n" + REL_ASSERT)]),
    "R4 build inside an if": ("fail", [_rel(
        REL_BUILD_CMD, IND + "if true; then\n" + REL_BUILD_CMD + "\n" + IND + "fi")]),
    "R4 Dockerfile conditional assert": ("fail", [(
        DOCKER, DOCKER_ASSERT,
        '    if [ -n "${SKIP:-}" ]; then :; else ' + ASSERT_DOCKER + "; fi", False)]),
    "R4 Dockerfile assert || true": ("fail", [(DOCKER, DOCKER_ASSERT, DOCKER_ASSERT + " || true", False)]),
    "R4 Dockerfile set +e": ("fail", [(DOCKER, '    test -n "$FEATURES"; \\', '    set +e; \\\n    test -n "$FEATURES"; \\', False)]),
    "Dockerfile does not COPY Cargo.lock": ("fail", [(DOCKER, "COPY Cargo.toml Cargo.lock", "COPY Cargo.toml", False)]),
    "Dockerfile does not COPY the declaration": ("fail", [(
        DOCKER, "COPY scripts/release-features.sh", "COPY scripts/assert-compiled-features.sh", False)]),
    # --- F3: the matrix build must exist as a real build step
    "F3 release.yml matrix build deleted (the SBOM step remains)": ("fail", [_rel(REL_BUILD_CMD, IND + "true")]),
    "F3 matrix build respelled as the cargo b alias": ("fail", [_rel(REL_BUILD_CMD, REL_BUILD_CMD.replace("cargo build", "cargo b"))]),
    # --- declaration / SBOM / proof / docs
    "declaration without sal-postgres": ("fail", [(DECL, "BUILD_FEATURES=(sal sal-postgres)", "BUILD_FEATURES=(sal)", False)]),
    "declaration exits non-zero": ("fail", [(
        DECL, "(IFS=,; printf '%s\\n' \"${BUILD_FEATURES[*]}\")", "(IFS=,; printf '%s\\n' \"${BUILD_FEATURES[*]}\"); exit 3", False)]),
    "no SBOM": ("fail", [_rel(SBOM_CMD, IND + "echo nosbom")]),
    "SBOM without --features": ("fail", [_rel(SBOM_CMD, IND + "cargo cyclonedx --format json")]),
    "release-shape does not read the declaration": ("fail", [
        (SHAPE, 'cargo build --locked --release --features "$FEATURES"', "true", False),
        (SHAPE, "scripts/release-features.sh", "scripts/x.sh", True)]),
    "release-shape build with a hard-coded feature list": ("fail", [(
        SHAPE, 'cargo build --locked --release --features "$FEATURES"', "cargo build --locked --release --features sal", False)]),
    "release-shape does not run the pg proof": ("fail", [(SHAPE, "scripts/release-shape-pg-proof.sh", "scripts/x.sh", True)]),
    "INSTALL does not name sal-postgres": ("fail", [(INSTALL, "sal-postgres", "sal-x", True)]),
    "INSTALL says the daemon path is a source build": ("fail", [(
        INSTALL, "## Pre-built Binaries\n", "## Pre-built Binaries\n\nThe daemon path is NOT shipped.\n", False)]),
    # --- F5: unreadable input exits 2
    "F5 release.yml is not valid UTF-8": ("input-error", [(REL, "", "\udcff\udcfe\n", False)]),
    "F5 Dockerfile is not valid UTF-8": ("input-error", [(DOCKER, "", "\udcff\udcfe\n", False)]),
}


def extract_build_step(rel_text: str) -> Optional[str]:
    for step in yaml_steps(rel_text):
        if "Build release binary" in step.splitlines()[0] if step.strip() else False:
            lines = step.splitlines()
            try:
                start = next(i for i, ln in enumerate(lines) if re.match(r"^\s+run: \|", ln))
            except StopIteration:
                return None
            body = lines[start + 1 :]
            indent = min((len(ln) - len(ln.lstrip()) for ln in body if ln.strip()), default=0)
            return "\n".join(ln[indent:] for ln in body)
    return None


def extract_docker_run(docker_text: str) -> Optional[str]:
    lines = docker_text.splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith("RUN set -eu"):
            buf = []
            j = i
            while j < len(lines):
                buf.append(lines[j])
                if not lines[j].rstrip().endswith("\\"):
                    break
                j += 1
            return " ".join(b.rstrip("\\").strip() for b in buf)[4:]
    return None


def self_test(root: Path) -> int:
    failures = 0
    # Scratch lives under $TMPDIR, else the repo-local .local-runs (never /tmp).
    base = os.environ.get("TMPDIR") or str(root / ".local-runs")
    Path(base).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="relfeat-selftest.", dir=base) as td:
        tmp = Path(td)

        # --- runtime fail-closed: a failing/empty declaration must abort the
        # extracted build step and the Dockerfile RUN under `set -e`.
        build_step = extract_build_step((root / ".github/workflows/release.yml").read_text(encoding="utf-8"))
        docker_run = extract_docker_run((root / "Dockerfile").read_text(encoding="utf-8"))
        if not build_step or not docker_run:
            print("check_release_features: self-test could not extract the build step / RUN", file=sys.stderr)
            return 1
        build_step = build_step.replace("${{ matrix.target }}", "x").replace("cargo build", "echo cargo-build")
        docker_run = (
            docker_run.replace("cargo build", "echo cargo-build")
            .replace("strip target", "echo strip target")
            .replace("bash scripts/assert-compiled-features.sh", "echo assert")
        )
        (tmp / "scripts").mkdir()
        for label, body, shell in (("build step", build_step, "bash"), ("Dockerfile RUN", docker_run, "sh")):
            shutil.copy2(root / "scripts/release-features.sh", tmp / "scripts/release-features.sh")
            ok = subprocess.run([shell, "-c", "set -e; " + body], cwd=tmp, capture_output=True).returncode == 0
            if not ok:
                print(f"self-test FAIL: {label} does not pass with the real declaration", file=sys.stderr)
                failures += 1
            for mutant in ("exit 1", "true", 'echo ""; exit 0'):
                (tmp / "scripts/release-features.sh").write_text(mutant + "\n", encoding="utf-8")
                rc = subprocess.run([shell, "-c", "set -e; " + body], cwd=tmp, capture_output=True).returncode
                if rc == 0:
                    print(f"self-test FAIL: {label} PASSED with a broken declaration ({mutant}): fail-open", file=sys.stderr)
                    failures += 1

        # --- the guard itself: positive controls and every bypass form.
        for name, (want, edits) in CASES.items():
            case_root = tmp / "case"
            mk_root(root, case_root)
            try:
                for rel, old, new, every in edits:
                    mutate_file(case_root / rel, old, new, every)
            except RuntimeError as exc:
                print(f"self-test FAIL: case '{name}': {exc}", file=sys.stderr)
                failures += 1
                continue
            try:
                errs, _ = run_guard(case_root)
                got = "fail" if errs else "pass"
            except InputError:
                errs, got = [], "input-error"
            if got != want:
                print(f"self-test FAIL: guard case '{name}' wanted {want}, got {got}: {errs[:2]}", file=sys.stderr)
                failures += 1
        # --- F5: through the real entry point, unreadable input is exit 2.
        bad_root = tmp / "badinput"
        mk_root(root, bad_root)
        (bad_root / ".github/workflows/release.yml").write_bytes(b"\xff\xfe not utf-8\n")
        rc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), str(bad_root)], capture_output=True
        ).returncode
        if rc != 2:
            print(f"self-test FAIL: non-UTF-8 input exited {rc}, wanted 2", file=sys.stderr)
            failures += 1
    if failures:
        return 1
    print(
        "check_release_features: self-test OK "
        f"(a failing or empty declaration fails the build step and the Dockerfile RUN; {len(CASES)} guard cases)"
    )
    return 0


# -------------------------------------------------------------------- main --
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Release feature-set guard (#4480, #4719).")
    ap.add_argument("root", nargs="?", default=None, help="repo root (default: the checkout holding this script)")
    ap.add_argument("--self-test", action="store_true", help="prove the guard refuses every drift form")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve() if args.root else HERE.parent
    if args.self_test:
        return self_test(root)
    try:
        errors, declared = run_guard(root)
    except InputError as exc:
        print(f"check_release_features: FAIL: {exc}", file=sys.stderr)
        return 2
    for e in errors:
        print(f"check_release_features: FAIL: {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"check_release_features: OK (release features: {declared})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
