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

Every check reads comment-stripped (quote-aware, full-line AND trailing) and
continuation-joined text, split into shell statements.

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
from typing import Callable, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent

ALLOWED_FEATURES = 'FEATURES="$(bash scripts/release-features.sh)"'
ALLOWED_REQUIRE = 'REQUIRE_FLAGS="$(bash scripts/release-features.sh --require-flags)"'
INLINE_USE_RE = re.compile(r"\$\(bash [^)]*release-features\.sh")
STEP_START_RE = re.compile(r"^\s*-\s+(?:name|uses|id|run):")
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


def logical_lines(text: str) -> List[str]:
    """Comment-strip each physical line, then join ``\\`` continuations."""
    out: List[str] = []
    buf = ""
    for raw in text.splitlines():
        line = strip_comment(raw)
        if line.endswith("\\"):
            buf += line[:-1].strip() + " "
            continue
        out.append((buf + line).strip())
        buf = ""
    if buf.strip():
        out.append(buf.strip())
    return [ln for ln in out if ln]


def split_statements(line: str) -> List[str]:
    """Split one logical line on ``;``, ``&&``, ``||`` outside quotes."""
    parts: List[str] = []
    cur: List[str] = []
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
                parts.append("".join(cur))
                cur = []
                i += 2 if c != ";" else 1
                continue
        elif c == quote:
            quote = None
        cur.append(c)
        i += 1
    parts.append("".join(cur))
    result: List[str] = []
    for part in parts:
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
            result.append(re.sub(r"\s+", " ", stmt))
    return result


def statements(text: str) -> List[str]:
    out: List[str] = []
    for ln in logical_lines(text):
        out.extend(split_statements(ln))
    return out


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
        rf"^read\s+(?:\S+\s+)*{v}(?:\s|$)",
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


def tokens_of(stmt: str, name: str, rep: Report) -> Optional[List[str]]:
    try:
        return shlex.split(stmt)
    except ValueError as exc:
        rep.bad(f"{name}: cannot parse statement ({exc}): {stmt[:80]}")
        return None


def check_cargo_args(name: str, stmt: str, need_locked: bool, rep: Report) -> None:
    """The build/SBOM command takes exactly --features "$FEATURES", never a
    narrowed or widened set, and (for builds) --locked as a real argument."""
    toks = tokens_of(stmt, name, rep)
    if toks is None:
        return
    if need_locked and "--locked" not in toks:
        rep.bad(f'{name}: build command does not use --locked (a comment does not count)')
    values: List[str] = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t == "--features":
            if i + 1 < len(toks):
                values.append(toks[i + 1])
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


def check_workflow_build(name: str, text: str, require_matrix: bool, rep: Report) -> int:
    """Check every release build step in a workflow; return how many were seen."""
    seen = 0
    for step in yaml_steps(text):
        stmts = statements(step)
        builds = [
            i for i, s in enumerate(stmts)
            if re.search(r"\bcargo\s+build\b", s) and (not require_matrix or "matrix.target" in s)
        ]
        sboms = [i for i, s in enumerate(stmts) if re.search(r"\bcargo\s+cyclonedx\b", s)]
        if not builds and not sboms:
            continue
        seen += 1
        for i in builds:
            check_cargo_args(f"{name} build", stmts[i], True, rep)
        for i in sboms:
            check_cargo_args(f"{name} SBOM (cargo cyclonedx)", stmts[i], False, rep)
        check_unit(f"{name} build/SBOM step", stmts, "FEATURES", ALLOWED_FEATURES, builds + sboms, rep)
    return seen


def check_workflow_assert(name: str, text: str, rep: Report) -> int:
    seen = 0
    for step in yaml_steps(text):
        stmts = statements(step)
        asserts = [i for i, s in enumerate(stmts) if "assert-compiled-features.sh" in s and re.search(r"\bbash\b", s)]
        if not asserts:
            continue
        seen += 1
        depths = compound_depths(stmts)
        for i in asserts:
            s = stmts[i]
            if "--strict" not in s.split() or "$REQUIRE_FLAGS" not in s.split() or "--require" in s.split():
                rep.bad(f"{name}: assert is not `--strict $REQUIRE_FLAGS`: {s[:80]}")
            if depths[i] != 0:
                rep.bad(f"{name}: the strict assert is inside a conditional/loop, so it can be skipped for a target (#4719)")
        check_unit(f"{name} assert step", stmts, "REQUIRE_FLAGS", ALLOWED_REQUIRE, asserts, rep)
    return seen


def docker_runs(text: str) -> List[List[str]]:
    """Statements of each RUN instruction (comment-stripped, joined)."""
    runs: List[List[str]] = []
    lines = logical_lines(text)
    for ln in lines:
        if ln.startswith("RUN "):
            runs.append(split_statements(ln[4:]))
    return runs


def check_dockerfile(text: str, rep: Report) -> None:
    norm = "\n".join(logical_lines(text))
    if not re.search(r"^COPY Cargo\.toml Cargo\.lock", norm, re.M):
        rep.bad("Dockerfile does not COPY Cargo.lock before the build")
    if not re.search(r"COPY scripts/release-features\.sh", norm):
        rep.bad("Dockerfile does not COPY scripts/release-features.sh into the build stage")
    seen = 0
    for stmts in docker_runs(text):
        builds = [i for i, s in enumerate(stmts) if re.search(r"\bcargo\s+build\b", s)]
        if not builds:
            continue
        seen += 1
        for i in builds:
            check_cargo_args("Dockerfile build", stmts[i], True, rep)
        asserts = [i for i, s in enumerate(stmts) if "assert-compiled-features.sh" in s]
        if not asserts:
            rep.bad("Dockerfile RUN has no assert-compiled-features.sh step")
        for i in asserts:
            toks = stmts[i].split()
            if "--strict" not in toks or "$REQUIRE_FLAGS" not in toks or "--require" in toks:
                rep.bad(f"Dockerfile assert is not `--strict $REQUIRE_FLAGS`: {stmts[i][:80]}")
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


def read(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


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
        proc = subprocess.run(["bash", str(feat)], capture_output=True, text=True, check=False)
        declared = proc.stdout.strip()
        if proc.returncode != 0:
            rep.bad(f"release-features.sh exited {proc.returncode}")
    except OSError as exc:
        rep.bad(f"cannot run release-features.sh: {exc}")
    if "sal-postgres" not in declared.split(","):
        rep.bad(f"release-features.sh declares [{declared}], without sal-postgres")

    rel = read(rel_p) or ""
    shape = read(shape_p) if shape_p.is_file() else None
    docker = read(docker_p) if docker_p.is_file() else None

    for name, text in (("release.yml", rel), ("release-shape.yml", shape or ""), ("Dockerfile", docker or "")):
        check_inline_use(name, text, rep)

    # release.yml: matrix build, SBOM, strict assert on every target.
    if check_workflow_build("release.yml", rel, True, rep) == 0:
        rep.bad("release.yml has no release-matrix 'cargo build --target' command")
    if not any("cargo cyclonedx" in s for s in statements(rel)):
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
        nshape = "\n".join(statements(shape))
        if "scripts/release-features.sh" not in nshape:
            rep.bad("release-shape.yml does not build from scripts/release-features.sh")
        if "scripts/release-shape-pg-proof.sh" not in nshape:
            rep.bad("release-shape.yml does not run scripts/release-shape-pg-proof.sh")
        check_workflow_build("release-shape.yml", shape, False, rep)

    # install docs.
    install = read(install_p) or ""
    m = re.search(r"^## Pre-built Binaries.*?(?=^## (?!Pre-built Binaries))", install, re.M | re.S)
    section = m.group(0) if m else ""
    if "sal-postgres" not in section:
        rep.bad("docs/INSTALL.md 'Pre-built Binaries' does not name sal-postgres")
    if "daemon path is NOT" in section or "requires a `--features sal,sal-postgres` source build" in section:
        rep.bad("docs/INSTALL.md still says the postgres path needs a source build")
    return rep.errors, declared


# --------------------------------------------------------------- self-test --
def mutate_file(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"mutation anchor missing in {path.name}: {old[:60]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


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


REL_BUILD = (
    '          FEATURES="$(bash scripts/release-features.sh)"\n'
    '          test -n "$FEATURES"\n'
    '          cargo build --locked --release --target ${{ matrix.target }} --features "$FEATURES"'
)
DOCKER_BUILD = 'cargo build --locked --release --features "$FEATURES"; \\'
REL_ASSERT = '          bash scripts/assert-compiled-features.sh "$bin" --strict $REQUIRE_FLAGS'

# name -> (want, edits[(relative file, old, new)])
Edit = Tuple[str, str, str]
CASES: Dict[str, Tuple[str, List[Edit]]] = {
    "unmutated": ("pass", []),
    "valid multi-line build": ("pass", [(
        ".github/workflows/release.yml", REL_BUILD,
        REL_BUILD.split("cargo build")[0]
        + 'cargo build --locked --release \\\n            --target ${{ matrix.target }} \\\n            --features "$FEATURES"')]),
    "valid build with a harmless trailing comment": ("pass", [(
        ".github/workflows/release.yml", REL_BUILD,
        REL_BUILD + "  # --locked is on; do not add --no-default-features")]),
    "multi-line inline use": ("fail", [(
        ".github/workflows/release.yml", REL_BUILD,
        '          cargo build --locked --release \\\n            --target ${{ matrix.target }} \\\n'
        '            --features "$(bash scripts/release-features.sh)"')]),
    "assignment only in a comment": ("fail", [(
        ".github/workflows/release.yml", REL_BUILD,
        '          # FEATURES="$(bash scripts/release-features.sh)"\n          FEATURES=sal\n'
        '          cargo build --locked --release --target ${{ matrix.target }} --features "$FEATURES"')]),
    "Dockerfile --locked only in a comment": ("fail", [
        ("Dockerfile", DOCKER_BUILD, 'cargo build --release --features "$FEATURES"; \\'),
        ("Dockerfile", "RUN set -eu; \\", '# cargo build --locked --release --features "$FEATURES"\nRUN set -eu; \\')]),
    "bypass (a) FEATURES reassigned before the release.yml build": ("fail", [(
        ".github/workflows/release.yml", '          test -n "$FEATURES"\n          cargo build',
        '          FEATURES=sal\n          test -n "$FEATURES"\n          cargo build')]),
    "bypass (a) FEATURES reassigned as a command prefix": ("fail", [(
        ".github/workflows/release.yml", "          cargo build --locked --release --target ${{ matrix.target }}",
        "          FEATURES=sal cargo build --locked --release --target ${{ matrix.target }}")]),
    "bypass (b) FEATURES reassigned inside the Dockerfile RUN": ("fail", [(
        "Dockerfile", '    test -n "$FEATURES"; \\', '    FEATURES=sal; \\\n    test -n "$FEATURES"; \\')]),
    "bypass (b) FEATURES appended inside the Dockerfile RUN": ("fail", [(
        "Dockerfile", '    test -n "$FEATURES"; \\', '    FEATURES+=,x; \\\n    test -n "$FEATURES"; \\')]),
    "bypass (c) --locked only in a trailing comment (release.yml)": ("fail", [(
        ".github/workflows/release.yml", "cargo build --locked --release --target ${{ matrix.target }}",
        'cargo build --release --target ${{ matrix.target }}')]),
    "bypass (c) --locked only in a trailing comment (release.yml, text kept)": ("fail", [(
        ".github/workflows/release.yml", REL_BUILD,
        REL_BUILD.replace("--locked ", "") + "  # --locked")]),
    "bypass (d) --no-default-features (release.yml)": ("fail", [(
        ".github/workflows/release.yml", REL_BUILD,
        REL_BUILD + " --no-default-features")]),
    "bypass (d) --no-default-features (Dockerfile)": ("fail", [(
        "Dockerfile", DOCKER_BUILD, 'cargo build --locked --release --no-default-features --features "$FEATURES"; \\')]),
    "hard-coded feature list": ("fail", [(
        ".github/workflows/release.yml", REL_BUILD, REL_BUILD.replace('"$FEATURES"', "sal"))]),
    "REQUIRE_FLAGS reassigned before the strict assert": ("fail", [(
        ".github/workflows/release.yml", '          test -n "$REQUIRE_FLAGS"',
        '          REQUIRE_FLAGS="--require sal"\n          test -n "$REQUIRE_FLAGS"')]),
    "strict assert skipped behind a conditional (non-native skip, #4719)": ("fail", [(
        ".github/workflows/release.yml", REL_ASSERT,
        '          if [[ "$bin" != *x86_64-apple-darwin* ]]; then\n' + REL_ASSERT + "\n          fi")]),
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
    base = os.environ.get("TMPDIR")
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
                for rel, old, new in edits:
                    mutate_file(case_root / rel, old, new)
            except RuntimeError as exc:
                print(f"self-test FAIL: case '{name}': {exc}", file=sys.stderr)
                failures += 1
                continue
            errs, _ = run_guard(case_root)
            got = "fail" if errs else "pass"
            if got != want:
                print(f"self-test FAIL: guard case '{name}' wanted {want}, got {got}: {errs[:2]}", file=sys.stderr)
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
    errors, declared = run_guard(root)
    for e in errors:
        print(f"check_release_features: FAIL: {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"check_release_features: OK (release features: {declared})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
