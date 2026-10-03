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

  (a) ``FEATURES=...`` reassigned between the declaration and the build;
  (b) the same inside the Dockerfile RUN;
  (c) ``--locked`` present only in a trailing comment on the build line;
  (d) ``--no-default-features`` (or ``--all-features`` / a literal feature list).

DESIGN: AN ALLOWLIST, NOT A DENYLIST. Two review rounds showed that a list of
bad bash statements is open-ended: the guard reads lines, bash reads a grammar
(heredocs, functions, aliases, ``hash``, ``exec``, ``PATH``, ``cd``, quoted
blocks, a folded YAML scalar...). So the units that decide what ships are
compared to their EXACT expected text, after normalising only whitespace and
``\\`` line continuation, and anything else is refused:

  * the release.yml build step, the strict-assert step, the SBOM step and the
    release-shape build step (statement lists, below);
  * the Dockerfile builder ``RUN`` (one instruction string).

Whole-line comments are dropped; a trailing ``#`` is NOT trusted (the statement
then differs from the allowed one and is refused). Those steps may carry only the
keys ``name``, ``shell: bash`` (not the SBOM) and ``run: |``: ``env:``,
``working-directory:``, ``if:``, ``continue-on-error:`` and a folded ``>`` or
quoted ``run`` are refused. The strict assert must sit in the SAME job as the
matrix build, after it; that job may carry only a fixed set of keys, so it has
no ``if:`` that can be false, no ``env:``, no ``defaults:``, no ``container:``.
``BASH_ENV`` is refused anywhere in release.yml and the Dockerfile; a Dockerfile
``SHELL`` instruction is refused; control characters (CR, form feed, NUL...) in
the workflow or Dockerfile are refused because Python and bash disagree on what
a line is.

OUT OF SCOPE (tracked): the shipped file differing from the asserted one
(#4752), another step or Dockerfile instruction poisoning the environment or
rewriting the declaration before the allowed units run (#4768).

Exit codes: 0 = guard passes, 1 = guard failure (or self-test / sweep failure),
2 = usage error or unreadable input (non-UTF-8, a directory or a symlink loop
where a file belongs). A guard that cannot parse its input fails closed.

Usage:
  scripts/check_release_features.py [repo-root]
  scripts/check_release_features.py --self-test
  scripts/check_release_features.py --mutation-sweep [repo-root]
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple, Union

HERE = Path(__file__).resolve().parent

ALLOWED_FEATURES = 'FEATURES="$(bash scripts/release-features.sh)"'
ALLOWED_REQUIRE = 'REQUIRE_FLAGS="$(bash scripts/release-features.sh --require-flags)"'
ALLOWED_BIN = 'bin="target/${{ matrix.target }}/release/${{ matrix.artifact }}"'
ASSERT_WORKFLOW = 'bash scripts/assert-compiled-features.sh "$bin" --strict $REQUIRE_FLAGS'
ASSERT_DOCKER = "bash scripts/assert-compiled-features.sh target/release/ai-memory --strict $REQUIRE_FLAGS"
BUILD_CMD = 'cargo build --locked --release --target ${{ matrix.target }} --features "$FEATURES"'
SHAPE_BUILD_CMD = 'cargo build --locked --release --features "$FEATURES"'
SBOM_CMD = 'cargo cyclonedx --format json --features "$FEATURES"'

# The exact statements (after normalisation) of each unit that decides what ships.
WF_BUILD = ("set -euo pipefail", ALLOWED_FEATURES, 'test -n "$FEATURES"', BUILD_CMD)
WF_ASSERT = ("set -euo pipefail", ALLOWED_BIN, ALLOWED_REQUIRE, 'test -n "$REQUIRE_FLAGS"', ASSERT_WORKFLOW)
WF_SBOM = (
    "set -euo pipefail",
    'SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"',
    "export SOURCE_DATE_EPOCH",
    ALLOWED_FEATURES,
    'test -n "$FEATURES"',
    SBOM_CMD,
    "mkdir -p dist",
    "cp ai-memory.cdx.json dist/",
    "cd dist",
    "sha256sum ai-memory.cdx.json > ai-memory.cdx.json.sha256",
    "ls -la ai-memory.cdx.json*",
)
SHAPE_BUILD = ("set -euo pipefail", ALLOWED_FEATURES, 'test -n "$FEATURES"', SHAPE_BUILD_CMD)
DOCKER_RUN = (
    "RUN set -eu; "
    + ALLOWED_FEATURES + "; "
    + ALLOWED_REQUIRE + "; "
    + 'test -n "$FEATURES"; test -n "$REQUIRE_FLAGS"; '
    + SHAPE_BUILD_CMD + "; "
    + "strip target/release/ai-memory; "
    + ASSERT_DOCKER
)
KEYS_SHELL = ("name", "shell", "run")
KEYS_PLAIN = ("name", "run")
TOP_KEYS = ("name", "on", "permissions", "concurrency", "jobs")
JOB_KEYS = ("name", "needs", "runs-on", "permissions", "strategy", "steps")

CARGO_BUILD_RE = re.compile(r"\bcargo(?:\s+\+\S+)?\s+build\b")
INLINE_USE_RE = re.compile(r"\$\(\s*bash [^)]*release-features\.sh|`\s*bash [^`]*release-features\.sh")
PLAIN_KEY_RE = re.compile(r"^(?P<ind> *)(?P<key>[A-Za-z_][A-Za-z0-9_-]*):(?: +(?P<val>.*))?$")
CONTROL_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f  ]")
SHELL_INSTR_RE = re.compile(r"^(?:ONBUILD\s+)?SHELL\b", re.I)
STEP_ITEM_PREFIX = "      - "
STEP_KEY_INDENT = len(STEP_ITEM_PREFIX)


# ------------------------------------------------------------ text helpers --
def strip_comment(line: str) -> str:
    """Drop a shell comment (full-line or trailing), quote- and escape-aware.

    ``#`` starts a comment only at the start of a word outside quotes. It is used
    ONLY for PRESENCE checks ("is X really there"), never to hide text from a
    refusal: a presence check that over-strips can only fail closed.
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


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def is_blank_or_comment(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("#")


def logical_lines(lines: List[str]) -> List[str]:
    """Normalise to logical lines: whole-line comments and blanks dropped, ``\\``
    continuations joined, whitespace collapsed. NOTHING else is interpreted: a
    trailing ``#`` stays in the line, and a comment line inside a continuation is
    kept (bash ends the command there), so extra text can only add refusals."""
    out: List[str] = []
    buf = ""
    for raw in lines:
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            buf += line[:-1].rstrip() + " "
            continue
        out.append(re.sub(r"\s+", " ", buf + line).strip())
        buf = ""
    if buf.strip():
        out.append(re.sub(r"\s+", " ", buf).strip())
    return out


def code_lines(text: str) -> str:
    """PRESENCE view of a file: whole-line comments dropped, trailing comments
    stripped."""
    return "\n".join(strip_comment(ln) for ln in text.split("\n") if not is_blank_or_comment(ln))


# ------------------------------------------------------------------ report --
class Report:
    def __init__(self) -> None:
        self.errors: List[str] = []

    def bad(self, msg: str) -> None:
        self.errors.append(msg)


class InputError(Exception):
    """An input file could not be read or decoded: exit 2, never a traceback."""


def load(path: Path, label: str, rep: Report, strict: bool) -> Optional[str]:
    """Read one input. Missing = a guard failure (None). Anything else that stops
    a read (non-UTF-8, a directory, a symlink loop, no permission) = InputError,
    exit 2. ``strict`` refuses control characters (CR, form feed, NUL, ...)."""
    try:
        text = path.read_bytes().decode("utf-8")  # bytes: text mode would fold CR away
    except FileNotFoundError:
        rep.bad(f"{label} is missing")
        return None
    except (OSError, ValueError) as exc:
        raise InputError(f"cannot read {label}: {exc}") from exc
    if strict and CONTROL_RE.search(text):
        rep.bad(f"{label} contains a control character (CR, form feed, NUL...): Python and bash disagree on line ends")
        return None
    return text


# ------------------------------------------------------- YAML step grammar --
def block_after(lines: List[str], idx: int) -> List[str]:
    """The lines nested under ``lines[idx]`` (more indented than it)."""
    base = indent_of(lines[idx])
    out: List[str] = []
    for ln in lines[idx + 1 :]:
        if not is_blank_or_comment(ln) and indent_of(ln) <= base:
            break
        out.append(ln)
    return out


def keys_at(lines: List[str], indent: int, allowed: Tuple[str, ...], label: str, rep: Report) -> None:
    """Every mapping key at ``indent`` is a plain key, allowed, and unique."""
    seen: List[str] = []
    for ln in lines:
        if is_blank_or_comment(ln) or indent_of(ln) != indent:
            continue
        m = PLAIN_KEY_RE.match(ln)
        if m is None:
            rep.bad(f"{label}: unsupported line at indent {indent}: {ln.strip()[:60]}")
            continue
        key = m.group("key")
        if key not in allowed:
            rep.bad(f"{label}: `{key}:` is not allowed here (allowed: {', '.join(allowed)})")
        if key in seen:
            rep.bad(f"{label}: duplicate key `{key}:`")
        seen.append(key)


def split_steps(lines: List[str]) -> List[List[str]]:
    """Group lines into workflow steps (``      - ...`` items); a step ends at the
    next item or at a live line indented less than its keys."""
    steps: List[List[str]] = []
    cur: Optional[List[str]] = None
    for ln in lines:
        if ln.startswith(STEP_ITEM_PREFIX):
            cur = [ln]
            steps.append(cur)
            continue
        if cur is None:
            continue
        if not is_blank_or_comment(ln) and indent_of(ln) < STEP_KEY_INDENT:
            cur = None
            continue
        cur.append(ln)
    return steps


def parse_step(step: List[str]) -> Tuple[Dict[str, str], List[str], str]:
    """Parse one step as ``key: value`` lines plus one ``run: |`` literal block.
    Anything it does not understand is refused (flow style, anchors, quoted keys,
    folded blocks, inconsistent indentation, duplicate keys): the third item
    returned is the reason, "" when the whole step parsed."""
    keys: Dict[str, str] = {}
    run: List[str] = []
    in_block = False
    block_indent = -1
    for n, raw in enumerate(step):
        line = " " * STEP_KEY_INDENT + raw[len(STEP_ITEM_PREFIX) :] if n == 0 else raw
        if in_block:
            if not line.strip():
                run.append("")
                continue
            ind = indent_of(line)
            if ind > STEP_KEY_INDENT:
                if block_indent < 0:
                    block_indent = ind
                if ind < block_indent:
                    return keys, run, "the run block has inconsistent indentation"
                run.append(line.strip())
                continue
            in_block = False
        if is_blank_or_comment(line):
            continue
        m = PLAIN_KEY_RE.match(line)
        if m is None or len(m.group("ind")) != STEP_KEY_INDENT:
            return keys, run, f"unsupported step line: {line.strip()[:60]}"
        key = m.group("key")
        if key in keys:
            return keys, run, f"duplicate step key `{key}:`"
        keys[key] = m.group("val") or ""
        if key == "run" and keys[key] == "|":
            in_block = True
            block_indent = -1
    return keys, run, ""


def step_problem(step: List[str], want_keys: Tuple[str, ...], expected: Tuple[str, ...]) -> str:
    """Why ``step`` is not the allowed one ("" when it is exactly the allowed one)."""
    keys, run, why = parse_step(step)
    if why:
        return why
    if set(keys) != set(want_keys):
        return f"step keys {sorted(keys)} differ from the only allowed set {sorted(want_keys)}"
    if keys["run"] != "|":
        return "`run:` must be a literal block (`run: |`); a folded, quoted or inline run is refused"
    if "shell" in want_keys and keys["shell"] != "bash":
        return f"`shell: {keys['shell']}` (only `shell: bash` is allowed)"
    got = tuple(logical_lines(run))
    if got == expected:
        return ""
    first = next((i for i in range(max(len(got), len(expected))) if i >= len(got) or i >= len(expected) or got[i] != expected[i]), 0)
    have = got[first] if first < len(got) else "<end of step>"
    want = expected[first] if first < len(expected) else "<end of step>"
    return f"statement {first + 1} is `{have[:90]}`, the only allowed one is `{want[:90]}`"


def canonical_steps(steps: List[List[str]], want_keys: Tuple[str, ...], expected: Tuple[str, ...]) -> List[int]:
    return [i for i, s in enumerate(steps) if not step_problem(s, want_keys, expected)]


def nearest_problem(steps: List[List[str]], marker: str, want_keys: Tuple[str, ...], expected: Tuple[str, ...]) -> str:
    """Reason for the first step that mentions ``marker`` but is not the allowed one."""
    for s in steps:
        if marker in "\n".join(s):
            why = step_problem(s, want_keys, expected)
            if why:
                return why
    return f"no step mentions `{marker}`"


# ------------------------------------------------------------------ checks --
def check_no_bash_env(label: str, text: str, rep: Report) -> None:
    if "BASH_ENV" in text:
        rep.bad(f"{label}: BASH_ENV runs a file before every non-interactive bash, so it can neutralise the assert (refused anywhere)")


def check_single_build(name: str, text: str, matrix_only: bool, rep: Report) -> None:
    """The allowed build (its presence is checked by the unit checks) is the ONLY
    one in the file. In release.yml any other
    ``cargo build`` of the matrix target (a later rebuild with another toolchain,
    different flags, or the same line twice) is refused; in the Dockerfile any
    other ``cargo build`` at all."""
    hits = [ln for ln in logical_lines(text.split("\n"))
            if CARGO_BUILD_RE.search(ln) and (not matrix_only or "matrix.target" in ln)]
    if len(hits) > 1:
        rep.bad(f"{name}: {len(hits)} release builds; only the allowed unit may build: {hits[-1][:90]}")


def check_release_yml(text: str, rep: Report) -> None:
    check_no_bash_env("release.yml", text, rep)
    check_single_build("release.yml", text, True, rep)
    lines = [ln.rstrip() for ln in text.split("\n")]
    keys_at(lines, 0, TOP_KEYS, "release.yml top level", rep)
    jobs_at = [i for i, ln in enumerate(lines) if ln == "jobs:"]
    # a duplicate `jobs:` is refused by keys_at above; no `jobs:` leaves no release job
    jobs = block_after(lines, jobs_at[0]) if jobs_at else []
    release_at = [i for i, ln in enumerate(jobs) if ln == "  release:"]
    if len(release_at) != 1:
        rep.bad("release.yml must have exactly one `release:` job")
        return
    job = block_after(jobs, release_at[0])
    keys_at(job, 4, JOB_KEYS, "release.yml release job", rep)
    steps = split_steps(job)
    builds = canonical_steps(steps, KEYS_SHELL, WF_BUILD)
    asserts = canonical_steps(steps, KEYS_SHELL, WF_ASSERT)
    if not builds:
        rep.bad("release.yml: the release job has no build step with exactly the allowed body: "
                + nearest_problem(steps, "cargo", KEYS_SHELL, WF_BUILD))
    if not asserts:
        rep.bad("release.yml: the release job has no strict-assert step with exactly the allowed body: "
                + nearest_problem(steps, "assert-compiled-features", KEYS_SHELL, WF_ASSERT))
    if builds and asserts and max(builds) > max(asserts):
        rep.bad("release.yml: the strict assert must run after the build, in the same job")
    if not canonical_steps(split_steps(lines), KEYS_PLAIN, WF_SBOM):
        rep.bad("release.yml: no SBOM step with exactly the allowed body: "
                + nearest_problem(split_steps(lines), "cyclonedx", KEYS_PLAIN, WF_SBOM))


def check_dockerfile(text: str, rep: Report) -> None:
    check_no_bash_env("Dockerfile", text, rep)
    check_single_build("Dockerfile", text, False, rep)
    logical = logical_lines(text.split("\n"))
    if not any(ln.startswith("COPY Cargo.toml Cargo.lock") for ln in logical):
        rep.bad("Dockerfile does not COPY Cargo.lock before the build")
    if not any(ln.startswith("COPY scripts/release-features.sh") for ln in logical):
        rep.bad("Dockerfile does not COPY scripts/release-features.sh into the build stage")
    for ln in logical:
        if SHELL_INSTR_RE.match(ln):
            rep.bad(f"Dockerfile: a SHELL instruction swaps the shell that runs the build RUN (refused): {ln[:60]}")
    if DOCKER_RUN not in logical:
        near = next((ln for ln in logical if re.match(r"RUN\b", ln, re.I) and "cargo" in ln), "<no RUN mentions cargo>")
        rep.bad("Dockerfile: no RUN instruction is exactly the allowed build+assert RUN; "
                f"nearest: {near[:120]}")


def check_inline_use(name: str, text: str, rep: Report) -> None:
    """Every use of the declaration is its own assignment (a failing declaration
    inside a substitution in another command would be swallowed)."""
    for ln in logical_lines(text.split("\n")):
        stripped = ln.replace(ALLOWED_FEATURES, "").replace(ALLOWED_REQUIRE, "")
        if INLINE_USE_RE.search(stripped):
            rep.bad(f"{name}: inline use of the declaration (a failure would be swallowed; assign it in its own statement): {ln[:80]}")


def check_shape(text: str, rep: Report) -> None:
    view = code_lines(text)
    if "scripts/release-shape-pg-proof.sh" not in view:
        rep.bad("release-shape.yml does not run scripts/release-shape-pg-proof.sh")
    steps = split_steps([ln.rstrip() for ln in text.split("\n")])
    if not canonical_steps(steps, KEYS_SHELL, SHAPE_BUILD):
        rep.bad("release-shape.yml: no build step with exactly the allowed body: "
                + nearest_problem(steps, "cargo build", KEYS_SHELL, SHAPE_BUILD))


def check_install(text: str, rep: Report) -> None:
    m = re.search(r"^## Pre-built Binaries.*?(?=^## (?!Pre-built Binaries))", text, re.M | re.S)
    section = m.group(0) if m else ""
    if "sal-postgres" not in section:
        rep.bad("docs/INSTALL.md 'Pre-built Binaries' does not name sal-postgres")
    if "daemon path is NOT" in section or "requires a `--features sal,sal-postgres` source build" in section:
        rep.bad("docs/INSTALL.md still says the postgres path needs a source build")


def run_guard(root: Path) -> Tuple[List[str], str]:
    rep = Report()
    feat = load(root / "scripts" / "release-features.sh", "scripts/release-features.sh", rep, False)
    rel = load(root / ".github" / "workflows" / "release.yml", ".github/workflows/release.yml", rep, True)
    shape = load(root / ".github" / "workflows" / "release-shape.yml", ".github/workflows/release-shape.yml (no release-shaped proof)", rep, True)
    docker = load(root / "Dockerfile", "Dockerfile", rep, True)
    install = load(root / "docs" / "INSTALL.md", "docs/INSTALL.md", rep, False)

    declared = ""
    if feat is not None:
        try:
            proc = subprocess.run(
                ["bash", str(root / "scripts" / "release-features.sh")], capture_output=True, text=True, check=False, timeout=60
            )
            declared = proc.stdout.strip()
            if proc.returncode != 0:
                rep.bad(f"release-features.sh exited {proc.returncode}")
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise InputError(f"cannot run release-features.sh: {exc}") from exc
        if "sal-postgres" not in declared.split(","):
            rep.bad(f"release-features.sh declares [{declared}], without sal-postgres")

    for name, text in (("release.yml", rel), ("release-shape.yml", shape), ("Dockerfile", docker)):
        if text is not None:
            check_inline_use(name, text, rep)
    if rel is not None:
        check_release_yml(rel, rep)
    if docker is not None:
        check_dockerfile(docker, rep)
    if shape is not None:
        check_shape(shape, rep)
    if install is not None:
        check_install(install, rep)
    return rep.errors, declared


# --------------------------------------------------------------- self-test --
Transform = Callable[[str], str]
Edit = Tuple[str, str, Union[str, None, Transform], bool]  # (file, old, new | None=delete | fn, every)
REL = ".github/workflows/release.yml"
SHAPE = ".github/workflows/release-shape.yml"
DOCKER = "Dockerfile"
INSTALL = "docs/INSTALL.md"
DECL = "scripts/release-features.sh"
INPUT_FILES = (REL, SHAPE, DOCKER, INSTALL, DECL)


def mutate_file(path: Path, old: str, new: Union[str, None, Transform], every: bool = False) -> None:
    """Apply one edit. ``new`` None deletes the file, a callable transforms the
    whole text, an empty ``old`` overwrites the file (surrogateescape bytes)."""
    if new is None:
        path.unlink()
        return
    if callable(new):
        path.write_text(new(path.read_text(encoding="utf-8")), encoding="utf-8")
        return
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
    for rel in INPUT_FILES:
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src / rel, dst / rel)


IND = "          "
ASSIGN = IND + ALLOWED_FEATURES + "\n"
REL_BUILD = ASSIGN + IND + 'test -n "$FEATURES"\n' + IND + BUILD_CMD
REL_BUILD_CMD = IND + BUILD_CMD
REL_ASSERT = IND + ASSERT_WORKFLOW
BIN_LINE = IND + ALLOWED_BIN
ASSERT_NAME = "      - name: Assert compiled features (#2676, #2728)\n"
ASSERT_HDR = ASSERT_NAME + "        shell: bash\n"
ASSERT_RUN = ASSERT_HDR + "        run: |\n"
BUILD_HDR = "      - name: Build release binary\n"
BUILD_SHELL = "        shell: bash\n        run: |\n          set -euo pipefail\n"
SBOM_HDR = "      - name: Generate CycloneDX SBOM (JSON)\n"
SBOM_LINE = IND + SBOM_CMD
PKG_HDR = "      - name: Package binary\n"
JOB_NAME = "    name: Release (${{ matrix.target }})\n"
DOCKER_BUILD = SHAPE_BUILD_CMD + "; \\"
DOCKER_ASSERT = "    " + ASSERT_DOCKER
DOCKER_RUN_HEAD = "RUN set -eu; \\\n"
SHAPE_HDR = "      - name: Build release binary (exactly as release.yml)\n"
SHAPE_LINE = IND + SHAPE_BUILD_CMD


def _rel(old: str, new: Union[str, Transform], every: bool = False) -> Edit:
    return (REL, old, new, every)


def _hdr_key(hdr: str, key: str) -> List[Edit]:
    """Add a step-level YAML key to a release.yml step header."""
    return [_rel(hdr, hdr + "        " + key + "\n")]


def _before_assert(stmt: str) -> List[Edit]:
    return [_rel(REL_ASSERT, stmt + "\n" + REL_ASSERT)]


def _before_build(stmt: str) -> List[Edit]:
    return [_rel(ASSIGN, stmt + "\n" + ASSIGN)]


def _move_assert_before_build(text: str) -> str:
    a, p, b = text.index(ASSERT_NAME), text.index(PKG_HDR), text.index(BUILD_HDR)
    block = text[a:p]
    text = text[:a] + text[p:]
    return text[:b] + block + text[b:]


def _move_assert_to_other_job(text: str) -> str:
    a, p = text.index(ASSERT_NAME), text.index(PKG_HDR)
    block = text[a:p]
    text = text[:a] + text[p:]
    return text.rstrip("\n") + "\n\n  verify-elsewhere:\n    runs-on: ubuntu-latest\n    steps:\n" + block


def _drop_assert_step(text: str) -> str:
    a, p = text.index(ASSERT_NAME), text.index(PKG_HDR)
    return text[:a] + text[p:]


def _dir_in_place(_: str) -> str:  # pragma: no cover - placeholder, see ENTRY_CASES
    return _


# name -> (want, edits). want: "pass" (guard accepts), "fail" (guard refuses),
# "input-error" (guard exits 2). `--mutation-sweep` neutralises every refusal
# site in turn and requires `--self-test` to go red, so each "fail" case must be
# refused by a distinct refusal, not merely by a neighbour.
CASES: Dict[str, Tuple[str, List[Edit]]] = {
    "unmutated": ("pass", []),
    "valid multi-line build": ("pass", [_rel(
        REL_BUILD_CMD,
        IND + 'cargo build --locked --release \\\n            --target ${{ matrix.target }} \\\n            --features "$FEATURES"')]),
    "valid whole-line comments between statements": ("pass", [_rel(
        REL_BUILD_CMD, IND + "# a harmless whole-line comment\n" + REL_BUILD_CMD)]),
    "valid blank line inside the assert step": ("pass", [_rel(REL_ASSERT, "\n" + REL_ASSERT)]),
    "trailing comment on the build statement is refused": ("fail", [_rel(
        REL_BUILD_CMD, REL_BUILD_CMD + "  # locked build on the declared set")]),
    "trailing comment on the assert statement is refused": ("fail", [_rel(REL_ASSERT, REL_ASSERT + "  # strict exact-set")]),
    # --- issue forms (a)-(d)
    "multi-line inline use": ("fail", [_rel(
        REL_BUILD_CMD,
        IND + 'cargo build --locked --release \\\n            --target ${{ matrix.target }} \\\n'
        '            --features "$(bash scripts/release-features.sh)"')]),
    "inline use of the declaration in the release-shape tree step": ("fail", [(
        SHAPE, '--features "$FEATURES")"', '--features "$(bash scripts/release-features.sh)")"', False)]),
    "inline use through backticks in the release-shape tree step": ("fail", [(
        SHAPE, '--features "$FEATURES")"', '--features `bash scripts/release-features.sh`)"', False)]),
    "assignment only in a comment": ("fail", [_rel(
        REL_BUILD,
        IND + '# FEATURES="$(bash scripts/release-features.sh)"\n' + IND + 'FEATURES=sal\n' + REL_BUILD_CMD)]),
    "Dockerfile --locked only in a comment": ("fail", [
        (DOCKER, DOCKER_BUILD, 'cargo build --release --features "$FEATURES"; \\', False),
        (DOCKER, DOCKER_RUN_HEAD, '# cargo build --locked --release --features "$FEATURES"\n' + DOCKER_RUN_HEAD, False)]),
    "bypass (a) FEATURES reassigned before the release.yml build": ("fail", _before_build(IND + "FEATURES=sal")),
    "bypass (a) FEATURES reassigned as a command prefix": ("fail", [_rel(
        IND + "cargo build --locked --release --target ${{ matrix.target }}",
        IND + "FEATURES=sal cargo build --locked --release --target ${{ matrix.target }}")]),
    "bypass (a) FEATURES reassigned in the SBOM step": ("fail", [_rel(
        IND + ALLOWED_FEATURES + "\n" + IND + 'test -n "$FEATURES"\n' + SBOM_LINE,
        IND + ALLOWED_FEATURES + "\n" + IND + "FEATURES=sal\n" + IND + 'test -n "$FEATURES"\n' + SBOM_LINE)]),
    "bypass (b) FEATURES reassigned inside the Dockerfile RUN": ("fail", [(
        DOCKER, '    test -n "$FEATURES"; \\', '    FEATURES=sal; \\\n    test -n "$FEATURES"; \\', False)]),
    "bypass (b) FEATURES appended inside the Dockerfile RUN": ("fail", [(
        DOCKER, '    test -n "$FEATURES"; \\', '    FEATURES+=,x; \\\n    test -n "$FEATURES"; \\', False)]),
    "bypass (c) --locked dropped (release.yml)": ("fail", [_rel(
        "cargo build --locked --release --target ${{ matrix.target }}", "cargo build --release --target ${{ matrix.target }}")]),
    "bypass (c) --locked only in a trailing comment (release.yml)": ("fail", [_rel(
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
    "FEATURES assigned after the build (order)": ("fail", [_rel(REL_BUILD, REL_BUILD_CMD + "\n" + ASSIGN.rstrip("\n"))]),
    "eval in the build step": ("fail", _before_build(IND + 'eval "echo hi"')),
    "source in the build step": ("fail", _before_build(IND + "source ./x.sh")),
    "nameref in the build step": ("fail", _before_build(IND + "declare -n r=FEATURES")),
    "read into FEATURES with an env prefix": ("fail", _before_build(IND + "IFS=, read -r FEATURES <<< sal")),
    "mapfile into FEATURES": ("fail", _before_build(IND + "mapfile -t FEATURES < /dev/null")),
    "second build with a +toolchain (hard-coded sal)": ("fail", [_rel(
        REL_BUILD_CMD,
        REL_BUILD_CMD + "\n" + IND + "cargo +1.98.0 build --locked --release --target ${{ matrix.target }} --features sal")]),
    # --- R5 / M-forms: a second or shadowed build in the build step
    "M01 cargo shadowed by a function in the build step": ("fail", [_rel(
        REL_BUILD_CMD,
        IND + "cargo() { command cargo build --locked --release --target ${{ matrix.target }} --features sal; }\n" + REL_BUILD_CMD)]),
    "M02 second build spelled with a quoted \"cargo\"": ("fail", [_rel(
        REL_BUILD_CMD, REL_BUILD_CMD + "\n" + IND + '"cargo" build --release --target ${{ matrix.target }} --features sal')]),
    "M03 second build spelled \\cargo": ("fail", [_rel(
        REL_BUILD_CMD, REL_BUILD_CMD + "\n" + IND + "\\cargo build --release --target ${{ matrix.target }} --features sal")]),
    "M04 quoted second build plus a heredoc-hidden assert": ("fail", [
        _rel(REL_BUILD_CMD, REL_BUILD_CMD + "\n" + IND + '"cargo" build --release --target ${{ matrix.target }} --features sal'),
        _rel(REL_ASSERT, IND + "cat > /dev/null <<'EOF'\n" + REL_ASSERT + "\n" + IND + "EOF")]),
    "build step rewrites the declaration file before reading it": ("fail", _before_build(
        IND + "sed -i.bak s/sal-postgres/sal/ scripts/release-features.sh")),
    "build step restores an old declaration": ("fail", _before_build(IND + "git checkout HEAD~50 -- scripts/release-features.sh")),
    "build step overwrites the asserter script": ("fail", _before_build(IND + "printf 'exit 0' > scripts/assert-compiled-features.sh")),
    "build step exports BASH_ENV through GITHUB_ENV": ("fail", _before_build(IND + 'echo "BASH_ENV=decoy/noop.sh" >> "$GITHUB_ENV"')),
    "build step adds a fake dir to GITHUB_PATH": ("fail", _before_build(IND + 'echo "$PWD/decoy" >> "$GITHUB_PATH"')),
    "build step cd before the build": ("fail", _before_build(IND + "cd decoy")),
    "build step hash -p override": ("fail", _before_build(IND + "hash -p /usr/bin/true cargo")),
    # --- R-F1 / R5: the assert step is the exact statement list
    "N01 assert inside a heredoc body": ("fail", [_rel(
        REL_ASSERT, IND + "cat > /dev/null <<'EOF'\n" + REL_ASSERT + "\n" + IND + "EOF")]),
    "N02 assert inside a multi-line single-quoted string": ("fail", [_rel(REL_ASSERT, IND + ": '\n" + REL_ASSERT + "\n" + IND + "'")]),
    "N03 assert inside a function body never called": ("fail", [_rel(
        REL_ASSERT, IND + "skip_assert() {\n" + REL_ASSERT + "\n" + IND + "}")]),
    "N04 false && { assert }": ("fail", [_rel(REL_ASSERT, IND + "false && {\n" + REL_ASSERT + "\n" + IND + "}\n" + IND + ":")]),
    "N05 false && ( assert )": ("fail", [_rel(REL_ASSERT, IND + "false && (\n" + REL_ASSERT + "\n" + IND + ")")]),
    "N06 bash shadowed by a function": ("fail", _before_assert(IND + "bash() { :; }")),
    "N06b function keyword form": ("fail", _before_assert(IND + "function bash { :; }")),
    "N07 PATH reassigned before the assert": ("fail", _before_assert(IND + 'PATH="$PWD/fake:$PATH"')),
    "N08 cd elsewhere before the assert": ("fail", _before_assert(IND + "cd fake")),
    "N09 working-directory on the assert step": ("fail", _hdr_key(ASSERT_HDR, "working-directory: fake")),
    "N09b env on the assert step": ("fail", _hdr_key(ASSERT_HDR, "env:\n          SHELLOPTS: ''")),
    "N09c env BASH_ENV on the assert step": ("fail", _hdr_key(ASSERT_HDR, "env:\n          BASH_ENV: decoy/noop.sh")),
    "N10 job-level env BASH_ENV": ("fail", [_rel(JOB_NAME, JOB_NAME + "    env:\n      BASH_ENV: ./fake/env.sh\n")]),
    "N10b BASH_ENV in a comment is still refused": ("fail", [_rel(JOB_NAME, JOB_NAME + "    # BASH_ENV\n")]),
    "N11 folded run: > with a commented line before the assert": ("fail", [
        _rel(ASSERT_RUN, ASSERT_RUN.replace("run: |", "run: >")),
        _rel(REL_ASSERT, IND + "true #\n" + REL_ASSERT)]),
    "N12 alias plus expand_aliases": ("fail", _before_assert(IND + "shopt -s expand_aliases\n" + IND + "alias bash=true")),
    "N13 job-level if: false on the release job": ("fail", [_rel(JOB_NAME, JOB_NAME + "    if: ${{ false }}\n")]),
    "N13b job-level if after the steps": ("fail", [_rel(
        "\n  sbom:\n", "\n    if: ${{ false }}\n\n  sbom:\n")]),
    "N13c assert step lives in a job that is not the build job": ("fail", [_rel(ASSERT_NAME, _move_assert_to_other_job)]),
    "N13d job-level continue-on-error": ("fail", [_rel(JOB_NAME, JOB_NAME + "    continue-on-error: true\n")]),
    "N13e job-level defaults": ("fail", [_rel(JOB_NAME, JOB_NAME + "    defaults:\n      run:\n        working-directory: fake\n")]),
    "N13f job key written with quotes": ("fail", [_rel(JOB_NAME, JOB_NAME + '    "if": false\n')]),
    "N13g duplicate job key": ("fail", [_rel(JOB_NAME, JOB_NAME + JOB_NAME)]),
    "N13h top-level env": ("fail", [_rel("\njobs:\n", "\nenv:\n  PATH: ./fake\n\njobs:\n")]),
    "N13i top-level defaults": ("fail", [_rel("\njobs:\n", "\ndefaults:\n  run:\n    working-directory: fake\n\njobs:\n")]),
    "N13j top-level unsupported line": ("fail", [_rel("\njobs:\n", "\n? complex\n: key\n\njobs:\n")]),
    "N13k two jobs: keys": ("fail", [_rel("\njobs:\n", "\njobs:\n  extra:\n    runs-on: x\n\njobs:\n")]),
    "N13k2 no top-level jobs": ("fail", [_rel("\njobs:\n", "\n#jobs:\n")]),
    "N13l two release jobs": ("fail", [_rel("\n  sbom:\n", "\n  release:\n    runs-on: x\n\n  sbom:\n")]),
    "N13m assert step moved before the build": ("fail", [_rel(ASSERT_NAME, _move_assert_before_build)]),
    "N13n assert step deleted": ("fail", [_rel(ASSERT_NAME, _drop_assert_step)]),
    "N14 hash -p shadows bash": ("fail", _before_assert(IND + "hash -p /usr/bin/true bash")),
    "N14b exec before the assert": ("fail", _before_assert(IND + "exec true")),
    "N15 assert step rewrites the declaration": ("fail", [_rel(
        IND + ALLOWED_REQUIRE, IND + "sed -i.bak s/,sal-postgres// scripts/release-features.sh\n" + IND + ALLOWED_REQUIRE)]),
    "N16 extra statement after the assert": ("fail", [_rel(REL_ASSERT, REL_ASSERT + "\n" + IND + "true")]),
    "N16b statements reordered": ("fail", [_rel(
        BIN_LINE + "\n" + IND + ALLOWED_REQUIRE, IND + ALLOWED_REQUIRE + "\n" + BIN_LINE)]),
    "N17 comment line inside a continuation hides the assert": ("fail", [_rel(
        REL_ASSERT, IND + "echo hi \\\n" + IND + "# x \\\n" + REL_ASSERT)]),
    "N18 step key written as a flow mapping": ("fail", [_rel(ASSERT_HDR, ASSERT_NAME + "        {shell: bash}\n")]),
    "N19 run block with inconsistent indentation": ("fail", [_rel(
        IND + "set -euo pipefail\n" + BIN_LINE, IND + "set -euo pipefail\n" + "         " + ALLOWED_BIN)]),
    "N20 duplicate step key": ("fail", _hdr_key(ASSERT_HDR, "shell: bash")),
    "N21 extra step key": ("fail", _hdr_key(ASSERT_HDR, "timeout-minutes: 5")),
    "N22 inline run value": ("fail", [_rel(ASSERT_RUN, ASSERT_HDR + "        run: " + ASSERT_WORKFLOW + "\n" + "          true\n")]),
    "N23 step carries only the first key as a dash line with extra spaces": ("fail", [_rel(
        ASSERT_NAME, "      -   name: Assert compiled features\n")]),
    # --- R1 / F2: the assert is pinned to the release binary
    "R1 assert targets another binary": ("fail", [_rel(REL_ASSERT, REL_ASSERT.replace('"$bin"', '"$bin.checked"'))]),
    "R1 assert targets /bin/ls": ("fail", [_rel(REL_ASSERT, REL_ASSERT.replace('"$bin"', "/bin/ls"))]),
    "R1 bin assigned from another path": ("fail", [_rel(BIN_LINE, IND + 'bin="/opt/known-good/ai-memory"')]),
    "R1 bin reassigned before the assert": ("fail", _before_assert(IND + "bin=/bin/ls")),
    "R1 Dockerfile assert targets another binary": ("fail", [(
        DOCKER, "assert-compiled-features.sh target/release/ai-memory", "assert-compiled-features.sh /bin/ls", False)]),
    "assert without --strict (release.yml)": ("fail", [_rel(REL_ASSERT, REL_ASSERT.replace("--strict ", ""))]),
    "assert with a literal --require instead of $REQUIRE_FLAGS": ("fail", [_rel(
        REL_ASSERT, REL_ASSERT.replace("$REQUIRE_FLAGS", "--require sal"))]),
    "Dockerfile assert not strict": ("fail", [(DOCKER, "--strict $REQUIRE_FLAGS", "$REQUIRE_FLAGS", False)]),
    "assert removed (release.yml)": ("fail", [_rel(REL_ASSERT, IND + "true")]),
    "Dockerfile has no assert": ("fail", [(DOCKER, DOCKER_ASSERT, "    true", False)]),
    # --- R4 / F1: a skippable assert (and build / SBOM)
    "strict assert skipped behind a shell if": ("fail", [_rel(
        REL_ASSERT, IND + 'if [[ "$bin" != *x86_64-apple-darwin* ]]; then\n' + REL_ASSERT + "\n" + IND + "fi")]),
    "R4 step-level if: on the assert step": ("fail", _hdr_key(ASSERT_NAME, "if: matrix.target != 'x86_64-apple-darwin'")),
    "R4 continue-on-error on the assert step": ("fail", _hdr_key(ASSERT_NAME, "continue-on-error: true")),
    "R4 step-level if: on the build step": ("fail", _hdr_key(BUILD_HDR, "if: matrix.os != 'macos-latest'")),
    "R4 continue-on-error on the SBOM step": ("fail", _hdr_key(SBOM_HDR, "continue-on-error: true")),
    "R4 non-bash shell on the assert step": ("fail", [_rel(ASSERT_HDR, ASSERT_HDR.replace("shell: bash", "shell: sh"))]),
    "R4 non-bash shell on the build step": ("fail", [_rel(BUILD_SHELL, BUILD_SHELL.replace("shell: bash", "shell: sh"))]),
    "R4 assert || true": ("fail", [_rel(REL_ASSERT, REL_ASSERT + " || true")]),
    "R4 assert followed by || on the next line": ("fail", [_rel(REL_ASSERT, REL_ASSERT + " ||\n" + IND + "true")]),
    "R4 build || true": ("fail", [_rel(REL_BUILD_CMD, REL_BUILD_CMD + " || true")]),
    "R4 SBOM || true": ("fail", [_rel(SBOM_LINE, SBOM_LINE + " || true")]),
    "R4 build piped to tee": ("fail", [_rel(REL_BUILD_CMD, REL_BUILD_CMD + " | tee build.log")]),
    "R4 SBOM in the background": ("fail", [_rel(SBOM_LINE, SBOM_LINE + " &")]),
    "R4 one-line test && assert": ("fail", [_rel(REL_ASSERT, IND + '[[ "$bin" != *x86_64-apple-darwin* ]] && ' + ASSERT_WORKFLOW)]),
    "R4 one-line test || assert": ("fail", [_rel(REL_ASSERT, IND + "false || " + ASSERT_WORKFLOW)]),
    "R4 assert piped to cat": ("fail", [_rel(REL_ASSERT, REL_ASSERT + " | cat")]),
    "R4 assert in the background": ("fail", [_rel(REL_ASSERT, REL_ASSERT + " &")]),
    "R4 set +e before the assert": ("fail", _before_assert(IND + "set +e")),
    "R4 trap before the assert": ("fail", _before_assert(IND + "trap 'exit 0' ERR")),
    "R4 exit 0 before the assert": ("fail", _before_assert(IND + "exit 0")),
    "R4 build inside an if": ("fail", [_rel(REL_BUILD_CMD, IND + "if true; then\n" + REL_BUILD_CMD + "\n" + IND + "fi")]),
    "R4 Dockerfile conditional assert": ("fail", [(
        DOCKER, DOCKER_ASSERT, '    if [ -n "${SKIP:-}" ]; then :; else ' + ASSERT_DOCKER + "; fi", False)]),
    "R4 Dockerfile assert || true": ("fail", [(DOCKER, DOCKER_ASSERT, DOCKER_ASSERT + " || true", False)]),
    "R4 Dockerfile set +e": ("fail", [(DOCKER, '    test -n "$FEATURES"; \\', '    set +e; \\\n    test -n "$FEATURES"; \\', False)]),
    "C09 later step cargo +toolchain build of the matrix target": ("fail", [_rel(
        PKG_HDR, "      - name: x\n        run: cargo +1.98.0 build --release --target ${{ matrix.target }}\n" + PKG_HDR, False)]),
    "C09b later step repeats the allowed build line": ("fail", [_rel(
        PKG_HDR, "      - name: x\n        run: " + BUILD_CMD + "\n" + PKG_HDR, False)]),
    "C09c later step rebuilds with different flags": ("fail", [_rel(
        PKG_HDR, "      - name: x\n        run: cargo build --release --target ${{ matrix.target }}\n" + PKG_HDR, False)]),
    "C09d second RUN with a cargo build in the Dockerfile": ("fail", [(
        DOCKER, DOCKER_RUN_HEAD, "RUN cargo build --release\n" + DOCKER_RUN_HEAD, False)]),
    # --- Dockerfile: the build RUN is one exact instruction
    "N-D1 Dockerfile assert in a function never called": ("fail", [(
        DOCKER, DOCKER_ASSERT, "    f() { " + ASSERT_DOCKER + "; }", False)]),
    "N-D2 Dockerfile bash shadowed by a function": ("fail", [(
        DOCKER, 'FEATURES="$(bash scripts/release-features.sh)"; \\', "bash() { :; }; \\\n    " + ALLOWED_FEATURES + "; \\", False)]),
    "N-D3 Dockerfile SHELL instruction before the RUN": ("fail", [(DOCKER, DOCKER_RUN_HEAD, 'SHELL ["/bin/true"]\n' + DOCKER_RUN_HEAD, False)]),
    "N-D3b Dockerfile lowercase shell instruction": ("fail", [(DOCKER, DOCKER_RUN_HEAD, 'shell ["/bin/true"]\n' + DOCKER_RUN_HEAD, False)]),
    "N-D4 Dockerfile ENV BASH_ENV": ("fail", [(DOCKER, DOCKER_RUN_HEAD, "ENV BASH_ENV=/build/noop.sh\n" + DOCKER_RUN_HEAD, False)]),
    "N-D5 Dockerfile RUN is not the only statement list": ("fail", [(DOCKER, "strip target/release/ai-memory", "true", False)]),
    "N-D6 Dockerfile RUN with a trailing comment": ("fail", [(DOCKER, DOCKER_ASSERT, DOCKER_ASSERT + "  # strict", False)]),
    "N-D7 Dockerfile RUN comment line inside the continuation": ("fail", [(
        DOCKER, '    test -n "$FEATURES"; \\', '    # note \\\n    test -n "$FEATURES"; \\', False)]),
    "N-D8 Dockerfile RUN uses --mount": ("fail", [(DOCKER, DOCKER_RUN_HEAD, "RUN --mount=type=cache,target=/x set -eu; \\\n", False)]),
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
    "no SBOM": ("fail", [_rel(SBOM_LINE, IND + "echo nosbom")]),
    "SBOM without --features": ("fail", [_rel(SBOM_LINE, IND + "cargo cyclonedx --format json")]),
    "SBOM step carries an if": ("fail", _hdr_key(SBOM_HDR, "if: github.event_name == 'never'")),
    "release-shape does not read the declaration": ("fail", [
        (SHAPE, SHAPE_BUILD_CMD, "true", False),
        (SHAPE, "scripts/release-features.sh", "scripts/x.sh", True)]),
    "release-shape build with a hard-coded feature list": ("fail", [(SHAPE, SHAPE_BUILD_CMD, "cargo build --locked --release --features sal", False)]),
    "release-shape build step carries continue-on-error": ("fail", [(SHAPE, SHAPE_HDR, SHAPE_HDR + "        continue-on-error: true\n", False)]),
    "release-shape does not run the pg proof": ("fail", [(SHAPE, "scripts/release-shape-pg-proof.sh", "scripts/x.sh", True)]),
    "INSTALL does not name sal-postgres": ("fail", [(INSTALL, "sal-postgres", "sal-x", True)]),
    "INSTALL says the daemon path is a source build": ("fail", [(
        INSTALL, "## Pre-built Binaries\n", "## Pre-built Binaries\n\nThe daemon path is NOT shipped.\n", False)]),
    # --- missing inputs are a guard failure (never a silent pass)
    "L1 scripts/release-features.sh is missing": ("fail", [(DECL, "", None, False)]),
    "L1 release.yml is missing": ("fail", [(REL, "", None, False)]),
    "L1 Dockerfile is missing": ("fail", [(DOCKER, "", None, False)]),
    "L1 release-shape.yml is missing": ("fail", [(SHAPE, "", None, False)]),
    "L1 docs/INSTALL.md is missing": ("fail", [(INSTALL, "", None, False)]),
    # --- control characters: Python and bash disagree on what a line is
    "control character: CR line ends in release.yml": ("fail", [_rel(REL_ASSERT, REL_ASSERT + "\r")]),
    "control character: form feed in the Dockerfile": ("fail", [(DOCKER, DOCKER_ASSERT, DOCKER_ASSERT + "\x0c# x", False)]),
    "control character: NUL in release.yml": ("fail", [_rel(REL_ASSERT, REL_ASSERT + "\x00")]),
    # --- F5: unreadable input exits 2
    "F5 release.yml is not valid UTF-8": ("input-error", [(REL, "", "\udcff\udcfe\n", False)]),
    "F5 Dockerfile is not valid UTF-8": ("input-error", [(DOCKER, "", "\udcff\udcfe\n", False)]),
}


def _entry_dir(rel: str) -> Callable[[Path], None]:
    def go(root: Path) -> None:
        (root / rel).unlink()
        (root / rel).mkdir()
    return go


def _entry_loop(rel: str) -> Callable[[Path], None]:
    def go(root: Path) -> None:
        (root / rel).unlink()
        os.symlink(root / rel, root / rel)
    return go


def _entry_dangling(rel: str) -> Callable[[Path], None]:
    def go(root: Path) -> None:
        (root / rel).unlink()
        os.symlink(root / "does-not-exist", root / rel)
    return go


def _entry_binary(rel: str) -> Callable[[Path], None]:
    def go(root: Path) -> None:
        (root / rel).write_bytes(b"\xff\xfe not utf-8\n")
    return go


# name -> (setup, wanted exit code) through the real entry point.
ENTRY_CASES: Dict[str, Tuple[Callable[[Path], None], int]] = {
    "entry: non-UTF-8 release.yml exits 2": (_entry_binary(REL), 2),
    "entry: release.yml is a directory exits 2": (_entry_dir(REL), 2),
    "entry: release.yml is a symlink loop exits 2": (_entry_loop(REL), 2),
    "entry: Dockerfile is a directory exits 2": (_entry_dir(DOCKER), 2),
    "entry: Dockerfile is a symlink loop exits 2": (_entry_loop(DOCKER), 2),
    "entry: release-shape.yml is a directory exits 2": (_entry_dir(SHAPE), 2),
    "entry: INSTALL.md is a directory exits 2": (_entry_dir(INSTALL), 2),
    "entry: release-features.sh is a directory exits 2": (_entry_dir(DECL), 2),
    "entry: dangling release.yml symlink is a guard failure (1)": (_entry_dangling(REL), 1),
}


def self_test(root: Path) -> int:
    failures = 0
    missing = [rel for rel in INPUT_FILES if not (root / rel).is_file()]
    if missing:
        print(f"check_release_features: self-test FAIL: missing inputs under {root}: {', '.join(missing)}", file=sys.stderr)
        return 1
    # Scratch lives under $TMPDIR, else the repo-local .local-runs (never /tmp).
    base = os.environ.get("TMPDIR") or str(root / ".local-runs")
    Path(base).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="relfeat-selftest.", dir=base) as td:
        tmp = Path(td)

        # --- runtime fail-closed: a failing/empty declaration must abort the
        # allowed build step and the Dockerfile RUN under `set -e`. (The guard
        # pins the real files to these exact statements, see the unmutated case.)
        build_body = "\n".join(WF_BUILD).replace("${{ matrix.target }}", "x").replace("cargo build", "echo cargo-build")
        docker_body = (
            DOCKER_RUN[len("RUN ") :]
            .replace("cargo build", "echo cargo-build")
            .replace("strip target", "echo strip target")
            .replace("bash scripts/assert-compiled-features.sh", "echo assert")
        )
        (tmp / "scripts").mkdir()
        for label, body, shell in (("build step", build_body, "bash"), ("Dockerfile RUN", docker_body, "sh")):
            shutil.copy2(root / DECL, tmp / DECL)
            ok = subprocess.run([shell, "-c", "set -e; " + body], cwd=tmp, capture_output=True).returncode == 0
            if not ok:
                print(f"self-test FAIL: {label} does not pass with the real declaration", file=sys.stderr)
                failures += 1
            for mutant in ("exit 1", "true", 'echo ""; exit 0'):
                (tmp / DECL).write_text(mutant + "\n", encoding="utf-8")
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
            except (RuntimeError, ValueError) as exc:
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

        # --- through the real entry point: exit codes for unreadable input.
        for name, (setup, want_rc) in ENTRY_CASES.items():
            case_root = tmp / "entry"
            mk_root(root, case_root)
            setup(case_root)
            rc = subprocess.run([sys.executable, str(Path(__file__).resolve()), str(case_root)], capture_output=True).returncode
            if rc != want_rc:
                print(f"self-test FAIL: '{name}' exited {rc}, wanted {want_rc}", file=sys.stderr)
                failures += 1
    if failures:
        return 1
    print(
        "check_release_features: self-test OK "
        f"(a failing or empty declaration fails the build step and the Dockerfile RUN; "
        f"{len(CASES)} guard cases, {len(ENTRY_CASES)} entry-point cases)"
    )
    return 0


# ---------------------------------------------------------- mutation sweep --
def _refusal_sites(src: bytes) -> List[Tuple[int, int, int]]:
    """(line, start, end) byte span of the ``<x>.bad`` callee of every refusal call."""
    starts = [0]
    for m in re.finditer(b"\n", src):
        starts.append(m.end())
    sites: List[Tuple[int, int, int]] = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "bad":
            f = node.func
            end_line = f.end_lineno if f.end_lineno is not None else f.lineno
            end_col = f.end_col_offset if f.end_col_offset is not None else f.col_offset
            sites.append((f.lineno, starts[f.lineno - 1] + f.col_offset, starts[end_line - 1] + end_col))
    return sorted(sites)


def mutation_sweep(root: Path) -> int:
    """Neutralise each refusal call of this script in turn (``x.bad(...)`` becomes
    a no-op) and require ``--self-test`` to fail. A survivor is a refusal that no
    case proves. Prints ``N mutants, S survivors``; exit 1 when S > 0."""
    me = Path(__file__).resolve()
    src = me.read_bytes()
    sites = _refusal_sites(src)
    base = os.environ.get("TMPDIR") or str(root / ".local-runs")
    Path(base).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="relfeat-sweep.", dir=base) as td:
        tmp = Path(td)
        control = subprocess.run([sys.executable, str(me), "--self-test", str(root)], capture_output=True, text=True)
        if control.returncode != 0:
            print("check_release_features: sweep aborted: the unmutated self-test is not green", file=sys.stderr)
            print(control.stderr, file=sys.stderr)
            return 1

        def run(item: Tuple[int, Tuple[int, int, int]]) -> Tuple[int, int, bool]:
            k, (line, start, end) = item
            mutant = tmp / f"mutant_{k}.py"
            mutant.write_bytes(src[:start] + b"(lambda *_a, **_k: None)" + src[end:])
            res = subprocess.run([sys.executable, str(mutant), "--self-test", str(root)], capture_output=True, text=True)
            return k, line, res.returncode != 0

        with ThreadPoolExecutor(max_workers=max(1, min(4, os.cpu_count() or 1))) as pool:
            results = sorted(pool.map(run, list(enumerate(sites))))
    survivors = [line for _, line, killed in results if not killed]
    for k, line, killed in results:
        print(f"site {k:3d} line {line:4d}: {'killed' if killed else 'SURVIVED'}")
    print(f"check_release_features: mutation sweep: {len(results)} mutants, {len(survivors)} survivors")
    if survivors:
        print(f"check_release_features: surviving refusal sites at lines {survivors}", file=sys.stderr)
        return 1
    return 0


# -------------------------------------------------------------------- main --
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Release feature-set guard (#4480, #4719).")
    ap.add_argument("root", nargs="?", default=None, help="repo root (default: the checkout holding this script)")
    ap.add_argument("--self-test", action="store_true", help="prove the guard refuses every drift form")
    ap.add_argument("--mutation-sweep", action="store_true",
                    help="disable each refusal in turn and require --self-test to go red (N mutants, 0 survivors)")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve() if args.root else HERE.parent
    if args.mutation_sweep:
        return mutation_sweep(root)
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
